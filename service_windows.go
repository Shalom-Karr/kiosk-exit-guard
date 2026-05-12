//go:build windows && amd64

// Service mode for kiosk-exit-guard.
//
// v1.1.0 split: instead of relying on a Task Scheduler entry to keep the
// controller alive, we register a real Windows Service running as
// LocalSystem. The Service has no UI of its own (Services run in Session 0
// since Vista and can't show windows to the user) — it just supervises and
// respawns a user-session controller process via CreateProcessAsUserW into
// the active console session. When the kiosk user kills the controller
// (taskkill, Process Hacker, etc.) the Service notices within seconds and
// spawns a new one. The user can't reach SCM without admin rights, so they
// can't stop the supervising Service the way they could `schtasks /Delete`
// the watchdog task.
//
// Build path:
//
//	kiosk-exit-guard.exe --service-install   first-run / install (admin)
//	kiosk-exit-guard.exe --service-run       invoked by SCM only
//	kiosk-exit-guard.exe --service-remove    uninstall (admin)
//
// The user-session controller is unchanged: it's just kiosk-exit-guard.exe
// with no args, launched into the active console session by the Service.

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/shirou/gopsutil/v4/process"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Service identity. Display name + description are what shows up in
// services.msc and `Get-Service`.
const (
	svcName        = "KioskExitGuardSvc"
	svcDisplayName = "Kiosk Exit Guard Service"
	svcDescription = "Watches and respawns the kiosk-exit-guard user-session controller."

	// Environment marker the controller looks for so it knows it was
	// spawned by the Service vs. launched manually by the admin. We use
	// this to suppress the first-run wizard when the Service is the one
	// launching us — first-run is owned by the admin's manual double-click.
	envViaService = "KIOSK_EXIT_GUARD_VIA_SERVICE"

	// Interval between supervisor loop iterations when there's no active
	// user session yet, and between respawns after a controller exit.
	svcNoSessionDelay = 2 * time.Second
	svcRespawnDelay   = 1 * time.Second
)

// ---------- Win32 plumbing not already in x/sys/windows ----------
//
// Everything we need (WTSGetActiveConsoleSessionId, WTSQueryUserToken,
// DuplicateTokenEx, CreateProcessAsUser, CreateEnvironmentBlock,
// DestroyEnvironmentBlock) is in golang.org/x/sys/windows v0.44.0. The
// only bits we need to define ourselves are a handful of constants the
// upstream package doesn't export.

const (
	// CreateProcessAsUser creation flags.
	createUnicodeEnv = 0x00000400
	createNewConsole = 0x00000010

	// DuplicateTokenEx levels / types.
	securityIdentification = 2
	tokenPrimary           = 1

	// Token desired-access mask we want for the duplicated primary token.
	// MAXIMUM_ALLOWED == 0x02000000.
	maximumAllowed = 0x02000000

	// Session ID returned by WTSGetActiveConsoleSessionId when no user is
	// logged in to the console (Welcome screen, lock screen w/ nobody,
	// no console session at all).
	noActiveSession uint32 = 0xFFFFFFFF
)

// destroyEnvironmentBlock is needed but not exported by x/sys/windows;
// CreateEnvironmentBlock is exported but its destroy companion isn't, so we
// reach into userenv.dll directly.
var (
	userenvDLL                  = windows.NewLazySystemDLL("userenv.dll")
	procDestroyEnvironmentBlock = userenvDLL.NewProc("DestroyEnvironmentBlock")
)

func destroyEnvironmentBlock(env *uint16) {
	if env == nil {
		return
	}
	_, _, _ = procDestroyEnvironmentBlock.Call(uintptr(unsafe.Pointer(env)))
}

// ---------- service install / remove ----------

// installService registers the Service with SCM, starts it, and removes
// any legacy v1.0.x scheduled task so the two managers don't fight. Safe
// to call repeatedly — if the service already exists it's stopped, deleted,
// and recreated so an update can rewrite the binary path.
func installService() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate exe: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	// If the service already exists (e.g. an upgrade install), stop and
	// delete it so we can recreate with the new exe path. Best-effort.
	if s, openErr := m.OpenService(svcName); openErr == nil {
		_, _ = s.Control(svc.Stop)
		// Give SCM a moment to shut down the old service before delete.
		for i := 0; i < 20; i++ {
			status, qErr := s.Query()
			if qErr != nil || status.State == svc.Stopped {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		_ = s.Delete()
		s.Close()
		// SCM marks deleted services as gone only once all handles close,
		// and the name remains reserved briefly. Wait it out so the
		// CreateService below doesn't fail with ERROR_SERVICE_MARKED_FOR_DELETE.
		for i := 0; i < 25; i++ {
			s2, oErr := m.OpenService(svcName)
			if oErr != nil {
				break
			}
			s2.Close()
			time.Sleep(200 * time.Millisecond)
		}
	}

	cfg := mgr.Config{
		DisplayName:      svcDisplayName,
		Description:      svcDescription,
		StartType:        mgr.StartAutomatic,
		ServiceType:      windows.SERVICE_WIN32_OWN_PROCESS,
		ErrorControl:     mgr.ErrorNormal,
		ServiceStartName: "", // LocalSystem
	}
	s, err := m.CreateService(svcName, exe, cfg, "--service-run")
	if err != nil {
		return fmt.Errorf("CreateService: %w", err)
	}
	defer s.Close()

	if err := s.Start(); err != nil {
		// Non-fatal: SCM will start it on next boot via Automatic anyway.
		// Log if we can.
		logf("installService: Service.Start failed: %v", err)
	}

	// v1.1.4: do NOT wipe the scheduled task. v1.1.0–v1.1.3 deleted it
	// here so the two managers wouldn't "fight", but in the field that
	// turned out to leave the kiosk unprotected whenever the Service
	// spawn path failed (e.g. WTSQueryUserToken NO_TOKEN on Win11 Home).
	// The Service and the scheduled task are now co-installed as
	// belt-and-suspenders. killRunningController() at every controller
	// startup keeps exactly one controller alive regardless of who fired
	// first.

	return nil
}

// removeService stops the Service and deletes it. Used by --uninstall and
// the standalone --service-remove flag. Idempotent — no error if the
// service doesn't exist.
func removeService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(svcName)
	if err != nil {
		// Probably doesn't exist — treat as success.
		return nil
	}
	defer s.Close()

	_, _ = s.Control(svc.Stop)
	for i := 0; i < 25; i++ {
		status, qErr := s.Query()
		if qErr != nil || status.State == svc.Stopped {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	return s.Delete()
}

// ---------- service runtime ----------

// kiosKExitGuardService implements svc.Handler. The Execute method is
// invoked by golang.org/x/sys/windows/svc when SCM starts the service.
type kioskExitGuardService struct {
	// stopCh is closed when Execute receives svc.Stop. The supervisor loop
	// watches this to break out of its respawn cycle.
	stopCh chan struct{}

	// currentChild holds the PID and handle of the controller we last
	// spawned. Used by Execute to terminate it on shutdown.
	currentChild atomic.Pointer[childProc]
}

type childProc struct {
	pid    uint32
	handle windows.Handle
}

// Execute is called by the svc package on a goroutine. We accept Stop and
// Shutdown; everything else is ignored. The supervisor runs in its own
// goroutine so Execute can stay responsive to control requests.
func (s *kioskExitGuardService) Execute(args []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown

	status <- svc.Status{State: svc.StartPending}
	s.stopCh = make(chan struct{})

	go s.supervisorLoop()

	status <- svc.Status{State: svc.Running, Accepts: accepted}
	logf("service: running, supervisor goroutine launched")

loop:
	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			status <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			logf("service: received Stop/Shutdown")
			break loop
		default:
			logf("service: unexpected control request: %d", c.Cmd)
		}
	}

	status <- svc.Status{State: svc.StopPending}
	close(s.stopCh)

	// Kill the running controller so it doesn't outlive its supervisor.
	// Without this the kiosk user could end up with an unattended
	// controller after `sc stop KioskExitGuardSvc` — the supervisor is
	// gone but the controller it spawned remains.
	if ch := s.currentChild.Load(); ch != nil && ch.handle != 0 {
		_ = windows.TerminateProcess(ch.handle, 1)
		_ = windows.CloseHandle(ch.handle)
	}

	status <- svc.Status{State: svc.Stopped}
	return false, 0
}

// supervisorLoop runs forever (until stopCh is closed) finding the active
// console session, spawning a controller into it, and waiting for the
// controller to exit. On clean exit, sleep briefly and respawn. On no
// user logged in, sleep and re-check.
func (s *kioskExitGuardService) supervisorLoop() {
	defer recoverAndLog("supervisorLoop")

	for {
		select {
		case <-s.stopCh:
			return
		default:
		}

		sessionID := windows.WTSGetActiveConsoleSessionId()
		if sessionID == noActiveSession {
			// Lock screen with nobody, or no console session. Wait and
			// poll again.
			select {
			case <-s.stopCh:
				return
			case <-time.After(svcNoSessionDelay):
			}
			continue
		}

		hProc, err := s.spawnControllerInSession(sessionID)
		if err != nil {
			logf("service: spawnControllerInSession(%d) failed: %v", sessionID, err)
			select {
			case <-s.stopCh:
				return
			case <-time.After(svcNoSessionDelay):
			}
			continue
		}

		// Record so Execute can kill us on shutdown.
		s.currentChild.Store(&childProc{handle: hProc})

		// Block until the controller exits or we're told to stop.
		exitCh := make(chan struct{})
		go func() {
			_, _ = windows.WaitForSingleObject(hProc, windows.INFINITE)
			close(exitCh)
		}()

		select {
		case <-s.stopCh:
			// Caller will TerminateProcess via currentChild — return so we
			// don't race the shutdown path.
			return
		case <-exitCh:
		}

		// Controller exited on its own. Clean up the handle, clear the
		// pointer, brief settle, and loop to respawn.
		_ = windows.CloseHandle(hProc)
		s.currentChild.Store(nil)
		logf("service: controller exited, respawning in %s", svcRespawnDelay)

		select {
		case <-s.stopCh:
			return
		case <-time.After(svcRespawnDelay):
		}
	}
}

// spawnControllerInSession is the meat of the Service: get the user's
// token from the given session, duplicate it to a primary token, build an
// environment block, and call CreateProcessAsUserW to spawn ourselves with
// no args (controller mode) into that session.
//
// Returns the process handle on success — the caller is responsible for
// closing it. The thread handle is closed inside this function.
func (s *kioskExitGuardService) spawnControllerInSession(sessionID uint32) (windows.Handle, error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("Executable: %w", err)
	}

	// 1. Get a user token for the target session. Try WTSQueryUserToken
	// first — that's the documented path and works on most installs.
	// When it fails (observed on Win11 Home: returns ERROR_NO_TOKEN even
	// for a fully-logged-in interactive session), fall back to stealing
	// explorer.exe's primary token in the same session. That's the
	// standard workaround for the WTSQueryUserToken NO_TOKEN behavior:
	// explorer.exe is guaranteed to exist whenever the user has logged
	// in to a desktop, and its token represents the user's identity.
	var userToken windows.Token
	wtsErr := windows.WTSQueryUserToken(sessionID, &userToken)
	if wtsErr != nil {
		fallback, fbErr := tokenFromExplorerInSession(sessionID)
		if fbErr != nil {
			return 0, fmt.Errorf("WTSQueryUserToken(%d): %w; explorer fallback: %v", sessionID, wtsErr, fbErr)
		}
		userToken = fallback
		logf("service: WTSQueryUserToken failed (%v); using explorer.exe token fallback for session %d", wtsErr, sessionID)
	}
	defer userToken.Close()

	// 2. Duplicate to a primary token suitable for CreateProcessAsUser.
	var primaryToken windows.Token
	if err := windows.DuplicateTokenEx(
		userToken,
		maximumAllowed,
		nil,
		securityIdentification,
		tokenPrimary,
		&primaryToken,
	); err != nil {
		return 0, fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	defer primaryToken.Close()

	// 3. Build the user's environment block so the spawned controller
	// sees the user's %APPDATA%, %TEMP%, etc. — not the Service's
	// SYSTEM environment.
	var envBlock *uint16
	if err := windows.CreateEnvironmentBlock(&envBlock, primaryToken, false); err != nil {
		return 0, fmt.Errorf("CreateEnvironmentBlock: %w", err)
	}
	defer destroyEnvironmentBlock(envBlock)

	// 4. Build STARTUPINFO. lpDesktop = "winsta0\default" is required for
	// the spawned process to show UI (the LL hook works fine without it,
	// but the password modal and toast would have nowhere to draw).
	desktop, err := windows.UTF16PtrFromString(`winsta0\default`)
	if err != nil {
		return 0, fmt.Errorf("UTF16PtrFromString(desktop): %w", err)
	}
	si := windows.StartupInfo{
		Cb:      uint32(unsafe.Sizeof(windows.StartupInfo{})),
		Desktop: desktop,
	}

	// 5. Command line: just the exe path, quoted. No args — that puts the
	// child into the default controller mode. Windows will tokenize the
	// command line itself.
	cmdLine, err := windows.UTF16PtrFromString(`"` + exe + `"`)
	if err != nil {
		return 0, fmt.Errorf("UTF16PtrFromString(cmd): %w", err)
	}

	// 6. Marker env var: inject KIOSK_EXIT_GUARD_VIA_SERVICE=1 into the
	// block CreateEnvironmentBlock built. The simplest correct way to
	// extend a Unicode env block is to build a new one ourselves —
	// CreateEnvironmentBlock's output is a contiguous "k=v\0k=v\0\0"
	// double-null-terminated UTF-16 buffer.
	mergedEnv := appendEnvVar(envBlock, envViaService, "1")

	// 7. CreateProcessAsUser. CREATE_UNICODE_ENVIRONMENT is required
	// because the env block is UTF-16. CREATE_NEW_CONSOLE keeps the
	// child's console (if any) separate from the Service's Session-0
	// invisible console.
	var pi windows.ProcessInformation
	err = windows.CreateProcessAsUser(
		primaryToken,
		nil,
		cmdLine,
		nil,
		nil,
		false,
		createUnicodeEnv|createNewConsole,
		&mergedEnv[0],
		nil,
		&si,
		&pi,
	)
	if err != nil {
		return 0, fmt.Errorf("CreateProcessAsUser: %w", err)
	}
	// Don't need the thread handle.
	_ = windows.CloseHandle(pi.Thread)

	logf("service: spawned controller pid=%d in session %d", pi.ProcessId, sessionID)
	return pi.Process, nil
}

// tokenFromExplorerInSession finds an explorer.exe instance running in the
// target console session, opens its primary token, and returns it. If
// explorer.exe is running under a user with UAC enabled, OpenProcessToken
// returns the *limited* half of the UAC-split token — kiosk-exit-guard
// needs admin (HKLM writes, IFEO, etc.) so we unwrap the limited token
// to its linked elevated counterpart via GetTokenInformation(TokenLinkedToken).
//
// This is the standard workaround for WTSQueryUserToken returning
// ERROR_NO_TOKEN on machines where the documented path inexplicably fails
// (observed on Win11 Home in the field — see v1.1.3 changelog).
func tokenFromExplorerInSession(sessionID uint32) (windows.Token, error) {
	procs, err := process.Processes()
	if err != nil {
		return 0, fmt.Errorf("enumerate processes: %w", err)
	}

	var lastErr error
	for _, p := range procs {
		name, nerr := p.Name()
		if nerr != nil || !strings.EqualFold(name, "explorer.exe") {
			continue
		}
		pid := uint32(p.Pid)

		// ProcessIdToSessionId tells us which session this explorer.exe
		// is running in. We only want one whose session matches the
		// active console session — there can be multiple explorer.exe
		// processes (RDP, fast-user-switch, etc.).
		var procSession uint32
		if sErr := windows.ProcessIdToSessionId(pid, &procSession); sErr != nil {
			lastErr = sErr
			continue
		}
		if procSession != sessionID {
			continue
		}

		hProc, oErr := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
		if oErr != nil {
			lastErr = oErr
			continue
		}

		// v1.1.8 HIGH#3 + MEDIUM#6: validate the process image path
		// before trusting its token. gopsutil's Name() returns the
		// process name from a user-readable enumeration that doesn't
		// authenticate identity — a kiosk user can spawn a renamed-
		// to-explorer.exe binary, and on the next supervisor tick we'd
		// open its token, unwrap to the linked elevated half, and
		// CreateProcessAsUser attacker code as the admin user. By
		// calling QueryFullProcessImageName on the same handle we used
		// for OpenProcessToken we re-derive the image from the kernel
		// at the moment of token capture, which also closes the PID-
		// recycle race (the OS guarantees the handle still refers to
		// the originally-opened process for the lifetime of the
		// handle). Reject anything that isn't %SystemRoot%\explorer.exe.
		if !isLegitimateExplorerHandle(hProc) {
			logf("service: rejecting non-system explorer.exe pid=%d (image path mismatch)", pid)
			_ = windows.CloseHandle(hProc)
			continue
		}

		var token windows.Token
		tErr := windows.OpenProcessToken(
			hProc,
			windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_IMPERSONATE,
			&token,
		)
		_ = windows.CloseHandle(hProc)
		if tErr != nil {
			lastErr = tErr
			continue
		}

		// If this is a UAC-split limited token, swap to its elevated
		// linked counterpart. kiosk-exit-guard needs admin to do its
		// job — a non-elevated controller can't write HKLM, register
		// IFEO debugger keys, or restart Explorer.
		if elevated, eErr := elevatedLinkedToken(token); eErr == nil && elevated != 0 {
			_ = token.Close()
			return elevated, nil
		}
		// Either elevation type is "Default" (UAC off / built-in admin)
		// or "Full" (already elevated) — use the token as-is.
		return token, nil
	}

	if lastErr != nil {
		return 0, fmt.Errorf("no usable explorer.exe in session %d (last error: %v)", sessionID, lastErr)
	}
	return 0, fmt.Errorf("no explorer.exe found in session %d (is a user logged in?)", sessionID)
}

// isLegitimateExplorerHandle reports whether the process referred to by
// hProc has an image path equal to %SystemRoot%\explorer.exe (case-
// insensitive). Called inside tokenFromExplorerInSession right after a
// successful OpenProcess so we authenticate the process by its on-disk
// image — not by its enumerable name — before unwrapping its token.
//
// Closes v1.1.8 HIGH#3 (kiosk user spawns renamed-to-explorer.exe to
// have the Service unwrap its linked elevated token and execute
// attacker code) and v1.1.8 MEDIUM#6 (PID-recycle race: between
// gopsutil's enumeration and OpenProcess the PID could in theory have
// been recycled — but the open handle pins the original kernel object,
// so QueryFullProcessImageName on that handle returns the image of
// whatever-the-kernel-currently-knows-as that handle, which is the
// process we opened, not a recycled one).
func isLegitimateExplorerHandle(hProc windows.Handle) bool {
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = `C:\Windows`
	}
	expected := strings.ToLower(systemRoot + `\explorer.exe`)

	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(hProc, 0, &buf[0], &size); err != nil {
		logf("isLegitimateExplorerHandle: QueryFullProcessImageName failed: %v", err)
		return false
	}
	actual := strings.ToLower(windows.UTF16ToString(buf[:size]))
	return actual == expected
}

// elevatedLinkedToken returns the elevated counterpart of a UAC-split
// limited token. Returns (0, nil) if the token is not split (i.e.
// elevation type is Default or Full — there's nothing to swap to). The
// returned token, when non-zero, must be Close()'d by the caller.
func elevatedLinkedToken(limited windows.Token) (windows.Token, error) {
	// TokenElevationType returns a DWORD: 1=Default, 2=Full, 3=Limited.
	var elevType uint32
	var retLen uint32
	if err := windows.GetTokenInformation(
		limited, windows.TokenElevationType,
		(*byte)(unsafe.Pointer(&elevType)),
		uint32(unsafe.Sizeof(elevType)),
		&retLen,
	); err != nil {
		return 0, fmt.Errorf("GetTokenInformation(TokenElevationType): %w", err)
	}
	const tokenElevationTypeLimited = 3
	if elevType != tokenElevationTypeLimited {
		return 0, nil
	}

	// TokenLinkedToken returns a TOKEN_LINKED_TOKEN struct which is a
	// single HANDLE (8 bytes on amd64).
	var linked windows.Token
	if err := windows.GetTokenInformation(
		limited, windows.TokenLinkedToken,
		(*byte)(unsafe.Pointer(&linked)),
		uint32(unsafe.Sizeof(linked)),
		&retLen,
	); err != nil {
		return 0, fmt.Errorf("GetTokenInformation(TokenLinkedToken): %w", err)
	}
	return linked, nil
}

// appendEnvVar copies the env block CreateEnvironmentBlock produced and
// appends `name=value` to it, returning a new []uint16 ending in the
// required double NUL. We don't try to dedupe — if the user already has
// `name` set, ours will be later in the block, which Windows honors.
func appendEnvVar(block *uint16, name, value string) []uint16 {
	// Walk the source block to find its length. The block is a series of
	// L"name=value\0" strings terminated by an extra L"\0" (i.e. ends in
	// two consecutive NULs).
	var src []uint16
	if block != nil {
		p := unsafe.Pointer(block)
		var i uintptr
		for {
			c0 := *(*uint16)(unsafe.Pointer(uintptr(p) + i*2))
			c1 := *(*uint16)(unsafe.Pointer(uintptr(p) + (i+1)*2))
			src = append(src, c0)
			if c0 == 0 && c1 == 0 {
				// We just appended the terminating NUL of a string AND the
				// next position is also a NUL: that's the end-of-block
				// double-NUL. Don't append the second NUL yet — we'll
				// drop it, add our new var, then re-add it below.
				break
			}
			i++
		}
		// `src` now ends with the inner-string-terminator NUL. Drop it
		// so we can splice our new var in.
		if n := len(src); n > 0 && src[n-1] == 0 {
			src = src[:n-1]
		}
	}

	addition, _ := syscall.UTF16FromString(name + "=" + value)
	// UTF16FromString already terminates `addition` with one NUL.

	// Layout: src + (NUL separator if src non-empty) + addition + final NUL.
	out := make([]uint16, 0, len(src)+len(addition)+2)
	if len(src) > 0 {
		out = append(out, src...)
		out = append(out, 0)
	}
	out = append(out, addition...)
	// Final block-terminator NUL.
	out = append(out, 0)
	return out
}

// ---------- entry points ----------

// runService is the --service-run entry point. SCM invokes the exe with
// this flag and waits for us to call svc.Run. svc.Run blocks until SCM
// sends Stop / Shutdown.
func runService() {
	logf("service: --service-run invoked, calling svc.Run")
	if err := svc.Run(svcName, &kioskExitGuardService{}); err != nil {
		logf("service: svc.Run returned error: %v", err)
		os.Exit(1)
	}
	logf("service: svc.Run returned cleanly")
}

// runServiceInstall is the --service-install entry point. Used by
// first-run setup (called inside the elevated process after the password
// is saved). Idempotent.
func runServiceInstall() {
	if err := installService(); err != nil {
		logf("service-install failed: %v", err)
		fmt.Fprintln(os.Stderr, "service install failed:", err)
		os.Exit(1)
	}
	logf("service: install complete")
}

// runServiceRemove is the --service-remove entry point. Used by
// --uninstall and as a manual rescue.
func runServiceRemove() {
	if err := removeService(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		logf("service-remove failed: %v", err)
		fmt.Fprintln(os.Stderr, "service remove failed:", err)
		os.Exit(1)
	}
	logf("service: remove complete")
}

// isLaunchedByService reports whether the current process was spawned
// by the supervising Service. v1.1.8 LOW#9 hardening: previously this
// just checked the KIOSK_EXIT_GUARD_VIA_SERVICE environment variable,
// which any process can forge before exec'ing kiosk-exit-guard.exe. A
// kiosk user who can reach a shell could set the env var, run the exe
// manually, and have it suppress the first-run wizard — leaving the
// device with no password configured AND no kiosk lockdown, then
// trick the admin into running the exe in a clean shell to complete
// setup.
//
// New gating: look up our parent PID via CreateToolhelp32Snapshot,
// then use QueryFullProcessImageName to read the parent's exe path.
// If it's %SystemRoot%\System32\services.exe we were genuinely
// spawned by the SCM-launched Service, since CreateProcessAsUserW
// makes the supervising service the parent process of the spawned
// controller. Otherwise treat as a manual launch.
//
// The env var is still honored as a hint when the parent lookup
// fails (snapshot creation can fail on stripped SKUs) so we don't
// regress the v1.1.0 behavior — but the parent path is the source of
// truth when available.
func isLaunchedByService() bool {
	parentPath, ok := parentProcessImagePath()
	if !ok {
		// Fall back to the legacy env-var hint. Logged so audits can
		// see when we couldn't authenticate the parent.
		hint := strings.EqualFold(os.Getenv(envViaService), "1")
		logf("isLaunchedByService: parent lookup failed, env hint=%v", hint)
		return hint
	}
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = `C:\Windows`
	}
	expected := strings.ToLower(systemRoot + `\System32\services.exe`)
	actual := strings.ToLower(parentPath)
	return actual == expected
}

// parentProcessImagePath returns the full path to our parent process's
// exe, using a toolhelp snapshot to find the parent PID and
// QueryFullProcessImageName to read the path from the kernel. Returns
// ok=false on any failure so the caller can fall back to the env hint.
// v1.1.8 LOW#9.
func parentProcessImagePath() (string, bool) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		logf("parentProcessImagePath: CreateToolhelp32Snapshot failed: %v", err)
		return "", false
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snap, &entry); err != nil {
		logf("parentProcessImagePath: Process32First failed: %v", err)
		return "", false
	}
	selfPID := uint32(os.Getpid())
	var parentPID uint32
	found := false
	for {
		if entry.ProcessID == selfPID {
			parentPID = entry.ParentProcessID
			found = true
			break
		}
		if err := windows.Process32Next(snap, &entry); err != nil {
			break
		}
	}
	if !found || parentPID == 0 {
		logf("parentProcessImagePath: own PID %d not found in snapshot", selfPID)
		return "", false
	}

	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, parentPID)
	if err != nil {
		logf("parentProcessImagePath: OpenProcess(parent=%d) failed: %v", parentPID, err)
		return "", false
	}
	defer windows.CloseHandle(hProc)

	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(hProc, 0, &buf[0], &size); err != nil {
		logf("parentProcessImagePath: QueryFullProcessImageName(parent=%d) failed: %v", parentPID, err)
		return "", false
	}
	return windows.UTF16ToString(buf[:size]), true
}
