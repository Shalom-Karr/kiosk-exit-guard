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
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

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
//
// wtsapi32 plumbing (v1.1.10): the v1.1.3 explorer-token fallback enumerated
// processes via gopsutil's process.Processes(). On the user's affected
// machine that path returned an empty (or filtered) list when called from
// the Session-0 LocalSystem service — so the supervisor logged
// "no explorer.exe found in session 1 (is a user logged in?)" every 2s
// even though the user WAS logged in and running the kiosk. The kernel
// can see across sessions just fine for LocalSystem (SeDebugPrivilege),
// but gopsutil's underlying snapshot API was missing them. Switching to
// WTSEnumerateProcessesExW — the Win32 API explicitly designed for
// service-side cross-session enumeration — fixes the enumeration
// reliably.
var (
	userenvDLL                  = windows.NewLazySystemDLL("userenv.dll")
	procDestroyEnvironmentBlock = userenvDLL.NewProc("DestroyEnvironmentBlock")

	wtsapi32DLL                     = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSEnumerateProcessesExW    = wtsapi32DLL.NewProc("WTSEnumerateProcessesExW")
	procWTSFreeMemoryExW            = wtsapi32DLL.NewProc("WTSFreeMemoryExW")
	procWTSEnumerateSessionsW       = wtsapi32DLL.NewProc("WTSEnumerateSessionsW")
	procWTSQuerySessionInformationW = wtsapi32DLL.NewProc("WTSQuerySessionInformationW")
	procWTSFreeMemory               = wtsapi32DLL.NewProc("WTSFreeMemory")
)

// WTS constants for the level-0 process info enumeration. wtsAnySession is
// the documented sentinel meaning "all sessions"; we pass the target
// session ID instead so the kernel filters for us.
const (
	wtsCurrentServerHandle   = 0
	wtsTypeProcessInfoLevel0 = 0
	wtsAnySession            = ^uint32(0) // (DWORD)-1

	// WTS_CONNECTSTATE_CLASS values. We only act on wtsActive — Connected
	// (locked screen on the console) and Disconnected (RDP'd-then-closed
	// without logoff) sessions are skipped, since the user isn't actually
	// looking at the desktop.
	wtsActive       = 0
	wtsConnected    = 1
	wtsDisconnected = 4

	// WTS_INFO_CLASS values. WTSUserName returns the logged-in user's
	// account name; WTSDomainName returns the domain (or local machine
	// name on workgroup boxes). Both used by pickActiveUserSession for
	// the v1.2.0 candidate-logging behavior.
	wtsInfoUserName   = 5
	wtsInfoDomainName = 7
)

// wtsSessionInfoW mirrors the Win32 WTS_SESSION_INFOW on amd64. Layout:
//
//	typedef struct _WTS_SESSION_INFOW {
//	    DWORD                  SessionId;        // 4 bytes
//	    LPWSTR                 pWinStationName;  // 8 bytes (pointer)
//	    WTS_CONNECTSTATE_CLASS State;            // 4 bytes
//	} WTS_SESSION_INFOW;
//
// MSVC inserts 4 bytes of padding after SessionId to 8-byte-align
// pWinStationName, and 4 bytes of trailing padding so the struct size is
// 24 bytes (8-byte aligned). Verified at runtime with unsafe.Sizeof at
// the call site.
type wtsSessionInfoW struct {
	SessionID      uint32
	_              uint32 // padding to 8-byte align WinStationName
	WinStationName *uint16
	State          uint32
	_              uint32 // trailing padding for 8-byte struct alignment
}

// wtsProcessInfoW mirrors the Win32 WTS_PROCESS_INFO_EXW (level 0) on
// amd64. The struct is 24 bytes per entry with natural 8-byte alignment.
// MSVC packs the two adjacent DWORDs (SessionId, ProcessId) into a single
// 8-byte slot, then the two pointer-sized fields follow at offsets 8 and
// 16. v1.2.0 fix: pre-v1.2.0 had explicit 4-byte padding fields between
// the DWORDs and the pointers (32 bytes total) which is wrong — on the
// real layout that miscast SessionId/ProcessId, walked off the array
// stride by 8 bytes per entry, and made the picker dereference garbage
// pointers. Verified at compile time via the size assertion below.
//
// typedef struct _WTS_PROCESS_INFOW {
//     DWORD  SessionId;     // offset 0, 4 bytes
//     DWORD  ProcessId;     // offset 4, 4 bytes
//     LPWSTR pProcessName;  // offset 8, 8 bytes
//     PSID   pUserSid;      // offset 16, 8 bytes
// } WTS_PROCESS_INFOW;       // sizeof == 24
//
// (The "Ex" variant at level 0 has the same on-disk layout as
// WTS_PROCESS_INFOW per MS docs — both are 24 bytes on x64.)
type wtsProcessInfoW struct {
	SessionId   uint32
	ProcessId   uint32
	ProcessName *uint16
	UserSid     uintptr // PSID
}

// Compile-time size assertions. If either struct's Go layout drifts from
// the Win32 ABI we'll dereference garbage at runtime; better to fail the
// build. Each array type below is invalid (negative length) unless the
// struct is exactly 24 bytes, so the build fails on layout drift.
var _ [1]struct{} = [unsafe.Sizeof(wtsProcessInfoW{}) - 23]struct{}{} // size must be >= 24 (length 1)
var _ [1]struct{} = [25 - unsafe.Sizeof(wtsProcessInfoW{})]struct{}{} // size must be <= 24 (length 1)
var _ [1]struct{} = [unsafe.Sizeof(wtsSessionInfoW{}) - 23]struct{}{} // size must be >= 24 (length 1)
var _ [1]struct{} = [25 - unsafe.Sizeof(wtsSessionInfoW{})]struct{}{} // size must be <= 24 (length 1)

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

// serviceStillExists returns true if KioskExitGuardSvc is currently
// registered with SCM. Used by runUninstallInvocation's post-uninstall
// verification block to confirm removeService actually deleted the
// service. v1.1.9 UX LOW#10.
func serviceStillExists() bool {
	m, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer m.Disconnect()
	s, err := m.OpenService(svcName)
	if err != nil {
		return false
	}
	s.Close()
	return true
}

// waitForServiceStopped polls SCM until the KioskExitGuardSvc reaches
// svc.Stopped or the deadline elapses, whichever comes first. Returns
// nil once the service is observed Stopped (or doesn't exist — same
// effective state for callers' purposes), or an error on timeout /
// open / query failure. v1.1.9 UX MEDIUM#7: extracted from the inline
// loop in installService so runUpdateInvocation can wait for `sc stop`
// to actually complete before renaming the exe. Without this the
// supervisor could respawn a fresh controller mid-rename and break
// the update.
func waitForServiceStopped(d time.Duration) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(svcName)
	if err != nil {
		// Service doesn't exist — equivalent to Stopped for callers
		// that want to safely rename the on-disk exe.
		return nil
	}
	defer s.Close()

	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		status, qErr := s.Query()
		if qErr != nil {
			return fmt.Errorf("query service: %w", qErr)
		}
		if status.State == svc.Stopped {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("service %s did not reach Stopped within %s", svcName, d)
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

// supervisorLoop runs forever (until stopCh is closed) finding an active
// user session, spawning a controller into it, and waiting for the
// controller to exit. On clean exit, sleep briefly and respawn. On no
// user logged in, sleep and re-check.
//
// v1.1.11: instead of trusting WTSGetActiveConsoleSessionId() — which
// returns the empty *physical* console session ID on a headless RDP'd
// Server 2022 (typically 1, with no user) while the real interactive
// user is in session 2 (RDP) — we walk WTSEnumerateSessionsW and pick
// the lowest-numbered WTSActive session that has a logged-in user,
// preferring the console session if it qualifies. On a Win11 laptop
// where the console session IS the user session, this picks the same
// session 1 as before; on Server 2022 / RDP it picks session 2 (or
// whatever the RDP session ID happens to be).
func (s *kioskExitGuardService) supervisorLoop() {
	defer recoverAndLog("supervisorLoop")

	var lastLoggedSession uint32 = noActiveSession
	for {
		select {
		case <-s.stopCh:
			return
		default:
		}

		sessionID, ok := pickActiveUserSession()
		if !ok {
			// No interactive user session anywhere (boot before any
			// user logged on, Welcome screen with nobody, all RDP
			// sessions disconnected). Wait and poll again.
			if lastLoggedSession != noActiveSession {
				logf("service: no active user session, waiting…")
				lastLoggedSession = noActiveSession
			}
			select {
			case <-s.stopCh:
				return
			case <-time.After(svcNoSessionDelay):
			}
			continue
		}

		if sessionID != lastLoggedSession {
			// v1.2.0: log chosen user/domain and any passed-over
			// candidates so an operator can see who the controller is
			// being spawned as on multi-user RDP boxes.
			lastPickMu.Lock()
			user, domain := lastPickUser, lastPickDomain
			cands := append([]string(nil), lastPickCandidates...)
			lastPickMu.Unlock()
			if len(cands) > 1 {
				logf("service: %d candidate sessions: %s", len(cands), strings.Join(cands, ", "))
			}
			logf("service: spawning controller in session %d (state=Active, user=%s\\%s)", sessionID, domain, user)
			lastLoggedSession = sessionID
		}

		hProc, err := s.spawnControllerInSession(sessionID)
		if err != nil {
			logf("service: spawnControllerInSession(%d) failed: %v", sessionID, err)
			// Force the next successful pick to re-log even if it
			// resolves to the same session — admins reading the log
			// want to see "spawn failed" / "spawn succeeded" pairs.
			lastLoggedSession = noActiveSession
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

// pickActiveUserSession walks every session reported by
// WTSEnumerateSessionsW and returns the best session to spawn a
// controller into:
//
//  1. Prefer the physical-console session (the one
//     WTSGetActiveConsoleSessionId reports) when it's WTSActive AND has
//     a logged-in user — that's the v1.1.10 behavior on a Win11 laptop.
//  2. Otherwise, the lowest-numbered other WTSActive session whose
//     WTSUserName query returns a non-empty string — that's the RDP
//     session on a headless Server 2022 where the console session is
//     empty.
//
// Returns (0, false) if no candidate session exists. The supervisor
// loop sleeps and retries on false.
//
// v1.1.11: introduced for Server 2022 RDP. On a headless server with
// nobody at the physical console, WTSGetActiveConsoleSessionId returns
// session 1 with State=Disconnected and no user. The user's actual
// session is the RDP one (typically 2). Walking the session list lets
// us pick session 2 and spawn the controller there.
func pickActiveUserSession() (uint32, bool) {
	var pSessionInfo *wtsSessionInfoW
	var count uint32

	r1, _, callErr := procWTSEnumerateSessionsW.Call(
		uintptr(wtsCurrentServerHandle),
		0, // Reserved — must be 0
		1, // Version — must be 1
		uintptr(unsafe.Pointer(&pSessionInfo)),
		uintptr(unsafe.Pointer(&count)),
	)
	if r1 == 0 {
		logf("pickActiveUserSession: WTSEnumerateSessionsW failed: %v", callErr)
		return 0, false
	}
	if pSessionInfo == nil || count == 0 {
		if pSessionInfo != nil {
			_, _, _ = procWTSFreeMemory.Call(uintptr(unsafe.Pointer(pSessionInfo)))
		}
		return 0, false
	}

	// Defensive: validate the on-disk struct size matches what we
	// declared. amd64 layout is 24 bytes; mismatch means we'd
	// dereference garbage. (Now compile-time asserted as well; this
	// runtime check stays as a belt-and-suspenders guard.)
	const expectedSessionInfoSize = 24
	if got := unsafe.Sizeof(wtsSessionInfoW{}); got != expectedSessionInfoSize {
		_, _, _ = procWTSFreeMemory.Call(uintptr(unsafe.Pointer(pSessionInfo)))
		logf("pickActiveUserSession: wtsSessionInfoW size mismatch: got %d, expected %d", got, expectedSessionInfoSize)
		return 0, false
	}

	sessions := unsafe.Slice(pSessionInfo, int(count))

	consoleID := windows.WTSGetActiveConsoleSessionId()

	// Two-pass: console first (if it qualifies), then lowest-numbered
	// other WTSActive with a user. v1.2.0: collect every candidate so we
	// can log what was passed over — on Server 2022 with multiple RDP
	// users the picker silently picks the lowest-numbered session, which
	// might not be the admin the kiosk is supposed to lock down.
	type candidate struct {
		sessionID uint32
		user      string
		domain    string
	}
	var candidates []candidate
	var consolePick uint32
	var consoleOK bool
	var bestOther uint32
	var bestOtherOK bool

	for i := range sessions {
		si := &sessions[i]
		if si.State != wtsActive {
			continue
		}
		user := wtsSessionString(si.SessionID, wtsInfoUserName)
		if user == "" {
			continue
		}
		domain := wtsSessionString(si.SessionID, wtsInfoDomainName)
		candidates = append(candidates, candidate{
			sessionID: si.SessionID,
			user:      user,
			domain:    domain,
		})
		if consoleID != noActiveSession && si.SessionID == consoleID {
			consolePick = si.SessionID
			consoleOK = true
			continue
		}
		if !bestOtherOK || si.SessionID < bestOther {
			bestOther = si.SessionID
			bestOtherOK = true
		}
	}

	_, _, _ = procWTSFreeMemory.Call(uintptr(unsafe.Pointer(pSessionInfo)))

	var chosen uint32
	var chosenOK bool
	switch {
	case consoleOK:
		chosen, chosenOK = consolePick, true
	case bestOtherOK:
		chosen, chosenOK = bestOther, true
	}
	if !chosenOK {
		return 0, false
	}

	// v1.2.0: cache pick info for the supervisor's once-per-change log
	// line. The supervisor calls pickActiveUserSession every 2s; logging
	// from inside would spam the log. We stash the chosen user/domain +
	// the full candidate list in package-level state so the supervisor
	// can read it on a transition without re-querying WTS.
	var chosenUser, chosenDomain string
	for _, c := range candidates {
		if c.sessionID == chosen {
			chosenUser, chosenDomain = c.user, c.domain
			break
		}
	}
	lastPickMu.Lock()
	lastPickChosen = chosen
	lastPickUser = chosenUser
	lastPickDomain = chosenDomain
	lastPickCandidates = lastPickCandidates[:0]
	for _, c := range candidates {
		lastPickCandidates = append(lastPickCandidates, fmt.Sprintf("%d (%s\\%s)", c.sessionID, c.domain, c.user))
	}
	lastPickMu.Unlock()

	return chosen, true
}

// lastPick* hold the most recent pickActiveUserSession result so the
// supervisor loop can log session/user/candidate info exactly once per
// transition (rather than every 2-second poll). Guarded by lastPickMu.
var (
	lastPickMu         sync.Mutex
	lastPickChosen     uint32
	lastPickUser       string
	lastPickDomain     string
	lastPickCandidates []string
)

// wtsSessionString returns a WTS string property (WTSUserName,
// WTSDomainName, …) for the given session, or "" on any error or empty
// result. Wraps the WTSQuerySessionInformationW call + WTSFreeMemory
// cleanup pattern used by sessionHasLoggedInUser. v1.2.0 visibility fix.
func wtsSessionString(sessionID uint32, infoClass uint32) string {
	var buf *uint16
	var bytesReturned uint32
	r1, _, _ := procWTSQuerySessionInformationW.Call(
		uintptr(wtsCurrentServerHandle),
		uintptr(sessionID),
		uintptr(infoClass),
		uintptr(unsafe.Pointer(&buf)),
		uintptr(unsafe.Pointer(&bytesReturned)),
	)
	if r1 == 0 || buf == nil {
		return ""
	}
	defer procWTSFreeMemory.Call(uintptr(unsafe.Pointer(buf)))
	if bytesReturned <= 2 {
		return ""
	}
	// Convert the UTF-16 NUL-terminated buffer to a Go string. Walk the
	// buffer up to bytesReturned/2 wchars to find the terminator.
	maxWChars := int(bytesReturned / 2)
	wchars := unsafe.Slice(buf, maxWChars)
	n := 0
	for n < maxWChars && wchars[n] != 0 {
		n++
	}
	return windows.UTF16ToString(wchars[:n])
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
		fallback, candidateName, fbErr := tokenFromUserSessionProcess(sessionID)
		if fbErr != nil {
			return 0, fmt.Errorf("WTSQueryUserToken(%d): %w; user-session-process fallback: %v", sessionID, wtsErr, fbErr)
		}
		userToken = fallback
		logf("service: WTSQueryUserToken failed (%v); user-session-process fallback found <%s> in session %d", wtsErr, candidateName, sessionID)
	} else {
		// v1.2.3 elevation fix: WTSQueryUserToken hands back the *filtered*
		// (UAC-limited) primary token for a split-token administrator.
		// app.manifest declares requireAdministrator, so CreateProcessAsUser
		// against the filtered token fails with ERROR_ELEVATION_REQUIRED
		// ("The requested operation requires elevation.") in an infinite
		// 2 s respawn loop. Swap to the elevated linked counterpart — the
		// same swap tokenFromUserSessionProcess already does for the
		// fallback path. elevatedLinkedToken returns (0, nil) when the
		// token isn't split (UAC off, built-in admin, or already full), in
		// which case we keep the original token as-is.
		if elevated, eErr := elevatedLinkedToken(userToken); eErr == nil && elevated != 0 {
			_ = userToken.Close()
			userToken = elevated
			logf("service: swapped WTSQueryUserToken's filtered token for its elevated linked counterpart")
		} else if eErr != nil {
			logf("service: elevatedLinkedToken on WTS token failed (%v); proceeding with filtered token", eErr)
		}
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

// userSessionCandidate names a well-known system-trusted process whose
// token represents the interactive console user. The image must live at
// the canonical path — we reject anything else so an attacker can't
// drop a `sihost.exe` in a writable directory and have the Service
// unwrap its linked elevated token.
//
// Priority order is preserved by candidateOrder: explorer.exe is the
// most common interactive-user token (it's what every standard logon
// produces), but a custom kiosk shell or a v1.1.x'd Explorer restart
// path that failed to respawn it can leave a session with no explorer.
// In that case sihost/taskhostw/RuntimeBroker/StartMenuExperienceHost
// are all auto-spawned by Windows under the interactive user's token
// and serve the same purpose.
type userSessionCandidate struct {
	name         string // e.g. "explorer.exe" (case-insensitive match)
	expectedPath string // canonical full path (case-insensitive compare)
	priority     int    // lower = preferred; 0 = explorer.exe
}

func candidateProcessList() []userSessionCandidate {
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = `C:\Windows`
	}
	return []userSessionCandidate{
		{name: "explorer.exe", expectedPath: systemRoot + `\explorer.exe`, priority: 0},
		{name: "sihost.exe", expectedPath: systemRoot + `\System32\sihost.exe`, priority: 1},
		{name: "taskhostw.exe", expectedPath: systemRoot + `\System32\taskhostw.exe`, priority: 2},
		{name: "RuntimeBroker.exe", expectedPath: systemRoot + `\System32\RuntimeBroker.exe`, priority: 3},
		{name: "StartMenuExperienceHost.exe", expectedPath: systemRoot + `\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe`, priority: 4},
	}
}

// tokenFromUserSessionProcess (v1.1.10, was tokenFromExplorerInSession in
// v1.1.3–v1.1.9) finds a system-trusted user-session process running in
// the target console session, opens its primary token, and returns it.
// If the process is running under a user with UAC enabled,
// OpenProcessToken returns the *limited* half of the UAC-split token —
// kiosk-exit-guard needs admin (HKLM writes, IFEO, etc.) so we unwrap
// the limited token to its linked elevated counterpart via
// GetTokenInformation(TokenLinkedToken).
//
// This is the standard workaround for WTSQueryUserToken returning
// ERROR_NO_TOKEN on machines where the documented path inexplicably
// fails (observed on Win11 Home in the field — see v1.1.3 changelog).
//
// v1.1.10 changes vs. v1.1.9:
//   - Enumerates via WTSEnumerateProcessesExW (wtsapi32) instead of
//     gopsutil. The user's affected machine had gopsutil returning an
//     empty list across sessions when invoked from LocalSystem; the
//     WTS API is the Win32-blessed path for service-side cross-session
//     enumeration and works reliably from Session 0.
//   - Accepts any of the well-known system-trusted user-session
//     processes (explorer.exe, sihost.exe, taskhostw.exe,
//     RuntimeBroker.exe, StartMenuExperienceHost.exe), prioritizing
//     explorer when present.
//
// Returns the token, the matched candidate name (for the log line in
// spawnControllerInSession), and an error.
func tokenFromUserSessionProcess(sessionID uint32) (windows.Token, string, error) {
	candidates := candidateProcessList()

	type match struct {
		pid      uint32
		cand     userSessionCandidate
	}
	var best *match

	processWTSResults := func(infos []wtsProcessInfoW) {
		for i := range infos {
			pi := &infos[i]
			if pi.SessionId != sessionID {
				continue
			}
			if pi.ProcessName == nil {
				continue
			}
			name := windows.UTF16PtrToString(pi.ProcessName)
			for _, c := range candidates {
				if !strings.EqualFold(name, c.name) {
					continue
				}
				if best != nil && best.cand.priority <= c.priority {
					// Already have an equal- or higher-priority match.
					continue
				}
				best = &match{pid: pi.ProcessId, cand: c}
				break
			}
		}
	}

	if err := enumerateWTSProcesses(sessionID, processWTSResults); err != nil {
		return 0, "", fmt.Errorf("WTSEnumerateProcessesExW: %w", err)
	}

	if best == nil {
		return 0, "", fmt.Errorf("no candidate process in session %d", sessionID)
	}

	hProc, oErr := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, best.pid)
	if oErr != nil {
		return 0, "", fmt.Errorf("OpenProcess(pid=%d, name=%s): %w", best.pid, best.cand.name, oErr)
	}

	// v1.1.8 HIGH#3 + MEDIUM#6: validate the process image path before
	// trusting its token. The WTS enumeration returns a process name
	// that doesn't authenticate identity — a kiosk user with write
	// access SOMEWHERE could spawn a renamed-to-sihost.exe binary, and
	// on the next supervisor tick we'd open its token, unwrap to the
	// linked elevated half, and CreateProcessAsUser attacker code as
	// the admin user. By calling QueryFullProcessImageName on the same
	// handle we used for OpenProcessToken we re-derive the image from
	// the kernel at the moment of token capture, which also closes the
	// PID-recycle race (the OS guarantees the handle still refers to
	// the originally-opened process for the lifetime of the handle).
	// Reject anything whose image path doesn't match the canonical
	// system path for the candidate.
	if !isLegitimateCandidateHandle(hProc, best.cand.expectedPath) {
		logf("service: rejecting non-canonical %s pid=%d (image path mismatch)", best.cand.name, best.pid)
		_ = windows.CloseHandle(hProc)
		return 0, "", fmt.Errorf("candidate %s pid=%d failed image-path validation", best.cand.name, best.pid)
	}

	var token windows.Token
	tErr := windows.OpenProcessToken(
		hProc,
		windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_IMPERSONATE,
		&token,
	)
	_ = windows.CloseHandle(hProc)
	if tErr != nil {
		return 0, "", fmt.Errorf("OpenProcessToken(pid=%d, name=%s): %w", best.pid, best.cand.name, tErr)
	}

	// If this is a UAC-split limited token, swap to its elevated linked
	// counterpart. kiosk-exit-guard needs admin to do its job — a
	// non-elevated controller can't write HKLM, register IFEO debugger
	// keys, or restart Explorer.
	if elevated, eErr := elevatedLinkedToken(token); eErr == nil && elevated != 0 {
		_ = token.Close()
		return elevated, best.cand.name, nil
	}
	// Either elevation type is "Default" (UAC off / built-in admin) or
	// "Full" (already elevated) — use the token as-is.
	return token, best.cand.name, nil
}

// enumerateWTSProcesses calls WTSEnumerateProcessesExW filtered to the
// given session ID and invokes cb with the resulting slice. The buffer
// is freed via WTSFreeMemoryExW before cb returns control to the
// caller's caller — critical because this runs every 2 seconds in the
// supervisor loop and leaks would compound.
//
// pLevel is in/out: we request level 0, the API confirms by writing 0
// back. We pass the target sessionID directly so the kernel filters for
// us (cheaper than enumerating every session and discarding).
func enumerateWTSProcesses(sessionID uint32, cb func([]wtsProcessInfoW)) error {
	level := uint32(wtsTypeProcessInfoLevel0)
	var pInfo *wtsProcessInfoW
	var count uint32

	r1, _, err := procWTSEnumerateProcessesExW.Call(
		uintptr(wtsCurrentServerHandle),
		uintptr(unsafe.Pointer(&level)),
		uintptr(sessionID),
		uintptr(unsafe.Pointer(&pInfo)),
		uintptr(unsafe.Pointer(&count)),
	)
	if r1 == 0 {
		return err
	}
	if pInfo == nil || count == 0 {
		// Free even on empty result — the API may have allocated a
		// zero-length buffer.
		if pInfo != nil {
			_, _, _ = procWTSFreeMemoryExW.Call(
				uintptr(wtsTypeProcessInfoLevel0),
				uintptr(unsafe.Pointer(pInfo)),
				uintptr(count),
			)
		}
		cb(nil)
		return nil
	}

	// Defensive: validate the on-disk struct size matches what we
	// declared. The amd64 layout is 24 bytes (compile-time asserted
	// above); this runtime check is a belt-and-suspenders guard against
	// the assertion ever being weakened.
	const expectedSize = 24
	if got := unsafe.Sizeof(wtsProcessInfoW{}); got != expectedSize {
		_, _, _ = procWTSFreeMemoryExW.Call(
			uintptr(wtsTypeProcessInfoLevel0),
			uintptr(unsafe.Pointer(pInfo)),
			uintptr(count),
		)
		return fmt.Errorf("wtsProcessInfoW size mismatch: got %d, expected %d", got, expectedSize)
	}

	// Build a Go slice over the C buffer without copying.
	infos := unsafe.Slice(pInfo, int(count))
	cb(infos)

	_, _, _ = procWTSFreeMemoryExW.Call(
		uintptr(wtsTypeProcessInfoLevel0),
		uintptr(unsafe.Pointer(pInfo)),
		uintptr(count),
	)
	return nil
}

// isLegitimateCandidateHandle reports whether the process referred to by
// hProc has an image path equal to the candidate's canonical path
// (case-insensitive). Called inside tokenFromUserSessionProcess right
// after a successful OpenProcess so we authenticate the process by its
// on-disk image — not by its enumerable name — before unwrapping its
// token.
//
// Closes v1.1.8 HIGH#3 (kiosk user spawns renamed-to-<candidate>.exe to
// have the Service unwrap its linked elevated token and execute
// attacker code) and v1.1.8 MEDIUM#6 (PID-recycle race: between WTS
// enumeration and OpenProcess the PID could in theory have been
// recycled — but the open handle pins the original kernel object, so
// QueryFullProcessImageName on that handle returns the image of
// whatever-the-kernel-currently-knows-as that handle, which is the
// process we opened, not a recycled one).
func isLegitimateCandidateHandle(hProc windows.Handle, expectedPath string) bool {
	expected := strings.ToLower(expectedPath)
	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(hProc, 0, &buf[0], &size); err != nil {
		logf("isLegitimateCandidateHandle: QueryFullProcessImageName failed: %v", err)
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
		// v1.1.10: don't log the v1.1.8 relocate-and-reexec normal case.
		// After the first-run relocate-from-Downloads-to-ProgramFiles
		// flow, the ORIGINAL parent exits before the re-execed child
		// runs the parent lookup. Windows returns ERROR_INVALID_PARAMETER
		// (87) for "PID no longer alive" and ERROR_ACCESS_DENIED (5)
		// for protected processes — both are expected and harmless
		// here; the caller falls back to the env-var hint, which is
		// the documented v1.1.0 behavior. Any other error still
		// surfaces so we can spot genuine failures.
		if errors.Is(err, syscall.Errno(windows.ERROR_INVALID_PARAMETER)) || errors.Is(err, syscall.Errno(windows.ERROR_ACCESS_DENIED)) {
			return "", false
		}
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
