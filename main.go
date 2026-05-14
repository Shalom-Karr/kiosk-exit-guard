//go:build windows && amd64

// kiosk-exit-guard v0.4.0 — Windows 11 Home kiosk lockdown utility.
//
// Architecture:
//
//   - The exe runs as a background controller (LL keyboard hook, registry
//     lockdown, kiosk-window supervisor). When filter mode is ON it launches
//     itself with the --webview flag as a child process to display the
//     kiosk page via embedded WebView2 (no Chrome dependency).
//   - First-run setup writes the bcrypt password hash and the kiosk URL to
//     HKLM\Software\KioskExitGuard (admin-write, can't be wiped by a
//     standard kiosk user). It also uninstalls Chrome silently and installs
//     an IFEO Debugger redirect on chrome.exe / msedge.exe so neither can
//     be launched as a kiosk-escape.
//   - When invoked via the IFEO Debugger redirect (Windows passes us a
//     --silent-exit flag followed by the target exe path), we exit
//     immediately — Chrome/Edge launches just silently fail.
//
// Flag summary:
//
//	(none)                  normal run — controller + hook + watchdog
//	--webview               render the WebView2 kiosk window
//	--silent-exit ...       no-op (IFEO Debugger redirect handler)
//	--set-password          change the password
//	--set-url               change the kiosk URL
//	--reset                 password-gated; clears registry lockdown + filter state
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/jchv/go-webview2"
	"github.com/ncruces/zenity"
	"github.com/shirou/gopsutil/v4/process"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// currentVersion must be kept in sync with versioninfo.json. Used by the
// --update flow to compare against the latest GitHub release tag.
const currentVersion = "1.2.6"

// Auto-update background-check timing. v1.2.1: the controller polls
// GitHub's /releases/latest on startup (after autoUpdateInitialDelay so
// the kiosk has time to settle) and every autoUpdateCheckInterval after
// that. On finding a newer release the controller spawns an
// `--auto-update-notify <newver>` child that renders the interactive
// "Update now? / Remind me later" WebView2 modal; the modal self-
// dismisses after autoUpdateDismissTimeout if nobody clicks.
const (
	autoUpdateInitialDelay   = 60 * time.Second
	autoUpdateCheckInterval  = 24 * time.Hour
	autoUpdateDismissTimeout = 60 * time.Second
)

// globalAutoUpdateNotifyMutexName guards runAutoUpdateChecker against
// stacking two notify children on top of each other (one from a normal
// 24h tick that races a freshly-spawned controller restart, for
// example). Admin-only DACL via acquireAdminOnlyNamedMutex.
const globalAutoUpdateNotifyMutexName = `Global\KioskExitGuardAutoUpdateNotify`

// ---------- logging ----------

const (
	logFileName    = "kiosk-exit-guard.log"
	logRotateBytes = 5 * 1024 * 1024 // 5 MB
)

var (
	logFile *os.File
	logMu   sync.Mutex
)

// initLogging opens kiosk-exit-guard.log next to the exe for append.
// Best-effort — if the open fails (read-only directory, permissions),
// logging silently no-ops and the rest of the controller keeps working.
func initLogging() {
	p, err := nextToExe(logFileName)
	if err != nil {
		return
	}
	// Naive size-based rotation: if the existing file is over the
	// rotate threshold, rename to .old (overwriting any previous .old)
	// and start a fresh file.
	if fi, err := os.Stat(p); err == nil && fi.Size() > logRotateBytes {
		_ = os.Remove(p + ".old")
		_ = os.Rename(p, p+".old")
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	logFile = f
	logf("--- start v%s pid=%d args=%v ---", currentVersion, os.Getpid(), os.Args[1:])
}

func logf(format string, args ...interface{}) {
	if logFile == nil {
		return
	}
	logMu.Lock()
	defer logMu.Unlock()
	line := fmt.Sprintf("[%s] %s\n",
		time.Now().Format("2006-01-02 15:04:05.000"),
		fmt.Sprintf(format, args...))
	_, _ = logFile.WriteString(line)
}

// recoverAndLog is a deferred panic capture. Use as
//
//	defer recoverAndLog("label")
//
// in goroutines so panics make it to the log file instead of
// disappearing into a stack trace nobody sees.
func recoverAndLog(where string) {
	if r := recover(); r != nil {
		logf("PANIC in %s: %v\n%s", where, r, string(debug.Stack()))
		// v1.1.9 UX HIGH#2: surface a user-visible toast before the
		// process tears down. Without this the controller would die
		// silently — the Service / scheduled task respawns it within
		// ~1s, but during the gap the kiosk WebView2 child disappears
		// and the user sees a black/desktop flash without explanation.
		// Spawned as a fire-and-forget child via the existing
		// --show-toast path so it survives this process's death.
		// Best-effort: any spawn failure is itself logged but we keep
		// going with the panic propagation (recover already consumed
		// the panic; we just return from this defer).
		if exe, err := os.Executable(); err == nil {
			cmd := exec.Command(exe, "--show-toast", "5000",
				"SK Filter restarted after an internal error. Auto-recovery in progress.")
			cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
			if startErr := cmd.Start(); startErr != nil {
				logf("recoverAndLog: failed to spawn recovery toast: %v", startErr)
			}
		}
	}
}

// scaleToastDim scales toast dimensions by the system DPI factor so
// toasts stay visually similar across DPI settings without going
// fullscreen (which would be overkill for a brief notification).
// Uses GetDpiForSystem on Win10 1607+, fallback 96 elsewhere.
func scaleToastDim(logical int) uint {
	dpi := uint(96)
	if err := procGetDpiForSystem.Find(); err == nil {
		if ret, _, _ := procGetDpiForSystem.Call(); ret != 0 {
			dpi = uint(ret)
		}
	}
	return uint(logical) * dpi / 96
}

// makeModalFullscreenTopmost makes a window fill the entire screen and
// sits topmost. Used for the password modal and first-run wizard so DPI
// scaling doesn't matter — the HTML's centered card lays itself out
// against whatever physical screen size we get. Sidesteps the "modal
// is too small on 4K displays" issue from v1.0.3-v1.0.4 entirely.
func makeModalFullscreenTopmost(hwnd uintptr) {
	if hwnd == 0 {
		return
	}
	const (
		wsExToolWindow = 0x00000080
		swpShow        = 0x0040
		swpFrameChang  = 0x0020
		swShow         = 5
	)
	cx, _, _ := procGetSystemMetrics.Call(smCXScreen)
	cy, _, _ := procGetSystemMetrics.Call(smCYScreen)
	procSetWindowLongPtrW.Call(hwnd, uintptr(gwlStyleU), uintptr(wsPopup|wsVisible))
	procSetWindowLongPtrW.Call(hwnd, uintptr(gwlExStyleU), uintptr(wsExTopmost|wsExToolWindow))
	procSetWindowPos.Call(hwnd, hwndTopmost, 0, 0, cx, cy, uintptr(swpShow|swpFrameChang))
	procShowWindow.Call(hwnd, uintptr(swShow))
	// v1.1.6: actually grab keyboard focus. Without this the modal is
	// visually on top but the kiosk WebView2 still owns input — user
	// types the password and it goes to the kiosk page. Triggered by
	// the user pressing Ctrl+Shift+Alt+K on the fullscreen kiosk and
	// seeing the modal not come to front. Uses the AttachThreadInput
	// idiom so we don't depend on SetForegroundWindow's eligibility
	// rules (which require the calling process to already own focus).
	forceForeground(hwnd)
}

// forceForeground steals foreground for hwnd from whichever window
// currently owns input. The AttachThreadInput trick temporarily
// merges our thread's input queue with the foreground thread's so
// the SetForegroundWindow call passes the eligibility check Windows
// applies (only the foreground process can normally grant foreground
// to another). Detaches in defer so a panic during the inner calls
// can't leak the input attach.
func forceForeground(hwnd uintptr) {
	if hwnd == 0 {
		return
	}
	fgHwnd, _, _ := procGetForegroundWindow.Call()
	if fgHwnd == hwnd {
		// Already foreground — nothing to steal.
		return
	}
	ourTid, _, _ := procGetCurrentThreadId.Call()
	if fgHwnd == 0 {
		// No foreground window — just call directly.
		procBringWindowToTop.Call(hwnd)
		procSetForegroundWindow.Call(hwnd)
		return
	}
	var fgPid uint32
	fgTid, _, _ := procGetWindowThreadProcessId.Call(fgHwnd, uintptr(unsafe.Pointer(&fgPid)))
	if fgTid == 0 || fgTid == ourTid {
		procSetForegroundWindow.Call(hwnd)
		return
	}
	procAttachThreadInput.Call(ourTid, fgTid, 1)
	defer procAttachThreadInput.Call(ourTid, fgTid, 0)
	procBringWindowToTop.Call(hwnd)
	procSetForegroundWindow.Call(hwnd)
}

// ---------- constants ----------

const (
	whKeyboardLL = 13
	wmKeyDown    = 0x0100
	wmKeyUp      = 0x0101
	wmSysKeyDown = 0x0104
	wmSysKeyUp   = 0x0105
	wmClose      = 0x0010

	// Function keys + system-shortcut keys. v1.2.6 widens the always-
	// blocked set to cover bare F1–F12, Tab, Escape, AppMenu (right-click
	// keyboard equivalent), PrintScreen, and Insert — see
	// isAlwaysBlockedKey for the swallow logic.
	vkTab    = 0x09
	vkEscape = 0x1B
	vkApps   = 0x5D // "menu" key, opens right-click context menu
	vkSnapshot = 0x2C // PrintScreen
	vkInsert = 0x2D
	vkF1     = 0x70
	vkF2     = 0x71
	vkF3     = 0x72
	vkF4     = 0x73
	vkF5     = 0x74
	vkF6     = 0x75
	vkF7     = 0x76
	vkF8     = 0x77
	vkF9     = 0x78
	vkF10    = 0x79
	vkF11    = 0x7A
	vkF12    = 0x7B
	vkR      = 0x52
	vkK      = 0x4B
	vk0      = 0x30 // browser zoom reset
	vkNum0   = 0x60 // numpad 0
	// VK_OEM_MINUS / VK_OEM_PLUS are the top-row -/= keys; numpad has
	// dedicated subtract/add VKs. All four pass through for zoom.
	vkOemMinus  = 0xBD
	vkOemPlus   = 0xBB
	vkSubtract  = 0x6D
	vkAdd       = 0x6B
	vkLMenu  = 0xA4
	vkRMenu  = 0xA5
	vkLWin   = 0x5B
	vkRWin   = 0x5C
	vkLCtrl  = 0xA2
	vkRCtrl  = 0xA3
	vkLShift = 0xA0
	vkRShift = 0xA1

	llkhfInject = 0x10

	// HKCU policy paths used for Task Manager + Run dialog lockdown
	regPolicySystem   = `Software\Microsoft\Windows\CurrentVersion\Policies\System`
	regPolicyExplorer = `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
	regDisableTaskMgr     = "DisableTaskMgr"
	regNoRun              = "NoRun"
	regNoTrayContextMenu  = "NoTrayContextMenu"
	regNoViewContextMenu  = "NoViewContextMenu"
	regNoTaskbar          = "NoTaskbar" // hides the taskbar entirely when filter active

	regAppKey         = `Software\KioskExitGuard`
	regHashValue      = "PasswordHash"
	regURLValue       = "KioskURL"
	regZoomValue      = "KioskZoom"      // DWORD: page zoom percent (50–200, default 100). v1.2.4
	regFilterModeVal  = "FilterMode"     // DWORD: 1 = active, 0 = paused
	regPauseUntilVal  = "PauseUntilNano" // QWORD: unix nano of pause expiry, 0 = no pause

	defaultKioskZoom = 100 // percent
	minKioskZoom     = 50
	maxKioskZoom     = 200

	ifeoBase = `Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`

	taskName         = "KioskExitGuard"
	stateFileName    = "filter_mode.state"
	hashFileName     = "password.hash" // legacy file — migrated to HKLM
	kioskURLFileName = "kiosk.url"     // legacy file — migrated to HKLM
	pauseFileName    = "pause_until.state"

	defaultKioskURL  = "https://skluach.pages.dev/CMH/"
	watchdogInterval = 30 * time.Second
	toastTimeoutMs   = 2000

	createNoWindow = 0x08000000
)

// Win32 constants for fullscreen + topmost window manipulation
const (
	// GWL_STYLE / GWL_EXSTYLE are negative; encode their two's-complement
	// bit pattern as uint32 so we can pass them through Call() cleanly.
	gwlStyleU     uint32 = 0xFFFFFFF0 // -16 reinterpreted
	gwlExStyleU   uint32 = 0xFFFFFFEC // -20 reinterpreted
	wsPopup       uint32 = 0x80000000
	wsVisible     uint32 = 0x10000000
	wsExTopmost   uint32 = 0x00000008
	swpShowWindow        = 0x0040
	swpFrameChang        = 0x0020
	smCXScreen           = 0
	smCYScreen           = 1
)

var hwndTopmost = ^uintptr(0) // (HWND)-1

type kbdLLHookStruct struct {
	VkCode      uint32
	ScanCode    uint32
	Flags       uint32
	Time        uint32
	DwExtraInfo uintptr
}

type msgT struct {
	HWnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
}

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procSetWindowHookExW    = user32.NewProc("SetWindowsHookExW")
	procUnhookWindowsHookEx = user32.NewProc("UnhookWindowsHookEx")
	procCallNextHookEx      = user32.NewProc("CallNextHookEx")
	procGetMessageW         = user32.NewProc("GetMessageW")
	procGetAsyncKeyState    = user32.NewProc("GetAsyncKeyState")
	procGetForegroundWindow = user32.NewProc("GetForegroundWindow")
	procPostMessageW        = user32.NewProc("PostMessageW")
	procSetWindowLongPtrW   = user32.NewProc("SetWindowLongPtrW")
	procSetWindowPos        = user32.NewProc("SetWindowPos")
	procGetSystemMetrics    = user32.NewProc("GetSystemMetrics")
	procSendInput           = user32.NewProc("SendInput")
	procSetForegroundWindow      = user32.NewProc("SetForegroundWindow")
	procBringWindowToTop         = user32.NewProc("BringWindowToTop")
	procGetDpiForSystem          = user32.NewProc("GetDpiForSystem")
	procGetWindowThreadProcessId = user32.NewProc("GetWindowThreadProcessId")
	procAttachThreadInput        = user32.NewProc("AttachThreadInput")
	procShowWindow               = user32.NewProc("ShowWindow")

	procCreateMutexW      = kernel32.NewProc("CreateMutexW")
	procReleaseMutex      = kernel32.NewProc("ReleaseMutex")
	procCloseHandle       = kernel32.NewProc("CloseHandle")
	procGetLastError      = kernel32.NewProc("GetLastError")
	procGetCurrentThreadId = kernel32.NewProc("GetCurrentThreadId")

	storedHash []byte
	promptOpen atomic.Bool
	filterMode atomic.Bool

	// hookPromptInFlight is set by hookCallback via CompareAndSwap to
	// guarantee at most one re-inject goroutine spawn per blocked combo.
	// promptOpen alone is insufficient because it isn't set until the
	// spawned goroutine actually enters askPasswordModal — a second
	// blocked combo arriving during that gap would race and overwrite
	// pendingComboV. Cleared by the goroutine on exit. Non-hook prompt
	// paths (promptAndPause, --reset, --uninstall, etc.) continue to
	// CAS on promptOpen themselves; they don't touch this flag.
	hookPromptInFlight atomic.Bool

	// winKeyChord stays true while a Win key is held with no other key
	// pressed since. On Win up, if it's still true → "Win alone" → prompt.
	// If any non-modifier key fires while Win is held, we clear it (this
	// is a combo, handled by the normal combo path).
	winKeyChord atomic.Bool

	pauseUntilNano atomic.Int64

	pauseTimerMu sync.Mutex
	pauseTimer   *time.Timer
)

// ---------- file paths ----------

func nextToExe(name string) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(exe), name), nil
}

func hashPath() (string, error)     { return nextToExe(hashFileName) }
func statePath() (string, error)    { return nextToExe(stateFileName) }
func kioskURLPath() (string, error) { return nextToExe(kioskURLFileName) }
func pausePath() (string, error)    { return nextToExe(pauseFileName) }

// canonicalInstallDir returns the canonical install directory under
// %ProgramFiles%\KioskExitGuard. Using %ProgramFiles% (env-resolved, not
// hardcoded) means we land in C:\Program Files on a normal Win11 box and
// in the localized path on non-en-US installs. Admin-write-only by
// default DACL inherited from %ProgramFiles%.
func canonicalInstallDir() string {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, "KioskExitGuard")
}

// canonicalInstallPath is the canonical exe location v1.1.8+ relocates
// to on first run so the SCM-registered binary path can't be replaced
// by the kiosk user. v1.1.8 security fix CRITICAL#1.
func canonicalInstallPath() string {
	return filepath.Join(canonicalInstallDir(), "kiosk-exit-guard.exe")
}

// programDataDir returns %ProgramData%\KioskExitGuard — the admin-only
// staging + WebView2 user-data root. Created lazily by ensureAdminOnlyDir.
func programDataDir() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "KioskExitGuard")
}

// ensureAdminOnlyDir creates dir (and any missing parents) and tightens
// the DACL via icacls so only SYSTEM and BUILTIN\Administrators can read
// or write. Idempotent — safe to call on every controller startup. Used
// for the v1.1.8 update-staging dir (CRITICAL#2) and the WebView2
// user-data dir (HIGH#4) so a non-admin kiosk user can't poison either.
//
// Returns nil on success. On failure logs and returns the error; callers
// generally treat failure as fatal for the operation they were trying to
// secure (e.g. abort the --update flow).
func ensureAdminOnlyDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	// icacls returns 0 on success and a non-zero code with a message on
	// failure. The "/inheritance:r" removes inherited ACEs so a less-
	// restrictive %ProgramData% inheritance can't widen access; the two
	// /grant:r entries then re-add only SYSTEM and Administrators with
	// (OI)(CI)F = full control, object + container inherit. Result: any
	// new file under dir is also admin-only by inheritance.
	cmd := exec.Command("icacls", dir,
		"/inheritance:r",
		"/grant:r", "SYSTEM:(OI)(CI)F",
		"/grant:r", "Administrators:(OI)(CI)F")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	if out, err := cmd.CombinedOutput(); err != nil {
		// Log but don't fail — the directory still exists, just with
		// inherited (potentially broader) ACL. Callers can decide whether
		// that's acceptable.
		logf("ensureAdminOnlyDir(%s): icacls failed: %v: %s", dir, err, strings.TrimSpace(string(out)))
		return fmt.Errorf("icacls %s: %w", dir, err)
	}
	return nil
}

// webView2DataPath is the WebView2 user-data folder shared across all
// in-process WebView2 instances (password modal, toast, first-run wizard,
// kiosk page, update notify). v1.1.8 security fix HIGH#4 moved the profile
// out of %LOCALAPPDATA% to keep the kiosk user from planting a service
// worker that intercepts the password modal's kgSubmit binding.
func webView2DataPath() string {
	return filepath.Join(programDataDir(), "WebView2")
}

// ensureWebView2DataDir lazily creates the WebView2 user-data directory
// and ensures the running user can read+write it.
//
// v1.2.2 regression fix: prior versions called ensureAdminOnlyDir() here,
// which set the DACL to SYSTEM+Administrators only. The kiosk controller
// runs as a non-admin user, so msedgewebview2.exe — spawned in that
// user's token — couldn't create EBWebView and surfaced "Microsoft Edge
// can't read and write to its data directory: C:\ProgramData\
// KioskExitGuard\WebView2\EBWebView". The admin-only DACL locked out the
// very process WebView2 was running as.
//
// Now we grant BUILTIN\Users Modify (OI+CI) so the kiosk user can create
// the profile. The original HIGH#4 threat (kiosk user planting a service
// worker via direct file-write) is partially restored by the fact that
// %ProgramData% is not a path the kiosk user normally browses to, but the
// real defense remains "all in-process WebView2s share this profile, so
// the kiosk page itself can plant a SW that the modal will inherit" — a
// JS-context isolation problem better fixed by per-purpose DataPaths,
// tracked for a future change.
//
// Idempotent. The icacls grant repairs older installs whose DACL was
// stripped by ensureAdminOnlyDir; it is best-effort — if the caller
// lacks WRITE_DAC (non-admin invocation against a pre-existing locked
// dir) the grant fails silently and the launch will still surface the
// "can't read and write" error, in which case an admin must run:
//
//   icacls "C:\ProgramData\KioskExitGuard\WebView2" /grant "Users:(OI)(CI)M"
//
// to repair the existing install.
func ensureWebView2DataDir() string {
	p := webView2DataPath()
	_ = os.MkdirAll(p, 0o700)
	cmd := exec.Command("icacls", p, "/grant", `BUILTIN\Users:(OI)(CI)M`)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	_ = cmd.Run()
	return p
}

// ---------- HKLM password / URL storage ----------

func loadHashFromRegistry() ([]byte, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, regAppKey, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer k.Close()
	hash, _, err := k.GetBinaryValue(regHashValue)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return hash, nil
}

func saveHashToRegistry(hash []byte) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, regAppKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open %s: %w", regAppKey, err)
	}
	defer k.Close()
	if err := k.SetBinaryValue(regHashValue, hash); err != nil {
		return err
	}
	// v1.1.8 HIGH#5: HKLM\Software inherits BUILTIN\Users:KEY_READ by
	// default, so the bcrypt hash was readable by any local user (and
	// thus targetable by an offline crack). Tighten the DACL right
	// after a successful write so existing installs heal on first
	// launch of the new exe. tightenHKLMConfigDACL is idempotent.
	tightenHKLMConfigDACL()
	return nil
}

// tightenHKLMConfigDACL installs an admin-only DACL on the HKLM config
// key (HKLM\Software\KioskExitGuard) so the bcrypt password hash is not
// readable by BUILTIN\Users. The default %SystemRoot% ACL inherits
// BUILTIN\Users:KEY_READ from HKLM\Software, which exposes the hash to
// any local user — they can then target the hash with an offline
// dictionary crack. After this call the key (and any subkey created
// later, via the CI = container-inherit flag in the SDDL) is readable
// and writable only by SYSTEM and BUILTIN\Administrators.
//
// SDDL meaning: D:PAI(A;CI;KA;;;SY)(A;CI;KA;;;BA)
//   - D: → DACL section
//   - P → SE_DACL_PROTECTED (do NOT inherit from HKLM\Software, which
//     is the entire point — otherwise BUILTIN\Users:KEY_READ leaks in)
//   - AI → SE_DACL_AUTO_INHERITED (well-formed; child keys inherit)
//   - (A;CI;KA;;;SY) → ALLOW SYSTEM KEY_ALL_ACCESS, container-inherit
//   - (A;CI;KA;;;BA) → ALLOW BUILTIN\Administrators KEY_ALL_ACCESS, CI
//
// The --ask-password child runs as the same admin user that launched
// the controller, so granting BUILTIN\Administrators is sufficient for
// every internal call site. Idempotent: re-applies the same DACL on
// every saveHashToRegistry call and on every controller startup.
func tightenHKLMConfigDACL() {
	const sddl = `D:PAI(A;CI;KA;;;SY)(A;CI;KA;;;BA)`
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		logf("tightenHKLMConfigDACL: SecurityDescriptorFromString failed: %v", err)
		return
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		logf("tightenHKLMConfigDACL: SECURITY_DESCRIPTOR.DACL() failed: %v", err)
		return
	}
	// SetNamedSecurityInfo with SE_REGISTRY_KEY: object name uses the
	// "MACHINE\..." prefix (NOT the registry path syntax the registry
	// package wants — the Win32 advapi32 API takes a different shape).
	objName := `MACHINE\` + regAppKey
	if err := windows.SetNamedSecurityInfo(
		objName,
		windows.SE_REGISTRY_KEY,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	); err != nil {
		// v1.1.10: silence ERROR_FILE_NOT_FOUND. The HKLM key is only
		// created the first time saveHashToRegistry runs (i.e. after
		// the user completes the first-run wizard). v1.1.8 placed this
		// tighten call at controller startup ALSO — before any save —
		// so on a fresh install we'd hit "The system cannot find the
		// file specified." every launch. The next saveHashToRegistry
		// call applies the same DACL anyway, so the key gets tightened
		// when it actually exists. Only noisy log lines suppressed —
		// any other error (access denied, invalid SDDL, etc.) still
		// surfaces.
		if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
			return
		}
		logf("tightenHKLMConfigDACL: SetNamedSecurityInfo(%s) failed: %v", objName, err)
	}
}

func loadKioskURLFromRegistry() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, regAppKey, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue(regURLValue)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(v)
}

func saveKioskURLToRegistry(url string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, regAppKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(regURLValue, url)
}

// clampKioskZoom keeps a user-supplied percent inside the supported
// range. Anything below minKioskZoom or above maxKioskZoom is silently
// snapped — both promptForKioskURL and the first-run wizard pre-validate,
// but this is also the gate the runWebViewKiosk reader leans on so a
// corrupted registry value can't render the kiosk at 1% or 10000%.
func clampKioskZoom(percent int) int {
	if percent < minKioskZoom {
		return minKioskZoom
	}
	if percent > maxKioskZoom {
		return maxKioskZoom
	}
	return percent
}

// loadKioskZoomPercent reads the persisted page-zoom percent from HKLM,
// defaulting to defaultKioskZoom when the value is absent or unreadable.
// The result is always inside [minKioskZoom, maxKioskZoom].
func loadKioskZoomPercent() int {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, regAppKey, registry.QUERY_VALUE)
	if err != nil {
		return defaultKioskZoom
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(regZoomValue)
	if err != nil {
		return defaultKioskZoom
	}
	return clampKioskZoom(int(v))
}

func saveKioskZoomPercent(percent int) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, regAppKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetDWordValue(regZoomValue, uint32(clampKioskZoom(percent)))
}

func migrateLegacyHash() {
	p, err := hashPath()
	if err != nil {
		return
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return
	}
	regHash, _ := loadHashFromRegistry()
	if len(regHash) > 0 {
		_ = os.Remove(p)
		return
	}
	hash := []byte(strings.TrimSpace(string(data)))
	if len(hash) == 0 {
		return
	}
	if err := saveHashToRegistry(hash); err == nil {
		_ = os.Remove(p)
	}
}

func loadHash() ([]byte, error) {
	return loadHashFromRegistry()
}

func setPassword() error {
	pw, err := zenity.Entry(
		"Set the kiosk-exit password.\nKeep this secret — anyone with it can dismiss the kiosk and toggle filter mode.",
		zenity.Title("kiosk-exit-guard — set password"),
		zenity.HideText(),
	)
	if err != nil {
		return err
	}
	if pw == "" {
		return fmt.Errorf("empty password rejected")
	}
	confirm, err := zenity.Entry(
		"Re-enter the password to confirm.",
		zenity.Title("kiosk-exit-guard — confirm"),
		zenity.HideText(),
	)
	if err != nil {
		return err
	}
	if pw != confirm {
		return fmt.Errorf("passwords do not match")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return saveHashToRegistry(hash)
}

func loadKioskURL() string {
	if u := loadKioskURLFromRegistry(); u != "" {
		return u
	}
	if p, err := kioskURLPath(); err == nil {
		if data, err := os.ReadFile(p); err == nil {
			if u := strings.TrimSpace(string(data)); u != "" {
				return u
			}
		}
	}
	return defaultKioskURL
}

// isValidKioskURL accepts http://, https://, or file:// URLs with a non-
// empty host/path. Trims and lowercases the scheme for comparison. We don't
// require a fully-RFC-compliant URL — WebView2 is lenient — but reject the
// common typo cases ("htttp://", missing scheme, plain "www.example.com")
// that would silently land on a Chromium error page.
func isValidKioskURL(u string) bool {
	u = strings.TrimSpace(u)
	if u == "" {
		return false
	}
	low := strings.ToLower(u)
	for _, prefix := range []string{"https://", "http://", "file:///"} {
		if strings.HasPrefix(low, prefix) && len(u) > len(prefix) {
			return true
		}
	}
	return false
}

func promptForKioskURL() (string, error) {
	current := loadKioskURL()
	for {
		url, err := zenity.Entry(
			"Enter the kiosk URL.\nThis is the page WebView2 will open in fullscreen.\n\nMust start with https://, http://, or file:///.",
			zenity.Title("kiosk-exit-guard — kiosk URL"),
			zenity.EntryText(current),
		)
		if err != nil {
			return "", err
		}
		url = strings.TrimSpace(url)
		if url == "" {
			url = current
		}
		if !isValidKioskURL(url) {
			_ = zenity.Warning(
				"That doesn't look like a valid URL.\n\nPlease enter something starting with https://, http://, or file:///.",
				zenity.Title("kiosk-exit-guard — kiosk URL"),
			)
			current = url // keep what they typed so they can edit it
			continue
		}
		if err := saveKioskURLToRegistry(url); err != nil {
			return "", err
		}
		// v1.2.4: also collect the WebView2 page-zoom percent. Saved to
		// the same HKLM key so the kiosk respawn picks it up. A cancel
		// at this second prompt does NOT roll back the URL save above —
		// the URL change is the primary intent, the zoom is a secondary
		// preference. Bad input gets snapped via clampKioskZoom rather
		// than re-prompting in a loop, on the theory that an admin who
		// typed "0" probably wants "50" (the minimum), not a re-prompt.
		if _, err := promptForKioskZoom(); err != nil && !errors.Is(err, zenity.ErrCanceled) {
			return "", err
		}
		return url, nil
	}
}

// promptForKioskZoom asks the admin for the default page-zoom percent
// (50–200) and persists it to HKLM. The default value pre-filled in the
// entry is the currently-stored zoom (or 100 first time). Returns the
// final saved percent. Cancel returns (0, zenity.ErrCanceled) so callers
// can distinguish "I didn't want to change zoom" from a real error.
func promptForKioskZoom() (int, error) {
	current := loadKioskZoomPercent()
	raw, err := zenity.Entry(
		fmt.Sprintf("Default page zoom for the kiosk window.\nA value below 100 zooms out, above 100 zooms in.\nCurrent: %d%%\nAllowed range: %d–%d.", current, minKioskZoom, maxKioskZoom),
		zenity.Title("kiosk-exit-guard — kiosk zoom"),
		zenity.EntryText(strconv.Itoa(current)),
	)
	if err != nil {
		return 0, err
	}
	raw = strings.TrimSpace(raw)
	raw = strings.TrimSuffix(raw, "%")
	raw = strings.TrimSpace(raw)
	if raw == "" {
		// Empty input = keep current. Don't re-save, but treat as success.
		return current, nil
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		// Garbage input — fall back to current rather than blocking the
		// flow with a re-prompt loop. The admin can re-run --set-url if
		// they care.
		return current, nil
	}
	zoom := clampKioskZoom(parsed)
	if err := saveKioskZoomPercent(zoom); err != nil {
		return 0, err
	}
	return zoom, nil
}

// ---------- filter mode + pause persistence ----------

// Filter mode + pause state both live in HKLM\Software\KioskExitGuard
// alongside the password hash, so they're admin-write-only and a
// standard kiosk user can't tamper by editing a file. The functions
// below keep the original names for call-site compatibility but back
// onto the registry. (Files in C:\Program Files were already admin-
// write-only in practice, but the registry path doesn't depend on the
// install location's ACLs.)

func loadFilterModeFromDisk() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, regAppKey, registry.QUERY_VALUE)
	if err != nil {
		return true // default-ON
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(regFilterModeVal)
	if err != nil {
		return true
	}
	return v == 1
}

func saveFilterModeToDisk(on bool) {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, regAppKey, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	var v uint32 = 0
	if on {
		v = 1
	}
	_ = k.SetDWordValue(regFilterModeVal, v)
}

func savePauseToDisk(until time.Time) {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, regAppKey, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	if until.IsZero() {
		_ = k.DeleteValue(regPauseUntilVal)
		return
	}
	_ = k.SetQWordValue(regPauseUntilVal, uint64(until.UnixNano()))
}

func loadPauseFromDisk() time.Time {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, regAppKey, registry.QUERY_VALUE)
	if err != nil {
		return time.Time{}
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(regPauseUntilVal)
	if err != nil || v == 0 {
		return time.Time{}
	}
	return time.Unix(0, int64(v))
}

// migrateLegacyState copies v1.0.4-and-earlier file-based state into the
// HKLM registry then deletes the file. Idempotent — no-op if files are
// missing or registry already has the values.
func migrateLegacyState() {
	if p, err := statePath(); err == nil {
		if data, rerr := os.ReadFile(p); rerr == nil {
			on := strings.TrimSpace(string(data)) == "1"
			saveFilterModeToDisk(on)
			_ = os.Remove(p)
		}
	}
	if p, err := pausePath(); err == nil {
		if data, rerr := os.ReadFile(p); rerr == nil {
			var nano int64
			if _, serr := fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &nano); serr == nil && nano > 0 {
				savePauseToDisk(time.Unix(0, nano))
			}
			_ = os.Remove(p)
		}
	}
}

func isPaused() bool {
	nano := pauseUntilNano.Load()
	if nano == 0 {
		return false
	}
	return time.Now().UnixNano() < nano
}

func setPauseUntil(t time.Time) {
	if t.IsZero() {
		pauseUntilNano.Store(0)
	} else {
		pauseUntilNano.Store(t.UnixNano())
	}
	savePauseToDisk(t)
}

// ---------- registry lockdown (HKCU) ----------

func setPolicyDWORD(subkey, name string, value uint32) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, subkey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open %s: %w", subkey, err)
	}
	defer k.Close()
	return k.SetDWordValue(name, value)
}

func deletePolicyValue(subkey, name string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, subkey, registry.SET_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return err
	}
	defer k.Close()
	err = k.DeleteValue(name)
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}

func applyLockdown() {
	_ = setPolicyDWORD(regPolicySystem, regDisableTaskMgr, 1)
	_ = setPolicyDWORD(regPolicyExplorer, regNoRun, 1)
	// Disable right-click context menus on the taskbar and the desktop.
	// Otherwise the user could right-click the kiosk's taskbar thumbnail
	// and pick "Close Window", bypassing our Alt+F4 password gate.
	_ = setPolicyDWORD(regPolicyExplorer, regNoTrayContextMenu, 1)
	_ = setPolicyDWORD(regPolicyExplorer, regNoViewContextMenu, 1)
	// Hide the taskbar entirely. Without this, a single LEFT click on the
	// Start button opens Start menu — from which Settings/File Explorer
	// are reachable. The Win-key keyboard hook can't catch a mouse click.
	_ = setPolicyDWORD(regPolicyExplorer, regNoTaskbar, 1)
	// NoTaskbar requires Explorer to reload its policy cache. Restart
	// Explorer so the change takes effect immediately.
	restartExplorer()
}

func removeLockdown() {
	_ = deletePolicyValue(regPolicySystem, regDisableTaskMgr)
	_ = deletePolicyValue(regPolicyExplorer, regNoRun)
	_ = deletePolicyValue(regPolicyExplorer, regNoTrayContextMenu)
	_ = deletePolicyValue(regPolicyExplorer, regNoViewContextMenu)
	_ = deletePolicyValue(regPolicyExplorer, regNoTaskbar)
	// Bring the taskbar back immediately rather than waiting for next
	// Explorer restart.
	restartExplorer()
}

// restartExplorer kills explorer.exe and lets Windows auto-relaunch it
// (the Shell registry entry triggers respawn). Needed to flush taskbar
// policy changes (NoTaskbar) which Explorer caches at startup.
//
// v1.1.11: on Server 2022 (and any custom-shell setup) the registered
// shell may not be explorer.exe — Server Core / fresh Server 2022
// installs without Desktop Experience don't even have explorer.exe as
// the user's shell. Killing explorer there is at best a no-op and at
// worst loses the user's actual shell permanently mid-session. Check
// HKLM\...\Winlogon\Shell first; only proceed if it's exactly
// "explorer.exe" (case-insensitive). The NoTaskbar policy still gets
// written; it just won't take effect until next logon — acceptable
// since a non-Explorer shell is the user's deliberate choice.
func restartExplorer() {
	const winlogonKey = `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, winlogonKey, registry.QUERY_VALUE)
	if err != nil {
		logf("restartExplorer: could not open Winlogon key: %v — skipping restart", err)
		return
	}
	shell, _, sErr := k.GetStringValue("Shell")
	k.Close()
	if sErr != nil {
		logf("restartExplorer: could not read Winlogon Shell value: %v — skipping restart", sErr)
		return
	}
	if !strings.EqualFold(strings.TrimSpace(shell), "explorer.exe") {
		logf("restartExplorer: registered shell is %q, not explorer.exe — skipping restart", shell)
		return
	}
	cmd := exec.Command("cmd.exe", "/c", "taskkill /F /IM explorer.exe & start explorer.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	_ = cmd.Run()
}

// ---------- IFEO browser launch block ----------

// setIFEOBlock makes any attempt to launch targetExe re-launch us with the
// --silent-exit flag (we exit immediately). Standard kiosk user cannot edit
// HKLM, so they can't remove the block.
func setIFEOBlock(targetExe string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	keyPath := ifeoBase + `\` + targetExe
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, keyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue("Debugger", fmt.Sprintf(`"%s" --silent-exit`, exe))
}

func removeIFEOBlock(targetExe string) {
	keyPath := ifeoBase + `\` + targetExe
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.SET_VALUE)
	if err != nil {
		// v1.1.11: silently absorb "no such key" — on Server 2022 fresh
		// installs the IFEO entry may never have been written (e.g. the
		// browser wasn't installed, so setIFEOBlock skipped — actually
		// setIFEOBlock writes unconditionally, but the v1.1.x removal
		// paths fire on uninstall / resume / reset, and a partial install
		// can legitimately leave the key absent). Other errors still log
		// for audit.
		if errors.Is(err, registry.ErrNotExist) || errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
			return
		}
		logf("removeIFEOBlock(%s): OpenKey failed: %v", targetExe, err)
		return
	}
	defer k.Close()
	_ = k.DeleteValue("Debugger")
}

// blockedExes lists every executable redirected to --silent-exit via IFEO
// Debugger. Both browsers (chrome/msedge) and the Windows accessibility
// helpers, which expose dialog-driven hyperlinks into Windows Settings
// when invoked (e.g. five-times-Shift opens Sticky Keys' setup dialog).
var blockedExes = []string{
	"chrome.exe", "msedge.exe",
	"sethc.exe",   // Sticky Keys (5x Shift)
	"osk.exe",     // On-Screen Keyboard
	"narrator.exe", // Narrator
	"utilman.exe", // Ease of Access launcher (Win+U)
	"magnify.exe", // Magnifier
}

func applyBrowserBlocks() {
	for _, exe := range blockedExes {
		_ = setIFEOBlock(exe)
	}
}

func removeBrowserBlocks() {
	for _, exe := range blockedExes {
		removeIFEOBlock(exe)
	}
}

// ---------- Chrome silent uninstall ----------

// uninstallChrome reads Chrome's UninstallString from the registry and
// runs it with --force-uninstall flags. Returns nil if Chrome isn't
// installed (treated as success since the end state is what we wanted).
func uninstallChrome() error {
	candidates := []struct {
		Root registry.Key
		Path string
	}{
		{registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome`},
		{registry.LOCAL_MACHINE, `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome`},
		{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome`},
	}
	found := false
	for _, c := range candidates {
		k, err := registry.OpenKey(c.Root, c.Path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		uninstallStr, _, err := k.GetStringValue("UninstallString")
		k.Close()
		if err != nil || uninstallStr == "" {
			continue
		}
		found = true
		// Chrome's uninstaller can hang behind a "close all Chrome windows"
		// prompt on some builds — bound the wait so first-run setup doesn't
		// appear frozen. If the uninstaller is still running after 60s we
		// kill it and continue; the IFEO block in the next step is what
		// actually prevents Chrome from being usable as a kiosk-escape, so
		// a leftover Chrome install is non-fatal.
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		cmd := exec.CommandContext(ctx, "cmd", "/C", uninstallStr+" --force-uninstall --do-not-launch-chrome")
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
		err = cmd.Run()
		cancel()
		if err == nil {
			return nil
		}
		logf("chrome uninstaller did not exit cleanly: %v (continuing — IFEO block still applies)", err)
	}
	// v1.1.11: distinguish "not installed" (info, expected on Server 2022
	// fresh installs) from "uninstall failed" (error path above already
	// logged). Either way return nil — the IFEO block is the actual
	// enforcement; missing Chrome is a clean end state.
	if !found {
		logf("uninstallChrome: Chrome not installed, skipping uninstall")
	}
	return nil
}

// ---------- self-install via schtasks ----------

// installStartupTask registers the controller's auto-launch via the
// PowerShell ScheduledTasks module:
//
//   - Single AtLogon trigger (no every-minute watchdog from v1.0.x —
//     the v1.1.x Windows Service handles respawn supervision; the
//     scheduled task is purely a logon-time "make sure it starts"
//     fallback for installs where the Service spawn path fails).
//   - MultipleInstances=IgnoreNew → re-logons during a session don't
//     stack instances
//   - AllowStartIfOnBatteries / DontStopIfGoingOnBatteries / StartWhenAvailable
//   - ExecutionTimeLimit=0 (no timeout — controller runs until killed)
//   - RestartOnFailure: 3 retries, 1 minute apart
//   - RunLevel=Highest (no UAC prompt at fire time; admin token from task)
//
// Idempotent: -Force replaces any existing task with the same name.
//
// v1.1.4 changes: dropped the every-1-minute repetition that v1.0.x
// used for watchdog respawn. The Service is the respawn supervisor
// now. Keeping the every-minute trigger alongside the Service caused
// kill/respawn churn — both auto-start paths would fire, the second
// to start would killRunningController() the first, the loser's
// supervisor would respawn, repeat. AtLogon-only stabilizes the
// race to a single contention at boot.
func installStartupTask() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// v1.1.8 MEDIUM#8: PowerShell-injection hardening. Previously the
	// exe path + task name were interpolated into the PowerShell
	// heredoc via fmt.Sprintf with a single-quote escape. Not
	// exploitable today because os.Executable returns a kernel-derived
	// path and taskName is a compile-time constant, but fragile — any
	// future change letting attacker-controlled data flow into either
	// variable becomes a code-execution bug. Pass both via environment
	// variables ($env:KEG_EXE / $env:KEG_TASKNAME) and base64-encode
	// the script body so quoting / parser edge cases in the values
	// can't escape into the surrounding shell syntax.
	//
	// PowerShell's -EncodedCommand expects a UTF-16-LE base64-encoded
	// script. cmd.Env scoping keeps KEG_EXE/KEG_TASKNAME out of the
	// parent process's environment.
	const psScript = `
$action  = New-ScheduledTaskAction -Execute $env:KEG_EXE
$logon   = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -Hidden
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest -LogonType Interactive
Register-ScheduledTask -TaskName $env:KEG_TASKNAME -Action $action -Trigger $logon -Settings $settings -Principal $principal -Force | Out-Null
`
	utf16 := utf16LEBytes(psScript)
	encoded := base64.StdEncoding.EncodeToString(utf16)
	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	cmd.Env = append(os.Environ(),
		"KEG_EXE="+exe,
		"KEG_TASKNAME="+taskName,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("Register-ScheduledTask failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// utf16LEBytes encodes a Go string into the little-endian UTF-16 byte
// sequence PowerShell -EncodedCommand expects. Pure helper; no error
// path because surrogate-pair handling is delegated to utf16.Encode
// inside syscall.UTF16FromString which is well-tested for this exact
// use case. v1.1.8 MEDIUM#8 helper.
func utf16LEBytes(s string) []byte {
	enc, _ := syscall.UTF16FromString(s)
	// syscall.UTF16FromString terminates with a NUL; strip it so the
	// PowerShell parser doesn't see a stray null at end-of-script.
	if n := len(enc); n > 0 && enc[n-1] == 0 {
		enc = enc[:n-1]
	}
	out := make([]byte, len(enc)*2)
	for i, w := range enc {
		out[i*2] = byte(w)
		out[i*2+1] = byte(w >> 8)
	}
	return out
}

// ---------- key state ----------

func keyDown(vk uint32) bool {
	r, _, _ := procGetAsyncKeyState.Call(uintptr(vk))
	return (uint16(r) & 0x8000) != 0
}

func altDown() bool   { return keyDown(vkLMenu) || keyDown(vkRMenu) }
func winDown() bool   { return keyDown(vkLWin) || keyDown(vkRWin) }
func ctrlDown() bool  { return keyDown(vkLCtrl) || keyDown(vkRCtrl) }
func shiftDown() bool { return keyDown(vkLShift) || keyDown(vkRShift) }

func isModifierVK(vk uint32) bool {
	switch vk {
	case vkLCtrl, vkRCtrl, vkLMenu, vkRMenu, vkLWin, vkRWin, vkLShift, vkRShift:
		return true
	}
	return false
}

// isAlwaysBlockedKey returns true for keys that are blocked regardless
// of modifier state — even bare presses go through the password-prompt
// path instead of reaching the kiosk page. v1.2.6 widened the lockdown
// in response to a field report that bare F-keys, Tab, and similar
// "system shortcut" keys were leaking through to the kiosk URL. The
// previous hook only swallowed *modifier+key* combos; a bare F11 (toggle
// fullscreen), F12 (DevTools — already disabled by WebView2 but a
// hardening defense), Tab (focus the address bar in normal Edge, focus
// next form field in the kiosk page), or Escape (exit fullscreen / close
// modals) all fell straight through to the page.
//
// The intent: nothing on this list is a typing key. Letters, numbers,
// space, punctuation, Enter, Backspace, arrows, and Delete still reach
// the page normally for form fill-in. Page-scroll navigation keys
// (Home/End/PgUp/PgDn) are intentionally NOT on this list so the kiosk
// page can be scrolled.
func isAlwaysBlockedKey(vk uint32) bool {
	switch vk {
	case vkTab, vkEscape, vkApps, vkSnapshot, vkInsert,
		vkF1, vkF2, vkF3, vkF4, vkF5, vkF6,
		vkF7, vkF8, vkF9, vkF10, vkF11, vkF12:
		return true
	}
	return false
}

// isAlwaysAllowedCombo lets specific keystrokes through even when the
// filter is active. Allowlist (Ctrl-only — no Alt / no Win):
//   - Ctrl+R: page reload
//   - Ctrl+0 / Ctrl+numpad-0: browser zoom reset
//   - Ctrl+- / Ctrl+numpad-minus: browser zoom out
//   - Ctrl++ / Ctrl+= / Ctrl+numpad-plus: browser zoom in
//
// v1.2.6 removed bare F5 — it's now caught by isAlwaysBlockedKey.
// Admins who want a manual reload still have Ctrl+R.
func isAlwaysAllowedCombo(vk uint32) bool {
	if !ctrlDown() || altDown() || winDown() {
		return false
	}
	switch vk {
	case vkR, // Ctrl+R reload
		vk0, vkNum0, // Ctrl+0 zoom reset
		vkOemMinus, vkSubtract, // Ctrl+- zoom out
		vkOemPlus, vkAdd: // Ctrl++ / Ctrl+= zoom in (US layout: Plus shares the = key)
		return true
	}
	return false
}

// makeWindowTopmostFront forces a window to the top of the z-order and
// gives it focus. Used for the password modal so it appears over the
// fullscreen topmost WebView2 kiosk window.
func makeWindowTopmostFront(hwnd uintptr) {
	if hwnd == 0 {
		return
	}
	const (
		swpNoMove = 0x0002
		swpNoSize = 0x0001
		swpShow   = 0x0040
	)
	procSetWindowPos.Call(hwnd, hwndTopmost, 0, 0, 0, 0,
		uintptr(swpNoMove|swpNoSize|swpShow))
	procBringWindowToTop.Call(hwnd)
	procSetForegroundWindow.Call(hwnd)
}

// makeModalFrameless strips the title bar and system menu from the
// modal's window so the user can't close it via the X button. The
// password modal is then dismissable only through the in-page Cancel
// button (or correct password). Critical to prevent killing the modal
// from bypassing the password gate.
//
// Earlier revisions also called BringWindowToTop + SetForegroundWindow
// here, but SetForegroundWindow has strict eligibility rules and on some
// Windows builds the combination contributed to a modal hang ("not
// responding" + blank white page). The combination of WS_POPUP + the
// WS_EX_TOPMOST extended style + HWND_TOPMOST in SetWindowPos is enough
// to put the modal above the kiosk without needing to steal foreground.
func makeModalFrameless(hwnd uintptr) {
	if hwnd == 0 {
		return
	}
	const (
		wsExToolWindow = 0x00000080
		swpNoMove      = 0x0002
		swpNoSize      = 0x0001
		swpShow        = 0x0040
		swpFrameChang  = 0x0020
	)
	procSetWindowLongPtrW.Call(hwnd, uintptr(gwlStyleU), uintptr(wsPopup|wsVisible))
	procSetWindowLongPtrW.Call(hwnd, uintptr(gwlExStyleU), uintptr(wsExTopmost|wsExToolWindow))
	procSetWindowPos.Call(hwnd, hwndTopmost, 0, 0, 0, 0,
		uintptr(swpNoMove|swpNoSize|swpShow|swpFrameChang))
}

// ---------- SendInput re-injection ----------

// INPUT on x64 is 40 bytes: 4 (type) + 4 (alignment pad) + 32 (largest
// union member is MOUSEINPUT, padded to 32 for ULONG_PTR alignment).
type winInput struct {
	Type uint32
	_    uint32
	U    [32]byte
}

type keybdInput struct {
	Vk        uint16
	Scan      uint16
	Flags     uint32
	Time      uint32
	ExtraInfo uintptr
}

const (
	inputKeyboard  = 1
	keyeventfKeyUp = 0x0002
)

// kioskMarker is a per-process, cryptographically-random sentinel value
// stuffed into SendInput's ExtraInfo on every key event we re-inject.
// hookCallback recognizes events carrying this value as our own and lets
// them pass through. Using a random per-process value (instead of a
// fixed compile-time constant) prevents a hostile external process from
// guessing the marker and bypassing the hook by calling SendInput with
// the magic value in ExtraInfo. Populated in init() before the LL hook
// is installed; never logged.
var kioskMarker uintptr

func init() {
	var buf [8]byte
	for {
		if _, err := rand.Read(buf[:]); err != nil {
			// crypto/rand failure on Windows is extraordinarily unlikely;
			// panic so the controller doesn't run with a zero marker.
			panic("kiosk-exit-guard: crypto/rand failed: " + err.Error())
		}
		v := binary.LittleEndian.Uint64(buf[:])
		if v != 0 {
			kioskMarker = uintptr(v)
			return
		}
	}
}

// buildKey constructs an INPUT for a single key event. The kiosk marker
// is stuffed into ExtraInfo so our own hook recognizes these as our own
// re-injection and lets them through.
func buildKey(vk uint32, up bool) winInput {
	var in winInput
	in.Type = inputKeyboard
	k := (*keybdInput)(unsafe.Pointer(&in.U[0]))
	k.Vk = uint16(vk)
	if up {
		k.Flags = keyeventfKeyUp
	}
	k.ExtraInfo = kioskMarker
	return in
}

// sendKeyCombo replays the given key combo via SendInput. Modifiers are
// pressed in order, the main key is press/released, then modifiers are
// released in reverse. The kiosk-exit-guard marker in ExtraInfo means
// our own hook callback won't re-block these.
func sendKeyCombo(modifiers []uint32, vk uint32) {
	if procSendInput.Find() != nil {
		return
	}
	inputs := make([]winInput, 0, 2*len(modifiers)+2)
	for _, m := range modifiers {
		inputs = append(inputs, buildKey(m, false))
	}
	inputs = append(inputs, buildKey(vk, false), buildKey(vk, true))
	for i := len(modifiers) - 1; i >= 0; i-- {
		inputs = append(inputs, buildKey(modifiers[i], true))
	}
	procSendInput.Call(
		uintptr(len(inputs)),
		uintptr(unsafe.Pointer(&inputs[0])),
		unsafe.Sizeof(inputs[0]),
	)
}

// pendingCombo captures the key + modifier state we swallowed, waiting on
// password verification before re-injecting.
type pendingCombo struct {
	vk        uint32
	modifiers []uint32
}

var (
	pendingComboMu sync.Mutex
	pendingComboV  *pendingCombo
)

func capturedModifiers() []uint32 {
	mods := make([]uint32, 0, 4)
	if ctrlDown() {
		mods = append(mods, vkLCtrl)
	}
	if shiftDown() {
		mods = append(mods, vkLShift)
	}
	if altDown() {
		mods = append(mods, vkLMenu)
	}
	if winDown() {
		mods = append(mods, vkLWin)
	}
	return mods
}

// ---------- toast helpers ----------

// toastHTML is the in-page template for our WebView2-based toast. The
// page itself sets a timer that calls kgClose() after the requested
// duration, so the Go side just spins up the window and waits for Run()
// to return when the close binding fires.
const toastHTML = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<style>
  *,*::before,*::after { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; height: 100vh;
    background: transparent;
    font-family: -apple-system, "Segoe UI", system-ui, sans-serif;
    -webkit-font-smoothing: antialiased; color: #f1f5f9; }
  .wrap { height: 100vh; display: flex; align-items: center; justify-content: center; padding: 0.6rem; }
  .toast { display: flex; align-items: center; gap: 0.85rem;
    background: linear-gradient(180deg, rgba(35, 47, 72, 0.97), rgba(26, 36, 56, 0.97));
    border: 1px solid rgba(148, 163, 184, 0.28); border-radius: 12px;
    padding: 0.85rem 1.15rem; font-size: 0.92rem; line-height: 1.5;
    box-shadow: 0 18px 50px rgba(0,0,0,0.55); width: 100%; }
  .badge { color: #38bdf8; font-size: 0.68rem; font-weight: 700;
    letter-spacing: 0.12em; text-transform: uppercase; flex-shrink: 0; }
  .msg { white-space: pre-line; }
</style></head><body>
<div class="wrap"><div class="toast">
  <span class="badge">SK Filter</span>
  <span class="msg" id="m"></span>
</div></div>
<script>
  document.getElementById('m').textContent = window.__msg || '';
  setTimeout(function() { if (window.kgClose) window.kgClose(); }, window.__ms || 2000);
</script>
</body></html>`

// showFrontmostToast renders a brief WebView2 toast and ensures it sits
// above the fullscreen topmost kiosk window. Falls back to zenity if
// WebView2 fails (Runtime missing).
func showFrontmostToast(text string, duration time.Duration) {
	// v1.1.8 HIGH#4: pin the WebView2 user-data folder to an admin-only
	// directory under %ProgramData% so a kiosk user can't poison the
	// profile (service worker that scrapes the kgSubmit binding's
	// password, persisted permissions, etc.). Default DataPath lives
	// under %LOCALAPPDATA% which IS user-writable.
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: false,
		DataPath:  ensureWebView2DataDir(),
		WindowOptions: webview2.WindowOptions{
			Title:  "SK Filter",
			Width:  scaleToastDim(480),
			Height: scaleToastDim(120),
			Center: true,
		},
	})
	if w == nil {
		ctx, cancel := context.WithTimeout(context.Background(), duration)
		defer cancel()
		_ = zenity.Info(text, zenity.Title("SK Filter"), zenity.Context(ctx))
		return
	}
	defer w.Destroy()

	w.Bind("kgClose", func() {
		w.Terminate()
	})

	// Tight poll: apply frameless+topmost the moment HWND is valid.
	// No fixed delay — the toast must show on top instantly.
	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			h := uintptr(w.Window())
			if h != 0 {
				makeModalFrameless(h)
				return
			}
			time.Sleep(15 * time.Millisecond)
		}
	}()

	w.Init(fmt.Sprintf(`window.__msg = %q; window.__ms = %d;`, text, duration.Milliseconds()))
	w.SetHtml(toastHTML)
	w.Run()
}

// showTimedInfo renders a brief branded toast. Always spawned as a
// `--show-toast` child process — never an in-process WebView2 — so the
// caller's process can use WebView2 for a password modal, first-run
// wizard, etc. without hitting the go-webview2 second-instance panic.
// Fire-and-forget; the child auto-dismisses after toastTimeoutMs ms.
//
// History: pre-v1.1.2 this called showFrontmostToast in-process. The
// controller (which uses WebView2 for first-run setup) would then crash
// the first time autoReenableFilterMode fired after a pause expired,
// because that toast was the 2nd WebView2 in the controller's lifetime.
// The crash dropped the LL keyboard hook and the Win key fell through
// until the supervising Service respawned the controller. Spawning a
// child sidesteps the issue: the child's WebView2 is always its first.
func showTimedInfo(text string) {
	exe, err := os.Executable()
	if err != nil {
		// Last-resort fallback. If we can't locate ourselves we have no
		// way to spawn the child; the original in-process path may panic
		// but is better than no feedback.
		showFrontmostToast(text, toastTimeoutMs*time.Millisecond)
		return
	}
	cmd := exec.Command(exe, "--show-toast", strconv.Itoa(toastTimeoutMs), text)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	_ = cmd.Start()
}

func showFailedToast() { showTimedInfo("Wrong password.") }

// showTimedInfoSync is the synchronous variant of showTimedInfo: it
// spawns the same --show-toast child process but cmd.Run() blocks until
// the child renders + dismisses. v1.1.9 UX MEDIUM#9: used by the
// pause / update / set-url flows that exit immediately after a
// "wrong password" or "operation cancelled" toast — the parent dying
// before the child paints meant the toast could fail to render. Use
// this only at exit-then-die call sites; fire-and-forget toasts during
// steady-state operation should keep using showTimedInfo.
func showTimedInfoSync(text string) {
	exe, err := os.Executable()
	if err != nil {
		showFrontmostToast(text, toastTimeoutMs*time.Millisecond)
		return
	}
	cmd := exec.Command(exe, "--show-toast", strconv.Itoa(toastTimeoutMs), text)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	_ = cmd.Run()
}

// showFailedToastSync is the synchronous "Wrong password." toast used at
// exit-after-failure call sites where the parent calls os.Exit(1)
// immediately after. v1.1.9 UX MEDIUM#9.
func showFailedToastSync() { showTimedInfoSync("Wrong password.") }

// ---------- WebView2 runtime auto-install ----------

const (
	// Microsoft's evergreen WebView2 bootstrapper. Tiny (~2 MB), downloads
	// the real runtime as needed. Same URL the Microsoft docs publish.
	webView2InstallerURL = "https://go.microsoft.com/fwlink/p/?LinkId=2124703"

	// WebView2 Runtime is detected via a "pv" version string under any of
	// these EdgeUpdate keys. See https://learn.microsoft.com/microsoft-edge/webview2/concepts/distribution#detect-if-a-suitable-webview2-runtime-is-already-installed
	webView2GUID = `{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}`
)

// isWebView2Installed returns true if any of the three canonical registry
// locations report a non-empty WebView2 Runtime "pv" version.
func isWebView2Installed() bool {
	type loc struct {
		root registry.Key
		path string
	}
	locs := []loc{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\EdgeUpdate\Clients\` + webView2GUID},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\` + webView2GUID},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\EdgeUpdate\Clients\` + webView2GUID},
	}
	for _, l := range locs {
		k, err := registry.OpenKey(l.root, l.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		pv, _, perr := k.GetStringValue("pv")
		k.Close()
		if perr == nil && pv != "" && pv != "0.0.0.0" {
			return true
		}
	}
	return false
}

func downloadFile(url, dest string) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "kiosk-exit-guard")
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

// installWebView2Runtime downloads the evergreen bootstrapper to TEMP and
// runs it silently. Bootstrapper handles the actual runtime download itself.
func installWebView2Runtime() error {
	tmpPath := filepath.Join(os.TempDir(), "MicrosoftEdgeWebview2Setup.exe")
	if err := downloadFile(webView2InstallerURL, tmpPath); err != nil {
		return fmt.Errorf("download bootstrapper: %w", err)
	}
	defer os.Remove(tmpPath)
	cmd := exec.Command(tmpPath, "/silent", "/install")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("bootstrapper exit: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ensureWebView2Installed is called by the controller before doing anything
// that needs the runtime. If missing, shows a non-blocking progress dialog
// and runs the silent install. On Win10/11 client SKUs this is a no-op
// (runtime ships pre-installed); on Server SKUs and stripped images it does
// the real work.
func ensureWebView2Installed() error {
	if isWebView2Installed() {
		return nil
	}
	// Spawn the "installing…" dialog asynchronously. Cancel its context
	// once the install completes so the dialog auto-closes.
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = zenity.Info(
			"WebView2 Runtime is missing — installing now.\nThis takes about 30 seconds and runs in the background.\n\nDo not close this window.",
			zenity.Title("kiosk-exit-guard — installing WebView2"),
			zenity.Context(ctx),
		)
	}()
	err := installWebView2Runtime()
	cancel()
	if err != nil {
		return err
	}
	if !isWebView2Installed() {
		return fmt.Errorf("bootstrapper exited cleanly but runtime still not detected")
	}
	return nil
}

// ---------- desktop shortcuts + per-action scheduled tasks ----------
//
// v1.2.4 changed the shortcut model. Before, each .lnk pointed directly at
// kiosk-exit-guard.exe with a flag like --pause; because the exe carries a
// requireAdministrator manifest, every click fired UAC, and for non-admin
// kiosk users the operation simply failed with "Access is denied" because
// they couldn't pass the consent prompt and didn't have HKLM write rights
// anyway.
//
// v1.2.4 routes each shortcut through a pre-registered Task Scheduler
// task running as NT AUTHORITY\SYSTEM with HighestAvailable run level and
// on-demand only. The shortcut's TargetPath is schtasks.exe and the
// argument is `/Run /TN KioskExitGuard_<Action>`. Triggering a task
// doesn't require UAC for the user (the default task DACL grants Users
// Execute), and the task body runs as SYSTEM — which has every privilege
// the action might need — and re-spawns the flag into the active user's
// session via spawnFlagAsUserInSession so the password modal and any
// other UI still render on the user's desktop.

// shortcutSpec ties together the desktop .lnk filename, the scheduled-
// task name, and the kiosk-exit-guard.exe flag the task executes.
// Keeping these in one table means an admin adding a new shortcut later
// only edits this list — createDesktopShortcut, installShortcutTasks,
// uninstallShortcutTasks, and removeDesktopShortcuts all walk the same
// data.
type shortcutSpec struct {
	lnkName     string // file under <Desktop>\ (without .lnk extension is added below)
	taskName    string // Task Scheduler task name; prefixed KioskExitGuard_ for namespacing
	flag        string // argument passed to kiosk-exit-guard.exe inside the task
	description string // shown in the .lnk's tooltip
}

func shortcutSpecs() []shortcutSpec {
	return []shortcutSpec{
		{"Pause SK Filter", "KioskExitGuard_Pause", "--pause",
			"Pause the SK Filter for a set time (password required)"},
		{"Resume SK Filter", "KioskExitGuard_Resume", "--resume",
			"End the current pause and re-activate the SK Filter"},
		{"Launch Kiosk", "KioskExitGuard_LaunchKiosk", "--launch-kiosk",
			"Re-open the kiosk window manually (no-op when filter is paused)"},
		{"Update SK Filter", "KioskExitGuard_Update", "--update",
			"Check GitHub for a new version of the SK Filter (password required to install)"},
		{"Change Kiosk URL", "KioskExitGuard_SetURL", "--set-url",
			"Change the URL the kiosk opens (password required)"},
		{"Uninstall SK Filter", "KioskExitGuard_Uninstall", "--uninstall",
			"Remove the SK Filter (password required)"},
	}
}

// schtasksPath resolves to %SystemRoot%\System32\schtasks.exe. Using the
// fully-qualified path means a kiosk user can't squat schtasks.exe in a
// writable PATH directory.
func schtasksPath() string {
	sysroot := os.Getenv("SystemRoot")
	if sysroot == "" {
		sysroot = `C:\Windows`
	}
	return filepath.Join(sysroot, "System32", "schtasks.exe")
}

// installShortcutTasks (idempotent) registers one Task Scheduler entry
// per shortcut action under \KioskExitGuard\. Each task runs as SYSTEM
// with HighestAvailable, on-demand only (no trigger), and its action
// invokes `<canonical-exe> --shortcut-handler <flag>`. The handler
// re-spawns the flag into the active user's session via
// spawnFlagAsUserInSession so the action's UI lands on the user's
// desktop. Re-running this function /Create /F-overwrites the existing
// definitions, so it's safe to call on every controller startup.
func installShortcutTasks() error {
	exe := canonicalInstallPath()
	for _, sc := range shortcutSpecs() {
		// schtasks /Create /F /TN <name>
		//   /TR "\"<exe>\" --shortcut-handler <flag>"
		//   /SC ONCE /ST 00:00 /RU SYSTEM /RL HIGHEST
		// /SC ONCE + /ST 00:00 is a no-op trigger in the past; combined
		// with /Z (= delete after expiry) it would delete itself, so we
		// omit /Z. Default DACL on a SYSTEM /HIGHEST task grants Users
		// Read + Execute, which is exactly the "any logged-in user can
		// /Run this" permission we need. We don't need to touch the SD.
		tr := fmt.Sprintf(`"%s" --shortcut-handler %s`, exe, sc.flag)
		args := []string{
			"/Create", "/F",
			"/TN", sc.taskName,
			"/TR", tr,
			"/SC", "ONCE",
			"/ST", "00:00",
			"/RU", "SYSTEM",
			"/RL", "HIGHEST",
		}
		cmd := exec.Command(schtasksPath(), args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
		if out, err := cmd.CombinedOutput(); err != nil {
			logf("installShortcutTasks: schtasks /Create %s failed: %v: %s", sc.taskName, err, strings.TrimSpace(string(out)))
			return fmt.Errorf("schtasks /Create %s: %w", sc.taskName, err)
		}
	}
	logf("installShortcutTasks: registered %d shortcut tasks", len(shortcutSpecs()))
	return nil
}

// uninstallShortcutTasks (idempotent) deletes every task registered by
// installShortcutTasks. Errors are logged and swallowed — a task that's
// already gone (or was never registered, e.g. upgrading from <v1.2.4) is
// not an uninstall failure.
func uninstallShortcutTasks() {
	for _, sc := range shortcutSpecs() {
		cmd := exec.Command(schtasksPath(), "/Delete", "/F", "/TN", sc.taskName)
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
		if out, err := cmd.CombinedOutput(); err != nil {
			// schtasks returns exit 1 with "ERROR: The system cannot find
			// the file specified" when the task doesn't exist — fine.
			outStr := strings.TrimSpace(string(out))
			if !strings.Contains(outStr, "cannot find") {
				logf("uninstallShortcutTasks: schtasks /Delete %s: %v: %s", sc.taskName, err, outStr)
			}
		}
	}
}

// runShortcutHandler is the entry point for the SYSTEM-context scheduled
// task fired by a desktop shortcut click. It looks up the active user
// session and re-spawns the requested flag into that session via
// spawnFlagAsUserInSession. The session-1 (or whatever) child runs in
// the user's interactive desktop with their token, so UI (password
// modal, duration picker, kiosk window) renders normally. The flag's
// existing implementation in main() handles the rest exactly as if the
// admin had double-clicked --pause / --resume / etc. directly.
//
// Errors are logged but otherwise swallowed — there's no UI in session 0
// to surface them, and the shortcut click is already over.
func runShortcutHandler(flag string) {
	sessionID, ok := pickActiveUserSession()
	if !ok {
		logf("shortcut-handler %s: pickActiveUserSession found no active user; nothing to do", flag)
		return
	}
	if err := spawnFlagAsUserInSession(sessionID, flag); err != nil {
		logf("shortcut-handler %s: spawnFlagAsUserInSession(session=%d) failed: %v", flag, sessionID, err)
		return
	}
}

// removeStalePerUserShortcuts is the v1.2.5 upgrade-cleanup pass: pre-
// v1.2.4 installs wrote the .lnk files to the *per-user* desktop with
// TargetPath = kiosk-exit-guard.exe (direct, UAC-triggering). v1.2.4
// moved them to the Public/All-Users desktop with TargetPath =
// schtasks.exe. When upgrading from <v1.2.4 those old per-user .lnks
// are stranded — the new schtasks-routed shortcuts get written to a
// different folder, so the user sees BOTH and the old direct-to-exe
// .lnks still fire UAC. This helper deletes the old .lnks from every
// loaded user's desktop (the only one we can reach as the currently-
// running controller is the active user's) so an admin upgrade leaves
// a clean desktop. Run BEFORE createDesktopShortcut so the freshly-
// written public-desktop .lnks aren't accidentally caught.
//
// Idempotent. Missing .lnks (fresh install, already-cleaned) are
// absorbed by Remove-Item -ErrorAction SilentlyContinue.
func removeStalePerUserShortcuts() {
	ps := `
$lnks = @('Kiosk Exit Guard.lnk','Pause SK Filter.lnk','Resume SK Filter.lnk','Launch Kiosk.lnk','Change Kiosk URL.lnk','Update SK Filter.lnk','Uninstall SK Filter.lnk')
$d = [Environment]::GetFolderPath('Desktop')
if ($d) {
    foreach ($n in $lnks) {
        Remove-Item -Path (Join-Path $d $n) -Force -ErrorAction SilentlyContinue
    }
}
`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	_ = cmd.Run()
}

// createDesktopShortcut (re)writes one .lnk per shortcutSpec on the
// current user's desktop. v1.2.4: each .lnk's TargetPath is
// schtasks.exe and the argument is `/Run /TN KioskExitGuard_<Action>`,
// so clicking the shortcut triggers the corresponding scheduled task
// (which then spawns the action into the user's session via
// runShortcutHandler). The shortcut's IconLocation still points at the
// canonical kiosk-exit-guard.exe so the .lnk shows the brand icon, not
// the generic schtasks icon.
//
// WindowStyle = 7 (Minimized) hides the brief schtasks console window
// flash that would otherwise pop on click; the actual UI surfaces from
// the spawned user-session child a moment later.
//
// v1.2.5: calls removeStalePerUserShortcuts first so an upgrade from
// <v1.2.4 doesn't leave the old direct-to-exe .lnks visible alongside
// the new schtasks-routed ones on the public desktop.
//
// Idempotent: re-creating overwrites the existing .lnk.
func createDesktopShortcut() error {
	removeStalePerUserShortcuts()
	icon := canonicalInstallPath()
	iconQ := strings.ReplaceAll(icon, `'`, `''`)
	stPath := schtasksPath()
	stPathQ := strings.ReplaceAll(stPath, `'`, `''`)

	var sb strings.Builder
	// v1.2.4: write to the Public/All Users desktop (CommonDesktopDirectory)
	// instead of the current user's desktop. Wizard runs as admin, so
	// pre-v1.2.4 the shortcuts landed on admin's desktop and a separate
	// non-admin kiosk user never saw them. Public desktop is rendered on
	// every user's desktop, so the shortcuts appear regardless of which
	// account is logged in.
	sb.WriteString(`$ws = New-Object -ComObject WScript.Shell
$desktop = [Environment]::GetFolderPath('CommonDesktopDirectory')
if (-not $desktop) { $desktop = [Environment]::GetFolderPath('Desktop') }
`)
	for _, sc := range shortcutSpecs() {
		lnkNameQ := strings.ReplaceAll(sc.lnkName, `'`, `''`)
		descQ := strings.ReplaceAll(sc.description, `'`, `''`)
		fmt.Fprintf(&sb, `
$lnk = $ws.CreateShortcut((Join-Path $desktop '%s.lnk'))
$lnk.TargetPath = '%s'
$lnk.Arguments = '/Run /TN %s'
$lnk.WorkingDirectory = ''
$lnk.IconLocation = ('%s' + ',0')
$lnk.Description = '%s'
$lnk.WindowStyle = 7
$lnk.Save()
`, lnkNameQ, stPathQ, sc.taskName, iconQ, descQ)
	}

	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", sb.String())
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("shortcut create failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ---------- first-run wizard (WebView2-backed) ----------

const firstRunHTML = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<style>
  *,*::before,*::after { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; background: radial-gradient(ellipse at top, #131c30, #0b1220 65%);
    color: #f1f5f9; font-family: -apple-system, "Segoe UI", system-ui, sans-serif;
    line-height: 1.55; min-height: 100vh; -webkit-font-smoothing: antialiased; }
  /* v1.2.5 UI audit: min-height + overflow-y means the wizard's 7-field
     form (pw1, pw2, url, zoom, error, actions, plus header) scrolls into
     view on short viewports — previous height: 100vh + overflow: hidden
     clipped the top on portrait 1280×1760 + 300% scaling and on tiny
     landscape windows. */
  .wrap { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 1.5rem; overflow-y: auto; }
  .card { background: linear-gradient(180deg, #232f48, #1a2438);
    border: 1px solid rgba(148, 163, 184, 0.22); border-radius: 16px;
    padding: 2.25rem 2.5rem; width: 100%; max-width: 560px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.45); }
  /* v1.2.5 UI audit: bumped from 520px → 560px so the new zoom field
     (added in v1.2.4) doesn't squeeze the help text. */
  h1 { font-size: 1.65rem; margin: 0 0 0.5rem; letter-spacing: -0.02em; font-weight: 700; }
  .pill { display: inline-block; background: rgba(56, 189, 248, 0.15); color: #38bdf8;
    padding: 0.15rem 0.6rem; border-radius: 999px; font-size: 0.7rem; font-weight: 700;
    margin-left: 0.5rem; vertical-align: middle; letter-spacing: 0.04em; text-transform: uppercase; }
  .subtitle { color: #94a3b8; font-size: 0.95rem; margin: 0 0 1.75rem; max-width: 44ch; }
  .field { margin-bottom: 1.15rem; }
  label { display: block; font-size: 0.78rem; color: #94a3b8; margin-bottom: 0.4rem;
    font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
  input { width: 100%; padding: 0.75rem 1rem; border-radius: 8px;
    border: 1px solid rgba(148, 163, 184, 0.25); background: rgba(15, 23, 42, 0.7);
    color: #f1f5f9; font-size: 0.95rem; font-family: inherit; transition: border-color 0.15s; }
  input:focus { outline: none; border-color: #38bdf8; box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.15); }
  .help { color: #64748b; font-size: 0.8rem; margin: 0.35rem 0 0; }
  .error { color: #ef4444; font-size: 0.85rem; min-height: 1.2em; margin: 0.65rem 0 0;
    background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.25);
    padding: 0.5rem 0.75rem; border-radius: 6px; display: none; }
  .error.show { display: block; }
  .actions { display: flex; gap: 0.6rem; justify-content: flex-end; margin-top: 1.65rem; }
  button { padding: 0.75rem 1.7rem; border-radius: 9px; border: 0; cursor: pointer;
    font-weight: 700; font-size: 0.95rem; font-family: inherit; transition: background 0.15s, transform 0.1s; }
  button:disabled { opacity: 0.55; cursor: not-allowed; }
  .btn-primary { background: #38bdf8; color: #0b1220; }
  .btn-primary:hover:not(:disabled) { background: #7dd3fc; }
  .btn-primary:active:not(:disabled) { transform: translateY(1px); }
  .btn-secondary { background: transparent; color: #94a3b8;
    border: 1px solid rgba(148, 163, 184, 0.3); }
  .btn-secondary:hover { color: #f1f5f9; border-color: rgba(148, 163, 184, 0.55); }
  .steps { display: flex; gap: 1rem; margin-bottom: 1.5rem; padding: 0.85rem 1rem;
    background: rgba(15, 23, 42, 0.5); border-radius: 8px; border: 1px solid rgba(148, 163, 184, 0.12);
    font-size: 0.78rem; color: #94a3b8; }
  .steps strong { color: #f1f5f9; display: block; font-size: 0.8rem; margin-bottom: 0.15rem; font-weight: 600; }
  .step { flex: 1; }
  .step.done { opacity: 0.55; }
  .step.done strong::before { content: '✓ '; color: #22c55e; }
</style></head>
<body>
<div class="wrap">
  <div class="card">
    <h1>kiosk-exit-guard <span class="pill">first run</span></h1>
    <p class="subtitle">Set an admin password and the kiosk URL. Setup will then uninstall Chrome, block Edge launches, and install the auto-start task.</p>

    <div class="steps">
      <div class="step"><strong>1 · Password</strong>Used to exit kiosk &amp; toggle filter mode</div>
      <div class="step"><strong>2 · Kiosk URL</strong>The page WebView2 will display</div>
      <div class="step"><strong>3 · System setup</strong>Chrome / Edge / startup task</div>
    </div>

    <div class="field">
      <label for="pw1">Admin password</label>
      <input type="password" id="pw1" autofocus />
    </div>
    <div class="field">
      <label for="pw2">Confirm password</label>
      <input type="password" id="pw2" />
    </div>
    <div class="field">
      <label for="url">Kiosk URL</label>
      <input type="text" id="url" value="" />
      <p class="help">Pre-filled with the most recent value. Anything you can open in a browser works.</p>
    </div>
    <div class="field">
      <label for="zoom">Default page zoom (%)</label>
      <input type="number" id="zoom" min="50" max="200" step="5" value="100" />
      <p class="help">Below 100 zooms out, above 100 zooms in. 90 is a common pick for fitting more on screen.</p>
    </div>

    <div class="error" id="error"></div>

    <div class="actions">
      <button class="btn-secondary" onclick="cancel()">Cancel</button>
      <button class="btn-primary" id="submit" onclick="submit()">Continue</button>
    </div>
  </div>
</div>

<script>
  document.getElementById('url').value = window.__defaultURL || 'https://skluach.pages.dev/CMH/';
  document.getElementById('zoom').value = window.__defaultZoom || 100;
  function showErr(msg) {
    var el = document.getElementById('error');
    el.textContent = msg;
    el.classList.add('show');
  }
  function clearErr() {
    document.getElementById('error').classList.remove('show');
  }
  function submit() {
    var pw1 = document.getElementById('pw1').value;
    var pw2 = document.getElementById('pw2').value;
    var url = document.getElementById('url').value.trim();
    var zoom = parseInt(document.getElementById('zoom').value, 10);
    if (!pw1) { showErr('Password is required.'); return; }
    if (pw1 !== pw2) { showErr('Passwords do not match.'); return; }
    if (!url) { showErr('Kiosk URL is required.'); return; }
    if (!zoom || zoom < 50 || zoom > 200) { showErr('Zoom must be between 50 and 200.'); return; }
    clearErr();
    var btn = document.getElementById('submit');
    btn.disabled = true;
    btn.textContent = 'Saving…';
    window.kgSubmit(pw1, url, zoom);
  }
  function cancel() { window.kgCancel(); }
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Enter')  { e.preventDefault(); submit(); }
    if (e.key === 'Escape') { e.preventDefault(); cancel(); }
  });
</script>
</body></html>`

type firstRunInput struct {
	password string
	url      string
	zoom     int // page-zoom percent, 0 = "wizard didn't collect" (zenity fallback)
	ok       bool
}

// runFirstRunWizard opens a branded WebView2 window with the first-run
// setup form. Blocks until the user clicks Continue (or closes the window).
// Returns the entered password + URL, or ok=false if the window was closed
// without submitting.
func runFirstRunWizard() *firstRunInput {
	result := &firstRunInput{}
	// v1.1.8 HIGH#4: shared admin-only WebView2 data path. See
	// askPasswordModalInProcess / showFrontmostToast.
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		DataPath:  ensureWebView2DataDir(),
		WindowOptions: webview2.WindowOptions{
			Title:  "kiosk-exit-guard — first run",
			Width:  720, // overridden by makeModalFullscreenTopmost
			Height: 780,
			Center: true,
		},
	})
	if w == nil {
		return nil // caller falls back to zenity
	}
	defer w.Destroy()

	w.Bind("kgSubmit", func(pw, url string, zoom int) {
		result.password = pw
		result.url = strings.TrimSpace(url)
		result.zoom = clampKioskZoom(zoom)
		result.ok = true
		w.Terminate()
	})
	w.Bind("kgCancel", func() {
		w.Terminate()
	})

	// Inject the default URL + zoom via window-level globals before the
	// page runs so the inputs' values are correct on first paint.
	w.Init(fmt.Sprintf(`window.__defaultURL = %q; window.__defaultZoom = %d;`, loadKioskURL(), loadKioskZoomPercent()))
	w.SetHtml(firstRunHTML)
	// Fullscreen the wizard so it's impossible to miss and DPI-agnostic.
	// The CSS centers the setup card on whatever screen size we get.
	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			h := uintptr(w.Window())
			if h != 0 {
				makeModalFullscreenTopmost(h)
				return
			}
			time.Sleep(15 * time.Millisecond)
		}
	}()
	w.Run()
	return result
}

// firstRunZenityFallback collects password + URL via plain zenity dialogs
// when WebView2 isn't available. Same output shape as runFirstRunWizard.
func firstRunZenityFallback() *firstRunInput {
	_ = zenity.Info(
		"WebView2 is not available, so we'll use simple dialogs for setup.\n\nYou'll be asked for an admin password (twice) and the kiosk URL.",
		zenity.Title("kiosk-exit-guard — first run"),
	)
	pw1, err := zenity.Entry(
		"Choose an admin password.\nKeep it secret — anyone with it can pause the kiosk, change its URL, or uninstall the filter.",
		zenity.Title("kiosk-exit-guard — set password"),
		zenity.HideText(),
	)
	if err != nil || pw1 == "" {
		return nil
	}
	pw2, err := zenity.Entry(
		"Re-enter the password to confirm.",
		zenity.Title("kiosk-exit-guard — confirm"),
		zenity.HideText(),
	)
	if err != nil {
		return nil
	}
	if pw1 != pw2 {
		_ = zenity.Error("Passwords did not match. Run kiosk-exit-guard.exe again to retry.", zenity.Title("kiosk-exit-guard"))
		return nil
	}
	url, err := zenity.Entry(
		"Enter the kiosk URL.\nMust start with https://, http://, or file:///.",
		zenity.Title("kiosk-exit-guard — kiosk URL"),
		zenity.EntryText(defaultKioskURL),
	)
	if err != nil {
		return nil
	}
	url = strings.TrimSpace(url)
	if url == "" {
		url = defaultKioskURL
	}
	if !isValidKioskURL(url) {
		_ = zenity.Error("That URL is not valid. Run kiosk-exit-guard.exe again to retry.", zenity.Title("kiosk-exit-guard"))
		return nil
	}
	return &firstRunInput{password: pw1, url: url, ok: true}
}

// relocateToProgramFilesIfNeeded ensures the exe is running from the
// canonical %ProgramFiles%\KioskExitGuard directory before any of the
// auto-start install paths (installService, installStartupTask,
// createDesktopShortcut) register its current path. Without this the
// SCM binary path / scheduled task / shortcut "TargetPath" all point
// at wherever the admin first double-clicked the exe — which on this
// user's machine was %USERPROFILE%\Downloads\, a kiosk-user-writable
// directory. The kiosk user could swap the binary there and on next
// service start the supervising Service (LocalSystem) would respawn
// attacker code as LocalSystem.
//
// Returns true if we relocated and re-exec'd — caller MUST exit.
// Returns false on any failure (mkdir, copy, exec) so the caller can
// continue installing from the current location with a warning rather
// than aborting the whole install. v1.1.8 CRITICAL#1 fix.
func relocateToProgramFilesIfNeeded() bool {
	exe, err := os.Executable()
	if err != nil {
		logf("relocate: os.Executable failed: %v", err)
		return false
	}
	canonical := canonicalInstallPath()
	if strings.EqualFold(exe, canonical) {
		// Already running from the canonical path. Nothing to do.
		return false
	}
	dir := canonicalInstallDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		logf("relocate: MkdirAll(%s) failed: %v — continuing from current location", dir, err)
		return false
	}

	// Copy the running exe to the canonical path. Use a temp + rename
	// so a partial copy can't leave behind a half-written canonical
	// binary that the next launch would try to execute.
	tmp := canonical + ".staging"
	src, err := os.Open(exe)
	if err != nil {
		logf("relocate: open running exe failed: %v", err)
		return false
	}
	dst, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		src.Close()
		logf("relocate: open destination %s failed: %v", tmp, err)
		return false
	}
	if _, err := io.Copy(dst, src); err != nil {
		src.Close()
		dst.Close()
		_ = os.Remove(tmp)
		logf("relocate: io.Copy failed: %v", err)
		return false
	}
	src.Close()
	dst.Close()
	// v1.2.0 LOW#9: atomic swap via MoveFileExW(MOVEFILE_REPLACE_EXISTING)
	// instead of the pre-v1.2.0 os.Remove(canonical) + os.Rename(tmp, …)
	// pair. The old sequence left the install dir empty if the rename
	// failed (lock held by a still-running previous controller): the
	// old canonical was already deleted and the new path never landed.
	// MoveFileExW preserves the old canonical on failure — if the swap
	// can't take effect, the previous binary is still there.
	pTmp, tmpErr := syscall.UTF16PtrFromString(tmp)
	pCanonical, canErr := syscall.UTF16PtrFromString(canonical)
	if tmpErr != nil || canErr != nil {
		_ = os.Remove(tmp)
		logf("relocate: UTF16PtrFromString failed: tmp=%v canonical=%v", tmpErr, canErr)
		return false
	}
	if err := windows.MoveFileEx(pTmp, pCanonical, windows.MOVEFILE_REPLACE_EXISTING); err != nil {
		_ = os.Remove(tmp)
		logf("relocate: MoveFileEx %s -> %s failed: %v (old canonical preserved)", tmp, canonical, err)
		return false
	}

	logf("relocate: copied exe to canonical path %s — re-executing", canonical)
	cmd := exec.Command(canonical, os.Args[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}

	// v1.2.0 HIGH#4: explicitly null out KIOSK_EXIT_GUARD_VIA_SERVICE in
	// the child's env. Today nothing sets that variable up the call
	// chain — only the Service supervisor sets it via
	// CreateEnvironmentBlock — but if a future change ever does, the
	// re-exec would inherit it and suppress the first-run wizard.
	// Scrubbing here makes that regression landmine inert.
	parentEnv := os.Environ()
	childEnv := parentEnv[:0:0]
	for _, kv := range parentEnv {
		// Match the var name case-insensitively (Windows env var names
		// are case-insensitive; the runtime can return them in any
		// case depending on which API set them).
		if eq := strings.IndexByte(kv, '='); eq > 0 {
			if strings.EqualFold(kv[:eq], envViaService) {
				continue
			}
		}
		childEnv = append(childEnv, kv)
	}
	cmd.Env = childEnv

	if err := cmd.Start(); err != nil {
		logf("relocate: exec.Command(canonical).Start failed: %v — continuing from current location", err)
		return false
	}
	return true
}

// firstRunWithWizard runs the full first-run sequence using the WebView2
// wizard for password + URL, then performs the system-setup steps
// (Chrome uninstall, IFEO blocks, Task Scheduler, desktop shortcut).
// Returns whether setup completed cleanly.
func firstRunWithWizard() bool {
	// v1.1.8 CRITICAL#1: relocate to %ProgramFiles%\KioskExitGuard before
	// registering any auto-start path so the SCM binary path / scheduled
	// task / desktop shortcut all reference an admin-only directory.
	// Best-effort: on any failure we keep going from the current
	// location with a warning rather than aborting setup (kiosk-user
	// still gets some protection, which beats none).
	if relocateToProgramFilesIfNeeded() {
		// New process now owns first-run; this process exits cleanly
		// so the wizard doesn't pop twice.
		os.Exit(0)
	}
	input := runFirstRunWizard()
	if input == nil {
		// WebView2 failed entirely — fall back to plain zenity so the
		// admin isn't stranded on a stripped-down image.
		input = firstRunZenityFallback()
		if input == nil || !input.ok {
			_ = zenity.Info(
				"Setup was cancelled. Re-launch kiosk-exit-guard.exe to try again.",
				zenity.Title("kiosk-exit-guard"),
			)
			return false
		}
	} else if !input.ok {
		_ = zenity.Info(
			"Setup was cancelled. Re-launch kiosk-exit-guard.exe to try again.",
			zenity.Title("kiosk-exit-guard"),
		)
		return false
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(input.password), bcrypt.DefaultCost)
	if err != nil {
		_ = zenity.Error(err.Error(), zenity.Title("kiosk-exit-guard"))
		return false
	}
	if err := saveHashToRegistry(hash); err != nil {
		_ = zenity.Error("Could not save password: "+err.Error(), zenity.Title("kiosk-exit-guard"))
		return false
	}
	if err := saveKioskURLToRegistry(input.url); err != nil {
		_ = zenity.Error("Could not save URL: "+err.Error(), zenity.Title("kiosk-exit-guard"))
		return false
	}
	// v1.2.4: persist the kiosk zoom captured by the first-run wizard.
	// Zero means "the wizard didn't collect a zoom" (zenity-fallback path
	// or pre-v1.2.4 form data), in which case we leave the existing
	// registry value alone — loadKioskZoomPercent will fall back to
	// defaultKioskZoom on read.
	if input.zoom > 0 {
		if err := saveKioskZoomPercent(input.zoom); err != nil {
			logf("first-run: saveKioskZoomPercent(%d) failed: %v", input.zoom, err)
		}
	}

	_ = uninstallChrome()
	applyBrowserBlocks()
	_ = installShortcutTasks()
	_ = createDesktopShortcut()

	// v1.1.4: belt-and-suspenders. v1.1.0 switched to a Service-only
	// auto-start and deleted any leftover scheduled task. In the field
	// this turned out to be brittle — on some Win11 Home installs
	// WTSQueryUserToken and even the v1.1.3 explorer-token fallback can
	// fail, leaving the kiosk with zero protection after reboot. So we
	// now install BOTH the Service AND the scheduled task at every
	// non-service-spawn launch. killRunningController() at controller
	// startup guarantees only one controller runs at a time regardless
	// of which auto-start mechanism fired first.
	// v1.1.9 UX MEDIUM#4 + #5: install BOTH auto-start mechanisms
	// without surfacing per-step warnings, then build a single status
	// dialog that reports which combination of success/failure occurred.
	// Previously installService surfaced a Warning before the task
	// attempt, and the task-failure path stacked an Error on top —
	// double-modal on dual-failure. Also the success message lied with
	// "Auto-start task installed" when only one mechanism succeeded.
	svcErr := installService()
	taskErr := installStartupTask()
	if svcErr != nil {
		logf("first-run: installService failed: %v", svcErr)
	}
	if taskErr != nil {
		logf("first-run: installStartupTask failed: %v", taskErr)
	}

	const (
		check = "✓"
		cross = "✗"
	)
	svcMark, taskMark := check, check
	if svcErr != nil {
		svcMark = cross
	}
	if taskErr != nil {
		taskMark = cross
	}
	autoStartLine := fmt.Sprintf("Auto-start: Windows Service %s, Scheduled task %s", svcMark, taskMark)
	baseMsg := fmt.Sprintf(
		"Setup complete.\n\n%s%s%s\n\nThe SK Filter is ON by default and will start enforcing immediately.\nUse Ctrl+Shift+Alt+K to pause it for 1–100 minutes when needed.",
		"• Password and kiosk URL saved\n• Chrome uninstalled\n• Chrome and Edge launches blocked\n• Desktop shortcut created\n• ",
		autoStartLine,
		"",
	)

	switch {
	case svcErr != nil && taskErr != nil:
		_ = zenity.Error(
			fmt.Sprintf(
				"Setup completed BUT auto-start install FAILED.\n\n%s\n\nService error: %v\nTask error:    %v\n\nThe kiosk will run while this exe stays open, but it will NOT auto-start after reboot. Try running the installer from a fully elevated admin shell.",
				autoStartLine, svcErr, taskErr,
			),
			zenity.Title("kiosk-exit-guard"),
		)
	case svcErr != nil:
		_ = zenity.Warning(
			fmt.Sprintf(
				"%s\n\nThe scheduled task is installed so the filter will auto-start on logon, but the Windows Service (which the kiosk user can't disable) was not registered.\n\nService error: %v",
				baseMsg, svcErr,
			),
			zenity.Title("kiosk-exit-guard"),
		)
	case taskErr != nil:
		_ = zenity.Warning(
			fmt.Sprintf(
				"%s\n\nThe Windows Service is installed and will respawn the controller after kills, but the AtLogon scheduled task fallback was not registered.\n\nTask error: %v",
				baseMsg, taskErr,
			),
			zenity.Title("kiosk-exit-guard"),
		)
	default:
		_ = zenity.Info(baseMsg, zenity.Title("kiosk-exit-guard"))
	}
	return true
}

// ---------- WebView2 kiosk window ----------

func makeFullscreenTopmost(hwnd uintptr) {
	cx, _, _ := procGetSystemMetrics.Call(smCXScreen)
	cy, _, _ := procGetSystemMetrics.Call(smCYScreen)
	// GWL_STYLE / GWL_EXSTYLE are negative int32 — cast through uint32
	// to preserve the sign-extended bit pattern as uintptr.
	procSetWindowLongPtrW.Call(hwnd, uintptr(gwlStyleU), uintptr(wsPopup|wsVisible))
	procSetWindowLongPtrW.Call(hwnd, uintptr(gwlExStyleU), uintptr(wsExTopmost))
	procSetWindowPos.Call(hwnd, hwndTopmost, 0, 0, cx, cy, uintptr(swpShowWindow|swpFrameChang))
}

// runWebViewKiosk renders the kiosk URL in a fullscreen WebView2 window.
// Blocks until the window is destroyed.
func runWebViewKiosk(url string) {
	// v1.1.8 HIGH#4: admin-only WebView2 data path. The kiosk page
	// itself rarely cares (it's the URL the admin configured) but
	// consistency means the same profile DACL applies everywhere.
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		DataPath:  ensureWebView2DataDir(),
		WindowOptions: webview2.WindowOptions{
			Title:  "Kiosk",
			Width:  1024,
			Height: 768,
			Center: false,
		},
	})
	if w == nil {
		_ = zenity.Error(
			"WebView2 Runtime is not installed.\n\nInstall it from https://developer.microsoft.com/microsoft-edge/webview2/ and re-run the kiosk.",
			zenity.Title("kiosk-exit-guard — webview"),
		)
		os.Exit(1)
	}
	defer w.Destroy()

	hwnd := w.Window()
	makeFullscreenTopmost(uintptr(hwnd))

	// Lock navigation to the kiosk URL only. Anything else gets canceled
	// at the JS level (and again at the navigation event in a real
	// hardened build, but this catches all anchor clicks).
	zoomPct := loadKioskZoomPercent()
	w.Init(fmt.Sprintf(`
		(function() {
			var kioskPrefix = %q;
			document.addEventListener('click', function(e) {
				var a = e.target.closest && e.target.closest('a');
				if (a && a.href && a.href.indexOf(kioskPrefix) !== 0) {
					e.preventDefault();
					e.stopPropagation();
				}
			}, true);

			// v1.2.5 kiosk zoom: apply persisted page-zoom percent via the
			// CSS zoom property on <body>. v1.2.4 originally targeted
			// <html> (document.documentElement), which compounded with
			// any kiosk page that ran its own document.body.style.zoom
			// fallback — net rendered scale became (admin × page) e.g.
			// 0.9 × 0.9 = 0.81. Targeting <body> means a page-side
			// body.style.zoom = "0.9" and our body.style.zoom = "0.9"
			// land on the same property, so the zoom level doesn't
			// compound and a page-side idempotence check sees our value
			// correctly on SPA re-renders.
			//
			// Admin config still wins: we apply at DOMContentLoaded AND
			// window.load, so even a page that sets its own body.zoom
			// inline during parse gets overridden by the admin's
			// configured value at DOMContentLoaded.
			var kioskZoomPct = %d;
			function applyZoom() {
				try {
					if (document.body) { document.body.style.zoom = (kioskZoomPct / 100); }
				} catch (e) { /* swallow — kiosk URL might sandbox style */ }
			}
			if (document.readyState === 'loading') {
				document.addEventListener('DOMContentLoaded', applyZoom);
			} else {
				applyZoom();
			}
			window.addEventListener('load', applyZoom);
		})();
	`, url, zoomPct))

	w.Navigate(url)
	w.Run() // blocks until window destroyed
}

// ---------- watchdog (manages the WebView2 child) ----------

func findOurWebViewChild() *process.Process {
	exe, _ := os.Executable()
	exeBase := strings.ToLower(filepath.Base(exe))
	procs, err := process.Processes()
	if err != nil {
		return nil
	}
	selfPID := int32(os.Getpid())
	for _, p := range procs {
		if p.Pid == selfPID {
			continue
		}
		name, _ := p.Name()
		if !strings.EqualFold(name, exeBase) {
			continue
		}
		cmd, err := p.Cmdline()
		if err != nil {
			continue
		}
		if strings.Contains(cmd, "--webview") {
			return p
		}
	}
	return nil
}

func launchWebViewChild() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	cmd := exec.Command(exe, "--webview")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	_ = cmd.Start()
}

func killWebViewChild() {
	if p := findOurWebViewChild(); p != nil {
		_ = p.Kill()
	}
}

// pauseJustAppliedMarkerName is the file under %ProgramData%\KioskExitGuard\
// that runPauseInvocation writes a future timestamp into RIGHT before
// killing the kiosk child. watchdogTick reads it and skips relaunching
// while the timestamp is still in the future, eliminating the brief
// kiosk-reappear flash between the pause shortcut killing the kiosk and
// syncFilterStateLoop (2s) flipping filterMode. v1.1.9 UX MEDIUM#6.
const pauseJustAppliedMarkerName = "pause-just-applied.flag"

func pauseJustAppliedMarkerPath() string {
	return filepath.Join(programDataDir(), pauseJustAppliedMarkerName)
}

// writePauseJustAppliedMarker creates the marker file holding a
// timestamp `dur` in the future as decimal UnixNano. Best-effort — on
// any error the kiosk-blink protection is just degraded back to the
// pre-v1.1.9 behavior (brief reappearance possible).
func writePauseJustAppliedMarker(dur time.Duration) {
	_ = ensureAdminOnlyDir(programDataDir())
	p := pauseJustAppliedMarkerPath()
	until := time.Now().Add(dur)
	if err := os.WriteFile(p, []byte(strconv.FormatInt(until.UnixNano(), 10)), 0o600); err != nil {
		logf("writePauseJustAppliedMarker: %v", err)
	}
}

// pauseJustAppliedActive returns true if the marker file exists AND its
// timestamp is still in the future. Stale markers (e.g. an old one from
// a previous boot) are treated as inactive. Returns false on any read
// error so the controller falls back to its pre-marker behavior rather
// than getting stuck never relaunching the kiosk.
func pauseJustAppliedActive() bool {
	b, err := os.ReadFile(pauseJustAppliedMarkerPath())
	if err != nil {
		return false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return false
	}
	return time.Now().UnixNano() < n
}

func watchdogTick() {
	if filterMode.Load() && !isPaused() {
		// v1.1.9 UX MEDIUM#6: a separate --pause invocation just killed
		// the kiosk child but the controller's filterMode hasn't yet
		// flipped (syncFilterStateLoop polls every 2s). Skip the
		// relaunch so the user doesn't see the kiosk briefly reappear.
		if pauseJustAppliedActive() {
			return
		}
		if findOurWebViewChild() == nil {
			launchWebViewChild()
		}
	} else {
		killWebViewChild()
	}
}

func runWatchdog() {
	ticker := time.NewTicker(watchdogInterval)
	defer ticker.Stop()
	watchdogTick()
	for range ticker.C {
		watchdogTick()
	}
}

// ---------- pause expiry ----------

func schedulePauseExpiry(d time.Duration) {
	pauseTimerMu.Lock()
	defer pauseTimerMu.Unlock()
	if pauseTimer != nil {
		pauseTimer.Stop()
	}
	pauseTimer = time.AfterFunc(d, autoReenableFilterMode)
}

func cancelPauseExpiry() {
	pauseTimerMu.Lock()
	defer pauseTimerMu.Unlock()
	if pauseTimer != nil {
		pauseTimer.Stop()
		pauseTimer = nil
	}
}

// autoReenableFilterMode runs when a pause timer fires. Restores everything
// the pause turned off: IFEO Edge/Chrome block, registry lockdown, kiosk
// WebView2 window.
func autoReenableFilterMode() {
	if filterMode.Load() {
		return
	}
	logf("auto-resume: pause expired, restoring filter")
	filterMode.Store(true)
	saveFilterModeToDisk(true)
	setPauseUntil(time.Time{})
	applyLockdown()
	applyBrowserBlocks() // re-apply Edge/Chrome IFEO redirect
	watchdogTick()       // launches the WebView2 kiosk child
	showTimedInfo("Pause ended.\nSK Filter is back on.")
}

func askPauseDuration() (time.Duration, bool) {
	choices := []string{
		"1 minute",
		"5 minutes",
		"10 minutes",
		"20 minutes",
		"30 minutes",
		"45 minutes",
		"Custom (1–100 minutes)",
	}
	choice, err := zenity.List(
		"Pause the SK Filter for how long?\nEdge will be allowed and the kiosk will close during the pause. The filter resumes automatically when the timer ends.",
		choices,
		zenity.RadioList(),
		zenity.Title("SK Filter — pause"),
	)
	if err != nil {
		return 0, false
	}
	switch choice {
	case choices[0]:
		return 1 * time.Minute, true
	case choices[1]:
		return 5 * time.Minute, true
	case choices[2]:
		return 10 * time.Minute, true
	case choices[3]:
		return 20 * time.Minute, true
	case choices[4]:
		return 30 * time.Minute, true
	case choices[5]:
		return 45 * time.Minute, true
	case choices[6]:
		return askCustomMinutes()
	}
	return 5 * time.Minute, true
}

// askCustomMinutes prompts for a custom pause length, validating it falls
// in the 1–100 minute range. Re-prompts on invalid input until the user
// either enters a valid number or cancels.
func askCustomMinutes() (time.Duration, bool) {
	for {
		raw, err := zenity.Entry(
			"How many minutes should the pause last?\nMust be a whole number between 1 and 100.",
			zenity.Title("SK Filter — custom pause"),
			zenity.EntryText("15"),
		)
		if err != nil {
			return 0, false
		}
		raw = strings.TrimSpace(raw)
		var n int
		_, scanErr := fmt.Sscanf(raw, "%d", &n)
		if scanErr != nil || n < 1 || n > 100 {
			_ = zenity.Warning(
				"Please enter a whole number between 1 and 100.",
				zenity.Title("SK Filter"),
			)
			continue
		}
		return time.Duration(n) * time.Minute, true
	}
}

// ---------- hook callback ----------

// kbdLLHookStructFromLParam decodes a LowLevelKeyboardProc lParam (a
// uintptr documented by Microsoft to be a pointer to KBDLLHOOKSTRUCT)
// into a typed *kbdLLHookStruct. Isolating the conversion in a
// nocheckptr helper silences go vet's unsafeptr analyzer (it can't see
// the Win32 ABI contract that lParam is a valid pointer) while keeping
// runtime checkptr happy.
//
//go:nosplit
//go:nocheckptr
func kbdLLHookStructFromLParam(lParam uintptr) *kbdLLHookStruct {
	return (*kbdLLHookStruct)(unsafe.Pointer(lParam)) //nolint:govet // Win32 LowLevelKeyboardProc ABI
}

func hookCallback(nCode int32, wParam uintptr, lParam uintptr) uintptr {
	if nCode >= 0 {
		kb := kbdLLHookStructFromLParam(lParam)
		injected := (kb.Flags & llkhfInject) != 0
		ourInjection := kb.DwExtraInfo == kioskMarker

		// v1.2.4 carve-out: let the Ctrl+Shift+Alt+K pause hotkey fire even
		// from injected input (AnyDesk's SendInput-based key forwarding,
		// AutoHotkey, remote shells). The hook normally ignores injected
		// events because the kiosk user can't physically inject and we
		// don't want to second-guess remote admins' typing. But that also
		// hid the pause hotkey from any tool an admin uses to escape a
		// fullscreen kiosk window remotely. Scope is exactly one combo —
		// every other injected key still falls straight through to
		// procCallNextHookEx unmodified, so AnyDesk typing, paste, etc.
		// keep working as today. GetAsyncKeyState reflects injected
		// modifier state, so ctrlDown/shiftDown/altDown observe the
		// SendInput-set modifiers correctly. ourInjection is excluded so
		// a re-inject path that ever carried K-with-all-modifiers can't
		// loop back through this.
		isKeyDownAny := wParam == wmKeyDown || wParam == wmSysKeyDown
		if injected && !ourInjection && isKeyDownAny &&
			kb.VkCode == vkK && ctrlDown() && shiftDown() && altDown() {
			if !promptOpen.Load() {
				go promptAndPause()
			}
			return 1
		}

		if !injected && !ourInjection {
			isKeyDown := wParam == wmKeyDown || wParam == wmSysKeyDown
			isKeyUp := wParam == wmKeyUp || wParam == wmSysKeyUp

			// Win key alone — swallow + prompt on release. Without this,
			// a single Win tap opens Start menu and the user can click
			// into the kiosk's taskbar entry to close it. Tracking the
			// chord flag distinguishes Win-alone (prompt) from Win+X
			// combos (handled by the normal combo block below).
			if filterMode.Load() && (kb.VkCode == vkLWin || kb.VkCode == vkRWin) {
				if isKeyDown {
					winKeyChord.Store(true)
				} else if isKeyUp {
					wasAlone := winKeyChord.Load()
					winKeyChord.Store(false)
					// CAS gate the goroutine spawn from the hook thread
					// itself so a second blocked combo can't race in
					// between our Load() and the goroutine setting
					// promptOpen — that race would overwrite
					// pendingComboV and the wrong combo would be
					// re-injected. The goroutine clears
					// hookPromptInFlight on exit.
					if wasAlone && hookPromptInFlight.CompareAndSwap(false, true) {
						pendingComboMu.Lock()
						pendingComboV = &pendingCombo{vk: kb.VkCode, modifiers: nil}
						pendingComboMu.Unlock()
						go promptAndReinject()
					}
				}
				return 1
			}

			if isKeyDown {
				// Any non-modifier key down while Win is held → it's a
				// combo, not a Start-menu-open attempt. Clear the
				// chord flag so the Win-up doesn't trigger the prompt.
				if filterMode.Load() && winDown() && !isModifierVK(kb.VkCode) {
					winKeyChord.Store(false)
				}

				// Pause hotkey works in either filter state.
				if kb.VkCode == vkK && ctrlDown() && shiftDown() && altDown() {
					if !promptOpen.Load() {
						go promptAndPause()
					}
					return 1
				}

				if filterMode.Load() {
					// v1.2.6: bare F-keys, Tab, Escape, AppMenu key, PrintScreen,
					// and Insert get the same swallow + password-prompt
					// treatment as modifier+key combos, regardless of whether
					// any modifier is held. Closes the "F-keys and Tab leak
					// through" gap. capturedModifiers() may return an empty
					// set here when the key was pressed alone — that's fine,
					// the re-injection path handles bare keys (it just sends
					// the VK with no modifier prefix).
					if isAlwaysBlockedKey(kb.VkCode) {
						mods := capturedModifiers()
						if hookPromptInFlight.CompareAndSwap(false, true) {
							pendingComboMu.Lock()
							pendingComboV = &pendingCombo{
								vk:        kb.VkCode,
								modifiers: mods,
							}
							pendingComboMu.Unlock()
							go promptAndReinject()
						}
						return 1
					}
					// Allowlist (Ctrl+R, Ctrl+zoom) before the broad block.
					if isAlwaysAllowedCombo(kb.VkCode) {
						// fall through to procCallNextHookEx
					} else if !isModifierVK(kb.VkCode) && (ctrlDown() || winDown() || altDown()) {
						// Snapshot the live modifier state *here* on the
						// hook thread, synchronously. Capturing it
						// inside the goroutine instead would race: if
						// the user releases Ctrl/Win/Alt while the
						// WebView2 modal is still spawning,
						// capturedModifiers() would observe an empty
						// modifier set and the re-injection would send
						// the bare key (e.g. Win+R degenerates to "R"
						// typed into whatever has focus).
						mods := capturedModifiers()
						if hookPromptInFlight.CompareAndSwap(false, true) {
							pendingComboMu.Lock()
							pendingComboV = &pendingCombo{
								vk:        kb.VkCode,
								modifiers: mods,
							}
							pendingComboMu.Unlock()
							go promptAndReinject()
						}
						// Always swallow even if a prompt is already open —
						// otherwise a second blocked combo while the modal
						// is up would leak through to Explorer.
						return 1
					}
				}
			}
		}
	}
	ret, _, _ := procCallNextHookEx.Call(0, uintptr(nCode), wParam, lParam)
	return ret
}

// ---------- password-gated actions ----------

// passwordPromptHTML is a branded WebView2 dialog used wherever the user
// has to enter the admin password. The input is autofocused so the user
// can start typing the moment the window appears.
const passwordPromptHTML = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<style>
  *,*::before,*::after { box-sizing: border-box; }
  html, body { margin: 0; padding: 0;
    background: radial-gradient(ellipse at top left, #1e293b, #0b1220 70%);
    color: #f1f5f9; font-family: -apple-system, "Segoe UI", system-ui, sans-serif;
    min-height: 100vh; -webkit-font-smoothing: antialiased; }
  /* v1.2.5 UI audit: min-height + overflow-y allows the card to scroll
     into view on tiny viewports (short landscape, accessibility scaling)
     instead of being clipped by the previous fixed 100vh + overflow:hidden.
     align-items: center keeps the card vertically centered when it does
     fit. */
  .wrap { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 1.25rem; overflow-y: auto; }
  .card { background: linear-gradient(180deg, rgba(35, 47, 72, 0.95), rgba(26, 36, 56, 0.95));
    border: 1px solid rgba(148, 163, 184, 0.22); border-radius: 16px;
    padding: 2rem 2.25rem; width: 100%; max-width: 540px;
    box-shadow: 0 30px 70px rgba(0,0,0,0.6); backdrop-filter: blur(8px); }
  /* v1.2.5 UI audit: cap card at 540px so on a low-DPI 1080p landscape
     the input doesn't stretch into a tubular 1800px-wide field. Modals
     stay focused at ~540px regardless of monitor width or orientation. */
  .header { display: flex; align-items: center; gap: 0.9rem; margin: 0 0 1.5rem; }
  .lock-icon { width: 48px; height: 48px; border-radius: 12px;
    background: linear-gradient(135deg, rgba(56, 189, 248, 0.18), rgba(56, 189, 248, 0.06));
    border: 1px solid rgba(56, 189, 248, 0.32); display: flex; align-items: center;
    justify-content: center; flex-shrink: 0; }
  .lock-icon svg { width: 22px; height: 22px; color: #38bdf8; }
  .brand { color: #38bdf8; font-size: 0.7rem; font-weight: 700;
    letter-spacing: 0.12em; text-transform: uppercase; margin: 0; }
  h1 { font-size: 1.25rem; margin: 0.15rem 0 0; letter-spacing: -0.015em;
    line-height: 1.25; font-weight: 700; }
  .subtitle { color: #cbd5e1; font-size: 0.92rem; margin: 0 0 1.25rem;
    line-height: 1.5; }
  label { display: block; font-size: 0.72rem; color: #94a3b8;
    margin-bottom: 0.4rem; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.08em; }
  input { width: 100%; padding: 0.85rem 1.05rem; border-radius: 9px;
    border: 1px solid rgba(148, 163, 184, 0.3); background: rgba(11, 18, 32, 0.7);
    color: #f1f5f9; font-size: 1rem; font-family: inherit;
    transition: border-color 0.15s, box-shadow 0.15s; }
  input:focus { outline: none; border-color: #38bdf8;
    box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.2); }
  .err { color: #fca5a5; font-size: 0.85rem; margin: 0.65rem 0 0;
    background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.32);
    padding: 0.55rem 0.8rem; border-radius: 7px; display: none; }
  .err.show { display: block; }
  .actions { display: flex; gap: 0.6rem; justify-content: flex-end; margin-top: 1.4rem; }
  button { padding: 0.7rem 1.5rem; border-radius: 8px; border: 0; cursor: pointer;
    font-weight: 700; font-size: 0.92rem; font-family: inherit;
    transition: background 0.15s, transform 0.05s; }
  button:active { transform: translateY(1px); }
  .btn-primary { background: #38bdf8; color: #0b1220; }
  .btn-primary:hover { background: #7dd3fc; }
  .btn-secondary { background: transparent; color: #94a3b8;
    border: 1px solid rgba(148, 163, 184, 0.3); }
  .btn-secondary:hover { color: #f1f5f9; border-color: rgba(148, 163, 184, 0.55); }
</style></head>
<body>
<div class="wrap"><div class="card">
  <div class="header">
    <div class="lock-icon" aria-hidden="true">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
        <rect x="3" y="11" width="18" height="11" rx="2"/>
        <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
      </svg>
    </div>
    <div>
      <p class="brand">SK Filter</p>
      <h1 id="title">This command has been locked</h1>
    </div>
  </div>
  <p class="subtitle" id="subtitle">Please enter your password to continue.</p>
  <label for="pw">Password</label>
  <input type="password" id="pw" />
  <div class="err" id="err"></div>
  <div class="actions">
    <button class="btn-secondary" onclick="cancel()">Cancel</button>
    <button class="btn-primary" onclick="submit()">Unlock</button>
  </div>
</div></div>
<script>
  if (window.__title)    document.getElementById('title').textContent    = window.__title;
  if (window.__subtitle) document.getElementById('subtitle').textContent = window.__subtitle;
  var input = document.getElementById('pw');
  // Autofocus — belt and suspenders to handle the race between WebView2's
  // first paint and document focus events. Both work; one is enough.
  setTimeout(function() { input.focus(); input.select(); }, 0);
  window.addEventListener('load',          function() { input.focus(); });
  document.addEventListener('DOMContentLoaded', function() { input.focus(); });
  // v1.2.0 MEDIUM#5: signal to Go that the page is interactive. The Go
  // side arms the inactivity timer here instead of before w.Run() so a
  // slow WebView2 cold-start (5–6s) doesn't eat into the 30s budget.
  document.addEventListener('DOMContentLoaded', function() {
    if (window.kgReady) { window.kgReady(); }
  });
  // Also fire on load in case DOMContentLoaded already fired before
  // this script ran (race during slow first paint).
  window.addEventListener('load', function() {
    if (window.kgReady) { window.kgReady(); }
  });
  input.addEventListener('keydown', function(e) {
    if (e.key === 'Enter')  { e.preventDefault(); submit(); }
    if (e.key === 'Escape') { e.preventDefault(); cancel(); }
  });
  // Catch Alt+F4 at the document level so the WebView2 host can't be
  // closed by keyboard either. Cancel button + Escape remain the only
  // dismissal paths.
  document.addEventListener('keydown', function(e) {
    if (e.key === 'F4' && e.altKey) { e.preventDefault(); cancel(); }
  }, true);
  function submit() { window.kgSubmit(input.value); }
  function cancel() { window.kgCancel(); }
  // kgShowError is called from Go after a wrong-password attempt to keep
  // the modal open and show the error inline rather than spawning a toast.
  window.kgShowError = function(msg) {
    var el = document.getElementById('err');
    el.textContent = msg;
    el.classList.add('show');
    input.value = '';
    input.focus();
  };
</script>
</body></html>`

// globalPromptMutexName is the well-known name of a system-wide mutex
// used to serialize password modals across processes. Without it, two
// desktop-shortcut clicks (or a click + hotkey) can stack two fullscreen
// modals on top of each other, confusing the user and racing on
// pendingComboV.
const globalPromptMutexName = `Global\KioskExitGuardPromptMutex`

// v1.1.9 UX HIGH#1: cross-process "only one controller alive" guard.
// Both the Windows Service supervisor and the AtLogon scheduled task
// auto-start the controller at logon. Whichever fires second runs
// killRunningController() to clear the first, the loser's supervisor
// respawns, and the kiosk WebView2 child blinks/reopens. Acquiring this
// mutex BEFORE killRunningController converts the race into a clean
// "second mover exits silently" — the first controller keeps running,
// the kiosk stays painted.
const globalControllerMutexName = `Global\KioskExitGuardControllerRunning`

const (
	errorAlreadyExists = 183
)

// acquireGlobalPromptLock tries to take the cross-process modal mutex.
// Returns (handle, true) if we own it, (0, false) if another process
// already does. The handle must be passed to releaseGlobalPromptLock.
//
// Uses a session-global named mutex so two --pause processes can't open
// stacked password modals.
func acquireGlobalPromptLock() (uintptr, bool) {
	if procCreateMutexW.Find() != nil {
		return 0, true // fail-open if kernel32 isn't loadable for some reason
	}
	name, err := syscall.UTF16PtrFromString(globalPromptMutexName)
	if err != nil {
		return 0, true
	}
	h, _, _ := procCreateMutexW.Call(0, 1 /* bInitialOwner */, uintptr(unsafe.Pointer(name)))
	if h == 0 {
		return 0, true // can't create — degrade gracefully
	}
	last, _, _ := procGetLastError.Call()
	if last == errorAlreadyExists {
		// Someone else owns it. We hold a handle but not ownership.
		procCloseHandle.Call(h)
		return 0, false
	}
	return h, true
}

func releaseGlobalPromptLock(h uintptr) {
	if h == 0 {
		return
	}
	procReleaseMutex.Call(h)
	procCloseHandle.Call(h)
}

// acquireControllerMutex tries to take the system-wide "controller is
// running" named mutex. Returns the handle (intentionally leaked for the
// controller's lifetime) if we own it, or 0 if another controller
// already does. v1.1.9 UX HIGH#1: called once at controller startup
// before killRunningController so the second-to-start logon-time auto-
// start exits silently instead of killing the first and triggering a
// kiosk WebView2 blink/reopen as the loser's supervisor respawns. Fail-
// open on kernel32 / mutex-create errors so a degraded kernel32 doesn't
// turn into "controller refuses to start".
//
// v1.2.0 INFO fix: passes an explicit SECURITY_ATTRIBUTES granting
// MUTEX_ALL_ACCESS only to BUILTIN\Administrators and SYSTEM. The
// default DACL on CreateMutexW grants the caller's process owner
// SYNCHRONIZE access — meaning the kiosk user (LocalSystem-spawned
// controller runs as the kiosk user) could pre-create the same-named
// mutex from a logon script and DoS the real controller. The admin-only
// DACL closes that hole.
func acquireControllerMutex() (handle uintptr, alreadyRunning bool) {
	return acquireAdminOnlyNamedMutex(globalControllerMutexName)
}

// acquireAdminOnlyNamedMutex is the v1.2.0 helper backing every
// process-level "only one of these alive" gate (controller, first-run
// relocate, update). Creates the named mutex with a DACL granting
// MUTEX_ALL_ACCESS (0x1F0001) only to BUILTIN\Administrators (BA) and
// SYSTEM (SY), so a kiosk-user logon script can't squat on it and DoS
// the real holder. Returns (handle, alreadyHeld) on success or
// (0, false) on any failure (fail-open so a degraded kernel32 doesn't
// brick the controller).
func acquireAdminOnlyNamedMutex(name string) (handle uintptr, alreadyHeld bool) {
	if procCreateMutexW.Find() != nil {
		return 0, false
	}
	wname, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, false
	}

	// SDDL: D: → DACL; (A;;0x1F0001;;;BA) ALLOW BUILTIN\Administrators
	// MUTEX_ALL_ACCESS; (A;;0x1F0001;;;SY) ALLOW SYSTEM the same.
	// 0x1F0001 = STANDARD_RIGHTS_REQUIRED (0x1F0000) | MUTANT_QUERY_STATE
	// (0x0001) = MUTEX_ALL_ACCESS.
	const sddl = `D:(A;;0x1F0001;;;BA)(A;;0x1F0001;;;SY)`
	sd, sdErr := windows.SecurityDescriptorFromString(sddl)
	if sdErr != nil {
		// Fall back to default DACL so we don't refuse to start on a
		// machine where SDDL parsing fails for some bizarre reason.
		logf("acquireAdminOnlyNamedMutex(%s): SecurityDescriptorFromString failed: %v — using default DACL", name, sdErr)
		h, _, _ := procCreateMutexW.Call(0, 1, uintptr(unsafe.Pointer(wname)))
		if h == 0 {
			return 0, false
		}
		last, _, _ := procGetLastError.Call()
		if last == errorAlreadyExists {
			procCloseHandle.Call(h)
			return 0, true
		}
		return h, false
	}
	sa := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
		InheritHandle:      0,
	}
	h, _, _ := procCreateMutexW.Call(uintptr(unsafe.Pointer(&sa)), 1 /* bInitialOwner */, uintptr(unsafe.Pointer(wname)))
	if h == 0 {
		return 0, false
	}
	last, _, _ := procGetLastError.Call()
	if last == errorAlreadyExists {
		procCloseHandle.Call(h)
		return 0, true
	}
	return h, false
}

// firstRunMutexName: see acquireFirstRunMutex for usage.
const globalFirstRunMutexName = `Global\KioskExitGuardFirstRunRelocate`

// globalUpdateMutexName guards runUpdateInvocation: see fix MEDIUM#7.
const globalUpdateMutexName = `Global\KioskExitGuardUpdating`

// passwordResult tells callers exactly how a password modal terminated so
// they can distinguish cancel (silent) from wrong-password (show toast).
type passwordResult int

const (
	pwOK       passwordResult = iota // submitted, hash matches
	pwWrong                          // submitted, hash mismatch
	pwCancel                         // user dismissed (Cancel / Esc / window close)
)

// askPasswordModal spawns a `--ask-password` child process to render
// the branded WebView2 password dialog and waits for its exit code:
// 0 = pwOK, 1 = pwWrong, 2 = pwCancel. Routing the modal through a
// child process is required because go-webview2 panics on the second
// NewWithOptions call in a process (chromium.go:131). The controller
// has already created one WebView2 during firstRunWithWizard, so
// opening askPasswordModal in-process from the LL hook callback
// would crash the controller and drop the keyboard hook. The child
// process has zero prior WebView2 instances, so the modal is always
// its first.
//
// Pre-v1.1.3 this function was in-process and produced the
// "controller crashes when user first presses Win" bug observed in
// the field. The original in-process implementation is preserved as
// askPasswordModalInProcess and is invoked only by the child's
// --ask-password flag handler in main().
func askPasswordModal(title, subtitle string) passwordResult {
	exe, err := os.Executable()
	if err != nil {
		// Can't locate ourselves — fall back to in-process. Last-resort
		// path that may still panic on second-instance, but better than
		// no auth at all.
		return askPasswordModalInProcess(title, subtitle)
	}
	cmd := exec.Command(exe, "--ask-password", title, subtitle)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	runErr := cmd.Run()
	if runErr == nil {
		return pwOK
	}
	if exitErr, ok := runErr.(*exec.ExitError); ok {
		switch exitErr.ExitCode() {
		case 1:
			return pwWrong
		case 2:
			return pwCancel
		}
	}
	// v1.1.9 UX MEDIUM#8: spawn-failure path. The child never started
	// (exec.Run returned a non-ExitError), so the user saw nothing.
	// Pre-v1.1.9 this returned pwCancel silently and the LL hook's
	// promptAndReinject swallowed the press — user taps Win, sees no
	// modal, assumes the filter is broken. Surface a one-line toast so
	// the user knows the issue is the prompt itself rather than the
	// keyboard hook. The Cancel return-path is unchanged so callers
	// don't show a "wrong password" toast for a plumbing failure.
	logf("askPasswordModal child exec failed (spawn-time): %v", runErr)
	showTimedInfo("Password prompt failed.\nCheck kiosk-exit-guard.log or restart the filter.")
	return pwCancel
}

// askPasswordModalInProcess shows a branded, autofocused WebView2 password
// dialog. Returns pwOK only if the entered password matches the stored
// bcrypt hash. Only called by the `--ask-password` child process; all
// other callers must use the parent-side askPasswordModal which spawns
// this in a child to avoid the go-webview2 double-instance panic.
func askPasswordModalInProcess(title, subtitle string) passwordResult {
	// v1.1.9 NEW: auto-dismiss the modal after this many seconds of
	// inactivity so a walked-away user can't hold the kiosk hostage
	// indefinitely. The kgSubmit / kgCancel bindings reset the timer
	// so an actively-typing user doesn't get yanked mid-attempt.
	const inactivityTimeout = 30 * time.Second

	if !promptOpen.CompareAndSwap(false, true) {
		return pwCancel
	}
	defer promptOpen.Store(false)

	// Cross-process serialization: if another kiosk-exit-guard process
	// already has a password modal open, don't stack a second one on top
	// of it. Two stacked fullscreen modals look identical and the user
	// can't tell which Cancel button belongs to which.
	gh, gotLock := acquireGlobalPromptLock()
	if !gotLock {
		showTimedInfo("Another SK Filter prompt is already open.\nFinish that one first.")
		return pwCancel
	}
	defer releaseGlobalPromptLock(gh)

	var (
		entered   string
		submitted bool
	)

	// v1.1.8 HIGH#4: see showFrontmostToast for rationale. The password
	// modal is the highest-value WebView2 instance to protect — a
	// poisoned profile injects a service worker that reads the input
	// before kgSubmit fires.
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		DataPath:  ensureWebView2DataDir(),
		WindowOptions: webview2.WindowOptions{
			Title:  "SK Filter — password required",
			Width:  640, // overridden by makeModalFullscreenTopmost
			Height: 420,
			Center: true,
		},
	})
	if w == nil {
		// WebView2 unavailable — fall back to zenity so the prompt still
		// works on stripped-down machines that haven't auto-installed it.
		pw, err := zenity.Entry(title+"\n"+subtitle,
			zenity.Title("SK Filter"), zenity.HideText())
		if err != nil {
			return pwCancel
		}
		if bcrypt.CompareHashAndPassword(storedHash, []byte(pw)) == nil {
			return pwOK
		}
		return pwWrong
	}
	defer w.Destroy()

	// Retry inline: on wrong password we show the error in the modal's
	// #err div and let the user try again, up to maxAttempts before
	// returning pwWrong. This avoids spawning a separate WebView2 toast
	// (slow on cold start) and keeps the password modal up so the user
	// can see what they got wrong.
	const maxAttempts = 3
	var attempts int

	// v1.1.9 NEW: inactivity timer — the bindings below reset it on every
	// user interaction so an actively-typing user doesn't get yanked
	// mid-attempt. v1.2.0 MEDIUM#5: armed inside the kgReady binding
	// (fired from DOMContentLoaded) so the 30s budget starts when the
	// user can actually type, not when the WebView2 host begins cold-
	// starting. WebView2 cold-start can eat 5–6s of the budget on the
	// first password modal of a session. A fallback timer arms before
	// w.Run() with a longer budget so a catastrophic WebView2 failure
	// can't hang the screen forever.
	var inactivityTimer *time.Timer
	var inactivityArmed atomic.Bool
	var autoDismissed atomic.Bool

	w.Bind("kgReady", func() {
		// First call wins; the page may emit multiple DOMContentLoaded /
		// load events on a redraw and we don't want to double-arm.
		if !inactivityArmed.CompareAndSwap(false, true) {
			return
		}
		inactivityTimer = time.AfterFunc(inactivityTimeout, func() {
			autoDismissed.Store(true)
			logf("askPasswordModalInProcess: %s inactivity timeout — auto-dismissing", inactivityTimeout)
			w.Dispatch(func() { w.Terminate() })
		})
	})

	w.Bind("kgSubmit", func(pw string) {
		if inactivityTimer != nil {
			inactivityTimer.Reset(inactivityTimeout)
		}
		attempts++
		if bcrypt.CompareHashAndPassword(storedHash, []byte(pw)) == nil {
			submitted = true
			entered = pw
			w.Terminate()
			return
		}
		if attempts >= maxAttempts {
			submitted = true
			entered = pw // non-matching; final return below classifies as pwWrong
			w.Terminate()
			return
		}
		remaining := maxAttempts - attempts
		var msg string
		if remaining == 1 {
			msg = "Wrong password. 1 attempt left."
		} else {
			msg = fmt.Sprintf("Wrong password. %d attempts left.", remaining)
		}
		w.Dispatch(func() {
			w.Eval(fmt.Sprintf(`window.kgShowError && window.kgShowError(%q);`, msg))
		})
	})
	w.Bind("kgCancel", func() {
		if inactivityTimer != nil {
			inactivityTimer.Reset(inactivityTimeout)
		}
		w.Terminate()
	})

	w.Init(fmt.Sprintf(`window.__title = %q; window.__subtitle = %q;`, title, subtitle))
	w.SetHtml(passwordPromptHTML)
	// Fullscreen the modal so DPI scaling doesn't matter — the CSS
	// centers the card inside whatever screen size we get. Also makes
	// the modal impossible to miss (covers the entire screen, sits
	// above the kiosk window).
	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			h := uintptr(w.Window())
			if h != 0 {
				makeModalFullscreenTopmost(h)
				return
			}
			time.Sleep(15 * time.Millisecond)
		}
	}()

	// v1.2.0 MEDIUM#5 fallback: if kgReady never fires (catastrophic
	// WebView2 failure where DOMContentLoaded never reaches our binding),
	// this longer timer arms so the modal can't hang the screen forever.
	// kgReady wins the race in the normal case: it CompareAndSwaps
	// inactivityArmed and replaces inactivityTimer.
	fallbackTimer := time.AfterFunc(60*time.Second, func() {
		if !inactivityArmed.CompareAndSwap(false, true) {
			// kgReady already armed the real timer; do nothing.
			return
		}
		autoDismissed.Store(true)
		logf("askPasswordModalInProcess: 60s fallback timeout (kgReady never fired) — auto-dismissing")
		w.Dispatch(func() { w.Terminate() })
	})
	defer fallbackTimer.Stop()
	defer func() {
		if inactivityTimer != nil {
			inactivityTimer.Stop()
		}
	}()

	w.Run()

	if !submitted {
		return pwCancel
	}
	if bcrypt.CompareHashAndPassword(storedHash, []byte(entered)) == nil {
		return pwOK
	}
	return pwWrong
}

// askPasswordOK is a convenience for callers that only care about the
// success path. Returns true only on pwOK.
func askPasswordOK(title, subtitle string) bool {
	return askPasswordModal(title, subtitle) == pwOK
}

// Backwards-compatible alias used by the toggle and reset paths.
func askPassword(label string) bool {
	// Split the label on the first newline into title + subtitle for the
	// modal layout. Callers like "Enter password to exit kiosk." pass a
	// single line.
	return askPasswordOK(label, "")
}

// promptAndReinject is the goroutine kicked off when the hook captures a
// blocked combo. Verifies the password, then re-injects the original key
// combo so the user's intended action goes through.
//
// hookPromptInFlight is set by hookCallback before this goroutine is
// spawned; we clear it on exit so the next blocked combo can spawn a
// fresh prompt.
func promptAndReinject() {
	defer hookPromptInFlight.Store(false)
	pendingComboMu.Lock()
	pc := pendingComboV
	pendingComboMu.Unlock()
	if pc == nil {
		return
	}

	result := askPasswordModal(
		"This command has been locked by the SK Filter",
		"Please enter your password to continue. The keystroke will go through once you unlock.",
	)

	// Clear the pending combo regardless of outcome.
	pendingComboMu.Lock()
	pendingComboV = nil
	pendingComboMu.Unlock()

	switch result {
	case pwWrong:
		showFailedToast()
		return
	case pwCancel:
		// User dismissed — silent, no scary toast.
		return
	}
	// Re-inject with a small delay so any in-flight key events the user
	// has released (modifiers) settle before we replay.
	time.Sleep(80 * time.Millisecond)
	sendKeyCombo(pc.modifiers, pc.vk)
}

// promptAndPause is the hotkey handler in v0.5.1+. The SK Filter is
// always on by default; pressing the hotkey starts a *pause* for a chosen
// duration, after which the filter resumes automatically. There is no
// "turn off" path — every pause has an explicit duration.
//
// If the filter is currently paused, the hotkey just shows the remaining
// time and exits. (Ending a pause early would defeat the point.)
func promptAndPause() {
	if !promptOpen.CompareAndSwap(false, true) {
		return
	}
	defer promptOpen.Store(false)

	// Already paused → status read-out, no toggle.
	if !filterMode.Load() {
		remain := time.Until(time.Unix(0, pauseUntilNano.Load())).Round(time.Second)
		showTimedInfo(fmt.Sprintf("SK Filter is paused.\nResumes in %s.", remain))
		return
	}

	switch askPasswordModal(
		"Pause the SK Filter?",
		"Edge will be allowed and the kiosk will close for the duration you choose. The filter resumes automatically when the timer ends.",
	) {
	case pwWrong:
		showFailedToast()
		return
	case pwCancel:
		return
	}
	// v1.1.7: kill the kiosk WebView2 child BEFORE showing the duration
	// picker. askPauseDuration uses zenity.List which is a native Win32
	// dialog (not HWND_TOPMOST) — it would render behind the kiosk's
	// fullscreen topmost WebView2 and be invisible to the user. With the
	// kiosk gone, zenity gets normal foreground. If the user cancels the
	// picker, the watchdog respawns the kiosk within 30s; we also try a
	// proactive relaunch on cancel below to avoid the gap.
	killWebViewChild()
	dur, accepted := askPauseDuration()
	if !accepted {
		showTimedInfo("Pause cancelled.\nSK Filter is still active.")
		// User backed out — bring the kiosk back immediately instead of
		// waiting for the next watchdog tick.
		launchWebViewChild()
		return
	}
	if dur <= 0 {
		launchWebViewChild()
		return
	}

	setPauseUntil(time.Now().Add(dur))
	schedulePauseExpiry(dur)
	filterMode.Store(false)
	saveFilterModeToDisk(false)

	// Tear everything down for the pause window:
	removeLockdown()
	removeIFEOBlock("chrome.exe")
	removeIFEOBlock("msedge.exe")
	// (kiosk already killed above)

	logf("pause started for %v (resumes at %s)", dur, time.Unix(0, pauseUntilNano.Load()).Format("3:04 PM"))
	showTimedInfo(fmt.Sprintf(
		"SK Filter paused.\nEdge is allowed; kiosk closed.\nResumes at %s.",
		time.Unix(0, pauseUntilNano.Load()).Format("3:04 PM"),
	))
}

// ---------- desktop button handlers ----------

// runLaunchKiosk is the entry point for the "Launch Kiosk" desktop
// shortcut. It re-opens the WebView2 kiosk window manually — useful
// after a crash or if the user closed the kiosk and wants it back
// before the controller's 30s watchdog tick runs. Refuses while a
// pause is active (otherwise the button would silently defeat the
// pause; resume the filter first).
func runLaunchKiosk() {
	pu := loadPauseFromDisk()
	if !pu.IsZero() && time.Now().Before(pu) {
		_ = zenity.Info(
			fmt.Sprintf(
				"SK Filter is paused until %s.\n\nTo re-open the kiosk now, use the \"Resume SK Filter\" shortcut to end the pause.",
				pu.Format("3:04 PM"),
			),
			zenity.Title("SK Filter"),
		)
		return
	}
	if findOurWebViewChild() != nil {
		// Already running — bring its window to front and exit.
		// (We don't have its HWND directly, so just no-op; the user
		// can press Win-key area or use the kiosk normally.)
		return
	}
	launchWebViewChild()
}

// runResumeInvocation is the entry point for `kiosk-exit-guard.exe --resume`,
// wired to the "Resume SK Filter" desktop shortcut. Ending a pause early
// makes the system more locked-down, not less, so this is intentionally
// NOT password-gated — anyone can resume. Pausing still needs the
// password.
func runResumeInvocation() {
	// If there's no pause in flight, no-op with feedback so a misclick is
	// obvious rather than silently re-applying lockdown.
	pu := loadPauseFromDisk()
	if pu.IsZero() || !time.Now().Before(pu) {
		showTimedInfo("SK Filter is already active.\nNothing to resume.")
		return
	}

	// Light confirm — no password (resuming is the safe direction) but a
	// "Yes/No" guards against accidental double-click on the shortcut
	// during a long pause window.
	remain := time.Until(pu).Round(time.Second)
	if err := zenity.Question(
		fmt.Sprintf(
			"End the SK Filter pause now?\n\nThe pause has %s remaining (until %s).\nThe kiosk will return within a few seconds.",
			remain, pu.Format("3:04 PM"),
		),
		zenity.Title("SK Filter — resume"),
		zenity.OKLabel("Resume now"),
		zenity.CancelLabel("Keep paused"),
	); err != nil {
		return
	}

	// Clear the pause file. The controller's syncFilterStateLoop picks
	// this up within 2s and runs autoReenableFilterMode for us; we also
	// re-apply blocks directly so the security state snaps back fast.
	setPauseUntil(time.Time{})
	applyBrowserBlocks()
	applyLockdown()
	cancelPauseExpiry()

	showTimedInfo("SK Filter resumed.\nKiosk will return within a few seconds.")
}

// runUninstallInvocation is the entry point for `--uninstall`, wired to
// the "Uninstall SK Filter" desktop shortcut. Password-gated. Removes:
//   - HKCU lockdown registry values
//   - HKLM Chrome / Edge IFEO blocks
//   - HKLM password + URL config (the entire KioskExitGuard key)
//   - The KioskExitGuard scheduled task
//   - All desktop shortcuts (incl. itself)
//   - filter_mode.state, pause_until.state, legacy password.hash files
//
// Does NOT delete the exe itself — admin handles that manually.
func runUninstallInvocation() {
	migrateLegacyHash()
	hash, err := loadHash()
	if err != nil || len(hash) == 0 {
		_ = zenity.Error(
			"SK Filter is not configured. Nothing to uninstall.",
			zenity.Title("SK Filter"),
		)
		os.Exit(1)
	}
	storedHash = hash

	switch askPasswordModal(
		"Uninstall the SK Filter?",
		"You will be asked to confirm. After this completes, the kiosk-exit-guard.exe binary remains on disk — delete it manually if you want full removal.",
	) {
	case pwWrong:
		showFailedToast()
		os.Exit(1)
	case pwCancel:
		os.Exit(0)
	}
	if err := zenity.Question(
		// v1.1.9 UX LOW#10: Windows Service added to the bulleted list
		// — pre-v1.1.9 the dialog only mentioned the scheduled task,
		// which understated what was about to happen on v1.1.0+ installs
		// where the Service is the primary auto-start mechanism.
		"Are you sure?\n\nThis removes:\n  • Chrome / Edge IFEO blocks\n  • Task Manager / Run dialog policies\n  • Stored password and kiosk URL\n  • Windows Service (KioskExitGuardSvc)\n  • Scheduled task\n  • Desktop shortcuts\n\nThe SK Filter will no longer enforce anything after this.",
		zenity.Title("SK Filter — Uninstall"),
		zenity.OKLabel("Uninstall"),
		zenity.CancelLabel("Keep installed"),
	); err != nil {
		// User clicked Cancel / closed.
		return
	}

	// Order matters here. Earlier versions ran teardown then killed the
	// controller — but the running controller's watchdog kept relaunching
	// the kiosk during the teardown, and on some Windows builds
	// schtasks /Delete silently refuses while the task's process is alive.
	// Now: kill processes FIRST, then end+delete the task, then wipe state.

	var failures []string

	// 1. Kill the controller + any --webview child it spawned. Belt and
	// suspenders: use both gopsutil and taskkill. selfPID is skipped.
	killRunningController()
	tkCmd := exec.Command("taskkill", "/F", "/IM", "kiosk-exit-guard.exe",
		"/FI", fmt.Sprintf("PID ne %d", os.Getpid()))
	tkCmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	_ = tkCmd.Run()
	time.Sleep(300 * time.Millisecond) // let TerminateProcess settle

	// 2a. Stop and unregister the v1.1.0 Windows Service (if installed).
	// Done before the scheduled-task teardown because the Service's
	// supervisor would otherwise re-spawn the controller we just killed.
	if err := removeService(); err != nil {
		failures = append(failures, fmt.Sprintf("removeService failed: %v", err))
	}

	// 2b. End any running instance of the legacy v1.0.x scheduled task,
	// then delete it. Still done for upgrade installs that started on
	// v1.0.x and might have a leftover task entry.
	endCmd := exec.Command("schtasks", "/End", "/TN", taskName)
	endCmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	_ = endCmd.Run()
	delCmd := exec.Command("schtasks", "/Delete", "/F", "/TN", taskName)
	delCmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	if delOut, delErr := delCmd.CombinedOutput(); delErr != nil {
		out := strings.TrimSpace(string(delOut))
		// 'task not found' is fine — it means the task is already gone.
		if !strings.Contains(out, "cannot find") && !strings.Contains(strings.ToLower(out), "does not exist") {
			failures = append(failures, fmt.Sprintf("schtasks /Delete failed: %v\n  %s", delErr, out))
		}
	}

	// 3. Tear down lockdown registry state.
	removeLockdown()
	removeIFEOBlock("chrome.exe")
	removeIFEOBlock("msedge.exe")

	// 4. Wipe the HKLM config key.
	if k, oErr := registry.OpenKey(registry.LOCAL_MACHINE, regAppKey, registry.ALL_ACCESS); oErr == nil {
		_ = k.DeleteValue(regHashValue)
		_ = k.DeleteValue(regURLValue)
		k.Close()
	}
	_ = registry.DeleteKey(registry.LOCAL_MACHINE, regAppKey)

	// 5. Delete state files next to the exe.
	for _, fn := range []string{stateFileName, pauseFileName, hashFileName, kioskURLFileName} {
		if p, err := nextToExe(fn); err == nil {
			_ = os.Remove(p)
		}
	}

	// 6. Remove desktop shortcuts + their backing scheduled tasks.
	uninstallShortcutTasks()
	removeDesktopShortcuts()

	// v1.1.8 CRITICAL#1 cleanup: if we installed into
	// %ProgramFiles%\KioskExitGuard, remove the directory and all
	// contents EXCEPT the running exe (Windows file-locks it). Schedule
	// the running exe for delete on reboot via MoveFileExW so the admin
	// doesn't have to manually delete it. If the running exe lives
	// somewhere else (e.g. relocation failed and we installed in place
	// from Downloads), skip — we don't want to nuke the user's
	// Downloads directory.
	cleanupInstallDir()

	// 7. Verify the task is actually gone.
	verifyCmd := exec.Command("schtasks", "/Query", "/TN", taskName)
	verifyCmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	if _, verifyErr := verifyCmd.CombinedOutput(); verifyErr == nil {
		// Query succeeded → task still exists!
		failures = append(failures,
			"The auto-start scheduled task could not be removed. "+
				"Open Task Scheduler (taskschd.msc) and delete the task named \""+taskName+"\" manually.")
	}

	// v1.1.9 UX LOW#10: also verify the Windows Service is gone. Pre-
	// v1.1.9 the verification block only checked the scheduled task,
	// so a stuck SCM entry would survive uninstall without complaint.
	if serviceStillExists() {
		failures = append(failures,
			"The Windows Service "+svcName+" could not be removed. "+
				"Open an Admin PowerShell and run: sc delete "+svcName)
	}
	// Log the raw schtasks output for diagnosis but don't dump it on the user.
	for _, f := range failures {
		logf("uninstall warning: %s", f)
	}

	msg := "SK Filter uninstalled successfully."
	if len(failures) > 0 {
		msg += "\n\nA few steps need manual cleanup:\n  • " +
			strings.Join(failures, "\n  • ") +
			"\n\nDetailed errors were written to kiosk-exit-guard.log."
	}
	msg += "\n\nNext steps:\n  • Delete kiosk-exit-guard.exe manually to finish removal.\n  • Reinstall Chrome from google.com/chrome if you use it."

	_ = zenity.Info(msg, zenity.Title("SK Filter"))
}

// cleanupInstallDir is the v1.1.8 CRITICAL#1 uninstall companion to
// relocateToProgramFilesIfNeeded. If the running exe lives at the
// canonical %ProgramFiles%\KioskExitGuard\kiosk-exit-guard.exe, walk
// the install directory and remove every file EXCEPT the running exe
// (Windows holds an exclusive lock on it). Schedule the running exe
// itself for deletion on next reboot via MoveFileExW with
// MOVEFILE_DELAY_UNTIL_REBOOT so the admin doesn't have to manually
// remove the directory after uninstall.
//
// If the running exe is anywhere else (relocation failed at first
// run, or the admin installed in place from Downloads on a v1.1.7-or-
// older install upgrading to v1.1.8 mid-uninstall), do nothing — we
// don't want to nuke arbitrary directories.
func cleanupInstallDir() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	canonical := canonicalInstallPath()
	if !strings.EqualFold(exe, canonical) {
		return
	}
	dir := filepath.Dir(canonical)
	entries, err := os.ReadDir(dir)
	if err != nil {
		logf("cleanupInstallDir: ReadDir(%s) failed: %v", dir, err)
		return
	}
	// v1.2.0 LOW#10: restrict removal to a known allowlist of file names.
	// Pre-v1.2.0 walked the directory and removed everything not the
	// running exe — fine when only our artifacts live in there, but if
	// an admin (or some future install bug) ever stashed something else
	// in %ProgramFiles%\KioskExitGuard\ we'd nuke it. The allowlist
	// covers every file we ever create plus the staging\ subdir.
	allowedFiles := map[string]struct{}{
		"kiosk-exit-guard.exe":         {},
		"kiosk-exit-guard.exe.old":     {},
		"kiosk-exit-guard.exe.staging": {},
		"kiosk-exit-guard.log":         {},
		"kiosk-exit-guard.log.old":     {},
		"resource.syso":                {},
	}
	allowedDirs := map[string]struct{}{
		"staging": {},
	}
	for _, e := range entries {
		name := e.Name()
		p := filepath.Join(dir, name)
		if strings.EqualFold(p, exe) {
			continue
		}
		if e.IsDir() {
			if _, ok := allowedDirs[strings.ToLower(name)]; ok {
				_ = os.RemoveAll(p)
			} else {
				logf("cleanupInstallDir: skipping unrecognized subdir %s (admin-placed?)", name)
			}
			continue
		}
		if _, ok := allowedFiles[strings.ToLower(name)]; ok {
			_ = os.Remove(p)
		} else {
			logf("cleanupInstallDir: skipping unrecognized file %s (admin-placed?)", name)
		}
	}
	// Schedule the running exe (and the now-empty containing dir) for
	// deletion on next reboot via MoveFileExW(MOVEFILE_DELAY_UNTIL_REBOOT).
	scheduleDeleteOnReboot(exe)
	scheduleDeleteOnReboot(dir)
}

// scheduleDeleteOnReboot calls MoveFileExW with MOVEFILE_DELAY_UNTIL_REBOOT
// and lpNewFileName = NULL, which queues the path for deletion on the
// next reboot. Used by cleanupInstallDir to remove the running exe
// (file-locked) and its containing directory once the admin reboots.
// Best-effort; failures are logged but not surfaced.
func scheduleDeleteOnReboot(path string) {
	const moveFileDelayUntilReboot = 0x4
	pPath, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		logf("scheduleDeleteOnReboot: UTF16PtrFromString(%s) failed: %v", path, err)
		return
	}
	if err := windows.MoveFileEx(pPath, nil, moveFileDelayUntilReboot); err != nil {
		logf("scheduleDeleteOnReboot: MoveFileEx(%s) failed: %v", path, err)
	}
}

// purgeLeftoverState wipes anything a prior install (or partial uninstall)
// might have left behind. Called at the start of first-run so the user
// gets a truly clean install regardless of what state the box is in
// (zombie controller, dangling scheduled task, stale IFEO blocks,
// half-deleted desktop shortcuts, etc.).
func purgeLeftoverState() {
	// v1.1.0: kill the supervising Service first. If we just kill the
	// controller, the Service notices and respawns it within a second,
	// fighting the rest of this teardown. Best-effort — removeService
	// returns nil when the service isn't registered.
	_ = removeService()

	killRunningController()
	removeLockdown()
	removeIFEOBlock("chrome.exe")
	removeIFEOBlock("msedge.exe")

	cmd := exec.Command("schtasks", "/Delete", "/F", "/TN", taskName)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	_ = cmd.Run()

	uninstallShortcutTasks()
	removeDesktopShortcuts()

	// Wipe HKLM config so the wizard genuinely starts from zero. (We're
	// about to write to it via setPassword.)
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, regAppKey, registry.ALL_ACCESS); err == nil {
		_ = k.DeleteValue(regHashValue)
		_ = k.DeleteValue(regURLValue)
		k.Close()
	}
	_ = registry.DeleteKey(registry.LOCAL_MACHINE, regAppKey)

	// Wipe state files next to the exe.
	for _, fn := range []string{stateFileName, pauseFileName, hashFileName, kioskURLFileName} {
		if p, err := nextToExe(fn); err == nil {
			_ = os.Remove(p)
		}
	}
}

// killRunningController finds and terminates any kiosk-exit-guard.exe
// process that's not us. Used by --uninstall to make sure the controller
// doesn't keep running with a stale in-memory password hash after the
// HKLM key is wiped.
func killRunningController() {
	selfPID := int32(os.Getpid())
	procs, err := process.Processes()
	if err != nil {
		return
	}
	for _, p := range procs {
		if p.Pid == selfPID {
			continue
		}
		name, _ := p.Name()
		if !strings.EqualFold(name, "kiosk-exit-guard.exe") {
			continue
		}
		_ = p.Kill()
	}
}

// ---------- self-update via GitHub releases ----------

const githubLatestAPI = "https://api.github.com/repos/Shalom-Karr/kiosk-exit-guard/releases/latest"

type ghAsset struct {
	Name        string `json:"name"`
	DownloadURL string `json:"browser_download_url"`
}
type ghRelease struct {
	TagName string    `json:"tag_name"`
	Name    string    `json:"name"`
	HTMLURL string    `json:"html_url"`
	Assets  []ghAsset `json:"assets"`
}

// fetchLatestRelease returns (versionString, downloadURL, sha256URL, error).
// The version is the tag with any leading "v" stripped so it lines up with
// the embedded currentVersion constant. sha256URL is the download URL of
// the kiosk-exit-guard.exe.sha256 sidecar asset if present in the release;
// empty string if the release doesn't publish one. v1.1.8 CRITICAL#2:
// callers SHA-256-verify the downloaded exe against this sidecar before
// installing.
func fetchLatestRelease() (string, string, string, error) {
	req, err := http.NewRequest("GET", githubLatestAPI, nil)
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "kiosk-exit-guard-updater")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", "", "", fmt.Errorf("github api returned %d", resp.StatusCode)
	}
	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", "", "", err
	}
	var exeURL, shaURL string
	for _, a := range rel.Assets {
		switch {
		case strings.EqualFold(a.Name, "kiosk-exit-guard.exe"):
			exeURL = a.DownloadURL
		case strings.EqualFold(a.Name, "kiosk-exit-guard.exe.sha256"):
			shaURL = a.DownloadURL
		}
	}
	if exeURL == "" {
		return "", "", "", errors.New("kiosk-exit-guard.exe asset not found in latest release")
	}
	return strings.TrimPrefix(rel.TagName, "v"), exeURL, shaURL, nil
}

// fetchExpectedSHA256 downloads the SHA-256 sidecar text from shaURL and
// returns the expected lowercase hex digest. Tolerant of the canonical
// release artifact format ("HEX  filename" or just "HEX"); the first
// whitespace-delimited token is taken as the digest. v1.1.8 CRITICAL#2.
func fetchExpectedSHA256(shaURL string) (string, error) {
	req, err := http.NewRequest("GET", shaURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "kiosk-exit-guard-updater")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("sha256 sidecar http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	fields := strings.Fields(strings.TrimSpace(string(body)))
	if len(fields) == 0 {
		return "", errors.New("sha256 sidecar empty")
	}
	digest := strings.ToLower(fields[0])
	if len(digest) != 64 {
		return "", fmt.Errorf("sha256 sidecar malformed (got %d hex chars, want 64)", len(digest))
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return "", fmt.Errorf("sha256 sidecar not valid hex: %w", err)
	}
	return digest, nil
}

// fileSHA256 computes the lowercase hex SHA-256 of the file at path.
// v1.1.8 CRITICAL#2.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// runUpdateInvocation is the entry point for `--update`, wired to the
// "Update SK Filter" desktop shortcut. Flow:
//   1. GET the GitHub /releases/latest API
//   2. If same version → tell the user, exit
//   3. Otherwise → confirm dialog showing both versions
//   4. Password prompt (admin action: rewriting the running exe)
//   5. Download new exe to TEMP
//   6. Rename current exe to .old (allowed even when running)
//   7. Rename downloaded exe into the current exe's path
//   8. Restart the KioskExitGuard scheduled task so the new exe loads
func runUpdateInvocation() {
	// v1.2.0 MEDIUM#7: cross-process update mutex. Two quick desktop-
	// shortcut double-clicks stack two GET pipelines + downloads on top
	// of each other; the loser could race the winner's rename and leave
	// a half-installed exe. v1.1.11 dropped the "Checking GitHub…" UI
	// cover that previously made the double-click less likely; this
	// mutex closes the same hole without re-adding a toast. Fail-silent
	// on contention so the second invocation just exits.
	if mh, alreadyHeld := acquireAdminOnlyNamedMutex(globalUpdateMutexName); alreadyHeld {
		logf("update: another update is already in flight; exiting silently")
		return
	} else {
		// Hold for the duration of the function. The handle is closed
		// implicitly on process exit; we don't release explicitly
		// because the rename-then-respawn-task path tears down this
		// process anyway.
		_ = mh
	}

	migrateLegacyHash()
	hash, err := loadHash()
	if err != nil || len(hash) == 0 {
		_ = zenity.Error("SK Filter is not configured. Run first-run setup first.", zenity.Title("SK Filter"))
		os.Exit(1)
	}
	storedHash = hash

	// v1.1.11: silent fetch — the "Checking GitHub for updates…" toast
	// (showTimedInfo spawns a WebView2 child, 200–500ms cold-start) added
	// visible latency before the meaningful UI without telling the admin
	// anything useful. User request: "scratch the checking for updates UI
	// just show the box do you want to update and password to approve it".

	latest, downloadURL, shaURL, err := fetchLatestRelease()
	if err != nil {
		_ = zenity.Error(
			fmt.Sprintf("Could not reach GitHub:\n%v\n\nMake sure the device has internet access.", err),
			zenity.Title("SK Filter — update"),
		)
		return
	}

	if latest == currentVersion {
		_ = zenity.Info(
			fmt.Sprintf("You're on v%s.\n\nNo update available.", currentVersion),
			zenity.Title("SK Filter — update"),
		)
		return
	}

	// v1.1.11: combine confirm + auth into a single password modal.
	// Previously a zenity.Question "A new version is available, download
	// and install?" preceded the password prompt; the modal's subtitle
	// already conveys the same intent, so two screens is one too many.
	switch askPasswordModal(
		fmt.Sprintf("Install v%s?", latest),
		fmt.Sprintf("A new version is available (you're on v%s). Enter your admin password to download and install.", currentVersion),
	) {
	case pwWrong:
		// v1.1.9 UX MEDIUM#9: sync variant — return below tears the
		// parent down immediately and the fire-and-forget child could
		// die before painting.
		showFailedToastSync()
		return
	case pwCancel:
		return
	}

	// v1.1.8 CRITICAL#2: stage the downloaded exe in an admin-only
	// directory under %ProgramData% rather than %TEMP%. %TEMP% is
	// user-writable, so a kiosk user could swap the downloaded exe
	// between downloadFile and os.Rename and have us install attacker
	// code. ensureAdminOnlyDir tightens the DACL via icacls so only
	// SYSTEM + Administrators can write into the staging directory.
	stagingDir := filepath.Join(programDataDir(), "staging")
	if err := ensureAdminOnlyDir(stagingDir); err != nil {
		_ = zenity.Error(fmt.Sprintf("Could not prepare staging directory: %v", err), zenity.Title("SK Filter — update"))
		return
	}
	tmpPath := filepath.Join(stagingDir, "kiosk-exit-guard.new.exe")
	if err := downloadFile(downloadURL, tmpPath); err != nil {
		_ = zenity.Error(fmt.Sprintf("Download failed: %v\n\nCheck the device's internet connection and try again.", err), zenity.Title("SK Filter — update"))
		return
	}

	// v1.1.8 CRITICAL#2: verify the downloaded exe's SHA-256 against
	// the kiosk-exit-guard.exe.sha256 sidecar asset (also published
	// by the release workflow). If the sidecar is absent on this
	// release, log a warning and proceed — older releases didn't
	// publish one, and refusing all updates would leave installs
	// stuck. If it's present and the digest doesn't match, abort.
	if shaURL != "" {
		expected, sErr := fetchExpectedSHA256(shaURL)
		if sErr != nil {
			_ = os.Remove(tmpPath)
			_ = zenity.Error(fmt.Sprintf("Could not verify the download:\n%v\n\nUpdate aborted.", sErr), zenity.Title("SK Filter — update"))
			return
		}
		actual, hErr := fileSHA256(tmpPath)
		if hErr != nil {
			_ = os.Remove(tmpPath)
			_ = zenity.Error(fmt.Sprintf("Could not hash the downloaded file:\n%v\n\nUpdate aborted.", hErr), zenity.Title("SK Filter — update"))
			return
		}
		if !strings.EqualFold(actual, expected) {
			_ = os.Remove(tmpPath)
			logf("update: SHA-256 mismatch! expected=%s actual=%s", expected, actual)
			_ = zenity.Error(fmt.Sprintf("Update aborted: the downloaded file does not match the published SHA-256.\n\nExpected: %s\nActual:   %s\n\nIf this persists, report it at https://github.com/Shalom-Karr/kiosk-exit-guard/issues — the GitHub release may have been tampered with.", expected, actual), zenity.Title("SK Filter — update"))
			return
		}
		logf("update: SHA-256 verification OK (%s)", expected)
	} else {
		// v1.2.0 HIGH#2: pre-v1.2.0 logged "proceeding without integrity
		// verification (legacy release)" and silently installed. That's
		// a downgrade attack vector — an attacker who can MITM the
		// download URL just needs to also strip the sidecar URL from
		// the GitHub release metadata (or publish a release without
		// one) and we'll install whatever they served. Make this a
		// deliberate admin decision instead: show a default-No
		// Yes/No prompt, exit on No (or any prompt error).
		choiceErr := zenity.Question(
			"Update integrity check unavailable.\n\n"+
				"This release does not publish a SHA-256 sidecar "+
				"(kiosk-exit-guard.exe.sha256). Proceeding will install "+
				"the downloaded binary without verifying it matches the "+
				"published release.\n\n"+
				"Continue anyway?",
			zenity.Title("SK Filter — update"),
			zenity.OKLabel("Yes, install unverified"),
			zenity.CancelLabel("No, abort"),
			zenity.QuestionIcon,
			zenity.DefaultCancel(),
		)
		// Question returns nil on OK (Yes), ErrCanceled on Cancel / X.
		// Any other error (rare — toolkit failure) treated as cancel
		// because the admin couldn't deliberately choose to bypass.
		if choiceErr != nil {
			logf("update: admin declined unverified install (no sidecar): %v", choiceErr)
			_ = os.Remove(tmpPath)
			return
		}
		logf("update: admin acknowledged no-sidecar; proceeding unverified")
	}

	exe, err := os.Executable()
	if err != nil {
		_ = zenity.Error(fmt.Sprintf("Could not locate current exe: %v", err), zenity.Title("SK Filter — update"))
		_ = os.Remove(tmpPath)
		return
	}

	// CRITICAL: stop the running controller before renaming. Windows holds
	// an exclusive lock on a running .exe, so os.Rename(exe, ...) returns
	// "access is denied" while the controller is alive. On v1.1.0+ the
	// supervising Service would also immediately respawn a fresh
	// controller if we just killed the running one — so we stop the
	// Service first, then end the legacy scheduled task (for upgrades
	// from v1.0.x), then kill any orphan controllers.
	stopCmd := exec.Command("sc", "stop", svcName)
	stopCmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	_ = stopCmd.Run()
	// v1.1.9 UX MEDIUM#7: poll SCM until the service is actually
	// Stopped. `sc stop` returns immediately; without this wait the
	// supervisor goroutine inside the running service can respawn a
	// fresh controller in the rename window. 10s is generous —
	// installService's inline poll uses 4s.
	if waitErr := waitForServiceStopped(10 * time.Second); waitErr != nil {
		logf("update: waitForServiceStopped: %v (continuing — service may have been ungraceful)", waitErr)
	}
	endCmd := exec.Command("schtasks", "/End", "/TN", taskName)
	endCmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	_ = endCmd.Run()
	killRunningController()
	tkCmd := exec.Command("taskkill", "/F", "/IM", "kiosk-exit-guard.exe",
		"/FI", fmt.Sprintf("PID ne %d", os.Getpid()))
	tkCmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	_ = tkCmd.Run()
	time.Sleep(500 * time.Millisecond)

	oldPath := exe + ".old"
	_ = os.Remove(oldPath) // clean any leftover

	// Retry the rename a few times — even after killing the controller, the
	// file handle can linger briefly while Windows finishes tearing the
	// process down.
	var renameErr error
	for attempt := 0; attempt < 5; attempt++ {
		renameErr = os.Rename(exe, oldPath)
		if renameErr == nil {
			break
		}
		time.Sleep(400 * time.Millisecond)
	}
	if renameErr != nil {
		_ = os.Remove(tmpPath)
		// Best-effort: restart the controller we just killed. Try the
		// v1.1.0 service first, fall back to the legacy task.
		startCmd := exec.Command("sc", "start", svcName)
		startCmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
		if err := startCmd.Run(); err != nil {
			runCmd := exec.Command("schtasks", "/Run", "/TN", taskName)
			runCmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
			_ = runCmd.Run()
		}
		_ = zenity.Error(
			fmt.Sprintf("Could not move current exe aside:\n%v\n\nThe SK Filter has been restarted at the previous version. Try the update again in a minute.", renameErr),
			zenity.Title("SK Filter — update"),
		)
		return
	}
	if err := os.Rename(tmpPath, exe); err != nil {
		// Rollback: put the old exe back where it was.
		_ = os.Rename(oldPath, exe)
		// Re-launch the controller so the device isn't left unprotected.
		startCmd := exec.Command("sc", "start", svcName)
		startCmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
		if err := startCmd.Run(); err != nil {
			runCmd := exec.Command("schtasks", "/Run", "/TN", taskName)
			runCmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
			_ = runCmd.Run()
		}
		_ = zenity.Error(fmt.Sprintf("Install failed: %v\n\nReverted to previous version and restarted the SK Filter.", err), zenity.Title("SK Filter — update"))
		return
	}

	// Re-launch the supervising Service (v1.1.0+) so the new exe loads.
	// Fall back to the legacy scheduled task if the service isn't
	// registered (upgrade from v1.0.x mid-update path, or a botched
	// service install).
	startCmd := exec.Command("sc", "start", svcName)
	startCmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	if err := startCmd.Run(); err != nil {
		runCmd := exec.Command("schtasks", "/Run", "/TN", taskName)
		runCmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
		_ = runCmd.Run()
	}
	time.Sleep(400 * time.Millisecond)

	_ = zenity.Info(
		fmt.Sprintf("Updated to v%s.\n\nSK Filter reloaded automatically.\nThe previous version was saved as kiosk-exit-guard.exe.old next to the new exe.", latest),
		zenity.Title("SK Filter — update complete"),
	)
}

func removeDesktopShortcuts() {
	// v1.2.4: wipe from both the per-user desktop (where pre-v1.2.4
	// installs put the .lnks) AND the public/all-users desktop (where
	// v1.2.4+ installs put them). Either path missing is fine —
	// Remove-Item with -ErrorAction SilentlyContinue absorbs that.
	ps := `
$lnks = @('Kiosk Exit Guard.lnk','Pause SK Filter.lnk','Resume SK Filter.lnk','Launch Kiosk.lnk','Change Kiosk URL.lnk','Update SK Filter.lnk','Uninstall SK Filter.lnk')
foreach ($d in @([Environment]::GetFolderPath('CommonDesktopDirectory'), [Environment]::GetFolderPath('Desktop'))) {
    if (-not $d) { continue }
    foreach ($n in $lnks) {
        Remove-Item -Path (Join-Path $d $n) -Force -ErrorAction SilentlyContinue
    }
}
`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	_ = cmd.Run()
}

// runAutoUpdateChecker is a long-lived goroutine started from the
// controller's main() once after the LL keyboard hook is up. Waits
// autoUpdateInitialDelay so the kiosk has time to paint, then polls
// GitHub's /releases/latest every autoUpdateCheckInterval. When a newer
// version is published it fire-and-forget spawns an
// `--auto-update-notify <newver>` child which renders the interactive
// WebView2 "Update now? / Remind me later" modal. Errors are logged at
// info level and otherwise ignored — a transient network blip just
// means we try again at the next tick.
//
// The auto-checker is intentionally only started from the long-lived
// controller process. All the short-lived flag invocations (--pause,
// --update, --silent-exit, --auto-update-notify, etc.) exit too quickly
// to be useful and would spam GitHub if they each spun one up.
func runAutoUpdateChecker(ctx context.Context) {
	defer recoverAndLog("runAutoUpdateChecker")
	logf("auto-update checker: started; initial delay=%s interval=%s",
		autoUpdateInitialDelay, autoUpdateCheckInterval)

	select {
	case <-ctx.Done():
		return
	case <-time.After(autoUpdateInitialDelay):
	}

	autoUpdateCheckOnce()
	ticker := time.NewTicker(autoUpdateCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			autoUpdateCheckOnce()
		}
	}
}

// autoUpdateCheckOnce performs a single GitHub /releases/latest check
// and, on finding a newer version, spawns the --auto-update-notify
// child. The child itself acquires globalAutoUpdateNotifyMutexName
// for its lifetime so we don't stack two notify modals if a previous
// one is still open.
func autoUpdateCheckOnce() {
	defer recoverAndLog("autoUpdateCheckOnce")
	logf("auto-update check: triggered")

	latest, _, _, err := fetchLatestRelease()
	if err != nil {
		logf("auto-update check: fetchLatestRelease error (silently ignored): %v", err)
		return
	}
	if latest == currentVersion {
		logf("auto-update check: on latest (v%s)", currentVersion)
		return
	}
	logf("auto-update check: new version v%s available; spawning notify child (current v%s)", latest, currentVersion)

	exe, err := os.Executable()
	if err != nil {
		logf("auto-update check: os.Executable failed: %v", err)
		return
	}
	cmd := exec.Command(exe, "--auto-update-notify", latest)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	if err := cmd.Start(); err != nil {
		logf("auto-update check: failed to spawn notify child: %v", err)
		return
	}
	// Fire-and-forget — release the OS process handle so this exiting
	// goroutine doesn't leak it. The child's exit gets logged from
	// within the child itself (see runAutoUpdateNotifyInvocation).
	_ = cmd.Process.Release()
}

// autoUpdateNotifyHTML is the branded WebView2 dialog rendered by the
// --auto-update-notify child. Structurally a copy of passwordPromptHTML
// (same dark gradient, lock-icon header, brand pill, sans-serif font
// stack, --accent color) but with no password input — two buttons.
// kgUpdateNow exits 0 (parent reads "admin clicked Update Now"),
// kgLater exits 1 (parent reads "Remind Me Later / timeout / close").
const autoUpdateNotifyHTML = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<style>
  *,*::before,*::after { box-sizing: border-box; }
  html, body { margin: 0; padding: 0;
    background: radial-gradient(ellipse at top left, #1e293b, #0b1220 70%);
    color: #f1f5f9; font-family: -apple-system, "Segoe UI", system-ui, sans-serif;
    min-height: 100vh; -webkit-font-smoothing: antialiased; }
  .wrap { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 1.25rem; overflow-y: auto; }
  .card { background: linear-gradient(180deg, rgba(35, 47, 72, 0.95), rgba(26, 36, 56, 0.95));
    border: 1px solid rgba(148, 163, 184, 0.22); border-radius: 16px;
    padding: 2rem 2.25rem; width: 100%; max-width: 540px;
    box-shadow: 0 30px 70px rgba(0,0,0,0.6); backdrop-filter: blur(8px); }
  .header { display: flex; align-items: center; gap: 0.9rem; margin: 0 0 1.5rem; }
  .lock-icon { width: 48px; height: 48px; border-radius: 12px;
    background: linear-gradient(135deg, rgba(56, 189, 248, 0.18), rgba(56, 189, 248, 0.06));
    border: 1px solid rgba(56, 189, 248, 0.32); display: flex; align-items: center;
    justify-content: center; flex-shrink: 0; }
  .lock-icon svg { width: 22px; height: 22px; color: #38bdf8; }
  .brand { color: #38bdf8; font-size: 0.7rem; font-weight: 700;
    letter-spacing: 0.12em; text-transform: uppercase; margin: 0; }
  h1 { font-size: 1.25rem; margin: 0.15rem 0 0; letter-spacing: -0.015em;
    line-height: 1.25; font-weight: 700; }
  .subtitle { color: #cbd5e1; font-size: 0.92rem; margin: 0 0 1.25rem;
    line-height: 1.5; }
  .actions { display: flex; gap: 0.6rem; justify-content: flex-end; margin-top: 1.4rem; }
  button { padding: 0.7rem 1.5rem; border-radius: 8px; border: 0; cursor: pointer;
    font-weight: 700; font-size: 0.92rem; font-family: inherit;
    transition: background 0.15s, transform 0.05s; }
  button:active { transform: translateY(1px); }
  .btn-primary { background: #38bdf8; color: #0b1220; }
  .btn-primary:hover { background: #7dd3fc; }
  .btn-secondary { background: transparent; color: #94a3b8;
    border: 1px solid rgba(148, 163, 184, 0.3); }
  .btn-secondary:hover { color: #f1f5f9; border-color: rgba(148, 163, 184, 0.55); }
</style></head>
<body>
<div class="wrap"><div class="card">
  <div class="header">
    <div class="lock-icon" aria-hidden="true">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
        <rect x="3" y="11" width="18" height="11" rx="2"/>
        <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
      </svg>
    </div>
    <div>
      <p class="brand">SK Filter</p>
      <h1 id="title">An update was pushed</h1>
    </div>
  </div>
  <p class="subtitle" id="subtitle">A new version is available. Install now?</p>
  <div class="actions">
    <button class="btn-secondary" onclick="later()">Remind Me Later</button>
    <button class="btn-primary" onclick="updateNow()">Update Now</button>
  </div>
</div>
<script>
  if (window.__title)    document.getElementById('title').textContent    = window.__title;
  if (window.__subtitle) document.getElementById('subtitle').textContent = window.__subtitle;
  // v1.2.1: signal Go that the page is interactive so the 60s auto-
  // dismiss timer starts when the admin can actually click, not when
  // the WebView2 host begins cold-starting. Same pattern as the v1.2.0
  // password-modal kgReady fix.
  document.addEventListener('DOMContentLoaded', function() {
    if (window.kgReady) { window.kgReady(); }
  });
  window.addEventListener('load', function() {
    if (window.kgReady) { window.kgReady(); }
  });
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Enter')  { e.preventDefault(); updateNow(); }
    if (e.key === 'Escape') { e.preventDefault(); later(); }
    if (e.key === 'F4' && e.altKey) { e.preventDefault(); later(); }
  }, true);
  function updateNow() { window.kgUpdateNow && window.kgUpdateNow(); }
  function later()     { window.kgLater     && window.kgLater();     }
</script>
</body></html>`

// runAutoUpdateNotifyInvocation is the entry point for
// `kiosk-exit-guard.exe --auto-update-notify <newver>`, a short-lived
// child process spawned by autoUpdateCheckOnce. Renders the branded
// "Update now? / Remind me later" WebView2 modal and:
//   - On Update Now: exec's `kiosk-exit-guard.exe --update` (which
//     pops the existing password modal, downloads, SHA-256 verifies,
//     atomic-swaps, restarts the Service) and exits 0.
//   - On Remind Me Later / window close / autoUpdateDismissTimeout
//     timeout: exits 1.
//
// Runs in its own process so the controller's in-process WebView2
// instances don't trigger go-webview2's second-NewWithOptions panic.
func runAutoUpdateNotifyInvocation() {
	if len(os.Args) < 3 {
		logf("--auto-update-notify: missing <newver> arg")
		os.Exit(1)
	}
	newver := os.Args[2]

	// Cross-process "only one notify modal alive" gate. If a previous
	// notify child is still up (admin walked away from it, or two
	// auto-checker ticks raced), exit silently. Intentionally leak the
	// handle: the kernel releases it on process exit, which is exactly
	// the lifetime we want.
	if mh, alreadyHeld := acquireAdminOnlyNamedMutex(globalAutoUpdateNotifyMutexName); alreadyHeld {
		logf("--auto-update-notify: another notify child is already open; exiting")
		os.Exit(1)
	} else {
		_ = mh
	}

	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		DataPath:  ensureWebView2DataDir(),
		WindowOptions: webview2.WindowOptions{
			Title:  "SK Filter — update available",
			Width:  640, // overridden by makeModalFullscreenTopmost
			Height: 360,
			Center: true,
		},
	})
	if w == nil {
		// WebView2 unavailable — fall back to zenity so the admin can
		// still make a choice on stripped-down machines.
		ok := zenity.Question(
			fmt.Sprintf("An SK Filter update was pushed.\nUpdate to v%s now? (You're on v%s.)", newver, currentVersion),
			zenity.Title("SK Filter — update available"),
			zenity.OKLabel("Update Now"), zenity.CancelLabel("Remind Me Later"),
		)
		if ok == nil {
			logf("auto-update notify: zenity fallback — admin chose Update Now")
			spawnUpdateInvocation()
			os.Exit(0)
		}
		logf("auto-update notify: zenity fallback — admin chose Remind Me Later")
		os.Exit(1)
	}
	defer w.Destroy()

	var (
		chose       atomic.Int32 // 0 = none yet, 1 = update, 2 = later
		dismissArmed atomic.Bool
	)

	w.Bind("kgReady", func() {
		if !dismissArmed.CompareAndSwap(false, true) {
			return
		}
		time.AfterFunc(autoUpdateDismissTimeout, func() {
			if chose.Load() != 0 {
				return // user already clicked something
			}
			logf("auto-update notify: timeout / window closed")
			chose.CompareAndSwap(0, 2)
			w.Dispatch(func() { w.Terminate() })
		})
	})

	w.Bind("kgUpdateNow", func() {
		chose.CompareAndSwap(0, 1)
		w.Terminate()
	})
	w.Bind("kgLater", func() {
		chose.CompareAndSwap(0, 2)
		w.Terminate()
	})

	title := "An update was pushed"
	subtitle := fmt.Sprintf("Version %s is available. The current version is %s. Install now?", newver, currentVersion)
	w.Init(fmt.Sprintf(`window.__title = %q; window.__subtitle = %q;`, title, subtitle))
	w.SetHtml(autoUpdateNotifyHTML)

	// Fullscreen the modal so DPI scaling doesn't matter and the
	// admin can't miss it. Same idiom as askPasswordModalInProcess.
	go func() {
		defer recoverAndLog("autoUpdateNotifyFS")
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			h := uintptr(w.Window())
			if h != 0 {
				makeModalFullscreenTopmost(h)
				return
			}
			time.Sleep(15 * time.Millisecond)
		}
	}()

	// Fallback timer in case kgReady never fires (catastrophic
	// WebView2 paint failure). Longer budget than the post-paint
	// timer so the post-paint one wins the race in the normal case.
	fallback := time.AfterFunc(autoUpdateDismissTimeout+30*time.Second, func() {
		if !dismissArmed.CompareAndSwap(false, true) {
			return
		}
		if chose.Load() != 0 {
			return
		}
		logf("auto-update notify: fallback timeout (kgReady never fired)")
		chose.CompareAndSwap(0, 2)
		w.Dispatch(func() { w.Terminate() })
	})
	defer fallback.Stop()

	w.Run()

	switch chose.Load() {
	case 1:
		logf("auto-update notify: admin chose Update Now — spawning --update")
		spawnUpdateInvocation()
		os.Exit(0)
	case 2:
		logf("auto-update notify: admin chose Remind Me Later")
		os.Exit(1)
	default:
		// Window closed without a binding firing (extremely rare —
		// the only dismissal paths are kgUpdateNow / kgLater / Esc /
		// Alt+F4 / the timer). Treat as Later.
		logf("auto-update notify: window closed without selection — treating as Remind Me Later")
		os.Exit(1)
	}
}

// spawnUpdateInvocation fire-and-forget launches
// `kiosk-exit-guard.exe --update` as a detached child. Used by the
// --auto-update-notify path on Update Now: the existing --update flow
// handles password modal, download, SHA-256 verify, atomic swap, and
// Service restart. We don't wait for it because this notify child is
// about to exit.
func spawnUpdateInvocation() {
	exe, err := os.Executable()
	if err != nil {
		logf("spawnUpdateInvocation: os.Executable failed: %v", err)
		return
	}
	cmd := exec.Command(exe, "--update")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	if err := cmd.Start(); err != nil {
		logf("spawnUpdateInvocation: failed to spawn --update: %v", err)
		return
	}
	// Release the OS process handle so we don't leak it; the child
	// runs to completion independent of this exiting process.
	_ = cmd.Process.Release()
}

// runPauseInvocation is the entry point for `kiosk-exit-guard.exe --pause`,
// which is wired to the "Pause SK Filter" desktop shortcut. It performs
// the same flow as the Ctrl+Shift+Alt+K hotkey would inside the running
// controller, but as a fresh process — password modal, duration picker,
// state changes — and exits.
//
// The running controller picks up the change via its file-watching
// goroutine (see syncFilterStateLoop) and updates its in-memory state to
// match (kills the kiosk child, etc.).
func runPauseInvocation() {
	migrateLegacyHash()
	hash, err := loadHash()
	if err != nil || len(hash) == 0 {
		_ = zenity.Error(
			"SK Filter is not set up yet. Run kiosk-exit-guard.exe first to complete setup.",
			zenity.Title("SK Filter"),
		)
		os.Exit(1)
	}
	storedHash = hash

	// Already paused? Show status read-out and exit — don't silently
	// overwrite a longer in-flight pause with a new (possibly shorter) one.
	if pu := loadPauseFromDisk(); !pu.IsZero() && time.Now().Before(pu) {
		remain := time.Until(pu).Round(time.Second)
		showTimedInfo(fmt.Sprintf(
			"SK Filter is already paused.\nResumes in %s (at %s).\n\nUse \"Resume SK Filter\" to end early.",
			remain, pu.Format("3:04 PM"),
		))
		return
	}

	switch askPasswordModal(
		"Pause the SK Filter?",
		"Edge will be allowed and the kiosk will close for the duration you choose. The filter resumes automatically when the timer ends.",
	) {
	case pwWrong:
		// v1.1.9 UX MEDIUM#9: sync variant — os.Exit below kills the
		// parent before a fire-and-forget child toast can render.
		showFailedToastSync()
		os.Exit(1)
	case pwCancel:
		os.Exit(0)
	}
	// v1.1.9 UX MEDIUM#6: write the pause-just-applied marker BEFORE
	// killing the kiosk child. The controller's runWatchdog ticks every
	// 30s; if a tick fires between this Kill and the syncFilterStateLoop
	// (2s) flipping filterMode, the watchdog respawns the kiosk and the
	// user sees the "paused" toast followed by the kiosk briefly
	// reappearing. The marker carries a 5s future timestamp; watchdogTick
	// skips relaunching while the marker is in the future.
	writePauseJustAppliedMarker(5 * time.Second)

	// v1.1.7: kill the kiosk WebView2 child BEFORE showing the duration
	// picker. zenity.List is not HWND_TOPMOST so it would render behind
	// the kiosk's fullscreen topmost WebView2 and be invisible. Killing
	// the kiosk first lets zenity grab normal foreground. If the user
	// cancels we relaunch the kiosk; otherwise pause takes effect and
	// the kiosk stays down for the pause window.
	if p := findOurWebViewChild(); p != nil {
		_ = p.Kill()
	}
	dur, accepted := askPauseDuration()
	if !accepted || dur <= 0 {
		showTimedInfo("Pause cancelled.\nSK Filter is still active.")
		// Kiosk will reappear on the controller's next watchdog tick (30s)
		// — explicitly nudge it back via a process the controller will
		// detect; the running controller is the one that actually
		// launches --webview children. Best we can do from this fresh
		// --pause process is exit and let the controller's watchdog
		// notice. The user sees ~ up to 30s without the kiosk.
		return
	}

	until := time.Now().Add(dur)
	setPauseUntil(until)

	// Tear down lockdown state directly. The controller's sync loop will
	// also update its in-memory filterMode within 2s, but doing the
	// teardown here means the user gets immediate relief without
	// waiting for the polling tick.
	removeLockdown()
	removeIFEOBlock("chrome.exe")
	removeIFEOBlock("msedge.exe")
	// (kiosk already killed above)

	showTimedInfo(fmt.Sprintf(
		"SK Filter paused.\nEdge is allowed; kiosk closed.\nResumes at %s.",
		until.Format("3:04 PM"),
	))
}

// syncFilterStateLoop runs in the controller process and reconciles
// in-memory filterMode + lockdown state with the pause file on disk. The
// pause file is the source of truth across processes — when a separate
// --pause invocation writes to it, this loop picks the change up within
// ~2 seconds and reflects it in the controller (kills the kiosk child,
// flips the in-memory flag so the hook stops blocking keystrokes, etc.).
func syncFilterStateLoop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		pu := loadPauseFromDisk()
		paused := !pu.IsZero() && time.Now().Before(pu)
		switch {
		case paused && filterMode.Load():
			// External --pause invocation just started a pause. Mirror
			// it into the controller's state.
			pauseUntilNano.Store(pu.UnixNano())
			schedulePauseExpiry(time.Until(pu))
			filterMode.Store(false)
			saveFilterModeToDisk(false)
			removeLockdown()
			removeIFEOBlock("chrome.exe")
			removeIFEOBlock("msedge.exe")
			killWebViewChild()
		case paused && !filterMode.Load():
			// Already paused. Detect a pause extension/replacement from
			// another process and re-arm the timer so we don't auto-resume
			// using the old (shorter) deadline.
			if pu.UnixNano() != pauseUntilNano.Load() {
				pauseUntilNano.Store(pu.UnixNano())
				schedulePauseExpiry(time.Until(pu))
				logf("pause re-armed from external write: now resumes at %s", pu.Format("3:04 PM"))
			}
		case !paused && !filterMode.Load():
			// Pause window ended (timer fired in another process, or the
			// file was manually cleared). Bring the lockdown back.
			autoReenableFilterMode()
		}
	}
}

// ---------- main ----------

func main() {
	// Pin the main goroutine to its initial OS thread for the life of the
	// process. The Win32 LL keyboard hook installed below via
	// SetWindowsHookExW is bound to the thread that called it: events are
	// only dispatched while THAT thread is running a GetMessage loop. If
	// the Go runtime migrates this goroutine to a different OS thread
	// between SetWindowsHookExW and GetMessageW, the hook silently goes
	// dead — symptom: Ctrl/Win/Alt combos fall through instead of opening
	// the password modal. Reliably reproducible on first-run install
	// because firstRunWithWizard() runs a WebView2 message loop which
	// leaves the goroutine on a different thread than it started on.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// IFEO redirect handler: if Windows invoked us as the Debugger for a
	// blocked exe, we get --silent-exit as argv[1] and the blocked exe's
	// path appended. Exit silently so the user's launch attempt just
	// fails with no error window. Logging not initialized in this path
	// to keep the IFEO redirect fast.
	if len(os.Args) > 1 && os.Args[1] == "--silent-exit" {
		return
	}

	// --show-toast <ms> <message…>: child-process toast renderer. Used by
	// flows that need a branded toast in a process which will also create
	// another WebView2 instance shortly after — go-webview2 panics on the
	// second NewWithOptions call in the same process, so toast + modal in
	// the same flow MUST run in separate processes. Spawned via
	// `exec.Command(exe, "--show-toast", ...)` and detached.
	if len(os.Args) > 1 && os.Args[1] == "--show-toast" {
		if len(os.Args) < 4 {
			return
		}
		var durMs int
		_, _ = fmt.Sscanf(os.Args[2], "%d", &durMs)
		if durMs <= 0 {
			durMs = 2000
		}
		text := strings.Join(os.Args[3:], " ")
		showFrontmostToast(text, time.Duration(durMs)*time.Millisecond)
		return
	}

	// Open the log file before anything else can panic. Best-effort.
	initLogging()
	defer recoverAndLog("main")

	// --ask-password <title> <subtitle>: child-process password modal.
	// Used by every askPasswordModal call site so the calling process
	// never instantiates the modal's WebView2 itself. go-webview2 panics
	// on the second NewWithOptions in a process; the controller has
	// already created one during firstRunWithWizard, and any flow that
	// shows a password modal after another in-process WebView2 (e.g.
	// the LL hook callback's promptAndReinject in the controller, or
	// --update's "Checking…" toast before v1.1.1) would crash. This
	// child has zero prior WebView2 instances so the modal is always
	// its first; result is conveyed via exit code: 0 pwOK, 1 pwWrong,
	// 2 pwCancel (and 2 also for any plumbing failure).
	if len(os.Args) > 1 && os.Args[1] == "--ask-password" {
		if len(os.Args) < 4 {
			os.Exit(2)
		}
		title := os.Args[2]
		subtitle := os.Args[3]
		migrateLegacyHash()
		hash, herr := loadHash()
		if herr != nil || len(hash) == 0 {
			logf("--ask-password: no hash configured")
			os.Exit(2)
		}
		storedHash = hash
		switch askPasswordModalInProcess(title, subtitle) {
		case pwOK:
			os.Exit(0)
		case pwWrong:
			os.Exit(1)
		default:
			os.Exit(2)
		}
	}

	// --auto-update-notify <newver>: short-lived child process spawned
	// by the controller's auto-update checker. Renders the branded
	// "Update now? / Remind me later" WebView2 modal and exec's the
	// existing `--update` flow on Yes. Runs in its own process so the
	// controller's existing in-process WebView2 instances don't trip
	// go-webview2's second-NewWithOptions panic. v1.2.1.
	if len(os.Args) > 1 && os.Args[1] == "--auto-update-notify" {
		runAutoUpdateNotifyInvocation()
		return
	}

	// --service-run: SCM-only entry point for the Windows Service. Runs
	// the supervisor loop that respawns the user-session controller via
	// CreateProcessAsUserW. Returns when SCM sends Stop / Shutdown.
	if len(os.Args) > 1 && os.Args[1] == "--service-run" {
		runService()
		return
	}

	// --service-install / --service-remove: admin-elevated SCM management.
	// installService is also called inside first-run; --service-install
	// stands alone for upgrade / repair scenarios.
	if len(os.Args) > 1 && os.Args[1] == "--service-install" {
		runServiceInstall()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "--service-remove" {
		runServiceRemove()
		return
	}

	// WebView2 child mode — render the kiosk window and exit when closed.
	if len(os.Args) > 1 && os.Args[1] == "--webview" {
		runWebViewKiosk(loadKioskURL())
		return
	}

	// v1.2.4 shortcut-handler entry: the scheduled task registered by
	// installShortcutTasks fires `kiosk-exit-guard.exe --shortcut-handler
	// <flag>` running as SYSTEM in session 0 when the user clicks a
	// desktop shortcut. We look up the active user session and spawn the
	// flag's normal handler (--pause, --resume, etc.) into that session
	// via spawnFlagAsUserInSession. Session-0 has no UI, so we exit
	// immediately; the spawned child surfaces the password modal / kiosk
	// window / duration picker on the user's desktop.
	if len(os.Args) > 2 && os.Args[1] == "--shortcut-handler" {
		runShortcutHandler(os.Args[2])
		return
	}

	// --pause: triggered by the "Pause SK Filter" desktop shortcut.
	if len(os.Args) > 1 && os.Args[1] == "--pause" {
		runPauseInvocation()
		return
	}

	// --resume: triggered by the "Resume SK Filter" desktop shortcut.
	// No password — resuming makes the system more locked-down.
	if len(os.Args) > 1 && os.Args[1] == "--resume" {
		runResumeInvocation()
		return
	}

	// --launch-kiosk: triggered by the "Launch Kiosk" desktop shortcut.
	// Spawns a --webview child if the filter is currently active. If
	// the filter is paused, refuses (otherwise the button would
	// silently defeat the pause semantics — the kiosk would come back
	// during a window the admin chose to keep it down).
	if len(os.Args) > 1 && os.Args[1] == "--launch-kiosk" {
		runLaunchKiosk()
		return
	}

	// --update: triggered by the "Update SK Filter" desktop shortcut.
	// Checks GitHub for a newer release. If found and confirmed, password
	// prompts then downloads + atomic-renames the new exe in place and
	// restarts the scheduled task.
	if len(os.Args) > 1 && os.Args[1] == "--update" {
		runUpdateInvocation()
		return
	}

	// --uninstall: triggered by the "Uninstall SK Filter" desktop
	// shortcut. Password-gated, then a confirm dialog before tearing
	// everything down.
	if len(os.Args) > 1 && os.Args[1] == "--uninstall" {
		runUninstallInvocation()
		return
	}

	migrateLegacyHash()
	migrateLegacyState()
	// v1.1.8 HIGH#5: tighten the HKLM config key's DACL on every
	// controller startup so an existing v1.1.7-and-earlier install
	// heals on first launch of the new exe (the default ACL inherits
	// BUILTIN\Users:KEY_READ from HKLM\Software, exposing the bcrypt
	// hash to offline cracking by any local user). Idempotent.
	tightenHKLMConfigDACL()

	switch {
	case len(os.Args) > 1 && os.Args[1] == "--reset":
		hash, err := loadHash()
		if err != nil || len(hash) == 0 {
			_ = zenity.Error(
				"No password configured. Wipe HKLM\\Software\\KioskExitGuard via regedit and re-run if needed.",
				zenity.Title("kiosk-exit-guard"),
			)
			os.Exit(1)
		}
		storedHash = hash
		switch askPasswordModal(
			"Reset SK Filter",
			"Enter your password to clear the registry lockdown, the Chrome/Edge IFEO blocks, and the filter-mode state.",
		) {
		case pwWrong:
			showFailedToast()
			os.Exit(1)
		case pwCancel:
			os.Exit(0)
		}
		removeLockdown()
		removeIFEOBlock("chrome.exe")
		removeIFEOBlock("msedge.exe")
		saveFilterModeToDisk(false)
		setPauseUntil(time.Time{})
		_ = zenity.Info(
			"Reset complete.\nRegistry lockdown cleared, browser IFEO blocks removed, filter mode reset.",
			zenity.Title("kiosk-exit-guard"),
		)
		return

	case len(os.Args) > 1 && os.Args[1] == "--set-password":
		if err := setPassword(); err != nil {
			_ = zenity.Error(err.Error(), zenity.Title("kiosk-exit-guard"))
			os.Exit(1)
		}
		_ = zenity.Info("Password updated.", zenity.Title("kiosk-exit-guard"))
		return

	case len(os.Args) > 1 && os.Args[1] == "--set-url":
		// Password-gated since it's wired to a desktop shortcut. If the
		// kiosk has been booted with the wrong URL, anyone who could
		// click a shortcut would otherwise be able to redirect it.
		hash, err := loadHash()
		if err != nil || len(hash) == 0 {
			_ = zenity.Error(
				"SK Filter is not configured. Run first-run setup first.",
				zenity.Title("SK Filter"),
			)
			os.Exit(1)
		}
		storedHash = hash
		switch askPasswordModal(
			"Change the kiosk URL?",
			"Enter the admin password to confirm.",
		) {
		case pwWrong:
			// v1.1.9 UX MEDIUM#9: sync variant — os.Exit below would
			// kill a fire-and-forget child mid-paint.
			showFailedToastSync()
			os.Exit(1)
		case pwCancel:
			os.Exit(0)
		}
		newURL, err := promptForKioskURL()
		if err != nil {
			// User-cancel of zenity.Entry returns an error too; don't
			// scare them with a raw error dialog — treat as cancel.
			if errors.Is(err, zenity.ErrCanceled) {
				return
			}
			_ = zenity.Error(err.Error(), zenity.Title("SK Filter"))
			os.Exit(1)
		}
		// v1.1.9 UX LOW#11: defensively re-save the URL to HKLM BEFORE
		// killing the kiosk child. promptForKioskURL already persists
		// it as its last step, but an explicit save here guards the
		// invariant against future refactors of promptForKioskURL:
		// the kiosk respawn loaded the OLD URL if Kill ever fired
		// before the registry write completed. Idempotent.
		if err := saveKioskURLToRegistry(newURL); err != nil {
			logf("--set-url: re-save before kiosk restart failed: %v (URL was already saved by promptForKioskURL)", err)
		}
		// Restart the kiosk child so it loads the new URL immediately
		// rather than waiting for the controller's next watchdog tick.
		if p := findOurWebViewChild(); p != nil {
			_ = p.Kill()
		}
		_ = zenity.Info(
			fmt.Sprintf("Kiosk URL updated to:\n%s\n\nThe kiosk window will relaunch at the new URL within a few seconds.", newURL),
			zenity.Title("SK Filter"),
		)
		return
	}

	// v1.2.0 HIGH#3: first-run/relocate mutex. relocateToProgramFilesIfNeeded
	// (called from firstRunWithWizard further down) copies the running exe
	// to %ProgramFiles%\KioskExitGuard and re-execs. Pre-v1.2.0 had no
	// gate on this: two simultaneous admin double-clicks both ran relocate
	// concurrently and corrupted each other's installs. The mutex makes
	// the second-mover exit silently. Skipped above for short-lived flag
	// paths that don't run the relocator. Fail-open on mutex-create
	// errors so a degraded kernel32 doesn't refuse to start.
	if mh, alreadyHeld := acquireAdminOnlyNamedMutex(globalFirstRunMutexName); alreadyHeld {
		logf("first-run/relocate already in progress in another instance, exiting")
		os.Exit(0)
	} else {
		// Intentionally leak the handle for the life of this process —
		// the controller mutex acquired further down takes over the
		// "only one controller" guarantee. The kernel releases on exit.
		_ = mh
	}

	// Ensure WebView2 Runtime is available before we touch anything else.
	// Auto-installs silently if missing (no-op on Win10/11 client; does
	// the real work on Server SKUs / stripped images). If install fails,
	// continue without — the --webview child will surface the error.
	if err := ensureWebView2Installed(); err != nil {
		_ = zenity.Warning(
			fmt.Sprintf("WebView2 auto-install failed: %v\n\nDownload manually from https://developer.microsoft.com/microsoft-edge/webview2/ and re-launch kiosk-exit-guard.", err),
			zenity.Title("kiosk-exit-guard"),
		)
	}

	// v1.1.8 MEDIUM#7: install the LL keyboard hook BEFORE killing any
	// leftover controller from a prior install. Previously the hook was
	// installed at the very bottom of main(), well after
	// killRunningController() ran — during the gap (seconds while
	// purgeLeftoverState, firstRunWithWizard, ensureWebView2Installed,
	// etc. run) no controller was alive AND no hook was installed,
	// leaving the kiosk briefly unprotected. The hook reads filterMode
	// (atomic.Bool default-false) and storedHash (nil at this point) —
	// since filterMode is still off, the hook is a no-op until the
	// "default-ON" branch below flips it. Once flipped, the hook is
	// already running and starts intercepting immediately.
	cb := syscall.NewCallback(hookCallback)
	hookHandle, _, hookErr := procSetWindowHookExW.Call(uintptr(whKeyboardLL), cb, 0, 0)
	if hookHandle == 0 {
		logf("ERROR: SetWindowsHookEx (early-install) failed: %v", hookErr)
		_ = zenity.Error(
			fmt.Sprintf("SetWindowsHookEx failed: %v", hookErr),
			zenity.Title("kiosk-exit-guard"),
		)
		os.Exit(1)
	}
	logf("LL keyboard hook installed early (handle=%d) before killRunningController", hookHandle)
	defer procUnhookWindowsHookEx.Call(hookHandle)

	// v1.1.9 UX HIGH#1: take the cross-process "controller is running"
	// mutex BEFORE killRunningController. Without this, at logon both
	// the Windows Service supervisor AND the AtLogon scheduled task
	// race to spawn a controller; whichever loses gets killed by the
	// winner's killRunningController call, the loser's supervisor
	// respawns it ~1s later, and the kiosk WebView2 child blinks /
	// reopens. With the mutex, the second mover exits silently and
	// the first controller keeps running (its supervisor never sees
	// a death, so no respawn, no kiosk blink). Skipped for all the
	// short-lived flag-driven invocations above (--reset, --update,
	// --pause, etc. — those already returned earlier in main).
	//
	// Intentionally leak the handle: holding it open for the
	// controller's lifetime is exactly what we want (the GetMessageW
	// loop at the bottom of main keeps the process alive, the kernel
	// frees the handle on process exit, the mutex is auto-released).
	if mh, alreadyRunning := acquireControllerMutex(); alreadyRunning {
		logf("controller mutex %s already held by another process; exiting", globalControllerMutexName)
		// Release the early-installed LL hook before exit so we
		// don't leak a hook handle into the kernel.
		procUnhookWindowsHookEx.Call(hookHandle)
		os.Exit(0)
	} else {
		_ = mh // own it for the life of the process; closed on exit
	}

	// If there's a leftover controller from a previous install still
	// running (orphaned by a partial uninstall, an aborted update, etc.),
	// kill it after our hook is in place. Otherwise two controllers fight
	// over the hook and the new install's password doesn't match the old
	// one's in-memory cached hash. With the mutex above held, this is now
	// a no-op in the steady-state co-installed-auto-start case — any
	// surviving controller would have held the mutex and we'd have
	// exited already. The kill remains useful for cleaning up orphans
	// from partial uninstalls / aborted updates where the dead process
	// can't have held the mutex.
	killRunningController()

	hash, err := loadHash()
	firstRun := err != nil || len(hash) == 0
	if firstRun {
		// If the supervising Service spawned us into a user session but
		// the admin hasn't completed first-run yet, do NOT pop the wizard
		// — the Service would respawn-loop a stack of wizards every few
		// seconds. Just log and exit; the admin's manual double-click is
		// the only legitimate path to first-run setup.
		if isLaunchedByService() {
			logf("service-spawned controller but no password configured; exiting without wizard")
			return
		}
		// Purge any leftover state before the wizard so the user gets a
		// truly clean install. Cheap if there's nothing to clean.
		purgeLeftoverState()
		if !firstRunWithWizard() {
			// User cancelled the wizard or setup failed mid-flow. Bail.
			os.Exit(1)
		}
		hash, err = loadHash()
		if err != nil || len(hash) == 0 {
			_ = zenity.Error("Password did not save. Aborting.", zenity.Title("kiosk-exit-guard"))
			os.Exit(1)
		}
	} else {
		// Refresh the desktop shortcuts and the auto-start mechanism on
		// every non-first-run launch. Both are idempotent and cheap; this
		// is how an installed v1.0.x auto-upgrades to v1.1.0's Service
		// (and how an existing v1.1.0 install heals a damaged service
		// registration) by just launching the new exe once.
		//
		// Skip when we were spawned by the Service itself — that would
		// race the SCM and stop our own parent during steady-state
		// operation. The admin's manual / desktop-shortcut launches still
		// refresh.
		_ = installShortcutTasks()
		_ = createDesktopShortcut()
		if !isLaunchedByService() {
			// v1.1.4: always refresh BOTH the Service and the scheduled
			// task. Either alone has been observed to fail in the field
			// (WTSQueryUserToken NO_TOKEN on some Win11 Home machines
			// kills the Service spawn path even when Service itself is
			// happily registered), so we keep both auto-start mechanisms
			// alive. killRunningController() prevents two controllers
			// from running simultaneously.
			if err := installService(); err != nil {
				logf("non-first-run service refresh failed: %v", err)
			}
			if err := installStartupTask(); err != nil {
				logf("non-first-run scheduled-task refresh failed: %v", err)
			}
		}
	}
	storedHash = hash

	// Default state in v0.5.1+: SK Filter is ON. The only persisted state
	// is the pause window (pause_until.state). If a pause is in-flight
	// and hasn't expired, restore it; otherwise the filter is active.
	pu := loadPauseFromDisk()
	if !pu.IsZero() && time.Now().Before(pu) {
		// Pause still active — keep filter off until timer fires.
		pauseUntilNano.Store(pu.UnixNano())
		schedulePauseExpiry(time.Until(pu))
		filterMode.Store(false)
		saveFilterModeToDisk(false)
		// Ensure the registry/IFEO state matches "paused" — don't apply
		// the kiosk lockdown or browser blocks until the pause ends.
		removeLockdown()
		removeIFEOBlock("chrome.exe")
		removeIFEOBlock("msedge.exe")
	} else {
		// Default: filter is ON. Wipe any stale pause file.
		setPauseUntil(time.Time{})
		filterMode.Store(true)
		saveFilterModeToDisk(true)
		applyLockdown()
		applyBrowserBlocks()
	}
	defer removeLockdown()
	defer cancelPauseExpiry()
	defer killWebViewChild()

	logf("controller steady-state filterMode=%v paused=%v kioskURL=%q",
		filterMode.Load(), pauseUntilNano.Load() != 0, loadKioskURL())

	go func() { defer recoverAndLog("watchdog"); runWatchdog() }()
	go func() { defer recoverAndLog("syncLoop"); syncFilterStateLoop() }()

	// v1.2.1: auto-update background checker. Polls GitHub on startup
	// (after a 60s settle delay) and every 24h thereafter; spawns the
	// branded WebView2 "Update now? / Remind me later" notify child
	// when a newer release is published. Only started from the long-
	// lived controller path — every short-lived flag invocation
	// returned earlier in main() without reaching here.
	autoUpdateCtx, cancelAutoUpdate := context.WithCancel(context.Background())
	defer cancelAutoUpdate()
	go runAutoUpdateChecker(autoUpdateCtx)

	// LL keyboard hook was installed early (v1.1.8 MEDIUM#7 fix) — the
	// GetMessageW pump below still has to live on the same thread as
	// the SetWindowsHookExW call (runtime.LockOSThread at the top of
	// main() guarantees this) so the hook stays alive for the
	// controller's lifetime.
	var m msgT
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
	}
}
