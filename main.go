//go:build windows && amd64

// kiosk-exit-guard is a single-binary Windows kiosk lockdown utility built
// for Windows 11 Home (where Assigned Access isn't available).
//
// Behavior is gated by a "filter mode" toggle that the admin flips with the
// hotkey Ctrl+Shift+Alt+K (password-gated):
//
//   - Filter mode OFF: all keys pass through, registry policies are not set
//   - Filter mode ON: Alt+F4 prompts for the password; Win+R, Win+E, Win+D,
//     and Ctrl+Shift+Esc are silently swallowed; Task Manager and the Run
//     dialog are disabled via HKCU registry policies
//
// First launch with no password.hash drops the user into a set-password
// modal and installs a Task Scheduler entry so the exe re-launches at every
// user logon. UAC consent is requested via an embedded manifest so the
// schtasks install (which needs HIGHEST run level) succeeds.
//
// Recovery: if the exe crashes while filter mode is ON, run
//
//	kiosk-exit-guard.exe --reset
//
// to restore Task Manager and the Run dialog.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/ncruces/zenity"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sys/windows/registry"
)

// ---------- Win32 constants ----------

const (
	whKeyboardLL = 13
	wmKeyDown    = 0x0100
	wmSysKeyDown = 0x0104
	wmClose      = 0x0010

	// Virtual-key codes
	vkF4     = 0x73
	vkR      = 0x52
	vkE      = 0x45
	vkD      = 0x44
	vkK      = 0x4B
	vkEscape = 0x1B
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
	regDisableTaskMgr = "DisableTaskMgr"
	regNoRun          = "NoRun"

	taskName       = "KioskExitGuard"
	stateFileName  = "filter_mode.state"
	hashFileName   = "password.hash"
	toastTimeoutMs = 2000
)

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
	user32 = syscall.NewLazyDLL("user32.dll")

	procSetWindowsHookExW   = user32.NewProc("SetWindowsHookExW")
	procUnhookWindowsHookEx = user32.NewProc("UnhookWindowsHookEx")
	procCallNextHookEx      = user32.NewProc("CallNextHookEx")
	procGetMessageW         = user32.NewProc("GetMessageW")
	procGetAsyncKeyState    = user32.NewProc("GetAsyncKeyState")
	procGetForegroundWindow = user32.NewProc("GetForegroundWindow")
	procPostMessageW        = user32.NewProc("PostMessageW")

	storedHash []byte
	promptOpen atomic.Bool
	filterMode atomic.Bool // mirrored to disk via filter_mode.state
)

// ---------- file paths ----------

func nextToExe(name string) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(exe), name), nil
}

func hashPath() (string, error)  { return nextToExe(hashFileName) }
func statePath() (string, error) { return nextToExe(stateFileName) }

// ---------- password storage ----------

func loadHash() ([]byte, error) {
	p, err := hashPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimSpace(string(data))), nil
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
	p, err := hashPath()
	if err != nil {
		return err
	}
	return os.WriteFile(p, hash, 0o600)
}

// ---------- filter mode persistence ----------

func loadFilterModeFromDisk() bool {
	p, err := statePath()
	if err != nil {
		return false
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == "1"
}

func saveFilterModeToDisk(on bool) {
	p, err := statePath()
	if err != nil {
		return
	}
	val := []byte("0")
	if on {
		val = []byte("1")
	}
	_ = os.WriteFile(p, val, 0o600)
}

// ---------- registry lockdown ----------

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
}

func removeLockdown() {
	_ = deletePolicyValue(regPolicySystem, regDisableTaskMgr)
	_ = deletePolicyValue(regPolicyExplorer, regNoRun)
}

// ---------- self-install via schtasks ----------

// installStartupTask registers a logon-triggered scheduled task that
// re-launches this exe at user logon with HIGHEST run level so it starts
// already elevated and skips the UAC prompt at logon time. Idempotent (the
// /F flag overwrites any existing task with the same name).
func installStartupTask() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(
		"schtasks", "/Create", "/F",
		"/TN", taskName,
		"/TR", fmt.Sprintf(`"%s"`, exe),
		"/SC", "ONLOGON",
		"/RL", "HIGHEST",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
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

// shouldSilentlyBlock returns true if the keystroke is one of the additional
// kiosk-escape combos we swallow with no user feedback. Only active when
// filter mode is ON.
func shouldSilentlyBlock(vk uint32) bool {
	switch vk {
	case vkR, vkE, vkD:
		return winDown()
	case vkEscape:
		return ctrlDown() && shiftDown()
	}
	return false
}

// ---------- toast helpers ----------

func showTimedInfo(text string) {
	ctx, cancel := context.WithTimeout(context.Background(), toastTimeoutMs*time.Millisecond)
	defer cancel()
	_ = zenity.Info(
		text,
		zenity.Title("kiosk-exit-guard"),
		zenity.Context(ctx),
	)
}

func showFailedToast() { showTimedInfo("Wrong password.") }

// ---------- hook callback ----------

func hookCallback(nCode int32, wParam uintptr, lParam uintptr) uintptr {
	if nCode >= 0 && (wParam == wmKeyDown || wParam == wmSysKeyDown) {
		kb := (*kbdLLHookStruct)(unsafe.Pointer(lParam))
		injected := (kb.Flags & llkhfInject) != 0
		if !injected {
			// Toggle hotkey works in both ON and OFF modes so the admin can
			// always flip the lockdown.
			if kb.VkCode == vkK && ctrlDown() && shiftDown() && altDown() {
				if !promptOpen.Load() {
					go promptAndToggleFilterMode()
				}
				return 1
			}
			if filterMode.Load() {
				if kb.VkCode == vkF4 && altDown() {
					if !promptOpen.Load() {
						go promptAndMaybeExit()
					}
					return 1
				}
				if shouldSilentlyBlock(kb.VkCode) {
					return 1
				}
			}
		}
	}
	ret, _, _ := procCallNextHookEx.Call(0, uintptr(nCode), wParam, lParam)
	return ret
}

// ---------- password-gated actions ----------

func askPassword(label string) (bool, bool) {
	// returns (ok, cancelled)
	pw, err := zenity.Entry(
		label,
		zenity.Title("kiosk-exit-guard"),
		zenity.HideText(),
	)
	if err != nil {
		return false, true
	}
	if bcrypt.CompareHashAndPassword(storedHash, []byte(pw)) != nil {
		return false, false
	}
	return true, false
}

func promptAndMaybeExit() {
	if !promptOpen.CompareAndSwap(false, true) {
		return
	}
	defer promptOpen.Store(false)
	hwnd, _, _ := procGetForegroundWindow.Call()
	ok, _ := askPassword("Enter password to exit kiosk.")
	if !ok {
		showFailedToast()
		return
	}
	procPostMessageW.Call(hwnd, uintptr(wmClose), 0, 0)
}

func promptAndToggleFilterMode() {
	if !promptOpen.CompareAndSwap(false, true) {
		return
	}
	defer promptOpen.Store(false)
	current := filterMode.Load()
	verb := "ON"
	if current {
		verb = "OFF"
	}
	ok, _ := askPassword(fmt.Sprintf("Enter password to turn filter mode %s.", verb))
	if !ok {
		showFailedToast()
		return
	}
	newState := !current
	filterMode.Store(newState)
	saveFilterModeToDisk(newState)
	if newState {
		applyLockdown()
		showTimedInfo("Filter mode ON.\nTask Manager, Run dialog, and kiosk-escape shortcuts are blocked.")
	} else {
		removeLockdown()
		showTimedInfo("Filter mode OFF.\nTask Manager and Run dialog restored.")
	}
}

// ---------- main ----------

func main() {
	// --reset: clear lockdown registry and exit. Recovery path if the exe
	// crashed while filter mode was on.
	if len(os.Args) > 1 && os.Args[1] == "--reset" {
		removeLockdown()
		saveFilterModeToDisk(false)
		_ = zenity.Info(
			"Lockdown registry entries cleared.\nFilter mode state reset to OFF.",
			zenity.Title("kiosk-exit-guard"),
		)
		return
	}

	// --set-password: change the password without going through first-run.
	if len(os.Args) > 1 && os.Args[1] == "--set-password" {
		if err := setPassword(); err != nil {
			_ = zenity.Error(err.Error(), zenity.Title("kiosk-exit-guard"))
			os.Exit(1)
		}
		_ = zenity.Info("Password updated.", zenity.Title("kiosk-exit-guard"))
		return
	}

	// First-run flow: no password file? walk the user through setting one
	// inline and install the auto-start scheduled task.
	hash, err := loadHash()
	firstRun := err != nil || len(hash) == 0
	if firstRun {
		_ = zenity.Info(
			"First run. The next two prompts will let you create the admin password used to exit kiosk mode and toggle filter mode.",
			zenity.Title("kiosk-exit-guard — first run"),
		)
		if perr := setPassword(); perr != nil {
			_ = zenity.Error(perr.Error(), zenity.Title("kiosk-exit-guard"))
			os.Exit(1)
		}
		hash, err = loadHash()
		if err != nil || len(hash) == 0 {
			_ = zenity.Error("Password file disappeared after setup. Aborting.", zenity.Title("kiosk-exit-guard"))
			os.Exit(1)
		}
		// Install the Task Scheduler entry so the exe re-launches at every
		// user logon. Reports installer error inline but doesn't abort —
		// the user can re-run later or schedule manually.
		if instErr := installStartupTask(); instErr != nil {
			_ = zenity.Warning(
				fmt.Sprintf("Auto-start install failed:\n%v\n\nThe exe is configured but won't launch automatically until you set up a Task Scheduler entry manually.", instErr),
				zenity.Title("kiosk-exit-guard"),
			)
		} else {
			_ = zenity.Info(
				"Setup complete.\n\nPassword saved. A scheduled task named \""+taskName+"\" will launch kiosk-exit-guard at every user logon.\n\nUse Ctrl+Shift+Alt+K to toggle filter mode.\nFilter mode starts OFF.",
				zenity.Title("kiosk-exit-guard"),
			)
		}
	}
	storedHash = hash

	// Restore persisted filter-mode state. If the user toggled it ON before
	// the last shutdown, re-apply the lockdown on relaunch.
	filterMode.Store(loadFilterModeFromDisk())
	if filterMode.Load() {
		applyLockdown()
	}
	defer removeLockdown()

	cb := syscall.NewCallback(hookCallback)
	h, _, callErr := procSetWindowsHookExW.Call(uintptr(whKeyboardLL), cb, 0, 0)
	if h == 0 {
		removeLockdown()
		_ = zenity.Error(
			fmt.Sprintf("SetWindowsHookEx failed: %v", callErr),
			zenity.Title("kiosk-exit-guard"),
		)
		os.Exit(1)
	}
	defer procUnhookWindowsHookEx.Call(h)

	// Win32 message loop on the main thread — required for LL hooks.
	var m msgT
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
	}
}
