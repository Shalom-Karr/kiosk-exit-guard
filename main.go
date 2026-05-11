//go:build windows && amd64

// kiosk-exit-guard is a single-binary Windows kiosk lockdown utility built
// for Windows 11 Home where Assigned Access isn't available.
//
// Filter mode toggle (Ctrl+Shift+Alt+K, password-gated):
//
//   - OFF (default): keys pass through; registry policies are clean; the
//     Chrome kiosk watchdog is paused.
//   - ON: Alt+F4 prompts for the password; Win+R, Win+E, Win+D, and
//     Ctrl+Shift+Esc are silently swallowed; Task Manager and Run dialog
//     disabled via HKCU policy registry; a 30s-tick watchdog auto-launches
//     Chrome in --kiosk mode pointing at the configured URL and re-launches
//     it if killed.
//
// Toggling filter mode OFF prompts the admin for a pause duration. When
// the pause expires, filter mode automatically flips back ON.
//
// Config: kiosk URL is read from kiosk.url next to the exe; defaults to
// https://skluach.pages.dev/CMH/ if the file is missing or empty.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/ncruces/zenity"
	"github.com/shirou/gopsutil/v4/process"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sys/windows/registry"
)

// ---------- Win32 constants ----------

const (
	whKeyboardLL = 13
	wmKeyDown    = 0x0100
	wmSysKeyDown = 0x0104
	wmClose      = 0x0010

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

	regPolicySystem   = `Software\Microsoft\Windows\CurrentVersion\Policies\System`
	regPolicyExplorer = `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
	regDisableTaskMgr = "DisableTaskMgr"
	regNoRun          = "NoRun"

	// HKLM key + value where the bcrypt password hash lives. HKLM means
	// only an admin / elevated process can write or delete the value, so a
	// kiosk user with a standard account can't bypass the password by
	// deleting a config file.
	regAppKey    = `Software\KioskExitGuard`
	regHashValue = "PasswordHash"
	regURLValue  = "KioskURL"

	taskName         = "KioskExitGuard"
	stateFileName    = "filter_mode.state"
	hashFileName     = "password.hash" // legacy — migrated to HKLM on startup
	kioskURLFileName = "kiosk.url"
	pauseFileName    = "pause_until.state"

	defaultKioskURL  = "https://skluach.pages.dev/CMH/"
	watchdogInterval = 30 * time.Second
	toastTimeoutMs   = 2000

	createNoWindow = 0x08000000
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
	filterMode atomic.Bool

	pauseUntilNano atomic.Int64 // 0 = not paused; else unix nano of expiry

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

// ---------- password storage ----------

// loadHashFromRegistry reads the bcrypt password hash out of HKLM. Returns
// (nil, nil) when no value is set — callers should treat that as "not
// configured" rather than an error.
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
	return k.SetBinaryValue(regHashValue, hash)
}

// migrateLegacyHash moves a v0.2.x-style password.hash file into HKLM and
// deletes the file. Idempotent — does nothing if file is absent or registry
// already populated.
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
		// Registry wins; remove stale file.
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

// ---------- filter mode + pause persistence ----------

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

func savePauseToDisk(until time.Time) {
	p, err := pausePath()
	if err != nil {
		return
	}
	if until.IsZero() {
		_ = os.Remove(p)
		return
	}
	_ = os.WriteFile(p, []byte(fmt.Sprintf("%d", until.UnixNano())), 0o600)
}

func loadPauseFromDisk() time.Time {
	p, err := pausePath()
	if err != nil {
		return time.Time{}
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return time.Time{}
	}
	var nano int64
	if _, err := fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &nano); err != nil {
		return time.Time{}
	}
	return time.Unix(0, nano)
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

// ---------- chrome watchdog ----------

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

// loadKioskURL: registry first, then legacy kiosk.url file next to exe,
// then the default. Lets v0.2.x users keep their file-based config until
// they re-run setup (which will write the URL into HKLM).
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

// promptForKioskURL asks the admin which URL the watchdog should keep open
// in Chrome. Pre-filled with the existing value (registry, file, or default)
// so an empty submission keeps the previous URL.
func promptForKioskURL() (string, error) {
	current := loadKioskURL()
	url, err := zenity.Entry(
		"Enter the kiosk URL.\nThis is the page Chrome will open in --kiosk mode and the watchdog will keep alive.",
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
	if err := saveKioskURLToRegistry(url); err != nil {
		return "", err
	}
	return url, nil
}

func findChrome() string {
	candidates := []string{
		filepath.Join(os.Getenv("ProgramFiles"), "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(os.Getenv("LocalAppData"), "Google", "Chrome", "Application", "chrome.exe"),
	}
	for _, p := range candidates {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

func launchKioskChrome(chromePath, kioskURL string) {
	cmd := exec.Command(chromePath, "--kiosk", kioskURL, "--no-first-run")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	_ = cmd.Start()
}

// watchdogTick checks Chrome state and re-launches the kiosk URL if needed.
// Mirrors the logic of the original Luach Kiosk Watchdog PowerShell script.
func watchdogTick(chromePath, kioskURL string) {
	if chromePath == "" {
		return
	}
	procs, err := process.Processes()
	if err != nil {
		return
	}
	var chromeProcs []*process.Process
	kioskAlive := false
	for _, p := range procs {
		name, _ := p.Name()
		if !strings.EqualFold(name, "chrome.exe") {
			continue
		}
		chromeProcs = append(chromeProcs, p)
		cmd, cerr := p.Cmdline()
		if cerr != nil {
			continue
		}
		if strings.Contains(cmd, "--kiosk") && strings.Contains(cmd, kioskURL) {
			kioskAlive = true
		}
	}
	if len(chromeProcs) == 0 {
		launchKioskChrome(chromePath, kioskURL)
		return
	}
	if !kioskAlive {
		for _, p := range chromeProcs {
			_ = p.Kill()
		}
		time.Sleep(2 * time.Second)
		launchKioskChrome(chromePath, kioskURL)
	}
}

func runWatchdog(kioskURL string) {
	chromePath := findChrome()
	ticker := time.NewTicker(watchdogInterval)
	defer ticker.Stop()
	// Fire one immediately so kiosk Chrome appears as soon as filter mode
	// is enabled, rather than waiting up to 30s.
	if filterMode.Load() && !isPaused() {
		watchdogTick(chromePath, kioskURL)
	}
	for range ticker.C {
		if filterMode.Load() && !isPaused() {
			watchdogTick(chromePath, kioskURL)
		}
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

func autoReenableFilterMode() {
	if filterMode.Load() {
		return
	}
	filterMode.Store(true)
	saveFilterModeToDisk(true)
	setPauseUntil(time.Time{})
	applyLockdown()
	showTimedInfo("Pause expired.\nFilter mode is back ON.")
}

// askPauseDuration shows a radio-list of pause options and returns the
// chosen duration. Zero return means "indefinite" (no auto-re-enable).
func askPauseDuration() (time.Duration, bool) {
	choices := []string{
		"5 minutes",
		"15 minutes",
		"30 minutes",
		"1 hour",
		"Indefinitely (re-enable manually)",
	}
	choice, err := zenity.List(
		"How long should kiosk mode stay OFF?\nFilter mode will auto-re-enable after this time.",
		choices,
		zenity.RadioList(),
		zenity.Title("kiosk-exit-guard — pause"),
	)
	if err != nil {
		// User cancelled the pause prompt — don't toggle filter mode.
		return 0, false
	}
	switch choice {
	case choices[0]:
		return 5 * time.Minute, true
	case choices[1]:
		return 15 * time.Minute, true
	case choices[2]:
		return 30 * time.Minute, true
	case choices[3]:
		return time.Hour, true
	case choices[4]:
		return 0, true // indefinite
	}
	return 5 * time.Minute, true
}

// ---------- hook callback ----------

// isModifierVK reports whether vk is itself a modifier key. Modifier-only
// presses (just Ctrl, just Alt, just Win, just Shift) should pass through
// so that downstream checks see them and so the kiosk app's normal text
// selection / accessibility features keep working when filter mode is off.
func isModifierVK(vk uint32) bool {
	switch vk {
	case vkLCtrl, vkRCtrl, vkLMenu, vkRMenu, vkLWin, vkRWin, vkLShift, vkRShift:
		return true
	}
	return false
}

func hookCallback(nCode int32, wParam uintptr, lParam uintptr) uintptr {
	if nCode >= 0 && (wParam == wmKeyDown || wParam == wmSysKeyDown) {
		kb := (*kbdLLHookStruct)(unsafe.Pointer(lParam))
		injected := (kb.Flags & llkhfInject) != 0
		if !injected {
			// Toggle hotkey always works in either mode so the admin can
			// always flip the lockdown.
			if kb.VkCode == vkK && ctrlDown() && shiftDown() && altDown() {
				if !promptOpen.Load() {
					go promptAndToggleFilterMode()
				}
				return 1
			}
			if filterMode.Load() {
				// Alt+F4 = password-gated window close.
				if kb.VkCode == vkF4 && altDown() {
					if !promptOpen.Load() {
						go promptAndMaybeExit()
					}
					return 1
				}
				// Blanket block: any non-modifier keystroke held with
				// Ctrl, Win, or Alt is swallowed. This covers Ctrl+F4,
				// Ctrl+W, Alt+Tab, Win+anything, etc. — every common
				// keyboard escape from a kiosk app at once. Plain Shift
				// is allowed so case-shift still works for any input
				// fields the kiosk URL exposes.
				if !isModifierVK(kb.VkCode) && (ctrlDown() || winDown() || altDown()) {
					return 1
				}
			}
		}
	}
	ret, _, _ := procCallNextHookEx.Call(0, uintptr(nCode), wParam, lParam)
	return ret
}

// ---------- password-gated actions ----------

func askPassword(label string) bool {
	pw, err := zenity.Entry(
		label,
		zenity.Title("kiosk-exit-guard"),
		zenity.HideText(),
	)
	if err != nil {
		return false
	}
	return bcrypt.CompareHashAndPassword(storedHash, []byte(pw)) == nil
}

func promptAndMaybeExit() {
	if !promptOpen.CompareAndSwap(false, true) {
		return
	}
	defer promptOpen.Store(false)
	hwnd, _, _ := procGetForegroundWindow.Call()
	if !askPassword("Enter password to exit kiosk.") {
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
	if !askPassword(fmt.Sprintf("Enter password to turn filter mode %s.", verb)) {
		showFailedToast()
		return
	}
	newState := !current
	if !newState {
		// Going OFF — ask for pause duration before flipping.
		dur, accepted := askPauseDuration()
		if !accepted {
			return
		}
		if dur > 0 {
			setPauseUntil(time.Now().Add(dur))
			schedulePauseExpiry(dur)
		} else {
			setPauseUntil(time.Time{})
			cancelPauseExpiry()
		}
	} else {
		// Going ON — clear any pending pause.
		setPauseUntil(time.Time{})
		cancelPauseExpiry()
	}
	filterMode.Store(newState)
	saveFilterModeToDisk(newState)
	if newState {
		applyLockdown()
		showTimedInfo("Filter mode ON.\nKiosk Chrome will launch and auto-restart.\nTask Manager, Run dialog, and escape shortcuts are blocked.")
	} else {
		removeLockdown()
		if pauseUntilNano.Load() != 0 {
			showTimedInfo(fmt.Sprintf(
				"Filter mode OFF.\nAuto-re-enable at %s.",
				time.Unix(0, pauseUntilNano.Load()).Format("3:04 PM"),
			))
		} else {
			showTimedInfo("Filter mode OFF (indefinitely).\nPress Ctrl+Shift+Alt+K to turn it back on.")
		}
	}
}

// ---------- main ----------

func main() {
	// Migrate any v0.2.x password.hash file before anything else, so the
	// hash is in HKLM by the time we need to verify a password.
	migrateLegacyHash()

	switch {
	case len(os.Args) > 1 && os.Args[1] == "--reset":
		// Recovery flag — restores Task Manager / Run dialog and clears
		// filter-mode state. Now password-gated so a curious kiosk user
		// can't trigger it from a shortcut. If no password is configured,
		// fail closed; an admin should wipe HKLM\Software\KioskExitGuard
		// via regedit and re-run first-run setup.
		hash, err := loadHash()
		if err != nil || len(hash) == 0 {
			_ = zenity.Error(
				"No password configured. --reset requires a configured password.\n\nIf the exe is in a broken state, an admin can wipe HKLM\\Software\\KioskExitGuard via regedit and re-run kiosk-exit-guard.exe to start over.",
				zenity.Title("kiosk-exit-guard"),
			)
			os.Exit(1)
		}
		storedHash = hash
		if !askPassword("Enter password to clear lockdown and reset filter mode.") {
			showFailedToast()
			os.Exit(1)
		}
		removeLockdown()
		saveFilterModeToDisk(false)
		setPauseUntil(time.Time{})
		_ = zenity.Info(
			"Reset complete.\nLockdown cleared, filter mode reset to OFF.",
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
		if _, err := promptForKioskURL(); err != nil {
			_ = zenity.Error(err.Error(), zenity.Title("kiosk-exit-guard"))
			os.Exit(1)
		}
		_ = zenity.Info("Kiosk URL updated.", zenity.Title("kiosk-exit-guard"))
		return
	}

	hash, err := loadHash()
	firstRun := err != nil || len(hash) == 0
	if firstRun {
		_ = zenity.Info(
			"First run. We'll create the admin password and then ask you which URL Chrome should open in kiosk mode.",
			zenity.Title("kiosk-exit-guard — first run"),
		)
		if perr := setPassword(); perr != nil {
			_ = zenity.Error(perr.Error(), zenity.Title("kiosk-exit-guard"))
			os.Exit(1)
		}
		hash, err = loadHash()
		if err != nil || len(hash) == 0 {
			_ = zenity.Error("Password did not save. Aborting.", zenity.Title("kiosk-exit-guard"))
			os.Exit(1)
		}
		if _, perr := promptForKioskURL(); perr != nil {
			_ = zenity.Warning(
				fmt.Sprintf("Kiosk URL not saved:\n%v\n\nWill fall back to the default URL. You can change it later with --set-url.", perr),
				zenity.Title("kiosk-exit-guard"),
			)
		}
		if instErr := installStartupTask(); instErr != nil {
			_ = zenity.Warning(
				fmt.Sprintf("Auto-start install failed:\n%v\n\nThe exe is configured but won't launch automatically until you set up a Task Scheduler entry manually.", instErr),
				zenity.Title("kiosk-exit-guard"),
			)
		} else {
			_ = zenity.Info(
				"Setup complete.\n\nA scheduled task named \""+taskName+"\" will launch kiosk-exit-guard at every user logon.\n\nUse Ctrl+Shift+Alt+K to toggle filter mode.\nFilter mode starts OFF.",
				zenity.Title("kiosk-exit-guard"),
			)
		}
	}
	storedHash = hash

	// Restore persisted state.
	filterMode.Store(loadFilterModeFromDisk())
	if pu := loadPauseFromDisk(); !pu.IsZero() {
		if time.Now().Before(pu) {
			pauseUntilNano.Store(pu.UnixNano())
			schedulePauseExpiry(time.Until(pu))
		} else {
			// Stored pause already expired during downtime — fire the
			// auto-re-enable path so registry + state line up.
			autoReenableFilterMode()
		}
	}
	if filterMode.Load() {
		applyLockdown()
	}
	defer removeLockdown()
	defer cancelPauseExpiry()

	// Start the Chrome kiosk watchdog. It checks filterMode + pause state
	// on every tick so it only acts when filter mode is actually engaged.
	go runWatchdog(loadKioskURL())

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

	var m msgT
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
	}
}
