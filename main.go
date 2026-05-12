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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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
	"golang.org/x/sys/windows/registry"
)

// currentVersion must be kept in sync with versioninfo.json. Used by the
// --update flow to compare against the latest GitHub release tag.
const currentVersion = "1.0.1"

// ---------- constants ----------

const (
	whKeyboardLL = 13
	wmKeyDown    = 0x0100
	wmKeyUp      = 0x0101
	wmSysKeyDown = 0x0104
	wmSysKeyUp   = 0x0105
	wmClose      = 0x0010

	vkF4     = 0x73
	vkF5     = 0x74
	vkR      = 0x52
	vkK      = 0x4B
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

	regAppKey    = `Software\KioskExitGuard`
	regHashValue = "PasswordHash"
	regURLValue  = "KioskURL"

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
	user32 = syscall.NewLazyDLL("user32.dll")

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
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	procBringWindowToTop    = user32.NewProc("BringWindowToTop")

	storedHash []byte
	promptOpen atomic.Bool
	filterMode atomic.Bool

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
	return k.SetBinaryValue(regHashValue, hash)
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

func promptForKioskURL() (string, error) {
	current := loadKioskURL()
	url, err := zenity.Entry(
		"Enter the kiosk URL.\nThis is the page WebView2 will open in fullscreen.",
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
	// and pick "Close Window", bypassing our Alt+F4 password gate. Same
	// menu also exposes Task Manager from some shells.
	_ = setPolicyDWORD(regPolicyExplorer, regNoTrayContextMenu, 1)
	_ = setPolicyDWORD(regPolicyExplorer, regNoViewContextMenu, 1)
}

func removeLockdown() {
	_ = deletePolicyValue(regPolicySystem, regDisableTaskMgr)
	_ = deletePolicyValue(regPolicyExplorer, regNoRun)
	_ = deletePolicyValue(regPolicyExplorer, regNoTrayContextMenu)
	_ = deletePolicyValue(regPolicyExplorer, regNoViewContextMenu)
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
		return
	}
	defer k.Close()
	_ = k.DeleteValue("Debugger")
}

func applyBrowserBlocks() {
	_ = setIFEOBlock("chrome.exe")
	_ = setIFEOBlock("msedge.exe")
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
		cmd := exec.Command("cmd", "/C", uninstallStr+" --force-uninstall --do-not-launch-chrome")
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
		if err := cmd.Run(); err == nil {
			return nil
		}
	}
	return nil // not found is fine
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

func isModifierVK(vk uint32) bool {
	switch vk {
	case vkLCtrl, vkRCtrl, vkLMenu, vkRMenu, vkLWin, vkRWin, vkLShift, vkRShift:
		return true
	}
	return false
}

// isAlwaysAllowedCombo lets specific keystrokes through even when the
// filter is active. Today: Ctrl+R and F5 are reload shortcuts the kiosk
// page should respect (admin can refresh the display without entering
// the password). Add more here as legitimate kiosk use cases emerge.
func isAlwaysAllowedCombo(vk uint32) bool {
	if vk == vkF5 && !ctrlDown() && !altDown() && !winDown() {
		return true
	}
	if vk == vkR && ctrlDown() && !altDown() && !winDown() {
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
	// Replace the standard window style with WS_POPUP|WS_VISIBLE — no
	// title bar, no min/max/close buttons, no resize grips.
	procSetWindowLongPtrW.Call(hwnd, uintptr(gwlStyleU), uintptr(wsPopup|wsVisible))
	// Topmost + tool-window (also hides from taskbar and Alt+Tab).
	procSetWindowLongPtrW.Call(hwnd, uintptr(gwlExStyleU), uintptr(wsExTopmost|wsExToolWindow))
	// Force a frame change so the style strip is repainted.
	procSetWindowPos.Call(hwnd, hwndTopmost, 0, 0, 0, 0,
		uintptr(swpNoMove|swpNoSize|swpShow|swpFrameChang))
	procBringWindowToTop.Call(hwnd)
	procSetForegroundWindow.Call(hwnd)
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
	inputKeyboard   = 1
	keyeventfKeyUp  = 0x0002
	kioskMarkerCode = 0xC0DE
)

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
	k.ExtraInfo = uintptr(kioskMarkerCode)
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
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: false,
		WindowOptions: webview2.WindowOptions{
			Title:  "SK Filter",
			Width:  480,
			Height: 110,
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

func showTimedInfo(text string) {
	showFrontmostToast(text, toastTimeoutMs*time.Millisecond)
}

func showFailedToast() { showTimedInfo("Wrong password.") }

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

// ---------- desktop shortcut ----------

// createDesktopShortcut drops two .lnk files on the current user's desktop:
//   - "Kiosk Exit Guard.lnk" — runs the controller exe (rarely needed
//     since Task Scheduler launches it at logon, but useful as a fallback)
//   - "Pause SK Filter.lnk" — runs the exe with --pause, which opens the
//     password + duration prompt directly without going through the
//     Ctrl+Shift+Alt+K hotkey
//
// Idempotent: re-creating overwrites the existing shortcuts.
func createDesktopShortcut() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exeQ := strings.ReplaceAll(exe, `'`, `''`)
	workDir := strings.ReplaceAll(filepath.Dir(exe), `'`, `''`)
	ps := fmt.Sprintf(`
$ws = New-Object -ComObject WScript.Shell
$desktop = [Environment]::GetFolderPath('Desktop')

$lnk1 = $ws.CreateShortcut(("$desktop\Pause SK Filter.lnk"))
$lnk1.TargetPath = '%s'
$lnk1.Arguments = '--pause'
$lnk1.WorkingDirectory = '%s'
$lnk1.IconLocation = ('%s' + ',0')
$lnk1.Description = 'Pause the SK Filter for a set time (password required)'
$lnk1.Save()

$lnk2 = $ws.CreateShortcut(("$desktop\Resume SK Filter.lnk"))
$lnk2.TargetPath = '%s'
$lnk2.Arguments = '--resume'
$lnk2.WorkingDirectory = '%s'
$lnk2.IconLocation = ('%s' + ',0')
$lnk2.Description = 'End the current pause and re-activate the SK Filter (no password needed)'
$lnk2.Save()

$lnk3 = $ws.CreateShortcut(("$desktop\Update SK Filter.lnk"))
$lnk3.TargetPath = '%s'
$lnk3.Arguments = '--update'
$lnk3.WorkingDirectory = '%s'
$lnk3.IconLocation = ('%s' + ',0')
$lnk3.Description = 'Check GitHub for a new version of the SK Filter (password required to install)'
$lnk3.Save()

$lnk4 = $ws.CreateShortcut(("$desktop\Uninstall SK Filter.lnk"))
$lnk4.TargetPath = '%s'
$lnk4.Arguments = '--uninstall'
$lnk4.WorkingDirectory = '%s'
$lnk4.IconLocation = ('%s' + ',0')
$lnk4.Description = 'Remove the SK Filter (password required)'
$lnk4.Save()
`, exeQ, workDir, exeQ, exeQ, workDir, exeQ, exeQ, workDir, exeQ, exeQ, workDir, exeQ)
	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps)
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
    line-height: 1.55; height: 100vh; overflow: hidden; -webkit-font-smoothing: antialiased; }
  .wrap { height: 100vh; display: flex; align-items: center; justify-content: center; padding: 1.5rem; }
  .card { background: linear-gradient(180deg, #232f48, #1a2438);
    border: 1px solid rgba(148, 163, 184, 0.22); border-radius: 16px;
    padding: 2.25rem 2.5rem; width: 520px; max-width: 100%;
    box-shadow: 0 20px 60px rgba(0,0,0,0.45); }
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

    <div class="error" id="error"></div>

    <div class="actions">
      <button class="btn-secondary" onclick="cancel()">Cancel</button>
      <button class="btn-primary" id="submit" onclick="submit()">Continue</button>
    </div>
  </div>
</div>

<script>
  document.getElementById('url').value = window.__defaultURL || 'https://skluach.pages.dev/CMH/';
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
    if (!pw1) { showErr('Password is required.'); return; }
    if (pw1 !== pw2) { showErr('Passwords do not match.'); return; }
    if (!url) { showErr('Kiosk URL is required.'); return; }
    clearErr();
    var btn = document.getElementById('submit');
    btn.disabled = true;
    btn.textContent = 'Saving…';
    window.kgSubmit(pw1, url);
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
	ok       bool
}

// runFirstRunWizard opens a branded WebView2 window with the first-run
// setup form. Blocks until the user clicks Continue (or closes the window).
// Returns the entered password + URL, or ok=false if the window was closed
// without submitting.
func runFirstRunWizard() *firstRunInput {
	result := &firstRunInput{}
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title:  "kiosk-exit-guard — first run",
			Width:  620,
			Height: 680,
			Center: true,
		},
	})
	if w == nil {
		return nil // caller falls back to zenity
	}
	defer w.Destroy()

	w.Bind("kgSubmit", func(pw, url string) {
		result.password = pw
		result.url = strings.TrimSpace(url)
		result.ok = true
		w.Terminate()
	})
	w.Bind("kgCancel", func() {
		w.Terminate()
	})

	// Inject the default URL via a window-level global before the page
	// runs so the input's value is correct on first paint.
	w.Init(fmt.Sprintf(`window.__defaultURL = %q;`, loadKioskURL()))
	w.SetHtml(firstRunHTML)
	go func() {
		time.Sleep(220 * time.Millisecond)
		h := uintptr(w.Window())
		if h != 0 {
			// First-run wizard runs before any kiosk window exists, so a
			// plain topmost is fine — no need to strip the frame.
			makeWindowTopmostFront(h)
		}
	}()
	w.Run()
	return result
}

// firstRunWithWizard runs the full first-run sequence using the WebView2
// wizard for password + URL, then performs the system-setup steps
// (Chrome uninstall, IFEO blocks, Task Scheduler, desktop shortcut).
// Returns whether setup completed cleanly.
func firstRunWithWizard() bool {
	input := runFirstRunWizard()
	if input == nil || !input.ok {
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

	_ = uninstallChrome()
	applyBrowserBlocks()
	_ = createDesktopShortcut()

	taskErr := installStartupTask()
	if taskErr != nil {
		_ = zenity.Warning(
			fmt.Sprintf("Auto-start install failed: %v\n\nThe exe is configured but won't launch automatically until you create a Task Scheduler entry manually.", taskErr),
			zenity.Title("kiosk-exit-guard"),
		)
	}
	_ = zenity.Info(
		"Setup complete.\n\n• Password and kiosk URL saved\n• Chrome uninstalled\n• Chrome and Edge launches blocked\n• Desktop shortcut created\n• Auto-start task installed\n\nThe SK Filter is ON by default and will start enforcing immediately.\nUse Ctrl+Shift+Alt+K to pause it for 1–100 minutes when needed.",
		zenity.Title("kiosk-exit-guard"),
	)
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
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
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
		})();
	`, url))

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

func watchdogTick() {
	if filterMode.Load() && !isPaused() {
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

func hookCallback(nCode int32, wParam uintptr, lParam uintptr) uintptr {
	if nCode >= 0 {
		kb := (*kbdLLHookStruct)(unsafe.Pointer(lParam))
		injected := (kb.Flags & llkhfInject) != 0
		ourInjection := kb.DwExtraInfo == uintptr(kioskMarkerCode)
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
					if wasAlone && !promptOpen.Load() {
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
					// Allowlist (Ctrl+R, F5) before the broad block.
					if isAlwaysAllowedCombo(kb.VkCode) {
						// fall through to procCallNextHookEx
					} else if !isModifierVK(kb.VkCode) && (ctrlDown() || winDown() || altDown()) {
						if !promptOpen.Load() {
							pendingComboMu.Lock()
							pendingComboV = &pendingCombo{
								vk:        kb.VkCode,
								modifiers: capturedModifiers(),
							}
							pendingComboMu.Unlock()
							go promptAndReinject()
						}
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
    height: 100vh; -webkit-font-smoothing: antialiased; overflow: hidden; }
  .wrap { height: 100vh; display: flex; align-items: center; justify-content: center; padding: 1.25rem; }
  .card { background: linear-gradient(180deg, rgba(35, 47, 72, 0.95), rgba(26, 36, 56, 0.95));
    border: 1px solid rgba(148, 163, 184, 0.22); border-radius: 16px;
    padding: 2rem 2.25rem; width: 100%;
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
</script>
</body></html>`

// askPasswordModal shows a branded, autofocused WebView2 password dialog.
// Returns (ok=true) only if the user entered a password that matches the
// stored bcrypt hash.
func askPasswordModal(title, subtitle string) bool {
	if !promptOpen.CompareAndSwap(false, true) {
		return false
	}
	defer promptOpen.Store(false)

	var (
		entered string
		ok      bool
	)

	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title:  "SK Filter — password required",
			Width:  520,
			Height: 360,
			Center: true,
		},
	})
	if w == nil {
		// WebView2 unavailable — fall back to zenity so the prompt still
		// works on stripped-down machines that haven't auto-installed it.
		pw, err := zenity.Entry(title+"\n"+subtitle,
			zenity.Title("SK Filter"), zenity.HideText())
		if err != nil {
			return false
		}
		return bcrypt.CompareHashAndPassword(storedHash, []byte(pw)) == nil
	}
	defer w.Destroy()

	w.Bind("kgSubmit", func(pw string) {
		entered = pw
		ok = true
		w.Terminate()
	})
	w.Bind("kgCancel", func() {
		w.Terminate()
	})

	w.Init(fmt.Sprintf(`window.__title = %q; window.__subtitle = %q;`, title, subtitle))
	w.SetHtml(passwordPromptHTML)
	// Tight HWND poll — apply frameless + topmost the instant the
	// WebView2 has a valid HWND. Single application (no retry storm
	// that hangs the message pump), but fast detection so the modal is
	// never visible behind the kiosk window.
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
	w.Run()

	if !ok {
		return false
	}
	return bcrypt.CompareHashAndPassword(storedHash, []byte(entered)) == nil
}

// Backwards-compatible alias used by the toggle and reset paths.
func askPassword(label string) bool {
	// Split the label on the first newline into title + subtitle for the
	// modal layout. Callers like "Enter password to exit kiosk." pass a
	// single line.
	return askPasswordModal(label, "")
}

// promptAndReinject is the goroutine kicked off when the hook captures a
// blocked combo. Verifies the password, then re-injects the original key
// combo so the user's intended action goes through.
func promptAndReinject() {
	pendingComboMu.Lock()
	pc := pendingComboV
	pendingComboMu.Unlock()
	if pc == nil {
		return
	}

	verified := askPasswordModal(
		"This command has been locked by the SK Filter",
		"Please enter your password to continue. The keystroke will go through once you unlock.",
	)

	// Clear the pending combo regardless of outcome.
	pendingComboMu.Lock()
	pendingComboV = nil
	pendingComboMu.Unlock()

	if !verified {
		showFailedToast()
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

	if !askPasswordModal(
		"Pause the SK Filter?",
		"Edge will be allowed and the kiosk will close for the duration you choose. The filter resumes automatically when the timer ends.",
	) {
		showFailedToast()
		return
	}
	dur, accepted := askPauseDuration()
	if !accepted {
		return
	}
	if dur <= 0 {
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
	killWebViewChild()

	showTimedInfo(fmt.Sprintf(
		"SK Filter paused.\nEdge is allowed; kiosk closed.\nResumes at %s.",
		time.Unix(0, pauseUntilNano.Load()).Format("3:04 PM"),
	))
}

// ---------- desktop button handlers ----------

// runResumeInvocation is the entry point for `kiosk-exit-guard.exe --resume`,
// wired to the "Resume SK Filter" desktop shortcut. Ending a pause early
// makes the system more locked-down, not less, so this is intentionally
// NOT password-gated — anyone can resume. Pausing still needs the
// password.
func runResumeInvocation() {
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

	if !askPasswordModal(
		"Uninstall the SK Filter?",
		"You will be asked to confirm. After this completes, the kiosk-exit-guard.exe binary remains on disk — delete it manually if you want full removal.",
	) {
		showFailedToast()
		os.Exit(1)
	}
	if err := zenity.Question(
		"Are you sure?\n\nThis removes:\n  • Chrome / Edge IFEO blocks\n  • Task Manager / Run dialog policies\n  • Stored password and kiosk URL\n  • Scheduled task\n  • Desktop shortcuts\n\nThe SK Filter will no longer enforce anything after this.",
		zenity.Title("SK Filter — Uninstall"),
		zenity.OKLabel("Uninstall"),
		zenity.CancelLabel("Keep installed"),
	); err != nil {
		// User clicked Cancel / closed.
		return
	}

	// Tear down everything we put in place.
	removeLockdown()
	removeIFEOBlock("chrome.exe")
	removeIFEOBlock("msedge.exe")
	if p := findOurWebViewChild(); p != nil {
		_ = p.Kill()
	}
	// Wipe HKLM key (values + key itself).
	if k, oErr := registry.OpenKey(registry.LOCAL_MACHINE, regAppKey, registry.ALL_ACCESS); oErr == nil {
		_ = k.DeleteValue(regHashValue)
		_ = k.DeleteValue(regURLValue)
		k.Close()
	}
	_ = registry.DeleteKey(registry.LOCAL_MACHINE, regAppKey)
	// Scheduled task.
	cmd := exec.Command("schtasks", "/Delete", "/F", "/TN", taskName)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	_ = cmd.Run()
	// State files next to exe.
	for _, fn := range []string{stateFileName, pauseFileName, hashFileName, kioskURLFileName} {
		if p, err := nextToExe(fn); err == nil {
			_ = os.Remove(p)
		}
	}
	// Desktop shortcuts.
	removeDesktopShortcuts()

	// Find and kill the running controller process. Without this, the
	// in-memory storedHash + filterMode survive the uninstall and the
	// controller keeps enforcing the filter from cached state.
	killRunningController()

	_ = zenity.Info(
		"SK Filter uninstalled.\n\nDelete kiosk-exit-guard.exe manually to complete removal.\nYou may want to reinstall Chrome from google.com/chrome if you use it.",
		zenity.Title("SK Filter"),
	)
}

// purgeLeftoverState wipes anything a prior install (or partial uninstall)
// might have left behind. Called at the start of first-run so the user
// gets a truly clean install regardless of what state the box is in
// (zombie controller, dangling scheduled task, stale IFEO blocks,
// half-deleted desktop shortcuts, etc.).
func purgeLeftoverState() {
	killRunningController()
	removeLockdown()
	removeIFEOBlock("chrome.exe")
	removeIFEOBlock("msedge.exe")

	cmd := exec.Command("schtasks", "/Delete", "/F", "/TN", taskName)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	_ = cmd.Run()

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

// fetchLatestRelease returns (versionString, downloadURL, error). The
// version is the tag with any leading "v" stripped so it lines up with
// the embedded currentVersion constant.
func fetchLatestRelease() (string, string, error) {
	req, err := http.NewRequest("GET", githubLatestAPI, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "kiosk-exit-guard-updater")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("github api returned %d", resp.StatusCode)
	}
	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", "", err
	}
	for _, a := range rel.Assets {
		if strings.EqualFold(a.Name, "kiosk-exit-guard.exe") {
			return strings.TrimPrefix(rel.TagName, "v"), a.DownloadURL, nil
		}
	}
	return "", "", errors.New("kiosk-exit-guard.exe asset not found in latest release")
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
	migrateLegacyHash()
	hash, err := loadHash()
	if err != nil || len(hash) == 0 {
		_ = zenity.Error("SK Filter is not configured. Run first-run setup first.", zenity.Title("SK Filter"))
		os.Exit(1)
	}
	storedHash = hash

	showTimedInfo("Checking GitHub for updates…")

	latest, downloadURL, err := fetchLatestRelease()
	if err != nil {
		_ = zenity.Error(
			fmt.Sprintf("Could not reach GitHub:\n%v\n\nMake sure the device has internet access.", err),
			zenity.Title("SK Filter — update"),
		)
		return
	}

	if latest == currentVersion {
		_ = zenity.Info(
			fmt.Sprintf("You're on the latest version (v%s).\n\nNo update needed.", currentVersion),
			zenity.Title("SK Filter — update"),
		)
		return
	}

	if qerr := zenity.Question(
		fmt.Sprintf(
			"A new version is available.\n\nCurrent: v%s\nLatest:  v%s\n\nDownload and install?",
			currentVersion, latest,
		),
		zenity.Title("SK Filter — update available"),
		zenity.OKLabel("Update now"),
		zenity.CancelLabel("Maybe later"),
	); qerr != nil {
		return
	}

	if !askPasswordModal(
		"Install the update?",
		fmt.Sprintf("Replacing the running kiosk-exit-guard.exe with v%s. Enter your admin password to confirm.", latest),
	) {
		showFailedToast()
		return
	}

	tmpPath := filepath.Join(os.TempDir(), "kiosk-exit-guard.new.exe")
	if err := downloadFile(downloadURL, tmpPath); err != nil {
		_ = zenity.Error(fmt.Sprintf("Download failed: %v", err), zenity.Title("SK Filter — update"))
		return
	}

	exe, err := os.Executable()
	if err != nil {
		_ = zenity.Error(fmt.Sprintf("Could not locate current exe: %v", err), zenity.Title("SK Filter — update"))
		return
	}
	oldPath := exe + ".old"
	_ = os.Remove(oldPath) // clean any leftover
	if err := os.Rename(exe, oldPath); err != nil {
		_ = zenity.Error(
			fmt.Sprintf("Could not move current exe aside:\n%v\n\nThe running controller may be holding the file. Try again in a moment.", err),
			zenity.Title("SK Filter — update"),
		)
		return
	}
	if err := os.Rename(tmpPath, exe); err != nil {
		// Rollback: put the old exe back where it was.
		_ = os.Rename(oldPath, exe)
		_ = zenity.Error(fmt.Sprintf("Install failed: %v\n\nReverted to previous version.", err), zenity.Title("SK Filter — update"))
		return
	}

	// Restart the scheduled task so the new exe loads. /End kills the
	// running controller; /Run launches a fresh instance from the new
	// binary at the same path.
	for _, op := range [][]string{{"/End", "/TN", taskName}, {"/Run", "/TN", taskName}} {
		cmd := exec.Command("schtasks", op...)
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
		_ = cmd.Run()
		time.Sleep(400 * time.Millisecond)
	}

	_ = zenity.Info(
		fmt.Sprintf("Updated to v%s.\n\nSK Filter reloaded automatically.\nThe previous version was saved as kiosk-exit-guard.exe.old next to the new exe.", latest),
		zenity.Title("SK Filter — update complete"),
	)
}

func removeDesktopShortcuts() {
	ps := `
$desktop = [Environment]::GetFolderPath('Desktop')
foreach ($n in @('Kiosk Exit Guard.lnk','Pause SK Filter.lnk','Resume SK Filter.lnk','Update SK Filter.lnk','Uninstall SK Filter.lnk')) {
    Remove-Item -Path (Join-Path $desktop $n) -Force -ErrorAction SilentlyContinue
}
`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	_ = cmd.Run()
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

	if !askPasswordModal(
		"Pause the SK Filter?",
		"Edge will be allowed and the kiosk will close for the duration you choose. The filter resumes automatically when the timer ends.",
	) {
		showFailedToast()
		os.Exit(1)
	}
	dur, accepted := askPauseDuration()
	if !accepted || dur <= 0 {
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

	// Kill the kiosk WebView2 child if it's running.
	if p := findOurWebViewChild(); p != nil {
		_ = p.Kill()
	}

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
		case !paused && !filterMode.Load():
			// Pause window ended (timer fired in another process, or the
			// file was manually cleared). Bring the lockdown back.
			autoReenableFilterMode()
		}
	}
}

// ---------- main ----------

func main() {
	// IFEO redirect handler: if Windows invoked us as the Debugger for a
	// blocked exe, we get --silent-exit as argv[1] and the blocked exe's
	// path appended. Exit silently so the user's launch attempt just
	// fails with no error window.
	if len(os.Args) > 1 && os.Args[1] == "--silent-exit" {
		return
	}

	// WebView2 child mode — render the kiosk window and exit when closed.
	if len(os.Args) > 1 && os.Args[1] == "--webview" {
		runWebViewKiosk(loadKioskURL())
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
		if !askPasswordModal(
			"Reset SK Filter",
			"Enter your password to clear the registry lockdown, the Chrome/Edge IFEO blocks, and the filter-mode state.",
		) {
			showFailedToast()
			os.Exit(1)
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
		if _, err := promptForKioskURL(); err != nil {
			_ = zenity.Error(err.Error(), zenity.Title("kiosk-exit-guard"))
			os.Exit(1)
		}
		_ = zenity.Info("Kiosk URL updated.", zenity.Title("kiosk-exit-guard"))
		return
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

	// If there's a leftover controller from a previous install still
	// running (orphaned by a partial uninstall, an aborted update, etc.),
	// kill it before we start. Otherwise two controllers fight over the
	// hook and the new install's password doesn't match the old one's
	// in-memory cached hash.
	killRunningController()

	hash, err := loadHash()
	firstRun := err != nil || len(hash) == 0
	if firstRun {
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
		// Desktop shortcut is cheap to re-create; silently overwrites if
		// it already exists. (IFEO blocks are reapplied below in the
		// state-restoration step instead of here so they get cleared
		// correctly during a paused state.)
		_ = createDesktopShortcut()
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

	go runWatchdog()
	go syncFilterStateLoop()

	cb := syscall.NewCallback(hookCallback)
	h, _, callErr := procSetWindowHookExW.Call(uintptr(whKeyboardLL), cb, 0, 0)
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
