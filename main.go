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

// ---------- constants ----------

const (
	whKeyboardLL = 13
	wmKeyDown    = 0x0100
	wmSysKeyDown = 0x0104
	wmClose      = 0x0010

	vkF4     = 0x73
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
	regDisableTaskMgr = "DisableTaskMgr"
	regNoRun          = "NoRun"

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
	procShowWindow          = user32.NewProc("ShowWindow")

	storedHash []byte
	promptOpen atomic.Bool
	filterMode atomic.Bool

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
}

func removeLockdown() {
	_ = deletePolicyValue(regPolicySystem, regDisableTaskMgr)
	_ = deletePolicyValue(regPolicyExplorer, regNoRun)
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

func autoReenableFilterMode() {
	if filterMode.Load() {
		return
	}
	filterMode.Store(true)
	saveFilterModeToDisk(true)
	setPauseUntil(time.Time{})
	applyLockdown()
	watchdogTick()
	showTimedInfo("Pause expired.\nFilter mode is back ON.")
}

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
		return 0, true
	}
	return 5 * time.Minute, true
}

// ---------- hook callback ----------

func hookCallback(nCode int32, wParam uintptr, lParam uintptr) uintptr {
	if nCode >= 0 && (wParam == wmKeyDown || wParam == wmSysKeyDown) {
		kb := (*kbdLLHookStruct)(unsafe.Pointer(lParam))
		injected := (kb.Flags & llkhfInject) != 0
		if !injected {
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
		setPauseUntil(time.Time{})
		cancelPauseExpiry()
	}
	filterMode.Store(newState)
	saveFilterModeToDisk(newState)
	if newState {
		applyLockdown()
		watchdogTick()
		showTimedInfo("Filter mode ON.\nKiosk window will launch.\nTask Manager, Run dialog, and escape shortcuts are blocked.")
	} else {
		removeLockdown()
		killWebViewChild()
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
		if !askPassword("Enter password to clear lockdown and reset filter mode.") {
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

	hash, err := loadHash()
	firstRun := err != nil || len(hash) == 0
	if firstRun {
		_ = zenity.Info(
			"First run.\n\nWe'll:\n  1. Set an admin password\n  2. Set the kiosk URL\n  3. Uninstall Chrome (if present)\n  4. Block Chrome and Edge launches via Image File Execution Options\n  5. Register a startup task",
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
				fmt.Sprintf("Kiosk URL not saved: %v\nFalling back to default. Change later with --set-url.", perr),
				zenity.Title("kiosk-exit-guard"),
			)
		}
		_ = uninstallChrome()
		applyBrowserBlocks()
		if instErr := installStartupTask(); instErr != nil {
			_ = zenity.Warning(
				fmt.Sprintf("Auto-start install failed: %v\nThe exe is configured but won't launch automatically until you create a Task Scheduler entry manually.", instErr),
				zenity.Title("kiosk-exit-guard"),
			)
		} else {
			_ = zenity.Info(
				"Setup complete.\n\nChrome uninstalled.\nChrome and Edge launches are blocked at the OS level.\nScheduled task \""+taskName+"\" launches kiosk-exit-guard at every user logon.\n\nUse Ctrl+Shift+Alt+K to toggle filter mode.\nFilter mode starts OFF.",
				zenity.Title("kiosk-exit-guard"),
			)
		}
	} else {
		// Make sure IFEO blocks survive — re-apply on every launch in case
		// they were somehow cleared (e.g. by a Windows feature update).
		applyBrowserBlocks()
	}
	storedHash = hash

	filterMode.Store(loadFilterModeFromDisk())
	if pu := loadPauseFromDisk(); !pu.IsZero() {
		if time.Now().Before(pu) {
			pauseUntilNano.Store(pu.UnixNano())
			schedulePauseExpiry(time.Until(pu))
		} else {
			autoReenableFilterMode()
		}
	}
	if filterMode.Load() {
		applyLockdown()
	}
	defer removeLockdown()
	defer cancelPauseExpiry()
	defer killWebViewChild()

	go runWatchdog()

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
