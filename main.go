//go:build windows && amd64

// kiosk-exit-guard intercepts Alt+F4 system-wide and only allows the keypress
// to reach the foreground window after the user enters the configured password.
// Wrong password = key is silently swallowed.
//
// Usage:
//
//	kiosk-exit-guard.exe --set-password   # one-time setup: prompts and writes password.hash
//	kiosk-exit-guard.exe                  # normal run: installs hook, sits in background
//
// Both password.hash and the exe should live in a directory the kiosk user
// has read but not write access to (e.g. C:\Program Files\KioskExitGuard\).
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/ncruces/zenity"
	"golang.org/x/crypto/bcrypt"
)

const (
	whKeyboardLL = 13
	wmKeyDown    = 0x0100
	wmSysKeyDown = 0x0104
	wmClose      = 0x0010
	vkF4         = 0x73
	vkLMenu      = 0xA4
	vkRMenu      = 0xA5
	llkhfInject  = 0x10
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
)

func hashPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(exe), "password.hash"), nil
}

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
		"Set the kiosk-exit password.\nKeep this secret — anyone with it can dismiss the kiosk.",
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
	if err := os.WriteFile(p, hash, 0o600); err != nil {
		return err
	}
	_ = zenity.Info(
		"Password saved.\n\nNow restart kiosk-exit-guard without the --set-password flag for normal operation.",
		zenity.Title("kiosk-exit-guard"),
	)
	return nil
}

func altDown() bool {
	l, _, _ := procGetAsyncKeyState.Call(uintptr(vkLMenu))
	r, _, _ := procGetAsyncKeyState.Call(uintptr(vkRMenu))
	return (uint16(l)&0x8000) != 0 || (uint16(r)&0x8000) != 0
}

func hookCallback(nCode int32, wParam uintptr, lParam uintptr) uintptr {
	if nCode >= 0 && (wParam == wmKeyDown || wParam == wmSysKeyDown) {
		kb := (*kbdLLHookStruct)(unsafe.Pointer(lParam))
		injected := (kb.Flags & llkhfInject) != 0
		if !injected && kb.VkCode == vkF4 && altDown() {
			if !promptOpen.Load() {
				go promptAndMaybeExit()
			}
			return 1 // swallow the Alt+F4
		}
	}
	ret, _, _ := procCallNextHookEx.Call(0, uintptr(nCode), wParam, lParam)
	return ret
}

func promptAndMaybeExit() {
	if !promptOpen.CompareAndSwap(false, true) {
		return
	}
	defer promptOpen.Store(false)

	// Capture the window that had focus before our dialog steals it.
	hwnd, _, _ := procGetForegroundWindow.Call()

	pw, err := zenity.Entry(
		"Enter password to exit kiosk.",
		zenity.Title("kiosk-exit-guard"),
		zenity.HideText(),
	)
	if err != nil {
		// User cancelled or dialog failed — treat as wrong password.
		return
	}
	if bcrypt.CompareHashAndPassword(storedHash, []byte(pw)) != nil {
		return
	}
	// Password matched. Politely ask the previously-focused window to close.
	procPostMessageW.Call(hwnd, uintptr(wmClose), 0, 0)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--set-password" {
		if err := setPassword(); err != nil {
			_ = zenity.Error(err.Error(), zenity.Title("kiosk-exit-guard"))
			os.Exit(1)
		}
		return
	}

	hash, err := loadHash()
	if err != nil || len(hash) == 0 {
		_ = zenity.Error(
			"password.hash not found next to the exe.\n\nRun kiosk-exit-guard.exe --set-password first.",
			zenity.Title("kiosk-exit-guard"),
		)
		os.Exit(1)
	}
	storedHash = hash

	cb := syscall.NewCallback(hookCallback)
	h, _, callErr := procSetWindowsHookExW.Call(uintptr(whKeyboardLL), cb, 0, 0)
	if h == 0 {
		_ = zenity.Error(
			fmt.Sprintf("SetWindowsHookEx failed: %v", callErr),
			zenity.Title("kiosk-exit-guard"),
		)
		os.Exit(1)
	}
	defer procUnhookWindowsHookEx.Call(h)

	// Win32 message loop on the main thread — required for LL hooks to dispatch.
	var m msgT
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
	}
}
