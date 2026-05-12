# Architecture

A single-binary kiosk lockdown utility. One ~7.7 MB `kiosk-exit-guard.exe` selects one of several internal modes based on its first command-line argument.

## Modes

| Mode | How it's invoked | What it does |
|---|---|---|
| **Controller** | no args (Task Scheduler at logon, or first manual launch) | Owns the LL keyboard hook, filter-mode state, registry lockdown, and supervises the kiosk window. Long-running. |
| **`--webview`** | spawned by the controller's watchdog | Renders the fullscreen WebView2 kiosk window. Dies when filter mode becomes paused. |
| **`--silent-exit`** | invoked by Windows when a blocked exe is launched (IFEO Debugger redirect) | Immediately returns. Used so `chrome.exe` / `msedge.exe` launches fail silently. |
| **`--pause`** | "Pause SK Filter" desktop button | Password modal + duration picker, writes pause state, kills the kiosk child. |
| **`--resume`** | "Resume SK Filter" desktop button | Clears the pause file, re-applies lockdown. No password (resuming is the safe direction). |
| **`--update`** | "Update SK Filter" desktop button | Checks GitHub `/releases/latest`, password-prompts, downloads to TEMP, atomic-renames the running exe. |
| **`--uninstall`** | "Uninstall SK Filter" desktop button | Password + confirm dialog, then full teardown of every piece of state. |
| **`--set-password`** | manual CLI | Re-runs the password prompt. |
| **`--set-url`** | manual CLI | Re-runs the kiosk URL prompt. |
| **`--reset`** | manual CLI (recovery) | Password-gated nuke of registry policies + IFEO blocks + filter state. |

## State surface

### HKLM (per-machine, admin-write)

```
HKLM\Software\KioskExitGuard
  ├── PasswordHash  (REG_BINARY, bcrypt hash of the admin password)
  └── KioskURL      (REG_SZ, URL the WebView2 kiosk loads)
```

### HKCU policies applied while filter is active

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System
  └── DisableTaskMgr      = 1   (Task Manager refuses to launch)

HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer
  ├── NoRun               = 1   (Win+R / Start → Run refuses to open)
  ├── NoTrayContextMenu   = 1   (right-click on the taskbar)
  └── NoViewContextMenu   = 1   (right-click on the desktop)
```

All four values are removed during a pause and re-applied when the pause ends.

### HKLM IFEO redirects (permanent across pause)

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\chrome.exe
  └── Debugger = "C:\Path\To\kiosk-exit-guard.exe" --silent-exit

HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msedge.exe
  └── Debugger = "C:\Path\To\kiosk-exit-guard.exe" --silent-exit
```

When anyone tries to launch chrome.exe or msedge.exe, Windows runs the Debugger value instead with the target's path appended. Our exe sees `--silent-exit`, exits immediately, and the launch fails. **Removed during a pause** (Edge becomes launchable) and re-applied at pause end.

### Files next to the exe

```
C:\Program Files\KioskExitGuard\
  ├── kiosk-exit-guard.exe
  ├── filter_mode.state        (0/1, persisted filter active flag)
  └── pause_until.state        (unix nano timestamp of when pause ends)
```

Legacy `password.hash` and `kiosk.url` files are migrated to HKLM on first launch of v0.5.0+, then removed.

### Task Scheduler

```
Task: KioskExitGuard
  Trigger:  At log on of any user
  Action:   Run C:\Program Files\KioskExitGuard\kiosk-exit-guard.exe
  Run as:   Highest privileges (no UAC prompt at logon)
```

### Desktop shortcuts

| Name | Argument | Password? |
|---|---|---|
| Pause SK Filter.lnk | `--pause` | required |
| Resume SK Filter.lnk | `--resume` | none |
| Update SK Filter.lnk | `--update` | required for install |
| Uninstall SK Filter.lnk | `--uninstall` | required + confirm |

## Threads, goroutines, processes

The controller process has these concurrent units:

| Unit | Where | What |
|---|---|---|
| Main message loop | main goroutine | Win32 `GetMessageW` loop that dispatches the LL keyboard hook callbacks. Lifetime = the process. |
| Hook callback | dispatched by message loop | Inspects every keystroke. May spawn `go promptAnd*()` goroutines for password modals. |
| Watchdog | goroutine, 30 s tick | When filter is active and not paused, ensures the `--webview` child is running. Spawns one if not. |
| Sync loop | goroutine, 2 s tick | Reconciles in-memory `filterMode` and pause state with the on-disk `pause_until.state` file. Picks up changes made by separate `--pause` / `--resume` processes. |
| Pause expiry timer | goroutine, fires once | `time.AfterFunc` set when a pause begins. Calls `autoReenableFilterMode()` when the duration elapses. |
| Password modal lifecycle | goroutine per modal | `webview2.New()` + `Run()` blocks the goroutine. Topmost-application runs in a sub-goroutine that polls `Window()` and applies the frameless+topmost style the moment the HWND is valid. |

## Flow: pressing a blocked combo

```
user presses Win+R
        │
        ▼
LL keyboard hook callback
  ├── injected event? → skip (lets re-injected events through)
  ├── kiosk marker?   → skip (our own re-injection)
  ├── Ctrl+Shift+Alt+K? → spawn promptAndPause goroutine, return 1
  ├── Win key alone tracking (down/up)
  ├── isAlwaysAllowedCombo (Ctrl+R / F5)? → fall through, allow
  └── any other non-modifier + (Ctrl|Win|Alt) → capture combo, spawn
                                                promptAndReinject, return 1
        │
        ▼
promptAndReinject goroutine
        │
        ├── askPasswordModal()  ── opens WebView2 frameless+topmost
        │       │                  modal, autofocus, waits for kgSubmit
        │       ▼
        │   bcrypt.CompareHashAndPassword
        │       │
        │       ├── wrong → showFailedToast(), return
        │       └── correct → sendKeyCombo(captured modifiers, captured vk)
        │                       │
        │                       ▼
        │                  SendInput with kioskMarkerCode in ExtraInfo
        │                       │
        │                       ▼
        │                  Hook callback fires again
        │                       │  (sees marker, lets through)
        │                       ▼
        │                  Win+R reaches Explorer → Run dialog opens
        ▼
done
```

## Flow: pausing the SK Filter

There are two equivalent entry points — the in-controller `Ctrl+Shift+Alt+K` hotkey, and the "Pause SK Filter" desktop shortcut which launches a fresh `--pause` process. Both converge on the same modal + duration picker, then either tear down state directly (the `--pause` process) or do it inline (the controller's `promptAndPause`).

When the `--pause` process tears down state, the running controller picks it up through the **sync loop** (2 s polling): the controller sees that the on-disk pause file is set but its in-memory `filterMode` is still true, calls the same teardown code, and brings its in-memory state into agreement.

```
press hotkey or click "Pause SK Filter"
        │
        ▼
password modal → duration picker (1/5/10/20/30/45/custom 1-100)
        │
        ▼
setPauseUntil(now + d)         (writes pause_until.state)
filterMode.Store(false)
removeLockdown()               (clears HKCU policies)
removeIFEOBlock("chrome.exe")  (lifts launch block)
removeIFEOBlock("msedge.exe")  (Edge can now be opened)
killWebViewChild()             (closes the kiosk window)
schedulePauseExpiry(d)         (time.AfterFunc starts the resume timer)
        │
        ▼
timer fires after d minutes
        │
        ▼
autoReenableFilterMode()
  ├── filterMode.Store(true)
  ├── setPauseUntil(zero)
  ├── applyLockdown()
  ├── applyBrowserBlocks()
  └── watchdogTick() → relaunches WebView2 kiosk child
```

## Flow: first run

```
double-click kiosk-exit-guard.exe (UAC consent)
        │
        ▼
controller mode (no args)
        │
        ├── --silent-exit? --webview? --pause? etc. → handle and exit
        │
        ▼
killRunningController()        (kill any zombie controller from prior install)
ensureWebView2Installed()      (download evergreen bootstrapper if missing)
loadHash()                     → empty → first-run branch
        │
        ▼
purgeLeftoverState()           (wipe HKLM, HKCU, IFEO, scheduled task,
                                desktop shortcuts, state files — guarantees
                                a clean baseline regardless of previous state)
        │
        ▼
runFirstRunWizard()            (WebView2 page collects password + URL)
        │
        ▼
saveHashToRegistry()           (bcrypt hash → HKLM\Software\KioskExitGuard)
saveKioskURLToRegistry()       (URL → same HKLM key)
uninstallChrome()              (silently runs Chrome's own uninstaller)
applyBrowserBlocks()           (sets chrome.exe + msedge.exe IFEO Debugger)
createDesktopShortcut()        (4 .lnk files: pause/resume/update/uninstall)
installStartupTask()           (registers KioskExitGuard scheduled task)
        │
        ▼
applyLockdown()
applyBrowserBlocks()
filterMode.Store(true)
go runWatchdog()
go syncFilterStateLoop()
        │
        ▼
SetWindowsHookExW(WH_KEYBOARD_LL, hookCallback)
        │
        ▼
Win32 message loop (controller is now running steady-state)
```

## Why WebView2 instead of Chrome

Earlier versions launched `chrome.exe --kiosk` as a child process. v0.4.0 switched to embedded WebView2 because:

1. **No Chrome dependency.** We uninstall Chrome during first-run and IFEO-block both browsers. WebView2 Runtime is a Windows component (Edge ships it; available on Server SKUs via separate install).
2. **We own the window.** WebView2 is in our process; we control creation flags, can apply `WS_POPUP|WS_VISIBLE` styles directly, can lock navigation via `Init` JS, and `Window()` returns the HWND for `SetWindowLongPtrW` tricks.
3. **Same rendering engine.** WebView2 is Chromium — same Blink renderer, same V8, same security model. The kiosk page sees no behavioral difference.

The exe is still ~7 MB because the WebView2 Runtime is provided by Windows; we just link the bindings.

## Why "default-ON, pause-only" instead of "toggle ON/OFF"

Earlier 0.5.0 had a true toggle: hotkey flipped `filterMode` from ON to OFF and back. That meant a malicious or coerced admin could turn the filter off "for now" and forget. In a kiosk context that's the same as turning it off forever.

v0.5.1+ enforces that **every relaxation of the filter has an expiry**. The user must pick how long they want the kiosk down, and after that time the system snaps back to fully locked without their involvement. There's no path that leaves it unlocked indefinitely.
