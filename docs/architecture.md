# Architecture

A single-binary kiosk lockdown utility targeting **Windows 11 Home** (no Assigned Access) and **Windows Server 2022 (RDP or physical console)**. One ~7.9 MB `kiosk-exit-guard.exe` selects one of several internal modes based on its first command-line argument.

The binary plays two long-lived roles per device:

- A **supervising Windows Service** (`KioskExitGuardSvc`) running as `LocalSystem` in Session 0. It has no UI (Services have been isolated from user sessions since Vista); its only job is to find the active user session and spawn the controller into it via `CreateProcessAsUserW`. The kiosk user can't reach SCM without admin rights, so they can't stop the supervisor.
- A **user-session controller** spawned by the Service into the user session. Owns the LL keyboard hook, filter-mode state, registry lockdown, and supervises the WebView2 kiosk child.

A second auto-start path — an AtLogon scheduled task — is co-installed alongside the Service as belt-and-suspenders backup for installs where the Service spawn path fails outright (e.g. `WTSQueryUserToken` returning `ERROR_NO_TOKEN` and the user-session-process fallback finding no candidate). A `Global\KioskExitGuardControllerRunning` named mutex keeps exactly one controller alive when both auto-start paths fire at logon.

## Picking the right session

`pickActiveUserSession()` in `service_windows.go` runs at the top of every supervisor iteration:

1. `WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, ...)` — enumerate every session on the box.
2. For each session where `State == WTSActive`, call `WTSQuerySessionInformationW(sessionID, WTSUserName)`. A session with an empty username is sitting at the logon dialog; skip it.
3. Prefer the console session (`WTSGetActiveConsoleSessionId()`) if it's active AND has a user — that's the Win11 laptop / physical-console case. Otherwise pick the lowest-numbered other `WTSActive` session with a user — that's the headless-RDP Server 2022 case.
4. Free the session list and each `WTSUserName` buffer via `WTSFreeMemory`.
5. Return `(0, false)` if no usable session is found; the supervisor sleeps `svcNoSessionDelay` (2 s) and retries.

On the chosen session, `spawnControllerInSession`:

1. Tries `WTSQueryUserToken(sessionID)` first — the documented Win32 path. Works on most installs.
2. Falls back to enumerating user-session processes via `WTSEnumerateProcessesExW` from `wtsapi32.dll` and stealing one's primary token. Candidate list: `explorer.exe` (preferred), `sihost.exe`, `taskhostw.exe`, `RuntimeBroker.exe`, `StartMenuExperienceHost.exe`. Each candidate is authenticated against its canonical `%SystemRoot%` path via `QueryFullProcessImageName` on the kernel handle (closes the renamed-binary impersonation and the PID-recycle race).
3. UAC-on admin users: if the token is the limited half of a split token (`TokenElevationType == Limited`), unwrap to the linked elevated token via `GetTokenInformation(TokenLinkedToken)`. The controller needs admin to write HKLM, set IFEO debugger keys, and restart Explorer.
4. `DuplicateTokenEx` to a primary token, `CreateEnvironmentBlock` for the per-user env, then `CreateProcessAsUserW` with `lpDesktop = "winsta0\default"` so the controller can show its modals.

The Service's environment block passes `KIOSK_EXIT_GUARD_VIA_SERVICE=1` so the controller knows it was spawned by the Service. If the controller boots that way with no password configured, it logs and exits immediately rather than popping the first-run wizard (which would respawn-loop on every Service cycle). That env-var marker is a hint only — `isLaunchedByService` authenticates the parent via parent-PID image-path lookup (`CreateToolhelp32Snapshot` + `QueryFullProcessImageName` against `%SystemRoot%\System32\services.exe`).

## Modes

| Mode | How it's invoked | What it does |
|---|---|---|
| **`--service-run`** | SCM only — never run by hand | Supervising Windows Service. Finds the active user session via `pickActiveUserSession()`, gets the user token (`WTSQueryUserToken` with `WTSEnumerateProcessesExW` user-session-process fallback), spawns the controller via `CreateProcessAsUserW`. Respawns on controller exit. On `sc stop` it `TerminateProcess`-es the controller. |
| **Controller** | no args — spawned by the Service into the user session, or first manual launch by the admin | Owns the LL keyboard hook, filter-mode state, registry lockdown, and supervises the kiosk window. Long-running. |
| **`--webview`** | spawned by the controller's watchdog | Renders the fullscreen WebView2 kiosk window. Dies when filter mode becomes paused. |
| **`--ask-password`** | spawned by `askPasswordModal` (any caller) | Child-process password modal. Renders the branded WebView2 dialog with a 30 s inactivity timeout, validates the entered password against the HKLM bcrypt hash, exits 0/1/2 = OK/Wrong/Cancel. Required because `go-webview2` panics on the second `NewWithOptions` per process — keeping the modal in a child guarantees the controller's WebView2 budget stays at 1 (the first-run wizard or kiosk window). |
| **`--show-toast`** | spawned by `showTimedInfo` (any caller) | Child-process toast renderer. Renders the branded toast for the given milliseconds, then exits. Same WebView2-isolation rationale as `--ask-password`. |
| **`--service-install`** | first-run setup (admin) | Registers `KioskExitGuardSvc` with SCM, starts it. |
| **`--service-remove`** | `--uninstall` (admin) | Stops and unregisters the Service. |
| **`--silent-exit`** | invoked by Windows when a blocked exe is launched (IFEO Debugger redirect) | Immediately returns. Used so `chrome.exe` / `msedge.exe` / accessibility-helper launches fail silently. |
| **`--pause`** | "Pause SK Filter" desktop button | Password modal + duration picker. Writes `pause-just-applied.flag` and the pause file, kills the kiosk child. |
| **`--resume`** | "Resume SK Filter" desktop button | Clears the pause file, re-applies lockdown. No password (resuming is the safe direction). |
| **`--launch-kiosk`** | "Launch Kiosk" desktop shortcut (legacy v1.0.3+) | Manually respawns the WebView2 kiosk child. Refuses during a pause so it can't silently defeat pause semantics. |
| **`--update`** | "Update SK Filter" desktop button | Fetches GitHub `/releases/latest`, password-prompts (combined confirm + auth modal as of v1.1.11), stops the Service (waits for `svc.Stopped`), SHA-256-verifies the downloaded exe, atomic-renames the running exe, starts the Service. |
| **`--uninstall`** | "Uninstall SK Filter" desktop button | Password + confirm dialog, then full teardown of every piece of state including the Service. |
| **`--set-password`** | manual CLI | Re-runs the password prompt. |
| **`--set-url`** | manual CLI | Re-runs the kiosk URL prompt. |
| **`--reset`** | manual CLI (recovery) | Password-gated nuke of registry policies + IFEO blocks + filter state. HKLM config + the Service / task survive — so the next controller launch starts up clean with the same password. |

## State surface

### HKLM (per-machine, admin-write, DACL tightened to SYSTEM + Administrators)

```
HKLM\Software\KioskExitGuard
  ├── PasswordHash  (REG_BINARY, bcrypt hash of the admin password)
  └── KioskURL      (REG_SZ, URL the WebView2 kiosk loads)
```

`tightenHKLMConfigDACL()` runs on every controller startup, applying `SetNamedSecurityInfo(SE_REGISTRY_KEY, SDDL=D:PAI(A;CI;KA;;;SY)(A;CI;KA;;;BA))`. Protected (no inherit from `HKLM\Software` so the default `BUILTIN\Users:KEY_READ` ACE doesn't leak in); SYSTEM + Administrators full control with container-inherit.

### HKCU policies applied while filter is active

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System
  └── DisableTaskMgr      = 1   (Task Manager refuses to launch)

HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer
  ├── NoRun               = 1   (Win+R / Start → Run refuses to open)
  ├── NoTrayContextMenu   = 1   (right-click on the taskbar)
  ├── NoViewContextMenu   = 1   (right-click on the desktop)
  └── NoTaskbar           = 1   (taskbar hidden — closes the Start-button left-click escape)
```

All five values are removed during a pause and re-applied when the pause ends.

### HKLM IFEO redirects (permanent across pause for accessibility helpers; lifted on browsers during pause)

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
  ├── chrome.exe\Debugger    = "<exe>" --silent-exit   (lifted during pause)
  ├── msedge.exe\Debugger    = "<exe>" --silent-exit   (lifted during pause)
  ├── sethc.exe\Debugger     = "<exe>" --silent-exit   (always)
  ├── osk.exe\Debugger       = "<exe>" --silent-exit   (always)
  ├── narrator.exe\Debugger  = "<exe>" --silent-exit   (always)
  ├── utilman.exe\Debugger   = "<exe>" --silent-exit   (always)
  └── magnify.exe\Debugger   = "<exe>" --silent-exit   (always)
```

When anyone tries to launch one of these exes, Windows runs the Debugger value instead with the target's path appended. Our exe sees `--silent-exit`, exits immediately, and the launch fails. The accessibility-helper blocks close Sticky-Keys-5x-Shift, Narrator, and Ease-of-Access escapes; they stay applied during a pause (a paused kiosk shouldn't suddenly let `osk.exe` open). The browser blocks lift during a pause so Edge is usable.

### Files

```
%ProgramFiles%\KioskExitGuard\
  ├── kiosk-exit-guard.exe
  ├── kiosk-exit-guard.exe.old     (rollback target after --update)
  ├── kiosk-exit-guard.log         (5 MB rotation to .log.old)
  ├── filter_mode.state            (0/1, persisted filter active flag)
  └── pause_until.state            (unix nano timestamp of when pause ends)

%ProgramData%\KioskExitGuard\      (DACL: SYSTEM + Administrators only, via icacls)
  ├── staging\                     (--update download target before atomic rename)
  ├── WebView2\                    (shared user-data folder for all in-process WebView2)
  └── pause-just-applied.flag      (short-lived: suppresses controller watchdog for 5 s after pause)
```

Legacy `password.hash` and `kiosk.url` files from the v0.x line are migrated to HKLM on first launch of v0.5.0+, then removed.

### Windows Service

```
Service:        KioskExitGuardSvc
Display name:   Kiosk Exit Guard Service
Description:    Watches and respawns the kiosk-exit-guard user-session controller.
Binary path:    "C:\Program Files\KioskExitGuard\kiosk-exit-guard.exe" --service-run
StartType:      Automatic
ServiceType:    SERVICE_WIN32_OWN_PROCESS
Account:        LocalSystem (required for SE_TCB_NAME / WTSQueryUserToken)
```

Verify with `Get-Service KioskExitGuardSvc` or `sc query KioskExitGuardSvc`. Stop / start with `sc stop KioskExitGuardSvc` / `sc start KioskExitGuardSvc` from an admin shell. The Service can't be stopped or deleted by a non-admin user.

### AtLogon scheduled task (belt-and-suspenders fallback)

```
Task: KioskExitGuard
  Trigger:  At log on of any user (single trigger, no repetition)
  Action:   Run C:\Program Files\KioskExitGuard\kiosk-exit-guard.exe
  Run as:   Highest privileges (no UAC prompt at logon)
```

Co-installed with the Service as of v1.1.4. Verify with `Get-ScheduledTask -TaskName KioskExitGuard`. The `killRunningController()` + `Global\KioskExitGuardControllerRunning` mutex pair keeps exactly one controller alive when both auto-start mechanisms fire at logon.

### Desktop shortcuts

| Name | Argument | Password? |
|---|---|---|
| Pause SK Filter.lnk | `--pause` | required |
| Resume SK Filter.lnk | `--resume` | none |
| Update SK Filter.lnk | `--update` | required for install |
| Uninstall SK Filter.lnk | `--uninstall` | required + confirm |

## Processes

| Process | Where it runs | Lifetime |
|---|---|---|
| `kiosk-exit-guard.exe --service-run` | Session 0, `LocalSystem` | Auto-started at boot by SCM. Lives until `sc stop` or shutdown. |
| `kiosk-exit-guard.exe` (controller, no args) | active user session, spawned by the Service via `CreateProcessAsUserW` | Lives until killed; respawned by the Service within ~1 s. |
| `kiosk-exit-guard.exe --webview` | same user session, spawned by the controller's watchdog | Lives while the kiosk should be visible. Killed during pause. |
| `kiosk-exit-guard.exe --ask-password` / `--show-toast` | same user session, spawned by any caller | Short-lived per-modal / per-toast child. |

## Threads, goroutines, processes

The controller process has these concurrent units:

| Unit | Where | What |
|---|---|---|
| Main message loop | main goroutine | Win32 `GetMessageW` loop that dispatches the LL keyboard hook callbacks. `runtime.LockOSThread()` pins this to the hook install thread (otherwise the runtime would migrate the goroutine after `firstRunWithWizard`'s WebView2 message loop and the hook would silently go dead). Lifetime = the process. |
| Hook callback | dispatched by message loop | Inspects every keystroke. Captures modifier state synchronously at the moment the blocked event fires (re-injection uses press-time modifiers, not modal-time). Atomic CAS on the in-flight prompt flag so a rapid second blocked combo can't race past the first. Spawns `go promptAnd*()` goroutines for password modals. |
| Watchdog | goroutine, 30 s tick | When filter is active and not paused, ensures the `--webview` child is running. Spawns one if not. Skips relaunch when `pause-just-applied.flag` is still in the future (avoids a race with `--pause` killing the kiosk just before the 2 s sync loop sees the new pause file). |
| Sync loop | goroutine, 2 s tick | Reconciles in-memory `filterMode` and pause state with the on-disk `pause_until.state` file. Picks up changes made by separate `--pause` / `--resume` processes. |
| Pause expiry timer | goroutine, fires once | `time.AfterFunc` set when a pause begins. Calls `autoReenableFilterMode()` when the duration elapses. |
| Password modal lifecycle | child process | The controller spawns `kiosk-exit-guard.exe --ask-password` and reads its exit code. The child runs its own WebView2 message loop (its first and only instance), and `forceForeground()` uses the `AttachThreadInput` idiom to grab keyboard focus on top of the fullscreen kiosk. |

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
  ├── isAlwaysAllowedCombo (Ctrl+R / F5 / Ctrl+0 / Ctrl+- / Ctrl++)? → fall through
  └── any other non-modifier + (Ctrl|Win|Alt) → capture combo, spawn
                                                promptAndReinject, return 1
        │
        ▼
promptAndReinject goroutine
        │
        ├── askPasswordModal()  ── spawns --ask-password child process
        │       │                  (child renders WebView2 frameless+topmost
        │       │                   modal, autofocus, attach-thread-input
        │       │                   foreground steal, 30s inactivity timeout)
        │       ▼
        │   bcrypt.CompareHashAndPassword (in the child)
        │       │
        │       ├── wrong → child exits 1 → parent calls showFailedToast() → return
        │       └── correct → child exits 0 → parent calls sendKeyCombo(captured modifiers, captured vk)
        │                       │
        │                       ▼
        │                  SendInput with random per-process nonce in ExtraInfo
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

Two equivalent entry points — the in-controller `Ctrl+Shift+Alt+K` hotkey, and the "Pause SK Filter" desktop shortcut which launches a fresh `--pause` process. Both converge on the same modal + duration picker, then either tear down state directly (the `--pause` process) or do it inline (the controller's `promptAndPause`).

When the `--pause` process tears down state, the running controller picks it up through the **sync loop** (2 s polling): the controller sees that the on-disk pause file is set but its in-memory `filterMode` is still true, calls the same teardown code, and brings its in-memory state into agreement.

```
press hotkey or click "Pause SK Filter"
        │
        ▼
password modal → kill kiosk WebView2 child → duration picker (1/5/10/20/30/45/custom 1-100)
        │                                    (kiosk killed first so the native
        │                                     zenity.List dialog gets foreground)
        ▼
writePauseJustAppliedMarker(5s)  (suppresses controller watchdog for the
                                  race window before sync loop catches up)
setPauseUntil(now + d)           (writes pause_until.state)
filterMode.Store(false)
removeLockdown()                 (clears HKCU policies)
removeIFEOBlock("chrome.exe")    (lifts launch block)
removeIFEOBlock("msedge.exe")    (Edge can now be opened)
schedulePauseExpiry(d)           (time.AfterFunc starts the resume timer)
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
relocateToProgramFilesIfNeeded()   (copy + re-exec into
                                    %ProgramFiles%\KioskExitGuard\ if launched
                                    from anywhere else; this becomes the
                                    SCM-registered binary path)
        │
        ▼
controller mode (no args)
        │
        ├── --silent-exit / --webview / --pause / etc. → handle and exit
        │
        ▼
SetWindowsHookExW(WH_KEYBOARD_LL, hookCallback)  (installed BEFORE the kill so the
                                                   gap between killing the old controller
                                                   and installing the new hook is closed)
killRunningController()            (kill any zombie controller from prior install)
ensureWebView2Installed()          (download evergreen bootstrapper if missing)
loadHash()                         → empty → first-run branch
        │
        ▼
purgeLeftoverState()               (wipe HKLM, HKCU, IFEO, scheduled task,
                                    desktop shortcuts, state files — clean slate)
        │
        ▼
runFirstRunWizard()                (WebView2 page collects password + URL)
        │
        ▼
saveHashToRegistry()               (bcrypt hash → HKLM, with DACL tightening)
saveKioskURLToRegistry()
uninstallChrome()                  (silently runs Chrome's own uninstaller;
                                    logs "Chrome not installed, skipping" on fresh Server 2022)
applyBrowserBlocks()               (sets chrome.exe + msedge.exe + a11y helper IFEO Debugger)
createDesktopShortcut()            (4 .lnk files: pause/resume/update/uninstall)
ensureAdminOnlyDir(programDataDir())  (DACL-tightens %ProgramData%\KioskExitGuard)
installService() + installStartupTask()  (co-installed; one combined status
                                          dialog reports svcErr + taskErr)
        │
        ▼
applyLockdown()
applyBrowserBlocks()
filterMode.Store(true)
go runWatchdog()
go syncFilterStateLoop()
        │
        ▼
Win32 message loop (controller is now running steady-state)
```

## Why WebView2 instead of Chrome

Earlier versions launched `chrome.exe --kiosk` as a child process. v0.4.0 switched to embedded WebView2 because:

1. **No Chrome dependency.** We uninstall Chrome during first-run and IFEO-block both browsers. WebView2 Runtime is a Windows component (Edge ships it; available on Server SKUs via separate install).
2. **We own the window.** WebView2 is in our process; we control creation flags, can apply `WS_POPUP|WS_VISIBLE` styles directly, can lock navigation via `Init` JS, and `Window()` returns the HWND for `SetWindowLongPtrW` tricks.
3. **Same rendering engine.** WebView2 is Chromium — same Blink renderer, same V8, same security model. The kiosk page sees no behavioral difference.

The exe is ~7.9 MB because the WebView2 Runtime is provided by Windows; we just link the bindings.

## Why "default-ON, pause-only" instead of "toggle ON/OFF"

Earlier 0.5.0 had a true toggle: hotkey flipped `filterMode` from ON to OFF and back. That meant a malicious or coerced admin could turn the filter off "for now" and forget. In a kiosk context that's the same as turning it off forever.

v0.5.1+ enforces that **every relaxation of the filter has an expiry**. The user must pick how long they want the kiosk down, and after that time the system snaps back to fully locked without their involvement. There's no path that leaves it unlocked indefinitely.

## Version evolution

The architecture described above is the steady state as of v1.1.11. The major shifts that got it there:

- **v0.1.0 – v0.4.0.** Single controller process, `chrome.exe --kiosk` child, Task Scheduler watchdog (every 1 minute) as the auto-start. Bcrypt password hash next to the exe.
- **v0.4.0.** Replaced the Chrome subprocess with embedded WebView2 (`go-webview2`). Same exe re-launches itself with `--webview` for the kiosk window. Chrome uninstalled at first run; chrome.exe and msedge.exe IFEO-blocked.
- **v0.5.x.** HKLM password storage replacing the on-disk hash file. Branded WebView2 first-run wizard and password modal. Four desktop shortcuts (pause / resume / update / uninstall), all UAC-elevated. Default-ON pause-only model: no "turn off" path, only time-bounded pauses that auto-resume.
- **v1.0.x.** Production-readiness audit pass. Random per-process re-injection nonce (replaces fixed `0xC0DE`). Accessibility-helper IFEO blocks. `NoTaskbar` HKCU policy. Atomic CAS on the in-flight prompt flag. Per-monitor-v2 DPI awareness. Log file + panic recovery. Cross-process modal serialization via named mutex.
- **v1.1.0.** Service migration. New `KioskExitGuardSvc` running as `LocalSystem` in Session 0 replaces the Task Scheduler watchdog. Kiosk users can't reach SCM, so they can't stop the supervisor. Two-process model: same exe, flag selects role. `runtime.LockOSThread()` at the top of `main()` to pin the LL-hook install thread.
- **v1.1.1 – v1.1.3.** Stabilization burst around `go-webview2`'s second-instance panic. All toasts and password modals routed through fresh child processes so the controller's WebView2 budget stays at 1. `WTSQueryUserToken` `ERROR_NO_TOKEN` fallback added (steal `explorer.exe`'s token + unwrap to the linked elevated half).
- **v1.1.4.** Belt-and-suspenders auto-start: Service + AtLogon scheduled task co-installed. Per-minute task watchdog removed (the Service is the in-session supervisor; keeping both watchdogs caused kill/respawn churn). `killRunningController()` keeps exactly one controller alive regardless of which mechanism fires.
- **v1.1.5 – v1.1.7.** Zoom shortcuts allowed through the LL hook. Password modal foreground / focus fix via `AttachThreadInput`. Kiosk killed before the pause-duration picker so the native zenity dialog gets foreground.
- **v1.1.8.** Security audit. Exe relocates to `%ProgramFiles%` at first run. `--update` stages in admin-only `%ProgramData%` and SHA-256-verifies. Explorer-token fallback authenticates by image path. WebView2 profile moved to admin-only `%ProgramData%\WebView2\`. HKLM hash key DACL-tightened. LL hook installed earlier in `main()`. PowerShell `installStartupTask` hardened. `isLaunchedByService` authenticates via parent-PID lookup.
- **v1.1.9.** UX audit. Password modal 30 s inactivity timeout. Controller mutex closes the logon-time kiosk blink. Panic recovery toast. Combined first-run status dialog. Pause-shortcut watchdog suppression marker. `--update` polls SCM until `svc.Stopped`. Synchronous toasts at exit-after-failure call sites.
- **v1.1.10.** Cross-session process enumeration rewritten from `gopsutil` (which returned empty when called from Session 0 on some installs) to `WTSEnumerateProcessesExW`. Candidate list broadened beyond `explorer.exe` for custom-shell setups. Two cosmetic log-noise cleanups.
- **v1.1.11.** Server 2022 RDP support. `pickActiveUserSession()` walks `WTSEnumerateSessionsW` to find the right session instead of hardcoding `WTSGetActiveConsoleSessionId()` — which on a headless RDP'd server returns the empty physical-console session ID 1. `restartExplorer` defensive shell check. IFEO removal absorbs "not installed". `--update` UI simplified to one combined confirm + auth screen.
