# Changelog

All notable changes to kiosk-exit-guard, newest first. Versions follow [Semantic Versioning](https://semver.org/) with the convention that 1.0.x is the stable line and 0.x was prototyping.

For the current state of the project, see the [landing page](https://shalom-karr.github.io/kiosk-exit-guard/), the [architecture doc](architecture.md), and the [admin runbook](admin-runbook.md).

## v1.1.6 — 2026-05-12

**Password modal now actually comes to front + gets keyboard focus on the fullscreen kiosk.** User report: "pressing Ctrl+Shift+Alt+K while on the [kiosk] full screen needs to move the modal to the front to pause the filter."

Root cause: both the kiosk WebView2 window and the password modal child process are `HWND_TOPMOST`. The modal's z-order beat the kiosk visually because of `SetWindowPos(HWND_TOPMOST)` ordering, but **keyboard focus** stayed with the kiosk because the modal child process never called `SetForegroundWindow` — and even if it had, Windows would have rejected the call (only the current foreground process can grant foreground to another). So the user saw the modal but typing the password went to the kiosk page.

The v1.0.3 fix had deliberately stripped `SetForegroundWindow` + `BringWindowToTop` because the combination caused modal hangs on Server SKUs. v1.1.6 brings them back via the **AttachThreadInput idiom** which bypasses the eligibility check without the hang risk: temporarily merge the modal thread's input queue with the foreground thread's queue, call `SetForegroundWindow` (Windows now treats them as the same process for foreground-grant purposes), then detach. `forceForeground()` in `main.go` does this; `makeModalFullscreenTopmost` calls it at the end so every fullscreen modal (password modal + first-run wizard) grabs focus on top of whatever was there before. The detach happens in `defer` so a panic during the steal can't leak the input attach.

## v1.1.5 — 2026-05-12

**Browser zoom shortcuts allowed through.** `Ctrl+0` (zoom reset), `Ctrl+-` (zoom out), and `Ctrl++` / `Ctrl+=` (zoom in) now pass through the LL hook to the kiosk WebView2 page instead of triggering the password modal. Numpad equivalents (`Ctrl+Numpad0`, `Ctrl+Subtract`, `Ctrl+Add`) are also allowed. All variants still require Ctrl-only — `Win+0`, `Alt+-`, etc. still hit the lockdown path.

Joins the existing always-allowed list: `F5` and `Ctrl+R` (page reload). `isAlwaysAllowedCombo` (`main.go`) restructured to share the Ctrl-without-Alt-or-Win precondition across all zoom + reload combos.

## v1.1.4 — 2026-05-12

**Belt-and-suspenders auto-start: Service AND scheduled task co-installed.**

Field report: "right now the filter only runs when I re-click the exe file from the downloads folder" — even after v1.1.3's explorer-token fallback shipped, the auto-start was still flaky on the affected machine. v1.1.0 had aggressively switched to Service-only and deleted any leftover v1.0.x scheduled task on install. That made the kiosk completely unprotected after reboot whenever the Service spawn path failed.

Fix: install BOTH the Windows Service and the scheduled task at first-run and on every non-service-spawn launch. Whichever auto-start mechanism fires first wins; `killRunningController()` at controller startup guarantees only one controller process runs at a time. Concrete changes:

- `firstRunWithWizard` now calls `installStartupTask()` *in addition to* `installService()` (not "if service install failed" — always).
- `installService` no longer deletes the scheduled task. v1.1.0–v1.1.3 wiped it to prevent two controllers fighting; v1.1.4 trusts `killRunningController()` to keep things sane.
- Non-first-run launches refresh BOTH managers.
- Scheduled task is now AtLogon-only (no every-minute repetition that v1.0.x used). The Service is the in-session respawn supervisor; the task is purely a logon-time fallback for installs where the Service spawn path fails. Dropping the per-minute watchdog avoids kill/respawn churn between the two auto-start mechanisms.
- If both auto-start installs fail, surface a loud `zenity.Error` so the admin can't silently end up with a kiosk that doesn't reboot-survive.

Threat-model note: the scheduled task is technically weaker than the Service (a kiosk user with admin privileges could `schtasks /Delete` it). On a non-admin kiosk user account the task is admin-only to delete, same as the Service. "Weaker auto-start that works" beats "stronger auto-start that doesn't fire" — the failure mode in the field was zero protection after reboot, which is the worst outcome.

## v1.1.3 — 2026-05-12

**Two critical bugs the v1.1.0–v1.1.2 line missed.** Reported from production logs.

### Bug A — controller crashed on first Win/Ctrl/Alt press

User-visible: install fresh, press Win key once, get the password modal, and the kiosk is bypassed because the controller crashed half-way through the modal.

Same root cause as v1.1.1 and v1.1.2: `go-webview2` panics on the second `NewWithOptions` call per process (`chromium.go:131`). I fixed `showTimedInfo` in v1.1.2 but missed the bigger call site — `askPasswordModal`. The controller has already used WebView2 once during `firstRunWithWizard`. When the LL hook fires on the first key combo and calls `promptAndReinject` → `askPasswordModal`, that's the controller's second WebView2 → panic on the `time.AfterFunc` goroutine with no recover → controller dies → LL hook dies with it → user pressed past the kiosk while the modal was still drawing. Confirmed from logs:

```
[01:55:17.167] LL keyboard hook installed (handle=3277641)
… modal opens, panics at chromium.go:131 …
"i got a full screen option to close the filter and then it crashed and let me get passed it"
```

Fix: `askPasswordModal` now spawns `kiosk-exit-guard.exe --ask-password <title> <subtitle>` as a child process and reads its exit code (0=OK, 1=Wrong, 2=Cancel). The child's WebView2 is always its first instance, so the panic class is structurally eliminated. The in-process implementation is preserved as `askPasswordModalInProcess` and used only by the `--ask-password` flag handler. Every call site (`runPauseInvocation`, `runUpdateInvocation`, `runUninstallInvocation`, `runReset`, `runSetURL`, and most importantly the controller's LL-hook-callback path) goes through the child route automatically — no per-site changes needed.

### Bug B — service couldn't spawn its child controller (filter only ran when manually launched)

User-visible: "right now the filter only runs when I re-click the exe file from the downloads folder." After a reboot the kiosk had zero protection until the admin manually double-clicked the exe.

Root cause: `WTSQueryUserToken(activeConsoleSession)` returned `ERROR_NO_TOKEN` every 2 seconds for the entire session. The supervising Service's `spawnControllerInSession` couldn't get a primary token for the console user, so `CreateProcessAsUserW` never ran. v1.0.x's Task-Scheduler path (which would have worked) was removed in v1.1.0 in favor of the Service-only path, so when `WTSQueryUserToken` fails on a given install, there's no fallback. Documented Windows API but inconsistent on Win11 Home in the field. Confirmed from logs — same machine, every spawn attempt:

```
service: spawnControllerInSession(1) failed: WTSQueryUserToken(1):
  An attempt was made to reference a token that does not exist.
```

Fix: if `WTSQueryUserToken` fails, fall back to stealing `explorer.exe`'s primary token in the same session. `explorer.exe` is guaranteed to exist whenever a user has reached the desktop, and its token represents that user's identity. To handle UAC, `tokenFromExplorerInSession` then calls `GetTokenInformation(TokenElevationType)` to detect a split-token state; if it's Limited (UAC-on admin user with the unelevated half running explorer), it unwraps to the linked elevated token via `GetTokenInformation(TokenLinkedToken)`. The controller needs admin (HKLM writes, IFEO, Explorer restart) so the limited half is not usable.

The `WTSQueryUserToken` path is still tried first because it's the documented one and works on most installs. Only the failure path goes via explorer.exe-token.

## v1.1.2 — 2026-05-11

**Hook stayed dead after pause auto-expired — root cause of "Win key not blocked" reports.**

Symptom: user resumes (or pause auto-expires), shortcut says "SK Filter is already active", but the Windows key is no longer blocked.

Root cause: `showTimedInfo` in v1.1.0/v1.1.1 still rendered the toast in-process via `go-webview2`. The controller had already created one WebView2 instance during the first-run wizard. When `autoReenableFilterMode` fired at pause expiry, its `showTimedInfo("Pause ended. SK Filter is back on.")` was the second `NewWithOptions` call in the controller's lifetime — `go-webview2` panics on the second instance per process (`chromium.go:131`, the same root cause as v1.1.1's `--update` fix). The panic ran on the `time.AfterFunc` goroutine which has no recovery, so the controller process crashed. The supervising Service respawned it within ~1 second, but in that gap the LL keyboard hook was gone and the Win key fell through. Same path bit any flow that combined `askPasswordModal` with a follow-up `showFailedToast` (wrong-password feedback after the modal): pause shortcut, update shortcut, uninstall shortcut, set-URL shortcut, reset.

Fix: `showTimedInfo` now always spawns `kiosk-exit-guard.exe --show-toast <ms> <text>` as a fire-and-forget child process instead of instantiating WebView2 in the caller's process. The child's WebView2 is always its first (the child exits as soon as the toast dismisses). The caller process is left with its WebView2 budget intact for password modals, the kiosk window, the first-run wizard, etc. This generalizes the per-call workaround `runUpdateInvocation` carried in v1.1.1 — that manual `exec.Command` is removed in favor of the single shared path.

Concretely: this fixes the user-visible bug where after a pause expired (or after typing the wrong password into any modal), the controller's hook went dead and Win/Ctrl/Alt combos fell through to Explorer until the Service respawned the controller.

## v1.1.1 — 2026-05-11

**`--update` panic from go-webview2 double-instance.** The "Update SK Filter" shortcut launched a toast ("Checking GitHub for updates…") via in-process WebView2 and then opened the password modal as a second WebView2 in the same process. `go-webview2` panics on the second `NewWithOptions` call. Worked around in v1.1.1 by spawning the toast in a separate `--show-toast` child process; v1.1.2 generalizes this to every toast call site.

## v1.1.0 — 2026-05-11

**Windows Service supervisor + LL-hook thread-pinning fix.** Replaces the v1.0.x Task-Scheduler-based auto-start with a real Windows Service running as `LocalSystem` in Session 0. The kiosk user can no longer reach `schtasks /Delete` to neutralize the watchdog — Service control requires admin rights, which the kiosk user doesn't have.

Architecture:

- **New supervising Service `KioskExitGuardSvc`.** Display name "Kiosk Exit Guard Service". Runs as `LocalSystem`, `StartType = Automatic`. Has no UI of its own (Services run in Session 0, isolated from user sessions since Vista). Its only job is to find the active console session via `WTSGetActiveConsoleSessionId`, get the user's token via `WTSQueryUserToken`, duplicate it to a primary token via `DuplicateTokenEx`, build a per-user environment block via `CreateEnvironmentBlock`, and spawn `kiosk-exit-guard.exe` into that session via `CreateProcessAsUserW` with `lpDesktop = "winsta0\default"`. Waits for the controller to exit, sleeps 1s, respawns. On `sc stop` it terminates the running controller via `TerminateProcess` so an unattended controller can't outlive its supervisor.
- **Two-process model.** The Service is the supervisor; the existing controller code (LL hook, WebView2 kiosk, password modal, etc.) runs unchanged as the user-session process spawned by the Service. The same `kiosk-exit-guard.exe` binary is both — flag selects the role: `--service-run` (SCM-only), `--service-install` (admin), `--service-remove` (admin), no args = controller.
- **First-run integration.** `firstRunWithWizard()` now calls `installService()` instead of `installStartupTask()`. The Service is registered, started, and any leftover v1.0.x scheduled task is deleted in the same call so the two managers don't fight. If service install fails (locked-down SCM, unusual SKU), falls back to the v1.0.x scheduled-task path so the device isn't left without auto-start.
- **Uninstall integration.** `runUninstallInvocation` now stops and deletes the Service before tearing down everything else. Without this, the supervisor would respawn the controller mid-teardown.
- **First-run guard for service-spawned controllers.** The Service sets `KIOSK_EXIT_GUARD_VIA_SERVICE=1` in the spawned controller's environment block. If the controller boots and finds no password configured, it checks for that marker — if present, it logs and exits silently instead of popping the wizard. Prevents the Service from respawn-looping a stack of first-run wizards every few seconds on a half-installed device.
- **Update flow.** `--update` now does `sc stop KioskExitGuardSvc` before renaming the exe, and `sc start` after. Falls back to `schtasks /Run` if the service isn't registered (rare, mid-migration installs).

Reliability:

- **`runtime.LockOSThread()` at the top of `main()`** (v1.0.7 fix folded into this release). Pins the main goroutine to its initial OS thread for the life of the process. The Win32 LL keyboard hook installed via `SetWindowsHookExW` is bound to the thread that called it, and events only dispatch while THAT thread is running a `GetMessage` loop. If the Go runtime migrates this goroutine to a different OS thread between `SetWindowsHookExW` and `GetMessageW` (which happened reliably on first-run install because `firstRunWithWizard()` runs a WebView2 message loop that leaves the goroutine on a different thread), the hook silently goes dead — symptom: Ctrl/Win/Alt combos fall through instead of opening the password modal. Pinning at the top of `main()` keeps the hook's install thread and message-pump thread the same.

Caveats:

- The Service runs as `LocalSystem` because `WTSQueryUserToken` requires `SE_TCB_NAME`, which only `LocalSystem` has by default. Don't change `ServiceStartName` away from blank-(LocalSystem) without granting the new account that privilege.
- On boot before any user logs in, the supervisor finds `WTSGetActiveConsoleSessionId == 0xFFFFFFFF` and polls every 2 s. The controller doesn't start until a user is logged into the console — same behavior the user perceives as v1.0.x's logon trigger.

## v1.0.6 — 2026-05-12

**Production-readiness fixes from a multi-agent security and UX audit.**

Security:

- Per-process random re-injection nonce. The old `kioskMarkerCode = 0xC0DE` fixed constant meant any other process could call `SendInput` with that ExtraInfo value and bypass the LL keyboard hook. Replaced with a `uintptr` drawn from `crypto/rand` at controller startup and never written to the log file. Every process restart re-randomizes; no attacker-observable value.
- Taskbar hidden while the filter is active. `applyLockdown` now writes `NoTaskbar=1` under `HKCU\…\Policies\Explorer` and restarts Explorer so the change takes effect immediately. Closes the Start-button left-click escape — a user could previously click Start, then click the kiosk's taskbar entry to focus and close it.
- WebView2 kiosk hardening. Default context menus, dev tools (F12 / Ctrl+Shift+I), the status bar, and zoom controls are disabled via the WebView2 `Settings` object. `NewWindowRequested` is handled and rejected, so popups, target=_blank links, and `window.open` calls cannot spawn a second WebView2 window outside the kiosk. Closes the file-picker, dev-tools, and child-window escape paths.
- IFEO Debugger redirects extended to accessibility helpers. `sethc.exe`, `osk.exe`, `narrator.exe`, `utilman.exe`, and `magnify.exe` now redirect to `kiosk-exit-guard --silent-exit` alongside `chrome.exe` / `msedge.exe`. Closes the Sticky-Keys-five-shifts / Narrator / Ease-of-Access escape that ran an accessibility tool above the kiosk.
- Atomic CompareAndSwap on `promptOpen` inside `hookCallback`. The previous check-then-set was TOCTOU — a second blocked combo arriving while the first was still being dispatched to the goroutine could overwrite `pendingComboV` and re-inject the wrong keystroke after auth. The hook itself now owns the CAS so only one in-flight prompt can exist.
- Modifier snapshot captured inside `hookCallback` synchronously. `capturedModifiers()` used to be called by the goroutine after the 200+ ms WebView2 modal spawn delay; a user who released the modifiers in that window would re-inject a bare key on success. Captured at the moment the LL hook fires now, so re-injection always uses the modifier state at press time.

UX:

- Password modals now distinguish cancel from wrong-password. `askPasswordModal` returns a `passwordResult` enum (`pwOK` / `pwWrong` / `pwCancel`); every call site was rewritten so a user clicking Cancel no longer triggers the "Wrong password" toast. Cancelling the pause / update / uninstall / reset / set-url flows is now silent (the correct affordance) rather than shaming.
- Wrong-password retry happens inline inside the modal. Up to 3 attempts; the error appears in the modal's `#err` div (kept hidden until needed) with "N attempts left" feedback. Eliminates the cold-start delay of spawning a second WebView2 host just to render a "Wrong password" toast — the existing modal stays up and the input is re-focused and cleared.
- Cross-process modal serialization via a `Global\KioskExitGuardPromptMutex` named mutex. Previously, double-clicking the "Pause SK Filter" shortcut twice in quick succession opened two stacked fullscreen modals. The second `askPasswordModal` call now detects the existing owner, shows "Another SK Filter prompt is already open — finish that one first", and returns immediately.
- `--pause` shortcut now refuses to re-pause when a pause is already in flight. Previously it would silently overwrite a 100-minute pause with a fresh 5-minute one. Now shows the existing pause's remaining time and points the user at "Resume SK Filter" to end early.
- `--resume` shortcut shows a confirm dialog with the remaining pause time before clearing the pause. Prevents misclicks during long pause windows from snapping the kiosk back. Also no-ops with feedback if no pause is in flight.
- `sync` loop gained a third branch: if the on-disk pause deadline is rewritten while the controller is already paused (a future feature: extending a pause from another process), the controller re-arms its `time.AfterFunc` timer to the new deadline rather than auto-resuming early based on the old one.
- `--update` flow now stops the controller's scheduled task before attempting the exe rename. Previously the rename failed with "access is denied" because Windows held an exclusive lock on the running .exe, and the admin had no in-UI path forward. The update now: `schtasks /End` → `taskkill` → 500 ms settle → up-to-5 rename retries → `schtasks /Run`. On rename failure the controller is automatically restarted so the device isn't left unprotected.
- First-run wizard falls back to plain zenity dialogs when WebView2 creation fails. Previously a WebView2 crash on a stripped Windows image left the admin with no setup path and a silent `os.Exit(1)`.
- First-run wizard cancel/X-out now shows an explanatory dialog instead of a silent exit so the admin understands they need to re-launch.
- Chrome silent uninstall is now bounded by a 60s `context.WithTimeout`. Hung uninstallers no longer freeze first-run setup; the IFEO block is what actually prevents kiosk-escape via Chrome, so a leftover install is non-fatal.
- Kiosk URL prompt validates the scheme (`https://`, `http://`, `file:///`). Previously a typo like `htttp://example.com` saved silently and the WebView2 child showed a Chromium error page; the prompt now loops with a warning until the URL is valid.
- Uninstall reports failures in plain English mapped to remediation ("Open Task Scheduler and delete the task named …") instead of dumping raw `schtasks` output into a zenity dialog. Raw output is still written to `kiosk-exit-guard.log` for diagnosis.
- Pause-duration cancel now shows "Pause cancelled. SK Filter is still active." so a misclick is obvious instead of silent.
- Set-URL flow recognizes the zenity-cancel error and treats it as a clean exit rather than surfacing the raw "dialog cancelled" error message.

## v1.0.4 — 2026-05-11

**Logging + panic recovery.**

- Added `kiosk-exit-guard.log` next to the exe (append-only, naive 5 MB rotation to `.log.old`). Captures controller startup, hook installation, pause start/expire, errors. Initialized at the top of controller `main()`.
- `recoverAndLog()` deferred in the watchdog and sync-loop goroutines so a panic gets a full stack trace into the log file before the goroutine dies.
- `--silent-exit` skips log init to keep the IFEO redirect fast.

## v1.0.3 — 2026-05-11

**Modal hang fix, DPI awareness, multi-trigger task, two new desktop shortcuts.**

- Stripped `SetForegroundWindow` + `BringWindowToTop` from `makeModalFrameless`. They have eligibility rules (foreground lock, input focus thread) and were the primary cause of the "blank white page + Not Responding" hang on some builds. The remaining `SetWindowLong(WS_POPUP)` + `SetWindowLong(WS_EX_TOPMOST)` + `SetWindowPos(HWND_TOPMOST)` is enough to put the modal above the kiosk.
- Added per-monitor-v2 DPI awareness via `app.manifest`. `GetSystemMetrics(SM_CX/CYSCREEN)` now returns physical pixels on 4K displays instead of scaled values; kiosk window fills the native resolution.
- Replaced `schtasks /Create /SC ONLOGON` with PowerShell `Register-ScheduledTask`. New triggers: `AtLogOn` + every-1-minute watchdog. Settings: `MultipleInstances=IgnoreNew`, `ExecutionTimeLimit=0`, `RestartOnFailure` 3×1min, `AllowStartIfOnBatteries`, `StartWhenAvailable`. If the controller dies mid-session it comes back within 1 minute.
- Non-first-run launches now re-register the scheduled task too — existing installs auto-upgrade to the multi-trigger format just by launching the new exe.
- **"Launch Kiosk"** desktop shortcut + `--launch-kiosk` flag. Manually spawns the WebView2 child if the filter is active. Refuses during pause so it can't silently defeat pause semantics.
- **"Change Kiosk URL"** desktop shortcut + password-gated `--set-url`. After URL save, kills the kiosk child so the watchdog respawns at the new URL within seconds.

## v1.0.2 — 2026-05-11

**Robust uninstall + docs.**

- Uninstall flow rewritten to handle the "kiosk keeps coming back after uninstall" bug. Order reversed: kill processes first (gopsutil + taskkill belt-and-suspenders), then end+delete the scheduled task, then wipe registry / files / shortcuts. Errors are now collected and surfaced in the result dialog instead of silently discarded. Final step runs `schtasks /Query` to verify the task is actually gone.
- Added `docs/architecture.md` — full breakdown of modes, state surface (HKLM / HKCU / IFEO / files / task scheduler / shortcuts), goroutine model, and three main flows (blocked combo, pause, first-run).
- Added `docs/admin-runbook.md` — day-to-day tasks, verification PowerShell queries, recovery scenarios (lost password, `--reset`, kiosk keeps coming back, IFEO leftover, WebView2 install failed), upgrade paths.

## v1.0.1 — 2026-05-11

**Modals and toasts always frontmost.**

- Password modal topmost is now instant. v1.0.0 waited 220 ms before applying frameless+topmost — modal was visible behind the kiosk for that window on slow systems. Replaced with a 15 ms tight poll that applies the style the moment `Window()` returns a valid HWND. Same one-shot model (no retry storm).
- Toast notifications now use a custom WebView2 toast instead of zenity. zenity dialogs aren't topmost, so "Wrong password" and "Filter paused" toasts appeared behind the kiosk and were effectively invisible. New `showFrontmostToast()` uses the same dark-themed styling, applies `makeModalFrameless` via the same tight poll, and the page auto-closes itself after the requested duration. Falls back to zenity if WebView2 is unavailable.

## v1.0.0 — 2026-05-11

**Feature-complete release of the 0.x line.**

- Taskbar right-click context menu disabled when filter active: `NoTrayContextMenu=1` + `NoViewContextMenu=1` HKCU policies. Closes the "Win key → right-click taskbar → Close Window" escape that worked even after we gated the Win key.
- Clean-slate install. First-run purges leftover state from any prior install before the wizard runs — zombie controller processes, dangling IFEO blocks, stale scheduled task, orphan shortcuts, leftover state files. Reinstalls always start from zero.
- Anti-zombie kill at controller startup. Before installing the LL keyboard hook, the controller enumerates other `kiosk-exit-guard.exe` processes and terminates them. Prevents two controllers fighting over the hook and stale in-memory password hashes surviving an `--uninstall`.
- Embedded `currentVersion` bumped to 1.0.0 — the self-update flow uses this to compare against GitHub's latest release tag.

## v0.5.5 — 2026-05-11

**Self-update flow, Windows-key-alone gate, uninstall kills controller.**

- **"Update SK Filter"** desktop shortcut + `--update` flag. Hits `api.github.com/repos/.../releases/latest`, compares against embedded `currentVersion`, prompts on a newer release, password-gates the install, downloads the new exe to TEMP, atomic-renames the current exe to `.old`, drops the new exe in place, then `/End` + `/Run` the scheduled task so the new binary loads.
- Windows key alone now opens the password modal. Pressing Win by itself used to open Start menu, which let the user click the kiosk's taskbar entry and close it. Tracked via `winKeyChord` atomic.Bool: set true on Win down, cleared if any non-modifier key arrives while Win is held (combo path), checked on Win up — if still true → Win alone → password prompt + re-inject.
- `--uninstall` now kills the running controller process. Without this, `--uninstall` wiped HKLM and the scheduled task but the running controller process kept enforcing the filter from in-memory state until reboot.

## v0.5.4 — 2026-05-11

**Frameless modal, --resume + --uninstall, fix modal hang.**

- Frameless password modal — close the "kill the modal to bypass the filter" hole. The modal had a standard title bar with an X close button; clicking X destroyed the elevated WebView2 process and bypassed the password gate. Now stripped to `WS_POPUP|WS_VISIBLE` with `WS_EX_TOOLWINDOW` so it has no title bar, no taskbar entry, and no Alt+Tab presence. Cancel + Esc remain the only dismissal paths.
- Modal-hang fix. The v0.5.2 12-iteration topmost retry loop was hammering `SetForegroundWindow` + `BringWindowToTop` on the WebView2's HWND from a competing goroutine, racing the message pump. The modal showed "Not Responding" because the message loop was starved. Replaced with one Win32 round-trip after a 220 ms settle.
- **"Resume SK Filter"** desktop shortcut + `--resume` flag. NOT password-gated. Resuming makes the system more locked-down so anyone can trigger it. Pausing keeps the password gate.
- **"Uninstall SK Filter"** desktop shortcut + `--uninstall` flag. Password-gated and confirm-dialog gated. Removes IFEO blocks, HKCU lockdown, HKLM config key, scheduled task, all desktop shortcuts. Leaves the exe on disk — admin handles that manually.
- Cancel button added to the first-run wizard (Esc dismisses too).

## v0.5.3 — 2026-05-11

**"Pause SK Filter" desktop shortcut + --pause flag.**

- First-run now drops a second desktop shortcut for Pause. Double-click → UAC consent → password modal → duration picker. Same flow as the `Ctrl+Shift+Alt+K` hotkey, just one click away.
- The `--pause` invocation is a fresh elevated process that writes the pause state to disk, removes IFEO blocks + HKCU lockdown, kills the kiosk WebView2 child.
- New 2-second polling goroutine in the controller (`syncFilterStateLoop`) reconciles in-memory `filterMode` + lockdown state with the pause file. When an external `--pause` flips the file, the controller picks it up within ~2 seconds.

## v0.5.2 — 2026-05-11

**Fix hotkey modal hidden behind kiosk, allow Ctrl+R / F5.**

- Pressing `Ctrl+Shift+Alt+K` appeared to do nothing. The password modal WAS being created, but behind the fullscreen `HWND_TOPMOST` kiosk WebView2 window. Fix: after creating the modal, a goroutine calls `SetWindowPos(HWND_TOPMOST)` + `BringWindowToTop` + `SetForegroundWindow` on the modal's HWND repeatedly for the first ~1 second.
- `Ctrl+R` was caught by the "block any Ctrl/Win/Alt combo" sweep, so the kiosk page couldn't be refreshed without entering the password. New `isAlwaysAllowedCombo()` check runs before the broad block. Allowlists `Ctrl+R` and `F5`.

## v0.5.1 — 2026-05-11

**Default-ON, pause-only model with 1–100 min durations.**

The filter is now ALWAYS ON by default. There is no "turn off" path — only a time-bounded pause. After the pause expires the filter resumes automatically with no user intervention.

- Hotkey is now a pause trigger, not a toggle. When filter is active: password prompt + duration picker. When already paused: hotkey just shows remaining time.
- Durations: 1 / 5 / 10 / 20 / 30 / 45 minutes preset, or custom 1–100.
- During a pause: kiosk WebView2 window closes, Edge IFEO block is lifted (Edge can be launched), HKCU registry lockdown is removed.
- Pause expiry re-applies everything automatically.
- Branded password modal copy: "This command has been locked by the SK Filter — Please enter your password to continue." Modal sized to 520×360 with a lock icon header and "SK Filter" brand badge.

## v0.5.0 — 2026-05-11

**Desktop shortcut, branded WebView2 dialogs, password-gated re-injection.**

- WebView2 Runtime auto-install: controller detects missing runtime via the canonical EdgeUpdate `pv` check, downloads the evergreen bootstrapper from `go.microsoft.com/fwlink/p/?LinkId=2124703` to TEMP, runs it silently. No-op on Win10/11 client SKUs (runtime ships pre-installed). On Server 2022 / stripped images, removes the manual install step.
- Desktop shortcut created during first-run via PowerShell + `WScript.Shell` COM. Self-heals on every controller launch.
- Branded WebView2 first-run wizard. Single page collecting password + URL with form validation, replacing the chain of small zenity prompts. Dark themed to match the kiosk landing page.
- Branded WebView2 password prompt. Autofocused input via attribute + `setTimeout(...,0)` + `load` event so the user can start typing the instant the modal appears. Falls back to zenity when WebView2 isn't available.
- Password-gated re-injection for ALL blocked combos. Previously the hook silently swallowed Ctrl/Win/Alt combos other than Alt+F4. Now any blocked combo captures the key + modifier state, opens the branded password modal, and on correct password replays the original combo via `SendInput` with a marker in `ExtraInfo` so our own hook doesn't re-block it.

## v0.4.1 — 2026-05-11

**Auto-install WebView2 Runtime if missing.**

The controller detects missing WebView2 Runtime on every launch via the canonical `pv` check under `HKLM\Software\Microsoft\EdgeUpdate\Clients\{F3017226-…}`. If not installed, downloads the evergreen bootstrapper and runs it silently. Adds `net/http` to the dependency closure — exe size goes from 4.0 MB to ~7.6 MB.

## v0.4.0 — 2026-05-11

**WebView2 kiosk window, Chrome uninstall, Edge IFEO block.**

Replaces the Chrome subprocess + watchdog with an embedded WebView2 kiosk window. Same exe re-launches itself with `--webview` when filter mode flips ON; the WebView2 instance is fullscreen, topmost, frameless, JS-locked to refuse navigation outside the configured URL.

- Set password (HKLM)
- Set kiosk URL (HKLM)
- Uninstall Chrome silently via registry `UninstallString` + `--force-uninstall`
- Apply IFEO Debugger redirects on `chrome.exe` and `msedge.exe` so any launch attempt invokes our exe with `--silent-exit` and exits silently
- Install Task Scheduler startup entry
- `--silent-exit` flag wired at the top of `main()` so IFEO-redirected launches die before any setup runs
- Adds `github.com/jchv/go-webview2` (pure-Go bindings, no CGo)

## v0.3.0 — 2026-05-11

**Chrome watchdog, broad keystroke blocking, HKLM password storage.**

- Chrome kiosk watchdog: 30-second tick that launches `chrome.exe --kiosk` at the configured URL and re-launches if killed.
- Broader keystroke blocking: filter mode ON now swallows ALL keystrokes held with Ctrl, Win, or Alt (except plain modifiers and the toggle hotkey).
- Pause duration prompt: toggling filter mode OFF asks for 5 / 15 / 30 / 60 min / Indefinite. Anything but Indefinite auto-re-enables.
- HKLM password storage: bcrypt hash now lives at `HKLM\Software\KioskExitGuard\PasswordHash` instead of a deletable file. Standard kiosk user can't bypass by wiping a config file. Legacy `password.hash` files are migrated to HKLM on first run.
- Configurable kiosk URL: first-run prompt asks for the URL. Stored in HKLM. Change later via `--set-url` flag.
- `--reset` is now password-gated. To recover without password, admin must wipe `HKLM\Software\KioskExitGuard` manually via regedit.
- GitHub Actions: `.github/workflows/release.yml` builds the exe on every `v*` tag push and creates a release with the binary attached.

## v0.2.0 — 2026-05-11

**UAC manifest, filter-mode toggle, self-install, kiosk-escape blocks.**

- UAC manifest embedded via `goversioninfo` (`requestedExecutionLevel: requireAdministrator`). Cleanly elevates on every launch.
- First-run modal: missing `password.hash` triggers the set-password flow inline instead of failing with an error.
- Self-install via `schtasks /Create /SC ONLOGON /RL HIGHEST` so the exe re-launches at every user logon without a UAC prompt at logon time.
- Filter mode toggle: `Ctrl+Shift+Alt+K` + password = flip on/off. State persists to `filter_mode.state`.
- When filter mode is ON: `Win+R`, `Win+E`, `Win+D`, `Ctrl+Shift+Esc` are silently swallowed. HKCU policy registry sets `DisableTaskMgr=1` and `NoRun=1`, restored on toggle-off and graceful exit.
- `--reset` recovery flag clears the registry policies and resets filter mode to OFF.

## v0.1.1 — 2026-05-11

**Show auto-dismissing failed toast on wrong password / cancel.**

Replaces the silent-swallow behavior with a 2 s `zenity.Info` dialog so the user gets confirmation the Alt+F4 was caught and rejected rather than wondering whether the keystroke was even seen.

## v0.1.0 — 2026-05-11

**Initial release.**

Single-binary Windows utility that password-gates Alt+F4 in a kiosk-locked Windows 11 Home session. Builds for windows/amd64, ~2.7 MB, runs headless via the standard Win32 message loop pattern. Installs a `WH_KEYBOARD_LL` hook, intercepts Alt+F4, prompts for the password, forwards `WM_CLOSE` to the previously-focused window on success. Password stored as a bcrypt hash next to the exe. CI workflow builds and releases on every `v*` tag.

---

## Versioning notes

The 0.x line was rapid prototyping — eight releases in one day as the design firmed up. The 1.0.0 release was the "feature complete" milestone after the design settled around the pause-only model + WebView2 kiosk + four desktop shortcuts. 1.0.x patches address live-deployment issues found during VM testing.

Backwards-compatibility within 1.0.x: the HKLM key shape (`PasswordHash`, `KioskURL`) is stable. The state file format (`pause_until.state` storing UnixNano) is stable. Upgrades via the in-app `--update` flow handle the exe replacement and scheduled task refresh automatically.
