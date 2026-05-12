# kiosk-exit-guard

Single-binary kiosk lockdown utility for **Windows 11 Home** (no Assigned Access). One ~7 MB exe contains an embedded WebView2 kiosk window, a low-level keyboard hook with re-injection, an HKLM-backed password store, Chrome / Edge launch blocks at the OS level, a Chrome uninstaller, a self-installer, a self-updater, and four desktop shortcuts for the admin.

## What's in v1.1.10

Service spawn reliability fix plus two log-noise cleanups from production traces:

- **Service can now spawn its supervised controller even when `gopsutil` enumeration is empty.** Field report: `spawnControllerInSession(1) failed: WTSQueryUserToken(1): An attempt was made to reference a token that does not exist.; explorer fallback: no explorer.exe found in session 1 (is a user logged in?)` firing every 2 seconds on a machine where the user WAS logged in and running the kiosk. Root cause: the v1.1.3 `WTSQueryUserToken`-NO_TOKEN fallback walked `gopsutil`'s `process.Processes()` to find `explorer.exe` in the active console session — but gopsutil's underlying snapshot can return an empty list when called from the Session-0 LocalSystem service even though the kernel itself can see across sessions just fine (LocalSystem has `SeDebugPrivilege`). A second contributing factor was the v1.1.8 fallback being explorer-only: a machine with a custom kiosk shell or a v1.1.x'd Explorer-restart-that-didn't-respawn could have no `explorer.exe` in session 1 at all. Fix: rewrote `tokenFromExplorerInSession` → `tokenFromUserSessionProcess` to use `WTSEnumerateProcessesExW` from `wtsapi32.dll` — the Win32 API explicitly designed for service-side cross-session enumeration. Pass the target `sessionID` directly so the kernel filters for us. Broadened the candidate list to `explorer.exe` / `sihost.exe` / `taskhostw.exe` / `RuntimeBroker.exe` / `StartMenuExperienceHost.exe` (all auto-spawned under the interactive user's token), with priority order preserved (explorer first). Each candidate validates against its canonical `%SystemRoot%` path via `QueryFullProcessImageName` so the v1.1.8 HIGH#3 image-path authentication is preserved. Buffer freed via `WTSFreeMemoryExW` every call — critical because the loop runs every 2 seconds.
- **`tightenHKLMConfigDACL` no longer logs on fresh installs.** Pre-v1.1.10 the v1.1.8 HIGH#5 DACL tightener ran at controller startup AND on every `saveHashToRegistry`. On a fresh install the HKLM key only exists after `saveHashToRegistry` — so the startup call hit `ERROR_FILE_NOT_FOUND` (2) and emitted `SetNamedSecurityInfo(MACHINE\Software\KioskExitGuard) failed: The system cannot find the file specified.` to `kiosk-exit-guard.log` on every startup until first-run completed. The function correctly returned (the key gets tightened in `saveHashToRegistry` when it gets created), but the log line was alarming. Now silently skips `ERROR_FILE_NOT_FOUND`; any other error still surfaces.
- **`parentProcessImagePath` no longer logs on the v1.1.8 relocate-and-reexec flow.** v1.1.8 LOW#9's parent-PID image-path lookup hit `ERROR_INVALID_PARAMETER` on the v1.1.8 relocate-from-Downloads-to-ProgramFiles flow because the original parent (the admin's double-click) had already exited by the time the re-execed child ran the parent lookup. The function correctly fell back to the env-var hint (the documented v1.1.0 behavior), but `OpenProcess(parent=…) failed: The parameter is incorrect.` looked scary. Now silently absorbs `ERROR_INVALID_PARAMETER` and `ERROR_ACCESS_DENIED` (both expected for "parent already exited" or "parent is a protected process"); the `isLaunchedByService: parent lookup failed, env hint=…` audit line is kept.

Per-fix root cause + diff in [docs/CHANGELOG.md](docs/CHANGELOG.md).

## What's in v1.1.9

UX audit pass plus a new "password modal can't be left up forever" rule. Eleven concrete fixes:

- **Password modal auto-dismisses after 30s of inactivity.** A user who pressed `Ctrl+Shift+Alt+K`, saw the modal, then walked away used to leave the fullscreen password screen up indefinitely — the kiosk WebView2 was dead and the next person at the device saw a frozen modal with no way to dismiss. `askPasswordModalInProcess` now arms a `time.AfterFunc(30*time.Second, ...)` that auto-cancels the modal, returning `pwCancel` so no failed-password toast fires. `kgSubmit` / `kgCancel` reset the timer so an actively-typing user isn't yanked mid-attempt.
- **Service / task race at logon no longer blinks the kiosk.** v1.1.4 co-installed both auto-start mechanisms; at logon both fire within ~1s and the loser was being killed by the winner's `killRunningController()`. The loser's supervisor respawned it, oscillation continued, kiosk WebView2 blinked / reopened 1 – 2s after logon. New cross-process Win32 mutex `Global\KioskExitGuardControllerRunning` acquired before `killRunningController` — second mover logs "controller mutex already held; exiting" and `os.Exit(0)`s cleanly. First controller keeps running, no respawn loop, no kiosk blink.
- **Controller panic surfaces a "SK Filter restarted after an internal error" toast.** Pre-v1.1.9 a panic in `recoverAndLog` logged silently and the user saw the desktop briefly while the Service / scheduled task respawned the controller. Now spawns a fire-and-forget `--show-toast` child explaining the brief glitch before the process tears down.
- **First-run dialog: one combined success/failure message.** Pre-v1.1.9 the `installService` failure path stacked a `zenity.Warning` BEFORE the task install attempt, then a `zenity.Error` on top if the task also failed. And the success message hardcoded "Auto-start task installed" even when only the Service installed. Now installs both first, then surfaces ONE dialog with "Auto-start: Windows Service ✓ / ✗, Scheduled task ✓ / ✗".
- **Pause shortcut kiosk-relaunch race closed.** The `--pause` shortcut killed the kiosk child so `zenity.List` (duration picker, not `HWND_TOPMOST`) could grab foreground. The controller's 30s watchdog could relaunch the kiosk before the 2s `syncFilterStateLoop` saw the pause file. New marker file `%ProgramData%\KioskExitGuard\pause-just-applied.flag` carries a 5s future timestamp; `watchdogTick` skips relaunching while the marker is in the future.
- **`--update` waits for SCM to actually stop the Service before renaming the exe.** `sc stop` returned immediately; the supervisor could respawn a fresh controller in the 1 – 2s window and file-lock the exe, breaking the rename. New `waitForServiceStopped(10s)` polls `mgr.Query` until the state is `svc.Stopped`, mirroring the pattern already in `installService`.
- **Win-key-alone modal spawn failure surfaces a toast.** If `--ask-password` failed to start (AV quarantine, missing exe, locked path), the wrapper returned `pwCancel` silently and the LL hook swallowed the press — user tapped Win, saw nothing, assumed the filter was broken. Now distinguishes spawn-failure (`runErr` is non-`*exec.ExitError`) from exit-code and shows "Password prompt failed. Check kiosk-exit-guard.log or restart the filter."
- **Toasts at exit-after-failure call sites now block on render.** `runPauseInvocation`, `runUpdateInvocation`, and `--set-url` previously fire-and-forgot `showFailedToast()` then immediately `os.Exit(1)` — the parent died before the child WebView2 finished cold-starting. New `showFailedToastSync()` uses `cmd.Run()` so the parent waits.
- **Uninstall dialog mentions the Windows Service; verification block confirms its removal.** Bulleted "this removes:" list updated. Post-uninstall failures list gains a row if `KioskExitGuardSvc` survives.
- **`--set-url` defensively writes the new URL to HKLM before killing the kiosk.** Already correct in current code (`promptForKioskURL` does the save before returning), but an explicit `saveKioskURLToRegistry(newURL)` call locks the invariant against future refactors. Idempotent.
- **`docs/admin-runbook.md` updated for v1.1.4+ co-installed auto-start and v1.1.8 paths.** Verification section now expects ONE row each for Service and scheduled task. New "Auto-start verification" section. New "Install paths (v1.1.8+)" section covering `%ProgramFiles%\KioskExitGuard\` and `%ProgramData%\KioskExitGuard\`.

Per-fix root cause + diff in [docs/CHANGELOG.md](docs/CHANGELOG.md).

## What's in v1.1.8

Security-audit pass — nine findings across the install, update, service-spawn, and registry-storage paths all closed:

- **Install path locked down.** First-run now relocates the exe to `%ProgramFiles%\KioskExitGuard\kiosk-exit-guard.exe` before registering the Service binary path, scheduled task, and desktop shortcuts. Previously the SCM-registered path was wherever the admin double-clicked from — usually `Downloads`, which is kiosk-user-writable; a kiosk user could swap the binary and have the supervising Service respawn attacker code as LocalSystem.
- **`--update` integrity verified.** Downloaded exe now stages under `%ProgramData%\KioskExitGuard\staging\` (admin-only DACL via `icacls`) instead of `%TEMP%` (user-writable), and the SHA-256 is verified against a new `kiosk-exit-guard.exe.sha256` sidecar asset published by the release workflow. Mismatch aborts the update.
- **Explorer-token fallback authenticated.** The Service's `WTSQueryUserToken`-NO_TOKEN fallback (v1.1.3) trusted any process named `explorer.exe`. It now `QueryFullProcessImageName`s the kernel handle to confirm the image is `%SystemRoot%\explorer.exe` before unwrapping the linked elevated token — closes the "kiosk user spawns renamed-to-explorer.exe to get LocalSystem code-exec" path and the PID-recycle race.
- **WebView2 profile admin-only.** All four `webview2.NewWithOptions` call sites (password modal, toast, first-run wizard, kiosk page) now share `%ProgramData%\KioskExitGuard\WebView2\` with the same locked-down DACL. The default `%LOCALAPPDATA%` profile was user-writable — a poisoned service worker could intercept the password modal's `kgSubmit` host-object call.
- **HKLM password-hash DACL tightened.** Default `HKLM\Software` inherits `BUILTIN\Users:KEY_READ` — the bcrypt hash was readable by any local user (offline-crackable). Tightened via `SetNamedSecurityInfo(SE_REGISTRY_KEY, SDDL=D:PAI(A;CI;KA;;;SY)(A;CI;KA;;;BA))` on every controller startup so existing installs heal.
- **LL keyboard hook installed earlier in `main()`.** Previously the gap between `killRunningController()` and `SetWindowsHookExW` (seconds for first-run, ~half a second for steady-state) was unprotected. Moved the hook install up so the new hook is alive before the old controller is killed.
- **PowerShell injection prep.** `installStartupTask` now passes the exe path and task name via `$env:KEG_EXE` / `$env:KEG_TASKNAME` and the script body via `-EncodedCommand <base64-utf16le>` instead of `fmt.Sprintf` into a heredoc — not exploitable today, but future-proof.
- **`isLaunchedByService` authenticated via parent PID.** Previously the `KIOSK_EXIT_GUARD_VIA_SERVICE` env var was the entire gate; any process could forge it. Now uses `CreateToolhelp32Snapshot` to look up the parent PID and `QueryFullProcessImageName` to confirm the parent is `%SystemRoot%\System32\services.exe`.

Detailed root-cause + fix breakdown in [docs/CHANGELOG.md](docs/CHANGELOG.md).

## What's in v1.1.5

`Ctrl+0` (zoom reset), `Ctrl+-` (zoom out), and `Ctrl++` / `Ctrl+=` (zoom in) — plus numpad equivalents — now pass through the LL hook to the kiosk WebView2 page instead of triggering the password modal. Joins the existing always-allowed list of `F5` and `Ctrl+R`. Still Ctrl-only: `Win+0` / `Alt+-` etc. continue to hit the lockdown path.

## What's in v1.1.4

Field report: "right now the filter only runs when I re-click the exe file from the downloads folder." Even after v1.1.3's explorer-token fallback shipped, the auto-start was still flaky on the affected machine. v1.1.0 had aggressively switched to Service-only and deleted any leftover scheduled task on install — which made the kiosk unprotected after reboot whenever the Service spawn path failed.

Fix: install BOTH auto-start mechanisms on first-run and on every non-service launch:

- **Windows Service** as the in-session respawn supervisor (LocalSystem in Session 0; kiosk user can't disable).
- **Scheduled task** as the AtLogon fallback for installs where the Service spawn path fails.

The v1.0.x every-1-minute watchdog repetition is dropped — the Service handles in-session respawn now, and keeping both watchdogs caused kill/respawn churn. The task is a single AtLogon trigger only. `installService` no longer wipes the scheduled task; `killRunningController()` at controller startup keeps exactly one controller alive regardless of which mechanism fired.

## What's in v1.1.3

Two production-reported bugs the v1.1.0–v1.1.2 line missed:

- **Password modal panic in the controller.** Fresh install, press Win once → modal flickers, panics, kiosk bypassed. Same root cause as v1.1.1 / v1.1.2: `go-webview2` panics on a process's second WebView2 instantiation. The controller's first WebView2 is `firstRunWithWizard`; the next one (`askPasswordModal` via the LL hook callback) crashed it. Fix: `askPasswordModal` now spawns a `--ask-password` child process and reads its exit code. The child's WebView2 is always its first.
- **Service couldn't spawn its child controller** — "the filter only runs when I re-click the exe." `WTSQueryUserToken` returned `ERROR_NO_TOKEN` for the entire session on the affected machine. Fix: fall back to stealing `explorer.exe`'s token in the active session, unwrapping the UAC-split limited half to its elevated linked token. The supervisor now spawns a working controller even when the documented WTS API fails.

## What's in v1.1.2

- **Pause-expiry crash fix.** Symptom: Resume shortcut said "SK Filter is already active" but the Win key wasn't actually blocked. Root cause: `autoReenableFilterMode`'s "Pause ended." toast was the controller's second in-process WebView2, which `go-webview2` panics on (same bug class as v1.1.1's `--update` fix). The panic ran on `time.AfterFunc`'s goroutine with no `recover` — the controller crashed and the LL hook went with it. Same path bit any flow pairing `askPasswordModal` with `showFailedToast` on wrong-password. Fix: all toasts now route through a `--show-toast` child process, so the caller never instantiates a second WebView2. See [docs/CHANGELOG.md](docs/CHANGELOG.md) for the full diagnosis.

## What's in v1.1.0

- **Windows Service supervisor.** `KioskExitGuardSvc` runs as `LocalSystem` and respawns the user-session controller via `CreateProcessAsUserW`. Replaces the v1.0.x Task Scheduler watchdog — kiosk users can't reach SCM, so they can't stop it the way they could `schtasks /Delete` the old task. See [docs/architecture.md](docs/architecture.md) for the two-process model.
- **LL-hook thread pinning.** `runtime.LockOSThread()` at the top of `main()` fixes the v1.0.6 "first-run install ignores keyboard combos" bug.

## What's in v1.0.6

Pause-only model with always-on filter:

- Filter is **ON by default** at install, on every reboot, and after every pause. There is no "turn off" path.
- **Pause** the filter for 1–100 minutes via password-gated prompt. Auto-resumes when the timer expires.

Lockdown surface:

- **WebView2 kiosk window** — fullscreen, topmost, frameless, JS-locked to the configured URL. No Chrome subprocess.
- **Keyboard hook** — every Ctrl/Win/Alt combo opens the SK Filter password modal. Correct password re-injects the original combo via `SendInput`. Wrong password / cancel = swallowed.
- **Windows key alone** also opens the modal (otherwise the Start menu lets users reach the taskbar to close the kiosk).
- **Ctrl+R and F5** pass through to the WebView2 kiosk so admins can refresh the page without entering the password.
- **Chrome uninstalled** during first-run setup. **Edge** stays installed (Windows internals need it) but launches are **IFEO-blocked** at the OS level.
- **Task Manager** disabled via `HKCU\…\DisableTaskMgr=1` when filter is active.
- **Run dialog** disabled via `HKCU\…\NoRun=1` when filter is active.

Admin UX:

- **Branded WebView2 first-run wizard** — one page collects password + URL.
- **Branded WebView2 password modal** — frameless (no X to bypass), autofocused input, "This command has been locked by the SK Filter" header.
- **Four desktop shortcuts**, all UAC-elevated:
  - **Pause SK Filter** — password + duration picker (1/5/10/20/30/45 min or custom 1–100).
  - **Resume SK Filter** — ends pause early. *No password* (resuming is the safe direction).
  - **Update SK Filter** — checks GitHub for newer releases, password-gates install, atomic-replaces the running exe.
  - **Uninstall SK Filter** — password + confirm dialog, full teardown.

Robustness:

- **Self-install** as a real Windows Service (`KioskExitGuardSvc`, `LocalSystem`, Automatic) that supervises and respawns the user-session controller. Falls back to a Task Scheduler entry if Service install fails.
- **WebView2 Runtime auto-install** — downloads evergreen bootstrapper from `go.microsoft.com` if missing (Server SKUs / stripped images).
- **HKLM password storage** — bcrypt hash in `HKLM\Software\KioskExitGuard\PasswordHash`. Admin-write only.
- **IFEO blocks survive Windows Update** — re-applied on every controller launch.
- **`--reset` recovery** — password-gated flag clears all lockdowns if anything wedges.

## Quick start

1. Download `kiosk-exit-guard.exe` from [Releases](../../releases).
2. Place in `C:\Program Files\KioskExitGuard\`.
3. Double-click. Approve the UAC prompt.
4. Walk through first-run: password, kiosk URL.
5. Setup will: install WebView2 Runtime (if needed), uninstall Chrome, block Edge launches, register a logon task, drop four desktop shortcuts.
6. The filter is on **immediately**. Press `Ctrl+Shift+Alt+K` or double-click "Pause SK Filter" when you need to use the computer normally.

## What it doesn't block

- `Ctrl+Alt+Del` and `Win+L` — Windows Secure Attention Sequence, below any user-mode hook.
- Booting from USB / safe mode. Set a BIOS password.
- Another admin with an elevated terminal can still kill the controller. The Task Manager disable raises the bar for a standard kiosk user.
- Third-party browsers an admin installs would not be IFEO-blocked unless added.

## CLI flags

```
kiosk-exit-guard.exe                  # normal — controller + hook + watchdog
kiosk-exit-guard.exe --pause          # password + duration picker (desktop button)
kiosk-exit-guard.exe --resume         # end pause early, no password (desktop button)
kiosk-exit-guard.exe --update         # check GitHub for new version (desktop button)
kiosk-exit-guard.exe --uninstall      # password + confirm, full teardown (desktop button)
kiosk-exit-guard.exe --webview        # internal: render the kiosk window
kiosk-exit-guard.exe --silent-exit    # internal: IFEO Debugger redirect handler
kiosk-exit-guard.exe --set-password   # change the password
kiosk-exit-guard.exe --set-url        # change the kiosk URL
kiosk-exit-guard.exe --reset          # password-gated, clears all lockdowns
kiosk-exit-guard.exe --service-run    # internal: SCM-only Service entry point
kiosk-exit-guard.exe --service-install  # admin: register the supervising Service
kiosk-exit-guard.exe --service-remove   # admin: stop + unregister the Service
```

## Build

CI at `.github/workflows/release.yml` rebuilds + releases on every `v*` tag push.

```
git tag v1.1.0 && git push origin v1.1.0
```

Local build:

```
go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest
goversioninfo -64 versioninfo.json
go build -ldflags="-H windowsgui -s -w" -o kiosk-exit-guard.exe
```

## License

MIT
