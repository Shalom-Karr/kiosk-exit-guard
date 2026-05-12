# Changelog

All notable changes to kiosk-exit-guard, newest first. Versions follow [Semantic Versioning](https://semver.org/) with the convention that 1.0.x is the stable line and 0.x was prototyping.

For the current state of the project, see the [landing page](https://shalom-karr.github.io/kiosk-exit-guard/), the [architecture doc](architecture.md), and the [admin runbook](admin-runbook.md).

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
