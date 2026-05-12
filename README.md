# kiosk-exit-guard

Single-binary kiosk lockdown for **Windows 11 Home** and **Windows Server 2022 (RDP / physical console)**. One ~7.9 MB exe contains an embedded WebView2 kiosk window, a low-level keyboard hook with password-gated re-injection, an HKLM-backed bcrypt password store, Chrome / Edge launch blocks at the OS level, a Chrome uninstaller, a self-installer, a self-updater, a supervising Windows Service, and four desktop shortcuts for the admin.

## What's new in v1.1.11

Server 2022 RDP is now a real supported target. The supervisor used to hardcode `WTSGetActiveConsoleSessionId()` as the spawn target — fine on a Win11 laptop where the console session is also the user's session, broken on a headless RDP'd server where the console session is empty and the user is in an RDP session (typically session 2). v1.1.11's new `pickActiveUserSession()` walks `WTSEnumerateSessionsW`, looks for a `WTSActive` session with a logged-in user (via `WTSQuerySessionInformationW(WTSUserName)`), prefers the console session when it qualifies, otherwise falls back to the lowest-numbered other interactive session. Same release: the `--update` flow drops its "checking for updates…" toast and standalone confirm — the password modal subtitle now mentions the new version, combining confirm + auth into one screen; `restartExplorer` reads `HKLM\...\Winlogon\Shell` and skips the kill / restart when the registered shell isn't `explorer.exe` (Server Core / custom-shell installs); IFEO removal and Chrome uninstall absorb "not installed" silently instead of emitting confusing errors on fresh Server 2022 boxes.

Full per-release history in [docs/CHANGELOG.md](docs/CHANGELOG.md). Architecture in [docs/architecture.md](docs/architecture.md). Day-to-day admin queries in [docs/admin-runbook.md](docs/admin-runbook.md).

## Lockdown surface

- **WebView2 kiosk window** — fullscreen, topmost, frameless, JS-locked to the configured URL. No Chrome subprocess; the kiosk renders inside the exe itself.
- **Low-level keyboard hook** — every Ctrl/Win/Alt combo opens the SK Filter password modal. Correct password re-injects the original combo via `SendInput` carrying a random per-process `ExtraInfo` nonce so the hook recognizes its own events. Wrong password / cancel = swallowed.
- **Windows key alone** also opens the modal (otherwise Start menu lets the user reach the taskbar to close the kiosk).
- **Ctrl+R / F5** and **Ctrl+0 / Ctrl+- / Ctrl++** (plus numpad equivalents) pass through to the kiosk WebView2 page so admins can refresh and adjust zoom without entering the password.
- **Chrome uninstalled** during first-run; **Edge** stays installed (Windows internals need it) but launches are **IFEO-blocked** at the OS level. Same IFEO block on `sethc.exe` / `osk.exe` / `narrator.exe` / `utilman.exe` / `magnify.exe` to close the Sticky-Keys and Ease-of-Access escapes.
- **Task Manager, Run dialog, taskbar right-click, desktop right-click, and the taskbar itself** are disabled via HKCU policies while the filter is active (`DisableTaskMgr`, `NoRun`, `NoTrayContextMenu`, `NoViewContextMenu`, `NoTaskbar`).
- **Pause** the filter for 1–100 minutes via password-gated prompt. Edge becomes launchable, HKCU lockdown lifts, kiosk window closes; everything restores automatically when the timer expires. There is no "turn off forever" path.

## Admin UX

- **Branded WebView2 first-run wizard** — one page collects password + URL.
- **Branded WebView2 password modal** — frameless (no X to bypass), autofocused input, attached-thread-input foreground steal, 30 s inactivity timeout.
- **Four UAC-elevated desktop shortcuts**: Pause SK Filter, Resume SK Filter (no password — resuming is the safe direction), Update SK Filter (GitHub `releases/latest`, SHA-256 verified, atomic-replaces the running exe), Uninstall SK Filter.

## Robustness

- **Supervising Windows Service** `KioskExitGuardSvc` (LocalSystem, Session 0) respawns the user-session controller via `CreateProcessAsUserW`. Co-installed with an AtLogon scheduled task as belt-and-suspenders fallback; a `Global\KioskExitGuardControllerRunning` named mutex keeps exactly one controller alive when both fire at logon.
- **WebView2 Runtime auto-install** — downloads the evergreen bootstrapper from `go.microsoft.com` if missing (Server SKUs / stripped images).
- **Install path locked down** — first-run relocates the exe into `%ProgramFiles%\KioskExitGuard\` before registering the Service binary path, and the WebView2 user-data folder + update staging directory live under `%ProgramData%\KioskExitGuard\` with an `icacls`-tightened admin-only DACL.
- **HKLM password storage** — bcrypt hash in `HKLM\Software\KioskExitGuard\PasswordHash`. Key DACL is reset to SYSTEM + Administrators only on every controller startup so an offline crack against the hash isn't reachable from a standard user.
- **IFEO blocks survive Windows Update** — re-applied on every controller launch.
- **`--reset` recovery** — password-gated flag clears all lockdowns if anything wedges.

## Quick start

1. Download `kiosk-exit-guard.exe` from [Releases](../../releases).
2. Double-click. Approve the UAC prompt. (The first-run wizard relocates the exe to `%ProgramFiles%\KioskExitGuard\` if it's launched from anywhere else.)
3. Walk through the first-run wizard: password, kiosk URL.
4. Setup installs WebView2 Runtime (if needed), uninstalls Chrome, blocks Edge launches, registers the Service + AtLogon task, drops the four desktop shortcuts.
5. The filter is on **immediately**. Press `Ctrl+Shift+Alt+K` or double-click "Pause SK Filter" when you need to use the computer normally.

## What it doesn't block

- `Ctrl+Alt+Del` and `Win+L` — Windows Secure Attention Sequence, below any user-mode hook.
- Booting from USB / safe mode. Set a BIOS password.
- Another admin with an elevated terminal can still kill the controller. The Task Manager disable + IFEO blocks raise the bar for a standard kiosk user.
- Third-party browsers an admin installs would not be IFEO-blocked unless added.
- Windows 11 Home doesn't support Assigned Access; on Pro / Enterprise the built-in kiosk mode is the simpler answer. This tool is for the SKUs where that isn't available.

## CLI flags

```
kiosk-exit-guard.exe                    # controller — LL hook + watchdog (spawned by Service)
kiosk-exit-guard.exe --service-run      # SCM-only — supervising Service (Session 0, LocalSystem)
kiosk-exit-guard.exe --service-install  # admin: register & start KioskExitGuardSvc
kiosk-exit-guard.exe --service-remove   # admin: stop & unregister the Service
kiosk-exit-guard.exe --pause            # password + duration picker (desktop button)
kiosk-exit-guard.exe --resume           # end pause early, no password (desktop button)
kiosk-exit-guard.exe --update           # GitHub releases/latest + SHA-256 + atomic replace (desktop button)
kiosk-exit-guard.exe --uninstall        # password + confirm, full teardown (desktop button)
kiosk-exit-guard.exe --launch-kiosk     # manually respawn the WebView2 kiosk child
kiosk-exit-guard.exe --set-password     # change the password
kiosk-exit-guard.exe --set-url          # change the kiosk URL
kiosk-exit-guard.exe --reset            # password-gated, clears all lockdowns
kiosk-exit-guard.exe --webview          # internal: render the kiosk window
kiosk-exit-guard.exe --silent-exit      # internal: IFEO Debugger redirect handler
kiosk-exit-guard.exe --ask-password     # internal: child-process password modal
kiosk-exit-guard.exe --show-toast       # internal: child-process toast renderer
```

## Build

CI at `.github/workflows/release.yml` rebuilds and releases on every `v*` tag push, attaching `kiosk-exit-guard.exe` and a `kiosk-exit-guard.exe.sha256` sidecar that the in-app `--update` verifies against.

```
git tag v1.1.11 && git push origin v1.1.11
```

Local build:

```
go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest
goversioninfo -64 versioninfo.json
go build -ldflags="-H windowsgui -s -w" -o kiosk-exit-guard.exe
```

## License

MIT
