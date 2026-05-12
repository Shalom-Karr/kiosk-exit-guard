# kiosk-exit-guard

Single-binary kiosk lockdown utility for **Windows 11 Home** (no Assigned Access). One ~7 MB exe contains an embedded WebView2 kiosk window, a low-level keyboard hook with re-injection, an HKLM-backed password store, Chrome / Edge launch blocks at the OS level, a Chrome uninstaller, a self-installer, a self-updater, and four desktop shortcuts for the admin.

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

- **Self-install** at startup via Task Scheduler (HIGHEST run level, no UAC prompt at logon).
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
```

## Build

CI at `.github/workflows/release.yml` rebuilds + releases on every `v*` tag push.

```
git tag v1.0.6 && git push origin v1.0.6
```

Local build:

```
go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest
goversioninfo -64 versioninfo.json
go build -ldflags="-H windowsgui -s -w" -o kiosk-exit-guard.exe
```

## License

MIT
