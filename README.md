# kiosk-exit-guard

Single-binary kiosk lockdown for **Windows 11 Home** (no Assigned Access). v0.4.0 replaces the Chrome-watchdog model with an embedded WebView2 kiosk window, uninstalls Chrome during setup, and blocks Chrome / Edge launches at the OS level via Image File Execution Options.

## v0.4.0 — what's new

| Change | What it means |
|---|---|
| **Kiosk renders via WebView2** | The kiosk page is a fullscreen, topmost, frameless window owned by this exe. No Chrome subprocess. WebView2 Runtime is pre-installed on Win10/11. |
| **Chrome uninstalled on first run** | First-run setup silently runs Chrome's own uninstaller via the registry's `UninstallString`. Idempotent — does nothing if Chrome isn't present. |
| **Chrome + Edge launches blocked via IFEO** | Sets `HKLM\…\Image File Execution Options\chrome.exe\Debugger` and `…\msedge.exe\Debugger` to redirect launches back to this exe with `--silent-exit`. They fail invisibly. Re-applied on every launch in case Windows Update restores them. |
| **`--silent-exit` flag** | No-op mode entered when Windows invokes us as the IFEO Debugger. Just returns immediately. |
| **`--webview` flag** | Sub-mode where the exe renders the kiosk window. The main exe launches itself in this mode when filter mode flips ON. |

## Full feature set (v0.2.0 → v0.4.0)

- UAC manifest embedded — admin elevation on every launch
- First-run modal — set password, set kiosk URL, install startup task, uninstall Chrome, apply IFEO blocks
- **Self-install** at user logon via Task Scheduler (`KioskExitGuard`, HIGHEST run level)
- **Filter mode toggle** — `Ctrl+Shift+Alt+K` → password → flip on/off
- **Pause duration prompt** when flipping OFF — 5m / 15m / 30m / 1h / Indefinite. Anything but Indefinite auto-re-enables
- **WebView2 kiosk window** — fullscreen, topmost, frameless, JS-locked to refuse navigation outside the kiosk URL
- **HKLM password storage** — bcrypt hash at `HKLM\Software\KioskExitGuard\PasswordHash`. Admin-write only, so a standard kiosk user can't bypass by wiping config
- **Blocked when filter mode ON**:
  - Alt+F4 → password prompt (closes the kiosk window if correct)
  - All Ctrl/Win/Alt key combos silently swallowed
  - Task Manager refuses to launch (`HKCU…DisableTaskMgr=1`)
  - Run dialog refuses to open (`HKCU…NoRun=1`)
  - Chrome and Edge cannot be launched (IFEO redirect — system-wide)

## Quick start

1. Download `kiosk-exit-guard.exe` from [Releases](../../releases).
2. Place it in `C:\Program Files\KioskExitGuard\` (admin-write, user-read).
3. Double-click. Approve the UAC prompt.
4. Walk through first-run: set password, set kiosk URL.
5. The exe will:
   - Uninstall Chrome (if present)
   - Block Chrome + Edge launches via IFEO
   - Register itself as a startup task at every user logon
6. Press `Ctrl+Shift+Alt+K` to flip filter mode ON when ready.

## What still won't be blocked

- `Ctrl+Alt+Del` and `Win+L` — Secure Attention Sequence, below any user-mode hook
- BIOS / USB boot — set a BIOS password
- An admin with an elevated terminal can still kill the exe

## CLI flags

```
kiosk-exit-guard.exe                  # normal — controller + hook + watchdog
kiosk-exit-guard.exe --webview        # internal: renders the kiosk window (launched by the controller)
kiosk-exit-guard.exe --silent-exit    # internal: IFEO Debugger redirect handler
kiosk-exit-guard.exe --set-password   # change the password
kiosk-exit-guard.exe --set-url        # change the kiosk URL
kiosk-exit-guard.exe --reset          # password-gated — clear lockdown + IFEO + filter state
```

## Build from source

The CI workflow at `.github/workflows/release.yml` rebuilds and releases on every `v*` tag push.

```
git tag v0.4.0 && git push origin v0.4.0
```

Local build:

```
go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest
goversioninfo -64 versioninfo.json
go build -ldflags="-H windowsgui -s -w" -o kiosk-exit-guard.exe
```

## License

MIT
