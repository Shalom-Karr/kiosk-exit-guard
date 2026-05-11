# kiosk-exit-guard

Single-binary kiosk lockdown utility for **Windows 11 Home** (no Assigned Access). Bundles every common kiosk-escape block, a Chrome kiosk watchdog, and a hotkey-toggleable filter mode into one signed-by-nobody-but-it-works exe.

## v0.3.0 — what it does

| Feature | How it works |
|---|---|
| **UAC elevation** | Embedded manifest requires admin on launch |
| **First-run setup modal** | If no `password.hash`, automatically opens a set-password dialog |
| **Self-install at startup** | Registers a Task Scheduler entry `KioskExitGuard` that re-launches the exe at every user logon with HIGHEST run level |
| **Filter mode toggle** | `Ctrl+Shift+Alt+K` → password prompt → filter mode flips on/off. State persists across reboots |
| **Pause duration prompt** | Toggling filter mode OFF asks "5m / 15m / 30m / 1h / Indefinitely". Anything but Indefinitely auto-re-enables when the timer expires |
| **Chrome kiosk watchdog** | 30-second tick (when filter mode is ON): if Chrome isn't running, launches `chrome.exe --kiosk <url>`; if Chrome is running but not the kiosk URL, kills it and relaunches |
| **Configurable URL** | Reads from `kiosk.url` next to the exe; defaults to `https://skluach.pages.dev/CMH/` |
| **Filter mode ON blocks** | Alt+F4 password-gated; every key combo with Ctrl, Win, or Alt held swallowed (covers Ctrl+F4, Ctrl+W, Alt+Tab, Win+anything, Ctrl+Shift+Esc, etc.); HKCU `DisableTaskMgr=1` and `NoRun=1` |
| **--reset recovery** | `kiosk-exit-guard.exe --reset` clears registry + pause + filter-mode if the exe crashed mid-lockdown |

## Quick start

1. Download `kiosk-exit-guard.exe` from [Releases](../../releases).
2. Drop it in `C:\Program Files\KioskExitGuard\` (admin-write, user-read).
3. Double-click. Approve the UAC prompt.
4. Set a password in the two prompts.
5. The exe self-installs the startup task. Future logons launch it silently.
6. Press `Ctrl+Shift+Alt+K` whenever you want to lock down the machine.

To point the watchdog at a different URL, drop a one-line `kiosk.url` file next to the exe with the URL inside.

## Toggle flow

```
Filter mode OFF (default at first launch)
  └── Ctrl+Shift+Alt+K → password → pick "ON" implicitly
        └── Filter mode ON
            ├── Chrome auto-launches in kiosk mode, auto-restarted every 30s
            ├── Alt+F4 prompts for password to close window
            ├── Every Ctrl/Win/Alt combo is swallowed
            └── Task Manager and Run dialog refuse to open
                  └── Ctrl+Shift+Alt+K → password → pick duration:
                        ├── 5 / 15 / 30 minutes / 1 hour: pause, auto-flip back ON
                        └── Indefinitely: pause forever until manual toggle
```

## What still won't be blocked

- `Ctrl+Alt+Del` and `Win+L` (Windows Secure Attention Sequence — below any user-mode hook)
- BIOS / USB boot — set a BIOS password
- An admin with an elevated terminal can still kill the exe

## CLI flags

```
kiosk-exit-guard.exe                  # normal run — restores state, installs hook, starts watchdog
kiosk-exit-guard.exe --set-password   # change the password
kiosk-exit-guard.exe --reset          # restore registry, reset filter-mode + pause (recovery)
```

## Build from source

The CI workflow at `.github/workflows/release.yml` rebuilds and releases on every `v*` tag push:

```
git tag v0.3.0
git push origin v0.3.0
```

To build locally:

```
go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest
goversioninfo -64 versioninfo.json
go build -ldflags="-H windowsgui -s -w" -o kiosk-exit-guard.exe
```

## License

MIT
