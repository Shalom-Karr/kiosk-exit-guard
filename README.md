# kiosk-exit-guard

A single-binary Windows kiosk lockdown utility for **Windows 11 Home** (no Assigned Access). Bundles every common kiosk-escape block into one exe — password-gated Alt+F4, swallowed Win+R/E/D/Ctrl+Shift+Esc, Task Manager + Run dialog disabled via HKCU policy registry. All toggleable on the fly with a hotkey.

## What it does (v0.2.0)

| Feature | How it works |
|---|---|
| **UAC elevation** | Embedded manifest requires admin on launch |
| **First-run setup modal** | If no `password.hash`, automatically opens a set-password dialog (no `--set-password` flag needed) |
| **Self-install at startup** | Registers a Task Scheduler entry `KioskExitGuard` that re-launches the exe at every user logon with HIGHEST run level |
| **Filter mode toggle** | `Ctrl+Shift+Alt+K` → password prompt → filter mode flips on/off. State persists across reboots in `filter_mode.state` |
| **Filter mode ON** | Alt+F4 password-gated; Win+R/E/D/Ctrl+Shift+Esc silently swallowed by the LL hook; `HKCU\…\System\DisableTaskMgr=1`; `HKCU\…\Explorer\NoRun=1` |
| **Filter mode OFF** | All keys pass through; registry policies removed |
| **--reset recovery** | `kiosk-exit-guard.exe --reset` clears the registry policies in case the exe crashed while filter mode was on |

## Quick start

1. **Download** `kiosk-exit-guard.exe` from [Releases](../../releases).
2. **Place it** in `C:\Program Files\KioskExitGuard\` (admin-write, user-read).
3. **Double-click** the exe. Approve the UAC prompt.
4. **Set a password** when the first-run dialog appears (entered twice for confirmation).
5. The exe **self-installs** a Task Scheduler entry that re-launches it at every user logon.
6. To **turn filter mode on**, press `Ctrl+Shift+Alt+K` and enter the password.

That's it. From here on, the exe runs in the background at every logon. Toggle filter mode with the hotkey whenever you want to lock down or unlock the machine.

## What's locked when filter mode is ON

| Action / shortcut | Blocked? | Mechanism |
|---|---|---|
| `Alt+F4` | Password prompt; correct → closes window | LL hook + WM_CLOSE |
| `Ctrl+Shift+Esc` (Task Manager) | Silently swallowed | LL hook |
| Task Manager opened any other way (e.g. taskbar right-click) | Refuses to launch with "Task Manager has been disabled" | `HKCU\…\DisableTaskMgr=1` |
| `Win+R` (Run dialog) | Silently swallowed at the key level | LL hook |
| Run dialog opened from Start menu | Refuses to open | `HKCU\…\NoRun=1` |
| `Win+E` (File Explorer) | Silently swallowed | LL hook |
| `Win+D` (Show desktop) | Silently swallowed | LL hook |
| `Ctrl+Alt+Del` / `Win+L` | NOT blocked | Handled by Windows Secure Attention Sequence below any user-mode hook |

## What still won't be blocked

- **`Ctrl+Alt+Del`** and **`Win+L`** go through the Windows Secure Attention Sequence, which is below user-mode hooks. There is no way to intercept them from a normal Win32 process. A determined user can always lock the screen or reach the SAS menu.
- **Boot to USB / safe mode** — out of scope for any user-mode tool. Set a BIOS password.

## CLI flags

```
kiosk-exit-guard.exe                  # normal run — installs hook, restores filter-mode state
kiosk-exit-guard.exe --set-password   # change the password
kiosk-exit-guard.exe --reset          # restore registry, reset filter-mode to OFF
```

## Caveats

- **Unsigned binary** — SmartScreen / Defender will warn on first run. Click *More info* → *Run anyway*. Add the install dir to Defender exclusions if needed.
- **Password file** is `password.hash` (bcrypt cost 10). Stored alongside the exe. Keep the install directory admin-write only.
- **User-space process** — anyone with admin rights can still kill it from an elevated terminal. The Task Manager disable makes this much harder for a standard kiosk user.

## Build from source

```
git clone https://github.com/Shalom-Karr/kiosk-exit-guard.git
cd kiosk-exit-guard

# regenerate the UAC manifest .syso (only needed if you change versioninfo.json)
go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest
goversioninfo -64 versioninfo.json

# build the windowless exe
go build -ldflags="-H windowsgui -s -w" -o kiosk-exit-guard.exe
```

## License

MIT
