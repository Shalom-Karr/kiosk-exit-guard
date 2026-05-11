# kiosk-exit-guard

A small Windows utility that intercepts **Alt+F4** system-wide and only lets the keypress reach the foreground window after the user enters a password. Wrong password → keypress is silently swallowed.

Intended for Windows 11 Home kiosk setups where Assigned Access isn't available — pairs well with an auto-launched `msedge.exe --kiosk <url>` running under a standard user account.

## Install

1. Download `kiosk-exit-guard.exe` from [Releases](../../releases).
2. Place it somewhere the kiosk user can read but **not write** — typically `C:\Program Files\KioskExitGuard\` (the Program Files ACL keeps the standard user out).
3. Run once with the `--set-password` flag (as **admin**, so the hash lands next to the exe):

   ```
   "C:\Program Files\KioskExitGuard\kiosk-exit-guard.exe" --set-password
   ```

   This prompts twice for a password and writes `password.hash` (bcrypt) next to the exe.

4. Set the exe to auto-launch at the kiosk user's login. Either:
   - Drop a shortcut in `shell:startup` for the kiosk user, or
   - Use Task Scheduler with trigger "At log on of \<kiosk-user\>"

5. Sign out of admin, sign in as the kiosk user. The hook installs silently in the background.

## Behavior

| Key combo | What happens |
|---|---|
| Alt+F4 (correct password entered) | Forwards `WM_CLOSE` to the previously-focused window — closes the browser / kiosk app |
| Alt+F4 (wrong password / cancel) | Silently swallowed; nothing happens |
| Any other key | Untouched — normal behavior |

The password prompt is a native Win32 input box (via [ncruces/zenity](https://github.com/ncruces/zenity)) with masked input. It runs in a separate goroutine so the low-level hook stays responsive.

## What this does NOT do

This is a *single-key* guard. It does **not** block:

- Win+R (Run dialog)
- Win+E (Explorer)
- Win+D (Show desktop)
- Ctrl+Shift+Esc / Ctrl+Alt+Del (Task Manager)
- Win+L (Lock screen)

A real kiosk should lock those down separately via Group Policy / Registry, ideally combined with a standard user account that has no admin rights.

## Caveats

- **SmartScreen warning** — the exe is unsigned. First-run will show "Microsoft Defender SmartScreen prevented an unrecognized app from starting." Click "More info" → "Run anyway." Add the install directory to Defender exclusions if needed.
- **User-space hook** — anyone who can open Task Manager can kill `kiosk-exit-guard.exe` and Alt+F4 starts working again. Lock down Task Manager via registry: set `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr = 1` for the kiosk user.
- **password.hash file** — readable by the kiosk user (Program Files ACL). It's a bcrypt hash so the plaintext can't be recovered, but a determined user could replace the file if they have write access. Make sure the install directory is admin-write-only.

## Build from source

```
go install github.com/Shalom-Karr/kiosk-exit-guard@latest
```

Or locally:

```
git clone https://github.com/Shalom-Karr/kiosk-exit-guard.git
cd kiosk-exit-guard
go build -ldflags="-H windowsgui -s -w" -o kiosk-exit-guard.exe
```

The `-H windowsgui` flag suppresses the console window so the exe runs headless.

## License

MIT
