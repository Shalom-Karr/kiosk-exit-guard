# Admin runbook

Day-to-day operation, recovery from common breakage, and the verification queries to check the install is in the state you expect.

## Common tasks

### Pause the filter for some work

Either:

- Press `Ctrl+Shift+Alt+K` (the hotkey opens the password modal in-place), **or**
- Double-click **Pause SK Filter** on the desktop (UAC consent → password modal)

Both paths converge on the duration picker. Pick 1 / 5 / 10 / 20 / 30 / 45 min or Custom 1–100. The kiosk closes; Edge can now be launched; Task Manager / Run dialog / taskbar right-click come back. When the timer expires, everything restores automatically.

### Resume early

Double-click **Resume SK Filter**. No password (resuming the lockdown is safe). Kiosk returns within a couple seconds (sync loop runs every 2 s).

### Change the password

```
"C:\Program Files\KioskExitGuard\kiosk-exit-guard.exe" --set-password
```

### Change the kiosk URL

```
"C:\Program Files\KioskExitGuard\kiosk-exit-guard.exe" --set-url
```

### Install an update

Double-click **Update SK Filter**. Hits the GitHub `/releases/latest` API, shows current vs latest. Click Install → password modal → it downloads, atomic-renames the running exe to `.old`, swaps in the new one, restarts the Service.

If the device can't reach `api.github.com`, the dialog will report a network error; download the new exe manually from [Releases](https://github.com/Shalom-Karr/kiosk-exit-guard/releases) and overwrite `kiosk-exit-guard.exe` (you'll need to kill the running controller first — see below).

### Uninstall

Double-click **Uninstall SK Filter**. Password modal + confirm dialog. After it completes the exe binary still exists at `C:\Program Files\KioskExitGuard\kiosk-exit-guard.exe` — delete it manually if you want full removal. (Re-running the exe at that point would re-trigger first-run setup.)

## Verification queries

Run these in an **Admin PowerShell** to check what's installed and what's active.

### Is the controller running?

```powershell
Get-Process kiosk-exit-guard -ErrorAction SilentlyContinue |
    Select-Object Id, ProcessName, StartTime
```

Expect, on a v1.1.0 install: two or three rows. One is the Service (`--service-run`, owned by `SYSTEM`), one is the user-session controller (no args), and a third appears as `--webview` when the kiosk is active.

### Is the Service installed and running? (v1.1.0+)

```powershell
Get-Service KioskExitGuardSvc -ErrorAction SilentlyContinue |
    Select-Object Name, DisplayName, Status, StartType
```

Expect: `Status = Running`, `StartType = Automatic`. Also check via `sc`:

```powershell
sc query KioskExitGuardSvc
sc qc KioskExitGuardSvc
```

`sc qc` should show `BINARY_PATH_NAME : "C:\Program Files\KioskExitGuard\kiosk-exit-guard.exe" --service-run` and `SERVICE_START_NAME : LocalSystem`.

### Is the scheduled task installed? (v1.1.4+)

```powershell
Get-ScheduledTask -TaskName KioskExitGuard -ErrorAction SilentlyContinue |
    Select-Object TaskName, State
```

Expect: **one row** with `State = Ready`. As of v1.1.4 the Service AND the scheduled task are co-installed as belt-and-suspenders auto-start — either alone has been observed to fail in the field, so we keep both. The Service is the in-session respawn supervisor; the task is the AtLogon fallback for installs where the Service spawn path fails. `killRunningController()` plus the v1.1.9 cross-process controller mutex (`Global\KioskExitGuardControllerRunning`) keep exactly one controller alive regardless of which mechanism fires first.

If no row exists, the AtLogon fallback isn't installed — re-run the exe (which re-installs both auto-starts on every non-service-spawn launch) or manually trigger via `"C:\Program Files\KioskExitGuard\kiosk-exit-guard.exe"`.

### Auto-start verification

Combined check that both auto-start paths are present and the running controller is sane:

```powershell
Get-Service KioskExitGuardSvc | Select-Object Name, Status, StartType
Get-ScheduledTask -TaskName KioskExitGuard | Select-Object TaskName, State
Get-Process kiosk-exit-guard -ErrorAction SilentlyContinue |
    Select-Object Id, ProcessName, StartTime, Path
```

Expect:

- `KioskExitGuardSvc` row: `Status = Running`, `StartType = Automatic`.
- `KioskExitGuard` scheduled task row: `State = Ready`.
- 2 – 3 `kiosk-exit-guard` processes: one `--service-run` (SYSTEM), one user-session controller (no args or `--service-run`-spawned), optionally one `--webview` while the kiosk is up.

All three rows should reference `Path = C:\Program Files\KioskExitGuard\kiosk-exit-guard.exe` on a v1.1.8+ install.

### Server 2022 / RDP: which session is the supervisor targeting? (v1.1.11+)

On a Windows Server 2022 install accessed over RDP, the physical-console session is empty and the user is in an RDP session (typically session 2). v1.1.11's `pickActiveUserSession()` walks every session and picks the one with a logged-in user. Verify which session won by looking at `kiosk-exit-guard.log`:

```powershell
Get-Content "C:\Program Files\KioskExitGuard\kiosk-exit-guard.log" -Tail 50 |
    Select-String "spawning controller in session"
```

Expect (on Server 2022 over RDP):

```
service: spawning controller in session 2 (state=Active, user logged in)
```

Expect (on a Win11 laptop or any install where the user is at the physical console):

```
service: spawning controller in session 1 (state=Active, user logged in)
```

Cross-check against `quser` — the session ID it reports for the `Active` row should match:

```cmd
quser
```

If the log says `service: no active user session, waiting…` every couple of seconds, no session is currently `WTSActive` with a logged-in user — the supervisor is waiting for someone to actually log in. This is the correct behavior between boot and first logon.

**Known Server 2022 gotcha — Server Core / custom shell.** v1.1.11's `restartExplorer` reads `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell` and skips the `taskkill /F /IM explorer.exe & start explorer.exe` step when the registered shell isn't exactly `explorer.exe`. On Server Core or any install with a custom shell, the `NoTaskbar` HKCU policy will still be written but won't take effect until the user logs off and back on — that's fine and intentional, but worth knowing if you're staring at the kiosk wondering why the taskbar is still visible on a Server Core install that's running with `cmd.exe` as its shell.

### Is the HKLM config set?

```powershell
Get-ItemProperty -Path "HKLM:\Software\KioskExitGuard" |
    Select-Object PasswordHash, KioskURL
```

Expect: `PasswordHash` is a non-empty bcrypt blob, `KioskURL` is your kiosk URL.

### Is the HKCU lockdown active (filter currently on)?

```powershell
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name DisableTaskMgr -ErrorAction SilentlyContinue
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoRun, NoTrayContextMenu, NoViewContextMenu, NoTaskbar -ErrorAction SilentlyContinue
```

Expect, while filter is active: all five values present and `= 1` (`NoTaskbar` added in v1.0.6 — hides the taskbar to close the Start-button left-click escape). During a pause: all five values absent.

### Are the IFEO blocks in place?

```powershell
$ifeoRoot = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
foreach ($exe in @("chrome.exe","msedge.exe","sethc.exe","osk.exe","narrator.exe","utilman.exe","magnify.exe")) {
    Get-ItemProperty "$ifeoRoot\$exe" -Name Debugger -ErrorAction SilentlyContinue |
        Select-Object @{N='Exe';E={$exe}}, Debugger
}
```

Expect: every row has `Debugger = "C:\Program Files\KioskExitGuard\kiosk-exit-guard.exe" --silent-exit`. **Permanent** — applies whether the filter is active or paused. The five accessibility helpers (`sethc`, `osk`, `narrator`, `utilman`, `magnify`) were added in v1.0.6 to close the Sticky-Keys-5x-Shift and Ease-of-Access escapes.

### Is a pause currently active?

```powershell
$pausePath = "C:\Program Files\KioskExitGuard\pause_until.state"
if (Test-Path $pausePath) {
    $nano = [int64](Get-Content $pausePath)
    $until = [DateTimeOffset]::FromUnixTimeMilliseconds($nano / 1000000).LocalDateTime
    Write-Host "Pause until: $until ($([Math]::Round(($until - (Get-Date)).TotalSeconds / 60, 1)) min remaining)"
} else {
    Write-Host "No pause file — filter is active."
}
```

## Recovery scenarios

### "I lost the password"

The bcrypt hash is one-way; we cannot recover the password from it. The only recovery is **manual cleanup**:

```powershell
# Run as Admin.
sc stop KioskExitGuardSvc
sc delete KioskExitGuardSvc
Get-Process kiosk-exit-guard | Stop-Process -Force
schtasks /Delete /F /TN KioskExitGuard   # v1.1.4+ AtLogon fallback task (also v1.0.x legacy)
Remove-Item -Recurse -Force "HKLM:\Software\KioskExitGuard"
$ifeoRoot = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
foreach ($exe in @("chrome.exe","msedge.exe","sethc.exe","osk.exe","narrator.exe","utilman.exe","magnify.exe")) {
    Remove-Item -Recurse -Force "$ifeoRoot\$exe" -ErrorAction SilentlyContinue
}
Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name DisableTaskMgr -ErrorAction SilentlyContinue
Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoRun, NoTrayContextMenu, NoViewContextMenu, NoTaskbar -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "C:\Program Files\KioskExitGuard\filter_mode.state","C:\Program Files\KioskExitGuard\pause_until.state" -ErrorAction SilentlyContinue
```

Then re-run the exe to walk through first-run again with a new password.

### "Filter is broken and I can't reach Uninstall"

Use `--reset` to clear the registry lockdown without uninstalling everything:

```powershell
"C:\Program Files\KioskExitGuard\kiosk-exit-guard.exe" --reset
```

Password-gated. Clears `DisableTaskMgr`, `NoRun`, `NoTrayContextMenu`, `NoViewContextMenu`, `NoTaskbar`, all IFEO blocks (browsers and accessibility helpers), and resets `filter_mode.state`. The scheduled task and the HKLM config survive — so on the next launch the controller starts up clean with the same password.

If `--reset` itself fails (HKLM gone, no password to verify), fall back to "I lost the password" above.

### "I ran Uninstall but the kiosk keeps coming back"

This was a v0.5.x bug — fixed in v1.0.2. Symptoms: uninstall completed but the controller process kept running and its watchdog re-spawned the kiosk window.

Manual fix on a v0.5.x install:

```powershell
Get-Process kiosk-exit-guard | Stop-Process -Force
schtasks /Delete /F /TN KioskExitGuard
```

On v1.1.0+ the equivalent rescue stops the Service first so it can't respawn the controller:

```powershell
sc stop KioskExitGuardSvc
sc delete KioskExitGuardSvc
Get-Process kiosk-exit-guard | Stop-Process -Force
```

Then redo Uninstall, which now also kills any process named `kiosk-exit-guard.exe` other than itself before tearing down.

### "Edge launches still get blocked even though I uninstalled"

If `Uninstall SK Filter` reported "some teardown steps reported errors" with `schtasks` or IFEO mentioned, the IFEO blocks may have leaked. Verify with the IFEO query above and manually remove:

```powershell
Remove-Item -Recurse -Force "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\chrome.exe"
Remove-Item -Recurse -Force "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msedge.exe"
```

### "WebView2 Runtime install failed during first-run"

On Windows 11 client SKUs the runtime is pre-installed and this never fails. On Server 2022 / stripped images, manual install:

```powershell
Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/p/?LinkId=2124703" -OutFile "$env:TEMP\MicrosoftEdgeWebview2Setup.exe"
Start-Process "$env:TEMP\MicrosoftEdgeWebview2Setup.exe" -ArgumentList "/silent","/install" -Wait
```

Then re-run kiosk-exit-guard.exe — it'll detect the now-installed runtime and continue normally.

## Install paths (v1.1.8+)

As of v1.1.8 the controller relocates itself at first run, and stores all admin-only data under `%ProgramData%`. Two directories matter:

- **`%ProgramFiles%\KioskExitGuard\`** — the canonical install path. `kiosk-exit-guard.exe` lives here; `kiosk-exit-guard.exe.old` appears here after an `--update` and stays as a rollback target. State files (`filter_mode.state`, `pause_until.state`) also land here. Admin-only DACL (NTFS default on `%ProgramFiles%`).
- **`%ProgramData%\KioskExitGuard\`** — admin-only data root, DACL tightened on every controller startup via `icacls /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F"`. Contains:
  - `staging\` — `--update` downloads the new exe here before atomic-rename. Kept admin-only so a kiosk user can't swap the file between download and install.
  - `WebView2\` — shared user-data folder for all four in-process WebView2 instances (password modal, toast, first-run wizard, kiosk page). Pre-v1.1.8 this was under `%LOCALAPPDATA%` and kiosk-user-writable, which allowed a poisoned service-worker attack on the password modal's `kgSubmit` binding.
  - `pause-just-applied.flag` (v1.1.9) — short-lived marker the `--pause` shortcut writes to suppress the controller's watchdog briefly while `syncFilterStateLoop` flips filterMode. Auto-stale after 5s; safe to delete.

Both directories survive uninstall as a courtesy (delete manually for full removal). The v1.1.8 uninstall flow deletes the contents of `%ProgramFiles%\KioskExitGuard\` and schedules the running exe + dir for delete-on-reboot via `MoveFileExW(MOVEFILE_DELAY_UNTIL_REBOOT)`.

## Logs and diagnostics

There's no log file by design (kiosk machines don't have anywhere good to put one). For diagnostics during development:

- Build without `-H windowsgui` to get a console window for `fmt.Println` output:
  ```
  go build -ldflags="-s -w" -o kiosk-exit-guard-debug.exe
  ```
- Run as a non-elevated user to see UAC prompts and zenity dialogs without the kiosk fighting for focus.
- Use Process Hacker / Process Explorer to inspect the `kiosk-exit-guard.exe` and `kiosk-exit-guard.exe --webview` processes, their HWNDs, and the LL hook installation.

## Upgrading from older versions

| From | Action |
|---|---|
| v0.4.x | Uninstall via PowerShell (legacy uninstall flag may not exist), then install v1.1.x fresh. |
| v0.5.0 – v0.5.5 | Double-click **Update SK Filter** desktop shortcut, or run the new exe — first-run's `purgeLeftoverState()` handles the migration. |
| v1.0.x | Same — Update shortcut handles it. On the next non-first-run launch, the controller calls `installService()` to register `KioskExitGuardSvc` AND `installStartupTask()` to (re)register the AtLogon scheduled task — both auto-start mechanisms are co-installed as of v1.1.4, no longer mutually exclusive. |

The atomic-rename approach in `--update` keeps the previous exe as `.old` next to the new one, so a botched update can be rolled back by renaming back. On v1.1.0+ the update flow does `sc stop KioskExitGuardSvc` before the rename and `sc start` after — as of v1.1.9 it also polls SCM until the service reaches the Stopped state before renaming, so the supervisor can't respawn a fresh controller mid-rename.
