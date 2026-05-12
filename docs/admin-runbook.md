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

Double-click **Update SK Filter**. Hits the GitHub `/releases/latest` API, shows current vs latest. Click Install → password modal → it downloads, atomic-renames the running exe to `.old`, swaps in the new one, restarts the scheduled task.

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

Expect: zero or one row in normal operation. The `--webview` child is a second row when the kiosk is active.

### Is the scheduled task installed?

```powershell
Get-ScheduledTask -TaskName KioskExitGuard -ErrorAction SilentlyContinue |
    Select-Object TaskName, State, @{N='LastResult';E={(Get-ScheduledTaskInfo $_).LastTaskResult}}
```

Expect: `State = Ready` (waiting for next logon trigger) or `Running` (controller is up). `LastResult = 0` means the last execution exited cleanly.

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
Get-Process kiosk-exit-guard | Stop-Process -Force
schtasks /Delete /F /TN KioskExitGuard
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
| v0.4.x | Uninstall via PowerShell (legacy uninstall flag may not exist), then install v1.0.x fresh. |
| v0.5.0 – v0.5.5 | Double-click **Update SK Filter** desktop shortcut, or run the new exe — first-run's `purgeLeftoverState()` handles the migration. |
| v1.0.0 – v1.0.1 | Same — Update shortcut handles it. |

The atomic-rename approach in `--update` keeps the previous exe as `.old` next to the new one, so a botched update can be rolled back by renaming back.
