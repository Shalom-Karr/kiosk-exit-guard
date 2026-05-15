# Changelog

All notable changes to kiosk-exit-guard, newest first. Versions follow [Semantic Versioning](https://semver.org/) with the convention that 1.0.x is the stable line and 0.x was prototyping.

For the current state of the project, see the [landing page](https://shalom-karr.github.io/kiosk-exit-guard/), the [architecture doc](architecture.md), and the [admin runbook](admin-runbook.md).


## v1.3.1 — 2026-05-15

Drop-in zoom override file + two diagnostic log lines.

### zoom.txt drop-in override

`%ProgramData%\KioskExitGuard\zoom.txt` — write a single number into it
(e.g. `90`, `90%`, trailing comment/whitespace tolerated) and the kiosk
renders at that page-zoom on the next `--webview` launch, no need to
go through the `--set-url` WebView2 form. Precedence: zoom.txt **wins**
over the registry `KioskZoom` DWORD AND syncs back into it, so the
`--set-url` form's pre-fill stays consistent — the file is the source
of truth on each launch. `loadKioskZoomPercent` now resolves
zoom.txt → registry → default(100); `registryZoomPercent` was split
out so the sync path can compare without recursing. Only the first
whitespace-delimited token is parsed and the value is clamped to
50–200, so a fat-fingered `9000` renders at 200% rather than breaking
layout.

### New log lines

- `kiosk: rendering "<url>" at zoom <n>%` — emitted by `runWebViewKiosk`
  on every kiosk paint, so the field log shows both the URL and the
  resolved zoom (after zoom.txt/registry resolution). When zoom.txt
  drives the value you also get `loadKioskZoomPercent: zoom.txt=<n>
  (raw <r>) synced to registry (was <old>)`.
- `watchdog: kiosk child not running — relaunching (next tick in 30s)`
  — emitted only on the relaunch transition (child found dead). A tick
  that finds the child alive stays silent so the 30 s cadence doesn't
  flood the log. `watchdog: filter active but pause-just-applied
  marker set — skipping relaunch this tick` covers the v1.1.9
  kiosk-blink-suppression window.


## v1.3.0 — 2026-05-15

Four field-reported runtime fixes (contributed via Copilot cloud-agent
PRs #2–#4). These close out the elevation / SID-mapping / log-path
problems chased across the v1.2.x line.

- **installStartupTask SID mapping.** `New-ScheduledTaskPrincipal`
  used `$env:USERNAME`, which evaluates to `SYSTEM` (or empty) when
  the function runs in the LocalSystem service context — Task
  Scheduler can't map that to an interactive-logon SID and returned
  `HRESULT 0x80070534` ("No mapping between account names and security
  IDs was done"), the error that flooded the v1.2.3 field logs. Now
  resolves the real interactive user via `os/user.Current()`, strips
  the `DOMAIN\` prefix, passes it as `KEG_USER`, and fails early with
  a meaningful log line if the user still can't be resolved.
- **parentProcessImagePath.** `ERROR_GEN_FAILURE (31)` ("a device
  attached to the system is not functioning") is now absorbed
  silently like the other expected parent-already-exited errors,
  instead of logging a scary line every service-spawn.
- **Log path moved to `%ProgramData%\KioskExitGuard\logs\`.** v1.2.9's
  `<install-dir>/logs/` layout failed once the exe relocated to
  `C:\Program Files\KioskExitGuard\` — standard users can't create
  files there. `%ProgramData%` is user-writable and already hosts the
  WebView2 data dir. `cleanupInstallDir` allowed-subdirs gained
  `logs` for the transitional case.
- **Service spawn privileges.** `enableServiceSpawnPrivileges` now
  enables `SeAssignPrimaryTokenPrivilege` + `SeIncreaseQuotaPrivilege`
  on the process token before `CreateProcessAsUser`. LocalSystem holds
  these by default but they're disabled; enabling them is the root-
  cause fix for the `ERROR_ELEVATION_REQUIRED` spawn loop the v1.2.3
  linked-token swap only treated symptomatically. Applied to both the
  Service supervisor path and `spawnFlagAsUserInSession`.

Release workflow also gained a `workflow_dispatch` trigger so a failed
build can be re-run from the Actions tab without pushing a new tag.


## v1.2.9 — 2026-05-13

Bundles the four queued items from v1.2.8: WebView2 URL/zoom form,
six-hour log rotation in a `logs/` subdirectory, version-suffixed
desktop shortcut filenames, and double-right-click → pause via a new
LL mouse hook.

### WebView2 URL/zoom form replaces the zenity entries

`--set-url` previously chained two `zenity.Entry` dialogs (one for
URL, one for zoom). Native Windows dialogs center themselves on the
screen with no programmatic positioning, so an AnyDesk admin whose
session bar overlapped the middle of the viewport couldn't reliably
reach the input. v1.2.9 replaces both with `runSetURLAndZoomDialog` —
a single branded WebView2 form matching the password modal's color
scheme, with URL + zoom inputs, validation messages, and a fixed
top-aligned layout (`.wrap { align-items: flex-start; padding-top:
4vh }`). Fall-back path: if `webview2.NewWithOptions` returns nil
(WebView2 runtime broken), we drop to the legacy zenity prompt so
admins on stripped-down boxes still have a path to change the URL.

### Six-hour log rotation in `<install>/logs/`

`initLogging` no longer writes to a single growing
`kiosk-exit-guard.log` next to the exe. Instead it creates a `logs/`
subdirectory and writes per-bucket files named
`kiosk-exit-guard-YYYY-MM-DD-HH.log` where HH ∈ {00, 06, 12, 18} —
four files per day. `logf` checks the bucket label against the
currently-open file on every write and rolls over when the boundary
crosses. The previous "5 MB → .log.old" size-based rotation handed
back a single coarse blob; v1.2.9's time buckets let an admin
investigating a field report jump straight to the relevant slice.

New log lines on rollover: `--- rolled into new bucket v%s pid=%d ---`
so each bucket file is self-describing for the reader.

`cleanupInstallDir`'s allowed-subdirs list grew `logs` so uninstall
can wipe the rotated files alongside the staging directory.

### Version-suffixed desktop shortcut filenames

Each `.lnk` createDesktopShortcut writes is now named
`<action> v<version>.lnk` — e.g. `Pause SK Filter v1.2.9.lnk`,
`Update SK Filter v1.2.9.lnk`. A glance at the desktop tells you the
installed version. `removeStalePerUserShortcuts` and
`removeDesktopShortcuts` switched from a fixed seven-name list to two
glob patterns per action (`<action>.lnk` legacy + `<action> v*.lnk`
versioned) so an upgrade cleans up old-version files alongside the
pre-v1.2.9 unversioned ones. `Remove-Item -ErrorAction SilentlyContinue`
absorbs missing-file cases.

### Double-right-click pauses the filter (LL mouse hook)

New `mouseCallback` installed via `SetWindowsHookExW(WH_MOUSE_LL, …)`
alongside the keyboard hook. Watches WM_RBUTTONDOWN events and on a
second right-button-down within 500 ms and ≤30 screen pixels of the
previous one, fires `promptAndPause` — the same flow Ctrl+Shift+Alt+K
triggers. Events pass through unmodified (we don't swallow
right-clicks); the prompt opens on top.

Honors both `LLMHF_INJECTED (0x01)` and `LLMHF_LOWER_IL_INJECTED
(0x02)`, so AnyDesk-forwarded right-clicks trigger the prompt the
same way local hardware clicks do — the deliberate mouse-side admin
escape hatch matching the keyboard side's K hotkey carve-out.

Hook install failure is non-fatal: a `WARN: SetWindowsHookEx (mouse
LL) failed: %v` line lands in the log and the keyboard hook (the
primary enforcement path) continues running.


## v1.2.8 — 2026-05-13

Admin hotkeys + AnyDesk reliability + top-aligned password modal for
the URL-change flow.

### New hotkeys — Ctrl+Shift+Alt+U (update) and Ctrl+Shift+Alt+C (change URL)

Two siblings of the existing Ctrl+Shift+Alt+K pause hotkey. Both spawn
the corresponding `--update` / `--set-url` invocation as a detached
child via the new `launchSelfWithFlag` helper, so the action runs in
the user's session with its own password modal + GitHub fetch (for
update) or password modal + URL/zoom entry (for set-url). All three
hotkeys (K, U, C) work from both local physical keyboard *and*
injected input (AnyDesk, AutoHotkey).

### Fix — AnyDesk Ctrl+Shift+Alt+K now actually triggers

v1.2.4 added an injected-key carve-out for the pause hotkey but
checked only `LLKHF_INJECTED (0x10)`. AnyDesk's keyboard-forwarding
worker runs at user-medium integrity level while the kiosk runs at
user-high IL (it carries a `requireAdministrator` manifest), so
remote-typed keys actually arrive with `LLKHF_LOWER_IL_INJECTED (0x02)`
in the LL hook struct flags — *not* 0x10. The carve-out silently never
fired.

v1.2.8 introduces `llkhfAnyInject = llkhfInject | llkhfLowerIlInject`
and treats either bit as "injected" for the K/U/C carve-outs. New
`logf` lines at the injected-detection site (`hook: injected
Ctrl+Shift+Alt+<K|U|C> detected (flags=0x%02x) — triggering ...`) make
the path observable in `kiosk-exit-guard.log` so a future
no-hotkey-from-AnyDesk report can be diagnosed in one log read.

### Password modal can render top-aligned

New `askPasswordModalTop(title, subtitle)` is the top-aligned sibling
of `askPasswordModal`. The child `--ask-password` process receives the
hint via env var `KEG_ASK_PASSWORD_TOP=1`; the password HTML reads
`window.__topAlign` and adds a `.top` class on `.wrap` that switches
`align-items` from `center` to `flex-start` with `padding-top: 4vh`.
Used by the `--set-url` flow so admins driving via AnyDesk can reach
the password input even when AnyDesk's session bar overlays the
center of the viewport.

### Known gaps tracked for v1.2.9

- URL/zoom entry after the password modal still uses `zenity.Entry`
  (native Win32 dialog, no programmatic positioning). Replacing it
  with a WebView2 form that lays out at the top is queued.
- Desktop .lnk filenames don't yet carry the version suffix.
- Log rotation (six-hour buckets in a `logs/` subfolder) not yet
  implemented — the log file still grows indefinitely as
  `kiosk-exit-guard.log`.
- Double-right-click → pause-filter prompt (mouse hook) not yet wired.


## v1.2.7 — 2026-05-13

Disable Win+L (lock workstation) via the canonical Windows registry
policy. Win+L is intercepted by `winlogon.exe` at a layer beneath the
LL keyboard hook — the v1.2.6 always-block + Win-modifier swallow can
suppress the visible Start menu hop, but the lock initiates anyway
because winlogon sees the key combo first. The proper Windows
mechanism is the policy
`HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableLockWorkstation = 1`,
which disables Win+L *and* the Start menu's "Lock" entry at the OS
level. v1.2.7 sets this in `applyLockdown` alongside the existing
DisableTaskMgr / NoRun / NoTrayContextMenu / NoViewContextMenu /
NoTaskbar policies, and clears it in `removeLockdown` so an
uninstall/reset restores the lock-screen shortcut.

### Other system commands

The pre-existing modifier+key block already catches everything else
in the Win+key family (Win+R, Win+E, Win+I, Win+D, Win+X, Win+.,
Win+Tab) — the LL hook swallows them and routes through the
password-prompt path. Win+L was the one outlier because of the
winlogon-level interception. Ctrl+Alt+Del (Secure Attention Sequence)
remains genuinely unblockable from user mode — it requires a
kernel-mode filter driver, which is outside scope for kiosk-exit-
guard.


## v1.2.6 — 2026-05-13

Lockdown widening: bare F1–F12, Tab, Escape, AppMenu (right-click
keyboard key), PrintScreen, and Insert are now swallowed and route
through the password-prompt path, even with no modifier held. Pre-
v1.2.6 the LL keyboard hook only caught `<modifier> + key` combos,
so a bare F11 (toggle browser fullscreen), F12 (DevTools), Tab (focus
next form field / address bar in normal Edge), or Escape (exit
fullscreen / close modals) all fell straight through to the kiosk
URL.

### What changed

- New `isAlwaysBlockedKey(vk)` helper in `main.go` returns true for
  the keys above. The hook calls it inside the existing
  `filterMode.Load()` branch, before the modifier+key block. Match
  triggers `promptAndReinject` (the same UX path as Win+R etc.) so
  an admin can authenticate and let the key through.
- `isAlwaysAllowedCombo` lost its bare-F5 case. F5 alone was an
  intentional v1.0 carve-out for page reload, but it conflicted with
  the new always-block list. Admins who want a manual reload still
  have Ctrl+R.
- `sendKeyCombo` already handles the bare-key re-injection case (no
  modifiers in the slice → just press+release the VK with the
  kiosk-exit-guard marker so the hook lets it through).

### What still works (intentionally not blocked)

- Letters, numbers, space, punctuation, Enter, Backspace, Delete —
  normal form fill-in on the kiosk page.
- Arrow keys, Home/End/PgUp/PgDn — page scrolling.
- Ctrl+R, Ctrl+0/+/− — manual reload and browser zoom (unchanged
  Ctrl-only allowlist).
- Caps Lock, Num Lock, Scroll Lock — toggle keys, not commands.
- AnyDesk-injected Ctrl+Shift+Alt+K — pause-hotkey carve-out from
  v1.2.4 is preserved; the new block list runs inside the
  `!injected && !ourInjection` branch.


## v1.2.5 — 2026-05-13

UI/UX audit pass for unusual viewports (sideways 4K TVs at 300% display
scaling, low-DPI 1080p landscape, etc.), plus a zoom-target fix that
prevents kiosk pages from accidentally double-zooming themselves on top
of the v1.2.4 admin-configured zoom, plus stale-shortcut cleanup so an
upgrade from <v1.2.4 doesn't leave the old direct-to-exe .lnks
alongside the new schtasks-routed ones.

### Fix — modal cards no longer stretch on wide monitors

v1.2.4's `passwordPromptHTML` and `autoUpdateNotifyHTML` both declared
`.card { width: 100% }` with no max. On a 1920×1080 landscape kiosk
the password input stretched into a tubular 1800px-wide field with the
lock icon floating at the far left and action buttons at the far
right. v1.2.5 caps both at `max-width: 540px`. The first-run wizard
card grew from 520px → 560px to fit the new zoom field added in v1.2.4
without crowding the help text.

### Fix — modal forms now scroll into view on short viewports

All three modal `<wrap>` containers switched from `height: 100vh` +
`overflow: hidden` (which clipped the top of the card when content
exceeded viewport height) to `min-height: 100vh` + `overflow-y: auto`.
The first-run wizard's 7-field form (pw1, pw2, url, zoom, error,
actions, plus header) is the biggest beneficiary — on a tight portrait
viewport or with accessibility text scaling, the card now scrolls
naturally instead of vanishing off the top edge.

### Fix — kiosk zoom no longer compounds with page-side zoom scripts

v1.2.4 injected `document.documentElement.style.zoom = pct / 100` —
i.e. zoom on `<html>`. A kiosk page that also runs its own
`document.body.style.zoom = '0.9'` fallback (so the page renders at
90% in regular browsers without kiosk-exit-guard installed) would land
on `<body>` while we landed on `<html>`. CSS `zoom` compounds across
nested elements, so the rendered scale became `<html> × <body>` —
e.g. 0.9 × 0.9 = 0.81 instead of the intended 0.9.

v1.2.5 targets `document.body.style.zoom` instead. Both code paths now
write to the same element, so the values don't multiply. Admin config
still wins: the injection fires at DOMContentLoaded AND `window.load`,
both of which run after any inline `<script>` in the page body, so an
admin-configured 80% overrides a page-side 90% to 80%. A page-side
idempotence check (`parseFloat(document.body.style.zoom)`) now
correctly observes our value on SPA re-renders.

### Fix — upgrade from <v1.2.4 cleans up stale per-user-desktop .lnks

v1.2.4 moved the shortcut .lnks from the running user's desktop to
`CommonDesktopDirectory` (so every logged-in user sees them). But
pre-v1.2.4 installs wrote to the per-user desktop with TargetPath =
`kiosk-exit-guard.exe` (direct, UAC-triggering); upgrading to v1.2.4
left those orphans next to the new public-desktop ones, so the user
saw double shortcuts and the old direct-to-exe set still fired UAC.

v1.2.5's `removeStalePerUserShortcuts()` runs at the top of
`createDesktopShortcut` (which is called on every controller startup
that isn't a Service spawn) and deletes the seven legacy .lnk
filenames from `[Environment]::GetFolderPath('Desktop')`. Then the
new schtasks-routed .lnks get written to `CommonDesktopDirectory` as
in v1.2.4. Idempotent — missing files are absorbed by
`Remove-Item -ErrorAction SilentlyContinue`.

Limitation: only the currently-running user's per-user desktop is
cleaned. A multi-user kiosk where a different admin originally ran
the wizard still has stale .lnks on that other admin's desktop until
they log in once with v1.2.5+.


## v1.2.4 — 2026-05-12

Two related fixes that both target "make the kiosk's admin surface
actually usable post-install": a shortcut + scheduled-task overhaul so
non-admin users can trigger Pause / Resume / Launch Kiosk / Update /
Change URL / Uninstall without UAC, and a small carve-out to let the
Ctrl+Shift+Alt+K pause hotkey fire from injected keyboard input
(AnyDesk, AutoHotkey, remote shells).

### Fix — desktop shortcuts now route through SYSTEM scheduled tasks

**Before v1.2.4** each .lnk pointed straight at
`kiosk-exit-guard.exe --pause` (etc.). The exe carries a
`requireAdministrator` manifest, so every click fired a UAC consent
prompt; for non-admin kiosk users the operation simply failed with
"Access is denied" because they couldn't pass the prompt and didn't
have HKLM write rights anyway. Shortcuts also landed on the wizard
runner's desktop (typically admin) — a separate non-admin kiosk user
never saw them.

**v1.2.4 introduces a shortcut → scheduled-task → spawn-into-session
indirection:**

1. **`installShortcutTasks()`** registers one Task Scheduler entry per
   action under the names `KioskExitGuard_Pause`,
   `KioskExitGuard_Resume`, `KioskExitGuard_LaunchKiosk`,
   `KioskExitGuard_Update`, `KioskExitGuard_SetURL`,
   `KioskExitGuard_Uninstall`. Each task runs as
   `NT AUTHORITY\SYSTEM` with `HighestAvailable` run level and on-
   demand only (no trigger). The action invokes
   `<canonical-exe> --shortcut-handler <flag>`. Default DACL on a
   SYSTEM/HIGHEST task already grants `BUILTIN\Users`
   Read + Execute — which is exactly the "any logged-in user can /Run
   this" permission the shortcuts need.

2. **`createDesktopShortcut()`** rewrites each .lnk to point at
   `%SystemRoot%\System32\schtasks.exe` with arguments
   `/Run /TN KioskExitGuard_<Action>`. The IconLocation still points
   at `canonicalInstallPath()` so the brand icon survives. WindowStyle
   = 7 (Minimized) hides the brief schtasks console flash on click.
   Shortcuts are now placed in `CommonDesktopDirectory` (the
   public/all-users desktop) instead of the per-user desktop, so every
   logged-in user sees them — fixes the "admin ran the wizard and the
   non-admin kiosk user has a blank desktop" case.

3. **`runShortcutHandler(flag)`** is the new `--shortcut-handler`
   entry point. The scheduled task fires it as SYSTEM in session 0;
   it calls `pickActiveUserSession()` (the same picker the Service
   uses) and `spawnFlagAsUserInSession(sessionID, flag)` to spawn
   `<canonical-exe> <flag>` in the active user's session with that
   user's primary token. `spawnFlagAsUserInSession` is the v1.2.4
   sibling of `spawnControllerInSession` in `service_windows.go`:
   same `WTSQueryUserToken` / `tokenFromUserSessionProcess` / v1.2.3
   `elevatedLinkedToken` swap, but spawns `<exe> <flag>` and does NOT
   set the `KIOSK_EXIT_GUARD_VIA_SERVICE` marker — the spawned child
   should behave exactly like an admin double-clicking the flag
   directly, not like a service-spawned controller.

4. The spawned child renders the password modal / duration picker /
   kiosk window / etc. on the user's desktop, then exits.

**Net effect for the user:** clicking a desktop shortcut no longer
shows UAC for split-token admin kiosks; the .lnks live on the public
desktop and show the canonical exe's icon; the shortcuts still
trigger exactly the same operation (with exactly the same password
modal) they always did, just routed through a SYSTEM context that has
the privileges to actually finish the work.

**Known limitation, true non-admin kiosk users:** when
`spawnFlagAsUserInSession` runs against a user whose primary token has
no elevated linked counterpart (a real Standard User account, not a
split-token admin), `CreateProcessAsUser` against the
`requireAdministrator` exe still returns `ERROR_ELEVATION_REQUIRED` —
exactly the same failure mode the v1.2.3 `spawnControllerInSession`
path has for that case. Fully supporting non-admin kiosk users
requires a follow-up: either flip the manifest to `asInvoker` and
move the privileged operations into a SYSTEM-side dispatcher, or run
the action body directly inside the SYSTEM task instead of spawning
into the user session. Tracked as future work.

### Feature — kiosk page zoom (50–200%, persisted in HKLM)

The "Change Kiosk URL" shortcut now also prompts for a default page-
zoom percent, and the first-run wizard grew a matching `Default page
zoom (%)` field next to the URL input. Values are clamped to 50–200,
default is 100, persisted as `KioskZoom` (DWORD) under
`HKLM\Software\KioskExitGuard` next to `KioskURL`.

`runWebViewKiosk` reads the persisted percent at startup and injects
an IIFE inside the existing `w.Init` block (the same one that already
hosts the link-prefix click guard). The IIFE sets
`document.documentElement.style.zoom = pct / 100` on both
`DOMContentLoaded` and `load` — covering the initial paint AND any
SPA-framework re-render that overwrites inline styles on `<html>`.
This is the CSS `zoom` property, the same mechanism Ctrl +/− triggers
in a browser; pages lay out at the scaled size and scrollbars adjust.

Existing installs without the registry key default to 100% — no
behavior change. Setting 90 once via the shortcut persists across
kiosk respawns, pause/resume cycles, and auto-updates.

### Fix — Ctrl+Shift+Alt+K pause hotkey now fires from injected input

Pause hotkey (Ctrl+Shift+Alt+K) now fires from injected keyboard input —
specifically AnyDesk, AutoHotkey, and any other tool that forwards
keystrokes via `SendInput`. Before v1.2.4 the LL keyboard hook ignored
all injected events wholesale, which meant an admin remoting into a
fullscreen kiosk via AnyDesk had no way to trigger the password modal
without physical access to the keyboard. v1.2.4 carves out exactly one
combo from the ignore-injected rule: Ctrl+Shift+Alt+K (key-down, with
all three modifiers held). Every other injected event still falls
straight through to `procCallNextHookEx` unmodified, so AnyDesk typing,
paste, mouse macros, etc. keep working exactly as before.

### Cause

`hookCallback` (main.go:2436) early-rejects every event where
`(kb.Flags & llkhfInject) != 0` is true and `DwExtraInfo != kioskMarker`
— i.e. anything injected by another process. The rationale is sound
for the broad case: the kiosk user can't physically inject, and we
don't want the kiosk's enforcement applied to legitimate remote-admin
keystrokes. But the pause-hotkey detection lived inside the same
`if !injected && !ourInjection { ... }` block, so the only way to
trigger the password modal was the local physical keyboard.

### Fix

A narrow new branch at the top of `hookCallback`, *before* the
existing `!injected && !ourInjection` gate:

```go
isKeyDownAny := wParam == wmKeyDown || wParam == wmSysKeyDown
if injected && !ourInjection && isKeyDownAny &&
    kb.VkCode == vkK && ctrlDown() && shiftDown() && altDown() {
    if !promptOpen.Load() {
        go promptAndPause()
    }
    return 1
}
```

- **Scope is one combo.** Only `vkK` with Ctrl + Shift + Alt held
  matches. Everything else (injected Win, injected Win+R, injected
  Ctrl+Esc, injected typing into the kiosk page) hits the existing
  fall-through path and behaves exactly as in v1.2.3.
- **`ctrlDown` / `shiftDown` / `altDown` see injected modifier state.**
  They wrap `GetAsyncKeyState`, which Windows updates regardless of
  whether the modifier-down event was injected. So AnyDesk's
  `SendInput(Ctrl-down, Shift-down, Alt-down, K-down)` chain leaves
  the async state reflecting all three modifiers by the time the K
  event arrives at the hook.
- **`ourInjection` is excluded.** A re-inject path that ever carried
  the exact same combo can't loop through this branch.
- **`promptOpen.Load()` gate** matches the existing physical-keyboard
  path so an AnyDesk admin who mashes the hotkey while the modal is
  already open doesn't spawn a second one.

### Reverse-direction note

Keystrokes the kiosk user types on the **local physical keyboard** are
unchanged — they were never injected, so the existing
`!injected && !ourInjection` branch already handles them. v1.2.4 is
purely additive: a remote admin path that didn't exist before, with no
behavioral change for any other input source.


## v1.2.3 — 2026-05-12

Companion hotfix to v1.2.2. With the WebView2 data-directory ACL fixed,
the next layer of the v1.1.8+ Win 11 breakage surfaced: the Windows
Service spun in a 2-second respawn loop, logging

```
service: spawnControllerInSession(1) failed: CreateProcessAsUser:
  The requested operation requires elevation.
```

every tick — meaning no controller, no kiosk window, no keyboard hook,
no filter enforcement. v1.2.3 makes the spawn succeed by handing
CreateProcessAsUser the user's elevated linked token instead of the
filtered one.

### Cause

`spawnControllerInSession` (service_windows.go:717) gets the target
session's user token via `WTSQueryUserToken`, then duplicates it and
calls `CreateProcessAsUserW`. On Win 11 Home with a split-token
administrator (UAC enabled), `WTSQueryUserToken` returns the
**filtered** (limited) primary token — the one Explorer.exe runs
under. `app.manifest` declares

```xml
<requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
```

so Windows refuses to launch kiosk-exit-guard.exe under a non-elevated
token and `CreateProcessAsUser` fails with **ERROR_ELEVATION_REQUIRED
(740)**. The Service's supervisor goroutine retries every 2 s,
producing the loop seen in field logs.

The fallback path (`tokenFromUserSessionProcess`, used only when
`WTSQueryUserToken` *itself* errors — Win 11 Home / ERROR_NO_TOKEN
edge case) already calls `elevatedLinkedToken` at line 960 to swap
the filtered token for its elevated linked counterpart. The primary
path didn't, so any install where `WTSQueryUserToken` succeeded but
returned a filtered token would deadlock on launch.

### Fix

After a successful `WTSQueryUserToken` call, run the same swap the
fallback path uses:

```go
if elevated, eErr := elevatedLinkedToken(userToken); eErr == nil && elevated != 0 {
    _ = userToken.Close()
    userToken = elevated
    logf("service: swapped WTSQueryUserToken's filtered token for its elevated linked counterpart")
}
```

`elevatedLinkedToken` returns `(0, nil)` when the token isn't split
(UAC off, built-in administrator, already full elevation), in which
case the original token is kept as-is — so non-split-token boxes are
unaffected. Errors from `GetTokenInformation` are logged and the
filtered token is used as a best-effort fallback (won't help on
require-admin manifests, but avoids regressing the rare case where
`TokenLinkedToken` fails on a token that's actually already elevated).

### Diagnostics

Every controller spawn now logs one of:

- `service: swapped WTSQueryUserToken's filtered token for its elevated linked counterpart` — split-token admin path, the v1.2.3 fix kicked in
- `service: elevatedLinkedToken on WTS token failed (%v); proceeding with filtered token` — GetTokenInformation error, rare
- (no message) — token was already non-split (built-in admin / UAC off / linked-token elevation), no swap needed
- `service: WTSQueryUserToken failed (%v); user-session-process fallback found <%s> in session %d` — pre-v1.2.3 fallback path, unchanged

so a field log makes it obvious which spawn path each install is on.


## v1.2.2 — 2026-05-12

Hotfix for a v1.1.8 regression: on Windows 11, the controller's WebView2
instances (kiosk page, first-run wizard, password modal, toast, and the
v1.2.1 auto-update notify) refused to launch with **"Microsoft Edge
can't read and write to its data directory:
C:\ProgramData\KioskExitGuard\WebView2\EBWebView — We couldn't create
the data directory."**

### Cause

`ensureWebView2DataDir` (added in v1.1.8 to address security finding
HIGH#4 — kiosk user planting a service worker in `%LOCALAPPDATA%`)
called `ensureAdminOnlyDir`, which ran:

```
icacls <path> /inheritance:r
              /grant:r SYSTEM:(OI)(CI)F
              /grant:r Administrators:(OI)(CI)F
```

stripping inheritance and granting only SYSTEM + BUILTIN\Administrators.
But per the comment at `acquireAdminOnlyNamedMutex` (and the actual
LocalSystem→user-session spawn path), the controller runs **as the
kiosk user** — a standard, non-admin account. So `msedgewebview2.exe`,
spawned in that user's token, could not create the `EBWebView`
subdirectory under the admin-only path. The very process the HIGH#4
DACL was meant to protect couldn't access the folder it was supposed
to use.

The regression manifested on every fresh v1.1.8+ install where the
kiosk account was not a member of `Administrators` — i.e. every
correctly-locked-down kiosk.

### Fix

`ensureWebView2DataDir` no longer calls `ensureAdminOnlyDir`. It does
a plain `os.MkdirAll` and then runs:

```
icacls <path> /grant BUILTIN\Users:(OI)(CI)M
```

so the running user can read+write the profile. The grant is
idempotent and additive — re-running on a fresh install is a no-op
beyond the ACE refresh, and on a v1.1.8–v1.2.1 install whose DACL was
previously stripped, the new ACE is added on top (the stripped
inheritance flag is irrelevant once an explicit Users ACE exists).

`ensureAdminOnlyDir` itself is **unchanged** — it still applies the
hardened DACL to the update-staging directory under
`%ProgramData%\KioskExitGuard\staging\` (v1.1.8 CRITICAL#2), which
correctly needs the kiosk user locked out so they can't poison the
downloaded exe between SHA-256 verification and atomic swap.

### Repairing an existing broken install

If a machine is already running v1.1.8 – v1.2.1 and the WebView2 dir
was created with the broken DACL, upgrading to v1.2.2 alone is not
enough — the new `/grant` runs but the call site is in the kiosk
user's context and lacks WRITE_DAC on the existing admin-only dir, so
the grant fails silently. Either of the following from an elevated
admin shell fixes it:

```
rmdir /S /Q C:\ProgramData\KioskExitGuard\WebView2
```

(simpler — next launch recreates with the correct DACL) or

```
icacls "C:\ProgramData\KioskExitGuard\WebView2" /grant "Users:(OI)(CI)M" /T
```

(preserves the existing profile, applies the new ACE recursively).

### Security trade-off

The original HIGH#4 finding observed that a kiosk user with normal
filesystem access to `%LOCALAPPDATA%` could plant a service-worker
script that intercepts the password modal's `kgSubmit` JS binding.
v1.2.2 mitigates this less than v1.1.8 claimed to: `Users:Modify` on
the profile directory means the kiosk user can still plant such a
script via direct file-write, just at a less-obvious path
(`%ProgramData%`).

In practice the v1.1.8 fix already failed at this — all five
WebView2 purposes (kiosk page, password modal, toast, wizard, update
notify) shared the same `DataPath`, so a service worker installed by
the kiosk page itself would have been inherited by the password modal
regardless of DACL. The per-purpose-DataPath isolation that actually
closes this hole is tracked as future work; v1.2.2 ships only the
minimum change needed to restore functionality on Win 11.


## v1.2.1 — 2026-05-12

Background auto-update check + interactive admin notification. The
controller now polls GitHub's `/releases/latest` on startup (after a
60 s settle delay so the kiosk has time to paint) and every 24 h
thereafter; when a newer version is published it spawns a branded
WebView2 modal asking the admin whether to install now. The existing
`--update` shortcut still works exactly as before — this is purely an
additive notification path so an admin doesn't have to remember to
click "Update SK Filter" themselves to find out a new version exists.

### Feature — auto-update background checker

New `runAutoUpdateChecker` goroutine started from the controller's
`main()` right after the LL keyboard hook is installed, alongside the
existing `runWatchdog` and `syncFilterStateLoop` goroutines. Waits
`autoUpdateInitialDelay = 60 * time.Second` for the kiosk WebView2
child to paint and the controller to settle into steady state, then
runs `autoUpdateCheckOnce`. After that, ticks on
`autoUpdateCheckInterval = 24 * time.Hour`. Every check logs one of:

- `auto-update check: triggered`
- `auto-update check: on latest (v%s)`
- `auto-update check: new version v%s available; spawning notify child (current v%s)`
- `auto-update check: fetchLatestRelease error (silently ignored): %v`

so admins reading `kiosk-exit-guard.log` can audit when updates were
detected and what the admin chose. Network errors are silently logged
— no toast, no user-visible noise.

The checker is started **only** from the long-lived controller path.
Every short-lived flag invocation (`--silent-exit`, `--show-toast`,
`--ask-password`, `--webview`, `--pause`, `--resume`,
`--launch-kiosk`, `--update`, `--uninstall`, `--set-url`, `--reset`,
`--service-install`, `--service-remove`, and the new
`--auto-update-notify` itself) returns earlier in `main()` without
ever reaching the goroutine launch. Otherwise every desktop-shortcut
click would spawn a checker that immediately exits, hammering GitHub.

### Feature — `--auto-update-notify <newver>` modal child process

New short-lived child process spawned by the controller when a newer
release is found. Renders a branded WebView2 modal (same dark
gradient, `--accent`, lock-icon header, brand pill, and sans-serif
stack as the v1.2.0 password modal) with two buttons:

- **Update Now** — fire-and-forget spawns
  `kiosk-exit-guard.exe --update`, which then pops the existing
  password modal, downloads the new exe, SHA-256 verifies it against
  the release's sidecar, atomic-swaps the running exe, and restarts
  the Service. The point of routing through `--update` (rather than
  doing the install directly from the notify child) is that the admin
  password is the confirmation of intent — auto-update **never**
  installs silently.
- **Remind Me Later** — exits the notify child with code 1. The 24 h
  ticker catches them on the next cycle.

Both `kgUpdateNow` and `kgLater` host bindings are exposed to the
modal JS. Escape and Alt+F4 also trigger `kgLater`. A 60 s auto-
dismiss timer (`autoUpdateDismissTimeout`) is armed inside a `kgReady`
binding fired from `DOMContentLoaded` so the budget starts when the
admin can actually click, not when WebView2 begins cold-starting —
same idiom as v1.2.0's password-modal timer fix. A 90 s pre-paint
fallback timer guards against a catastrophic WebView2 paint failure
where `kgReady` never fires.

The modal uses `makeModalFullscreenTopmost` + `forceForeground` so it
grabs keyboard focus and sits above the kiosk's fullscreen topmost
window, and `ensureWebView2DataDir()` so the user-data folder is the
admin-only `%ProgramData%\KioskExitGuard\WebView2\` path instead of
the user-writable default.

Running as a separate process avoids go-webview2's
second-`NewWithOptions`-in-the-same-process panic — same child-
process WebView2 pattern as v1.1.3's `--ask-password` and v1.1.9's
`--show-toast`. The branded modal HTML is a separate const
(`autoUpdateNotifyHTML`) from `passwordPromptHTML` so any future edit
to one can't accidentally leak input handlers into the other.

### Feature — `Global\KioskExitGuardAutoUpdateNotify` mutex

Admin-only DACL via `acquireAdminOnlyNamedMutex` (same SDDL helper
introduced in v1.2.0 for the controller / first-run / update
mutexes). Acquired by the notify child at startup and held for its
lifetime. If a second auto-update tick fires while a previous notify
modal is still on screen (admin walked away from it), the second
child exits silently and the first stays up. Closes the
"two stacked notify modals after a 24 h walk-away" hole.

### Misc

- Self-update happy-path `--update` is unchanged. SHA-256 sidecar
  verification, atomic install swap, default-No prompt on missing
  sidecar — all the v1.2.0 plumbing carries forward.
- WebView2 fallback: if `webview2.NewWithOptions` returns nil on the
  notify child (stripped-down machine without the Runtime), we fall
  back to a `zenity.Question` so the admin still gets a choice.


## v1.2.0 — 2026-05-12

Consolidation release combining the v1.1.5–v1.1.11 work into a single
shipping line, plus an audit pass that fixed one CRITICAL struct-layout
bug, three HIGH-severity install/update issues, four MEDIUM items
(modal-timer race, multi-RDP-user visibility, update mutex, go-vet
annotation), two LOW items (atomic install swap, uninstall allowlist),
and one INFO finding (controller-mutex DACL).

### CRITICAL — wtsProcessInfoW struct layout was wrong

`service_windows.go` modeled `WTS_PROCESS_INFOW` as a 32-byte struct
with explicit 4-byte padding fields between the two DWORDs (SessionId,
ProcessId) and the following pointers. The real Win32 layout on x64
packs the two DWORDs into a single 8-byte slot and is 24 bytes total.
With the wrong layout, the Go side walked the WTS-allocated array with
a stride 8 bytes larger than each entry, mismatched `SessionId` /
`ProcessId` interpretations, and dereferenced garbage pointers for
`ProcessName`. The runtime size assertion at the call site caught most
of the damage by aborting the enumeration with a `size mismatch` log
line, but on hosts where Go happened to lay the struct out as 32 bytes
the function returned silently-wrong results.

Fix: drop the padding fields so the struct is 24 bytes, matching the
actual ABI. Added compile-time size assertions for both
`wtsProcessInfoW` and `wtsSessionInfoW` — the build fails if either
struct ever drifts off 24 bytes, so we can't ship a working binary with
a broken layout again.

### HIGH — silent SHA-256 sidecar absence was a downgrade attack vector

Pre-v1.2.0, `runUpdateInvocation` logged
"proceeding without integrity verification (legacy release)" whenever
the release didn't publish a `kiosk-exit-guard.exe.sha256` sidecar, and
installed the binary anyway. An attacker who could MITM the download
URL only needed to also strip the sidecar URL from the GitHub release
metadata (or trick the admin into pulling from a release that never
had one) and we'd cheerfully install whatever they served.

Fix: when the sidecar URL is empty, show a default-No
`zenity.Question` explaining that integrity verification is unavailable
and ask the admin to confirm. Cancel / window-close / any other error
aborts the install. Only an explicit "Yes" lets the update proceed,
and the choice is logged
(`update: admin acknowledged no-sidecar; proceeding unverified`).
Releases since v1.1.8 publish the sidecar, so this prompt should never
fire in normal operation — it's a tripwire for tampered release pages
and for offline / mirror-served installs.

### HIGH — first-run double-click race could corrupt the install

`relocateToProgramFilesIfNeeded` (called from `firstRunWithWizard`)
copies the running exe to `%ProgramFiles%\KioskExitGuard` and re-execs
the canonical path. Pre-v1.2.0 this ran before any process-level
mutex, so two simultaneous admin double-clicks both entered relocate
concurrently, fought over the staging file, and could leave the
canonical exe in a corrupted or empty state.

Fix: a new admin-only named mutex `Global\KioskExitGuardFirstRunRelocate`
acquired between the flag-dispatch section of `main()` and the bare-args
controller path. The first instance owns it; the second logs
`first-run/relocate already in progress in another instance, exiting`
and `os.Exit(0)`. Short-lived flag invocations (`--pause`, `--update`,
`--silent-exit`, etc.) don't acquire the mutex — they exit before
touching the relocator.

### HIGH — re-exec env could carry KIOSK_EXIT_GUARD_VIA_SERVICE

`relocateToProgramFilesIfNeeded`'s `exec.Command(canonical, …)` inherits
the parent's environment block. Today nothing sets
`KIOSK_EXIT_GUARD_VIA_SERVICE` up the call chain (only the Service
supervisor sets it via `CreateEnvironmentBlock` on the duplicated user
token), but if a future change ever leaked that variable into the
controller's own environment, the re-exec would inherit it and the
re-execed process would see itself as Service-spawned — suppressing the
first-run wizard. Silent regression landmine.

Fix: build the child's env explicitly, dropping any entry whose name
case-insensitively matches `KIOSK_EXIT_GUARD_VIA_SERVICE`. The
re-execed first-run instance now provably never sees that variable
regardless of what's in the parent's env.

### MEDIUM — password modal 30s timer started before WebView2 paint

`askPasswordModalInProcess` armed the 30-second inactivity timer just
before `w.Run()`. WebView2 cold-start can eat 5–6 seconds of that
budget before the user can even type, so on a fresh logon the modal
sometimes auto-dismissed itself while the admin was still waiting for
the password field to appear.

Fix: expose a JavaScript-callable `kgReady` binding that the page
calls from `DOMContentLoaded` and `load` handlers. The Go handler arms
the inactivity timer there — the 30-second budget now starts when the
page is actually interactive. A 60-second fallback timer still arms
before `w.Run()` so a catastrophic WebView2 failure (where
DOMContentLoaded never reaches our binding) can't hang the screen
forever. Each fires whichever wins the `inactivityArmed` CAS.

### MEDIUM — pickActiveUserSession was invisible on multi-RDP hosts

On a Server 2022 box with multiple RDP users, `pickActiveUserSession`
silently picked the lowest-numbered active session with a user. That
might not be the admin the kiosk is supposed to lock down, and the
silent pick made it hard to diagnose from the log alone.

Fix: log the chosen user and domain on every supervisor-loop session
transition (`service: spawning controller in session %d (state=Active,
user=%s\\%s)`), and when there's more than one candidate also log every
candidate that was considered (`service: %d candidate sessions: 2
(DOMAIN\\Alice), 3 (DOMAIN\\Bob)`). The picker collects candidate info
once per call and stashes it under a mutex so the supervisor can read
it on a transition without re-querying WTS — log volume stays at one
line per transition rather than every 2-second poll. No allowlist /
user-filter yet; this is visibility-only for now.

### MEDIUM — --update had no UI cover during HTTP fetches

v1.1.11 dropped the "Checking GitHub…" toast for UI simplification.
Two HTTP GETs (30s timeout each) and a download (5min timeout) all
happen before any UI element fires, so two quick double-clicks on the
Update shortcut stacked two pipelines on top of each other; the loser
could race the winner's rename and leave a half-installed exe.

Fix: a global admin-only mutex `Global\KioskExitGuardUpdating` acquired
at the top of `runUpdateInvocation`. Second invocations exit silently
(`update: another update is already in flight; exiting silently`). The
toast stays gone — user explicitly asked for that removal — and the
mutex prevents the failure mode the original toast was helping with.

### MEDIUM — go vet unsafeptr warning on hookCallback

`hookCallback` casts the Win32 `LowLevelKeyboardProc` `lParam` (a
`uintptr` documented to be a pointer to `KBDLLHOOKSTRUCT`) via
`unsafe.Pointer(lParam)`. `go vet`'s unsafeptr analyzer correctly
flags this — it can't see the Win32 ABI contract.

Fix: isolate the conversion in a `kbdLLHookStructFromLParam` helper
annotated with `//go:nosplit`, `//go:nocheckptr`, and a `//nolint:govet`
explanation citing the Win32 hook ABI. `go vet` still emits the
unsafeptr line at the helper (the warning is not suppressible in-source),
but the conversion is now centralized and documented, and no new vet
warnings were introduced by the v1.2.0 changes.

### LOW — atomic install swap (MoveFileExW)

`relocateToProgramFilesIfNeeded` previously did
`os.Remove(canonical) + os.Rename(tmp, canonical)`. If the rename
failed (lock held by a still-running previous controller), the old
canonical was already gone and the new one never landed — install dir
empty.

Fix: replace the remove+rename pair with
`windows.MoveFileEx(tmp, canonical, MOVEFILE_REPLACE_EXISTING)`, which
is atomic and preserves the old canonical on failure.

### LOW — cleanupInstallDir now uses an allowlist

`--uninstall`'s `cleanupInstallDir` walked
`%ProgramFiles%\KioskExitGuard\` and removed everything not the
running exe. Fine when only our artifacts live in there, but an
admin-placed file (or a future install bug) would have been silently
nuked.

Fix: restrict deletion to a known allowlist —
`kiosk-exit-guard.exe`, `kiosk-exit-guard.exe.old`,
`kiosk-exit-guard.exe.staging`, `kiosk-exit-guard.log`,
`kiosk-exit-guard.log.old`, `resource.syso`, plus the `staging\`
subdir. Anything else is left in place and logged
(`cleanupInstallDir: skipping unrecognized file %s (admin-placed?)`).

### INFO — controller mutex DACL is now admin-only

`acquireControllerMutex` previously called `CreateMutexW(NULL, …)`,
which assigns the caller's default DACL. The kiosk user (the
controller spawned via `CreateProcessAsUserW` runs as them) could
pre-create the same-named mutex from a logon script and DoS the real
controller — at logon the genuine controller would see
`ERROR_ALREADY_EXISTS` and exit silently.

Fix: pass an explicit `SECURITY_ATTRIBUTES` whose DACL grants
`MUTEX_ALL_ACCESS` (0x1F0001) only to `BUILTIN\Administrators` and
`SYSTEM`, built from the SDDL
`D:(A;;0x1F0001;;;BA)(A;;0x1F0001;;;SY)`. The same helper
(`acquireAdminOnlyNamedMutex`) backs the new first-run and update
mutexes from HIGH#3 and MEDIUM#7, so all three named mutexes share
the same admin-only DACL.

## v1.1.11 — 2026-05-12

**Server 2022 RDP is a real supported target, and the supervisor now picks the right session for it.** The v1.1.10 ship helped a user whose machine turned out — on follow-up diagnostic — to actually be a headless Windows Server 2022 accessed over RDP, not a Win11 Home laptop. v1.1.10's `WTSEnumerateProcessesExW` cross-session process enumeration handles session 1 fine, but the supervisor hardcoded `sessionID = WTSGetActiveConsoleSessionId()` — on a headless RDP'd server that returns the empty physical-console session ID 1 while the real interactive user is in session 2. The controller never spawned. This release picks the right session, plus four smaller fixes that fell out of the Server 2022 pivot.

### CRITICAL — Service supervisor now walks all WTS sessions, picks the right one for RDP

**Root cause:** `supervisorLoop` in `service_windows.go` started every iteration with:

```go
sessionID := windows.WTSGetActiveConsoleSessionId()
if sessionID == noActiveSession { ... }
hProc, err := s.spawnControllerInSession(sessionID)
```

`WTSGetActiveConsoleSessionId()` returns the session ID of the *physical* console attached to the keyboard/monitor — not the user's session in general. On a Win11 laptop where someone is sitting at the device, that's session 1 and it's also the user's interactive session, so the v1.1.0 design happened to work. On a headless RDP'd Windows Server 2022, the physical console session exists (ID 1) but is empty (state=Disconnected, no user); the user's actual session is the RDP one (ID 2, state=Active, user=administrator). The supervisor spawned no controller, logged nothing (the call returned a valid ID 1, not `noActiveSession`), and `spawnControllerInSession(1)` failed at the `WTSQueryUserToken(1)` step or the user-session-process fallback because no candidate process exists in an empty session. After every reboot the kiosk was completely unprotected on the server. User's diagnostic on the server:

```
quser → administrator  rdp-tcp#0  ID 2  Active
Win32_Process Name SessionId
  sihost.exe       2
  taskhostw.exe    2
  explorer.exe     2
```

**Fix:** new helper `pickActiveUserSession() (uint32, bool)` in `service_windows.go`:

1. Call `WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, Reserved=0, Version=1, &pSessionInfo, &count)` to get every session on the box.
2. For each session where `State == WTSActive`, call `WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessionID, WTSUserName=5, &buffer, &bytesReturned)`. A logged-in interactive session has a non-empty username; an RDP session sitting at the logon dialog returns an empty string.
3. Priority: console session (compared against `WTSGetActiveConsoleSessionId()` return value) if it's active AND has a user — preserves Win11 / laptop behavior where session 1 is both the console AND the user. Else lowest-numbered other `WTSActive` session with a user — picks session 2 (RDP) on Server 2022.
4. Free the session list via `WTSFreeMemory` and each `WTSUserName` buffer via `WTSFreeMemory`.
5. Returns `(0, false)` if no usable session is found; supervisor sleeps `svcNoSessionDelay` and retries.

Win32 plumbing added to the `var` block: `procWTSEnumerateSessionsW`, `procWTSQuerySessionInformationW`, `procWTSFreeMemory`. New constants `wtsActive=0`, `wtsConnected=1`, `wtsDisconnected=4`, `wtsInfoUserName=5`. New struct `wtsSessionInfoW` mirroring the Win32 `WTS_SESSION_INFOW` layout (24 bytes on amd64 — `SessionID DWORD` + 4 bytes padding + `WinStationName LPWSTR` + `State DWORD` + 4 bytes trailing padding for 8-byte struct alignment, verified at runtime with `unsafe.Sizeof`).

`supervisorLoop` now calls `pickActiveUserSession()` instead of `WTSGetActiveConsoleSessionId()`. New `lastLoggedSession` variable on the loop tracks the last successful pick so we only log on state change — verbose-on-first-success but quiet on the steady-state respawn cycle. New log lines: `service: spawning controller in session N (state=Active, user logged in)` on a new successful session, `service: no active user session, waiting…` on the first failure tick after a successful streak. `spawnControllerInSession` failure paths reset `lastLoggedSession` so admins reading the log see paired "spawn failed" / "spawn succeeded" lines without having to grep for both.

On a Win11 laptop where `WTSGetActiveConsoleSessionId()` returns 1 and session 1 is `WTSActive` with a user, `pickActiveUserSession()` picks session 1 — both because it qualifies as the console session AND because no other session matches (server-class WTS sessions like Services/Listen are not `WTSActive`). The laptop / Win11 path is unchanged.

### MEDIUM — `restartExplorer` defensive shell check

**Root cause:** `restartExplorer()` in `main.go` did:

```go
cmd := exec.Command("cmd.exe", "/c", "taskkill /F /IM explorer.exe & start explorer.exe")
```

On Server 2022 (and any custom-shell setup) the registered shell may not be `explorer.exe`. On Server 2022 Core / fresh Server 2022 installs without Desktop Experience, `explorer.exe` may not exist at all as the user's shell — the `taskkill` succeeds (kills any explorer instance), but the `start explorer.exe` may not restore the user's actual shell properly; the user could lose their shell permanently mid-session.

**Fix:** before the taskkill, open `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` and read the `Shell` `REG_SZ` value. If the value (after `strings.TrimSpace`) is exactly `"explorer.exe"` (case-insensitive via `strings.EqualFold`), proceed with the restart. Otherwise log `restartExplorer: registered shell is %q, not explorer.exe — skipping restart` and return. The `NoTaskbar` HKCU policy still gets written by the caller; it just won't take effect until next logon, which is acceptable since a non-Explorer shell is the user's deliberate choice. If the registry open or read itself fails, log and skip — fail-closed is safe (the worst case is the taskbar reappearing for one session until logoff).

### MEDIUM — IFEO removal silently absorbs `ERROR_FILE_NOT_FOUND` / `registry.ErrNotExist`

**Root cause:** `removeIFEOBlock(targetExe string)` in `main.go` returned silently on any `OpenKey` failure. That hid actual errors (access denied, registry corruption) as well as the expected "key doesn't exist" case. On Server 2022 fresh installs without Chrome, the IFEO `chrome.exe` key may never have been written if `setIFEOBlock` never ran (e.g. on a `--reset` / `--resume` / `--uninstall` flow on a half-installed box). Silently swallowing all errors made post-mortem log review harder.

**Fix:** distinguish "not exist" (silent, expected) from other errors (logged for audit). `removeIFEOBlock` now does `errors.Is(err, registry.ErrNotExist) || errors.Is(err, syscall.ERROR_FILE_NOT_FOUND)` on the `OpenKey` error; both return silently. Other errors get `logf("removeIFEOBlock(%s): OpenKey failed: %v", targetExe, err)`. Behavior unchanged on installs where the IFEO key was written by a prior `applyBrowserBlocks()` — `OpenKey` succeeds, `DeleteValue("Debugger")` succeeds.

### MEDIUM — `uninstallChrome` logs "Chrome not installed" instead of silently returning success

**Root cause:** `uninstallChrome()` in `main.go` looped through three registry candidates (`HKLM\...\Uninstall\Google Chrome`, the WOW6432Node twin, and `HKCU\...\Uninstall\Google Chrome`); any `OpenKey` failure was `continue`'d. If none of the three keys existed (Chrome not installed — normal on a fresh Server 2022), the function returned `nil` silently. That's the correct end state, but logging nothing made it look like the function ran successfully and silently uninstalled Chrome, which was confusing in post-mortem log review.

**Fix:** track a `found` bool that flips true when any candidate yields a non-empty `UninstallString`. At the end, if `!found`, log `uninstallChrome: Chrome not installed, skipping uninstall` at info level. Return `nil` either way — the IFEO block is the actual enforcement, missing Chrome is a clean end state.

### MEDIUM — `--update` UI simplified: drop the "checking" toast and the separate confirm

**User request, verbatim:** "scratch the checking for updates ui just show the box do you want to update and password to approve it".

**Old flow** (`runUpdateInvocation` in `main.go`):

1. `showTimedInfo("Checking GitHub for updates…")` — toast (200–500ms WebView2 cold-start)
2. HTTP fetch of `/releases/latest`
3. If same version → `zenity.Info` "You're on the latest version (v%s). No update needed."
4. Else → `zenity.Question` "A new version is available. Current: v%s, Latest: v%s. Download and install?"
5. `askPasswordModal("Install the update?", "Replacing the running kiosk-exit-guard.exe with v%s. Enter your admin password to confirm.")`
6. Download / SHA-256 verify / atomic rename / Service restart

**New flow:**

1. Silent HTTP fetch (no toast — the user doesn't need a status update for a sub-second network round-trip)
2. If same version → `zenity.Info` "You're on v%s. No update available." (kept so the click isn't silent — admin needs feedback when nothing happens)
3. Else → `askPasswordModal("Install v%s?", "A new version is available (you're on v%s). Enter your admin password to download and install.")` — combines confirm + auth in one screen
4. Download / verify / rename (existing)

Deleted the `showTimedInfo("Checking GitHub for updates…")` line and the `zenity.Question` block. The password modal subtitle now mentions both the new version (target) and the current version (context) so the admin can verify the version bump before typing their password.

### Doc pivot — Windows Server 2022 (RDP / physical console) is a supported target

The project shipped through v1.1.10 documenting "Windows 11 Home (no Assigned Access)" as the target. The Server 2022 discovery in v1.1.11 makes that wording wrong — and the v1.1.11 supervisor logic is generic across both. Updated:

- **`README.md`** line 1 tagline and new "What's in v1.1.11" section.
- **`docs/index.html`** title, h1 tagline, download-card metadata, version pill v1.1.10→v1.1.11, new `<h2 id="whats-new">v1.1.11 — Server 2022 RDP session-id fix</h2>` callout, retitled v1.1.10 section to `<h2 id="v1110">v1.1.10 — WTS process enumeration</h2>`, four new feature cards at the top of the feature-grid (Server 2022 RDP support, Update UI simplified, restartExplorer respects the registered shell, IFEO/Chrome cleanup absorbs "not installed").
- **`versioninfo.json`** `FileDescription` "Kiosk lockdown utility for Windows 11 Home" → "Kiosk lockdown for Windows 11 Home and Server 2022", and both Patch:10 / "1.1.10" entries → Patch:11 / "1.1.11".
- **`app.manifest`** version attribute "1.1.10.0" → "1.1.11.0".
- **`docs/architecture.md`** v1.1.0 paragraph rewritten ("active console session" → "active user session") with a v1.1.11 sub-paragraph explaining the RDP discovery and `pickActiveUserSession()`. The `--service-run` row in the modes table updated to mention `pickActiveUserSession()` and the v1.1.10 user-session-process fallback.
- **`docs/admin-runbook.md`** new "Server 2022 / RDP: which session is the supervisor targeting? (v1.1.11+)" section with the expected log line, a `quser` cross-check, and the Server Core / custom-shell `restartExplorer` gotcha.

### Build

`goversioninfo -64 versioninfo.json` regenerated `resource.syso`. `go build -ldflags="-H windowsgui -s -w" -o kiosk-exit-guard.exe ./...` produces a ~7.9 MB binary (7,897,088 bytes — `+~2 KB` vs. v1.1.10 for the new session-enumeration code).

## v1.1.10 — 2026-05-12

**Service spawn reliability fix plus two log-noise cleanups from production traces.** The headline fix is a switch from `gopsutil` to `WTSEnumerateProcessesExW` for the service-side cross-session process enumeration, which makes the kiosk reboot-survivable on machines where the gopsutil snapshot path was returning empty results across sessions. The other two are cosmetic — they suppress alarming-looking but benign log lines that were firing on every controller startup.

### HIGH — Service can now spawn its supervised controller even when `gopsutil` enumeration is empty

**Root cause:** the v1.1.3 `WTSQueryUserToken` NO_TOKEN fallback (`tokenFromExplorerInSession` in `service_windows.go`) walked `gopsutil`'s `process.Processes()` looking for `explorer.exe` in the active console session. On the user's affected machine (Win11 Home, custom kiosk shell, fully-logged-in interactive session) gopsutil returned a filtered or empty list when called from the Session-0 LocalSystem service. The kernel can see across sessions just fine for LocalSystem (it has `SeDebugPrivilege`), but gopsutil's underlying snapshot API was missing them. Result: the supervisor logged `spawnControllerInSession(1) failed: WTSQueryUserToken(1): An attempt was made to reference a token that does not exist.; explorer fallback: no explorer.exe found in session 1 (is a user logged in?)` every 2 seconds, and the kiosk never got an active controller after reboot until the admin re-clicked the exe.

A second contributing factor was the v1.1.8 fallback being explorer-only: if the machine had no `explorer.exe` in session 1 (custom kiosk shell, or v1.1.x's Explorer-restart never respawned it), there was no other candidate.

**Fix:** rewrote `tokenFromExplorerInSession` → `tokenFromUserSessionProcess` to use `WTSEnumerateProcessesExW` from `wtsapi32.dll` — the Win32 API explicitly designed for service-side cross-session enumeration. Pass the target `sessionID` directly so the kernel filters for us instead of enumerating every session. Broadened the candidate list beyond `explorer.exe` to include `sihost.exe`, `taskhostw.exe`, `RuntimeBroker.exe`, and `StartMenuExperienceHost.exe` — all Windows-auto-spawned under the interactive user's token, all serving the same purpose as the original `explorer.exe`-token unwrap. Priority order preserved: prefer `explorer.exe` if present (most common), fall back to the others if not. The v1.1.8 `QueryFullProcessImageName` validation against the canonical `%SystemRoot%\<candidate>.exe` path is preserved (each candidate has its own expected path), so an attacker can't drop a `sihost.exe` in a writable directory and have its token used. The `unsafe.Slice` over the WTS buffer is freed via `WTSFreeMemoryExW` every call — critical because this runs every 2 seconds in the supervisor loop. Updated the call site in `spawnControllerInSession` to log `service: WTSQueryUserToken failed (%v); user-session-process fallback found <%s> in session %d` on success and `user-session-process fallback: <reason>` on the failure path. Defensive `unsafe.Sizeof(wtsProcessInfoW{}) == 32` check before slicing the buffer; mismatch aborts cleanly instead of dereferencing garbage. `gopsutil` stays in `go.mod` because other call sites (`findOurWebViewChild`, `killRunningController`, and the toolhelp-based `parentProcessImagePath`) still use it.

### LOW — `tightenHKLMConfigDACL` no longer logs on fresh installs

**Root cause:** v1.1.8 HIGH#5 added `tightenHKLMConfigDACL()` at controller startup so existing installs would heal the HKLM password-hash key DACL. The function calls `SetNamedSecurityInfo(MACHINE\Software\KioskExitGuard, SE_REGISTRY_KEY, ...)`. On a fresh install the key only exists after `saveHashToRegistry` runs in the first-run wizard — so the startup call hits `ERROR_FILE_NOT_FOUND` (2) and emits `tightenHKLMConfigDACL: SetNamedSecurityInfo(MACHINE\Software\KioskExitGuard) failed: The system cannot find the file specified.` to `kiosk-exit-guard.log` on every controller startup until first-run completes. The function correctly silently returns and the key gets tightened in `saveHashToRegistry` when it actually creates the key — but the log line looked alarming.

**Fix:** check `errors.Is(err, syscall.ERROR_FILE_NOT_FOUND)` before logging in `tightenHKLMConfigDACL` (`main.go`). On match, silently return — the next `saveHashToRegistry` call applies the same DACL when the key gets created. Any other error (access denied, invalid SDDL, etc.) still surfaces via the existing `logf` call.

### LOW — `parentProcessImagePath` no longer logs on the v1.1.8 relocate-and-reexec path

**Root cause:** v1.1.8 LOW#9 added a parent-PID image-path lookup in `parentProcessImagePath` (`service_windows.go`) so `isLaunchedByService` could authenticate the supervising parent via `%SystemRoot%\System32\services.exe` instead of a forgeable env-var marker. On the v1.1.8 relocate-from-Downloads-to-ProgramFiles flow the ORIGINAL parent (the admin's double-click) exits before the re-execed child runs the parent lookup. `windows.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, parentPID)` correctly fails with `ERROR_INVALID_PARAMETER` (87) for "PID no longer alive" — Windows returns that error rather than `ERROR_NOT_FOUND` because by the time the lookup runs the PID slot may also have been recycled. The function correctly falls back to the env-var hint (which on the relocate path is empty, so the caller treats it as a manual launch — the correct outcome). The log line `parentProcessImagePath: OpenProcess(parent=6292) failed: The parameter is incorrect.` looked scary on every relocate-flow startup.

**Fix:** check `errors.Is(err, syscall.Errno(windows.ERROR_INVALID_PARAMETER))` and `windows.ERROR_ACCESS_DENIED` before logging in `parentProcessImagePath`. Both are expected for "parent already exited" or "parent is a protected process" — silently return `("", false)` so the caller falls back to the env-var hint, which is the documented v1.1.0 behavior. Any other error still surfaces. The `isLaunchedByService: parent lookup failed, env hint=...` line is kept as-is — that one is useful for audit trails.

## v1.1.9 — 2026-05-12

**UX audit pass plus a 30-second password-modal timeout.** Eleven concrete fixes addressing the kiosk-blink at logon, silent panics, stacked first-run dialogs, the orphan-toast race at exit, stale admin-runbook docs, and the new "user walks away from the password modal and holds the kiosk hostage" report.

### NEW — password modal auto-dismisses after 30 seconds of inactivity

**Root cause:** `askPasswordModalInProcess` (`main.go`) entered `w.Run()` and waited indefinitely for either a `kgSubmit` / `kgCancel` host-object call or a window destroy. A user who pressed `Ctrl+Shift+Alt+K`, saw the modal, then walked away would leave the fullscreen modal painted forever — the kiosk WebView2 child stayed killed (because the controller's hook had spawned the modal first), and the next person hitting the device saw a frozen "SK Filter — password required" screen with no way to dismiss without the password.

**Fix:** new `const inactivityTimeout = 30 * time.Second` near the top of `askPasswordModalInProcess`. After `w.Run()` is set up but before entering the message pump, arm a `time.AfterFunc(inactivityTimeout, ...)` that calls `w.Dispatch(func() { w.Terminate() })` — Dispatch ensures Terminate runs on the WebView2 UI thread that owns `w.Run()`. The child then exits with `pwCancel` (the `!submitted` branch of the existing return logic) so no failed-password toast fires, and the controller's caller path treats it as a benign cancel. Both `w.Bind("kgSubmit", ...)` and `w.Bind("kgCancel", ...)` reset the timer (`inactivityTimer.Reset(inactivityTimeout)`) at the top of their callbacks so an actively-typing user isn't yanked mid-attempt. Logged ("inactivity timeout — auto-dismissing") so admin runbook traces can confirm the cause when reviewing a "modal disappeared on me" report.

### UX HIGH#1 — service / task race at logon no longer blinks the kiosk

**Root cause:** as of v1.1.4 both the Windows Service supervisor AND the AtLogon scheduled task auto-start the controller. At logon both fire within ~1s of each other. Whichever loses the race gets killed by the winner's `killRunningController()` call inside `main()`. The loser's supervisor (Service or task RestartOnFailure) respawns the lost controller within seconds. The respawn re-enters `main()`, kills the *winner*, and oscillation continues until both supervisors decide one process is "good enough". User-visible symptom: the kiosk WebView2 child blinks / reopens 1 – 2s after logon.

**Fix:** new named Win32 mutex `Global\KioskExitGuardControllerRunning` acquired via `procCreateMutexW` (the same pattern as `acquireGlobalPromptLock`) right before `killRunningController()` in `main()`. The acquisition runs only for the default controller mode (no early-return flag handler fired) so short-lived `--reset` / `--update` / `--pause` / `--resume` / `--launch-kiosk` / `--set-url` / `--service-install` / `--service-remove` / `--silent-exit` / `--show-toast` / `--ask-password` / `--webview` invocations don't fight over it. `--service-run` itself doesn't take the path either — it's the Service wrapper that spawns the controller, not the controller. New `acquireControllerMutex()` in `main.go` returns `(handle, alreadyRunning bool)`. On `alreadyRunning == true` the second mover logs "controller mutex … already held by another process; exiting", releases its early-installed LL keyboard hook (to avoid leaking a hook handle), and `os.Exit(0)`s cleanly. The first controller keeps running; its supervisor never sees a death; no respawn loop; no kiosk blink. The handle is intentionally leaked for the controller's lifetime (the GetMessageW pump keeps the process alive; the kernel auto-releases the mutex on process exit).

### UX HIGH#2 — controller panic now surfaces a recovery toast

**Root cause:** `recoverAndLog` (`main.go`) logged the panic + stack trace to `kiosk-exit-guard.log` and returned, letting the deferred panic propagate. The Service / scheduled task respawned the controller within ~1s, but in that window the kiosk WebView2 child died (no parent to watchdog-respawn it) and the user saw the desktop briefly without explanation.

**Fix:** `recoverAndLog` now spawns `kiosk-exit-guard.exe --show-toast 5000 "SK Filter restarted after an internal error. Auto-recovery in progress."` as a fire-and-forget child via the existing `--show-toast` path before returning. The child's WebView2 is its own first instance so it survives the crashing parent. The user sees a 5-second toast explaining the brief glitch; the supervising Service respawns the controller; the kiosk paints again. Best-effort — spawn failure is itself logged but doesn't block panic propagation.

### UX HIGH#3 — `docs/admin-runbook.md` updated for v1.1.4+ co-installed auto-start and v1.1.8 paths

**Root cause:** the runbook still claimed the v1.0.x scheduled task gets *deleted* on upgrade to v1.1.0+, and described `--update` as "restarts the scheduled task". v1.1.4 made the Service and task co-installed (`installService` no longer touches the task), and v1.1.0+'s `--update` flow restarts the Service via `sc start KioskExitGuardSvc`.

**Fix:** rewrote the verification section so the scheduled-task query expects **one row** `State = Ready` (it's the AtLogon fallback now, not a legacy artifact). Added an "Auto-start verification" section that exercises `Get-Service` + `Get-ScheduledTask` + `Get-Process kiosk-exit-guard` together. Added an "Install paths (v1.1.8+)" section describing `%ProgramFiles%\KioskExitGuard\` (canonical install dir, NTFS-default admin-only) and `%ProgramData%\KioskExitGuard\` (icacls-tightened data root with `staging\`, `WebView2\`, and the new v1.1.9 `pause-just-applied.flag`). Replaced "restarts the scheduled task" with "restarts the Service" in the `Install an update` task. Updated the "I lost the password" recovery script comment so the `schtasks /Delete` line no longer claims to be a no-op on v1.1.0+. Updated the v1.0.x upgrade table row to describe both `installService()` and `installStartupTask()` running, not the v1.0.x task-deletion behavior that's gone.

### UX MEDIUM#4 + UX MEDIUM#5 — first-run setup now shows ONE combined status dialog

**Root cause:** the first-run success path's `zenity.Info` hardcoded "Auto-start task installed" — a lie when only the Service installed or only the task installed. Worse, dual-failure stacked two modals: `installService` failure surfaced a `zenity.Warning` BEFORE the task install attempt, and a follow-up `zenity.Error` if the task also failed, so admins on broken installs saw the Warning, dismissed it, then got an Error on top.

**Fix:** install both first without surfacing per-step warnings, then build a single status dialog from `(svcErr, taskErr)`. The line "Auto-start: Windows Service ✓, Scheduled task ✓" (or any combination of ✓ / ✗) replaces the hardcoded string. Dual-success surfaces `zenity.Info`; service-only-failure / task-only-failure each surface a single `zenity.Warning` explaining what survived; dual-failure escalates to `zenity.Error` with both error texts in one body. One modal per first-run outcome, no stacking.

### UX MEDIUM#6 — pause-shortcut kiosk-relaunch race closed

**Root cause:** `runPauseInvocation` kills the kiosk WebView2 child immediately after password accept so `zenity.List` (the duration picker, native Win32 dialog without `HWND_TOPMOST`) can grab foreground. The controller's `runWatchdog` ticks every 30s and `syncFilterStateLoop` polls the pause file every 2s. If a watchdog tick fired between the kill and the sync-loop seeing the new pause file, the watchdog respawned the kiosk and the user saw the "Pause cancelled / paused" zenity flow interrupted by a flash of the kiosk re-appearing.

**Fix:** new marker file `%ProgramData%\KioskExitGuard\pause-just-applied.flag` written via new `writePauseJustAppliedMarker(5*time.Second)` BEFORE the `findOurWebViewChild().Kill()` in `runPauseInvocation`. The marker is a decimal `time.Now().Add(5*time.Second).UnixNano()` string. `watchdogTick` (`main.go`) now calls `pauseJustAppliedActive()` before launching a `--webview` child; if the marker exists AND its timestamp is still in the future, the watchdog skips the relaunch this tick. The 5-second buffer covers the worst-case skew between the two processes' wall clocks, far exceeding the 2-second `syncFilterStateLoop` interval that actually flips `filterMode` — so the marker is irrelevant after the sync loop catches up. Stale markers (old timestamps from a previous boot) read as inactive; any parse error degrades back to pre-v1.1.9 behavior. The directory is admin-only via the existing `ensureAdminOnlyDir(programDataDir())`.

### UX MEDIUM#7 — `--update` waits for the Service to actually reach Stopped

**Root cause:** `runUpdateInvocation` (`main.go`) ran `exec.Command("sc", "stop", svcName).Run()` and continued immediately. `sc stop` returns as soon as SCM accepts the stop request, not when the service is actually Stopped. In the 1 – 2s the supervisor takes to wind down, the running supervisor goroutine could respawn a fresh controller via `CreateProcessAsUserW`, which then file-locked `kiosk-exit-guard.exe` and broke the subsequent `os.Rename(exe, oldPath)`.

**Fix:** extracted the SCM poll loop from `installService` into a reusable `waitForServiceStopped(d time.Duration) error` helper in `service_windows.go`. Same pattern (`mgr.Connect` → `OpenService` → `s.Query` → check `status.State == svc.Stopped` → `time.Sleep(200ms)`), wrapped in a deadline check. `runUpdateInvocation` calls `waitForServiceStopped(10 * time.Second)` after `sc stop` and logs (but proceeds anyway) on timeout — 10s is enough headroom for any normal SCM cycle without bricking the update if SCM is hung. Mirrors the inline loop already in `installService` (`service_windows.go:127-133`).

### UX MEDIUM#8 — modal-spawn failure surfaces a toast instead of silent swallow

**Root cause:** `askPasswordModal` (`main.go`, the parent-side wrapper around the `--ask-password` child) returned `pwCancel` on any `cmd.Run` error that wasn't an `*exec.ExitError`. The LL-hook callback path swallows `pwCancel` silently (intentional for "user pressed Esc"). So if the child failed to *start* — antivirus quarantine, missing exe, locked path — the user tapped Win, saw nothing, and assumed the filter was broken or had bypassed itself.

**Fix:** distinguish spawn-failure from exit-code in the wrapper. If `runErr` is non-nil AND NOT `*exec.ExitError`, the child never started — log it (already done) and additionally call `showTimedInfo("Password prompt failed.\nCheck kiosk-exit-guard.log or restart the filter.")`. The wrapper still returns `pwCancel` so callers don't trigger the wrong-password toast for what is actually plumbing failure — a "Wrong password" message would be actively misleading.

### UX MEDIUM#9 — exit-after-failure toasts wait for the child to render

**Root cause:** `runPauseInvocation`, `runUpdateInvocation`, and the `--set-url` flow all called `showFailedToast()` (fire-and-forget via `--show-toast` child) on wrong-password, then immediately `os.Exit(1)`. The parent process died before the child WebView2 finished cold-starting, sometimes before the toast painted at all. User-visible symptom: enter the wrong password on `--pause`, the parent disappears, no feedback.

**Fix:** new `showTimedInfoSync(text)` and `showFailedToastSync()` in `main.go` that use `cmd.Run()` instead of `cmd.Start()` — the parent blocks until the child renders + the existing dismiss timer fires. Replaced `showFailedToast()` with `showFailedToastSync()` at the three exit-after-failure call sites. The hook-callback `promptAndPause` path keeps the async `showFailedToast()` (the controller doesn't exit after, so fire-and-forget is correct).

### UX LOW#10 — uninstall dialog mentions the Windows Service; post-uninstall block verifies its removal

**Root cause:** the `zenity.Question` confirm dialog in `runUninstallInvocation` listed "Scheduled task" but not the Service. On v1.1.0+ installs the Service is the primary auto-start mechanism — the dialog understated what was about to happen. Also, the post-uninstall verification block only ran `schtasks /Query` to confirm the task was gone; a stuck SCM entry (`removeService` rare-failure mode) would survive uninstall without complaint.

**Fix:** added "Windows Service (KioskExitGuardSvc)" to the bulleted "this removes:" list. Added a verification check after the existing scheduled-task query via new helper `serviceStillExists()` in `service_windows.go` (uses `mgr.Connect` + `OpenService` — clean way to avoid leaking the `golang.org/x/sys/windows/svc/mgr` import into `main.go`). On true return, the failures list gains `"The Windows Service KioskExitGuardSvc could not be removed. Open an Admin PowerShell and run: sc delete KioskExitGuardSvc"`.

### UX LOW#11 — `--set-url` writes to HKLM before killing the kiosk child

**Root cause / fix:** `promptForKioskURL` already calls `saveKioskURLToRegistry` as its last step before returning the new URL, then the caller in `main()` kills the kiosk child to force a respawn at the new URL. The audit flagged this as a potential reorder risk in future refactors of `promptForKioskURL`. Added a defensive `saveKioskURLToRegistry(newURL)` call in the `--set-url` block AFTER `promptForKioskURL` returns and BEFORE the `findOurWebViewChild().Kill()`, with a log line on the (idempotent) second-save failure. Belt and suspenders — the current code path was correct, the second call costs one `RegSetValueEx` and locks the invariant against drift.

### Shared helpers added

- `acquireControllerMutex()` (`main.go`) — UX HIGH#1.
- `writePauseJustAppliedMarker(dur)` / `pauseJustAppliedActive()` / `pauseJustAppliedMarkerPath()` (`main.go`) — UX MEDIUM#6.
- `showTimedInfoSync(text)` / `showFailedToastSync()` (`main.go`) — UX MEDIUM#9.
- `waitForServiceStopped(d)` (`service_windows.go`) — UX MEDIUM#7, extracted from `installService`'s inline loop.
- `serviceStillExists()` (`service_windows.go`) — UX LOW#10.

### Build

`goversioninfo -64 versioninfo.json` regenerated the resource. `go build -ldflags="-H windowsgui -s -w" -o kiosk-exit-guard.exe ./...` produces a 7.89 MB binary (was 7.88 MB on v1.1.8).

## v1.1.8 — 2026-05-12

**Security audit pass: every finding addressed.** Nine concrete fixes spanning install-path hardening, update-flow integrity, identity authentication of the explorer-token fallback, WebView2 profile isolation, registry DACL tightening, hook-install ordering, PowerShell injection prep, and parent-PID authentication.

### CRITICAL #1 — exe relocated to %ProgramFiles% before SCM registers its path

**Root cause:** `installService` (`service_windows.go:111`) called `os.Executable()` and registered whatever path the admin double-clicked from. On this user's machine that was `C:\Users\<user>\Downloads\kiosk-exit-guard.exe` — kiosk-user-writable. The kiosk user could swap the binary and on the next Service start the supervisor (LocalSystem) would respawn attacker code as LocalSystem.

**Fix:** new `relocateToProgramFilesIfNeeded()` (`main.go`) runs at the top of `firstRunWithWizard`. Detects whether the running exe is already at `%ProgramFiles%\KioskExitGuard\kiosk-exit-guard.exe`; if not, mkdir + copy + re-exec the canonical copy with the original argv, and `os.Exit(0)` the staging process. The re-exec'd canonical copy completes first-run from the admin-only directory so `installService`, `installStartupTask`, and `createDesktopShortcut` all register the ProgramFiles path. Uses `os.Getenv("ProgramFiles")` so non-en-US installs land in the localized path. On any failure (mkdir / copy / exec) we fall back to installing from the current location with a logged warning — kiosk-user gets weaker but still some protection, which beats none.

`runUninstallInvocation` now calls a companion `cleanupInstallDir()` (`main.go`) that walks `%ProgramFiles%\KioskExitGuard` and removes every file except the running exe (Windows file-locks it), then schedules the running exe + containing directory for delete-on-reboot via `MoveFileExW(MOVEFILE_DELAY_UNTIL_REBOOT)`. Skipped if the running exe isn't at the canonical path (don't nuke `~/Downloads/`).

### CRITICAL #2 — `--update` now stages in %ProgramData% and verifies SHA-256

**Root cause:** `runUpdateInvocation` (`main.go:2702`) downloaded the new exe to `os.TempDir()`. `%TEMP%` is user-writable. Between `downloadFile` and `os.Rename` a kiosk user could swap the temp file and have us atomically install attacker code as part of the legitimate update flow. There was also no integrity check on the downloaded bytes — a GitHub Releases compromise (token leak, supply-chain) would replace the running controller silently.

**Fix:** two layers.

- **Admin-only staging directory.** `tmpPath` is now `%ProgramData%\KioskExitGuard\staging\kiosk-exit-guard.new.exe`. A new shared helper `ensureAdminOnlyDir(path)` (`main.go`) mkdir's the directory and invokes `icacls /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F"` so even a kiosk-user-writable inheritance from `%ProgramData%` can't widen the ACL. Same helper is reused by HIGH#4 for the WebView2 user-data folder. Update aborts with `zenity.Error` if the staging dir can't be locked down.
- **SHA-256 sidecar verification.** `fetchLatestRelease` returns three values now (`version`, `exeURL`, `shaURL`); it also scans release assets for `kiosk-exit-guard.exe.sha256`. If present, `fetchExpectedSHA256` downloads the sidecar (first whitespace-delimited token, accept canonical `Get-FileHash` output), `fileSHA256` hashes the downloaded exe, and a `strings.EqualFold` mismatch aborts the update with a `zenity.Error` pointing at the issue tracker. If the sidecar is absent (legacy releases), log a warning and proceed — refusing updates without an integrity proof would brick existing installs that pre-date this fix.

The release workflow (`.github/workflows/release.yml`) gained a "Generate SHA-256 sidecar" step that runs `Get-FileHash -Algorithm SHA256 kiosk-exit-guard.exe` and writes the lowercase hex digest to `kiosk-exit-guard.exe.sha256` (ASCII, no BOM, no trailing newline) which is then attached to the release alongside the exe.

### HIGH #3 — `tokenFromExplorerInSession` now authenticates explorer.exe by image path

**Root cause:** `service_windows.go:468` trusted any process whose `gopsutil` `Name()` matched `explorer.exe`. A kiosk user can spawn a renamed-to-explorer.exe binary in the active console session; on the next supervisor tick the Service opens its token, unwraps the linked elevated half via `TokenLinkedToken`, and `CreateProcessAsUserW`'s attacker code as the admin user. Also a PID-recycle race window between the gopsutil enumeration and `OpenProcess` (MEDIUM #6 — same fix closes both).

**Fix:** new `isLegitimateExplorerHandle(hProc windows.Handle)` (`service_windows.go`) called immediately after the successful `OpenProcess`. It calls `windows.QueryFullProcessImageName` on the kernel handle we just opened (NOT on the PID, which closes the recycle race — the handle pins the original kernel object regardless of PID reuse), and lowercases-compares the returned path against `%SystemRoot%\explorer.exe`. Anything else is rejected with a logged warning and the loop continues to the next candidate explorer.exe.

### HIGH #4 — WebView2 user-data folder moved to admin-only %ProgramData% path

**Root cause:** `go-webview2`'s default `DataPath` lands under `%LOCALAPPDATA%\<exe>.WebView2` — kiosk-user-writable. A kiosk user can plant a service-worker script in the profile that's then loaded by the `--ask-password` child WebView2 instance; the worker can intercept the `kgSubmit` host-object call and exfiltrate the plaintext password before bcrypt comparison.

**Fix:** new `webView2DataPath()` returns `%ProgramData%\KioskExitGuard\WebView2`; `ensureWebView2DataDir()` lazily creates + DACL-tightens it via `ensureAdminOnlyDir` (shared with CRITICAL#2). Every `webview2.NewWithOptions` call site (`askPasswordModalInProcess`, `showFrontmostToast`, `runFirstRunWizard`, `runWebViewKiosk`) now passes `DataPath: ensureWebView2DataDir()` so all four in-process WebView2 instances share the same locked-down profile root. Verified `WebViewOptions.DataPath` is the top-level field name in the `github.com/jchv/go-webview2` v0.0.0-20260205173254-56598839c808 release (`webview.go:75`).

### HIGH #5 — HKLM\Software\KioskExitGuard DACL now admin-only

**Root cause:** default `HKLM\Software` ACL inherits `BUILTIN\Users:KEY_READ`. Any local user could read `HKLM\Software\KioskExitGuard\PasswordHash` and run an offline bcrypt-dictionary attack against it; the password becomes the kiosk-bypass + uninstall + update authorization across the whole device.

**Fix:** new `tightenHKLMConfigDACL()` (`main.go`) calls `windows.SetNamedSecurityInfo` with `SE_REGISTRY_KEY`, object name `MACHINE\Software\KioskExitGuard`, and a DACL parsed from the SDDL `D:PAI(A;CI;KA;;;SY)(A;CI;KA;;;BA)` — protected (no inherit from HKLM\Software so the BUILTIN\Users:KEY_READ ACE doesn't leak in), auto-inherited (child keys inherit our DACL), SYSTEM full control + container-inherit, Administrators full control + container-inherit. Called from `saveHashToRegistry` (so first-run installs are tight from the first write) AND unconditionally on every controller startup right after `migrateLegacyHash` (so existing v1.1.7-and-earlier installs heal on first launch of v1.1.8). The `--ask-password` child runs as the same admin user that launched the controller, so granting BUILTIN\Administrators is sufficient for every internal call site.

### MEDIUM #6 — PID-recycle race in explorer-token path

Covered by HIGH #3's `isLegitimateExplorerHandle` — image path is re-derived from the kernel via `QueryFullProcessImageName` on the same handle we used for `OpenProcessToken`, so the race window between gopsutil's enumeration and our open is closed (the handle pins the original kernel object regardless of whether the PID is recycled later).

### MEDIUM #7 — LL keyboard hook installed BEFORE `killRunningController()`

**Root cause:** `main.go:3176` ran `killRunningController()` then `firstRunWithWizard` / `ensureWebView2Installed` / state loading, with the `SetWindowsHookExW` call only happening at the very end (`:3265`). In the seconds between the old controller dying and the new hook installing, no other controller was alive AND no hook was up — the kiosk was briefly unprotected.

**Fix:** moved the `procSetWindowHookExW.Call` block to immediately after the `--reset` / `--set-password` / `--set-url` switch and `ensureWebView2Installed`, before `killRunningController`. The hook reads `filterMode.Load()` (default-false `atomic.Bool`) and `storedHash` (nil at this point) — since `filterMode` is still off, the hook is a structural no-op until the "default-ON" branch below flips it on. Once flipped, the hook is already running and starts intercepting immediately. The `GetMessageW` pump still lives at the bottom of `main()` (`runtime.LockOSThread` at the top guarantees it runs on the same thread that installed the hook for the controller's lifetime).

### MEDIUM #8 — PowerShell injection hardening in `installStartupTask`

**Root cause:** `main.go:776` used `fmt.Sprintf` to interpolate `taskName` and the `exe` path into a PowerShell heredoc with a single-quote-doubling escape. Not exploitable today — `taskName` is a compile-time constant and `os.Executable()` returns a kernel-derived path — but fragile.

**Fix:** the exe path and task name flow through environment variables (`KEG_EXE`, `KEG_TASKNAME`) on the spawned PowerShell process; the script body references `$env:KEG_EXE` / `$env:KEG_TASKNAME` so no values are interpolated into PS source text. The script body itself is now passed via `-EncodedCommand <base64-of-UTF-16-LE>` to dodge any quoting / parser edge cases in argument transit between Go's `exec.Command` and PowerShell's argv parser. `cmd.Env = append(os.Environ(), ...)` keeps the temporary env vars out of the calling Go process's environment. New helper `utf16LEBytes(s string)` encodes the script body for `-EncodedCommand`.

### LOW #9 — `isLaunchedByService` now authenticates via parent-PID lookup

**Root cause:** `service_windows.go:649` decided whether to suppress first-run by checking the `KIOSK_EXIT_GUARD_VIA_SERVICE` env var. Any process can set the env var before exec'ing `kiosk-exit-guard.exe`. A kiosk user with shell access could set it, run the exe manually, and have first-run suppressed — leaving the device with no password and no lockdown applied, ready for the admin to walk into a half-installed state.

**Fix:** new `parentProcessImagePath()` (`service_windows.go`) uses `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` + `Process32First` / `Process32Next` to find our own PID's entry, reads `ParentProcessID`, then `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `QueryFullProcessImageName` to read the parent's image. `isLaunchedByService` now compares against `%SystemRoot%\System32\services.exe` — `CreateProcessAsUserW` from the SCM-launched Service makes services.exe (the parent of the Service) the parent of the spawned controller. The env var is kept as a fallback hint when the snapshot path fails (stripped SKUs / locked-down SCM) to avoid regressing v1.1.0 behavior, but the parent path is the source of truth when available.

### Shared helpers

- **`ensureAdminOnlyDir(path string)`** (`main.go`): mkdir + icacls inheritance/grant. Used by CRITICAL#2 (staging dir) and HIGH#4 (WebView2 user-data dir).
- **`canonicalInstallDir() / canonicalInstallPath()`** (`main.go`): env-resolved `%ProgramFiles%\KioskExitGuard\...` paths for the relocation logic.
- **`programDataDir() / webView2DataPath()`** (`main.go`): env-resolved `%ProgramData%\KioskExitGuard\...` roots.
- **`utf16LEBytes(s string)`** (`main.go`): UTF-16-LE encoder for PowerShell `-EncodedCommand`.

### Build

`goversioninfo -64 versioninfo.json` regenerated the resource. `go build -ldflags="-H windowsgui -s -w" -o kiosk-exit-guard.exe ./...` produces a 7.88 MB binary (was 7.79 MB on v1.1.7).

## v1.1.7 — 2026-05-12

**Pause-duration picker now visible on the fullscreen kiosk.** v1.1.6 fixed the password modal's foreground-grab; this fix covers the screen that comes AFTER the password — the "1 / 5 / 10 / 20 / 30 / 45 / custom" duration picker. User report: "after the password when I tried to set if it was 1 minute or 5 or other that I couldn't see it."

Root cause: `askPauseDuration` uses `zenity.List` and `askCustomMinutes` uses `zenity.Entry` — both are **native Win32 dialogs**, not WebView2 modals. They don't get the `HWND_TOPMOST` flag and they don't go through v1.1.6's `forceForeground` path. The kiosk WebView2 child is fullscreen `HWND_TOPMOST` and traps focus; the zenity dialogs render behind it and are effectively invisible / unfocused.

Fix: in both `runPauseInvocation` (the `--pause` shortcut) and `promptAndPause` (the Ctrl+Shift+Alt+K hotkey from the LL hook), kill the kiosk WebView2 child *immediately after* the password modal is accepted and *before* showing the duration picker. With the kiosk gone, zenity gets normal foreground. If the user cancels the duration picker, the controller's watchdog respawns the kiosk within 30 s (or `promptAndPause` calls `launchWebViewChild` proactively to close that gap).

## v1.1.6 — 2026-05-12

**Password modal now actually comes to front + gets keyboard focus on the fullscreen kiosk.** User report: "pressing Ctrl+Shift+Alt+K while on the [kiosk] full screen needs to move the modal to the front to pause the filter."

Root cause: both the kiosk WebView2 window and the password modal child process are `HWND_TOPMOST`. The modal's z-order beat the kiosk visually because of `SetWindowPos(HWND_TOPMOST)` ordering, but **keyboard focus** stayed with the kiosk because the modal child process never called `SetForegroundWindow` — and even if it had, Windows would have rejected the call (only the current foreground process can grant foreground to another). So the user saw the modal but typing the password went to the kiosk page.

The v1.0.3 fix had deliberately stripped `SetForegroundWindow` + `BringWindowToTop` because the combination caused modal hangs on Server SKUs. v1.1.6 brings them back via the **AttachThreadInput idiom** which bypasses the eligibility check without the hang risk: temporarily merge the modal thread's input queue with the foreground thread's queue, call `SetForegroundWindow` (Windows now treats them as the same process for foreground-grant purposes), then detach. `forceForeground()` in `main.go` does this; `makeModalFullscreenTopmost` calls it at the end so every fullscreen modal (password modal + first-run wizard) grabs focus on top of whatever was there before. The detach happens in `defer` so a panic during the steal can't leak the input attach.

## v1.1.5 — 2026-05-12

**Browser zoom shortcuts allowed through.** `Ctrl+0` (zoom reset), `Ctrl+-` (zoom out), and `Ctrl++` / `Ctrl+=` (zoom in) now pass through the LL hook to the kiosk WebView2 page instead of triggering the password modal. Numpad equivalents (`Ctrl+Numpad0`, `Ctrl+Subtract`, `Ctrl+Add`) are also allowed. All variants still require Ctrl-only — `Win+0`, `Alt+-`, etc. still hit the lockdown path.

Joins the existing always-allowed list: `F5` and `Ctrl+R` (page reload). `isAlwaysAllowedCombo` (`main.go`) restructured to share the Ctrl-without-Alt-or-Win precondition across all zoom + reload combos.

## v1.1.4 — 2026-05-12

**Belt-and-suspenders auto-start: Service AND scheduled task co-installed.**

Field report: "right now the filter only runs when I re-click the exe file from the downloads folder" — even after v1.1.3's explorer-token fallback shipped, the auto-start was still flaky on the affected machine. v1.1.0 had aggressively switched to Service-only and deleted any leftover v1.0.x scheduled task on install. That made the kiosk completely unprotected after reboot whenever the Service spawn path failed.

Fix: install BOTH the Windows Service and the scheduled task at first-run and on every non-service-spawn launch. Whichever auto-start mechanism fires first wins; `killRunningController()` at controller startup guarantees only one controller process runs at a time. Concrete changes:

- `firstRunWithWizard` now calls `installStartupTask()` *in addition to* `installService()` (not "if service install failed" — always).
- `installService` no longer deletes the scheduled task. v1.1.0–v1.1.3 wiped it to prevent two controllers fighting; v1.1.4 trusts `killRunningController()` to keep things sane.
- Non-first-run launches refresh BOTH managers.
- Scheduled task is now AtLogon-only (no every-minute repetition that v1.0.x used). The Service is the in-session respawn supervisor; the task is purely a logon-time fallback for installs where the Service spawn path fails. Dropping the per-minute watchdog avoids kill/respawn churn between the two auto-start mechanisms.
- If both auto-start installs fail, surface a loud `zenity.Error` so the admin can't silently end up with a kiosk that doesn't reboot-survive.

Threat-model note: the scheduled task is technically weaker than the Service (a kiosk user with admin privileges could `schtasks /Delete` it). On a non-admin kiosk user account the task is admin-only to delete, same as the Service. "Weaker auto-start that works" beats "stronger auto-start that doesn't fire" — the failure mode in the field was zero protection after reboot, which is the worst outcome.

## v1.1.3 — 2026-05-12

**Two critical bugs the v1.1.0–v1.1.2 line missed.** Reported from production logs.

### Bug A — controller crashed on first Win/Ctrl/Alt press

User-visible: install fresh, press Win key once, get the password modal, and the kiosk is bypassed because the controller crashed half-way through the modal.

Same `go-webview2` second-instance panic v1.1.1 / v1.1.2 closed at the toast call sites — v1.1.2 missed the bigger one, `askPasswordModal`. The controller has already used WebView2 once during `firstRunWithWizard`; the LL hook firing on the first key combo calls `promptAndReinject` → `askPasswordModal` → second `NewWithOptions` → panic on the `time.AfterFunc` goroutine with no recover → controller dies, LL hook dies with it, user is past the kiosk before the modal finishes drawing. Confirmed from logs:

```
[01:55:17.167] LL keyboard hook installed (handle=3277641)
… modal opens, panics at chromium.go:131 …
"i got a full screen option to close the filter and then it crashed and let me get passed it"
```

Fix: `askPasswordModal` now spawns `kiosk-exit-guard.exe --ask-password <title> <subtitle>` as a child process and reads its exit code (0=OK, 1=Wrong, 2=Cancel). The child's WebView2 is always its first instance, so the panic class is structurally eliminated. The in-process implementation is preserved as `askPasswordModalInProcess` and used only by the `--ask-password` flag handler. Every call site (`runPauseInvocation`, `runUpdateInvocation`, `runUninstallInvocation`, `runReset`, `runSetURL`, and most importantly the controller's LL-hook-callback path) goes through the child route automatically — no per-site changes needed.

### Bug B — service couldn't spawn its child controller (filter only ran when manually launched)

User-visible: "right now the filter only runs when I re-click the exe file from the downloads folder." After a reboot the kiosk had zero protection until the admin manually double-clicked the exe.

Root cause: `WTSQueryUserToken(activeConsoleSession)` returned `ERROR_NO_TOKEN` every 2 seconds for the entire session. The supervising Service's `spawnControllerInSession` couldn't get a primary token for the console user, so `CreateProcessAsUserW` never ran. v1.0.x's Task-Scheduler path (which would have worked) was removed in v1.1.0 in favor of the Service-only path, so when `WTSQueryUserToken` fails on a given install, there's no fallback. Documented Windows API but inconsistent on Win11 Home in the field. Confirmed from logs — same machine, every spawn attempt:

```
service: spawnControllerInSession(1) failed: WTSQueryUserToken(1):
  An attempt was made to reference a token that does not exist.
```

Fix: if `WTSQueryUserToken` fails, fall back to stealing `explorer.exe`'s primary token in the same session. `explorer.exe` is guaranteed to exist whenever a user has reached the desktop, and its token represents that user's identity. To handle UAC, `tokenFromExplorerInSession` then calls `GetTokenInformation(TokenElevationType)` to detect a split-token state; if it's Limited (UAC-on admin user with the unelevated half running explorer), it unwraps to the linked elevated token via `GetTokenInformation(TokenLinkedToken)`. The controller needs admin (HKLM writes, IFEO, Explorer restart) so the limited half is not usable.

The `WTSQueryUserToken` path is still tried first because it's the documented one and works on most installs. Only the failure path goes via explorer.exe-token.

## v1.1.2 — 2026-05-12

**Generalizes v1.1.1's child-process toast workaround to every call site.**

Symptom: user resumes (or pause auto-expires), shortcut says "SK Filter is already active", but the Windows key is no longer blocked. Root cause is the same `go-webview2` second-instance panic as v1.1.1, hit by a different call site: `autoReenableFilterMode` at pause expiry was rendering its "Pause ended" toast in-process via `showTimedInfo`, which was the controller's second `NewWithOptions` call (the first having been `firstRunWithWizard`). The panic ran on the `time.AfterFunc` goroutine which has no recovery, so the controller crashed; the Service respawned it within ~1 s, but in that gap the LL keyboard hook was gone and Win/Ctrl/Alt fell through. Same path bit any flow that combined `askPasswordModal` with a follow-up `showFailedToast` on wrong password — pause / update / uninstall / set-URL / reset.

Fix: `showTimedInfo` now always spawns `kiosk-exit-guard.exe --show-toast <ms> <text>` as a fire-and-forget child process instead of instantiating WebView2 in the caller's process. The child's WebView2 is always its first. The v1.1.1 per-call workaround in `runUpdateInvocation` is reverted to a plain `showTimedInfo` call now that the universal path does the same thing.

## v1.1.1 — 2026-05-12

**`--update` panic from `go-webview2` double-instance.** The "Update SK Filter" shortcut launched a "Checking GitHub for updates…" toast via in-process WebView2 and then opened the password modal as a second WebView2 in the same process. `go-webview2` panics on the second `NewWithOptions` per process (`chromium.go:131`). Worked around in v1.1.1 by spawning the toast in a separate `--show-toast` child process; v1.1.2 generalizes this to every toast call site.

## v1.1.0 — 2026-05-12

**Windows Service supervisor + LL-hook thread-pinning fix.** Replaces the v1.0.x Task-Scheduler-based auto-start with a real Windows Service running as `LocalSystem` in Session 0. The kiosk user can no longer reach `schtasks /Delete` to neutralize the watchdog — Service control requires admin rights, which the kiosk user doesn't have.

Architecture:

- **New supervising Service `KioskExitGuardSvc`.** Display name "Kiosk Exit Guard Service". Runs as `LocalSystem`, `StartType = Automatic`. Has no UI of its own (Services run in Session 0, isolated from user sessions since Vista). Its only job is to find the active console session via `WTSGetActiveConsoleSessionId`, get the user's token via `WTSQueryUserToken`, duplicate it to a primary token via `DuplicateTokenEx`, build a per-user environment block via `CreateEnvironmentBlock`, and spawn `kiosk-exit-guard.exe` into that session via `CreateProcessAsUserW` with `lpDesktop = "winsta0\default"`. Waits for the controller to exit, sleeps 1s, respawns. On `sc stop` it terminates the running controller via `TerminateProcess` so an unattended controller can't outlive its supervisor.
- **Two-process model.** The Service is the supervisor; the existing controller code (LL hook, WebView2 kiosk, password modal, etc.) runs unchanged as the user-session process spawned by the Service. The same `kiosk-exit-guard.exe` binary is both — flag selects the role: `--service-run` (SCM-only), `--service-install` (admin), `--service-remove` (admin), no args = controller.
- **First-run integration.** `firstRunWithWizard()` now calls `installService()` instead of `installStartupTask()`. The Service is registered, started, and any leftover v1.0.x scheduled task is deleted in the same call so the two managers don't fight. If service install fails (locked-down SCM, unusual SKU), falls back to the v1.0.x scheduled-task path so the device isn't left without auto-start.
- **Uninstall integration.** `runUninstallInvocation` now stops and deletes the Service before tearing down everything else. Without this, the supervisor would respawn the controller mid-teardown.
- **First-run guard for service-spawned controllers.** The Service sets `KIOSK_EXIT_GUARD_VIA_SERVICE=1` in the spawned controller's environment block. If the controller boots and finds no password configured, it checks for that marker — if present, it logs and exits silently instead of popping the wizard. Prevents the Service from respawn-looping a stack of first-run wizards every few seconds on a half-installed device.
- **Update flow.** `--update` now does `sc stop KioskExitGuardSvc` before renaming the exe, and `sc start` after. Falls back to `schtasks /Run` if the service isn't registered (rare, mid-migration installs).

Reliability:

- **`runtime.LockOSThread()` at the top of `main()`** (v1.0.7 fix folded into this release). Pins the main goroutine to its initial OS thread for the life of the process. The Win32 LL keyboard hook installed via `SetWindowsHookExW` is bound to the thread that called it, and events only dispatch while THAT thread is running a `GetMessage` loop. If the Go runtime migrates this goroutine to a different OS thread between `SetWindowsHookExW` and `GetMessageW` (which happened reliably on first-run install because `firstRunWithWizard()` runs a WebView2 message loop that leaves the goroutine on a different thread), the hook silently goes dead — symptom: Ctrl/Win/Alt combos fall through instead of opening the password modal. Pinning at the top of `main()` keeps the hook's install thread and message-pump thread the same.

Caveats:

- The Service runs as `LocalSystem` because `WTSQueryUserToken` requires `SE_TCB_NAME`, which only `LocalSystem` has by default. Don't change `ServiceStartName` away from blank-(LocalSystem) without granting the new account that privilege.
- On boot before any user logs in, the supervisor finds `WTSGetActiveConsoleSessionId == 0xFFFFFFFF` and polls every 2 s. The controller doesn't start until a user is logged into the console — same behavior the user perceives as v1.0.x's logon trigger.

## v1.0.6 — 2026-05-12

**Production-readiness fixes from a multi-agent security and UX audit.**

Security:

- Per-process random re-injection nonce. The old `kioskMarkerCode = 0xC0DE` fixed constant meant any other process could call `SendInput` with that ExtraInfo value and bypass the LL keyboard hook. Replaced with a `uintptr` drawn from `crypto/rand` at controller startup and never written to the log file. Every process restart re-randomizes; no attacker-observable value.
- Taskbar hidden while the filter is active. `applyLockdown` now writes `NoTaskbar=1` under `HKCU\…\Policies\Explorer` and restarts Explorer so the change takes effect immediately. Closes the Start-button left-click escape — a user could previously click Start, then click the kiosk's taskbar entry to focus and close it.
- WebView2 kiosk hardening. Default context menus, dev tools (F12 / Ctrl+Shift+I), the status bar, and zoom controls are disabled via the WebView2 `Settings` object. `NewWindowRequested` is handled and rejected, so popups, target=_blank links, and `window.open` calls cannot spawn a second WebView2 window outside the kiosk. Closes the file-picker, dev-tools, and child-window escape paths.
- IFEO Debugger redirects extended to accessibility helpers. `sethc.exe`, `osk.exe`, `narrator.exe`, `utilman.exe`, and `magnify.exe` now redirect to `kiosk-exit-guard --silent-exit` alongside `chrome.exe` / `msedge.exe`. Closes the Sticky-Keys-five-shifts / Narrator / Ease-of-Access escape that ran an accessibility tool above the kiosk.
- Atomic CompareAndSwap on `promptOpen` inside `hookCallback`. The previous check-then-set was TOCTOU — a second blocked combo arriving while the first was still being dispatched to the goroutine could overwrite `pendingComboV` and re-inject the wrong keystroke after auth. The hook itself now owns the CAS so only one in-flight prompt can exist.
- Modifier snapshot captured inside `hookCallback` synchronously. `capturedModifiers()` used to be called by the goroutine after the 200+ ms WebView2 modal spawn delay; a user who released the modifiers in that window would re-inject a bare key on success. Captured at the moment the LL hook fires now, so re-injection always uses the modifier state at press time.

UX:

- Password modals now distinguish cancel from wrong-password. `askPasswordModal` returns a `passwordResult` enum (`pwOK` / `pwWrong` / `pwCancel`); every call site was rewritten so a user clicking Cancel no longer triggers the "Wrong password" toast. Cancelling the pause / update / uninstall / reset / set-url flows is now silent (the correct affordance) rather than shaming.
- Wrong-password retry happens inline inside the modal. Up to 3 attempts; the error appears in the modal's `#err` div (kept hidden until needed) with "N attempts left" feedback. Eliminates the cold-start delay of spawning a second WebView2 host just to render a "Wrong password" toast — the existing modal stays up and the input is re-focused and cleared.
- Cross-process modal serialization via a `Global\KioskExitGuardPromptMutex` named mutex. Previously, double-clicking the "Pause SK Filter" shortcut twice in quick succession opened two stacked fullscreen modals. The second `askPasswordModal` call now detects the existing owner, shows "Another SK Filter prompt is already open — finish that one first", and returns immediately.
- `--pause` shortcut now refuses to re-pause when a pause is already in flight. Previously it would silently overwrite a 100-minute pause with a fresh 5-minute one. Now shows the existing pause's remaining time and points the user at "Resume SK Filter" to end early.
- `--resume` shortcut shows a confirm dialog with the remaining pause time before clearing the pause. Prevents misclicks during long pause windows from snapping the kiosk back. Also no-ops with feedback if no pause is in flight.
- `sync` loop gained a third branch: if the on-disk pause deadline is rewritten while the controller is already paused (a future feature: extending a pause from another process), the controller re-arms its `time.AfterFunc` timer to the new deadline rather than auto-resuming early based on the old one.
- `--update` flow now stops the controller's scheduled task before attempting the exe rename. Previously the rename failed with "access is denied" because Windows held an exclusive lock on the running .exe, and the admin had no in-UI path forward. The update now: `schtasks /End` → `taskkill` → 500 ms settle → up-to-5 rename retries → `schtasks /Run`. On rename failure the controller is automatically restarted so the device isn't left unprotected.
- First-run wizard falls back to plain zenity dialogs when WebView2 creation fails. Previously a WebView2 crash on a stripped Windows image left the admin with no setup path and a silent `os.Exit(1)`.
- First-run wizard cancel/X-out now shows an explanatory dialog instead of a silent exit so the admin understands they need to re-launch.
- Chrome silent uninstall is now bounded by a 60s `context.WithTimeout`. Hung uninstallers no longer freeze first-run setup; the IFEO block is what actually prevents kiosk-escape via Chrome, so a leftover install is non-fatal.
- Kiosk URL prompt validates the scheme (`https://`, `http://`, `file:///`). Previously a typo like `htttp://example.com` saved silently and the WebView2 child showed a Chromium error page; the prompt now loops with a warning until the URL is valid.
- Uninstall reports failures in plain English mapped to remediation ("Open Task Scheduler and delete the task named …") instead of dumping raw `schtasks` output into a zenity dialog. Raw output is still written to `kiosk-exit-guard.log` for diagnosis.
- Pause-duration cancel now shows "Pause cancelled. SK Filter is still active." so a misclick is obvious instead of silent.
- Set-URL flow recognizes the zenity-cancel error and treats it as a clean exit rather than surfacing the raw "dialog cancelled" error message.

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
