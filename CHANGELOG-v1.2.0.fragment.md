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
