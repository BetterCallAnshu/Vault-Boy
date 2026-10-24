# Vaultly Audit — Status Handoff

Paused mid **Step 2**. Resume from "Next actions" below.

## Rules in force (from user)
- Never claim "works"/"tested" without saying how it was verified.
- Do not loosen tsconfig, add `any`, disable lint rules, or weaken a security
  setting to make something pass. Security tradeoff needed → stop and ask.
- Keep `unsafe` confined to `platform_windows/`.
- Stop and report after each step; wait for go-ahead before the next.
- One commit per logical fix.
- Use `cargo build --locked` and `npm ci`.
- No new features this pass: no tray, hotkey, Hello, SendInput, docs, CI.

## Step 1 — DONE (committed)
- `git init`, `.gitignore` extended (covers `.toolchain/`, `target/`, `node_modules/`,
  `dist/`, `*.vlt*`, `*.vault*`, `*.log`, `lockout.dat`, `device.key`, `settings.json`, `.env`).
- Verified staging clean: 77 files, no secrets/vaults/toolchain binaries.
- Baseline commit: **55511331ad1c68757fe4871cb499cb7068a3ed86** — "Baseline: pre-audit state".
- Both lockfiles committed (`Cargo.lock`, `package-lock.json`).
- Repo size `.git` = 479K.

## Step 2 — IN PROGRESS
Goal: Win32 verification audit. Repeatable scripts in `tools/verify/`, each exits
non-zero on failure, prints PASS/FAIL, cleans up. Top runner `tools/verify/run-all.ps1`
runs pre-approved checks; disruptive ones behind `-IncludeDisruptive` (clipboards etc).
Write negative tests too. Prove test hooks are compiled out of release.

### Permissions
- Pre-approved (headless, own process, no desktop): ACL read-back, mitigation
  read-back, PE header checks, atomic-write + kill-mid-write, backoff tamper,
  DPAPI round-trip, clipboard format/sequence checks, memory-dump scans.
- ASK FIRST (tell what will happen): LockWorkStation, sleep/hibernate, anything
  stealing focus or screenshotting desktop, anything overwriting clipboard.
- Never touch real vaults. Throwaway vault + temp dir for every test.

### Work already changed (UNCOMMITTED)
- `src-tauri/src/platform_windows/mitigations.rs`: added **`read_back()`** +
  `query_policy()` helper. Uses `GetProcessMitigationPolicy(GetCurrentProcess(), ...)`
  to read the real OS state for all 5 policies. Production feature (diagnostics +
  Step 4 verification), NOT a test hook. Needs `cargo build --locked` to confirm it
  compiles (imports `GetProcessMitigationPolicy`, `GetCurrentProcess`).
  → This is the first commit of Step 2 once it compiles.

### Planned test targets (Rust, `src-tauri/tests/`)
Each is its own process; `unsafe` only inside existing `platform_windows` pub API.
1. `acl_verify.rs` — ensure/verify positive; tamper DACL via external `icacls` then
   `verify_private` must return false (negative). Display real SDDL via PowerShell `Get-Acl`.
2. `atomic_write_verify.rs` — write/backup/corrupt-recover; simulated crash (temp
   written, replace not executed) leaves target untouched; kill-mid-write invariant
   (target never torn) with a naive-write child control that CAN tear (non-vacuous).
3. `backoff_verify.rs` — persistence, flip-byte tamper → rejected + max delay,
   success reset, DPAPI round-trip.
4. `mitigations_verify.rs` — `apply(false)` (4 core policies, NOT signature, to avoid
   blocking non-MS DLL loads in throwaway process) then `read_back()`; assert the 4
   core are true; signature read-back reported (control = false). Prints report.
5. `clipboard_verify.rs` — env-gated (`VAULTLY_ALLOW_CLIPBOARD_TESTS=1`, default skip):
   exclusion formats present, sequence-number auto-clear, preserve external value.
6. `memory_verify.rs` — install real `WindowsPageLocker`, `Key32.is_locked()==true`
   (VirtualLock works); `LockedBuffer::new(small)==Ok`. Do NOT attempt huge locks.
7. `crates/vaultly-core/src/crypto/keys.rs` — add `#[cfg(test)]` unit test: install a
   FAILING locker → `Key32.is_locked()==false` (documents current fail-open behavior).

### Planned PowerShell scripts (`tools/verify/`)
- `run-all.ps1` — orchestrator; summary table; clipboard behind `-IncludeClipBoard`;
  disruptive behind `-IncludeDisruptive` (session/sleep/RDP are manual, just print).
- `check-pe-mitigations.ps1` — parse release EXE OptionalHeader.DllCharacteristics
  (PE32+ DllCharacteristics at optional-header offset 70): DYNAMICBASE 0x40,
  NXCOMPAT 0x100, HIGHENTROPYVA 0x200, GUARD_CF 0x4000.
- `check-release-no-hooks.ps1` — `cargo build --release --locked`, scan binary for
  hook strings (e.g. `VAULTLY_ATOMIC_CHILD`, `crash_child_writer`, test-command names,
  debug port) and confirm absent.
- `check-window-affinity.ps1` — hidden WinForms window; SetWindowDisplayAffinity
  (WDA_EXCLUDEFROMCAPTURE=1) then GetWindowDisplayAffinity read-back = 1, then WDA_NONE=0.
  (Verifies the OS honors the flag the code sets; webview-window integration = Step 4.)

### Status table format (required): Feature | What the code does | Automated test (name)
### | Verified how | Status. Status ∈ {Verified, Compiles only, Unverified, Needs human}.

### Likely "Needs human" / manual (write numbered checklist, mark Unverified until confirmed)
- Session watcher events: lock, logoff, RDP disconnect, suspend, shutdown
  (needs LockWorkStation/sleep/RDP → permission required).
- Debugger detection positive path (attach a debugger).
- WebView2 hardening actual settings (needs running window = Step 4).
- Application of capture exclusion + single-instance kernel DACL + DLL hijack demo
  (may be verifiable in Step 4 against the real app).

### Next actions (in order)
1. `cargo build --locked` to confirm `read_back()` compiles. Fix if not. Commit as
   "Add GetProcessMitigationPolicy read-back".
2. Create `tools/verify/`, write the Rust test targets above, run them.
3. If any test exposes a bug → STOP, report, then fix in its own commit.
4. If a test passes first try, confirm it can fail (negative/control cases).
5. Write the PowerShell scripts + `run-all.ps1`.
6. Build release with `cargo build --locked`, run PE + no-hooks scripts.
7. Produce the Step 2 report (table + new tests + manual checklist), then STOP and
   wait for go-ahead for Step 3.

## Later steps (not started)
- **Step 3:** `src/main.tsx` + `src/App.tsx` (Onboarding→Unlock→Vault, theme follows
  Windows), `tsc --strict --noEmit` + ESLint (report counts grouped by cause first),
  IPC audit + typed wrapper (prefer specta/ts-rs), no vault data in
  localStorage/sessionStorage/IndexedDB/cache (grep + runtime), CSP has no
  unsafe-inline/eval, `npm run build` clean.
- **Step 4:** release launch all mitigations on, WebView renders, bisect any
  conflicting mitigation (report, do NOT silently disable), smoke test table.
- **Final report:** 1 honest paragraph, Win32 table, manual checklist, open decisions,
  commit list.
