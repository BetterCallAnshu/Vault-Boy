# run-all.ps1
# Top-level Step 2 verifier. Runs every pre-approved check (headless, own
# process, no desktop interference), prints a summary table, and exits
# non-zero if anything failed.
#
#   -IncludeClipBoard   run the clipboard suite. WARNING: it overwrites your
#                       Windows clipboard (original plain text is restored on
#                       best effort; other formats like copied files/images are
#                       not). Off by default.
#   -IncludeDisruptive  print the manual checklist (session lock/logoff/RDP/
#                       suspend, debugger attach, real-window checks). Those
#                       never run automatically - they only appear as NEEDS HUMAN
#                       rows with numbered steps. Off by default.
#   -SkipReleaseBuild   reuse an existing release binary for the no-hooks scan.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File tools\verify\run-all.ps1
#   powershell -ExecutionPolicy Bypass -File tools\verify\run-all.ps1 -IncludeClipBoard
#   powershell -ExecutionPolicy Bypass -File tools\verify\run-all.ps1 -IncludeDisruptive

param(
    [switch]$IncludeClipBoard,
    [switch]$IncludeDisruptive,
    [switch]$SkipReleaseBuild
)

$ErrorActionPreference = "Continue"
$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $root

# Project-local Rust toolchain (same convention as the audit runs).
$cargoBin = Join-Path $root ".toolchain\cargo\bin"
if (Test-Path (Join-Path $cargoBin "cargo.exe")) {
    $env:CARGO_HOME = Join-Path $root ".toolchain\cargo"
    $env:RUSTUP_HOME = Join-Path $root ".toolchain\rustup"
    $env:PATH = "$cargoBin;$env:PATH"
    Write-Host "toolchain: project-local ($cargoBin)"
} else {
    Write-Host "toolchain: system cargo from PATH"
}

$script:results = @()

function Add-Result {
    param([string]$Name, [string]$Status, [string]$Detail = "")
    $script:results += [pscustomobject]@{ Check = $Name; Status = $Status; Detail = $Detail }
}

# Run a scriptblock whose last native command sets $LASTEXITCODE.
function Invoke-Step {
    param([string]$Name, [scriptblock]$Action)
    Write-Host ""
    Write-Host "=== $Name ===" -ForegroundColor Cyan
    $global:LASTEXITCODE = 0
    & $Action
    $code = $LASTEXITCODE
    if ($code -eq 0) {
        Add-Result $Name "PASS" ""
        Write-Host ">>> PASS: $Name" -ForegroundColor Green
    } else {
        Add-Result $Name "FAIL" "exit $code"
        Write-Host ">>> FAIL: $Name (exit $code)" -ForegroundColor Red
    }
}

# Child powershell process for .ps1 helpers - powershell.exe is a native
# command, so $LASTEXITCODE carries the helper's exit code back to Invoke-Step.
# (No `exit` here: exit would terminate the whole runner.)
function Invoke-Script {
    param([string]$Script, [string[]]$ExtraArgs = @())
    $argList = @("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $Script) + $ExtraArgs
    & powershell.exe @argList
}

Write-Host "Vaultly Step 2 verification runner"
Write-Host "root: $root"

# 1. Full Rust suite: unit tests + the six Win32 integration suites.
#    The clipboard suite self-skips here unless the env flag is set.
Invoke-Step "Rust: vaultly unit + Win32 integration suites" {
    cargo test --locked -p vaultly -- --nocapture
}

# 2. vaultly-core (crypto/vault format) suite including the fail-open test.
Invoke-Step "Rust: vaultly-core crypto/vault suite" {
    cargo test --locked -p vaultly-core
}

# 3. Clipboard suite (gated: overwrites the desktop clipboard).
if ($IncludeClipBoard) {
    Write-Host ""
    Write-Host "WARNING: the clipboard checks below OVERWRITE your Windows clipboard." -ForegroundColor Yellow
    Write-Host "Your current plain text is snapshotted and restored afterwards;" -ForegroundColor Yellow
    Write-Host "other clipboard formats (copied files/images) are NOT restorable." -ForegroundColor Yellow
    Invoke-Step "Rust: clipboard suite (gated)" {
        $env:VAULTLY_ALLOW_CLIPBOARD_TESTS = "1"
        cargo test --locked -p vaultly --test clipboard_verify -- --nocapture
        $env:VAULTLY_ALLOW_CLIPBOARD_TESTS = $null
    }
} else {
    Write-Host ""
    Write-Host "=== clipboard suite ===" -ForegroundColor Cyan
    Write-Host "SKIPPED: gated behind -IncludeClipBoard (it overwrites the clipboard)"
    Add-Result "clipboard suite (gated)" "SKIPPED" "use -IncludeClipBoard"
}

# 4. PE hardening bits of the release binary.
Invoke-Step "PE: release DllCharacteristics hardening bits" {
    Invoke-Script (Join-Path $PSScriptRoot "check-pe-mitigations.ps1")
}

# 5. Release build + no test hooks / no debug surfaces.
$noHooksArgs = @()
if ($SkipReleaseBuild) { $noHooksArgs += "-SkipBuild" }
Invoke-Step "Release: no test hooks / no debug surfaces" {
    Invoke-Script (Join-Path $PSScriptRoot "check-release-no-hooks.ps1") $noHooksArgs
}

# 6. Display affinity round trip on this process's own hidden window.
Invoke-Step "Win32: SetWindowDisplayAffinity read-back" {
    Invoke-Script (Join-Path $PSScriptRoot "check-window-affinity.ps1")
}

# 7. Disruptive / manual items: never executed automatically.
if ($IncludeDisruptive) {
    Write-Host ""
    Write-Host "=== Manual checklist (requires a human; never automated) ===" -ForegroundColor Cyan
    @(
        "1. Lock workstation (Win+L) while unlocked  -> vault must lock.",
        "2. Log off while unlocked                    -> vault must lock.",
        "3. Start RDP session, disconnect, reconnect   -> vault must lock.",
        "4. Suspend/resume the machine                -> vault must lock.",
        "5. Attach a debugger to the release process  -> debugger_detected status true / behavior documented.",
        "6. Real app window: capture exclusion (PrintScreen / Win+Shift+S) shows nothing.",
        "7. Real app window: WebView2 settings read-back (devtools/context menu/password save off).",
        "8. Second instance launch                    -> focuses the first, exits."
    ) | ForEach-Object { Write-Host "  $_" }
    Add-Result "manual checklist (session/RDP/suspend/debugger/window)" "NEEDS HUMAN" "see steps above"
} else {
    Add-Result "manual checklist (session/RDP/suspend/debugger/window)" "SKIPPED" "use -IncludeDisruptive"
}

# Summary -------------------------------------------------------------------
Write-Host ""
Write-Host "=== SUMMARY ===" -ForegroundColor Cyan
$results | Format-Table -AutoSize | Out-String | Write-Host

$failed = @($results | Where-Object { $_.Status -eq "FAIL" })
if ($failed.Count -gt 0) {
    Write-Host "RESULT: $($failed.Count) check(s) FAILED" -ForegroundColor Red
    exit 1
}
Write-Host "RESULT: all executed checks passed" -ForegroundColor Green
exit 0
