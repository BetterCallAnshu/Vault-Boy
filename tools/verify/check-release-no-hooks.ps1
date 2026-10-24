# check-release-no-hooks.ps1
# Builds the release binary (unless -SkipBuild) and proves test/debug hooks are
# compiled out of it:
#   * control strings that MUST be present (so a broken scanner cannot pass),
#   * hook strings that MUST be absent (test env hooks, #[cfg(test)] temp
#     prefixes, libtest flags, inspector flags),
#   * no debug-port/test patterns anywhere in the production source,
#   * no debug/test commands in tauri::generate_handler![...].
# Prints one PASS/FAIL line per check; exits non-zero on any failure.
#
# Usage: powershell -ExecutionPolicy Bypass -File check-release-no-hooks.ps1 [-SkipBuild]

param(
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$exe = Join-Path $root "target\release\vaultly.exe"

# Project-local toolchain (same convention as the audit runs).
$cargoBin = Join-Path $root ".toolchain\cargo\bin"
if (Test-Path (Join-Path $cargoBin "cargo.exe")) {
    $env:CARGO_HOME = Join-Path $root ".toolchain\cargo"
    $env:RUSTUP_HOME = Join-Path $root ".toolchain\rustup"
    $env:PATH = "$cargoBin;$env:PATH"
    $cargo = Join-Path $cargoBin "cargo.exe"
} else {
    $cargo = "cargo"
}

if (-not $SkipBuild) {
    Write-Host "==> $cargo build --release --locked -p vaultly"
    & $cargo build --release --locked -p vaultly
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAIL: release build failed (exit $LASTEXITCODE)"
        exit 1
    }
}

if (-not (Test-Path -LiteralPath $exe)) {
    Write-Host "FAIL: release binary not found: $exe"
    exit 1
}

$size = (Get-Item -LiteralPath $exe).Length
$hash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
Write-Host "exe:    $exe"
Write-Host "size:   $size bytes"
Write-Host "sha256: $hash"

$failed = $false
$text = [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($exe))

# --- Scanner sanity: strings that MUST exist in the release binary. ---------
$controls = @(
    "Vaultly must not run elevated",   # process::fatal_dialog text
    "vaultly: startup failed"          # run() failure path
)
foreach ($needle in $controls) {
    if ($text.Contains($needle)) {
        Write-Host "PASS: scanner control present: `"$needle`""
    } else {
        Write-Host "FAIL: scanner control MISSING (`"$needle`") - scanner broken, results untrustworthy"
        $failed = $true
    }
}

# --- Forbidden: hooks / test code / debug listeners. ------------------------
$forbidden = @(
    @{ Needle = "VAULTLY_ATOMIC_CHILD"; Why = "test-child env hook (src-tauri/tests only)" },
    @{ Needle = "vaultly-acl-test";     Why = "#[cfg(test)] unit-test temp prefix" },
    @{ Needle = "vaultly-backoff-";     Why = "#[cfg(test)] unit-test temp prefix" },
    @{ Needle = "--nocapture";          Why = "libtest flag - no test harness is linked" },
    @{ Needle = "crash_child_writer";   Why = "planned test hook name" },
    @{ Needle = "VAULTLY_TEST_HOOK";    Why = "reserved test hook name" },
    @{ Needle = "--inspect";            Why = "inspector/debug-server flag" },
    @{ Needle = "inspectBrk";           Why = "inspector break-on-start flag" }
)
foreach ($item in $forbidden) {
    if ($text.Contains($item.Needle)) {
        Write-Host "FAIL: hook string present in release binary: `"$($item.Needle)`" ($($item.Why))"
        $failed = $true
    } else {
        Write-Host "PASS: absent from release binary: `"$($item.Needle)`""
    }
}

# --- Source scan: no debug port / inspector code exists at all. -------------
$srcDir = Join-Path $root "src-tauri\src"
$debugPortMatches = @(Get-ChildItem -Path $srcDir -Recurse -Filter *.rs |
    Select-String -Pattern "9229|--inspect|debug_port|ws://127\.0\.0\.1" -SimpleMatch:$false)
if ($debugPortMatches.Count -eq 0) {
    Write-Host "PASS: no debug-port/inspector patterns in production source"
} else {
    Write-Host "FAIL: debug-port/inspector patterns found in source:"
    $debugPortMatches | ForEach-Object { Write-Host "       $($_.Path):$($_.LineNumber): $($_.Line.Trim())" }
    $failed = $true
}

# --- invoke_handler must list only product commands. ------------------------
$libRs = Get-Content -Raw (Join-Path $srcDir "lib.rs")
$handlerMatch = [regex]::Match($libRs, "generate_handler!\[(?<body>[^\]]+)\]")
if (-not $handlerMatch.Success) {
    Write-Host "FAIL: generate_handler![...] not found in lib.rs"
    $failed = $true
} else {
    $commands = @($handlerMatch.Groups["body"].Value -split "," |
        ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })
    $suspicious = @($commands | Where-Object { $_ -match "(?i)(debug|test|dev|force)" })
    if ($suspicious.Count -eq 0) {
        Write-Host "PASS: $($commands.Count) IPC commands registered, none debug/test-named"
    } else {
        Write-Host "FAIL: suspicious IPC commands: $($suspicious -join ', ')"
        $failed = $true
    }
}

if ($failed) {
    Write-Host "FAIL: release binary contains hooks/debug surfaces (see above)"
    exit 1
}
Write-Host "PASS: release binary is free of test hooks and debug surfaces"
exit 0
