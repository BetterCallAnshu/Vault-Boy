# check-pe-mitigations.ps1
# Verifies the PE OptionalHeader.DllCharacteristics hardening bits of the
# release binary by parsing the PE header directly.
# Prints one PASS/FAIL line per bit; exits non-zero if a required bit is missing.
#
# Usage: powershell -ExecutionPolicy Bypass -File check-pe-mitigations.ps1 [-ExePath <path>]

param(
    [string]$ExePath = ""
)

$ErrorActionPreference = "Stop"

if (-not $ExePath) {
    $ExePath = Join-Path $PSScriptRoot "..\..\target\release\vaultly.exe"
}

if (-not (Test-Path -LiteralPath $ExePath)) {
    Write-Host "FAIL: release binary not found: $ExePath (run cargo build --release first)"
    exit 1
}
$ExePath = (Resolve-Path -LiteralPath $ExePath).Path

try {
    $bytes = [System.IO.File]::ReadAllBytes($ExePath)
} catch {
    Write-Host "FAIL: cannot read ${ExePath}: $_"
    exit 1
}

if ($bytes.Length -lt 0x40) {
    Write-Host "FAIL: file too small to be a PE image"
    exit 1
}

$eLfanew = [BitConverter]::ToInt32($bytes, 0x3C)
if ($eLfanew -lt 0x40 -or ($eLfanew + 24 + 72) -gt $bytes.Length) {
    Write-Host "FAIL: e_lfanew out of range ($eLfanew)"
    exit 1
}
if (-not ($bytes[$eLfanew] -eq 0x50 -and $bytes[$eLfanew + 1] -eq 0x45 -and
          $bytes[$eLfanew + 2] -eq 0 -and $bytes[$eLfanew + 3] -eq 0)) {
    Write-Host "FAIL: PE signature missing"
    exit 1
}

$optStart = $eLfanew + 24
$magic = [BitConverter]::ToUInt16($bytes, $optStart)        # 0x20B = PE32+
$dllCharacteristics = [BitConverter]::ToUInt16($bytes, $optStart + 70)

$magicName = switch ($magic) {
    0x20B { "PE32+" }
    0x10B { "PE32" }
    default { "unknown(0x$($magic.ToString('X')))" }
}
Write-Host "exe:   $ExePath"
Write-Host "format: $magicName"
Write-Host "DllCharacteristics: 0x$($dllCharacteristics.ToString('X4'))"

# IMAGE_DLLCHARACTERISTICS_* values from winnt.h.
$checks = @(
    @{ Name = "DYNAMICBASE (ASLR)";            Mask = 0x0040; Required = $true },
    @{ Name = "NXCOMPAT (DEP)";                Mask = 0x0100; Required = $true },
    @{ Name = "HIGHENTROPYVA (64-bit ASLR)";   Mask = 0x0020; Required = ($magic -eq 0x20B) },
    @{ Name = "GUARD_CF (Control Flow Guard)"; Mask = 0x4000; Required = $true },
    @{ Name = "NO_SEH (informational)";        Mask = 0x0400; Required = $false },
    @{ Name = "FORCE_INTEGRITY (informational)"; Mask = 0x0080; Required = $false }
)

$failed = $false
foreach ($check in $checks) {
    $present = ($dllCharacteristics -band $check.Mask) -ne 0
    if ($present) {
        Write-Host "PASS: $($check.Name) present"
    } elseif ($check.Required) {
        Write-Host "FAIL: $($check.Name) MISSING"
        $failed = $true
    } else {
        Write-Host "INFO: $($check.Name) absent (informational only)"
    }
}

if ($failed) {
    Write-Host "FAIL: one or more required PE hardening bits are missing"
    exit 1
}
Write-Host "PASS: all required PE hardening bits present"
exit 0
