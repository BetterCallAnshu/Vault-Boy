# check-window-affinity.ps1
# Verifies that the OS honours the exact display-affinity call Vaultly's
# capture.rs makes: SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE=1)
# followed by a GetWindowDisplayAffinity read-back of 1, then the WDA_NONE=0
# round trip. Uses a hidden, off-screen, never-shown top-level window of this
# process: it does not steal focus, does not appear on screen or in the
# taskbar, and does not touch the desktop.
# Prints one PASS/FAIL line per step; exits non-zero on any failure.
#
# (Integration against the real Tauri window happens in Step 4.)
#
# Usage: powershell -ExecutionPolicy Bypass -File check-window-affinity.ps1

$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class VaultlyAffinityNative {
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool SetWindowDisplayAffinity(IntPtr hWnd, uint dwAffinity);
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool GetWindowDisplayAffinity(IntPtr hWnd, out uint pdwAffinity);
}
"@

$WDA_NONE = 0               # matches WDA_NONE used in capture.rs
$WDA_EXCLUDEFROMCAPTURE = 1 # matches WDA_EXCLUDEFROMCAPTURE used in capture.rs

$failed = $false
$form = $null
try {
    # A top-level window that is never shown: handle exists, window stays
    # invisible and unactivated.
    $form = New-Object System.Windows.Forms.Form
    $form.ShowInTaskbar = $false
    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::Manual
    $form.Location = New-Object System.Drawing.Point(-32000, -32000)
    $form.Size = New-Object System.Drawing.Size(1, 1)
    $hwnd = $form.Handle
    if ($hwnd -eq [IntPtr]::Zero) {
        Write-Host "FAIL: could not create the test window handle"
        exit 1
    }
    Write-Host "test window: hidden top-level HWND 0x$($hwnd.ToString('X')) (never shown)"

    # Step 1: exclude from capture, read back.
    $ok = [VaultlyAffinityNative]::SetWindowDisplayAffinity($hwnd, $WDA_EXCLUDEFROMCAPTURE)
    if (-not $ok) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Host "FAIL: SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE) failed, win32 error $err"
        $failed = $true
    } else {
        [uint32]$readback = 0
        if (-not [VaultlyAffinityNative]::GetWindowDisplayAffinity($hwnd, [ref]$readback)) {
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Host "FAIL: GetWindowDisplayAffinity failed, win32 error $err"
            $failed = $true
        } elseif ($readback -ne $WDA_EXCLUDEFROMCAPTURE) {
            Write-Host "FAIL: read-back $readback, expected $WDA_EXCLUDEFROMCAPTURE"
            $failed = $true
        } else {
            Write-Host "PASS: WDA_EXCLUDEFROMCAPTURE set and read back as $readback"
        }
    }

    # Step 2: clear back to WDA_NONE, read back (round trip both directions).
    $ok = [VaultlyAffinityNative]::SetWindowDisplayAffinity($hwnd, $WDA_NONE)
    if (-not $ok) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Host "FAIL: SetWindowDisplayAffinity(WDA_NONE) failed, win32 error $err"
        $failed = $true
    } else {
        [uint32]$readback = 99
        if (-not [VaultlyAffinityNative]::GetWindowDisplayAffinity($hwnd, [ref]$readback)) {
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Host "FAIL: GetWindowDisplayAffinity failed after reset, win32 error $err"
            $failed = $true
        } elseif ($readback -ne $WDA_NONE) {
            Write-Host "FAIL: read-back $readback after reset, expected $WDA_NONE"
            $failed = $true
        } else {
            Write-Host "PASS: WDA_NONE reset read back as $readback"
        }
    }
} finally {
    if ($form -ne $null) {
        $form.Dispose()
    }
}

if ($failed) {
    Write-Host "FAIL: window display affinity verification failed"
    exit 1
}
Write-Host "PASS: display-affinity set/reset round trip verified by the OS"
exit 0
