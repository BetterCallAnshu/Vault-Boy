//! Process-level hardening and environment checks.

use std::ffi::c_void;

use windows::core::{w, BOOL, PCWSTR};
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows::Win32::System::Diagnostics::Debug::{
    CheckRemoteDebuggerPresent, IsDebuggerPresent, SetErrorMode, SEM_FAILCRITICALERRORS,
    SEM_NOGPFAULTERRORBOX,
};
use windows::Win32::System::ErrorReporting::WerAddExcludedApplication;
use windows::Win32::System::LibraryLoader::{
    SetDefaultDllDirectories, SetDllDirectoryW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};

use super::{PlatformError, PlatformResult};

/// True when this process token is elevated (high integrity).
pub fn is_elevated() -> bool {
    let mut token = windows::Win32::Foundation::HANDLE::default();
    let opened = unsafe {
        // SAFETY: current process pseudo-handle is always valid; token receives
        // an owned handle closed below.
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_ok()
    };
    if !opened {
        return false;
    }

    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0u32;
    let size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
    // SAFETY: elevation is correctly sized for TokenElevation; token is live.
    let result = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut c_void),
            size,
            &mut returned,
        )
    };
    // SAFETY: token was opened above and is owned by this function.
    unsafe {
        let _ = CloseHandle(token);
    }
    result.is_ok() && elevation.TokenIsElevated != 0
}

/// True when the session is an RDP/remote session.
pub fn is_remote_session() -> bool {
    use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_REMOTESESSION};
    // SAFETY: pure query, no parameters.
    unsafe { GetSystemMetrics(SM_REMOTESESSION) != 0 }
}

/// Debugger detection. Documented as a speed bump: a debugger can hide itself,
/// and this is trivially bypassed by patching the check.
pub fn debugger_present() -> bool {
    // SAFETY: pure query.
    if unsafe { IsDebuggerPresent() }.as_bool() {
        return true;
    }
    let mut remote = BOOL(0);
    // SAFETY: current process pseudo-handle is valid; remote points to a BOOL.
    let result = unsafe { CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut remote) };
    result.is_ok() && remote.as_bool()
}

/// Restrict DLL search to System32 and clear the legacy DLL directory.
///
/// This prevents DLL search-order hijacking for any library loaded by name.
/// Vaultly's own dependencies are statically linked or loaded by absolute path.
pub fn harden_dll_search() -> PlatformResult<()> {
    // SAFETY: documented process-wide setting with no pointer arguments.
    unsafe {
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)
            .map_err(|_| PlatformError::new("SetDefaultDllDirectories"))?;
        let _ = SetDllDirectoryW(PCWSTR::null());
    }
    Ok(())
}

/// Suppress Windows Error Reporting dialogs and exclude Vaultly from WER.
pub fn suppress_crash_reporting() {
    // SAFETY: process-wide flag change; no pointers.
    unsafe {
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
        // Best effort: per-user WER exclusion so crash reports are not queued.
        let _ = WerAddExcludedApplication(w!("Vaultly.exe"), false);
    }
}

/// Show a blocking error dialog before exiting (used when refusing elevation).
pub fn fatal_dialog(title: &str, message: &str) {
    let title: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
    let message: Vec<u16> = message.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: both buffers are NUL-terminated and alive for the call.
    unsafe {
        MessageBoxW(
            None,
            PCWSTR(message.as_ptr()),
            PCWSTR(title.as_ptr()),
            MB_OK | MB_ICONERROR,
        );
    }
}
