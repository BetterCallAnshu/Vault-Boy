//! Single-instance enforcement.
//!
//! A named mutex with a DACL granting access only to the current user. A second
//! launch does not talk to the first one about secrets at all: it only restores
//! the existing window and exits, so there is no IPC surface to attack.

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_ALREADY_EXISTS, HANDLE, HLOCAL,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::System::Threading::CreateMutexW;
use windows::Win32::UI::WindowsAndMessaging::{
    FindWindowW, SetForegroundWindow, ShowWindow, SW_RESTORE,
};

use super::{acl, PlatformError, PlatformResult};

const MUTEX_NAME: windows::core::PCWSTR = w!("Local\\Vaultly.SingleInstance");

/// Holds the mutex for the lifetime of the process.
pub struct SingleInstance {
    handle: HANDLE,
}

impl Drop for SingleInstance {
    fn drop(&mut self) {
        // SAFETY: handle is owned by this struct and closed exactly once.
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

/// Returns `Some` for the first instance, `None` when another one is running.
pub fn acquire() -> PlatformResult<Option<SingleInstance>> {
    let sid = acl::current_user_sid_string()?;
    let sddl = format!("D:P(A;;GA;;;{sid})");
    let sddl_w: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();

    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: sddl_w is NUL-terminated and alive for the call.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_w.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
        .map_err(|_| {
            PlatformError::new("ConvertStringSecurityDescriptorToSecurityDescriptorW")
        })?;
    }

    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: windows::Win32::Foundation::FALSE,
    };

    // SAFETY: attributes points at a live descriptor for this call; the mutex
    // handle is owned by the returned guard.
    let created = unsafe { CreateMutexW(Some(&attributes), true, MUTEX_NAME) };
    // SAFETY: GetLastError has no preconditions and must be read immediately.
    let already_exists = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
    // SAFETY: matching LocalFree for the descriptor above.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
    }

    match created {
        Ok(handle) if already_exists => {
            // SAFETY: handle is owned by this branch and not stored.
            unsafe {
                let _ = CloseHandle(handle);
            }
            Ok(None)
        }
        Ok(handle) => Ok(Some(SingleInstance { handle })),
        Err(_) => Err(PlatformError::new("CreateMutexW")),
    }
}

/// Restore and focus the running instance's window.
pub fn focus_running_instance() {
    // SAFETY: window lookup by title; the handle is only used for two
    // documented activation calls and not retained.
    unsafe {
        if let Ok(window) = FindWindowW(PCWSTR::null(), w!("Vaultly")) {
            let _ = ShowWindow(window, SW_RESTORE);
            let _ = SetForegroundWindow(window);
        }
    }
}
