//! DACL hardening: only the current user may read the vault directory.
//!
//! We set a protected DACL containing exactly one ACE (current user, full
//! access) and verify it on startup. A changed ACL produces a warning, not a
//! silent failure.

use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    GetTokenInformation, SetFileSecurityW, TokenUser, DACL_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::{PlatformError, PlatformResult};

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

fn wide_str(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The current process token's user SID as a string.
pub fn current_user_sid_string() -> PlatformResult<String> {
    let mut token = HANDLE::default();
    // SAFETY: current process pseudo-handle is always valid; token receives an
    // owned handle we close below.
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .map_err(|_| PlatformError::new("OpenProcessToken"))?;
    }

    let mut needed = 0u32;
    // SAFETY: first call with a null buffer only reports the required length.
    unsafe {
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
    }
    if needed == 0 {
        // SAFETY: token was opened above and is closed on this path.
        unsafe {
            let _ = CloseHandle(token);
        }
        return Err(PlatformError::new("GetTokenInformation"));
    }

    let mut buffer = vec![0u8; needed as usize];
    // SAFETY: buffer is `needed` bytes, matching what the API requested.
    let result = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr() as *mut core::ffi::c_void),
            needed,
            &mut needed,
        )
    };
    if result.is_err() {
        // SAFETY: token is owned by this function.
        unsafe {
            let _ = CloseHandle(token);
        }
        return Err(PlatformError::new("GetTokenInformation"));
    }

    // SAFETY: the API filled a TOKEN_USER whose SID points into `buffer`, which
    // outlives this use.
    let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };

    let mut sid_string = PWSTR::null();
    // SAFETY: sid is valid for the lifetime of buffer.
    let converted = unsafe { ConvertSidToStringSidW(sid, &mut sid_string) };
    // SAFETY: token handle is owned by this function and no longer needed.
    unsafe {
        let _ = CloseHandle(token);
    }
    if converted.is_err() {
        return Err(PlatformError::new("ConvertSidToStringSidW"));
    }

    // SAFETY: ConvertSidToStringSidW returns a LocalAlloc'd string.
    let text = unsafe { sid_string.to_string() }
        .map_err(|_| PlatformError::new("ConvertSidToStringSidW"))?;
    // SAFETY: matching LocalFree for the string above.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sid_string.0 as *mut core::ffi::c_void)));
    }
    Ok(text)
}

fn expected_sddl() -> PlatformResult<String> {
    Ok(format!("D:P(A;;FA;;;{})", current_user_sid_string()?))
}

fn apply_private(path: &Path) -> PlatformResult<()> {
    let sddl = expected_sddl()?;
    let sddl_w = wide_str(&sddl);
    let path_w = wide(path);

    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: sddl_w is NUL-terminated and alive for the call; the returned
    // descriptor is LocalAlloc'd and freed below.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_w.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
        .map_err(|_| PlatformError::new("ConvertStringSecurityDescriptorToSecurityDescriptorW"))?;
    }

    // SAFETY: descriptor is a valid security descriptor from the call above.
    let applied = unsafe {
        SetFileSecurityW(
            PCWSTR(path_w.as_ptr()),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        )
    };
    // SAFETY: LocalAlloc'd descriptor no longer needed.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
    }
    if !applied.as_bool() {
        return Err(PlatformError::new("SetFileSecurityW"));
    }
    Ok(())
}

/// Apply the user-only DACL to the vault directory (inherited by new files).
pub fn ensure_private_directory(path: &Path) -> PlatformResult<()> {
    std::fs::create_dir_all(path).map_err(|_| PlatformError::with_code("create_dir", 5))?;
    apply_private(path)
}

/// Apply the user-only DACL to a single file.
pub fn apply_private_file(path: &Path) -> PlatformResult<()> {
    apply_private(path)
}

/// Read the DACL and compare it with the expected protected, user-only SDDL.
pub fn verify_private(path: &Path) -> PlatformResult<bool> {
    let expected = expected_sddl()?;
    let path_w = wide(path);
    let mut descriptor = PSECURITY_DESCRIPTOR::default();

    // SAFETY: path_w is NUL-terminated; descriptor is filled by the API and
    // freed below.
    let status = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &mut descriptor,
        )
    };
    if status.0 != 0 {
        return Err(PlatformError::with_code("GetNamedSecurityInfoW", status.0));
    }

    let mut text = PWSTR::null();
    // SAFETY: descriptor is valid and owned by us; text is LocalAlloc'd.
    let converted = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut text,
            None,
        )
    };
    // SAFETY: descriptor from GetNamedSecurityInfoW must be LocalFree'd.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
    }
    if converted.is_err() {
        return Err(PlatformError::new(
            "ConvertSecurityDescriptorToStringSecurityDescriptorW",
        ));
    }

    // SAFETY: text is a NUL-terminated, LocalAlloc'd string.
    let actual = unsafe { text.to_string() }.unwrap_or_default();
    // SAFETY: matching LocalFree for the string.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(text.0 as *mut core::ffi::c_void)));
    }

    Ok(actual.eq_ignore_ascii_case(&expected))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secures_and_verifies_a_directory() {
        let dir = std::env::temp_dir().join(format!("vaultly-acl-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        ensure_private_directory(&dir).expect("secure directory");
        assert!(verify_private(&dir).expect("verify"), "ACL should match");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sid_string_is_well_formed() {
        let sid = current_user_sid_string().unwrap();
        assert!(sid.starts_with("S-1-"), "unexpected SID {sid}");
    }
}
