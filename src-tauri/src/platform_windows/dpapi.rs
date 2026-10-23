//! DPAPI helpers.
//!
//! Used only to protect the *device key* that HMACs the lockout state; never to
//! protect the vault itself (the vault uses the master-password-derived key).

use std::ffi::c_void;

use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};

use super::{PlatformError, PlatformResult};

fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    }
}

fn take_blob(output: CRYPT_INTEGER_BLOB) -> PlatformResult<Vec<u8>> {
    if output.pbData.is_null() {
        return Err(PlatformError::with_code("DPAPI", 0));
    }
    // SAFETY: DPAPI returned a LocalAlloc'd buffer of cbData bytes.
    let bytes = unsafe {
        std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec()
    };
    // SAFETY: matching LocalFree for the DPAPI output buffer.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(output.pbData as *mut core::ffi::c_void)));
    }
    Ok(bytes)
}

/// Protect bytes for the current user on this machine.
pub fn protect(data: &[u8]) -> PlatformResult<Vec<u8>> {
    let input = blob(data);
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: input points at `data` for the call; output is filled by DPAPI.
    unsafe {
        CryptProtectData(
            &input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
        .map_err(|_| PlatformError::new("CryptProtectData"))?;
    }
    take_blob(output)
}

/// Unprotect bytes previously protected for this user.
pub fn unprotect(data: &[u8]) -> PlatformResult<Vec<u8>> {
    let input = blob(data);
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: input points at `data` for the call; output is filled by DPAPI.
    unsafe {
        CryptUnprotectData(&input, None, None, None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut output)
            .map_err(|_| PlatformError::new("CryptUnprotectData"))?;
    }
    take_blob(output)
}

/// Silence an unused-parameter lint while keeping the c_void import honest.
#[allow(dead_code)]
fn _reserved(_: *const c_void) {}
