//! Clipboard handling for secrets.
//!
//! Every secret copied by Vaultly is written with three marker formats:
//!
//! * `ExcludeClipboardContentFromMonitorProcessing` - keep clipboard monitors
//!   (including some DLP/remote tools) from processing the value;
//! * `CanIncludeInClipboardHistory = 0` - do not add it to Win+V history;
//! * `CanUploadToCloudClipboard = 0` - do not roam it to the cloud.
//!
//! Auto-clear is verified against `GetClipboardSequenceNumber`: if anything
//! else wrote to the clipboard in the meantime, Vaultly leaves it alone.

use std::ffi::c_void;

use windows::core::w;
use windows::Win32::Foundation::{HANDLE, HGLOBAL};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardSequenceNumber, OpenClipboard,
    RegisterClipboardFormatW, SetClipboardData,
};
use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
use windows::Win32::System::Ole::CF_UNICODETEXT;

use super::{PlatformError, PlatformResult};

const EXCLUDE_MONITOR: windows::core::PCWSTR =
    w!("ExcludeClipboardContentFromMonitorProcessing");
const NO_HISTORY: windows::core::PCWSTR = w!("CanIncludeInClipboardHistory");
const NO_CLOUD: windows::core::PCWSTR = w!("CanUploadToCloudClipboard");

struct ClipboardGuard {
    open: bool,
}

impl ClipboardGuard {
    fn open() -> PlatformResult<Self> {
        // SAFETY: opening with no owner window is documented and does not
        // require any live handle.
        unsafe { OpenClipboard(None) }.map_err(|_| PlatformError::new("OpenClipboard"))?;
        Ok(ClipboardGuard { open: true })
    }
}

impl Drop for ClipboardGuard {
    fn drop(&mut self) {
        if self.open {
            // SAFETY: balanced with the successful OpenClipboard above.
            unsafe {
                let _ = CloseClipboard();
            }
        }
    }
}

fn alloc_bytes(bytes: &[u8]) -> PlatformResult<HGLOBAL> {
    // SAFETY: GMEM_MOVEABLE allocation of an explicit size; ownership passes to
    // the clipboard on SetClipboardData.
    let handle = unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes.len()) }
        .map_err(|_| PlatformError::new("GlobalAlloc"))?;
    // SAFETY: handle is a live GMEM_MOVEABLE block of bytes.len() bytes.
    let pointer = unsafe { GlobalLock(handle) };
    if pointer.is_null() {
        return Err(PlatformError::new("GlobalLock"));
    }
    // SAFETY: destination is the locked block, source is the caller's slice.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), pointer as *mut u8, bytes.len());
        let _ = GlobalUnlock(handle);
    }
    Ok(handle)
}

/// Write `text` to the clipboard. Returns the sequence number so the caller can
/// verify the clear later.
pub fn copy_secret(text: &str) -> PlatformResult<u32> {
    let utf16: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let payload: &[u8] = unsafe {
        // SAFETY: reinterpreting a live &[u16] as bytes for a memcpy only.
        std::slice::from_raw_parts(utf16.as_ptr() as *const u8, std::mem::size_of_val(&utf16[..]))
    };

    let _guard = ClipboardGuard::open()?;
    // SAFETY: clipboard is open and owned by this thread.
    unsafe {
        let _ = EmptyClipboard();
    }

    let text_handle = alloc_bytes(payload)?;
    // SAFETY: clipboard is open; on success the clipboard owns text_handle.
    unsafe {
        SetClipboardData(CF_UNICODETEXT.0 as u32, Some(HANDLE(text_handle.0)))
            .map_err(|_| PlatformError::new("SetClipboardData"))?;
    }

    // DWORD 0 markers: "do not include in history", "do not upload to cloud".
    let marker = 0u32.to_le_bytes();
    for name in [EXCLUDE_MONITOR, NO_HISTORY, NO_CLOUD] {
        // SAFETY: name is a static NUL-terminated string.
        let format = unsafe { RegisterClipboardFormatW(name) };
        if format == 0 {
            continue;
        }
        if let Ok(handle) = alloc_bytes(&marker) {
            // SAFETY: clipboard open; SetClipboardData takes ownership.
            unsafe {
                let _ = SetClipboardData(format, Some(HANDLE(handle.0)));
            }
        }
    }

    // SAFETY: no preconditions.
    Ok(unsafe { GetClipboardSequenceNumber() })
}

/// Clear the clipboard only if our value is still the current contents.
pub fn clear_if_sequence(expected: u32) -> bool {
    // SAFETY: no preconditions.
    if unsafe { GetClipboardSequenceNumber() } != expected {
        return false;
    }
    let Ok(_guard) = ClipboardGuard::open() else {
        return false;
    };
    // SAFETY: clipboard open and owned by this thread.
    unsafe { EmptyClipboard().is_ok() }
}

/// Current clipboard sequence, exposed for diagnostics/tests.
pub fn sequence() -> u32 {
    // SAFETY: no preconditions.
    unsafe { GetClipboardSequenceNumber() }
}

/// Kept so the unused-import lint stays honest about raw pointer types.
#[allow(dead_code)]
fn _assert_pointer_types(_: *const c_void) {}
