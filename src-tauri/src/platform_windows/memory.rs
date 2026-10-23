//! Page locking for key material.
//!
//! `VirtualLock` is best effort: Windows enforces a per-process working-set
//! minimum that the application may raise, and a locked page can still be
//! written to a hibernation file by the kernel. It keeps secrets out of the
//! ordinary pagefile, which is the threat we claim.

use std::ffi::c_void;

use vaultly_core::crypto::keys::{Page, PageLocker, PAGE_SIZE};
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, VirtualLock, VirtualUnlock, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_READWRITE,
};

use super::{PlatformError, PlatformResult};

/// Installed into the crypto layer so every [`vaultly_core`] key page is
/// `VirtualLock`ed for its lifetime.
pub struct WindowsPageLocker;

impl PageLocker for WindowsPageLocker {
    fn lock(&self, page: &Page) -> bool {
        let address = page.as_ptr() as *const c_void;
        // SAFETY: `page` is a live, page-aligned 4 KiB allocation owned by the
        // caller for at least as long as the lock. VirtualLock only pins it.
        unsafe { VirtualLock(address, PAGE_SIZE).is_ok() }
    }

    fn unlock(&self, page: &Page) {
        let address = page.as_ptr() as *const c_void;
        // SAFETY: same live allocation previously passed to VirtualLock.
        unsafe {
            let _ = VirtualUnlock(address, PAGE_SIZE);
        }
    }
}

/// A page-aligned, `VirtualLock`ed scratch buffer for plaintext that must not
/// reach the pagefile (for example a password about to be written to the
/// clipboard).
pub struct LockedBuffer {
    address: *mut u8,
    len: usize,
}

impl LockedBuffer {
    pub fn new(len: usize) -> PlatformResult<Self> {
        if len == 0 {
            return Err(PlatformError::with_code("VirtualAlloc", 87));
        }
        // SAFETY: VirtualAlloc with MEM_COMMIT|MEM_RESERVE and PAGE_READWRITE
        // returns a fresh committed region or null; no aliasing exists yet.
        let address = unsafe {
            VirtualAlloc(None, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) as *mut u8
        };
        if address.is_null() {
            return Err(PlatformError::new("VirtualAlloc"));
        }

        // SAFETY: address/len describe the allocation above. Failure only means
        // the working-set quota is exhausted; we then refuse to use unlocked
        // scratch memory for secrets.
        let locked = unsafe { VirtualLock(address as *const c_void, len).is_ok() };
        if !locked {
            // SAFETY: releasing the allocation created above.
            unsafe {
                let _ = VirtualFree(address as *mut c_void, 0, MEM_RELEASE);
            }
            return Err(PlatformError::new("VirtualLock"));
        }
        Ok(LockedBuffer { address, len })
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: the buffer owns `len` initialized bytes at `address` for its
        // whole lifetime; the mutable borrow prevents aliasing.
        unsafe { std::slice::from_raw_parts_mut(self.address, self.len) }
    }
}

impl Drop for LockedBuffer {
    fn drop(&mut self) {
        // SAFETY: address/len are the live allocation; overwriting before free
        // is the point of this type.
        unsafe {
            std::ptr::write_bytes(self.address, 0, self.len);
            let _ = VirtualUnlock(self.address as *const c_void, self.len);
            let _ = VirtualFree(self.address as *mut c_void, 0, MEM_RELEASE);
        }
    }
}
