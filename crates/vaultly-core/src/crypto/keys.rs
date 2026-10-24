//! Key material lives in page-aligned buffers that the Windows layer can lock
//! with `VirtualLock`, so it is excluded from the pagefile while alive.

use std::fmt;
use std::sync::OnceLock;

use zeroize::Zeroize;

use super::CryptoError;

/// Windows allocation granularity. A dedicated page per key makes
/// `VirtualLock` cover the whole secret instead of a partial page.
pub const PAGE_SIZE: usize = 4096;
const KEY_LEN: usize = 32;

/// A page-aligned 4 KiB buffer. Alignment is enforced by the type, without
/// `unsafe`, so the platform layer can lock the exact page.
#[repr(align(4096))]
pub struct Page(pub(crate) [u8; PAGE_SIZE]);

impl Page {
    pub(crate) fn zeroed() -> Box<Self> {
        Box::new(Page([0u8; PAGE_SIZE]))
    }

    /// Address of the page. Returning a pointer is safe; dereferencing it is
    /// the platform layer's responsibility (and only inside `unsafe`).
    pub fn as_ptr(&self) -> *const Page {
        self as *const Page
    }
}

/// Implemented by the Windows layer to lock key pages out of the pagefile.
pub trait PageLocker: Send + Sync {
    /// Lock the page. Returns `false` when the OS refused (working-set quota).
    fn lock(&self, page: &Page) -> bool;
    /// Unlock the page; called from `Key32::drop`.
    fn unlock(&self, page: &Page);
}

static PAGE_LOCKER: OnceLock<Box<dyn PageLocker>> = OnceLock::new();

/// Install the platform page locker. Must be called once, early in startup,
/// before any key is derived. Returns the locker back if one is already set.
pub fn install_page_locker(locker: Box<dyn PageLocker>) -> Result<(), Box<dyn PageLocker>> {
    PAGE_LOCKER.set(locker)
}

/// A 256-bit key in its own page.
///
/// * no `Debug` output, no `Clone`, no serialization;
/// * zeroized on drop;
/// * `VirtualLock`ed when a [`PageLocker`] is installed.
pub struct Key32 {
    page: Box<Page>,
    locked: bool,
}

impl Key32 {
    /// Wrap existing bytes. The caller owns zeroizing the source buffer.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        let mut page = Page::zeroed();
        page.0[..KEY_LEN].copy_from_slice(&bytes);
        let locked = PAGE_LOCKER
            .get()
            .map(|locker| locker.lock(&page))
            .unwrap_or(false);
        Key32 { page, locked }
    }

    /// Generate a key from the OS CSPRNG.
    pub fn random() -> Result<Self, CryptoError> {
        let mut bytes = [0u8; KEY_LEN];
        getrandom::fill(&mut bytes).map_err(|_| CryptoError::Rng)?;
        let key = Key32::from_bytes(bytes);
        bytes.zeroize();
        Ok(key)
    }

    /// Run a closure with the raw key bytes.
    ///
    /// This is the only exposure path: callers cannot hold a `&[u8; 32]`
    /// beyond the closure, which keeps accidental long-lived references rare.
    pub fn with_secret<R>(&self, f: impl FnOnce(&[u8; KEY_LEN]) -> R) -> R {
        let bytes: &[u8; KEY_LEN] = self.page.0[..KEY_LEN]
            .try_into()
            .expect("key page always holds a full key");
        f(bytes)
    }

    /// Whether the page is currently locked in RAM.
    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl Drop for Key32 {
    fn drop(&mut self) {
        self.page.0.zeroize();
        if self.locked {
            if let Some(locker) = PAGE_LOCKER.get() {
                locker.unlock(&self.page);
            }
        }
    }
}

impl fmt::Debug for Key32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key32([redacted])")
    }
}

impl fmt::Display for Key32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_are_page_aligned() {
        let key = Key32::from_bytes([7u8; 32]);
        assert_eq!(key.page.as_ptr() as usize % PAGE_SIZE, 0);
    }

    #[test]
    fn debug_never_prints_key_material() {
        let key = Key32::from_bytes([0xABu8; 32]);
        let rendered = format!("{key:?} {key}");
        assert!(!rendered.to_lowercase().contains("ab"));
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn with_secret_sees_exact_bytes() {
        let mut raw = [0u8; 32];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }
        let key = Key32::from_bytes(raw);
        key.with_secret(|bytes| assert_eq!(bytes, &raw));
    }

    /// A locker that always refuses, as Windows does when the working-set
    /// quota is exhausted.
    struct RefusingLocker;

    impl PageLocker for RefusingLocker {
        fn lock(&self, _page: &Page) -> bool {
            false
        }
        fn unlock(&self, _page: &Page) {}
    }

    /// Documents the fail-open contract: a refused `VirtualLock` leaves the
    /// key usable but honestly reports `is_locked() == false` — it never
    /// claims protection it does not have, and it never panics.
    #[test]
    fn key_reports_unlocked_when_the_platform_locker_refuses() {
        if install_page_locker(Box::new(RefusingLocker)).is_err() {
            panic!("another test already installed a page locker");
        }
        let key = Key32::from_bytes([9u8; 32]);
        assert!(!key.is_locked(), "a refusing locker must leave the key unlocked");
        key.with_secret(|bytes| assert_eq!(bytes[0], 9, "key must stay usable"));
    }
}
