//! Page-lock verification: the production `WindowsPageLocker` really
//! `VirtualLock`s key pages (`Key32::is_locked() == true`), locked scratch
//! buffers work, and a zero-length locked buffer is refused.
//!
//! The page locker is a process-wide `OnceLock`; only this test binary installs
//! it, so no other suite is affected. Quotas are tiny (two pages) on purpose.

use vaultly_core::crypto::keys::{install_page_locker, Key32};
use vaultly_lib::platform_windows::memory::{LockedBuffer, WindowsPageLocker};

#[test]
fn key_pages_are_virtual_locked_by_the_production_locker() {
    if install_page_locker(Box::new(WindowsPageLocker)).is_err() {
        panic!("FAIL: another test already installed a page locker");
    }

    let key = Key32::random().expect("CSPRNG");
    assert!(key.is_locked(), "FAIL: VirtualLock refused the key page");
    key.with_secret(|bytes| assert_eq!(bytes.len(), 32, "FAIL: key length"));
    println!("PASS: Key32 page is VirtualLock-ed (is_locked == true)");

    // Key drop unlocks and zeroizes without error; smoke through the path.
    drop(key);
    println!("PASS: locked key dropped cleanly");
}

#[test]
fn locked_scratch_buffer_works_and_zero_length_is_refused() {
    let mut buffer = LockedBuffer::new(64).expect("VirtualLock of a small scratch buffer");
    buffer.as_mut_slice()[..4].copy_from_slice(&[1, 2, 3, 4]);
    assert_eq!(&buffer.as_mut_slice()[..4], &[1, 2, 3, 4], "FAIL: locked buffer not writable");
    println!("PASS: LockedBuffer::new(64) locks and is writable");

    // Negative: a zero-length locked buffer makes no sense and must fail.
    assert!(LockedBuffer::new(0).is_err(), "FAIL: zero-length LockedBuffer must be refused");
    println!("PASS: LockedBuffer::new(0) refused (negative case)");
}
