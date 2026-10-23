//! Cryptographic primitives.
//!
//! Only reviewed crates are used: `argon2` (Argon2id), `chacha20poly1305`
//! (XChaCha20-Poly1305), `hkdf`/`sha2` (HKDF-SHA256), `getrandom`
//! (BCryptGenRandom on Windows) and `subtle` (constant-time comparison).
//! Nothing in this module invents a primitive.

pub mod aead;
pub mod derive;
pub mod encoding;
pub mod kdf;
pub mod keys;

pub use keys::{install_page_locker, Key32, PageLocker, PAGE_SIZE};

/// Errors from the crypto layer. Deliberately opaque: they never contain key
/// material, plaintext or library internals.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("key derivation failed")]
    Kdf,
    #[error("encryption failed")]
    Encrypt,
    #[error("authentication failed")]
    Decrypt,
    #[error("the operating system random number generator failed")]
    Rng,
    #[error("invalid key derivation parameters")]
    InvalidParams,
    #[error("invalid recovery key")]
    RecoveryKey,
}

/// Constant-time equality for secret byte strings.
///
/// Length is compared first (length is not secret in our formats); content is
/// compared with [`subtle`]. Returning early on length is intentional and safe
/// here because every call site compares fixed-size material.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}
