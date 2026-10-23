//! Vault format, storage model and derived features.
//!
//! Nothing here performs IO: the caller reads the vault file, hands the bytes
//! to [`store::Vault::unlock`], and writes back what
//! [`store::Vault::to_bytes`] returns. That keeps the format testable and keeps
//! the Windows layer in charge of atomic replacement and ACLs.

pub mod csvio;
pub mod format;
pub mod generator;
pub mod health;
pub mod index;
pub mod model;
pub mod search;
pub mod store;
pub mod totp;
pub mod wordlist;

pub use store::{CreateOptions, CreatedVault, EntryDraft, EntryPatch, Vault};

/// Errors surfaced to the UI.
///
/// Variants are deliberately coarse: the frontend learns *what* failed, never
/// *why* in cryptographic detail, and no variant ever carries plaintext.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum VaultError {
    #[error("this file is not a Vaultly vault")]
    BadMagic,
    #[error("unsupported vault version")]
    UnsupportedVersion(u16),
    #[error("the vault file is corrupt or was modified")]
    Corrupt,
    #[error("incorrect master password")]
    InvalidPassword,
    #[error("entry not found")]
    NotFound,
    #[error("invalid input")]
    InvalidInput,
    #[error("cryptographic operation failed")]
    Crypto,
    #[error("could not parse the CSV file")]
    Csv,
    #[error("this build cannot perform that operation yet")]
    Unsupported,
}

impl From<crate::crypto::CryptoError> for VaultError {
    fn from(_: crate::crypto::CryptoError) -> Self {
        VaultError::Crypto
    }
}
