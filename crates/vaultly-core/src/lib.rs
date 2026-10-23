//! Vaultly core: cryptography, vault format and data model.
//!
//! This crate deliberately has **no IO and no UI dependencies**. The Windows
//! layer supplies randomness (through `getrandom`), storage paths and page
//! locking; the core only ever sees byte slices and returns byte slices.
//!
//! Security invariants upheld here:
//! * all key material is wrapped in [`crypto::keys::Key32`], which lives in a
//!   page-aligned buffer, is zeroized on drop and can be `VirtualLock`ed by the
//!   platform through [`crypto::keys::install_page_locker`];
//! * every encryption uses a fresh 24-byte random XChaCha20-Poly1305 nonce;
//! * no derived key is reused for two purposes (HKDF with distinct `info`);
//! * decryption failures are reported as [`vault::VaultError::InvalidPassword`]
//!   or [`vault::VaultError::Corrupt`] without leaking any internal detail.

#![forbid(unsafe_code)]
#![deny(clippy::undocumented_unsafe_blocks)]

pub mod crypto;
pub mod vault;

pub use vault::model::{
    CardSecrets, CustomField, EntryKind, EntryMeta, EntrySecrets, IdentitySecrets, Revision,
    SecretField,
};
pub use vault::store::{CreateOptions, CreatedVault, EntryDraft, EntryPatch, Vault};
pub use vault::VaultError;
