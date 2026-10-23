//! HKDF-SHA256 subkey derivation.
//!
//! A single 256-bit vault root key is never used directly as an AEAD key for
//! more than one purpose: the index, each entry and the header each get their
//! own subkey with a distinct `info` label.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use super::keys::Key32;
use super::CryptoError;

/// Domain-separation labels. Changing a label is a format change.
pub const INFO_INDEX: &[u8] = b"vaultly/v1/index";
pub const INFO_ENTRY_PREFIX: &[u8] = b"vaultly/v1/entry";
pub const INFO_HELLO: &[u8] = b"vaultly/v1/hello";

/// Derive a 256-bit subkey.
///
/// `salt` is the 16-byte vault id, which binds every subkey to this vault.
pub fn derive_subkey(root: &Key32, salt: &[u8], info: &[u8]) -> Result<Key32, CryptoError> {
    root.with_secret(|root_bytes| {
        let hkdf = Hkdf::<Sha256>::new(Some(salt), root_bytes);
        let mut okm = [0u8; 32];
        let result = hkdf.expand(info, &mut okm);
        let key = result.map(|()| Key32::from_bytes(okm));
        okm.zeroize();
        key
    })
    .map_err(|_| CryptoError::Kdf)
}

/// Per-entry subkey: `HKDF(vault_root, vault_id, "vaultly/v1/entry" || id)`.
pub fn derive_entry_key(root: &Key32, salt: &[u8], entry_id: &[u8; 16]) -> Result<Key32, CryptoError> {
    let mut info = Vec::with_capacity(INFO_ENTRY_PREFIX.len() + entry_id.len());
    info.extend_from_slice(INFO_ENTRY_PREFIX);
    info.extend_from_slice(entry_id);
    derive_subkey(root, salt, &info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_labels_produce_distinct_keys() {
        let root = Key32::from_bytes([7u8; 32]);
        let salt = [1u8; 16];
        let a = derive_subkey(&root, &salt, INFO_INDEX).unwrap();
        let b = derive_subkey(&root, &salt, INFO_HELLO).unwrap();
        assert!(!a.with_secret(|x| b.with_secret(|y| x == y)));
    }

    #[test]
    fn distinct_entry_ids_produce_distinct_keys() {
        let root = Key32::from_bytes([7u8; 32]);
        let salt = [1u8; 16];
        let a = derive_entry_key(&root, &salt, &[0u8; 16]).unwrap();
        let b = derive_entry_key(&root, &salt, &[1u8; 16]).unwrap();
        assert!(!a.with_secret(|x| b.with_secret(|y| x == y)));
    }

    #[test]
    fn derivation_is_stable() {
        let root = Key32::from_bytes([7u8; 32]);
        let salt = [1u8; 16];
        let a = derive_subkey(&root, &salt, INFO_INDEX).unwrap();
        let b = derive_subkey(&root, &salt, INFO_INDEX).unwrap();
        assert!(a.with_secret(|x| b.with_secret(|y| x == y)));
    }
}
