//! XChaCha20-Poly1305 authenticated encryption.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::{Zeroize, Zeroizing};

use super::keys::Key32;
use super::CryptoError;

/// 192-bit nonce: safe with random generation for a virtually unbounded number
/// of messages per key, so no counter state has to be persisted.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;

/// Nonce plus ciphertext (ciphertext includes the tag).
#[derive(Clone)]
pub struct Sealed {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

impl Sealed {
    pub fn len(&self) -> usize {
        self.ciphertext.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ciphertext.is_empty()
    }
}

impl Drop for Sealed {
    fn drop(&mut self) {
        self.nonce.zeroize();
        // Ciphertext is not secret, but zeroizing keeps memory dumps clean.
        self.ciphertext.zeroize();
    }
}

/// Encrypt `plaintext` with a fresh random nonce.
///
/// `aad` binds the ciphertext to its context (vault id, record id, purpose);
/// a body replayed into another vault or record fails to open.
pub fn seal(key: &Key32, aad: &[u8], plaintext: &[u8]) -> Result<Sealed, CryptoError> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| CryptoError::Rng)?;

    let ciphertext = key
        .with_secret(|key_bytes| {
            let cipher = XChaCha20Poly1305::new(Key::from_slice(key_bytes));
            cipher.encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
        })
        .map_err(|_| CryptoError::Encrypt)?;

    Ok(Sealed { nonce, ciphertext })
}

/// Decrypt and authenticate. The returned buffer zeroizes on drop.
pub fn open(
    key: &Key32,
    aad: &[u8],
    sealed: &Sealed,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if sealed.ciphertext.len() < TAG_LEN {
        return Err(CryptoError::Decrypt);
    }
    let plaintext = key
        .with_secret(|key_bytes| {
            let cipher = XChaCha20Poly1305::new(Key::from_slice(key_bytes));
            cipher.decrypt(
                XNonce::from_slice(&sealed.nonce),
                Payload {
                    msg: &sealed.ciphertext,
                    aad,
                },
            )
        })
        .map_err(|_| CryptoError::Decrypt)?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> Key32 {
        Key32::from_bytes([byte; 32])
    }

    #[test]
    fn round_trip() {
        let k = key(1);
        let sealed = seal(&k, b"ctx", b"attack at dawn").unwrap();
        let opened = open(&k, b"ctx", &sealed).unwrap();
        assert_eq!(&opened[..], b"attack at dawn");
    }

    #[test]
    fn wrong_key_fails() {
        let sealed = seal(&key(1), b"ctx", b"secret").unwrap();
        assert!(open(&key(2), b"ctx", &sealed).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let k = key(1);
        let mut sealed = seal(&k, b"ctx", b"secret").unwrap();
        let last = sealed.ciphertext.len() - 1;
        sealed.ciphertext[last] ^= 0x01;
        assert!(open(&k, b"ctx", &sealed).is_err());
    }

    #[test]
    fn tampered_aad_fails() {
        let k = key(1);
        let sealed = seal(&k, b"vault-a", b"secret").unwrap();
        assert!(open(&k, b"vault-b", &sealed).is_err());
    }

    #[test]
    fn nonces_are_unique() {
        let k = key(9);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..512 {
            let sealed = seal(&k, b"ctx", b"x").unwrap();
            assert!(seen.insert(sealed.nonce), "nonce reused");
        }
    }

    #[test]
    fn truncated_ciphertext_is_rejected() {
        let k = key(1);
        let mut sealed = seal(&k, b"ctx", b"secret").unwrap();
        sealed.ciphertext.truncate(TAG_LEN - 1);
        assert!(open(&k, b"ctx", &sealed).is_err());
    }
}
