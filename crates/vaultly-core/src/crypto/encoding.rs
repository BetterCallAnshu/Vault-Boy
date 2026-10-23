//! Recovery key encoding: 256 random bits rendered as grouped base32.
//!
//! The recovery key is shown once at creation. It is a *key*, not a password:
//! 256 bits of entropy, so stretching it with Argon2id is defence in depth
//! rather than the source of its strength.

use data_encoding::BASE32_NOPAD;
use zeroize::{Zeroize, Zeroizing};

use super::keys::Key32;
use super::CryptoError;

/// Raw recovery key size.
pub const RECOVERY_BYTES: usize = 32;
/// Group size used for display only.
const GROUP: usize = 4;

/// Generate a recovery key such as `AB2C-DE3F-...` (52 base32 chars, 13 groups).
pub fn generate_recovery_key() -> Result<Zeroizing<String>, CryptoError> {
    let mut raw = [0u8; RECOVERY_BYTES];
    getrandom::fill(&mut raw).map_err(|_| CryptoError::Rng)?;
    let encoded = BASE32_NOPAD.encode(&raw);
    raw.zeroize();
    Ok(Zeroizing::new(group(&encoded)))
}

/// Uppercase and strip separators/spaces; users paste keys with arbitrary
/// casing, dashes or line breaks.
pub fn normalize_recovery_key(input: &str) -> Zeroizing<String> {
    let normalized: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_ascii_uppercase();
    Zeroizing::new(normalized)
}

/// Decode a user-supplied recovery key back into key material.
pub fn decode_recovery_key(input: &str) -> Result<Key32, CryptoError> {
    let normalized = normalize_recovery_key(input);
    let decoded = BASE32_NOPAD
        .decode(normalized.as_bytes())
        .map_err(|_| CryptoError::RecoveryKey)?;
    if decoded.len() != RECOVERY_BYTES {
        return Err(CryptoError::RecoveryKey);
    }
    let mut raw = [0u8; RECOVERY_BYTES];
    raw.copy_from_slice(&decoded);
    let key = Key32::from_bytes(raw);
    raw.zeroize();
    Ok(key)
}

fn group(encoded: &str) -> String {
    let chars: Vec<char> = encoded.chars().collect();
    let mut out = String::with_capacity(encoded.len() + chars.len() / GROUP);
    for (index, chunk) in chars.chunks(GROUP).enumerate() {
        if index > 0 {
            out.push('-');
        }
        out.extend(chunk);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_display_format() {
        let display = generate_recovery_key().unwrap();
        let decoded = decode_recovery_key(&display).unwrap();
        assert!(decoded.is_locked() || !decoded.is_locked());
        let again = decode_recovery_key(&display.to_lowercase().replace('-', " ")).unwrap();
        assert!(decoded.with_secret(|a| again.with_secret(|b| a == b)));
    }

    #[test]
    fn displayed_key_has_expected_shape() {
        let display = generate_recovery_key().unwrap();
        assert_eq!(display.len(), 52 + 12);
        assert_eq!(display.matches('-').count(), 12);
        assert!(!display.contains('='));
    }

    #[test]
    fn rejects_invalid_keys() {
        assert!(decode_recovery_key("not-a-key").is_err());
        assert!(decode_recovery_key("AAAA").is_err());
        assert!(decode_recovery_key("").is_err());
    }

    #[test]
    fn normalization_is_stable() {
        assert_eq!(&*normalize_recovery_key(" abcd-efgh \n"), "ABCDEFGH");
    }
}
