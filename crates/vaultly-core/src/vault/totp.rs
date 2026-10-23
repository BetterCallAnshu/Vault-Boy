//! TOTP (RFC 6238) codes.
//!
//! The shared secret never leaves the backend: the UI only ever receives the
//! current six-digit code and the seconds remaining in the period.

use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Builder};
use uuid::Uuid;

use super::store::Vault;
use super::VaultError;

pub const PERIOD_SECONDS: u64 = 30;
pub const DIGITS: u8 = 6;
/// RFC 4226 requires at least 128 bits; we refuse anything shorter than 80 bits
/// so obviously broken secrets are rejected early.
const MIN_SECRET_BYTES: usize = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpCode {
    pub code: String,
    pub seconds_remaining: u32,
    pub period: u32,
}

/// Generate the current code for an entry.
pub fn code(vault: &Vault, id: Uuid, now_ms: i64) -> Result<TotpCode, VaultError> {
    let secrets = vault.secrets(id)?;
    if secrets.totp_secret.trim().is_empty() {
        return Err(VaultError::NotFound);
    }
    let secret = decode_secret(&secrets.totp_secret)?;
    let totp = Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_secret(secret)
        .with_digits(DIGITS)
        .with_step_duration(PERIOD_SECONDS)
        .build()
        .map_err(|_| VaultError::InvalidInput)?;

    let seconds = (now_ms.max(0) / 1000) as u64;
    let code = totp.generate(seconds).to_string();
    let seconds_remaining = PERIOD_SECONDS - (seconds % PERIOD_SECONDS);
    Ok(TotpCode {
        code,
        seconds_remaining: seconds_remaining as u32,
        period: PERIOD_SECONDS as u32,
    })
}

/// Accept a raw base32 secret or an `otpauth://` URI.
fn decode_secret(raw: &str) -> Result<Vec<u8>, VaultError> {
    let trimmed = raw.trim();
    let encoded = if trimmed.to_ascii_lowercase().starts_with("otpauth://") {
        let query = trimmed.split('?').nth(1).ok_or(VaultError::InvalidInput)?;
        query
            .split('&')
            .find_map(|part| part.strip_prefix("secret="))
            .ok_or(VaultError::InvalidInput)?
    } else {
        trimmed
    };
    decode_base32(encoded)
}

fn decode_base32(encoded: &str) -> Result<Vec<u8>, VaultError> {
    let cleaned: String = encoded
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_ascii_uppercase();
    let trimmed = cleaned.trim_end_matches('=');
    let bytes = BASE32_NOPAD
        .decode(trimmed.as_bytes())
        .map_err(|_| VaultError::InvalidInput)?;
    if bytes.len() < MIN_SECRET_BYTES {
        return Err(VaultError::InvalidInput);
    }
    Ok(bytes)
}

/// RFC 6238 test vector: the ASCII secret "12345678901234567890".
#[cfg(test)]
fn rfc_secret() -> String {
    BASE32_NOPAD.encode(b"12345678901234567890")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::model::{EntryKind, EntrySecrets};
    use crate::vault::store::{CreateOptions, EntryDraft};
    use crate::crypto::kdf::KdfParams;

    fn vault_with_secret(secret: &str) -> (Vault, Uuid) {
        let mut vault = Vault::create(
            b"correct horse battery",
            CreateOptions {
                kdf: KdfParams::new(64 * 1024, 1, 1),
                recovery: false,
                now: 0,
            },
        )
        .unwrap()
        .vault;
        let mut secrets = EntrySecrets::default();
        secrets.totp_secret = secret.into();
        secrets.password = "entry-password-1".into();
        let id = vault
            .create_entry(
                EntryDraft {
                    kind: EntryKind::Login,
                    title: "TOTP".into(),
                    username: "user".into(),
                    url: String::new(),
                    tags: vec![],
                    folder: None,
                    favorite: false,
                    secrets,
                },
                0,
            )
            .unwrap();
        (vault, id)
    }

    #[test]
    fn rfc6238_vectors_at_six_digits() {
        let (vault, id) = vault_with_secret(&rfc_secret());
        // (unix seconds, RFC vector truncated to 6 digits)
        let vectors = [
            (59u64, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
            (20_000_000_000, "353130"),
        ];
        for (time, expected) in vectors {
            let generated = code(&vault, id, (time * 1000) as i64).unwrap();
            assert_eq!(generated.code, expected, "t={time}");
        }
    }

    #[test]
    fn countdown_is_within_period() {
        let (vault, id) = vault_with_secret(&rfc_secret());
        let generated = code(&vault, id, 59_000).unwrap();
        assert_eq!(generated.period, 30);
        assert_eq!(generated.seconds_remaining, 1);
    }

    #[test]
    fn accepts_otpauth_uri() {
        let uri = format!(
            "otpauth://totp/Example:alice?secret={}&issuer=Example",
            rfc_secret()
        );
        let (vault, id) = vault_with_secret(&uri);
        assert_eq!(code(&vault, id, 59_000).unwrap().code, "287082");
    }

    #[test]
    fn rejects_invalid_secrets() {
        let (vault, id) = vault_with_secret("!!!!not-base32!!!!");
        assert!(code(&vault, id, 0).is_err());
    }

    #[test]
    fn entries_without_totp_report_not_found() {
        let (vault, id) = vault_with_secret("");
        let mut secrets = vault.secrets(id).unwrap();
        secrets.password = "placeholder".into();
        let mut vault = vault;
        vault.set_secrets(id, secrets, 0).unwrap();
        assert_eq!(code(&vault, id, 0).unwrap_err(), VaultError::NotFound);
    }
}
