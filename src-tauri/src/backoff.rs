//! Failed-unlock backoff.
//!
//! The counter is persisted so restarting Vaultly does not reset it. Integrity
//! is protected by an HMAC keyed with a random device key that DPAPI protects
//! for the current Windows user. This is tamper-evident, not tamper-proof: a
//! local attacker who can delete the file resets the counter, and an attacker
//! who can read the DPAPI-protected key can forge it. Documented in SECURITY.md.
//!
//! On any integrity failure we fail closed with the maximum delay.

use std::path::{Path, PathBuf};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::platform_windows::dpapi;

const MAX_DELAY_SECONDS: u64 = 300;
const MAX_FAILURES: u32 = 32;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Stored {
    failures: u32,
    last_failure_ms: i64,
    mac: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Signed {
    failures: u32,
    last_failure_ms: i64,
}

pub struct Backoff {
    failures: u32,
    last_failure_ms: i64,
    tampered: bool,
    state_path: PathBuf,
    key: Option<[u8; 32]>,
}

impl Backoff {
    pub fn load(state_path: &Path, key_path: &Path) -> Self {
        let key = Self::load_or_create_key(key_path);
        let mut chain = Self {
            failures: 0,
            last_failure_ms: 0,
            tampered: false,
            state_path: state_path.to_path_buf(),
            key,
        };
        if let Ok(bytes) = std::fs::read(state_path) {
            match serde_json::from_slice::<Stored>(&bytes) {
                Ok(stored) => match chain.verify(&stored) {
                    true => {
                        chain.failures = stored.failures.min(MAX_FAILURES);
                        chain.last_failure_ms = stored.last_failure_ms;
                    }
                    false => chain.tampered = true,
                },
                Err(_) => chain.tampered = true,
            }
        }
        chain
    }

    fn load_or_create_key(path: &Path) -> Option<[u8; 32]> {
        if let Ok(bytes) = std::fs::read(path) {
            if let Ok(plain) = dpapi::unprotect(&bytes) {
                if plain.len() == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&plain);
                    return Some(key);
                }
            }
        }
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).ok()?;
        let protected = dpapi::protect(&key).ok()?;
        let _ = std::fs::write(path, &protected);
        let _ = crate::platform_windows::acl::apply_private_file(path);
        Some(key)
    }

    fn verify(&self, stored: &Stored) -> bool {
        let Some(key) = self.key else {
            return false;
        };
        let payload = Signed {
            failures: stored.failures,
            last_failure_ms: stored.last_failure_ms,
        };
        let Ok(bytes) = serde_json::to_vec(&payload) else {
            return false;
        };
        let Ok(expected) = hex_decode(&stored.mac) else {
            return false;
        };
        let Ok(mut mac) = HmacSha256::new_from_slice(&key) else {
            return false;
        };
        mac.update(&bytes);
        mac.verify_slice(&expected).is_ok()
    }

    fn persist(&self) {
        let Some(key) = self.key else {
            return;
        };
        let payload = Signed {
            failures: self.failures,
            last_failure_ms: self.last_failure_ms,
        };
        let Ok(bytes) = serde_json::to_vec(&payload) else {
            return;
        };
        let Ok(mut mac) = HmacSha256::new_from_slice(&key) else {
            return;
        };
        mac.update(&bytes);
        let signature = mac.finalize().into_bytes();
        let stored = Stored {
            failures: self.failures,
            last_failure_ms: self.last_failure_ms,
            mac: hex_encode(&signature),
        };
        if let Ok(encoded) = serde_json::to_vec(&stored) {
            let _ = std::fs::write(&self.state_path, encoded);
            let _ = crate::platform_windows::acl::apply_private_file(&self.state_path);
        }
    }

    pub fn is_tampered(&self) -> bool {
        self.tampered
    }

    /// Milliseconds the UI must wait before another attempt is allowed.
    pub fn remaining_ms(&self, now_ms: i64) -> u64 {
        if self.tampered {
            return MAX_DELAY_SECONDS * 1000;
        }
        if self.failures == 0 {
            return 0;
        }
        let delay = delay_seconds(self.failures);
        let elapsed = (now_ms - self.last_failure_ms).max(0) as u64;
        delay.saturating_mul(1000).saturating_sub(elapsed)
    }

    pub fn record_failure(&mut self, now_ms: i64) {
        self.failures = (self.failures + 1).min(MAX_FAILURES);
        self.last_failure_ms = now_ms;
        self.persist();
    }

    pub fn record_success(&mut self) {
        self.failures = 0;
        self.last_failure_ms = 0;
        self.tampered = false;
        self.persist();
    }

    pub fn failures(&self) -> u32 {
        self.failures
    }
}

fn delay_seconds(failures: u32) -> u64 {
    if failures == 0 {
        return 0;
    }
    let exponent = (failures - 1).min(9);
    (1u64 << exponent).min(MAX_DELAY_SECONDS)
}

impl Drop for Backoff {
    fn drop(&mut self) {
        if let Some(key) = &mut self.key {
            key.zeroize();
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn hex_decode(text: &str) -> Result<Vec<u8>, ()> {
    if text.len() % 2 != 0 {
        return Err(());
    }
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).map_err(|_| ()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delays_grow_and_cap() {
        assert_eq!(delay_seconds(0), 0);
        assert_eq!(delay_seconds(1), 1);
        assert_eq!(delay_seconds(2), 2);
        assert_eq!(delay_seconds(3), 4);
        assert_eq!(delay_seconds(20), MAX_DELAY_SECONDS);
    }

    #[test]
    fn backoff_is_persisted_and_detects_tampering() {
        let dir = std::env::temp_dir().join(format!("vaultly-backoff-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let state = dir.join("lockout.dat");
        let key = dir.join("device.key");

        let mut backoff = Backoff::load(&state, &key);
        backoff.record_failure(1_000);
        backoff.record_failure(1_000);
        drop(backoff);

        let reloaded = Backoff::load(&state, &key);
        assert_eq!(reloaded.failures(), 2);
        assert_eq!(reloaded.remaining_ms(1_000), 2_000);

        // Flip a byte in the persisted state; HMAC must fail.
        let mut bytes = std::fs::read(&state).unwrap();
        let last = bytes.len() - 3;
        bytes[last] ^= 0x01;
        std::fs::write(&state, &bytes).unwrap();
        let tampered = Backoff::load(&state, &key);
        assert!(tampered.is_tampered());
        assert!(tampered.remaining_ms(0) >= MAX_DELAY_SECONDS * 1000);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
