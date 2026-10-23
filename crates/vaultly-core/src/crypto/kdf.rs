//! Argon2id key derivation, parameters and calibration.

use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::keys::Key32;
use super::CryptoError;

/// Salt size for both the master password and the recovery key. 128 bits.
pub const SALT_LEN: usize = 16;

/// OWASP-recommended baseline; the vault never reads below this.
pub const MIN_M_COST_KIB: u32 = 64 * 1024;
/// Parameter caps prevent a tampered header from turning unlock into a DoS.
pub const MAX_M_COST_KIB: u32 = 512 * 1024;
pub const MAX_T_COST: u32 = 12;
pub const MAX_P_COST: u32 = 8;

pub const DEFAULT_M_COST_KIB: u32 = 64 * 1024;
pub const DEFAULT_T_COST: u32 = 3;
pub const DEFAULT_P_COST: u32 = 4;

/// Argon2id parameters persisted in the vault header.
///
/// They are part of the AEAD associated data for the wrapped vault key, so
/// lowering them invalidates the wrap instead of silently weakening the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams {
            m_cost_kib: DEFAULT_M_COST_KIB,
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
        }
    }
}

impl KdfParams {
    pub const fn new(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> Self {
        KdfParams {
            m_cost_kib,
            t_cost,
            p_cost,
        }
    }

    /// Reject parameters outside the supported envelope.
    pub fn validate(&self) -> Result<(), CryptoError> {
        if self.m_cost_kib < MIN_M_COST_KIB
            || self.m_cost_kib > MAX_M_COST_KIB
            || self.t_cost == 0
            || self.t_cost > MAX_T_COST
            || self.p_cost == 0
            || self.p_cost > MAX_P_COST
        {
            return Err(CryptoError::InvalidParams);
        }
        Ok(())
    }
}

/// Random 128-bit salt.
pub fn random_salt() -> Result<[u8; SALT_LEN], CryptoError> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|_| CryptoError::Rng)?;
    Ok(salt)
}

/// Derive a 256-bit key with Argon2id (version 0x13).
///
/// The output is written straight into a [`Key32`] page; the intermediate
/// stack copy is zeroized before returning.
pub fn derive_key(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    params: &KdfParams,
) -> Result<Key32, CryptoError> {
    params.validate()?;
    let argon_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(32),
    )
    .map_err(|_| CryptoError::InvalidParams)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut output = [0u8; 32];
    let result = argon.hash_password_into(password, salt, &mut output);
    if result.is_err() {
        output.zeroize();
        return Err(CryptoError::Kdf);
    }
    let key = Key32::from_bytes(output);
    output.zeroize();
    Ok(key)
}

/// Pick `t_cost` so that derivation takes roughly `target` on this machine.
///
/// Only used when a vault is created; unlock always uses the parameters stored
/// in the header, so the same password opens the vault on slower hardware.
pub fn calibrate(target: Duration) -> KdfParams {
    let mut base = KdfParams::default();
    let salt = [0u8; SALT_LEN];
    for t_cost in 1..=MAX_T_COST {
        let candidate = KdfParams {
            t_cost,
            ..base
        };
        let started = Instant::now();
        // Calibration failure falls back to the default cost.
        if derive_key(b"vaultly-calibration", &salt, &candidate).is_err() {
            break;
        }
        if started.elapsed() >= target {
            return candidate;
        }
        base = candidate;
    }
    base
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_params() -> KdfParams {
        // Tests use the minimum allowed memory to stay quick.
        KdfParams::new(MIN_M_COST_KIB, 1, 1)
    }

    #[test]
    fn derivation_is_deterministic() {
        let salt = [3u8; SALT_LEN];
        let a = derive_key(b"correct horse", &salt, &fast_params()).unwrap();
        let b = derive_key(b"correct horse", &salt, &fast_params()).unwrap();
        let same = a.with_secret(|x| b.with_secret(|y| x == y));
        assert!(same);
    }

    #[test]
    fn different_password_or_salt_differs() {
        let salt = [3u8; SALT_LEN];
        let a = derive_key(b"one", &salt, &fast_params()).unwrap();
        let b = derive_key(b"two", &salt, &fast_params()).unwrap();
        assert!(!a.with_secret(|x| b.with_secret(|y| x == y)));

        let c = derive_key(b"one", &[4u8; SALT_LEN], &fast_params()).unwrap();
        assert!(!a.with_secret(|x| c.with_secret(|y| x == y)));
    }

    #[test]
    fn rejects_weakened_parameters() {
        assert!(KdfParams::new(1024, 3, 4).validate().is_err());
        assert!(KdfParams::new(MIN_M_COST_KIB, 0, 4).validate().is_err());
        assert!(KdfParams::new(MIN_M_COST_KIB, 3, 0).validate().is_err());
        assert!(KdfParams::new(MAX_M_COST_KIB + 1, 3, 4).validate().is_err());
    }

    #[test]
    fn calibrate_returns_valid_params() {
        let params = calibrate(Duration::from_millis(1));
        params.validate().unwrap();
    }
}
