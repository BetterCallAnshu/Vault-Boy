//! Local password health report: weak, reused and old passwords.
//!
//! This runs entirely offline. Each password is decrypted only for the duration
//! of the check and dropped (zeroized) immediately; reuse detection compares
//! SHA-256 digests, never plaintext.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroize;

use super::store::{Vault, OLD_PASSWORD_MS};
use super::VaultError;

const DAY_MS: i64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    pub total: usize,
    pub weak: Vec<WeakEntry>,
    pub reused: Vec<ReuseGroup>,
    pub old: Vec<OldEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeakEntry {
    pub id: Uuid,
    pub score: u8,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReuseGroup {
    pub ids: Vec<Uuid>,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OldEntry {
    pub id: Uuid,
    pub age_days: i64,
}

/// Analyze all active entries. Entries with no password are skipped.
pub fn analyze(vault: &Vault, now: i64) -> Result<HealthReport, VaultError> {
    let mut total = 0usize;
    let mut weak = Vec::new();
    let mut old = Vec::new();
    let mut digests: HashMap<[u8; 32], Vec<Uuid>> = HashMap::new();

    for meta in vault.active_entries() {
        total += 1;
        if let Some(at) = meta.password_updated_at {
            let age = now.saturating_sub(at);
            if age > OLD_PASSWORD_MS {
                old.push(OldEntry {
                    id: meta.id,
                    age_days: age / DAY_MS,
                });
            }
        }

        let secrets = vault.secrets(meta.id)?;
        if secrets.password.is_empty() {
            continue;
        }

        let (score, reasons) = score_password(&secrets.password);
        if score <= 1 {
            weak.push(WeakEntry {
                id: meta.id,
                score,
                reasons,
            });
        }

        let mut hasher = Sha256::new();
        hasher.update(secrets.password.as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        digests.entry(digest).or_default().push(meta.id);
    }

    let mut reused = Vec::new();
    for (mut digest, ids) in digests.into_iter() {
        if ids.len() > 1 {
            reused.push(ReuseGroup {
                count: ids.len(),
                ids,
            });
        }
        digest.zeroize();
    }
    reused.sort_by_key(|group| std::cmp::Reverse(group.count));
    weak.sort_by_key(|entry| entry.score);
    old.sort_by_key(|entry| std::cmp::Reverse(entry.age_days));

    Ok(HealthReport {
        total,
        weak,
        reused,
        old,
    })
}

/// Heuristic strength score (0-4), deliberately independent of zxcvbn: the
/// frontend's zxcvbn meter runs in JavaScript on input, while this runs over
/// stored passwords in Rust. Documented as a heuristic in SECURITY.md.
fn score_password(password: &str) -> (u8, Vec<String>) {
    let length = password.chars().count();
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_symbol = password.chars().any(|c| !c.is_ascii_alphanumeric());
    let classes = [has_lower, has_upper, has_digit, has_symbol]
        .into_iter()
        .filter(|present| *present)
        .count();

    let mut reasons = Vec::new();
    let mut score: i32 = match length {
        0..=7 => 0,
        8..=11 => 1,
        12..=15 => 2,
        16..=19 => 3,
        _ => 4,
    };

    if classes <= 1 {
        score -= 1;
        reasons.push("uses a single character class".to_string());
    }
    if length < 12 {
        reasons.push("shorter than 12 characters".to_string());
    }
    if is_predictable(password) {
        score = 0;
        reasons.push("matches a predictable pattern".to_string());
    }

    (score.clamp(0, 4) as u8, reasons)
}

fn is_predictable(password: &str) -> bool {
    let lower = password.to_ascii_lowercase();
    if ["password", "qwerty", "letmein", "admin", "welcome", "iloveyou"]
        .iter()
        .any(|needle| lower.contains(needle))
    {
        return true;
    }
    // A single repeated character or a plain ascending/descending run.
    let mut chars = password.chars();
    let first = match chars.next() {
        Some(first) => first,
        None => return false,
    };
    if password.chars().all(|c| c == first) {
        return true;
    }
    let bytes = password.as_bytes();
    let ascending = bytes.windows(2).all(|pair| pair[1] == pair[0].wrapping_add(1));
    let descending = bytes.windows(2).all(|pair| pair[1].wrapping_add(1) == pair[0]);
    ascending || descending
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::KdfParams;
    use crate::vault::model::{EntryKind, EntrySecrets};
    use crate::vault::store::{CreateOptions, EntryDraft};

    fn vault() -> Vault {
        Vault::create(
            b"correct horse battery",
            CreateOptions {
                kdf: KdfParams::new(64 * 1024, 1, 1),
                recovery: false,
                now: 0,
            },
        )
        .unwrap()
        .vault
    }

    fn add(vault: &mut Vault, title: &str, password: &str, now: i64) -> Uuid {
        let mut secrets = EntrySecrets::default();
        secrets.password = password.into();
        vault
            .create_entry(
                EntryDraft {
                    kind: EntryKind::Login,
                    title: title.into(),
                    username: "user".into(),
                    url: String::new(),
                    tags: vec![],
                    folder: None,
                    favorite: false,
                    secrets,
                },
                now,
            )
            .unwrap()
    }

    #[test]
    fn flags_weak_and_short_passwords() {
        let mut vault = vault();
        let weak = add(&mut vault, "Weak", "abc123", 0);
        let strong = add(&mut vault, "Strong", "V7!k#pQ2$mZx9LwR", 0);
        let report = vault.health_report(DAY_MS).unwrap();
        assert_eq!(report.total, 2);
        assert!(report.weak.iter().any(|entry| entry.id == weak));
        assert!(!report.weak.iter().any(|entry| entry.id == strong));
    }

    #[test]
    fn detects_reuse() {
        let mut vault = vault();
        let a = add(&mut vault, "A", "Same-Password-42!", 0);
        let b = add(&mut vault, "B", "Same-Password-42!", 0);
        add(&mut vault, "C", "Totally-Different-9#", 0);
        let report = vault.health_report(0).unwrap();
        assert_eq!(report.reused.len(), 1);
        let group = &report.reused[0];
        assert_eq!(group.count, 2);
        assert!(group.ids.contains(&a) && group.ids.contains(&b));
    }

    #[test]
    fn flags_old_passwords() {
        let mut vault = vault();
        let id = add(&mut vault, "Old", "Long-Enough-Pass-1!", 0);
        let report = vault.health_report(OLD_PASSWORD_MS + DAY_MS).unwrap();
        assert_eq!(report.old.len(), 1);
        assert_eq!(report.old[0].id, id);
        assert_eq!(report.old[0].age_days, 366);
    }

    #[test]
    fn predictable_passwords_score_zero() {
        assert!(is_predictable("aaaaaaaaaaaa"));
        assert!(is_predictable("abcdefghijkl"));
        assert!(is_predictable("MyPassword123!"));
        assert!(!is_predictable("V7!k#pQ2$mZx9LwR"));
    }
}
