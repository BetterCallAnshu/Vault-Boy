//! Password and passphrase generation.
//!
//! Randomness comes from the default `rand` thread RNG (seeded from the OS
//! CSPRNG). Selection and shuffling use `rand`'s unbiased helpers rather than
//! modulo arithmetic.

use rand::seq::{IndexedRandom, SliceRandom};
use serde::{Deserialize, Serialize};

use super::wordlist::{BITS_PER_WORD, EFF_SHORT_WORDS};
use super::VaultError;

pub const MIN_LENGTH: usize = 8;
pub const MAX_LENGTH: usize = 128;
pub const MIN_WORDS: usize = 4;
pub const MAX_WORDS: usize = 16;

const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.?/";
/// Characters that are easy to confuse in many fonts.
const AMBIGUOUS: &str = "Il1O0o|`'\"{}[]()/\\";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneratorOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
    pub passphrase: bool,
    pub words: usize,
    pub separator: String,
    pub capitalize: bool,
}

impl Default for GeneratorOptions {
    fn default() -> Self {
        GeneratorOptions {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: true,
            passphrase: false,
            words: 6,
            separator: "-".to_string(),
            capitalize: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedSecret {
    pub value: String,
    /// Estimated entropy of the *process*, useful for the UI meter.
    pub entropy_bits: f64,
}

/// Generate either a random-character password or a Diceware-style passphrase.
pub fn generate(options: &GeneratorOptions) -> Result<GeneratedSecret, VaultError> {
    if options.passphrase {
        generate_passphrase(options)
    } else {
        generate_password(options)
    }
}

fn generate_password(options: &GeneratorOptions) -> Result<GeneratedSecret, VaultError> {
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&options.length) {
        return Err(VaultError::InvalidInput);
    }

    let mut pools: Vec<Vec<char>> = Vec::new();
    for (enabled, set) in [
        (options.lowercase, LOWERCASE),
        (options.uppercase, UPPERCASE),
        (options.digits, DIGITS),
        (options.symbols, SYMBOLS),
    ] {
        if !enabled {
            continue;
        }
        let pool: Vec<char> = set
            .chars()
            .filter(|c| !options.exclude_ambiguous || !AMBIGUOUS.contains(*c))
            .collect();
        if pool.is_empty() {
            return Err(VaultError::InvalidInput);
        }
        pools.push(pool);
    }

    if pools.is_empty() || options.length < pools.len() {
        return Err(VaultError::InvalidInput);
    }

    let mut rng = rand::rng();
    let mut chars: Vec<char> = Vec::with_capacity(options.length);

    // Guarantee at least one character from every selected class.
    for pool in &pools {
        let picked = *pool.choose(&mut rng).ok_or(VaultError::InvalidInput)?;
        chars.push(picked);
    }

    let merged: Vec<char> = pools.iter().flatten().copied().collect();
    while chars.len() < options.length {
        chars.push(*merged.choose(&mut rng).ok_or(VaultError::InvalidInput)?);
    }
    chars.shuffle(&mut rng);

    let entropy_bits = options.length as f64 * (merged.len() as f64).log2();
    let value: String = chars.into_iter().collect();
    Ok(GeneratedSecret {
        value,
        entropy_bits,
    })
}

fn generate_passphrase(options: &GeneratorOptions) -> Result<GeneratedSecret, VaultError> {
    if !(MIN_WORDS..=MAX_WORDS).contains(&options.words) {
        return Err(VaultError::InvalidInput);
    }
    if options.separator.chars().count() > 3 {
        return Err(VaultError::InvalidInput);
    }

    let mut rng = rand::rng();
    let mut words: Vec<String> = Vec::with_capacity(options.words);
    for _ in 0..options.words {
        let word = *EFF_SHORT_WORDS
            .choose(&mut rng)
            .ok_or(VaultError::InvalidInput)?;
        words.push(word.to_string());
    }
    if options.capitalize {
        for word in &mut words {
            let mut chars = word.chars();
            if let Some(first) = chars.next() {
                *word = first.to_uppercase().collect::<String>() + chars.as_str();
            }
        }
    }
    let value = words.join(&options.separator);
    Ok(GeneratedSecret {
        value,
        entropy_bits: options.words as f64 * BITS_PER_WORD,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn respects_length_and_character_classes() {
        let options = GeneratorOptions {
            length: 32,
            ..Default::default()
        };
        let generated = generate(&options).unwrap();
        assert_eq!(generated.value.chars().count(), 32);
        assert!(generated.value.chars().any(|c| c.is_ascii_lowercase()));
        assert!(generated.value.chars().any(|c| c.is_ascii_uppercase()));
        assert!(generated.value.chars().any(|c| c.is_ascii_digit()));
        assert!(generated
            .value
            .chars()
            .any(|c| SYMBOLS.contains(c)));
        assert!(generated.entropy_bits > 100.0);
    }

    #[test]
    fn excludes_ambiguous_characters_when_asked() {
        let options = GeneratorOptions {
            length: 64,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: false,
            exclude_ambiguous: true,
            ..Default::default()
        };
        for _ in 0..16 {
            let generated = generate(&options).unwrap();
            assert!(
                !generated.value.chars().any(|c| AMBIGUOUS.contains(c)),
                "generated {}",
                generated.value
            );
        }
    }

    #[test]
    fn rejects_impossible_options() {
        assert!(generate(&GeneratorOptions {
            length: 4,
            ..Default::default()
        })
        .is_err());
        assert!(generate(&GeneratorOptions {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            ..Default::default()
        })
        .is_err());
        assert!(generate(&GeneratorOptions {
            passphrase: true,
            words: 1,
            ..Default::default()
        })
        .is_err());
    }

    #[test]
    fn passphrase_has_requested_word_count() {
        let options = GeneratorOptions {
            passphrase: true,
            words: 7,
            separator: "-".into(),
            capitalize: true,
            ..Default::default()
        };
        let generated = generate(&options).unwrap();
        assert_eq!(generated.value.split('-').count(), 7);
        assert!(generated
            .value
            .split('-')
            .all(|word| word.starts_with(|c: char| c.is_ascii_uppercase())));
        assert!((generated.entropy_bits - 7.0 * BITS_PER_WORD).abs() < f64::EPSILON);
    }

    #[test]
    fn successive_output_differs() {
        let options = GeneratorOptions::default();
        let first = generate(&options).unwrap().value;
        let second = generate(&options).unwrap().value;
        assert_ne!(first, second);
    }
}
