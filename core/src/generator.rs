use rand::{rngs::OsRng, seq::SliceRandom, Rng};
use serde::Deserialize;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{}:;,.<>?/~";
const AMBIGUOUS: &str = "il1IoO0|`'\";:,.";

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct GeneratorOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

impl Default for GeneratorOptions {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GeneratorError {
    #[error("at least one character set must be enabled")]
    NoCharsetSelected,
    #[error("length must be at least 1")]
    LengthTooShort,
}

fn filtered(set: &str, exclude_ambiguous: bool) -> Vec<char> {
    set.chars()
        .filter(|c| !exclude_ambiguous || !AMBIGUOUS.contains(*c))
        .collect()
}

/// Generates a cryptographically random password. When multiple character
/// classes are enabled, the result is guaranteed to contain at least one
/// character from each, which avoids the (rare but annoying) all-digits or
/// all-lowercase outcome that pure random sampling can produce.
pub fn generate(opts: &GeneratorOptions) -> Result<String, GeneratorError> {
    if opts.length == 0 {
        return Err(GeneratorError::LengthTooShort);
    }

    let mut classes: Vec<Vec<char>> = Vec::new();
    if opts.lowercase {
        classes.push(filtered(LOWER, opts.exclude_ambiguous));
    }
    if opts.uppercase {
        classes.push(filtered(UPPER, opts.exclude_ambiguous));
    }
    if opts.digits {
        classes.push(filtered(DIGITS, opts.exclude_ambiguous));
    }
    if opts.symbols {
        classes.push(filtered(SYMBOLS, opts.exclude_ambiguous));
    }
    if classes.is_empty() {
        return Err(GeneratorError::NoCharsetSelected);
    }

    let mut rng = OsRng;
    let all: Vec<char> = classes.iter().flatten().copied().collect();

    let mut password: Vec<char> = Vec::with_capacity(opts.length);
    // Guarantee coverage of every selected class, capped at the requested length.
    for class in &classes {
        if password.len() >= opts.length {
            break;
        }
        password.push(class[rng.gen_range(0..class.len())]);
    }
    while password.len() < opts.length {
        password.push(all[rng.gen_range(0..all.len())]);
    }

    password.shuffle(&mut rng);
    Ok(password.into_iter().collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrengthLabel {
    VeryWeak,
    Weak,
    Reasonable,
    Strong,
    VeryStrong,
}

impl StrengthLabel {
    pub fn as_str(&self) -> &'static str {
        match self {
            StrengthLabel::VeryWeak => "very weak",
            StrengthLabel::Weak => "weak",
            StrengthLabel::Reasonable => "reasonable",
            StrengthLabel::Strong => "strong",
            StrengthLabel::VeryStrong => "very strong",
        }
    }
}

/// Rough Shannon-style entropy estimate based on the character classes
/// actually present in the password, not a full pattern-aware model
/// (no dictionary/L33t-speak detection) — good enough to flag obviously
/// weak input without pulling in a heavy dependency like zxcvbn.
pub fn estimate_strength(password: &str) -> (f64, StrengthLabel) {
    let mut pool = 0usize;
    if password.chars().any(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        pool += 26;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if password.chars().any(|c| !c.is_ascii_alphanumeric()) {
        pool += SYMBOLS.chars().count();
    }
    let pool = pool.max(1);
    let bits = (password.chars().count() as f64) * (pool as f64).log2();

    let label = match bits {
        b if b < 28.0 => StrengthLabel::VeryWeak,
        b if b < 36.0 => StrengthLabel::Weak,
        b if b < 60.0 => StrengthLabel::Reasonable,
        b if b < 100.0 => StrengthLabel::Strong,
        _ => StrengthLabel::VeryStrong,
    };
    (bits, label)
}
