use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Result, VaultError};

type HmacSha1 = Hmac<Sha1>;

pub const DEFAULT_PERIOD: u64 = 30;
pub const DEFAULT_DIGITS: u32 = 6;

fn decode_secret(secret: &str) -> Result<Vec<u8>> {
    let cleaned: String = secret.chars().filter(|c| !c.is_whitespace()).collect();
    base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &cleaned.to_uppercase())
        .ok_or(VaultError::InvalidTotpSecret)
}

/// RFC 6238 TOTP code for a given unix timestamp. `secret` is the shared
/// secret as it's normally shown/stored: Base32, no padding.
pub fn generate_at(secret: &str, unix_time: u64, period: u64, digits: u32) -> Result<String> {
    let key = decode_secret(secret)?;
    let counter = unix_time / period;

    let mut mac = HmacSha1::new_from_slice(&key).map_err(|_| VaultError::InvalidTotpSecret)?;
    mac.update(&counter.to_be_bytes());
    let hs = mac.finalize().into_bytes();

    let offset = (hs[hs.len() - 1] & 0x0f) as usize;
    let binary = ((hs[offset] as u32 & 0x7f) << 24)
        | ((hs[offset + 1] as u32) << 16)
        | ((hs[offset + 2] as u32) << 8)
        | (hs[offset + 3] as u32);

    let code = binary % 10u32.pow(digits);
    Ok(format!("{:0width$}", code, width = digits as usize))
}

/// Convenience wrapper for "the code right now" using default 30s/6-digit
/// parameters, which is what the overwhelming majority of services use.
pub fn current(secret: &str) -> Result<String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    generate_at(secret, now, DEFAULT_PERIOD, DEFAULT_DIGITS)
}

/// Seconds remaining until the current code rotates, for a countdown UI.
pub fn seconds_remaining(period: u64) -> u64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    period - (now % period)
}
