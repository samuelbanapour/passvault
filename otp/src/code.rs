use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::{OtpError, Result};

pub const CODE_LEN: usize = 6;
pub const DEFAULT_TTL_SECS: i64 = 600; // 10 minutes
pub const MAX_ATTEMPTS: u8 = 5;

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

fn hash_code(code: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    hasher.finalize().into()
}

fn generate_code() -> String {
    let mut rng = rand::rngs::OsRng;
    let n: u32 = rng.gen_range(0..10u32.pow(CODE_LEN as u32));
    format!("{:0width$}", n, width = CODE_LEN)
}

/// A pending OTP challenge. Only the hash of the code is kept — the
/// plaintext is returned once from `Challenge::new` to be sent to the user
/// and is never stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    code_hash: [u8; 32],
    expires_at: i64,
    attempts: u8,
}

impl Challenge {
    /// Creates a new challenge and returns it along with the plaintext code
    /// to deliver to the user (over email/SMS — never persisted as-is).
    pub fn new() -> (Self, String) {
        let code = generate_code();
        let challenge = Challenge {
            code_hash: hash_code(&code),
            expires_at: now() + DEFAULT_TTL_SECS,
            attempts: 0,
        };
        (challenge, code)
    }

    /// Verifies a submitted code in constant time, tracking attempts so a
    /// single challenge can't be brute-forced (six digits is only ~1e6
    /// possibilities — the attempt cap, not the code space, is what makes
    /// this safe).
    pub fn verify(&mut self, submitted: &str) -> Result<()> {
        if now() > self.expires_at {
            return Err(OtpError::Expired);
        }
        if self.attempts >= MAX_ATTEMPTS {
            return Err(OtpError::TooManyAttempts);
        }
        self.attempts += 1;

        let submitted_hash = hash_code(submitted.trim());
        if submitted_hash.ct_eq(&self.code_hash).into() {
            Ok(())
        } else {
            Err(OtpError::WrongCode)
        }
    }
}
