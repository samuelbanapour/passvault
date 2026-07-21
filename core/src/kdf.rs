use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};

/// Argon2id parameters used to derive the key-encryption-key from the master
/// password. Chosen well above OWASP's minimums since this protects a
/// long-lived vault rather than a single login attempt.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_kib: 65536, // 64 MiB
            iterations: 3,
            parallelism: 4,
        }
    }
}

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;

pub fn derive_key(password: &str, salt: &[u8], params: KdfParams) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let argon2_params = Params::new(params.memory_kib, params.iterations, params.parallelism, Some(KEY_LEN))
        .map_err(|_| VaultError::Corrupt)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|_| VaultError::Corrupt)?;
    Ok(key)
}
