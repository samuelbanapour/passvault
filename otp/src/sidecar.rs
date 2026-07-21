use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyCustody {
    /// Recovery key lives only in this device's OS keychain. OTP just
    /// gates whether the app is allowed to read it back out.
    Local,
    /// Recovery key is held by a key-custody server, released after OTP
    /// verification — lets the same vault file be unlocked from any
    /// device, at the cost of trusting that server.
    Server,
}

/// Unencrypted metadata living next to a vault file (`<vault>.otp.json`)
/// describing how to reach the user for OTP login. Holds no secrets —
/// the actual recovery key is either in the local OS keychain or on the
/// key-custody server, never here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtpConfig {
    pub account_id: String,
    pub contact: String,
    pub custody: KeyCustody,
    pub server_url: Option<String>,
}

impl OtpConfig {
    pub fn new(contact: String, custody: KeyCustody, server_url: Option<String>) -> Self {
        Self {
            account_id: Uuid::new_v4().to_string(),
            contact,
            custody,
            server_url,
        }
    }
}

fn sidecar_path(vault_path: &Path) -> PathBuf {
    let mut p = vault_path.as_os_str().to_owned();
    p.push(".otp.json");
    PathBuf::from(p)
}

pub fn exists(vault_path: &Path) -> bool {
    sidecar_path(vault_path).exists()
}

pub fn load(vault_path: &Path) -> Result<Option<OtpConfig>> {
    let path = sidecar_path(vault_path);
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(path)?;
    Ok(Some(serde_json::from_str(&raw)?))
}

pub fn save(vault_path: &Path, cfg: &OtpConfig) -> Result<()> {
    let path = sidecar_path(vault_path);
    std::fs::write(path, serde_json::to_string_pretty(cfg)?)?;
    Ok(())
}

pub fn delete(vault_path: &Path) -> Result<()> {
    let path = sidecar_path(vault_path);
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}
