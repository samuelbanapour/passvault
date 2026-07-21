mod code;
mod config;
mod error;
mod keychain;
mod mail;
mod recovery_key;
mod server_client;
mod sidecar;

pub use code::Challenge;
pub use config::NotifyConfig;
pub use error::{OtpError, Result};
pub use server_client::KeyServerClient;
pub use sidecar::{KeyCustody, OtpConfig};

use std::path::Path;

/// Exposed directly so the key-custody server can deliver its own OTP
/// challenges without duplicating the email-sending logic.
pub fn send_email_code(cfg: &NotifyConfig, to: &str, code: &str) -> Result<()> {
    mail::send_code(cfg, to, code)
}

/// Sets up OTP login for a brand-new vault: generates a recovery key (the
/// string that actually protects the vault — the same role a master
/// password plays under the hood) and sends a verification code to prove
/// the contact info is correct before anything is persisted.
///
/// In `Local` custody, this process itself generates and checks the code,
/// then sends it via the locally configured SMTP credentials. In `Server`
/// custody, the *server* generates, sends, and verifies the code (so it
/// can rate-limit attempts) — this process only relays the user's input
/// to it.
pub struct PendingSetup {
    pub otp_config: OtpConfig,
    pub recovery_key: String,
    local_challenge: Option<Challenge>,
}

pub fn begin_setup(contact: String, custody: KeyCustody, server_url: Option<String>) -> Result<PendingSetup> {
    let recovery_key = recovery_key::generate();

    match custody {
        KeyCustody::Local => {
            let notify_cfg = NotifyConfig::load();
            let otp_config = OtpConfig::new(contact.clone(), custody, None);
            let (challenge, code) = Challenge::new();
            send_email_code(&notify_cfg, &contact, &code)?;
            Ok(PendingSetup {
                otp_config,
                recovery_key,
                local_challenge: Some(challenge),
            })
        }
        KeyCustody::Server => {
            let server_url = server_url.ok_or(OtpError::NotConfigured)?;
            let client = KeyServerClient::new(&server_url);
            let account_id = client.register(&contact)?;
            client.request_otp(&account_id)?;

            let mut otp_config = OtpConfig::new(contact, custody, Some(server_url));
            otp_config.account_id = account_id;
            Ok(PendingSetup {
                otp_config,
                recovery_key,
                local_challenge: None,
            })
        }
    }
}

impl PendingSetup {
    /// Confirms the verification code the user just received, then
    /// persists everything: the sidecar next to the vault, and the
    /// recovery key either in the local keychain or on the key server.
    pub fn confirm(mut self, vault_path: &Path, code: &str) -> Result<()> {
        match self.otp_config.custody {
            KeyCustody::Local => {
                self.local_challenge.as_mut().expect("local custody always has a local challenge").verify(code)?;
                keychain::store(&self.otp_config.account_id, &self.recovery_key)?;
            }
            KeyCustody::Server => {
                let server_url = self.otp_config.server_url.clone().ok_or(OtpError::NotConfigured)?;
                let client = KeyServerClient::new(&server_url);
                let session = client.verify_otp(&self.otp_config.account_id, code)?;
                client.store_key(&session, &self.recovery_key)?;
            }
        }

        sidecar::save(vault_path, &self.otp_config)?;
        Ok(())
    }
}

/// Begins an unlock attempt for a vault already configured for OTP login:
/// sends a fresh code to the registered email (via local SMTP config for
/// `Local` custody, or via the key-custody server itself for `Server`
/// custody).
pub struct PendingUnlock {
    otp_config: OtpConfig,
    local_challenge: Option<Challenge>,
}

pub fn begin_unlock(vault_path: &Path) -> Result<PendingUnlock> {
    let otp_config = sidecar::load(vault_path)?.ok_or(OtpError::NotConfigured)?;

    match otp_config.custody {
        KeyCustody::Local => {
            let notify_cfg = NotifyConfig::load();
            let (challenge, code) = Challenge::new();
            send_email_code(&notify_cfg, &otp_config.contact, &code)?;
            Ok(PendingUnlock {
                otp_config,
                local_challenge: Some(challenge),
            })
        }
        KeyCustody::Server => {
            let server_url = otp_config.server_url.clone().ok_or(OtpError::NotConfigured)?;
            let client = KeyServerClient::new(&server_url);
            client.request_otp(&otp_config.account_id)?;
            Ok(PendingUnlock {
                otp_config,
                local_challenge: None,
            })
        }
    }
}

impl PendingUnlock {
    pub fn contact(&self) -> &str {
        &self.otp_config.contact
    }

    /// Verifies the submitted code and returns the recovery key to unlock
    /// the vault with — callers pass this straight to
    /// `passvault_core::Vault::unlock`.
    pub fn confirm(mut self, code: &str) -> Result<String> {
        match self.otp_config.custody {
            KeyCustody::Local => {
                self.local_challenge.as_mut().expect("local custody always has a local challenge").verify(code)?;
                keychain::load(&self.otp_config.account_id)
            }
            KeyCustody::Server => {
                let server_url = self.otp_config.server_url.clone().ok_or(OtpError::NotConfigured)?;
                let client = KeyServerClient::new(&server_url);
                let session = client.verify_otp(&self.otp_config.account_id, code)?;
                client.fetch_key(&session)
            }
        }
    }

    /// Verifies the submitted code and, for `Server` custody, permanently
    /// deletes the account's key from the key-custody server. Used to
    /// authorize vault deletion — a separate flow from `confirm` (which
    /// fetches the key) so that a single compromised code can only ever
    /// do one or the other, not both.
    pub fn confirm_and_delete(mut self, code: &str) -> Result<()> {
        match self.otp_config.custody {
            KeyCustody::Local => {
                self.local_challenge.as_mut().expect("local custody always has a local challenge").verify(code)?;
                Ok(())
            }
            KeyCustody::Server => {
                let server_url = self.otp_config.server_url.clone().ok_or(OtpError::NotConfigured)?;
                let client = KeyServerClient::new(&server_url);
                let session = client.verify_otp(&self.otp_config.account_id, code)?;
                client.delete_account(&session)
            }
        }
    }
}

pub fn is_configured(vault_path: &Path) -> bool {
    sidecar::exists(vault_path)
}

pub fn config_for(vault_path: &Path) -> Result<Option<OtpConfig>> {
    sidecar::load(vault_path)
}

/// Shows enough of an email address to confirm it's the right one without
/// fully exposing it over someone's shoulder.
pub fn mask_contact(contact: &str) -> String {
    if let Some((user, domain)) = contact.split_once('@') {
        let visible = user.chars().take(2).collect::<String>();
        format!("{visible}***@{domain}")
    } else {
        let len = contact.chars().count();
        let tail: String = contact.chars().skip(len.saturating_sub(4)).collect();
        format!("***{tail}")
    }
}

pub fn disable(vault_path: &Path) -> Result<()> {
    if let Some(cfg) = sidecar::load(vault_path)? {
        if cfg.custody == KeyCustody::Local {
            let _ = keychain::delete(&cfg.account_id);
        }
    }
    sidecar::delete(vault_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_key_has_expected_shape() {
        let key = recovery_key::generate();
        // 256 bits of Crockford base32 grouped in 4-char chunks with dashes.
        assert!(key.len() > 40);
        assert!(key.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
        let a = recovery_key::generate();
        let b = recovery_key::generate();
        assert_ne!(a, b, "two generated keys should never collide");
    }

    #[test]
    fn challenge_accepts_correct_code_and_rejects_wrong_code() {
        let (mut challenge, code) = Challenge::new();
        assert_eq!(code.len(), code::CODE_LEN);
        assert!(challenge.verify("000000").is_err() || code == "000000");
    }

    #[test]
    fn challenge_locks_out_after_max_attempts() {
        let (mut challenge, code) = Challenge::new();
        let wrong = if code == "111111" { "222222" } else { "111111" };
        for _ in 0..code::MAX_ATTEMPTS {
            let _ = challenge.verify(wrong);
        }
        // One more attempt (even with the *correct* code) should now be
        // locked out — attempts are capped regardless of correctness.
        assert!(matches!(challenge.verify(&code), Err(OtpError::TooManyAttempts)));
    }

    #[test]
    fn challenge_verifies_correct_code_end_to_end() {
        let (mut challenge, code) = Challenge::new();
        assert!(challenge.verify(&code).is_ok());
    }

    #[test]
    fn keychain_round_trip() {
        // Exercises the real OS credential store (macOS Keychain /
        // Windows Credential Manager / Linux Secret Service) — skipped
        // gracefully in headless CI environments with no such backend.
        let account_id = format!("test-{}", uuid::Uuid::new_v4());
        let secret = "TEST-RECOVERY-KEY-DO-NOT-USE";

        match keychain::store(&account_id, secret) {
            Ok(()) => {
                let loaded = keychain::load(&account_id).expect("should read back what was just stored");
                assert_eq!(loaded, secret);
                keychain::delete(&account_id).expect("cleanup should succeed");
                assert!(keychain::load(&account_id).is_err(), "deleted entry should no longer be readable");
            }
            Err(e) => {
                eprintln!("skipping keychain_round_trip: no OS credential backend available ({e})");
            }
        }
    }

    #[test]
    fn sidecar_round_trip() {
        let dir = std::env::temp_dir().join(format!("passvault-otp-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let vault_path = dir.join("vault.pvault");

        assert!(!is_configured(&vault_path));

        let cfg = OtpConfig::new("user@example.com".to_string(), KeyCustody::Local, None);
        sidecar::save(&vault_path, &cfg).unwrap();

        assert!(is_configured(&vault_path));
        let loaded = config_for(&vault_path).unwrap().expect("sidecar should exist");
        assert_eq!(loaded.contact, "user@example.com");

        sidecar::delete(&vault_path).unwrap();
        assert!(!is_configured(&vault_path));

        std::fs::remove_dir_all(&dir).ok();
    }
}
