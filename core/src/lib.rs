mod b64;
mod crypto;
mod entry;
mod error;
mod generator;
mod import;
mod kdf;
mod totp;
mod vault;

pub use entry::{CustomField, Entry};
pub use error::{Result, VaultError};
pub use generator::{estimate_strength, generate, GeneratorError, GeneratorOptions, StrengthLabel};
pub use import::parse_csv;
pub use kdf::KdfParams;
pub use totp::{current as totp_now, generate_at as totp_at, seconds_remaining as totp_seconds_remaining};
pub use vault::Vault;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn create_unlock_and_crud_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.pvault");

        {
            let mut vault = Vault::create(&path, "correct horse battery staple").unwrap();
            let mut e = Entry::new("GitHub");
            e.username = "octocat".into();
            e.password = "hunter2".into();
            vault.add_entry(e);
            vault.save().unwrap();
        }

        let vault = Vault::unlock(&path, "correct horse battery staple").unwrap();
        assert_eq!(vault.entries().len(), 1);
        assert_eq!(vault.entries()[0].title, "GitHub");
        assert_eq!(vault.entries()[0].password, "hunter2");

        // Wrong password must fail closed.
        let err = Vault::unlock(&path, "wrong password").unwrap_err();
        assert!(matches!(err, VaultError::WrongPassword));
    }

    #[test]
    fn change_master_password_preserves_data() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test2.pvault");

        let mut vault = Vault::create(&path, "old-pass").unwrap();
        vault.add_entry(Entry::new("Example"));
        vault.save().unwrap();

        vault.change_master_password("old-pass", "new-pass").unwrap();

        let reopened = Vault::unlock(&path, "new-pass").unwrap();
        assert_eq!(reopened.entries().len(), 1);
        assert!(Vault::unlock(&path, "old-pass").is_err());
    }

    #[test]
    fn generator_respects_length_and_charsets() {
        let opts = GeneratorOptions {
            length: 24,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: false,
            exclude_ambiguous: true,
        };
        let pw = generate(&opts).unwrap();
        assert_eq!(pw.chars().count(), 24);
        assert!(pw.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn totp_matches_known_vector() {
        // RFC 6238 test vector: secret "12345678901234567890" (ASCII, Base32
        // encoded below), at unix time 59, should yield "94287082".
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let code = totp_at(secret, 59, 30, 8).unwrap();
        assert_eq!(code, "94287082");
    }
}
