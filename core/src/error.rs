use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("incorrect master password")]
    WrongPassword,
    #[error("vault file is corrupt or not a passvault file")]
    Corrupt,
    #[error("unsupported vault format version {0}")]
    UnsupportedVersion(u32),
    #[error("entry not found")]
    EntryNotFound,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("invalid base32 TOTP secret")]
    InvalidTotpSecret,
    #[error("vault already exists at this path")]
    AlreadyExists,
    #[error("could not parse import file: {0}")]
    Import(String),
}

pub type Result<T> = std::result::Result<T, VaultError>;
