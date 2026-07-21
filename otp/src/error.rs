use thiserror::Error;

#[derive(Debug, Error)]
pub enum OtpError {
    #[error("code has expired — request a new one")]
    Expired,
    #[error("incorrect code")]
    WrongCode,
    #[error("too many incorrect attempts — request a new code")]
    TooManyAttempts,
    #[error("please wait {0}s before requesting another code")]
    RateLimited(u64),
    #[error("email is not configured — set SMTP_HOST/SMTP_USER/SMTP_PASS/SMTP_FROM")]
    EmailNotConfigured,
    #[error("failed to send email: {0}")]
    EmailSend(String),
    #[error("keychain error: {0}")]
    Keychain(#[from] keyring::Error),
    #[error("no OTP login configured for this vault")]
    NotConfigured,
    #[error("server request failed: {0}")]
    Server(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, OtpError>;
