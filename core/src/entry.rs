use serde::{Deserialize, Serialize};
use uuid::Uuid;

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomField {
    pub key: String,
    pub value: String,
    /// Hidden fields are masked in the GUI/CLI by default (e.g. security
    /// question answers) but are stored with the same protection as
    /// everything else in the vault.
    #[serde(default)]
    pub hidden: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub id: Uuid,
    pub title: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
    /// Base32-encoded TOTP seed, if this entry has 2FA configured.
    #[serde(default)]
    pub totp_secret: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Entry {
    pub fn new(title: impl Into<String>) -> Self {
        let ts = now();
        Self {
            id: Uuid::new_v4(),
            title: title.into(),
            username: String::new(),
            password: String::new(),
            url: String::new(),
            notes: String::new(),
            tags: Vec::new(),
            custom_fields: Vec::new(),
            totp_secret: None,
            created_at: ts,
            updated_at: ts,
        }
    }

    pub fn touch(&mut self) {
        self.updated_at = now();
    }
}
