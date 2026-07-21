use std::collections::HashMap;
use std::path::PathBuf;

/// Email provider credentials. Loaded from environment variables if set,
/// otherwise from a `KEY=VALUE` config file at `<app data dir>/notify.env`
/// (same idea as a `.env` file, just not tied to a particular process's
/// working directory — this app has no fixed cwd across CLI/GUI/OS).
/// Never hardcoded, never committed anywhere.
#[derive(Debug, Clone, Default)]
pub struct NotifyConfig {
    pub smtp_host: Option<String>,
    pub smtp_port: Option<u16>,
    pub smtp_user: Option<String>,
    pub smtp_pass: Option<String>,
    pub smtp_from: Option<String>,
    /// Skips TLS and auth entirely — for pointing at a local SMTP catcher
    /// (Mailpit, MailHog, aiosmtpd) during development. Never set this
    /// against a real mail server: codes would be sent in the clear.
    pub smtp_insecure: bool,

    pub key_server_url: Option<String>,
}

pub fn config_file_path() -> PathBuf {
    directories::ProjectDirs::from("studio", "SoloAppsStudio", "PassVault")
        .map(|d| d.config_dir().join("notify.env"))
        .unwrap_or_else(|| PathBuf::from("notify.env"))
}

fn parse_env_file(path: &PathBuf) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let Ok(contents) = std::fs::read_to_string(path) else {
        return map;
    };
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let value = value.trim().trim_matches('"');
            map.insert(key.trim().to_string(), value.to_string());
        }
    }
    map
}

impl NotifyConfig {
    pub fn load() -> Self {
        let file_vars = parse_env_file(&config_file_path());
        let get = |key: &str| -> Option<String> {
            std::env::var(key).ok().or_else(|| file_vars.get(key).cloned())
        };

        NotifyConfig {
            smtp_host: get("SMTP_HOST"),
            smtp_port: get("SMTP_PORT").and_then(|p| p.parse().ok()),
            smtp_user: get("SMTP_USER"),
            smtp_pass: get("SMTP_PASS"),
            smtp_from: get("SMTP_FROM"),
            smtp_insecure: get("SMTP_INSECURE").as_deref() == Some("1") || get("SMTP_INSECURE").as_deref() == Some("true"),
            key_server_url: get("PASSVAULT_KEY_SERVER_URL"),
        }
    }

    pub fn email_ready(&self) -> bool {
        if self.smtp_insecure {
            return self.smtp_host.is_some() && self.smtp_from.is_some();
        }
        self.smtp_host.is_some() && self.smtp_user.is_some() && self.smtp_pass.is_some() && self.smtp_from.is_some()
    }
}
