use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};

use crate::config::NotifyConfig;
use crate::error::{OtpError, Result};

pub fn send_code(cfg: &NotifyConfig, to: &str, code: &str) -> Result<()> {
    if !cfg.email_ready() {
        return Err(OtpError::EmailNotConfigured);
    }
    let host = cfg.smtp_host.as_deref().unwrap();
    let from = cfg.smtp_from.as_deref().unwrap();
    let port = cfg.smtp_port.unwrap_or(587);

    let email = Message::builder()
        .from(from.parse().map_err(|e| OtpError::EmailSend(format!("invalid from address: {e}")))?)
        .to(to.parse().map_err(|e| OtpError::EmailSend(format!("invalid to address: {e}")))?)
        .subject("Your PassVault login code")
        .body(format!(
            "Your PassVault login code is: {code}\n\nThis code expires in 10 minutes. If you didn't request this, you can ignore this email."
        ))
        .map_err(|e| OtpError::EmailSend(e.to_string()))?;

    let mailer = if cfg.smtp_insecure {
        SmtpTransport::builder_dangerous(host).port(port).build()
    } else {
        let user = cfg.smtp_user.clone().unwrap();
        let pass = cfg.smtp_pass.clone().unwrap();
        // `relay()` always negotiates implicit TLS (SMTPS, port 465
        // semantics); `starttls_relay()` connects in plaintext first and
        // upgrades via STARTTLS (submission, port 587 semantics). Getting
        // this backwards produces a garbled handshake, not a clean auth
        // error — picking the right one based on the configured port
        // avoids silently breaking on the vastly more common port-587
        // setup (Gmail, Brevo, SendGrid, etc. all default to it).
        let builder = if port == 465 {
            SmtpTransport::relay(host)
        } else {
            SmtpTransport::starttls_relay(host)
        }
        .map_err(|e| OtpError::EmailSend(e.to_string()))?;

        builder.port(port).credentials(Credentials::new(user, pass)).build()
    };

    mailer.send(&email).map_err(|e| OtpError::EmailSend(e.to_string()))?;
    Ok(())
}
