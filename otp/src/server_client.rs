use serde::{Deserialize, Serialize};

use crate::error::{OtpError, Result};

pub struct KeyServerClient {
    base_url: String,
    client: reqwest::blocking::Client,
}

#[derive(Serialize)]
struct RegisterRequest<'a> {
    contact: &'a str,
}
#[derive(Deserialize)]
struct RegisterResponse {
    account_id: String,
}

#[derive(Serialize)]
struct OtpRequestBody<'a> {
    account_id: &'a str,
}

#[derive(Serialize)]
struct OtpVerifyBody<'a> {
    account_id: &'a str,
    code: &'a str,
}
#[derive(Deserialize)]
struct OtpVerifyResponse {
    session_token: String,
}

#[derive(Serialize)]
struct StoreKeyBody<'a> {
    session_token: &'a str,
    recovery_key: &'a str,
}

#[derive(Deserialize)]
struct FetchKeyResponse {
    recovery_key: String,
}

#[derive(Deserialize)]
struct ErrorResponse {
    error: String,
}

impl KeyServerClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            client: reqwest::blocking::Client::new(),
        }
    }

    fn check(resp: reqwest::blocking::Response) -> Result<reqwest::blocking::Response> {
        if resp.status().is_success() {
            Ok(resp)
        } else {
            let status = resp.status();
            let msg = resp
                .json::<ErrorResponse>()
                .map(|e| e.error)
                .unwrap_or_else(|_| status.to_string());
            Err(OtpError::Server(msg))
        }
    }

    /// Registers (or fetches an existing) account for this contact and
    /// returns its account_id.
    pub fn register(&self, contact: &str) -> Result<String> {
        let resp = self
            .client
            .post(format!("{}/accounts", self.base_url))
            .json(&RegisterRequest { contact })
            .send()
            .map_err(|e| OtpError::Server(e.to_string()))?;
        let resp = Self::check(resp)?;
        Ok(resp.json::<RegisterResponse>().map_err(|e| OtpError::Server(e.to_string()))?.account_id)
    }

    pub fn request_otp(&self, account_id: &str) -> Result<()> {
        let resp = self
            .client
            .post(format!("{}/otp/request", self.base_url))
            .json(&OtpRequestBody { account_id })
            .send()
            .map_err(|e| OtpError::Server(e.to_string()))?;
        Self::check(resp)?;
        Ok(())
    }

    pub fn verify_otp(&self, account_id: &str, code: &str) -> Result<String> {
        let resp = self
            .client
            .post(format!("{}/otp/verify", self.base_url))
            .json(&OtpVerifyBody { account_id, code })
            .send()
            .map_err(|e| OtpError::Server(e.to_string()))?;
        let resp = Self::check(resp)?;
        Ok(resp
            .json::<OtpVerifyResponse>()
            .map_err(|e| OtpError::Server(e.to_string()))?
            .session_token)
    }

    pub fn store_key(&self, session_token: &str, recovery_key: &str) -> Result<()> {
        let resp = self
            .client
            .post(format!("{}/key", self.base_url))
            .json(&StoreKeyBody { session_token, recovery_key })
            .send()
            .map_err(|e| OtpError::Server(e.to_string()))?;
        Self::check(resp)?;
        Ok(())
    }

    pub fn fetch_key(&self, session_token: &str) -> Result<String> {
        let resp = self
            .client
            .get(format!("{}/key", self.base_url))
            .query(&[("session_token", session_token)])
            .send()
            .map_err(|e| OtpError::Server(e.to_string()))?;
        let resp = Self::check(resp)?;
        Ok(resp
            .json::<FetchKeyResponse>()
            .map_err(|e| OtpError::Server(e.to_string()))?
            .recovery_key)
    }

    /// Permanently purges the account and its stored key from the server.
    pub fn delete_account(&self, session_token: &str) -> Result<()> {
        let resp = self
            .client
            .delete(format!("{}/account", self.base_url))
            .query(&[("session_token", session_token)])
            .send()
            .map_err(|e| OtpError::Server(e.to_string()))?;
        Self::check(resp)?;
        Ok(())
    }
}
