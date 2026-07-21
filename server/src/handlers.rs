use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use passvault_otp::Challenge;

use crate::error::AppError;
use crate::AppState;

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

fn today_bucket() -> i64 {
    now() / 86_400
}

const MIN_SECONDS_BETWEEN_SENDS: i64 = 60;
const MAX_SENDS_PER_DAY: i64 = 10;
const SESSION_TTL_SECS: i64 = 900;

// ---------- POST /accounts ----------

#[derive(Deserialize)]
pub struct RegisterRequest {
    contact: String,
}
#[derive(Serialize)]
pub struct RegisterResponse {
    account_id: String,
}

pub async fn register(State(state): State<Arc<AppState>>, Json(req): Json<RegisterRequest>) -> Result<Json<RegisterResponse>, AppError> {
    if req.contact.trim().is_empty() {
        return Err(AppError::BadRequest("contact must not be empty".into()));
    }
    let conn = state.db.0.lock().unwrap();

    if let Ok(id) = conn
        .query_row("SELECT id FROM accounts WHERE contact = ?1", [&req.contact], |r| r.get::<_, String>(0))
    {
        return Ok(Json(RegisterResponse { account_id: id }));
    }

    let id = Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO accounts (id, contact, created_at) VALUES (?1, ?2, ?3)",
        (&id, &req.contact, now()),
    )?;
    Ok(Json(RegisterResponse { account_id: id }))
}

// ---------- POST /otp/request ----------

#[derive(Deserialize)]
pub struct OtpRequestBody {
    account_id: String,
}

pub async fn otp_request(State(state): State<Arc<AppState>>, Json(req): Json<OtpRequestBody>) -> Result<StatusCode, AppError> {
    let contact: String = {
        let conn = state.db.0.lock().unwrap();
        conn.query_row("SELECT contact FROM accounts WHERE id = ?1", [&req.account_id], |r| r.get(0))
            .map_err(|_| AppError::NotFound("unknown account".into()))?
    };

    // Rate limit: cheap to check before we bother generating/sending a code.
    // Tracked in a table separate from the challenge itself, so a
    // successful verify (which deletes the challenge) can't reset it.
    let day = today_bucket();
    let sends_today = {
        let conn = state.db.0.lock().unwrap();
        let existing = conn
            .query_row(
                "SELECT last_sent_at, day_bucket, sends_today FROM otp_rate_limits WHERE account_id = ?1",
                [&req.account_id],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)),
            )
            .ok();

        match existing {
            Some((last_sent_at, day_bucket, sends_today)) => {
                let elapsed = now() - last_sent_at;
                if elapsed < MIN_SECONDS_BETWEEN_SENDS {
                    return Err(AppError::RateLimited((MIN_SECONDS_BETWEEN_SENDS - elapsed) as u64));
                }
                if day_bucket == day && sends_today >= MAX_SENDS_PER_DAY {
                    return Err(AppError::RateLimited(86_400));
                }
                if day_bucket == day {
                    sends_today + 1
                } else {
                    1
                }
            }
            None => 1,
        }
    };

    let (challenge, code) = Challenge::new();
    let notify_cfg = passvault_otp::NotifyConfig::load();
    // Delivery failures are a server-side misconfiguration (missing/broken
    // SMTP credentials), not something the client did wrong.
    passvault_otp::send_email_code(&notify_cfg, &contact, &code).map_err(|e| AppError::Internal(e.to_string()))?;

    let challenge_json = serde_json::to_string(&challenge).map_err(|e| AppError::Internal(e.to_string()))?;
    let conn = state.db.0.lock().unwrap();
    conn.execute(
        "INSERT INTO otp_challenges (account_id, challenge_json) VALUES (?1, ?2)
         ON CONFLICT(account_id) DO UPDATE SET challenge_json = ?2",
        (&req.account_id, &challenge_json),
    )?;
    conn.execute(
        "INSERT INTO otp_rate_limits (account_id, last_sent_at, day_bucket, sends_today) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(account_id) DO UPDATE SET last_sent_at = ?2, day_bucket = ?3, sends_today = ?4",
        (&req.account_id, now(), day, sends_today),
    )?;

    Ok(StatusCode::NO_CONTENT)
}

// ---------- POST /otp/verify ----------

#[derive(Deserialize)]
pub struct OtpVerifyBody {
    account_id: String,
    code: String,
}
#[derive(Serialize)]
pub struct OtpVerifyResponse {
    session_token: String,
}

pub async fn otp_verify(
    State(state): State<Arc<AppState>>,
    Json(req): Json<OtpVerifyBody>,
) -> Result<Json<OtpVerifyResponse>, AppError> {
    let conn = state.db.0.lock().unwrap();
    let challenge_json: String = conn
        .query_row("SELECT challenge_json FROM otp_challenges WHERE account_id = ?1", [&req.account_id], |r| r.get(0))
        .map_err(|_| AppError::NotFound("no pending code for this account — request one first".into()))?;

    let mut challenge: Challenge = serde_json::from_str(&challenge_json).map_err(|e| AppError::Internal(e.to_string()))?;

    match challenge.verify(&req.code) {
        Ok(()) => {
            conn.execute("DELETE FROM otp_challenges WHERE account_id = ?1", [&req.account_id])?;

            let mut token_bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut token_bytes);
            let token = URL_SAFE_NO_PAD.encode(token_bytes);

            conn.execute(
                "INSERT INTO sessions (token, account_id, expires_at) VALUES (?1, ?2, ?3)",
                (&token, &req.account_id, now() + SESSION_TTL_SECS),
            )?;
            Ok(Json(OtpVerifyResponse { session_token: token }))
        }
        Err(e) => {
            use passvault_otp::OtpError;
            match &e {
                OtpError::TooManyAttempts | OtpError::Expired => {
                    conn.execute("DELETE FROM otp_challenges WHERE account_id = ?1", [&req.account_id])?;
                }
                _ => {
                    let updated = serde_json::to_string(&challenge).map_err(|e| AppError::Internal(e.to_string()))?;
                    conn.execute(
                        "UPDATE otp_challenges SET challenge_json = ?1 WHERE account_id = ?2",
                        (&updated, &req.account_id),
                    )?;
                }
            }
            // Wrong/expired/exhausted codes are the client's fault, not ours.
            Err(AppError::BadRequest(e.to_string()))
        }
    }
}

// ---------- session validation shared by /key handlers ----------

fn take_session(conn: &rusqlite::Connection, token: &str) -> Result<String, AppError> {
    let account_id: String = conn
        .query_row(
            "SELECT account_id FROM sessions WHERE token = ?1 AND expires_at > ?2",
            (token, now()),
            |r| r.get(0),
        )
        .map_err(|_| AppError::Unauthorized("invalid or expired session — verify your code again".into()))?;
    // Sessions are single-use: one key operation per successful OTP verification.
    conn.execute("DELETE FROM sessions WHERE token = ?1", [token])?;
    Ok(account_id)
}

// ---------- POST /key ----------

#[derive(Deserialize)]
pub struct StoreKeyBody {
    session_token: String,
    recovery_key: String,
}

pub async fn store_key(State(state): State<Arc<AppState>>, Json(req): Json<StoreKeyBody>) -> Result<StatusCode, AppError> {
    let conn = state.db.0.lock().unwrap();
    let account_id = take_session(&conn, &req.session_token)?;

    let (nonce, ciphertext) = state.master_key.encrypt(&req.recovery_key);
    conn.execute(
        "INSERT INTO vault_keys (account_id, nonce, ciphertext, updated_at) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(account_id) DO UPDATE SET nonce = ?2, ciphertext = ?3, updated_at = ?4",
        (&account_id, &nonce, &ciphertext, now()),
    )?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------- GET /key ----------

#[derive(Deserialize)]
pub struct FetchKeyQuery {
    session_token: String,
}
#[derive(Serialize)]
pub struct FetchKeyResponse {
    recovery_key: String,
}

pub async fn fetch_key(
    State(state): State<Arc<AppState>>,
    Query(q): Query<FetchKeyQuery>,
) -> Result<Json<FetchKeyResponse>, AppError> {
    let conn = state.db.0.lock().unwrap();
    let account_id = take_session(&conn, &q.session_token)?;

    let (nonce, ciphertext): (Vec<u8>, Vec<u8>) = conn
        .query_row("SELECT nonce, ciphertext FROM vault_keys WHERE account_id = ?1", [&account_id], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .map_err(|_| AppError::NotFound("no key stored for this account".into()))?;

    let recovery_key = state
        .master_key
        .decrypt(&nonce, &ciphertext)
        .ok_or_else(|| AppError::Internal("failed to decrypt stored key".into()))?;

    Ok(Json(FetchKeyResponse { recovery_key }))
}

// ---------- DELETE /account ----------

#[derive(Deserialize)]
pub struct DeleteAccountQuery {
    session_token: String,
}

/// Permanently purges everything for this account — the stored (encrypted)
/// vault key, any pending challenge, and rate-limit history. Requires a
/// fresh OTP-verified session like `/key` does; there's no separate
/// "are you sure" step server-side because the client already gates this
/// behind its own confirmation before ever requesting the session.
pub async fn delete_account(State(state): State<Arc<AppState>>, Query(q): Query<DeleteAccountQuery>) -> Result<StatusCode, AppError> {
    let conn = state.db.0.lock().unwrap();
    let account_id = take_session(&conn, &q.session_token)?;

    conn.execute("DELETE FROM vault_keys WHERE account_id = ?1", [&account_id])?;
    conn.execute("DELETE FROM otp_challenges WHERE account_id = ?1", [&account_id])?;
    conn.execute("DELETE FROM otp_rate_limits WHERE account_id = ?1", [&account_id])?;
    conn.execute("DELETE FROM accounts WHERE id = ?1", [&account_id])?;
    Ok(StatusCode::NO_CONTENT)
}
