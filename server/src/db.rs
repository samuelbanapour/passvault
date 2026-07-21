use rusqlite::Connection;
use std::sync::Mutex;

pub struct Db(pub Mutex<Connection>);

impl Db {
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;

            CREATE TABLE IF NOT EXISTS accounts (
                id          TEXT PRIMARY KEY,
                contact     TEXT NOT NULL UNIQUE,
                created_at  INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS otp_challenges (
                account_id      TEXT PRIMARY KEY REFERENCES accounts(id),
                challenge_json  TEXT NOT NULL
            );

            -- Deliberately separate from otp_challenges: this must survive
            -- a successful verify (which deletes the challenge row) so the
            -- send-rate limit can't be reset by simply logging in.
            CREATE TABLE IF NOT EXISTS otp_rate_limits (
                account_id      TEXT PRIMARY KEY REFERENCES accounts(id),
                last_sent_at    INTEGER NOT NULL,
                day_bucket      INTEGER NOT NULL,
                sends_today     INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token       TEXT PRIMARY KEY,
                account_id  TEXT NOT NULL REFERENCES accounts(id),
                expires_at  INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS vault_keys (
                account_id  TEXT PRIMARY KEY REFERENCES accounts(id),
                nonce       BLOB NOT NULL,
                ciphertext  BLOB NOT NULL,
                updated_at  INTEGER NOT NULL
            );
            ",
        )?;
        Ok(Db(Mutex::new(conn)))
    }
}
