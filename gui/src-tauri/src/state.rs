use std::sync::Mutex;
use std::time::{Duration, Instant};

use passvault_core::Vault;
use passvault_otp::{PendingSetup, PendingUnlock};

pub const AUTO_LOCK_SECS: u64 = 300; // 5 minutes idle

pub struct AppState {
    pub vault: Option<Vault>,
    pub vault_path: Option<String>,
    pub last_activity: Instant,
    /// Set only while the currently-open vault was unlocked via OTP —
    /// needed if the user chooses to turn OTP login back off (that flow
    /// re-wraps the DEK under a new master password, which requires the
    /// old "password" — i.e. this recovery key). Cleared on lock.
    pub otp_recovery_key: Option<String>,
    pub pending_otp_setup: Option<(String, PendingSetup)>,
    pub pending_otp_unlock: Option<(String, PendingUnlock)>,
    /// Separate from `pending_otp_unlock` even though both hold a
    /// `PendingUnlock` — this one is only ever consumed by
    /// `confirm_and_delete`, never `confirm`, so a code requested for one
    /// purpose can't accidentally authorize the other.
    pub pending_otp_delete: Option<(String, PendingUnlock)>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            vault: None,
            vault_path: None,
            last_activity: Instant::now(),
            otp_recovery_key: None,
            pending_otp_setup: None,
            pending_otp_unlock: None,
            pending_otp_delete: None,
        }
    }
}

impl AppState {
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn idle_for(&self) -> Duration {
        self.last_activity.elapsed()
    }
}

pub type SharedState = Mutex<AppState>;
