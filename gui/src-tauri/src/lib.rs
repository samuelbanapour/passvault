mod commands;
mod otp_commands;
mod state;

use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use tauri::{Emitter, Manager};

use state::{AppState, SharedState, AUTO_LOCK_SECS};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage::<SharedState>(Mutex::new(AppState::default()))
        .setup(|app| {
            let handle = app.handle().clone();
            thread::spawn(move || loop {
                thread::sleep(Duration::from_secs(5));
                let state = handle.state::<SharedState>();
                let mut st = state.lock().unwrap();
                if st.vault.is_some() && st.idle_for() >= Duration::from_secs(AUTO_LOCK_SECS) {
                    st.vault = None;
                    st.vault_path = None;
                    st.otp_recovery_key = None;
                    st.pending_otp_setup = None;
                    st.pending_otp_unlock = None;
                    st.pending_otp_delete = None;
                    drop(st);
                    let _ = handle.emit("vault-locked", ());
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::default_vault_path,
            commands::vault_exists,
            commands::create_vault,
            commands::unlock_vault,
            commands::lock_vault,
            commands::is_unlocked,
            commands::list_entries,
            commands::add_entry,
            commands::update_entry,
            commands::delete_entry,
            commands::get_totp,
            commands::change_master_password,
            commands::generate_password,
            commands::estimate_password_strength,
            commands::import_preview,
            commands::import_confirm,
            otp_commands::otp_status,
            otp_commands::otp_begin_setup,
            otp_commands::otp_confirm_setup,
            otp_commands::otp_begin_unlock,
            otp_commands::otp_confirm_unlock,
            otp_commands::otp_disable,
            otp_commands::delete_vault_password,
            otp_commands::delete_vault_otp_begin,
            otp_commands::delete_vault_otp_confirm,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
