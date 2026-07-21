use serde::{Deserialize, Serialize};
use tauri::State;

use passvault_core::{Entry, Vault};
use passvault_otp::{mask_contact, KeyCustody};

use crate::commands::default_vault_path;
use crate::state::SharedState;

#[derive(Serialize)]
pub struct OtpStatusDto {
    configured: bool,
    contact_masked: Option<String>,
    custody: Option<String>,
}

#[tauri::command]
pub fn otp_status(path: Option<String>) -> Result<OtpStatusDto, String> {
    let path = path.unwrap_or_else(default_vault_path);
    match passvault_otp::config_for(std::path::Path::new(&path)).map_err(|e| e.to_string())? {
        None => Ok(OtpStatusDto {
            configured: false,
            contact_masked: None,
            custody: None,
        }),
        Some(cfg) => Ok(OtpStatusDto {
            configured: true,
            contact_masked: Some(mask_contact(&cfg.contact)),
            custody: Some(
                match cfg.custody {
                    KeyCustody::Local => "local",
                    KeyCustody::Server => "server",
                }
                .to_string(),
            ),
        }),
    }
}

// ---------- setting up OTP login for a brand-new vault ----------

#[derive(Deserialize)]
pub struct BeginOtpSetupArgs {
    path: Option<String>,
    contact: String,
    portable: bool,
    server_url: Option<String>,
}

#[tauri::command]
pub fn otp_begin_setup(state: State<SharedState>, args: BeginOtpSetupArgs) -> Result<String, String> {
    let path = args.path.unwrap_or_else(default_vault_path);
    if std::path::Path::new(&path).exists() {
        return Err("a vault already exists at this location".into());
    }
    let custody = if args.portable { KeyCustody::Server } else { KeyCustody::Local };
    if args.portable && args.server_url.is_none() {
        return Err("portable OTP login requires a key-custody server URL".into());
    }

    let pending = passvault_otp::begin_setup(args.contact.clone(), custody, args.server_url).map_err(|e| e.to_string())?;
    let masked = mask_contact(&args.contact);

    let mut st = state.lock().unwrap();
    st.pending_otp_setup = Some((path, pending));
    Ok(masked)
}

#[tauri::command]
pub fn otp_confirm_setup(state: State<SharedState>, code: String) -> Result<Vec<Entry>, String> {
    let mut st = state.lock().unwrap();
    let (path, pending) = st.pending_otp_setup.take().ok_or("no OTP setup is in progress")?;
    let recovery_key = pending.recovery_key.clone();
    if let Some(parent) = std::path::Path::new(&path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    pending.confirm(std::path::Path::new(&path), &code).map_err(|e| e.to_string())?;
    let vault = Vault::create(&path, &recovery_key).map_err(|e| e.to_string())?;
    let entries = vault.entries().to_vec();

    st.vault_path = Some(path);
    st.vault = Some(vault);
    st.otp_recovery_key = Some(recovery_key);
    st.touch();
    Ok(entries)
}

// ---------- unlocking an existing OTP-configured vault ----------

#[derive(Serialize)]
pub struct OtpUnlockInfoDto {
    contact_masked: String,
}

#[tauri::command]
pub fn otp_begin_unlock(state: State<SharedState>, path: Option<String>) -> Result<OtpUnlockInfoDto, String> {
    let path = path.unwrap_or_else(default_vault_path);
    let pending = passvault_otp::begin_unlock(std::path::Path::new(&path)).map_err(|e| e.to_string())?;
    let info = OtpUnlockInfoDto {
        contact_masked: mask_contact(pending.contact()),
    };

    let mut st = state.lock().unwrap();
    st.pending_otp_unlock = Some((path, pending));
    Ok(info)
}

#[tauri::command]
pub fn otp_confirm_unlock(state: State<SharedState>, code: String) -> Result<Vec<Entry>, String> {
    let mut st = state.lock().unwrap();
    let (path, pending) = st.pending_otp_unlock.take().ok_or("no OTP unlock is in progress")?;
    let recovery_key = pending.confirm(&code).map_err(|e| e.to_string())?;
    let vault = Vault::unlock(&path, &recovery_key).map_err(|e| e.to_string())?;
    let entries = vault.entries().to_vec();

    st.vault_path = Some(path);
    st.vault = Some(vault);
    st.otp_recovery_key = Some(recovery_key);
    st.touch();
    Ok(entries)
}

// ---------- turning OTP login back off ----------

#[tauri::command]
pub fn otp_disable(state: State<SharedState>, new_master_password: String) -> Result<(), String> {
    let mut st = state.lock().unwrap();
    let recovery_key = st.otp_recovery_key.clone().ok_or("this vault wasn't unlocked via OTP")?;
    let path = st.vault_path.clone().ok_or("vault is locked")?;
    let vault = st.vault.as_mut().ok_or("vault is locked")?;

    vault
        .change_master_password(&recovery_key, &new_master_password)
        .map_err(|e| e.to_string())?;
    passvault_otp::disable(std::path::Path::new(&path)).map_err(|e| e.to_string())?;
    st.otp_recovery_key = None;
    st.touch();
    Ok(())
}

// ---------- permanently deleting the vault ----------

fn wipe_session(st: &mut crate::state::AppState) {
    st.vault = None;
    st.vault_path = None;
    st.otp_recovery_key = None;
    st.pending_otp_setup = None;
    st.pending_otp_unlock = None;
    st.pending_otp_delete = None;
}

/// For master-password vaults: re-verifies the password (fresh, not just
/// relying on the vault already being open this session) before deleting.
#[tauri::command]
pub fn delete_vault_password(state: State<SharedState>, password: String) -> Result<(), String> {
    let mut st = state.lock().unwrap();
    let path = st.vault_path.clone().ok_or("vault is locked")?;
    Vault::unlock(&path, &password).map_err(|_| "incorrect master password — vault was not deleted".to_string())?;

    std::fs::remove_file(&path).map_err(|e| e.to_string())?;
    wipe_session(&mut st);
    Ok(())
}

#[tauri::command]
pub fn delete_vault_otp_begin(state: State<SharedState>) -> Result<OtpUnlockInfoDto, String> {
    let mut st = state.lock().unwrap();
    let path = st.vault_path.clone().ok_or("vault is locked")?;
    let pending = passvault_otp::begin_unlock(std::path::Path::new(&path)).map_err(|e| e.to_string())?;
    let info = OtpUnlockInfoDto {
        contact_masked: mask_contact(pending.contact()),
    };
    st.pending_otp_delete = Some((path, pending));
    Ok(info)
}

#[tauri::command]
pub fn delete_vault_otp_confirm(state: State<SharedState>, code: String) -> Result<(), String> {
    let mut st = state.lock().unwrap();
    let (path, pending) = st.pending_otp_delete.take().ok_or("no deletion is in progress")?;
    pending
        .confirm_and_delete(&code)
        .map_err(|e| format!("OTP verification failed — vault was not deleted: {e}"))?;
    passvault_otp::disable(std::path::Path::new(&path)).map_err(|e| e.to_string())?;
    std::fs::remove_file(&path).map_err(|e| e.to_string())?;
    wipe_session(&mut st);
    Ok(())
}
