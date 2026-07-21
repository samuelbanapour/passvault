use serde::{Deserialize, Serialize};
use tauri::State;
use uuid::Uuid;

use passvault_core::{estimate_strength, generate, CustomField, Entry, GeneratorOptions, Vault};

use crate::state::SharedState;

fn vault_default_path() -> String {
    if let Ok(p) = std::env::var("PASSVAULT_PATH") {
        return p;
    }
    directories::ProjectDirs::from("studio", "SoloAppsStudio", "PassVault")
        .map(|d| d.data_dir().join("vault.pvault").to_string_lossy().into_owned())
        .unwrap_or_else(|| "vault.pvault".to_string())
}

#[derive(Deserialize)]
pub struct EntryInput {
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
    #[serde(default)]
    pub totp_secret: Option<String>,
}

#[derive(Serialize)]
pub struct TotpDto {
    pub code: String,
    pub seconds_remaining: u64,
}

#[derive(Serialize)]
pub struct StrengthDto {
    pub bits: f64,
    pub label: String,
}

fn apply_input(entry: &mut Entry, input: EntryInput) {
    entry.title = input.title;
    entry.username = input.username;
    entry.password = input.password;
    entry.url = input.url;
    entry.notes = input.notes;
    entry.tags = input.tags;
    entry.custom_fields = input.custom_fields;
    entry.totp_secret = input.totp_secret;
}

#[tauri::command]
pub fn default_vault_path() -> String {
    vault_default_path()
}

#[tauri::command]
pub fn vault_exists(path: Option<String>) -> bool {
    std::path::Path::new(&path.unwrap_or_else(vault_default_path)).exists()
}

#[tauri::command]
pub fn create_vault(state: State<SharedState>, path: Option<String>, master_password: String) -> Result<Vec<Entry>, String> {
    let path = path.unwrap_or_else(vault_default_path);
    if let Some(parent) = std::path::Path::new(&path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let vault = Vault::create(&path, &master_password).map_err(|e| e.to_string())?;
    let entries = vault.entries().to_vec();

    let mut st = state.lock().unwrap();
    st.vault_path = Some(path);
    st.vault = Some(vault);
    st.touch();
    Ok(entries)
}

#[tauri::command]
pub fn unlock_vault(state: State<SharedState>, path: Option<String>, master_password: String) -> Result<Vec<Entry>, String> {
    let path = path.unwrap_or_else(vault_default_path);
    let vault = Vault::unlock(&path, &master_password).map_err(|e| e.to_string())?;
    let entries = vault.entries().to_vec();

    let mut st = state.lock().unwrap();
    st.vault_path = Some(path);
    st.vault = Some(vault);
    st.touch();
    Ok(entries)
}

#[tauri::command]
pub fn lock_vault(state: State<SharedState>) {
    let mut st = state.lock().unwrap();
    st.vault = None;
    st.vault_path = None;
    st.otp_recovery_key = None;
    st.pending_otp_setup = None;
    st.pending_otp_unlock = None;
}

#[tauri::command]
pub fn is_unlocked(state: State<SharedState>) -> bool {
    state.lock().unwrap().vault.is_some()
}

#[tauri::command]
pub fn list_entries(state: State<SharedState>) -> Result<Vec<Entry>, String> {
    let mut st = state.lock().unwrap();
    let vault = st.vault.as_ref().ok_or("vault is locked")?;
    let entries = vault.entries().to_vec();
    st.touch();
    Ok(entries)
}

#[tauri::command]
pub fn add_entry(state: State<SharedState>, input: EntryInput) -> Result<Entry, String> {
    let mut st = state.lock().unwrap();
    let vault = st.vault.as_mut().ok_or("vault is locked")?;

    let mut entry = Entry::new(input.title.clone());
    apply_input(&mut entry, input);
    let result = entry.clone();
    vault.add_entry(entry);
    vault.save().map_err(|e| e.to_string())?;
    st.touch();
    Ok(result)
}

#[tauri::command]
pub fn update_entry(state: State<SharedState>, id: String, input: EntryInput) -> Result<Entry, String> {
    let id = Uuid::parse_str(&id).map_err(|e| e.to_string())?;
    let mut st = state.lock().unwrap();
    let vault = st.vault.as_mut().ok_or("vault is locked")?;

    vault.update_entry(id, |e| apply_input(e, input)).map_err(|e| e.to_string())?;
    vault.save().map_err(|e| e.to_string())?;
    let result = vault.find(id).cloned().ok_or("entry vanished")?;
    st.touch();
    Ok(result)
}

#[tauri::command]
pub fn delete_entry(state: State<SharedState>, id: String) -> Result<(), String> {
    let id = Uuid::parse_str(&id).map_err(|e| e.to_string())?;
    let mut st = state.lock().unwrap();
    let vault = st.vault.as_mut().ok_or("vault is locked")?;

    vault.delete_entry(id).map_err(|e| e.to_string())?;
    vault.save().map_err(|e| e.to_string())?;
    st.touch();
    Ok(())
}

#[tauri::command]
pub fn get_totp(state: State<SharedState>, id: String) -> Result<TotpDto, String> {
    let id = Uuid::parse_str(&id).map_err(|e| e.to_string())?;
    let mut st = state.lock().unwrap();
    let vault = st.vault.as_ref().ok_or("vault is locked")?;
    let entry = vault.find(id).ok_or("entry not found")?;
    let secret = entry.totp_secret.as_ref().ok_or("entry has no TOTP secret")?;

    let code = passvault_core::totp_now(secret).map_err(|e| e.to_string())?;
    let seconds_remaining = passvault_core::totp_seconds_remaining(30);
    st.touch();
    Ok(TotpDto { code, seconds_remaining })
}

#[tauri::command]
pub fn change_master_password(state: State<SharedState>, old_password: String, new_password: String) -> Result<(), String> {
    let mut st = state.lock().unwrap();
    let vault = st.vault.as_mut().ok_or("vault is locked")?;
    vault
        .change_master_password(&old_password, &new_password)
        .map_err(|e| e.to_string())?;
    st.touch();
    Ok(())
}

#[tauri::command]
pub fn generate_password(opts: GeneratorOptions) -> Result<String, String> {
    generate(&opts).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn estimate_password_strength(password: String) -> StrengthDto {
    let (bits, label) = estimate_strength(&password);
    StrengthDto {
        bits,
        label: label.as_str().to_string(),
    }
}

#[derive(Serialize)]
pub struct ImportPreviewItem {
    pub title: String,
    pub username: String,
    pub url: String,
}

/// Previews an import without touching the vault — used to show the user
/// what's about to be added (title/username/url only, never the
/// password) before they confirm.
#[tauri::command]
pub fn import_preview(csv_text: String) -> Result<Vec<ImportPreviewItem>, String> {
    let entries = passvault_core::parse_csv(&csv_text).map_err(|e| e.to_string())?;
    Ok(entries
        .into_iter()
        .map(|e| ImportPreviewItem {
            title: e.title,
            username: e.username,
            url: e.url,
        })
        .collect())
}

#[tauri::command]
pub fn import_confirm(state: State<SharedState>, csv_text: String) -> Result<Vec<Entry>, String> {
    let mut st = state.lock().unwrap();
    let vault = st.vault.as_mut().ok_or("vault is locked")?;

    let entries = passvault_core::parse_csv(&csv_text).map_err(|e| e.to_string())?;
    for entry in entries {
        vault.add_entry(entry);
    }
    vault.save().map_err(|e| e.to_string())?;
    let all = vault.entries().to_vec();
    st.touch();
    Ok(all)
}
