use std::path::PathBuf;

pub fn default_vault_path() -> PathBuf {
    if let Ok(p) = std::env::var("PASSVAULT_PATH") {
        return PathBuf::from(p);
    }
    directories::ProjectDirs::from("studio", "SoloAppsStudio", "PassVault")
        .map(|d| d.data_dir().join("vault.pvault"))
        .unwrap_or_else(|| PathBuf::from("vault.pvault"))
}
