use keyring::Entry;

use crate::error::Result;

const SERVICE: &str = "studio.soloapps.passvault.recovery-key";

/// Stores/retrieves a vault's recovery key in the OS-native credential
/// store (macOS Keychain, Windows Credential Manager, Linux Secret
/// Service via libsecret). `account_id` should be unique per vault —
/// callers use a random ID from the vault's OTP sidecar file, not the
/// vault's file path (paths move, this doesn't need to).
pub fn store(account_id: &str, recovery_key: &str) -> Result<()> {
    let entry = Entry::new(SERVICE, account_id)?;
    entry.set_password(recovery_key)?;
    Ok(())
}

pub fn load(account_id: &str) -> Result<String> {
    let entry = Entry::new(SERVICE, account_id)?;
    Ok(entry.get_password()?)
}

pub fn delete(account_id: &str) -> Result<()> {
    let entry = Entry::new(SERVICE, account_id)?;
    entry.delete_credential()?;
    Ok(())
}
