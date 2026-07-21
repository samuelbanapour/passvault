use std::fs;
use std::path::{Path, PathBuf};

use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto;
use crate::entry::Entry;
use crate::error::{Result, VaultError};
use crate::kdf::{self, KdfParams, KEY_LEN, SALT_LEN};

const MAGIC: &str = "PASSVAULT";
const FORMAT_VERSION: u32 = 1;

/// On-disk representation. The master password only ever unlocks the DEK
/// (data encryption key) via a key-wrapping scheme, so changing the master
/// password never requires re-encrypting the whole vault body.
#[derive(Serialize, Deserialize)]
struct VaultFile {
    magic: String,
    version: u32,
    kdf: KdfParams,
    #[serde(with = "crate::b64")]
    salt: Vec<u8>,
    #[serde(with = "crate::b64")]
    dek_nonce: Vec<u8>,
    #[serde(with = "crate::b64")]
    wrapped_dek: Vec<u8>,
    #[serde(with = "crate::b64")]
    data_nonce: Vec<u8>,
    #[serde(with = "crate::b64")]
    data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Default)]
struct VaultBody {
    entries: Vec<Entry>,
}

/// An unlocked vault held in memory. The master password itself is never
/// retained past `unlock`/`create`/`change_master_password` returning — only
/// the already-unwrapped data encryption key (`dek`) and the still-wrapped
/// form (`dek_nonce`/`wrapped_dek`) needed to persist it back to disk. This
/// means callers (e.g. a GUI) don't need to keep the master password in
/// memory for the lifetime of a session just to be able to call `save`.
pub struct Vault {
    path: PathBuf,
    dek: Zeroizing<[u8; KEY_LEN]>,
    kdf_params: KdfParams,
    salt: Vec<u8>,
    dek_nonce: Vec<u8>,
    wrapped_dek: Vec<u8>,
    entries: Vec<Entry>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Creates a brand-new, empty vault at `path`, protected by
    /// `master_password`, and writes it to disk.
    pub fn create(path: impl AsRef<Path>, master_password: &str) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            return Err(VaultError::AlreadyExists);
        }

        let mut salt = vec![0u8; SALT_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);

        let mut dek = [0u8; KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut dek);
        let dek = Zeroizing::new(dek);

        let kdf_params = KdfParams::default();
        let kek = kdf::derive_key(master_password, &salt, kdf_params)?;
        let (dek_nonce, wrapped_dek) = crypto::encrypt(&kek, dek.as_ref());

        let vault = Vault {
            path,
            dek,
            kdf_params,
            salt,
            dek_nonce,
            wrapped_dek,
            entries: Vec::new(),
        };
        vault.save()?;
        Ok(vault)
    }

    /// Decrypts and loads an existing vault from disk.
    pub fn unlock(path: impl AsRef<Path>, master_password: &str) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let raw = fs::read_to_string(&path)?;
        let file: VaultFile = serde_json::from_str(&raw).map_err(|_| VaultError::Corrupt)?;

        if file.magic != MAGIC {
            return Err(VaultError::Corrupt);
        }
        if file.version != FORMAT_VERSION {
            return Err(VaultError::UnsupportedVersion(file.version));
        }

        let kek = kdf::derive_key(master_password, &file.salt, file.kdf)?;
        let dek_bytes = crypto::decrypt(&kek, &file.dek_nonce, &file.wrapped_dek)?;
        let mut dek = [0u8; KEY_LEN];
        dek.copy_from_slice(&dek_bytes[..KEY_LEN]);
        let dek = Zeroizing::new(dek);

        let body_bytes = crypto::decrypt(&dek, &file.data_nonce, &file.data)?;
        let body: VaultBody = serde_json::from_slice(&body_bytes).map_err(|_| VaultError::Corrupt)?;

        Ok(Vault {
            path,
            dek,
            kdf_params: file.kdf,
            salt: file.salt,
            dek_nonce: file.dek_nonce,
            wrapped_dek: file.wrapped_dek,
            entries: body.entries,
        })
    }

    /// Re-encrypts the current in-memory entries and (re)writes the vault
    /// file, reusing the already-wrapped DEK. Does not require the master
    /// password — only `change_master_password` does.
    pub fn save(&self) -> Result<()> {
        let body = VaultBody {
            entries: self.entries.clone(),
        };
        let body_bytes = serde_json::to_vec(&body)?;
        let (data_nonce, data) = crypto::encrypt(&self.dek, &body_bytes);

        let file = VaultFile {
            magic: MAGIC.to_string(),
            version: FORMAT_VERSION,
            kdf: self.kdf_params,
            salt: self.salt.clone(),
            dek_nonce: self.dek_nonce.clone(),
            wrapped_dek: self.wrapped_dek.clone(),
            data_nonce,
            data,
        };

        let json = serde_json::to_string_pretty(&file)?;
        let tmp_path = self.path.with_extension("tmp");
        fs::write(&tmp_path, json)?;
        fs::rename(&tmp_path, &self.path)?;
        Ok(())
    }

    /// Verifies `old_password`, then re-derives a fresh key-encryption-key
    /// (with a freshly generated salt) from `new_password` and rewraps the
    /// unchanged DEK under it. Entry data itself is never re-encrypted.
    pub fn change_master_password(&mut self, old_password: &str, new_password: &str) -> Result<()> {
        let old_kek = kdf::derive_key(old_password, &self.salt, self.kdf_params)?;
        crypto::decrypt(&old_kek, &self.dek_nonce, &self.wrapped_dek)?;

        let mut new_salt = vec![0u8; SALT_LEN];
        rand::rngs::OsRng.fill_bytes(&mut new_salt);
        let new_kek = kdf::derive_key(new_password, &new_salt, self.kdf_params)?;
        let (new_dek_nonce, new_wrapped_dek) = crypto::encrypt(&new_kek, self.dek.as_ref());

        self.salt = new_salt;
        self.dek_nonce = new_dek_nonce;
        self.wrapped_dek = new_wrapped_dek;
        self.save()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn find(&self, id: Uuid) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// Case-insensitive lookup by title. Returns all matches since titles
    /// aren't required to be unique.
    pub fn find_by_title<'a>(&'a self, title: &str) -> Vec<&'a Entry> {
        let needle = title.to_lowercase();
        self.entries
            .iter()
            .filter(|e| e.title.to_lowercase().contains(&needle))
            .collect()
    }

    pub fn add_entry(&mut self, entry: Entry) {
        self.entries.push(entry);
    }

    pub fn update_entry(&mut self, id: Uuid, f: impl FnOnce(&mut Entry)) -> Result<()> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or(VaultError::EntryNotFound)?;
        f(entry);
        entry.touch();
        Ok(())
    }

    pub fn delete_entry(&mut self, id: Uuid) -> Result<Entry> {
        let idx = self
            .entries
            .iter()
            .position(|e| e.id == id)
            .ok_or(VaultError::EntryNotFound)?;
        Ok(self.entries.remove(idx))
    }
}
