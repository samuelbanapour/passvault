use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng as AeadOsRng},
    AeadCore, XChaCha20Poly1305, XNonce,
};
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};

pub const NONCE_LEN: usize = 24;

/// Encrypts `plaintext` under `key`, returning a freshly generated random
/// nonce alongside the ciphertext (which includes the Poly1305 auth tag).
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut AeadOsRng);
    // XChaCha20Poly1305 with a random 24-byte nonce is safe to encrypt under
    // the same key an effectively unlimited number of times.
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .expect("encryption cannot fail for in-memory buffers");
    (nonce.to_vec(), ciphertext)
}

pub fn decrypt(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if nonce.len() != NONCE_LEN {
        return Err(VaultError::Corrupt);
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| VaultError::WrongPassword)?;
    Ok(Zeroizing::new(plaintext))
}
