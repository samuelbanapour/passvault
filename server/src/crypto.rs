use base64::{engine::general_purpose::STANDARD, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    AeadCore, XChaCha20Poly1305, XNonce,
};

/// Encrypts stored recovery keys at rest so a database-only compromise
/// (e.g. a stolen backup, an SQL injection that only reads rows) doesn't
/// hand over vault keys directly. This does NOT protect against a full
/// server compromise — whoever controls the process controls this key
/// too. That's the honest limit of server-custodied key storage; the
/// local-keychain mode has no equivalent single point of failure.
#[derive(Clone)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    pub fn from_env() -> Self {
        let b64 = std::env::var("SERVER_MASTER_KEY").unwrap_or_else(|_| {
            eprintln!("SERVER_MASTER_KEY is not set.");
            eprintln!("Generate one with: openssl rand -base64 32");
            eprintln!("Then set SERVER_MASTER_KEY to that value before starting the server.");
            std::process::exit(1);
        });
        let bytes = STANDARD.decode(b64.trim()).expect("SERVER_MASTER_KEY must be valid base64");
        let arr: [u8; 32] = bytes.as_slice().try_into().expect("SERVER_MASTER_KEY must decode to exactly 32 bytes");
        MasterKey(arr)
    }

    pub fn encrypt(&self, plaintext: &str) -> (Vec<u8>, Vec<u8>) {
        let cipher = XChaCha20Poly1305::new((&self.0).into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes()).expect("encryption cannot fail here");
        (nonce.to_vec(), ciphertext)
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Option<String> {
        let cipher = XChaCha20Poly1305::new((&self.0).into());
        let nonce = XNonce::from_slice(nonce);
        let plaintext = cipher.decrypt(nonce, ciphertext).ok()?;
        String::from_utf8(plaintext).ok()
    }
}
