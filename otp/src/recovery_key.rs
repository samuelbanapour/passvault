use rand::RngCore;

/// A recovery key stands in for the master password when a vault is
/// unlocked via OTP: it's what actually gets fed to `Vault::create` /
/// `Vault::unlock` under the hood. 256 bits of entropy, Base32-encoded
/// (Crockford alphabet — no ambiguous characters) and grouped for
/// readability, in case a user ever needs to write it down as a fallback.
pub fn generate() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let encoded = base32::encode(base32::Alphabet::Crockford, &bytes);

    encoded
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("-")
}
