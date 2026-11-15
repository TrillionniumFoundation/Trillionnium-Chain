//! Opaque local Ed25519 signing ownership for the existing development CLI.
//! This is legacy key custody hardening, not a PQ algorithm or activation path.
use ed25519_dalek::{Signer, SigningKey};
use zeroize::Zeroizing;

/// Retains a zeroizing signing key, not the input hex string. There is no
/// private-key export, Display, Debug or serialization implementation.
///
/// ```compile_fail
/// use trnm_crypto_primitives::owned_ed25519::OwnedEd25519Key;
/// let key = OwnedEd25519Key::from_canonical_hex(&"11".repeat(32)).unwrap();
/// println!("{key:?}");
/// ```
#[derive(Clone)]
pub struct OwnedEd25519Key {
    key: SigningKey,
}
impl OwnedEd25519Key {
    pub fn from_canonical_hex(secret: &str) -> Result<Self, &'static str> {
        if secret.len() != 64 {
            return Err("AUTH_KEY_LENGTH");
        }
        if !secret
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("AUTH_KEY_CANONICAL");
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(secret, seed.as_mut()).map_err(|_| "AUTH_KEY_ENCODING")?;
        Ok(Self {
            key: SigningKey::from_bytes(&seed),
        })
    }
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.key.verifying_key().to_bytes())
    }
    pub fn sign_hex(&self, message: &[u8]) -> String {
        hex::encode(self.key.sign(message).to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_and_signature_only_match_existing_strict_verifier() {
        let key = OwnedEd25519Key::from_canonical_hex(&"2a".repeat(32)).unwrap();
        let message = b"owned legacy signer is not a migration permission";
        crate::verify_hex_strict(&key.public_key_hex(), message, &key.sign_hex(message)).unwrap();
        assert!(crate::verify_hex_strict(
            &key.public_key_hex(),
            b"changed",
            &key.sign_hex(message)
        )
        .is_err());
        assert!(OwnedEd25519Key::from_canonical_hex(&"2A".repeat(32)).is_err());
        assert!(OwnedEd25519Key::from_canonical_hex(&"z".repeat(64)).is_err());
    }
}
