use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferTx {
    pub from: String,
    pub to: String,
    pub amount: u128,
    pub fee: u128,
    pub nonce: u64,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferTxValidationError {
    EmptyFrom,
    EmptyTo,
    SameSenderAndRecipient,
    ZeroAmount,
    MissingSignature,
    InvalidSignature,
}

impl std::fmt::Display for TransferTxValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyFrom => write!(f, "from cannot be empty"),
            Self::EmptyTo => write!(f, "to cannot be empty"),
            Self::SameSenderAndRecipient => write!(f, "from and to cannot be the same"),
            Self::ZeroAmount => write!(f, "amount must be > 0"),
            Self::MissingSignature => write!(f, "signature is required"),
            Self::InvalidSignature => write!(f, "signature is invalid"),
        }
    }
}

impl std::error::Error for TransferTxValidationError {}

impl TransferTx {
    pub fn signing_message(&self) -> Vec<u8> {
        format!(
            "trnm-transfer-v1|from={}|to={}|amount={}|fee={}|nonce={}",
            self.from, self.to, self.amount, self.fee, self.nonce
        )
        .into_bytes()
    }

    pub fn derive_address_from_ed25519_pubkey(pubkey: &[u8]) -> String {
        let digest = Sha256::digest(pubkey);
        let addr_hex = hex::encode(&digest[..20]);
        format!("trnm1{}", addr_hex)
    }

    pub fn sign_with_private_key_hex(
        &self,
        private_key_hex: &str,
    ) -> Result<String, TransferTxValidationError> {
        let secret = hex::decode(private_key_hex)
            .map_err(|_| TransferTxValidationError::InvalidSignature)?;
        let secret_bytes: [u8; 32] = secret
            .as_slice()
            .try_into()
            .map_err(|_| TransferTxValidationError::InvalidSignature)?;

        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();
        let sig = signing_key.sign(&self.signing_message());
        Ok(format!(
            "ed25519:{}:{}",
            hex::encode(verifying_key.as_bytes()),
            hex::encode(sig.to_bytes())
        ))
    }

    pub fn validate_basic(&self) -> Result<(), TransferTxValidationError> {
        if self.from.trim().is_empty() {
            return Err(TransferTxValidationError::EmptyFrom);
        }
        if self.to.trim().is_empty() {
            return Err(TransferTxValidationError::EmptyTo);
        }
        if self.from == self.to {
            return Err(TransferTxValidationError::SameSenderAndRecipient);
        }
        if self.amount == 0 {
            return Err(TransferTxValidationError::ZeroAmount);
        }
        if self.signature.trim().is_empty() {
            return Err(TransferTxValidationError::MissingSignature);
        }

        let mut parts = self.signature.split(':');
        let algo = parts
            .next()
            .ok_or(TransferTxValidationError::InvalidSignature)?;
        let pubkey_hex = parts
            .next()
            .ok_or(TransferTxValidationError::InvalidSignature)?;
        let sig_hex = parts
            .next()
            .ok_or(TransferTxValidationError::InvalidSignature)?;
        if parts.next().is_some() || algo != "ed25519" {
            return Err(TransferTxValidationError::InvalidSignature);
        }

        let pubkey =
            hex::decode(pubkey_hex).map_err(|_| TransferTxValidationError::InvalidSignature)?;
        let pubkey_bytes: [u8; 32] = pubkey
            .as_slice()
            .try_into()
            .map_err(|_| TransferTxValidationError::InvalidSignature)?;
        let expected_from = Self::derive_address_from_ed25519_pubkey(&pubkey_bytes);
        if self.from != expected_from {
            return Err(TransferTxValidationError::InvalidSignature);
        }

        let sig_raw =
            hex::decode(sig_hex).map_err(|_| TransferTxValidationError::InvalidSignature)?;
        let sig_bytes: [u8; 64] = sig_raw
            .as_slice()
            .try_into()
            .map_err(|_| TransferTxValidationError::InvalidSignature)?;

        let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|_| TransferTxValidationError::InvalidSignature)?;
        let sig = Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify(&self.signing_message(), &sig)
            .map_err(|_| TransferTxValidationError::InvalidSignature)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE_SK_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn valid_tx() -> TransferTx {
        let seed = [0x11u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let from = TransferTx::derive_address_from_ed25519_pubkey(sk.verifying_key().as_bytes());
        let mut tx = TransferTx {
            from,
            to: "trnm1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            amount: 10,
            fee: 1,
            nonce: 1,
            signature: String::new(),
        };
        tx.signature = tx.sign_with_private_key_hex(ALICE_SK_HEX).unwrap();
        tx
    }

    #[test]
    fn transfer_tx_basic_validate_ok() {
        let tx = valid_tx();
        assert!(tx.validate_basic().is_ok());
    }

    #[test]
    fn transfer_tx_missing_signature_rejected() {
        let mut tx = valid_tx();
        tx.signature = String::new();
        assert_eq!(
            tx.validate_basic().unwrap_err(),
            TransferTxValidationError::MissingSignature
        );
    }

    #[test]
    fn transfer_tx_reject_tampered_signature() {
        let mut tx = valid_tx();
        tx.signature.push('0');
        assert_eq!(
            tx.validate_basic().unwrap_err(),
            TransferTxValidationError::InvalidSignature
        );
    }

    #[test]
    fn transfer_tx_reject_address_mismatch() {
        let mut tx = valid_tx();
        tx.from = "trnm1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
        assert_eq!(
            tx.validate_basic().unwrap_err(),
            TransferTxValidationError::InvalidSignature
        );
    }
}
