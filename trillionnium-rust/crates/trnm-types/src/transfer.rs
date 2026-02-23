use serde::{Deserialize, Serialize};

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
    pub fn expected_signature(&self) -> String {
        format!("sig:{}:{}", self.from, self.nonce)
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
        if self.signature != self.expected_signature() {
            return Err(TransferTxValidationError::InvalidSignature);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_tx() -> TransferTx {
        TransferTx {
            from: "alice".into(),
            to: "bob".into(),
            amount: 10,
            fee: 1,
            nonce: 1,
            signature: "sig:alice:1".into(),
        }
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
}
