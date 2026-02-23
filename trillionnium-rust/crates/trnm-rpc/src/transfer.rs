use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use trnm_types::{TransferTx, TransferTxValidationError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTransferRequest {
    pub tx: TransferTx,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTransferResponse {
    pub accepted: bool,
    pub from_balance: u128,
    pub to_balance: u128,
    pub next_nonce: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferApplyError {
    Basic(TransferTxValidationError),
    NonceRollback { expected: u64, got: u64 },
    InsufficientBalance { balance: u128, needed: u128 },
}

impl std::fmt::Display for TransferApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Basic(e) => write!(f, "{}", e),
            Self::NonceRollback { expected, got } => {
                write!(f, "nonce rollback/replay: expected {}, got {}", expected, got)
            }
            Self::InsufficientBalance { balance, needed } => {
                write!(f, "insufficient balance: balance {}, needed {}", balance, needed)
            }
        }
    }
}

impl std::error::Error for TransferApplyError {}

#[derive(Debug, Default)]
pub struct InMemoryTransferLedger {
    balances: BTreeMap<String, u128>,
    nonces: BTreeMap<String, u64>,
}

impl InMemoryTransferLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_account(&mut self, addr: impl Into<String>, balance: u128, next_nonce: u64) {
        let addr = addr.into();
        self.balances.insert(addr.clone(), balance);
        self.nonces.insert(addr, next_nonce);
    }

    pub fn balance_of(&self, addr: &str) -> u128 {
        self.balances.get(addr).copied().unwrap_or(0)
    }

    pub fn next_nonce_of(&self, addr: &str) -> u64 {
        self.nonces.get(addr).copied().unwrap_or(0)
    }

    pub fn apply_transfer(&mut self, req: SubmitTransferRequest) -> Result<SubmitTransferResponse, TransferApplyError> {
        let tx = req.tx;
        tx.validate_basic().map_err(TransferApplyError::Basic)?;

        let expected_nonce = self.next_nonce_of(&tx.from);
        if tx.nonce != expected_nonce {
            return Err(TransferApplyError::NonceRollback {
                expected: expected_nonce,
                got: tx.nonce,
            });
        }

        let needed = tx.amount.saturating_add(tx.fee);
        let from_balance = self.balance_of(&tx.from);
        if from_balance < needed {
            return Err(TransferApplyError::InsufficientBalance {
                balance: from_balance,
                needed,
            });
        }

        let to_balance = self.balance_of(&tx.to);
        let new_from = from_balance - needed;
        let new_to = to_balance.saturating_add(tx.amount);

        self.balances.insert(tx.from.clone(), new_from);
        self.balances.insert(tx.to.clone(), new_to);
        self.nonces.insert(tx.from.clone(), expected_nonce + 1);

        Ok(SubmitTransferResponse {
            accepted: true,
            from_balance: new_from,
            to_balance: new_to,
            next_nonce: expected_nonce + 1,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx(from: &str, to: &str, amount: u128, fee: u128, nonce: u64, signature: &str) -> SubmitTransferRequest {
        SubmitTransferRequest {
            tx: TransferTx {
                from: from.into(),
                to: to.into(),
                amount,
                fee,
                nonce,
                signature: signature.into(),
            },
        }
    }

    #[test]
    fn apply_transfer_success() {
        let mut ledger = InMemoryTransferLedger::new();
        ledger.set_account("alice", 100, 0);
        ledger.set_account("bob", 5, 0);

        let out = ledger
            .apply_transfer(tx("alice", "bob", 10, 1, 0, "sig:alice:0"))
            .unwrap();

        assert!(out.accepted);
        assert_eq!(ledger.balance_of("alice"), 89);
        assert_eq!(ledger.balance_of("bob"), 15);
        assert_eq!(ledger.next_nonce_of("alice"), 1);
    }

    #[test]
    fn reject_nonce_rollback() {
        let mut ledger = InMemoryTransferLedger::new();
        ledger.set_account("alice", 100, 1);

        let err = ledger
            .apply_transfer(tx("alice", "bob", 10, 1, 0, "sig:alice:0"))
            .unwrap_err();
        assert_eq!(
            err,
            TransferApplyError::NonceRollback {
                expected: 1,
                got: 0
            }
        );
    }

    #[test]
    fn reject_insufficient_balance() {
        let mut ledger = InMemoryTransferLedger::new();
        ledger.set_account("alice", 10, 0);

        let err = ledger
            .apply_transfer(tx("alice", "bob", 10, 1, 0, "sig:alice:0"))
            .unwrap_err();
        assert_eq!(
            err,
            TransferApplyError::InsufficientBalance {
                balance: 10,
                needed: 11
            }
        );
    }

    #[test]
    fn reject_missing_signature() {
        let mut ledger = InMemoryTransferLedger::new();
        ledger.set_account("alice", 100, 0);

        let err = ledger
            .apply_transfer(tx("alice", "bob", 1, 0, 0, ""))
            .unwrap_err();
        assert_eq!(
            err,
            TransferApplyError::Basic(TransferTxValidationError::MissingSignature)
        );
    }

    #[test]
    fn reject_invalid_signature() {
        let mut ledger = InMemoryTransferLedger::new();
        ledger.set_account("alice", 100, 0);

        let err = ledger
            .apply_transfer(tx("alice", "bob", 1, 0, 0, "sig:mallory:0"))
            .unwrap_err();
        assert_eq!(
            err,
            TransferApplyError::Basic(TransferTxValidationError::InvalidSignature)
        );
    }
}
