use crate::transfer::validation::TransferApplyError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use trnm_types::TransferTx;

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

#[derive(Debug, Default)]
pub struct InMemoryTransferLedger {
    pub(crate) balances: BTreeMap<String, u128>,
    pub(crate) nonces: BTreeMap<String, u64>,
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

    pub fn apply_transfer(
        &mut self,
        req: SubmitTransferRequest,
    ) -> Result<SubmitTransferResponse, TransferApplyError> {
        crate::transfer::validation::apply_transfer(self, req)
    }
}

pub fn compute_tx_hash(tx: &TransferTx) -> String {
    let mut h = Sha256::new();
    h.update(tx.from.as_bytes());
    h.update([0]);
    h.update(tx.to.as_bytes());
    h.update([0]);
    h.update(tx.amount.to_le_bytes());
    h.update(tx.fee.to_le_bytes());
    h.update(tx.nonce.to_le_bytes());
    h.update(tx.signature.as_bytes());
    format!("0x{}", hex::encode(h.finalize()))
}
