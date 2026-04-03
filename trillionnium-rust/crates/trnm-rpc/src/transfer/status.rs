use crate::transfer::helpers::{InMemoryTransferLedger, SubmitTransferRequest};
use crate::transfer::validation::TransferApplyError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use trnm_types::TransferTx;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TxStatus {
    Pending,
    Committed,
    #[serde(alias = "failed", alias = "error")]
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetTxResponse {
    pub tx_hash: String,
    pub status: TxStatus,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GetTxError {
    NotFound(String),
}

impl std::fmt::Display for GetTxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(h) => write!(f, "tx not found: {}", h),
        }
    }
}

impl std::error::Error for GetTxError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxLifecycleRecord {
    pub tx_hash: String,
    pub tx: TransferTx,
    pub status: TxStatus,
    pub error: Option<String>,
    pub submitted_at_unix_ms: u128,
    pub updated_at_unix_ms: u128,
}

pub fn get_tx(
    txs: &mut BTreeMap<String, TxLifecycleRecord>,
    ledger: &mut InMemoryTransferLedger,
    tx_hash: &str,
    now_unix_ms: u128,
) -> Result<GetTxResponse, GetTxError> {
    let Some(rec) = txs.get_mut(tx_hash) else {
        return Err(GetTxError::NotFound(tx_hash.to_string()));
    };

    if rec.status == TxStatus::Pending {
        let req = SubmitTransferRequest { tx: rec.tx.clone() };
        match ledger.apply_transfer(req) {
            Ok(_) => {
                rec.status = TxStatus::Committed;
                rec.error = None;
                rec.updated_at_unix_ms = now_unix_ms;
            }
            Err(err) => {
                rec.status = TxStatus::Fail;
                rec.error = Some(render_apply_error(err));
                rec.updated_at_unix_ms = now_unix_ms;
            }
        }
    }

    Ok(GetTxResponse {
        tx_hash: rec.tx_hash.clone(),
        status: rec.status.clone(),
        error: rec.error.clone(),
    })
}

fn render_apply_error(err: TransferApplyError) -> String {
    err.to_string()
}
