use crate::transfer::helpers::compute_tx_hash;
use crate::transfer::status::{TxLifecycleRecord, TxStatus};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use trnm_types::TransferTx;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendTxResponse {
    pub tx_hash: String,
    pub status: TxStatus,
}

pub fn submit_tx(
    txs: &mut BTreeMap<String, TxLifecycleRecord>,
    tx: TransferTx,
    now_unix_ms: u128,
) -> SendTxResponse {
    let tx_hash = compute_tx_hash(&tx);

    if tx.validate_basic().is_err() {
        return SendTxResponse {
            tx_hash,
            status: TxStatus::Fail,
        };
    }

    if !txs.contains_key(&tx_hash) {
        txs.insert(
            tx_hash.clone(),
            TxLifecycleRecord {
                tx_hash: tx_hash.clone(),
                tx,
                status: TxStatus::Pending,
                error: None,
                submitted_at_unix_ms: now_unix_ms,
                updated_at_unix_ms: now_unix_ms,
            },
        );
    }
    SendTxResponse {
        tx_hash,
        status: TxStatus::Pending,
    }
}
