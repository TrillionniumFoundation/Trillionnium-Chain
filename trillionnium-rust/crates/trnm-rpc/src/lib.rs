pub mod reliability;

mod relay;
mod transfer;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use trnm_types::{GovProposalStatus, TaskStatus};

pub use relay::*;
pub use transfer::{
    compute_tx_hash, get_tx, submit_tx, GetTxError, GetTxResponse, InMemoryTransferLedger,
    SendTxResponse, SubmitTransferRequest, SubmitTransferResponse, TransferApplyError,
    TxLifecycleRecord, TxStatus,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskQueryResponse {
    pub task_id: u64,
    pub status: TaskStatus,
    pub worker: Option<String>,
    pub bounty: u128,
    pub result_hash_hex: Option<String>,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovProposalQueryResponse {
    pub proposal_id: u64,
    pub title: String,
    pub proposer: String,
    pub status: GovProposalStatus,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovParamQueryResponse {
    pub key: String,
    pub value: String,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventQueryResponse {
    pub event_type: String,
    pub task_id: u64,
    pub from_status: String,
    pub to_status: String,
    pub actor: String,
    pub tx_id: u64,
    pub block_height: u64,
    pub state_root: String,
    pub ts_unix_ms: u128,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenger: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub treasury_delta: Option<i128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenger_delta: Option<i128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond_disposition: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageRequestQueryResponse {
    pub request_id: String,
    pub task_id: u64,
    pub channel: String,
    pub user_id: String,
    pub session_id: String,
    pub text: String,
    pub idempotency_key: String,
    pub status: String,
    pub created_at_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestFullQueryResponse {
    pub request: MessageRequestQueryResponse,
    pub verifier_status: Option<String>,
    pub resolution_code: Option<String>,
    pub result_hash: Option<String>,
    pub commit_tx_hash: Option<String>,
    pub reveal_tx_hash: Option<String>,
    pub events: Vec<EventQueryResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountState {
    pub address: String,
    pub balance: u128,
    pub nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountBalanceQueryResponse {
    pub address: String,
    pub balance: u128,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountNonceQueryResponse {
    pub address: String,
    pub nonce: u64,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FaucetRequestResponse {
    pub ok: bool,
    pub code: String,
    pub message: String,
    pub address: String,
    pub requested_amount: u128,
    pub granted_amount: u128,
    pub balance: Option<u128>,
    pub nonce: Option<u64>,
    pub window_seconds: u64,
    pub next_allowed_unix_ms: u128,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RpcErrorResponse {
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountQueryError {
    InvalidAddressFormat(String),
    AccountNotFound(String),
}

impl AccountQueryError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidAddressFormat(_) => "INVALID_ADDRESS",
            Self::AccountNotFound(_) => "ACCOUNT_NOT_FOUND",
        }
    }

    pub fn message(&self) -> String {
        match self {
            Self::InvalidAddressFormat(addr) => {
                format!("invalid address format: {}", addr)
            }
            Self::AccountNotFound(addr) => format!("account not found: {}", addr),
        }
    }

    pub fn to_rpc_error(&self) -> RpcErrorResponse {
        RpcErrorResponse {
            code: self.code(),
            message: self.message(),
        }
    }
}

impl std::fmt::Display for AccountQueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for AccountQueryError {}

pub fn validate_trnm_address(address: &str) -> Result<(), AccountQueryError> {
    let Some(hex_part) = address.strip_prefix("trnm1") else {
        return Err(AccountQueryError::InvalidAddressFormat(address.to_string()));
    };
    if hex_part.len() != 40 {
        return Err(AccountQueryError::InvalidAddressFormat(address.to_string()));
    }
    if !hex_part
        .chars()
        .all(|c| c.is_ascii_hexdigit() || c.is_ascii_lowercase() || c.is_ascii_digit())
    {
        return Err(AccountQueryError::InvalidAddressFormat(address.to_string()));
    }
    Ok(())
}

pub fn query_account_state(
    accounts: &BTreeMap<String, AccountState>,
    address: &str,
) -> Result<AccountState, AccountQueryError> {
    validate_trnm_address(address)?;
    accounts
        .get(address)
        .cloned()
        .ok_or_else(|| AccountQueryError::AccountNotFound(address.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn rpc_schema_smoke_task_fields_stable() {
        let task = TaskQueryResponse {
            task_id: 1,
            status: TaskStatus::Open,
            worker: None,
            bounty: 100,
            result_hash_hex: None,
            version: 1,
        };
        let v = serde_json::to_value(task).unwrap();
        let obj = v.as_object().unwrap();
        for k in [
            "task_id",
            "status",
            "worker",
            "bounty",
            "result_hash_hex",
            "version",
        ] {
            assert!(obj.contains_key(k), "missing key: {}", k);
        }
    }

    #[test]
    fn rpc_schema_smoke_event_fields_stable() {
        let evt = EventQueryResponse {
            event_type: "commit".into(),
            task_id: 1,
            from_status: "Assigned".into(),
            to_status: "Committed".into(),
            actor: "worker1".into(),
            tx_id: 7,
            block_height: 2,
            state_root: "abc".into(),
            ts_unix_ms: 1,
            signer: None,
            challenger: None,
            tx_hash: None,
            resolution_code: None,
            treasury_delta: None,
            challenger_delta: None,
            bond_disposition: None,
        };
        let v = serde_json::to_value(evt).unwrap();
        assert_eq!(
            v,
            json!({
                "event_type":"commit",
                "task_id":1,
                "from_status":"Assigned",
                "to_status":"Committed",
                "actor":"worker1",
                "tx_id":7,
                "block_height":2,
                "state_root":"abc",
                "ts_unix_ms":1
            })
        );
    }

    #[test]
    fn query_account_state_ok() {
        let address = format!("trnm1{}", "1".repeat(40));
        let mut accounts = BTreeMap::new();
        accounts.insert(
            address.clone(),
            AccountState {
                address: address.clone(),
                balance: 42,
                nonce: 7,
            },
        );

        let got = query_account_state(&accounts, &address).unwrap();
        assert_eq!(got.balance, 42);
        assert_eq!(got.nonce, 7);
    }

    #[test]
    fn query_account_state_address_not_found() {
        let accounts = BTreeMap::new();
        let addr = &format!("trnm1{}", "2".repeat(40));
        let err = query_account_state(&accounts, addr).unwrap_err();
        assert_eq!(err.code(), "ACCOUNT_NOT_FOUND");
    }

    #[test]
    fn query_account_state_invalid_input() {
        let accounts = BTreeMap::new();
        let err = query_account_state(&accounts, "not-an-address").unwrap_err();
        assert_eq!(err.code(), "INVALID_ADDRESS");
    }
}
