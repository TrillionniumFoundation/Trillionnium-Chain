use serde_json::json;
use trnm_rpc::{
    AccountBalanceQueryResponse, AccountNonceQueryResponse, EventQueryResponse, GetTxResponse,
    RpcErrorResponse, SendTxResponse, TxStatus,
};

#[path = "rpc_contract_v1/account_contract.rs"]
mod account_contract;
#[path = "rpc_contract_v1/error_contract.rs"]
mod error_contract;
#[path = "rpc_contract_v1/event_contract.rs"]
mod event_contract;
#[path = "rpc_contract_v1/tx_contract.rs"]
mod tx_contract;
