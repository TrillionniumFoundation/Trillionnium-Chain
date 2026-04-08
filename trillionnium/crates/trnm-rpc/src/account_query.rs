use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccountState {
    pub address: String,
    pub balance: u128,
    pub nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccountBalanceQueryResponse {
    pub address: String,
    pub balance: u128,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccountNonceQueryResponse {
    pub address: String,
    pub nonce: u64,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

    const TRNM_SUFFIX_LEN: usize = 40;
    if hex_part.len() != TRNM_SUFFIX_LEN {
        return Err(AccountQueryError::InvalidAddressFormat(address.to_string()));
    }

    if !hex_part
        .as_bytes()
        .iter()
        .copied()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(AccountQueryError::InvalidAddressFormat(address.to_string()));
    }

    Ok(())
}

pub fn query_account_state(
    accounts: &BTreeMap<String, AccountState>,
    address: &str,
) -> Result<AccountState, AccountQueryError> {
    let normalized_address = address.trim();
    validate_trnm_address(normalized_address)?;
    accounts
        .get(normalized_address)
        .cloned()
        .ok_or_else(|| AccountQueryError::AccountNotFound(normalized_address.to_string()))
}
