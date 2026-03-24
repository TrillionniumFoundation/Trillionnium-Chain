use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelaySessionStatus {
    Open,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayEnvelope {
    pub envelope_id: u64,
    pub session_id: String,
    pub sequence: u64,
    pub route: String,
    pub from: String,
    pub to: Option<String>,
    pub payload: Vec<u8>,
    pub created_at_unix_ms: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelaySession {
    pub session_id: String,
    pub status: RelaySessionStatus,
    pub created_at_unix_ms: u128,
    pub closed_at_unix_ms: Option<u128>,
}
