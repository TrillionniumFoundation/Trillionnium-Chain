use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Phase A envelope auth schema aligned with `agent-user-p2p-communication-min-spec-v0.1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayAuthEnvelope {
    pub version: String,
    #[serde(default)]
    pub chain_id: String,
    pub task_id: String,
    pub session_id: String,
    pub seq: u64,
    pub timestamp_ms: u128,
    pub msg_type: String,
    pub from: String,
    pub to: String,
    pub nonce: String,
    pub payload: Vec<u8>,
    pub payload_hash: String,
    pub sig: String,
}

impl RelayAuthEnvelope {
    pub const SPEC_VERSION: &'static str = "p2p-v0.2";
    pub const LEGACY_SPEC_VERSION: &'static str = "p2p-v0.1";
    pub const SIGNING_DOMAIN_V1: &'static str = "TRNM_P2P_V1";

    pub fn envelope_hash(&self) -> crate::Hash32 {
        crate::relay_auth_envelope_hash(self)
    }

    pub fn payload_hash_hex(payload: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(payload);
        lower_hex(&hasher.finalize())
    }

    pub fn signing_message(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            Self::SIGNING_DOMAIN_V1,
            self.chain_id,
            self.msg_type,
            self.version,
            self.task_id,
            self.session_id,
            self.seq,
            self.timestamp_ms,
            self.from,
            self.to,
            self.nonce,
            self.payload_hash
        )
    }

    pub fn signing_message_legacy_v0(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.version,
            self.task_id,
            self.session_id,
            self.seq,
            self.timestamp_ms,
            self.msg_type,
            self.from,
            self.to,
            self.nonce,
            self.payload_hash
        )
    }

    pub fn is_supported_type(&self) -> bool {
        matches!(
            self.msg_type.as_str(),
            "TASK_ACCEPT"
                | "INPUT_CHUNK"
                | "RESULT_META"
                | "RESULT_POINTER"
                | "ACK"
                | "ERROR"
                | "CLOSE"
        )
    }

    pub fn requires_routing_fields(&self) -> bool {
        matches!(
            self.msg_type.as_str(),
            "TASK_ACCEPT"
                | "INPUT_CHUNK"
                | "RESULT_META"
                | "RESULT_POINTER"
                | "ACK"
                | "ERROR"
                | "CLOSE"
        )
    }

    /// Skeleton signer for local testing and integration bring-up.
    pub fn sign_for_test(&self, key_material: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.signing_message().as_bytes());
        hasher.update(b"|");
        hasher.update(key_material.as_bytes());
        lower_hex(&hasher.finalize())
    }

    pub fn sign_for_test_legacy_v0(&self, key_material: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.signing_message_legacy_v0().as_bytes());
        hasher.update(b"|");
        hasher.update(key_material.as_bytes());
        lower_hex(&hasher.finalize())
    }

    pub fn verify_test_sig_compat(&self, key_material: &str) -> bool {
        self.sign_for_test(key_material) == self.sig
            || (self.version == Self::LEGACY_SPEC_VERSION
                && self.sign_for_test_legacy_v0(key_material) == self.sig)
    }
}

pub(super) fn lower_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}
