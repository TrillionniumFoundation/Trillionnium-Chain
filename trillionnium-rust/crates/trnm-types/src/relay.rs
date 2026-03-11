use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fmt;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayAuthError {
    PayloadHashMismatch,
    BadSig,
    SeqRegression {
        last_seq: u64,
        got_seq: u64,
    },
    SeqGap {
        expected_seq: u64,
        got_seq: u64,
    },
    Replay {
        nonce: String,
    },
    TimeSkew {
        now_ms: u128,
        got_ms: u128,
        max_skew_ms: u128,
    },
    BadVersion {
        expected: String,
        got: String,
    },
    UnsupportedType {
        got: String,
    },
    MissingRequiredField {
        field: &'static str,
    },
}

impl RelayAuthError {
    pub fn stable_code(&self) -> &'static str {
        match self {
            RelayAuthError::BadSig => "BadSig",
            RelayAuthError::Replay { .. } => "Replay",
            RelayAuthError::SeqRegression { .. } => "SeqRegression",
            RelayAuthError::SeqGap { .. } => "SeqGap",
            RelayAuthError::TimeSkew { .. } => "TimeSkew",
            RelayAuthError::PayloadHashMismatch => "PayloadHashMismatch",
            RelayAuthError::BadVersion { .. } => "BadVersion",
            RelayAuthError::UnsupportedType { .. } => "UnsupportedType",
            RelayAuthError::MissingRequiredField { .. } => "MissingRequiredField",
        }
    }
}

impl fmt::Display for RelayAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelayAuthError::PayloadHashMismatch => {
                write!(f, "payload hash mismatch (code={})", self.stable_code())
            }
            RelayAuthError::BadSig => {
                write!(f, "signature verify failed (code={})", self.stable_code())
            }
            RelayAuthError::SeqRegression { last_seq, got_seq } => write!(
                f,
                "seq regression: last_seq={} got_seq={} (code={})",
                last_seq,
                got_seq,
                self.stable_code()
            ),
            RelayAuthError::SeqGap {
                expected_seq,
                got_seq,
            } => write!(
                f,
                "seq gap detected: expected_seq={} got_seq={} (code={})",
                expected_seq,
                got_seq,
                self.stable_code()
            ),
            RelayAuthError::Replay { nonce } => {
                write!(
                    f,
                    "nonce replay detected: {} (code={})",
                    nonce,
                    self.stable_code()
                )
            }
            RelayAuthError::TimeSkew {
                now_ms,
                got_ms,
                max_skew_ms,
            } => write!(
                f,
                "timestamp outside skew window: now_ms={} got_ms={} max_skew_ms={} (code={})",
                now_ms,
                got_ms,
                max_skew_ms,
                self.stable_code()
            ),
            RelayAuthError::BadVersion { expected, got } => write!(
                f,
                "unsupported version: expected={} got={} (code={})",
                expected,
                got,
                self.stable_code()
            ),
            RelayAuthError::UnsupportedType { got } => {
                write!(f, "unsupported type: {} (code={})", got, self.stable_code())
            }
            RelayAuthError::MissingRequiredField { field } => write!(
                f,
                "missing required field: {} (code={})",
                field,
                self.stable_code()
            ),
        }
    }
}

impl std::error::Error for RelayAuthError {}

#[derive(Debug, Clone)]
pub struct RelayAuthVerifier {
    max_skew_ms: u128,
    allow_legacy_v0: bool,
    last_seq: HashMap<(String, String, String, String), u64>,
    seen_nonce: HashSet<(String, String, String, String, String)>,
}

impl RelayAuthVerifier {
    pub fn new(max_skew_ms: u128) -> Self {
        Self {
            max_skew_ms,
            allow_legacy_v0: true,
            last_seq: HashMap::new(),
            seen_nonce: HashSet::new(),
        }
    }

    pub fn strict(max_skew_ms: u128) -> Self {
        Self {
            max_skew_ms,
            allow_legacy_v0: false,
            last_seq: HashMap::new(),
            seen_nonce: HashSet::new(),
        }
    }

    fn verify_envelope_fields(
        &self,
        env: &RelayAuthEnvelope,
        verify_signature: impl Fn(&RelayAuthEnvelope) -> bool,
    ) -> Result<(), RelayAuthError> {
        let is_current = env.version == RelayAuthEnvelope::SPEC_VERSION;
        let is_legacy = env.version == RelayAuthEnvelope::LEGACY_SPEC_VERSION;
        if !(is_current || (self.allow_legacy_v0 && is_legacy)) {
            return Err(RelayAuthError::BadVersion {
                expected: if self.allow_legacy_v0 {
                    format!(
                        "{}|{}",
                        RelayAuthEnvelope::SPEC_VERSION,
                        RelayAuthEnvelope::LEGACY_SPEC_VERSION
                    )
                } else {
                    RelayAuthEnvelope::SPEC_VERSION.to_string()
                },
                got: env.version.clone(),
            });
        }

        if !env.is_supported_type() {
            return Err(RelayAuthError::UnsupportedType {
                got: env.msg_type.clone(),
            });
        }

        if env.requires_routing_fields() {
            if env.chain_id.trim().is_empty() && is_current {
                return Err(RelayAuthError::MissingRequiredField { field: "chain_id" });
            }
            if is_current && env.chain_id.trim() != env.chain_id {
                return Err(RelayAuthError::MissingRequiredField { field: "chain_id" });
            }
            if env.session_id.trim().is_empty() {
                return Err(RelayAuthError::MissingRequiredField {
                    field: "session_id",
                });
            }
            if env.session_id.trim() != env.session_id {
                return Err(RelayAuthError::MissingRequiredField {
                    field: "session_id",
                });
            }
            if env.seq == 0 {
                return Err(RelayAuthError::MissingRequiredField { field: "seq" });
            }
        }

        // BFT auth hardening: signing_message is delimiter encoded; reject
        // delimiter-injection and non-canonical actor identifiers up-front.
        for (field, value) in [
            ("task_id", env.task_id.as_str()),
            ("session_id", env.session_id.as_str()),
            ("msg_type", env.msg_type.as_str()),
            ("from", env.from.as_str()),
            ("to", env.to.as_str()),
            ("nonce", env.nonce.as_str()),
            ("payload_hash", env.payload_hash.as_str()),
        ] {
            if value.trim().is_empty() || value.trim() != value || value.contains('|') {
                return Err(RelayAuthError::MissingRequiredField { field });
            }
        }
        if is_current && env.chain_id.contains('|') {
            return Err(RelayAuthError::MissingRequiredField { field: "chain_id" });
        }

        let computed_payload_hash = RelayAuthEnvelope::payload_hash_hex(&env.payload);
        if computed_payload_hash != env.payload_hash {
            return Err(RelayAuthError::PayloadHashMismatch);
        }

        if !verify_signature(env) {
            return Err(RelayAuthError::BadSig);
        }

        Ok(())
    }

    pub fn verify(
        &mut self,
        env: &RelayAuthEnvelope,
        now_ms: u128,
        verify_signature: impl Fn(&RelayAuthEnvelope) -> bool,
    ) -> Result<(), RelayAuthError> {
        self.verify_envelope_fields(env, verify_signature)?;

        if env.timestamp_ms > now_ms {
            if env.timestamp_ms - now_ms > self.max_skew_ms {
                return Err(RelayAuthError::TimeSkew {
                    now_ms,
                    got_ms: env.timestamp_ms,
                    max_skew_ms: self.max_skew_ms,
                });
            }
        } else if now_ms - env.timestamp_ms > self.max_skew_ms {
            return Err(RelayAuthError::TimeSkew {
                now_ms,
                got_ms: env.timestamp_ms,
                max_skew_ms: self.max_skew_ms,
            });
        }

        let seq_key = (
            env.chain_id.clone(),
            env.task_id.clone(),
            env.session_id.clone(),
            env.from.clone(),
        );
        if let Some(last_seq) = self.last_seq.get(&seq_key) {
            if env.seq <= *last_seq {
                return Err(RelayAuthError::SeqRegression {
                    last_seq: *last_seq,
                    got_seq: env.seq,
                });
            }
            let expected_seq = last_seq.saturating_add(1);
            if env.seq != expected_seq {
                return Err(RelayAuthError::SeqGap {
                    expected_seq,
                    got_seq: env.seq,
                });
            }
        }

        let nonce_key = (
            env.chain_id.clone(),
            env.task_id.clone(),
            env.session_id.clone(),
            env.from.clone(),
            env.nonce.clone(),
        );
        if self.seen_nonce.contains(&nonce_key) {
            return Err(RelayAuthError::Replay {
                nonce: env.nonce.clone(),
            });
        }

        self.last_seq.insert(seq_key, env.seq);
        self.seen_nonce.insert(nonce_key);
        Ok(())
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_envelope_json_roundtrip() {
        let env = RelayEnvelope {
            envelope_id: 1,
            session_id: "sess_1".to_string(),
            sequence: 1,
            route: "relay.echo".to_string(),
            from: "worker-a".to_string(),
            to: Some("worker-b".to_string()),
            payload: b"ping".to_vec(),
            created_at_unix_ms: 1,
        };
        let s = serde_json::to_string(&env).expect("serialize");
        let back: RelayEnvelope = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back, env);
    }

    fn sample_env(seq: u64, nonce: &str, now_ms: u128, key: &str) -> RelayAuthEnvelope {
        let payload = br#"{"hello":"world"}"#.to_vec();
        let payload_hash = RelayAuthEnvelope::payload_hash_hex(&payload);
        let mut env = RelayAuthEnvelope {
            version: RelayAuthEnvelope::SPEC_VERSION.to_string(),
            chain_id: "trnm-mainnet".to_string(),
            task_id: "task-1".to_string(),
            session_id: "sess-1".to_string(),
            seq,
            timestamp_ms: now_ms,
            msg_type: "INPUT_CHUNK".to_string(),
            from: "trnm1from".to_string(),
            to: "trnm1to".to_string(),
            nonce: nonce.to_string(),
            payload,
            payload_hash,
            sig: String::new(),
        };
        env.sig = env.sign_for_test(key);
        env
    }

    #[test]
    fn relay_auth_verify_pass() {
        let key = "sender-key";
        let mut verifier = RelayAuthVerifier::new(120_000);
        let env = sample_env(1, "nonce-1", 1_730_000_000_000, key);

        let ok = verifier.verify(&env, 1_730_000_000_050, |e| e.sign_for_test(key) == e.sig);
        assert!(ok.is_ok());
    }

    #[test]
    fn relay_auth_verify_fail_bad_signature() {
        let key = "sender-key";
        let mut verifier = RelayAuthVerifier::new(120_000);
        let mut env = sample_env(1, "nonce-1", 1_730_000_000_000, key);
        env.sig = "bad-signature".to_string();

        let err = verifier
            .verify(&env, 1_730_000_000_050, |e| e.sign_for_test(key) == e.sig)
            .unwrap_err();
        assert_eq!(err.stable_code(), "BadSig");
    }

    #[test]
    fn relay_auth_verify_replay_nonce_rejected() {
        let key = "sender-key";
        let mut verifier = RelayAuthVerifier::new(120_000);
        let env1 = sample_env(1, "nonce-dup", 1_730_000_000_000, key);
        let env2 = sample_env(2, "nonce-dup", 1_730_000_000_100, key);

        verifier
            .verify(&env1, 1_730_000_000_200, |e| e.sign_for_test(key) == e.sig)
            .expect("first message accepted");

        let err = verifier
            .verify(&env2, 1_730_000_000_250, |e| e.sign_for_test(key) == e.sig)
            .unwrap_err();
        assert_eq!(err.stable_code(), "Replay");
    }

    #[test]
    fn relay_auth_allows_same_nonce_for_different_senders() {
        let key = "sender-key";
        let mut verifier = RelayAuthVerifier::new(120_000);

        let env1 = sample_env(1, "nonce-shared", 1_730_000_000_000, key);

        let mut env2 = sample_env(1, "nonce-shared", 1_730_000_000_050, key);
        env2.from = "trnm1from-peer".to_string();
        env2.sig = env2.sign_for_test(key);

        verifier
            .verify(&env1, 1_730_000_000_100, |e| e.sign_for_test(key) == e.sig)
            .expect("first sender accepted");

        let ok = verifier.verify(&env2, 1_730_000_000_150, |e| e.sign_for_test(key) == e.sig);
        assert!(ok.is_ok());
    }

    #[test]
    fn relay_auth_allows_same_nonce_for_different_task_ids() {
        let key = "sender-key";
        let mut verifier = RelayAuthVerifier::new(120_000);

        let env1 = sample_env(1, "nonce-shared", 1_730_000_000_000, key);

        let mut env2 = sample_env(2, "nonce-shared", 1_730_000_000_050, key);
        env2.task_id = "task-2".to_string();
        env2.sig = env2.sign_for_test(key);

        verifier
            .verify(&env1, 1_730_000_000_100, |e| e.sign_for_test(key) == e.sig)
            .expect("first task accepted");

        let ok = verifier.verify(&env2, 1_730_000_000_150, |e| e.sign_for_test(key) == e.sig);
        assert!(ok.is_ok());
    }

    #[test]
    fn relay_auth_verify_seq_regression_rejected() {
        let key = "sender-key";
        let mut verifier = RelayAuthVerifier::new(120_000);
        let env1 = sample_env(3, "nonce-1", 1_730_000_000_000, key);
        let env2 = sample_env(2, "nonce-2", 1_730_000_000_100, key);

        verifier
            .verify(&env1, 1_730_000_000_200, |e| e.sign_for_test(key) == e.sig)
            .expect("first message accepted");

        let err = verifier
            .verify(&env2, 1_730_000_000_250, |e| e.sign_for_test(key) == e.sig)
            .unwrap_err();
        assert_eq!(err.stable_code(), "SeqRegression");
    }

    #[test]
    fn relay_auth_verify_time_skew_rejected() {
        let key = "sender-key";
        let mut verifier = RelayAuthVerifier::new(120_000);
        let env = sample_env(1, "nonce-1", 1_730_000_000_000, key);

        let err = verifier
            .verify(&env, 1_730_000_200_001, |e| e.sign_for_test(key) == e.sig)
            .unwrap_err();
        assert_eq!(err.stable_code(), "TimeSkew");
    }

    #[test]
    fn relay_auth_verify_bad_version_rejected() {
        let key = "sender-key";
        let mut verifier = RelayAuthVerifier::new(120_000);
        let mut env = sample_env(1, "nonce-1", 1_730_000_000_000, key);
        env.version = "p2p-v9.9".to_string();
        env.sig = env.sign_for_test(key);

        let err = verifier
            .verify(&env, 1_730_000_000_050, |e| e.sign_for_test(key) == e.sig)
            .unwrap_err();
        assert_eq!(err.stable_code(), "BadVersion");
    }

    #[test]
    fn relay_auth_verify_unsupported_type_rejected() {
        let key = "sender-key";
        let mut verifier = RelayAuthVerifier::new(120_000);
        let mut env = sample_env(1, "nonce-1", 1_730_000_000_000, key);
        env.msg_type = "WEIRD_TYPE".to_string();
        env.sig = env.sign_for_test(key);

        let err = verifier
            .verify(&env, 1_730_000_000_050, |e| e.sign_for_test(key) == e.sig)
            .unwrap_err();
        assert_eq!(err.stable_code(), "UnsupportedType");
    }

    #[test]
    fn relay_auth_verify_rejects_noncanonical_chain_id_whitespace() {
        let key = "sender-key";
        let mut verifier = RelayAuthVerifier::new(120_000);
        let mut env = sample_env(1, "nonce-1", 1_730_000_000_000, key);
        env.chain_id = " trnm-mainnet".to_string();
        env.sig = env.sign_for_test(key);

        let err = verifier
            .verify(&env, 1_730_000_000_050, |e| e.sign_for_test(key) == e.sig)
            .unwrap_err();
        assert_eq!(err.stable_code(), "MissingRequiredField");
    }

    #[test]
    fn relay_auth_verify_rejects_noncanonical_session_id_whitespace() {
        let key = "sender-key";
        let mut verifier = RelayAuthVerifier::new(120_000);
        let mut env = sample_env(1, "nonce-1", 1_730_000_000_000, key);
        env.session_id = "sess-1 ".to_string();
        env.sig = env.sign_for_test(key);

        let err = verifier
            .verify(&env, 1_730_000_000_050, |e| e.sign_for_test(key) == e.sig)
            .unwrap_err();
        assert_eq!(err.stable_code(), "MissingRequiredField");
    }

    #[test]
    fn relay_auth_negative_matrix_min12_cases() {
        let key = "sender-key";

        let cases: Vec<(&str, RelayAuthEnvelope, u128, &'static str)> = vec![
            {
                let mut env = sample_env(3, "nonce-ph-1", 1_730_000_000_000, key);
                env.payload = b"tampered".to_vec();
                (
                    "payload_hash_tampered_payload",
                    env,
                    1_730_000_000_050,
                    "PayloadHashMismatch",
                )
            },
            {
                let mut env = sample_env(3, "nonce-ph-2", 1_730_000_000_000, key);
                env.payload_hash = "00".repeat(32);
                env.sig = env.sign_for_test(key);
                (
                    "payload_hash_tampered_header",
                    env,
                    1_730_000_000_050,
                    "PayloadHashMismatch",
                )
            },
            {
                let mut env = sample_env(3, "nonce-sig-1", 1_730_000_000_000, key);
                env.sig = "bad-signature".to_string();
                ("bad_signature_literal", env, 1_730_000_000_050, "BadSig")
            },
            {
                let mut env = sample_env(3, "nonce-sig-2", 1_730_000_000_000, key);
                env.to = "trnm1evil".to_string();
                (
                    "bad_signature_after_mutation",
                    env,
                    1_730_000_000_050,
                    "BadSig",
                )
            },
            {
                let mut env = sample_env(3, "nonce-v-1", 1_730_000_000_000, key);
                env.version = "p2p-v9.9".to_string();
                env.sig = env.sign_for_test(key);
                ("bad_version_1", env, 1_730_000_000_050, "BadVersion")
            },
            {
                let mut env = sample_env(3, "nonce-t-1", 1_730_000_000_000, key);
                env.msg_type = "WEIRD_TYPE".to_string();
                env.sig = env.sign_for_test(key);
                (
                    "unsupported_type",
                    env,
                    1_730_000_000_050,
                    "UnsupportedType",
                )
            },
            {
                let env = sample_env(3, "nonce-old-1", 1_730_000_000_000, key);
                ("time_skew_old_boundary", env, 1_730_000_120_001, "TimeSkew")
            },
            {
                let env = sample_env(3, "nonce-old-2", 1_730_000_000_000, key);
                ("time_skew_old_far", env, 1_730_000_500_000, "TimeSkew")
            },
            {
                let env = sample_env(3, "nonce-new-1", 1_730_000_500_000, key);
                ("time_skew_new_boundary", env, 1_730_000_379_999, "TimeSkew")
            },
            {
                let env = sample_env(3, "nonce-base-2", 1_730_000_000_200, key);
                ("nonce_replay", env, 1_730_000_000_250, "Replay")
            },
            {
                let env = sample_env(2, "nonce-seq-back", 1_730_000_000_000, key);
                ("seq_rollback", env, 1_730_000_000_050, "SeqRegression")
            },
            {
                let env = sample_env(5, "nonce-seq-jump", 1_730_000_000_000, key);
                ("seq_jump_forward", env, 1_730_000_000_050, "SeqGap")
            },
        ];

        assert_eq!(cases.len(), 12);

        for (name, env, now_ms, want_code) in cases {
            let mut verifier = RelayAuthVerifier::new(120_000);
            let baseline1 = sample_env(1, "nonce-base-1", 1_730_000_000_000, key);
            let baseline2 = sample_env(2, "nonce-base-2", 1_730_000_000_100, key);
            verifier
                .verify(&baseline1, 1_730_000_000_050, |e| {
                    e.sign_for_test(key) == e.sig
                })
                .expect("baseline1");
            verifier
                .verify(&baseline2, 1_730_000_000_150, |e| {
                    e.sign_for_test(key) == e.sig
                })
                .expect("baseline2");

            let err = verifier
                .verify(&env, now_ms, |e| e.sign_for_test(key) == e.sig)
                .unwrap_err();
            assert_eq!(err.stable_code(), want_code, "case={name}");
        }
    }

    #[test]
    fn relay_auth_legacy_v0_compat_allowed_by_default() {
        let key = "sender-key";
        let mut verifier = RelayAuthVerifier::new(120_000);
        let mut env = sample_env(1, "nonce-legacy-1", 1_730_000_000_000, key);
        env.version = RelayAuthEnvelope::LEGACY_SPEC_VERSION.to_string();
        env.chain_id.clear();
        env.sig = env.sign_for_test_legacy_v0(key);

        let ok = verifier.verify(&env, 1_730_000_000_050, |e| e.verify_test_sig_compat(key));
        assert!(ok.is_ok());
    }

    #[test]
    fn relay_auth_legacy_v0_rejected_in_strict_mode() {
        let key = "sender-key";
        let mut verifier = RelayAuthVerifier::strict(120_000);
        let mut env = sample_env(1, "nonce-legacy-2", 1_730_000_000_000, key);
        env.version = RelayAuthEnvelope::LEGACY_SPEC_VERSION.to_string();
        env.chain_id.clear();
        env.sig = env.sign_for_test_legacy_v0(key);

        let err = verifier
            .verify(&env, 1_730_000_000_050, |e| e.verify_test_sig_compat(key))
            .unwrap_err();
        assert_eq!(err.stable_code(), "BadVersion");
    }

    #[test]
    fn relay_auth_cross_chain_replay_rejected_by_domain_signature() {
        let key = "sender-key";
        let mut verifier = RelayAuthVerifier::new(120_000);
        let mut env = sample_env(1, "nonce-cross-chain", 1_730_000_000_000, key);
        env.chain_id = "trnm-otherchain".to_string();

        let err = verifier
            .verify(&env, 1_730_000_000_050, |e| e.sign_for_test(key) == e.sig)
            .unwrap_err();
        assert_eq!(err.stable_code(), "BadSig");
    }

    #[test]
    fn relay_auth_missing_required_fields_rejected() {
        let key = "sender-key";
        let mut verifier = RelayAuthVerifier::new(120_000);

        let mut missing_chain = sample_env(1, "nonce-miss-1", 1_730_000_000_000, key);
        missing_chain.chain_id.clear();
        missing_chain.sig = missing_chain.sign_for_test(key);
        let err = verifier
            .verify(&missing_chain, 1_730_000_000_050, |e| {
                e.sign_for_test(key) == e.sig
            })
            .unwrap_err();
        assert_eq!(err.stable_code(), "MissingRequiredField");

        let mut missing_seq = sample_env(0, "nonce-miss-2", 1_730_000_000_000, key);
        missing_seq.sig = missing_seq.sign_for_test(key);
        let err = verifier
            .verify(&missing_seq, 1_730_000_000_050, |e| {
                e.sign_for_test(key) == e.sig
            })
            .unwrap_err();
        assert_eq!(err.stable_code(), "MissingRequiredField");
    }

    #[test]
    fn relay_auth_rejects_delimiter_injection_in_signed_fields() {
        let key = "sender-key";
        let mut verifier = RelayAuthVerifier::new(120_000);
        let mut env = sample_env(1, "nonce|poison", 1_730_000_000_000, key);
        env.sig = env.sign_for_test(key);

        let err = verifier
            .verify(&env, 1_730_000_000_050, |e| e.sign_for_test(key) == e.sig)
            .unwrap_err();
        assert_eq!(err.stable_code(), "MissingRequiredField");
    }

    #[test]
    fn relay_auth_wrong_domain_signature_rejected() {
        let key = "sender-key";
        let mut verifier = RelayAuthVerifier::new(120_000);
        let mut env = sample_env(1, "nonce-domain-1", 1_730_000_000_000, key);
        env.sig = env.sign_for_test_legacy_v0(key);

        let err = verifier
            .verify(&env, 1_730_000_000_050, |e| e.sign_for_test(key) == e.sig)
            .unwrap_err();
        assert_eq!(err.stable_code(), "BadSig");
    }
}
