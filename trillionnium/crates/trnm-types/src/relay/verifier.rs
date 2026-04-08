use std::collections::{HashMap, HashSet};
use std::fmt;

use super::auth_envelope::RelayAuthEnvelope;

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
