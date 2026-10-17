use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;

/// A relay verifier only needs replay state for envelopes that can still pass
/// the timestamp gate. Bound the retained state so an unauthenticated peer
/// cannot grow the verifier indefinitely by rotating task/session identifiers.
pub const MAX_RELAY_AUTH_CONTEXTS: usize = 65_536;
/// Replay keys retain several envelope identifiers. Reject oversized values
/// before signature work or key insertion so a single authenticated-looking
/// envelope cannot amplify memory through cloned map keys.
pub const MAX_RELAY_AUTH_FIELD_BYTES: usize = 256;
/// Keep relay authentication work proportional to the bounded P2P frame
/// contract. This check runs before hashing the payload or invoking the
/// caller-provided signature verifier.
pub const MAX_RELAY_AUTH_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;
/// Signatures are currently represented as text. Leave room for future
/// encodings while preventing an untrusted envelope from forcing a large
/// allocation or expensive signature-parser work.
pub const MAX_RELAY_AUTH_SIGNATURE_BYTES: usize = 512;
/// Full replay-state expiry sweeps are amortized across valid envelopes. A
/// targeted key is still checked on every request, while unrelated stale
/// entries are reclaimed at this bounded interval or when the interval's
/// capacity check runs.
const RELAY_AUTH_GC_INTERVAL_CALLS: u64 = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelaySessionStatus {
    Open,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayEnvelope {
    pub envelope_id: u64,
    #[serde(deserialize_with = "deserialize_bounded_relay_field")]
    pub session_id: String,
    pub sequence: u64,
    #[serde(deserialize_with = "deserialize_bounded_relay_field")]
    pub route: String,
    #[serde(deserialize_with = "deserialize_bounded_relay_field")]
    pub from: String,
    #[serde(deserialize_with = "deserialize_bounded_relay_optional_field")]
    pub to: Option<String>,
    #[serde(deserialize_with = "deserialize_bounded_relay_payload")]
    pub payload: Vec<u8>,
    pub created_at_unix_ms: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelaySession {
    #[serde(deserialize_with = "deserialize_bounded_relay_field")]
    pub session_id: String,
    pub status: RelaySessionStatus,
    pub created_at_unix_ms: u128,
    pub closed_at_unix_ms: Option<u128>,
}

/// Phase A envelope auth schema aligned with `agent-user-p2p-communication-min-spec-v0.1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayAuthEnvelope {
    #[serde(deserialize_with = "deserialize_bounded_relay_field")]
    pub version: String,
    #[serde(default, deserialize_with = "deserialize_bounded_relay_field")]
    pub chain_id: String,
    #[serde(deserialize_with = "deserialize_bounded_relay_field")]
    pub task_id: String,
    #[serde(deserialize_with = "deserialize_bounded_relay_field")]
    pub session_id: String,
    pub seq: u64,
    pub timestamp_ms: u128,
    #[serde(deserialize_with = "deserialize_bounded_relay_field")]
    pub msg_type: String,
    #[serde(deserialize_with = "deserialize_bounded_relay_field")]
    pub from: String,
    #[serde(deserialize_with = "deserialize_bounded_relay_field")]
    pub to: String,
    #[serde(deserialize_with = "deserialize_bounded_relay_field")]
    pub nonce: String,
    #[serde(deserialize_with = "deserialize_bounded_relay_payload")]
    pub payload: Vec<u8>,
    #[serde(deserialize_with = "deserialize_bounded_relay_field")]
    pub payload_hash: String,
    #[serde(deserialize_with = "deserialize_bounded_relay_signature")]
    pub sig: String,
}

fn deserialize_bounded_relay_field<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.len() > MAX_RELAY_AUTH_FIELD_BYTES {
        return Err(serde::de::Error::custom("relay auth field exceeds bound"));
    }
    Ok(value)
}

fn deserialize_bounded_relay_signature<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.len() > MAX_RELAY_AUTH_SIGNATURE_BYTES {
        return Err(serde::de::Error::custom(
            "relay auth signature exceeds bound",
        ));
    }
    Ok(value)
}

fn deserialize_bounded_relay_optional_field<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)?.map_or(Ok(None), |value| {
        if value.len() > MAX_RELAY_AUTH_FIELD_BYTES {
            Err(serde::de::Error::custom(
                "relay auth field exceeds bound",
            ))
        } else {
            Ok(Some(value))
        }
    })
}

fn deserialize_bounded_relay_payload<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Vec::<u8>::deserialize(deserializer)?;
    if value.len() > MAX_RELAY_AUTH_PAYLOAD_BYTES {
        return Err(serde::de::Error::custom("relay auth payload exceeds bound"));
    }
    Ok(value)
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
    ResourceLimit,
    ChainIdMismatch {
        expected: String,
        got: String,
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
            RelayAuthError::ResourceLimit => "ResourceLimit",
            RelayAuthError::ChainIdMismatch { .. } => "ChainIdMismatch",
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
            RelayAuthError::ResourceLimit => {
                write!(
                    f,
                    "relay auth replay state limit reached (code={})",
                    self.stable_code()
                )
            }
            RelayAuthError::ChainIdMismatch { expected, got } => write!(
                f,
                "relay auth chain mismatch: expected={} got={} (code={})",
                expected,
                got,
                self.stable_code()
            ),
        }
    }
}

impl std::error::Error for RelayAuthError {}

#[derive(Debug, Clone)]
pub struct RelayAuthVerifier {
    max_skew_ms: u128,
    /// Optional chain binding for deployments that serve one network.  The
    /// original constructors remain source-compatible and leave this unset;
    /// callers should use [`Self::with_chain_id`] or
    /// [`Self::strict_for_chain`] at a network boundary so a signed envelope
    /// from another chain cannot be replayed unchanged.
    expected_chain_id: Option<String>,
    last_seq: HashMap<(String, String, String, String), (u64, u128)>,
    seen_nonce: HashMap<(String, String, String, String, String), u128>,
    gc_tick: u64,
    last_gc_tick: u64,
}

impl RelayAuthVerifier {
    pub fn new(max_skew_ms: u128) -> Self {
        Self {
            max_skew_ms,
            expected_chain_id: None,
            last_seq: HashMap::new(),
            seen_nonce: HashMap::new(),
            gc_tick: 0,
            last_gc_tick: 0,
        }
    }

    /// Construct a verifier with the same fail-closed policy as [`Self::new`].
    ///
    /// The v0 envelope signing domain does not include `chain_id`, so accepting
    /// it would allow a valid signature from one chain to be replayed on every
    /// other chain.  Keep this constructor as an explicit compatibility alias
    /// for callers that previously selected strict mode.
    pub fn strict(max_skew_ms: u128) -> Self {
        Self::new(max_skew_ms)
    }

    /// Bind this verifier to one chain while preserving the builder-style
    /// constructor used by existing callers.  The expected value is checked
    /// before payload hashing or signature verification.
    pub fn with_chain_id(mut self, chain_id: impl Into<String>) -> Self {
        self.expected_chain_id = Some(chain_id.into());
        self
    }

    /// Construct a strict verifier that rejects legacy envelopes and binds
    /// every accepted envelope to the supplied chain identifier.
    pub fn strict_for_chain(max_skew_ms: u128, chain_id: impl Into<String>) -> Self {
        Self::strict(max_skew_ms).with_chain_id(chain_id)
    }

    /// Return the configured chain binding, if one was supplied.
    pub fn expected_chain_id(&self) -> Option<&str> {
        self.expected_chain_id.as_deref()
    }

    fn maybe_reap_expired(&mut self, cutoff: u128) {
        self.gc_tick = self.gc_tick.wrapping_add(1);
        let due = self.last_gc_tick == 0
            || self.gc_tick.wrapping_sub(self.last_gc_tick) >= RELAY_AUTH_GC_INTERVAL_CALLS;
        if !due {
            return;
        }
        self.last_seq.retain(|_, (_, seen_at)| *seen_at >= cutoff);
        self.seen_nonce.retain(|_, seen_at| *seen_at >= cutoff);
        self.last_gc_tick = self.gc_tick;
    }

    fn verify_envelope_fields(
        &self,
        env: &RelayAuthEnvelope,
        verify_signature: impl Fn(&RelayAuthEnvelope) -> bool,
    ) -> Result<(), RelayAuthError> {
        // Bound attacker-controlled strings before constructing error values or
        // invoking any caller-provided verification callback. Serde callers may
        // otherwise supply multi-megabyte version/type fields that are cloned
        // into diagnostics before the generic field checks below.
        for (field, value) in [("version", env.version.as_str()), ("msg_type", env.msg_type.as_str())] {
            if value.len() > MAX_RELAY_AUTH_FIELD_BYTES {
                return Err(RelayAuthError::MissingRequiredField { field });
            }
        }

        let is_current = env.version == RelayAuthEnvelope::SPEC_VERSION;
        // Never admit v0 here. Its signing domain predates chain binding and
        // cannot distinguish an envelope for this chain from a replay on a
        // different chain. The verifier must reject it before invoking a
        // caller-provided signature callback.
        if !is_current {
            return Err(RelayAuthError::BadVersion {
                expected: RelayAuthEnvelope::SPEC_VERSION.to_string(),
                got: env.version.clone(),
            });
        }

        // Chain binding is an endpoint policy, not something inferred from
        // the first packet. Without it, a valid signed envelope for chain A
        // can be replayed unchanged to a verifier serving chain B because the
        // signature callback authenticates the envelope's own chain_id.
        if let Some(expected) = &self.expected_chain_id {
            if env.chain_id != *expected {
                return Err(RelayAuthError::ChainIdMismatch {
                    expected: expected.clone(),
                    got: env.chain_id.clone(),
                });
            }
        }

        if !env.is_supported_type() {
            return Err(RelayAuthError::UnsupportedType {
                got: env.msg_type.clone(),
            });
        }

        if env.requires_routing_fields() {
            if env.chain_id.trim().is_empty() {
                return Err(RelayAuthError::MissingRequiredField { field: "chain_id" });
            }
            if env.chain_id.trim() != env.chain_id {
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
        if env.chain_id.len() > MAX_RELAY_AUTH_FIELD_BYTES {
            return Err(RelayAuthError::MissingRequiredField { field: "chain_id" });
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
            if value.len() > MAX_RELAY_AUTH_FIELD_BYTES
                || value.trim().is_empty()
                || value.trim() != value
                || value.contains('|')
            {
                return Err(RelayAuthError::MissingRequiredField { field });
            }
        }
        if env.chain_id.contains('|') {
            return Err(RelayAuthError::MissingRequiredField { field: "chain_id" });
        }

        // Enforce wire-size bounds before hashing or signature work. The
        // transport frame has a finite budget, but callers may construct an
        // envelope directly (or decode it before reaching this verifier), so
        // keep the admission check here as the final fail-closed boundary.
        if env.payload.len() > MAX_RELAY_AUTH_PAYLOAD_BYTES {
            return Err(RelayAuthError::MissingRequiredField { field: "payload" });
        }
        if env.sig.len() > MAX_RELAY_AUTH_SIGNATURE_BYTES {
            return Err(RelayAuthError::MissingRequiredField { field: "sig" });
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

        // Entries older than the admissible timestamp window can no longer be
        // used for a successful replay. Full-map expiry sweeps are amortized;
        // the current sequence/nonce keys are checked below on every request,
        // and unrelated entries are reclaimed at the bounded interval before
        // enforcing the memory guard.
        let cutoff = now_ms.saturating_sub(self.max_skew_ms);
        self.maybe_reap_expired(cutoff);

        let seq_key = (
            env.chain_id.clone(),
            env.task_id.clone(),
            env.session_id.clone(),
            env.from.clone(),
        );
        if self
            .last_seq
            .get(&seq_key)
            .is_some_and(|(_, seen_at)| *seen_at < cutoff)
        {
            self.last_seq.remove(&seq_key);
        }
        if let Some((last_seq, _)) = self.last_seq.get(&seq_key) {
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
        if self
            .seen_nonce
            .get(&nonce_key)
            .is_some_and(|seen_at| *seen_at < cutoff)
        {
            self.seen_nonce.remove(&nonce_key);
        }
        if self.seen_nonce.contains_key(&nonce_key) {
            return Err(RelayAuthError::Replay {
                nonce: env.nonce.clone(),
            });
        }

        if !self.last_seq.contains_key(&seq_key) && self.last_seq.len() >= MAX_RELAY_AUTH_CONTEXTS {
            return Err(RelayAuthError::ResourceLimit);
        }
        if self.seen_nonce.len() >= MAX_RELAY_AUTH_CONTEXTS {
            return Err(RelayAuthError::ResourceLimit);
        }

        self.last_seq.insert(seq_key, (env.seq, env.timestamp_ms));
        self.seen_nonce.insert(nonce_key, env.timestamp_ms);
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
    fn relay_auth_chain_binding_rejects_unchanged_cross_chain_replay() {
        let key = "sender-key";
        let env = sample_env(1, "nonce-chain-bound", 1_730_000_000_000, key);

        let mut matching = RelayAuthVerifier::new(120_000).with_chain_id("trnm-mainnet");
        matching
            .verify(&env, 1_730_000_000_050, |e| e.sign_for_test(key) == e.sig)
            .expect("bound chain accepts matching envelope");

        // The exact bytes signed for mainnet must not be accepted by a
        // verifier serving another chain. No mutation or re-signing occurs.
        let mut other = RelayAuthVerifier::new(120_000).with_chain_id("trnm-otherchain");
        let signature_called = std::cell::Cell::new(false);
        let err = other
            .verify(&env, 1_730_000_000_050, |_| {
                signature_called.set(true);
                true
            })
            .unwrap_err();
        assert_eq!(err.stable_code(), "ChainIdMismatch");
        assert!(!signature_called.get());
    }

    #[test]
    fn strict_for_chain_rejects_legacy_and_exposes_binding() {
        let key = "sender-key";
        let mut verifier = RelayAuthVerifier::strict_for_chain(120_000, "trnm-mainnet");
        assert_eq!(verifier.expected_chain_id(), Some("trnm-mainnet"));
        let mut legacy = sample_env(1, "nonce-chain-legacy", 1_730_000_000_000, key);
        legacy.version = RelayAuthEnvelope::LEGACY_SPEC_VERSION.to_string();
        legacy.chain_id.clear();
        legacy.sig = legacy.sign_for_test_legacy_v0(key);
        let err = verifier
            .verify(&legacy, 1_730_000_000_050, |e| e.verify_test_sig_compat(key))
            .unwrap_err();
        // Schema validation remains first: legacy signatures are rejected
        // before any endpoint-specific chain policy is considered.
        assert_eq!(err.stable_code(), "BadVersion");
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
    fn relay_auth_replay_state_expires_after_timestamp_window() {
        let key = "sender-key";
        let base = 1_730_000_000_000;
        let mut verifier = RelayAuthVerifier::new(120_000);
        let first = sample_env(1, "nonce-window-1", base, key);
        verifier
            .verify(&first, base + 50, |e| e.sign_for_test(key) == e.sig)
            .expect("first message accepted");

        // Once the original timestamp is outside the admissible window, its
        // sequence/nonce state can no longer authorize a successful replay and
        // is reclaimed. A new active relay session may then start at seq=1.
        let next = sample_env(1, "nonce-window-2", base + 120_001, key);
        verifier
            .verify(&next, base + 120_001, |e| e.sign_for_test(key) == e.sig)
            .expect("expired replay state reclaimed");
    }

    #[test]
    fn relay_auth_replay_gc_is_amortized_and_reclaims_expired_state() {
        let key = "sender-key";
        let base = 1_730_000_000_000;
        let mut verifier = RelayAuthVerifier::new(120_000);
        let first = sample_env(1, "nonce-gc-initial", base, key);
        verifier
            .verify(&first, base, |e| e.sign_for_test(key) == e.sig)
            .expect("first message accepted");

        let stale_key = (
            "trnm-mainnet".to_string(),
            "task-gc-stale".to_string(),
            "sess-1".to_string(),
            "trnm1from".to_string(),
        );
        verifier.last_seq.insert(stale_key.clone(), (1, base));
        let initial_gc_tick = verifier.last_gc_tick;

        for index in 0..RELAY_AUTH_GC_INTERVAL_CALLS {
            let task_id = format!("task-gc-{index}");
            let nonce = format!("nonce-gc-{index}");
            let mut env = sample_env(1, &nonce, base + 120_001, key);
            env.task_id = task_id;
            env.sig = env.sign_for_test(key);
            verifier
                .verify(&env, base + 120_001, |e| e.sign_for_test(key) == e.sig)
                .expect("valid envelope accepted during amortized sweep");
        }

        assert!(verifier.last_gc_tick > initial_gc_tick);
        assert!(!verifier.last_seq.contains_key(&stale_key));
    }

    #[test]
    fn relay_auth_replay_state_limit_fails_closed() {
        let key = "sender-key";
        let base = 1_730_000_000_000;
        let mut verifier = RelayAuthVerifier::new(120_000);
        for index in 0..MAX_RELAY_AUTH_CONTEXTS {
            verifier.last_seq.insert(
                (
                    format!("chain-{index}"),
                    "task".to_string(),
                    "session".to_string(),
                    "from".to_string(),
                ),
                (1, base),
            );
        }
        let env = sample_env(1, "nonce-cap", base + 1, key);
        let err = verifier
            .verify(&env, base + 1, |e| e.sign_for_test(key) == e.sig)
            .unwrap_err();
        assert_eq!(err.stable_code(), "ResourceLimit");
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
    fn relay_auth_verify_rejects_oversized_replay_key_fields() {
        let key = "sender-key";
        let mut verifier = RelayAuthVerifier::new(120_000);
        let mut env = sample_env(1, "nonce-oversized", 1_730_000_000_000, key);
        env.task_id = "t".repeat(MAX_RELAY_AUTH_FIELD_BYTES + 1);
        env.sig = env.sign_for_test(key);

        let err = verifier
            .verify(&env, 1_730_000_000_050, |_| false)
            .unwrap_err();
        assert_eq!(err.stable_code(), "MissingRequiredField");
        assert!(verifier.last_seq.is_empty());
        assert!(verifier.seen_nonce.is_empty());
    }

    #[test]
    fn relay_auth_verify_rejects_oversized_payload_before_hash_or_signature() {
        let key = "sender-key";
        let mut verifier = RelayAuthVerifier::new(120_000);
        let mut env = sample_env(1, "nonce-payload-oversized", 1_730_000_000_000, key);
        env.payload = vec![0_u8; MAX_RELAY_AUTH_PAYLOAD_BYTES + 1];
        let signature_called = std::cell::Cell::new(false);
        let err = verifier
            .verify(&env, 1_730_000_000_050, |_| {
                signature_called.set(true);
                false
            })
            .unwrap_err();
        assert_eq!(err.stable_code(), "MissingRequiredField");
        assert!(!signature_called.get());
        assert!(verifier.last_seq.is_empty());
        assert!(verifier.seen_nonce.is_empty());
    }

    #[test]
    fn relay_auth_verify_rejects_oversized_signature_before_signature_callback() {
        let key = "sender-key";
        let mut verifier = RelayAuthVerifier::new(120_000);
        let mut env = sample_env(1, "nonce-signature-oversized", 1_730_000_000_000, key);
        env.sig = "s".repeat(MAX_RELAY_AUTH_SIGNATURE_BYTES + 1);
        let signature_called = std::cell::Cell::new(false);
        let err = verifier
            .verify(&env, 1_730_000_000_050, |_| {
                signature_called.set(true);
                false
            })
            .unwrap_err();
        assert_eq!(err.stable_code(), "MissingRequiredField");
        assert!(!signature_called.get());
        assert!(verifier.last_seq.is_empty());
        assert!(verifier.seen_nonce.is_empty());
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
    fn relay_auth_legacy_v0_rejected_by_default_to_prevent_cross_chain_replay() {
        let key = "sender-key";
        let mut verifier = RelayAuthVerifier::new(120_000);
        let mut env = sample_env(1, "nonce-legacy-1", 1_730_000_000_000, key);
        env.version = RelayAuthEnvelope::LEGACY_SPEC_VERSION.to_string();
        env.chain_id.clear();
        env.sig = env.sign_for_test_legacy_v0(key);

        let err = verifier
            .verify(&env, 1_730_000_000_050, |e| e.verify_test_sig_compat(key))
            .unwrap_err();
        assert_eq!(err.stable_code(), "BadVersion");
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
