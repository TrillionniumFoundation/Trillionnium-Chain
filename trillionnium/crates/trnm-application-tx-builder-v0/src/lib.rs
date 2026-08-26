#![forbid(unsafe_code)]

//! Candidate canonical application-transaction builder for native PoCO-BFT.
//!
//! This crate deliberately stops at a signed, byte-stable envelope.  It does
//! not read a clock, reserve a nonce, write a WAL, contact an RPC endpoint, or
//! broadcast a transaction.  Those effects belong to the future native node
//! owner, where epoch-authenticated resource limits and durable replay can be
//! enforced.  Every package-level production/signing/broadcast flag remains
//! false until that integration is independently reviewed.

use anyhow::{anyhow, ensure, Context, Result};
use serde::de::{DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use trnm_finality_types::{hash_domain, Hash32, SignedCommandEnvelopeV1};
use trnm_mempool::{CanonicalSignerId, CanonicalTxDigest, ResourceLimits, SignedEnvelopeView};
use trnm_protocol::{CanonicalCommandV1, CanonicalTxV1};

pub const BUILDER_SCHEMA_V0: &str = "trnm.application.tx-builder.v0";
pub const MAX_INNER_BYTES_V0: usize = 1024 * 1024;
pub const MAX_OUTER_BYTES_V0: usize = 2 * 1024 * 1024;
pub const MAX_TTL_MILLIS_V0: u64 = 30 * 24 * 60 * 60 * 1000;
pub const MAX_GAS_V0: u64 = 10_000_000_000;
pub const MAX_FEE_LIMIT_V0: u128 = 1_000_000_000_000_000_000;
pub const PRODUCTION_CANDIDATE_V0: bool = false;
const MAX_JSON_DEPTH_V0: usize = 64;
const MAX_JSON_FIELDS_V0: usize = 4096;

/// Walks a JSON value without materialising it and rejects duplicate object
/// keys at every nesting level. `serde_json`'s ordinary map deserializer keeps
/// only the last duplicate, which would make a byte-preserving canonicality
/// check depend on parser policy instead of an explicit protocol rule.
fn reject_duplicate_json_keys(bytes: &[u8]) -> Result<()> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let mut budget = JsonScanBudget { fields: 0 };
    DuplicateKeySeed {
        depth: 0,
        budget: &mut budget,
        charge_item: false,
    }
    .deserialize(&mut deserializer)
    .map_err(|error| anyhow!("strict JSON parse: {error}"))?;
    deserializer
        .end()
        .map_err(|error| anyhow!("trailing JSON data: {error}"))
}

/// Validate JSON framing and structure before a caller deserializes a
/// request/control envelope with `serde_json`.
///
/// `serde_json` intentionally follows the usual last-key-wins behaviour for
/// duplicate object members.  Protocol/control envelopes cannot use that
/// behaviour because a duplicated discriminator or generation could make the
/// bytes observed by an ingress boundary differ from the typed value it acts
/// on.  This helper is public so node process hosts can apply the same
/// bounded duplicate/depth/field policy to their own envelopes; it does not
/// authenticate a transaction or establish any node authority.
pub fn validate_strict_json_structure_v0(bytes: &[u8]) -> Result<()> {
    ensure!(!bytes.is_empty(), "JSON envelope must not be empty");
    ensure!(
        bytes.len() <= MAX_OUTER_BYTES_V0,
        "JSON envelope exceeds the candidate limit"
    );
    reject_duplicate_json_keys(bytes)
}

struct JsonScanBudget {
    fields: usize,
}

impl JsonScanBudget {
    fn charge_field<E>(&mut self) -> core::result::Result<(), E>
    where
        E: serde::de::Error,
    {
        self.fields = self
            .fields
            .checked_add(1)
            .ok_or_else(|| E::custom("JSON field budget overflow"))?;
        if self.fields > MAX_JSON_FIELDS_V0 {
            return Err(E::custom("JSON field budget exceeded"));
        }
        Ok(())
    }
}

struct DuplicateKeySeed<'a> {
    depth: usize,
    budget: &'a mut JsonScanBudget,
    charge_item: bool,
}

impl<'de, 'a> DeserializeSeed<'de> for DuplicateKeySeed<'a> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> core::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        if self.charge_item {
            self.budget.charge_field::<D::Error>()?;
        }
        deserializer.deserialize_any(DuplicateKeyVisitor {
            depth: self.depth,
            budget: self.budget,
        })
    }
}

struct DuplicateKeyVisitor<'a> {
    depth: usize,
    budget: &'a mut JsonScanBudget,
}

impl<'de, 'a> Visitor<'de> for DuplicateKeyVisitor<'a> {
    type Value = ();

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, _value: bool) -> core::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> core::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> core::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> core::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> core::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_borrowed_str<E>(self, _value: &'de str) -> core::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, _value: String) -> core::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E>(self) -> core::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> core::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> core::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        if self.depth >= MAX_JSON_DEPTH_V0 {
            return Err(serde::de::Error::custom(
                "JSON nesting exceeds the candidate limit",
            ));
        }
        DuplicateKeySeed {
            depth: self.depth + 1,
            budget: self.budget,
            charge_item: false,
        }
        .deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut access: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if self.depth >= MAX_JSON_DEPTH_V0 {
            return Err(serde::de::Error::custom(
                "JSON nesting exceeds the candidate limit",
            ));
        }
        while access
            .next_element_seed(DuplicateKeySeed {
                depth: self.depth + 1,
                budget: self.budget,
                charge_item: true,
            })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A>(self, mut access: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        if self.depth >= MAX_JSON_DEPTH_V0 {
            return Err(serde::de::Error::custom(
                "JSON nesting exceeds the candidate limit",
            ));
        }
        let mut keys = BTreeSet::new();
        while let Some(key) = access.next_key::<String>()? {
            self.budget.charge_field::<A::Error>()?;
            if !keys.insert(key) {
                return Err(serde::de::Error::custom("duplicate JSON object key"));
            }
            access.next_value_seed(DuplicateKeySeed {
                depth: self.depth + 1,
                budget: self.budget,
                charge_item: false,
            })?;
        }
        Ok(())
    }
}

/// Limits supplied by the node-side admission policy.
///
/// The absolute candidate caps above cannot be widened by a caller.  A future
/// epoch-authenticated policy may choose smaller values, but it must not use
/// this builder to silently create a larger envelope than the protocol
/// boundary permits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxBuilderLimitsV0 {
    pub max_inner_bytes: usize,
    pub max_outer_bytes: usize,
    pub max_ttl_millis: u64,
    pub max_gas: u64,
    pub max_fee_limit: u128,
}

impl TxBuilderLimitsV0 {
    pub const fn candidate_v0() -> Self {
        Self {
            max_inner_bytes: MAX_INNER_BYTES_V0,
            max_outer_bytes: MAX_OUTER_BYTES_V0,
            max_ttl_millis: MAX_TTL_MILLIS_V0,
            max_gas: MAX_GAS_V0,
            max_fee_limit: MAX_FEE_LIMIT_V0,
        }
    }

    fn validate(self) -> Result<()> {
        ensure!(self.max_inner_bytes > 0, "max_inner_bytes must be positive");
        ensure!(
            self.max_inner_bytes <= MAX_INNER_BYTES_V0,
            "max_inner_bytes exceeds the immutable candidate cap"
        );
        ensure!(self.max_outer_bytes > 0, "max_outer_bytes must be positive");
        ensure!(
            self.max_outer_bytes <= MAX_OUTER_BYTES_V0,
            "max_outer_bytes exceeds the immutable candidate cap"
        );
        ensure!(self.max_ttl_millis > 0, "max_ttl_millis must be positive");
        ensure!(
            self.max_ttl_millis <= MAX_TTL_MILLIS_V0,
            "max_ttl_millis exceeds the immutable candidate cap"
        );
        ensure!(self.max_gas > 0, "max_gas must be positive");
        ensure!(
            self.max_gas <= MAX_GAS_V0,
            "max_gas exceeds the immutable candidate cap"
        );
        ensure!(self.max_fee_limit > 0, "max_fee_limit must be positive");
        ensure!(
            self.max_fee_limit <= MAX_FEE_LIMIT_V0,
            "max_fee_limit exceeds the immutable candidate cap"
        );
        Ok(())
    }
}

impl Default for TxBuilderLimitsV0 {
    fn default() -> Self {
        Self::candidate_v0()
    }
}

/// Explicit inputs owned by the node-side transaction admission path.
///
/// No field is inferred from wall-clock time or a local wallet.  In
/// particular, `command_id` is optional only so a deterministic retry-stable
/// id can be derived from the exact canonical transaction bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalTxBuildContextV0 {
    pub chain_id: String,
    pub sender: String,
    pub command_id: Option<String>,
    pub nonce: u64,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub max_gas: u64,
    pub fee_limit: u128,
    pub limits: TxBuilderLimitsV0,
}

/// A signer boundary suitable for a remote signer/HSM adapter.
///
/// The trait exposes only public identity and receives the exact envelope
/// signing preimage.  It has no constructor from a raw private key and cannot
/// mutate node nonce/WAL state.
pub trait ApplicationSignerV0 {
    fn signer_id(&self) -> &str;
    fn signer_role(&self) -> &str;
    fn public_key_hex(&self) -> &str;
    fn sign(&self, preimage: &[u8]) -> Result<[u8; 64]>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltCanonicalTxV0 {
    envelope: SignedCommandEnvelopeV1,
    exact_inner_bytes: Vec<u8>,
    exact_outer_bytes: Vec<u8>,
    protocol_tx_hash_v1: Hash32,
    outer_bytes_sha256: Hash32,
}

/// Exact typed mempool view for one already-built envelope.
///
/// The signer/account identity is supplied by the node's canonical identity
/// authority; this adapter deliberately does not hash a display string or
/// derive an identity from a public key.  It exposes no nonce reservation or
/// WAL capability.  The node must still call the lifecycle admission API with
/// its own [`trnm_mempool::PendingNonceAuthority`].
#[derive(Debug, Clone, Copy)]
pub struct BuiltCanonicalTxAdmissionViewV0<'a> {
    transaction: &'a BuiltCanonicalTxV0,
    signer_id: CanonicalSignerId,
}

impl<'a> BuiltCanonicalTxAdmissionViewV0<'a> {
    pub const fn new(transaction: &'a BuiltCanonicalTxV0, signer_id: CanonicalSignerId) -> Self {
        Self {
            transaction,
            signer_id,
        }
    }

    pub const fn transaction(&self) -> &'a BuiltCanonicalTxV0 {
        self.transaction
    }
}

impl SignedEnvelopeView for BuiltCanonicalTxAdmissionViewV0<'_> {
    fn canonical_digest(&self) -> CanonicalTxDigest {
        // The builder only constructs this carrier after validating the exact
        // envelope.  The digest was computed from those immutable bytes, so a
        // fallible trait surface would only create a silent alternate hash
        // path here.
        CanonicalTxDigest::from_bytes(self.transaction.protocol_tx_hash_v1)
            .expect("builder-produced transaction hash is nonzero")
    }

    fn canonical_signer_id(&self) -> Result<CanonicalSignerId, trnm_mempool::AdmissionReject> {
        Ok(self.signer_id)
    }

    fn canonical_body(&self) -> &[u8] {
        self.transaction.exact_inner_bytes()
    }

    fn nonce(&self) -> u64 {
        self.transaction.envelope().nonce
    }

    fn fee_limit(&self) -> u128 {
        self.transaction
            .envelope()
            .payload_bytes()
            .ok()
            .and_then(|bytes| serde_json::from_slice::<CanonicalTxV1>(&bytes).ok())
            .map(|transaction| transaction.fee_limit)
            .unwrap_or_default()
    }

    fn resource_limits(&self) -> ResourceLimits {
        ResourceLimits {
            max_gas: self
                .transaction
                .envelope()
                .payload_bytes()
                .ok()
                .and_then(|bytes| serde_json::from_slice::<CanonicalTxV1>(&bytes).ok())
                .map(|transaction| transaction.max_gas)
                .unwrap_or_default(),
            max_bytes: u64::try_from(self.transaction.exact_inner_bytes().len())
                .unwrap_or(u64::MAX),
        }
    }

    fn validate_canonical(&self) -> Result<(), trnm_mempool::AdmissionReject> {
        self.decode_canonical_transaction().map(|_| ())
    }
}

impl BuiltCanonicalTxAdmissionViewV0<'_> {
    fn decode_canonical_transaction(&self) -> Result<CanonicalTxV1, trnm_mempool::AdmissionReject> {
        let envelope = self.transaction.envelope();
        envelope
            .validate_shape()
            .map_err(|_| trnm_mempool::AdmissionReject::CanonicalValidationFailed)?;
        if envelope.payload_type != trnm_protocol::CANONICAL_TX_PAYLOAD_TYPE_V1 {
            return Err(trnm_mempool::AdmissionReject::CanonicalValidationFailed);
        }
        let payload = envelope
            .payload_bytes()
            .map_err(|_| trnm_mempool::AdmissionReject::CanonicalValidationFailed)?;
        if payload != self.transaction.exact_inner_bytes() {
            return Err(trnm_mempool::AdmissionReject::CanonicalValidationFailed);
        }
        let transaction: CanonicalTxV1 =
            serde_json::from_slice(self.transaction.exact_inner_bytes())
                .map_err(|_| trnm_mempool::AdmissionReject::CanonicalValidationFailed)?;
        transaction
            .validate()
            .map_err(|_| trnm_mempool::AdmissionReject::CanonicalValidationFailed)?;
        if transaction.sender != envelope.signer_id
            || transaction.nonce != envelope.nonce
            || transaction.max_gas == 0
            || transaction.fee_limit == 0
            || self.canonical_digest().as_bytes() != self.transaction.protocol_tx_hash_v1
        {
            return Err(trnm_mempool::AdmissionReject::CanonicalValidationFailed);
        }
        Ok(transaction)
    }
}

impl BuiltCanonicalTxV0 {
    pub fn envelope(&self) -> &SignedCommandEnvelopeV1 {
        &self.envelope
    }

    pub fn exact_inner_bytes(&self) -> &[u8] {
        &self.exact_inner_bytes
    }

    pub fn exact_outer_bytes(&self) -> &[u8] {
        &self.exact_outer_bytes
    }

    pub const fn protocol_tx_hash_v1(&self) -> Hash32 {
        self.protocol_tx_hash_v1
    }

    pub const fn outer_bytes_sha256(&self) -> Hash32 {
        self.outer_bytes_sha256
    }

    /// Create the exact typed view consumed by `trnm-mempool` admission.
    ///
    /// This is intentionally only a view: it does not reserve a nonce, write
    /// durable state, call CheckTx, or broadcast.
    pub const fn admission_view_v0(
        &self,
        signer_id: CanonicalSignerId,
    ) -> BuiltCanonicalTxAdmissionViewV0<'_> {
        BuiltCanonicalTxAdmissionViewV0::new(self, signer_id)
    }

    /// Decode one exact, canonical outer envelope at a node ingress boundary.
    ///
    /// The builder normally creates this carrier from typed inputs, but a
    /// process host receives bytes. This constructor preserves those bytes
    /// verbatim while re-running the structural and hash checks performed by
    /// the builder. Signature/context authentication remains the node-owned
    /// `validate_at_strict`/admission hook; this function never treats an
    /// untrusted byte string as an authenticated authority by itself.
    pub fn from_exact_outer_bytes_v0(bytes: &[u8]) -> Result<Self> {
        ensure!(!bytes.is_empty(), "outer envelope must not be empty");
        ensure!(
            bytes.len() <= MAX_OUTER_BYTES_V0,
            "outer envelope exceeds the candidate limit"
        );
        reject_duplicate_json_keys(bytes).context("reject duplicate outer JSON keys")?;
        let envelope: SignedCommandEnvelopeV1 =
            serde_json::from_slice(bytes).context("decode signed command envelope")?;
        envelope
            .validate_shape()
            .context("validate signed envelope shape")?;
        let canonical_outer =
            serde_json::to_vec(&envelope).context("canonicalize signed command envelope")?;
        ensure!(
            canonical_outer == bytes,
            "outer envelope is not canonical JSON"
        );
        let exact_inner_bytes = envelope
            .payload_bytes()
            .context("decode envelope payload")?;
        ensure!(
            exact_inner_bytes.len() <= MAX_INNER_BYTES_V0,
            "inner transaction exceeds the candidate limit"
        );
        ensure!(
            envelope.payload_type == trnm_protocol::CANONICAL_TX_PAYLOAD_TYPE_V1,
            "unsupported canonical transaction payload type"
        );
        reject_duplicate_json_keys(&exact_inner_bytes)
            .context("reject duplicate inner JSON keys")?;
        let transaction: CanonicalTxV1 =
            serde_json::from_slice(&exact_inner_bytes).context("decode canonical transaction")?;
        transaction
            .validate()
            .context("validate canonical transaction")?;
        let canonical_inner =
            serde_json::to_vec(&transaction).context("canonicalize canonical transaction")?;
        ensure!(
            canonical_inner == exact_inner_bytes,
            "inner transaction is not canonical JSON"
        );
        ensure!(
            transaction.sender == envelope.signer_id
                && transaction.nonce == envelope.nonce
                && transaction.max_gas > 0
                && transaction.fee_limit > 0,
            "inner transaction and envelope metadata differ"
        );
        let protocol_tx_hash_v1 = envelope.tx_hash().context("derive transaction hash")?;
        let outer_bytes_sha256 = Sha256::digest(bytes).into();
        Ok(Self {
            envelope,
            exact_inner_bytes,
            exact_outer_bytes: bytes.to_vec(),
            protocol_tx_hash_v1,
            outer_bytes_sha256,
        })
    }
}

/// Derive a retry-stable command id from the exact canonical command body.
pub fn derive_command_id_v0(
    chain_id: &str,
    sender: &str,
    nonce: u64,
    exact_inner_bytes: &[u8],
) -> String {
    let nonce_bytes = nonce.to_be_bytes();
    hex::encode(hash_domain(
        "trnm.command-id.v1",
        &[
            chain_id.as_bytes(),
            sender.as_bytes(),
            &nonce_bytes,
            exact_inner_bytes,
        ],
    ))
}

/// Build and externally sign one canonical application transaction.
pub fn build_signed_canonical_tx_v0(
    context: CanonicalTxBuildContextV0,
    command: CanonicalCommandV1,
    signer: &dyn ApplicationSignerV0,
) -> Result<BuiltCanonicalTxV0> {
    context.limits.validate()?;
    ensure!(context.nonce > 0, "nonce must be positive");
    ensure!(
        context.expires_at_unix_ms > context.issued_at_unix_ms,
        "expires_at_unix_ms must be after issued_at_unix_ms"
    );
    let ttl = context
        .expires_at_unix_ms
        .checked_sub(context.issued_at_unix_ms)
        .ok_or_else(|| anyhow!("transaction TTL underflow"))?;
    ensure!(
        ttl <= context.limits.max_ttl_millis,
        "transaction TTL exceeds the admitted limit"
    );
    ensure!(
        context.max_gas > 0 && context.max_gas <= context.limits.max_gas,
        "max_gas is outside the admitted limit"
    );
    ensure!(
        context.fee_limit > 0 && context.fee_limit <= context.limits.max_fee_limit,
        "fee_limit is outside the admitted limit"
    );

    // Check signer identity before invoking an external effect.  This keeps a
    // mismatched caller from consuming HSM/remote-signer work or producing an
    // unusable signature.
    ensure!(
        context.sender == signer.signer_id(),
        "transaction sender does not match signer identity"
    );

    let transaction = CanonicalTxV1 {
        schema: trnm_protocol::CANONICAL_TX_SCHEMA_V1.to_string(),
        sender: context.sender.clone(),
        nonce: context.nonce,
        max_gas: context.max_gas,
        fee_limit: context.fee_limit,
        command,
    };
    transaction
        .validate()
        .map_err(|error| anyhow!("canonical transaction rejected: {error}"))?;

    let exact_inner_bytes =
        serde_json::to_vec(&transaction).context("serialize canonical transaction")?;
    ensure!(
        exact_inner_bytes.len() <= context.limits.max_inner_bytes,
        "canonical transaction exceeds the admitted inner-byte limit"
    );
    let roundtrip: CanonicalTxV1 = serde_json::from_slice(&exact_inner_bytes)
        .context("decode canonical transaction roundtrip")?;
    ensure!(
        roundtrip == transaction,
        "canonical transaction bytes are not stable"
    );

    let command_id = context.command_id.unwrap_or_else(|| {
        derive_command_id_v0(
            &context.chain_id,
            &context.sender,
            context.nonce,
            &exact_inner_bytes,
        )
    });
    let mut envelope = SignedCommandEnvelopeV1 {
        schema: trnm_finality_types::SIGNED_COMMAND_SCHEMA_V1.to_string(),
        chain_id: context.chain_id.clone(),
        command_id,
        signer_id: signer.signer_id().to_string(),
        signer_role: signer.signer_role().to_string(),
        public_key_hex: signer.public_key_hex().to_string(),
        nonce: context.nonce,
        issued_at_unix_ms: context.issued_at_unix_ms,
        expires_at_unix_ms: context.expires_at_unix_ms,
        payload_type: trnm_protocol::CANONICAL_TX_PAYLOAD_TYPE_V1.to_string(),
        payload_hex: hex::encode(&exact_inner_bytes),
        payload_hash_hex: hex::encode(hash_domain(
            "trnm.command.payload.v1",
            &[&exact_inner_bytes],
        )),
        signature_hex: String::new(),
    };
    envelope.validate_shape()?;
    let preimage = envelope.signing_bytes()?;
    let signature = signer.sign(&preimage)?;
    envelope.signature_hex = hex::encode(signature);
    // Use the issued timestamp as a deterministic self-check point.  The
    // node must still validate against its current block time at admission.
    envelope.validate_at_strict(&context.chain_id, context.issued_at_unix_ms)?;

    let exact_outer_bytes = serde_json::to_vec(&envelope).context("serialize signed envelope")?;
    ensure!(
        exact_outer_bytes.len() <= context.limits.max_outer_bytes,
        "signed envelope exceeds the admitted outer-byte limit"
    );
    let outer_roundtrip: SignedCommandEnvelopeV1 =
        serde_json::from_slice(&exact_outer_bytes).context("decode signed envelope roundtrip")?;
    ensure!(
        outer_roundtrip == envelope,
        "signed envelope bytes are not stable"
    );
    Ok(BuiltCanonicalTxV0 {
        protocol_tx_hash_v1: envelope.tx_hash()?,
        outer_bytes_sha256: Sha256::digest(&exact_outer_bytes).into(),
        envelope,
        exact_inner_bytes,
        exact_outer_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::fmt::Write as _;
    use trnm_finality_types::crypto::public_key_hex;
    use trnm_mempool::{
        AdmissionReject, IngressClass, PendingNonceAuthority, PendingNonceReservation,
        SignedAdmissionHooks, SignedEnvelopeMetadata, TypedAdmissionGate, TypedAdmitOutcome,
    };
    use trnm_protocol::CANONICAL_TX_SCHEMA_V1;

    struct TestSigner {
        key: SigningKey,
        id: String,
        role: String,
        public_key: String,
    }

    impl ApplicationSignerV0 for TestSigner {
        fn signer_id(&self) -> &str {
            &self.id
        }

        fn signer_role(&self) -> &str {
            &self.role
        }

        fn public_key_hex(&self) -> &str {
            &self.public_key
        }

        fn sign(&self, preimage: &[u8]) -> Result<[u8; 64]> {
            Ok(self.key.sign(preimage).to_bytes())
        }
    }

    fn signer() -> TestSigner {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let public_key = public_key_hex(&key);
        TestSigner {
            key,
            id: "did:trnm:alice".to_string(),
            role: "account".to_string(),
            public_key,
        }
    }

    fn context(sender: &str) -> CanonicalTxBuildContextV0 {
        CanonicalTxBuildContextV0 {
            chain_id: "trnm-devnet".to_string(),
            sender: sender.to_string(),
            command_id: None,
            nonce: 1,
            issued_at_unix_ms: 1_000,
            expires_at_unix_ms: 2_000,
            max_gas: 10_000,
            fee_limit: 10,
            limits: TxBuilderLimitsV0::candidate_v0(),
        }
    }

    fn command() -> CanonicalCommandV1 {
        CanonicalCommandV1::Transfer {
            to: "did:trnm:bob".to_string(),
            amount: 7,
        }
    }

    #[test]
    fn build_returns_stable_exact_inner_and_outer_bytes() {
        let signer = signer();
        let first = build_signed_canonical_tx_v0(context(&signer.id), command(), &signer).unwrap();
        let second = build_signed_canonical_tx_v0(context(&signer.id), command(), &signer).unwrap();
        assert_eq!(first.exact_inner_bytes(), second.exact_inner_bytes());
        assert_eq!(first.exact_outer_bytes(), second.exact_outer_bytes());
        assert_eq!(first.protocol_tx_hash_v1(), second.protocol_tx_hash_v1());
        assert_eq!(first.outer_bytes_sha256(), second.outer_bytes_sha256());
        first
            .envelope()
            .validate_at_strict("trnm-devnet", 1_000)
            .unwrap();
    }

    #[test]
    fn exact_outer_decoder_preserves_bytes_and_rejects_noncanonical_or_substituted_payload() {
        let signer = signer();
        let built = build_signed_canonical_tx_v0(context(&signer.id), command(), &signer).unwrap();
        let decoded = BuiltCanonicalTxV0::from_exact_outer_bytes_v0(built.exact_outer_bytes())
            .expect("builder output must decode at the byte ingress");
        assert_eq!(decoded, built);

        let mut whitespace = built.exact_outer_bytes().to_vec();
        whitespace.push(b'\n');
        assert!(BuiltCanonicalTxV0::from_exact_outer_bytes_v0(&whitespace).is_err());

        let mut forged = built.envelope().clone();
        forged.payload_hex = hex::encode(braced_payload_for_test());
        let forged_bytes = serde_json::to_vec(&forged).unwrap();
        assert!(BuiltCanonicalTxV0::from_exact_outer_bytes_v0(&forged_bytes).is_err());
    }

    #[test]
    fn exact_outer_decoder_rejects_duplicate_keys_at_both_json_layers() {
        let signer = signer();
        let built = build_signed_canonical_tx_v0(context(&signer.id), command(), &signer).unwrap();

        let outer = String::from_utf8(built.exact_outer_bytes().to_vec()).unwrap();
        let close = outer.rfind('}').expect("outer object close");
        let duplicate_outer = format!(
            "{},\"nonce\":{}{}",
            &outer[..close],
            built.envelope().nonce,
            &outer[close..]
        );
        assert!(BuiltCanonicalTxV0::from_exact_outer_bytes_v0(duplicate_outer.as_bytes()).is_err());

        let inner = String::from_utf8(built.exact_inner_bytes().to_vec()).unwrap();
        let inner_close = inner.rfind('}').expect("inner object close");
        let duplicate_inner = format!(
            "{},\"nonce\":{}{}",
            &inner[..inner_close],
            built.envelope().nonce,
            &inner[inner_close..]
        );
        let mut forged = built.envelope().clone();
        forged.payload_hex = hex::encode(duplicate_inner.as_bytes());
        forged.payload_hash_hex = hex::encode(hash_domain(
            "trnm.command.payload.v1",
            &[duplicate_inner.as_bytes()],
        ));
        forged.signature_hex.clear();
        let forged_bytes = serde_json::to_vec(&forged).unwrap();
        assert!(BuiltCanonicalTxV0::from_exact_outer_bytes_v0(&forged_bytes).is_err());
    }

    #[test]
    fn strict_json_scan_rejects_field_and_depth_bombs_before_typed_decode() {
        let mut object = String::from("{");
        for index in 0..=MAX_JSON_FIELDS_V0 {
            if index != 0 {
                object.push(',');
            }
            write!(&mut object, "\"k{index}\":0").expect("string formatting");
        }
        object.push('}');
        assert!(reject_duplicate_json_keys(object.as_bytes()).is_err());

        let deeply_nested = format!(
            "{}0{}",
            "[".repeat(MAX_JSON_DEPTH_V0 + 1),
            "]".repeat(MAX_JSON_DEPTH_V0 + 1)
        );
        assert!(reject_duplicate_json_keys(deeply_nested.as_bytes()).is_err());
    }

    fn braced_payload_for_test() -> Vec<u8> {
        serde_json::to_vec(&CanonicalTxV1 {
            schema: CANONICAL_TX_SCHEMA_V1.to_owned(),
            sender: "did:trnm:alice".to_owned(),
            nonce: 1,
            max_gas: 10_000,
            fee_limit: 10,
            command: CanonicalCommandV1::Transfer {
                to: "did:trnm:bob".to_owned(),
                amount: 8,
            },
        })
        .unwrap()
    }

    #[test]
    fn derived_command_id_is_retry_stable_and_nonce_bound() {
        let signer = signer();
        let tx = build_signed_canonical_tx_v0(context(&signer.id), command(), &signer).unwrap();
        let changed = {
            let mut c = context(&signer.id);
            c.nonce = 2;
            build_signed_canonical_tx_v0(c, command(), &signer).unwrap()
        };
        assert_eq!(
            tx.envelope().command_id,
            derive_command_id_v0("trnm-devnet", &signer.id, 1, tx.exact_inner_bytes())
        );
        assert_ne!(tx.envelope().command_id, changed.envelope().command_id);
    }

    #[test]
    fn sender_mismatch_is_rejected_before_signer_callback() {
        struct CountingSigner(TestSigner, std::cell::Cell<u32>);
        impl ApplicationSignerV0 for CountingSigner {
            fn signer_id(&self) -> &str {
                self.0.signer_id()
            }
            fn signer_role(&self) -> &str {
                self.0.signer_role()
            }
            fn public_key_hex(&self) -> &str {
                self.0.public_key_hex()
            }
            fn sign(&self, preimage: &[u8]) -> Result<[u8; 64]> {
                self.1.set(self.1.get() + 1);
                self.0.sign(preimage)
            }
        }
        let signer = CountingSigner(signer(), std::cell::Cell::new(0));
        assert!(
            build_signed_canonical_tx_v0(context("did:trnm:mallory"), command(), &signer).is_err()
        );
        assert_eq!(signer.1.get(), 0);
    }

    #[test]
    fn malformed_external_signature_fails_closed() {
        struct BadSigner(TestSigner);
        impl ApplicationSignerV0 for BadSigner {
            fn signer_id(&self) -> &str {
                self.0.signer_id()
            }
            fn signer_role(&self) -> &str {
                self.0.signer_role()
            }
            fn public_key_hex(&self) -> &str {
                self.0.public_key_hex()
            }
            fn sign(&self, _preimage: &[u8]) -> Result<[u8; 64]> {
                Ok([0u8; 64])
            }
        }
        assert!(build_signed_canonical_tx_v0(
            context("did:trnm:alice"),
            command(),
            &BadSigner(signer())
        )
        .is_err());
    }

    #[test]
    fn policy_and_shape_bounds_fail_closed() {
        let signer = signer();
        let mut too_long = context(&signer.id);
        too_long.expires_at_unix_ms = too_long.issued_at_unix_ms + MAX_TTL_MILLIS_V0 + 1;
        assert!(build_signed_canonical_tx_v0(too_long, command(), &signer).is_err());
        let mut too_wide = context(&signer.id);
        too_wide.limits.max_gas = MAX_GAS_V0 + 1;
        assert!(build_signed_canonical_tx_v0(too_wide, command(), &signer).is_err());
        let mut zero_fee = context(&signer.id);
        zero_fee.fee_limit = 0;
        assert!(build_signed_canonical_tx_v0(zero_fee, command(), &signer).is_err());
    }

    #[test]
    fn package_flags_keep_builder_inert() {
        assert_eq!(BUILDER_SCHEMA_V0, "trnm.application.tx-builder.v0");
        assert!(!std::hint::black_box(PRODUCTION_CANDIDATE_V0));
    }

    #[derive(Debug)]
    struct TestReservation {
        state: u8,
    }

    impl PendingNonceReservation for TestReservation {
        fn handoff(&mut self) -> Result<(), AdmissionReject> {
            assert_eq!(self.state, 0);
            self.state = 1;
            Ok(())
        }

        fn commit(&mut self) -> Result<(), AdmissionReject> {
            assert_eq!(self.state, 1);
            self.state = 2;
            Ok(())
        }

        fn release(&mut self) -> Result<(), AdmissionReject> {
            assert!(self.state < 2);
            self.state = 3;
            Ok(())
        }
    }

    struct TestHooks;

    impl<'a> SignedAdmissionHooks<BuiltCanonicalTxAdmissionViewV0<'a>> for TestHooks {
        fn verify_signature(
            &mut self,
            envelope: &BuiltCanonicalTxAdmissionViewV0<'a>,
            _metadata: &SignedEnvelopeMetadata,
        ) -> Result<(), AdmissionReject> {
            envelope
                .transaction()
                .envelope()
                .validate_at_strict("trnm-devnet", 1_000)
                .map_err(|_| AdmissionReject::SignatureRejected)
        }

        fn recheck(&mut self, _metadata: &SignedEnvelopeMetadata) -> Result<(), AdmissionReject> {
            Ok(())
        }
    }

    struct TestNonceAuthority;

    impl<'a> PendingNonceAuthority<BuiltCanonicalTxAdmissionViewV0<'a>> for TestNonceAuthority {
        fn reserve_pending_nonce(
            &mut self,
            _envelope: &BuiltCanonicalTxAdmissionViewV0<'a>,
            metadata: &SignedEnvelopeMetadata,
        ) -> Result<Box<dyn PendingNonceReservation>, AdmissionReject> {
            assert_eq!(metadata.nonce(), 1);
            assert_eq!(
                metadata.body().len(),
                metadata.resource_limits().max_bytes as usize
            );
            Ok(Box::new(TestReservation { state: 0 }))
        }
    }

    #[test]
    fn exact_builder_view_enters_typed_pending_nonce_admission() {
        let signer = signer();
        let transaction =
            build_signed_canonical_tx_v0(context(&signer.id), command(), &signer).unwrap();
        let signer_id = CanonicalSignerId::from_bytes([0xA1; 32]).unwrap();
        let view = transaction.admission_view_v0(signer_id);
        let mut gate = TypedAdmissionGate::with_default_body_limit(4, 0);
        let mut hooks = TestHooks;
        let mut authority = TestNonceAuthority;

        assert_eq!(
            gate.admit_signed_with_pending_nonce(
                &view,
                IngressClass::Normal,
                &mut hooks,
                &mut authority,
            ),
            TypedAdmitOutcome::Accepted
        );
        let mut ready = gate.pop_ready_with_lifecycle().expect("queued transaction");
        assert_eq!(ready.metadata().signer_id(), signer_id);
        ready.handoff().unwrap();
        ready.commit().unwrap();
    }
}
