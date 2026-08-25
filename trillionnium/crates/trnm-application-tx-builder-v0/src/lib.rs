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
use sha2::{Digest, Sha256};
use trnm_finality_types::{hash_domain, Hash32, SignedCommandEnvelopeV1};
use trnm_protocol::{CanonicalCommandV1, CanonicalTxV1};

pub const BUILDER_SCHEMA_V0: &str = "trnm.application.tx-builder.v0";
pub const MAX_INNER_BYTES_V0: usize = 1024 * 1024;
pub const MAX_OUTER_BYTES_V0: usize = 2 * 1024 * 1024;
pub const MAX_TTL_MILLIS_V0: u64 = 30 * 24 * 60 * 60 * 1000;
pub const MAX_GAS_V0: u64 = 10_000_000_000;
pub const MAX_FEE_LIMIT_V0: u128 = 1_000_000_000_000_000_000;
pub const PRODUCTION_CANDIDATE_V0: bool = false;

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
    use trnm_finality_types::crypto::public_key_hex;

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
}
