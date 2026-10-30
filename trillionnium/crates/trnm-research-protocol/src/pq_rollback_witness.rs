//! Strict, research-only post-quantum external recovery witness verifier.
//!
//! No signature (even a valid ML-DSA-65 signature) is local execution or
//! consensus authority. The receiving caller MUST obtain the witness key,
//! minimum sequence and one-time challenge from independently retained state.
//! Rolling back SQLite and these inputs together defeats this component.
use crate::canonical::{CanonicalCbor, CanonicalDecodeError, Decoder, Encoder, CANONICAL_ENCODING};
use crate::types::Digest32;
use ml_dsa::{
    EncodedVerifyingKey, KeyExport, Keypair, MlDsa65, Signature, SignatureEncoding, Signer,
    SigningKey, VerifyingKey,
};
use thiserror::Error;

const DOMAIN: &str = "trnm-external-pq-recovery-witness-v1";
pub const PQ_RECOVERY_WITNESS_VERSION: u8 = 1;
pub const MAX_PQ_RECOVERY_WITNESS_BYTES: usize = 8192;
const PUBLIC_KEY_BYTES: usize = 1952;
const SIGNATURE_BYTES: usize = 3309;
const MAX_WITNESS_TTL_SECONDS: u64 = 300;

/// Actual local bytes read by the recovery owner, not supplied by the witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalRecoveryHeadV1 {
    pub tip: Digest32,
    pub state_root: Digest32,
    pub effect_journal_head: Digest32,
    pub height: u64,
    pub owner_generation: u64,
}

/// All fields in this context must come from an external, independently
/// trusted witness policy and a fresh local owner read. An old local SQLite
/// snapshot must NOT supply the minimum sequence or the challenge.
pub struct ExternalRecoveryExpectationV1<'a> {
    pub chain_id: &'a str,
    pub witness_did: &'a str,
    pub trusted_ml_dsa65_public_key: &'a [u8],
    pub genesis: Digest32,
    pub outstanding_challenge: Digest32,
    pub last_external_sequence: u64,
    pub now_unix_s: u64,
    pub actual_local: &'a LocalRecoveryHeadV1,
}

/// A signed external observation. The signer and signature alone do NOT
/// establish external independence, physical durability or finality.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPqRecoveryWitnessV1 {
    pub chain_id: String,
    pub witness_did: String,
    pub public_key: Vec<u8>,
    pub genesis: Digest32,
    pub observed: LocalRecoveryHeadV1,
    pub sequence: u64,
    pub challenge: Digest32,
    pub issued_unix_s: u64,
    pub expires_unix_s: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum PqRecoveryWitnessError {
    #[error(transparent)]
    Canonical(#[from] CanonicalDecodeError),
    #[error("PQ recovery witness over 8192 bytes")]
    WireTooLarge,
    #[error("invalid PQ recovery witness identity or material")]
    InvalidShape,
    #[error("invalid signature size or encoding")]
    InvalidSignatureEncoding,
    #[error("invalid ML-DSA-65 recovery witness signature")]
    InvalidSignature,
    #[error("unexpected signed recovery witness version or encoding")]
    VersionOrEncoding,
    #[error("trusted witness context mismatch: {0}")]
    ContextMismatch(&'static str),
    #[error("external witness sequence is stale")]
    StaleSequence,
    #[error("witness expired or outside its short validity window")]
    TimeWindow,
    #[error("local tip or journal differs from externally witnessed state")]
    LocalRollbackOrDivergence,
}

impl SignedPqRecoveryWitnessV1 {
    pub fn sign(
        chain_id: String,
        witness_did: String,
        genesis: Digest32,
        observed: LocalRecoveryHeadV1,
        sequence: u64,
        challenge: Digest32,
        issued_unix_s: u64,
        expires_unix_s: u64,
        key: &SigningKey<MlDsa65>,
    ) -> Result<Self, PqRecoveryWitnessError> {
        let mut witness = Self {
            chain_id,
            witness_did,
            public_key: key.verifying_key().to_bytes().to_vec(),
            genesis,
            observed,
            sequence,
            challenge,
            issued_unix_s,
            expires_unix_s,
            signature: Vec::new(),
        };
        witness.check_shape()?;
        let signature: Signature<MlDsa65> = key.sign(&witness.signing_bytes());
        witness.signature = signature.to_vec();
        Ok(witness)
    }

    /// In a fresh recovery, verify one exact externally witnessed local state.
    /// A caller with a newer legitimate chain tip must obtain a fresh witness;
    /// this API never guesses ancestry or accepts a higher tip without proof.
    pub fn verify_for_recovery(
        &self,
        trusted: &ExternalRecoveryExpectationV1<'_>,
    ) -> Result<(), PqRecoveryWitnessError> {
        self.check_shape()?;
        if trusted.trusted_ml_dsa65_public_key.len() != PUBLIC_KEY_BYTES
            || trusted.genesis == [0; 32]
            || trusted.outstanding_challenge == [0; 32]
        {
            return Err(PqRecoveryWitnessError::InvalidShape);
        }
        if self.chain_id != trusted.chain_id {
            return Err(PqRecoveryWitnessError::ContextMismatch("chain_id"));
        }
        if self.witness_did != trusted.witness_did {
            return Err(PqRecoveryWitnessError::ContextMismatch("witness_did"));
        }
        if self.public_key != trusted.trusted_ml_dsa65_public_key {
            return Err(PqRecoveryWitnessError::ContextMismatch("public_key"));
        }
        if self.genesis != trusted.genesis {
            return Err(PqRecoveryWitnessError::ContextMismatch("genesis"));
        }
        if self.challenge != trusted.outstanding_challenge {
            return Err(PqRecoveryWitnessError::ContextMismatch("challenge"));
        }
        if self.sequence <= trusted.last_external_sequence {
            return Err(PqRecoveryWitnessError::StaleSequence);
        }
        if trusted.now_unix_s < self.issued_unix_s
            || trusted.now_unix_s > self.expires_unix_s
        {
            return Err(PqRecoveryWitnessError::TimeWindow);
        }
        if self.observed != *trusted.actual_local {
            return Err(PqRecoveryWitnessError::LocalRollbackOrDivergence);
        }
        let signature = Signature::<MlDsa65>::try_from(self.signature.as_slice())
            .map_err(|_| PqRecoveryWitnessError::InvalidSignatureEncoding)?;
        let encoded = EncodedVerifyingKey::<MlDsa65>::try_from(self.public_key.as_slice())
            .map_err(|_| PqRecoveryWitnessError::InvalidShape)?;
        if !VerifyingKey::<MlDsa65>::decode(&encoded).verify_with_context(
            &self.signing_bytes(),
            &[],
            &signature,
        ) {
            return Err(PqRecoveryWitnessError::InvalidSignature);
        }
        Ok(())
    }

    fn check_shape(&self) -> Result<(), PqRecoveryWitnessError> {
        if self.chain_id.is_empty()
            || self.chain_id.len() > 64
            || !self.chain_id.bytes().all(|b| {
                b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || matches!(b, b'-' | b'_' | b'.' | b':')
            })
            || !(5..=192).contains(&self.witness_did.len())
            || !self.witness_did.starts_with("did:")
            || !self.witness_did.bytes().all(|b| b.is_ascii_graphic())
            || self.public_key.len() != PUBLIC_KEY_BYTES
            || self.sequence == 0
            || self.observed.owner_generation == 0
            || [
                self.genesis,
                self.observed.tip,
                self.observed.state_root,
                self.observed.effect_journal_head,
                self.challenge,
            ]
            .contains(&[0; 32])
            || self.issued_unix_s == 0
            || self.expires_unix_s.checked_sub(self.issued_unix_s).is_none_or(|ttl| {
                ttl == 0 || ttl > MAX_WITNESS_TTL_SECONDS
            })
        {
            return Err(PqRecoveryWitnessError::InvalidShape);
        }
        Ok(())
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::default();
        e.array(16);
        e.text(DOMAIN);
        e.uint(PQ_RECOVERY_WITNESS_VERSION as u64);
        e.text(CANONICAL_ENCODING);
        e.text(&self.chain_id);
        e.text(&self.witness_did);
        e.bytes(&self.public_key);
        e.bytes(&self.genesis);
        e.bytes(&self.observed.tip);
        e.bytes(&self.observed.state_root);
        e.bytes(&self.observed.effect_journal_head);
        e.uint(self.observed.height);
        e.uint(self.observed.owner_generation);
        e.uint(self.sequence);
        e.bytes(&self.challenge);
        e.uint(self.issued_unix_s);
        e.uint(self.expires_unix_s);
        e.finish()
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        CanonicalCbor::canonical_bytes(self)
    }

    /// Untrusted parse only. This method grants NO authority, and deliberately
    /// does not verify the embedded self-selected key. Call verify_for_recovery
    /// with independent expectations before treating this as an observation.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PqRecoveryWitnessError> {
        if bytes.len() > MAX_PQ_RECOVERY_WITNESS_BYTES {
            return Err(PqRecoveryWitnessError::WireTooLarge);
        }
        let mut d = Decoder::new(bytes);
        d.array(16)?;
        if d.uint()? != PQ_RECOVERY_WITNESS_VERSION as u64 || d.text()? != CANONICAL_ENCODING {
            return Err(PqRecoveryWitnessError::VersionOrEncoding);
        }
        let chain_id = d.text()?;
        let witness_did = d.text()?;
        let key = d.bytes()?;
        if key.len() != PUBLIC_KEY_BYTES {
            return Err(PqRecoveryWitnessError::InvalidShape);
        }
        let public_key = key.to_vec();
        let genesis = d.bytes_exact()?;
        let tip = d.bytes_exact()?;
        let state_root = d.bytes_exact()?;
        let effect_journal_head = d.bytes_exact()?;
        let height = d.uint()?;
        let owner_generation = d.uint()?;
        let sequence = d.uint()?;
        let challenge = d.bytes_exact()?;
        let issued_unix_s = d.uint()?;
        let expires_unix_s = d.uint()?;
        let bytes_signature = d.bytes()?;
        if bytes_signature.len() != SIGNATURE_BYTES {
            return Err(PqRecoveryWitnessError::InvalidSignatureEncoding);
        }
        let signature = bytes_signature.to_vec();
        d.finish()?;
        let item = Self {
            chain_id,
            witness_did,
            public_key,
            genesis,
            observed: LocalRecoveryHeadV1 {
                tip,
                state_root,
                effect_journal_head,
                height,
                owner_generation,
            },
            sequence,
            challenge,
            issued_unix_s,
            expires_unix_s,
            signature,
        };
        if item.canonical_bytes() != bytes {
            return Err(CanonicalDecodeError::NonCanonicalRoundTrip.into());
        }
        item.check_shape()?;
        Ok(item)
    }
}

impl CanonicalCbor for SignedPqRecoveryWitnessV1 {
    fn encode_canonical(&self, e: &mut Encoder) {
        e.array(16);
        e.uint(PQ_RECOVERY_WITNESS_VERSION as u64);
        e.text(CANONICAL_ENCODING);
        e.text(&self.chain_id);
        e.text(&self.witness_did);
        e.bytes(&self.public_key);
        e.bytes(&self.genesis);
        e.bytes(&self.observed.tip);
        e.bytes(&self.observed.state_root);
        e.bytes(&self.observed.effect_journal_head);
        e.uint(self.observed.height);
        e.uint(self.observed.owner_generation);
        e.uint(self.sequence);
        e.bytes(&self.challenge);
        e.uint(self.issued_unix_s);
        e.uint(self.expires_unix_s);
        e.bytes(&self.signature);
    }
}
