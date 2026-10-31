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

/// Signed facts assembled by the external observer before ML-DSA signing.
/// This value is data only; it does not prove the observer is independent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqRecoveryWitnessStatementV1 {
    pub chain_id: String,
    pub witness_did: String,
    pub genesis: Digest32,
    pub observed: LocalRecoveryHeadV1,
    pub sequence: u64,
    pub challenge: Digest32,
    pub issued_unix_s: u64,
    pub expires_unix_s: u64,
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
        statement: PqRecoveryWitnessStatementV1,
        key: &SigningKey<MlDsa65>,
    ) -> Result<Self, PqRecoveryWitnessError> {
        let mut witness = Self {
            chain_id: statement.chain_id,
            witness_did: statement.witness_did,
            public_key: key.verifying_key().to_bytes().to_vec(),
            genesis: statement.genesis,
            observed: statement.observed,
            sequence: statement.sequence,
            challenge: statement.challenge,
            issued_unix_s: statement.issued_unix_s,
            expires_unix_s: statement.expires_unix_s,
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
        self.preflight_for_recovery(trusted)?;
        self.verify_signature()
    }

    /// Read a caller-trusted clock *after* ML-DSA verification. The previous
    /// preflight snapshot may expire while cryptographic work is in progress.
    /// This grants no recovery authority, nor a monotonic-sequence write.
    /// The callback must read fresh independent time, not witness data.
    pub fn verify_for_recovery_with_fresh_time(
        &self,
        trusted: &ExternalRecoveryExpectationV1<'_>,
        after_verify_unix_s: impl FnOnce() -> u64,
    ) -> Result<(), PqRecoveryWitnessError> {
        self.verify_for_recovery(trusted)?;
        let post_verify_unix_s = after_verify_unix_s();
        if post_verify_unix_s < trusted.now_unix_s
            || post_verify_unix_s < self.issued_unix_s
            || post_verify_unix_s >= self.expires_unix_s
        {
            return Err(PqRecoveryWitnessError::TimeWindow);
        }
        Ok(())
    }

    // No ML-DSA verification or key expansion here. In a quorum, check every
    // provided witness for cheap context and shape errors before verifying any
    // signatures, including invalid extra witnesses.
    fn preflight_for_recovery(
        &self,
        trusted: &ExternalRecoveryExpectationV1<'_>,
    ) -> Result<(), PqRecoveryWitnessError> {
        self.check_shape()?;
        if self.signature.len() != SIGNATURE_BYTES {
            return Err(PqRecoveryWitnessError::InvalidSignatureEncoding);
        }
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
        // Expiry is an exclusive UNIX-second boundary: accepting a witness
        // at now == expires would keep expired recovery authority alive for
        // one additional second. Apply this at the shared single/quorum
        // cheap preflight, before any ML-DSA verification.
        if trusted.now_unix_s < self.issued_unix_s || trusted.now_unix_s >= self.expires_unix_s {
            return Err(PqRecoveryWitnessError::TimeWindow);
        }
        if self.observed != *trusted.actual_local {
            return Err(PqRecoveryWitnessError::LocalRollbackOrDivergence);
        }
        Ok(())
    }

    fn verify_signature(&self) -> Result<(), PqRecoveryWitnessError> {
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
            || self
                .expires_unix_s
                .checked_sub(self.issued_unix_s)
                .is_none_or(|ttl| ttl == 0 || ttl > MAX_WITNESS_TTL_SECONDS)
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

/// A bounded roster of independently *pinned* recovery witnesses. This is
/// not itself evidence that the keys are held by independent operators.
pub const MAX_PQ_RECOVERY_QUORUM_SIGNERS_V1: usize = 16;

/// Caller-owned, out-of-band authority: these values must never be recovered
/// exclusively from the potentially rolled-back database.
#[derive(Clone, Copy)]
pub struct PqRecoveryTrustedSignerV1<'a> {
    pub witness_did: &'a str,
    pub trusted_ml_dsa65_public_key: &'a [u8],
    pub last_external_sequence: u64,
    pub outstanding_challenge: Digest32,
}

/// This policy is obtained from independently retained configuration and
/// monotonic floors. A majority threshold guarantees signer-set intersection
/// only while the roster itself is held fixed.
pub struct PqRecoveryQuorumPolicyV1<'a> {
    pub chain_id: &'a str,
    pub genesis: Digest32,
    pub now_unix_s: u64,
    pub actual_local: &'a LocalRecoveryHeadV1,
    pub roster: &'a [PqRecoveryTrustedSignerV1<'a>],
    pub threshold: usize,
}

#[derive(Debug, Error)]
pub enum PqRecoveryQuorumErrorV1 {
    #[error("invalid or non-majority recovery quorum policy")]
    InvalidPolicy,
    #[error("duplicate witness DID or ML-DSA key in pinned quorum roster")]
    DuplicateRosterIdentity,
    #[error("untrusted or excessive witness receipt")]
    UntrustedWitness,
    #[error("duplicate receipt for one pinned witness")]
    DuplicateWitness,
    #[error("not enough distinct, valid post-quantum witness receipts")]
    InsufficientQuorum,
    #[error(transparent)]
    Witness(#[from] PqRecoveryWitnessError),
}

/// A read-only quorum observation, NOT permission to install, spend, finalize,
/// replay effects, or advance an external monotonic counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedPqRecoveryQuorumV1 {
    verified_signers: usize,
}

impl ObservedPqRecoveryQuorumV1 {
    pub fn verified_signers(&self) -> usize {
        self.verified_signers
    }
}

/// Reject mixed contexts, forged keys, duplicate signers, stale or conflicting
/// observations, malformed policies and non-majority thresholds. Every
/// presented receipt must verify; invalid extras cannot be silently ignored.
///
/// The caller MUST independently persist each accepted witness high-water
/// sequence and consume the one-time challenges *before* granting any local
/// recovery capability. This function deliberately performs neither action.
pub fn verify_pq_recovery_quorum_v1(
    receipts: &[SignedPqRecoveryWitnessV1],
    policy: &PqRecoveryQuorumPolicyV1<'_>,
) -> Result<ObservedPqRecoveryQuorumV1, PqRecoveryQuorumErrorV1> {
    let roster = policy.roster;
    if !(2..=MAX_PQ_RECOVERY_QUORUM_SIGNERS_V1).contains(&roster.len())
        || policy.threshold <= roster.len() / 2
        || policy.threshold > roster.len()
        || policy.chain_id.is_empty()
        || policy.chain_id.len() > 64
        || !policy.chain_id.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.' | b':')
        })
        || policy.genesis == [0; 32]
        || policy.now_unix_s == 0
        || policy.actual_local.owner_generation == 0
        || [
            policy.actual_local.tip,
            policy.actual_local.state_root,
            policy.actual_local.effect_journal_head,
        ]
        .contains(&[0; 32])
    {
        return Err(PqRecoveryQuorumErrorV1::InvalidPolicy);
    }
    for (index, member) in roster.iter().enumerate() {
        if !(5..=192).contains(&member.witness_did.len())
            || !member.witness_did.starts_with("did:")
            || !member.witness_did.bytes().all(|b| b.is_ascii_graphic())
            || member.trusted_ml_dsa65_public_key.len() != PUBLIC_KEY_BYTES
            || member.last_external_sequence == u64::MAX
            || member.outstanding_challenge == [0; 32]
        {
            return Err(PqRecoveryQuorumErrorV1::InvalidPolicy);
        }
        if roster[..index].iter().any(|previous| {
            previous.witness_did == member.witness_did
                || previous.trusted_ml_dsa65_public_key == member.trusted_ml_dsa65_public_key
        }) {
            return Err(PqRecoveryQuorumErrorV1::DuplicateRosterIdentity);
        }
    }
    if receipts.len() > roster.len() {
        return Err(PqRecoveryQuorumErrorV1::UntrustedWitness);
    }
    // A minority of witnesses cannot authorize recovery; do not spend any
    // signature-verification work before rejecting it.
    if receipts.len() < policy.threshold {
        return Err(PqRecoveryQuorumErrorV1::InsufficientQuorum);
    }
    let mut seen = [false; MAX_PQ_RECOVERY_QUORUM_SIGNERS_V1];
    // First preflight the entire batch. One forged early signature must not
    // force ML-DSA work before a later cheap replay, expiry, duplicate or
    // out-of-roster rejection can be discovered.
    for receipt in receipts {
        let index = roster
            .iter()
            .position(|member| member.witness_did == receipt.witness_did)
            .ok_or(PqRecoveryQuorumErrorV1::UntrustedWitness)?;
        if seen[index] {
            return Err(PqRecoveryQuorumErrorV1::DuplicateWitness);
        }
        seen[index] = true;
        let member = &roster[index];
        let expectation = ExternalRecoveryExpectationV1 {
            chain_id: policy.chain_id,
            witness_did: member.witness_did,
            trusted_ml_dsa65_public_key: member.trusted_ml_dsa65_public_key,
            genesis: policy.genesis,
            outstanding_challenge: member.outstanding_challenge,
            last_external_sequence: member.last_external_sequence,
            now_unix_s: policy.now_unix_s,
            actual_local: policy.actual_local,
        };
        receipt.preflight_for_recovery(&expectation)?;
    }
    // Every presented witness has passed the complete cheap policy preflight.
    // Now, and only now, perform the costly ML-DSA signature checks. A
    // signature failure still rejects the whole batch, not just one signer.
    for receipt in receipts {
        receipt.verify_signature()?;
    }
    Ok(ObservedPqRecoveryQuorumV1 {
        verified_signers: receipts.len(),
    })
}

/// Check all quorum signatures against the cached initial time, then require
/// a fresh trusted time reading before returning an observation. Any clock
/// rollback or expiry of even one supplied receipt rejects the whole quorum.
/// Recovery owners must independently persist sequence floors, consume the
/// one-use challenges, and recheck State and effect-journal ownership.
pub fn verify_pq_recovery_quorum_with_fresh_time_v1(
    receipts: &[SignedPqRecoveryWitnessV1],
    policy: &PqRecoveryQuorumPolicyV1<'_>,
    after_verify_unix_s: impl FnOnce() -> u64,
) -> Result<ObservedPqRecoveryQuorumV1, PqRecoveryQuorumErrorV1> {
    let observed = verify_pq_recovery_quorum_v1(receipts, policy)?;
    let post_verify_unix_s = after_verify_unix_s();
    if post_verify_unix_s < policy.now_unix_s
        || receipts.iter().any(|receipt| {
            post_verify_unix_s < receipt.issued_unix_s
                || post_verify_unix_s >= receipt.expires_unix_s
        })
    {
        return Err(PqRecoveryQuorumErrorV1::Witness(
            PqRecoveryWitnessError::TimeWindow,
        ));
    }
    Ok(observed)
}
