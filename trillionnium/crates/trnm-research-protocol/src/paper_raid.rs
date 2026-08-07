use crate::canonical::{
    canonical_hash, CanonicalCbor, CanonicalDecodeError, Decoder, Encoder, CANONICAL_ENCODING,
};
use crate::command::AuthorityRole;
use crate::types::{Digest32, ExternalKey, ObjectRefV1, ResearchObjectKind};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Paper Raid's settlement-aware commitment is deliberately versioned outside
/// the frozen generic Research V1 command/state schema.
pub const PAPER_RAID_FINALITY_COMMITMENT_VERSION_V2: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum PaperRaidAppealStatusV2 {
    Open = 1,
    ClosedNoAppeal = 2,
    ResolvedUpheld = 3,
    ResolvedOverturned = 4,
}

impl CanonicalCbor for PaperRaidAppealStatusV2 {
    fn encode_canonical(&self, encoder: &mut Encoder) {
        encoder.uint(*self as u64);
    }
}

/// Immutable Paper Raid scientific-finality and settlement eligibility tuple.
///
/// The commitment binds the exact Paper/submission/release/bundle/consent,
/// evaluation, latest reproduction, appeal closure, and policy facts. A Chain
/// receipt can prove inclusion of this object without conflating scientific
/// finality with ranking or reward eligibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaperRaidFinalityCommitmentV2 {
    pub commitment_id: ExternalKey,
    pub paper_project_id: ExternalKey,
    pub submission_id: ExternalKey,
    pub match_evidence_ref: ObjectRefV1,
    pub release_candidate_hash: Digest32,
    pub paper_bundle_hash: Digest32,
    pub submission_commitment_hash: Digest32,
    pub author_consent_set_hash: Digest32,
    pub tolerance_policy_hash: Digest32,
    pub evaluation_id: ExternalKey,
    pub evaluation_hash: Digest32,
    pub evaluation_score_bps: u16,
    pub evaluation_accepted: bool,
    pub evaluation_completed_at_unix_s: u64,
    pub latest_reproduction_id: ExternalKey,
    pub latest_reproduction_hash: Digest32,
    pub latest_reproduction_accepted: bool,
    pub latest_reproduction_completed_at_unix_s: u64,
    pub evaluation_superseded_by: Option<ExternalKey>,
    pub reproduction_superseded_by: Option<ExternalKey>,
    pub appeal_status: PaperRaidAppealStatusV2,
    pub appeal_id: Option<ExternalKey>,
    pub appeal_resolution_hash: Option<Digest32>,
    pub appeal_window_closes_at_unix_s: u64,
    pub settlement_policy_hash: Digest32,
    pub scientific_finality: bool,
    pub score_eligible: bool,
    pub ranking_eligible: bool,
    pub reward_eligible: bool,
    pub economic_eligible: bool,
    pub finalized_at_unix_s: u64,
}

impl PaperRaidFinalityCommitmentV2 {
    pub fn validate(&self) -> Result<(), PaperRaidFinalityValidationError> {
        for (field, key) in [
            ("commitment_id", self.commitment_id),
            ("paper_project_id", self.paper_project_id),
            ("submission_id", self.submission_id),
            ("evaluation_id", self.evaluation_id),
            ("latest_reproduction_id", self.latest_reproduction_id),
        ] {
            ensure_key(field, key)?;
        }
        ensure_key("match_evidence_ref.key", self.match_evidence_ref.key)?;
        if self.match_evidence_ref.kind != ResearchObjectKind::MatchEvidence
            || self.match_evidence_ref.object_version == 0
        {
            return Err(PaperRaidFinalityValidationError::InvalidMatchEvidenceRef);
        }
        for (field, digest) in [
            ("release_candidate_hash", &self.release_candidate_hash),
            ("paper_bundle_hash", &self.paper_bundle_hash),
            (
                "submission_commitment_hash",
                &self.submission_commitment_hash,
            ),
            ("author_consent_set_hash", &self.author_consent_set_hash),
            ("tolerance_policy_hash", &self.tolerance_policy_hash),
            ("evaluation_hash", &self.evaluation_hash),
            ("latest_reproduction_hash", &self.latest_reproduction_hash),
            ("settlement_policy_hash", &self.settlement_policy_hash),
        ] {
            ensure_digest(field, digest)?;
        }
        if self.evaluation_score_bps > 10_000
            || (self.evaluation_accepted && self.evaluation_score_bps == 0)
            || (!self.evaluation_accepted && self.latest_reproduction_accepted)
        {
            return Err(PaperRaidFinalityValidationError::InconsistentEvaluation);
        }
        if self.evaluation_completed_at_unix_s == 0
            || self.latest_reproduction_completed_at_unix_s < self.evaluation_completed_at_unix_s
            || self.appeal_window_closes_at_unix_s < self.latest_reproduction_completed_at_unix_s
            || self.finalized_at_unix_s < self.appeal_window_closes_at_unix_s
        {
            return Err(PaperRaidFinalityValidationError::TimestampRegression);
        }
        if let Some(key) = self.evaluation_superseded_by {
            ensure_key("evaluation_superseded_by", key)?;
            return Err(PaperRaidFinalityValidationError::SupersededEvaluation);
        }
        if let Some(key) = self.reproduction_superseded_by {
            ensure_key("reproduction_superseded_by", key)?;
            return Err(PaperRaidFinalityValidationError::SupersededReproduction);
        }
        match self.appeal_status {
            PaperRaidAppealStatusV2::Open => {
                return Err(PaperRaidFinalityValidationError::AppealStillOpen)
            }
            PaperRaidAppealStatusV2::ClosedNoAppeal => {
                if self.appeal_id.is_some() || self.appeal_resolution_hash.is_some() {
                    return Err(PaperRaidFinalityValidationError::InconsistentAppeal);
                }
            }
            PaperRaidAppealStatusV2::ResolvedUpheld
            | PaperRaidAppealStatusV2::ResolvedOverturned => {
                let appeal_id = self
                    .appeal_id
                    .ok_or(PaperRaidFinalityValidationError::InconsistentAppeal)?;
                ensure_key("appeal_id", appeal_id)?;
                let resolution_hash = self
                    .appeal_resolution_hash
                    .as_ref()
                    .ok_or(PaperRaidFinalityValidationError::InconsistentAppeal)?;
                ensure_digest("appeal_resolution_hash", resolution_hash)?;
            }
        }
        if self.appeal_status == PaperRaidAppealStatusV2::ResolvedOverturned
            && self.evaluation_accepted
        {
            return Err(PaperRaidFinalityValidationError::InconsistentAppeal);
        }
        if !self.scientific_finality {
            return Err(PaperRaidFinalityValidationError::ScientificFinalityRequired);
        }

        let eligibility_base = self.evaluation_accepted
            && self.latest_reproduction_accepted
            && matches!(
                self.appeal_status,
                PaperRaidAppealStatusV2::ClosedNoAppeal | PaperRaidAppealStatusV2::ResolvedUpheld
            );
        if (self.score_eligible
            || self.ranking_eligible
            || self.reward_eligible
            || self.economic_eligible)
            && !eligibility_base
        {
            return Err(PaperRaidFinalityValidationError::EligibilityWithoutFinalFacts);
        }
        if self.ranking_eligible && !self.score_eligible {
            return Err(PaperRaidFinalityValidationError::InconsistentEligibility);
        }
        if self.reward_eligible
            && !(self.ranking_eligible && self.score_eligible && self.economic_eligible)
        {
            return Err(PaperRaidFinalityValidationError::InconsistentEligibility);
        }
        if self.economic_eligible && !self.reward_eligible {
            return Err(PaperRaidFinalityValidationError::InconsistentEligibility);
        }
        Ok(())
    }

    pub fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<Self, PaperRaidFinalityCommitmentDecodeError> {
        let mut decoder = Decoder::new(bytes);
        decoder.array(32)?;
        let version = decoder.uint()?;
        if version != PAPER_RAID_FINALITY_COMMITMENT_VERSION_V2 as u64 {
            return Err(CanonicalDecodeError::UnsupportedVersion(version).into());
        }
        let commitment = Self {
            commitment_id: decode_key(&mut decoder)?,
            paper_project_id: decode_key(&mut decoder)?,
            submission_id: decode_key(&mut decoder)?,
            match_evidence_ref: decode_object_ref(&mut decoder)?,
            release_candidate_hash: decoder.bytes_exact()?,
            paper_bundle_hash: decoder.bytes_exact()?,
            submission_commitment_hash: decoder.bytes_exact()?,
            author_consent_set_hash: decoder.bytes_exact()?,
            tolerance_policy_hash: decoder.bytes_exact()?,
            evaluation_id: decode_key(&mut decoder)?,
            evaluation_hash: decoder.bytes_exact()?,
            evaluation_score_bps: {
                let value = decoder.uint()?;
                u16::try_from(value)
                    .map_err(|_| PaperRaidFinalityCommitmentDecodeError::ScoreOutOfRange(value))?
            },
            evaluation_accepted: decoder.bool()?,
            evaluation_completed_at_unix_s: decoder.uint()?,
            latest_reproduction_id: decode_key(&mut decoder)?,
            latest_reproduction_hash: decoder.bytes_exact()?,
            latest_reproduction_accepted: decoder.bool()?,
            latest_reproduction_completed_at_unix_s: decoder.uint()?,
            evaluation_superseded_by: decode_option_key(&mut decoder)?,
            reproduction_superseded_by: decode_option_key(&mut decoder)?,
            appeal_status: decode_appeal_status(&mut decoder)?,
            appeal_id: decode_option_key(&mut decoder)?,
            appeal_resolution_hash: decode_option_digest(&mut decoder)?,
            appeal_window_closes_at_unix_s: decoder.uint()?,
            settlement_policy_hash: decoder.bytes_exact()?,
            scientific_finality: decoder.bool()?,
            score_eligible: decoder.bool()?,
            ranking_eligible: decoder.bool()?,
            reward_eligible: decoder.bool()?,
            economic_eligible: decoder.bool()?,
            finalized_at_unix_s: decoder.uint()?,
        };
        decoder.finish()?;
        commitment.validate()?;
        if commitment.canonical_bytes() != bytes {
            return Err(CanonicalDecodeError::NonCanonicalRoundTrip.into());
        }
        Ok(commitment)
    }
}

impl CanonicalCbor for PaperRaidFinalityCommitmentV2 {
    fn encode_canonical(&self, encoder: &mut Encoder) {
        encoder.array(32);
        encoder.uint(PAPER_RAID_FINALITY_COMMITMENT_VERSION_V2 as u64);
        self.commitment_id.encode_canonical(encoder);
        self.paper_project_id.encode_canonical(encoder);
        self.submission_id.encode_canonical(encoder);
        self.match_evidence_ref.encode_canonical(encoder);
        encoder.bytes(&self.release_candidate_hash);
        encoder.bytes(&self.paper_bundle_hash);
        encoder.bytes(&self.submission_commitment_hash);
        encoder.bytes(&self.author_consent_set_hash);
        encoder.bytes(&self.tolerance_policy_hash);
        self.evaluation_id.encode_canonical(encoder);
        encoder.bytes(&self.evaluation_hash);
        encoder.uint(self.evaluation_score_bps as u64);
        encoder.bool(self.evaluation_accepted);
        encoder.uint(self.evaluation_completed_at_unix_s);
        self.latest_reproduction_id.encode_canonical(encoder);
        encoder.bytes(&self.latest_reproduction_hash);
        encoder.bool(self.latest_reproduction_accepted);
        encoder.uint(self.latest_reproduction_completed_at_unix_s);
        encode_option_key(encoder, self.evaluation_superseded_by);
        encode_option_key(encoder, self.reproduction_superseded_by);
        self.appeal_status.encode_canonical(encoder);
        encode_option_key(encoder, self.appeal_id);
        encode_option_digest(encoder, &self.appeal_resolution_hash);
        encoder.uint(self.appeal_window_closes_at_unix_s);
        encoder.bytes(&self.settlement_policy_hash);
        encoder.bool(self.scientific_finality);
        encoder.bool(self.score_eligible);
        encoder.bool(self.ranking_eligible);
        encoder.bool(self.reward_eligible);
        encoder.bool(self.economic_eligible);
        encoder.uint(self.finalized_at_unix_s);
    }
}

/// Hepta-authorized, signature-bearing Paper Raid finality command.  It is a
/// separate V2 envelope so adding Paper settlement semantics cannot change the
/// frozen `SignedResearchCommandV1` wire or its command discriminants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPaperRaidFinalityCommandV2 {
    pub chain_id: String,
    pub command_id: ExternalKey,
    pub signer_did: String,
    pub signer_role: AuthorityRole,
    pub nonce: u64,
    pub public_key: [u8; 32],
    pub commitment: PaperRaidFinalityCommitmentV2,
    pub signature: Vec<u8>,
}

impl SignedPaperRaidFinalityCommandV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        chain_id: String,
        command_id: ExternalKey,
        signer_did: String,
        nonce: u64,
        commitment: PaperRaidFinalityCommitmentV2,
        signing_key: &SigningKey,
    ) -> Result<Self, SignedPaperRaidFinalityCommandValidationError> {
        let mut signed = Self {
            chain_id,
            command_id,
            signer_did,
            signer_role: AuthorityRole::HeptaAuthority,
            nonce,
            public_key: signing_key.verifying_key().to_bytes(),
            commitment,
            signature: Vec::new(),
        };
        signed.validate_unsigned()?;
        signed.signature = signing_key
            .sign(&signed.signing_bytes())
            .to_bytes()
            .to_vec();
        Ok(signed)
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut encoder = Encoder::default();
        encoder.array(9);
        encoder.uint(PAPER_RAID_FINALITY_COMMITMENT_VERSION_V2 as u64);
        encoder.text(CANONICAL_ENCODING);
        encoder.text(&self.chain_id);
        self.command_id.encode_canonical(&mut encoder);
        encoder.text(&self.signer_did);
        self.signer_role.encode_canonical(&mut encoder);
        encoder.uint(self.nonce);
        encoder.bytes(&self.public_key);
        self.commitment.encode_canonical(&mut encoder);
        encoder.finish()
    }

    pub fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<Self, SignedPaperRaidFinalityCommandValidationError> {
        let mut decoder = Decoder::new(bytes);
        decoder.array(10)?;
        let version = decoder.uint()?;
        if version != PAPER_RAID_FINALITY_COMMITMENT_VERSION_V2 as u64 {
            return Err(CanonicalDecodeError::UnsupportedVersion(version).into());
        }
        if decoder.text()? != CANONICAL_ENCODING {
            return Err(SignedPaperRaidFinalityCommandValidationError::EncodingMismatch);
        }
        let chain_id = decoder.text()?;
        let command_id = decode_key(&mut decoder)?;
        let signer_did = decoder.text()?;
        let signer_role = match decoder.uint()? {
            1 => AuthorityRole::NakamaAuthority,
            2 => AuthorityRole::HeptaAuthority,
            value => {
                return Err(CanonicalDecodeError::UnknownDiscriminant {
                    name: "AuthorityRole",
                    value,
                }
                .into())
            }
        };
        let nonce = decoder.uint()?;
        let public_key = decoder.bytes_exact()?;
        let commitment = decode_commitment(&mut decoder)?;
        let signature = decoder.bytes()?.to_vec();
        decoder.finish()?;
        let signed = Self {
            chain_id,
            command_id,
            signer_did,
            signer_role,
            nonce,
            public_key,
            commitment,
            signature,
        };
        if signed.canonical_bytes() != bytes {
            return Err(CanonicalDecodeError::NonCanonicalRoundTrip.into());
        }
        signed.validate()?;
        Ok(signed)
    }

    pub fn validate(&self) -> Result<(), SignedPaperRaidFinalityCommandValidationError> {
        self.validate_unsigned()?;
        let signature_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| SignedPaperRaidFinalityCommandValidationError::InvalidSignature)?;
        let verifying_key = VerifyingKey::from_bytes(&self.public_key)
            .map_err(|_| SignedPaperRaidFinalityCommandValidationError::InvalidPublicKey)?;
        verifying_key
            .verify_strict(
                &self.signing_bytes(),
                &Signature::from_bytes(&signature_bytes),
            )
            .map_err(|_| SignedPaperRaidFinalityCommandValidationError::InvalidSignature)
    }

    pub fn command_fingerprint(&self) -> Digest32 {
        canonical_hash(
            "trnm-paper-raid-finality-command-fingerprint-v2",
            &self.signing_bytes(),
        )
    }

    pub fn payload_hash(&self) -> Digest32 {
        self.commitment
            .canonical_hash("trnm-paper-raid-finality-commitment-v2")
    }

    fn validate_unsigned(&self) -> Result<(), SignedPaperRaidFinalityCommandValidationError> {
        validate_chain_id(&self.chain_id)?;
        ensure_key("command_id", self.command_id)?;
        validate_signer_did(&self.signer_did)?;
        if self.signer_role != AuthorityRole::HeptaAuthority {
            return Err(SignedPaperRaidFinalityCommandValidationError::HeptaAuthorityRequired);
        }
        if self.nonce == 0 {
            return Err(SignedPaperRaidFinalityCommandValidationError::ZeroNonce);
        }
        if self.public_key == [0; 32] || VerifyingKey::from_bytes(&self.public_key).is_err() {
            return Err(SignedPaperRaidFinalityCommandValidationError::InvalidPublicKey);
        }
        self.commitment.validate()?;
        Ok(())
    }
}

impl CanonicalCbor for SignedPaperRaidFinalityCommandV2 {
    fn encode_canonical(&self, encoder: &mut Encoder) {
        encoder.array(10);
        encoder.uint(PAPER_RAID_FINALITY_COMMITMENT_VERSION_V2 as u64);
        encoder.text(CANONICAL_ENCODING);
        encoder.text(&self.chain_id);
        self.command_id.encode_canonical(encoder);
        encoder.text(&self.signer_did);
        self.signer_role.encode_canonical(encoder);
        encoder.uint(self.nonce);
        encoder.bytes(&self.public_key);
        self.commitment.encode_canonical(encoder);
        encoder.bytes(&self.signature);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PaperRaidFinalityValidationError {
    #[error("{0} must be a non-zero ExternalKey")]
    ZeroExternalKey(&'static str),
    #[error("{0} must be a non-zero digest")]
    ZeroDigest(&'static str),
    #[error("match_evidence_ref must reference a positive-version MatchEvidence object")]
    InvalidMatchEvidenceRef,
    #[error("evaluation and reproduction decisions are inconsistent")]
    InconsistentEvaluation,
    #[error("Paper Raid finality timestamps regress")]
    TimestampRegression,
    #[error("superseded evaluation cannot be finalized")]
    SupersededEvaluation,
    #[error("superseded reproduction cannot be finalized")]
    SupersededReproduction,
    #[error("appeal window is still open")]
    AppealStillOpen,
    #[error("appeal identity, resolution, and outcome are inconsistent")]
    InconsistentAppeal,
    #[error("scientific_finality must be true for a finality commitment")]
    ScientificFinalityRequired,
    #[error("eligibility cannot be granted before accepted final facts")]
    EligibilityWithoutFinalFacts,
    #[error("ranking, score, reward, and economic eligibility are inconsistent")]
    InconsistentEligibility,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PaperRaidFinalityCommitmentDecodeError {
    #[error(transparent)]
    Canonical(#[from] CanonicalDecodeError),
    #[error(transparent)]
    Validation(#[from] PaperRaidFinalityValidationError),
    #[error("evaluation_score_bps {0} exceeds u16")]
    ScoreOutOfRange(u64),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SignedPaperRaidFinalityCommandValidationError {
    #[error(transparent)]
    Canonical(#[from] CanonicalDecodeError),
    #[error(transparent)]
    Commitment(#[from] PaperRaidFinalityValidationError),
    #[error("unsupported canonical encoding")]
    EncodingMismatch,
    #[error("chain_id must be canonical lowercase ASCII")]
    InvalidChainId,
    #[error("signer_did must be a canonical did:* token")]
    InvalidSignerDid,
    #[error("Paper Raid finality must be signed by a Hepta authority")]
    HeptaAuthorityRequired,
    #[error("nonce must be positive")]
    ZeroNonce,
    #[error("invalid Ed25519 public key")]
    InvalidPublicKey,
    #[error("invalid Ed25519 signature")]
    InvalidSignature,
}

fn ensure_key(
    field: &'static str,
    key: ExternalKey,
) -> Result<(), PaperRaidFinalityValidationError> {
    if key.as_bytes() == &[0; 32] {
        Err(PaperRaidFinalityValidationError::ZeroExternalKey(field))
    } else {
        Ok(())
    }
}

fn ensure_digest(
    field: &'static str,
    digest: &Digest32,
) -> Result<(), PaperRaidFinalityValidationError> {
    if digest == &[0; 32] {
        Err(PaperRaidFinalityValidationError::ZeroDigest(field))
    } else {
        Ok(())
    }
}

fn encode_option_key(encoder: &mut Encoder, key: Option<ExternalKey>) {
    match key {
        Some(key) => key.encode_canonical(encoder),
        None => encoder.null(),
    }
}

fn encode_option_digest(encoder: &mut Encoder, digest: &Option<Digest32>) {
    match digest {
        Some(digest) => encoder.bytes(digest),
        None => encoder.null(),
    }
}

fn decode_key(decoder: &mut Decoder<'_>) -> Result<ExternalKey, CanonicalDecodeError> {
    Ok(ExternalKey::from_bytes(decoder.bytes_exact()?))
}

fn decode_option_key(
    decoder: &mut Decoder<'_>,
) -> Result<Option<ExternalKey>, CanonicalDecodeError> {
    if decoder.consume_null() {
        Ok(None)
    } else {
        decode_key(decoder).map(Some)
    }
}

fn decode_option_digest(
    decoder: &mut Decoder<'_>,
) -> Result<Option<Digest32>, CanonicalDecodeError> {
    if decoder.consume_null() {
        Ok(None)
    } else {
        decoder.bytes_exact().map(Some)
    }
}

fn decode_object_ref(decoder: &mut Decoder<'_>) -> Result<ObjectRefV1, CanonicalDecodeError> {
    decoder.array(4)?;
    let version = decoder.uint()?;
    if version != crate::types::PROTOCOL_VERSION as u64 {
        return Err(CanonicalDecodeError::UnsupportedVersion(version));
    }
    let kind = match decoder.uint()? {
        1 => ResearchObjectKind::MatchEvidence,
        2 => ResearchObjectKind::EvaluationCommitment,
        3 => ResearchObjectKind::WorkloadReceipt,
        4 => ResearchObjectKind::ResearchClaim,
        5 => ResearchObjectKind::LicenseDeclaration,
        6 => ResearchObjectKind::ClaimChallenge,
        7 => ResearchObjectKind::ClaimResolution,
        value => {
            return Err(CanonicalDecodeError::UnknownDiscriminant {
                name: "ResearchObjectKind",
                value,
            })
        }
    };
    Ok(ObjectRefV1 {
        kind,
        key: decode_key(decoder)?,
        object_version: decoder.uint()?,
    })
}

fn decode_appeal_status(
    decoder: &mut Decoder<'_>,
) -> Result<PaperRaidAppealStatusV2, CanonicalDecodeError> {
    match decoder.uint()? {
        1 => Ok(PaperRaidAppealStatusV2::Open),
        2 => Ok(PaperRaidAppealStatusV2::ClosedNoAppeal),
        3 => Ok(PaperRaidAppealStatusV2::ResolvedUpheld),
        4 => Ok(PaperRaidAppealStatusV2::ResolvedOverturned),
        value => Err(CanonicalDecodeError::UnknownDiscriminant {
            name: "PaperRaidAppealStatusV2",
            value,
        }),
    }
}

fn decode_commitment(
    decoder: &mut Decoder<'_>,
) -> Result<PaperRaidFinalityCommitmentV2, CanonicalDecodeError> {
    decoder.array(32)?;
    let version = decoder.uint()?;
    if version != PAPER_RAID_FINALITY_COMMITMENT_VERSION_V2 as u64 {
        return Err(CanonicalDecodeError::UnsupportedVersion(version));
    }
    Ok(PaperRaidFinalityCommitmentV2 {
        commitment_id: decode_key(decoder)?,
        paper_project_id: decode_key(decoder)?,
        submission_id: decode_key(decoder)?,
        match_evidence_ref: decode_object_ref(decoder)?,
        release_candidate_hash: decoder.bytes_exact()?,
        paper_bundle_hash: decoder.bytes_exact()?,
        submission_commitment_hash: decoder.bytes_exact()?,
        author_consent_set_hash: decoder.bytes_exact()?,
        tolerance_policy_hash: decoder.bytes_exact()?,
        evaluation_id: decode_key(decoder)?,
        evaluation_hash: decoder.bytes_exact()?,
        evaluation_score_bps: {
            let value = decoder.uint()?;
            u16::try_from(value).map_err(|_| CanonicalDecodeError::UnknownDiscriminant {
                name: "evaluation_score_bps",
                value,
            })?
        },
        evaluation_accepted: decoder.bool()?,
        evaluation_completed_at_unix_s: decoder.uint()?,
        latest_reproduction_id: decode_key(decoder)?,
        latest_reproduction_hash: decoder.bytes_exact()?,
        latest_reproduction_accepted: decoder.bool()?,
        latest_reproduction_completed_at_unix_s: decoder.uint()?,
        evaluation_superseded_by: decode_option_key(decoder)?,
        reproduction_superseded_by: decode_option_key(decoder)?,
        appeal_status: decode_appeal_status(decoder)?,
        appeal_id: decode_option_key(decoder)?,
        appeal_resolution_hash: decode_option_digest(decoder)?,
        appeal_window_closes_at_unix_s: decoder.uint()?,
        settlement_policy_hash: decoder.bytes_exact()?,
        scientific_finality: decoder.bool()?,
        score_eligible: decoder.bool()?,
        ranking_eligible: decoder.bool()?,
        reward_eligible: decoder.bool()?,
        economic_eligible: decoder.bool()?,
        finalized_at_unix_s: decoder.uint()?,
    })
}

fn validate_chain_id(chain_id: &str) -> Result<(), SignedPaperRaidFinalityCommandValidationError> {
    if chain_id.is_empty()
        || chain_id.len() > 64
        || !chain_id.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
    {
        Err(SignedPaperRaidFinalityCommandValidationError::InvalidChainId)
    } else {
        Ok(())
    }
}

fn validate_signer_did(
    signer_did: &str,
) -> Result<(), SignedPaperRaidFinalityCommandValidationError> {
    if signer_did.len() < 5
        || signer_did.len() > 192
        || !signer_did.starts_with("did:")
        || !signer_did.bytes().all(|byte| byte.is_ascii_graphic())
    {
        Err(SignedPaperRaidFinalityCommandValidationError::InvalidSignerDid)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> ExternalKey {
        ExternalKey::from_bytes([byte; 32])
    }

    fn commitment() -> PaperRaidFinalityCommitmentV2 {
        PaperRaidFinalityCommitmentV2 {
            commitment_id: key(1),
            paper_project_id: key(2),
            submission_id: key(3),
            match_evidence_ref: ObjectRefV1::new(ResearchObjectKind::MatchEvidence, key(4), 1),
            release_candidate_hash: [5; 32],
            paper_bundle_hash: [6; 32],
            submission_commitment_hash: [7; 32],
            author_consent_set_hash: [8; 32],
            tolerance_policy_hash: [9; 32],
            evaluation_id: key(10),
            evaluation_hash: [11; 32],
            evaluation_score_bps: 8_500,
            evaluation_accepted: true,
            evaluation_completed_at_unix_s: 100,
            latest_reproduction_id: key(12),
            latest_reproduction_hash: [13; 32],
            latest_reproduction_accepted: true,
            latest_reproduction_completed_at_unix_s: 110,
            evaluation_superseded_by: None,
            reproduction_superseded_by: None,
            appeal_status: PaperRaidAppealStatusV2::ClosedNoAppeal,
            appeal_id: None,
            appeal_resolution_hash: None,
            appeal_window_closes_at_unix_s: 120,
            settlement_policy_hash: [14; 32],
            scientific_finality: true,
            score_eligible: true,
            ranking_eligible: true,
            reward_eligible: true,
            economic_eligible: true,
            finalized_at_unix_s: 121,
        }
    }

    #[test]
    fn canonical_roundtrip_binds_complete_finality_tuple() {
        let commitment = commitment();
        commitment.validate().unwrap();
        let bytes = commitment.canonical_bytes();
        assert_eq!(
            PaperRaidFinalityCommitmentV2::from_canonical_bytes(&bytes).unwrap(),
            commitment
        );

        let mut trailing = bytes;
        trailing.push(0);
        assert!(PaperRaidFinalityCommitmentV2::from_canonical_bytes(&trailing).is_err());
    }

    #[test]
    fn eligibility_fails_closed_for_open_appeal_and_non_latest_facts() {
        let mut value = commitment();
        value.appeal_status = PaperRaidAppealStatusV2::Open;
        assert_eq!(
            value.validate(),
            Err(PaperRaidFinalityValidationError::AppealStillOpen)
        );

        let mut value = commitment();
        value.evaluation_superseded_by = Some(key(15));
        assert_eq!(
            value.validate(),
            Err(PaperRaidFinalityValidationError::SupersededEvaluation)
        );

        let mut value = commitment();
        value.reproduction_superseded_by = Some(key(16));
        assert_eq!(
            value.validate(),
            Err(PaperRaidFinalityValidationError::SupersededReproduction)
        );
    }

    #[test]
    fn scientific_finality_does_not_imply_settlement_eligibility() {
        let mut value = commitment();
        value.score_eligible = false;
        value.ranking_eligible = false;
        value.reward_eligible = false;
        value.economic_eligible = false;
        value.validate().unwrap();

        value.ranking_eligible = true;
        assert_eq!(
            value.validate(),
            Err(PaperRaidFinalityValidationError::InconsistentEligibility)
        );
    }

    #[test]
    fn rejected_or_overturned_facts_cannot_unlock_eligibility() {
        let mut value = commitment();
        value.latest_reproduction_accepted = false;
        assert_eq!(
            value.validate(),
            Err(PaperRaidFinalityValidationError::EligibilityWithoutFinalFacts)
        );

        let mut value = commitment();
        value.evaluation_accepted = false;
        value.latest_reproduction_accepted = false;
        value.evaluation_score_bps = 0;
        value.appeal_status = PaperRaidAppealStatusV2::ResolvedOverturned;
        value.appeal_id = Some(key(17));
        value.appeal_resolution_hash = Some([18; 32]);
        value.score_eligible = false;
        value.ranking_eligible = false;
        value.reward_eligible = false;
        value.economic_eligible = false;
        value.validate().unwrap();
    }

    #[test]
    fn signed_v2_command_roundtrips_and_binds_every_finality_field() {
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let signed = SignedPaperRaidFinalityCommandV2::sign(
            "trnm-paper-raid-test".to_string(),
            key(19),
            "did:trnm:hepta-paper-raid".to_string(),
            7,
            commitment(),
            &signing_key,
        )
        .unwrap();
        let bytes = signed.canonical_bytes();
        assert_eq!(
            SignedPaperRaidFinalityCommandV2::from_canonical_bytes(&bytes).unwrap(),
            signed
        );

        let mut tampered = signed.clone();
        tampered.commitment.paper_bundle_hash = [0x77; 32];
        assert_eq!(
            tampered.validate(),
            Err(SignedPaperRaidFinalityCommandValidationError::InvalidSignature)
        );
        assert_ne!(tampered.command_fingerprint(), signed.command_fingerprint());
    }

    #[test]
    fn signed_v2_command_rejects_non_hepta_role_before_signature_use() {
        let signing_key = SigningKey::from_bytes(&[0x43; 32]);
        let mut signed = SignedPaperRaidFinalityCommandV2::sign(
            "trnm-paper-raid-test".to_string(),
            key(20),
            "did:trnm:hepta-paper-raid".to_string(),
            8,
            commitment(),
            &signing_key,
        )
        .unwrap();
        signed.signer_role = AuthorityRole::NakamaAuthority;
        assert_eq!(
            signed.validate(),
            Err(SignedPaperRaidFinalityCommandValidationError::HeptaAuthorityRequired)
        );
    }
}
