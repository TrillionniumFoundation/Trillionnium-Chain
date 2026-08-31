//! Candidate-only closed verification-profile registry and challenge lifecycle.
//!
//! Exact profile resolution and evidence binding happen before backend
//! invocation. The resulting decision never moves settlement assets, changes
//! Order finality or becomes PoCO weight in this package.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use sha2::{Digest, Sha256};

pub const VERIFICATION_PROFILE_FALLBACK_ALLOWED_V1: bool = false;
pub const VERIFICATION_PROFILES_GLOBALLY_ENABLED_V1: bool = false;
pub const VERIFICATION_DECISION_ECONOMIC_AUTHORITY_V1: bool = false;
pub const VERIFICATION_DECISION_ORDER_REORG_AUTHORITY_V1: bool = false;
pub const VERIFICATION_DECISION_POCO_WEIGHT_AUTHORITY_V1: bool = false;

pub type VerificationDigestV1 = [u8; 32];
pub type VerificationProfileIdV1 = [u8; 32];
pub type VerificationObjectIdV1 = [u8; 32];
pub type VerificationActorIdV1 = [u8; 32];

const STATEMENT_DOMAIN_V1: &[u8] = b"trnm.g2c.verification-statement.v1\0";
const DECISION_DOMAIN_V1: &[u8] = b"trnm.g2c.verification-decision.v1\0";
const CHALLENGE_DOMAIN_V1: &[u8] = b"trnm.g2c.challenge-record.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VerificationProfileKindV1 {
    DeterministicReexecution,
    ReproducibleMachineLearning,
    ZeroKnowledge,
    TrustedExecutionEnvironment,
    StakeQuorum,
    Optimistic,
    Subjective,
}

impl VerificationProfileKindV1 {
    const ALL: [Self; 7] = [
        Self::DeterministicReexecution,
        Self::ReproducibleMachineLearning,
        Self::ZeroKnowledge,
        Self::TrustedExecutionEnvironment,
        Self::StakeQuorum,
        Self::Optimistic,
        Self::Subjective,
    ];

    const fn tag(self) -> u8 {
        match self {
            Self::DeterministicReexecution => 0,
            Self::ReproducibleMachineLearning => 1,
            Self::ZeroKnowledge => 2,
            Self::TrustedExecutionEnvironment => 3,
            Self::StakeQuorum => 4,
            Self::Optimistic => 5,
            Self::Subjective => 6,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationProfileErrorV1 {
    ZeroIdentifier,
    ZeroVersion,
    InvalidHeightRange,
    DuplicateKind,
    DuplicateProfileIdentity,
    IncompleteRegistry,
    ProfileNotFound,
    ProfileHashMismatch,
    ProfileDisabled,
    ProfileNotYetValid,
    ProfileExpired,
    ProfileRevoked,
    SubjectiveAuthorityEscalation,
    MalformedStatement,
    EvidenceBindingMismatch,
    EvidenceWindowClosed,
    BackendUnavailable,
    ArithmeticOverflow,
    DuplicateChallenge,
    ChallengeNotFound,
    InvalidChallengePhase,
    ChallengeDeadlineMissed,
    AppealAlreadyUsed,
}

impl fmt::Display for VerificationProfileErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZeroIdentifier => "verification identifier is zero",
            Self::ZeroVersion => "verification profile version is zero",
            Self::InvalidHeightRange => "verification height range is invalid",
            Self::DuplicateKind => "verification profile kind is duplicated",
            Self::DuplicateProfileIdentity => "verification profile identity is duplicated",
            Self::IncompleteRegistry => "verification profile registry is incomplete",
            Self::ProfileNotFound => "verification profile was not found",
            Self::ProfileHashMismatch => "verification profile hash differs",
            Self::ProfileDisabled => "verification profile is disabled",
            Self::ProfileNotYetValid => "verification profile is not yet valid",
            Self::ProfileExpired => "verification profile expired",
            Self::ProfileRevoked => "verification profile was revoked",
            Self::SubjectiveAuthorityEscalation => "subjective profile requests objective authority",
            Self::MalformedStatement => "verification statement is malformed",
            Self::EvidenceBindingMismatch => "verification evidence binding differs",
            Self::EvidenceWindowClosed => "verification evidence window is closed",
            Self::BackendUnavailable => "verification backend is unavailable",
            Self::ArithmeticOverflow => "verification arithmetic overflowed",
            Self::DuplicateChallenge => "a challenge already exists for this result",
            Self::ChallengeNotFound => "challenge was not found",
            Self::InvalidChallengePhase => "challenge transition is invalid",
            Self::ChallengeDeadlineMissed => "challenge deadline was missed",
            Self::AppealAlreadyUsed => "challenge appeal was already used",
        })
    }
}

impl std::error::Error for VerificationProfileErrorV1 {}

pub type VerificationProfileResultV1<T> = Result<T, VerificationProfileErrorV1>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationProfileV1 {
    pub profile_id: VerificationProfileIdV1,
    pub version: u32,
    pub profile_hash: VerificationDigestV1,
    pub kind: VerificationProfileKindV1,
    pub enabled: bool,
    pub valid_from_height: u64,
    pub expires_at_height: Option<u64>,
    pub revoked_at_height: Option<u64>,
    pub objective_settlement_allowed: bool,
    pub poco_weight_allowed: bool,
}

impl VerificationProfileV1 {
    pub fn validate(self) -> VerificationProfileResultV1<Self> {
        require_nonzero(&self.profile_id)?;
        require_nonzero(&self.profile_hash)?;
        if self.version == 0 {
            return Err(VerificationProfileErrorV1::ZeroVersion);
        }
        if self
            .expires_at_height
            .is_some_and(|height| height < self.valid_from_height)
            || self
                .revoked_at_height
                .is_some_and(|height| height < self.valid_from_height)
        {
            return Err(VerificationProfileErrorV1::InvalidHeightRange);
        }
        if self.kind == VerificationProfileKindV1::Subjective
            && (self.objective_settlement_allowed || self.poco_weight_allowed)
        {
            return Err(VerificationProfileErrorV1::SubjectiveAuthorityEscalation);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationProfileRegistryV1 {
    by_identity: BTreeMap<(VerificationProfileIdV1, u32), VerificationProfileV1>,
}

impl VerificationProfileRegistryV1 {
    pub fn closed(profiles: Vec<VerificationProfileV1>) -> VerificationProfileResultV1<Self> {
        let mut kinds = BTreeSet::new();
        let mut by_identity = BTreeMap::new();
        for profile in profiles {
            let profile = profile.validate()?;
            if !kinds.insert(profile.kind) {
                return Err(VerificationProfileErrorV1::DuplicateKind);
            }
            if by_identity
                .insert((profile.profile_id, profile.version), profile)
                .is_some()
            {
                return Err(VerificationProfileErrorV1::DuplicateProfileIdentity);
            }
        }
        if kinds != VerificationProfileKindV1::ALL.into_iter().collect() {
            return Err(VerificationProfileErrorV1::IncompleteRegistry);
        }
        Ok(Self { by_identity })
    }

    pub fn resolve_exact(
        &self,
        profile_id: VerificationProfileIdV1,
        version: u32,
        expected_hash: VerificationDigestV1,
        height: u64,
    ) -> VerificationProfileResultV1<VerificationProfileV1> {
        let profile = self
            .by_identity
            .get(&(profile_id, version))
            .copied()
            .ok_or(VerificationProfileErrorV1::ProfileNotFound)?;
        if profile.profile_hash != expected_hash {
            return Err(VerificationProfileErrorV1::ProfileHashMismatch);
        }
        if !profile.enabled {
            return Err(VerificationProfileErrorV1::ProfileDisabled);
        }
        if height < profile.valid_from_height {
            return Err(VerificationProfileErrorV1::ProfileNotYetValid);
        }
        if profile
            .expires_at_height
            .is_some_and(|expiry| height > expiry)
        {
            return Err(VerificationProfileErrorV1::ProfileExpired);
        }
        if profile
            .revoked_at_height
            .is_some_and(|revocation| height >= revocation)
        {
            return Err(VerificationProfileErrorV1::ProfileRevoked);
        }
        Ok(profile)
    }

    pub fn len(&self) -> usize {
        self.by_identity.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_identity.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationStatementV1 {
    pub task_id: VerificationObjectIdV1,
    pub lease_id: VerificationObjectIdV1,
    pub execution_receipt_id: VerificationObjectIdV1,
    pub profile_id: VerificationProfileIdV1,
    pub profile_version: u32,
    pub profile_hash: VerificationDigestV1,
    pub artifact_evidence_digest: VerificationDigestV1,
    pub availability_certificate_digest: VerificationDigestV1,
    pub evidence_window_start: u64,
    pub evidence_window_end: u64,
    pub submitted_height: u64,
    pub statement_digest: VerificationDigestV1,
}

impl VerificationStatementV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        task_id: VerificationObjectIdV1,
        lease_id: VerificationObjectIdV1,
        execution_receipt_id: VerificationObjectIdV1,
        profile_id: VerificationProfileIdV1,
        profile_version: u32,
        profile_hash: VerificationDigestV1,
        artifact_evidence_digest: VerificationDigestV1,
        availability_certificate_digest: VerificationDigestV1,
        evidence_window_start: u64,
        evidence_window_end: u64,
        submitted_height: u64,
    ) -> VerificationProfileResultV1<Self> {
        let mut value = Self {
            task_id,
            lease_id,
            execution_receipt_id,
            profile_id,
            profile_version,
            profile_hash,
            artifact_evidence_digest,
            availability_certificate_digest,
            evidence_window_start,
            evidence_window_end,
            submitted_height,
            statement_digest: [1; 32],
        };
        value.validate_shape()?;
        value.statement_digest = value.recompute_digest();
        Ok(value)
    }

    fn validate_shape(&self) -> VerificationProfileResultV1<()> {
        for value in [
            self.task_id,
            self.lease_id,
            self.execution_receipt_id,
            self.profile_id,
            self.profile_hash,
            self.artifact_evidence_digest,
            self.availability_certificate_digest,
        ] {
            require_nonzero(&value)?;
        }
        if self.profile_version == 0
            || self.evidence_window_start > self.evidence_window_end
            || self.submitted_height < self.evidence_window_start
            || self.submitted_height > self.evidence_window_end
        {
            return Err(VerificationProfileErrorV1::MalformedStatement);
        }
        Ok(())
    }

    fn recompute_digest(&self) -> VerificationDigestV1 {
        let mut hasher = Sha256::new();
        hash_frame(&mut hasher, STATEMENT_DOMAIN_V1);
        hash_frame(&mut hasher, &self.task_id);
        hash_frame(&mut hasher, &self.lease_id);
        hash_frame(&mut hasher, &self.execution_receipt_id);
        hash_frame(&mut hasher, &self.profile_id);
        hash_frame(&mut hasher, &self.profile_version.to_be_bytes());
        hash_frame(&mut hasher, &self.profile_hash);
        hash_frame(&mut hasher, &self.artifact_evidence_digest);
        hash_frame(&mut hasher, &self.availability_certificate_digest);
        hash_frame(&mut hasher, &self.evidence_window_start.to_be_bytes());
        hash_frame(&mut hasher, &self.evidence_window_end.to_be_bytes());
        hash_frame(&mut hasher, &self.submitted_height.to_be_bytes());
        hasher.finalize().into()
    }

    fn validate_digest(&self) -> VerificationProfileResultV1<()> {
        self.validate_shape()?;
        if self.statement_digest != self.recompute_digest() {
            return Err(VerificationProfileErrorV1::MalformedStatement);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationEvidenceV1 {
    pub task_id: VerificationObjectIdV1,
    pub lease_id: VerificationObjectIdV1,
    pub execution_receipt_id: VerificationObjectIdV1,
    pub artifact_evidence_digest: VerificationDigestV1,
    pub availability_certificate_digest: VerificationDigestV1,
    pub backend_payload_digest: VerificationDigestV1,
}

impl VerificationEvidenceV1 {
    fn validate_bound_to(
        &self,
        statement: &VerificationStatementV1,
    ) -> VerificationProfileResultV1<()> {
        for value in [
            self.task_id,
            self.lease_id,
            self.execution_receipt_id,
            self.artifact_evidence_digest,
            self.availability_certificate_digest,
            self.backend_payload_digest,
        ] {
            require_nonzero(&value)?;
        }
        if self.task_id != statement.task_id
            || self.lease_id != statement.lease_id
            || self.execution_receipt_id != statement.execution_receipt_id
            || self.artifact_evidence_digest != statement.artifact_evidence_digest
            || self.availability_certificate_digest
                != statement.availability_certificate_digest
        {
            return Err(VerificationProfileErrorV1::EvidenceBindingMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationBackendResultV1 {
    Verified,
    Rejected,
    Unavailable,
}

pub trait VerificationBackendV1 {
    fn verify(
        &mut self,
        profile: VerificationProfileV1,
        statement: &VerificationStatementV1,
        evidence: &VerificationEvidenceV1,
    ) -> VerificationBackendResultV1;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationDecisionStatusV1 {
    Verified,
    Rejected,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationDecisionV1 {
    pub status: VerificationDecisionStatusV1,
    pub profile_kind: VerificationProfileKindV1,
    pub statement_digest: VerificationDigestV1,
    pub decision_digest: VerificationDigestV1,
    pub economic_authority: bool,
    pub order_reorg_authority: bool,
    pub poco_weight_authority: bool,
}

pub fn verify_statement_v1<B: VerificationBackendV1>(
    registry: &VerificationProfileRegistryV1,
    statement: &VerificationStatementV1,
    evidence: &VerificationEvidenceV1,
    current_height: u64,
    backend: &mut B,
) -> VerificationProfileResultV1<VerificationDecisionV1> {
    statement.validate_digest()?;
    let profile = registry.resolve_exact(
        statement.profile_id,
        statement.profile_version,
        statement.profile_hash,
        current_height,
    )?;
    evidence.validate_bound_to(statement)?;
    if current_height < statement.evidence_window_start
        || current_height > statement.evidence_window_end
    {
        return Err(VerificationProfileErrorV1::EvidenceWindowClosed);
    }
    let status = match backend.verify(profile, statement, evidence) {
        VerificationBackendResultV1::Verified => VerificationDecisionStatusV1::Verified,
        VerificationBackendResultV1::Rejected => VerificationDecisionStatusV1::Rejected,
        VerificationBackendResultV1::Unavailable => VerificationDecisionStatusV1::Unavailable,
    };
    let mut hasher = Sha256::new();
    hash_frame(&mut hasher, DECISION_DOMAIN_V1);
    hash_frame(&mut hasher, &statement.statement_digest);
    hash_frame(&mut hasher, &[profile.kind.tag()]);
    hash_frame(
        &mut hasher,
        &[match status {
            VerificationDecisionStatusV1::Verified => 0,
            VerificationDecisionStatusV1::Rejected => 1,
            VerificationDecisionStatusV1::Unavailable => 2,
        }],
    );
    hash_frame(&mut hasher, &evidence.backend_payload_digest);
    Ok(VerificationDecisionV1 {
        status,
        profile_kind: profile.kind,
        statement_digest: statement.statement_digest,
        decision_digest: hasher.finalize().into(),
        economic_authority: false,
        order_reorg_authority: false,
        poco_weight_authority: false,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengePhaseV1 {
    Opened,
    EvidencePeriod,
    ResponsePeriod,
    DecisionPending,
    Upheld,
    Rejected,
    AppealPending,
    Final,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeFinalOutcomeV1 {
    Upheld,
    Rejected,
    Withdrawn,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeRecordV1 {
    pub challenge_id: VerificationObjectIdV1,
    pub result_id: VerificationObjectIdV1,
    pub challenger: VerificationActorIdV1,
    pub phase: ChallengePhaseV1,
    pub opened_height: u64,
    pub evidence_deadline: u64,
    pub response_deadline: u64,
    pub decision_deadline: u64,
    pub appeal_deadline: u64,
    pub appeal_used: bool,
    pub final_outcome: Option<ChallengeFinalOutcomeV1>,
    pub record_digest: VerificationDigestV1,
    pub economic_authority: bool,
    pub order_reorg: bool,
}

impl ChallengeRecordV1 {
    #[allow(clippy::too_many_arguments)]
    fn open(
        challenge_id: VerificationObjectIdV1,
        result_id: VerificationObjectIdV1,
        challenger: VerificationActorIdV1,
        opened_height: u64,
        challenge_window_end: u64,
        evidence_deadline: u64,
        response_deadline: u64,
        decision_deadline: u64,
        appeal_deadline: u64,
    ) -> VerificationProfileResultV1<Self> {
        require_nonzero(&challenge_id)?;
        require_nonzero(&result_id)?;
        require_nonzero(&challenger)?;
        if opened_height > challenge_window_end
            || evidence_deadline < opened_height
            || response_deadline < evidence_deadline
            || decision_deadline < response_deadline
            || appeal_deadline < decision_deadline
        {
            return Err(VerificationProfileErrorV1::ChallengeDeadlineMissed);
        }
        let mut value = Self {
            challenge_id,
            result_id,
            challenger,
            phase: ChallengePhaseV1::Opened,
            opened_height,
            evidence_deadline,
            response_deadline,
            decision_deadline,
            appeal_deadline,
            appeal_used: false,
            final_outcome: None,
            record_digest: [1; 32],
            economic_authority: false,
            order_reorg: false,
        };
        value.refresh_digest();
        Ok(value)
    }

    pub fn submit_evidence(&mut self, height: u64) -> VerificationProfileResultV1<()> {
        self.require_phase(ChallengePhaseV1::Opened)?;
        self.require_at_or_before(height, self.evidence_deadline)?;
        self.phase = ChallengePhaseV1::EvidencePeriod;
        self.refresh_digest();
        Ok(())
    }

    pub fn begin_response(&mut self, height: u64) -> VerificationProfileResultV1<()> {
        self.require_phase(ChallengePhaseV1::EvidencePeriod)?;
        self.require_at_or_before(height, self.response_deadline)?;
        self.phase = ChallengePhaseV1::ResponsePeriod;
        self.refresh_digest();
        Ok(())
    }

    pub fn submit_response(&mut self, height: u64) -> VerificationProfileResultV1<()> {
        self.require_phase(ChallengePhaseV1::ResponsePeriod)?;
        self.require_at_or_before(height, self.response_deadline)?;
        self.phase = ChallengePhaseV1::DecisionPending;
        self.refresh_digest();
        Ok(())
    }

    pub fn decide(
        &mut self,
        height: u64,
        outcome: ChallengeFinalOutcomeV1,
    ) -> VerificationProfileResultV1<()> {
        if !matches!(
            self.phase,
            ChallengePhaseV1::DecisionPending | ChallengePhaseV1::AppealPending
        ) || !matches!(
            outcome,
            ChallengeFinalOutcomeV1::Upheld | ChallengeFinalOutcomeV1::Rejected
        ) {
            return Err(VerificationProfileErrorV1::InvalidChallengePhase);
        }
        self.require_at_or_before(height, self.decision_deadline)?;
        self.phase = match outcome {
            ChallengeFinalOutcomeV1::Upheld => ChallengePhaseV1::Upheld,
            ChallengeFinalOutcomeV1::Rejected => ChallengePhaseV1::Rejected,
            ChallengeFinalOutcomeV1::Withdrawn | ChallengeFinalOutcomeV1::Expired => {
                return Err(VerificationProfileErrorV1::InvalidChallengePhase)
            }
        };
        self.final_outcome = Some(outcome);
        self.refresh_digest();
        Ok(())
    }

    pub fn appeal(
        &mut self,
        height: u64,
        appeal_decision_deadline: u64,
    ) -> VerificationProfileResultV1<()> {
        if self.appeal_used {
            return Err(VerificationProfileErrorV1::AppealAlreadyUsed);
        }
        if !matches!(self.phase, ChallengePhaseV1::Upheld | ChallengePhaseV1::Rejected) {
            return Err(VerificationProfileErrorV1::InvalidChallengePhase);
        }
        self.require_at_or_before(height, self.appeal_deadline)?;
        if appeal_decision_deadline < height {
            return Err(VerificationProfileErrorV1::ChallengeDeadlineMissed);
        }
        self.appeal_used = true;
        self.phase = ChallengePhaseV1::AppealPending;
        self.final_outcome = None;
        self.decision_deadline = appeal_decision_deadline;
        self.appeal_deadline = appeal_decision_deadline;
        self.refresh_digest();
        Ok(())
    }

    pub fn finalize(&mut self, height: u64) -> VerificationProfileResultV1<()> {
        if !matches!(self.phase, ChallengePhaseV1::Upheld | ChallengePhaseV1::Rejected)
            || height <= self.appeal_deadline
        {
            return Err(VerificationProfileErrorV1::InvalidChallengePhase);
        }
        self.phase = ChallengePhaseV1::Final;
        self.refresh_digest();
        Ok(())
    }

    pub fn withdraw(&mut self) -> VerificationProfileResultV1<()> {
        if matches!(
            self.phase,
            ChallengePhaseV1::Upheld
                | ChallengePhaseV1::Rejected
                | ChallengePhaseV1::Final
                | ChallengePhaseV1::AppealPending
        ) {
            return Err(VerificationProfileErrorV1::InvalidChallengePhase);
        }
        self.phase = ChallengePhaseV1::Final;
        self.final_outcome = Some(ChallengeFinalOutcomeV1::Withdrawn);
        self.refresh_digest();
        Ok(())
    }

    pub fn expire(&mut self, height: u64) -> VerificationProfileResultV1<()> {
        let deadline = match self.phase {
            ChallengePhaseV1::Opened | ChallengePhaseV1::EvidencePeriod => self.evidence_deadline,
            ChallengePhaseV1::ResponsePeriod => self.response_deadline,
            ChallengePhaseV1::DecisionPending | ChallengePhaseV1::AppealPending => {
                self.decision_deadline
            }
            ChallengePhaseV1::Upheld
            | ChallengePhaseV1::Rejected
            | ChallengePhaseV1::Final => {
                return Err(VerificationProfileErrorV1::InvalidChallengePhase)
            }
        };
        if height <= deadline {
            return Err(VerificationProfileErrorV1::ChallengeDeadlineMissed);
        }
        self.phase = ChallengePhaseV1::Final;
        self.final_outcome = Some(ChallengeFinalOutcomeV1::Expired);
        self.refresh_digest();
        Ok(())
    }

    fn require_phase(&self, phase: ChallengePhaseV1) -> VerificationProfileResultV1<()> {
        if self.phase != phase {
            return Err(VerificationProfileErrorV1::InvalidChallengePhase);
        }
        Ok(())
    }

    fn require_at_or_before(&self, height: u64, deadline: u64) -> VerificationProfileResultV1<()> {
        if height > deadline {
            return Err(VerificationProfileErrorV1::ChallengeDeadlineMissed);
        }
        Ok(())
    }

    fn refresh_digest(&mut self) {
        let mut hasher = Sha256::new();
        hash_frame(&mut hasher, CHALLENGE_DOMAIN_V1);
        hash_frame(&mut hasher, &self.challenge_id);
        hash_frame(&mut hasher, &self.result_id);
        hash_frame(&mut hasher, &self.challenger);
        hash_frame(&mut hasher, &[self.phase as u8]);
        hash_frame(&mut hasher, &self.opened_height.to_be_bytes());
        hash_frame(&mut hasher, &self.evidence_deadline.to_be_bytes());
        hash_frame(&mut hasher, &self.response_deadline.to_be_bytes());
        hash_frame(&mut hasher, &self.decision_deadline.to_be_bytes());
        hash_frame(&mut hasher, &self.appeal_deadline.to_be_bytes());
        hash_frame(&mut hasher, &[u8::from(self.appeal_used)]);
        hash_frame(
            &mut hasher,
            &[match self.final_outcome {
                None => 0,
                Some(ChallengeFinalOutcomeV1::Upheld) => 1,
                Some(ChallengeFinalOutcomeV1::Rejected) => 2,
                Some(ChallengeFinalOutcomeV1::Withdrawn) => 3,
                Some(ChallengeFinalOutcomeV1::Expired) => 4,
            }],
        );
        self.record_digest = hasher.finalize().into();
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChallengeBookV1 {
    by_result: BTreeMap<VerificationObjectIdV1, ChallengeRecordV1>,
}

impl ChallengeBookV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        &mut self,
        challenge_id: VerificationObjectIdV1,
        result_id: VerificationObjectIdV1,
        challenger: VerificationActorIdV1,
        opened_height: u64,
        challenge_window_end: u64,
        evidence_deadline: u64,
        response_deadline: u64,
        decision_deadline: u64,
        appeal_deadline: u64,
    ) -> VerificationProfileResultV1<&mut ChallengeRecordV1> {
        if self.by_result.contains_key(&result_id) {
            return Err(VerificationProfileErrorV1::DuplicateChallenge);
        }
        let record = ChallengeRecordV1::open(
            challenge_id,
            result_id,
            challenger,
            opened_height,
            challenge_window_end,
            evidence_deadline,
            response_deadline,
            decision_deadline,
            appeal_deadline,
        )?;
        self.by_result.insert(result_id, record);
        self.by_result
            .get_mut(&result_id)
            .ok_or(VerificationProfileErrorV1::ChallengeNotFound)
    }

    pub fn get_mut(
        &mut self,
        result_id: &VerificationObjectIdV1,
    ) -> VerificationProfileResultV1<&mut ChallengeRecordV1> {
        self.by_result
            .get_mut(result_id)
            .ok_or(VerificationProfileErrorV1::ChallengeNotFound)
    }
}

fn require_nonzero(value: &[u8; 32]) -> VerificationProfileResultV1<()> {
    if *value == [0; 32] {
        return Err(VerificationProfileErrorV1::ZeroIdentifier);
    }
    Ok(())
}

fn hash_frame(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(
        u64::try_from(value.len())
            .expect("hash frame length fits u64")
            .to_be_bytes(),
    );
    hasher.update(value);
}
