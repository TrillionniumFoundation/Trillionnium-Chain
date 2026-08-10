use alloc::boxed::Box;

use crate::{
    CanonicalSignable, ConsensusParametersV0, Result, SignatureVerifier, SignedProposalV0,
    TimeoutVote, ValidationError, ValidatorId, ValidatorSet, Vote,
};

/// Diagnostic equivocation scaffold for the P1 consensus core.
///
/// Proposal evidence retains the exact signed proposal envelopes, but the
/// frozen header-only evidence encoding and evidence ID are still pending.
/// Persisted/slashing consumers must therefore retain the authenticated parent
/// contexts alongside this value and use [`Self::verify_proposals`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EquivocationEvidence {
    Proposal {
        first: Box<SignedProposalV0>,
        second: Box<SignedProposalV0>,
    },
    Vote {
        first: Box<Vote>,
        second: Box<Vote>,
    },
    Timeout {
        first: Box<TimeoutVote>,
        second: Box<TimeoutVote>,
    },
}

impl EquivocationEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn proposal(
        mut first: SignedProposalV0,
        mut second: SignedProposalV0,
        active_validator_set: &ValidatorSet,
        old_validator_set: Option<&ValidatorSet>,
        consensus_parameters: &ConsensusParametersV0,
        mut first_authenticated_parent_timestamp_ms: u64,
        mut second_authenticated_parent_timestamp_ms: u64,
    ) -> Result<Self> {
        if first.signing_root() > second.signing_root() {
            core::mem::swap(&mut first, &mut second);
            core::mem::swap(
                &mut first_authenticated_parent_timestamp_ms,
                &mut second_authenticated_parent_timestamp_ms,
            );
        }
        let value = Self::Proposal {
            first: Box::new(first),
            second: Box::new(second),
        };
        value.validate_proposals(
            active_validator_set,
            old_validator_set,
            consensus_parameters,
            first_authenticated_parent_timestamp_ms,
            second_authenticated_parent_timestamp_ms,
        )?;
        Ok(value)
    }

    pub fn vote(mut first: Vote, mut second: Vote, validator_set: &ValidatorSet) -> Result<Self> {
        if first.signing_root() > second.signing_root() {
            core::mem::swap(&mut first, &mut second);
        }
        let value = Self::Vote {
            first: Box::new(first),
            second: Box::new(second),
        };
        value.validate_shape(validator_set)?;
        Ok(value)
    }

    pub fn timeout(
        mut first: TimeoutVote,
        mut second: TimeoutVote,
        validator_set: &ValidatorSet,
    ) -> Result<Self> {
        if first.signing_root() > second.signing_root() {
            core::mem::swap(&mut first, &mut second);
        }
        let value = Self::Timeout {
            first: Box::new(first),
            second: Box::new(second),
        };
        value.validate_shape(validator_set)?;
        Ok(value)
    }

    pub fn offender(&self) -> ValidatorId {
        match self {
            Self::Proposal { first, .. } => first.proposer(),
            Self::Vote { first, .. } => first.author(),
            Self::Timeout { first, .. } => first.author(),
        }
    }

    pub fn validate_shape(&self, validator_set: &ValidatorSet) -> Result<()> {
        match self {
            Self::Proposal { first, second } => {
                first.validate_shape(validator_set, None)?;
                second.validate_shape(validator_set, None)?;
                if !first.conflicts_with(second) {
                    return Err(ValidationError::InvalidEvidence(
                        "proposals do not prove same-view proposer equivocation",
                    ));
                }
                validate_canonical_pair(first.signing_root(), second.signing_root())
            }
            Self::Vote { first, second } => {
                first.validate_shape(validator_set)?;
                second.validate_shape(validator_set)?;
                if !first.conflicts_with(second) {
                    return Err(ValidationError::InvalidEvidence(
                        "votes do not prove same-view double voting",
                    ));
                }
                validate_canonical_pair(first.signing_root(), second.signing_root())
            }
            Self::Timeout { first, second } => {
                first.validate_shape(validator_set)?;
                second.validate_shape(validator_set)?;
                if !first.conflicts_with(second) {
                    return Err(ValidationError::InvalidEvidence(
                        "timeouts do not prove same-view conflicting timeout signing",
                    ));
                }
                validate_canonical_pair(first.signing_root(), second.signing_root())
            }
        }
    }

    pub fn verify<V: SignatureVerifier>(
        &self,
        validator_set: &ValidatorSet,
        verifier: &V,
    ) -> Result<()> {
        self.verify_vote_timeout(validator_set, verifier)
    }

    /// Verifies evidence kinds that do not need authenticated parent context.
    /// Exact proposal evidence must use [`Self::verify_proposals`].
    pub fn verify_vote_timeout<V: SignatureVerifier>(
        &self,
        validator_set: &ValidatorSet,
        verifier: &V,
    ) -> Result<()> {
        self.validate_shape(validator_set)?;
        match self {
            Self::Proposal { .. } => Err(ValidationError::InvalidEvidence(
                "proposal evidence requires parameters and authenticated parent timestamps",
            )),
            Self::Vote { first, second } => {
                first.verify(validator_set, verifier)?;
                second.verify(validator_set, verifier)
            }
            Self::Timeout { first, second } => {
                first.verify(validator_set, verifier)?;
                second.verify(validator_set, verifier)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn validate_proposals(
        &self,
        active_validator_set: &ValidatorSet,
        old_validator_set: Option<&ValidatorSet>,
        consensus_parameters: &ConsensusParametersV0,
        first_authenticated_parent_timestamp_ms: u64,
        second_authenticated_parent_timestamp_ms: u64,
    ) -> Result<()> {
        let Self::Proposal { first, second } = self else {
            return Err(ValidationError::InvalidEvidence(
                "evidence is not proposal equivocation",
            ));
        };
        first.validate(
            active_validator_set,
            old_validator_set,
            consensus_parameters,
            first_authenticated_parent_timestamp_ms,
        )?;
        second.validate(
            active_validator_set,
            old_validator_set,
            consensus_parameters,
            second_authenticated_parent_timestamp_ms,
        )?;
        if !first.conflicts_with(second) {
            return Err(ValidationError::InvalidEvidence(
                "proposals do not prove same-view proposer equivocation",
            ));
        }
        validate_canonical_pair(first.signing_root(), second.signing_root())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_proposals<V: SignatureVerifier>(
        &self,
        active_validator_set: &ValidatorSet,
        old_validator_set: Option<&ValidatorSet>,
        consensus_parameters: &ConsensusParametersV0,
        first_authenticated_parent_timestamp_ms: u64,
        second_authenticated_parent_timestamp_ms: u64,
        verifier: &V,
    ) -> Result<()> {
        self.validate_proposals(
            active_validator_set,
            old_validator_set,
            consensus_parameters,
            first_authenticated_parent_timestamp_ms,
            second_authenticated_parent_timestamp_ms,
        )?;
        let Self::Proposal { first, second } = self else {
            return Err(ValidationError::InvalidEvidence(
                "evidence is not proposal equivocation",
            ));
        };
        first.verify(
            active_validator_set,
            old_validator_set,
            consensus_parameters,
            first_authenticated_parent_timestamp_ms,
            verifier,
        )?;
        second.verify(
            active_validator_set,
            old_validator_set,
            consensus_parameters,
            second_authenticated_parent_timestamp_ms,
            verifier,
        )
    }
}

fn validate_canonical_pair(first: crate::SigningRoot, second: crate::SigningRoot) -> Result<()> {
    if first >= second {
        return Err(ValidationError::InvalidEvidence(
            "evidence statements are not in canonical signing-root order",
        ));
    }
    Ok(())
}
