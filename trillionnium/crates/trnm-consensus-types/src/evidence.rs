use alloc::boxed::Box;

use crate::{
    CanonicalSignable, Proposal, Result, SignatureVerifier, TimeoutVote, ValidationError,
    ValidatorId, ValidatorSet, Vote,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EquivocationEvidence {
    Proposal {
        first: Box<Proposal>,
        second: Box<Proposal>,
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
    pub fn proposal(
        mut first: Proposal,
        mut second: Proposal,
        validator_set: &ValidatorSet,
    ) -> Result<Self> {
        if first.signing_root() > second.signing_root() {
            core::mem::swap(&mut first, &mut second);
        }
        let value = Self::Proposal {
            first: Box::new(first),
            second: Box::new(second),
        };
        value.validate_shape(validator_set)?;
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
                first.validate_shape(validator_set)?;
                second.validate_shape(validator_set)?;
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
        self.validate_shape(validator_set)?;
        match self {
            Self::Proposal { first, second } => {
                first.verify(validator_set, verifier)?;
                second.verify(validator_set, verifier)
            }
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
}

fn validate_canonical_pair(first: crate::SigningRoot, second: crate::SigningRoot) -> Result<()> {
    if first >= second {
        return Err(ValidationError::InvalidEvidence(
            "evidence statements are not in canonical signing-root order",
        ));
    }
    Ok(())
}
