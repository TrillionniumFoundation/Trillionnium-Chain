use core::fmt;

use trnm_consensus_types::{CanonicalSignIntentV0, CanonicalSignPreimageV0, ValidatorSet};

/// Complete command kinds admitted by remote-signer protocol schema 1.
///
/// Proposal and old/new epoch handoff are intentionally absent. They require
/// separately reviewed canonical intents and journal conflict keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RemoteConsensusCommandKindV1 {
    Vote,
    TimeoutVote,
}

impl RemoteConsensusCommandKindV1 {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Vote => 0,
            Self::TimeoutVote => 1,
        }
    }

    pub(crate) fn from_tag(tag: u8) -> Result<Self, RemoteConsensusCommandValidationErrorV1> {
        match tag {
            0 => Ok(Self::Vote),
            1 => Ok(Self::TimeoutVote),
            _ => Err(RemoteConsensusCommandValidationErrorV1::UnsupportedCommandTag(tag)),
        }
    }
}

/// Owned, exact, well-formed signing request admitted by protocol schema 1.
///
/// Both fields are private so external callers cannot pair a vote command tag
/// with a timeout-vote intent or the inverse. Construction always fresh-
/// validates and classifies the complete canonical intent. It does not prove
/// that Core persisted the intent or that HotStuff locked-QC/safe-vote rules
/// authorized it; a future signer service must enforce that separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteConsensusCommandV1 {
    kind: RemoteConsensusCommandKindV1,
    intent: CanonicalSignIntentV0,
}

impl RemoteConsensusCommandV1 {
    /// Classifies a complete canonical intent after fresh validator-set shape
    /// validation. No caller-selected bytes or signing root are accepted, but
    /// successful classification is not Core or SafetyRules authority.
    pub fn from_canonical_intent(
        intent: CanonicalSignIntentV0,
        validator_set: &ValidatorSet,
    ) -> Result<Self, RemoteConsensusCommandValidationErrorV1> {
        validator_set
            .validate_shape()
            .map_err(|_| RemoteConsensusCommandValidationErrorV1::InvalidValidatorSet)?;
        intent
            .validate(validator_set)
            .map_err(|_| RemoteConsensusCommandValidationErrorV1::InvalidCanonicalIntent)?;
        if intent.validator_set_id() != validator_set.id()
            || intent.epoch() != validator_set.epoch()
            || intent.chain_id() != validator_set.chain_id()
            || intent.protocol_version() != validator_set.protocol_version()
        {
            return Err(RemoteConsensusCommandValidationErrorV1::ContextMismatch);
        }
        if validator_set.validator(intent.author()).is_none() {
            return Err(RemoteConsensusCommandValidationErrorV1::UnknownAuthor);
        }
        let kind = match intent.preimage() {
            CanonicalSignPreimageV0::Vote(_) => RemoteConsensusCommandKindV1::Vote,
            CanonicalSignPreimageV0::TimeoutVote(_) => RemoteConsensusCommandKindV1::TimeoutVote,
        };
        Ok(Self { kind, intent })
    }

    pub const fn kind(&self) -> RemoteConsensusCommandKindV1 {
        self.kind
    }

    pub const fn intent(&self) -> &CanonicalSignIntentV0 {
        &self.intent
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteConsensusCommandValidationErrorV1 {
    InvalidValidatorSet,
    InvalidCanonicalIntent,
    ContextMismatch,
    UnknownAuthor,
    UnsupportedCommandTag(u8),
    CommandKindMismatch,
}

impl fmt::Display for RemoteConsensusCommandValidationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidValidatorSet => formatter.write_str("validator set is invalid"),
            Self::InvalidCanonicalIntent => {
                formatter.write_str("canonical consensus sign intent is invalid")
            }
            Self::ContextMismatch => {
                formatter.write_str("canonical sign intent context differs from validator set")
            }
            Self::UnknownAuthor => {
                formatter.write_str("canonical sign intent author is not in validator set")
            }
            Self::UnsupportedCommandTag(tag) => {
                write!(formatter, "unsupported remote consensus command tag {tag}")
            }
            Self::CommandKindMismatch => formatter
                .write_str("remote consensus command tag differs from canonical intent kind"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trnm_consensus_types::{
        BlockId, ChainId, ConsensusParametersHash, ConsensusPublicKey, Epoch, GenesisHash, Height,
        ProtocolVersion, Validator, ValidatorId, View, VotingPower,
    };

    fn validator_set() -> ValidatorSet {
        ValidatorSet::new(
            GenesisHash::new([7; 32]),
            ChainId::from_static("trnm-remote-signer-command-test"),
            ProtocolVersion::V0,
            Epoch::new(4),
            ConsensusParametersHash::new([8; 32]),
            alloc::vec![Validator::new(
                ValidatorId::new([1; 32]),
                ConsensusPublicKey::new([2; 32]),
                VotingPower::new(1).unwrap(),
            )
            .unwrap()],
        )
        .unwrap()
    }

    #[test]
    fn canonical_intents_are_owned_and_strictly_classified() {
        let set = validator_set();
        let vote = CanonicalSignIntentV0::vote(
            &set,
            ValidatorId::new([1; 32]),
            3,
            View::new(5),
            Height::new(6),
            BlockId::new([9; 32]),
        )
        .unwrap();
        let command = RemoteConsensusCommandV1::from_canonical_intent(vote.clone(), &set).unwrap();
        assert_eq!(command.kind(), RemoteConsensusCommandKindV1::Vote);
        assert_eq!(command.intent(), &vote);

        for reserved in [2, 3, 4, u8::MAX] {
            assert_eq!(
                RemoteConsensusCommandKindV1::from_tag(reserved),
                Err(RemoteConsensusCommandValidationErrorV1::UnsupportedCommandTag(reserved))
            );
        }
    }
}
