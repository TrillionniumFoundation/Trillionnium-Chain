//! Typed direct-7 RecoveryReady/RecoveryStart collection.
//!
//! Transport authentication and bounded opaque routing live in
//! `restart_protocol`; canonical statement verification lives in
//! `trnm-consensus-types`.  This module joins those two boundaries without
//! granting restart authority: normal builds only retain at most one exact
//! externally signed statement per validator and phase and reconstruct the
//! full N/N ReadySet and StartCertificate. Local signing helpers are test-only
//! until a later consuming caught-up/journal owner exists. It has no journal,
//! filesystem, process-control, Core, signer-activation, timer, or ordinary-
//! ingress API.

use std::{collections::BTreeMap, fmt};

#[cfg(test)]
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use trnm_consensus_crypto::StrictEd25519Verifier;
#[cfg(test)]
use trnm_consensus_types::Signature64;
use trnm_consensus_types::{
    decode_signed_recovery_ready_v1_exact, decode_signed_recovery_start_v1_exact,
    RecoveryContextV1, RecoveryErrorV1, RecoveryReadySetV1, RecoveryStartCertificateV1,
    SignedRecoveryReadyV1, SignedRecoveryStartV1, ValidatorId, ValidatorSet,
    DIRECT7_RECOVERY_VALIDATOR_COUNT_V1, MAX_SIGNED_RECOVERY_START_BYTES_V1,
};

const SLOT_DIGEST_DOMAIN_V1: &[u8] = b"trnm.poco-g3.recovery-barrier-slot.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RecoveryBarrierPhaseV1 {
    Ready,
    Start,
}

impl RecoveryBarrierPhaseV1 {
    const fn tag_v1(self) -> u8 {
        match self {
            Self::Ready => 1,
            Self::Start => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoveryBarrierAdmissionV1 {
    New,
    Buffered,
    ExactReplay,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RecoveryBarrierErrorV1 {
    Recovery(RecoveryErrorV1),
    UnknownOrigin,
    AuthenticatedOriginMismatch,
    LocalKeyMismatch,
    Incomplete,
    PayloadTooLarge,
    Equivocation {
        origin: Box<ValidatorId>,
        phase: RecoveryBarrierPhaseV1,
    },
    Poisoned,
}

impl fmt::Display for RecoveryBarrierErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Recovery(error) => write!(formatter, "recovery statement: {error}"),
            Self::UnknownOrigin => formatter.write_str("unknown recovery barrier origin"),
            Self::AuthenticatedOriginMismatch => {
                formatter.write_str("recovery statement author differs from authenticated origin")
            }
            Self::LocalKeyMismatch => {
                formatter.write_str("local recovery signing key differs from validator set")
            }
            Self::Incomplete => formatter.write_str("recovery barrier is incomplete"),
            Self::PayloadTooLarge => formatter.write_str("recovery barrier payload is too large"),
            Self::Equivocation { origin, phase } => write!(
                formatter,
                "recovery barrier equivocation by {origin:?} in {phase:?}"
            ),
            Self::Poisoned => formatter.write_str("recovery barrier is poisoned"),
        }
    }
}

impl std::error::Error for RecoveryBarrierErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Recovery(error) => Some(error),
            _ => None,
        }
    }
}

impl From<RecoveryErrorV1> for RecoveryBarrierErrorV1 {
    fn from(error: RecoveryErrorV1) -> Self {
        Self::Recovery(error)
    }
}

/// Signs one Ready statement only after the local Ed25519 key is joined to
/// the exact validator record.  The returned typed statement remains inert.
#[cfg(test)]
pub(crate) fn issue_local_recovery_ready_v1(
    context: RecoveryContextV1,
    origin: ValidatorId,
    validator_set: &ValidatorSet,
    signing_key: &SigningKey,
) -> Result<SignedRecoveryReadyV1, RecoveryBarrierErrorV1> {
    context.validate_direct7(validator_set)?;
    require_local_key_v1(origin, validator_set, signing_key)?;
    let root = SignedRecoveryReadyV1::signing_root_for(&context, origin);
    let signature = Signature64::from_array(signing_key.sign(root.as_bytes()).to_bytes());
    SignedRecoveryReadyV1::from_signature(
        context,
        origin,
        signature,
        validator_set,
        &StrictEd25519Verifier,
    )
    .map_err(Into::into)
}

/// Signs one Start statement only from a complete verified ReadySet.  There
/// is deliberately no scalar ReadySet-digest input.
#[cfg(test)]
pub(crate) fn issue_local_recovery_start_v1(
    ready_set: &RecoveryReadySetV1,
    origin: ValidatorId,
    validator_set: &ValidatorSet,
    signing_key: &SigningKey,
) -> Result<SignedRecoveryStartV1, RecoveryBarrierErrorV1> {
    ready_set.verify(validator_set, &StrictEd25519Verifier)?;
    require_local_key_v1(origin, validator_set, signing_key)?;
    let root = SignedRecoveryStartV1::signing_root_for(ready_set, origin);
    let signature = Signature64::from_array(signing_key.sign(root.as_bytes()).to_bytes());
    SignedRecoveryStartV1::from_signature(
        ready_set,
        origin,
        signature,
        validator_set,
        &StrictEd25519Verifier,
    )
    .map_err(Into::into)
}

#[cfg(test)]
fn require_local_key_v1(
    origin: ValidatorId,
    validator_set: &ValidatorSet,
    signing_key: &SigningKey,
) -> Result<(), RecoveryBarrierErrorV1> {
    let validator = validator_set
        .validator(origin)
        .ok_or(RecoveryBarrierErrorV1::UnknownOrigin)?;
    if validator.consensus_key().as_bytes() != &signing_key.verifying_key().to_bytes() {
        return Err(RecoveryBarrierErrorV1::LocalKeyMismatch);
    }
    Ok(())
}

/// Fixed two-phase collector for one exact direct-7 recovery context.
///
/// Start bytes may arrive before this process has observed all Ready bytes.
/// They are retained under the already-authenticated outer origin and decoded
/// only after the complete ReadySet exists.  This avoids turning network
/// reordering into a lost semantic slot while preserving exact 2N capacity.
pub(crate) struct RecoveryBarrierRoundV1 {
    context: RecoveryContextV1,
    validator_set: ValidatorSet,
    slots: BTreeMap<(ValidatorId, RecoveryBarrierPhaseV1), [u8; 32]>,
    ready: BTreeMap<ValidatorId, SignedRecoveryReadyV1>,
    buffered_start: BTreeMap<ValidatorId, Vec<u8>>,
    start: BTreeMap<ValidatorId, SignedRecoveryStartV1>,
    poisoned: bool,
}

impl RecoveryBarrierRoundV1 {
    pub(crate) fn new(
        context: RecoveryContextV1,
        validator_set: ValidatorSet,
    ) -> Result<Self, RecoveryBarrierErrorV1> {
        context.validate_direct7(&validator_set)?;
        if validator_set.validators().len() != DIRECT7_RECOVERY_VALIDATOR_COUNT_V1 {
            return Err(RecoveryBarrierErrorV1::Incomplete);
        }
        Ok(Self {
            context,
            validator_set,
            slots: BTreeMap::new(),
            ready: BTreeMap::new(),
            buffered_start: BTreeMap::new(),
            start: BTreeMap::new(),
            poisoned: false,
        })
    }

    pub(crate) const fn context_v1(&self) -> &RecoveryContextV1 {
        &self.context
    }

    pub(crate) fn admit_ready_bytes_v1(
        &mut self,
        authenticated_origin: ValidatorId,
        bytes: &[u8],
    ) -> Result<RecoveryBarrierAdmissionV1, RecoveryBarrierErrorV1> {
        self.ensure_live_v1()?;
        let statement = decode_signed_recovery_ready_v1_exact(
            bytes,
            &self.validator_set,
            &StrictEd25519Verifier,
        )?;
        if statement.origin() != authenticated_origin {
            self.poisoned = true;
            return Err(RecoveryBarrierErrorV1::AuthenticatedOriginMismatch);
        }
        self.admit_ready_v1(statement)
    }

    pub(crate) fn admit_ready_v1(
        &mut self,
        statement: SignedRecoveryReadyV1,
    ) -> Result<RecoveryBarrierAdmissionV1, RecoveryBarrierErrorV1> {
        self.ensure_live_v1()?;
        statement.verify(&self.validator_set, &StrictEd25519Verifier)?;
        if statement.context() != &self.context {
            return Err(RecoveryErrorV1::ContextMismatch.into());
        }
        let origin = statement.origin();
        let bytes = statement.try_cev1_bytes()?;
        let digest = slot_digest_v1(RecoveryBarrierPhaseV1::Ready, &bytes);
        match self.preflight_slot_v1(origin, RecoveryBarrierPhaseV1::Ready, digest)? {
            RecoveryBarrierAdmissionV1::ExactReplay => {
                return Ok(RecoveryBarrierAdmissionV1::ExactReplay);
            }
            RecoveryBarrierAdmissionV1::New => {}
            RecoveryBarrierAdmissionV1::Buffered => unreachable!("slot preflight never buffers"),
        }
        self.commit_slot_v1(origin, RecoveryBarrierPhaseV1::Ready, digest)?;
        self.ready.insert(origin, statement);
        if self.ready.len() == DIRECT7_RECOVERY_VALIDATOR_COUNT_V1 {
            self.promote_buffered_starts_v1()?;
        }
        Ok(RecoveryBarrierAdmissionV1::New)
    }

    pub(crate) fn admit_start_bytes_v1(
        &mut self,
        authenticated_origin: ValidatorId,
        bytes: &[u8],
    ) -> Result<RecoveryBarrierAdmissionV1, RecoveryBarrierErrorV1> {
        self.ensure_live_v1()?;
        if self.validator_set.validator(authenticated_origin).is_none() {
            return Err(RecoveryBarrierErrorV1::UnknownOrigin);
        }
        if bytes.is_empty() || bytes.len() > MAX_SIGNED_RECOVERY_START_BYTES_V1 {
            return Err(RecoveryBarrierErrorV1::PayloadTooLarge);
        }
        if self.ready.len() != DIRECT7_RECOVERY_VALIDATOR_COUNT_V1 {
            return self.buffer_start_v1(authenticated_origin, bytes);
        }
        let ready_set = self.ready_set_v1()?;
        let statement = decode_signed_recovery_start_v1_exact(
            bytes,
            &ready_set,
            &self.validator_set,
            &StrictEd25519Verifier,
        )?;
        if statement.origin() != authenticated_origin {
            self.poisoned = true;
            return Err(RecoveryBarrierErrorV1::AuthenticatedOriginMismatch);
        }
        self.admit_start_v1(statement)
    }

    pub(crate) fn admit_start_v1(
        &mut self,
        statement: SignedRecoveryStartV1,
    ) -> Result<RecoveryBarrierAdmissionV1, RecoveryBarrierErrorV1> {
        self.ensure_live_v1()?;
        let ready_set = self.ready_set_v1()?;
        statement.verify(&ready_set, &self.validator_set, &StrictEd25519Verifier)?;
        let origin = statement.origin();
        let bytes = statement.try_cev1_bytes()?;
        let digest = slot_digest_v1(RecoveryBarrierPhaseV1::Start, &bytes);
        match self.preflight_slot_v1(origin, RecoveryBarrierPhaseV1::Start, digest)? {
            RecoveryBarrierAdmissionV1::ExactReplay => {
                return Ok(RecoveryBarrierAdmissionV1::ExactReplay);
            }
            RecoveryBarrierAdmissionV1::New => {}
            RecoveryBarrierAdmissionV1::Buffered => unreachable!("slot preflight never buffers"),
        }
        self.commit_slot_v1(origin, RecoveryBarrierPhaseV1::Start, digest)?;
        self.start.insert(origin, statement);
        Ok(RecoveryBarrierAdmissionV1::New)
    }

    pub(crate) fn ready_set_v1(&self) -> Result<RecoveryReadySetV1, RecoveryBarrierErrorV1> {
        self.ensure_live_v1()?;
        let statements = self
            .validator_set
            .validators()
            .iter()
            .map(|validator| self.ready.get(&validator.id()).cloned())
            .collect::<Option<Vec<_>>>()
            .ok_or(RecoveryBarrierErrorV1::Incomplete)?;
        RecoveryReadySetV1::new(
            self.context,
            statements,
            &self.validator_set,
            &StrictEd25519Verifier,
        )
        .map_err(Into::into)
    }

    pub(crate) fn start_certificate_v1(
        &self,
    ) -> Result<RecoveryStartCertificateV1, RecoveryBarrierErrorV1> {
        self.ensure_live_v1()?;
        let ready_set = self.ready_set_v1()?;
        let statements = self
            .validator_set
            .validators()
            .iter()
            .map(|validator| self.start.get(&validator.id()).cloned())
            .collect::<Option<Vec<_>>>()
            .ok_or(RecoveryBarrierErrorV1::Incomplete)?;
        RecoveryStartCertificateV1::new(
            ready_set,
            statements,
            &self.validator_set,
            &StrictEd25519Verifier,
        )
        .map_err(Into::into)
    }

    pub(crate) fn ready_count_v1(&self) -> usize {
        self.ready.len()
    }

    pub(crate) fn start_count_v1(&self) -> usize {
        self.start.len()
    }

    pub(crate) fn buffered_start_count_v1(&self) -> usize {
        self.buffered_start.len()
    }

    pub(crate) const fn is_poisoned_v1(&self) -> bool {
        self.poisoned
    }

    fn buffer_start_v1(
        &mut self,
        origin: ValidatorId,
        bytes: &[u8],
    ) -> Result<RecoveryBarrierAdmissionV1, RecoveryBarrierErrorV1> {
        let digest = slot_digest_v1(RecoveryBarrierPhaseV1::Start, bytes);
        if let Some(existing) = self.slots.get(&(origin, RecoveryBarrierPhaseV1::Start)) {
            if *existing == digest {
                return Ok(RecoveryBarrierAdmissionV1::ExactReplay);
            }
            self.poisoned = true;
            return Err(RecoveryBarrierErrorV1::Equivocation {
                origin: Box::new(origin),
                phase: RecoveryBarrierPhaseV1::Start,
            });
        }
        self.commit_slot_v1(origin, RecoveryBarrierPhaseV1::Start, digest)?;
        self.buffered_start.insert(origin, bytes.to_vec());
        Ok(RecoveryBarrierAdmissionV1::Buffered)
    }

    fn promote_buffered_starts_v1(&mut self) -> Result<(), RecoveryBarrierErrorV1> {
        if self.buffered_start.is_empty() {
            return Ok(());
        }
        let ready_set = self.ready_set_v1()?;
        let buffered = std::mem::take(&mut self.buffered_start);
        for (origin, bytes) in buffered {
            let statement = match decode_signed_recovery_start_v1_exact(
                &bytes,
                &ready_set,
                &self.validator_set,
                &StrictEd25519Verifier,
            ) {
                Ok(statement) if statement.origin() == origin => statement,
                Ok(_) => {
                    self.poisoned = true;
                    return Err(RecoveryBarrierErrorV1::AuthenticatedOriginMismatch);
                }
                Err(error) => {
                    self.poisoned = true;
                    return Err(error.into());
                }
            };
            self.start.insert(origin, statement);
        }
        Ok(())
    }

    fn preflight_slot_v1(
        &mut self,
        origin: ValidatorId,
        phase: RecoveryBarrierPhaseV1,
        digest: [u8; 32],
    ) -> Result<RecoveryBarrierAdmissionV1, RecoveryBarrierErrorV1> {
        if let Some(existing) = self.slots.get(&(origin, phase)) {
            if *existing == digest {
                return Ok(RecoveryBarrierAdmissionV1::ExactReplay);
            }
            self.poisoned = true;
            return Err(RecoveryBarrierErrorV1::Equivocation {
                origin: Box::new(origin),
                phase,
            });
        }
        if self.slots.len() == DIRECT7_RECOVERY_VALIDATOR_COUNT_V1 * 2 {
            self.poisoned = true;
            return Err(RecoveryBarrierErrorV1::Poisoned);
        }
        Ok(RecoveryBarrierAdmissionV1::New)
    }

    fn commit_slot_v1(
        &mut self,
        origin: ValidatorId,
        phase: RecoveryBarrierPhaseV1,
        digest: [u8; 32],
    ) -> Result<(), RecoveryBarrierErrorV1> {
        if self.slots.len() == DIRECT7_RECOVERY_VALIDATOR_COUNT_V1 * 2
            || self.slots.insert((origin, phase), digest).is_some()
        {
            self.poisoned = true;
            return Err(RecoveryBarrierErrorV1::Poisoned);
        }
        Ok(())
    }

    fn ensure_live_v1(&self) -> Result<(), RecoveryBarrierErrorV1> {
        if self.poisoned {
            Err(RecoveryBarrierErrorV1::Poisoned)
        } else {
            Ok(())
        }
    }
}

fn slot_digest_v1(phase: RecoveryBarrierPhaseV1, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SLOT_DIGEST_DOMAIN_V1);
    hasher.update([phase.tag_v1()]);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use trnm_consensus_types::{
        BlockId, ChainId, ConsensusParametersHash, ConsensusPublicKey, Epoch, GenesisHash, Height,
        ProtocolVersion, RecoveryContextV1Fields, RecoveryModeV1, StateRoot, Validator,
        ValidatorId, ValidatorSet, VotingPower,
    };

    use super::*;

    fn fixture_v1() -> (ValidatorSet, Vec<SigningKey>, RecoveryContextV1) {
        let keys = (0u8..7)
            .map(|index| SigningKey::from_bytes(&[0x31 + index; 32]))
            .collect::<Vec<_>>();
        let validators = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                Validator::new(
                    ValidatorId::new([0x41 + index as u8; 32]),
                    ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap()
            })
            .collect();
        let set = ValidatorSet::new(
            GenesisHash::new([0x11; 32]),
            ChainId::new("trnm-recovery-test").unwrap(),
            ProtocolVersion::new(1).unwrap(),
            Epoch::new(3),
            ConsensusParametersHash::new([0x12; 32]),
            validators,
        )
        .unwrap();
        let target = set.validators()[0].id();
        let context = RecoveryContextV1::new_direct7(
            RecoveryContextV1Fields {
                mode: RecoveryModeV1::ZeroDelta,
                campaign_context_sha256: [0x21; 32],
                fleet_start_certificate_sha256: [0x22; 32],
                validator_set_id: set.id(),
                validator_set_artifact_sha256: [0x23; 32],
                restart_cut_artifact_sha256: [0x24; 32],
                restart_park_artifact_sha256: [0x2b; 32],
                restart_parked_ack_artifact_sha256: [0x2c; 32],
                restart_parked_ack_admission_set_sha256: [0x2d; 32],
                caught_up_cut_artifact_sha256: [0x2a; 32],
                target_validator: target,
                process_instance: 2,
                recovery_nonce: [0x25; 32],
                restart_cut_epoch: Epoch::new(3),
                restart_cut_height: Height::new(9),
                restart_cut_block_id: BlockId::new([0x26; 32]),
                restart_cut_state_root: StateRoot::new([0x27; 32]),
                restart_cut_chain_root: [0x28; 32],
                terminal_epoch: Epoch::new(3),
                terminal_height: Height::new(9),
                terminal_block_id: BlockId::new([0x26; 32]),
                terminal_state_root: StateRoot::new([0x27; 32]),
                terminal_chain_root: [0x28; 32],
                node_facts_sha256: [0x29; 32],
            },
            &set,
        )
        .unwrap();
        (set, keys, context)
    }

    fn ready_statements_v1(
        context: RecoveryContextV1,
        set: &ValidatorSet,
        keys: &[SigningKey],
    ) -> Vec<SignedRecoveryReadyV1> {
        set.validators()
            .iter()
            .zip(keys)
            .map(|(validator, key)| {
                issue_local_recovery_ready_v1(context, validator.id(), set, key).unwrap()
            })
            .collect()
    }

    #[test]
    fn exact_ready_and_start_form_one_direct7_certificate_v1() {
        let (set, keys, context) = fixture_v1();
        let ready = ready_statements_v1(context, &set, &keys);
        let ready_set =
            RecoveryReadySetV1::new(context, ready.clone(), &set, &StrictEd25519Verifier).unwrap();
        let starts = set
            .validators()
            .iter()
            .zip(&keys)
            .map(|(validator, key)| {
                issue_local_recovery_start_v1(&ready_set, validator.id(), &set, key).unwrap()
            })
            .collect::<Vec<_>>();

        let mut round = RecoveryBarrierRoundV1::new(context, set.clone()).unwrap();
        for statement in ready.iter().rev() {
            let bytes = statement.try_cev1_bytes().unwrap();
            assert_eq!(
                round
                    .admit_ready_bytes_v1(statement.origin(), &bytes)
                    .unwrap(),
                RecoveryBarrierAdmissionV1::New
            );
        }
        assert_eq!(round.ready_count_v1(), 7);
        for statement in &starts {
            let bytes = statement.try_cev1_bytes().unwrap();
            assert_eq!(
                round
                    .admit_start_bytes_v1(statement.origin(), &bytes)
                    .unwrap(),
                RecoveryBarrierAdmissionV1::New
            );
        }
        let certificate = round.start_certificate_v1().unwrap();
        certificate.verify(&set, &StrictEd25519Verifier).unwrap();
        assert_eq!(certificate.statement_count(), 7);
        assert_eq!(round.start_count_v1(), 7);
        assert!(!round.is_poisoned_v1());
    }

    #[test]
    fn reordered_start_is_bounded_then_promoted_after_full_ready_v1() {
        let (set, keys, context) = fixture_v1();
        let ready = ready_statements_v1(context, &set, &keys);
        let ready_set =
            RecoveryReadySetV1::new(context, ready.clone(), &set, &StrictEd25519Verifier).unwrap();
        let early =
            issue_local_recovery_start_v1(&ready_set, set.validators()[1].id(), &set, &keys[1])
                .unwrap();
        let early_bytes = early.try_cev1_bytes().unwrap();
        let mut round = RecoveryBarrierRoundV1::new(context, set.clone()).unwrap();
        assert_eq!(
            round
                .admit_start_bytes_v1(early.origin(), &early_bytes)
                .unwrap(),
            RecoveryBarrierAdmissionV1::Buffered
        );
        assert_eq!(
            round
                .admit_start_bytes_v1(early.origin(), &early_bytes)
                .unwrap(),
            RecoveryBarrierAdmissionV1::ExactReplay
        );
        for statement in ready {
            round.admit_ready_v1(statement).unwrap();
        }
        assert_eq!(round.buffered_start_count_v1(), 0);
        assert_eq!(round.start_count_v1(), 1);
    }

    #[test]
    fn key_origin_context_and_buffer_equivocation_fail_closed_v1() {
        let (set, keys, context) = fixture_v1();
        assert_eq!(
            issue_local_recovery_ready_v1(context, set.validators()[0].id(), &set, &keys[1])
                .unwrap_err(),
            RecoveryBarrierErrorV1::LocalKeyMismatch
        );

        let ready =
            issue_local_recovery_ready_v1(context, set.validators()[0].id(), &set, &keys[0])
                .unwrap();
        let bytes = ready.try_cev1_bytes().unwrap();
        let mut round = RecoveryBarrierRoundV1::new(context, set.clone()).unwrap();
        assert_eq!(
            round
                .admit_ready_bytes_v1(set.validators()[1].id(), &bytes)
                .unwrap_err(),
            RecoveryBarrierErrorV1::AuthenticatedOriginMismatch
        );
        assert!(round.is_poisoned_v1());

        let mut buffered = RecoveryBarrierRoundV1::new(context, set.clone()).unwrap();
        assert_eq!(
            buffered
                .admit_start_bytes_v1(set.validators()[0].id(), &[1])
                .unwrap(),
            RecoveryBarrierAdmissionV1::Buffered
        );
        assert!(matches!(
            buffered.admit_start_bytes_v1(set.validators()[0].id(), &[2]),
            Err(RecoveryBarrierErrorV1::Equivocation {
                phase: RecoveryBarrierPhaseV1::Start,
                ..
            })
        ));
        assert!(buffered.is_poisoned_v1());
    }

    #[test]
    fn park_only_context_mismatch_cannot_enter_ready_barrier_v1() {
        let (set, keys, context) = fixture_v1();
        let mut alternate_fields = context.fields();
        alternate_fields.restart_park_artifact_sha256 = [0x7b; 32];
        let alternate = RecoveryContextV1::new_direct7(alternate_fields, &set).unwrap();
        let origin = set.validators()[0].id();
        let statement = issue_local_recovery_ready_v1(alternate, origin, &set, &keys[0]).unwrap();
        let mut round = RecoveryBarrierRoundV1::new(context, set).unwrap();

        assert!(matches!(
            round.admit_ready_v1(statement),
            Err(RecoveryBarrierErrorV1::Recovery(
                RecoveryErrorV1::ContextMismatch
            ))
        ));
        assert_eq!(round.ready_count_v1(), 0);
        assert!(!round.is_poisoned_v1());
    }

    #[test]
    fn incomplete_barriers_never_issue_full_authority_artifacts_v1() {
        let (set, keys, context) = fixture_v1();
        let mut round = RecoveryBarrierRoundV1::new(context, set.clone()).unwrap();
        for statement in ready_statements_v1(context, &set, &keys)
            .into_iter()
            .take(6)
        {
            round.admit_ready_v1(statement).unwrap();
        }
        assert_eq!(round.ready_count_v1(), 6);
        assert_eq!(
            round.ready_set_v1().unwrap_err(),
            RecoveryBarrierErrorV1::Incomplete
        );
        assert_eq!(
            round.start_certificate_v1().unwrap_err(),
            RecoveryBarrierErrorV1::Incomplete
        );
    }
}
