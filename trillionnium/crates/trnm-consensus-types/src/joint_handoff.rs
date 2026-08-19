use core::fmt;

use crate::{
    BlockId, BlockKind, CertificateId, CheckpointTwoSealKernelV0, ConsensusParametersHash,
    ConsensusParametersV0, Epoch, EpochAnchorAuthorizationKernelV0, FinalityProofV0, Height,
    NextEpochCommitmentHash, NextEpochCommitmentV0, ProtocolVersion, SignatureVerifier, StateRoot,
    ValidationError, ValidatorSet, ValidatorSetId, View,
};

/// Stable failures for the B2-F same-version joint-handoff composition kernel.
///
/// These are semantic/cryptographic composition outcomes, not CEV0 parser
/// failures. Exact decoders retain their existing `DecodeErrorCode` taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JointHandoffKernelErrorCode {
    UnsupportedProtocolUpgrade,
    InvalidOldContext,
    InvalidNewContext,
    InvalidCommitmentContext,
    InvalidCheckpointFinality,
    InvalidCertificateKernel,
    CheckpointHandoffMismatch,
    TerminalHandoffMismatch,
    InvalidSignature,
}

impl JointHandoffKernelErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedProtocolUpgrade => "unsupported_protocol_upgrade",
            Self::InvalidOldContext => "invalid_old_context",
            Self::InvalidNewContext => "invalid_new_context",
            Self::InvalidCommitmentContext => "invalid_commitment_context",
            Self::InvalidCheckpointFinality => "invalid_checkpoint_finality",
            Self::InvalidCertificateKernel => "invalid_certificate_kernel",
            Self::CheckpointHandoffMismatch => "checkpoint_handoff_mismatch",
            Self::TerminalHandoffMismatch => "terminal_handoff_mismatch",
            Self::InvalidSignature => "invalid_signature",
        }
    }
}

/// One stable B2-F failure class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JointHandoffKernelError {
    code: JointHandoffKernelErrorCode,
}

impl JointHandoffKernelError {
    const fn new(code: JointHandoffKernelErrorCode) -> Self {
        Self { code }
    }

    pub const fn code(self) -> JointHandoffKernelErrorCode {
        self.code
    }
}

impl fmt::Display for JointHandoffKernelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "joint-handoff kernel error {}",
            self.code.as_str()
        )
    }
}

impl core::error::Error for JointHandoffKernelError {}

pub type JointHandoffKernelResult<T> = core::result::Result<T, JointHandoffKernelError>;

/// Stable failures for the bounded same-version transition-proof kernel.
///
/// This kernel is deliberately a verification result only.  It does not
/// activate a Core, create a signer namespace, or mutate SafetyState.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SameVersionEpochTransitionKernelErrorCode {
    InvalidJointHandoff,
    InvalidNewEpochFinality,
    InvalidFirstNewEpochGeometry,
    AuthorizationSubstitution,
    UnsupportedTimeoutPath,
    InvalidNewEpochSignature,
}

impl SameVersionEpochTransitionKernelErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidJointHandoff => "invalid_joint_handoff",
            Self::InvalidNewEpochFinality => "invalid_new_epoch_finality",
            Self::InvalidFirstNewEpochGeometry => "invalid_first_new_epoch_geometry",
            Self::AuthorizationSubstitution => "authorization_substitution",
            Self::UnsupportedTimeoutPath => "unsupported_timeout_path",
            Self::InvalidNewEpochSignature => "invalid_new_epoch_signature",
        }
    }
}

/// One stable bounded transition-proof failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SameVersionEpochTransitionKernelError {
    code: SameVersionEpochTransitionKernelErrorCode,
}

impl SameVersionEpochTransitionKernelError {
    const fn new(code: SameVersionEpochTransitionKernelErrorCode) -> Self {
        Self { code }
    }

    pub const fn code(self) -> SameVersionEpochTransitionKernelErrorCode {
        self.code
    }
}

impl fmt::Display for SameVersionEpochTransitionKernelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "same-version epoch-transition kernel error {}",
            self.code.as_str()
        )
    }
}

impl core::error::Error for SameVersionEpochTransitionKernelError {}

pub type SameVersionEpochTransitionKernelResult<T> =
    core::result::Result<T, SameVersionEpochTransitionKernelError>;

/// Verified same-version relations across the B2-C, B2-E, and B2-B kernels.
///
/// This private-field token is deliberately inert. It records that one caller
/// supplied verifier accepted the old checkpoint/two-seal proof, terminal old
/// QC, and both handoff roles, and that every imported context/digest relation
/// is exact. It does not authenticate snapshot/JMT/runtime provenance,
/// deterministic candidate or fallback construction, proof of possession,
/// governance, or checkpoint execution. It therefore cannot construct an
/// epoch anchor, authorize handoff signing or a first-new-epoch proposal, or
/// activate a transition.
///
/// The token does not attest which `SignatureVerifier` implementation was
/// supplied. Production integration must use the strict Ed25519 verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JointHandoffKernelV0 {
    checkpoint_finality_proof_id: CertificateId,
    next_epoch_commitment_digest: NextEpochCommitmentHash,
    handoff_descriptor_digest: CertificateId,
    handoff_certificate_digest: CertificateId,
    old_epoch: Epoch,
    new_epoch: Epoch,
    old_validator_set_hash: ValidatorSetId,
    new_validator_set_hash: ValidatorSetId,
    old_consensus_parameters_hash: ConsensusParametersHash,
    new_consensus_parameters_hash: ConsensusParametersHash,
    checkpoint_height: Height,
    checkpoint_block_id: BlockId,
    checkpoint_state_root: StateRoot,
    terminal_old_height: Height,
    terminal_old_block_id: BlockId,
    terminal_old_qc_digest: CertificateId,
    activation_height: Height,
}

impl JointHandoffKernelV0 {
    pub const fn checkpoint_finality_proof_id(&self) -> CertificateId {
        self.checkpoint_finality_proof_id
    }

    pub const fn next_epoch_commitment_digest(&self) -> NextEpochCommitmentHash {
        self.next_epoch_commitment_digest
    }

    pub const fn handoff_descriptor_digest(&self) -> CertificateId {
        self.handoff_descriptor_digest
    }

    pub const fn handoff_certificate_digest(&self) -> CertificateId {
        self.handoff_certificate_digest
    }

    pub const fn old_epoch(&self) -> Epoch {
        self.old_epoch
    }

    pub const fn new_epoch(&self) -> Epoch {
        self.new_epoch
    }

    pub const fn old_validator_set_hash(&self) -> ValidatorSetId {
        self.old_validator_set_hash
    }

    pub const fn new_validator_set_hash(&self) -> ValidatorSetId {
        self.new_validator_set_hash
    }

    pub const fn old_consensus_parameters_hash(&self) -> ConsensusParametersHash {
        self.old_consensus_parameters_hash
    }

    pub const fn new_consensus_parameters_hash(&self) -> ConsensusParametersHash {
        self.new_consensus_parameters_hash
    }

    pub const fn checkpoint_height(&self) -> Height {
        self.checkpoint_height
    }

    pub const fn checkpoint_block_id(&self) -> BlockId {
        self.checkpoint_block_id
    }

    pub const fn checkpoint_state_root(&self) -> StateRoot {
        self.checkpoint_state_root
    }

    pub const fn terminal_old_height(&self) -> Height {
        self.terminal_old_height
    }

    pub const fn terminal_old_block_id(&self) -> BlockId {
        self.terminal_old_block_id
    }

    pub const fn terminal_old_qc_digest(&self) -> CertificateId {
        self.terminal_old_qc_digest
    }

    pub const fn activation_height(&self) -> Height {
        self.activation_height
    }
}

/// Verified relations spanning the terminal old epoch and the first finalized
/// new-epoch handoff block.
///
/// This private-field value remains inert because the supplied
/// [`SignatureVerifier`] is not attested.  The strict downstream wrapper in
/// `trnm-consensus-crypto` is the only API which upgrades these facts into a
/// strict-Ed25519 observation.  Neither value is Core/Safety activation
/// authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SameVersionEpochTransitionKernelV0 {
    joint_handoff: JointHandoffKernelV0,
    first_new_epoch_finality_proof_id: CertificateId,
    first_new_epoch_block_id: BlockId,
    first_new_epoch_height: Height,
    first_new_epoch_state_root: StateRoot,
    observed_new_epoch_tip_block_id: BlockId,
    observed_new_epoch_tip_height: Height,
    observed_new_epoch_tip_view: View,
}

impl SameVersionEpochTransitionKernelV0 {
    pub const fn joint_handoff(&self) -> &JointHandoffKernelV0 {
        &self.joint_handoff
    }

    pub const fn first_new_epoch_finality_proof_id(&self) -> CertificateId {
        self.first_new_epoch_finality_proof_id
    }

    pub const fn first_new_epoch_block_id(&self) -> BlockId {
        self.first_new_epoch_block_id
    }

    pub const fn first_new_epoch_height(&self) -> Height {
        self.first_new_epoch_height
    }

    pub const fn first_new_epoch_state_root(&self) -> StateRoot {
        self.first_new_epoch_state_root
    }

    pub const fn observed_new_epoch_tip_block_id(&self) -> BlockId {
        self.observed_new_epoch_tip_block_id
    }

    pub const fn observed_new_epoch_tip_height(&self) -> Height {
        self.observed_new_epoch_tip_height
    }

    pub const fn observed_new_epoch_tip_view(&self) -> View {
        self.observed_new_epoch_tip_view
    }
}

/// Verifies one exact, next-view-only same-version transition proof.
///
/// The function first re-runs the complete B2-F checkpoint/two-seal and dual
/// quorum composition.  It then validates one new-epoch three-chain whose
/// finalized target is the exact `EpochHandoff` block at activation height and
/// view one.  The embedded authorization must byte-match the B2-F certificate
/// kernel.  All three new-set proposer and certifying-QC signatures are
/// checked by the supplied verifier.
///
/// Skipped-view/TC handoff is intentionally outside this first bounded
/// tranche.  Success observes finality; it does not create a live Core,
/// SafetyState, signing permission, or persistence transition.
#[allow(clippy::too_many_arguments)]
pub fn verify_same_version_epoch_transition_proof_kernel_v0<V: SignatureVerifier>(
    old_checkpoint_finality: &FinalityProofV0,
    next_epoch_commitment: &NextEpochCommitmentV0,
    anchor_certificate_kernel: &EpochAnchorAuthorizationKernelV0,
    old_validator_set: &ValidatorSet,
    old_consensus_parameters: &ConsensusParametersV0,
    new_validator_set: &ValidatorSet,
    new_consensus_parameters: &ConsensusParametersV0,
    authenticated_checkpoint_parent_timestamp_ms: u64,
    first_new_epoch_finality: &FinalityProofV0,
    verifier: &V,
) -> SameVersionEpochTransitionKernelResult<SameVersionEpochTransitionKernelV0> {
    let joint_handoff = verify_same_version_joint_handoff_kernel_v0(
        old_checkpoint_finality,
        next_epoch_commitment,
        anchor_certificate_kernel,
        old_validator_set,
        old_consensus_parameters,
        new_validator_set,
        new_consensus_parameters,
        authenticated_checkpoint_parent_timestamp_ms,
        verifier,
    )
    .map_err(|_| {
        transition_error(SameVersionEpochTransitionKernelErrorCode::InvalidJointHandoff)
    })?;

    let first = first_new_epoch_finality.finalized_block();
    let child = first_new_epoch_finality.child();
    let grandchild = first_new_epoch_finality.grandchild();
    first_new_epoch_finality
        .validate(
            new_validator_set,
            Some(old_validator_set),
            new_consensus_parameters,
            anchor_certificate_kernel
                .terminal_old_header()
                .timestamp_ms(),
        )
        .map_err(|_| {
            transition_error(SameVersionEpochTransitionKernelErrorCode::InvalidNewEpochFinality)
        })?;

    let first_header = first.header();
    let child_header = child.header();
    let grandchild_header = grandchild.header();
    if first_header.block_kind() != BlockKind::EpochHandoff
        || first_header.epoch() != joint_handoff.new_epoch()
        || first_header.height() != joint_handoff.activation_height()
        || first_header.parent_id() != joint_handoff.terminal_old_block_id()
        || first_header.view() != View::new(1)
        || child_header.block_kind() != BlockKind::Regular
        || child_header.view() != View::new(2)
        || grandchild_header.block_kind() != BlockKind::Regular
        || grandchild_header.view() != View::new(3)
    {
        return Err(transition_error(
            SameVersionEpochTransitionKernelErrorCode::InvalidFirstNewEpochGeometry,
        ));
    }
    if first.timeout_certificate().is_some()
        || child.timeout_certificate().is_some()
        || grandchild.timeout_certificate().is_some()
    {
        return Err(transition_error(
            SameVersionEpochTransitionKernelErrorCode::UnsupportedTimeoutPath,
        ));
    }

    let authorization = first.epoch_anchor_authorization().ok_or_else(|| {
        transition_error(SameVersionEpochTransitionKernelErrorCode::AuthorizationSubstitution)
    })?;
    let expected_authorization = anchor_certificate_kernel.try_cev0_bytes().map_err(|_| {
        transition_error(SameVersionEpochTransitionKernelErrorCode::AuthorizationSubstitution)
    })?;
    let actual_authorization = authorization.try_cev0_bytes().map_err(|_| {
        transition_error(SameVersionEpochTransitionKernelErrorCode::AuthorizationSubstitution)
    })?;
    if actual_authorization != expected_authorization {
        return Err(transition_error(
            SameVersionEpochTransitionKernelErrorCode::AuthorizationSubstitution,
        ));
    }

    for certified in [first, child, grandchild] {
        certified
            .certifying_qc()
            .verify(new_validator_set, verifier)
            .map_err(|_| {
                transition_error(
                    SameVersionEpochTransitionKernelErrorCode::InvalidNewEpochSignature,
                )
            })?;
        let proposer = new_validator_set
            .validator(certified.header().proposer_id())
            .ok_or_else(|| {
                transition_error(
                    SameVersionEpochTransitionKernelErrorCode::InvalidNewEpochSignature,
                )
            })?;
        if !verifier.verify(
            proposer,
            &certified.proposal_signing_root(),
            certified.proposer_signature(),
        ) {
            return Err(transition_error(
                SameVersionEpochTransitionKernelErrorCode::InvalidNewEpochSignature,
            ));
        }
    }

    Ok(SameVersionEpochTransitionKernelV0 {
        joint_handoff,
        first_new_epoch_finality_proof_id: first_new_epoch_finality.id(),
        first_new_epoch_block_id: first_header.id(),
        first_new_epoch_height: first_header.height(),
        first_new_epoch_state_root: first_header.state_root(),
        observed_new_epoch_tip_block_id: grandchild_header.id(),
        observed_new_epoch_tip_height: grandchild_header.height(),
        observed_new_epoch_tip_view: grandchild_header.view(),
    })
}

/// Verifies the complete same-version joint-handoff composition kernel.
///
/// The input objects remain independently encoded values: protocol v0 defines
/// no aggregate handoff-bundle CEV0 object or digest. Successful verification
/// returns only [`JointHandoffKernelV0`], never an epoch-anchor authorization or
/// transition capability.
#[allow(clippy::too_many_arguments)]
pub fn verify_same_version_joint_handoff_kernel_v0<V: SignatureVerifier>(
    old_checkpoint_finality: &FinalityProofV0,
    next_epoch_commitment: &NextEpochCommitmentV0,
    anchor_certificate_kernel: &EpochAnchorAuthorizationKernelV0,
    old_validator_set: &ValidatorSet,
    old_consensus_parameters: &ConsensusParametersV0,
    new_validator_set: &ValidatorSet,
    new_consensus_parameters: &ConsensusParametersV0,
    authenticated_checkpoint_parent_timestamp_ms: u64,
    verifier: &V,
) -> JointHandoffKernelResult<JointHandoffKernelV0> {
    let commitment = next_epoch_commitment.fields();
    if commitment.new_protocol_version != ProtocolVersion::V0
        || commitment.upgrade_plan_hash.is_some()
        || old_validator_set.protocol_version() != ProtocolVersion::V0
        || new_validator_set.protocol_version() != ProtocolVersion::V0
        || old_consensus_parameters.protocol_version() != ProtocolVersion::V0.get()
        || new_consensus_parameters.protocol_version() != ProtocolVersion::V0.get()
    {
        return Err(error(
            JointHandoffKernelErrorCode::UnsupportedProtocolUpgrade,
        ));
    }

    old_validator_set
        .validate_against_parameters(old_consensus_parameters)
        .map_err(|_| error(JointHandoffKernelErrorCode::InvalidOldContext))?;
    if (
        old_validator_set.genesis_hash(),
        old_validator_set.chain_id(),
        old_validator_set.protocol_version(),
        old_validator_set.epoch(),
    ) != (
        commitment.genesis_hash,
        commitment.chain_id,
        ProtocolVersion::V0,
        commitment.old_epoch,
    ) {
        return Err(error(JointHandoffKernelErrorCode::InvalidOldContext));
    }

    new_validator_set
        .validate_against_parameters(new_consensus_parameters)
        .map_err(|_| error(JointHandoffKernelErrorCode::InvalidNewContext))?;
    if (
        new_validator_set.genesis_hash(),
        new_validator_set.chain_id(),
        new_validator_set.protocol_version(),
        new_validator_set.epoch(),
        new_validator_set.id(),
        new_validator_set.consensus_parameters_hash(),
    ) != (
        commitment.genesis_hash,
        commitment.chain_id,
        commitment.new_protocol_version,
        commitment.new_epoch,
        commitment.new_validator_set_hash,
        commitment.new_consensus_parameters_hash,
    ) {
        return Err(error(JointHandoffKernelErrorCode::InvalidNewContext));
    }

    next_epoch_commitment
        .validate_same_version_context(
            old_validator_set,
            old_consensus_parameters,
            new_validator_set,
            new_consensus_parameters,
        )
        .map_err(|_| error(JointHandoffKernelErrorCode::InvalidCommitmentContext))?;

    let checkpoint = old_checkpoint_finality
        .verify_checkpoint_two_seal_kernel(
            old_validator_set,
            old_consensus_parameters,
            next_epoch_commitment,
            authenticated_checkpoint_parent_timestamp_ms,
            verifier,
        )
        .map_err(|failure| {
            map_verification_failure(
                failure,
                JointHandoffKernelErrorCode::InvalidCheckpointFinality,
            )
        })?;

    anchor_certificate_kernel
        .verify_certificate_kernel(old_validator_set, new_validator_set, verifier)
        .map_err(|failure| {
            map_verification_failure(
                failure,
                JointHandoffKernelErrorCode::InvalidCertificateKernel,
            )
        })?;

    validate_composition_relations(
        &checkpoint,
        next_epoch_commitment,
        anchor_certificate_kernel,
        old_validator_set,
        old_consensus_parameters,
        new_validator_set,
        new_consensus_parameters,
    )?;

    let certificate = anchor_certificate_kernel.handoff_certificate();
    let descriptor = certificate.descriptor();
    Ok(JointHandoffKernelV0 {
        checkpoint_finality_proof_id: checkpoint.proof_id(),
        next_epoch_commitment_digest: checkpoint.next_epoch_commitment_digest(),
        handoff_descriptor_digest: descriptor.id(),
        handoff_certificate_digest: certificate.id(),
        old_epoch: checkpoint.old_epoch(),
        new_epoch: checkpoint.new_epoch(),
        old_validator_set_hash: old_validator_set.id(),
        new_validator_set_hash: new_validator_set.id(),
        old_consensus_parameters_hash: old_consensus_parameters.hash(),
        new_consensus_parameters_hash: new_consensus_parameters.hash(),
        checkpoint_height: checkpoint.checkpoint_height(),
        checkpoint_block_id: checkpoint.checkpoint_block_id(),
        checkpoint_state_root: checkpoint.checkpoint_state_root(),
        terminal_old_height: checkpoint.terminal_old_height(),
        terminal_old_block_id: checkpoint.terminal_old_block_id(),
        terminal_old_qc_digest: checkpoint.terminal_old_qc_digest(),
        activation_height: checkpoint.activation_height(),
    })
}

fn validate_composition_relations(
    checkpoint: &CheckpointTwoSealKernelV0,
    next_epoch_commitment: &NextEpochCommitmentV0,
    anchor_certificate_kernel: &EpochAnchorAuthorizationKernelV0,
    old_validator_set: &ValidatorSet,
    old_consensus_parameters: &ConsensusParametersV0,
    new_validator_set: &ValidatorSet,
    new_consensus_parameters: &ConsensusParametersV0,
) -> JointHandoffKernelResult<()> {
    let commitment = next_epoch_commitment.fields();
    let descriptor = anchor_certificate_kernel
        .handoff_certificate()
        .descriptor()
        .fields();

    if (
        descriptor.genesis_hash,
        descriptor.chain_id,
        descriptor.old_epoch,
        descriptor.new_epoch,
        descriptor.new_protocol_version,
        descriptor.new_validator_set_hash,
        descriptor.new_consensus_parameters_hash,
        descriptor.next_epoch_commitment_digest,
        descriptor.activation_height,
    ) != (
        commitment.genesis_hash,
        commitment.chain_id,
        commitment.old_epoch,
        commitment.new_epoch,
        commitment.new_protocol_version,
        commitment.new_validator_set_hash,
        commitment.new_consensus_parameters_hash,
        next_epoch_commitment.id(),
        commitment.activation_height,
    ) {
        return Err(error(JointHandoffKernelErrorCode::InvalidCommitmentContext));
    }

    if (
        descriptor.old_protocol_version,
        descriptor.old_validator_set_hash,
        descriptor.old_consensus_parameters_hash,
    ) != (
        old_validator_set.protocol_version(),
        old_validator_set.id(),
        old_consensus_parameters.hash(),
    ) {
        return Err(error(JointHandoffKernelErrorCode::InvalidOldContext));
    }
    if (
        descriptor.new_protocol_version,
        descriptor.new_validator_set_hash,
        descriptor.new_consensus_parameters_hash,
    ) != (
        new_validator_set.protocol_version(),
        new_validator_set.id(),
        new_consensus_parameters.hash(),
    ) {
        return Err(error(JointHandoffKernelErrorCode::InvalidNewContext));
    }

    if descriptor.old_epoch != checkpoint.old_epoch()
        || descriptor.new_epoch != checkpoint.new_epoch()
        || descriptor.checkpoint_height != checkpoint.checkpoint_height()
        || descriptor.checkpoint_block_id != checkpoint.checkpoint_block_id()
        || descriptor.checkpoint_state_root != checkpoint.checkpoint_state_root()
        || descriptor.next_epoch_commitment_digest != checkpoint.next_epoch_commitment_digest()
        || descriptor.activation_height != checkpoint.activation_height()
    {
        return Err(error(
            JointHandoffKernelErrorCode::CheckpointHandoffMismatch,
        ));
    }

    let terminal_header = anchor_certificate_kernel.terminal_old_header();
    let terminal_qc = anchor_certificate_kernel.terminal_old_qc();
    if descriptor.terminal_old_height != checkpoint.terminal_old_height()
        || descriptor.terminal_old_block_id != checkpoint.terminal_old_block_id()
        || descriptor.terminal_old_qc_digest != checkpoint.terminal_old_qc_digest()
        || terminal_header.height() != checkpoint.terminal_old_height()
        || terminal_header.id() != checkpoint.terminal_old_block_id()
        || terminal_qc.id() != checkpoint.terminal_old_qc_digest()
    {
        return Err(error(JointHandoffKernelErrorCode::TerminalHandoffMismatch));
    }

    Ok(())
}

const fn error(code: JointHandoffKernelErrorCode) -> JointHandoffKernelError {
    JointHandoffKernelError::new(code)
}

const fn transition_error(
    code: SameVersionEpochTransitionKernelErrorCode,
) -> SameVersionEpochTransitionKernelError {
    SameVersionEpochTransitionKernelError::new(code)
}

fn map_verification_failure(
    failure: ValidationError,
    fallback: JointHandoffKernelErrorCode,
) -> JointHandoffKernelError {
    if matches!(failure, ValidationError::InvalidSignature(_)) {
        error(JointHandoffKernelErrorCode::InvalidSignature)
    } else {
        error(fallback)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;
    use crate::{
        decode_epoch_anchor_authorization_kernel_v0_exact, BlockHeader, BlockKind, ChainId,
        ConsensusPublicKey, EpochAnchorAuthorizationV0, EpochFallbackReasonV0, EvidenceRoot,
        GenesisHash, HandoffCertificateV0, HandoffDescriptorV0, HandoffDescriptorV0Fields,
        NextEpochCommitmentV0Fields, OrderedRootV0, PayloadDigest, QcReferenceV0,
        QuorumCertificate, ReceiptsRoot, RootKind, Signature64, SignatureBytes, SignatureShareV0,
        SigningRoot, Validator, ValidatorId, View, Vote, VotingPower, SCHEMA_VERSION_V0,
    };

    const AUTHENTICATED_PARENT_TIMESTAMP_MS: u64 = 100;

    struct Fixture {
        old_parameters: ConsensusParametersV0,
        new_parameters: ConsensusParametersV0,
        old_set: ValidatorSet,
        new_set: ValidatorSet,
        commitment: NextEpochCommitmentV0,
        finality: FinalityProofV0,
        checkpoint_header: BlockHeader,
        terminal_header: BlockHeader,
        terminal_qc: crate::QuorumCertificate,
        descriptor: HandoffDescriptorV0,
        anchor_kernel: EpochAnchorAuthorizationKernelV0,
    }

    #[derive(Clone, Copy)]
    struct ByteRejectingVerifier(Option<u8>);

    impl SignatureVerifier for ByteRejectingVerifier {
        fn verify(
            &self,
            _validator: &Validator,
            _signing_root: &SigningRoot,
            signature: &SignatureBytes,
        ) -> bool {
            self.0
                .is_none_or(|rejected| signature.as_bytes()[0] != rejected)
        }
    }

    #[test]
    fn same_version_joint_handoff_returns_only_inert_bound_facts() {
        let fixture = fixture();
        let token = verify(
            &fixture,
            &fixture.anchor_kernel,
            &ByteRejectingVerifier(None),
        )
        .unwrap();

        assert_eq!(token.checkpoint_finality_proof_id(), fixture.finality.id());
        assert_eq!(
            token.next_epoch_commitment_digest(),
            fixture.commitment.id()
        );
        assert_eq!(token.handoff_descriptor_digest(), fixture.descriptor.id());
        assert_eq!(
            token.handoff_certificate_digest(),
            fixture.anchor_kernel.handoff_certificate().id()
        );
        assert_eq!(token.old_epoch(), Epoch::new(0));
        assert_eq!(token.new_epoch(), Epoch::new(1));
        assert_eq!(token.old_validator_set_hash(), fixture.old_set.id());
        assert_eq!(token.new_validator_set_hash(), fixture.new_set.id());
        assert_eq!(
            token.old_consensus_parameters_hash(),
            fixture.old_parameters.hash()
        );
        assert_eq!(
            token.new_consensus_parameters_hash(),
            fixture.new_parameters.hash()
        );
        assert_eq!(token.checkpoint_block_id(), fixture.checkpoint_header.id());
        assert_eq!(token.terminal_old_block_id(), fixture.terminal_header.id());
        assert_eq!(token.terminal_old_qc_digest(), fixture.terminal_qc.id());
        assert_eq!(token.activation_height(), Height::new(10_001));
    }

    #[test]
    fn same_version_transition_proof_binds_both_finality_sides() {
        let fixture = fixture();
        let first_new_epoch_finality = first_new_epoch_finality(&fixture);
        let token = verify_transition(
            &fixture,
            &first_new_epoch_finality,
            &ByteRejectingVerifier(None),
        )
        .unwrap();

        assert_eq!(token.joint_handoff().old_epoch(), Epoch::new(0));
        assert_eq!(token.joint_handoff().new_epoch(), Epoch::new(1));
        assert_eq!(
            token.joint_handoff().handoff_certificate_digest(),
            fixture.anchor_kernel.handoff_certificate().id()
        );
        assert_eq!(
            token.first_new_epoch_finality_proof_id(),
            first_new_epoch_finality.id()
        );
        assert_eq!(
            token.first_new_epoch_block_id(),
            first_new_epoch_finality.finalized_block().header().id()
        );
        assert_eq!(token.first_new_epoch_height(), Height::new(10_001));
        assert_eq!(token.first_new_epoch_state_root(), StateRoot::new([61; 32]));
        assert_eq!(
            token.observed_new_epoch_tip_block_id(),
            first_new_epoch_finality.grandchild().header().id()
        );
        assert_eq!(token.observed_new_epoch_tip_height(), Height::new(10_003));
        assert_eq!(token.observed_new_epoch_tip_view(), View::new(3));
    }

    #[test]
    fn transition_proof_rejects_old_new_and_authorization_substitution() {
        let fixture = fixture();
        let first_new_epoch_finality = first_new_epoch_finality(&fixture);

        let old_failure = verify_transition(
            &fixture,
            &first_new_epoch_finality,
            &ByteRejectingVerifier(Some(1)),
        )
        .unwrap_err();
        assert_eq!(
            old_failure.code(),
            SameVersionEpochTransitionKernelErrorCode::InvalidJointHandoff
        );

        let new_failure = verify_transition(
            &fixture,
            &first_new_epoch_finality,
            &ByteRejectingVerifier(Some(3)),
        )
        .unwrap_err();
        assert_eq!(
            new_failure.code(),
            SameVersionEpochTransitionKernelErrorCode::InvalidNewEpochSignature
        );

        let foreign_certificate = HandoffCertificateV0::new(
            fixture.descriptor.clone(),
            handoff_shares_with_byte(&fixture.old_set, 4),
            handoff_shares_with_byte(&fixture.new_set, 4),
            &fixture.old_set,
            &fixture.new_set,
        )
        .unwrap();
        let foreign_authorization = EpochAnchorAuthorizationV0::new(
            fixture.terminal_header.clone(),
            fixture.terminal_qc.clone(),
            foreign_certificate,
            &fixture.old_set,
            &fixture.new_set,
        )
        .unwrap();
        let substituted =
            first_new_epoch_finality_with_authorization(&fixture, foreign_authorization);
        let substitution_failure =
            verify_transition(&fixture, &substituted, &ByteRejectingVerifier(None)).unwrap_err();
        assert_eq!(
            substitution_failure.code(),
            SameVersionEpochTransitionKernelErrorCode::AuthorizationSubstitution
        );
    }

    #[test]
    fn old_new_and_upgrade_contexts_fail_with_stable_codes() {
        let fixture = fixture();
        let mut changed_fields = fixture.old_parameters.fields();
        changed_fields.base_timeout_ms += 1;
        let changed_parameters = ConsensusParametersV0::new(changed_fields).unwrap();

        let old_error = verify_same_version_joint_handoff_kernel_v0(
            &fixture.finality,
            &fixture.commitment,
            &fixture.anchor_kernel,
            &fixture.old_set,
            &changed_parameters,
            &fixture.new_set,
            &fixture.new_parameters,
            AUTHENTICATED_PARENT_TIMESTAMP_MS,
            &ByteRejectingVerifier(None),
        )
        .unwrap_err();
        assert_eq!(
            old_error.code(),
            JointHandoffKernelErrorCode::InvalidOldContext
        );

        let new_error = verify_same_version_joint_handoff_kernel_v0(
            &fixture.finality,
            &fixture.commitment,
            &fixture.anchor_kernel,
            &fixture.old_set,
            &fixture.old_parameters,
            &fixture.new_set,
            &changed_parameters,
            AUTHENTICATED_PARENT_TIMESTAMP_MS,
            &ByteRejectingVerifier(None),
        )
        .unwrap_err();
        assert_eq!(
            new_error.code(),
            JointHandoffKernelErrorCode::InvalidNewContext
        );

        let mut upgrade_fields = fixture.commitment.fields();
        upgrade_fields.new_protocol_version = ProtocolVersion::new(1).unwrap();
        upgrade_fields.upgrade_plan_hash = Some(crate::UpgradePlanHash::new([91; 32]));
        let upgrade = NextEpochCommitmentV0::new(upgrade_fields).unwrap();
        let upgrade_error = verify_same_version_joint_handoff_kernel_v0(
            &fixture.finality,
            &upgrade,
            &fixture.anchor_kernel,
            &fixture.old_set,
            &fixture.old_parameters,
            &fixture.new_set,
            &fixture.new_parameters,
            AUTHENTICATED_PARENT_TIMESTAMP_MS,
            &ByteRejectingVerifier(None),
        )
        .unwrap_err();
        assert_eq!(
            upgrade_error.code(),
            JointHandoffKernelErrorCode::UnsupportedProtocolUpgrade
        );
    }

    #[test]
    fn commitment_checkpoint_and_terminal_relation_mismatches_are_distinct() {
        let fixture = fixture();

        let foreign_commitment_digest = NextEpochCommitmentHash::new([71; 32]);
        let (foreign_terminal, foreign_terminal_qc) =
            alternate_terminal(&fixture, BlockId::new([72; 32]), foreign_commitment_digest);
        let mut commitment_mismatch_fields = fixture.descriptor.fields().clone();
        commitment_mismatch_fields.next_epoch_commitment_digest = foreign_commitment_digest;
        commitment_mismatch_fields.terminal_old_block_id = foreign_terminal.id();
        commitment_mismatch_fields.terminal_old_qc_digest = foreign_terminal_qc.id();
        let commitment_mismatch = anchor_kernel(
            &fixture,
            commitment_mismatch_fields,
            foreign_terminal,
            foreign_terminal_qc,
        );
        assert_eq!(
            verify(&fixture, &commitment_mismatch, &ByteRejectingVerifier(None))
                .unwrap_err()
                .code(),
            JointHandoffKernelErrorCode::InvalidCommitmentContext
        );

        let mut checkpoint_mismatch_fields = fixture.descriptor.fields().clone();
        checkpoint_mismatch_fields.checkpoint_block_id = BlockId::new([73; 32]);
        let checkpoint_mismatch = anchor_kernel(
            &fixture,
            checkpoint_mismatch_fields,
            fixture.terminal_header.clone(),
            fixture.terminal_qc.clone(),
        );
        assert_eq!(
            verify(&fixture, &checkpoint_mismatch, &ByteRejectingVerifier(None))
                .unwrap_err()
                .code(),
            JointHandoffKernelErrorCode::CheckpointHandoffMismatch
        );

        let (foreign_terminal, foreign_terminal_qc) =
            alternate_terminal(&fixture, BlockId::new([74; 32]), fixture.commitment.id());
        let mut terminal_mismatch_fields = fixture.descriptor.fields().clone();
        terminal_mismatch_fields.terminal_old_block_id = foreign_terminal.id();
        terminal_mismatch_fields.terminal_old_qc_digest = foreign_terminal_qc.id();
        let terminal_mismatch = anchor_kernel(
            &fixture,
            terminal_mismatch_fields,
            foreign_terminal,
            foreign_terminal_qc,
        );
        assert_eq!(
            verify(&fixture, &terminal_mismatch, &ByteRejectingVerifier(None))
                .unwrap_err()
                .code(),
            JointHandoffKernelErrorCode::TerminalHandoffMismatch
        );
    }

    #[test]
    fn checkpoint_admission_and_signature_failures_remain_fail_closed() {
        let fixture = fixture();
        let timestamp_error = verify_same_version_joint_handoff_kernel_v0(
            &fixture.finality,
            &fixture.commitment,
            &fixture.anchor_kernel,
            &fixture.old_set,
            &fixture.old_parameters,
            &fixture.new_set,
            &fixture.new_parameters,
            AUTHENTICATED_PARENT_TIMESTAMP_MS + 1,
            &ByteRejectingVerifier(None),
        )
        .unwrap_err();
        assert_eq!(
            timestamp_error.code(),
            JointHandoffKernelErrorCode::InvalidCheckpointFinality
        );

        let finality_signature_error = verify(
            &fixture,
            &fixture.anchor_kernel,
            &ByteRejectingVerifier(Some(1)),
        )
        .unwrap_err();
        assert_eq!(
            finality_signature_error.code(),
            JointHandoffKernelErrorCode::InvalidSignature
        );

        let handoff_signature_error = verify(
            &fixture,
            &fixture.anchor_kernel,
            &ByteRejectingVerifier(Some(2)),
        )
        .unwrap_err();
        assert_eq!(
            handoff_signature_error.code(),
            JointHandoffKernelErrorCode::InvalidSignature
        );
    }

    fn verify<V: SignatureVerifier>(
        fixture: &Fixture,
        kernel: &EpochAnchorAuthorizationKernelV0,
        verifier: &V,
    ) -> JointHandoffKernelResult<JointHandoffKernelV0> {
        verify_same_version_joint_handoff_kernel_v0(
            &fixture.finality,
            &fixture.commitment,
            kernel,
            &fixture.old_set,
            &fixture.old_parameters,
            &fixture.new_set,
            &fixture.new_parameters,
            AUTHENTICATED_PARENT_TIMESTAMP_MS,
            verifier,
        )
    }

    fn verify_transition<V: SignatureVerifier>(
        fixture: &Fixture,
        first_new_epoch_finality: &FinalityProofV0,
        verifier: &V,
    ) -> SameVersionEpochTransitionKernelResult<SameVersionEpochTransitionKernelV0> {
        verify_same_version_epoch_transition_proof_kernel_v0(
            &fixture.finality,
            &fixture.commitment,
            &fixture.anchor_kernel,
            &fixture.old_set,
            &fixture.old_parameters,
            &fixture.new_set,
            &fixture.new_parameters,
            AUTHENTICATED_PARENT_TIMESTAMP_MS,
            first_new_epoch_finality,
            verifier,
        )
    }

    fn fixture() -> Fixture {
        let old_parameters = ConsensusParametersV0::reference_shadow_v0();
        let new_parameters = old_parameters;
        let genesis_hash = GenesisHash::new([9; 32]);
        let chain_id = ChainId::new("trnm-b2f-kernel").unwrap();
        let old_set = validator_set(genesis_hash, chain_id, Epoch::new(0), &old_parameters, 1);
        let new_set = validator_set(genesis_hash, chain_id, Epoch::new(1), &new_parameters, 11);
        let checkpoint_state_root = StateRoot::new([31; 32]);
        let commitment = NextEpochCommitmentV0::new(NextEpochCommitmentV0Fields {
            schema_version: SCHEMA_VERSION_V0,
            genesis_hash,
            chain_id,
            old_epoch: Epoch::new(0),
            new_epoch: Epoch::new(1),
            snapshot_cutoff_height: Height::new(9_898),
            snapshot_state_root: StateRoot::new([30; 32]),
            new_protocol_version: ProtocolVersion::V0,
            new_validator_set_hash: new_set.id(),
            new_consensus_parameters_hash: new_parameters.hash(),
            rollout_phase: new_parameters.rollout_phase(),
            upgrade_plan_hash: None,
            fallback_used: false,
            fallback_reason: EpochFallbackReasonV0::None,
            activation_height: Height::new(10_001),
        })
        .unwrap();

        let parent_block_id = BlockId::new([40; 32]);
        let parent_qc = quorum_certificate(
            &old_set,
            View::new(1),
            Height::new(9_997),
            parent_block_id,
            1,
        );
        let checkpoint_header = header(
            &old_set,
            BlockKind::EpochCheckpoint,
            View::new(2),
            Height::new(9_998),
            parent_block_id,
            old_set.validators()[1].id(),
            checkpoint_state_root,
            commitment.id(),
            101,
            false,
        );
        let checkpoint_qc = quorum_certificate(
            &old_set,
            checkpoint_header.view(),
            checkpoint_header.height(),
            checkpoint_header.id(),
            1,
        );
        let checkpoint = crate::CertifiedHeaderV0::new(
            checkpoint_header.clone(),
            QcReferenceV0::ordinary(parent_qc),
            None,
            None,
            signature(1),
            checkpoint_qc.clone(),
            &old_set,
            None,
            &old_parameters,
            AUTHENTICATED_PARENT_TIMESTAMP_MS,
        )
        .unwrap();

        let seal_1_header = header(
            &old_set,
            BlockKind::EpochSeal1,
            View::new(3),
            Height::new(9_999),
            checkpoint_header.id(),
            old_set.validators()[2].id(),
            checkpoint_state_root,
            commitment.id(),
            102,
            true,
        );
        let seal_1_qc = quorum_certificate(
            &old_set,
            seal_1_header.view(),
            seal_1_header.height(),
            seal_1_header.id(),
            1,
        );
        let seal_1 = crate::CertifiedHeaderV0::new(
            seal_1_header.clone(),
            QcReferenceV0::ordinary(checkpoint_qc),
            None,
            None,
            signature(1),
            seal_1_qc.clone(),
            &old_set,
            None,
            &old_parameters,
            101,
        )
        .unwrap();

        let terminal_header = header(
            &old_set,
            BlockKind::EpochSeal2,
            View::new(4),
            Height::new(10_000),
            seal_1_header.id(),
            old_set.validators()[3].id(),
            checkpoint_state_root,
            commitment.id(),
            103,
            true,
        );
        let terminal_qc = quorum_certificate(
            &old_set,
            terminal_header.view(),
            terminal_header.height(),
            terminal_header.id(),
            1,
        );
        let seal_2 = crate::CertifiedHeaderV0::new(
            terminal_header.clone(),
            QcReferenceV0::ordinary(seal_1_qc),
            None,
            None,
            signature(1),
            terminal_qc.clone(),
            &old_set,
            None,
            &old_parameters,
            102,
        )
        .unwrap();
        let finality = FinalityProofV0::new(
            checkpoint,
            seal_1,
            seal_2,
            &old_set,
            None,
            &old_parameters,
            AUTHENTICATED_PARENT_TIMESTAMP_MS,
        )
        .unwrap();

        let descriptor = HandoffDescriptorV0::new(HandoffDescriptorV0Fields {
            genesis_hash,
            chain_id,
            old_epoch: Epoch::new(0),
            new_epoch: Epoch::new(1),
            old_protocol_version: ProtocolVersion::V0,
            new_protocol_version: ProtocolVersion::V0,
            old_validator_set_hash: old_set.id(),
            new_validator_set_hash: new_set.id(),
            old_consensus_parameters_hash: old_parameters.hash(),
            new_consensus_parameters_hash: new_parameters.hash(),
            checkpoint_height: checkpoint_header.height(),
            checkpoint_block_id: checkpoint_header.id(),
            checkpoint_state_root,
            next_epoch_commitment_digest: commitment.id(),
            terminal_old_height: terminal_header.height(),
            terminal_old_block_id: terminal_header.id(),
            terminal_old_qc_digest: terminal_qc.id(),
            terminal_old_view: terminal_header.view(),
            activation_height: Height::new(10_001),
            initial_new_view: View::new(1),
        })
        .unwrap();
        let anchor_kernel = anchor_kernel_from_parts(
            descriptor.clone(),
            terminal_header.clone(),
            terminal_qc.clone(),
            &old_set,
            &new_set,
        );

        Fixture {
            old_parameters,
            new_parameters,
            old_set,
            new_set,
            commitment,
            finality,
            checkpoint_header,
            terminal_header,
            terminal_qc,
            descriptor,
            anchor_kernel,
        }
    }

    fn validator_set(
        genesis_hash: GenesisHash,
        chain_id: ChainId,
        epoch: Epoch,
        parameters: &ConsensusParametersV0,
        key_start: u8,
    ) -> ValidatorSet {
        let validators = (0u8..4)
            .map(|index| {
                Validator::new(
                    ValidatorId::from_bytes(&[index + 1]).unwrap(),
                    ConsensusPublicKey::new([key_start + index; 32]),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap()
            })
            .collect();
        ValidatorSet::new(
            genesis_hash,
            chain_id,
            ProtocolVersion::V0,
            epoch,
            parameters.hash(),
            validators,
        )
        .unwrap()
    }

    fn first_new_epoch_finality(fixture: &Fixture) -> FinalityProofV0 {
        let authorization = EpochAnchorAuthorizationV0::new(
            fixture.anchor_kernel.terminal_old_header().clone(),
            fixture.anchor_kernel.terminal_old_qc().clone(),
            fixture.anchor_kernel.handoff_certificate().clone(),
            &fixture.old_set,
            &fixture.new_set,
        )
        .unwrap();
        first_new_epoch_finality_with_authorization(fixture, authorization)
    }

    fn first_new_epoch_finality_with_authorization(
        fixture: &Fixture,
        authorization: EpochAnchorAuthorizationV0,
    ) -> FinalityProofV0 {
        let first_header = new_epoch_header(
            &fixture.new_set,
            BlockKind::EpochHandoff,
            View::new(1),
            Height::new(10_001),
            fixture.terminal_header.id(),
            fixture.new_set.validators()[0].id(),
            StateRoot::new([61; 32]),
            104,
        );
        let first_qc = quorum_certificate(
            &fixture.new_set,
            first_header.view(),
            first_header.height(),
            first_header.id(),
            3,
        );
        let first = crate::CertifiedHeaderV0::new(
            first_header.clone(),
            QcReferenceV0::epoch_anchor(authorization.epoch_anchor_qc()),
            None,
            Some(authorization),
            signature(3),
            first_qc.clone(),
            &fixture.new_set,
            Some(&fixture.old_set),
            &fixture.new_parameters,
            fixture.terminal_header.timestamp_ms(),
        )
        .unwrap();

        let child_header = new_epoch_header(
            &fixture.new_set,
            BlockKind::Regular,
            View::new(2),
            Height::new(10_002),
            first_header.id(),
            fixture.new_set.validators()[1].id(),
            StateRoot::new([62; 32]),
            105,
        );
        let child_qc = quorum_certificate(
            &fixture.new_set,
            child_header.view(),
            child_header.height(),
            child_header.id(),
            3,
        );
        let child = crate::CertifiedHeaderV0::new(
            child_header.clone(),
            QcReferenceV0::ordinary(first_qc),
            None,
            None,
            signature(3),
            child_qc.clone(),
            &fixture.new_set,
            Some(&fixture.old_set),
            &fixture.new_parameters,
            first_header.timestamp_ms(),
        )
        .unwrap();

        let grandchild_header = new_epoch_header(
            &fixture.new_set,
            BlockKind::Regular,
            View::new(3),
            Height::new(10_003),
            child_header.id(),
            fixture.new_set.validators()[2].id(),
            StateRoot::new([63; 32]),
            106,
        );
        let grandchild_qc = quorum_certificate(
            &fixture.new_set,
            grandchild_header.view(),
            grandchild_header.height(),
            grandchild_header.id(),
            3,
        );
        let grandchild = crate::CertifiedHeaderV0::new(
            grandchild_header,
            QcReferenceV0::ordinary(child_qc),
            None,
            None,
            signature(3),
            grandchild_qc,
            &fixture.new_set,
            Some(&fixture.old_set),
            &fixture.new_parameters,
            child_header.timestamp_ms(),
        )
        .unwrap();

        FinalityProofV0::new(
            first,
            child,
            grandchild,
            &fixture.new_set,
            Some(&fixture.old_set),
            &fixture.new_parameters,
            fixture.terminal_header.timestamp_ms(),
        )
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn new_epoch_header(
        set: &ValidatorSet,
        block_kind: BlockKind,
        view: View,
        height: Height,
        parent_id: BlockId,
        proposer_id: ValidatorId,
        state_root: StateRoot,
        timestamp_ms: u64,
    ) -> BlockHeader {
        BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            view,
            height,
            block_kind,
            parent_id,
            proposer_id,
            set.id(),
            set.consensus_parameters_hash(),
            PayloadDigest::new([54; 32]),
            state_root,
            ReceiptsRoot::new([55; 32]),
            EvidenceRoot::new([56; 32]),
            timestamp_ms,
            None,
        )
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn header(
        set: &ValidatorSet,
        block_kind: BlockKind,
        view: View,
        height: Height,
        parent_id: BlockId,
        proposer_id: ValidatorId,
        state_root: StateRoot,
        commitment_digest: NextEpochCommitmentHash,
        timestamp_ms: u64,
        empty_roots: bool,
    ) -> BlockHeader {
        let (payload_root, receipts_root, evidence_root) = if empty_roots {
            (
                PayloadDigest::new(
                    OrderedRootV0::from_items::<&[u8]>(RootKind::Payload, &[])
                        .unwrap()
                        .digest(),
                ),
                ReceiptsRoot::new(
                    OrderedRootV0::from_items::<&[u8]>(RootKind::Receipts, &[])
                        .unwrap()
                        .digest(),
                ),
                EvidenceRoot::new(
                    OrderedRootV0::from_items::<&[u8]>(RootKind::Evidence, &[])
                        .unwrap()
                        .digest(),
                ),
            )
        } else {
            (
                PayloadDigest::new([51; 32]),
                ReceiptsRoot::new([52; 32]),
                EvidenceRoot::new([53; 32]),
            )
        };
        BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            view,
            height,
            block_kind,
            parent_id,
            proposer_id,
            set.id(),
            set.consensus_parameters_hash(),
            payload_root,
            state_root,
            receipts_root,
            evidence_root,
            timestamp_ms,
            Some(commitment_digest),
        )
        .unwrap()
    }

    fn quorum_certificate(
        set: &ValidatorSet,
        view: View,
        height: Height,
        block_id: BlockId,
        signature_byte: u8,
    ) -> QuorumCertificate {
        let votes = set.validators()[..3]
            .iter()
            .map(|validator| {
                Vote::new(
                    set.chain_id(),
                    set.protocol_version(),
                    set.epoch(),
                    view,
                    height,
                    block_id,
                    set.id(),
                    validator.id(),
                    signature(signature_byte),
                    set,
                )
                .unwrap()
            })
            .collect();
        QuorumCertificate::new(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            view,
            height,
            block_id,
            set.id(),
            votes,
            set,
        )
        .unwrap()
    }

    fn handoff_shares(set: &ValidatorSet) -> Vec<SignatureShareV0> {
        handoff_shares_with_byte(set, 2)
    }

    fn handoff_shares_with_byte(set: &ValidatorSet, signature_byte: u8) -> Vec<SignatureShareV0> {
        set.validators()[..3]
            .iter()
            .map(|validator| {
                SignatureShareV0::new(validator.id(), signature(signature_byte)).unwrap()
            })
            .collect()
    }

    fn anchor_kernel(
        fixture: &Fixture,
        descriptor_fields: HandoffDescriptorV0Fields,
        terminal_header: BlockHeader,
        terminal_qc: QuorumCertificate,
    ) -> EpochAnchorAuthorizationKernelV0 {
        anchor_kernel_from_parts(
            HandoffDescriptorV0::new(descriptor_fields).unwrap(),
            terminal_header,
            terminal_qc,
            &fixture.old_set,
            &fixture.new_set,
        )
    }

    fn anchor_kernel_from_parts(
        descriptor: HandoffDescriptorV0,
        terminal_header: BlockHeader,
        terminal_qc: QuorumCertificate,
        old_set: &ValidatorSet,
        new_set: &ValidatorSet,
    ) -> EpochAnchorAuthorizationKernelV0 {
        let certificate = HandoffCertificateV0::new(
            descriptor,
            handoff_shares(old_set),
            handoff_shares(new_set),
            old_set,
            new_set,
        )
        .unwrap();
        let authorization = EpochAnchorAuthorizationV0::new(
            terminal_header,
            terminal_qc,
            certificate,
            old_set,
            new_set,
        )
        .unwrap();
        decode_epoch_anchor_authorization_kernel_v0_exact(
            &authorization.try_cev0_bytes().unwrap(),
            old_set,
            new_set,
        )
        .unwrap()
    }

    fn alternate_terminal(
        fixture: &Fixture,
        parent_id: BlockId,
        commitment_digest: NextEpochCommitmentHash,
    ) -> (BlockHeader, QuorumCertificate) {
        let header = header(
            &fixture.old_set,
            BlockKind::EpochSeal2,
            View::new(4),
            Height::new(10_000),
            parent_id,
            fixture.old_set.validators()[3].id(),
            fixture.checkpoint_header.state_root(),
            commitment_digest,
            103,
            true,
        );
        let qc = quorum_certificate(
            &fixture.old_set,
            header.view(),
            header.height(),
            header.id(),
            1,
        );
        (header, qc)
    }

    const fn signature(byte: u8) -> Signature64 {
        Signature64::from_array([byte; crate::SIGNATURE_BYTES])
    }
}
