use ::core::{
    cell::{Cell, RefCell},
    sync::atomic::{AtomicUsize, Ordering},
};
use alloc::{boxed::Box, collections::BTreeSet, vec, vec::Vec};

use trnm_consensus_safety_rules::{
    InertSafetyTransitionKindV1, SafetyRulesDurableTransitionStoreV1, SafetyRulesStateDigestV1,
};
use trnm_consensus_types::{
    decode_application_payload_v0_exact, decode_double_vote_evidence_v0_exact,
    decode_finality_proof_v0_exact_with_trusted_genesis, ApplicationPayloadV0, Block, BlockBodyV0,
    BlockHeader, BlockId, BlockKind, CanonicalSignIntentV0, CanonicalSignPreimageV0, CertificateId,
    CertifiedHeaderV0, ChainId, ConsensusParametersV0, ConsensusPublicKey, ContextAuthorizedQcV0,
    Epoch, EpochGeometryV0, EvidenceRoot, ExecutionReceiptCommitmentV0, ExecutionReceiptsV0,
    FinalityProofV0, GenesisHash, GenesisQcApplicationBindingV0, GenesisQcV0, Height,
    NextEpochCommitmentHash, PayloadDigest, ProposalWitnessV0, ProtocolVersion, QcRef,
    QcReferenceV0, QuorumCertificate, ReceiptsRoot, SignatureBytes, SignatureVerifier,
    SignedProposalV0, SigningRoot, StateRoot, TimeoutCertificateV0, TimeoutEntryV0, TimeoutVote,
    ValidatedBlockCommitmentsV0, ValidationError, Validator, ValidatorId, ValidatorSet, View, Vote,
    VotingPower, SIGNATURE_BYTES,
};

use crate::{
    block_tree::{BlockTree, PayloadTransition},
    core::payload_parent_context_matches_target_v0,
};

use super::*;

const CHAIN: ChainId = ChainId::from_static("trnm-core-test-0");
const GENESIS: BlockId = BlockId::new([0xA5; 32]);
const GENESIS_TIMESTAMP_MS: u64 = 0;

const _: () = {
    assert!(CORE_BOUNDED_EXACT_VALIDATED_PROPOSAL_RETENTION_V0);
    assert!(CORE_PROPOSAL_RETENTION_AGGREGATE_RESOURCE_BUDGET_ENFORCED_V1);
    assert!(CORE_PROPOSAL_RETENTION_ARC_BACKED_V1);
    assert!(CORE_MAX_RETAINED_VALIDATED_PROPOSAL_RESOURCE_BYTES_V1 > 0);
    assert!(!CORE_PROPOSAL_RETENTION_APPLICATION_VALID_AUTHORITY_V0);
    assert!(!CORE_PROPOSAL_RETENTION_FINALITY_AUTHORITY_V0);
    assert!(!CORE_PROPOSAL_RETENTION_PERSISTENCE_AUTHORITY_V0);
    assert!(!CORE_PROPOSAL_RETENTION_SIGNER_AUTHORITY_V0);
    assert!(CORE_SAFETY_RULES_SHADOW_EVALUATION_V1);
    assert!(CORE_SAFETY_RULES_MAX_ANCESTRY_BLOCKS_V1 == 64);
    assert!(CORE_SAFETY_RULES_ANCESTRY_OVER_BOUND_FAILS_CLOSED_V1);
    assert!(!CORE_SAFETY_RULES_LONG_ANCESTRY_LIVENESS_EQUIVALENCE_V1);
    assert!(!CORE_SAFETY_RULES_AUTHORITATIVE_V1);
    assert!(!CORE_SAFETY_RULES_APPLICATION_VALID_AUTHORITY_V1);
    assert!(!CORE_SAFETY_RULES_PERSISTENCE_AUTHORITY_V1);
    assert!(!CORE_SAFETY_RULES_SIGNER_AUTHORITY_V1);
    assert!(!CORE_SAFETY_RULES_RECOVERY_REPLAY_AUTHORITY_V1);
    assert!(!CORE_SAFETY_RULES_REMOTE_WIRE_V1);
    assert!(!CORE_SAFETY_RULES_RUNTIME_ACTIVATION_V1);
    assert!(!CORE_SAFETY_RULES_PRODUCTION_CANDIDATE_V1);
    assert!(!CORE_SAFETY_RULES_PRODUCTION_CONSENSUS_ACTIVATION_V1);
};

#[derive(Debug, Clone, Copy)]
struct RootSignatures;

impl SignatureVerifier for RootSignatures {
    fn verify(
        &self,
        _validator: &Validator,
        signing_root: &SigningRoot,
        signature: &SignatureBytes,
    ) -> bool {
        signature.as_bytes()[..32] == signing_root.as_bytes()[..]
            && signature.as_bytes()[32..] == signing_root.as_bytes()[..]
    }
}

#[derive(Debug, Clone, Copy)]
struct RejectSignatures;

impl SignatureVerifier for RejectSignatures {
    fn verify(
        &self,
        _validator: &Validator,
        _signing_root: &SigningRoot,
        _signature: &SignatureBytes,
    ) -> bool {
        false
    }
}

#[derive(Debug, Default)]
struct CoreAuthorityTransitionStore {
    transitions: Vec<(SafetyRulesStateDigestV1, SafetyRulesStateDigestV1)>,
    fail: bool,
}

impl SafetyRulesDurableTransitionStoreV1 for CoreAuthorityTransitionStore {
    type Error = &'static str;

    fn persist_transition_v1(
        &mut self,
        transition: &trnm_consensus_safety_rules::InertSafetyTransitionV1,
    ) -> ::core::result::Result<(), Self::Error> {
        if self.fail {
            return Err("simulated Core authority persistence failure");
        }
        self.transitions.push((
            transition.predecessor_state_digest(),
            transition.successor_state().digest(),
        ));
        Ok(())
    }
}

/// Records every delegated crypto call while retaining the deterministic test
/// signature semantics. The admission-cache tests assert that raw calls are
/// exactly the number of unique `(validator, root, signature)` tuples.
type RecordedSignatureKey = (ValidatorId, [u8; 32], [u8; 64]);

#[derive(Debug, Default)]
struct RecordingSignatures {
    calls: AtomicUsize,
    unique: RefCell<BTreeSet<RecordedSignatureKey>>,
    accept: Cell<bool>,
}

impl RecordingSignatures {
    fn accepting() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            unique: RefCell::new(BTreeSet::new()),
            accept: Cell::new(true),
        }
    }

    fn rejecting() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            unique: RefCell::new(BTreeSet::new()),
            accept: Cell::new(false),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }

    fn unique_calls(&self) -> usize {
        self.unique.borrow().len()
    }
}

impl SignatureVerifier for RecordingSignatures {
    fn verify(
        &self,
        validator: &Validator,
        signing_root: &SigningRoot,
        signature: &SignatureBytes,
    ) -> bool {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let valid = signature.as_bytes()[..32] == signing_root.as_bytes()[..]
            && signature.as_bytes()[32..] == signing_root.as_bytes()[..];
        if self.accept.get() && valid {
            self.unique.borrow_mut().insert((
                validator.id(),
                *signing_root.as_bytes(),
                *signature.as_bytes(),
            ));
            true
        } else {
            false
        }
    }
}

fn version() -> ProtocolVersion {
    ProtocolVersion::V0
}

fn validator_id(index: u8) -> ValidatorId {
    ValidatorId::new([index; 32])
}

fn consensus_parameters() -> ConsensusParametersV0 {
    ConsensusParametersV0::reference_shadow_v0()
}

fn short_epoch_parameters() -> ConsensusParametersV0 {
    let mut fields = consensus_parameters().fields();
    fields.epoch_length_blocks = 6;
    fields.snapshot_lead_blocks = 3;
    ConsensusParametersV0::new(fields).expect("valid short epoch parameters")
}

fn validator_set() -> ValidatorSet {
    validator_set_with_parameters(&consensus_parameters())
}

fn validator_set_with_parameters(parameters: &ConsensusParametersV0) -> ValidatorSet {
    let validators = (1..=4)
        .map(|index| {
            Validator::new(
                validator_id(index),
                ConsensusPublicKey::new([index.saturating_add(100); 32]),
                VotingPower::new(1).expect("positive voting power"),
            )
            .expect("valid validator")
        })
        .collect();
    ValidatorSet::new(
        GenesisHash::new([0xA5; 32]),
        CHAIN,
        version(),
        Epoch::new(0),
        parameters.hash(),
        validators,
    )
    .expect("valid validator set")
}

fn signature(root: SigningRoot) -> SignatureBytes {
    let mut bytes = [0u8; SIGNATURE_BYTES];
    bytes[..32].copy_from_slice(root.as_bytes());
    bytes[32..].copy_from_slice(root.as_bytes());
    SignatureBytes::from_array(bytes)
}

fn signed_vote(
    set: &ValidatorSet,
    view: u64,
    height: u64,
    block_id: BlockId,
    author: ValidatorId,
) -> Vote {
    let root = Vote::signing_root_for_set(set, View::new(view), Height::new(height), block_id)
        .expect("valid vote signing context");
    Vote::new(
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(view),
        Height::new(height),
        block_id,
        set.id(),
        author,
        signature(root),
        set,
    )
    .expect("valid signed vote")
}

fn qc(set: &ValidatorSet, view: u64, height: u64, block_id: BlockId) -> QuorumCertificate {
    qc_with_authors(set, view, height, block_id, &[1, 2, 3])
}

fn qc_with_authors(
    set: &ValidatorSet,
    view: u64,
    height: u64,
    block_id: BlockId,
    authors: &[u8],
) -> QuorumCertificate {
    let votes = authors
        .iter()
        .copied()
        .map(|author| signed_vote(set, view, height, block_id, validator_id(author)))
        .collect();
    QuorumCertificate::new(
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(view),
        Height::new(height),
        block_id,
        set.id(),
        votes,
        set,
    )
    .expect("valid QC")
}

fn genesis_qc(set: &ValidatorSet) -> GenesisQcV0 {
    GenesisQcV0::new(set.genesis_hash(), set.chain_id(), set).expect("valid GenesisQC")
}

trait IntoQcReference {
    fn into_qc_reference(self) -> QcReferenceV0;
}

impl IntoQcReference for GenesisQcV0 {
    fn into_qc_reference(self) -> QcReferenceV0 {
        QcReferenceV0::genesis_anchor(self)
    }
}

impl IntoQcReference for QuorumCertificate {
    fn into_qc_reference(self) -> QcReferenceV0 {
        QcReferenceV0::ordinary(self)
    }
}

impl IntoQcReference for QcReferenceV0 {
    fn into_qc_reference(self) -> QcReferenceV0 {
        self
    }
}

fn block(
    set: &ValidatorSet,
    view: u64,
    height: u64,
    parent: BlockId,
    payload: &[u8],
    proposer: ValidatorId,
) -> Block {
    block_with_timestamp(
        set,
        view,
        height,
        parent,
        payload,
        proposer,
        height.saturating_mul(100),
    )
}

fn canonical_body_and_receipts(payload: &[u8]) -> (BlockBodyV0, ExecutionReceiptsV0) {
    let application_payload =
        ApplicationPayloadV0::new(vec![payload.to_vec()]).expect("canonical test payload");
    let receipt =
        ExecutionReceiptCommitmentV0::for_transaction(&application_payload, 0, 0, 0, Vec::new())
            .expect("canonical test receipt");
    let receipts = ExecutionReceiptsV0::new(&application_payload, vec![receipt])
        .expect("canonical test receipt list");
    let body =
        BlockBodyV0::new(application_payload, Vec::new()).expect("canonical test block body");
    (body, receipts)
}

#[allow(clippy::too_many_arguments)]
fn block_with_timestamp(
    set: &ValidatorSet,
    view: u64,
    height: u64,
    parent: BlockId,
    payload: &[u8],
    proposer: ValidatorId,
    timestamp_ms: u64,
) -> Block {
    let (body, receipts) = canonical_body_and_receipts(payload);
    let header = BlockHeader::new(
        set.genesis_hash(),
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(view),
        Height::new(height),
        BlockKind::Regular,
        parent,
        proposer,
        set.id(),
        set.consensus_parameters_hash(),
        body.payload_root().expect("canonical payload root"),
        StateRoot::new([height as u8; 32]),
        receipts.receipts_root().expect("canonical receipts root"),
        body.evidence_root().expect("canonical evidence root"),
        timestamp_ms,
        None,
    )
    .expect("valid header");
    Block::new(
        header,
        body.application_payload()
            .try_cev0_bytes()
            .expect("canonical application payload"),
        body.evidence()
            .iter()
            .map(|item| item.try_cev0_bytes().expect("canonical evidence"))
            .collect(),
    )
    .expect("payload matches header")
}

#[allow(clippy::too_many_arguments)]
fn block_with_anchor_test_header_fields(
    set: &ValidatorSet,
    view: u64,
    height: u64,
    parent: BlockId,
    payload: &[u8],
    proposer: ValidatorId,
    timestamp_ms: u64,
    state_root: StateRoot,
    block_kind: BlockKind,
    next_epoch_commitment_hash: Option<NextEpochCommitmentHash>,
) -> Block {
    let (body, receipts) = canonical_body_and_receipts(payload);
    let header = BlockHeader::new(
        set.genesis_hash(),
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(view),
        Height::new(height),
        block_kind,
        parent,
        proposer,
        set.id(),
        set.consensus_parameters_hash(),
        body.payload_root().expect("canonical payload root"),
        state_root,
        receipts.receipts_root().expect("canonical receipts root"),
        body.evidence_root().expect("canonical evidence root"),
        timestamp_ms,
        next_epoch_commitment_hash,
    )
    .expect("shape-valid anchor test header");
    Block::new(
        header,
        body.application_payload()
            .try_cev0_bytes()
            .expect("canonical application payload"),
        body.evidence()
            .iter()
            .map(|item| item.try_cev0_bytes().expect("canonical evidence"))
            .collect(),
    )
    .expect("anchor test payload matches header")
}

fn try_proposal_with_proposer<J: IntoQcReference>(
    set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
    justify: J,
    view: u64,
    payload: &[u8],
    proposer: ValidatorId,
) -> ::core::result::Result<SignedProposalV0, ValidationError> {
    let justify = justify.into_qc_reference();
    let justify_ref = justify.qc_ref();
    let proposed = block(
        set,
        view,
        justify_ref.height().get() + 1,
        justify_ref.block_id(),
        payload,
        proposer,
    );
    signed_proposal_from_block(
        set,
        parameters,
        proposed,
        justify,
        None,
        justify_ref.height().get().saturating_mul(100),
    )
}

fn proposal<J: IntoQcReference>(
    set: &ValidatorSet,
    justify: J,
    view: u64,
    payload: &[u8],
) -> SignedProposalV0 {
    try_proposal_with_proposer(
        set,
        &consensus_parameters(),
        justify,
        view,
        payload,
        leader_for(set, View::new(view)),
    )
    .expect("valid signed proposal")
}

fn proposal_with_parameters<J: IntoQcReference>(
    set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
    justify: J,
    view: u64,
    payload: &[u8],
) -> SignedProposalV0 {
    try_proposal_with_proposer(
        set,
        parameters,
        justify,
        view,
        payload,
        leader_for(set, View::new(view)),
    )
    .expect("valid signed proposal")
}

fn proposal_from_block<J: IntoQcReference>(
    set: &ValidatorSet,
    proposed: Block,
    justify: J,
) -> SignedProposalV0 {
    let justify = justify.into_qc_reference();
    let authenticated_parent_timestamp_ms = justify.qc_ref().height().get().saturating_mul(100);
    signed_proposal_from_block(
        set,
        &consensus_parameters(),
        proposed,
        justify,
        None,
        authenticated_parent_timestamp_ms,
    )
    .expect("valid signed proposal")
}

fn same_signed_envelope_with_body_bytes(
    set: &ValidatorSet,
    proposal: &SignedProposalV0,
    application_payload: Vec<u8>,
) -> SignedProposalV0 {
    let replacement = Block::new(
        proposal.block().header().clone(),
        application_payload,
        proposal.block().evidence_objects().to_vec(),
    )
    .expect("replacement body retains a valid header envelope");
    let parent_timestamp_ms = proposal
        .witness()
        .justify_qc()
        .qc_ref()
        .height()
        .get()
        .saturating_mul(100);
    SignedProposalV0::new(
        replacement,
        proposal.witness().clone(),
        set,
        None,
        &consensus_parameters(),
        parent_timestamp_ms,
    )
    .expect("body bytes are not independently trusted by proposal shape validation")
}

fn signed_proposal_from_block(
    set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
    proposed: Block,
    justify: QcReferenceV0,
    timeout_certificate: Option<TimeoutCertificateV0>,
    authenticated_parent_timestamp_ms: u64,
) -> ::core::result::Result<SignedProposalV0, ValidationError> {
    let signing_root = ProposalWitnessV0::signing_root_for(
        proposed.header(),
        &justify,
        timeout_certificate.as_ref(),
        None,
    )?;
    let witness = ProposalWitnessV0::new(
        proposed.header(),
        justify,
        timeout_certificate,
        None,
        signature(signing_root),
        set,
        None,
        parameters,
        authenticated_parent_timestamp_ms,
    )?;
    SignedProposalV0::new(
        proposed,
        witness,
        set,
        None,
        parameters,
        authenticated_parent_timestamp_ms,
    )
}

fn timeout_vote(set: &ValidatorSet, view: u64, high_qc: QcRef, author: ValidatorId) -> TimeoutVote {
    let root = TimeoutVote::signing_root_for_set(set, View::new(view), high_qc)
        .expect("valid timeout signing context");
    TimeoutVote::new(
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(view),
        set.id(),
        high_qc,
        author,
        signature(root),
        set,
    )
    .expect("valid timeout vote")
}

fn timeout_certificate<J: IntoQcReference>(
    set: &ValidatorSet,
    view: u64,
    high_qc: J,
) -> TimeoutCertificateV0 {
    let high_qc = high_qc.into_qc_reference();
    let high_ref = high_qc.qc_ref();
    let entries = (1..=3)
        .map(|author| {
            let author = validator_id(author);
            let vote = timeout_vote(set, view, high_ref, author);
            TimeoutEntryV0::new(author, high_ref, *vote.signature()).expect("valid timeout entry")
        })
        .collect();
    TimeoutCertificateV0::new(
        View::new(view),
        entries,
        vec![high_qc.clone()],
        high_qc.id(),
        set,
    )
    .expect("valid TimeoutCertificateV0")
}

fn timeout_certificate_with_two_qcs(
    set: &ValidatorSet,
    view: u64,
    lower: QuorumCertificate,
    selected: QuorumCertificate,
) -> TimeoutCertificateV0 {
    assert!(lower.view() < selected.view());
    let lower_ref = QcRef::from(&lower);
    let selected_ref = QcRef::from(&selected);
    let entries = [
        timeout_vote(set, view, lower_ref, validator_id(1)),
        timeout_vote(set, view, selected_ref, validator_id(2)),
        timeout_vote(set, view, selected_ref, validator_id(3)),
    ]
    .into_iter()
    .map(|vote| {
        TimeoutEntryV0::new(vote.author(), vote.high_qc(), *vote.signature())
            .expect("valid timeout entry")
    })
    .collect();
    let mut referenced = vec![
        QcReferenceV0::ordinary(lower),
        QcReferenceV0::ordinary(selected.clone()),
    ];
    referenced.sort_by_key(QcReferenceV0::id);
    TimeoutCertificateV0::new(View::new(view), entries, referenced, selected.id(), set)
        .expect("valid multi-QC TimeoutCertificateV0")
}

fn timeout_proposal(
    set: &ValidatorSet,
    certificate: TimeoutCertificateV0,
    payload: &[u8],
) -> SignedProposalV0 {
    timeout_proposal_with_parameters(set, &consensus_parameters(), certificate, payload)
}

fn timeout_proposal_with_parameters(
    set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
    certificate: TimeoutCertificateV0,
    payload: &[u8],
) -> SignedProposalV0 {
    let view = certificate
        .timed_out_view()
        .checked_next()
        .expect("test view does not overflow");
    let high_qc = certificate
        .referenced_qcs()
        .iter()
        .find(|reference| reference.id() == certificate.selected_high_qc_digest())
        .cloned()
        .expect("TC selects an exact referenced QC");
    let high_ref = high_qc.qc_ref();
    let proposer = leader_for(set, view);
    let proposed = block(
        set,
        view.get(),
        high_ref.height().get() + 1,
        high_ref.block_id(),
        payload,
        proposer,
    );
    signed_proposal_from_block(
        set,
        parameters,
        proposed,
        high_qc,
        Some(certificate),
        high_ref.height().get().saturating_mul(100),
    )
    .expect("valid timeout-justified proposal")
}

fn configured_core() -> (CoreConfig, Core) {
    configured_core_with_parameters(consensus_parameters())
}

fn configured_core_with_parameters(parameters: ConsensusParametersV0) -> (CoreConfig, Core) {
    let set = validator_set_with_parameters(&parameters);
    let config = CoreConfig::new(
        validator_id(1),
        set.clone(),
        parameters,
        GENESIS_TIMESTAMP_MS,
        32,
        64,
    )
    .expect("valid config");
    let core =
        Core::new(config.clone(), genesis_qc(&set), &RootSignatures).expect("valid bootstrap");
    (config, core)
}

fn assert_one_crypto_pass(input: Input) {
    let (_config, mut core) = configured_core();
    let verifier = RecordingSignatures::accepting();
    let result = core.step(input, &verifier);
    assert!(
        result.is_ok(),
        "authenticated input was rejected: {result:?}"
    );
    assert_eq!(
        verifier.calls(),
        verifier.unique_calls(),
        "one input caused duplicate underlying signature verification"
    );
}

#[test]
fn preauthentication_cache_covers_all_peer_message_kinds() {
    let (config, _core) = configured_core();
    let set = config.validator_set();
    let parent = BlockId::new([0x31; 32]);
    let ordinary_qc = qc(set, 1, 1, parent);

    assert_one_crypto_pass(Input::Proposal(Box::new(proposal(
        set,
        genesis_qc(set),
        1,
        b"preauth-proposal",
    ))));
    assert_one_crypto_pass(Input::SyncedProposal(Box::new(proposal(
        set,
        genesis_qc(set),
        1,
        b"preauth-synced",
    ))));
    assert_one_crypto_pass(Input::Vote(signed_vote(set, 1, 1, parent, validator_id(1))));
    assert_one_crypto_pass(Input::TimeoutVote(timeout_vote(
        set,
        2,
        QcRef::from(&ordinary_qc),
        validator_id(1),
    )));
    assert_one_crypto_pass(Input::QuorumCertificate(ordinary_qc.clone()));
    assert_one_crypto_pass(Input::TimeoutCertificate(timeout_certificate(
        set,
        2,
        ordinary_qc,
    )));
}

#[test]
fn preauthentication_token_is_exact_and_process_local() {
    let (config, core) = configured_core();
    let set = config.validator_set();
    let first = Input::Vote(signed_vote(
        set,
        1,
        1,
        BlockId::new([0x41; 32]),
        validator_id(1),
    ));
    let altered = Input::Vote(signed_vote(
        set,
        1,
        1,
        BlockId::new([0x42; 32]),
        validator_id(1),
    ));
    let token = core
        .preauthentication_token_v0(&first)
        .expect("token digest should be computable")
        .expect("vote must be a peer input");
    assert!(core
        .validate_preauthentication_token_v0(&first, &token)
        .is_ok());
    assert!(
        core.validate_preauthentication_token_v0(&altered, &token)
            .is_err(),
        "changing the signed input must invalidate the old token"
    );
    let public_clone = core.clone();
    assert!(
        public_clone
            .validate_preauthentication_token_v0(&first, &token)
            .is_err(),
        "a public Core clone must not accept another Core's token"
    );
    let transactional_clone = core.transactional_clone_v0();
    assert!(
        transactional_clone
            .validate_preauthentication_token_v0(&first, &token)
            .is_ok(),
        "the private transactional clone must preserve the admission affinity"
    );
}

#[test]
fn failed_preauthentication_does_not_authorize_a_later_retry() {
    let (config, mut core) = configured_core();
    let vote = Input::Vote(signed_vote(
        config.validator_set(),
        1,
        1,
        BlockId::new([0x51; 32]),
        validator_id(1),
    ));
    let verifier = RecordingSignatures::rejecting();
    assert!(core.step(vote.clone(), &verifier).is_err());
    let failed_calls = verifier.calls();
    verifier.accept.set(true);
    assert!(core.step(vote, &verifier).is_ok());
    assert!(
        verifier.calls() > failed_calls,
        "a failed admission must not reuse a cached positive verification"
    );
}

fn canonical_sign_intent_for_test(
    config: &CoreConfig,
    intent: &SignIntent,
) -> CanonicalSignIntentV0 {
    match intent {
        SignIntent::Vote {
            authorizing_safety_revision,
            view,
            height,
            block_id,
            ..
        } => CanonicalSignIntentV0::vote(
            config.validator_set(),
            config.local_validator(),
            *authorizing_safety_revision,
            *view,
            *height,
            *block_id,
        )
        .expect("fixture vote intent is canonical"),
        SignIntent::TimeoutVote {
            authorizing_safety_revision,
            view,
            high_qc,
            ..
        } => CanonicalSignIntentV0::timeout_vote(
            config.validator_set(),
            config.local_validator(),
            *authorizing_safety_revision,
            *view,
            *high_qc,
        )
        .expect("fixture timeout intent is canonical"),
    }
}

fn h1_state_sync_fixture() -> (
    CoreConfig,
    FinalityProofV0,
    SignedProposalV0,
    SignedProposalV0,
    SignedProposalV0,
) {
    let parameters = consensus_parameters();
    let set = validator_set_with_parameters(&parameters);
    let config = CoreConfig::new(
        validator_id(1),
        set.clone(),
        parameters,
        GENESIS_TIMESTAMP_MS,
        32,
        64,
    )
    .expect("valid h1 state-sync config");
    let h1 = proposal_with_parameters(&set, &parameters, genesis_qc(&set), 1, b"sync h1");
    let q1 = qc(&set, 1, 1, h1.block().id());
    let h2 = proposal_with_parameters(&set, &parameters, q1.clone(), 2, b"sync h2");
    let q2 = qc(&set, 2, 2, h2.block().id());
    let h3 = proposal_with_parameters(&set, &parameters, q2.clone(), 3, b"sync h3");
    let q3 = qc(&set, 3, 3, h3.block().id());
    let certified_h1 = CertifiedHeaderV0::from_signed_proposal(
        h1.clone(),
        q1,
        &set,
        None,
        &parameters,
        GENESIS_TIMESTAMP_MS,
    )
    .expect("valid certified h1");
    let certified_h2 = CertifiedHeaderV0::from_signed_proposal(
        h2.clone(),
        q2,
        &set,
        None,
        &parameters,
        h1.block().header().timestamp_ms(),
    )
    .expect("valid certified h2");
    let certified_h3 = CertifiedHeaderV0::from_signed_proposal(
        h3.clone(),
        q3,
        &set,
        None,
        &parameters,
        h2.block().header().timestamp_ms(),
    )
    .expect("valid certified h3");
    let proof = FinalityProofV0::new(
        certified_h1,
        certified_h2,
        certified_h3,
        &set,
        None,
        &parameters,
        GENESIS_TIMESTAMP_MS,
    )
    .expect("valid genesis-anchored h1 finality proof");
    (config, proof, h1, h2, h3)
}

#[derive(Debug, Clone, Copy)]
struct H1AnchorChainMutationV0 {
    proof_parent_timestamp_ms: u64,
    h1_timestamp_ms: u64,
    h1_state_root: StateRoot,
    h1_block_kind: BlockKind,
    h1_next_epoch_commitment_hash: Option<NextEpochCommitmentHash>,
}

impl Default for H1AnchorChainMutationV0 {
    fn default() -> Self {
        Self {
            proof_parent_timestamp_ms: GENESIS_TIMESTAMP_MS,
            h1_timestamp_ms: 100,
            h1_state_root: StateRoot::new([1; 32]),
            h1_block_kind: BlockKind::Regular,
            h1_next_epoch_commitment_hash: None,
        }
    }
}

fn h1_state_sync_fixture_with(
    parameters: ConsensusParametersV0,
    mutation: H1AnchorChainMutationV0,
) -> (
    CoreConfig,
    FinalityProofV0,
    SignedProposalV0,
    SignedProposalV0,
    SignedProposalV0,
) {
    let set = validator_set_with_parameters(&parameters);
    let config = CoreConfig::new(
        validator_id(1),
        set.clone(),
        parameters,
        GENESIS_TIMESTAMP_MS,
        32,
        64,
    )
    .expect("valid mutated h1 state-sync config");
    let genesis = genesis_qc(&set);
    let h1_parent_timestamp_ms = mutation.proof_parent_timestamp_ms;
    let h1_block = block_with_anchor_test_header_fields(
        &set,
        1,
        1,
        genesis.block_id(),
        b"sync h1 mutated",
        leader_for(&set, View::new(1)),
        mutation.h1_timestamp_ms,
        mutation.h1_state_root,
        mutation.h1_block_kind,
        mutation.h1_next_epoch_commitment_hash,
    );
    let h1 = signed_proposal_from_block(
        &set,
        &parameters,
        h1_block,
        QcReferenceV0::genesis_anchor(genesis),
        None,
        h1_parent_timestamp_ms,
    )
    .expect("valid mutated signed h1");
    let q1 = qc(&set, 1, 1, h1.block().id());
    let h2_block = block_with_timestamp(
        &set,
        2,
        2,
        q1.block_id(),
        b"sync h2 mutated",
        leader_for(&set, View::new(2)),
        mutation.h1_timestamp_ms.saturating_add(100),
    );
    let h2 = signed_proposal_from_block(
        &set,
        &parameters,
        h2_block,
        QcReferenceV0::ordinary(q1.clone()),
        None,
        mutation.h1_timestamp_ms,
    )
    .expect("valid mutated signed h2");
    let q2 = qc(&set, 2, 2, h2.block().id());
    let h3_block = block_with_timestamp(
        &set,
        3,
        3,
        q2.block_id(),
        b"sync h3 mutated",
        leader_for(&set, View::new(3)),
        mutation.h1_timestamp_ms.saturating_add(200),
    );
    let h3 = signed_proposal_from_block(
        &set,
        &parameters,
        h3_block,
        QcReferenceV0::ordinary(q2.clone()),
        None,
        mutation.h1_timestamp_ms.saturating_add(100),
    )
    .expect("valid mutated signed h3");
    let q3 = qc(&set, 3, 3, h3.block().id());
    let certified_h1 = CertifiedHeaderV0::from_signed_proposal(
        h1.clone(),
        q1,
        &set,
        None,
        &parameters,
        h1_parent_timestamp_ms,
    )
    .expect("valid mutated certified h1");
    let certified_h2 = CertifiedHeaderV0::from_signed_proposal(
        h2.clone(),
        q2,
        &set,
        None,
        &parameters,
        mutation.h1_timestamp_ms,
    )
    .expect("valid mutated certified h2");
    let certified_h3 = CertifiedHeaderV0::from_signed_proposal(
        h3.clone(),
        q3,
        &set,
        None,
        &parameters,
        mutation.h1_timestamp_ms.saturating_add(100),
    )
    .expect("valid mutated certified h3");
    let proof = FinalityProofV0::new(
        certified_h1,
        certified_h2,
        certified_h3,
        &set,
        None,
        &parameters,
        h1_parent_timestamp_ms,
    )
    .expect("valid mutated genesis-anchored h1 finality proof");
    (config, proof, h1, h2, h3)
}

fn h1_state_sync_proof_with_invalid_proposer_signature() -> (CoreConfig, FinalityProofV0) {
    let (config, proof, _h1, _h2, _h3) = h1_state_sync_fixture();
    let mut encoded = proof
        .try_cev0_bytes()
        .expect("encode the canonical h1 finality proof");
    let proposer_signature = proof.finalized_block().proposer_signature().as_bytes();
    let signature_offset = encoded
        .windows(proposer_signature.len())
        .position(|window| window == proposer_signature)
        .expect("the finalized proposer signature occurs in its canonical proof");
    encoded[signature_offset] ^= 1;
    let tampered = decode_finality_proof_v0_exact_with_trusted_genesis(
        &encoded,
        config.validator_set(),
        config.consensus_parameters(),
        config.trusted_genesis_timestamp_ms(),
    )
    .expect("exact decoding is deliberately cryptographically inert");
    assert_ne!(
        tampered.finalized_block().proposer_signature(),
        proof.finalized_block().proposer_signature(),
    );
    (config, tampered)
}

#[allow(clippy::too_many_arguments)]
fn anchored_state_from_test_parts(
    base: &SafetyState,
    current_view: View,
    high_qc: QcReferenceV0,
    locked_qc: QcReferenceV0,
    revision: u64,
    payload_terminal_facts: Vec<PayloadTerminalFact>,
) -> SafetyState {
    SafetyState::from_persisted_parts_v13(
        base.schema_version(),
        base.chain_id(),
        base.protocol_version(),
        base.epoch(),
        base.validator_set_id(),
        base.genesis_block_id(),
        base.authenticated_genesis_application_parent_v0().copied(),
        current_view,
        base.last_voted_view(),
        base.last_timeout_view(),
        high_qc,
        locked_qc,
        base.finalized(),
        revision,
        base.durable_observed_qcs().to_vec(),
        payload_terminal_facts,
        base.payload_validation_obligations().to_vec(),
        base.payload_validation_completions().to_vec(),
        base.pending_tc_high_qc_sync().cloned(),
        base.pending_standalone_qc_sync().cloned(),
        base.pending_sign().cloned(),
        base.last_finalization().cloned(),
        base.state_sync_anchor().cloned(),
        base.application_applied(),
        base.finalization_queue().to_vec(),
        base.pending_finalize(),
        base.safety_halt().cloned(),
    )
}

fn anchored_state_with_validation_parts_v0(
    base: &SafetyState,
    revision: u64,
    obligations: Vec<DurablePayloadValidationObligationV0>,
    completions: Vec<DurablePayloadValidationCompletionV0>,
    facts: Vec<PayloadTerminalFact>,
) -> SafetyState {
    SafetyState::from_persisted_parts_v13(
        base.schema_version(),
        base.chain_id(),
        base.protocol_version(),
        base.epoch(),
        base.validator_set_id(),
        base.genesis_block_id(),
        base.authenticated_genesis_application_parent_v0().copied(),
        base.current_view(),
        base.last_voted_view(),
        base.last_timeout_view(),
        base.high_qc().clone(),
        base.locked_qc().clone(),
        base.finalized(),
        revision,
        base.durable_observed_qcs().to_vec(),
        facts,
        obligations,
        completions,
        base.pending_tc_high_qc_sync().cloned(),
        base.pending_standalone_qc_sync().cloned(),
        base.pending_sign().cloned(),
        base.last_finalization().cloned(),
        base.state_sync_anchor().cloned(),
        base.application_applied(),
        base.finalization_queue().to_vec(),
        base.pending_finalize(),
        base.safety_halt().cloned(),
    )
}

#[derive(Debug)]
struct ExactFreshStateSyncReconcilerV0 {
    expected_state: SafetyState,
    expected_h1: BlockHeader,
    accept: bool,
    calls: usize,
}

impl StateSyncAnchorRecoveryReconcilerV0 for ExactFreshStateSyncReconcilerV0 {
    fn reconcile_state_sync_anchor_v0(
        &mut self,
        challenge: &StateSyncAnchorRecoveryChallengeV0,
    ) -> bool {
        self.calls += 1;
        self.accept
            && challenge.safety_state() == &self.expected_state
            && challenge.trusted_base_header() == &self.expected_h1
    }
}

#[derive(Debug)]
struct ExactAnchorSuccessorReconcilerV0 {
    expected_state: SafetyState,
    expected_phase: StateSyncAnchorSuccessorPhaseV0,
    expected_child: SignedProposalV0,
    expected_grandchild: SignedProposalV0,
    accept: bool,
    calls: usize,
}

impl StateSyncAnchorSuccessorRecoveryReconcilerV0 for ExactAnchorSuccessorReconcilerV0 {
    fn reconcile_state_sync_anchor_successors_v0(
        &mut self,
        challenge: &StateSyncAnchorSuccessorRecoveryChallengeV0,
    ) -> bool {
        self.calls += 1;
        self.accept
            && challenge.safety_state() == &self.expected_state
            && challenge.phase() == self.expected_phase
            && challenge.child() == &self.expected_child
            && challenge.grandchild() == &self.expected_grandchild
    }
}

#[derive(Debug)]
struct ExactAnchorOrdinaryReconcilerV0 {
    expected_state: SafetyState,
    expected_child: SignedProposalV0,
    expected_grandchild: SignedProposalV0,
    accept: bool,
    calls: usize,
}

impl StateSyncAnchorOrdinaryRecoveryReconcilerV0 for ExactAnchorOrdinaryReconcilerV0 {
    fn reconcile_state_sync_anchor_ordinary_v0(
        &mut self,
        challenge: &StateSyncAnchorOrdinaryRecoveryChallengeV0,
    ) -> bool {
        self.calls += 1;
        self.accept
            && challenge.safety_state() == &self.expected_state
            && challenge.child() == &self.expected_child
            && challenge.grandchild() == &self.expected_grandchild
    }
}

#[derive(Debug)]
struct ExactCheckpointedOrdinaryRehydrateReconcilerV0 {
    expected_state: SafetyState,
    expected_plan: AnchoredOrdinaryReplayArchivePlanV0,
    expected_entries: Vec<AnchoredOrdinarySignedReplayEntryV0>,
    accept: bool,
    calls: usize,
}

impl AnchoredOrdinaryRehydrateReconcilerV0 for ExactCheckpointedOrdinaryRehydrateReconcilerV0 {
    fn reconcile_checkpointed_ordinary_replay_v0(
        &mut self,
        challenge: &AnchoredOrdinaryRehydrateChallengeV0,
    ) -> bool {
        self.calls += 1;
        self.accept
            && challenge.safety_state_v0() == &self.expected_state
            && challenge.plan_v0() == self.expected_plan
            && challenge.entries_v0() == self.expected_entries
            && challenge.rehydrate_digest_v0() != [0; 32]
    }
}

const SAFETY_STATE_RECORD_TEST_PROFILE_REF: [u8; 32] = [0x71; 32];

fn safety_state_record_test_limits() -> SafetyStateRecordLimitsV0 {
    SafetyStateRecordLimitsV0::new(64 * 1024 * 1024, 16 * 1024 * 1024)
        .expect("valid safety-state record test limits")
}

fn roundtrip_safety_state_record(config: &CoreConfig, state: &SafetyState) -> SafetyState {
    let context = SafetyStateRecordContextV0::new(
        config,
        SAFETY_STATE_RECORD_TEST_PROFILE_REF,
        safety_state_record_test_limits(),
    )
    .expect("capacity-compatible safety-state record context");
    let encoded = encode_safety_state_record_v0(state, &context)
        .expect("the Core-produced SafetyState has an exact durable encoding");
    let decoded = decode_safety_state_record_v0_exact(&encoded, &context)
        .expect("the exact durable SafetyState record decodes");
    assert_eq!(decoded.state(), state);
    assert_eq!(
        encode_safety_state_record_v0(decoded.state(), &context)
            .expect("the decoded SafetyState re-encodes"),
        encoded,
        "the durable record must be byte-canonical"
    );
    decoded.state().clone()
}

fn finalization_apply_authority_for_test(
    core: &Core,
) -> CoreIssuedApplicationFinalizationApplyAuthorityV0 {
    core.issue_application_finalization_apply_authority_v0()
        .expect("one application finalization apply authority per live Core")
}

fn finalization_readback_for_test(
    core: &Core,
    authority: &CoreIssuedApplicationFinalizationApplyAuthorityV0,
    permit: &CoreIssuedApplicationFinalizationPermitV0,
) -> ApplicationFinalizationApplyReadbackV0 {
    let target = permit.finalization().proof().finalized_block().header();
    let source = core
        .safety_state()
        .payload_validation_completions()
        .iter()
        .find(|completion| {
            completion.result().artifact_ref().is_some_and(|artifact| {
                artifact.overlay() == permit.finalization().target_overlay_ref()
            })
        })
        .expect("the finalization target has one durable Valid source");
    let source_artifact_checksum = source
        .result()
        .artifact_ref()
        .expect("the finalization source is Valid")
        .source_artifact_checksum();
    authority
        .application_store_apply_readback_v0(
            permit,
            source.route(),
            source.id(),
            target.height().get(),
            [0x31; 32],
            [0x32; 32],
            [0x33; 32],
            source_artifact_checksum,
            [0x35; 32],
            [0x36; 32],
            [0x37; 32],
        )
        .expect("the simulated exact ApplicationStore readback binds the permit")
}

fn finalization_receipt_for_test(
    core: &Core,
    authority: &CoreIssuedApplicationFinalizationApplyAuthorityV0,
) -> ApplicationFinalizationReceiptV0 {
    let permit = core
        .issue_application_finalization_permit_v0()
        .expect("one permit for the exact durable queue front");
    let readback = finalization_readback_for_test(core, authority, &permit);
    authority
        .receipt_after_application_store_apply_v0(permit, readback)
        .expect("the permit and installed application authority share one live Core")
}

fn pending_finalization_receipt_for_test() -> (Core, ApplicationFinalizationReceiptV0) {
    let (_config, core, _validation, _result) =
        finalization_gated_validation(b"live queue-front guard");
    let authority = finalization_apply_authority_for_test(&core);
    let receipt = finalization_receipt_for_test(&core, &authority);
    (core, receipt)
}

fn finalization_recovery_transition_for_test(
    consumed: &DurableFinalizationV0,
    readback: &ApplicationFinalizationApplyReadbackV0,
    action: NativeFinalizationAppliedPostAckActionV0,
    revision: u64,
) -> NativeFinalizationAppliedRecoveryTransitionV0 {
    NativeFinalizationAppliedRecoveryTransitionV0::from_persisted_parts(
        readback.ordinal(),
        consumed.proof_id(),
        consumed.authenticated_parent().block_id(),
        consumed.proof().finalized_block().header().id(),
        consumed.target_overlay_ref().overlay_checksum(),
        readback.source_route(),
        readback.source_validation_id(),
        readback.application_host_config_ref(),
        readback.finalization_checksum(),
        readback.source_artifact_checksum(),
        readback.accepted_source_checksum(),
        readback.applied_job_row_checksum(),
        readback.prior_head_checksum(),
        readback.new_head_checksum(),
        readback.receipt_row_checksum(),
        action,
        revision,
    )
}

struct ExactNativeFinalizationRecoveryReconcilerV0 {
    expected_revision: u64,
    expected_transition: NativeFinalizationAppliedRecoveryTransitionV0,
    expected_readback: ApplicationFinalizationApplyReadbackV0,
    accept: bool,
    calls: usize,
}

impl NativeFinalizationAppliedRecoveryReconcilerV0 for ExactNativeFinalizationRecoveryReconcilerV0 {
    fn reconcile_native_finalization_applied_v0(
        &mut self,
        challenge: &NativeFinalizationAppliedRecoveryChallengeV0,
        transition: &NativeFinalizationAppliedRecoveryTransitionV0,
        application_readback: &ApplicationFinalizationApplyReadbackV0,
    ) -> bool {
        self.calls += 1;
        self.accept
            && challenge.safety_head_revision() == self.expected_revision
            && transition == &self.expected_transition
            && application_readback == &self.expected_readback
    }
}

struct ExactNativeValidCompletionRecoveryReconcilerV0 {
    expected_state: SafetyState,
    expected_record_checksum: [u8; 32],
    expected_action: NativeValidPostAckActionV0,
    accept: bool,
    calls: usize,
}

impl NativeValidCompletionRecoveryReconcilerV0 for ExactNativeValidCompletionRecoveryReconcilerV0 {
    fn reconcile_native_valid_completion_v0(
        &mut self,
        challenge: &NativeValidCompletionRecoveryChallengeV0,
        safety_state_record_checksum: [u8; 32],
        post_ack_action: NativeValidPostAckActionV0,
    ) -> bool {
        self.calls += 1;
        self.accept
            && challenge.safety_state() == &self.expected_state
            && safety_state_record_checksum == self.expected_record_checksum
            && post_ack_action == self.expected_action
    }
}

fn apply_finalization_for_test(
    core: &mut Core,
    authority: &CoreIssuedApplicationFinalizationApplyAuthorityV0,
) -> Result<Vec<Effect>> {
    let receipt = finalization_receipt_for_test(core, authority);
    core.step_application_finalization_receipt_v0(receipt, &RootSignatures)
        .map_err(|rejection| rejection.into_parts().0)
}

fn assert_safety_state_record_roundtrip_and_validate(config: &CoreConfig, state: &SafetyState) {
    let decoded = roundtrip_safety_state_record(config, state);
    Core::validate_persisted_state_v0(config, &decoded, &RootSignatures)
        .expect("the decoded record remains a semantically valid inert SafetyState");
}

fn authenticated_genesis_application_fixture_v0() -> (CoreConfig, SafetyState) {
    let parameters = consensus_parameters();
    let set = validator_set_with_parameters(&parameters);
    let parent = AuthenticatedGenesisApplicationParentV0::new(
        BlockId::new(*set.genesis_hash().as_bytes()),
        GENESIS_TIMESTAMP_MS,
        0,
        StateRoot::new([0x31; 32]),
        [0x41; 32],
        [0x51; 32],
    )
    .expect("shape-valid operator-pinned genesis application parent");
    let config = CoreConfig::new_with_authenticated_genesis_application_parent_v0(
        validator_id(1),
        set.clone(),
        parameters,
        GENESIS_TIMESTAMP_MS,
        parent,
        32,
        64,
    )
    .expect("shadow-only authenticated-genesis config");
    let state = SafetyState::from_authenticated_genesis_application_for_test_v0(
        &set,
        genesis_qc(&set),
        GENESIS_TIMESTAMP_MS,
        parent,
    )
    .expect("construct inert schema-v12 record fixture");
    (config, state)
}

#[test]
fn authenticated_genesis_application_strict_prepare_binds_genesis_qc_v0() {
    let (config, _) = authenticated_genesis_application_fixture_v0();
    let parent = config
        .authenticated_genesis_application_parent_v0()
        .copied()
        .expect("fixture has an authenticated application parent");
    let commitment = parent
        .genesis_application_commitment_v0()
        .expect("convert the configured parent to the independent commitment");
    assert_eq!(
        parent.binding_ref_v0(),
        commitment.binding_ref_v0(),
        "the additive commitment retains the legacy parent binding preimage"
    );

    let genesis = genesis_qc(config.validator_set());
    let raw_bytes = genesis.try_cev0_bytes().expect("raw GenesisQC bytes");
    let raw_id = genesis.id();
    let binding = GenesisQcApplicationBindingV0::new(genesis.clone(), commitment)
        .expect("same-hash GenesisQC/application ceremony binding");
    let prepared = Core::prepare_authenticated_genesis_application_bootstrap_with_genesis_application_commitment_v0(
        config.clone(),
        binding,
        SAFETY_STATE_RECORD_TEST_PROFILE_REF,
        safety_state_record_test_limits(),
        &RootSignatures,
    )
    .expect("strict binding prepares the exact inert revision-zero facts");
    assert_eq!(
        prepared.authenticated_genesis_application_parent_v0(),
        parent
    );
    assert_eq!(
        genesis.try_cev0_bytes().expect("raw bytes remain stable"),
        raw_bytes
    );
    assert_eq!(genesis.id(), raw_id);
    assert!(
        !config.consensus_parameters().production_activation(),
        "strict commissioning remains outside production activation"
    );
}

#[test]
fn authenticated_genesis_application_strict_prepare_rejects_foreign_commitment_v0() {
    let (config, _) = authenticated_genesis_application_fixture_v0();
    let parent = config
        .authenticated_genesis_application_parent_v0()
        .copied()
        .expect("fixture has an authenticated application parent");
    let foreign_parent = AuthenticatedGenesisApplicationParentV0::new(
        parent.genesis_block_id(),
        parent.timestamp_ms(),
        parent.state_version(),
        parent.state_root(),
        [0xD1; 32],
        [0xE1; 32],
    )
    .expect("shape-valid foreign application provenance");
    let foreign_commitment = foreign_parent
        .genesis_application_commitment_v0()
        .expect("convert the foreign parent");
    let binding = GenesisQcV0::new(
        config.validator_set().genesis_hash(),
        config.validator_set().chain_id(),
        config.validator_set(),
    )
    .expect("trusted GenesisQC")
    .bind_application_commitment_v0(foreign_commitment)
    .expect("foreign commitment still names the same genesis hash");

    assert!(matches!(
        Core::prepare_authenticated_genesis_application_bootstrap_with_genesis_application_commitment_v0(
            config,
            binding,
            SAFETY_STATE_RECORD_TEST_PROFILE_REF,
            safety_state_record_test_limits(),
            &RootSignatures,
        ),
        Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
            "GenesisQC application commitment differs from the configured application parent"
        ))
    ));
}

fn authenticated_genesis_h1_offline_fixture_v0(
    payload: &[u8],
) -> (
    CoreConfig,
    SignedProposalV0,
    AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0,
) {
    let (config, _) = authenticated_genesis_application_fixture_v0();
    let genesis = genesis_qc(config.validator_set());
    let h1 = proposal_with_parameters(
        config.validator_set(),
        config.consensus_parameters(),
        genesis.clone(),
        1,
        payload,
    );
    let prepared = Core::prepare_authenticated_genesis_application_bootstrap_v0(
        config.clone(),
        genesis,
        SAFETY_STATE_RECORD_TEST_PROFILE_REF,
        safety_state_record_test_limits(),
        &RootSignatures,
    )
    .expect("prepare exact authenticated-genesis revision-zero facts");
    struct TestRegistrarV0;

    impl AuthenticatedGenesisApplicationH1OfflineApplicationRegistrarV0 for TestRegistrarV0 {
        type Output = AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0;
        type Error = std::convert::Infallible;

        fn register_authenticated_genesis_application_h1_offline_v0(
            self,
            owner: AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0,
        ) -> std::result::Result<Self::Output, Self::Error> {
            Ok(owner)
        }
    }

    let bundle = Core::begin_authenticated_genesis_application_h1_offline_validation_v0(
        config.clone(),
        prepared,
        &RootSignatures,
    )
    .expect("prepare the bounded offline h1 activation bundle");
    let owner = bundle
        .activate_application_v0(TestRegistrarV0)
        .unwrap_or_else(|never| match never {});
    (config, h1, owner)
}

fn exact_h1_finality_proof_v0(config: &CoreConfig, h1: &SignedProposalV0) -> FinalityProofV0 {
    let set = config.validator_set();
    let parameters = config.consensus_parameters();
    let q1 = qc(set, 1, 1, h1.block().id());
    let h2 = proposal_with_parameters(set, parameters, q1.clone(), 2, b"promotion h2");
    let q2 = qc(set, 2, 2, h2.block().id());
    let h3 = proposal_with_parameters(set, parameters, q2.clone(), 3, b"promotion h3");
    let q3 = qc(set, 3, 3, h3.block().id());
    let certified_h1 = CertifiedHeaderV0::from_signed_proposal(
        h1.clone(),
        q1,
        set,
        None,
        parameters,
        config.trusted_genesis_timestamp_ms(),
    )
    .expect("certify the exact completed h1");
    let certified_h2 = CertifiedHeaderV0::from_signed_proposal(
        h2.clone(),
        q2,
        set,
        None,
        parameters,
        h1.block().header().timestamp_ms(),
    )
    .expect("certify the direct h1 child");
    let certified_h3 = CertifiedHeaderV0::from_signed_proposal(
        h3,
        q3,
        set,
        None,
        parameters,
        h2.block().header().timestamp_ms(),
    )
    .expect("certify the h1 grandchild");
    FinalityProofV0::new(
        certified_h1,
        certified_h2,
        certified_h3,
        set,
        None,
        parameters,
        config.trusted_genesis_timestamp_ms(),
    )
    .expect("construct the exact complete h1 finality proof")
}

fn completed_authenticated_genesis_h1_owner_v0(
    payload: &[u8],
) -> (
    CoreConfig,
    SignedProposalV0,
    AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0,
) {
    let (config, h1, mut owner) = authenticated_genesis_h1_offline_fixture_v0(payload);
    let obligation = owner
        .submit_exact_h1_synced_proposal_v0(h1.clone(), &RootSignatures)
        .expect("admit exact promotion h1");
    let _safety_binding = owner
        .issue_safety_persistence_binding_v0()
        .expect("bind the completed promotion owner to its exact Safety namespace");
    let request = owner
        .acknowledge_obligation_persisted_v0(&obligation, obligation.barrier_v0(), &RootSignatures)
        .expect("release exact promotion validation request");
    let claimed = request
        .try_claim_v0()
        .unwrap_or_else(|_| panic!("fresh promotion request must be claimable"));
    let (_route, validation_id, block, _parent, permit) = claimed.into_parts();
    let sealed = owner.seal_after_application_store_commit_v0(
        permit,
        valid_commitments_for_config(&config, &block),
        artifact_ref_for_ids(block.id(), block.header().parent_id()),
    );
    let completion = owner
        .accept_application_sealed_valid_v0(&sealed, &RootSignatures)
        .expect("accept exact promotion h1 Valid result");
    let [durable_completion] = completion
        .persistence_v0()
        .state()
        .payload_validation_completions()
    else {
        panic!("promotion rev2 has one exact completion")
    };
    let delivery_facts = ApplicationNativeValidDeliveryFactsV0::new(
        PayloadValidationRouteV0::Synced,
        validation_id,
        [0x91; 32],
        [0x92; 32],
        [0x93; 32],
        native_valid_result_checksum_v0(durable_completion.result())
            .expect("promotion completion is canonically Valid"),
        [0x94; 32],
        [0x95; 32],
        1,
        [0x96; 32],
        [0x97; 32],
        NativeValidPostAckActionV0::None,
        2,
    )
    .expect("exact promotion delivery facts");
    let sealed_delivery = owner
        .seal_authenticated_genesis_h1_native_valid_transition_v0(completion, delivery_facts)
        .expect("seal exact promotion delivery");
    let _completed = owner
        .acknowledge_completion_persisted_v0(
            &sealed_delivery,
            sealed_delivery.completion_persistence_v0().barrier_v0(),
            &RootSignatures,
        )
        .expect("close exact promotion h1 rev2");
    assert_eq!(
        owner
            .phase_v0()
            .expect("classify completed promotion owner"),
        AuthenticatedGenesisApplicationH1OfflinePhaseV0::CompletedRev2
    );
    (config, h1, owner)
}

fn authenticated_genesis_empty_h1_proposal_v0(config: &CoreConfig) -> SignedProposalV0 {
    let payload = ApplicationPayloadV0::new(Vec::new()).expect("empty application payload");
    let receipts = ExecutionReceiptsV0::new(&payload, Vec::new()).expect("empty receipts");
    let body = BlockBodyV0::new(payload, Vec::new()).expect("empty regular body");
    let proposer = leader_for(config.validator_set(), View::new(1));
    let header = BlockHeader::new(
        config.validator_set().genesis_hash(),
        config.validator_set().chain_id(),
        config.validator_set().protocol_version(),
        Epoch::new(0),
        View::new(1),
        Height::new(1),
        BlockKind::Regular,
        config.genesis_block_id(),
        proposer,
        config.validator_set().id(),
        config.consensus_parameters().hash(),
        body.payload_root().expect("empty payload root"),
        StateRoot::new([1; 32]),
        receipts.receipts_root().expect("empty receipts root"),
        body.evidence_root().expect("empty evidence root"),
        100,
        None,
    )
    .expect("canonical empty h1 header");
    let block = Block::new(
        header,
        body.application_payload()
            .try_cev0_bytes()
            .expect("encode empty payload"),
        Vec::new(),
    )
    .expect("canonical empty h1 block");
    let justify = QcReferenceV0::genesis_anchor(genesis_qc(config.validator_set()));
    let root = ProposalWitnessV0::signing_root_for(block.header(), &justify, None, None)
        .expect("empty h1 signing root");
    let witness = ProposalWitnessV0::new(
        block.header(),
        justify,
        None,
        None,
        signature(root),
        config.validator_set(),
        None,
        config.consensus_parameters(),
        config.trusted_genesis_timestamp_ms(),
    )
    .expect("canonical empty h1 witness");
    SignedProposalV0::new(
        block,
        witness,
        config.validator_set(),
        None,
        config.consensus_parameters(),
        config.trusted_genesis_timestamp_ms(),
    )
    .expect("canonical empty h1 proposal")
}

struct AuthenticatedGenesisH1TakeoverTestRegistrarV0;

impl AuthenticatedGenesisApplicationH1OfflineApplicationRegistrarV0
    for AuthenticatedGenesisH1TakeoverTestRegistrarV0
{
    type Output = AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0;
    type Error = std::convert::Infallible;

    fn register_authenticated_genesis_application_h1_offline_v0(
        self,
        owner: AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0,
    ) -> std::result::Result<Self::Output, Self::Error> {
        Ok(owner)
    }
}

fn authenticated_genesis_h1_takeover_fixture_v0() -> (
    CoreConfig,
    PreparedAuthenticatedGenesisApplicationBootstrapV0,
    SignedProposalV0,
    SafetyState,
) {
    let (config, _) = authenticated_genesis_application_fixture_v0();
    let prepared_live = Core::prepare_authenticated_genesis_application_bootstrap_v0(
        config.clone(),
        genesis_qc(config.validator_set()),
        SAFETY_STATE_RECORD_TEST_PROFILE_REF,
        safety_state_record_test_limits(),
        &RootSignatures,
    )
    .expect("prepare live exact empty-h1 owner");
    let prepared_takeover = Core::prepare_authenticated_genesis_application_bootstrap_v0(
        config.clone(),
        genesis_qc(config.validator_set()),
        SAFETY_STATE_RECORD_TEST_PROFILE_REF,
        safety_state_record_test_limits(),
        &RootSignatures,
    )
    .expect("prepare independent takeover tag-5 facts");
    let bundle = Core::begin_authenticated_genesis_application_h1_offline_validation_v0(
        config.clone(),
        prepared_live,
        &RootSignatures,
    )
    .expect("begin live exact empty-h1 owner");
    let mut owner = bundle
        .activate_application_v0(AuthenticatedGenesisH1TakeoverTestRegistrarV0)
        .unwrap_or_else(|never| match never {});
    let proposal = authenticated_genesis_empty_h1_proposal_v0(&config);
    let persistence = owner
        .submit_exact_h1_synced_proposal_v0(proposal.clone(), &RootSignatures)
        .expect("derive the durable empty-h1 revision-one obligation");
    (
        config,
        prepared_takeover,
        proposal,
        persistence.persistence_v0().state().clone(),
    )
}

fn authenticated_genesis_h1_takeover_safety_facts_v0(
    challenge: &AuthenticatedGenesisApplicationH1ObligationTakeoverChallengeV0,
) -> AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyHeadFactsV0 {
    AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyHeadFactsV0::from_authenticated_store_comparison_v0(
        [0x01; 32],
        SAFETY_STATE_RECORD_TEST_PROFILE_REF,
        challenge.safety_state_record_config_ref_v0(),
        [0x03; 32],
        [0x04; 32],
        [0x05; 32],
        [0x06; 32],
        [0x07; 32],
        [0x08; 32],
        [0x09; 32],
        [0x0A; 32],
        challenge.barrier_v0(),
        challenge.validation_id_v0(),
        challenge.authenticated_parent_binding_ref_v0(),
    )
    .expect("shape-valid exact takeover Safety comparison facts")
}

struct AuthenticatedGenesisH1TakeoverTestReconcilerV0 {
    expected_revision_one: SafetyState,
    expected_proposal: SignedProposalV0,
    accept: bool,
    calls: usize,
}

impl AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyReconcilerV0
    for AuthenticatedGenesisH1TakeoverTestReconcilerV0
{
    fn reconcile_authenticated_genesis_application_h1_obligation_takeover_v0(
        &mut self,
        challenge: &AuthenticatedGenesisApplicationH1ObligationTakeoverChallengeV0,
        _safety_head_facts: &AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyHeadFactsV0,
    ) -> bool {
        self.calls += 1;
        self.accept
            && challenge.revision_zero_state_v0().revision() == 0
            && challenge.revision_one_state_v0() == &self.expected_revision_one
            && challenge.proposal_v0() == &self.expected_proposal
    }
}

// Core cannot authenticate a foreign crate's live SQLite owner. This test-only
// implementation models the explicitly trusted linked-host rebind boundary;
// production callers must use SafetyStore's consuming rev1 capability bridge.
struct AuthenticatedGenesisH1TakeoverLinkedHostRebindTestV0;

impl AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyRebindRegistrarV0
    for AuthenticatedGenesisH1TakeoverLinkedHostRebindTestV0
{
    type Error = CoreError;

    fn rebind_authenticated_genesis_application_h1_obligation_takeover_v0(
        self,
        safety_head_facts: &AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyHeadFactsV0,
        persistence: &AuthenticatedGenesisApplicationH1ObligationPersistenceV0,
        binding: AuthenticatedGenesisApplicationH1OfflineSafetyPersistenceBindingV0,
    ) -> std::result::Result<(), Self::Error> {
        if safety_head_facts.barrier_v0() != persistence.barrier_v0()
            || safety_head_facts.validation_id_v0() != persistence.validation_id_v0()
            || !binding.accepts_persistence_v0(persistence.persistence_v0())
        {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "test linked-host rebind rejected the replay owner",
            ));
        }
        Ok(())
    }
}

#[test]
fn authenticated_genesis_h1_obligation_takeover_replays_exact_rev1_before_safety_attested_ack_v0() {
    let (config, prepared, proposal, revision_one) = authenticated_genesis_h1_takeover_fixture_v0();
    let session = Core::begin_authenticated_genesis_application_h1_obligation_takeover_v0(
        config.clone(),
        prepared,
        revision_one.clone(),
        &RootSignatures,
    )
    .expect("real narrow replay exactly reproduces the durable revision-one obligation");
    let challenge = session.challenge_v0();
    let [obligation] = revision_one.payload_validation_obligations() else {
        panic!("fixture has one durable obligation")
    };
    let validation_id = obligation.id();
    let parent_binding_ref = obligation
        .parent_binding_ref_v0()
        .expect("durable obligation binds its authenticated parent");
    assert_eq!(challenge.revision_zero_state_v0().revision(), 0);
    assert_eq!(challenge.revision_one_state_v0(), &revision_one);
    assert_eq!(challenge.proposal_v0(), &proposal);
    assert_eq!(challenge.barrier_v0(), BarrierId::new(1));
    assert_eq!(challenge.validation_id_v0(), validation_id);
    assert_eq!(
        challenge.authenticated_parent_binding_ref_v0(),
        parent_binding_ref
    );

    let safety_facts = authenticated_genesis_h1_takeover_safety_facts_v0(challenge);
    let expected_safety_facts = safety_facts.clone();
    let mut reconciler = AuthenticatedGenesisH1TakeoverTestReconcilerV0 {
        expected_revision_one: revision_one,
        expected_proposal: proposal.clone(),
        accept: true,
        calls: 0,
    };
    let attestation = challenge
        .attest_authenticated_safety_head_v0(safety_facts, &mut reconciler)
        .expect("trusted live Safety join attests the exact pending rev1 head");
    assert_eq!(reconciler.calls, 1);
    let activation = session
        .activate_after_authenticated_safety_v0(attestation)
        .expect("the session consumes only its own Safety attestation");
    assert_eq!(activation.safety_head_facts_v0(), &expected_safety_facts);

    let rebound = activation
        .rebind_live_safety_v0(AuthenticatedGenesisH1TakeoverLinkedHostRebindTestV0)
        .expect("the linked-host TCB installs the replay binding before ack");
    let (bundle, request) = rebound
        .acknowledge_and_release_validation_request_v0(&RootSignatures)
        .expect("real StorageAck releases the sole live Core request after attestation");
    assert_eq!(request.route_v0(), PayloadValidationRouteV0::Synced);
    assert_eq!(request.validation_id_v0(), validation_id);
    assert_eq!(request.block_v0(), proposal.block());
    assert_eq!(
        request
            .parent_binding_ref_v0()
            .expect("released request retains exact parent provenance"),
        parent_binding_ref
    );
    let owner = bundle
        .activate_application_v0(AuthenticatedGenesisH1TakeoverTestRegistrarV0)
        .unwrap_or_else(|never| match never {});
    assert_eq!(
        owner.phase_v0().expect("classify the replayed live owner"),
        AuthenticatedGenesisApplicationH1OfflinePhaseV0::ValidationRequestReleasedRev1
    );
    assert!(
        owner.accepts_validation_request_v0(&request),
        "the application owner authenticates its exact request before App reservation"
    );
}

#[test]
fn authenticated_genesis_h1_obligation_takeover_rejects_nonempty_body_and_foreign_provenance_v0() {
    let (config, original_prepared, _proposal, _revision_one) =
        authenticated_genesis_h1_takeover_fixture_v0();
    let (_same_config, nonempty_h1, mut nonempty_owner) =
        authenticated_genesis_h1_offline_fixture_v0(b"nonempty takeover payload");
    let nonempty = nonempty_owner
        .submit_exact_h1_synced_proposal_v0(nonempty_h1, &RootSignatures)
        .expect("the general live h1 owner admits this canonical nonempty body");
    assert!(matches!(
        Core::begin_authenticated_genesis_application_h1_obligation_takeover_v0(
            config.clone(),
            original_prepared,
            nonempty.persistence_v0().state().clone(),
            &RootSignatures,
        ),
        Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
            "takeover supports only the canonical empty h1 obligation"
        ))
    ));

    let original_parent = config
        .authenticated_genesis_application_parent_v0()
        .copied()
        .expect("fixture has an authenticated application parent");
    let foreign_parent = AuthenticatedGenesisApplicationParentV0::new(
        original_parent.genesis_block_id(),
        original_parent.timestamp_ms(),
        original_parent.state_version(),
        original_parent.state_root(),
        [0xD1; 32],
        [0xE1; 32],
    )
    .expect("same-root foreign application provenance");
    let foreign_config = CoreConfig::new_with_authenticated_genesis_application_parent_v0(
        config.local_validator(),
        config.validator_set().clone(),
        *config.consensus_parameters(),
        config.trusted_genesis_timestamp_ms(),
        foreign_parent,
        config.max_blocks(),
        config.max_observed_messages(),
    )
    .expect("shape-valid same-root foreign provenance config");
    let foreign_prepared_live = Core::prepare_authenticated_genesis_application_bootstrap_v0(
        foreign_config.clone(),
        genesis_qc(foreign_config.validator_set()),
        SAFETY_STATE_RECORD_TEST_PROFILE_REF,
        safety_state_record_test_limits(),
        &RootSignatures,
    )
    .expect("prepare foreign live owner");
    let foreign_bundle = Core::begin_authenticated_genesis_application_h1_offline_validation_v0(
        foreign_config.clone(),
        foreign_prepared_live,
        &RootSignatures,
    )
    .expect("begin foreign live owner");
    let mut foreign_owner = foreign_bundle
        .activate_application_v0(AuthenticatedGenesisH1TakeoverTestRegistrarV0)
        .unwrap_or_else(|never| match never {});
    let foreign_h1 = authenticated_genesis_empty_h1_proposal_v0(&foreign_config);
    let foreign_revision_one = foreign_owner
        .submit_exact_h1_synced_proposal_v0(foreign_h1, &RootSignatures)
        .expect("derive same-root foreign-provenance rev1")
        .persistence_v0()
        .state()
        .clone();
    let original_prepared = Core::prepare_authenticated_genesis_application_bootstrap_v0(
        config.clone(),
        genesis_qc(config.validator_set()),
        SAFETY_STATE_RECORD_TEST_PROFILE_REF,
        safety_state_record_test_limits(),
        &RootSignatures,
    )
    .expect("prepare original provenance takeover facts");
    assert!(
        Core::begin_authenticated_genesis_application_h1_obligation_takeover_v0(
            config,
            original_prepared,
            foreign_revision_one,
            &RootSignatures,
        )
        .is_err()
    );
}

#[test]
fn authenticated_genesis_h1_obligation_takeover_rejects_same_header_body_substitution_v0() {
    let (config, prepared, proposal, mut revision_one) =
        authenticated_genesis_h1_takeover_fixture_v0();
    let substituted_payload =
        ApplicationPayloadV0::new(vec![b"takeover substituted body".to_vec()])
            .expect("canonical substituted payload")
            .try_cev0_bytes()
            .expect("encode substituted payload");
    let substituted_block = Block::new(
        proposal.block().header().clone(),
        substituted_payload,
        proposal.block().evidence_objects().to_vec(),
    )
    .expect("transport block accepts a same-header body carrier");
    let substituted_proposal = SignedProposalV0::new(
        substituted_block,
        proposal.witness().clone(),
        config.validator_set(),
        None,
        config.consensus_parameters(),
        config.trusted_genesis_timestamp_ms(),
    )
    .expect("unchanged signed header and witness remain structurally authenticated");
    let [obligation] = revision_one.payload_validation_obligations() else {
        panic!("fixture has one durable obligation")
    };
    let substituted_obligation = DurablePayloadValidationObligationV0::new(
        obligation.route(),
        obligation.id(),
        substituted_proposal,
        obligation.parent().clone(),
        obligation.first_recorded_revision(),
    );
    revision_one.set_payload_validation_obligations(vec![substituted_obligation]);

    assert!(
        Core::begin_authenticated_genesis_application_h1_obligation_takeover_v0(
            config,
            prepared,
            revision_one,
            &RootSignatures,
        )
        .is_err()
    );
}

#[test]
fn authenticated_genesis_h1_obligation_takeover_rejects_phase_and_attestation_splice_v0() {
    let (config, prepared_a, proposal, revision_one) =
        authenticated_genesis_h1_takeover_fixture_v0();
    let wrong_phase_prepared = Core::prepare_authenticated_genesis_application_bootstrap_v0(
        config.clone(),
        genesis_qc(config.validator_set()),
        SAFETY_STATE_RECORD_TEST_PROFILE_REF,
        safety_state_record_test_limits(),
        &RootSignatures,
    )
    .expect("prepare wrong-phase challenge");
    assert!(
        Core::begin_authenticated_genesis_application_h1_obligation_takeover_v0(
            config.clone(),
            wrong_phase_prepared,
            SafetyState::from_authenticated_genesis_application_for_test_v0(
                config.validator_set(),
                genesis_qc(config.validator_set()),
                config.trusted_genesis_timestamp_ms(),
                config
                    .authenticated_genesis_application_parent_v0()
                    .copied()
                    .expect("fixture parent"),
            )
            .expect("shape-valid revision-zero state"),
            &RootSignatures,
        )
        .is_err()
    );

    let prepared_b = Core::prepare_authenticated_genesis_application_bootstrap_v0(
        config.clone(),
        genesis_qc(config.validator_set()),
        SAFETY_STATE_RECORD_TEST_PROFILE_REF,
        safety_state_record_test_limits(),
        &RootSignatures,
    )
    .expect("prepare second takeover session");
    let session_a = Core::begin_authenticated_genesis_application_h1_obligation_takeover_v0(
        config.clone(),
        prepared_a,
        revision_one.clone(),
        &RootSignatures,
    )
    .expect("begin takeover session A");
    let session_b = Core::begin_authenticated_genesis_application_h1_obligation_takeover_v0(
        config,
        prepared_b,
        revision_one.clone(),
        &RootSignatures,
    )
    .expect("begin takeover session B");
    assert!(!session_a
        .challenge_v0()
        .same_takeover_instance_v0(session_b.challenge_v0()));

    let wrong_parent_facts =
        AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyHeadFactsV0::from_authenticated_store_comparison_v0(
            [1; 32], [2; 32], session_a.challenge_v0().safety_state_record_config_ref_v0(),
            [3; 32], [4; 32], [5; 32], [6; 32], [7; 32], [8; 32], [9; 32], [10; 32],
            session_a.challenge_v0().barrier_v0(),
            session_a.challenge_v0().validation_id_v0(),
            [0xFA; 32],
        )
        .expect("shape-valid but foreign parent facts");
    let mut reconciler = AuthenticatedGenesisH1TakeoverTestReconcilerV0 {
        expected_revision_one: revision_one.clone(),
        expected_proposal: proposal.clone(),
        accept: true,
        calls: 0,
    };
    assert!(session_a
        .challenge_v0()
        .attest_authenticated_safety_head_v0(wrong_parent_facts, &mut reconciler)
        .is_err());
    assert_eq!(
        reconciler.calls, 0,
        "Core rejects coordinate splice before TCB join"
    );

    reconciler.accept = false;
    let rejected_safety_facts =
        authenticated_genesis_h1_takeover_safety_facts_v0(session_a.challenge_v0());
    assert!(session_a
        .challenge_v0()
        .attest_authenticated_safety_head_v0(rejected_safety_facts, &mut reconciler)
        .is_err());
    assert_eq!(
        reconciler.calls, 1,
        "the trusted join may still veto exact coordinates"
    );

    reconciler.accept = true;
    let safety_facts = authenticated_genesis_h1_takeover_safety_facts_v0(session_a.challenge_v0());
    let attestation = session_a
        .challenge_v0()
        .attest_authenticated_safety_head_v0(safety_facts, &mut reconciler)
        .expect("session A mints its own exact attestation");
    assert!(matches!(
        session_b.activate_after_authenticated_safety_v0(attestation),
        Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
            "takeover Safety attestation belongs to another session"
        ))
    ));
}

#[test]
fn authenticated_genesis_h1_context_facts_are_exact_inert_core_config_material_v0() {
    let (config, _h1, owner) =
        authenticated_genesis_h1_offline_fixture_v0(b"authenticated genesis h1 context facts");
    let facts = owner
        .h1_context_facts_v0()
        .expect("commissioned rev0 owner exposes inert h1 context facts");
    let parent = config
        .authenticated_genesis_application_parent_v0()
        .copied()
        .expect("fixture carries the authenticated application parent");
    let record_context = SafetyStateRecordContextV0::new(
        &config,
        SAFETY_STATE_RECORD_TEST_PROFILE_REF,
        safety_state_record_test_limits(),
    )
    .expect("fixture has an exact record context");

    assert_eq!(facts.authenticated_genesis_application_parent_v0(), parent);
    assert_eq!(
        facts.safety_state_record_config_ref_v0(),
        safety_state_record_config_ref_v0(&record_context)
            .expect("derive the expected record config reference")
    );
    assert_eq!(facts.validator_set_v0(), config.validator_set());
    assert_eq!(
        facts.consensus_parameters_v0(),
        config.consensus_parameters()
    );
    assert_eq!(
        facts.trusted_genesis_timestamp_ms_v0(),
        config.trusted_genesis_timestamp_ms()
    );
    assert_eq!(
        facts,
        facts.clone(),
        "cloning inert facts grants no authority"
    );
}

#[test]
fn authenticated_genesis_h1_context_facts_cannot_be_reminted_after_h1_admission_v0() {
    let (_config, h1, mut owner) =
        authenticated_genesis_h1_offline_fixture_v0(b"authenticated genesis h1 phase fence");
    let _obligation = owner
        .submit_exact_h1_synced_proposal_v0(h1, &RootSignatures)
        .expect("canonical h1 enters obligation-pending rev1");

    assert!(matches!(
        owner.h1_context_facts_v0(),
        Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
            "h1 context facts are available only at commissioned revision zero"
        ))
    ));
}

#[test]
fn authenticated_genesis_h1_activation_rejects_core_config_substitution_v0() {
    let (config, _) = authenticated_genesis_application_fixture_v0();
    let parent = config
        .authenticated_genesis_application_parent_v0()
        .copied()
        .expect("fixture carries the authenticated application parent");
    let substitutions = [
        (
            "local validator",
            CoreConfig::new_with_authenticated_genesis_application_parent_v0(
                validator_id(2),
                config.validator_set().clone(),
                *config.consensus_parameters(),
                config.trusted_genesis_timestamp_ms(),
                parent,
                config.max_blocks(),
                config.max_observed_messages(),
            )
            .expect("shape-valid local-validator substitution"),
        ),
        (
            "block bound",
            CoreConfig::new_with_authenticated_genesis_application_parent_v0(
                config.local_validator(),
                config.validator_set().clone(),
                *config.consensus_parameters(),
                config.trusted_genesis_timestamp_ms(),
                parent,
                config.max_blocks() + 1,
                config.max_observed_messages(),
            )
            .expect("shape-valid block-bound substitution"),
        ),
        (
            "observation bound",
            CoreConfig::new_with_authenticated_genesis_application_parent_v0(
                config.local_validator(),
                config.validator_set().clone(),
                *config.consensus_parameters(),
                config.trusted_genesis_timestamp_ms(),
                parent,
                config.max_blocks(),
                config.max_observed_messages() + 1,
            )
            .expect("shape-valid observation-bound substitution"),
        ),
    ];

    for (label, substituted) in substitutions {
        let prepared = Core::prepare_authenticated_genesis_application_bootstrap_v0(
            config.clone(),
            genesis_qc(config.validator_set()),
            SAFETY_STATE_RECORD_TEST_PROFILE_REF,
            safety_state_record_test_limits(),
            &RootSignatures,
        )
        .expect("prepare exact config-A facts");
        assert!(prepared.matches_core_config_v0(&config));
        assert!(
            !prepared.matches_core_config_v0(&substituted),
            "{label} must change the complete prepared Core configuration"
        );
        let substituted_prepared = Core::prepare_authenticated_genesis_application_bootstrap_v0(
            substituted.clone(),
            genesis_qc(substituted.validator_set()),
            SAFETY_STATE_RECORD_TEST_PROFILE_REF,
            safety_state_record_test_limits(),
            &RootSignatures,
        )
        .expect("config B can independently prepare canonical facts");
        assert_ne!(
            prepared.safety_state_record_config_ref_v0(),
            substituted_prepared.safety_state_record_config_ref_v0(),
            "{label} must change the Safety record configuration reference"
        );

        assert!(matches!(
            Core::begin_authenticated_genesis_application_h1_offline_validation_v0(
                substituted,
                prepared,
                &RootSignatures,
            ),
            Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "prepared and configured authenticated application contexts differ"
            ))
        ));
    }
}

#[test]
fn authenticated_genesis_h1_offline_valid_closes_rev0_rev1_rev2_without_generic_effects_v0() {
    let (config, h1, mut owner) =
        authenticated_genesis_h1_offline_fixture_v0(b"authenticated genesis exact h1");
    let expected_parent = config
        .authenticated_genesis_application_parent_v0()
        .copied()
        .expect("fixture carries its authenticated application parent");
    assert_eq!(
        owner.phase_v0().expect("classify commissioned owner"),
        AuthenticatedGenesisApplicationH1OfflinePhaseV0::CommissionedRev0
    );
    let obligation = owner
        .submit_exact_h1_synced_proposal_v0(h1.clone(), &RootSignatures)
        .expect("admit canonical signed h1");
    assert_eq!(obligation.barrier_v0(), BarrierId::new(1));
    assert_eq!(obligation.validation_id_v0().generation(), 1);
    assert_eq!(obligation.persistence_v0().state().revision(), 1);
    assert_eq!(
        obligation
            .persistence_v0()
            .state()
            .payload_validation_obligations()
            .len(),
        1
    );
    assert!(obligation
        .persistence_v0()
        .state()
        .payload_validation_completions()
        .is_empty());
    assert_safety_state_record_roundtrip_and_validate(&config, obligation.persistence_v0().state());
    assert_eq!(
        owner.phase_v0().expect("classify rev1 pending owner"),
        AuthenticatedGenesisApplicationH1OfflinePhaseV0::ObligationPersistencePendingRev1
    );

    let safety_binding = owner
        .issue_safety_persistence_binding_v0()
        .expect("issue the dedicated h1 SafetyStore binding");
    assert!(safety_binding.accepts_persistence_v0(obligation.persistence_v0()));
    assert_eq!(
        safety_binding.authenticated_genesis_application_parent_v0(),
        expected_parent
    );
    assert_eq!(safety_binding.proposal_v0(), &h1);
    assert_eq!(
        safety_binding.validation_id_v0(),
        obligation.validation_id_v0()
    );

    let request = owner
        .acknowledge_obligation_persisted_v0(&obligation, obligation.barrier_v0(), &RootSignatures)
        .expect("release the sole request only after rev1 persistence");
    assert_eq!(request.route_v0(), PayloadValidationRouteV0::Synced);
    assert_eq!(request.validation_id_v0(), obligation.validation_id_v0());
    assert_eq!(request.block_v0(), h1.block());
    assert_eq!(
        request
            .parent_v0()
            .authenticated_genesis_application_parent_v0(),
        Some(expected_parent)
    );
    assert_eq!(
        request
            .parent_binding_ref_v0()
            .expect("bind the exact authenticated parent"),
        request
            .parent_v0()
            .binding_ref_v0()
            .expect("derive the same exact parent binding")
    );
    assert_eq!(
        owner.phase_v0().expect("classify released request owner"),
        AuthenticatedGenesisApplicationH1OfflinePhaseV0::ValidationRequestReleasedRev1
    );

    let claimed = request
        .try_claim_v0()
        .unwrap_or_else(|_| panic!("fresh exact h1 request must be claimable once"));
    let (route, validation_id, block, parent, permit) = claimed.into_parts();
    assert_eq!(route, PayloadValidationRouteV0::Synced);
    assert_eq!(validation_id, obligation.validation_id_v0());
    assert_eq!(&block, h1.block());
    assert_eq!(
        parent.authenticated_genesis_application_parent_v0(),
        Some(expected_parent)
    );
    let sealed = owner.seal_after_application_store_commit_v0(
        permit,
        valid_commitments_for_config(&config, &block),
        artifact_ref_for_ids(block.id(), block.header().parent_id()),
    );
    let completion = owner
        .accept_application_sealed_valid_v0(&sealed, &RootSignatures)
        .expect("accept only the App-sealed exact h1 Valid result");
    assert_eq!(completion.barrier_v0(), BarrierId::new(2));
    assert_eq!(completion.validation_id_v0(), validation_id);
    assert_eq!(completion.persistence_v0().state().revision(), 2);
    assert_eq!(
        completion
            .persistence_v0()
            .native_valid_post_ack_action_v0(),
        Some(NativeValidPostAckActionV0::None)
    );
    assert!(safety_binding.accepts_persistence_v0(completion.persistence_v0()));
    assert_safety_state_record_roundtrip_and_validate(&config, completion.persistence_v0().state());
    assert_eq!(
        owner.phase_v0().expect("classify rev2 pending owner"),
        AuthenticatedGenesisApplicationH1OfflinePhaseV0::CompletionPersistencePendingRev2
    );
    let [durable_completion] = completion
        .persistence_v0()
        .state()
        .payload_validation_completions()
    else {
        panic!("exact rev2 state contains one completion")
    };
    let delivery_facts = ApplicationNativeValidDeliveryFactsV0::new(
        PayloadValidationRouteV0::Synced,
        validation_id,
        [0x81; 32],
        [0x82; 32],
        [0x83; 32],
        native_valid_result_checksum_v0(durable_completion.result())
            .expect("rev2 completion contains a canonical Valid result"),
        [0x84; 32],
        [0x85; 32],
        1,
        [0x86; 32],
        [0x87; 32],
        NativeValidPostAckActionV0::None,
        2,
    )
    .expect("exact App D-stage facts");
    let sealed_delivery = owner
        .seal_authenticated_genesis_h1_native_valid_transition_v0(completion, delivery_facts)
        .expect("the installed application authority seals the exact rev2 carrier");
    assert_eq!(sealed_delivery.delivery_facts_v0(), delivery_facts);
    assert_ne!(sealed_delivery.carrier_checksum_v0(), [0; 32]);

    let completed = owner
        .acknowledge_completion_persisted_v0(
            &sealed_delivery,
            sealed_delivery.completion_persistence_v0().barrier_v0(),
            &RootSignatures,
        )
        .expect("close with no post-ack effect");
    assert_eq!(completed.proposal_v0(), &h1);
    assert_eq!(completed.validation_id_v0(), validation_id);
    assert_eq!(completed.safety_revision_v0(), 2);
    assert_eq!(
        completed.terminal_fact_v0().result(),
        PayloadTerminalResult::Valid
    );
    assert_eq!(
        completed
            .completion_v0()
            .result()
            .artifact_ref()
            .expect("terminal completion is Valid")
            .overlay(),
        completed
            .terminal_fact_v0()
            .valid_overlay()
            .expect("terminal fact retains the same overlay")
    );
    assert_eq!(
        owner.phase_v0().expect("classify bounded terminal owner"),
        AuthenticatedGenesisApplicationH1OfflinePhaseV0::CompletedRev2
    );
}

#[test]
fn completed_authenticated_h1_retires_only_into_exact_proof_derived_state_sync_candidate_v0() {
    let (source_config, h1, owner) =
        completed_authenticated_genesis_h1_owner_v0(b"proof carrying promotion h1");
    let proof = exact_h1_finality_proof_v0(&source_config, &h1);
    let proof_id = proof.id();
    let source_parent = source_config
        .authenticated_genesis_application_parent_v0()
        .copied()
        .expect("source config binds the authenticated genesis application parent");
    let candidate = owner
        .retire_completed_into_h1_state_sync_promotion_v0(proof, &RootSignatures)
        .expect("retire the completed narrow owner into an inert proof-derived candidate");

    assert!(candidate
        .plain_core_config_v0()
        .authenticated_genesis_application_parent_v0()
        .is_none());
    assert_eq!(candidate.h1_proposal_v0(), &h1);
    assert_eq!(candidate.proof_id_v0(), proof_id);
    assert_eq!(candidate.source_authenticated_parent_v0(), source_parent);
    assert_eq!(
        candidate.source_validation_id_v0().block_id(),
        h1.block().id()
    );
    assert_ne!(candidate.source_valid_result_checksum_v0(), [0; 32]);
    let target = FinalizedTip::new(
        h1.block().header().height(),
        h1.block().header().view(),
        h1.block().id(),
        h1.block().header().timestamp_ms(),
    );
    let prepared = candidate.prepared_bootstrap_v0().safety_state();
    assert_eq!(prepared.revision(), 0);
    assert_eq!(prepared.finalized(), target);
    assert_eq!(prepared.application_applied(), target);
    assert_eq!(
        prepared
            .state_sync_anchor()
            .expect("candidate retains the complete proof anchor")
            .proof_id(),
        proof_id
    );

    let (plain_config, prepared, returned_h1) = candidate.into_h1_state_sync_bootstrap_parts_v0();
    assert!(plain_config
        .authenticated_genesis_application_parent_v0()
        .is_none());
    assert_eq!(returned_h1, h1);
    assert_eq!(prepared.safety_state().finalized(), target);
}

#[test]
fn authenticated_h1_promotion_consumes_and_rejects_incomplete_or_foreign_authority_v0() {
    let (incomplete_config, incomplete_h1, incomplete_owner) =
        authenticated_genesis_h1_offline_fixture_v0(b"incomplete promotion owner");
    let proof = exact_h1_finality_proof_v0(&incomplete_config, &incomplete_h1);
    assert!(matches!(
        incomplete_owner.retire_completed_into_h1_state_sync_promotion_v0(proof, &RootSignatures,),
        Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
            "h1 state-sync promotion requires the exact completed revision-two owner"
        ))
    ));

    let (source_config, source_h1, source_owner) =
        completed_authenticated_genesis_h1_owner_v0(b"source promotion owner");
    let (foreign_config, foreign_h1, _foreign_owner) =
        authenticated_genesis_h1_offline_fixture_v0(b"foreign promotion proof");
    assert_eq!(
        source_config.validator_set(),
        foreign_config.validator_set(),
        "the negative must isolate proposal identity rather than validator-set scope"
    );
    assert_ne!(source_h1, foreign_h1);
    let foreign_proof = exact_h1_finality_proof_v0(&foreign_config, &foreign_h1);
    assert!(matches!(
        source_owner.retire_completed_into_h1_state_sync_promotion_v0(
            foreign_proof,
            &RootSignatures,
        ),
        Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
            "h1 state-sync proof does not exactly bind the completed proposal and rev2 Valid result"
        ))
    ));
}

#[test]
fn authenticated_h1_promotion_requires_signature_verified_complete_finality_proof_v0() {
    let (source_config, h1, owner) =
        completed_authenticated_genesis_h1_owner_v0(b"promotion signature proof");
    let proof = exact_h1_finality_proof_v0(&source_config, &h1);
    assert!(owner
        .retire_completed_into_h1_state_sync_promotion_v0(proof, &RejectSignatures)
        .is_err());
}

#[test]
fn authenticated_genesis_h1_stable_native_valid_recovery_is_exact_and_inert_v0() {
    let (config, _) = authenticated_genesis_application_fixture_v0();
    let genesis = genesis_qc(config.validator_set());
    let prepared_live = Core::prepare_authenticated_genesis_application_bootstrap_v0(
        config.clone(),
        genesis.clone(),
        SAFETY_STATE_RECORD_TEST_PROFILE_REF,
        safety_state_record_test_limits(),
        &RootSignatures,
    )
    .expect("prepare live empty-h1 owner");
    let prepared_recovery = Core::prepare_authenticated_genesis_application_bootstrap_v0(
        config.clone(),
        genesis,
        SAFETY_STATE_RECORD_TEST_PROFILE_REF,
        safety_state_record_test_limits(),
        &RootSignatures,
    )
    .expect("prepare independent recovery facts");
    struct Registrar;
    impl AuthenticatedGenesisApplicationH1OfflineApplicationRegistrarV0 for Registrar {
        type Output = AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0;
        type Error = std::convert::Infallible;
        fn register_authenticated_genesis_application_h1_offline_v0(
            self,
            owner: AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0,
        ) -> std::result::Result<Self::Output, Self::Error> {
            Ok(owner)
        }
    }
    let bundle = Core::begin_authenticated_genesis_application_h1_offline_validation_v0(
        config.clone(),
        prepared_live,
        &RootSignatures,
    )
    .expect("begin empty-h1 owner");
    let mut owner = bundle
        .activate_application_v0(Registrar)
        .unwrap_or_else(|never| match never {});
    let h1 = authenticated_genesis_empty_h1_proposal_v0(&config);
    let obligation = owner
        .submit_exact_h1_synced_proposal_v0(h1.clone(), &RootSignatures)
        .expect("persistable empty-h1 obligation");
    let revision_one = obligation.persistence_v0().state().clone();
    let _binding = owner
        .issue_safety_persistence_binding_v0()
        .expect("issue dedicated live binding");
    let request = owner
        .acknowledge_obligation_persisted_v0(&obligation, obligation.barrier_v0(), &RootSignatures)
        .expect("release exact empty-h1 request");
    let claimed = request
        .try_claim_v0()
        .unwrap_or_else(|_| panic!("fresh empty-h1 request was already claimed"));
    let (_route, validation_id, block, _parent, permit) = claimed.into_parts();
    let sealed = owner.seal_after_application_store_commit_v0(
        permit,
        valid_commitments_for_config(&config, &block),
        artifact_ref_for_ids(block.id(), block.header().parent_id()),
    );
    let completion = owner
        .accept_application_sealed_valid_v0(&sealed, &RootSignatures)
        .expect("produce exact empty-h1 rev2");
    let revision_two = completion.persistence_v0().state().clone();
    let carrier_checksum = completion.carrier_checksum_v0();
    let valid_result_checksum =
        native_valid_result_checksum_v0(revision_two.payload_validation_completions()[0].result())
            .expect("canonical valid checksum");
    let delivery = ApplicationNativeValidDeliveryFactsV0::new(
        PayloadValidationRouteV0::Synced,
        validation_id,
        [0x81; 32],
        [0x82; 32],
        [0x83; 32],
        valid_result_checksum,
        [0x84; 32],
        [0x85; 32],
        1,
        [0x86; 32],
        [0x87; 32],
        NativeValidPostAckActionV0::None,
        2,
    )
    .expect("exact delivery comparison facts");

    let parent = config
        .authenticated_genesis_application_parent_v0()
        .copied()
        .expect("authenticated parent");
    let foreign_config = CoreConfig::new_with_authenticated_genesis_application_parent_v0(
        validator_id(2),
        config.validator_set().clone(),
        *config.consensus_parameters(),
        config.trusted_genesis_timestamp_ms(),
        parent,
        32,
        64,
    )
    .expect("shape-valid foreign local Core config");
    let foreign_prepared = Core::prepare_authenticated_genesis_application_bootstrap_v0(
        foreign_config,
        genesis_qc(config.validator_set()),
        SAFETY_STATE_RECORD_TEST_PROFILE_REF,
        safety_state_record_test_limits(),
        &RootSignatures,
    )
    .expect("prepare foreign Core facts");
    assert!(matches!(
        Core::begin_authenticated_genesis_application_h1_stable_native_valid_recovery_v0(
            config.clone(),
            foreign_prepared,
            revision_one.clone(),
            revision_two.clone(),
            &RootSignatures,
        ),
        Err(CoreError::NativeValidCompletionRecoveryRejected(
            "prepared and configured authenticated-genesis contexts differ"
        ))
    ));
    let splice_prepared = Core::prepare_authenticated_genesis_application_bootstrap_v0(
        config.clone(),
        genesis_qc(config.validator_set()),
        SAFETY_STATE_RECORD_TEST_PROFILE_REF,
        safety_state_record_test_limits(),
        &RootSignatures,
    )
    .expect("prepare exact splice challenge facts");
    assert!(
        Core::begin_authenticated_genesis_application_h1_stable_native_valid_recovery_v0(
            config.clone(),
            splice_prepared,
            revision_two.clone(),
            revision_one.clone(),
            &RootSignatures,
        )
        .is_err()
    );
    assert_eq!(
        Core::recover(config.clone(), revision_two.clone(), &RootSignatures),
        Err(CoreError::AuthenticatedGenesisApplicationActivationUnavailable)
    );

    let session = Core::begin_authenticated_genesis_application_h1_stable_native_valid_recovery_v0(
        config,
        prepared_recovery,
        revision_one,
        revision_two,
        &RootSignatures,
    )
    .expect("begin dedicated stable completion recovery");
    assert_eq!(session.challenge_v0().proposal_v0(), &h1);
    assert_eq!(session.challenge_v0().validation_id_v0(), validation_id);
    assert_eq!(
        session.challenge_v0().completion_carrier_checksum_v0(),
        carrier_checksum
    );
    let core_config_ref = session.challenge_v0().safety_state_record_config_ref_v0();
    let safety_facts =
        AuthenticatedGenesisApplicationH1StableNativeValidSafetyHeadFactsV0::from_authenticated_store_comparison_v0(
            [1; 32], [2; 32], core_config_ref,
            [3; 32], [4; 32], [5; 32], [6; 32], [7; 32], [8; 32],
            [9; 32], [10; 32], [11; 32], [12; 32], [13; 32],
            carrier_checksum, delivery,
        )
        .expect("shape-valid inert Safety comparison facts");
    struct Reconciler;
    impl AuthenticatedGenesisApplicationH1StableNativeValidRecoveryReconcilerV0 for Reconciler {
        fn reconcile_authenticated_genesis_application_h1_stable_native_valid_v0(
            &mut self,
            _challenge: &AuthenticatedGenesisApplicationH1StableNativeValidRecoveryChallengeV0,
            _safety_head_facts: &AuthenticatedGenesisApplicationH1StableNativeValidSafetyHeadFactsV0,
        ) -> bool {
            true
        }
    }
    let attestation = session
        .challenge_v0()
        .attest_authenticated_reconciliation_v0(safety_facts, &mut Reconciler)
        .expect("trusted exact join attests the inert tuple");
    let mut replay = session
        .reconcile_and_complete_v0(attestation)
        .expect("session consumes its own attestation");
    let recovered = replay
        .release_inert_completed_facts_v0()
        .expect("release exact completed facts once");
    assert_eq!(recovered.proposal_v0(), &h1);
    assert_eq!(recovered.completion_v0().id(), validation_id);
    assert_eq!(
        recovered.terminal_fact_v0().valid_overlay(),
        Some(
            recovered
                .completion_v0()
                .result()
                .artifact_ref()
                .expect("Valid")
                .overlay()
        )
    );
    assert_eq!(recovered.completion_carrier_checksum_v0(), carrier_checksum);
    assert!(matches!(
        replay.release_inert_completed_facts_v0(),
        Err(CoreError::NativeValidCompletionRecoveryRejected(
            "stable h1 completion facts were already released"
        ))
    ));
}

#[test]
fn authenticated_genesis_h1_offline_rejects_same_header_body_substitution_transactionally_v0() {
    let (config, h1, mut owner) =
        authenticated_genesis_h1_offline_fixture_v0(b"authenticated genesis canonical body");
    let substituted_payload =
        ApplicationPayloadV0::new(vec![b"authenticated genesis substituted body".to_vec()])
            .expect("canonical substituted payload")
            .try_cev0_bytes()
            .expect("encode substituted payload");
    let substituted_block = Block::new(
        h1.block().header().clone(),
        substituted_payload,
        h1.block().evidence_objects().to_vec(),
    )
    .expect("transport block accepts a same-header body carrier");
    let substituted = SignedProposalV0::new(
        substituted_block,
        h1.witness().clone(),
        config.validator_set(),
        None,
        config.consensus_parameters(),
        config.trusted_genesis_timestamp_ms(),
    )
    .expect("unchanged signed header and witness remain structurally authenticated");
    assert_eq!(substituted.block().header(), h1.block().header());
    assert_eq!(substituted.witness(), h1.witness());

    assert!(matches!(
        owner.submit_exact_h1_synced_proposal_v0(substituted, &RootSignatures),
        Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
            "offline h1 body is not canonically bound to its signed roots"
        ))
    ));
    assert_eq!(
        owner
            .phase_v0()
            .expect("rejected body leaves owner unchanged"),
        AuthenticatedGenesisApplicationH1OfflinePhaseV0::CommissionedRev0
    );
}

#[test]
fn authenticated_genesis_h1_offline_rejects_foreign_application_seal_transactionally_v0() {
    let (_foreign_config, _foreign_h1, foreign_owner) =
        authenticated_genesis_h1_offline_fixture_v0(b"foreign seal owner");
    let (config, h1, mut owner) =
        authenticated_genesis_h1_offline_fixture_v0(b"foreign seal target");
    let obligation = owner
        .submit_exact_h1_synced_proposal_v0(h1, &RootSignatures)
        .expect("enter exact rev1 phase");
    let _binding = owner
        .issue_safety_persistence_binding_v0()
        .expect("bind the target Safety owner");
    let request = owner
        .acknowledge_obligation_persisted_v0(&obligation, obligation.barrier_v0(), &RootSignatures)
        .expect("release the target request");
    let claimed = request
        .try_claim_v0()
        .unwrap_or_else(|_| panic!("target request must be claimable once"));
    let (_route, validation_id, block, _parent, permit) = claimed.into_parts();
    let foreign_sealed = foreign_owner.seal_after_application_store_commit_v0(
        permit,
        valid_commitments_for_config(&config, &block),
        artifact_ref_for_ids(block.id(), block.header().parent_id()),
    );

    match owner.accept_application_sealed_valid_v0(&foreign_sealed, &RootSignatures) {
        Err(CoreError::ApplicationSealedValidMismatch(block_id)) => {
            assert_eq!(block_id, validation_id.block_id());
        }
        Err(error) => panic!("foreign application seal returned the wrong error: {error:?}"),
        Ok(_) => panic!("foreign application seal produced rev2 persistence"),
    }
    assert_eq!(
        owner
            .phase_v0()
            .expect("foreign seal leaves owner unchanged"),
        AuthenticatedGenesisApplicationH1OfflinePhaseV0::ValidationRequestReleasedRev1
    );
}

#[test]
fn authenticated_genesis_h1_offline_enforces_binding_barriers_and_phase_order_v0() {
    let (config, h1, mut owner) =
        authenticated_genesis_h1_offline_fixture_v0(b"offline phase and barrier ordering");
    let obligation = owner
        .submit_exact_h1_synced_proposal_v0(h1.clone(), &RootSignatures)
        .expect("enter rev1 pending phase");
    assert!(matches!(
        owner.acknowledge_obligation_persisted_v0(
            &obligation,
            obligation.barrier_v0(),
            &RootSignatures,
        ),
        Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
            _
        ))
    ));
    let _binding = owner
        .issue_safety_persistence_binding_v0()
        .expect("issue exact Safety binding once");
    assert!(matches!(
        owner.issue_safety_persistence_binding_v0(),
        Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
            _
        ))
    ));
    assert!(matches!(
        owner.acknowledge_obligation_persisted_v0(&obligation, BarrierId::new(9), &RootSignatures,),
        Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
            _
        ))
    ));
    assert_eq!(
        owner
            .phase_v0()
            .expect("wrong rev1 barrier is transactional"),
        AuthenticatedGenesisApplicationH1OfflinePhaseV0::ObligationPersistencePendingRev1
    );
    let request = owner
        .acknowledge_obligation_persisted_v0(&obligation, obligation.barrier_v0(), &RootSignatures)
        .expect("exact rev1 barrier releases one request");
    assert!(matches!(
        owner.acknowledge_obligation_persisted_v0(
            &obligation,
            obligation.barrier_v0(),
            &RootSignatures,
        ),
        Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
            _
        ))
    ));
    assert!(matches!(
        owner.submit_exact_h1_synced_proposal_v0(h1, &RootSignatures),
        Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
            _
        ))
    ));

    let claimed = request
        .try_claim_v0()
        .unwrap_or_else(|_| panic!("ordered request remains uniquely claimable"));
    let (_route, _id, block, _parent, permit) = claimed.into_parts();
    let sealed = owner.seal_after_application_store_commit_v0(
        permit,
        valid_commitments_for_config(&config, &block),
        artifact_ref_for_ids(block.id(), block.header().parent_id()),
    );
    let completion = owner
        .accept_application_sealed_valid_v0(&sealed, &RootSignatures)
        .expect("exact sealed result enters rev2 pending");
    let [durable_completion] = completion
        .persistence_v0()
        .state()
        .payload_validation_completions()
    else {
        panic!("exact rev2 state contains one completion")
    };
    let facts = ApplicationNativeValidDeliveryFactsV0::new(
        PayloadValidationRouteV0::Synced,
        completion.validation_id_v0(),
        [0x91; 32],
        [0x92; 32],
        [0x93; 32],
        native_valid_result_checksum_v0(durable_completion.result())
            .expect("exact rev2 completion is Valid"),
        [0x94; 32],
        [0x95; 32],
        1,
        [0x96; 32],
        [0x97; 32],
        NativeValidPostAckActionV0::None,
        2,
    )
    .expect("exact D facts");
    let sealed_delivery = owner
        .seal_authenticated_genesis_h1_native_valid_transition_v0(completion, facts)
        .expect("seal exact D transition");
    assert!(matches!(
        owner.acknowledge_completion_persisted_v0(
            &sealed_delivery,
            BarrierId::new(99),
            &RootSignatures,
        ),
        Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
            _
        ))
    ));
    assert_eq!(
        owner
            .phase_v0()
            .expect("wrong rev2 barrier is transactional"),
        AuthenticatedGenesisApplicationH1OfflinePhaseV0::CompletionPersistencePendingRev2
    );
    let _completed = owner
        .acknowledge_completion_persisted_v0(
            &sealed_delivery,
            sealed_delivery.completion_persistence_v0().barrier_v0(),
            &RootSignatures,
        )
        .expect("exact rev2 barrier reaches bounded completion");
    assert!(matches!(
        owner.accept_application_sealed_valid_v0(&sealed, &RootSignatures),
        Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
            _
        ))
    ));
}

#[test]
fn authenticated_genesis_h1_offline_surface_remains_non_generic_v0() {
    let source = include_str!("core.rs");
    let implementation = source
        .split_once("impl AuthenticatedGenesisApplicationH1OfflineValidationV0 {")
        .expect("bounded offline h1 implementation remains present")
        .1
        .split_once("\n}\n\n/// Inert schema-v12 SafetyState")
        .expect("bounded offline h1 implementation remains separately auditable")
        .0;
    for forbidden in [
        "pub fn core(",
        "pub fn step(",
        "pub fn effects(",
        "pub fn into_parts(",
        "pub fn resume(",
        "pub fn timeout(",
        "pub fn issue_application_seal_authority_v0(",
        "pub fn issue_application_finalization",
    ] {
        assert!(
            !implementation.contains(forbidden),
            "bounded offline h1 owner must not expose `{forbidden}`",
        );
    }
    for forbidden_trait in [
        "impl Clone for AuthenticatedGenesisApplicationH1OfflineValidationV0",
        "impl Deref for AuthenticatedGenesisApplicationH1OfflineValidationV0",
        "impl AsRef<Core> for AuthenticatedGenesisApplicationH1OfflineValidationV0",
        "impl From<AuthenticatedGenesisApplicationH1OfflineValidationV0> for Core",
    ] {
        assert!(
            !source.contains(forbidden_trait),
            "bounded offline h1 owner must not expose `{forbidden_trait}`",
        );
    }
}

#[test]
fn authenticated_genesis_application_bootstrap_prepares_only_inert_canonical_facts_v0() {
    let (config, _) = authenticated_genesis_application_fixture_v0();
    let parent = config
        .authenticated_genesis_application_parent_v0()
        .copied()
        .expect("fixture carries the exact application parent");
    let genesis = genesis_qc(config.validator_set());
    let prepared = Core::prepare_authenticated_genesis_application_bootstrap_v0(
        config.clone(),
        genesis.clone(),
        SAFETY_STATE_RECORD_TEST_PROFILE_REF,
        safety_state_record_test_limits(),
        &RootSignatures,
    )
    .expect("prepare inert authenticated-genesis commissioning facts");

    let state = prepared.safety_state();
    assert_eq!(state.schema_version(), SAFETY_STATE_SCHEMA_VERSION);
    assert_eq!(state.revision(), 0);
    assert_eq!(state.current_view(), View::new(1));
    assert_eq!(state.high_qc(), state.locked_qc());
    assert_eq!(state.finalized(), state.application_applied());
    assert_eq!(state.finalized().height(), Height::new(0));
    assert_eq!(state.finalized().view(), View::new(0));
    assert_eq!(state.finalized().block_id(), config.genesis_block_id());
    assert_eq!(
        state.finalized().timestamp_ms(),
        config.trusted_genesis_timestamp_ms()
    );
    assert_eq!(
        state.authenticated_genesis_application_parent_v0(),
        Some(&parent)
    );
    assert_eq!(
        prepared.authenticated_genesis_application_parent_v0(),
        parent
    );
    assert!(state.state_sync_anchor().is_none());
    assert!(state.last_voted_view().is_none());
    assert!(state.last_timeout_view().is_none());
    assert!(state.payload_terminal_facts().is_empty());
    assert!(state.payload_validation_obligations().is_empty());
    assert!(state.payload_validation_completions().is_empty());
    assert!(state.pending_tc_high_qc_sync().is_none());
    assert!(state.pending_standalone_qc_sync().is_none());
    assert!(state.pending_sign().is_none());
    assert!(state.last_finalization().is_none());
    assert!(state.finalization_queue().is_empty());
    assert!(state.pending_finalize().is_none());
    assert!(state.safety_halt().is_none());

    let record_context = SafetyStateRecordContextV0::new(
        &config,
        SAFETY_STATE_RECORD_TEST_PROFILE_REF,
        safety_state_record_test_limits(),
    )
    .expect("capacity-compatible exact record context");
    assert_eq!(
        prepared.safety_state_record_config_ref_v0(),
        safety_state_record_config_ref_v0(&record_context)
            .expect("derive the same canonical record config reference")
    );
    let foreign_profile = Core::prepare_authenticated_genesis_application_bootstrap_v0(
        config.clone(),
        genesis.clone(),
        [0x72; 32],
        safety_state_record_test_limits(),
        &RootSignatures,
    )
    .expect("a distinct nonzero verifier profile remains structurally valid");
    assert_ne!(
        prepared.safety_state_record_config_ref_v0(),
        foreign_profile.safety_state_record_config_ref_v0(),
        "the canonical config reference must bind the verifier profile",
    );
    let wider_limits = SafetyStateRecordLimitsV0::new(65 * 1024 * 1024, 17 * 1024 * 1024)
        .expect("shape-valid wider record limits");
    let wider_envelope = Core::prepare_authenticated_genesis_application_bootstrap_v0(
        config.clone(),
        genesis.clone(),
        SAFETY_STATE_RECORD_TEST_PROFILE_REF,
        wider_limits,
        &RootSignatures,
    )
    .expect("a wider bounded record envelope remains valid");
    assert_ne!(
        prepared.safety_state_record_config_ref_v0(),
        wider_envelope.safety_state_record_config_ref_v0(),
        "the canonical config reference must bind the record-resource envelope",
    );
    state
        .validate_exact_authenticated_genesis_application_bootstrap_v0(&config, &genesis)
        .expect("the returned state retains the exact fresh commissioning shape");
    assert_safety_state_record_roundtrip_and_validate(&config, state);
}

#[test]
fn authenticated_genesis_application_bootstrap_rejects_missing_or_weak_context_v0() {
    let (plain_config, _) = configured_core();
    match Core::prepare_authenticated_genesis_application_bootstrap_v0(
        plain_config.clone(),
        genesis_qc(plain_config.validator_set()),
        SAFETY_STATE_RECORD_TEST_PROFILE_REF,
        safety_state_record_test_limits(),
        &RootSignatures,
    ) {
        Err(CoreError::InvalidConfig(
            "authenticated genesis application bootstrap requires its exact application parent",
        )) => {}
        Err(error) => panic!("missing-parent preparation returned the wrong error: {error:?}"),
        Ok(_) => panic!("missing-parent preparation returned commissioning facts"),
    }

    let (config, _) = authenticated_genesis_application_fixture_v0();
    let genesis = genesis_qc(config.validator_set());
    match Core::prepare_authenticated_genesis_application_bootstrap_v0(
            config.clone(),
            genesis.clone(),
            [0; 32],
            safety_state_record_test_limits(),
            &RootSignatures,
        ) {
        Err(CoreError::InvalidConfig(
            "authenticated genesis application bootstrap requires a nonzero verifier profile reference",
        )) => {}
        Err(error) => panic!("zero-profile preparation returned the wrong error: {error:?}"),
        Ok(_) => panic!("zero-profile preparation returned commissioning facts"),
    }
    let insufficient_limits =
        SafetyStateRecordLimitsV0::new(128, 1).expect("shape-valid but insufficient limits");
    match Core::prepare_authenticated_genesis_application_bootstrap_v0(
        config,
        genesis,
        SAFETY_STATE_RECORD_TEST_PROFILE_REF,
        insufficient_limits,
        &RootSignatures,
    ) {
        Err(CoreError::InvalidConfig(
            "authenticated genesis application bootstrap safety-state record context is invalid",
        )) => {}
        Err(error) => panic!("bounded preparation returned the wrong error: {error:?}"),
        Ok(_) => panic!("insufficient record limits returned commissioning facts"),
    }
}

#[test]
fn prepared_authenticated_genesis_application_surface_remains_inert_v0() {
    let source = include_str!("core.rs");
    assert_eq!(
        source
            .matches("impl PreparedAuthenticatedGenesisApplicationBootstrapV0 {")
            .count(),
        1,
        "the prepared facts must keep one auditable inherent implementation",
    );
    let implementation = source
        .split_once("impl PreparedAuthenticatedGenesisApplicationBootstrapV0 {")
        .expect("prepared authenticated-genesis implementation remains present")
        .1;
    let implementation = implementation
        .split_once("\n}\n\n/// Exact live-only phases")
        .expect("prepared implementation remains a separately bounded surface")
        .0;

    for forbidden in [
        "fn core",
        "fn into_parts",
        "fn step",
        "issue_",
        "authority",
        "permit",
        "receipt",
    ] {
        assert!(
            !implementation.contains(forbidden),
            "prepared authenticated-genesis facts must not expose `{forbidden}`",
        );
    }
    for forbidden_trait in [
        "impl Deref for PreparedAuthenticatedGenesisApplicationBootstrapV0",
        "impl AsRef<Core> for PreparedAuthenticatedGenesisApplicationBootstrapV0",
        "impl From<PreparedAuthenticatedGenesisApplicationBootstrapV0> for Core",
    ] {
        assert!(
            !source.contains(forbidden_trait),
            "prepared authenticated-genesis facts must not expose `{forbidden_trait}`",
        );
    }
}

#[test]
fn authenticated_genesis_application_bootstrap_rejects_every_nonempty_runtime_fact_v0() {
    let worker = std::thread::Builder::new()
        .name(std::string::String::from(
            "core-authenticated-genesis-empty-classifier",
        ))
        .stack_size(32 * 1024 * 1024)
        .spawn(run_authenticated_genesis_runtime_fact_matrix_v0)
        .expect("spawn the bounded large-stack authenticated-genesis mutation matrix");
    match worker.join() {
        Ok(()) => {}
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

fn run_authenticated_genesis_runtime_fact_matrix_v0() {
    let (config, pristine) = authenticated_genesis_application_fixture_v0();
    let genesis = genesis_qc(config.validator_set());
    let set = config.validator_set();
    let ordinary_block_id = BlockId::new([0x81; 32]);
    let ordinary_qc = qc(set, 1, 1, ordinary_block_id);
    let ordinary_reference = QcReferenceV0::ordinary(ordinary_qc.clone());
    let proposed = proposal(set, genesis.clone(), 1, b"authenticated genesis mutation");
    let validation_id =
        ValidationId::new(proposed.block().id(), proposed.block().header().view(), 1);
    let authenticated_parent = PayloadValidationParentV0::authenticated_genesis_application(
        pristine.finalized(),
        config
            .authenticated_genesis_application_parent_v0()
            .copied()
            .expect("fixture carries its authenticated application parent"),
    )
    .expect("exact genesis parent context");
    let obligation = DurablePayloadValidationObligationV0::new(
        PayloadValidationRouteV0::Proposal,
        validation_id,
        proposed,
        authenticated_parent,
        1,
    );
    let completion = DurablePayloadValidationCompletionV0::new(
        PayloadValidationRouteV0::Proposal,
        validation_id,
        DurablePayloadValidationResultV1::DeterministicallyInvalid,
        1,
    );
    let pending_tc = PendingTcHighQcSync::from_timeout_certificate(timeout_certificate(
        set,
        2,
        ordinary_qc.clone(),
    ))
    .expect("canonical pending TC mutation");
    let vote_root =
        Vote::signing_root_for_set(set, View::new(1), Height::new(1), ordinary_block_id)
            .expect("canonical pending vote mutation");
    let (_plain_config, proof, h1, _h2, _h3) = h1_state_sync_fixture();
    let finalization = DurableFinalizationV0::new(
        pristine.finalized(),
        proof,
        BlockIdOverlayRefV0::new(h1.block().id(), pristine.finalized().block_id(), [0xA1; 32]),
    )
    .expect("shape-valid durable finalization mutation");

    let mut future_view = pristine.clone();
    future_view.set_current_view(View::new(2));
    let mut voted = pristine.clone();
    voted.set_last_voted(View::new(1));
    let mut timed_out = pristine.clone();
    timed_out.set_last_timeout(View::new(1));
    let mut high_qc = pristine.clone();
    high_qc.set_high_qc(ordinary_reference.clone());
    let mut locked_qc = pristine.clone();
    locked_qc.set_locked_qc(ordinary_reference);
    let mut finalized = pristine.clone();
    finalized.set_finalized(FinalizedTip::new(
        Height::new(1),
        View::new(1),
        ordinary_block_id,
        100,
    ));
    let mut revision = pristine.clone();
    revision
        .next_revision()
        .expect("advance the durable revision mutation");
    let mut terminal = pristine.clone();
    terminal.set_payload_terminal_facts(vec![PayloadTerminalFact::new_deterministically_invalid(
        BlockId::new([0x91; 32]),
        1,
    )]);
    let mut obligation_state = pristine.clone();
    obligation_state.set_payload_validation_obligations(vec![obligation]);
    let mut completion_state = pristine.clone();
    completion_state.set_payload_validation_completions(vec![completion]);
    let mut tc_sync = pristine.clone();
    tc_sync.set_pending_tc_high_qc_sync(Some(pending_tc));
    let mut standalone_sync = pristine.clone();
    standalone_sync.set_pending_standalone_qc_sync(Some(PendingStandaloneQcSync::new(ordinary_qc)));
    let mut pending_sign = pristine.clone();
    pending_sign.set_pending_sign(Some(SignIntent::Vote {
        authorizing_safety_revision: 1,
        view: View::new(1),
        height: Height::new(1),
        block_id: ordinary_block_id,
        signing_root: vote_root,
    }));
    let mut last_finalization = pristine.clone();
    last_finalization.set_last_finalization(finalization.clone());
    let mut application_applied = pristine.clone();
    application_applied.set_application_applied(FinalizedTip::new(
        Height::new(1),
        View::new(1),
        ordinary_block_id,
        100,
    ));
    let mut finalization_queue = pristine.clone();
    finalization_queue.set_finalization_queue(vec![finalization.clone()]);
    let mut pending_finalize = pristine.clone();
    pending_finalize.set_pending_finalize(Some(finalization.proof_id()));
    let mut safety_halt = pristine;
    safety_halt.set_safety_halt(Some(SafetyHalt::conflicting_payload_validation(
        ordinary_block_id,
    )));

    for (name, state) in [
        ("advanced current view", future_view),
        ("durable vote watermark", voted),
        ("durable timeout watermark", timed_out),
        ("advanced high QC", high_qc),
        ("advanced locked QC", locked_qc),
        ("advanced finalized tip", finalized),
        ("advanced safety revision", revision),
        ("payload terminal history", terminal),
        ("payload validation obligation", obligation_state),
        ("payload validation completion", completion_state),
        ("pending TC high-QC sync", tc_sync),
        ("pending standalone QC sync", standalone_sync),
        ("pending sign outbox", pending_sign),
        ("last durable finalization", last_finalization),
        (
            "advanced application-applied watermark",
            application_applied,
        ),
        ("nonempty finalization queue", finalization_queue),
        ("pending finalize proof", pending_finalize),
        ("durable safety halt", safety_halt),
    ] {
        assert_eq!(
            state.validate_exact_authenticated_genesis_application_bootstrap_v0(
                &config, &genesis,
            ),
            Err(CoreError::InvalidRecovery(
                "authenticated genesis application bootstrap must contain only exact inert revision-zero genesis facts",
            )),
            "{name} must not enter the commissioning record",
        );
    }
}

#[test]
fn fresh_h1_state_sync_bootstrap_is_anchor_only_and_resumes_with_safety_replay() {
    let (config, proof, h1, _h2, h3) = h1_state_sync_fixture();
    assert!(Core::prepare_h1_state_sync_bootstrap_v0(
        config.clone(),
        proof.clone(),
        &RejectSignatures,
    )
    .is_err());

    let prepared = Core::prepare_h1_state_sync_bootstrap_v0(config.clone(), proof, &RootSignatures)
        .expect("the complete h1 proof prepares an inert bootstrap");
    let state = prepared.safety_state();
    assert_eq!(state.schema_version(), 13);
    assert_eq!(state.revision(), 0);
    assert_eq!(state.finalized(), state.application_applied());
    assert_eq!(state.finalized().block_id(), h1.block().id());
    assert_eq!(state.high_qc().qc_ref().block_id(), h3.block().id());
    assert!(state.last_voted_view().is_none());
    assert!(state.last_timeout_view().is_none());
    assert!(state.last_finalization().is_none());
    assert!(state.finalization_queue().is_empty());
    assert!(state.pending_finalize().is_none());
    assert!(state.payload_terminal_facts().is_empty());
    assert!(state.payload_validation_obligations().is_empty());
    assert!(state.payload_validation_completions().is_empty());
    let anchor = state
        .state_sync_anchor()
        .expect("schema v13 keeps permanent h1 provenance");
    assert_eq!(
        anchor.proof().finalized_block().header(),
        h1.block().header()
    );
    assert_eq!(anchor.authenticated_parent().block_id(), GENESIS);
    assert_safety_state_record_roundtrip_and_validate(&config, state);

    let durable = prepared.into_safety_state();
    assert_eq!(
        Core::recover(config.clone(), durable.clone(), &RootSignatures),
        Err(CoreError::InvalidRecovery(
            "a state-sync anchored namespace requires its dedicated authenticated recovery session"
        ))
    );
    let session =
        Core::begin_state_sync_anchor_recovery_v0(config, durable.clone(), &RootSignatures)
            .expect("the exact prepared state creates an inert recovery session");
    let mut reconciler = ExactFreshStateSyncReconcilerV0 {
        expected_state: durable,
        expected_h1: h1.block().header().clone(),
        accept: true,
        calls: 0,
    };
    let mut core = session
        .reconcile_and_activate_v0(&mut reconciler)
        .expect("the trusted host accepted the exact base and virgin signer binding");
    assert_eq!(reconciler.calls, 1);
    let effects = core
        .step(Input::Resume, &RootSignatures)
        .expect("fresh anchor recovery resumes only through safety replay");
    assert!(matches!(
        effects.as_slice(),
        [Effect::RequestSafetyReplay {
            finalized,
            high_qc,
            locked_qc,
        }] if *finalized == core.safety_state().finalized()
            && *high_qc == core.safety_state().high_qc().qc_ref()
            && *locked_qc == core.safety_state().locked_qc().qc_ref()
    ));
}

#[test]
fn state_sync_anchor_is_replay_request_only_until_successor_recovery_exists() {
    let (config, proof, h1, h2, _h3) = h1_state_sync_fixture();
    let durable = Core::prepare_h1_state_sync_bootstrap_v0(config.clone(), proof, &RootSignatures)
        .expect("valid h1 bootstrap")
        .into_safety_state();
    let session =
        Core::begin_state_sync_anchor_recovery_v0(config, durable.clone(), &RootSignatures)
            .expect("exact h1 session");
    let mut reconciler = ExactFreshStateSyncReconcilerV0 {
        expected_state: durable,
        expected_h1: h1.block().header().clone(),
        accept: true,
        calls: 0,
    };
    let mut core = session
        .reconcile_and_activate_v0(&mut reconciler)
        .expect("exact fresh host reconciliation");
    let initial = core.clone();
    let first_replay_request = core
        .step(Input::Resume, &RootSignatures)
        .expect("request initial safety replay");
    let second_replay_request = core
        .step(Input::Resume, &RootSignatures)
        .expect("repeat the exact inert safety replay request");
    assert_eq!(first_replay_request, second_replay_request);
    assert!(matches!(
        first_replay_request.as_slice(),
        [Effect::RequestSafetyReplay { finalized, high_qc, locked_qc }]
            if *finalized == initial.safety_state().finalized()
                && *high_qc == initial.safety_state().high_qc().qc_ref()
                && *locked_qc == initial.safety_state().locked_qc().qc_ref()
    ));
    assert_eq!(core, initial, "Resume must leave the anchored Core inert");

    assert_eq!(
        core.step(Input::SyncedProposal(Box::new(h2)), &RootSignatures),
        Err(CoreError::StateSyncAnchorSuccessorRecoveryUnavailable),
        "h2 cannot create a durable obligation before anchored-successor recovery"
    );
    assert_eq!(core, initial, "rejected h2 replay must be transactional");
    assert_eq!(core.safety_state().revision(), 0);
    assert!(core
        .safety_state()
        .payload_terminal_fact(h1.block().id())
        .is_none());
    assert!(core
        .safety_state()
        .payload_validation_completions()
        .iter()
        .all(|completion| completion.id().block_id() != h1.block().id()));
    assert!(core
        .safety_state()
        .payload_validation_obligations()
        .is_empty());

    assert_eq!(
        core.step(Input::SafetyReplayComplete, &RootSignatures),
        Err(CoreError::StateSyncAnchorSuccessorRecoveryUnavailable),
        "the replay fence cannot be cleared without authenticated successor recovery"
    );
    assert_eq!(core, initial, "rejected replay completion must be inert");
    assert_eq!(
        core.step(Input::Resume, &RootSignatures)
            .expect("the replay request remains idempotently available"),
        first_replay_request
    );
}

#[test]
fn state_sync_anchor_persisted_state_rejects_every_noncanonical_successor() {
    let (config, proof, _h1, _h2, _h3) = h1_state_sync_fixture();
    let prepared = Core::prepare_h1_state_sync_bootstrap_v0(config.clone(), proof, &RootSignatures)
        .expect("valid h1 bootstrap")
        .into_safety_state();
    let mut unreachable_successor = prepared.clone();
    unreachable_successor
        .next_revision()
        .expect("construct a self-consistent but unreachable successor revision");

    assert_eq!(
        Core::validate_persisted_state_v0(&config, &unreachable_successor, &RootSignatures,),
        Err(CoreError::InvalidRecovery(
            "anchored h2 pending phase requires exactly one obligation",
        )),
        "storage must not authenticate a revision-only anchored successor",
    );
    assert_eq!(
        Core::validate_persisted_successor_v0(
            &config,
            &prepared,
            &unreachable_successor,
            &RootSignatures,
        ),
        Err(CoreError::InvalidRecovery(
            "anchored h2 pending phase requires exactly one obligation",
        )),
        "the standalone journal must reject the same unreachable successor",
    );
}

fn anchored_successor_bundle_and_replay_v0(
    config: &CoreConfig,
    state: SafetyState,
    h2: SignedProposalV0,
    h3: SignedProposalV0,
) -> StateSyncAnchorSuccessorReplayV0 {
    let bundle = Core::prepare_h1_state_sync_anchor_successor_bundle_v0(
        config,
        &state,
        h2.clone(),
        h3.clone(),
        &RootSignatures,
    )
    .expect("exact h2/h3 carrier");
    let phase = match state.revision() {
        0 => StateSyncAnchorSuccessorPhaseV0::H1Bootstrap,
        1 => StateSyncAnchorSuccessorPhaseV0::H2ValidationPending,
        2 => StateSyncAnchorSuccessorPhaseV0::H2Valid,
        3 => StateSyncAnchorSuccessorPhaseV0::H3ValidationPending,
        4 => StateSyncAnchorSuccessorPhaseV0::H3Valid,
        revision => panic!("test helper cannot recover phase at revision {revision}"),
    };
    let session = Core::begin_state_sync_anchor_successor_recovery_v0(
        config.clone(),
        state.clone(),
        bundle,
        &RootSignatures,
    )
    .expect("stable anchored-successor session");
    let mut reconciler = ExactAnchorSuccessorReconcilerV0 {
        expected_state: state,
        expected_phase: phase,
        expected_child: h2,
        expected_grandchild: h3,
        accept: true,
        calls: 0,
    };
    let replay = session
        .reconcile_and_activate_v0(&mut reconciler)
        .expect("trusted exact application closure");
    assert_eq!(reconciler.calls, 1);
    replay
}

fn seal_anchored_successor_valid_v0(
    replay: &StateSyncAnchorSuccessorReplayV0,
    authority: &CoreIssuedApplicationSealAuthorityV0,
    effects: Vec<Effect>,
) -> ApplicationSealedValidV0 {
    let request = into_validation_request(effects);
    let claimed = request
        .try_claim()
        .unwrap_or_else(|_| panic!("exact successor request is unclaimed"));
    let (_route, _id, block, _parent, permit) = claimed.into_parts();
    authority.seal_after_application_store_commit_v0(
        permit,
        valid_commitments_for_config(replay.config(), &block),
        artifact_ref_for_ids(block.id(), block.header().parent_id()),
    )
}

fn h3_valid_anchor_successor_replay_v0() -> (
    CoreConfig,
    SignedProposalV0,
    SignedProposalV0,
    SignedProposalV0,
    SafetyState,
    StateSyncAnchorSuccessorReplayV0,
) {
    let (config, proof, h1, h2, h3) = h1_state_sync_fixture();
    let initial = Core::prepare_h1_state_sync_bootstrap_v0(config.clone(), proof, &RootSignatures)
        .expect("h1 bootstrap")
        .into_safety_state();
    let mut replay =
        anchored_successor_bundle_and_replay_v0(&config, initial, h2.clone(), h3.clone());
    let authority = replay
        .issue_application_seal_authority_v0()
        .expect("one anchored-successor application authority");
    for expected in [
        StateSyncAnchorSuccessorPhaseV0::H2Valid,
        StateSyncAnchorSuccessorPhaseV0::H3Valid,
    ] {
        let obligation = replay
            .step_next_proposal_v0(&RootSignatures)
            .expect("register exact anchored successor");
        let (obligation_barrier, _) = persistence_effect(&obligation);
        let request = replay
            .step_storage_ack_v0(obligation_barrier, &RootSignatures)
            .expect("ack successor obligation");
        let sealed = seal_anchored_successor_valid_v0(&replay, &authority, request);
        let completion = replay
            .step_application_sealed_valid_v0(&sealed, &RootSignatures)
            .expect("record exact successor Valid result");
        let (completion_barrier, _) = persistence_effect(&completion);
        assert!(replay
            .step_storage_ack_v0(completion_barrier, &RootSignatures)
            .expect("ack successor completion")
            .is_empty());
        assert_eq!(replay.phase().expect("stable successor phase"), expected);
    }
    let revision_four = replay.safety_state().clone();
    (config, h1, h2, h3, revision_four, replay)
}

#[derive(Clone)]
struct AnchoredOrdinaryRehydrateFixtureV0 {
    config: CoreConfig,
    h2: SignedProposalV0,
    h3: SignedProposalV0,
    safety: SafetyState,
    plan: AnchoredOrdinaryReplayArchivePlanV0,
    entries: Vec<AnchoredOrdinarySignedReplayEntryV0>,
}

fn anchored_ordinary_rehydrate_fixture_v0() -> AnchoredOrdinaryRehydrateFixtureV0 {
    let (config, _h1, h2, h3, _revision_four, mut replay) = h3_valid_anchor_successor_replay_v0();
    let promotion = replay
        .step_ordinary_promotion_v0(&RootSignatures)
        .expect("prepare anchored ordinary revision five");
    let (_, revision_five) = persistence_effect(&promotion);
    let set = config.validator_set();
    let parameters = config.consensus_parameters();
    let q3 = revision_five
        .state_sync_anchor()
        .expect("fixture retains permanent h1 anchor")
        .proof()
        .grandchild()
        .certifying_qc()
        .clone();
    let h4 = proposal_with_parameters(set, parameters, q3.clone(), 4, b"rehydrate h4");
    let q4 = qc(set, 4, 4, h4.block().id());
    let h5 = proposal_with_parameters(set, parameters, q4.clone(), 5, b"rehydrate h5");
    let q5 = qc(set, 5, 5, h5.block().id());
    let h4_artifact = artifact_ref_for_ids(h4.block().id(), h3.block().id());
    let h5_artifact = artifact_ref_for_ids(h5.block().id(), h4.block().id());
    let h4_commitments = DurableValidatedBlockCommitmentsV1::from_live(
        valid_commitments_for_config(&config, h4.block()),
    );
    let h5_commitments = DurableValidatedBlockCommitmentsV1::from_live(
        valid_commitments_for_config(&config, h5.block()),
    );
    let h4_source = ValidationId::new(h4.block().id(), h4.block().header().view(), 6);
    let h5_source = ValidationId::new(h5.block().id(), h5.block().header().view(), 8);
    let h4_target = ValidationId::new(h4.block().id(), h4.block().header().view(), 10);
    let h5_target = ValidationId::new(h5.block().id(), h5.block().header().view(), 12);
    let mut completions = revision_five.payload_validation_completions().to_vec();
    completions.extend([
        DurablePayloadValidationCompletionV0::new(
            PayloadValidationRouteV0::Proposal,
            h4_source,
            DurablePayloadValidationResultV1::Valid {
                commitments: h4_commitments,
                artifact_ref: h4_artifact,
            },
            7,
        ),
        DurablePayloadValidationCompletionV0::new(
            PayloadValidationRouteV0::Proposal,
            h5_source,
            DurablePayloadValidationResultV1::Valid {
                commitments: h5_commitments,
                artifact_ref: h5_artifact,
            },
            9,
        ),
        DurablePayloadValidationCompletionV0::new(
            PayloadValidationRouteV0::Synced,
            h4_target,
            DurablePayloadValidationResultV1::Valid {
                commitments: h4_commitments,
                artifact_ref: h4_artifact,
            },
            11,
        ),
        DurablePayloadValidationCompletionV0::new(
            PayloadValidationRouteV0::Synced,
            h5_target,
            DurablePayloadValidationResultV1::Valid {
                commitments: h5_commitments,
                artifact_ref: h5_artifact,
            },
            13,
        ),
    ]);
    completions.sort_by_key(DurablePayloadValidationCompletionV0::key);
    let mut terminal_facts = revision_five.payload_terminal_facts().to_vec();
    terminal_facts.extend([
        PayloadTerminalFact::new_valid(h4_artifact.overlay(), 7),
        PayloadTerminalFact::new_valid(h5_artifact.overlay(), 9),
    ]);
    terminal_facts.sort_by_key(|fact| fact.block_id());

    let certified_h3 = CertifiedHeaderV0::from_signed_proposal(
        h3.clone(),
        q3,
        set,
        None,
        parameters,
        h2.block().header().timestamp_ms(),
    )
    .expect("certify replay h3");
    let certified_h4 = CertifiedHeaderV0::from_signed_proposal(
        h4.clone(),
        q4.clone(),
        set,
        None,
        parameters,
        h3.block().header().timestamp_ms(),
    )
    .expect("certify replay h4");
    let certified_h5 = CertifiedHeaderV0::from_signed_proposal(
        h5.clone(),
        q5.clone(),
        set,
        None,
        parameters,
        h4.block().header().timestamp_ms(),
    )
    .expect("certify replay h5");
    let finality_proof = FinalityProofV0::new(
        certified_h3,
        certified_h4,
        certified_h5,
        set,
        None,
        parameters,
        h2.block().header().timestamp_ms(),
    )
    .expect("construct replay h3 finality proof");
    let h2_tip = FinalizedTip::new(
        h2.block().header().height(),
        h2.block().header().view(),
        h2.block().id(),
        h2.block().header().timestamp_ms(),
    );
    let h3_tip = FinalizedTip::new(
        h3.block().header().height(),
        h3.block().header().view(),
        h3.block().id(),
        h3.block().header().timestamp_ms(),
    );
    let finalization = DurableFinalizationV0::new(
        h2_tip,
        finality_proof,
        revision_five
            .payload_terminal_fact(h3.block().id())
            .and_then(PayloadTerminalFact::valid_overlay)
            .expect("anchored h3 has a permanent Valid overlay"),
    )
    .expect("construct exact replay finalization");
    let safety = SafetyState::from_persisted_parts_v13(
        revision_five.schema_version(),
        revision_five.chain_id(),
        revision_five.protocol_version(),
        revision_five.epoch(),
        revision_five.validator_set_id(),
        revision_five.genesis_block_id(),
        revision_five
            .authenticated_genesis_application_parent_v0()
            .copied(),
        View::new(6),
        revision_five.last_voted_view(),
        revision_five.last_timeout_view(),
        QcReferenceV0::ordinary(q5.clone()),
        QcReferenceV0::ordinary(q4.clone()),
        h3_tip,
        13,
        revision_five.durable_observed_qcs().to_vec(),
        terminal_facts,
        Vec::new(),
        completions,
        None,
        None,
        None,
        Some(finalization),
        revision_five.state_sync_anchor().cloned(),
        h3_tip,
        Vec::new(),
        None,
        None,
    );
    Core::validate_persisted_state_v0(&config, &safety, &RootSignatures)
        .expect("synthetic checkpointed ordinary cut is a valid durable Core state");

    let plan = AnchoredOrdinaryReplayArchivePlanV0::new(
        [0x10; 32], [0x11; 32], [0x12; 32], 4, [0x13; 32], [0x14; 32], [0x15; 32], 2, 100,
        [0x16; 32], 9, [0x17; 32], [0x18; 32], [0x19; 32], [0x1a; 32], 20, [0x1b; 32], [0x1c; 32],
        [0x1e; 32], [0x1f; 32],
    )
    .expect("valid replay archive plan");
    let h4_claim = AnchoredOrdinaryCheckpointedLinkClaimV0::new(
        plan.session_id_v0(),
        0,
        [0x20; 32],
        [0x30; 32],
        h4_target,
        [0x40; 32],
        plan.canonical_store_sequence_v0(),
        4,
        [0x41; 32],
        h4_artifact.source_artifact_checksum(),
        [0x42; 32],
        11,
        [0x43; 32],
        plan.initial_checkpoint_scope_v0(),
        plan.initial_checkpoint_profile_ref_v0(),
        plan.initial_checkpoint_checksum_v0(),
        21,
        [0x44; 32],
        plan.initial_progress_checksum_v0(),
        [0x1d; 32],
        5,
        [0x45; 32],
    )
    .expect("valid h4 checkpointed link claim");
    let h5_claim = AnchoredOrdinaryCheckpointedLinkClaimV0::new(
        plan.session_id_v0(),
        1,
        [0x21; 32],
        [0x31; 32],
        h5_target,
        [0x40; 32],
        plan.canonical_store_sequence_v0(),
        8,
        [0x46; 32],
        h5_artifact.source_artifact_checksum(),
        [0x47; 32],
        13,
        [0x48; 32],
        plan.initial_checkpoint_scope_v0(),
        plan.initial_checkpoint_profile_ref_v0(),
        [0x44; 32],
        22,
        [0x49; 32],
        [0x1d; 32],
        plan.final_progress_checksum_v0(),
        10,
        [0x4a; 32],
    )
    .expect("valid h5 checkpointed link claim");
    AnchoredOrdinaryRehydrateFixtureV0 {
        config,
        h2,
        h3,
        safety,
        plan,
        entries: vec![
            AnchoredOrdinarySignedReplayEntryV0::new(h4, q4, h4_claim),
            AnchoredOrdinarySignedReplayEntryV0::new(h5, q5, h5_claim),
        ],
    }
}

fn begin_anchored_ordinary_rehydrate_v0(
    fixture: &AnchoredOrdinaryRehydrateFixtureV0,
    plan: AnchoredOrdinaryReplayArchivePlanV0,
    entries: Vec<AnchoredOrdinarySignedReplayEntryV0>,
) -> Result<AnchoredOrdinaryRehydrateSessionV0> {
    let bundle = Core::prepare_h1_state_sync_anchor_successor_bundle_v0(
        &fixture.config,
        &fixture.safety,
        fixture.h2.clone(),
        fixture.h3.clone(),
        &RootSignatures,
    )?;
    let session = Core::begin_state_sync_anchor_ordinary_recovery_v0(
        fixture.config.clone(),
        fixture.safety.clone(),
        bundle,
        &RootSignatures,
    )?;
    let mut reconciler = ExactAnchorOrdinaryReconcilerV0 {
        expected_state: fixture.safety.clone(),
        expected_child: fixture.h2.clone(),
        expected_grandchild: fixture.h3.clone(),
        accept: true,
        calls: 0,
    };
    let result = session.begin_checkpointed_ordinary_rehydrate_v0(
        &mut reconciler,
        plan,
        entries,
        &RootSignatures,
    );
    assert_eq!(reconciler.calls, 1);
    result
}

fn reconcile_anchored_ordinary_rehydrate_v0(
    fixture: &AnchoredOrdinaryRehydrateFixtureV0,
) -> AnchoredOrdinaryRehydratedOwnerV0 {
    let session =
        begin_anchored_ordinary_rehydrate_v0(fixture, fixture.plan, fixture.entries.clone())
            .expect("Core authenticates the complete checkpointed replay prefix");
    let mut reconciler = ExactCheckpointedOrdinaryRehydrateReconcilerV0 {
        expected_state: fixture.safety.clone(),
        expected_plan: fixture.plan,
        expected_entries: fixture.entries.clone(),
        accept: true,
        calls: 0,
    };
    let owner = session
        .reconcile_checkpointed_links_v0(&mut reconciler)
        .expect("trusted store owners join every checkpointed replay link");
    assert_eq!(reconciler.calls, 1);
    owner
}

#[allow(clippy::too_many_arguments)]
fn rebuild_checkpointed_claim_v0(
    source: AnchoredOrdinaryCheckpointedLinkClaimV0,
    cursor: u64,
    source_row_checksum: [u8; 32],
    source_artifact_checksum: [u8; 32],
    source_history_checksum: [u8; 32],
    checkpoint_predecessor_checksum: [u8; 32],
    checkpoint_checksum: [u8; 32],
    previous_progress_checksum: [u8; 32],
    progress_checksum: [u8; 32],
) -> AnchoredOrdinaryCheckpointedLinkClaimV0 {
    AnchoredOrdinaryCheckpointedLinkClaimV0::new(
        source.session_id_v0(),
        cursor,
        source.source_validation_store_id_v0(),
        source.target_validation_store_id_v0(),
        source.target_core_validation_id_v0(),
        source.owner_id_v0(),
        source.source_store_sequence_v0(),
        source.source_row_revision_v0(),
        source_row_checksum,
        source_artifact_checksum,
        source_history_checksum,
        source.safety_revision_v0(),
        source.alias_closure_checksum_v0(),
        source.checkpoint_scope_v0(),
        source.checkpoint_profile_ref_v0(),
        checkpoint_predecessor_checksum,
        source.checkpoint_generation_v0(),
        checkpoint_checksum,
        previous_progress_checksum,
        progress_checksum,
        source.link_row_revision_v0(),
        source.link_row_checksum_v0(),
    )
    .expect("mutated test claim remains structurally constructible")
}

#[test]
fn anchored_ordinary_bulk_rehydrate_is_exact_replay_fenced_and_repeatable_v0() {
    let fixture = anchored_ordinary_rehydrate_fixture_v0();
    let session =
        begin_anchored_ordinary_rehydrate_v0(&fixture, fixture.plan, fixture.entries.clone())
            .expect("Core authenticates the complete checkpointed replay prefix");
    let first_digest = session.challenge_v0().rehydrate_digest_v0();
    let mut reconciler = ExactCheckpointedOrdinaryRehydrateReconcilerV0 {
        expected_state: fixture.safety.clone(),
        expected_plan: fixture.plan,
        expected_entries: fixture.entries.clone(),
        accept: true,
        calls: 0,
    };
    let owner = session
        .reconcile_checkpointed_links_v0(&mut reconciler)
        .expect("trusted store owners join every checkpointed link");
    assert_eq!(reconciler.calls, 1);
    let facts = owner.facts_v0();
    assert_eq!(facts.safety_revision_v0(), fixture.safety.revision());
    assert_eq!(facts.replayed_link_count_v0(), 2);
    assert_eq!(facts.finalized_v0(), fixture.safety.finalized());
    assert_eq!(facts.high_qc_v0(), fixture.safety.high_qc().qc_ref());
    assert_eq!(facts.locked_qc_v0(), fixture.safety.locked_qc().qc_ref());
    assert_eq!(facts.rehydrate_digest_v0(), first_digest);
    assert_eq!(
        owner.challenge_v0().entries_v0(),
        fixture.entries.as_slice()
    );

    let reopened =
        begin_anchored_ordinary_rehydrate_v0(&fixture, fixture.plan, fixture.entries.clone())
            .expect("process3 may repeat exact deterministic rehydration");
    assert_eq!(reopened.challenge_v0().rehydrate_digest_v0(), first_digest);
    let mut reopened_reconciler = ExactCheckpointedOrdinaryRehydrateReconcilerV0 {
        expected_state: fixture.safety.clone(),
        expected_plan: fixture.plan,
        expected_entries: fixture.entries.clone(),
        accept: true,
        calls: 0,
    };
    let reopened_owner = reopened
        .reconcile_checkpointed_links_v0(&mut reopened_reconciler)
        .expect("same durable owners can authenticate an exact reopen");
    assert_eq!(reopened_reconciler.calls, 1);
    assert_eq!(reopened_owner.facts_v0(), facts);
}

#[test]
fn anchored_ordinary_activation_consumes_replay_fence_and_releases_one_exact_timer_v0() {
    let fixture = anchored_ordinary_rehydrate_fixture_v0();
    let owner = reconcile_anchored_ordinary_rehydrate_v0(&fixture);
    let rehydrated_facts = owner.facts_v0();
    let activation = owner
        .reconcile_and_activate_checkpointed_ordinary_v0(&RootSignatures)
        .expect("exact checkpointed owner clears only its Core replay fence");
    assert_eq!(activation.facts_v0(), rehydrated_facts);
    assert_eq!(
        activation.startup_timer_v0().epoch_v0(),
        fixture.safety.epoch()
    );
    assert_eq!(
        activation.startup_timer_v0().view_v0(),
        fixture.safety.current_view()
    );

    let (mut core, timer) = activation.into_parts_v0();
    assert_eq!(core.safety_state(), &fixture.safety);
    assert!(matches!(
        timer.into_effect_v0(),
        Effect::ArmViewTimer { epoch, view }
            if epoch == fixture.safety.epoch() && view == fixture.safety.current_view()
    ));
    assert!(matches!(
        core.step(Input::Resume, &RootSignatures)
            .expect("activated Core no longer requests replay")
            .as_slice(),
        [Effect::ArmViewTimer { epoch, view }]
            if *epoch == fixture.safety.epoch() && *view == fixture.safety.current_view()
    ));
}

#[test]
fn anchored_ordinary_activation_rejects_zero_multiple_and_mismatched_timers_v0() {
    let fixture = anchored_ordinary_rehydrate_fixture_v0();
    let activation = reconcile_anchored_ordinary_rehydrate_v0(&fixture)
        .reconcile_and_activate_checkpointed_ordinary_v0(&RootSignatures)
        .expect("fixture reaches the exact activated Core cut");
    let (core, _timer) = activation.into_parts_v0();
    let epoch = fixture.safety.epoch();
    let view = fixture.safety.current_view();

    assert!(matches!(
        crate::core::exact_anchored_ordinary_replay_complete_timer_v0(&core, Vec::new()),
        Err(CoreError::AnchoredOrdinaryRehydrateRejected(_))
    ));
    assert!(matches!(
        crate::core::exact_anchored_ordinary_replay_complete_timer_v0(
            &core,
            vec![
                Effect::ArmViewTimer { epoch, view },
                Effect::ArmViewTimer { epoch, view },
            ],
        ),
        Err(CoreError::AnchoredOrdinaryRehydrateRejected(_))
    ));
    assert!(matches!(
        crate::core::exact_anchored_ordinary_replay_complete_timer_v0(
            &core,
            vec![Effect::ArmViewTimer {
                epoch,
                view: View::new(view.get() + 1),
            }],
        ),
        Err(CoreError::AnchoredOrdinaryRehydrateRejected(_))
    ));
}

#[test]
fn anchored_ordinary_bulk_rehydrate_rejects_order_gap_fork_and_signed_substitution_v0() {
    let fixture = anchored_ordinary_rehydrate_fixture_v0();

    let mut reversed = fixture.entries.clone();
    reversed.swap(0, 1);
    assert!(begin_anchored_ordinary_rehydrate_v0(&fixture, fixture.plan, reversed).is_err());

    let mut cursor_gap = fixture.entries.clone();
    let entry = cursor_gap[1].clone();
    let claim = entry.checkpointed_link_v0();
    let gap_claim = rebuild_checkpointed_claim_v0(
        claim,
        2,
        claim.source_row_checksum_v0(),
        claim.source_artifact_checksum_v0(),
        claim.source_application_history_checksum_v0(),
        claim.checkpoint_predecessor_checksum_v0(),
        claim.checkpoint_checksum_v0(),
        claim.previous_progress_checksum_v0(),
        claim.progress_checksum_v0(),
    );
    cursor_gap[1] = AnchoredOrdinarySignedReplayEntryV0::new(
        entry.proposal_v0().clone(),
        entry.certifying_qc_v0().clone(),
        gap_claim,
    );
    assert!(begin_anchored_ordinary_rehydrate_v0(&fixture, fixture.plan, cursor_gap).is_err());

    let q3 = fixture.entries[0]
        .proposal_v0()
        .witness()
        .justify_qc()
        .as_ordinary()
        .expect("h4 carries q3")
        .clone();
    let fork = proposal_with_parameters(
        fixture.config.validator_set(),
        fixture.config.consensus_parameters(),
        q3,
        4,
        b"forked replay h4",
    );
    let fork_qc = qc(fixture.config.validator_set(), 4, 4, fork.block().id());
    let mut forked = fixture.entries.clone();
    forked[1] =
        AnchoredOrdinarySignedReplayEntryV0::new(fork, fork_qc, forked[1].checkpointed_link_v0());
    assert!(begin_anchored_ordinary_rehydrate_v0(&fixture, fixture.plan, forked).is_err());

    let mut proposal_substitution = fixture.entries.clone();
    proposal_substitution[0] = AnchoredOrdinarySignedReplayEntryV0::new(
        fixture.entries[1].proposal_v0().clone(),
        fixture.entries[0].certifying_qc_v0().clone(),
        fixture.entries[0].checkpointed_link_v0(),
    );
    assert!(
        begin_anchored_ordinary_rehydrate_v0(&fixture, fixture.plan, proposal_substitution,)
            .is_err()
    );

    let mut qc_substitution = fixture.entries.clone();
    qc_substitution[0] = AnchoredOrdinarySignedReplayEntryV0::new(
        fixture.entries[0].proposal_v0().clone(),
        fixture.entries[1].certifying_qc_v0().clone(),
        fixture.entries[0].checkpointed_link_v0(),
    );
    assert!(
        begin_anchored_ordinary_rehydrate_v0(&fixture, fixture.plan, qc_substitution,).is_err()
    );

    let h3_timestamp = fixture.h3.block().header().timestamp_ms();
    let substituted_timestamp = h3_timestamp
        .checked_add(fixture.config.max_block_time_step_ms())
        .and_then(|value| value.checked_add(1))
        .expect("test timestamp remains bounded");
    let wrong_time_block = block_with_timestamp(
        fixture.config.validator_set(),
        4,
        4,
        fixture.h3.block().id(),
        b"wrong parent timestamp replay",
        leader_for(fixture.config.validator_set(), View::new(4)),
        substituted_timestamp,
    );
    let wrong_time_proposal = signed_proposal_from_block(
        fixture.config.validator_set(),
        fixture.config.consensus_parameters(),
        wrong_time_block,
        fixture.entries[0]
            .proposal_v0()
            .witness()
            .justify_qc()
            .clone(),
        None,
        substituted_timestamp - 1,
    )
    .expect("proposal is valid only under the substituted parent timestamp");
    let wrong_time_qc = qc(
        fixture.config.validator_set(),
        4,
        4,
        wrong_time_proposal.block().id(),
    );
    let mut wrong_timestamp = fixture.entries.clone();
    wrong_timestamp[0] = AnchoredOrdinarySignedReplayEntryV0::new(
        wrong_time_proposal,
        wrong_time_qc,
        fixture.entries[0].checkpointed_link_v0(),
    );
    assert!(
        begin_anchored_ordinary_rehydrate_v0(&fixture, fixture.plan, wrong_timestamp,).is_err()
    );
}

#[test]
fn anchored_ordinary_bulk_rehydrate_rejects_artifact_checkpoint_and_terminal_cut_v0() {
    let fixture = anchored_ordinary_rehydrate_fixture_v0();

    let mut artifact = fixture.entries.clone();
    let entry = artifact[0].clone();
    let claim = entry.checkpointed_link_v0();
    let artifact_claim = rebuild_checkpointed_claim_v0(
        claim,
        claim.cursor_v0(),
        claim.source_row_checksum_v0(),
        [0x91; 32],
        claim.source_application_history_checksum_v0(),
        claim.checkpoint_predecessor_checksum_v0(),
        claim.checkpoint_checksum_v0(),
        claim.previous_progress_checksum_v0(),
        claim.progress_checksum_v0(),
    );
    artifact[0] = AnchoredOrdinarySignedReplayEntryV0::new(
        entry.proposal_v0().clone(),
        entry.certifying_qc_v0().clone(),
        artifact_claim,
    );
    assert!(begin_anchored_ordinary_rehydrate_v0(&fixture, fixture.plan, artifact).is_err());

    let mut checkpoint = fixture.entries.clone();
    let entry = checkpoint[0].clone();
    let claim = entry.checkpointed_link_v0();
    let checkpoint_claim = rebuild_checkpointed_claim_v0(
        claim,
        claim.cursor_v0(),
        claim.source_row_checksum_v0(),
        claim.source_artifact_checksum_v0(),
        claim.source_application_history_checksum_v0(),
        claim.checkpoint_predecessor_checksum_v0(),
        [0x92; 32],
        claim.previous_progress_checksum_v0(),
        claim.progress_checksum_v0(),
    );
    checkpoint[0] = AnchoredOrdinarySignedReplayEntryV0::new(
        entry.proposal_v0().clone(),
        entry.certifying_qc_v0().clone(),
        checkpoint_claim,
    );
    assert!(begin_anchored_ordinary_rehydrate_v0(&fixture, fixture.plan, checkpoint).is_err());

    let terminal_plan = AnchoredOrdinaryReplayArchivePlanV0::new(
        fixture.plan.core_config_ref_v0(),
        fixture.plan.recovery_challenge_digest_v0(),
        fixture.plan.archive_context_digest_v0(),
        fixture.plan.archive_sequence_v0(),
        fixture.plan.archive_record_digest_v0(),
        fixture.plan.session_id_v0(),
        fixture.plan.validation_store_id_v0(),
        fixture.plan.expected_link_count_v0(),
        fixture.plan.canonical_store_sequence_v0(),
        fixture.plan.application_history_digest_v0(),
        fixture.plan.initial_safety_revision_v0(),
        fixture.plan.initial_safety_state_checksum_v0(),
        fixture.plan.initial_safety_chain_checksum_v0(),
        fixture.plan.initial_checkpoint_scope_v0(),
        fixture.plan.initial_checkpoint_profile_ref_v0(),
        fixture.plan.initial_checkpoint_generation_v0(),
        fixture.plan.initial_checkpoint_checksum_v0(),
        fixture.plan.initial_progress_checksum_v0(),
        [0x93; 32],
        fixture.plan.durable_session_row_checksum_v0(),
    )
    .expect("terminal-cut substitution remains shape-valid");
    assert!(
        begin_anchored_ordinary_rehydrate_v0(&fixture, terminal_plan, fixture.entries.clone(),)
            .is_err()
    );
}

#[test]
fn anchored_ordinary_bulk_rehydrate_requires_live_source_k_and_history_join_v0() {
    let fixture = anchored_ordinary_rehydrate_fixture_v0();
    for (source_row_checksum, history_checksum) in
        [([0x94; 32], None), ([0x41; 32], Some([0x95; 32]))]
    {
        let mut entries = fixture.entries.clone();
        let entry = entries[0].clone();
        let claim = entry.checkpointed_link_v0();
        let mutated = rebuild_checkpointed_claim_v0(
            claim,
            claim.cursor_v0(),
            source_row_checksum,
            claim.source_artifact_checksum_v0(),
            history_checksum.unwrap_or(claim.source_application_history_checksum_v0()),
            claim.checkpoint_predecessor_checksum_v0(),
            claim.checkpoint_checksum_v0(),
            claim.previous_progress_checksum_v0(),
            claim.progress_checksum_v0(),
        );
        entries[0] = AnchoredOrdinarySignedReplayEntryV0::new(
            entry.proposal_v0().clone(),
            entry.certifying_qc_v0().clone(),
            mutated,
        );
        let session = begin_anchored_ordinary_rehydrate_v0(&fixture, fixture.plan, entries)
            .expect("opaque source facts remain untrusted until host reconciliation");
        let mut exact = ExactCheckpointedOrdinaryRehydrateReconcilerV0 {
            expected_state: fixture.safety.clone(),
            expected_plan: fixture.plan,
            expected_entries: fixture.entries.clone(),
            accept: true,
            calls: 0,
        };
        assert!(matches!(
            session.reconcile_checkpointed_links_v0(&mut exact),
            Err(CoreError::AnchoredOrdinaryRehydrateRejected(_))
        ));
        assert_eq!(exact.calls, 1);
    }
}

#[test]
fn application_sealed_valid_to_delivery_returns_only_the_affined_core_d_carrier_v0() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(&set, genesis_qc(&set), 1, b"core D authority");
    let authority = core
        .issue_application_seal_authority_v0()
        .expect("one application authority");
    let obligation = core
        .step(Input::Proposal(Box::new(proposed.clone())), &RootSignatures)
        .expect("proposal registers one obligation");
    let (obligation_barrier, _) = persistence_effect(&obligation);
    let released = core
        .step(
            Input::StorageAck {
                barrier: obligation_barrier,
            },
            &RootSignatures,
        )
        .expect("obligation persistence releases validation");
    let request = into_validation_request(released);
    let claimed = request.try_claim().expect("claim exact request");
    let (route, id, block, _parent, permit) = claimed.into_parts();
    let proof = authority.seal_after_application_store_commit_v0(
        permit,
        valid_commitments_for_config(core.config(), &block),
        artifact_ref_for_ids(block.id(), block.header().parent_id()),
    );

    let accepted = core
        .step_application_sealed_valid_to_delivery_v0(&proof, &RootSignatures)
        .expect("Core mints one D authority");
    assert_eq!(accepted.route_v0(), route);
    assert_eq!(accepted.validation_id_v0(), id);
    assert_eq!(accepted.completion_revision_v0(), 2);
    assert_eq!(accepted.barrier_v0().get(), 2);
    assert_eq!(
        accepted.persistence_request_v0().state(),
        core.safety_state()
    );
    assert_ne!(accepted.valid_result_checksum_v0(), [0; 32]);
    assert_ne!(accepted.delivery_digest_v0(), [0; 32]);
    assert_eq!(
        accepted
            .persistence_request_v0()
            .native_valid_post_ack_action_v0(),
        Some(NativeValidPostAckActionV0::RequestSignature),
        "the vote intent is durable but no RequestSignature effect is released before Safety ACK",
    );
    assert!(core.safety_state().pending_sign().is_some());
    assert!(matches!(
        core.step_application_sealed_valid_to_delivery_v0(&proof, &RootSignatures),
        Err(CoreError::UnknownValidation(id_block)) if id_block == block.id()
    ));
}

#[test]
fn h1_anchor_successor_replay_closes_exact_h2_h3_without_side_effects_v0() {
    let (config, proof, h1, h2, h3) = h1_state_sync_fixture();
    let initial = Core::prepare_h1_state_sync_bootstrap_v0(config.clone(), proof, &RootSignatures)
        .expect("h1 bootstrap")
        .into_safety_state();
    let mut replay =
        anchored_successor_bundle_and_replay_v0(&config, initial.clone(), h2.clone(), h3.clone());
    assert_eq!(
        replay.phase().expect("phase"),
        StateSyncAnchorSuccessorPhaseV0::H1Bootstrap
    );
    let authority = replay
        .issue_application_seal_authority_v0()
        .expect("one test application authority");

    let h2_persist = replay
        .step_next_proposal_v0(&RootSignatures)
        .expect("exact h2 registers");
    let (h2_obligation_barrier, h2_obligation_state) = persistence_effect(&h2_persist);
    assert_eq!(h2_obligation_state.revision(), 1);
    assert_eq!(
        h2_obligation_state.payload_validation_obligations().len(),
        1
    );
    assert!(h2_obligation_state
        .payload_validation_completions()
        .is_empty());
    assert_safety_state_record_roundtrip_and_validate(&config, &h2_obligation_state);
    let mut recovered_h2 = anchored_successor_bundle_and_replay_v0(
        &config,
        h2_obligation_state.clone(),
        h2.clone(),
        h3.clone(),
    );
    assert_eq!(
        recovered_h2.phase().expect("recovered rev1 phase"),
        StateSyncAnchorSuccessorPhaseV0::H2ValidationPending
    );
    let replayed_h2_obligation = recovered_h2
        .pending_obligation_persistence_v0()
        .expect("rev1 recovery retains the exact persistence owner");
    assert_eq!(replayed_h2_obligation.state(), &h2_obligation_state);
    assert_eq!(replayed_h2_obligation.barrier(), h2_obligation_barrier);
    let recovered_h2_authority = recovered_h2
        .issue_application_seal_authority_v0()
        .expect("recovered rev1 application authority");
    let recovered_h2_request = recovered_h2
        .step_storage_ack_v0(h2_obligation_barrier, &RootSignatures)
        .expect("rev1 exact barrier remints the sole h2 request");
    let recovered_h2_sealed = seal_anchored_successor_valid_v0(
        &recovered_h2,
        &recovered_h2_authority,
        recovered_h2_request,
    );
    let recovered_h2_completion = recovered_h2
        .step_application_sealed_valid_v0(&recovered_h2_sealed, &RootSignatures)
        .expect("recovered rev1 request closes h2");
    let (recovered_h2_barrier, recovered_h2_state) = persistence_effect(&recovered_h2_completion);
    assert_eq!(recovered_h2_barrier, BarrierId::new(2));
    assert_eq!(recovered_h2_state.revision(), 2);
    let h2_request = replay
        .step_storage_ack_v0(h2_obligation_barrier, &RootSignatures)
        .expect("h2 obligation persistence acknowledged");
    let h2_sealed = seal_anchored_successor_valid_v0(&replay, &authority, h2_request);
    let h2_valid_persist = replay
        .step_application_sealed_valid_v0(&h2_sealed, &RootSignatures)
        .expect("opaque h2 Valid accepted");
    let (h2_valid_barrier, h2_valid_state) = persistence_effect(&h2_valid_persist);
    assert_eq!(h2_valid_state.revision(), 2);
    assert!(h2_valid_state.payload_validation_obligations().is_empty());
    assert_eq!(h2_valid_state.payload_validation_completions().len(), 1);
    assert_eq!(h2_valid_state.payload_terminal_facts().len(), 1);
    assert!(h2_valid_state
        .payload_terminal_fact(h1.block().id())
        .is_none());
    assert_safety_state_record_roundtrip_and_validate(&config, &h2_valid_state);
    assert!(replay
        .step_storage_ack_v0(h2_valid_barrier, &RootSignatures)
        .expect("h2 completion persistence acknowledged")
        .is_empty());

    let h3_persist = replay
        .step_next_proposal_v0(&RootSignatures)
        .expect("exact h3 registers");
    let (h3_obligation_barrier, h3_obligation_state) = persistence_effect(&h3_persist);
    assert_eq!(h3_obligation_state.revision(), 3);
    assert_eq!(
        h3_obligation_state.payload_validation_obligations().len(),
        1
    );
    assert_eq!(
        h3_obligation_state.payload_validation_completions().len(),
        1
    );
    assert_safety_state_record_roundtrip_and_validate(&config, &h3_obligation_state);
    let mut recovered_h3 = anchored_successor_bundle_and_replay_v0(
        &config,
        h3_obligation_state.clone(),
        h2.clone(),
        h3.clone(),
    );
    assert_eq!(
        recovered_h3.phase().expect("recovered rev3 phase"),
        StateSyncAnchorSuccessorPhaseV0::H3ValidationPending
    );
    let replayed_h3_obligation = recovered_h3
        .pending_obligation_persistence_v0()
        .expect("rev3 recovery retains the exact persistence owner");
    assert_eq!(replayed_h3_obligation.state(), &h3_obligation_state);
    assert_eq!(replayed_h3_obligation.barrier(), h3_obligation_barrier);
    let recovered_h3_authority = recovered_h3
        .issue_application_seal_authority_v0()
        .expect("recovered rev3 application authority");
    let recovered_h3_request = recovered_h3
        .step_storage_ack_v0(h3_obligation_barrier, &RootSignatures)
        .expect("rev3 exact barrier remints the sole h3 request");
    let recovered_h3_sealed = seal_anchored_successor_valid_v0(
        &recovered_h3,
        &recovered_h3_authority,
        recovered_h3_request,
    );
    let recovered_h3_completion = recovered_h3
        .step_application_sealed_valid_v0(&recovered_h3_sealed, &RootSignatures)
        .expect("recovered rev3 request closes h3");
    let (recovered_h3_barrier, recovered_h3_state) = persistence_effect(&recovered_h3_completion);
    assert_eq!(recovered_h3_barrier, BarrierId::new(4));
    assert_eq!(recovered_h3_state.revision(), 4);
    let h3_request = replay
        .step_storage_ack_v0(h3_obligation_barrier, &RootSignatures)
        .expect("h3 obligation persistence acknowledged");
    let h3_sealed = seal_anchored_successor_valid_v0(&replay, &authority, h3_request);
    let h3_valid_persist = replay
        .step_application_sealed_valid_v0(&h3_sealed, &RootSignatures)
        .expect("opaque h3 Valid accepted");
    let (h3_valid_barrier, h3_valid_state) = persistence_effect(&h3_valid_persist);
    assert_eq!(h3_valid_state.revision(), 4);
    assert!(h3_valid_state.payload_validation_obligations().is_empty());
    assert_eq!(h3_valid_state.payload_validation_completions().len(), 2);
    assert_eq!(h3_valid_state.payload_terminal_facts().len(), 2);
    assert!(h3_valid_state
        .payload_terminal_fact(h1.block().id())
        .is_none());
    assert_safety_state_record_roundtrip_and_validate(&config, &h3_valid_state);
    assert!(replay
        .step_storage_ack_v0(h3_valid_barrier, &RootSignatures)
        .expect("h3 completion persistence acknowledged")
        .is_empty());
    assert_eq!(
        replay.phase().expect("closed phase"),
        StateSyncAnchorSuccessorPhaseV0::H3Valid
    );

    let reopened = anchored_successor_bundle_and_replay_v0(&config, h3_valid_state, h2, h3);
    assert_eq!(
        reopened.phase().expect("reopened closed phase"),
        StateSyncAnchorSuccessorPhaseV0::H3Valid
    );
    assert_eq!(
        reopened.safety_state().finalized().block_id(),
        h1.block().id()
    );
    assert_eq!(
        reopened.safety_state().application_applied(),
        initial.application_applied()
    );
    assert!(reopened.safety_state().pending_sign().is_none());
    assert!(reopened.safety_state().pending_finalize().is_none());
    assert!(reopened.safety_state().finalization_queue().is_empty());
}

#[test]
fn h3_valid_anchor_promotion_is_one_exact_persistence_ack_before_generic_core_v0() {
    let (config, _h1, _h2, _h3, revision_four, mut replay) = h3_valid_anchor_successor_replay_v0();
    let effects = replay
        .step_ordinary_promotion_v0(&RootSignatures)
        .expect("H3Valid crosses the explicit promotion persistence barrier");
    let request = match effects.as_slice() {
        [Effect::PersistSafetyState(request)] => request,
        other => panic!("promotion produced unexpected effects: {other:?}"),
    };
    let manifest = request
        .state_sync_anchor_ordinary_promotion_v0()
        .expect("promotion request carries its Core-owned manifest");
    assert_eq!(request.barrier(), BarrierId::new(5));
    assert_eq!(manifest.transition_revision(), 5);
    assert_eq!(
        manifest.anchor_proof_id(),
        revision_four
            .state_sync_anchor()
            .expect("permanent h1 anchor")
            .proof_id()
    );
    assert!(request.native_valid_post_ack_action_v0().is_none());
    assert!(request.native_finalization_applied_v0().is_none());
    let expected_revision_five = anchored_state_with_validation_parts_v0(
        &revision_four,
        5,
        revision_four.payload_validation_obligations().to_vec(),
        revision_four.payload_validation_completions().to_vec(),
        revision_four.payload_terminal_facts().to_vec(),
    );
    assert_eq!(request.state(), &expected_revision_five);
    assert_eq!(replay.safety_state(), &expected_revision_five);
    Core::validate_persisted_successor_v0(
        &config,
        &revision_four,
        &expected_revision_five,
        &RootSignatures,
    )
    .expect("the exact revision-four to revision-five promotion is monotonic");

    let activation = replay
        .acknowledge_ordinary_promotion_v0(request.barrier(), &RootSignatures)
        .expect("the exact durable barrier releases generic Core");
    assert!(matches!(
        activation.effects(),
        [Effect::ArmViewTimer { epoch, view }]
            if *epoch == expected_revision_five.epoch()
                && *view == expected_revision_five.current_view()
    ));
    let (mut core, _) = activation.into_parts_v0();
    assert!(matches!(
        core.step(Input::Resume, &RootSignatures)
            .expect("promoted Resume is ordinary"),
        effects if matches!(effects.as_slice(), [Effect::ArmViewTimer { .. }])
    ));

    let q3 = expected_revision_five
        .state_sync_anchor()
        .expect("permanent anchor")
        .proof()
        .grandchild()
        .certifying_qc()
        .clone();
    let h4 = proposal_with_parameters(
        config.validator_set(),
        config.consensus_parameters(),
        q3,
        4,
        b"ordinary promoted h4",
    );
    let ordinary = core
        .step(Input::Proposal(Box::new(h4)), &RootSignatures)
        .expect("promoted Core accepts an ordinary proposal");
    assert!(matches!(
        ordinary.as_slice(),
        [Effect::PersistSafetyState(request)]
            if request.state().revision() == 6
                && request.state_sync_anchor_ordinary_promotion_v0().is_none()
    ));
}

#[test]
fn anchor_promotion_rejects_pre_h3_and_recovers_exact_committed_rev5_v0() {
    let (config, proof, _h1, h2, h3) = h1_state_sync_fixture();
    let initial = Core::prepare_h1_state_sync_bootstrap_v0(config.clone(), proof, &RootSignatures)
        .expect("h1 bootstrap")
        .into_safety_state();
    let mut early =
        anchored_successor_bundle_and_replay_v0(&config, initial, h2.clone(), h3.clone());
    assert!(matches!(
        early.step_ordinary_promotion_v0(&RootSignatures),
        Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(_))
    ));

    let (config, _h1, h2, h3, revision_four, mut replay) = h3_valid_anchor_successor_replay_v0();
    let promotion = replay
        .step_ordinary_promotion_v0(&RootSignatures)
        .expect("prepare committed rev5 crash cut");
    let (barrier, revision_five) = persistence_effect(&promotion);
    assert_eq!(barrier, BarrierId::new(5));
    assert!(Core::recover(config.clone(), revision_five.clone(), &RootSignatures,).is_err());
    let bundle = Core::prepare_h1_state_sync_anchor_successor_bundle_v0(
        &config,
        &revision_five,
        h2.clone(),
        h3.clone(),
        &RootSignatures,
    )
    .expect("authenticate exact proof-named bodies at promoted cut");
    let session = Core::begin_state_sync_anchor_ordinary_recovery_v0(
        config.clone(),
        revision_five.clone(),
        bundle,
        &RootSignatures,
    )
    .expect("begin promoted restart recovery");
    let mut reconciler = ExactAnchorOrdinaryReconcilerV0 {
        expected_state: revision_five.clone(),
        expected_child: h2,
        expected_grandchild: h3,
        accept: true,
        calls: 0,
    };
    let activation = session
        .reconcile_and_activate_v0(&mut reconciler, &RootSignatures)
        .expect("trusted application join recovers promoted Core");
    assert_eq!(reconciler.calls, 1);
    assert!(matches!(
        activation.effects(),
        [Effect::ArmViewTimer { .. }]
    ));
    assert_eq!(activation.core().safety_state(), &revision_five);
    let (mut recovered, _) = activation.into_parts_v0();
    assert!(matches!(
        recovered
            .step(Input::Resume, &RootSignatures)
            .expect("restart no longer reissues anchored-successor replay")
            .as_slice(),
        [Effect::ArmViewTimer { .. }]
    ));

    let tampered_rev5 = anchored_state_with_validation_parts_v0(
        &revision_four,
        5,
        Vec::new(),
        revision_four.payload_validation_completions()[..1].to_vec(),
        revision_four.payload_terminal_facts()[..1].to_vec(),
    );
    assert!(Core::validate_persisted_state_v0(&config, &tampered_rev5, &RootSignatures,).is_err());
}

#[test]
fn h1_anchor_successor_bundle_and_reconciler_tamper_fail_closed_v0() {
    let (config, proof, h1, h2, h3) = h1_state_sync_fixture();
    let state = Core::prepare_h1_state_sync_bootstrap_v0(config.clone(), proof, &RootSignatures)
        .expect("h1 bootstrap")
        .into_safety_state();

    let foreign_body = proposal_with_parameters(
        config.validator_set(),
        config.consensus_parameters(),
        h2.witness().justify_qc().clone(),
        h2.block().header().view().get(),
        b"foreign h2 body",
    );
    assert!(matches!(
        Core::prepare_h1_state_sync_anchor_successor_bundle_v0(
            &config,
            &state,
            foreign_body,
            h3.clone(),
            &RootSignatures,
        ),
        Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(_))
    ));

    let substituted_payload = ApplicationPayloadV0::new(vec![b"substituted h2 body".to_vec()])
        .expect("canonical substituted payload")
        .try_cev0_bytes()
        .expect("encode substituted payload");
    let substituted_block = Block::new(
        h2.block().header().clone(),
        substituted_payload,
        h2.block().evidence_objects().to_vec(),
    )
    .expect("transport block accepts a same-header body carrier");
    let substituted_h2 = SignedProposalV0::new(
        substituted_block,
        h2.witness().clone(),
        config.validator_set(),
        None,
        config.consensus_parameters(),
        h1.block().header().timestamp_ms(),
    )
    .expect("proposal witness authenticates the unchanged header");
    assert_eq!(substituted_h2.block().header(), h2.block().header());
    assert_eq!(substituted_h2.witness(), h2.witness());
    assert!(matches!(
        Core::prepare_h1_state_sync_anchor_successor_bundle_v0(
            &config,
            &state,
            substituted_h2,
            h3.clone(),
            &RootSignatures,
        ),
        Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(_))
    ));

    assert!(matches!(
        Core::prepare_h1_state_sync_anchor_successor_bundle_v0(
            &config,
            &state,
            h2.clone(),
            h3.clone(),
            &RejectSignatures,
        ),
        Err(CoreError::Protocol(_))
    ));

    let bundle = Core::prepare_h1_state_sync_anchor_successor_bundle_v0(
        &config,
        &state,
        h2.clone(),
        h3.clone(),
        &RootSignatures,
    )
    .expect("exact bundle");
    let session = Core::begin_state_sync_anchor_successor_recovery_v0(
        config.clone(),
        state.clone(),
        bundle,
        &RootSignatures,
    )
    .expect("exact inert session");
    let mut rejecting = ExactAnchorSuccessorReconcilerV0 {
        expected_state: state,
        expected_phase: StateSyncAnchorSuccessorPhaseV0::H1Bootstrap,
        expected_child: h2,
        expected_grandchild: h3,
        accept: false,
        calls: 0,
    };
    assert!(matches!(
        session.reconcile_and_activate_v0(&mut rejecting),
        Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(_))
    ));
    assert_eq!(rejecting.calls, 1);
}

#[test]
fn h1_anchor_successor_recovery_recovers_rev3_and_rejects_noncanonical_valid_metadata_v0() {
    let (config, proof, _h1, h2, h3) = h1_state_sync_fixture();
    let initial = Core::prepare_h1_state_sync_bootstrap_v0(config.clone(), proof, &RootSignatures)
        .expect("h1 bootstrap")
        .into_safety_state();
    let mut replay =
        anchored_successor_bundle_and_replay_v0(&config, initial, h2.clone(), h3.clone());
    let authority = replay
        .issue_application_seal_authority_v0()
        .expect("one application authority");
    let h2_o = replay.step_next_proposal_v0(&RootSignatures).expect("h2 O");
    let (barrier, _) = persistence_effect(&h2_o);
    let request = replay
        .step_storage_ack_v0(barrier, &RootSignatures)
        .expect("h2 P");
    let sealed = seal_anchored_successor_valid_v0(&replay, &authority, request);
    let h2_c = replay
        .step_application_sealed_valid_v0(&sealed, &RootSignatures)
        .expect("h2 C");
    let (barrier, rev2) = persistence_effect(&h2_c);
    assert!(replay
        .step_storage_ack_v0(barrier, &RootSignatures)
        .expect("h2 K")
        .is_empty());
    let h3_o = replay.step_next_proposal_v0(&RootSignatures).expect("h3 O");
    let (_barrier, rev3) = persistence_effect(&h3_o);
    let recovered_rev3 =
        anchored_successor_bundle_and_replay_v0(&config, rev3.clone(), h2.clone(), h3.clone());
    assert_eq!(
        recovered_rev3.phase().expect("rev3 recovery phase"),
        StateSyncAnchorSuccessorPhaseV0::H3ValidationPending
    );
    let recovered_persistence = recovered_rev3
        .pending_obligation_persistence_v0()
        .expect("rev3 recovery retains the exact h3 persistence owner");
    assert_eq!(
        recovered_persistence.state(),
        &rev3,
        "rev3 recovery must replay the byte-identical durable obligation"
    );

    let exact_completion = rev2.payload_validation_completions()[0].clone();
    let exact_fact = rev2.payload_terminal_facts()[0];
    let exact_result = exact_completion.result();
    let commitments = exact_result.commitments().expect("Valid commitments");
    let artifact = exact_result.artifact_ref().expect("Valid artifact");
    let wrong_parent = ValidatedPayloadArtifactRefV0::new(
        BlockIdOverlayRefV0::new(
            artifact.overlay().block_id(),
            BlockId::new([0x91; 32]),
            artifact.overlay().overlay_checksum(),
        ),
        artifact.source_artifact_checksum(),
    );
    let wrong_result = DurablePayloadValidationResultV1::Valid {
        commitments,
        artifact_ref: wrong_parent,
    };
    let wrong_completion = DurablePayloadValidationCompletionV0::new(
        PayloadValidationRouteV0::Synced,
        exact_completion.id(),
        wrong_result,
        2,
    );
    let wrong_fact = PayloadTerminalFact::new_valid(wrong_parent.overlay(), 2);
    let wrong_parent_state = anchored_state_with_validation_parts_v0(
        &rev2,
        2,
        Vec::new(),
        vec![wrong_completion],
        vec![wrong_fact],
    );
    assert!(
        Core::validate_persisted_state_v0(&config, &wrong_parent_state, &RootSignatures,).is_err()
    );

    let wrong_generation = DurablePayloadValidationCompletionV0::new(
        PayloadValidationRouteV0::Synced,
        ValidationId::new(h2.block().id(), h2.block().header().view(), 9),
        exact_result,
        2,
    );
    let wrong_generation_state = anchored_state_with_validation_parts_v0(
        &rev2,
        2,
        Vec::new(),
        vec![wrong_generation],
        vec![exact_fact],
    );
    assert!(
        Core::validate_persisted_state_v0(&config, &wrong_generation_state, &RootSignatures,)
            .is_err()
    );

    let wrong_view = DurablePayloadValidationCompletionV0::new(
        PayloadValidationRouteV0::Synced,
        ValidationId::new(
            h2.block().id(),
            h2.block()
                .header()
                .view()
                .checked_next()
                .expect("test view can advance"),
            1,
        ),
        exact_result,
        2,
    );
    let wrong_view_state = anchored_state_with_validation_parts_v0(
        &rev2,
        2,
        Vec::new(),
        vec![wrong_view],
        vec![exact_fact],
    );
    assert!(
        Core::validate_persisted_state_v0(&config, &wrong_view_state, &RootSignatures).is_err()
    );

    let wrong_revision = DurablePayloadValidationCompletionV0::new(
        PayloadValidationRouteV0::Synced,
        exact_completion.id(),
        exact_result,
        1,
    );
    let wrong_revision_state = anchored_state_with_validation_parts_v0(
        &rev2,
        2,
        Vec::new(),
        vec![wrong_revision],
        vec![exact_fact],
    );
    assert!(
        Core::validate_persisted_state_v0(&config, &wrong_revision_state, &RootSignatures,)
            .is_err()
    );
}

#[test]
fn fresh_h1_state_sync_anchor_rejects_foreign_config_and_signatures() {
    let (config, proof, _h1, _h2, _h3) = h1_state_sync_fixture();

    let foreign_chain = ChainId::from_static("trnm-core-foreign-chain-0");
    let foreign_chain_set = ValidatorSet::new(
        config.validator_set().genesis_hash(),
        foreign_chain,
        config.validator_set().protocol_version(),
        config.validator_set().epoch(),
        config.consensus_parameters().hash(),
        config.validator_set().validators().to_vec(),
    )
    .expect("shape-valid foreign-chain set");
    let foreign_chain_config = CoreConfig::new(
        validator_id(1),
        foreign_chain_set,
        *config.consensus_parameters(),
        config.trusted_genesis_timestamp_ms(),
        config.max_blocks(),
        config.max_observed_messages(),
    )
    .expect("shape-valid foreign-chain config");
    assert!(Core::prepare_h1_state_sync_bootstrap_v0(
        foreign_chain_config,
        proof.clone(),
        &RootSignatures,
    )
    .is_err());

    let foreign_genesis_set = ValidatorSet::new(
        GenesisHash::new([0x6b; 32]),
        config.validator_set().chain_id(),
        config.validator_set().protocol_version(),
        config.validator_set().epoch(),
        config.consensus_parameters().hash(),
        config.validator_set().validators().to_vec(),
    )
    .expect("shape-valid foreign-genesis set");
    let foreign_genesis_config = CoreConfig::new(
        validator_id(1),
        foreign_genesis_set,
        *config.consensus_parameters(),
        config.trusted_genesis_timestamp_ms(),
        config.max_blocks(),
        config.max_observed_messages(),
    )
    .expect("shape-valid foreign-genesis config");
    assert!(Core::prepare_h1_state_sync_bootstrap_v0(
        foreign_genesis_config,
        proof.clone(),
        &RootSignatures,
    )
    .is_err());

    let mut foreign_validators = config.validator_set().validators().to_vec();
    foreign_validators[0] = Validator::new(
        validator_id(1),
        ConsensusPublicKey::new([0x91; 32]),
        VotingPower::new(1).expect("positive voting power"),
    )
    .expect("shape-valid foreign validator");
    let foreign_set = ValidatorSet::new(
        config.validator_set().genesis_hash(),
        config.validator_set().chain_id(),
        config.validator_set().protocol_version(),
        config.validator_set().epoch(),
        config.consensus_parameters().hash(),
        foreign_validators,
    )
    .expect("shape-valid foreign validator set");
    let foreign_set_config = CoreConfig::new(
        validator_id(1),
        foreign_set,
        *config.consensus_parameters(),
        config.trusted_genesis_timestamp_ms(),
        config.max_blocks(),
        config.max_observed_messages(),
    )
    .expect("shape-valid foreign-set config");
    assert!(Core::prepare_h1_state_sync_bootstrap_v0(
        foreign_set_config,
        proof.clone(),
        &RootSignatures,
    )
    .is_err());

    let mut parameter_fields = config.consensus_parameters().fields();
    parameter_fields.base_timeout_ms = parameter_fields.base_timeout_ms.saturating_add(1);
    let foreign_parameters =
        ConsensusParametersV0::new(parameter_fields).expect("shape-valid foreign parameters");
    let foreign_parameter_set = validator_set_with_parameters(&foreign_parameters);
    let foreign_parameter_config = CoreConfig::new(
        validator_id(1),
        foreign_parameter_set,
        foreign_parameters,
        config.trusted_genesis_timestamp_ms(),
        config.max_blocks(),
        config.max_observed_messages(),
    )
    .expect("shape-valid foreign-parameter config");
    assert!(Core::prepare_h1_state_sync_bootstrap_v0(
        foreign_parameter_config,
        proof.clone(),
        &RootSignatures,
    )
    .is_err());

    let (signature_config, invalid_signature_proof) =
        h1_state_sync_proof_with_invalid_proposer_signature();
    assert!(Core::prepare_h1_state_sync_bootstrap_v0(
        signature_config,
        invalid_signature_proof,
        &RootSignatures,
    )
    .is_err());

    let _canonical = Core::prepare_h1_state_sync_bootstrap_v0(config, proof, &RootSignatures)
        .expect("all foreign-context probes leave the canonical source usable");
}

#[test]
fn fresh_h1_state_sync_anchor_binds_root_timestamp_kind_and_epoch_fence() {
    let (root_config, root_proof, root_h1, _root_h2, _root_h3) = h1_state_sync_fixture_with(
        consensus_parameters(),
        H1AnchorChainMutationV0 {
            h1_state_root: StateRoot::new([0x72; 32]),
            ..H1AnchorChainMutationV0::default()
        },
    );
    assert!(Core::prepare_h1_state_sync_bootstrap_v0(
        root_config.clone(),
        root_proof.clone(),
        &RejectSignatures,
    )
    .is_err());
    let root_state =
        Core::prepare_h1_state_sync_bootstrap_v0(root_config.clone(), root_proof, &RootSignatures)
            .expect("a distinct authenticated state root prepares an exact anchor")
            .into_safety_state();
    assert_eq!(
        root_state
            .state_sync_anchor()
            .expect("prepared state retains its anchor")
            .proof()
            .finalized_block()
            .header()
            .state_root(),
        root_h1.block().header().state_root(),
    );
    Core::validate_persisted_state_v0(&root_config, &root_state, &RootSignatures)
        .expect("the exact authenticated root remains durable");

    let (timestamp_config, timestamp_proof, timestamp_h1, _timestamp_h2, _timestamp_h3) =
        h1_state_sync_fixture_with(
            consensus_parameters(),
            H1AnchorChainMutationV0 {
                h1_timestamp_ms: 101,
                ..H1AnchorChainMutationV0::default()
            },
        );
    let timestamp_state = Core::prepare_h1_state_sync_bootstrap_v0(
        timestamp_config.clone(),
        timestamp_proof,
        &RootSignatures,
    )
    .expect("a distinct valid timestamp prepares an exact anchor")
    .into_safety_state();
    assert_eq!(
        timestamp_state.finalized().timestamp_ms(),
        timestamp_h1.block().header().timestamp_ms(),
    );
    Core::validate_persisted_state_v0(&timestamp_config, &timestamp_state, &RootSignatures)
        .expect("the exact authenticated timestamp remains durable");

    let kind_parameters = consensus_parameters();
    let kind_set = validator_set_with_parameters(&kind_parameters);
    let kind_genesis = genesis_qc(&kind_set);
    let checkpoint_h1 = block_with_anchor_test_header_fields(
        &kind_set,
        1,
        1,
        kind_genesis.block_id(),
        b"checkpoint cannot masquerade as h1",
        leader_for(&kind_set, View::new(1)),
        100,
        StateRoot::new([0x44; 32]),
        BlockKind::EpochCheckpoint,
        Some(NextEpochCommitmentHash::new([0x33; 32])),
    );
    assert!(signed_proposal_from_block(
        &kind_set,
        &kind_parameters,
        checkpoint_h1,
        QcReferenceV0::genesis_anchor(kind_genesis),
        None,
        GENESIS_TIMESTAMP_MS,
    )
    .is_err(),
    "the canonical signed-proposal type gate prevents a non-Regular h1 from reaching prepare_h1",
    );

    let bad_timestamp_parameters = consensus_parameters();
    let bad_h1_timestamp_ms = bad_timestamp_parameters
        .max_block_time_step_ms()
        .checked_add(1)
        .expect("reference timestamp bound does not overflow");
    let (bad_timestamp_config, bad_timestamp_proof, _bad_h1, _bad_h2, _bad_h3) =
        h1_state_sync_fixture_with(
            bad_timestamp_parameters,
            H1AnchorChainMutationV0 {
                proof_parent_timestamp_ms: 1,
                h1_timestamp_ms: bad_h1_timestamp_ms,
                ..H1AnchorChainMutationV0::default()
            },
        );
    assert!(Core::prepare_h1_state_sync_bootstrap_v0(
        bad_timestamp_config,
        bad_timestamp_proof,
        &RootSignatures,
    )
    .is_err());

    let short_parameters = short_epoch_parameters();
    let shortest_geometry =
        EpochGeometryV0::new(Epoch::new(0), &short_parameters).expect("valid shortest geometry");
    assert_eq!(shortest_geometry.checkpoint_height(), Height::new(4));
    let (fence_config, fence_proof, _fence_h1, _fence_h2, fence_h3) =
        h1_state_sync_fixture_with(short_parameters, H1AnchorChainMutationV0::default());
    assert_eq!(
        fence_h3.block().header().height(),
        shortest_geometry
            .last_pre_checkpoint_height()
            .expect("checkpoint height is positive"),
    );
    let fence_state = Core::prepare_h1_state_sync_bootstrap_v0(
        fence_config.clone(),
        fence_proof,
        &RootSignatures,
    )
    .expect("the h1 three-chain ends exactly before the earliest valid checkpoint")
    .into_safety_state();
    Core::validate_persisted_state_v0(&fence_config, &fence_state, &RootSignatures)
        .expect("the shortest-geometry fence remains exact after persistence");

    let mut crossing_fence_fields = consensus_parameters().fields();
    crossing_fence_fields.epoch_length_blocks = 5;
    crossing_fence_fields.snapshot_lead_blocks = 3;
    assert!(
        ConsensusParametersV0::new(crossing_fence_fields).is_err(),
        "parameter admission forbids moving the checkpoint onto the mandatory h1 three-chain",
    );
}

#[test]
fn fresh_h1_state_sync_anchor_persisted_shape_is_exact_and_history_free() {
    let (config, proof, h1, _h2, _h3) = h1_state_sync_fixture();
    let prepared = Core::prepare_h1_state_sync_bootstrap_v0(config.clone(), proof, &RootSignatures)
        .expect("valid fresh anchor")
        .into_safety_state();
    let proof = prepared
        .state_sync_anchor()
        .expect("prepared state retains its anchor")
        .proof();

    let wrong_current_view = anchored_state_from_test_parts(
        &prepared,
        prepared
            .current_view()
            .checked_next()
            .expect("test view does not overflow"),
        prepared.high_qc().clone(),
        prepared.locked_qc().clone(),
        prepared.revision(),
        Vec::new(),
    );
    let wrong_high = anchored_state_from_test_parts(
        &prepared,
        prepared.current_view(),
        prepared.locked_qc().clone(),
        prepared.locked_qc().clone(),
        prepared.revision(),
        Vec::new(),
    );
    let wrong_lock = anchored_state_from_test_parts(
        &prepared,
        prepared.current_view(),
        prepared.high_qc().clone(),
        QcReferenceV0::ordinary(proof.grandchild().certifying_qc().clone()),
        prepared.revision(),
        Vec::new(),
    );
    let wrong_revision = anchored_state_from_test_parts(
        &prepared,
        prepared.current_view(),
        prepared.high_qc().clone(),
        prepared.locked_qc().clone(),
        1,
        Vec::new(),
    );
    let synthetic_h1_history = anchored_state_from_test_parts(
        &prepared,
        prepared.current_view(),
        prepared.high_qc().clone(),
        prepared.locked_qc().clone(),
        1,
        vec![PayloadTerminalFact::new_deterministically_invalid(
            h1.block().id(),
            1,
        )],
    );

    for (name, malformed) in [
        ("current-view", wrong_current_view),
        ("high-qc", wrong_high),
        ("locked-qc", wrong_lock),
        ("revision", wrong_revision),
        ("h1-history", synthetic_h1_history),
    ] {
        assert!(
            Core::validate_persisted_state_v0(&config, &malformed, &RootSignatures).is_err(),
            "persisted anchor accepted noncanonical {name}",
        );
    }
    Core::validate_persisted_state_v0(&config, &prepared, &RootSignatures)
        .expect("all rejection probes leave the canonical source unchanged");
}

#[test]
fn fresh_h1_state_sync_anchor_record_is_exact_and_configuration_bound() {
    let (config, proof, _h1, _h2, _h3) = h1_state_sync_fixture();
    let prepared = Core::prepare_h1_state_sync_bootstrap_v0(config.clone(), proof, &RootSignatures)
        .expect("valid fresh anchor")
        .into_safety_state();
    let context = SafetyStateRecordContextV0::new(
        &config,
        SAFETY_STATE_RECORD_TEST_PROFILE_REF,
        safety_state_record_test_limits(),
    )
    .expect("valid record context");
    let encoded = encode_safety_state_record_v0(&prepared, &context)
        .expect("encode canonical anchored record");
    let decoded = decode_safety_state_record_v0_exact(&encoded, &context)
        .expect("decode exact canonical anchored record");
    assert_eq!(decoded.state(), &prepared);
    Core::validate_persisted_state_v0(&config, decoded.state(), &RootSignatures)
        .expect("decoded anchored record passes Core semantics");

    let semantic_tamper = anchored_state_from_test_parts(
        &prepared,
        prepared.current_view(),
        prepared.high_qc().clone(),
        prepared.locked_qc().clone(),
        1,
        Vec::new(),
    );
    let semantic_tamper_bytes = encode_safety_state_record_v0(&semantic_tamper, &context)
        .expect("record framing can encode inert decoder-facing parts");
    let semantic_tamper_record =
        decode_safety_state_record_v0_exact(&semantic_tamper_bytes, &context)
            .expect("record framing authenticates bytes, not Core reachability");
    assert_eq!(
        Core::validate_persisted_state_v0(&config, semantic_tamper_record.state(), &RootSignatures,),
        Err(CoreError::InvalidRecovery(
            "anchored h2 pending phase requires exactly one obligation",
        )),
    );

    let mut checksum_tampered = encoded.clone();
    let last = checksum_tampered
        .last_mut()
        .expect("an encoded record has a checksum");
    *last ^= 1;
    assert!(decode_safety_state_record_v0_exact(&checksum_tampered, &context).is_err());

    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(decode_safety_state_record_v0_exact(&trailing, &context).is_err());

    let mut config_ref_tampered = encoded.clone();
    config_ref_tampered[12] ^= 1;
    assert_eq!(
        decode_safety_state_record_v0_exact(&config_ref_tampered, &context),
        Err(SafetyStateRecordErrorV0::ConfigMismatch),
    );

    let foreign_context =
        SafetyStateRecordContextV0::new(&config, [0x72; 32], safety_state_record_test_limits())
            .expect("shape-valid foreign verifier-profile context");
    assert_eq!(
        decode_safety_state_record_v0_exact(&encoded, &foreign_context),
        Err(SafetyStateRecordErrorV0::ConfigMismatch),
    );
}

#[test]
fn native_valid_post_ack_manifest_has_eight_closed_action_codes() {
    use crate::model::DeferredEffect;

    let cases = [
        (Vec::new(), NativeValidPostAckActionV0::None),
        (
            vec![DeferredEffect::RequestSignature],
            NativeValidPostAckActionV0::RequestSignature,
        ),
        (
            vec![DeferredEffect::ArmViewTimer],
            NativeValidPostAckActionV0::ArmViewTimer,
        ),
        (
            vec![DeferredEffect::ArmViewTimer, DeferredEffect::Finalize],
            NativeValidPostAckActionV0::ArmViewTimerThenFinalize,
        ),
        (
            vec![DeferredEffect::RequestTcHighQcSync],
            NativeValidPostAckActionV0::RequestTcHighQcSync,
        ),
        (
            vec![DeferredEffect::RequestStandaloneQcSync],
            NativeValidPostAckActionV0::RequestStandaloneQcSync,
        ),
        (
            vec![
                DeferredEffect::ArmViewTimer,
                DeferredEffect::RequestStandaloneQcSync,
            ],
            NativeValidPostAckActionV0::ArmViewTimerThenRequestStandaloneQcSync,
        ),
        (
            vec![DeferredEffect::SafetyHalted],
            NativeValidPostAckActionV0::SafetyHaltedConflict,
        ),
    ];
    for (expected_code, (deferred, expected)) in (0u32..).zip(cases) {
        assert_eq!(expected.code(), expected_code);
        assert_eq!(
            NativeValidPostAckActionV0::from_code(expected_code),
            Some(expected)
        );
        assert_eq!(
            NativeValidPostAckActionV0::from_deferred_v0(&deferred),
            Some(expected)
        );
    }
    assert_eq!(NativeValidPostAckActionV0::from_code(8), None);
    assert_eq!(
        NativeValidPostAckActionV0::from_deferred_v0(&[DeferredEffect::Finalize]),
        None
    );
    assert_eq!(
        NativeValidPostAckActionV0::from_deferred_v0(&[
            DeferredEffect::RequestStandaloneQcSync,
            DeferredEffect::ArmViewTimer,
        ]),
        None
    );
}

#[test]
fn native_finalization_applied_post_ack_manifest_has_nine_distinct_closed_action_codes() {
    use crate::model::DeferredEffect;

    let cases = [
        (Vec::new(), NativeFinalizationAppliedPostAckActionV0::None),
        (
            vec![DeferredEffect::ArmViewTimer],
            NativeFinalizationAppliedPostAckActionV0::ArmViewTimer,
        ),
        (
            vec![DeferredEffect::RequestSignature],
            NativeFinalizationAppliedPostAckActionV0::RequestSignature,
        ),
        (
            vec![
                DeferredEffect::ArmViewTimer,
                DeferredEffect::RequestSignature,
            ],
            NativeFinalizationAppliedPostAckActionV0::ArmViewTimerThenRequestSignature,
        ),
        (
            vec![DeferredEffect::Finalize],
            NativeFinalizationAppliedPostAckActionV0::Finalize,
        ),
        (
            vec![DeferredEffect::ArmViewTimer, DeferredEffect::Finalize],
            NativeFinalizationAppliedPostAckActionV0::ArmViewTimerThenFinalize,
        ),
        (
            vec![DeferredEffect::RequestTcHighQcSync],
            NativeFinalizationAppliedPostAckActionV0::RequestTcHighQcSync,
        ),
        (
            vec![DeferredEffect::RequestStandaloneQcSync],
            NativeFinalizationAppliedPostAckActionV0::RequestStandaloneQcSync,
        ),
        (
            vec![
                DeferredEffect::ArmViewTimer,
                DeferredEffect::RequestStandaloneQcSync,
            ],
            NativeFinalizationAppliedPostAckActionV0::ArmViewTimerThenRequestStandaloneQcSync,
        ),
    ];
    for (expected_code, (deferred, expected)) in (0u32..).zip(cases) {
        assert_eq!(expected.code(), expected_code);
        assert_eq!(
            NativeFinalizationAppliedPostAckActionV0::from_code(expected_code),
            Some(expected)
        );
        assert_eq!(
            NativeFinalizationAppliedPostAckActionV0::from_deferred_v0(&deferred),
            Some(expected)
        );
    }
    assert_eq!(NativeFinalizationAppliedPostAckActionV0::from_code(9), None);
    assert_eq!(
        NativeFinalizationAppliedPostAckActionV0::from_deferred_v0(&[
            DeferredEffect::RequestSignature,
            DeferredEffect::ArmViewTimer,
        ]),
        None
    );
}

#[test]
fn native_finalization_applied_recovery_remints_all_nine_shapes_against_exact_outboxes() {
    let (_config, mut idle) = configured_core();
    assert!(idle
        .native_finalization_applied_recovery_effects_for_test_v0(
            NativeFinalizationAppliedPostAckActionV0::None,
        )
        .expect("None matches an idle durable state")
        .is_empty());
    assert!(matches!(
        idle.native_finalization_applied_recovery_effects_for_test_v0(
            NativeFinalizationAppliedPostAckActionV0::ArmViewTimer,
        )
        .expect("Timer matches the same idle durable state")
        .as_slice(),
        [Effect::ArmViewTimer { epoch, view }]
            if *epoch == idle.safety_state().epoch()
                && *view == idle.safety_state().current_view()
    ));

    let (_signature_config, mut signature_source) = configured_core();
    let signature_set = signature_source.config().validator_set().clone();
    let signature_proposal = proposal(
        &signature_set,
        genesis_qc(&signature_set),
        1,
        b"tag3 exact vote-signature action",
    );
    let registration = signature_source
        .step(
            Input::Proposal(Box::new(signature_proposal)),
            &RootSignatures,
        )
        .expect("proposal registers an exact payload-validation slot");
    let validation_effects = release_persisted_effects(&mut signature_source, registration);
    let validation = validation_effect(&validation_effects);
    let result = valid_result_for_effect(&signature_source, &validation_effects, validation);
    let sign_effects = signature_source
        .step(
            Input::PayloadValidated {
                id: validation,
                result,
            },
            &RootSignatures,
        )
        .expect("validated proposal creates a durable exact vote-sign intent");
    let (_, signature_state) = persistence_effect(&sign_effects);
    let mut timer_signature = signature_source.clone();
    let mut signature = signature_source;
    assert!(matches!(
        signature
            .native_finalization_applied_recovery_effects_for_test_v0(
                NativeFinalizationAppliedPostAckActionV0::RequestSignature,
            )
            .expect("Signature matches the exact durable sign intent")
            .as_slice(),
        [Effect::RequestSignature { intent }]
            if intent.signing_root()
                == signature_state.pending_sign().expect("sign intent").signing_root()
    ));
    assert!(matches!(
        timer_signature
            .native_finalization_applied_recovery_effects_for_test_v0(
                NativeFinalizationAppliedPostAckActionV0::ArmViewTimerThenRequestSignature,
            )
            .expect("Timer then Signature preserves exact ordering")
            .as_slice(),
        [Effect::ArmViewTimer { .. }, Effect::RequestSignature { .. }]
    ));

    let (_finalize_config, mut finalize, _id, _result) =
        finalization_gated_validation(b"tag3 all-shapes finalize");
    let expected_front = finalize
        .safety_state()
        .pending_finalization()
        .expect("a durable finalization front")
        .clone();
    assert!(matches!(
        finalize
            .native_finalization_applied_recovery_effects_for_test_v0(
                NativeFinalizationAppliedPostAckActionV0::Finalize,
            )
            .expect("Finalize matches the exact durable queue front")
            .as_slice(),
        [Effect::Finalize(front)] if front.as_ref() == &expected_front
    ));
    assert!(matches!(
        finalize
            .native_finalization_applied_recovery_effects_for_test_v0(
                NativeFinalizationAppliedPostAckActionV0::ArmViewTimerThenFinalize,
            )
            .expect("Timer then Finalize preserves exact ordering")
            .as_slice(),
        [Effect::ArmViewTimer { .. }, Effect::Finalize(front)]
            if front.as_ref() == &expected_front
    ));

    let (_tc_config, mut tc) = configured_core();
    let tc_set = tc.config().validator_set().clone();
    let tc_parent = proposal(&tc_set, genesis_qc(&tc_set), 1, b"tag3 tc parent");
    let tc_parent_qc = qc(&tc_set, 1, 1, tc_parent.block().id());
    let tc_target = proposal(&tc_set, tc_parent_qc, 2, b"tag3 tc target");
    let tc_qc = qc(&tc_set, 2, 2, tc_target.block().id());
    tc.step(
        Input::TimeoutCertificate(timeout_certificate(&tc_set, 3, tc_qc.clone())),
        &RootSignatures,
    )
    .expect("missing TC target becomes durable");
    assert!(matches!(
        tc.native_finalization_applied_recovery_effects_for_test_v0(
            NativeFinalizationAppliedPostAckActionV0::RequestTcHighQcSync,
        )
        .expect("TC action matches its exact durable target")
        .as_slice(),
        [Effect::RequestTcHighQcSync { target, .. }]
            if target.qc_digest() == tc_qc.id()
    ));

    let (_standalone_config, mut standalone) = configured_core();
    let standalone_set = standalone.config().validator_set().clone();
    let standalone_qc = qc(&standalone_set, 1, 1, BlockId::new([0x6a; 32]));
    standalone
        .step(
            Input::QuorumCertificate(standalone_qc.clone()),
            &RootSignatures,
        )
        .expect("unknown QC becomes a durable standalone target");
    assert!(matches!(
        standalone
            .native_finalization_applied_recovery_effects_for_test_v0(
                NativeFinalizationAppliedPostAckActionV0::RequestStandaloneQcSync,
            )
            .expect("Standalone sync matches its exact durable target")
            .as_slice(),
        [Effect::RequestStandaloneQcSync { target, .. }]
            if target.qc_digest() == standalone_qc.id()
    ));
    assert!(matches!(
        standalone
            .native_finalization_applied_recovery_effects_for_test_v0(
                NativeFinalizationAppliedPostAckActionV0::ArmViewTimerThenRequestStandaloneQcSync,
            )
            .expect("Timer then standalone sync preserves exact ordering")
            .as_slice(),
        [Effect::ArmViewTimer { .. }, Effect::RequestStandaloneQcSync { target, .. }]
            if target.qc_digest() == standalone_qc.id()
    ));

    assert_eq!(
        idle.native_finalization_applied_recovery_effects_for_test_v0(
            NativeFinalizationAppliedPostAckActionV0::Finalize,
        ),
        Err(CoreError::NativeFinalizationAppliedRecoveryRejected(
            "recorded tag-3 action does not match its durable outbox",
        )),
        "an inert action code cannot invent a missing durable outbox",
    );
}

#[test]
fn current_tag3_recovery_requires_exact_reconciliation_and_remints_only_its_recorded_action() {
    let (config, mut core) = configured_core();
    let authority = finalization_apply_authority_for_test(&core);
    let set = core.config().validator_set().clone();
    let p1 = proposal(&set, genesis_qc(&set), 1, b"tag3 recovery one");
    let q1 = qc(&set, 1, 1, p1.block().id());
    let p2 = proposal(&set, q1, 2, b"tag3 recovery two");
    let q2 = qc(&set, 2, 2, p2.block().id());
    let p3 = proposal(&set, q2, 3, b"tag3 recovery three");
    let q3 = qc(&set, 3, 3, p3.block().id());
    let p4 = proposal(&set, q3.clone(), 4, b"tag3 recovery four");
    let q4 = qc(&set, 4, 4, p4.block().id());
    for proposed in [p1.clone(), p2.clone(), p3, p4] {
        replay_valid(&mut core, proposed);
    }
    let effects = core
        .step(
            Input::TimeoutCertificate(timeout_certificate_with_two_qcs(&set, 5, q3, q4)),
            &RootSignatures,
        )
        .expect("two ordered finalizations become durable");
    let (barrier, _) = persistence_effect(&effects);
    core.step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("the first finalization request is released");

    let consumed = core
        .safety_state()
        .pending_finalization()
        .expect("the exact first queue front exists")
        .clone();
    let permit = core
        .issue_application_finalization_permit_v0()
        .expect("the exact queue front has one permit");
    let readback = finalization_readback_for_test(&core, &authority, &permit);
    let wrong_readback = authority
        .application_store_apply_readback_v0(
            &permit,
            readback.source_route(),
            readback.source_validation_id(),
            readback.ordinal(),
            readback.application_host_config_ref(),
            readback.prior_head_checksum(),
            readback.new_head_checksum(),
            readback.source_artifact_checksum(),
            readback.accepted_source_checksum(),
            readback.applied_job_row_checksum(),
            [0x99; 32],
        )
        .expect("a distinct inert App readback remains comparison data");
    let receipt = authority
        .receipt_after_application_store_apply_v0(permit, readback.clone())
        .expect("the exact App readback creates one receipt");
    let effects = core
        .step_application_finalization_receipt_v0(receipt, &RootSignatures)
        .expect("the App receipt creates one tag-3 persistence request");
    let request = persistence_request(&effects);
    let manifest = request
        .native_finalization_applied_v0()
        .expect("the current head transition is tag 3");
    assert_eq!(
        manifest.post_ack_action_v0(),
        NativeFinalizationAppliedPostAckActionV0::Finalize,
    );
    let persisted = request.state().clone();
    let transition = finalization_recovery_transition_for_test(
        &consumed,
        &readback,
        manifest.post_ack_action_v0(),
        persisted.revision(),
    );

    let session = Core::begin_native_finalization_applied_recovery_v0(
        config.clone(),
        persisted.clone(),
        &RootSignatures,
    )
    .expect("an authenticated current tag-3 SafetyState creates an inert session");
    let mut reject = ExactNativeFinalizationRecoveryReconcilerV0 {
        expected_revision: persisted.revision(),
        expected_transition: transition.clone(),
        expected_readback: readback.clone(),
        accept: false,
        calls: 0,
    };
    let wrong_transition = finalization_recovery_transition_for_test(
        &consumed,
        &readback,
        manifest.post_ack_action_v0(),
        persisted
            .revision()
            .checked_add(1)
            .expect("test revision remains bounded"),
    );
    assert!(matches!(
        session.challenge().attest_authenticated_reconciliation_v0(
            &persisted,
            &wrong_transition,
            &readback,
            &mut reject,
        ),
        Err(CoreError::NativeFinalizationAppliedRecoveryRejected(
            "tag-3 transition, SafetyState, and ApplicationStore readback are not exactly congruent",
        )),
    ));
    let transition_with_storage_union =
        |application_host_config_ref, finalization_checksum, accepted_source_checksum| {
            NativeFinalizationAppliedRecoveryTransitionV0::from_persisted_parts(
                transition.ordinal(),
                transition.proof_id(),
                transition.parent_block_id(),
                transition.target_block_id(),
                transition.overlay_checksum(),
                transition.source_route(),
                transition.source_validation_id(),
                application_host_config_ref,
                finalization_checksum,
                transition.source_artifact_checksum(),
                accepted_source_checksum,
                transition.applied_job_row_checksum(),
                transition.prior_head_checksum(),
                transition.new_head_checksum(),
                transition.application_receipt_row_checksum(),
                transition.post_ack_action_v0(),
                transition.transition_revision(),
            )
        };
    for mismatched_transition in [
        transition_with_storage_union(
            [0xa1; 32],
            transition.finalization_checksum(),
            transition.accepted_source_checksum(),
        ),
        transition_with_storage_union(
            transition.application_host_config_ref(),
            [0xa2; 32],
            transition.accepted_source_checksum(),
        ),
        transition_with_storage_union(
            transition.application_host_config_ref(),
            transition.finalization_checksum(),
            [0xa3; 32],
        ),
    ] {
        assert!(matches!(
            session.challenge().attest_authenticated_reconciliation_v0(
                &persisted,
                &mismatched_transition,
                &readback,
                &mut reject,
            ),
            Err(CoreError::NativeFinalizationAppliedRecoveryRejected(
                "tag-3 transition, SafetyState, and ApplicationStore readback are not exactly congruent",
            )),
        ));
    }
    assert!(matches!(
        session.challenge().attest_authenticated_reconciliation_v0(
            &persisted,
            &transition,
            &wrong_readback,
            &mut reject,
        ),
        Err(CoreError::NativeFinalizationAppliedRecoveryRejected(
            "tag-3 transition, SafetyState, and ApplicationStore readback are not exactly congruent",
        )),
    ));
    assert_eq!(
        reject.calls, 0,
        "inert mismatches never reach the trusted host"
    );
    assert!(matches!(
        session.challenge().attest_authenticated_reconciliation_v0(
            &persisted,
            &transition,
            &readback,
            &mut reject,
        ),
        Err(CoreError::NativeFinalizationAppliedRecoveryRejected(
            "the trusted host rejected the exact SafetyStore/ApplicationStore tuple",
        )),
    ));
    assert_eq!(reject.calls, 1);

    let mut accept = ExactNativeFinalizationRecoveryReconcilerV0 {
        expected_revision: persisted.revision(),
        expected_transition: transition.clone(),
        expected_readback: readback.clone(),
        accept: true,
        calls: 0,
    };
    let attestation = session
        .challenge()
        .attest_authenticated_reconciliation_v0(&persisted, &transition, &readback, &mut accept)
        .expect("the trusted host authenticates the exact tuple");
    assert_eq!(accept.calls, 1);
    let mut recovered = session
        .reconcile_and_activate_v0(attestation)
        .expect("the exact session-affined attestation activates recovery");
    let mut public_clone = recovered.clone();
    assert_eq!(
        public_clone.step(Input::Resume, &RootSignatures),
        Err(CoreError::NativeFinalizationAppliedRecoveryRejected(
            "the exact tag-3 recovery fence belongs to a different Core instance",
        )),
        "a public Core clone cannot consume the original process-local fence",
    );
    let before_resume = recovered.safety_state().clone();
    let effects = recovered
        .step(Input::Resume, &RootSignatures)
        .expect("first Resume remints the exact recorded action");
    assert!(matches!(
        effects.as_slice(),
        [Effect::Finalize(next)]
            if next.as_ref() == before_resume.pending_finalization().expect("next queue front")
    ));
    assert_eq!(
        recovered.safety_state(),
        &before_resume,
        "exact action remint creates no SafetyState transition",
    );
    assert!(!effects
        .iter()
        .any(|effect| matches!(effect, Effect::PersistSafetyState(_))));

    // A public clone receives a fresh process affinity. Even identical
    // protocol state and inert transition/readback rows cannot activate or
    // consume the original session fence.
    let foreign_session = Core::begin_native_finalization_applied_recovery_v0(
        config,
        persisted.clone(),
        &RootSignatures,
    )
    .expect("a second inert recovery session has a distinct affinity");
    let mut foreign_accept = ExactNativeFinalizationRecoveryReconcilerV0 {
        expected_revision: persisted.revision(),
        expected_transition: transition.clone(),
        expected_readback: readback.clone(),
        accept: true,
        calls: 0,
    };
    let foreign_attestation = foreign_session
        .challenge()
        .attest_authenticated_reconciliation_v0(
            &persisted,
            &transition,
            &readback,
            &mut foreign_accept,
        )
        .expect("the second trusted session authenticates its own tuple");
    let third_session = Core::begin_native_finalization_applied_recovery_v0(
        recovered.config().clone(),
        persisted,
        &RootSignatures,
    )
    .expect("a third inert session has another affinity");
    let rejection = third_session
        .reconcile_and_activate_v0(foreign_attestation)
        .expect_err("a foreign session attestation is rejected owner-preservingly");
    assert_eq!(
        rejection.error(),
        &CoreError::NativeFinalizationAppliedRecoveryRejected(
            "recovery attestation belongs to a different session or SafetyState",
        ),
    );
    let (_error, retry_session, retry_attestation) = rejection.into_parts();
    foreign_session
        .reconcile_and_activate_v0(retry_attestation)
        .expect("the returned attestation remains usable by its issuing session");
    drop(retry_session);
}

#[test]
fn drained_tag3_recovery_binds_the_consumed_proof_id_to_the_durable_tail() {
    let (config, mut core, validation, result) =
        finalization_gated_validation(b"tag3 drained proof identity");
    let validation_effects = core
        .step(
            Input::PayloadValidated {
                id: validation,
                result,
            },
            &RootSignatures,
        )
        .expect("the exact Valid callback persists before tag-3 recovery");
    let (validation_barrier, _) = persistence_effect(&validation_effects);
    core.step(
        Input::StorageAck {
            barrier: validation_barrier,
        },
        &RootSignatures,
    )
    .expect("the Valid callback persistence is acknowledged");
    let authority = finalization_apply_authority_for_test(&core);
    let consumed = core
        .safety_state()
        .pending_finalization()
        .expect("the fixture has one finalization queue front")
        .clone();
    let permit = core
        .issue_application_finalization_permit_v0()
        .expect("the exact queue front has one permit");
    let readback = finalization_readback_for_test(&core, &authority, &permit);
    let receipt = authority
        .receipt_after_application_store_apply_v0(permit, readback.clone())
        .expect("the exact App readback creates one receipt");
    let effects = core
        .step_application_finalization_receipt_v0(receipt, &RootSignatures)
        .expect("the receipt creates one tag-3 persistence request");
    let request = persistence_request(&effects);
    let persisted = request.state().clone();
    assert!(persisted.finalization_queue().is_empty());
    assert_eq!(
        persisted
            .last_finalization()
            .expect("the durable tail retains the consumed proof")
            .proof_id(),
        consumed.proof_id()
    );

    let transition = finalization_recovery_transition_for_test(
        &consumed,
        &readback,
        request
            .native_finalization_applied_v0()
            .expect("the persistence request carries the tag-3 manifest")
            .post_ack_action_v0(),
        persisted.revision(),
    );
    let tampered = NativeFinalizationAppliedRecoveryTransitionV0::from_persisted_parts(
        transition.ordinal(),
        CertificateId::new([0xabu8; 32]),
        transition.parent_block_id(),
        transition.target_block_id(),
        transition.overlay_checksum(),
        transition.source_route(),
        transition.source_validation_id(),
        transition.application_host_config_ref(),
        transition.finalization_checksum(),
        transition.source_artifact_checksum(),
        transition.accepted_source_checksum(),
        transition.applied_job_row_checksum(),
        transition.prior_head_checksum(),
        transition.new_head_checksum(),
        transition.application_receipt_row_checksum(),
        transition.post_ack_action_v0(),
        transition.transition_revision(),
    );
    let session = Core::begin_native_finalization_applied_recovery_v0(
        config,
        persisted.clone(),
        &RootSignatures,
    )
    .expect("the exact drained tag-3 state creates an inert recovery session");
    assert_eq!(
        session
            .challenge()
            .application_store_readback_for_recovery_v0(&persisted, &tampered),
        Err(CoreError::NativeFinalizationAppliedRecoveryRejected(
            "tag-3 transition, SafetyState, and ApplicationStore readback are not exactly congruent",
        ))
    );
}

#[test]
fn native_valid_post_ack_manifest_is_absent_from_ordinary_persistence() {
    let (_config, mut timeout_core) = configured_core();
    let timeout_epoch = timeout_core.safety_state().epoch();
    let timeout_view = timeout_core.safety_state().current_view();
    let timeout_effects = timeout_core
        .step(
            Input::LocalTimeout {
                epoch: timeout_epoch,
                view: timeout_view,
            },
            &RootSignatures,
        )
        .expect("ordinary timeout intent persists");
    assert_eq!(
        persistence_request(&timeout_effects).native_valid_post_ack_action_v0(),
        None
    );

    let (_config, mut valid_core) = configured_core();
    let set = valid_core.config().validator_set().clone();
    let proposed = proposal(&set, genesis_qc(&set), 1, b"native Valid manifest scope");
    let registration = valid_core
        .step(Input::Proposal(Box::new(proposed)), &RootSignatures)
        .expect("proposal registration persists");
    assert_eq!(
        persistence_request(&registration).native_valid_post_ack_action_v0(),
        None,
        "registration is not a Valid callback transition"
    );
    let validation = release_persisted_effects(&mut valid_core, registration);
    let id = validation_effect(&validation);
    let result = valid_result_for_effect(&valid_core, &validation, id);
    let callback = valid_core
        .step(Input::PayloadValidated { id, result }, &RootSignatures)
        .expect("Valid callback persists");
    assert_eq!(
        persistence_request(&callback).native_valid_post_ack_action_v0(),
        Some(NativeValidPostAckActionV0::RequestSignature)
    );
}

#[test]
fn native_valid_completion_recovery_remints_one_exact_inert_action_v0() {
    let (config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(
        &set,
        genesis_qc(&set),
        1,
        b"native Valid C plus D or K recovery",
    );
    let registration = core
        .step(Input::Proposal(Box::new(proposed)), &RootSignatures)
        .expect("proposal registration persists");
    let validation = release_persisted_effects(&mut core, registration);
    let id = validation_effect(&validation);
    let result = valid_result_for_effect(&core, &validation, id);
    let callback = core
        .step(Input::PayloadValidated { id, result }, &RootSignatures)
        .expect("Valid callback persists");
    let persisted = persistence_request(&callback).state().clone();
    let expected_action = persistence_request(&callback)
        .native_valid_post_ack_action_v0()
        .expect("NativeValid transition carries one closed action");
    assert_eq!(
        expected_action,
        NativeValidPostAckActionV0::RequestSignature
    );
    assert_eq!(
        Core::recover(config.clone(), persisted.clone(), &RootSignatures),
        Err(CoreError::InvalidRecovery(
            "a current NativeValid completion requires its dedicated cross-store recovery session"
        ))
    );

    let session =
        Core::begin_native_valid_completion_recovery_v0(config, persisted.clone(), &RootSignatures)
            .expect("one current NativeValid completion creates an inert session");
    assert_eq!(session.challenge().safety_state(), &persisted);
    assert_eq!(
        session.challenge().route_v0(),
        PayloadValidationRouteV0::Proposal
    );
    assert_eq!(session.challenge().validation_id_v0(), id);
    assert_eq!(
        session.challenge().valid_result_checksum_v0(),
        native_valid_result_checksum_v0(session.challenge().completion().result())
            .expect("the challenged completion is Valid")
    );
    let record_checksum = [0x91; 32];
    let mut reconciler = ExactNativeValidCompletionRecoveryReconcilerV0 {
        expected_state: persisted.clone(),
        expected_record_checksum: record_checksum,
        expected_action,
        accept: true,
        calls: 0,
    };
    let attestation = session
        .challenge()
        .attest_authenticated_reconciliation_v0(
            &persisted,
            record_checksum,
            expected_action,
            &mut reconciler,
        )
        .expect("trusted Safety/App reconciliation mints one linear attestation");
    assert_eq!(
        attestation.safety_state_record_checksum_v0(),
        record_checksum
    );
    assert_eq!(attestation.post_ack_action_v0(), expected_action);
    let mut replay = session
        .reconcile_and_activate_v0(attestation)
        .expect("the exact session consumes its own attestation");
    assert_eq!(reconciler.calls, 1);
    assert_eq!(replay.safety_state(), &persisted);
    let recovered = replay
        .remint_inert_post_ack_action_v0()
        .expect("the exact action is released once as inert comparison data");
    assert_eq!(recovered.safety_head_revision_v0(), persisted.revision());
    assert_eq!(recovered.safety_state_record_checksum_v0(), record_checksum);
    assert_eq!(recovered.route_v0(), PayloadValidationRouteV0::Proposal);
    assert_eq!(recovered.validation_id_v0(), id);
    assert_eq!(recovered.post_ack_action_v0(), expected_action);
    assert_eq!(
        recovered.valid_result_checksum_v0(),
        session_result_checksum_for_test(&persisted)
    );
    assert!(matches!(
        replay.remint_inert_post_ack_action_v0(),
        Err(CoreError::NativeValidCompletionRecoveryRejected(
            "the exact recovered post-ack action was already reminted"
        ))
    ));
    assert_eq!(replay.safety_state(), &persisted);
}

fn session_result_checksum_for_test(state: &SafetyState) -> [u8; 32] {
    native_valid_result_checksum_v0(state.payload_validation_completions()[0].result())
        .expect("fixture completion is Valid")
}

fn historical_unavailable_synced_completion_v0(
) -> (CoreConfig, Core, SignedProposalV0, ValidationId) {
    let (config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(
        &set,
        genesis_qc(&set),
        1,
        b"historical completion before current NativeValid",
    );
    let registration = core
        .step(
            Input::SyncedProposal(Box::new(proposed.clone())),
            &RootSignatures,
        )
        .expect("historical synced proposal registration persists");
    let validation = release_persisted_effects(&mut core, registration);
    let historical_id = synced_validation_effect(&validation);
    let unavailable = core
        .step(
            Input::SyncedPayloadValidated {
                id: historical_id,
                result: PayloadValidationResult::Unavailable,
            },
            &RootSignatures,
        )
        .expect("historical Unavailable completion persists");
    let (barrier, historical_state) = persistence_effect(&unavailable);
    assert_eq!(historical_state.payload_validation_completions().len(), 1);
    assert_eq!(
        historical_state.payload_validation_completions()[0].id(),
        historical_id
    );
    assert!(core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("historical completion persistence is acknowledged")
        .is_empty());
    (config, core, proposed, historical_id)
}

fn current_native_valid_with_historical_completion_v0(
) -> (CoreConfig, SafetyState, ValidationId, ValidationId) {
    let (config, mut core, proposed, historical_id) = historical_unavailable_synced_completion_v0();
    let registration = core
        .step(Input::SyncedProposal(Box::new(proposed)), &RootSignatures)
        .expect("the same proposal registers under a fresh generation");
    let validation = release_persisted_effects(&mut core, registration);
    let current_id = synced_validation_effect(&validation);
    assert_ne!(current_id, historical_id);
    let result = valid_result_for_effect(&core, &validation, current_id);
    let callback = core
        .step(
            Input::SyncedPayloadValidated {
                id: current_id,
                result,
            },
            &RootSignatures,
        )
        .expect("current Valid completion persists beside history");
    let (_, state) = persistence_effect(&callback);
    assert_eq!(state.payload_validation_completions().len(), 2);
    (config, state, historical_id, current_id)
}

#[test]
fn native_valid_completion_recovery_accepts_history_and_one_current_valid_v0() {
    let (config, state, historical_id, current_id) =
        current_native_valid_with_historical_completion_v0();
    let historical = state
        .payload_validation_completions()
        .iter()
        .find(|completion| completion.id() == historical_id)
        .expect("historical completion remains durable");
    let current = state
        .payload_validation_completions()
        .iter()
        .find(|completion| completion.id() == current_id)
        .expect("current Valid completion remains durable");
    assert!(historical.first_recorded_revision() < state.revision());
    assert_eq!(current.first_recorded_revision(), state.revision());
    assert!(current.result().is_valid());

    let session = Core::begin_native_valid_completion_recovery_v0(config, state, &RootSignatures)
        .expect("bounded recovery selects the unique current Valid completion");
    assert_eq!(session.challenge().validation_id_v0(), current_id);
    assert_eq!(
        session.challenge().route_v0(),
        PayloadValidationRouteV0::Synced
    );
}

#[test]
fn native_valid_completion_recovery_rejects_two_current_revision_completions_v0() {
    let (config, state, historical_id, _current_id) =
        current_native_valid_with_historical_completion_v0();
    let mut completions = state.payload_validation_completions().to_vec();
    let historical = completions
        .iter_mut()
        .find(|completion| completion.id() == historical_id)
        .expect("historical completion remains durable");
    *historical = DurablePayloadValidationCompletionV0::new(
        historical.route(),
        historical.id(),
        historical.result(),
        state.revision(),
    );
    let two_current = decoded_state_with_validation_records(&state, Vec::new(), completions);

    assert!(matches!(
        Core::begin_native_valid_completion_recovery_v0(config, two_current, &RootSignatures),
        Err(CoreError::NativeValidCompletionRecoveryRejected(
            "bounded recovery requires exactly one completion first recorded at the current revision"
        ))
    ));
}

#[test]
fn native_valid_completion_recovery_ignores_only_historical_completions_v0() {
    let (config, mut core, proposed, historical_id) = historical_unavailable_synced_completion_v0();
    let registration = core
        .step(Input::SyncedProposal(Box::new(proposed)), &RootSignatures)
        .expect("a fresh synced generation persists");
    let validation = release_persisted_effects(&mut core, registration);
    let pending_id = synced_validation_effect(&validation);
    let cancellation = core
        .step(
            Input::CancelSyncedPayloadValidation { id: pending_id },
            &RootSignatures,
        )
        .expect("canceling the fresh generation advances the durable revision");
    let (_, state) = persistence_effect(&cancellation);
    assert!(state.payload_validation_obligations().is_empty());
    assert_eq!(state.payload_validation_completions().len(), 1);
    let historical = &state.payload_validation_completions()[0];
    assert_eq!(historical.id(), historical_id);
    assert!(historical.first_recorded_revision() < state.revision());

    assert!(matches!(
        Core::begin_native_valid_completion_recovery_v0(config, state, &RootSignatures),
        Err(CoreError::NativeValidCompletionRecoveryNotRequired)
    ));
}

#[test]
fn native_valid_completion_recovery_rejects_noncurrent_multiple_and_foreign_v0() {
    let (config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(
        &set,
        genesis_qc(&set),
        1,
        b"native Valid recovery rejection",
    );
    let registration = core
        .step(Input::Proposal(Box::new(proposed)), &RootSignatures)
        .expect("proposal registration persists");
    let validation = release_persisted_effects(&mut core, registration);
    let id = validation_effect(&validation);
    let result = valid_result_for_effect(&core, &validation, id);
    let callback = core
        .step(Input::PayloadValidated { id, result }, &RootSignatures)
        .expect("Valid callback persists");
    let persisted = persistence_request(&callback).state().clone();
    let action = persistence_request(&callback)
        .native_valid_post_ack_action_v0()
        .expect("NativeValid action exists");

    let first = Core::begin_native_valid_completion_recovery_v0(
        config.clone(),
        persisted.clone(),
        &RootSignatures,
    )
    .expect("first inert session");
    let second = Core::begin_native_valid_completion_recovery_v0(
        config.clone(),
        persisted.clone(),
        &RootSignatures,
    )
    .expect("second inert session");
    let mut reconciler = ExactNativeValidCompletionRecoveryReconcilerV0 {
        expected_state: persisted.clone(),
        expected_record_checksum: [0x44; 32],
        expected_action: action,
        accept: true,
        calls: 0,
    };
    assert!(matches!(
        first.challenge().attest_authenticated_reconciliation_v0(
            &persisted,
            [0; 32],
            action,
            &mut reconciler,
        ),
        Err(CoreError::NativeValidCompletionRecoveryRejected(
            "authenticated SafetyStore record checksum is zero"
        ))
    ));
    assert!(matches!(
        first.challenge().attest_authenticated_reconciliation_v0(
            &persisted,
            [0x44; 32],
            NativeValidPostAckActionV0::RequestTcHighQcSync,
            &mut reconciler,
        ),
        Err(CoreError::NativeValidCompletionRecoveryRejected(
            "the recorded post-ack action is incompatible with the durable outbox state"
        ))
    ));
    let mut rejecting = ExactNativeValidCompletionRecoveryReconcilerV0 {
        expected_state: persisted.clone(),
        expected_record_checksum: [0x44; 32],
        expected_action: action,
        accept: false,
        calls: 0,
    };
    assert!(matches!(
        first.challenge().attest_authenticated_reconciliation_v0(
            &persisted,
            [0x44; 32],
            action,
            &mut rejecting,
        ),
        Err(CoreError::NativeValidCompletionRecoveryRejected(
            "the trusted host rejected the exact SafetyStore/ApplicationStore tuple"
        ))
    ));
    assert_eq!(rejecting.calls, 1);
    let foreign = first
        .challenge()
        .attest_authenticated_reconciliation_v0(&persisted, [0x44; 32], action, &mut reconciler)
        .expect("first session mints its own attestation");
    assert!(matches!(
        second.reconcile_and_activate_v0(foreign),
        Err(CoreError::NativeValidCompletionRecoveryRejected(
            "recovery attestation belongs to a different session or SafetyState"
        ))
    ));

    let mut two = persisted.payload_validation_completions().to_vec();
    let base = &two[0];
    let second_id = ValidationId::new(
        base.id().block_id(),
        base.id().view(),
        base.id()
            .generation()
            .checked_add(1)
            .expect("test generation"),
    );
    two.push(DurablePayloadValidationCompletionV0::new(
        PayloadValidationRouteV0::Synced,
        second_id,
        base.result(),
        persisted.revision(),
    ));
    two.sort_by_key(DurablePayloadValidationCompletionV0::key);
    let multiple = decoded_state_with_validation_records(&persisted, Vec::new(), two);
    assert!(matches!(
        Core::begin_native_valid_completion_recovery_v0(config.clone(), multiple, &RootSignatures,),
        Err(CoreError::NativeValidCompletionRecoveryRejected(
            "bounded recovery requires exactly one completion first recorded at the current revision"
        ))
    ));

    let old = SafetyState::from_persisted_parts(
        persisted.schema_version(),
        persisted.chain_id(),
        persisted.protocol_version(),
        persisted.epoch(),
        persisted.validator_set_id(),
        persisted.genesis_block_id(),
        persisted.current_view(),
        persisted.last_voted_view(),
        persisted.last_timeout_view(),
        persisted.high_qc().clone(),
        persisted.locked_qc().clone(),
        persisted.finalized(),
        persisted.revision().checked_add(1).expect("test revision"),
        persisted.payload_terminal_facts().to_vec(),
        Vec::new(),
        persisted.payload_validation_completions().to_vec(),
        persisted.pending_tc_high_qc_sync().cloned(),
        persisted.pending_standalone_qc_sync().cloned(),
        persisted.pending_sign().cloned(),
        persisted.last_finalization().cloned(),
        persisted.pending_finalize(),
        persisted.safety_halt().cloned(),
    );
    assert!(matches!(
        Core::begin_native_valid_completion_recovery_v0(config, old, &RootSignatures),
        Err(CoreError::NativeValidCompletionRecoveryNotRequired)
    ));

    let (anchor_config, proof, _h1, _h2, _h3) = h1_state_sync_fixture();
    let anchored =
        Core::prepare_h1_state_sync_bootstrap_v0(anchor_config.clone(), proof, &RootSignatures)
            .expect("exact h1 bootstrap")
            .into_safety_state();
    assert!(matches!(
        Core::begin_native_valid_completion_recovery_v0(anchor_config, anchored, &RootSignatures,),
        Err(CoreError::NativeValidCompletionRecoveryRejected(
            "state-sync anchored NativeValid completion requires its bounded successor protocol"
        ))
    ));

    let (obligation_config, mut obligation_core) = configured_core();
    let obligation_set = obligation_core.config().validator_set().clone();
    let obligation_proposal = proposal(
        &obligation_set,
        genesis_qc(&obligation_set),
        1,
        b"ordinary obligation cannot enter completion recovery",
    );
    let obligation_effects = obligation_core
        .step(
            Input::Proposal(Box::new(obligation_proposal)),
            &RootSignatures,
        )
        .expect("ordinary proposal creates one obligation");
    let (_, obligation_state) = persistence_effect(&obligation_effects);
    assert!(matches!(
        Core::begin_native_valid_completion_recovery_v0(
            obligation_config,
            obligation_state,
            &RootSignatures,
        ),
        Err(CoreError::NativeValidCompletionRecoveryRejected(
            "NativeValid completion recovery cannot overlap a validation obligation"
        ))
    ));

    let (unavailable_config, mut unavailable_core) = configured_core();
    let unavailable_set = unavailable_core.config().validator_set().clone();
    let unavailable_proposal = proposal(
        &unavailable_set,
        genesis_qc(&unavailable_set),
        1,
        b"Unavailable completion cannot enter NativeValid recovery",
    );
    let unavailable_registration = unavailable_core
        .step(
            Input::SyncedProposal(Box::new(unavailable_proposal)),
            &RootSignatures,
        )
        .expect("synced proposal creates one obligation");
    let unavailable_validation =
        release_persisted_effects(&mut unavailable_core, unavailable_registration);
    let unavailable_id = synced_validation_effect(&unavailable_validation);
    let unavailable_effects = unavailable_core
        .step(
            Input::SyncedPayloadValidated {
                id: unavailable_id,
                result: PayloadValidationResult::Unavailable,
            },
            &RootSignatures,
        )
        .expect("Unavailable closes the exact durable generation");
    let (_, unavailable_state) = persistence_effect(&unavailable_effects);
    assert!(matches!(
        Core::begin_native_valid_completion_recovery_v0(
            unavailable_config,
            unavailable_state,
            &RootSignatures,
        ),
        Err(CoreError::NativeValidCompletionRecoveryRejected(
            "the current durable completion is not Valid"
        ))
    ));
}

fn assert_rejected_without_state_change(core: &mut Core, input: Input) {
    let before = core.clone();
    assert!(matches!(
        core.step(input, &RejectSignatures),
        Err(CoreError::Protocol(_))
    ));
    assert_eq!(core, &before);
}

fn assert_epoch_boundary_rejected_without_state_change(
    core: &mut Core,
    input: Input,
    height: u64,
    checkpoint_height: u64,
) {
    let before = core.clone();
    assert_eq!(
        core.step(input, &RootSignatures),
        Err(CoreError::EpochBoundaryUnsupported {
            height: Height::new(height),
            checkpoint_height: Height::new(checkpoint_height),
        })
    );
    assert_eq!(core, &before);
}

fn validation_effect(effects: &[Effect]) -> ValidationId {
    effects
        .iter()
        .find_map(|effect| match effect {
            Effect::ValidatePayload(request) => Some(request.id()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("expected a payload-validation effect: {effects:?}"))
}

fn synced_validation_effect(effects: &[Effect]) -> ValidationId {
    effects
        .iter()
        .find_map(|effect| match effect {
            Effect::ValidateSyncedPayload(request) => Some(request.id()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("expected a synced-payload validation effect: {effects:?}"))
}

fn validation_block(effects: &[Effect], expected_id: ValidationId) -> &Block {
    effects
        .iter()
        .find_map(|effect| match effect {
            Effect::ValidatePayload(request) | Effect::ValidateSyncedPayload(request)
                if request.id() == expected_id =>
            {
                Some(request.block())
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("expected validation block for {expected_id:?}: {effects:?}"))
}

fn into_validation_request(effects: Vec<Effect>) -> PayloadValidationRequest {
    effects
        .into_iter()
        .find_map(|effect| match effect {
            Effect::ValidatePayload(request) | Effect::ValidateSyncedPayload(request) => {
                Some(request)
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("expected an owned payload-validation request"))
}

fn valid_commitments(core: &Core, block: &Block) -> ValidatedBlockCommitmentsV0 {
    valid_commitments_for_config(core.config(), block)
}

fn valid_commitments_for_config(config: &CoreConfig, block: &Block) -> ValidatedBlockCommitmentsV0 {
    let application_payload = decode_application_payload_v0_exact(
        block.application_payload(),
        config.consensus_parameters(),
    )
    .expect("core test block carries exact application payload CEV0");
    let receipts = ExecutionReceiptsV0::new(
        &application_payload,
        (0..application_payload.transaction_count())
            .map(|index| {
                ExecutionReceiptCommitmentV0::for_transaction(
                    &application_payload,
                    index,
                    0,
                    0,
                    Vec::new(),
                )
                .expect("canonical test receipt")
            })
            .collect(),
    )
    .expect("canonical test receipt list");
    let evidence = block
        .evidence_objects()
        .iter()
        .map(|bytes| {
            decode_double_vote_evidence_v0_exact(bytes, config.validator_set())
                .expect("core test block carries exact evidence CEV0")
        })
        .collect();
    let body = BlockBodyV0::new(application_payload, evidence).expect("canonical test block body");
    body.validate_ordinary_commitments(
        block.header(),
        &receipts,
        config.consensus_parameters(),
        config.validator_set(),
        &RootSignatures,
    )
    .expect("canonical core-test block mints the B2-D commitment capability")
}

fn artifact_ref_for_ids(block_id: BlockId, parent_id: BlockId) -> ValidatedPayloadArtifactRefV0 {
    let mut overlay_checksum = *block_id.as_bytes();
    overlay_checksum[0] ^= 0x5a;
    let mut source_artifact_checksum = *block_id.as_bytes();
    source_artifact_checksum[0] ^= 0xa5;
    ValidatedPayloadArtifactRefV0::new(
        BlockIdOverlayRefV0::new(block_id, parent_id, overlay_checksum),
        source_artifact_checksum,
    )
}

fn valid_result(core: &Core, block: &Block) -> PayloadValidationResult {
    let block_id = block.id();
    let parent_id = block.header().parent_id();
    PayloadValidationResult::authorized_valid_v0(
        valid_commitments(core, block),
        artifact_ref_for_ids(block_id, parent_id),
    )
}

fn valid_result_for_effect(
    core: &Core,
    effects: &[Effect],
    id: ValidationId,
) -> PayloadValidationResult {
    valid_result(core, validation_block(effects, id))
}

fn persistence_effect(effects: &[Effect]) -> (BarrierId, SafetyState) {
    match effects {
        [Effect::PersistSafetyState(request)] => (request.barrier(), request.state().clone()),
        _ => panic!("expected exactly one persistence effect: {effects:?}"),
    }
}

fn persistence_request(effects: &[Effect]) -> &SafetyStatePersistenceV0 {
    match effects {
        [Effect::PersistSafetyState(request)] => request,
        _ => panic!("expected exactly one persistence effect: {effects:?}"),
    }
}

#[test]
fn exact_proposal_retention_preserves_unavailable_retry_then_freezes_valid_body() {
    let (_config, core) = configured_core();
    let set = core.config().validator_set().clone();
    let valid = proposal(
        &set,
        genesis_qc(&set),
        1,
        b"validated body retained exactly",
    );
    let unavailable = same_signed_envelope_with_body_bytes(&set, &valid, vec![0xff]);
    assert_eq!(unavailable.block().header(), valid.block().header());
    assert_eq!(unavailable.witness(), valid.witness());
    assert_ne!(unavailable, valid);

    let mut tree = BlockTree::new(4, usize::MAX);
    tree.insert_verified_proposal(&unavailable, &[])
        .expect("first source fixes only header and witness");
    assert_eq!(
        tree.record_payload_validation_for_proposal(
            &unavailable,
            PayloadValidationResult::Unavailable,
        )
        .expect("Unavailable remains source-scoped"),
        PayloadTransition::Unavailable,
    );
    assert!(tree.validated_proposal(valid.block().id()).is_none());
    tree.insert_verified_proposal(&valid, &[])
        .expect("a different body source remains admissible before Valid");

    let result = valid_result(&core, valid.block());
    assert_eq!(
        tree.record_payload_validation_for_proposal(&valid, result)
            .expect("the exact application-Valid body becomes frozen"),
        PayloadTransition::BecameValid,
    );
    assert_eq!(tree.validated_proposal(valid.block().id()), Some(&valid));
    tree.insert_verified_proposal(&valid, &[])
        .expect("exact frozen proposal replay is idempotent");
    assert_eq!(
        tree.record_payload_validation_for_proposal(&valid, result)
            .expect("exact Valid replay remains idempotent"),
        PayloadTransition::RepeatedTerminal,
    );
    assert_eq!(
        tree.insert_verified_proposal(&unavailable, &[]),
        Err(CoreError::ConflictingBlock(valid.block().id())),
        "a pre-Valid body cannot replace the frozen exact proposal",
    );
}

#[test]
fn aggregate_validated_proposal_retention_budget_is_exact_and_transactional() {
    let (_config, core) = configured_core();
    let set = core.config().validator_set().clone();
    let first = proposal(
        &set,
        genesis_qc(&set),
        1,
        b"first aggregate retained proposal",
    );
    let second = proposal(
        &set,
        genesis_qc(&set),
        1,
        b"second aggregate retained proposal",
    );
    let first_bytes = first
        .durable_validation_resource_size_v0()
        .expect("first deterministic retention charge");
    let second_bytes = second
        .durable_validation_resource_size_v0()
        .expect("second deterministic retention charge");
    let exact_total = first_bytes
        .checked_add(second_bytes)
        .expect("test retention total");
    let maximum = exact_total - 1;

    let mut tree = BlockTree::new(4, maximum);
    for proposed in [&first, &second] {
        tree.insert_verified_proposal(proposed, &[])
            .expect("bounded sibling proposal inserts");
    }
    assert_eq!(
        tree.record_payload_validation_for_proposal(&first, valid_result(&core, first.block()),)
            .expect("first retained proposal fits"),
        PayloadTransition::BecameValid,
    );
    assert_eq!(tree.retained_validated_proposal_bytes(), first_bytes);
    assert!(tree.retention_accounting_is_exact_for_test());

    let before_rejection = tree.clone();
    assert_eq!(
        tree.record_payload_validation_for_proposal(&second, valid_result(&core, second.block()),),
        Err(CoreError::ValidatedProposalRetentionBudgetExceeded {
            retained: first_bytes,
            requested: second_bytes,
            maximum,
        }),
    );
    assert_eq!(
        tree, before_rejection,
        "budget failure mutates no tree fact"
    );

    tree.set_retention_budget_for_test(exact_total);
    assert_eq!(
        tree.record_payload_validation_for_proposal(&second, valid_result(&core, second.block()),)
            .expect("the exact aggregate budget admits the second proposal"),
        PayloadTransition::BecameValid,
    );
    assert_eq!(tree.retained_validated_proposal_bytes(), exact_total);
    assert_eq!(
        tree.record_payload_validation_for_proposal(&second, valid_result(&core, second.block()),)
            .expect("an exact Valid replay is not charged twice"),
        PayloadTransition::RepeatedTerminal,
    );
    assert_eq!(tree.retained_validated_proposal_bytes(), exact_total);
    assert!(tree.retention_accounting_is_exact_for_test());
}

#[test]
fn invalid_valid_overlay_is_rejected_before_retention_capacity() {
    let (_config, core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(
        &set,
        genesis_qc(&set),
        1,
        b"invalid overlay before retention capacity",
    );
    let block_id = proposed.block().id();
    let wrong_parent = BlockId::new([0x6d; 32]);
    assert_ne!(wrong_parent, proposed.block().header().parent_id());
    let result = PayloadValidationResult::authorized_valid_v0(
        valid_commitments(&core, proposed.block()),
        artifact_ref_for_ids(block_id, wrong_parent),
    );
    let mut tree = BlockTree::new(4, 0);
    tree.insert_verified_proposal(&proposed, &[])
        .expect("invalid-overlay target header and witness insert");
    let before = tree.clone();

    assert_eq!(
        tree.record_payload_validation_for_proposal(&proposed, result),
        Err(CoreError::ConflictingPayloadValidation(block_id)),
    );
    assert_eq!(tree, before);
}

#[test]
fn frozen_body_conflict_precedes_overlay_and_retention_errors() {
    let (_config, core) = configured_core();
    let set = core.config().validator_set().clone();
    let valid = proposal(
        &set,
        genesis_qc(&set),
        1,
        b"frozen body conflict error order",
    );
    let conflicting = same_signed_envelope_with_body_bytes(&set, &valid, vec![0xff]);
    assert_eq!(conflicting.block().id(), valid.block().id());
    assert_eq!(conflicting.witness(), valid.witness());
    assert_ne!(conflicting, valid);
    let retained = valid
        .durable_validation_resource_size_v0()
        .expect("deterministic frozen proposal charge");
    let mut tree = BlockTree::new(4, retained);
    tree.insert_verified_proposal(&valid, &[])
        .expect("frozen-body target inserts");
    tree.record_payload_validation_for_proposal(&valid, valid_result(&core, valid.block()))
        .expect("exact body becomes application-Valid");
    let wrong_parent = BlockId::new([0x6e; 32]);
    assert_ne!(wrong_parent, valid.block().header().parent_id());
    let doubly_invalid = PayloadValidationResult::authorized_valid_v0(
        valid_commitments(&core, valid.block()),
        artifact_ref_for_ids(valid.block().id(), wrong_parent),
    );
    let before = tree.clone();

    assert_eq!(
        tree.record_payload_validation_for_proposal(&conflicting, doubly_invalid),
        Err(CoreError::ConflictingBlock(valid.block().id())),
    );
    assert_eq!(tree, before);
}

#[test]
fn authenticated_valid_restore_obeys_the_same_pre_mutation_retention_budget() {
    let (_config, core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(
        &set,
        genesis_qc(&set),
        1,
        b"authenticated restore retention budget",
    );
    let requested = proposed
        .durable_validation_resource_size_v0()
        .expect("deterministic restore charge");
    let maximum = requested - 1;
    let overlay =
        artifact_ref_for_ids(proposed.block().id(), proposed.block().header().parent_id())
            .overlay();
    let mut tree = BlockTree::new(4, maximum);
    tree.insert_verified_proposal(&proposed, &[])
        .expect("restore target header and witness insert");
    let before_rejection = tree.clone();

    assert_eq!(
        tree.restore_authenticated_valid_overlay_v0(&proposed, overlay),
        Err(CoreError::ValidatedProposalRetentionBudgetExceeded {
            retained: 0,
            requested,
            maximum,
        }),
    );
    assert_eq!(tree, before_rejection, "restore rejection is transactional");

    tree.set_retention_budget_for_test(requested);
    tree.restore_authenticated_valid_overlay_v0(&proposed, overlay)
        .expect("the exact restore budget admits the immutable proposal");
    assert_eq!(
        tree.validated_proposal(proposed.block().id()),
        Some(&proposed)
    );
    assert_eq!(tree.retained_validated_proposal_bytes(), requested);
    assert!(tree.retention_accounting_is_exact_for_test());
}

#[test]
fn finalization_pruning_releases_every_removed_retention_charge() {
    let (_config, core) = configured_core();
    let set = core.config().validator_set().clone();
    let p1 = proposal(&set, genesis_qc(&set), 1, b"pruned retained proposal one");
    let p2 = proposal(
        &set,
        qc(&set, 1, 1, p1.block().id()),
        2,
        b"pruned retained proposal two",
    );
    let p3 = proposal(
        &set,
        qc(&set, 2, 2, p2.block().id()),
        3,
        b"retained finalized proposal three",
    );
    let mut tree = BlockTree::new(8, usize::MAX);
    for proposed in [&p1, &p2, &p3] {
        tree.insert_verified_proposal(proposed, &[])
            .expect("finalization path proposal inserts");
        tree.record_payload_validation_for_proposal(
            proposed,
            valid_result(&core, proposed.block()),
        )
        .expect("finalization path proposal becomes application-Valid");
    }
    let p3_bytes = p3
        .durable_validation_resource_size_v0()
        .expect("deterministic surviving proposal charge");

    tree.prune_below(3, p3.block().id(), &[])
        .expect("finalization pruning releases the older exact bodies");
    assert!(!tree.contains_header(p1.block().id()));
    assert!(!tree.contains_header(p2.block().id()));
    assert!(tree.contains_header(p3.block().id()));
    assert_eq!(tree.retained_validated_proposal_bytes(), p3_bytes);
    assert!(tree.retention_accounting_is_exact_for_test());
}

#[test]
fn core_valid_callback_enforces_budget_and_retained_cache_clones_share_allocation() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(&set, genesis_qc(&set), 1, b"core callback retention budget");
    let block_id = proposed.block().id();
    let requested = proposed
        .durable_validation_resource_size_v0()
        .expect("deterministic callback charge");
    let maximum = requested - 1;
    let registration = core
        .step(Input::Proposal(Box::new(proposed)), &RootSignatures)
        .expect("proposal registration persists");
    let validation = release_persisted_effects(&mut core, registration);
    let id = validation_effect(&validation);
    let result = valid_result_for_effect(&core, &validation, id);
    let before_safety = core.safety_state().clone();
    let before_pending = core.pending_validation_count();
    core.set_validated_proposal_retention_budget_for_test_v1(maximum);

    assert_eq!(
        core.step(Input::PayloadValidated { id, result }, &RootSignatures,),
        Err(CoreError::ValidatedProposalRetentionBudgetExceeded {
            retained: 0,
            requested,
            maximum,
        }),
    );
    assert_eq!(core.safety_state(), &before_safety);
    assert_eq!(core.pending_validation_count(), before_pending);
    assert_eq!(core.retained_validated_proposal_bytes_for_test_v1(), 0);
    assert!(core.retained_proposal_accounting_is_exact_for_test_v1());

    core.set_validated_proposal_retention_budget_for_test_v1(requested);
    let effects = core
        .step(Input::PayloadValidated { id, result }, &RootSignatures)
        .expect("the exact retention budget admits the Valid callback");
    assert!(matches!(
        effects.as_slice(),
        [Effect::PersistSafetyState(_)]
    ));
    assert_eq!(
        core.retained_validated_proposal_bytes_for_test_v1(),
        requested,
    );
    assert!(core.retained_proposal_accounting_is_exact_for_test_v1());
    let cloned = core.clone();
    assert!(core.retained_proposal_allocation_is_shared_for_test_v1(&cloned, block_id));
    assert_eq!(
        cloned.retained_validated_proposal_bytes_for_test_v1(),
        requested,
    );
}

#[test]
fn core_config_rejects_one_message_larger_than_the_retention_hard_cap() {
    let mut fields = consensus_parameters().fields();
    fields.max_consensus_message_bytes =
        u32::try_from(CORE_MAX_RETAINED_VALIDATED_PROPOSAL_RESOURCE_BYTES_V1 + 1)
            .expect("the fixed retention cap fits below u32::MAX");
    let parameters = ConsensusParametersV0::new(fields).expect("protocol parameters remain valid");
    let set = validator_set_with_parameters(&parameters);
    assert_eq!(
        CoreConfig::new(
            validator_id(1),
            set,
            parameters,
            GENESIS_TIMESTAMP_MS,
            32,
            64,
        ),
        Err(CoreError::InvalidConfig(
            "one consensus message may exceed the retained-proposal hard cap",
        )),
    );
}

#[test]
fn deterministic_invalid_restore_cannot_freeze_or_replace_a_complete_proposal() {
    let set = validator_set();
    let proposed = proposal(
        &set,
        genesis_qc(&set),
        1,
        b"deterministic invalid retention boundary",
    );
    let mut tree = BlockTree::new(4, usize::MAX);
    tree.insert_verified_proposal(&proposed, &[])
        .expect("proposal header and witness insert");
    assert_eq!(
        tree.record_deterministically_invalid(proposed.block().id())
            .expect("narrow durable-invalid restore is accepted"),
        PayloadTransition::BecameDeterministicallyInvalid,
    );
    assert!(tree.validated_proposal(proposed.block().id()).is_none());
    assert_eq!(
        tree.record_deterministically_invalid(proposed.block().id())
            .expect("exact deterministic-invalid replay is idempotent"),
        PayloadTransition::RepeatedTerminal,
    );
}

#[test]
fn exact_validated_path_is_bounded_and_requires_every_frozen_edge() {
    let (_config, core) = configured_core();
    let set = core.config().validator_set().clone();
    let p1 = proposal(&set, genesis_qc(&set), 1, b"retained path one");
    let q1 = qc(&set, 1, 1, p1.block().id());
    let p2 = proposal(&set, q1, 2, b"retained path two");
    let q2 = qc(&set, 2, 2, p2.block().id());
    let p3 = proposal(&set, q2, 3, b"retained path three");
    let finalized = FinalizedTip::new(Height::new(0), View::new(0), GENESIS, GENESIS_TIMESTAMP_MS);

    let mut complete = BlockTree::new(8, usize::MAX);
    for proposal in [&p1, &p2, &p3] {
        complete
            .insert_verified_proposal(proposal, &[])
            .expect("complete path proposal inserts");
        complete
            .record_payload_validation_for_proposal(proposal, valid_result(&core, proposal.block()))
            .expect("complete path body freezes after Valid");
    }
    assert_eq!(
        complete
            .exact_validated_proposal_path(
                p3.block().id(),
                finalized,
                3,
                core.config().max_block_time_step_ms(),
            )
            .expect("three exact frozen proposals form the path"),
        vec![&p1, &p2, &p3],
    );
    assert!(complete
        .exact_validated_proposal_path(
            p3.block().id(),
            finalized,
            2,
            core.config().max_block_time_step_ms(),
        )
        .is_none());

    let mut missing = BlockTree::new(8, usize::MAX);
    for proposal in [&p1, &p2, &p3] {
        missing
            .insert_verified_proposal(proposal, &[])
            .expect("path header and witness insert");
    }
    for proposal in [&p1, &p3] {
        missing
            .record_payload_validation_for_proposal(proposal, valid_result(&core, proposal.block()))
            .expect("selected path body freezes");
    }
    assert!(missing
        .exact_validated_proposal_path(
            p3.block().id(),
            finalized,
            3,
            core.config().max_block_time_step_ms(),
        )
        .is_none());

    let wrong_finalized_edge = FinalizedTip::new(
        Height::new(0),
        View::new(0),
        GENESIS,
        p1.block().header().timestamp_ms(),
    );
    assert!(complete
        .exact_validated_proposal_path(
            p3.block().id(),
            wrong_finalized_edge,
            3,
            core.config().max_block_time_step_ms(),
        )
        .is_none());
}

#[test]
fn exact_proposal_retention_remains_bounded_and_honors_protected_nodes() {
    let (_config, core) = configured_core();
    let set = core.config().validator_set().clone();
    let genesis = genesis_qc(&set);
    let first = proposal(&set, genesis.clone(), 1, b"protected retained proposal");
    let mut side_branches = vec![first.clone()];
    for timed_out_view in 1..=4 {
        side_branches.push(timeout_proposal(
            &set,
            timeout_certificate(&set, timed_out_view, genesis.clone()),
            &[0x90 + timed_out_view as u8],
        ));
    }

    let mut tree = BlockTree::new(4, usize::MAX);
    for proposal in &side_branches[..4] {
        tree.insert_verified_proposal(proposal, &[])
            .expect("bounded side branch inserts");
        tree.record_payload_validation_for_proposal(
            proposal,
            valid_result(&core, proposal.block()),
        )
        .expect("the retained side branch becomes application-Valid");
    }
    let before_eviction = tree.retained_validated_proposal_bytes();
    let evicted_bytes = side_branches[1]
        .durable_validation_resource_size_v0()
        .expect("deterministic evicted proposal charge");
    tree.insert_verified_proposal(&side_branches[4], &[first.block().id()])
        .expect("one unprotected side branch is evicted");
    assert!(tree.contains_header(first.block().id()));
    assert!(tree.contains_header(side_branches[4].block().id()));
    assert!(!tree.contains_header(side_branches[1].block().id()));
    assert_eq!(
        tree.retained_validated_proposal_bytes(),
        before_eviction - evicted_bytes,
    );
    assert!(tree.retention_accounting_is_exact_for_test());
}

#[test]
fn persistence_effects_are_affined_to_the_issuing_core_instance() {
    let (config, mut core) = configured_core();
    let previous = core.safety_state().clone();
    let binding = core.safety_state_persistence_binding_v0();
    let mut public_clone = core.clone();
    let clone_binding = public_clone.safety_state_persistence_binding_v0();
    let input = Input::LocalTimeout {
        epoch: Epoch::new(0),
        view: previous.current_view(),
    };

    let original_effects = core
        .step(input.clone(), &RootSignatures)
        .expect("the designated Core emits its persistence request");
    let clone_effects = public_clone
        .step(input, &RootSignatures)
        .expect("the public clone emits an otherwise equal persistence request");
    assert_eq!(original_effects, clone_effects);

    let [Effect::PersistSafetyState(original)] = original_effects.as_slice() else {
        panic!("designated Core emitted a non-persistence effect: {original_effects:?}");
    };
    let [Effect::PersistSafetyState(cloned)] = clone_effects.as_slice() else {
        panic!("cloned Core emitted a non-persistence effect: {clone_effects:?}");
    };
    assert!(binding.accepts(original));
    assert!(!binding.accepts(cloned));
    assert!(clone_binding.accepts(cloned));
    assert!(!clone_binding.accepts(original));
    let retry = (*original).clone();
    assert!(binding.accepts(&retry));
    Core::validate_persisted_successor_v0(&config, &previous, original.state(), &RootSignatures)
        .expect("a successful internal transactional clone preserves Core affinity and history");
}

fn conflicting_qc_halt_persistence(
    effects: &[Effect],
    expected_first: &QuorumCertificate,
    expected_second: &QuorumCertificate,
) -> (BarrierId, SafetyState) {
    assert!(
        effects
            .iter()
            .all(|effect| matches!(effect, Effect::PersistSafetyState(_) | Effect::Evidence(_))),
        "a QC-conflict step may expose only persistence plus diagnostic evidence: {effects:?}"
    );
    let mut persisted = effects.iter().filter_map(|effect| match effect {
        Effect::PersistSafetyState(request) => Some((request.barrier(), request.state().clone())),
        _ => None,
    });
    let (barrier, state) = persisted
        .next()
        .unwrap_or_else(|| panic!("QC conflict did not persist its halt: {effects:?}"));
    assert!(
        persisted.next().is_none(),
        "QC conflict crossed more than one persistence barrier: {effects:?}"
    );
    let (first, second) = state
        .safety_halt()
        .and_then(SafetyHalt::conflicting_qcs)
        .expect("same-view conflict retains both complete QCs");
    let retained = [first.id(), second.id()];
    assert!(retained.contains(&expected_first.id()));
    assert!(retained.contains(&expected_second.id()));
    (barrier, state)
}

fn signature_request(effects: &[Effect]) -> (SignId, SigningRoot) {
    match effects {
        [Effect::RequestSignature { intent }] => {
            (SignId::new(intent.signing_root()), intent.signing_root())
        }
        _ => panic!("expected exactly one signature request: {effects:?}"),
    }
}

fn insert_valid_and_vote(core: &mut Core, proposal: SignedProposalV0) {
    let effects = core
        .step(Input::Proposal(Box::new(proposal)), &RootSignatures)
        .expect("proposal accepted");
    let effects = release_persisted_effects(core, effects);
    let id = validation_effect(&effects);
    let result = valid_result_for_effect(core, &effects, id);
    let effects = core
        .step(Input::PayloadValidated { id, result }, &RootSignatures)
        .expect("valid payload result accepted");
    let (barrier, _) = persistence_effect(&effects);
    let request = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("vote intent durable");
    let (sign_id, root) = signature_request(&request);
    assert!(matches!(
        core.step(
            Input::SignatureReady {
                id: sign_id,
                signature: signature(root),
            },
            &RootSignatures,
        )
        .expect("vote signature accepted")
        .as_slice(),
        [Effect::Broadcast(OutboundMessage::Vote(_))]
    ));
}

fn replay_valid(core: &mut Core, proposal: SignedProposalV0) {
    let effects = core
        .step(Input::SyncedProposal(Box::new(proposal)), &RootSignatures)
        .expect("replay proposal accepted");
    let effects = release_persisted_effects(core, effects);
    let id = match effects.as_slice() {
        [Effect::ValidateSyncedPayload(request)] => request.id(),
        _ => panic!("expected synced-payload validation: {effects:?}"),
    };
    let result = valid_result_for_effect(core, &effects, id);
    let effects = core
        .step(
            Input::SyncedPayloadValidated { id, result },
            &RootSignatures,
        )
        .expect("replay payload accepted");
    assert!(release_persisted_effects(core, effects).is_empty());
}

fn release_persisted_effects(core: &mut Core, effects: Vec<Effect>) -> Vec<Effect> {
    let barrier = effects.iter().find_map(|effect| match effect {
        Effect::PersistSafetyState(request) => Some(request.barrier()),
        _ => None,
    });
    match barrier {
        Some(barrier) => core
            .step(Input::StorageAck { barrier }, &RootSignatures)
            .expect("safety-state persistence acknowledged"),
        None => effects,
    }
}

#[test]
fn genesis_safety_state_has_no_payload_validation_records() {
    let (_config, core) = configured_core();

    assert!(
        core.safety_state()
            .payload_validation_obligations()
            .is_empty(),
        "genesis must not synthesize a durable payload-validation obligation"
    );
    assert!(
        core.safety_state()
            .payload_validation_completions()
            .is_empty(),
        "genesis must not synthesize a durable payload-validation completion"
    );
}

#[test]
fn validation_request_keeps_synthetic_genesis_explicitly_headerless() {
    let (config, mut core) = configured_core();
    let set = config.validator_set().clone();
    let proposed = proposal(&set, genesis_qc(&set), 1, b"a");
    let expected_block = proposed.block().clone();
    let effects = core
        .step(Input::Proposal(Box::new(proposed)), &RootSignatures)
        .expect("genesis child accepted");
    let effects = release_persisted_effects(&mut core, effects);
    let request = effects
        .iter()
        .find_map(|effect| match effect {
            Effect::ValidatePayload(request) => Some(request),
            _ => None,
        })
        .expect("Core emits exact genesis-child validation request");

    assert_eq!(request.block(), &expected_block);
    assert_eq!(request.parent().tip(), core.safety_state().finalized());
    assert_eq!(request.parent().tip().height(), Height::new(0));
    assert!(request.parent().exact_header().is_none());
    assert!(request.parent().is_legacy_trusted_genesis_v0());
    assert!(request
        .parent()
        .authenticated_genesis_application_parent_v0()
        .is_none());
    assert_eq!(
        request.parent().provenance(),
        PayloadValidationParentProvenanceV0::Finalized
    );
}

#[test]
fn authenticated_genesis_application_parent_is_inert_config_and_record_bound_v0() {
    let parameters = consensus_parameters();
    let set = validator_set_with_parameters(&parameters);
    let parent = AuthenticatedGenesisApplicationParentV0::new(
        BlockId::new(*set.genesis_hash().as_bytes()),
        GENESIS_TIMESTAMP_MS,
        0,
        StateRoot::new([0x31; 32]),
        [0x41; 32],
        [0x51; 32],
    )
    .expect("shape-valid operator-pinned genesis application parent");
    let config = CoreConfig::new_with_authenticated_genesis_application_parent_v0(
        validator_id(1),
        set.clone(),
        parameters,
        GENESIS_TIMESTAMP_MS,
        parent,
        32,
        64,
    )
    .expect("shadow-only authenticated-genesis config");
    let genesis = genesis_qc(&set);
    assert_eq!(
        Core::new(config.clone(), genesis.clone(), &RootSignatures),
        Err(CoreError::AuthenticatedGenesisApplicationActivationUnavailable),
        "an operator-pinned application root cannot activate the generic Core surface",
    );
    let durable = SafetyState::from_authenticated_genesis_application_for_test_v0(
        &set,
        genesis,
        GENESIS_TIMESTAMP_MS,
        parent,
    )
    .expect("construct inert schema-v12 record fixture");
    assert_eq!(
        durable.authenticated_genesis_application_parent_v0(),
        Some(&parent)
    );
    assert_safety_state_record_roundtrip_and_validate(&config, &durable);
    let application_parent =
        PayloadValidationParentV0::authenticated_genesis_application(durable.finalized(), parent)
            .expect("construct inert tagged parent comparison facts");
    assert_eq!(
        application_parent.authenticated_genesis_application_parent_v0(),
        Some(parent)
    );
    assert!(application_parent.exact_header().is_none());
    assert!(!application_parent.is_legacy_trusted_genesis_v0());
    assert_ne!(
        application_parent.binding_ref_v0().expect("binding ref"),
        PayloadValidationParentV0::trusted_genesis(application_parent.tip())
            .binding_ref_v0()
            .expect("legacy binding ref"),
    );
    assert_eq!(
        Core::recover(config.clone(), durable.clone(), &RootSignatures),
        Err(CoreError::AuthenticatedGenesisApplicationActivationUnavailable),
        "an inert record cannot recover the generic Core surface",
    );

    let foreign_parent = AuthenticatedGenesisApplicationParentV0::new(
        parent.genesis_block_id(),
        parent.timestamp_ms(),
        parent.state_version(),
        StateRoot::new([0x32; 32]),
        parent.descriptor_ref(),
        parent.projection_profile_ref(),
    )
    .expect("shape-valid foreign root");
    let foreign_config = CoreConfig::new_with_authenticated_genesis_application_parent_v0(
        validator_id(1),
        set,
        parameters,
        GENESIS_TIMESTAMP_MS,
        foreign_parent,
        32,
        64,
    )
    .expect("shape-valid foreign config");
    assert_eq!(
        Core::validate_persisted_state_v0(&foreign_config, &durable, &RootSignatures),
        Err(CoreError::InvalidRecovery(
            "durable authenticated genesis application parent differs from core configuration",
        ))
    );
}

#[test]
fn authenticated_genesis_application_parent_and_h1_state_sync_anchor_are_mutually_exclusive_v0() {
    let (plain_config, proof, _h1, _h2, _h3) = h1_state_sync_fixture();
    let parent = AuthenticatedGenesisApplicationParentV0::new(
        plain_config.genesis_block_id(),
        plain_config.trusted_genesis_timestamp_ms(),
        0,
        StateRoot::new([0x31; 32]),
        [0x41; 32],
        [0x51; 32],
    )
    .expect("shape-valid operator-pinned genesis application parent");
    let config = CoreConfig::new_with_authenticated_genesis_application_parent_v0(
        plain_config.local_validator(),
        plain_config.validator_set().clone(),
        *plain_config.consensus_parameters(),
        plain_config.trusted_genesis_timestamp_ms(),
        parent,
        32,
        64,
    )
    .expect("shadow-only authenticated-genesis config");
    let genesis_parent = FinalizedTip::new(
        Height::new(0),
        View::new(0),
        config.genesis_block_id(),
        config.trusted_genesis_timestamp_ms(),
    );
    let anchor = DurableStateSyncAnchorV0::new(genesis_parent, proof)
        .expect("shape-valid h1 state-sync anchor");
    let mixed = SafetyState::from_h1_state_sync_anchor(
        config.validator_set(),
        config.genesis_block_id(),
        Some(parent),
        anchor,
    )
    .expect("schema-v13 decoder model can represent the unsupported mixed state");
    assert_eq!(mixed.schema_version(), 13);
    assert_eq!(
        mixed.authenticated_genesis_application_parent_v0(),
        Some(&parent)
    );
    assert!(mixed.state_sync_anchor().is_some());
    assert_eq!(
        mixed.validate_exact_authenticated_genesis_application_bootstrap_v0(
            &config,
            &genesis_qc(config.validator_set()),
        ),
        Err(CoreError::InvalidRecovery(
            "authenticated genesis application bootstrap and h1 state-sync bootstrap are mutually exclusive",
        )),
        "the dedicated commissioning guard must reject the mixed trust-root state",
    );

    let decoded = roundtrip_safety_state_record(&config, &mixed);
    assert_eq!(
        Core::validate_persisted_state_v0(&config, &decoded, &RootSignatures),
        Err(CoreError::InvalidRecovery(
            "authenticated genesis application bootstrap and h1 state-sync bootstrap are mutually exclusive",
        )),
        "a canonical schema-v13 record cannot combine the two bootstrap trust roots",
    );
}

#[test]
fn authenticated_genesis_application_parent_fences_every_generic_begin_surface_v0() {
    macro_rules! assert_activation_unavailable {
        ($surface:literal, $result:expr) => {
            match $result {
                Err(CoreError::AuthenticatedGenesisApplicationActivationUnavailable) => {}
                Err(error) => panic!("{} returned the wrong error: {error:?}", $surface),
                Ok(_) => panic!("{} leaked a recovery session", $surface),
            }
        };
    }

    let (config, durable) = authenticated_genesis_application_fixture_v0();
    assert_activation_unavailable!(
        "begin_state_sync_anchor_recovery_v0",
        Core::begin_state_sync_anchor_recovery_v0(config.clone(), durable.clone(), &RootSignatures,)
    );
    assert_activation_unavailable!(
        "begin_payload_validation_obligation_recovery_v0",
        Core::begin_payload_validation_obligation_recovery_v0(
            config.clone(),
            durable.clone(),
            &RootSignatures,
        )
    );
    assert_activation_unavailable!(
        "begin_native_valid_completion_recovery_v0",
        Core::begin_native_valid_completion_recovery_v0(
            config.clone(),
            durable.clone(),
            &RootSignatures,
        )
    );
    assert_activation_unavailable!(
        "begin_native_finalization_applied_recovery_v0",
        Core::begin_native_finalization_applied_recovery_v0(
            config.clone(),
            durable.clone(),
            &RootSignatures,
        )
    );

    let (anchor_config, proof, _h1, h2, h3) = h1_state_sync_fixture();
    match Core::prepare_h1_state_sync_bootstrap_v0(
        config.clone(),
        proof.clone(),
        &RootSignatures,
    ) {
        Err(CoreError::InvalidConfig(
            "authenticated genesis application bootstrap and h1 state-sync bootstrap are mutually exclusive",
        )) => {}
        Err(error) => panic!("prepare_h1_state_sync_bootstrap_v0 returned the wrong error: {error:?}"),
        Ok(_) => panic!("prepare_h1_state_sync_bootstrap_v0 accepted mixed bootstrap trust roots"),
    }
    let anchor_state =
        Core::prepare_h1_state_sync_bootstrap_v0(anchor_config.clone(), proof, &RootSignatures)
            .expect("prepare a type-correct inert successor bundle fixture")
            .into_safety_state();
    let bundle = Core::prepare_h1_state_sync_anchor_successor_bundle_v0(
        &anchor_config,
        &anchor_state,
        h2,
        h3,
        &RootSignatures,
    )
    .expect("prepare a type-correct inert successor bundle fixture");
    assert_activation_unavailable!(
        "begin_state_sync_anchor_successor_recovery_v0",
        Core::begin_state_sync_anchor_successor_recovery_v0(
            config,
            durable,
            bundle,
            &RootSignatures,
        )
    );
}

#[test]
fn authenticated_genesis_application_parent_rejects_malformed_and_nonshadow_config_v0() {
    let parameters = consensus_parameters();
    let set = validator_set_with_parameters(&parameters);
    let genesis = BlockId::new(*set.genesis_hash().as_bytes());
    assert!(AuthenticatedGenesisApplicationParentV0::new(
        genesis,
        GENESIS_TIMESTAMP_MS,
        1,
        StateRoot::new([0x31; 32]),
        [0x41; 32],
        [0x51; 32],
    )
    .is_err());
    assert!(AuthenticatedGenesisApplicationParentV0::new(
        genesis,
        GENESIS_TIMESTAMP_MS,
        0,
        StateRoot::ZERO,
        [0x41; 32],
        [0x51; 32],
    )
    .is_err());
    let parent = AuthenticatedGenesisApplicationParentV0::new(
        genesis,
        GENESIS_TIMESTAMP_MS,
        0,
        StateRoot::new([0x31; 32]),
        [0x41; 32],
        [0x51; 32],
    )
    .expect("shape-valid parent");
    for tampered in [
        AuthenticatedGenesisApplicationParentV0::new(
            genesis,
            GENESIS_TIMESTAMP_MS,
            0,
            StateRoot::new([0x32; 32]),
            parent.descriptor_ref(),
            parent.projection_profile_ref(),
        )
        .expect("tampered root remains shape-valid"),
        AuthenticatedGenesisApplicationParentV0::new(
            genesis,
            GENESIS_TIMESTAMP_MS,
            0,
            parent.state_root(),
            [0x42; 32],
            parent.projection_profile_ref(),
        )
        .expect("tampered descriptor remains shape-valid"),
        AuthenticatedGenesisApplicationParentV0::new(
            genesis,
            GENESIS_TIMESTAMP_MS,
            0,
            parent.state_root(),
            parent.descriptor_ref(),
            [0x52; 32],
        )
        .expect("tampered profile remains shape-valid"),
    ] {
        assert_ne!(tampered.binding_ref_v0(), parent.binding_ref_v0());
    }
    assert!(AuthenticatedGenesisApplicationParentV0::new(
        genesis,
        GENESIS_TIMESTAMP_MS,
        0,
        StateRoot::new([0x31; 32]),
        [0; 32],
        [0x51; 32],
    )
    .is_err());
    assert!(AuthenticatedGenesisApplicationParentV0::new(
        genesis,
        GENESIS_TIMESTAMP_MS,
        0,
        StateRoot::new([0x31; 32]),
        [0x41; 32],
        [0; 32],
    )
    .is_err());
    let mut production_fields = parameters.fields();
    production_fields.production_activation = true;
    let production = ConsensusParametersV0::new(production_fields)
        .expect("production bit does not violate structural safety invariants");
    let production_set = validator_set_with_parameters(&production);
    let production_parent = AuthenticatedGenesisApplicationParentV0::new(
        BlockId::new(*production_set.genesis_hash().as_bytes()),
        GENESIS_TIMESTAMP_MS,
        0,
        parent.state_root(),
        parent.descriptor_ref(),
        parent.projection_profile_ref(),
    )
    .expect("shape-valid production-scoped parent");
    assert!(
        CoreConfig::new_with_authenticated_genesis_application_parent_v0(
            validator_id(1),
            production_set,
            production,
            GENESIS_TIMESTAMP_MS,
            production_parent,
            32,
            64,
        )
        .is_err()
    );
}

#[test]
fn validation_request_freezes_the_exact_speculative_parent_header() {
    let (config, mut core) = configured_core();
    let set = config.validator_set().clone();
    let parent = proposal(&set, genesis_qc(&set), 1, b"parent");
    let parent_header = parent.block().header().clone();
    insert_valid_and_vote(&mut core, parent);

    let parent_qc = qc(&set, 1, 1, parent_header.id());
    let child = proposal(&set, parent_qc, 2, b"child");
    let child_block = child.block().clone();
    let effects = core
        .step(Input::Proposal(Box::new(child)), &RootSignatures)
        .expect("speculative child accepted");
    let (barrier, durable_child) = persistence_effect(&effects);
    assert_safety_state_record_roundtrip_and_validate(&config, &durable_child);
    let effects = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("exact-parent validation obligation persisted");
    let request = effects
        .iter()
        .find_map(|effect| match effect {
            Effect::ValidatePayload(request) => Some(request),
            _ => None,
        })
        .expect("Core emits exact speculative-child validation request");

    assert_eq!(request.block(), &child_block);
    assert_eq!(request.parent().exact_header(), Some(&parent_header));
    assert_eq!(
        request.parent().provenance(),
        PayloadValidationParentProvenanceV0::Speculative(
            artifact_ref_for_ids(parent_header.id(), parent_header.parent_id()).overlay()
        )
    );
    assert_eq!(request.parent().tip().block_id(), parent_header.id());
    assert_eq!(request.parent().tip().height(), parent_header.height());
    assert_eq!(request.parent().tip().view(), parent_header.view());
    assert_eq!(
        request.parent().tip().timestamp_ms(),
        parent_header.timestamp_ms()
    );
}

#[test]
fn payload_validation_route_is_core_bound_and_survives_deferred_storage_ack() {
    let (direct_config, mut direct_core) = configured_core();
    let set = direct_core.config().validator_set().clone();
    let proposed = proposal(&set, genesis_qc(&set), 1, b"route-bound request");

    let effects = direct_core
        .step(Input::Proposal(Box::new(proposed.clone())), &RootSignatures)
        .expect("direct proposal accepted");
    assert!(effects.iter().all(|effect| !matches!(
        effect,
        Effect::ValidatePayload(_) | Effect::ValidateSyncedPayload(_)
    )));
    let (barrier, durable_direct) = persistence_effect(&effects);
    assert_eq!(durable_direct.payload_validation_obligations().len(), 1);
    assert_safety_state_record_roundtrip_and_validate(&direct_config, &durable_direct);
    let effects = direct_core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("direct request released after persistence");
    let direct = effects
        .into_iter()
        .find_map(|effect| match effect {
            Effect::ValidatePayload(request) => Some(request),
            _ => None,
        })
        .expect("direct route emits ValidatePayload");
    let direct_obligation = &durable_direct.payload_validation_obligations()[0];
    assert_eq!(
        direct_obligation.route(),
        PayloadValidationRouteV0::Proposal
    );
    assert_eq!(direct_obligation.id(), direct.id());
    assert_eq!(direct_obligation.proposal(), &proposed);
    assert_eq!(direct_obligation.parent(), direct.parent());
    assert_eq!(
        direct_obligation.first_recorded_revision(),
        durable_direct.revision()
    );
    assert_eq!(
        direct_obligation.id().generation(),
        direct_obligation.first_recorded_revision()
    );
    assert_eq!(direct.route(), PayloadValidationRouteV0::Proposal);

    let direct_clone = direct.clone();
    assert_eq!(direct_clone, direct);
    assert_eq!(direct_clone.route(), PayloadValidationRouteV0::Proposal);
    assert!(std::format!("{direct:?}").contains("route: Proposal"));
    let opposite_route = PayloadValidationRequest::new(
        PayloadValidationRouteV0::Synced,
        direct.id(),
        direct.block().clone(),
        direct.parent().clone(),
        alloc::sync::Arc::new(()),
    );
    assert_ne!(direct, opposite_route);

    let claimed = direct
        .try_claim()
        .unwrap_or_else(|_| panic!("direct request wins its fresh claim"));
    assert_eq!(claimed.route(), PayloadValidationRouteV0::Proposal);
    let (route, id, block, parent, _valid_permit) = claimed.into_parts();
    assert_eq!(route, PayloadValidationRouteV0::Proposal);
    assert_eq!(id, direct_clone.id());
    assert_eq!(&block, direct_clone.block());
    assert_eq!(&parent, direct_clone.parent());
    match direct_clone.try_claim() {
        Ok(_) => panic!("direct clone bypassed the shared claim gate"),
        Err(duplicate) => {
            assert_eq!(duplicate.route(), PayloadValidationRouteV0::Proposal);
            assert_eq!(duplicate.id(), id);
        }
    }

    let (synced_config, mut synced_core) = configured_core();
    let effects = synced_core
        .step(Input::SyncedProposal(Box::new(proposed)), &RootSignatures)
        .expect("synced proposal accepted");
    assert!(effects.iter().all(|effect| !matches!(
        effect,
        Effect::ValidatePayload(_) | Effect::ValidateSyncedPayload(_)
    )));
    let (barrier, durable_synced) = persistence_effect(&effects);
    assert_eq!(durable_synced.payload_validation_obligations().len(), 1);
    assert_safety_state_record_roundtrip_and_validate(&synced_config, &durable_synced);
    let effects = synced_core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("synced request released after persistence");
    let synced = effects
        .into_iter()
        .find_map(|effect| match effect {
            Effect::ValidateSyncedPayload(request) => Some(request),
            _ => None,
        })
        .expect("synced route emits ValidateSyncedPayload");
    let synced_obligation = &durable_synced.payload_validation_obligations()[0];
    assert_eq!(synced_obligation.route(), PayloadValidationRouteV0::Synced);
    assert_eq!(synced_obligation.id(), synced.id());
    assert_eq!(synced_obligation.parent(), synced.parent());
    assert_eq!(
        synced_obligation.first_recorded_revision(),
        durable_synced.revision()
    );
    assert_eq!(
        synced_obligation.id().generation(),
        synced_obligation.first_recorded_revision()
    );
    assert_eq!(synced.route(), PayloadValidationRouteV0::Synced);
    assert!(std::format!("{synced:?}").contains("route: Synced"));
}

#[test]
fn payload_validation_request_clones_share_exactly_one_process_local_claim() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(&set, genesis_qc(&set), 1, b"concurrent claim");
    let effects = core
        .step(Input::Proposal(Box::new(proposed)), &RootSignatures)
        .expect("proposal accepted");
    let effects = release_persisted_effects(&mut core, effects);
    let request = into_validation_request(effects);
    let expected_route = PayloadValidationRouteV0::Proposal;
    assert_eq!(request.route(), expected_route);
    let expected_id = request.id();
    let expected_block = request.block().clone();
    let expected_parent = request.parent().clone();
    let cloned_before_claim = request.clone();

    let mut candidates: Vec<_> = (0..15).map(|_| request.clone()).collect();
    candidates.push(request);
    let claim_barrier = std::sync::Arc::new(std::sync::Barrier::new(candidates.len()));
    let claims: Vec<_> = candidates
        .into_iter()
        .map(|candidate| {
            let expected_block = expected_block.clone();
            let expected_parent = expected_parent.clone();
            let claim_barrier = std::sync::Arc::clone(&claim_barrier);
            std::thread::spawn(move || {
                claim_barrier.wait();
                match candidate.try_claim() {
                    Ok(claimed) => {
                        assert_eq!(claimed.route(), expected_route);
                        assert_eq!(claimed.id(), expected_id);
                        assert_eq!(claimed.block(), &expected_block);
                        assert_eq!(claimed.parent(), &expected_parent);
                        let (route, id, block, parent, _valid_permit) = claimed.into_parts();
                        assert_eq!(route, expected_route);
                        assert_eq!(id, expected_id);
                        assert_eq!(block, expected_block);
                        assert_eq!(parent, expected_parent);
                        1usize
                    }
                    Err(duplicate) => {
                        assert_eq!(duplicate.route(), expected_route);
                        assert_eq!(duplicate.id(), expected_id);
                        assert_eq!(duplicate.block(), &expected_block);
                        assert_eq!(duplicate.parent(), &expected_parent);
                        0usize
                    }
                }
            })
        })
        .collect();
    assert_eq!(
        claims
            .into_iter()
            .map(|claim| claim.join().expect("claim worker did not panic"))
            .sum::<usize>(),
        1
    );

    let cloned_after_claim = cloned_before_claim.clone();
    assert_eq!(cloned_before_claim, cloned_after_claim);
    for duplicate in [cloned_before_claim, cloned_after_claim] {
        match duplicate.try_claim() {
            Ok(_) => panic!("a clone recovered an already-consumed claim"),
            Err(duplicate) => {
                assert_eq!(duplicate.route(), expected_route);
                assert_eq!(duplicate.id(), expected_id);
                assert_eq!(duplicate.block(), &expected_block);
                assert_eq!(duplicate.parent(), &expected_parent);
            }
        }
    }
}

#[test]
fn distinct_payload_validation_generations_claim_independently() {
    let (config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(&set, genesis_qc(&set), 1, b"independent generations");

    let effects = core
        .step(Input::Proposal(Box::new(proposed.clone())), &RootSignatures)
        .expect("first proposal accepted");
    let effects = release_persisted_effects(&mut core, effects);
    let first = into_validation_request(effects);
    let first_id = first.id();
    assert!(first.try_claim().is_ok());
    let effects = core
        .step(
            Input::PayloadValidated {
                id: first_id,
                result: PayloadValidationResult::Unavailable,
            },
            &RootSignatures,
        )
        .expect("first generation retired as unavailable");
    let (barrier, retired) = persistence_effect(&effects);
    assert!(retired.payload_validation_obligations().is_empty());
    assert_eq!(
        retired
            .payload_validation_completions()
            .iter()
            .find(|completion| completion.id() == first_id)
            .expect("Unavailable completion is durable")
            .result(),
        DurablePayloadValidationResultV1::Unavailable
    );
    assert_eq!(retired.payload_terminal_result(first_id.block_id()), None);
    assert_safety_state_record_roundtrip_and_validate(&config, &retired);
    assert!(core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("first generation cleanup became durable")
        .is_empty());

    let effects = core
        .step(Input::Proposal(Box::new(proposed)), &RootSignatures)
        .expect("same proposal receives a fresh generation");
    let effects = release_persisted_effects(&mut core, effects);
    let second = into_validation_request(effects);
    let second_id = second.id();
    assert_eq!(second_id.block_id(), first_id.block_id());
    assert_eq!(second_id.view(), first_id.view());
    assert!(second_id.generation() > first_id.generation());
    assert!(second.try_claim().is_ok());
}

#[test]
fn recovery_with_a_claimed_durable_validation_fails_closed_without_reopening_it() {
    let (config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(&set, genesis_qc(&set), 1, b"restart claim fence");

    let effects = core
        .step(Input::Proposal(Box::new(proposed.clone())), &RootSignatures)
        .expect("proposal accepted before restart");
    let (barrier, durable_request) = persistence_effect(&effects);
    let effects = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("durable request released");
    let request = into_validation_request(effects);
    let stale = request.clone();
    let stale_id = request.id();
    assert!(request.try_claim().is_ok());

    Core::validate_persisted_state_v0(&config, &durable_request, &RootSignatures)
        .expect("an obligation-bearing record is a valid inert persistence fact");
    assert!(
        Core::validate_persisted_state_v0(&config, &durable_request, &RejectSignatures).is_err(),
        "read-only validation still authenticates durable obligation signatures"
    );

    let mismatched_config = CoreConfig::new(
        config.local_validator(),
        config.validator_set().clone(),
        *config.consensus_parameters(),
        config
            .trusted_genesis_timestamp_ms()
            .checked_add(1)
            .expect("test timestamp does not overflow"),
        config.max_blocks(),
        config.max_observed_messages(),
    )
    .expect("the mismatched persistence context is internally valid");
    assert_eq!(
        Core::validate_persisted_state_v0(&mismatched_config, &durable_request, &RootSignatures,),
        Err(CoreError::InvalidRecovery(
            "durable payload validation lacks a non-genesis parent header",
        )),
        "an inert record is still bound to the exact trusted persistence context"
    );

    let obligation = durable_request
        .payload_validation_obligations()
        .first()
        .expect("the fixture retains one durable obligation");
    let spliced_obligation = DurablePayloadValidationObligationV0::new(
        obligation.route(),
        ValidationId::new(
            BlockId::new([0x5E; 32]),
            obligation.id().view(),
            obligation.id().generation(),
        ),
        obligation.proposal().clone(),
        obligation.parent().clone(),
        obligation.first_recorded_revision(),
    );
    let spliced_state =
        decoded_state_with_validation_records(&durable_request, vec![spliced_obligation], vec![]);
    assert_eq!(
        Core::validate_persisted_state_v0(&config, &spliced_state, &RootSignatures),
        Err(CoreError::InvalidRecovery(
            "durable payload validation id differs from its signed proposal",
        )),
        "a checksum-consistent decoder splice cannot become a validated inert fact"
    );

    assert_eq!(
        Core::recover(config, durable_request, &RootSignatures),
        Err(CoreError::InvalidRecovery(
            "durable payload validation obligations require an authenticated replay ticket before recovery can reissue them",
        ))
    );

    match stale.try_claim() {
        Ok(_) => panic!("a stale pre-restart clone reclaimed its generation"),
        Err(duplicate) => {
            assert_eq!(duplicate.id(), stale_id);
            assert_eq!(duplicate.block().id(), stale_id.block_id());
        }
    }
}

#[test]
fn recovery_with_an_unclaimed_durable_validation_fails_closed_without_revoking_it() {
    let (config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(&set, genesis_qc(&set), 1, b"unclaimed restart boundary");

    let effects = core
        .step(Input::Proposal(Box::new(proposed.clone())), &RootSignatures)
        .expect("proposal accepted before restart");
    let (barrier, durable_request) = persistence_effect(&effects);
    let effects = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("durable request released");
    let stale = into_validation_request(effects);
    let stale_id = stale.id();

    Core::validate_persisted_state_v0(&config, &durable_request, &RootSignatures)
        .expect("an unclaimed obligation is still a valid inert persistence fact");

    assert_eq!(
        Core::recover(config, durable_request, &RootSignatures),
        Err(CoreError::InvalidRecovery(
            "durable payload validation obligations require an authenticated replay ticket before recovery can reissue them",
        ))
    );

    // The Arc gate is local to one request object graph. Recovery cannot
    // revoke an old, never-claimed object that remains alive in another host
    // task. The recovered Core is therefore unavailable until a future
    // authenticated replay-ticket tranche can safely reissue the obligation.
    assert!(stale.try_claim().is_ok());
    assert_eq!(stale_id.block_id(), proposed.block().id());
}

fn obligation_recovery_fixture(
    route: PayloadValidationRouteV0,
    body: &'static [u8],
) -> (CoreConfig, SafetyState, SignedProposalV0, ValidationId) {
    let (config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(&set, genesis_qc(&set), 1, body);
    let input = match route {
        PayloadValidationRouteV0::Proposal => Input::Proposal(Box::new(proposed.clone())),
        PayloadValidationRouteV0::Synced => Input::SyncedProposal(Box::new(proposed.clone())),
    };
    let effects = core
        .step(input, &RootSignatures)
        .expect("the fixture registers one durable validation obligation");
    let (_, durable) = persistence_effect(&effects);
    let [obligation] = durable.payload_validation_obligations() else {
        panic!("the fixture must persist exactly one obligation");
    };
    assert_eq!(obligation.route(), route);
    assert_eq!(obligation.proposal(), &proposed);
    let id = obligation.id();
    (config, durable, proposed, id)
}

struct ExactDeterministicInvalidReconcilerV0 {
    expected_head_revision: u64,
    expected_route: PayloadValidationRouteV0,
    expected_id: ValidationId,
    expected_proposal: SignedProposalV0,
    expected_parent: PayloadValidationParentV0,
    expected_first_revision: u64,
    calls: usize,
}

impl PayloadValidationRecoveryReconcilerV0 for ExactDeterministicInvalidReconcilerV0 {
    fn reconcile_deterministically_invalid_obligation_v0(
        &mut self,
        challenge: &PayloadValidationRecoveryChallengeV0,
    ) -> PayloadValidationRecoveryDecisionV0 {
        self.calls += 1;
        if challenge.safety_head_revision() == self.expected_head_revision
            && challenge.route() == self.expected_route
            && challenge.id() == self.expected_id
            && challenge.proposal() == &self.expected_proposal
            && challenge.parent() == &self.expected_parent
            && challenge.first_recorded_revision() == self.expected_first_revision
        {
            PayloadValidationRecoveryDecisionV0::AcceptDeterministicallyInvalid
        } else {
            PayloadValidationRecoveryDecisionV0::Reject
        }
    }
}

fn activate_exact_obligation_recovery(
    config: CoreConfig,
    durable: SafetyState,
    expected_route: PayloadValidationRouteV0,
) -> (Core, ValidationId, usize) {
    let session = Core::begin_payload_validation_obligation_recovery_v0(
        config,
        durable.clone(),
        &RootSignatures,
    )
    .expect("the exact single-obligation recovery session begins inertly");
    let challenge = session.challenge();
    let expected_id = challenge.id();
    let mut reconciler = ExactDeterministicInvalidReconcilerV0 {
        expected_head_revision: durable.revision(),
        expected_route,
        expected_id,
        expected_proposal: challenge.proposal().clone(),
        expected_parent: challenge.parent().clone(),
        expected_first_revision: challenge.first_recorded_revision(),
        calls: 0,
    };
    let core = session
        .reconcile_and_activate_v0(&mut reconciler)
        .expect("the trusted host accepts the complete deterministic-invalid job");
    (core, expected_id, reconciler.calls)
}

#[test]
fn proposal_obligation_recovery_rebuilds_the_exact_target_before_invalid_callback() {
    let (config, durable, proposed, id) = obligation_recovery_fixture(
        PayloadValidationRouteV0::Proposal,
        b"recovered proposal invalid",
    );
    let (mut recovered, recovered_id, reconciliations) = activate_exact_obligation_recovery(
        config,
        durable.clone(),
        PayloadValidationRouteV0::Proposal,
    );
    assert_eq!(recovered_id, id);
    assert_eq!(reconciliations, 1);
    assert_eq!(recovered.pending_validation_count(), 1);
    assert!(recovered
        .step(Input::Resume, &RootSignatures)
        .expect("Resume is an inert probe while the recovered result is fenced")
        .is_empty());
    assert_eq!(
        recovered.step(
            Input::LocalTimeout {
                epoch: Epoch::new(0),
                view: recovered.safety_state().current_view(),
            },
            &RootSignatures,
        ),
        Err(CoreError::Busy(
            "a recovered deterministic-invalid validation must be durably consumed before consensus resumes",
        )),
        "pacemaker input cannot bypass the recovery callback fence"
    );
    assert_eq!(
        recovered.step(
            Input::PayloadValidated {
                id,
                result: PayloadValidationResult::Unavailable,
            },
            &RootSignatures,
        ),
        Err(CoreError::Busy(
            "a recovered deterministic-invalid validation must be durably consumed before consensus resumes",
        )),
        "the recovered deterministic-invalid claim cannot be weakened to Unavailable"
    );

    let effects = recovered
        .step(
            Input::PayloadValidated {
                id,
                result: PayloadValidationResult::DeterministicallyInvalid,
            },
            &RootSignatures,
        )
        .expect("the exact callback finds its reconstructed BlockTree target");
    let (_, persisted) = persistence_effect(&effects);
    assert!(persisted.payload_validation_obligations().is_empty());
    assert_eq!(
        persisted.payload_terminal_result(proposed.block().id()),
        Some(PayloadTerminalResult::DeterministicallyInvalid)
    );
}

#[test]
fn synced_obligation_recovery_rebuilds_the_exact_route_and_witness() {
    let (config, durable, proposed, id) = obligation_recovery_fixture(
        PayloadValidationRouteV0::Synced,
        b"recovered synced invalid",
    );
    let (mut recovered, recovered_id, reconciliations) =
        activate_exact_obligation_recovery(config, durable, PayloadValidationRouteV0::Synced);
    assert_eq!(recovered_id, id);
    assert_eq!(reconciliations, 1);
    assert_eq!(recovered.pending_validation_count(), 1);
    assert_eq!(
        recovered.step(
            Input::PayloadValidated {
                id,
                result: PayloadValidationResult::DeterministicallyInvalid,
            },
            &RootSignatures,
        ),
        Err(CoreError::Busy(
            "a recovered deterministic-invalid validation must be durably consumed before consensus resumes",
        )),
        "a proposal-route callback cannot consume a synced-route challenge"
    );
    let effects = recovered
        .step(
            Input::SyncedPayloadValidated {
                id,
                result: PayloadValidationResult::DeterministicallyInvalid,
            },
            &RootSignatures,
        )
        .expect("the exact synced callback finds its reconstructed target and witness");
    let (_, persisted) = persistence_effect(&effects);
    assert!(persisted.payload_validation_obligations().is_empty());
    assert_eq!(
        persisted.payload_terminal_result(proposed.block().id()),
        Some(PayloadTerminalResult::DeterministicallyInvalid)
    );
}

#[test]
fn recovered_invalid_completion_ack_releases_the_fence_back_to_safety_replay() {
    let (config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let parent = proposal(&set, genesis_qc(&set), 1, b"recovery replay parent");
    let parent_qc = qc(&set, 1, 1, parent.block().id());
    insert_valid_and_vote(&mut core, parent);
    let _ = accept_qc(&mut core, parent_qc.clone());
    assert_ne!(
        core.safety_state().high_qc().qc_ref().block_id(),
        core.safety_state().finalized().block_id()
    );

    let child = proposal(&set, parent_qc, 2, b"recovery replay invalid child");
    let effects = core
        .step(Input::Proposal(Box::new(child)), &RootSignatures)
        .expect("the child obligation is persisted above the replay anchor");
    let (_, durable) = persistence_effect(&effects);
    let id = durable.payload_validation_obligations()[0].id();
    let (mut recovered, recovered_id, reconciliations) =
        activate_exact_obligation_recovery(config, durable, PayloadValidationRouteV0::Proposal);
    assert_eq!(recovered_id, id);
    assert_eq!(reconciliations, 1);

    let effects = recovered
        .step(
            Input::PayloadValidated {
                id,
                result: PayloadValidationResult::DeterministicallyInvalid,
            },
            &RootSignatures,
        )
        .expect("the reconciled invalid result becomes a persistence request");
    let (barrier, completed) = persistence_effect(&effects);
    assert!(completed.payload_validation_obligations().is_empty());
    assert!(recovered
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("the recovered completion becomes durable")
        .is_empty());
    assert!(matches!(
        recovered
            .step(Input::Resume, &RootSignatures)
            .expect("ordinary safety replay resumes only after completion acknowledgement")
            .as_slice(),
        [Effect::RequestSafetyReplay { .. }]
    ));
}

struct RejectRecoveryV0 {
    calls: usize,
}

impl PayloadValidationRecoveryReconcilerV0 for RejectRecoveryV0 {
    fn reconcile_deterministically_invalid_obligation_v0(
        &mut self,
        _challenge: &PayloadValidationRecoveryChallengeV0,
    ) -> PayloadValidationRecoveryDecisionV0 {
        self.calls += 1;
        PayloadValidationRecoveryDecisionV0::Reject
    }
}

#[test]
fn obligation_recovery_never_exposes_a_core_when_reconciliation_is_omitted() {
    let (config, durable, _, _) =
        obligation_recovery_fixture(PayloadValidationRouteV0::Proposal, b"recovery omission");
    let session =
        Core::begin_payload_validation_obligation_recovery_v0(config, durable, &RootSignatures)
            .expect("the inert recovery session begins");
    let mut reconciler = RejectRecoveryV0 { calls: 0 };
    assert_eq!(
        session.reconcile_and_activate_v0(&mut reconciler),
        Err(CoreError::PayloadValidationRecoveryRejected)
    );
    assert_eq!(
        reconciler.calls, 1,
        "Core must actually invoke the reconciler"
    );
}

struct WrongSessionRecoveryV0<'a> {
    expected: &'a PayloadValidationRecoveryChallengeV0,
    calls: usize,
}

impl PayloadValidationRecoveryReconcilerV0 for WrongSessionRecoveryV0<'_> {
    fn reconcile_deterministically_invalid_obligation_v0(
        &mut self,
        challenge: &PayloadValidationRecoveryChallengeV0,
    ) -> PayloadValidationRecoveryDecisionV0 {
        self.calls += 1;
        if challenge.same_recovery_instance_v0(self.expected) {
            PayloadValidationRecoveryDecisionV0::AcceptDeterministicallyInvalid
        } else {
            PayloadValidationRecoveryDecisionV0::Reject
        }
    }
}

#[test]
fn obligation_recovery_challenge_is_bound_to_one_process_local_session() {
    let (config, durable, _, _) = obligation_recovery_fixture(
        PayloadValidationRouteV0::Proposal,
        b"wrong recovery session",
    );
    let first = Core::begin_payload_validation_obligation_recovery_v0(
        config.clone(),
        durable.clone(),
        &RootSignatures,
    )
    .expect("first inert recovery session begins");
    let second =
        Core::begin_payload_validation_obligation_recovery_v0(config, durable, &RootSignatures)
            .expect("second inert recovery session begins");
    assert!(!first
        .challenge()
        .same_recovery_instance_v0(second.challenge()));
    let mut wrong = WrongSessionRecoveryV0 {
        expected: first.challenge(),
        calls: 0,
    };
    assert_eq!(
        second.reconcile_and_activate_v0(&mut wrong),
        Err(CoreError::PayloadValidationRecoveryRejected)
    );
    assert_eq!(wrong.calls, 1);
}

#[test]
fn obligation_recovery_rejects_tampered_duplicate_and_concurrent_records() {
    let (config, durable, _, _) = obligation_recovery_fixture(
        PayloadValidationRouteV0::Proposal,
        b"tampered recovery obligation",
    );
    let obligation = durable.payload_validation_obligations()[0].clone();
    let tampered = DurablePayloadValidationObligationV0::new(
        obligation.route(),
        ValidationId::new(
            BlockId::new([0x6D; 32]),
            obligation.id().view(),
            obligation.id().generation(),
        ),
        obligation.proposal().clone(),
        obligation.parent().clone(),
        obligation.first_recorded_revision(),
    );
    let tampered_state = decoded_state_with_validation_records(&durable, vec![tampered], vec![]);
    assert!(matches!(
        Core::begin_payload_validation_obligation_recovery_v0(
            config.clone(),
            tampered_state,
            &RootSignatures,
        ),
        Err(CoreError::InvalidRecovery(
            "durable payload validation id differs from its signed proposal",
        ))
    ));

    let duplicated_state = decoded_state_with_validation_records(
        &durable,
        vec![obligation.clone(), obligation],
        vec![],
    );
    assert!(matches!(
        Core::begin_payload_validation_obligation_recovery_v0(
            config,
            duplicated_state,
            &RootSignatures,
        ),
        Err(CoreError::InvalidRecovery(
            "durable payload validation obligations are not uniquely sorted by full id",
        ))
    ));

    let (terminal_config, terminal_durable, _, terminal_id) = obligation_recovery_fixture(
        PayloadValidationRouteV0::Proposal,
        b"terminal fact recovery conflict",
    );
    let terminal_state = SafetyState::from_persisted_parts_v13(
        terminal_durable.schema_version(),
        terminal_durable.chain_id(),
        terminal_durable.protocol_version(),
        terminal_durable.epoch(),
        terminal_durable.validator_set_id(),
        terminal_durable.genesis_block_id(),
        terminal_durable
            .authenticated_genesis_application_parent_v0()
            .copied(),
        terminal_durable.current_view(),
        terminal_durable.last_voted_view(),
        terminal_durable.last_timeout_view(),
        terminal_durable.high_qc().clone(),
        terminal_durable.locked_qc().clone(),
        terminal_durable.finalized(),
        terminal_durable.revision(),
        terminal_durable.durable_observed_qcs().to_vec(),
        vec![PayloadTerminalFact::new_valid(
            artifact_ref_for_ids(
                terminal_id.block_id(),
                terminal_durable.payload_validation_obligations()[0]
                    .proposal()
                    .block()
                    .header()
                    .parent_id(),
            )
            .overlay(),
            terminal_durable.revision(),
        )],
        terminal_durable.payload_validation_obligations().to_vec(),
        terminal_durable.payload_validation_completions().to_vec(),
        terminal_durable.pending_tc_high_qc_sync().cloned(),
        terminal_durable.pending_standalone_qc_sync().cloned(),
        terminal_durable.pending_sign().cloned(),
        terminal_durable.last_finalization().cloned(),
        terminal_durable.state_sync_anchor().cloned(),
        terminal_durable.application_applied(),
        terminal_durable.finalization_queue().to_vec(),
        terminal_durable.pending_finalize(),
        terminal_durable.safety_halt().cloned(),
    );
    assert!(matches!(
        Core::begin_payload_validation_obligation_recovery_v0(
            terminal_config,
            terminal_state,
            &RootSignatures,
        ),
        Err(CoreError::UnsupportedPayloadValidationRecoveryState(
            "the challenged block already has a durable terminal payload fact",
        ))
    ));

    let (multi_config, mut multi_core) = configured_core();
    let set = multi_core.config().validator_set().clone();
    let proposed = proposal(
        &set,
        genesis_qc(&set),
        1,
        b"two recovery obligations are unsupported",
    );
    let effects = multi_core
        .step(Input::Proposal(Box::new(proposed.clone())), &RootSignatures)
        .expect("the first obligation is staged");
    let (barrier, _) = persistence_effect(&effects);
    multi_core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("the first obligation is durably released");
    let effects = multi_core
        .step(Input::SyncedProposal(Box::new(proposed)), &RootSignatures)
        .expect("a distinct route receives its own durable generation");
    let (_, concurrent) = persistence_effect(&effects);
    assert_eq!(concurrent.payload_validation_obligations().len(), 2);
    assert!(matches!(
        Core::begin_payload_validation_obligation_recovery_v0(
            multi_config,
            concurrent,
            &RootSignatures,
        ),
        Err(CoreError::UnsupportedPayloadValidationRecovery { obligations: 2 })
    ));
}

fn persisted_state_with_qcs<H: IntoQcReference, L: IntoQcReference>(
    state: &SafetyState,
    high_qc: H,
    locked_qc: L,
) -> SafetyState {
    SafetyState::from_persisted_parts_v13(
        state.schema_version(),
        state.chain_id(),
        state.protocol_version(),
        state.epoch(),
        state.validator_set_id(),
        state.genesis_block_id(),
        state.authenticated_genesis_application_parent_v0().copied(),
        state.current_view(),
        state.last_voted_view(),
        state.last_timeout_view(),
        high_qc.into_qc_reference(),
        locked_qc.into_qc_reference(),
        state.finalized(),
        state.revision(),
        state.durable_observed_qcs().to_vec(),
        state.payload_terminal_facts().to_vec(),
        state.payload_validation_obligations().to_vec(),
        state.payload_validation_completions().to_vec(),
        state.pending_tc_high_qc_sync().cloned(),
        state.pending_standalone_qc_sync().cloned(),
        state.pending_sign().cloned(),
        state.last_finalization().cloned(),
        state.state_sync_anchor().cloned(),
        state.application_applied(),
        state.finalization_queue().to_vec(),
        state.pending_finalize(),
        state.safety_halt().cloned(),
    )
}

#[allow(clippy::too_many_arguments)]
fn persisted_state_with_outbox_fields(
    state: &SafetyState,
    current_view: View,
    last_voted_view: Option<View>,
    last_timeout_view: Option<View>,
    revision: u64,
    pending_sign: Option<SignIntent>,
    pending_finalize: Option<CertificateId>,
) -> SafetyState {
    let (application_applied, finalization_queue) =
        match (pending_finalize.is_some(), state.last_finalization()) {
            (true, Some(finalization)) => (
                finalization.authenticated_parent(),
                vec![finalization.clone()],
            ),
            _ => (state.finalized(), Vec::new()),
        };
    SafetyState::from_persisted_parts_v13(
        state.schema_version(),
        state.chain_id(),
        state.protocol_version(),
        state.epoch(),
        state.validator_set_id(),
        state.genesis_block_id(),
        state.authenticated_genesis_application_parent_v0().copied(),
        current_view,
        last_voted_view,
        last_timeout_view,
        state.high_qc().clone(),
        state.locked_qc().clone(),
        state.finalized(),
        revision,
        state.durable_observed_qcs().to_vec(),
        state.payload_terminal_facts().to_vec(),
        state.payload_validation_obligations().to_vec(),
        state.payload_validation_completions().to_vec(),
        state.pending_tc_high_qc_sync().cloned(),
        state.pending_standalone_qc_sync().cloned(),
        pending_sign,
        state.last_finalization().cloned(),
        state.state_sync_anchor().cloned(),
        application_applied,
        finalization_queue,
        pending_finalize,
        state.safety_halt().cloned(),
    )
}

#[test]
fn persisted_successor_rejects_a_reintroduced_signing_outbox() {
    let (config, core) = configured_core();
    let genesis = core.safety_state();
    let view = genesis.current_view();
    let previous = persisted_state_with_outbox_fields(
        genesis,
        view,
        None,
        Some(view),
        genesis.revision().checked_add(1).unwrap(),
        None,
        None,
    );
    Core::validate_persisted_state_v0(&config, &previous, &RootSignatures)
        .expect("a previously completed timeout signing watermark is a valid inert state");
    let signing_root = TimeoutVote::signing_root_for_set(
        config.validator_set(),
        view,
        previous.high_qc().qc_ref(),
    )
    .expect("derive timeout signing root");
    let current = persisted_state_with_outbox_fields(
        &previous,
        view,
        None,
        Some(view),
        previous.revision().checked_add(1).unwrap(),
        Some(SignIntent::TimeoutVote {
            authorizing_safety_revision: previous.revision().checked_add(1).unwrap(),
            view,
            high_qc: previous.high_qc().qc_ref(),
            signing_root,
        }),
        None,
    );
    Core::validate_persisted_state_v0(&config, &current, &RootSignatures)
        .expect("the spliced state is self-consistent in isolation");
    assert_eq!(
        Core::validate_persisted_successor_v0(&config, &previous, &current, &RootSignatures,),
        Err(CoreError::InvalidRecovery(
            "pending signing intent was introduced without advancing its watermark",
        ))
    );
}

#[test]
fn persisted_successor_rejects_replacing_an_active_signing_outbox() {
    let (config, core) = configured_core();
    let genesis = core.safety_state();
    let view = genesis.current_view();
    let first_revision = genesis.revision().checked_add(1).unwrap();
    let first_root =
        TimeoutVote::signing_root_for_set(config.validator_set(), view, genesis.high_qc().qc_ref())
            .expect("derive first timeout signing root");
    let previous = persisted_state_with_outbox_fields(
        genesis,
        view,
        None,
        Some(view),
        first_revision,
        Some(SignIntent::TimeoutVote {
            authorizing_safety_revision: first_revision,
            view,
            high_qc: genesis.high_qc().qc_ref(),
            signing_root: first_root,
        }),
        None,
    );
    Core::validate_persisted_state_v0(&config, &previous, &RootSignatures)
        .expect("the first pending timeout intent is self-consistent");

    let replacement_view = view.checked_next().expect("fixture view advances");
    let replacement_revision = previous.revision().checked_add(1).unwrap();
    let replacement_root = TimeoutVote::signing_root_for_set(
        config.validator_set(),
        replacement_view,
        previous.high_qc().qc_ref(),
    )
    .expect("derive replacement timeout signing root");
    let current = persisted_state_with_outbox_fields(
        &previous,
        replacement_view,
        None,
        Some(replacement_view),
        replacement_revision,
        Some(SignIntent::TimeoutVote {
            authorizing_safety_revision: replacement_revision,
            view: replacement_view,
            high_qc: previous.high_qc().qc_ref(),
            signing_root: replacement_root,
        }),
        None,
    );
    Core::validate_persisted_state_v0(&config, &current, &RootSignatures)
        .expect("the replacement is individually self-consistent");
    assert_eq!(
        Core::validate_persisted_successor_v0(&config, &previous, &current, &RootSignatures,),
        Err(CoreError::InvalidRecovery(
            "pending signing intent was replaced before acknowledgement",
        ))
    );
}

#[test]
fn persisted_successor_rejects_a_reintroduced_applied_finalization_queue_front() {
    let (config, mut core) = configured_core();
    let (_set, _qc, _finalization_authority) = finalize_height_one(&mut core);
    let previous = core.safety_state().clone();
    assert!(previous.pending_finalize().is_none());
    let proof_id = previous
        .last_finalization()
        .expect("height-one finality retains its permanent proof")
        .proof_id();
    let current = persisted_state_with_outbox_fields(
        &previous,
        previous.current_view(),
        previous.last_voted_view(),
        previous.last_timeout_view(),
        previous.revision().checked_add(1).unwrap(),
        previous.pending_sign().cloned(),
        Some(proof_id),
    );
    Core::validate_persisted_state_v0(&config, &current, &RootSignatures)
        .expect("the rebuilt applied-to-finalized queue is self-consistent in isolation");
    assert_eq!(previous.application_applied(), previous.finalized());
    assert!(previous.finalization_queue().is_empty());
    assert_eq!(current.finalization_queue().len(), 1);
    assert_eq!(
        current.application_applied(),
        current.finalization_queue()[0].authenticated_parent()
    );
    assert_eq!(
        Core::validate_persisted_successor_v0(&config, &previous, &current, &RootSignatures,),
        Err(CoreError::InvalidRecovery(
            "application-applied watermark changed without a prior queue front",
        ))
    );
}

#[test]
fn persisted_successor_rejects_changed_finalization_carrier_without_finality_advance() {
    let (config, mut core) = configured_core();
    let (_set, _qc, _finalization_authority) = finalize_height_one(&mut core);
    let previous = core.safety_state().clone();
    assert!(previous.finalization_queue().is_empty());
    assert_eq!(previous.application_applied(), previous.finalized());
    let durable = previous
        .last_finalization()
        .expect("height-one finality retains its complete permanent carrier");
    let parent = durable.authenticated_parent();
    let tampered_parent = FinalizedTip::new(
        parent.height(),
        parent.view(),
        parent.block_id(),
        parent
            .timestamp_ms()
            .checked_add(1)
            .expect("fixture parent timestamp advances by one millisecond"),
    );
    let tampered = DurableFinalizationV0::new(
        tampered_parent,
        durable.proof().clone(),
        durable.target_overlay_ref(),
    )
    .expect("the tampered parent remains shape-valid in isolation");
    assert_ne!(&tampered, durable);
    assert_eq!(tampered.proof(), durable.proof());

    let current = SafetyState::from_persisted_parts_v13(
        previous.schema_version(),
        previous.chain_id(),
        previous.protocol_version(),
        previous.epoch(),
        previous.validator_set_id(),
        previous.genesis_block_id(),
        previous
            .authenticated_genesis_application_parent_v0()
            .copied(),
        previous.current_view(),
        previous.last_voted_view(),
        previous.last_timeout_view(),
        previous.high_qc().clone(),
        previous.locked_qc().clone(),
        previous.finalized(),
        previous.revision().checked_add(1).unwrap(),
        previous.durable_observed_qcs().to_vec(),
        previous.payload_terminal_facts().to_vec(),
        previous.payload_validation_obligations().to_vec(),
        previous.payload_validation_completions().to_vec(),
        previous.pending_tc_high_qc_sync().cloned(),
        previous.pending_standalone_qc_sync().cloned(),
        previous.pending_sign().cloned(),
        Some(tampered),
        previous.state_sync_anchor().cloned(),
        previous.application_applied(),
        previous.finalization_queue().to_vec(),
        previous.pending_finalize(),
        previous.safety_halt().cloned(),
    );
    Core::validate_persisted_state_v0(&config, &current, &RootSignatures)
        .expect("the timestamp splice remains self-consistent in isolation");
    assert_eq!(
        Core::validate_persisted_successor_v0(&config, &previous, &current, &RootSignatures),
        Err(CoreError::InvalidRecovery(
            "permanent finalization carrier changed without advancing finality",
        ))
    );
}

fn decoded_state_with_validation_records(
    state: &SafetyState,
    obligations: Vec<DurablePayloadValidationObligationV0>,
    completions: Vec<DurablePayloadValidationCompletionV0>,
) -> SafetyState {
    SafetyState::from_persisted_parts_v13(
        state.schema_version(),
        state.chain_id(),
        state.protocol_version(),
        state.epoch(),
        state.validator_set_id(),
        state.genesis_block_id(),
        state.authenticated_genesis_application_parent_v0().copied(),
        state.current_view(),
        state.last_voted_view(),
        state.last_timeout_view(),
        state.high_qc().clone(),
        state.locked_qc().clone(),
        state.finalized(),
        state.revision(),
        state.durable_observed_qcs().to_vec(),
        state.payload_terminal_facts().to_vec(),
        obligations,
        completions,
        state.pending_tc_high_qc_sync().cloned(),
        state.pending_standalone_qc_sync().cloned(),
        state.pending_sign().cloned(),
        state.last_finalization().cloned(),
        state.state_sync_anchor().cloned(),
        state.application_applied(),
        state.finalization_queue().to_vec(),
        state.pending_finalize(),
        state.safety_halt().cloned(),
    )
}

#[allow(clippy::too_many_arguments)]
fn decoded_state_with_obligations(
    state: &SafetyState,
    current_view: View,
    last_voted_view: Option<View>,
    last_timeout_view: Option<View>,
    high_qc: QcReferenceV0,
    locked_qc: QcReferenceV0,
    finalized: FinalizedTip,
    pending_tc_high_qc_sync: Option<PendingTcHighQcSync>,
    pending_standalone_qc_sync: Option<PendingStandaloneQcSync>,
    pending_sign: Option<SignIntent>,
    last_finalization: Option<DurableFinalizationV0>,
    pending_finalize: Option<CertificateId>,
) -> SafetyState {
    SafetyState::from_persisted_parts_v13(
        state.schema_version(),
        state.chain_id(),
        state.protocol_version(),
        state.epoch(),
        state.validator_set_id(),
        state.genesis_block_id(),
        state.authenticated_genesis_application_parent_v0().copied(),
        current_view,
        last_voted_view,
        last_timeout_view,
        high_qc,
        locked_qc,
        finalized,
        state.revision(),
        state.durable_observed_qcs().to_vec(),
        state.payload_terminal_facts().to_vec(),
        vec![],
        state.payload_validation_completions().to_vec(),
        pending_tc_high_qc_sync,
        pending_standalone_qc_sync,
        pending_sign,
        last_finalization,
        state.state_sync_anchor().cloned(),
        state.application_applied(),
        state.finalization_queue().to_vec(),
        pending_finalize,
        state.safety_halt().cloned(),
    )
}

fn decoded_halted_state_with_invalid_reference(
    state: &SafetyState,
    current_view: View,
    last_voted_view: Option<View>,
    last_timeout_view: Option<View>,
    block_id: BlockId,
    reference: InvalidPayloadReference,
) -> SafetyState {
    let mut facts = state.payload_terminal_facts().to_vec();
    facts.retain(|fact| fact.block_id() != block_id);
    facts.push(PayloadTerminalFact::new_deterministically_invalid(
        block_id,
        state.revision(),
    ));
    facts.sort_by_key(|fact| fact.block_id());
    let halt = SafetyHalt::deterministically_invalid_payload(block_id, reference)
        .expect("canonical invalid-payload halt witness");
    SafetyState::from_persisted_parts_v13(
        state.schema_version(),
        state.chain_id(),
        state.protocol_version(),
        state.epoch(),
        state.validator_set_id(),
        state.genesis_block_id(),
        state.authenticated_genesis_application_parent_v0().copied(),
        current_view,
        last_voted_view,
        last_timeout_view,
        state.high_qc().clone(),
        state.locked_qc().clone(),
        state.finalized(),
        state.revision(),
        state.durable_observed_qcs().to_vec(),
        facts,
        vec![],
        state.payload_validation_completions().to_vec(),
        None,
        None,
        None,
        state.last_finalization().cloned(),
        state.state_sync_anchor().cloned(),
        state.application_applied(),
        state.finalization_queue().to_vec(),
        None,
        Some(halt),
    )
}

fn accept_qc(core: &mut Core, certificate: QuorumCertificate) -> Vec<Effect> {
    let effects = core
        .step(Input::QuorumCertificate(certificate), &RootSignatures)
        .expect("QC accepted");
    let (barrier, _) = persistence_effect(&effects);
    core.step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("persistence acknowledged")
}

fn finalization_gated_validation(
    payload: &[u8],
) -> (CoreConfig, Core, ValidationId, PayloadValidationResult) {
    let (config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let first = proposal(&set, genesis_qc(&set), 1, b"gated helper one");
    let first_qc = qc(&set, 1, 1, first.block().id());
    insert_valid_and_vote(&mut core, first);
    let second = proposal(&set, first_qc, 2, b"gated helper two");
    let second_qc = qc(&set, 2, 2, second.block().id());
    insert_valid_and_vote(&mut core, second);
    let third = proposal(&set, second_qc, 3, b"gated helper three");
    let third_qc = qc(&set, 3, 3, third.block().id());
    insert_valid_and_vote(&mut core, third);

    let child = proposal(&set, third_qc, 4, payload);
    let effects = core
        .step(Input::Proposal(Box::new(child)), &RootSignatures)
        .expect("ready justify creates finality and child validation");
    let (barrier, durable) = persistence_effect(&effects);
    assert!(durable.pending_finalize().is_some());
    let effects = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("finality and validation are released after persistence");
    assert!(effects
        .iter()
        .any(|effect| matches!(effect, Effect::Finalize(_))));
    let validation = validation_effect(&effects);
    let result = valid_result_for_effect(&core, &effects, validation);
    (config, core, validation, result)
}

fn awaiting_timeout_signature_with_missing_qc() -> (Core, ValidatorSet, QuorumCertificate) {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let durable_qc = qc(&set, 1, 1, BlockId::new([0xA1; 32]));
    let effects = core
        .step(
            Input::QuorumCertificate(durable_qc.clone()),
            &RootSignatures,
        )
        .expect("missing QC becomes durable");
    let (barrier, _) = persistence_effect(&effects);
    core.step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("missing QC acknowledgement releases sync");

    let effects = core
        .step(
            Input::LocalTimeout {
                epoch: Epoch::new(0),
                view: View::new(1),
            },
            &RootSignatures,
        )
        .expect("timeout intent can coexist with certified sync");
    let (barrier, _) = persistence_effect(&effects);
    assert!(matches!(
        core.step(Input::StorageAck { barrier }, &RootSignatures)
            .expect("timeout signature request is released")
            .as_slice(),
        [Effect::RequestSignature { .. }]
    ));
    (core, set, durable_qc)
}

fn known_invalid_with_durable_same_view_qc() -> (
    CoreConfig,
    Core,
    ValidatorSet,
    QuorumCertificate,
    QuorumCertificate,
) {
    let (config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let invalid_proposal = proposal(
        &set,
        genesis_qc(&set),
        1,
        b"known invalid same-view conflict target",
    );
    let invalid_block_id = invalid_proposal.block().id();

    let effects = core
        .step(Input::Proposal(Box::new(invalid_proposal)), &RootSignatures)
        .expect("uncertified proposal enters payload validation");
    let effects = release_persisted_effects(&mut core, effects);
    let validation = validation_effect(&effects);
    let effects = core
        .step(
            Input::PayloadValidated {
                id: validation,
                result: PayloadValidationResult::DeterministicallyInvalid,
            },
            &RootSignatures,
        )
        .expect("uncertified invalid result becomes durable");
    assert!(release_persisted_effects(&mut core, effects).is_empty());

    let durable_qc = qc(&set, 1, 1, BlockId::new([0x91; 32]));
    assert_ne!(durable_qc.block_id(), invalid_block_id);
    let effects = core
        .step(
            Input::QuorumCertificate(durable_qc.clone()),
            &RootSignatures,
        )
        .expect("first same-view QC becomes a durable sync obligation");
    let (barrier, durable) = persistence_effect(&effects);
    assert_eq!(
        durable
            .pending_standalone_qc_sync()
            .expect("first QC is retained durably")
            .active(),
        &durable_qc
    );
    assert!(matches!(
        core.step(Input::StorageAck { barrier }, &RootSignatures)
            .expect("first QC becomes durable before conflict injection")
            .as_slice(),
        [Effect::RequestStandaloneQcSync { certificate_id, .. }]
            if *certificate_id == durable_qc.id()
    ));

    let invalid_qc = qc(&set, 1, 1, invalid_block_id);
    (config, core, set, durable_qc, invalid_qc)
}

fn finalize_height_one(
    core: &mut Core,
) -> (
    ValidatorSet,
    QuorumCertificate,
    CoreIssuedApplicationFinalizationApplyAuthorityV0,
) {
    let finalization_authority = finalization_apply_authority_for_test(core);
    let set = core.config().validator_set().clone();
    let first = proposal(&set, genesis_qc(&set), 1, b"finalized stale-QC one");
    let first_qc = qc(&set, 1, 1, first.block().id());
    insert_valid_and_vote(core, first);
    accept_qc(core, first_qc.clone());

    let second = proposal(&set, first_qc.clone(), 2, b"finalized stale-QC two");
    let second_qc = qc(&set, 2, 2, second.block().id());
    insert_valid_and_vote(core, second);
    accept_qc(core, second_qc.clone());

    let third = proposal(&set, second_qc, 3, b"finalized stale-QC three");
    let third_qc = qc(&set, 3, 3, third.block().id());
    insert_valid_and_vote(core, third);
    let effects = accept_qc(core, third_qc);
    assert!(effects
        .iter()
        .any(|effect| matches!(effect, Effect::Finalize(_))));

    let effects = apply_finalization_for_test(core, &finalization_authority)
        .expect("height-one finality is applied");
    let effects = release_persisted_effects(core, effects);
    assert!(effects.is_empty());
    assert_eq!(core.safety_state().finalized().height(), Height::new(1));
    assert_eq!(
        core.safety_state().finalized().block_id(),
        first_qc.block_id()
    );
    (set, first_qc, finalization_authority)
}

fn short_epoch_core_before_last_regular() -> (
    CoreConfig,
    Core,
    ValidatorSet,
    ConsensusParametersV0,
    QuorumCertificate,
) {
    let parameters = short_epoch_parameters();
    let (config, mut core) = configured_core_with_parameters(parameters);
    let set = core.config().validator_set().clone();

    let first =
        proposal_with_parameters(&set, &parameters, genesis_qc(&set), 1, b"short epoch one");
    let first_qc = qc(&set, 1, 1, first.block().id());
    insert_valid_and_vote(&mut core, first);
    accept_qc(&mut core, first_qc.clone());

    let second = proposal_with_parameters(&set, &parameters, first_qc, 2, b"short epoch two");
    let second_qc = qc(&set, 2, 2, second.block().id());
    insert_valid_and_vote(&mut core, second);
    accept_qc(&mut core, second_qc.clone());

    (config, core, set, parameters, second_qc)
}

fn short_epoch_core_at_boundary() -> (
    CoreConfig,
    Core,
    ValidatorSet,
    ConsensusParametersV0,
    QuorumCertificate,
) {
    let (config, mut core, set, parameters, second_qc) = short_epoch_core_before_last_regular();
    let finalization_authority = finalization_apply_authority_for_test(&core);
    let third =
        proposal_with_parameters(&set, &parameters, second_qc, 3, b"short epoch last regular");
    let third_qc = qc(&set, 3, 3, third.block().id());
    insert_valid_and_vote(&mut core, third);
    let effects = accept_qc(&mut core, third_qc.clone());
    assert!(effects
        .iter()
        .any(|effect| matches!(effect, Effect::Finalize(_))));
    let effects = apply_finalization_for_test(&mut core, &finalization_authority)
        .expect("short epoch finality applies");
    assert!(release_persisted_effects(&mut core, effects).is_empty());
    assert_eq!(core.safety_state().current_view(), View::new(4));

    (config, core, set, parameters, third_qc)
}

#[test]
fn unauthenticated_peer_messages_are_rejected_without_state_change() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let genesis = genesis_qc(&set);
    let proposed = proposal(&set, genesis.clone(), 1, b"unauthenticated proposal");

    assert_rejected_without_state_change(&mut core, Input::Proposal(Box::new(proposed.clone())));
    assert_rejected_without_state_change(
        &mut core,
        Input::SyncedProposal(Box::new(proposed.clone())),
    );
    assert_rejected_without_state_change(
        &mut core,
        Input::Vote(signed_vote(
            &set,
            1,
            1,
            proposed.block().id(),
            validator_id(2),
        )),
    );
    assert_rejected_without_state_change(
        &mut core,
        Input::TimeoutVote(timeout_vote(
            &set,
            1,
            genesis.clone().into_qc_reference().qc_ref(),
            validator_id(2),
        )),
    );
    assert_rejected_without_state_change(
        &mut core,
        Input::QuorumCertificate(qc(&set, 1, 1, proposed.block().id())),
    );
    assert_rejected_without_state_change(
        &mut core,
        Input::TimeoutCertificate(timeout_certificate(&set, 1, genesis)),
    );
}

#[test]
fn wrong_consensus_context_is_rejected_without_state_change() {
    let (_config, mut core) = configured_core();
    let parameters = consensus_parameters();
    let foreign_set = ValidatorSet::new(
        GenesisHash::new([0xA5; 32]),
        CHAIN,
        version(),
        Epoch::new(1),
        parameters.hash(),
        (1..=4)
            .map(|index| {
                Validator::new(
                    validator_id(index),
                    ConsensusPublicKey::new([index.saturating_add(100); 32]),
                    VotingPower::new(1).expect("positive voting power"),
                )
                .expect("valid validator")
            })
            .collect(),
    )
    .expect("valid foreign validator set");
    let foreign_vote = signed_vote(
        &foreign_set,
        1,
        1,
        BlockId::new([0x44; 32]),
        validator_id(2),
    );
    let before = core.clone();

    assert!(core
        .step(Input::Vote(foreign_vote), &RootSignatures)
        .is_err());
    assert_eq!(core, before);
}

#[test]
fn busy_gate_precedes_peer_authentication() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    core.step(
        Input::LocalTimeout {
            epoch: Epoch::new(0),
            view: View::new(1),
        },
        &RootSignatures,
    )
    .expect("timeout enters the persistence barrier");
    let before = core.clone();
    let vote = signed_vote(&set, 1, 1, BlockId::new([0x45; 32]), validator_id(2));

    assert!(matches!(
        core.step(Input::Vote(vote), &RejectSignatures),
        Err(CoreError::Busy(_))
    ));
    assert_eq!(core, before);
}

#[test]
fn vote_signing_is_persist_ack_sign_verify_broadcast() {
    let (config, mut core) = configured_core();
    let set = core.config().validator_set();
    let proposal = proposal(set, genesis_qc(set), 1, b"one");
    let effects = core
        .step(Input::Proposal(Box::new(proposal)), &RootSignatures)
        .expect("proposal accepted");
    let effects = release_persisted_effects(&mut core, effects);
    let validation = validation_effect(&effects);
    let result = valid_result_for_effect(&core, &effects, validation);

    let effects = core
        .step(
            Input::PayloadValidated {
                id: validation,
                result,
            },
            &RootSignatures,
        )
        .expect("valid payload accepted");
    let (barrier, persisted) = persistence_effect(&effects);
    let transition = persistence_request(&effects)
        .safety_rules_shadow_transition_v1()
        .expect("vote persistence carries the exact SafetyRules shadow transition");
    assert_eq!(transition.kind(), InertSafetyTransitionKindV1::Vote);
    assert_eq!(transition.successor_state().revision(), barrier.get());
    assert_eq!(
        transition.canonical_intent().authorizing_safety_revision(),
        barrier.get()
    );
    assert!(persisted.pending_sign().is_some());
    let completion = persisted
        .payload_validation_completions()
        .iter()
        .find(|completion| completion.id() == validation)
        .expect("Valid completion is durable");
    let commitments = completion
        .result()
        .commitments()
        .expect("Valid completion retains inert comparison facts");
    assert_eq!(commitments.block_id(), validation.block_id());
    assert!(commitments.logical_block_size() > 0);
    assert_eq!(commitments.transaction_count(), 1);
    assert_eq!(
        persisted.payload_terminal_result(validation.block_id()),
        Some(PayloadTerminalResult::Valid)
    );
    assert_safety_state_record_roundtrip_and_validate(&config, &persisted);
    assert!(matches!(
        core.step(
            Input::LocalTimeout {
                epoch: Epoch::new(0),
                view: View::new(1),
            },
            &RootSignatures,
        ),
        Err(CoreError::Busy(_))
    ));

    let request = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("write acknowledged");
    let [Effect::RequestSignature { intent }] = request.as_slice() else {
        panic!("expected one complete canonical sign intent: {request:?}");
    };
    intent
        .validate(core.config().validator_set())
        .expect("Core emits a self-consistent signer contract");
    assert_eq!(intent.author(), core.config().local_validator());
    assert_eq!(intent.authorizing_safety_revision(), barrier.get());
    assert!(matches!(
        intent.preimage(),
        CanonicalSignPreimageV0::Vote(preimage)
            if preimage.block_id() == validation.block_id()
    ));
    let (sign_id, root) = signature_request(&request);
    let invalid_signature = SignatureBytes::from_array([0xEE; SIGNATURE_BYTES]);
    assert!(matches!(
        core.step(
            Input::SignatureReady {
                id: sign_id,
                signature: invalid_signature,
            },
            &RootSignatures,
        ),
        Err(CoreError::Protocol(_))
    ));
    let effects = core
        .step(
            Input::SignatureReady {
                id: sign_id,
                signature: signature(root),
            },
            &RootSignatures,
        )
        .expect("signature verified");
    assert!(matches!(
        effects.as_slice(),
        [Effect::Broadcast(OutboundMessage::Vote(_))]
    ));
    assert!(core.safety_state().pending_sign().is_none());
    assert!(core
        .safety_state()
        .matches_signature_released_successor_of_v0(&persisted));
    assert!(!persisted.matches_signature_released_successor_of_v0(core.safety_state()));
}

#[test]
fn timeout_signing_uses_the_same_durable_barrier() {
    let (config, mut core) = configured_core();
    let effects = core
        .step(
            Input::LocalTimeout {
                epoch: Epoch::new(0),
                view: View::new(1),
            },
            &RootSignatures,
        )
        .expect("timeout accepted");
    let (barrier, persisted) = persistence_effect(&effects);
    assert_safety_state_record_roundtrip_and_validate(&config, &persisted);
    let request = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("timeout state durable");
    let [Effect::RequestSignature { intent }] = request.as_slice() else {
        panic!("expected one complete timeout sign intent: {request:?}");
    };
    intent
        .validate(core.config().validator_set())
        .expect("timeout signer contract validates independently");
    assert_eq!(intent.authorizing_safety_revision(), barrier.get());
    assert!(matches!(
        intent.preimage(),
        CanonicalSignPreimageV0::TimeoutVote(preimage)
            if preimage.view() == View::new(1)
    ));
    let (id, root) = signature_request(&request);
    let effects = core
        .step(
            Input::SignatureReady {
                id,
                signature: signature(root),
            },
            &RootSignatures,
        )
        .expect("timeout signature verified");
    assert!(matches!(
        effects.as_slice(),
        [Effect::Broadcast(OutboundMessage::TimeoutVote(_))]
    ));
    assert!(core
        .safety_state()
        .matches_signature_released_successor_of_v0(&persisted));
    assert!(!persisted.matches_signature_released_successor_of_v0(core.safety_state()));
}

#[test]
fn persisted_sign_intent_is_re_requested_after_recovery() {
    let (config, mut core) = configured_core();
    let effects = core
        .step(
            Input::LocalTimeout {
                epoch: Epoch::new(0),
                view: View::new(1),
            },
            &RootSignatures,
        )
        .expect("timeout accepted");
    let (_barrier, state) = persistence_effect(&effects);
    let expected = state.pending_sign().expect("durable intent").id();

    let mut recovered =
        Core::recover(config, state, &RootSignatures).expect("valid recovery state");
    let effects = recovered
        .step(Input::Resume, &RootSignatures)
        .expect("resume accepted");
    let (id, _) = signature_request(&effects);
    assert_eq!(id, expected);
}

#[test]
fn callback_persistence_preserves_exact_sign_intent_across_crash_resume() {
    let (config, mut core) = configured_core();
    let set = config.validator_set().clone();
    let proposed = proposal(&set, genesis_qc(&set), 1, b"callback during signing");
    let proposal_effects = core
        .step(Input::Proposal(Box::new(proposed)), &RootSignatures)
        .expect("proposal accepted");
    let validation_effects = release_persisted_effects(&mut core, proposal_effects);
    let validation_id = validation_effect(&validation_effects);
    let validation_result = valid_result_for_effect(&core, &validation_effects, validation_id);

    let timeout_effects = core
        .step(
            Input::LocalTimeout {
                epoch: Epoch::new(0),
                view: View::new(1),
            },
            &RootSignatures,
        )
        .expect("timeout signing intent staged");
    let (sign_barrier, sign_state) = persistence_effect(&timeout_effects);
    assert_eq!(
        sign_state
            .pending_sign()
            .expect("signing outbox is durable")
            .authorizing_safety_revision(),
        sign_barrier.get()
    );
    let request = core
        .step(
            Input::StorageAck {
                barrier: sign_barrier,
            },
            &RootSignatures,
        )
        .expect("first signing barrier acknowledged");
    let first_intent = match request.as_slice() {
        [Effect::RequestSignature { intent }] => intent.clone(),
        _ => panic!("expected one complete signature request: {request:?}"),
    };
    let first_bytes = first_intent
        .canonical_bytes()
        .expect("first intent has canonical bytes");
    let first_fingerprint = first_intent.fingerprint();
    let first_revision = first_intent.authorizing_safety_revision();
    assert_eq!(first_revision, sign_barrier.get());

    let callback_effects = core
        .step(
            Input::PayloadValidated {
                id: validation_id,
                result: validation_result,
            },
            &RootSignatures,
        )
        .expect("the exact registered callback may persist while signing");
    let (callback_barrier, callback_state) = persistence_effect(&callback_effects);
    assert_eq!(
        callback_barrier.get(),
        sign_barrier
            .get()
            .checked_add(1)
            .expect("fixture revision fits")
    );
    assert_eq!(
        callback_state
            .pending_sign()
            .expect("callback persistence preserves the signing outbox")
            .authorizing_safety_revision(),
        first_revision
    );
    assert_safety_state_record_roundtrip_and_validate(&config, &callback_state);
    assert!(core
        .step(
            Input::StorageAck {
                barrier: callback_barrier,
            },
            &RootSignatures,
        )
        .expect("callback persistence acknowledged")
        .is_empty());

    assert_eq!(
        Core::recover(config.clone(), callback_state.clone(), &RootSignatures),
        Err(CoreError::InvalidRecovery(
            "a current NativeValid completion requires its dedicated cross-store recovery session"
        ))
    );
    let resumed_intent = callback_state
        .pending_sign()
        .expect("the dedicated recovery challenge retains the exact sign intent");
    let resumed_canonical = canonical_sign_intent_for_test(&config, resumed_intent);
    assert_eq!(resumed_intent.authorizing_safety_revision(), first_revision);
    assert_eq!(resumed_canonical.fingerprint(), first_fingerprint);
    assert_eq!(
        resumed_canonical
            .canonical_bytes()
            .expect("resumed intent has canonical bytes"),
        first_bytes
    );
    assert_eq!(resumed_canonical, first_intent);
}

#[test]
fn synced_callback_persistence_preserves_exact_vote_intent_across_crash_resume() {
    let (config, mut core) = configured_core();
    let set = config.validator_set().clone();

    let unrelated = proposal(&set, genesis_qc(&set), 1, b"unrelated synced callback");
    let unrelated_effects = core
        .step(Input::SyncedProposal(Box::new(unrelated)), &RootSignatures)
        .expect("unrelated synced proposal accepted");
    let unrelated_validation_effects = release_persisted_effects(&mut core, unrelated_effects);
    let unrelated_id = synced_validation_effect(&unrelated_validation_effects);
    let unrelated_result =
        valid_result_for_effect(&core, &unrelated_validation_effects, unrelated_id);

    let timeout = timeout_certificate(&set, 1, genesis_qc(&set));
    let vote_proposal = timeout_proposal(&set, timeout.clone(), b"vote after timeout");
    let timeout_effects = core
        .step(Input::TimeoutCertificate(timeout), &RootSignatures)
        .expect("timeout certificate advances the current view");
    let (timeout_barrier, _) = persistence_effect(&timeout_effects);
    core.step(
        Input::StorageAck {
            barrier: timeout_barrier,
        },
        &RootSignatures,
    )
    .expect("timeout progress is durable");

    let proposal_effects = core
        .step(Input::Proposal(Box::new(vote_proposal)), &RootSignatures)
        .expect("view-two proposal accepted");
    let vote_validation_effects = release_persisted_effects(&mut core, proposal_effects);
    let vote_validation_id = validation_effect(&vote_validation_effects);
    let vote_validation_result =
        valid_result_for_effect(&core, &vote_validation_effects, vote_validation_id);
    let sign_effects = core
        .step(
            Input::PayloadValidated {
                id: vote_validation_id,
                result: vote_validation_result,
            },
            &RootSignatures,
        )
        .expect("validated proposal stages a vote intent");
    let (sign_barrier, sign_state) = persistence_effect(&sign_effects);
    assert!(matches!(
        sign_state.pending_sign(),
        Some(SignIntent::Vote {
            authorizing_safety_revision,
            block_id,
            ..
        }) if *authorizing_safety_revision == sign_barrier.get()
            && *block_id == vote_validation_id.block_id()
    ));
    let request = core
        .step(
            Input::StorageAck {
                barrier: sign_barrier,
            },
            &RootSignatures,
        )
        .expect("vote signing barrier acknowledged");
    let first_intent = match request.as_slice() {
        [Effect::RequestSignature { intent }] => intent.clone(),
        _ => panic!("expected one complete vote signature request: {request:?}"),
    };
    assert!(matches!(
        first_intent.preimage(),
        CanonicalSignPreimageV0::Vote(preimage)
            if preimage.block_id() == vote_validation_id.block_id()
    ));
    let first_bytes = first_intent
        .canonical_bytes()
        .expect("first vote intent has canonical bytes");
    let first_fingerprint = first_intent.fingerprint();
    let first_revision = first_intent.authorizing_safety_revision();

    let callback_effects = core
        .step(
            Input::SyncedPayloadValidated {
                id: unrelated_id,
                result: unrelated_result,
            },
            &RootSignatures,
        )
        .expect("the unrelated exact synced callback may persist while signing");
    let (callback_barrier, callback_state) = persistence_effect(&callback_effects);
    assert_eq!(
        callback_barrier.get(),
        sign_barrier
            .get()
            .checked_add(1)
            .expect("fixture revision fits")
    );
    assert_eq!(
        callback_state
            .pending_sign()
            .expect("callback persistence preserves the vote outbox")
            .authorizing_safety_revision(),
        first_revision
    );
    assert_safety_state_record_roundtrip_and_validate(&config, &callback_state);
    assert!(core
        .step(
            Input::StorageAck {
                barrier: callback_barrier,
            },
            &RootSignatures,
        )
        .expect("unrelated callback persistence acknowledged")
        .is_empty());

    assert_eq!(
        Core::recover(config.clone(), callback_state.clone(), &RootSignatures),
        Err(CoreError::InvalidRecovery(
            "a current NativeValid completion requires its dedicated cross-store recovery session"
        ))
    );
    let resumed_intent = callback_state
        .pending_sign()
        .expect("the dedicated recovery challenge retains the exact vote intent");
    let resumed_canonical = canonical_sign_intent_for_test(&config, resumed_intent);
    assert_eq!(resumed_intent.authorizing_safety_revision(), first_revision);
    assert_eq!(resumed_canonical.fingerprint(), first_fingerprint);
    assert_eq!(
        resumed_canonical
            .canonical_bytes()
            .expect("resumed vote intent has canonical bytes"),
        first_bytes
    );
    assert_eq!(resumed_canonical, first_intent);
}

#[test]
fn only_the_deterministic_leader_can_propose() {
    let set = validator_set();
    let wrong = validator_id(2);
    assert_ne!(wrong, leader_for(&set, View::new(1)));
    assert!(matches!(
        try_proposal_with_proposer(
            &set,
            &consensus_parameters(),
            genesis_qc(&set),
            1,
            b"wrong",
            wrong,
        ),
        Err(ValidationError::InvalidProposal(_))
    ));
}

#[test]
fn a_genesis_proposal_cannot_skip_views_without_a_timeout_certificate() {
    let set = validator_set();
    let proposer = leader_for(&set, View::new(9));
    let proposed = block(&set, 9, 1, GENESIS, b"view skip", proposer);
    assert!(signed_proposal_from_block(
        &set,
        &consensus_parameters(),
        proposed,
        genesis_qc(&set).into_qc_reference(),
        None,
        GENESIS_TIMESTAMP_MS,
    )
    .is_err());
}

#[test]
fn synthetic_genesis_bootstraps_but_signed_ordinary_view_zero_cannot_be_constructed() {
    let (_config, core) = configured_core();
    let set = core.config().validator_set().clone();
    assert!(matches!(
        core.safety_state().high_qc().as_synthetic(),
        Some(ContextAuthorizedQcV0::Genesis(_))
    ));

    let votes = [1, 2, 3]
        .into_iter()
        .map(|author| signed_vote(&set, 0, 0, GENESIS, validator_id(author)))
        .collect();
    assert_eq!(
        QuorumCertificate::new(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(0),
            Height::new(0),
            GENESIS,
            set.id(),
            votes,
            &set,
        ),
        Err(ValidationError::InvalidCertificate(
            "ordinary QC view must be positive"
        ))
    );
    assert!(core.safety_state().high_qc().as_ordinary().is_none());
}

#[test]
fn genesis_anchor_accepts_view_one_and_an_exact_tc_authorized_skipped_view() {
    let (view_one_config, mut view_one_core) = configured_core();
    let set = view_one_core.config().validator_set().clone();
    let view_one = proposal(&set, genesis_qc(&set), 1, b"view one");
    let effects = view_one_core
        .step(Input::Proposal(Box::new(view_one)), &RootSignatures)
        .expect("view-one Genesis proposal accepted");
    let (_barrier, state) = persistence_effect(&effects);
    assert_eq!(state.current_view(), View::new(1));
    assert_safety_state_record_roundtrip_and_validate(&view_one_config, &state);

    let (skipped_config, mut skipped_core) = configured_core();
    let skipped = timeout_proposal(
        &set,
        timeout_certificate(&set, 8, genesis_qc(&set)),
        b"skipped view",
    );
    let effects = skipped_core
        .step(Input::Proposal(Box::new(skipped)), &RootSignatures)
        .expect("exact Genesis TC authorizes the skipped view");
    let (_barrier, state) = persistence_effect(&effects);
    assert_eq!(state.current_view(), View::new(9));
    assert!(state.high_qc().as_synthetic().is_some());
    assert!(state.locked_qc().as_synthetic().is_some());
    assert_safety_state_record_roundtrip_and_validate(&skipped_config, &state);
}

#[test]
fn a_qc_never_finalizes_without_a_complete_verified_three_chain() {
    let (config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let genesis = genesis_qc(&set);

    let p1 = proposal(&set, genesis, 1, b"one");
    let committed_id = p1.block().id();
    let q1 = qc(&set, 1, 1, p1.block().id());
    insert_valid_and_vote(&mut core, p1);
    let effects = accept_qc(&mut core, q1.clone());
    assert!(!effects
        .iter()
        .any(|effect| matches!(effect, Effect::Finalize(_))));

    let p2 = proposal(&set, q1.clone(), 2, b"two");
    let q2 = qc(&set, 2, 2, p2.block().id());
    insert_valid_and_vote(&mut core, p2);
    let effects = accept_qc(&mut core, q2.clone());
    assert!(!effects
        .iter()
        .any(|effect| matches!(effect, Effect::Finalize(_))));

    let p3 = proposal(&set, q2, 3, b"three");
    let q3 = qc(&set, 3, 3, p3.block().id());
    insert_valid_and_vote(&mut core, p3);

    let effects = core
        .step(Input::QuorumCertificate(q3), &RootSignatures)
        .expect("third QC accepted");
    assert!(!effects
        .iter()
        .any(|effect| matches!(effect, Effect::Finalize(_))));
    let (barrier, state) = persistence_effect(&effects);
    assert_eq!(state.finalized().block_id(), committed_id);
    assert!(state.pending_finalize().is_some());
    let decoded_roundtrip = roundtrip_safety_state_record(&config, &state);
    assert_eq!(
        decoded_roundtrip.durable_observed_qcs(),
        state.durable_observed_qcs(),
        "nonempty ordinary-QC observations survive the canonical record roundtrip",
    );
    Core::validate_persisted_state_v0(&config, &decoded_roundtrip, &RootSignatures)
        .expect("the roundtripped three-chain state remains valid");
    let effects = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("commit state durable");
    let proof = effects
        .iter()
        .find_map(|effect| match effect {
            Effect::Finalize(proof) => Some(proof),
            _ => None,
        })
        .expect("finalize released only after persistence");
    assert_eq!(proof.finalized_block().header().id(), committed_id);
    let durable = state
        .last_finalization()
        .expect("permanent proof and authenticated parent are durable");
    assert_eq!(durable.proof_id(), state.pending_finalize().unwrap());
    proof
        .verify(
            &set,
            None,
            &consensus_parameters(),
            durable.authenticated_parent().timestamp_ms(),
            &RootSignatures,
        )
        .expect("emitted FinalityProofV0 fully verifies");
}

#[test]
fn a_qc_with_unknown_ancestry_cannot_advance_high_qc_after_finalization() {
    let (_config, mut core) = configured_core();
    let finalization_authority = finalization_apply_authority_for_test(&core);
    let set = core.config().validator_set().clone();
    let p1 = proposal(&set, genesis_qc(&set), 1, b"one");
    let q1 = qc(&set, 1, 1, p1.block().id());
    let finalized_id = p1.block().id();
    insert_valid_and_vote(&mut core, p1);
    accept_qc(&mut core, q1.clone());

    let p2 = proposal(&set, q1, 2, b"two");
    let q2 = qc(&set, 2, 2, p2.block().id());
    insert_valid_and_vote(&mut core, p2);
    accept_qc(&mut core, q2.clone());

    let p3 = proposal(&set, q2, 3, b"three");
    let q3 = qc(&set, 3, 3, p3.block().id());
    insert_valid_and_vote(&mut core, p3);
    let effects = core
        .step(Input::QuorumCertificate(q3.clone()), &RootSignatures)
        .expect("third QC accepted");
    let (barrier, state) = persistence_effect(&effects);
    assert!(state.pending_finalize().is_some());
    let effects = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("finality state durable");
    assert!(effects
        .iter()
        .any(|effect| matches!(effect, Effect::Finalize(_))));
    let effects = apply_finalization_for_test(&mut core, &finalization_authority)
        .expect("application finalized");
    let (barrier, _) = persistence_effect(&effects);
    core.step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("finalization acknowledgement durable");
    assert_eq!(core.safety_state().finalized().block_id(), finalized_id);

    let unknown = qc(&set, 4, 2, BlockId::new([0xD4; 32]));
    let effects = core
        .step(Input::QuorumCertificate(unknown.clone()), &RootSignatures)
        .expect("unknown QC creates a durable catch-up obligation");
    let (barrier, durable) = persistence_effect(&effects);
    let pending = durable
        .pending_standalone_qc_sync()
        .expect("standalone QC target is persisted before requesting data");
    assert_eq!(pending.active().id(), unknown.id());
    assert!(pending.backlog().is_empty());
    let effects = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("standalone QC target is durable");
    assert!(matches!(
        effects.as_slice(),
        [Effect::RequestStandaloneQcSync {
            certificate_id,
            target,
            ..
        }] if *certificate_id == unknown.id() && target.block_id() == unknown.block_id()
    ));
    assert_eq!(core.safety_state().high_qc().id(), q3.id());
    assert_eq!(core.safety_state().finalized().block_id(), finalized_id);
}

#[test]
fn same_height_different_view_qc_is_finalized_subsumed_and_idempotent() {
    let (_config, mut core) = configured_core();
    let (set, _finalized_qc, _finalization_authority) = finalize_height_one(&mut core);
    let stale = qc(&set, 7, 1, BlockId::new([0xD7; 32]));
    let before = core.safety_state().clone();

    let effects = core
        .step(Input::QuorumCertificate(stale.clone()), &RootSignatures)
        .expect("different-view historical QC is operationally subsumed");
    let (barrier, durable) = persistence_effect(&effects);
    assert_ne!(&durable, &before);
    assert!(durable
        .durable_observed_qcs()
        .iter()
        .any(|certificate| certificate.id() == stale.id()));
    core.step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("historical QC observation is durable");
    let after_first = core.safety_state().clone();
    assert!(after_first.pending_standalone_qc_sync().is_none());

    assert!(core
        .step(Input::QuorumCertificate(stale), &RootSignatures)
        .expect("the same subsumed QC is idempotent")
        .is_empty());
    assert_eq!(core.safety_state(), &after_first);
}

#[test]
fn same_view_competitor_at_finalized_height_halts_before_subsumption_and_recovers() {
    let (config, mut core) = configured_core();
    let (set, finalized_qc, _finalization_authority) = finalize_height_one(&mut core);
    let conflict = qc(&set, 1, 1, BlockId::new([0xC1; 32]));

    let mut recovered_live =
        Core::recover(config.clone(), core.safety_state().clone(), &RootSignatures)
            .expect("finality proof and safety anchors recover before replay");
    let recovered_effects = recovered_live
        .step(Input::QuorumCertificate(conflict.clone()), &RootSignatures)
        .expect("durable proof QC detects the conflict even during recovery replay");
    assert!(recovered_effects.iter().any(|effect| matches!(
        effect,
        Effect::PersistSafetyState(request)
            if matches!(
                request.state().safety_halt(),
                Some(SafetyHalt::ConflictingQuorumCertificates { .. })
            )
    )));

    let effects = core
        .step(Input::QuorumCertificate(conflict.clone()), &RootSignatures)
        .expect("same-view conflict crosses a durable halt before stale classification");
    let (barrier, halted) = effects
        .iter()
        .find_map(|effect| match effect {
            Effect::PersistSafetyState(request) => {
                Some((request.barrier(), request.state().clone()))
            }
            _ => None,
        })
        .expect("same-view finalized conflict persists its full witness");
    let (first, second) = halted
        .safety_halt()
        .and_then(SafetyHalt::conflicting_qcs)
        .expect("both quorum certificates are retained");
    let ids = [first.id(), second.id()];
    assert!(ids.contains(&finalized_qc.id()));
    assert!(ids.contains(&conflict.id()));
    assert_eq!(halted.finalized().block_id(), finalized_qc.block_id());
    assert!(matches!(
        core.step(Input::StorageAck { barrier }, &RootSignatures)
            .expect("halt acknowledgement releases only the halt effect")
            .as_slice(),
        [Effect::SafetyHalted(_)]
    ));

    let mut recovered =
        Core::recover(config, halted, &RootSignatures).expect("durable stale-QC halt recovers");
    assert!(matches!(
        recovered
            .step(Input::Resume, &RootSignatures)
            .expect("recovery reissues the same halt")
            .as_slice(),
        [Effect::SafetyHalted(_)]
    ));
}

#[test]
fn two_historical_qcs_from_one_later_view_halt_on_the_second_arrival() {
    let (config, mut core) = configured_core();
    let (set, _finalized_qc, _finalization_authority) = finalize_height_one(&mut core);
    let first = qc(&set, 7, 1, BlockId::new([0x71; 32]));
    let second = qc(&set, 7, 1, BlockId::new([0x72; 32]));

    let first_effects = core
        .step(Input::QuorumCertificate(first.clone()), &RootSignatures)
        .expect("first different-view historical QC is retained durably");
    let (first_barrier, first_state) = persistence_effect(&first_effects);
    assert!(first_state
        .durable_observed_qcs()
        .iter()
        .any(|certificate| certificate.id() == first.id()));
    core.step(
        Input::StorageAck {
            barrier: first_barrier,
        },
        &RootSignatures,
    )
    .expect("first historical QC persistence is acknowledged");

    // The second carrier is deliberately admitted by a fresh Core.  This is
    // the crash boundary that used to erase the first witness from the
    // volatile observed-QC map.
    let mut recovered = Core::recover(config, first_state, &RootSignatures)
        .expect("durable historical QC observation recovers");
    let effects = recovered
        .step(Input::QuorumCertificate(second.clone()), &RootSignatures)
        .expect("second QC in that same historical view detects the conflict");
    let halted = effects
        .iter()
        .find_map(|effect| match effect {
            Effect::PersistSafetyState(request) => Some(request.state()),
            _ => None,
        })
        .expect("historical same-view conflict persists before subsumption");
    let (retained_first, retained_second) = halted
        .safety_halt()
        .and_then(SafetyHalt::conflicting_qcs)
        .expect("historical conflict retains both QCs");
    let ids = [retained_first.id(), retained_second.id()];
    assert!(ids.contains(&first.id()));
    assert!(ids.contains(&second.id()));
}

#[test]
fn active_qc_conflict_retention_fails_closed_at_capacity() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let maximum = core.config().max_observed_messages();

    for view in 1..=maximum as u64 {
        let mut block_id = [0xC8; 32];
        block_id[..8].copy_from_slice(&view.to_be_bytes());
        let certificate = qc(&set, view, 1, BlockId::new(block_id));
        assert!(core
            .observe_qc_for_test(&certificate)
            .expect("active QC fits the conflict-retention budget")
            .is_none());
    }
    assert_eq!(core.observed_qc_views_for_test().len(), maximum);

    let mut overflow_id = [0xC9; 32];
    overflow_id[..8].copy_from_slice(&(maximum as u64 + 1).to_be_bytes());
    let overflow = qc(&set, maximum as u64 + 1, 1, BlockId::new(overflow_id));
    let before = core.observed_qc_views_for_test();
    assert_eq!(
        core.observe_qc_for_test(&overflow),
        Err(CoreError::ObservedQcRetentionFull)
    );
    assert_eq!(core.observed_qc_views_for_test(), before);
}

#[test]
fn finalized_block_id_with_a_different_qc_view_is_rejected_transactionally() {
    let (_config, mut core) = configured_core();
    let (set, finalized_qc, _finalization_authority) = finalize_height_one(&mut core);
    let malformed = qc(&set, 7, 1, finalized_qc.block_id());
    let before = core.clone();

    assert!(matches!(
        core.step(Input::QuorumCertificate(malformed), &RootSignatures),
        Err(CoreError::ConflictingCertificate)
    ));
    assert_eq!(core, before);
}

#[test]
fn finalized_block_id_with_a_lower_qc_height_is_rejected_transactionally() {
    let (_config, mut core) = configured_core();
    let (set, _finalized_qc, finalization_authority) = finalize_height_one(&mut core);
    let third_qc = core
        .safety_state()
        .high_qc()
        .as_ordinary()
        .expect("height-three high QC")
        .clone();
    let fourth = proposal(&set, third_qc, 4, b"advance finality to height two");
    let fourth_qc = qc(&set, 4, 4, fourth.block().id());
    insert_valid_and_vote(&mut core, fourth);
    let effects = accept_qc(&mut core, fourth_qc);
    assert!(effects
        .iter()
        .any(|effect| matches!(effect, Effect::Finalize(_))));
    let effects = apply_finalization_for_test(&mut core, &finalization_authority)
        .expect("height-two finality applied");
    assert!(release_persisted_effects(&mut core, effects).is_empty());
    assert_eq!(core.safety_state().finalized().height(), Height::new(2));

    let malformed = qc(&set, 7, 1, core.safety_state().finalized().block_id());
    let before = core.clone();
    assert!(matches!(
        core.step(Input::QuorumCertificate(malformed), &RootSignatures),
        Err(CoreError::ConflictingCertificate)
    ));
    assert_eq!(core, before);
}

#[test]
fn tc_with_a_subsumed_competing_selected_qc_advances_only_its_view() {
    let (_config, mut core) = configured_core();
    let (set, _finalized_qc, _finalization_authority) = finalize_height_one(&mut core);
    let stale = qc(&set, 7, 1, BlockId::new([0xA7; 32]));
    let certificate = timeout_certificate(&set, 10, stale);
    let before = core.safety_state().clone();

    let effects = core
        .step(Input::TimeoutCertificate(certificate), &RootSignatures)
        .expect("the TC remains an independently authenticated view transition");
    let (barrier, durable) = persistence_effect(&effects);
    assert_eq!(durable.current_view(), View::new(11));
    assert_eq!(durable.high_qc(), before.high_qc());
    assert_eq!(durable.locked_qc(), before.locked_qc());
    assert_eq!(durable.finalized(), before.finalized());
    assert!(durable.pending_tc_high_qc_sync().is_none());
    assert!(durable.pending_standalone_qc_sync().is_none());
    assert!(matches!(
        core.step(Input::StorageAck { barrier }, &RootSignatures)
            .expect("TC view progress becomes durable")
            .as_slice(),
        [Effect::ArmViewTimer { view, .. }] if *view == View::new(11)
    ));
}

#[test]
fn unrelated_subsumed_qc_does_not_join_an_active_tc_obligation() {
    let (_config, mut core) = configured_core();
    let (set, _finalized_qc, _finalization_authority) = finalize_height_one(&mut core);
    let target = qc(&set, 7, 2, BlockId::new([0xA2; 32]));
    let certificate = timeout_certificate(&set, 10, target);
    let effects = core
        .step(
            Input::TimeoutCertificate(certificate.clone()),
            &RootSignatures,
        )
        .expect("missing TC target becomes durable");
    let (barrier, pending) = persistence_effect(&effects);
    assert_eq!(
        pending
            .pending_tc_high_qc_sync()
            .expect("TC obligation")
            .certificate_id(),
        certificate.id()
    );
    core.step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("TC obligation is durable");
    let before = core.safety_state().clone();

    let unrelated = qc(&set, 8, 1, BlockId::new([0xB8; 32]));
    let effects = core
        .step(Input::QuorumCertificate(unrelated.clone()), &RootSignatures)
        .expect("unrelated historical QC is already subsumed");
    let (unrelated_barrier, durable) = persistence_effect(&effects);
    assert_ne!(&durable, &before);
    assert!(durable.pending_tc_high_qc_sync().is_some());
    core.step(
        Input::StorageAck {
            barrier: unrelated_barrier,
        },
        &RootSignatures,
    )
    .expect("unrelated historical QC observation is durable");
    assert!(core.safety_state().pending_standalone_qc_sync().is_none());
    assert!(core
        .safety_state()
        .durable_observed_qcs()
        .iter()
        .any(|candidate| candidate.block_id() == unrelated.block_id()));
    assert_eq!(
        core.safety_state()
            .pending_tc_high_qc_sync()
            .expect("the exact TC remains active")
            .certificate_id(),
        certificate.id()
    );
}

#[test]
fn known_stale_prefix_in_a_carried_tc_advances_view_without_extending_child() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let competing_tc = timeout_certificate(&set, 6, genesis_qc(&set));
    let competing_parent =
        timeout_proposal(&set, competing_tc, b"known same-height competing parent");
    let competing_qc = qc(&set, 7, 1, competing_parent.block().id());
    replay_valid(&mut core, competing_parent);

    let (_set, _finalized_qc, _finalization_authority) = finalize_height_one(&mut core);
    let carrier_tc = timeout_certificate(&set, 10, competing_qc);
    let carrier = timeout_proposal(&set, carrier_tc, b"must not extend stale known parent");
    let before = core.safety_state().clone();
    let effects = core
        .step(Input::Proposal(Box::new(carrier)), &RootSignatures)
        .expect("known stale prefix is a view-only carried-TC transition");
    let (barrier, durable) = persistence_effect(&effects);
    assert_eq!(durable.current_view(), View::new(11));
    assert_eq!(durable.high_qc(), before.high_qc());
    assert_eq!(durable.locked_qc(), before.locked_qc());
    assert_eq!(durable.finalized(), before.finalized());
    assert!(durable.pending_tc_high_qc_sync().is_none());
    assert!(durable.pending_standalone_qc_sync().is_none());
    assert_eq!(core.pending_validation_count(), 0);
    assert!(matches!(
        core.step(Input::StorageAck { barrier }, &RootSignatures)
            .expect("carried TC view progress is durable")
            .as_slice(),
        [Effect::ArmViewTimer { view, .. }] if *view == View::new(11)
    ));
}

#[test]
fn proposal_carried_finalized_subsumed_qc_is_dropped_without_sync_or_error() {
    let (_config, mut core) = configured_core();
    let (set, _finalized_qc, _finalization_authority) = finalize_height_one(&mut core);
    let stale = qc(&set, 7, 1, BlockId::new([0xB7; 32]));
    let carrier = proposal(&set, stale.clone(), 8, b"subsumed carrier child");
    let before = core.safety_state().clone();

    let effects = core
        .step(Input::Proposal(Box::new(carrier)), &RootSignatures)
        .expect("missing stale parent is subsumed without a fetch loop");
    let (barrier, durable) = persistence_effect(&effects);
    assert_ne!(&durable, &before);
    assert!(durable
        .durable_observed_qcs()
        .iter()
        .any(|candidate| candidate.block_id() == stale.block_id()));
    core.step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("carried historical QC observation is durable");
    assert_eq!(core.pending_validation_count(), 0);
    assert!(core.safety_state().pending_tc_high_qc_sync().is_none());
    assert!(core.safety_state().pending_standalone_qc_sync().is_none());
}

#[test]
fn tc_reference_conflict_halts_before_subsumed_view_progress() {
    let (_config, mut core) = configured_core();
    let (set, _finalized_qc, _finalization_authority) = finalize_height_one(&mut core);
    let first = qc(&set, 7, 1, BlockId::new([0xE1; 32]));
    let second = qc(&set, 7, 1, BlockId::new([0xE2; 32]));
    let first_effects = core
        .step(Input::QuorumCertificate(first), &RootSignatures)
        .expect("first historical QC is observed and subsumed");
    let (first_barrier, _) = persistence_effect(&first_effects);
    core.step(
        Input::StorageAck {
            barrier: first_barrier,
        },
        &RootSignatures,
    )
    .expect("first historical QC observation is durable");
    let before_view = core.safety_state().current_view();

    let effects = core
        .step(
            Input::TimeoutCertificate(timeout_certificate(&set, 10, second)),
            &RootSignatures,
        )
        .expect("the TC reference conflict halts before TC view advancement");
    let halted = effects
        .iter()
        .find_map(|effect| match effect {
            Effect::PersistSafetyState(request) => Some(request.state()),
            _ => None,
        })
        .expect("TC reference conflict is durable");
    assert_eq!(halted.current_view(), before_view);
    assert!(matches!(
        halted.safety_halt(),
        Some(SafetyHalt::ConflictingQuorumCertificates { .. })
    ));
}

#[test]
fn same_height_pending_qc_is_atomically_cleared_when_tc_finalizes_that_height() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let first = proposal(&set, genesis_qc(&set), 1, b"same-height queue one");
    let first_qc = qc(&set, 1, 1, first.block().id());
    insert_valid_and_vote(&mut core, first);
    accept_qc(&mut core, first_qc.clone());

    let second = proposal(&set, first_qc.clone(), 2, b"same-height queue two");
    let second_qc = qc(&set, 2, 2, second.block().id());
    insert_valid_and_vote(&mut core, second);
    accept_qc(&mut core, second_qc.clone());

    let third = proposal(&set, second_qc, 3, b"same-height queue three");
    let third_qc = qc(&set, 3, 3, third.block().id());
    insert_valid_and_vote(&mut core, third);

    let stale = qc(&set, 7, 1, BlockId::new([0xD1; 32]));
    let effects = core
        .step(Input::QuorumCertificate(stale.clone()), &RootSignatures)
        .expect("pre-finality competing QC becomes an exact durable target");
    let (barrier, durable) = persistence_effect(&effects);
    assert_eq!(
        durable
            .pending_standalone_qc_sync()
            .expect("same-height target is pending before finality")
            .active(),
        &stale
    );
    core.step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("same-height target is acknowledged before TC arrival");

    let effects = core
        .step(
            Input::TimeoutCertificate(timeout_certificate(&set, 8, third_qc.clone())),
            &RootSignatures,
        )
        .expect("ready TC finality subsumes the same-height pending branch");
    let (_barrier, completed) = persistence_effect(&effects);
    assert_eq!(completed.finalized().block_id(), first_qc.block_id());
    assert_eq!(completed.finalized().height(), Height::new(1));
    assert_eq!(completed.high_qc().id(), third_qc.id());
    assert!(completed.pending_standalone_qc_sync().is_none());
    assert!(completed.pending_tc_high_qc_sync().is_none());
    assert!(completed.pending_finalize().is_some());
}

#[test]
fn standalone_qc_backlog_survives_crash_and_advances_without_preemption() {
    let (config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let first_proposal = proposal(&set, genesis_qc(&set), 1, b"standalone first");
    let first_qc = qc(&set, 1, 1, first_proposal.block().id());
    let second_proposal = proposal(&set, first_qc.clone(), 2, b"standalone second");
    let second_qc = qc(&set, 2, 2, second_proposal.block().id());

    let effects = core
        .step(Input::QuorumCertificate(first_qc.clone()), &RootSignatures)
        .expect("QC-before-block creates the active durable target");
    let (barrier, first_durable) = persistence_effect(&effects);
    let first_pending = first_durable
        .pending_standalone_qc_sync()
        .expect("first standalone target is durable");
    assert_eq!(first_pending.active().id(), first_qc.id());
    assert!(first_pending.backlog().is_empty());
    assert!(matches!(
        core.step(Input::StorageAck { barrier }, &RootSignatures)
            .expect("first target acknowledged")
            .as_slice(),
        [Effect::RequestStandaloneQcSync { certificate_id, .. }]
            if *certificate_id == first_qc.id()
    ));

    let effects = core
        .step(Input::QuorumCertificate(second_qc.clone()), &RootSignatures)
        .expect("a later QC is queued without replacing the active target");
    let (_barrier, durable_backlog) = persistence_effect(&effects);
    let pending = durable_backlog
        .pending_standalone_qc_sync()
        .expect("active target and backlog are in one durable image");
    assert_eq!(pending.active().id(), first_qc.id());
    assert_eq!(
        pending
            .backlog()
            .iter()
            .map(QuorumCertificate::id)
            .collect::<Vec<_>>(),
        vec![second_qc.id()]
    );
    assert_safety_state_record_roundtrip_and_validate(&config, &durable_backlog);

    // The storage write completed, but the process crashed before observing
    // its acknowledgement. Recovery must reissue the exact immutable active
    // QC rather than preempting it with the stronger backlog entry.
    let mut recovered =
        Core::recover(config, durable_backlog, &RootSignatures).expect("durable backlog recovers");
    let effects = recovered
        .step(Input::Resume, &RootSignatures)
        .expect("recovery resumes the exact active target");
    assert!(matches!(
        effects.as_slice(),
        [Effect::ArmViewTimer { .. }, Effect::RequestStandaloneQcSync {
            certificate_id,
            ..
        }] if *certificate_id == first_qc.id()
    ));

    let effects = recovered
        .step(
            Input::SyncedProposal(Box::new(first_proposal)),
            &RootSignatures,
        )
        .expect("first target body and ancestry arrive");
    let effects = release_persisted_effects(&mut recovered, effects);
    let validation = synced_validation_effect(&effects);
    let result = valid_result_for_effect(&recovered, &effects, validation);
    let effects = recovered
        .step(
            Input::SyncedPayloadValidated {
                id: validation,
                result,
            },
            &RootSignatures,
        )
        .expect("first target validates");
    let (barrier, rotated) = persistence_effect(&effects);
    assert_eq!(rotated.high_qc().id(), first_qc.id());
    assert_eq!(
        rotated
            .pending_standalone_qc_sync()
            .expect("backlog head becomes active")
            .active()
            .id(),
        second_qc.id()
    );
    let effects = recovered
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("active rotation is durable");
    assert!(effects.iter().any(|effect| matches!(
        effect,
        Effect::RequestStandaloneQcSync { certificate_id, .. }
            if *certificate_id == second_qc.id()
    )));

    let effects = recovered
        .step(
            Input::SyncedProposal(Box::new(second_proposal)),
            &RootSignatures,
        )
        .expect("second target body and ancestry arrive");
    let effects = release_persisted_effects(&mut recovered, effects);
    let validation = synced_validation_effect(&effects);
    let result = valid_result_for_effect(&recovered, &effects, validation);
    let effects = recovered
        .step(
            Input::SyncedPayloadValidated {
                id: validation,
                result,
            },
            &RootSignatures,
        )
        .expect("second target validates");
    let (barrier, completed) = persistence_effect(&effects);
    assert_eq!(completed.high_qc().id(), second_qc.id());
    assert!(completed.pending_standalone_qc_sync().is_none());
    recovered
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("completed standalone obligation is durable");
    assert!(recovered.safety_state().pending_sign().is_none());
}

#[test]
fn recovery_rejects_a_noncanonical_standalone_qc_backlog() {
    let (config, core) = configured_core();
    let set = core.config().validator_set().clone();
    let state = core.safety_state();
    let active = qc(&set, 1, 1, BlockId::new([0xB1; 32]));
    let lower = qc(&set, 2, 2, BlockId::new([0xB2; 32]));
    let higher = qc(&set, 3, 3, BlockId::new([0xB3; 32]));
    let decoded = SafetyState::from_persisted_parts(
        state.schema_version(),
        state.chain_id(),
        state.protocol_version(),
        state.epoch(),
        state.validator_set_id(),
        state.genesis_block_id(),
        state.current_view(),
        state.last_voted_view(),
        state.last_timeout_view(),
        state.high_qc().clone(),
        state.locked_qc().clone(),
        state.finalized(),
        1,
        Vec::new(),
        vec![],
        vec![],
        None,
        Some(PendingStandaloneQcSync::from_persisted_parts(
            active,
            vec![higher, lower],
        )),
        None,
        None,
        None,
        None,
    );
    assert!(matches!(
        Core::recover(config, decoded, &RootSignatures),
        Err(CoreError::InvalidRecovery(
            "standalone QC sync backlog is not canonically sorted"
        ))
    ));
}

#[test]
fn proposal_carried_qc_persists_before_pre_header_sync_and_recovers_exactly() {
    let (config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let parent = proposal(&set, genesis_qc(&set), 1, b"carrier parent absent");
    let parent_qc = qc(&set, 1, 1, parent.block().id());
    let child = proposal(&set, parent_qc.clone(), 2, b"carrier child first");

    let effects = core
        .step(Input::Proposal(Box::new(child)), &RootSignatures)
        .expect("authenticated carrier creates an exact missing-parent obligation");
    let (barrier, durable) = persistence_effect(&effects);
    let pending = durable
        .pending_standalone_qc_sync()
        .expect("carrier QC is durable before any data request");
    assert_eq!(pending.active(), &parent_qc);
    assert!(pending.backlog().is_empty());
    assert_eq!(core.pending_validation_count(), 0);
    assert_ne!(durable.high_qc().id(), parent_qc.id());

    assert!(matches!(
        core.step(Input::StorageAck { barrier }, &RootSignatures)
            .expect("carrier obligation is acknowledged before release")
            .as_slice(),
        [Effect::RequestStandaloneQcSync {
            certificate_id,
            target,
            ..
        }] if *certificate_id == parent_qc.id()
            && target.qc_digest() == parent_qc.id()
            && target.block_id() == parent_qc.block_id()
    ));

    // The same durable image is sufficient if the process instead crashes at
    // the persistence boundary before observing that acknowledgement.
    let mut recovered =
        Core::recover(config, durable, &RootSignatures).expect("carrier obligation recovers");
    assert!(matches!(
        recovered
            .step(Input::Resume, &RootSignatures)
            .expect("recovery reissues the exact carried QC")
            .as_slice(),
        [Effect::ArmViewTimer { .. }, Effect::RequestStandaloneQcSync {
            certificate_id,
            target,
            ..
        }] if *certificate_id == parent_qc.id() && target.qc_digest() == parent_qc.id()
    ));
}

#[test]
fn missing_parent_carrier_requires_a_valid_proposer_signature() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let parent = proposal(&set, genesis_qc(&set), 1, b"unavailable signed parent");
    let parent_qc = qc(&set, 1, 1, parent.block().id());
    let proposed = block(
        &set,
        2,
        2,
        parent.block().id(),
        b"bad carrier signature",
        leader_for(&set, View::new(2)),
    );
    let justify = QcReferenceV0::ordinary(parent_qc);
    let witness = ProposalWitnessV0::new(
        proposed.header(),
        justify,
        None,
        None,
        SignatureBytes::from_array([0xEE; SIGNATURE_BYTES]),
        &set,
        None,
        &consensus_parameters(),
        parent.block().header().timestamp_ms(),
    )
    .expect("invalid cryptographic bytes still have a valid bounded shape");
    let carrier = SignedProposalV0::new(
        proposed,
        witness,
        &set,
        None,
        &consensus_parameters(),
        parent.block().header().timestamp_ms(),
    )
    .expect("proposal construction is structural, not signature verification");
    let before = core.clone();

    assert!(matches!(
        core.step(Input::Proposal(Box::new(carrier)), &RootSignatures),
        Err(CoreError::Protocol(ValidationError::InvalidSignature(_)))
    ));
    assert_eq!(core, before);
}

#[test]
fn proposal_carried_qc_persists_when_the_parent_header_has_no_valid_body_context() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let parent = proposal(&set, genesis_qc(&set), 1, b"known header unknown body");
    let parent_qc = qc(&set, 1, 1, parent.block().id());
    let child = proposal(&set, parent_qc.clone(), 2, b"dependent carrier");

    let effects = core
        .step(Input::Proposal(Box::new(parent)), &RootSignatures)
        .expect("parent header enters validation");
    let effects = release_persisted_effects(&mut core, effects);
    let parent_validation = validation_effect(&effects);

    let effects = core
        .step(Input::Proposal(Box::new(child)), &RootSignatures)
        .expect("known header without Valid context becomes durable QC catch-up");
    let (barrier, durable) = persistence_effect(&effects);
    assert_eq!(
        durable
            .pending_standalone_qc_sync()
            .expect("header-known dependency is retained")
            .active(),
        &parent_qc
    );
    assert_eq!(core.pending_validation_count(), 1);
    assert_eq!(parent_validation.block_id(), parent_qc.block_id());
    assert!(matches!(
        core.step(Input::StorageAck { barrier }, &RootSignatures)
            .expect("header-known request follows persistence")
            .as_slice(),
        [Effect::RequestStandaloneQcSync { certificate_id, .. }]
            if *certificate_id == parent_qc.id()
    ));
}

#[test]
fn carrier_and_direct_qc_orders_preserve_the_first_exact_active_and_canonical_backlog() {
    let (_config, mut carrier_first) = configured_core();
    let set = carrier_first.config().validator_set().clone();
    let parent = proposal(&set, genesis_qc(&set), 1, b"order parent");
    let first = qc_with_authors(&set, 1, 1, parent.block().id(), &[1, 2, 3]);
    let alternate = qc_with_authors(&set, 1, 1, parent.block().id(), &[2, 3, 4]);
    assert_ne!(first.id(), alternate.id());
    let child = proposal(&set, first.clone(), 2, b"carrier order child");

    let effects = carrier_first
        .step(Input::Proposal(Box::new(child.clone())), &RootSignatures)
        .expect("carrier wins the first durable target");
    let (barrier, _) = persistence_effect(&effects);
    carrier_first
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("carrier target is durable");
    assert!(matches!(
        carrier_first
            .step(
                Input::QuorumCertificate(alternate.clone()),
                &RootSignatures,
            )
            .expect("alternate direct encoding is coordinate-idempotent")
            .as_slice(),
        [Effect::RequestStandaloneQcSync { certificate_id, .. }]
            if *certificate_id == first.id()
    ));
    assert_eq!(
        carrier_first
            .safety_state()
            .pending_standalone_qc_sync()
            .expect("active remains immutable")
            .active(),
        &first
    );
    let conflict = qc(&set, 1, 1, BlockId::new([0xCF; 32]));
    let effects = carrier_first
        .step(Input::QuorumCertificate(conflict), &RootSignatures)
        .expect("a direct conflict with the carried durable QC fails stopped");
    let halted = effects
        .iter()
        .find_map(|effect| match effect {
            Effect::PersistSafetyState(request) => Some(request.state()),
            _ => None,
        })
        .expect("the conflicting arrival persists its halt");
    assert!(matches!(
        halted.safety_halt(),
        Some(SafetyHalt::ConflictingQuorumCertificates { .. })
    ));

    let (_config, mut direct_first) = configured_core();
    let effects = direct_first
        .step(Input::QuorumCertificate(first.clone()), &RootSignatures)
        .expect("direct QC wins the first durable target");
    let (barrier, _) = persistence_effect(&effects);
    direct_first
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("direct target is durable");
    assert!(matches!(
        direct_first
            .step(Input::Proposal(Box::new(child)), &RootSignatures)
            .expect("the same carried QC is idempotent behind its direct arrival")
            .as_slice(),
        [Effect::RequestStandaloneQcSync { certificate_id, .. }]
            if *certificate_id == first.id()
    ));

    let second_parent = proposal(&set, first.clone(), 2, b"backlog parent");
    let second = qc(&set, 2, 2, second_parent.block().id());
    let backlog_carrier = proposal(&set, second.clone(), 3, b"backlog carrier");
    let effects = direct_first
        .step(Input::Proposal(Box::new(backlog_carrier)), &RootSignatures)
        .expect("a later carried QC enters the canonical backlog");
    let (_barrier, durable) = persistence_effect(&effects);
    let pending = durable
        .pending_standalone_qc_sync()
        .expect("active and carried backlog are durable together");
    assert_eq!(pending.active(), &first);
    assert_eq!(pending.backlog(), &[second]);
}

#[test]
fn proposal_carrier_preserves_an_existing_tc_sync_priority() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let parent = proposal(&set, genesis_qc(&set), 1, b"TC-priority carrier parent");
    let parent_qc = qc(&set, 1, 1, parent.block().id());
    let tc = timeout_certificate(&set, 2, parent_qc.clone());
    let child = timeout_proposal(&set, tc.clone(), b"TC-priority carrier child");

    let effects = core
        .step(Input::TimeoutCertificate(tc.clone()), &RootSignatures)
        .expect("missing TC target becomes durable");
    let (barrier, _) = persistence_effect(&effects);
    core.step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("TC target is durable before its request");

    assert!(matches!(
        core.step(Input::Proposal(Box::new(child)), &RootSignatures)
            .expect("carrier of the same QC continues the higher-priority TC")
            .as_slice(),
        [Effect::RequestTcHighQcSync {
            certificate_id,
            target,
            ..
        }] if *certificate_id == tc.id() && target.qc_digest() == parent_qc.id()
    ));
    assert!(core.safety_state().pending_standalone_qc_sync().is_none());
    assert_eq!(
        core.safety_state()
            .pending_tc_high_qc_sync()
            .expect("TC remains the exact durable obligation")
            .certificate_id(),
        tc.id()
    );
}

#[test]
fn proposal_carried_multi_ref_tc_persists_complete_crash_recoverable_sync() {
    let (config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let lower_parent = proposal(&set, genesis_qc(&set), 1, b"carrier TC lower parent");
    let lower_qc = qc(&set, 1, 1, lower_parent.block().id());
    let selected_parent = proposal(&set, lower_qc.clone(), 2, b"carrier TC selected parent");
    let selected_qc = qc(&set, 2, 2, selected_parent.block().id());
    let tc = timeout_certificate_with_two_qcs(&set, 4, lower_qc.clone(), selected_qc.clone());
    let carrier = timeout_proposal(&set, tc.clone(), b"complete TC carrier first");

    let effects = core
        .step(Input::Proposal(Box::new(carrier)), &RootSignatures)
        .expect("first carrier durably retains its complete missing TC");
    let (barrier, durable) = persistence_effect(&effects);
    let pending = durable
        .pending_tc_high_qc_sync()
        .expect("the full multi-reference TC is durable");
    assert_eq!(pending.timeout_certificate(), &tc);
    assert_eq!(pending.selected_high_qc().id(), selected_qc.id());
    assert_eq!(durable.current_view(), View::new(5));
    assert!(durable.pending_standalone_qc_sync().is_none());
    assert_safety_state_record_roundtrip_and_validate(&config, &durable);
    assert!(matches!(
        core.step(Input::StorageAck { barrier }, &RootSignatures)
            .expect("complete TC persists before requesting its first dependency")
            .as_slice(),
        [Effect::ArmViewTimer { view, .. }, Effect::RequestTcHighQcSync {
            certificate_id,
            target,
            ..
        }] if *view == View::new(5)
            && *certificate_id == tc.id()
            && target.qc_digest() == lower_qc.id()
    ));

    let mut recovered =
        Core::recover(config, durable, &RootSignatures).expect("complete carried TC recovers");
    assert!(matches!(
        recovered
            .step(Input::Resume, &RootSignatures)
            .expect("recovery reissues the same complete TC and lower target")
            .as_slice(),
        [Effect::ArmViewTimer { view, .. }, Effect::RequestTcHighQcSync {
            certificate_id,
            target,
            ..
        }] if *view == View::new(5)
            && *certificate_id == tc.id()
            && target.qc_digest() == lower_qc.id()
    ));
}

#[test]
fn all_ready_multi_ref_tc_carrier_advances_view_and_admits_its_child_atomically() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let first = proposal(&set, genesis_qc(&set), 1, b"ready carrier first");
    let first_qc = qc(&set, 1, 1, first.block().id());
    insert_valid_and_vote(&mut core, first);
    accept_qc(&mut core, first_qc.clone());

    let second = proposal(&set, first_qc.clone(), 2, b"ready carrier second");
    let second_qc = qc(&set, 2, 2, second.block().id());
    insert_valid_and_vote(&mut core, second);
    accept_qc(&mut core, second_qc.clone());

    let certificate = timeout_certificate_with_two_qcs(&set, 4, first_qc, second_qc.clone());
    let child = timeout_proposal(&set, certificate, b"all-ready carried TC child");
    let child_id = child.block().id();
    let effects = core
        .step(Input::Proposal(Box::new(child)), &RootSignatures)
        .expect("one atomic transition processes the TC and admits its child");
    let (barrier, durable) = persistence_effect(&effects);
    assert_eq!(durable.current_view(), View::new(5));
    assert_eq!(durable.high_qc().id(), second_qc.id());
    assert!(durable.pending_tc_high_qc_sync().is_none());
    assert!(durable.pending_standalone_qc_sync().is_none());

    let effects = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("view progress and child validation release together");
    assert!(matches!(
        effects.as_slice(),
        [
            Effect::ArmViewTimer { view, .. },
            Effect::ValidatePayload(request)
        ] if *view == View::new(5) && request.id().block_id() == child_id
    ));
    let validation = validation_effect(&effects);
    let result = valid_result_for_effect(&core, &effects, validation);
    let effects = core
        .step(
            Input::PayloadValidated {
                id: validation,
                result,
            },
            &RootSignatures,
        )
        .expect("the TC-authorized child becomes vote-eligible");
    let (vote_barrier, vote_state) = persistence_effect(&effects);
    assert!(matches!(
        vote_state.pending_sign(),
        Some(SignIntent::Vote { block_id, .. }) if *block_id == child_id
    ));
    assert!(matches!(
        core.step(
            Input::StorageAck {
                barrier: vote_barrier,
            },
            &RootSignatures,
        )
        .expect("the child vote intent is durable")
        .as_slice(),
        [Effect::RequestSignature { .. }]
    ));
}

#[test]
fn invalid_lower_reference_in_proposal_carried_tc_halts_with_full_tc() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let lower_parent = proposal(&set, genesis_qc(&set), 1, b"invalid lower TC reference");
    let lower_id = lower_parent.block().id();
    let lower_qc = qc(&set, 1, 1, lower_id);

    let effects = core
        .step(Input::Proposal(Box::new(lower_parent)), &RootSignatures)
        .expect("lower parent enters validation");
    let effects = release_persisted_effects(&mut core, effects);
    let validation = validation_effect(&effects);
    let effects = core
        .step(
            Input::PayloadValidated {
                id: validation,
                result: PayloadValidationResult::DeterministicallyInvalid,
            },
            &RootSignatures,
        )
        .expect("lower invalid result becomes durable");
    assert!(release_persisted_effects(&mut core, effects).is_empty());

    let selected_parent = proposal(&set, lower_qc.clone(), 2, b"selected TC reference");
    let selected_qc = qc(&set, 2, 2, selected_parent.block().id());
    let tc = timeout_certificate_with_two_qcs(&set, 4, lower_qc, selected_qc);
    let carrier = timeout_proposal(&set, tc.clone(), b"invalid lower ref carrier");
    let effects = core
        .step(Input::Proposal(Box::new(carrier)), &RootSignatures)
        .expect("the carried TC detects its invalid lower reference");
    let (_barrier, halted) = persistence_effect(&effects);
    assert_eq!(halted.current_view(), View::new(5));
    match halted
        .safety_halt()
        .expect("lower-reference halt is durable")
    {
        SafetyHalt::DeterministicallyInvalidPayload {
            block_id,
            reference: InvalidPayloadReference::TimeoutCertificate(certificate),
        } => {
            assert_eq!(*block_id, lower_id);
            assert_eq!(certificate.as_ref(), &tc);
            assert_eq!(certificate.referenced_qcs().len(), 2);
        }
        other => panic!("unexpected lower-reference TC halt: {other:?}"),
    }
}

#[test]
fn pending_sign_allows_authenticated_carrier_and_direct_tc_conflicts_to_halt() {
    let (mut carrier_core, set, durable_qc) = awaiting_timeout_signature_with_missing_qc();
    let conflicting_parent = proposal(&set, genesis_qc(&set), 1, b"carrier sign conflict");
    let conflicting_qc = qc(&set, 1, 1, conflicting_parent.block().id());
    assert_ne!(conflicting_qc.block_id(), durable_qc.block_id());
    let carrier = proposal(
        &set,
        conflicting_qc,
        2,
        b"carrier bypasses sign gate safely",
    );

    let effects = carrier_core
        .step(Input::Proposal(Box::new(carrier)), &RootSignatures)
        .expect("fully authenticated carrier conflict crosses the pending-sign gate");
    let carrier_halt = effects
        .iter()
        .find_map(|effect| match effect {
            Effect::PersistSafetyState(request) => Some(request.state()),
            _ => None,
        })
        .expect("carrier conflict persists its halt");
    assert!(carrier_halt.pending_sign().is_none());
    assert!(carrier_halt.pending_standalone_qc_sync().is_none());
    assert!(matches!(
        carrier_halt.safety_halt(),
        Some(SafetyHalt::ConflictingQuorumCertificates { .. })
    ));

    let (mut direct_tc_core, set, durable_qc) = awaiting_timeout_signature_with_missing_qc();
    let conflicting_parent = proposal(&set, genesis_qc(&set), 1, b"direct TC sign conflict");
    let conflicting_qc = qc(&set, 1, 1, conflicting_parent.block().id());
    assert_ne!(conflicting_qc.block_id(), durable_qc.block_id());
    let tc = timeout_certificate(&set, 2, conflicting_qc);
    let effects = direct_tc_core
        .step(Input::TimeoutCertificate(tc), &RootSignatures)
        .expect("fully authenticated direct TC conflict crosses the pending-sign gate");
    let direct_tc_halt = effects
        .iter()
        .find_map(|effect| match effect {
            Effect::PersistSafetyState(request) => Some(request.state()),
            _ => None,
        })
        .expect("direct TC conflict persists its halt");
    assert!(direct_tc_halt.pending_sign().is_none());
    assert!(matches!(
        direct_tc_halt.safety_halt(),
        Some(SafetyHalt::ConflictingQuorumCertificates { .. })
    ));
}

#[test]
fn pending_finalize_allows_authenticated_carrier_conflict_to_halt() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let first = proposal(&set, genesis_qc(&set), 1, b"finalize conflict one");
    let first_qc = qc(&set, 1, 1, first.block().id());
    insert_valid_and_vote(&mut core, first);
    accept_qc(&mut core, first_qc.clone());

    let second = proposal(&set, first_qc, 2, b"finalize conflict two");
    let second_qc = qc(&set, 2, 2, second.block().id());
    insert_valid_and_vote(&mut core, second);
    accept_qc(&mut core, second_qc.clone());

    let third = proposal(&set, second_qc, 3, b"finalize conflict three");
    let third_qc = qc(&set, 3, 3, third.block().id());
    insert_valid_and_vote(&mut core, third);
    let effects = core
        .step(Input::QuorumCertificate(third_qc.clone()), &RootSignatures)
        .expect("third QC creates a durable finalization outbox");
    let (barrier, durable) = persistence_effect(&effects);
    assert!(durable.pending_finalize().is_some());
    let expected_pending = durable.pending_finalize();
    let expected_queue = durable.finalization_queue().to_vec();
    let effects = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("finalization is released after its durable boundary");
    assert!(effects
        .iter()
        .any(|effect| matches!(effect, Effect::Finalize(_))));

    let conflicting_qc = qc(&set, 3, 3, BlockId::new([0xF3; 32]));
    assert_ne!(conflicting_qc.block_id(), third_qc.block_id());
    let carrier = proposal(&set, conflicting_qc, 4, b"carrier crosses pending finalize");
    let effects = core
        .step(Input::Proposal(Box::new(carrier)), &RootSignatures)
        .expect("authenticated carrier conflict crosses the pending-finalize gate");
    let halted = effects
        .iter()
        .find_map(|effect| match effect {
            Effect::PersistSafetyState(request) => Some(request.state()),
            _ => None,
        })
        .expect("pending-finalize conflict persists its halt");
    assert_eq!(halted.pending_finalize(), expected_pending);
    assert_eq!(halted.finalization_queue(), expected_queue);
    assert!(matches!(
        halted.safety_halt(),
        Some(SafetyHalt::ConflictingQuorumCertificates { .. })
    ));
}

#[test]
fn recovered_replay_carrier_conflict_halts_before_stale_height_rejection() {
    let (config, mut original) = configured_core();
    let set = original.config().validator_set().clone();
    let durable_parent = proposal(&set, genesis_qc(&set), 1, b"durable replay parent");
    let durable_qc = qc(&set, 1, 1, durable_parent.block().id());
    insert_valid_and_vote(&mut original, durable_parent);
    accept_qc(&mut original, durable_qc.clone());

    let mut recovered = Core::recover(config, original.safety_state().clone(), &RootSignatures)
        .expect("durable high QC enters safety replay");
    let conflicting_parent = proposal(&set, genesis_qc(&set), 1, b"conflicting replay parent");
    let conflicting_qc = qc(&set, 1, 1, conflicting_parent.block().id());
    let carrier = proposal(&set, conflicting_qc, 2, b"replay conflict carrier");

    let effects = recovered
        .step(Input::Proposal(Box::new(carrier)), &RootSignatures)
        .expect("ordinary carrier conflict crosses replay after staged preauthentication");
    let halted = effects
        .iter()
        .find_map(|effect| match effect {
            Effect::PersistSafetyState(request) => Some(request.state()),
            _ => None,
        })
        .expect("replay conflict persists its halt");
    let (first, second) = halted
        .safety_halt()
        .and_then(SafetyHalt::conflicting_qcs)
        .expect("replay carrier retains both conflicting QCs");
    assert_eq!(first.view(), durable_qc.view());
    assert_eq!(second.view(), durable_qc.view());
    assert_ne!(first.block_id(), second.block_id());
}

#[test]
fn ready_proposal_justify_runs_complete_qc_processing_before_child_validation() {
    let (_config, mut core) = configured_core();
    let finalization_authority = finalization_apply_authority_for_test(&core);
    let set = core.config().validator_set().clone();
    let p1 = proposal(&set, genesis_qc(&set), 1, b"carrier chain one");
    let finalized_id = p1.block().id();
    let q1 = qc(&set, 1, 1, p1.block().id());
    insert_valid_and_vote(&mut core, p1);

    let p2 = proposal(&set, q1, 2, b"carrier chain two");
    let q2 = qc(&set, 2, 2, p2.block().id());
    insert_valid_and_vote(&mut core, p2);

    let p3 = proposal(&set, q2, 3, b"carrier chain three");
    let q3 = qc(&set, 3, 3, p3.block().id());
    insert_valid_and_vote(&mut core, p3);

    let p4 = proposal(&set, q3, 4, b"carrier triggers finality");
    let effects = core
        .step(Input::Proposal(Box::new(p4)), &RootSignatures)
        .expect("ready carried justify performs the complete QC transition");
    let (barrier, durable) = persistence_effect(&effects);
    let proof = durable
        .last_finalization_proof()
        .expect("carrier QC discovers three-chain finality");
    assert_eq!(proof.finalized_block().header().id(), finalized_id);
    assert_eq!(durable.finalized().block_id(), finalized_id);
    assert_eq!(durable.finalized().height(), Height::new(1));
    assert!(durable.pending_finalize().is_some());
    assert!(durable.pending_sign().is_none());

    let effects = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("finality and child validation release after one durable boundary");
    let finalize_index = effects
        .iter()
        .position(|effect| matches!(effect, Effect::Finalize(_)))
        .expect("carrier finality is released");
    let validation_index = effects
        .iter()
        .position(|effect| matches!(effect, Effect::ValidatePayload(_)))
        .expect("dependent child validation is released");
    assert!(finalize_index < validation_index);
    let validation = validation_effect(&effects);
    let result = valid_result_for_effect(&core, &effects, validation);
    let effects = core
        .step(
            Input::PayloadValidated {
                id: validation,
                result,
            },
            &RootSignatures,
        )
        .expect("an eager child callback remains gated by durable finality");
    let (_barrier, gated) = persistence_effect(&effects);
    assert!(gated.pending_finalize().is_some());
    assert!(gated.pending_sign().is_none());

    let (validation_barrier, _) = persistence_effect(&effects);
    assert!(core
        .step(
            Input::StorageAck {
                barrier: validation_barrier,
            },
            &RootSignatures,
        )
        .expect("the terminal Valid fact is durable")
        .is_empty());
    let effects = apply_finalization_for_test(&mut core, &finalization_authority)
        .expect("application finalization is acknowledged");
    let (vote_barrier, vote_state) = persistence_effect(&effects);
    assert!(vote_state.pending_finalize().is_none());
    assert!(matches!(
        vote_state.pending_sign(),
        Some(SignIntent::Vote { block_id, .. }) if *block_id == validation.block_id()
    ));

    // A crash after the atomic finalization-clear/vote-intent write must not
    // rebroadcast from the compact signing root alone. The durable state does
    // not retain the complete signed proposal body/runtime authorization, so
    // generic recovery remains closed until the dedicated authenticated
    // body-replay protocol exists.
    assert_eq!(
        Core::recover(core.config().clone(), vote_state.clone(), &RootSignatures),
        Err(CoreError::InvalidRecovery(
            "a pending proposal vote requires dedicated authenticated body replay before recovery",
        ))
    );

    let request = core
        .step(
            Input::StorageAck {
                barrier: vote_barrier,
            },
            &RootSignatures,
        )
        .expect("the autonomous vote intent becomes durable");
    let (sign_id, signing_root) = signature_request(&request);
    assert!(matches!(
        core.step(
            Input::SignatureReady {
                id: sign_id,
                signature: signature(signing_root),
            },
            &RootSignatures,
        )
        .expect("the autonomous vote signature is accepted")
        .as_slice(),
        [Effect::Broadcast(OutboundMessage::Vote(vote))]
            if vote.block_id() == validation.block_id()
    ));
}

#[test]
fn invalid_callback_during_finalization_never_creates_a_vote_intent() {
    let (_config, mut core, validation, _valid_result) =
        finalization_gated_validation(b"invalid while finalizing");
    let finalization_authority = finalization_apply_authority_for_test(&core);
    let effects = core
        .step(
            Input::PayloadValidated {
                id: validation,
                result: PayloadValidationResult::DeterministicallyInvalid,
            },
            &RootSignatures,
        )
        .expect("the terminal invalid result is retained during finalization");
    let (barrier, invalid) = persistence_effect(&effects);
    assert!(invalid.pending_finalize().is_some());
    assert!(invalid.pending_sign().is_none());
    assert_eq!(
        invalid.payload_terminal_result(validation.block_id()),
        Some(PayloadTerminalResult::DeterministicallyInvalid)
    );
    assert!(core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("the invalid fact is durable")
        .is_empty());

    let effects = apply_finalization_for_test(&mut core, &finalization_authority)
        .expect("finalization can clear without re-driving an invalid child");
    let (barrier, cleared) = persistence_effect(&effects);
    assert!(cleared.pending_finalize().is_none());
    assert!(cleared.pending_sign().is_none());
    assert!(core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("the finalization acknowledgement is durable")
        .is_empty());
}

#[test]
fn recovery_before_finalization_ack_does_not_reconstruct_a_vote_candidate() {
    let (config, mut original, validation, result) =
        finalization_gated_validation(b"valid before recovery");
    let effects = original
        .step(
            Input::PayloadValidated {
                id: validation,
                result,
            },
            &RootSignatures,
        )
        .expect("the eager Valid result is persisted behind finalization");
    let (barrier, gated) = persistence_effect(&effects);
    assert!(gated.pending_finalize().is_some());
    assert!(gated.pending_sign().is_none());
    assert!(gated.payload_validation_obligations().is_empty());
    let completion = gated
        .payload_validation_completions()
        .iter()
        .find(|completion| completion.id() == validation)
        .expect("the Valid callback atomically leaves one durable completion");
    assert_eq!(completion.route(), PayloadValidationRouteV0::Proposal);
    assert!(completion.result().matches_live(result));
    let live_commitments = result
        .commitments()
        .expect("the fixture returns one live Valid capability");
    let durable_commitments = completion
        .result()
        .commitments()
        .expect("the durable result retains only inert comparison data");
    assert_eq!(durable_commitments.block_id(), live_commitments.block_id());
    assert_eq!(
        durable_commitments.logical_block_size(),
        live_commitments.logical_block_size()
    );
    assert_eq!(
        durable_commitments.transaction_count(),
        live_commitments.transaction_count()
    );
    assert_eq!(
        durable_commitments.evidence_count(),
        live_commitments.evidence_count()
    );
    assert_eq!(
        DurableValidatedBlockCommitmentsV1::from_persisted_parts(
            durable_commitments.block_id(),
            durable_commitments.logical_block_size(),
            durable_commitments.transaction_count(),
            durable_commitments.evidence_count(),
        ),
        durable_commitments,
        "durable decoding reconstructs only the inert comparison snapshot"
    );
    assert_eq!(completion.first_recorded_revision(), gated.revision());
    let expected_completion = (*completion).clone();
    let expected_completions = gated.payload_validation_completions().to_vec();
    assert!(original
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("the terminal fact is durable before the crash")
        .is_empty());

    assert_eq!(
        Core::recover(config, gated.clone(), &RootSignatures),
        Err(CoreError::InvalidRecovery(
            "a current NativeValid completion requires its dedicated cross-store recovery session"
        ))
    );
    assert_eq!(gated.payload_validation_completions(), expected_completions);
    assert!(gated
        .payload_validation_completions()
        .contains(&expected_completion));
    assert!(gated
        .pending_finalize()
        .is_some(), "the exact finalization outbox remains durable behind the dedicated completion recovery fence");
}

#[test]
fn conflicting_terminal_callback_clears_the_finalization_vote_candidate() {
    let (config, mut core, validation, result) =
        finalization_gated_validation(b"conflicting while finalizing");
    let effects = core
        .step(
            Input::PayloadValidated {
                id: validation,
                result,
            },
            &RootSignatures,
        )
        .expect("the first terminal result is retained");
    let (barrier, _) = persistence_effect(&effects);
    assert!(core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("the first terminal result is durable")
        .is_empty());
    let expected_pending = core.safety_state().pending_finalize();
    let expected_queue = core.safety_state().finalization_queue().to_vec();

    let effects = core
        .step(
            Input::PayloadValidated {
                id: validation,
                result: PayloadValidationResult::DeterministicallyInvalid,
            },
            &RootSignatures,
        )
        .expect("a conflicting terminal callback safety-halts");
    let (barrier, halted) = persistence_effect(&effects);
    assert_eq!(halted.pending_finalize(), expected_pending);
    assert_eq!(halted.finalization_queue(), expected_queue);
    assert!(halted.pending_sign().is_none());
    assert!(matches!(
        halted.safety_halt(),
        Some(SafetyHalt::ConflictingPayloadValidation { .. })
    ));
    assert_safety_state_record_roundtrip_and_validate(&config, &halted);
    assert!(matches!(
        core.step(Input::StorageAck { barrier }, &RootSignatures)
            .expect("the halt is released only after persistence")
            .as_slice(),
        [Effect::SafetyHalted(halt)]
            if matches!(halt.as_ref(), SafetyHalt::ConflictingPayloadValidation { .. })
    ));

    let mut recovered =
        Core::recover(config, halted, &RootSignatures).expect("the durable halt recovers");
    assert!(matches!(
        recovered
            .step(Input::Resume, &RootSignatures)
            .expect("recovery remains halted without a signing outbox")
            .as_slice(),
        [Effect::SafetyHalted(halt)]
            if matches!(halt.as_ref(), SafetyHalt::ConflictingPayloadValidation { .. })
    ));
}

#[test]
fn stale_valid_callback_during_finalization_is_not_re_driven() {
    let (_config, mut core) = configured_core();
    let finalization_authority = finalization_apply_authority_for_test(&core);
    let set = core.config().validator_set().clone();
    let first = proposal(&set, genesis_qc(&set), 1, b"stale gated one");
    let first_qc = qc(&set, 1, 1, first.block().id());
    insert_valid_and_vote(&mut core, first);
    let second = proposal(&set, first_qc, 2, b"stale gated two");
    let second_qc = qc(&set, 2, 2, second.block().id());
    insert_valid_and_vote(&mut core, second);
    let third = proposal(&set, second_qc.clone(), 3, b"stale gated three");
    let third_qc = qc(&set, 3, 3, third.block().id());
    insert_valid_and_vote(&mut core, third);

    // Register a view-four fork without completing its payload. A later TC
    // carries q3, advances to view five, and creates the finalization outbox.
    let stale = timeout_proposal(
        &set,
        timeout_certificate(&set, 3, second_qc),
        b"stale view-four candidate",
    );
    let effects = core
        .step(Input::Proposal(Box::new(stale)), &RootSignatures)
        .expect("the view-four proposal enters validation");
    let effects = release_persisted_effects(&mut core, effects);
    let stale_validation = validation_effect(&effects);
    let stale_result = valid_result_for_effect(&core, &effects, stale_validation);
    assert_eq!(stale_validation.view(), View::new(4));

    let current = timeout_proposal(
        &set,
        timeout_certificate(&set, 4, third_qc),
        b"current view-five finality carrier",
    );
    let effects = core
        .step(Input::Proposal(Box::new(current)), &RootSignatures)
        .expect("the view-five carrier advances finality");
    let (barrier, finalized) = persistence_effect(&effects);
    assert_eq!(finalized.current_view(), View::new(5));
    assert!(finalized.pending_finalize().is_some());
    let effects = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("view five and finalization are durable");
    assert!(effects
        .iter()
        .any(|effect| matches!(effect, Effect::Finalize(_))));

    let effects = core
        .step(
            Input::PayloadValidated {
                id: stale_validation,
                result: stale_result,
            },
            &RootSignatures,
        )
        .expect("the registered stale callback may record its terminal fact");
    let (barrier, stale_fact) = persistence_effect(&effects);
    assert_eq!(stale_fact.current_view(), View::new(5));
    assert!(stale_fact.pending_sign().is_none());
    assert!(core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("the stale terminal fact is durable")
        .is_empty());

    let effects = apply_finalization_for_test(&mut core, &finalization_authority)
        .expect("finalization does not revive the stale proposal");
    let (barrier, cleared) = persistence_effect(&effects);
    assert!(cleared.pending_finalize().is_none());
    assert!(cleared.pending_sign().is_none());
    assert!(core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("the no-vote acknowledgement is durable")
        .is_empty());
}

#[test]
fn invalid_parent_then_ordinary_qc_carrier_halts_durably() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let parent = proposal(&set, genesis_qc(&set), 1, b"invalid carrier parent");
    let parent_id = parent.block().id();
    let parent_qc = qc(&set, 1, 1, parent_id);
    let child = proposal(&set, parent_qc.clone(), 2, b"ordinary invalid carrier");

    let effects = core
        .step(Input::Proposal(Box::new(parent)), &RootSignatures)
        .expect("parent enters validation");
    let effects = release_persisted_effects(&mut core, effects);
    let validation = validation_effect(&effects);
    let effects = core
        .step(
            Input::PayloadValidated {
                id: validation,
                result: PayloadValidationResult::DeterministicallyInvalid,
            },
            &RootSignatures,
        )
        .expect("uncertified invalid parent becomes durable");
    assert!(release_persisted_effects(&mut core, effects).is_empty());

    let effects = core
        .step(Input::Proposal(Box::new(child)), &RootSignatures)
        .expect("ordinary QC carrier detects the durable invalid parent");
    let (_barrier, halted) = persistence_effect(&effects);
    match halted.safety_halt().expect("carrier collision is durable") {
        SafetyHalt::DeterministicallyInvalidPayload {
            block_id,
            reference: InvalidPayloadReference::QuorumCertificate(certificate),
        } => {
            assert_eq!(*block_id, parent_id);
            assert_eq!(certificate.id(), parent_qc.id());
        }
        other => panic!("unexpected ordinary carrier halt: {other:?}"),
    }
    assert!(halted.pending_standalone_qc_sync().is_none());
}

#[test]
fn direct_qc_same_view_conflict_precedes_a_known_invalid_payload_halt() {
    let (config, mut core, _set, durable_qc, invalid_qc) =
        known_invalid_with_durable_same_view_qc();
    let before_view = core.safety_state().current_view();

    let effects = core
        .step(
            Input::QuorumCertificate(invalid_qc.clone()),
            &RootSignatures,
        )
        .expect("same-view QC conflict outranks the known invalid payload");
    let (barrier, halted) = conflicting_qc_halt_persistence(&effects, &durable_qc, &invalid_qc);
    assert_eq!(halted.current_view(), before_view);
    assert!(halted.pending_standalone_qc_sync().is_none());
    assert!(!effects
        .iter()
        .any(|effect| matches!(effect, Effect::SafetyHalted(_))));

    assert!(matches!(
        core.step(Input::StorageAck { barrier }, &RootSignatures)
            .expect("the full QC witness becomes durable before fail-stop release")
            .as_slice(),
        [Effect::SafetyHalted(_)]
    ));

    let mut recovered =
        Core::recover(config, halted, &RootSignatures).expect("full QC witness recovers");
    let resumed = recovered
        .step(Input::Resume, &RootSignatures)
        .expect("recovery reissues the durable fail-stop");
    assert!(matches!(resumed.as_slice(), [Effect::SafetyHalted(_)]));
    let recovered_halt = recovered
        .safety_state()
        .safety_halt()
        .and_then(SafetyHalt::conflicting_qcs)
        .expect("recovery retains both same-view QCs");
    let recovered_ids = [recovered_halt.0.id(), recovered_halt.1.id()];
    assert!(recovered_ids.contains(&durable_qc.id()));
    assert!(recovered_ids.contains(&invalid_qc.id()));
}

#[test]
fn direct_tc_same_view_conflict_precedes_invalid_view_progress() {
    let (_config, mut core, set, durable_qc, invalid_qc) =
        known_invalid_with_durable_same_view_qc();
    let before_view = core.safety_state().current_view();
    let certificate = timeout_certificate(&set, 2, invalid_qc.clone());

    let effects = core
        .step(Input::TimeoutCertificate(certificate), &RootSignatures)
        .expect("referenced same-view conflict outranks invalid-TC view progress");
    let (barrier, halted) = conflicting_qc_halt_persistence(&effects, &durable_qc, &invalid_qc);
    assert_eq!(halted.current_view(), before_view);
    assert!(halted.pending_tc_high_qc_sync().is_none());
    assert!(halted.pending_standalone_qc_sync().is_none());

    assert!(matches!(
        core.step(Input::StorageAck { barrier }, &RootSignatures)
            .expect("TC conflict is released only after its full witness is durable")
            .as_slice(),
        [Effect::SafetyHalted(_)]
    ));
}

#[test]
fn proposal_carried_tc_same_view_conflict_precedes_invalid_view_progress() {
    let (_config, mut core, set, durable_qc, invalid_qc) =
        known_invalid_with_durable_same_view_qc();
    let before_view = core.safety_state().current_view();
    let certificate = timeout_certificate(&set, 2, invalid_qc.clone());
    let carrier = timeout_proposal(
        &set,
        certificate,
        b"proposal-carried known-invalid same-view conflict",
    );

    let effects = core
        .step(Input::Proposal(Box::new(carrier)), &RootSignatures)
        .expect("carried same-view conflict outranks invalid-TC view progress");
    let (barrier, halted) = conflicting_qc_halt_persistence(&effects, &durable_qc, &invalid_qc);
    assert_eq!(halted.current_view(), before_view);
    assert!(halted.pending_tc_high_qc_sync().is_none());
    assert!(halted.pending_standalone_qc_sync().is_none());
    assert_eq!(core.pending_validation_count(), 0);

    assert!(matches!(
        core.step(Input::StorageAck { barrier }, &RootSignatures)
            .expect("carried-TC conflict is released only after persistence")
            .as_slice(),
        [Effect::SafetyHalted(_)]
    ));
}

#[test]
fn safety_anchor_replay_precedes_a_lower_standalone_qc_obligation() {
    let (config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let first_proposal = proposal(&set, genesis_qc(&set), 1, b"replay first");
    let first_qc = qc(&set, 1, 1, first_proposal.block().id());
    insert_valid_and_vote(&mut core, first_proposal.clone());
    accept_qc(&mut core, first_qc.clone());
    let second_proposal = proposal(&set, first_qc, 2, b"replay second");
    let second_qc = qc(&set, 2, 2, second_proposal.block().id());
    insert_valid_and_vote(&mut core, second_proposal.clone());
    accept_qc(&mut core, second_qc.clone());

    let standalone = qc(&set, 3, 1, BlockId::new([0xC3; 32]));
    let effects = core
        .step(
            Input::QuorumCertificate(standalone.clone()),
            &RootSignatures,
        )
        .expect("lower missing QC becomes a durable standalone obligation");
    let (_barrier, durable) = persistence_effect(&effects);
    let mut recovered =
        Core::recover(config, durable, &RootSignatures).expect("combined recovery state validates");

    assert!(matches!(
        recovered
            .step(Input::Resume, &RootSignatures)
            .expect("durable safety anchors replay first")
            .as_slice(),
        [Effect::RequestSafetyReplay { high_qc, .. }]
            if high_qc.qc_digest() == second_qc.id()
    ));
    replay_valid(&mut recovered, first_proposal);
    replay_valid(&mut recovered, second_proposal);
    let effects = recovered
        .step(Input::SafetyReplayComplete, &RootSignatures)
        .expect("full-height safety replay completes before standalone sync");
    assert!(matches!(
        effects.as_slice(),
        [Effect::RequestStandaloneQcSync { certificate_id, .. }]
            if *certificate_id == standalone.id()
    ));
    assert_eq!(recovered.safety_state().high_qc().id(), second_qc.id());
}

#[test]
fn tc_finality_discards_a_subsumed_standalone_qc_without_impossible_sync() {
    let (_config, mut core) = configured_core();
    let finalization_authority = finalization_apply_authority_for_test(&core);
    let set = core.config().validator_set().clone();
    let first = proposal(&set, genesis_qc(&set), 1, b"subsumption one");
    let q1 = qc(&set, 1, 1, first.block().id());
    insert_valid_and_vote(&mut core, first);
    accept_qc(&mut core, q1.clone());
    let second = proposal(&set, q1, 2, b"subsumption two");
    let q2 = qc(&set, 2, 2, second.block().id());
    let second_id = second.block().id();
    insert_valid_and_vote(&mut core, second);
    accept_qc(&mut core, q2.clone());
    let third = proposal(&set, q2, 3, b"subsumption three");
    let q3 = qc(&set, 3, 3, third.block().id());
    let third_id = third.block().id();
    insert_valid_and_vote(&mut core, third);
    let effects = core
        .step(Input::QuorumCertificate(q3.clone()), &RootSignatures)
        .expect("third QC creates the first finalization");
    let (barrier, durable) = persistence_effect(&effects);
    assert!(durable.pending_finalize().is_some());
    core.step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("first finalization is durable");
    let effects = apply_finalization_for_test(&mut core, &finalization_authority)
        .expect("application accepts the first finalized block");
    let (barrier, _) = persistence_effect(&effects);
    core.step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("first finalization acknowledgement is durable");

    let fourth = proposal(&set, q3, 4, b"subsumption four");
    let q4 = qc(&set, 4, 4, fourth.block().id());
    replay_valid(&mut core, fourth);
    let fifth = proposal(&set, q4.clone(), 5, b"subsumption five");
    let q5 = qc(&set, 5, 5, fifth.block().id());
    replay_valid(&mut core, fifth);

    // The missing height-two target is above the current height-one finality.
    // A single TC transaction then processes q4 and q5 in order, coalescing
    // finality through height three before pruning this now-subsumed target.
    let stale_missing = qc(&set, 10, 2, BlockId::new([0xD1; 32]));
    let effects = core
        .step(
            Input::QuorumCertificate(stale_missing.clone()),
            &RootSignatures,
        )
        .expect("missing low-height QC becomes durable before finality subsumes it");
    let (barrier, _) = persistence_effect(&effects);
    assert!(matches!(
        core.step(Input::StorageAck { barrier }, &RootSignatures)
            .expect("standalone request follows persistence")
            .as_slice(),
        [Effect::RequestStandaloneQcSync { certificate_id, .. }]
            if *certificate_id == stale_missing.id()
    ));

    let tc = timeout_certificate_with_two_qcs(&set, 12, q4, q5);
    let effects = core
        .step(Input::TimeoutCertificate(tc), &RootSignatures)
        .expect("ready TC advances finality past the missing low-height QC");
    let (barrier, durable) = persistence_effect(&effects);
    assert_eq!(durable.finalized().block_id(), third_id);
    assert_ne!(durable.finalized().block_id(), second_id);
    assert!(durable.pending_standalone_qc_sync().is_none());
    let effects = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("subsumption and finality are durable together");
    assert!(effects
        .iter()
        .any(|effect| matches!(effect, Effect::Finalize(_))));
    assert!(!effects
        .iter()
        .any(|effect| matches!(effect, Effect::RequestStandaloneQcSync { .. })));
}

#[test]
fn tc_completion_atomically_drains_a_ready_standalone_active_and_backlog() {
    let (_config, mut core) = configured_core();
    let finalization_authority = finalization_apply_authority_for_test(&core);
    let set = core.config().validator_set().clone();
    let first = proposal(&set, genesis_qc(&set), 1, b"overlap one");
    let q1 = qc(&set, 1, 1, first.block().id());
    let second = proposal(&set, q1.clone(), 2, b"overlap two");
    let q2 = qc(&set, 2, 2, second.block().id());
    let third = proposal(&set, q2.clone(), 3, b"overlap three");
    let q3 = qc(&set, 3, 3, third.block().id());

    let effects = core
        .step(Input::QuorumCertificate(q1.clone()), &RootSignatures)
        .expect("first missing QC becomes the immutable standalone target");
    let (barrier, _) = persistence_effect(&effects);
    core.step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("first standalone target is durable");
    let effects = core
        .step(Input::QuorumCertificate(q2.clone()), &RootSignatures)
        .expect("second missing QC is retained behind the active target");
    let (barrier, queued) = persistence_effect(&effects);
    let pending = queued
        .pending_standalone_qc_sync()
        .expect("active and backlog are durable together");
    assert_eq!(pending.active().id(), q1.id());
    assert_eq!(pending.backlog(), std::slice::from_ref(&q2));
    core.step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("standalone backlog is durable");

    let effects = core
        .step(
            Input::TimeoutCertificate(timeout_certificate(&set, 4, q3.clone())),
            &RootSignatures,
        )
        .expect("the missing TC target takes priority without replacing standalone work");
    let (barrier, pending_tc) = persistence_effect(&effects);
    assert!(pending_tc.pending_tc_high_qc_sync().is_some());
    assert_eq!(
        pending_tc
            .pending_standalone_qc_sync()
            .expect("standalone queue survives TC admission"),
        pending
    );
    let effects = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("TC obligation is durable");
    assert!(effects
        .iter()
        .any(|effect| matches!(effect, Effect::RequestTcHighQcSync { .. })));

    for proposal in [first, second] {
        let effects = core
            .step(Input::SyncedProposal(Box::new(proposal)), &RootSignatures)
            .expect("TC ancestry proposal is accepted");
        let effects = release_persisted_effects(&mut core, effects);
        let id = synced_validation_effect(&effects);
        let result = valid_result_for_effect(&core, &effects, id);
        let effects = core
            .step(
                Input::SyncedPayloadValidated { id, result },
                &RootSignatures,
            )
            .expect("ready standalone ancestry remains queued behind the TC");
        let effects = release_persisted_effects(&mut core, effects);
        assert!(effects
            .iter()
            .any(|effect| matches!(effect, Effect::RequestTcHighQcSync { .. })));
    }
    let still_queued = core
        .safety_state()
        .pending_standalone_qc_sync()
        .expect("TC priority preserves the complete standalone queue");
    assert_eq!(still_queued.active().id(), q1.id());
    assert_eq!(still_queued.backlog(), std::slice::from_ref(&q2));

    let effects = core
        .step(Input::SyncedProposal(Box::new(third)), &RootSignatures)
        .expect("final TC target body arrives");
    let effects = release_persisted_effects(&mut core, effects);
    let id = synced_validation_effect(&effects);
    let result = valid_result_for_effect(&core, &effects, id);
    let effects = core
        .step(
            Input::SyncedPayloadValidated { id, result },
            &RootSignatures,
        )
        .expect("TC completion normalizes every now-ready standalone target");
    let (barrier, completed) = persistence_effect(&effects);
    assert_eq!(completed.high_qc().id(), q3.id());
    assert_eq!(completed.finalized().block_id(), q1.block_id());
    assert!(completed.pending_tc_high_qc_sync().is_none());
    assert!(completed.pending_standalone_qc_sync().is_none());
    assert!(completed.pending_finalize().is_some());

    let effects = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("TC, finality, and queue drain share one durable boundary");
    assert!(effects
        .iter()
        .any(|effect| matches!(effect, Effect::Finalize(_))));
    assert!(!effects
        .iter()
        .any(|effect| matches!(effect, Effect::RequestStandaloneQcSync { .. })));
    let effects = apply_finalization_for_test(&mut core, &finalization_authority)
        .expect("application finalization acknowledgement is accepted");
    let (barrier, acknowledged) = persistence_effect(&effects);
    assert!(acknowledged.pending_standalone_qc_sync().is_none());
    assert!(core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("finalization acknowledgement does not resurrect empty replay")
        .is_empty());
}

#[test]
fn a_malformed_payload_cannot_poison_an_authenticated_header() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(&set, genesis_qc(&set), 1, b"valid authenticated payload");
    let certificate = qc(&set, 1, 1, proposed.block().id());
    let effects = core
        .step(Input::Proposal(Box::new(proposed.clone())), &RootSignatures)
        .expect("proposal received");
    let effects = release_persisted_effects(&mut core, effects);
    let validation = validation_effect(&effects);
    let effects = core
        .step(
            Input::PayloadValidated {
                id: validation,
                result: PayloadValidationResult::Unavailable,
            },
            &RootSignatures,
        )
        .expect("invalid result consumed");
    let (barrier, cleaned) = persistence_effect(&effects);
    assert!(cleaned.payload_validation_obligations().is_empty());
    assert!(core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("source-scoped validation cleanup became durable")
        .is_empty());
    let effects = core
        .step(
            Input::QuorumCertificate(certificate.clone()),
            &RootSignatures,
        )
        .expect("the authenticated QC waits for an alternate payload source");
    let (barrier, durable) = persistence_effect(&effects);
    assert_eq!(
        durable
            .pending_standalone_qc_sync()
            .expect("QC catch-up is durable")
            .active()
            .id(),
        certificate.id()
    );
    assert!(matches!(
        core.step(Input::StorageAck { barrier }, &RootSignatures)
            .expect("QC catch-up released after persistence")
            .as_slice(),
        [Effect::RequestStandaloneQcSync { certificate_id, .. }]
            if *certificate_id == certificate.id()
    ));
    let effects = core
        .step(Input::SyncedProposal(Box::new(proposed)), &RootSignatures)
        .expect("the same signed header remains retryable");
    let effects = release_persisted_effects(&mut core, effects);
    let retry_id = synced_validation_effect(&effects);
    let result = valid_result_for_effect(&core, &effects, retry_id);
    let effects = core
        .step(
            Input::SyncedPayloadValidated {
                id: retry_id,
                result,
            },
            &RootSignatures,
        )
        .expect("an alternate source validates and releases the retained QC");
    let (barrier, state) = persistence_effect(&effects);
    assert_eq!(state.high_qc().id(), certificate.id());
    core.step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("retained QC adoption is durable");
    assert_eq!(core.safety_state().high_qc().id(), certificate.id());
    assert_eq!(core.safety_state().finalized().block_id(), GENESIS);
}

#[test]
fn validation_generations_retry_live_while_nonempty_recovery_fails_closed() {
    let (config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let first = proposal(&set, genesis_qc(&set), 1, b"first-invalid");

    let effects = core
        .step(Input::Proposal(Box::new(first.clone())), &RootSignatures)
        .expect("first proposal received");
    let (barrier, durable_request) = persistence_effect(&effects);
    let effects = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("validation request released after the durable revision fence");
    let first_id = validation_effect(&effects);
    let first_result = valid_result_for_effect(&core, &effects, first_id);
    assert!(first_id.generation() <= durable_request.revision());
    assert_eq!(
        Core::recover(config.clone(), durable_request, &RootSignatures),
        Err(CoreError::InvalidRecovery(
            "durable payload validation obligations require an authenticated replay ticket before recovery can reissue them",
        ))
    );

    let effects = core
        .step(
            Input::PayloadValidated {
                id: first_id,
                result: PayloadValidationResult::Unavailable,
            },
            &RootSignatures,
        )
        .expect("current validation result remains usable");
    let (barrier, cleaned) = persistence_effect(&effects);
    assert!(cleaned.payload_validation_obligations().is_empty());
    let completion = cleaned
        .payload_validation_completions()
        .iter()
        .find(|completion| completion.id() == first_id)
        .expect("Unavailable atomically replaces its exact durable obligation");
    assert_eq!(completion.route(), PayloadValidationRouteV0::Proposal);
    assert_eq!(
        completion.result(),
        DurablePayloadValidationResultV1::Unavailable
    );
    assert_eq!(completion.first_recorded_revision(), cleaned.revision());
    let expected_completion = (*completion).clone();
    assert!(core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("unavailable generation cleanup became durable")
        .is_empty());

    let mut recovered =
        Core::recover(config, cleaned, &RootSignatures).expect("completion-only state recovers");
    assert_eq!(
        recovered.safety_state().payload_validation_completions(),
        ::core::slice::from_ref(&expected_completion)
    );
    assert!(recovered
        .step(
            Input::PayloadValidated {
                id: first_id,
                result: PayloadValidationResult::Unavailable,
            },
            &RootSignatures,
        )
        .expect("a duplicate result remains idempotent after recovery")
        .is_empty());
    let before_conflict = recovered.clone();
    assert_eq!(
        recovered.step(
            Input::PayloadValidated {
                id: first_id,
                result: first_result,
            },
            &RootSignatures,
        ),
        Err(CoreError::ConflictingPayloadValidation(first_id.block_id()))
    );
    assert_eq!(recovered, before_conflict);
    let effects = core
        .step(Input::Proposal(Box::new(first)), &RootSignatures)
        .expect("a negative body result cannot poison the signed header");
    let effects = release_persisted_effects(&mut core, effects);
    let retry_id = validation_effect(&effects);
    assert!(retry_id.generation() > first_id.generation());
}

#[test]
fn ordinary_validation_rejects_a_wrong_block_capability_without_consuming_the_generation() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(&set, genesis_qc(&set), 1, b"capability target");
    let wrong = proposal(&set, genesis_qc(&set), 1, b"capability substitution");
    assert_ne!(proposed.block().id(), wrong.block().id());

    let effects = core
        .step(Input::Proposal(Box::new(proposed)), &RootSignatures)
        .expect("proposal accepted");
    let effects = release_persisted_effects(&mut core, effects);
    let id = validation_effect(&effects);
    let exact_result = valid_result_for_effect(&core, &effects, id);
    let wrong_result = valid_result(&core, wrong.block());
    let before = core.clone();

    assert_eq!(
        core.step(
            Input::PayloadValidated {
                id,
                result: wrong_result,
            },
            &RootSignatures,
        ),
        Err(CoreError::ValidationCapabilityMismatch {
            expected: id.block_id(),
            received: wrong.block().id(),
        })
    );
    assert_eq!(core, before);

    let effects = core
        .step(
            Input::PayloadValidated {
                id,
                result: exact_result,
            },
            &RootSignatures,
        )
        .expect("the exact capability remains usable for the same generation");
    let (_barrier, state) = persistence_effect(&effects);
    assert_eq!(
        state.payload_terminal_result(id.block_id()),
        Some(PayloadTerminalResult::Valid)
    );
}

#[test]
fn ordinary_validation_requires_the_exact_sealed_overlay_edge() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(&set, genesis_qc(&set), 1, b"exact sealed overlay edge");
    let effects = core
        .step(Input::Proposal(Box::new(proposed)), &RootSignatures)
        .expect("proposal accepted");
    let effects = release_persisted_effects(&mut core, effects);
    let id = validation_effect(&effects);
    let block = validation_block(&effects, id);
    let exact = valid_result(&core, block);
    let PayloadValidationResult::Valid(valid) = exact else {
        unreachable!("fixture result is Valid")
    };
    let commitments = valid.commitments();

    let wrong_block_id = BlockId::new([0x7b; 32]);
    assert_ne!(wrong_block_id, id.block_id());
    let wrong_block_ref = PayloadValidationResult::authorized_valid_v0(
        commitments,
        artifact_ref_for_ids(wrong_block_id, block.header().parent_id()),
    );
    let before = core.clone();
    assert_eq!(
        core.step(
            Input::PayloadValidated {
                id,
                result: wrong_block_ref,
            },
            &RootSignatures,
        ),
        Err(CoreError::ValidationCapabilityMismatch {
            expected: id.block_id(),
            received: wrong_block_id,
        })
    );
    assert_eq!(core, before);

    let wrong_parent = BlockId::new([0x6c; 32]);
    assert_ne!(wrong_parent, block.header().parent_id());
    let wrong_parent_ref = PayloadValidationResult::authorized_valid_v0(
        commitments,
        artifact_ref_for_ids(id.block_id(), wrong_parent),
    );
    assert_eq!(
        core.step(
            Input::PayloadValidated {
                id,
                result: wrong_parent_ref,
            },
            &RootSignatures,
        ),
        Err(CoreError::ConflictingPayloadValidation(id.block_id()))
    );
    assert_eq!(core, before);

    let effects = core
        .step(
            Input::PayloadValidated { id, result: exact },
            &RootSignatures,
        )
        .expect("the exact overlay remains usable after both rejected callbacks");
    let (_barrier, state) = persistence_effect(&effects);
    let fact = state
        .payload_terminal_fact(id.block_id())
        .expect("Valid callback persists a terminal fact");
    assert_eq!(
        fact.valid_overlay(),
        exact
            .artifact_ref()
            .map(ValidatedPayloadArtifactRefV0::overlay)
    );
}

#[test]
fn exact_validation_completion_replay_binds_the_source_artifact_checksum() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(&set, genesis_qc(&set), 1, b"exact source artifact replay");
    let effects = core
        .step(Input::Proposal(Box::new(proposed)), &RootSignatures)
        .expect("proposal accepted");
    let effects = release_persisted_effects(&mut core, effects);
    let id = validation_effect(&effects);
    let exact = valid_result_for_effect(&core, &effects, id);
    let PayloadValidationResult::Valid(valid) = exact else {
        unreachable!("fixture result is Valid")
    };
    let commitments = valid.commitments();
    let artifact_ref = valid.artifact_ref();
    let effects = core
        .step(
            Input::PayloadValidated { id, result: exact },
            &RootSignatures,
        )
        .expect("exact callback accepted");
    let (barrier, _) = persistence_effect(&effects);
    let _ = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("exact completion persisted before signing");
    assert!(core
        .step(
            Input::PayloadValidated { id, result: exact },
            &RootSignatures
        )
        .expect("byte-exact callback replay is idempotent")
        .is_empty());

    let mut changed_source = artifact_ref.source_artifact_checksum();
    changed_source[0] ^= 1;
    let conflicting = PayloadValidationResult::authorized_valid_v0(
        commitments,
        ValidatedPayloadArtifactRefV0::new(artifact_ref.overlay(), changed_source),
    );
    let before = core.clone();
    assert_eq!(
        core.step(
            Input::PayloadValidated {
                id,
                result: conflicting,
            },
            &RootSignatures,
        ),
        Err(CoreError::ConflictingPayloadValidation(id.block_id()))
    );
    assert_eq!(core, before);
}

#[test]
fn recovery_accepts_route_scoped_sources_only_when_they_share_one_terminal_overlay() {
    let (config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(
        &set,
        genesis_qc(&set),
        1,
        b"route-scoped sources share one overlay",
    );
    let effects = core
        .step(Input::Proposal(Box::new(proposed)), &RootSignatures)
        .expect("proposal accepted");
    let effects = release_persisted_effects(&mut core, effects);
    let id = validation_effect(&effects);
    let exact = valid_result_for_effect(&core, &effects, id);
    let PayloadValidationResult::Valid(valid) = exact else {
        unreachable!("fixture result is Valid")
    };
    let effects = core
        .step(
            Input::PayloadValidated { id, result: exact },
            &RootSignatures,
        )
        .expect("Proposal-route Valid callback accepted");
    let (_, completed) = persistence_effect(&effects);

    let mut second_source_checksum = valid.artifact_ref().source_artifact_checksum();
    second_source_checksum[0] ^= 1;
    let second_route_result = PayloadValidationResult::authorized_valid_v0(
        valid.commitments(),
        ValidatedPayloadArtifactRefV0::new(valid.artifact_ref().overlay(), second_source_checksum),
    );
    let second_id = ValidationId::new(
        id.block_id(),
        id.view(),
        id.generation()
            .checked_add(1)
            .expect("fixture generation does not overflow"),
    );
    assert!(second_id.generation() <= completed.revision());
    let mut completions = completed.payload_validation_completions().to_vec();
    completions.push(DurablePayloadValidationCompletionV0::new(
        PayloadValidationRouteV0::Synced,
        second_id,
        DurablePayloadValidationResultV1::from_live(second_route_result),
        completed.revision(),
    ));
    completions.sort_by_key(DurablePayloadValidationCompletionV0::key);
    let candidate = decoded_state_with_validation_records(&completed, vec![], completions);
    let decoded = roundtrip_safety_state_record(&config, &candidate);
    Core::validate_persisted_state_v0(&config, &decoded, &RootSignatures)
        .expect("route-scoped sources may differ only behind one stable overlay");
    assert_eq!(
        decoded
            .payload_terminal_fact(id.block_id())
            .and_then(PayloadTerminalFact::valid_overlay),
        Some(valid.artifact_ref().overlay())
    );
}

#[test]
fn recovery_rejects_cross_route_valid_completions_with_different_stable_overlays() {
    let (config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(
        &set,
        genesis_qc(&set),
        1,
        b"stable overlay recovery conflict",
    );
    let effects = core
        .step(Input::Proposal(Box::new(proposed)), &RootSignatures)
        .expect("proposal accepted");
    let effects = release_persisted_effects(&mut core, effects);
    let id = validation_effect(&effects);
    let exact = valid_result_for_effect(&core, &effects, id);
    let PayloadValidationResult::Valid(valid) = exact else {
        unreachable!("fixture result is Valid")
    };
    let commitments = valid.commitments();
    let artifact_ref = valid.artifact_ref();
    let effects = core
        .step(
            Input::PayloadValidated { id, result: exact },
            &RootSignatures,
        )
        .expect("Valid callback accepted");
    let (_, completed) = persistence_effect(&effects);

    let mut changed_overlay_checksum = artifact_ref.overlay().overlay_checksum();
    changed_overlay_checksum[0] ^= 1;
    let conflicting_live = PayloadValidationResult::authorized_valid_v0(
        commitments,
        ValidatedPayloadArtifactRefV0::new(
            BlockIdOverlayRefV0::new(
                id.block_id(),
                artifact_ref.overlay().parent_block_id(),
                changed_overlay_checksum,
            ),
            artifact_ref.source_artifact_checksum(),
        ),
    );
    let conflicting_id = ValidationId::new(
        id.block_id(),
        id.view(),
        id.generation()
            .checked_add(1)
            .expect("fixture generation does not overflow"),
    );
    assert!(conflicting_id.generation() <= completed.revision());
    let mut completions = completed.payload_validation_completions().to_vec();
    completions.push(DurablePayloadValidationCompletionV0::new(
        PayloadValidationRouteV0::Synced,
        conflicting_id,
        DurablePayloadValidationResultV1::from_live(conflicting_live),
        completed.revision(),
    ));
    completions.sort_by_key(DurablePayloadValidationCompletionV0::key);
    let tampered = decoded_state_with_validation_records(&completed, vec![], completions);
    let decoded = roundtrip_safety_state_record(&config, &tampered);
    assert_eq!(
        Core::validate_persisted_state_v0(&config, &decoded, &RootSignatures),
        Err(CoreError::InvalidRecovery(
            "durable Valid completion disagrees with its terminal overlay",
        ))
    );
}

#[test]
fn synced_validation_rejects_a_wrong_block_capability_without_completing_sync() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(&set, genesis_qc(&set), 1, b"synced capability target");
    let wrong = proposal(&set, genesis_qc(&set), 1, b"synced capability substitution");
    assert_ne!(proposed.block().id(), wrong.block().id());

    let effects = core
        .step(Input::SyncedProposal(Box::new(proposed)), &RootSignatures)
        .expect("synced proposal accepted");
    let effects = release_persisted_effects(&mut core, effects);
    let id = synced_validation_effect(&effects);
    let exact_result = valid_result_for_effect(&core, &effects, id);
    let wrong_result = valid_result(&core, wrong.block());
    let before = core.clone();

    assert_eq!(
        core.step(
            Input::SyncedPayloadValidated {
                id,
                result: wrong_result,
            },
            &RootSignatures,
        ),
        Err(CoreError::ValidationCapabilityMismatch {
            expected: id.block_id(),
            received: wrong.block().id(),
        })
    );
    assert_eq!(core, before);

    let effects = core
        .step(
            Input::SyncedPayloadValidated {
                id,
                result: exact_result,
            },
            &RootSignatures,
        )
        .expect("the exact synced capability remains usable");
    let (_barrier, state) = persistence_effect(&effects);
    assert_eq!(
        state.payload_terminal_result(id.block_id()),
        Some(PayloadTerminalResult::Valid)
    );
}

#[test]
fn canceled_synced_validation_drops_only_the_exact_request_and_can_reregister() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(&set, genesis_qc(&set), 1, b"cancel synced validation");

    let effects = core
        .step(
            Input::SyncedProposal(Box::new(proposed.clone())),
            &RootSignatures,
        )
        .expect("first synced proposal accepted");
    let effects = release_persisted_effects(&mut core, effects);
    let first_id = synced_validation_effect(&effects);
    let stale_result = valid_result_for_effect(&core, &effects, first_id);
    assert_eq!(core.pending_validation_count(), 1);

    let wrong_id = ValidationId::new(
        first_id.block_id(),
        first_id.view(),
        first_id.generation() + 1,
    );
    let before_wrong_cancel = core.clone();
    assert_eq!(
        core.step(
            Input::CancelSyncedPayloadValidation { id: wrong_id },
            &RootSignatures,
        ),
        Err(CoreError::UnknownValidation(wrong_id.block_id()))
    );
    assert_eq!(core, before_wrong_cancel);
    assert_eq!(core.pending_validation_count(), 1);

    let effects = core
        .step(
            Input::CancelSyncedPayloadValidation { id: first_id },
            &RootSignatures,
        )
        .expect("the exact volatile request is canceled");
    let (barrier, canceled) = persistence_effect(&effects);
    assert!(canceled.payload_validation_obligations().is_empty());
    assert_eq!(core.pending_validation_count(), 0);
    assert!(core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("synced cancellation became durable")
        .is_empty());
    assert_eq!(
        core.step(
            Input::SyncedPayloadValidated {
                id: first_id,
                result: stale_result,
            },
            &RootSignatures,
        ),
        Err(CoreError::UnknownValidation(first_id.block_id()))
    );

    let effects = core
        .step(Input::SyncedProposal(Box::new(proposed)), &RootSignatures)
        .expect("the same block can register under a fresh request");
    let effects = release_persisted_effects(&mut core, effects);
    let second_id = synced_validation_effect(&effects);
    assert_ne!(second_id, first_id);
    let exact_result = valid_result_for_effect(&core, &effects, second_id);
    let effects = core
        .step(
            Input::SyncedPayloadValidated {
                id: second_id,
                result: exact_result,
            },
            &RootSignatures,
        )
        .expect("the fresh synced request completes");
    let (_barrier, state) = persistence_effect(&effects);
    assert_eq!(
        state.payload_terminal_result(second_id.block_id()),
        Some(PayloadTerminalResult::Valid)
    );
}

#[test]
fn uncertified_invalid_payload_halts_only_when_a_qc_later_references_it() {
    let (config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(&set, genesis_qc(&set), 1, b"terminal invalid");
    let certificate = qc(&set, 1, 1, proposed.block().id());

    let effects = core
        .step(Input::Proposal(Box::new(proposed.clone())), &RootSignatures)
        .expect("proposal accepted");
    let effects = release_persisted_effects(&mut core, effects);
    let id = validation_effect(&effects);
    let effects = core
        .step(
            Input::PayloadValidated {
                id,
                result: PayloadValidationResult::DeterministicallyInvalid,
            },
            &RootSignatures,
        )
        .expect("an uncertified invalid payload becomes a bounded durable fact");
    let (terminal_barrier, terminal_state) = persistence_effect(&effects);
    assert_eq!(
        terminal_state.payload_terminal_result(proposed.block().id()),
        Some(PayloadTerminalResult::DeterministicallyInvalid)
    );
    assert_eq!(
        terminal_state
            .payload_validation_completions()
            .iter()
            .find(|completion| completion.id() == id)
            .expect("deterministically-invalid completion is durable")
            .result(),
        DurablePayloadValidationResultV1::DeterministicallyInvalid
    );
    assert_safety_state_record_roundtrip_and_validate(&config, &terminal_state);
    assert!(core
        .step(
            Input::QuorumCertificate(certificate.clone()),
            &RootSignatures,
        )
        .is_err());
    assert!(core
        .step(
            Input::StorageAck {
                barrier: terminal_barrier,
            },
            &RootSignatures,
        )
        .expect("terminal fact is durable before more consensus input")
        .is_empty());
    assert!(core
        .step(
            Input::PayloadValidated {
                id,
                result: PayloadValidationResult::DeterministicallyInvalid,
            },
            &RootSignatures,
        )
        .expect("the same terminal callback is idempotent")
        .is_empty());
    let mut recovered = Core::recover(config.clone(), terminal_state, &RootSignatures)
        .expect("ordinary terminal fact survives a crash");
    let effects = recovered
        .step(Input::Proposal(Box::new(proposed)), &RootSignatures)
        .expect("the exact invalid proposal is handled from the durable terminal cache");
    assert!(!effects
        .iter()
        .any(|effect| matches!(effect, Effect::ValidatePayload(_))));

    let effects = recovered
        .step(
            Input::QuorumCertificate(certificate.clone()),
            &RootSignatures,
        )
        .expect("a later QC collides with the invalid terminal fact");
    let (barrier, halted) = persistence_effect(&effects);
    match halted.safety_halt().expect("halt is in the durable image") {
        SafetyHalt::DeterministicallyInvalidPayload {
            block_id,
            reference: InvalidPayloadReference::QuorumCertificate(witness),
        } => {
            assert_eq!(*block_id, certificate.block_id());
            assert_eq!(witness.id(), certificate.id());
        }
        other => panic!("unexpected payload halt: {other:?}"),
    }
    assert_safety_state_record_roundtrip_and_validate(&config, &halted);
    assert!(matches!(
        recovered
            .step(Input::StorageAck { barrier }, &RootSignatures)
            .expect("halt persisted before notification")
            .as_slice(),
        [Effect::SafetyHalted(_)]
    ));

    let mut recovered =
        Core::recover(config, halted, &RootSignatures).expect("payload halt recovers");
    assert!(matches!(
        recovered
            .step(Input::Resume, &RootSignatures)
            .expect("recovery reissues only the halt")
            .as_slice(),
        [Effect::SafetyHalted(_)]
    ));
}

#[test]
fn qc_before_invalid_payload_is_retained_until_validation_completes() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(&set, genesis_qc(&set), 1, b"QC first");
    let certificate = qc(&set, 1, 1, proposed.block().id());

    let effects = core
        .step(Input::Proposal(Box::new(proposed)), &RootSignatures)
        .expect("proposal accepted");
    let effects = release_persisted_effects(&mut core, effects);
    let id = validation_effect(&effects);
    let effects = core
        .step(
            Input::QuorumCertificate(certificate.clone()),
            &RootSignatures,
        )
        .expect("verified QC waits on the known header's payload");
    let (barrier, durable) = persistence_effect(&effects);
    assert_eq!(
        durable
            .pending_standalone_qc_sync()
            .expect("verified QC is a durable obligation")
            .active()
            .id(),
        certificate.id()
    );
    assert!(matches!(
        core.step(Input::StorageAck { barrier }, &RootSignatures)
            .expect("QC sync request follows the durable acknowledgement")
            .as_slice(),
        [Effect::RequestStandaloneQcSync { certificate_id, .. }]
            if *certificate_id == certificate.id()
    ));
    assert_ne!(core.safety_state().high_qc().id(), certificate.id());

    let effects = core
        .step(
            Input::PayloadValidated {
                id,
                result: PayloadValidationResult::DeterministicallyInvalid,
            },
            &RootSignatures,
        )
        .expect("the retained QC forces a durable invalid-payload halt");
    let (_barrier, halted) = persistence_effect(&effects);
    match halted.safety_halt().expect("durable payload halt") {
        SafetyHalt::DeterministicallyInvalidPayload {
            block_id,
            reference: InvalidPayloadReference::QuorumCertificate(witness),
        } => {
            assert_eq!(*block_id, certificate.block_id());
            assert_eq!(witness.id(), certificate.id());
        }
        other => panic!("unexpected payload halt: {other:?}"),
    }
}

#[test]
fn durable_valid_fact_still_requires_body_and_context_readiness_after_recovery() {
    let (config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(&set, genesis_qc(&set), 1, b"durable valid but body-scoped");

    let effects = core
        .step(
            Input::SyncedProposal(Box::new(proposed.clone())),
            &RootSignatures,
        )
        .expect("synced proposal accepted");
    let effects = release_persisted_effects(&mut core, effects);
    let first_id = synced_validation_effect(&effects);
    let first_result = valid_result_for_effect(&core, &effects, first_id);
    let effects = core
        .step(
            Input::SyncedPayloadValidated {
                id: first_id,
                result: first_result,
            },
            &RootSignatures,
        )
        .expect("terminal Valid fact accepted");
    let (barrier, durable) = persistence_effect(&effects);
    assert_eq!(
        durable.payload_terminal_result(proposed.block().id()),
        Some(PayloadTerminalResult::Valid)
    );
    assert_eq!(
        Core::recover(config.clone(), durable.clone(), &RootSignatures),
        Err(CoreError::InvalidRecovery(
            "a current NativeValid completion requires its dedicated cross-store recovery session"
        ))
    );
    assert!(core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("Valid fact persisted")
        .is_empty());

    let session =
        Core::begin_native_valid_completion_recovery_v0(config, durable.clone(), &RootSignatures)
            .expect("the durable Valid fact enters only its dedicated cross-store session");
    assert_eq!(session.challenge().validation_id_v0(), first_id);
    assert_eq!(
        session
            .challenge()
            .safety_state()
            .payload_terminal_result(proposed.block().id()),
        Some(PayloadTerminalResult::Valid)
    );
}

#[test]
fn recovered_invalid_fact_rejects_a_vote_outbox_without_a_durable_halt() {
    let (config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(&set, genesis_qc(&set), 1, b"tampered recovered vote outbox");
    let effects = core
        .step(Input::Proposal(Box::new(proposed.clone())), &RootSignatures)
        .expect("proposal accepted");
    let effects = release_persisted_effects(&mut core, effects);
    let id = validation_effect(&effects);
    let result = valid_result_for_effect(&core, &effects, id);
    let effects = core
        .step(Input::PayloadValidated { id, result }, &RootSignatures)
        .expect("valid callback stages a vote outbox");
    let (_, vote_state) = persistence_effect(&effects);
    let missing_completion = decoded_state_with_validation_records(&vote_state, vec![], vec![]);
    let decoded_missing_completion = roundtrip_safety_state_record(&config, &missing_completion);
    assert_eq!(
        Core::validate_persisted_state_v0(&config, &decoded_missing_completion, &RootSignatures,),
        Err(CoreError::InvalidRecovery(
            "vote intent has no durable completion for its Valid overlay",
        ))
    );
    let valid_fact = vote_state.payload_terminal_facts()[0];
    let invalid_fact = PayloadTerminalFact::new_deterministically_invalid(
        valid_fact.block_id(),
        valid_fact.first_recorded_revision(),
    );
    let tampered = SafetyState::from_persisted_parts_v13(
        vote_state.schema_version(),
        vote_state.chain_id(),
        vote_state.protocol_version(),
        vote_state.epoch(),
        vote_state.validator_set_id(),
        vote_state.genesis_block_id(),
        vote_state
            .authenticated_genesis_application_parent_v0()
            .copied(),
        vote_state.current_view(),
        vote_state.last_voted_view(),
        vote_state.last_timeout_view(),
        vote_state.high_qc().clone(),
        vote_state.locked_qc().clone(),
        vote_state.finalized(),
        vote_state.revision(),
        vote_state.durable_observed_qcs().to_vec(),
        vec![invalid_fact],
        vec![],
        vote_state.payload_validation_completions().to_vec(),
        vote_state.pending_tc_high_qc_sync().cloned(),
        vote_state.pending_standalone_qc_sync().cloned(),
        vote_state.pending_sign().cloned(),
        vote_state.last_finalization().cloned(),
        vote_state.state_sync_anchor().cloned(),
        vote_state.application_applied(),
        vote_state.finalization_queue().to_vec(),
        vote_state.pending_finalize(),
        None,
    );
    let decoded = roundtrip_safety_state_record(&config, &tampered);
    assert!(matches!(
        Core::validate_persisted_state_v0(&config, &decoded, &RootSignatures),
        Err(CoreError::InvalidRecovery(_))
    ));
    assert!(matches!(
        Core::recover(config, tampered, &RootSignatures),
        Err(CoreError::InvalidRecovery(_))
    ));
}

#[test]
fn certified_invalid_probe_cancels_a_recovered_timeout_outbox_before_signing() {
    let (config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(&set, genesis_qc(&set), 1, b"invalid before timeout crash");
    let certificate = qc(&set, 1, 1, proposed.block().id());
    let effects = core
        .step(Input::Proposal(Box::new(proposed)), &RootSignatures)
        .expect("proposal accepted");
    let effects = release_persisted_effects(&mut core, effects);
    let id = validation_effect(&effects);
    let effects = core
        .step(
            Input::PayloadValidated {
                id,
                result: PayloadValidationResult::DeterministicallyInvalid,
            },
            &RootSignatures,
        )
        .expect("ordinary invalid fact staged");
    let effects = release_persisted_effects(&mut core, effects);
    assert!(effects.is_empty());
    let effects = core
        .step(
            Input::LocalTimeout {
                epoch: Epoch::new(0),
                view: View::new(1),
            },
            &RootSignatures,
        )
        .expect("unrelated timeout outbox staged");
    let (_, timeout_state) = persistence_effect(&effects);

    let mut recovered = Core::recover(config, timeout_state, &RootSignatures)
        .expect("invalid fact may coexist with an unrelated timeout outbox");
    let effects = recovered
        .step(Input::QuorumCertificate(certificate), &RootSignatures)
        .expect("certified-invalid probe bypasses the recovered outbox gate");
    let (_, halted) = persistence_effect(&effects);
    assert!(halted.pending_sign().is_none());
    assert!(matches!(
        halted.safety_halt(),
        Some(SafetyHalt::DeterministicallyInvalidPayload { .. })
    ));
}

#[test]
fn conflicting_terminal_callback_cancels_a_pending_vote_before_signature() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(&set, genesis_qc(&set), 1, b"callback conflict");

    let effects = core
        .step(Input::Proposal(Box::new(proposed)), &RootSignatures)
        .expect("proposal accepted");
    let effects = release_persisted_effects(&mut core, effects);
    let id = validation_effect(&effects);
    let result = valid_result_for_effect(&core, &effects, id);
    let effects = core
        .step(Input::PayloadValidated { id, result }, &RootSignatures)
        .expect("valid result stages a vote intent");
    let (barrier, _) = persistence_effect(&effects);
    let request = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("vote intent durable");
    let (sign_id, signing_root) = signature_request(&request);
    assert!(core
        .step(Input::PayloadValidated { id, result }, &RootSignatures,)
        .expect("same callback remains idempotent while the signer is outstanding")
        .is_empty());

    let effects = core
        .step(
            Input::PayloadValidated {
                id,
                result: PayloadValidationResult::DeterministicallyInvalid,
            },
            &RootSignatures,
        )
        .expect("opposite terminal callback enters fail-stop");
    let (halt_barrier, halted) = persistence_effect(&effects);
    assert!(halted.pending_sign().is_none());
    assert!(matches!(
        halted.safety_halt(),
        Some(SafetyHalt::ConflictingPayloadValidation {
            block_id,
            first: PayloadTerminalResult::Valid,
            second: PayloadTerminalResult::DeterministicallyInvalid,
        }) if *block_id == id.block_id()
    ));
    assert!(matches!(
        core.step(
            Input::SignatureReady {
                id: sign_id,
                signature: signature(signing_root),
            },
            &RootSignatures,
        ),
        Err(CoreError::Busy(_))
    ));
    assert!(matches!(
        core.step(
            Input::StorageAck {
                barrier: halt_barrier,
            },
            &RootSignatures,
        )
        .expect("conflict halt persisted")
        .as_slice(),
        [Effect::SafetyHalted(_)]
    ));
    assert!(matches!(
        core.step(
            Input::SignatureReady {
                id: sign_id,
                signature: signature(signing_root),
            },
            &RootSignatures,
        ),
        Err(CoreError::Busy(_))
    ));
}

#[test]
fn valid_callback_during_timeout_signing_can_vote_after_the_outbox_clears() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(&set, genesis_qc(&set), 1, b"deferred valid vote");

    let effects = core
        .step(Input::Proposal(Box::new(proposed.clone())), &RootSignatures)
        .expect("proposal accepted");
    let effects = release_persisted_effects(&mut core, effects);
    let validation_id = validation_effect(&effects);
    let validation_result = valid_result_for_effect(&core, &effects, validation_id);
    let effects = core
        .step(
            Input::LocalTimeout {
                epoch: Epoch::new(0),
                view: View::new(1),
            },
            &RootSignatures,
        )
        .expect("timeout can race validation");
    let (barrier, _) = persistence_effect(&effects);
    let request = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("timeout signing intent durable");
    let (timeout_sign_id, timeout_root) = signature_request(&request);
    let effects = core
        .step(
            Input::PayloadValidated {
                id: validation_id,
                result: validation_result,
            },
            &RootSignatures,
        )
        .expect("valid fact is retained while timeout signing is active");
    assert!(release_persisted_effects(&mut core, effects).is_empty());
    assert!(matches!(
        core.step(
            Input::SignatureReady {
                id: timeout_sign_id,
                signature: signature(timeout_root),
            },
            &RootSignatures,
        )
        .expect("timeout signature clears the outbox")
        .as_slice(),
        [Effect::Broadcast(OutboundMessage::TimeoutVote(_))]
    ));

    let effects = core
        .step(Input::Proposal(Box::new(proposed)), &RootSignatures)
        .expect("the known-valid proposal is re-evaluated");
    let (_barrier, state) = persistence_effect(&effects);
    assert!(matches!(
        state.pending_sign(),
        Some(SignIntent::Vote { block_id, .. }) if *block_id == validation_id.block_id()
    ));
}

#[test]
fn oversized_blocks_and_invalid_timestamp_steps_are_rejected_before_validation() {
    let mut small_fields = consensus_parameters().fields();
    small_fields.max_block_bytes = 3;
    let small_parameters =
        ConsensusParametersV0::new(small_fields).expect("valid small-block parameters");
    let set = validator_set_with_parameters(&small_parameters);
    let small_config = CoreConfig::new(
        validator_id(1),
        set.clone(),
        small_parameters,
        GENESIS_TIMESTAMP_MS,
        32,
        64,
    )
    .expect("valid bounded config");
    let mut small_core =
        Core::new(small_config, genesis_qc(&set), &RootSignatures).expect("valid bounded core");
    let oversized = try_proposal_with_proposer(
        &set,
        &small_parameters,
        genesis_qc(&set),
        1,
        b"four",
        leader_for(&set, View::new(1)),
    )
    .expect("wire-valid oversized proposal");
    let oversized_logical_size = oversized.block().logical_block_size();
    assert_eq!(
        small_core.step(Input::Proposal(Box::new(oversized)), &RootSignatures),
        Err(CoreError::BlockTooLarge {
            actual: oversized_logical_size,
            maximum: 3,
        })
    );

    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposer = leader_for(&set, View::new(1));
    let late_block = block_with_timestamp(&set, 1, 1, GENESIS, b"late", proposer, 60_001);
    let late = signed_proposal_from_block(
        &set,
        &consensus_parameters(),
        late_block,
        genesis_qc(&set).into_qc_reference(),
        None,
        1,
    )
    .expect("proposal is valid only against the claimed parent timestamp");
    assert!(matches!(
        core.step(Input::Proposal(Box::new(late)), &RootSignatures),
        Err(CoreError::Protocol(_))
    ));
    assert_eq!(core.pending_validation_count(), 0);
}

#[test]
fn complete_signed_proposal_resource_bound_precedes_validation_registration() {
    let reference_parameters = consensus_parameters();
    let reference_set = validator_set_with_parameters(&reference_parameters);
    let reference = proposal_with_parameters(
        &reference_set,
        &reference_parameters,
        genesis_qc(&reference_set),
        1,
        b"bounded complete proposal",
    );
    let block_size = reference.block().logical_block_size();
    let complete_size = reference
        .durable_validation_resource_size_v0()
        .expect("bounded proposal resource size");
    assert!(complete_size > block_size);

    let mut bounded_fields = reference_parameters.fields();
    bounded_fields.max_block_bytes = u32::try_from(block_size).expect("test block size fits u32");
    bounded_fields.max_consensus_message_bytes =
        u32::try_from(complete_size - 1).expect("test proposal size fits u32");
    let bounded_parameters =
        ConsensusParametersV0::new(bounded_fields).expect("valid narrow resource parameters");
    let (_config, mut core) = configured_core_with_parameters(bounded_parameters);
    let set = core.config().validator_set().clone();
    let proposal = proposal_with_parameters(
        &set,
        &bounded_parameters,
        genesis_qc(&set),
        1,
        b"bounded complete proposal",
    );
    let actual = proposal
        .durable_validation_resource_size_v0()
        .expect("bounded proposal resource size");
    let maximum = bounded_parameters.max_consensus_message_bytes() as usize;
    assert_eq!(proposal.block().logical_block_size(), block_size);
    assert!(proposal.block().logical_block_size() <= core.config().max_block_bytes());
    assert!(actual > maximum);
    assert_eq!(
        core.step(Input::Proposal(Box::new(proposal)), &RootSignatures),
        Err(CoreError::PayloadValidationResourceTooLarge { actual, maximum })
    );
    assert_eq!(core.pending_validation_count(), 0);
    assert!(core
        .safety_state()
        .payload_validation_obligations()
        .is_empty());
}

#[test]
fn aggregate_durable_validation_resource_bound_preserves_the_existing_obligation() {
    const GENESIS_OBLIGATION_FIXED_BYTES: usize =
        1 + (32 + 8 + 8) + 4 + (8 + 8 + 32 + 8) + 1 + 1 + 8;
    let reference_parameters = consensus_parameters();
    let reference_set = validator_set_with_parameters(&reference_parameters);
    let reference = proposal_with_parameters(
        &reference_set,
        &reference_parameters,
        genesis_qc(&reference_set),
        1,
        b"aggregate bounded proposal",
    );
    let block_size = reference.block().logical_block_size();
    let single_obligation_size = reference
        .durable_validation_resource_size_v0()
        .expect("bounded proposal resource size")
        + GENESIS_OBLIGATION_FIXED_BYTES;

    let mut bounded_fields = reference_parameters.fields();
    bounded_fields.max_block_bytes = u32::try_from(block_size).expect("test block size fits u32");
    bounded_fields.max_consensus_message_bytes =
        u32::try_from(single_obligation_size).expect("test obligation size fits u32");
    let bounded_parameters =
        ConsensusParametersV0::new(bounded_fields).expect("valid aggregate resource parameters");
    let (_config, mut core) = configured_core_with_parameters(bounded_parameters);
    let set = core.config().validator_set().clone();
    let proposal = proposal_with_parameters(
        &set,
        &bounded_parameters,
        genesis_qc(&set),
        1,
        b"aggregate bounded proposal",
    );
    let actual_single = proposal
        .durable_validation_resource_size_v0()
        .expect("bounded proposal resource size")
        + GENESIS_OBLIGATION_FIXED_BYTES;
    let maximum = bounded_parameters.max_consensus_message_bytes() as usize;
    assert_eq!(actual_single, maximum);

    let effects = core
        .step(Input::Proposal(Box::new(proposal.clone())), &RootSignatures)
        .expect("one complete durable obligation fits exactly");
    let (barrier, durable) = persistence_effect(&effects);
    assert_eq!(durable.payload_validation_obligations().len(), 1);
    core.step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("first obligation is released only after persistence");

    let actual = actual_single
        .checked_mul(2)
        .expect("test aggregate resource size");
    assert_eq!(
        core.step(Input::SyncedProposal(Box::new(proposal)), &RootSignatures,),
        Err(CoreError::PayloadValidationResourceTooLarge { actual, maximum })
    );
    assert_eq!(core.pending_validation_count(), 1);
    assert_eq!(
        core.safety_state().payload_validation_obligations(),
        durable.payload_validation_obligations()
    );
}

#[test]
fn recovery_rejects_an_anchor_header_with_an_invalid_finalized_timestamp_edge() {
    let (config, bootstrap) = configured_core();
    let set = bootstrap.config().validator_set().clone();
    let proposer = leader_for(&set, View::new(1));
    let late_block = block_with_timestamp(&set, 1, 1, GENESIS, b"late", proposer, 60_001);
    let late_proposal = signed_proposal_from_block(
        &set,
        &consensus_parameters(),
        late_block,
        genesis_qc(&set).into_qc_reference(),
        None,
        1,
    )
    .expect("proposal is valid only against the claimed parent timestamp");
    let high_qc = qc(&set, 1, 1, late_proposal.block().id());
    let genesis = bootstrap.safety_state();
    let recovered_state = SafetyState::from_persisted_parts(
        SAFETY_STATE_SCHEMA_VERSION,
        genesis.chain_id(),
        genesis.protocol_version(),
        genesis.epoch(),
        genesis.validator_set_id(),
        genesis.genesis_block_id(),
        View::new(2),
        None,
        None,
        high_qc.into_qc_reference(),
        genesis.locked_qc().clone(),
        genesis.finalized(),
        genesis.revision(),
        Vec::new(),
        vec![],
        vec![],
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let mut recovered = Core::recover(config, recovered_state, &RootSignatures)
        .expect("QC-only state requires header replay");
    assert!(matches!(
        recovered.step(
            Input::SyncedProposal(Box::new(late_proposal)),
            &RootSignatures,
        ),
        Err(CoreError::Protocol(_))
    ));
    assert!(matches!(
        recovered.step(Input::SafetyReplayComplete, &RootSignatures),
        Err(CoreError::InvalidRecovery(_))
    ));
}

#[test]
fn recovery_rejects_a_finalized_tip_without_its_permanent_proof() {
    let (config, core) = configured_core();
    let state = core.safety_state();
    let set = core.config().validator_set();
    let proposed = proposal(set, genesis_qc(set), 1, b"unproven finalized tip");
    let certificate = qc(set, 1, 1, proposed.block().id());
    let decoded = SafetyState::from_persisted_parts_v13(
        SAFETY_STATE_SCHEMA_VERSION,
        state.chain_id(),
        state.protocol_version(),
        state.epoch(),
        state.validator_set_id(),
        state.genesis_block_id(),
        state.authenticated_genesis_application_parent_v0().copied(),
        state.current_view(),
        state.last_voted_view(),
        state.last_timeout_view(),
        certificate.clone().into_qc_reference(),
        certificate.into_qc_reference(),
        FinalizedTip::new(
            proposed.block().header().height(),
            proposed.block().header().view(),
            proposed.block().id(),
            proposed.block().header().timestamp_ms(),
        ),
        state.revision(),
        state.durable_observed_qcs().to_vec(),
        state.payload_terminal_facts().to_vec(),
        vec![],
        state.payload_validation_completions().to_vec(),
        state.pending_tc_high_qc_sync().cloned(),
        state.pending_standalone_qc_sync().cloned(),
        state.pending_sign().cloned(),
        None,
        state.state_sync_anchor().cloned(),
        state.application_applied(),
        state.finalization_queue().to_vec(),
        state.pending_finalize(),
        state.safety_halt().cloned(),
    );
    assert!(matches!(
        Core::recover(config, decoded, &RootSignatures),
        Err(CoreError::InvalidRecovery(_))
    ));
}

#[test]
fn recovery_rejects_noncanonical_durable_payload_validation_completions() {
    let (config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(&set, genesis_qc(&set), 1, b"completion recovery invariants");
    let effects = core
        .step(Input::Proposal(Box::new(proposed.clone())), &RootSignatures)
        .expect("completion fixture proposal accepted");
    let effects = release_persisted_effects(&mut core, effects);
    let id = validation_effect(&effects);
    let effects = core
        .step(
            Input::PayloadValidated {
                id,
                result: PayloadValidationResult::Unavailable,
            },
            &RootSignatures,
        )
        .expect("completion fixture callback accepted");
    let (barrier, completed) = persistence_effect(&effects);
    assert!(core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("completion fixture persisted")
        .is_empty());
    let base = completed
        .payload_validation_completions()
        .iter()
        .find(|completion| completion.id() == id)
        .cloned()
        .expect("fixture completion is durable");
    assert_eq!(base.route(), PayloadValidationRouteV0::Proposal);
    assert_eq!(base.result(), DurablePayloadValidationResultV1::Unavailable);

    let assert_invalid = |label: &str, state: SafetyState, message: &'static str| {
        let decoded = roundtrip_safety_state_record(&config, &state);
        assert_eq!(
            Core::validate_persisted_state_v0(&config, &decoded, &RootSignatures),
            Err(CoreError::InvalidRecovery(message)),
            "{label}: exact decoding must not upgrade a checksum-consistent splice"
        );
        assert_eq!(
            Core::recover(config.clone(), state, &RootSignatures),
            Err(CoreError::InvalidRecovery(message)),
            "{label}"
        );
    };

    let other_id = ValidationId::new(BlockId::new([0xD7; 32]), View::new(1), 1);
    assert_ne!(other_id.block_id(), id.block_id());
    let other = DurablePayloadValidationCompletionV0::new(
        PayloadValidationRouteV0::Proposal,
        other_id,
        DurablePayloadValidationResultV1::Unavailable,
        completed.revision(),
    );
    let mut reversed = vec![base.clone(), other];
    reversed.sort_by_key(DurablePayloadValidationCompletionV0::key);
    reversed.reverse();
    assert_invalid(
        "completion order",
        decoded_state_with_validation_records(&completed, vec![], reversed),
        "durable payload validation completions are not uniquely sorted by route and full id",
    );
    assert_invalid(
        "duplicate completion key",
        decoded_state_with_validation_records(&completed, vec![], vec![base.clone(), base.clone()]),
        "durable payload validation completions are not uniquely sorted by route and full id",
    );

    let zero_revision =
        DurablePayloadValidationCompletionV0::new(base.route(), base.id(), base.result(), 0);
    assert_invalid(
        "zero completion revision",
        decoded_state_with_validation_records(&completed, vec![], vec![zero_revision]),
        "durable payload validation completion has an impossible generation or first revision",
    );
    let future_revision = DurablePayloadValidationCompletionV0::new(
        base.route(),
        base.id(),
        base.result(),
        completed
            .revision()
            .checked_add(1)
            .expect("fixture revision does not overflow"),
    );
    assert_invalid(
        "future completion revision",
        decoded_state_with_validation_records(&completed, vec![], vec![future_revision]),
        "durable payload validation completion has an impossible generation or first revision",
    );

    let wrong = proposal(&set, genesis_qc(&set), 1, b"foreign completion commitments");
    assert_ne!(wrong.block().id(), id.block_id());
    let foreign_commitments = valid_result(&core, wrong.block());
    let mismatched_result = DurablePayloadValidationCompletionV0::new(
        base.route(),
        base.id(),
        DurablePayloadValidationResultV1::from_live(foreign_commitments),
        base.first_recorded_revision(),
    );
    assert_invalid(
        "foreign Valid commitments",
        decoded_state_with_validation_records(&completed, vec![], vec![mismatched_result]),
        "durable payload validation completion result differs from its full id",
    );

    let opposite_route = DurablePayloadValidationCompletionV0::new(
        PayloadValidationRouteV0::Synced,
        base.id(),
        base.result(),
        base.first_recorded_revision(),
    );
    let mut reused_id = vec![base.clone(), opposite_route];
    reused_id.sort_by_key(DurablePayloadValidationCompletionV0::key);
    assert_invalid(
        "full id reused across routes",
        decoded_state_with_validation_records(&completed, vec![], reused_id),
        "durable payload validation completion reused one full id across routes",
    );

    let effects = core
        .step(Input::Proposal(Box::new(proposed)), &RootSignatures)
        .expect("a fresh generation reserves an overlap fixture obligation");
    let (_barrier, obligated) = persistence_effect(&effects);
    let obligation = obligated
        .payload_validation_obligations()
        .first()
        .expect("fresh generation has one durable obligation");
    let overlap = DurablePayloadValidationCompletionV0::new(
        obligation.route(),
        obligation.id(),
        DurablePayloadValidationResultV1::Unavailable,
        obligated.revision(),
    );
    let mut overlapping = obligated.payload_validation_completions().to_vec();
    overlapping.push(overlap);
    overlapping.sort_by_key(DurablePayloadValidationCompletionV0::key);
    assert_invalid(
        "completion overlaps obligation",
        decoded_state_with_validation_records(
            &obligated,
            obligated.payload_validation_obligations().to_vec(),
            overlapping,
        ),
        "durable payload validation completion overlaps a live obligation",
    );

    let maximum = config.max_observed_messages();
    let mut over_capacity = obligated.payload_validation_completions().to_vec();
    let mut suffix = 0u8;
    while over_capacity.len() < maximum {
        let mut block_id = [0xC7; 32];
        block_id[31] = suffix;
        suffix = suffix
            .checked_add(1)
            .expect("fixture completion IDs fit in one byte");
        let block_id = BlockId::new(block_id);
        if block_id == id.block_id() {
            continue;
        }
        over_capacity.push(DurablePayloadValidationCompletionV0::new(
            PayloadValidationRouteV0::Proposal,
            ValidationId::new(block_id, View::new(1), 1),
            DurablePayloadValidationResultV1::Unavailable,
            completed.revision(),
        ));
    }
    over_capacity.sort_by_key(DurablePayloadValidationCompletionV0::key);
    assert_eq!(over_capacity.len(), maximum);
    assert_invalid(
        "completion and obligation capacity",
        decoded_state_with_validation_records(
            &obligated,
            obligated.payload_validation_obligations().to_vec(),
            over_capacity,
        ),
        "durable payload validation records exceed the configured bound",
    );
}

#[test]
fn recovery_rejects_pre_v12_safety_state_without_genesis_application_parent_layout() {
    let (config, core) = configured_core();
    let state = core.safety_state();
    assert_eq!(SAFETY_STATE_SCHEMA_VERSION, 13);
    for legacy_schema in [5, 6, 7, 8, 9, 10, 11] {
        let legacy = SafetyState::from_persisted_parts(
            legacy_schema,
            state.chain_id(),
            state.protocol_version(),
            state.epoch(),
            state.validator_set_id(),
            state.genesis_block_id(),
            state.current_view(),
            state.last_voted_view(),
            state.last_timeout_view(),
            state.high_qc().clone(),
            state.locked_qc().clone(),
            state.finalized(),
            state.revision(),
            state.payload_terminal_facts().to_vec(),
            vec![],
            vec![],
            state.pending_tc_high_qc_sync().cloned(),
            state.pending_standalone_qc_sync().cloned(),
            state.pending_sign().cloned(),
            state.last_finalization().cloned(),
            state.pending_finalize(),
            state.safety_halt().cloned(),
        );
        assert_eq!(
            Core::validate_persisted_state_v0(&config, &legacy, &RootSignatures),
            Err(CoreError::InvalidRecovery(
                "unsupported safety-state schema version"
            )),
            "schema {legacy_schema} must not validate as a current inert record"
        );
        assert_eq!(
            Core::recover(config.clone(), legacy, &RootSignatures),
            Err(CoreError::InvalidRecovery(
                "unsupported safety-state schema version"
            )),
            "schema {legacy_schema} must not be implicitly migrated"
        );
    }
}

#[test]
fn recovery_requires_a_locked_anchor_that_is_not_on_the_high_qc_branch() {
    let (config, bootstrap) = configured_core();
    let set = bootstrap.config().validator_set().clone();
    let locked_proposal = proposal(&set, genesis_qc(&set), 1, b"locked branch");
    let locked_qc = qc(&set, 1, 1, locked_proposal.block().id());
    let high_proposal = timeout_proposal(
        &set,
        timeout_certificate(&set, 1, genesis_qc(&set)),
        b"high branch",
    );
    let high_qc = qc(&set, 2, 1, high_proposal.block().id());
    let genesis = bootstrap.safety_state();
    let recovered_state = SafetyState::from_persisted_parts(
        SAFETY_STATE_SCHEMA_VERSION,
        genesis.chain_id(),
        genesis.protocol_version(),
        genesis.epoch(),
        genesis.validator_set_id(),
        genesis.genesis_block_id(),
        View::new(3),
        None,
        None,
        high_qc.into_qc_reference(),
        locked_qc.into_qc_reference(),
        genesis.finalized(),
        genesis.revision(),
        Vec::new(),
        vec![],
        vec![],
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let mut recovered = Core::recover(config, recovered_state, &RootSignatures)
        .expect("forked durable anchors are replayed fail-closed");

    replay_valid(&mut recovered, high_proposal);
    assert!(matches!(
        recovered.step(Input::SafetyReplayComplete, &RootSignatures),
        Err(CoreError::InvalidRecovery(_))
    ));
    replay_valid(&mut recovered, locked_proposal);
    assert!(matches!(
        recovered
            .step(Input::SafetyReplayComplete, &RootSignatures)
            .expect("both durable branches were replayed")
            .as_slice(),
        [Effect::ArmViewTimer { .. }]
    ));
}

#[test]
fn synced_proposal_installs_validated_ancestry_without_voting_or_advancing_view() {
    let (config, bootstrap) = configured_core();
    let set = bootstrap.config().validator_set().clone();
    let synced = proposal(&set, genesis_qc(&set), 1, b"synced only");
    let high_qc = qc(&set, 1, 1, synced.block().id());
    let genesis = bootstrap.safety_state();
    let recovered_state = SafetyState::from_persisted_parts(
        SAFETY_STATE_SCHEMA_VERSION,
        genesis.chain_id(),
        genesis.protocol_version(),
        genesis.epoch(),
        genesis.validator_set_id(),
        genesis.genesis_block_id(),
        View::new(2),
        None,
        None,
        high_qc.into_qc_reference(),
        genesis.locked_qc().clone(),
        genesis.finalized(),
        genesis.revision(),
        Vec::new(),
        vec![],
        vec![],
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let mut recovered =
        Core::recover(config, recovered_state, &RootSignatures).expect("replay is required");

    let effects = recovered
        .step(Input::SyncedProposal(Box::new(synced)), &RootSignatures)
        .expect("synced proposal accepted");
    let (barrier, persisted) = persistence_effect(&effects);
    assert_eq!(persisted.current_view(), View::new(2));
    assert_eq!(persisted.last_voted_view(), None);
    assert!(persisted.pending_sign().is_none());
    let effects = recovered
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("sync validation request is durable");
    let id = match effects.as_slice() {
        [Effect::ValidateSyncedPayload(request)] => request.id(),
        _ => panic!("expected only synced validation, got {effects:?}"),
    };
    let result = valid_result_for_effect(&recovered, &effects, id);
    let effects = recovered
        .step(
            Input::SyncedPayloadValidated { id, result },
            &RootSignatures,
        )
        .expect("synced payload installed");
    assert!(release_persisted_effects(&mut recovered, effects).is_empty());
    assert_eq!(recovered.safety_state().current_view(), View::new(2));
    assert_eq!(recovered.safety_state().last_voted_view(), None);
    assert!(recovered.safety_state().pending_sign().is_none());
}

#[test]
fn recovery_rejects_network_qc_and_tc_until_replay_completes() {
    let (config, bootstrap) = configured_core();
    let set = bootstrap.config().validator_set().clone();
    let proposal = proposal(&set, genesis_qc(&set), 1, b"durable high anchor");
    let high_qc = qc(&set, 1, 1, proposal.block().id());
    let genesis = bootstrap.safety_state();
    let recovered_state = SafetyState::from_persisted_parts(
        SAFETY_STATE_SCHEMA_VERSION,
        genesis.chain_id(),
        genesis.protocol_version(),
        genesis.epoch(),
        genesis.validator_set_id(),
        genesis.genesis_block_id(),
        View::new(2),
        None,
        None,
        high_qc.clone().into_qc_reference(),
        genesis.locked_qc().clone(),
        genesis.finalized(),
        genesis.revision(),
        Vec::new(),
        vec![],
        vec![],
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let mut recovered =
        Core::recover(config, recovered_state, &RootSignatures).expect("replay is required");
    let before = recovered.safety_state().clone();

    assert!(matches!(
        recovered.step(Input::QuorumCertificate(high_qc.clone()), &RootSignatures,),
        Err(CoreError::Busy(_))
    ));
    assert_eq!(recovered.safety_state(), &before);

    let tc = timeout_certificate(&set, before.current_view().get(), high_qc);
    assert!(matches!(
        recovered.step(Input::TimeoutCertificate(tc), &RootSignatures),
        Err(CoreError::Busy(_))
    ));
    assert_eq!(recovered.safety_state(), &before);
}

#[test]
fn replay_completion_requires_a_live_fence_and_is_transactional() {
    let (_config, mut core) = configured_core();
    let before = core.safety_state().clone();

    assert!(matches!(
        core.step(Input::SafetyReplayComplete, &RootSignatures),
        Err(CoreError::InvalidRecovery(_))
    ));
    assert_eq!(core.safety_state(), &before);
}

#[test]
fn recovery_replays_stale_verified_headers_before_resuming_finality() {
    let (config, mut original) = configured_core();
    let set = original.config().validator_set().clone();
    let genesis = genesis_qc(&set);

    let p1 = proposal(&set, genesis, 1, b"one");
    let committed_id = p1.block().id();
    let q1 = qc(&set, 1, 1, committed_id);
    insert_valid_and_vote(&mut original, p1.clone());
    accept_qc(&mut original, q1.clone());

    let p2 = proposal(&set, q1.clone(), 2, b"two");
    let q2 = qc(&set, 2, 2, p2.block().id());
    insert_valid_and_vote(&mut original, p2.clone());
    let effects = original
        .step(Input::QuorumCertificate(q2.clone()), &RootSignatures)
        .expect("second QC accepted");
    let (_barrier, persisted) = persistence_effect(&effects);

    let mut recovered =
        Core::recover(config.clone(), persisted, &RootSignatures).expect("recover safety state");
    let effects = recovered
        .step(Input::Resume, &RootSignatures)
        .expect("request recovery replay");
    let replay_request = effects
        .iter()
        .find_map(|effect| match effect {
            Effect::RequestSafetyReplay {
                finalized,
                high_qc,
                locked_qc,
            } => Some((*finalized, *high_qc, *locked_qc)),
            _ => None,
        })
        .expect("recovery names every durable safety anchor");
    assert_eq!(replay_request.0, recovered.safety_state().finalized());
    assert_eq!(
        replay_request.1,
        recovered.safety_state().high_qc().qc_ref()
    );
    assert_eq!(
        replay_request.2,
        recovered.safety_state().locked_qc().qc_ref()
    );
    assert!(matches!(
        recovered.step(Input::SafetyReplayComplete, &RootSignatures),
        Err(CoreError::InvalidRecovery(_))
    ));
    assert_eq!(
        recovered.step(Input::SyncedProposal(Box::new(p2.clone())), &RootSignatures,),
        Err(CoreError::MissingBlock(p2.block().header().parent_id()))
    );
    replay_valid(&mut recovered, p1);
    assert!(matches!(
        recovered.step(Input::SafetyReplayComplete, &RootSignatures),
        Err(CoreError::InvalidRecovery(_))
    ));
    replay_valid(&mut recovered, p2.clone());
    assert!(matches!(
        recovered
            .step(Input::SafetyReplayComplete, &RootSignatures)
            .expect("verified replay completed")
            .as_slice(),
        [Effect::ArmViewTimer { .. }]
    ));

    let p3 = proposal(&set, q2.clone(), 3, b"three");
    let q3 = qc(&set, 3, 3, p3.block().id());
    insert_valid_and_vote(&mut recovered, p3.clone());
    let effects = recovered
        .step(Input::QuorumCertificate(q3), &RootSignatures)
        .expect("third QC accepted after replay");
    let (_barrier, state) = persistence_effect(&effects);
    assert_eq!(state.finalized().block_id(), committed_id);
    let proof_id = state.pending_finalize().expect("durable commit outbox");

    let conflicting_high = persisted_state_with_qcs(
        &state,
        qc(&set, 3, 3, BlockId::new([0xA3; 32])),
        state.locked_qc().clone(),
    );
    assert!(matches!(
        Core::recover(config.clone(), conflicting_high, &RootSignatures),
        Err(CoreError::InvalidRecovery(_))
    ));
    let rolled_back_lock = persisted_state_with_qcs(&state, state.high_qc().clone(), q1.clone());
    assert!(matches!(
        Core::recover(config.clone(), rolled_back_lock, &RootSignatures),
        Err(CoreError::InvalidRecovery(_))
    ));

    let mut restarted = Core::recover(config.clone(), state, &RootSignatures)
        .expect("recover durable commit outbox");
    let restarted_finalization_authority = finalization_apply_authority_for_test(&restarted);
    assert!(matches!(
        restarted
            .step(Input::Resume, &RootSignatures)
            .expect("reissue finalization")
            .as_slice(),
        [Effect::Finalize(_)]
    ));
    let effects = apply_finalization_for_test(&mut restarted, &restarted_finalization_authority)
        .expect("application commit acknowledged");
    let (barrier, cleared) = persistence_effect(&effects);
    assert!(cleared.pending_finalize().is_none());
    assert_eq!(
        cleared
            .last_finalization_proof()
            .expect("finalization proof remains permanently bound")
            .id(),
        proof_id
    );
    assert!(restarted
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("outbox clear durable")
        .is_empty());
    let mut recovered_after_ack = Core::recover(config, cleared, &RootSignatures)
        .expect("permanent proof authenticates the finalized tip after outbox acknowledgement");
    assert!(recovered_after_ack
        .step(Input::Resume, &RootSignatures)
        .expect("recovery proceeds from the permanently proven tip")
        .iter()
        .any(|effect| matches!(effect, Effect::RequestSafetyReplay { .. })));
    replay_valid(&mut recovered_after_ack, p2);
    replay_valid(&mut recovered_after_ack, p3);
    assert!(matches!(
        recovered_after_ack
            .step(Input::SafetyReplayComplete, &RootSignatures)
            .expect("post-finality safety replay completes")
            .as_slice(),
        [Effect::ArmViewTimer { .. }]
    ));
    let before_duplicate = recovered_after_ack.safety_state().clone();
    assert!(recovered_after_ack
        .step(Input::QuorumCertificate(q2), &RootSignatures)
        .expect("duplicate q2 is idempotent after restart")
        .is_empty());
    assert_eq!(recovered_after_ack.safety_state(), &before_duplicate);
}

#[test]
fn recovered_core_treats_tc_qcs_below_finality_as_durably_subsumed() {
    let (config, mut original) = configured_core();
    let finalization_authority = finalization_apply_authority_for_test(&original);
    let set = original.config().validator_set().clone();

    let p1 = proposal(&set, genesis_qc(&set), 1, b"stale tc one");
    let q1 = qc(&set, 1, 1, p1.block().id());
    let p2 = proposal(&set, q1.clone(), 2, b"stale tc two");
    let q2 = qc(&set, 2, 2, p2.block().id());
    let p3 = proposal(&set, q2.clone(), 3, b"stale tc three");
    let q3 = qc(&set, 3, 3, p3.block().id());
    let p4 = proposal(&set, q3.clone(), 4, b"stale tc four");
    let q4 = qc(&set, 4, 4, p4.block().id());

    for (proposal, certificate) in [(p1, q1.clone()), (p2.clone(), q2)] {
        insert_valid_and_vote(&mut original, proposal);
        accept_qc(&mut original, certificate);
    }
    insert_valid_and_vote(&mut original, p3.clone());
    let effects = original
        .step(Input::QuorumCertificate(q3.clone()), &RootSignatures)
        .expect("first finality QC accepted");
    let (barrier, state) = persistence_effect(&effects);
    assert!(state.pending_finalize().is_some());
    original
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("first finality state durable");
    let effects = apply_finalization_for_test(&mut original, &finalization_authority)
        .expect("first finality applied");
    let (barrier, _) = persistence_effect(&effects);
    original
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("first finality acknowledgement durable");

    insert_valid_and_vote(&mut original, p4.clone());
    let effects = original
        .step(Input::QuorumCertificate(q4.clone()), &RootSignatures)
        .expect("second finality QC accepted");
    let (barrier, state) = persistence_effect(&effects);
    assert_eq!(state.finalized().block_id(), p2.block().id());
    assert!(state.pending_finalize().is_some());
    original
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("second finality state durable");
    let effects = apply_finalization_for_test(&mut original, &finalization_authority)
        .expect("second finality applied");
    let (barrier, durable) = persistence_effect(&effects);
    original
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("second finality acknowledgement durable");

    let finalized_chain_root_before_recovery = original.finalized_chain_root_v0();
    let mut recovered =
        Core::recover(config, durable, &RootSignatures).expect("finalized state recovers");
    assert_eq!(
        recovered.finalized_chain_root_v0(),
        finalized_chain_root_before_recovery,
        "the hash-linked finalized-prefix commitment must survive exact SafetyState recovery"
    );
    assert!(recovered
        .step(Input::Resume, &RootSignatures)
        .expect("recovery requests only live safety anchors")
        .iter()
        .any(|effect| matches!(effect, Effect::RequestSafetyReplay { .. })));
    replay_valid(&mut recovered, p3);
    replay_valid(&mut recovered, p4);
    recovered
        .step(Input::SafetyReplayComplete, &RootSignatures)
        .expect("live safety anchors replayed");

    let before = recovered.safety_state().clone();
    assert_eq!(before.finalized().height(), Height::new(2));
    let effects = recovered
        .step(
            Input::TimeoutCertificate(timeout_certificate(&set, before.current_view().get(), q1)),
            &RootSignatures,
        )
        .expect("verified TC reference below finality is already subsumed");
    let (barrier, state) = persistence_effect(&effects);
    assert_eq!(state.current_view(), View::new(6));
    assert_eq!(state.high_qc(), before.high_qc());
    assert_eq!(state.locked_qc(), before.locked_qc());
    assert_eq!(state.finalized(), before.finalized());
    assert!(state.pending_tc_high_qc_sync().is_none());
    let effects = recovered
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("stale-reference TC view is durable");
    assert!(matches!(
        effects.as_slice(),
        [Effect::ArmViewTimer { view, .. }] if *view == View::new(6)
    ));
}

#[test]
fn timeout_certificate_advances_view_but_does_not_lock_or_finalize() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let locked = core.safety_state().locked_qc().clone();
    let finalized = core.safety_state().finalized();
    let tc = timeout_certificate(&set, 1, genesis_qc(&set));

    let effects = core
        .step(Input::TimeoutCertificate(tc), &RootSignatures)
        .expect("verified TC accepted");
    let (barrier, state) = persistence_effect(&effects);
    assert_eq!(state.current_view(), View::new(2));
    assert_eq!(state.locked_qc(), &locked);
    assert_eq!(state.finalized(), finalized);
    let effects = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("TC state durable");
    assert!(!effects
        .iter()
        .any(|effect| matches!(effect, Effect::Finalize(_))));
}

#[test]
fn timeout_certificate_persists_missing_target_and_adopts_after_full_sync() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let parent = proposal(&set, genesis_qc(&set), 1, b"synced TC parent");
    let parent_qc = qc(&set, 1, 1, parent.block().id());
    let target = proposal(&set, parent_qc, 2, b"synced TC target");
    let high_qc = qc(&set, 2, 2, target.block().id());
    let certificate = timeout_certificate(&set, 3, high_qc.clone());

    let effects = core
        .step(
            Input::TimeoutCertificate(certificate.clone()),
            &RootSignatures,
        )
        .expect("verified TC with missing target is retained");
    let (barrier, state) = persistence_effect(&effects);
    let pending = state
        .pending_tc_high_qc_sync()
        .expect("missing selected high QC becomes durable sync target");
    assert_eq!(pending.certificate_id(), certificate.id());
    assert_eq!(pending.selected_high_qc().id(), high_qc.id());
    assert_eq!(state.current_view(), View::new(4));
    assert_ne!(state.high_qc().id(), high_qc.id());

    let effects = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("pending target is durable before requesting sync");
    assert!(effects.iter().any(|effect| matches!(
        effect,
        Effect::ArmViewTimer { view, .. } if *view == View::new(4)
    )));
    assert!(effects.iter().any(|effect| matches!(
        effect,
        Effect::RequestTcHighQcSync {
            certificate_id,
            timed_out_view,
            target: sync_target,
            finalized,
        } if *certificate_id == certificate.id()
            && *timed_out_view == View::new(3)
            && sync_target.qc_digest() == high_qc.id()
            && *finalized == state.finalized()
    )));

    let effects = core
        .step(Input::SyncedProposal(Box::new(parent)), &RootSignatures)
        .expect("parent sync accepted");
    let effects = release_persisted_effects(&mut core, effects);
    let id = synced_validation_effect(&effects);
    let result = valid_result_for_effect(&core, &effects, id);
    let effects = core
        .step(
            Input::SyncedPayloadValidated { id, result },
            &RootSignatures,
        )
        .expect("parent payload validates");
    let effects = release_persisted_effects(&mut core, effects);
    assert!(matches!(
        effects.as_slice(),
        [Effect::RequestTcHighQcSync { target, .. }]
            if target.qc_digest() == high_qc.id()
    ));

    let effects = core
        .step(Input::SyncedProposal(Box::new(target)), &RootSignatures)
        .expect("selected high-QC proposal sync accepted");
    let effects = release_persisted_effects(&mut core, effects);
    let id = synced_validation_effect(&effects);
    let result = valid_result_for_effect(&core, &effects, id);
    let effects = core
        .step(
            Input::SyncedPayloadValidated { id, result },
            &RootSignatures,
        )
        .expect("selected high-QC payload completes sync");
    let (barrier, state) = persistence_effect(&effects);
    assert_eq!(state.high_qc().id(), high_qc.id());
    assert_eq!(state.current_view(), View::new(4));
    assert!(state.pending_tc_high_qc_sync().is_none());
    assert!(matches!(
        core.step(Input::StorageAck { barrier }, &RootSignatures)
            .expect("adopted TC target is durable")
            .as_slice(),
        [Effect::ArmViewTimer { view, .. }] if *view == View::new(4)
    ));
}

#[test]
fn unavailable_tc_target_retries_then_invalid_halts_with_the_full_tc() {
    let (config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let parent = proposal(&set, genesis_qc(&set), 1, b"TC retry parent");
    let parent_qc = qc(&set, 1, 1, parent.block().id());
    let target = proposal(&set, parent_qc, 2, b"TC retry target");
    let target_qc = qc(&set, 2, 2, target.block().id());
    let certificate = timeout_certificate(&set, 3, target_qc.clone());

    let effects = core
        .step(
            Input::TimeoutCertificate(certificate.clone()),
            &RootSignatures,
        )
        .expect("missing TC target is retained");
    let (barrier, pending) = persistence_effect(&effects);
    assert_eq!(pending.current_view(), View::new(4));
    assert!(pending.pending_tc_high_qc_sync().is_some());
    core.step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("TC target is durable before sync");

    let effects = core
        .step(Input::SyncedProposal(Box::new(parent)), &RootSignatures)
        .expect("TC parent sync accepted");
    let effects = release_persisted_effects(&mut core, effects);
    let parent_id = synced_validation_effect(&effects);
    let parent_result = valid_result_for_effect(&core, &effects, parent_id);
    let effects = core
        .step(
            Input::SyncedPayloadValidated {
                id: parent_id,
                result: parent_result,
            },
            &RootSignatures,
        )
        .expect("parent validates");
    let effects = release_persisted_effects(&mut core, effects);
    assert!(matches!(
        effects.as_slice(),
        [Effect::RequestTcHighQcSync { .. }]
    ));

    let effects = core
        .step(
            Input::SyncedProposal(Box::new(target.clone())),
            &RootSignatures,
        )
        .expect("TC target sync accepted");
    let effects = release_persisted_effects(&mut core, effects);
    let unavailable_id = synced_validation_effect(&effects);
    let effects = core
        .step(
            Input::SyncedPayloadValidated {
                id: unavailable_id,
                result: PayloadValidationResult::Unavailable,
            },
            &RootSignatures,
        )
        .expect("source failure keeps the exact TC obligation");
    let (barrier, retriable) = persistence_effect(&effects);
    assert!(retriable.payload_validation_obligations().is_empty());
    let unavailable_completion = retriable
        .payload_validation_completions()
        .iter()
        .find(|completion| completion.id() == unavailable_id)
        .expect("synced Unavailable retains its exact durable completion");
    assert_eq!(
        unavailable_completion.route(),
        PayloadValidationRouteV0::Synced
    );
    assert_eq!(unavailable_completion.id(), unavailable_id);
    assert_eq!(
        unavailable_completion.result(),
        DurablePayloadValidationResultV1::Unavailable
    );
    assert_eq!(
        unavailable_completion.first_recorded_revision(),
        retriable.revision()
    );
    assert_eq!(
        retriable
            .pending_tc_high_qc_sync()
            .expect("TC obligation survives Unavailable")
            .certificate_id(),
        certificate.id()
    );
    assert_safety_state_record_roundtrip_and_validate(&config, &retriable);
    assert!(matches!(
        core.step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("source cleanup is durable before retrying the TC target")
        .as_slice(),
        [Effect::RequestTcHighQcSync {
            certificate_id,
            timed_out_view,
            target,
            ..
        }] if *certificate_id == certificate.id()
            && *timed_out_view == View::new(3)
            && target.qc_digest() == target_qc.id()
    ));
    assert!(core
        .step(
            Input::SyncedPayloadValidated {
                id: unavailable_id,
                result: PayloadValidationResult::Unavailable,
            },
            &RootSignatures,
        )
        .expect("duplicate unavailable completion is idempotent")
        .is_empty());
    assert_eq!(core.safety_state().current_view(), View::new(4));
    assert_eq!(
        core.safety_state()
            .pending_tc_high_qc_sync()
            .expect("TC obligation survives Unavailable")
            .certificate_id(),
        certificate.id()
    );

    let effects = core
        .step(Input::SyncedProposal(Box::new(target)), &RootSignatures)
        .expect("another source receives a fresh validation generation");
    let effects = release_persisted_effects(&mut core, effects);
    let invalid_id = synced_validation_effect(&effects);
    assert!(invalid_id.generation() > unavailable_id.generation());
    let effects = core
        .step(
            Input::SyncedPayloadValidated {
                id: invalid_id,
                result: PayloadValidationResult::DeterministicallyInvalid,
            },
            &RootSignatures,
        )
        .expect("terminal invalidity collides with the retained TC");
    let (halt_barrier, halted) = persistence_effect(&effects);
    assert_eq!(halted.current_view(), View::new(4));
    assert!(halted.pending_tc_high_qc_sync().is_none());
    assert!(halted.payload_validation_obligations().is_empty());
    match halted.safety_halt().expect("TC collision is durable") {
        SafetyHalt::DeterministicallyInvalidPayload {
            block_id,
            reference: InvalidPayloadReference::TimeoutCertificate(witness),
        } => {
            assert_eq!(*block_id, target_qc.block_id());
            assert_eq!(witness.id(), certificate.id());
        }
        other => panic!("unexpected TC payload halt: {other:?}"),
    }
    assert_safety_state_record_roundtrip_and_validate(&config, &halted);
    assert!(matches!(
        core.step(
            Input::StorageAck {
                barrier: halt_barrier,
            },
            &RootSignatures,
        )
        .expect("TC invalid halt persisted before notification")
        .as_slice(),
        [Effect::SafetyHalted(_)]
    ));

    let mut recovered =
        Core::recover(config, halted, &RootSignatures).expect("TC payload halt recovers");
    assert!(matches!(
        recovered
            .step(Input::Resume, &RootSignatures)
            .expect("recovery reissues the same fail-stop")
            .as_slice(),
        [Effect::SafetyHalted(_)]
    ));
}

#[test]
fn proposal_carried_tc_preserves_view_and_full_witness_on_invalid_collision() {
    let (_config, mut base) = configured_core();
    let set = base.config().validator_set().clone();
    let target = proposal(&set, genesis_qc(&set), 1, b"invalid TC parent");
    let target_qc = qc(&set, 1, 1, target.block().id());
    let certificate = timeout_certificate(&set, 2, target_qc);
    let child = timeout_proposal(&set, certificate.clone(), b"TC carrier child");

    let effects = base
        .step(Input::Proposal(Box::new(target)), &RootSignatures)
        .expect("target proposal accepted");
    let effects = release_persisted_effects(&mut base, effects);
    let id = validation_effect(&effects);
    let effects = base
        .step(
            Input::PayloadValidated {
                id,
                result: PayloadValidationResult::DeterministicallyInvalid,
            },
            &RootSignatures,
        )
        .expect("uncertified invalid target is cached");
    assert!(release_persisted_effects(&mut base, effects).is_empty());

    let mut ordinary = base.clone();
    let ordinary_effects = ordinary
        .step(Input::Proposal(Box::new(child.clone())), &RootSignatures)
        .expect("ordinary proposal detects its TC collision");
    let (_barrier, ordinary_state) = persistence_effect(&ordinary_effects);

    let mut synced = base;
    let synced_effects = synced
        .step(Input::SyncedProposal(Box::new(child)), &RootSignatures)
        .expect("synced proposal detects the same TC collision");
    let (_barrier, synced_state) = persistence_effect(&synced_effects);
    assert_eq!(ordinary_state, synced_state);
    assert_eq!(ordinary_state.current_view(), View::new(3));
    match ordinary_state
        .safety_halt()
        .expect("TC carrier collision is durable")
    {
        SafetyHalt::DeterministicallyInvalidPayload {
            block_id,
            reference: InvalidPayloadReference::TimeoutCertificate(witness),
        } => {
            assert_eq!(*block_id, id.block_id());
            assert_eq!(witness.id(), certificate.id());
        }
        other => panic!("unexpected carried-TC halt: {other:?}"),
    }
}

#[test]
fn pending_tc_timeout_outbox_survives_a_crash_and_resumes_exactly() {
    let (config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(&set, genesis_qc(&set), 1, b"pending timeout target");
    let target_qc = qc(&set, 1, 1, proposed.block().id());
    let certificate = timeout_certificate(&set, 2, target_qc);

    let effects = core
        .step(Input::TimeoutCertificate(certificate), &RootSignatures)
        .expect("missing TC target is staged");
    let (_barrier, pending_state) = persistence_effect(&effects);
    assert_eq!(pending_state.current_view(), View::new(3));
    assert!(pending_state.pending_tc_high_qc_sync().is_some());

    let mut recovered = Core::recover(config.clone(), pending_state, &RootSignatures)
        .expect("pending TC state recovers");
    let effects = recovered
        .step(
            Input::LocalTimeout {
                epoch: Epoch::new(0),
                view: View::new(3),
            },
            &RootSignatures,
        )
        .expect("pending sync permits a timeout for the advanced view");
    let (_barrier, timeout_state) = persistence_effect(&effects);
    assert_eq!(timeout_state.last_timeout_view(), Some(View::new(3)));
    assert!(matches!(
        timeout_state.pending_sign(),
        Some(SignIntent::TimeoutVote { view, .. }) if *view == View::new(3)
    ));
    assert!(timeout_state.pending_tc_high_qc_sync().is_some());
    assert_safety_state_record_roundtrip_and_validate(&config, &timeout_state);

    let mut after_crash = Core::recover(config, timeout_state, &RootSignatures)
        .expect("pending TC plus timeout outbox recovers");
    let request = after_crash
        .step(Input::Resume, &RootSignatures)
        .expect("the exact timeout signature is re-requested");
    let (sign_id, root) = signature_request(&request);
    let effects = after_crash
        .step(
            Input::SignatureReady {
                id: sign_id,
                signature: signature(root),
            },
            &RootSignatures,
        )
        .expect("recovered timeout signature is accepted");
    assert!(effects.iter().any(|effect| matches!(
        effect,
        Effect::Broadcast(OutboundMessage::TimeoutVote(vote))
            if vote.view() == View::new(3)
    )));
    assert!(effects
        .iter()
        .any(|effect| matches!(effect, Effect::RequestTcHighQcSync { .. })));
    let effects = after_crash
        .step(Input::Resume, &RootSignatures)
        .expect("timer and sync resume after broadcasting the timeout");
    assert!(effects.iter().any(
        |effect| matches!(effect, Effect::ArmViewTimer { view, .. } if *view == View::new(3))
    ));
    assert!(effects
        .iter()
        .any(|effect| matches!(effect, Effect::RequestTcHighQcSync { .. })));
}

#[test]
fn missing_lower_tc_qc_advances_view_without_regressing_local_high_qc() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();

    let local_parent = proposal(&set, genesis_qc(&set), 1, b"local high parent");
    let local_parent_qc = qc(&set, 1, 1, local_parent.block().id());
    insert_valid_and_vote(&mut core, local_parent);
    accept_qc(&mut core, local_parent_qc.clone());
    let local_high_block = timeout_proposal(
        &set,
        timeout_certificate(&set, 9, local_parent_qc),
        b"local higher QC",
    );
    let local_high_qc = qc(&set, 10, 2, local_high_block.block().id());
    insert_valid_and_vote(&mut core, local_high_block);
    accept_qc(&mut core, local_high_qc.clone());
    assert_eq!(core.safety_state().current_view(), View::new(11));

    let missing_parent = timeout_proposal(
        &set,
        timeout_certificate(&set, 7, genesis_qc(&set)),
        b"missing lower parent",
    );
    let missing_parent_qc = qc(&set, 8, 1, missing_parent.block().id());
    let missing_block = proposal(&set, missing_parent_qc, 9, b"missing lower TC reference");
    let missing_lower_qc = qc(&set, 9, 2, missing_block.block().id());
    let effects = core
        .step(
            Input::TimeoutCertificate(timeout_certificate(&set, 11, missing_lower_qc)),
            &RootSignatures,
        )
        .expect("lower missing QC is retained for lock processing");
    let (_barrier, pending) = persistence_effect(&effects);
    assert_eq!(pending.current_view(), View::new(12));
    assert_eq!(pending.high_qc().id(), local_high_qc.id());
    assert!(pending.pending_tc_high_qc_sync().is_some());
}

#[test]
fn tc_processes_every_referenced_qc_before_clearing_pending_state() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();

    let low_parent = proposal(&set, genesis_qc(&set), 1, b"low parent");
    let low_parent_qc = qc(&set, 1, 1, low_parent.block().id());
    replay_valid(&mut core, low_parent.clone());

    let high_lock_parent = timeout_proposal(
        &set,
        timeout_certificate(&set, 7, genesis_qc(&set)),
        b"high lock parent",
    );
    let high_lock_parent_qc = qc(&set, 8, 1, high_lock_parent.block().id());
    replay_valid(&mut core, high_lock_parent.clone());
    let lower_referenced = proposal(
        &set,
        high_lock_parent_qc.clone(),
        9,
        b"lower referenced QC block",
    );
    let lower_qc = qc(&set, 9, 2, lower_referenced.block().id());
    replay_valid(&mut core, lower_referenced);

    let selected_block = timeout_proposal(
        &set,
        timeout_certificate(&set, 9, low_parent_qc),
        b"selected lower-lock branch",
    );
    let selected_qc = qc(&set, 10, 2, selected_block.block().id());
    replay_valid(&mut core, selected_block);

    let certificate = timeout_certificate_with_two_qcs(&set, 11, lower_qc, selected_qc.clone());
    let effects = core
        .step(Input::TimeoutCertificate(certificate), &RootSignatures)
        .expect("all ready TC references are processed atomically");
    let (_barrier, state) = persistence_effect(&effects);
    assert_eq!(state.high_qc().id(), selected_qc.id());
    assert_eq!(state.locked_qc().id(), high_lock_parent_qc.id());
    assert_eq!(state.current_view(), View::new(12));
    assert!(state.pending_tc_high_qc_sync().is_none());
}

#[test]
fn pending_multi_ref_tc_rechecks_subsumption_after_lower_qc_finality_and_recovers() {
    let (config, mut uninterrupted) = configured_core();
    let set = uninterrupted.config().validator_set().clone();

    let p1 = proposal(&set, genesis_qc(&set), 1, b"dynamic subsumption one");
    let q1 = qc(&set, 1, 1, p1.block().id());
    insert_valid_and_vote(&mut uninterrupted, p1.clone());
    accept_qc(&mut uninterrupted, q1.clone());

    let p2 = proposal(&set, q1.clone(), 2, b"dynamic subsumption two");
    let q2 = qc(&set, 2, 2, p2.block().id());
    insert_valid_and_vote(&mut uninterrupted, p2.clone());
    accept_qc(&mut uninterrupted, q2.clone());

    // q3 is the lower-view TC reference. Once its missing body validates, its
    // three-chain finality moves the durable tip to p1 at height one.
    let p3 = proposal(&set, q2.clone(), 3, b"dynamic subsumption three");
    let q3 = qc(&set, 3, 3, p3.block().id());
    // The selected higher-view QC is unavailable and competes with p1 at the
    // height q3 will finalize. It must be fetched before that transition, but
    // is durably subsumed immediately afterwards.
    let selected_stale = qc(&set, 7, 1, BlockId::new([0xD7; 32]));
    let tc = timeout_certificate_with_two_qcs(&set, 8, q3.clone(), selected_stale.clone());

    let effects = uninterrupted
        .step(Input::TimeoutCertificate(tc.clone()), &RootSignatures)
        .expect("the complete multi-reference TC becomes durable");
    let (pending_barrier, pending_state) = persistence_effect(&effects);
    assert_eq!(pending_state.current_view(), View::new(9));
    assert_eq!(pending_state.high_qc().id(), q2.id());
    assert_eq!(pending_state.finalized().height(), Height::new(0));
    let pending = pending_state
        .pending_tc_high_qc_sync()
        .expect("the complete TC is retained while q3 is missing");
    assert_eq!(pending.timeout_certificate(), &tc);
    assert_eq!(pending.selected_high_qc().id(), selected_stale.id());

    let effects = uninterrupted
        .step(
            Input::StorageAck {
                barrier: pending_barrier,
            },
            &RootSignatures,
        )
        .expect("the pending TC is acknowledged before sync starts");
    assert!(matches!(
        effects.as_slice(),
        [
            Effect::ArmViewTimer { view, .. },
            Effect::RequestTcHighQcSync {
                certificate_id,
                target,
                ..
            }
        ] if *view == View::new(9)
            && *certificate_id == tc.id()
            && target.qc_digest() == q3.id()
    ));

    let sync_and_validate_q3 = |core: &mut Core, proposal: SignedProposalV0| {
        let effects = core
            .step(Input::SyncedProposal(Box::new(proposal)), &RootSignatures)
            .expect("the exact lower-view TC target is accepted");
        let effects = release_persisted_effects(core, effects);
        let id = synced_validation_effect(&effects);
        let result = valid_result_for_effect(core, &effects, id);
        core.step(
            Input::SyncedPayloadValidated { id, result },
            &RootSignatures,
        )
        .expect("the lower-view TC target becomes ready")
    };
    let assert_completed = |state: &SafetyState| {
        assert_eq!(state.current_view(), View::new(9));
        assert_eq!(state.high_qc().id(), q3.id());
        assert_eq!(state.locked_qc().id(), q2.id());
        assert_eq!(state.finalized().height(), Height::new(1));
        assert_eq!(state.finalized().block_id(), p1.block().id());
        assert!(state.pending_tc_high_qc_sync().is_none());
        assert!(state.pending_standalone_qc_sync().is_none());
        assert!(state.safety_halt().is_none());
        let proof_id = state
            .pending_finalize()
            .expect("q3 finality and TC clearing share one durable state");
        let proof = state
            .last_finalization_proof()
            .expect("the exact q3 three-chain proof is retained");
        assert_eq!(proof.id(), proof_id);
        assert_eq!(proof.finalized_block().header().id(), p1.block().id());
        assert_eq!(proof.child().header().id(), p2.block().id());
        assert_eq!(proof.grandchild().header().id(), p3.block().id());
        proof_id
    };

    let effects = sync_and_validate_q3(&mut uninterrupted, p3.clone());
    let (completed_barrier, completed_state) = persistence_effect(&effects);
    let proof_id = assert_completed(&completed_state);
    assert_ne!(completed_state.high_qc().id(), selected_stale.id());

    // A crash from the original pending state must replay the durable safety
    // anchors first, then reissue q3 rather than the selected stale branch.
    let mut recovered_pending = Core::recover(config.clone(), pending_state, &RootSignatures)
        .expect("the full pending TC survives a crash");
    assert!(matches!(
        recovered_pending
            .step(Input::Resume, &RootSignatures)
            .expect("durable anchors replay before pending TC sync")
            .as_slice(),
        [Effect::RequestSafetyReplay {
            high_qc,
            locked_qc,
            ..
        }] if high_qc.qc_digest() == q2.id() && locked_qc.qc_digest() == q1.id()
    ));
    replay_valid(&mut recovered_pending, p1.clone());
    replay_valid(&mut recovered_pending, p2.clone());
    assert!(matches!(
        recovered_pending
            .step(Input::SafetyReplayComplete, &RootSignatures)
            .expect("replayed anchors release the exact lower-view dependency")
            .as_slice(),
        [Effect::RequestTcHighQcSync {
            certificate_id,
            target,
            ..
        }] if *certificate_id == tc.id() && target.qc_digest() == q3.id()
    ));
    let effects = sync_and_validate_q3(&mut recovered_pending, p3.clone());
    let (_recovered_barrier, recovered_state) = persistence_effect(&effects);
    let recovered_proof_id = assert_completed(&recovered_state);
    assert_eq!(recovered_proof_id, proof_id);
    assert_ne!(recovered_state.high_qc().id(), selected_stale.id());

    // A crash after the atomic state write but before its acknowledgement
    // replays only the exact finality outbox; the cleared TC never resurrects.
    assert_eq!(
        Core::recover(config, completed_state.clone(), &RootSignatures),
        Err(CoreError::InvalidRecovery(
            "a current NativeValid completion requires its dedicated cross-store recovery session"
        ))
    );
    assert!(completed_state.pending_tc_high_qc_sync().is_none());
    assert_eq!(completed_state.pending_finalize(), Some(proof_id));

    let released = uninterrupted
        .step(
            Input::StorageAck {
                barrier: completed_barrier,
            },
            &RootSignatures,
        )
        .expect("the atomic TC/finality state is acknowledged");
    assert!(released.iter().any(|effect| matches!(
        effect,
        Effect::Finalize(proof) if proof.id() == proof_id
    )));
    assert!(!released
        .iter()
        .any(|effect| matches!(effect, Effect::RequestTcHighQcSync { .. })));
}

#[test]
fn tc_delivered_qc_finalizes_only_after_the_ready_state_is_persisted() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let p1 = proposal(&set, genesis_qc(&set), 1, b"tc finality one");
    let q1 = qc(&set, 1, 1, p1.block().id());
    let p2 = proposal(&set, q1.clone(), 2, b"tc finality two");
    let q2 = qc(&set, 2, 2, p2.block().id());
    let p3 = proposal(&set, q2, 3, b"tc finality three");
    let q3 = qc(&set, 3, 3, p3.block().id());
    replay_valid(&mut core, p1.clone());
    replay_valid(&mut core, p2);

    let effects = core
        .step(
            Input::TimeoutCertificate(timeout_certificate(&set, 4, q3.clone())),
            &RootSignatures,
        )
        .expect("missing TC-delivered QC is retained");
    let (barrier, pending) = persistence_effect(&effects);
    assert_eq!(pending.current_view(), View::new(5));
    assert!(pending.pending_tc_high_qc_sync().is_some());
    core.step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("pending TC state is durable");

    let effects = core
        .step(Input::SyncedProposal(Box::new(p3)), &RootSignatures)
        .expect("final TC block sync is accepted");
    let effects = release_persisted_effects(&mut core, effects);
    let id = synced_validation_effect(&effects);
    let result = valid_result_for_effect(&core, &effects, id);
    let effects = core
        .step(
            Input::SyncedPayloadValidated { id, result },
            &RootSignatures,
        )
        .expect("ready TC-delivered QC is fully processed");
    let (barrier, finalized) = persistence_effect(&effects);
    assert_eq!(finalized.high_qc().id(), q3.id());
    assert_eq!(finalized.finalized().block_id(), p1.block().id());
    assert!(finalized.pending_tc_high_qc_sync().is_none());
    let proof_id = finalized
        .pending_finalize()
        .expect("finality outbox is durable in the same state");

    let effects = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("finality is emitted only after persistence");
    assert!(effects.iter().any(|effect| matches!(
        effect,
        Effect::Finalize(proof) if proof.id() == proof_id
    )));
}

#[test]
fn already_ready_tc_delivered_qc_runs_the_same_finality_transition() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let p1 = proposal(&set, genesis_qc(&set), 1, b"ready finality one");
    let q1 = qc(&set, 1, 1, p1.block().id());
    let p2 = proposal(&set, q1, 2, b"ready finality two");
    let q2 = qc(&set, 2, 2, p2.block().id());
    let p3 = proposal(&set, q2, 3, b"ready finality three");
    let q3 = qc(&set, 3, 3, p3.block().id());
    replay_valid(&mut core, p1.clone());
    replay_valid(&mut core, p2);
    replay_valid(&mut core, p3);

    let effects = core
        .step(
            Input::TimeoutCertificate(timeout_certificate(&set, 4, q3.clone())),
            &RootSignatures,
        )
        .expect("ready TC-delivered QC is fully processed");
    let (barrier, finalized) = persistence_effect(&effects);
    assert_eq!(finalized.high_qc().id(), q3.id());
    assert_eq!(finalized.finalized().block_id(), p1.block().id());
    assert!(finalized.pending_tc_high_qc_sync().is_none());
    let proof_id = finalized
        .pending_finalize()
        .expect("ready finality outbox is durable");
    let effects = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("ready finality is emitted after persistence");
    assert!(effects.iter().any(|effect| matches!(
        effect,
        Effect::Finalize(proof) if proof.id() == proof_id
    )));
}

#[test]
fn application_finalization_receipt_rejects_empty_live_queue_transactionally() {
    let (mut core, receipt) = pending_finalization_receipt_for_test();
    core.set_finalization_queue_for_test_v0(Vec::new());
    let before = core.clone();

    let rejection = core
        .step_application_finalization_receipt_v0(receipt, &RootSignatures)
        .expect_err("an empty live queue cannot acknowledge a finalization receipt");
    assert_eq!(rejection.error(), &CoreError::UnexpectedFinalizationAck);
    assert_eq!(core, before, "a malformed live ACK is transactional");
    let _receipt = rejection.into_receipt();
}

#[test]
fn application_finalization_receipt_rejects_nonmatching_live_queue_front_transactionally() {
    let (mut core, receipt) = pending_finalization_receipt_for_test();
    let front = core
        .safety_state()
        .finalization_queue()
        .first()
        .expect("the fixture has one pending queue front")
        .clone();
    let mut tampered_checksum = front.target_overlay_ref().overlay_checksum();
    tampered_checksum[0] ^= 1;
    let tampered_front = DurableFinalizationV0::new(
        front.authenticated_parent(),
        front.proof().clone(),
        BlockIdOverlayRefV0::new(
            front.target_overlay_ref().block_id(),
            front.target_overlay_ref().parent_block_id(),
            tampered_checksum,
        ),
    )
    .expect("the test queue front remains shape-valid but differs exactly");
    core.set_finalization_queue_for_test_v0(vec![tampered_front]);
    let before = core.clone();

    let rejection = core
        .step_application_finalization_receipt_v0(receipt, &RootSignatures)
        .expect_err("a receipt must name the exact live queue front");
    assert_eq!(rejection.error(), &CoreError::UnexpectedFinalizationAck);
    assert_eq!(core, before, "a nonmatching live ACK is transactional");
    let _receipt = rejection.into_receipt();
}

#[test]
fn application_finalization_receipt_rechecks_finality_proof_before_commit() {
    let (mut core, receipt) = pending_finalization_receipt_for_test();
    let before = core.clone();

    // The receipt and queue-front coordinates are otherwise exact.  A
    // verifier failure must still stop the callback before the application
    // watermark or queue can advance; the callback path cannot rely solely on
    // the earlier proposal/QC admission that created the outbox.
    let rejection = core
        .step_application_finalization_receipt_v0(receipt, &RejectSignatures)
        .expect_err("finalization callback must re-authenticate its three-chain proof");
    assert!(matches!(rejection.error(), CoreError::Protocol(_)));
    assert_eq!(core, before, "failed proof recheck is transactional");
    let _receipt = rejection.into_receipt();
}

#[test]
fn application_finalization_receipt_rejects_safety_rules_revision_mismatch_transactionally() {
    let (mut core, receipt) = pending_finalization_receipt_for_test();
    // Model a torn Core/Safety handoff after the linear permit was issued:
    // the queue front and proof remain unchanged, but the Safety revision no
    // longer names the predecessor captured by the permit.
    core.advance_safety_revision_for_test_v0()
        .expect("test Safety revision increment");
    let before = core.clone();

    let rejection = core
        .step_application_finalization_receipt_v0(receipt, &RootSignatures)
        .expect_err("a receipt with a stale Core/Safety permit must fail closed");
    assert!(matches!(
        rejection.error(),
        CoreError::SafetyRulesShadowMismatch(
            "finalization receipt lacks an exact authenticated Core/SafetyRules proof join"
        )
    ));
    assert_eq!(core, before, "a SafetyRules join failure is transactional");
    let _receipt = rejection.into_receipt();
}

#[test]
fn one_tc_queues_every_monotonic_finality_step_in_ancestor_order() {
    let (config, mut core) = configured_core();
    let finalization_authority = finalization_apply_authority_for_test(&core);
    assert!(matches!(
        core.issue_application_finalization_apply_authority_v0(),
        Err(CoreError::ApplicationFinalizationApplyAuthorityAlreadyIssued)
    ));
    let set = core.config().validator_set().clone();
    let p1 = proposal(&set, genesis_qc(&set), 1, b"coalesced one");
    let q1 = qc(&set, 1, 1, p1.block().id());
    let p2 = proposal(&set, q1, 2, b"coalesced two");
    let q2 = qc(&set, 2, 2, p2.block().id());
    let p3 = proposal(&set, q2, 3, b"coalesced three");
    let q3 = qc(&set, 3, 3, p3.block().id());
    let p4 = proposal(&set, q3.clone(), 4, b"coalesced four");
    let q4 = qc(&set, 4, 4, p4.block().id());
    for proposal in [p1.clone(), p2.clone(), p3, p4] {
        replay_valid(&mut core, proposal);
    }

    let certificate = timeout_certificate_with_two_qcs(&set, 5, q3, q4.clone());
    let effects = core
        .step(Input::TimeoutCertificate(certificate), &RootSignatures)
        .expect("both ready referenced QCs are processed in monotonic order");
    let (barrier, finalized) = persistence_effect(&effects);
    assert_eq!(finalized.high_qc().id(), q4.id());
    assert_eq!(finalized.finalized().block_id(), p2.block().id());
    assert_eq!(finalized.application_applied().height(), Height::new(0));
    assert_eq!(finalized.finalization_queue().len(), 2);
    assert_eq!(
        finalized.finalization_queue()[0]
            .proof()
            .finalized_block()
            .header()
            .id(),
        p1.block().id()
    );
    assert_eq!(
        finalized.finalization_queue()[0].target_overlay_ref(),
        artifact_ref_for_ids(p1.block().id(), p1.block().header().parent_id()).overlay()
    );
    assert_eq!(
        finalized.finalization_queue()[1]
            .proof()
            .finalized_block()
            .header()
            .id(),
        p2.block().id()
    );
    assert_eq!(
        finalized.finalization_queue()[1].target_overlay_ref(),
        artifact_ref_for_ids(p2.block().id(), p2.block().header().parent_id()).overlay()
    );
    let latest = finalized
        .last_finalization_proof()
        .expect("latest proof permanently covers the new finalized tip");
    assert_eq!(latest.finalized_block().header().id(), p2.block().id());
    let first_proof_id = finalized
        .pending_finalize()
        .expect("the oldest finality outbox is durable");
    assert_eq!(first_proof_id, finalized.finalization_queue()[0].proof_id());

    let mut tampered_checksum = finalized.finalization_queue()[0]
        .target_overlay_ref()
        .overlay_checksum();
    tampered_checksum[0] ^= 1;
    let mut tampered_queue = finalized.finalization_queue().to_vec();
    let original_front = tampered_queue[0].clone();
    tampered_queue[0] = DurableFinalizationV0::new(
        original_front.authenticated_parent(),
        original_front.proof().clone(),
        BlockIdOverlayRefV0::new(
            original_front.target_overlay_ref().block_id(),
            original_front.target_overlay_ref().parent_block_id(),
            tampered_checksum,
        ),
    )
    .expect("shape-valid but terminal-inconsistent overlay fixture");
    let mut tampered_state = finalized.clone();
    tampered_state.set_finalization_queue(tampered_queue);
    let tampered_state = roundtrip_safety_state_record(&config, &tampered_state);
    assert_eq!(
        Core::validate_persisted_state_v0(&config, &tampered_state, &RootSignatures),
        Err(CoreError::InvalidRecovery(
            "application-finalization queue target overlay differs from its terminal Valid fact",
        ))
    );

    let mut exact_capacity_queue = finalized.finalization_queue().to_vec();
    exact_capacity_queue.resize(config.max_blocks(), original_front.clone());
    let mut exact_capacity_state = finalized.clone();
    exact_capacity_state.set_finalization_queue(exact_capacity_queue.clone());
    assert_eq!(
        roundtrip_safety_state_record(&config, &exact_capacity_state),
        exact_capacity_state,
        "the schema-v12 codec admits exactly max_blocks inert queue carriers",
    );
    exact_capacity_queue.push(original_front);
    let mut over_capacity_state = finalized.clone();
    over_capacity_state.set_finalization_queue(exact_capacity_queue);
    let context = SafetyStateRecordContextV0::new(
        &config,
        SAFETY_STATE_RECORD_TEST_PROFILE_REF,
        safety_state_record_test_limits(),
    )
    .expect("capacity-compatible safety-state record context");
    assert_eq!(
        encode_safety_state_record_v0(&over_capacity_state, &context),
        Err(SafetyStateRecordErrorV0::InvalidConsensusValue(
            "application finalization queue",
        )),
        "the codec rejects max_blocks + 1 before emitting an oversized record",
    );
    assert_eq!(
        Core::validate_persisted_state_v0(&config, &over_capacity_state, &RootSignatures),
        Err(CoreError::InvalidRecovery(
            "application-finalization queue exceeds the configured block bound",
        )),
    );

    let persisted = roundtrip_safety_state_record(&config, &finalized);
    let mut recovered = Core::recover(config, persisted, &RootSignatures)
        .expect("the ordered finalization queue recovers");
    assert!(matches!(
        recovered
            .step(Input::Resume, &RootSignatures)
            .expect("restart reissues only the queue front")
            .as_slice(),
        [Effect::Finalize(proof)]
            if proof.id() == first_proof_id
                && proof.finalized_block().header().id() == p1.block().id()
                && proof.target_overlay_ref()
                    == finalized.finalization_queue()[0].target_overlay_ref()
    ));

    let effects = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("the oldest proof is emitted after persistence");
    assert!(matches!(
        effects.as_slice(),
        [
            Effect::ArmViewTimer { epoch, view },
            Effect::Finalize(proof),
        ]
            if *epoch == finalized.epoch()
                && *view == finalized.current_view()
                && proof.id() == first_proof_id
                && proof.finalized_block().header().id() == p1.block().id()
                && proof.target_overlay_ref()
                    == finalized.finalization_queue()[0].target_overlay_ref()
    ));

    // Recovery authenticates the same durable front but creates fresh
    // process-local authority.  Its receipt cannot cross into the original
    // Core and the owner returned by that rejection succeeds unchanged on the
    // recovered Core which minted it.
    let recovered_authority = finalization_apply_authority_for_test(&recovered);
    let recovered_permit = recovered
        .issue_application_finalization_permit_v0()
        .expect("the recovered Core issues its exact pending-front permit");
    let recovered_readback =
        finalization_readback_for_test(&recovered, &recovered_authority, &recovered_permit);
    assert!(!finalization_authority.matches_application_finalization_permit_v0(&recovered_permit));
    let recovered_permit_rejection = finalization_authority
        .receipt_after_application_store_apply_v0(recovered_permit, recovered_readback.clone())
        .expect_err("the original application authority rejects before any foreign store write");
    assert_eq!(
        recovered_permit_rejection.error(),
        &CoreError::ApplicationFinalizationPermitMismatch
    );
    let recovered_permit = recovered_permit_rejection.into_permit();
    assert!(recovered_authority.matches_application_finalization_permit_v0(&recovered_permit));
    let recovered_receipt = recovered_authority
        .receipt_after_application_store_apply_v0(recovered_permit, recovered_readback)
        .expect("the owner returned by prewrite rejection remains usable by its issuing authority");
    let before_recovered_receipt = core.safety_state().clone();
    let rejection = core
        .step_application_finalization_receipt_v0(recovered_receipt, &RootSignatures)
        .expect_err("a recovered Core has a fresh process affinity");
    assert_eq!(
        rejection.error(),
        &CoreError::ApplicationFinalizationReceiptMismatch
    );
    assert_eq!(core.safety_state(), &before_recovered_receipt);
    let recovered_receipt = rejection.into_receipt();
    let recovered_effects = recovered
        .step_application_finalization_receipt_v0(recovered_receipt, &RootSignatures)
        .expect("the exact recovered queue-front owner remains usable on its issuing Core");
    let (_recovered_barrier, recovered_after_first) = persistence_effect(&recovered_effects);
    assert_eq!(
        recovered_after_first.application_applied().block_id(),
        p1.block().id()
    );

    // Even the correct installed application authority cannot turn a permit
    // for a different Core/front into an acknowledgement for this queue.
    let (_foreign_config, mut foreign_core, _foreign_validation, _foreign_result) =
        finalization_gated_validation(b"foreign finalization receipt front");
    let foreign_authority = finalization_apply_authority_for_test(&foreign_core);
    let foreign_permit = foreign_core
        .issue_application_finalization_permit_v0()
        .expect("foreign Core has its own exact pending front");
    let foreign_readback =
        finalization_readback_for_test(&foreign_core, &foreign_authority, &foreign_permit);
    assert_ne!(
        foreign_permit.finalization(),
        core.safety_state()
            .pending_finalization()
            .expect("the original front remains pending")
    );
    assert!(!finalization_authority.matches_application_finalization_permit_v0(&foreign_permit));
    let foreign_permit_rejection = finalization_authority
        .receipt_after_application_store_apply_v0(foreign_permit, foreign_readback.clone())
        .expect_err("a foreign permit is rejected before the receiving store can write");
    assert_eq!(
        foreign_permit_rejection.error(),
        &CoreError::ApplicationFinalizationPermitMismatch
    );
    let foreign_permit = foreign_permit_rejection.into_permit();
    assert!(foreign_authority.matches_application_finalization_permit_v0(&foreign_permit));
    let foreign_receipt = foreign_authority
        .receipt_after_application_store_apply_v0(foreign_permit, foreign_readback)
        .expect("the returned foreign permit remains usable with its issuing authority");
    let before_foreign_front = core.safety_state().clone();
    let rejection = core
        .step_application_finalization_receipt_v0(foreign_receipt, &RootSignatures)
        .expect_err("a different durable queue front cannot be acknowledged");
    assert_eq!(
        rejection.error(),
        &CoreError::ApplicationFinalizationReceiptMismatch
    );
    assert_eq!(core.safety_state(), &before_foreign_front);
    let foreign_receipt = rejection.into_receipt();
    let _foreign_effects = foreign_core
        .step_application_finalization_receipt_v0(foreign_receipt, &RootSignatures)
        .expect("the receipt returned by the original Core remains usable on its foreign issuer");

    // One front issues one permit. A public Core clone has equal protocol
    // state but fresh affinities; its rejection returns the exact sole owner,
    // which then succeeds on the issuing Core.
    let permit = core
        .issue_application_finalization_permit_v0()
        .expect("the original exact queue front issues one permit");
    let readback = finalization_readback_for_test(&core, &finalization_authority, &permit);
    assert!(matches!(
        core.issue_application_finalization_permit_v0(),
        Err(CoreError::ApplicationFinalizationPermitAlreadyIssued)
    ));
    let mut public_clone = core.clone();
    let public_clone_authority = finalization_apply_authority_for_test(&public_clone);
    assert!(!public_clone_authority.matches_application_finalization_permit_v0(&permit));
    let permit_rejection = public_clone_authority
        .receipt_after_application_store_apply_v0(permit, readback.clone())
        .expect_err("a public Core clone rejects the permit before any simulated store write");
    assert_eq!(
        permit_rejection.error(),
        &CoreError::ApplicationFinalizationPermitMismatch
    );
    let permit = permit_rejection.into_permit();
    assert!(finalization_authority.matches_application_finalization_permit_v0(&permit));
    let receipt = finalization_authority
        .receipt_after_application_store_apply_v0(permit, readback)
        .expect("the issuing application authority consumes its returned permit");
    let public_clone_before = public_clone.safety_state().clone();
    let rejection = public_clone
        .step_application_finalization_receipt_v0(receipt, &RootSignatures)
        .expect_err("a public Core clone must receive fresh receipt affinities");
    assert_eq!(
        rejection.error(),
        &CoreError::ApplicationFinalizationReceiptMismatch
    );
    assert_eq!(public_clone.safety_state(), &public_clone_before);
    let receipt = rejection.into_receipt();
    let effects = core
        .step_application_finalization_receipt_v0(receipt, &RootSignatures)
        .expect("the oldest queue entry is acknowledged first");
    let manifest = persistence_request(&effects)
        .native_finalization_applied_v0()
        .expect("the receipt transition carries its exact App readback manifest");
    assert_eq!(manifest.predecessor(), finalized.application_applied());
    assert_eq!(
        manifest.successor().block_id(),
        p1.block().id(),
        "the persisted successor is the exact consumed queue front",
    );
    assert_eq!(
        manifest.post_ack_action_v0(),
        NativeFinalizationAppliedPostAckActionV0::Finalize,
    );
    assert_eq!(
        manifest
            .application_store_readback_v0()
            .source_validation_id()
            .block_id(),
        p1.block().id(),
    );
    assert_eq!(
        manifest
            .application_store_readback_v0()
            .finalization_checksum(),
        native_finalization_applied_checksum_v0(&finalized.finalization_queue()[0])
            .expect("queue front has a canonical checksum"),
    );
    assert_eq!(
        persistence_request(&effects).native_valid_post_ack_action_v0(),
        None,
        "finalization-applied and NativeValid manifests are disjoint",
    );
    let (barrier, after_first) = persistence_effect(&effects);
    assert_eq!(
        after_first.application_applied().block_id(),
        p1.block().id()
    );
    assert_eq!(after_first.finalization_queue().len(), 1);
    assert_eq!(
        after_first.finalization_queue()[0]
            .proof()
            .finalized_block()
            .header()
            .id(),
        p2.block().id()
    );
    let second_proof_id = after_first
        .pending_finalize()
        .expect("the next ancestor becomes the queue front");

    assert!(matches!(
        core.issue_application_finalization_permit_v0(),
        Err(CoreError::Busy(
            "waiting for durable safety-state acknowledgement"
        ))
    ));

    let effects = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("the next ancestor is emitted only after the first ack is durable");
    assert!(matches!(
        effects.as_slice(),
        [Effect::Finalize(proof)]
            if proof.id() == second_proof_id
                && proof.finalized_block().header().id() == p2.block().id()
                && proof.target_overlay_ref()
                    == after_first.finalization_queue()[0].target_overlay_ref()
    ));

    let effects = apply_finalization_for_test(&mut core, &finalization_authority)
        .expect("the second ancestor is acknowledged");
    let (_barrier, drained) = persistence_effect(&effects);
    assert_eq!(drained.application_applied().block_id(), p2.block().id());
    assert!(drained.finalization_queue().is_empty());
    assert!(drained.pending_finalize().is_none());
}

#[test]
fn one_high_qc_reconstructs_every_missing_finalization_from_genesis() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let p1 = proposal(&set, genesis_qc(&set), 1, b"suffix one");
    let q1 = qc(&set, 1, 1, p1.block().id());
    let p2 = proposal(&set, q1, 2, b"suffix two");
    let q2 = qc(&set, 2, 2, p2.block().id());
    let p3 = proposal(&set, q2, 3, b"suffix three");
    let q3 = qc(&set, 3, 3, p3.block().id());
    let p4 = proposal(&set, q3, 4, b"suffix four");
    let q4 = qc(&set, 4, 4, p4.block().id());
    let p5 = proposal(&set, q4, 5, b"suffix five");
    let q5 = qc(&set, 5, 5, p5.block().id());
    let p6 = proposal(&set, q5, 6, b"suffix six");
    let q6 = qc(&set, 6, 6, p6.block().id());
    for proposed in [&p1, &p2, &p3, &p4, &p5, &p6] {
        replay_valid(&mut core, proposed.clone());
    }

    let effects = core
        .step(
            Input::TimeoutCertificate(timeout_certificate(&set, 7, q6.clone())),
            &RootSignatures,
        )
        .expect("one ready high QC reconstructs the complete certified suffix");
    let (_barrier, finalized) = persistence_effect(&effects);
    assert_eq!(finalized.high_qc().id(), q6.id());
    assert_eq!(finalized.application_applied().height(), Height::new(0));
    assert_eq!(finalized.finalized().block_id(), p4.block().id());
    assert_eq!(finalized.finalization_queue().len(), 4);

    let expected = [
        (&p1, GENESIS),
        (&p2, p1.block().id()),
        (&p3, p2.block().id()),
        (&p4, p3.block().id()),
    ];
    for (durable, (proposed, parent_id)) in finalized.finalization_queue().iter().zip(expected) {
        assert_eq!(durable.authenticated_parent().block_id(), parent_id);
        assert_eq!(
            durable.proof().finalized_block().header().id(),
            proposed.block().id()
        );
        assert_eq!(
            durable.target_overlay_ref(),
            artifact_ref_for_ids(proposed.block().id(), parent_id).overlay()
        );
    }
    assert_eq!(
        finalized.pending_finalize(),
        Some(finalized.finalization_queue()[0].proof_id())
    );
    assert_eq!(
        finalized.last_finalization(),
        finalized.finalization_queue().last()
    );
}

#[test]
fn live_suffix_at_the_block_tree_bound_stays_below_the_queue_bound() {
    const MAX_BLOCKS: usize = 6;

    let parameters = consensus_parameters();
    let set = validator_set_with_parameters(&parameters);
    let config = CoreConfig::new(
        validator_id(1),
        set.clone(),
        parameters,
        GENESIS_TIMESTAMP_MS,
        MAX_BLOCKS,
        64,
    )
    .expect("valid exact-capacity config");
    let mut core = Core::new(config, genesis_qc(&set), &RootSignatures)
        .expect("valid exact-capacity bootstrap");
    let p1 = proposal(&set, genesis_qc(&set), 1, b"bounded suffix one");
    let q1 = qc(&set, 1, 1, p1.block().id());
    let p2 = proposal(&set, q1, 2, b"bounded suffix two");
    let q2 = qc(&set, 2, 2, p2.block().id());
    let p3 = proposal(&set, q2, 3, b"bounded suffix three");
    let q3 = qc(&set, 3, 3, p3.block().id());
    let p4 = proposal(&set, q3, 4, b"bounded suffix four");
    let q4 = qc(&set, 4, 4, p4.block().id());
    let p5 = proposal(&set, q4, 5, b"bounded suffix five");
    let q5 = qc(&set, 5, 5, p5.block().id());
    let p6 = proposal(&set, q5, 6, b"bounded suffix six");
    let q6 = qc(&set, 6, 6, p6.block().id());
    for proposed in [&p1, &p2, &p3, &p4, &p5, &p6] {
        replay_valid(&mut core, proposed.clone());
    }

    let effects = core
        .step(
            Input::TimeoutCertificate(timeout_certificate(&set, 7, q6)),
            &RootSignatures,
        )
        .expect("the complete live tree produces its maximal fresh suffix");
    let (_barrier, finalized) = persistence_effect(&effects);
    assert_eq!(finalized.finalization_queue().len(), MAX_BLOCKS - 2);
    assert!(finalized.finalization_queue().len() < MAX_BLOCKS);
}

#[test]
fn persisted_nonempty_finalization_queue_blocks_a_later_suffix_without_changing_its_front() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let p1 = proposal(&set, genesis_qc(&set), 1, b"blocked suffix one");
    let q1 = qc(&set, 1, 1, p1.block().id());
    let p2 = proposal(&set, q1, 2, b"blocked suffix two");
    let q2 = qc(&set, 2, 2, p2.block().id());
    let p3 = proposal(&set, q2, 3, b"blocked suffix three");
    let q3 = qc(&set, 3, 3, p3.block().id());
    let p4 = proposal(&set, q3, 4, b"blocked suffix four");
    let q4 = qc(&set, 4, 4, p4.block().id());
    let p5 = proposal(&set, q4.clone(), 5, b"blocked suffix five");
    let q5 = qc(&set, 5, 5, p5.block().id());
    let p6 = proposal(&set, q5, 6, b"blocked suffix six");
    let q6 = qc(&set, 6, 6, p6.block().id());
    for proposed in [&p1, &p2, &p3, &p4, &p5, &p6] {
        replay_valid(&mut core, proposed.clone());
    }

    let effects = core
        .step(
            Input::TimeoutCertificate(timeout_certificate(&set, 7, q4)),
            &RootSignatures,
        )
        .expect("the first ready suffix is persisted");
    let (barrier, queued) = persistence_effect(&effects);
    assert_eq!(queued.finalization_queue().len(), 2);
    let expected_front = queued.finalization_queue()[0].clone();
    core.step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("the queue front is durably released to the application");

    let before = core.clone();
    assert_eq!(
        core.step(
            Input::TimeoutCertificate(timeout_certificate(&set, 8, q6)),
            &RootSignatures,
        ),
        Err(CoreError::Busy(
            "waiting for application finalization acknowledgement",
        )),
    );
    assert_eq!(core, before);
    assert_eq!(core.safety_state().finalization_queue().len(), 2);
    assert_eq!(core.safety_state().finalization_queue()[0], expected_front);
    assert_eq!(
        core.safety_state().pending_finalize(),
        Some(expected_front.proof_id()),
    );
}

#[test]
fn reconstructed_suffix_uses_exact_block_ids_when_siblings_share_height_and_state_root() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let p1 = proposal(&set, genesis_qc(&set), 1, b"exact sibling parent");
    let q1 = qc(&set, 1, 1, p1.block().id());
    let selected = proposal(&set, q1.clone(), 2, b"selected same-root sibling");
    let sibling = timeout_proposal(
        &set,
        timeout_certificate(&set, 4, q1),
        b"foreign same-root sibling",
    );
    assert_eq!(
        selected.block().header().height(),
        sibling.block().header().height()
    );
    assert_eq!(
        selected.block().header().state_root(),
        sibling.block().header().state_root(),
        "the block fixture intentionally assigns one state root per height",
    );
    assert_ne!(selected.block().id(), sibling.block().id());

    let q2 = qc(&set, 2, 2, selected.block().id());
    let p3 = proposal(&set, q2, 3, b"exact sibling child");
    let q3 = qc(&set, 3, 3, p3.block().id());
    let p4 = proposal(&set, q3, 4, b"exact sibling grandchild");
    let q4 = qc(&set, 4, 4, p4.block().id());
    for proposed in [&p1, &sibling, &selected, &p3, &p4] {
        replay_valid(&mut core, proposed.clone());
    }

    let selected_overlay = artifact_ref_for_ids(selected.block().id(), p1.block().id()).overlay();
    let sibling_overlay = artifact_ref_for_ids(sibling.block().id(), p1.block().id()).overlay();
    assert_eq!(
        core.safety_state()
            .payload_terminal_fact(selected.block().id())
            .and_then(PayloadTerminalFact::valid_overlay),
        Some(selected_overlay),
    );
    assert_eq!(
        core.safety_state()
            .payload_terminal_fact(sibling.block().id())
            .and_then(PayloadTerminalFact::valid_overlay),
        Some(sibling_overlay),
    );
    assert_ne!(selected_overlay, sibling_overlay);

    let effects = core
        .step(
            Input::TimeoutCertificate(timeout_certificate(&set, 5, q4)),
            &RootSignatures,
        )
        .expect("the selected certified branch reconstructs its exact suffix");
    let (_barrier, finalized) = persistence_effect(&effects);
    assert_eq!(finalized.finalization_queue().len(), 2);
    assert_eq!(
        finalized.finalization_queue()[0]
            .proof()
            .finalized_block()
            .header()
            .id(),
        p1.block().id(),
    );
    assert_eq!(
        finalized.finalization_queue()[1]
            .proof()
            .finalized_block()
            .header()
            .id(),
        selected.block().id(),
    );
    assert_eq!(
        finalized.finalization_queue()[1].target_overlay_ref(),
        selected_overlay,
    );
    assert!(finalized.finalization_queue().iter().all(|durable| {
        durable.proof().finalized_block().header().id() != sibling.block().id()
            && durable.target_overlay_ref() != sibling_overlay
    }));
}

#[test]
fn certified_same_root_fork_cannot_append_a_prefix_past_the_applied_tip() {
    let (_config, mut core) = configured_core();
    let finalization_authority = finalization_apply_authority_for_test(&core);
    let set = core.config().validator_set().clone();
    let p1 = proposal(&set, genesis_qc(&set), 1, b"fork common parent");
    let q1 = qc(&set, 1, 1, p1.block().id());

    let applied = proposal(&set, q1.clone(), 2, b"applied same-root branch");
    let applied_q2 = qc(&set, 2, 2, applied.block().id());
    let applied_p3 = proposal(&set, applied_q2, 3, b"applied branch child");
    let applied_q3 = qc(&set, 3, 3, applied_p3.block().id());
    let applied_p4 = proposal(&set, applied_q3, 4, b"applied branch grandchild");
    let applied_q4 = qc(&set, 4, 4, applied_p4.block().id());

    // A higher-view sibling has the same height and state root, but a
    // different BlockId and an entirely different certified continuation.
    let competing = timeout_proposal(
        &set,
        timeout_certificate(&set, 4, q1),
        b"competing same-root branch",
    );
    assert_eq!(
        applied.block().header().height(),
        competing.block().header().height()
    );
    assert_eq!(
        applied.block().header().state_root(),
        competing.block().header().state_root(),
    );
    assert_ne!(applied.block().id(), competing.block().id());
    let competing_q2 = qc(&set, 5, 2, competing.block().id());
    let competing_p3 = proposal(&set, competing_q2, 6, b"competing branch child");
    let competing_q3 = qc(&set, 6, 3, competing_p3.block().id());
    let competing_p4 = proposal(&set, competing_q3, 7, b"competing branch grandchild");
    let competing_q4 = qc(&set, 7, 4, competing_p4.block().id());

    for proposed in [
        &p1,
        &applied,
        &applied_p3,
        &applied_p4,
        &competing,
        &competing_p3,
        &competing_p4,
    ] {
        replay_valid(&mut core, proposed.clone());
    }

    let effects = core
        .step(
            Input::TimeoutCertificate(timeout_certificate(&set, 8, applied_q4)),
            &RootSignatures,
        )
        .expect("the first certified branch becomes the exact durable tip");
    let (barrier, queued) = persistence_effect(&effects);
    assert_eq!(queued.finalization_queue().len(), 2);
    core.step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("the first branch queue is durable");
    for expected in [&p1, &applied] {
        let effects = apply_finalization_for_test(&mut core, &finalization_authority)
            .expect("the exact queue front is applied in order");
        let (barrier, applied_state) = persistence_effect(&effects);
        assert_eq!(
            applied_state.application_applied().block_id(),
            expected.block().id(),
        );
        core.step(Input::StorageAck { barrier }, &RootSignatures)
            .expect("the application watermark is durable");
    }
    assert_eq!(
        core.safety_state().finalized().block_id(),
        applied.block().id()
    );
    assert_eq!(
        core.safety_state().application_applied().block_id(),
        applied.block().id(),
    );
    assert!(core.safety_state().finalization_queue().is_empty());

    let before = core.clone();
    assert_eq!(
        core.step(
            Input::TimeoutCertificate(timeout_certificate(&set, 9, competing_q4)),
            &RootSignatures,
        ),
        Err(CoreError::ConflictingCertificate),
    );
    assert_eq!(
        core, before,
        "a conflicting embedded suffix must not append even one valid-looking prefix",
    );
    assert_eq!(
        core.safety_state().finalized().block_id(),
        applied.block().id(),
    );
    assert_eq!(
        core.safety_state().application_applied().block_id(),
        applied.block().id(),
    );
    assert!(core.safety_state().finalization_queue().is_empty());
}

#[test]
fn pending_q5_and_tc_q6_append_the_complete_suffix_after_applied_height_two() {
    let (_config, mut core) = configured_core();
    let finalization_authority = finalization_apply_authority_for_test(&core);
    let set = core.config().validator_set().clone();
    let p1 = proposal(&set, genesis_qc(&set), 1, b"overlap suffix one");
    let q1 = qc(&set, 1, 1, p1.block().id());
    let p2 = proposal(&set, q1, 2, b"overlap suffix two");
    let q2 = qc(&set, 2, 2, p2.block().id());
    let p3 = proposal(&set, q2, 3, b"overlap suffix three");
    let q3 = qc(&set, 3, 3, p3.block().id());
    let p4 = proposal(&set, q3, 4, b"overlap suffix four");
    let q4 = qc(&set, 4, 4, p4.block().id());
    let p5 = proposal(&set, q4.clone(), 5, b"overlap suffix five");
    let q5 = qc(&set, 5, 5, p5.block().id());
    let p6 = proposal(&set, q5.clone(), 6, b"overlap suffix six");
    let q6 = qc(&set, 6, 6, p6.block().id());
    for proposed in [&p1, &p2, &p3, &p4] {
        replay_valid(&mut core, proposed.clone());
    }

    let effects = core
        .step(
            Input::TimeoutCertificate(timeout_certificate(&set, 7, q4)),
            &RootSignatures,
        )
        .expect("q4 first queues heights one and two");
    let (barrier, queued) = persistence_effect(&effects);
    assert_eq!(queued.finalization_queue().len(), 2);
    core.step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("the initial queue is durable");
    for expected in [&p1, &p2] {
        let effects = apply_finalization_for_test(&mut core, &finalization_authority)
            .expect("the application acknowledges the exact queue front");
        let (barrier, applied) = persistence_effect(&effects);
        assert_eq!(
            applied.application_applied().block_id(),
            expected.block().id()
        );
        core.step(Input::StorageAck { barrier }, &RootSignatures)
            .expect("the application watermark is durable");
    }
    assert_eq!(
        core.safety_state().application_applied().block_id(),
        p2.block().id()
    );
    assert_eq!(core.safety_state().finalized().block_id(), p2.block().id());
    assert!(core.safety_state().finalization_queue().is_empty());

    replay_valid(&mut core, p5.clone());
    let tc = timeout_certificate(&set, 9, q6.clone());
    let effects = core
        .step(Input::TimeoutCertificate(tc.clone()), &RootSignatures)
        .expect("missing q6 target becomes the durable TC obligation");
    let (barrier, pending_tc) = persistence_effect(&effects);
    assert_eq!(
        pending_tc
            .pending_tc_high_qc_sync()
            .expect("q6 TC remains pending")
            .certificate_id(),
        tc.id()
    );
    core.step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("the q6 TC obligation is durable");

    let effects = core
        .step(Input::QuorumCertificate(q5.clone()), &RootSignatures)
        .expect("ready q5 waits behind the higher-priority TC");
    let (barrier, both_pending) = persistence_effect(&effects);
    assert_eq!(
        both_pending
            .pending_standalone_qc_sync()
            .expect("q5 is retained as the standalone active target")
            .active()
            .id(),
        q5.id()
    );
    assert!(both_pending.pending_tc_high_qc_sync().is_some());
    core.step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("both pending targets are durable");

    let effects = core
        .step(Input::SyncedProposal(Box::new(p6)), &RootSignatures)
        .expect("the exact q6 block arrives through the synced route");
    let effects = release_persisted_effects(&mut core, effects);
    let id = synced_validation_effect(&effects);
    let result = valid_result_for_effect(&core, &effects, id);
    let effects = core
        .step(
            Input::SyncedPayloadValidated { id, result },
            &RootSignatures,
        )
        .expect("q6 completion appends both missing ancestors without conflict");
    assert_eq!(
        persistence_request(&effects).native_valid_post_ack_action_v0(),
        Some(NativeValidPostAckActionV0::ArmViewTimerThenFinalize)
    );
    let (barrier, completed) = persistence_effect(&effects);
    assert_eq!(completed.high_qc().id(), q6.id());
    assert_eq!(completed.application_applied().block_id(), p2.block().id());
    assert_eq!(completed.finalized().block_id(), p4.block().id());
    assert!(completed.pending_tc_high_qc_sync().is_none());
    assert!(completed.pending_standalone_qc_sync().is_none());
    assert_eq!(completed.finalization_queue().len(), 2);
    assert_eq!(
        completed.finalization_queue()[0]
            .authenticated_parent()
            .block_id(),
        p2.block().id()
    );
    assert_eq!(
        completed.finalization_queue()[0]
            .proof()
            .finalized_block()
            .header()
            .id(),
        p3.block().id()
    );
    assert_eq!(
        completed.finalization_queue()[0].target_overlay_ref(),
        artifact_ref_for_ids(p3.block().id(), p2.block().id()).overlay()
    );
    assert_eq!(
        completed.finalization_queue()[1]
            .authenticated_parent()
            .block_id(),
        p3.block().id()
    );
    assert_eq!(
        completed.finalization_queue()[1]
            .proof()
            .finalized_block()
            .header()
            .id(),
        p4.block().id()
    );
    assert_eq!(
        completed.finalization_queue()[1].target_overlay_ref(),
        artifact_ref_for_ids(p4.block().id(), p3.block().id()).overlay()
    );
    assert_eq!(
        completed.pending_finalize(),
        Some(completed.finalization_queue()[0].proof_id())
    );
    assert!(matches!(
        core.step(Input::StorageAck { barrier }, &RootSignatures)
            .expect("only the oldest recovered ancestor is released")
            .as_slice(),
        [Effect::ArmViewTimer { .. }, Effect::Finalize(proof)]
            if proof.id() == completed.finalization_queue()[0].proof_id()
                && proof.finalized_block().header().id() == p3.block().id()
    ));
}

#[test]
fn pending_timeout_sync_survives_recovery_and_reissues_exact_target() {
    let (config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(&set, genesis_qc(&set), 1, b"recover TC target");
    let high_qc = qc(&set, 1, 1, proposed.block().id());
    let certificate = timeout_certificate(&set, 2, high_qc.clone());
    let effects = core
        .step(
            Input::TimeoutCertificate(certificate.clone()),
            &RootSignatures,
        )
        .expect("missing TC target is staged");
    let (_barrier, persisted) = persistence_effect(&effects);

    let mut recovered = Core::recover(config, persisted, &RootSignatures)
        .expect("durable pending TC target recovers");
    let effects = recovered
        .step(Input::Resume, &RootSignatures)
        .expect("recovery resumes pending TC sync");
    assert!(effects.iter().any(|effect| matches!(
        effect,
        Effect::RequestTcHighQcSync {
            certificate_id,
            timed_out_view,
            target,
            ..
        } if *certificate_id == certificate.id()
            && *timed_out_view == View::new(2)
            && target.qc_digest() == high_qc.id()
    )));

    let effects = recovered
        .step(Input::SyncedProposal(Box::new(proposed)), &RootSignatures)
        .expect("recovered sync accepts target proposal");
    let effects = release_persisted_effects(&mut recovered, effects);
    let id = synced_validation_effect(&effects);
    let result = valid_result_for_effect(&recovered, &effects, id);
    let effects = recovered
        .step(
            Input::SyncedPayloadValidated { id, result },
            &RootSignatures,
        )
        .expect("recovered sync adopts target");
    let (_barrier, adopted) = persistence_effect(&effects);
    assert_eq!(adopted.high_qc().id(), high_qc.id());
    assert_eq!(adopted.current_view(), View::new(3));
    assert!(adopted.pending_tc_high_qc_sync().is_none());
}

#[test]
fn pending_timeout_sync_target_is_idempotent_and_same_view_conflicts_halt() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let first_block = proposal(&set, genesis_qc(&set), 1, b"first TC target");
    let first_qc = qc(&set, 1, 1, first_block.block().id());
    let first_tc = timeout_certificate(&set, 2, first_qc.clone());
    let effects = core
        .step(Input::TimeoutCertificate(first_tc.clone()), &RootSignatures)
        .expect("first missing target is staged");
    let (barrier, _) = persistence_effect(&effects);
    core.step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("first target is durable");

    assert!(matches!(
        core.step(
            Input::TimeoutCertificate(first_tc.clone()),
            &RootSignatures,
        )
        .expect("the exact pending TC is idempotent")
        .as_slice(),
        [Effect::RequestTcHighQcSync { target, .. }]
            if target.qc_digest() == first_qc.id()
    ));

    let other_block = proposal(&set, genesis_qc(&set), 1, b"other TC target");
    let other_qc = qc(&set, 1, 1, other_block.block().id());
    let other_tc = timeout_certificate(&set, 2, other_qc);
    let effects = core
        .step(Input::TimeoutCertificate(other_tc), &RootSignatures)
        .expect("same-view QC conflict outranks pending-target identity");
    let halted = effects
        .iter()
        .find_map(|effect| match effect {
            Effect::PersistSafetyState(request) => Some(request.state()),
            _ => None,
        })
        .expect("conflicting TC persists a fail-stop witness");
    assert!(halted.pending_tc_high_qc_sync().is_none());
    assert!(matches!(
        halted.safety_halt(),
        Some(SafetyHalt::ConflictingQuorumCertificates { .. })
    ));
}

#[test]
fn timeout_certificate_rejects_unreferenced_extra_qcs() {
    let set = validator_set();
    let unused = qc(&set, 1, 1, BlockId::new([0x61; 32]));
    let selected = qc(&set, 2, 2, BlockId::new([0x62; 32]));
    let selected_ref = QcRef::from(&selected);
    let entries = (1..=3)
        .map(|author| {
            let author = validator_id(author);
            let vote = timeout_vote(&set, 3, selected_ref, author);
            TimeoutEntryV0::new(author, selected_ref, *vote.signature()).unwrap()
        })
        .collect();
    let mut referenced = vec![
        QcReferenceV0::ordinary(unused),
        QcReferenceV0::ordinary(selected.clone()),
    ];
    referenced.sort_by_key(QcReferenceV0::id);

    assert!(matches!(
        TimeoutCertificateV0::new(View::new(3), entries, referenced, selected.id(), &set),
        Err(ValidationError::InvalidCertificate(
            "TC carries a referenced QC that no timeout entry signed"
        ))
    ));
}

#[test]
fn payload_parent_context_is_block_kind_aware_at_epoch_handoff() {
    let old_parameters = consensus_parameters();
    let old_set = validator_set_with_parameters(&old_parameters);

    let mut new_parameter_fields = old_parameters.fields();
    new_parameter_fields.base_timeout_ms += 1;
    let new_parameters = ConsensusParametersV0::new(new_parameter_fields)
        .expect("next-epoch parameters remain valid");
    let new_set = ValidatorSet::new(
        old_set.genesis_hash(),
        old_set.chain_id(),
        old_set.protocol_version(),
        Epoch::new(1),
        new_parameters.hash(),
        old_set.validators().to_vec(),
    )
    .expect("next-epoch validator set is valid");
    let alternate_new_set = ValidatorSet::new(
        old_set.genesis_hash(),
        old_set.chain_id(),
        old_set.protocol_version(),
        Epoch::new(1),
        old_parameters.hash(),
        old_set.validators().to_vec(),
    )
    .expect("alternate next-epoch validator set is valid");

    let make_header =
        |set: &ValidatorSet,
         parameters: &ConsensusParametersV0,
         view: u64,
         height: u64,
         block_kind: BlockKind,
         parent_id: BlockId,
         marker: u8,
         next_epoch_commitment_hash: Option<NextEpochCommitmentHash>| {
            BlockHeader::new(
                set.genesis_hash(),
                set.chain_id(),
                set.protocol_version(),
                set.epoch(),
                View::new(view),
                Height::new(height),
                block_kind,
                parent_id,
                validator_id(1),
                set.id(),
                parameters.hash(),
                PayloadDigest::new([marker; 32]),
                StateRoot::new([marker.wrapping_add(1); 32]),
                ReceiptsRoot::new([marker.wrapping_add(2); 32]),
                EvidenceRoot::new([marker.wrapping_add(3); 32]),
                height.saturating_mul(100),
                next_epoch_commitment_hash,
            )
            .expect("test context header is valid")
        };

    let terminal_seal = make_header(
        &old_set,
        &old_parameters,
        12,
        10,
        BlockKind::EpochSeal2,
        BlockId::new([0x81; 32]),
        0x82,
        Some(NextEpochCommitmentHash::new([0x83; 32])),
    );
    let handoff = make_header(
        &new_set,
        &new_parameters,
        1,
        11,
        BlockKind::EpochHandoff,
        terminal_seal.id(),
        0x84,
        None,
    );
    assert!(
        payload_parent_context_matches_target_v0(&handoff, &terminal_seal)
            .expect("epoch increment is representable")
    );

    let same_context_regular = make_header(
        &new_set,
        &new_parameters,
        2,
        12,
        BlockKind::Regular,
        handoff.id(),
        0x85,
        None,
    );
    assert!(
        payload_parent_context_matches_target_v0(&same_context_regular, &handoff)
            .expect("ordinary context comparison succeeds")
    );

    let changed_context_regular = make_header(
        &alternate_new_set,
        &old_parameters,
        2,
        12,
        BlockKind::Regular,
        handoff.id(),
        0x86,
        None,
    );
    assert!(
        !payload_parent_context_matches_target_v0(&changed_context_regular, &handoff)
            .expect("ordinary context comparison succeeds")
    );

    let wrong_parent_kind = make_header(
        &old_set,
        &old_parameters,
        12,
        10,
        BlockKind::Regular,
        BlockId::new([0x81; 32]),
        0x87,
        None,
    );
    assert!(
        !payload_parent_context_matches_target_v0(&handoff, &wrong_parent_kind)
            .expect("epoch increment is representable")
    );
}

#[test]
fn epoch_checkpoint_and_seal_blocks_fail_closed_before_transition_support() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let parent = proposal(&set, genesis_qc(&set), 1, b"regular parent");
    let parent_qc = qc(&set, 1, 1, parent.block().id());
    insert_valid_and_vote(&mut core, parent);
    accept_qc(&mut core, parent_qc.clone());

    let proposer = leader_for(&set, View::new(2));
    let header = BlockHeader::new(
        set.genesis_hash(),
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(2),
        Height::new(2),
        BlockKind::EpochSeal2,
        parent_qc.block_id(),
        proposer,
        set.id(),
        set.consensus_parameters_hash(),
        PayloadDigest::new([0x71; 32]),
        StateRoot::new([0x72; 32]),
        ReceiptsRoot::new([0x73; 32]),
        EvidenceRoot::new([0x74; 32]),
        200,
        Some(NextEpochCommitmentHash::new([0x75; 32])),
    )
    .unwrap();
    let block = Block::new(header, vec![0, 0, 0, 0], Vec::new()).unwrap();
    let seal = signed_proposal_from_block(
        &set,
        &consensus_parameters(),
        block,
        QcReferenceV0::ordinary(parent_qc),
        None,
        100,
    )
    .unwrap();

    assert_eq!(
        core.step(Input::Proposal(Box::new(seal)), &RootSignatures),
        Err(CoreError::UnsupportedBlockKind)
    );
}

#[test]
fn last_pre_checkpoint_regular_block_keeps_the_durable_vote_pipeline() {
    let (_config, mut core, set, parameters, second_qc) = short_epoch_core_before_last_regular();
    let proposed = proposal_with_parameters(
        &set,
        &parameters,
        second_qc,
        3,
        b"last pre-checkpoint regular",
    );
    assert_eq!(proposed.block().header().height(), Height::new(3));

    let effects = core
        .step(Input::Proposal(Box::new(proposed.clone())), &RootSignatures)
        .expect("height checkpoint-1 proposal is accepted");
    let (barrier, persisted) = persistence_effect(&effects);
    assert!(persisted.pending_sign().is_none());
    let effects = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("proposal observation is durable");
    let validation = validation_effect(&effects);
    let result = valid_result_for_effect(&core, &effects, validation);

    let effects = core
        .step(
            Input::PayloadValidated {
                id: validation,
                result,
            },
            &RootSignatures,
        )
        .expect("height checkpoint-1 payload is valid");
    let (barrier, persisted) = persistence_effect(&effects);
    let transition = persistence_request(&effects)
        .safety_rules_shadow_transition_v1()
        .expect("vote persistence carries the exact SafetyRules transition");
    assert_eq!(transition.successor_state().revision(), barrier.get());
    assert_eq!(
        transition.canonical_intent().signing_root(),
        persisted
            .pending_sign()
            .expect("vote persistence retains its sign intent")
            .signing_root()
    );
    assert!(matches!(
        persisted.pending_sign(),
        Some(SignIntent::Vote { height, block_id, .. })
            if *height == Height::new(3) && *block_id == proposed.block().id()
    ));

    let effects = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("vote intent is durable before signing");
    let (sign_id, root) = signature_request(&effects);
    let effects = core
        .step(
            Input::SignatureReady {
                id: sign_id,
                signature: signature(root),
            },
            &RootSignatures,
        )
        .expect("height checkpoint-1 vote is signed");
    assert!(matches!(
        effects.as_slice(),
        [Effect::Broadcast(OutboundMessage::Vote(vote))]
            if vote.height() == Height::new(3) && vote.block_id() == proposed.block().id()
    ));
}

#[test]
fn regular_proposal_and_replay_are_fenced_at_every_epoch_boundary_height() {
    let (_config, core, set, parameters, last_regular_qc) = short_epoch_core_at_boundary();
    let checkpoint_height = 4;
    let boundary_parents = [
        (checkpoint_height, last_regular_qc),
        (5, qc(&set, 4, 4, BlockId::new([0xA4; 32]))),
        (6, qc(&set, 5, 5, BlockId::new([0xA5; 32]))),
        (7, qc(&set, 6, 6, BlockId::new([0xA6; 32]))),
    ];

    for (height, parent_qc) in boundary_parents {
        let proposed = proposal_with_parameters(
            &set,
            &parameters,
            parent_qc,
            height,
            b"regular epoch-boundary proposal",
        );
        assert_eq!(proposed.block().header().height(), Height::new(height));

        let mut live = core.clone();
        assert_epoch_boundary_rejected_without_state_change(
            &mut live,
            Input::Proposal(Box::new(proposed.clone())),
            height,
            checkpoint_height,
        );

        let mut replay = core.clone();
        assert_epoch_boundary_rejected_without_state_change(
            &mut replay,
            Input::SyncedProposal(Box::new(proposed)),
            height,
            checkpoint_height,
        );
    }
}

#[test]
fn votes_qcs_and_all_tc_carriers_are_fenced_before_observation_or_view_advance() {
    let (_config, core, set, parameters, last_regular_qc) = short_epoch_core_at_boundary();
    let boundary_qc = qc(&set, 4, 4, BlockId::new([0xB4; 32]));
    let boundary_vote = signed_vote(&set, 4, 4, boundary_qc.block_id(), validator_id(2));
    let boundary_timeout_vote = timeout_vote(&set, 5, QcRef::from(&boundary_qc), validator_id(2));
    let boundary_tc =
        timeout_certificate_with_two_qcs(&set, 5, last_regular_qc, boundary_qc.clone());
    let carried_qc = proposal_with_parameters(
        &set,
        &parameters,
        boundary_qc.clone(),
        5,
        b"boundary justify QC carrier",
    );
    let carried_tc = timeout_proposal_with_parameters(
        &set,
        &parameters,
        timeout_certificate(&set, 5, boundary_qc.clone()),
        b"boundary TC carrier",
    );

    for input in [
        Input::Vote(boundary_vote),
        Input::TimeoutVote(boundary_timeout_vote),
        Input::QuorumCertificate(boundary_qc),
        Input::TimeoutCertificate(boundary_tc),
    ] {
        let mut candidate = core.clone();
        assert_epoch_boundary_rejected_without_state_change(&mut candidate, input, 4, 4);
    }
    for input in [
        Input::Proposal(Box::new(carried_qc)),
        Input::Proposal(Box::new(carried_tc)),
    ] {
        let mut candidate = core.clone();
        assert_epoch_boundary_rejected_without_state_change(&mut candidate, input, 5, 4);
    }
}

#[test]
fn recovery_fences_high_lock_pending_syncs_and_both_sign_intents() {
    let (config, core, set, _parameters, _last_regular_qc) = short_epoch_core_at_boundary();
    let state = core.safety_state();
    let boundary_qc = qc(&set, 4, 4, BlockId::new([0xC4; 32]));
    let expected = CoreError::EpochBoundaryUnsupported {
        height: Height::new(4),
        checkpoint_height: Height::new(4),
    };
    let assert_recovery_fenced = |decoded| {
        assert_eq!(
            Core::recover(config.clone(), decoded, &RootSignatures),
            Err(expected.clone())
        );
    };

    assert_recovery_fenced(decoded_state_with_obligations(
        state,
        View::new(5),
        state.last_voted_view(),
        state.last_timeout_view(),
        QcReferenceV0::ordinary(boundary_qc.clone()),
        QcReferenceV0::ordinary(boundary_qc.clone()),
        state.finalized(),
        None,
        None,
        None,
        state.last_finalization().cloned(),
        state.pending_finalize(),
    ));

    assert_recovery_fenced(decoded_state_with_obligations(
        state,
        state.current_view(),
        state.last_voted_view(),
        state.last_timeout_view(),
        state.high_qc().clone(),
        state.locked_qc().clone(),
        state.finalized(),
        None,
        Some(PendingStandaloneQcSync::new(boundary_qc.clone())),
        None,
        state.last_finalization().cloned(),
        state.pending_finalize(),
    ));

    let pending_tc = PendingTcHighQcSync::from_timeout_certificate(timeout_certificate(
        &set,
        5,
        boundary_qc.clone(),
    ))
    .expect("canonical pending TC target");
    assert_recovery_fenced(decoded_state_with_obligations(
        state,
        View::new(6),
        state.last_voted_view(),
        state.last_timeout_view(),
        state.high_qc().clone(),
        state.locked_qc().clone(),
        state.finalized(),
        Some(pending_tc),
        None,
        None,
        state.last_finalization().cloned(),
        state.pending_finalize(),
    ));

    let vote_root =
        Vote::signing_root_for_set(&set, View::new(4), Height::new(4), boundary_qc.block_id())
            .expect("boundary vote root");
    assert_recovery_fenced(decoded_state_with_obligations(
        state,
        View::new(4),
        Some(View::new(4)),
        state.last_timeout_view(),
        state.high_qc().clone(),
        state.locked_qc().clone(),
        state.finalized(),
        None,
        None,
        Some(SignIntent::Vote {
            authorizing_safety_revision: state.revision(),
            view: View::new(4),
            height: Height::new(4),
            block_id: boundary_qc.block_id(),
            signing_root: vote_root,
        }),
        state.last_finalization().cloned(),
        state.pending_finalize(),
    ));

    let boundary_ref = QcRef::from(&boundary_qc);
    let timeout_root = TimeoutVote::signing_root_for_set(&set, View::new(5), boundary_ref)
        .expect("boundary timeout root");
    assert_recovery_fenced(decoded_state_with_obligations(
        state,
        View::new(5),
        state.last_voted_view(),
        Some(View::new(5)),
        state.high_qc().clone(),
        state.locked_qc().clone(),
        state.finalized(),
        None,
        None,
        Some(SignIntent::TimeoutVote {
            authorizing_safety_revision: state.revision(),
            view: View::new(5),
            high_qc: boundary_ref,
            signing_root: timeout_root,
        }),
        state.last_finalization().cloned(),
        state.pending_finalize(),
    ));
}

#[test]
fn recovery_fences_finalized_tip_and_finality_certifying_qc() {
    let (config, core, set, parameters, last_regular_qc) = short_epoch_core_at_boundary();
    let state = core.safety_state();
    let expected = CoreError::EpochBoundaryUnsupported {
        height: Height::new(4),
        checkpoint_height: Height::new(4),
    };

    let boundary_tip =
        FinalizedTip::new(Height::new(4), View::new(4), BlockId::new([0xD4; 32]), 400);
    let decoded = decoded_state_with_obligations(
        state,
        state.current_view(),
        state.last_voted_view(),
        state.last_timeout_view(),
        state.high_qc().clone(),
        state.locked_qc().clone(),
        boundary_tip,
        None,
        None,
        None,
        None,
        None,
    );
    assert_eq!(
        Core::recover(config.clone(), decoded, &RootSignatures),
        Err(expected.clone())
    );

    let first = proposal_with_parameters(
        &set,
        &parameters,
        genesis_qc(&set),
        1,
        b"finality fence one",
    );
    let first_qc = qc(&set, 1, 1, first.block().id());
    let second = proposal_with_parameters(
        &set,
        &parameters,
        first_qc.clone(),
        2,
        b"finality fence two",
    );
    let second_qc = qc(&set, 2, 2, second.block().id());
    let third = proposal_with_parameters(
        &set,
        &parameters,
        second_qc.clone(),
        3,
        b"finality fence three",
    );
    let third_qc = qc(&set, 3, 3, third.block().id());
    let fourth = proposal_with_parameters(
        &set,
        &parameters,
        third_qc.clone(),
        4,
        b"finality fence four",
    );
    let fourth_qc = qc(&set, 4, 4, fourth.block().id());

    let second_certified = CertifiedHeaderV0::from_signed_proposal(
        second.clone(),
        second_qc,
        &set,
        None,
        &parameters,
        first.block().header().timestamp_ms(),
    )
    .expect("valid second certified header");
    let third_certified = CertifiedHeaderV0::from_signed_proposal(
        third.clone(),
        third_qc,
        &set,
        None,
        &parameters,
        second.block().header().timestamp_ms(),
    )
    .expect("valid third certified header");
    let fourth_certified = CertifiedHeaderV0::from_signed_proposal(
        fourth,
        fourth_qc,
        &set,
        None,
        &parameters,
        third.block().header().timestamp_ms(),
    )
    .expect("valid boundary certified header");
    let proof = FinalityProofV0::new(
        second_certified,
        third_certified,
        fourth_certified,
        &set,
        None,
        &parameters,
        first.block().header().timestamp_ms(),
    )
    .expect("valid three-chain crossing the unsupported boundary");
    let durable = DurableFinalizationV0::new(
        FinalizedTip::new(
            first.block().header().height(),
            first.block().header().view(),
            first.block().id(),
            first.block().header().timestamp_ms(),
        ),
        proof,
        artifact_ref_for_ids(second.block().id(), first.block().id()).overlay(),
    )
    .expect("valid durable finality witness");
    let decoded = decoded_state_with_obligations(
        state,
        state.current_view(),
        state.last_voted_view(),
        state.last_timeout_view(),
        state.high_qc().clone(),
        state.locked_qc().clone(),
        state.finalized(),
        None,
        None,
        None,
        Some(durable),
        None,
    );
    assert_eq!(
        Core::recover(config, decoded, &RootSignatures),
        Err(expected)
    );

    assert_eq!(last_regular_qc.height(), Height::new(3));
}

#[test]
fn recovery_fences_boundary_tc_inside_an_invalid_payload_halt_witness() {
    let (config, core, set, _parameters, _last_regular_qc) = short_epoch_core_at_boundary();
    let state = core.safety_state();
    let block_id = BlockId::new([0xE4; 32]);
    let boundary_qc = qc(&set, 4, 4, block_id);
    let certificate = timeout_certificate(&set, 5, boundary_qc);
    let decoded = decoded_halted_state_with_invalid_reference(
        state,
        View::new(6),
        state.last_voted_view(),
        Some(View::new(5)),
        block_id,
        InvalidPayloadReference::TimeoutCertificate(Box::new(certificate)),
    );

    assert_eq!(
        Core::recover(config, decoded, &RootSignatures),
        Err(CoreError::EpochBoundaryUnsupported {
            height: Height::new(4),
            checkpoint_height: Height::new(4),
        })
    );
}

#[test]
fn recovery_fences_boundary_vote_inside_an_invalid_payload_halt_witness() {
    let (config, core, set, _parameters, _last_regular_qc) = short_epoch_core_at_boundary();
    let state = core.safety_state();
    let block_id = BlockId::new([0xE5; 32]);
    let signing_root = Vote::signing_root_for_set(&set, View::new(4), Height::new(4), block_id)
        .expect("boundary vote signing root");
    let decoded = decoded_halted_state_with_invalid_reference(
        state,
        View::new(4),
        Some(View::new(4)),
        state.last_timeout_view(),
        block_id,
        InvalidPayloadReference::PendingVote(Box::new(SignIntent::Vote {
            authorizing_safety_revision: state.revision(),
            view: View::new(4),
            height: Height::new(4),
            block_id,
            signing_root,
        })),
    );

    assert_eq!(
        Core::recover(config, decoded, &RootSignatures),
        Err(CoreError::EpochBoundaryUnsupported {
            height: Height::new(4),
            checkpoint_height: Height::new(4),
        })
    );
}

#[test]
fn safety_state_record_roundtrips_an_invalid_payload_pending_vote_witness() {
    let (config, mut core) = configured_core();
    let effects = core
        .step(
            Input::LocalTimeout {
                epoch: Epoch::new(0),
                view: View::new(1),
            },
            &RootSignatures,
        )
        .expect("timeout creates a positive durable revision for the halt fixture");
    let (_barrier, state) = persistence_effect(&effects);
    let set = config.validator_set();
    let block_id = BlockId::new([0xE6; 32]);
    let view = View::new(1);
    let height = Height::new(1);
    let signing_root = Vote::signing_root_for_set(set, view, height, block_id)
        .expect("valid pending-vote signing root");
    let halted = decoded_halted_state_with_invalid_reference(
        &state,
        view,
        Some(view),
        state.last_timeout_view(),
        block_id,
        InvalidPayloadReference::PendingVote(Box::new(SignIntent::Vote {
            authorizing_safety_revision: state.revision(),
            view,
            height,
            block_id,
            signing_root,
        })),
    );

    assert_safety_state_record_roundtrip_and_validate(&config, &halted);
}

#[test]
fn conflicting_timeout_certificate_entries_produce_equivocation_evidence() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let first_proposal = proposal(&set, genesis_qc(&set), 1, b"first TC anchor");
    let first_high = qc(&set, 1, 1, first_proposal.block().id());
    insert_valid_and_vote(&mut core, first_proposal);
    accept_qc(&mut core, first_high.clone());
    let second_proposal = proposal(&set, first_high.clone(), 2, b"second TC anchor");
    let second_high = qc(&set, 2, 2, second_proposal.block().id());
    insert_valid_and_vote(&mut core, second_proposal);
    accept_qc(&mut core, second_high.clone());

    let effects = core
        .step(
            Input::TimeoutCertificate(timeout_certificate(&set, 9, first_high)),
            &RootSignatures,
        )
        .expect("first TC entries are observed");
    let (barrier, _) = persistence_effect(&effects);
    core.step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("first TC view is durable");

    let effects = core
        .step(
            Input::TimeoutCertificate(timeout_certificate(&set, 9, second_high)),
            &RootSignatures,
        )
        .expect("conflicting timeout entries produce evidence");
    assert!(effects
        .iter()
        .any(|effect| matches!(effect, Effect::Evidence(_))));
}

#[test]
fn conflicting_verified_votes_produce_canonical_evidence() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let first = signed_vote(&set, 9, 7, BlockId::new([1; 32]), validator_id(2));
    let second = signed_vote(&set, 9, 7, BlockId::new([2; 32]), validator_id(2));
    assert!(core
        .step(Input::Vote(first), &RootSignatures)
        .expect("first vote observed")
        .is_empty());
    let effects = core
        .step(Input::Vote(second), &RootSignatures)
        .expect("conflict observed");
    assert!(matches!(effects.as_slice(), [Effect::Evidence(_)]));
}

#[test]
fn conflicting_qcs_persist_a_recoverable_fail_stop() {
    let (config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let genesis = genesis_qc(&set);
    let first_proposal = proposal(&set, genesis, 1, b"first");
    let first = qc(&set, 1, 1, first_proposal.block().id());
    insert_valid_and_vote(&mut core, first_proposal);
    accept_qc(&mut core, first.clone());

    let second = qc(&set, 1, 1, BlockId::new([0x99; 32]));
    let effects = core
        .step(Input::QuorumCertificate(second.clone()), &RootSignatures)
        .expect("conflicting verified QC triggers fail-stop persistence");
    let (barrier, state) = effects
        .iter()
        .find_map(|effect| match effect {
            Effect::PersistSafetyState(request) => {
                Some((request.barrier(), request.state().clone()))
            }
            _ => None,
        })
        .expect("halt state persistence");
    let halt = state.safety_halt().expect("durable safety halt");
    let (halt_first, halt_second) = halt.conflicting_qcs().expect("conflicting QC halt");
    assert_ne!(halt_first.block_id(), halt_second.block_id());
    let decoded_roundtrip = roundtrip_safety_state_record(&config, &state);
    assert_eq!(
        decoded_roundtrip.durable_observed_qcs(),
        state.durable_observed_qcs(),
        "nonempty ordinary-QC observations survive the canonical record roundtrip",
    );
    Core::validate_persisted_state_v0(&config, &decoded_roundtrip, &RootSignatures)
        .expect("the roundtripped halt state remains valid");
    assert!(matches!(
        core.step(Input::StorageAck { barrier }, &RootSignatures)
            .expect("halt state durable")
            .as_slice(),
        [Effect::SafetyHalted(_)]
    ));
    assert!(matches!(
        core.step(
            Input::LocalTimeout {
                epoch: Epoch::new(0),
                view: View::new(2),
            },
            &RootSignatures,
        ),
        Err(CoreError::Busy(_))
    ));

    let decoded_halt =
        SafetyHalt::from_conflicting_qcs(first, second).expect("canonical halt reconstruction");
    let decoded = SafetyState::from_persisted_parts_v13(
        SAFETY_STATE_SCHEMA_VERSION,
        state.chain_id(),
        state.protocol_version(),
        state.epoch(),
        state.validator_set_id(),
        state.genesis_block_id(),
        state.authenticated_genesis_application_parent_v0().copied(),
        state.current_view(),
        state.last_voted_view(),
        state.last_timeout_view(),
        state.high_qc().clone(),
        state.locked_qc().clone(),
        state.finalized(),
        state.revision(),
        state.durable_observed_qcs().to_vec(),
        state.payload_terminal_facts().to_vec(),
        vec![],
        state.payload_validation_completions().to_vec(),
        state.pending_tc_high_qc_sync().cloned(),
        state.pending_standalone_qc_sync().cloned(),
        state.pending_sign().cloned(),
        state.last_finalization().cloned(),
        state.state_sync_anchor().cloned(),
        state.application_applied(),
        state.finalization_queue().to_vec(),
        state.pending_finalize(),
        Some(decoded_halt),
    );
    let mut recovered =
        Core::recover(config, decoded, &RootSignatures).expect("halted WAL state validates");
    assert!(matches!(
        recovered
            .step(Input::Resume, &RootSignatures)
            .expect("halt is reissued")
            .as_slice(),
        [Effect::SafetyHalted(_)]
    ));
}

#[test]
fn a_conflict_with_the_recovered_lock_halts_before_block_lookup() {
    let (config, mut original) = configured_core();
    let set = original.config().validator_set().clone();
    let p1 = proposal(&set, genesis_qc(&set), 1, b"one");
    let q1 = qc(&set, 1, 1, p1.block().id());
    insert_valid_and_vote(&mut original, p1);
    accept_qc(&mut original, q1.clone());

    let p2 = proposal(&set, q1.clone(), 2, b"two");
    let q2 = qc(&set, 2, 2, p2.block().id());
    insert_valid_and_vote(&mut original, p2);
    let effects = original
        .step(Input::QuorumCertificate(q2), &RootSignatures)
        .expect("second QC accepted");
    let (_barrier, state) = persistence_effect(&effects);
    assert_eq!(state.locked_qc().id(), q1.id());

    let mut recovered =
        Core::recover(config, state, &RootSignatures).expect("durable lock recovers");
    let conflicting = qc(&set, 1, 1, BlockId::new([0x91; 32]));
    let effects = recovered
        .step(Input::QuorumCertificate(conflicting), &RootSignatures)
        .expect("durable lock conflict enters fail-stop");
    let (_barrier, halted) = persistence_effect(&effects);
    let halt = halted.safety_halt().expect("conflict is retained durably");
    let (first, second) = halt.conflicting_qcs().expect("conflicting QC halt");
    assert_eq!(first.view(), View::new(1));
    assert_eq!(second.view(), View::new(1));
    assert_ne!(first.block_id(), second.block_id());
}

#[test]
fn alternate_qc_encodings_for_one_block_choose_the_max_digest_without_halting() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(&set, genesis_qc(&set), 1, b"one block, two QCs");
    let first = qc_with_authors(&set, 1, 1, proposed.block().id(), &[1, 2, 3]);
    let second = qc_with_authors(&set, 1, 1, proposed.block().id(), &[2, 3, 4]);
    assert_ne!(first.id(), second.id());
    let (lower, higher) = if first.id() < second.id() {
        (first, second)
    } else {
        (second, first)
    };
    insert_valid_and_vote(&mut core, proposed);
    accept_qc(&mut core, lower);

    let effects = core
        .step(Input::QuorumCertificate(higher.clone()), &RootSignatures)
        .expect("alternate signer subset is not a safety conflict");
    let (_barrier, state) = persistence_effect(&effects);
    assert_eq!(state.high_qc().id(), higher.id());
    assert!(state.safety_halt().is_none());
}

#[test]
fn duplicate_block_justifications_keep_the_first_exact_witness_for_locking() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let parent = proposal(&set, genesis_qc(&set), 1, b"parent");
    let first = qc_with_authors(&set, 1, 1, parent.block().id(), &[1, 2, 3]);
    let second = qc_with_authors(&set, 1, 1, parent.block().id(), &[2, 3, 4]);
    let (lower, higher) = if first.id() < second.id() {
        (first, second)
    } else {
        (second, first)
    };
    insert_valid_and_vote(&mut core, parent);
    accept_qc(&mut core, lower.clone());

    let proposer = leader_for(&set, View::new(2));
    let proposed = block(&set, 2, 2, lower.block_id(), b"same header", proposer);
    let lower_proposal = proposal_from_block(&set, proposed.clone(), lower.clone());
    let higher_proposal = proposal_from_block(&set, proposed, higher.clone());

    let effects = core
        .step(Input::Proposal(Box::new(lower_proposal)), &RootSignatures)
        .expect("first proposal accepted");
    let effects = release_persisted_effects(&mut core, effects);
    let validation = validation_effect(&effects);
    let result = valid_result_for_effect(&core, &effects, validation);
    let effects = core
        .step(Input::Proposal(Box::new(higher_proposal)), &RootSignatures)
        .expect("alternate signed witness still teaches its independently valid QC");
    assert!(effects
        .iter()
        .any(|effect| matches!(effect, Effect::Evidence(_))));
    let (barrier, state) = effects
        .iter()
        .find_map(|effect| match effect {
            Effect::PersistSafetyState(request) => {
                Some((request.barrier(), request.state().clone()))
            }
            _ => None,
        })
        .expect("the alternate carrier QC transition is durable");
    assert_eq!(state.high_qc().id(), higher.id());
    core.step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("alternate carrier QC is acknowledged");

    let effects = core
        .step(
            Input::PayloadValidated {
                id: validation,
                result,
            },
            &RootSignatures,
        )
        .expect("payload accepted");
    let (barrier, _) = persistence_effect(&effects);
    let request = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("vote intent durable");
    let (sign_id, root) = signature_request(&request);
    core.step(
        Input::SignatureReady {
            id: sign_id,
            signature: signature(root),
        },
        &RootSignatures,
    )
    .expect("vote signed");

    let certificate = qc(&set, 2, 2, validation.block_id());
    let effects = core
        .step(Input::QuorumCertificate(certificate), &RootSignatures)
        .expect("child QC accepted");
    let (_barrier, state) = persistence_effect(&effects);
    assert_ne!(state.locked_qc().id(), higher.id());
    assert_eq!(state.locked_qc().id(), lower.id());
    assert!(state.safety_halt().is_none());
}

#[test]
fn bounded_tree_never_evicts_the_incoming_proposals_justified_parent() {
    let parameters = consensus_parameters();
    let set = validator_set_with_parameters(&parameters);
    let config = CoreConfig::new(
        validator_id(1),
        set.clone(),
        parameters,
        GENESIS_TIMESTAMP_MS,
        4,
        64,
    )
    .expect("valid four-block core");
    let mut core = Core::new(config, genesis_qc(&set), &RootSignatures).expect("valid bootstrap");

    let parent = proposal(&set, genesis_qc(&set), 1, b"parent that must survive");
    let parent_qc = qc(&set, 1, 1, parent.block().id());
    insert_valid_and_vote(&mut core, parent);
    for timed_out_view in 1..=3 {
        let filler = timeout_proposal(
            &set,
            timeout_certificate(&set, timed_out_view, genesis_qc(&set)),
            &[0x80 + timed_out_view as u8],
        );
        insert_valid_and_vote(&mut core, filler);
    }

    let child = timeout_proposal(
        &set,
        timeout_certificate(&set, 4, parent_qc.clone()),
        b"child of the oldest side branch",
    );
    insert_valid_and_vote(&mut core, child);
    assert_eq!(core.safety_state().high_qc().id(), parent_qc.id());
}

#[test]
fn safe_vote_rule_rejects_a_fork_below_the_lock() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let genesis = genesis_qc(&set);

    let p1 = proposal(&set, genesis.clone(), 1, b"one");
    let q1 = qc(&set, 1, 1, p1.block().id());
    insert_valid_and_vote(&mut core, p1);
    accept_qc(&mut core, q1.clone());

    let p2 = proposal(&set, q1.clone(), 2, b"two");
    let q2 = qc(&set, 2, 2, p2.block().id());
    insert_valid_and_vote(&mut core, p2);
    accept_qc(&mut core, q2);
    assert_eq!(
        core.safety_state().locked_qc().qc_ref().block_id(),
        q1.block_id()
    );

    let fork = timeout_proposal(&set, timeout_certificate(&set, 2, genesis), b"fork");
    let effects = core
        .step(Input::Proposal(Box::new(fork)), &RootSignatures)
        .expect("fork proposal received");
    let effects = release_persisted_effects(&mut core, effects);
    let validation = validation_effect(&effects);
    let result = valid_result_for_effect(&core, &effects, validation);
    let effects = core
        .step(
            Input::PayloadValidated {
                id: validation,
                result,
            },
            &RootSignatures,
        )
        .expect("unsafe proposal is consumed without voting");
    assert!(release_persisted_effects(&mut core, effects).is_empty());
    assert_eq!(core.pending_validation_count(), 0);
}

fn core_with_replayed_linear_prefix_for_shadow_bound(
    target_height: u64,
) -> (Core, SignedProposalV0) {
    assert!(target_height > 1);
    let parameters = consensus_parameters();
    let set = validator_set_with_parameters(&parameters);
    let config = CoreConfig::new(
        validator_id(1),
        set.clone(),
        parameters,
        GENESIS_TIMESTAMP_MS,
        128,
        256,
    )
    .expect("valid long-shadow-path Core configuration");
    let bootstrap =
        Core::new(config.clone(), genesis_qc(&set), &RootSignatures).expect("valid bootstrap");
    let genesis = bootstrap.safety_state();
    let mut justify = genesis_qc(&set).into_qc_reference();
    let mut prefix = Vec::with_capacity((target_height - 1) as usize);
    for height in 1..target_height {
        let payload = height.to_be_bytes();
        let proposed = proposal(&set, justify.clone(), height, &payload);
        justify = qc(&set, height, height, proposed.block().id()).into_qc_reference();
        prefix.push(proposed);
    }
    // Keep replay's maximum height at the target while avoiding a certificate
    // for the target itself: the durable high QC certifies a sibling in the
    // immediately preceding view, and a complete TC carries the parent QC into
    // the target view. This is a valid recovered fork shape and leaves the
    // finalized-to-target path available for the comparison-only bound probe.
    let high_sibling = proposal(
        &set,
        justify.clone(),
        target_height,
        b"shadow-bound high sibling",
    );
    let high_qc = qc(
        &set,
        target_height,
        target_height,
        high_sibling.block().id(),
    );
    let target = timeout_proposal(
        &set,
        timeout_certificate(&set, target_height, justify),
        b"shadow-bound target",
    );
    assert_eq!(target.block().header().height(), Height::new(target_height));
    assert_eq!(target.block().header().view(), View::new(target_height + 1));
    let recovered_state = SafetyState::from_persisted_parts(
        SAFETY_STATE_SCHEMA_VERSION,
        genesis.chain_id(),
        genesis.protocol_version(),
        genesis.epoch(),
        genesis.validator_set_id(),
        genesis.genesis_block_id(),
        View::new(target_height + 1),
        None,
        None,
        high_qc.into_qc_reference(),
        genesis.locked_qc().clone(),
        genesis.finalized(),
        genesis.revision(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let mut recovered = Core::recover(config, recovered_state, &RootSignatures)
        .expect("long exact high-QC path enters fail-closed replay");
    for proposed in prefix {
        replay_valid(&mut recovered, proposed);
    }
    replay_valid(&mut recovered, high_sibling);
    replay_valid(&mut recovered, target.clone());
    recovered
        .step(Input::SafetyReplayComplete, &RootSignatures)
        .expect("the complete exact prefix satisfies replay");
    (recovered, target)
}

#[test]
fn safety_rules_shadow_core_bound_admits_64_and_fails_closed_at_65() {
    let (at_bound, target_64) = core_with_replayed_linear_prefix_for_shadow_bound(64);
    let mut at_bound_probe = at_bound.clone();
    assert!(at_bound_probe
        .stage_vote_validated_proposal_for_test_v1(&target_64, &RootSignatures)
        .expect("an exact 64-block path is inside the inclusive Core shadow bound"));
    assert_eq!(
        at_bound_probe.safety_state().last_voted_view(),
        Some(View::new(65))
    );
    assert!(matches!(
        at_bound_probe.safety_state().pending_sign(),
        Some(SignIntent::Vote { view, height, .. })
            if *view == View::new(65) && *height == Height::new(64)
    ));
    assert_eq!(
        at_bound.safety_state().last_voted_view(),
        None,
        "the pre-persistence boundary was exercised only on an isolated clone"
    );

    let (over_bound, target_65) = core_with_replayed_linear_prefix_for_shadow_bound(65);
    let mut over_bound_probe = over_bound.clone();
    let before = over_bound_probe.clone();
    assert_eq!(
        over_bound_probe.stage_vote_validated_proposal_for_test_v1(&target_65, &RootSignatures),
        Err(CoreError::SafetyRulesShadowMismatch(
            "exact application-Valid ancestry is missing, unfrozen, or exceeds the shadow bound"
        ))
    );
    assert_eq!(
        over_bound_probe, before,
        "the over-bound rejection occurs before Core mutation"
    );
}

#[test]
fn safety_rules_transition_binding_is_rechecked_before_storage_ack() {
    let (_config_a, mut core_a) = configured_core();
    let (_config_b, mut core_b) = configured_core();
    let set_a = core_a.config().validator_set().clone();
    let set_b = core_b.config().validator_set().clone();

    let stage_vote_persistence = |core: &mut Core, proposal: SignedProposalV0| {
        let proposal_effects = core
            .step(Input::Proposal(Box::new(proposal)), &RootSignatures)
            .expect("proposal enters validation");
        let validation_effects = release_persisted_effects(core, proposal_effects);
        let validation = validation_effect(&validation_effects);
        let result = valid_result_for_effect(core, &validation_effects, validation);
        core.step(
            Input::PayloadValidated {
                id: validation,
                result,
            },
            &RootSignatures,
        )
        .expect("valid proposal stages a Vote persistence request")
    };

    let effects_a = stage_vote_persistence(
        &mut core_a,
        proposal(&set_a, genesis_qc(&set_a), 1, b"transition binding A"),
    );
    let barrier_a = persistence_request(&effects_a).barrier();
    let transition_b = {
        let effects_b = stage_vote_persistence(
            &mut core_b,
            proposal(&set_b, genesis_qc(&set_b), 1, b"transition binding B"),
        );
        persistence_request(&effects_b)
            .safety_rules_shadow_transition_v1()
            .expect("second Vote request carries its SafetyRules transition")
            .clone()
    };

    core_a
        .replace_pending_safety_rules_transition_for_test_v1(Some(transition_b))
        .expect("first Core has a pending persistence slot");
    let before = core_a.clone();
    assert_eq!(
        core_a.step(Input::StorageAck { barrier: barrier_a }, &RootSignatures,),
        Err(CoreError::SafetyRulesShadowMismatch(
            "SafetyRules transition successor differs from the Core successor",
        ))
    );
    assert_eq!(
        core_a, before,
        "a detached transition cannot consume the persistence barrier"
    );
}

#[test]
fn safety_rules_shadow_core_accepts_a_view_stronger_shallower_high_qc() {
    let (config, bootstrap) = configured_core();
    let set = config.validator_set().clone();
    let genesis = genesis_qc(&set);
    let locked_parent = proposal(&set, genesis.clone(), 1, b"shadow deep-lock parent");
    let locked_parent_qc = qc(&set, 1, 1, locked_parent.block().id());
    let locked_child = proposal(&set, locked_parent_qc, 2, b"shadow deep lock");
    let locked_qc = qc(&set, 2, 2, locked_child.block().id());
    let shallow_high_proposal = timeout_proposal(
        &set,
        timeout_certificate(&set, 2, genesis),
        b"shadow view-stronger shallow high",
    );
    let shallow_high_qc = qc(&set, 3, 1, shallow_high_proposal.block().id());
    assert!(shallow_high_qc.view() > locked_qc.view());
    assert!(shallow_high_qc.height() < locked_qc.height());
    let target = proposal(
        &set,
        shallow_high_qc.clone(),
        4,
        b"shadow shallower-fork unlock target",
    );

    let genesis_state = bootstrap.safety_state();
    let recovered_state = SafetyState::from_persisted_parts(
        SAFETY_STATE_SCHEMA_VERSION,
        genesis_state.chain_id(),
        genesis_state.protocol_version(),
        genesis_state.epoch(),
        genesis_state.validator_set_id(),
        genesis_state.genesis_block_id(),
        View::new(4),
        None,
        None,
        shallow_high_qc.clone().into_qc_reference(),
        locked_qc.clone().into_qc_reference(),
        genesis_state.finalized(),
        genesis_state.revision(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let mut recovered = Core::recover(config, recovered_state, &RootSignatures)
        .expect("view ordering permits a shallower high QC above a deeper lock");
    for proposed in [
        locked_parent,
        locked_child,
        shallow_high_proposal,
        target.clone(),
    ] {
        replay_valid(&mut recovered, proposed);
    }
    recovered
        .step(Input::SafetyReplayComplete, &RootSignatures)
        .expect("both exact fork paths satisfy recovery replay");

    let expected_high = QcRef::from(&shallow_high_qc);
    let expected_lock = QcRef::from(&locked_qc);
    let mut timeout_probe = recovered.clone();
    let timeout_effects = timeout_probe
        .step(
            Input::LocalTimeout {
                epoch: Epoch::new(0),
                view: View::new(4),
            },
            &RootSignatures,
        )
        .expect("the timeout shadow uses view-ordered QC strength");
    let (_barrier, timeout_state) = persistence_effect(&timeout_effects);
    assert_eq!(timeout_state.high_qc().qc_ref(), expected_high);
    assert_eq!(timeout_state.locked_qc().qc_ref(), expected_lock);
    assert!(matches!(
        timeout_state.pending_sign(),
        Some(SignIntent::TimeoutVote { high_qc, .. }) if *high_qc == expected_high
    ));

    let mut vote_probe = recovered.clone();
    assert!(vote_probe
        .stage_vote_validated_proposal_for_test_v1(&target, &RootSignatures)
        .expect("the higher-view shallow justify unlocks the deeper fork lock"));
    assert_eq!(vote_probe.safety_state().high_qc().qc_ref(), expected_high);
    assert_eq!(
        vote_probe.safety_state().locked_qc().qc_ref(),
        expected_lock
    );
    assert!(matches!(
        vote_probe.safety_state().pending_sign(),
        Some(SignIntent::Vote { block_id, .. }) if *block_id == target.block().id()
    ));
}

#[test]
fn safety_rules_shadow_timeout_uses_the_exact_complete_high_qc() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(&set, genesis_qc(&set), 1, b"shadow timeout high QC");
    let high_qc = qc(&set, 1, 1, proposed.block().id());
    insert_valid_and_vote(&mut core, proposed);
    accept_qc(&mut core, high_qc.clone());
    let expected_high_qc = QcRef::from(&high_qc);
    let epoch = core.safety_state().epoch();
    let view = core.safety_state().current_view();

    let effects = core
        .step(Input::LocalTimeout { epoch, view }, &RootSignatures)
        .expect("pure and legacy TimeoutVote candidates match");
    let (barrier, persisted) = persistence_effect(&effects);
    let transition = persistence_request(&effects)
        .safety_rules_shadow_transition_v1()
        .expect("timeout persistence carries the exact SafetyRules transition");
    assert_eq!(transition.successor_state().revision(), barrier.get());
    assert_eq!(
        transition.canonical_intent().signing_root(),
        persisted
            .pending_sign()
            .expect("timeout persistence retains its sign intent")
            .signing_root()
    );
    assert!(matches!(
        persisted.pending_sign(),
        Some(SignIntent::TimeoutVote {
            authorizing_safety_revision,
            view: pending_view,
            high_qc: pending_high_qc,
            ..
        }) if *authorizing_safety_revision == barrier.get()
            && *pending_view == view
            && *pending_high_qc == expected_high_qc
    ));
    let request = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("timeout persistence releases only the legacy signer request");
    assert!(matches!(
        request.as_slice(),
        [Effect::RequestSignature { intent }]
            if matches!(
                intent.preimage(),
                CanonicalSignPreimageV0::TimeoutVote(preimage)
                    if preimage.view() == view && preimage.high_qc() == expected_high_qc
            )
    ));
}

#[test]
fn core_safety_rules_authority_owns_timeout_and_fences_legacy_staging() {
    let (_config, mut core) = configured_core();
    let epoch = core.safety_state().epoch();
    let view = core.safety_state().current_view();
    let mut owner = core
        .issue_safety_rules_authority_v1(CoreAuthorityTransitionStore::default(), &RootSignatures)
        .expect("the live Core issues one SafetyRules owner");
    assert!(core.safety_rules_authority_issued_v1());
    assert!(matches!(
        core.issue_safety_rules_authority_v1(
            CoreAuthorityTransitionStore::default(),
            &RootSignatures
        ),
        Err(CoreError::Busy(
            "this Core instance already issued its SafetyRules authority"
        ))
    ));

    let commit = owner
        .authorize_timeout_v1(&core, epoch, view, &RootSignatures)
        .expect("the owner evaluates and durably records the timeout transition");
    assert_eq!(
        commit.transition().kind(),
        InertSafetyTransitionKindV1::TimeoutVote
    );
    let expected_digest = commit.transition().successor_state().digest();
    let effects = owner
        .commit_v1(&mut core, commit, &RootSignatures)
        .expect("the exact persisted timeout transition installs into Core");
    let (barrier, persisted) = persistence_effect(&effects);
    assert_eq!(
        persisted
            .pending_sign()
            .expect("timeout intent remains pending until StorageAck")
            .kind(),
        SignKind::TimeoutVote
    );
    assert_eq!(owner.state_digest(), expected_digest,);
    assert!(matches!(
        core.step(Input::LocalTimeout { epoch, view }, &RootSignatures),
        Err(CoreError::Busy(_))
    ));
    let request = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("Core releases the ordinary signer request after its barrier");
    assert!(matches!(
        request.as_slice(),
        [Effect::RequestSignature { .. }]
    ));
}

#[test]
fn core_safety_rules_authority_poisoning_and_core_affinity_fail_closed() {
    let (_config, core) = configured_core();
    let epoch = core.safety_state().epoch();
    let view = core.safety_state().current_view();
    let before = core.safety_state().clone();
    let mut owner = core
        .issue_safety_rules_authority_v1(
            CoreAuthorityTransitionStore {
                fail: true,
                ..CoreAuthorityTransitionStore::default()
            },
            &RootSignatures,
        )
        .expect("the owner opens before its store is exercised");
    assert!(matches!(
        owner.authorize_timeout_v1(&core, epoch, view, &RootSignatures),
        Err(CoreSafetyRulesAuthorityErrorV1::Persistence(
            "simulated Core authority persistence failure"
        ))
    ));
    assert!(owner.is_poisoned());
    assert_eq!(core.safety_state(), &before);
    assert!(matches!(
        owner.authorize_timeout_v1(&core, epoch, view, &RootSignatures),
        Err(CoreSafetyRulesAuthorityErrorV1::Poisoned)
    ));

    let (_other_config, other_core) = configured_core();
    let mut healthy_owner = other_core
        .issue_safety_rules_authority_v1(CoreAuthorityTransitionStore::default(), &RootSignatures)
        .expect("a separate Core issues an independent owner");
    assert!(matches!(
        healthy_owner.authorize_timeout_v1(&core, epoch, view, &RootSignatures),
        Err(CoreSafetyRulesAuthorityErrorV1::OwnerMismatch)
    ));
}

#[test]
fn safety_rules_shadow_vote_transition_is_carried_by_persistence_request() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(&set, genesis_qc(&set), 1, b"shadow vote carrier");
    let proposal_effects = core
        .step(Input::Proposal(Box::new(proposed)), &RootSignatures)
        .expect("proposal enters validation");
    let validation_effects = release_persisted_effects(&mut core, proposal_effects);
    let validation = validation_effect(&validation_effects);
    let result = valid_result_for_effect(&core, &validation_effects, validation);
    let vote_persistence = core
        .step(
            Input::PayloadValidated {
                id: validation,
                result,
            },
            &RootSignatures,
        )
        .expect("valid proposal stages its vote persistence");
    let request = persistence_request(&vote_persistence);
    let transition = request
        .safety_rules_shadow_transition_v1()
        .expect("vote persistence carries the exact SafetyRules shadow transition");
    assert_eq!(transition.kind(), InertSafetyTransitionKindV1::Vote);
    assert_eq!(
        transition.successor_state().revision(),
        request.barrier().get()
    );
    assert_eq!(
        transition.canonical_intent().authorizing_safety_revision(),
        request.barrier().get()
    );
    let pending_block_id = match request.state().pending_sign().expect("pending vote") {
        SignIntent::Vote { block_id, .. } => *block_id,
        SignIntent::TimeoutVote { .. } => panic!("vote persistence carried a timeout intent"),
    };
    assert_eq!(transition.vote_block_id(), Some(pending_block_id));
}

#[test]
fn safety_rules_shadow_missing_body_releases_aggregate_charge_and_fails_closed() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(&set, genesis_qc(&set), 1, b"shadow missing frozen body");
    let block_id = proposed.block().id();
    let proposal_effects = core
        .step(Input::Proposal(Box::new(proposed.clone())), &RootSignatures)
        .expect("proposal enters validation");
    let validation_effects = release_persisted_effects(&mut core, proposal_effects);
    let validation = validation_effect(&validation_effects);
    let valid = valid_result_for_effect(&core, &validation_effects, validation);

    let timeout_effects = core
        .step(
            Input::LocalTimeout {
                epoch: Epoch::new(0),
                view: View::new(1),
            },
            &RootSignatures,
        )
        .expect("timeout keeps the later Valid callback from staging a Vote");
    let (timeout_barrier, _) = persistence_effect(&timeout_effects);
    let timeout_request = core
        .step(
            Input::StorageAck {
                barrier: timeout_barrier,
            },
            &RootSignatures,
        )
        .expect("timeout persistence releases its signer request");
    let (timeout_id, timeout_root) = signature_request(&timeout_request);

    let callback_effects = core
        .step(
            Input::PayloadValidated {
                id: validation,
                result: valid,
            },
            &RootSignatures,
        )
        .expect("Valid body is frozen while the timeout signature is outstanding");
    let (callback_barrier, callback_state) = persistence_effect(&callback_effects);
    assert_eq!(
        callback_state.payload_terminal_result(block_id),
        Some(PayloadTerminalResult::Valid)
    );
    assert!(core
        .step(
            Input::StorageAck {
                barrier: callback_barrier,
            },
            &RootSignatures,
        )
        .expect("Valid callback is durable")
        .is_empty());
    let retained_before_forget = core.retained_validated_proposal_bytes_for_test_v1();
    assert!(retained_before_forget > 0);
    assert!(core
        .forget_validated_proposal_for_test_v1(block_id)
        .expect("test-only removal releases its aggregate charge"));
    assert_eq!(core.retained_validated_proposal_bytes_for_test_v1(), 0);
    assert!(core.retained_proposal_accounting_is_exact_for_test_v1());
    core.step(
        Input::SignatureReady {
            id: timeout_id,
            signature: signature(timeout_root),
        },
        &RootSignatures,
    )
    .expect("timeout signature clears the legacy signing outbox");

    let before = core.clone();
    assert_eq!(
        core.step(Input::Proposal(Box::new(proposed)), &RootSignatures),
        Err(CoreError::SafetyRulesShadowMismatch(
            "exact application-Valid ancestry is missing, unfrozen, or exceeds the shadow bound"
        ))
    );
    assert_eq!(core, before, "a shadow mismatch is transactional");
}
