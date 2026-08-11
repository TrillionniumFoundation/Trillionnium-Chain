use alloc::{boxed::Box, vec, vec::Vec};

use trnm_consensus_types::{
    decode_application_payload_v0_exact, decode_double_vote_evidence_v0_exact,
    ApplicationPayloadV0, Block, BlockBodyV0, BlockHeader, BlockId, BlockKind, CertificateId,
    CertifiedHeaderV0, ChainId, ConsensusParametersV0, ConsensusPublicKey, ContextAuthorizedQcV0,
    Epoch, EvidenceRoot, ExecutionReceiptCommitmentV0, ExecutionReceiptsV0, FinalityProofV0,
    GenesisHash, GenesisQcV0, Height, NextEpochCommitmentHash, PayloadDigest, ProposalWitnessV0,
    ProtocolVersion, QcRef, QcReferenceV0, QuorumCertificate, ReceiptsRoot, SignatureBytes,
    SignatureVerifier, SignedProposalV0, SigningRoot, StateRoot, TimeoutCertificateV0,
    TimeoutEntryV0, TimeoutVote, ValidatedBlockCommitmentsV0, ValidationError, Validator,
    ValidatorId, ValidatorSet, View, Vote, VotingPower, SIGNATURE_BYTES,
};

use crate::core::payload_parent_context_matches_target_v0;

use super::*;

const CHAIN: ChainId = ChainId::from_static("trnm-core-test-0");
const GENESIS: BlockId = BlockId::new([0xA5; 32]);
const GENESIS_TIMESTAMP_MS: u64 = 0;

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

fn assert_safety_state_record_roundtrip_and_validate(config: &CoreConfig, state: &SafetyState) {
    let decoded = roundtrip_safety_state_record(config, state);
    Core::validate_persisted_state_v0(config, &decoded, &RootSignatures)
        .expect("the decoded record remains a semantically valid inert SafetyState");
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
    let application_payload = decode_application_payload_v0_exact(
        block.application_payload(),
        core.config().consensus_parameters(),
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
            decode_double_vote_evidence_v0_exact(bytes, core.config().validator_set())
                .expect("core test block carries exact evidence CEV0")
        })
        .collect();
    let body = BlockBodyV0::new(application_payload, evidence).expect("canonical test block body");
    body.validate_ordinary_commitments(
        block.header(),
        &receipts,
        core.config().consensus_parameters(),
        core.config().validator_set(),
        &RootSignatures,
    )
    .expect("canonical core-test block mints the B2-D commitment capability")
}

fn valid_result(core: &Core, block: &Block) -> PayloadValidationResult {
    PayloadValidationResult::Valid {
        commitments: valid_commitments(core, block),
    }
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
        [Effect::PersistSafetyState { barrier, state }] => (*barrier, state.as_ref().clone()),
        _ => panic!("expected exactly one persistence effect: {effects:?}"),
    }
}

fn conflicting_qc_halt_persistence(
    effects: &[Effect],
    expected_first: &QuorumCertificate,
    expected_second: &QuorumCertificate,
) -> (BarrierId, SafetyState) {
    assert!(
        effects.iter().all(|effect| matches!(
            effect,
            Effect::PersistSafetyState { .. } | Effect::Evidence(_)
        )),
        "a QC-conflict step may expose only persistence plus diagnostic evidence: {effects:?}"
    );
    let mut persisted = effects.iter().filter_map(|effect| match effect {
        Effect::PersistSafetyState { barrier, state } => Some((*barrier, state.as_ref().clone())),
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
        [Effect::RequestSignature {
            id, signing_root, ..
        }] => (*id, *signing_root),
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
        Effect::PersistSafetyState { barrier, .. } => Some(*barrier),
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
    );
    assert_ne!(direct, opposite_route);

    let claimed = direct
        .try_claim()
        .unwrap_or_else(|_| panic!("direct request wins its fresh claim"));
    assert_eq!(claimed.route(), PayloadValidationRouteV0::Proposal);
    let (route, id, block, parent) = claimed.into_parts();
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
                        let (route, id, block, parent) = claimed.into_parts();
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

fn persisted_state_with_qcs<H: IntoQcReference, L: IntoQcReference>(
    state: &SafetyState,
    high_qc: H,
    locked_qc: L,
) -> SafetyState {
    SafetyState::from_persisted_parts(
        state.schema_version(),
        state.chain_id(),
        state.protocol_version(),
        state.epoch(),
        state.validator_set_id(),
        state.genesis_block_id(),
        state.current_view(),
        state.last_voted_view(),
        state.last_timeout_view(),
        high_qc.into_qc_reference(),
        locked_qc.into_qc_reference(),
        state.finalized(),
        state.revision(),
        state.payload_terminal_facts().to_vec(),
        state.payload_validation_obligations().to_vec(),
        state.payload_validation_completions().to_vec(),
        state.pending_tc_high_qc_sync().cloned(),
        state.pending_standalone_qc_sync().cloned(),
        state.pending_sign().cloned(),
        state.last_finalization().cloned(),
        state.pending_finalize(),
        state.safety_halt().cloned(),
    )
}

fn decoded_state_with_validation_records(
    state: &SafetyState,
    obligations: Vec<DurablePayloadValidationObligationV0>,
    completions: Vec<DurablePayloadValidationCompletionV0>,
) -> SafetyState {
    SafetyState::from_persisted_parts(
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
        state.revision(),
        state.payload_terminal_facts().to_vec(),
        obligations,
        completions,
        state.pending_tc_high_qc_sync().cloned(),
        state.pending_standalone_qc_sync().cloned(),
        state.pending_sign().cloned(),
        state.last_finalization().cloned(),
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
    SafetyState::from_persisted_parts(
        state.schema_version(),
        state.chain_id(),
        state.protocol_version(),
        state.epoch(),
        state.validator_set_id(),
        state.genesis_block_id(),
        current_view,
        last_voted_view,
        last_timeout_view,
        high_qc,
        locked_qc,
        finalized,
        state.revision(),
        state.payload_terminal_facts().to_vec(),
        vec![],
        state.payload_validation_completions().to_vec(),
        pending_tc_high_qc_sync,
        pending_standalone_qc_sync,
        pending_sign,
        last_finalization,
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
    facts.push(PayloadTerminalFact::new(
        block_id,
        PayloadTerminalResult::DeterministicallyInvalid,
        state.revision(),
    ));
    facts.sort_by_key(|fact| fact.block_id());
    let halt = SafetyHalt::deterministically_invalid_payload(block_id, reference)
        .expect("canonical invalid-payload halt witness");
    SafetyState::from_persisted_parts(
        state.schema_version(),
        state.chain_id(),
        state.protocol_version(),
        state.epoch(),
        state.validator_set_id(),
        state.genesis_block_id(),
        current_view,
        last_voted_view,
        last_timeout_view,
        state.high_qc().clone(),
        state.locked_qc().clone(),
        state.finalized(),
        state.revision(),
        facts,
        vec![],
        state.payload_validation_completions().to_vec(),
        None,
        None,
        None,
        state.last_finalization().cloned(),
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

fn finalize_height_one(core: &mut Core) -> (ValidatorSet, QuorumCertificate) {
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

    let proof_id = core
        .safety_state()
        .pending_finalize()
        .expect("height-one finality has a durable application outbox");
    let effects = core
        .step(Input::FinalizationApplied { proof_id }, &RootSignatures)
        .expect("height-one finality is applied");
    let effects = release_persisted_effects(core, effects);
    assert!(effects.is_empty());
    assert_eq!(core.safety_state().finalized().height(), Height::new(1));
    assert_eq!(
        core.safety_state().finalized().block_id(),
        first_qc.block_id()
    );
    (set, first_qc)
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
    let third =
        proposal_with_parameters(&set, &parameters, second_qc, 3, b"short epoch last regular");
    let third_qc = qc(&set, 3, 3, third.block().id());
    insert_valid_and_vote(&mut core, third);
    let effects = accept_qc(&mut core, third_qc.clone());
    assert!(effects
        .iter()
        .any(|effect| matches!(effect, Effect::Finalize(_))));
    let proof_id = core
        .safety_state()
        .pending_finalize()
        .expect("short epoch height-one finality is durable");
    let effects = core
        .step(Input::FinalizationApplied { proof_id }, &RootSignatures)
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
    assert_safety_state_record_roundtrip_and_validate(&config, &state);
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
    let proof_id = state.pending_finalize().expect("commit outbox");
    let effects = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("finality state durable");
    assert!(effects
        .iter()
        .any(|effect| matches!(effect, Effect::Finalize(_))));
    let effects = core
        .step(Input::FinalizationApplied { proof_id }, &RootSignatures)
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
    let (set, _finalized_qc) = finalize_height_one(&mut core);
    let stale = qc(&set, 7, 1, BlockId::new([0xD7; 32]));
    let before = core.safety_state().clone();

    assert!(core
        .step(Input::QuorumCertificate(stale.clone()), &RootSignatures,)
        .expect("different-view historical QC is operationally subsumed")
        .is_empty());
    assert_eq!(core.safety_state(), &before);
    assert!(core.safety_state().pending_standalone_qc_sync().is_none());

    assert!(core
        .step(Input::QuorumCertificate(stale), &RootSignatures)
        .expect("the same subsumed QC is idempotent")
        .is_empty());
    assert_eq!(core.safety_state(), &before);
}

#[test]
fn same_view_competitor_at_finalized_height_halts_before_subsumption_and_recovers() {
    let (config, mut core) = configured_core();
    let (set, finalized_qc) = finalize_height_one(&mut core);
    let conflict = qc(&set, 1, 1, BlockId::new([0xC1; 32]));

    let mut recovered_live =
        Core::recover(config.clone(), core.safety_state().clone(), &RootSignatures)
            .expect("finality proof and safety anchors recover before replay");
    let recovered_effects = recovered_live
        .step(Input::QuorumCertificate(conflict.clone()), &RootSignatures)
        .expect("durable proof QC detects the conflict even during recovery replay");
    assert!(recovered_effects.iter().any(|effect| matches!(
        effect,
        Effect::PersistSafetyState { state, .. }
            if matches!(
                state.safety_halt(),
                Some(SafetyHalt::ConflictingQuorumCertificates { .. })
            )
    )));

    let effects = core
        .step(Input::QuorumCertificate(conflict.clone()), &RootSignatures)
        .expect("same-view conflict crosses a durable halt before stale classification");
    let (barrier, halted) = effects
        .iter()
        .find_map(|effect| match effect {
            Effect::PersistSafetyState { barrier, state } => {
                Some((*barrier, state.as_ref().clone()))
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
    let (_config, mut core) = configured_core();
    let (set, _finalized_qc) = finalize_height_one(&mut core);
    let first = qc(&set, 7, 1, BlockId::new([0x71; 32]));
    let second = qc(&set, 7, 1, BlockId::new([0x72; 32]));

    assert!(core
        .step(Input::QuorumCertificate(first.clone()), &RootSignatures)
        .expect("first different-view historical QC is subsumed")
        .is_empty());
    let effects = core
        .step(Input::QuorumCertificate(second.clone()), &RootSignatures)
        .expect("second QC in that same historical view detects the conflict");
    let halted = effects
        .iter()
        .find_map(|effect| match effect {
            Effect::PersistSafetyState { state, .. } => Some(state.as_ref()),
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
fn finalized_block_id_with_a_different_qc_view_is_rejected_transactionally() {
    let (_config, mut core) = configured_core();
    let (set, finalized_qc) = finalize_height_one(&mut core);
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
    let (set, _finalized_qc) = finalize_height_one(&mut core);
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
    let proof_id = core
        .safety_state()
        .pending_finalize()
        .expect("height-two finality outbox");
    let effects = core
        .step(Input::FinalizationApplied { proof_id }, &RootSignatures)
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
    let (set, _finalized_qc) = finalize_height_one(&mut core);
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
    let (set, _finalized_qc) = finalize_height_one(&mut core);
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
    assert!(core
        .step(Input::QuorumCertificate(unrelated), &RootSignatures)
        .expect("unrelated historical QC is already subsumed")
        .is_empty());
    assert_eq!(core.safety_state(), &before);
    assert!(core.safety_state().pending_standalone_qc_sync().is_none());
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

    let (_set, _finalized_qc) = finalize_height_one(&mut core);
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
    let (set, _finalized_qc) = finalize_height_one(&mut core);
    let stale = qc(&set, 7, 1, BlockId::new([0xB7; 32]));
    let carrier = proposal(&set, stale, 8, b"subsumed carrier child");
    let before = core.safety_state().clone();

    assert!(core
        .step(Input::Proposal(Box::new(carrier)), &RootSignatures)
        .expect("missing stale parent is subsumed without a fetch loop")
        .is_empty());
    assert_eq!(core.safety_state(), &before);
    assert_eq!(core.pending_validation_count(), 0);
    assert!(core.safety_state().pending_tc_high_qc_sync().is_none());
    assert!(core.safety_state().pending_standalone_qc_sync().is_none());
}

#[test]
fn tc_reference_conflict_halts_before_subsumed_view_progress() {
    let (_config, mut core) = configured_core();
    let (set, _finalized_qc) = finalize_height_one(&mut core);
    let first = qc(&set, 7, 1, BlockId::new([0xE1; 32]));
    let second = qc(&set, 7, 1, BlockId::new([0xE2; 32]));
    assert!(core
        .step(Input::QuorumCertificate(first), &RootSignatures)
        .expect("first historical QC is observed and subsumed")
        .is_empty());
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
            Effect::PersistSafetyState { state, .. } => Some(state.as_ref()),
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
            Effect::PersistSafetyState { state, .. } => Some(state.as_ref()),
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
            Effect::PersistSafetyState { state, .. } => Some(state.as_ref()),
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
            Effect::PersistSafetyState { state, .. } => Some(state.as_ref()),
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
            Effect::PersistSafetyState { state, .. } => Some(state.as_ref()),
            _ => None,
        })
        .expect("pending-finalize conflict persists its halt");
    assert!(halted.pending_finalize().is_none());
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
            Effect::PersistSafetyState { state, .. } => Some(state.as_ref()),
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
    let proof_id = core
        .safety_state()
        .pending_finalize()
        .expect("application finalization remains outstanding");
    let effects = core
        .step(Input::FinalizationApplied { proof_id }, &RootSignatures)
        .expect("application finalization is acknowledged");
    let (vote_barrier, vote_state) = persistence_effect(&effects);
    assert!(vote_state.pending_finalize().is_none());
    assert!(matches!(
        vote_state.pending_sign(),
        Some(SignIntent::Vote { block_id, .. }) if *block_id == validation.block_id()
    ));

    // A crash after the atomic finalization-clear/vote-intent write resumes
    // precisely that durable signing root; it does not need a proposal
    // retransmission or a second safety transition.
    let mut recovered = Core::recover(core.config().clone(), vote_state.clone(), &RootSignatures)
        .expect("the atomic vote intent is recoverable");
    assert!(matches!(
        recovered
            .step(Input::Resume, &RootSignatures)
            .expect("recovery resumes the exact persisted vote")
            .as_slice(),
        [Effect::RequestSignature { .. }]
    ));

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

    let proof_id = core
        .safety_state()
        .pending_finalize()
        .expect("application finalization remains outstanding");
    let effects = core
        .step(Input::FinalizationApplied { proof_id }, &RootSignatures)
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

    let mut recovered =
        Core::recover(config, gated, &RootSignatures).expect("durable finalization recovers");
    assert_eq!(
        recovered.safety_state().payload_validation_completions(),
        expected_completions
    );
    assert!(recovered
        .safety_state()
        .payload_validation_completions()
        .contains(&expected_completion));
    assert!(recovered
        .step(
            Input::PayloadValidated {
                id: validation,
                result,
            },
            &RootSignatures,
        )
        .expect("the exact Valid completion remains idempotent after recovery")
        .is_empty());
    let proof_id = recovered
        .safety_state()
        .pending_finalize()
        .expect("the exact finalization outbox survives recovery");
    assert!(matches!(
        recovered
            .step(Input::Resume, &RootSignatures)
            .expect("recovery first resumes finalization")
            .as_slice(),
        [Effect::Finalize(proof)] if proof.id() == proof_id
    ));
    let effects = recovered
        .step(Input::FinalizationApplied { proof_id }, &RootSignatures)
        .expect("the recovered application acknowledgement is accepted");
    let (barrier, cleared) = persistence_effect(&effects);
    assert!(cleared.pending_finalize().is_none());
    assert!(cleared.pending_sign().is_none());
    assert!(recovered
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("the recovered acknowledgement is durable")
        .is_empty());
    assert!(matches!(
        recovered
            .step(Input::Resume, &RootSignatures)
            .expect("canonical bodies must be replayed after recovery")
            .as_slice(),
        [Effect::RequestSafetyReplay { .. }]
    ));
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
    assert!(halted.pending_finalize().is_none());
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

    let proof_id = core
        .safety_state()
        .pending_finalize()
        .expect("application finalization is still outstanding");
    let effects = core
        .step(Input::FinalizationApplied { proof_id }, &RootSignatures)
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
    let proof_id = durable.pending_finalize().expect("first finalize outbox");
    core.step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("first finalization is durable");
    let effects = core
        .step(Input::FinalizationApplied { proof_id }, &RootSignatures)
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
    let proof_id = completed
        .pending_finalize()
        .expect("the TC-created finality outbox is durable");

    let effects = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("TC, finality, and queue drain share one durable boundary");
    assert!(effects
        .iter()
        .any(|effect| matches!(effect, Effect::Finalize(_))));
    assert!(!effects
        .iter()
        .any(|effect| matches!(effect, Effect::RequestStandaloneQcSync { .. })));
    let effects = core
        .step(Input::FinalizationApplied { proof_id }, &RootSignatures)
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
    let recovered_before_ack = Core::recover(config.clone(), durable.clone(), &RootSignatures)
        .expect("the durable Valid fact recovers if the process crashes before observing the ack");
    assert_eq!(
        recovered_before_ack
            .safety_state()
            .payload_terminal_result(proposed.block().id()),
        Some(PayloadTerminalResult::Valid)
    );
    assert!(core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("Valid fact persisted")
        .is_empty());

    let mut recovered =
        Core::recover(config, durable, &RootSignatures).expect("Valid fact recovers after the ack");
    let effects = recovered
        .step(Input::SyncedProposal(Box::new(proposed)), &RootSignatures)
        .expect("a newly sourced body still enters the host boundary");
    let effects = release_persisted_effects(&mut recovered, effects);
    let recovered_id = synced_validation_effect(&effects);
    assert!(recovered_id.generation() > first_id.generation());
    assert_eq!(recovered.safety_state().last_voted_view(), None);
    assert!(recovered.safety_state().pending_sign().is_none());
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
    let valid_fact = vote_state.payload_terminal_facts()[0];
    let invalid_fact = PayloadTerminalFact::new(
        valid_fact.block_id(),
        PayloadTerminalResult::DeterministicallyInvalid,
        valid_fact.first_recorded_revision(),
    );
    let tampered = SafetyState::from_persisted_parts(
        vote_state.schema_version(),
        vote_state.chain_id(),
        vote_state.protocol_version(),
        vote_state.epoch(),
        vote_state.validator_set_id(),
        vote_state.genesis_block_id(),
        vote_state.current_view(),
        vote_state.last_voted_view(),
        vote_state.last_timeout_view(),
        vote_state.high_qc().clone(),
        vote_state.locked_qc().clone(),
        vote_state.finalized(),
        vote_state.revision(),
        vec![invalid_fact],
        vec![],
        vote_state.payload_validation_completions().to_vec(),
        vote_state.pending_tc_high_qc_sync().cloned(),
        vote_state.pending_standalone_qc_sync().cloned(),
        vote_state.pending_sign().cloned(),
        vote_state.last_finalization().cloned(),
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
    const GENESIS_OBLIGATION_FIXED_BYTES: usize = 1 + (32 + 8 + 8) + 4 + (8 + 8 + 32 + 8) + 1 + 8;
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
    let decoded = SafetyState::from_persisted_parts(
        SAFETY_STATE_SCHEMA_VERSION,
        state.chain_id(),
        state.protocol_version(),
        state.epoch(),
        state.validator_set_id(),
        state.genesis_block_id(),
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
        state.payload_terminal_facts().to_vec(),
        vec![],
        state.payload_validation_completions().to_vec(),
        state.pending_tc_high_qc_sync().cloned(),
        state.pending_standalone_qc_sync().cloned(),
        state.pending_sign().cloned(),
        None,
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
fn recovery_rejects_pre_v7_safety_state_without_inert_completion_snapshots() {
    let (config, core) = configured_core();
    let state = core.safety_state();
    assert_eq!(SAFETY_STATE_SCHEMA_VERSION, 7);
    for legacy_schema in [5, 6] {
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
    assert!(matches!(
        restarted
            .step(Input::Resume, &RootSignatures)
            .expect("reissue finalization")
            .as_slice(),
        [Effect::Finalize(_)]
    ));
    let effects = restarted
        .step(Input::FinalizationApplied { proof_id }, &RootSignatures)
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
    let proof_id = state.pending_finalize().expect("first finality outbox");
    original
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("first finality state durable");
    let effects = original
        .step(Input::FinalizationApplied { proof_id }, &RootSignatures)
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
    let proof_id = state.pending_finalize().expect("second finality outbox");
    original
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("second finality state durable");
    let effects = original
        .step(Input::FinalizationApplied { proof_id }, &RootSignatures)
        .expect("second finality applied");
    let (barrier, durable) = persistence_effect(&effects);
    original
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("second finality acknowledgement durable");

    let mut recovered =
        Core::recover(config, durable, &RootSignatures).expect("finalized state recovers");
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
    let mut recovered_completed = Core::recover(config, completed_state, &RootSignatures)
        .expect("the completed but unacknowledged transition recovers");
    assert!(recovered_completed
        .safety_state()
        .pending_tc_high_qc_sync()
        .is_none());
    assert!(matches!(
        recovered_completed
            .step(Input::Resume, &RootSignatures)
            .expect("the exact unacknowledged finality is replayed")
            .as_slice(),
        [Effect::Finalize(proof)] if proof.id() == proof_id
    ));
    assert!(recovered_completed
        .safety_state()
        .pending_tc_high_qc_sync()
        .is_none());

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
fn one_tc_coalesces_multiple_monotonic_finality_steps_into_the_latest_proof() {
    let (_config, mut core) = configured_core();
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
    let latest = finalized
        .last_finalization_proof()
        .expect("latest proof permanently covers the new finalized tip");
    assert_eq!(latest.finalized_block().header().id(), p2.block().id());
    let proof_id = finalized
        .pending_finalize()
        .expect("one coalesced finality outbox is durable");

    let effects = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("the coalesced proof is emitted after persistence");
    assert_eq!(
        effects
            .iter()
            .filter(|effect| matches!(effect, Effect::Finalize(_)))
            .count(),
        1
    );
    assert!(effects.iter().any(|effect| matches!(
        effect,
        Effect::Finalize(proof)
            if proof.id() == proof_id
                && proof.finalized_block().header().id() == p2.block().id()
    )));
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
            Effect::PersistSafetyState { state, .. } => Some(state.as_ref()),
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
            Effect::PersistSafetyState { barrier, state } => {
                Some((*barrier, state.as_ref().clone()))
            }
            _ => None,
        })
        .expect("halt state persistence");
    let halt = state.safety_halt().expect("durable safety halt");
    let (halt_first, halt_second) = halt.conflicting_qcs().expect("conflicting QC halt");
    assert_ne!(halt_first.block_id(), halt_second.block_id());
    assert_safety_state_record_roundtrip_and_validate(&config, &state);
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
    let decoded = SafetyState::from_persisted_parts(
        SAFETY_STATE_SCHEMA_VERSION,
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
        state.payload_validation_completions().to_vec(),
        state.pending_tc_high_qc_sync().cloned(),
        state.pending_standalone_qc_sync().cloned(),
        state.pending_sign().cloned(),
        state.last_finalization().cloned(),
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
            Effect::PersistSafetyState { barrier, state } => {
                Some((*barrier, state.as_ref().clone()))
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
