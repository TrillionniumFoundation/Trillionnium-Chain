use alloc::{boxed::Box, vec::Vec};

use trnm_consensus_types::{
    Block, BlockHeader, BlockId, BlockKind, ChainId, ConsensusParametersHash, ConsensusPublicKey,
    Epoch, EvidenceRoot, GenesisHash, Height, PayloadDigest, Proposal, ProposalJustification,
    ProtocolVersion, QcRef, QuorumCertificate, ReceiptsRoot, SignatureBytes, SignatureVerifier,
    SigningRoot, StateRoot, TimeoutCertificate, TimeoutVote, Validator, ValidatorId, ValidatorSet,
    View, Vote, VotingPower, SIGNATURE_BYTES,
};

use super::*;

const CHAIN: ChainId = ChainId::from_static("trnm-core-test-0");
const GENESIS: BlockId = BlockId::new([0x42; 32]);

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

fn version() -> ProtocolVersion {
    ProtocolVersion::V0
}

fn validator_id(index: u8) -> ValidatorId {
    ValidatorId::new([index; 32])
}

fn validator_set() -> ValidatorSet {
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
        ConsensusParametersHash::new([0x5A; 32]),
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

fn genesis_qc(set: &ValidatorSet) -> QuorumCertificate {
    qc(set, 0, 0, GENESIS)
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
    let payload_marker = payload
        .first()
        .copied()
        .unwrap_or_default()
        .wrapping_add(height as u8);
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
        PayloadDigest::new([payload_marker; 32]),
        StateRoot::new([height as u8; 32]),
        ReceiptsRoot::new([height as u8; 32]),
        EvidenceRoot::new([height as u8; 32]),
        timestamp_ms,
        None,
    )
    .expect("valid header");
    Block::new(header, payload.to_vec()).expect("payload matches header")
}

fn proposal_with_proposer(
    set: &ValidatorSet,
    justify: QuorumCertificate,
    view: u64,
    payload: &[u8],
    proposer: ValidatorId,
) -> Proposal {
    let proposed = block(
        set,
        view,
        justify.height().get() + 1,
        justify.block_id(),
        payload,
        proposer,
    );
    let justification = ProposalJustification::quorum(justify);
    let root = Proposal::signing_root_for(&proposed, &justification, None, set)
        .expect("valid proposal signing context");
    Proposal::new(proposed, justification, proposer, signature(root), set).expect("valid proposal")
}

fn proposal(set: &ValidatorSet, justify: QuorumCertificate, view: u64, payload: &[u8]) -> Proposal {
    proposal_with_proposer(
        set,
        justify,
        view,
        payload,
        leader_for(set, View::new(view)),
    )
}

fn proposal_from_block(
    set: &ValidatorSet,
    proposed: Block,
    justify: QuorumCertificate,
) -> Proposal {
    let proposer = proposed.header().proposer_id();
    let justification = ProposalJustification::quorum(justify);
    let root = Proposal::signing_root_for(&proposed, &justification, None, set)
        .expect("valid proposal signing context");
    Proposal::new(proposed, justification, proposer, signature(root), set).expect("valid proposal")
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

fn timeout_certificate(
    set: &ValidatorSet,
    view: u64,
    high_qc: QuorumCertificate,
) -> TimeoutCertificate {
    let high_ref = QcRef::from(&high_qc);
    let votes = (1..=3)
        .map(|author| timeout_vote(set, view, high_ref, validator_id(author)))
        .collect();
    TimeoutCertificate::new(
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(view),
        set.id(),
        high_qc,
        votes,
        set,
    )
    .expect("valid TC")
}

fn timeout_proposal(
    set: &ValidatorSet,
    certificate: TimeoutCertificate,
    payload: &[u8],
) -> Proposal {
    let view = certificate
        .view()
        .checked_next()
        .expect("test view does not overflow");
    let high_qc = certificate.high_qc();
    let proposer = leader_for(set, view);
    let proposed = block(
        set,
        view.get(),
        high_qc.height().get() + 1,
        high_qc.block_id(),
        payload,
        proposer,
    );
    let justification = ProposalJustification::timeout(certificate);
    let root = Proposal::signing_root_for(&proposed, &justification, None, set)
        .expect("valid timeout proposal signing context");
    Proposal::new(proposed, justification, proposer, signature(root), set)
        .expect("valid timeout-justified proposal")
}

fn configured_core() -> (CoreConfig, Core) {
    let set = validator_set();
    let config = CoreConfig::new(
        validator_id(1),
        set.clone(),
        GENESIS,
        32,
        64,
        4 * 1024 * 1024,
        1_000,
    )
    .expect("valid config");
    let core =
        Core::new(config.clone(), genesis_qc(&set), &RootSignatures).expect("valid bootstrap");
    (config, core)
}

fn validation_effect(effects: &[Effect]) -> ValidationId {
    effects
        .iter()
        .find_map(|effect| match effect {
            Effect::ValidatePayload { id, .. } => Some(*id),
            _ => None,
        })
        .unwrap_or_else(|| panic!("expected a payload-validation effect: {effects:?}"))
}

fn persistence_effect(effects: &[Effect]) -> (BarrierId, SafetyState) {
    match effects {
        [Effect::PersistSafetyState { barrier, state }] => (*barrier, state.as_ref().clone()),
        _ => panic!("expected exactly one persistence effect: {effects:?}"),
    }
}

fn signature_request(effects: &[Effect]) -> (SignId, SigningRoot) {
    match effects {
        [Effect::RequestSignature {
            id, signing_root, ..
        }] => (*id, *signing_root),
        _ => panic!("expected exactly one signature request: {effects:?}"),
    }
}

fn insert_valid_and_vote(core: &mut Core, proposal: Proposal) {
    let effects = core
        .step(Input::Proposal(Box::new(proposal)), &RootSignatures)
        .expect("proposal accepted");
    let effects = release_persisted_effects(core, effects);
    let id = validation_effect(&effects);
    let effects = core
        .step(Input::PayloadValidated { id, valid: true }, &RootSignatures)
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

fn replay_valid(core: &mut Core, proposal: Proposal) {
    let effects = core
        .step(Input::Proposal(Box::new(proposal)), &RootSignatures)
        .expect("replay proposal accepted");
    let effects = release_persisted_effects(core, effects);
    let id = match effects.as_slice() {
        [Effect::ValidateSyncedPayload { id, .. }] => *id,
        _ => panic!("expected synced-payload validation: {effects:?}"),
    };
    assert!(core
        .step(
            Input::SyncedPayloadValidated { id, valid: true },
            &RootSignatures,
        )
        .expect("replay payload accepted")
        .is_empty());
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

fn persisted_state_with_qcs(
    state: &SafetyState,
    high_qc: QuorumCertificate,
    locked_qc: QuorumCertificate,
) -> SafetyState {
    SafetyState::from_persisted_parts(
        state.chain_id(),
        state.protocol_version(),
        state.epoch(),
        state.validator_set_id(),
        state.genesis_block_id(),
        state.current_view(),
        state.last_voted_view(),
        state.last_timeout_view(),
        high_qc,
        locked_qc,
        state.finalized(),
        state.revision(),
        state.pending_sign().cloned(),
        state.last_finalization_proof().cloned(),
        state.pending_finalize().cloned(),
        state.safety_halt().cloned(),
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

#[test]
fn vote_signing_is_persist_ack_sign_verify_broadcast() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set();
    let proposal = proposal(set, genesis_qc(set), 1, b"one");
    let effects = core
        .step(Input::Proposal(Box::new(proposal)), &RootSignatures)
        .expect("proposal accepted");
    let effects = release_persisted_effects(&mut core, effects);
    let validation = validation_effect(&effects);

    let effects = core
        .step(
            Input::PayloadValidated {
                id: validation,
                valid: true,
            },
            &RootSignatures,
        )
        .expect("valid payload accepted");
    let (barrier, persisted) = persistence_effect(&effects);
    assert!(persisted.pending_sign().is_some());
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
    let (_config, mut core) = configured_core();
    let effects = core
        .step(
            Input::LocalTimeout {
                epoch: Epoch::new(0),
                view: View::new(1),
            },
            &RootSignatures,
        )
        .expect("timeout accepted");
    let (barrier, _) = persistence_effect(&effects);
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
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set();
    let wrong = validator_id(2);
    assert_ne!(wrong, leader_for(set, View::new(1)));
    let proposal = proposal_with_proposer(set, genesis_qc(set), 1, b"wrong", wrong);
    assert!(matches!(
        core.step(Input::Proposal(Box::new(proposal)), &RootSignatures),
        Err(CoreError::UnexpectedLeader { .. })
    ));
}

#[test]
fn a_qc_proposal_cannot_skip_views_without_a_timeout_certificate() {
    let set = validator_set();
    let proposer = leader_for(&set, View::new(9));
    let proposed = block(&set, 9, 1, GENESIS, b"view skip", proposer);
    let justification = ProposalJustification::quorum(genesis_qc(&set));
    let root = Proposal::signing_root_for(&proposed, &justification, None, &set)
        .expect("signing root remains total over the candidate fields");
    assert!(Proposal::new(proposed, justification, proposer, signature(root), &set).is_err());
}

#[test]
fn a_qc_never_finalizes_without_a_complete_verified_three_chain() {
    let (_config, mut core) = configured_core();
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
    assert_eq!(proof.committed().id(), committed_id);
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
    let proof_id = state.pending_finalize().expect("commit outbox").id();
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
    assert_eq!(
        core.step(Input::QuorumCertificate(unknown), &RootSignatures),
        Err(CoreError::MissingBlock(BlockId::new([0xD4; 32])))
    );
    assert_eq!(core.safety_state().high_qc().id(), q3.id());
    assert_eq!(core.safety_state().finalized().block_id(), finalized_id);
}

#[test]
fn a_qc_cannot_override_local_payload_invalidity() {
    let (_config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let proposed = proposal(&set, genesis_qc(&set), 1, b"invalid application payload");
    let certificate = qc(&set, 1, 1, proposed.block().id());
    let effects = core
        .step(Input::Proposal(Box::new(proposed)), &RootSignatures)
        .expect("proposal received");
    let effects = release_persisted_effects(&mut core, effects);
    let validation = validation_effect(&effects);
    assert!(core
        .step(
            Input::PayloadValidated {
                id: validation,
                valid: false,
            },
            &RootSignatures,
        )
        .expect("invalid result consumed")
        .is_empty());
    assert_eq!(
        core.step(Input::QuorumCertificate(certificate), &RootSignatures,),
        Err(CoreError::ConflictingCertificate)
    );
    assert_eq!(core.safety_state().finalized().block_id(), GENESIS);
}

#[test]
fn validation_tokens_are_durable_non_reusable_and_payload_validity_is_sticky() {
    let (config, mut core) = configured_core();
    let set = core.config().validator_set().clone();
    let first = proposal(&set, genesis_qc(&set), 1, b"first-invalid");

    let effects = core
        .step(Input::Proposal(Box::new(first.clone())), &RootSignatures)
        .expect("first proposal received");
    let (barrier, durable_request) = persistence_effect(&effects);
    let effects = core
        .step(Input::StorageAck { barrier }, &RootSignatures)
        .expect("validation token made durable");
    let first_id = validation_effect(&effects);
    assert!(first_id.generation() <= durable_request.revision());
    let mut recovered = Core::recover(config, durable_request, &RootSignatures)
        .expect("durable validation generation recovers");
    let effects = recovered
        .step(Input::Proposal(Box::new(first.clone())), &RootSignatures)
        .expect("proposal is revalidated after restart");
    let effects = release_persisted_effects(&mut recovered, effects);
    let recovered_id = validation_effect(&effects);
    assert!(recovered_id.generation() > first_id.generation());
    assert_eq!(
        recovered.step(
            Input::PayloadValidated {
                id: first_id,
                valid: true,
            },
            &RootSignatures,
        ),
        Err(CoreError::UnknownValidation(first_id.block_id()))
    );
    assert!(recovered
        .step(
            Input::PayloadValidated {
                id: recovered_id,
                valid: false,
            },
            &RootSignatures,
        )
        .expect("current validation result remains usable")
        .is_empty());
    assert!(recovered
        .step(Input::Proposal(Box::new(first)), &RootSignatures)
        .expect("known-invalid proposal is not revalidated")
        .is_empty());
}

#[test]
fn oversized_blocks_and_invalid_timestamp_steps_are_rejected_before_validation() {
    let set = validator_set();
    let small_config = CoreConfig::new(validator_id(1), set.clone(), GENESIS, 32, 64, 3, 1_000)
        .expect("valid bounded config");
    let mut small_core =
        Core::new(small_config, genesis_qc(&set), &RootSignatures).expect("valid bounded core");
    let oversized = proposal(&set, genesis_qc(&set), 1, b"four");
    assert_eq!(
        small_core.step(Input::Proposal(Box::new(oversized)), &RootSignatures),
        Err(CoreError::BlockTooLarge {
            actual: 4,
            maximum: 3,
        })
    );

    let (_config, mut core) = configured_core();
    let proposer = leader_for(&set, View::new(1));
    let late_block = block_with_timestamp(&set, 1, 1, GENESIS, b"late", proposer, 1_001);
    let late = proposal_from_block(&set, late_block, genesis_qc(&set));
    assert_eq!(
        core.step(Input::Proposal(Box::new(late)), &RootSignatures),
        Err(CoreError::UnsafeProposal)
    );
    assert_eq!(core.pending_validation_count(), 0);
}

#[test]
fn recovery_rejects_an_anchor_header_with_an_invalid_finalized_timestamp_edge() {
    let (config, bootstrap) = configured_core();
    let set = bootstrap.config().validator_set().clone();
    let proposer = leader_for(&set, View::new(1));
    let late_block = block_with_timestamp(&set, 1, 1, GENESIS, b"late", proposer, 1_001);
    let late_proposal = proposal_from_block(&set, late_block, genesis_qc(&set));
    let high_qc = qc(&set, 1, 1, late_proposal.block().id());
    let genesis = bootstrap.safety_state();
    let recovered_state = SafetyState::from_persisted_parts(
        genesis.chain_id(),
        genesis.protocol_version(),
        genesis.epoch(),
        genesis.validator_set_id(),
        genesis.genesis_block_id(),
        View::new(2),
        None,
        None,
        high_qc,
        genesis.locked_qc().clone(),
        genesis.finalized(),
        genesis.revision(),
        None,
        None,
        None,
        None,
    );
    let mut recovered = Core::recover(config, recovered_state, &RootSignatures)
        .expect("QC-only state requires header replay");
    assert_eq!(
        recovered.step(Input::Proposal(Box::new(late_proposal)), &RootSignatures),
        Err(CoreError::UnsafeProposal)
    );
    assert!(matches!(
        recovered.step(Input::SafetyReplayComplete, &RootSignatures),
        Err(CoreError::InvalidRecovery(_))
    ));
}

#[test]
fn recovery_rejects_a_finalized_tip_without_its_permanent_proof() {
    let (config, core) = configured_core();
    let state = core.safety_state();
    let decoded = SafetyState::from_persisted_parts(
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
        FinalizedTip::new(Height::new(0), View::new(0), GENESIS, 1),
        state.revision(),
        state.pending_sign().cloned(),
        None,
        state.pending_finalize().cloned(),
        state.safety_halt().cloned(),
    );
    assert!(matches!(
        Core::recover(config, decoded, &RootSignatures),
        Err(CoreError::InvalidRecovery(_))
    ));
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
        genesis.chain_id(),
        genesis.protocol_version(),
        genesis.epoch(),
        genesis.validator_set_id(),
        genesis.genesis_block_id(),
        View::new(3),
        None,
        None,
        high_qc,
        locked_qc,
        genesis.finalized(),
        genesis.revision(),
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
        QcRef::from(recovered.safety_state().high_qc())
    );
    assert_eq!(
        replay_request.2,
        QcRef::from(recovered.safety_state().locked_qc())
    );
    assert!(matches!(
        recovered.step(Input::SafetyReplayComplete, &RootSignatures),
        Err(CoreError::InvalidRecovery(_))
    ));
    assert_eq!(
        recovered.step(Input::Proposal(Box::new(p2.clone())), &RootSignatures),
        Err(CoreError::MissingBlock(p2.block().header().parent_id()))
    );
    replay_valid(&mut recovered, p1);
    assert!(matches!(
        recovered.step(Input::SafetyReplayComplete, &RootSignatures),
        Err(CoreError::InvalidRecovery(_))
    ));
    replay_valid(&mut recovered, p2);
    assert!(matches!(
        recovered
            .step(Input::SafetyReplayComplete, &RootSignatures)
            .expect("verified replay completed")
            .as_slice(),
        [Effect::ArmViewTimer { .. }]
    ));

    let p3 = proposal(&set, q2, 3, b"three");
    let q3 = qc(&set, 3, 3, p3.block().id());
    insert_valid_and_vote(&mut recovered, p3);
    let effects = recovered
        .step(Input::QuorumCertificate(q3), &RootSignatures)
        .expect("third QC accepted after replay");
    let (_barrier, state) = persistence_effect(&effects);
    assert_eq!(state.finalized().block_id(), committed_id);
    let proof_id = state
        .pending_finalize()
        .expect("durable commit outbox")
        .id();

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
    assert_ne!(halt.first().block_id(), halt.second().block_id());
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
        state.pending_sign().cloned(),
        state.last_finalization_proof().cloned(),
        state.pending_finalize().cloned(),
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
    assert_eq!(halt.first().view(), View::new(1));
    assert_eq!(halt.second().view(), View::new(1));
    assert_ne!(halt.first().block_id(), halt.second().block_id());
}

#[test]
fn alternate_qc_encodings_for_one_block_choose_the_max_digest_without_halting() {
    let set = validator_set();
    let first = qc_with_authors(&set, 0, 0, GENESIS, &[1, 2, 3]);
    let second = qc_with_authors(&set, 0, 0, GENESIS, &[2, 3, 4]);
    assert_ne!(first.id(), second.id());
    let (lower, higher) = if first.id() < second.id() {
        (first, second)
    } else {
        (second, first)
    };
    let config = CoreConfig::new(
        validator_id(1),
        set.clone(),
        GENESIS,
        32,
        64,
        4 * 1024 * 1024,
        1_000,
    )
    .expect("valid config");
    let mut core = Core::new(config, lower, &RootSignatures).expect("lower QC bootstraps");

    let effects = core
        .step(Input::QuorumCertificate(higher.clone()), &RootSignatures)
        .expect("alternate signer subset is not a safety conflict");
    let (_barrier, state) = persistence_effect(&effects);
    assert_eq!(state.high_qc().id(), higher.id());
    assert!(state.safety_halt().is_none());
}

#[test]
fn duplicate_block_justifications_keep_the_max_qc_digest_for_locking() {
    let set = validator_set();
    let first = qc_with_authors(&set, 0, 0, GENESIS, &[1, 2, 3]);
    let second = qc_with_authors(&set, 0, 0, GENESIS, &[2, 3, 4]);
    let (lower, higher) = if first.id() < second.id() {
        (first, second)
    } else {
        (second, first)
    };
    let config = CoreConfig::new(
        validator_id(1),
        set.clone(),
        GENESIS,
        32,
        64,
        4 * 1024 * 1024,
        1_000,
    )
    .expect("valid config");
    let mut core = Core::new(config, lower.clone(), &RootSignatures).expect("lower QC bootstraps");
    let proposer = leader_for(&set, View::new(1));
    let proposed = block(&set, 1, 1, GENESIS, b"same header", proposer);
    let lower_proposal = proposal_from_block(&set, proposed.clone(), lower);
    let higher_proposal = proposal_from_block(&set, proposed, higher.clone());

    let effects = core
        .step(Input::Proposal(Box::new(lower_proposal)), &RootSignatures)
        .expect("first proposal accepted");
    let effects = release_persisted_effects(&mut core, effects);
    let validation = validation_effect(&effects);
    let effects = core
        .step(Input::Proposal(Box::new(higher_proposal)), &RootSignatures)
        .expect("alternate justification accepted");
    let _ = release_persisted_effects(&mut core, effects);

    let effects = core
        .step(
            Input::PayloadValidated {
                id: validation,
                valid: true,
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

    let certificate = qc(&set, 1, 1, validation.block_id());
    let effects = core
        .step(Input::QuorumCertificate(certificate), &RootSignatures)
        .expect("child QC accepted");
    let (_barrier, state) = persistence_effect(&effects);
    assert_eq!(state.locked_qc().id(), higher.id());
    assert!(state.safety_halt().is_none());
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
    assert_eq!(core.safety_state().locked_qc().block_id(), q1.block_id());

    let fork = timeout_proposal(&set, timeout_certificate(&set, 2, genesis), b"fork");
    let effects = core
        .step(Input::Proposal(Box::new(fork)), &RootSignatures)
        .expect("fork proposal received");
    let effects = release_persisted_effects(&mut core, effects);
    let validation = validation_effect(&effects);
    assert!(core
        .step(
            Input::PayloadValidated {
                id: validation,
                valid: true,
            },
            &RootSignatures,
        )
        .expect("unsafe proposal is consumed without voting")
        .is_empty());
    assert_eq!(core.pending_validation_count(), 0);
}
