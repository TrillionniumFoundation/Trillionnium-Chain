use alloc::{vec, vec::Vec};

use trnm_consensus_types::{
    Block, BlockHeader, CanonicalSignPreimageV0, ConsensusPublicKey, EvidenceRoot, PayloadDigest,
    ProposalWitnessV0, QuorumCertificate, ReceiptsRoot, SignatureBytes, SigningRoot, StateRoot,
    TimeoutCertificateV0, TimeoutEntryV0, TimeoutVote, Validator, Vote, VotingPower,
    SIGNATURE_BYTES,
};

use super::*;

const CHAIN: ChainId = ChainId::from_static("trnm-safety-rules-test");

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

fn parameters() -> ConsensusParametersV0 {
    ConsensusParametersV0::reference_shadow_v0()
}

fn validator_id(index: u8) -> ValidatorId {
    ValidatorId::new([index; 32])
}

fn validator_set(parameters: &ConsensusParametersV0) -> ValidatorSet {
    let validators = (1u8..=4)
        .map(|index| {
            Validator::new(
                validator_id(index),
                ConsensusPublicKey::new([index + 100; 32]),
                VotingPower::new(1).expect("positive power"),
            )
            .expect("valid validator")
        })
        .collect();
    ValidatorSet::new(
        GenesisHash::new([0xA5; 32]),
        CHAIN,
        ProtocolVersion::V0,
        Epoch::new(0),
        parameters.hash(),
        validators,
    )
    .expect("valid set")
}

fn context_with_bound(bound: u32) -> SafetyRulesContextV1 {
    let parameters = parameters();
    let set = validator_set(&parameters);
    SafetyRulesContextV1::new(set, parameters, validator_id(1), 0, bound)
        .expect("valid safety context")
}

fn context() -> SafetyRulesContextV1 {
    context_with_bound(16)
}

fn root_signature(root: SigningRoot) -> SignatureBytes {
    let mut bytes = [0u8; SIGNATURE_BYTES];
    bytes[..32].copy_from_slice(root.as_bytes());
    bytes[32..].copy_from_slice(root.as_bytes());
    SignatureBytes::from_array(bytes)
}

fn invalid_signature() -> SignatureBytes {
    SignatureBytes::from_array([0xD7; SIGNATURE_BYTES])
}

fn signed_vote(
    set: &ValidatorSet,
    view: u64,
    height: u64,
    block_id: BlockId,
    author: ValidatorId,
    valid_signature: bool,
) -> Vote {
    let root = Vote::signing_root_for_set(set, View::new(view), Height::new(height), block_id)
        .expect("valid vote root");
    Vote::new(
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(view),
        Height::new(height),
        block_id,
        set.id(),
        author,
        if valid_signature {
            root_signature(root)
        } else {
            invalid_signature()
        },
        set,
    )
    .expect("shape-valid vote")
}

fn qc_with_signature_validity(
    set: &ValidatorSet,
    view: u64,
    height: u64,
    block_id: BlockId,
    valid_signatures: bool,
) -> QuorumCertificate {
    let votes = (1u8..=3)
        .map(|author| {
            signed_vote(
                set,
                view,
                height,
                block_id,
                validator_id(author),
                valid_signatures,
            )
        })
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
    .expect("shape-valid QC")
}

fn qc(set: &ValidatorSet, view: u64, height: u64, block_id: BlockId) -> QuorumCertificate {
    qc_with_signature_validity(set, view, height, block_id, true)
}

fn leader(set: &ValidatorSet, view: u64) -> ValidatorId {
    let index = (view.saturating_sub(1) % set.validators().len() as u64) as usize;
    set.validators()[index].id()
}

#[allow(clippy::too_many_arguments)]
fn block(
    set: &ValidatorSet,
    view: u64,
    height: u64,
    parent: BlockId,
    timestamp_ms: u64,
    payload_tag: u8,
    proposer: ValidatorId,
) -> Block {
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
        PayloadDigest::new([payload_tag; 32]),
        StateRoot::new([payload_tag.wrapping_add(1); 32]),
        ReceiptsRoot::new([payload_tag.wrapping_add(2); 32]),
        EvidenceRoot::new([payload_tag.wrapping_add(3); 32]),
        timestamp_ms,
        None,
    )
    .expect("shape-valid block header");
    Block::new(header, vec![payload_tag], Vec::new()).expect("shape-valid block")
}

#[allow(clippy::too_many_arguments)]
fn signed_proposal(
    set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
    justify: QcReferenceV0,
    timeout_certificate: Option<TimeoutCertificateV0>,
    view: u64,
    height: u64,
    parent: BlockId,
    authenticated_parent_timestamp_ms: u64,
    timestamp_ms: u64,
    payload_tag: u8,
    valid_proposer_signature: bool,
) -> SignedProposalV0 {
    let proposed = block(
        set,
        view,
        height,
        parent,
        timestamp_ms,
        payload_tag,
        leader(set, view),
    );
    signed_proposal_from_block(
        set,
        parameters,
        proposed,
        justify,
        timeout_certificate,
        authenticated_parent_timestamp_ms,
        valid_proposer_signature,
    )
    .expect("typed proposal")
}

#[allow(clippy::too_many_arguments)]
fn signed_proposal_from_block(
    set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
    proposed: Block,
    justify: QcReferenceV0,
    timeout_certificate: Option<TimeoutCertificateV0>,
    authenticated_parent_timestamp_ms: u64,
    valid_proposer_signature: bool,
) -> core::result::Result<SignedProposalV0, trnm_consensus_types::ValidationError> {
    let root = ProposalWitnessV0::signing_root_for(
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
        if valid_proposer_signature {
            root_signature(root)
        } else {
            invalid_signature()
        },
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

fn genesis_reference(context: &SafetyRulesContextV1) -> QcReferenceV0 {
    QcReferenceV0::genesis_anchor(
        GenesisQcV0::new(
            context.validator_set.genesis_hash(),
            context.validator_set.chain_id(),
            &context.validator_set,
        )
        .expect("valid genesis QC"),
    )
}

fn genesis_state(context: &SafetyRulesContextV1) -> SafetyRulesStateV1 {
    let genesis = match genesis_reference(context) {
        QcReferenceV0::Synthetic(anchor) => match *anchor {
            ContextAuthorizedQcV0::Genesis(genesis) => genesis,
            ContextAuthorizedQcV0::Epoch(_) => unreachable!(),
        },
        QcReferenceV0::Ordinary(_) => unreachable!(),
    };
    SafetyRulesStateV1::from_genesis(context, genesis, &RootSignatures)
        .expect("valid genesis state")
}

fn first_proposal(context: &SafetyRulesContextV1, payload_tag: u8) -> SignedProposalV0 {
    signed_proposal(
        &context.validator_set,
        &context.consensus_parameters,
        genesis_reference(context),
        None,
        1,
        1,
        BlockId::new(*context.validator_set.genesis_hash().as_bytes()),
        context.trusted_genesis_timestamp_ms,
        context.trusted_genesis_timestamp_ms + 100,
        payload_tag,
        true,
    )
}

fn timeout_vote(
    set: &ValidatorSet,
    timed_out_view: u64,
    high_qc: QcRef,
    author: ValidatorId,
    valid_signature: bool,
) -> TimeoutVote {
    let root = TimeoutVote::signing_root_for_set(set, View::new(timed_out_view), high_qc)
        .expect("valid timeout root");
    TimeoutVote::new(
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(timed_out_view),
        set.id(),
        high_qc,
        author,
        if valid_signature {
            root_signature(root)
        } else {
            invalid_signature()
        },
        set,
    )
    .expect("shape-valid timeout vote")
}

fn timeout_certificate(
    set: &ValidatorSet,
    timed_out_view: u64,
    high_qc: QcReferenceV0,
    valid_signatures: bool,
) -> TimeoutCertificateV0 {
    let high_ref = high_qc.qc_ref();
    let entries = (1u8..=3)
        .map(|author| {
            let vote = timeout_vote(
                set,
                timed_out_view,
                high_ref,
                validator_id(author),
                valid_signatures,
            );
            TimeoutEntryV0::new(vote.author(), vote.high_qc(), *vote.signature())
                .expect("valid timeout entry")
        })
        .collect();
    TimeoutCertificateV0::new(
        View::new(timed_out_view),
        entries,
        vec![high_qc.clone()],
        high_qc.id(),
        set,
    )
    .expect("shape-valid TC")
}

#[test]
fn vote_transition_rebuilds_intent_and_advances_only_vote_watermark() {
    let context = context();
    let state = genesis_state(&context);
    let target = first_proposal(&context, 11);

    let transition =
        PureHotStuffSafetyKernelV1::prepare_vote(&context, &state, &[], &target, &RootSignatures)
            .expect("safe first vote");

    assert_eq!(transition.kind(), InertSafetyTransitionKindV1::Vote);
    assert_eq!(transition.predecessor_state_digest(), state.digest());
    assert_eq!(transition.vote_block_id(), Some(target.block().id()));
    assert_eq!(
        transition.successor_state().last_voted_view(),
        Some(View::new(1))
    );
    assert_eq!(transition.successor_state().last_timeout_view(), None);
    assert_eq!(transition.successor_state().revision(), 1);
    assert_ne!(transition.successor_state().digest(), state.digest());
    assert_eq!(
        transition.canonical_intent().authorizing_safety_revision(),
        1
    );
    match transition.canonical_intent().preimage() {
        CanonicalSignPreimageV0::Vote(preimage) => {
            assert_eq!(preimage.view(), View::new(1));
            assert_eq!(preimage.height(), Height::new(1));
            assert_eq!(preimage.block_id(), target.block().id());
        }
        CanonicalSignPreimageV0::TimeoutVote(_) => panic!("unexpected timeout intent"),
    }
}

#[test]
fn same_view_different_vote_is_rejected_by_the_successor_watermark() {
    let context = context();
    let state = genesis_state(&context);
    let first = first_proposal(&context, 21);
    let conflicting = first_proposal(&context, 22);
    assert_ne!(first.block().id(), conflicting.block().id());

    let first_transition =
        PureHotStuffSafetyKernelV1::prepare_vote(&context, &state, &[], &first, &RootSignatures)
            .expect("first vote candidate");
    assert_eq!(
        PureHotStuffSafetyKernelV1::prepare_vote(
            &context,
            first_transition.successor_state(),
            &[],
            &conflicting,
            &RootSignatures,
        ),
        Err(SafetyRulesErrorV1::VoteWatermarkRegression)
    );
}

#[test]
fn timeout_uses_exact_retained_high_qc_and_timeout_then_vote_same_view_is_allowed() {
    let context = context();
    let state = genesis_state(&context);
    let exact_high = state.high_qc().qc_ref();
    let timeout = PureHotStuffSafetyKernelV1::prepare_timeout(&context, &state, &RootSignatures)
        .expect("timeout candidate");

    assert_eq!(timeout.kind(), InertSafetyTransitionKindV1::TimeoutVote);
    assert_eq!(
        timeout.successor_state().last_timeout_view(),
        Some(View::new(1))
    );
    assert_eq!(timeout.successor_state().last_voted_view(), None);
    assert_eq!(timeout.successor_state().revision(), 1);
    match timeout.canonical_intent().preimage() {
        CanonicalSignPreimageV0::TimeoutVote(preimage) => {
            assert_eq!(preimage.view(), View::new(1));
            assert_eq!(preimage.high_qc(), exact_high);
        }
        CanonicalSignPreimageV0::Vote(_) => panic!("unexpected vote intent"),
    }

    let target = first_proposal(&context, 31);
    let vote = PureHotStuffSafetyKernelV1::prepare_vote(
        &context,
        timeout.successor_state(),
        &[],
        &target,
        &RootSignatures,
    )
    .expect("timeout and vote use independent same-view watermarks");
    assert_eq!(
        vote.successor_state().last_timeout_view(),
        Some(View::new(1))
    );
    assert_eq!(vote.successor_state().last_voted_view(), Some(View::new(1)));
    assert_eq!(vote.successor_state().revision(), 2);
    assert_eq!(vote.canonical_intent().authorizing_safety_revision(), 2);
}

#[test]
fn repeated_timeout_is_rejected_without_changing_vote_watermark() {
    let context = context();
    let state = genesis_state(&context);
    let first = PureHotStuffSafetyKernelV1::prepare_timeout(&context, &state, &RootSignatures)
        .expect("first timeout");
    assert_eq!(
        PureHotStuffSafetyKernelV1::prepare_timeout(
            &context,
            first.successor_state(),
            &RootSignatures,
        ),
        Err(SafetyRulesErrorV1::TimeoutWatermarkRegression)
    );
    assert_eq!(first.successor_state().last_voted_view(), None);
}

fn locked_fork_fixture(
    unlock_with_higher_qc: bool,
) -> (
    SafetyRulesContextV1,
    SafetyRulesStateV1,
    Vec<SignedProposalV0>,
    SignedProposalV0,
) {
    let context = context();
    let set = &context.validator_set;
    let parameters = &context.consensus_parameters;
    let genesis_id = BlockId::new(*set.genesis_hash().as_bytes());

    let first = first_proposal(&context, 41);
    let first_qc = qc(set, 1, 1, first.block().id());
    let second = signed_proposal(
        set,
        parameters,
        QcReferenceV0::ordinary(first_qc),
        None,
        2,
        2,
        first.block().id(),
        first.block().header().timestamp_ms(),
        200,
        42,
        true,
    );
    let second_qc = qc(set, 2, 2, second.block().id());

    let locked_block = BlockId::new([0x71; 32]);
    let locked = QcReferenceV0::ordinary(qc(set, 2, 2, locked_block));
    let (ancestry, justify, current_view, high) = if unlock_with_higher_qc {
        let third = signed_proposal(
            set,
            parameters,
            QcReferenceV0::ordinary(second_qc),
            None,
            3,
            3,
            second.block().id(),
            second.block().header().timestamp_ms(),
            300,
            43,
            true,
        );
        let third_qc = qc(set, 3, 3, third.block().id());
        (
            vec![first, second, third],
            QcReferenceV0::ordinary(third_qc.clone()),
            5,
            QcReferenceV0::ordinary(third_qc),
        )
    } else {
        let high = QcReferenceV0::ordinary(qc(set, 3, 3, BlockId::new([0x72; 32])));
        (
            vec![first, second],
            QcReferenceV0::ordinary(second_qc),
            5,
            high,
        )
    };
    let tc = timeout_certificate(set, current_view - 1, justify.clone(), true);
    let parent = ancestry.last().expect("non-empty ancestry");
    let target = signed_proposal(
        set,
        parameters,
        justify,
        Some(tc),
        current_view,
        parent.block().header().height().get() + 1,
        parent.block().id(),
        parent.block().header().timestamp_ms(),
        500,
        44,
        true,
    );
    let state = SafetyRulesStateV1::new(
        &context,
        SafetyRulesStateSeedV1::new(
            View::new(current_view),
            None,
            None,
            high,
            locked,
            FinalizedBlockRefV1::trusted_genesis(&context),
            0,
        ),
        &RootSignatures,
    )
    .expect("valid locked-fork state");
    assert_eq!(state.finalized().block_id(), genesis_id);
    (context, state, ancestry, target)
}

#[test]
fn equal_view_justify_on_a_lock_fork_is_rejected() {
    let (context, state, ancestry, target) = locked_fork_fixture(false);
    assert_eq!(target.witness().justify_qc().qc_ref().view(), View::new(2));
    assert_eq!(state.locked_qc().qc_ref().view(), View::new(2));
    assert_eq!(
        PureHotStuffSafetyKernelV1::prepare_vote(
            &context,
            &state,
            &ancestry,
            &target,
            &RootSignatures,
        ),
        Err(SafetyRulesErrorV1::UnsafeLock)
    );
}

#[test]
fn lower_view_justify_on_a_lock_fork_is_rejected() {
    let context = context();
    let set = &context.validator_set;
    let first = first_proposal(&context, 45);
    let first_qc = QcReferenceV0::ordinary(qc(set, 1, 1, first.block().id()));
    let locked = QcReferenceV0::ordinary(qc(set, 2, 2, BlockId::new([0x73; 32])));
    let high = QcReferenceV0::ordinary(qc(set, 3, 3, BlockId::new([0x74; 32])));
    let target = signed_proposal(
        set,
        &context.consensus_parameters,
        first_qc.clone(),
        Some(timeout_certificate(set, 4, first_qc, true)),
        5,
        2,
        first.block().id(),
        first.block().header().timestamp_ms(),
        500,
        46,
        true,
    );
    let state = SafetyRulesStateV1::new(
        &context,
        SafetyRulesStateSeedV1::new(
            View::new(5),
            None,
            None,
            high,
            locked,
            FinalizedBlockRefV1::trusted_genesis(&context),
            0,
        ),
        &RootSignatures,
    )
    .expect("valid lower-justify fork state");

    assert!(target.witness().justify_qc().qc_ref().view() < state.locked_qc().qc_ref().view());
    assert_eq!(
        PureHotStuffSafetyKernelV1::prepare_vote(
            &context,
            &state,
            core::slice::from_ref(&first),
            &target,
            &RootSignatures,
        ),
        Err(SafetyRulesErrorV1::UnsafeLock)
    );
}

#[test]
fn higher_complete_qc_unlocks_a_finalized_descendant_path() {
    let (context, state, ancestry, target) = locked_fork_fixture(true);
    assert!(target.witness().justify_qc().qc_ref().view() > state.locked_qc().qc_ref().view());
    PureHotStuffSafetyKernelV1::prepare_vote(&context, &state, &ancestry, &target, &RootSignatures)
        .expect("higher verified QC unlocks");
}

#[test]
fn bad_proposer_and_qc_or_tc_signatures_fail_fresh_verification() {
    let context = context();
    let state = genesis_state(&context);
    let bad_proposer = signed_proposal(
        &context.validator_set,
        &context.consensus_parameters,
        genesis_reference(&context),
        None,
        1,
        1,
        BlockId::new(*context.validator_set.genesis_hash().as_bytes()),
        0,
        100,
        51,
        false,
    );
    assert_eq!(
        PureHotStuffSafetyKernelV1::prepare_vote(
            &context,
            &state,
            &[],
            &bad_proposer,
            &RootSignatures,
        ),
        Err(SafetyRulesErrorV1::InvalidConsensusArtifact)
    );

    let first = first_proposal(&context, 52);
    let bad_qc = QcReferenceV0::ordinary(qc_with_signature_validity(
        &context.validator_set,
        1,
        1,
        first.block().id(),
        false,
    ));
    let target = signed_proposal(
        &context.validator_set,
        &context.consensus_parameters,
        bad_qc.clone(),
        Some(timeout_certificate(
            &context.validator_set,
            2,
            bad_qc,
            false,
        )),
        3,
        2,
        first.block().id(),
        100,
        300,
        53,
        true,
    );
    let mut state_view_three = state.clone();
    state_view_three.current_view = View::new(3);
    state_view_three.digest = compute_state_digest_v1(&state_view_three);
    assert_eq!(
        PureHotStuffSafetyKernelV1::prepare_vote(
            &context,
            &state_view_three,
            core::slice::from_ref(&first),
            &target,
            &RootSignatures,
        ),
        Err(SafetyRulesErrorV1::InvalidConsensusArtifact)
    );

    let valid_qc = QcReferenceV0::ordinary(qc(&context.validator_set, 1, 1, first.block().id()));
    let bad_tc_target = signed_proposal(
        &context.validator_set,
        &context.consensus_parameters,
        valid_qc.clone(),
        Some(timeout_certificate(
            &context.validator_set,
            2,
            valid_qc,
            false,
        )),
        3,
        2,
        first.block().id(),
        100,
        300,
        54,
        true,
    );
    assert_eq!(
        PureHotStuffSafetyKernelV1::prepare_vote(
            &context,
            &state_view_three,
            core::slice::from_ref(&first),
            &bad_tc_target,
            &RootSignatures,
        ),
        Err(SafetyRulesErrorV1::InvalidConsensusArtifact)
    );
}

#[test]
fn wrong_parent_height_justify_timestamp_missing_edge_cycle_and_bound_are_rejected() {
    let context = context();
    let state = genesis_state(&context);
    let set = &context.validator_set;
    let parameters = &context.consensus_parameters;
    let genesis_id = BlockId::new(*set.genesis_hash().as_bytes());

    let alternate_parent = BlockId::new([0x81; 32]);
    let alternate_qc = QcReferenceV0::ordinary(qc(set, 1, 1, alternate_parent));
    let wrong_parent = signed_proposal(
        set,
        parameters,
        alternate_qc,
        None,
        2,
        2,
        alternate_parent,
        100,
        200,
        61,
        true,
    );
    assert_eq!(
        PureHotStuffSafetyKernelV1::prepare_vote(
            &context,
            &state,
            &[],
            &wrong_parent,
            &RootSignatures,
        ),
        Err(SafetyRulesErrorV1::WrongView)
    );

    let mut view_two = state.clone();
    view_two.current_view = View::new(2);
    view_two.digest = compute_state_digest_v1(&view_two);
    assert_eq!(
        PureHotStuffSafetyKernelV1::prepare_vote(
            &context,
            &view_two,
            &[],
            &wrong_parent,
            &RootSignatures,
        ),
        Err(SafetyRulesErrorV1::ParentEdgeMismatch)
    );

    let wrong_height_qc = QcReferenceV0::ordinary(qc(set, 1, 1, genesis_id));
    let wrong_height = signed_proposal(
        set,
        parameters,
        wrong_height_qc,
        None,
        2,
        2,
        genesis_id,
        0,
        200,
        62,
        true,
    );
    assert_eq!(
        PureHotStuffSafetyKernelV1::prepare_vote(
            &context,
            &view_two,
            &[],
            &wrong_height,
            &RootSignatures,
        ),
        Err(SafetyRulesErrorV1::HeightEdgeMismatch)
    );

    let wrong_justify_qc = QcReferenceV0::ordinary(qc(set, 1, 0, genesis_id));
    let wrong_justify = signed_proposal(
        set,
        parameters,
        wrong_justify_qc,
        None,
        2,
        1,
        genesis_id,
        0,
        200,
        63,
        true,
    );
    assert_eq!(
        PureHotStuffSafetyKernelV1::prepare_vote(
            &context,
            &view_two,
            &[],
            &wrong_justify,
            &RootSignatures,
        ),
        Err(SafetyRulesErrorV1::JustifyEdgeMismatch)
    );

    let context_with_later_genesis =
        SafetyRulesContextV1::new(set.clone(), *parameters, validator_id(1), 100, 16)
            .expect("later timestamp context");
    let later_state = SafetyRulesStateV1::from_genesis(
        &context_with_later_genesis,
        GenesisQcV0::new(set.genesis_hash(), set.chain_id(), set).expect("genesis QC"),
        &RootSignatures,
    )
    .expect("later timestamp state");
    let stale_timestamp = signed_proposal(
        set,
        parameters,
        genesis_reference(&context),
        None,
        1,
        1,
        genesis_id,
        0,
        50,
        64,
        true,
    );
    assert_eq!(
        PureHotStuffSafetyKernelV1::prepare_vote(
            &context_with_later_genesis,
            &later_state,
            &[],
            &stale_timestamp,
            &RootSignatures,
        ),
        Err(SafetyRulesErrorV1::InvalidConsensusArtifact)
    );

    let first = first_proposal(&context, 65);
    let first_qc = QcReferenceV0::ordinary(qc(set, 1, 1, first.block().id()));
    let second = signed_proposal(
        set,
        parameters,
        first_qc,
        None,
        2,
        2,
        first.block().id(),
        100,
        200,
        66,
        true,
    );
    assert_eq!(
        PureHotStuffSafetyKernelV1::prepare_vote(
            &context,
            &view_two,
            &[],
            &second,
            &RootSignatures,
        ),
        Err(SafetyRulesErrorV1::ParentEdgeMismatch)
    );
    assert_eq!(
        PureHotStuffSafetyKernelV1::prepare_vote(
            &context,
            &view_two,
            &[first.clone(), first],
            &second,
            &RootSignatures,
        ),
        Err(SafetyRulesErrorV1::DuplicateOrCyclicBlock)
    );

    let short_context = context_with_bound(1);
    let short_state = genesis_state(&short_context);
    let short_first = first_proposal(&short_context, 67);
    let short_qc = QcReferenceV0::ordinary(qc(
        &short_context.validator_set,
        1,
        1,
        short_first.block().id(),
    ));
    let short_second = signed_proposal(
        &short_context.validator_set,
        &short_context.consensus_parameters,
        short_qc,
        None,
        2,
        2,
        short_first.block().id(),
        100,
        200,
        68,
        true,
    );
    let mut short_view_two = short_state;
    short_view_two.current_view = View::new(2);
    short_view_two.digest = compute_state_digest_v1(&short_view_two);
    assert_eq!(
        PureHotStuffSafetyKernelV1::prepare_vote(
            &short_context,
            &short_view_two,
            &[short_first],
            &short_second,
            &RootSignatures,
        ),
        Err(SafetyRulesErrorV1::AncestryTooLong)
    );
}

#[test]
fn wrong_scheduled_leader_is_rejected_before_it_can_become_a_typed_candidate() {
    let context = context();
    let set = &context.validator_set;
    let proposed = block(
        set,
        1,
        1,
        BlockId::new(*set.genesis_hash().as_bytes()),
        100,
        71,
        validator_id(2),
    );
    assert_ne!(proposed.header().proposer_id(), leader(set, 1));
    assert!(signed_proposal_from_block(
        set,
        &context.consensus_parameters,
        proposed,
        genesis_reference(&context),
        None,
        0,
        true,
    )
    .is_err());
}

#[test]
fn state_rejects_incomplete_qc_signatures_and_regressing_coordinates() {
    let context = context();
    let bad_high = QcReferenceV0::ordinary(qc_with_signature_validity(
        &context.validator_set,
        1,
        1,
        BlockId::new([0x91; 32]),
        false,
    ));
    assert_eq!(
        SafetyRulesStateV1::new(
            &context,
            SafetyRulesStateSeedV1::new(
                View::new(2),
                None,
                None,
                bad_high,
                genesis_reference(&context),
                FinalizedBlockRefV1::trusted_genesis(&context),
                0,
            ),
            &RootSignatures,
        ),
        Err(SafetyRulesErrorV1::InvalidConsensusArtifact)
    );

    let high = QcReferenceV0::ordinary(qc(&context.validator_set, 1, 1, BlockId::new([0x92; 32])));
    assert_eq!(
        SafetyRulesStateV1::new(
            &context,
            SafetyRulesStateSeedV1::new(
                View::new(1),
                None,
                None,
                high,
                genesis_reference(&context),
                FinalizedBlockRefV1::trusted_genesis(&context),
                0,
            ),
            &RootSignatures,
        ),
        Err(SafetyRulesErrorV1::InvalidState)
    );
}

#[test]
fn state_and_transition_digest_goldens_are_frozen() {
    let context = context();
    let state = genesis_state(&context);
    let timeout = PureHotStuffSafetyKernelV1::prepare_timeout(&context, &state, &RootSignatures)
        .expect("timeout candidate");

    // Values are intentionally literal and must be updated only with an
    // explicit schema/domain migration. They were independently derived from
    // the frozen framing and reference-profile field preimages.
    const STATE_GOLDEN: [u8; 32] = [
        0xa9, 0x19, 0x86, 0x84, 0xcc, 0x07, 0x19, 0x30, 0x0b, 0x7d, 0x09, 0x66, 0x4d, 0x50, 0xe4,
        0x80, 0xdd, 0xe8, 0x7d, 0x3a, 0xde, 0x2a, 0xaf, 0x54, 0x59, 0xbd, 0x4b, 0x25, 0xb2, 0xd9,
        0x13, 0x3a,
    ];
    const TRANSITION_GOLDEN: [u8; 32] = [
        0x9d, 0xbe, 0xd3, 0xcb, 0xdf, 0xa0, 0x7d, 0xb2, 0x1b, 0x09, 0x1c, 0x1e, 0x69, 0xb9, 0xc5,
        0x7f, 0xe0, 0x5e, 0x79, 0x4f, 0x33, 0xb8, 0x5e, 0x4a, 0x88, 0xea, 0x34, 0x52, 0xd5, 0xc0,
        0x4f, 0x88,
    ];
    assert_eq!(state.digest().into_bytes(), STATE_GOLDEN);
    assert_eq!(timeout.candidate_digest().into_bytes(), TRANSITION_GOLDEN);
}

const _: () = {
    assert!(!APPLICATION_VALID_AUTHORITY_V1);
    assert!(!COMPLETE_VOTE_ADMISSION_V1);
    assert!(!SIGNER_AUTHORITY_V1);
    assert!(!STATE_SEED_AUTHORITY_V1);
    assert!(!FINALIZED_REFERENCE_AUTHORITY_V1);
    assert!(!PERSISTENCE_AUTHORITY_V1);
    assert!(!EXTERNAL_CAS_AUTHORITY_V1);
    assert!(!HSM_AUTHORITY_V1);
    assert!(!CORE_INTEGRATION_V1);
    assert!(!REMOTE_WIRE_V1);
    assert!(!OBSERVE_QC_V1);
    assert!(!OBSERVE_TC_V1);
    assert!(!RUNTIME_ACTIVATION_V1);
    assert!(!PRODUCTION_CANDIDATE_V1);
    assert!(!PRODUCTION_CONSENSUS_ACTIVATION_V1);
};
