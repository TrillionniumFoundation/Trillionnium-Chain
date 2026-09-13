//! Long-horizon deterministic replay coverage for the pure SafetyRules kernel.
//!
//! This is deliberately an integration test rather than a production claim:
//! it drives the public kernel with a fixed, genesis-anchored proposal shape
//! and compares two independent runs.  It proves that the vote/timeout
//! watermark transition stream is deterministic for 100,000 views while the
//! authoritative store/signer/node gates remain separate and fail-closed.

use sha2::{Digest, Sha256};
use trnm_consensus_safety_rules::{
    FinalizedBlockRefV1, PureHotStuffSafetyKernelV1, SafetyRulesContextV1, SafetyRulesStateSeedV1,
    SafetyRulesStateV1,
};
use trnm_consensus_types::{
    Block, BlockHeader, BlockId, BlockKind, CanonicalSignPreimageV0, ConsensusParametersV0,
    ConsensusPublicKey, EvidenceRoot, GenesisHash, GenesisQcV0, Height, PayloadDigest,
    ProposalWitnessV0, ProtocolVersion, QcReferenceV0, ReceiptsRoot, SignatureBytes,
    SignatureVerifier, SignedProposalV0, SigningRoot, StateRoot, TimeoutCertificateV0,
    TimeoutEntryV0, TimeoutVote, Validator, ValidatorId, ValidatorSet, View, VotingPower,
    SIGNATURE_BYTES,
};

const CHAIN: trnm_consensus_types::ChainId =
    trnm_consensus_types::ChainId::from_static("trnm-safety-rules-replay-100k");
const ITERATIONS: u64 = 100_000;

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

fn root_signature(root: SigningRoot) -> SignatureBytes {
    let mut bytes = [0_u8; SIGNATURE_BYTES];
    bytes[..32].copy_from_slice(root.as_bytes());
    bytes[32..].copy_from_slice(root.as_bytes());
    SignatureBytes::from_array(bytes)
}

fn validator_id(index: u8) -> ValidatorId {
    ValidatorId::new([index; 32])
}

fn parameters() -> ConsensusParametersV0 {
    ConsensusParametersV0::reference_shadow_v0()
}

fn validator_set(parameters: &ConsensusParametersV0) -> ValidatorSet {
    let validators = (1_u8..=4)
        .map(|index| {
            Validator::new(
                validator_id(index),
                ConsensusPublicKey::new([index + 100; 32]),
                VotingPower::new(1).expect("positive voting power"),
            )
            .expect("valid validator")
        })
        .collect();
    ValidatorSet::new(
        GenesisHash::new([0xA5; 32]),
        CHAIN,
        ProtocolVersion::V0,
        trnm_consensus_types::Epoch::new(0),
        parameters.hash(),
        validators,
    )
    .expect("valid validator set")
}

fn context() -> SafetyRulesContextV1 {
    let parameters = parameters();
    let set = validator_set(&parameters);
    SafetyRulesContextV1::new(set, parameters, validator_id(1), 0, 16)
        .expect("valid safety-rules context")
}

fn genesis_reference(context: &SafetyRulesContextV1) -> QcReferenceV0 {
    QcReferenceV0::genesis_anchor(
        GenesisQcV0::new(
            context.validator_set().genesis_hash(),
            context.validator_set().chain_id(),
            context.validator_set(),
        )
        .expect("valid genesis QC"),
    )
}

fn genesis_state(context: &SafetyRulesContextV1) -> SafetyRulesStateV1 {
    let genesis = match genesis_reference(context) {
        QcReferenceV0::Synthetic(anchor) => match *anchor {
            trnm_consensus_types::ContextAuthorizedQcV0::Genesis(genesis) => genesis,
            trnm_consensus_types::ContextAuthorizedQcV0::Epoch(_) => unreachable!(),
        },
        QcReferenceV0::Ordinary(_) => unreachable!(),
    };
    SafetyRulesStateV1::from_genesis(context, genesis, &RootSignatures)
        .expect("valid genesis state")
}

fn timeout_certificate(
    context: &SafetyRulesContextV1,
    timed_out_view: u64,
) -> TimeoutCertificateV0 {
    let high_qc = genesis_reference(context);
    let entries = (1_u8..=3)
        .map(|author| {
            let root = TimeoutVote::signing_root_for_set(
                context.validator_set(),
                View::new(timed_out_view),
                high_qc.qc_ref(),
            )
            .expect("timeout signing root");
            TimeoutEntryV0::new(validator_id(author), high_qc.qc_ref(), root_signature(root))
                .expect("shape-valid timeout entry")
        })
        .collect();
    TimeoutCertificateV0::new(
        View::new(timed_out_view),
        entries,
        vec![high_qc.clone()],
        high_qc.id(),
        context.validator_set(),
    )
    .expect("shape-valid timeout certificate")
}

fn proposal(
    context: &SafetyRulesContextV1,
    view: u64,
    timeout_certificate: Option<TimeoutCertificateV0>,
) -> SignedProposalV0 {
    // The proposal remains directly genesis-anchored.  The changing view and
    // payload tag make every signing root distinct without requiring a second
    // mutable authority or an unbounded ancestry cache.
    let tag = ((view % 254) as u8).saturating_add(1);
    let header = BlockHeader::new(
        context.validator_set().genesis_hash(),
        context.validator_set().chain_id(),
        context.validator_set().protocol_version(),
        context.validator_set().epoch(),
        View::new(view),
        Height::new(1),
        BlockKind::Regular,
        BlockId::new(*context.validator_set().genesis_hash().as_bytes()),
        validator_id(((view.saturating_sub(1) % 4) as u8) + 1),
        context.validator_set().id(),
        context.validator_set().consensus_parameters_hash(),
        PayloadDigest::new([tag; 32]),
        StateRoot::new([tag.wrapping_add(1); 32]),
        ReceiptsRoot::new([tag.wrapping_add(2); 32]),
        EvidenceRoot::new([tag.wrapping_add(3); 32]),
        1,
        None,
    )
    .expect("shape-valid header");
    let block = Block::new(header, vec![tag], Vec::new()).expect("shape-valid block");
    let justify = genesis_reference(context);
    let root = ProposalWitnessV0::signing_root_for(
        block.header(),
        &justify,
        timeout_certificate.as_ref(),
        None,
    )
    .expect("proposal signing root");
    let witness = ProposalWitnessV0::new(
        block.header(),
        justify,
        timeout_certificate,
        None,
        root_signature(root),
        context.validator_set(),
        None,
        context.consensus_parameters(),
        0,
    )
    .expect("shape-valid proposal witness");
    SignedProposalV0::new(
        block,
        witness,
        context.validator_set(),
        None,
        context.consensus_parameters(),
        0,
    )
    .expect("shape-valid signed proposal")
}

fn absorb_transition(
    hasher: &mut Sha256,
    kind: u8,
    transition: &trnm_consensus_safety_rules::InertSafetyTransitionV1,
) {
    hasher.update([kind]);
    hasher.update(transition.predecessor_state_digest().as_bytes());
    hasher.update(transition.successor_state().digest().as_bytes());
    hasher.update(transition.candidate_digest().as_bytes());
    hasher.update(transition.canonical_intent().fingerprint().as_bytes());
    hasher.update(transition.canonical_intent().signing_root().as_bytes());
    match transition.canonical_intent().preimage() {
        CanonicalSignPreimageV0::Vote(preimage) => {
            hasher.update([0]);
            hasher.update(preimage.view().get().to_be_bytes());
            hasher.update(preimage.height().get().to_be_bytes());
            hasher.update(preimage.block_id().as_bytes());
        }
        CanonicalSignPreimageV0::TimeoutVote(preimage) => {
            hasher.update([1]);
            hasher.update(preimage.view().get().to_be_bytes());
            hasher.update(preimage.high_qc().qc_digest().as_bytes());
        }
    }
}

fn run_replay() -> (
    [u8; 32],
    trnm_consensus_safety_rules::SafetyRulesStateDigestV1,
    u64,
) {
    let context = context();
    let mut state = genesis_state(&context);
    let mut trace = Sha256::new();
    trace.update(b"trnm.consensus.safety-rules.replay-100k.v1");
    trace.update(ITERATIONS.to_be_bytes());

    for view in 1..=ITERATIONS {
        assert_eq!(state.current_view(), View::new(view));
        let timeout =
            PureHotStuffSafetyKernelV1::prepare_timeout(&context, &state, &RootSignatures)
                .expect("timeout transition remains valid");
        absorb_transition(&mut trace, 1, &timeout);
        state = timeout.successor_state().clone();

        let target = proposal(
            &context,
            view,
            (view > 1).then(|| timeout_certificate(&context, view - 1)),
        );
        let vote = PureHotStuffSafetyKernelV1::prepare_vote(
            &context,
            &state,
            &[],
            &target,
            &RootSignatures,
        )
        .expect("vote transition remains valid");
        absorb_transition(&mut trace, 0, &vote);
        state = vote.successor_state().clone();

        if view != ITERATIONS {
            state = SafetyRulesStateV1::new(
                &context,
                SafetyRulesStateSeedV1::new(
                    View::new(view + 1),
                    state.last_voted_view(),
                    state.last_timeout_view(),
                    state.high_qc().clone(),
                    state.locked_qc().clone(),
                    FinalizedBlockRefV1::trusted_genesis(&context),
                    state.revision(),
                ),
                &RootSignatures,
            )
            .expect("next-view state remains authenticated");
        }
    }

    (trace.finalize().into(), state.digest(), state.revision())
}

#[test]
#[ignore = "long-horizon evidence; run explicitly in release mode with --ignored"]
fn one_hundred_thousand_view_vote_timeout_replay_is_byte_stable() {
    let first = run_replay();
    let second = run_replay();
    assert_eq!(first, second, "independent replay runs diverged");
    assert_eq!(first.2, ITERATIONS * 2);
    assert_ne!(first.0, [0_u8; 32]);
}
