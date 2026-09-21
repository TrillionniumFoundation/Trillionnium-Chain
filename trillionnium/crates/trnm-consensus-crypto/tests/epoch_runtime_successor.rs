use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use trnm_consensus_crypto::{
    recover_epoch_activation_authority_strict_v0,
    verify_same_version_epoch_activation_authority_strict_v0, StrictEpochRuntimeContextV1,
};
use trnm_consensus_types::*;

const CORPUS: &str = include_str!(
    "../../../../docs/protocol/poco-bft-v0/vectors/poco-authenticated-checkpoint-handoff-v0.json"
);

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).unwrap())
        .collect()
}

fn predecessor() -> trnm_consensus_crypto::StrictSameVersionEpochActivationAuthorityV0 {
    let corpus: Value = serde_json::from_str(CORPUS).unwrap();
    let case = &corpus["positive"];
    let raw = |section: &str, field: &str| unhex(case[section][field].as_str().unwrap());
    let evidence = EpochActivationEvidenceBytesV0 {
        old_checkpoint_finality: raw("checkpoint_finality", "raw_finality_proof_cev0_hex"),
        next_epoch_commitment: raw("preheader", "commitment_cev0_hex"),
        authorization_kernel: raw("handoff", "raw_anchor_certificate_kernel_cev0_hex"),
        old_validator_set: raw("preheader", "old_validator_set_cev0_hex"),
        old_consensus_parameters: raw("preheader", "old_parameters_cev0_hex"),
        new_validator_set: raw("preheader", "new_validator_set_cev0_hex"),
        new_consensus_parameters: raw("preheader", "new_parameters_cev0_hex"),
        authenticated_checkpoint_parent_header: raw(
            "preheader",
            "checkpoint_parent_header_cev0_hex",
        ),
    };
    let old_set = decode_validator_set_v0_exact(&evidence.old_validator_set).unwrap();
    let old_parameters =
        decode_consensus_parameters_v0_exact(&evidence.old_consensus_parameters).unwrap();
    let binding = unhex("4ba70b831d3bd70a1be8669f654ac42148017fca0b83f84e999ac532b9c70e4f")
        .try_into()
        .unwrap();
    recover_epoch_activation_authority_strict_v0(
        evidence.as_preimages(),
        &old_set,
        &old_parameters,
        binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap()
}

fn signing_key(validator: &Validator) -> SigningKey {
    let mut seed = Sha256::new();
    seed.update(b"trnm.poco-bft.checkpoint-finality.private-fixture.v0:");
    seed.update(validator.id().as_bytes());
    let key = SigningKey::from_bytes(&seed.finalize().into());
    assert_eq!(
        key.verifying_key().to_bytes(),
        validator.consensus_key().into_bytes()
    );
    key
}

fn qc(set: &ValidatorSet, header: &BlockHeader) -> QuorumCertificate {
    qc_with_signature_mutation(set, header, false)
}

fn qc_with_signature_mutation(
    set: &ValidatorSet,
    header: &BlockHeader,
    corrupt: bool,
) -> QuorumCertificate {
    let root =
        Vote::signing_root_for_set(set, header.view(), header.height(), header.id()).unwrap();
    let votes = set
        .validators()
        .iter()
        .enumerate()
        .map(|(index, validator)| {
            let mut signature = signing_key(validator).sign(root.as_bytes()).to_bytes();
            if corrupt && index == 0 {
                signature[0] ^= 1;
            }
            Vote::new(
                set.chain_id(),
                set.protocol_version(),
                set.epoch(),
                header.view(),
                header.height(),
                header.id(),
                set.id(),
                validator.id(),
                SignatureBytes::from_array(signature),
                set,
            )
            .unwrap()
        })
        .collect();
    QuorumCertificate::new(
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        header.view(),
        header.height(),
        header.id(),
        set.id(),
        votes,
        set,
    )
    .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn header(
    set: &ValidatorSet,
    kind: BlockKind,
    view: u64,
    height: u64,
    parent_id: BlockId,
    proposer: ValidatorId,
    state_root: StateRoot,
    commitment: Option<NextEpochCommitmentHash>,
    timestamp: u64,
    empty: bool,
) -> BlockHeader {
    let empty_root = |kind| {
        OrderedRootV0::from_items::<&[u8]>(kind, &[])
            .unwrap()
            .digest()
    };
    BlockHeader::new(
        set.genesis_hash(),
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(view),
        Height::new(height),
        kind,
        parent_id,
        proposer,
        set.id(),
        set.consensus_parameters_hash(),
        PayloadDigest::new(if empty {
            empty_root(RootKind::Payload)
        } else {
            [41; 32]
        }),
        state_root,
        ReceiptsRoot::new(if empty {
            empty_root(RootKind::Receipts)
        } else {
            [42; 32]
        }),
        EvidenceRoot::new(if empty {
            empty_root(RootKind::Evidence)
        } else {
            [43; 32]
        }),
        timestamp,
        commitment,
    )
    .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn certified(
    set: &ValidatorSet,
    params: &ConsensusParametersV0,
    header: BlockHeader,
    justify: QuorumCertificate,
    parent_timestamp: u64,
    timeout: Option<TimeoutCertificateV0>,
    certifying: QuorumCertificate,
    corrupt: bool,
) -> CertifiedHeaderV0 {
    let justify_ref = QcReferenceV0::ordinary(justify);
    let root =
        ProposalWitnessV0::signing_root_for(&header, &justify_ref, timeout.as_ref(), None).unwrap();
    let mut signature = signing_key(set.validator(header.proposer_id()).unwrap())
        .sign(root.as_bytes())
        .to_bytes();
    if corrupt {
        signature[0] ^= 1;
    }
    CertifiedHeaderV0::new(
        header,
        justify_ref,
        timeout,
        None,
        Signature64::from_array(signature),
        certifying,
        set,
        None,
        params,
        parent_timestamp,
    )
    .unwrap()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SuccessorBadSignature {
    None,
    ParentQc,
    CheckpointQc,
    Seal1Qc,
    Seal2Qc,
    CheckpointProposal,
    Seal1Proposal,
    Seal2Proposal,
    CheckpointTimeout,
    Seal1Timeout,
    Seal2Timeout,
    OldHandoff,
    NewHandoff,
}

fn mixed_timeout(
    set: &ValidatorSet,
    parent_qc: &QuorumCertificate,
    anchor: &QcReferenceV0,
    view: View,
    corrupt: bool,
) -> TimeoutCertificateV0 {
    let ordinary = QcReferenceV0::ordinary(parent_qc.clone());
    let entries = set
        .validators()
        .iter()
        .enumerate()
        .map(|(index, validator)| {
            let reference = if index == 0 { anchor } else { &ordinary };
            let root = TimeoutVote::signing_root_for_set(set, view, reference.qc_ref()).unwrap();
            let mut signature = signing_key(validator).sign(root.as_bytes()).to_bytes();
            if corrupt && index == 0 {
                signature[0] ^= 1;
            }
            TimeoutEntryV0::new(
                validator.id(),
                reference.qc_ref(),
                SignatureBytes::from_array(signature),
            )
            .unwrap()
        })
        .collect();
    let mut references = vec![ordinary.clone(), anchor.clone()];
    references.sort_by_key(QcReferenceV0::id);
    TimeoutCertificateV0::new(view, entries, references, ordinary.id(), set).unwrap()
}

// A comparison digest, not a constructor of strict activation authority.
fn evidence_binding(e: &EpochActivationEvidenceBytesV0) -> [u8; 32] {
    let domain = b"trnm.poco-bft.strict-epoch-activation-binding-ref.v0";
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.domain.hash.v1");
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    for root in [
        &e.old_checkpoint_finality,
        &e.next_epoch_commitment,
        &e.authorization_kernel,
        &e.old_validator_set,
        &e.old_consensus_parameters,
        &e.new_validator_set,
        &e.new_consensus_parameters,
        &e.authenticated_checkpoint_parent_header,
    ] {
        hasher.update((root.len() as u64).to_be_bytes());
        hasher.update(root);
    }
    hasher.finalize().into()
}

fn successor_evidence(
    predecessor: &StrictEpochRuntimeContextV1,
) -> (
    EpochActivationEvidenceBytesV0,
    ValidatorSet,
    ConsensusParametersV0,
    [u8; 32],
    Vec<BlockHeader>,
) {
    successor_evidence_variant(predecessor, false, SuccessorBadSignature::None)
}

fn successor_evidence_variant(
    context: &StrictEpochRuntimeContextV1,
    with_timeout: bool,
    bad: SuccessorBadSignature,
) -> (
    EpochActivationEvidenceBytesV0,
    ValidatorSet,
    ConsensusParametersV0,
    [u8; 32],
    Vec<BlockHeader>,
) {
    successor_evidence_with_ancestry_variant(context, with_timeout, bad, false)
}

fn successor_evidence_with_ancestry_variant(
    context: &StrictEpochRuntimeContextV1,
    with_timeout: bool,
    bad: SuccessorBadSignature,
    repeated_ancestry_view: bool,
) -> (
    EpochActivationEvidenceBytesV0,
    ValidatorSet,
    ConsensusParametersV0,
    [u8; 32],
    Vec<BlockHeader>,
) {
    let predecessor = context.activation();
    let old_set = predecessor.new_validator_set().clone();
    let old_params = *predecessor.new_consensus_parameters();
    let geometry = EpochGeometryV0::new(old_set.epoch(), &old_params).unwrap();
    let new_epoch = old_set.epoch().checked_next().unwrap();
    let new_set = ValidatorSet::new(
        old_set.genesis_hash(),
        old_set.chain_id(),
        old_set.protocol_version(),
        new_epoch,
        old_params.hash(),
        old_set
            .validators()
            .iter()
            .map(|validator| {
                Validator::new(
                    validator.id(),
                    validator.consensus_key(),
                    validator.voting_power(),
                )
                .unwrap()
            })
            .collect(),
    )
    .unwrap();
    let commitment = NextEpochCommitmentV0::new(NextEpochCommitmentV0Fields {
        schema_version: SCHEMA_VERSION_V0,
        genesis_hash: old_set.genesis_hash(),
        chain_id: old_set.chain_id(),
        old_epoch: old_set.epoch(),
        new_epoch,
        snapshot_cutoff_height: Height::new(
            geometry
                .checkpoint_height()
                .get()
                .checked_sub(old_params.snapshot_lead_blocks())
                .unwrap(),
        ),
        snapshot_state_root: StateRoot::new([73; 32]),
        new_protocol_version: new_set.protocol_version(),
        new_validator_set_hash: new_set.id(),
        new_consensus_parameters_hash: old_params.hash(),
        rollout_phase: old_params.rollout_phase(),
        upgrade_plan_hash: None,
        fallback_used: false,
        fallback_reason: EpochFallbackReasonV0::None,
        activation_height: geometry.epoch_end().checked_next().unwrap(),
    })
    .unwrap();

    let mut ancestry = Vec::with_capacity(
        (geometry.last_pre_checkpoint_height().unwrap().get()
            - predecessor.terminal_old_header().height().get()
            + 1) as usize,
    );
    let mut parent = predecessor.terminal_old_header().clone();
    ancestry.push(parent.clone());
    for height in (parent.height().get() + 1)..=geometry.last_pre_checkpoint_height().unwrap().get()
    {
        let kind = geometry.expected_block_kind(Height::new(height)).unwrap();
        let view = if repeated_ancestry_view {
            1
        } else {
            height - predecessor.terminal_old_header().height().get()
        };
        let proposer =
            old_set.validators()[((view - 1) % old_set.validators().len() as u64) as usize].id();
        parent = header(
            &old_set,
            kind,
            view,
            height,
            parent.id(),
            proposer,
            StateRoot::new([70; 32]),
            None,
            parent.timestamp_ms() + 1,
            false,
        );
        ancestry.push(parent.clone());
    }
    let gap = if with_timeout { 2 } else { 1 };
    let checkpoint_view = parent.view().get() + gap;
    let proposer = |view: u64| {
        old_set.validators()[((view - 1) % old_set.validators().len() as u64) as usize].id()
    };
    let checkpoint = header(
        &old_set,
        BlockKind::EpochCheckpoint,
        checkpoint_view,
        geometry.checkpoint_height().get(),
        parent.id(),
        proposer(checkpoint_view),
        StateRoot::new([74; 32]),
        Some(commitment.id()),
        parent.timestamp_ms() + 1,
        false,
    );
    let checkpoint_qc = qc_with_signature_mutation(
        &old_set,
        &checkpoint,
        bad == SuccessorBadSignature::CheckpointQc,
    );
    let seal_1 = header(
        &old_set,
        BlockKind::EpochSeal1,
        checkpoint_view + gap,
        geometry.seal_1_height().get(),
        checkpoint.id(),
        proposer(checkpoint_view + gap),
        checkpoint.state_root(),
        Some(commitment.id()),
        checkpoint.timestamp_ms() + 1,
        true,
    );
    let seal_1_qc =
        qc_with_signature_mutation(&old_set, &seal_1, bad == SuccessorBadSignature::Seal1Qc);
    let seal_2 = header(
        &old_set,
        BlockKind::EpochSeal2,
        checkpoint_view + 2 * gap,
        geometry.seal_2_height().get(),
        seal_1.id(),
        proposer(checkpoint_view + 2 * gap),
        checkpoint.state_root(),
        Some(commitment.id()),
        seal_1.timestamp_ms() + 1,
        true,
    );
    let seal_2_qc =
        qc_with_signature_mutation(&old_set, &seal_2, bad == SuccessorBadSignature::Seal2Qc);
    let parent_qc = if bad == SuccessorBadSignature::ParentQc {
        qc_with_signature_mutation(&old_set, &parent, true)
    } else {
        qc(&old_set, &parent)
    };
    let anchor = context.anchor_reference();
    let timeout = |header: &BlockHeader, justify: &QuorumCertificate, bad_kind| {
        with_timeout.then(|| {
            mixed_timeout(
                &old_set,
                justify,
                anchor,
                View::new(header.view().get() - 1),
                bad == bad_kind,
            )
        })
    };
    let finality = FinalityProofV0::new(
        certified(
            &old_set,
            &old_params,
            checkpoint.clone(),
            parent_qc.clone(),
            parent.timestamp_ms(),
            timeout(
                &checkpoint,
                &parent_qc,
                SuccessorBadSignature::CheckpointTimeout,
            ),
            checkpoint_qc.clone(),
            bad == SuccessorBadSignature::CheckpointProposal,
        ),
        certified(
            &old_set,
            &old_params,
            seal_1.clone(),
            checkpoint_qc,
            checkpoint.timestamp_ms(),
            timeout(
                &seal_1,
                &qc_with_signature_mutation(
                    &old_set,
                    &checkpoint,
                    bad == SuccessorBadSignature::CheckpointQc,
                ),
                SuccessorBadSignature::Seal1Timeout,
            ),
            seal_1_qc.clone(),
            bad == SuccessorBadSignature::Seal1Proposal,
        ),
        certified(
            &old_set,
            &old_params,
            seal_2.clone(),
            seal_1_qc.clone(),
            seal_1.timestamp_ms(),
            timeout(&seal_2, &seal_1_qc, SuccessorBadSignature::Seal2Timeout),
            seal_2_qc.clone(),
            bad == SuccessorBadSignature::Seal2Proposal,
        ),
        &old_set,
        None,
        &old_params,
        parent.timestamp_ms(),
    )
    .unwrap();
    let descriptor = HandoffDescriptorV0::new(HandoffDescriptorV0Fields {
        genesis_hash: old_set.genesis_hash(),
        chain_id: old_set.chain_id(),
        old_epoch: old_set.epoch(),
        new_epoch,
        old_protocol_version: old_set.protocol_version(),
        new_protocol_version: new_set.protocol_version(),
        old_validator_set_hash: old_set.id(),
        new_validator_set_hash: new_set.id(),
        old_consensus_parameters_hash: old_params.hash(),
        new_consensus_parameters_hash: old_params.hash(),
        checkpoint_height: finality.finalized_block().header().height(),
        checkpoint_block_id: finality.finalized_block().header().id(),
        checkpoint_state_root: finality.finalized_block().header().state_root(),
        next_epoch_commitment_digest: commitment.id(),
        terminal_old_height: seal_2.height(),
        terminal_old_block_id: seal_2.id(),
        terminal_old_qc_digest: seal_2_qc.id(),
        terminal_old_view: seal_2.view(),
        activation_height: geometry.epoch_end().checked_next().unwrap(),
        initial_new_view: View::new(1),
    })
    .unwrap();
    let old_root = descriptor.old_set_signing_root();
    let new_root = descriptor.new_set_signing_root();
    let shares = |set: &ValidatorSet, root: SigningRoot, corrupt: bool| {
        set.validators()
            .iter()
            .take(3)
            .enumerate()
            .map(|(index, validator)| {
                let mut signature = signing_key(validator).sign(root.as_bytes()).to_bytes();
                if corrupt && index == 0 {
                    signature[0] ^= 1;
                }
                SignatureShareV0::new(validator.id(), Signature64::from_array(signature)).unwrap()
            })
            .collect()
    };
    let handoff = HandoffCertificateV0::new(
        descriptor,
        shares(&old_set, old_root, bad == SuccessorBadSignature::OldHandoff),
        shares(&new_set, new_root, bad == SuccessorBadSignature::NewHandoff),
        &old_set,
        &new_set,
    )
    .unwrap();
    let kernel = EpochAnchorAuthorizationKernelV0::from_parts_v0(
        seal_2, seal_2_qc, handoff, &old_set, &new_set,
    )
    .unwrap();
    let evidence = EpochActivationEvidenceBytesV0 {
        old_checkpoint_finality: finality.try_cev0_bytes().unwrap(),
        next_epoch_commitment: commitment.try_cev0_bytes().unwrap(),
        authorization_kernel: kernel.try_cev0_bytes().unwrap(),
        old_validator_set: old_set.try_cev0_bytes().unwrap(),
        old_consensus_parameters: old_params.canonical_bytes(),
        new_validator_set: new_set.try_cev0_bytes().unwrap(),
        new_consensus_parameters: old_params.canonical_bytes(),
        authenticated_checkpoint_parent_header: parent.try_cev0_bytes().unwrap(),
    };
    let binding = evidence_binding(&evidence);
    if !with_timeout && bad == SuccessorBadSignature::None {
        let verified = verify_same_version_epoch_activation_authority_strict_v0(
            &finality,
            &commitment,
            &kernel,
            &old_set,
            &old_params,
            &new_set,
            &old_params,
            &parent,
        )
        .unwrap();
        assert_eq!(*verified.binding_ref().as_bytes(), binding);
    }
    (evidence, old_set, old_params, binding, ancestry)
}

#[test]
fn strict_runtime_context_accepts_a_real_repeated_epoch_successor() {
    let predecessor_context =
        StrictEpochRuntimeContextV1::from_activation_v1(predecessor()).unwrap();
    let (evidence, old_set, old_params, binding, ancestry) =
        successor_evidence(&predecessor_context);
    let successor = recover_epoch_activation_authority_strict_v0(
        evidence.as_preimages(),
        &old_set,
        &old_params,
        binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    assert_eq!(
        old_set,
        *predecessor_context.activation().new_validator_set()
    );
    let successor_context = StrictEpochRuntimeContextV1::from_activation_v1(successor).unwrap();
    let composed = StrictEpochRuntimeContextV1::compose_successor_v1(
        &predecessor_context,
        successor_context,
        &ancestry,
    )
    .unwrap();
    assert_eq!(
        composed.activation().new_validator_set().epoch(),
        Epoch::new(4)
    );
}

#[test]
fn strict_runtime_context_rejects_a_successor_endpoint_substitution() {
    let predecessor_context =
        StrictEpochRuntimeContextV1::from_activation_v1(predecessor()).unwrap();
    let (evidence, old_set, old_params, binding, mut ancestry) =
        successor_evidence(&predecessor_context);
    let successor = recover_epoch_activation_authority_strict_v0(
        evidence.as_preimages(),
        &old_set,
        &old_params,
        binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let successor_context = StrictEpochRuntimeContextV1::from_activation_v1(successor).unwrap();
    ancestry.pop();
    let error = StrictEpochRuntimeContextV1::compose_successor_v1(
        &predecessor_context,
        successor_context,
        &ancestry,
    )
    .expect_err("a missing successor checkpoint parent must not compose");
    assert!(format!("{error:?}").contains("successor retained ancestry endpoints differ"));
}

#[test]
fn strict_runtime_context_rejects_a_disconnected_successor_ancestry_edge() {
    let predecessor_context =
        StrictEpochRuntimeContextV1::from_activation_v1(predecessor()).unwrap();
    let (evidence, old_set, old_params, binding, mut ancestry) =
        successor_evidence(&predecessor_context);
    let successor = recover_epoch_activation_authority_strict_v0(
        evidence.as_preimages(),
        &old_set,
        &old_params,
        binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let successor_context = StrictEpochRuntimeContextV1::from_activation_v1(successor).unwrap();
    let broken = ancestry[1].clone();
    ancestry[1] = BlockHeader::new(
        broken.genesis_hash(),
        broken.chain_id(),
        broken.protocol_version(),
        broken.epoch(),
        broken.view(),
        broken.height(),
        broken.block_kind(),
        BlockId::new([0xabu8; 32]),
        broken.proposer_id(),
        broken.validator_set_id(),
        broken.consensus_parameters_hash(),
        broken.payload_root(),
        broken.state_root(),
        broken.receipts_root(),
        broken.evidence_root(),
        broken.timestamp_ms(),
        broken.next_epoch_commitment_hash(),
    )
    .unwrap();
    let error = StrictEpochRuntimeContextV1::compose_successor_v1(
        &predecessor_context,
        successor_context,
        &ancestry,
    )
    .expect_err("a disconnected retained ancestry edge must not compose");
    assert!(format!("{error:?}").contains("successor retained ancestry edge mismatch"));
}

#[test]
fn strict_runtime_context_rejects_a_foreign_epoch_in_retained_successor_ancestry() {
    let predecessor_context =
        StrictEpochRuntimeContextV1::from_activation_v1(predecessor()).unwrap();
    let (evidence, old_set, old_params, binding, mut ancestry) =
        successor_evidence(&predecessor_context);
    let successor = recover_epoch_activation_authority_strict_v0(
        evidence.as_preimages(),
        &old_set,
        &old_params,
        binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let successor_context = StrictEpochRuntimeContextV1::from_activation_v1(successor).unwrap();
    let child = ancestry[1].clone();
    ancestry[1] = BlockHeader::new(
        child.genesis_hash(),
        child.chain_id(),
        child.protocol_version(),
        predecessor_context.activation().old_validator_set().epoch(),
        child.view(),
        child.height(),
        child.block_kind(),
        child.parent_id(),
        child.proposer_id(),
        child.validator_set_id(),
        child.consensus_parameters_hash(),
        child.payload_root(),
        child.state_root(),
        child.receipts_root(),
        child.evidence_root(),
        child.timestamp_ms(),
        child.next_epoch_commitment_hash(),
    )
    .unwrap();
    let error = StrictEpochRuntimeContextV1::compose_successor_v1(
        &predecessor_context,
        successor_context,
        &ancestry,
    )
    .expect_err("a foreign epoch ancestry child must not compose");
    assert!(format!("{error:?}").contains("successor retained ancestry edge mismatch"));
}

include!("epoch_runtime_successor_contextual.inc");
