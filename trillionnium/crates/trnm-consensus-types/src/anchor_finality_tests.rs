use alloc::{format, string::String, vec, vec::Vec};

use sha2::{Digest, Sha256};

use super::*;
use crate::message::{proposal_signing_bytes_from_digests, proposal_signing_root_from_digests};

const VECTOR_JSON: &str =
    include_str!("../../../../docs/protocol/poco-bft-v0/vectors/anchor-finality-v0.json");
const CHAIN_ID: ChainId = ChainId::from_static("trnm-anchor-0");
const BASE_TIMESTAMP_MS: u64 = 1_800_000_000_000;

#[derive(Debug)]
struct GoldenFixture {
    genesis_qc: GenesisQcV0,
    genesis_tc: TimeoutCertificateV0,
    genesis_proposal_bytes: Vec<u8>,
    genesis_proposal_root: SigningRoot,
    descriptor: HandoffDescriptorV0,
    handoff_certificate: HandoffCertificateV0,
    authorization: EpochAnchorAuthorizationV0,
    epoch_anchor_qc: EpochAnchorQcV0,
    finalized: CertifiedHeaderV0,
    child: CertifiedHeaderV0,
    grandchild: CertifiedHeaderV0,
    proof: FinalityProofV0,
    q0_alternate_subset: QuorumCertificate,
}

#[test]
fn anchor_handoff_and_finality_types_match_frozen_golden_bytes() {
    let fixture = build_fixture().unwrap();

    assert_vector_bytes("genesis_qc", &fixture.genesis_qc.try_cev0_bytes().unwrap());
    assert_vector_field(
        "genesis_qc",
        "digest_hex",
        fixture.genesis_qc.id().as_bytes(),
    );
    assert_vector_bytes(
        "genesis_view_3_timeout_certificate",
        &fixture.genesis_tc.try_cev0_bytes().unwrap(),
    );
    assert_vector_field(
        "genesis_view_3_timeout_certificate",
        "digest_hex",
        fixture.genesis_tc.id().as_bytes(),
    );
    assert_vector_bytes(
        "genesis_view_3_proposal_sign",
        &fixture.genesis_proposal_bytes,
    );
    assert_vector_field(
        "genesis_view_3_proposal_sign",
        "signing_root_hex",
        fixture.genesis_proposal_root.as_bytes(),
    );

    assert_vector_bytes(
        "handoff_descriptor",
        &fixture.descriptor.try_cev0_bytes().unwrap(),
    );
    assert_vector_field(
        "handoff_descriptor",
        "digest_hex",
        fixture.descriptor.id().as_bytes(),
    );
    assert_vector_bytes(
        "handoff_certificate",
        &fixture.handoff_certificate.try_cev0_bytes().unwrap(),
    );
    assert_vector_field(
        "handoff_certificate",
        "digest_hex",
        fixture.handoff_certificate.id().as_bytes(),
    );
    assert_vector_bytes(
        "epoch_anchor_authorization",
        &fixture.authorization.try_cev0_bytes().unwrap(),
    );
    assert_vector_bytes(
        "epoch_anchor_qc",
        &fixture.epoch_anchor_qc.try_cev0_bytes().unwrap(),
    );
    assert_vector_field(
        "epoch_anchor_qc",
        "digest_hex",
        fixture.epoch_anchor_qc.id().as_bytes(),
    );

    assert_certified_header("finalized_block", &fixture.finalized);
    assert_certified_header("child", &fixture.child);
    assert_certified_header("grandchild", &fixture.grandchild);
    assert_vector_bytes("finality_proof", &fixture.proof.try_cev0_bytes().unwrap());
    assert_vector_field(
        "finality_proof",
        "digest_hex",
        fixture.proof.id().as_bytes(),
    );
    assert_eq!(
        hex_bytes(fixture.proof.id().as_bytes()),
        "f2db7eda8e8a8bc60c3d0d242e72e24aa8284e286d5007493299fcd590bcc9f0"
    );
}

#[test]
fn synthetic_anchors_cannot_enter_ordinary_or_certifying_qc_slots() {
    let fixture = build_fixture().unwrap();
    let synthetic = QcReferenceV0::epoch_anchor(fixture.epoch_anchor_qc.clone());
    assert!(synthetic.as_ordinary().is_none());
    assert!(synthetic.as_synthetic().is_some());

    let anchor = &fixture.epoch_anchor_qc;
    let empty_ordinary = QuorumCertificate::from_parts_for_test(
        anchor.genesis_hash(),
        anchor.chain_id(),
        anchor.protocol_version(),
        anchor.epoch(),
        anchor.view(),
        anchor.height(),
        anchor.block_id(),
        anchor.validator_set_hash(),
        vec![],
    );
    assert_eq!(
        empty_ordinary.unwrap_err(),
        ValidationError::InvalidCertificate("ordinary test QC must contain signatures")
    );

    // `CertifiedHeaderV0::certifying_qc` is statically a
    // `QuorumCertificate`, never `QcReferenceV0`; the only raw ordinary-QC
    // fixture constructor also rejects an empty signature list above.
    assert!(!fixture.finalized.certifying_qc().votes().is_empty());
}

#[test]
fn frozen_negative_mutations_fail_closed() {
    let fixture = build_fixture().unwrap();

    assert_global_field(
        "replacement_qc_digest_hex",
        fixture.q0_alternate_subset.id().as_bytes(),
    );
    let replaced_child = CertifiedHeaderV0::from_parts_unchecked_for_test(
        fixture.child.header().clone(),
        QcReferenceV0::ordinary(fixture.q0_alternate_subset.clone()),
        fixture.child.timeout_certificate().cloned(),
        fixture.child.epoch_anchor_authorization().cloned(),
        *fixture.child.proposer_signature(),
        fixture.child.certifying_qc().clone(),
    );
    let replacement_error = FinalityProofV0::from_parts_for_test(
        fixture.finalized.clone(),
        replaced_child,
        fixture.grandchild.clone(),
    )
    .unwrap_err();
    assert_eq!(
        replacement_error,
        ValidationError::InvalidFinalityProof(
            "child justify-QC digest differs from finalized certifying QC"
        )
    );

    assert_eq!(
        Signature64::from_slice(&[]).unwrap_err(),
        ValidationError::InvalidSignatureLength {
            actual: 0,
            expected: SIGNATURE_BYTES,
        }
    );

    let child_tc = fixture.child.timeout_certificate().unwrap();
    let mutated_selected = CertificateId::new(fixture_hash("mutated-selected-high-qc"));
    assert_global_field("mutated_selected_digest_hex", mutated_selected.as_bytes());
    let selected_error = TimeoutCertificateV0::from_parts_for_test(
        child_tc.genesis_hash(),
        child_tc.chain_id(),
        child_tc.protocol_version(),
        child_tc.epoch(),
        child_tc.validator_set_hash(),
        child_tc.timed_out_view(),
        child_tc.entries().to_vec(),
        child_tc.referenced_qcs().to_vec(),
        mutated_selected,
    )
    .unwrap_err();
    assert_eq!(
        selected_error,
        ValidationError::InvalidCertificate("TC selected high QC is not the deterministic maximum")
    );
}

fn build_fixture() -> Result<GoldenFixture> {
    let genesis_hash = GenesisHash::new(fixture_hash("genesis"));
    let old_set_hash = ValidatorSetId::new(fixture_hash("old-validator-set"));
    let new_set_hash = ValidatorSetId::new(fixture_hash("new-validator-set"));
    let old_parameters_hash = ConsensusParametersHash::new(fixture_hash("old-parameters"));
    let new_parameters_hash = ConsensusParametersHash::new(fixture_hash("new-parameters"));
    let checkpoint_state_root = fixture_hash("checkpoint-state");
    let next_epoch_commitment = fixture_hash("next-epoch-commitment");
    let old_signers = [
        validator_id(b"old-a")?,
        validator_id(b"old-b")?,
        validator_id(b"old-c")?,
    ];
    let new_signers = [
        validator_id(b"new-a")?,
        validator_id(b"new-b")?,
        validator_id(b"new-c")?,
    ];

    let genesis_qc = GenesisQcV0::from_parts_for_test(genesis_hash, CHAIN_ID, old_set_hash)?;
    let genesis_header = make_header(
        genesis_hash,
        ProtocolVersion::V0,
        Epoch::new(0),
        View::new(3),
        Height::new(1),
        BlockKind::Regular,
        BlockId::new(*genesis_hash.as_bytes()),
        validator_id(b"old-c")?,
        old_set_hash,
        old_parameters_hash,
        "genesis-first-view-3",
        None,
        BASE_TIMESTAMP_MS,
        None,
    )?;
    let genesis_tc = make_tc(
        genesis_hash,
        ProtocolVersion::V0,
        Epoch::new(0),
        old_set_hash,
        View::new(2),
        QcReferenceV0::genesis_anchor(genesis_qc.clone()),
        &old_signers,
    )?;
    let genesis_context = CommonConsensusContextV0::new(
        genesis_hash,
        CHAIN_ID,
        ProtocolVersion::V0,
        Epoch::new(0),
        old_set_hash,
        View::new(3),
        MessageKind::Proposal,
    )?;
    let genesis_proposal_bytes = proposal_signing_bytes_from_digests(
        genesis_context,
        Height::new(1),
        genesis_header.id(),
        genesis_qc.id(),
        Some(genesis_tc.id()),
        None,
    )?;
    let genesis_proposal_root = proposal_signing_root_from_digests(
        genesis_context,
        Height::new(1),
        genesis_header.id(),
        genesis_qc.id(),
        Some(genesis_tc.id()),
        None,
    );

    let terminal_header = make_header(
        genesis_hash,
        ProtocolVersion::V0,
        Epoch::new(0),
        View::new(12),
        Height::new(10),
        BlockKind::EpochSeal2,
        BlockId::new(fixture_hash("old-seal-1-block")),
        validator_id(b"old-d")?,
        old_set_hash,
        old_parameters_hash,
        "terminal-old-seal-2",
        Some(checkpoint_state_root),
        BASE_TIMESTAMP_MS + 10_000,
        Some(next_epoch_commitment),
    )?;
    let terminal_qc = raw_qc(
        genesis_hash,
        ProtocolVersion::V0,
        Epoch::new(0),
        View::new(12),
        Height::new(10),
        terminal_header.id(),
        old_set_hash,
        &old_signers,
    )?;
    let descriptor = HandoffDescriptorV0::new(HandoffDescriptorV0Fields {
        genesis_hash,
        chain_id: CHAIN_ID,
        old_epoch: Epoch::new(0),
        new_epoch: Epoch::new(1),
        old_protocol_version: ProtocolVersion::V0,
        new_protocol_version: ProtocolVersion::V0,
        old_validator_set_hash: old_set_hash,
        new_validator_set_hash: new_set_hash,
        old_consensus_parameters_hash: old_parameters_hash,
        new_consensus_parameters_hash: new_parameters_hash,
        checkpoint_height: Height::new(8),
        checkpoint_block_id: BlockId::new(fixture_hash("old-checkpoint-block")),
        checkpoint_state_root: StateRoot::new(checkpoint_state_root),
        next_epoch_commitment_digest: NextEpochCommitmentHash::new(next_epoch_commitment),
        terminal_old_height: Height::new(10),
        terminal_old_block_id: terminal_header.id(),
        terminal_old_qc_digest: terminal_qc.id(),
        terminal_old_view: View::new(12),
        activation_height: Height::new(11),
        initial_new_view: View::new(1),
    })?;
    let handoff_certificate = HandoffCertificateV0::from_parts_for_test(
        descriptor.clone(),
        signature_shares(&old_signers)?,
        signature_shares(&new_signers)?,
    )?;
    let authorization = EpochAnchorAuthorizationV0::from_parts_for_test(
        terminal_header.clone(),
        terminal_qc,
        handoff_certificate.clone(),
    )?;
    let epoch_anchor_qc = authorization.epoch_anchor_qc();
    let first_epoch_tc = make_tc(
        genesis_hash,
        ProtocolVersion::V0,
        Epoch::new(1),
        new_set_hash,
        View::new(1),
        QcReferenceV0::epoch_anchor(epoch_anchor_qc.clone()),
        &new_signers,
    )?;

    let finalized_header = make_header(
        genesis_hash,
        ProtocolVersion::V0,
        Epoch::new(1),
        View::new(2),
        Height::new(11),
        BlockKind::EpochHandoff,
        terminal_header.id(),
        validator_id(b"new-b")?,
        new_set_hash,
        new_parameters_hash,
        "new-epoch-first-view-2",
        None,
        BASE_TIMESTAMP_MS + 11_000,
        None,
    )?;
    let q0 = raw_qc(
        genesis_hash,
        ProtocolVersion::V0,
        Epoch::new(1),
        View::new(2),
        Height::new(11),
        finalized_header.id(),
        new_set_hash,
        &new_signers,
    )?;
    let alternate_signers = [
        validator_id(b"new-b")?,
        validator_id(b"new-c")?,
        validator_id(b"new-d")?,
    ];
    let q0_alternate_subset = raw_qc(
        genesis_hash,
        ProtocolVersion::V0,
        Epoch::new(1),
        View::new(2),
        Height::new(11),
        finalized_header.id(),
        new_set_hash,
        &alternate_signers,
    )?;
    let finalized_witness = ProposalWitnessV0::from_parts_for_test(
        QcReferenceV0::epoch_anchor(epoch_anchor_qc.clone()),
        Some(first_epoch_tc),
        Some(authorization.clone()),
        fixed_signature(),
    )?;
    let finalized = CertifiedHeaderV0::from_proposal_witness_for_test(
        finalized_header.clone(),
        finalized_witness,
        q0.clone(),
    )?;

    let child_header = make_header(
        genesis_hash,
        ProtocolVersion::V0,
        Epoch::new(1),
        View::new(4),
        Height::new(12),
        BlockKind::Regular,
        finalized_header.id(),
        validator_id(b"new-d")?,
        new_set_hash,
        new_parameters_hash,
        "finality-child-view-4",
        None,
        BASE_TIMESTAMP_MS + 12_000,
        None,
    )?;
    let child_tc = make_tc(
        genesis_hash,
        ProtocolVersion::V0,
        Epoch::new(1),
        new_set_hash,
        View::new(3),
        QcReferenceV0::ordinary(q0.clone()),
        &new_signers,
    )?;
    let q1 = raw_qc(
        genesis_hash,
        ProtocolVersion::V0,
        Epoch::new(1),
        View::new(4),
        Height::new(12),
        child_header.id(),
        new_set_hash,
        &new_signers,
    )?;
    let child_witness = ProposalWitnessV0::from_parts_for_test(
        QcReferenceV0::ordinary(q0),
        Some(child_tc),
        None,
        fixed_signature(),
    )?;
    let child = CertifiedHeaderV0::from_proposal_witness_for_test(
        child_header.clone(),
        child_witness,
        q1.clone(),
    )?;

    let grandchild_header = make_header(
        genesis_hash,
        ProtocolVersion::V0,
        Epoch::new(1),
        View::new(5),
        Height::new(13),
        BlockKind::Regular,
        child_header.id(),
        validator_id(b"new-a")?,
        new_set_hash,
        new_parameters_hash,
        "finality-grandchild-view-5",
        None,
        BASE_TIMESTAMP_MS + 13_000,
        None,
    )?;
    let q2 = raw_qc(
        genesis_hash,
        ProtocolVersion::V0,
        Epoch::new(1),
        View::new(5),
        Height::new(13),
        grandchild_header.id(),
        new_set_hash,
        &new_signers,
    )?;
    let grandchild_witness = ProposalWitnessV0::from_parts_for_test(
        QcReferenceV0::ordinary(q1),
        None,
        None,
        fixed_signature(),
    )?;
    let grandchild = CertifiedHeaderV0::from_proposal_witness_for_test(
        grandchild_header,
        grandchild_witness,
        q2,
    )?;
    let proof =
        FinalityProofV0::from_parts_for_test(finalized.clone(), child.clone(), grandchild.clone())?;

    Ok(GoldenFixture {
        genesis_qc,
        genesis_tc,
        genesis_proposal_bytes,
        genesis_proposal_root,
        descriptor,
        handoff_certificate,
        authorization,
        epoch_anchor_qc,
        finalized,
        child,
        grandchild,
        proof,
        q0_alternate_subset,
    })
}

#[allow(clippy::too_many_arguments)]
fn make_header(
    genesis_hash: GenesisHash,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    view: View,
    height: Height,
    block_kind: BlockKind,
    parent_id: BlockId,
    proposer_id: ValidatorId,
    validator_set_id: ValidatorSetId,
    parameters_hash: ConsensusParametersHash,
    label: &str,
    state_root: Option<[u8; 32]>,
    timestamp_ms: u64,
    next_epoch_commitment: Option<[u8; 32]>,
) -> Result<BlockHeader> {
    BlockHeader::new(
        genesis_hash,
        CHAIN_ID,
        protocol_version,
        epoch,
        view,
        height,
        block_kind,
        parent_id,
        proposer_id,
        validator_set_id,
        parameters_hash,
        PayloadDigest::new(fixture_hash(&format!("{label}:payload"))),
        StateRoot::new(state_root.unwrap_or_else(|| fixture_hash(&format!("{label}:state")))),
        ReceiptsRoot::new(fixture_hash(&format!("{label}:receipts"))),
        EvidenceRoot::new(fixture_hash(&format!("{label}:evidence"))),
        timestamp_ms,
        next_epoch_commitment.map(NextEpochCommitmentHash::new),
    )
}

#[allow(clippy::too_many_arguments)]
fn raw_qc(
    genesis_hash: GenesisHash,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    view: View,
    height: Height,
    block_id: BlockId,
    validator_set_hash: ValidatorSetId,
    signer_ids: &[ValidatorId],
) -> Result<QuorumCertificate> {
    let signatures = signer_ids
        .iter()
        .copied()
        .map(|signer| (signer, fixed_signature()))
        .collect();
    QuorumCertificate::from_parts_for_test(
        genesis_hash,
        CHAIN_ID,
        protocol_version,
        epoch,
        view,
        height,
        block_id,
        validator_set_hash,
        signatures,
    )
}

fn make_tc(
    genesis_hash: GenesisHash,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    validator_set_hash: ValidatorSetId,
    timed_out_view: View,
    high_qc: QcReferenceV0,
    signer_ids: &[ValidatorId],
) -> Result<TimeoutCertificateV0> {
    let high_qc_summary = high_qc.qc_ref();
    let selected_high_qc_digest = high_qc.id();
    let entries = signer_ids
        .iter()
        .copied()
        .map(|signer| TimeoutEntryV0::new(signer, high_qc_summary, fixed_signature()))
        .collect::<Result<Vec<_>>>()?;
    TimeoutCertificateV0::from_parts_for_test(
        genesis_hash,
        CHAIN_ID,
        protocol_version,
        epoch,
        validator_set_hash,
        timed_out_view,
        entries,
        vec![high_qc],
        selected_high_qc_digest,
    )
}

fn signature_shares(signers: &[ValidatorId]) -> Result<Vec<SignatureShareV0>> {
    signers
        .iter()
        .copied()
        .map(|signer| SignatureShareV0::new(signer, fixed_signature()))
        .collect()
}

fn validator_id(value: &[u8]) -> Result<ValidatorId> {
    ValidatorId::from_bytes(value)
}

fn fixed_signature() -> Signature64 {
    Signature64::from_array(hex_array(
        "324a7b305ab428de6f7bdde956b7c9f6f5cf0a92bdd21b0b2b5b0b166fa61411403ed1a3b5d4f2dc234ac78b11a5ca5f8d8fae548c22b5386818f328e503bd0d",
    ))
}

fn fixture_hash(label: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.poco-bft.anchor-finality.fixture.v0:");
    hasher.update(label.as_bytes());
    hasher.finalize().into()
}

fn assert_certified_header(object: &str, certified: &CertifiedHeaderV0) {
    assert_vector_bytes(object, &certified.try_cev0_bytes().unwrap());
    let signed_proposal = SignedProposalV0::from_parts_for_test(
        Block::new(certified.header().clone(), vec![]).unwrap(),
        certified.witness().clone(),
    )
    .unwrap();
    assert_eq!(
        signed_proposal.signing_root(),
        certified.proposal_signing_root(),
        "shared proposal witness root mismatch for {object}"
    );
    assert_vector_field(object, "block_id_hex", certified.header().id().as_bytes());
    assert_vector_field(
        object,
        "justify_qc_digest_hex",
        certified.justify_qc().id().as_bytes(),
    );
    if let Some(certificate) = certified.timeout_certificate() {
        assert_vector_field(
            object,
            "timeout_certificate_digest_hex",
            certificate.id().as_bytes(),
        );
    }
    if let Some(authorization) = certified.epoch_anchor_authorization() {
        assert_vector_field(
            object,
            "handoff_certificate_digest_hex",
            authorization.handoff_certificate().id().as_bytes(),
        );
    }
    assert_vector_field(
        object,
        "proposal_signing_root_hex",
        certified.proposal_signing_root().as_bytes(),
    );
    assert_vector_field(
        object,
        "certifying_qc_digest_hex",
        certified.certifying_qc().id().as_bytes(),
    );
}

fn assert_vector_bytes(object: &str, actual: &[u8]) {
    assert_eq!(
        hex_bytes(actual),
        vector_string_field(object, "cev0_hex"),
        "CEV0 mismatch for {object}"
    );
}

fn assert_vector_field(object: &str, field: &str, actual: &[u8]) {
    assert_eq!(
        hex_bytes(actual),
        vector_string_field(object, field),
        "vector field mismatch for {object}.{field}"
    );
}

fn assert_global_field(field: &str, actual: &[u8]) {
    assert_eq!(
        hex_bytes(actual),
        global_string_field(field),
        "vector field mismatch for {field}"
    );
}

fn vector_string_field(object: &str, field: &str) -> &'static str {
    let object_marker = format!("\"{object}\": {{");
    let object_start = VECTOR_JSON
        .find(&object_marker)
        .unwrap_or_else(|| panic!("missing vector object {object}"));
    string_field_from(&VECTOR_JSON[object_start + object_marker.len()..], field)
}

fn global_string_field(field: &str) -> &'static str {
    string_field_from(VECTOR_JSON, field)
}

fn string_field_from(source: &'static str, field: &str) -> &'static str {
    let field_marker = format!("\"{field}\": \"");
    let value_start = source
        .find(&field_marker)
        .unwrap_or_else(|| panic!("missing vector field {field}"))
        + field_marker.len();
    let remainder = &source[value_start..];
    let value_end = remainder
        .find('"')
        .unwrap_or_else(|| panic!("unterminated vector field {field}"));
    &remainder[..value_end]
}

fn hex_bytes(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    let source = value.as_bytes();
    let mut output = [0u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = (hex_nibble(source[index * 2]) << 4) | hex_nibble(source[index * 2 + 1]);
    }
    output
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("invalid lowercase hex fixture"),
    }
}
