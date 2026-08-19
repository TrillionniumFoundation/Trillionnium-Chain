use serde_json::Value;
use sha2::{Digest, Sha256};
use trnm_consensus_crypto::{
    verify_same_version_epoch_activation_authority_strict_v0, StrictEd25519Verifier,
};
use trnm_consensus_types::{
    decode_block_header_v0_exact, decode_checkpoint_finality_proof_v0_exact,
    decode_consensus_parameters_v0_exact, decode_epoch_anchor_authorization_kernel_v0_exact,
    decode_next_epoch_commitment_v0_exact, decode_validator_set_v0_exact,
    verify_same_version_joint_handoff_kernel_v0, BlockHeader, ConsensusParametersV0, DecodeError,
    EpochAnchorAuthorizationKernelV0, FinalityProofV0, JointHandoffKernelErrorCode,
    JointHandoffKernelV0, NextEpochCommitmentV0, StateRoot, ValidatorSet,
};

const VECTOR: &str = include_str!(
    "../../../../docs/protocol/poco-bft-v0/vectors/joint-handoff-composition-kernel-v0.json"
);
const AUTHORITY_VECTOR: &str = include_str!(
    "../../../../docs/protocol/poco-bft-v0/vectors/poco-authenticated-checkpoint-handoff-v0.json"
);
const STRICT_EPOCH_ACTIVATION_BINDING_DOMAIN_V0: &[u8] =
    b"trnm.poco-bft.strict-epoch-activation-binding-ref.v0";
const POSITIVE_BINDING_REF_HEX: &str =
    "4ba70b831d3bd70a1be8669f654ac42148017fca0b83f84e999ac532b9c70e4f";
const FALLBACK_BINDING_REF_HEX: &str =
    "3f719cc7d84539da791a3206d46c4d529f390b2333c35128847f7b62dcd2fc73";

struct DecodedBundle {
    old_parameters: ConsensusParametersV0,
    new_parameters: ConsensusParametersV0,
    old_set: ValidatorSet,
    new_set: ValidatorSet,
    commitment: NextEpochCommitmentV0,
    finality: FinalityProofV0,
    anchor_kernel: EpochAnchorAuthorizationKernelV0,
    composition_parent_timestamp_ms: u64,
}

struct DecodedAuthorityBundle {
    old_parameters: ConsensusParametersV0,
    new_parameters: ConsensusParametersV0,
    old_set: ValidatorSet,
    new_set: ValidatorSet,
    commitment: NextEpochCommitmentV0,
    checkpoint_parent_header: BlockHeader,
    finality: FinalityProofV0,
    anchor_kernel: EpochAnchorAuthorizationKernelV0,
    raw_anchor_kernel: Vec<u8>,
}

#[derive(Debug)]
struct BundleDecodeFailure {
    stage: &'static str,
    error: DecodeError,
}

#[test]
fn exact_raw_positive_bundles_return_only_the_committed_inert_facts() {
    let root: Value = serde_json::from_str(VECTOR).expect("valid B2-F vector JSON");
    assert_manifest_identity(&root);

    let positives = array(&root, "positive_cases");
    assert_eq!(
        positives.len(),
        2,
        "B2-F must retain both positive profiles"
    );
    let verifier = StrictEd25519Verifier;

    for case in positives {
        let id = string(case, "id");
        let decoded =
            decode_raw_bundle(case).unwrap_or_else(|failure| panic!("{id} failed at {failure:?}"));
        let token = verify_same_version_joint_handoff_kernel_v0(
            &decoded.finality,
            &decoded.commitment,
            &decoded.anchor_kernel,
            &decoded.old_set,
            &decoded.old_parameters,
            &decoded.new_set,
            &decoded.new_parameters,
            decoded.composition_parent_timestamp_ms,
            &verifier,
        )
        .unwrap_or_else(|failure| panic!("{id} composition failed: {failure}"));

        assert_token_facts(&token, object(case, "expected_token_facts"), id);
    }

    let ids: Vec<_> = positives.iter().map(|case| string(case, "id")).collect();
    assert_eq!(ids, ["distinct_set", "exact_fallback"]);
}

#[test]
fn strict_pre_first_block_authority_owns_every_exact_bound_preimage() {
    let root: Value = serde_json::from_str(AUTHORITY_VECTOR)
        .expect("valid authenticated checkpoint/handoff vector JSON");

    for profile in ["positive", "authenticated_fallback"] {
        let case = object(&root, profile);
        let id = string(case, "id");
        let decoded = decode_authority_bundle(case);
        let authority = verify_same_version_epoch_activation_authority_strict_v0(
            &decoded.finality,
            &decoded.commitment,
            &decoded.anchor_kernel,
            &decoded.old_set,
            &decoded.old_parameters,
            &decoded.new_set,
            &decoded.new_parameters,
            &decoded.checkpoint_parent_header,
        )
        .unwrap_or_else(|failure| panic!("{id} authority failed: {failure}"));

        assert_eq!(
            authority.joint_handoff().checkpoint_finality_proof_id(),
            decoded.finality.id()
        );
        assert_eq!(
            authority.joint_handoff().handoff_certificate_digest(),
            decoded.anchor_kernel.handoff_certificate().id()
        );
        assert_eq!(authority.old_checkpoint_finality(), &decoded.finality);
        assert_eq!(authority.next_epoch_commitment(), &decoded.commitment);
        assert_eq!(authority.old_validator_set(), &decoded.old_set);
        assert_eq!(authority.new_validator_set(), &decoded.new_set);
        assert_eq!(
            authority.old_consensus_parameters(),
            &decoded.old_parameters
        );
        assert_eq!(
            authority.new_consensus_parameters(),
            &decoded.new_parameters
        );
        assert_eq!(
            authority.authenticated_checkpoint_parent_header(),
            &decoded.checkpoint_parent_header
        );
        assert_eq!(
            authority.authenticated_checkpoint_parent_block_id(),
            decoded.finality.finalized_block().header().parent_id()
        );
        assert_eq!(
            authority.authenticated_checkpoint_parent_timestamp_ms(),
            decoded.checkpoint_parent_header.timestamp_ms()
        );
        assert_eq!(authority.authorization_kernel(), &decoded.anchor_kernel);
        assert_eq!(
            authority
                .authorization_cev0_bytes()
                .expect("bounded authorization bytes"),
            decoded.raw_anchor_kernel
        );
        assert_eq!(
            authority.terminal_old_header(),
            decoded.anchor_kernel.terminal_old_header()
        );
        assert_eq!(
            authority.terminal_old_qc(),
            decoded.anchor_kernel.terminal_old_qc()
        );
        assert_eq!(
            authority.handoff_certificate(),
            decoded.anchor_kernel.handoff_certificate()
        );
        let expected_binding_ref = match profile {
            "positive" => POSITIVE_BINDING_REF_HEX,
            "authenticated_fallback" => FALLBACK_BINDING_REF_HEX,
            _ => unreachable!("the profile loop is closed above"),
        };
        assert_eq!(
            authority.binding_ref().as_bytes(),
            &hex_32(expected_binding_ref),
            "{id} strict activation binding vector drift"
        );
    }
}

#[test]
fn strict_binding_ref_commits_every_exact_cev0_preimage_in_fixed_order() {
    let root: Value = serde_json::from_str(AUTHORITY_VECTOR)
        .expect("valid authenticated checkpoint/handoff vector JSON");
    let decoded = decode_authority_bundle(object(&root, "positive"));
    let preimages = exact_activation_preimages(&decoded);
    let baseline = activation_binding_vector_v0(&preimages);

    assert_eq!(baseline, hex_32(POSITIVE_BINDING_REF_HEX));

    let labels = [
        "checkpoint finality",
        "next-epoch commitment",
        "authorization kernel",
        "old validator set",
        "old consensus parameters",
        "new validator set",
        "new consensus parameters",
        "checkpoint-parent header",
    ];
    for (index, label) in labels.into_iter().enumerate() {
        let mut substituted = preimages.clone();
        let offset = substituted[index].len() / 2;
        substituted[index][offset] ^= 0x01;
        assert_ne!(
            activation_binding_vector_v0(&substituted),
            baseline,
            "{label} substitution must change the binding reference"
        );
    }

    let mut reordered = preimages.clone();
    reordered.swap(0, 1);
    assert_ne!(
        activation_binding_vector_v0(&reordered),
        baseline,
        "field order is part of the frozen binding vector"
    );
}

#[test]
fn strict_authority_rejects_cross_bundle_substitution_before_minting() {
    let root: Value = serde_json::from_str(AUTHORITY_VECTOR)
        .expect("valid authenticated checkpoint/handoff vector JSON");
    let first = decode_authority_bundle(object(&root, "positive"));
    let second = decode_authority_bundle(object(&root, "authenticated_fallback"));
    let generic_root: Value =
        serde_json::from_str(VECTOR).expect("valid B2-F composition vector JSON");
    let foreign_context = decode_raw_bundle(&array(&generic_root, "positive_cases")[0])
        .expect("foreign but internally valid composition context");

    assert!(verify_same_version_epoch_activation_authority_strict_v0(
        &second.finality,
        &first.commitment,
        &first.anchor_kernel,
        &first.old_set,
        &first.old_parameters,
        &first.new_set,
        &first.new_parameters,
        &first.checkpoint_parent_header,
    )
    .is_err());
    assert!(verify_same_version_epoch_activation_authority_strict_v0(
        &first.finality,
        &second.commitment,
        &first.anchor_kernel,
        &first.old_set,
        &first.old_parameters,
        &first.new_set,
        &first.new_parameters,
        &first.checkpoint_parent_header,
    )
    .is_err());
    assert!(verify_same_version_epoch_activation_authority_strict_v0(
        &first.finality,
        &first.commitment,
        &second.anchor_kernel,
        &first.old_set,
        &first.old_parameters,
        &first.new_set,
        &first.new_parameters,
        &first.checkpoint_parent_header,
    )
    .is_err());
    assert_eq!(
        first.new_set, second.new_set,
        "the authenticated fallback corpus intentionally retains the same candidate set"
    );
    assert!(verify_same_version_epoch_activation_authority_strict_v0(
        &first.finality,
        &first.commitment,
        &first.anchor_kernel,
        &foreign_context.old_set,
        &first.old_parameters,
        &first.new_set,
        &first.new_parameters,
        &first.checkpoint_parent_header,
    )
    .is_err());
    assert!(verify_same_version_epoch_activation_authority_strict_v0(
        &first.finality,
        &first.commitment,
        &first.anchor_kernel,
        &first.old_set,
        &first.old_parameters,
        &foreign_context.new_set,
        &first.new_parameters,
        &first.checkpoint_parent_header,
    )
    .is_err());

    let mut old_parameter_fields = first.old_parameters.fields();
    old_parameter_fields.base_timeout_ms += 1;
    let substituted_old_parameters =
        ConsensusParametersV0::new(old_parameter_fields).expect("valid substituted old params");
    assert!(verify_same_version_epoch_activation_authority_strict_v0(
        &first.finality,
        &first.commitment,
        &first.anchor_kernel,
        &first.old_set,
        &substituted_old_parameters,
        &first.new_set,
        &first.new_parameters,
        &first.checkpoint_parent_header,
    )
    .is_err());

    let mut new_parameter_fields = first.new_parameters.fields();
    new_parameter_fields.base_timeout_ms += 1;
    let substituted_new_parameters =
        ConsensusParametersV0::new(new_parameter_fields).expect("valid substituted new params");
    assert!(verify_same_version_epoch_activation_authority_strict_v0(
        &first.finality,
        &first.commitment,
        &first.anchor_kernel,
        &first.old_set,
        &first.old_parameters,
        &first.new_set,
        &substituted_new_parameters,
        &first.checkpoint_parent_header,
    )
    .is_err());
}

#[test]
fn strict_authority_rejects_parent_timestamp_and_header_substitution() {
    let root: Value = serde_json::from_str(AUTHORITY_VECTOR)
        .expect("valid authenticated checkpoint/handoff vector JSON");
    let decoded = decode_authority_bundle(object(&root, "positive"));
    let checkpoint_timestamp = decoded.finality.finalized_block().header().timestamp_ms();

    let substituted_timestamp = decoded
        .checkpoint_parent_header
        .timestamp_ms()
        .checked_add(1)
        .expect("fixture timestamp has room");
    assert!(substituted_timestamp < checkpoint_timestamp);
    assert!(
        checkpoint_timestamp - substituted_timestamp
            <= decoded.old_parameters.max_block_time_step_ms()
    );
    let wrong_timestamp_parent = rebuild_parent_header(
        &decoded.checkpoint_parent_header,
        substituted_timestamp,
        decoded.checkpoint_parent_header.state_root(),
    );
    assert_ne!(
        wrong_timestamp_parent.id(),
        decoded.finality.finalized_block().header().parent_id(),
        "the changed timestamp must also change the canonical parent identity"
    );
    let baseline_preimages = exact_activation_preimages(&decoded);
    let mut timestamp_preimages = baseline_preimages.clone();
    timestamp_preimages[7] = wrong_timestamp_parent
        .try_cev0_bytes()
        .expect("bounded substituted parent header");
    assert_ne!(
        activation_binding_vector_v0(&timestamp_preimages),
        activation_binding_vector_v0(&baseline_preimages),
        "the exact parent timestamp and resulting header ID are binding inputs"
    );
    let timestamp_failure = verify_same_version_epoch_activation_authority_strict_v0(
        &decoded.finality,
        &decoded.commitment,
        &decoded.anchor_kernel,
        &decoded.old_set,
        &decoded.old_parameters,
        &decoded.new_set,
        &decoded.new_parameters,
        &wrong_timestamp_parent,
    )
    .expect_err("a plausible scalar timestamp cannot substitute its exact parent header");
    assert_eq!(
        timestamp_failure.code(),
        JointHandoffKernelErrorCode::CheckpointParentMismatch
    );

    let wrong_identity_parent = rebuild_parent_header(
        &decoded.checkpoint_parent_header,
        decoded.checkpoint_parent_header.timestamp_ms(),
        StateRoot::new([0xa5; 32]),
    );
    assert_ne!(
        wrong_identity_parent.id(),
        decoded.finality.finalized_block().header().parent_id()
    );
    let mut identity_preimages = baseline_preimages.clone();
    identity_preimages[7] = wrong_identity_parent
        .try_cev0_bytes()
        .expect("bounded substituted parent header");
    assert_ne!(
        activation_binding_vector_v0(&identity_preimages),
        activation_binding_vector_v0(&baseline_preimages),
        "a different canonical parent header ID must change the binding reference"
    );
    let identity_failure = verify_same_version_epoch_activation_authority_strict_v0(
        &decoded.finality,
        &decoded.commitment,
        &decoded.anchor_kernel,
        &decoded.old_set,
        &decoded.old_parameters,
        &decoded.new_set,
        &decoded.new_parameters,
        &wrong_identity_parent,
    )
    .expect_err("a different valid header cannot substitute the checkpoint parent");
    assert_eq!(
        identity_failure.code(),
        JointHandoffKernelErrorCode::CheckpointParentMismatch
    );
}

#[test]
fn every_raw_negative_fails_at_its_committed_rust_stage_and_code() {
    let root: Value = serde_json::from_str(VECTOR).expect("valid B2-F vector JSON");
    assert_manifest_identity(&root);

    let negatives = array(&root, "negative_cases");
    assert_eq!(negatives.len(), 10, "B2-F must retain ten negative classes");
    let verifier = StrictEd25519Verifier;
    let mut composition_rejections = 0usize;
    let mut decoder_rejections = 0usize;

    for case in negatives {
        let id = string(case, "id");
        let expected_stage = string(case, "expected_rust_stage");
        let expected_code = string(case, "expected_rust_code");
        match expected_stage {
            "composition" => {
                let decoded = decode_raw_bundle(case).unwrap_or_else(|failure| {
                    panic!("{id} was committed for composition but failed at {failure:?}")
                });
                let failure = verify_same_version_joint_handoff_kernel_v0(
                    &decoded.finality,
                    &decoded.commitment,
                    &decoded.anchor_kernel,
                    &decoded.old_set,
                    &decoded.old_parameters,
                    &decoded.new_set,
                    &decoded.new_parameters,
                    decoded.composition_parent_timestamp_ms,
                    &verifier,
                )
                .unwrap_err();
                assert_eq!(
                    failure.code().as_str(),
                    expected_code,
                    "{id} semantic code drift"
                );
                composition_rejections += 1;
            }
            "decode" => {
                let failure = match decode_raw_bundle(case) {
                    Ok(_) => panic!("{id} unexpectedly passed its fail-closed exact decoder"),
                    Err(failure) => failure,
                };
                assert_eq!(
                    failure.stage, "epoch_anchor_authorization",
                    "{id} decode stage drift"
                );
                assert_eq!(
                    failure.error.code().as_str(),
                    expected_code,
                    "{id} decode code drift"
                );
                assert_eq!(
                    failure.error.byte_offset(),
                    number_usize(case, "expected_rust_offset"),
                    "{id} decode offset drift"
                );
                decoder_rejections += 1;
            }
            other => panic!("{id} names unsupported Rust stage {other}"),
        }
    }

    assert_eq!(composition_rejections, 9);
    assert_eq!(decoder_rejections, 1);
}

fn decode_raw_bundle(case: &Value) -> Result<DecodedBundle, BundleDecodeFailure> {
    let bundle = object(case, "raw_bundle");
    assert_eq!(number(bundle, "schema_version"), 0);
    assert!(bundle["aggregate_digest_domain"].is_null());
    let expected_genesis_hash = hex_32(string(bundle, "genesis_hash_hex"));
    let expected_chain_id = string(bundle, "chain_id");

    let old_parameters_raw = raw(bundle, "old_consensus_parameters_cev0_hex");
    let old_parameters = decode_consensus_parameters_v0_exact(&old_parameters_raw)
        .map_err(|error| decode_failure("old_consensus_parameters", error))?;
    assert_eq!(old_parameters.canonical_bytes(), old_parameters_raw);

    let new_parameters_raw = raw(bundle, "new_consensus_parameters_cev0_hex");
    let new_parameters = decode_consensus_parameters_v0_exact(&new_parameters_raw)
        .map_err(|error| decode_failure("new_consensus_parameters", error))?;
    assert_eq!(new_parameters.canonical_bytes(), new_parameters_raw);

    let old_set_raw = raw(bundle, "old_validator_set_cev0_hex");
    let old_set = decode_validator_set_v0_exact(&old_set_raw)
        .map_err(|error| decode_failure("old_validator_set", error))?;
    assert_eq!(
        old_set.try_cev0_bytes().expect("bounded old set"),
        old_set_raw
    );
    assert_eq!(old_set.genesis_hash().as_bytes(), &expected_genesis_hash);
    assert_eq!(old_set.chain_id().as_str(), expected_chain_id);

    let new_set_raw = raw(bundle, "new_validator_set_cev0_hex");
    let new_set = decode_validator_set_v0_exact(&new_set_raw)
        .map_err(|error| decode_failure("new_validator_set", error))?;
    assert_eq!(
        new_set.try_cev0_bytes().expect("bounded new set"),
        new_set_raw
    );
    assert_eq!(new_set.genesis_hash().as_bytes(), &expected_genesis_hash);
    assert_eq!(new_set.chain_id().as_str(), expected_chain_id);

    let commitment_raw = raw(bundle, "next_epoch_commitment_cev0_hex");
    let commitment = decode_next_epoch_commitment_v0_exact(&commitment_raw)
        .map_err(|error| decode_failure("next_epoch_commitment", error))?;
    assert_eq!(
        commitment.try_cev0_bytes().expect("bounded commitment"),
        commitment_raw
    );

    let decode_parent_timestamp_ms = decimal_u64(
        bundle,
        "decode_authenticated_checkpoint_parent_timestamp_ms",
    );
    let composition_parent_timestamp_ms = decimal_u64(
        bundle,
        "composition_authenticated_checkpoint_parent_timestamp_ms",
    );
    let finality_raw = raw(bundle, "old_checkpoint_finality_cev0_hex");
    let finality = decode_checkpoint_finality_proof_v0_exact(
        &finality_raw,
        &old_set,
        &old_parameters,
        &commitment,
        decode_parent_timestamp_ms,
    )
    .map_err(|error| decode_failure("old_checkpoint_finality", error))?;
    assert_eq!(
        finality.try_cev0_bytes().expect("bounded finality proof"),
        finality_raw
    );

    let anchor_raw = raw(bundle, "epoch_anchor_authorization_kernel_cev0_hex");
    let anchor_kernel =
        decode_epoch_anchor_authorization_kernel_v0_exact(&anchor_raw, &old_set, &new_set)
            .map_err(|error| decode_failure("epoch_anchor_authorization", error))?;
    assert_eq!(
        anchor_kernel
            .try_cev0_bytes()
            .expect("bounded anchor authorization kernel"),
        anchor_raw
    );

    Ok(DecodedBundle {
        old_parameters,
        new_parameters,
        old_set,
        new_set,
        commitment,
        finality,
        anchor_kernel,
        composition_parent_timestamp_ms,
    })
}

fn decode_authority_bundle(case: &Value) -> DecodedAuthorityBundle {
    let preheader = object(case, "preheader");
    let checkpoint_finality = object(case, "checkpoint_finality");
    let handoff = object(case, "handoff");

    let old_parameters =
        decode_consensus_parameters_v0_exact(&raw(preheader, "old_parameters_cev0_hex"))
            .expect("exact old parameters");
    let new_parameters =
        decode_consensus_parameters_v0_exact(&raw(preheader, "new_parameters_cev0_hex"))
            .expect("exact new parameters");
    let old_set = decode_validator_set_v0_exact(&raw(preheader, "old_validator_set_cev0_hex"))
        .expect("exact old set");
    let new_set = decode_validator_set_v0_exact(&raw(preheader, "new_validator_set_cev0_hex"))
        .expect("exact new set");
    let commitment = decode_next_epoch_commitment_v0_exact(&raw(preheader, "commitment_cev0_hex"))
        .expect("exact next-epoch commitment");
    let checkpoint_parent_header =
        decode_block_header_v0_exact(&raw(preheader, "checkpoint_parent_header_cev0_hex"))
            .expect("exact checkpoint parent header");
    let finality = decode_checkpoint_finality_proof_v0_exact(
        &raw(checkpoint_finality, "raw_finality_proof_cev0_hex"),
        &old_set,
        &old_parameters,
        &commitment,
        checkpoint_parent_header.timestamp_ms(),
    )
    .expect("exact checkpoint/two-seal finality");
    let raw_anchor_kernel = raw(handoff, "raw_anchor_certificate_kernel_cev0_hex");
    let anchor_kernel =
        decode_epoch_anchor_authorization_kernel_v0_exact(&raw_anchor_kernel, &old_set, &new_set)
            .expect("exact anchor certificate kernel");

    DecodedAuthorityBundle {
        old_parameters,
        new_parameters,
        old_set,
        new_set,
        commitment,
        checkpoint_parent_header,
        finality,
        anchor_kernel,
        raw_anchor_kernel,
    }
}

fn rebuild_parent_header(
    header: &BlockHeader,
    timestamp_ms: u64,
    state_root: StateRoot,
) -> BlockHeader {
    BlockHeader::new(
        header.genesis_hash(),
        header.chain_id(),
        header.protocol_version(),
        header.epoch(),
        header.view(),
        header.height(),
        header.block_kind(),
        header.parent_id(),
        header.proposer_id(),
        header.validator_set_id(),
        header.consensus_parameters_hash(),
        header.payload_digest(),
        state_root,
        header.receipts_root(),
        header.evidence_root(),
        timestamp_ms,
        header.next_epoch_commitment_hash(),
    )
    .expect("substituted parent header remains structurally valid")
}

fn exact_activation_preimages(decoded: &DecodedAuthorityBundle) -> [Vec<u8>; 8] {
    [
        decoded
            .finality
            .try_cev0_bytes()
            .expect("bounded checkpoint finality"),
        decoded
            .commitment
            .try_cev0_bytes()
            .expect("bounded next-epoch commitment"),
        decoded
            .anchor_kernel
            .try_cev0_bytes()
            .expect("bounded authorization kernel"),
        decoded
            .old_set
            .try_cev0_bytes()
            .expect("bounded old validator set"),
        decoded.old_parameters.canonical_bytes(),
        decoded
            .new_set
            .try_cev0_bytes()
            .expect("bounded new validator set"),
        decoded.new_parameters.canonical_bytes(),
        decoded
            .checkpoint_parent_header
            .try_cev0_bytes()
            .expect("bounded checkpoint-parent header"),
    ]
}

fn activation_binding_vector_v0(preimages: &[Vec<u8>; 8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.domain.hash.v1");
    hasher.update(
        u64::try_from(STRICT_EPOCH_ACTIVATION_BINDING_DOMAIN_V0.len())
            .expect("binding domain length fits u64")
            .to_be_bytes(),
    );
    hasher.update(STRICT_EPOCH_ACTIVATION_BINDING_DOMAIN_V0);
    for preimage in preimages {
        hasher.update(
            u64::try_from(preimage.len())
                .expect("bounded CEV0 preimage length fits u64")
                .to_be_bytes(),
        );
        hasher.update(preimage);
    }
    hasher.finalize().into()
}

fn assert_token_facts(token: &JointHandoffKernelV0, facts: &Value, id: &str) {
    assert_eq!(
        token.checkpoint_finality_proof_id().as_bytes(),
        &hex_32(string(facts, "checkpoint_finality_proof_id_hex")),
        "{id} finality proof ID"
    );
    assert_eq!(
        token.next_epoch_commitment_digest().as_bytes(),
        &hex_32(string(facts, "next_epoch_commitment_digest_hex")),
        "{id} commitment digest"
    );
    assert_eq!(
        token.handoff_descriptor_digest().as_bytes(),
        &hex_32(string(facts, "handoff_descriptor_digest_hex")),
        "{id} descriptor digest"
    );
    assert_eq!(
        token.handoff_certificate_digest().as_bytes(),
        &hex_32(string(facts, "handoff_certificate_digest_hex")),
        "{id} certificate digest"
    );
    assert_eq!(token.old_epoch().get(), decimal_u64(facts, "old_epoch"));
    assert_eq!(token.new_epoch().get(), decimal_u64(facts, "new_epoch"));
    assert_eq!(
        token.old_validator_set_hash().as_bytes(),
        &hex_32(string(facts, "old_validator_set_hash_hex"))
    );
    assert_eq!(
        token.new_validator_set_hash().as_bytes(),
        &hex_32(string(facts, "new_validator_set_hash_hex"))
    );
    assert_eq!(
        token.old_consensus_parameters_hash().as_bytes(),
        &hex_32(string(facts, "old_consensus_parameters_hash_hex"))
    );
    assert_eq!(
        token.new_consensus_parameters_hash().as_bytes(),
        &hex_32(string(facts, "new_consensus_parameters_hash_hex"))
    );
    assert_eq!(
        token.checkpoint_height().get(),
        decimal_u64(facts, "checkpoint_height")
    );
    assert_eq!(
        token.checkpoint_block_id().as_bytes(),
        &hex_32(string(facts, "checkpoint_block_id_hex"))
    );
    assert_eq!(
        token.checkpoint_state_root().as_bytes(),
        &hex_32(string(facts, "checkpoint_state_root_hex"))
    );
    assert_eq!(
        token.terminal_old_height().get(),
        decimal_u64(facts, "terminal_old_height")
    );
    assert_eq!(
        token.terminal_old_block_id().as_bytes(),
        &hex_32(string(facts, "terminal_old_block_id_hex"))
    );
    assert_eq!(
        token.terminal_old_qc_digest().as_bytes(),
        &hex_32(string(facts, "terminal_old_qc_digest_hex"))
    );
    assert_eq!(
        token.activation_height().get(),
        decimal_u64(facts, "activation_height")
    );
    assert_eq!(facts["epoch_anchor_qc_output"], false);
    assert!(facts["aggregate_digest"].is_null());
}

fn assert_manifest_identity(root: &Value) {
    assert_eq!(
        string(root, "schema"),
        "trnm_poco_bft_joint_handoff_composition_kernel_vectors_v0"
    );
    assert_eq!(number(root, "schema_version"), 0);
    assert_eq!(root["aggregate_cev0"], false);
    assert!(root["aggregate_digest_domain"].is_null());
    assert!(root["aggregate_digest"].is_null());
    assert_eq!(root["expected_gate_statistics"]["authorization_outputs"], 0);
    assert_eq!(
        root["expected_gate_statistics"]["epoch_anchor_qc_outputs"],
        0
    );
}

fn decode_failure(stage: &'static str, error: DecodeError) -> BundleDecodeFailure {
    BundleDecodeFailure { stage, error }
}

fn object<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .get(key)
        .and_then(Value::as_object)
        .map(|_| &value[key])
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn number(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be a u64"))
}

fn number_usize(value: &Value, key: &str) -> usize {
    usize::try_from(number(value, key)).unwrap_or_else(|_| panic!("{key} must fit usize"))
}

fn decimal_u64(value: &Value, key: &str) -> u64 {
    string(value, key)
        .parse()
        .unwrap_or_else(|_| panic!("{key} must be canonical u64 text"))
}

fn raw(value: &Value, key: &str) -> Vec<u8> {
    hex_vec(string(value, key))
}

fn hex_32(value: &str) -> [u8; 32] {
    hex_vec(value)
        .try_into()
        .unwrap_or_else(|bytes: Vec<u8>| panic!("expected 32 bytes, got {}", bytes.len()))
}

fn hex_vec(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex must contain complete octets");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
        .collect()
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("noncanonical lowercase hex byte"),
    }
}
