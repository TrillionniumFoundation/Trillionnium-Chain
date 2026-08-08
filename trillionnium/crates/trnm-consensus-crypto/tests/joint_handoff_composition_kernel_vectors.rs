use serde_json::Value;
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_types::{
    decode_checkpoint_finality_proof_v0_exact, decode_consensus_parameters_v0_exact,
    decode_epoch_anchor_authorization_kernel_v0_exact, decode_next_epoch_commitment_v0_exact,
    decode_validator_set_v0_exact, verify_same_version_joint_handoff_kernel_v0,
    ConsensusParametersV0, DecodeError, EpochAnchorAuthorizationKernelV0, FinalityProofV0,
    JointHandoffKernelV0, NextEpochCommitmentV0, ValidatorSet,
};

const VECTOR: &str = include_str!(
    "../../../../docs/protocol/poco-bft-v0/vectors/joint-handoff-composition-kernel-v0.json"
);

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
