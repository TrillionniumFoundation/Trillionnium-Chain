use serde_json::Value;
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_types::{
    decode_wire_envelope_v0_semantic, Cev0AdmissionBudgetV0, ChainId, ConsensusParametersV0,
    ConsensusPublicKey, Epoch, GenesisHash, ProtocolVersion, Validator, ValidatorId, ValidatorSet,
    VotingPower, WireSemanticBodyKindV0, WireSemanticDecodeErrorCode,
};

const VECTOR: &str =
    include_str!("../../../../docs/protocol/poco-bft-v0/vectors/wire-authenticated-v0.json");

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing string field {key}"))
}

fn uint(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("missing integer field {key}"))
}

fn hex_bytes(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2), "odd-length hex fixture");
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = (pair[0] as char)
            .to_digit(16)
            .unwrap_or_else(|| panic!("invalid hex digit"));
        let low = (pair[1] as char)
            .to_digit(16)
            .unwrap_or_else(|| panic!("invalid hex digit"));
        bytes.push(((high << 4) | low) as u8);
    }
    bytes
}

fn hex32(value: &str) -> [u8; 32] {
    hex_bytes(value)
        .try_into()
        .unwrap_or_else(|_| panic!("expected 32-byte hex fixture"))
}

fn build_validator_set(root: &Value, parameters: &ConsensusParametersV0) -> ValidatorSet {
    let context = root.get("context").expect("authenticated context");
    let genesis = GenesisHash::new(hex32(string(context, "genesis_hash_hex")));
    let chain =
        ChainId::from_bytes(string(context, "chain_id").as_bytes()).expect("canonical chain id");
    let validators = context
        .get("validators")
        .and_then(Value::as_array)
        .expect("validator array")
        .iter()
        .map(|entry| {
            Validator::new(
                ValidatorId::from_bytes(&hex_bytes(string(entry, "validator_id_hex")))
                    .expect("bounded validator id"),
                ConsensusPublicKey::new(hex32(string(entry, "consensus_public_key_hex"))),
                VotingPower::new(uint(entry, "power")).expect("positive voting power"),
            )
            .expect("valid validator shape")
        })
        .collect();
    ValidatorSet::new(
        genesis,
        chain,
        ProtocolVersion::V0,
        Epoch::new(uint(context, "epoch")),
        parameters.hash(),
        validators,
    )
    .expect("authenticated validator set")
}

fn expected_body_kind(value: u64) -> WireSemanticBodyKindV0 {
    match value {
        2 => WireSemanticBodyKindV0::Vote,
        3 => WireSemanticBodyKindV0::TimeoutVote,
        4 => WireSemanticBodyKindV0::QuorumCertificate,
        5 => WireSemanticBodyKindV0::TimeoutCertificate,
        other => panic!("unexpected authenticated body kind {other}"),
    }
}

#[test]
fn authenticated_reference_frames_round_trip_through_strict_rust_path() {
    let root: Value = serde_json::from_str(VECTOR).expect("valid authenticated vector JSON");
    assert_eq!(
        string(&root, "schema"),
        "trnm_poco_bft_wire_authenticated_reference_v0"
    );
    assert_eq!(root.get("schema_version").and_then(Value::as_u64), Some(0));
    assert_eq!(
        root.get("wire_conformance").and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(root.get("activation").and_then(Value::as_bool), Some(false));

    let parameters = ConsensusParametersV0::reference_shadow_v0();
    let validator_set = build_validator_set(&root, &parameters);
    let context = root.get("context").expect("authenticated context");
    assert_eq!(
        validator_set.id().as_bytes(),
        &hex32(string(context, "validator_set_hash_hex"))
    );
    assert_eq!(
        parameters.hash().as_bytes(),
        &hex32(string(context, "consensus_parameters_hash_hex"))
    );
    StrictEd25519Verifier
        .validate_validator_set_v0(&validator_set)
        .expect("all corpus keys pass strict Ed25519 admission");

    let cases = root
        .get("cases")
        .and_then(Value::as_array)
        .expect("canonical authenticated cases");
    assert_eq!(cases.len(), 4);
    for case in cases {
        let frame = hex_bytes(string(case, "frame_hex"));
        let mut budget = Cev0AdmissionBudgetV0::for_validator_set(&parameters, &validator_set);
        let proof =
            decode_wire_envelope_v0_semantic(&frame, &validator_set, &parameters, &mut budget)
                .unwrap_or_else(|error| {
                    panic!("{} semantic decode failed: {error}", string(case, "id"))
                });
        assert_eq!(
            proof.body_kind(),
            expected_body_kind(uint(case, "body_kind")),
            "{} body kind",
            string(case, "id")
        );
        assert_eq!(
            proof.aggregate_signature_shares(),
            uint(case, "aggregate") as usize,
            "{} aggregate signature work",
            string(case, "id")
        );
        proof
            .verify_signatures(&validator_set, &StrictEd25519Verifier)
            .unwrap_or_else(|error| panic!("{} strict auth failed: {error}", string(case, "id")));
    }
}

#[test]
fn authenticated_reference_signature_mutants_reach_strict_verifier() {
    let root: Value = serde_json::from_str(VECTOR).expect("valid authenticated vector JSON");
    let parameters = ConsensusParametersV0::reference_shadow_v0();
    let validator_set = build_validator_set(&root, &parameters);
    let negatives = root
        .get("negative_cases")
        .and_then(Value::as_array)
        .expect("authenticated negative cases");
    assert_eq!(negatives.len(), 6);
    for case in negatives {
        let frame = hex_bytes(string(case, "frame_hex"));
        let expected = string(case, "expected_error");
        let mut budget = Cev0AdmissionBudgetV0::for_validator_set(&parameters, &validator_set);
        let decoded =
            decode_wire_envelope_v0_semantic(&frame, &validator_set, &parameters, &mut budget);
        if expected == "invalid_signature" {
            let proof = decoded.unwrap_or_else(|error| {
                panic!(
                    "{} mutation stopped before auth: {error}",
                    string(case, "id")
                )
            });
            let error = proof
                .verify_signatures(&validator_set, &StrictEd25519Verifier)
                .expect_err("signature mutation must fail strict verification");
            assert_eq!(error.code(), WireSemanticDecodeErrorCode::InvalidSignature);
        } else {
            let error = decoded.expect_err("non-auth mutation must fail semantic decode");
            assert_eq!(
                error.code(),
                WireSemanticDecodeErrorCode::UnexpectedEof,
                "{} semantic rejection",
                string(case, "id")
            );
        }
    }
}
