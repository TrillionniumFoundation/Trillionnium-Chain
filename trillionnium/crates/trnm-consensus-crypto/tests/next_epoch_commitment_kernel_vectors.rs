use serde_json::Value;
use trnm_consensus_types::{decode_next_epoch_commitment_v0_exact, DecodeErrorCode};

const VECTOR: &str = include_str!(
    "../../../../docs/protocol/poco-bft-v0/vectors/next-epoch-commitment-kernel-v0.json"
);

#[test]
fn exact_raw_next_epoch_commitments_decode_reencode_and_hash() {
    let root: Value = serde_json::from_str(VECTOR).expect("valid next-epoch vector JSON");
    assert_eq!(
        string(&root, "schema"),
        "trnm_poco_bft_next_epoch_commitment_kernel_vectors_v0"
    );
    assert_eq!(root["cryptographic_validity_claimed"], false);

    let objects = root["valid_raw_objects"]
        .as_array()
        .expect("valid_raw_objects array");
    assert_eq!(objects.len(), 3);
    for object in objects {
        let id = string(object, "id");
        let raw = hex_vec(string(object, "cev0_hex"));
        assert_eq!(
            raw.len(),
            object["length"].as_u64().expect("object length") as usize,
            "source length drift for {id}"
        );

        let commitment = decode_next_epoch_commitment_v0_exact(&raw)
            .unwrap_or_else(|error| panic!("{id} exact decode failed: {error:?}"));
        assert_eq!(
            commitment
                .try_cev0_bytes()
                .expect("bounded commitment CEV0"),
            raw,
            "decode/re-encode mismatch for {id}"
        );
        assert_eq!(
            commitment.id().as_bytes(),
            &hex_array(string(object, "digest_hex")),
            "commitment digest mismatch for {id}"
        );

        for prefix_len in 0..raw.len() {
            let error = decode_next_epoch_commitment_v0_exact(&raw[..prefix_len])
                .expect_err("every non-complete prefix must fail");
            assert_eq!(
                error.code(),
                DecodeErrorCode::UnexpectedEof,
                "unexpected prefix error for {id} at length {prefix_len}"
            );
        }

        let mut with_trailing = raw.clone();
        with_trailing.push(0);
        let error = decode_next_epoch_commitment_v0_exact(&with_trailing)
            .expect_err("a trailing byte must fail exact decoding");
        assert_eq!(error.code(), DecodeErrorCode::TrailingBytes);
        assert_eq!(error.byte_offset(), raw.len());
    }
}

#[test]
fn boundary_corpus_is_shared_with_the_rust_exact_decoder() {
    let root: Value = serde_json::from_str(VECTOR).expect("valid next-epoch vector JSON");
    let objects = root["valid_raw_objects"]
        .as_array()
        .expect("valid_raw_objects array");
    let base = raw_object(objects, "normal_same_version_no_upgrade");
    let present = raw_object(objects, "present_upgrade_shape_only");
    let cases = root["boundary_cases"]
        .as_array()
        .expect("boundary_cases array");
    assert_eq!(cases.len(), 25, "boundary corpus cardinality drift");

    for case in cases {
        let id = string(case, "id");
        let mutation = string(case, "mutation");
        let raw = mutate_boundary(mutation, &base, &present);
        let expected = string(case, "expected");

        if expected == "valid" {
            decode_next_epoch_commitment_v0_exact(&raw)
                .unwrap_or_else(|error| panic!("boundary {id} must decode: {error:?}"));
            continue;
        }

        let error = match decode_next_epoch_commitment_v0_exact(&raw) {
            Ok(_) => panic!("boundary {id} must be rejected"),
            Err(error) => error,
        };
        assert_eq!(
            error.code(),
            decode_error_code(expected),
            "boundary {id} error-code drift"
        );
        assert_eq!(
            error.byte_offset(),
            case["expected_offset"]
                .as_u64()
                .expect("invalid boundary expected_offset") as usize,
            "boundary {id} error-offset drift"
        );
    }
}

fn raw_object(objects: &[Value], id: &str) -> Vec<u8> {
    let object = objects
        .iter()
        .find(|object| string(object, "id") == id)
        .unwrap_or_else(|| panic!("missing raw object {id}"));
    hex_vec(string(object, "cev0_hex"))
}

fn mutate_boundary(mutation: &str, base: &[u8], present: &[u8]) -> Vec<u8> {
    const SCHEMA_VERSION: usize = 0;
    const GENESIS_HASH: usize = 2;
    const CHAIN_LENGTH: usize = 34;
    const CHAIN_BYTES: usize = 36;
    const BASE_CHAIN_LENGTH: usize = 19;
    const OLD_EPOCH: usize = 55;
    const NEW_EPOCH: usize = 63;
    const SNAPSHOT_STATE_ROOT: usize = 79;
    const NEW_VALIDATOR_SET_HASH: usize = 115;
    const NEW_PARAMETERS_HASH: usize = 147;
    const ROLLOUT_PHASE: usize = 179;
    const OPTIONAL_TAG: usize = 180;
    const PRESENT_UPGRADE_HASH: usize = 181;
    const FALLBACK_USED: usize = 181;
    const ACTIVATION_HEIGHT: usize = 184;

    assert_eq!(base.len(), 192, "base CEV0 layout drift");
    assert_eq!(present.len(), 224, "present-upgrade CEV0 layout drift");
    assert_eq!(
        u16::from_be_bytes([base[CHAIN_LENGTH], base[CHAIN_LENGTH + 1]]),
        19
    );
    assert_eq!(CHAIN_BYTES + BASE_CHAIN_LENGTH, OLD_EPOCH);

    let mut raw = if matches!(mutation, "optional_tag_1" | "zero_present_upgrade_hash") {
        present.to_vec()
    } else {
        base.to_vec()
    };

    match mutation {
        "chain_length_0" => rebuild_with_chain_id(base, &[]),
        "chain_length_128" => rebuild_with_chain_id(base, &bounded_ascii_chain_id(128)),
        "chain_length_129" => rebuild_with_chain_id(base, &bounded_ascii_chain_id(129)),
        "chain_invalid_ascii" => rebuild_with_chain_id(base, b"Uppercase"),
        "optional_tag_0" | "optional_tag_1" | "fallback_false_reason_0" => raw,
        "optional_tag_2" => {
            raw[OPTIONAL_TAG] = 2;
            raw
        }
        "rollout_phase_0" => {
            raw[ROLLOUT_PHASE] = 0;
            raw
        }
        "rollout_phase_3" => {
            raw[ROLLOUT_PHASE] = 3;
            raw
        }
        "rollout_phase_4" => {
            raw[ROLLOUT_PHASE] = 4;
            raw
        }
        "fallback_true_reason_1" => {
            set_fallback(&mut raw, true, 1);
            raw
        }
        "fallback_true_reason_9" => {
            set_fallback(&mut raw, true, 9);
            raw
        }
        "fallback_reason_10" => {
            set_fallback(&mut raw, true, 10);
            raw
        }
        "fallback_false_reason_1" => {
            set_fallback(&mut raw, false, 1);
            raw
        }
        "fallback_true_reason_0" => {
            set_fallback(&mut raw, true, 0);
            raw
        }
        "fallback_bool_2" => {
            raw[FALLBACK_USED] = 2;
            raw
        }
        "schema_version_1" => {
            raw[SCHEMA_VERSION..SCHEMA_VERSION + 2].copy_from_slice(&1u16.to_be_bytes());
            raw
        }
        "zero_genesis_hash" => {
            raw[GENESIS_HASH..GENESIS_HASH + 32].fill(0);
            raw
        }
        "zero_snapshot_state_root" => {
            raw[SNAPSHOT_STATE_ROOT..SNAPSHOT_STATE_ROOT + 32].fill(0);
            raw
        }
        "zero_new_validator_set_hash" => {
            raw[NEW_VALIDATOR_SET_HASH..NEW_VALIDATOR_SET_HASH + 32].fill(0);
            raw
        }
        "zero_new_parameters_hash" => {
            raw[NEW_PARAMETERS_HASH..NEW_PARAMETERS_HASH + 32].fill(0);
            raw
        }
        "zero_present_upgrade_hash" => {
            raw[PRESENT_UPGRADE_HASH..PRESENT_UPGRADE_HASH + 32].fill(0);
            raw
        }
        "new_epoch_not_adjacent" => {
            let old_epoch = u64::from_be_bytes(
                raw[OLD_EPOCH..OLD_EPOCH + 8]
                    .try_into()
                    .expect("old epoch bytes"),
            );
            raw[NEW_EPOCH..NEW_EPOCH + 8].copy_from_slice(&(old_epoch + 2).to_be_bytes());
            raw
        }
        "activation_height_0" => {
            raw[ACTIVATION_HEIGHT..ACTIVATION_HEIGHT + 8].fill(0);
            raw
        }
        unknown => panic!("unimplemented boundary mutation {unknown}"),
    }
}

fn rebuild_with_chain_id(base: &[u8], chain_id: &[u8]) -> Vec<u8> {
    const CHAIN_LENGTH: usize = 34;
    const BASE_CHAIN_END: usize = 55;

    let chain_length = u16::try_from(chain_id.len()).expect("test chain ID fits u16");
    let mut raw = Vec::with_capacity(base.len() - (BASE_CHAIN_END - CHAIN_LENGTH) + chain_id.len());
    raw.extend_from_slice(&base[..CHAIN_LENGTH]);
    raw.extend_from_slice(&chain_length.to_be_bytes());
    raw.extend_from_slice(chain_id);
    raw.extend_from_slice(&base[BASE_CHAIN_END..]);
    raw
}

fn bounded_ascii_chain_id(length: usize) -> Vec<u8> {
    assert!(length > 0);
    let mut chain_id = vec![b'b'; length];
    chain_id[0] = b'a';
    chain_id
}

fn set_fallback(raw: &mut [u8], used: bool, reason: u16) {
    const FALLBACK_USED: usize = 181;
    const FALLBACK_REASON: usize = 182;

    raw[FALLBACK_USED] = u8::from(used);
    raw[FALLBACK_REASON..FALLBACK_REASON + 2].copy_from_slice(&reason.to_be_bytes());
}

fn decode_error_code(value: &str) -> DecodeErrorCode {
    match value {
        "length_limit_exceeded" => DecodeErrorCode::LengthLimitExceeded,
        "invalid_schema_version" => DecodeErrorCode::InvalidSchemaVersion,
        "invalid_consensus_string" => DecodeErrorCode::InvalidConsensusString,
        "invalid_optional_tag" => DecodeErrorCode::InvalidOptionalTag,
        "zero_genesis_hash" => DecodeErrorCode::ZeroGenesisHash,
        "invalid_boolean" => DecodeErrorCode::InvalidBoolean,
        "invalid_rollout_phase" => DecodeErrorCode::InvalidRolloutPhase,
        "invalid_fallback_reason" => DecodeErrorCode::InvalidFallbackReason,
        "invalid_next_epoch_commitment" => DecodeErrorCode::InvalidNextEpochCommitment,
        unknown => panic!("unmapped boundary error code {unknown}"),
    }
}

fn string<'a>(value: &'a Value, field: &str) -> &'a str {
    value[field]
        .as_str()
        .unwrap_or_else(|| panic!("{field} must be a string"))
}

fn hex_vec(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex must have an even length");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = core::str::from_utf8(pair).expect("ASCII hex");
            u8::from_str_radix(text, 16).expect("lowercase hex byte")
        })
        .collect()
}

fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    hex_vec(value)
        .try_into()
        .unwrap_or_else(|bytes: Vec<u8>| panic!("expected {N} bytes, got {}", bytes.len()))
}
