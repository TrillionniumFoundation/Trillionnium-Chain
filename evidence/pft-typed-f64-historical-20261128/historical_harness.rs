//! One fixed historical byte observation; private matrices are compile-time inputs.
//! Caller-side SHA verification is separate; this is not original-owner authority.
#[allow(dead_code)]
#[path = "../../trillionnium/crates/trnm-pon-node/src/pft_readout_f64_v1.rs"]
mod pft;
use pft::*;
use std::io::Write;

fn pin(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64);
    std::array::from_fn(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
}

fn main() {
    let model = PftModelDescriptorV1 {
        schema: MODEL_SCHEMA.into(),
        family: FAMILY.into(),
        numeric_profile: PROFILE.into(),
        candidate_sha256: pin("001f322da2ac470f83a9e502971b79e47c0dca3baa9211fc4abd10ba10b115ae"),
        contract_sha256: pin("c9312e832c0cbbe661a83f382ab02b210e703e9fa4db9be45067958e36f26a53"),
        head: pin("b14e6e321ea79310fda10641efed789af489d771c9fff97e862ef0dfec09a858"),
        weight_sha256: pin("3ec311f81f5323c74e114e6433813b5dbc8ea90a3dc3d191bde48f42fa42f022"),
        feature_program_sha256: pin(
            "c369c1393db613ff64b4b5e219e637d512e52d0841201bfb972f485cec9dfd1a",
        ),
        normalization_sha256: pin(
            "3ef7898bda42b3a6bfbcfe2271cfe0435099a19da16d72978328f6ab3ef95a06",
        ),
        time_semantics_sha256: pin(
            "b069120ba03b60034c3a437bbc4ccfef5e42ae79251a90ff47528caa67a903ca",
        ),
        dimension: 41,
        outputs: 3,
    };
    let input = PftInputDescriptorV1 {
        schema: INPUT_SCHEMA.into(),
        candidate_sha256: pin("001f322da2ac470f83a9e502971b79e47c0dca3baa9211fc4abd10ba10b115ae"),
        weight_sha256: pin("3ec311f81f5323c74e114e6433813b5dbc8ea90a3dc3d191bde48f42fa42f022"),
        contract_sha256: pin("c9312e832c0cbbe661a83f382ab02b210e703e9fa4db9be45067958e36f26a53"),
        feature_program_sha256: pin(
            "c369c1393db613ff64b4b5e219e637d512e52d0841201bfb972f485cec9dfd1a",
        ),
        normalization_sha256: pin(
            "3ef7898bda42b3a6bfbcfe2271cfe0435099a19da16d72978328f6ab3ef95a06",
        ),
        time_semantics_sha256: pin(
            "b069120ba03b60034c3a437bbc4ccfef5e42ae79251a90ff47528caa67a903ca",
        ),
        request_id: pin("8f58fa50c17a83ee7c523cc61c3fd84c111e182acc838b877fa16175df6d22ab"),
        source_sha256: pin("e1370cae11b8ad905fed061a348ecf9898bd3da8640f5cbc512c126b4e69c81f"),
        row_ids_sha256: pin("fc9b11abe87a55f3622c3d09e816be5f0a6c2389e718b1c35de8fd721e368169"),
        feature_packet_sha256: pin(
            "26456299b8fc9ac79914f8ac5762280329ebf3ced28c3e2d4420f7e95d1dd9e0",
        ),
        rows: 4,
        dimension: 41,
    };
    let prepared = PreparedPftReadoutV1::prepare(
        &model,
        include_bytes!(env!("TRNM_PFT_ACTUAL_WEIGHT_FILE")),
        &model,
        include_bytes!(env!("TRNM_PFT_EXPECTED_WEIGHT_FILE")),
    )
    .expect("model comparison");
    let input = prepared
        .prepare_input(
            &input,
            include_bytes!(env!("TRNM_PFT_ACTUAL_FEATURE_FILE")),
            &input,
            include_bytes!(env!("TRNM_PFT_EXPECTED_FEATURE_FILE")),
        )
        .expect("feature comparison");
    let prediction = prepared.predict(&input).expect("bounded typed readout");
    assert_eq!(prediction.shape(), [4, 3]);
    let bytes = prediction.to_le_bytes();
    assert!(
        bytes.as_slice() == include_bytes!(env!("TRNM_PFT_REFERENCE_OUTPUT_FILE")),
        "output differs from previously retained reference bytes"
    );
    std::io::stdout().lock().write_all(&bytes).unwrap();
}
