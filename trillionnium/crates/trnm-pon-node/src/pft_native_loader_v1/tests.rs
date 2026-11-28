use super::*;

const CANDIDATE: &[u8] = include_bytes!(
    "../../../../../evidence/pft-candidate-readback-20261128/SYNTHETIC_CANDIDATE.json"
);
const FEATURES: &[u8] =
    include_bytes!("../../../../../evidence/pft-native-loader-20261128/SYNTHETIC_FEATURES.json");
const EXPECTED: &[u8] =
    include_bytes!("../../../../../evidence/pft-native-loader-20261128/SYNTHETIC_EXPECTED.json");

fn expected() -> PftNativeExpectationsV1 {
    let e: Value = serde_json::from_slice(EXPECTED).unwrap();
    let p = |key: &str| pin(&e[key]).unwrap();
    PftNativeExpectationsV1 {
        profile: PROFILE.into(),
        model: core::PftModelDescriptorV1 {
            schema: core::MODEL_SCHEMA.into(),
            family: core::FAMILY.into(),
            numeric_profile: core::PROFILE.into(),
            candidate_sha256: p("candidate_sha256"),
            contract_sha256: p("contract_sha256"),
            head: p("head"),
            weight_sha256: p("weight_sha256"),
            feature_program_sha256: p("feature_program_sha256"),
            normalization_sha256: p("normalization_sha256"),
            time_semantics_sha256: p("time_semantics_sha256"),
            dimension: 2,
            outputs: 2,
        },
        input: core::PftInputDescriptorV1 {
            schema: core::INPUT_SCHEMA.into(),
            candidate_sha256: p("candidate_sha256"),
            weight_sha256: p("weight_sha256"),
            contract_sha256: p("contract_sha256"),
            feature_program_sha256: p("feature_program_sha256"),
            normalization_sha256: p("normalization_sha256"),
            time_semantics_sha256: p("time_semantics_sha256"),
            request_id: p("request_id"),
            source_sha256: p("source_sha256"),
            row_ids_sha256: p("row_ids_sha256"),
            feature_packet_sha256: p("feature_packet_sha256"),
            rows: 2,
            dimension: 2,
        },
        parent_model_sha256: p("parent_model_sha256"),
        objective_sha256: p("objective_sha256"),
        feature_binary_sha256: p("feature_binary_sha256"),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn public_fixture_has_independent_pins_known_octets_and_owned_inputs() {
    let mut c = CANDIDATE.to_vec();
    let mut f = FEATURES.to_vec();
    let mut e = expected();
    let loaded = load_pinned_pft(&c, &f, &e).unwrap();
    c.fill(0);
    f.fill(0);
    e.model.weight_sha256 = [99; 32];
    let output = loaded.predict().unwrap();
    assert_eq!(output.shape(), [2, 2]);
    assert_eq!(
        hex(&output.to_le_bytes()),
        "000000000000004000000000000014c000000000000010c00000000000002440"
    );
    assert_eq!(
        loaded.expectations().model.weight_sha256,
        expected().model.weight_sha256
    );
}

#[test]
fn every_separately_retained_pin_is_required() {
    for index in 0..20 {
        let mut e = expected();
        let p = match index {
            0 => &mut e.model.candidate_sha256,
            1 => &mut e.model.contract_sha256,
            2 => &mut e.model.head,
            3 => &mut e.model.weight_sha256,
            4 => &mut e.model.feature_program_sha256,
            5 => &mut e.model.normalization_sha256,
            6 => &mut e.model.time_semantics_sha256,
            7 => &mut e.input.candidate_sha256,
            8 => &mut e.input.weight_sha256,
            9 => &mut e.input.contract_sha256,
            10 => &mut e.input.feature_program_sha256,
            11 => &mut e.input.normalization_sha256,
            12 => &mut e.input.time_semantics_sha256,
            13 => &mut e.input.request_id,
            14 => &mut e.input.source_sha256,
            15 => &mut e.input.row_ids_sha256,
            16 => &mut e.input.feature_packet_sha256,
            17 => &mut e.parent_model_sha256,
            18 => &mut e.objective_sha256,
            _ => &mut e.feature_binary_sha256,
        };
        *p = [7; 32];
        assert!(
            load_pinned_pft(CANDIDATE, FEATURES, &e).is_err(),
            "pin {index}"
        );
    }
    let mut e = expected();
    e.profile.push('x');
    assert!(load_pinned_pft(CANDIDATE, FEATURES, &e).is_err());
}

#[test]
fn numeric_private_maps_remain_objects_with_arbitrary_precision() {
    let value = json::parse(br#"{"$serde_json::private::Number":"2"}"#).unwrap();
    assert!(value.is_object());
    assert_eq!(real(&value), Err(NativePftErrorV1::Numeric));
    for raw in [
        "NaN",
        "Infinity",
        "-Infinity",
        "1.2.3",
        "01",
        "-",
        "2true",
        "[1,]",
        "{\"x\":1,}",
        "true false",
    ] {
        assert_eq!(
            json::parse(raw.as_bytes()),
            Err(NativePftErrorV1::Json),
            "{raw}"
        );
    }
    assert_eq!(json::parse(b"\"\xff\""), Err(NativePftErrorV1::Json));
    assert_eq!(json::parse(br#""\ud800""#), Err(NativePftErrorV1::Json));
    match json::parse(b"1e400") {
        Ok(value) => assert_eq!(real(&value), Err(NativePftErrorV1::Numeric)),
        Err(error) => assert_eq!(error, NativePftErrorV1::Json),
    }
}

#[test]
fn parser_and_packet_allocation_limits_are_checked() {
    let depth = format!("{}0{}", "[".repeat(9), "]".repeat(9));
    let string = format!("\"{}\"", "a".repeat(131071));
    let number = "1".repeat(129);
    let fields = format!(
        "{{{}}}",
        (0..33)
            .map(|n| format!("\"x{n}\":0"))
            .collect::<Vec<_>>()
            .join(",")
    );
    let nodes = format!("[{}0]", "0,".repeat(299999));
    for raw in [depth, string, number, fields, nodes] {
        assert_eq!(json::parse(raw.as_bytes()), Err(NativePftErrorV1::Limit));
    }
    let big = vec![b' '; MAX_BYTES + 1];
    assert!(matches!(
        load_pinned_pft(&big, FEATURES, &expected()),
        Err(NativePftErrorV1::Limit)
    ));
    assert!(matches!(
        load_pinned_pft(CANDIDATE, &big, &expected()),
        Err(NativePftErrorV1::Limit)
    ));
}
