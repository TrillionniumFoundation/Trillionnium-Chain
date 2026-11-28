use super::*;
use serde_json::json;

fn fixture() -> (Value, Value, PftNativeExpectationsV1) {
    (
        json::parse(CANDIDATE).unwrap(),
        json::parse(FEATURES).unwrap(),
        expected(),
    )
}

// Negative controls may repin the outer packet to reach an inner validation.
fn changed(c: &Value, f: &Value, e: &PftNativeExpectationsV1) -> Result<LoadedPftReadoutV1> {
    let (c, f) = (
        serde_json::to_vec(c).unwrap(),
        serde_json::to_vec(f).unwrap(),
    );
    let mut e = e.clone();
    e.model.candidate_sha256 = hash(&c);
    e.input.candidate_sha256 = hash(&c);
    e.input.feature_packet_sha256 = hash(&f);
    load_pinned_pft(&c, &f, &e)
}

fn head(c: &mut Value, h: &Value, e: &mut PftNativeExpectationsV1) {
    let raw = serde_json::to_string(h).unwrap();
    e.model.head = hash(raw.as_bytes());
    c["head"] = json!(hex(&e.model.head));
    c["head_material_canonical_json"] = json!(raw);
}

fn contract(c: &mut Value, e: &mut PftNativeExpectationsV1) {
    let raw = serde_json::to_string(&c["contract"]).unwrap();
    e.model.contract_sha256 = hash(raw.as_bytes());
    c["contract_sha256"] = json!(hex(&e.model.contract_sha256));
    c["contract_canonical_json"] = json!(raw);
    let mut h = json::parse(
        c["head_material_canonical_json"]
            .as_str()
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    h["contract_sha256"] = c["contract_sha256"].clone();
    head(c, &h, e);
}

#[test]
fn duplicate_and_unknown_fields_refuse_at_all_schema_levels() {
    for raw in [
        br#"{"a":1,"a":2}"#.as_slice(),
        br#"{"a":1,"\u0061":2}"#,
        br#"{"outer":{"a":1,"a":2}}"#,
    ] {
        assert_eq!(json::parse(raw), Err(NativePftErrorV1::DuplicateKey));
    }
    for key in ["contract_canonical_json", "head_material_canonical_json"] {
        let (mut c, f, mut e) = fixture();
        let raw = "{\"a\":1,\"a\":2}";
        let digest = hash(raw.as_bytes());
        c[key] = json!(raw);
        if key == "contract_canonical_json" {
            c["contract_sha256"] = json!(hex(&digest));
            e.model.contract_sha256 = digest;
        } else {
            c["head"] = json!(hex(&digest));
            e.model.head = digest;
        }
        assert!(matches!(
            changed(&c, &f, &e),
            Err(NativePftErrorV1::DuplicateKey)
        ));
    }
    for level in 0..4 {
        let (mut c, mut f, mut e) = fixture();
        match level {
            0 => c["unknown"] = json!(true),
            1 => f["unknown"] = json!(true),
            2 => {
                c["contract"]["unknown"] = json!(true);
                contract(&mut c, &mut e);
            }
            _ => {
                let mut h = json::parse(
                    c["head_material_canonical_json"]
                        .as_str()
                        .unwrap()
                        .as_bytes(),
                )
                .unwrap();
                h["unknown"] = json!(true);
                head(&mut c, &h, &mut e);
            }
        }
        assert!(matches!(changed(&c, &f, &e), Err(NativePftErrorV1::Fields)));
    }
}

#[test]
fn contract_types_ranges_constants_and_raw_strings_are_pinned() {
    for (key, value) in [
        ("epoch", json!(true)),
        ("epoch", json!(0.5)),
        ("epoch", json!(u64::MAX)),
        ("dimension", json!(0)),
        ("dimension", json!(1025)),
        ("outputs", json!(33)),
        ("regularizer", json!(-0.0)),
        ("regularizer", json!(-1)),
        ("regularizer", json!(1e-310)),
        ("schema", json!("v2")),
        ("model_family", json!("int257")),
        ("dtype", json!("f32")),
        ("aggregation", json!("unordered")),
        ("statistics_validation", json!("none")),
    ] {
        let (mut c, f, mut e) = fixture();
        c["contract"][key] = value;
        contract(&mut c, &mut e);
        assert!(changed(&c, &f, &e).is_err(), "{key}");
    }
    let (mut c, f, e) = fixture();
    c["contract"]["epoch"] = json!(1);
    assert!(matches!(
        changed(&c, &f, &e),
        Err(NativePftErrorV1::Contract)
    ));
    c["contract_canonical_json"] = json!("{}");
    assert!(matches!(changed(&c, &f, &e), Err(NativePftErrorV1::Pin)));
}

#[test]
fn head_membership_order_revision_count_and_payloads_are_strict() {
    for case in 0..9 {
        let (mut c, f, mut e) = fixture();
        let mut h = json::parse(
            c["head_material_canonical_json"]
                .as_str()
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        match case {
            0 => h["batches"].as_array_mut().unwrap().reverse(),
            1 => h["batches"][1] = h["batches"][0].clone(),
            2 => h["batches"][0][0] = json!("invalid/ID"),
            3 => h["batches"][0][1] = json!("A".repeat(64)),
            4 => h["contract_sha256"] = json!("a".repeat(64)),
            5 => c["revision"] = json!(1),
            6 => c["count"] = json!(1),
            7 => c["count"] = json!(200001),
            _ => h["batches"] = json!([]),
        }
        head(&mut c, &h, &mut e);
        assert!(changed(&c, &f, &e).is_err(), "head case {case}");
    }
}

#[test]
fn scalar_types_shapes_and_le_weight_bytes_cannot_be_substituted() {
    for raw in [
        "true",
        "null",
        "{}",
        "1e-310",
        r#"{"$serde_json::private::Number":"1.0"}"#,
    ] {
        let value = json::parse(raw.as_bytes()).unwrap();
        for feature in [false, true] {
            let (mut c, mut f, e) = fixture();
            if feature {
                f["features"][0][0] = value.clone();
            } else {
                c["weight"][0][0] = value.clone();
            }
            assert!(
                matches!(changed(&c, &f, &e), Err(NativePftErrorV1::Numeric)),
                "{raw}"
            );
        }
    }
    for case in 0..7 {
        let (mut c, mut f, e) = fixture();
        match case {
            0 => c["weight"][1][1] = json!(0.0),
            1 => c["weight"][0][1] = json!(0.0),
            2 => c["weight_shape"] = json!([2, 3]),
            3 => c["weight"][0] = json!([1]),
            4 => f["features"][0] = json!([1]),
            5 => f["features"][0][0] = json!(3.0),
            _ => c["weight_encoding"] = json!("float64-be-c-rowmajor"),
        }
        assert!(changed(&c, &f, &e).is_err(), "matrix case {case}");
    }
}

#[test]
fn feature_rows_request_source_and_semantics_are_independent() {
    for case in 0..9 {
        let (c, mut f, e) = fixture();
        match case {
            0 => f["row_ids"][1] = f["row_ids"][0].clone(),
            1 => f["row_ids"].as_array_mut().unwrap().reverse(),
            2 => f["row_ids"][0] = json!("not-a-digest"),
            3 => f["row_ids"] = json!([]),
            n => {
                f[[
                    "request_id",
                    "source_sha256",
                    "feature_program_sha256",
                    "normalization_sha256",
                    "time_semantics_sha256",
                ][n - 4]] = json!("a".repeat(64))
            }
        }
        assert!(changed(&c, &f, &e).is_err(), "feature case {case}");
    }
}
