//! Actual production-function observations, not an independent implementation.
//! The separately coded Python oracle must recompute every comparison result.
use super::*;

fn response(result: Result<IntegerModelV2>) -> Value {
    match result {
        Ok(model) => json!({"error":null,"model_hex":hex::encode(model.encode()),
            "artifact":hex::encode(model.id())}),
        Err(error) => json!({"error":error}),
    }
}

#[test]
fn native_arithmetic_observations_for_independent_python() {
    let cfg = Config::installed_with_model_profiles(
        crate::public_evaluation::PROFILE,
        crate::continuity_v1::PROFILE,
        PROFILE,
    )
    .unwrap();
    let family = cfg.family;
    let model = |value: i16| {
        let mut coefficients = vec![0; 3855];
        coefficients[1542] = value;
        IntegerModelV2::from_coefficients(family, coefficients).unwrap()
    };
    let raw = model(0).encode();
    let mut cases = Vec::new();
    for (name, input, expected) in [
        ("valid", raw.clone(), None),
        (
            "truncated",
            raw[..raw.len() - 1].to_vec(),
            Some("FACTOR_MODEL_LENGTH"),
        ),
        (
            "trailing",
            [raw.clone(), vec![0]].concat(),
            Some("FACTOR_MODEL_LENGTH"),
        ),
    ] {
        let result = IntegerModelV2::decode(&input, family);
        assert_eq!(result.as_ref().err().copied(), expected);
        cases.push(
            json!({"kind":"decode","name":name,"raw_hex":hex::encode(input),
            "native":response(result)}),
        );
    }
    for (name, offset, bytes, error) in [
        ("version", 4, vec![3], "FACTOR_MODEL_VERSION"),
        ("family", 6, vec![raw[6] ^ 1], "FACTOR_MODEL_CONTEXT"),
        ("dimensions", 38, vec![0, 0], "FACTOR_MODEL_CONTEXT"),
        (
            "minimum-i16",
            46,
            i16::MIN.to_le_bytes().to_vec(),
            "FACTOR_MODEL_RANGE",
        ),
    ] {
        let mut input = raw.clone();
        input[offset..offset + bytes.len()].copy_from_slice(&bytes);
        let result = IntegerModelV2::decode(&input, family);
        assert_eq!(result.as_ref().err().copied(), Some(error));
        cases.push(
            json!({"kind":"decode","name":name,"raw_hex":hex::encode(input),
            "native":response(result)}),
        );
    }
    for (name, base, values, omit, error) in [
        ("parent-once", 10, vec![13, 8], None, None),
        ("omit-first", 10, vec![13, 8], Some(0), None),
        ("omit-second", 10, vec![13, 8], Some(1), None),
        (
            "wide-positive",
            20_000,
            vec![32_000, 32_000, 2_000],
            None,
            None,
        ),
        (
            "wide-negative",
            -20_000,
            vec![-32_000, -32_000, -2_000],
            None,
            None,
        ),
        (
            "omit-overflow",
            20_000,
            vec![32_000, 32_000, 2_000],
            Some(2),
            Some("MODEL_COMPOSITION_RANGE"),
        ),
        (
            "positive-overflow",
            20_000,
            vec![32_000, 32_000],
            None,
            Some("MODEL_COMPOSITION_RANGE"),
        ),
        (
            "negative-overflow",
            -20_000,
            vec![-32_000, -32_000],
            None,
            Some("MODEL_COMPOSITION_RANGE"),
        ),
    ] {
        let parent = model(base);
        let components: Vec<_> = values.into_iter().map(model).collect();
        let result = derive(family, &parent, &components, omit);
        assert_eq!(result.as_ref().err().copied(), error);
        cases.push(
            json!({"kind":"derive","name":name,"parent_hex":hex::encode(parent.encode()),
            "components_hex":components.iter().map(|m|hex::encode(m.encode())).collect::<Vec<_>>(),
            "omit":omit,"native":response(result)}),
        );
    }
    for (name, values, expected) in [
        ("two-distinct", vec![13, 8], Ok(1)),
        ("four-distinct", vec![11, 12, 14, 18], Ok(11)),
        (
            "cancel-pair",
            vec![13, 7, 15],
            Err("MODEL_COMPOSITION_REDUNDANT_SUBSET"),
        ),
        (
            "cancel-all-four",
            vec![11, 12, 14, 3],
            Err("MODEL_COMPOSITION_REDUNDANT_SUBSET"),
        ),
        ("too-few", vec![11], Err("MODEL_COMPOSITION_COUNT")),
        (
            "too-many",
            vec![11, 12, 14, 18, 26],
            Err("MODEL_COMPOSITION_COUNT"),
        ),
    ] {
        let parent = model(10);
        let components: Vec<_> = values.into_iter().map(model).collect();
        let result = reject_redundant_subsets(&parent, &components);
        assert_eq!(result, expected);
        let native = match result {
            Ok(count) => json!({"error":null,"count":count}),
            Err(error) => json!({"error":error}),
        };
        cases.push(
            json!({"kind":"subsets","name":name,"parent_hex":hex::encode(parent.encode()),
            "components_hex":components.iter().map(|m|hex::encode(m.encode())).collect::<Vec<_>>(),
            "native":native}),
        );
    }
    let mut inputs = vec![("all-zero".to_owned(), model(0))];
    for expert in 0..3 {
        for class in 0..3 {
            let mut coefficients = vec![0; 3855];
            coefficients[771 + expert * 257 + 256] = 1;
            coefficients[(2 + expert) * 771 + class * 257 + 256] = 32767;
            inputs.push((
                format!("expert-{expert}-class-{class}"),
                IntegerModelV2::from_coefficients(family, coefficients).unwrap(),
            ));
        }
    }
    for seed in 0_usize..8 {
        let coefficients = (0_usize..3855)
            .map(|index| (((index * 17 + seed * 31) % 65535) as i32 - 32767) as i16)
            .collect();
        inputs.push((
            format!("full-model-{seed}"),
            IntegerModelV2::from_coefficients(family, coefficients).unwrap(),
        ));
    }
    let mut router_tie = vec![0; 3855];
    router_tie[771 + 256] = 1;
    router_tie[771 + 257 + 256] = 1;
    router_tie[2 * 771 + 2 * 257 + 256] = 7;
    router_tie[3 * 771 + 257 + 256] = 7;
    inputs.push((
        "router-tie".into(),
        IntegerModelV2::from_coefficients(family, router_tie).unwrap(),
    ));
    let mut class_tie = vec![0; 3855];
    class_tie[257 + 256] = 32767;
    class_tie[2 * 771 + 2 * 257 + 256] = 32767;
    inputs.push((
        "class-tie".into(),
        IntegerModelV2::from_coefficients(family, class_tie).unwrap(),
    ));
    let mut base_delta = vec![0; 3855];
    base_delta[2 * 257 + 256] = 5;
    base_delta[2 * 771 + 257 + 256] = 6;
    inputs.push((
        "base-plus-delta".into(),
        IntegerModelV2::from_coefficients(family, base_delta).unwrap(),
    ));
    for (name, model) in inputs {
        let correct = empirical::model_correct(&cfg, &model).unwrap();
        assert!(correct <= 25);
        cases.push(
            json!({"kind":"inference","name":name,"model_hex":hex::encode(model.encode()),
            "native":{"error":null,"correct":correct,"artifact":hex::encode(model.id())}}),
        );
    }
    assert_eq!(cases.len(), 42);
    if let Ok(directory) = std::env::var("TRNM_MODEL_COMPOSITION_VECTORS") {
        let run_id = std::env::var("TRNM_MODEL_COMPOSITION_RUN_ID").expect("explicit fresh run id");
        assert!(!run_id.is_empty() && run_id.len() <= 256);
        std::fs::create_dir_all(&directory).unwrap();
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(std::path::Path::new(&directory).join("arithmetic-production.json"))
            .expect("fresh observations must not overwrite a prior run");
        serde_json::to_writer(file, &json!({
            "schema":"model-composition-native-observation-v1","run_id":run_id,
            "kind":"arithmetic","name":"production","input":{"family":hex::encode(family)},
            "native":{"cases":cases},
            "scope":"native-observation-for-independent-model-conformance-only",
            "economic_accepted":false,"independent_operators_accepted":false,"public_reward_eligible":false
        })).unwrap();
    }
}
