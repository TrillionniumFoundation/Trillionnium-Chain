use super::*;
use serde_json::{json, Value};

const CANDIDATE: &[u8] = include_bytes!(
    "../../../../../evidence/pft-candidate-readback-20261128/SYNTHETIC_CANDIDATE.json"
);
const EXPECTED: &[u8] = include_bytes!(
    "../../../../../evidence/pft-selected-inspection-20261128/SYNTHETIC_BINDING_EXPECTED.json"
);

fn expected_pin(key: &str) -> [u8; 32] {
    let object: Value = serde_json::from_slice(EXPECTED).unwrap();
    let value = object[key].as_str().unwrap();
    std::array::from_fn(|index| u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap())
}

// Synthetic projection only; these controls do not create or impersonate an owner.
fn metadata() -> SelectedMetadata<'static> {
    SelectedMetadata {
        version: [33; 64],
        revision: 7,
        generation: 2,
        family: core::FAMILY,
        loader_profile: expected_pin("loader_profile_sha256"),
        base: expected_pin("parent_model_sha256"),
        layout: expected_pin("contract_sha256"),
        tokenizer: expected_pin("no_tokenizer_sha256"),
        file_count: 1,
        roots: &[0],
        path: CANDIDATE_PATH,
        is_base: true,
        dependencies: &[],
        payload_sha256: expected_pin("candidate_sha256"),
        payload_bytes: CANDIDATE.len() as u64,
    }
}

#[test]
fn frozen_profile_and_owned_metadata_match_the_public_candidate() {
    assert_eq!(PROFILE, "trnm.pft.selected-candidate-inspection.v1");
    assert_eq!(
        loader_profile_digest(),
        expected_pin("loader_profile_sha256")
    );
    assert_eq!(no_tokenizer_digest(), expected_pin("no_tokenizer_sha256"));
    let mut bytes = CANDIDATE.to_vec();
    let observed = inspect(metadata(), &bytes).unwrap();
    bytes.fill(0);
    assert_eq!(observed.version_commitment(), [33; 64]);
    assert_eq!(observed.selection_revision(), 7);
    assert_eq!(observed.model_generation(), 2);
    let model = observed.model_descriptor();
    assert_eq!((model.dimension, model.outputs), (2, 2));
    assert_eq!(model.numeric_profile, core::PROFILE);
    assert_eq!(model.candidate_sha256, expected_pin("candidate_sha256"));
    assert_eq!(model.weight_sha256, expected_pin("weight_sha256"));
    assert_eq!(model.head, expected_pin("head"));
}

#[test]
fn old_profiles_and_changed_file_graphs_are_refused() {
    for case in 0..12 {
        let mut selected = metadata();
        match case {
            0 => selected.family = "pon-cell-stateful-native-int257-v1",
            1 => selected.loader_profile = Sha256::digest(loader::PROFILE.as_bytes()).into(),
            2 => selected.tokenizer = [9; 32],
            3 => selected.file_count = 2,
            4 => selected.roots = &[],
            5 => selected.roots = &[1],
            6 => selected.roots = &[0, 0],
            7 => selected.path = "pft/Online-candidate.json",
            8 => selected.path = "pft/../online-candidate.json",
            9 => selected.is_base = false,
            10 => selected.dependencies = &[0],
            _ => selected.file_count = 0,
        }
        assert_eq!(
            inspect(selected, CANDIDATE),
            Err(PftSelectedBindingErrorV1::Profile),
            "case {case}"
        );
    }
}

#[test]
fn selected_contract_base_and_payload_pins_are_independent() {
    for case in 0..6 {
        let mut selected = metadata();
        let wrong = if case < 3 { [7; 32] } else { [0; 32] };
        match case % 3 {
            0 => selected.payload_sha256 = wrong,
            1 => selected.layout = wrong,
            _ => selected.base = wrong,
        }
        assert!(matches!(
            inspect(selected, CANDIDATE),
            Err(PftSelectedBindingErrorV1::Candidate(
                loader::NativePftErrorV1::Pin
            ))
        ));
    }
}

#[test]
fn missing_selection_and_original_payload_bounds_refuse() {
    for case in 0..3 {
        let mut selected = metadata();
        match case {
            0 => selected.version = [0; 64],
            1 => selected.revision = 0,
            _ => selected.generation = 0,
        }
        assert_eq!(
            inspect(selected, CANDIDATE),
            Err(PftSelectedBindingErrorV1::Selection)
        );
    }
    let mut selected = metadata();
    selected.payload_bytes += 1;
    assert_eq!(
        inspect(selected, CANDIDATE),
        Err(PftSelectedBindingErrorV1::Payload)
    );
    assert_eq!(
        inspect(metadata(), &[]),
        Err(PftSelectedBindingErrorV1::Payload)
    );
    let oversized = vec![b' '; MAX_CANDIDATE_BYTES + 1];
    let mut selected = metadata();
    selected.payload_bytes = oversized.len() as u64;
    assert_eq!(
        inspect(selected, &oversized),
        Err(PftSelectedBindingErrorV1::Payload)
    );
}

#[test]
fn raw_bytes_are_compared_before_candidate_interpretation() {
    let mut bytes = CANDIDATE.to_vec();
    bytes[0] = b'!';
    assert_eq!(
        inspect(metadata(), &bytes),
        Err(PftSelectedBindingErrorV1::Candidate(
            loader::NativePftErrorV1::Pin
        ))
    );
    let mut bytes = CANDIDATE.to_vec();
    bytes.push(b' ');
    let mut selected = metadata();
    selected.payload_bytes = bytes.len() as u64;
    assert_eq!(
        inspect(selected, &bytes),
        Err(PftSelectedBindingErrorV1::Candidate(
            loader::NativePftErrorV1::Pin
        ))
    );
}

#[test]
fn selected_bytes_still_need_full_internal_model_validation() {
    for case in 0..8 {
        let mut value: Value = serde_json::from_slice(CANDIDATE).unwrap();
        match case {
            0 => value["weight"][0][0] = json!(true),
            1 => value["weight"][0][0] = json!({"$serde_json::private::Number": "1.0"}),
            2 => value["weight_shape"] = json!([3, 2]),
            3 => value["head"] = json!("a".repeat(64)),
            4 => value["weight"][1][1] = json!(0.0),
            5 => value["unknown"] = json!(true),
            6 => value["count"] = json!(0),
            _ => value["contract"]["regularizer"] = json!(2.0),
        }
        let bytes = serde_json::to_vec(&value).unwrap();
        let mut selected = metadata();
        // Deliberately model a selected but malformed payload; only its outer
        // reference is repinned. Selection alone must not certify native safety.
        selected.payload_sha256 = Sha256::digest(&bytes).into();
        selected.payload_bytes = bytes.len() as u64;
        assert!(
            matches!(
                inspect(selected, &bytes),
                Err(PftSelectedBindingErrorV1::Candidate(_))
            ),
            "case {case}"
        );
    }
    let duplicate = br#"{"contract":{},"contract":{}}"#;
    let mut selected = metadata();
    selected.payload_sha256 = Sha256::digest(duplicate).into();
    selected.payload_bytes = duplicate.len() as u64;
    assert_eq!(
        inspect(selected, duplicate),
        Err(PftSelectedBindingErrorV1::Candidate(
            loader::NativePftErrorV1::DuplicateKey
        ))
    );
}
