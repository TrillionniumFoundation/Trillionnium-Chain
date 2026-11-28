//! Actual SQLite owner, original typed loader and exact arithmetic on public data.
use super::*;
use serde_json::Value;
use std::path::PathBuf;
use trnm_data_availability::cell::{
    CellAdoptionActionV1, CellAdoptionOwnerV1, CellAdoptionPolicyV1, CellAdoptionSnapshotV1,
    CellCandidateEvidenceV1, CellExecutionBoundaryV1, CellModelUpdateBoundaryV1,
    CellVersionManifestV1,
};

const CANDIDATE: &[u8] = include_bytes!(
    "../../../../../evidence/pft-candidate-readback-20261128/SYNTHETIC_CANDIDATE.json"
);
const FEATURES: &[u8] =
    include_bytes!("../../../../../evidence/pft-native-loader-20261128/SYNTHETIC_FEATURES.json");
const EXPECTED: &[u8] =
    include_bytes!("../../../../../evidence/pft-native-loader-20261128/SYNTHETIC_EXPECTED.json");
const FIXTURE: &[u8] = include_bytes!(
    "../../../../../evidence/pft-selected-readout-20261128/SYNTHETIC_OWNER_FIXTURE.json"
);

fn version(name: &str) -> CellVersionManifestV1 {
    let document: Value = serde_json::from_slice(FIXTURE).unwrap();
    let item = &document[name];
    let wire = hex::decode(item["wire_hex"].as_str().unwrap()).unwrap();
    assert_eq!(hex::encode(Sha256::digest(&wire)), item["wire_sha256"]);
    let version = CellVersionManifestV1::decode(&wire).unwrap();
    assert_eq!(version.encode(), wire);
    assert_eq!(hex::encode(version.commitment()), item["commitment_sha512"]);
    version
}

fn expected() -> loader::PftNativeExpectationsV1 {
    let document: Value = serde_json::from_slice(EXPECTED).unwrap();
    let pin = |name: &str| -> [u8; 32] {
        hex::decode(document[name].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    };
    loader::PftNativeExpectationsV1 {
        profile: loader::PROFILE.into(),
        model: core::PftModelDescriptorV1 {
            schema: core::MODEL_SCHEMA.into(),
            family: core::FAMILY.into(),
            numeric_profile: core::PROFILE.into(),
            candidate_sha256: pin("candidate_sha256"),
            contract_sha256: pin("contract_sha256"),
            head: pin("head"),
            weight_sha256: pin("weight_sha256"),
            feature_program_sha256: pin("feature_program_sha256"),
            normalization_sha256: pin("normalization_sha256"),
            time_semantics_sha256: pin("time_semantics_sha256"),
            dimension: 2,
            outputs: 2,
        },
        input: core::PftInputDescriptorV1 {
            schema: core::INPUT_SCHEMA.into(),
            candidate_sha256: pin("candidate_sha256"),
            weight_sha256: pin("weight_sha256"),
            contract_sha256: pin("contract_sha256"),
            feature_program_sha256: pin("feature_program_sha256"),
            normalization_sha256: pin("normalization_sha256"),
            time_semantics_sha256: pin("time_semantics_sha256"),
            request_id: pin("request_id"),
            source_sha256: pin("source_sha256"),
            row_ids_sha256: pin("row_ids_sha256"),
            feature_packet_sha256: pin("feature_packet_sha256"),
            rows: 2,
            dimension: 2,
        },
        parent_model_sha256: pin("parent_model_sha256"),
        objective_sha256: pin("objective_sha256"),
        feature_binary_sha256: pin("feature_binary_sha256"),
    }
}

fn execution() -> CellExecutionBoundaryV1 {
    CellExecutionBoundaryV1 {
        network: [31; 32],
        consensus: [32; 32],
        fees: [33; 32],
        root_authority: [34; 32],
        node_software: [35; 32],
        protocol_configuration: [36; 32],
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    policy: CellAdoptionPolicyV1,
    owner: CellAdoptionOwnerV1,
    selected: CellAdoptionSnapshotV1,
}

fn setup(name: &str) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let parent = directory.path().canonicalize().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = parent.join("adoption.sqlite");
    let model = version(name);
    let boundary = CellModelUpdateBoundaryV1::new(
        &model,
        vec![CellFileRoleV1::Base],
        execution(),
        1_000_000,
        64,
    )
    .unwrap();
    let policy = CellAdoptionPolicyV1::new([1; 32], [2; 32], [3; 32], boundary).unwrap();
    let mut owner = CellAdoptionOwnerV1::create(&path, &policy).unwrap();
    owner
        .observe_candidate(&model, None, CellCandidateEvidenceV1::default())
        .unwrap();
    let before = owner.snapshot().unwrap();
    let selected = owner
        .decide(
            [1; 32],
            &before,
            CellAdoptionActionV1::Adopt,
            model.commitment(),
            [71; 64],
        )
        .unwrap()
        .after()
        .clone();
    Fixture {
        _directory: directory,
        path,
        policy,
        owner,
        selected,
    }
}

#[test]
fn selected_readout_uses_exact_candidate_and_input_after_cold_reopen() {
    let mut fixture = setup("selected");
    for _ in 0..2 {
        let output = predict_selected_pft(
            CellAdoptionUseV1 {
                owner: &mut fixture.owner,
                snapshot: &fixture.selected,
                execution: &execution(),
            },
            CANDIDATE,
            FEATURES,
            &expected(),
            || true,
        )
        .unwrap();
        assert_eq!(
            output.version_commitment(),
            version("selected").commitment()
        );
        assert_eq!(
            (output.selection_revision(), output.model_generation()),
            (1, 2)
        );
        assert_eq!(output.model_descriptor(), &expected().model);
        assert_eq!(output.input_descriptor(), &expected().input);
        assert_eq!(output.prediction().shape(), [2, 2]);
        assert_eq!(
            hex::encode(output.prediction().to_le_bytes()),
            "000000000000004000000000000014c000000000000010c00000000000002440"
        );
        assert_eq!(fixture.owner.snapshot().unwrap(), fixture.selected);
        drop(fixture.owner);
        fixture.owner =
            CellAdoptionOwnerV1::open(&fixture.path, &fixture.policy, &fixture.selected).unwrap();
    }
}

#[test]
fn inspection_only_profile_and_substituted_model_or_input_refuse() {
    let mut old = setup("inspection_only");
    assert!(matches!(
        predict_selected_pft(
            CellAdoptionUseV1 {
                owner: &mut old.owner,
                snapshot: &old.selected,
                execution: &execution()
            },
            CANDIDATE,
            FEATURES,
            &expected(),
            || true
        ),
        Err(PftSelectedReadoutErrorV1::Profile)
    ));
    let mut fixture = setup("selected");
    let mut changed_candidate = CANDIDATE.to_vec();
    changed_candidate[0] ^= 1;
    assert!(matches!(
        predict_selected_pft(
            CellAdoptionUseV1 {
                owner: &mut fixture.owner,
                snapshot: &fixture.selected,
                execution: &execution(),
            },
            &changed_candidate,
            FEATURES,
            &expected(),
            || true,
        ),
        Err(PftSelectedReadoutErrorV1::Loader(
            loader::NativePftErrorV1::Pin
        ))
    ));
    let mut changed = expected();
    changed.model.weight_sha256 = [91; 32];
    assert!(matches!(
        predict_selected_pft(
            CellAdoptionUseV1 {
                owner: &mut fixture.owner,
                snapshot: &fixture.selected,
                execution: &execution()
            },
            CANDIDATE,
            FEATURES,
            &changed,
            || true
        ),
        Err(PftSelectedReadoutErrorV1::ModelIdentity)
    ));
    let mut changed = expected();
    changed.input.request_id = [91; 32];
    assert!(matches!(
        predict_selected_pft(
            CellAdoptionUseV1 {
                owner: &mut fixture.owner,
                snapshot: &fixture.selected,
                execution: &execution()
            },
            CANDIDATE,
            FEATURES,
            &changed,
            || true
        ),
        Err(PftSelectedReadoutErrorV1::Loader(_))
    ));
    assert!(matches!(
        predict_selected_pft(
            CellAdoptionUseV1 {
                owner: &mut fixture.owner,
                snapshot: &fixture.selected,
                execution: &execution()
            },
            CANDIDATE,
            b"{}",
            &expected(),
            || true
        ),
        Err(PftSelectedReadoutErrorV1::Loader(_))
    ));
    assert_eq!(fixture.owner.snapshot().unwrap(), fixture.selected);
}

#[test]
fn original_writer_fence_spans_arithmetic_and_stale_selection_never_runs_guard() {
    let mut fixture = setup("selected");
    let successor = version("successor");
    fixture
        .owner
        .observe_candidate(
            &successor,
            Some(version("selected").commitment()),
            CellCandidateEvidenceV1::default(),
        )
        .unwrap();
    let mut other =
        CellAdoptionOwnerV1::open(&fixture.path, &fixture.policy, &fixture.selected).unwrap();
    let mut checks = 0;
    let output = predict_selected_pft(
        CellAdoptionUseV1 {
            owner: &mut fixture.owner,
            snapshot: &fixture.selected,
            execution: &execution(),
        },
        CANDIDATE,
        FEATURES,
        &expected(),
        || {
            checks += 1;
            assert!(other
                .decide(
                    [2; 32],
                    &fixture.selected,
                    CellAdoptionActionV1::Adopt,
                    successor.commitment(),
                    [72; 64]
                )
                .is_err());
            true
        },
    )
    .unwrap();
    assert!(checks >= 6);
    assert_eq!(
        output.version_commitment(),
        version("selected").commitment()
    );
    let after = other
        .decide(
            [2; 32],
            &fixture.selected,
            CellAdoptionActionV1::Adopt,
            successor.commitment(),
            [72; 64],
        )
        .unwrap()
        .after()
        .clone();
    let result = predict_selected_pft(
        CellAdoptionUseV1 {
            owner: &mut fixture.owner,
            snapshot: &fixture.selected,
            execution: &execution(),
        },
        b"{",
        b"{",
        &expected(),
        || panic!("stale owner must refuse before parsing or caller check"),
    );
    assert!(matches!(result, Err(PftSelectedReadoutErrorV1::Owner(_))));
    assert_eq!(fixture.owner.snapshot().unwrap(), after);
}

#[test]
fn caller_refusal_during_and_after_arithmetic_releases_fence_without_prediction() {
    // This 2x2 fixture checks twice in the wrapper, then core entry, first row,
    // each column, second row, each column, and finally after all arithmetic.
    // Check 6 refuses after one completed output; check 10 refuses at the end.
    for refusal_at in [6, 10] {
        let mut fixture = setup("selected");
        let successor = version("successor");
        fixture
            .owner
            .observe_candidate(
                &successor,
                Some(version("selected").commitment()),
                CellCandidateEvidenceV1::default(),
            )
            .unwrap();
        let mut checks = 0;
        let result = predict_selected_pft(
            CellAdoptionUseV1 {
                owner: &mut fixture.owner,
                snapshot: &fixture.selected,
                execution: &execution(),
            },
            CANDIDATE,
            FEATURES,
            &expected(),
            || {
                checks += 1;
                checks < refusal_at
            },
        );
        assert!(matches!(
            result,
            Err(PftSelectedReadoutErrorV1::Numeric(
                core::PftErrorV1::ResourceBoundary
            ))
        ));
        assert_eq!(checks, refusal_at);
        assert_eq!(fixture.owner.snapshot().unwrap(), fixture.selected);
        let mut other =
            CellAdoptionOwnerV1::open(&fixture.path, &fixture.policy, &fixture.selected).unwrap();
        assert!(other
            .decide(
                [2; 32],
                &fixture.selected,
                CellAdoptionActionV1::Adopt,
                successor.commitment(),
                [72; 64]
            )
            .is_ok());
    }
}
