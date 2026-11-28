//! Real original SQLite owner and wrapper; only public synthetic metadata/data.
//! Test-local comparison pins are not a host authorization or FinalUse grant.

use super::*;
use crate::pft_native_loader_v1::NativePftErrorV1;
use crate::pft_readout_f64_v1::PftModelDescriptorV1;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use trnm_data_availability::cell::{
    CellAdoptionActionV1, CellAdoptionOwnerV1, CellAdoptionPolicyV1, CellAdoptionSnapshotV1,
    CellCandidateEvidenceV1, CellExecutionBoundaryV1, CellModelUpdateBoundaryV1,
    CellVersionManifestV1,
};

const CANDIDATE: &[u8] = include_bytes!(
    "../../../../../evidence/pft-candidate-readback-20261128/SYNTHETIC_CANDIDATE.json"
);
const FIXTURE: &[u8] = include_bytes!(
    "../../../../../evidence/pft-selected-owner-controls-20261128/SYNTHETIC_OWNER_FIXTURE.json"
);

fn document() -> Value {
    serde_json::from_slice(FIXTURE).unwrap()
}

fn pin<const N: usize>(value: &Value) -> [u8; N] {
    hex::decode(value.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn version(name: &str) -> CellVersionManifestV1 {
    let doc = document();
    let item = &doc[name];
    let wire = hex::decode(item["wire_hex"].as_str().unwrap()).unwrap();
    let wire_digest: [u8; 32] = Sha256::digest(&wire).into();
    assert_eq!(wire_digest, pin::<32>(&item["wire_sha256"]));
    let value = CellVersionManifestV1::decode(&wire).unwrap();
    assert_eq!(value.encode(), wire);
    assert_eq!(value.commitment(), pin::<64>(&item["commitment_sha512"]));
    assert_eq!(value.model().id(), pin::<32>(&item["model_root_sha256"]));
    assert_eq!(
        value.model().closure().selected_generation(),
        item["generation"].as_u64().unwrap()
    );
    value
}

fn expected_descriptor() -> PftModelDescriptorV1 {
    let doc = document();
    let d = &doc["descriptor"];
    PftModelDescriptorV1 {
        schema: d["schema"].as_str().unwrap().into(),
        family: d["family"].as_str().unwrap().into(),
        numeric_profile: d["numeric_profile"].as_str().unwrap().into(),
        candidate_sha256: pin(&d["candidate_sha256"]),
        contract_sha256: pin(&d["contract_sha256"]),
        head: pin(&d["head"]),
        weight_sha256: pin(&d["weight_sha256"]),
        feature_program_sha256: pin(&d["feature_program_sha256"]),
        normalization_sha256: pin(&d["normalization_sha256"]),
        time_semantics_sha256: pin(&d["time_semantics_sha256"]),
        dimension: d["dimension"].as_u64().unwrap().try_into().unwrap(),
        outputs: d["outputs"].as_u64().unwrap().try_into().unwrap(),
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
    version: CellVersionManifestV1,
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
    let version = version(name);
    let boundary = CellModelUpdateBoundaryV1::new(
        &version,
        vec![CellFileRoleV1::Base],
        execution(),
        1_000_000,
        64,
    )
    .unwrap();
    let policy = CellAdoptionPolicyV1::new([1; 32], [2; 32], [3; 32], boundary).unwrap();
    let mut owner = CellAdoptionOwnerV1::create(&path, &policy).unwrap();
    owner
        .observe_candidate(&version, None, CellCandidateEvidenceV1::default())
        .unwrap();
    Fixture {
        _directory: directory,
        path,
        policy,
        owner,
        version,
    }
}

fn bootstrap(f: &mut Fixture) -> CellAdoptionSnapshotV1 {
    let before = f.owner.snapshot().unwrap();
    f.owner
        .decide(
            [1; 32],
            &before,
            CellAdoptionActionV1::Adopt,
            f.version.commitment(),
            [71; 64],
        )
        .unwrap()
        .after()
        .clone()
}

fn inspect(
    f: &mut Fixture,
    snapshot: &CellAdoptionSnapshotV1,
    candidate: &[u8],
    current: &CellExecutionBoundaryV1,
) -> Result<PftSelectedInspectionV1, PftSelectedInspectionErrorV1> {
    inspect_selected_pft(
        CellAdoptionUseV1 {
            owner: &mut f.owner,
            snapshot,
            execution: current,
        },
        candidate,
    )
}

#[test]
fn selected_catalog_wrapper_returns_frozen_descriptor_and_cold_reopen_agrees() {
    let mut f = setup("selected");
    let selected = bootstrap(&mut f);
    let observed = inspect(&mut f, &selected, CANDIDATE, &execution()).unwrap();
    assert_eq!(observed.version_commitment(), f.version.commitment());
    assert_eq!(observed.selection_revision(), 1);
    assert_eq!(observed.model_generation(), 2);
    assert_eq!(observed.model_descriptor(), &expected_descriptor());
    assert_eq!(f.owner.snapshot().unwrap(), selected);
    drop(f.owner);
    f.owner = CellAdoptionOwnerV1::open(&f.path, &f.policy, &selected).unwrap();
    assert_eq!(
        inspect(&mut f, &selected, CANDIDATE, &execution()).unwrap(),
        observed
    );
    assert_eq!(f.owner.snapshot().unwrap(), selected);
}

#[test]
fn original_owner_refuses_empty_stale_and_changed_execution_before_model_parse() {
    let mut f = setup("selected");
    let empty = f.owner.snapshot().unwrap();
    assert!(matches!(
        inspect(&mut f, &empty, b"{", &execution()),
        Err(PftSelectedInspectionErrorV1::Owner(_))
    ));
    let selected = bootstrap(&mut f);
    let mut changed = execution();
    changed.root_authority = [99; 32];
    assert!(matches!(
        inspect(&mut f, &selected, b"{", &changed),
        Err(PftSelectedInspectionErrorV1::Owner(_))
    ));
    assert_eq!(f.owner.snapshot().unwrap(), selected);
    let next = version("successor");
    f.owner
        .observe_candidate(
            &next,
            Some(f.version.commitment()),
            CellCandidateEvidenceV1::default(),
        )
        .unwrap();
    let current = f
        .owner
        .decide(
            [2; 32],
            &selected,
            CellAdoptionActionV1::Adopt,
            next.commitment(),
            [72; 64],
        )
        .unwrap()
        .after()
        .clone();
    assert!(matches!(
        inspect(&mut f, &selected, b"{", &execution()),
        Err(PftSelectedInspectionErrorV1::Owner(_))
    ));
    let observed = inspect(&mut f, &current, CANDIDATE, &execution()).unwrap();
    assert_eq!(observed.version_commitment(), next.commitment());
    assert_eq!(observed.selection_revision(), 2);
    assert_eq!(observed.model_generation(), 3);
    assert_eq!(observed.model_descriptor(), &expected_descriptor());
    assert_eq!(f.owner.snapshot().unwrap(), current);
}

#[test]
fn selected_catalog_payload_and_profile_refuse_without_changing_selection() {
    let mut f = setup("selected");
    let selected = bootstrap(&mut f);
    let mut appended = CANDIDATE.to_vec();
    appended.push(b' ');
    assert!(matches!(
        inspect(&mut f, &selected, &appended, &execution()),
        Err(PftSelectedInspectionErrorV1::Binding(
            PftSelectedBindingErrorV1::Payload
        ))
    ));
    let mut changed = CANDIDATE.to_vec();
    changed[0] ^= 1;
    assert!(matches!(
        inspect(&mut f, &selected, &changed, &execution()),
        Err(PftSelectedInspectionErrorV1::Binding(
            PftSelectedBindingErrorV1::Candidate(NativePftErrorV1::Pin)
        ))
    ));
    assert_eq!(f.owner.snapshot().unwrap(), selected);
    assert!(inspect(&mut f, &selected, CANDIDATE, &execution()).is_ok());
    let mut wrong_profile = setup("wrong_profile");
    let wrong_selected = bootstrap(&mut wrong_profile);
    assert!(matches!(
        inspect(&mut wrong_profile, &wrong_selected, CANDIDATE, &execution()),
        Err(PftSelectedInspectionErrorV1::Binding(
            PftSelectedBindingErrorV1::Profile
        ))
    ));
    assert_eq!(wrong_profile.owner.snapshot().unwrap(), wrong_selected);
}

#[test]
fn selected_catalog_repinned_invalid_pft_is_refused_by_original_parser() {
    let mut f = setup("invalid_candidate");
    let selected = bootstrap(&mut f);
    let doc = document();
    let bytes = doc["invalid_candidate_utf8"].as_str().unwrap().as_bytes();
    assert_ne!(bytes, CANDIDATE);
    let payload_digest: [u8; 32] = Sha256::digest(bytes).into();
    assert_eq!(
        payload_digest,
        f.version.model().closure().files()[0].payload_sha256
    );
    assert!(matches!(
        inspect(&mut f, &selected, bytes, &execution()),
        Err(PftSelectedInspectionErrorV1::Binding(
            PftSelectedBindingErrorV1::Candidate(NativePftErrorV1::Numeric)
        ))
    ));
    assert_eq!(f.owner.snapshot().unwrap(), selected);
}
