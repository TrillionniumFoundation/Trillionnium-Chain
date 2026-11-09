use super::super::execution_wire::{
    ConfigurationPolicy, Contract, DirectoryIdentity, Outside, LEGACY_PROFILE, PROFILE,
};
use super::*;
use std::path::PathBuf;

fn contract(profile: &str, environment: BTreeMap<String, String>) -> Contract {
    let outside = Outside {
        path: PathBuf::from("/fixture/launch.json"),
        sha256: "11".repeat(32),
        registry_key: "22".repeat(32),
        task_key: "33".repeat(32),
        source_commit: "44".repeat(20),
        node_policy_source: "55".repeat(20),
        registry2_package: "66".repeat(32),
    };
    Contract {
        schema_version: 1,
        profile: profile.into(),
        namespace: [1; 32],
        protected_trust_sha256: [2; 32],
        node_bundle: [3; 32],
        artifact_name: "fixture-node".into(),
        program_sha256: [4; 32],
        program_size: 512,
        platform_digest: [5; 32],
        working_directory: PathBuf::from("/fixture/working"),
        working_identity: DirectoryIdentity {
            device: 1,
            inode: 1,
            uid: 1,
            mode: 0o40700,
        },
        environment,
        arguments: outside.arguments().unwrap(),
        outside,
    }
}

#[test]
fn legacy_contract_is_replayable_but_cannot_authorize_new_execution() {
    let old = contract(LEGACY_PROFILE, legacy_environment());
    assert!(old.validate().is_ok());
    assert!(old.require_closed_execution().is_err());
    let current = contract(PROFILE, restricted_environment());
    assert!(current.validate().is_ok());
    assert!(current.require_closed_execution().is_ok());
    // A profile substitution cannot reuse either complete signed environment.
    assert!(contract(PROFILE, legacy_environment()).validate().is_err());
    assert!(contract(LEGACY_PROFILE, restricted_environment())
        .validate()
        .is_err());
}

#[test]
fn legacy_configuration_bytes_keep_their_original_signed_digest() {
    let policy = ConfigurationPolicy {
        schema_version: 1,
        contract: contract(LEGACY_PROFILE, legacy_environment()),
        inputs_digest: [6; 32],
    };
    let raw = super::super::codec::encode(&policy, 131072).unwrap();
    assert_eq!(raw.len(), 1845);
    // Independently recomputed from the original ordered JSON fields, the
    // original domain and its big-endian u64 payload length. This fixture
    // carries no release signatures or production authority.
    assert_eq!(
        hex::encode(policy.digest().unwrap()),
        "4eda981573772152dffe3b3066f1c4d3a8793bffe6946a0e6a9e12eface8cf1a"
    );
    let replayed: ConfigurationPolicy = super::super::codec::decode(&raw, 131072).unwrap();
    assert_eq!(replayed.digest().unwrap(), policy.digest().unwrap());
    assert!(replayed.contract.require_closed_execution().is_err());
    let current = ConfigurationPolicy {
        contract: contract(PROFILE, restricted_environment()),
        ..policy
    };
    assert_ne!(current.digest().unwrap(), replayed.digest().unwrap());
}

#[test]
fn empty_configuration_is_explicit_and_external_provider_paths_are_refused() {
    let valid = LIBRARY_ENVIRONMENT.map(|(_, value)| Some(OsString::from(value)));
    assert!(provider_values(valid.clone()).is_ok());
    for index in 0..3 {
        let mut missing = valid.clone();
        missing[index] = None;
        assert!(provider_values(missing).is_err());
        let mut replaced = valid.clone();
        replaced[index] = Some(OsString::from("/fixture/unbound"));
        assert!(provider_values(replaced).is_err());
    }
}

fn environment_rows() -> Vec<(OsString, OsString)> {
    restricted_environment()
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect()
}

#[test]
fn exact_environment_refuses_omissions_duplicates_injection_and_non_utf8() {
    use std::os::unix::ffi::OsStringExt;
    assert!(exact_values(environment_rows()).is_ok());
    let mut missing = environment_rows();
    missing.pop();
    assert!(exact_values(missing).is_err());
    let mut duplicate = environment_rows();
    duplicate[1] = duplicate[0].clone();
    assert!(exact_values(duplicate).is_err());
    let mut injected = environment_rows();
    injected.push(("LD_PRELOAD".into(), "/fixture/unbound.so".into()));
    assert!(exact_values(injected).is_err());
    let mut invalid = environment_rows();
    invalid[0].1 = OsString::from_vec(vec![0xff]);
    assert!(exact_values(invalid).is_err());
}

fn auxv(rows: &[(usize, usize)]) -> Vec<u8> {
    rows.iter()
        .flat_map(|(tag, value)| [tag.to_ne_bytes(), value.to_ne_bytes()].concat())
        .collect()
}

#[test]
fn secure_execution_mode_is_explicit_not_inferred_from_environment_text() {
    let secure = libc::AT_SECURE as usize;
    assert!(!secure_auxiliary_vector(&auxv(&[(secure, 0), (0, 0)])).unwrap());
    assert!(secure_auxiliary_vector(&auxv(&[(secure, 1), (0, 0)])).unwrap());
    for rows in [
        vec![(0, 0)],
        vec![(secure, 0)],
        vec![(secure, 2), (0, 0)],
        vec![(secure, 0), (secure, 0), (0, 0)],
        vec![(secure, 0), (0, 1)],
        vec![(secure, 0), (0, 0), (secure, 0)],
    ] {
        assert!(secure_auxiliary_vector(&auxv(&rows)).is_err());
    }
    assert!(secure_auxiliary_vector(&[0; 4097]).is_err());
}

#[test]
fn actual_kernel_auxiliary_vector_has_a_current_secure_mode() {
    let raw = std::fs::read("/proc/self/auxv").unwrap();
    assert!(secure_auxiliary_vector(&raw).is_ok());
}
