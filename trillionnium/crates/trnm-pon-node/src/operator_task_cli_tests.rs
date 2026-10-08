//! Unexecuted protected-config mechanism definitions; no operational keys.
use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};

fn args(path: &Path, sha: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "--operator-task-mode".into(),
            trnm_pon_node::operator_task_policy::MODE.into(),
        ),
        (
            "--operator-task-config".into(),
            path.to_str().unwrap().into(),
        ),
        ("--operator-task-config-sha256".into(), sha.into()),
        ("--operator-task-source-commit".into(), "11".repeat(20)),
        (
            "--operator-task-policy-source-sha256".into(),
            "22".repeat(32),
        ),
        ("--operator-task-registry2-package".into(), "33".repeat(32)),
    ])
}

#[test]
fn required_cli_options_are_all_or_none_without_fallback() {
    assert!(operator_task_inputs(&BTreeMap::new()).unwrap().is_none());
    for key in OWNER_CONFIG_OPTIONS
        .into_iter()
        .chain(["--operator-task-mode"])
    {
        let one = BTreeMap::from([(key.into(), "placeholder".into())]);
        assert_eq!(
            operator_task_inputs(&one).err().unwrap().to_string(),
            "OWNER_TASK_COMPLETE_CONFIG_REQUIRED"
        );
    }
    let mut complete = args(Path::new("relative-config"), &"11".repeat(32));
    assert_eq!(
        operator_task_inputs(&complete).err().unwrap().to_string(),
        "OWNER_TASK_CONFIG_ABSOLUTE"
    );
    complete.insert("--operator-task-mode".into(), "unrecognized-mode".into());
    assert_eq!(
        operator_task_inputs(&complete).err().unwrap().to_string(),
        "OWNER_TASK_COMPLETE_CONFIG_REQUIRED"
    );
}

#[test]
fn protected_config_refuses_symlink_hardlink_and_group_writable_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    std::fs::write(&path, b"{}").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
    assert_eq!(
        operator_task_inputs(&args(&path, &"11".repeat(32)))
            .err()
            .unwrap()
            .to_string(),
        "OWNER_TASK_CONFIG_FILE"
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let other = dir.path().join("other.json");
    std::fs::hard_link(&path, &other).unwrap();
    assert_eq!(
        operator_task_inputs(&args(&path, &"11".repeat(32)))
            .err()
            .unwrap()
            .to_string(),
        "OWNER_TASK_CONFIG_FILE"
    );
    std::fs::remove_file(&other).unwrap();
    symlink(&path, &other).unwrap();
    assert_eq!(
        operator_task_inputs(&args(&other, &"11".repeat(32)))
            .err()
            .unwrap()
            .to_string(),
        "OWNER_TASK_CONFIG_FILE"
    );
}

#[test]
fn exact_config_digest_is_required_before_untrusted_schema_or_authority() {
    use sha2::{Digest, Sha256};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    std::fs::write(&path, b"{}").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        operator_task_inputs(&args(&path, &"11".repeat(32)))
            .err()
            .unwrap()
            .to_string(),
        "OWNER_TASK_CONFIG_SHA"
    );
    let exact = hex::encode(Sha256::digest(b"{}"));
    assert_eq!(
        operator_task_inputs(&args(&path, &exact))
            .err()
            .unwrap()
            .to_string(),
        "OWNER_TASK_CONFIG_SCHEMA"
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"{}");
}
