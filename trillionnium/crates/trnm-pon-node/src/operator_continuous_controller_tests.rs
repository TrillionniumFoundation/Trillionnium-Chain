use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};
#[test]
fn mode4_control_unit_structs_reject_extra_duplicate_and_unknown_fields() {
    for raw in [
        r#"{"purpose":"cancel-epoch","refund":true}"#,
        r#"{"purpose":"read-status","credit":0}"#,
        r#"{"purpose":"read-head","credit":0}"#,
        r#"{"purpose":"read-status","purpose":"read-status"}"#,
        r#"{"purpose":"read-scope-snapshot","operation_id":"a","unexpected":true}"#,
    ] {
        assert!(serde_json::from_str::<Step>(raw).is_err());
    }
    assert!(matches!(
        serde_json::from_str::<Step>(r#"{"purpose":"cancel-epoch"}"#).unwrap(),
        Step::CancelEpoch {}
    ));
    assert!(matches!(
        serde_json::from_str::<Step>(r#"{"purpose":"read-status"}"#).unwrap(),
        Step::ReadStatus {}
    ));
}
#[test]
fn mode4_late_metadata_unknown_preserves_native_durable_value_without_fake_head() {
    let native =
        json!({"native_id":"aa".repeat(32),"native_error":null,"durable_result_preserved":true});
    let result = step_result(
        1,
        Ok(native.clone()),
        Completion {
            parent: None,
            generation: None,
            journal_head: None,
            frame_recorded: false,
            errors: vec!["JOURNAL_HEAD_UNAVAILABLE", "ACTIVE_METADATA_UNAVAILABLE"],
        },
    );
    assert_eq!(result["result"], native);
    assert!(result["parent"].is_null());
    assert!(result["generation"].is_null());
    assert!(result["journal_head"].is_null());
    assert!(result["native_error"].is_null());
    assert_eq!(result["metadata_errors"].as_array().unwrap().len(), 2);
    assert_eq!(result["public_network_ready"], false);
    let result = step_result(
        2,
        Err("original Native failure".into()),
        Completion {
            parent: None,
            generation: None,
            journal_head: None,
            frame_recorded: false,
            errors: vec!["JOURNAL_FRAME_UNAVAILABLE"],
        },
    );
    assert!(result["result"].is_null());
    assert_eq!(result["native_error"], "original Native failure");
}
#[test]
fn mode4_launch_held_configuration_rejects_modes_symlinks_and_content_substitution() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("launch.json");
    fs::write(&path, b"{}").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(held_configuration(&path, 64).unwrap(), b"{}");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o664)).unwrap();
    assert!(held_configuration(&path, 64).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let link = dir.path().join("link");
    symlink(&path, &link).unwrap();
    assert!(held_configuration(&link, 64).is_err());
    let outside = OutsideLaunch {
        path: &path,
        sha256: &"00".repeat(32),
        registry_key: &"11".repeat(32),
        task_key: &"22".repeat(32),
        source_commit: &"33".repeat(20),
        node_policy_source: &"44".repeat(32),
        registry2_package: &"55".repeat(32),
    };
    assert!(read_launch(&outside).is_err());
}
