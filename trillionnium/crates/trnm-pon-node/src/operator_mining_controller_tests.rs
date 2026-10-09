//! Decoder/held-file tests do not qualify any model, task, miner or Native result.
use super::*;
use std::os::unix::fs::PermissionsExt;
#[test]
fn unknown_purpose_and_missing_complete_refresh_refuse_before_controller() {
    assert!(serde_json::from_slice::<Step>(br#"{"purpose":"submit","packet":"00"}"#).is_err());
    assert!(
        serde_json::from_slice::<Step>(br#"{"purpose":"search","operation_id":"00"}"#).is_err()
    );
    assert!(serde_json::from_slice::<Step>(br#"{"purpose":"refresh","inputs":null}"#).is_err());
    assert!(serde_json::from_slice::<Step>(
        br#"{"purpose":"winner-validation","packet":"00","search_id":"00"}"#
    )
    .is_err());
}
#[test]
fn no_legacy_work_pool_or_taskview_alias_in_control_protocol() {
    for purpose in [
        "pool-submit",
        "pool-mining",
        "taskview",
        "legacy-development",
        "admit-work-checked",
    ] {
        let raw = serde_json::to_vec(&json!({"purpose":purpose})).unwrap();
        assert!(serde_json::from_slice::<Step>(&raw).is_err());
    }
    assert!(matches!(
        serde_json::from_slice::<Step>(br#"{"purpose":"read-status"}"#).unwrap(),
        Step::ReadStatus {}
    ));
}
#[test]
fn launch_digest_hardlink_symlink_and_group_write_fail_before_authority_or_native() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("launch.json");
    let raw = b"{\"schema\":\"not-a-launch\"}";
    std::fs::write(&path, raw).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let h = "11".repeat(32);
    let source = "22".repeat(20);
    assert!(read_launch(&path, &h, &h, &h, &source, &h, &h).is_err());
    let digest = crate::operator_task_policy::digest_bytes(raw);
    let alias = temp.path().join("alias");
    std::fs::hard_link(&path, &alias).unwrap();
    assert!(read_launch(&path, &digest, &h, &h, &source, &h, &h).is_err());
    std::fs::remove_file(&alias).unwrap();
    std::os::unix::fs::symlink(&path, &alias).unwrap();
    assert!(read_launch(&alias, &digest, &h, &h, &source, &h, &h).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
    assert!(read_launch(&path, &digest, &h, &h, &source, &h, &h).is_err());
}
#[test]
fn duplicate_or_unknown_control_fields_cannot_override_a_signed_operation() {
    assert!(serde_json::from_slice::<Step>(
        br#"{"purpose":"search","purpose":"activate","operation_id":"00","transactions":[]}"#
    )
    .is_err());
    assert!(
        serde_json::from_slice::<Step>(br#"{"purpose":"cancel-epoch","refund":true}"#).is_err()
    );
    assert!(serde_json::from_slice::<Step>(br#"{"purpose":"read-status","refund":true}"#).is_err());
    assert!(serde_json::from_slice::<Step>(
        br#"{"purpose":"read-status","purpose":"read-status"}"#
    )
    .is_err());
    assert!(serde_json::from_slice::<Step>(
        br#"{"purpose":"read-status","extra":true,"extra":false}"#
    )
    .is_err());
    assert!(matches!(
        serde_json::from_slice::<Step>(br#"{"purpose":"cancel-epoch"}"#).unwrap(),
        Step::CancelEpoch {}
    ));
    assert!(serde_json::from_slice::<Step>(br#"{"purpose":"search","operation_id":"00","transactions":[],"model_id":"self-authorized"}"#).is_err());
}
