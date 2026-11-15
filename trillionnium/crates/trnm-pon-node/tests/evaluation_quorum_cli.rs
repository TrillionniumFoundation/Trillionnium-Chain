//! Actual CLI selector, separate persistent contexts and incompatible-profile refusal.
use serde_json::Value;
use std::{
    path::Path,
    process::{Command, Output},
};
use trnm_mvcc_fee::{model_composition_v4, model_evidence_v3, public_evaluation};

fn status(store: &Path, policy: &str, model: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"))
        .args([
            "status",
            "--development",
            "--genesis-time",
            "1",
            "--evaluation-policy",
            policy,
            "--model-profile",
            model,
            "--workers",
            "2",
        ])
        .arg("--store")
        .arg(store)
        .output()
        .unwrap()
}

#[test]
fn explicit_cli_profile_has_distinct_context_and_cannot_reopen_a_legacy_store() {
    let temp = tempfile::tempdir().unwrap();
    for (index, model) in [model_evidence_v3::PROFILE, model_composition_v4::PROFILE]
        .into_iter()
        .enumerate()
    {
        let current_path = temp.path().join(format!("quorum-{index}"));
        let old_path = temp.path().join(format!("legacy-{index}"));
        let current = status(&current_path, public_evaluation::QUORUM_PROFILE, model);
        assert!(
            current.status.success(),
            "{}",
            String::from_utf8_lossy(&current.stderr)
        );
        let old = status(&old_path, public_evaluation::PROFILE, model);
        assert!(
            old.status.success(),
            "{}",
            String::from_utf8_lossy(&old.stderr)
        );
        let current: Value = serde_json::from_slice(&current.stdout).unwrap();
        let old: Value = serde_json::from_slice(&old.stdout).unwrap();
        for field in ["network", "parameters", "genesis"] {
            assert_ne!(
                current["result"][field], old["result"][field],
                "{model}: {field}"
            );
        }
        assert_eq!(current["result"]["production_activation"], false);
        assert_eq!(
            status(&current_path, public_evaluation::PROFILE, model)
                .status
                .code(),
            Some(2)
        );
        let reopened = status(&current_path, public_evaluation::QUORUM_PROFILE, model);
        assert!(reopened.status.success());
        assert_eq!(
            serde_json::from_slice::<Value>(&reopened.stdout).unwrap(),
            current
        );
    }
    let unsupported = temp.path().join("attested-not-created");
    let rejected = status(
        &unsupported,
        public_evaluation::QUORUM_PROFILE,
        "linear-expert-dev-v1",
    );
    assert_eq!(rejected.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("PUBLIC_EVAL_NATIVE_REPLAY_REQUIRED")
    );
    assert!(!unsupported.exists());
}
