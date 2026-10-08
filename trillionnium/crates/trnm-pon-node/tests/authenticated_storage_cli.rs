//! Actual process entrypoints for the explicitly selected native storage schema.
use serde_json::Value;
use std::{
    path::Path,
    process::{Command, Output},
};
use trnm_mvcc_fee::continuity_v1::PROFILE;

fn command(name: &str, store: &Path, backend: Option<&str>) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"));
    cmd.arg(name)
        .args([
            "--development",
            "--genesis-time",
            "1",
            "--logical-now",
            "1000",
            "--evaluation-policy",
            "native-public-evaluation-dev-v1",
            "--task-profile",
            PROFILE,
        ])
        .arg("--store")
        .arg(store);
    if let Some(backend) = backend {
        cmd.args(["--state-backend", backend]);
    }
    cmd
}

fn accepted(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn rejected(output: Output, code: &str) {
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(code),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn explicit_backend_mines_and_cold_reopens_the_same_authenticated_native_state() {
    let temp = tempfile::tempdir().unwrap();
    let store = temp.path().join("authenticated");
    let packet = temp.path().join("first.packet");
    let mined = accepted(
        command("mine", &store, Some("authenticated-v1"))
            .args(["--timestamp", "11", "--consensus-maintenance"])
            .arg("--output")
            .arg(&packet)
            .output()
            .unwrap(),
    );
    assert_eq!(mined["result"]["state"]["height"], 1);
    assert_eq!(mined["result"]["admitted"], true);
    assert!(packet.is_file());
    let reopened = accepted(
        command("recover", &store, Some("authenticated-v1"))
            .output()
            .unwrap(),
    );
    assert_eq!(reopened["result"], mined["result"]["state"]);
    let observed = accepted(
        command("capacity-observe", &store, Some("authenticated-v1"))
            .output()
            .unwrap(),
    );
    assert_eq!(
        observed["result"]["observed_tip"],
        reopened["result"]["tip"]
    );
    assert_eq!(
        observed["result"]["state_root"],
        reopened["result"]["state_root"]
    );
    let db = rusqlite::Connection::open_with_flags(
        store.join("native.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let commitments: u64 = db
        .query_row("SELECT COUNT(*) FROM native_state_commitments", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(commitments, 2);
}

#[test]
fn explicit_and_default_storage_namespaces_reject_each_other_without_changing_the_database() {
    let temp = tempfile::tempdir().unwrap();
    for (name, selected, wrong) in [
        ("authenticated", Some("authenticated-v1"), None),
        ("legacy", None, Some("authenticated-v1")),
    ] {
        let store = temp.path().join(name);
        let initial = accepted(command("status", &store, selected).output().unwrap());
        let before = std::fs::read(store.join("native.sqlite")).unwrap();
        rejected(
            command("recover", &store, wrong).output().unwrap(),
            "SCHEMA",
        );
        assert_eq!(before, std::fs::read(store.join("native.sqlite")).unwrap());
        let reopened = accepted(command("status", &store, selected).output().unwrap());
        assert_eq!(reopened, initial);
        if selected.is_none() {
            assert_eq!(
                accepted(
                    command("status", &store, Some("legacy-v2"))
                        .output()
                        .unwrap()
                ),
                initial
            );
        }
    }
}

#[test]
fn invalid_backend_scope_and_external_owner_combinations_reject_before_open() {
    let temp = tempfile::tempdir().unwrap();
    let store = temp.path().join("must-not-exist");
    rejected(
        command("status", &store, Some("unknown")).output().unwrap(),
        "NATIVE_STATE_BACKEND",
    );
    assert!(!store.exists());
    for name in ["push", "head", "task-fixture", "genesis-prepare"] {
        rejected(
            command(name, &store, Some("authenticated-v1"))
                .output()
                .unwrap(),
            "NATIVE_STATE_BACKEND_COMMAND",
        );
        assert!(!store.exists());
    }
    for key in [
        "--operator-task-mode",
        "--operator-task-config",
        "--operator-task-config-sha256",
        "--operator-task-source-commit",
        "--operator-task-policy-source-sha256",
        "--operator-task-registry2-package",
    ] {
        rejected(
            command("status", &store, Some("authenticated-v1"))
                .args([key, "deliberately-incomplete"])
                .output()
                .unwrap(),
            "NATIVE_STATE_BACKEND_EXTERNAL_OWNER",
        );
        assert!(!store.exists());
    }
}
