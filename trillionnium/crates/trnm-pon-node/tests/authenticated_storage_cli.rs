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

// Exercise the public Node owner, not a second SQL implementation. A separate
// connection commits deliberate damage to a disposable database while the real
// owner's statement cache stays warm. Repair is test-only: production services
// must stop on the local-integrity errors asserted below.
mod cached_owner_reads {
    use super::*;
    use rusqlite::{params, Connection, OpenFlags};
    use trnm_pon_node::{development_public, Node, Settings};

    fn settings() -> Settings {
        Settings::development_with_profiles(Some(1), "native-public-evaluation-dev-v1", PROFILE)
            .unwrap()
    }

    fn open(path: &Path) -> Node {
        Node::open_with_authenticated_state(path, settings(), 1).unwrap()
    }

    fn disk(path: &Path) -> Connection {
        Connection::open_with_flags(path.join("native.sqlite"), OpenFlags::SQLITE_OPEN_READ_WRITE)
            .unwrap()
    }

    #[test]
    fn live_owner_rechecks_genesis_block_after_committed_damage_and_restore() {
        let directory = tempfile::tempdir().unwrap();
        let node = open(directory.path());
        let expected = node.read_active().unwrap();
        let genesis = node.settings().genesis();
        let db = disk(directory.path());
        for _ in 0..3 {
            assert_eq!(node.read_active().unwrap(), expected);
            assert_eq!(
                db.execute(
                    "UPDATE blocks SET packet=? WHERE id=?",
                    params![b"invalid-genesis-packet".as_slice(), genesis.as_slice()],
                )
                .unwrap(),
                1
            );
            let error = node.read_active().unwrap_err();
            assert_eq!(error.to_string(), "NATIVE_STATE_GENESIS");
            assert!(error.requires_owner_stop());
            assert_eq!(
                db.execute(
                    "UPDATE blocks SET packet=NULL WHERE id=?",
                    [genesis.as_slice()],
                )
                .unwrap(),
                1
            );
            assert_eq!(node.read_active().unwrap(), expected);
        }
        drop(db);
        drop(node);
        assert_eq!(open(directory.path()).read_active().unwrap(), expected);
    }

    #[test]
    fn live_owner_rechecks_parent_work_after_real_admission() {
        let directory = tempfile::tempdir().unwrap();
        let mut node = open(directory.path());
        let genesis = node.settings().genesis();
        let packet = node
            .make_consensus_maintenance(
                genesis,
                vec![],
                development_public(0).unwrap(),
                11,
                4096,
            )
            .unwrap();
        let id = node.admit(&packet, 1000).unwrap();
        node.activate(id).unwrap();
        let expected = node.read_active().unwrap();
        assert_eq!(expected.0, id);
        let db = disk(directory.path());
        let original: Vec<u8> = db
            .query_row(
                "SELECT chainwork FROM blocks WHERE id=?",
                [genesis.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            db.execute(
                "UPDATE blocks SET chainwork=? WHERE id=?",
                params![vec![255u8; 64], genesis.as_slice()],
            )
            .unwrap(),
            1
        );
        assert!(node.read_active().unwrap_err().requires_owner_stop());
        db.execute(
            "UPDATE blocks SET chainwork=? WHERE id=?",
            params![original, genesis.as_slice()],
        )
        .unwrap();
        assert_eq!(node.read_active().unwrap(), expected);
        drop(db);
        drop(node);
        assert_eq!(open(directory.path()).read_active().unwrap(), expected);
    }

    #[test]
    fn live_owner_rechecks_record_limits_missing_rows_and_sql_types() {
        let directory = tempfile::tempdir().unwrap();
        let node = open(directory.path());
        let expected = node.read_active().unwrap();
        let genesis = node.settings().genesis();
        let db = disk(directory.path());
        let original: Vec<u8> = db
            .query_row(
                "SELECT data FROM native_state_commitments WHERE block=?",
                [genesis.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        for length in [16 * 1024 + 1, 128 * 1024] {
            db.execute(
                "UPDATE native_state_commitments SET data=? WHERE block=?",
                params![vec![b'x'; length], genesis.as_slice()],
            )
            .unwrap();
            let error = node.read_active().unwrap_err();
            assert_eq!(error.to_string(), "NATIVE_STATE_RECORD_LIMIT");
            assert!(error.requires_owner_stop());
            db.execute(
                "UPDATE native_state_commitments SET data=? WHERE block=?",
                params![&original, genesis.as_slice()],
            )
            .unwrap();
            assert_eq!(node.read_active().unwrap(), expected);
        }
        db.execute(
            "UPDATE native_state_commitments SET data=CAST(data AS TEXT) WHERE block=?",
            [genesis.as_slice()],
        )
        .unwrap();
        assert!(node.read_active().unwrap_err().requires_owner_stop());
        db.execute(
            "DELETE FROM native_state_commitments WHERE block=?",
            [genesis.as_slice()],
        )
        .unwrap();
        let error = node.read_active().unwrap_err();
        assert_eq!(error.to_string(), "NATIVE_STATE_MISSING");
        assert!(error.requires_owner_stop());
        db.execute(
            "INSERT INTO native_state_commitments(block,data) VALUES(?,?)",
            params![genesis.as_slice(), original],
        )
        .unwrap();
        assert_eq!(node.read_active().unwrap(), expected);
        drop(db);
        drop(node);
        assert_eq!(open(directory.path()).read_active().unwrap(), expected);
    }

    #[test]
    fn live_owner_snapshot_damage_rolls_back_admission_and_rejects_cold_open() {
        let directory = tempfile::tempdir().unwrap();
        let mut node = open(directory.path());
        let expected = node.read_active().unwrap();
        let genesis = node.settings().genesis();
        let packet = node
            .make_consensus_maintenance(
                genesis,
                vec![],
                development_public(0).unwrap(),
                11,
                4096,
            )
            .unwrap();
        let id = packet.id().unwrap();
        let db = disk(directory.path());
        let original: Vec<u8> = db
            .query_row(
                "SELECT state FROM snapshots WHERE block=?",
                [genesis.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        let counts = |db: &Connection| -> (u64, u64, u64, u64, u64) {
            db.query_row(
                "SELECT (SELECT COUNT(*) FROM blocks), (SELECT COUNT(*) FROM deltas), \
                 (SELECT COUNT(*) FROM native_state_commitments), \
                 (SELECT COUNT(*) FROM archive_nodes), (SELECT COUNT(*) FROM snapshots)",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap()
        };
        let before = counts(&db);
        db.execute(
            "UPDATE snapshots SET state=? WHERE block=?",
            params![b"{}".as_slice(), genesis.as_slice()],
        )
        .unwrap();
        let error = node.admit(&packet, 1000).unwrap_err();
        assert_eq!(error.to_string(), "NATIVE_STATE_GENESIS");
        assert!(error.requires_owner_stop());
        assert_eq!(counts(&db), before);
        let inserted: u64 = db
            .query_row(
                "SELECT COUNT(*) FROM blocks WHERE id=?",
                [id.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(inserted, 0);
        assert_eq!(node.read_active().unwrap(), expected);
        drop(node);
        let error = Node::open_with_authenticated_state(directory.path(), settings(), 1)
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "NATIVE_STATE_GENESIS");
        assert!(error.requires_owner_stop());
        assert_eq!(counts(&db), before);
        db.execute(
            "UPDATE snapshots SET state=? WHERE block=?",
            params![original, genesis.as_slice()],
        )
        .unwrap();
        drop(db);
        let mut reopened = open(directory.path());
        assert_eq!(reopened.read_active().unwrap(), expected);
        assert_eq!(reopened.admit(&packet, 1000).unwrap(), id);
        reopened.activate(id).unwrap();
        let restored = reopened.read_active().unwrap();
        assert_eq!(restored.0, id);
        drop(reopened);
        assert_eq!(open(directory.path()).read_active().unwrap(), restored);
    }
}
