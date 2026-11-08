//! The real local CLI must observe an owner's state without opening a writer.
#![cfg(target_os = "linux")]
use serde_json::Value;
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    os::unix::fs::MetadataExt,
    path::Path,
    process::{Command, Output},
};
use trnm_pon_node::{
    observe_existing_packet, Node, Packet, PacketObservationBackend, Settings,
    DEFAULT_PACKET_OBSERVATION_SNAPSHOT_BYTE_LIMIT,
};
use trnm_protocol::pon_wire::Header;

const CLOCK: u64 = 1_800_010_000;
const BACKENDS: [PacketObservationBackend; 2] = [
    PacketObservationBackend::LegacyV2,
    PacketObservationBackend::AuthenticatedV1,
];

fn golden() -> Packet {
    Packet {
        header: Header::decode(include_bytes!(
            "../../../../formal/pon-nakamoto-v1/vectors/accepted-block/header.bin"
        ))
        .unwrap(),
        transactions: vec![include_bytes!(
            "../../../../formal/pon-nakamoto-v1/vectors/accepted-block/transaction.bin"
        )
        .to_vec()],
        proof: include_bytes!("../../../../formal/pon-nakamoto-v1/vectors/accepted-block/work.bin")
            .to_vec(),
    }
}

fn writer_result(path: &Path, backend: PacketObservationBackend) -> trnm_pon_node::Result<Node> {
    let settings = Settings::development(None).unwrap();
    match backend {
        PacketObservationBackend::LegacyV2 => Node::open(path, settings, 1),
        PacketObservationBackend::AuthenticatedV1 => {
            Node::open_with_authenticated_state(path, settings, 1)
        }
    }
}

fn writer(path: &Path, backend: PacketObservationBackend) -> Node {
    writer_result(path, backend).unwrap()
}

fn command(store: &Path, packet: &Path, backend: PacketObservationBackend) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"));
    command
        .args(["packet-status", "--development", "--store"])
        .arg(store)
        .arg("--packet")
        .arg(packet)
        .arg("--logical-now")
        .arg(CLOCK.to_string())
        .args([
            "--state-backend",
            match backend {
                PacketObservationBackend::LegacyV2 => "legacy-v2",
                PacketObservationBackend::AuthenticatedV1 => "authenticated-v1",
            },
        ]);
    command
}

fn accepted(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["production_activation"], false);
    assert_eq!(value["clock_scope"], "logical-test");
    value["result"].clone()
}

fn rejected(output: Output, code: &str) {
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(code),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[derive(Debug, Eq, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
    length: u64,
    mode: u32,
    links: u64,
    owner: (u32, u32),
    modified: (i64, i64),
    changed: (i64, i64),
}

fn identity(metadata: &fs::Metadata) -> Identity {
    Identity {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        mode: metadata.mode(),
        links: metadata.nlink(),
        owner: (metadata.uid(), metadata.gid()),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
    }
}

#[derive(Debug, Eq, PartialEq)]
struct NamespaceImage {
    directory: Identity,
    files: BTreeMap<OsString, (Identity, Vec<u8>)>,
}

// Read access time is deliberately excluded. No SQLite connection is opened by
// this assertion helper, including when recovery sidecars are present.
fn image(path: &Path) -> NamespaceImage {
    let files = fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let metadata = fs::symlink_metadata(entry.path()).unwrap();
            assert!(metadata.is_file());
            (
                entry.file_name(),
                (identity(&metadata), fs::read(entry.path()).unwrap()),
            )
        })
        .collect();
    NamespaceImage {
        directory: identity(&fs::symlink_metadata(path).unwrap()),
        files,
    }
}

fn packet_file(directory: &Path, packet: &Packet) -> std::path::PathBuf {
    let path = directory.join("input.packet");
    fs::write(&path, packet.encode().unwrap()).unwrap();
    path
}

#[test]
fn packet_status_cli_does_not_activate_an_admitted_packet() {
    for backend in BACKENDS {
        let temp = tempfile::tempdir().unwrap();
        let store = temp.path().join("store");
        let packet = golden();
        let input = packet_file(temp.path(), &packet);
        let mut owner = writer(&store, backend);
        let id = owner.admit(&packet, CLOCK).unwrap();
        let expected = owner.exact_packet_observation(&packet).unwrap();
        assert_eq!(expected["stored_exact"], true);
        assert_eq!(expected["active_chain_member"], false);
        assert_eq!(expected["generation"], 0);
        assert_eq!(
            expected["active_tip"],
            hex::encode(owner.settings().genesis())
        );
        drop(owner);

        let before = image(&store);
        // This subprocess is the regression: the previous CLI ran Node::open
        // and silently selected the admitted block before reporting its status.
        let observed = accepted(command(&store, &input, backend).output().unwrap());
        assert_eq!(observed, expected);
        assert_eq!(image(&store), before);
        assert_eq!(
            observe_existing_packet(
                &store,
                Settings::development(None).unwrap(),
                &packet,
                backend,
                1,
                DEFAULT_PACKET_OBSERVATION_SNAPSHOT_BYTE_LIMIT,
            )
            .unwrap(),
            expected
        );
        assert_eq!(image(&store), before);

        // Only the ordinary writer still performs its established recovery.
        let recovered = writer(&store, backend);
        assert_eq!(recovered.stats().unwrap()["tip"], hex::encode(id));
        assert_eq!(recovered.stats().unwrap()["generation"], 1);
    }
}

#[test]
fn packet_status_cli_refuses_unfinished_native_reorg_without_recovering() {
    for backend in BACKENDS {
        let temp = tempfile::tempdir().unwrap();
        let store = temp.path().join("store");
        let packet = golden();
        let input = packet_file(temp.path(), &packet);
        let mut owner = writer(&store, backend);
        let id = owner.admit(&packet, CLOCK).unwrap();
        let mut at_intent = false;
        let error = owner
            .activate_with_fault(
                id,
                Some(&mut |point| {
                    if point == "intent" {
                        at_intent = true;
                        Err("PACKET_OBSERVER_TEST_CUT".into())
                    } else {
                        Ok(())
                    }
                }),
            )
            .unwrap_err();
        assert!(at_intent);
        assert_eq!(error.to_string(), "PACKET_OBSERVER_TEST_CUT");
        drop(owner);
        assert!(!store.join("native.sqlite-wal").exists());
        assert!(!store.join("native.sqlite-shm").exists());

        let before = image(&store);
        rejected(
            command(&store, &input, backend).output().unwrap(),
            "REORG_IN_PROGRESS",
        );
        assert_eq!(image(&store), before);
        assert_eq!(
            writer(&store, backend).stats().unwrap()["tip"],
            hex::encode(id)
        );
    }
}

#[test]
fn packet_status_cli_decodes_all_completed_reorg_fields_like_the_original_writer() {
    for backend in BACKENDS {
        for corruption in [
            "UPDATE reorg SET generation=-1 WHERE singleton=1",
            "UPDATE reorg SET cursor=-1 WHERE singleton=1",
            "UPDATE reorg SET generation='not-an-integer' WHERE singleton=1",
            "UPDATE reorg SET cursor='not-an-integer' WHERE singleton=1",
            "UPDATE reorg SET old_tip='not-a-blob' WHERE singleton=1",
            "UPDATE reorg SET new_tip='not-a-blob' WHERE singleton=1",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let store = temp.path().join("store");
            let packet = golden();
            let input = packet_file(temp.path(), &packet);
            let mut owner = writer(&store, backend);
            let id = owner.admit(&packet, CLOCK).unwrap();
            let mut published = false;
            // An actual native journaled activation, not a fabricated reorg row.
            owner
                .activate_with_fault(
                    id,
                    Some(&mut |point| {
                        if point == "published" {
                            published = true;
                        }
                        Ok(())
                    }),
                )
                .unwrap();
            assert!(published);
            drop(owner);

            // Corrupt the real, closed completed journal through SQLite. Its
            // DDL permits these values, so typed cold-open checks must refuse.
            let database = rusqlite::Connection::open(store.join("native.sqlite")).unwrap();
            let done: u64 = database
                .query_row("SELECT done FROM reorg WHERE singleton=1", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(done, 1);
            assert_eq!(database.execute(corruption, []).unwrap(), 1);
            database.close().unwrap();
            assert!(!store.join("native.sqlite-wal").exists());
            assert!(!store.join("native.sqlite-shm").exists());

            let expected_error = writer_result(&store, backend)
                .err()
                .expect("the ordinary writer must reject the corrupted completed row")
                .to_string();
            let before = image(&store);
            rejected(
                command(&store, &input, backend).output().unwrap(),
                &expected_error,
            );
            assert_eq!(image(&store), before, "{corruption}");
        }
    }
}

#[test]
fn packet_status_cli_preserves_recovery_candidate_checks_for_an_unrelated_query() {
    for backend in BACKENDS {
        for corruption in [
            "UPDATE blocks SET id=X'00' WHERE height=1",
            "UPDATE blocks SET id='not-a-blob' WHERE height=1",
            "UPDATE blocks SET height=-1 WHERE height=1",
            "UPDATE blocks SET chainwork=X'FF' WHERE height=1",
            "UPDATE active SET generation=9223372036854775807 WHERE singleton=1",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let store = temp.path().join("store");
            let packet = golden();
            let mut unrelated = packet.clone();
            unrelated.header.nonce = unrelated.header.nonce.wrapping_add(1);
            assert_ne!(unrelated.id().unwrap(), packet.id().unwrap());
            let input = packet_file(temp.path(), &unrelated);
            let mut owner = writer(&store, backend);
            owner.admit(&packet, CLOCK).unwrap();
            assert_eq!(
                owner.exact_packet_observation(&unrelated).unwrap()["stored_exact"],
                false
            );
            drop(owner);

            let database = rusqlite::Connection::open(store.join("native.sqlite")).unwrap();
            database.pragma_update(None, "foreign_keys", false).unwrap();
            assert_eq!(database.execute(corruption, []).unwrap(), 1);
            database.close().unwrap();
            assert!(!store.join("native.sqlite-wal").exists());
            assert!(!store.join("native.sqlite-shm").exists());

            let expected_error = writer_result(&store, backend)
                .err()
                .expect("the original recovery prefix must reject the malformed candidate")
                .to_string();
            let before = image(&store);
            rejected(
                command(&store, &input, backend).output().unwrap(),
                &expected_error,
            );
            assert_eq!(image(&store), before, "{corruption}");
        }
    }
}

#[test]
fn packet_status_cli_refuses_the_live_owner_without_touching_its_files() {
    for backend in BACKENDS {
        let temp = tempfile::tempdir().unwrap();
        let store = temp.path().join("store");
        let input = packet_file(temp.path(), &golden());
        let owner = writer(&store, backend);
        let before = image(&store);
        rejected(
            command(&store, &input, backend).output().unwrap(),
            "WRITER_BUSY",
        );
        assert_eq!(image(&store), before);
        assert_eq!(owner.stats().unwrap()["height"], 0);
    }
}

#[test]
fn packet_status_cli_refuses_recovery_and_owner_markers_without_sqlite_cleanup() {
    for backend in BACKENDS {
        let temp = tempfile::tempdir().unwrap();
        let store = temp.path().join("store");
        let input = packet_file(temp.path(), &golden());
        drop(writer(&store, backend));
        for (name, code) in [
            ("initializing.json", "GROWTH_OBSERVATION_RECOVERY_REQUIRED"),
            ("native.sqlite-wal", "GROWTH_OBSERVATION_RECOVERY_REQUIRED"),
            ("native.sqlite-shm", "GROWTH_OBSERVATION_RECOVERY_REQUIRED"),
            (
                "native.sqlite-journal",
                "GROWTH_OBSERVATION_RECOVERY_REQUIRED",
            ),
            (
                "authenticated-migration.pending",
                "NATIVE_STATE_MIGRATION_PENDING",
            ),
            ("owner-task-policy.required", "OWNER_TASK_POLICY_REQUIRED"),
        ] {
            let marker = store.join(name);
            fs::write(&marker, b"unresolved original owner state\n").unwrap();
            let before = image(&store);
            rejected(command(&store, &input, backend).output().unwrap(), code);
            assert_eq!(image(&store), before);
            fs::remove_file(marker).unwrap();
        }
    }
}

#[test]
fn packet_status_cli_never_creates_a_store_or_recreates_a_missing_owner_lock() {
    for backend in BACKENDS {
        let temp = tempfile::tempdir().unwrap();
        let store = temp.path().join("store");
        let input = packet_file(temp.path(), &golden());
        rejected(
            command(&store, &input, backend).output().unwrap(),
            "PACKET_STATUS_EXISTING_STORE_REQUIRED",
        );
        assert!(!store.exists());

        drop(writer(&store, backend));
        fs::remove_file(store.join("owner.lock")).unwrap();
        let before = image(&store);
        let output = command(&store, &input, backend).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(image(&store), before);
        assert!(!store.join("owner.lock").exists());
    }
}

#[test]
fn packet_status_cli_preserves_context_exact_bytes_and_snapshot_budget() {
    for backend in BACKENDS {
        let temp = tempfile::tempdir().unwrap();
        let store = temp.path().join("store");
        let packet = golden();
        let input = packet_file(temp.path(), &packet);
        let mut owner = writer(&store, backend);
        owner.admit(&packet, CLOCK).unwrap();
        drop(owner);
        let before = image(&store);
        let other = match backend {
            PacketObservationBackend::LegacyV2 => PacketObservationBackend::AuthenticatedV1,
            PacketObservationBackend::AuthenticatedV1 => PacketObservationBackend::LegacyV2,
        };
        rejected(command(&store, &input, other).output().unwrap(), "SCHEMA");
        assert_eq!(image(&store), before);
        rejected(
            command(&store, &input, backend)
                .args(["--workers", "3"])
                .output()
                .unwrap(),
            "WORKERS",
        );
        assert_eq!(image(&store), before);
        rejected(
            command(&store, &input, backend)
                .args(["--genesis-time", "1"])
                .output()
                .unwrap(),
            "STORAGE_CONTEXT",
        );
        assert_eq!(image(&store), before);

        let mut wrong = packet.clone();
        wrong.proof[100] ^= 1;
        assert_eq!(wrong.id().unwrap(), packet.id().unwrap());
        let wrong_input = temp.path().join("wrong.packet");
        fs::write(&wrong_input, wrong.encode().unwrap()).unwrap();
        rejected(
            command(&store, &wrong_input, backend).output().unwrap(),
            "DUPLICATE_CONTENT",
        );
        assert_eq!(image(&store), before);

        let length = fs::metadata(store.join("native.sqlite")).unwrap().len();
        assert_eq!(
            observe_existing_packet(
                &store,
                Settings::development(None).unwrap(),
                &packet,
                backend,
                1,
                length - 1,
            )
            .unwrap_err()
            .to_string(),
            "GROWTH_OBSERVATION_SNAPSHOT_LIMIT"
        );
        assert_eq!(image(&store), before);
    }
}

#[test]
fn packet_status_cli_absence_is_local_only_and_does_not_execute() {
    for backend in BACKENDS {
        let temp = tempfile::tempdir().unwrap();
        let store = temp.path().join("store");
        let packet = golden();
        let input = packet_file(temp.path(), &packet);
        drop(writer(&store, backend));
        let before = image(&store);
        let observed = accepted(command(&store, &input, backend).output().unwrap());
        assert_eq!(observed["stored_exact"], false);
        assert_eq!(observed["active_chain_member"], false);
        assert_eq!(observed["generation"], 0);
        assert_eq!(observed["local_target_only"], true);
        for authority in [
            "global_absence_authority",
            "confirmation_authority",
            "finality_authority",
            "execution_authority",
            "production_activation",
        ] {
            assert_eq!(observed[authority], false, "{authority}");
        }
        assert_eq!(image(&store), before);
    }
}

#[test]
fn packet_status_budget_and_worker_options_refuse_before_touching_source() {
    for backend in BACKENDS {
        let temp = tempfile::tempdir().unwrap();
        let store = temp.path().join("store");
        let packet = golden();
        let input = packet_file(temp.path(), &packet);
        // Keep the actual owner alive. Budget/worker validation must precede
        // even attempts to acquire its lock or inspect private stored state.
        let owner = writer(&store, backend);
        let before = image(&store);
        for (flag, value, code) in [
            (
                "--observation-cpu-seconds",
                "0",
                "PACKET_OBSERVATION_BUDGET",
            ),
            (
                "--observation-cpu-seconds",
                "31",
                "PACKET_OBSERVATION_BUDGET",
            ),
            (
                "--observation-cpu-seconds",
                "-1",
                "PACKET_OBSERVATION_BUDGET",
            ),
            (
                "--observation-wall-seconds",
                "0",
                "PACKET_OBSERVATION_BUDGET",
            ),
            (
                "--observation-wall-seconds",
                "121",
                "PACKET_OBSERVATION_BUDGET",
            ),
            (
                "--packet-observer-worker",
                "invalid",
                "PACKET_OBSERVATION_WORKER",
            ),
        ] {
            rejected(
                command(&store, &input, backend)
                    .args([flag, value])
                    .output()
                    .unwrap(),
                code,
            );
            assert_eq!(image(&store), before);
        }
        drop(owner);
        let before = image(&store);
        // These are local reader budgets. They must never cause a remote
        // reconciliation call to take a different transport/authority path.
        rejected(
            command(&store, &input, backend)
                .args(["--peer", "127.0.0.1:1", "--observation-cpu-seconds", "1"])
                .output()
                .unwrap(),
            "PACKET_OBSERVATION_LOCAL_ONLY",
        );
        assert_eq!(image(&store), before);
    }
}
