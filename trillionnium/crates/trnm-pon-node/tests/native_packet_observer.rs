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

fn resource_profile() -> trnm_pon_node::resource_owner_v1::ResourceProfileV1 {
    use trnm_pon_node::resource_owner_v1::{ResourceProfileV1, ResourcesV1};
    ResourceProfileV1 {
        owner_id: [71; 32],
        grants: [ResourcesV1 {
            cpu_ns: 60_000_000_000,
            io_bytes: 4 * 1024 * 1024 * 1024,
        }; 3],
        max_operations: [16; 3],
        max_inflight: [4; 3],
        overshoot: ResourcesV1 {
            cpu_ns: 1_000_000_000,
            io_bytes: 131_072,
        },
    }
}

fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}

fn resource_contract(
    packet: &Packet,
    backend: PacketObservationBackend,
    operation: u8,
    parent: [u8; 32],
) -> trnm_pon_node::PacketObservationResourceContractV1 {
    use sha2::{Digest, Sha256};
    trnm_pon_node::PacketObservationResourceContractV1 {
        profile_id: resource_profile().id().unwrap(),
        operation_id: [operation; 32],
        packet_sha256: Sha256::digest(packet.encode().unwrap()).into(),
        parent_state: parent,
        deadline_unix_ms: wall_ms() + 30_000,
        backend,
        workers: 1,
        snapshot_byte_limit: 64 * 1024 * 1024,
        cpu_seconds: 5,
        wall_seconds: 30,
        logical_now: Some(CLOCK),
    }
}

fn owned_command(
    store: &Path,
    input: &Path,
    contract: &trnm_pon_node::PacketObservationResourceContractV1,
) -> Command {
    let mut call = command(store, input, contract.backend);
    call.args([
        "--observation-resource-profile-sha256",
        &hex::encode(contract.profile_id),
        "--observation-operation-id",
        &hex::encode(contract.operation_id),
        "--observation-parent-state",
        &hex::encode(contract.parent_state),
        "--observation-deadline-unix-ms",
        &contract.deadline_unix_ms.to_string(),
        "--observation-packet-sha256",
        &hex::encode(contract.packet_sha256),
        "--observation-cpu-seconds",
        &contract.cpu_seconds.to_string(),
        "--observation-wall-seconds",
        &contract.wall_seconds.to_string(),
        "--observation-snapshot-bytes",
        &contract.snapshot_byte_limit.to_string(),
        "--workers",
        &contract.workers.to_string(),
    ]);
    call
}

fn source_without_resource_journal(store: &Path) -> NamespaceImage {
    let mut state = image(store);
    state.files.remove(&OsString::from(
        trnm_pon_node::resource_owner_v1::JOURNAL_NAME,
    ));
    state
}

#[test]
fn explicit_resource_owner_initialization_is_pinned_and_never_replaces_an_account() {
    use sha2::{Digest, Sha256};
    use trnm_pon_node::resource_owner_v1::ResourceOwnerV1;
    let temp = tempfile::tempdir().unwrap();
    let store = temp.path().join("store");
    drop(writer(&store, PacketObservationBackend::LegacyV2));
    let profile = resource_profile();
    let raw = serde_json::to_vec(&profile).unwrap();
    let profile_path = temp.path().join("resource-profile.json");
    fs::write(&profile_path, &raw).unwrap();
    let invoke = |pin: &str| {
        Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"))
            .args(["resource-owner-init", "--development", "--store"])
            .arg(&store)
            .arg("--resource-profile")
            .arg(&profile_path)
            .args(["--resource-profile-sha256", pin])
            .output()
            .unwrap()
    };
    rejected(
        invoke(&hex::encode([0; 32])),
        "RESOURCE_OWNER_PROFILE_FILE_HASH",
    );
    assert!(!ResourceOwnerV1::is_present(&store).unwrap());
    let pin = hex::encode(Sha256::digest(&raw));
    let output = invoke(&pin);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let initialized: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        initialized["resource_profile"],
        hex::encode(profile.id().unwrap())
    );
    let before = image(&store);
    assert!(!invoke(&pin).status.success());
    assert_eq!(image(&store), before);
}

#[test]
fn adopted_observer_settles_original_principal_and_retry_only_reads_original_status() {
    use trnm_pon_node::resource_owner_v1::{ChargeV1, OperationStateV1, ResourceOwnerV1};
    for backend in BACKENDS {
        let temp = tempfile::tempdir().unwrap();
        let store = temp.path().join("store");
        let node = writer(&store, backend);
        let parent = node.active().unwrap().0;
        drop(node);
        let owner = ResourceOwnerV1::initialize(&store, &resource_profile()).unwrap();
        let packet = golden();
        let input = packet_file(temp.path(), &packet);
        let contract = resource_contract(&packet, backend, 72, parent);
        let before = source_without_resource_journal(&store);
        let output = owned_command(&store, &input, &contract).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["result"]["native_source_unchanged"], true);
        assert_eq!(
            value["result"]["source_scope"],
            serde_json::json!(["native.sqlite", "owner.lock"])
        );
        assert_eq!(value["resource_settlement"]["actual_cpu_measured"], false);
        let record = owner.observe(contract.operation_id).unwrap().unwrap();
        assert_eq!(record.state, OperationStateV1::Settled);
        assert_eq!(record.charge, Some(ChargeV1::Conservative));
        let snapshot = owner.snapshot().unwrap();
        assert_eq!(snapshot.lanes[0].unresolved_operations, 0);
        assert_eq!(snapshot.lanes[0].retained_operations, 1);
        let retry = owned_command(&store, &input, &contract).output().unwrap();
        assert!(retry.status.success());
        let retry: Value = serde_json::from_slice(&retry.stdout).unwrap();
        assert_eq!(retry["dispatched"], false);
        assert_eq!(retry["safe_retry_authorized"], false);
        assert_eq!(owner.snapshot().unwrap().record_hash, snapshot.record_hash);
        assert_eq!(source_without_resource_journal(&store), before);
    }
}

#[test]
fn adopted_store_requires_claimed_profile_for_cli_internal_worker_and_library() {
    use trnm_pon_node::resource_owner_v1::{AdmissionV1, OperationStateV1, ResourceOwnerV1};
    for backend in BACKENDS {
        let temp = tempfile::tempdir().unwrap();
        let store = temp.path().join("store");
        let node = writer(&store, backend);
        let parent = node.active().unwrap().0;
        drop(node);
        let owner = ResourceOwnerV1::initialize(&store, &resource_profile()).unwrap();
        let packet = golden();
        let input = packet_file(temp.path(), &packet);
        let before = source_without_resource_journal(&store);
        rejected(
            command(&store, &input, backend).output().unwrap(),
            "PACKET_OBSERVATION_RESOURCE_PROFILE_REQUIRED",
        );
        rejected(
            command(&store, &input, backend)
                .args(["--packet-observer-worker", "v1"])
                .output()
                .unwrap(),
            "PACKET_OBSERVATION_RESOURCE_PROFILE_REQUIRED",
        );
        assert!(observe_existing_packet(
            &store,
            Settings::development(None).unwrap(),
            &packet,
            backend,
            1,
            DEFAULT_PACKET_OBSERVATION_SNAPSHOT_BYTE_LIMIT
        )
        .unwrap_err()
        .to_string()
        .contains("PACKET_OBSERVATION_RESOURCE_PROFILE_REQUIRED"));
        let contract = resource_contract(&packet, backend, 73, parent);
        let request = contract
            .request(&Settings::development(None).unwrap())
            .unwrap();
        let guard = match owner.reserve(&request, wall_ms()).unwrap() {
            AdmissionV1::Fresh(guard) => guard,
            AdmissionV1::Existing(_) => panic!("new operation required"),
        };
        assert!(trnm_pon_node::observe_existing_packet_owned(
            &store,
            Settings::development(None).unwrap(),
            &packet.encode().unwrap(),
            &contract,
            guard
        )
        .unwrap_err()
        .to_string()
        .contains("RESOURCE_OWNER_NATIVE_CLAIM_REQUIRED"));
        assert_eq!(
            owner.observe(contract.operation_id).unwrap().unwrap().state,
            OperationStateV1::Reserved
        );
        assert_eq!(source_without_resource_journal(&store), before);
    }
}

#[test]
fn owned_packet_byte_mismatch_keeps_reservation_and_never_dispatches() {
    use trnm_pon_node::resource_owner_v1::{OperationStateV1, ResourceOwnerV1};
    let temp = tempfile::tempdir().unwrap();
    let store = temp.path().join("store");
    let node = writer(&store, PacketObservationBackend::LegacyV2);
    let parent = node.active().unwrap().0;
    drop(node);
    let owner = ResourceOwnerV1::initialize(&store, &resource_profile()).unwrap();
    let packet = golden();
    let input = packet_file(temp.path(), &packet);
    let mut contract = resource_contract(&packet, PacketObservationBackend::LegacyV2, 74, parent);
    contract.packet_sha256 = [75; 32];
    let before = source_without_resource_journal(&store);
    rejected(
        owned_command(&store, &input, &contract).output().unwrap(),
        "PACKET_OBSERVATION_PACKET_BINDING",
    );
    let record = owner.observe(contract.operation_id).unwrap().unwrap();
    assert_eq!(record.state, OperationStateV1::Reserved);
    assert!(record.charge.is_none());
    assert_eq!(owner.snapshot().unwrap().lanes[0].unresolved_operations, 1);
    assert_eq!(source_without_resource_journal(&store), before);
}

#[test]
fn owned_worker_claim_is_once_only_and_parent_mismatch_keeps_original_hold() {
    use trnm_pon_node::resource_owner_v1::{OperationStateV1, ResourceOwnerV1};
    let temp = tempfile::tempdir().unwrap();
    let store = temp.path().join("store");
    drop(writer(&store, PacketObservationBackend::LegacyV2));
    let owner = ResourceOwnerV1::initialize(&store, &resource_profile()).unwrap();
    let packet = golden();
    let input = packet_file(temp.path(), &packet);
    let contract = resource_contract(&packet, PacketObservationBackend::LegacyV2, 76, [77; 32]);
    let request = contract
        .request(&Settings::development(None).unwrap())
        .unwrap();
    let before = source_without_resource_journal(&store);
    rejected(
        owned_command(&store, &input, &contract)
            .args(["--packet-observer-worker", "resource-owner-v1"])
            .output()
            .unwrap(),
        "RESOURCE_OWNER_OPERATION",
    );
    assert_eq!(owner.snapshot().unwrap().lanes[0].retained_operations, 0);
    drop(owner.reserve(&request, wall_ms()).unwrap());
    rejected(
        owned_command(&store, &input, &contract)
            .args(["--packet-observer-worker", "resource-owner-v1"])
            .output()
            .unwrap(),
        "PACKET_OBSERVATION_PARENT_STATE",
    );
    assert_eq!(
        owner.observe(contract.operation_id).unwrap().unwrap().state,
        OperationStateV1::Running
    );
    rejected(
        owned_command(&store, &input, &contract)
            .args(["--packet-observer-worker", "resource-owner-v1"])
            .output()
            .unwrap(),
        "RESOURCE_OWNER_ALREADY_CLAIMED",
    );
    assert_eq!(owner.snapshot().unwrap().lanes[0].unresolved_operations, 1);
    assert_eq!(source_without_resource_journal(&store), before);
}
