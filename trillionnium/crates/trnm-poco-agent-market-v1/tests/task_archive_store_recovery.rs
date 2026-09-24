//! Process-loss, reopen, and concurrent-writer evidence for the candidate
//! proof-preserving TaskV1 archive owner.
//!
//! These tests exercise the public storage boundary only.  They do not claim
//! consensus finality, independent custody, or production activation.

use std::{
    collections::BTreeSet,
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use tempfile::tempdir;
use trnm_poco_agent_market_v1::{
    plan_task_archive_pruning_v1, verify_task_archive_batch_v1, verify_task_archive_inclusion_v1,
    AgentMarketErrorCodeV1, Hash32V1, ProtocolContextV1, TaskArchiveBatchV1, TaskArchivePolicyV1,
    TaskArchiveStoreV1, TaskIdV1, TerminalTaskArchiveRecordV1, TASK_ARCHIVE_SCHEMA_VERSION_V1,
};

const CHILD_ENV: &str = "TRNM_TASK_ARCHIVE_SIGKILL_CHILD";
const CHILD_STORE_ENV: &str = "TRNM_TASK_ARCHIVE_SIGKILL_STORE";
const CHILD_MARKER_ENV: &str = "TRNM_TASK_ARCHIVE_SIGKILL_MARKER";

fn context() -> ProtocolContextV1 {
    ProtocolContextV1 {
        genesis_hash: Hash32V1([0x11; 32]),
        chain_id: "trnm-task-archive-store-recovery".to_string(),
        protocol_version: 1,
        stack_profile_hash: Hash32V1([0x22; 32]),
    }
}

fn policy() -> TaskArchivePolicyV1 {
    TaskArchivePolicyV1 {
        schema_version: TASK_ARCHIVE_SCHEMA_VERSION_V1,
        context: context(),
        minimum_terminal_retention_blocks: 5,
        maximum_live_terminal_records: 1,
        maximum_live_terminal_bytes: 100,
        maximum_archive_batch_records: 8,
        maximum_archive_batch_bytes: 800,
        retention_charge_units_per_byte_block: 2,
    }
}

fn record(id: u8) -> TerminalTaskArchiveRecordV1 {
    TerminalTaskArchiveRecordV1 {
        schema_version: TASK_ARCHIVE_SCHEMA_VERSION_V1,
        context: context(),
        task_id: TaskIdV1([id; 32]),
        terminal_height: u64::from(id),
        task_revision: u64::from(id),
        terminal_state_digest: Hash32V1([id.wrapping_add(1); 32]),
        terminal_receipt_digest: Hash32V1([id.wrapping_add(2); 32]),
        evidence_root: Hash32V1([id.wrapping_add(3); 32]),
        encoded_bytes: 100,
        retention_paid_through_height: u64::from(id) + 4,
        retention_charge_paid: 1_000,
    }
}

fn batch() -> (
    TaskArchivePolicyV1,
    Vec<TerminalTaskArchiveRecordV1>,
    TaskArchiveBatchV1,
) {
    let policy = policy();
    let records = vec![record(1), record(2), record(3)];
    let plan = plan_task_archive_pruning_v1(
        &policy,
        &records,
        &BTreeSet::new(),
        20,
        1,
        Hash32V1([0; 32]),
    )
    .expect("archive plan");
    (
        policy,
        records,
        plan.archive_batch().expect("archive pressure").clone(),
    )
}

fn remove_sqlite_artifacts(path: &Path) {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let candidate = PathBuf::from(format!("{}{}", path.display(), suffix));
        let _ = fs::remove_file(candidate);
    }
}

fn child_process_loss(path: &Path, marker: &Path) -> ! {
    let (policy, records, batch) = batch();
    let store = TaskArchiveStoreV1::open_existing(path, policy).expect("child opens store");
    store
        .archive_and_delete_v1(&batch)
        .expect("child commits archive deletion");
    fs::write(marker, b"committed").expect("commit marker");
    let _ = records;
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}

#[test]
#[cfg(unix)]
fn archive_store_process_loss_after_commit_reopens_and_retries_exact_batch() {
    if env::var_os(CHILD_ENV).is_some() {
        let path = PathBuf::from(env::var_os(CHILD_STORE_ENV).expect("child store"));
        let marker = PathBuf::from(env::var_os(CHILD_MARKER_ENV).expect("child marker"));
        child_process_loss(&path, &marker);
    }

    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("archive-sigkill.sqlite");
    let marker = directory.path().join("archive-sigkill.marker");
    let (policy, records, batch) = batch();
    let store = TaskArchiveStoreV1::initialize(&path, policy.clone()).expect("initialize");
    store
        .install_live_records_v1(&records, 20)
        .expect("install live inventory");
    let plan = plan_task_archive_pruning_v1(
        &policy,
        &records,
        &BTreeSet::new(),
        20,
        1,
        Hash32V1([0; 32]),
    )
    .expect("rebuild plan");
    assert_eq!(plan.archive_batch().expect("batch"), &batch);

    let mut child = Command::new(env::current_exe().expect("test executable"))
        .arg("--exact")
        .arg("archive_store_process_loss_after_commit_reopens_and_retries_exact_batch")
        .arg("--nocapture")
        .env(CHILD_ENV, "1")
        .env(CHILD_STORE_ENV, &path)
        .env(CHILD_MARKER_ENV, &marker)
        .spawn()
        .expect("spawn child");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !marker.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    assert!(
        marker.exists(),
        "child did not acknowledge committed deletion"
    );
    child.kill().expect("SIGKILL child");
    let status = child.wait().expect("child status");
    assert!(!status.success(), "child unexpectedly exited before kill");

    let reopened =
        TaskArchiveStoreV1::open_existing(&path, policy.clone()).expect("reopen after kill");
    let archived = reopened
        .read_archive_batch_v1(1)
        .expect("committed batch survives");
    verify_task_archive_batch_v1(&policy, &archived).expect("archived batch verifies");
    for record in &archived.records {
        let proof = archived
            .inclusion_proof(&policy, record.task_id)
            .expect("inclusion proof");
        verify_task_archive_inclusion_v1(&archived.seal, record, &proof)
            .expect("inclusion proof verifies");
    }
    assert_eq!(archived, batch);
    let first_retry = reopened
        .archive_and_delete_v1(&batch)
        .expect("exact retry after process loss");
    assert_eq!(first_retry.deleted_record_count, batch.seal.record_count);
    assert_eq!(
        reopened
            .archive_and_delete_v1(&batch)
            .expect("idempotent retry"),
        first_retry
    );
    remove_sqlite_artifacts(&path);
}

#[test]
fn archive_store_concurrent_same_batch_has_one_commit_and_no_partial_delete() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("archive-concurrent.sqlite");
    let (policy, records, batch) = batch();
    let store = TaskArchiveStoreV1::initialize(&path, policy.clone()).expect("initialize");
    store
        .install_live_records_v1(&records, 20)
        .expect("install live inventory");
    let path = Arc::new(path);
    let batch = Arc::new(batch);
    let mut workers = Vec::new();
    for _ in 0..8 {
        let path = Arc::clone(&path);
        let batch = Arc::clone(&batch);
        let policy = policy.clone();
        workers.push(thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let result = TaskArchiveStoreV1::open_existing(path.as_ref(), policy.clone())
                    .and_then(|store| store.archive_and_delete_v1(batch.as_ref()));
                match result {
                    Ok(receipt) => break Ok(receipt),
                    Err(error)
                        if matches!(
                            error.code(),
                            AgentMarketErrorCodeV1::SidecarPresent
                                | AgentMarketErrorCodeV1::StoreFailure
                        ) && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => break Err(error),
                }
            }
        }));
    }
    let results = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker join"))
        .collect::<Vec<_>>();
    let receipts = results
        .into_iter()
        .map(|result| result.expect("concurrent archive retry"))
        .collect::<Vec<_>>();
    assert!(receipts.windows(2).all(|pair| pair[0] == pair[1]));
    let reopened =
        TaskArchiveStoreV1::open_existing(path.as_path(), policy.clone()).expect("reopen");
    assert_eq!(reopened.read_archive_batch_v1(1).expect("archive"), *batch);
    // The first receipt is the durable post-state root.  The archived proof
    // and this exact root together detect a partial move or duplicate delete.
    assert_eq!(
        reopened.live_root_v1().expect("live root"),
        receipts[0].live_root_after
    );
    remove_sqlite_artifacts(path.as_ref());
}
