use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use tempfile::tempdir;
use trnm_durable_file_adapters_v0::FileAuthorityCoordinatorV0;
use trnm_node_boundary_v0::{
    AuthorityReceiptV0, AuthorityStageV0, Digest32V0, NodeIdentityV0, OperationBindingV0,
};
use trnm_poco_node_production_v0::{
    AuthoritySessionReadinessV0, ProductionAuthoritySessionV0,
};

const MAX_PAYLOAD_BYTES: usize = 16 * 1024;
const MAX_RECORDS: u64 = 64;
const CHILD_ENV: &str = "TRNM_AUTHORITY_SESSION_PROCESS_HELPER";
const ROOT_ENV: &str = "TRNM_AUTHORITY_SESSION_ROOT";
const MARKER_ENV: &str = "TRNM_AUTHORITY_SESSION_MARKER";
const STEP_ENV: &str = "TRNM_AUTHORITY_SESSION_STEP";

type DurableSession = ProductionAuthoritySessionV0<
    FileAuthorityCoordinatorV0,
    fn(&FileAuthorityCoordinatorV0) -> Option<AuthorityReceiptV0>,
>;

fn digest(byte: u8) -> Digest32V0 {
    Digest32V0([byte; 32])
}

fn identity() -> NodeIdentityV0 {
    NodeIdentityV0 {
        chain_id: digest(1),
        validator_id: digest(2),
        application_id: digest(3),
        generation: 1,
    }
}

fn binding(height: u64, block: u8, parent: u8) -> OperationBindingV0 {
    OperationBindingV0::derive(
        identity(),
        height,
        height,
        digest(block),
        digest(parent),
        digest(block.wrapping_add(40)),
        digest(block.wrapping_add(80)),
        digest(block.wrapping_add(120)),
    )
    .unwrap()
}

fn session(coordinator: FileAuthorityCoordinatorV0) -> DurableSession {
    ProductionAuthoritySessionV0::new(
        coordinator,
        FileAuthorityCoordinatorV0::current_receipt,
    )
    .unwrap()
}

fn reopen(root: &Path) -> DurableSession {
    let coordinator =
        FileAuthorityCoordinatorV0::open(root, identity(), MAX_PAYLOAD_BYTES, MAX_RECORDS).unwrap();
    let mut session = session(coordinator);
    assert_eq!(
        session.recover().unwrap(),
        AuthoritySessionReadinessV0::Ready
    );
    session
}

fn successor(step: u8) -> (AuthorityStageV0, AuthorityStageV0, Digest32V0) {
    match step {
        1 => (
            AuthorityStageV0::Prepared,
            AuthorityStageV0::ApplicationSealed,
            digest(31),
        ),
        2 => (
            AuthorityStageV0::ApplicationSealed,
            AuthorityStageV0::SafetyPersisted,
            digest(32),
        ),
        3 => (
            AuthorityStageV0::SafetyPersisted,
            AuthorityStageV0::SignIntentPersisted,
            digest(33),
        ),
        4 => (
            AuthorityStageV0::SignIntentPersisted,
            AuthorityStageV0::SignatureConfirmed,
            digest(34),
        ),
        5 => (
            AuthorityStageV0::SignatureConfirmed,
            AuthorityStageV0::FinalityApplied,
            digest(35),
        ),
        6 => (
            AuthorityStageV0::FinalityApplied,
            AuthorityStageV0::CheckpointConfirmed,
            digest(36),
        ),
        7 => (
            AuthorityStageV0::CheckpointConfirmed,
            AuthorityStageV0::OutboundPublished,
            digest(37),
        ),
        _ => panic!("invalid authority process step"),
    }
}

fn apply_step(session: &mut DurableSession, step: u8) -> AuthorityReceiptV0 {
    match step {
        0 => session.begin_prepared(binding(1, 10, 9), digest(20)).unwrap(),
        1..=7 => {
            let (expected, next, facts) = successor(step);
            session
                .advance(binding(1, 10, 9), expected, next, facts)
                .unwrap()
        }
        8 => session.begin_prepared(binding(2, 11, 10), digest(60)).unwrap(),
        _ => panic!("invalid authority process step"),
    }
}

fn expected_stage(step: u8) -> AuthorityStageV0 {
    match step {
        0 | 8 => AuthorityStageV0::Prepared,
        1..=7 => successor(step).1,
        _ => panic!("invalid authority process step"),
    }
}

fn write_ready_marker(path: &Path, receipt: AuthorityReceiptV0) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    writeln!(
        file,
        "{} {} {:?}",
        receipt.durable_sequence,
        hex::encode(receipt.record_digest.0),
        receipt.durable_stage
    )
    .unwrap();
    file.sync_all().unwrap();
    let parent = OpenOptions::new().read(true).open(path.parent().unwrap()).unwrap();
    parent.sync_all().unwrap();
}

#[test]
fn process_helper() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let root = PathBuf::from(std::env::var_os(ROOT_ENV).unwrap());
    let marker = PathBuf::from(std::env::var_os(MARKER_ENV).unwrap());
    let step = std::env::var(STEP_ENV).unwrap().parse::<u8>().unwrap();
    let mut active = reopen(&root);
    let receipt = apply_step(&mut active, step);
    write_ready_marker(&marker, receipt);
    thread::sleep(Duration::from_secs(30));
    panic!("parent did not terminate authority helper after durable marker");
}

fn kill_after_durable_marker(root: &Path, marker: &Path, step: u8) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("process_helper")
        .arg("--nocapture")
        .env(CHILD_ENV, "1")
        .env(ROOT_ENV, root)
        .env(MARKER_ENV, marker)
        .env(STEP_ENV, step.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(15);
    while !marker.is_file() {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("authority helper exited before durable marker: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "authority helper did not publish durable marker"
        );
        thread::sleep(Duration::from_millis(20));
    }

    child.kill().unwrap();
    let status = child.wait().unwrap();
    assert!(!status.success(), "terminated helper unexpectedly succeeded");
}

#[test]
fn every_stage_survives_process_termination_and_exact_replay() {
    let directory = tempdir().unwrap();
    let root = directory.path().join("authority");
    let coordinator =
        FileAuthorityCoordinatorV0::create(&root, identity(), MAX_PAYLOAD_BYTES, MAX_RECORDS)
            .unwrap();
    drop(coordinator);

    for step in 0..=8 {
        let marker = directory.path().join(format!("step-{step}.ready"));
        kill_after_durable_marker(&root, &marker, step);
        let mut recovered = reopen(&root);
        let durable = recovered.current_receipt().unwrap();
        assert_eq!(durable.durable_stage, expected_stage(step));
        let replayed = apply_step(&mut recovered, step);
        assert_eq!(replayed, durable);
        drop(recovered.into_coordinator());
        fs::remove_file(marker).unwrap();
    }

    let final_reopen = reopen(&root);
    let final_receipt = final_reopen.current_receipt().unwrap();
    assert_eq!(final_receipt.binding, binding(2, 11, 10));
    assert_eq!(final_receipt.durable_stage, AuthorityStageV0::Prepared);
    assert_eq!(final_receipt.durable_sequence, 8);
}
