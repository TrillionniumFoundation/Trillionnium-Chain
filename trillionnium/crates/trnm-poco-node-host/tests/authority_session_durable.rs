#![cfg(feature = "persistent-authority-candidate")]

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use tempfile::tempdir;
use trnm_node_boundary_v0::{
    AuthorityCommandV0, AuthorityCoordinatorV0, AuthorityReceiptV0, AuthorityStageV0,
    BoundIngressV0, BoundaryErrorV0, Digest32V0, IngressFrameV0, NodeIdentityV0,
    RecoveryDispositionV0,
};
use trnm_poco_node_authority::{NodeAuthorityCoordinatorV0, NodeAuthorityErrorV0};
use trnm_poco_node_production_v0::{AuthoritySessionReadinessV0, ProductionAuthoritySessionV0};

const CHILD_ENV: &str = "TRNM_AUTHORITY_SESSION_PROCESS_HELPER";
const ROOT_ENV: &str = "TRNM_AUTHORITY_SESSION_ROOT";
const MARKER_ENV: &str = "TRNM_AUTHORITY_SESSION_MARKER";
const STEP_ENV: &str = "TRNM_AUTHORITY_SESSION_STEP";

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

fn ingress(height: u64, block: u8, parent: u8, replay_nonce: u64, payload: u8) -> BoundIngressV0 {
    let frame = IngressFrameV0::new(
        digest(payload.wrapping_add(1)),
        digest(payload.wrapping_add(2)),
        replay_nonce,
        vec![payload],
    )
    .unwrap();
    BoundIngressV0::derive(
        identity(),
        height,
        height,
        digest(block),
        digest(parent),
        frame,
    )
    .unwrap()
}

fn first_ingress() -> BoundIngressV0 {
    ingress(1, 10, 9, 1, 20)
}

fn second_ingress() -> BoundIngressV0 {
    ingress(2, 11, 10, 2, 21)
}

fn all_ingresses() -> Vec<BoundIngressV0> {
    vec![first_ingress(), second_ingress()]
}

struct NodeAuthorityAdapter {
    inner: NodeAuthorityCoordinatorV0,
    ingresses: Vec<BoundIngressV0>,
}

impl NodeAuthorityAdapter {
    fn open(root: &Path) -> Result<Self, NodeAuthorityErrorV0> {
        fs::create_dir_all(root).map_err(NodeAuthorityErrorV0::RootIo)?;
        Ok(Self {
            inner: NodeAuthorityCoordinatorV0::open_candidate(root, identity())?,
            ingresses: all_ingresses(),
        })
    }

    fn current_receipt(&self) -> Option<AuthorityReceiptV0> {
        self.inner.current_receipt()
    }
}

impl AuthorityCoordinatorV0 for NodeAuthorityAdapter {
    type Error = NodeAuthorityErrorV0;

    fn identity(&self) -> NodeIdentityV0 {
        self.inner
            .identity()
            .expect("persistent node authority must retain its identity")
    }

    fn recover(&mut self) -> Result<RecoveryDispositionV0, Self::Error> {
        self.inner.recover()
    }

    fn apply(&mut self, command: AuthorityCommandV0) -> Result<AuthorityReceiptV0, Self::Error> {
        match command {
            AuthorityCommandV0::Begin {
                binding,
                ingress_digest,
            } => {
                let exact = self
                    .ingresses
                    .iter()
                    .find(|candidate| {
                        candidate.binding == binding && candidate.ingress_digest() == ingress_digest
                    })
                    .cloned()
                    .ok_or(NodeAuthorityErrorV0::Boundary(
                        BoundaryErrorV0::OperationBindingMismatch,
                    ))?;
                self.inner.prepare_bound_ingress(&exact)
            }
            AuthorityCommandV0::Advance {
                binding,
                expected_stage,
                next_stage,
                facts_digest,
            } => self
                .inner
                .advance_exact(binding, expected_stage, next_stage, facts_digest),
        }
    }
}

type Session = ProductionAuthoritySessionV0<
    NodeAuthorityAdapter,
    fn(&NodeAuthorityAdapter) -> Option<AuthorityReceiptV0>,
>;

fn reopen(root: &Path) -> Session {
    let adapter = NodeAuthorityAdapter::open(root).unwrap();
    let mut session =
        ProductionAuthoritySessionV0::new(adapter, NodeAuthorityAdapter::current_receipt).unwrap();
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

fn apply_step(session: &mut Session, step: u8) -> AuthorityReceiptV0 {
    let first = first_ingress();
    let second = second_ingress();
    match step {
        0 => session
            .begin_prepared(first.binding, first.ingress_digest())
            .unwrap(),
        1..=7 => {
            let (expected, next, facts) = successor(step);
            session
                .advance(first.binding, expected, next, facts)
                .unwrap()
        }
        8 => session
            .begin_prepared(second.binding, second.ingress_digest())
            .unwrap(),
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

#[test]
fn node_authority_and_complete_receipt_session_reopen_every_stage() {
    let directory = tempdir().unwrap();
    let root = directory.path().join("authority");
    let mut active = reopen(&root);

    let first = first_ingress();
    let mut receipt = active
        .begin_prepared(first.binding, first.ingress_digest())
        .unwrap();
    drop(active.into_coordinator());
    active = reopen(&root);
    assert_eq!(active.current_receipt(), Some(receipt));

    for step in 1..=7 {
        let (expected, next, facts) = successor(step);
        receipt = active
            .advance(first.binding, expected, next, facts)
            .unwrap();
        drop(active.into_coordinator());
        active = reopen(&root);
        assert_eq!(active.current_receipt(), Some(receipt));
    }

    let second = second_ingress();
    let next = active
        .begin_prepared(second.binding, second.ingress_digest())
        .unwrap();
    drop(active.into_coordinator());
    let reopened = reopen(&root);
    assert_eq!(reopened.current_receipt(), Some(next));
    assert_eq!(next.durable_sequence, 8);
}

fn write_ready_marker(path: &Path, receipt: AuthorityReceiptV0) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    writeln!(
        file,
        "{} {:?}",
        receipt.durable_sequence, receipt.durable_stage
    )
    .unwrap();
    file.sync_all().unwrap();
    let parent = OpenOptions::new()
        .read(true)
        .open(path.parent().unwrap())
        .unwrap();
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
    assert!(
        !status.success(),
        "terminated helper unexpectedly succeeded"
    );
}

#[test]
fn every_stage_survives_process_termination_and_exact_replay() {
    let directory = tempdir().unwrap();
    let root = directory.path().join("authority");
    fs::create_dir(&root).unwrap();

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
    assert_eq!(final_receipt.binding, second_ingress().binding);
    assert_eq!(final_receipt.durable_stage, AuthorityStageV0::Prepared);
    assert_eq!(final_receipt.durable_sequence, 8);
}
