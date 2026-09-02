#![forbid(unsafe_code)]

use std::{
    convert::Infallible,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use trnm_durable_file_adapters_v0::FileAuthorityCoordinatorV0;
use trnm_node_boundary_v0::{
    AuthorityStageV0, BoundIngressV0, BoundaryErrorV0, Digest32V0, HostErrorV0,
    HostReadinessV0, IngressFrameV0, IoPollV0, IoRuntimeV0, NodeIdentityV0,
    OutboundFrameV0, PersistentValidatorHostV0, StepBudgetV0,
};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after the Unix epoch")
            .as_nanos();
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "trnm-{label}-{}-{timestamp}-{counter}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create private test directory");
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct NoopIo;

impl IoRuntimeV0 for NoopIo {
    type Error = Infallible;

    fn poll_ingress(&mut self, _budget: StepBudgetV0) -> Result<IoPollV0, Self::Error> {
        Ok(IoPollV0::Idle)
    }

    fn publish(
        &mut self,
        _frame: OutboundFrameV0,
        _budget: StepBudgetV0,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

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

fn bound_ingress() -> BoundIngressV0 {
    let frame = IngressFrameV0::new(digest(40), digest(41), 1, b"proposal-v0".to_vec())
        .expect("valid bounded ingress frame");
    BoundIngressV0::derive(
        identity(),
        10,
        2,
        digest(10),
        digest(9),
        frame,
    )
    .expect("valid frame-to-operation binding")
}

#[test]
fn prepared_receipt_survives_reopen_and_exact_replay() {
    let directory = TestDirectory::new("host-prepared-reopen");
    let ingress = bound_ingress();

    let first = {
        let coordinator =
            FileAuthorityCoordinatorV0::open(&directory.0, identity()).expect("open authority");
        let mut host =
            PersistentValidatorHostV0::new(coordinator, NoopIo, StepBudgetV0::default())
                .expect("construct host");
        assert_eq!(
            host.recover().expect("recover clean authority"),
            HostReadinessV0::Ready
        );
        let receipt = host
            .prepare_bound_ingress(&ingress)
            .expect("persist Prepared authority record");
        assert_eq!(receipt.binding, ingress.binding);
        assert_eq!(receipt.durable_stage, AuthorityStageV0::Prepared);
        assert_eq!(receipt.durable_sequence, 0);
        assert_eq!(receipt.facts_digest, ingress.ingress_digest());
        assert_ne!(receipt.record_digest, Digest32V0([0; 32]));
        receipt
    };

    let coordinator =
        FileAuthorityCoordinatorV0::open(&directory.0, identity()).expect("reopen authority");
    let mut host = PersistentValidatorHostV0::new(coordinator, NoopIo, StepBudgetV0::default())
        .expect("construct restarted host");
    assert_eq!(
        host.recover().expect("recover retained Prepared record"),
        HostReadinessV0::Ready
    );
    let replay = host
        .prepare_bound_ingress(&ingress)
        .expect("resolve response-loss replay from durable readback");
    assert_eq!(replay, first);

    let substituted = BoundIngressV0 {
        binding: ingress.binding,
        frame: IngressFrameV0::new(
            ingress.frame.peer_id,
            ingress.frame.profile_digest,
            ingress.frame.replay_nonce + 1,
            b"substituted-proposal".to_vec(),
        )
        .expect("bounded substituted frame"),
    };
    assert!(matches!(
        host.prepare_bound_ingress(&substituted),
        Err(HostErrorV0::Boundary(
            BoundaryErrorV0::OperationBindingMismatch
        ))
    ));

    let (coordinator, _) = host.into_parts();
    assert_eq!(coordinator.current_receipt(), Some(first));
}
