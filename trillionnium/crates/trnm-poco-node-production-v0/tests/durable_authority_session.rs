use tempfile::tempdir;
use trnm_durable_file_adapters_v0::FileAuthorityCoordinatorV0;
use trnm_node_boundary_v0::{
    AuthorityCommandV0, AuthorityCoordinatorV0, AuthorityReceiptV0, AuthorityStageV0, Digest32V0,
    NodeIdentityV0, OperationBindingV0,
};
use trnm_poco_node_production_v0::{
    AuthoritySessionReadinessV0, ProductionAuthoritySessionV0,
};

const MAX_PAYLOAD_BYTES: usize = 16 * 1024;
const MAX_RECORDS: u64 = 64;

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

fn reopen(root: &std::path::Path) -> DurableSession {
    let coordinator =
        FileAuthorityCoordinatorV0::open(root, identity(), MAX_PAYLOAD_BYTES, MAX_RECORDS).unwrap();
    let mut session = session(coordinator);
    assert_eq!(
        session.recover().unwrap(),
        AuthoritySessionReadinessV0::Ready
    );
    session
}

#[test]
fn every_durable_stage_reopens_with_the_exact_complete_receipt() {
    let directory = tempdir().unwrap();
    let root = directory.path().join("authority");
    let coordinator =
        FileAuthorityCoordinatorV0::create(&root, identity(), MAX_PAYLOAD_BYTES, MAX_RECORDS)
            .unwrap();
    let mut active = session(coordinator);
    assert_eq!(
        active.recover().unwrap(),
        AuthoritySessionReadinessV0::Ready
    );

    let first = binding(1, 10, 9);
    let mut receipt = active.begin_prepared(first, digest(20)).unwrap();
    drop(active.into_coordinator());
    active = reopen(&root);
    assert_eq!(active.current_receipt(), Some(receipt));

    let successors = [
        AuthorityStageV0::ApplicationSealed,
        AuthorityStageV0::SafetyPersisted,
        AuthorityStageV0::SignIntentPersisted,
        AuthorityStageV0::SignatureConfirmed,
        AuthorityStageV0::FinalityApplied,
        AuthorityStageV0::CheckpointConfirmed,
        AuthorityStageV0::OutboundPublished,
    ];
    for (index, next) in successors.into_iter().enumerate() {
        let previous = receipt;
        receipt = active
            .advance(
                first,
                previous.durable_stage,
                next,
                digest(30 + u8::try_from(index).unwrap()),
            )
            .unwrap();
        assert_eq!(receipt.durable_sequence, previous.durable_sequence + 1);
        assert_ne!(receipt.record_digest, previous.record_digest);
        drop(active.into_coordinator());
        active = reopen(&root);
        assert_eq!(active.current_receipt(), Some(receipt));
    }

    let terminal = receipt;
    let second = binding(2, 11, 10);
    let prepared = active.begin_prepared(second, digest(60)).unwrap();
    assert_eq!(prepared.durable_stage, AuthorityStageV0::Prepared);
    assert_eq!(prepared.durable_sequence, terminal.durable_sequence + 1);
    assert_ne!(prepared.record_digest, terminal.record_digest);
    drop(active.into_coordinator());
    let reopened = reopen(&root);
    assert_eq!(reopened.current_receipt(), Some(prepared));
}

#[test]
fn durable_write_with_lost_response_recovers_and_replays_exactly() {
    let directory = tempdir().unwrap();
    let root = directory.path().join("authority");
    let mut coordinator =
        FileAuthorityCoordinatorV0::create(&root, identity(), MAX_PAYLOAD_BYTES, MAX_RECORDS)
            .unwrap();
    assert!(matches!(
        coordinator.recover().unwrap(),
        trnm_node_boundary_v0::RecoveryDispositionV0::Clean
    ));

    let first = binding(1, 10, 9);
    let applied_but_unobserved = coordinator
        .apply(AuthorityCommandV0::Begin {
            binding: first,
            ingress_digest: digest(20),
        })
        .unwrap();
    drop(coordinator);

    let mut recovered = reopen(&root);
    assert_eq!(recovered.current_receipt(), Some(applied_but_unobserved));
    let replayed = recovered.begin_prepared(first, digest(20)).unwrap();
    assert_eq!(replayed, applied_but_unobserved);

    drop(recovered.into_coordinator());
    let final_reopen = reopen(&root);
    assert_eq!(final_reopen.current_receipt(), Some(applied_but_unobserved));
}
