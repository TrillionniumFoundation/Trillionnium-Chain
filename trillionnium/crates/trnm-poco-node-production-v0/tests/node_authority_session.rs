use tempfile::tempdir;
use trnm_node_boundary_v0::{
    AuthorityReceiptV0, AuthorityStageV0, Digest32V0, NodeIdentityV0, OperationBindingV0,
};
use trnm_poco_node_authority::PersistentFileAuthorityCoordinatorV0;
use trnm_poco_node_production_v0::{
    AuthoritySessionReadinessV0, ProductionAuthoritySessionV0,
};

const MAX_PAYLOAD_BYTES: usize = 16 * 1024;
const MAX_RECORDS: u64 = 64;

type NodeAuthoritySession = ProductionAuthoritySessionV0<
    PersistentFileAuthorityCoordinatorV0,
    fn(&PersistentFileAuthorityCoordinatorV0) -> Option<AuthorityReceiptV0>,
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

fn session(coordinator: PersistentFileAuthorityCoordinatorV0) -> NodeAuthoritySession {
    ProductionAuthoritySessionV0::new(
        coordinator,
        PersistentFileAuthorityCoordinatorV0::current_receipt,
    )
    .unwrap()
}

fn reopen(root: &std::path::Path) -> NodeAuthoritySession {
    let coordinator = PersistentFileAuthorityCoordinatorV0::open(
        root,
        identity(),
        MAX_PAYLOAD_BYTES,
        MAX_RECORDS,
    )
    .unwrap();
    let mut session = session(coordinator);
    assert_eq!(
        session.recover().unwrap(),
        AuthoritySessionReadinessV0::Ready
    );
    session
}

#[test]
fn node_authority_wrapper_preserves_complete_receipts_across_reopen() {
    let directory = tempdir().unwrap();
    let root = directory.path().join("authority");
    let coordinator = PersistentFileAuthorityCoordinatorV0::create(
        &root,
        identity(),
        MAX_PAYLOAD_BYTES,
        MAX_RECORDS,
    )
    .unwrap();
    let mut active = session(coordinator);
    active.recover().unwrap();

    let first = binding(1, 10, 9);
    let mut receipt = active.begin_prepared(first, digest(20)).unwrap();
    drop(active.into_coordinator());
    active = reopen(&root);
    assert_eq!(active.current_receipt(), Some(receipt));

    for (index, next) in [
        AuthorityStageV0::ApplicationSealed,
        AuthorityStageV0::SafetyPersisted,
        AuthorityStageV0::SignIntentPersisted,
        AuthorityStageV0::SignatureConfirmed,
        AuthorityStageV0::FinalityApplied,
        AuthorityStageV0::CheckpointConfirmed,
        AuthorityStageV0::OutboundPublished,
    ]
    .into_iter()
    .enumerate()
    {
        let previous = receipt;
        receipt = active
            .advance(
                first,
                previous.durable_stage,
                next,
                digest(30 + u8::try_from(index).unwrap()),
            )
            .unwrap();
        drop(active.into_coordinator());
        active = reopen(&root);
        assert_eq!(active.current_receipt(), Some(receipt));
    }

    let second = binding(2, 11, 10);
    let next = active.begin_prepared(second, digest(60)).unwrap();
    drop(active.into_coordinator());
    let reopened = reopen(&root);
    assert_eq!(reopened.current_receipt(), Some(next));
}
