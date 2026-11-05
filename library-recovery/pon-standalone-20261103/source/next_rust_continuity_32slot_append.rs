
/// Native W1 + SQLite boundary: all 32 optional slots can be opened and revoked
/// without blocking a Genesis Maintenance block or authenticated confirmation.
/// Identity keys are public development fixtures, not independent operators.
#[test]
fn native_32_slot_revocation_preserves_maintenance_confirmation_and_reopen() {
    use trnm_protocol::qualified_work_task::lifecycle_v2::{DemandRevocationV2, DEMAND_SLOTS};

    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let bootstrap = settings.bootstrap_lifecycle_task().unwrap();
    let mut node = Node::open(dir.path(), settings.clone(), 2).unwrap();
    let mut leases = vec![bootstrap.lease.clone()];
    let mut opens = Vec::new();
    for slot in 1..DEMAND_SLOTS {
        let mut lease = bootstrap.lease.clone();
        lease.slot = slot;
        lease.generation = u64::from(slot) + 1;
        lease.revision = 1;
        lease.not_before = 1;
        lease.expires = 1001;
        lease.available_until = 1101;
        lease.demand_id = lease.derived_demand_id();
        opens.push(signed(&settings, 1, u64::from(slot), 18, lease.encode().unwrap()));
        leases.push(lease);
    }
    let watched_tx = opens.last().unwrap().clone();
    let included = mine(&mut node, 1, opens);
    let saturated = node.read_active().unwrap();
    assert_eq!(saturated.0, included);
    for slot in 0..DEMAND_SLOTS {
        assert_eq!(
            saturated.2[&qualified_task_lifecycle::slot_key(slot).unwrap()]["status"],
            "active",
        );
    }
    assert_eq!(node.next_nonce(development_public(1).unwrap()).unwrap(), 32);
    let mut revocations = Vec::new();
    for (slot, lease) in leases.iter().enumerate() {
        let request = DemandRevocationV2 {
            network: settings.network(),
            parameters: settings.parameters(),
            slot: slot as u8,
            demand_id: lease.demand_id,
            requester: lease.requester,
            expected_revision: lease.revision,
        };
        revocations.push(signed(
            &settings, 1, 32 + slot as u64, 20, request.encode().unwrap(),
        ));
    }
    mine(&mut node, 2, revocations);
    let revoked = node.read_active().unwrap();
    for slot in 0..DEMAND_SLOTS {
        assert_eq!(
            revoked.2[&qualified_task_lifecycle::slot_key(slot).unwrap()]["status"],
            "revoked",
        );
    }
    assert_eq!(node.next_nonce(development_public(1).unwrap()).unwrap(), 64);
    assert!(node.lifecycle_task_lease(revoked.0, bootstrap.signed.manifest.matrix_task, 3).is_err());
    assert_eq!(revoked.2[continuity_v1::MAINTENANCE_KEY]["useful_output_credit"], 0);

    // A signed new generation cannot bypass the retained record during height 3.
    let mut new_lease = bootstrap.lease.clone();
    new_lease.generation = 33;
    new_lease.not_before = 3;
    new_lease.expires = 1003;
    new_lease.available_until = 1103;
    new_lease.demand_id = new_lease.derived_demand_id();
    let attempted = signed(&settings, 1, 64, 18, new_lease.encode().unwrap());
    let before_refusal = node.read_active().unwrap();
    let error = node.make_consensus_maintenance(
        revoked.0, vec![attempted], development_public(0).unwrap(), 31, 4096,
    ).unwrap_err();
    assert_eq!(error.to_string(), "TASK_RETAINED");
    assert_eq!(node.read_active().unwrap(), before_refusal);
    assert_eq!(node.next_nonce(development_public(1).unwrap()).unwrap(), 64);

    for height in 3..=9 {
        mine(&mut node, height, vec![]);
    }
    let watched = hash(b"tx-id", &[&watched_tx]);
    let observed = node.confirmation(watched, included, 100_000).unwrap();
    assert!(observed.confirmed);
    assert!(!observed.reorged);
    assert!(!observed.finalized);
    assert!(!observed.execution_authority);
    let before = node.read_active().unwrap();
    drop(node);
    let reopened = Node::open(dir.path(), settings, 1).unwrap();
    assert_eq!(reopened.read_active().unwrap(), before);
    assert!(reopened.confirmation(watched, included, 100_000).unwrap().confirmed);
}
