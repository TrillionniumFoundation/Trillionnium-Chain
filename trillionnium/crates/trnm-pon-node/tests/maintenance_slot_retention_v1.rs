//! P0-B development regression: 32-slot Q4/Rev12 capacity, final-lease loss,
//! retention barrier and fresh-generation reuse. Source signing is NOT bypassed;
//! this test only OPENs new demands and does not manufacture their registrations.
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::{continuity_v1, qualified_task_lifecycle};
use trnm_pon_node::{development_public, Node, Settings};
use trnm_protocol::{
    pon_wire::{hash, Envelope, Hash},
    qualified_work_task::{lifecycle_v2::{DemandLeaseV2, DemandRevocationV2}, TaskPurpose},
};

fn public(owner: u64) -> Hash {
    development_public(owner).unwrap()
}
fn tx(settings: &Settings, owner: u64, nonce: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut signed = Envelope {
        network: settings.network(),
        sender: public(owner),
        nonce,
        expiry: 2000,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    let private = signing_key_from_hex(&hex::encode(hash(
        b"DEV-ONLY-KEY",
        &[&owner.to_le_bytes()],
    )))
    .unwrap();
    signed.signature = hex::decode(sign_hex(
        &private,
        &signed.signing_digest().unwrap(),
    ))
    .unwrap()
    .try_into()
    .unwrap();
    signed.encode().unwrap()
}
fn new_lease(
    original: &DemandLeaseV2,
    slot: u8,
    generation: u64,
    expires: u64,
) -> DemandLeaseV2 {
    let mut lease = original.clone();
    lease.slot = slot;
    lease.purpose = TaskPurpose::InferenceContraction;
    lease.generation = generation;
    lease.requester = public(2);
    lease.not_before = 1;
    lease.expires = expires;
    lease.available_until = expires + 100;
    lease.demand_id = lease.derived_demand_id();
    lease
}
fn maintenance(node: &mut Node, parent: Hash, height: u64, txs: Vec<Vec<u8>>) -> Hash {
    let packet = node
        .make_consensus_maintenance(parent, txs, public(0), 1 + height * 10, 4096)
        .unwrap();
    let id = packet.id().unwrap();
    assert_eq!(node.admit(&packet, 100_000).unwrap(), id);
    node.activate(id).unwrap();
    id
}

#[test]
fn full_slot_reuse_only_after_retention_requires_fresh_authorized_generation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node");
    let settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap();
    let boot = settings.bootstrap_lifecycle_task().unwrap();
    let mut node = Node::open(&path, settings.clone(), 1).unwrap();
    let old_task = boot.signed.manifest.matrix_task;
    let revocation = DemandRevocationV2 {
        slot: boot.lease.slot,
        network: settings.network(),
        parameters: settings.parameters(),
        demand_id: boot.lease.demand_id,
        requester: boot.lease.requester,
        expected_revision: boot.lease.revision,
    };
    let mut batch = vec![tx(&settings, 1, 1, 20, revocation.encode().unwrap())];
    // Genesis uses slot0. Thirty-one additional OPEN-only demands fill all
    // thirty-two slots. OPEN is NOT a mining work or source authorization.
    for slot in 1_u8..=31_u8 {
        let lease = new_lease(&boot.lease, slot, u64::from(slot) + 1, 3);
        batch.push(tx(
            &settings,
            2,
            u64::from(slot),
            18,
            lease.encode().unwrap(),
        ));
    }
    let mut tip = maintenance(&mut node, settings.genesis(), 1, batch);
    assert!(node.lifecycle_task_lease(tip, old_task, 2).is_err());
    for slot in 0_u8..=31_u8 {
        assert!(
            node.read_active()
                .unwrap()
                .2
                .contains_key(&qualified_task_lifecycle::slot_key(slot).unwrap()),
            "missing original bounded slot {slot}"
        );
    }
    let mut replacement = new_lease(&boot.lease, 1, 33, 105);
    // Q4 OPEN needs not_before >= actual inclusion height, not the old height.
    replacement.not_before = 104;
    let next_open = tx(&settings, 2, 32, 18, replacement.encode().unwrap());
    // At height2 the old record is occupied; an attempted next-generation
    // OPEN is NOT a free bypass of the 100-block retention obligation.
    let before = node.read_active().unwrap();
    assert!(
        node.make_consensus_maintenance(
            tip,
            vec![next_open.clone()],
            public(0),
            21,
            4096,
        )
        .is_err()
    );
    assert_eq!(node.read_active().unwrap(), before);

    // No optional task remains eligible. Advance only via the public,
    // genesis-committed Maintenance source; do not synthesize source renewal.
    for height in 2_u64..=102_u64 {
        tip = maintenance(&mut node, tip, height, vec![]);
        assert!(node.lifecycle_task_lease(tip, old_task, height + 1).is_err());
    }
    // Exactly at height103 the retired record is still retained. The
    // prospective successor is otherwise valid, but may not replace it.
    let retained = node.read_active().unwrap();
    assert!(
        node.make_consensus_maintenance(
            tip,
            vec![next_open.clone()],
            public(0),
            1031,
            4096,
        )
        .is_err()
    );
    assert_eq!(node.read_active().unwrap(), retained);
    tip = maintenance(&mut node, tip, 103, vec![]);
    let before_expiry = node.read_active().unwrap();
    assert!(
        node.make_consensus_maintenance(
            tip,
            vec![next_open.clone()],
            public(0),
            1041, // actual successor is height104; old retention ends103
            4096,
        )
        .is_ok()
    );
    assert_eq!(node.read_active().unwrap(), before_expiry);
    // The validity here comes only from an authentic requester PNX1 OPEN.
    // It creates no source-signed QWA2 and therefore no new work authority.
    tip = maintenance(&mut node, tip, 104, vec![next_open]);
    let state = node.read_active().unwrap();
    assert_eq!(state.0, tip);
    assert_eq!(
        state.2[&qualified_task_lifecycle::slot_key(1).unwrap()]["generation"],
        33
    );
    assert_eq!(
        state.2[&qualified_task_lifecycle::slot_key(1).unwrap()]["output_count"],
        0
    );
    drop(node);
    let node = Node::open(&path, settings, 1).unwrap();
    assert_eq!(node.read_active().unwrap(), state);
    assert!(node.lifecycle_task_lease(tip, old_task, 105).is_err());
    eprintln!("q4-retention regression: 32 slots, 104 real maintenance blocks, expired slot held to height103, new signed requester OPEN at104, old work refused; independent source and WAN=false");
}
