//! Native SQLite/proof integration. The capacity fixture explicitly seeds a
//! separate test genesis with dormant accounts; it does not claim a generated
//! 65,000-account historical chain or alter any installed genesis constructor.
use super::*;
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::continuity_v1;
use trnm_protocol::qualified_work_task::lifecycle_v2::DemandRevocationV2;

fn settings() -> Settings {
    Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap()
}
fn signed(settings: &Settings, who: u64, nonce: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut tx = trnm_protocol::pon_wire::Envelope {
        network: settings.network(),
        sender: development_public(who).unwrap(),
        nonce,
        expiry: 2000,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&who.to_le_bytes()]))).unwrap();
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}
fn mine(node: &mut Node, height: u64, txs: Vec<Vec<u8>>) -> Hash {
    let packet = node
        .make_consensus_maintenance(
            node.active().unwrap().0,
            txs,
            development_public(0).unwrap(),
            1 + height * 10,
            4096,
        )
        .unwrap();
    assert_eq!(
        packet.header.work_task,
        continuity_v1::maintenance_task().unwrap()
    );
    let id = node.admit(&packet, 100_000).unwrap();
    node.activate(id).unwrap();
    id
}

fn capacity_settings(spare_keys: usize) -> (Settings, String) {
    let mut settings = settings();
    let target = continuity_v1::MAX_KEYS - 20 - spare_keys;
    let dormant = format!(
        "account:{}",
        hex::encode(hash(b"continuity-dormant-account", &[&0u64.to_le_bytes()]))
    );
    for index in 0u64.. {
        if settings.initial.len() == target {
            break;
        }
        settings.initial.insert(
            format!(
                "account:{}",
                hex::encode(hash(b"continuity-dormant-account", &[&index.to_le_bytes()]))
            ),
            serde_json::json!({"balance":0,"nonce":7}),
        );
    }
    // This is an explicit preallocated test genesis, not account creation history.
    continuity_v1::check_state(&settings.initial, 0, &settings.app).unwrap();
    settings.genesis = hash(
        b"genesis",
        &[
            &settings.network(),
            &settings.parameters(),
            &root(&settings.initial).unwrap(),
            &settings.genesis_time().to_le_bytes(),
        ],
    );
    (settings, dormant)
}

#[test]
fn explicit_maintenance_survives_all_optional_task_revocation_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let bootstrap = settings.bootstrap_lifecycle_task().unwrap();
    let (old_model, old_input, _, _) = settings.bootstrap_task_material().unwrap();
    let (model, input, _, _) = settings.consensus_maintenance_material().unwrap();
    assert_ne!(model, old_model);
    assert_ne!(input, old_input);
    let mut node = Node::open(dir.path(), settings.clone(), 2).unwrap();
    let initial = node.read_active().unwrap().2;
    assert!(matches!(
        node.eligible_work_task_from_state(
            &initial,
            continuity_v1::maintenance_task().unwrap(),
            1001
        )
        .unwrap(),
        ParentTaskEligibility::ConsensusMaintenance
    ));
    assert!(node
        .eligible_work_task_from_state(&initial, bootstrap.signed.manifest.matrix_task, 1001)
        .is_err());
    let revoke = DemandRevocationV2 {
        network: settings.network(),
        parameters: settings.parameters(),
        slot: 0,
        demand_id: bootstrap.lease.demand_id,
        requester: bootstrap.lease.requester,
        expected_revision: bootstrap.lease.revision,
    };
    let tx = signed(&settings, 1, 1, 20, revoke.encode().unwrap());
    mine(&mut node, 1, vec![tx]);
    let parent = node.active().unwrap().0;
    assert_eq!(
        node.lifecycle_task_lease(parent, bootstrap.signed.manifest.matrix_task, 2)
            .unwrap_err()
            .to_string(),
        "TASK"
    );
    // Supplying the revoked task's actual materials cannot select maintenance.
    assert!(node
        .prepare_registered_material_controlled(
            parent,
            vec![],
            development_public(0).unwrap(),
            21,
            4096,
            &old_model,
            &old_input,
            &ExecutionControl::new(&|_| Ok(()), &())
        )
        .is_err());
    let id = mine(&mut node, 2, vec![]);
    let state = node.read_active().unwrap().2;
    assert_eq!(
        state[&qualified_task_lifecycle::slot_key(0).unwrap()]["status"],
        "revoked"
    );
    assert_eq!(
        state[&qualified_task_lifecycle::slot_key(0).unwrap()]["output_count"],
        0
    );
    assert_eq!(
        state[continuity_v1::MAINTENANCE_KEY]["useful_output_credit"],
        0
    );
    drop(node);
    let mut restored = Node::open(dir.path(), settings.clone(), 1).unwrap();
    assert_eq!(restored.active().unwrap().0, id);
    assert_eq!(restored.read_active().unwrap().2, state);
    mine(&mut restored, 3, vec![]);
    // No generic make() route or old profile is silently reinterpreted.
    assert_eq!(
        restored
            .make(
                restored.active().unwrap().0,
                vec![],
                development_public(0).unwrap(),
                41,
                4096
            )
            .unwrap_err()
            .to_string(),
        "EXPLICIT_TASK_REQUIRED"
    );
    let old = Settings::development(Some(1)).unwrap();
    assert_eq!(
        old.consensus_maintenance_material()
            .unwrap_err()
            .to_string(),
        "CONTINUITY_PROFILE"
    );
}

#[test]
fn actual_65536_key_native_chain_rejects_growth_keeps_nonce_and_reopens() {
    let dir = tempfile::tempdir().unwrap();
    let (settings, dormant) = capacity_settings(0);
    let mut node = Node::open(dir.path(), settings.clone(), 2).unwrap();
    for height in 1..=20 {
        mine(&mut node, height, vec![]);
    }
    let before = node.read_active().unwrap();
    assert_eq!(before.2.len(), continuity_v1::MAX_KEYS);
    assert_eq!(
        continuity_v1::capacity(&before.2, 20, &settings.app)
            .unwrap()
            .required_keys,
        continuity_v1::MAX_KEYS
    );
    let new_miner = development_public(4).unwrap();
    assert!(!before
        .2
        .contains_key(&format!("account:{}", hex::encode(new_miner))));
    let error = node
        .make_consensus_maintenance(before.0, vec![], new_miner, 211, 4096)
        .unwrap_err();
    assert_eq!(error.to_string(), "STATE_CAPACITY");
    let mut payload = new_miner.to_vec();
    payload.extend(1u64.to_le_bytes());
    let raw = signed(&settings, 0, 1, 1, payload);
    assert_eq!(
        node.make_consensus_maintenance(
            before.0,
            vec![raw],
            development_public(0).unwrap(),
            211,
            4096
        )
        .unwrap_err()
        .to_string(),
        "STATE_CAPACITY"
    );
    assert_eq!(node.read_active().unwrap(), before);
    assert_eq!(node.next_nonce(development_public(0).unwrap()).unwrap(), 1);
    assert_eq!(
        before.2[&dormant],
        serde_json::json!({"balance":0,"nonce":7})
    );
    drop(node);
    let mut restored = Node::open(dir.path(), settings.clone(), 1).unwrap();
    assert_eq!(restored.read_active().unwrap(), before);
    let mut transfer = development_public(1).unwrap().to_vec();
    transfer.extend(1u64.to_le_bytes());
    let raw = signed(&settings, 0, 1, 1, transfer);
    mine(&mut restored, 21, vec![raw]);
    let after = restored.read_active().unwrap();
    assert_eq!(after.2.len(), continuity_v1::MAX_KEYS);
    assert_eq!(after.2[&dormant]["nonce"], 7);
    assert_eq!(
        restored.next_nonce(development_public(0).unwrap()).unwrap(),
        2
    );
    drop(restored);
    let reopened = Node::open(dir.path(), settings, 2).unwrap();
    assert_eq!(reopened.read_active().unwrap(), after);
    assert_eq!(
        reopened.next_nonce(development_public(0).unwrap()).unwrap(),
        2
    );
}

#[test]
fn actual_capacity_reclaimed_after_refund_admits_new_account_and_reorganizes() {
    let dir = tempfile::tempdir().unwrap();
    let (settings, dormant) = capacity_settings(1);
    let owner = development_public(0).unwrap();
    let owner_key = format!("account:{}", hex::encode(owner));
    let consumer = development_public(1).unwrap();
    let provider = development_public(2).unwrap();
    let deadline = 22u64;
    let units = 1u64;
    let quota = hash(
        b"quota-instance-v3",
        &[
            &settings.network(),
            &settings.parameters(),
            &owner,
            &1u64.to_le_bytes(),
            &consumer,
            &provider,
            &units.to_le_bytes(),
            &deadline.to_le_bytes(),
        ],
    );
    let quota_key = format!("quota:{}", hex::encode(quota));
    let mut payload = quota.to_vec();
    payload.extend(consumer);
    payload.extend(provider);
    payload.extend(units.to_le_bytes());
    payload.extend(deadline.to_le_bytes());
    let open = signed(&settings, 0, 1, 10, payload);
    let mut node = Node::open(dir.path(), settings.clone(), 2).unwrap();
    mine(&mut node, 1, vec![open]);
    for height in 2..=20 {
        mine(&mut node, height, vec![]);
    }
    let recipient = development_public(4).unwrap();
    let recipient_key = format!("account:{}", hex::encode(recipient));
    let mut payload = recipient.to_vec();
    payload.extend(1u64.to_le_bytes());
    let enter = signed(&settings, 0, 2, 1, payload);
    // Expiry refunds at height22 but deliberately retains its row until height23.
    // A failed candidate must roll back that tentative mandatory refund too.
    for height in [21u64, 22] {
        let before = node.read_active().unwrap();
        assert_eq!(before.2.len(), continuity_v1::MAX_KEYS);
        assert_eq!(
            continuity_v1::capacity(&before.2, height - 1, &settings.app)
                .unwrap()
                .required_keys,
            continuity_v1::MAX_KEYS
        );
        assert!(!before.2.contains_key(&recipient_key));
        assert_eq!(before.2[&quota_key]["status"], "reserved");
        assert_eq!(node.next_nonce(owner).unwrap(), 2);
        let error = node
            .make_consensus_maintenance(before.0, vec![enter.clone()], owner, 1 + height * 10, 4096)
            .unwrap_err();
        assert_eq!(error.to_string(), "STATE_CAPACITY");
        assert_eq!(node.read_active().unwrap(), before);
        assert_eq!(node.next_nonce(owner).unwrap(), 2);
        let due_reward: u64 = before
            .2
            .iter()
            .filter(|(key, value)| {
                key.starts_with("reward:") && value["maturity"].as_u64() == Some(height)
            })
            .map(|(_, value)| value["amount"].as_u64().unwrap())
            .sum();
        let refund = if height == deadline {
            before.2[&quota_key]["remaining"].as_u64().unwrap()
        } else {
            0
        };
        mine(&mut node, height, vec![]);
        let after = node.read_active().unwrap().2;
        assert_eq!(after.len(), continuity_v1::MAX_KEYS);
        assert_eq!(
            after[&owner_key]["balance"].as_u64().unwrap(),
            before.2[&owner_key]["balance"].as_u64().unwrap() + due_reward + refund
        );
        assert_eq!(after[&dormant]["nonce"], 7);
    }
    let refunded = node.read_active().unwrap();
    assert_eq!(refunded.2[&quota_key]["remaining"], 0);
    assert_eq!(refunded.2[&quota_key]["status"], "expired");
    assert!(!refunded.2.contains_key(&recipient_key));
    drop(node);
    let mut node = Node::open(dir.path(), settings.clone(), 1).unwrap();
    assert_eq!(node.read_active().unwrap(), refunded);

    let admitted = mine(&mut node, 23, vec![enter]);
    let entered = node.read_active().unwrap();
    assert_eq!(entered.0, admitted);
    assert_eq!(entered.2.len(), continuity_v1::MAX_KEYS);
    assert!(!entered.2.contains_key(&quota_key));
    assert_eq!(entered.2[&recipient_key]["balance"], 1);
    assert_eq!(node.next_nonce(owner).unwrap(), 3);
    assert_eq!(entered.2[&dormant]["nonce"], 7);

    // Real competing packets replace the entry branch only after greater work.
    // Both branches perform the same legitimate expiry cleanup; neither deletes
    // an account or resets a retained nonce to manufacture admission capacity.
    let fork23 = node
        .make_consensus_maintenance(refunded.0, vec![], owner, 232, 4096)
        .unwrap();
    let fork23 = node.admit(&fork23, 100_000).unwrap();
    assert_eq!(node.activate(fork23).unwrap(), admitted);
    let fork24 = node
        .make_consensus_maintenance(fork23, vec![], owner, 241, 4096)
        .unwrap();
    let fork24 = node.admit(&fork24, 100_000).unwrap();
    assert_eq!(node.activate(fork24).unwrap(), fork24);
    let detached = node.read_active().unwrap();
    assert!(!detached.2.contains_key(&quota_key));
    assert!(!detached.2.contains_key(&recipient_key));
    assert_eq!(detached.2.len(), continuity_v1::MAX_KEYS - 1);
    assert_eq!(node.next_nonce(owner).unwrap(), 2);
    assert_eq!(detached.2[&dormant]["nonce"], 7);
    drop(node);
    let mut node = Node::open(dir.path(), settings.clone(), 2).unwrap();
    assert_eq!(node.read_active().unwrap(), detached);

    let main24 = node
        .make_consensus_maintenance(admitted, vec![], owner, 241, 4096)
        .unwrap();
    let main24 = node.admit(&main24, 100_000).unwrap();
    assert_eq!(node.activate(main24).unwrap(), fork24);
    let main25 = node
        .make_consensus_maintenance(main24, vec![], owner, 251, 4096)
        .unwrap();
    let main25 = node.admit(&main25, 100_000).unwrap();
    assert_eq!(node.activate(main25).unwrap(), main25);
    let restored = node.read_active().unwrap();
    assert_eq!(restored.2.len(), continuity_v1::MAX_KEYS);
    assert!(!restored.2.contains_key(&quota_key));
    assert_eq!(restored.2[&recipient_key], entered.2[&recipient_key]);
    assert_eq!(node.next_nonce(owner).unwrap(), 3);
    assert_eq!(restored.2[&dormant]["nonce"], 7);
    drop(node);
    let reopened = Node::open(dir.path(), settings, 1).unwrap();
    assert_eq!(reopened.read_active().unwrap(), restored);
    assert_eq!(reopened.next_nonce(owner).unwrap(), 3);
    eprintln!(
        "capacity reentry: accepted_native_packets=27, rejected_growth=2, reorgs=2, reopens=3, synthetic_preallocated_genesis=true"
    );
}

#[test]
fn recovery_rejects_missing_genesis_maintenance_even_with_recomputed_state_root() {
    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let node = Node::open(dir.path(), settings.clone(), 1).unwrap();
    let mut state = node.read_active().unwrap().2;
    state.remove(continuity_v1::MAINTENANCE_KEY);
    let changed_root = root(&state).unwrap();
    node.db
        .execute(
            "DELETE FROM kv WHERE key=?",
            [continuity_v1::MAINTENANCE_KEY],
        )
        .unwrap();
    node.db
        .execute(
            "UPDATE blocks SET state_root=? WHERE id=?",
            params![changed_root.as_slice(), settings.genesis().as_slice()],
        )
        .unwrap();
    drop(node);
    assert_eq!(
        Node::open(dir.path(), settings, 1)
            .err()
            .unwrap()
            .to_string(),
        "CONTINUITY_MAINTENANCE"
    );
}

#[test]
fn signed_lease_cannot_alias_the_reserved_maintenance_task() {
    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let bootstrap = settings.bootstrap_lifecycle_task().unwrap();
    let mut lease = bootstrap.lease;
    lease.slot = 1;
    lease.generation = 2;
    lease.not_before = 1;
    lease.expires = 1001;
    lease.available_until = 1101;
    lease.demand_id = lease.derived_demand_id();
    let (model, input, _, _) = settings.consensus_maintenance_material().unwrap();
    let mut manifest = bootstrap.signed.manifest;
    manifest.demand_id = lease.demand_id;
    manifest.source_record = lease.bound_source_record().unwrap();
    manifest.model = hash(b"artifact", &[&model]);
    manifest.layer = QualifiedWorkTask::layer_id(manifest.model);
    manifest.input = hash(b"qualified-task-input-v1", &[&input]);
    manifest.matrix_task = continuity_v1::maintenance_task().unwrap();
    manifest.withdrawal_head = lease.withdrawal_frontier().unwrap();
    manifest.not_before = lease.not_before;
    manifest.expires = lease.expires;
    manifest.available_until = lease.available_until;
    manifest.output_meter = manifest.derived_output_meter();
    let mut statement = trnm_protocol::qualified_work_task::lifecycle_v2::SignedLifecycleTaskV2 {
        lease_id: lease.id().unwrap(),
        manifest,
        signature: [0; 64],
    };
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0u64.to_le_bytes()]))).unwrap();
    statement.signature = hex::decode(sign_hex(&key, &statement.signing_message().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    let txs = vec![
        signed(&settings, 1, 1, 18, lease.encode().unwrap()),
        signed(&settings, 0, 1, 21, statement.encode().unwrap()),
    ];
    let node = Node::open(dir.path(), settings, 1).unwrap();
    let before = node.read_active().unwrap();
    assert_eq!(
        node.make_consensus_maintenance(before.0, txs, development_public(0).unwrap(), 11, 4096)
            .unwrap_err()
            .to_string(),
        "CONTINUITY_TASK_RESERVED"
    );
    assert_eq!(node.read_active().unwrap(), before);
    assert_eq!(node.next_nonce(development_public(1).unwrap()).unwrap(), 1);
}
