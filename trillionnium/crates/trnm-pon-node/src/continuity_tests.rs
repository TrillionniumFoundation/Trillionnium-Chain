//! Native SQLite/proof integration. The capacity fixture explicitly seeds a
//! separate test genesis with dormant accounts; it does not claim a generated
//! 65,000-account historical chain or alter any installed genesis constructor.
use super::*;
use crate::ErrorCode;
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
fn signed(
    settings: &Settings,
    who: u64,
    account_sequence: u64,
    tag: u8,
    payload: Vec<u8>,
) -> Vec<u8> {
    let mut tx = trnm_protocol::pon_wire::Envelope {
        network: settings.network(),
        sender: development_public(who).unwrap(),
        nonce: account_sequence,
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

fn capacity_report(node: &Node, view: &(Hash, u64, State), height: u64) -> Value {
    let report = serde_json::to_value(node.capacity_observation().unwrap()).unwrap();
    assert_eq!(report["schema"], "pon-continuity-capacity-observation-v1");
    assert_eq!(report["observed_tip"], hex::encode(view.0));
    assert_eq!(report["active_generation"], view.1);
    assert_eq!(report["observed_height"], height);
    assert_eq!(report["state_root"], hex::encode(root(&view.2).unwrap()));
    assert_eq!(report["actual_keys"], view.2.len());
    assert_eq!(report["maximum_keys"], continuity_v1::MAX_KEYS);
    assert_eq!(report["next_block_admission_guaranteed"], false);
    report
}

#[test]
fn capacity_observation_distinguishes_reserved_and_retained_accounts() {
    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut node = Node::open(dir.path(), settings.clone(), 1).unwrap();
    let before = node.read_active().unwrap();
    let initial = capacity_report(&node, &before, 0);
    assert_eq!(initial["retained_account_keys"], 4);
    assert_eq!(initial["credit_account_reserve"], 0);
    assert_eq!(initial["archive_reserve"], 0);
    assert_eq!(initial["reward_queue_reserve"], 20);
    let original_required = initial["required_keys"].as_u64().unwrap();
    let recipient = development_public(4).unwrap();
    for height in 1..=2 {
        let packet = node
            .make_consensus_maintenance(
                node.active().unwrap().0,
                vec![],
                recipient,
                1 + height * 10,
                4096,
            )
            .unwrap();
        let id = node.admit(&packet, 100_000).unwrap();
        node.activate(id).unwrap();
        let report = capacity_report(&node, &node.read_active().unwrap(), height);
        assert_eq!(report["retained_account_keys"], 4);
        // Two future rewards to one missing recipient reserve exactly one key.
        assert_eq!(report["credit_account_reserve"], 1);
        assert_eq!(report["reward_queue_reserve"], 20 - height);
        assert_eq!(report["required_keys"], original_required + 1);
    }
    let mut transfer = recipient.to_vec();
    transfer.extend(1u64.to_le_bytes());
    mine(&mut node, 3, vec![signed(&settings, 0, 1, 1, transfer)]);
    let after = node.read_active().unwrap();
    let report = capacity_report(&node, &after, 3);
    assert_eq!(report["retained_account_keys"], 5);
    assert_eq!(report["credit_account_reserve"], 0);
    assert_eq!(report["reward_queue_reserve"], 17);
    assert_eq!(report["required_keys"], original_required + 1);
    assert_eq!(
        report["unreserved_keys"],
        continuity_v1::MAX_KEYS as u64 - original_required - 1
    );
    assert_eq!(
        after.2[&format!("account:{}", hex::encode(recipient))]["balance"],
        1
    );
    // This command's report is not inserted into legacy or signed peer Head stats.
    assert!(node.stats().unwrap().get("capacity_observation").is_none());
    assert!(node.stats().unwrap().get("required_keys").is_none());
    drop(node);
    let reopened = Node::open(dir.path(), settings, 1).unwrap();
    assert_eq!(capacity_report(&reopened, &after, 3), report);
}

#[test]
fn capacity_observation_rechecks_actual_bytes_cancellation_and_generation() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::open(dir.path(), settings(), 1).unwrap();
    let before = node.read_active().unwrap();
    let mut total = 0;
    let expected = node
        .capacity_observation_with_progress(&mut || {
            total += 1;
            Ok(())
        })
        .unwrap();
    for cut in [1, 2, total] {
        let mut calls = 0;
        let error = node
            .capacity_observation_with_progress(&mut || {
                calls += 1;
                if calls == cut {
                    Err(Error::new(ErrorCode::PublicRequestCancelled))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert!(error.is(ErrorCode::PublicRequestCancelled));
        assert!(!error.requires_owner_stop());
        assert_eq!(calls, cut);
        assert_eq!(node.read_active().unwrap(), before);
    }
    let mut calls = 0;
    let error = node
        .capacity_observation_with_progress(&mut || {
            calls += 1;
            if calls == total {
                node.db
                    .execute("UPDATE active SET generation=?", [before.1 + 1])
                    .unwrap();
            }
            Ok(())
        })
        .unwrap_err();
    assert_eq!(error.to_string(), "STALE_VIEW");
    assert!(!error.requires_owner_stop());
    node.db
        .execute("UPDATE active SET generation=?", [before.1])
        .unwrap();
    assert_eq!(node.capacity_observation().unwrap(), expected);

    // A warm derived commitment must not hide tampered actual SQLite bytes.
    let original = serde_json::to_vec(&before.2["model:current"]).unwrap();
    for (bytes, code) in [
        (b"null".as_slice(), "ROOT"),
        (b" null".as_slice(), "STATE_BYTES"),
    ] {
        node.db
            .execute("UPDATE kv SET value=? WHERE key='model:current'", [bytes])
            .unwrap();
        let error = node.capacity_observation().unwrap_err();
        assert_eq!(error.to_string(), code);
        assert!(error.requires_owner_stop());
    }
    node.db
        .execute(
            "UPDATE kv SET value=? WHERE key='model:current'",
            [original],
        )
        .unwrap();
    assert_eq!(node.read_active().unwrap(), before);
    assert_eq!(node.capacity_observation().unwrap(), expected);

    let legacy = tempfile::tempdir().unwrap();
    let legacy = Node::open(legacy.path(), Settings::development(Some(1)).unwrap(), 1).unwrap();
    assert_eq!(
        legacy.capacity_observation().unwrap_err().to_string(),
        "CONTINUITY_PROFILE"
    );
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
    let genesis_report = capacity_report(&node, &node.read_active().unwrap(), 0);
    assert_eq!(genesis_report["actual_keys"], continuity_v1::MAX_KEYS - 20);
    assert_eq!(genesis_report["reward_queue_reserve"], 20);
    assert_eq!(genesis_report["unreserved_keys"], 0);
    for height in 1..=20 {
        mine(&mut node, height, vec![]);
    }
    let before = node.read_active().unwrap();
    let full_report = capacity_report(&node, &before, 20);
    assert_eq!(full_report["credit_account_reserve"], 0);
    assert_eq!(full_report["archive_reserve"], 0);
    assert_eq!(full_report["reward_queue_reserve"], 0);
    assert_eq!(full_report["unreserved_keys"], 0);
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
    assert_eq!(capacity_report(&node, &before, 20), full_report);
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
    let continuing_report = capacity_report(&restored, &after, 21);
    assert_eq!(continuing_report["unreserved_keys"], 0);
    assert_eq!(
        continuing_report["retained_account_keys"],
        full_report["retained_account_keys"]
    );
    assert_eq!(after.2.len(), continuity_v1::MAX_KEYS);
    assert_eq!(after.2[&dormant]["nonce"], 7);
    assert_eq!(
        restored.next_nonce(development_public(0).unwrap()).unwrap(),
        2
    );
    drop(restored);
    let reopened = Node::open(dir.path(), settings, 2).unwrap();
    assert_eq!(reopened.read_active().unwrap(), after);
    assert_eq!(capacity_report(&reopened, &after, 21), continuing_report);
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
    let refunded_report = capacity_report(&node, &refunded, 22);
    assert_eq!(refunded_report["unreserved_keys"], 0);
    assert_eq!(refunded.2[&quota_key]["remaining"], 0);
    assert_eq!(refunded.2[&quota_key]["status"], "expired");
    assert!(!refunded.2.contains_key(&recipient_key));
    drop(node);
    let mut node = Node::open(dir.path(), settings.clone(), 1).unwrap();
    assert_eq!(node.read_active().unwrap(), refunded);

    let admitted = mine(&mut node, 23, vec![enter]);
    let entered = node.read_active().unwrap();
    let entered_report = capacity_report(&node, &entered, 23);
    assert_eq!(entered_report["unreserved_keys"], 0);
    assert_eq!(
        entered_report["retained_account_keys"].as_u64().unwrap(),
        refunded_report["retained_account_keys"].as_u64().unwrap() + 1
    );
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
    let detached_report = capacity_report(&node, &detached, 24);
    assert_eq!(detached_report["unreserved_keys"], 1);
    assert_eq!(
        detached_report["retained_account_keys"],
        refunded_report["retained_account_keys"]
    );
    assert!(!detached.2.contains_key(&quota_key));
    assert!(!detached.2.contains_key(&recipient_key));
    assert_eq!(detached.2.len(), continuity_v1::MAX_KEYS - 1);
    assert_eq!(node.next_nonce(owner).unwrap(), 2);
    assert_eq!(detached.2[&dormant]["nonce"], 7);
    drop(node);
    let mut node = Node::open(dir.path(), settings.clone(), 2).unwrap();
    assert_eq!(node.read_active().unwrap(), detached);
    assert_eq!(capacity_report(&node, &detached, 24), detached_report);

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
    let restored_report = capacity_report(&node, &restored, 25);
    assert_eq!(restored_report["unreserved_keys"], 0);
    assert_eq!(
        restored_report["retained_account_keys"],
        entered_report["retained_account_keys"]
    );
    assert_eq!(restored.2.len(), continuity_v1::MAX_KEYS);
    assert!(!restored.2.contains_key(&quota_key));
    assert_eq!(restored.2[&recipient_key], entered.2[&recipient_key]);
    assert_eq!(node.next_nonce(owner).unwrap(), 3);
    assert_eq!(restored.2[&dormant]["nonce"], 7);
    drop(node);
    let reopened = Node::open(dir.path(), settings, 1).unwrap();
    assert_eq!(reopened.read_active().unwrap(), restored);
    assert_eq!(capacity_report(&reopened, &restored, 25), restored_report);
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

#[test]
fn maintenance_recovers_signed_task_registration_and_policy_confirmation_after_revoke() {
    use trnm_protocol::qualified_work_task::{
        lifecycle_v2::{DemandLeaseV2, SignedLifecycleTaskV2}, TaskPurpose,
    };
    use trnm_crypto_primitives::{pon_work, qualified_work_task::derive_matrices};

    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let bootstrap = settings.bootstrap_lifecycle_task().unwrap();
    let mut node = Node::open(dir.path(), settings.clone(), 2).unwrap();
    // A second SQLite owner independently replays *real* PNW1 packet bytes.
    // This is a same-admin development client, not an independent operator.
    let verifier_path = dir.path().join("separate-verifier");
    let mut verifier = Node::open(&verifier_path, settings.clone(), 1).unwrap();
    let old_task = bootstrap.signed.manifest.matrix_task;
    let revoke = DemandRevocationV2 {
        network: settings.network(),
        parameters: settings.parameters(),
        slot: 0,
        demand_id: bootstrap.lease.demand_id,
        requester: bootstrap.lease.requester,
        expected_revision: bootstrap.lease.revision,
    };
    let revocation_tx = signed(&settings, 1, 1, 20, revoke.encode().unwrap());
    let first = mine(&mut node, 1, vec![revocation_tx]);
    let first_packet = node.packet(first).unwrap();
    assert_eq!(verifier.admit(&first_packet, 100_000).unwrap(), first);
    verifier.activate(first).unwrap();
    assert_eq!(verifier.read_active().unwrap(), node.read_active().unwrap());
    assert!(node.lifecycle_task_lease(node.active().unwrap().0, old_task, 2).is_err());

    // Fresh real signed requester and source statements, not a renewed or
    // fabricated old permission. The sole work source for this block is the
    // genesis maintenance task, with zero useful-output credit.
    let model: Vec<u8> = (0..4096_u32)
        .flat_map(|i| ((i * 11 + 7) % 97).to_le_bytes())
        .collect();
    let input: Vec<u8> = (0..4096_u32)
        .flat_map(|i| ((i * 17 + 5) % 101).to_le_bytes())
        .collect();
    let (a, b) = derive_matrices(&model, &input).unwrap();
    let mut successor: DemandLeaseV2 = bootstrap.lease.clone();
    successor.slot = 1;
    successor.generation = 2;
    successor.purpose = TaskPurpose::InferenceContraction;
    successor.requester = development_public(2).unwrap();
    successor.not_before = 2;
    successor.expires = 1002;
    successor.available_until = 1102;
    successor.demand_id = successor.derived_demand_id();
    let mut manifest = bootstrap.signed.manifest;
    manifest.purpose = successor.purpose;
    manifest.source = successor.source;
    manifest.demand_id = successor.demand_id;
    manifest.source_record = successor.bound_source_record().unwrap();
    manifest.model = hash(b"artifact", &[&model]);
    manifest.layer = QualifiedWorkTask::layer_id(manifest.model);
    manifest.input = hash(b"qualified-task-input-v1", &[&input]);
    manifest.matrix_task = pon_work::task_id(&a, &b).unwrap();
    manifest.availability_manifest = successor.availability_manifest;
    manifest.availability_root = successor.availability_root;
    manifest.authorization_scope = successor.authorization_scope;
    manifest.withdrawal_head = successor.withdrawal_frontier().unwrap();
    manifest.demand_nonce = 1;
    manifest.not_before = successor.not_before;
    manifest.expires = successor.expires;
    manifest.available_until = successor.available_until;
    manifest.useful_output_limit = successor.purpose.output_limit();
    manifest.output_meter = manifest.derived_output_meter();
    let mut signed_statement = SignedLifecycleTaskV2 {
        lease_id: successor.id().unwrap(),
        manifest,
        signature: [0; 64],
    };
    let source_key = signing_key_from_hex(
        &hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()])),
    )
    .unwrap();
    signed_statement.signature = hex::decode(sign_hex(
        &source_key,
        &signed_statement.signing_message().unwrap(),
    ))
    .unwrap()
    .try_into()
    .unwrap();
    let open_tx = signed(&settings, 2, 1, 18, successor.encode().unwrap());
    let register_tx = signed(&settings, 0, 1, 21, signed_statement.encode().unwrap());
    let include = mine(&mut node, 2, vec![open_tx, register_tx.clone()]);
    let registered_packet = node.packet(include).unwrap();
    assert_eq!(verifier.admit(&registered_packet, 100_000).unwrap(), include);
    verifier.activate(include).unwrap();
    assert_eq!(verifier.read_active().unwrap(), node.read_active().unwrap());
    assert!(node.lifecycle_task_lease(include, signed_statement.manifest.matrix_task, 3).is_ok());
    assert!(node.lifecycle_task_lease(include, old_task, 3).is_err());
    assert_eq!(
        node.read_active().unwrap().2[continuity_v1::MAINTENANCE_KEY]["useful_output_credit"],
        0,
    );
    for height in 3..=9 {
        let block = mine(&mut node, height, vec![]);
        let bytes = node.packet(block).unwrap().encode().unwrap();
        let independently_decoded = Packet::decode(&bytes).unwrap();
        assert_eq!(verifier.admit(&independently_decoded, 100_000).unwrap(), block);
        verifier.activate(block).unwrap();
        assert_eq!(verifier.read_active().unwrap(), node.read_active().unwrap());
    }
    // Invalid proof on an independently observed block cannot mutate
    // either owner; even a valid header must still pass the full W1 relation.
    let verified_before = verifier.read_active().unwrap();
    let mut corrupt = registered_packet.clone();
    let last = corrupt.proof.len() - 1;
    corrupt.proof[last] ^= 1;
    assert!(verifier.admit(&corrupt, 100_000).is_err());
    assert_eq!(verifier.read_active().unwrap(), verified_before);
    let confirmation = node.confirmation(hash(b"tx-id", &[&register_tx]), include, 100_000).unwrap();
    assert!(confirmation.confirmed);
    assert!(!confirmation.reorged);
    assert!(!confirmation.finalized);
    assert!(!confirmation.execution_authority);
    let independent_confirmation = verifier
        .confirmation(hash(b"tx-id", &[&register_tx]), include, 100_000)
        .unwrap();
    assert_eq!(independent_confirmation.transaction, confirmation.transaction);
    assert_eq!(independent_confirmation.included_block, confirmation.included_block);
    assert_eq!(independent_confirmation.observed_tip, confirmation.observed_tip);
    assert_eq!(independent_confirmation.required_work_delta, confirmation.required_work_delta);
    assert_eq!(independent_confirmation.work_delta, confirmation.work_delta);
    assert!(independent_confirmation.confirmed);
    assert!(!independent_confirmation.reorged);
    assert!(!independent_confirmation.finalized);
    assert!(!independent_confirmation.execution_authority);
    let before = node.read_active().unwrap();
    assert_eq!(verifier.read_active().unwrap(), before);
    drop(node);
    drop(verifier);
    let reopened = Node::open(dir.path(), settings.clone(), 1).unwrap();
    let independent_reopened = Node::open(&verifier_path, settings, 1).unwrap();
    assert_eq!(reopened.read_active().unwrap(), before);
    assert_eq!(independent_reopened.read_active().unwrap(), before);
    assert!(reopened.confirmation(hash(b"tx-id", &[&register_tx]), include, 100_000)
        .unwrap().confirmed);
    assert!(independent_reopened
        .confirmation(hash(b"tx-id", &[&register_tx]), include, 100_000)
        .unwrap().confirmed);
}

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
