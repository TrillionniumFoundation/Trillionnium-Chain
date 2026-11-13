//! Revocation and reward-maturity continuity through actual signed admission,
//! authenticated storage, interrupted reorganization and cold recovery.
//! This installed-genesis fixture is separate from the 65,536-key capacity test.
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::{continuity_v1, qualified_task_lifecycle};
use trnm_pon_node::{development_public, Error, ErrorCode, Node, Settings};
use trnm_protocol::{
    pon_wire::{hash, Envelope, Hash},
    qualified_work_task::lifecycle_v2::DemandRevocationV2,
};

fn public(owner: u64) -> Hash {
    development_public(owner).unwrap()
}
fn signed(
    settings: &Settings,
    owner: u64,
    account_sequence: u64,
    tag: u8,
    payload: Vec<u8>,
) -> Vec<u8> {
    let mut tx = Envelope {
        network: settings.network(),
        sender: public(owner),
        nonce: account_sequence,
        expiry: 2000,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&owner.to_le_bytes()]))).unwrap();
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}
fn admit_pair(
    reference: &mut Node,
    native: &mut Node,
    parent: Hash,
    height: u64,
    txs: Vec<Vec<u8>>,
    miner: Hash,
    timestamp_offset: u64,
) -> Hash {
    let packet = reference
        .make_consensus_maintenance(parent, txs, miner, 1 + height * 10 + timestamp_offset, 4096)
        .unwrap();
    assert_eq!(
        packet.header.work_task,
        continuity_v1::maintenance_task().unwrap()
    );
    let id = reference.admit(&packet, 100_000).unwrap();
    assert_eq!(native.admit(&packet, 100_000).unwrap(), id);
    assert_eq!(
        reference.state_at(id).unwrap(),
        native.state_at(id).unwrap()
    );
    id
}

#[test]
fn revoked_optional_work_keeps_maintenance_maturity_and_interrupted_native_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap();
    let mut reference = Node::open(&dir.path().join("reference"), settings.clone(), 1).unwrap();
    let path = dir.path().join("authenticated");
    let mut native = Node::open_with_authenticated_state(&path, settings.clone(), 2).unwrap();
    let bootstrap = settings.bootstrap_lifecycle_task().unwrap();
    let revoked_task = bootstrap.signed.manifest.matrix_task;
    let revoke = DemandRevocationV2 {
        network: settings.network(),
        parameters: settings.parameters(),
        slot: 0,
        demand_id: bootstrap.lease.demand_id,
        requester: bootstrap.lease.requester,
        expected_revision: bootstrap.lease.revision,
    };
    let tx = signed(&settings, 1, 1, 20, revoke.encode().unwrap());
    let mut parent = settings.genesis();
    let recipient_key = format!("account:{}", hex::encode(public(999)));
    assert!(!native.read_active().unwrap().2.contains_key(&recipient_key));
    for height in 1..=21 {
        let txs = if height == 1 {
            vec![tx.clone()]
        } else {
            vec![]
        };
        let miner = public(if height == 1 { 999 } else { 0 });
        let id = admit_pair(&mut reference, &mut native, parent, height, txs, miner, 0);
        reference.activate(id).unwrap();
        native.activate(id).unwrap();
        assert_eq!(
            native.read_active().unwrap(),
            reference.read_active().unwrap()
        );
        assert_eq!(
            native
                .lifecycle_task_lease(id, revoked_task, height + 1)
                .unwrap_err()
                .to_string(),
            "TASK"
        );
        let state = native.read_active().unwrap().2;
        assert_eq!(
            state[continuity_v1::MAINTENANCE_KEY]["useful_output_credit"],
            0
        );
        let slot = &state[&qualified_task_lifecycle::slot_key(0).unwrap()];
        assert_eq!(slot["status"], "revoked");
        assert_eq!(slot["output_count"], 0);
        if height < 21 {
            assert!(!state.contains_key(&recipient_key));
        }
        parent = id;
        if height == 2 {
            let before = native.read_active().unwrap();
            drop(native);
            native = Node::open_with_authenticated_state(&path, settings.clone(), 1).unwrap();
            assert_eq!(native.read_active().unwrap(), before);
        }
    }
    let mature = native.read_active().unwrap();
    let reward = mature.2[&recipient_key]["balance"].as_u64().unwrap();
    assert!(reward > 1_000);
    assert_eq!(mature.2[&recipient_key]["nonce"], 0);
    let mut payload = public(1000).to_vec();
    payload.extend(1u64.to_le_bytes());
    let spend = signed(&settings, 999, 1, 1, payload);
    let main22 = admit_pair(
        &mut reference,
        &mut native,
        parent,
        22,
        vec![spend],
        public(0),
        0,
    );
    reference.activate(main22).unwrap();
    native.activate(main22).unwrap();
    let spent = native.read_active().unwrap();
    assert_eq!(spent.2[&recipient_key]["nonce"], 1);
    assert_eq!(
        spent.2[&format!("account:{}", hex::encode(public(1000)))]["balance"],
        1
    );
    // Read cancellation is not a structural failure and cannot mutate the view.
    let error = native
        .capacity_observation_with_progress(&mut || {
            Err(Error::new(ErrorCode::PublicRequestCancelled))
        })
        .unwrap_err();
    assert!(error.is(ErrorCode::PublicRequestCancelled));
    assert!(!error.requires_owner_stop());
    assert_eq!(native.read_active().unwrap(), spent);
    let fork22 = admit_pair(
        &mut reference,
        &mut native,
        parent,
        22,
        vec![],
        public(0),
        1,
    );
    assert_eq!(native.activate(fork22).unwrap(), main22);
    let fork23 = admit_pair(
        &mut reference,
        &mut native,
        fork22,
        23,
        vec![],
        public(0),
        0,
    );
    let mut cuts = 0;
    let error = native
        .activate_with_fault(
            fork23,
            Some(&mut |point| {
                if point == "detach:0" {
                    cuts += 1;
                    Err(Error::from("CONTINUITY_NATIVE_REORG_CUT"))
                } else {
                    Ok(())
                }
            }),
        )
        .unwrap_err();
    assert_eq!(error.to_string(), "CONTINUITY_NATIVE_REORG_CUT");
    assert_eq!(cuts, 1);
    assert_eq!(native.read_active().unwrap(), spent);
    drop(native);
    native = Node::open_with_authenticated_state(&path, settings.clone(), 1).unwrap();
    reference.activate(fork23).unwrap();
    assert_eq!(
        native.read_active().unwrap(),
        reference.read_active().unwrap()
    );
    let recovered = native.read_active().unwrap();
    assert_eq!(recovered.0, fork23);
    assert_eq!(recovered.2[&recipient_key]["nonce"], 0);
    assert_eq!(recovered.2[&recipient_key]["balance"], reward);
    assert!(!recovered
        .2
        .contains_key(&format!("account:{}", hex::encode(public(1000)))));
    assert_eq!(native.state_at(main22).unwrap(), spent.2);
    assert_eq!(
        native
            .lifecycle_task_lease(fork23, revoked_task, 24)
            .unwrap_err()
            .to_string(),
        "TASK"
    );
    drop(native);
    let native = Node::open_with_authenticated_state(&path, settings, 1).unwrap();
    assert_eq!(native.read_active().unwrap(), recovered);
    eprintln!("native continuity: admitted_packets=24, signed_transactions=2, all_optional_tasks_revoked=true, maturity_height=21, reorg_cut=detach:0, cold_reopens=3, useful_output_credit=0, full_capacity=false");
}
/// PN0/P0-A: Maintenance must carry honest signed task re-entry after all
/// optional work is revoked, not merely emit empty blocks. A second durable
/// native backend and a third, fresh independently replaying client check the
/// same actual PNW1 packet bytes and installed depth+work confirmation policy.
/// This does not grant source/operator independence or W1 hardness qualification.
#[test]
fn maintenance_reentry_registers_signed_task_and_independent_client_confirms() {
    use trnm_crypto_primitives::qualified_work_task::{
        derive_matrices, lifecycle_v2::verify_lifecycle_admission, TaskMaterial,
    };
    use trnm_protocol::qualified_work_task::{
        lifecycle_v2::SignedLifecycleTaskV2, QualifiedWorkTask, TaskPurpose,
    };

    let dir = tempfile::tempdir().unwrap();
    let settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap();
    let bootstrap = settings.bootstrap_lifecycle_task().unwrap();
    let revoked_task = bootstrap.signed.manifest.matrix_task;

    // Construct a new source-authenticated demand from canonical public test
    // keys. No extension, impersonation or silent renewal of the revoked lease.
    let mut lease = bootstrap.lease.clone();
    lease.slot = 1;
    lease.generation = 2;
    lease.purpose = TaskPurpose::InferenceContraction;
    lease.not_before = 1;
    lease.expires = 1001;
    lease.available_until = 1101;
    lease.demand_id = lease.derived_demand_id();
    let model: Vec<u8> = (0..4096_u32)
        .flat_map(|i| ((i * 11 + 7) % 97).to_le_bytes())
        .collect();
    let input: Vec<u8> = (0..4096_u32)
        .flat_map(|i| ((i * 17 + 5) % 101).to_le_bytes())
        .collect();
    let (a, b) = derive_matrices(&model, &input).unwrap();
    let new_task = trnm_crypto_primitives::pon_work::task_id(&a, &b).unwrap();
    assert_ne!(new_task, revoked_task);
    assert_ne!(new_task, continuity_v1::maintenance_task().unwrap());

    let mut manifest = bootstrap.signed.manifest;
    manifest.purpose = lease.purpose;
    manifest.source = lease.source;
    manifest.demand_id = lease.demand_id;
    manifest.source_record = lease.bound_source_record().unwrap();
    manifest.model = hash(b"artifact", &[&model]);
    manifest.layer = QualifiedWorkTask::layer_id(manifest.model);
    manifest.input = hash(b"qualified-task-input-v1", &[&input]);
    manifest.matrix_task = new_task;
    manifest.authorization_scope = lease.authorization_scope;
    manifest.availability_manifest = lease.availability_manifest;
    manifest.availability_root = lease.availability_root;
    manifest.withdrawal_head = lease.withdrawal_frontier().unwrap();
    manifest.not_before = lease.not_before;
    manifest.expires = lease.expires;
    manifest.available_until = lease.available_until;
    manifest.demand_nonce = 1;
    manifest.useful_output_limit = lease.purpose.output_limit();
    manifest.output_meter = manifest.derived_output_meter();

    let mut statement = SignedLifecycleTaskV2 {
        lease_id: lease.id().unwrap(),
        manifest,
        signature: [0; 64],
    };
    let source_key = signing_key_from_hex(&hex::encode(hash(
        b"DEV-ONLY-KEY",
        &[&0_u64.to_le_bytes()],
    )))
    .unwrap();
    statement.signature = hex::decode(sign_hex(
        &source_key,
        &statement.signing_message().unwrap(),
    ))
    .unwrap()
    .try_into()
    .unwrap();

    let revoke = DemandRevocationV2 {
        network: settings.network(),
        parameters: settings.parameters(),
        slot: bootstrap.lease.slot,
        demand_id: bootstrap.lease.demand_id,
        requester: bootstrap.lease.requester,
        expected_revision: bootstrap.lease.revision,
    };
    let revoke_tx = signed(&settings, 1, 1, 20, revoke.encode().unwrap());
    let open_tx = signed(&settings, 1, 2, 18, lease.encode().unwrap());
    let registration_tx = signed(&settings, 0, 1, 21, statement.encode().unwrap());
    let revoke_id = hash(b"tx-id", &[&revoke_tx]);
    let open_id = hash(b"tx-id", &[&open_tx]);
    let registration_id = hash(b"tx-id", &[&registration_tx]);

    let mut reference =
        Node::open(&dir.path().join("reference"), settings.clone(), 1).unwrap();
    let mut native = Node::open_with_authenticated_state(
        &dir.path().join("native"),
        settings.clone(),
        2,
    )
    .unwrap();
    // Forecast only from the fully checked actual parent. This report is not
    // a signer or dispatcher; real signed tag22 admission remains elsewhere.
    let mut advisory_successor = bootstrap.lease.clone();
    advisory_successor.revision += 1;
    advisory_successor.not_before = 1;
    advisory_successor.expires = 1001;
    advisory_successor.available_until = 1101;
    let (advisory_tip, advisory_generation, advisory) = native
        .forecast_q4_renewal_from_active(revoked_task, &advisory_successor, 5, 10)
        .unwrap();
    assert_eq!(advisory_tip, settings.genesis());
    assert_eq!(advisory_generation, native.active().unwrap().1);
    assert_eq!(
        advisory.phase,
        trnm_pon_node::Q4RenewalPhase::WindowOpenByTime
    );
    assert_eq!(advisory.last_legal_height, 1000);

    let mut parent = settings.genesis();
    let mut admitted = Vec::new();
    let mut revoke_block = None;
    let mut registered_block = None;

    for height in 1..=9 {
        let txs = match height {
            1 => vec![revoke_tx.clone()],
            2 => vec![open_tx.clone(), registration_tx.clone()],
            _ => vec![],
        };
        let id = admit_pair(
            &mut reference,
            &mut native,
            parent,
            height,
            txs,
            public(0),
            0,
        );
        reference.activate(id).unwrap();
        native.activate(id).unwrap();
        if height == 1 {
            revoke_block = Some(id);
            assert!(native
                .lifecycle_task_lease(id, revoked_task, 2)
                .is_err());
            assert!(native
                .forecast_q4_renewal_from_active(
                    revoked_task,
                    &advisory_successor,
                    0,
                    0,
                )
                .is_err());
        }
        if height == 2 {
            registered_block = Some(id);
            assert!(native
                .lifecycle_task_lease(id, new_task, 3)
                .is_ok());
        }
        assert_eq!(
            native.read_active().unwrap(),
            reference.read_active().unwrap()
        );
        admitted.push(id);
        parent = id;
    }

    // Registration is not sufficient to close P0-A: actually produce the first
    // qualified W1 block under the NEW signed task after Maintenance reentry.
    let checked = verify_lifecycle_admission(
        &statement.encode().unwrap(),
        TaskMaterial { model: &model, input: &input, a: &a, b: &b },
        &lease,
        10,
    ).unwrap();
    let new_work = reference.make_with_task(
        parent,
        vec![],
        public(0),
        101,
        4096,
        &checked,
        TaskMaterial { model: &model, input: &input, a: &a, b: &b },
    ).unwrap();
    assert_eq!(new_work.header.work_task, new_task);
    let new_id = reference.admit(&new_work, 100_000).unwrap();
    assert_eq!(native.admit(&new_work, 100_000).unwrap(), new_id);
    reference.activate(new_id).unwrap();
    native.activate(new_id).unwrap();
    assert_eq!(native.read_active().unwrap(), reference.read_active().unwrap());
    let slot = qualified_task_lifecycle::slot_key(1).unwrap();
    let active = native.read_active().unwrap();
    assert_eq!(active.2[&slot]["output_count"], 1);
    admitted.push(new_id);
    parent = new_id;

    // A freshly opened independent consumer independently checks each actual
    // signed PNX1 / full PNW1 packet, not producer status or a hand-entered
    // confirmation Boolean. All accepted bytes remain bound to Revision12.
    let mut consumer = Node::open_with_authenticated_state(
        &dir.path().join("consumer"),
        settings.clone(),
        1,
    )
    .unwrap();
    for id in admitted {
        let packet = reference.packet(id).unwrap();
        assert_eq!(consumer.admit(&packet, 100_000).unwrap(), id);
        consumer.activate(id).unwrap();
    }
    assert_eq!(
        consumer.read_active().unwrap(),
        native.read_active().unwrap()
    );
    assert!(consumer
        .lifecycle_task_lease(parent, revoked_task, 11)
        .is_err());
    let admitted_lease = consumer
        .lifecycle_task_lease(parent, new_task, 11)
        .unwrap();
    assert_eq!(admitted_lease.slot, 1);
    assert_eq!(admitted_lease.generation, 2);

    for (transaction, included) in [
        (revoke_id, revoke_block.unwrap()),
        (open_id, registered_block.unwrap()),
        (registration_id, registered_block.unwrap()),
    ] {
        let receipt = consumer
            .confirmation(transaction, included, 100_000)
            .unwrap();
        assert!(receipt.confirmed);
        assert!(!receipt.reorged);
        assert!(!receipt.finalized);
        assert!(!receipt.execution_authority);
        assert_eq!(receipt.observed_tip, hex::encode(parent));
    }
    drop(consumer);
    let cold = Node::open_with_authenticated_state(
        &dir.path().join("consumer"),
        settings,
        1,
    )
    .unwrap();
    assert_eq!(cold.read_active().unwrap(), native.read_active().unwrap());
    assert!(cold
        .lifecycle_task_lease(parent, new_task, 11)
        .is_ok());
}


/// P0-B: all 32 original demand slots are occupied by actual signed main
/// envelopes, then both native backends must reject an early replacement.
/// Genesis maintenance is still a permitted next-block work source. Unlike
/// the M06 pure transition test, this exercises real PNW1 and cold persistence.
/// It grants no independent signer, public network or production authority.
#[test]
fn full_32_slot_maintenance_rejects_premature_native_replacement() {
    use trnm_protocol::qualified_work_task::lifecycle_v2::DEMAND_SLOTS;

    let dir = tempfile::tempdir().unwrap();
    let settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap();
    let bootstrap = settings.bootstrap_lifecycle_task().unwrap();
    let opens: Vec<Vec<u8>> = (1..DEMAND_SLOTS)
        .map(|slot| {
            let mut lease = bootstrap.lease.clone();
            lease.slot = slot;
            lease.generation = u64::from(slot) + 1;
            lease.not_before = 1;
            lease.expires = 1001;
            lease.available_until = 1101;
            lease.demand_id = lease.derived_demand_id();
            signed(&settings, 1, u64::from(slot), 18, lease.encode().unwrap())
        })
        .collect();
    assert_eq!(opens.len(), usize::from(DEMAND_SLOTS) - 1);

    let mut reference = Node::open(&dir.path().join("reference"), settings.clone(), 1).unwrap();
    let native_path = dir.path().join("native");
    let mut native =
        Node::open_with_authenticated_state(&native_path, settings.clone(), 2).unwrap();
    let full = admit_pair(
        &mut reference,
        &mut native,
        settings.genesis(),
        1,
        opens,
        public(0),
        0,
    );
    reference.activate(full).unwrap();
    native.activate(full).unwrap();
    let before = native.read_active().unwrap();
    assert_eq!(reference.read_active().unwrap(), before);
    assert_eq!(
        before.2[qualified_task_lifecycle::GENERATION_KEY],
        32
    );
    assert_eq!(
        before
            .2
            .keys()
            .filter(|key| key.starts_with("qualified-demand-slot-v2:"))
            .count(),
        usize::from(DEMAND_SLOTS)
    );

    let mut successor = bootstrap.lease.clone();
    successor.generation = 33;
    successor.revision = 1;
    successor.not_before = 2;
    successor.expires = 1002;
    successor.available_until = 1102;
    successor.demand_id = successor.derived_demand_id();
    let premature = signed(&settings, 1, 32, 18, successor.encode().unwrap());
    for node in [&reference, &native] {
        assert_eq!(
            node.make_consensus_maintenance(
                full,
                vec![premature.clone()],
                public(0),
                21,
                4096,
            )
            .unwrap_err()
            .to_string(),
            "TASK_RETAINED"
        );
        assert_eq!(node.read_active().unwrap(), before);
    }

    let maintenance =
        admit_pair(&mut reference, &mut native, full, 2, vec![], public(0), 0);
    reference.activate(maintenance).unwrap();
    native.activate(maintenance).unwrap();
    assert_eq!(reference.read_active().unwrap(), native.read_active().unwrap());
    assert_eq!(
        native.read_active().unwrap().2[qualified_task_lifecycle::GENERATION_KEY],
        32
    );
    let before_reopen = native.read_active().unwrap();
    drop(native);
    let reopened = Node::open_with_authenticated_state(&native_path, settings, 1).unwrap();
    assert_eq!(reopened.read_active().unwrap(), before_reopen);
}


/// Release-only native evidence for all Q4 slots exhausted, last-source
/// revocation, exact 1100/1101 retention cut, heavier reorg, reauthorization
/// and cold recovery. Uses real W1 packets, not a synthetic height leap.
#[test]
#[ignore = "release-only 1103-block native Q4 retention and reorg campaign"]
fn full_slot_native_retention_reclaim_and_heavier_fork_restore() {
    use trnm_protocol::qualified_work_task::lifecycle_v2::DEMAND_SLOTS;

    let dir = tempfile::tempdir().unwrap();
    let settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap();
    let boot = settings.bootstrap_lifecycle_task().unwrap();
    let mut reference = Node::open(&dir.path().join("reference"), settings.clone(), 1).unwrap();
    let native_path = dir.path().join("native");
    let mut native =
        Node::open_with_authenticated_state(&native_path, settings.clone(), 2).unwrap();
    let opens: Vec<Vec<u8>> = (1..DEMAND_SLOTS)
        .map(|slot| {
            let mut lease = boot.lease.clone();
            lease.slot = slot;
            lease.generation = u64::from(slot) + 1;
            lease.not_before = 1;
            lease.expires = 1001;
            lease.available_until = 1101;
            lease.demand_id = lease.derived_demand_id();
            signed(&settings, 1, u64::from(slot), 18, lease.encode().unwrap())
        })
        .collect();
    let mut tip = admit_pair(
        &mut reference,
        &mut native,
        settings.genesis(),
        1,
        opens,
        public(0),
        0,
    );
    reference.activate(tip).unwrap();
    native.activate(tip).unwrap();
    let revoke = DemandRevocationV2 {
        network: settings.network(),
        parameters: settings.parameters(),
        slot: 0,
        demand_id: boot.lease.demand_id,
        requester: boot.lease.requester,
        expected_revision: boot.lease.revision,
    };
    tip = admit_pair(
        &mut reference,
        &mut native,
        tip,
        2,
        vec![signed(&settings, 1, 32, 20, revoke.encode().unwrap())],
        public(0),
        0,
    );
    reference.activate(tip).unwrap();
    native.activate(tip).unwrap();
    assert_eq!(
        native.read_active().unwrap().2[&qualified_task_lifecycle::slot_key(0).unwrap()]["status"],
        "revoked"
    );
    for height in 3..=1099 {
        tip = admit_pair(&mut reference, &mut native, tip, height, vec![], public(0), 0);
        reference.activate(tip).unwrap();
        native.activate(tip).unwrap();
    }

    let mut successor = boot.lease.clone();
    successor.generation = 33;
    successor.revision = 1;
    successor.not_before = 1101;
    successor.expires = 2101;
    successor.available_until = 2201;
    successor.demand_id = successor.derived_demand_id();
    let authorized = signed(&settings, 1, 33, 18, successor.encode().unwrap());
    assert_eq!(
        reference
            .make_consensus_maintenance(tip, vec![authorized.clone()], public(0), 11001, 4096)
            .unwrap_err()
            .to_string(),
        "TASK_RETAINED"
    );
    let retained = admit_pair(&mut reference, &mut native, tip, 1100, vec![], public(0), 0);
    reference.activate(retained).unwrap();
    native.activate(retained).unwrap();
    let replacement = admit_pair(
        &mut reference,
        &mut native,
        retained,
        1101,
        vec![authorized],
        public(0),
        0,
    );
    reference.activate(replacement).unwrap();
    native.activate(replacement).unwrap();
    assert_eq!(reference.read_active().unwrap(), native.read_active().unwrap());
    assert_eq!(
        native.read_active().unwrap().2[qualified_task_lifecycle::GENERATION_KEY],
        33
    );

    // Two original PNW1 fork packets beat the shorter replacement branch;
    // rollback restores generation 32, old revoked slot and requester nonce.
    let fork_1101 =
        admit_pair(&mut reference, &mut native, retained, 1101, vec![], public(0), 1);
    let fork_1102 =
        admit_pair(&mut reference, &mut native, fork_1101, 1102, vec![], public(0), 1);
    reference.activate(fork_1102).unwrap();
    native.activate(fork_1102).unwrap();
    assert_eq!(reference.read_active().unwrap(), native.read_active().unwrap());
    assert_eq!(
        native.read_active().unwrap().2[qualified_task_lifecycle::GENERATION_KEY],
        32
    );
    assert_eq!(
        native.read_active().unwrap().2[&qualified_task_lifecycle::slot_key(0).unwrap()]["status"],
        "revoked"
    );

    // The original transaction had signed not_before=1101, so at 1103 it
    // cannot be silently reissued. This is a new signed operation at 1103.
    successor.not_before = 1103;
    successor.expires = 2103;
    successor.available_until = 2203;
    successor.demand_id = successor.derived_demand_id();
    let new_authorization = signed(&settings, 1, 33, 18, successor.encode().unwrap());
    let recovered = admit_pair(
        &mut reference,
        &mut native,
        fork_1102,
        1103,
        vec![new_authorization],
        public(0),
        1,
    );
    reference.activate(recovered).unwrap();
    native.activate(recovered).unwrap();
    assert_eq!(reference.read_active().unwrap(), native.read_active().unwrap());
    assert_eq!(
        native.read_active().unwrap().2[qualified_task_lifecycle::GENERATION_KEY],
        33
    );
    let snapshot = native.read_active().unwrap();
    drop(native);
    let cold = Node::open_with_authenticated_state(&native_path, settings, 1).unwrap();
    assert_eq!(cold.read_active().unwrap(), snapshot);
}
