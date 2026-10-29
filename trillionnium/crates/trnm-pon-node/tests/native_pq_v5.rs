//! Genuine dual-PQ task permission -> ordinary M05/M06/W1/SQL/cold/reorg paths.
//! Public deterministic test keys and matrix materials; no real-demand claim.
use rusqlite::{Connection, OpenFlags};
use trnm_crypto_primitives::{pon_work, qualified_work_task::pq_lifecycle_v5 as crypto};
use trnm_mvcc_fee::pon_executor::{pq_accounts_v2::tasks_v5 as tasks, State};
use trnm_pon_node::{
    pq_accounts_v2::{GenesisAccount, PqNodeV2, PqPacketV2},
    pq_quota_v3::{PqNodeV3, PqPacketV3},
    pq_tasks_v4::{PqNodeV4, PqPacketV4},
    pq_tasks_v5::{PqNodeV5, PqPacketV5},
    Error, Node, Packet, PoolLimits, Settings,
};
use trnm_protocol::{
    pon_wire::Hash, pq_native_accounts_v2 as wire,
    qualified_work_task::pq_lifecycle_v5::DemandLeaseV5,
};
#[path = "../../trnm-protocol/tests/support/native_pq_task_fixture_v5.rs"]
mod fixture;
use fixture::{Key, Witness};

fn setup() -> (Settings, [Key; 3]) {
    let keys = [
        Key::public_test_seed(221),
        Key::public_test_seed(222),
        Key::public_test_seed(223),
    ];
    let accounts: Vec<_> = keys
        .iter()
        .map(|k| GenesisAccount {
            spki: k.spki.clone(),
            balance: 100_000_000,
        })
        .collect();
    (Settings::native_pq_tasks_v5(&accounts, 1000).unwrap(), keys)
}
fn limits(miner: Hash) -> PoolLimits {
    PoolLimits {
        max_records: 256,
        max_bytes: 524288,
        max_group_members: 16,
        critical_reserve: 0,
        max_removals: 256,
        preview_miner: miner,
    }
}
fn account(state: &State, id: Hash) -> &serde_json::Value {
    &state[&format!("account:{}", hex::encode(id))]
}
fn task() -> Hash {
    let (_, _, a, b) = fixture::material();
    pon_work::task_id(&a, &b).unwrap()
}
fn sign(
    s: &Settings,
    requester: Hash,
    nonce: u64,
    generation: u64,
    kind: u8,
    payload: &[u8],
    witnesses: &[Witness<'_>],
) -> Vec<u8> {
    fixture::signed(
        &fixture::common(
            s.native_pq_accounts_context().unwrap(),
            requester,
            nonce,
            generation,
        ),
        kind,
        payload,
        witnesses,
        None,
    )
}
fn open(s: &Settings, lease: &DemandLeaseV5, requester: &Key, nonce: u64) -> Vec<u8> {
    sign(
        s,
        lease.requester,
        nonce,
        1,
        18,
        &lease.encode().unwrap(),
        &[fixture::primary(requester, 1)],
    )
}
fn register(s: &Settings, lease: &DemandLeaseV5, requester: &Key, source: &Key) -> Vec<u8> {
    sign(
        s,
        lease.requester,
        2,
        1,
        21,
        &fixture::registration(lease, task(), 1, [0; 32])
            .encode()
            .unwrap(),
        &[fixture::primary(requester, 1), fixture::source(source, 1)],
    )
}
struct RevocationRow {
    ordinal: i64,
    lineage: Vec<u8>,
    lease: Vec<u8>,
    revision: i64,
    demand: Vec<u8>,
    block: Vec<u8>,
    generation: i64,
}
fn read_revocation_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RevocationRow> {
    Ok(RevocationRow {
        ordinal: row.get(0)?,
        lineage: row.get(1)?,
        lease: row.get(2)?,
        revision: row.get(3)?,
        demand: row.get(4)?,
        block: row.get(5)?,
        generation: row.get(6)?,
    })
}
fn sql(path: &std::path::Path) -> Connection {
    Connection::open_with_flags(path.join("native.sqlite"), OpenFlags::SQLITE_OPEN_READ_ONLY)
        .unwrap()
}
fn check_and_admit(
    node: &mut PqNodeV5,
    packet: &PqPacketV5,
    started: std::time::Instant,
    phase: &str,
) {
    pon_work::verify_reference(
        packet.header().challenge(),
        packet.header().work_task,
        packet.header().target,
        packet.proof(),
    )
    .unwrap();
    assert_eq!(node.admit(packet, 10_000).unwrap(), packet.id().unwrap());
    println!(
        "{}",
        serde_json::json!({"schema":"native-pq5-actual-phase-v1", "phase":phase,
        "transactions":packet.transactions().len(),"raw_bytes":packet.transactions().iter().map(Vec::len).sum::<usize>(),
        "proof_bytes":packet.proof().len(),"packet_bytes":packet.encode().unwrap().len(),"wall_nanoseconds":started.elapsed().as_nanos(),
        "block":hex::encode(packet.id().unwrap()),"scope":"actual shared-host complete W1/reference/admit/SQL; not isolated worst-case cost"})
    );
}
fn admitted(
    node: &mut PqNodeV5,
    parent: Hash,
    rows: Vec<Vec<u8>>,
    miner: Hash,
    time: u64,
) -> PqPacketV5 {
    let started = std::time::Instant::now();
    let packet = node.make(parent, rows, miner, time, 4096).unwrap();
    check_and_admit(node, &packet, started, "maintenance");
    packet
}
fn material_admitted(node: &mut PqNodeV5, parent: Hash, miner: Hash, time: u64) -> PqPacketV5 {
    let (model, input, _, _) = fixture::material();
    let started = std::time::Instant::now();
    let packet = node
        .make_with_registered_material(parent, vec![], miner, time, 4096, &model, &input)
        .unwrap();
    check_and_admit(node, &packet, started, "registered-material");
    packet
}
fn registered(
    node: &mut PqNodeV5,
    s: &Settings,
    keys: &[Key; 3],
) -> (DemandLeaseV5, PqPacketV5, PqPacketV5, Vec<u8>) {
    let lease = fixture::lease(
        s.native_pq_accounts_context().unwrap(),
        keys[0].id,
        keys[1].id,
    );
    let opened = admitted(
        node,
        s.genesis(),
        vec![open(s, &lease, &keys[0], 1)],
        keys[2].id,
        1001,
    );
    node.activate(opened.id().unwrap()).unwrap();
    let raw = register(s, &lease, &keys[0], &keys[1]);
    let registration = admitted(
        node,
        opened.id().unwrap(),
        vec![raw.clone()],
        keys[2].id,
        1002,
    );
    node.activate(registration.id().unwrap()).unwrap();
    (lease, opened, registration, raw)
}

#[test]
fn dual_pq_task_pool_ordinary_material_actual_w1_output_and_cold_read_form_one_namespace() {
    let dir = tempfile::tempdir().unwrap();
    let (s, keys) = setup();
    let mut node = PqNodeV5::open(dir.path(), s.clone(), 1).unwrap();
    node.enable_local_mempool(limits(keys[2].id)).unwrap();
    let lease = fixture::lease(
        s.native_pq_accounts_context().unwrap(),
        keys[0].id,
        keys[1].id,
    );
    let opened = admitted(
        &mut node,
        s.genesis(),
        vec![open(&s, &lease, &keys[0], 1)],
        keys[2].id,
        1001,
    );
    node.activate(opened.id().unwrap()).unwrap();
    let before = node.state_at(opened.id().unwrap()).unwrap();
    let raw = register(&s, &lease, &keys[0], &keys[1]);
    let mut bad = raw.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(node.pool_submit(bad).is_err());
    assert!(node
        .pool_submit(register(&s, &lease, &keys[0], &keys[2]))
        .is_err());
    assert!(node.pool_status().unwrap().groups.is_empty());
    assert_eq!(node.state_at(opened.id().unwrap()).unwrap(), before);
    let receipt = node.pool_submit(raw.clone()).unwrap();
    assert_eq!(receipt.typed_gate_admissions, 1);
    let batch = node
        .pool_mining_batch(opened.id().unwrap(), node.active().unwrap().1, 256, 524288)
        .unwrap();
    assert_eq!(batch.transactions, vec![raw.clone()]);
    assert_eq!(node.pool_validate_batch(&batch).unwrap(), 1);
    let registration = admitted(
        &mut node,
        opened.id().unwrap(),
        batch.transactions,
        keys[2].id,
        1002,
    );
    node.activate(registration.id().unwrap()).unwrap();
    let state = node.state_at(registration.id().unwrap()).unwrap();
    assert_eq!(account(&state, keys[0].id)["nonce"], 2);
    assert_eq!(account(&state, keys[1].id), account(&before, keys[1].id));
    let witnesses: Vec<_> = state
        .iter()
        .filter(|(k, _)| k.starts_with(tasks::WITNESS_PREFIX))
        .collect();
    assert_eq!(witnesses.len(), 5);
    assert_eq!(
        witnesses
            .iter()
            .flat_map(|(_, v)| hex::decode(v.as_str().unwrap()).unwrap())
            .collect::<Vec<_>>(),
        raw
    );
    drop(node);
    let mut node = PqNodeV5::open(dir.path(), s.clone(), 1).unwrap();
    assert_eq!(node.state_at(registration.id().unwrap()).unwrap(), state);
    let (mut model, input, _, _) = fixture::material();
    model[0] ^= 1;
    assert!(node
        .make_with_registered_material(
            registration.id().unwrap(),
            vec![],
            keys[2].id,
            1003,
            4096,
            &model,
            &input
        )
        .is_err());
    let worked = material_admitted(&mut node, registration.id().unwrap(), keys[2].id, 1003);
    node.activate(worked.id().unwrap()).unwrap();
    let worked_state = node.state_at(worked.id().unwrap()).unwrap();
    let row = &worked_state[&tasks::slot_key(0).unwrap()];
    assert_eq!(row["output_count"], 1);
    assert_eq!(row["output_height"], 3);
    assert_ne!(row["output_product"], hex::encode([0; 32]));
    let repeated = material_admitted(&mut node, worked.id().unwrap(), keys[2].id, 1004);
    node.activate(repeated.id().unwrap()).unwrap();
    assert_eq!(
        node.state_at(repeated.id().unwrap()).unwrap()[&tasks::slot_key(0).unwrap()],
        *row
    );
    let stored: Vec<u8> = sql(dir.path())
        .query_row(
            "SELECT packet FROM blocks WHERE id=?",
            [worked.id().unwrap().as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stored, worked.encode().unwrap());
    assert!(stored.starts_with(b"PQP5\x05\0\0\0"));
    assert!(PqPacketV4::decode(&stored).is_err());
    assert!(PqPacketV3::decode(&stored).is_err());
    assert!(PqPacketV2::decode(&stored).is_err());
    assert!(Packet::decode(&stored).is_err());
    let final_state = node.state_at(repeated.id().unwrap()).unwrap();
    drop(node);
    let node = PqNodeV5::open(dir.path(), s, 1).unwrap();
    assert_eq!(node.state_at(repeated.id().unwrap()).unwrap(), final_state);
}

#[test]
fn actual_source_rotation_new_dual_proofs_and_heavier_fork_reauthorize_from_cold_state() {
    let dir = tempfile::tempdir().unwrap();
    let (s, keys) = setup();
    let mut node = PqNodeV5::open(dir.path(), s.clone(), 1).unwrap();
    node.enable_local_mempool(limits(keys[2].id)).unwrap();
    let (lease, _, registration, raw) = registered(&mut node, &s, &keys);
    let registered_id = registration.id().unwrap();
    let prior = crypto::statement_id(&raw).unwrap();
    let next = Key::public_test_seed(224);
    let rotation = sign(
        &s,
        keys[1].id,
        1,
        1,
        wire::ROTATE,
        &[
            2_u64.to_be_bytes().as_slice(),
            &node.authority_digest(registered_id, keys[1].id).unwrap(),
        ]
        .concat(),
        &[
            Witness {
                key: &keys[1],
                role: 3,
                generation: 1,
                carried: false,
            },
            Witness {
                key: &next,
                role: 4,
                generation: 2,
                carried: true,
            },
        ],
    );
    let rotated = admitted(&mut node, registered_id, vec![rotation], keys[2].id, 1003);
    node.activate(rotated.id().unwrap()).unwrap();
    let (model, input, _, _) = fixture::material();
    assert!(node
        .make_with_registered_material(
            rotated.id().unwrap(),
            vec![],
            keys[2].id,
            1004,
            4096,
            &model,
            &input
        )
        .is_err());
    let request = fixture::registration(&lease, task(), 2, prior);
    let fresh = sign(
        &s,
        lease.requester,
        3,
        1,
        21,
        &request.encode().unwrap(),
        &[fixture::primary(&keys[0], 1), fixture::source(&next, 2)],
    );
    let retired = sign(
        &s,
        lease.requester,
        3,
        1,
        21,
        &request.encode().unwrap(),
        &[fixture::primary(&keys[0], 1), fixture::source(&keys[1], 1)],
    );
    assert!(node.pool_submit(retired).is_err());
    let renewed = admitted(
        &mut node,
        rotated.id().unwrap(),
        vec![fresh],
        keys[2].id,
        1004,
    );
    node.activate(renewed.id().unwrap()).unwrap();
    drop(node);
    let mut node = PqNodeV5::open(dir.path(), s.clone(), 1).unwrap();
    let worked = material_admitted(&mut node, renewed.id().unwrap(), keys[2].id, 1005);
    node.activate(worked.id().unwrap()).unwrap();
    let mut fork = registered_id;
    for time in 1006..=1009 {
        fork = admitted(&mut node, fork, vec![], keys[2].id, time)
            .id()
            .unwrap();
    }
    node.activate(fork).unwrap();
    let branch = node.state_at(fork).unwrap();
    assert_eq!(account(&branch, keys[1].id)["nonce"], 0);
    assert_eq!(branch[&tasks::slot_key(0).unwrap()]["source_sequence"], 1);
    assert_eq!(branch[&tasks::slot_key(0).unwrap()]["output_count"], 0);
    drop(node);
    let mut node = PqNodeV5::open(dir.path(), s, 1).unwrap();
    let worked = material_admitted(&mut node, fork, keys[2].id, 1010);
    node.activate(worked.id().unwrap()).unwrap();
    assert_eq!(
        node.state_at(worked.id().unwrap()).unwrap()[&tasks::slot_key(0).unwrap()]["output_count"],
        1
    );
}

#[test]
fn activation_cut_recovery_and_heavier_reorg_never_rewind_local_revocation_or_change_remote_validity(
) {
    let dir = tempfile::tempdir().unwrap();
    let (s, keys) = setup();
    let mut node = PqNodeV5::open(dir.path(), s.clone(), 1).unwrap();
    let (lease, opened, registration, initial_raw) = registered(&mut node, &s, &keys);
    let revoked = sign(
        &s,
        lease.requester,
        3,
        1,
        20,
        &fixture::revocation(&lease).encode().unwrap(),
        &[fixture::primary(&keys[0], 1)],
    );
    let revoked = admitted(
        &mut node,
        registration.id().unwrap(),
        vec![revoked],
        keys[2].id,
        1003,
    );
    let mut cuts = 0;
    assert!(node
        .activate_with_fault(revoked.id().unwrap(), &mut |phase| {
            if phase == "before-publish" {
                cuts += 1;
                return Err(Error::from("PQ5_TEST_CUT"));
            }
            Ok(())
        })
        .is_err());
    assert_eq!(cuts, 1);
    assert_eq!(node.local_revocation_count().unwrap(), 0);
    drop(node);
    let mut node = PqNodeV5::open(dir.path(), s.clone(), 1).unwrap();
    assert_eq!(node.active().unwrap().0, revoked.id().unwrap());
    assert_eq!(node.local_revocation_count().unwrap(), 1);
    let next = fixture::successor(&lease, 3, lease.expires + 50);
    let prior = crypto::statement_id(&initial_raw).unwrap();
    let raw = sign(
        &s,
        lease.requester,
        3,
        1,
        22,
        &fixture::atomic(&lease, &next, task(), 2, prior)
            .encode()
            .unwrap(),
        &[fixture::primary(&keys[0], 1), fixture::source(&keys[1], 1)],
    );
    let fork3 = admitted(
        &mut node,
        registration.id().unwrap(),
        vec![raw],
        keys[2].id,
        1004,
    );
    assert_ne!(lease.id().unwrap(), next.id().unwrap());
    assert_eq!(
        lease.lineage_id(s.genesis()).unwrap(),
        next.lineage_id(s.genesis()).unwrap()
    );
    let fork4 = admitted(&mut node, fork3.id().unwrap(), vec![], keys[2].id, 1005);
    node.activate(fork4.id().unwrap()).unwrap();
    assert_eq!(
        node.state_at(fork4.id().unwrap()).unwrap()[&tasks::slot_key(0).unwrap()]["status"],
        "active"
    );
    assert_eq!(node.local_revocation_count().unwrap(), 1);
    drop(node);
    let mut node = PqNodeV5::open(dir.path(), s.clone(), 1).unwrap();
    let (model, input, _, _) = fixture::material();
    let refusal = node
        .make_with_registered_material(
            fork4.id().unwrap(),
            vec![],
            keys[2].id,
            1006,
            4096,
            &model,
            &input,
        )
        .unwrap_err();
    assert!(refusal.to_string().contains("PQ5_LOCAL_TASK_REVOKED"));
    let peer_dir = tempfile::tempdir().unwrap();
    let mut peer = PqNodeV5::open(peer_dir.path(), s.clone(), 1).unwrap();
    for packet in [&opened, &registration, &fork3, &fork4] {
        peer.admit(packet, 10_000).unwrap();
    }
    peer.activate(fork4.id().unwrap()).unwrap();
    let remote = material_admitted(&mut peer, fork4.id().unwrap(), keys[2].id, 1006);
    assert_eq!(node.admit(&remote, 10_000).unwrap(), remote.id().unwrap());
    node.activate(remote.id().unwrap()).unwrap();
    assert_eq!(node.local_revocation_count().unwrap(), 1);
    assert_eq!(
        node.state_at(remote.id().unwrap()).unwrap()[&tasks::slot_key(0).unwrap()]["output_count"],
        1
    );
    drop(node);
    // Keep the exact old header, block ID and actual complete W1. Its retained
    // detached transaction membership still must be checked independently of
    // the current active chain and of the local withdrawal table's own bytes.
    let substituted =
        PqPacketV5::from_parts(revoked.header().clone(), vec![], revoked.proof().to_vec()).unwrap();
    assert_eq!(substituted.id().unwrap(), revoked.id().unwrap());
    assert_eq!(substituted.header(), revoked.header());
    let db = Connection::open(dir.path().join("native.sqlite")).unwrap();
    let saved = db
        .query_row(
            "SELECT * FROM local_pq_task_revocations_v5",
            [],
            read_revocation_row,
        )
        .unwrap();
    db.execute("DELETE FROM local_pq_task_revocations_v5", [])
        .unwrap();
    db.execute(
        "UPDATE blocks SET packet=? WHERE id=?",
        rusqlite::params![
            substituted.encode().unwrap(),
            revoked.id().unwrap().as_slice()
        ],
    )
    .unwrap();
    drop(db);
    let refusal = PqNodeV5::open(dir.path(), s.clone(), 1).err().unwrap();
    assert!(refusal
        .to_string()
        .contains("PQ5_REVOCATION_PACKET_MEMBERSHIP"));
    let db = Connection::open(dir.path().join("native.sqlite")).unwrap();
    db.execute(
        "UPDATE blocks SET packet=? WHERE id=?",
        rusqlite::params![revoked.encode().unwrap(), revoked.id().unwrap().as_slice()],
    )
    .unwrap();
    db.execute(
        "INSERT INTO local_pq_task_revocations_v5 VALUES(?,?,?,?,?,?,?)",
        rusqlite::params![
            saved.ordinal,
            saved.lineage,
            saved.lease,
            saved.revision,
            saved.demand,
            saved.block,
            saved.generation
        ],
    )
    .unwrap();
    drop(db);
    let node = PqNodeV5::open(dir.path(), s, 1).unwrap();
    assert_eq!(node.active().unwrap().0, remote.id().unwrap());
    assert_eq!(node.local_revocation_count().unwrap(), 1);
}

#[test]
fn cold_missing_witness_and_deleted_local_revocation_evidence_refuse_without_legacy_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let (s, keys) = setup();
    let other = tempfile::tempdir().unwrap();
    assert!(Node::open(other.path(), s.clone(), 1).is_err());
    assert!(PqNodeV2::open(other.path(), s.clone(), 1).is_err());
    assert!(PqNodeV3::open(other.path(), s.clone(), 1).is_err());
    assert!(PqNodeV4::open(other.path(), s.clone(), 1).is_err());
    let accounts: Vec<_> = keys
        .iter()
        .map(|k| GenesisAccount {
            spki: k.spki.clone(),
            balance: 100_000_000,
        })
        .collect();
    assert!(PqNodeV5::open(
        other.path(),
        Settings::native_pq_quota_v3(&accounts, 1000).unwrap(),
        1
    )
    .is_err());
    let mut node = PqNodeV5::open(dir.path(), s.clone(), 1).unwrap();
    let (lease, _, registered, _) = registered(&mut node, &s, &keys);
    let raw = sign(
        &s,
        lease.requester,
        3,
        1,
        20,
        &fixture::revocation(&lease).encode().unwrap(),
        &[fixture::primary(&keys[0], 1)],
    );
    let revoked = admitted(
        &mut node,
        registered.id().unwrap(),
        vec![raw],
        keys[2].id,
        1003,
    );
    node.activate(revoked.id().unwrap()).unwrap();
    assert_eq!(node.local_revocation_count().unwrap(), 1);
    drop(node);
    let db = Connection::open(dir.path().join("native.sqlite")).unwrap();
    let saved = db
        .query_row(
            "SELECT * FROM local_pq_task_revocations_v5",
            [],
            read_revocation_row,
        )
        .unwrap();
    db.execute(
        "UPDATE local_pq_task_revocations_v5 SET revision=revision+1",
        [],
    )
    .unwrap();
    drop(db);
    assert!(PqNodeV5::open(dir.path(), s.clone(), 1).is_err());
    let db = Connection::open(dir.path().join("native.sqlite")).unwrap();
    db.execute(
        "UPDATE local_pq_task_revocations_v5 SET revision=?",
        [saved.revision],
    )
    .unwrap();
    db.execute("DELETE FROM local_pq_task_revocations_v5", [])
        .unwrap();
    drop(db);
    assert!(PqNodeV5::open(dir.path(), s.clone(), 1).is_err());
    let db = Connection::open(dir.path().join("native.sqlite")).unwrap();
    db.execute(
        "INSERT INTO local_pq_task_revocations_v5 VALUES(?,?,?,?,?,?,?)",
        rusqlite::params![
            saved.ordinal,
            saved.lineage,
            saved.lease,
            saved.revision,
            saved.demand,
            saved.block,
            saved.generation
        ],
    )
    .unwrap();
    db.execute(
        "DELETE FROM kv WHERE slot=(SELECT state_slot FROM active WHERE singleton=1) AND key=?",
        [format!("{}00:1", tasks::WITNESS_PREFIX)],
    )
    .unwrap();
    drop(db);
    assert!(PqNodeV5::open(dir.path(), s, 1).is_err());
}

#[test]
fn all_32_task_slots_reach_actual_pool_w1_sql_bounded_leaves_and_cold_material_use() {
    let dir = tempfile::tempdir().unwrap();
    let (s, keys) = setup();
    let mut node = PqNodeV5::open(dir.path(), s.clone(), 4).unwrap();
    node.enable_local_mempool(limits(keys[2].id)).unwrap();
    let mut leases = Vec::new();
    let mut opens = Vec::new();
    for slot in 0..32 {
        let mut lease = fixture::lease(
            s.native_pq_accounts_context().unwrap(),
            keys[0].id,
            keys[1].id,
        );
        lease.slot = slot;
        lease.generation = u64::from(slot) + 1;
        lease.demand_id = lease.derived_demand_id();
        opens.push(open(&s, &lease, &keys[0], u64::from(slot) + 1));
        leases.push(lease);
    }
    let opened = admitted(&mut node, s.genesis(), opens, keys[2].id, 1001);
    node.activate(opened.id().unwrap()).unwrap();
    let mut raws = Vec::new();
    for (index, lease) in leases.iter().enumerate() {
        let request = fixture::registration(
            lease,
            if index == 0 {
                task()
            } else {
                [index as u8; 32]
            },
            1,
            [0; 32],
        );
        let raw = sign(
            &s,
            keys[0].id,
            33 + index as u64,
            1,
            21,
            &request.encode().unwrap(),
            &[fixture::primary(&keys[0], 1), fixture::source(&keys[1], 1)],
        );
        node.pool_submit(raw.clone()).unwrap();
        raws.push(raw);
    }
    let batch = node
        .pool_mining_batch(opened.id().unwrap(), node.active().unwrap().1, 256, 524288)
        .unwrap();
    assert_eq!(batch.transactions, raws);
    assert_eq!(node.pool_validate_batch(&batch).unwrap(), 32);
    let registered = admitted(
        &mut node,
        opened.id().unwrap(),
        batch.transactions,
        keys[2].id,
        1002,
    );
    node.activate(registered.id().unwrap()).unwrap();
    let state = node.state_at(registered.id().unwrap()).unwrap();
    assert_eq!(
        state
            .keys()
            .filter(|k| k.starts_with(tasks::WITNESS_PREFIX))
            .count(),
        160
    );
    assert!(state
        .values()
        .all(|v| serde_json::to_vec(v).unwrap().len() <= 4096));
    assert_eq!(account(&state, keys[0].id)["nonce"], 64);
    let mut renewals = Vec::new();
    for (index, lease) in leases.iter().enumerate() {
        let next = fixture::successor(lease, 3, lease.expires + 50);
        let prior = crypto::statement_id(&raws[index]).unwrap();
        let request = fixture::atomic(
            lease,
            &next,
            if index == 0 {
                task()
            } else {
                [index as u8; 32]
            },
            2,
            prior,
        );
        let raw = sign(
            &s,
            keys[0].id,
            65 + index as u64,
            1,
            22,
            &request.encode().unwrap(),
            &[fixture::primary(&keys[0], 1), fixture::source(&keys[1], 1)],
        );
        node.pool_submit(raw.clone()).unwrap();
        renewals.push(raw);
    }
    assert_eq!(renewals.iter().map(Vec::len).sum::<usize>(), 264768);
    let batch = node
        .pool_mining_batch(
            registered.id().unwrap(),
            node.active().unwrap().1,
            256,
            524288,
        )
        .unwrap();
    assert_eq!(batch.transactions, renewals);
    assert_eq!(node.pool_validate_batch(&batch).unwrap(), 32);
    let renewed = admitted(
        &mut node,
        registered.id().unwrap(),
        batch.transactions,
        keys[2].id,
        1003,
    );
    assert_eq!(renewed.encode().unwrap().len(), 314348);
    node.activate(renewed.id().unwrap()).unwrap();
    let state = node.state_at(renewed.id().unwrap()).unwrap();
    assert_eq!(account(&state, keys[0].id)["nonce"], 96);
    assert!(state
        .values()
        .all(|v| serde_json::to_vec(v).unwrap().len() <= 4096));
    assert_eq!(
        state
            .keys()
            .filter(|k| k.starts_with(tasks::WITNESS_PREFIX))
            .count(),
        160
    );
    drop(node);
    let mut node = PqNodeV5::open(dir.path(), s, 1).unwrap();
    assert_eq!(node.state_at(renewed.id().unwrap()).unwrap(), state);
    let worked = material_admitted(&mut node, renewed.id().unwrap(), keys[2].id, 1004);
    node.activate(worked.id().unwrap()).unwrap();
    assert_eq!(
        node.state_at(worked.id().unwrap()).unwrap()[&tasks::slot_key(0).unwrap()]["output_count"],
        1
    );
}

fn short_registered(
    node: &mut PqNodeV5,
    s: &Settings,
    keys: &[Key; 3],
) -> (DemandLeaseV5, PqPacketV5, Vec<u8>) {
    let mut lease = fixture::lease(
        s.native_pq_accounts_context().unwrap(),
        keys[0].id,
        keys[1].id,
    );
    lease.expires = 3;
    lease.available_until = 103;
    let opened = admitted(
        node,
        s.genesis(),
        vec![open(s, &lease, &keys[0], 1)],
        keys[2].id,
        1001,
    );
    node.activate(opened.id().unwrap()).unwrap();
    let raw = register(s, &lease, &keys[0], &keys[1]);
    let registered = admitted(
        node,
        opened.id().unwrap(),
        vec![raw.clone()],
        keys[2].id,
        1002,
    );
    node.activate(registered.id().unwrap()).unwrap();
    (lease, registered, raw)
}
#[test]
fn atomic_22_in_actual_material_block_preserves_output_then_cold_uses_extended_window() {
    let dir = tempfile::tempdir().unwrap();
    let (s, keys) = setup();
    let mut node = PqNodeV5::open(dir.path(), s.clone(), 1).unwrap();
    node.enable_local_mempool(limits(keys[2].id)).unwrap();
    let (lease, registered, prior_raw) = short_registered(&mut node, &s, &keys);
    let next = fixture::successor(&lease, 3, 53);
    let raw = sign(
        &s,
        lease.requester,
        3,
        1,
        22,
        &fixture::atomic(
            &lease,
            &next,
            task(),
            2,
            crypto::statement_id(&prior_raw).unwrap(),
        )
        .encode()
        .unwrap(),
        &[fixture::primary(&keys[0], 1), fixture::source(&keys[1], 1)],
    );
    let before = node.state_at(registered.id().unwrap()).unwrap();
    let mut bad = raw.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(node.pool_submit(bad).is_err());
    assert!(node.pool_status().unwrap().groups.is_empty());
    node.pool_submit(raw.clone()).unwrap();
    let batch = node
        .pool_mining_batch(
            registered.id().unwrap(),
            node.active().unwrap().1,
            256,
            524288,
        )
        .unwrap();
    assert_eq!(batch.transactions, vec![raw]);
    assert_eq!(node.pool_validate_batch(&batch).unwrap(), 1);
    let (model, input, _, _) = fixture::material();
    let started = std::time::Instant::now();
    let renewed = node
        .make_with_registered_material(
            registered.id().unwrap(),
            batch.transactions,
            keys[2].id,
            1003,
            4096,
            &model,
            &input,
        )
        .unwrap();
    check_and_admit(&mut node, &renewed, started, "registered-material");
    node.activate(renewed.id().unwrap()).unwrap();
    let state = node.state_at(renewed.id().unwrap()).unwrap();
    let row = &state[&tasks::slot_key(0).unwrap()];
    assert_eq!(row["lease"], hex::encode(next.encode().unwrap()));
    assert_eq!(row["signed_lease"], row["lease"]);
    assert_eq!(row["statement_kind"], 22);
    assert_eq!(row["output_count"], 1);
    assert_eq!(row["output_height"], 3);
    assert_eq!(account(&state, keys[1].id), account(&before, keys[1].id));
    drop(node);
    let mut node = PqNodeV5::open(dir.path(), s.clone(), 1).unwrap();
    assert_eq!(node.state_at(renewed.id().unwrap()).unwrap(), state);
    let worked = material_admitted(&mut node, renewed.id().unwrap(), keys[2].id, 1004);
    node.activate(worked.id().unwrap()).unwrap();
    assert_eq!(
        node.state_at(worked.id().unwrap()).unwrap()[&tasks::slot_key(0).unwrap()]["output_count"],
        1
    );
    let old3 = admitted(
        &mut node,
        registered.id().unwrap(),
        vec![],
        keys[2].id,
        1004,
    );
    assert!(node
        .make_with_registered_material(
            old3.id().unwrap(),
            vec![],
            keys[2].id,
            1005,
            4096,
            &model,
            &input
        )
        .is_err());
    let stored: Vec<u8> = sql(dir.path())
        .query_row(
            "SELECT packet FROM blocks WHERE id=?",
            [renewed.id().unwrap().as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stored, renewed.encode().unwrap());
    assert!(stored.starts_with(b"PQP5\x05\0\0\0"));
    assert!(PqPacketV4::decode(&stored).is_err());
    assert!(Packet::decode(&stored).is_err());
}
#[test]
fn staged_19_waits_across_cold_start_until_21_actual_source_proof_then_reads_next_task() {
    let dir = tempfile::tempdir().unwrap();
    let (s, keys) = setup();
    let mut node = PqNodeV5::open(dir.path(), s.clone(), 1).unwrap();
    let (lease, registered, prior_raw) = short_registered(&mut node, &s, &keys);
    let next = fixture::successor(&lease, 3, 53);
    let prior = crypto::statement_id(&prior_raw).unwrap();
    let raw = sign(
        &s,
        lease.requester,
        3,
        1,
        19,
        &fixture::renewal(&lease, &next, prior).encode().unwrap(),
        &[fixture::primary(&keys[0], 1)],
    );
    let (model, input, _, _) = fixture::material();
    let started = std::time::Instant::now();
    let pending = node
        .make_with_registered_material(
            registered.id().unwrap(),
            vec![raw],
            keys[2].id,
            1003,
            4096,
            &model,
            &input,
        )
        .unwrap();
    check_and_admit(&mut node, &pending, started, "registered-material");
    node.activate(pending.id().unwrap()).unwrap();
    let state = node.state_at(pending.id().unwrap()).unwrap();
    let row = &state[&tasks::slot_key(0).unwrap()];
    assert_eq!(row["status"], "awaiting-source");
    assert_eq!(row["signed_lease"], hex::encode(lease.encode().unwrap()));
    assert_eq!(row["output_count"], 1);
    assert_eq!(row["output_height"], 3);
    drop(node);
    let mut node = PqNodeV5::open(dir.path(), s.clone(), 1).unwrap();
    assert_eq!(node.state_at(pending.id().unwrap()).unwrap(), state);
    assert!(node
        .make_with_registered_material(
            pending.id().unwrap(),
            vec![],
            keys[2].id,
            1004,
            4096,
            &model,
            &input
        )
        .is_err());
    let request = fixture::registration(&next, task(), 2, prior);
    let good = sign(
        &s,
        lease.requester,
        4,
        1,
        21,
        &request.encode().unwrap(),
        &[fixture::primary(&keys[0], 1), fixture::source(&keys[1], 1)],
    );
    let bad = sign(
        &s,
        lease.requester,
        4,
        1,
        21,
        &request.encode().unwrap(),
        &[fixture::primary(&keys[0], 1), fixture::source(&keys[2], 1)],
    );
    assert!(node
        .make(pending.id().unwrap(), vec![bad], keys[2].id, 1004, 4096)
        .is_err());
    let rebound = admitted(
        &mut node,
        pending.id().unwrap(),
        vec![good],
        keys[2].id,
        1004,
    );
    node.activate(rebound.id().unwrap()).unwrap();
    drop(node);
    let mut node = PqNodeV5::open(dir.path(), s, 1).unwrap();
    let worked = material_admitted(&mut node, rebound.id().unwrap(), keys[2].id, 1005);
    node.activate(worked.id().unwrap()).unwrap();
    let state = node.state_at(worked.id().unwrap()).unwrap();
    let row = &state[&tasks::slot_key(0).unwrap()];
    assert_eq!(row["status"], "active");
    assert_eq!(row["source_sequence"], 2);
    assert_eq!(row["output_count"], 1);
    assert_eq!(row["output_height"], 3);
    assert_eq!(state[&format!("{}00:4", tasks::WITNESS_PREFIX)], "");
}
