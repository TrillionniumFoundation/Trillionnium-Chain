//! Actual NPQ3 dual-authority quota -> M05/M06 -> original W1/SQL/reorg.
use rusqlite::{Connection, OpenFlags};
use trnm_crypto_primitives::pon_work;
use trnm_mvcc_fee::pon_executor::State;
use trnm_pon_node::{
    pq_accounts_v2::{GenesisAccount, PqNodeV2, PqPacketV2},
    pq_quota_v3::{PqNodeV3, PqPacketV3},
    Error, PoolLimits, PoolState, Settings,
};
use trnm_protocol::{
    pon_wire::{hash, Hash},
    pq_native_accounts_v2 as wire,
};
#[path = "../../trnm-protocol/tests/support/native_pq_quota_fixture.rs"]
mod fixture;
use fixture::{Key, Witness};
fn setup() -> (Settings, [Key; 3]) {
    let keys = [
        Key::public_test_seed(181),
        Key::public_test_seed(182),
        Key::public_test_seed(183),
    ];
    let accounts: Vec<_> = keys
        .iter()
        .map(|key| GenesisAccount {
            spki: key.spki.clone(),
            balance: 100_000_000,
        })
        .collect();
    (Settings::native_pq_quota_v3(&accounts, 1000).unwrap(), keys)
}
fn common(s: &Settings, account: Hash, nonce: u64, generation: u64) -> wire::Common {
    wire::Common {
        context: s.native_pq_accounts_context().unwrap(),
        account,
        nonce,
        generation,
        expires_at: 2000,
        max_fee: 100_000,
    }
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
fn reserve(s: &Settings, keys: &[Key; 3]) -> (Hash, Vec<u8>) {
    let [owner, consumer, provider] = keys;
    let units = 1000_u64;
    let deadline = 50_u64;
    let quota = hash(
        b"quota-instance-v3",
        &[
            &s.network(),
            &s.parameters(),
            &owner.id,
            &1_u64.to_le_bytes(),
            &consumer.id,
            &provider.id,
            &units.to_le_bytes(),
            &deadline.to_le_bytes(),
        ],
    );
    let payload = [
        quota.as_slice(),
        &consumer.id,
        &provider.id,
        &units.to_le_bytes(),
        &deadline.to_le_bytes(),
    ]
    .concat();
    (
        quota,
        fixture::signed(
            &common(s, owner.id, 1, 1),
            10,
            &payload,
            &[Witness {
                key: owner,
                role: 1,
                generation: 1,
                carried: false,
            }],
            None,
        ),
    )
}
fn consume(
    s: &Settings,
    quota: Hash,
    provider: &Key,
    consumer: &Key,
    consumer_generation: u64,
) -> Vec<u8> {
    consume_at_nonce(s, quota, provider, consumer, consumer_generation, 1)
}
fn consume_at_nonce(
    s: &Settings,
    quota: Hash,
    provider: &Key,
    consumer: &Key,
    consumer_generation: u64,
    nonce: u64,
) -> Vec<u8> {
    let payload = [quota.as_slice(), &10_u64.to_le_bytes(), &[94; 32]].concat();
    fixture::signed(
        &common(s, provider.id, nonce, 1),
        11,
        &payload,
        &[
            Witness {
                key: provider,
                role: 1,
                generation: 1,
                carried: false,
            },
            Witness {
                key: consumer,
                role: 2,
                generation: consumer_generation,
                carried: false,
            },
        ],
        None,
    )
}
fn admitted(
    node: &mut PqNodeV3,
    parent: Hash,
    raws: Vec<Vec<u8>>,
    miner: Hash,
    time: u64,
) -> PqPacketV3 {
    let started = std::time::Instant::now();
    let count = raws.len();
    let bytes: usize = raws.iter().map(Vec::len).sum();
    let packet = node.make(parent, raws, miner, time, 4096).unwrap();
    pon_work::verify_reference(
        packet.header().challenge(),
        packet.header().work_task,
        packet.header().target,
        packet.proof(),
    )
    .unwrap();
    assert_eq!(node.admit(&packet, 10_000).unwrap(), packet.id().unwrap());
    eprintln!(
        "{}",
        serde_json::json!({"schema":"native-pq3-actual-phase-v1","phase":"make-complete-w1-independent-reference-admit-sql","transactions":count,"raw_bytes":bytes,"wall_nanoseconds":started.elapsed().as_nanos(),"block":hex::encode(packet.id().unwrap()),"scope":"shared host actual calls, not isolated cost or worst case"})
    );
    packet
}
fn sql(path: &std::path::Path) -> Connection {
    Connection::open_with_flags(path.join("native.sqlite"), OpenFlags::SQLITE_OPEN_READ_ONLY)
        .unwrap()
}
fn ordinal(path: &std::path::Path) -> u64 {
    sql(path)
        .query_row("SELECT MAX(ordinal) FROM local_pool_groups", [], |r| {
            r.get(0)
        })
        .unwrap()
}

#[test]
fn dual_pq_quota_actual_pool_work_sql_cut_cold_recovery_and_heavier_fork() {
    let dir = tempfile::tempdir().unwrap();
    let (s, keys) = setup();
    let genesis = s.genesis();
    let mut node = PqNodeV3::open(dir.path(), s.clone(), 1).unwrap();
    node.enable_local_mempool(limits(keys[2].id)).unwrap();
    let (quota, reservation) = reserve(&s, &keys);
    let reserved = admitted(&mut node, genesis, vec![reservation], keys[2].id, 1001)
        .id()
        .unwrap();
    node.activate(reserved).unwrap();
    let before = node.state_at(reserved).unwrap();
    let usage = consume(&s, quota, &keys[2], &keys[1], 1);
    assert_eq!(usage.len(), 7314);
    let mut bad = usage.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(node.pool_submit(bad).is_err());
    assert!(node.pool_status().unwrap().groups.is_empty());
    let receipt = node.pool_submit(usage.clone()).unwrap();
    let original_ordinal = ordinal(dir.path());
    assert_eq!(receipt.typed_gate_admissions, 1);
    let batch = node
        .pool_mining_batch(reserved, node.active().unwrap().1, 256, 524288)
        .unwrap();
    assert_eq!(batch.transactions, vec![usage.clone()]);
    assert_eq!(node.pool_validate_batch(&batch).unwrap(), 1);
    let packet = admitted(&mut node, reserved, batch.transactions, keys[2].id, 1002);
    let used = packet.id().unwrap();
    node.activate(used).unwrap();
    let spent = node.state_at(used).unwrap();
    let quota_key = format!("quota:{}", hex::encode(quota));
    assert_eq!(spent[&quota_key]["units"], 990);
    assert_eq!(account(&spent, keys[2].id)["nonce"], 1);
    assert_eq!(account(&spent, keys[1].id), account(&before, keys[1].id));
    let stored: Vec<u8> = sql(dir.path())
        .query_row(
            "SELECT packet FROM blocks WHERE id=?",
            [used.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stored, packet.encode().unwrap());
    assert!(stored.starts_with(b"PQP3\x03\0\0\0"));
    assert!(PqPacketV2::decode(&stored).is_err());
    let statements: u64 = sql(dir.path())
        .query_row("SELECT COUNT(*) FROM local_pq_statements_v3", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(statements, 1);
    drop(node);
    let mut node = PqNodeV3::open(dir.path(), s.clone(), 1).unwrap();
    assert_eq!(node.state_at(used).unwrap(), spent);
    let fork1 = admitted(&mut node, reserved, vec![], keys[2].id, 1003)
        .id()
        .unwrap();
    let fork2 = admitted(&mut node, fork1, vec![], keys[2].id, 1004)
        .id()
        .unwrap();
    let mut cuts = 0;
    let error = node
        .activate_with_fault(fork2, &mut |point| {
            if point == "detach:0" {
                cuts += 1;
                Err(Error::from("PQ3_QUOTA_REORG_CUT"))
            } else {
                Ok(())
            }
        })
        .unwrap_err();
    assert_eq!(error.to_string(), "PQ3_QUOTA_REORG_CUT");
    assert_eq!(cuts, 1);
    assert_eq!(node.active().unwrap().0, used);
    assert_eq!(node.state_at(used).unwrap(), spent);
    drop(node);
    let mut node = PqNodeV3::open(dir.path(), s.clone(), 1).unwrap();
    assert_eq!(node.active().unwrap().0, fork2);
    let restored = node.state_at(fork2).unwrap();
    assert_eq!(restored[&quota_key], before[&quota_key]);
    assert_eq!(account(&restored, keys[2].id), account(&before, keys[2].id));
    assert_eq!(ordinal(dir.path()), original_ordinal);
    let status = node.pool_status().unwrap();
    assert_eq!(status.profile, "native-local-queued-npq3-v1");
    assert_eq!(status.groups[0].state, PoolState::Queued);
    let batch = node
        .pool_mining_batch(fork2, node.active().unwrap().1, 256, 524288)
        .unwrap();
    assert_eq!(batch.transactions, vec![usage.clone()]);
    let reapplied = admitted(&mut node, fork2, batch.transactions, keys[2].id, 1005)
        .id()
        .unwrap();
    node.activate(reapplied).unwrap();
    assert_eq!(node.state_at(reapplied).unwrap()[&quota_key]["units"], 990);
    assert!(node
        .make(reapplied, vec![usage], keys[2].id, 1006, 4096)
        .is_err());
    assert_eq!(
        node.settings()
            .state_root(&node.state_at(reapplied).unwrap())
            .unwrap(),
        node.packet(reapplied).unwrap().header().state
    );
}

#[test]
fn actual_consumer_rotation_rejects_retired_proof_and_reorg_restores_original_authority() {
    let dir = tempfile::tempdir().unwrap();
    let (s, keys) = setup();
    let mut node = PqNodeV3::open(dir.path(), s.clone(), 1).unwrap();
    node.enable_local_mempool(limits(keys[2].id)).unwrap();
    let (quota, raw) = reserve(&s, &keys);
    let reserved = admitted(&mut node, s.genesis(), vec![raw], keys[2].id, 1001)
        .id()
        .unwrap();
    node.activate(reserved).unwrap();
    let usage = consume(&s, quota, &keys[2], &keys[1], 1);
    node.pool_submit(usage.clone()).unwrap();
    let original_ordinal = ordinal(dir.path());
    let next = Key::public_test_seed(184);
    let payload = [
        2_u64.to_be_bytes().as_slice(),
        &node.authority_digest(reserved, keys[1].id).unwrap(),
    ]
    .concat();
    let rotation = fixture::signed(
        &common(&s, keys[1].id, 1, 1),
        wire::ROTATE,
        &payload,
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
        None,
    );
    for rows in [
        vec![rotation.clone(), usage.clone()],
        vec![usage.clone(), rotation.clone()],
    ] {
        assert!(node.make(reserved, rows, keys[2].id, 1002, 4096).is_err());
    }
    let rotated = admitted(&mut node, reserved, vec![rotation], keys[2].id, 1002)
        .id()
        .unwrap();
    node.activate(rotated).unwrap();
    assert!(node
        .make(rotated, vec![usage.clone()], keys[2].id, 1003, 4096)
        .is_err());
    assert_ne!(
        node.pool_status().unwrap().groups[0].state,
        PoolState::Queued
    );
    let fresh = consume(&s, quota, &keys[2], &next, 2);
    let settled = admitted(&mut node, rotated, vec![fresh], keys[2].id, 1003)
        .id()
        .unwrap();
    node.activate(settled).unwrap();
    assert_eq!(
        node.state_at(settled).unwrap()[&format!("quota:{}", hex::encode(quota))]["consumer"],
        hex::encode(keys[1].id)
    );
    let mut fork = reserved;
    for time in 1004..=1006 {
        fork = admitted(&mut node, fork, vec![], keys[2].id, time)
            .id()
            .unwrap();
    }
    node.activate(fork).unwrap();
    assert_eq!(
        account(&node.state_at(fork).unwrap(), keys[1].id)["nonce"],
        0
    );
    assert_eq!(ordinal(dir.path()), original_ordinal);
    let batch = node
        .pool_mining_batch(fork, node.active().unwrap().1, 256, 524288)
        .unwrap();
    assert_eq!(batch.transactions, vec![usage]);
    assert_eq!(node.pool_validate_batch(&batch).unwrap(), 1);
    drop(node);
    let node = PqNodeV3::open(dir.path(), s, 1).unwrap();
    assert_eq!(node.active().unwrap().0, fork);
}

#[test]
fn exact_new_packet_settings_and_sql_namespaces_refuse_old_profile_fallback() {
    let v3_dir = tempfile::tempdir().unwrap();
    let v2_dir = tempfile::tempdir().unwrap();
    let (s, keys) = setup();
    let accounts: Vec<_> = keys
        .iter()
        .map(|key| GenesisAccount {
            spki: key.spki.clone(),
            balance: 100_000_000,
        })
        .collect();
    let old = Settings::native_pq_accounts_v2(&accounts, 1000).unwrap();
    assert_ne!(s.genesis(), old.genesis());
    assert!(PqNodeV3::open(v3_dir.path(), old.clone(), 1).is_err());
    assert!(PqNodeV2::open(v2_dir.path(), s.clone(), 1).is_err());
    let v3 = PqNodeV3::open(v3_dir.path(), s.clone(), 1).unwrap();
    let p3 = v3
        .make(s.genesis(), vec![], keys[2].id, 1001, 4096)
        .unwrap();
    drop(v3);
    let v2 = PqNodeV2::open(v2_dir.path(), old.clone(), 1).unwrap();
    let p2 = v2
        .make(old.genesis(), vec![], keys[2].id, 1001, 4096)
        .unwrap();
    drop(v2);
    assert!(PqPacketV2::decode(&p3.encode().unwrap()).is_err());
    assert!(PqPacketV3::decode(&p2.encode().unwrap()).is_err());
    assert!(PqNodeV2::open(v3_dir.path(), old.clone(), 1).is_err());
    assert!(PqNodeV3::open(v2_dir.path(), s.clone(), 1).is_err());
    assert!(PqNodeV3::open(v3_dir.path(), s, 1).is_ok());
    assert!(PqNodeV2::open(v2_dir.path(), old, 1).is_ok());
}

#[test]
fn full_dual_proof_capacity_reaches_native_pool_packet_sql_and_cold_read() {
    let dir = tempfile::tempdir().unwrap();
    let (s, keys) = setup();
    let mut node = PqNodeV3::open(dir.path(), s.clone(), 1).unwrap();
    node.enable_local_mempool(limits(keys[2].id)).unwrap();
    let (quota, reservation) = reserve(&s, &keys);
    let reserved = admitted(&mut node, s.genesis(), vec![reservation], keys[2].id, 1001)
        .id()
        .unwrap();
    node.activate(reserved).unwrap();
    let before = node.state_at(reserved).unwrap();
    let rows: Vec<_> = (1..=72)
        .map(|nonce| consume_at_nonce(&s, quota, &keys[2], &keys[1], 1, nonce))
        .collect();
    assert!(rows.iter().all(|raw| raw.len() == 7314));
    assert_eq!(rows[..71].iter().map(Vec::len).sum::<usize>(), 519294);
    assert_eq!(rows.iter().map(Vec::len).sum::<usize>(), 526608);
    for group in rows[..71].chunks(16) {
        node.pool_submit_bundle(group.to_vec()).unwrap();
    }
    let status = serde_json::to_value(node.pool_status().unwrap()).unwrap();
    assert_eq!(status["retained_records"], 71);
    assert_eq!(status["retained_bytes"], 519294);
    let error = node.pool_submit(rows[71].clone()).unwrap_err();
    assert!(error.to_string().contains("POOL_BYTE_LIMIT"), "{error}");
    assert_eq!(
        serde_json::to_value(node.pool_status().unwrap()).unwrap(),
        status
    );
    assert!(node
        .make(reserved, rows.clone(), keys[2].id, 1002, 4096)
        .is_err());
    assert_eq!(node.state_at(reserved).unwrap(), before);
    let batch = node
        .pool_mining_batch(reserved, node.active().unwrap().1, 256, 524288)
        .unwrap();
    assert_eq!(batch.transactions, rows[..71]);
    assert_eq!(node.pool_validate_batch(&batch).unwrap(), 71);
    let packet = admitted(&mut node, reserved, batch.transactions, keys[2].id, 1002);
    let accepted = packet.id().unwrap();
    node.activate(accepted).unwrap();
    let after = node.state_at(accepted).unwrap();
    let quota_key = format!("quota:{}", hex::encode(quota));
    assert_eq!(after[&quota_key]["units"], 290);
    assert_eq!(account(&after, keys[2].id)["nonce"], 71);
    assert_eq!(account(&after, keys[1].id), account(&before, keys[1].id));
    let wire = packet.encode().unwrap();
    assert!(wire.len() < 1048576);
    assert_eq!(
        PqPacketV3::decode(&wire).unwrap().transactions(),
        &rows[..71]
    );
    let stored: Vec<u8> = sql(dir.path())
        .query_row(
            "SELECT packet FROM blocks WHERE id=?",
            [accepted.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stored, wire);
    drop(node);
    let node = PqNodeV3::open(dir.path(), s, 1).unwrap();
    assert_eq!(node.active().unwrap().0, accepted);
    assert_eq!(node.state_at(accepted).unwrap(), after);
    assert_eq!(node.packet(accepted).unwrap().transactions(), &rows[..71]);
}

#[test]
fn actual_source_checkpoint_claimed_consumer_uses_quota_and_reorg_restores_import_lock() {
    use trnm_mvcc_fee::continuity_v1;
    use trnm_pon_node::{
        development_public,
        pq_quota_v3::{PrecommittedAccount, TrustedPqPrecommitments},
        Node,
    };
    let source_dir = tempfile::tempdir().unwrap();
    let source_settings = Settings::development_with_profiles(
        Some(1000),
        "legacy-first-two-v3",
        continuity_v1::PROFILE,
    )
    .unwrap();
    let prior: Vec<_> = (191..195).map(Key::public_test_seed).collect();
    let entries: Vec<_> = prior
        .iter()
        .enumerate()
        .map(|(i, key)| PrecommittedAccount {
            source_account: development_public(i as u64).unwrap(),
            spki: key.spki.clone(),
            generation: 9,
        })
        .collect();
    // Independent premise frozen BEFORE obtaining this actual source checkpoint.
    let registry = TrustedPqPrecommitments::pin(
        source_settings.network(),
        source_settings.genesis(),
        &entries,
    )
    .unwrap();
    let prior_commitment = registry.commitment();
    let owner = development_public(0).unwrap();
    let mut source =
        Node::open_with_authenticated_state(source_dir.path(), source_settings.clone(), 1).unwrap();
    let source_packet = source
        .make_consensus_maintenance(source_settings.genesis(), vec![], owner, 1010, 4096)
        .unwrap();
    pon_work::verify_reference(
        source_packet.header.challenge(),
        source_packet.header.work_task,
        source_packet.header.target,
        &source_packet.proof,
    )
    .unwrap();
    let checkpoint = source.admit(&source_packet, 10_000).unwrap();
    source.activate(checkpoint).unwrap();
    let source_state = source.state_at(checkpoint).unwrap();
    let anchor = source
        .pin_native_pq_migration_checkpoint(registry, checkpoint)
        .unwrap();
    assert_eq!(anchor.checkpoint(), checkpoint);
    let provider = Key::public_test_seed(195);
    let imported_key = Key::public_test_seed(196);
    let seed = [GenesisAccount {
        spki: provider.spki.clone(),
        balance: 1_000_000,
    }];
    let old = Settings::native_pq_accounts_v2_with_migration(&seed, 1500, anchor.clone()).unwrap();
    let s = Settings::native_pq_quota_v3_with_trusted_migration(&seed, 1500, anchor).unwrap();
    assert_ne!(s.genesis(), old.genesis());
    let dir = tempfile::tempdir().unwrap();
    let mut node = PqNodeV3::open(dir.path(), s.clone(), 1).unwrap();
    node.enable_local_mempool(limits(provider.id)).unwrap();
    let initial = node.state_at(s.genesis()).unwrap();
    assert_eq!(
        initial["meta:issued"].as_u64().unwrap(),
        source_state["meta:issued"].as_u64().unwrap() + 1_000_000
    );
    assert_eq!(account(&initial, owner), account(&source_state, owner));
    assert_eq!(account(&initial, owner)["nonce"], 0);
    let claim = fixture::signed(
        &common(&s, owner, 1, 0),
        wire::CLAIM,
        &node.migration_claim_payload(owner).unwrap(),
        &[
            Witness {
                key: &prior[0],
                role: 5,
                generation: 9,
                carried: false,
            },
            Witness {
                key: &imported_key,
                role: 6,
                generation: 1,
                carried: true,
            },
        ],
        None,
    );
    assert_eq!(claim.len(), 9432);
    node.pool_submit(claim.clone()).unwrap();
    let claimed = admitted(
        &mut node,
        s.genesis(),
        vec![claim.clone()],
        provider.id,
        1510,
    )
    .id()
    .unwrap();
    node.activate(claimed).unwrap();
    let origin = format!("pq-import-v2:{}", hex::encode(owner));
    assert_eq!(node.state_at(claimed).unwrap()[&origin]["claimed"], true);
    let units = 1000_u64;
    let deadline = 50_u64;
    let quota = hash(
        b"quota-instance-v3",
        &[
            &s.network(),
            &s.parameters(),
            &owner,
            &2_u64.to_le_bytes(),
            &owner,
            &provider.id,
            &units.to_le_bytes(),
            &deadline.to_le_bytes(),
        ],
    );
    let payload = [
        quota.as_slice(),
        &owner,
        &provider.id,
        &units.to_le_bytes(),
        &deadline.to_le_bytes(),
    ]
    .concat();
    let reservation = fixture::signed(
        &common(&s, owner, 2, 1),
        10,
        &payload,
        &[Witness {
            key: &imported_key,
            role: 1,
            generation: 1,
            carried: false,
        }],
        None,
    );
    assert!(node
        .make(
            s.genesis(),
            vec![reservation.clone()],
            provider.id,
            1511,
            4096
        )
        .is_err());
    node.pool_submit(reservation.clone()).unwrap();
    let reserved = admitted(&mut node, claimed, vec![reservation], provider.id, 1520)
        .id()
        .unwrap();
    node.activate(reserved).unwrap();
    // Quota State names the imported stable source account, not the new key ID.
    let usage = consume(&s, quota, &provider, &imported_key, 1);
    node.pool_submit(usage.clone()).unwrap();
    let used = admitted(&mut node, reserved, vec![usage], provider.id, 1530)
        .id()
        .unwrap();
    node.activate(used).unwrap();
    let spent = node.state_at(used).unwrap();
    let q = format!("quota:{}", hex::encode(quota));
    assert_eq!(spent[&q]["consumer"], hex::encode(owner));
    assert_eq!(spent[&q]["units"], 990);
    assert_eq!(account(&spent, owner)["nonce"], 2);
    assert_eq!(account(&spent, provider.id)["nonce"], 1);
    assert_eq!(
        spent["meta:issued"].as_u64().unwrap(),
        initial["meta:issued"].as_u64().unwrap() + 3000
    );
    let original_ordinal = ordinal(dir.path());
    drop(node);
    let mut node = PqNodeV3::open(dir.path(), s.clone(), 1).unwrap();
    assert_eq!(node.state_at(used).unwrap(), spent);
    let mut fork = s.genesis();
    for time in 1502..=1505 {
        fork = admitted(&mut node, fork, vec![], provider.id, time)
            .id()
            .unwrap();
    }
    node.activate(fork).unwrap();
    let restored = node.state_at(fork).unwrap();
    assert_eq!(restored[&origin]["claimed"], false);
    assert_eq!(account(&restored, owner), account(&initial, owner));
    assert!(!restored.contains_key(&q));
    assert_eq!(account(&restored, provider.id)["nonce"], 0);
    assert_eq!(ordinal(dir.path()), original_ordinal);
    let batch = node
        .pool_mining_batch(fork, node.active().unwrap().1, 256, 524288)
        .unwrap();
    assert_eq!(batch.transactions, vec![claim]);
    let reclaimed = admitted(&mut node, fork, batch.transactions, provider.id, 1540)
        .id()
        .unwrap();
    node.activate(reclaimed).unwrap();
    assert_eq!(node.state_at(reclaimed).unwrap()[&origin]["claimed"], true);
    assert_eq!(ordinal(dir.path()), original_ordinal);
    assert_eq!(source.state_at(checkpoint).unwrap(), source_state);
    eprintln!("NPQ3 actual conditional import: prior registry={}, source checkpoint={}; claim then current-State consumer quota used; source retirement/finality and prior registry history are external premises",hex::encode(prior_commitment),hex::encode(checkpoint));
}
