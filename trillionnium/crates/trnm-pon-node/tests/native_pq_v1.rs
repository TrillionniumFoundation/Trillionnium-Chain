//! Explicit fresh PQ transfer profile through the actual M05/M06/PoN/SQL owner.
//! Public fixture seeds, no production authority or legacy migration claim.
use rusqlite::{Connection, OpenFlags};
use trnm_crypto_primitives::pon_work;
use trnm_mvcc_fee::pon_executor::State;
use trnm_pon_node::{
    pq_native_v1::{GenesisAccount, PqNodeV1, PqPacketV1},
    Error, Node, Packet, PoolLimits, PoolState, Settings,
};
use trnm_protocol::{pon_wire::Hash, pq_native_transfer_v1 as wire};
#[path = "../../trnm-protocol/tests/support/native_pq_fixture.rs"]
mod fixture;

fn setup(timestamp: u64) -> (Settings, fixture::Key, fixture::Key) {
    let a = fixture::Key::public_test_seed(91);
    let b = fixture::Key::public_test_seed(92);
    let settings = Settings::native_pq_transfers_v1(
        &[
            GenesisAccount {
                spki: a.spki.clone(),
                balance: 100_000_000,
            },
            GenesisAccount {
                spki: b.spki.clone(),
                balance: 100_000_000,
            },
        ],
        timestamp,
    )
    .unwrap();
    (settings, a, b)
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
fn nonce(state: &State, id: Hash) -> u64 {
    state[&format!("account:{}", hex::encode(id))]["nonce"]
        .as_u64()
        .unwrap()
}
fn auth_partition(state: &State) -> State {
    state
        .iter()
        .filter(|(k, _)| k.starts_with("pq-auth-v1:") || k.starts_with("pq-key-v1:"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}
fn sql(path: &std::path::Path) -> Connection {
    Connection::open_with_flags(path.join("native.sqlite"), OpenFlags::SQLITE_OPEN_READ_ONLY)
        .unwrap()
}
fn last_ordinal(path: &std::path::Path) -> u64 {
    sql(path)
        .query_row("SELECT MAX(ordinal) FROM local_pool_groups", [], |r| {
            r.get(0)
        })
        .unwrap()
}
fn admitted(
    node: &mut PqNodeV1,
    parent: Hash,
    txs: Vec<Vec<u8>>,
    miner: Hash,
    time: u64,
) -> PqPacketV1 {
    let packet = node.make(parent, txs, miner, time, 4096).unwrap();
    pon_work::verify_reference(
        packet.header().challenge(),
        packet.header().work_task,
        packet.header().target,
        packet.proof(),
    )
    .unwrap();
    assert_eq!(node.admit(&packet, 10_000).unwrap(), packet.id().unwrap());
    packet
}

#[test]
fn actual_pq_pool_m06_pon_sql_cold_open_and_heavier_fork_requeue() {
    let dir = tempfile::tempdir().unwrap();
    let (s, a, b) = setup(1000);
    let genesis = s.genesis();
    let mut node = PqNodeV1::open(dir.path(), s.clone(), 1).unwrap();
    node.enable_local_mempool(limits(b.id)).unwrap();
    let initial = node.state_at(genesis).unwrap();
    let auth = auth_partition(&initial);
    assert_eq!(auth.len(), 4);
    let raw = a.transfer(
        s.native_pq_context().unwrap(),
        b.id,
        1,
        1100,
        17,
        100_000,
        &[],
        None,
    );
    let receipt = node.pool_submit(raw.clone()).unwrap();
    assert!(!receipt.duplicate);
    assert_eq!(receipt.typed_gate_admissions, 1);
    assert_eq!(receipt.typed_gate_ready_metadata, 1);
    let original_ordinal = last_ordinal(dir.path());
    let (parent, generation) = node.active().unwrap();
    let batch = node
        .pool_mining_batch(parent, generation, 256, 524288)
        .unwrap();
    assert_eq!(node.pool_validate_batch(&batch).unwrap(), 1);
    assert_eq!(batch.transactions, vec![raw.clone()]);
    let main = admitted(&mut node, parent, batch.transactions, b.id, 1001);
    let main_id = main.id().unwrap();
    let raw_packet = main.encode().unwrap();
    assert!(raw_packet.starts_with(wire::PACKET_PREFIX));
    assert!(Packet::decode(&raw_packet).is_err());
    assert_eq!(
        PqPacketV1::decode(&raw_packet).unwrap().encode().unwrap(),
        raw_packet
    );
    assert_eq!(
        main.header().transactions,
        trnm_pon_node::sequence_root("transactions", &[raw])
    );
    node.activate(main_id).unwrap();
    let spent = node.state_at(main_id).unwrap();
    assert_eq!(nonce(&spent, a.id), 1);
    assert_eq!(
        spent[&format!("account:{}", hex::encode(b.id))]["balance"],
        100_000_017
    );
    assert_eq!(auth_partition(&spent), auth);
    assert_eq!(s.state_root(&spent).unwrap(), main.header().state);
    assert_eq!(
        node.pool_status().unwrap().groups[0].state,
        PoolState::SequenceConsumed
    );
    let stored: Vec<u8> = sql(dir.path())
        .query_row(
            "SELECT packet FROM blocks WHERE id=?",
            [main_id.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stored, raw_packet);
    drop(node);
    let mut node = PqNodeV1::open(dir.path(), s.clone(), 1).unwrap();
    assert_eq!(node.state_at(main_id).unwrap(), spent);
    assert_eq!(node.packet(main_id).unwrap().encode().unwrap(), stored);
    // Changing the observed wall clock does not reinterpret a stored tx's expiry.
    assert_eq!(node.admit(&main, u64::MAX).unwrap(), main_id);
    let branch1 = admitted(&mut node, genesis, vec![], b.id, 1002)
        .id()
        .unwrap();
    let branch2 = admitted(&mut node, branch1, vec![], b.id, 1003)
        .id()
        .unwrap();
    assert_eq!(node.activate(branch2).unwrap(), branch2);
    let returned = node.state_at(branch2).unwrap();
    assert_eq!(nonce(&returned, a.id), 0);
    assert_eq!(auth_partition(&returned), auth);
    let status = node.pool_status().unwrap();
    assert_eq!(status.profile, "native-local-queued-npq1-v1");
    assert_eq!(status.groups[0].state, PoolState::Queued);
    assert_eq!(last_ordinal(dir.path()), original_ordinal);
    let generation = node.active().unwrap().1;
    let batch = node
        .pool_mining_batch(branch2, generation, 256, 524288)
        .unwrap();
    assert_eq!(batch.transactions.len(), 1);
    assert_eq!(node.pool_validate_batch(&batch).unwrap(), 1);
    eprintln!("native PQ: actual ML-DSA -> M05 -> M06 -> full PoN -> SQLite -> cold open -> heavier fork; chain nonce 1 -> 0; ordinal unchanged; authority leaves unchanged");
}

#[test]
fn randomized_resign_duplicate_requires_real_signature_and_keeps_removal_history() {
    let dir = tempfile::tempdir().unwrap();
    let (s, a, b) = setup(1000);
    let g = s.genesis();
    let mut node = PqNodeV1::open(dir.path(), s.clone(), 1).unwrap();
    node.enable_local_mempool(limits(b.id)).unwrap();
    let ctx = s.native_pq_context().unwrap();
    let one = a.transfer(ctx, b.id, 1, 1100, 17, 100_000, &[], Some([1; 32]));
    let two = a.transfer(ctx, b.id, 1, 1100, 17, 100_000, &[], Some([2; 32]));
    assert_ne!(one, two);
    let first = node.pool_submit(one.clone()).unwrap();
    let ordinal = last_ordinal(dir.path());
    let duplicate = node.pool_submit(two.clone()).unwrap();
    assert!(duplicate.duplicate);
    assert_eq!(first.group, duplicate.group);
    assert_eq!(duplicate.typed_gate_admissions, 0);
    assert_eq!(node.pool_status().unwrap().retained_records, 1);
    assert_eq!(last_ordinal(dir.path()), ordinal);
    let mut forged = two.clone();
    forged[12 + 144 + 178] ^= 1;
    assert!(node.pool_submit(forged).is_err());
    assert_eq!(last_ordinal(dir.path()), ordinal);
    let main = admitted(&mut node, g, vec![one], b.id, 1001).id().unwrap();
    node.activate(main).unwrap();
    let group: Hash = hex::decode(first.group).unwrap().try_into().unwrap();
    node.pool_prune_terminal(group).unwrap();
    assert_eq!(node.pool_status().unwrap().local_removals, 1);
    let fork1 = admitted(&mut node, g, vec![], b.id, 1002).id().unwrap();
    let fork2 = admitted(&mut node, fork1, vec![], b.id, 1003).id().unwrap();
    node.activate(fork2).unwrap();
    assert_eq!(nonce(&node.state_at(fork2).unwrap(), a.id), 0);
    assert_eq!(
        node.pool_submit(two.clone()).unwrap_err().to_string(),
        "POOL_REMOVED"
    );
    drop(node);
    let mut node = PqNodeV1::open(dir.path(), s, 1).unwrap();
    assert_eq!(
        node.pool_submit(two).unwrap_err().to_string(),
        "POOL_REMOVED"
    );
}

#[test]
fn expiry_equal_header_time_mtp_preview_future_skew_and_overflow_are_explicit() {
    let dir = tempfile::tempdir().unwrap();
    let (s, a, b) = setup(1000);
    let g = s.genesis();
    let mut node = PqNodeV1::open(dir.path(), s.clone(), 1).unwrap();
    node.enable_local_mempool(limits(b.id)).unwrap();
    let raw = a.transfer(
        s.native_pq_context().unwrap(),
        b.id,
        1,
        1001,
        17,
        100_000,
        &[],
        None,
    );
    node.pool_submit(raw.clone()).unwrap();
    assert!(node.make(g, vec![raw.clone()], b.id, 1002, 4096).is_err());
    let packet = node.make(g, vec![raw], b.id, 1001, 4096).unwrap();
    assert_eq!(
        node.admit(&packet, 0).unwrap_err().to_string(),
        "TIME_DEFERRED"
    );
    assert_eq!(node.active().unwrap().0, g);
    node.admit(&packet, 1001).unwrap();
    node.activate(packet.id().unwrap()).unwrap();
    drop(node);
    let node = PqNodeV1::open(dir.path(), s, 1).unwrap();
    assert_eq!(
        nonce(&node.state_at(packet.id().unwrap()).unwrap(), a.id),
        1
    );
    // Parent time need not be the MTP lower bound. On a two-block fork the
    // next preview uses sorted upper median, preserving the original time rule.
    let dir2 = tempfile::tempdir().unwrap();
    let (s, a, b) = setup(1000);
    let g = s.genesis();
    let mut node = PqNodeV1::open(dir2.path(), s.clone(), 1).unwrap();
    let first = admitted(&mut node, g, vec![], b.id, 1100).id().unwrap();
    node.activate(first).unwrap();
    let second = admitted(&mut node, first, vec![], b.id, 1200).id().unwrap();
    node.activate(second).unwrap();
    node.enable_local_mempool(limits(b.id)).unwrap();
    let raw = a.transfer(
        s.native_pq_context().unwrap(),
        b.id,
        1,
        1101,
        17,
        100_000,
        &[],
        None,
    );
    node.pool_submit(raw.clone()).unwrap();
    let next = admitted(&mut node, second, vec![raw], b.id, 1101);
    node.activate(next.id().unwrap()).unwrap();
    let dir3 = tempfile::tempdir().unwrap();
    let (s, _, b) = setup(u64::MAX);
    let mut node = PqNodeV1::open(dir3.path(), s, 1).unwrap();
    assert_eq!(
        node.enable_local_mempool(limits(b.id))
            .unwrap_err()
            .to_string(),
        "PQ_PREVIEW_TIME_OVERFLOW"
    );
    let configured: u64 = sql(dir3.path())
        .query_row("SELECT COUNT(*) FROM local_pool_metadata", [], |r| r.get(0))
        .unwrap();
    assert_eq!(configured, 0);
}

#[test]
fn full_6129_byte_rows_and_packet_have_actual_85_transfer_limit() {
    let dir = tempfile::tempdir().unwrap();
    let (s, a, b) = setup(1000);
    let g = s.genesis();
    let mut node = PqNodeV1::open(dir.path(), s.clone(), 1).unwrap();
    node.enable_local_mempool(limits(b.id)).unwrap();
    let ctx = s.native_pq_context().unwrap();
    let raws: Vec<_> = (1..=86)
        .map(|n| a.transfer(ctx, b.id, n, 2000, 1, 100_000, &[7; 512], None))
        .collect();
    assert!(raws.iter().all(|r| r.len() == 6129));
    for group in raws[..85].chunks(16) {
        node.pool_submit_bundle(group.to_vec()).unwrap();
    }
    assert_eq!(
        node.pool_submit(raws[85].clone()).unwrap_err().to_string(),
        "POOL_BYTE_LIMIT"
    );
    let status = node.pool_status().unwrap();
    assert_eq!(status.retained_records, 85);
    assert_eq!(status.retained_bytes, 85 * 6129);
    let packet = admitted(&mut node, g, raws[..85].to_vec(), b.id, 1001);
    assert!(
        PqPacketV1::from_parts(packet.header().clone(), raws, packet.proof().to_vec()).is_err()
    );
    node.activate(packet.id().unwrap()).unwrap();
    assert_eq!(
        nonce(&node.state_at(packet.id().unwrap()).unwrap(), a.id),
        85
    );
}

#[test]
fn explicit_namespace_old_codec_context_and_sql_schema_cannot_fall_back() {
    let dir = tempfile::tempdir().unwrap();
    let (s, a, b) = setup(1000);
    assert!(Node::open(&dir.path().join("old"), s.clone(), 1).is_err());
    assert!(!dir.path().join("old").exists());
    let legacy_settings = Settings::development(Some(1)).unwrap();
    let legacy_path = dir.path().join("old");
    drop(Node::open(&legacy_path, legacy_settings.clone(), 1).unwrap());
    assert!(PqNodeV1::open(&legacy_path, s.clone(), 1).is_err());
    // A refused cross-profile opening does not mutate the original store.
    drop(Node::open(&legacy_path, legacy_settings, 1).unwrap());
    assert!(PqNodeV1::open(
        &dir.path().join("pq"),
        Settings::development(Some(1)).unwrap(),
        1
    )
    .is_err());
    let path = dir.path().join("actual");
    let mut node = PqNodeV1::open(&path, s.clone(), 1).unwrap();
    assert!(node.enable_local_mempool(limits([8; 32])).is_err());
    let configured: u64 = sql(&path)
        .query_row("SELECT COUNT(*) FROM local_pool_metadata", [], |r| r.get(0))
        .unwrap();
    assert_eq!(configured, 0);
    node.enable_local_mempool(limits(b.id)).unwrap();
    let ctx = s.native_pq_context().unwrap();
    for changed in [
        wire::ChainContext {
            genesis: [3; 32],
            ..ctx
        },
        wire::ChainContext {
            parameters: [4; 32],
            ..ctx
        },
    ] {
        let raw = a.transfer(changed, b.id, 1, 1100, 17, 100_000, &[], None);
        assert!(node.pool_submit(raw).is_err());
    }
    let mut raw = a.transfer(ctx, b.id, 1, 1100, 17, 100_000, &[], None);
    let start = raw.len() - b.spki.len();
    raw[start..].copy_from_slice(&b.spki);
    assert!(node.pool_submit(raw).is_err());
    assert_eq!(node.pool_status().unwrap().retained_records, 0);
    let db = Connection::open(path.join("native.sqlite")).unwrap();
    db.execute_batch("CREATE TABLE foreign_pq_authority(value BLOB)")
        .unwrap();
    drop(db);
    assert!(node.pool_status().is_err());
    drop(node);
    assert!(PqNodeV1::open(&path, s, 1).is_err());
}

#[test]
fn interrupted_heavier_reorg_preserves_original_atomic_state_and_recovers_cold() {
    let dir = tempfile::tempdir().unwrap();
    let (s, a, b) = setup(1000);
    let g = s.genesis();
    let mut node = PqNodeV1::open(dir.path(), s.clone(), 1).unwrap();
    let initial = node.state_at(g).unwrap();
    let raw = a.transfer(
        s.native_pq_context().unwrap(),
        b.id,
        1,
        1100,
        17,
        100_000,
        &[],
        None,
    );
    let main = admitted(&mut node, g, vec![raw], b.id, 1001).id().unwrap();
    node.activate(main).unwrap();
    let spent = node.state_at(main).unwrap();
    let fork1 = admitted(&mut node, g, vec![], b.id, 1002).id().unwrap();
    let fork2 = admitted(&mut node, fork1, vec![], b.id, 1003).id().unwrap();
    let mut cuts = 0;
    let error = node
        .activate_with_fault(fork2, &mut |point| {
            if point == "detach:0" {
                cuts += 1;
                Err(Error::from("PQ_REORG_CUT"))
            } else {
                Ok(())
            }
        })
        .unwrap_err();
    assert_eq!(error.to_string(), "PQ_REORG_CUT");
    assert_eq!(cuts, 1);
    assert_eq!(node.active().unwrap().0, main);
    assert_eq!(node.state_at(main).unwrap(), spent);
    drop(node);
    let node = PqNodeV1::open(dir.path(), s.clone(), 1).unwrap();
    assert_eq!(node.active().unwrap().0, fork2);
    let restored = node.state_at(fork2).unwrap();
    assert_eq!(nonce(&restored, a.id), 0);
    assert_eq!(auth_partition(&restored), auth_partition(&initial));
    assert_eq!(
        s.state_root(&restored).unwrap(),
        node.packet(fork2).unwrap().header().state
    );
    assert_eq!(node.state_at(main).unwrap(), spent);
}
