//! Explicit fresh PQ2 account profile through the actual M05/M06/PoN/SQL owner.
//! Public fixture seeds, no production authority or legacy migration claim.
use rusqlite::{Connection, OpenFlags};
use trnm_crypto_primitives::pon_work;
use trnm_mvcc_fee::pon_executor::State;
use trnm_pon_node::{
    pq_accounts_v2::{GenesisAccount, PqNodeV2, PqPacketV2},
    Error, Node, Packet, PoolLimits, PoolState, Settings,
};
use trnm_protocol::{pon_wire::Hash, pq_native_accounts_v2 as wire};
#[path = "../../trnm-protocol/tests/support/native_pq_accounts_fixture.rs"]
mod fixture;

fn setup(timestamp: u64) -> (Settings, fixture::Key, fixture::Key) {
    let a = fixture::Key::public_test_seed(101);
    let b = fixture::Key::public_test_seed(102);
    let settings = Settings::native_pq_accounts_v2(
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
        .filter(|(k, _)| {
            k.starts_with("pq-auth-v2:")
                || k.starts_with("pq-key-v2:")
                || k.starts_with("pq-key-status-v2:")
        })
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
// Observations cover the actual calls below, including failed results. They
// are shared-host wall times, not isolated CPU, energy, worst-case or TPS bounds.
struct PhaseTimer {
    start: std::time::Instant,
    phase: &'static str,
    details: serde_json::Value,
    result: &'static str,
}
impl Drop for PhaseTimer {
    fn drop(&mut self) {
        eprintln!(
            "{}",
            serde_json::json!({"schema":"native-pq2-phase-observation-v1",
            "phase":self.phase,"details":&self.details,"result":self.result,
            "wall_nanoseconds":self.start.elapsed().as_nanos(),
            "scope":"actual complete call on shared host; not isolated CPU, worst-case cost or TPS"})
        );
    }
}
fn timed<T, E>(
    phase: &'static str,
    details: serde_json::Value,
    run: impl FnOnce() -> std::result::Result<T, E>,
) -> std::result::Result<T, E> {
    let mut timer = PhaseTimer {
        start: std::time::Instant::now(),
        phase,
        details,
        result: "unwind",
    };
    let result = run();
    timer.result = if result.is_ok() { "ok" } else { "error" };
    result
}
fn admitted(
    node: &mut PqNodeV2,
    parent: Hash,
    txs: Vec<Vec<u8>>,
    miner: Hash,
    time: u64,
) -> PqPacketV2 {
    let count = txs.len();
    let raw_bytes: usize = txs.iter().map(Vec::len).sum();
    let packet=timed("native_make_m06_and_complete_pon_search",serde_json::json!({"parent":hex::encode(parent),"transactions":count,"raw_bytes":raw_bytes,"attempt_cap":4096}),||node.make(parent,txs,miner,time,4096)).unwrap();
    let id = packet.id().unwrap();
    timed("independent_complete_w1_reference",serde_json::json!({"block":hex::encode(id),"proof_bytes":packet.proof().len(),"winning_header_nonce":packet.header().nonce}),||pon_work::verify_reference(packet.header().challenge(),packet.header().work_task,packet.header().target,packet.proof())).unwrap();
    assert_eq!(
        timed(
            "native_admit_w1_m06_sql",
            serde_json::json!({"block":hex::encode(id),"transactions":count,"raw_bytes":raw_bytes}),
            || node.admit(&packet, 10_000)
        )
        .unwrap(),
        id
    );
    packet
}

#[test]
fn actual_pq_pool_m06_pon_sql_cold_open_and_heavier_fork_requeue() {
    let dir = tempfile::tempdir().unwrap();
    let (s, a, b) = setup(1000);
    let genesis = s.genesis();
    let mut node = PqNodeV2::open(dir.path(), s.clone(), 1).unwrap();
    node.enable_local_mempool(limits(b.id)).unwrap();
    let initial = node.state_at(genesis).unwrap();
    let auth = auth_partition(&initial);
    assert_eq!(auth.len(), 6);
    let raw = a.transfer(
        s.native_pq_accounts_context().unwrap(),
        b.id,
        1,
        1100,
        17,
        100_000,
        &[],
        None,
    );
    {
        use trnm_mvcc_fee::pon_executor::pq_accounts_v2 as pq;
        let (cfg, component_state, component_genesis) = pq::genesis(
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
            1000,
        )
        .unwrap();
        assert_eq!(component_genesis, genesis);
        assert_eq!(component_state, initial);
        assert_eq!(
            pq::context(&cfg).unwrap(),
            s.native_pq_accounts_context().unwrap()
        );
        timed("m01_m06_signature_with_actual_state_key_reads",serde_json::json!({"raw_bytes":raw.len(),"witnesses":1,"state_keys":initial.len(),"fixture":"bound native genesis"}),||pq::prepare_signature(&initial,&raw,1001,&cfg)).unwrap();
        timed(
            "actual_state_grammar_and_current_authority",
            serde_json::json!({"state_keys":initial.len()}),
            || pq::validate_current_authority(&initial, &raw, &cfg),
        )
        .unwrap();
        let alternate = a.transfer(
            s.native_pq_accounts_context().unwrap(),
            b.id,
            1,
            1100,
            18,
            100_000,
            &[],
            None,
        );
        let signature_bytes = trnm_protocol::pq_frame::ML_DSA_65_SIGNATURE_BYTES;
        let mut wrong_message = raw.clone();
        let start = wrong_message.len() - signature_bytes;
        wrong_message[start..].copy_from_slice(&alternate[alternate.len() - signature_bytes..]);
        assert!(wire::UnverifiedEnvelope::decode(&wrong_message).is_ok());
        assert!(timed("canonical_signature_for_wrong_message",serde_json::json!({"raw_bytes":wrong_message.len(),"state_keys":initial.len(),"scope":"genuine canonical ML-DSA signature from another statement, not a proven global worst case"}),||pq::prepare_signature(&initial,&wrong_message,1001,&cfg)).is_err());
    }
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
        PqPacketV2::decode(&raw_packet).unwrap().encode().unwrap(),
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
    let mut node = PqNodeV2::open(dir.path(), s.clone(), 1).unwrap();
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
    assert_eq!(status.profile, "native-local-queued-npq2-v1");
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
    let mut node = PqNodeV2::open(dir.path(), s.clone(), 1).unwrap();
    node.enable_local_mempool(limits(b.id)).unwrap();
    let ctx = s.native_pq_accounts_context().unwrap();
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
    let signature_start = forged.len() - trnm_protocol::pq_frame::ML_DSA_65_SIGNATURE_BYTES;
    forged[signature_start] ^= 1;
    assert!(wire::UnverifiedEnvelope::decode(&forged).is_ok());
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
    let mut node = PqNodeV2::open(dir.path(), s, 1).unwrap();
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
    let mut node = PqNodeV2::open(dir.path(), s.clone(), 1).unwrap();
    node.enable_local_mempool(limits(b.id)).unwrap();
    let raw = a.transfer(
        s.native_pq_accounts_context().unwrap(),
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
    let node = PqNodeV2::open(dir.path(), s, 1).unwrap();
    assert_eq!(
        nonce(&node.state_at(packet.id().unwrap()).unwrap(), a.id),
        1
    );
    // Parent time need not be the MTP lower bound. On a two-block fork the
    // next preview uses sorted upper median, preserving the original time rule.
    let dir2 = tempfile::tempdir().unwrap();
    let (s, a, b) = setup(1000);
    let g = s.genesis();
    let mut node = PqNodeV2::open(dir2.path(), s.clone(), 1).unwrap();
    let first = admitted(&mut node, g, vec![], b.id, 1100).id().unwrap();
    node.activate(first).unwrap();
    let second = admitted(&mut node, first, vec![], b.id, 1200).id().unwrap();
    node.activate(second).unwrap();
    node.enable_local_mempool(limits(b.id)).unwrap();
    let raw = a.transfer(
        s.native_pq_accounts_context().unwrap(),
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
    let mut node = PqNodeV2::open(dir3.path(), s, 1).unwrap();
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
fn full_4263_byte_rows_and_packet_have_actual_122_transfer_limit() {
    let dir = tempfile::tempdir().unwrap();
    let (s, a, b) = setup(1000);
    let g = s.genesis();
    let mut node = PqNodeV2::open(dir.path(), s.clone(), 1).unwrap();
    node.enable_local_mempool(limits(b.id)).unwrap();
    let ctx = s.native_pq_accounts_context().unwrap();
    let raws: Vec<_> = (1..=123)
        .map(|n| a.transfer(ctx, b.id, n, 2000, 1, 100_000, &[7; 512], None))
        .collect();
    assert!(raws.iter().all(|r| r.len() == 4263));
    let mut pending_members = 0;
    for group in raws[..122].chunks(16) {
        let receipt=timed("capacity_actual_pool_bundle",serde_json::json!({"transactions":group.len(),"raw_bytes":group.iter().map(Vec::len).sum::<usize>()}),||node.pool_submit_bundle(group.to_vec())).unwrap();
        // The original owner reconstructs the entire queued prefix for each
        // submission. Both counts describe that prefix, including prior groups.
        pending_members += group.len();
        assert_eq!(receipt.typed_gate_admissions, pending_members);
        assert_eq!(receipt.typed_gate_ready_metadata, pending_members);
    }
    assert_eq!(pending_members, 122);
    assert_eq!(
        node.pool_submit(raws[122].clone()).unwrap_err().to_string(),
        "POOL_BYTE_LIMIT"
    );
    let status = node.pool_status().unwrap();
    assert_eq!(status.retained_records, 122);
    assert_eq!(status.retained_bytes, 122 * 4263);
    let packet = admitted(&mut node, g, raws[..122].to_vec(), b.id, 1001);
    assert!(
        PqPacketV2::from_parts(packet.header().clone(), raws, packet.proof().to_vec()).is_err()
    );
    node.activate(packet.id().unwrap()).unwrap();
    assert_eq!(
        nonce(&node.state_at(packet.id().unwrap()).unwrap(), a.id),
        122
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
    assert!(PqNodeV2::open(&legacy_path, s.clone(), 1).is_err());
    // A refused cross-profile opening does not mutate the original store.
    drop(Node::open(&legacy_path, legacy_settings, 1).unwrap());
    assert!(PqNodeV2::open(
        &dir.path().join("pq"),
        Settings::development(Some(1)).unwrap(),
        1
    )
    .is_err());
    let path = dir.path().join("actual");
    let mut node = PqNodeV2::open(&path, s.clone(), 1).unwrap();
    assert!(node.enable_local_mempool(limits([0; 32])).is_err());
    let configured: u64 = sql(&path)
        .query_row("SELECT COUNT(*) FROM local_pool_metadata", [], |r| r.get(0))
        .unwrap();
    assert_eq!(configured, 0);
    node.enable_local_mempool(limits(b.id)).unwrap();
    let ctx = s.native_pq_accounts_context().unwrap();
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
    // Ordinary NPQ2 carries no SPKI: corrupt the actual ML-DSA signature.
    *raw.last_mut().unwrap() ^= 1;
    assert!(node.pool_submit(raw).is_err());
    assert_eq!(node.pool_status().unwrap().retained_records, 0);
    let db = Connection::open(path.join("native.sqlite")).unwrap();
    db.execute_batch("CREATE TABLE foreign_pq_authority(value BLOB)")
        .unwrap();
    drop(db);
    assert!(node.pool_status().is_err());
    drop(node);
    assert!(PqNodeV2::open(&path, s, 1).is_err());
}

#[test]
fn interrupted_heavier_reorg_preserves_original_atomic_state_and_recovers_cold() {
    let dir = tempfile::tempdir().unwrap();
    let (s, a, b) = setup(1000);
    let g = s.genesis();
    let mut node = PqNodeV2::open(dir.path(), s.clone(), 1).unwrap();
    let initial = node.state_at(g).unwrap();
    let raw = a.transfer(
        s.native_pq_accounts_context().unwrap(),
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
    let node = PqNodeV2::open(dir.path(), s.clone(), 1).unwrap();
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

// Fresh generation-one convenience for the retained six native controls above.
// Real current-state keys and full signatures are still checked by M01/M05/M06.
trait TransferFixture {
    #[allow(clippy::too_many_arguments)]
    fn transfer(
        &self,
        ctx: wire::ChainContext,
        recipient: Hash,
        nonce: u64,
        expires_at: u64,
        amount: u64,
        max_fee: u64,
        memo: &[u8],
        randomness: Option<[u8; 32]>,
    ) -> Vec<u8>;
}
impl TransferFixture for fixture::Key {
    #[allow(clippy::too_many_arguments)]
    fn transfer(
        &self,
        context: wire::ChainContext,
        recipient: Hash,
        nonce: u64,
        expires_at: u64,
        amount: u64,
        max_fee: u64,
        memo: &[u8],
        randomness: Option<[u8; 32]>,
    ) -> Vec<u8> {
        let common = wire::Common {
            context,
            account: self.id,
            nonce,
            expires_at,
            max_fee,
            generation: 1,
        };
        let payload = [
            recipient.as_slice(),
            &amount.to_le_bytes(),
            &(memo.len() as u16).to_be_bytes(),
            memo,
        ]
        .concat();
        fixture::signed(
            &common,
            1,
            &payload,
            &[fixture::Witness {
                key: self,
                role: 1,
                generation: 1,
                carried: false,
            }],
            randomness,
        )
    }
}

fn common(s: &Settings, account: Hash, nonce: u64, generation: u64) -> wire::Common {
    wire::Common {
        context: s.native_pq_accounts_context().unwrap(),
        account,
        nonce,
        expires_at: 2000,
        max_fee: 100_000,
        generation,
    }
}
#[allow(clippy::too_many_arguments)]
fn ordinary(
    s: &Settings,
    key: &fixture::Key,
    account: Hash,
    nonce: u64,
    generation: u64,
    kind: u8,
    payload: &[u8],
) -> Vec<u8> {
    fixture::signed(
        &common(s, account, nonce, generation),
        kind,
        payload,
        &[fixture::Witness {
            key,
            role: 1,
            generation,
            carried: false,
        }],
        None,
    )
}
fn register(s: &Settings, key: &fixture::Key) -> Vec<u8> {
    fixture::signed(
        &common(s, key.id, 1, 0),
        wire::REGISTER,
        &1_u64.to_be_bytes(),
        &[fixture::Witness {
            key,
            role: 2,
            generation: 1,
            carried: true,
        }],
        None,
    )
}
fn auth(state: &State, account: Hash) -> &serde_json::Value {
    &state[&format!("pq-auth-v2:{}", hex::encode(account))]
}
fn pool_ordinal(path: &std::path::Path) -> u64 {
    sql(path)
        .query_row(
            "SELECT seq FROM sqlite_sequence WHERE name='local_pool_groups'",
            [],
            |r| r.get(0),
        )
        .unwrap()
}
fn exact_pool_block(
    node: &mut PqNodeV2,
    parent: Hash,
    raw: Vec<u8>,
    miner: Hash,
    time: u64,
) -> Hash {
    let syntax = wire::UnverifiedEnvelope::decode(&raw).unwrap();
    let receipt=timed("actual_pool_crypto_state_m06_sql",serde_json::json!({"kind":syntax.kind,"raw_bytes":raw.len(),"witnesses":syntax.witnesses().len(),"parent":hex::encode(parent)}),||node.pool_submit(raw.clone())).unwrap();
    assert_eq!(receipt.typed_gate_admissions, 1);
    let (active, generation) = node.active().unwrap();
    assert_eq!(active, parent);
    let batch = node
        .pool_mining_batch(parent, generation, 256, 524288)
        .unwrap();
    assert_eq!(batch.transactions, vec![raw]);
    assert_eq!(node.pool_validate_batch(&batch).unwrap(), 1);
    let packet = admitted(node, parent, batch.transactions, miner, time);
    let id = packet.id().unwrap();
    node.activate(id).unwrap();
    id
}

#[test]
fn unregistered_pure_pon_miner_matures_actual_rewards_then_registers_without_whitelist() {
    let dir = tempfile::tempdir().unwrap();
    let (s, alice, _) = setup(1000);
    let newcomer = fixture::Key::public_test_seed(103);
    let name = format!("account:{}", hex::encode(newcomer.id));
    let mut node = PqNodeV2::open(dir.path(), s.clone(), 1).unwrap();
    node.enable_local_mempool(limits(newcomer.id)).unwrap();
    assert!(!node.state_at(s.genesis()).unwrap().contains_key(&name));
    assert!(node.pool_submit(register(&s, &newcomer)).is_err());
    // Fixed research-profile contract; actual balances/fees below check it.
    let subsidy = 1_000_u64;
    let register_fee = 5_891_u64;
    let needed = register_fee.div_ceil(subsidy);
    assert!(needed > 0 && needed <= 16); // finite original-parameter fixture
    let maturity = 20_u64;
    let mut tip = s.genesis();
    for height in 1..=needed + maturity {
        let miner = if height <= needed {
            newcomer.id
        } else {
            alice.id
        };
        let packet = admitted(&mut node, tip, vec![], miner, 1000 + height * 10);
        tip = packet.id().unwrap();
        node.activate(tip).unwrap();
        let state = node.state_at(tip).unwrap();
        if height <= maturity {
            assert!(!state.contains_key(&name));
        }
        if height == maturity + 1 {
            assert_eq!(state[&name]["balance"], subsidy);
        }
        assert!(!state.contains_key(&format!("pq-auth-v2:{}", hex::encode(newcomer.id))));
    }
    let before = node.state_at(tip).unwrap();
    assert_eq!(before[&name]["balance"], needed * subsidy);
    assert_eq!(nonce(&before, newcomer.id), 0);
    let final_tip = exact_pool_block(
        &mut node,
        tip,
        register(&s, &newcomer),
        newcomer.id,
        1000 + (needed + maturity + 1) * 10,
    );
    let after = node.state_at(final_tip).unwrap();
    assert_eq!(nonce(&after, newcomer.id), 1);
    assert_eq!(
        auth(&after, newcomer.id)["key_id"],
        hex::encode(newcomer.id)
    );
    assert_eq!(after[&name]["balance"], needed * subsidy - register_fee);
    drop(node);
    let node = PqNodeV2::open(dir.path(), s, 1).unwrap();
    assert_eq!(node.state_at(final_tip).unwrap(), after);
    eprintln!("PQ2 actual reward-funded registration: mined rewards={needed}, maturity={maturity}, fee={register_fee}; no runtime registry or additional consensus weight");
}

#[test]
fn dual_key_rotation_preserves_actual_task_permissions_and_reorg_reauthorizes_original_pool() {
    use trnm_protocol::pon_wire::hash;
    let dir = tempfile::tempdir().unwrap();
    let (s, owner, provider) = setup(1000);
    let next = fixture::Key::public_test_seed(105);
    let mut node = PqNodeV2::open(dir.path(), s.clone(), 1).unwrap();
    node.enable_local_mempool(limits(provider.id)).unwrap();
    let budget = 50_000_u64;
    let deadline = 30_u64;
    let task = hash(
        b"task-instance-v3",
        &[
            &s.network(),
            &s.parameters(),
            &owner.id,
            &1_u64.to_le_bytes(),
            &provider.id,
            &budget.to_le_bytes(),
            &deadline.to_le_bytes(),
        ],
    );
    let reserve = ordinary(
        &s,
        &owner,
        owner.id,
        1,
        1,
        2,
        &[
            task.as_slice(),
            &provider.id,
            &budget.to_le_bytes(),
            &deadline.to_le_bytes(),
        ]
        .concat(),
    );
    let reserved = exact_pool_block(&mut node, s.genesis(), reserve, provider.id, 1010);
    let payload = [
        2_u64.to_be_bytes().as_slice(),
        &timed(
            "actual_rotation_authority_state_read",
            serde_json::json!({"parent":hex::encode(reserved)}),
            || node.authority_digest(reserved, owner.id),
        )
        .unwrap(),
    ]
    .concat();
    let rotate = fixture::signed(
        &common(&s, owner.id, 2, 1),
        wire::ROTATE,
        &payload,
        &[
            fixture::Witness {
                key: &owner,
                role: 3,
                generation: 1,
                carried: false,
            },
            fixture::Witness {
                key: &next,
                role: 4,
                generation: 2,
                carried: true,
            },
        ],
        None,
    );
    assert_eq!(rotate.len(), 9272);
    let extra = ordinary(&s, &owner, owner.id, 3, 1, 3, &task);
    for txs in [
        vec![rotate.clone(), extra.clone()],
        vec![extra, rotate.clone()],
    ] {
        assert!(node.make(reserved, txs, provider.id, 1020, 4096).is_err());
    }
    let rotated = exact_pool_block(&mut node, reserved, rotate.clone(), provider.id, 1020);
    let rotated_state = node.state_at(rotated).unwrap();
    assert_eq!(auth(&rotated_state, owner.id)["generation"], 2);
    assert_eq!(
        auth(&rotated_state, owner.id)["key_id"],
        hex::encode(next.id)
    );
    assert_eq!(
        rotated_state[&format!(
            "pq-key-status-v2:{}:0000000000000001",
            hex::encode(owner.id)
        )]["retired"],
        true
    );
    assert!(node
        .pool_submit(ordinary(&s, &owner, owner.id, 3, 1, 3, &task))
        .is_err());
    assert!(node
        .pool_submit(ordinary(&s, &provider, provider.id, 1, 1, 3, &task))
        .is_err());
    let output = [9; 32];
    let receipt = ordinary(
        &s,
        &provider,
        provider.id,
        1,
        1,
        4,
        &[task.as_slice(), &output].concat(),
    );
    let received = exact_pool_block(&mut node, rotated, receipt, provider.id, 1030);
    let accept = ordinary(
        &s,
        &next,
        owner.id,
        3,
        2,
        5,
        &[task.as_slice(), &output].concat(),
    );
    let accepted = exact_pool_block(&mut node, received, accept, provider.id, 1040);
    let key = format!("task:{}", hex::encode(task));
    assert_eq!(node.state_at(accepted).unwrap()[&key]["status"], "settled");
    // A genuine competing branch executes original CancelTask under the SAME
    // stable account/new key, then wins by ordinary accumulated PoN work.
    let cancel = ordinary(&s, &next, owner.id, 3, 2, 3, &task);
    let mut cancelled = admitted(&mut node, rotated, vec![cancel], provider.id, 1031)
        .id()
        .unwrap();
    for time in [1041, 1051] {
        cancelled = admitted(&mut node, cancelled, vec![], provider.id, time)
            .id()
            .unwrap();
    }
    node.activate(cancelled).unwrap();
    assert_eq!(
        node.state_at(cancelled).unwrap()[&key]["status"],
        "cancelled"
    );
    let ordinal = pool_ordinal(dir.path());
    // Roll the authority change itself out. No key/nonce/local-ordinal shortcut:
    // the original queued rotation must be reverified against the new parent.
    let mut fork = reserved;
    for height in 2..=6 {
        fork = admitted(&mut node, fork, vec![], provider.id, 1001 + height * 10)
            .id()
            .unwrap();
    }
    node.activate(fork).unwrap();
    let old = node.state_at(fork).unwrap();
    assert_eq!(auth(&old, owner.id)["generation"], 1);
    assert_eq!(auth(&old, owner.id)["key_id"], hex::encode(owner.id));
    assert!(!old.contains_key(&format!(
        "pq-key-v2:{}:0000000000000002",
        hex::encode(owner.id)
    )));
    assert_eq!(nonce(&old, owner.id), 1);
    assert_eq!(pool_ordinal(dir.path()), ordinal);
    let (active, generation) = node.active().unwrap();
    let batch = timed(
        "actual_pool_reauthorization_at_branch",
        serde_json::json!({"parent":hex::encode(active),"local_generation":generation}),
        || node.pool_mining_batch(active, generation, 256, 524288),
    )
    .unwrap();
    assert_eq!(batch.transactions.first(), Some(&rotate));
    assert_eq!(
        node.pool_validate_batch(&batch).unwrap(),
        batch.transactions.len()
    );
    drop(node);
    let mut node = PqNodeV2::open(dir.path(), s.clone(), 1).unwrap();
    assert_eq!(node.active().unwrap().0, fork);
    assert_eq!(
        auth(&node.state_at(fork).unwrap(), owner.id)["generation"],
        1
    );
    assert_eq!(node.state_at(rotated).unwrap(), rotated_state);
    assert_eq!(pool_ordinal(dir.path()), ordinal);
    let (active, generation) = node.active().unwrap();
    let batch = timed(
        "actual_pool_reauthorization_at_branch",
        serde_json::json!({"parent":hex::encode(active),"local_generation":generation}),
        || node.pool_mining_batch(active, generation, 256, 524288),
    )
    .unwrap();
    assert_eq!(batch.transactions.first(), Some(&rotate));
}

#[test]
fn prior_pq_commitment_actual_legacy_pon_checkpoint_claim_cold_reorg_and_permission_conserve() {
    use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
    use trnm_mvcc_fee::continuity_v1;
    use trnm_pon_node::{
        development_public,
        pq_accounts_v2::{PrecommittedAccount, TrustedPqPrecommitments},
    };
    use trnm_protocol::pon_wire::{hash, Envelope};
    let source_dir = tempfile::tempdir().unwrap();
    let source_settings = Settings::development_with_profiles(
        Some(1000),
        "legacy-first-two-v3",
        continuity_v1::PROFILE,
    )
    .unwrap();
    let prior: Vec<_> = (111..115).map(fixture::Key::public_test_seed).collect();
    let entries: Vec<_> = prior
        .iter()
        .enumerate()
        .map(|(i, key)| PrecommittedAccount {
            source_account: development_public(i as u64).unwrap(),
            spki: key.spki.clone(),
            generation: 9,
        })
        .collect();
    // Freeze this independent PQ trust premise BEFORE obtaining the checkpoint.
    // The old repository did not provide this prior PQ registration; source
    // retirement/finality/asset locking remain external, and this is valueless.
    let registry = TrustedPqPrecommitments::pin(
        source_settings.network(),
        source_settings.genesis(),
        &entries,
    )
    .unwrap();
    let prior_commitment = registry.commitment();
    let mut source =
        Node::open_with_authenticated_state(source_dir.path(), source_settings.clone(), 1).unwrap();
    let owner = development_public(0).unwrap();
    let provider = development_public(1).unwrap();
    let budget = 10_000_u64;
    let deadline = 10_u64;
    let task = hash(
        b"task-instance-v3",
        &[
            &source_settings.network(),
            &source_settings.parameters(),
            &owner,
            &1_u64.to_le_bytes(),
            &provider,
            &budget.to_le_bytes(),
            &deadline.to_le_bytes(),
        ],
    );
    let mut reserve = Envelope {
        network: source_settings.network(),
        sender: owner,
        nonce: 1,
        expiry: 2000,
        fee_limit: 100_000,
        tag: 2,
        payload: [
            task.as_slice(),
            &provider,
            &budget.to_le_bytes(),
            &deadline.to_le_bytes(),
        ]
        .concat(),
        signature: [0; 64],
    };
    let ed =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()]))).unwrap();
    reserve.signature = hex::decode(sign_hex(&ed, &reserve.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    let source_packet = source
        .make_consensus_maintenance(
            source_settings.genesis(),
            vec![reserve.encode().unwrap()],
            provider,
            1010,
            4096,
        )
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
    assert_eq!(
        source_packet.header.state,
        source_settings.state_root(&source_state).unwrap()
    );
    assert!(source
        .pin_native_pq_migration_checkpoint(registry.clone(), [7; 32])
        .is_err());
    let anchor = source
        .pin_native_pq_migration_checkpoint(registry.clone(), checkpoint)
        .unwrap();
    assert_eq!(anchor.checkpoint(), checkpoint);
    // A still-valid old active root during an interrupted reorg is not a
    // ready/current export point. The already pinned prior anchor is separate.
    let mut source_fork = source_settings.genesis();
    for timestamp in [1011, 1021] {
        let packet = source
            .make_consensus_maintenance(source_fork, vec![], provider, timestamp, 4096)
            .unwrap();
        source_fork = source.admit(&packet, 10_000).unwrap();
    }
    let mut export_cut = 0;
    let cut_error = source
        .activate_with_fault(
            source_fork,
            Some(&mut |point| {
                if point == "detach:0" {
                    export_cut += 1;
                    Err(Error::from("PQ2_SOURCE_EXPORT_REORG_CUT"))
                } else {
                    Ok(())
                }
            }),
        )
        .unwrap_err();
    assert_eq!(cut_error.to_string(), "PQ2_SOURCE_EXPORT_REORG_CUT");
    assert_eq!(export_cut, 1);
    assert_eq!(source.active().unwrap().0, checkpoint);
    let refused = match source.pin_native_pq_migration_checkpoint(registry.clone(), checkpoint) {
        Ok(_) => panic!("unfinished source reorg exported as ready"),
        Err(error) => error,
    };
    assert_eq!(refused.to_string(), "REORG_IN_PROGRESS");
    assert_eq!(source.recover().unwrap(), source_fork);
    assert!(source
        .pin_native_pq_migration_checkpoint(registry, checkpoint)
        .is_err());
    let s = Settings::native_pq_accounts_v2_with_migration(&[], 1500, anchor).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut node = PqNodeV2::open(dir.path(), s.clone(), 1).unwrap();
    node.enable_local_mempool(limits(provider)).unwrap();
    let genesis = node.state_at(s.genesis()).unwrap();
    assert_eq!(genesis["meta:issued"], source_state["meta:issued"]);
    for (key, value) in source_state
        .iter()
        .filter(|(key, _)| key.starts_with("account:"))
    {
        assert_eq!(&genesis[key], value);
    }
    let task_key = format!("task:{}", hex::encode(task));
    assert_eq!(genesis[&task_key]["deadline"], 9);
    let reward_key = source_state
        .keys()
        .find(|key| key.starts_with("reward:"))
        .unwrap();
    assert_eq!(genesis[reward_key]["maturity"], 20);
    let next = fixture::Key::public_test_seed(120);
    let raw = fixture::signed(
        &common(&s, owner, 2, 0),
        wire::CLAIM,
        &node.migration_claim_payload(owner).unwrap(),
        &[
            fixture::Witness {
                key: &prior[0],
                role: 5,
                generation: 9,
                carried: false,
            },
            fixture::Witness {
                key: &next,
                role: 6,
                generation: 1,
                carried: true,
            },
        ],
        None,
    );
    assert_eq!(raw.len(), 9432);
    assert!(node.pool_submit(reserve.encode().unwrap()).is_err());
    let claimed = exact_pool_block(&mut node, s.genesis(), raw.clone(), provider, 1510);
    assert!(node.pool_submit(raw.clone()).is_err());
    let claimed_state = node.state_at(claimed).unwrap();
    assert_eq!(nonce(&claimed_state, owner), 2);
    assert_eq!(auth(&claimed_state, owner)["key_id"], hex::encode(next.id));
    assert_eq!(
        claimed_state[&format!("pq-import-v2:{}", hex::encode(owner))]["claimed"],
        true
    );
    drop(node);
    let mut node = PqNodeV2::open(dir.path(), s.clone(), 1).unwrap();
    assert_eq!(node.state_at(claimed).unwrap(), claimed_state);
    let cancel = ordinary(&s, &next, owner, 3, 1, 3, &task);
    let cancelled = exact_pool_block(&mut node, claimed, cancel, provider, 1520);
    assert_eq!(
        node.state_at(cancelled).unwrap()[&task_key]["status"],
        "cancelled"
    );
    let ordinal = pool_ordinal(dir.path());
    let mut fork = s.genesis();
    for height in 1..=3 {
        fork = admitted(&mut node, fork, vec![], provider, 1501 + height * 10)
            .id()
            .unwrap();
    }
    node.activate(fork).unwrap();
    let restored = node.state_at(fork).unwrap();
    assert_eq!(nonce(&restored, owner), 1);
    assert!(!restored.contains_key(&format!("pq-auth-v2:{}", hex::encode(owner))));
    assert_eq!(
        restored[&format!("pq-import-v2:{}", hex::encode(owner))]["claimed"],
        false
    );
    assert_eq!(restored[&task_key]["remaining"], budget);
    assert_eq!(pool_ordinal(dir.path()), ordinal);
    let (active, generation) = node.active().unwrap();
    let batch = timed(
        "actual_pool_reauthorization_at_branch",
        serde_json::json!({"parent":hex::encode(active),"local_generation":generation}),
        || node.pool_mining_batch(active, generation, 256, 524288),
    )
    .unwrap();
    assert_eq!(batch.transactions, vec![raw]);
    let reattached = admitted(&mut node, active, batch.transactions, provider, 1540)
        .id()
        .unwrap();
    node.activate(reattached).unwrap();
    let restored_claim = node.state_at(reattached).unwrap();
    assert_eq!(nonce(&restored_claim, owner), 2);
    assert_eq!(auth(&restored_claim, owner)["key_id"], hex::encode(next.id));
    assert_eq!(pool_ordinal(dir.path()), ordinal);
    drop(node);
    let node = PqNodeV2::open(dir.path(), s.clone(), 1).unwrap();
    assert_eq!(node.active().unwrap().0, reattached);
    assert_eq!(node.state_at(reattached).unwrap(), restored_claim);
    assert_eq!(
        s.state_root(&restored_claim).unwrap(),
        node.packet(reattached).unwrap().header().state
    );
    assert_eq!(source.state_at(checkpoint).unwrap(), source_state);
    eprintln!("PQ2 conditional migration: prior registry={}, actual admitted source checkpoint={}, exact source State={}, original supply={} ; source-chain retirement/finality and prior trust remain independent premises",hex::encode(prior_commitment),hex::encode(checkpoint),hex::encode(source_packet.header.state),source_state["meta:issued"]);
}
