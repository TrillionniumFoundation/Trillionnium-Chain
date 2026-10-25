use super::*;
use trnm_crypto_primitives::pon_work::{self, facts::WorkFactCache};
fn fixture() -> (tempfile::TempDir, Mutex<Node>, Packet) {
    fixture_with_transfers(4)
}
fn signed_transfer(settings: &crate::Settings, nonce: u64) -> Vec<u8> {
    use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
    use trnm_protocol::pon_wire::Envelope;
    let seed = hash(b"DEV-ONLY-KEY", &[&1u64.to_le_bytes()]);
    let key = signing_key_from_hex(&hex::encode(seed)).unwrap();
    let mut payload = crate::development_public(21).unwrap().to_vec();
    payload.extend(1u64.to_le_bytes());
    let mut tx = Envelope {
        network: settings.network(),
        sender: crate::development_public(1).unwrap(),
        nonce,
        expiry: 10000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}
fn fixture_with_transfers(count: u64) -> (tempfile::TempDir, Mutex<Node>, Packet) {
    let dir = tempfile::tempdir().unwrap();
    let clock = now().unwrap();
    let settings = crate::Settings::development(Some(clock - 100)).unwrap();
    let node = Node::open(dir.path(), settings.clone(), 2).unwrap();
    let packet = node
        .make(
            settings.genesis(),
            (1..=count).map(|n| signed_transfer(&settings, n)).collect(),
            crate::development_public(0).unwrap(),
            clock - 90,
            4096,
        )
        .unwrap();
    (dir, Mutex::new(node), packet)
}
fn request(p: &Packet) -> Request {
    Request::Submit {
        packet: hex::encode(p.encode().unwrap()),
    }
}
fn bad_product(p: &Packet, i: usize) -> Packet {
    let mut q = p.clone();
    let at = 4 + 8 * pon_work::CELLS + 4 * i;
    let old = u32::from_le_bytes(q.proof[at..at + 4].try_into().unwrap());
    q.proof[at..at + 4]
        .copy_from_slice(&(((u64::from(old) + 1) % pon_work::Q as u64) as u32).to_le_bytes());
    q
}
#[test]
fn m05_cached_product_variants_reject_then_valid_packet_commits_and_reopens() {
    let (dir, node, p) = fixture();
    let facts = WorkFactCache::new(4).unwrap();
    let initial = node.lock().unwrap().read_active().unwrap();
    let settings = node.lock().unwrap().settings().clone();
    WorkCheckedPacket::verify_with_facts(p.clone(), &facts, &mut |_| Ok(())).unwrap(); // math only, no ledger write
    for i in [0, pon_work::CELLS / 2, pon_work::CELLS - 1] {
        let error = dispatch_shared_with_work_facts(
            &node,
            request(&bad_product(&p, i)),
            &facts,
            &|| Ok(()),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "WORK:Product");
        assert_eq!(node.lock().unwrap().read_active().unwrap(), initial);
    }
    let reply = dispatch_shared_with_work_facts(&node, request(&p), &facts, &|| Ok(())).unwrap();
    assert_eq!(reply["block"], hex::encode(p.id().unwrap()));
    assert_eq!(reply["physical_execution"], false);
    assert_eq!(facts.counters().full_replays, 1);
    assert_eq!(facts.counters().hits, 4);
    let actual = node.lock().unwrap().read_active().unwrap();
    let reference_dir = tempfile::tempdir().unwrap();
    let reference = Mutex::new(Node::open(reference_dir.path(), settings.clone(), 2).unwrap());
    dispatch_shared_with(
        &reference,
        request(&p),
        &mut |_| Ok(()),
        WorkCheckedPacket::verify,
    )
    .unwrap();
    assert_eq!(reference.lock().unwrap().read_active().unwrap(), actual);
    drop(node);
    let reopened = Node::open(dir.path(), settings, 2).unwrap();
    assert_eq!(reopened.read_active().unwrap(), actual);
    println!("M05_FACT_OBSERVATION invalid_product_rejections=3 full_replays=1 cache_hits=4 cold_reopen=true original_state_equal=true physical_execution=false");
}
#[test]
fn m05_invalid_first_cannot_poison_the_valid_block_identifier() {
    let (_dir, node, p) = fixture();
    let facts = WorkFactCache::new(1).unwrap();
    let bad = bad_product(&p, 0);
    assert_eq!(p.id().unwrap(), bad.id().unwrap());
    assert!(dispatch_shared_with_work_facts(&node, request(&bad), &facts, &|| Ok(())).is_err());
    let reply = dispatch_shared_with_work_facts(&node, request(&p), &facts, &|| Ok(())).unwrap();
    assert_eq!(reply["block"], hex::encode(p.id().unwrap()));
    assert_eq!(facts.counters().full_replays, 2);
}
#[test]
fn m05_warm_fact_cannot_bypass_current_context_or_body_root() {
    let (_dir, node, p) = fixture();
    let facts = WorkFactCache::new(4).unwrap();
    WorkCheckedPacket::verify_with_facts(p.clone(), &facts, &mut |_| Ok(())).unwrap();
    let before = node.lock().unwrap().read_active().unwrap();
    for field in 0..3 {
        let mut q = p.clone();
        match field {
            0 => q.header.network[0] ^= 1,
            1 => q.header.target = [0; 32],
            _ => q.header.state[0] ^= 1,
        }
        let a = dispatch_shared_with(
            &node,
            request(&q),
            &mut |_| Ok(()),
            WorkCheckedPacket::verify,
        )
        .unwrap_err();
        let b =
            dispatch_shared_with_work_facts(&node, request(&q), &facts, &|| Ok(())).unwrap_err();
        assert_eq!(a.to_string(), b.to_string());
        assert_eq!(node.lock().unwrap().read_active().unwrap(), before);
    }
    assert!(dispatch_shared_with_work_facts(&node, request(&p), &facts, &|| Ok(())).is_ok());
}
#[test]
fn m05_eight_concurrent_requests_have_one_replay_and_one_durable_block() {
    let (dir, node, p) = fixture();
    let node = Arc::new(node);
    let facts = Arc::new(WorkFactCache::new(1).unwrap());
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let n = node.clone();
            let f = facts.clone();
            let b = barrier.clone();
            let p = p.clone();
            thread::spawn(move || {
                b.wait();
                dispatch_shared_with_work_facts(&n, request(&p), &f, &|| Ok(())).unwrap()
            })
        })
        .collect();
    for handle in threads {
        assert_eq!(
            handle.join().unwrap()["block"],
            hex::encode(p.id().unwrap())
        );
    }
    assert_eq!(facts.counters().full_replays, 1);
    let sql = rusqlite::Connection::open(dir.path().join("native.sqlite")).unwrap();
    let count: u64 = sql
        .query_row(
            "SELECT COUNT(*) FROM blocks WHERE id=?",
            [p.id().unwrap().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
    println!("M05_FACT_CONCURRENT callers=8 full_replays=1 durable_matching_blocks=1");
}
#[test]
fn m05_hit_and_miss_do_not_hold_the_only_durable_owner() {
    let (_dir, node, p) = fixture();
    let facts = WorkFactCache::new(1).unwrap();
    for _ in 0..2 {
        WorkCheckedPacket::verify_with_facts(p.clone(), &facts, &mut |_| {
            assert!(node.try_lock().is_ok());
            Ok(())
        })
        .unwrap();
    }
    dispatch_shared_with(&node, request(&p), &mut |_| Ok(()), |packet| {
        WorkCheckedPacket::verify_with_facts(packet, &facts, &mut |_| {
            assert!(node.try_lock().is_ok());
            Ok(())
        })
    })
    .unwrap();
    assert_eq!(facts.counters().full_replays, 1);
}
#[test]
fn m05_cancel_after_warm_verification_cannot_commit_and_retry_rechecks() {
    let (_dir, node, p) = fixture();
    let facts = WorkFactCache::new(1).unwrap();
    let before = node.lock().unwrap().read_active().unwrap();
    WorkCheckedPacket::verify_with_facts(p.clone(), &facts, &mut |_| Ok(())).unwrap();
    let stopped = AtomicBool::new(false);
    let error = dispatch_shared_with(
        &node,
        request(&p),
        &mut |_| ensure(!stopped.load(Ordering::Acquire), "FACT_TEST_CANCEL"),
        |packet| {
            let checked = WorkCheckedPacket::verify_with_facts(packet, &facts, &mut |_| Ok(()))?;
            stopped.store(true, Ordering::Release);
            Ok(checked)
        },
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "FACT_TEST_CANCEL");
    assert_eq!(node.lock().unwrap().read_active().unwrap(), before);
    assert!(dispatch_shared_with_work_facts(&node, request(&p), &facts, &|| Ok(())).is_ok());
    assert_eq!(facts.counters().full_replays, 1);
}

#[test]
fn m05_one_slot_accepts_full_256_signed_transfer_block_without_duplicate_effects() {
    let (_dir, node, p) = fixture_with_transfers(256);
    let facts = WorkFactCache::new(1).unwrap();
    assert_eq!(p.transactions.len(), 256);
    WorkCheckedPacket::verify_with_facts(p.clone(), &facts, &mut |_| Ok(())).unwrap();
    for _ in 0..2 {
        let reply =
            dispatch_shared_with_work_facts(&node, request(&p), &facts, &|| Ok(())).unwrap();
        assert_eq!(reply["block"], hex::encode(p.id().unwrap()));
    }
    assert_eq!(
        node.lock()
            .unwrap()
            .next_nonce(crate::development_public(1).unwrap())
            .unwrap(),
        257
    );
    assert_eq!(facts.counters().full_replays, 1);
    assert_eq!(facts.capacity(), 1);
    println!("M05_FACT_CAPACITY signed_transfers=256 next_nonce=257 slots=1 full_replays=1 duplicate_dispatches=1");
}

/// Cost ownership is shared across different W1 statements and caller identities.
/// The native verdict is never inferred from a CPU reservation or cached prior result.
#[test]
fn m05_plain_w1_metered_dispatch_debits_invalid_and_valid_work_in_one_owner_domain() {
    let (_dir, node, packet) = fixture();
    let domain = public_v3::ServiceMutationCpuDomain::standalone();
    let cloned = domain.clone();
    assert!(domain.shares_domain_with(&cloned));
    let initial = node.lock().unwrap().read_active().unwrap();
    let bad = bad_product(&packet, 0);
    let failed = dispatch_shared_with_metered_w1(
        &node,
        request(&bad),
        &domain,
        &|| Ok(()),
    )
    .unwrap();
    assert_eq!(failed.native.unwrap_err().to_string(), "WORK:Product");
    assert!(!failed.cpu.accounting_unavailable);
    assert!(failed.cpu.total_cpu_ns.is_some_and(|v| v > 0));
    assert_eq!(node.lock().unwrap().read_active().unwrap(), initial);

    let accepted = dispatch_shared_with_metered_w1(
        &node,
        request(&packet),
        &cloned,
        &|| Ok(()),
    )
    .unwrap();
    assert!(!accepted.cpu.accounting_unavailable);
    assert!(accepted.cpu.total_cpu_ns.is_some_and(|v| v > 0));
    assert_eq!(
        accepted.native.unwrap()["block"],
        hex::encode(packet.id().unwrap())
    );
}

/// Reconstructing a new CPU budget for the same durable owner cannot mint a
/// second source of start-credit. The original Node owner keeps one domain ID.
#[test]
fn m05_metered_w1_rejects_fresh_cpu_domain_after_binding() {
    let (_dir, node, packet) = fixture();
    let original = public_v3::ServiceMutationCpuDomain::standalone();
    let another = public_v3::ServiceMutationCpuDomain::standalone();
    assert!(!original.shares_domain_with(&another));
    let invalid = bad_product(&packet, 0);
    let before = node.lock().unwrap().read_active().unwrap();
    let first = dispatch_shared_with_metered_w1(
        &node,
        request(&invalid),
        &original,
        &|| Ok(()),
    )
    .unwrap();
    assert_eq!(first.native.unwrap_err().to_string(), "WORK:Product");
    assert!(!first.cpu.accounting_unavailable);
    assert!(dispatch_shared_with_metered_w1(
        &node,
        request(&packet),
        &another,
        &|| Ok(()),
    )
    .is_err());
    assert_eq!(node.lock().unwrap().read_active().unwrap(), before);
    // Reusing the original domain must still admit an honest statement.
    let valid = dispatch_shared_with_metered_w1(
        &node,
        request(&packet),
        &original,
        &|| Ok(()),
    )
    .unwrap();
    assert!(!valid.cpu.accounting_unavailable);
    assert!(valid.native.is_ok());
}
