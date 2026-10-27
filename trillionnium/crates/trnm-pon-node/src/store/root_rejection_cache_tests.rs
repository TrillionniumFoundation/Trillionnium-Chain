use super::*;
use root_rejection_cache::{Cache, FinalMismatch, MAX_ENTRIES, MAX_RETAINED_BYTES, TTL_NS};
use std::sync::atomic::{AtomicUsize, Ordering};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_protocol::pon_wire::Envelope;
use trnm_protocol::pon_wire::HEADER_BYTES;

fn transfer(settings: &Settings, nonce: u64) -> Vec<u8> {
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()]))).unwrap();
    let mut payload = development_public(1).unwrap().to_vec();
    payload.extend(1_u64.to_le_bytes());
    let mut envelope = Envelope {
        network: settings.network(),
        sender: development_public(0).unwrap(),
        nonce,
        expiry: 10_000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    envelope.signature = hex::decode(sign_hex(&key, &envelope.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    envelope.encode().unwrap()
}
fn remake(mut packet: Packet) -> Packet {
    let (a, b) = maintenance();
    let producer = pon_work::PreparedTask::new(&a, &b).unwrap();
    for _ in 0..4096 {
        packet.proof = producer.prove(packet.header.challenge()).unwrap();
        if pon_work::verify(
            packet.header.challenge(),
            packet.header.work_task,
            packet.header.target,
            &packet.proof,
        )
        .is_ok()
        {
            return packet;
        }
        packet.header.nonce += 1;
    }
    panic!("bounded real W1 producer search exhausted");
}
fn fixture(path: &Path) -> (Node, Packet, Packet) {
    let settings = Settings::development(Some(1)).unwrap();
    let node = Node::open_with_authenticated_state(path, settings.clone(), 1).unwrap();
    let valid = node
        .make(
            settings.genesis(),
            vec![transfer(&settings, 1)],
            development_public(0).unwrap(),
            1001,
            4096,
        )
        .unwrap();
    let mut wrong = valid.clone();
    wrong.header.state[0] ^= 1;
    (node, valid, remake(wrong))
}
fn entries(node: &Node) -> usize {
    node.root_rejection_cache
        .borrow()
        .as_ref()
        .map_or(0, |cache| cache.entries())
}
fn replay(node: &mut Node, packet: &Packet) -> (Error, usize, usize) {
    let work_rows = AtomicUsize::new(0);
    let checked = WorkCheckedPacket::verify_with_progress(packet.clone(), &mut |point| {
        if matches!(point, pon_work::VerificationProgress::MatrixRow { .. }) {
            work_rows.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    })
    .unwrap();
    let prepared = AtomicUsize::new(0);
    let result = node.admit_work_checked_with_progress(checked, 1000, &|point| {
        if matches!(point, ExecutionProgress::BeforePrepare { .. }) {
            prepared.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    });
    (
        result.unwrap_err(),
        work_rows.load(Ordering::Relaxed),
        prepared.load(Ordering::Relaxed),
    )
}

#[test]
fn root_rejection_opt_in_reuses_execution_but_each_replay_verifies_full_work() {
    let dir = tempfile::tempdir().unwrap();
    let (mut node, valid, wrong) = fixture(dir.path());
    let original = node.read_active().unwrap();
    let stats = node.stats().unwrap();
    for _ in 0..2 {
        let (error, rows, prepared) = replay(&mut node, &wrong);
        assert_eq!(error.to_string(), "ROOT");
        assert!(rows > 0 && prepared > 0);
        assert_eq!(entries(&node), 0);
    }
    node.enable_local_root_rejection_cache().unwrap();
    let (error, rows, prepared) = replay(&mut node, &wrong);
    assert_eq!(error.to_string(), "ROOT");
    assert!(rows > 0 && prepared > 0);
    assert_eq!(entries(&node), 1);
    node.enable_local_root_rejection_cache().unwrap();
    let (error, rows, prepared) = replay(&mut node, &wrong);
    assert_eq!(error.to_string(), "ROOT");
    assert!(rows > 0);
    assert_eq!(prepared, 0);
    assert_eq!(entries(&node), 1);
    assert_eq!(node.read_active().unwrap(), original);
    assert_eq!(node.stats().unwrap(), stats);
    assert!(node.record(wrong.id().unwrap()).is_err());
    let mut corrupt = wrong.clone();
    corrupt.proof[4 + 2 * pon_work::CELLS * 4] ^= 1;
    assert!(WorkCheckedPacket::verify(corrupt).is_err());
    let mut changed = wrong.clone();
    changed.header.nonce += 1;
    let changed = remake(changed);
    assert!(replay(&mut node, &changed).2 > 0);
    assert_eq!(entries(&node), 2);
    assert_eq!(node.admit(&valid, 1000).unwrap(), valid.id().unwrap());
    assert_eq!(entries(&node), 2); // Success is never retained.
    let scope = node.root_rejection_scope(wrong.header.parent, root(&original.2).unwrap());
    assert!(!node
        .root_rejection_cache
        .borrow_mut()
        .as_mut()
        .unwrap()
        .rejects(scope, &wrong.encode().unwrap(), &wrong.header, None));
    node.enable_local_root_rejection_cache().unwrap();
    assert!(replay(&mut node, &wrong).2 > 0);
    assert_eq!(entries(&node), 0); // Reenable cannot reset a failed clock.
    drop(node);
    let reopened =
        Node::open_with_authenticated_state(dir.path(), Settings::development(Some(1)).unwrap(), 1)
            .unwrap();
    assert_eq!(entries(&reopened), 0);
    assert!(reopened.root_rejection_cache.borrow().is_none());
}

#[test]
fn root_rejection_fresh_context_storage_and_cancellation_precede_hit() {
    let dir = tempfile::tempdir().unwrap();
    let (mut node, _, wrong) = fixture(dir.path());
    node.enable_local_root_rejection_cache().unwrap();
    assert_eq!(replay(&mut node, &wrong).0.to_string(), "ROOT");
    let error = node
        .admit_work_checked(WorkCheckedPacket::verify(wrong.clone()).unwrap(), 0)
        .unwrap_err();
    assert_ne!(error.to_string(), "ROOT");
    for cancel_at in [
        ExecutionProgress::BeforeParentBinding,
        ExecutionProgress::BeforeOutput,
    ] {
        let error = node
            .admit_work_checked_with_progress(
                WorkCheckedPacket::verify(wrong.clone()).unwrap(),
                1000,
                &|point| {
                    if point == cancel_at {
                        Err("PUBLIC_REQUEST_CANCELLED".into())
                    } else {
                        Ok(())
                    }
                },
            )
            .unwrap_err();
        assert_eq!(error.code(), Some(crate::ErrorCode::PublicRequestCancelled));
    }
    let original_root = node.record(wrong.header.parent).unwrap().root;
    node.db
        .execute(
            "UPDATE blocks SET state_root=? WHERE id=?",
            params![[99_u8; 32].as_slice(), wrong.header.parent.as_slice()],
        )
        .unwrap();
    let error = replay(&mut node, &wrong).0;
    assert_eq!(error.to_string(), "ROOT");
    assert!(error.requires_owner_stop());
    node.db
        .execute(
            "UPDATE blocks SET state_root=? WHERE id=?",
            params![original_root.as_slice(), wrong.header.parent.as_slice()],
        )
        .unwrap();
    assert_eq!(replay(&mut node, &wrong).2, 0);
    // Same SQL root cannot authorize changed actual State or account graph.
    node.db
        .execute(
            "UPDATE kv SET value=? WHERE rowid=(SELECT MIN(rowid) FROM kv)",
            params![b"null".as_slice()],
        )
        .unwrap();
    let error = replay(&mut node, &wrong).0;
    assert!(error.requires_owner_stop());
    assert_eq!(entries(&node), 1);
}

#[test]
fn root_rejection_cancelled_cold_execution_and_generic_root_never_seed() {
    let dir = tempfile::tempdir().unwrap();
    let (mut node, _, wrong) = fixture(dir.path());
    node.enable_local_root_rejection_cache().unwrap();
    for message in [
        "PUBLIC_REQUEST_CANCELLED",
        "ROOT",
        "PUBLIC_MUTATION_CPU_UNAVAILABLE",
    ] {
        let error = node
            .admit_work_checked_with_progress(
                WorkCheckedPacket::verify(wrong.clone()).unwrap(),
                1000,
                &|point| {
                    if point == ExecutionProgress::AfterCommitment {
                        Err(message.into())
                    } else {
                        Ok(())
                    }
                },
            )
            .unwrap_err();
        assert_eq!(error.to_string(), message);
        assert_eq!(entries(&node), 0);
    }
    let mut invalid = wrong;
    invalid.header.transactions[0] ^= 1;
    let invalid = remake(invalid);
    assert_eq!(replay(&mut node, &invalid).0.to_string(), "ROOT");
    assert_eq!(entries(&node), 0);
}

#[test]
fn root_rejection_retains_only_the_actual_bound_parent_across_sql_faults() {
    use std::sync::Mutex;
    let dir = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let mut node = Node::open(dir.path(), settings.clone(), 1).unwrap();
    node.enable_local_root_rejection_cache().unwrap();
    let valid = node
        .make(
            settings.genesis(),
            vec![transfer(&settings, 1)],
            development_public(0).unwrap(),
            1001,
            4096,
        )
        .unwrap();
    let original = node.read_active().unwrap();
    let mut changed = original.2.clone();
    changed.insert("local-fault-extra".into(), serde_json::json!(1));
    let root_b = root(&changed).unwrap();
    let root_a = root(&original.2).unwrap();
    let slot = node.slot().unwrap();
    let mut context_calls = 0;
    node.check_admission_context_with_progress(&valid, 1000, &mut || {
        context_calls += 1;
        Ok(())
    })
    .unwrap();
    let foreign = Mutex::new(Connection::open(dir.path().join("native.sqlite")).unwrap());
    let calls = AtomicUsize::new(0);
    let stage = AtomicUsize::new(0);
    let error = node
        .admit_work_checked_with_progress(
            WorkCheckedPacket::verify(valid.clone()).unwrap(),
            1000,
            &|point| {
                if point == ExecutionProgress::BeforeParentBinding
                    && calls.fetch_add(1, Ordering::Relaxed) == context_calls
                {
                    // Outer Record was A; actual State and the binding below are B.
                    let mut db = foreign.lock().unwrap();
                    let tx = db.transaction().unwrap();
                    tx.execute(
                        "INSERT INTO kv VALUES(?,?,?)",
                        params![slot, "local-fault-extra", b"1".as_slice()],
                    )
                    .unwrap();
                    tx.execute(
                        "UPDATE blocks SET state_root=? WHERE id=?",
                        params![root_b.as_slice(), settings.genesis().as_slice()],
                    )
                    .unwrap();
                    tx.commit().unwrap();
                    stage.store(1, Ordering::Relaxed);
                }
                if point == ExecutionProgress::BeforeOutput && stage.load(Ordering::Relaxed) == 1 {
                    // M06's immutable B output is complete; restore actual SQL A.
                    let mut db = foreign.lock().unwrap();
                    let tx = db.transaction().unwrap();
                    tx.execute(
                        "DELETE FROM kv WHERE slot=? AND key=?",
                        params![slot, "local-fault-extra"],
                    )
                    .unwrap();
                    tx.execute(
                        "UPDATE blocks SET state_root=? WHERE id=?",
                        params![root_a.as_slice(), settings.genesis().as_slice()],
                    )
                    .unwrap();
                    tx.commit().unwrap();
                    stage.store(2, Ordering::Relaxed);
                }
                Ok(())
            },
        )
        .unwrap_err();
    assert_eq!(error.to_string(), "ROOT");
    assert_eq!(stage.load(Ordering::Relaxed), 2);
    assert_eq!(entries(&node), 1);
    assert_eq!(node.read_active().unwrap(), original);
    let prepared = AtomicUsize::new(0);
    let accepted = node.admit_work_checked_with_progress(
        WorkCheckedPacket::verify(valid.clone()).unwrap(),
        1000,
        &|point| {
            if matches!(point, ExecutionProgress::BeforePrepare { .. }) {
                prepared.fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        },
    );
    assert!(accepted.is_ok(), "B's refusal cannot reject A");
    assert_eq!(accepted.unwrap(), valid.id().unwrap());
    assert!(prepared.load(Ordering::Relaxed) > 0);
}

fn scope() -> root_rejection_cache::Scope {
    root_rejection_cache::Scope {
        context: [1; 32],
        parent: [2; 32],
        root: [3; 32],
    }
}
fn mismatch() -> FinalMismatch {
    FinalMismatch {
        state: [4; 32],
        receipts: [5; 32],
    }
}
fn header() -> Header {
    let mut raw = [0; HEADER_BYTES];
    raw[..4].copy_from_slice(b"PNH1");
    raw[4..6].copy_from_slice(&1_u16.to_le_bytes());
    Header::decode(&raw).unwrap()
}

#[test]
fn root_rejection_exact_scope_full_bytes_expiry_and_clock_failure_are_bounded() {
    let mut cache = Cache::default();
    cache.retain(scope(), vec![8, 9], mismatch(), Some(100));
    assert!(cache.rejects(scope(), &[8, 9], &header(), Some(100 + TTL_NS - 1)));
    assert!(!cache.rejects(scope(), &[8, 9], &header(), Some(100 + TTL_NS)));
    assert_eq!(cache.entries(), 0); // Hits do not renew the original TTL.
    for alter in 0..3 {
        let mut cache = Cache::default();
        cache.retain(scope(), vec![8, 9], mismatch(), Some(100));
        let mut other = scope();
        match alter {
            0 => other.context[0] ^= 1,
            1 => other.parent[0] ^= 1,
            _ => other.root[0] ^= 1,
        }
        assert!(!cache.rejects(other, &[8, 9], &header(), Some(101)));
        assert!(!cache.rejects(scope(), &[8, 10], &header(), Some(101)));
        assert!(!cache.rejects(scope(), &[8, 9, 0], &header(), Some(101)));
        let anomaly = if alter == 0 { None } else { Some(99) };
        assert!(!cache.rejects(scope(), &[8, 9], &header(), anomaly));
        assert_eq!(cache.entries(), 0);
        cache.retain(scope(), vec![8, 9], mismatch(), Some(102));
        assert!(!cache.rejects(scope(), &[8, 9], &header(), Some(103)));
        assert_eq!(cache.entries(), 0);
    }
}

#[test]
fn root_rejection_slots_fifo_and_exact_retained_bytes_enforce_caps() {
    let mut cache = Cache::default();
    for index in 0..=MAX_ENTRIES {
        cache.retain(
            scope(),
            vec![u8::try_from(index).unwrap()],
            mismatch(),
            Some(index as u64),
        );
        assert!(cache.entries() <= MAX_ENTRIES);
        assert!(cache.retained_bytes() <= MAX_RETAINED_BYTES);
    }
    assert!(!cache.rejects(scope(), &[0], &header(), Some(100)));
    assert!(cache.rejects(scope(), &[1], &header(), Some(100)));
    let mut cache = Cache::default();
    let fixed = cache.retained_bytes();
    let bytes = MAX_RETAINED_BYTES - fixed;
    cache.retain(scope(), vec![8; bytes], mismatch(), Some(1));
    assert_eq!(cache.retained_bytes(), MAX_RETAINED_BYTES);
    cache.retain(scope(), vec![9; bytes + 1], mismatch(), Some(2));
    assert_eq!(cache.retained_bytes(), MAX_RETAINED_BYTES);
    cache.retain(scope(), vec![7], mismatch(), Some(3));
    assert_eq!(cache.entries(), 1);
    assert_eq!(cache.retained_bytes(), fixed + 1);
}

#[test]
fn root_rejection_public_replays_keep_signed_root_full_work_and_actual_paid_cpu() {
    use crate::ingress::{self, public_v3};
    use std::{
        net::TcpListener,
        sync::{atomic::AtomicBool, Arc, Mutex},
        thread,
    };
    let identity =
        |n| ingress::DevelopmentIdentity::from_secret_hex(&hex::encode([n; 32])).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let (mut node, _, wrong) = fixture(dir.path());
    let settings = node.settings().clone();
    node.enable_local_mempool(crate::PoolLimits {
        max_records: 16,
        max_bytes: 32768,
        max_group_members: 4,
        critical_reserve: 0,
        max_removals: 64,
        preview_miner: development_public(0).unwrap(),
    })
    .unwrap();
    let original = node.read_active().unwrap();
    let original_stats = node.stats().unwrap();
    node.enable_local_root_rejection_cache().unwrap();
    let owner = Arc::new(Mutex::new(node));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let observer = public_v3::PublicRequestObserver::new(4).unwrap();
    let policy = public_v3::PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
    let server = public_v3::PublicServer::new(identity(71), policy).unwrap();
    let domain = server.mutation_cpu_domain();
    let (shared, signal, capture) = (owner.clone(), stop.clone(), observer.clone());
    let worker = thread::spawn(move || {
        public_v3::serve_public_protected_v3_with_request_observer(
            listener,
            shared,
            Duration::from_secs(8),
            signal,
            server,
            Arc::new(Mutex::new(public_v3::PublicMetrics::default())),
            capture,
        )
    });
    let mut calls = Vec::new();
    let mut previous = domain.observe_actual_flow().unwrap().unwrap();
    for n in [80, 81] {
        let result = public_v3::call_public_protected_v3(
            address,
            &public_v3::Request::Submit {
                packet: hex::encode(wrong.encode().unwrap()),
            },
            &settings,
            identity(71).public_key(),
            &identity(n),
            policy,
        );
        let after = domain.observe_actual_flow().unwrap().unwrap();
        calls.push((
            result,
            after
                .paid_cpu_debit_ns
                .checked_sub(previous.paid_cpu_debit_ns),
            after.balance_identity_verified
                && after.live_owners == 0
                && after.booked_reservation_ns == 0
                && after.unsettled_known_live_cpu_ns == 0
                && after.paid_cpu_debit_ns == after.settled_full_cpu_ns,
        ));
        previous = after;
    }
    stop.store(true, Ordering::Release);
    let service = worker.join().unwrap();
    service.unwrap();
    for (reply, paid, settled) in calls {
        let reply = reply.unwrap(); // Client independently verifies signed reply.
        assert!(!reply.ok);
        assert_eq!(reply.value["error"], "ROOT");
        assert!(paid.is_some_and(|ns| ns > 0));
        assert!(settled);
    }
    let captured = observer.snapshot();
    assert!(captured.coverage_complete());
    assert_eq!(captured.records.len(), 2);
    for record in captured.records {
        assert!(record.full_work_started);
        assert_eq!(record.full_work_accepted, Some(true));
        assert!(record.full_work_thread_cpu_ns.is_some_and(|ns| ns > 0));
        assert_eq!(record.dispatch_accepted, Some(false));
        assert!(record.dispatch_thread_cpu_ns.is_some_and(|ns| ns > 0));
    }
    let node = owner.lock().unwrap();
    assert_eq!(entries(&node), 1);
    assert_eq!(node.read_active().unwrap(), original);
    assert_eq!(node.stats().unwrap(), original_stats);
}
