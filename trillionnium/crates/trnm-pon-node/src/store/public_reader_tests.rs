use super::*;
use crate::{development_public, Settings};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    sync::{mpsc, Arc, Mutex},
    time::{Duration, Instant},
};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_protocol::pon_wire::Envelope;

const CLOCK: u64 = 1_000_000;
mod compiled_source {
    include!("../../examples/support/distributed_source_inventory.rs");
}

fn transfer(settings: &Settings, nonce: u64) -> Vec<u8> {
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()]))).unwrap();
    let mut payload = development_public(1).unwrap().to_vec();
    payload.extend(1_u64.to_le_bytes());
    let mut tx = Envelope {
        network: settings.network(),
        sender: development_public(0).unwrap(),
        nonce,
        expiry: 10_000,
        fee_limit: 1000,
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
fn chain(path: &std::path::Path, blocks: u64) -> (Node, Vec<Hash>) {
    chain_observed(path, blocks, &mut |_, _, _| {})
}
fn chain_observed(
    path: &std::path::Path,
    blocks: u64,
    observer: &mut dyn FnMut(&Node, u64, u128),
) -> (Node, Vec<Hash>) {
    let settings = Settings::development(Some(1)).unwrap();
    let mut node = Node::open(path, settings.clone(), 1).unwrap();
    let mut ids = vec![settings.genesis()];
    for height in 1..=blocks {
        let started = Instant::now();
        let transactions = if height == 1 {
            (1..=256).map(|n| transfer(&settings, n)).collect()
        } else {
            Vec::new()
        };
        let packet = node
            .make(
                *ids.last().unwrap(),
                transactions,
                development_public(2).unwrap(),
                1 + height * 10,
                4096,
            )
            .unwrap();
        let id = node.admit(&packet, CLOCK).unwrap();
        node.activate(id).unwrap();
        ids.push(id);
        observer(&node, height, started.elapsed().as_nanos());
    }
    (node, ids)
}
fn old_page(node: &Node, tip: Hash, after: Hash) -> Value {
    let packets = node
        .public_history_packet(tip, after, 1024, &mut |_| Ok(()))
        .unwrap();
    let next = packets
        .last()
        .map(|packet| packet.id().unwrap())
        .unwrap_or(after);
    serde_json::to_value(crate::ingress::Page {
        schema: "pon-native-history-v1".into(),
        network: hex::encode(node.settings().network()),
        parameters: hex::encode(node.settings().parameters()),
        genesis: hex::encode(node.settings().genesis()),
        tip: hex::encode(tip),
        after: hex::encode(after),
        complete: next == tip,
        next: hex::encode(next),
        packets: packets
            .iter()
            .map(|packet| hex::encode(packet.encode().unwrap()))
            .collect(),
    })
    .unwrap()
}
fn snapshot_page(node: &Node, tip: Hash, after: Hash) -> Value {
    let read = node
        .prepare_public_history_snapshot(tip, after, 1024, &mut |_| Ok(()))
        .unwrap()
        .read(&mut |_| Ok(()))
        .unwrap();
    node.finish_public_history_snapshot(read, &mut |_| Ok(()))
        .unwrap()
}

#[test]
fn readonly_history_snapshot_keeps_original_page_and_cold_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let (mut node, ids) = chain(directory.path(), 17);
    let state = node.read_active().unwrap();
    let changes = node.db.total_changes();
    for (tip, after) in [
        (ids[17], ids[0]),
        (ids[17], ids[16]),
        (ids[17], ids[17]),
        (ids[0], ids[0]),
    ] {
        assert_eq!(
            snapshot_page(&node, tip, after),
            old_page(&node, tip, after)
        );
    }
    let fork = node
        .make(
            ids[15],
            Vec::new(),
            development_public(3).unwrap(),
            201,
            4096,
        )
        .unwrap();
    let forkid = node.admit(&fork, CLOCK).unwrap();
    assert_eq!(
        snapshot_page(&node, forkid, ids[15]),
        old_page(&node, forkid, ids[15])
    );
    assert_eq!(node.read_active().unwrap(), state);
    assert!(node.db.total_changes() > changes);
    let settings = node.settings().clone();
    drop(node);
    let reopened = Node::open(directory.path(), settings, 1).unwrap();
    assert_eq!(reopened.read_active().unwrap(), state);
    assert_eq!(
        snapshot_page(&reopened, ids[17], ids[0]),
        old_page(&reopened, ids[17], ids[0])
    );
}

#[test]
fn readonly_history_allows_real_writer_commit_without_releasing_writer_authority() {
    let directory = tempfile::tempdir().unwrap();
    let (node, ids) = chain(directory.path(), 17);
    let packet = node
        .make(
            ids[17],
            Vec::new(),
            development_public(3).unwrap(),
            181,
            4096,
        )
        .unwrap();
    let expected = old_page(&node, ids[17], ids[0]);
    let owner = Arc::new(Mutex::new(node));
    let snapshot = owner
        .lock()
        .unwrap()
        .prepare_public_history_snapshot(ids[17], ids[0], 1024, &mut |_| Ok(()))
        .unwrap();
    // PRAGMA/BEGIN, four context reads, ready and three epoch reads have
    // completed before this gate. The reader holds an actual SQLite snapshot.
    let gate = snapshot.budget.used + 10;
    let (entered_tx, entered_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut stopped = false;
        snapshot
            .read(&mut |step| {
                if step > gate && !stopped {
                    stopped = true;
                    entered_tx.send(()).unwrap();
                    resume_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                }
                Ok(())
            })
            .unwrap()
    });
    entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let id = {
        let mut node = owner
            .try_lock()
            .expect("readonly SQL must not hold Node mutex");
        let id = node.admit(&packet, CLOCK).unwrap();
        assert_eq!(node.active().unwrap().0, ids[17]);
        id
    };
    // A second durable owner still cannot open while the original writer lives.
    assert_eq!(
        Node::open(
            directory.path(),
            owner.lock().unwrap().settings().clone(),
            1
        )
        .err()
        .unwrap()
        .to_string(),
        "WRITER_BUSY"
    );
    resume_tx.send(()).unwrap();
    let read = reader.join().unwrap();
    assert!(
        read.snapshot_observation()["unique_query_facts"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_eq!(
        owner
            .lock()
            .unwrap()
            .finish_public_history_snapshot(read, &mut |_| Ok(()))
            .unwrap(),
        expected
    );
    assert_eq!(
        owner.lock().unwrap().packet(id).unwrap().encode().unwrap(),
        packet.encode().unwrap()
    );
}

#[test]
fn readonly_history_refuses_reorganization_epoch_before_page_publication() {
    let directory = tempfile::tempdir().unwrap();
    let (mut node, ids) = chain(directory.path(), 17);
    let read = node
        .prepare_public_history_snapshot(ids[17], ids[0], 1024, &mut |_| Ok(()))
        .unwrap()
        .read(&mut |_| Ok(()))
        .unwrap();
    let successor = node
        .make(
            ids[17],
            Vec::new(),
            development_public(2).unwrap(),
            181,
            4096,
        )
        .unwrap();
    let id = node.admit(&successor, CLOCK).unwrap();
    node.activate(id).unwrap();
    let changed = node.read_active().unwrap();
    assert_eq!(
        node.finish_public_history_snapshot(read, &mut |_| Ok(()))
            .unwrap_err()
            .to_string(),
        "STALE_VIEW"
    );
    assert_eq!(node.read_active().unwrap(), changed);
    let read = node
        .prepare_public_history_snapshot(ids[17], ids[0], 1024, &mut |_| Ok(()))
        .unwrap()
        .read(&mut |_| Ok(()))
        .unwrap();
    let mut fork_parent = ids[15];
    for height in 16..=19 {
        let packet = node
            .make(
                fork_parent,
                Vec::new(),
                development_public(3).unwrap(),
                1 + height * 10,
                4096,
            )
            .unwrap();
        fork_parent = node.admit(&packet, CLOCK).unwrap();
    }
    node.activate(fork_parent).unwrap();
    let reorg_state = node.read_active().unwrap();
    assert_ne!(reorg_state, changed);
    assert_eq!(
        node.finish_public_history_snapshot(read, &mut |_| Ok(()))
            .unwrap_err()
            .to_string(),
        "STALE_VIEW"
    );
    assert_eq!(node.read_active().unwrap(), reorg_state);
    // The old explicit tip remains a legal historical request in a fresh epoch.
    assert_eq!(
        snapshot_page(&node, ids[17], ids[0]),
        old_page(&node, ids[17], ids[0])
    );
}

#[test]
fn readonly_history_detects_foreign_write_restore_and_same_owner_raw_damage() {
    let directory = tempfile::tempdir().unwrap();
    let (node, ids) = chain(directory.path(), 17);
    let original = node.packet(ids[1]).unwrap().encode().unwrap();
    let selected = node.active().unwrap();
    let read = node
        .prepare_public_history_snapshot(ids[17], ids[0], 1024, &mut |_| Ok(()))
        .unwrap()
        .read(&mut |_| Ok(()))
        .unwrap();
    let foreign = Connection::open(directory.path().join("native.sqlite")).unwrap();
    let mut changed = original.clone();
    changed[trnm_protocol::pon_wire::HEADER_BYTES + 4] ^= 1;
    foreign
        .execute(
            "UPDATE blocks SET packet=? WHERE id=?",
            params![&changed, ids[1].as_slice()],
        )
        .unwrap();
    foreign
        .execute(
            "UPDATE blocks SET packet=? WHERE id=?",
            params![&original, ids[1].as_slice()],
        )
        .unwrap();
    assert_eq!(node.active().unwrap(), selected);
    let error = node
        .finish_public_history_snapshot(read, &mut |_| Ok(()))
        .unwrap_err();
    assert!(error.requires_owner_stop());
    drop(foreign);
    let read = node
        .prepare_public_history_snapshot(ids[17], ids[0], 1024, &mut |_| Ok(()))
        .unwrap()
        .read(&mut |_| Ok(()))
        .unwrap();
    let old: Vec<u8> = node
        .db
        .query_row(
            "SELECT seal FROM ancestry_jump WHERE block=? AND level=4",
            [ids[17].as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    node.db
        .execute(
            "UPDATE ancestry_jump SET seal=? WHERE block=? AND level=4",
            params![[99_u8; 32].as_slice(), ids[17].as_slice()],
        )
        .unwrap();
    assert_eq!(node.active().unwrap(), selected);
    let error = node
        .finish_public_history_snapshot(read, &mut |_| Ok(()))
        .unwrap_err();
    assert!(error.requires_owner_stop());
    assert_eq!(error.to_string(), "ANCESTRY_INDEX_STRUCTURE");
    node.db
        .execute(
            "UPDATE ancestry_jump SET seal=? WHERE block=? AND level=4",
            params![old, ids[17].as_slice()],
        )
        .unwrap();
    assert_eq!(
        snapshot_page(&node, ids[17], ids[0]),
        old_page(&node, ids[17], ids[0])
    );
}

#[test]
fn readonly_history_same_generation_owner_epoch_damage_stops_without_wrapping_cancel() {
    let directory = tempfile::tempdir().unwrap();
    let (node, ids) = chain(directory.path(), 17);
    let selected = node.active().unwrap();
    let slot = node.slot().unwrap();
    let root = node.record(ids[17]).unwrap().root;
    let read = || {
        node.prepare_public_history_snapshot(ids[17], ids[0], 1024, &mut |_| Ok(()))
            .unwrap()
            .read(&mut |_| Ok(()))
            .unwrap()
    };
    for damage in ["tip", "slot", "record"] {
        let observed = read();
        match damage {
            "tip" => {
                node.db
                    .execute(
                        "UPDATE active SET tip=? WHERE singleton=1",
                        [ids[16].as_slice()],
                    )
                    .unwrap();
            }
            "slot" => {
                node.db
                    .execute(
                        "UPDATE active SET state_slot=? WHERE singleton=1",
                        [1 - slot],
                    )
                    .unwrap();
            }
            _ => {
                node.db
                    .execute(
                        "UPDATE blocks SET state_root=? WHERE id=?",
                        params![[99_u8; 32].as_slice(), ids[17].as_slice()],
                    )
                    .unwrap();
            }
        }
        assert_eq!(node.active().unwrap().1, selected.1);
        let error = node
            .finish_public_history_snapshot(observed, &mut |_| Ok(()))
            .unwrap_err();
        assert_eq!(error.to_string(), "STALE_VIEW");
        assert!(error.requires_owner_stop());
        node.db
            .execute(
                "UPDATE active SET tip=?,state_slot=? WHERE singleton=1",
                params![selected.0.as_slice(), slot],
            )
            .unwrap();
        node.db
            .execute(
                "UPDATE blocks SET state_root=? WHERE id=?",
                params![root.as_slice(), ids[17].as_slice()],
            )
            .unwrap();
        assert_eq!(
            snapshot_page(&node, ids[17], ids[0]),
            old_page(&node, ids[17], ids[0])
        );
    }
    for offset in [10, 11] {
        let observed = read();
        let cancel_at = observed.budget.used + offset;
        let error = node
            .finish_public_history_snapshot(observed, &mut |used| {
                ensure(used < cancel_at, "PUBLIC_REQUEST_CANCELLED")
            })
            .unwrap_err();
        assert_eq!(error.to_string(), "PUBLIC_REQUEST_CANCELLED");
        assert!(!error.requires_owner_stop());
    }
}

#[test]
fn readonly_history_cancel_drops_lease_and_namespace_changes_refuse() {
    let directory = tempfile::tempdir().unwrap();
    let (node, ids) = chain(directory.path(), 3);
    let changes = node.db.total_changes();
    let state = node.read_active().unwrap();
    let snapshot = node
        .prepare_public_history_snapshot(ids[3], ids[0], 1024, &mut |_| Ok(()))
        .unwrap();
    let cancel_at = snapshot.budget.used + 12;
    let error = snapshot
        .read(&mut |step| ensure(step < cancel_at, "PUBLIC_REQUEST_CANCELLED"))
        .err()
        .unwrap();
    assert!(!error.requires_owner_stop());
    assert_eq!(node.db.total_changes(), changes);
    assert_eq!(node.read_active().unwrap(), state);
    let snapshot = node
        .prepare_public_history_snapshot(ids[3], ids[0], 1024, &mut |_| Ok(()))
        .unwrap();
    let lock = directory.path().join("owner.lock");
    let saved = directory.path().join("owner.saved");
    fs::rename(&lock, &saved).unwrap();
    fs::write(&lock, []).unwrap();
    assert_eq!(
        snapshot.read(&mut |_| Ok(())).err().unwrap().to_string(),
        "OWNER_REPLACED"
    );
    fs::remove_file(&lock).unwrap();
    fs::rename(&saved, &lock).unwrap();
    let snapshot = node
        .prepare_public_history_snapshot(ids[3], ids[0], 1024, &mut |_| Ok(()))
        .unwrap();
    let settings = node.settings().clone();
    drop(node);
    assert_eq!(
        Node::open(directory.path(), settings.clone(), 1)
            .err()
            .unwrap()
            .to_string(),
        "WRITER_BUSY"
    );
    drop(snapshot);
    assert_eq!(
        Node::open(directory.path(), settings, 1)
            .unwrap()
            .read_active()
            .unwrap(),
        state
    );
}

#[test]
fn readonly_history_one_cumulative_budget_has_exact_limit_and_no_partial_result() {
    let directory = tempfile::tempdir().unwrap();
    let (node, ids) = chain(directory.path(), 17);
    let expected = old_page(&node, ids[17], ids[0]);
    let changes = node.db.total_changes();
    let state = node.read_active().unwrap();
    let mut observed = 0;
    let mut progress = |used| {
        observed = used;
        Ok(())
    };
    let read = node
        .prepare_public_history_snapshot(ids[17], ids[0], 1024, &mut progress)
        .unwrap()
        .read(&mut progress)
        .unwrap();
    assert!(
        read.snapshot_observation()["reserved_cleanup_statements"]
            .as_u64()
            .unwrap()
            == 1
    );
    assert_eq!(
        node.finish_public_history_snapshot(read, &mut progress)
            .unwrap(),
        expected
    );
    let exact = observed;
    println!(
        "{}",
        json!({"schema":"native-readonly-history-exact-budget-control-v1","actual_blocks":17,"actual_signed_transactions":256,"complete_cumulative_sql":exact,"full_page_equal":true,"scope":"actual complete operation N/N-1 boundary; not extreme-height production exhaustion"})
    );
    assert!((3..=1024).contains(&exact));
    // The production held-owner algorithm has its own original single allowance;
    // only genuine request exhaustion keeps this healthy owner available.
    let mut held_exact = 0;
    let packets = node
        .public_history_packet(ids[17], ids[0], 1024, &mut |used| {
            held_exact = used;
            Ok(())
        })
        .unwrap();
    assert_eq!(packets.len(), 1);
    for maximum in [held_exact, held_exact - 1] {
        let result = node.public_history_packet(ids[17], ids[0], maximum, &mut |_| Ok(()));
        if maximum == held_exact {
            assert_eq!(
                result
                    .unwrap()
                    .iter()
                    .map(|packet| packet.encode().unwrap())
                    .collect::<Vec<_>>(),
                packets
                    .iter()
                    .map(|packet| packet.encode().unwrap())
                    .collect::<Vec<_>>()
            );
        } else {
            let error = result.unwrap_err();
            assert_eq!(error.to_string(), "ANCESTRY_INDEX_BUDGET");
            assert!(!error.requires_owner_stop());
        }
        assert_eq!(node.db.total_changes(), changes);
        assert_eq!(node.read_active().unwrap(), state);
    }
    for maximum in [exact, exact - 1] {
        let mut used = 0;
        let mut progress = |step| {
            used = step;
            Ok(())
        };
        let result = (|| -> Result<Value> {
            let read = node
                .prepare_public_history_snapshot(ids[17], ids[0], maximum, &mut progress)?
                .read(&mut progress)?;
            node.finish_public_history_snapshot(read, &mut progress)
        })();
        assert!(used <= maximum);
        if maximum == exact {
            assert_eq!(result.unwrap(), expected);
            assert_eq!(used, exact);
        } else {
            let error = result.unwrap_err();
            assert_eq!(error.to_string(), "ANCESTRY_INDEX_BUDGET");
            assert!(!error.requires_owner_stop());
        }
        assert_eq!(node.db.total_changes(), changes);
        assert_eq!(node.read_active().unwrap(), state);
    }
    // Cancellation after a complete private page still returns no response.
    let read = node
        .prepare_public_history_snapshot(ids[17], ids[0], 1024, &mut |_| Ok(()))
        .unwrap()
        .read(&mut |_| Ok(()))
        .unwrap();
    let cancel_at = read.budget.used + 12;
    let error = node
        .finish_public_history_snapshot(read, &mut |step| {
            ensure(step < cancel_at, "PUBLIC_REQUEST_CANCELLED")
        })
        .unwrap_err();
    assert_eq!(error.to_string(), "PUBLIC_REQUEST_CANCELLED");
    assert!(!error.requires_owner_stop());
    assert_eq!(node.db.total_changes(), changes);
    assert_eq!(snapshot_page(&node, ids[17], ids[0]), expected);
    let request = Error::public_history_budget();
    assert_eq!(request.code(), Some(crate::ErrorCode::AncestryIndexBudget));
    assert_eq!(request.kind(), crate::ErrorKind::Capacity);
    assert!(!request.requires_owner_stop());
    assert!(request.local_integrity().requires_owner_stop());
    assert!(Error::from("ANCESTRY_INDEX_BUDGET").requires_owner_stop());
    assert!(Error::new(crate::ErrorCode::AncestryIndexBudget).requires_owner_stop());
    assert!(Error::remote("ANCESTRY_INDEX_BUDGET")
        .local_integrity()
        .requires_owner_stop());
    for maximum in [3, 18, 24] {
        let result = (|| -> Result<Value> {
            let read = node
                .prepare_public_history_snapshot(ids[17], ids[0], maximum, &mut |_| Ok(()))?
                .read(&mut |_| Ok(()))?;
            node.finish_public_history_snapshot(read, &mut |_| Ok(()))
        })();
        let error = result.unwrap_err();
        assert_eq!(error.to_string(), "ANCESTRY_INDEX_BUDGET");
        assert!(!error.requires_owner_stop());
        assert_eq!(node.db.total_changes(), changes);
    }
}

#[test]
fn readonly_history_signed_repeated_request_budget_refusal_keeps_writer_and_normal_reads() {
    use crate::ingress::{
        public_v3::{
            call_public_protected_v3, serve_public_protected_v3_with_metrics, PublicMetrics,
            PublicPolicy, PublicServer, Request,
        },
        DevelopmentIdentity,
    };
    use std::{
        net::TcpListener,
        sync::atomic::{AtomicBool, Ordering},
    };
    let directory = tempfile::tempdir().unwrap();
    let (mut node, ids) = chain(directory.path(), 17);
    let settings = node.settings().clone();
    let packet = node
        .make(
            ids[17],
            Vec::new(),
            development_public(2).unwrap(),
            181,
            4096,
        )
        .unwrap();
    let state = node.read_active().unwrap();
    // A valid three-statement request limit is insufficient for either the
    // original held-owner lookup or the extra research snapshot fences.
    node.public_history_test_sql_limit = Some(3);
    node.enable_local_mempool(crate::PoolLimits {
        max_records: 16,
        max_bytes: 32768,
        max_group_members: 16,
        critical_reserve: 0,
        max_removals: 64,
        preview_miner: development_public(0).unwrap(),
    })
    .unwrap();
    let changes = node.db.total_changes();
    let owner = Arc::new(Mutex::new(node));
    let identity = |n| DevelopmentIdentity::from_secret_hex(&hex::encode([n; 32])).unwrap();
    let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
    let server = PublicServer::new(identity(71), policy).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let metrics = Arc::new(Mutex::new(PublicMetrics::default()));
    let (service_owner, service_stop, service_metrics) =
        (owner.clone(), stop.clone(), metrics.clone());
    let worker = std::thread::spawn(move || {
        serve_public_protected_v3_with_metrics(
            listener,
            service_owner,
            Duration::from_secs(15),
            service_stop,
            server,
            service_metrics,
        )
        .unwrap()
    });
    let history = Request::History {
        tip: hex::encode(ids[17]),
        after: hex::encode(ids[0]),
    };
    let call = |request: &Request, who| {
        call_public_protected_v3(
            address,
            request,
            &settings,
            identity(71).public_key(),
            &identity(who),
            policy,
        )
        .unwrap()
    };
    // Both default held-owner and explicitly selected research snapshot refusals
    // leave the real service writer available. Selection is per owner and cfg(test).
    for snapshot in [false, true] {
        owner.lock().unwrap().public_history_test_snapshot = snapshot;
        for caller in [80, 81, 82] {
            let reply = call(&history, caller);
            assert!(!reply.ok);
            assert_eq!(reply.value["error"], "ANCESTRY_INDEX_BUDGET");
            assert_eq!(owner.lock().unwrap().read_active().unwrap(), state);
            assert_eq!(owner.lock().unwrap().db.total_changes(), changes);
        }
    }
    assert!(call(&Request::Head, 83).ok);
    owner.lock().unwrap().public_history_test_sql_limit = None;
    for snapshot in [false, true] {
        owner.lock().unwrap().public_history_test_snapshot = snapshot;
        let reply = call(&history, 84);
        assert!(reply.ok, "{}", reply.value);
        assert_eq!(
            reply.value,
            old_page(&owner.lock().unwrap(), ids[17], ids[0])
        );
    }
    let reply = call(
        &Request::Submit {
            packet: hex::encode(packet.encode().unwrap()),
        },
        85,
    );
    assert!(reply.ok, "{}", reply.value);
    assert_eq!(reply.value["block"], hex::encode(packet.id().unwrap()));
    assert_ne!(owner.lock().unwrap().read_active().unwrap(), state);
    stop.store(true, Ordering::Release);
    let metrics = worker.join().unwrap();
    assert_eq!(metrics.completed_submit, 1);
    // This fault controls only a test-local limit, not production resource policy.
    assert_eq!(owner.lock().unwrap().public_history_test_sql_limit, None);
}

#[test]
fn readonly_history_original_cursor_errors_and_used_fact_damage_keep_origin() {
    let directory = tempfile::tempdir().unwrap();
    let (mut node, ids) = chain(directory.path(), 17);
    let fork = node
        .make(
            ids[15],
            Vec::new(),
            development_public(3).unwrap(),
            161,
            4096,
        )
        .unwrap();
    let fork = node.admit(&fork, CLOCK).unwrap();
    let missing = [71; 32];
    for (tip, after) in [
        (missing, ids[0]),
        (ids[17], missing),
        (ids[3], ids[17]),
        (ids[17], fork),
    ] {
        let old = node
            .public_history_packet(tip, after, 1024, &mut |_| Ok(()))
            .unwrap_err();
        let new = node
            .prepare_public_history_snapshot(tip, after, 1024, &mut |_| Ok(()))
            .unwrap()
            .read(&mut |_| Ok(()))
            .err()
            .unwrap();
        assert_eq!(new.to_string(), old.to_string());
        assert_eq!(new.kind(), old.kind());
        assert_eq!(new.requires_owner_stop(), old.requires_owner_stop());
    }
    let read = node
        .prepare_public_history_snapshot(ids[17], ids[0], 1024, &mut |_| Ok(()))
        .unwrap()
        .read(&mut |_| Ok(()))
        .unwrap();
    let row: Vec<u8> = node
        .db
        .query_row(
            "SELECT packet FROM blocks WHERE id=?",
            [ids[1].as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let mut damaged = row.clone();
    damaged[trnm_protocol::pon_wire::HEADER_BYTES + 4] ^= 1;
    node.db
        .execute(
            "UPDATE blocks SET packet=? WHERE id=?",
            params![damaged, ids[1].as_slice()],
        )
        .unwrap();
    let unchanged = node.active().unwrap();
    let error = node
        .finish_public_history_snapshot(read, &mut |_| Ok(()))
        .unwrap_err();
    assert_eq!(error.to_string(), "STORAGE_PACKET");
    assert!(error.requires_owner_stop());
    assert_eq!(node.active().unwrap(), unchanged);
    node.db
        .execute(
            "UPDATE blocks SET packet=? WHERE id=?",
            params![row, ids[1].as_slice()],
        )
        .unwrap();
    assert_eq!(
        snapshot_page(&node, ids[17], ids[0]),
        old_page(&node, ids[17], ids[0])
    );
}

fn directory_bytes(path: &std::path::Path) -> u64 {
    fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                directory_bytes(&entry.path())
            } else {
                entry.metadata().unwrap().len()
            }
        })
        .sum()
}
fn emit(log: &mut File, row: Value) {
    writeln!(log, "{}", row).unwrap();
    log.flush().unwrap();
    println!("{row}");
}

#[test]
#[ignore = "complete snapshot/public-history cost and retained long-history growth; saved output required"]
fn readonly_history_whole_operation_and_retained_growth_cost() {
    let out = std::env::var_os("TRNM_PUBLIC_READER_EVIDENCE_DIRECTORY")
        .expect("new outside-checkout directory required");
    let out = std::path::Path::new(&out);
    fs::create_dir(out).unwrap();
    let mut log = File::create(out.join("reader-cost.jsonl")).unwrap();
    emit(
        &mut log,
        json!({"schema":"native-readonly-history-cost-source-v1","source_files":compiled_source::FILES.iter().map(|(path,bytes)|json!({"path":path,"sha256":hex::encode(Sha256::digest(bytes))})).collect::<Vec<_>>(),"binary_sha256":hex::encode(Sha256::digest(fs::read(std::env::current_exe().unwrap()).unwrap())),"architecture":std::env::consts::ARCH,"os":std::env::consts::OS,"build_profile":if cfg!(debug_assertions){"debug"}else{"release"},"builder_commit_claim":option_env!("TRNM_DISTRIBUTED_SOURCE_COMMIT"),"builder_tree_claim":option_env!("TRNM_DISTRIBUTED_SOURCE_TREE"),"reference_scope":"prior held-owner complete public one-packet read plus Page encoding in same current binary; no alternate executable","timed_scope":"complete prepare/read/final owner revalidation, complete Page JSON encoding and Page value release; complete byte comparison, response hashing and export outside timer","pairs_per_case":64,"warm_cache_policy":"no cache flushing; alternating arm order; all samples retained","concurrent_context":std::env::var("TRNM_READER_CONCURRENT_CONTEXT").ok(),"public_network_ready":false,"production_activation":false}),
    );
    let (node, ids) = chain_observed(&out.join("owner"), 512, &mut |node, height, elapsed| {
        if height.is_power_of_two() || height == 512 {
            let state = node.read_active().unwrap();
            let page_count: u64 = node
                .db
                .query_row("PRAGMA page_count", [], |row| row.get(0))
                .unwrap();
            let page_size: u64 = node
                .db
                .query_row("PRAGMA page_size", [], |row| row.get(0))
                .unwrap();
            let freelist: u64 = node
                .db
                .query_row("PRAGMA freelist_count", [], |row| row.get(0))
                .unwrap();
            let retained:(u64,u64,u64,u64,u64)=node.db.query_row("SELECT (SELECT COUNT(*) FROM blocks),(SELECT COUNT(*) FROM deltas),(SELECT COUNT(*) FROM snapshots),(SELECT COUNT(*) FROM ancestry_jump),(SELECT COUNT(*) FROM kv)",[],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?))).unwrap();
            let files:Vec<_>=fs::read_dir(out.join("owner")).unwrap().map(|entry|{let entry=entry.unwrap();json!({"name":entry.file_name().to_string_lossy(),"logical_bytes":entry.metadata().unwrap().len()})}).collect();
            emit(
                &mut log,
                json!({"schema":"native-readonly-history-growth-v1","actual_blocks":height,"actual_signed_transactions":256,"last_complete_make_admit_activate_ns":elapsed,"actual_state_keys":state.2.len(),"retained_block_rows":retained.0,"retained_delta_rows":retained.1,"retained_snapshot_rows":retained.2,"retained_jump_rows":retained.3,"live_kv_rows":retained.4,"maximum_jump_rows_per_block":63,"maximum_non_genesis_snapshots":64,"active":hex::encode(node.active().unwrap().0),"generation":node.active().unwrap().1,"directory_logical_bytes":directory_bytes(&out.join("owner")),"files":files,"sqlite_page_count":page_count,"sqlite_page_size":page_size,"sqlite_freelist_pages":freelist,"scope":"actual retained chain and current database/WAL/SHM logical sizes; not permanent retention, physical media allocation or pricing"}),
            );
        }
    });
    let owner = Mutex::new(node);
    let state = owner.lock().unwrap().read_active().unwrap();
    let disk_before = directory_bytes(&out.join("owner"));
    // The old deep request still succeeds. Final fences share the same global
    // allowance: the exact complete cap works and one fewer returns no Page.
    {
        let node = owner.lock().unwrap();
        let expected = old_page(&node, ids[512], ids[0]);
        let changes = node.db.total_changes();
        let mut exact = 0;
        let mut progress = |used| {
            exact = used;
            Ok(())
        };
        let read = node
            .prepare_public_history_snapshot(ids[512], ids[0], 1024, &mut progress)
            .unwrap()
            .read(&mut progress)
            .unwrap();
        assert_eq!(
            node.finish_public_history_snapshot(read, &mut progress)
                .unwrap(),
            expected
        );
        for maximum in [exact, exact - 1] {
            let result = (|| -> Result<Value> {
                let read = node
                    .prepare_public_history_snapshot(ids[512], ids[0], maximum, &mut |_| Ok(()))?
                    .read(&mut |_| Ok(()))?;
                node.finish_public_history_snapshot(read, &mut |_| Ok(()))
            })();
            if maximum == exact {
                assert_eq!(result.unwrap(), expected);
            } else {
                let error = result.unwrap_err();
                assert_eq!(error.to_string(), "ANCESTRY_INDEX_BUDGET");
                assert!(!error.requires_owner_stop());
            }
            assert_eq!(node.db.total_changes(), changes);
            assert_eq!(node.read_active().unwrap(), state);
        }
        emit(
            &mut log,
            json!({"schema":"native-readonly-history-deep-cap-control-v1","actual_blocks":512,"prior_held_owner_full_page_succeeds":true,"complete_cumulative_sql":exact,"exact_cap_succeeds":true,"one_less_cap_refuses_without_page_or_sql_write":true,"refusal_wire_error":"ANCESTRY_INDEX_BUDGET","refusal_owner_stopping":false,"scope":"finite512-block actual-chain exact-limit injection, not extreme-height default1024 exhaustion"}),
        );
    }
    let mut samples = 0;
    for (case, tip, after) in [
        ("full_first_packet", ids[512], ids[0]),
        ("late_empty_packet", ids[512], ids[510]),
        ("empty_page", ids[512], ids[512]),
    ] {
        let expected = old_page(&owner.lock().unwrap(), tip, after);
        for pair in 0..64 {
            for arm in if pair % 2 == 0 {
                ["held_owner", "snapshot"]
            } else {
                ["snapshot", "held_owner"]
            } {
                let mut held_ns = 0_u128;
                let mut observation = None;
                let mut charged = 0;
                let started = Instant::now();
                let page = if arm == "held_owner" || case == "empty_page" {
                    let node = owner.lock().unwrap();
                    let held = Instant::now();
                    let page = old_page(&node, tip, after);
                    held_ns += held.elapsed().as_nanos();
                    page
                } else {
                    let ticket = {
                        let node = owner.lock().unwrap();
                        let held = Instant::now();
                        let ticket = node
                            .prepare_public_history_snapshot(tip, after, 1024, &mut |_| Ok(()))
                            .unwrap();
                        held_ns += held.elapsed().as_nanos();
                        ticket
                    };
                    let read = ticket.read(&mut |_| Ok(())).unwrap();
                    observation = Some((
                        read.pin.active,
                        read.pin.external_version,
                        read.reads.len(),
                        read.budget.used,
                        read.budget.maximum,
                        read.budget.cleanup,
                        read.body.map(|body| body.1).unwrap_or(0),
                    ));
                    let node = owner.lock().unwrap();
                    let held = Instant::now();
                    let page = node
                        .finish_public_history_snapshot(read, &mut |used| {
                            charged = used;
                            Ok(())
                        })
                        .unwrap();
                    held_ns += held.elapsed().as_nanos();
                    page
                };
                let bytes = serde_json::to_vec(&page).unwrap();
                drop(page);
                let elapsed = started.elapsed().as_nanos();
                // Diagnostic allocation/hex encoding is outside both clocks.
                let observation=observation.map_or(Value::Null,|(active,version,facts,used,maximum,cleanup,body)|json!({"snapshot_active_tip":hex::encode(active.0),"snapshot_generation":active.1,"snapshot_external_data_version":version,"unique_query_facts":facts,"cumulative_sql_used_before_final_fence":used,"cumulative_sql_limit":maximum,"reserved_cleanup_statements":cleanup,"body_bytes":body}));
                assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), expected);
                emit(
                    &mut log,
                    json!({"schema":"native-readonly-history-cost-sample-v1","case":case,"pair":pair,"arm":arm,"elapsed_ns":elapsed,"owner_held_ns":held_ns,"snapshot_observation":observation,"completed_cumulative_sql":if charged==0 {None}else{Some(charged)},"response_bytes":bytes.len(),"response_hash":hex::encode(hash(b"reader-observed-json-v1",&[&bytes])),"complete_response_equal":true,"empty_page_original_path":case=="empty_page"}),
                );
                samples += 1;
            }
        }
    }
    let disk_after = directory_bytes(&out.join("owner"));
    assert_eq!(owner.lock().unwrap().read_active().unwrap(), state);
    let node = owner.into_inner().unwrap();
    let settings = node.settings().clone();
    drop(node);
    let started = Instant::now();
    let reopened = Node::open(&out.join("owner"), settings, 1).unwrap();
    assert_eq!(reopened.read_active().unwrap(), state);
    let recovery = started.elapsed().as_nanos();
    emit(
        &mut log,
        json!({"schema":"native-readonly-history-cost-result-v1","complete":true,"samples":samples,"actual_blocks":512,"actual_signed_transactions":256,"disk_directory_bytes_before":disk_before,"disk_directory_bytes_after":disk_after,"disk_scope":"logical files including current SQLite/WAL/SHM; not physical pages, permanent retention or pricing","complete_reopen_state_ns":recovery,"reopened_state_equal":true,"single_writer":true,"readset_fact_limit":1024,"public_network_ready":false,"independent_accepted":false,"production_activation":false,"wan_tps":null,"history_global_retention_bound":null}),
    );
}
