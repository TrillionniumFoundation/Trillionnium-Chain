//! Same-request State reuse, with real W1, M06, SQL faults and durable readback.
//! The original pressure campaign remains the service acceptance criterion.
use super::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_protocol::pon_wire::Envelope;

fn open(path: &Path, settings: &Settings, authenticated: bool) -> Node {
    if authenticated {
        Node::open_with_authenticated_state(path, settings.clone(), 1).unwrap()
    } else {
        Node::open(path, settings.clone(), 1).unwrap()
    }
}
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
fn make(node: &Node, parent: Hash, nonce: u64, timestamp: u64, miner: u64) -> Packet {
    node.make(
        parent,
        vec![transfer(node.settings(), nonce)],
        development_public(miner).unwrap(),
        timestamp,
        4096,
    )
    .unwrap()
}
fn wrong_root(mut packet: Packet) -> Packet {
    packet.header.state[0] ^= 1;
    let (a, b) = maintenance();
    let producer = pon_work::PreparedTask::new(&a, &b).unwrap();
    for _ in 0..4096 {
        packet.proof = producer.prove(packet.header.challenge()).unwrap();
        if WorkCheckedPacket::verify(packet.clone()).is_ok() {
            return packet;
        }
        packet.header.nonce += 1;
    }
    panic!("bounded real W1 search exhausted");
}
fn state_reads(node: &Node) -> u64 {
    node.native_history_arithmetic_observation()["stages"]
        .as_array()
        .expect("actual history stage observations")
        .iter()
        .find(|row| row["stage"] == "state_at")
        .unwrap()["totals"]["calls"]
        .as_u64()
        .unwrap()
}
fn context_checkpoints(node: &Node, packet: &Packet) -> usize {
    let mut calls = 0;
    assert!(node
        .check_admission_context_with_progress(packet, 1000, &mut || {
            calls += 1;
            Ok(())
        })
        .unwrap()
        .is_none());
    assert!(calls > 0);
    calls
}

#[test]
fn admission_parent_reads_once_per_root_refusal_without_cross_request_cache() {
    let dir = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let mut node = open(dir.path(), &settings, true);
    let valid = make(&node, settings.genesis(), 1, 1001, 0);
    let wrong = wrong_root(valid.clone());
    let before = node.read_active().unwrap();
    let stats = node.stats().unwrap();
    assert!(node.root_rejection_cache.borrow().is_none());
    for _ in 0..2 {
        let reads = state_reads(&node);
        let prepared = AtomicUsize::new(0);
        let error = node
            .admit_work_checked_with_progress(
                WorkCheckedPacket::verify(wrong.clone()).unwrap(),
                1000,
                &|point| {
                    if matches!(point, ExecutionProgress::BeforePrepare { .. }) {
                        prepared.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(())
                },
            )
            .unwrap_err();
        assert_eq!(error.to_string(), "ROOT");
        assert!(!error.requires_owner_stop());
        assert!(prepared.load(Ordering::Relaxed) > 0);
        assert_eq!(
            state_reads(&node) - reads,
            1,
            "one admission reconstructed its identical parent twice"
        );
        assert!(node.record(wrong.id().unwrap()).is_err());
        assert_eq!(node.stats().unwrap(), stats);
        assert_eq!(node.read_active().unwrap(), before);
        assert!(node.root_rejection_cache.borrow().is_none());
    }
    // A full W1 and a previous successful context check cannot retain another
    // request's clock authority or skip the current context checks.
    context_checkpoints(&node, &valid);
    let error = node
        .admit_work_checked(WorkCheckedPacket::verify(valid.clone()).unwrap(), 0)
        .unwrap_err();
    assert_eq!(error.to_string(), "TIME_DEFERRED");
    assert_eq!(node.stats().unwrap(), stats);
    assert_eq!(
        node.admit_work_checked(WorkCheckedPacket::verify(valid.clone()).unwrap(), 1000)
            .unwrap(),
        valid.id().unwrap()
    );
}

#[test]
fn admission_parent_keeps_second_boundary_cancellation_and_error_identity() {
    for authenticated in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut node = open(dir.path(), &settings, authenticated);
        let packet = make(&node, settings.genesis(), 1, 1001, 0);
        let before = node.read_active().unwrap();
        let stats = node.stats().unwrap();
        for code in [
            crate::ErrorCode::PublicRequestCancelled,
            crate::ErrorCode::PublicMutationCpuBudget,
        ] {
            // Locate the boundary from actual complete context validation,
            // without depending on how many account/history rows it visits.
            let boundary = context_checkpoints(&node, &packet) + 1;
            let seen = AtomicUsize::new(0);
            let prepared = AtomicUsize::new(0);
            let error = node
                .admit_work_checked_with_progress(
                    WorkCheckedPacket::verify(packet.clone()).unwrap(),
                    1000,
                    &|point| {
                        if matches!(point, ExecutionProgress::BeforePrepare { .. }) {
                            prepared.fetch_add(1, Ordering::Relaxed);
                        }
                        if point == ExecutionProgress::BeforeParentBinding
                            && seen.fetch_add(1, Ordering::Relaxed) + 1 == boundary
                        {
                            Err(Error::new(code))
                        } else {
                            Ok(())
                        }
                    },
                )
                .unwrap_err();
            assert!(error.is(code));
            assert!(!error.requires_owner_stop());
            assert_eq!(seen.load(Ordering::Relaxed), boundary);
            assert_eq!(prepared.load(Ordering::Relaxed), 0);
            assert!(node.record(packet.id().unwrap()).is_err());
            assert_eq!(node.stats().unwrap(), stats);
            assert_eq!(node.read_active().unwrap(), before);
        }
        let id = node
            .admit_work_checked(WorkCheckedPacket::verify(packet.clone()).unwrap(), 1000)
            .unwrap();
        node.activate_observed(id, 1000).unwrap();
        let after = node.read_active().unwrap();
        drop(node);
        assert_eq!(
            open(dir.path(), &settings, authenticated)
                .read_active()
                .unwrap(),
            after
        );
    }
}

#[test]
fn admission_parent_foreign_sql_change_forces_original_fresh_state_validation() {
    let dir = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let mut node = open(dir.path(), &settings, true);
    let valid = make(&node, settings.genesis(), 1, 1001, 0);
    let wrong = wrong_root(valid.clone());
    let before = node.read_active().unwrap();
    let stats = node.stats().unwrap();
    let boundary = context_checkpoints(&node, &wrong) + 1;
    let slot = node.slot().unwrap();
    let (key, bytes): (String, Vec<u8>) = node
        .db
        .query_row(
            "SELECT key,value FROM kv WHERE slot=? ORDER BY key LIMIT 1",
            [slot],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let foreign = Mutex::new(Connection::open(dir.path().join("native.sqlite")).unwrap());
    let version_before: u64 = node
        .db
        .query_row("PRAGMA data_version", [], |row| row.get(0))
        .unwrap();
    let seen = AtomicUsize::new(0);
    let reads = state_reads(&node);
    let prepared = AtomicUsize::new(0);
    let error = node
        .admit_work_checked_with_progress(
            WorkCheckedPacket::verify(wrong.clone()).unwrap(),
            1000,
            &|point| {
                if matches!(point, ExecutionProgress::BeforePrepare { .. }) {
                    prepared.fetch_add(1, Ordering::Relaxed);
                }
                if point == ExecutionProgress::BeforeParentBinding
                    && seen.fetch_add(1, Ordering::Relaxed) + 1 == boundary
                {
                    foreign.lock().unwrap().execute(
                        "UPDATE kv SET value=? WHERE slot=? AND key=?",
                        params![b"null".as_slice(), slot, key],
                    )?;
                }
                Ok(())
            },
        )
        .unwrap_err();
    let version_after: u64 = node
        .db
        .query_row("PRAGMA data_version", [], |row| row.get(0))
        .unwrap();
    assert_ne!(version_before, version_after);
    assert_eq!(error.to_string(), "ROOT");
    assert!(
        error.requires_owner_stop(),
        "a current local State fault became a peer ROOT refusal"
    );
    assert_eq!(prepared.load(Ordering::Relaxed), 0);
    assert_eq!(state_reads(&node) - reads, 2);
    assert!(node.record(wrong.id().unwrap()).is_err());
    // stats() also validates the complete active State. Until the deliberately
    // corrupted KV is restored, it must preserve the same local-integrity error.
    let stats_error = node.stats().unwrap_err();
    assert_eq!(stats_error.to_string(), "ROOT");
    assert!(stats_error.requires_owner_stop());
    foreign
        .lock()
        .unwrap()
        .execute(
            "UPDATE kv SET value=? WHERE slot=? AND key=?",
            params![bytes, slot, key],
        )
        .unwrap();
    assert_eq!(node.read_active().unwrap(), before);
    assert_eq!(node.stats().unwrap(), stats);
    assert_eq!(
        node.admit_work_checked(WorkCheckedPacket::verify(valid.clone()).unwrap(), 1000)
            .unwrap(),
        valid.id().unwrap()
    );
}

#[test]
fn admission_parent_reuse_matches_reference_execution_on_inactive_parent_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let mut producer = open(&dir.path().join("producer"), &settings, false);
    let left = make(&producer, settings.genesis(), 1, 1001, 0);
    let right = make(&producer, settings.genesis(), 1, 1002, 2);
    for packet in [&left, &right] {
        producer.admit(packet, 1000).unwrap();
    }
    producer
        .activate_observed(left.id().unwrap(), 1000)
        .unwrap();
    let packet = make(&producer, right.id().unwrap(), 2, 1003, 2);
    let actual = producer.state_at(right.id().unwrap()).unwrap();
    // This independently executes the actual parent and transaction through
    // unchanged M06; it does not use the admission-context reuse path.
    let reference = producer
        .execute_derived_with_progress(
            &actual,
            ExecutionRequest {
                timestamp: None,
                transactions: &packet.transactions,
                height: packet.header.height,
                miner: packet.header.miner,
                parent_id: packet.header.parent,
                workers: 1,
            },
            &|_| Ok(()),
        )
        .unwrap();
    assert_eq!(reference.output.root, packet.header.state);
    assert_eq!(
        sequence_root("receipts", &reference.output.receipts),
        packet.header.receipts
    );
    for authenticated in [false, true] {
        let path = dir.path().join(if authenticated {
            "authenticated"
        } else {
            "legacy"
        });
        let mut receiver = open(&path, &settings, authenticated);
        for branch in [&left, &right] {
            receiver.admit(branch, 1000).unwrap();
        }
        receiver
            .activate_observed(left.id().unwrap(), 1000)
            .unwrap();
        assert_ne!(receiver.active().unwrap().0, packet.header.parent);
        let id = receiver
            .admit_work_checked(WorkCheckedPacket::verify(packet.clone()).unwrap(), 1000)
            .unwrap();
        assert_eq!(id, packet.id().unwrap());
        assert_eq!(receiver.state_at(id).unwrap(), reference.output.state);
        receiver.activate_observed(id, 1000).unwrap();
        let after = receiver.read_active().unwrap();
        assert_eq!(after.0, id);
        assert_eq!(after.2, reference.output.state);
        assert!(receiver.root_rejection_cache.borrow().is_none());
        drop(receiver);
        let reopened = open(&path, &settings, authenticated);
        assert_eq!(reopened.read_active().unwrap(), after);
        assert_eq!(
            reopened.packet(id).unwrap().encode().unwrap(),
            packet.encode().unwrap()
        );
    }
}
