use super::*;
use crate::ingress::public_v3::{
    public_dispatch, task_alive, PublicDispatchObservation, PublicMetrics, Request,
};
use rusqlite::{params, Connection};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, TryLockError,
    },
    thread,
    time::{Duration, Instant},
};

const CLOCK: u64 = 1_000_000;

struct Fixture {
    owner: Arc<Mutex<Node>>,
    directory: tempfile::TempDir,
    main: [Hash; 3],
    fork: [Hash; 4],
}
fn extend(node: &mut Node, parent: Hash, height: u64, miner: u64, activate: bool) -> Hash {
    let packet = node
        .make(
            parent,
            vec![],
            crate::development_public(miner).unwrap(),
            1 + height * 10 + miner,
            4096,
        )
        .unwrap();
    let id = node.admit(&packet, CLOCK).unwrap();
    if activate {
        node.activate(id).unwrap();
    }
    id
}
fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let genesis = settings.genesis();
    let mut node = Node::open(directory.path(), settings, 1).unwrap();
    let first = extend(&mut node, genesis, 1, 0, true);
    let second = extend(&mut node, first, 2, 0, true);
    let fork_first = extend(&mut node, genesis, 1, 1, false);
    let fork_second = extend(&mut node, fork_first, 2, 1, false);
    let fork_third = extend(&mut node, fork_second, 3, 1, false);
    Fixture {
        owner: Arc::new(Mutex::new(node)),
        directory,
        main: [genesis, first, second],
        fork: [genesis, fork_first, fork_second, fork_third],
    }
}

// The previous held-owner formatter, with the original settings-selected codec
// and bound. This reference performs the same actual indexed read from Node.
fn held_page(node: &Node, tip: Hash, after: Hash) -> Result<Value> {
    let packets = node.public_history_packet(tip, after, MAX_HISTORY_STEPS, &mut |_| Ok(()))?;
    let next = packets
        .last()
        .map(|packet| packet.id().map(hex::encode))
        .transpose()?
        .unwrap_or_else(|| hex::encode(after));
    let mut encoded = Vec::new();
    for packet in packets {
        let raw = packet.encode_for_settings(node.settings())?;
        ensure(
            raw.len()
                .checked_mul(2)
                .is_some_and(|length| length <= 2 * MAX_PACKET),
            "PUBLIC_HISTORY_BYTES",
        )?;
        encoded.push(hex::encode(raw));
    }
    Ok(serde_json::to_value(crate::ingress::Page {
        schema: if node.settings().is_native_pq_application_v6() {
            "pon-native-pq-history-v6"
        } else {
            "pon-native-history-v1"
        }
        .into(),
        network: hex::encode(node.settings().network()),
        parameters: hex::encode(node.settings().parameters()),
        genesis: hex::encode(node.settings().genesis()),
        tip: hex::encode(tip),
        after: hex::encode(after),
        complete: next == hex::encode(tip),
        next,
        packets: encoded,
    })?)
}
fn dispatch(owner: &Mutex<Node>, tip: Hash, after: Hash) -> Result<Value> {
    public_dispatch(
        owner,
        Request::History {
            tip: hex::encode(tip),
            after: hex::encode(after),
        },
        Instant::now() + Duration::from_secs(30),
        &AtomicBool::new(false),
        &AtomicBool::new(false),
        &Mutex::new(PublicMetrics::default()),
        PublicDispatchObservation {
            observation: None,
            mutation_cpu: None,
            arithmetic_facts: None,
            w1_rejection_cache: None,
        },
    )
}

#[test]
fn public_history_formatting_matches_bytes_cursors_and_fresh_foreign_damage() {
    let f = fixture();
    let before = f.owner.lock().unwrap().read_active().unwrap();
    for (tip, after) in [
        (f.main[2], f.main[0]),
        (f.main[2], f.main[1]),
        (f.main[2], f.main[2]),
        (f.fork[3], f.fork[1]),
    ] {
        let expected = held_page(&f.owner.lock().unwrap(), tip, after).unwrap();
        let actual = dispatch(&f.owner, tip, after).unwrap();
        assert_eq!(
            serde_json::to_vec(&actual).unwrap(),
            serde_json::to_vec(&expected).unwrap()
        );
    }
    for (tip, after) in [
        (f.main[2], f.fork[1]),
        (f.main[1], f.main[2]),
        ([255; 32], f.main[0]),
    ] {
        let expected = held_page(&f.owner.lock().unwrap(), tip, after).unwrap_err();
        let actual = dispatch(&f.owner, tip, after).unwrap_err();
        assert_eq!(actual.to_string(), expected.to_string());
        assert_eq!(actual.kind(), expected.kind());
        assert_eq!(actual.code(), expected.code());
        assert_eq!(actual.requires_owner_stop(), expected.requires_owner_stop());
    }
    // Preserve header/trace/id and total length while damaging the body count.
    // Warm response formatting cannot replace the next request's fresh decode.
    let foreign = Connection::open(f.directory.path().join("native.sqlite")).unwrap();
    let original: Vec<u8> = foreign
        .query_row(
            "SELECT packet FROM blocks WHERE id=?",
            [f.main[1].as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let mut damaged = original.clone();
    let offset = trnm_protocol::pon_wire::HEADER_BYTES;
    damaged[offset..offset + 2].copy_from_slice(&257_u16.to_le_bytes());
    foreign
        .execute(
            "UPDATE blocks SET packet=? WHERE id=?",
            params![damaged, f.main[1].as_slice()],
        )
        .unwrap();
    let expected = held_page(&f.owner.lock().unwrap(), f.main[2], f.main[0]).unwrap_err();
    let actual = dispatch(&f.owner, f.main[2], f.main[0]).unwrap_err();
    assert_eq!(actual.to_string(), expected.to_string());
    assert_eq!(actual.kind(), expected.kind());
    assert_eq!(actual.code(), expected.code());
    assert!(actual.requires_owner_stop());
    foreign
        .execute(
            "UPDATE blocks SET packet=? WHERE id=?",
            params![original, f.main[1].as_slice()],
        )
        .unwrap();
    assert_eq!(
        dispatch(&f.owner, f.main[2], f.main[0]).unwrap(),
        held_page(&f.owner.lock().unwrap(), f.main[2], f.main[0]).unwrap()
    );
    assert_eq!(f.owner.lock().unwrap().read_active().unwrap(), before);
}

#[test]
fn public_history_formatting_releases_owner_and_keeps_fixed_tip_during_reorg() {
    let f = fixture();
    let expected = held_page(&f.owner.lock().unwrap(), f.main[2], f.main[0]).unwrap();
    let (released_tx, released_rx) = mpsc::sync_channel(0);
    let (changed_tx, changed_rx) = mpsc::sync_channel(0);
    let owner = f.owner.clone();
    let tip = f.main[2];
    let after = f.main[0];
    let reader = thread::spawn(move || {
        let mut held_seen = false;
        let mut released_seen = false;
        let result = read(&owner, hex::encode(tip), hex::encode(after), &mut |_| {
            match owner.try_lock() {
                Ok(guard) => {
                    drop(guard);
                    if held_seen && !released_seen {
                        released_seen = true;
                        released_tx.send(()).unwrap();
                        changed_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                    }
                }
                Err(TryLockError::WouldBlock) => held_seen = true,
                Err(TryLockError::Poisoned(_)) => panic!("owner poisoned"),
            }
            Ok(())
        });
        assert!(held_seen && released_seen);
        result
    });
    // The real writer must finish while the reader is paused at its first
    // formatting checkpoint. No response bytes or validation verdict are reused.
    released_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    {
        let mut node = f.owner.lock().unwrap();
        node.activate(f.fork[3]).unwrap();
        assert_eq!(node.active().unwrap().0, f.fork[3]);
    }
    changed_tx.send(()).unwrap();
    assert_eq!(reader.join().unwrap().unwrap(), expected);
    assert_eq!(dispatch(&f.owner, f.main[2], f.main[0]).unwrap(), expected);
    let fork_page = dispatch(&f.owner, f.fork[3], f.fork[0]).unwrap();
    assert_eq!(fork_page["next"], hex::encode(f.fork[1]));
    assert_ne!(fork_page["next"], expected["next"]);
}

#[test]
fn public_history_formatting_checks_original_cancel_stop_and_deadline() {
    let f = fixture();
    let before = f.owner.lock().unwrap().read_active().unwrap();
    for target in 1..=3 {
        for cancel in [true, false] {
            let stopped = AtomicBool::new(false);
            let cancelled = AtomicBool::new(false);
            let deadline = Instant::now() + Duration::from_secs(30);
            let mut held_seen = false;
            let mut formatting_checks = 0;
            let error = read(
                &f.owner,
                hex::encode(f.main[2]),
                hex::encode(f.main[0]),
                &mut |_| {
                    match f.owner.try_lock() {
                        Ok(guard) => {
                            drop(guard);
                            if held_seen {
                                formatting_checks += 1;
                                if formatting_checks == target {
                                    if cancel {
                                        cancelled.store(true, Ordering::Release);
                                    } else {
                                        stopped.store(true, Ordering::Release);
                                    }
                                }
                            }
                        }
                        Err(TryLockError::WouldBlock) => held_seen = true,
                        Err(TryLockError::Poisoned(_)) => panic!("owner poisoned"),
                    }
                    task_alive(deadline, &stopped, &cancelled)
                },
            )
            .unwrap_err();
            assert_eq!(formatting_checks, target);
            assert_eq!(
                error.to_string(),
                if cancel {
                    "PUBLIC_REQUEST_CANCELLED"
                } else {
                    "PUBLIC_REQUEST_DEADLINE"
                }
            );
            assert!(!error.requires_owner_stop());
        }
    }
    let expired = Instant::now();
    let error = read(
        &f.owner,
        hex::encode(f.main[2]),
        hex::encode(f.main[0]),
        &mut |_| task_alive(expired, &AtomicBool::new(false), &AtomicBool::new(false)),
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "PUBLIC_REQUEST_DEADLINE");
    assert_eq!(f.owner.lock().unwrap().read_active().unwrap(), before);
    assert!(dispatch(&f.owner, f.main[2], f.main[0]).is_ok());
}
