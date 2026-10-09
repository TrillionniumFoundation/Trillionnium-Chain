#!/usr/bin/env python3
"""Stage a bounded snapshot acceleration; never a runtime fallback or receipt."""
import hashlib
from pathlib import Path
root = Path(__file__).resolve().parents[2]
source = root / 'trillionnium/crates/trnm-pon-node/src/store.rs'
tests = root / 'trillionnium/crates/trnm-pon-node/src/native_authenticated_tests.rs'
def checked(path, expected):
    data = path.read_bytes()
    assert hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest() == expected, str(path)
    return data.decode()
old = checked(source, '10740c92fa7c0d03f408cbd23c3e858049bc68ca')
prior = checked(tests, 'b132b62f8db6ffe281f6d934744666594b112e2b')
needle = '        if h.height.is_multiple_of(128) {\n            ensure(\n                tx.execute(\n                    "INSERT INTO snapshots VALUES(?,?)",'
replacement = '''        // Authenticated admission otherwise reconstructs the just-written state
        // from genesis, verifying every intermediate complete account tree.
        // Keep an ordinary canonical snapshot for each admitted native block.
        // These are disposable accelerators: retain the existing 64-row policy,
        // genesis anchor, full history/delta checks and post-write readback.
        // Legacy cadence remains unchanged; no validity verdict is cached.
        if self.state_backend == StateBackend::AuthenticatedV1 || h.height.is_multiple_of(128) {
            ensure(
                tx.execute(
                    "INSERT INTO snapshots VALUES(?,?)",'''
assert old.count(needle) == 1
candidate = old.replace(needle, replacement)
prune = '            tx.execute("DELETE FROM snapshots WHERE block!=? AND block NOT IN (SELECT snapshots.block FROM snapshots JOIN blocks ON blocks.id=snapshots.block ORDER BY blocks.height DESC,blocks.id LIMIT 64)",[self.settings.genesis.as_slice()])?;'
assert candidate.count(prune) == 1
candidate = candidate.replace(prune, prune + '''
            let retained: u64 = tx.query_row(
                "SELECT COUNT(*) FROM snapshots WHERE block!=?",
                [self.settings.genesis.as_slice()],
                |row| row.get(0),
            )?;
            ensure(retained <= 64, "SNAPSHOT_LIMIT").map_err(Error::local_integrity)?;''')
source.write_text(candidate)
tests.write_text(prior + r'''

#[test]
fn native_dense_snapshots_retain_64_and_reconstruct_pruned_history() {
    let dir = tempfile::tempdir().unwrap();
    let native_path = dir.path().join("dense");
    let mut node = open(&native_path, StateBackend::AuthenticatedV1);
    let mut reference = open(&dir.path().join("reference"), StateBackend::Legacy);
    let genesis = node.settings.genesis();
    let mut ids = vec![genesis];
    let mut parent = genesis;
    for height in 1..=70 {
        let packet = make(&reference, parent, vec![]);
        parent = node.admit(&packet, 100_000).unwrap();
        assert_eq!(reference.admit(&packet, 100_000).unwrap(), parent);
        node.activate(parent).unwrap();
        reference.activate(parent).unwrap();
        ids.push(parent);
        let count: u64 = node.db.query_row("SELECT COUNT(*) FROM snapshots WHERE block!=?", [genesis.as_slice()], |row| row.get(0)).unwrap();
        assert_eq!(count, height.min(64));
        let legacy: u64 = reference.db.query_row("SELECT COUNT(*) FROM snapshots", [], |row| row.get(0)).unwrap();
        assert_eq!(legacy, 1);
    }
    let retained: Vec<Vec<u8>> = node.db.prepare("SELECT snapshots.block FROM snapshots JOIN blocks ON blocks.id=snapshots.block WHERE blocks.height>0 ORDER BY blocks.height,blocks.id").unwrap()
        .query_map([], |row| row.get(0)).unwrap().map(|row| row.unwrap()).collect();
    assert_eq!(retained, ids[7..].iter().map(|id| id.to_vec()).collect::<Vec<_>>());
    let before = logical_rows(&node.db);
    drop(node);
    let node = open(&native_path, StateBackend::AuthenticatedV1);
    assert_eq!(logical_rows(&node.db), before);
    for index in [0, 1, 6, 7, 35, 69, 70] {
        assert_eq!(node.state_at(ids[index]).unwrap(), reference.state_at(ids[index]).unwrap());
    }
    let active = node.read_active().unwrap();
    node.db.execute("DELETE FROM snapshots WHERE block!=?", [genesis.as_slice()]).unwrap();
    for index in [1, 7, 35, 69] {
        assert_eq!(node.state_at(ids[index]).unwrap(), reference.state_at(ids[index]).unwrap());
    }
    assert_eq!(node.read_active().unwrap(), active);
    native_authenticated::verify_history(&node.db, &node.settings, parent, &mut || Ok(())).unwrap();
}

#[test]
fn native_dense_snapshot_insert_corruption_and_delta_omission_roll_back() {
    for trigger in [
        "CREATE TEMP TRIGGER snapshot_fault BEFORE INSERT ON snapshots BEGIN SELECT RAISE(IGNORE); END;",
        "CREATE TEMP TRIGGER snapshot_fault AFTER INSERT ON snapshots BEGIN UPDATE snapshots SET state=X'7b7d' WHERE block=NEW.block; END;",
        "CREATE TEMP TRIGGER snapshot_fault AFTER INSERT ON snapshots BEGIN DELETE FROM deltas WHERE block=NEW.block; END;",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut node = open(dir.path(), StateBackend::AuthenticatedV1);
        let packet = make(&node, node.settings.genesis(), vec![transfer(&node.settings, 1, 811)]);
        let before = logical_rows(&node.db);
        node.db.execute_batch(trigger).unwrap();
        assert!(node.admit(&packet, 100_000).is_err(), "{trigger}");
        assert_eq!(logical_rows(&node.db), before, "{trigger}");
        node.db.execute_batch("DROP TRIGGER snapshot_fault").unwrap();
        let id = node.admit(&packet, 100_000).unwrap();
        assert_ne!(id, node.settings.genesis());
    }
}

#[test]
fn native_dense_snapshot_pruning_suppression_preserves_atomic_limit() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = open(dir.path(), StateBackend::AuthenticatedV1);
    let mut parent = node.settings.genesis();
    for _ in 0..64 {
        let packet = make(&node, parent, vec![]);
        parent = node.admit(&packet, 100_000).unwrap();
        node.activate(parent).unwrap();
    }
    let packet = make(&node, parent, vec![]);
    let before = logical_rows(&node.db);
    node.db.execute_batch("CREATE TEMP TRIGGER refuse_prune BEFORE DELETE ON snapshots BEGIN SELECT RAISE(IGNORE); END;").unwrap();
    let error = node.admit(&packet, 100_000).unwrap_err();
    assert_eq!(error.to_string(), "SNAPSHOT_LIMIT");
    assert_eq!(error.kind(), ErrorKind::LocalStructure);
    assert_eq!(logical_rows(&node.db), before);
    node.db.execute_batch("DROP TRIGGER refuse_prune").unwrap();
    node.admit(&packet, 100_000).unwrap();
    let count: u64 = node.db.query_row("SELECT COUNT(*) FROM snapshots", [], |row| row.get(0)).unwrap();
    assert_eq!(count, 65);
}

#[test]
fn native_dense_snapshot_cannot_hide_old_delta_damage_from_admission() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = open(dir.path(), StateBackend::AuthenticatedV1);
    let packet = make(&node, node.settings.genesis(), vec![transfer(&node.settings, 1, 812)]);
    let first = node.admit(&packet, 100_000).unwrap();
    node.activate(first).unwrap();
    let second = make(&node, first, vec![]);
    let second = node.admit(&second, 100_000).unwrap();
    node.activate(second).unwrap();
    let next = make(&node, second, vec![]);
    let before = logical_rows(&node.db);
    node.db.execute_batch(&format!("CREATE TEMP TRIGGER damage_old_delta AFTER INSERT ON snapshots BEGIN DELETE FROM deltas WHERE block=X'{}'; END;", hex::encode(first))).unwrap();
    assert!(node.admit(&next, 100_000).is_err());
    assert_eq!(logical_rows(&node.db), before);
    node.db.execute_batch("DROP TRIGGER damage_old_delta").unwrap();
    node.admit(&next, 100_000).unwrap();
}

#[test]
fn native_dense_snapshot_readback_cost_keeps_full_state_and_unaccelerated_reference() {
    let dir = tempfile::tempdir().unwrap();
    let mut settings = settings();
    for index in 0..1024u64 {
        settings.initial.insert(format!("account:{}", hex::encode(hash(b"dense-snapshot-zero-balance", &[&index.to_le_bytes()]))), json!({"balance":0,"nonce":7}));
    }
    settings.genesis = hash(b"dense-snapshot-cost-explicit-fixture", &[&settings.genesis, &root(&settings.initial).unwrap()]);
    let mut node = Node::open_with_authenticated_state(dir.path(), settings, 1).unwrap();
    let mut parent = node.settings.genesis();
    for height in 1..=8 {
        let packet = make(&node, parent, vec![]);
        parent = node.admit(&packet, 100_000).unwrap();
        if height < 8 { node.activate(parent).unwrap(); }
    }
    let logical_before = logical_rows(&node.db);
    let expected = node.state_at(parent).unwrap();
    let mut observations = Vec::new();
    for pair in 0..4 {
        for accelerated in if pair % 2 == 0 { [false, true] } else { [true, false] } {
            let tx = node.db.unchecked_transaction().unwrap();
            if !accelerated {
                tx.execute("DELETE FROM snapshots WHERE block!=?", [node.settings.genesis().as_slice()]).unwrap();
            }
            let mut callbacks = 0usize;
            let start = std::time::Instant::now();
            let state = node.state_at_with_progress(parent, &mut || { callbacks += 1; Ok(()) }).unwrap();
            let elapsed_ns = start.elapsed().as_nanos();
            assert_eq!(state, expected);
            observations.push(json!({"pair":pair,"accelerated":accelerated,"height":8,"full_keys":state.len(),"elapsed_ns":elapsed_ns,"callbacks":callbacks}));
            tx.rollback().unwrap();
            assert_eq!(logical_rows(&node.db), logical_before);
        }
    }
    eprintln!("pon_native_snapshot_readback_cost_v1 {}", json!({"scope":"same unmodified state_at implementation with/without optional snapshots; synthetic1024 zero-balance accounts, not full capacity or TPS","observations":observations}));
}
''')
print('Candidate built; all previous source checks, tests and 64-row retention remain.')
