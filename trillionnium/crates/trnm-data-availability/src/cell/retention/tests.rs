use std::{
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use super::*;
use crate::cell::{fetch_cell, serve_cells, CellContextV1, CellPeerLimitsV1};

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

fn config(id: u8, capacity: u64) -> CellRetentionConfigV1 {
    CellRetentionConfigV1 {
        store_id: [id; 32],
        capacity_bytes: capacity,
        maximum_obligations: 16,
    }
}

fn material(directory: &Path, size: usize) -> (CellStoreV1, CellManifestV1, Vec<u8>) {
    let bytes = (0..size)
        .map(|n| ((n * 37 + 11) % 251) as u8)
        .collect::<Vec<_>>();
    let input = directory.join("input");
    fs::write(&input, &bytes).unwrap();
    let cache = CellStoreV1::open(&directory.join("cache.sqlite"), cache_config()).unwrap();
    let manifest = cache
        .pack_file(
            &input,
            CellContextV1 {
                family: "retention-native-test-v1".into(),
                base: [1; 32],
                parent: [2; 32],
                tokenizer: [3; 32],
                layout: [4; 32],
                runtime: [5; 32],
            },
            16_384,
        )
        .unwrap();
    (cache, manifest, bytes)
}

fn contract(id: u8, manifest: &CellManifestV1) -> CellRetentionContractV1 {
    CellRetentionContractV1 {
        operation: [id; 32],
        funding_operation: [id + 32; 32],
        manifest: manifest.clone(),
        retain_from_height: 0,
        retain_until_height: 10,
        maximum_repair_bytes: manifest.size() * 2,
        successor: None,
    }
}

fn damage(store: &mut CellRetentionStoreV1) {
    store.arena.seek(SeekFrom::Start(0)).unwrap();
    store.arena.write_all(&[0xff]).unwrap();
    store.arena.sync_all().unwrap();
}

#[test]
fn actual_capacity_is_allocated_before_ack_and_full_refusal_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let (cache, manifest, _) = material(dir.path(), 5000);
    let path = dir.path().join("retention");
    let cfg = config(1, 8192);
    let mut store = CellRetentionStoreV1::create(&path, cfg.clone()).unwrap();
    let reserved = store.reserve(contract(1, &manifest)).unwrap();
    assert!(!reserved.acknowledged);
    assert_eq!(reserved.reserved_bytes, 8192);
    assert!(reserved.physical_arena_bytes >= 8192);
    assert!(store.reserve(contract(2, &manifest)).is_err());
    let ack = store.acknowledge([1; 32], &cache, deadline()).unwrap();
    assert!(ack.acknowledged);
    assert!(store.retire([1; 32], 9, None, deadline()).is_err());
    drop(store);
    let mut store = CellRetentionStoreV1::open(&path, cfg).unwrap();
    assert_eq!(store.verify([1; 32], deadline()).unwrap(), ack);
    assert!(store.reserve(contract(2, &manifest)).is_err());
    assert!(store.retire([1; 32], 0, None, deadline()).is_err());
}

#[test]
fn pending_ack_never_claims_bytes_and_keeps_original_reservation() {
    let dir = tempfile::tempdir().unwrap();
    let (cache, manifest, _) = material(dir.path(), 5000);
    let path = dir.path().join("retention");
    let cfg = config(1, 8192);
    let mut store = CellRetentionStoreV1::create(&path, cfg.clone()).unwrap();
    store.reserve(contract(1, &manifest)).unwrap();
    let expired = Instant::now() - Duration::from_secs(1);
    assert!(store.acknowledge([1; 32], &cache, expired).is_err());
    drop(store);
    let mut store = CellRetentionStoreV1::open(&path, cfg).unwrap();
    let pending = store.reserve(contract(1, &manifest)).unwrap();
    assert!(!pending.acknowledged);
    assert_eq!(pending.initial_copy_bytes_committed, 0);
    assert!(store.verify([1; 32], deadline()).is_err());
    assert!(store.reserve(contract(2, &manifest)).is_err());
    assert!(
        store
            .acknowledge([1; 32], &cache, deadline())
            .unwrap()
            .acknowledged
    );
}

#[test]
fn corrupt_payload_and_failed_repair_keep_duty_and_irreversible_byte_cost() {
    let dir = tempfile::tempdir().unwrap();
    let (cache, manifest, _) = material(dir.path(), 5000);
    let path = dir.path().join("retention");
    let cfg = config(1, 8192);
    let empty = CellStoreV1::open(&dir.path().join("empty.sqlite"), cache_config()).unwrap();
    let mut store = CellRetentionStoreV1::create(&path, cfg.clone()).unwrap();
    store.reserve(contract(1, &manifest)).unwrap();
    store.acknowledge([1; 32], &cache, deadline()).unwrap();
    damage(&mut store);
    assert!(store.verify([1; 32], deadline()).is_err());
    assert!(store
        .repair([1; 32], [101; 32], &empty, deadline())
        .is_err());
    assert_eq!(
        store
            .reserve(contract(1, &manifest))
            .unwrap()
            .repair_bytes_committed,
        5000
    );
    drop(store);
    let mut store = CellRetentionStoreV1::open(&path, cfg).unwrap();
    // The unknown original attempt cannot dispatch again, even with good bytes.
    assert!(store
        .repair([1; 32], [101; 32], &cache, deadline())
        .is_err());
    assert_eq!(
        store
            .reserve(contract(1, &manifest))
            .unwrap()
            .repair_bytes_committed,
        5000
    );
    let repaired = store
        .repair([1; 32], [102; 32], &cache, deadline())
        .unwrap();
    assert_eq!(repaired.repair_bytes_committed, 10000);
    assert_eq!(
        store
            .repair([1; 32], [102; 32], &cache, deadline())
            .unwrap(),
        repaired
    );
    damage(&mut store);
    assert!(store
        .repair([1; 32], [102; 32], &cache, deadline())
        .is_err());
    assert!(store
        .repair([1; 32], [103; 32], &cache, deadline())
        .is_err());
    assert_eq!(
        store
            .reserve(contract(1, &manifest))
            .unwrap()
            .repair_bytes_committed,
        10000
    );
    assert!(store.reserve(contract(2, &manifest)).is_err());
}

#[test]
fn lost_repair_ack_reconciles_actual_bytes_without_second_write_or_charge() {
    let dir = tempfile::tempdir().unwrap();
    let (cache, manifest, _) = material(dir.path(), 5000);
    let path = dir.path().join("retention");
    let cfg = config(1, 8192);
    let mut store = CellRetentionStoreV1::create(&path, cfg.clone()).unwrap();
    store.reserve(contract(1, &manifest)).unwrap();
    store.acknowledge([1; 32], &cache, deadline()).unwrap();
    damage(&mut store);
    store
        .repair([1; 32], [101; 32], &cache, deadline())
        .unwrap();
    // Deterministic cut between fsynced destination and completion journal ACK.
    store
        .connection
        .execute(
            "UPDATE repairs SET complete=0,checksum=?1 WHERE operation=?2",
            params![
                repair_checksum([101; 32], [1; 32], 5000, false),
                [101u8; 32].as_slice()
            ],
        )
        .unwrap();
    drop(store);
    let mut store = CellRetentionStoreV1::open(&path, cfg).unwrap();
    let empty = CellStoreV1::open(&dir.path().join("empty.sqlite"), cache_config()).unwrap();
    let result = store
        .repair([1; 32], [101; 32], &empty, deadline())
        .unwrap();
    assert_eq!(result.repair_bytes_committed, 5000);
    assert!(store.repair_row([101; 32]).unwrap().unwrap().2);
}

#[test]
fn mandatory_successor_requires_fresh_verified_bytes_before_capacity_reuse() {
    let dir = tempfile::tempdir().unwrap();
    let (cache, manifest, _) = material(dir.path(), 5000);
    let mut first =
        CellRetentionStoreV1::create(&dir.path().join("first"), config(1, 8192)).unwrap();
    let mut next = CellRetentionStoreV1::create(&dir.path().join("next"), config(2, 8192)).unwrap();
    let mut duty = contract(1, &manifest);
    duty.successor = Some(([2; 32], [2; 32]));
    first.reserve(duty.clone()).unwrap();
    first.acknowledge([1; 32], &cache, deadline()).unwrap();
    assert!(first.retire([1; 32], 10, None, deadline()).is_err());
    assert!(first
        .retire([1; 32], 10, Some(&mut next), deadline())
        .is_err());
    let mut continuation = contract(2, &manifest);
    continuation.retain_until_height = 30;
    next.reserve(continuation).unwrap();
    next.acknowledge([2; 32], &cache, deadline()).unwrap();
    damage(&mut next);
    assert!(first
        .retire([1; 32], 10, Some(&mut next), deadline())
        .is_err());
    next.repair([2; 32], [101; 32], &cache, deadline()).unwrap();
    assert!(
        first
            .retire([1; 32], 10, Some(&mut next), deadline())
            .unwrap()
            .retired
    );
    assert!(first.reserve(duty).unwrap().retired);
    first.reserve(contract(3, &manifest)).unwrap();
    assert!(first.verify([1; 32], deadline()).is_err());
    assert!(next.verify([2; 32], deadline()).is_ok());
}

#[test]
fn original_ids_and_limits_cannot_be_renamed_reopened_or_recycled() {
    let dir = tempfile::tempdir().unwrap();
    let (cache, manifest, _) = material(dir.path(), 5000);
    let path = dir.path().join("retention");
    let mut cfg = config(1, 8192);
    cfg.maximum_obligations = 1;
    let mut store = CellRetentionStoreV1::create(&path, cfg.clone()).unwrap();
    let duty = contract(1, &manifest);
    store.reserve(duty.clone()).unwrap();
    let mut changed = duty.clone();
    changed.maximum_repair_bytes += 1;
    assert!(store.reserve(changed).is_err());
    let mut alias = duty.clone();
    alias.operation = [2; 32];
    assert!(store.reserve(alias).is_err());
    assert!(CellRetentionStoreV1::open(&path, cfg.clone()).is_err());
    store.acknowledge([1; 32], &cache, deadline()).unwrap();
    store.retire([1; 32], 10, None, deadline()).unwrap();
    assert!(store.reserve(contract(2, &manifest)).is_err());
    drop(store);
    let mut repin = cfg.clone();
    repin.capacity_bytes = 16384;
    assert!(CellRetentionStoreV1::open(&path, repin).is_err());
    let mut store = CellRetentionStoreV1::open(&path, cfg).unwrap();
    assert!(store.reserve(duty).unwrap().retired);
}

#[test]
fn truncated_physical_backing_or_mutated_obligation_refuses_cold_open() {
    let dir = tempfile::tempdir().unwrap();
    let (_, manifest, _) = material(dir.path(), 5000);
    let path = dir.path().join("retention");
    let cfg = config(1, 8192);
    let mut store = CellRetentionStoreV1::create(&path, cfg.clone()).unwrap();
    store.reserve(contract(1, &manifest)).unwrap();
    store
        .connection
        .execute("UPDATE obligations SET retain_until=1", [])
        .unwrap();
    drop(store);
    assert!(CellRetentionStoreV1::open(&path, cfg).is_err());
    let path = dir.path().join("truncated");
    let cfg = config(2, 8192);
    let store = CellRetentionStoreV1::create(&path, cfg.clone()).unwrap();
    drop(store);
    OpenOptions::new()
        .write(true)
        .open(path.join("payload.arena"))
        .unwrap()
        .set_len(4096)
        .unwrap();
    assert!(CellRetentionStoreV1::open(&path, cfg).is_err());
}

#[test]
fn retained_origin_bytes_rehydrate_existing_peer_protocol_after_cache_loss() {
    let dir = tempfile::tempdir().unwrap();
    let (origin, manifest, expected) = material(dir.path(), 37_000);
    let mut store =
        CellRetentionStoreV1::create(&dir.path().join("retention"), config(1, 40_960)).unwrap();
    store.reserve(contract(1, &manifest)).unwrap();
    store.acknowledge([1; 32], &origin, deadline()).unwrap();
    drop(origin);
    fs::remove_file(dir.path().join("cache.sqlite")).unwrap();
    fs::remove_file(dir.path().join("input")).unwrap();
    let peer_path = dir.path().join("repaired-cache.sqlite");
    let peer = CellStoreV1::open(&peer_path, cache_config()).unwrap();
    store.populate_cache([1; 32], &peer, deadline()).unwrap();
    drop(peer);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let stop = shutdown.clone();
    let limits = CellPeerLimitsV1 {
        request_timeout: Duration::from_secs(2),
        overall_timeout: Duration::from_secs(10),
        max_cell_bytes: 65_536,
        parallelism: 2,
        max_connections: 100,
        max_response_bytes: 262_144,
    };
    let server = thread::spawn(move || {
        let peer = CellStoreV1::open(&peer_path, cache_config()).unwrap();
        serve_cells(&listener, &peer, &stop, limits).unwrap()
    });
    let consumer = CellStoreV1::open(&dir.path().join("consumer.sqlite"), cache_config()).unwrap();
    let received = fetch_cell(&consumer, manifest.id(), &[address], limits);
    shutdown.store(true, Ordering::Release);
    server.join().unwrap();
    received.unwrap();
    let output = dir.path().join("downloaded.cell");
    consumer.materialize(&manifest, &output).unwrap();
    assert_eq!(fs::read(output).unwrap(), expected);
}

#[test]
fn retention_process_child() {
    let Some(path) = std::env::var_os("TRNM_RETENTION_CRASH_FIXTURE") else {
        return;
    };
    let path = PathBuf::from(path);
    let (cache, manifest, _) = material(&path, 5000);
    let mut store = CellRetentionStoreV1::create(&path.join("retention"), config(1, 8192)).unwrap();
    store.reserve(contract(1, &manifest)).unwrap();
    let mut row = store.required_row([1; 32]).unwrap();
    row.initial_bytes = row.contract.manifest.size();
    store.write_row(&row, false).unwrap();
    // The exact production copy/fsync/readback, followed by process death in
    // the publication window before acknowledge changes the durable status.
    store.copy_payload(&row, &cache, deadline()).unwrap();
    std::process::exit(91);
}

#[test]
fn real_process_death_after_payload_sync_recovers_ack_without_origin_or_new_capacity() {
    let dir = tempfile::tempdir().unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "cell::retention::tests::retention_process_child",
            "--nocapture",
        ])
        .env("TRNM_RETENTION_CRASH_FIXTURE", dir.path())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(91));
    fs::remove_file(dir.path().join("input")).unwrap();
    let empty = CellStoreV1::open(&dir.path().join("empty.sqlite"), cache_config()).unwrap();
    let path = dir.path().join("retention");
    let mut store = CellRetentionStoreV1::open(&path, config(1, 8192)).unwrap();
    assert_eq!(store.required_row([1; 32]).unwrap().status, 0);
    let recovered = store
        .reconcile_acknowledgement([1; 32], deadline())
        .unwrap();
    assert!(recovered.acknowledged);
    assert_eq!(recovered.reserved_bytes, 8192);
    assert_eq!(recovered.initial_copy_bytes_committed, 5000);
    assert_eq!(recovered.repair_bytes_committed, 0);
    assert_eq!(
        store.acknowledge([1; 32], &empty, deadline()).unwrap(),
        recovered
    );
    drop(store);
    let mut reopened = CellRetentionStoreV1::open(&path, config(1, 8192)).unwrap();
    assert_eq!(reopened.verify([1; 32], deadline()).unwrap(), recovered);
}

#[test]
fn initial_partial_copy_cannot_be_redispatched_under_the_same_obligation() {
    let dir = tempfile::tempdir().unwrap();
    let (cache, manifest, bytes) = material(dir.path(), 37_000);
    let partial = CellStoreV1::open(&dir.path().join("partial.sqlite"), cache_config()).unwrap();
    let first = &manifest.chunks()[0];
    partial
        .put_chunk(first, &bytes[..first.size as usize])
        .unwrap();
    let path = dir.path().join("retention");
    let cfg = config(1, 40_960);
    let mut store = CellRetentionStoreV1::create(&path, cfg.clone()).unwrap();
    store.reserve(contract(1, &manifest)).unwrap();
    assert!(store.acknowledge([1; 32], &partial, deadline()).is_err());
    drop(store);
    let mut store = CellRetentionStoreV1::open(&path, cfg).unwrap();
    assert!(store.acknowledge([1; 32], &cache, deadline()).is_err());
}

#[test]
fn successful_noop_repair_keeps_its_identity_after_later_target_damage() {
    let dir = tempfile::tempdir().unwrap();
    let (cache, manifest, _) = material(dir.path(), 5000);
    let path = dir.path().join("retention");
    let cfg = config(1, 8192);
    let mut store = CellRetentionStoreV1::create(&path, cfg.clone()).unwrap();
    store.reserve(contract(1, &manifest)).unwrap();
    store.acknowledge([1; 32], &cache, deadline()).unwrap();
    assert_eq!(
        store
            .repair([1; 32], [101; 32], &cache, deadline())
            .unwrap()
            .repair_bytes_committed,
        0
    );
    drop(store);
    let mut store = CellRetentionStoreV1::open(&path, cfg).unwrap();
    damage(&mut store);
    assert!(store
        .repair([1; 32], [101; 32], &cache, deadline())
        .is_err());
    assert_eq!(
        store
            .reserve(contract(1, &manifest))
            .unwrap()
            .repair_bytes_committed,
        0
    );
    assert_eq!(
        store
            .repair([1; 32], [102; 32], &cache, deadline())
            .unwrap()
            .repair_bytes_committed,
        5000
    );
}

#[test]
fn interrupted_initial_copy_keeps_full_charge_and_requires_a_separate_repair() {
    let dir = tempfile::tempdir().unwrap();
    let (cache, manifest, bytes) = material(dir.path(), 37_000);
    let partial = CellStoreV1::open(&dir.path().join("partial.sqlite"), cache_config()).unwrap();
    let first = &manifest.chunks()[0];
    partial
        .put_chunk(first, &bytes[..first.size as usize])
        .unwrap();
    let path = dir.path().join("retention");
    let cfg = config(1, 40_960);
    let mut store = CellRetentionStoreV1::create(&path, cfg.clone()).unwrap();
    let duty = contract(1, &manifest);
    store.reserve(duty.clone()).unwrap();
    assert!(store.acknowledge([1; 32], &partial, deadline()).is_err());
    let pending = store.reserve(duty.clone()).unwrap();
    assert_eq!(pending.initial_copy_bytes_committed, 37_000);
    assert_eq!(pending.repair_bytes_committed, 0);
    assert!(!pending.acknowledged);
    damage(&mut store);
    assert!(store
        .reconcile_acknowledgement([1; 32], deadline())
        .is_err());
    assert!(store
        .reconcile_repair([1; 32], [101; 32], deadline())
        .is_err());
    assert!(store.repair_row([101; 32]).unwrap().is_none());
    store.arena.seek(SeekFrom::Start(0)).unwrap();
    let mut first = [0];
    store.arena.read_exact(&mut first).unwrap();
    assert_eq!(first, [0xff]);
    drop(store);
    let mut store = CellRetentionStoreV1::open(&path, cfg).unwrap();
    assert_eq!(store.reserve(duty.clone()).unwrap(), pending);
    assert!(store.acknowledge([1; 32], &cache, deadline()).is_err());
    let recovered = store
        .repair([1; 32], [101; 32], &cache, deadline())
        .unwrap();
    assert!(recovered.acknowledged);
    assert_eq!(recovered.initial_copy_bytes_committed, 37_000);
    assert_eq!(recovered.repair_bytes_committed, 37_000);
    assert_eq!(
        store
            .reconcile_repair([1; 32], [101; 32], deadline())
            .unwrap(),
        recovered
    );
    assert_eq!(
        store
            .reconcile_acknowledgement([1; 32], deadline())
            .unwrap(),
        recovered
    );
}

#[test]
fn missing_repair_intent_can_only_reconcile_a_complete_target_and_seals_its_id() {
    let dir = tempfile::tempdir().unwrap();
    let (cache, manifest, _) = material(dir.path(), 5000);
    let path = dir.path().join("retention");
    let cfg = config(1, 8192);
    let mut store = CellRetentionStoreV1::create(&path, cfg.clone()).unwrap();
    store.reserve(contract(1, &manifest)).unwrap();
    assert!(store
        .reconcile_repair([1; 32], [101; 32], deadline())
        .is_err());
    assert!(store.repair_row([101; 32]).unwrap().is_none());
    store.acknowledge([1; 32], &cache, deadline()).unwrap();
    let unchanged = store
        .reconcile_repair([1; 32], [101; 32], deadline())
        .unwrap();
    assert_eq!(unchanged.repair_bytes_committed, 0);
    assert_eq!(
        store.repair_row([101; 32]).unwrap(),
        Some(([1; 32], 0, true))
    );
    drop(store);
    let mut store = CellRetentionStoreV1::open(&path, cfg).unwrap();
    damage(&mut store);
    assert!(store
        .repair([1; 32], [101; 32], &cache, deadline())
        .is_err());
    assert!(store
        .reconcile_repair([1; 32], [101; 32], deadline())
        .is_err());
    assert_eq!(
        store.repair_row([101; 32]).unwrap(),
        Some(([1; 32], 0, true))
    );
}

#[test]
fn contract_commitment_has_an_exact_vector_and_binds_every_immutable_term() {
    let dir = tempfile::tempdir().unwrap();
    let (_, manifest, _) = material(dir.path(), 5000);
    let mut duty = contract(1, &manifest);
    duty.retain_from_height = 2;
    duty.successor = Some(([2; 32], [3; 32]));
    // Independently derived from the fixed TCM1 bytes and fixed-width BE fields.
    assert_eq!(
        hex::encode(manifest.id()),
        "96f4a7f752bbebf383f45d51996dae950148567bd0bff8cc3c980049f601ec33"
    );
    let id = duty.commitment([1; 32]);
    assert_eq!(
        hex::encode(id),
        "36c1818c4a3f60034450f869fb067da766d5e127f445f9bedf7d30a395f05e73"
    );
    assert_ne!(duty.commitment([9; 32]), id);
    for field in 0..8 {
        let mut changed = duty.clone();
        match field {
            0 => changed.operation = [9; 32],
            1 => changed.funding_operation = [9; 32],
            2 => changed.retain_from_height = 1,
            3 => changed.retain_until_height = 11,
            4 => changed.maximum_repair_bytes = 9_999,
            5 => changed.successor = None,
            6 => changed.successor = Some(([4; 32], [3; 32])),
            _ => changed.successor = Some(([2; 32], [4; 32])),
        }
        assert_ne!(changed.commitment([1; 32]), id);
    }
    fs::create_dir(dir.path().join("other")).unwrap();
    let (_, other_manifest, _) = material(&dir.path().join("other"), 5001);
    let mut changed = duty;
    changed.manifest = other_manifest;
    assert_ne!(changed.commitment([1; 32]), id);
}

#[test]
fn immutable_service_interval_and_exact_schema_survive_reopen_without_migration() {
    let dir = tempfile::tempdir().unwrap();
    let (_, manifest, _) = material(dir.path(), 5000);
    let path = dir.path().join("retention");
    let cfg = config(1, 8192);
    let mut store = CellRetentionStoreV1::create(&path, cfg.clone()).unwrap();
    let mut duty = contract(1, &manifest);
    duty.retain_from_height = 10;
    assert!(store.reserve(duty.clone()).is_err());
    duty.retain_from_height = 2;
    store.reserve(duty.clone()).unwrap();
    assert_eq!(store.store_id(), [1; 32]);
    assert_eq!(store.contract(duty.operation).unwrap(), duty);
    let mut changed = duty.clone();
    changed.retain_from_height = 3;
    assert!(store.reserve(changed).is_err());
    drop(store);
    let store = CellRetentionStoreV1::open(&path, cfg.clone()).unwrap();
    assert_eq!(store.contract(duty.operation).unwrap(), duty);
    drop(store);
    let connection = Connection::open(path.join("retention.sqlite")).unwrap();
    connection
        .execute_batch("ALTER TABLE obligations ADD COLUMN old_layout INTEGER")
        .unwrap();
    drop(connection);
    assert!(CellRetentionStoreV1::open(&path, cfg).is_err());
}

#[test]
fn successor_future_service_window_cannot_release_current_bytes_early() {
    let dir = tempfile::tempdir().unwrap();
    let (cache, manifest, _) = material(dir.path(), 5000);
    let mut first =
        CellRetentionStoreV1::create(&dir.path().join("first"), config(1, 8192)).unwrap();
    let mut next = CellRetentionStoreV1::create(&dir.path().join("next"), config(2, 8192)).unwrap();
    let mut duty = contract(1, &manifest);
    duty.successor = Some(([2; 32], [2; 32]));
    first.reserve(duty.clone()).unwrap();
    first.acknowledge([1; 32], &cache, deadline()).unwrap();
    let mut continuation = contract(2, &manifest);
    continuation.retain_from_height = 11;
    continuation.retain_until_height = 30;
    next.reserve(continuation).unwrap();
    next.acknowledge([2; 32], &cache, deadline()).unwrap();
    // A branch can return below the successor's service start while both local
    // physical receipts remain. The earlier duty must still cover the gap.
    assert!(first
        .retire([1; 32], 10, Some(&mut next), deadline())
        .is_err());
    assert!(!first.reserve(duty).unwrap().retired);
    assert!(
        first
            .retire([1; 32], 11, Some(&mut next), deadline())
            .unwrap()
            .retired
    );
}

#[cfg(target_os = "linux")]
fn actual_thread_cpu_ns() -> CellResultV1<u64> {
    use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
    let stamp = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ThreadCPUTime))
        .map_err(|_| CellErrorV1::Invalid("retention test CPU clock unavailable"))?;
    let seconds = u64::try_from(stamp.tv_sec)
        .map_err(|_| CellErrorV1::Invalid("retention test CPU clock"))?;
    let nanos = u64::try_from(stamp.tv_nsec)
        .map_err(|_| CellErrorV1::Invalid("retention test CPU clock"))?;
    require(nanos < 1_000_000_000, "retention test CPU clock")?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(nanos))
        .ok_or(CellErrorV1::Invalid("retention test CPU clock"))
}

#[cfg(target_os = "linux")]
struct ActualCpuLimit {
    owner: std::thread::ThreadId,
    start: u64,
    limit: u64,
    observed: u64,
    checks: u64,
}
#[cfg(target_os = "linux")]
impl ActualCpuLimit {
    fn new(limit: u64) -> Self {
        Self {
            owner: std::thread::current().id(),
            start: actual_thread_cpu_ns().unwrap(),
            limit,
            observed: 0,
            checks: 0,
        }
    }
    fn check(&mut self) -> CellResultV1<()> {
        require(
            std::thread::current().id() == self.owner,
            "retention test CPU thread changed",
        )?;
        self.observed = actual_thread_cpu_ns()?
            .checked_sub(self.start)
            .ok_or(CellErrorV1::Invalid("retention test CPU clock regressed"))?;
        self.checks += 1;
        require(self.observed <= self.limit, "retention test CPU exhausted")
    }
}

#[test]
#[cfg(target_os = "linux")]
fn actual_thread_cpu_stops_large_repair_before_completion_and_never_redispatches_its_id() {
    let dir = tempfile::tempdir().unwrap();
    let (cache, manifest, _) = material(dir.path(), 8 * 1024 * 1024);
    let path = dir.path().join("retention");
    let cfg = config(1, manifest.size());
    let mut store = CellRetentionStoreV1::create(&path, cfg.clone()).unwrap();
    let mut duty = contract(1, &manifest);
    duty.maximum_repair_bytes = manifest.size() * 3;
    store.reserve(duty.clone()).unwrap();
    store.acknowledge([1; 32], &cache, deadline()).unwrap();
    damage(&mut store);
    // The one-nanosecond limit is an actual clock admission refusal, not a
    // mocked counter. It must not create a write intent or invent a zero cost.
    let mut tiny = ActualCpuLimit::new(1);
    let error = store
        .repair_controlled([1; 32], [100; 32], &cache, deadline(), &mut || tiny.check())
        .unwrap_err();
    assert!(error.to_string().contains("CPU exhausted"));
    assert!(tiny.observed > tiny.limit);
    assert!(store.repair_row([100; 32]).unwrap().is_none());
    // Measure the real complete operation once, then use one quarter of that
    // CPU allowance on the same bytes. This is independent of scheduler wall
    // stalls and proves checks interrupt work before the completion journal.
    let mut full = ActualCpuLimit::new(5_000_000_000);
    store
        .repair_controlled([1; 32], [101; 32], &cache, deadline(), &mut || full.check())
        .unwrap();
    assert!(full.observed > 0 && full.checks > manifest.chunks().len() as u64 * 4);
    damage(&mut store);
    let mut limited = ActualCpuLimit::new((full.observed / 4).max(1));
    let error = store
        .repair_controlled([1; 32], [102; 32], &cache, deadline(), &mut || {
            limited.check()
        })
        .unwrap_err();
    assert!(error.to_string().contains("CPU exhausted"));
    assert!(limited.observed > limited.limit);
    assert_eq!(
        store.repair_row([102; 32]).unwrap(),
        Some(([1; 32], manifest.size(), false))
    );
    assert_eq!(
        store.reserve(duty.clone()).unwrap().repair_bytes_committed,
        manifest.size() * 2
    );
    eprintln!(
        "actual retention repair CPU: complete={}ns limited={}ns observed={}ns checks={}",
        full.observed, limited.limit, limited.observed, limited.checks
    );
    // Force a target mismatch after the unknown attempt: a retry may verify
    // that mismatch but cannot write even though a new CPU allowance is ample.
    damage(&mut store);
    drop(store);
    let mut store = CellRetentionStoreV1::open(&path, cfg).unwrap();
    let mut retry = ActualCpuLimit::new(5_000_000_000);
    assert!(store
        .repair_controlled([1; 32], [102; 32], &cache, deadline(), &mut || retry
            .check())
        .is_err());
    store.arena.seek(SeekFrom::Start(0)).unwrap();
    let mut first = [0];
    store.arena.read_exact(&mut first).unwrap();
    assert_eq!(first, [0xff]);
    assert_eq!(
        store.reserve(duty).unwrap().repair_bytes_committed,
        manifest.size() * 2
    );
    let mut final_budget = ActualCpuLimit::new(5_000_000_000);
    let restored = store
        .repair_controlled([1; 32], [103; 32], &cache, deadline(), &mut || {
            final_budget.check()
        })
        .unwrap();
    assert!(restored.acknowledged);
    assert_eq!(restored.repair_bytes_committed, manifest.size() * 3);
    let mut tiny = ActualCpuLimit::new(1);
    assert!(store
        .reconcile_repair_controlled([1; 32], [103; 32], deadline(), &mut || tiny.check())
        .is_err());
    let mut enough = ActualCpuLimit::new(5_000_000_000);
    assert_eq!(
        store
            .reconcile_repair_controlled([1; 32], [103; 32], deadline(), &mut || enough.check())
            .unwrap(),
        restored
    );
}

#[test]
fn rejected_control_is_sticky_and_absolute_deadline_precedes_any_copy_intent() {
    let dir = tempfile::tempdir().unwrap();
    let (cache, manifest, _) = material(dir.path(), 37_000);
    let mut store =
        CellRetentionStoreV1::create(&dir.path().join("retention"), config(1, 40_960)).unwrap();
    let duty = contract(1, &manifest);
    store.reserve(duty.clone()).unwrap();
    let mut calls = 0;
    let mut check = || {
        calls += 1;
        Err(CellErrorV1::Invalid("intentional checkpoint refusal"))
    };
    assert!(store
        .repair_controlled([1; 32], [101; 32], &cache, deadline(), &mut check)
        .is_err());
    assert_eq!(calls, 1);
    assert!(store.repair_row([101; 32]).unwrap().is_none());
    let mut calls = 0;
    let mut check = || {
        calls += 1;
        Ok(())
    };
    assert!(store
        .repair_controlled(
            [1; 32],
            [101; 32],
            &cache,
            Instant::now() - Duration::from_secs(1),
            &mut check
        )
        .is_err());
    assert_eq!(calls, 0);
    assert!(store.repair_row([101; 32]).unwrap().is_none());
    let mut calls = 0;
    let mut refuse_once = || {
        calls += 1;
        if calls == 1 {
            Err(CellErrorV1::Invalid("one rejected checkpoint"))
        } else {
            Ok(())
        }
    };
    {
        let mut control = OperationControl {
            deadline: deadline(),
            checkpoint: &mut refuse_once,
            stopped: false,
        };
        assert!(control.check().is_err());
        assert!(control.check().is_err());
        assert!(control.stopped);
    }
    assert_eq!(calls, 1);
    assert_eq!(store.reserve(duty).unwrap().repair_bytes_committed, 0);
}

#[test]
fn repair_intent_and_charge_must_survive_sqlite_suppression_before_payload() {
    // Native SQLite suppression/corruption after open's schema audit. Both a
    // reported zero-row write and an AFTER trigger that reports one changed
    // row must be caught before the first physical payload write. These are
    // write-boundary fault injections, not a claim to resist full-host rollback.
    for (case, sql) in [
        ("suppressed intent", "CREATE TRIGGER omit_repair BEFORE INSERT ON repairs BEGIN SELECT RAISE(IGNORE); END;"),
        ("suppressed charge", "CREATE TRIGGER omit_charge BEFORE UPDATE OF repair_bytes ON obligations BEGIN SELECT RAISE(IGNORE); END;"),
        ("erased intent", "CREATE TRIGGER erase_repair AFTER INSERT ON repairs BEGIN DELETE FROM repairs WHERE operation=NEW.operation; END;"),
        ("rewound charge", "CREATE TRIGGER rewind_charge AFTER UPDATE OF repair_bytes ON obligations WHEN NEW.repair_bytes>OLD.repair_bytes BEGIN UPDATE obligations SET repair_bytes=OLD.repair_bytes,checksum=OLD.checksum WHERE operation=NEW.operation; END;"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (cache, manifest, _) = material(dir.path(), 5000);
        let path = dir.path().join("retention");
        let mut store = CellRetentionStoreV1::create(&path, config(1, 8192)).unwrap();
        store.reserve(contract(1, &manifest)).unwrap();
        store.acknowledge([1; 32], &cache, deadline()).unwrap();
        damage(&mut store);
        let before = fs::read(path.join("payload.arena")).unwrap();
        store.connection.execute_batch(sql).unwrap();
        let result = store.repair_controlled(
            [1; 32], [101; 32], &cache, deadline(), &mut || Ok(()),
        );
        assert!(result.is_err(), "{case}: unsealed repair must be refused");
        assert_eq!(fs::read(path.join("payload.arena")).unwrap(), before,
            "{case}: payload changed before a real durable intent and charge");
        assert_eq!(store.required_row([1; 32]).unwrap().repair_bytes, 0,
            "{case}: failed pre-copy transaction must roll back");
        assert!(store.repair_row([101; 32]).unwrap().is_none(),
            "{case}: failed pre-copy transaction must roll back");
    }
}

#[test]
fn repair_completion_refuses_a_schema_change_after_payload_and_keeps_full_charge() {
    let dir = tempfile::tempdir().unwrap();
    let (cache, manifest, bytes) = material(dir.path(), 5000);
    let path = dir.path().join("retention");
    let mut store = CellRetentionStoreV1::create(&path, config(1, 8192)).unwrap();
    store.reserve(contract(1, &manifest)).unwrap();
    store.acknowledge([1; 32], &cache, deadline()).unwrap();
    damage(&mut store);
    let foreign = Connection::open(path.join("retention.sqlite")).unwrap();
    let mut injected = false;
    let mut checkpoint = || {
        if !injected && fs::read(path.join("payload.arena"))?[..bytes.len()] == bytes {
            // The original intent/charge is already durable and actual bytes
            // have been written. Introduce a completion-rewinding trigger before
            // the completion boundary, using a real second SQLite connection.
            foreign.execute_batch("CREATE TRIGGER rewind_completion AFTER UPDATE OF complete ON repairs WHEN NEW.complete=1 BEGIN UPDATE repairs SET complete=OLD.complete,checksum=OLD.checksum WHERE operation=NEW.operation; END;")?;
            injected = true;
        }
        Ok(())
    };
    let result = store.repair_controlled([1; 32], [101; 32], &cache, deadline(), &mut checkpoint);
    assert!(injected);
    assert!(
        result.is_err(),
        "schema-changed completion cannot manufacture a durable ACK"
    );
    assert_eq!(
        store.repair_row([101; 32]).unwrap(),
        Some(([1; 32], manifest.size(), false))
    );
    assert_eq!(
        store.required_row([1; 32]).unwrap().repair_bytes,
        manifest.size()
    );
    assert_eq!(
        &fs::read(path.join("payload.arena")).unwrap()[..bytes.len()],
        bytes.as_slice()
    );
}

#[test]
fn expired_absolute_retirement_deadline_cannot_release_a_slot_without_a_successor() {
    let dir = tempfile::tempdir().unwrap();
    let (cache, manifest, _) = material(dir.path(), 5000);
    let mut store =
        CellRetentionStoreV1::create(&dir.path().join("retention"), config(1, 8192)).unwrap();
    let duty = contract(1, &manifest);
    store.reserve(duty.clone()).unwrap();
    let before = store.acknowledge([1; 32], &cache, deadline()).unwrap();
    assert!(store
        .retire(
            [1; 32],
            duty.retain_until_height,
            None,
            Instant::now() - Duration::from_secs(1)
        )
        .is_err());
    assert_eq!(store.reserve(duty).unwrap(), before);
    assert!(store.reserve(contract(2, &manifest)).is_err());
    // The ordinary verified-height rule still permits a separately requested,
    // in-deadline retirement; it is not weakened by the wall-clock fence.
    assert!(store.retire([1; 32], 10, None, deadline()).unwrap().retired);
}

#[test]
fn sqlite_like_wildcard_cannot_hide_a_user_trigger_at_repair_or_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let (cache, manifest, _) = material(dir.path(), 5000);
    let path = dir.path().join("retention");
    let cfg = config(1, 8192);
    let mut store = CellRetentionStoreV1::create(&path, cfg.clone()).unwrap();
    store.reserve(contract(1, &manifest)).unwrap();
    store.acknowledge([1; 32], &cache, deadline()).unwrap();
    damage(&mut store);
    let before = fs::read(path.join("payload.arena")).unwrap();
    // SQLite permits this user name. LIKE's underscore wildcard must not
    // classify it as an internal sqlite_* object and bypass the schema fence.
    store
        .connection
        .execute_batch(
            "CREATE TRIGGER sqliteX_hidden_repair AFTER INSERT ON repairs BEGIN SELECT 1; END;",
        )
        .unwrap();
    let live_rejected = store
        .repair_controlled([1; 32], [101; 32], &cache, deadline(), &mut || Ok(()))
        .is_err();
    let payload_unchanged = fs::read(path.join("payload.arena")).unwrap() == before;
    drop(store);
    let cold_rejected = CellRetentionStoreV1::open(&path, cfg).is_err();
    assert!(live_rejected && payload_unchanged && cold_rejected,
        "noninternal trigger bypass: live_rejected={live_rejected}, payload_unchanged={payload_unchanged}, cold_rejected={cold_rejected}");
}

// Explicit finite fixture quota; covers the existing <=32MiB commit fixtures.
fn cache_config() -> crate::cell::CellCacheConfigV2 {
    crate::cell::CellCacheConfigV2 {
        max_logical_bytes: 64 * 1024 * 1024,
        max_chunk_rows: 4096,
        max_manifest_rows: 256,
    }
}
