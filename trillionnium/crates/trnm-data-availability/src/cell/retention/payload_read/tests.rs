use std::time::Duration;

use super::*;
use crate::cell::{CellCacheConfigV4, CellContextV1};

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

fn fixture(
    directory: &Path,
) -> (
    CellRetentionStoreV1,
    CellStoreV1,
    CellRetentionContractV1,
    Vec<u8>,
) {
    let bytes = (0..50_017)
        .map(|n| ((n * 19 + 23) % 251) as u8)
        .collect::<Vec<_>>();
    let input = directory.join("input.bin");
    fs::write(&input, &bytes).unwrap();
    let cache = CellStoreV1::open(
        &directory.join("cache.sqlite"),
        CellCacheConfigV4 {
            max_database_bytes: 16 * 1024 * 1024,
            max_logical_bytes: 4 * 1024 * 1024,
            max_chunk_rows: 64,
            max_manifest_rows: 16,
        },
    )
    .unwrap();
    let manifest = cache
        .pack_file(
            &input,
            CellContextV1 {
                family: "retained-read-native-v1".into(),
                base: [1; 32],
                parent: [2; 32],
                tokenizer: [3; 32],
                layout: [4; 32],
                runtime: [5; 32],
            },
            16_384,
        )
        .unwrap();
    let contract = CellRetentionContractV1 {
        operation: [9; 32],
        funding_operation: [10; 32],
        manifest,
        retain_from_height: 0,
        retain_until_height: 10,
        maximum_repair_bytes: bytes.len() as u64,
        successor: None,
    };
    let mut arena = CellRetentionStoreV1::create(
        &directory.join("retained"),
        CellRetentionConfigV1 {
            store_id: [11; 32],
            capacity_bytes: 65_536,
            maximum_obligations: 16,
        },
    )
    .unwrap();
    arena.reserve_until(contract.clone(), deadline()).unwrap();
    (arena, cache, contract, bytes)
}

#[test]
fn bounded_arena_read_returns_exact_multichunk_bytes_without_cache_or_debit_changes() {
    let dir = tempfile::tempdir().unwrap();
    let (mut arena, cache, contract, bytes) = fixture(dir.path());
    let initial = arena
        .acknowledge(contract.operation, &cache, deadline())
        .unwrap();
    drop(cache);
    fs::remove_file(dir.path().join("cache.sqlite")).unwrap();
    let actual = arena
        .read_payload_controlled(
            contract.operation,
            bytes.len() as u64,
            deadline(),
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(actual, bytes);
    assert_eq!(
        arena.verify(contract.operation, deadline()).unwrap(),
        initial
    );
}

#[test]
fn bounded_arena_read_refuses_pending_retired_and_missing_obligations() {
    let dir = tempfile::tempdir().unwrap();
    let (mut arena, cache, contract, bytes) = fixture(dir.path());
    assert!(arena
        .read_payload_controlled(
            contract.operation,
            bytes.len() as u64,
            deadline(),
            &mut || Ok(())
        )
        .is_err());
    assert!(arena
        .read_payload_controlled([99; 32], bytes.len() as u64, deadline(), &mut || Ok(()))
        .is_err());
    arena
        .acknowledge(contract.operation, &cache, deadline())
        .unwrap();
    arena
        .retire(contract.operation, 10, None, deadline())
        .unwrap();
    assert!(arena
        .read_payload_controlled(
            contract.operation,
            bytes.len() as u64,
            deadline(),
            &mut || Ok(())
        )
        .is_err());
}

#[test]
fn bounded_arena_read_enforces_allocation_and_original_deadline_without_recharging() {
    let dir = tempfile::tempdir().unwrap();
    let (mut arena, cache, contract, bytes) = fixture(dir.path());
    let initial = arena
        .acknowledge(contract.operation, &cache, deadline())
        .unwrap();
    assert!(matches!(
        arena.read_payload_controlled(
            contract.operation,
            bytes.len() as u64 - 1,
            deadline(),
            &mut || Ok(())
        ),
        Err(CellErrorV1::Invalid("retention read allocation limit"))
    ));
    let mut called = false;
    assert!(arena
        .read_payload_controlled(
            contract.operation,
            bytes.len() as u64,
            Instant::now() - Duration::from_secs(1),
            &mut || {
                called = true;
                Ok(())
            }
        )
        .is_err());
    assert!(!called);
    assert_eq!(
        arena.verify(contract.operation, deadline()).unwrap(),
        initial
    );
}

#[test]
fn bounded_arena_read_checks_actual_late_chunk_and_cannot_substitute_cache_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let (mut arena, cache, contract, bytes) = fixture(dir.path());
    arena
        .acknowledge(contract.operation, &cache, deadline())
        .unwrap();
    arena.arena.seek(SeekFrom::Start(32_768)).unwrap();
    arena.arena.write_all(&[0xff]).unwrap();
    arena.arena.sync_all().unwrap();
    cache.verify_complete(&contract.manifest).unwrap();
    assert!(arena
        .read_payload_controlled(
            contract.operation,
            bytes.len() as u64,
            deadline(),
            &mut || Ok(())
        )
        .is_err());
    let row = arena.required_row(contract.operation).unwrap();
    assert_eq!(row.initial_bytes, bytes.len() as u64);
    assert_eq!(row.repair_bytes, 0);
}

#[test]
fn bounded_arena_read_cancellation_is_not_swallowed_as_corruption_or_repair_permission() {
    let dir = tempfile::tempdir().unwrap();
    let (mut arena, cache, contract, bytes) = fixture(dir.path());
    let initial = arena
        .acknowledge(contract.operation, &cache, deadline())
        .unwrap();
    let mut count = 0;
    let result = arena.read_payload_controlled(
        contract.operation,
        bytes.len() as u64,
        deadline(),
        &mut || {
            count += 1;
            Err(CellErrorV1::Invalid("reader owner cancellation"))
        },
    );
    assert!(matches!(
        result,
        Err(CellErrorV1::Invalid("reader owner cancellation"))
    ));
    assert_eq!(count, 1);
    assert_eq!(
        arena.verify(contract.operation, deadline()).unwrap(),
        initial
    );
}

#[cfg(unix)]
#[test]
fn bounded_arena_read_refuses_replaced_path_even_when_old_fd_has_valid_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let (mut arena, cache, contract, bytes) = fixture(dir.path());
    arena
        .acknowledge(contract.operation, &cache, deadline())
        .unwrap();
    let path = dir.path().join("retained/payload.arena");
    let previous = dir.path().join("retained/original.arena");
    fs::rename(&path, &previous).unwrap();
    let replacement = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    FileExt::allocate(&replacement, 65_536).unwrap();
    replacement.set_len(65_536).unwrap();
    replacement.sync_all().unwrap();
    assert!(matches!(
        arena.read_payload_controlled(
            contract.operation,
            bytes.len() as u64,
            deadline(),
            &mut || Ok(())
        ),
        Err(CellErrorV1::Invalid("retention arena identity"))
    ));
    assert_eq!(fs::read(&previous).unwrap()[..bytes.len()], bytes);
}
