use super::*;
use trnm_data_availability::cell::{CellCacheConfigV2, CellErrorV1};

#[test]
fn cache_deletion_and_cache_quota_failure_cannot_release_actual_paid_retention() {
    let directory = tempfile::tempdir().unwrap();
    let mut node = open_node(
        &directory.path().join("node"),
        StateBackend::PermanentAccountGrowthV2,
    );
    let source = fund(&mut node, 1, 1000);
    let (cache, manifest, _) = material(directory.path());
    let request = request(source, &manifest);
    let mut budgets =
        NativeBudgetStoreV1::open(&directory.path().join("budget.sqlite"), config(&node)).unwrap();
    let mut retained =
        CellRetentionStoreV1::create(&directory.path().join("retention"), retention_config())
            .unwrap();
    let original = node
        .retain_native_cell(
            &mut budgets,
            &mut retained,
            &cache,
            request.clone(),
            deadline(),
        )
        .unwrap();
    let paid_before = budgets.report().unwrap();
    let funding_before = node.native_funding_observation(source).unwrap();
    let obligation_before = retained.contract(request.contract.operation).unwrap();
    let cache_before = cache.cache_usage().unwrap();
    let db = rusqlite::Connection::open(directory.path().join("cache.sqlite")).unwrap();
    for chunk in manifest.chunks() {
        // Mutate only this owned cache fixture, then execute its real corrupt
        // read/delete path. The separate paid retention arena is never touched.
        db.execute(
            "UPDATE cell_chunks_v1 SET bytes=?1 WHERE hash=?2",
            rusqlite::params![vec![0xff_u8; chunk.size as usize], chunk.sha256.as_slice()],
        )
        .unwrap();
        assert!(cache.chunk(chunk.sha256).unwrap().is_none());
    }
    let after_delete = cache.cache_usage().unwrap();
    assert_eq!(after_delete.chunk_rows, 0);
    assert_eq!(
        cache_before.logical_bytes - after_delete.logical_bytes,
        manifest.size() + 32 * manifest.chunks().len() as u64
    );
    let blocked = CellStoreV1::open(
        &directory.path().join("blocked.sqlite"),
        CellCacheConfigV2 {
            max_logical_bytes: 1,
            max_chunk_rows: 1,
            max_manifest_rows: 1,
        },
    )
    .unwrap();
    assert!(matches!(
        retained.populate_cache(request.contract.operation, &blocked, deadline()),
        Err(CellErrorV1::CacheQuotaExceeded)
    ));
    assert_eq!(blocked.cache_usage().unwrap().logical_bytes, 0);
    assert_eq!(
        retained
            .verify(request.contract.operation, deadline())
            .unwrap(),
        original.target
    );
    assert_eq!(
        retained.contract(request.contract.operation).unwrap(),
        obligation_before
    );
    assert_eq!(budgets.report().unwrap(), paid_before);
    let funding_after = node.native_funding_observation(source).unwrap();
    assert_eq!(funding_after.anchor, funding_before.anchor);
    assert_eq!(funding_after.source, funding_before.source);
    assert_eq!(funding_after.row, funding_before.row);
    let replay = node
        .retain_native_cell(&mut budgets, &mut retained, &cache, request, deadline())
        .unwrap();
    assert_eq!(replay.replay, NativeBudgetReplayV1::Done);
    assert_eq!(replay.target, original.target);
    assert_eq!(budgets.report().unwrap(), paid_before);
}
