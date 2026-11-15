//! CRR2 pages share the original full TCA3 version and funding contract.

use super::*;
use crate::cell::{
    CellPagedRetainedShardPlanFileV2, CellPagedRetainedShardPlanRequestV2,
    CellPagedRetainedShardPlanV2, CellRetainedShardPageV2, MAX_CELL_PAGED_RETAINED_CHUNKS_V2,
    MAX_CELL_RETAINED_SHARD_ROOT_BYTES_V2,
};

fn paged_request(
    catalog: &CellVersionRetentionStoreV3,
    chunks: usize,
    width: u16,
) -> CellPagedRetainedShardPlanRequestV2 {
    let base = request(catalog, chunks);
    let mut providers = base.providers;
    for provider in &mut providers {
        provider.capacity_bytes = 2 * 1024 * 1024;
        provider.maximum_obligations = 256;
    }
    CellPagedRetainedShardPlanRequestV2 {
        operation: base.operation,
        expected_catalog: base.expected_catalog,
        current_height: base.current_height,
        required_until_height: base.required_until_height,
        providers,
        funding_operations: base.funding_operations,
        maximum_repairs_per_slot: base.maximum_repairs_per_slot,
        chunks_per_page: width,
    }
}

#[test]
fn paged_shard_root_crosses_128_with_shared_version_and_page_local_source_staging() {
    assert_eq!(MAX_CELL_RETAINED_SHARD_CHUNKS_V1, 128);
    assert_eq!(MAX_CELL_PAGED_RETAINED_CHUNKS_V2, 4096);
    let dir = tempfile::tempdir().unwrap();
    let source_path = dir.path().join("source.sqlite");
    let source = capacity_cache(&source_path);
    let contract = complete_contract(&source, 128);
    let catalog_path = dir.path().join("catalog");
    let config = config(1024);
    let mut catalog = CellVersionRetentionStoreV3::create(&catalog_path, config.clone()).unwrap();
    acknowledge(&mut catalog, &contract, &source);
    let anchor = catalog.anchor(deadline()).unwrap();
    let before = catalog.inventory(11, deadline()).unwrap().usage;
    drop(source);
    fs::remove_file(source_path).unwrap();
    let output = dir.path().join("paged");
    let prepared = paged_request(&catalog, 129, 128);
    let owner =
        CellPagedRetainedShardPlanFileV2::create(&output, &mut catalog, prepared, deadline())
            .unwrap();
    assert_eq!(owner.plan().page_count(), 2);
    assert_eq!(owner.plan().chunk_count(), 129);
    assert_eq!(owner.plan().roots().len(), 1);
    assert_eq!(
        owner.plan().roots()[0].version(),
        contract.version.commitment()
    );
    assert_eq!(owner.plan().catalog_anchor(), anchor);
    assert_eq!(owner.plan().pages()[0].start_chunk(), 0);
    assert_eq!(owner.plan().pages()[0].chunk_count(), 128);
    assert_eq!(owner.plan().pages()[1].start_chunk(), 128);
    assert_eq!(owner.plan().pages()[1].chunk_count(), 1);
    assert!(owner.plan().encode().len() <= MAX_CELL_RETAINED_SHARD_ROOT_BYTES_V2);
    let pin = owner.commitment();
    drop(owner);
    drop(catalog);
    let owner = CellPagedRetainedShardPlanFileV2::open(&output, pin, deadline()).unwrap();
    let mut catalog = CellVersionRetentionStoreV3::open(&catalog_path, config, anchor).unwrap();
    let staging = CellStoreV1::open(
        &dir.path().join("six-only.sqlite"),
        CellCacheConfigV4 {
            max_database_bytes: 16 << 20,
            max_logical_bytes: 1 << 20,
            max_chunk_rows: 6,
            max_manifest_rows: 6,
        },
    )
    .unwrap();
    assert_eq!(staging.cache_usage().unwrap().chunk_rows, 0);
    owner
        .stage_chunk_from_catalog(1, 0, &mut catalog, &staging, 11, deadline())
        .unwrap();
    let last = owner.read_page(1, deadline()).unwrap();
    assert_eq!(last.chunks().len(), 1);
    for slot in last.chunks()[0].slots() {
        staging.verify_complete(slot.manifest()).unwrap();
    }
    assert_eq!(staging.cache_usage().unwrap().chunk_rows, 6);
    assert_eq!(staging.cache_usage().unwrap().manifest_rows, 6);
    assert_eq!(catalog.inventory(11, deadline()).unwrap().usage, before);
    assert_eq!(catalog.anchor(deadline()).unwrap(), anchor);
    assert_eq!(
        owner.read_current(&catalog, 11, deadline()).unwrap(),
        *owner.plan()
    );
}

#[test]
fn paged_shard_global_funding_and_capacity_are_checked_before_directory_creation() {
    let dir = tempfile::tempdir().unwrap();
    let source = cache(&dir.path().join("source.sqlite"));
    let contract = make_contract(&source, 1);
    let mut catalog =
        CellVersionRetentionStoreV3::create(&dir.path().join("catalog"), config(16)).unwrap();
    acknowledge(&mut catalog, &contract, &source);
    let mut cases = Vec::new();
    let mut cross_page = paged_request(&catalog, 2, 1);
    cross_page.funding_operations[1][5] = cross_page.funding_operations[0][0];
    cases.push(cross_page);
    let mut original = paged_request(&catalog, 2, 1);
    original.funding_operations[1][0] = contract.objects[0].operation;
    cases.push(original);
    let mut omitted = paged_request(&catalog, 2, 1);
    omitted.funding_operations.pop();
    cases.push(omitted);
    let mut history = paged_request(&catalog, 2, 1);
    history.providers[5].maximum_obligations = 1;
    cases.push(history);
    let mut capacity = paged_request(&catalog, 2, 1);
    capacity.providers[5].capacity_bytes = 4096;
    cases.push(capacity);
    let mut no_page = paged_request(&catalog, 2, 1);
    no_page.chunks_per_page = 0;
    cases.push(no_page);
    let mut oversized_page = paged_request(&catalog, 2, 1);
    oversized_page.chunks_per_page = 129;
    cases.push(oversized_page);
    let before = catalog.inventory(11, deadline()).unwrap().usage;
    for (index, prepared) in cases.into_iter().enumerate() {
        let output = dir.path().join(format!("refused-{index}"));
        assert!(CellPagedRetainedShardPlanFileV2::create(
            &output,
            &mut catalog,
            prepared,
            deadline()
        )
        .is_err());
        assert!(!output.exists());
    }
    assert_eq!(catalog.inventory(11, deadline()).unwrap().usage, before);
}

#[test]
fn paged_shard_missing_last_page_cannot_reopen_or_yield_current_coverage() {
    let dir = tempfile::tempdir().unwrap();
    let source = cache(&dir.path().join("source.sqlite"));
    let contract = make_contract(&source, 1);
    let mut catalog =
        CellVersionRetentionStoreV3::create(&dir.path().join("catalog"), config(16)).unwrap();
    acknowledge(&mut catalog, &contract, &source);
    let output = dir.path().join("paged");
    let prepared = paged_request(&catalog, 2, 1);
    let owner =
        CellPagedRetainedShardPlanFileV2::create(&output, &mut catalog, prepared, deadline())
            .unwrap();
    let original = owner.plan().encode();
    let pin = owner.commitment();
    fs::remove_file(output.join("page-00001.crg2")).unwrap();
    assert!(owner.read_page(0, deadline()).is_err());
    assert!(owner.read_current(&catalog, 11, deadline()).is_err());
    drop(owner);
    assert!(CellPagedRetainedShardPlanFileV2::open(&output, pin, deadline()).is_err());
    assert_eq!(fs::read(output.join("root.crr2")).unwrap(), original);
    assert!(
        catalog
            .verify_version(contract.operation, deadline())
            .unwrap()
            .acknowledged
    );
}

#[test]
fn paged_shard_current_catalog_changes_refuse_completion_but_preserve_original_page_identities() {
    let dir = tempfile::tempdir().unwrap();
    let source = cache(&dir.path().join("source.sqlite"));
    let contract = make_contract(&source, 1);
    let mut catalog =
        CellVersionRetentionStoreV3::create(&dir.path().join("catalog"), config(32)).unwrap();
    acknowledge(&mut catalog, &contract, &source);
    let prepared = paged_request(&catalog, 2, 1);
    let owner = CellPagedRetainedShardPlanFileV2::create(
        &dir.path().join("paged"),
        &mut catalog,
        prepared,
        deadline(),
    )
    .unwrap();
    let original_page = owner.read_page(1, deadline()).unwrap();
    assert!(owner.read_current(&catalog, 90, deadline()).is_err());
    let next = make_contract(&source, 2);
    catalog
        .reserve_version(next, catalog.anchor(deadline()).unwrap(), deadline())
        .unwrap();
    assert!(owner.read_current(&catalog, 11, deadline()).is_err());
    assert_eq!(owner.read_page(1, deadline()).unwrap(), original_page);
    assert_eq!(
        original_page.chunks()[0].slots()[0]
            .owner()
            .original_operation,
        owner.plan().operation()
    );
}

#[test]
fn paged_shard_root_page_namespaces_pins_and_range_selection_remain_distinct() {
    let dir = tempfile::tempdir().unwrap();
    let source = cache(&dir.path().join("source.sqlite"));
    let contract = make_contract(&source, 1);
    let mut catalog =
        CellVersionRetentionStoreV3::create(&dir.path().join("catalog"), config(16)).unwrap();
    acknowledge(&mut catalog, &contract, &source);
    let prepared = paged_request(&catalog, 2, 1);
    let owner = CellPagedRetainedShardPlanFileV2::create(
        &dir.path().join("paged"),
        &mut catalog,
        prepared,
        deadline(),
    )
    .unwrap();
    let root = owner.plan();
    let wire = root.encode();
    assert_eq!(&wire[..4], b"CRR2");
    assert_eq!(
        CellPagedRetainedShardPlanV2::decode_pinned(&wire, owner.commitment(), deadline()).unwrap(),
        *root
    );
    assert!(CellPagedRetainedShardPlanV2::decode_pinned(&wire, [8; 32], deadline()).is_err());
    assert!(CellRetainedShardPlanV1::decode_pinned(&wire, owner.commitment(), deadline()).is_err());
    let page = owner.read_page(0, deadline()).unwrap();
    let page_wire = page.encode();
    assert_eq!(&page_wire[..4], b"CRG2");
    assert_eq!(
        CellRetainedShardPageV2::decode_pinned(&page_wire, root, 0, deadline()).unwrap(),
        page
    );
    assert!(CellRetainedShardPageV2::decode_pinned(&page_wire, root, 1, deadline()).is_err());
    assert!(owner.read_page(2, deadline()).is_err());
    assert!(owner
        .stage_chunk_from_catalog(0, 1, &mut catalog, &source, 11, deadline())
        .is_err());
    let duplicate = paged_request(&catalog, 2, 1);
    assert!(CellPagedRetainedShardPlanFileV2::create(
        &dir.path().join("paged"),
        &mut catalog,
        duplicate,
        deadline()
    )
    .is_err());
    assert_eq!(owner.read(deadline()).unwrap(), *root);
}

#[cfg(unix)]
#[test]
fn paged_shard_live_owner_checks_page_file_identity_before_returning_its_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let source = cache(&dir.path().join("source.sqlite"));
    let contract = make_contract(&source, 1);
    let mut catalog =
        CellVersionRetentionStoreV3::create(&dir.path().join("catalog"), config(16)).unwrap();
    acknowledge(&mut catalog, &contract, &source);
    let prepared = paged_request(&catalog, 2, 1);
    let output = dir.path().join("paged");
    let owner =
        CellPagedRetainedShardPlanFileV2::create(&output, &mut catalog, prepared, deadline())
            .unwrap();
    let page = owner.read_page(1, deadline()).unwrap();
    let replacement = dir.path().join("replacement");
    fs::write(&replacement, page.encode()).unwrap();
    fs::rename(&replacement, output.join("page-00001.crg2")).unwrap();
    assert!(owner.read_page(1, deadline()).is_err());
    let reopened =
        CellPagedRetainedShardPlanFileV2::open(&output, owner.commitment(), deadline()).unwrap();
    fs::hard_link(
        output.join("page-00001.crg2"),
        dir.path().join("page-alias"),
    )
    .unwrap();
    assert!(reopened.read_page(1, deadline()).is_err());
}

#[test]
fn paged_shard_complete_current_rechecks_same_inode_page_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let source = cache(&dir.path().join("source.sqlite"));
    let contract = make_contract(&source, 1);
    let mut catalog =
        CellVersionRetentionStoreV3::create(&dir.path().join("catalog"), config(16)).unwrap();
    acknowledge(&mut catalog, &contract, &source);
    let prepared = paged_request(&catalog, 2, 1);
    let output = dir.path().join("paged");
    let owner =
        CellPagedRetainedShardPlanFileV2::create(&output, &mut catalog, prepared, deadline())
            .unwrap();
    assert_eq!(
        owner
            .read_complete_current(&catalog, 11, deadline())
            .unwrap(),
        *owner.plan()
    );
    let path = output.join("page-00000.crg2");
    let mut bytes = fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(&path, bytes).unwrap();
    // Root/catalog-only inspection remains available for diagnosis; complete
    // page integrity cannot be inferred from that lightweight observation.
    assert_eq!(
        owner.read_current(&catalog, 11, deadline()).unwrap(),
        *owner.plan()
    );
    assert!(owner
        .read_complete_current(&catalog, 11, deadline())
        .is_err());
    assert!(owner.read_page(0, deadline()).is_err());
    assert!(owner.read_page(1, deadline()).is_ok());
    assert!(
        catalog
            .verify_version(contract.operation, deadline())
            .unwrap()
            .acknowledged
    );
}
