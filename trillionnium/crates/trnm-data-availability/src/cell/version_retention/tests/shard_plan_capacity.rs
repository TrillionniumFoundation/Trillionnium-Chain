//! Initial CRP1 capacity profile, tested through real complete TCA3 closures.
//! These use many bounded 16 KiB chunks, not fabricated manifest summaries.

use super::*;
use crate::cell::{
    MAX_CELL_RETAINED_SHARD_CHUNKS_V1, MAX_CELL_RETAINED_SHARD_PLAN_BYTES_V1,
    MAX_CELL_RETAINED_SHARD_ROOTS_V1,
};

fn capacity_cache(path: &Path) -> CellStoreV1 {
    // Explicit fixture admission within the unchanged ordinary cache limits:
    // 128 original chunks plus 768 independent original CRS1 wires/manifests.
    CellStoreV1::open(
        path,
        CellCacheConfigV4 {
            max_database_bytes: 64 << 20,
            max_logical_bytes: 32 << 20,
            max_chunk_rows: 1024,
            max_manifest_rows: 1024,
        },
    )
    .unwrap()
}

fn complete_contract(source: &CellStoreV1, model_chunks: usize) -> CellVersionRetentionContractV3 {
    let seed = 33;
    let mut original = make_contract(source, seed);
    let environment = original.version.environment().clone();
    let environment_id = environment.files()[0].manifest;
    let environment_manifest = original
        .version
        .manifests()
        .iter()
        .find(|manifest| manifest.id() == environment_id)
        .unwrap()
        .clone();
    let mut bytes = vec![0x53; model_chunks * 16_384];
    for (index, chunk) in bytes.chunks_mut(16_384).enumerate() {
        chunk[..8].copy_from_slice(&(index as u64).to_be_bytes());
    }
    let chunks: Vec<_> = bytes
        .chunks(16_384)
        .map(|chunk| CellChunkV1 {
            size: chunk.len() as u32,
            sha256: Sha256::digest(chunk).into(),
        })
        .collect();
    let manifest = CellManifestV1::new(
        original.model.context.clone(),
        bytes.len() as u64,
        Sha256::digest(&bytes).into(),
        16_384,
        chunks,
    )
    .unwrap();
    source
        .put_manifest(manifest.id(), &manifest.encode())
        .unwrap();
    for (expected, payload) in manifest.chunks().iter().zip(bytes.chunks(16_384)) {
        source.put_chunk(expected, payload).unwrap();
    }
    let model = CellReleaseClosureV1::new(
        manifest.context().clone(),
        original.model.selected_generation,
        original.model.loader_profile,
        vec![0],
        vec![CellClosureFileV1 {
            path: "base.bin".into(),
            role: CellFileRoleV1::Base,
            manifest: manifest.id(),
            payload_sha256: manifest.payload_sha256(),
            payload_bytes: manifest.size(),
            dependencies: vec![],
        }],
    )
    .unwrap();
    original.model.closure_id = model.id();
    original.model.max_payload_bytes = manifest.size();
    original.model.max_chunks = model_chunks as u64;
    let mut manifests = vec![manifest, environment_manifest];
    manifests.sort_by_key(CellManifestV1::id);
    original.version = CellVersionManifestV1::new(
        CellModelReleaseRootV1::new(model, vec![]).unwrap(),
        environment,
        manifests,
    )
    .unwrap();
    original.objects = original
        .version
        .manifests()
        .iter()
        .enumerate()
        .map(|(index, manifest)| CellRetentionContractV1 {
            operation: identity(10 + index as u8, seed),
            funding_operation: identity(20 + index as u8, seed),
            manifest: manifest.clone(),
            retain_from_height: 10,
            retain_until_height: 120,
            maximum_repair_bytes: 4 * manifest.size(),
            successor: None,
        })
        .collect();
    original
}

fn capacity_request(
    catalog: &CellVersionRetentionStoreV3,
    chunks: usize,
) -> CellRetainedShardPlanRequestV1 {
    let mut prepared = request(catalog, chunks);
    for provider in &mut prepared.providers {
        // Each 16 KiB source shard wire occupies two unchanged 4 KiB arena
        // units; this new fixture explicitly admits its full finite duty set.
        provider.capacity_bytes = 128 * 8192;
        provider.maximum_obligations = 128;
    }
    prepared
}

#[test]
fn retained_shard_plan_initial_128_profile_accepts_complete_65_and_128_chunk_catalogs() {
    assert_eq!(MAX_CELL_RETAINED_SHARD_CHUNKS_V1, 128);
    assert_eq!(MAX_CELL_RETAINED_SHARD_ROOTS_V1, 64);
    assert_eq!(MAX_CELL_RETAINED_SHARD_PLAN_BYTES_V1, 2 * 1024 * 1024);
    for complete_chunks in [65_usize, 128] {
        let dir = tempfile::tempdir().unwrap();
        let source_path = dir.path().join("source.sqlite");
        let source = capacity_cache(&source_path);
        let contract = complete_contract(&source, complete_chunks - 1);
        let catalog_path = dir.path().join("catalog");
        let config = config(1024);
        let mut catalog =
            CellVersionRetentionStoreV3::create(&catalog_path, config.clone()).unwrap();
        acknowledge(&mut catalog, &contract, &source);
        assert_eq!(
            contract
                .version
                .manifests()
                .iter()
                .map(|manifest| manifest.chunks().len())
                .sum::<usize>(),
            complete_chunks
        );
        let anchor = catalog.anchor(deadline()).unwrap();
        drop(source);
        drop(catalog);
        fs::remove_file(source_path).unwrap();
        let mut catalog = CellVersionRetentionStoreV3::open(&catalog_path, config, anchor).unwrap();
        let empty = capacity_cache(&dir.path().join("empty.sqlite"));
        assert_eq!(empty.cache_usage().unwrap().chunk_rows, 0);
        let prepared = capacity_request(&catalog, complete_chunks);
        let output = dir.path().join("complete.crp1");
        // File preparation repopulates from the actual retained arena after
        // source deletion, then derives every canonical six-slot descriptor.
        let file = CellRetainedShardPlanFileV1::create(
            &output,
            &mut catalog,
            &empty,
            prepared,
            deadline(),
        )
        .unwrap();
        assert_eq!(file.plan().chunks().len(), complete_chunks);
        assert_eq!(file.plan().manifests().len(), 2);
        assert_eq!(file.plan().roots().len(), 1);
        assert_eq!(
            file.plan().roots()[0].version(),
            contract.version.commitment()
        );
        assert!(file.plan().encode().len() <= MAX_CELL_RETAINED_SHARD_PLAN_BYTES_V1);
        for manifest in contract.version.manifests() {
            empty.verify_complete(manifest).unwrap();
        }
        for chunk in file.plan().chunks() {
            for slot in chunk.slots() {
                empty.verify_complete(slot.manifest()).unwrap();
            }
        }
        let pin = file.commitment();
        drop(file);
        let reopened = CellRetainedShardPlanFileV1::open(&output, pin, deadline()).unwrap();
        assert_eq!(
            reopened
                .read_current(&catalog, 11, deadline())
                .unwrap()
                .chunks()
                .len(),
            complete_chunks
        );
        assert_eq!(catalog.anchor(deadline()).unwrap(), anchor);
    }
}

#[test]
fn retained_shard_plan_initial_128_profile_refuses_129_complete_chunks_before_staging() {
    let dir = tempfile::tempdir().unwrap();
    let source = capacity_cache(&dir.path().join("source.sqlite"));
    let contract = complete_contract(&source, 128);
    let mut catalog =
        CellVersionRetentionStoreV3::create(&dir.path().join("catalog"), config(1024)).unwrap();
    acknowledge(&mut catalog, &contract, &source);
    assert_eq!(
        contract
            .version
            .manifests()
            .iter()
            .map(|manifest| manifest.chunks().len())
            .sum::<usize>(),
        129
    );
    let anchor = catalog.anchor(deadline()).unwrap();
    let empty = capacity_cache(&dir.path().join("empty.sqlite"));
    let before = empty.cache_usage().unwrap();
    let prepared = capacity_request(&catalog, 129);
    let output = dir.path().join("refused.crp1");
    assert_invalid(
        CellRetainedShardPlanFileV1::create(&output, &mut catalog, &empty, prepared, deadline()),
        "retained shard plan complete chunk capacity",
    );
    assert!(!output.exists());
    assert_eq!(catalog.anchor(deadline()).unwrap(), anchor);
    assert_eq!(empty.cache_usage().unwrap(), before);
}

#[test]
fn retained_shard_plan_initial_128_profile_keeps_original_two_mib_wire_and_file_ceiling() {
    let dir = tempfile::tempdir().unwrap();
    let source = cache(&dir.path().join("source.sqlite"));
    let contract = make_contract(&source, 1);
    let mut catalog =
        CellVersionRetentionStoreV3::create(&dir.path().join("catalog"), config(16)).unwrap();
    acknowledge(&mut catalog, &contract, &source);
    let prepared = request(&catalog, 2);
    let file = CellRetainedShardPlanFileV1::create(
        &dir.path().join("valid.crp1"),
        &mut catalog,
        &source,
        prepared,
        deadline(),
    )
    .unwrap();
    let mut wire = file.plan().encode();
    wire.resize(MAX_CELL_RETAINED_SHARD_PLAN_BYTES_V1 + 1, 0);
    let pin = plan_digest(&wire);
    assert_invalid(
        CellRetainedShardPlanV1::decode_pinned(&wire, pin, deadline()),
        "retained shard plan independent pin/size",
    );
    let output = dir.path().join("oversized.crp1");
    fs::write(&output, wire).unwrap();
    assert_invalid(
        CellRetainedShardPlanFileV1::open(&output, pin, deadline()),
        "retained shard plan file size",
    );
}
