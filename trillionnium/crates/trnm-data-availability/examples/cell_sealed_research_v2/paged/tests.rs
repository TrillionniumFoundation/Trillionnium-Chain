//! Exercise the explicit paged research owner with synthetic bytes only.
//! These tests do not run a model, pay for custody or grant execution rights.

use super::super::SNAPSHOT_BOUND;
use super::{restore, Profile, Restore};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};
use trnm_data_availability::cell::*;

fn profile() -> Profile {
    Profile {
        schema: "trnm.cell-sealed-paged-custody.v1".into(),
        chunks_per_page: 64,
        available_slots: [0, 2, 4, 5],
    }
}

fn identity(tag: u8, ordinal: u64) -> CellDigestV1 {
    let mut hash = Sha256::new();
    hash.update(b"test-sealed-paged-research");
    hash.update([tag]);
    hash.update(ordinal.to_be_bytes());
    hash.finalize().into()
}

fn manifest(store: &CellStoreV1, context: &CellContextV1, bytes: &[u8]) -> CellManifestV1 {
    let mut wire = b"TCM1".to_vec();
    wire.push(context.family.len() as u8);
    wire.extend_from_slice(context.family.as_bytes());
    for value in [
        context.base,
        context.parent,
        context.tokenizer,
        context.layout,
        context.runtime,
    ] {
        wire.extend_from_slice(&value);
    }
    wire.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    wire.extend_from_slice(&Sha256::digest(bytes));
    wire.extend_from_slice(&16_384_u32.to_be_bytes());
    wire.extend_from_slice(&(bytes.len().div_ceil(16_384) as u32).to_be_bytes());
    for raw in bytes.chunks(16_384) {
        let chunk = CellChunkV1 {
            size: raw.len() as u32,
            sha256: Sha256::digest(raw).into(),
        };
        wire.extend_from_slice(&chunk.size.to_be_bytes());
        wire.extend_from_slice(&chunk.sha256);
        store.put_chunk(&chunk, raw).unwrap();
    }
    let manifest = CellManifestV1::decode(&wire).unwrap();
    store.put_manifest(manifest.id(), &wire).unwrap();
    manifest
}

struct Fixture {
    directory: tempfile::TempDir,
    source: CellStoreV1,
    received: CellStoreV1,
    archive: CellVersionRetentionStoreV3,
    config: CellVersionRetentionConfigV3,
    anchor: CellVersionCatalogAnchorV3,
    version: CellVersionManifestV1,
    content: CellVersionContentV2,
    model_owner: CellLoaderContextV1,
    environment_owner: CellLoaderContextV1,
    source_path: PathBuf,
    received_path: PathBuf,
    archive_path: PathBuf,
    operation: CellDigestV1,
}

impl Fixture {
    fn new(model_chunks: usize, deadline: Instant) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let source_path = directory.path().join("publisher.sqlite");
        let received_path = directory.path().join("bep52-received.sqlite");
        let archive_path = directory.path().join("retained");
        let source = super::super::cache(&source_path).unwrap();
        let received = super::super::cache(&received_path).unwrap();
        let context = CellContextV1 {
            family: "paged-research-fixture".into(),
            base: identity(1, 0),
            parent: identity(2, 0),
            tokenizer: identity(3, 0),
            layout: identity(4, 0),
            runtime: identity(5, 0),
        };
        let environment_manifest = manifest(&source, &context, b"pinned local runtime");
        let environment = CellReleaseClosureV1::new(
            context.clone(),
            1,
            identity(6, 0),
            vec![0],
            vec![CellClosureFileV1 {
                path: "runtime.bin".into(),
                role: CellFileRoleV1::Configuration,
                manifest: environment_manifest.id(),
                payload_sha256: environment_manifest.payload_sha256(),
                payload_bytes: environment_manifest.size(),
                dependencies: vec![],
            }],
        )
        .unwrap();
        let model_context = CellContextV1 {
            runtime: environment.id(),
            ..context
        };
        let bytes: Vec<_> = (0..model_chunks * 16_384)
            .map(|index| ((index / 16_384 + index % 16_384) % 251) as u8)
            .collect();
        let model_manifest = manifest(&source, &model_context, &bytes);
        let model = CellModelReleaseRootV1::new(
            CellReleaseClosureV1::new(
                model_context,
                1,
                identity(7, 0),
                vec![0],
                vec![CellClosureFileV1 {
                    path: "base/payload.bin".into(),
                    role: CellFileRoleV1::Base,
                    manifest: model_manifest.id(),
                    payload_sha256: model_manifest.payload_sha256(),
                    payload_bytes: model_manifest.size(),
                    dependencies: vec![],
                }],
            )
            .unwrap(),
            vec![],
        )
        .unwrap();
        let mut manifests = vec![model_manifest, environment_manifest];
        manifests.sort_by_key(CellManifestV1::id);
        let version = CellVersionManifestV1::new(model, environment, manifests).unwrap();
        let model_owner = super::super::owner(
            version.model().closure(),
            vec![CellFileRoleV1::Base],
            SNAPSHOT_BOUND,
        );
        let environment_owner = super::super::owner(
            version.environment(),
            vec![CellFileRoleV1::Configuration],
            SNAPSHOT_BOUND,
        );
        let owner = CellVersionLoaderContextV1 {
            commitment: version.commitment(),
            model: &model_owner,
            environment: &environment_owner,
        };
        let content = CellVersionContentV2::capture_cached(
            &version,
            &source,
            &owner,
            &mut super::super::session(deadline, SNAPSHOT_BOUND).unwrap(),
        )
        .unwrap();
        for member in version.manifests() {
            received
                .put_manifest(member.id(), &member.encode())
                .unwrap();
            for chunk in member.chunks() {
                let raw = source.chunk(chunk.sha256).unwrap().unwrap();
                received.put_chunk(chunk, &raw).unwrap();
            }
        }
        let operation = identity(8, 0);
        let config = CellVersionRetentionConfigV3 {
            retention: CellRetentionConfigV1 {
                store_id: identity(9, 0),
                capacity_bytes: SNAPSHOT_BOUND,
                maximum_obligations: 128,
            },
            maximum_versions: 16,
            maximum_metadata_bytes: 64 << 20,
        };
        let contract = CellVersionRetentionContractV3 {
            operation,
            funding_operation: identity(10, 0),
            responsible_owner: identity(11, 0),
            failure_domain: identity(12, 0),
            replica_index: 0,
            required_replicas: 1,
            retain_from_height: 1,
            retain_until_height: 100,
            repair_deadline_height: 90,
            version: version.clone(),
            model: CellVersionLoaderPinV3::from_context(&model_owner),
            environment: CellVersionLoaderPinV3::from_context(&environment_owner),
            tensor_model: None,
            snapshot: None,
            objects: version
                .manifests()
                .iter()
                .enumerate()
                .map(|(index, member)| CellRetentionContractV1 {
                    operation: identity(13, index as u64),
                    funding_operation: identity(14, index as u64),
                    manifest: member.clone(),
                    retain_from_height: 1,
                    retain_until_height: 100,
                    maximum_repair_bytes: member.size(),
                    successor: None,
                })
                .collect(),
        };
        let mut archive =
            CellVersionRetentionStoreV3::create(&archive_path, config.clone()).unwrap();
        archive
            .reserve_version(contract, archive.anchor(deadline).unwrap(), deadline)
            .unwrap();
        archive
            .acknowledge_version(operation, &received, deadline)
            .unwrap();
        let anchor = archive.anchor(deadline).unwrap();
        Self {
            directory,
            source,
            received,
            archive,
            config,
            anchor,
            version,
            content,
            model_owner,
            environment_owner,
            source_path,
            received_path,
            archive_path,
            operation,
        }
    }
}

#[test]
fn paged_research_profile_binds_exact_canonical_available_slots() {
    profile().validate().unwrap();
    let original = profile().commitment().unwrap();
    let mut other = profile();
    other.available_slots = [0, 1, 2, 3];
    other.validate().unwrap();
    assert_ne!(original, other.commitment().unwrap());
    for slots in [[0, 0, 4, 5], [0, 4, 2, 5], [0, 2, 4, 6]] {
        let mut invalid = profile();
        invalid.available_slots = slots;
        assert!(invalid.validate().is_err());
    }
    let mut invalid = profile();
    invalid.chunks_per_page = 0;
    assert!(invalid.validate().is_err());
    invalid = profile();
    invalid.schema = "trnm.cell-sealed-research-source.v2".into();
    assert!(invalid.validate().is_err());
}

#[test]
fn paged_research_restores_two_pages_from_four_reopened_targets() {
    let started = Instant::now();
    let deadline = started + Duration::from_secs(90);
    let fixture = Fixture::new(65, deadline);
    let owner = CellVersionLoaderContextV1 {
        commitment: fixture.version.commitment(),
        model: &fixture.model_owner,
        environment: &fixture.environment_owner,
    };
    let config = fixture.config.clone();
    let anchor = fixture.archive.anchor(deadline).unwrap();
    let anchor_wire = anchor.encode();
    let cancelled = AtomicBool::new(false);
    let mut report = json!({"m12_funding_admitted": false, "hepta_final_use": false,
        "production_activation": false});
    let consumer = restore(
        Restore {
            source: fixture.source,
            received: fixture.received,
            archive: fixture.archive,
            config: fixture.config,
            anchor: fixture.anchor,
            version: &fixture.version,
            content: &fixture.content,
            owner: &owner,
            source_path: &fixture.source_path,
            received_path: &fixture.received_path,
            archive_path: &fixture.archive_path,
            output: fixture.directory.path(),
            operation: fixture.operation,
            deadline,
            started,
            cancelled: &cancelled,
        },
        &profile(),
        &mut report,
    )
    .unwrap();
    assert!(!fixture.source_path.exists());
    assert!(!fixture.received_path.exists());
    for member in fixture.version.manifests() {
        consumer.verify_complete(member).unwrap();
    }
    fixture
        .content
        .verify_cached(
            &consumer,
            &owner,
            fixture.content.commitment(),
            &mut super::super::session(deadline, SNAPSHOT_BOUND).unwrap(),
        )
        .unwrap();
    let observed = &report["paged_custody"];
    assert_eq!(observed["passed"], true);
    assert_eq!(observed["chunk_count"], 66);
    assert_eq!(observed["page_count"], 2);
    assert_eq!(observed["quarantined_slots"], json!([1, 3]));
    assert_eq!(observed["verified_shards"], 264);
    assert_eq!(observed["missing_shards"], 132);
    assert_eq!(observed["rejected_shards"], 0);
    assert_eq!(observed["source_cache_absent"], true);
    assert_eq!(observed["received_cache_absent"], true);
    assert_eq!(observed["staging_cache_absent"], true);
    assert_eq!(observed["catalog_payload_unavailable"], true);
    let provider_root = Path::new(observed["provider_root"].as_str().unwrap());
    assert!(provider_root.starts_with(fixture.directory.path()));
    for slot in 0..6 {
        let live = provider_root.join(format!("provider-{slot}"));
        let quarantined = provider_root.join(format!("quarantined-{slot}"));
        if [1, 3].contains(&slot) {
            assert!(!live.exists());
            assert!(quarantined.is_dir());
            assert!(fs::read(quarantined.join("payload.arena"))
                .unwrap()
                .iter()
                .any(|byte| *byte != 0));
        } else {
            assert!(live.is_dir());
            assert!(!quarantined.exists());
        }
    }
    assert!(!fixture
        .directory
        .path()
        .join("paged-shard-staging.sqlite")
        .exists());
    assert_eq!(observed["restore_budget"]["attempts_committed"], 1);
    assert_eq!(observed["restore_budget"]["provider_reads_committed"], 396);
    assert_eq!(report["m12_funding_admitted"], false);
    assert_eq!(report["hepta_final_use"], false);
    assert_eq!(report["production_activation"], false);
    let arena = fixture.archive_path.join("objects/payload.arena");
    assert!(fs::read(arena).unwrap().iter().all(|byte| *byte == 0));
    let reopened =
        CellVersionRetentionStoreV3::open(&fixture.archive_path, config, anchor).unwrap();
    assert_eq!(reopened.anchor(deadline).unwrap().encode(), anchor_wire);
}

#[test]
fn paged_research_expired_original_deadline_retains_failure_observation() {
    let prepared_deadline = Instant::now() + Duration::from_secs(60);
    let fixture = Fixture::new(1, prepared_deadline);
    let owner = CellVersionLoaderContextV1 {
        commitment: fixture.version.commitment(),
        model: &fixture.model_owner,
        environment: &fixture.environment_owner,
    };
    let deadline = Instant::now()
        .checked_sub(Duration::from_millis(1))
        .unwrap();
    let started = deadline.checked_sub(Duration::from_millis(1)).unwrap();
    let cancelled = AtomicBool::new(false);
    let mut report = json!({});
    let result = restore(
        Restore {
            source: fixture.source,
            received: fixture.received,
            archive: fixture.archive,
            config: fixture.config,
            anchor: fixture.anchor,
            version: &fixture.version,
            content: &fixture.content,
            owner: &owner,
            source_path: &fixture.source_path,
            received_path: &fixture.received_path,
            archive_path: &fixture.archive_path,
            output: fixture.directory.path(),
            operation: fixture.operation,
            deadline,
            started,
            cancelled: &cancelled,
        },
        &profile(),
        &mut report,
    );
    assert!(result.is_err());
    assert!(fixture.source_path.exists());
    assert!(fixture.received_path.exists());
    assert_eq!(report["paged_custody"]["passed"], false);
    assert!(report["paged_custody"]["error"].is_string());
    assert!(report["paged_custody"]["stage"].is_string());
    assert!(report["paged_custody"]["elapsed_ms"].as_u64().is_some());
    assert_eq!(
        report["paged_custody"]["restore_budget"]["attempts_committed"],
        0
    );
}

#[test]
fn paged_research_original_cancellation_is_not_reset_for_cold_reconstruction() {
    let started = Instant::now();
    let deadline = started + Duration::from_secs(60);
    let fixture = Fixture::new(1, deadline);
    let owner = CellVersionLoaderContextV1 {
        commitment: fixture.version.commitment(),
        model: &fixture.model_owner,
        environment: &fixture.environment_owner,
    };
    let cancelled = AtomicBool::new(true);
    let mut report = json!({});
    let result = restore(
        Restore {
            source: fixture.source,
            received: fixture.received,
            archive: fixture.archive,
            config: fixture.config,
            anchor: fixture.anchor,
            version: &fixture.version,
            content: &fixture.content,
            owner: &owner,
            source_path: &fixture.source_path,
            received_path: &fixture.received_path,
            archive_path: &fixture.archive_path,
            output: fixture.directory.path(),
            operation: fixture.operation,
            deadline,
            started,
            cancelled: &cancelled,
        },
        &profile(),
        &mut report,
    );
    assert!(result.is_err());
    assert!(cancelled.load(std::sync::atomic::Ordering::Acquire));
    assert!(fixture.source_path.exists());
    assert!(fixture.received_path.exists());
    assert_eq!(report["paged_custody"]["passed"], false);
    assert!(report["paged_custody"]["error"].is_string());
    assert!(report["paged_custody"]["elapsed_ms"].as_u64().is_some());
    assert_eq!(
        report["paged_custody"]["restore_budget"]["attempts_committed"],
        0
    );
}

fn wrapper() -> serde_json::Value {
    let mut source: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../evidence/cell-capacity-release-dc0357-20261109/model/source-inputs.v2.json"
    )))
    .unwrap();
    let index: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../evidence/cell-capacity-release-dc0357-20261109/model/index.json"
    )))
    .unwrap();
    source["operation"] = json!("42".repeat(32));
    source["output"] = json!("/unused-paged-research-wire-fixture");
    let pins = &index["operation_pins"];
    json!({
        "schema": "trnm.cell-sealed-paged-research-source.v1",
        "source": source,
        "custody": {
            "schema": "trnm.cell-sealed-paged-custody.v1",
            "chunks_per_page": 64,
            "available_slots": [0,2,4,5],
        },
        "expected": {
            "previous_operation": pins["operation"],
            "tcv1": pins["tcv1"], "tcv2": pins["tcv2"], "cts1": pins["cts1"],
            "bep52_plan": pins["bep52_plan"],
            "payload_bytes": index["inputs"]["payload_bytes"],
            "manifest_count": index["inputs"]["manifest_count"],
            "chunks": index["inputs"]["storage_chunks"],
        },
    })
}

#[test]
fn paged_research_wrapper_is_explicit_and_old_v2_wire_stays_closed() {
    let raw = wrapper();
    let parsed: super::super::PagedSpec = serde_json::from_value(raw.clone()).unwrap();
    parsed.validate().unwrap();
    assert!(serde_json::from_value::<super::super::Spec>(raw["source"].clone()).is_ok());
    assert!(serde_json::from_value::<super::super::Spec>(raw.clone()).is_err());
    let mut source = raw["source"].clone();
    source["custody"] = raw["custody"].clone();
    assert!(serde_json::from_value::<super::super::Spec>(source).is_err());
    let mut unknown = raw;
    unknown["latest"] = json!(true);
    assert!(serde_json::from_value::<super::super::PagedSpec>(unknown).is_err());
}

#[test]
fn paged_research_wrapper_requires_independent_previous_identity_and_canonical_pins() {
    let mut changed = wrapper();
    changed["expected"]["previous_operation"] = changed["source"]["operation"].clone();
    assert!(serde_json::from_value::<super::super::PagedSpec>(changed)
        .unwrap()
        .validate()
        .is_err());
    for field in ["tcv1", "tcv2", "cts1", "bep52_plan"] {
        let mut changed = wrapper();
        changed["expected"][field] = json!("AA".repeat(64));
        assert!(serde_json::from_value::<super::super::PagedSpec>(changed)
            .unwrap()
            .validate()
            .is_err());
    }
    let mut changed = wrapper();
    changed["expected"]["chunks"] = json!(0);
    assert!(serde_json::from_value::<super::super::PagedSpec>(changed)
        .unwrap()
        .validate()
        .is_err());
    let mut changed = wrapper();
    changed["schema"] = json!("trnm.cell-sealed-research-source.v2");
    assert!(serde_json::from_value::<super::super::PagedSpec>(changed)
        .unwrap()
        .validate()
        .is_err());
}
