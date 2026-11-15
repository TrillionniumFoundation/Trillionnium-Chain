//! Real local provider bytes, complete version pins and irreversible budgets.
//! These fixtures grant no native funding, custody settlement or execution rights.

use super::*;
use crate::cell::*;
use sha2::{Digest, Sha256};
use std::{cell::RefCell, collections::BTreeMap, fs, time::Duration};

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(60)
}

fn identity(tag: u8, ordinal: u64) -> CellDigestV1 {
    let mut hash = Sha256::new();
    hash.update(b"test-paged-consumer-restore");
    hash.update([tag]);
    hash.update(ordinal.to_be_bytes());
    hash.finalize().into()
}

fn cache(path: &std::path::Path) -> CellStoreV1 {
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

struct Fixture {
    directory: tempfile::TempDir,
    catalog: CellVersionRetentionStoreV3,
    plan: CellPagedRetainedShardPlanFileV2,
    contract: CellVersionRetentionContractV3,
    content: CellVersionContentV2,
    providers: RefCell<[CellRs46ShardProviderV1; 6]>,
    slots: BTreeMap<CellDigestV1, usize>,
}

impl Fixture {
    fn new(model_chunks: usize, page_width: u16) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let source_path = directory.path().join("publisher.sqlite");
        let staging_path = directory.path().join("delivery.sqlite");
        let source = cache(&source_path);
        let make = |context: CellContextV1, bytes: &[u8]| {
            let manifest = CellManifestV1::new(
                context,
                bytes.len() as u64,
                Sha256::digest(bytes).into(),
                16_384,
                bytes
                    .chunks(16_384)
                    .map(|chunk| CellChunkV1 {
                        size: chunk.len() as u32,
                        sha256: Sha256::digest(chunk).into(),
                    })
                    .collect(),
            )
            .unwrap();
            source
                .put_manifest(manifest.id(), &manifest.encode())
                .unwrap();
            for (chunk, bytes) in manifest.chunks().iter().zip(bytes.chunks(16_384)) {
                source.put_chunk(chunk, bytes).unwrap();
            }
            manifest
        };
        let context = |runtime| CellContextV1 {
            family: "paged-consumer-restore".into(),
            base: [1; 32],
            parent: [2; 32],
            tokenizer: [3; 32],
            layout: [4; 32],
            runtime,
        };
        let closure = |manifest: &CellManifestV1, role, path: &str, generation| {
            CellReleaseClosureV1::new(
                manifest.context().clone(),
                generation,
                identity(70, generation),
                vec![0],
                vec![CellClosureFileV1 {
                    path: path.into(),
                    role,
                    manifest: manifest.id(),
                    payload_sha256: manifest.payload_sha256(),
                    payload_bytes: manifest.size(),
                    dependencies: vec![],
                }],
            )
            .unwrap()
        };
        let environment_manifest = make(context(identity(71, 0)), b"pinned local runtime");
        let environment = closure(
            &environment_manifest,
            CellFileRoleV1::Configuration,
            "runtime.bin",
            11,
        );
        let mut bytes = vec![0x53; model_chunks * 16_384];
        for (index, chunk) in bytes.chunks_mut(16_384).enumerate() {
            chunk[..8].copy_from_slice(&(index as u64).to_be_bytes());
        }
        let model_manifest = make(context(environment.id()), &bytes);
        let model = closure(&model_manifest, CellFileRoleV1::Base, "base.bin", 17);
        let pin = |value: &CellReleaseClosureV1, role, chunks, payload| CellVersionLoaderPinV3 {
            closure_id: value.id(),
            context: value.release().context().clone(),
            selected_generation: value.selected_generation(),
            loader_profile: value.loader_profile(),
            required_roles: vec![role],
            max_payload_bytes: payload,
            max_chunks: chunks,
        };
        let model_pin = pin(
            &model,
            CellFileRoleV1::Base,
            model_chunks as u64,
            bytes.len() as u64,
        );
        let environment_pin = pin(&environment, CellFileRoleV1::Configuration, 1, 4096);
        let mut manifests = vec![environment_manifest, model_manifest];
        manifests.sort_by_key(CellManifestV1::id);
        let version = CellVersionManifestV1::new(
            CellModelReleaseRootV1::new(model, vec![]).unwrap(),
            environment,
            manifests,
        )
        .unwrap();
        let objects = version
            .manifests()
            .iter()
            .enumerate()
            .map(|(index, manifest)| CellRetentionContractV1 {
                operation: identity(10, index as u64),
                funding_operation: identity(11, index as u64),
                manifest: manifest.clone(),
                retain_from_height: 10,
                retain_until_height: 120,
                maximum_repair_bytes: 2 * manifest.size(),
                successor: None,
            })
            .collect();
        let contract = CellVersionRetentionContractV3 {
            operation: identity(1, 0),
            funding_operation: identity(2, 0),
            responsible_owner: [41; 32],
            failure_domain: [42; 32],
            replica_index: 0,
            required_replicas: 1,
            retain_from_height: 10,
            retain_until_height: 100,
            repair_deadline_height: 90,
            version,
            model: model_pin,
            environment: environment_pin,
            tensor_model: None,
            snapshot: None,
            objects,
        };
        let model = contract.model.loader_context();
        let environment = contract.environment.loader_context();
        let expected = CellVersionLoaderContextV1 {
            commitment: contract.version.commitment(),
            model: &model,
            environment: &environment,
        };
        let mut readback = CellContentReadSessionV2::new(
            CellReleaseLimitsV1 {
                max_payload_bytes: 8 << 20,
                max_chunks: 1024,
                deadline: deadline(),
            },
            1,
        )
        .unwrap();
        let content = CellVersionContentV2::capture_cached(
            &contract.version,
            &source,
            &expected,
            &mut readback,
        )
        .unwrap();
        let mut catalog = CellVersionRetentionStoreV3::create(
            &directory.path().join("catalog"),
            CellVersionRetentionConfigV3 {
                retention: CellRetentionConfigV1 {
                    store_id: [73; 32],
                    capacity_bytes: 8 << 20,
                    maximum_obligations: 64,
                },
                maximum_versions: 16,
                maximum_metadata_bytes: 16 << 20,
            },
        )
        .unwrap();
        catalog
            .reserve_version(
                contract.clone(),
                catalog.anchor(deadline()).unwrap(),
                deadline(),
            )
            .unwrap();
        catalog
            .acknowledge_version(contract.operation, &source, deadline())
            .unwrap();
        let configs: [CellRs46ShardProviderConfigV1; 6] =
            std::array::from_fn(|slot| CellRs46ShardProviderConfigV1 {
                placement: CellRs46ShardPlacementV1 {
                    provider_id: identity(30, slot as u64),
                    responsible_owner: identity(31, slot as u64),
                    administrator: identity(32, slot as u64),
                    failure_domain: identity(33, slot as u64),
                    domain_evidence: identity(34, slot as u64),
                    repair_owner: identity(35, slot as u64),
                },
                owner_generation: 1,
                capacity_bytes: 4 << 20,
                maximum_obligations: 256,
            });
        let expected_catalog = catalog.anchor(deadline()).unwrap();
        let plan = CellPagedRetainedShardPlanFileV2::create(
            &directory.path().join("plan"),
            &mut catalog,
            CellPagedRetainedShardPlanRequestV2 {
                operation: identity(3, 0),
                expected_catalog,
                current_height: 10,
                required_until_height: 90,
                providers: configs.clone(),
                funding_operations: (0..model_chunks + 1)
                    .map(|index| {
                        std::array::from_fn(|slot| identity(40, (6 * index + slot) as u64))
                    })
                    .collect(),
                maximum_repairs_per_slot: 2,
                chunks_per_page: page_width,
            },
            deadline(),
        )
        .unwrap();
        let staging = cache(&staging_path);
        let mut providers: [CellRs46ShardProviderV1; 6] = configs
            .into_iter()
            .enumerate()
            .map(|(slot, config)| {
                CellRs46ShardProviderV1::create(
                    &directory.path().join(format!("provider-{slot}")),
                    config,
                )
                .unwrap()
            })
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .unwrap();
        let mut slots = BTreeMap::new();
        for index in 0..plan.plan().page_count() {
            let page = plan.read_page(index, deadline()).unwrap();
            for (local, chunk) in page.chunks().iter().enumerate() {
                plan.stage_chunk_from_catalog(index, local, &mut catalog, &staging, 11, deadline())
                    .unwrap();
                for (slot, contract) in chunk.slots().iter().enumerate() {
                    providers[slot]
                        .publish(contract, contract.operation(), &staging, deadline())
                        .unwrap();
                    slots.insert(contract.operation(), slot);
                }
            }
        }
        drop(source);
        drop(staging);
        fs::remove_file(source_path).unwrap();
        fs::remove_file(staging_path).unwrap();
        let arena = directory.path().join("catalog/objects/payload.arena");
        let length = fs::metadata(&arena).unwrap().len() as usize;
        fs::write(arena, vec![0; length]).unwrap();
        Self {
            directory,
            catalog,
            plan,
            contract,
            content,
            providers: RefCell::new(providers),
            slots,
        }
    }

    fn limits(&self, attempts: u32) -> CellPagedShardRestoreLimitsV2 {
        CellPagedShardRestoreLimitsV2 {
            deadline: deadline(),
            maximum_attempts: attempts,
            maximum_chunks: 4096,
            maximum_provider_reads: 6 * 4096,
            maximum_input_bytes: 32 << 20,
            maximum_reconstruction_bytes: 32 << 20,
            maximum_cache_bytes: 32 << 20,
            maximum_readback_payload_bytes: 32 << 20,
            maximum_readback_chunks: 4096,
        }
    }

    fn read(
        &self,
        contract: &CellRs46ShardContractV1,
        end: Instant,
    ) -> CellResultV1<Option<Vec<u8>>> {
        self.read_subset(contract, end, &[0, 1, 2, 3])
    }

    fn read_subset(
        &self,
        contract: &CellRs46ShardContractV1,
        end: Instant,
        available: &[usize],
    ) -> CellResultV1<Option<Vec<u8>>> {
        let slot = self.slots[&contract.operation()];
        if !available.contains(&slot) {
            return Ok(None);
        }
        Ok(Some(
            self.providers.borrow_mut()[slot]
                .read(
                    contract.binding(),
                    contract.operation(),
                    end,
                    &mut || Ok(()),
                )?
                .shard()
                .encode(),
        ))
    }

    fn restore(
        &self,
        target: &CellStoreV1,
        budget: &mut CellPagedShardRestoreBudgetV2,
        read: impl FnMut(&CellRs46ShardContractV1, Instant) -> CellResultV1<Option<Vec<u8>>>,
    ) -> CellResultV1<CellPagedShardRestoreReadbackV2> {
        let model = self.contract.model.loader_context();
        let environment = self.contract.environment.loader_context();
        restore_cell_paged_version_to_cache_v2(
            CellPagedShardRestoreRequestV2 {
                plan_file: &self.plan,
                catalog: &self.catalog,
                current_height: 11,
                original_root_operation: self.contract.operation,
                content: &self.content,
                expected: &CellVersionLoaderContextV1 {
                    commitment: self.contract.version.commitment(),
                    model: &model,
                    environment: &environment,
                },
                content_pin: self.content.commitment(),
                target,
            },
            budget,
            read,
        )
    }

    fn restore_controlled(
        &self,
        target: &CellStoreV1,
        budget: &mut CellPagedShardRestoreBudgetV2,
        read: impl FnMut(&CellRs46ShardContractV1, Instant) -> CellResultV1<Option<Vec<u8>>>,
        checkpoint: &mut impl FnMut() -> CellResultV1<()>,
    ) -> CellResultV1<CellPagedShardRestoreReadbackV2> {
        let model = self.contract.model.loader_context();
        let environment = self.contract.environment.loader_context();
        restore_cell_paged_version_to_cache_controlled_v2(
            CellPagedShardRestoreRequestV2 {
                plan_file: &self.plan,
                catalog: &self.catalog,
                current_height: 11,
                original_root_operation: self.contract.operation,
                content: &self.content,
                expected: &CellVersionLoaderContextV1 {
                    commitment: self.contract.version.commitment(),
                    model: &model,
                    environment: &environment,
                },
                content_pin: self.content.commitment(),
                target,
            },
            budget,
            read,
            checkpoint,
        )
    }

    fn provider_payloads(&self) -> Vec<CellDigestV1> {
        (0..6)
            .map(|slot| {
                Sha256::digest(
                    fs::read(
                        self.directory
                            .path()
                            .join(format!("provider-{slot}/payload.arena")),
                    )
                    .unwrap(),
                )
                .into()
            })
            .collect()
    }
}

#[test]
fn paged_consumer_restore_crosses_128_from_four_actual_targets_without_copy_fallback() {
    let fixture = Fixture::new(128, 128);
    assert_eq!(fixture.plan.plan().page_count(), 2);
    assert_eq!(fixture.plan.plan().chunk_count(), 129);
    let target = cache(&fixture.directory.path().join("consumer.sqlite"));
    assert_eq!(target.cache_usage().unwrap().chunk_rows, 0);
    let before = fixture.catalog.inventory(11, deadline()).unwrap();
    let provider_payloads = fixture.provider_payloads();
    let mut budget = CellPagedShardRestoreBudgetV2::new(fixture.limits(1)).unwrap();
    let mut reads = 0;
    let result = fixture
        .restore(&target, &mut budget, |contract, end| {
            reads += 1;
            fixture.read(contract, end)
        })
        .unwrap();
    assert_eq!(reads, 129 * 6);
    assert_eq!(result.original_root_operation, fixture.contract.operation);
    assert_eq!(result.version, fixture.contract.version.commitment());
    assert_eq!(result.content, fixture.content.commitment());
    assert_eq!(result.plan, fixture.plan.commitment());
    assert_eq!(result.chunks, 129);
    assert_eq!(result.verified_shards, 129 * 4);
    assert_eq!(result.missing_shards, 129 * 2);
    assert_eq!(result.rejected_shards, 0);
    assert_eq!(result.usage.attempts_committed, 1);
    assert_eq!(result.usage.provider_reads_committed, 129 * 6);
    assert_eq!(result.codec_usage.attempts_committed, 129);
    assert_eq!(result.readback_usage.attempted_scans, 1);
    assert_eq!(target.cache_usage().unwrap().chunk_rows, 129);
    for manifest in fixture.content.version().manifests() {
        target.verify_complete(manifest).unwrap();
    }
    let after = fixture.catalog.inventory(11, deadline()).unwrap();
    assert_eq!(after.anchor, before.anchor);
    assert_eq!(after.usage, before.usage);
    assert_eq!(fixture.provider_payloads(), provider_payloads);
}

#[test]
fn paged_consumer_restore_missing_last_page_refuses_before_reads_or_cache_writes() {
    let fixture = Fixture::new(2, 2);
    let target = cache(&fixture.directory.path().join("consumer.sqlite"));
    let last = fs::read_dir(fixture.directory.path().join("plan"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.file_name().unwrap() != "root.crr2")
        .max()
        .unwrap();
    fs::remove_file(last).unwrap();
    let mut budget = CellPagedShardRestoreBudgetV2::new(fixture.limits(1)).unwrap();
    let mut reads = 0;
    assert!(fixture
        .restore(&target, &mut budget, |_, _| {
            reads += 1;
            Ok(None)
        })
        .is_err());
    assert_eq!(reads, 0);
    assert_eq!(target.cache_usage().unwrap().chunk_rows, 0);
}

#[test]
fn paged_consumer_restore_late_missing_quorum_spends_one_original_attempt() {
    let fixture = Fixture::new(2, 2);
    let target = cache(&fixture.directory.path().join("consumer.sqlite"));
    let last = fixture.plan.read_page(1, deadline()).unwrap();
    let missing_operation = last.chunks()[0].slots()[3].operation();
    let mut budget = CellPagedShardRestoreBudgetV2::new(fixture.limits(1)).unwrap();
    assert!(fixture
        .restore(&target, &mut budget, |contract, end| {
            if contract.operation() == missing_operation {
                Ok(None)
            } else {
                fixture.read(contract, end)
            }
        })
        .is_err());
    let charged = budget.usage();
    assert_eq!(charged.attempts_committed, 1);
    assert_eq!(charged.chunks_committed, 3);
    assert_eq!(charged.provider_reads_committed, 18);
    // Two full 16 KiB model chunks and the 20-byte runtime file. Each CRS1
    // wire carries its 81-byte header, including unavailable slots' potential.
    assert_eq!(charged.input_bytes_committed, 50_640);
    assert_eq!(charged.reconstruction_bytes_committed, 83_428);
    assert_eq!(charged.cache_bytes_committed, 65_576);
    assert_eq!(charged.readback_payload_bytes_committed, 32_788);
    assert_eq!(charged.readback_chunks_committed, 3);
    let mut reads = 0;
    assert!(fixture
        .restore(&target, &mut budget, |contract, end| {
            reads += 1;
            fixture.read(contract, end)
        })
        .is_err());
    assert_eq!(reads, 0, "a failed attempt must not mint another allowance");
    assert_eq!(budget.usage(), charged);
}

#[test]
fn paged_consumer_restore_global_short_budget_refuses_before_callback() {
    let fixture = Fixture::new(2, 2);
    let target = cache(&fixture.directory.path().join("consumer.sqlite"));
    let mut limits = fixture.limits(1);
    limits.maximum_provider_reads = 17;
    let mut budget = CellPagedShardRestoreBudgetV2::new(limits).unwrap();
    let mut reads = 0;
    assert!(fixture
        .restore(&target, &mut budget, |_, _| {
            reads += 1;
            Ok(None)
        })
        .is_err());
    assert_eq!(reads, 0);
    assert_eq!(target.cache_usage().unwrap().chunk_rows, 0);
}

#[test]
fn paged_consumer_restore_wrong_content_pin_refuses_even_when_shards_are_available() {
    let fixture = Fixture::new(2, 2);
    let target = cache(&fixture.directory.path().join("consumer.sqlite"));
    let model = fixture.contract.model.loader_context();
    let environment = fixture.contract.environment.loader_context();
    let expected = CellVersionLoaderContextV1 {
        commitment: fixture.contract.version.commitment(),
        model: &model,
        environment: &environment,
    };
    let mut wrong = fixture.content.commitment();
    wrong[0] ^= 1;
    let mut budget = CellPagedShardRestoreBudgetV2::new(fixture.limits(1)).unwrap();
    let mut reads = 0;
    assert!(restore_cell_paged_version_to_cache_v2(
        CellPagedShardRestoreRequestV2 {
            plan_file: &fixture.plan,
            catalog: &fixture.catalog,
            current_height: 11,
            original_root_operation: fixture.contract.operation,
            content: &fixture.content,
            expected: &expected,
            content_pin: wrong,
            target: &target,
        },
        &mut budget,
        |contract, end| {
            reads += 1;
            fixture.read(contract, end)
        },
    )
    .is_err());
    assert_eq!(reads, 0);
    assert_eq!(target.cache_usage().unwrap().chunk_rows, 0);
}

#[test]
fn paged_consumer_restore_corrupt_committed_shard_cannot_be_hidden_by_available_peers() {
    let fixture = Fixture::new(2, 2);
    let target = cache(&fixture.directory.path().join("consumer.sqlite"));
    let mut budget = CellPagedShardRestoreBudgetV2::new(fixture.limits(1)).unwrap();
    let mut corrupt = false;
    let result = fixture.restore(&target, &mut budget, |contract, end| {
        let mut wire = fixture.read(contract, end)?;
        if !corrupt {
            if let Some(wire) = &mut wire {
                *wire.last_mut().unwrap() ^= 1;
                corrupt = true;
            }
        }
        Ok(wire)
    });
    assert!(corrupt);
    assert!(result.is_err());
    assert_eq!(target.cache_usage().unwrap().chunk_rows, 0);
}

#[test]
fn paged_consumer_restore_rechecks_earlier_page_bytes_after_last_provider_read() {
    let fixture = Fixture::new(2, 2);
    let target = cache(&fixture.directory.path().join("consumer.sqlite"));
    let first = fs::read_dir(fixture.directory.path().join("plan"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.file_name().unwrap() != "root.crr2")
        .min()
        .unwrap();
    let mut changed = fs::read(&first).unwrap();
    *changed.last_mut().unwrap() ^= 1;
    let mut budget = CellPagedShardRestoreBudgetV2::new(fixture.limits(1)).unwrap();
    let mut reads = 0;
    assert!(fixture
        .restore(&target, &mut budget, |contract, end| {
            let wire = fixture.read(contract, end)?;
            reads += 1;
            if reads == 18 {
                // Preserve the inode and length of a previously observed page.
                fs::write(&first, &changed)?;
            }
            Ok(wire)
        })
        .is_err());
    assert_eq!(reads, 18);
}

#[test]
fn paged_consumer_restore_catalog_change_cannot_be_hidden_by_a_readable_selected_version() {
    let mut fixture = Fixture::new(2, 2);
    let target = cache(&fixture.directory.path().join("consumer.sqlite"));
    let mut added = fixture.contract.clone();
    added.operation = identity(80, 0);
    added.funding_operation = identity(81, 0);
    fixture
        .catalog
        .reserve_version(
            added,
            fixture.catalog.anchor(deadline()).unwrap(),
            deadline(),
        )
        .unwrap();
    let current = fixture.catalog.anchor(deadline()).unwrap();
    let mut budget = CellPagedShardRestoreBudgetV2::new(fixture.limits(1)).unwrap();
    let mut reads = 0;
    assert!(fixture
        .restore(&target, &mut budget, |contract, end| {
            reads += 1;
            fixture.read(contract, end)
        })
        .is_err());
    assert_eq!(reads, 0);
    assert_eq!(target.cache_usage().unwrap().chunk_rows, 0);
    assert_eq!(fixture.catalog.anchor(deadline()).unwrap(), current);
}

#[test]
fn paged_consumer_restore_cold_targets_share_the_original_cumulative_allowance() {
    let fixture = Fixture::new(2, 2);
    let provider_payloads = fixture.provider_payloads();
    let mut budget = CellPagedShardRestoreBudgetV2::new(fixture.limits(2)).unwrap();
    let mut first_usage = None;
    for attempt in 1..=2 {
        let target = cache(
            &fixture
                .directory
                .path()
                .join(format!("consumer-{attempt}.sqlite")),
        );
        let result = fixture
            .restore(&target, &mut budget, |contract, end| {
                fixture.read(contract, end)
            })
            .unwrap();
        assert_eq!(result.usage.attempts_committed, attempt);
        assert_eq!(result.usage.chunks_committed, u64::from(attempt) * 3);
        assert_eq!(
            result.usage.provider_reads_committed,
            u64::from(attempt) * 18
        );
        assert_eq!(result.readback_usage.attempted_scans, attempt);
        if let Some(first) = first_usage {
            assert_eq!(result.usage.readback_payload_bytes_committed, 2 * first);
        } else {
            first_usage = Some(result.usage.readback_payload_bytes_committed);
        }
        for manifest in fixture.content.version().manifests() {
            target.verify_complete(manifest).unwrap();
        }
    }
    assert_eq!(fixture.provider_payloads(), provider_payloads);
    let charged = budget.usage();
    let target = cache(&fixture.directory.path().join("consumer-refused.sqlite"));
    let mut reads = 0;
    assert!(fixture
        .restore(&target, &mut budget, |_, _| {
            reads += 1;
            Ok(None)
        })
        .is_err());
    assert_eq!(reads, 0);
    assert_eq!(budget.usage(), charged);
    assert_eq!(target.cache_usage().unwrap().chunk_rows, 0);
}

#[test]
fn paged_consumer_restore_uses_parity_when_two_systematic_targets_are_unavailable() {
    let fixture = Fixture::new(2, 2);
    let target = cache(&fixture.directory.path().join("parity-consumer.sqlite"));
    let mut budget = CellPagedShardRestoreBudgetV2::new(fixture.limits(1)).unwrap();
    let result = fixture
        .restore(&target, &mut budget, |contract, end| {
            fixture.read_subset(contract, end, &[0, 2, 4, 5])
        })
        .unwrap();
    assert_eq!(result.verified_shards, 12);
    assert_eq!(result.missing_shards, 6);
    assert_eq!(result.rejected_shards, 0);
    assert_eq!(result.payload_bytes, 32_788);
    assert_eq!(result.usage.input_bytes_committed, 50_640);
    assert_eq!(result.usage.reconstruction_bytes_committed, 83_428);
    assert_eq!(result.usage.cache_bytes_committed, 65_576);
    assert_eq!(result.usage.readback_chunks_committed, 3);
    assert_eq!(result.readback_usage.reserved_payload_bytes, 32_788);
    assert_eq!(result.readback_usage.reserved_chunks, 3);
    for manifest in fixture.content.version().manifests() {
        target.verify_complete(manifest).unwrap();
    }
}

#[test]
fn paged_consumer_restore_requires_the_original_retained_root_operation() {
    let fixture = Fixture::new(2, 2);
    let target = cache(&fixture.directory.path().join("consumer.sqlite"));
    let model = fixture.contract.model.loader_context();
    let environment = fixture.contract.environment.loader_context();
    let expected = CellVersionLoaderContextV1 {
        commitment: fixture.contract.version.commitment(),
        model: &model,
        environment: &environment,
    };
    let mut budget = CellPagedShardRestoreBudgetV2::new(fixture.limits(1)).unwrap();
    let mut reads = 0;
    assert!(restore_cell_paged_version_to_cache_v2(
        CellPagedShardRestoreRequestV2 {
            plan_file: &fixture.plan,
            catalog: &fixture.catalog,
            current_height: 11,
            original_root_operation: identity(99, 0),
            content: &fixture.content,
            expected: &expected,
            content_pin: fixture.content.commitment(),
            target: &target,
        },
        &mut budget,
        |contract, end| {
            reads += 1;
            fixture.read(contract, end)
        },
    )
    .is_err());
    assert_eq!(reads, 0);
    assert_eq!(budget.usage().attempts_committed, 0);
    assert_eq!(target.cache_usage().unwrap().chunk_rows, 0);
}

#[test]
fn paged_consumer_control_cancels_after_last_valid_shard_before_final_chunk_write() {
    let fixture = Fixture::new(2, 2);
    let target = cache(&fixture.directory.path().join("cancel-last.sqlite"));
    let reads = std::cell::Cell::new(0);
    let mut budget = CellPagedShardRestoreBudgetV2::new(fixture.limits(2)).unwrap();
    let original_deadline = budget.deadline();
    let result = fixture.restore_controlled(
        &target,
        &mut budget,
        |contract, end| {
            assert_eq!(end, original_deadline);
            // Slot five is present: cancellation happens after obtaining the
            // fourth valid shard for the last chunk, not a missing-quorum case.
            let wire = fixture.read_subset(contract, end, &[0, 2, 4, 5])?;
            reads.set(reads.get() + 1);
            Ok(wire)
        },
        &mut || require(reads.get() < 18, "test original owner cancelled"),
    );
    assert!(matches!(
        result,
        Err(CellErrorV1::Invalid("test original owner cancelled"))
    ));
    assert_eq!(reads.get(), 18);
    assert_eq!(target.cache_usage().unwrap().chunk_rows, 2);
    assert_eq!(budget.usage().attempts_committed, 1);
    assert_eq!(budget.usage().provider_reads_committed, 18);
    assert_eq!(budget.codec_usage().attempts_committed, 2);
    assert_eq!(budget.readback_usage().attempted_scans, 0);
    assert_eq!(budget.deadline(), original_deadline);
    let spent = budget.usage();
    let mut retry_reads = 0;
    assert!(matches!(
        fixture.restore(&target, &mut budget, |_, _| {
            retry_reads += 1;
            Ok(None)
        }),
        Err(CellErrorV1::Invalid("paged restore control stopped"))
    ));
    assert_eq!(retry_reads, 0);
    assert_eq!(budget.usage(), spent);
    assert_eq!(target.cache_usage().unwrap().chunk_rows, 2);
}

#[test]
fn paged_consumer_control_all_boundaries_preserve_costs_bytes_and_stop_retries() {
    let fixture = Fixture::new(1, 2);
    let original_providers = fixture.provider_payloads();
    let reference = cache(&fixture.directory.path().join("control-reference.sqlite"));
    let mut reference_budget = CellPagedShardRestoreBudgetV2::new(fixture.limits(2)).unwrap();
    let mut checkpoints = 0;
    let result = fixture
        .restore_controlled(
            &reference,
            &mut reference_budget,
            |contract, end| fixture.read(contract, end),
            &mut || {
                checkpoints += 1;
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(result.chunks, 2);
    assert_eq!(result.verified_shards, 8);
    assert_eq!(result.readback_usage.attempted_scans, 1);
    let mut before_admission = false;
    let mut during_codec = false;
    let mut after_publication = false;
    let mut during_readback = false;
    // Sweep the actual cooperative boundaries, including codec reconstruction,
    // cache publication/readback and the final complete-content scan. No test
    // relies on a magic checkpoint ordinal or a timing race.
    for stop in 1..=checkpoints {
        let directory = tempfile::tempdir_in(fixture.directory.path()).unwrap();
        let target = cache(&directory.path().join("consumer.sqlite"));
        let mut budget = CellPagedShardRestoreBudgetV2::new(fixture.limits(2)).unwrap();
        let original_deadline = budget.deadline();
        let mut calls = 0;
        let result = fixture.restore_controlled(
            &target,
            &mut budget,
            |contract, end| fixture.read(contract, end),
            &mut || {
                calls += 1;
                assert!(calls <= stop, "a stopped owner was called again");
                require(calls < stop, "test boundary owner refusal")
            },
        );
        assert!(
            matches!(
                result,
                Err(CellErrorV1::Invalid("test boundary owner refusal"))
            ),
            "boundary {stop}"
        );
        assert_eq!(calls, stop);
        let spent = budget.usage();
        let codec = budget.codec_usage();
        let readback = budget.readback_usage();
        let cache_usage = target.cache_usage().unwrap();
        before_admission |= spent.attempts_committed == 0;
        during_codec |= codec.attempts_committed > 0 && codec.cache_bytes_committed == 0;
        after_publication |= cache_usage.chunk_rows > 0;
        during_readback |= readback.attempted_scans > 0;
        if spent.attempts_committed > 0 {
            assert_eq!(spent, reference_budget.usage());
        }
        if readback.attempted_scans > 0 {
            assert_eq!(readback, reference_budget.readback_usage());
        }
        // Any chunks committed before refusal remain readable and match the
        // original hashes. Refusal does not erase already incurred effects.
        for manifest in fixture.content.version().manifests() {
            for chunk in manifest.chunks() {
                if let Some(bytes) = target.chunk(chunk.sha256).unwrap() {
                    assert_eq!(bytes.len(), chunk.size as usize);
                    assert_eq!(<[u8; 32]>::from(Sha256::digest(&bytes)), chunk.sha256);
                }
            }
        }
        let mut retry_reads = 0;
        assert!(matches!(
            fixture.restore(&target, &mut budget, |_, _| {
                retry_reads += 1;
                Ok(None)
            }),
            Err(CellErrorV1::Invalid("paged restore control stopped"))
        ));
        assert_eq!(retry_reads, 0);
        assert_eq!(budget.usage(), spent);
        assert_eq!(budget.codec_usage(), codec);
        assert_eq!(budget.readback_usage(), readback);
        assert_eq!(budget.deadline(), original_deadline);
        assert_eq!(target.cache_usage().unwrap(), cache_usage);
    }
    assert!(before_admission && during_codec && after_publication && during_readback);
    assert_eq!(fixture.provider_payloads(), original_providers);
}

#[test]
fn paged_consumer_control_checks_the_original_deadline_after_owner_returns() {
    let fixture = Fixture::new(1, 2);
    let target = cache(&fixture.directory.path().join("late-control.sqlite"));
    let mut limits = fixture.limits(2);
    limits.deadline = Instant::now() + Duration::from_millis(100);
    let mut budget = CellPagedShardRestoreBudgetV2::new(limits).unwrap();
    let mut calls = 0;
    let result = fixture.restore_controlled(
        &target,
        &mut budget,
        |_, _| panic!("expired owner must not dispatch a provider read"),
        &mut || {
            calls += 1;
            std::thread::sleep(
                limits.deadline.saturating_duration_since(Instant::now())
                    + Duration::from_millis(1),
            );
            Ok(())
        },
    );
    assert!(matches!(
        result,
        Err(CellErrorV1::Invalid("paged restore original deadline"))
    ));
    assert_eq!(calls, 1);
    assert_eq!(budget.deadline(), limits.deadline);
    assert_eq!(budget.usage(), CellPagedShardRestoreUsageV2::default());
    assert_eq!(target.cache_usage().unwrap().chunk_rows, 0);
    assert!(matches!(
        fixture.restore(&target, &mut budget, |_, _| panic!(
            "cancelled reservation retried"
        )),
        Err(CellErrorV1::Invalid("paged restore control stopped"))
    ));
}

#[test]
fn paged_consumer_control_read_failure_can_retry_within_original_allowance() {
    let fixture = Fixture::new(1, 2);
    let target = cache(&fixture.directory.path().join("read-failure.sqlite"));
    let mut budget = CellPagedShardRestoreBudgetV2::new(fixture.limits(2)).unwrap();
    assert!(matches!(
        fixture.restore_controlled(
            &target,
            &mut budget,
            |_, _| Err(CellErrorV1::Unavailable),
            &mut || Ok(()),
        ),
        Err(CellErrorV1::Unavailable)
    ));
    let first = budget.usage();
    let result = fixture
        .restore_controlled(
            &target,
            &mut budget,
            |contract, end| fixture.read(contract, end),
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(result.usage.attempts_committed, 2);
    assert_eq!(
        result.usage.input_bytes_committed,
        2 * first.input_bytes_committed
    );
    assert_eq!(
        result.usage.cache_bytes_committed,
        2 * first.cache_bytes_committed
    );
    assert_eq!(
        result.usage.provider_reads_committed,
        2 * first.provider_reads_committed
    );
    assert_eq!(result.readback_usage.attempted_scans, 1);
    for manifest in fixture.content.version().manifests() {
        target.verify_complete(manifest).unwrap();
    }
}

#[test]
fn paged_consumer_control_read_error_cannot_hide_concurrent_owner_cancellation() {
    let fixture = Fixture::new(1, 2);
    let target = cache(
        &fixture
            .directory
            .path()
            .join("cancel-and-read-error.sqlite"),
    );
    let mut budget = CellPagedShardRestoreBudgetV2::new(fixture.limits(2)).unwrap();
    let cancelled = std::cell::Cell::new(false);
    let mut stop_observations = 0;
    assert!(matches!(
        fixture.restore_controlled(
            &target,
            &mut budget,
            |_, _| {
                cancelled.set(true);
                Err(CellErrorV1::Unavailable)
            },
            &mut || {
                if cancelled.get() {
                    stop_observations += 1;
                }
                require(!cancelled.get(), "test concurrent owner cancellation")
            },
        ),
        Err(CellErrorV1::Unavailable)
    ));
    assert_eq!(stop_observations, 1);
    let charged = budget.usage();
    assert_eq!(charged.attempts_committed, 1);
    assert!(matches!(
        fixture.restore(&target, &mut budget, |_, _| panic!(
            "cancelled owner redispatched"
        )),
        Err(CellErrorV1::Invalid("paged restore control stopped"))
    ));
    assert_eq!(budget.usage(), charged);
    assert_eq!(target.cache_usage().unwrap().chunk_rows, 0);
}
