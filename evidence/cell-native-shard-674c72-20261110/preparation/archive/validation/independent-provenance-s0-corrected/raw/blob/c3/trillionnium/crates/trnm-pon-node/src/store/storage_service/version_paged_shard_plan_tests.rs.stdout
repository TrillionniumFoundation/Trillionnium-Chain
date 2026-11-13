//! The native owner must admit the complete CRP2 set before a page can create
//! effects. Page boundaries do not reset M12 identities or observation budgets.

use super::*;
use trnm_data_availability::cell::{
    CellPagedRetainedShardPlanFileV2, CellPagedRetainedShardPlanRequestV2, CellRs46ShardContractV1,
};

#[path = "version_paged_shard_recovery_tests.rs"]
mod recovery_tests;

struct PagedFixture {
    directory: tempfile::TempDir,
    node: Node,
    catalog: CellVersionRetentionStoreV3,
    file: CellPagedRetainedShardPlanFileV2,
    providers: [CellRs46ShardProviderV1; 6],
    cache: CellStoreV1,
    budgets: NativeBudgetStoreV1,
    request: NativeCellRetainedShardPlanRequestV1,
    input_bytes: u64,
    reconstruction_bytes: u64,
}

impl PagedFixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut node = open_node(
            &directory.path().join("node"),
            StateBackend::PermanentAccountGrowthV2,
        );
        let (source, mut contract) = version_material(directory.path());
        contract.retain_until_height = 40;
        contract.repair_deadline_height = 35;
        for object in &mut contract.objects {
            object.retain_until_height = 40;
        }
        let mut catalog = CellVersionRetentionStoreV3::create(
            &directory.path().join("catalog"),
            version_config(),
        )
        .unwrap();
        let root = funded_version(&mut node, &catalog, contract);
        let mut budgets =
            NativeBudgetStoreV1::open(&directory.path().join("budgets.sqlite"), config(&node))
                .unwrap();
        node.retain_native_cell_version(
            &mut budgets,
            &mut catalog,
            &source,
            root.clone(),
            deadline(),
        )
        .unwrap();
        // Neither CRP2 construction nor first provider delivery may depend on
        // the original files or the publisher's disposable source cache.
        drop(source);
        for name in [
            "runtime.bin",
            "base.bin",
            "tokenizer.json",
            "version-cache.sqlite",
        ] {
            fs::remove_file(directory.path().join(name)).unwrap();
        }
        let request = CellPagedRetainedShardPlanRequestV2 {
            operation: [189; 32],
            expected_catalog: catalog.anchor(deadline()).unwrap(),
            current_height: node
                .native_funding_observation(root.policy.source)
                .unwrap()
                .anchor
                .height,
            required_until_height: 35,
            providers: provider_configs(),
            maximum_repairs_per_slot: 2,
            funding_operations: (0..3)
                .map(|chunk| std::array::from_fn(|slot| [191 + chunk * 6 + slot as u8; 32]))
                .collect(),
            chunks_per_page: 2,
        };
        let file = CellPagedRetainedShardPlanFileV2::create(
            &directory.path().join("paged-plan"),
            &mut catalog,
            request,
            deadline(),
        )
        .unwrap();
        assert_eq!(file.plan().roots().len(), 1);
        assert_eq!(file.plan().chunk_count(), 3);
        assert_eq!(file.plan().page_count(), 2);
        let providers = provider_configs()
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
        let mut slots = Vec::new();
        let mut source_bytes = 0_u64;
        for index in 0..file.plan().page_count() {
            let page = file.read_page(index, deadline()).unwrap();
            for chunk in page.chunks() {
                source_bytes += u64::from(chunk.binding().source_bytes());
                for contract in chunk.slots() {
                    let bytes = contract.manifest().size();
                    let owner = contract.owner();
                    let resources = NativeBudgetResourcesV1::Storage {
                        retained_bytes: bytes,
                        retained_byte_blocks: bytes
                            * (owner.retain_until_height - owner.retain_from_height),
                    };
                    let budget = [220 + slots.len() as u8; 32];
                    let beneficiary =
                        contract.placement().placements[usize::from(owner.slot)].responsible_owner;
                    slots.push(NativeCellShardRetentionRequestV1 {
                        policy: NativeBudgetPolicyV1 {
                            budget,
                            // Preserve M06's sixteen-expirations-per-height
                            // limit and the four original root/member jobs at 50.
                            source: fund_provider(
                                &mut node,
                                beneficiary,
                                100,
                                41 + u64::from(owner.slot),
                            ),
                            monetary_cap: 100,
                            deadline: 40,
                            resource_cap: resources.clone(),
                            max_inflight: 1,
                        },
                        claim: NativeBudgetClaimV1 {
                            claim: owner.funding_operation,
                            budget,
                            subject: contract
                                .retention_contract()
                                .commitment(owner.provider_store),
                            beneficiary,
                            monetary_reservation: 100,
                            resource_reservation: resources,
                        },
                        contract: contract.clone(),
                    });
                }
            }
        }
        assert_eq!(slots.len(), 18);
        let input_bytes = slots
            .iter()
            .map(|slot| slot.contract.manifest().size())
            .sum();
        let cache =
            CellStoreV1::open(&directory.path().join("delivery.sqlite"), cache_config()).unwrap();
        Self {
            directory,
            node,
            catalog,
            file,
            providers,
            cache,
            budgets,
            request: NativeCellRetainedShardPlanRequestV1 { slots },
            input_bytes,
            reconstruction_bytes: input_bytes + source_bytes,
        }
    }

    fn observe(
        &mut self,
        request: NativeCellRetainedShardPlanRequestV1,
        verification: &mut NativeCellRetainedShardVerificationBudgetV1,
    ) -> Result<NativeCellPagedRetainedShardPlanReadbackV2> {
        self.node.retain_native_cell_paged_shard_plan(
            &mut self.budgets,
            NativeCellPagedRetainedShardPlanTargetsV2 {
                catalog: &mut self.catalog,
                plan_file: &self.file,
                providers: &mut self.providers,
                cache: &self.cache,
            },
            request,
            verification,
        )
    }
}

#[test]
fn native_paged_shard_plan_reopens_done_without_sources_or_fresh_allowance() {
    let mut fixture = PagedFixture::new();
    let mut verification = NativeCellRetainedShardVerificationBudgetV1::new(
        Instant::now() + Duration::from_secs(30),
        12,
        4 * fixture.input_bytes,
        4 * fixture.reconstruction_bytes,
    );
    let first = fixture
        .observe(fixture.request.clone(), &mut verification)
        .unwrap();
    assert_eq!(first.plan, fixture.file.commitment());
    assert_eq!(first.retained, fixture.file.plan().retained_commitment());
    assert_eq!(first.pages.len(), 2);
    for (index, expected_range) in [(0, (0, 2)), (1, (2, 1))] {
        let actual = &first.pages[index];
        assert_eq!(actual.index, index);
        assert_eq!((actual.start_chunk, actual.chunk_count), expected_range);
        assert_eq!(
            actual.commitment,
            fixture
                .file
                .read_page(index, deadline())
                .unwrap()
                .commitment()
        );
    }
    assert_eq!(first.slots.len(), 18);
    assert!(first
        .slots
        .iter()
        .all(|slot| slot.native.replay == NativeBudgetReplayV1::Done));
    // Both the first per-page readback and independent complete-set readback
    // consume the same original allowance, including the final one-chunk page.
    assert_eq!(first.verification_usage.attempts_committed, 6);
    assert_eq!(first.codec_usage.attempts_committed, 6);
    assert_eq!(
        first.verification_usage.input_bytes_committed,
        2 * fixture.input_bytes
    );
    assert_eq!(
        first.verification_usage.reconstruction_bytes_committed,
        2 * fixture.reconstruction_bytes
    );
    let original_rows: Vec<_> = (0..6)
        .map(|slot| physical_debits(&fixture.directory.path().join(format!("provider-{slot}"))))
        .collect();
    assert!(original_rows.iter().all(
        |rows| rows.len() == 3 && rows.iter().all(|row| row.1 == 1 && row.2 > 0 && row.3 == 0)
    ));
    let charged = fixture.budgets.report().unwrap();
    assert_eq!(charged["budgets"].as_array().unwrap().len(), 22);
    let catalog_anchor = fixture.catalog.anchor(deadline()).unwrap();
    let plan_pin = fixture.file.commitment();
    let PagedFixture {
        directory,
        mut node,
        catalog,
        file,
        providers,
        cache,
        budgets,
        request,
        input_bytes,
        reconstruction_bytes,
    } = fixture;
    drop(catalog);
    drop(file);
    drop(providers);
    drop(cache);
    drop(budgets);
    fs::remove_file(directory.path().join("delivery.sqlite")).unwrap();
    let mut catalog = CellVersionRetentionStoreV3::open(
        &directory.path().join("catalog"),
        version_config(),
        catalog_anchor,
    )
    .unwrap();
    let file = CellPagedRetainedShardPlanFileV2::open(
        &directory.path().join("paged-plan"),
        plan_pin,
        deadline(),
    )
    .unwrap();
    let mut providers: [CellRs46ShardProviderV1; 6] = provider_configs()
        .into_iter()
        .enumerate()
        .map(|(slot, config)| {
            CellRs46ShardProviderV1::open(
                &directory.path().join(format!("provider-{slot}")),
                config,
            )
            .unwrap()
        })
        .collect::<Vec<_>>()
        .try_into()
        .ok()
        .unwrap();
    let mut budgets =
        NativeBudgetStoreV1::open(&directory.path().join("budgets.sqlite"), config(&node)).unwrap();
    let empty = CellStoreV1::open(&directory.path().join("empty.sqlite"), cache_config()).unwrap();
    let repeat = node
        .retain_native_cell_paged_shard_plan(
            &mut budgets,
            NativeCellPagedRetainedShardPlanTargetsV2 {
                catalog: &mut catalog,
                plan_file: &file,
                providers: &mut providers,
                cache: &empty,
            },
            request.clone(),
            &mut verification,
        )
        .unwrap();
    assert_eq!(repeat.plan, first.plan);
    assert_eq!(repeat.catalog, first.catalog);
    assert_eq!(repeat.retained, first.retained);
    assert_eq!(repeat.pages.len(), 2);
    assert_eq!(repeat.slots.len(), 18);
    assert!(repeat
        .slots
        .iter()
        .all(|slot| slot.native.replay == NativeBudgetReplayV1::Done));
    assert_eq!(repeat.verification_usage.attempts_committed, 12);
    assert_eq!(repeat.codec_usage.attempts_committed, 12);
    assert_eq!(
        repeat.verification_usage.input_bytes_committed,
        4 * input_bytes
    );
    assert_eq!(
        repeat.verification_usage.reconstruction_bytes_committed,
        4 * reconstruction_bytes
    );
    assert_eq!(budgets.report().unwrap(), charged);
    for (slot, expected) in original_rows.iter().enumerate() {
        assert_eq!(
            &physical_debits(&directory.path().join(format!("provider-{slot}"))),
            expected
        );
    }
    let error = node
        .retain_native_cell_paged_shard_plan(
            &mut budgets,
            NativeCellPagedRetainedShardPlanTargetsV2 {
                catalog: &mut catalog,
                plan_file: &file,
                providers: &mut providers,
                cache: &empty,
            },
            request,
            &mut verification,
        )
        .unwrap_err();
    assert!(error.to_string().contains("VERIFICATION_RESERVATION"));
    assert_eq!(verification.usage(), repeat.verification_usage);
    assert_eq!(budgets.report().unwrap(), charged);
    for (slot, expected) in original_rows.iter().enumerate() {
        assert_eq!(
            &physical_debits(&directory.path().join(format!("provider-{slot}"))),
            expected
        );
    }
}

#[test]
fn native_paged_shard_plan_checks_last_page_before_any_provider_effect() {
    let mut fixture = PagedFixture::new();
    let before = fixture.budgets.report().unwrap();
    let mut verification = NativeCellRetainedShardVerificationBudgetV1::new(
        Instant::now() + Duration::from_secs(30),
        6,
        2 * fixture.input_bytes,
        2 * fixture.reconstruction_bytes,
    );
    let mut omitted = fixture.request.clone();
    omitted.slots.pop();
    let mut aliased = fixture.request.clone();
    aliased.slots[17].policy.source = aliased.slots[0].policy.source;
    let mut unfunded = fixture.request.clone();
    unfunded.slots[17].policy.source = NativeFundingSourceV1::Task([9; 32]);
    let mut wrong_owner = fixture.request.clone();
    wrong_owner.slots[17].claim.beneficiary = public(0);
    for refused in [omitted, aliased, unfunded, wrong_owner] {
        assert!(fixture.observe(refused, &mut verification).is_err());
        assert_eq!(fixture.budgets.report().unwrap(), before);
        assert_eq!(verification.usage().attempts_committed, 0);
        assert_eq!(verification.codec_usage().attempts_committed, 0);
        for slot in 0..6 {
            assert!(
                physical_debits(&fixture.directory.path().join(format!("provider-{slot}")))
                    .is_empty()
            );
        }
    }
    let accepted = fixture
        .observe(fixture.request.clone(), &mut verification)
        .unwrap();
    assert_eq!(accepted.pages.len(), 2);
    assert_eq!(accepted.slots.len(), 18);
    assert_eq!(accepted.verification_usage.attempts_committed, 6);
    assert!(accepted
        .slots
        .iter()
        .all(|slot| slot.native.replay == NativeBudgetReplayV1::Done));
}

#[test]
fn native_paged_shard_plan_unknown_final_slot_never_replays_source_copy() {
    let mut fixture = PagedFixture::new();
    let entry = fixture.request.slots[17].clone();
    fixture
        .budgets
        .open_budget(&mut fixture.node, entry.policy.clone())
        .unwrap();
    fixture
        .budgets
        .reserve(&mut fixture.node, entry.claim.clone())
        .unwrap();
    let pending = fixture.providers[5]
        .reserve(&entry.contract, entry.contract.operation(), deadline())
        .unwrap();
    assert!(!pending.acknowledged);
    assert_eq!(pending.initial_copy_bytes_committed, 0);
    let owner = entry.contract.owner();
    // A stopped original native operation has persisted its M12 intent, but
    // did not start its provider copy. That uncertainty is not a new attempt.
    assert_eq!(
        fixture
            .budgets
            .begin_effect_in_window(
                &mut fixture.node,
                entry.claim.claim,
                entry.contract.operation(),
                entry.claim.subject,
                owner.retain_from_height,
                owner.retain_until_height,
            )
            .unwrap(),
        NativeBudgetReplayV1::New
    );
    let mut verification = NativeCellRetainedShardVerificationBudgetV1::new(
        Instant::now() + Duration::from_secs(30),
        12,
        4 * fixture.input_bytes,
        4 * fixture.reconstruction_bytes,
    );
    assert!(fixture
        .observe(fixture.request.clone(), &mut verification)
        .is_err());
    assert_eq!(verification.usage().attempts_committed, 6);
    assert_eq!(verification.codec_usage().attempts_committed, 2);
    let rows: Vec<_> = (0..6)
        .map(|slot| physical_debits(&fixture.directory.path().join(format!("provider-{slot}"))))
        .collect();
    assert_eq!(rows.iter().flatten().filter(|row| row.1 == 1).count(), 17);
    let unresolved = rows[5]
        .iter()
        .find(|row| row.0.as_slice() == entry.contract.operation())
        .unwrap();
    assert_eq!((unresolved.1, unresolved.2, unresolved.3), (0, 0, 0));
    let charged = fixture.budgets.report().unwrap();
    // The page's source shards now exist for its five successful siblings.
    // Their presence still cannot authorize a write for the original Pending
    // slot. Failed complete observations keep their full global reservation.
    assert!(fixture
        .observe(fixture.request.clone(), &mut verification)
        .is_err());
    assert_eq!(verification.usage().attempts_committed, 12);
    assert_eq!(verification.codec_usage().attempts_committed, 4);
    assert_eq!(fixture.budgets.report().unwrap(), charged);
    for (slot, expected) in rows.iter().enumerate() {
        assert_eq!(
            &physical_debits(&fixture.directory.path().join(format!("provider-{slot}"))),
            expected
        );
    }
}

#[test]
fn native_paged_shard_plan_corrupt_last_page_refuses_before_any_effect_or_debit() {
    let mut fixture = PagedFixture::new();
    let before = fixture.budgets.report().unwrap();
    let path = fixture.directory.path().join("paged-plan/page-00001.crg2");
    let mut bytes = fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(path, bytes).unwrap();
    let mut verification = NativeCellRetainedShardVerificationBudgetV1::new(
        Instant::now() + Duration::from_secs(30),
        6,
        2 * fixture.input_bytes,
        2 * fixture.reconstruction_bytes,
    );
    assert!(fixture
        .observe(fixture.request.clone(), &mut verification)
        .is_err());
    assert_eq!(fixture.budgets.report().unwrap(), before);
    assert_eq!(verification.usage().attempts_committed, 0);
    assert_eq!(verification.codec_usage().attempts_committed, 0);
    for slot in 0..6 {
        assert!(
            physical_debits(&fixture.directory.path().join(format!("provider-{slot}"))).is_empty()
        );
    }
}

#[test]
fn native_paged_shard_plan_counts_retired_provider_history_before_first_new_effect() {
    let mut fixture = PagedFixture::new();
    let height = fixture
        .node
        .native_funding_observation(fixture.request.slots[0].policy.source)
        .unwrap()
        .anchor
        .height;
    fixture
        .file
        .stage_chunk_from_catalog(
            1,
            0,
            &mut fixture.catalog,
            &fixture.cache,
            height,
            deadline(),
        )
        .unwrap();
    let original = &fixture.request.slots[17].contract;
    let wire = fixture
        .cache
        .chunk(original.manifest().chunks()[0].sha256)
        .unwrap()
        .unwrap();
    // The original provider profile has 64 lifetime obligations. These 62
    // acknowledged and explicitly retired duties release their physical space
    // but remain in the provider's original descriptor/history namespace.
    for index in 0_u64..62 {
        let mut owner = original.owner().clone();
        owner.original_operation = hash(b"test-paged-retired-operation", &[&index.to_be_bytes()]);
        owner.funding_operation = hash(b"test-paged-retired-funding", &[&index.to_be_bytes()]);
        owner.retain_from_height = 0;
        owner.retain_until_height = 1;
        let historical = CellRs46ShardContractV1::from_verified_shard(
            owner,
            original.binding(),
            original.codeword(),
            original.placement(),
            &wire,
        )
        .unwrap();
        CellRs46ShardProviderV1::cache_shard(
            &historical,
            historical.operation(),
            &wire,
            &fixture.cache,
            deadline(),
        )
        .unwrap();
        fixture.providers[5]
            .publish(
                &historical,
                historical.operation(),
                &fixture.cache,
                deadline(),
            )
            .unwrap();
        fixture.providers[5]
            .retire(
                historical.binding(),
                historical.operation(),
                1,
                deadline(),
                &mut || Ok(()),
            )
            .unwrap();
    }
    let rows: Vec<_> = (0..6)
        .map(|slot| physical_debits(&fixture.directory.path().join(format!("provider-{slot}"))))
        .collect();
    assert_eq!(rows[5].len(), 62);
    assert!(rows[5].iter().all(|row| row.1 == 2));
    let before = fixture.budgets.report().unwrap();
    let mut verification = NativeCellRetainedShardVerificationBudgetV1::new(
        Instant::now() + Duration::from_secs(30),
        6,
        2 * fixture.input_bytes,
        2 * fixture.reconstruction_bytes,
    );
    let error = fixture
        .observe(fixture.request.clone(), &mut verification)
        .unwrap_err();
    assert!(error.to_string().contains("capacity"));
    assert_eq!(verification.usage().attempts_committed, 0);
    assert_eq!(fixture.budgets.report().unwrap(), before);
    for (slot, expected) in rows.iter().enumerate() {
        assert_eq!(
            &physical_debits(&fixture.directory.path().join(format!("provider-{slot}"))),
            expected
        );
    }
}
