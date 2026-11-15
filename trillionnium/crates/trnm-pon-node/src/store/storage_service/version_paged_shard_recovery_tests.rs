//! Original native repair owners across both CRR2 pages, with no payload
//! fallback to the catalog, original files or a disposable delivery cache.

use super::*;

type DebitRows = Vec<Vec<(Vec<u8>, u8, u64, u64)>>;

impl PagedFixture {
    fn retained_for_recovery() -> Self {
        let mut value = Self::new();
        let mut budget = NativeCellRetainedShardVerificationBudgetV1::new(
            Instant::now() + Duration::from_secs(30),
            6,
            2 * value.input_bytes,
            2 * value.reconstruction_bytes,
        );
        value.observe(value.request.clone(), &mut budget).unwrap();
        value.clear_recovery_cache(1);
        value
    }

    fn clear_recovery_cache(&mut self, ordinal: u32) {
        let name = format!("recovery-empty-{ordinal}.sqlite");
        let empty = CellStoreV1::open(&self.directory.path().join(&name), cache_config()).unwrap();
        drop(std::mem::replace(&mut self.cache, empty));
        for old in [
            "delivery.sqlite",
            "recovery-empty-1.sqlite",
            "recovery-empty-2.sqlite",
        ] {
            let path = self.directory.path().join(old);
            if old != name && path.exists() {
                fs::remove_file(path).unwrap();
            }
        }
        for entry in &self.request.slots {
            assert!(self
                .cache
                .chunk(entry.contract.manifest().chunks()[0].sha256)
                .unwrap()
                .is_none());
        }
    }

    fn repair_claim(&mut self, index: usize, nonce: u64) -> NativeCellShardRepairRequestV1 {
        let contract = &self.request.slots[index].contract;
        let beneficiary = contract.placement().placements[index % 6].repair_owner;
        let budget = hash(b"TEST_PAGED_RECOVERY_BUDGET", &[&nonce.to_le_bytes()]);
        let claim = hash(b"TEST_PAGED_RECOVERY_CLAIM", &[&nonce.to_le_bytes()]);
        let operation = hash(b"TEST_PAGED_RECOVERY_OPERATION", &[&nonce.to_le_bytes()]);
        let resources = NativeBudgetResourcesV1::Repair {
            cpu_ns: 5_000_000_000,
            download_bytes: contract.manifest().size(),
            upload_bytes: contract.manifest().size(),
            attempts: 1,
        };
        NativeCellShardRepairRequestV1 {
            policy: NativeBudgetPolicyV1 {
                budget,
                source: fund_provider(&mut self.node, beneficiary, 100, 49),
                monetary_cap: 100,
                deadline: 40,
                resource_cap: resources.clone(),
                max_inflight: 1,
            },
            claim: NativeBudgetClaimV1 {
                claim,
                budget,
                subject: native_cell_shard_repair_subject_v1(
                    &self.providers[index % 6],
                    contract,
                    operation,
                    claim,
                ),
                beneficiary,
                monetary_reservation: 100,
                resource_reservation: resources,
            },
            binding: contract.binding().clone(),
            operation: contract.operation(),
            repair_operation: operation,
        }
    }

    fn recovery_request(
        &self,
        repairs: &[(usize, NativeCellShardRepairRequestV1)],
    ) -> NativeCellShardRecoveryRequestV1 {
        let mut entries = vec![None; self.request.slots.len()];
        for (index, repair) in repairs {
            assert!(entries[*index].replace(repair.clone()).is_none());
        }
        NativeCellShardRecoveryRequestV1 {
            storage: self.request.clone(),
            repairs: entries,
        }
    }

    fn recovery_limits(
        &self,
        request: &NativeCellShardRecoveryRequestV1,
        attempts: u32,
    ) -> NativeCellShardRecoveryLimitsV1 {
        let authorized: Vec<_> = request
            .repairs
            .iter()
            .enumerate()
            .filter(|(_, repair)| repair.is_some())
            .collect();
        let bytes: u64 = authorized
            .iter()
            .map(|(index, _)| self.request.slots[*index].contract.manifest().size())
            .sum();
        let count = u64::from(attempts);
        NativeCellShardRecoveryLimitsV1 {
            deadline: Instant::now() + Duration::from_secs(30),
            maximum_plan_attempts: attempts,
            maximum_provider_reads: count
                * (3 * self.request.slots.len() as u64 + authorized.len() as u64),
            maximum_input_bytes: count * (6 * self.input_bytes + bytes),
            maximum_reconstruction_bytes: count * 3 * self.reconstruction_bytes,
            maximum_repairs: count * authorized.len() as u64,
            maximum_repair_bytes: count * bytes,
            maximum_cpu_ns: count * 5_000_000_000,
            cpu_ns_per_attempt: 5_000_000_000,
        }
    }

    fn recover_paged(
        &mut self,
        request: NativeCellShardRecoveryRequestV1,
        budget: &mut NativeCellPagedShardRecoveryBudgetV2,
    ) -> std::result::Result<
        NativeCellPagedShardRecoveryReadbackV2,
        Box<NativeCellShardRecoveryFailureV1>,
    > {
        self.node.recover_native_cell_paged_shard_plan(
            &mut self.budgets,
            NativeCellPagedRetainedShardPlanTargetsV2 {
                catalog: &mut self.catalog,
                plan_file: &self.file,
                providers: &mut self.providers,
                cache: &self.cache,
            },
            request,
            budget,
        )
    }

    fn recovery_ledger(&self) -> DebitRows {
        (0..6)
            .map(|slot| physical_debits(&self.directory.path().join(format!("provider-{slot}"))))
            .collect()
    }

    fn damage_original_slot(&self, index: usize) {
        let path = self
            .directory
            .path()
            .join(format!("provider-{}", index % 6));
        let operation = self.request.slots[index].contract.operation();
        let db = rusqlite::Connection::open(path.join("retention.sqlite")).unwrap();
        let position: u64 = db
            .query_row(
                "SELECT position FROM obligations WHERE operation=?1",
                [operation.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(path.join("payload.arena"))
            .unwrap();
        file.seek(SeekFrom::Start(position)).unwrap();
        file.write_all(&[0xff]).unwrap();
        file.sync_all().unwrap();
    }
}

#[test]
fn native_paged_shard_recovery_repairs_both_pages_from_four_original_targets_and_reopens_done() {
    let mut fixture = PagedFixture::retained_for_recovery();
    fixture.use_six_row_delivery_cache("six-row-recovery.sqlite");
    let repairs: Vec<_> = [4, 5, 16, 17]
        .into_iter()
        .enumerate()
        .map(|(nonce, index)| (index, fixture.repair_claim(index, nonce as u64)))
        .collect();
    let request = fixture.recovery_request(&repairs);
    let mut budget =
        NativeCellPagedShardRecoveryBudgetV2::new(fixture.recovery_limits(&request, 2)).unwrap();
    let before = fixture.recovery_ledger();
    // Preserve the immutable catalog/commitments but make its payload
    // unavailable, so successful recovery must use the four real peer shards.
    let mut arena = fs::OpenOptions::new()
        .write(true)
        .open(
            fixture
                .directory
                .path()
                .join("catalog/objects/payload.arena"),
        )
        .unwrap();
    let length = arena.metadata().unwrap().len() as usize;
    arena.write_all(&vec![0; length]).unwrap();
    arena.sync_all().unwrap();
    for (index, _) in &repairs {
        fixture.damage_original_slot(*index);
    }
    let result = fixture.recover_paged(request.clone(), &mut budget).unwrap();
    assert_eq!(result.plan, fixture.file.commitment());
    assert_eq!(result.pages.len(), 2);
    assert_eq!(result.slots.len(), 18);
    assert_eq!(result.detected_damage.len(), 4);
    assert_eq!(result.actions.len(), 4);
    assert_eq!(result.usage.plan_attempts_committed, 1);
    assert_eq!(result.usage.provider_reads_committed, 58);
    assert_eq!(result.usage.repairs_committed, 4);
    assert_eq!(result.codec_usage.attempts_committed, 8);
    let usage = fixture.cache.cache_usage().unwrap();
    assert_eq!(
        (usage.logical_bytes, usage.chunk_rows, usage.manifest_rows),
        (0, 0, 0)
    );
    assert!(result
        .actions
        .iter()
        .all(|row| row.native.replay == NativeBudgetReplayV1::New));
    assert!(result
        .slots
        .iter()
        .all(|row| row.native.replay == NativeBudgetReplayV1::Done));
    assert!(result.cpu.observed_ns > 0 && result.cpu.observed_ns <= result.cpu.ceiling_ns);
    let after = fixture.recovery_ledger();
    for (old, rows) in before.iter().zip(&after) {
        for (old, row) in old.iter().zip(rows) {
            assert_eq!((&old.0, old.1, old.2), (&row.0, row.1, row.2));
        }
    }
    for (slot, rows) in after.iter().enumerate() {
        let expected: u64 = repairs
            .iter()
            .filter(|(index, _)| index % 6 == slot)
            .map(|(index, _)| fixture.request.slots[*index].contract.manifest().size())
            .sum();
        assert_eq!(rows.iter().map(|row| row.3).sum::<u64>(), expected);
    }
    let money = fixture.budgets.report().unwrap();
    fixture.clear_recovery_cache(2);
    drop(fixture.providers);
    fixture.providers = provider_configs()
        .into_iter()
        .enumerate()
        .map(|(slot, config)| {
            CellRs46ShardProviderV1::open(
                &fixture.directory.path().join(format!("provider-{slot}")),
                config,
            )
            .unwrap()
        })
        .collect::<Vec<_>>()
        .try_into()
        .ok()
        .unwrap();
    drop(fixture.budgets);
    fixture.budgets = NativeBudgetStoreV1::open(
        &fixture.directory.path().join("budgets.sqlite"),
        config(&fixture.node),
    )
    .unwrap();
    let repeated = fixture.recover_paged(request.clone(), &mut budget).unwrap();
    assert!(repeated.detected_damage.is_empty());
    assert_eq!(repeated.actions.len(), 4);
    assert!(repeated
        .actions
        .iter()
        .all(|row| row.native.replay == NativeBudgetReplayV1::Done));
    assert_eq!(repeated.usage.plan_attempts_committed, 2);
    assert_eq!(repeated.usage.repairs_committed, 4);
    assert_eq!(repeated.codec_usage.attempts_committed, 14);
    assert_eq!(fixture.recovery_ledger(), after);
    assert_eq!(fixture.budgets.report().unwrap(), money);
    let failure = fixture.recover_paged(request, &mut budget).unwrap_err();
    assert!(failure.to_string().contains("RECOVERY_BUDGET"));
    assert_eq!(failure.usage, repeated.usage);
    assert_eq!(failure.codec_usage, repeated.codec_usage);
    assert_eq!(fixture.recovery_ledger(), after);
}

#[test]
fn native_paged_shard_recovery_missing_quorum_preserves_whole_attempt_charge() {
    let mut fixture = PagedFixture::retained_for_recovery();
    let repairs: Vec<_> = [3, 4, 5]
        .into_iter()
        .enumerate()
        .map(|(nonce, index)| (index, fixture.repair_claim(index, 10 + nonce as u64)))
        .collect();
    let request = fixture.recovery_request(&repairs);
    let mut budget =
        NativeCellPagedShardRecoveryBudgetV2::new(fixture.recovery_limits(&request, 1)).unwrap();
    let ledger = fixture.recovery_ledger();
    let money = fixture.budgets.report().unwrap();
    for (index, _) in &repairs {
        fixture.damage_original_slot(*index);
    }
    let failure = fixture
        .recover_paged(request.clone(), &mut budget)
        .unwrap_err();
    assert!(failure
        .to_string()
        .contains("FOUR_ORIGINAL_SHARDS_REQUIRED"));
    assert_eq!(failure.usage.plan_attempts_committed, 1);
    assert_eq!(failure.usage.provider_reads_committed, 57);
    assert_eq!(failure.detected_damage.len(), 3);
    assert_eq!(failure.codec_usage.attempts_committed, 0);
    assert!(failure.completed_actions.is_empty());
    assert_eq!(fixture.recovery_ledger(), ledger);
    assert_eq!(fixture.budgets.report().unwrap(), money);
    let again = fixture.recover_paged(request, &mut budget).unwrap_err();
    assert!(again.to_string().contains("RECOVERY_BUDGET"));
    assert_eq!(again.usage, failure.usage);
}

#[test]
fn native_paged_shard_recovery_pending_last_page_never_redispatches_the_original_repair() {
    let mut fixture = PagedFixture::retained_for_recovery();
    fixture.damage_original_slot(17);
    let pending = fixture.repair_claim(17, 20);
    assert!(fixture
        .node
        .repair_native_cell_shard(
            &mut fixture.budgets,
            &mut fixture.providers[5],
            &fixture.cache,
            pending.clone(),
            deadline()
        )
        .is_err());
    let request = fixture.recovery_request(&[(17, pending)]);
    let mut budget =
        NativeCellPagedShardRecoveryBudgetV2::new(fixture.recovery_limits(&request, 1)).unwrap();
    let money = fixture.budgets.report().unwrap();
    let ledger = fixture.recovery_ledger();
    let failure = fixture.recover_paged(request, &mut budget).unwrap_err();
    assert!(failure.to_string().contains("FRESH_AUTHORITY_REQUIRED"));
    assert_eq!(failure.detected_damage.len(), 1);
    assert_eq!(failure.usage.plan_attempts_committed, 1);
    assert_eq!(failure.usage.repairs_committed, 0);
    assert_eq!(failure.codec_usage.attempts_committed, 2);
    assert!(failure.completed_actions.is_empty());
    assert_eq!(fixture.budgets.report().unwrap(), money);
    assert_eq!(fixture.recovery_ledger(), ledger);
    let fresh = fixture.repair_claim(17, 21);
    let fresh_request = fixture.recovery_request(&[(17, fresh)]);
    let mut fresh_budget =
        NativeCellPagedShardRecoveryBudgetV2::new(fixture.recovery_limits(&fresh_request, 1))
            .unwrap();
    let result = fixture
        .recover_paged(fresh_request, &mut fresh_budget)
        .unwrap();
    assert_eq!(result.actions.len(), 1);
    assert_eq!(result.actions[0].native.replay, NativeBudgetReplayV1::New);
    assert_eq!(result.pages.len(), 2);
}

#[test]
fn native_paged_shard_recovery_preflights_last_page_authority_and_exact_global_budget() {
    let mut fixture = PagedFixture::retained_for_recovery();
    let repair = fixture.repair_claim(17, 30);
    let request = fixture.recovery_request(&[(17, repair)]);
    let money = fixture.budgets.report().unwrap();
    let ledger = fixture.recovery_ledger();
    let mut wrong_owner = request.clone();
    wrong_owner.repairs[17].as_mut().unwrap().claim.beneficiary = public(0);
    let mut alias = request.clone();
    alias.repairs[17].as_mut().unwrap().policy.source = alias.storage.slots[0].policy.source;
    let mut missing = request.clone();
    missing.repairs.pop();
    for refused in [wrong_owner, alias, missing] {
        let mut budget =
            NativeCellPagedShardRecoveryBudgetV2::new(fixture.recovery_limits(&request, 1))
                .unwrap();
        assert!(fixture.recover_paged(refused, &mut budget).is_err());
        assert_eq!(budget.usage().plan_attempts_committed, 0);
        assert_eq!(fixture.recovery_ledger(), ledger);
        assert_eq!(fixture.budgets.report().unwrap(), money);
    }
    let mut short = fixture.recovery_limits(&request, 1);
    short.maximum_input_bytes -= 1;
    let mut budget = NativeCellPagedShardRecoveryBudgetV2::new(short).unwrap();
    assert!(fixture
        .recover_paged(request.clone(), &mut budget)
        .unwrap_err()
        .to_string()
        .contains("RECOVERY_BUDGET"));
    assert_eq!(budget.usage().plan_attempts_committed, 0);
    let mut original = fixture
        .catalog
        .contract(fixture.file.plan().roots()[0].operation(), deadline())
        .unwrap();
    original.operation = [251; 32];
    original.funding_operation = [252; 32];
    fixture
        .catalog
        .reserve_version(
            original,
            fixture.catalog.anchor(deadline()).unwrap(),
            deadline(),
        )
        .unwrap();
    let mut budget =
        NativeCellPagedShardRecoveryBudgetV2::new(fixture.recovery_limits(&request, 1)).unwrap();
    assert!(fixture.recover_paged(request, &mut budget).is_err());
    assert_eq!(budget.usage().plan_attempts_committed, 0);
    assert_eq!(fixture.recovery_ledger(), ledger);
    assert_eq!(fixture.budgets.report().unwrap(), money);
}

#[test]
fn native_paged_recovery_completes_original_pending_within_three_passes_and_six_rows() {
    let mut fixture = PagedFixture::new();
    fixture.use_six_row_delivery_cache("six-row-pending.sqlite");
    let height = fixture
        .node
        .native_funding_observation(fixture.request.slots[0].policy.source)
        .unwrap()
        .anchor
        .height;
    // A normal stopping point: physical delivery finished, while the final
    // original M12 intent has not yet recorded Done. No journal is rewound.
    for page_index in 0..fixture.file.plan().page_count() {
        let page = fixture.file.read_page(page_index, deadline()).unwrap();
        for (local, chunk) in page.chunks().iter().enumerate() {
            fixture
                .file
                .stage_chunk_from_catalog(
                    page_index,
                    local,
                    &mut fixture.catalog,
                    &fixture.cache,
                    height,
                    deadline(),
                )
                .unwrap();
            let base = (page.start_chunk() + local) * 6;
            for slot in 0..6 {
                let entry = fixture.request.slots[base + slot].clone();
                if base + slot == 17 {
                    fixture
                        .budgets
                        .open_budget(&mut fixture.node, entry.policy.clone())
                        .unwrap();
                    fixture
                        .budgets
                        .reserve(&mut fixture.node, entry.claim.clone())
                        .unwrap();
                    fixture.providers[slot]
                        .reserve(&entry.contract, entry.contract.operation(), deadline())
                        .unwrap();
                    let owner = entry.contract.owner();
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
                    fixture.providers[slot]
                        .publish(
                            &entry.contract,
                            entry.contract.operation(),
                            &fixture.cache,
                            deadline(),
                        )
                        .unwrap();
                } else {
                    fixture
                        .node
                        .retain_native_cell_shard(
                            &mut fixture.budgets,
                            &mut fixture.providers[slot],
                            &fixture.cache,
                            entry,
                            deadline(),
                        )
                        .unwrap();
                }
            }
            for contract in chunk.slots() {
                fixture
                    .cache
                    .discard_manifest_until(contract.manifest(), deadline())
                    .unwrap();
            }
        }
    }
    let before = fixture.recovery_ledger();
    let request = fixture.recovery_request(&[]);
    let limits = fixture.recovery_limits(&request, 1);
    assert_eq!(limits.maximum_provider_reads, 54);
    let mut budget = NativeCellPagedShardRecoveryBudgetV2::new(limits).unwrap();
    let result = fixture.recover_paged(request, &mut budget).unwrap();
    assert_eq!((result.pages.len(), result.slots.len()), (2, 18));
    assert_eq!(result.usage.provider_reads_committed, 54);
    assert_eq!(result.codec_usage.attempts_committed, 6);
    assert_eq!(result.usage.repairs_committed, 0);
    assert_eq!(result.usage.repair_bytes_committed, 0);
    assert!(result.detected_damage.is_empty() && result.actions.is_empty());
    assert_eq!(
        result.slots[17].native.replay,
        NativeBudgetReplayV1::Pending
    );
    assert!(result.slots[..17]
        .iter()
        .all(|row| row.native.replay == NativeBudgetReplayV1::Done));
    let entry = &fixture.request.slots[17];
    let owner = entry.contract.owner();
    let check = trnm_service_settlement::native_budget::NativeBudgetEffectCheckV1 {
        policy: &entry.policy,
        claim: &entry.claim,
        operation: entry.contract.operation(),
        effect: entry
            .contract
            .retention_contract()
            .commitment(fixture.providers[5].store_id()),
        window: Some((owner.retain_from_height, owner.retain_until_height)),
    };
    assert_eq!(
        fixture
            .budgets
            .check_effects(&mut fixture.node, &[check])
            .unwrap(),
        vec![NativeBudgetReplayV1::Done]
    );
    assert_eq!(fixture.recovery_ledger(), before);
    let usage = fixture.cache.cache_usage().unwrap();
    assert_eq!(
        (usage.logical_bytes, usage.chunk_rows, usage.manifest_rows),
        (0, 0, 0)
    );
}
