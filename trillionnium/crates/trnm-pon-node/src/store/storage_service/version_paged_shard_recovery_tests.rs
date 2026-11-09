//! Real native tasks, original provider arenas and a two-shard staging quota.
//! Original files/CAS and even the catalog payload are absent as repair sources.

use super::*;

type PhysicalDebitRow = (Vec<u8>, u8, u64, u64);

impl PagedFixture {
    fn retained_for_recovery() -> Self {
        let mut fixture = Self::new();
        let mut verification = NativeCellRetainedShardVerificationBudgetV1::new(
            Instant::now() + Duration::from_secs(30),
            6,
            2 * fixture.input_bytes,
            2 * fixture.reconstruction_bytes,
        );
        let held = fixture
            .observe(fixture.request.clone(), &mut verification)
            .unwrap();
        assert_eq!(held.pages.len(), 2);
        assert_eq!(held.slots.len(), 18);
        assert!(held
            .slots
            .iter()
            .all(|row| row.native.replay == NativeBudgetReplayV1::Done));
        let mut staging_config = cache_config();
        // A codeword with four valid targets needs at most two missing shards.
        // Six repairs across three chunks cannot accumulate in this cache.
        staging_config.max_chunk_rows = 2;
        staging_config.max_manifest_rows = 2;
        let staging = CellStoreV1::open(
            &fixture.directory.path().join("recovery.sqlite"),
            staging_config,
        )
        .unwrap();
        let previous = std::mem::replace(&mut fixture.cache, staging);
        drop(previous);
        fs::remove_file(fixture.directory.path().join("delivery.sqlite")).unwrap();
        let mut original = fs::OpenOptions::new()
            .write(true)
            .open(
                fixture
                    .directory
                    .path()
                    .join("catalog/objects/payload.arena"),
            )
            .unwrap();
        let original_size = original.metadata().unwrap().len();
        assert_eq!(original_size, 65_536);
        original
            .write_all(&vec![0; original_size as usize])
            .unwrap();
        original.sync_all().unwrap();
        fixture.assert_recovery_cache_empty();
        fixture
    }

    fn fund_recovery(&mut self, index: usize, nonce: u64) -> NativeCellShardRepairRequestV1 {
        let contract = &self.request.slots[index].contract;
        let beneficiary = contract.placement().placements[index % 6].repair_owner;
        let budget = hash(
            b"TEST_NATIVE_PAGED_RECOVERY_BUDGET",
            &[&nonce.to_le_bytes()],
        );
        let claim = hash(b"TEST_NATIVE_PAGED_RECOVERY_CLAIM", &[&nonce.to_le_bytes()]);
        let operation = hash(
            b"TEST_NATIVE_PAGED_RECOVERY_OPERATION",
            &[&nonce.to_le_bytes()],
        );
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
    ) -> NativeCellPagedShardRecoveryRequestV2 {
        let mut entries = vec![None; self.request.slots.len()];
        for (index, repair) in repairs {
            assert!(entries[*index].replace(repair.clone()).is_none());
        }
        NativeCellPagedShardRecoveryRequestV2 {
            storage: self.request.clone(),
            repairs: entries,
        }
    }

    fn recovery_limits(
        &self,
        request: &NativeCellPagedShardRecoveryRequestV2,
        attempts: u32,
    ) -> NativeCellShardRecoveryLimitsV1 {
        let authorized = request
            .repairs
            .iter()
            .filter(|repair| repair.is_some())
            .count();
        let repair_bytes: u64 = request
            .repairs
            .iter()
            .enumerate()
            .filter(|(_, repair)| repair.is_some())
            .map(|(index, _)| self.request.slots[index].contract.manifest().size())
            .sum();
        let count = u64::from(attempts);
        NativeCellShardRecoveryLimitsV1 {
            deadline: Instant::now() + Duration::from_secs(30),
            maximum_plan_attempts: attempts,
            maximum_provider_reads: count
                * (3 * self.request.slots.len() as u64 + authorized as u64),
            maximum_input_bytes: count * (6 * self.input_bytes + repair_bytes),
            maximum_reconstruction_bytes: count * 3 * self.reconstruction_bytes,
            maximum_repairs: count * authorized as u64,
            maximum_repair_bytes: count * repair_bytes,
            maximum_cpu_ns: count * 5_000_000_000,
            cpu_ns_per_attempt: 5_000_000_000,
        }
    }

    fn recovery_allowance(
        &self,
        request: &NativeCellPagedShardRecoveryRequestV2,
        attempts: u32,
    ) -> NativeCellPagedShardRecoveryBudgetV2 {
        NativeCellPagedShardRecoveryBudgetV2::new(self.recovery_limits(request, attempts)).unwrap()
    }

    fn recover_paged(
        &mut self,
        request: NativeCellPagedShardRecoveryRequestV2,
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

    fn damage_recovery_slot(&self, index: usize) {
        let path = self
            .directory
            .path()
            .join(format!("provider-{}", index % 6));
        let connection = rusqlite::Connection::open(path.join("retention.sqlite")).unwrap();
        let operation = self.request.slots[index].contract.operation();
        let position: u64 = connection
            .query_row(
                "SELECT position FROM obligations WHERE operation=?1",
                [operation.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        drop(connection);
        let mut target = fs::OpenOptions::new()
            .write(true)
            .open(path.join("payload.arena"))
            .unwrap();
        target.seek(SeekFrom::Start(position)).unwrap();
        target.write_all(&[0xff]).unwrap();
        target.sync_all().unwrap();
    }

    fn recovery_ledger(&self) -> Vec<Vec<PhysicalDebitRow>> {
        (0..6)
            .map(|slot| physical_debits(&self.directory.path().join(format!("provider-{slot}"))))
            .collect()
    }

    fn assert_recovery_cache_empty(&self) {
        let usage = self.cache.cache_usage().unwrap();
        assert_eq!(usage.logical_bytes, 0);
        assert_eq!(usage.chunk_rows, 0);
        assert_eq!(usage.manifest_rows, 0);
    }

    fn recovery_target_wire(&mut self, index: usize) -> Vec<u8> {
        let contract = &self.request.slots[index].contract;
        self.providers[index % 6]
            .read(
                contract.binding(),
                contract.operation(),
                deadline(),
                &mut || Ok(()),
            )
            .unwrap()
            .shard()
            .encode()
    }

    fn stage_recovery_target(&self, index: usize, wire: &[u8]) {
        let contract = &self.request.slots[index].contract;
        CellRs46ShardProviderV1::cache_shard(
            contract,
            contract.operation(),
            wire,
            &self.cache,
            deadline(),
        )
        .unwrap();
    }

    fn reopen_recovery_owners(self) -> Self {
        let anchor = self.catalog.anchor(deadline()).unwrap();
        let pin = self.file.commitment();
        let Self {
            directory,
            node,
            catalog,
            file,
            providers,
            cache,
            budgets,
            request,
            input_bytes,
            reconstruction_bytes,
        } = self;
        drop(catalog);
        drop(file);
        drop(providers);
        drop(budgets);
        let catalog = CellVersionRetentionStoreV3::open(
            &directory.path().join("catalog"),
            version_config(),
            anchor,
        )
        .unwrap();
        let file = CellPagedRetainedShardPlanFileV2::open(
            &directory.path().join("paged-plan"),
            pin,
            deadline(),
        )
        .unwrap();
        let providers = provider_configs()
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
        let budgets =
            NativeBudgetStoreV1::open(&directory.path().join("budgets.sqlite"), config(&node))
                .unwrap();
        Self {
            directory,
            node,
            catalog,
            file,
            providers,
            cache,
            budgets,
            request,
            input_bytes,
            reconstruction_bytes,
        }
    }
}

#[test]
fn native_paged_shard_recovery_uses_four_targets_per_chunk_and_reopens_done() {
    let mut fixture = PagedFixture::retained_for_recovery();
    let indices = [4, 5, 10, 11, 16, 17];
    let repairs: Vec<_> = indices
        .iter()
        .enumerate()
        .map(|(nonce, index)| (*index, fixture.fund_recovery(*index, nonce as u64 + 1)))
        .collect();
    let request = fixture.recovery_request(&repairs);
    let mut budget = fixture.recovery_allowance(&request, 2);
    let before = fixture.recovery_ledger();
    for index in indices {
        fixture.damage_recovery_slot(index);
    }
    let first = fixture.recover_paged(request.clone(), &mut budget).unwrap();
    assert_eq!(first.plan, fixture.file.commitment());
    assert_eq!(first.retained, fixture.file.plan().retained_commitment());
    assert_eq!(first.pages.len(), 2);
    assert_eq!(
        (first.pages[0].start_chunk, first.pages[0].chunk_count),
        (0, 2)
    );
    assert_eq!(
        (first.pages[1].start_chunk, first.pages[1].chunk_count),
        (2, 1)
    );
    assert_eq!(first.slots.len(), 18);
    assert_eq!(first.detected_damage.len(), 6);
    assert_eq!(first.actions.len(), 6);
    assert!(first
        .actions
        .iter()
        .all(|row| row.native.replay == NativeBudgetReplayV1::New));
    assert!(first
        .slots
        .iter()
        .all(|row| row.native.replay == NativeBudgetReplayV1::Done));
    assert_eq!(first.usage.plan_attempts_committed, 1);
    assert_eq!(first.usage.provider_reads_committed, 60);
    assert_eq!(first.usage.repairs_committed, 6);
    assert_eq!(
        first.usage.reconstruction_bytes_committed,
        3 * fixture.reconstruction_bytes
    );
    assert_eq!(first.codec_usage.attempts_committed, 9);
    assert!(first.cpu.observed_ns > 0 && first.cpu.observed_ns <= first.cpu.ceiling_ns);
    fixture.assert_recovery_cache_empty();
    let repaired = fixture.recovery_ledger();
    for (slot, (old, actual)) in before.iter().zip(&repaired).enumerate() {
        assert_eq!(old.len(), actual.len());
        for (old, actual) in old.iter().zip(actual) {
            assert_eq!((&old.0, old.1, old.2), (&actual.0, actual.1, actual.2));
        }
        let expected: u64 = indices
            .iter()
            .filter(|index| **index % 6 == slot)
            .map(|index| fixture.request.slots[*index].contract.manifest().size())
            .sum();
        assert_eq!(actual.iter().map(|row| row.3).sum::<u64>(), expected);
    }
    let money = fixture.budgets.report().unwrap();
    assert_eq!(money["budgets"].as_array().unwrap().len(), 28);
    // Model a process stop after original repairs finished but before disposal.
    // These bytes come from the real original target, under the same descriptors.
    for index in [4, 5] {
        let wire = fixture.recovery_target_wire(index);
        fixture.stage_recovery_target(index, &wire);
    }
    assert_eq!(fixture.cache.cache_usage().unwrap().chunk_rows, 2);
    fixture = fixture.reopen_recovery_owners();
    let repeat = fixture.recover_paged(request.clone(), &mut budget).unwrap();
    assert!(repeat.detected_damage.is_empty());
    assert_eq!(repeat.pages.len(), 2);
    assert_eq!(repeat.actions.len(), 6);
    assert!(repeat
        .actions
        .iter()
        .all(|row| row.native.replay == NativeBudgetReplayV1::Done));
    assert_eq!(repeat.usage.plan_attempts_committed, 2);
    assert_eq!(repeat.usage.repairs_committed, 6);
    assert_eq!(repeat.codec_usage.attempts_committed, 15);
    assert_eq!(fixture.budgets.report().unwrap(), money);
    assert_eq!(fixture.recovery_ledger(), repaired);
    fixture.assert_recovery_cache_empty();
    let exhausted = fixture.recover_paged(request, &mut budget).unwrap_err();
    assert!(exhausted.to_string().contains("RECOVERY_BUDGET"));
    assert_eq!(exhausted.usage, repeat.usage);
    assert_eq!(exhausted.codec_usage, repeat.codec_usage);
    assert_eq!(fixture.budgets.report().unwrap(), money);
    assert_eq!(fixture.recovery_ledger(), repaired);
}

#[test]
fn native_paged_shard_recovery_last_page_authority_and_quorum_precede_any_new_repair() {
    let mut fixture = PagedFixture::retained_for_recovery();
    let early = fixture.fund_recovery(4, 20);
    fixture.damage_recovery_slot(4);
    fixture.damage_recovery_slot(17);
    let incomplete = fixture.recovery_request(&[(4, early.clone())]);
    let mut budget = fixture.recovery_allowance(&incomplete, 1);
    let before = fixture.recovery_ledger();
    let money = fixture.budgets.report().unwrap();
    let denied = fixture.recover_paged(incomplete, &mut budget).unwrap_err();
    assert!(denied.to_string().contains("FRESH_AUTHORITY_REQUIRED"));
    assert_eq!(denied.detected_damage.len(), 2);
    assert!(denied.completed_actions.is_empty());
    assert_eq!(denied.usage.plan_attempts_committed, 1);
    assert_eq!(denied.codec_usage.attempts_committed, 2);
    assert_eq!(fixture.recovery_ledger(), before);
    assert_eq!(fixture.budgets.report().unwrap(), money);
    fixture.assert_recovery_cache_empty();
    let mut repairs = vec![(4, early)];
    for index in 15..18 {
        repairs.push((index, fixture.fund_recovery(index, index as u64 + 20)));
        fixture.damage_recovery_slot(index);
    }
    let request = fixture.recovery_request(&repairs);
    let mut budget = fixture.recovery_allowance(&request, 1);
    let denied = fixture
        .recover_paged(request.clone(), &mut budget)
        .unwrap_err();
    assert!(denied.to_string().contains("FOUR_ORIGINAL_SHARDS_REQUIRED"));
    assert_eq!(denied.detected_damage.len(), 4);
    assert!(denied.completed_actions.is_empty());
    assert_eq!(denied.usage.plan_attempts_committed, 1);
    assert_eq!(denied.usage.repairs_committed, 4);
    assert_eq!(denied.codec_usage.attempts_committed, 2);
    assert_eq!(fixture.recovery_ledger(), before);
    assert_eq!(fixture.budgets.report().unwrap(), money);
    fixture.assert_recovery_cache_empty();
    let exhausted = fixture.recover_paged(request, &mut budget).unwrap_err();
    assert!(exhausted.to_string().contains("RECOVERY_BUDGET"));
    assert_eq!(exhausted.usage, denied.usage);
    assert_eq!(exhausted.codec_usage, denied.codec_usage);
}

#[test]
fn native_paged_shard_recovery_last_page_repair_bytes_precede_any_new_repair() {
    let mut fixture = PagedFixture::retained_for_recovery();
    let contract = fixture.request.slots[17].contract.clone();
    let wire = fixture.recovery_target_wire(17);
    // Exhaust the original two-copy allowance through real native repair
    // operations. No ledger row, checksum or byte counter is edited by a test.
    for nonce in [60, 61] {
        fixture.stage_recovery_target(17, &wire);
        fixture.damage_recovery_slot(17);
        let repair = fixture.fund_recovery(17, nonce);
        let observed = fixture
            .node
            .repair_native_cell_shard(
                &mut fixture.budgets,
                &mut fixture.providers[5],
                &fixture.cache,
                repair,
                deadline(),
            )
            .unwrap();
        assert_eq!(observed.native.replay, NativeBudgetReplayV1::New);
    }
    fixture
        .cache
        .discard_manifest_until(contract.manifest(), deadline())
        .unwrap();
    fixture.assert_recovery_cache_empty();
    let early = fixture.fund_recovery(4, 62);
    let late = fixture.fund_recovery(17, 63);
    let request = fixture.recovery_request(&[(4, early), (17, late)]);
    fixture.damage_recovery_slot(4);
    fixture.damage_recovery_slot(17);
    let before = fixture.recovery_ledger();
    let original = before[5]
        .iter()
        .find(|row| row.0.as_slice() == contract.operation().as_slice())
        .unwrap();
    assert_eq!(original.3, 2 * contract.manifest().size());
    let money = fixture.budgets.report().unwrap();
    let mut budget = fixture.recovery_allowance(&request, 1);
    let denied = fixture.recover_paged(request, &mut budget).unwrap_err();
    assert!(denied.to_string().contains("repair capacity exhausted"));
    assert_eq!(denied.detected_damage.len(), 2);
    assert!(denied.completed_actions.is_empty());
    assert_eq!(denied.usage.plan_attempts_committed, 1);
    assert_eq!(denied.usage.repairs_committed, 2);
    assert_eq!(denied.codec_usage.attempts_committed, 3);
    assert_eq!(fixture.recovery_ledger(), before);
    assert_eq!(fixture.budgets.report().unwrap(), money);
    fixture.assert_recovery_cache_empty();
}

#[test]
fn native_paged_shard_recovery_pending_and_done_never_redispatch_original_repairs() {
    let mut fixture = PagedFixture::retained_for_recovery();
    fixture.damage_recovery_slot(17);
    let pending = fixture.fund_recovery(17, 70);
    // This real single-slot operation persists M12 Pending before discovering
    // the empty repair source. Its uncertainty is not a new copy allowance.
    assert!(fixture
        .node
        .repair_native_cell_shard(
            &mut fixture.budgets,
            &mut fixture.providers[5],
            &fixture.cache,
            pending.clone(),
            deadline(),
        )
        .is_err());
    let early = fixture.fund_recovery(4, 71);
    fixture.damage_recovery_slot(4);
    let original = fixture.recovery_request(&[(4, early.clone()), (17, pending.clone())]);
    let physical = fixture.recovery_ledger();
    let unknown_money = fixture.budgets.report().unwrap();
    let mut allowance = fixture.recovery_allowance(&original, 1);
    let denied = fixture
        .recover_paged(original.clone(), &mut allowance)
        .unwrap_err();
    assert!(denied.to_string().contains("FRESH_AUTHORITY_REQUIRED"));
    assert_eq!(denied.detected_damage.len(), 2);
    assert!(denied.completed_actions.is_empty());
    assert_eq!(denied.usage.plan_attempts_committed, 1);
    assert_eq!(denied.usage.repairs_committed, 1);
    assert_eq!(fixture.budgets.report().unwrap(), unknown_money);
    assert_eq!(fixture.recovery_ledger(), physical);
    fixture.assert_recovery_cache_empty();
    let fresh = fixture.fund_recovery(17, 72);
    assert_ne!(fresh.policy.source, pending.policy.source);
    let authorized = fixture.recovery_request(&[(4, early), (17, fresh)]);
    let mut allowance = fixture.recovery_allowance(&authorized, 1);
    let restored = fixture.recover_paged(authorized, &mut allowance).unwrap();
    assert_eq!(restored.actions.len(), 2);
    assert!(restored
        .actions
        .iter()
        .all(|row| row.native.replay == NativeBudgetReplayV1::New));
    let repaired = fixture.recovery_ledger();
    fixture.assert_recovery_cache_empty();
    let mut allowance = fixture.recovery_allowance(&original, 2);
    let reconciled = fixture
        .recover_paged(original.clone(), &mut allowance)
        .unwrap();
    assert_eq!(reconciled.actions.len(), 2);
    let old = reconciled
        .actions
        .iter()
        .find(|row| row.repair_operation == pending.repair_operation)
        .unwrap();
    assert_eq!(old.native.replay, NativeBudgetReplayV1::Pending);
    assert_eq!(reconciled.usage.repairs_committed, 0);
    assert_eq!(fixture.recovery_ledger(), repaired);
    fixture.assert_recovery_cache_empty();
    let complete_money = fixture.budgets.report().unwrap();
    let done = fixture
        .recover_paged(original.clone(), &mut allowance)
        .unwrap();
    assert!(done
        .actions
        .iter()
        .all(|row| row.native.replay == NativeBudgetReplayV1::Done));
    assert_eq!(done.usage.repairs_committed, 0);
    assert_eq!(fixture.budgets.report().unwrap(), complete_money);
    assert_eq!(fixture.recovery_ledger(), repaired);
    fixture.assert_recovery_cache_empty();
    fixture.damage_recovery_slot(17);
    let mut allowance = fixture.recovery_allowance(&original, 1);
    let refused = fixture.recover_paged(original, &mut allowance).unwrap_err();
    assert!(refused.to_string().contains("FRESH_AUTHORITY_REQUIRED"));
    assert_eq!(refused.usage.repairs_committed, 0);
    assert!(refused.completed_actions.is_empty());
    assert_eq!(fixture.budgets.report().unwrap(), complete_money);
    assert_eq!(fixture.recovery_ledger(), repaired);
    fixture.assert_recovery_cache_empty();
}

#[test]
fn native_paged_shard_recovery_global_claims_and_cumulative_limits_fail_before_effects() {
    let mut fixture = PagedFixture::retained_for_recovery();
    let early = fixture.fund_recovery(4, 80);
    let late = fixture.fund_recovery(17, 81);
    let request = fixture.recovery_request(&[(4, early), (17, late)]);
    let money = fixture.budgets.report().unwrap();
    let physical = fixture.recovery_ledger();
    let mut omitted = request.clone();
    omitted.repairs.pop();
    let mut unfunded = request.clone();
    unfunded.repairs[17].as_mut().unwrap().policy.source = NativeFundingSourceV1::Task([9; 32]);
    let mut wrong_owner = request.clone();
    wrong_owner.repairs[17].as_mut().unwrap().claim.beneficiary = public(0);
    let mut alias = request.clone();
    let changed = alias.repairs[17].as_mut().unwrap();
    changed.repair_operation = fixture.file.plan().original_identities().next().unwrap();
    changed.claim.subject = native_cell_shard_repair_subject_v1(
        &fixture.providers[5],
        &fixture.request.slots[17].contract,
        changed.repair_operation,
        changed.claim.claim,
    );
    for refused in [omitted, unfunded, wrong_owner, alias] {
        let mut allowance = fixture.recovery_allowance(&request, 1);
        assert!(fixture.recover_paged(refused, &mut allowance).is_err());
        assert_eq!(allowance.usage().plan_attempts_committed, 0);
        assert_eq!(allowance.codec_usage().attempts_committed, 0);
        assert_eq!(fixture.budgets.report().unwrap(), money);
        assert_eq!(fixture.recovery_ledger(), physical);
    }
    let mut limits = fixture.recovery_limits(&request, 1);
    limits.maximum_input_bytes -= 1;
    let mut low = NativeCellPagedShardRecoveryBudgetV2::new(limits).unwrap();
    let refused = fixture
        .recover_paged(request.clone(), &mut low)
        .unwrap_err();
    assert!(refused.to_string().contains("RECOVERY_BUDGET"));
    assert_eq!(low.usage().plan_attempts_committed, 0);
    let mut limits = fixture.recovery_limits(&request, 1);
    limits.deadline = Instant::now();
    let mut late = NativeCellPagedShardRecoveryBudgetV2::new(limits).unwrap();
    assert!(fixture.recover_paged(request.clone(), &mut late).is_err());
    assert_eq!(late.usage().plan_attempts_committed, 0);
    let mut limits = fixture.recovery_limits(&request, 1);
    limits.maximum_cpu_ns = 1;
    limits.cpu_ns_per_attempt = 1;
    let mut stopped = NativeCellPagedShardRecoveryBudgetV2::new(limits).unwrap();
    let refused = fixture.recover_paged(request, &mut stopped).unwrap_err();
    assert!(refused.to_string().contains("CPU"));
    assert_eq!(refused.usage.plan_attempts_committed, 1);
    assert_eq!(refused.usage.cpu_ns_committed, 1);
    assert!(refused.detected_damage.is_empty());
    assert!(refused.completed_actions.is_empty());
    assert_eq!(refused.codec_usage.attempts_committed, 0);
    assert_eq!(fixture.budgets.report().unwrap(), money);
    assert_eq!(fixture.recovery_ledger(), physical);
    fixture.assert_recovery_cache_empty();
}
