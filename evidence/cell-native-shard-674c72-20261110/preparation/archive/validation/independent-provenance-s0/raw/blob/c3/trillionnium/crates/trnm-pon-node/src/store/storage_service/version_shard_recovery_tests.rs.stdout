//! Complete original native funding and real provider arenas. No reconstruction
//! test obtains its repair payload from the deleted original source/CAS.

use super::*;

type PhysicalDebitRow = (Vec<u8>, u8, u64, u64);

struct Fixture {
    dir: tempfile::TempDir,
    node: Node,
    budgets: NativeBudgetStoreV1,
    catalog: CellVersionRetentionStoreV3,
    file: CellRetainedShardPlanFileV1,
    providers: [CellRs46ShardProviderV1; 6],
    storage: NativeCellRetainedShardPlanRequestV1,
    cache: Option<CellStoreV1>,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut node = open_node(
            &dir.path().join("node"),
            StateBackend::PermanentAccountGrowthV2,
        );
        let (source, mut contract) = version_material(dir.path());
        contract.retain_until_height = 40;
        contract.repair_deadline_height = 35;
        for object in &mut contract.objects {
            object.retain_until_height = 40;
        }
        let catalog_path = dir.path().join("catalog");
        let mut catalog =
            CellVersionRetentionStoreV3::create(&catalog_path, version_config()).unwrap();
        let root = funded_version(&mut node, &catalog, contract);
        let journal = dir.path().join("budgets.sqlite");
        let mut budgets = NativeBudgetStoreV1::open(&journal, config(&node)).unwrap();
        node.retain_native_cell_version(
            &mut budgets,
            &mut catalog,
            &source,
            root.clone(),
            deadline(),
        )
        .unwrap();
        let plan_path = dir.path().join("complete.crp1");
        let plan_request = CellRetainedShardPlanRequestV1 {
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
                .map(|chunk| std::array::from_fn(|slot| [191 + chunk as u8 * 6 + slot as u8; 32]))
                .collect(),
        };
        let file = CellRetainedShardPlanFileV1::create(
            &plan_path,
            &mut catalog,
            &source,
            plan_request,
            deadline(),
        )
        .unwrap();
        assert_eq!(file.plan().chunks().len(), 3);
        let mut providers = Self::providers(dir.path(), false);
        let mut entries = Vec::new();
        for (index, slot) in file
            .plan()
            .chunks()
            .iter()
            .flat_map(|chunk| chunk.slots())
            .enumerate()
        {
            let bytes = slot.manifest().size();
            let owner = slot.owner();
            let resources = NativeBudgetResourcesV1::Storage {
                retained_bytes: bytes,
                retained_byte_blocks: bytes
                    * (owner.retain_until_height - owner.retain_from_height),
            };
            let budget = [220 + index as u8; 32];
            let beneficiary =
                slot.placement().placements[usize::from(owner.slot)].responsible_owner;
            entries.push(NativeCellShardRetentionRequestV1 {
                policy: NativeBudgetPolicyV1 {
                    budget,
                    source: fund_provider(&mut node, beneficiary, 100, 41 + u64::from(owner.slot)),
                    monetary_cap: 100,
                    deadline: 40,
                    resource_cap: resources.clone(),
                    max_inflight: 1,
                },
                claim: NativeBudgetClaimV1 {
                    claim: owner.funding_operation,
                    budget,
                    subject: slot.retention_contract().commitment(owner.provider_store),
                    beneficiary,
                    monetary_reservation: 100,
                    resource_reservation: resources,
                },
                contract: slot.clone(),
            });
        }
        let storage = NativeCellRetainedShardPlanRequestV1 { slots: entries };
        let wire_bytes: u64 = storage
            .slots
            .iter()
            .map(|entry| entry.contract.manifest().size())
            .sum();
        let source_bytes: u64 = file
            .plan()
            .chunks()
            .iter()
            .map(|chunk| u64::from(chunk.binding().source_bytes()))
            .sum();
        let mut verify = NativeCellRetainedShardVerificationBudgetV1::new(
            Instant::now() + Duration::from_secs(30),
            3,
            wire_bytes,
            wire_bytes + source_bytes,
        );
        let held = node
            .retain_native_cell_shard_plan(
                &mut budgets,
                NativeCellRetainedShardPlanTargetsV1 {
                    catalog: &catalog,
                    plan_file: &file,
                    providers: &mut providers,
                    cache: &source,
                },
                storage.clone(),
                &mut verify,
            )
            .unwrap();
        assert_eq!(held.slots.len(), 18);
        assert!(held
            .slots
            .iter()
            .all(|slot| slot.native.replay == NativeBudgetReplayV1::New));
        assert_eq!(held.observed_at.height, 22);
        let anchor = catalog.anchor(deadline()).unwrap();
        let pin = file.commitment();
        drop(source);
        drop(catalog);
        drop(providers);
        drop(file);
        drop(budgets);
        for name in [
            "runtime.bin",
            "base.bin",
            "tokenizer.json",
            "version-cache.sqlite",
        ] {
            fs::remove_file(dir.path().join(name)).unwrap();
        }
        let catalog =
            CellVersionRetentionStoreV3::open(&catalog_path, version_config(), anchor).unwrap();
        let file = CellRetainedShardPlanFileV1::open(&plan_path, pin, deadline()).unwrap();
        let providers = Self::providers(dir.path(), true);
        let budgets = NativeBudgetStoreV1::open(&journal, config(&node)).unwrap();
        let cache =
            Some(CellStoreV1::open(&dir.path().join("recovery.sqlite"), cache_config()).unwrap());
        let result = Self {
            dir,
            node,
            budgets,
            catalog,
            file,
            providers,
            storage,
            cache,
        };
        result.assert_empty_cache();
        result
    }

    fn providers(path: &Path, reopen: bool) -> [CellRs46ShardProviderV1; 6] {
        provider_configs()
            .into_iter()
            .enumerate()
            .map(|(slot, config)| {
                let path = path.join(format!("provider-{slot}"));
                if reopen {
                    CellRs46ShardProviderV1::open(&path, config).unwrap()
                } else {
                    CellRs46ShardProviderV1::create(&path, config).unwrap()
                }
            })
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .unwrap()
    }

    fn fund_repair(&mut self, index: usize, nonce: u64) -> NativeCellShardRepairRequestV1 {
        let contract = &self.storage.slots[index].contract;
        let beneficiary = contract.placement().placements[index % 6].repair_owner;
        let budget = hash(b"TEST_NATIVE_PLAN_RECOVERY_BUDGET", &[&nonce.to_le_bytes()]);
        let claim = hash(b"TEST_NATIVE_PLAN_RECOVERY_CLAIM", &[&nonce.to_le_bytes()]);
        let operation = hash(
            b"TEST_NATIVE_PLAN_RECOVERY_OPERATION",
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

    fn request(
        &self,
        repairs: &[(usize, NativeCellShardRepairRequestV1)],
    ) -> NativeCellShardRecoveryRequestV1 {
        let mut entries = vec![None; self.storage.slots.len()];
        for (index, repair) in repairs {
            assert!(entries[*index].replace(repair.clone()).is_none());
        }
        NativeCellShardRecoveryRequestV1 {
            storage: self.storage.clone(),
            repairs: entries,
        }
    }

    fn allowance(
        &self,
        request: &NativeCellShardRecoveryRequestV1,
        attempts: u32,
    ) -> NativeCellShardRecoveryBudgetV1 {
        NativeCellShardRecoveryBudgetV1::new(self.limits(request, attempts)).unwrap()
    }

    fn limits(
        &self,
        request: &NativeCellShardRecoveryRequestV1,
        attempts: u32,
    ) -> NativeCellShardRecoveryLimitsV1 {
        let wire_bytes: u64 = self
            .storage
            .slots
            .iter()
            .map(|entry| entry.contract.manifest().size())
            .sum();
        let original_bytes: u64 = self
            .file
            .plan()
            .chunks()
            .iter()
            .map(|chunk| u64::from(chunk.binding().source_bytes()))
            .sum();
        let authorized: Vec<_> = request
            .repairs
            .iter()
            .enumerate()
            .filter(|(_, repair)| repair.is_some())
            .collect();
        let repair_bytes: u64 = authorized
            .iter()
            .map(|(index, _)| self.storage.slots[*index].contract.manifest().size())
            .sum();
        let count = u64::from(attempts);
        NativeCellShardRecoveryLimitsV1 {
            deadline: Instant::now() + Duration::from_secs(30),
            maximum_plan_attempts: attempts,
            maximum_provider_reads: count
                * (2 * self.storage.slots.len() as u64 + authorized.len() as u64),
            maximum_input_bytes: count * (4 * wire_bytes + repair_bytes),
            maximum_reconstruction_bytes: count * 2 * (wire_bytes + original_bytes),
            maximum_repairs: count * authorized.len() as u64,
            maximum_repair_bytes: count * repair_bytes,
            maximum_cpu_ns: count * 5_000_000_000,
            cpu_ns_per_attempt: 5_000_000_000,
        }
    }

    fn recover(
        &mut self,
        request: NativeCellShardRecoveryRequestV1,
        budget: &mut NativeCellShardRecoveryBudgetV1,
    ) -> std::result::Result<NativeCellShardRecoveryReadbackV1, Box<NativeCellShardRecoveryFailureV1>>
    {
        self.node.recover_native_cell_shard_plan(
            &mut self.budgets,
            NativeCellRetainedShardPlanTargetsV1 {
                catalog: &self.catalog,
                plan_file: &self.file,
                providers: &mut self.providers,
                cache: self.cache.as_ref().unwrap(),
            },
            request,
            budget,
        )
    }

    fn damage(&self, slot: usize) {
        damage(&self.dir.path().join(format!("provider-{slot}")));
    }
    fn ledger(&self) -> Vec<Vec<PhysicalDebitRow>> {
        (0..6)
            .map(|slot| physical_debits(&self.dir.path().join(format!("provider-{slot}"))))
            .collect()
    }
    fn assert_empty_cache(&self) {
        for slot in &self.storage.slots {
            assert!(self
                .cache
                .as_ref()
                .unwrap()
                .chunk(slot.contract.manifest().chunks()[0].sha256)
                .unwrap()
                .is_none());
        }
    }
    fn clear_cache(&mut self) {
        drop(self.cache.take());
        let path = self.dir.path().join("recovery.sqlite");
        fs::remove_file(&path).unwrap();
        self.cache = Some(CellStoreV1::open(&path, cache_config()).unwrap());
        self.assert_empty_cache();
    }
}

#[test]
fn native_shard_plan_automatic_recovery_uses_four_targets_after_all_sources_are_deleted() {
    let mut fixture = Fixture::new();
    let repairs = [
        (4, fixture.fund_repair(4, 1)),
        (5, fixture.fund_repair(5, 2)),
    ];
    let request = fixture.request(&repairs);
    let mut budget = fixture.allowance(&request, 2);
    let before = fixture.ledger();
    let original_money = fixture.budgets.report().unwrap();
    // The ordinary TCA3 catalog still pins the full retained set, but even its
    // own original payload is unavailable as a hidden reconstruction fallback.
    let mut original_arena = fs::OpenOptions::new()
        .write(true)
        .open(fixture.dir.path().join("catalog/objects/payload.arena"))
        .unwrap();
    let original_size = original_arena.metadata().unwrap().len();
    assert_eq!(original_size, 65_536);
    original_arena
        .write_all(&vec![0; original_size as usize])
        .unwrap();
    original_arena.sync_all().unwrap();
    drop(original_arena);
    fixture.damage(4);
    fixture.damage(5);
    let mut incomplete_authority = request.clone();
    incomplete_authority.repairs[5] = None;
    let mut denied_budget = fixture.allowance(&incomplete_authority, 1);
    let denied = fixture
        .recover(incomplete_authority, &mut denied_budget)
        .unwrap_err();
    assert!(denied.to_string().contains("FRESH_AUTHORITY_REQUIRED"));
    assert_eq!(denied.detected_damage.len(), 2);
    assert_eq!(denied.usage.plan_attempts_committed, 1);
    assert_eq!(denied.codec_usage.attempts_committed, 0);
    assert!(denied.completed_actions.is_empty());
    assert_eq!(fixture.budgets.report().unwrap(), original_money);
    assert_eq!(fixture.ledger(), before);
    fixture.assert_empty_cache();
    let result = fixture.recover(request.clone(), &mut budget).unwrap();
    assert_eq!(result.slots.len(), 18);
    assert_eq!(result.detected_damage.len(), 2);
    assert_eq!(result.actions.len(), 2);
    assert!(result
        .actions
        .iter()
        .all(|action| action.native.replay == NativeBudgetReplayV1::New));
    assert!(result
        .slots
        .iter()
        .all(|slot| slot.native.replay == NativeBudgetReplayV1::Done));
    assert_eq!(result.usage.plan_attempts_committed, 1);
    assert_eq!(result.usage.repairs_committed, 2);
    assert_eq!(result.codec_usage.attempts_committed, 4);
    assert!(result.cpu.observed_ns > 0 && result.cpu.observed_ns <= result.cpu.ceiling_ns);
    let repaired = fixture.ledger();
    for (slot, (old, actual)) in before.iter().zip(&repaired).enumerate() {
        assert_eq!(old.len(), actual.len());
        for (old, actual) in old.iter().zip(actual) {
            assert_eq!((&old.0, old.1, old.2), (&actual.0, actual.1, actual.2));
        }
        let repaired_bytes: u64 = actual.iter().map(|row| row.3).sum();
        assert_eq!(
            repaired_bytes,
            if slot >= 4 {
                fixture.storage.slots[slot].contract.manifest().size()
            } else {
                0
            }
        );
    }
    let charged = fixture.budgets.report().unwrap();
    assert_eq!(original_money["budgets"].as_array().unwrap().len(), 22);
    assert_eq!(charged["budgets"].as_array().unwrap().len(), 24);
    for action in &result.actions {
        let slot = request
            .storage
            .slots
            .iter()
            .find(|slot| slot.contract.operation() == action.operation)
            .unwrap();
        assert_eq!(
            action.native.target.initial_copy_bytes_committed,
            slot.contract.manifest().size()
        );
        assert_eq!(
            action.native.target.repair_bytes_committed,
            slot.contract.manifest().size()
        );
    }
    fixture.clear_cache();
    // Assignment evaluates its RHS before dropping the old field. Close both
    // owners first so reopening actually observes their durable state.
    drop(fixture.providers);
    fixture.providers = Fixture::providers(fixture.dir.path(), true);
    drop(fixture.budgets);
    fixture.budgets = NativeBudgetStoreV1::open(
        &fixture.dir.path().join("budgets.sqlite"),
        config(&fixture.node),
    )
    .unwrap();
    let repeated = fixture.recover(request, &mut budget).unwrap();
    assert!(repeated.detected_damage.is_empty());
    assert_eq!(repeated.actions.len(), 2);
    assert!(repeated
        .actions
        .iter()
        .all(|action| action.native.replay == NativeBudgetReplayV1::Done));
    assert_eq!(repeated.usage.plan_attempts_committed, 2);
    assert_eq!(repeated.usage.repairs_committed, 2);
    assert_eq!(repeated.codec_usage.attempts_committed, 7);
    assert_eq!(fixture.budgets.report().unwrap(), charged);
    assert_eq!(fixture.ledger(), repaired);
    fixture.assert_empty_cache();
}

#[test]
fn native_shard_plan_recovery_refuses_missing_quorum_without_spending_new_repairs_or_refunding_reads(
) {
    let mut fixture = Fixture::new();
    let repairs = [
        (3, fixture.fund_repair(3, 3)),
        (4, fixture.fund_repair(4, 4)),
        (5, fixture.fund_repair(5, 5)),
    ];
    let request = fixture.request(&repairs);
    let mut budget = fixture.allowance(&request, 1);
    let original = fixture.budgets.report().unwrap();
    let physical = fixture.ledger();
    for slot in 3..6 {
        fixture.damage(slot);
    }
    let failure = fixture.recover(request.clone(), &mut budget).unwrap_err();
    assert!(failure
        .to_string()
        .contains("FOUR_ORIGINAL_SHARDS_REQUIRED"));
    assert_eq!(failure.detected_damage.len(), 3);
    assert!(failure.completed_actions.is_empty());
    assert_eq!(failure.usage.plan_attempts_committed, 1);
    assert_eq!(failure.usage.provider_reads_committed, 39);
    assert_eq!(failure.usage.repairs_committed, 3);
    assert!(failure.usage.input_bytes_committed > 0 && failure.usage.repair_bytes_committed > 0);
    assert_eq!(failure.codec_usage.attempts_committed, 0);
    assert_eq!(fixture.budgets.report().unwrap(), original);
    assert_eq!(fixture.ledger(), physical);
    fixture.assert_empty_cache();
    let again = fixture.recover(request, &mut budget).unwrap_err();
    assert!(again.to_string().contains("RECOVERY_BUDGET"));
    assert!(again.detected_damage.is_empty());
    assert_eq!(again.usage, failure.usage);
    assert_eq!(again.codec_usage, failure.codec_usage);
    assert_eq!(fixture.budgets.report().unwrap(), original);
    assert_eq!(fixture.ledger(), physical);
}

#[test]
fn native_shard_plan_pending_repair_cannot_redispatch_and_needs_independent_new_funding() {
    let mut fixture = Fixture::new();
    fixture.damage(5);
    let pending = fixture.fund_repair(5, 6);
    // A real ordinary M12 intent is admitted before the absent CAS is observed.
    // No physical repair byte has been written; subsequent recovery may only
    // inspect its original target under this same operation and debit.
    assert!(fixture
        .node
        .repair_native_cell_shard(
            &mut fixture.budgets,
            &mut fixture.providers[5],
            fixture.cache.as_ref().unwrap(),
            pending.clone(),
            deadline()
        )
        .is_err());
    let unknown_money = fixture.budgets.report().unwrap();
    let physical = fixture.ledger();
    let pending_request = fixture.request(&[(5, pending.clone())]);
    let mut failed_budget = fixture.allowance(&pending_request, 1);
    let failure = fixture
        .recover(pending_request.clone(), &mut failed_budget)
        .unwrap_err();
    assert!(failure.to_string().contains("chunk digest"));
    assert_eq!(failure.detected_damage.len(), 1);
    assert!(failure.completed_actions.is_empty());
    assert_eq!(failure.usage.plan_attempts_committed, 1);
    assert_eq!(failure.usage.repairs_committed, 0);
    assert_eq!(failure.codec_usage.attempts_committed, 0);
    assert_eq!(fixture.budgets.report().unwrap(), unknown_money);
    assert_eq!(fixture.ledger(), physical);
    fixture.assert_empty_cache();
    // Merely changing an ID under the same claim cannot grant a second write.
    let mut forged = pending_request;
    forged.repairs[5].as_mut().unwrap().repair_operation = [7; 32];
    let changed = forged.repairs[5].as_mut().unwrap();
    changed.claim.subject = native_cell_shard_repair_subject_v1(
        &fixture.providers[5],
        &fixture.storage.slots[5].contract,
        changed.repair_operation,
        changed.claim.claim,
    );
    let mut refused = fixture.allowance(&forged, 1);
    assert!(fixture.recover(forged, &mut refused).is_err());
    assert_eq!(refused.usage().plan_attempts_committed, 0);
    assert_eq!(fixture.budgets.report().unwrap(), unknown_money);
    let fresh = fixture.fund_repair(5, 7);
    assert_ne!(fresh.policy.source, pending.policy.source);
    let fresh_request = fixture.request(&[(5, fresh)]);
    let mut repair_budget = fixture.allowance(&fresh_request, 1);
    let recovered = fixture.recover(fresh_request, &mut repair_budget).unwrap();
    assert_eq!(recovered.actions.len(), 1);
    assert_eq!(
        recovered.actions[0].native.replay,
        NativeBudgetReplayV1::New
    );
    let repaired = fixture.ledger();
    let repair_bytes: u64 = repaired[5].iter().map(|row| row.3).sum();
    assert_eq!(
        repair_bytes,
        fixture.storage.slots[5].contract.manifest().size()
    );
    fixture.clear_cache();
    let old = fixture.request(&[(5, pending)]);
    let mut reconcile_budget = fixture.allowance(&old, 1);
    let reconciled = fixture.recover(old, &mut reconcile_budget).unwrap();
    assert_eq!(reconciled.actions.len(), 1);
    assert_eq!(
        reconciled.actions[0].native.replay,
        NativeBudgetReplayV1::Pending
    );
    assert_eq!(reconciled.usage.repairs_committed, 0);
    assert_eq!(fixture.ledger(), repaired);
    fixture.assert_empty_cache();
}

#[test]
fn native_shard_plan_recovery_preflight_cpu_and_metadata_fail_closed_without_hidden_copies() {
    let mut fixture = Fixture::new();
    let repair = fixture.fund_repair(5, 8);
    let request = fixture.request(&[(5, repair)]);
    let original_money = fixture.budgets.report().unwrap();
    let physical = fixture.ledger();
    let mut omitted = request.clone();
    omitted.storage.slots.pop();
    let mut wrong_owner = request.clone();
    wrong_owner.repairs[5].as_mut().unwrap().claim.beneficiary = public(0);
    let mut alias = request.clone();
    alias.repairs[5].as_mut().unwrap().policy.source = alias.storage.slots[0].policy.source;
    let mut no_original_intent = request.clone();
    // The same descriptor cannot be passed through a new unfunded native
    // source/claim in order to grant an initial write from a recovery entry.
    no_original_intent.storage.slots[0].policy.source = NativeFundingSourceV1::Task([8; 32]);
    for rejected in [omitted, wrong_owner, alias, no_original_intent] {
        let mut budget = fixture.allowance(&request, 1);
        assert!(fixture.recover(rejected, &mut budget).is_err());
        assert_eq!(budget.usage().plan_attempts_committed, 0);
        assert_eq!(fixture.budgets.report().unwrap(), original_money);
        assert_eq!(fixture.ledger(), physical);
    }
    let mut low = fixture.limits(&request, 1);
    low.maximum_input_bytes -= 1;
    let mut budget = NativeCellShardRecoveryBudgetV1::new(low).unwrap();
    let error = fixture.recover(request.clone(), &mut budget).unwrap_err();
    assert!(error.to_string().contains("RECOVERY_BUDGET"));
    assert_eq!(budget.usage().plan_attempts_committed, 0);
    let mut late = fixture.limits(&request, 1);
    late.deadline = Instant::now();
    let mut budget = NativeCellShardRecoveryBudgetV1::new(late).unwrap();
    assert!(fixture.recover(request.clone(), &mut budget).is_err());
    assert_eq!(budget.usage().plan_attempts_committed, 0);
    let mut stopped = fixture.limits(&request, 1);
    stopped.maximum_cpu_ns = 1;
    stopped.cpu_ns_per_attempt = 1;
    let mut budget = NativeCellShardRecoveryBudgetV1::new(stopped).unwrap();
    let error = fixture.recover(request.clone(), &mut budget).unwrap_err();
    assert!(error.to_string().contains("CPU"));
    assert_eq!(error.usage.plan_attempts_committed, 1);
    assert_eq!(error.usage.cpu_ns_committed, 1);
    assert!(error.detected_damage.is_empty());
    assert!(error.completed_actions.is_empty());
    assert_eq!(error.codec_usage.attempts_committed, 0);
    assert_eq!(fixture.budgets.report().unwrap(), original_money);
    assert_eq!(fixture.ledger(), physical);
    // A healthy target does not open or reserve a merely available fresh task.
    let mut budget = fixture.allowance(&request, 1);
    let healthy = fixture.recover(request.clone(), &mut budget).unwrap();
    assert!(healthy.actions.is_empty() && healthy.detected_damage.is_empty());
    assert_eq!(healthy.usage.repairs_committed, 1);
    assert_eq!(fixture.budgets.report().unwrap(), original_money);
    fixture.assert_empty_cache();
    // Lost metadata is not a damaged payload. Earlier successful target reads
    // remain charged, but no original descriptor or repair ID is manufactured.
    let descriptor = fixture
        .dir
        .path()
        .join("provider-5/slot-descriptors-v1")
        .join(hex::encode(fixture.storage.slots[5].contract.operation()));
    let bytes = fs::read(&descriptor).unwrap();
    fs::remove_file(&descriptor).unwrap();
    let mut budget = fixture.allowance(&request, 1);
    let failed = fixture.recover(request.clone(), &mut budget).unwrap_err();
    assert_eq!(failed.usage.plan_attempts_committed, 1);
    assert!(failed.detected_damage.is_empty() && failed.completed_actions.is_empty());
    assert_eq!(failed.codec_usage.attempts_committed, 0);
    assert_eq!(fixture.budgets.report().unwrap(), original_money);
    assert_eq!(fixture.ledger(), physical);
    fixture.assert_empty_cache();
    fs::write(descriptor, bytes).unwrap();
    let mut extra = fixture
        .catalog
        .contract(fixture.file.plan().roots()[0].operation(), deadline())
        .unwrap();
    extra.operation = [175; 32];
    extra.funding_operation = [176; 32];
    fixture
        .catalog
        .reserve_version(
            extra,
            fixture.catalog.anchor(deadline()).unwrap(),
            deadline(),
        )
        .unwrap();
    let mut budget = fixture.allowance(&request, 1);
    let stale = fixture.recover(request, &mut budget).unwrap_err();
    assert!(
        stale.to_string().contains("retained shard plan")
            || stale.to_string().contains("complete service")
    );
    assert_eq!(stale.usage.plan_attempts_committed, 0);
    assert_eq!(fixture.budgets.report().unwrap(), original_money);
    assert_eq!(fixture.ledger(), physical);
}
