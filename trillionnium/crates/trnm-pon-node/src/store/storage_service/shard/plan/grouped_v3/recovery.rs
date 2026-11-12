//! Group repair uses fresh original M12 parents and separately durable children.
use super::*;
use trnm_data_availability::cell::CellRs46ShardRepairRequestV1;
use trnm_service_settlement::native_budget::NativeBudgetResourcesV1;

#[derive(Debug)]
pub struct NativeCellGroupedShardRecoveryBudgetV3 {
    limits: NativeCellShardRecoveryLimitsV1,
    usage: NativeCellShardRecoveryUsageV1,
    codec: CellRs46RepairBudgetV1,
}
impl NativeCellGroupedShardRecoveryBudgetV3 {
    pub fn new(limits: NativeCellShardRecoveryLimitsV1) -> Result<Self> {
        ensure(
            limits.maximum_plan_attempts > 0
                && limits.cpu_ns_per_attempt > 0
                && limits.cpu_ns_per_attempt <= limits.maximum_cpu_ns,
            "NATIVE_CELL_GROUPED_RECOVERY_LIMITS",
        )?;
        let attempts = limits
            .maximum_plan_attempts
            .checked_mul(3 * MAX_GROUPED_CHUNKS_V3 as u32)
            .ok_or("NATIVE_CELL_GROUPED_RECOVERY_LIMITS")?;
        Ok(Self {
            limits,
            usage: NativeCellShardRecoveryUsageV1::default(),
            codec: CellRs46RepairBudgetV1::new(
                limits.deadline,
                attempts,
                limits.maximum_input_bytes,
                limits.maximum_reconstruction_bytes,
            ),
        })
    }
    pub fn usage(&self) -> NativeCellShardRecoveryUsageV1 {
        self.usage
    }
    pub fn codec_usage(&self) -> CellRs46RepairUsageV1 {
        self.codec.usage()
    }
    fn reserve(&mut self, cost: RecoveryCostV3) -> Result<()> {
        let RecoveryCostV3 {
            source,
            wire,
            children,
            authorized_bytes,
            repair_bytes,
            repairs,
            slots,
        } = cost;
        storage_deadline(self.limits.deadline)?;
        let add = |a: u64, b: u64| {
            a.checked_add(b)
                .ok_or("NATIVE_CELL_GROUPED_RECOVERY_BUDGET")
        };
        let next = NativeCellShardRecoveryUsageV1 {
            plan_attempts_committed: self
                .usage
                .plan_attempts_committed
                .checked_add(1)
                .ok_or("NATIVE_CELL_GROUPED_RECOVERY_BUDGET")?,
            provider_reads_committed: add(
                self.usage.provider_reads_committed,
                (slots as u64)
                    .checked_mul(3)
                    .and_then(|n| n.checked_add(children as u64))
                    .ok_or("NATIVE_CELL_GROUPED_RECOVERY_BUDGET")?,
            )?,
            input_bytes_committed: add(
                self.usage.input_bytes_committed,
                wire.checked_mul(6)
                    .and_then(|n| n.checked_add(authorized_bytes))
                    .ok_or("NATIVE_CELL_GROUPED_RECOVERY_BUDGET")?,
            )?,
            reconstruction_bytes_committed: add(
                self.usage.reconstruction_bytes_committed,
                wire.checked_add(source)
                    .and_then(|n| n.checked_mul(3))
                    .ok_or("NATIVE_CELL_GROUPED_RECOVERY_BUDGET")?,
            )?,
            repairs_committed: add(self.usage.repairs_committed, repairs as u64)?,
            repair_bytes_committed: add(self.usage.repair_bytes_committed, repair_bytes)?,
            cpu_ns_committed: add(self.usage.cpu_ns_committed, self.limits.cpu_ns_per_attempt)?,
        };
        ensure(
            next.plan_attempts_committed <= self.limits.maximum_plan_attempts
                && next.provider_reads_committed <= self.limits.maximum_provider_reads
                && next.input_bytes_committed <= self.limits.maximum_input_bytes
                && next.reconstruction_bytes_committed <= self.limits.maximum_reconstruction_bytes
                && next.repairs_committed <= self.limits.maximum_repairs
                && next.repair_bytes_committed <= self.limits.maximum_repair_bytes
                && next.cpu_ns_committed <= self.limits.maximum_cpu_ns,
            "NATIVE_CELL_GROUPED_RECOVERY_BUDGET",
        )?;
        self.usage = next;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct NativeCellGroupedChildCpuV3 {
    pub operation: Hash,
    pub observed_ns: u64,
    pub ceiling_ns: u64,
    pub original_attempt: bool,
}
#[derive(Clone, Debug)]
pub struct NativeCellGroupedShardRecoveryReadbackV3 {
    pub plan: Hash,
    pub observed_at: NativeBudgetAnchorV1,
    pub storage_parents: Vec<NativeCellShardParentGroupReadbackV3>,
    pub repair_parents: Vec<NativeCellShardParentGroupReadbackV3>,
    pub storage_children: usize,
    pub repair_children: usize,
    pub detected_damage: Vec<NativeCellShardDamageV1>,
    pub usage: NativeCellShardRecoveryUsageV1,
    pub codec_usage: CellRs46RepairUsageV1,
    pub cpu: NativeCellShardRecoveryCpuV1,
    pub child_cpu: Vec<NativeCellGroupedChildCpuV3>,
}
#[derive(Debug)]
pub struct NativeCellGroupedShardRecoveryFailureV3 {
    pub error: Error,
    pub usage: NativeCellShardRecoveryUsageV1,
    pub codec_usage: CellRs46RepairUsageV1,
    pub detected_damage: Vec<NativeCellShardDamageV1>,
    pub completed_children: usize,
    pub cpu: Option<NativeCellShardRecoveryCpuV1>,
}
impl std::fmt::Display for NativeCellGroupedShardRecoveryFailureV3 {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.error, out)
    }
}
impl std::error::Error for NativeCellGroupedShardRecoveryFailureV3 {}

fn repair_receipt(child: &NativeCellShardGroupChildV3) -> Hash {
    hash(
        b"trnm.native-cell-group-child-repair-readback.v3\0",
        &[&child.claim.subject],
    )
}

struct RepairPrepared {
    contracts: Vec<[CellRs46ShardContractV1; 6]>,
    anchor: NativeBudgetAnchorV1,
    lookup: BTreeMap<(usize, usize), (usize, usize)>,
    fresh_children: usize,
    repair_bytes: u64,
    authorized_bytes: u64,
}
struct RecoveryCostV3 {
    source: u64,
    wire: u64,
    children: usize,
    authorized_bytes: u64,
    repair_bytes: u64,
    repairs: usize,
    slots: usize,
}
fn preflight(
    node: &mut Node,
    budgets: &NativeBudgetStoreV1,
    targets: &mut NativeCellPagedRetainedShardPlanTargetsV2<'_>,
    request: &NativeCellGroupedShardRepairRequestV3,
    journal: &mut NativeCellShardGroupJournalV3,
    deadline: Instant,
) -> Result<RepairPrepared> {
    ensure(
        !request.storage.groups.is_empty(),
        "NATIVE_CELL_GROUPED_STORAGE_REQUIRED",
    )?;
    let anchor = node
        .native_funding_observation(request.storage.groups[0].policy.source)?
        .anchor;
    let plan = targets.plan_file.commitment();
    let contracts = load_contracts(targets.plan_file, targets.catalog, anchor.height, deadline)?;
    journal.verify_context(
        &journal_context(node, plan, contracts[0][0].owner().owner_generation),
        deadline,
    )?;
    types::validate_groups(
        plan,
        NativeCellShardGroupKindV3::Storage,
        &request.storage.groups,
        &[0, 1, 2, 3, 4, 5],
        &contracts,
        targets.providers,
    )?;
    types::validate_groups(
        plan,
        NativeCellShardGroupKindV3::Repair,
        &request.groups,
        &request.repair_slots,
        &contracts,
        targets.providers,
    )?;
    let identities: Vec<_> = request
        .storage
        .groups
        .iter()
        .map(|g| (NativeCellShardGroupKindV3::Storage, g))
        .chain(
            request
                .groups
                .iter()
                .map(|g| (NativeCellShardGroupKindV3::Repair, g)),
        )
        .collect();
    types::validate_identity_union(&identities)?;
    let mut checks = Vec::with_capacity(identities.len());
    for (_, group) in &identities {
        let owner = group.children[0].contract.owner();
        checks.push(NativeBudgetEffectCheckV1 {
            policy: &group.policy,
            claim: &group.claim,
            operation: group.operation,
            effect: group.claim.subject,
            window: Some((owner.retain_from_height, owner.retain_until_height)),
        });
    }
    let replays = budgets.check_effects(node, &checks).map_err(owner_error)?;
    let storage_count = request.storage.groups.len();
    ensure(
        replays[..storage_count]
            .iter()
            .all(|r| *r == NativeBudgetReplayV1::Done),
        "NATIVE_CELL_GROUPED_STORAGE_PARENT_NOT_DONE",
    )?;
    for group in &request.storage.groups {
        journal.require_roster(
            group.operation,
            &types::descriptor(plan, NativeCellShardGroupKindV3::Storage, group)?,
            &types::bindings(NativeCellShardGroupKindV3::Storage, group)?,
            deadline,
        )?;
        for index in 0..group.children.len() {
            ensure(
                matches!(
                    journal.state(group.operation, index, deadline)?,
                    ChildStateV3::Done(_)
                ),
                "NATIVE_CELL_GROUPED_STORAGE_CHILD_NOT_DONE",
            )?;
        }
    }
    let mut lookup = BTreeMap::new();
    let mut fresh_children = 0;
    let mut repair_bytes = 0_u64;
    let mut authorized_bytes = 0_u64;
    for (gi, (group, replay)) in request
        .groups
        .iter()
        .zip(&replays[storage_count..])
        .enumerate()
    {
        journal.register(
            group.operation,
            &types::descriptor(plan, NativeCellShardGroupKindV3::Repair, group)?,
            &types::bindings(NativeCellShardGroupKindV3::Repair, group)?,
            *replay == NativeBudgetReplayV1::New,
            deadline,
        )?;
        for (ci, child) in group.children.iter().enumerate() {
            ensure(
                lookup
                    .insert((usize::from(group.slot), group.first_chunk + ci), (gi, ci))
                    .is_none(),
                "NATIVE_CELL_GROUPED_REPAIR_ALIAS",
            )?;
            authorized_bytes = authorized_bytes
                .checked_add(child.contract.manifest().size())
                .ok_or("NATIVE_CELL_GROUPED_SIZE")?;
            match (*replay, journal.state(group.operation, ci, deadline)?) {
                (NativeBudgetReplayV1::New, ChildStateV3::Unstarted) => {
                    fresh_children += 1;
                    repair_bytes = repair_bytes
                        .checked_add(child.contract.manifest().size())
                        .ok_or("NATIVE_CELL_GROUPED_SIZE")?;
                }
                (NativeBudgetReplayV1::Pending, ChildStateV3::Pending | ChildStateV3::Done(_))
                | (NativeBudgetReplayV1::Done, ChildStateV3::Done(_)) => {}
                _ => return Err("NATIVE_CELL_GROUPED_REPAIR_PARENT_CHILD_HISTORY".into()),
            }
        }
    }
    storage_deadline(deadline)?;
    Ok(RepairPrepared {
        contracts,
        anchor,
        lookup,
        fresh_children,
        repair_bytes,
        authorized_bytes,
    })
}

impl Node {
    pub fn recover_native_cell_grouped_shard_plan_v3(
        &mut self,
        budgets: &mut NativeBudgetStoreV1,
        mut targets: NativeCellPagedRetainedShardPlanTargetsV2<'_>,
        request: NativeCellGroupedShardRepairRequestV3,
        journal: &mut NativeCellShardGroupJournalV3,
        budget: &mut NativeCellGroupedShardRecoveryBudgetV3,
    ) -> std::result::Result<
        NativeCellGroupedShardRecoveryReadbackV3,
        Box<NativeCellGroupedShardRecoveryFailureV3>,
    > {
        let mut damage = Vec::new();
        let mut completed = 0;
        let mut cpu_observation = None;
        let mut child_cpu = Vec::new();
        let result = (|| -> Result<NativeCellGroupedShardRecoveryReadbackV3> {
            let deadline = budget.limits.deadline;
            let prepared = preflight(self, budgets, &mut targets, &request, journal, deadline)?;
            let (source, wire) = original_bytes(&prepared.contracts)?;
            budget.reserve(RecoveryCostV3 {
                source,
                wire,
                children: prepared.lookup.len(),
                authorized_bytes: prepared.authorized_bytes,
                repair_bytes: prepared.repair_bytes,
                repairs: prepared.fresh_children,
                slots: 6 * prepared.contracts.len(),
            })?;
            let mut cpu = RepairCpuOwner::start(budget.limits.cpu_ns_per_attempt, deadline)
                .map_err(owner_error)?;
            let plan = targets.plan_file.commitment();
            let outcome = Run {
                node: self,
                budgets,
                targets,
                request: &request,
                prepared: &prepared,
                journal,
                budget,
                cpu: &mut cpu,
                damage: &mut damage,
                completed: &mut completed,
                child_cpu: &mut child_cpu,
            }
            .run();
            let measured = cpu
                .finish(true)
                .map(|c| NativeCellShardRecoveryCpuV1 {
                    observed_ns: c.observed_ns,
                    ceiling_ns: c.ceiling_ns,
                })
                .map_err(owner_error);
            if let Ok(value) = &measured {
                cpu_observation = Some(*value);
            }
            let (storage_parents, repair_parents, observed_at) = outcome?;
            let cpu = measured?;
            Ok(NativeCellGroupedShardRecoveryReadbackV3 {
                plan,
                observed_at,
                storage_parents,
                repair_parents,
                storage_children: 6 * prepared.contracts.len(),
                repair_children: prepared.lookup.len(),
                detected_damage: damage.clone(),
                usage: budget.usage(),
                codec_usage: budget.codec_usage(),
                cpu,
                child_cpu: child_cpu.clone(),
            })
        })();
        result.map_err(|error| {
            Box::new(NativeCellGroupedShardRecoveryFailureV3 {
                error,
                usage: budget.usage(),
                codec_usage: budget.codec_usage(),
                detected_damage: damage,
                completed_children: completed,
                cpu: cpu_observation,
            })
        })
    }
}
struct Run<'a, 'b> {
    node: &'a mut Node,
    budgets: &'a mut NativeBudgetStoreV1,
    targets: NativeCellPagedRetainedShardPlanTargetsV2<'b>,
    request: &'a NativeCellGroupedShardRepairRequestV3,
    prepared: &'a RepairPrepared,
    journal: &'a mut NativeCellShardGroupJournalV3,
    budget: &'a mut NativeCellGroupedShardRecoveryBudgetV3,
    cpu: &'a mut RepairCpuOwner,
    damage: &'a mut Vec<NativeCellShardDamageV1>,
    completed: &'a mut usize,
    child_cpu: &'a mut Vec<NativeCellGroupedChildCpuV3>,
}

impl Run<'_, '_> {
    fn run(
        mut self,
    ) -> Result<(
        Vec<NativeCellShardParentGroupReadbackV3>,
        Vec<NativeCellShardParentGroupReadbackV3>,
        NativeBudgetAnchorV1,
    )> {
        let deadline = self.budget.limits.deadline;
        let plan = self.targets.plan_file.commitment();
        let storage_runs = engine::prepare_parents(
            self.node,
            self.budgets,
            self.journal,
            plan,
            NativeCellShardGroupKindV3::Storage,
            &self.request.storage.groups,
            deadline,
        )?;
        let repair_runs = engine::prepare_parents(
            self.node,
            self.budgets,
            self.journal,
            plan,
            NativeCellShardGroupKindV3::Repair,
            &self.request.groups,
            deadline,
        )?;
        for index in 0..self.prepared.contracts.len() {
            self.repair_chunk(index, &repair_runs)?;
        }
        let (storage_current, repair_current) = self.final_readback()?;
        let storage_parents = engine::finish_parents(
            self.node,
            self.budgets,
            self.journal,
            engine::ParentCompletionV3 {
                plan,
                kind: NativeCellShardGroupKindV3::Storage,
                groups: &self.request.storage.groups,
                runs: &storage_runs,
                observed: &storage_current,
                deadline,
            },
        )?;
        let repair_parents = engine::finish_parents(
            self.node,
            self.budgets,
            self.journal,
            engine::ParentCompletionV3 {
                plan,
                kind: NativeCellShardGroupKindV3::Repair,
                groups: &self.request.groups,
                runs: &repair_runs,
                observed: &repair_current,
                deadline,
            },
        )?;
        self.cpu.check().map_err(owner_error)?;
        let current = self
            .node
            .native_funding_observation(self.request.storage.groups[0].policy.source)?
            .anchor;
        ensure(
            current == self.prepared.anchor,
            "NATIVE_CELL_GROUPED_ANCHOR_CHANGED",
        )?;
        self.targets
            .plan_file
            .read_complete_current(self.targets.catalog, current.height, deadline)
            .map_err(owner_error)?;
        self.journal.verify_context(
            &journal_context(
                self.node,
                plan,
                self.prepared.contracts[0][0].owner().owner_generation,
            ),
            deadline,
        )?;
        self.cpu.check().map_err(owner_error)?;
        Ok((storage_parents, repair_parents, current))
    }
    fn repair_child(
        &mut self,
        gi: usize,
        ci: usize,
        run: &engine::ParentRunV3,
        wire: Option<&[u8]>,
    ) -> Result<CellRs46StoredShardV1> {
        let deadline = self.budget.limits.deadline;
        let group = self.request.groups[gi].clone();
        let child = &group.children[ci];
        let slot = usize::from(group.slot);
        let contract = &child.contract;
        let fresh = run.authorize_child(self.node, self.journal, &group, ci, deadline)?;
        ensure(
            fresh == wire.is_some(),
            "NATIVE_CELL_GROUPED_REPAIR_DISPATCH_SCOPE",
        )?;
        self.cpu.check().map_err(owner_error)?;
        if let Some(wire) = wire {
            CellRs46ShardProviderV1::cache_shard(
                contract,
                contract.operation(),
                wire,
                self.targets.cache,
                deadline,
            )
            .map_err(owner_error)?;
        }
        let NativeBudgetResourcesV1::Repair { cpu_ns, .. } = &child.claim.resource_reservation
        else {
            return Err("NATIVE_CELL_GROUPED_REPAIR_CPU_REQUIRED".into());
        };
        let mut child_cpu = RepairCpuOwner::start(*cpu_ns, deadline).map_err(owner_error)?;
        let repair_operation = child
            .repair_operation
            .ok_or("NATIVE_CELL_GROUPED_REPAIR_OPERATION")?;
        let provider = &mut self.targets.providers[slot];
        let cpu = &mut *self.cpu;
        let (target, stored) = if fresh {
            provider
                .repair(
                    CellRs46ShardRepairRequestV1 {
                        binding: contract.binding(),
                        operation: contract.operation(),
                        repair_operation,
                        cache: self.targets.cache,
                        deadline,
                    },
                    &mut || {
                        cpu.check()?;
                        child_cpu.check()
                    },
                )
                .map_err(owner_error)?
        } else {
            provider
                .reconcile_repair(
                    contract.binding(),
                    contract.operation(),
                    repair_operation,
                    deadline,
                    &mut || {
                        cpu.check()?;
                        child_cpu.check()
                    },
                )
                .map_err(owner_error)?
        };
        ensure(
            target.acknowledged && !target.retired,
            "NATIVE_CELL_GROUPED_REPAIR_TARGET_ACK",
        )?;
        let observed = child_cpu.finish(fresh).map_err(owner_error)?;
        self.child_cpu.push(NativeCellGroupedChildCpuV3 {
            operation: repair_operation,
            observed_ns: observed.observed_ns,
            ceiling_ns: observed.ceiling_ns,
            original_attempt: fresh,
        });
        self.journal
            .complete_child(group.operation, ci, repair_receipt(child), deadline)?;
        *self.completed += 1;
        self.cpu.check().map_err(owner_error)?;
        Ok(stored)
    }
    fn repair_chunk(&mut self, index: usize, runs: &[engine::ParentRunV3]) -> Result<()> {
        let deadline = self.budget.limits.deadline;
        let contracts = self.prepared.contracts[index].clone();
        let mut valid: [Option<CellRs46StoredShardV1>; 6] = std::array::from_fn(|_| None);
        for (slot, valid_slot) in valid.iter_mut().enumerate() {
            self.cpu.check().map_err(owner_error)?;
            let cpu = &mut *self.cpu;
            match self.targets.providers[slot].reconcile_acknowledgement(
                contracts[slot].binding(),
                contracts[slot].operation(),
                deadline,
                &mut || cpu.check(),
            ) {
                Ok((target, stored)) => {
                    ensure(
                        target.acknowledged && !target.retired,
                        "NATIVE_CELL_GROUPED_TARGET_ACK",
                    )?;
                    *valid_slot = Some(stored);
                }
                Err(CellErrorV1::Invalid(
                    reason @ ("chunk digest" | "retention payload digest"),
                )) => {
                    self.damage.push(NativeCellShardDamageV1 {
                        operation: contracts[slot].operation(),
                        provider_store: self.targets.providers[slot].store_id(),
                        reason,
                    });
                }
                Err(error) => return Err(owner_error(error)),
            }
        }
        for (slot, valid_slot) in valid.iter_mut().enumerate() {
            if let Some(&(gi, ci)) = self.prepared.lookup.get(&(slot, index)) {
                if runs[gi].is_fresh() {
                    ensure(
                        valid_slot.is_none(),
                        "NATIVE_CELL_GROUPED_FRESH_REPAIR_TARGET_NOT_DAMAGED",
                    )?;
                } else {
                    *valid_slot = Some(self.repair_child(gi, ci, &runs[gi], None)?);
                }
            }
        }
        if valid.iter().any(Option::is_none) {
            ensure(
                valid.iter().filter(|v| v.is_some()).count() >= 4,
                "NATIVE_CELL_GROUPED_FOUR_ORIGINAL_SHARDS_REQUIRED",
            )?;
            for (slot, valid_slot) in valid.iter().enumerate() {
                if valid_slot.is_none() {
                    let &(gi, _) = self
                        .prepared
                        .lookup
                        .get(&(slot, index))
                        .ok_or("NATIVE_CELL_GROUPED_FRESH_REPAIR_REQUIRED")?;
                    ensure(
                        runs[gi].is_fresh(),
                        "NATIVE_CELL_GROUPED_FRESH_REPAIR_REQUIRED",
                    )?;
                }
            }
            let wires: Vec<_> = valid
                .iter()
                .enumerate()
                .filter_map(|(slot, stored)| {
                    stored.as_ref().map(|s| (slot as u8, s.shard().encode()))
                })
                .collect();
            let inputs: Vec<_> = wires
                .iter()
                .map(|(slot, wire)| CellRs46ShardInputV1 { index: *slot, wire })
                .collect();
            let original = &contracts[0];
            self.cpu.check().map_err(owner_error)?;
            let repaired = original
                .codeword()
                .repair_chunk(
                    original.binding(),
                    original.codeword().id(),
                    &inputs,
                    &mut self.budget.codec,
                )
                .map_err(owner_error)?;
            for (slot, valid_slot) in valid.iter_mut().enumerate() {
                if valid_slot.is_none() {
                    let &(gi, ci) = self
                        .prepared
                        .lookup
                        .get(&(slot, index))
                        .ok_or("NATIVE_CELL_GROUPED_REPAIR_COVERAGE")?;
                    let wire = repaired
                        .repaired_shards()
                        .iter()
                        .find(|s| usize::from(s.index()) == slot)
                        .ok_or("NATIVE_CELL_GROUPED_REPAIR_CODEWORD")?
                        .encode();
                    *valid_slot = Some(self.repair_child(gi, ci, &runs[gi], Some(&wire))?);
                }
            }
        }
        drop(valid);
        let mut actual = Vec::with_capacity(6);
        for (slot, contract) in contracts.iter().enumerate() {
            let cpu = &mut *self.cpu;
            actual.push(observe_original(
                &mut self.targets.providers[slot],
                contract,
                deadline,
                &mut || cpu.check(),
            )?);
        }
        self.cpu.check().map_err(owner_error)?;
        verify_actual_codeword(&contracts, &actual, &mut self.budget.codec)?;
        self.cpu.check().map_err(owner_error)
    }
    fn final_readback(&mut self) -> Result<(BTreeMap<Hash, Hash>, BTreeMap<Hash, Hash>)> {
        let deadline = self.budget.limits.deadline;
        let mut storage_lookup = BTreeMap::new();
        for (gi, group) in self.request.storage.groups.iter().enumerate() {
            for ci in 0..group.children.len() {
                ensure(
                    storage_lookup
                        .insert((usize::from(group.slot), group.first_chunk + ci), (gi, ci))
                        .is_none(),
                    "NATIVE_CELL_GROUPED_STORAGE_ALIAS",
                )?;
            }
        }
        let mut storage_current = BTreeMap::new();
        let mut repair_current = BTreeMap::new();
        for index in 0..self.prepared.contracts.len() {
            let contracts = self.prepared.contracts[index].clone();
            let mut actual = Vec::with_capacity(6);
            for (slot, contract) in contracts.iter().enumerate() {
                self.cpu.check().map_err(owner_error)?;
                let &(sgi, sci) = storage_lookup
                    .get(&(slot, index))
                    .ok_or("NATIVE_CELL_GROUPED_STORAGE_COVERAGE")?;
                let storage_child = &self.request.storage.groups[sgi].children[sci];
                let cpu = &mut *self.cpu;
                let (target, stored) =
                    if let Some(&(gi, ci)) = self.prepared.lookup.get(&(slot, index)) {
                        let child = &self.request.groups[gi].children[ci];
                        let operation = child
                            .repair_operation
                            .ok_or("NATIVE_CELL_GROUPED_REPAIR_OPERATION")?;
                        let result = self.targets.providers[slot]
                            .reconcile_repair(
                                contract.binding(),
                                contract.operation(),
                                operation,
                                deadline,
                                &mut || cpu.check(),
                            )
                            .map_err(owner_error)?;
                        repair_current.insert(operation, repair_receipt(child));
                        result
                    } else {
                        self.targets.providers[slot]
                            .reconcile_acknowledgement(
                                contract.binding(),
                                contract.operation(),
                                deadline,
                                &mut || cpu.check(),
                            )
                            .map_err(owner_error)?
                    };
                ensure(
                    target.acknowledged && !target.retired,
                    "NATIVE_CELL_GROUPED_CURRENT_TARGET_ACK",
                )?;
                let receipt = hash(
                    b"trnm.native-cell-group-child-storage-readback.v3\0",
                    &[&storage_child.claim.subject],
                );
                ensure(
                    storage_current
                        .insert(
                            logical_operation(NativeCellShardGroupKindV3::Storage, storage_child)?,
                            receipt,
                        )
                        .is_none(),
                    "NATIVE_CELL_GROUPED_CURRENT_CHILD_ALIAS",
                )?;
                actual.push(stored);
            }
            verify_actual_codeword(&contracts, &actual, &mut self.budget.codec)?;
            self.cpu.check().map_err(owner_error)?;
        }
        ensure(
            storage_current.len() == 6 * self.prepared.contracts.len()
                && repair_current.len() == self.prepared.lookup.len(),
            "NATIVE_CELL_GROUPED_CURRENT_COVERAGE",
        )?;
        Ok((storage_current, repair_current))
    }
}
