use super::*;

pub(super) struct Execution<'a, 'b> {
    pub node: &'a mut Node,
    pub budgets: &'a mut NativeBudgetStoreV1,
    pub targets: NativeCellRetainedShardPlanTargetsV1<'b>,
    pub request: &'a NativeCellShardRecoveryRequestV1,
    pub prepared: &'a PreparedRecovery,
    pub budget: &'a mut NativeCellShardRecoveryBudgetV1,
    pub cpu: &'a mut RepairCpuOwner,
    pub damage: &'a mut Vec<NativeCellShardDamageV1>,
    pub actions: &'a mut Vec<NativeCellShardRecoveryActionV1>,
}

impl Execution<'_, '_> {
    pub(super) fn run(
        self,
    ) -> Result<(
        Vec<NativeCellRetainedShardSlotReadbackV1>,
        NativeBudgetAnchorV1,
    )> {
        let Self {
            node,
            budgets,
            targets,
            request,
            prepared,
            budget,
            cpu,
            damage,
            actions,
        } = self;
        let NativeCellRetainedShardPlanTargetsV1 {
            catalog,
            plan_file,
            providers,
            cache,
        } = targets;
        let deadline = budget.limits.deadline;
        let mut slots = Vec::with_capacity(request.storage.slots.len());
        for (chunk_index, chunk) in prepared.plan.chunks().iter().enumerate() {
            cpu.check().map_err(owner_error)?;
            let base = chunk_index * 6;
            let mut valid: [Option<CellRs46StoredShardV1>; 6] = std::array::from_fn(|_| None);
            // Read the real fixed target first. Only payload-digest failures
            // permit reconstruction: metadata, descriptor, identity, I/O, CPU
            // and deadline failures cannot become fresh-copy authorization.
            for (slot, provider) in providers.iter_mut().enumerate() {
                let contract = &chunk.slots()[slot];
                let observed = provider.reconcile_acknowledgement(
                    chunk.binding(),
                    contract.operation(),
                    deadline,
                    &mut || cpu.check(),
                );
                match observed {
                    Ok((target, stored)) => {
                        ensure(
                            target.acknowledged && !target.retired,
                            "NATIVE_CELL_SHARD_RECOVERY_TARGET_ACK",
                        )?;
                        valid[slot] = Some(stored);
                    }
                    Err(CellErrorV1::Invalid(
                        reason @ ("chunk digest" | "retention payload digest"),
                    )) => {
                        damage.push(NativeCellShardDamageV1 {
                            operation: contract.operation(),
                            provider_store: provider.store_id(),
                            reason,
                        });
                    }
                    Err(error) => return Err(owner_error(error)),
                }
                cpu.check().map_err(owner_error)?;
            }
            // An existing repair intent is never redispatched, even when its
            // target is damaged and four peers are healthy. The original Node
            // adapter only reconciles Pending/Done, without inspecting cache.
            for (slot, provider) in providers.iter_mut().enumerate() {
                if matches!(
                    prepared.repair_replays[base + slot],
                    Some(NativeBudgetReplayV1::Pending | NativeBudgetReplayV1::Done)
                ) {
                    let repair = request.repairs[base + slot]
                        .as_ref()
                        .ok_or("NATIVE_CELL_SHARD_RECOVERY_REPAIR_COVERAGE")?;
                    cpu.check().map_err(owner_error)?;
                    let observed = node.repair_native_cell_shard(
                        budgets,
                        provider,
                        cache,
                        repair.clone(),
                        deadline,
                    )?;
                    actions.push(NativeCellShardRecoveryActionV1 {
                        operation: repair.operation,
                        repair_operation: repair.repair_operation,
                        native: observed.native,
                    });
                    valid[slot] = Some(observed.stored);
                    cpu.check().map_err(owner_error)?;
                }
            }
            if valid.iter().any(Option::is_none) {
                ensure(
                    valid.iter().filter(|entry| entry.is_some()).count() >= 4,
                    "NATIVE_CELL_SHARD_RECOVERY_FOUR_ORIGINAL_SHARDS_REQUIRED",
                )?;
                for (slot, entry) in valid.iter().enumerate() {
                    if entry.is_none() {
                        ensure(
                            prepared.repair_replays[base + slot] == Some(NativeBudgetReplayV1::New),
                            "NATIVE_CELL_SHARD_RECOVERY_FRESH_AUTHORITY_REQUIRED",
                        )?;
                    }
                }
                let wires: Vec<_> = valid
                    .iter()
                    .enumerate()
                    .filter_map(|(slot, entry)| {
                        entry
                            .as_ref()
                            .map(|stored| (slot as u8, stored.shard().encode()))
                    })
                    .collect();
                let inputs: Vec<_> = wires
                    .iter()
                    .map(|(index, wire)| CellRs46ShardInputV1 {
                        index: *index,
                        wire,
                    })
                    .collect();
                let original = &chunk.slots()[0];
                cpu.check().map_err(owner_error)?;
                let reconstructed = original
                    .codeword()
                    .repair_chunk(
                        chunk.binding(),
                        original.codeword().id(),
                        &inputs,
                        &mut budget.codec,
                    )
                    .map_err(owner_error)?;
                cpu.check().map_err(owner_error)?;
                // The existing codec returns only canonical missing originals
                // after checking the recovered full payload and all six IDs.
                for (slot, provider) in providers.iter_mut().enumerate() {
                    if valid[slot].is_some() {
                        continue;
                    }
                    let repair = request.repairs[base + slot]
                        .as_ref()
                        .ok_or("NATIVE_CELL_SHARD_RECOVERY_FRESH_AUTHORITY_REQUIRED")?;
                    let shard = reconstructed
                        .repaired_shards()
                        .iter()
                        .find(|shard| usize::from(shard.index()) == slot)
                        .ok_or("NATIVE_CELL_SHARD_RECOVERY_RECONSTRUCTION_COVERAGE")?;
                    let contract = &chunk.slots()[slot];
                    cpu.check().map_err(owner_error)?;
                    // This CAS entry comes only from the actual peer codeword;
                    // an older cache or TCA3 payload is never a recovery source.
                    CellRs46ShardProviderV1::cache_shard(
                        contract,
                        contract.operation(),
                        &shard.encode(),
                        cache,
                        deadline,
                    )
                    .map_err(owner_error)?;
                    cpu.check().map_err(owner_error)?;
                    let observed = node.repair_native_cell_shard(
                        budgets,
                        provider,
                        cache,
                        repair.clone(),
                        deadline,
                    )?;
                    actions.push(NativeCellShardRecoveryActionV1 {
                        operation: repair.operation,
                        repair_operation: repair.repair_operation,
                        native: observed.native,
                    });
                    valid[slot] = Some(observed.stored);
                    cpu.check().map_err(owner_error)?;
                }
            }
            drop(valid);
            // Reobserve all six original storage effects through their own
            // Pending/Done path. This also completes an original partial ACK
            // after its target became valid, without another initial copy.
            let mut actual = Vec::with_capacity(6);
            for (slot, provider) in providers.iter_mut().enumerate() {
                cpu.check().map_err(owner_error)?;
                actual.push(node.retain_native_cell_shard(
                    budgets,
                    provider,
                    cache,
                    request.storage.slots[base + slot].clone(),
                    deadline,
                )?);
                cpu.check().map_err(owner_error)?;
            }
            let wires: Vec<_> = actual
                .iter()
                .map(|row| row.stored.shard().encode())
                .collect();
            let inputs: Vec<_> = wires
                .iter()
                .enumerate()
                .map(|(slot, wire)| CellRs46ShardInputV1 {
                    index: slot as u8,
                    wire,
                })
                .collect();
            let original = &chunk.slots()[0];
            let complete = original
                .codeword()
                .repair_chunk(
                    chunk.binding(),
                    original.codeword().id(),
                    &inputs,
                    &mut budget.codec,
                )
                .map_err(owner_error)?;
            cpu.check().map_err(owner_error)?;
            ensure(
                complete.verified_slots().len() == 6
                    && complete.rejected_slots().is_empty()
                    && complete.missing_slots().is_empty(),
                "NATIVE_CELL_SHARD_RECOVERY_COMPLETE_CODEWORD",
            )?;
            slots.extend(
                actual
                    .into_iter()
                    .map(|row| NativeCellRetainedShardSlotReadbackV1 {
                        operation: row.stored.operation(),
                        provider_store: row.stored.provider_store(),
                        shard: row.stored.shard().id(),
                        native: row.native,
                    }),
            );
            // Payload buffers belong to this one bounded codeword and are
            // dropped at the end of the iteration, rather than the whole plan.
        }
        cpu.check().map_err(owner_error)?;
        let current = node
            .native_funding_observation(request.storage.slots[0].policy.source)?
            .anchor;
        ensure(
            current == prepared.current,
            "NATIVE_CELL_SHARD_RECOVERY_CURRENT_ANCHOR_CHANGED",
        )?;
        plan_file
            .read_current(catalog, current.height, deadline)
            .map_err(owner_error)?;
        cpu.check().map_err(owner_error)?;
        Ok((slots, current))
    }
}
