use super::*;

pub(super) fn prepare(
    node: &mut Node,
    budgets: &NativeBudgetStoreV1,
    targets: &NativeCellPagedRetainedShardPlanTargetsV2<'_>,
    request: &NativeCellPagedShardRecoveryRequestV2,
    deadline: Instant,
) -> Result<PreparedPagedRecovery> {
    storage_deadline(deadline)?;
    let plan = targets.plan_file.read(deadline).map_err(owner_error)?;
    let slot_count = plan
        .chunk_count()
        .checked_mul(6)
        .ok_or("NATIVE_CELL_PAGED_RECOVERY_SIZE")?;
    ensure(
        slot_count > 0
            && request.storage.slots.len() == slot_count
            && request.repairs.len() == slot_count,
        "NATIVE_CELL_PAGED_RECOVERY_EXACT_COVERAGE",
    )?;
    let mut identities: BTreeSet<_> = plan.original_identities().collect();
    ensure(
        identities.insert(plan.operation()),
        "NATIVE_CELL_PAGED_RECOVERY_IDENTITY_ALIAS",
    )?;
    let mut sources = BTreeSet::new();
    let mut checks = Vec::with_capacity(2 * slot_count);
    let mut wire_bytes = 0_u64;
    let mut source_bytes = 0_u64;
    let mut covered = 0_usize;
    for page_index in 0..plan.page_count() {
        storage_deadline(deadline)?;
        let page = targets
            .plan_file
            .read_page(page_index, deadline)
            .map_err(owner_error)?;
        ensure(
            page.index() == page_index && page.start_chunk() == covered,
            "NATIVE_CELL_PAGED_RECOVERY_EXACT_COVERAGE",
        )?;
        for chunk in page.chunks() {
            source_bytes = source_bytes
                .checked_add(u64::from(chunk.binding().source_bytes()))
                .ok_or("NATIVE_CELL_PAGED_RECOVERY_SIZE")?;
            for (slot, expected) in chunk.slots().iter().enumerate() {
                storage_deadline(deadline)?;
                let entry = &request.storage.slots[covered * 6 + slot];
                ensure(
                    entry.contract == *expected,
                    "NATIVE_CELL_PAGED_RECOVERY_EXACT_COVERAGE",
                )?;
                for identity in [
                    entry.contract.operation(),
                    entry.claim.claim,
                    entry.policy.budget,
                ] {
                    ensure(
                        identity != [0; 32] && identities.insert(identity),
                        "NATIVE_CELL_PAGED_RECOVERY_IDENTITY_ALIAS",
                    )?;
                }
                ensure(
                    sources.insert(entry.policy.source),
                    "NATIVE_CELL_PAGED_RECOVERY_TASK_ALIAS",
                )?;
                checks.push(shard_storage_check(&targets.providers[slot], entry)?);
                wire_bytes = wire_bytes
                    .checked_add(expected.manifest().size())
                    .ok_or("NATIVE_CELL_PAGED_RECOVERY_SIZE")?;
            }
            covered += 1;
        }
    }
    ensure(
        covered == plan.chunk_count(),
        "NATIVE_CELL_PAGED_RECOVERY_EXACT_COVERAGE",
    )?;
    let mut authorized_indices = Vec::new();
    let mut authorized_bytes = 0_u64;
    for (index, repair) in request.repairs.iter().enumerate() {
        let Some(repair) = repair else { continue };
        storage_deadline(deadline)?;
        let contract = &request.storage.slots[index].contract;
        let provider = &targets.providers[index % 6];
        let owner = contract.owner();
        let placement = &contract.placement().placements[usize::from(owner.slot)];
        task_policy(&repair.policy, &repair.claim)?;
        let effect = native_cell_shard_repair_subject_v1(
            provider,
            contract,
            repair.repair_operation,
            repair.claim.claim,
        );
        ensure(
            repair.binding == *contract.binding()
                && repair.operation == contract.operation()
                && repair.claim.subject == effect
                && repair.claim.beneficiary == placement.repair_owner
                && matches!(repair.claim.resource_reservation,
                NativeBudgetResourcesV1::Repair { cpu_ns, download_bytes, upload_bytes, attempts }
                if cpu_ns > 0 && download_bytes >= contract.manifest().size()
                    && upload_bytes >= contract.manifest().size() && attempts >= 1),
            "NATIVE_CELL_PAGED_RECOVERY_REPAIR_BINDING",
        )?;
        for identity in [
            repair.repair_operation,
            repair.claim.claim,
            repair.policy.budget,
        ] {
            ensure(
                identity != [0; 32] && identities.insert(identity),
                "NATIVE_CELL_PAGED_RECOVERY_IDENTITY_ALIAS",
            )?;
        }
        ensure(
            sources.insert(repair.policy.source),
            "NATIVE_CELL_PAGED_RECOVERY_TASK_ALIAS",
        )?;
        checks.push(NativeBudgetEffectCheckV1 {
            policy: &repair.policy,
            claim: &repair.claim,
            operation: repair.repair_operation,
            effect,
            window: Some((owner.retain_from_height, owner.retain_until_height)),
        });
        authorized_indices.push(index);
        authorized_bytes = authorized_bytes
            .checked_add(contract.manifest().size())
            .ok_or("NATIVE_CELL_PAGED_RECOVERY_SIZE")?;
    }
    let replays = budgets.check_effects(node, &checks).map_err(owner_error)?;
    ensure(
        replays[..slot_count]
            .iter()
            .all(|replay| *replay != NativeBudgetReplayV1::New),
        "NATIVE_CELL_PAGED_RECOVERY_ORIGINAL_INTENT_REQUIRED",
    )?;
    let mut repair_replays = vec![None; slot_count];
    let mut repairs = 0_u64;
    let mut repair_bytes = 0_u64;
    for (index, replay) in authorized_indices.iter().zip(&replays[slot_count..]) {
        repair_replays[*index] = Some(*replay);
        if *replay == NativeBudgetReplayV1::New {
            repairs += 1;
            repair_bytes = repair_bytes
                .checked_add(request.storage.slots[*index].contract.manifest().size())
                .ok_or("NATIVE_CELL_PAGED_RECOVERY_SIZE")?;
        }
    }
    // Current descriptor/history/extent state is checked for every provider,
    // including retired historical records. Recovery cannot create a missing
    // original target; the census below will require its existing descriptor.
    for (slot, provider) in targets.providers.iter().enumerate() {
        let contracts: Vec<_> = request
            .storage
            .slots
            .iter()
            .skip(slot)
            .step_by(6)
            .map(|entry| &entry.contract)
            .collect();
        provider
            .check_reservations(&contracts, deadline)
            .map_err(owner_error)?;
    }
    storage_deadline(deadline)?;
    let current = node
        .native_funding_observation(request.storage.slots[0].policy.source)?
        .anchor;
    targets
        .plan_file
        .read_current(targets.catalog, current.height, deadline)
        .map_err(owner_error)?;
    storage_deadline(deadline)?;
    // Three complete target scans, one original repair call per authorized
    // slot and at most three codec admissions per chunk. Each scan plus codec
    // input is bounded by 2W, and each reconstruction by W + source bytes.
    // This is logical work, not a claim about SQL/filesystem amplification.
    let cost = RecoveryCost {
        provider_reads: (slot_count as u64)
            .checked_mul(3)
            .and_then(|count| count.checked_add(authorized_indices.len() as u64))
            .ok_or("NATIVE_CELL_PAGED_RECOVERY_SIZE")?,
        input_bytes: wire_bytes
            .checked_mul(6)
            .and_then(|bytes| bytes.checked_add(authorized_bytes))
            .ok_or("NATIVE_CELL_PAGED_RECOVERY_SIZE")?,
        reconstruction_bytes: wire_bytes
            .checked_add(source_bytes)
            .and_then(|bytes| bytes.checked_mul(3))
            .ok_or("NATIVE_CELL_PAGED_RECOVERY_SIZE")?,
        repairs,
        repair_bytes,
    };
    Ok(PreparedPagedRecovery {
        plan,
        current,
        repair_replays,
        cost,
    })
}
