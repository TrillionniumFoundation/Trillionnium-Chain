use super::*;

pub(super) struct Execution<'a, 'b> {
    pub node: &'a mut Node,
    pub budgets: &'a mut NativeBudgetStoreV1,
    pub targets: NativeCellPagedRetainedShardPlanTargetsV2<'b>,
    pub request: &'a NativeCellPagedShardRecoveryRequestV2,
    pub prepared: &'a PreparedPagedRecovery,
    pub budget: &'a mut NativeCellShardRecoveryBudgetV1,
    pub cpu: &'a mut RepairCpuOwner,
    pub damage: &'a mut Vec<NativeCellShardDamageV1>,
    pub actions: &'a mut Vec<NativeCellShardRecoveryActionV1>,
}

type CompleteObservation = (
    Vec<NativeCellRetainedShardPageReadbackV2>,
    Vec<NativeCellRetainedShardSlotReadbackV1>,
);

impl Execution<'_, '_> {
    pub(super) fn run(
        mut self,
    ) -> Result<(
        Vec<NativeCellRetainedShardPageReadbackV2>,
        Vec<NativeCellRetainedShardSlotReadbackV1>,
        NativeBudgetAnchorV1,
    )> {
        // Every page is checked before a new repair can start. Payload buffers
        // are dropped per chunk; only a bounded slot bitmap survives the census.
        let damaged = self.census()?;
        self.check_repair_capacity(&damaged)?;
        self.check_current()?;
        for page_index in 0..self.prepared.plan.page_count() {
            self.cpu.check().map_err(owner_error)?;
            let page = self
                .targets
                .plan_file
                .read_page(page_index, self.budget.limits.deadline)
                .map_err(owner_error)?;
            for (local_index, chunk) in page.chunks().iter().enumerate() {
                let base = (page.start_chunk() + local_index) * 6;
                self.repair_chunk(chunk, base, &damaged[base..base + 6])?;
            }
        }
        // An earlier successful page is insufficient. Read all actual targets
        // again after every repair, including pages that needed no repair.
        let (pages, slots) = self.observe_complete()?;
        self.check_original_intents_complete()?;
        let current = self.check_current()?;
        Ok((pages, slots, current))
    }

    fn census(&mut self) -> Result<Vec<bool>> {
        let mut damaged = vec![false; self.request.storage.slots.len()];
        for page_index in 0..self.prepared.plan.page_count() {
            self.cpu.check().map_err(owner_error)?;
            let page = self
                .targets
                .plan_file
                .read_page(page_index, self.budget.limits.deadline)
                .map_err(owner_error)?;
            for (local_index, chunk) in page.chunks().iter().enumerate() {
                let base = (page.start_chunk() + local_index) * 6;
                let valid = self.read_chunk(chunk, None)?;
                ensure(
                    valid.iter().filter(|entry| entry.is_some()).count() >= 4,
                    "NATIVE_CELL_PAGED_RECOVERY_FOUR_ORIGINAL_SHARDS_REQUIRED",
                )?;
                for (slot, entry) in valid.iter().enumerate() {
                    damaged[base + slot] = entry.is_none();
                    if entry.is_none() {
                        ensure(
                            self.prepared.repair_replays[base + slot]
                                == Some(NativeBudgetReplayV1::New),
                            "NATIVE_CELL_PAGED_RECOVERY_FRESH_AUTHORITY_REQUIRED",
                        )?;
                    }
                }
                // Also validate the full source/codeword relation before any
                // effects. Four individually valid hashes alone are not the
                // final complete-codeword assertion of the retained plan.
                self.verify_chunk(chunk, &valid, false)?;
            }
        }
        Ok(damaged)
    }

    fn check_repair_capacity(&mut self, damaged: &[bool]) -> Result<()> {
        for (slot, provider) in self.targets.providers.iter().enumerate() {
            self.cpu.check().map_err(owner_error)?;
            let mut repairs = Vec::new();
            for index in (slot..self.request.repairs.len()).step_by(6) {
                let Some(repair) = &self.request.repairs[index] else {
                    continue;
                };
                let replay = self.prepared.repair_replays[index];
                if damaged[index]
                    || matches!(
                        replay,
                        Some(NativeBudgetReplayV1::Pending | NativeBudgetReplayV1::Done)
                    )
                {
                    repairs.push((
                        &self.request.storage.slots[index].contract,
                        repair.repair_operation,
                        damaged[index],
                    ));
                }
            }
            // Includes original history, Pending charges and zero-byte
            // reconciliation rows. This is read-only; no new intent or debit.
            provider
                .check_repair_reservations(&repairs, self.budget.limits.deadline)
                .map_err(owner_error)?;
            self.cpu.check().map_err(owner_error)?;
        }
        Ok(())
    }

    fn read_chunk(
        &mut self,
        chunk: &CellRetainedShardChunkV1,
        known_damage: Option<&[bool]>,
    ) -> Result<[Option<CellRs46StoredShardV1>; 6]> {
        let deadline = self.budget.limits.deadline;
        let mut valid = std::array::from_fn(|_| None);
        for (slot, provider) in self.targets.providers.iter_mut().enumerate() {
            self.cpu.check().map_err(owner_error)?;
            let contract = &chunk.slots()[slot];
            // The original ACK path may reconcile already-written bytes. It
            // never copies source bytes or opens a new repair/funding intent.
            let observed = provider.reconcile_acknowledgement(
                chunk.binding(),
                contract.operation(),
                deadline,
                &mut || self.cpu.check(),
            );
            match observed {
                Ok((target, stored)) => {
                    ensure(
                        target.acknowledged && !target.retired,
                        "NATIVE_CELL_PAGED_RECOVERY_TARGET_ACK",
                    )?;
                    valid[slot] = Some(stored);
                }
                Err(CellErrorV1::Invalid(
                    reason @ ("chunk digest" | "retention payload digest"),
                )) => {
                    if !known_damage.is_some_and(|known| known[slot]) {
                        self.damage.push(NativeCellShardDamageV1 {
                            operation: contract.operation(),
                            provider_store: provider.store_id(),
                            reason,
                        });
                    }
                }
                // Metadata, I/O, CPU and deadline failures are not permission
                // to copy again or substitute an original descriptor.
                Err(error) => return Err(owner_error(error)),
            }
            self.cpu.check().map_err(owner_error)?;
        }
        Ok(valid)
    }

    fn repair_chunk(
        &mut self,
        chunk: &CellRetainedShardChunkV1,
        base: usize,
        known_damage: &[bool],
    ) -> Result<()> {
        let deadline = self.budget.limits.deadline;
        let mut valid = self.read_chunk(chunk, Some(known_damage))?;
        // No new damage may expand the globally admitted copy set. A later
        // fault fails this attempt with its original reservations preserved.
        ensure(
            valid
                .iter()
                .enumerate()
                .all(|(slot, entry)| entry.is_some() || known_damage[slot]),
            "NATIVE_CELL_PAGED_RECOVERY_TARGET_CHANGED_AFTER_CENSUS",
        )?;
        for (slot, provider) in self.targets.providers.iter_mut().enumerate() {
            if matches!(
                self.prepared.repair_replays[base + slot],
                Some(NativeBudgetReplayV1::Pending | NativeBudgetReplayV1::Done)
            ) {
                let repair = self.request.repairs[base + slot]
                    .as_ref()
                    .ok_or("NATIVE_CELL_PAGED_RECOVERY_REPAIR_COVERAGE")?;
                self.cpu.check().map_err(owner_error)?;
                let observed = self.node.repair_native_cell_shard(
                    self.budgets,
                    provider,
                    self.targets.cache,
                    repair.clone(),
                    deadline,
                )?;
                self.actions.push(NativeCellShardRecoveryActionV1 {
                    operation: repair.operation,
                    repair_operation: repair.repair_operation,
                    native: observed.native,
                });
                valid[slot] = Some(observed.stored);
                self.cpu.check().map_err(owner_error)?;
            }
        }
        if valid.iter().any(Option::is_none) {
            ensure(
                valid.iter().filter(|entry| entry.is_some()).count() >= 4,
                "NATIVE_CELL_PAGED_RECOVERY_FOUR_ORIGINAL_SHARDS_REQUIRED",
            )?;
            let wires = target_wires(&valid);
            let inputs: Vec<_> = wires
                .iter()
                .map(|(index, wire)| CellRs46ShardInputV1 {
                    index: *index,
                    wire,
                })
                .collect();
            let original = &chunk.slots()[0];
            self.cpu.check().map_err(owner_error)?;
            let reconstructed = original
                .codeword()
                .repair_chunk(
                    chunk.binding(),
                    original.codeword().id(),
                    &inputs,
                    &mut self.budget.codec,
                )
                .map_err(owner_error)?;
            self.cpu.check().map_err(owner_error)?;
            ensure(
                reconstructed.rejected_slots().is_empty()
                    && reconstructed.verified_slots().len() == wires.len(),
                "NATIVE_CELL_PAGED_RECOVERY_COMPLETE_CODEWORD",
            )?;
            for (slot, provider) in self.targets.providers.iter_mut().enumerate() {
                if valid[slot].is_some() {
                    continue;
                }
                ensure(
                    self.prepared.repair_replays[base + slot] == Some(NativeBudgetReplayV1::New),
                    "NATIVE_CELL_PAGED_RECOVERY_FRESH_AUTHORITY_REQUIRED",
                )?;
                let repair = self.request.repairs[base + slot]
                    .as_ref()
                    .ok_or("NATIVE_CELL_PAGED_RECOVERY_FRESH_AUTHORITY_REQUIRED")?;
                let shard = reconstructed
                    .repaired_shards()
                    .iter()
                    .find(|shard| usize::from(shard.index()) == slot)
                    .ok_or("NATIVE_CELL_PAGED_RECOVERY_RECONSTRUCTION_COVERAGE")?;
                let contract = &chunk.slots()[slot];
                self.cpu.check().map_err(owner_error)?;
                // Only freshly reconstructed original CRS1 bytes enter this
                // disposable cache. No source/catalog/cache fallback exists.
                CellRs46ShardProviderV1::cache_shard(
                    contract,
                    contract.operation(),
                    &shard.encode(),
                    self.targets.cache,
                    deadline,
                )
                .map_err(owner_error)?;
                self.cpu.check().map_err(owner_error)?;
                let observed = self.node.repair_native_cell_shard(
                    self.budgets,
                    provider,
                    self.targets.cache,
                    repair.clone(),
                    deadline,
                )?;
                self.actions.push(NativeCellShardRecoveryActionV1 {
                    operation: repair.operation,
                    repair_operation: repair.repair_operation,
                    native: observed.native,
                });
                valid[slot] = Some(observed.stored);
                self.cpu.check().map_err(owner_error)?;
            }
        }
        ensure(
            valid.iter().all(Option::is_some),
            "NATIVE_CELL_PAGED_RECOVERY_RECONSTRUCTION_COVERAGE",
        )?;
        // Each retained peer and each repaired target has verified its original
        // wire. Dispose only this named staging set, including residue left by
        // a previously successful original repair before a process stopped.
        // The independent final whole-root scan follows after every chunk.
        for contract in chunk.slots() {
            self.cpu.check().map_err(owner_error)?;
            self.targets
                .cache
                .discard_manifest_until(contract.manifest(), deadline)
                .map_err(owner_error)?;
            self.cpu.check().map_err(owner_error)?;
        }
        Ok(())
    }

    fn observe_complete(&mut self) -> Result<CompleteObservation> {
        let mut pages = Vec::with_capacity(self.prepared.plan.page_count());
        let mut slots = Vec::with_capacity(self.request.storage.slots.len());
        let deadline = self.budget.limits.deadline;
        for page_index in 0..self.prepared.plan.page_count() {
            self.cpu.check().map_err(owner_error)?;
            let page = self
                .targets
                .plan_file
                .read_page(page_index, deadline)
                .map_err(owner_error)?;
            for (local_index, chunk) in page.chunks().iter().enumerate() {
                let base = (page.start_chunk() + local_index) * 6;
                let mut actual = Vec::with_capacity(6);
                for (slot, provider) in self.targets.providers.iter_mut().enumerate() {
                    self.cpu.check().map_err(owner_error)?;
                    let observed = self.node.retain_native_cell_shard(
                        self.budgets,
                        provider,
                        self.targets.cache,
                        self.request.storage.slots[base + slot].clone(),
                        deadline,
                    )?;
                    ensure(
                        observed.native.replay != NativeBudgetReplayV1::New,
                        "NATIVE_CELL_PAGED_RECOVERY_ORIGINAL_INTENT_REQUIRED",
                    )?;
                    actual.push(observed);
                    self.cpu.check().map_err(owner_error)?;
                }
                let valid = std::array::from_fn(|slot| Some(actual[slot].stored.clone()));
                self.verify_chunk(chunk, &valid, true)?;
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
            }
            pages.push(NativeCellRetainedShardPageReadbackV2 {
                index: page.index(),
                commitment: page.commitment(),
                start_chunk: page.start_chunk(),
                chunk_count: page.chunks().len(),
            });
        }
        Ok((pages, slots))
    }

    fn verify_chunk(
        &mut self,
        chunk: &CellRetainedShardChunkV1,
        valid: &[Option<CellRs46StoredShardV1>; 6],
        complete: bool,
    ) -> Result<()> {
        let wires = target_wires(valid);
        let inputs: Vec<_> = wires
            .iter()
            .map(|(index, wire)| CellRs46ShardInputV1 {
                index: *index,
                wire,
            })
            .collect();
        let original = &chunk.slots()[0];
        self.cpu.check().map_err(owner_error)?;
        let verified = original
            .codeword()
            .repair_chunk(
                chunk.binding(),
                original.codeword().id(),
                &inputs,
                &mut self.budget.codec,
            )
            .map_err(owner_error)?;
        self.cpu.check().map_err(owner_error)?;
        ensure(
            verified.verified_slots().len() == wires.len()
                && verified.rejected_slots().is_empty()
                && verified.missing_slots().len() == 6 - wires.len()
                && (!complete || verified.verified_slots().len() == 6),
            "NATIVE_CELL_PAGED_RECOVERY_COMPLETE_CODEWORD",
        )
    }

    fn check_original_intents_complete(&mut self) -> Result<()> {
        self.cpu.check().map_err(owner_error)?;
        let mut checks = Vec::with_capacity(self.request.storage.slots.len());
        for (index, entry) in self.request.storage.slots.iter().enumerate() {
            self.cpu.check().map_err(owner_error)?;
            checks.push(shard_storage_check(
                &self.targets.providers[index % 6],
                entry,
            )?);
        }
        let replays = self
            .budgets
            .check_effects(self.node, &checks)
            .map_err(owner_error)?;
        ensure(
            replays
                .iter()
                .all(|replay| *replay == NativeBudgetReplayV1::Done),
            "NATIVE_CELL_PAGED_RECOVERY_ORIGINAL_INTENT_INCOMPLETE",
        )?;
        self.cpu.check().map_err(owner_error)
    }

    fn check_current(&mut self) -> Result<NativeBudgetAnchorV1> {
        self.cpu.check().map_err(owner_error)?;
        let current = self
            .node
            .native_funding_observation(self.request.storage.slots[0].policy.source)?
            .anchor;
        ensure(
            current == self.prepared.current,
            "NATIVE_CELL_PAGED_RECOVERY_CURRENT_ANCHOR_CHANGED",
        )?;
        self.targets
            .plan_file
            .read_current(
                self.targets.catalog,
                current.height,
                self.budget.limits.deadline,
            )
            .map_err(owner_error)?;
        self.cpu.check().map_err(owner_error)?;
        Ok(current)
    }
}

fn target_wires(valid: &[Option<CellRs46StoredShardV1>; 6]) -> Vec<(u8, Vec<u8>)> {
    valid
        .iter()
        .enumerate()
        .filter_map(|(slot, entry)| {
            entry
                .as_ref()
                .map(|stored| (slot as u8, stored.shard().encode()))
        })
        .collect()
}
