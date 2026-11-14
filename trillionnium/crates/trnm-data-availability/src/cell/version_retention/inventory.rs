use super::*;
use crate::cell::retention::CellRetentionCatalogObjectV1;

pub(super) struct Projection {
    historical_objects: u32,
    occupied: u64,
    promised: u64,
    retired_version_occupied: u64,
    initial: u64,
    repair: u64,
}

/// All Pending promises and occupied slots, including retired-root slots still
/// awaiting GC, count together. Future promises must fit one free extent: this
/// conservative bound lets the existing first-fit allocator fulfill them in any
/// retry order. Total free bytes alone cannot guarantee that under fragmentation.
pub(super) fn projection(
    rows: &[DutyRow],
    physical: &[CellRetentionCatalogObjectV1],
    config: &CellVersionRetentionConfigV3,
    deadline: Instant,
) -> CellResultV1<Projection> {
    let mut history = BTreeMap::new();
    let mut protected = BTreeSet::new();
    let mut previously_allocated = BTreeSet::new();
    let mut active = BTreeSet::new();
    for row in rows {
        check_deadline(deadline)?;
        for object in &row.contract.objects {
            history.insert(object.operation, object);
            if row.status != 2 {
                protected.insert(object.operation);
            }
            if row.status != 0 {
                previously_allocated.insert(object.operation);
            }
            if row.status == 1 {
                active.insert(object.operation);
            }
        }
    }
    require(
        history.len() <= config.retention.maximum_obligations as usize,
        "version retention physical history capacity",
    )?;
    let present: BTreeMap<_, _> = physical.iter().map(|row| (row.operation, row)).collect();
    require(
        present.len() == physical.len(),
        "version retention physical identity alias",
    )?;
    let mut occupied = 0_u64;
    let mut retired_version_occupied = 0_u64;
    let mut initial = 0_u64;
    let mut repair = 0_u64;
    for row in physical {
        check_deadline(deadline)?;
        let contract = history.get(&row.operation).ok_or(CellErrorV1::Invalid(
            "version retention physical descriptor absent",
        ))?;
        require(
            row.contract_commitment == contract.commitment(config.retention.store_id)
                && row.funding_operation == contract.funding_operation
                && row.manifest == contract.manifest.id(),
            "version retention physical contract changed",
        )?;
        initial = add(initial, row.initial_copy_bytes_committed)?;
        repair = add(repair, row.repair_bytes_committed)?;
        if !row.retired {
            occupied = add(occupied, row.reserved_bytes)?;
            if !protected.contains(&row.operation) {
                retired_version_occupied = add(retired_version_occupied, row.reserved_bytes)?;
            }
        } else {
            require(
                !protected.contains(&row.operation),
                "version retention protected object retired",
            )?;
        }
        if active.contains(&row.operation) {
            require(
                row.acknowledged,
                "version retention active object state regression",
            )?;
        }
    }
    let mut promised = 0_u64;
    for (operation, contract) in &history {
        check_deadline(deadline)?;
        if !present.contains_key(operation) {
            require(
                !previously_allocated.contains(operation),
                "version retention physical history lost",
            )?;
            require(
                protected.contains(operation),
                "version retention incomplete retired object",
            )?;
            promised = add(promised, aligned(contract.manifest.size())?)?;
        }
    }
    require(
        add(occupied, promised)? <= config.retention.capacity_bytes,
        "version retention pending union capacity",
    )?;
    let mut live: Vec<_> = physical.iter().filter(|row| !row.retired).collect();
    live.sort_by_key(|row| row.offset);
    let mut end = 0_u64;
    let mut largest_gap = 0_u64;
    for row in live {
        require(row.offset >= end, "version retention physical overlap")?;
        largest_gap = largest_gap.max(row.offset - end);
        end = add(row.offset, row.reserved_bytes)?;
    }
    require(
        end <= config.retention.capacity_bytes,
        "version retention physical bounds",
    )?;
    largest_gap = largest_gap.max(config.retention.capacity_bytes - end);
    require(
        promised <= largest_gap,
        "version retention pending contiguous capacity",
    )?;
    check_deadline(deadline)?;
    Ok(Projection {
        historical_objects: history.len() as u32,
        occupied,
        promised,
        retired_version_occupied,
        initial,
        repair,
    })
}

fn add(left: u64, right: u64) -> CellResultV1<u64> {
    left.checked_add(right)
        .ok_or(CellErrorV1::Invalid("version retention size overflow"))
}

impl CellVersionRetentionStoreV3 {
    /// Includes immutable Retired history for replay and snapshot cursor recovery.
    pub(crate) fn audited_duties(
        &self,
        deadline: Instant,
    ) -> CellResultV1<Vec<CellVersionRetentionDutyV3>> {
        Ok(self
            .check(deadline)?
            .rows
            .into_iter()
            .map(public_duty)
            .collect())
    }

    pub fn inventory(
        &self,
        current_height: u64,
        deadline: Instant,
    ) -> CellResultV1<CellVersionRetentionInventoryV3> {
        let current = self.check(deadline)?;
        let physical = self.retention.catalog_inventory(deadline)?;
        let projected = projection(&current.rows, &physical, &self.config, deadline)?;
        let mut usage = CellVersionRetentionUsageV3 {
            historical_versions: current.rows.len() as u32,
            protected_versions: 0,
            pending_versions: 0,
            active_versions: 0,
            expired_unretired_versions: 0,
            metadata_bytes: current.metadata_bytes,
            historical_objects: projected.historical_objects,
            occupied_bytes: projected.occupied,
            promised_unallocated_bytes: projected.promised,
            retired_version_occupied_bytes: projected.retired_version_occupied,
            initial_copy_bytes_committed: projected.initial,
            repair_bytes_committed: projected.repair,
        };
        let mut protected = Vec::new();
        for row in current.rows {
            check_deadline(deadline)?;
            if row.status == 2 {
                continue;
            }
            usage.protected_versions += 1;
            if row.status == 0 {
                usage.pending_versions += 1;
            }
            if row.status == 1 {
                usage.active_versions += 1;
            }
            if current_height >= row.contract.retain_until_height {
                usage.expired_unretired_versions += 1;
            }
            protected.push(public_duty(row));
        }
        check_deadline(deadline)?;
        Ok(CellVersionRetentionInventoryV3 {
            anchor: current.anchor,
            protected,
            usage,
        })
    }

    /// An all-protected-set service view. Pending or expired duties refuse a
    /// complete health assertion; fresh payload verification remains separate.
    pub fn service_set(
        &self,
        current_height: u64,
        required_until_height: u64,
        deadline: Instant,
    ) -> CellResultV1<CellRetainedVersionSetV1> {
        require(
            current_height < required_until_height && required_until_height <= i64::MAX as u64,
            "version retention service horizon",
        )?;
        let current = self.check(deadline)?;
        let mut entries: BTreeMap<CellVersionCommitmentV1, CellRetainedVersionEntryV1> =
            BTreeMap::new();
        for row in current.rows.iter().filter(|row| row.status != 2) {
            check_deadline(deadline)?;
            let contract = &row.contract;
            require(
                row.status == 1
                    && contract.retain_from_height <= current_height
                    && required_until_height <= contract.retain_until_height,
                "version retention complete service unavailable",
            )?;
            let commitment = contract.version.commitment();
            if let Some(entry) = entries.get_mut(&commitment) {
                require(
                    entry.version == contract.version,
                    "version retention version commitment collision",
                )?;
                entry.retain_from_height =
                    entry.retain_from_height.max(contract.retain_from_height);
                entry.retain_until_height =
                    entry.retain_until_height.min(contract.retain_until_height);
            } else {
                entries.insert(
                    commitment,
                    CellRetainedVersionEntryV1 {
                        version: contract.version.clone(),
                        retain_from_height: contract.retain_from_height,
                        retain_until_height: contract.retain_until_height,
                    },
                );
            }
        }
        let result = CellRetainedVersionSetV1::new(
            current.anchor.generation,
            entries.into_values().collect(),
        )?;
        check_deadline(deadline)?;
        Ok(result)
    }
}

fn public_duty(row: DutyRow) -> CellVersionRetentionDutyV3 {
    CellVersionRetentionDutyV3 {
        contract: row.contract,
        generation: row.generation,
        state: match row.status {
            0 => CellVersionRetentionStateV3::Pending,
            1 => CellVersionRetentionStateV3::Active,
            _ => CellVersionRetentionStateV3::Retired,
        },
    }
}
