//! Read-only whole-composition capacity admission. Actual reserves recheck it.
use super::*;

impl CellRetentionStoreV1 {
    /// Simulate first-fit allocations against one read snapshot. Historical
    /// rows still consume metadata capacity. No bytes or effects are admitted.
    pub fn check_reservations(
        &self,
        contracts: &[CellRetentionContractV1],
        deadline: Instant,
    ) -> CellResultV1<()> {
        check_deadline(deadline)?;
        require(
            !contracts.is_empty() && contracts.len() <= self.config.maximum_obligations as usize,
            "retention preflight count",
        )?;
        self.check_arena()?;
        let original_ms: u64 = self
            .connection
            .pragma_query_value(None, "busy_timeout", |row| row.get(0))?;
        let original = Duration::from_millis(original_ms);
        self.connection
            .busy_timeout(original.min(deadline.saturating_duration_since(Instant::now())))?;
        let result = (|| {
            check_deadline(deadline)?;
            let transaction = self.connection.unchecked_transaction()?;
            validate_schema(&transaction)?;
            let mut rows = Self::audit_layout_from(&transaction, &self.config, &mut || {
                check_deadline(deadline)
            })?;
            let mut proposed = std::collections::BTreeSet::new();
            for contract in contracts {
                check_deadline(deadline)?;
                validate_contract(contract, &self.config)?;
                require(
                    proposed.insert(contract.operation),
                    "retention preflight duplicate",
                )?;
                if let Some(previous) = rows
                    .iter()
                    .find(|row| row.contract.operation == contract.operation)
                {
                    require(
                        previous.contract == *contract,
                        "retention operation changed",
                    )?;
                    require(previous.status != 2, "retention target retired")?;
                    continue;
                }
                require(
                    rows.len() < self.config.maximum_obligations as usize,
                    "retention record capacity",
                )?;
                require(
                    rows.iter()
                        .all(|row| row.contract.funding_operation != contract.funding_operation),
                    "retention funding alias",
                )?;
                let reserved = aligned(contract.manifest.size())?;
                let mut offset = 0_u64;
                rows.sort_by_key(|row| row.offset);
                for previous in rows.iter().filter(|row| row.status != 2) {
                    check_deadline(deadline)?;
                    if offset
                        .checked_add(reserved)
                        .is_some_and(|end| end <= previous.offset)
                    {
                        break;
                    }
                    offset = previous
                        .offset
                        .checked_add(previous.reserved)
                        .ok_or(CellErrorV1::Invalid("retention capacity exhausted"))?;
                }
                require(
                    offset
                        .checked_add(reserved)
                        .is_some_and(|end| end <= self.config.capacity_bytes),
                    "retention capacity exhausted",
                )?;
                rows.push(Row {
                    contract: contract.clone(),
                    offset,
                    reserved,
                    status: 0,
                    initial_bytes: 0,
                    repair_bytes: 0,
                });
            }
            check_deadline(deadline)?;
            transaction.rollback()?;
            self.check_arena()?;
            check_deadline(deadline)
        })();
        self.connection.busy_timeout(original)?;
        result
    }
}
