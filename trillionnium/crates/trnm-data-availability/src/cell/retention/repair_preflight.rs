//! Read-only admission of a complete set of original repair responsibilities.

use super::*;

impl CellRetentionStoreV1 {
    /// Check one read snapshot before a multi-target recovery admits any new
    /// repair. Each tuple is (exact original contract, repair operation,
    /// requires_new_copy). A requested copy must have no previous physical
    /// repair intent: Pending and Done never grant another write. A target-only
    /// reconciliation may need one zero-byte history row, but never new bytes.
    ///
    /// This reserves nothing and verifies no payload. The caller must first
    /// authenticate funding and census the actual original targets. The real
    /// repair owner rechecks all limits when admitting its durable intent.
    pub fn check_repair_reservations(
        &self,
        repairs: &[(CellRetentionContractV1, CellDigestV1, bool)],
        deadline: Instant,
    ) -> CellResultV1<()> {
        check_deadline(deadline)?;
        require(
            repairs.len() <= self.config.maximum_obligations as usize,
            "retention repair preflight count",
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
            let mut count: u64 =
                transaction.query_row("SELECT count(*) FROM repairs", [], |row| row.get(0))?;
            let mut proposed = BTreeSet::new();
            for (contract, repair_operation, requires_new_copy) in repairs {
                check_deadline(deadline)?;
                validate_contract(contract, &self.config)?;
                require(
                    *repair_operation != [0; 32]
                        && *repair_operation != contract.operation
                        && proposed.insert(*repair_operation),
                    "retention repair preflight identity",
                )?;
                let row = rows
                    .iter_mut()
                    .find(|row| row.contract.operation == contract.operation)
                    .ok_or(CellErrorV1::Invalid("retention unknown obligation"))?;
                require(row.contract == *contract, "retention operation changed")?;
                require(row.status != 2, "retention target retired")?;
                if let Some((obligation, amount, complete)) =
                    Self::repair_row_from(&transaction, *repair_operation)?
                {
                    require(
                        obligation == contract.operation
                            && (amount == contract.manifest.size() || (amount == 0 && complete)),
                        "retention repair alias",
                    )?;
                    require(
                        !*requires_new_copy,
                        "retention repair requires reconciliation",
                    )?;
                    continue;
                }
                count = count
                    .checked_add(1)
                    .ok_or(CellErrorV1::Invalid("retention repair record capacity"))?;
                require(
                    count <= u64::from(self.config.maximum_obligations),
                    "retention repair record capacity",
                )?;
                if *requires_new_copy {
                    row.repair_bytes = row
                        .repair_bytes
                        .checked_add(contract.manifest.size())
                        .ok_or(CellErrorV1::Invalid("retention repair overflow"))?;
                    require(
                        row.repair_bytes <= contract.maximum_repair_bytes,
                        "retention repair capacity exhausted",
                    )?;
                }
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
