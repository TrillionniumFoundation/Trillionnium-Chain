//! Metadata/space admission before the original native M12 effect intent.

use super::*;

impl CellRs46ShardProviderV1 {
    /// Read-only global descriptor/history/extent admission. Actual reserves
    /// still check each original target under its original writer.
    pub fn check_reservations(
        &self,
        contracts: &[&CellRs46ShardContractV1],
        deadline: Instant,
    ) -> CellResultV1<()> {
        check(deadline)?;
        require(
            !contracts.is_empty() && contracts.len() <= self.config.maximum_obligations as usize,
            "RS46 provider preflight count",
        )?;
        let mut count = self.descriptor_count(Some(deadline))?;
        let mut operations = std::collections::BTreeSet::new();
        let mut physical = Vec::with_capacity(contracts.len());
        for contract in contracts {
            check(deadline)?;
            self.check_contract(contract, contract.operation())?;
            require(
                operations.insert(contract.operation()),
                "RS46 provider preflight duplicate",
            )?;
            let path = self.descriptors_path.join(digest_hex(contract.operation()));
            match fs::symlink_metadata(path) {
                Ok(_) => require(
                    self.descriptor(contract.binding(), contract.operation(), deadline)?
                        == **contract,
                    "RS46 provider descriptor changed",
                )?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    count = count
                        .checked_add(1)
                        .ok_or(CellErrorV1::Invalid("RS46 provider descriptor capacity"))?;
                    require(
                        count <= self.config.maximum_obligations,
                        "RS46 provider descriptor capacity",
                    )?;
                }
                Err(error) => return Err(error.into()),
            }
            physical.push(contract.retention_contract());
        }
        self.arena.check_reservations(&physical, deadline)?;
        self.check_descriptor_directory()?;
        check(deadline)
    }

    pub fn configuration(&self) -> &CellRs46ShardProviderConfigV1 {
        &self.config
    }

    /// Preserve the complete original CSP1 and reserve its physical extent.
    /// No source is inspected and no initial or repair byte is copied. Native
    /// callers use this before recording the original M12 effect intent, then
    /// permit a source write only when that intent was returned as New.
    pub fn reserve(
        &mut self,
        contract: &CellRs46ShardContractV1,
        expected_operation: CellDigestV1,
        deadline: Instant,
    ) -> CellResultV1<CellRetentionReadbackV1> {
        check(deadline)?;
        self.check_contract(contract, expected_operation)?;
        self.persist_descriptor(contract, expected_operation, deadline)?;
        check(deadline)?;
        let result = self
            .arena
            .reserve_until(contract.retention_contract(), deadline)?;
        check(deadline)?;
        self.check_reserved_contract(contract)?;
        let actual = self.descriptor(contract.binding(), expected_operation, deadline)?;
        require(actual == *contract, "RS46 reserved descriptor changed")?;
        check(deadline)?;
        Ok(result)
    }
}
