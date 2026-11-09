//! Metadata/space admission before the original native M12 effect intent.

use super::*;

impl CellRs46ShardProviderV1 {
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
