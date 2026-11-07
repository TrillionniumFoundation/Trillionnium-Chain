//! Node-owned bridge to M12. The chain remains the only monetary ledger; M12
//! records local costs/effects and observations of ordinary native payments.
use super::{Node, StateBackend};
use crate::{ensure, Error, Result};
use rusqlite::OptionalExtension;
use trnm_service_settlement::native_budget::{
    NativeBudgetAnchorV1, NativeBudgetErrorV1, NativeBudgetResultV1, NativeFundingObservationV1,
    NativeFundingOwnerV1, NativeFundingSourceV1, NativePaymentObservationV1, NativePaymentQueryV1,
};

impl Node {
    /// Authenticate a snapshot that this owner actually published as active in
    /// the stated generation. Merely retaining a valid side-branch block does
    /// not establish a historical funding or payment observation.
    pub(in crate::store) fn validate_native_active_anchor_v1(
        &self,
        anchor: &NativeBudgetAnchorV1,
    ) -> Result<()> {
        ensure(
            anchor.network == self.settings.network()
                && anchor.parameters == self.settings.parameters()
                && anchor.genesis == self.settings.genesis()
                && anchor.generation <= self.active()?.1,
            "NATIVE_ACTIVE_ANCHOR_CONTEXT",
        )?;
        let record = self.record(anchor.block)?;
        ensure(
            record.root == anchor.state_root && record.height == anchor.height,
            "NATIVE_ACTIVE_ANCHOR_BLOCK",
        )?;
        if anchor.generation == 0 {
            return ensure(
                anchor.block == self.settings.genesis() && anchor.height == 0,
                "NATIVE_ACTIVE_ANCHOR_HISTORY",
            );
        }
        let last: Option<(i64, Vec<u8>)> = self
            .db
            .query_row(
                "SELECT kind,block FROM events WHERE generation=?1 ORDER BY ordinal DESC LIMIT 1",
                [anchor.generation],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        ensure(
            last.as_ref()
                .is_some_and(|(kind, block)| *kind == 1 && block.as_slice() == anchor.block),
            "NATIVE_ACTIVE_ANCHOR_HISTORY",
        )
    }

    /// The actual current anchor and exact monetary row from one verified native
    /// snapshot. No caller-supplied amount, caller State, or historical row can
    /// become funding authority through this method. Absence remains None.
    pub fn native_funding_observation(
        &self,
        source: NativeFundingSourceV1,
    ) -> Result<NativeFundingObservationV1> {
        if self.state_backend == StateBackend::PermanentAccountGrowthV2 {
            let snapshot = self.growth_current_working()?;
            return Ok(NativeFundingObservationV1 {
                anchor: NativeBudgetAnchorV1 {
                    network: snapshot.commitment.network,
                    parameters: snapshot.commitment.parameters,
                    genesis: snapshot.commitment.genesis,
                    block: snapshot.block,
                    state_root: snapshot.commitment.id,
                    height: snapshot.height,
                    generation: snapshot.generation,
                },
                source,
                row: snapshot.working.get(&source.key()).cloned(),
            });
        }
        self.namespace()?;
        let read = self.db.unchecked_transaction()?;
        self.storage_context()?;
        let (block, generation, state) = self.read_active()?;
        let record = self.record(block)?;
        let observation = NativeFundingObservationV1 {
            anchor: NativeBudgetAnchorV1 {
                network: self.settings.network(),
                parameters: self.settings.parameters(),
                genesis: self.settings.genesis(),
                block,
                state_root: record.root,
                height: record.height,
                generation,
            },
            source,
            row: state.get(&source.key()).cloned(),
        };
        self.namespace()?;
        self.storage_context()?;
        read.rollback()?;
        Ok(observation)
    }
}
fn owner_error(error: Error) -> NativeBudgetErrorV1 {
    NativeBudgetErrorV1::Owner(error.to_string())
}
mod payment;
impl NativeFundingOwnerV1 for Node {
    fn observe_funding(
        &mut self,
        source: NativeFundingSourceV1,
    ) -> NativeBudgetResultV1<NativeFundingObservationV1> {
        self.observe_native_budget_funding_v1(source)
            .map_err(owner_error)
    }
    fn observe_payment(
        &mut self,
        query: &NativePaymentQueryV1,
    ) -> NativeBudgetResultV1<NativePaymentObservationV1> {
        self.native_payment_observation(query).map_err(owner_error)
    }
}

#[cfg(test)]
mod tests;
