//! Node-owned bridge to M12. The chain remains the only monetary ledger; M12
//! records local costs/effects and observations of ordinary native payments.
use super::{Node, StateBackend};
use crate::{Error, Result};
use trnm_service_settlement::native_budget::{
    NativeBudgetAnchorV1, NativeBudgetErrorV1, NativeBudgetResultV1, NativeFundingObservationV1,
    NativeFundingOwnerV1, NativeFundingSourceV1, NativePaymentObservationV1, NativePaymentQueryV1,
};

impl Node {
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
        self.native_funding_observation(source).map_err(owner_error)
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
