//! Opt-in M12 V3 effect owner: every New dispatch/settlement decision crosses
//! a real authenticated external witness. The original V2 research owner is
//! not a fallback for this profile and is not rollback-qualified.
//!
//! Local commit precedes witness CAS. An uncertain CAS never returns New.
//! Cold recovery accepts only exact equality with the independently retained
//! witness head; it never adopts an older local root or republishes an unwitnessed
//! successor. Lost-ACK recovery is observation-only under the original identity.
use super::*;
use crate::pq_rollback_witness::{Checkpoint, WitnessClient};
use trnm_service_settlement::native_generation_budget_v2::{
    DispatchDecisionV2, FailureV2, GenerationReadbackV2, GenerationRecoveryCheckpointV3,
    NativeGenerationStoreV2,
};

pub const RECOVERY_PROFILE_V3: &str = "trnm-m12-witnessed-full-generation-v3";

/// Actual Node funding and generation ownership plus the complete M12 journal.
/// Neither inner journal nor its unguarded dispatch API is exposed by this type.
/// Independent administration, current revocation and provider retention remain
/// deployment obligations; two local test directories do not establish them.
pub struct NodeGenerationOwnerV3<'a, R> {
    owner: NodeGenerationOwnerV2<'a, R>,
    store: NativeGenerationStoreV2,
    witness: WitnessClient,
    fenced: bool,
    // Test-only scheduling boundary: the reply has already been authenticated
    // and its original exchange deadline checked. Never compiled into owners.
    #[cfg(test)]
    pub(super) before_recovery_transaction: Option<Box<dyn FnOnce() + Send>>,
}

fn checkpoint(store: &NativeGenerationStoreV2) -> Result<Checkpoint> {
    let point = store.recovery_checkpoint_v3()?;
    Checkpoint::new(point.sequence, point.root).map_err(owner_error)
}

impl<'a, R: OwnedGenerationRuntimeV2> NodeGenerationOwnerV3<'a, R> {
    /// `independent_binding_pin` and the live witness configuration must come
    /// from the current owner authority outside the restored Node/M12 backup.
    /// This constructor does not initialize a witness or derive a new trust pin
    /// from local files. The witness's own reopen also requires an independently
    /// retained current checkpoint; restoring all trust domains is not detectable.
    pub fn open(
        node: &'a mut Node,
        runtime: &'a mut R,
        store: NativeGenerationStoreV2,
        mut witness: WitnessClient,
        authority_generation: u64,
        independent_binding_pin: [u8; 64],
    ) -> Result<Self> {
        check(
            independent_binding_pin != [0; 64]
                && witness.binding().id() == independent_binding_pin
                && witness
                    .binding()
                    .matches_generation_v3(store.recovery_context_v3()?, authority_generation),
            "GENERATION_RECOVERY_BINDING",
        )?;
        // Quarantine is checked before even opening the local task-owner DB.
        check(
            checkpoint(&store)? == witness.current().map_err(owner_error)?,
            "GENERATION_RECOVERY_ROLLBACK_OR_UNWITNESSED",
        )?;
        Ok(Self {
            owner: NodeGenerationOwnerV2::new(node, runtime)?,
            store,
            witness,
            fenced: false,
            #[cfg(test)]
            before_recovery_transaction: None,
        })
    }

    fn check_current(&mut self) -> Result<Checkpoint> {
        check(!self.fenced, "GENERATION_RECOVERY_QUARANTINED")?;
        let result = (|| {
            let local = checkpoint(&self.store)?;
            let remote = self.witness.current().map_err(owner_error)?;
            check(
                local == remote,
                "GENERATION_RECOVERY_ROLLBACK_OR_UNWITNESSED",
            )?;
            Ok(local)
        })();
        if result.is_err() {
            self.fenced = true;
        }
        result
    }

    fn mutate<T>(
        &mut self,
        action: impl FnOnce(
            &mut NodeGenerationOwnerV2<'a, R>,
            &mut NativeGenerationStoreV2,
        ) -> Result<T>,
    ) -> Result<T> {
        let before = self.check_current()?;
        #[cfg(test)]
        if let Some(hook) = self.before_recovery_transaction.take() {
            hook();
        }
        // The ordinary V2 transaction rechecks this exact authenticated head
        // under its existing SQLite write lock, before invoking an owner or
        // applying an event. A path hash before the transaction is insufficient.
        let outcome = self.store.with_recovery_fence_v3(
            GenerationRecoveryCheckpointV3 {
                sequence: before.sequence,
                root: before.root,
            },
            |store| action(&mut self.owner, store),
        );
        // An action may have committed before reporting a readback error. An
        // error never lets us authenticate a newly observed local successor.
        let after = match checkpoint(&self.store) {
            Ok(after) => after,
            Err(error) => {
                self.fenced = true;
                return Err(error);
            }
        };
        let (value, committed) = match outcome {
            Ok(result) => result,
            Err(error) => {
                if after != before {
                    self.fenced = true;
                }
                return Err(error);
            }
        };
        if committed.sequence != after.sequence || committed.root != after.root {
            self.fenced = true;
            return Err(error("GENERATION_RECOVERY_CONCURRENT_MUTATION"));
        }
        if after != before {
            let anchored = (|| {
                check(
                    before.sequence.checked_add(1) == Some(after.sequence),
                    "GENERATION_RECOVERY_CONCURRENT_MUTATION",
                )?;
                self.witness.advance(before, after).map_err(owner_error)?;
                // Do not return New if another local writer changed the journal
                // during the external exchange. This is not a live-use lease.
                check(
                    checkpoint(&self.store)? == after,
                    "GENERATION_RECOVERY_CONCURRENT_MUTATION",
                )
            })();
            if let Err(error) = anchored {
                self.fenced = true;
                return Err(error);
            }
        }
        Ok(value)
    }

    pub fn prepare(&mut self, statement: GenerationStatementV2) -> Result<Hash> {
        self.mutate(|owner, store| store.prepare(owner, statement))
    }

    fn live_new(&mut self, id: Hash, decision: DispatchDecisionV2) -> Result<DispatchDecisionV2> {
        if matches!(decision, DispatchDecisionV2::New) {
            // Signing and CAS count against the original business deadline.
            // An authenticated late commit remains an intent, never a new lease.
            let statement = self.store.readback(id)?.statement;
            statement
                .original_deadline
                .check(&self.owner.runtime.clock_checkpoint()?)?;
        }
        Ok(decision)
    }

    /// Sole dispatch entry for RECOVERY_PROFILE_V3. Pending/Done never authorize
    /// another provider call, even if an earlier transport result was Unknown.
    pub fn begin(&mut self, id: Hash) -> Result<DispatchDecisionV2> {
        let decision = self.mutate(|owner, store| store.begin(owner, id))?;
        self.live_new(id, decision)
    }

    pub fn bind_job(&mut self, id: Hash, job: ProviderJobV2) -> Result<()> {
        self.mutate(|_, store| store.bind_job(id, job))
    }

    pub fn verify(&mut self, id: Hash, evidence: &GenerationEvidenceV2<'_>) -> Result<()> {
        self.mutate(|owner, store| store.verify(owner, id, evidence))
    }

    pub fn cancel(&mut self, id: Hash, reason: Hash) -> Result<()> {
        self.mutate(|_, store| store.cancel(id, reason))
    }

    /// The ordinary Node still validates exact settlement bytes. This method
    /// creates only a guarded local intent; it cannot sign, submit or pay.
    pub fn prepare_settlement(&mut self, id: Hash, wire: Vec<u8>) -> Result<DispatchDecisionV2> {
        let decision = self.mutate(|owner, store| store.prepare_settlement(owner, id, wire))?;
        self.live_new(id, decision)
    }

    pub fn record_payment(&mut self, id: Hash) -> Result<()> {
        self.mutate(|owner, store| store.record_payment(owner, id))
    }

    pub fn reobserve_payment(&mut self, id: Hash) -> Result<NativePaymentObservationV1> {
        let point = self.check_current()?;
        self.store
            .with_recovery_fence_v3(
                GenerationRecoveryCheckpointV3 {
                    sequence: point.sequence,
                    root: point.root,
                },
                |store| store.reobserve_payment(&mut self.owner, id),
            )
            .map(|(value, _)| value)
    }

    pub fn readback_current(&mut self, id: Hash) -> Result<GenerationReadbackV2> {
        let point = self.check_current()?;
        self.store
            .with_recovery_fence_v3(
                GenerationRecoveryCheckpointV3 {
                    sequence: point.sequence,
                    root: point.root,
                },
                |store| store.readback(id),
            )
            .map(|(value, _)| value)
    }

    /// Historical observation is permitted in quarantine, with no effect
    /// authorization. It cannot clear the fence, return New or reduce a charge.
    pub fn historical_readback(&self, id: Hash) -> Result<GenerationReadbackV2> {
        self.store.readback(id)
    }

    pub fn is_quarantined(&self) -> bool {
        self.fenced
    }

    #[cfg(test)]
    pub(super) fn fixture_error_after_committed_cancel(&mut self, id: Hash) -> Result<()> {
        self.mutate(|_, store| {
            store.cancel(id, [62; 32])?;
            Err(error("EXPLICIT_ERROR_AFTER_LOCAL_COMMIT"))
        })
    }
}

impl<R: OwnedTerminalGenerationRuntimeV3> NodeGenerationOwnerV3<'_, R> {
    /// Preserve the original terminal evidence and full cap if any process/GPU
    /// observation remains unknown. This cannot dispatch, refund or settle.
    pub fn reconcile_terminal_failure(&mut self, id: Hash) -> Result<FailureV2> {
        self.mutate(|owner, store| owner.reconcile_terminal_failure(store, id))
    }
}
