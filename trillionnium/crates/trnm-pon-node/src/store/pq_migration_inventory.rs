//! Inventory of an independently selected, already admitted local checkpoint.
//!
//! The same read snapshot supplies its retained header, packet and complete
//! checked State. A retained side branch is valid input; the report makes no
//! claim about canonical membership, currentness, finality or source retirement.
use super::{Node, StateBackend};
use crate::{ensure, Error, Result};
use trnm_mvcc_fee::pon_executor::pq_accounts_v2::{
    migration_inventory_v1::{self, CheckpointInventory, SourcePins},
    CheckpointMaterial, TrustedMigrationAnchor, TrustedPqPrecommitments,
};

impl Node {
    /// Inspect one retained checkpoint without changing its source or choosing
    /// a migration destination. Pins must come from independently selected
    /// source context, not from a report returned by this call.
    ///
    /// This rechecks actual retained state and identity inside one SQLite read
    /// transaction. It does not accept a caller-constructed header or State,
    /// reverify new work, establish source finality or authorize a CLAIM. State
    /// replay and inventory retain the existing complete-State/history costs.
    pub fn inspect_pq_migration_checkpoint(&self, pins: SourcePins) -> Result<CheckpointInventory> {
        self.with_pq_migration_checkpoint(pins, |material| {
            Ok(migration_inventory_v1::inspect_checkpoint(
                pins,
                &material,
                &self.settings.app,
            )?)
        })
    }

    /// Prepare a bounded new-network anchor from this actual admitted source.
    /// The exact prior-registry commitment must be independently retained along
    /// with the checkpoint pins; it is never derived from source account keys.
    ///
    /// Inventory and anchor use one complete SQLite read snapshot. Unsupported
    /// source rows are refused by the original M06 importer, even when their
    /// balance is zero. No source row, active tip or retirement state is changed.
    /// This is not source-finality, prior-binding-time or source-retirement
    /// evidence: those independent premises remain necessary before a cutover.
    pub fn prepare_pq_migration_checkpoint(
        &self,
        pins: SourcePins,
        prior_registry_commitment: [u8; 48],
        registry: TrustedPqPrecommitments,
    ) -> Result<(TrustedMigrationAnchor, CheckpointInventory)> {
        ensure(
            prior_registry_commitment != [0; 48]
                && registry.commitment() == prior_registry_commitment,
            "PQ_MIGRATION_REGISTRY_PIN",
        )?;
        self.with_pq_migration_checkpoint(pins, |material| {
            let report =
                migration_inventory_v1::inspect_checkpoint(pins, &material, &self.settings.app)?;
            let anchor = registry.pin_checkpoint(pins.checkpoint, material, &self.settings.app)?;
            Ok((anchor, report))
        })
    }

    fn with_pq_migration_checkpoint<T>(
        &self,
        pins: SourcePins,
        inspect: impl FnOnce(CheckpointMaterial) -> Result<T>,
    ) -> Result<T> {
        ensure(
            !self.settings.app.is_pq_account_profile(),
            "PQ_INVENTORY_SOURCE_PROFILE",
        )?;
        ensure(
            self.state_backend != StateBackend::PermanentAccountGrowthV2,
            "GROWTH_COMPLETE_STATE_UNAVAILABLE",
        )?;
        ensure(
            pins.network == self.settings.network()
                && pins.genesis == self.settings.genesis()
                && pins.checkpoint != [0; 32],
            "PQ_INVENTORY_CHECKPOINT",
        )?;
        ensure(
            pins.checkpoint != self.settings.genesis(),
            "GENESIS_HAS_NO_PACKET",
        )?;
        self.namespace()?;
        let tx = self.db.unchecked_transaction()?;
        let changes = tx.total_changes();
        self.storage_context()?;
        self.ready()?;
        // The bounded retained-header reader checks the packet length and
        // block/parent record identities before packet() copies its body.
        let header = self.stored_header(pins.checkpoint)?;
        let packet = self.packet(pins.checkpoint)?;
        let trace = packet
            .proof
            .last_chunk::<32>()
            .copied()
            .ok_or_else(|| Error::from("WORK_LENGTH").local_integrity())?;
        let material = CheckpointMaterial {
            genesis: self.settings.genesis(),
            header,
            trace,
            state: self.state_at(pins.checkpoint)?,
        };
        let report = inspect(material)?;
        if tx.total_changes() != changes {
            self.invalidate_commitment();
            return Err(Error::from("PQ_INVENTORY_WRITE").local_integrity());
        }
        tx.rollback()?;
        Ok(report)
    }
}

#[cfg(test)]
#[path = "pq_migration_inventory_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "pq_migration_handoff_tests.rs"]
mod handoff_tests;
