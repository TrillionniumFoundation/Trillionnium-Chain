//! Repeated read-only AAM1 queries for an explicitly pinned historical root.
//! Pin issuance retains the complete native checks. Queries re-read exact record
//! and block identities and real Patricia paths, not the complete State. This is
//! no execution-parent, active-state, retention, admission or finality authority.
use super::{native_authenticated, NativeAccountProofFailure, NativeAccountProofProgress, Node};
use crate::account_archive_prototype::{
    multiproof, native_store, ArchiveError, Checkpoint, Context,
};
use crate::{ensure, Error, Hash, Result};
use rusqlite::Connection;

/// A process-local root pin issued only after complete native State validation.
/// It is deliberately not deserializable. Retained matching records and tree
/// bytes remain required; a pin never promises their availability or current use.
#[derive(Clone, Debug)]
pub struct PinnedNativeAccountQuery {
    context: Context,
    checkpoint: Checkpoint,
    record: native_authenticated::Record,
    block_identity: Hash,
}
impl PinnedNativeAccountQuery {
    /// Fixed historical proof context, never a fresh audit of current native KV.
    pub fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }
}

impl Node {
    /// Keep the original explicit read transaction through every callback and
    /// error exit. Row counters alone cannot detect COMMIT/ROLLBACK followed by
    /// BEGIN, a savepoint ABA, or an automatic transaction rollback.
    pub(super) fn with_account_query_snapshot<T>(
        &self,
        read: impl FnOnce(&Connection) -> Result<T>,
    ) -> Result<T> {
        let tx = self.db.unchecked_transaction()?;
        let changes = tx.total_changes();
        let result = {
            let scope = trnm_sqlite_io_boundary::TransactionScope::capture(&tx)
                .map_err(|error| Error::local_replay_source("NATIVE_ACCOUNT_PROOF_SCOPE", error))?;
            let result = read(&tx);
            let scope_error = scope
                .unchanged()
                .err()
                .map(|error| Error::local_replay_source("NATIVE_ACCOUNT_PROOF_SCOPE", error))
                .or_else(|| {
                    tx.is_autocommit()
                        .then(|| Error::from("NATIVE_ACCOUNT_PROOF_SCOPE").local_integrity())
                });
            match scope_error {
                None => result,
                Some(error) => {
                    self.invalidate_commitment();
                    // A cancellation or storage error cannot hide a replaced
                    // snapshot. Retain the original typed cause for the caller.
                    Err(match result {
                        Ok(_) => error,
                        Err(first) => {
                            Error::local_replay_source("NATIVE_ACCOUNT_PROOF_SCOPE", first)
                        }
                    })
                }
            }
        };
        // Any callback write invalidates derived candidates, including on an
        // ordinary cancellation. An unchanged transaction can still roll that
        // write back, so keep the original error and its cancellation category.
        let wrote = tx.total_changes() != changes;
        if wrote {
            self.invalidate_commitment();
        }
        let output = result?;
        if wrote {
            return Err(Error::from("NATIVE_ACCOUNT_PROOF_WRITE").local_integrity());
        }
        // Queries retain no commit authority, including for uncounted DDL.
        tx.rollback()?;
        Ok(output)
    }

    fn account_query_context(&self) -> Context {
        Context {
            network: self.settings.network(),
            parameters: self.settings.parameters(),
            genesis: self.settings.genesis(),
        }
    }

    // Shared with the original strict query: keep its full validation order.
    pub(super) fn checked_account_query_checkpoint(
        &self,
        db: &Connection,
        block: Hash,
        progress: &(impl Fn(NativeAccountProofProgress) -> Result<()> + ?Sized),
    ) -> Result<(Checkpoint, native_authenticated::Record)> {
        let state = self.state_at_with_progress(block, &mut || {
            progress(NativeAccountProofProgress::StateReplay)
        })?;
        native_authenticated::verify_state(db, &self.settings, block, &state, &mut || {
            progress(NativeAccountProofProgress::StateVerification)
        })?;
        let record = native_authenticated::load(db, block)?;
        let checkpoint = native_store::query_checkpoint(
            db,
            self.account_query_context(),
            block,
            record.height,
            record.state.state_root,
            &record.accounts,
        )?;
        Ok((checkpoint, record))
    }

    /// Audit the complete historical State once, within the existing owner and
    /// one read snapshot. This operation is still linear in State/history.
    pub fn pin_authenticated_account_query(
        &self,
        block: Hash,
        progress: &(impl Fn(NativeAccountProofProgress) -> Result<()> + ?Sized),
    ) -> Result<PinnedNativeAccountQuery> {
        ensure(
            self.state_backend == super::StateBackend::AuthenticatedV1,
            "NATIVE_STATE_BACKEND_REQUIRED",
        )?;
        progress(NativeAccountProofProgress::BeforeRead)?;
        self.namespace()?;
        self.with_account_query_snapshot(|db| {
            self.storage_context()?;
            let (checkpoint, record) =
                self.checked_account_query_checkpoint(db, block, progress)?;
            let pin = PinnedNativeAccountQuery {
                context: self.account_query_context(),
                checkpoint,
                record,
                block_identity: native_authenticated::account_query_block_identity(db, block)?,
            };
            progress(NativeAccountProofProgress::BeforeOutput)?;
            Ok(pin)
        })
    }

    /// Prove requested accounts at a previously audited historical root without
    /// replaying State. The original strict query and all native execution,
    /// publication, recovery and cold-open checks remain separate and unchanged.
    pub fn authenticated_account_multiproof_at_pin(
        &self,
        pin: &PinnedNativeAccountQuery,
        owners: &[Hash],
        progress: &(impl Fn(NativeAccountProofProgress) -> Result<()> + ?Sized),
    ) -> Result<(
        Checkpoint,
        multiproof::Multiproof,
        multiproof::ConstructionObservation,
    )> {
        ensure(
            self.state_backend == super::StateBackend::AuthenticatedV1,
            "NATIVE_STATE_BACKEND_REQUIRED",
        )?;
        if owners.len() > multiproof::MAX_ACCOUNTS {
            return Err(NativeAccountProofFailure::Archive(ArchiveError::Budget).into_error());
        }
        if owners
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != owners.len()
        {
            return Err(
                NativeAccountProofFailure::Archive(ArchiveError::InvalidWitness).into_error(),
            );
        }
        ensure(
            pin.context == self.account_query_context(),
            "NATIVE_ACCOUNT_QUERY_CONTEXT",
        )?;
        progress(NativeAccountProofProgress::BeforeRead)?;
        self.namespace()?;
        self.with_account_query_snapshot(|db| {
            self.storage_context()?;
            let block = pin.record.block;
            ensure(
                native_authenticated::load(db, block)? == pin.record
                    && native_authenticated::account_query_block_identity(db, block)?
                        == pin.block_identity,
                "NATIVE_ACCOUNT_QUERY_PIN_CHANGED",
            )
            .map_err(Error::local_integrity)?;
            let checkpoint = native_store::query_checkpoint(
                db,
                pin.context,
                block,
                pin.record.height,
                pin.record.state.state_root,
                &pin.record.accounts,
            )?;
            ensure(
                checkpoint == pin.checkpoint,
                "NATIVE_ACCOUNT_QUERY_PIN_CHANGED",
            )
            .map_err(Error::local_integrity)?;
            let (proof, observation) =
                multiproof::from_native_database(db, &checkpoint, owners, &|point| {
                    progress(NativeAccountProofProgress::Proof(point))
                        .map_err(NativeAccountProofFailure::Control)
                })
                .map_err(NativeAccountProofFailure::into_error)?;
            progress(NativeAccountProofProgress::BeforeOutput)?;
            Ok((checkpoint, proof, observation))
        })
    }
}

#[cfg(test)]
#[path = "pinned_account_query_tests.rs"]
mod tests;
