//! Same-owner termination of an unpublished multi-step reorganization.
//! A reserved lifecycle row and paid headroom precede the durable intent.
//! Cancellation may only mark that staging operation terminal; it cannot
//! activate a block, edit State, acknowledge a peer or renew a deadline.
use super::*;
use crate::ingress::public_v3::{
    scalar_cpu::{reorg_cleanup_interrupt, ReorgTerminationCpuReservation},
    ServiceMutationCpuCheckpoint,
};
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

pub(super) struct Reservation {
    old: Hash,
    target: Hash,
    generation: u64,
    old_slot: u64,
    old_root: Hash,
    owner_context: Hash,
    data_version: u64,
    schema_version: u64,
    temp_schema_version: u64,
    operation: Option<i64>,
    _cpu: Option<ReorgTerminationCpuReservation>,
}

struct Lifecycle {
    operation: i64,
    old: Hash,
    target: Hash,
    generation: u64,
    old_slot: u64,
    old_root: Hash,
    owner_context: Hash,
    outcome: u64,
    cursor: Option<u64>,
    reason: String,
}

fn cancellation_authorizer(context: AuthContext<'_>) -> Authorization {
    match context.action {
        AuthAction::Select | AuthAction::Transaction { .. } => Authorization::Allow,
        AuthAction::Read { .. } if context.database_name == Some("main") => Authorization::Allow,
        AuthAction::Pragma {
            pragma_name: "data_version" | "schema_version",
            pragma_value: None,
        } => Authorization::Allow,
        AuthAction::Update {
            table_name,
            column_name,
        } if context.accessor.is_none()
            && context.database_name == Some("main")
            && ((table_name == "reorg" && column_name == "done")
                || (table_name == "reorg_lifecycle_v1"
                    && matches!(column_name, "outcome" | "cancelled_cursor" | "reason"))) =>
        {
            Authorization::Allow
        }
        // In particular, trigger/view writes, State, active pointers, block
        // facts, peer replay, local revocations and CPU journals are forbidden.
        _ => Authorization::Deny,
    }
}

struct CleanupSqlGuard<'a> {
    db: &'a Connection,
    prior_busy_ms: u64,
}
impl Drop for CleanupSqlGuard<'_> {
    fn drop(&mut self) {
        self.db
            .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
            .expect("Node owns the SQLite connection when removing its authorizer");
        self.db
            .progress_handler(0, None::<fn() -> bool>)
            .expect("Node owns the SQLite connection when removing its progress handler");
        // Restoring the same connection policy grants no work authority. A
        // panic still rolls back the transaction and poisons its outer owner.
        let _ = self
            .db
            .busy_timeout(Duration::from_millis(self.prior_busy_ms));
    }
}

impl Node {
    pub(super) fn resume_owned_reorg(
        &mut self,
        hook: &mut Option<&mut Hook<'_>>,
        progress: &mut dyn FnMut() -> Result<()>,
        cpu: Option<&ServiceMutationCpuCheckpoint>,
    ) -> Result<Hash> {
        let pending: Option<(Vec<u8>, Vec<u8>, u64)> = self
            .db
            .query_row(
                "SELECT old_tip,new_tip,generation FROM reorg WHERE singleton=1 AND done=0",
                [],
                |row| {
                    Ok((
                        fixed_blob::<32>(row, 0)?,
                        fixed_blob::<32>(row, 1)?,
                        row.get(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((old, target, generation)) = pending else {
            return self.resume_intent_with_progress(hook, progress);
        };
        let target = bytes32(target)?;
        // A new call's activation permit cannot authorize a different old
        // pending target merely because both live under the same Node lock.
        self.continuous_activation_gate(target)?;
        self.mining_activation_gate(target)?;
        let mut reservation =
            self.reserve_reorg_cancellation(bytes32(old)?, target, generation, cpu)?;
        reservation.operation = Some(self.last_reorg_lifecycle()?.operation);
        self.check_reserved_reorg_lifecycle(&reservation, 0, None, "")?;
        let outcome = self.resume_intent_with_progress(hook, progress);
        self.finish_or_cancel_reorg(&reservation, outcome, hook)
    }

    pub(super) fn reorg_owner_context(&self) -> Hash {
        // Logical owner identity survives the existing explicit Legacy ->
        // Authenticated copy migration. Actual schema, inode and SQLite epochs
        // are separately pinned by each live Reservation; copying historical
        // records never transfers a live reservation or grants a CPU scope.
        let marker = self
            .owner_policy
            .as_ref()
            .map(|owner| owner.required_marker.as_slice())
            .or_else(|| {
                self.mining_owner
                    .as_ref()
                    .map(|owner| owner.marker.as_slice())
            })
            .or_else(|| {
                self.continuous_owner
                    .as_ref()
                    .map(|owner| owner.marker.as_slice())
            })
            .unwrap_or_default();
        hash(
            b"native-reorg-lifecycle-owner-v1",
            &[
                &self.settings.genesis(),
                &self.settings.parameters(),
                marker,
            ],
        )
    }

    pub(super) fn reserve_reorg_cancellation(
        &self,
        old: Hash,
        target: Hash,
        generation: u64,
        cpu: Option<&ServiceMutationCpuCheckpoint>,
    ) -> Result<Reservation> {
        self.namespace()?;
        self.storage_context()?;
        let continuous_cpu = self.continuous_reorg_original_cpu()?;
        let mining_cpu = self.mining_reorg_original_cpu()?;
        ensure(
            continuous_cpu.is_none() || mining_cpu.is_none(),
            "OWNER_REORG_TERMINATION_CPU_REQUIRED",
        )?;
        let original_cpu = continuous_cpu
            .as_ref()
            .or_else(|| mining_cpu.as_ref().map(|(_, cpu)| cpu));
        let cpu = if let Some(original) = original_cpu {
            ensure(
                cpu.is_none_or(|provided| provided.shares_operation_with(original)),
                "OWNER_PUBLIC_SERVICE_CPU_DOMAIN",
            )?;
            Some(original)
        } else {
            cpu
        };
        let domain = mining_cpu
            .as_ref()
            .map(|(domain, _)| Ok(domain.clone()))
            .unwrap_or_else(|| self.public_service_cpu_domain());
        let reserved = match (domain, cpu) {
            (Ok(domain), Some(cpu)) => {
                ensure(
                    cpu.shares_domain_with(&domain),
                    "OWNER_PUBLIC_SERVICE_CPU_DOMAIN",
                )?;
                Some(cpu.reserve_reorg_termination()?)
            }
            (Ok(_), None) => return Err("OWNER_REORG_TERMINATION_CPU_REQUIRED".into()),
            (Err(error), None) if error.is(crate::ErrorCode::OwnerPublicServiceDomainUnbound) => {
                // Existing unmetered local APIs remain explicitly unmetered.
                // This branch creates no CPU account or paid-service claim.
                ensure(
                    self.continuous_owner.is_none() && self.mining_owner.is_none(),
                    "OWNER_REORG_TERMINATION_CPU_REQUIRED",
                )?;
                None
            }
            (Err(error), _) => return Err(error),
        };
        self.continuous_scope_checkpoint()?;
        ensure(
            generation > 0 && self.active()? == (old, generation - 1),
            "GENERATION",
        )
        .map_err(Error::local_integrity)?;
        Ok(Reservation {
            old,
            target,
            generation,
            old_slot: self.slot()?,
            old_root: self.record(old)?.root,
            owner_context: self.reorg_owner_context(),
            data_version: self
                .db
                .query_row("PRAGMA data_version", [], |row| row.get(0))?,
            schema_version: self
                .db
                .query_row("PRAGMA schema_version", [], |row| row.get(0))?,
            temp_schema_version: self
                .db
                .query_row("PRAGMA temp.schema_version", [], |row| row.get(0))?,
            operation: None,
            _cpu: reserved,
        })
    }

    pub(super) fn insert_reorg_lifecycle(&self, reservation: &mut Reservation) -> Result<()> {
        ensure(reservation.operation.is_none(), "REORG_LIFECYCLE")?;
        let changed = self.db.execute(
            "INSERT INTO reorg_lifecycle_v1(old_tip,new_tip,generation,old_slot,old_root,owner_context,outcome,cancelled_cursor,reason) VALUES(?,?,?,?,?,?,0,NULL,'')",
            params![reservation.old.as_slice(), reservation.target.as_slice(), reservation.generation,
                reservation.old_slot, reservation.old_root.as_slice(), reservation.owner_context.as_slice()],
        )?;
        ensure(changed == 1, "REORG_LIFECYCLE").map_err(Error::local_integrity)?;
        reservation.operation = Some(self.db.last_insert_rowid());
        self.check_reserved_reorg_lifecycle(reservation, 0, None, "")
    }

    fn last_reorg_lifecycle(&self) -> Result<Lifecycle> {
        self.db.query_row(
            "SELECT operation,old_tip,new_tip,generation,old_slot,old_root,owner_context,outcome,cancelled_cursor,reason FROM reorg_lifecycle_v1 ORDER BY operation DESC LIMIT 1",
            [], |row| Ok((row.get::<_, i64>(0)?, fixed_blob::<32>(row, 1)?, fixed_blob::<32>(row, 2)?,
                row.get::<_, u64>(3)?, row.get::<_, u64>(4)?, fixed_blob::<32>(row, 5)?,
                fixed_blob::<32>(row, 6)?, row.get::<_, u64>(7)?, row.get::<_, Option<u64>>(8)?,
                row.get::<_, String>(9)?)),
        ).map_err(|error| Error::from(error).local_integrity()).and_then(|row| {
            ensure(row.0 > 0 && row.9.len() <= 96, "REORG_LIFECYCLE")
                .map_err(Error::local_integrity)?;
            Ok(Lifecycle {operation:row.0, old:bytes32(row.1)?, target:bytes32(row.2)?,
                generation:row.3, old_slot:row.4, old_root:bytes32(row.5)?, owner_context:bytes32(row.6)?,
                outcome:row.7, cursor:row.8, reason:row.9})
        })
    }

    fn check_reserved_reorg_lifecycle(
        &self,
        expected: &Reservation,
        outcome: u64,
        cursor: Option<u64>,
        reason: &str,
    ) -> Result<()> {
        let row = self.last_reorg_lifecycle()?;
        ensure(
            Some(row.operation) == expected.operation
                && row.old == expected.old
                && row.target == expected.target
                && row.generation == expected.generation
                && row.old_slot == expected.old_slot
                && row.old_root == expected.old_root
                && row.owner_context == expected.owner_context
                && row.outcome == outcome
                && row.cursor == cursor
                && row.reason == reason,
            "REORG_LIFECYCLE",
        )
        .map_err(Error::local_integrity)
    }

    pub(super) fn finish_reorg_lifecycle(
        &self,
        old: Hash,
        target: Hash,
        generation: u64,
    ) -> Result<()> {
        let row = self.last_reorg_lifecycle()?;
        ensure(
            row.old == old
                && row.target == target
                && row.generation == generation
                && row.outcome == 0
                && row.cursor.is_none()
                && row.reason.is_empty()
                && row.owner_context == self.reorg_owner_context(),
            "REORG_LIFECYCLE",
        )
        .map_err(Error::local_integrity)?;
        ensure(
            self.db.execute(
                "UPDATE reorg_lifecycle_v1 SET outcome=1 WHERE operation=? AND outcome=0",
                [row.operation],
            )? == 1,
            "REORG_LIFECYCLE",
        )
        .map_err(Error::local_integrity)?;
        let after = self.last_reorg_lifecycle()?;
        ensure(
            after.operation == row.operation
                && after.outcome == 1
                && after.old == old
                && after.target == target
                && after.generation == generation
                && after.old_slot == row.old_slot
                && after.old_root == row.old_root
                && after.owner_context == row.owner_context
                && after.cursor.is_none()
                && after.reason.is_empty(),
            "REORG_LIFECYCLE",
        )
        .map_err(Error::local_integrity)
    }

    pub(super) fn check_cancelled_reorg_lifecycle(&self) -> Result<()> {
        let (old, target, generation, cursor, done): (Vec<u8>, Vec<u8>, u64, u64, u64) =
            self.db.query_row(
                "SELECT old_tip,new_tip,generation,cursor,done FROM reorg WHERE singleton=1",
                [],
                |row| {
                    Ok((
                        fixed_blob::<32>(row, 0)?,
                        fixed_blob::<32>(row, 1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )?;
        let row = self.last_reorg_lifecycle()?;
        ensure(
            done == 2
                && row.old == bytes32(old)?
                && row.target == bytes32(target)?
                && row.generation == generation
                && row.outcome == 2
                && row.cursor == Some(cursor)
                && !row.reason.is_empty()
                && row.owner_context == self.reorg_owner_context()
                && row.old_root == self.record(row.old)?.root,
            "REORG_LIFECYCLE",
        )
        .map_err(Error::local_integrity)
    }

    pub(super) fn finish_or_cancel_reorg(
        &self,
        reservation: &Reservation,
        outcome: Result<Hash>,
        hook: &mut Option<&mut Hook<'_>>,
    ) -> Result<Hash> {
        let Err(error) = outcome else {
            return outcome;
        };
        if error.kind() != crate::ErrorKind::Cancelled
            && !error.is(crate::ErrorCode::PublicMutationCpuBudget)
            && !error.is(crate::ErrorCode::OwnerContinuousCpuBudget)
        {
            return Err(error);
        }
        let reason = error
            .code()
            .map_or("LOCAL_CANCELLED", crate::ErrorCode::as_str);
        self.cancel_unpublished_reorg(reservation, reason, hook)
            .map_err(Error::local_integrity)?;
        // Keep the original nonterminal local outcome. No terminal peer ACK,
        // nonce advancement or completed activation is fabricated by cleanup.
        Err(error)
    }

    fn cancel_unpublished_reorg(
        &self,
        reservation: &Reservation,
        reason: &str,
        hook: &mut Option<&mut Hook<'_>>,
    ) -> Result<()> {
        self.namespace()?;
        self.storage_context()?;
        ensure(
            reservation.owner_context == self.reorg_owner_context(),
            "REORG_LIFECYCLE",
        )
        .map_err(Error::local_integrity)?;
        let prior_busy_ms: u64 = self
            .db
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))?;
        self.db.busy_timeout(Duration::ZERO)?;
        let _guard = CleanupSqlGuard {
            db: &self.db,
            prior_busy_ms,
        };
        self.db
            .progress_handler(100, Some(reorg_cleanup_interrupt()?))?;
        self.db.authorizer(Some(cancellation_authorizer))?;
        cut(hook, "cancel-before-transaction")?;
        let tx = rusqlite::Transaction::new_unchecked(
            &self.db,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let data_version: u64 = self
            .db
            .query_row("PRAGMA data_version", [], |row| row.get(0))?;
        let schema_version: u64 = self
            .db
            .query_row("PRAGMA schema_version", [], |row| row.get(0))?;
        let temp_schema_version: u64 =
            self.db
                .query_row("PRAGMA temp.schema_version", [], |row| row.get(0))?;
        ensure(
            data_version == reservation.data_version
                && schema_version == reservation.schema_version
                && temp_schema_version == reservation.temp_schema_version,
            "STORAGE_CONTEXT",
        )
        .map_err(Error::local_integrity)?;
        let done: u64 =
            self.db
                .query_row("SELECT done FROM reorg WHERE singleton=1", [], |row| {
                    row.get(0)
                })?;
        if done == 1 {
            self.check_reserved_reorg_lifecycle(reservation, 1, None, "")?;
            tx.rollback()?;
            return Ok(());
        }
        ensure(
            done == 0
                && self.active()? == (reservation.old, reservation.generation - 1)
                && self.slot()? == reservation.old_slot
                && self.record(reservation.old)?.root == reservation.old_root,
            "REORG_LIFECYCLE",
        )
        .map_err(Error::local_integrity)?;
        self.check_reserved_reorg_lifecycle(reservation, 0, None, "")?;
        let cursor: u64 =
            self.db
                .query_row("SELECT cursor FROM reorg WHERE singleton=1", [], |row| {
                    row.get(0)
                })?;
        self.check_reorg_row(
            reservation.old,
            reservation.target,
            reservation.generation,
            cursor,
            0,
        )?;
        let before = self.db.total_changes();
        ensure(self.db.execute(
            "UPDATE reorg_lifecycle_v1 SET outcome=2,cancelled_cursor=?,reason=? WHERE operation=? AND outcome=0",
            params![cursor, reason, reservation.operation.ok_or("REORG_LIFECYCLE")?],
        )? == 1, "REORG_LIFECYCLE").map_err(Error::local_integrity)?;
        cut(hook, "cancel-lifecycle-written")?;
        ensure(self.db.execute(
            "UPDATE reorg SET done=2 WHERE singleton=1 AND done=0 AND old_tip=? AND new_tip=? AND generation=? AND cursor=?",
            params![reservation.old.as_slice(), reservation.target.as_slice(), reservation.generation, cursor],
        )? == 1, "REORG_LIFECYCLE").map_err(Error::local_integrity)?;
        ensure(
            self.db.total_changes() == before + 2
                && self.active()? == (reservation.old, reservation.generation - 1)
                && self.slot()? == reservation.old_slot,
            "REORG_LIFECYCLE",
        )
        .map_err(Error::local_integrity)?;
        self.check_reserved_reorg_lifecycle(reservation, 2, Some(cursor), reason)?;
        self.check_reorg_row(
            reservation.old,
            reservation.target,
            reservation.generation,
            cursor,
            2,
        )?;
        tx.commit()?;
        cut(hook, "cancel-committed")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
