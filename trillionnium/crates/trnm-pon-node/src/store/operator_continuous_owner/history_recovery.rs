//! Explicit local recovery selector, not a new V5 signature or journal meaning.
//! A held Node is not published until the exact authorized History operation
//! actually activates and both original CPU scopes have known settlements.
use super::*;
#[cfg(test)]
use crate::ingress::OwnedHistoryProgress;
use crate::ingress::{OwnedHistoryRequest, OwnedHistoryResult};
use serde::Deserialize;
use std::net::SocketAddr;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryRecoverySelection {
    pub schema: String,
    pub target: String,
    pub prior_validation_operation_id: String,
    pub prior_validation_settled_record_sha256: String,
    pub validation_operation_id: String,
    pub activation_operation_id: String,
}
impl HistoryRecoverySelection {
    pub(super) fn check(&self) -> Result<()> {
        ensure(
            self.schema == "restricted-continuous-single-successor-recovery-v1",
            "OWNER_CONTINUOUS_HISTORY_RECOVERY_SCHEMA",
        )?;
        for value in [
            &self.target,
            &self.prior_validation_operation_id,
            &self.prior_validation_settled_record_sha256,
            &self.validation_operation_id,
            &self.activation_operation_id,
        ] {
            ensure(
                value.len() == 64
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "OWNER_CONTINUOUS_HISTORY_RECOVERY_ID",
            )?;
        }
        ensure(
            self.validation_operation_id != self.prior_validation_operation_id
                && self.validation_operation_id != self.activation_operation_id
                && self.activation_operation_id != self.prior_validation_operation_id,
            "OWNER_CONTINUOUS_HISTORY_RECOVERY_FRESH_OPERATIONS",
        )
    }
    pub(super) fn permits(&self, claim: &history::Claim) -> bool {
        (claim.purpose == "receiver-validation" && claim.operation == self.validation_operation_id)
            || (claim.purpose == "receiver-activate"
                && claim.operation == self.activation_operation_id)
    }
    pub(super) fn target_id(&self) -> Result<Hash> {
        crate::digest(&self.target)
    }
}

/// No mutable Node getter or Deref is provided. Readback, cancellation, a single
/// exact resume, and clean close are available while recovery is held.
pub struct ContinuousHistoryRecovery {
    pub(super) node: Node,
    model: Vec<u8>,
    input: Vec<u8>,
    selection: HistoryRecoverySelection,
    attempted: bool,
    result: Option<OwnedHistoryResult>,
}
impl ContinuousHistoryRecovery {
    pub fn active(&self) -> Result<(Hash, u64)> {
        self.node.active()
    }
    pub fn journal_head(&self) -> Result<serde_json::Value> {
        self.node.continuous_journal_head()
    }
    pub fn scope_receipt(&self, operation: &str) -> Result<serde_json::Value> {
        self.node.continuous_scope_receipt(operation)
    }
    pub fn process_cpu_snapshot(&self) -> Result<serde_json::Value> {
        self.node.continuous_process_cpu_snapshot()
    }
    pub fn cancellation_handle(&self) -> Result<ContinuousEpochCancellation> {
        self.node.continuous_cancellation_handle()
    }
    pub fn outcome(&self) -> Option<&OwnedHistoryResult> {
        self.result.as_ref()
    }
    pub fn resume_from(
        &mut self,
        source: SocketAddr,
        raw_page: &[u8],
        observed_now: u64,
    ) -> Result<&OwnedHistoryResult> {
        ensure(
            !self.attempted,
            "OWNER_CONTINUOUS_HISTORY_RECOVERY_ALREADY_ATTEMPTED",
        )?;
        self.attempted = true;
        let after = self.node.active()?.0;
        let result = crate::ingress::receive_public_owned_history_from(
            &mut self.node,
            source,
            OwnedHistoryRequest {
                raw_page,
                tip: self.selection.target_id()?,
                after,
                validation_operation_id: &self.selection.validation_operation_id,
                activation_operation_id: &self.selection.activation_operation_id,
                observed_now,
            },
        )?;
        self.result = Some(result);
        self.result
            .as_ref()
            .ok_or_else(|| "OWNER_CONTINUOUS_HISTORY_RECOVERY_RESULT".into())
    }
    #[cfg(test)]
    pub(super) fn resume_native_fixture(
        &mut self,
        raw_page: &[u8],
        observed_now: u64,
        resource: &(dyn Fn(OwnedHistoryProgress) -> Result<()> + Sync),
    ) -> Result<&OwnedHistoryResult> {
        ensure(
            !self.attempted,
            "OWNER_CONTINUOUS_HISTORY_RECOVERY_ALREADY_ATTEMPTED",
        )?;
        self.attempted = true;
        let after = self.node.active()?.0;
        let result = self.node.receive_owned_history_operation(
            OwnedHistoryRequest {
                raw_page,
                tip: self.selection.target_id()?,
                after,
                validation_operation_id: &self.selection.validation_operation_id,
                activation_operation_id: &self.selection.activation_operation_id,
                observed_now,
            },
            resource,
        )?;
        self.result = Some(result);
        self.result
            .as_ref()
            .ok_or_else(|| "OWNER_CONTINUOUS_HISTORY_RECOVERY_RESULT".into())
    }
    /// A successful local receipt is checked against real native active metadata
    /// and retained known original scopes before normal mutable access is returned.
    pub fn into_ready(mut self) -> Result<(Node, Vec<u8>, Vec<u8>)> {
        let result = self
            .result
            .as_ref()
            .ok_or("OWNER_CONTINUOUS_HISTORY_RECOVERY_INCOMPLETE")?;
        let target = self.selection.target_id()?;
        let generation = self
            .node
            .continuous_owner
            .as_ref()
            .ok_or("OWNER_CONTINUOUS_MODE_REQUIRED")?
            .view
            .body
            .actual_generation
            .checked_add(1)
            .ok_or("OWNER_CONTINUOUS_HISTORY_RECOVERY_GENERATION")?;
        ensure(
            result.completed
                && result.validation.native_id == Some(target)
                && result.activation.as_ref().is_some_and(|step| {
                    step.native_id == Some(target)
                        && step.accounting_record_persisted
                        && !step.cpu.accounting_unavailable
                        && !step.cpu.live_refused
                })
                && result.validation.accounting_record_persisted
                && !result.validation.cpu.accounting_unavailable
                && !result.validation.cpu.live_refused
                && self.node.active()? == (target, generation),
            "OWNER_CONTINUOUS_HISTORY_RECOVERY_INCOMPLETE",
        )?;
        let owner = self
            .node
            .continuous_owner
            .as_mut()
            .ok_or("OWNER_CONTINUOUS_MODE_REQUIRED")?;
        ensure(owner.slot()?.is_none(), "OWNER_CONTINUOUS_SCOPE_BUSY")?;
        owner.ready()?;
        {
            let journal = owner
                .journal
                .lock()
                .map_err(|_| "OWNER_CONTINUOUS_JOURNAL_UNKNOWN")?;
            for operation in [
                &self.selection.validation_operation_id,
                &self.selection.activation_operation_id,
            ] {
                let receipt = journal
                    .scope_receipt(&scope_id(operation))
                    .map_err(continuous_error)?;
                ensure(
                    receipt.linked_operations == vec![operation.clone()],
                    "OWNER_CONTINUOUS_HISTORY_RECOVERY_RECEIPT",
                )?;
            }
        }
        let cpu = owner.cpu.observe()?;
        ensure(
            cpu.in_flight == 0 && !cpu.accounting_unavailable,
            "OWNER_CONTINUOUS_HISTORY_RECOVERY_ACCOUNTING",
        )?;
        owner.history_recovery = None;
        Ok((self.node, self.model, self.input))
    }
    /// Failure/unknown accounting is never changed into a clean-close record.
    pub fn close_checkpoint(self) -> Result<serde_json::Value> {
        self.node.close_continuous_checkpoint()
    }
}

impl Node {
    pub fn open_operator_continuous_history_recovery(
        path: &Path,
        inputs: policy::Inputs,
        deadline: std::time::Instant,
        workers: usize,
        selection: HistoryRecoverySelection,
    ) -> Result<ContinuousHistoryRecovery> {
        selection.check()?;
        let (node, model, input) = Self::open_continuous_checkpoint_internal(
            path,
            inputs,
            deadline,
            workers,
            Some(selection.clone()),
        )?;
        Ok(ContinuousHistoryRecovery {
            node,
            model,
            input,
            selection,
            attempted: false,
            result: None,
        })
    }
    pub(super) fn continuous_authorized_history_recovery(
        &self,
        owner: &ContinuousOwner,
        selection: &HistoryRecoverySelection,
        tip: Hash,
        generation: u64,
        best: Hash,
    ) -> Result<()> {
        selection.check()?;
        ensure(
            best != tip && best == selection.target_id()?,
            "OWNER_CONTINUOUS_HISTORY_RECOVERY_TARGET",
        )?;
        let validation = super::history_import::selected(
            owner,
            &selection.validation_operation_id,
            "receiver-validation",
        )?;
        let activation = super::history_import::selected(
            owner,
            &selection.activation_operation_id,
            "receiver-activate",
        )?;
        ensure(
            validation.parent == hex::encode(tip)
                && validation.generation == generation
                && validation.payload == activation.payload
                && validation.parent == activation.parent
                && validation.generation == activation.generation
                && validation.native_task == activation.native_task
                && validation.instance_class == activation.instance_class
                && validation.task_binding == activation.task_binding,
            "OWNER_CONTINUOUS_HISTORY_RECOVERY_CLAIM_PAIR",
        )?;
        let packet = self.packet(best)?;
        ensure(
            packet.header.parent == tip
                && packet.header.height
                    == self.parent_height(tip)?.checked_add(1).ok_or("HEIGHT")?,
            "OWNER_CONTINUOUS_HISTORY_RECOVERY_SINGLE_SUCCESSOR",
        )?;
        owner
            .view
            .permission("receiver-validation", &validation.payload)
            .map_err(continuous_error)?
            .check_exact_receiver_packet(&packet, tip, generation)
            .map_err(continuous_error)?;
        let journal = owner
            .journal
            .lock()
            .map_err(|_| "OWNER_CONTINUOUS_JOURNAL_UNKNOWN")?;
        ensure(
            !journal.operation_used(&selection.validation_operation_id)
                && !journal.operation_used(&selection.activation_operation_id),
            "OWNER_CONTINUOUS_HISTORY_RECOVERY_FRESH_OPERATIONS",
        )?;
        journal
            .check_nonce_window(packet.header.nonce, packet.header.nonce)
            .map_err(continuous_error)?;
        let prior = journal
            .claim(&selection.prior_validation_operation_id)
            .map_err(continuous_error)?;
        ensure(
            prior.purpose == "receiver-validation"
                && prior.payload == validation.payload
                && prior.parent == validation.parent
                && prior.generation == validation.generation
                && prior.native_task == validation.native_task
                && prior.instance_class == validation.instance_class
                && prior.task_binding == validation.task_binding,
            "OWNER_CONTINUOUS_HISTORY_RECOVERY_PRIOR_BINDING",
        )?;
        let settled = journal
            .scope_receipt(&scope_id(&selection.prior_validation_operation_id))
            .map_err(continuous_error)?;
        ensure(
            settled.settled_record_sha256 == selection.prior_validation_settled_record_sha256
                && settled.linked_operations
                    == vec![selection.prior_validation_operation_id.clone()],
            "OWNER_CONTINUOUS_HISTORY_RECOVERY_PRIOR_SETTLEMENT",
        )?;
        Ok(())
    }
}
