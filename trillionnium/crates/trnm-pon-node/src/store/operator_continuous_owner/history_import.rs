//! Explicit V5 single-successor History operation. This adapter does not alter
//! the signed parent/generation domain or authorize arbitrary fork import.
use super::*;
use crate::ingress::{
    OwnedHistoryProgress, OwnedHistoryRequest, OwnedHistoryResult, OwnedHistoryStepResult, Page,
};

const MAX_OWNED_PAGE_BYTES: usize = 2 * 1024 * 1024;

pub(super) fn selected<'a>(
    owner: &'a ContinuousOwner,
    operation: &str,
    purpose: &str,
) -> Result<&'a history::Claim> {
    ensure(
        operation.len() == 64
            && operation
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "OWNER_CONTINUOUS_HISTORY_OPERATION_ID",
    )?;
    owner
        .view
        .allocations
        .iter()
        .find(|allocation| {
            allocation.claim().operation == operation && allocation.claim().purpose == purpose
        })
        .map(|allocation| allocation.claim())
        .ok_or_else(|| "OWNER_CONTINUOUS_HISTORY_SIGNED_OPERATION_REQUIRED".into())
}

fn step_result(
    operation_id: String,
    native: Result<Hash>,
    settled: crate::operator_continuous_cpu::DurableSettlement,
) -> OwnedHistoryStepResult {
    OwnedHistoryStepResult {
        operation_id,
        native_id: native.as_ref().ok().copied(),
        native_error: native.err().map(|error| error.to_string()),
        cpu: settled.actual,
        accounting_record_persisted: settled.accounting_record_persisted,
        accounting_fault_persistence_failed: settled.accounting_fault_persistence_failed,
    }
}

fn known_success(step: &OwnedHistoryStepResult, expected: Hash) -> bool {
    step.native_id == Some(expected)
        && step.native_error.is_none()
        && step.accounting_record_persisted
        && !step.cpu.accounting_unavailable
        && !step.cpu.live_refused
}

impl Node {
    /// Crate-private native adapter. External callers use the concrete-source
    /// Host-gated ingress entry. Select grants BEFORE JSON/hex/proof decoding;
    /// malformed authorized input spends its claim and actual CPU exactly once.
    pub(crate) fn receive_owned_history_operation(
        &mut self,
        request: OwnedHistoryRequest<'_>,
        resource: &(dyn Fn(OwnedHistoryProgress) -> Result<()> + Sync),
    ) -> Result<OwnedHistoryResult> {
        ensure(
            !request.raw_page.is_empty() && request.raw_page.len() <= MAX_OWNED_PAGE_BYTES,
            "PAGE_LIMIT",
        )?;
        let owner = self
            .continuous_owner
            .as_ref()
            .ok_or("OWNER_CONTINUOUS_MODE_REQUIRED")?
            .clone();
        owner.ready()?;
        ensure(owner.slot()?.is_none(), "OWNER_CONTINUOUS_SCOPE_BUSY")?;
        let (parent, generation) = self.active()?;
        ensure(
            request.after == parent
                && request.tip != parent
                && owner.view.body.actual_parent == hex::encode(parent)
                && owner.view.body.actual_generation == generation,
            "OWNER_CONTINUOUS_HISTORY_EXACT_ACTIVE_SUCCESSOR_REQUIRED",
        )?;
        let validation = selected(
            &owner,
            request.validation_operation_id,
            "receiver-validation",
        )?;
        let activation = selected(&owner, request.activation_operation_id, "receiver-activate")?;
        ensure(
            validation.payload == activation.payload
                && validation.parent == activation.parent
                && validation.generation == activation.generation
                && validation.native_task == activation.native_task
                && validation.instance_class == activation.instance_class
                && validation.task_binding == activation.task_binding,
            "OWNER_CONTINUOUS_HISTORY_EXACT_CLAIM_PAIR",
        )?;
        let payload = validation.payload.clone();
        // No decoded request field can become a permit. Both allocations were
        // authenticated by the original protected Inputs/TaskView constructor.
        let permit = self.continuous_pair(&owner, "receiver-validation", &payload)?;
        ensure(
            permit.allocation.claim().operation == request.validation_operation_id,
            "OWNER_CONTINUOUS_HISTORY_OPERATION_ID",
        )?;
        let operation = owner.operation(&permit, None)?;
        let checkpoint = operation.checkpoint_handle().map_err(continuous_error)?;
        let fence = |point| {
            resource(point)?;
            permit.progress().map_err(continuous_error)?;
            checkpoint.checkpoint()
        };
        let native = (|| -> Result<Hash> {
            fence(OwnedHistoryProgress::Decode)?;
            let page: Page = serde_json::from_slice(request.raw_page)?;
            fence(OwnedHistoryProgress::Decode)?;
            ensure(
                page.schema == "pon-native-history-v1"
                    && page.network == hex::encode(self.settings().network())
                    && page.parameters == hex::encode(self.settings().parameters())
                    && page.genesis == hex::encode(self.settings().genesis()),
                "PAGE_CONTEXT",
            )?;
            ensure(
                page.tip == hex::encode(request.tip)
                    && page.after == hex::encode(request.after)
                    && page.packets.len() == 1
                    && page.complete
                    && page.next == page.tip,
                "OWNER_CONTINUOUS_HISTORY_SINGLE_SUCCESSOR_PAGE",
            )?;
            let encoded = &page.packets[0];
            ensure(encoded.len() <= MAX_OWNED_PAGE_BYTES - 1024, "PAGE_LIMIT")?;
            let raw = hex::decode(encoded).map_err(|_| "PACKET_HEX")?;
            fence(OwnedHistoryProgress::Decode)?;
            ensure(
                crate::operator_task_policy::digest_bytes(&raw) == payload,
                "OWNER_CONTINUOUS_HISTORY_PACKET_DIGEST",
            )?;
            let packet = Packet::decode(&raw)?;
            fence(OwnedHistoryProgress::Decode)?;
            ensure(
                packet.encode()? == raw,
                "OWNER_CONTINUOUS_HISTORY_CANONICAL_PACKET",
            )?;
            ensure(
                packet.header.parent == parent && packet.id()? == request.tip,
                "PAGE_PARENT",
            )?;
            // A correctly signed packet does not replace the upper delegation's
            // signed nonce window. Reuse the original public receiver checks
            // before any State restoration, full Work or M06 execution.
            permit
                .allocation
                .check_exact_receiver_packet(&packet, parent, generation)
                .map_err(continuous_error)?;
            owner
                .journal
                .lock()
                .map_err(|_| "OWNER_CONTINUOUS_JOURNAL_UNKNOWN")?
                .check_nonce_window(packet.header.nonce, packet.header.nonce)
                .map_err(continuous_error)?;
            let _scope = owner.enter(
                permit.clone(),
                None,
                checkpoint.clone(),
                Binding::packet(&packet)?,
            )?;
            fence(OwnedHistoryProgress::Context)?;
            self.continuous_actual_packet_binding_with_progress(&permit, &packet, &mut || {
                fence(OwnedHistoryProgress::Context)
            })?;
            if let Some(id) = self.check_admission_context_with_progress(
                &packet,
                request.observed_now,
                &mut || fence(OwnedHistoryProgress::Context),
            )? {
                return Ok(id);
            }
            let checked = WorkCheckedPacket::verify_with_progress(packet, &mut |point| {
                permit.progress().map_err(continuous_error)?;
                checkpoint.checkpoint()?;
                if crate::ingress::history_kernel_work_checkpoint(point) {
                    fence(OwnedHistoryProgress::Work(point))?;
                }
                Ok(())
            })?;
            let execution_progress = |point| fence(OwnedHistoryProgress::Execution(point));
            let control = ExecutionControl::new(
                &execution_progress,
                operation.worker_accounting().map_err(continuous_error)?,
            );
            self.admit_work_checked_with_control(checked, request.observed_now, &control)
        })();
        // Native execution joins all original scoped children, including on
        // cancellation/panic, before this sole original CPU interval settles.
        let settled = operation.finish().map_err(continuous_error)?;
        let validation = step_result(request.validation_operation_id.to_owned(), native, settled);
        let mut result = OwnedHistoryResult {
            schema: "restricted-owner-continuous-single-successor-history-v1",
            validation,
            activation: None,
            activation_start_error: None,
            terminal_boundary_error: None,
            completed: false,
            durable_result_preserved: true,
            public_network_ready: false,
        };
        if !known_success(&result.validation, request.tip) {
            return Ok(result);
        }
        // Activation has its own independently signed allocation. Failure to
        // start it must retain the actual preceding validation result.
        match self.activate_owned_history_successor(&owner, &payload, request, resource) {
            Ok(activation) => {
                result.completed = known_success(&activation, request.tip);
                result.activation = Some(activation);
            }
            Err(error) => result.activation_start_error = Some(error.to_string()),
        }
        Ok(result)
    }

    fn activate_owned_history_successor(
        &mut self,
        owner: &ContinuousOwner,
        payload: &str,
        request: OwnedHistoryRequest<'_>,
        resource: &(dyn Fn(OwnedHistoryProgress) -> Result<()> + Sync),
    ) -> Result<OwnedHistoryStepResult> {
        let permit = self.continuous_pair(owner, "receiver-activate", payload)?;
        ensure(
            permit.allocation.claim().operation == request.activation_operation_id,
            "OWNER_CONTINUOUS_HISTORY_OPERATION_ID",
        )?;
        let operation = owner.operation(&permit, None)?;
        let checkpoint = operation.checkpoint_handle().map_err(continuous_error)?;
        let native = (|| -> Result<Hash> {
            let _scope = owner.enter(permit.clone(), None, checkpoint.clone(), Binding::none())?;
            self.activate_observed_with_progress(request.tip, request.observed_now, &mut || {
                resource(OwnedHistoryProgress::Activation)?;
                permit.progress().map_err(continuous_error)?;
                checkpoint.checkpoint()
            })
        })();
        let settled = operation.finish().map_err(continuous_error)?;
        Ok(step_result(
            request.activation_operation_id.to_owned(),
            native,
            settled,
        ))
    }
}

#[cfg(test)]
#[path = "history_import_tests.rs"]
pub(in crate::store) mod tests;
