//! Typed owner boundary for failed, timed-out and cancelled executions.
//!
//! This observation domain is separate from successful proof verification.
//! Terminal dispatch state never authorizes NativeTask refund or provider pay.
//! Incomplete process/GPU accounting keeps the entire original resource charge.
use super::*;
use trnm_service_settlement::native_generation_budget_v2::{
    FailureKindV2, FailureV2, NativeGenerationStoreV2,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalReasonV3 {
    Failed,
    TimedOut,
    Cancelled,
}

/// Constructible only by a crate-owned runtime that has reconciled the original
/// execution. A provider response or a caller-supplied terminal flag cannot
/// construct this observation. None is required if any owned descendant,
/// verifier/controller scope, GPU/device authority or measurement is unknown.
pub struct OwnedTerminalExecutionV3 {
    pub(crate) job: ProviderJobV2,
    pub(crate) execution_source_commitment: Hash,
    pub(crate) evidence_digest: Hash,
    pub(crate) reason: TerminalReasonV3,
    pub(crate) resources: Option<GenerationResourcesV2>,
    pub(crate) controller_observed: ClockCheckpointV2,
}

/// No default implementation: an existing proof runtime gains no terminal
/// accounting authority merely by implementing OwnedGenerationRuntimeV2.
/// Implementations must retain and re-read the same job's terminal evidence;
/// this method must never launch, cancel, re-sign, submit or renew a deadline.
pub trait OwnedTerminalGenerationRuntimeV3: OwnedGenerationRuntimeV2 {
    fn reconcile_terminal_execution(
        &mut self,
        statement: &GenerationStatementV2,
        job: &ProviderJobV2,
    ) -> Result<OwnedTerminalExecutionV3>;
}

impl<R: OwnedTerminalGenerationRuntimeV3> NodeGenerationOwnerV2<'_, R> {
    /// Reconcile a previously dispatched terminal failure into the existing
    /// M12 Failure event. Exact replay uses the committed event without another
    /// runtime call. It works after the original deadline and native reorg,
    /// preserving local operation history; it never observes or changes funds.
    pub fn reconcile_terminal_failure(
        &mut self,
        store: &mut NativeGenerationStoreV2,
        id: Hash,
    ) -> Result<FailureV2> {
        let before = store.readback(id)?;
        check(
            before.dispatch_intent
                && before.verified.is_none()
                && before.settlement.is_none()
                && before.historical_payment.is_none(),
            "GENERATION_TERMINAL_FENCE",
        )?;
        if let Some(failure) = before.failure {
            return Ok(failure);
        }
        let job = before.job.as_ref().ok_or(error("GENERATION_JOB_UNKNOWN"))?;
        let observed = self
            .runtime
            .reconcile_terminal_execution(&before.statement, job)?;
        let now = self.runtime.clock_checkpoint()?;
        let deadline = &before.statement.original_deadline;
        check(
            observed.job == *job
                && observed.execution_source_commitment
                    == before.statement.execution_source_commitment
                && observed.evidence_digest != [0; 32],
            "GENERATION_TERMINAL_OWNED_EXECUTION",
        )?;
        check(
            observed.controller_observed.clock_domain == deadline.clock_domain
                && now.clock_domain == deadline.clock_domain
                && observed.controller_observed.now_ns >= deadline.winner_ns
                && now.now_ns >= observed.controller_observed.now_ns,
            "GENERATION_TERMINAL_CLOCK",
        )?;
        match observed.reason {
            TerminalReasonV3::Cancelled => check(
                before.cancellation.is_some(),
                "GENERATION_TERMINAL_OWNER_CANCEL_REQUIRED",
            )?,
            TerminalReasonV3::TimedOut => check(
                observed.controller_observed.now_ns >= deadline.deadline_ns,
                "GENERATION_TERMINAL_ORIGINAL_DEADLINE",
            )?,
            TerminalReasonV3::Failed => {}
        }
        let reason = match observed.reason {
            TerminalReasonV3::Failed => 0_u8,
            TerminalReasonV3::TimedOut => 1,
            TerminalReasonV3::Cancelled => 2,
        };
        // Fresh observation digest; no changed signed domain or stored schema.
        // Every field capable of changing the charge is part of the binding.
        let mut binding = b"TRNM-W1-OWNED-TERMINAL-3".to_vec();
        binding.extend(id);
        binding.extend(job.provider_namespace);
        binding.extend(job.operation);
        binding.extend(job.request_digest);
        binding.extend((job.job_id.len() as u64).to_le_bytes());
        binding.extend(job.job_id.as_bytes());
        binding.extend(observed.execution_source_commitment);
        binding.extend(observed.evidence_digest);
        binding.push(reason);
        binding.extend(observed.controller_observed.clock_domain);
        binding.extend(observed.controller_observed.now_ns.to_le_bytes());
        binding.push(u8::from(observed.resources.is_some()));
        if let Some(used) = &observed.resources {
            binding.extend(used.cpu_ns.to_le_bytes());
            binding.extend(used.gpu_ns.to_le_bytes());
            binding.extend(used.memory_peak_upper_bound_bytes.to_le_bytes());
            binding.extend(used.receipt_bytes.to_le_bytes());
        }
        let kind = match &observed.resources {
            None => FailureKindV2::Unknown,
            Some(used)
                if used.cpu_ns > before.statement.resource_cap.cpu_ns
                    || used.gpu_ns > before.statement.resource_cap.gpu_ns
                    || used.memory_peak_upper_bound_bytes
                        > before.statement.resource_cap.memory_peak_upper_bound_bytes
                    || used.receipt_bytes > before.statement.resource_cap.receipt_bytes =>
            {
                FailureKindV2::ResourceOverrun
            }
            Some(_) => FailureKindV2::Failed,
        };
        let failure = FailureV2 {
            kind,
            evidence_digest: sha256(&binding),
            consumed: observed.resources,
        };
        store.fail(id, failure.clone())?;
        check(
            store.readback(id)?.failure.as_ref() == Some(&failure),
            "GENERATION_TERMINAL_READBACK",
        )?;
        Ok(failure)
    }
}
