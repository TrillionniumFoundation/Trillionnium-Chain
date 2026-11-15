//! One explicit bounded PQ recovery campaign. Every outbound operation uses
//! actual pinned native/PQHistory clients and the same durable reservation owner.
use super::{journal::Journal, PinnedPqRecoveryClient, PQ_RECOVERY_HISTORY_TRANSPORT};
use crate::public_submit::{ns, SubmitRecoveryAttempt, SubmitRecoveryPlan};
use crate::{digest, ensure, ingress, Error, ErrorCode, Node, Packet, Result};
use serde::Serialize;
use serde_json::Value;
use std::path::Path;
use std::time::{Duration, Instant};
use trnm_protocol::pon_wire::Hash;

mod delivery;
mod observations;

/// Initial sequence is an explicit trusted input, never adopted from an outbox.
/// Create's plan must be captured before packet parsing and ordinary Node::open.
/// Resume retains the original boot, time namespace, epoch and all spent limits.
pub enum PqRecoveryCampaign<'a> {
    Create {
        directory: &'a Path,
        initial_sequence: u64,
        plan: SubmitRecoveryPlan,
    },
    Resume {
        directory: &'a Path,
        initial_sequence: u64,
    },
}
#[derive(Debug, Serialize)]
pub struct NativeRecoveryAttempt {
    pub reserved_call: u8,
    pub purpose: &'static str,
    pub packet: String,
    pub sequence: u64,
    pub original_expires_at: u64,
    pub operation: String,
    pub request_wire_sha256: String,
    pub request_wire_bytes: usize,
    pub response_wire_sha256: Option<String>,
    pub authenticated_response: Option<Value>,
    pub elapsed_since_epoch_ns: u64,
    pub remaining_before_call_ns: u64,
    pub receipt_persisted: bool,
    pub client_error: Option<String>,
    pub journal_error: Option<String>,
    pub retryable_transport_eof: bool,
}
/// History records contain only real PublicClientMetrics. A native dispatch
/// has its own exact request/receipt observations and does not fabricate them.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", content = "observation", rename_all = "snake_case")]
pub enum PqRecoveryAttempt {
    Native(NativeRecoveryAttempt),
    History(SubmitRecoveryAttempt),
}
#[derive(Debug, Serialize)]
pub struct PendingRecovery {
    pub sequence: u64,
    pub original_expires_at: u64,
    pub operation: String,
    pub packet: Option<String>,
    pub reserved_attempts: u8,
}
#[derive(Debug, Serialize)]
pub struct PqSubmitRecoveryOutcome {
    pub schema: &'static str,
    pub ok: bool,
    pub packet: String,
    pub context: String,
    pub network: String,
    pub parameters: String,
    pub genesis: String,
    pub native_transport: &'static str,
    pub history_transport: &'static str,
    pub membership_observed: bool,
    pub may_advance_dependency: bool,
    pub submission_outcome_uncertain: bool,
    pub acknowledged_packets: Vec<String>,
    pub restored_parent_memberships: Vec<String>,
    pub observed_head: Option<String>,
    pub observed_generation: Option<u64>,
    pub pending: Option<PendingRecovery>,
    pub reserved_calls: Option<u8>,
    pub planned_parent_count: Option<usize>,
    pub attempts: Vec<PqRecoveryAttempt>,
    pub failure: Option<String>,
    pub journal_observation_error: Option<String>,
    pub total_elapsed_ns: u64,
    pub original_budget_ns: u64,
    pub submit_attempt_limit_per_packet: u8,
    pub rpc_reservation_limit: u8,
    pub parent_packet_limit: u8,
    pub retry_pause_ns: u64,
    pub native_stages_nonpreemptive: bool,
    pub whole_directory_rollback_protection: bool,
    pub production_activation: bool,
}
struct Session<'a, 'b> {
    node: &'a Node,
    client: &'a PinnedPqRecoveryClient<'b>,
    journal: &'a mut Journal,
    plan: SubmitRecoveryPlan,
    outcome: &'a mut PqSubmitRecoveryOutcome,
}

/// Restore only the producer's actually retained and admitted byte-identical
/// packet/ancestors. No request is re-signed after an uncertain dispatch, no
/// History observation consumes a native sequence, and no limit resets on cold
/// open. A valid signed business refusal is a consumed, known result.
pub fn submit_with_pq_parent_recovery(
    local_producer: &Node,
    client: &PinnedPqRecoveryClient<'_>,
    packet: &Packet,
    campaign: PqRecoveryCampaign<'_>,
) -> Result<PqSubmitRecoveryOutcome> {
    if let PqRecoveryCampaign::Create { plan, .. } = &campaign {
        plan.validate()?;
        plan.alive()?;
    }
    client.validate_for_node(local_producer)?;
    let id = packet.id()?;
    let mut journal = match campaign {
        PqRecoveryCampaign::Create {
            directory,
            initial_sequence,
            plan,
        } => Journal::initialize(directory, client, id, initial_sequence, &plan)?,
        PqRecoveryCampaign::Resume {
            directory,
            initial_sequence,
        } => Journal::open(directory, client, id, initial_sequence)?,
    };
    let plan = journal.recovery_plan()?;
    let settings = local_producer.settings();
    let mut outcome = PqSubmitRecoveryOutcome {
        schema: "native-pq-local-parent-recovery-v1",
        ok: false,
        packet: hex::encode(id),
        context: hex::encode(client.context_id()),
        network: hex::encode(settings.network()),
        parameters: hex::encode(settings.parameters()),
        genesis: hex::encode(settings.genesis()),
        native_transport: client.transport.mode(),
        history_transport: PQ_RECOVERY_HISTORY_TRANSPORT,
        membership_observed: false,
        may_advance_dependency: false,
        submission_outcome_uncertain: false,
        acknowledged_packets: Vec::new(),
        restored_parent_memberships: Vec::new(),
        observed_head: None,
        observed_generation: None,
        pending: None,
        reserved_calls: None,
        planned_parent_count: None,
        attempts: Vec::new(),
        failure: None,
        journal_observation_error: None,
        total_elapsed_ns: 0,
        original_budget_ns: ns(plan.deadline.saturating_duration_since(plan.started)),
        submit_attempt_limit_per_packet: plan.max_submit_attempts,
        rpc_reservation_limit: plan.max_calls,
        parent_packet_limit: plan.max_parent_packets,
        retry_pause_ns: ns(plan.retry_pause),
        native_stages_nonpreemptive: true,
        whole_directory_rollback_protection: false,
        production_activation: false,
    };
    let result = (|| -> Result<()> {
        let mut session = Session {
            node: local_producer,
            client,
            journal: &mut journal,
            plan,
            outcome: &mut outcome,
        };
        let retained = session.local_packet(id)?;
        ensure(
            retained.encode_for_settings(settings)? == packet.encode_for_settings(settings)?,
            "SUBMIT_RECOVERY_LOCAL_BYTES",
        )?;
        if packet.header.parent != settings.genesis() {
            session.local_packet(packet.header.parent)?;
        }
        if !session.resume_pending(packet)? && !session.membership(packet)? {
            session.deliver(packet, true)?;
        }
        session.ready()?;
        ensure(
            session.journal.pending_request()?.is_none(),
            "PQ_RECOVERY_UNCONFIRMED_SEQUENCE",
        )?;
        session.journal.recheck()?;
        session.ready()
    })();
    match result {
        Ok(()) => {
            outcome.ok = true;
            outcome.membership_observed = true;
            outcome.may_advance_dependency = true;
        }
        Err(error) => outcome.failure = Some(error.to_string()),
    }
    // Unavailable observations stay explicitly unknown. A fenced owner never
    // turns failed status/cursor reads into zero spent calls or no pending work.
    let observation = (|| -> Result<()> {
        journal.recheck()?;
        let status = journal.status()?;
        let pending = journal.pending_request()?;
        outcome.reserved_calls = Some(status.used_calls);
        outcome.planned_parent_count = Some(status.planned_parent_count);
        if let Some(pending) = pending {
            outcome.submission_outcome_uncertain = pending.attempts > 0;
            outcome.pending = Some(PendingRecovery {
                sequence: pending.sequence,
                original_expires_at: pending.expires_at,
                operation: hex::encode(pending.operation),
                packet: pending.packet_id.map(hex::encode),
                reserved_attempts: pending.attempts,
            });
        }
        Ok(())
    })();
    if let Err(error) = observation {
        // An unreadable journal cannot establish that no prior effect remains
        // unconfirmed, including before cold pending metadata was inspected.
        outcome.submission_outcome_uncertain = true;
        outcome.journal_observation_error = Some(error.to_string());
        outcome.ok = false;
        outcome.membership_observed = false;
        outcome.may_advance_dependency = false;
        if outcome.failure.is_none() {
            outcome.failure = Some(error.to_string());
        }
    }
    outcome.total_elapsed_ns = ns(plan.started.elapsed());
    Ok(outcome)
}
