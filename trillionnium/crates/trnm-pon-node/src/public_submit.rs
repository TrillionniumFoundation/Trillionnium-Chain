//! Bounded honest-client recovery. No new admission or confirmation authority.
use crate::{digest, ensure, ingress, Error, ErrorCode, Node, Packet, Result};
use ingress::public_v3::{
    call_public_protected_v3_with_deadline, PublicClientMetrics, PublicClientStage, PublicPolicy,
    PublicReply, Request,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    thread,
    time::Duration,
    time::Instant,
};
use trnm_protocol::pon_wire::{hash, Hash};

pub const MAX_SUBMIT_ATTEMPTS: u8 = 3;
pub const MAX_RECOVERY_CALLS: u8 = 64;
pub const MAX_PARENT_PACKETS: u8 = 16;
pub const MAX_RECOVERY_MILLISECONDS: u64 = 60_000;

/// The epoch includes the caller's packet parsing and normal Node::open when
/// constructed before those stages. Native reads are nonpreemptive: a late
/// return is refused, rather than reported as an on-time completion.
#[derive(Clone, Copy, Debug)]
pub struct SubmitRecoveryPlan {
    pub started: Instant,
    pub deadline: Instant,
    pub max_submit_attempts: u8,
    pub max_calls: u8,
    pub max_parent_packets: u8,
    pub retry_pause: Duration,
}
impl SubmitRecoveryPlan {
    pub fn new(budget: Duration) -> Result<Self> {
        let started = Instant::now();
        let plan = Self {
            started,
            deadline: started
                .checked_add(budget)
                .ok_or("SUBMIT_RECOVERY_LIMITS")?,
            max_submit_attempts: 3,
            max_calls: 16,
            max_parent_packets: 1,
            retry_pause: Duration::from_millis(100),
        };
        plan.validate()?;
        Ok(plan)
    }
    pub fn validate(&self) -> Result<()> {
        let budget = self
            .deadline
            .checked_duration_since(self.started)
            .ok_or("SUBMIT_RECOVERY_LIMITS")?;
        ensure(
            self.started <= Instant::now()
                && budget >= Duration::from_millis(1)
                && budget <= Duration::from_millis(MAX_RECOVERY_MILLISECONDS)
                && (1..=MAX_SUBMIT_ATTEMPTS).contains(&self.max_submit_attempts)
                && (1..=MAX_RECOVERY_CALLS).contains(&self.max_calls)
                && self.max_parent_packets <= MAX_PARENT_PACKETS
                && self.retry_pause <= Duration::from_secs(1),
            "SUBMIT_RECOVERY_LIMITS",
        )
    }
    fn alive(&self) -> Result<()> {
        ensure(Instant::now() < self.deadline, "SUBMIT_RECOVERY_DEADLINE")
    }
}

pub struct PinnedPublicClient<'a> {
    pub address: SocketAddr,
    pub server_public: &'a str,
    pub identity: &'a ingress::DevelopmentIdentity,
    pub policy: PublicPolicy,
}

/// Actual per-call observations, including failures and parent restoration.
/// Request bodies/identity/peer addresses are excluded. The returned reply and
/// metrics are client-local observations, not the original signed frame bytes.
#[derive(Debug, Serialize)]
pub struct SubmitRecoveryAttempt {
    pub ordinal: u64,
    pub operation: &'static str,
    pub purpose: &'static str,
    pub packet: Option<String>,
    pub request_body_digest: String,
    pub request_body_bytes: usize,
    pub elapsed_since_epoch_ns: u64,
    pub remaining_before_call_ns: u64,
    pub metrics: PublicClientMetrics,
    pub authenticated_reply: Option<Value>,
    pub client_error: Option<String>,
    pub retryable_transport_eof: bool,
}

#[derive(Debug, Serialize)]
pub struct SubmitRecoveryOutcome {
    pub schema: &'static str,
    pub ok: bool,
    pub packet: Option<String>,
    pub network: String,
    pub parameters: String,
    pub genesis: String,
    pub membership_observed: bool,
    pub may_advance_dependency: bool,
    pub formal_confirmation_observed: Option<bool>,
    pub acknowledged_packets: Vec<String>,
    pub restored_parent_memberships: Vec<String>,
    pub submission_outcome_uncertain: bool,
    pub observed_head: Option<String>,
    pub observed_generation: Option<u64>,
    pub attempts: Vec<SubmitRecoveryAttempt>,
    pub failure: Option<String>,
    pub total_elapsed_ns: u64,
    pub budget_ns: u64,
    pub submit_attempt_limit_per_packet: u8,
    pub rpc_attempt_limit: u8,
    pub parent_packet_limit: u8,
    /// Configured short retry pause and minimum CPU-budget retry pause; not
    /// the actual duration of every wait. Call timestamps retain elapsed facts.
    pub retry_pause_ns: u64,
    pub native_stages_nonpreemptive: bool,
    pub remote_persistence_proved: bool,
    pub source_attestation: bool,
    pub identity_authority: bool,
    pub public_network_ready: bool,
    pub resource_fairness_qualified: bool,
    pub model_quality_qualified: bool,
    pub hardness_qualified: bool,
    pub production_activation: bool,
}

fn ns(duration: Duration) -> u64 {
    duration.as_nanos().min(u64::MAX as u128) as u64
}

fn retryable_eof(error: &Error, metrics: &PublicClientMetrics) -> bool {
    error.is(ErrorCode::FrameEof)
        && error.kind() == crate::ErrorKind::Transport
        && matches!(
            metrics.failed_stage,
            Some(PublicClientStage::Challenge | PublicClientStage::SolutionBodyResponse)
        )
}

fn uncertain_failed_stage(metrics: &PublicClientMetrics) -> bool {
    matches!(
        metrics.failed_stage,
        Some(
            PublicClientStage::Challenge
                | PublicClientStage::SolutionSearch
                | PublicClientStage::SolutionBodyResponse
        )
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteHead {
    network: String,
    parameters: String,
    genesis: String,
    tip: String,
    height: u64,
    chainwork_hex: String,
    state_root: String,
    generation: u64,
    context_matches: bool,
    commitment_scope: String,
    production_activation: bool,
}

struct Session<'a, 'b> {
    node: &'a Node,
    client: PinnedPublicClient<'a>,
    plan: SubmitRecoveryPlan,
    outcome: &'b mut SubmitRecoveryOutcome,
    submit_counts: BTreeMap<Hash, u8>,
    planned_parents: BTreeSet<Hash>,
}
impl Session<'_, '_> {
    fn pause(&self) -> Result<()> {
        self.pause_for(self.plan.retry_pause)
    }

    fn pause_for(&self, pause: Duration) -> Result<()> {
        self.plan.alive()?;
        let remaining = self.plan.deadline.saturating_duration_since(Instant::now());
        ensure(pause < remaining, "SUBMIT_RECOVERY_DEADLINE")?;
        thread::sleep(pause);
        self.plan.alive()
    }

    fn pause_after_cpu_budget(&self, id: Hash) -> Result<()> {
        self.plan.alive()?;
        let used = self.submit_counts.get(&id).copied().unwrap_or_default();
        let remaining_submits = self.plan.max_submit_attempts.saturating_sub(used);
        ensure(remaining_submits > 0, "SUBMIT_RECOVERY_ATTEMPT_LIMIT")?;
        ensure(
            self.outcome.attempts.len() < self.plan.max_calls as usize,
            "SUBMIT_RECOVERY_CALL_LIMIT",
        )?;
        // This is the original absolute epoch after a real absent-membership
        // observation. Keep time for each remaining Submit and its membership
        // reads instead of spending every finite attempt in one short burst.
        let remaining = self.plan.deadline.saturating_duration_since(Instant::now());
        let pause = self
            .plan
            .retry_pause
            .max(remaining / (u32::from(remaining_submits) + 1));
        self.pause_for(pause)
    }

    fn call(
        &mut self,
        request: &Request,
        purpose: &'static str,
        packet: Option<Hash>,
    ) -> Result<PublicReply> {
        self.plan.alive()?;
        ensure(
            self.outcome.attempts.len() < self.plan.max_calls as usize,
            "SUBMIT_RECOVERY_CALL_LIMIT",
        )?;
        let operation = match request {
            Request::Submit { .. } => "submit",
            Request::Head => "head",
            Request::History { .. } => "history",
            _ => return Err("SUBMIT_RECOVERY_OPERATION".into()),
        };
        let raw = serde_json::to_vec(request)?;
        let remaining = self.plan.deadline.saturating_duration_since(Instant::now());
        let (reply, metrics) = call_public_protected_v3_with_deadline(
            self.client.address,
            request,
            self.node.settings(),
            self.client.server_public,
            self.client.identity,
            self.client.policy,
            Some(self.plan.deadline),
        );
        let record = SubmitRecoveryAttempt {
            ordinal: self.outcome.attempts.len() as u64 + 1,
            operation,
            purpose,
            packet: packet.map(hex::encode),
            request_body_digest: hex::encode(hash(b"public-request-body-v3", &[&raw])),
            request_body_bytes: raw.len(),
            elapsed_since_epoch_ns: ns(self.plan.started.elapsed()),
            remaining_before_call_ns: ns(remaining),
            authenticated_reply: reply.as_ref().ok().map(serde_json::to_value).transpose()?,
            client_error: reply.as_ref().err().map(ToString::to_string),
            retryable_transport_eof: reply
                .as_ref()
                .err()
                .is_some_and(|error| retryable_eof(error, &metrics)),
            metrics,
        };
        if packet.is_some() && reply.is_err() && uncertain_failed_stage(&record.metrics) {
            // A permanent client-side refusal must not claim that the remote
            // Node had no effect merely because its response was not accepted.
            self.outcome.submission_outcome_uncertain = true;
        }
        if let (Some(id), Ok(reply)) = (packet, &reply) {
            if valid_ack(reply, id) && !self.outcome.acknowledged_packets.contains(&hex::encode(id))
            {
                // Preserve a real ACK even if the local whole epoch expires
                // immediately after receiving it. It grants no membership.
                self.outcome.acknowledged_packets.push(hex::encode(id));
            }
        }
        self.outcome.attempts.push(record);
        self.plan.alive()?;
        reply
    }

    fn read(&mut self, request: &Request, purpose: &'static str) -> Result<PublicReply> {
        for attempt in 0..self.plan.max_submit_attempts {
            let result = self.call(request, purpose, None);
            let record = self.outcome.attempts.last();
            match result {
                Ok(reply) if reply.ok => return Ok(reply),
                Ok(reply) => return Err(remote_error(&reply)?),
                Err(error)
                    if record.is_some_and(|r| retryable_eof(&error, &r.metrics))
                        && attempt + 1 < self.plan.max_submit_attempts =>
                {
                    self.pause()?;
                }
                Err(error) => return Err(error),
            }
        }
        Err("SUBMIT_RECOVERY_READ_LIMIT".into())
    }

    fn local_packet(&self, id: Hash) -> Result<Packet> {
        self.plan.alive()?;
        let packet = self.node.packet(id)?;
        ensure(
            self.node
                .check_admission_context(&packet, ingress::now()?)?
                == Some(id),
            "SUBMIT_RECOVERY_LOCAL_ADMISSION",
        )?;
        // Actual full State reconstruction/root validation remains with Node.
        let state = self.node.state_at(id)?;
        ensure(
            trnm_mvcc_fee::pon_executor::root(&state)? == packet.header.state,
            "SUBMIT_RECOVERY_LOCAL_ROOT",
        )?;
        self.plan.alive()?;
        Ok(packet)
    }

    fn head(&mut self) -> Result<RemoteHead> {
        let reply = self.read(&Request::Head, "active-membership-head")?;
        let head: RemoteHead = serde_json::from_value(reply.value)?;
        let settings = self.node.settings();
        ensure(
            head.network == hex::encode(settings.network())
                && head.parameters == hex::encode(settings.parameters())
                && head.genesis == hex::encode(settings.genesis())
                && head.context_matches
                && !head.production_activation
                && head.commitment_scope == "admitted-active-header; no fresh key/value audit",
            "SUBMIT_RECOVERY_HEAD_CONTEXT",
        )?;
        let tip = digest(&head.tip)?;
        digest(&head.state_root)?;
        // Chainwork is transport metadata, never used as a confirmation rule.
        ensure(
            head.chainwork_hex.len() == 128
                && head
                    .chainwork_hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "SUBMIT_RECOVERY_HEAD_WORK_ENCODING",
        )?;
        let expected_height = if tip == settings.genesis() {
            0
        } else {
            self.local_packet(tip)?.header.height
        };
        self.node.check_observed_history(tip, ingress::now()?)?;
        let state = self.node.state_at(tip)?;
        ensure(
            head.height == expected_height
                && head.state_root == hex::encode(trnm_mvcc_fee::pon_executor::root(&state)?),
            "SUBMIT_RECOVERY_HEAD_ROOT",
        )?;
        self.plan.alive()?;
        Ok(head)
    }

    fn membership(&mut self, packet: &Packet) -> Result<bool> {
        let id = packet.id()?;
        let head = self.head()?;
        // A known older active head establishes no membership for this packet.
        if head.height < packet.header.height {
            return Ok(false);
        }
        let tip = digest(&head.tip)?;
        let deadline = self.plan.deadline;
        let expected =
            self.node
                .public_history_packet(tip, packet.header.parent, 1024, &mut |_| {
                    ensure(Instant::now() < deadline, "SUBMIT_RECOVERY_DEADLINE")
                })?;
        ensure(
            expected.len() == 1 && expected[0].encode()? == packet.encode()?,
            "SUBMIT_RECOVERY_STALE_BRANCH",
        )?;
        let reply = self.read(
            &Request::History {
                tip: head.tip.clone(),
                after: hex::encode(packet.header.parent),
            },
            "active-membership-history",
        )?;
        let page: ingress::Page = serde_json::from_value(reply.value)?;
        ensure(
            page.schema == "pon-native-history-v1"
                && page.network == self.outcome.network
                && page.parameters == self.outcome.parameters
                && page.genesis == self.outcome.genesis
                && page.tip == head.tip
                && page.after == hex::encode(packet.header.parent)
                && page.next == hex::encode(id)
                && page.complete == (id == tip)
                && page.packets.len() == 1,
            "SUBMIT_RECOVERY_HISTORY_CONTEXT",
        )?;
        ensure(
            page.packets[0] == hex::encode(packet.encode()?)
                && page.packets[0] == hex::encode(expected[0].encode()?),
            "SUBMIT_RECOVERY_HISTORY_BYTES",
        )?;
        let latest = self.head()?;
        ensure(
            latest.tip == head.tip
                && latest.generation == head.generation
                && latest.state_root == head.state_root,
            "SUBMIT_RECOVERY_STALE_HEAD",
        )?;
        self.outcome.observed_head = Some(head.tip);
        self.outcome.observed_generation = Some(head.generation);
        self.plan.alive()?;
        Ok(true)
    }

    fn restore_parent(&mut self, parent: Hash) -> Result<()> {
        let head = self.head()?;
        let anchor = digest(&head.tip)?;
        let mut current = parent;
        let mut missing = Vec::new();
        while current != anchor {
            self.plan.alive()?;
            ensure(
                self.planned_parents.contains(&current)
                    || self.planned_parents.len() < self.plan.max_parent_packets as usize,
                "SUBMIT_RECOVERY_PARENT_LIMIT",
            )?;
            ensure(
                current != self.node.settings().genesis(),
                "SUBMIT_RECOVERY_PARENT_BRANCH",
            )?;
            let packet = self.local_packet(current)?;
            self.planned_parents.insert(current);
            current = packet.header.parent;
            missing.push(packet);
        }
        ensure(!missing.is_empty(), "SUBMIT_RECOVERY_PARENT_CONTRADICTION")?;
        for packet in missing.iter().rev() {
            // The planned ordered path must not start a recursive repair after a
            // concurrent branch change. Refuse and preserve completed facts.
            self.deliver(packet, false)?;
            self.outcome
                .restored_parent_memberships
                .push(hex::encode(packet.id()?));
        }
        Ok(())
    }

    fn deliver(&mut self, packet: &Packet, allow_parent_repair: bool) -> Result<()> {
        let id = packet.id()?;
        loop {
            self.plan.alive()?;
            let attempts = self.submit_counts.entry(id).or_default();
            ensure(
                *attempts < self.plan.max_submit_attempts,
                "SUBMIT_RECOVERY_ATTEMPT_LIMIT",
            )?;
            *attempts += 1;
            let result = self.call(
                &Request::Submit {
                    packet: hex::encode(packet.encode()?),
                },
                if allow_parent_repair {
                    "pending-packet"
                } else {
                    "parent-restoration"
                },
                Some(id),
            );
            match result {
                Ok(reply) if reply.ok => {
                    ensure(valid_ack(&reply, id), "SUBMIT_RECOVERY_ACK_CONTEXT")?;
                    ensure(
                        self.membership(packet)?,
                        "SUBMIT_RECOVERY_MEMBERSHIP_ABSENT",
                    )?;
                    return Ok(());
                }
                Ok(reply) => {
                    let error = remote_error(&reply)?;
                    if error.is(ErrorCode::UnknownParent) && allow_parent_repair {
                        self.restore_parent(packet.header.parent)?;
                    } else if error.is(ErrorCode::PublicMutationCpuBudget) {
                        // This signed Submit refusal remains in attempts. An
                        // earlier admission may already have placed the exact
                        // retained packet on the current remote active branch;
                        // full membership can resolve that fact without an ACK.
                        if self.membership(packet)? {
                            return Ok(());
                        }
                        // Absent membership is not admission. A fresh attempt
                        // consumes the original per-packet/call/epoch limits.
                        self.pause_after_cpu_budget(id)?;
                    } else {
                        return Err(error);
                    }
                }
                Err(error) => {
                    let retryable = self
                        .outcome
                        .attempts
                        .last()
                        .is_some_and(|r| retryable_eof(&error, &r.metrics));
                    if !retryable {
                        return Err(error);
                    }
                    self.outcome.submission_outcome_uncertain = true;
                    // A response lost after durable admission can be resolved by
                    // real membership without another mutating call.
                    if self.membership(packet)? {
                        return Ok(());
                    }
                    self.pause()?;
                }
            }
        }
    }
}

fn remote_error(reply: &PublicReply) -> Result<Error> {
    reply
        .value
        .get("error")
        .and_then(Value::as_str)
        .filter(|error| !error.is_empty() && error.len() <= 256)
        .map(Error::remote)
        .ok_or_else(|| "SUBMIT_RECOVERY_REMOTE_ERROR".into())
}

fn valid_ack(reply: &PublicReply, id: Hash) -> bool {
    reply.ok
        && reply.value["block"] == hex::encode(id)
        && reply.value["active"]
            .as_str()
            .is_some_and(|active| digest(active).is_ok())
        && reply.value["generation"].as_u64().is_some()
}

/// Requires a retained, byte-identical packet admitted by this actual local
/// Node. It never admits a caller claim, synthesizes a parent, signs/rebases a
/// transaction, or writes a guest/session/confirmation record. Node::open and
/// its existing local recovery are the caller's explicit normal operation.
pub fn submit_with_verified_parent_recovery(
    local_producer: &Node,
    client: PinnedPublicClient<'_>,
    packet: &Packet,
    plan: SubmitRecoveryPlan,
) -> SubmitRecoveryOutcome {
    let settings = local_producer.settings();
    let mut outcome = SubmitRecoveryOutcome {
        schema: "public-v3-local-submit-recovery-v1",
        ok: false,
        packet: None,
        network: hex::encode(settings.network()),
        parameters: hex::encode(settings.parameters()),
        genesis: hex::encode(settings.genesis()),
        membership_observed: false,
        may_advance_dependency: false,
        formal_confirmation_observed: None,
        acknowledged_packets: Vec::new(),
        restored_parent_memberships: Vec::new(),
        submission_outcome_uncertain: false,
        observed_head: None,
        observed_generation: None,
        attempts: Vec::new(),
        failure: None,
        total_elapsed_ns: 0,
        budget_ns: ns(plan.deadline.saturating_duration_since(plan.started)),
        submit_attempt_limit_per_packet: plan.max_submit_attempts,
        rpc_attempt_limit: plan.max_calls,
        parent_packet_limit: plan.max_parent_packets,
        retry_pause_ns: ns(plan.retry_pause),
        native_stages_nonpreemptive: true,
        remote_persistence_proved: false,
        source_attestation: false,
        identity_authority: false,
        public_network_ready: false,
        resource_fairness_qualified: false,
        model_quality_qualified: false,
        hardness_qualified: false,
        production_activation: false,
    };
    let result = (|| -> Result<()> {
        plan.validate()?;
        plan.alive()?;
        digest(client.server_public)?;
        PublicPolicy::new(
            client.policy.bits,
            Duration::from_millis(client.policy.lifetime_ms),
        )?;
        let id = packet.id()?;
        outcome.packet = Some(hex::encode(id));
        let mut session = Session {
            node: local_producer,
            client,
            plan,
            outcome: &mut outcome,
            submit_counts: BTreeMap::new(),
            planned_parents: BTreeSet::new(),
        };
        ensure(
            session.local_packet(id)?.encode()? == packet.encode()?,
            "SUBMIT_RECOVERY_LOCAL_BYTES",
        )?;
        if packet.header.parent != settings.genesis() {
            session.local_packet(packet.header.parent)?;
        }
        session.plan.alive()?;
        session.deliver(packet, true)?;
        session.plan.alive()
    })();
    match result {
        Ok(()) => {
            outcome.ok = true;
            outcome.membership_observed = true;
            outcome.may_advance_dependency = true;
        }
        Err(error) => outcome.failure = Some(error.to_string()),
    }
    outcome.total_elapsed_ns = ns(plan.started.elapsed());
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_requires_local_frame_eof_at_one_of_the_existing_response_stages() {
        for (stage, retryable, uncertain) in [
            (None, false, false),
            (Some(PublicClientStage::Construction), false, false),
            (Some(PublicClientStage::Challenge), true, true),
            (Some(PublicClientStage::SolutionSearch), false, true),
            (Some(PublicClientStage::SolutionBodyResponse), true, true),
            (Some(PublicClientStage::Complete), false, false),
            (
                Some(PublicClientStage::Unknown("future-stage")),
                false,
                false,
            ),
            (Some(PublicClientStage::Unknown("challenge")), false, false),
            (
                Some(PublicClientStage::Unknown("solution-search")),
                false,
                false,
            ),
            (
                Some(PublicClientStage::Unknown("solution-body-response")),
                false,
                false,
            ),
        ] {
            let metrics = PublicClientMetrics {
                failed_stage: stage,
                ..PublicClientMetrics::default()
            };
            assert_eq!(
                retryable_eof(&Error::from("FRAME_EOF"), &metrics),
                retryable,
                "{stage:?}",
            );
            assert_eq!(uncertain_failed_stage(&metrics), uncertain, "{stage:?}");
            for error in [
                Error::remote("FRAME_EOF"),
                Error::remote("OWNER_REPLACED"),
                Error::from(std::io::Error::other("FRAME_EOF")),
                Error::from("PUBLIC_EOF"),
                Error::from("FRAME_EOF: peer claim"),
                Error::from("FRAME_DEADLINE"),
                Error::from("PUBLIC_CLIENT_DEADLINE"),
                Error::from("PUBLIC_REQUEST_CANCELLED"),
                Error::from("PEER_POLL_CANCELLED"),
                Error::from("PUBLIC_COOKIE_CONTEXT"),
                Error::from("SUBMIT_RECOVERY_STALE_HEAD"),
                Error::from("SUBMIT_RECOVERY_STALE_BRANCH"),
                Error::from("PUBLIC_MUTATION_CPU_UNAVAILABLE"),
            ] {
                assert!(!retryable_eof(&error, &metrics), "{stage:?}: {error}");
            }
        }
    }
}
