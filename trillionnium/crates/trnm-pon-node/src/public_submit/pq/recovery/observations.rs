use super::*;
use crate::ingress::public_v3::{PublicReply, Request as HistoryRequest};
use crate::ingress::Page;
use crate::public_submit::{remote_error, retryable_eof, RemoteHead};
use trnm_protocol::pon_wire::hash;

impl Session<'_, '_> {
    pub(super) fn ready(&mut self) -> Result<()> {
        let current = self.journal.recovery_plan()?;
        // Re-sampling a persisted BOOTTIME deadline cannot lengthen even the
        // conservative Instant mapping already observed in this process.
        self.plan.deadline = self.plan.deadline.min(current.deadline);
        self.plan.alive()?;
        self.client.validate_for_node(self.node)?;
        self.journal.recheck()?;
        self.plan.alive()
    }
    pub(super) fn pause_for(&mut self, pause: Duration) -> Result<()> {
        self.ready()?;
        ensure(
            pause < self.plan.deadline.saturating_duration_since(Instant::now()),
            "SUBMIT_RECOVERY_DEADLINE",
        )?;
        std::thread::sleep(pause);
        self.ready()
    }
    pub(super) fn pause_after_cpu_budget(&mut self, id: Hash) -> Result<()> {
        self.ready()?;
        let status = self.journal.status()?;
        let used = status
            .per_packet_submit_counts
            .get(&id)
            .copied()
            .unwrap_or_default();
        let remaining_submits = self.plan.max_submit_attempts.saturating_sub(used);
        ensure(remaining_submits > 0, "SUBMIT_RECOVERY_ATTEMPT_LIMIT")?;
        ensure(
            status.used_calls < self.plan.max_calls,
            "SUBMIT_RECOVERY_CALL_LIMIT",
        )?;
        let remaining = self.plan.deadline.saturating_duration_since(Instant::now());
        let pause = self
            .plan
            .retry_pause
            .max(remaining / (u32::from(remaining_submits) + 1));
        self.pause_for(pause)
    }
    fn history_call(
        &mut self,
        request: &HistoryRequest,
        purpose: &'static str,
    ) -> Result<PublicReply> {
        self.ready()?;
        let operation = match request {
            HistoryRequest::Head => "head",
            HistoryRequest::History { .. } => "history",
            _ => return Err("PQ_PARENT_RECOVERY_HISTORY_READ_ONLY".into()),
        };
        let raw = serde_json::to_vec(request)?;
        self.journal.reserve_read()?;
        self.ready()?;
        let ordinal = u64::from(self.journal.status()?.used_calls);
        let remaining = self.plan.deadline.saturating_duration_since(Instant::now());
        let (reply, metrics) = self
            .client
            .read_history(self.node, request, self.plan.deadline);
        let observation = SubmitRecoveryAttempt {
            ordinal,
            operation,
            purpose,
            packet: None,
            request_body_digest: hex::encode(hash(b"pq-parent-history-observation-v1", &[&raw])),
            request_body_bytes: raw.len(),
            elapsed_since_epoch_ns: ns(self.plan.started.elapsed()),
            remaining_before_call_ns: ns(remaining),
            authenticated_reply: reply.as_ref().ok().map(serde_json::to_value).transpose()?,
            client_error: reply.as_ref().err().map(ToString::to_string),
            retryable_transport_eof: reply
                .as_ref()
                .err()
                .is_some_and(|e| retryable_eof(e, &metrics)),
            metrics,
        };
        self.outcome
            .attempts
            .push(PqRecoveryAttempt::History(observation));
        let reply = reply?;
        self.ready()?;
        Ok(reply)
    }
    fn read(&mut self, request: &HistoryRequest, purpose: &'static str) -> Result<PublicReply> {
        for attempt in 0..self.plan.max_submit_attempts {
            let before = self.outcome.attempts.len();
            let result = self.history_call(request, purpose);
            match result {
                Ok(reply) if reply.ok => return Ok(reply),
                Ok(reply) => return Err(remote_error(&reply)?),
                Err(error) => {
                    let retry = match self.outcome.attempts.last() {
                        Some(PqRecoveryAttempt::History(row)) => {
                            self.outcome.attempts.len() == before + 1
                                && row.client_error.is_some()
                                && row.retryable_transport_eof
                                && retryable_eof(&error, &row.metrics)
                        }
                        _ => false,
                    };
                    if !retry || attempt + 1 >= self.plan.max_submit_attempts {
                        return Err(error);
                    }
                    self.pause_for(self.plan.retry_pause)?;
                }
            }
        }
        Err("SUBMIT_RECOVERY_READ_LIMIT".into())
    }
    pub(super) fn local_packet(&mut self, id: Hash) -> Result<Packet> {
        self.ready()?;
        let packet = self.node.packet(id)?;
        ensure(
            self.node
                .check_admission_context(&packet, ingress::now()?)?
                == Some(id),
            "SUBMIT_RECOVERY_LOCAL_ADMISSION",
        )?;
        let state = self.node.state_at(id)?;
        ensure(
            self.node.settings().state_root(&state)? == packet.header.state,
            "SUBMIT_RECOVERY_LOCAL_ROOT",
        )?;
        self.ready()?;
        Ok(packet)
    }
    pub(super) fn head(&mut self) -> Result<RemoteHead> {
        let reply = self.read(&HistoryRequest::Head, "active-membership-head")?;
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
                && head.state_root == hex::encode(self.node.settings().state_root(&state)?),
            "SUBMIT_RECOVERY_HEAD_ROOT",
        )?;
        self.ready()?;
        Ok(head)
    }
    pub(super) fn membership(&mut self, packet: &Packet) -> Result<bool> {
        let id = packet.id()?;
        let head = self.head()?;
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
        let encoded = packet.encode_for_settings(self.node.settings())?;
        ensure(
            expected.len() == 1
                && expected[0].encode_for_settings(self.node.settings())? == encoded,
            "SUBMIT_RECOVERY_STALE_BRANCH",
        )?;
        let reply = self.read(
            &HistoryRequest::History {
                tip: head.tip.clone(),
                after: hex::encode(packet.header.parent),
            },
            "active-membership-history",
        )?;
        let page: Page = serde_json::from_value(reply.value)?;
        let schema = if self.node.settings().is_native_pq_application_v6() {
            "pon-native-pq-history-v6"
        } else {
            "pon-native-history-v1"
        };
        ensure(
            page.schema == schema
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
            page.packets[0] == hex::encode(&encoded)
                && page.packets[0]
                    == hex::encode(expected[0].encode_for_settings(self.node.settings())?),
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
        self.ready()?;
        Ok(true)
    }
}
