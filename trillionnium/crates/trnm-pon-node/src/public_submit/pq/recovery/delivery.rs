use super::*;
use crate::ingress::pq_network::PqResponse;
use crate::ingress::Request;
use sha2::{Digest, Sha256};

fn native_eof(error: &Error) -> bool {
    error.is(ErrorCode::FrameEof) && error.kind() == crate::ErrorKind::Transport
}
fn remote_error(value: &Value) -> Result<Error> {
    value
        .get("error")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 256)
        .map(Error::remote)
        .ok_or_else(|| "SUBMIT_RECOVERY_REMOTE_ERROR".into())
}
fn valid_ack(reply: &PqResponse, id: Hash) -> bool {
    reply.ok
        && reply.value["block"] == hex::encode(id)
        && reply.value["active"]
            .as_str()
            .is_some_and(|v| digest(v).is_ok())
        && reply.value["generation"].as_u64().is_some()
}
impl Session<'_, '_> {
    fn send_packet(&mut self, packet: &Packet, purpose: &'static str) -> Result<PqResponse> {
        self.ready()?;
        let id = packet.id()?;
        let request = Request::Submit {
            packet: hex::encode(packet.encode_for_settings(self.node.settings())?),
        };
        let lifetime = self
            .plan
            .deadline
            .saturating_duration_since(Instant::now())
            .as_secs()
            .min(trnm_protocol::pq_legacy_profile::MAX_LIFETIME_SECONDS);
        let expiry = ingress::now()?
            .checked_add(lifetime)
            .ok_or("PQ_NETWORK_LIFETIME")?;
        let prepared = self
            .journal
            .prepare_or_restore(self.client, &request, expiry)?;
        self.ready()?;
        self.journal.record_attempt()?;
        self.ready()?;
        let ordinal = self.journal.status()?.used_calls;
        let remaining = self.plan.deadline.saturating_duration_since(Instant::now());
        let mut observation = NativeRecoveryAttempt {
            reserved_call: ordinal,
            purpose,
            packet: hex::encode(id),
            sequence: prepared.sequence(),
            original_expires_at: prepared.expires_at(),
            operation: hex::encode(prepared.operation_id()),
            request_wire_sha256: hex::encode(Sha256::digest(prepared.wire())),
            request_wire_bytes: prepared.wire().len(),
            response_wire_sha256: None,
            authenticated_response: None,
            elapsed_since_epoch_ns: 0,
            remaining_before_call_ns: ns(remaining),
            receipt_persisted: false,
            client_error: None,
            journal_error: None,
            retryable_transport_eof: false,
        };
        // The reservation is durable before this real dispatch is entered.
        // Any failure may have followed a remote effect; membership cannot
        // discharge its sequence. Only an authenticated receipt can do that.
        self.ready()?;
        let send_deadline = self
            .plan
            .deadline
            .min(Instant::now() + Duration::from_secs(10));
        observation.remaining_before_call_ns =
            ns(self.plan.deadline.saturating_duration_since(Instant::now()));
        self.outcome.submission_outcome_uncertain = true;
        let result = match self.client.send_until(&prepared, send_deadline) {
            Ok(evidence) => {
                observation.response_wire_sha256 =
                    Some(hex::encode(Sha256::digest(evidence.wire())));
                observation.authenticated_response =
                    Some(serde_json::to_value(evidence.response())?);
                match self.journal.complete(self.client, &evidence) {
                    Ok(()) => {
                        observation.receipt_persisted = true;
                        self.outcome.submission_outcome_uncertain = false;
                        let response = evidence.into_response();
                        if valid_ack(&response, id) {
                            let id = hex::encode(id);
                            if !self.outcome.acknowledged_packets.contains(&id) {
                                self.outcome.acknowledged_packets.push(id);
                            }
                        }
                        Ok(response)
                    }
                    Err(error) => {
                        observation.journal_error = Some(error.to_string());
                        Err(error)
                    }
                }
            }
            Err(error) => {
                observation.client_error = Some(error.to_string());
                observation.retryable_transport_eof = native_eof(&error);
                // This is the direct local send error, never the error string
                // in an authenticated ok=false business response above.
                if error.is(ErrorCode::PqNetworkExpired) {
                    if let Err(fence_error) = self.journal.fence_expired_unconfirmed(&prepared) {
                        observation.journal_error = Some(fence_error.to_string());
                    }
                }
                Err(error)
            }
        };
        observation.elapsed_since_epoch_ns = ns(self.plan.started.elapsed());
        self.outcome
            .attempts
            .push(PqRecoveryAttempt::Native(observation));
        let reply = result?;
        self.ready()?;
        Ok(reply)
    }
    pub(super) fn resume_pending(&mut self, target: &Packet) -> Result<bool> {
        self.ready()?;
        let Some(pending) = self.journal.pending_request()? else {
            return Ok(false);
        };
        self.outcome.submission_outcome_uncertain = pending.attempts > 0;
        let id = pending
            .packet_id
            .ok_or("PQ_PARENT_RECOVERY_PENDING_OPERATION")?;
        let mut retained = target.clone();
        let mut depth = 0u8;
        while retained.id()? != id {
            ensure(
                depth < self.plan.max_parent_packets
                    && retained.header.parent != self.node.settings().genesis(),
                "PQ_PARENT_RECOVERY_PENDING_ANCESTOR",
            )?;
            depth += 1;
            retained = self.local_packet(retained.header.parent)?;
        }
        let request = Request::Submit {
            packet: hex::encode(retained.encode_for_settings(self.node.settings())?),
        };
        ensure(
            serde_json::to_string(&request)? == pending.canonical_request_json,
            "PQ_PARENT_RECOVERY_PENDING_REQUEST",
        )?;
        let is_target = id == target.id()?;
        self.deliver(&retained, is_target)?;
        if !is_target {
            self.outcome
                .restored_parent_memberships
                .push(hex::encode(id));
        }
        Ok(is_target)
    }
    fn restore_parent(&mut self, parent: Hash) -> Result<()> {
        self.ready()?;
        ensure(
            self.journal.pending_request()?.is_none(),
            "PQ_RECOVERY_UNCONFIRMED_SEQUENCE",
        )?;
        let anchor = digest(&self.head()?.tip)?;
        let mut current = parent;
        let mut missing = Vec::new();
        while current != anchor {
            self.ready()?;
            ensure(
                current != self.node.settings().genesis(),
                "SUBMIT_RECOVERY_PARENT_BRANCH",
            )?;
            let packet = self.local_packet(current)?;
            self.journal.reserve_parent(current)?;
            current = packet.header.parent;
            missing.push(packet);
        }
        ensure(!missing.is_empty(), "SUBMIT_RECOVERY_PARENT_CONTRADICTION")?;
        for packet in missing.iter().rev() {
            // Ordered ancestors cannot start another recursive repair after a
            // remote branch change. Every reservation survives cold reopening.
            self.deliver(packet, false)?;
            self.outcome
                .restored_parent_memberships
                .push(hex::encode(packet.id()?));
        }
        Ok(())
    }
    pub(super) fn deliver(&mut self, packet: &Packet, allow_parent_repair: bool) -> Result<()> {
        let id = packet.id()?;
        loop {
            self.ready()?;
            let used = self
                .journal
                .status()?
                .per_packet_submit_counts
                .get(&id)
                .copied()
                .unwrap_or_default();
            ensure(
                used < self.plan.max_submit_attempts,
                "SUBMIT_RECOVERY_ATTEMPT_LIMIT",
            )?;
            let purpose = if allow_parent_repair {
                "pending-packet"
            } else {
                "parent-restoration"
            };
            let before = self.outcome.attempts.len();
            match self.send_packet(packet, purpose) {
                Ok(reply) if reply.ok => {
                    ensure(valid_ack(&reply, id), "SUBMIT_RECOVERY_ACK_CONTEXT")?;
                    ensure(
                        self.journal.pending_request()?.is_none(),
                        "PQ_RECOVERY_UNCONFIRMED_SEQUENCE",
                    )?;
                    ensure(
                        self.membership(packet)?,
                        "SUBMIT_RECOVERY_MEMBERSHIP_ABSENT",
                    )?;
                    return Ok(());
                }
                Ok(reply) => {
                    let error = remote_error(&reply.value)?;
                    match reply.value.get("error").and_then(Value::as_str) {
                        Some("UNKNOWN_PARENT") if allow_parent_repair => {
                            self.restore_parent(packet.header.parent)?;
                        }
                        Some("PUBLIC_MUTATION_CPU_BUDGET") => {
                            // This signed refusal already consumed its native
                            // sequence. Membership now observes only chain state.
                            if self.membership(packet)? {
                                return Ok(());
                            }
                            self.pause_after_cpu_budget(id)?;
                        }
                        _ => return Err(error),
                    }
                }
                Err(error) => {
                    let actual_local_eof = match self.outcome.attempts.last() {
                        Some(PqRecoveryAttempt::Native(row)) => {
                            self.outcome.attempts.len() == before + 1
                                && row.client_error.is_some()
                                && row.retryable_transport_eof
                                && row.journal_error.is_none()
                                && native_eof(&error)
                        }
                        _ => false,
                    };
                    if !actual_local_eof {
                        return Err(error);
                    }
                    // Keep the original request bytes, signature, expiry and
                    // sequence. Never turn a History observation into an ACK.
                    self.pause_for(self.plan.retry_pause)?;
                }
            }
        }
    }
}
