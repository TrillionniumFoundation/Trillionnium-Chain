/// Cloneable signed bytes retained only for transport retry. These slots carry
/// no admission, persistence, or lifecycle authority. Every receiver still
/// passes the original `(origin, phase)` admission and exact-replay checks.
#[derive(Debug, Default)]
struct RestartProtocolRetransmitV1 {
    prepare_payload: Option<Vec<u8>>,
    cut_payload: Option<Vec<u8>>,
    parked_ack_payload: Option<Vec<u8>>,
    next_retry_at: Option<Instant>,
    retry_rounds: u64,
}

impl RestartProtocolRetransmitV1 {
    fn remember_v1(
        &mut self,
        phase: RestartProtocolPhaseV1,
        payload: Vec<u8>,
        now: Instant,
    ) -> Result<()> {
        ensure!(!payload.is_empty(), "restart retry payload is empty");
        let slot = match phase {
            RestartProtocolPhaseV1::Prepare => &mut self.prepare_payload,
            RestartProtocolPhaseV1::Cut => &mut self.cut_payload,
            RestartProtocolPhaseV1::ParkedAck => &mut self.parked_ack_payload,
            RestartProtocolPhaseV1::RecoveryReady | RestartProtocolPhaseV1::RecoveryStart => {
                bail!("process-1 retry owner cannot retain recovery phases")
            }
        };        ensure!(
            slot.as_ref().is_none_or(|existing| existing == &payload),
            "restart retry slot conflicts with its original signed payload"
        );
        if slot.is_none() {
            *slot = Some(payload);
        }
        self.next_retry_at = Some(
            now.checked_add(RESTART_PROTOCOL_RETRY_INTERVAL_V1)
                .ok_or_else(|| anyhow!("restart retry deadline overflows"))?,
        );
        Ok(())
    }

    fn schedule_next_v1(&mut self, now: Instant) -> Result<()> {
        self.retry_rounds = self
            .retry_rounds
            .checked_add(1)
            .context("restart retry-round counter overflows")?;
        self.next_retry_at = Some(
            now.checked_add(RESTART_PROTOCOL_RETRY_INTERVAL_V1)
                .ok_or_else(|| anyhow!("restart retry deadline overflows"))?,
        );
        Ok(())
    }

    fn clear_if_empty_v1(&mut self) {
        if self.prepare_payload.is_none()
            && self.cut_payload.is_none()            && self.parked_ack_payload.is_none()
        {
            self.next_retry_at = None;
        }
    }
}

fn restart_retry_missing_recipients_v1(
    remote_peers: &BTreeSet<ValidatorId>,
    completed_origins: &BTreeSet<ValidatorId>,
) -> BTreeSet<ValidatorId> {
    remote_peers
        .difference(completed_origins)
        .copied()
        .collect()
}

impl BoundedConsensusOwnerV1 {
    fn maybe_retry_restart_protocol_v1(&mut self, now: Instant) -> Result<bool> {
        let Some(next_retry_at) = self.restart_retransmit.next_retry_at else {
            return Ok(false);
        };
        if now < next_retry_at
            || !self.outbox.is_empty()
            || self.mesh_v1()?.pending_outbound_bytes_v1()? != 0
        {
            return Ok(false);
        }
        ensure!(
            self.preflight.transport == ConsensusTransportProfileV1::Direct
                && self.config.validator_set().validators().len() == 7,
            "process-1 restart retransmission requires direct-seven transport"
        );
        let remote_peers = self
            .config
            .validator_set()
            .validators()
            .iter()
            .map(|validator| validator.id())
            .filter(|origin| *origin != self.config.local_validator())            .collect::<BTreeSet<_>>();
        ensure!(remote_peers.len() == 6, "restart retry peer set is not direct-seven");

        let prepare_payload = self.restart_retransmit.prepare_payload.clone();
        let cut_payload = self.restart_retransmit.cut_payload.clone();
        let parked_ack_payload = self.restart_retransmit.parked_ack_payload.clone();
        let mut plans = Vec::<(FrameKind, Vec<u8>, BTreeSet<ValidatorId>)>::new();
        let mut clear_prepare = false;
        let mut clear_cut = false;
        let mut clear_ack = false;

        if let Some(payload) = prepare_payload {
            if matches!(self.restart_lifecycle, RestartLifecycleV1::TargetCollecting(_)) {
                let completed = self
                    .restart_round
                    .admitted_statements
                    .keys()
                    .copied()
                    .collect::<BTreeSet<_>>();
                let missing = restart_retry_missing_recipients_v1(&remote_peers, &completed);
                if missing.is_empty() {
                    clear_prepare = true;
                } else {
                    plans.push((FrameKind::RestartPrepare, payload, missing));
                }
            } else {
                clear_prepare = true;
            }
        }

        if let Some(payload) = cut_payload {            if matches!(
                self.restart_lifecycle,
                RestartLifecycleV1::TargetAcked(_) | RestartLifecycleV1::PeerAcked(_)
            ) {
                clear_cut = true;
            } else if self.restart_lifecycle.is_prepared_v1() {
                // A remote ParkedAck proves that origin formed the complete
                // Cut/Park barrier and therefore admitted this local Cut.
                let completed = self
                    .restart_round
                    .pending_parked_acks
                    .keys()
                    .chain(self.restart_round.admitted_parked_acks.keys())
                    .copied()
                    .collect::<BTreeSet<_>>();
                let missing = restart_retry_missing_recipients_v1(&remote_peers, &completed);
                if missing.is_empty() {
                    clear_cut = true;
                } else {
                    plans.push((FrameKind::RestartCut, payload, missing));
                }
            }
        }

        if let Some(payload) = parked_ack_payload {
            if matches!(
                self.restart_lifecycle,
                RestartLifecycleV1::TargetAckCollecting(_)
                    | RestartLifecycleV1::PeerAckCollecting(_)
            ) {                // There is no sixth protocol phase. Repeat the exact signed Ack
                // until this node's N/N collector and transport drain both close.
                plans.push((FrameKind::RestartParkedAck, payload, remote_peers));
            } else if matches!(
                self.restart_lifecycle,
                RestartLifecycleV1::TargetAcked(_) | RestartLifecycleV1::PeerAcked(_)
            ) {
                clear_ack = true;
            }
        }

        if clear_prepare {
            self.restart_retransmit.prepare_payload = None;
        }
        if clear_cut {
            self.restart_retransmit.cut_payload = None;
        }
        if clear_ack {
            self.restart_retransmit.parked_ack_payload = None;
        }
        self.restart_retransmit.clear_if_empty_v1();
        if plans.is_empty() {
            if self.restart_retransmit.next_retry_at.is_some() {
                self.restart_retransmit.schedule_next_v1(now)?;
            }
            return Ok(false);
        }
        for (kind, payload, recipients) in plans {
            self.outbox.enqueue_to_peers_v1(kind, payload, recipients)?;
        }        self.restart_retransmit.schedule_next_v1(now)?;
        Ok(true)
    }
}
