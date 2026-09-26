// Direct-seven terminal coordination stays outside Core and restart authority.
impl BoundedConsensusOwnerV1 {
    fn terminal_barrier_v1(&self) -> Result<&crate::terminal_barrier_v1::TerminalBarrierV1> {
        self.terminal_barrier
            .as_ref()
            .context("terminal barrier requires direct seven profile")
    }
    fn terminal_barrier_mut_v1(
        &mut self,
    ) -> Result<&mut crate::terminal_barrier_v1::TerminalBarrierV1> {
        self.terminal_barrier
            .as_mut()
            .context("terminal barrier requires direct seven profile")
    }

    fn terminal_barrier_enabled_v1(&self) -> bool {
        self.preflight.transport == ConsensusTransportProfileV1::Direct
            && self.config.validator_set().validators().len() == 7
    }

    fn maybe_advance_terminal_barrier_v1(&mut self, now: Instant) -> Result<bool> {
        if !self.terminal_barrier_enabled_v1() {
            return self.terminal_ready_v1(now);
        }
        if self.terminal_owner.is_some() {
            return Ok(self.terminal_barrier_v1()?.complete()?
                && self.outbox.is_empty()
                && self.mesh_v1()?.pending_outbound_bytes_v1()? == 0);
        }
        if !self.terminal_barrier_v1()?.local_prepared() {
            if !self.terminal_ready_v1(now)? {
                return Ok(false);
            }
            let snapshot = self.restart_quiescence_snapshot_v1()?;
            let prepare = terminal_prepare_from_snapshot_v1(&snapshot)?;
            self.terminal_prepared_snapshot = Some(snapshot);
            let bytes = self.terminal_barrier_mut_v1()?.prepare_local(prepare)?;
            self.outbox.enqueue(FrameKind::TerminalBarrier, bytes)?;
            return Ok(false);
        }
        // Prepare does not change the durable consensus cut. Transport bytes
        // for Prepare/Park may be in flight; every other snapshot field must
        // still match the actual Ready/signer/checkpoint readback.
        let mut current = self.restart_quiescence_snapshot_v1()?;
        current.outbox_frame_count = 0;
        current.outbox_payload_bytes = 0;
        current.mesh_pending_outbound_bytes = 0;
        ensure!(
            Some(current) == self.terminal_prepared_snapshot,
            "local durable work changed after terminal Prepare"
        );
        if self.terminal_barrier_v1()?.prepare_set()?.is_none()
            || !self.outbox.is_empty()
            || self.mesh_v1()?.pending_outbound_bytes_v1()? != 0
        {
            return Ok(false);
        }
        let authority = self
            .authority
            .take()
            .context("terminal Prepare lost actual continuous authority")?;
        let mut terminal = authority.into_terminal_owner_v0()?;
        // This entry accepts the actual non-cloneable consumed owner and
        // freshly confirms it before returning any Park bytes.
        let bytes = self.terminal_barrier_mut_v1()?.park_local(&mut terminal)?;
        self.terminal_owner = Some(terminal);
        self.pacemaker.cancel();
        self.outbox.enqueue(FrameKind::TerminalBarrier, bytes)?;
        Ok(false)
    }

    fn poll_parked_terminal_v1(&mut self) -> Result<bool> {
        ensure!(
            self.authority.is_none() && self.terminal_owner.is_some(),
            "parked terminal retained ordinary authority"
        );
        ensure!(
            self.restart_lifecycle.is_running_v1(),
            "terminal Park conflicts with restart authority"
        );
        self.mesh_v1()?.ensure_healthy()?;
        // A control request cannot reactivate a consumed ordinary owner.
        self.poll_runtime_control_v1()?;
        ensure!(
            self.restart_lifecycle.is_running_v1()
                && self.active_connectivity_fault.is_none()
                && self.event_journal.observation().active_faults.is_empty()
                && self
                    .runtime_control
                    .as_ref().is_none_or(|c| c.expected_fault().is_none()),
            "control work arrived after terminal Park"
        );
        self.flush_outbox_v1()?;
        if let Some(event) = self.mesh_v1()?.receive_timeout(OWNER_POLL_INTERVAL_V1)? {
            self.handle_parked_terminal_event_v1(event)?;
        }
        drain_remaining_ingress_tick_v1(|| {
            self.mesh_v1()?
                .receive_timeout(Duration::ZERO)?
                .map(|event| self.handle_parked_terminal_event_v1(event))
                .transpose()
        })?;
        self.maybe_advance_terminal_barrier_v1(Instant::now())
    }

    fn handle_parked_terminal_event_v1(&mut self, event: MeshIngressEventV0) -> Result<bool> {
        match event {
            MeshIngressEventV0::Frame(inbound) => {
                ensure!(
                    inbound.frame().kind == FrameKind::TerminalBarrier,
                    "ordinary or restart ingress after terminal Park"
                );
                self.admit_inbound_mesh_frame_session_v1(&inbound)?;
                self.network_rx_bytes = self
                    .network_rx_bytes
                    .checked_add(authenticated_frame_wire_bytes_v1(
                        self.config.run_id(),
                        inbound.frame().payload.len(),
                    )?)
                    .context("terminal receive counter overflows")?;
                self.terminal_barrier_mut_v1()?.admit(&inbound)?;
            }
            MeshIngressEventV0::SessionUnavailable(session) => {
                self.terminal_barrier_mut_v1()?
                    .observe_unavailable(session)?;
            }
            MeshIngressEventV0::SessionReestablished(_) => {
                bail!("peer reconnected after terminal Park")
            }
        }
        Ok(false)
    }

    fn require_terminal_drain_deadline_v1(&self, now: Instant) -> Result<()> {
        if let Some(stopping_since) = self.stopping_since {
            let deadline = stopping_since
                .max(self.nominal_deadline)
                .checked_add(TERMINAL_DRAIN_GRACE_V1)
                .context("terminal drain deadline overflows")?;
            ensure!(
                now < deadline,
                "bounded consensus could not reach an obligation-free terminal cut"
            );
        }
        Ok(())
    }
}

fn terminal_prepare_from_snapshot_v1(
    snapshot: &RestartQuiescenceSnapshotV1,
) -> Result<crate::terminal_barrier_v1::TerminalPrepareV1> {
    ensure!(
        snapshot.authority_phase == PocoNodeLabAuthorityPhaseV0::Ready
            && snapshot.normal_stop_in_progress
            && !snapshot.restart_requested
            && snapshot.pending_proposal_count == 0
            && snapshot.pending_certificate_count == 0
            && snapshot.prestarted_ingress_count == 0
            && snapshot.unavailable_session_count == 0
            && snapshot.outbox_frame_count == 0
            && snapshot.outbox_payload_bytes == 0
            && snapshot.mesh_pending_outbound_bytes == 0
            && !snapshot.pending_timeout_certificate
            && !snapshot.post_timeout_rebase_pending
            && !snapshot.active_connectivity_fault
            && !snapshot.expected_control_fault
            && snapshot.active_journal_fault_count == 0
            && snapshot.journal_restart_prepare_absent
            && !snapshot.journal_restart_pending_catchup
            && !snapshot.journal_final_tip_recorded
            && !snapshot.journal_clean_stop_recorded
            && !snapshot.journal_safety_halted
            && snapshot.application_height == snapshot.finalized_height
            && snapshot.application_block_id == snapshot.finalized_block_id
            && snapshot.checkpoint_canonical_sha256 == snapshot.runtime_checkpoint_canonical_sha256
            && snapshot.signer_inventory_digest == snapshot.authenticated_signer_inventory_digest
            && snapshot.signer_exact_watermark.is_some()
            && snapshot.signer_exact_watermark == snapshot.checkpoint_signer_exact_watermark,
        "terminal Prepare lacks an exact obligation-free Ready cut"
    );
    let mut hash = Sha256::new();
    hash.update(b"TRNM/DirectSevenTerminalLocalCut/V1\0");
    // The independently persisted canonical node checkpoint binds Core,
    // native P/K, Safety and exact signer cut. Archive and signed journal
    // heads bind the corresponding process evidence, without timing/queues.
    hash.update(snapshot.local_validator.as_bytes());
    hash.update(snapshot.process_instance.to_le_bytes());
    hash.update(snapshot.checkpoint_generation.to_le_bytes());
    hash.update(snapshot.checkpoint_canonical_sha256);
    hash.update(snapshot.signer_inventory_digest);
    hash.update(snapshot.replay_archive_context_sha256);
    hash.update(snapshot.replay_archive_head_sequence.to_le_bytes());
    hash.update(snapshot.replay_archive_head_sha256);
    hash.update(snapshot.journal_head_sequence.to_le_bytes());
    hash.update(snapshot.journal_head_sha256);
    hash.update(snapshot.journal_next_sequence.to_le_bytes());
    Ok(crate::terminal_barrier_v1::TerminalPrepareV1 {
        common: crate::terminal_barrier_v1::TerminalCommonCutV1 {
            height: snapshot.finalized_height,
            block: *snapshot.finalized_block_id.as_bytes(),
            state: snapshot.application_state_root,
            chain: snapshot.finalized_chain_root,
        },
        checkpoint: snapshot.checkpoint_canonical_sha256,
        local_cut: hash.finalize().into(),
    })
}
