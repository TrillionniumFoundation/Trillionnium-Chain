#[derive(Debug, Clone)]
struct PeerQuarantineRecordV1 {
    source: PeerSessionFactsV0,
    reason: crate::transport::EstablishedPeerInputRejectionV1,
    pinned: BTreeMap<PeerDirectionV0, PeerSessionFactsV0>,
    refused_reconnects: u64,
    canceled_ingress_frames: u64,
    canceled_ingress_bytes: u64,
    cleaned: bool,
}

#[derive(Default)]
struct PeerQuarantineStateV1 {
    configured: bool,
    incoming: BTreeSet<ValidatorId>,
    outgoing: BTreeSet<ValidatorId>,
    records: BTreeMap<ValidatorId, PeerQuarantineRecordV1>,
    outgoing_workers: BTreeMap<ValidatorId, JoinHandle<()>>,
}

impl MeshFenceRegistryV1 {
    fn configure_peer_quarantine_v1(
        &self,
        incoming: BTreeSet<ValidatorId>,
        outgoing: BTreeSet<ValidatorId>,
    ) -> Result<()> {
        ensure!(
            !incoming.is_empty()
                && incoming.len() <= MAX_DIRECTED_PEERS
                && outgoing.len() <= MAX_DIRECTED_PEERS
                && !incoming.contains(&self.local)
                && !outgoing.contains(&self.local),
            "quarantine peer inventory is invalid"
        );
        let mut state = self
            .quarantine
            .lock()
            .map_err(|_| anyhow!("quarantine registry poisoned"))?;
        ensure!(
            !state.configured,
            "quarantine peer inventory already configured"
        );
        state.incoming = incoming;
        state.outgoing = outgoing;
        state.configured = true;
        Ok(())
    }

    fn cancel_quarantined_ingress_v1(&self, event: &MeshIngressEventV0) -> Result<bool> {
        let MeshIngressEventV0::Frame(frame) = event else {
            return Ok(false);
        };
        let mut state = self
            .quarantine
            .lock()
            .map_err(|_| anyhow!("quarantine registry poisoned"))?;
        let Some(record) = state.records.get_mut(&frame.remote) else {
            return Ok(false);
        };
        ensure!(
            frame.direction == PeerDirectionV0::Inbound
                && frame.session_generation <= record.source.generation
                && (frame.session_generation < record.source.generation
                    || frame.session_id == record.source.session_id),
            "quarantined ingress owner has a foreign generation"
        );
        let frames = record
            .canceled_ingress_frames
            .checked_add(1)
            .context("quarantine ingress count overflows")?;
        let bytes = record
            .canceled_ingress_bytes
            .checked_add(
                u64::try_from(frame.frame.payload.len())
                    .context("quarantine ingress length overflows")?,
            )
            .context("quarantine ingress bytes overflow")?;
        record.canceled_ingress_frames = frames;
        record.canceled_ingress_bytes = bytes;
        Ok(true)
    }

    fn peer_quarantined_v1(&self, remote: ValidatorId) -> Result<bool> {
        Ok(self
            .quarantine
            .lock()
            .map_err(|_| anyhow!("quarantine registry poisoned"))?
            .records
            .contains_key(&remote))
    }

    // Caller holds admission_lock: quarantine publication and new lease
    // admission cannot pass each other, including host-attestation side effects.
    fn refuse_quarantined_admission_locked_v1(&self, remote: ValidatorId) -> Result<bool> {
        let mut state = self
            .quarantine
            .lock()
            .map_err(|_| anyhow!("quarantine registry poisoned"))?;
        let Some(record) = state.records.get_mut(&remote) else {
            return Ok(false);
        };
        record.refused_reconnects = record
            .refused_reconnects
            .checked_add(1)
            .context("quarantine reconnect counter overflows")?;
        Ok(true)
    }

    fn publish_peer_rejection_v1(
        &self,
        source: PeerSessionFactsV0,
        error: &crate::transport::EstablishedReceiveErrorV1,
    ) -> Result<()> {
        let crate::transport::EstablishedReceiveClassV1::PeerInput(reason) = error.class_v1()
        else {
            bail!("non-peer error cannot quarantine a peer");
        };
        ensure!(
            source.direction == PeerDirectionV0::Inbound
                && source.remote == error.session_v1().remote()
                && source.session_id == error.session_v1().session()
                && source.generation > 0,
            "quarantine differs from authenticated receive owner"
        );
        let _guard = self
            .admission_lock
            .lock()
            .map_err(|_| anyhow!("mesh fence admission lock poisoned"))?;
        self.revalidate_locked((source.direction, source.remote))?;
        let tokens = self
            .tokens
            .lock()
            .map_err(|_| anyhow!("mesh fence token map poisoned"))?;
        let mut pinned = BTreeMap::new();
        for direction in [PeerDirectionV0::Inbound, PeerDirectionV0::Outbound] {
            if let Some(entry) = tokens.get(&(direction, source.remote)) {
                let scope = entry.token.scope();
                ensure!(
                    !entry.external_release_confirmed
                        && scope.local() == self.local
                        && scope.remote() == source.remote,
                    "quarantine pins an invalid lease"
                );
                pinned.insert(
                    direction,
                    PeerSessionFactsV0 {
                        remote: source.remote,
                        direction,
                        session_id: scope.session_id(),
                        generation: scope.generation(),
                    },
                );
            }
        }
        ensure!(
            pinned.get(&PeerDirectionV0::Inbound) == Some(&source),
            "quarantine inbound lease changed"
        );
        let mut state = self
            .quarantine
            .lock()
            .map_err(|_| anyhow!("quarantine registry poisoned"))?;
        ensure!(
            state.configured && state.incoming.contains(&source.remote),
            "quarantine peer is outside frozen inventory"
        );
        if let Some(prior) = state.records.get(&source.remote) {
            ensure!(
                prior.source == source && prior.reason == reason,
                "conflicting quarantine source"
            );
            return Ok(());
        }
        ensure!(
            state.records.len() < state.incoming.len(),
            "quarantine identity capacity exhausted"
        );
        state.records.insert(
            source.remote,
            PeerQuarantineRecordV1 {
                source,
                reason,
                pinned,
                refused_reconnects: 0,
                canceled_ingress_frames: 0,
                canceled_ingress_bytes: 0,
                cleaned: false,
            },
        );
        Ok(())
    }

    fn register_outgoing_worker_v1(
        &self,
        remote: ValidatorId,
        worker: &mut Option<JoinHandle<()>>,
    ) -> Result<()> {
        let mut state = self
            .quarantine
            .lock()
            .map_err(|_| anyhow!("quarantine registry poisoned"))?;
        ensure!(
            state.configured
                && state.outgoing.contains(&remote)
                && !state.records.contains_key(&remote)
                && !state.outgoing_workers.contains_key(&remote),
            "outgoing quarantine worker inventory differs"
        );
        state.outgoing_workers.insert(
            remote,
            worker
                .take()
                .context("outgoing worker was already consumed")?,
        );
        Ok(())
    }

    fn join_outgoing_workers_v1(&self) -> Result<()> {
        // Poison is fatal, but cleanup must still join handles already owned by
        // this registry. Recovering the container is not recovering authority.
        let (workers, poisoned) = match self.quarantine.lock() {
            Ok(mut state) => (std::mem::take(&mut state.outgoing_workers), false),
            Err(error) => (
                std::mem::take(&mut error.into_inner().outgoing_workers),
                true,
            ),
        };
        let mut panicked = false;
        for (_, worker) in workers {
            panicked |= worker.join().is_err();
        }
        ensure!(!poisoned, "quarantine registry poisoned during join");
        ensure!(!panicked, "outgoing mesh worker panicked during join");
        Ok(())
    }

    fn retire_quarantined_peer_v1(
        &self,
        source: PeerSessionFactsV0,
        children: &mut BTreeMap<ValidatorId, InboundWorkerV0>,
        controls: &ActiveControlsV0,
        ingress: &SyncSender<MeshIngressEventV0>,
        terminal: &Mutex<Option<MeshTerminalFailureV0>>,
        stop: &AtomicBool,
    ) -> Result<()> {
        let record = self
            .quarantine
            .lock()
            .map_err(|_| anyhow!("quarantine registry poisoned"))?
            .records
            .get(&source.remote)
            .cloned()
            .context("quarantine retirement lacks publication")?;
        ensure!(
            record.source == source,
            "quarantine retirement source changed"
        );
        if record.cleaned {
            return Ok(());
        }
        ensure!(
            children.get(&source.remote).map(|w| w.facts) == Some(source),
            "quarantine worker generation changed"
        );
        // No new admission can replace either direction after publication.
        remove_control_checked_v1(controls, PeerDirectionV0::Inbound, source.remote)?;
        remove_control_checked_v1(controls, PeerDirectionV0::Outbound, source.remote)?;
        let worker = children
            .remove(&source.remote)
            .context("quarantine worker disappeared")?;
        ensure!(
            worker.handle.join().is_ok(),
            "quarantined inbound worker panicked"
        );
        self.finish_joined_quarantine_v1(source, controls, ingress, terminal, stop)
    }

    // Called only after the original inbound JoinHandle was consumed by the
    // acceptor, including an explicit old-generation replacement race.
    fn finish_joined_quarantine_v1(
        &self,
        source: PeerSessionFactsV0,
        controls: &ActiveControlsV0,
        ingress: &SyncSender<MeshIngressEventV0>,
        terminal: &Mutex<Option<MeshTerminalFailureV0>>,
        stop: &AtomicBool,
    ) -> Result<()> {
        let record = self
            .quarantine
            .lock()
            .map_err(|_| anyhow!("quarantine registry poisoned"))?
            .records
            .get(&source.remote)
            .cloned()
            .context("quarantine retirement lacks publication")?;
        ensure!(
            record.source == source && !record.cleaned,
            "quarantine joined source changed"
        );
        remove_control_checked_v1(controls, PeerDirectionV0::Outbound, source.remote)?;
        let outgoing = {
            let mut state = self
                .quarantine
                .lock()
                .map_err(|_| anyhow!("quarantine registry poisoned"))?;
            if state.outgoing.contains(&source.remote) {
                Some(
                    state
                        .outgoing_workers
                        .remove(&source.remote)
                        .context("quarantine outgoing worker disappeared")?,
                )
            } else {
                None
            }
        };
        if let Some(worker) = outgoing {
            ensure!(
                worker.join().is_ok(),
                "quarantined outgoing worker panicked"
            );
        }
        {
            let _guard = self
                .admission_lock
                .lock()
                .map_err(|_| anyhow!("mesh fence admission lock poisoned"))?;
            for direction in [PeerDirectionV0::Inbound, PeerDirectionV0::Outbound] {
                let current = self
                    .tokens
                    .lock()
                    .map_err(|_| anyhow!("mesh fence token map poisoned"))?
                    .get(&(direction, source.remote))
                    .map(|entry| {
                        let scope = entry.token.scope();
                        PeerSessionFactsV0 {
                            remote: scope.remote(),
                            direction,
                            session_id: scope.session_id(),
                            generation: scope.generation(),
                        }
                    });
                ensure!(
                    current.as_ref() == record.pinned.get(&direction),
                    "quarantine cleanup lease changed"
                );
                self.release_locked_v1(direction, source.remote)?;
            }
            self.quarantine
                .lock()
                .map_err(|_| anyhow!("quarantine registry poisoned"))?
                .records
                .get_mut(&source.remote)
                .context("quarantine record disappeared")?
                .cleaned = true;
        }
        for facts in record.pinned.values() {
            emit_event(
                ingress,
                MeshIngressEventV0::SessionUnavailable(*facts),
                terminal,
                stop,
                *facts,
                None,
            )?;
        }
        Ok(())
    }
}

fn remove_control_checked_v1(
    controls: &ActiveControlsV0,
    direction: PeerDirectionV0,
    remote: ValidatorId,
) -> Result<()> {
    let stream = controls
        .lock()
        .map_err(|_| anyhow!("mesh control map poisoned"))?
        .remove(&(direction, remote));
    if let Some(stream) = stream {
        // An already disconnected TCP edge is not an authority failure.
        if let Err(error) = stream.shutdown(Shutdown::Both) {
            ensure!(
                error.kind() == io::ErrorKind::NotConnected,
                "quarantine socket shutdown failed: {error}"
            );
        }
    }
    Ok(())
}

impl MeshFenceRegistryV1 {
    fn require_quarantine_cleanup_v1(&self) -> Result<()> {
        ensure!(
            self.quarantine
                .lock()
                .map_err(|_| anyhow!("quarantine registry poisoned"))?
                .records
                .values()
                .all(|r| r.cleaned),
            "quarantine retirement was incomplete at shutdown"
        );
        Ok(())
    }

    fn refuse_quarantined_reconnect_v1(&self, remote: ValidatorId) -> Result<bool> {
        let _guard = self
            .admission_lock
            .lock()
            .map_err(|_| anyhow!("mesh fence admission lock poisoned"))?;
        self.refuse_quarantined_admission_locked_v1(remote)
    }
}

fn stop_quarantined_sender_v1(
    fences: &MeshFenceRegistryV1,
    remote: ValidatorId,
    terminal: &Mutex<Option<MeshTerminalFailureV0>>,
    stop: &AtomicBool,
) -> bool {
    match fences.peer_quarantined_v1(remote) {
        Ok(stopped) => stopped,
        Err(error) => {
            set_terminal(
                terminal,
                stop,
                MeshTerminalFailureV0 {
                    remote,
                    direction: PeerDirectionV0::Outbound,
                    reason: error.to_string(),
                },
            );
            true
        }
    }
}

fn handle_completed_peer_rejection_v1(
    fences: &MeshFenceRegistryV1,
    source: PeerSessionFactsV0,
    error: &crate::transport::EstablishedReceiveErrorV1,
    lifecycle: &SyncSender<InboundLifecycleV0>,
    terminal: &Mutex<Option<MeshTerminalFailureV0>>,
    stop: &AtomicBool,
) {
    // This classification already completed against the actual old session.
    // Supersession must join this worker before releasing its lease; its cancel
    // bit cannot erase an established peer violation or authorize a new lease.
    let result = (|| {
        ensure!(
            matches!(
                error.class_v1(),
                crate::transport::EstablishedReceiveClassV1::PeerInput(_)
            ),
            "non-peer receive failure reached quarantine consumer"
        );
        ensure!(
            !stop.load(Ordering::Acquire),
            "completed peer input rejection during shutdown: {}",
            error.frame_error_v1()
        );
        fences.publish_peer_rejection_v1(source, error)?;
        // At most one terminal lifecycle per current worker and capacity 2*N.
        // Never block a supersession join if that internal bound is violated.
        lifecycle
            .try_send(InboundLifecycleV0::PeerRejected(source))
            .map_err(|error| {
                anyhow!(match error {
                    TrySendError::Full(_) => "quarantine lifecycle queue full",
                    TrySendError::Disconnected(_) => "quarantine lifecycle owner disappeared",
                })
            })
    })();
    if let Err(failure) = result {
        set_terminal(
            terminal,
            stop,
            MeshTerminalFailureV0 {
                remote: source.remote,
                direction: source.direction,
                reason: failure.to_string(),
            },
        );
    }
}

fn retain_classified_inbound_failure_v1(
    terminal: &Mutex<Option<MeshTerminalFailureV0>>,
    stop: &AtomicBool,
    edge_cancel: &AtomicBool,
    source: PeerSessionFactsV0,
    error: &crate::transport::EstablishedReceiveErrorV1,
) {
    if error.class_v1() == crate::transport::EstablishedReceiveClassV1::Internal {
        // Completed local/host/cursor failures are not caused by superseding
        // a socket, and cannot be erased by that connection's cancel bit.
        set_terminal(
            terminal,
            stop,
            MeshTerminalFailureV0 {
                remote: source.remote,
                direction: source.direction,
                reason: format!(
                    "internal established receive failure: {}",
                    error.frame_error_v1()
                ),
            },
        );
    } else {
        retain_nontransient_inbound_failure_v1(
            terminal,
            stop,
            edge_cancel,
            source,
            "non-recoverable frame error",
            error.frame_error_v1(),
        );
    }
}
