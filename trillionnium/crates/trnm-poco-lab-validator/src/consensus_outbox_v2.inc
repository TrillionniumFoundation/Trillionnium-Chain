#[derive(Debug)]
struct OrderedBroadcastV1 {
    kind: FrameKind,
    payload: Arc<[u8]>,
    remaining_peers: BTreeSet<ValidatorId>,
}

#[derive(Debug)]
struct OrderedConsensusOutboxV1 {
    peers: Vec<ValidatorId>,
    pending: VecDeque<OrderedBroadcastV1>,
    pending_bytes: usize,
}

impl OrderedConsensusOutboxV1 {
    fn new(peers: Vec<ValidatorId>) -> Self {
        Self {
            peers,
            pending: VecDeque::new(),
            pending_bytes: 0,
        }
    }

    fn enqueue(&mut self, kind: FrameKind, payload: Vec<u8>) -> Result<()> {
        self.enqueue_with_excluded_v1(kind, payload, None)
    }

    fn enqueue_except_v1(
        &mut self,
        kind: FrameKind,
        payload: Vec<u8>,
        excluded_peer: ValidatorId,
    ) -> Result<()> {
        self.enqueue_with_excluded_v1(kind, payload, Some(excluded_peer))
    }

    fn enqueue_with_excluded_v1(
        &mut self,
        kind: FrameKind,
        payload: Vec<u8>,
        excluded_peer: Option<ValidatorId>,
    ) -> Result<()> {
        ensure!(!payload.is_empty(), "consensus outbox payload is empty");
        ensure!(
            self.pending.len() < MAXIMUM_PENDING_BROADCASTS_V1,
            "consensus outbox message capacity exhausted"
        );
        let next_bytes = self
            .pending_bytes
            .checked_add(payload.len())
            .context("consensus outbox byte accounting overflows")?;
        ensure!(
            next_bytes <= MAXIMUM_PENDING_BROADCAST_BYTES_V1,
            "consensus outbox byte capacity exhausted"
        );
        let mut remaining_peers = self.peers.iter().copied().collect::<BTreeSet<_>>();
        if let Some(excluded_peer) = excluded_peer {
            remaining_peers.remove(&excluded_peer);
        }
        ensure!(
            !remaining_peers.is_empty(),
            "consensus outbox has no eligible destination peer"
        );
        self.pending_bytes = next_bytes;
        self.pending.push_back(OrderedBroadcastV1 {
            kind,
            payload: Arc::from(payload),
            remaining_peers,
        });
        Ok(())
    }

    fn flush_front_v1(&mut self, mesh: &PersistentAuthenticatedPeerMeshV0) -> Result<(u64, u64)> {
        self.flush_with_v2(|peer, kind, payload| mesh.send_shared_to_v0(peer, kind, payload))
    }

    // Scheduling only: the sole production caller above retains every mesh
    // identity/session check. No transport disposition creates consensus trust.
    fn flush_with_v2(
        &mut self,
        mut send: impl FnMut(
            ValidatorId,
            FrameKind,
            Arc<[u8]>,
        ) -> Result<crate::consensus_mesh::MeshSendDispositionV0>,
    ) -> Result<(u64, u64)> {
        let mut attempted = BTreeSet::new();
        let mut queued_payload_bytes = 0u64;
        let mut queued_frames = 0u64;
        for broadcast in &mut self.pending {
            // A destination can advance only its oldest remaining frame in
            // this flush, including when that frame is backpressured.
            let peers = broadcast
                .remaining_peers
                .iter()
                .copied()
                .collect::<Vec<_>>();
            for peer in peers {
                if !attempted.insert(peer) {
                    continue;
                }
                match send(peer, broadcast.kind, Arc::clone(&broadcast.payload))? {
                    crate::consensus_mesh::MeshSendDispositionV0::Queued => {
                        broadcast.remaining_peers.remove(&peer);
                        queued_payload_bytes = queued_payload_bytes
                            .checked_add(
                                u64::try_from(broadcast.payload.len())
                                    .context("consensus payload size does not fit u64")?,
                            )
                            .context("queued payload-byte counter overflows")?;
                        queued_frames = queued_frames
                            .checked_add(1)
                            .context("queued frame counter overflows")?;
                    }
                    crate::consensus_mesh::MeshSendDispositionV0::Backpressured => {}
                }
            }
            if attempted.len() == self.peers.len() {
                break;
            }
        }
        // An excluded recipient can let a later row complete before an older
        // row. Retire all completed rows, retaining each shared payload once
        // until its last original destination has actually queued it.
        self.pending.retain(|broadcast| {
            if !broadcast.remaining_peers.is_empty() {
                return true;
            }
            self.pending_bytes = self
                .pending_bytes
                .checked_sub(broadcast.payload.len())
                .expect("outbox byte accounting is monotonic");
            false
        });
        Ok((queued_payload_bytes, queued_frames))
    }

    fn is_empty(&self) -> bool {
        self.pending.is_empty() && self.pending_bytes == 0
    }
}

#[cfg(test)]
#[path = "consensus_outbox_v2_tests.rs"]
mod consensus_outbox_v2_tests;
