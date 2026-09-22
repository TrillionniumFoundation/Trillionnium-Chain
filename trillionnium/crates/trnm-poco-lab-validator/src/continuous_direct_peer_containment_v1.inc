/// Only failures of the initial pure wire decoder can enter this closed set.
/// Collector, Core and physical-owner failures never become peer rejections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectPeerRejectionReasonV1 {
    TooLarge,
    Truncated,
    Malformed,
    InvalidStatement,
    AuthorMismatch,
    UnsupportedKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectPeerRejectionFactsV1 {
    remote: ValidatorId,
    kind: crate::frame::FrameKind,
    payload_sha256: [u8; 32],
    reason: DirectPeerRejectionReasonV1,
    dropped_frames: u64,
}

impl DirectPeerRejectionFactsV1 {
    pub(crate) fn diagnostic_v1(self) -> String {
        format!(
            "remote={} kind={:?} reason={:?} payload_sha256={}",
            hex::encode(self.remote.as_bytes()),
            self.kind,
            self.reason,
            hex::encode(self.payload_sha256),
        )
    }
}

pub(crate) enum DirectPeerFrameOutcomeV1 {
    Admitted(Option<RoutedConsensusActionV0>),
    Rejected(DirectPeerRejectionFactsV1),
    Quarantined,
}

impl ContinuousConsensusWindowsV0 {
    fn admit_contained_direct_frame_v1(
        &mut self,
        frame: &AuthenticatedFrame,
    ) -> Result<DirectPeerFrameOutcomeV1> {
        // These facts belong to the authenticated mesh/local owner rather
        // than the payload. Preserve fatal failure on broken local joins.
        ensure!(frame.session != [0; 32], "zero direct mesh session");
        ensure!(
            self.validator_set.validator(frame.sender).is_some(),
            "direct mesh sender is outside the pinned local validator set"
        );
        ensure!(
            self.consensus_parameters.hash() == self.validator_set.consensus_parameters_hash(),
            "direct decoder local parameter context differs from the pinned set"
        );
        if let Some(facts) = self.direct_peer_rejections.get_mut(&frame.sender) {
            facts.dropped_frames = facts
                .dropped_frames
                .checked_add(1)
                .context("direct peer rejection accounting overflows")?;
            return Ok(DirectPeerFrameOutcomeV1::Quarantined);
        }
        let decoded = match decode_authenticated_consensus_frame_v0(
            frame,
            &self.validator_set,
            &self.consensus_parameters,
        ) {
            Ok(decoded) => decoded,
            Err(error) => {
                use crate::wire::ConsensusWireError;
                let reason = match error {
                    ConsensusIngressErrorV0::Wire(ConsensusWireError::TooLarge) => {
                        DirectPeerRejectionReasonV1::TooLarge
                    }
                    ConsensusIngressErrorV0::Wire(ConsensusWireError::Truncated(_)) => {
                        DirectPeerRejectionReasonV1::Truncated
                    }
                    ConsensusIngressErrorV0::Wire(ConsensusWireError::Malformed(_)) => {
                        DirectPeerRejectionReasonV1::Malformed
                    }
                    ConsensusIngressErrorV0::Wire(ConsensusWireError::Invalid(_)) => {
                        DirectPeerRejectionReasonV1::InvalidStatement
                    }
                    ConsensusIngressErrorV0::SenderStatementMismatch => {
                        DirectPeerRejectionReasonV1::AuthorMismatch
                    }
                    ConsensusIngressErrorV0::UnsupportedFrameKind => {
                        DirectPeerRejectionReasonV1::UnsupportedKind
                    }
                    // A future decoder error is fatal until its producer
                    // semantics are explicitly reviewed; never catch anyhow.
                    other => return Err(anyhow::Error::new(other).context("direct decoder")),
                };
                ensure!(
                    self.direct_peer_rejections.len() < self.validator_set.validators().len(),
                    "bounded direct peer rejection inventory exhausted"
                );
                let facts = DirectPeerRejectionFactsV1 {
                    remote: frame.sender,
                    kind: frame.kind,
                    payload_sha256: Sha256::digest(&frame.payload).into(),
                    reason,
                    dropped_frames: 1,
                };
                self.direct_peer_rejections.insert(frame.sender, facts);
                return Ok(DirectPeerFrameOutcomeV1::Rejected(facts));
            }
        };
        // This call includes collector mutation/aggregation. Its errors must
        // retain their original fatal classification and violation counters.
        self.admit_predecoded_direct_frame_v1(frame, decoded)
            .map(DirectPeerFrameOutcomeV1::Admitted)
    }
}

impl ContinuousValidatorAuthorityV0 {
    // All direct, relay and originated-admission surfaces share this fence.
    // Signed phases remain live; only an actually consumed owner is refused.
    // Check before pure decode as well as any collector/replay mutation.
    fn require_live_consensus_admission_v1(&self) -> Result<()> {
        ensure!(
            self.phase.is_some(),
            "consensus admission owner is fail-closed"
        );
        Ok(())
    }

    pub(crate) fn admit_contained_direct_frame_v1(
        &mut self,
        frame: &AuthenticatedFrame,
    ) -> Result<DirectPeerFrameOutcomeV1> {
        self.require_live_consensus_admission_v1()?;
        let result = self
            .consensus_windows
            .admit_contained_direct_frame_v1(frame);
        if let Err(error) = &result {
            self.protocol_violations.record_anyhow_v0(error)?;
        }
        result
    }
}
