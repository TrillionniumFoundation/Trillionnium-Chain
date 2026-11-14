//! Narrow recovery of one original authenticated pending Submit. The ordinary
//! begin_authenticated_request ready() gate remains unchanged for all requests.
use super::*;

impl Node {
    /// The ingress caller has already verified the original signature, key,
    /// session and canonical request, and observed ready()'s pending-intent
    /// refusal. This cannot reserve another nonce or authorize another packet.
    pub(crate) fn begin_authenticated_pending_activation(
        &mut self,
        frame: AuthenticatedPeerFrameV0,
        payload: &[u8],
        packet: &Packet,
        observed_now: u64,
        progress: &mut dyn FnMut() -> Result<()>,
    ) -> Result<AuthenticatedReplayDecision> {
        progress()?;
        self.namespace()?;
        self.storage_context()?;
        ensure(
            !self.public_service_epoch_unknown,
            "OWNER_PUBLIC_SERVICE_UNCLEAN_EPOCH",
        )?;
        let before = self.admission_state_epoch()?;
        let session = frame.session();
        ensure(
            session.chain_id().bytes() == self.settings.genesis()
                && session.protocol_digest().bytes() == self.settings.parameters()
                && session.profile_digest().bytes() == crate::authenticated_profile_digest()
                && session.generation() <= i64::MAX as u64
                && frame.replay_nonce() <= i64::MAX as u64,
            "AUTH_REPLAY_CONTEXT",
        )?;
        let state = self
            .authenticated_replay_state(session)?
            .ok_or("REORG_IN_PROGRESS")?;
        ensure(state.pending() == Some(frame), "REORG_IN_PROGRESS")?;
        let mut admission =
            CandidateP2pAdmissionV0::recover_verified(state, &mut ReplayRecovery { db: &self.db })
                .map_err(|error| Error::local_replay_source("AUTH_RECOVERY", error))?;
        let verified = admission
            .verify_frame(frame, &mut ExactFrameSource { payload })
            .map_err(|error| Error::peer_frame_source("AUTH_FRAME", error))?;
        admission
            .admit_verified(verified)
            .map_err(|error| Error::peer_admission_source("AUTH_REPLAY", error))?;
        // The existing hex_packet ingress accepts only lowercase canonical hex.
        // Bind these exact request bytes to the packet, not just its claimed ID.
        let canonical = serde_json::to_vec(&crate::ingress::Request::Submit {
            packet: hex::encode(packet.encode_for_settings(&self.settings)?),
        })?;
        ensure(canonical == payload, "AUTH_CONFLICTING_REPLAY")?;
        ensure(
            self.pending_exact_activation_replay(packet, observed_now, progress)?
                .is_some(),
            "REORG_IN_PROGRESS",
        )?;
        progress()?;
        ensure(self.admission_state_epoch()? == before, "STORAGE_CONTEXT")
            .map_err(Error::local_integrity)?;
        // No writes: keep the same pending frame until the original activation
        // and independently recovered finish_authenticated_request succeed.
        Ok(AuthenticatedReplayDecision::Execute)
    }

    #[cfg(test)]
    pub(crate) fn cancel_next_activation_intent_for_test(&mut self) {
        self.cancel_next_activation_intent = true;
    }
}
