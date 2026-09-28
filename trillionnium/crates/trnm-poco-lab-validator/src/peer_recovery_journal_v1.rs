//! Resident peer completion using the existing signed recovery-event grammar.
use super::*;
use crate::continuous_runtime::ContinuousRuntimeFactsV0;
use anyhow::{ensure, Context, Result};

/// Minted only after the original peer journal records all three exact phases.
/// It cannot be copied or assembled from a control response.
#[must_use]
pub(crate) struct PeerRecoveryStartJournalCommitV1 {
    path: PathBuf,
    head: (u64, [u8; 32]),
    local_validator: ValidatorId,
    parked_facts: ContinuousRuntimeFactsV0,
}

impl PeerRecoveryStartJournalCommitV1 {
    pub(crate) fn require_owner_v1(
        &self,
        journal: &RuntimeEventJournalV1,
        validator: ValidatorId,
        facts: ContinuousRuntimeFactsV0,
    ) -> Result<()> {
        journal.require_peer_named_head_v1()?;
        ensure!(
            journal.path == self.path
                && journal.context.validator_id == self.local_validator
                && validator == self.local_validator
                && facts == self.parked_facts
                && journal.last_event_facts() == Some(self.head)
                && journal.restart_phase_v1() == RuntimeRestartPhaseV1::Process1PeerCompleted,
            "peer recovery commit differs from its live owner/journal"
        );
        Ok(())
    }
}

impl RuntimeEventJournalV1 {
    fn require_peer_named_head_v1(&self) -> Result<()> {
        ensure!(
            !self.fail_stopped && self.process_instance == 1,
            "peer recovery requires the original live process-1 journal"
        );
        let file = self.reopen_exact_named_journal_v1()?;
        let events = read_exact_events(&file)?;
        let recovered = validate_event_chain(&events, &self.context)?;
        ensure!(
            recovered.process_instance == self.process_instance
                && recovered.next_sequence == self.next_sequence
                && recovered.previous_event_sha256 == self.previous_event_sha256
                && recovered.last_monotonic_ns == self.last_monotonic_ns
                && recovered.state == self.state,
            "peer recovery named journal no longer equals the held owner"
        );
        Ok(())
    }

    fn require_peer_ack_head_v1(
        &self,
        owner: &DurablyAcknowledgedRestartParkedBarrierV1,
    ) -> Result<()> {
        self.require_peer_named_head_v1()?;
        owner.revalidate_fresh_v1()?;
        let stored = owner.stored_cut_park_v1();
        let RuntimeRestartJournalStateV1::ParkedAcked(facts) = self.state.restart else {
            anyhow::bail!("peer recovery requires the exact ParkedAck journal head");
        };
        ensure!(
            self.restart_phase_v1() == RuntimeRestartPhaseV1::Process1PeerParkedAcked
                && facts.parked.cut_park.preparation.role_v1() == RestartParkRoleV1::Peer
                && self.context.validator_id == stored.local_validator_v1()
                && self.context.config_sha256 == stored.local_config_sha256_v1()
                && self.context.validator_set == *stored.validator_set_v1()
                && owner.local_statement_v1().role() == RestartParkRoleV1::Peer
                && facts.subject.ack_certificate_sha256 == owner.ack_artifact_sha256_v1()
                && facts.subject.local_ack_statement_sha256
                    == owner.local_statement_v1().statement_sha256()
                && facts.subject.ack_admission_set_sha256 == owner.ack_admission_set_sha256_v1()
                && facts.subject.cut_artifact_sha256 == stored.cut_artifact_sha256_v1()
                && facts.subject.park_artifact_sha256 == stored.park_artifact_sha256_v1()
                && facts.parked.cut_park.subject.body_sha256 == stored.body_v1().digest()
                && facts.parked.cut_park.subject.admission_set_sha256
                    == stored.admission_set_sha256_v1()
                && facts.parked.subject.local_park_statement_sha256
                    == stored.local_park_statement_sha256_v1()
                && self.state.fleet_start_certificate_sha256
                    == Some(stored.body_v1().fleet_start_certificate_sha256()),
            "peer ParkedAck owner differs from its original journal"
        );
        Ok(())
    }

    pub(crate) fn record_peer_recovery_start_v1(
        &mut self,
        owner: &DurablyAcknowledgedRestartParkedBarrierV1,
        zero: &StoredRecoveryZeroDeltaCutV1,
        start: &StoredRecoveryStartCertificateV1,
    ) -> Result<PeerRecoveryStartJournalCommitV1> {
        self.require_peer_ack_head_v1(owner)?;
        require_peer_certificate_join_v1(owner, zero, start)?;
        let context = zero.context_v1();
        let count = u64::try_from(start.ready_set_v1().statements().len())?;
        self.append_raw(
            "recovery_zero_delta",
            &RecoveryZeroDeltaSubjectV1 {
                zero_delta_artifact_sha256: zero.artifact_sha256_v1(),
                recovery_context_sha256: context.digest(),
            }
            .encode(),
            self.state.finalized_height,
            self.current_monotonic_ns_v1(),
        )?;
        self.append_raw(
            "recovery_ready",
            &RecoveryReadySubjectV1 {
                ready_set_artifact_sha256: start.ready_set_artifact_sha256_v1(),
                recovery_context_sha256: context.digest(),
            }
            .encode(),
            count,
            self.current_monotonic_ns_v1(),
        )?;
        self.append_raw(
            "recovery_start",
            &RecoveryStartSubjectV1 {
                start_certificate_artifact_sha256: start.artifact_sha256_v1(),
                ready_set_artifact_sha256: start.ready_set_artifact_sha256_v1(),
                recovery_context_sha256: context.digest(),
            }
            .encode(),
            count,
            self.current_monotonic_ns_v1(),
        )?;
        require_peer_certificate_join_v1(owner, zero, start)?;
        let result = PeerRecoveryStartJournalCommitV1 {
            path: self.path.clone(),
            head: self
                .last_event_facts()
                .context("peer recovery journal head missing")?,
            local_validator: self.context.validator_id,
            parked_facts: owner.parked_facts_v1(),
        };
        result.require_owner_v1(self, self.context.validator_id, owner.parked_facts_v1())?;
        Ok(result)
    }
}

fn require_peer_certificate_join_v1(
    owner: &DurablyAcknowledgedRestartParkedBarrierV1,
    zero: &StoredRecoveryZeroDeltaCutV1,
    start: &StoredRecoveryStartCertificateV1,
) -> Result<()> {
    owner.revalidate_fresh_v1()?;
    let stored = owner.stored_cut_park_v1();
    let set = stored.validator_set_v1();
    zero.revalidate_fresh_v1(set)?;
    start.revalidate_fresh_v1(set)?;
    let context = zero.context_v1();
    let f = context.fields();
    let body = stored.body_v1();
    let shared = body.shared_cut_v1();
    let facts = owner.parked_facts_v1();
    ensure!(
        start.context_v1() == context
            && context.mode() == trnm_consensus_types::RecoveryModeV1::ZeroDelta
            && f.process_instance == 2
            && f.target_validator == body.target_validator()
            && f.target_validator != stored.local_validator_v1()
            && f.validator_set_id == set.id()
            && f.validator_set_artifact_sha256 == body.validator_set_sha256()
            && f.campaign_context_sha256 == body.campaign().digest()
            && f.fleet_start_certificate_sha256 == body.fleet_start_certificate_sha256()
            && f.restart_cut_artifact_sha256 == stored.cut_artifact_sha256_v1()
            && f.restart_park_artifact_sha256 == stored.park_artifact_sha256_v1()
            && f.restart_parked_ack_artifact_sha256 == owner.ack_artifact_sha256_v1()
            && f.restart_parked_ack_admission_set_sha256 == owner.ack_admission_set_sha256_v1()
            && f.caught_up_cut_artifact_sha256 == zero.artifact_sha256_v1()
            && f.restart_cut_epoch == shared.epoch()
            && f.restart_cut_height == shared.finalized_height()
            && f.restart_cut_block_id == shared.finalized_block_id()
            && f.restart_cut_state_root == shared.application_state_root()
            && f.restart_cut_chain_root == shared.finalized_chain_root()
            && f.terminal_epoch == shared.epoch()
            && f.terminal_height == shared.finalized_height()
            && f.terminal_block_id == shared.finalized_block_id()
            && f.terminal_state_root == shared.application_state_root()
            && f.terminal_chain_root == shared.finalized_chain_root()
            && facts.finalized_height_v0() == shared.finalized_height().get()
            && facts.application_applied_height_v0() == shared.application_height().get()
            && facts.finalized_block_id_v0() == shared.finalized_block_id()
            && facts.application_applied_block_id_v0() == shared.application_block_id()
            && facts.application_state_root_v0() == shared.application_state_root()
            && facts.finalized_chain_root_v0() == shared.finalized_chain_root(),
        "signed peer recovery context differs from its exact retained parked cut"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn resident_peer_named_journal_rejects_same_inode_tamper_without_mutation() {
        let (temporary, context, key) = crate::process_event::tests::fixture();
        let path = temporary.path().join("peer-journal.jsonl");
        let journal = RuntimeEventJournalV1::start_with_context(&path, context, key).unwrap();
        journal.require_peer_named_head_v1().unwrap();
        let head = journal.last_event_facts();
        let corrupt = b"not an authenticated runtime event\n";
        std::fs::write(&path, corrupt).unwrap();
        assert!(journal.require_peer_named_head_v1().is_err());
        assert_eq!(std::fs::read(&path).unwrap(), corrupt);
        assert_eq!(journal.last_event_facts(), head);
    }

    #[test]
    fn resident_peer_named_journal_rejects_equal_bytes_at_replaced_path() {
        let (temporary, context, key) = crate::process_event::tests::fixture();
        let path = temporary.path().join("peer-journal.jsonl");
        let journal = RuntimeEventJournalV1::start_with_context(&path, context, key).unwrap();
        journal.require_peer_named_head_v1().unwrap();
        let head = journal.last_event_facts();
        let before = std::fs::read(&path).unwrap();
        let retained = temporary.path().join("retained-original.jsonl");
        std::fs::rename(&path, &retained).unwrap();
        std::fs::write(&path, &before).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(journal.require_peer_named_head_v1().is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(std::fs::read(&retained).unwrap(), before);
        assert_eq!(journal.last_event_facts(), head);
    }
}
