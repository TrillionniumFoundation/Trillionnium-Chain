impl<W: ExternalMonotonicWatermarkV0> PocoNodeLabTerminalOwnerV0<W> {
    /// Reaudits the exact consumed cut. Failure permanently fences this owner;
    /// success returns only its original inert facts, never a live capability.
    pub fn confirm_terminal_cut_v1(
        &mut self,
    ) -> Result<&PocoNodeLabTerminalCutV0, PocoNodeLabAuthorityErrorV0> {
        if self.readback_fenced {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "terminal owner readback is fenced",
            ));
        }
        self.readback_fenced = true;
        let guard = CrossStoreLockGuardV0::acquire_exclusive_for_paths_v0(
            self._application.path(),
            &self.proposal_journal.store_path,
        )
        .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
        // External watermark callbacks cannot establish a replacement local
        // trust cut: audit the original local namespaces on both sides.
        self.confirm_local_terminal_cut_v1()?;
        let signer = self
            ._signer_journal
            .confirm_node_checkpoint_head_exact_v0()
            .map_err(PocoNodeLabAuthorityErrorV0::Signer)?;
        let inventory = clean_signer_lifetime_inventory_v1(&signer).ok_or(
            PocoNodeLabAuthorityErrorV0::InvalidBootstrap("terminal signer lifecycle changed"),
        )?;
        let expected = &self.facts;
        if !signer.belongs_to_operational_journal_at_path_v0(
            &self._signer_journal,
            self._signer_journal.path(),
        ) || signer.pending_intent().is_some()
            || signer.journal_id() != expected.signer_journal_id
            || signer.profile_checksum() != expected.signer_profile_checksum
            || signer.exact_watermark() != expected.signer_exact_watermark
            || signer.capacity().intent_count() != expected.signer_intent_count
            || signer.capacity().event_count() != expected.signer_event_count
            || inventory.durable_vote_intent_count() != expected.signer_durable_vote_intent_count
            || inventory.durable_timeout_intent_count()
                != expected.signer_durable_timeout_intent_count
            || inventory.signed_vote_intent_count() != expected.signer_signed_vote_intent_count
            || inventory.signed_timeout_intent_count()
                != expected.signer_signed_timeout_intent_count
            || inventory.inventory_digest() != expected.signer_inventory_digest
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "terminal signer cut changed",
            ));
        }
        self.confirm_local_terminal_cut_v1()?;
        guard
            .validate_identity_v0()
            .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
        self.readback_fenced = false;
        Ok(&self.facts)
    }

    fn confirm_local_terminal_cut_v1(&mut self) -> Result<(), PocoNodeLabAuthorityErrorV0> {
        let expected = &self.facts;
        let safety = self
            ._safety_store
            .confirm_node_checkpoint_head_exact_v0(self._core.safety_state())
            .map_err(PocoNodeLabAuthorityErrorV0::Safety)?;
        if !safety.belongs_to_store_at_path_v0(&self._safety_store, self._safety_store.path())
            || safety.journal_id_v0() != expected.safety_journal_id
            || safety.revision_v0() != expected.safety_revision
            || safety.state_record_checksum_v0() != expected.safety_state_record_checksum
            || safety.chain_checksum_v0() != expected.safety_record_chain_checksum
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "terminal Safety cut changed",
            ));
        }
        let checkpoint = self
            ._checkpoint_store
            .load(expected.checkpoint.scope())
            .map_err(PocoNodeLabAuthorityErrorV0::Checkpoint)?;
        if checkpoint != Some(expected.checkpoint) {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "terminal independent checkpoint changed",
            ));
        }
        let native = self
            ._application
            .confirm_ordinary_terminal_inventory_v1()
            .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
        let head = native.head_v1();
        if !native.belongs_to_application_at_path_v1(&self._application, self._application.path())
            || head.block_id().as_bytes() != expected.finalized_block_id.as_bytes()
            || head.height().get() != expected.finalized_height
            || head.state_root().as_bytes() != &expected.application_state_root
            || head.commit_id().as_bytes() != &expected.application_commit_id
            || application_head_checksum_v0(
                b"trnm.poco-node.lab-finalization.checkpoint-head.v0",
                head,
            ) != expected.application_committed_head_row_checksum
            || native.durable_sequence_v1() != expected.application_durable_sequence
            || native.prepared_count_v1() != expected.prepared_application_record_count
            || self._application.config_v0().store_id() != expected.application_store_id
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "terminal native inventory changed",
            ));
        }
        let store = &mut self._proposal_validation_store;
        let audit = store
            .confirm_terminal_k_audit_v0()
            .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
        if !audit.belongs_to_store_at_path_v0(store, &self.proposal_journal.store_path)
            || audit.scope_v0() != self.proposal_journal.scope
            || audit.scope_v0().as_bytes() != &expected.proposal_validation_scope
            || audit.store_id_v0() != expected.proposal_validation_store_id
            || audit.owner_id_v0() != self.proposal_journal.owner_id
            || audit.owner_id_v0().as_bytes() != &expected.proposal_validation_owner_id
            || audit.store_sequence_v0() != expected.proposal_validation_durable_sequence
            || audit.terminal_row_count_v0() != expected.proposal_validation_terminal_row_count
            || audit.maximum_terminal_height_v0() != expected.submitted_height
            || u64::try_from(self.retained_executions.len()).ok()
                != Some(expected.prepared_application_record_count)
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "terminal K inventory changed",
            ));
        }
        for (block, retained) in &self.retained_executions {
            let owner = reconfirm_terminal_retained_execution_v0(
                *block,
                retained,
                &self._application,
                store,
                expected.proposal_validation_durable_sequence,
            )?;
            if owner != self.proposal_journal.owner_id {
                return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                    "terminal retained P/K owner changed",
                ));
            }
        }
        if store
            .durable_sequence_v0()
            .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?
            != expected.proposal_validation_durable_sequence
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "terminal K sequence changed during readback",
            ));
        }
        Ok(())
    }
}
