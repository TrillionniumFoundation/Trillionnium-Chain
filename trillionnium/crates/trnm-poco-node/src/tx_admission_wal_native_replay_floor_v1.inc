/// A deterministic description of the only native replay-floor policy this
/// candidate accepts. Callers cannot substitute a different retention rule.
const NATIVE_REPLAY_FLOOR_RETENTION_POLICY_DOMAIN_V1: &[u8] =
    b"trnm.poco-node.native-replay-floor-retention.v1";

pub fn native_replay_floor_retention_policy_digest_v1() -> [u8; 32] {
    let schema = u64::try_from(SCHEMA_VERSION_V0)
        .expect("the frozen WAL schema version is nonnegative")
        .to_be_bytes();
    let max_batch = u64::try_from(MAX_TOMBSTONE_BATCH_V1)
        .expect("the frozen tombstone batch bound fits u64")
        .to_be_bytes();
    framed_digest_v1(
        NATIVE_REPLAY_FLOOR_RETENTION_POLICY_DOMAIN_V1,
        &[
            schema.as_slice(),
            max_batch.as_slice(),
            b"application-signer-contiguous-nonce-prefix-from-one",
            b"tombstone-terminal-height-at-or-below-finalized-height",
            b"strict-ed25519-three-chain-finality-proof",
        ],
    )
}

struct DurableNativeReplayFloorVerifierV1<'a> {
    application: &'a DurableNativeApplicationV0,
    fact: &'a trnm_native_execution_v0::VerifiedNativeSignerReplayFloorV1,
    namespace: [u8; 32],
    canonical_signer: [u8; 32],
    application_signer_id: &'a str,
    retention_policy_digest: [u8; 32],
}

impl fmt::Debug for DurableNativeReplayFloorVerifierV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableNativeReplayFloorVerifierV1")
            .field("namespace", &self.namespace)
            .field("canonical_signer", &self.canonical_signer)
            .field("application_signer_id", &self.application_signer_id)
            .finish_non_exhaustive()
    }
}

impl replay_floor_verifier_seal_v1::Sealed for DurableNativeReplayFloorVerifierV1<'_> {}

impl TxAdmissionReplayFloorVerifierV1 for DurableNativeReplayFloorVerifierV1<'_> {
    fn verify_replay_floor_v1(
        &self,
        evidence: &TxAdmissionReplayFloorEvidenceV1,
    ) -> Result<(), TxAdmissionWalErrorV0> {
        if !self.fact.belongs_to_application_v1(self.application) {
            return Err(TxAdmissionWalErrorV0::CommitReadbackUnavailable);
        }
        if self.fact.application_signer_id_v1() != self.application_signer_id
            || evidence.namespace() != self.namespace
            || evidence.signer_id().as_bytes() != self.canonical_signer
            || evidence.reject_nonce_through() != self.fact.reject_nonce_through_v1()
            || evidence.finalized_height().get() != self.fact.finalized_height_v1()
            || *evidence.state_root().as_bytes() != self.fact.state_root_v1()
            || evidence.finality_proof_digest() != self.fact.finality_proof_digest_v1()
            || evidence.retention_policy_digest() != self.retention_policy_digest
        {
            return Err(TxAdmissionWalErrorV0::CommitReceiptMismatch);
        }
        Ok(())
    }
}

impl NodeOwnedTxAdmissionBoundaryV0 {
    /// Purge compact replay tombstones only after joining the exact canonical
    /// signer identity to a strictly finalized native-application nonce prefix.
    ///
    /// No caller-supplied height, state root, proof digest, or retention-policy
    /// digest crosses this boundary. The private verified floor is consumed
    /// before the method returns and no application/finality authority escapes.
    pub fn purge_tombstones_with_native_replay_floor_v1(
        &mut self,
        transaction: &BuiltCanonicalTxV0,
        reject_nonce_through: u64,
        application: &DurableNativeApplicationV0,
        finality_proof: &FinalityProofV0,
        authenticated_parent_timestamp_ms: u64,
        max_rows: usize,
    ) -> Result<TxAdmissionTombstoneGcResultV1, AdmissionReject> {
        if self.allow_handed_off_recovery {
            return Err(AdmissionReject::InconsistentState);
        }
        let canonical_signer = self
            .signer_resolver
            .as_ref()
            .ok_or(AdmissionReject::SignerIdentityUnavailable)?
            .resolve_canonical_signer_id_v0(transaction)?;
        let application_signer_id = transaction.envelope().signer_id.as_str();
        let finalized_height = trnm_native_application::HeightV0::new(
            finality_proof.finalized_block().header().height().get(),
        );
        let fact = application
            .verify_finalized_signer_replay_floor_v1(
                application_signer_id,
                reject_nonce_through,
                finalized_height,
                finality_proof,
                authenticated_parent_timestamp_ms,
            )
            .map_err(|_| AdmissionReject::InconsistentState)?;
        let retention_policy_digest = native_replay_floor_retention_policy_digest_v1();
        let evidence = TxAdmissionReplayFloorEvidenceV1::new(
            self.authority.namespace,
            canonical_signer,
            fact.reject_nonce_through_v1(),
            Height::new(fact.finalized_height_v1()),
            StateRoot::new(fact.state_root_v1()),
            fact.finality_proof_digest_v1(),
            retention_policy_digest,
        )
        .map_err(map_reject_v0)?;
        let verifier = DurableNativeReplayFloorVerifierV1 {
            application,
            fact: &fact,
            namespace: self.authority.namespace,
            canonical_signer: canonical_signer.as_bytes(),
            application_signer_id,
            retention_policy_digest,
        };
        let floor = evidence.verify_with(&verifier).map_err(map_reject_v0)?;
        self.authority
            .purge_tombstones_with_replay_floor_v1(&floor, max_rows)
            .map_err(map_reject_v0)
    }
}
