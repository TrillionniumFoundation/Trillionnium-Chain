#![forbid(unsafe_code)]
//! Conformance probes for production adapters.
//!
//! This crate is a testkit and is forbidden from the production dependency
//! closure.  It models durable crash points and verifies the contracts exposed
//! by the v0 protocol cores without claiming physical power-loss, real HSM, or
//! multi-host evidence.

pub const PRODUCTION_ADAPTER_CONFORMANCE_VERSION_V0: u16 = 0;

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};
    use std::{
        collections::BTreeMap,
        convert::Infallible,
        error::Error,
        fmt,
        sync::{Arc, Mutex},
    };
    use trnm_control_plane_v0::{
        ActionDecisionV0, ControlPlaneErrorV0, Digest32V0 as ControlDigest,
        ForbiddenAuthorityActionV0, LocalPlanGuardV0, OptimizationPlanV1,
        PlanActionV0, PlanSignatureVerifierV0,
    };
    use trnm_migration_v0::{
        ExportRowV0, MigrationErrorV0,
    };
    use trnm_node_boundary_v0::{
        AuthorityCommandV0, AuthorityCoordinatorV0, AuthorityReceiptV0, AuthorityStageV0,
        BoundaryErrorV0, Digest32V0 as NodeDigest, NodeIdentityV0, OperationBindingV0,
        RecoveryDispositionV0,
    };
    use trnm_state_sync_v0::{
        chunk_merkle_root_v0, verify_trust_path_v0, CheckpointLinkV0,
        CheckpointProofVerifierV0, Digest32V0 as SyncDigest, InstallReceiptV0,
        NonDestructiveInstallTargetV0, SnapshotChunkV0, SnapshotManifestV0,
        StagingIdentityV0, StateRootRecomputerV0, StateSyncSessionV0,
        WeakSubjectivityAnchorV0,
    };
    use trnm_tx_lifecycle_v0::{
        AuthorizationVerifierV0, BroadcastReceiptV0, Digest32V0 as TxDigest,
        FinalityWitnessV0, OrderedPositionV0, ProposalHandoffV0, ResourceLimitsV0,
        TxIntentV0, TxLifecycleErrorV0, TxLifecycleV0,
    };

    fn node_d(byte: u8) -> NodeDigest {
        NodeDigest([byte; 32])
    }

    fn sync_d(byte: u8) -> SyncDigest {
        SyncDigest([byte; 32])
    }

    fn tx_d(byte: u8) -> TxDigest {
        TxDigest([byte; 32])
    }

    fn control_d(byte: u8) -> ControlDigest {
        ControlDigest([byte; 32])
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum DurableCoordinatorError {
        Boundary(BoundaryErrorV0),
        Poisoned,
        CrashAfterPersist,
    }

    impl fmt::Display for DurableCoordinatorError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Boundary(error) => write!(f, "boundary: {error}"),
                Self::Poisoned => f.write_str("durable journal mutex poisoned"),
                Self::CrashAfterPersist => f.write_str("injected crash after durable persist"),
            }
        }
    }

    impl Error for DurableCoordinatorError {}

    #[derive(Default)]
    struct DurableJournal {
        current: Option<AuthorityReceiptV0>,
        crash_after_next_persist: bool,
    }

    #[derive(Clone)]
    struct DurableCoordinator {
        identity: NodeIdentityV0,
        journal: Arc<Mutex<DurableJournal>>,
    }

    impl DurableCoordinator {
        fn new(identity: NodeIdentityV0) -> Self {
            Self {
                identity,
                journal: Arc::new(Mutex::new(DurableJournal::default())),
            }
        }

        fn restart(&self) -> Self {
            self.clone()
        }

        fn inject_crash_after_persist(&self) {
            self.journal.lock().unwrap().crash_after_next_persist = true;
        }

        fn record_digest(
            &self,
            binding: OperationBindingV0,
            stage: AuthorityStageV0,
            sequence: u64,
            facts: NodeDigest,
            previous: NodeDigest,
        ) -> NodeDigest {
            NodeDigest::hash(
                b"trnm.adapter-conformance.authority-record.v0",
                &[
                    &self.identity.digest().0,
                    &binding.operation_id.0,
                    &[stage as u8],
                    &sequence.to_be_bytes(),
                    &facts.0,
                    &previous.0,
                ],
            )
        }
    }

    impl AuthorityCoordinatorV0 for DurableCoordinator {
        type Error = DurableCoordinatorError;

        fn identity(&self) -> NodeIdentityV0 {
            self.identity
        }

        fn recover(&mut self) -> Result<RecoveryDispositionV0, Self::Error> {
            let journal = self.journal.lock().map_err(|_| DurableCoordinatorError::Poisoned)?;
            Ok(match journal.current {
                None => RecoveryDispositionV0::Clean,
                Some(receipt) => RecoveryDispositionV0::Resume {
                    binding: receipt.binding,
                    durable_stage: receipt.durable_stage,
                    durable_sequence: receipt.durable_sequence,
                },
            })
        }

        fn apply(
            &mut self,
            command: AuthorityCommandV0,
        ) -> Result<AuthorityReceiptV0, Self::Error> {
            let mut journal = self.journal.lock().map_err(|_| DurableCoordinatorError::Poisoned)?;
            let (binding, target_stage, facts) = match command {
                AuthorityCommandV0::Begin {
                    binding,
                    ingress_digest,
                } => {
                    if let Some(existing) = journal.current {
                        if existing.binding == binding
                            && existing.durable_stage == AuthorityStageV0::Prepared
                        {
                            return Ok(existing);
                        }
                        return Err(DurableCoordinatorError::Boundary(
                            BoundaryErrorV0::InvalidStageTransition,
                        ));
                    }
                    (binding, AuthorityStageV0::Prepared, ingress_digest)
                }
                AuthorityCommandV0::Advance {
                    binding,
                    expected_stage,
                    next_stage,
                    facts_digest,
                } => {
                    let existing = journal.current.ok_or(DurableCoordinatorError::Boundary(
                        BoundaryErrorV0::InvalidStageTransition,
                    ))?;
                    if existing.binding != binding {
                        return Err(DurableCoordinatorError::Boundary(
                            BoundaryErrorV0::OperationBindingMismatch,
                        ));
                    }
                    if existing.durable_stage == next_stage
                        && expected_stage.successor() == Some(next_stage)
                    {
                        return Ok(existing);
                    }
                    if existing.durable_stage != expected_stage
                        || expected_stage.successor() != Some(next_stage)
                    {
                        return Err(DurableCoordinatorError::Boundary(
                            BoundaryErrorV0::InvalidStageTransition,
                        ));
                    }
                    (binding, next_stage, facts_digest)
                }
            };
            let (sequence, previous) = journal.current.map_or(
                (0, NodeDigest([0; 32])),
                |receipt| {
                    (
                        receipt
                            .durable_sequence
                            .checked_add(1)
                            .expect("test journal sequence must remain bounded"),
                        receipt.record_digest,
                    )
                },
            );
            let receipt = AuthorityReceiptV0 {
                binding,
                durable_stage: target_stage,
                durable_sequence: sequence,
                record_digest: self.record_digest(
                    binding,
                    target_stage,
                    sequence,
                    facts,
                    previous,
                ),
            };
            journal.current = Some(receipt);
            if journal.crash_after_next_persist {
                journal.crash_after_next_persist = false;
                return Err(DurableCoordinatorError::CrashAfterPersist);
            }
            Ok(receipt)
        }
    }

    fn node_identity() -> NodeIdentityV0 {
        NodeIdentityV0 {
            chain_id: node_d(1),
            validator_id: node_d(2),
            application_id: node_d(3),
            generation: 4,
        }
    }

    fn operation() -> OperationBindingV0 {
        OperationBindingV0::derive(
            node_identity(),
            10,
            11,
            node_d(12),
            node_d(13),
            node_d(14),
        )
    }

    #[test]
    fn durable_authority_recovers_crash_after_persist_without_double_advance() {
        let mut coordinator = DurableCoordinator::new(node_identity());
        let binding = operation();
        let prepared = coordinator
            .apply(AuthorityCommandV0::Begin {
                binding,
                ingress_digest: node_d(20),
            })
            .unwrap();
        assert_eq!(prepared.durable_sequence, 0);

        coordinator.inject_crash_after_persist();
        assert_eq!(
            coordinator
                .apply(AuthorityCommandV0::Advance {
                    binding,
                    expected_stage: AuthorityStageV0::Prepared,
                    next_stage: AuthorityStageV0::ApplicationSealed,
                    facts_digest: node_d(21),
                })
                .unwrap_err(),
            DurableCoordinatorError::CrashAfterPersist
        );

        let mut restarted = coordinator.restart();
        assert_eq!(
            restarted.recover().unwrap(),
            RecoveryDispositionV0::Resume {
                binding,
                durable_stage: AuthorityStageV0::ApplicationSealed,
                durable_sequence: 1,
            }
        );
        let replayed = restarted
            .apply(AuthorityCommandV0::Advance {
                binding,
                expected_stage: AuthorityStageV0::Prepared,
                next_stage: AuthorityStageV0::ApplicationSealed,
                facts_digest: node_d(21),
            })
            .unwrap();
        assert_eq!(replayed.durable_sequence, 1);
        assert_eq!(replayed.durable_stage, AuthorityStageV0::ApplicationSealed);
    }

    struct AcceptCheckpoint;
    impl CheckpointProofVerifierV0 for AcceptCheckpoint {
        type Error = Infallible;
        fn verify_link(&self, _link: &CheckpointLinkV0) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    struct CanonicalTestRoot;
    impl StateRootRecomputerV0 for CanonicalTestRoot {
        type Error = Infallible;
        fn recompute_state_root<'a, I>(
            &self,
            schema_digest: SyncDigest,
            ordered_chunks: I,
        ) -> Result<SyncDigest, Self::Error>
        where
            I: IntoIterator<Item = &'a [u8]>,
        {
            let mut h = Sha256::new();
            h.update(b"trnm.adapter-conformance.state-root.v0");
            h.update(schema_digest.0);
            for bytes in ordered_chunks {
                h.update((bytes.len() as u64).to_be_bytes());
                h.update(bytes);
            }
            Ok(SyncDigest(h.finalize().into()))
        }
    }

    fn sync_fixture() -> (StateSyncSessionV0, SyncDigest) {
        let anchor = WeakSubjectivityAnchorV0 {
            chain_id: sync_d(1),
            protocol_digest: sync_d(2),
            epoch: 3,
            height: 4,
            checkpoint_digest: sync_d(5),
            validator_set_digest: sync_d(6),
        };
        let bytes = [b"alpha".as_slice(), b"beta".as_slice()];
        let state_root = CanonicalTestRoot
            .recompute_state_root(sync_d(7), bytes)
            .unwrap();
        let mut link = CheckpointLinkV0 {
            chain_id: anchor.chain_id,
            protocol_digest: anchor.protocol_digest,
            epoch: anchor.epoch,
            height: anchor.height + 1,
            state_root,
            validator_set_digest: anchor.validator_set_digest,
            next_validator_set_digest: anchor.validator_set_digest,
            parent_checkpoint_digest: anchor.checkpoint_digest,
            finality_proof_digest: sync_d(8),
            checkpoint_digest: sync_d(0),
        };
        link.checkpoint_digest = link.canonical_digest();
        let trust = verify_trust_path_v0(&AcceptCheckpoint, anchor, &[link]).unwrap();
        let mut manifest = SnapshotManifestV0 {
            chain_id: anchor.chain_id,
            protocol_digest: anchor.protocol_digest,
            height: link.height,
            epoch: link.epoch,
            state_root,
            chunk_root: sync_d(0),
            chunk_count: 2,
            maximum_chunk_bytes: 1024,
            total_bytes: 9,
            schema_digest: sync_d(7),
            checkpoint_digest: link.checkpoint_digest,
            manifest_digest: sync_d(0),
        };
        let binding = manifest.chunk_binding_digest();
        let chunks: Vec<SnapshotChunkV0> = bytes
            .iter()
            .enumerate()
            .map(|(index, bytes)| SnapshotChunkV0 {
                manifest_digest: binding,
                index: index as u32,
                bytes: bytes.to_vec(),
                chunk_digest: SnapshotChunkV0::canonical_digest(binding, index as u32, bytes),
            })
            .collect();
        manifest.chunk_root = chunk_merkle_root_v0(
            &chunks.iter().map(|chunk| chunk.chunk_digest).collect::<Vec<_>>(),
        );
        manifest.manifest_digest = manifest.canonical_digest();
        let mut session = StateSyncSessionV0::new(trust, manifest).unwrap();
        for chunk in chunks {
            session.accept_chunk(chunk).unwrap();
        }
        (session, state_root)
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum InstallFailure {
        None,
        Begin,
        Write(u32),
        CommitBeforeSwap,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct InstallError;
    impl fmt::Display for InstallError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("injected atomic install failure")
        }
    }
    impl Error for InstallError {}

    struct AtomicTarget {
        current_root: SyncDigest,
        current_height: u64,
        next_generation: u64,
        staging: BTreeMap<u32, Vec<u8>>,
        failure: InstallFailure,
        aborts: u32,
    }

    impl AtomicTarget {
        fn new(current_root: SyncDigest, failure: InstallFailure) -> Self {
            Self {
                current_root,
                current_height: 1,
                next_generation: 2,
                staging: BTreeMap::new(),
                failure,
                aborts: 0,
            }
        }
    }

    impl NonDestructiveInstallTargetV0 for AtomicTarget {
        type Error = InstallError;

        fn begin_staging(
            &mut self,
            manifest: &SnapshotManifestV0,
        ) -> Result<StagingIdentityV0, Self::Error> {
            if self.failure == InstallFailure::Begin {
                return Err(InstallError);
            }
            self.staging.clear();
            Ok(StagingIdentityV0 {
                generation: self.next_generation,
                staging_digest: SyncDigest::hash(
                    b"trnm.adapter-conformance.staging.v0",
                    &[&manifest.manifest_digest.0, &self.next_generation.to_be_bytes()],
                ),
            })
        }

        fn write_chunk(
            &mut self,
            _staging: StagingIdentityV0,
            index: u32,
            bytes: &[u8],
        ) -> Result<(), Self::Error> {
            if self.failure == InstallFailure::Write(index) {
                return Err(InstallError);
            }
            self.staging.insert(index, bytes.to_vec());
            Ok(())
        }

        fn commit_staging_cas(
            &mut self,
            staging: StagingIdentityV0,
            expected_current_root: SyncDigest,
            manifest: &SnapshotManifestV0,
        ) -> Result<InstallReceiptV0, Self::Error> {
            if self.failure == InstallFailure::CommitBeforeSwap
                || self.current_root != expected_current_root
                || self.staging.len() != manifest.chunk_count as usize
            {
                return Err(InstallError);
            }
            let previous_root = self.current_root;
            self.current_root = manifest.state_root;
            self.current_height = manifest.height;
            self.next_generation = self.next_generation.saturating_add(1);
            Ok(InstallReceiptV0 {
                previous_root,
                installed_root: self.current_root,
                installed_height: self.current_height,
                generation: staging.generation,
                durable_receipt_digest: SyncDigest::hash(
                    b"trnm.adapter-conformance.install-receipt.v0",
                    &[
                        &previous_root.0,
                        &self.current_root.0,
                        &self.current_height.to_be_bytes(),
                        &staging.generation.to_be_bytes(),
                    ],
                ),
            })
        }

        fn abort_staging(&mut self, _staging: StagingIdentityV0) -> Result<(), Self::Error> {
            self.staging.clear();
            self.aborts = self.aborts.saturating_add(1);
            Ok(())
        }
    }

    #[test]
    fn every_pre_swap_install_failure_preserves_the_serving_root() {
        for failure in [
            InstallFailure::Begin,
            InstallFailure::Write(0),
            InstallFailure::Write(1),
            InstallFailure::CommitBeforeSwap,
        ] {
            let (session, _) = sync_fixture();
            let old_root = sync_d(90);
            let mut target = AtomicTarget::new(old_root, failure);
            assert!(session
                .install(&CanonicalTestRoot, &mut target, old_root)
                .is_err());
            assert_eq!(target.current_root, old_root);
        }
    }

    #[test]
    fn successful_atomic_install_switches_once_and_binds_receipt() {
        let (session, expected_root) = sync_fixture();
        let old_root = sync_d(90);
        let mut target = AtomicTarget::new(old_root, InstallFailure::None);
        let receipt = session
            .install(&CanonicalTestRoot, &mut target, old_root)
            .unwrap();
        assert_eq!(receipt.previous_root, old_root);
        assert_eq!(receipt.installed_root, expected_root);
        assert_eq!(target.current_root, expected_root);
        assert_eq!(target.aborts, 0);
    }

    struct AcceptTxAuthorization;
    impl AuthorizationVerifierV0 for AcceptTxAuthorization {
        type Error = Infallible;
        fn verify(
            &self,
            _sender: TxDigest,
            _signing_digest: TxDigest,
            _authorization: &[u8],
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    fn tx_intent() -> TxIntentV0 {
        TxIntentV0 {
            chain_id: tx_d(1),
            sender: tx_d(2),
            nonce: 3,
            fee_bid: 100,
            valid_until_height: 1000,
            resource_limits: ResourceLimitsV0 {
                max_compute: 1000,
                max_state_reads: 10,
                max_state_writes: 10,
                max_event_bytes: 1024,
            },
            payload: vec![4, 5, 6],
            authorization: vec![7; 64],
        }
    }

    #[test]
    fn transaction_effect_receipt_substitution_is_rejected() {
        let mut lifecycle = TxLifecycleV0::new(tx_d(1), AcceptTxAuthorization);
        let tx_id = lifecycle.admit(tx_intent(), 1).unwrap();
        lifecycle.persist_wal(tx_id, 1).unwrap();
        lifecycle
            .handoff_proposal(
                tx_id,
                ProposalHandoffV0 {
                    proposal_id: tx_d(8),
                    proposal_index: 0,
                },
            )
            .unwrap();
        let position = OrderedPositionV0 {
            block_id: tx_d(9),
            height: 10,
            transaction_index: 0,
        };
        lifecycle.mark_ordered(tx_id, position).unwrap();
        let intent = lifecycle.create_broadcast_intent(tx_id, tx_d(11)).unwrap();
        lifecycle
            .confirm_broadcast(BroadcastReceiptV0 {
                tx_id,
                intent_sequence: intent.intent_sequence,
                envelope_digest: intent.envelope_digest,
                transport_receipt_digest: tx_d(12),
            })
            .unwrap();
        assert_eq!(
            lifecycle
                .confirm_broadcast(BroadcastReceiptV0 {
                    tx_id,
                    intent_sequence: intent.intent_sequence,
                    envelope_digest: intent.envelope_digest,
                    transport_receipt_digest: tx_d(13),
                })
                .unwrap_err(),
            TxLifecycleErrorV0::ReceiptSubstitution
        );
        let _unused = FinalityWitnessV0 {
            block_id: position.block_id,
            height: position.height,
            state_root: tx_d(14),
            finality_proof_digest: tx_d(15),
        };
    }

    struct AcceptPlanSignature;
    impl PlanSignatureVerifierV0 for AcceptPlanSignature {
        type Error = Infallible;
        fn verify_plan_signature(&self, _plan: &OptimizationPlanV1) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn control_plane_cannot_finalize_even_with_a_valid_signature() {
        let guard = LocalPlanGuardV0::new(
            AcceptPlanSignature,
            control_d(2),
            control_d(3),
            7,
            vec![],
        )
        .unwrap();
        let mut plan = OptimizationPlanV1 {
            plan_id: control_d(1),
            source_graph_digest: control_d(2),
            contract_set_digest: control_d(3),
            workload_assumption_digest: control_d(4),
            expected_effect_digest: control_d(5),
            rollback_plan_digest: control_d(6),
            issued_generation: 8,
            not_before_height: 100,
            expires_after_height: 200,
            actions: vec![PlanActionV0::Forbidden(
                ForbiddenAuthorityActionV0::Finalize,
            )],
            signer_id: control_d(7),
            signature_digest: control_d(8),
            canonical_plan_digest: control_d(0),
        };
        plan.canonical_plan_digest = plan.canonical_digest();
        let receipt = guard
            .evaluate(&plan, 150, None, None, control_d(9), control_d(10))
            .unwrap();
        assert!(!receipt.accepted);
        assert_eq!(
            receipt.action_results[0].decision,
            ActionDecisionV0::Rejected(ControlPlaneErrorV0::ForbiddenAuthorityAction)
        );
    }

    #[test]
    fn migration_testkit_proves_signer_journal_is_unimportable() {
        let namespace = b"signer_journal".to_vec();
        let key = vec![1];
        let value = vec![2];
        let row = ExportRowV0 {
            row_digest: ExportRowV0::canonical_digest(&namespace, &key, &value),
            namespace,
            key,
            value,
        };
        assert_eq!(
            row.validate().unwrap_err(),
            MigrationErrorV0::ForbiddenAuthorityState
        );
    }
}
