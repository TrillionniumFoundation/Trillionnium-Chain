use crate::{AuthorityStageV0, Digest32V0, OperationBindingV0};
use trnm_node_boundary_v0::BoundaryErrorV0;
use trnm_poco_node::ConfirmedNodeCheckpointCandidateV0;

#[cfg(feature = "persistent-authority-candidate")]
use crate::{AuthorityReceiptV0, NodeAuthorityCoordinatorV0, NodeAuthorityErrorV0};

/// Non-cloneable application/Safety fact source derived from one freshly
/// confirmed whole-node checkpoint candidate.
///
/// The fields and raw constructor remain private. A decoded checkpoint value
/// is insufficient: construction consumes the non-forgeable candidate and
/// requires positive application height and Safety revision, excluding the
/// virgin-genesis capability. This capability proves only the application and
/// Safety facts already joined into that checkpoint. It grants no signing,
/// finality, publication, networking, or activation authority.
///
/// ```compile_fail
/// use trnm_poco_node_authority::{
///     ConfirmedApplicationSafetyAuthorityV0, Digest32V0,
/// };
/// fn forge() -> ConfirmedApplicationSafetyAuthorityV0 {
///     ConfirmedApplicationSafetyAuthorityV0 {
///         scope: Digest32V0([1; 32]),
///         checkpoint_checksum: Digest32V0([2; 32]),
///         height: 1,
///         view: 0,
///         block_id: Digest32V0([3; 32]),
///         application_sealed_digest: Digest32V0([4; 32]),
///         safety_persisted_digest: Digest32V0([5; 32]),
///     }
/// }
/// ```
#[derive(Debug)]
pub struct ConfirmedApplicationSafetyAuthorityV0 {
    scope: Digest32V0,
    checkpoint_checksum: Digest32V0,
    height: u64,
    view: u64,
    block_id: Digest32V0,
    application_sealed_digest: Digest32V0,
    safety_persisted_digest: Digest32V0,
}

/// One-use continuation created only after the application fact has been bound
/// to an exact node operation. It cannot be cloned or constructed externally.
#[derive(Debug)]
pub struct ConfirmedSafetyContinuationV0 {
    binding: OperationBindingV0,
    scope: Digest32V0,
    checkpoint_checksum: Digest32V0,
    safety_persisted_digest: Digest32V0,
}

impl ConfirmedApplicationSafetyAuthorityV0 {
    /// Consume a freshly authenticated checkpoint capability and derive
    /// canonical application/Safety fact digests from all joined fields.
    pub fn from_checkpoint_candidate_v0(
        candidate: ConfirmedNodeCheckpointCandidateV0,
    ) -> Option<Self> {
        let checkpoint = candidate.checkpoint();
        let fields = checkpoint.fields();
        if fields.application_height == 0 || fields.safety_revision == 0 {
            return None;
        }

        let generation = fields.generation.to_be_bytes();
        let height = fields.application_height.to_be_bytes();
        let view = fields.application_view.to_be_bytes();
        let timestamp = fields.application_timestamp_ms.to_be_bytes();
        let safety_revision = fields.safety_revision.to_be_bytes();
        let watermark_sequence = fields.signer_exact_watermark.sequence().to_be_bytes();
        let checkpoint_checksum = checkpoint.checkpoint_checksum();
        let application_sealed_digest = Digest32V0::hash(
            b"trnm.confirmed-application-sealed.v0",
            &[
                &fields.scope,
                &generation,
                &fields.predecessor_checksum,
                &fields.application_host_config_ref,
                &fields.application_projection_profile_ref,
                &fields.application_safety_binding_manifest_checksum,
                &fields.application_committed_head_row_checksum,
                &fields.application_recovery_closure_checksum,
                fields.application_block_id.as_bytes(),
                &height,
                fields.application_state_root.as_bytes(),
                &view,
                &timestamp,
                &checkpoint_checksum,
            ],
        );
        let safety_persisted_digest = Digest32V0::hash(
            b"trnm.confirmed-safety-persisted.v0",
            &[
                &application_sealed_digest.0,
                &fields.safety_journal_id,
                &fields.safety_verifier_profile_ref,
                &safety_revision,
                &fields.safety_state_record_checksum,
                &fields.safety_record_chain_checksum,
                &fields.signer_journal_id,
                &fields.signer_profile_checksum,
                &fields.signer_exact_watermark.scope(),
                &fields.signer_exact_watermark.journal_id(),
                &watermark_sequence,
                &fields.signer_exact_watermark.chain_checksum(),
                &checkpoint_checksum,
            ],
        );
        if application_sealed_digest == Digest32V0([0; 32])
            || safety_persisted_digest == Digest32V0([0; 32])
            || application_sealed_digest == safety_persisted_digest
        {
            return None;
        }
        Some(Self {
            scope: Digest32V0(fields.scope),
            checkpoint_checksum: Digest32V0(checkpoint_checksum),
            height: fields.application_height,
            view: fields.application_view,
            block_id: Digest32V0(*fields.application_block_id.as_bytes()),
            application_sealed_digest,
            safety_persisted_digest,
        })
    }

    /// Consume this capability and bind ApplicationSealed to the exact
    /// operation, returning a one-use Safety continuation.
    pub fn into_application_stage_v0(
        self,
        binding: OperationBindingV0,
    ) -> Result<(Digest32V0, ConfirmedSafetyContinuationV0), BoundaryErrorV0> {
        validate_coordinates_v0(binding, self.height, self.view, self.block_id)?;
        let digest = bound_stage_digest_v0(
            binding,
            AuthorityStageV0::ApplicationSealed,
            self.scope,
            self.checkpoint_checksum,
            self.application_sealed_digest,
        );
        Ok((
            digest,
            ConfirmedSafetyContinuationV0 {
                binding,
                scope: self.scope,
                checkpoint_checksum: self.checkpoint_checksum,
                safety_persisted_digest: self.safety_persisted_digest,
            },
        ))
    }
}

impl ConfirmedSafetyContinuationV0 {
    /// Consume this continuation and bind SafetyPersisted to the exact full
    /// operation previously accepted for ApplicationSealed.
    pub fn into_safety_stage_v0(
        self,
        binding: OperationBindingV0,
    ) -> Result<Digest32V0, BoundaryErrorV0> {
        if binding != self.binding {
            return Err(BoundaryErrorV0::OperationBindingMismatch);
        }
        Ok(bound_stage_digest_v0(
            binding,
            AuthorityStageV0::SafetyPersisted,
            self.scope,
            self.checkpoint_checksum,
            self.safety_persisted_digest,
        ))
    }
}

fn validate_coordinates_v0(
    binding: OperationBindingV0,
    height: u64,
    view: u64,
    block_id: Digest32V0,
) -> Result<(), BoundaryErrorV0> {
    if binding.operation_id == Digest32V0([0; 32]) {
        return Err(BoundaryErrorV0::InvalidOperationBinding);
    }
    if binding.height != height || binding.view != view || binding.block_id != block_id {
        return Err(BoundaryErrorV0::OperationBindingMismatch);
    }
    Ok(())
}

fn bound_stage_digest_v0(
    binding: OperationBindingV0,
    stage: AuthorityStageV0,
    scope: Digest32V0,
    checkpoint_checksum: Digest32V0,
    source: Digest32V0,
) -> Digest32V0 {
    let stage_byte = [stage as u8];
    Digest32V0::hash(
        b"trnm.node-authority.confirmed-stage.v0",
        &[
            &binding.operation_id.0,
            &scope.0,
            &checkpoint_checksum.0,
            &binding.block_id.0,
            &binding.height.to_be_bytes(),
            &binding.view.to_be_bytes(),
            &stage_byte,
            &source.0,
        ],
    )
}

#[cfg(feature = "persistent-authority-candidate")]
impl NodeAuthorityCoordinatorV0 {
    /// Persist ApplicationSealed from a non-forgeable whole-node checkpoint
    /// capability and return the one-use continuation for SafetyPersisted.
    pub fn advance_confirmed_application_v0(
        &mut self,
        binding: OperationBindingV0,
        facts: ConfirmedApplicationSafetyAuthorityV0,
    ) -> Result<(AuthorityReceiptV0, ConfirmedSafetyContinuationV0), NodeAuthorityErrorV0> {
        let identity = self.identity().ok_or(NodeAuthorityErrorV0::Inert)?;
        binding
            .validate(identity)
            .map_err(NodeAuthorityErrorV0::Boundary)?;
        let (digest, continuation) = facts
            .into_application_stage_v0(binding)
            .map_err(NodeAuthorityErrorV0::Boundary)?;
        let receipt = self.advance_exact(
            binding,
            AuthorityStageV0::Prepared,
            AuthorityStageV0::ApplicationSealed,
            digest,
        )?;
        Ok((receipt, continuation))
    }

    /// Consume the exact continuation returned by ApplicationSealed and
    /// persist SafetyPersisted for the same full operation binding.
    pub fn advance_confirmed_safety_v0(
        &mut self,
        binding: OperationBindingV0,
        continuation: ConfirmedSafetyContinuationV0,
    ) -> Result<AuthorityReceiptV0, NodeAuthorityErrorV0> {
        let identity = self.identity().ok_or(NodeAuthorityErrorV0::Inert)?;
        binding
            .validate(identity)
            .map_err(NodeAuthorityErrorV0::Boundary)?;
        let digest = continuation
            .into_safety_stage_v0(binding)
            .map_err(NodeAuthorityErrorV0::Boundary)?;
        self.advance_exact(
            binding,
            AuthorityStageV0::ApplicationSealed,
            AuthorityStageV0::SafetyPersisted,
            digest,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NodeIdentityV0;

    fn identity() -> NodeIdentityV0 {
        NodeIdentityV0 {
            chain_id: Digest32V0([1; 32]),
            validator_id: Digest32V0([2; 32]),
            application_id: Digest32V0([3; 32]),
            generation: 1,
        }
    }

    fn binding() -> OperationBindingV0 {
        OperationBindingV0::derive(
            identity(),
            1,
            0,
            Digest32V0([6; 32]),
            Digest32V0([7; 32]),
            Digest32V0([8; 32]),
        )
    }

    fn facts() -> ConfirmedApplicationSafetyAuthorityV0 {
        ConfirmedApplicationSafetyAuthorityV0 {
            scope: Digest32V0([9; 32]),
            checkpoint_checksum: Digest32V0([10; 32]),
            height: 1,
            view: 0,
            block_id: Digest32V0([6; 32]),
            application_sealed_digest: Digest32V0([11; 32]),
            safety_persisted_digest: Digest32V0([12; 32]),
        }
    }

    #[test]
    fn typed_stage_chain_is_one_use_and_exact_binding_scoped() {
        let binding = binding();
        let (application, continuation) = facts()
            .into_application_stage_v0(binding)
            .expect("application digest");
        let safety = continuation
            .into_safety_stage_v0(binding)
            .expect("Safety digest");
        assert_ne!(application, safety);

        let mut wrong_height = binding;
        wrong_height.height += 1;
        assert!(matches!(
            facts().into_application_stage_v0(wrong_height),
            Err(BoundaryErrorV0::OperationBindingMismatch)
        ));
        let (_, continuation) = facts()
            .into_application_stage_v0(binding)
            .expect("continuation");
        let mut wrong_proposal = binding;
        wrong_proposal.proposal_digest = Digest32V0([13; 32]);
        assert_eq!(
            continuation.into_safety_stage_v0(wrong_proposal),
            Err(BoundaryErrorV0::OperationBindingMismatch)
        );
    }

    #[cfg(feature = "persistent-authority-candidate")]
    #[test]
    fn coordinator_accepts_only_typed_application_then_safety() {
        use crate::{BoundIngressV0, IngressFrameV0, RecoveryDispositionV0};

        let directory = tempfile::tempdir().expect("tempdir");
        let mut coordinator =
            NodeAuthorityCoordinatorV0::open_candidate(directory.path(), identity()).expect("open");
        assert_eq!(
            coordinator.recover().expect("recover"),
            RecoveryDispositionV0::Clean
        );
        let frame = IngressFrameV0::new(
            Digest32V0([4; 32]),
            Digest32V0([5; 32]),
            1,
            b"proposal".to_vec(),
        )
        .expect("frame");
        let ingress = BoundIngressV0::derive(
            identity(),
            1,
            0,
            Digest32V0([6; 32]),
            Digest32V0([7; 32]),
            frame,
        )
        .expect("ingress");
        let prepared = coordinator
            .prepare_bound_ingress(&ingress)
            .expect("prepare");
        let (application, continuation) = coordinator
            .advance_confirmed_application_v0(prepared.binding, facts())
            .expect("application");
        let safety = coordinator
            .advance_confirmed_safety_v0(prepared.binding, continuation)
            .expect("Safety");
        assert_eq!(application.durable_stage, AuthorityStageV0::ApplicationSealed);
        assert_eq!(safety.durable_stage, AuthorityStageV0::SafetyPersisted);
        assert_ne!(application.facts_digest, safety.facts_digest);
        assert_eq!(coordinator.current_receipt(), Some(safety));
    }
}
