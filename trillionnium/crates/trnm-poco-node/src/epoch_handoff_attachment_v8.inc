// A live consuming composition only. Kernel decoding and checkpoint fields are
// comparison data; the original native attachment producer verifies authority.
use trnm_native_execution_v0::LaterEpochApplicationEdgeV1;

/// Retained actual role custody and a strictly attached native13 successor.
/// Attachment alone releases no Core activation, ordinary custody or signing.
/// Explicit V9 consumes this owner; no cold conversion is exposed.
///
/// ```compile_fail
/// use trnm_poco_node::EpochHandoffAttachedRuntimeV8;
/// use trnm_consensus_signer_journal::{ExternalSignerRetirementV1, ExternalMonotonicWatermarkV0};
/// fn copy<W: ExternalSignerRetirementV1, N: ExternalSignerRetirementV1, H: ExternalMonotonicWatermarkV0>(v: EpochHandoffAttachedRuntimeV8<W,N,H>) {
///     let _ = v.clone();
/// }
/// ```
#[must_use]
pub struct EpochHandoffAttachedRuntimeV8<
    W: ExternalSignerRetirementV1,
    N: ExternalSignerRetirementV1,
    H: ExternalMonotonicWatermarkV0,
> {
    roles: Box<EpochHandoffRolesRuntimeV7<W, N, H>>,
    edge: LaterEpochApplicationEdgeV1,
    kernel: Box<[u8]>,
    checkpoint: EpochNodeCheckpointV1,
    fenced: bool,
}

impl<
        W: ExternalSignerRetirementV1,
        N: ExternalSignerRetirementV1,
        H: ExternalMonotonicWatermarkV0,
    > EpochHandoffRolesRuntimeV7<W, N, H>
{
    /// Consume the live owner. Failure, including uncertain native/node commit,
    /// releases no reusable role or ordinary owner and grants no activation.
    pub fn attach_joint_handoff_v8(
        mut self,
        kernel: &[u8],
    ) -> Result<EpochHandoffAttachedRuntimeV8<W, N, H>> {
        self.retired
            .checkpoint
            .fields()
            .generation
            .checked_add(1)
            .context("joint attachment generation exhausted")?;
        validate_joint_kernel_v8(&self, kernel)?;
        confirm_attachment_source_v8(&mut self)?;
        self.retired
            .checkpoint_store
            .confirm_exact(&self.retired.checkpoint)?;
        let edge = self
            .retired
            .source
            .application
            .attach_later_epoch_handoff_v1(&self.retired.source.receipt, kernel)?;
        validate_attached_edge_v8(&self, &edge)?;
        let original_checkpoint = self.retired.checkpoint;
        let mut attached = EpochHandoffAttachedRuntimeV8 {
            roles: Box::new(self),
            edge,
            kernel: kernel.into(),
            // The original tag3 remains in roles.retired.checkpoint.
            checkpoint: original_checkpoint,
            fenced: false,
        };
        attached.checkpoint = attached.target_checkpoint_v8()?;
        attached.confirm_native_and_custody_v8()?;
        attached
            .roles
            .retired
            .checkpoint_store
            .compare_and_advance(&attached.roles.retired.checkpoint, &attached.checkpoint)?;
        attached.confirm_attached_cut_v8()?;
        Ok(attached)
    }
}

fn confirm_attachment_custody_v8<
    W: ExternalSignerRetirementV1,
    N: ExternalSignerRetirementV1,
    H: ExternalMonotonicWatermarkV0,
>(
    roles: &mut EpochHandoffRolesRuntimeV7<W, N, H>,
) -> Result<()> {
    ensure!(
        !roles.fenced && !roles.retired.fenced,
        "joint attachment source owner fenced"
    );
    let path = roles.journal.path().to_path_buf();
    ensure!(
        roles
            .head
            .belongs_to_owner_at_path_v1(&mut roles.journal, &path)
            && roles.head.pending_fingerprint_v1().is_none()
            && roles.head.terminal_fence_checksum_v1().is_some(),
        "joint attachment exact role head/fence changed"
    );
    confirm_role_profile_v7(&roles.retired, roles.journal.profile())?;
    // These are immutable handoff/custody owners after successor activation.
    // They remain valid historical dependencies even after the native current
    // head advances inside the successor epoch.
    roles.head.confirm_local_owner_v1(&roles.journal)?;
    roles
        .retired
        .retirement
        .confirm_local_owner_v1(&roles.retired.retired)?;
    roles
        .retired
        .source
        .incoming_retirement
        .confirm_local_owner_v1(&roles.retired.source.incoming_retired)?;
    Ok(())
}

fn confirm_attachment_source_v8<
    W: ExternalSignerRetirementV1,
    N: ExternalSignerRetirementV1,
    H: ExternalMonotonicWatermarkV0,
>(
    roles: &mut EpochHandoffRolesRuntimeV7<W, N, H>,
) -> Result<()> {
    confirm_attachment_custody_v8(roles)?;
    // Before successor activation the retired V6 cut is also the current
    // application cut.  Do not reuse this current-cut assertion after V10 has
    // legitimately advanced the native head.
    ensure!(
        roles.retired.join_target_v6()? == roles.retired.checkpoint,
        "joint attachment original retired cut changed"
    );
    Ok(())
}

fn validate_joint_kernel_v8<
    W: ExternalSignerRetirementV1,
    N: ExternalSignerRetirementV1,
    H: ExternalMonotonicWatermarkV0,
>(
    roles: &EpochHandoffRolesRuntimeV7<W, N, H>,
    bytes: &[u8],
) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= 8 * 1024 * 1024,
        "joint attachment kernel byte bound"
    );
    let context = roles.retired.source.receipt.strict_context();
    let kernel = trnm_consensus_types::decode_epoch_anchor_authorization_kernel_v0_exact(
        bytes,
        context.old_validator_set(),
        context.new_validator_set(),
    )
    .map_err(|e| anyhow::anyhow!("joint attachment canonical kernel: {e:?}"))?;
    let descriptor = context.descriptor();
    let proof = roles
        .retired
        .source
        .driver
        .state()
        .last_finalization_proof()
        .context("joint attachment original finality missing")?;
    ensure!(
        kernel.handoff_certificate().descriptor() == descriptor
            && kernel.terminal_old_header() == proof.grandchild().header()
            && kernel.terminal_old_qc() == proof.grandchild().certifying_qc()
            && kernel.terminal_old_header().id() == descriptor.fields().terminal_old_block_id
            && kernel.terminal_old_qc().id() == descriptor.fields().terminal_old_qc_digest,
        "joint attachment original descriptor/terminal differs"
    );
    let old = roles
        .old_signature
        .as_ref()
        .context("joint attachment lacks local old role")?;
    validate_local_role_v8(roles, old, HandoffSignerRoleV1::OldSet)?;
    let certificate = kernel.handoff_certificate();
    for (shares, receipt) in [
        (certificate.old_signatures(), Some(old)),
        (certificate.new_signatures(), roles.new_signature.as_ref()),
    ] {
        if let Some(local) = shares
            .iter()
            .find(|s| s.validator_id() == roles.journal.profile().author())
        {
            ensure!(
                receipt.is_some_and(|r| local.signature().as_bytes() == r.signature.as_bytes()),
                "joint attachment included local signature differs"
            );
        }
    }
    match roles.retired.checkpoint.fields().role {
        EpochCheckpointRoleV1::Continuing => {
            let new = roles
                .new_signature
                .as_ref()
                .context("joint attachment lacks local new role")?;
            validate_local_role_v8(roles, new, HandoffSignerRoleV1::NewSet)?;
        }
        EpochCheckpointRoleV1::Removed => ensure!(
            roles.new_signature.is_none(),
            "removed role has new signature"
        ),
        EpochCheckpointRoleV1::VirginNew => {
            anyhow::bail!("joint attachment has no outgoing new-only owner")
        }
    }
    Ok(())
}

fn validate_local_role_v8<
    W: ExternalSignerRetirementV1,
    N: ExternalSignerRetirementV1,
    H: ExternalMonotonicWatermarkV0,
>(
    roles: &EpochHandoffRolesRuntimeV7<W, N, H>,
    local: &RecordedEpochHandoffSignatureV7,
    role: HandoffSignerRoleV1,
) -> Result<()> {
    let context = roles.retired.source.receipt.strict_context();
    let make = match role {
        HandoffSignerRoleV1::OldSet => CanonicalHandoffSignIntentV1::old_set,
        HandoffSignerRoleV1::NewSet => CanonicalHandoffSignIntentV1::new_set,
    };
    let expected = make(
        context.descriptor(),
        context.old_validator_set(),
        context.new_validator_set(),
        context.old_consensus_parameters(),
        context.new_consensus_parameters(),
        roles.journal.profile().author(),
    )
    .map_err(|e| anyhow::anyhow!("joint attachment local intent: {e:?}"))?;
    let head = roles.head.exact_watermark_v1();
    ensure!(
        local.intent == expected
            && local.native_owner_cut == roles.retired.source.receipt.committed_owner_cut_ref_v1()
            && local.node_checkpoint == roles.retired.checkpoint.checksum()
            && local.retirement_checksum == roles.retired.retirement.record_v1().checksum_v1()
            && local.role_profile_checksum == roles.head.profile_checksum_v1()
            && local.role_watermark.scope() == head.scope()
            && local.role_watermark.journal_id() == head.journal_id()
            && local.role_watermark.sequence() <= head.sequence()
            && (local.role_watermark.sequence() != head.sequence() || local.role_watermark == head),
        "joint attachment original local role custody differs"
    );
    Ok(())
}

fn validate_attached_edge_v8<
    W: ExternalSignerRetirementV1,
    N: ExternalSignerRetirementV1,
    H: ExternalMonotonicWatermarkV0,
>(
    roles: &EpochHandoffRolesRuntimeV7<W, N, H>,
    edge: &LaterEpochApplicationEdgeV1,
) -> Result<()> {
    let source = &roles.retired.source;
    let app = &roles.retired.checkpoint.fields().application;
    let d = source.receipt.strict_context().descriptor().fields();
    ensure!(
        edge.belongs_to_application(&source.application)
            && edge.predecessor_edge() == source.edge.authorization_id()
            && edge.checkpoint_block() == app.block_id
            && edge.checkpoint_height() == app.height
            && edge.checkpoint_root() == app.state_root
            && edge.checkpoint_commit_id() == app.native_commit_id
            && edge.checkpoint_p_digest() == app.p_digest
            && edge.checkpoint_commit_sequence() == app.commit_sequence
            && edge.terminal_block() == *d.terminal_old_block_id.as_bytes()
            && edge.terminal_height() == d.terminal_old_height.get()
            && edge.first_application_height() == d.activation_height.get(),
        "joint attachment native edge differs from original source"
    );
    Ok(())
}

fn attached_edge_digest_v8(edge: &LaterEpochApplicationEdgeV1) -> [u8; 32] {
    epoch_transition_digest(
        "trnm.node.epoch-handoff-native-edge.v8",
        &[
            &edge.successor_binding(),
            &edge.predecessor_edge(),
            &edge.checkpoint_block(),
            &edge.checkpoint_p_digest(),
            &edge.checkpoint_commit_sequence().to_be_bytes(),
            &edge.checkpoint_height().to_be_bytes(),
            &edge.checkpoint_root(),
            &edge.checkpoint_commit_id(),
            &edge.terminal_height().to_be_bytes(),
            &edge.terminal_block(),
            &edge.first_application_height().to_be_bytes(),
            &edge.proof_context_digest(),
            &edge.successor_context_digest(),
            &edge.authority_digest(),
            &edge.record_digest(),
        ],
    )
}
fn local_role_digest_v8(local: Option<&RecordedEpochHandoffSignatureV7>) -> [u8; 32] {
    match local {
        None => epoch_transition_digest("trnm.node.epoch-handoff-local-role.v8", &[&[0]]),
        Some(r) => epoch_transition_digest(
            "trnm.node.epoch-handoff-local-role.v8",
            &[
                &[1],
                r.intent.fingerprint().as_bytes(),
                r.signature.as_bytes(),
                &r.native_owner_cut,
                &r.node_checkpoint,
                &r.retirement_checksum,
                &r.role_profile_checksum,
                &r.role_watermark.scope(),
                &r.role_watermark.journal_id(),
                &r.role_watermark.sequence().to_be_bytes(),
                &r.role_watermark.chain_checksum(),
            ],
        ),
    }
}

impl<
        W: ExternalSignerRetirementV1,
        N: ExternalSignerRetirementV1,
        H: ExternalMonotonicWatermarkV0,
    > EpochHandoffAttachedRuntimeV8<W, N, H>
{
    fn target_checkpoint_v8(&self) -> Result<EpochNodeCheckpointV1> {
        let source = self.roles.retired.checkpoint;
        let mut fields = *source.fields();
        let head = self.roles.head.exact_watermark_v1();
        fields.phase = EpochCheckpointPhaseV1::EpochHandoffAttachedNative13;
        fields.generation = fields
            .generation
            .checked_add(1)
            .context("joint attachment generation exhausted")?;
        fields.predecessor_checksum = source.checksum();
        fields.edge.native_authorization_id = self.edge.successor_binding();
        fields.phase_authority_binding = epoch_transition_digest(
            "trnm.node.epoch-handoff-attachment.v8",
            &[
                &source.checksum(),
                &self
                    .roles
                    .retired
                    .source
                    .receipt
                    .committed_owner_cut_ref_v1(),
                &attached_edge_digest_v8(&self.edge),
                &Sha256::digest(&self.kernel),
                &self.roles.head.profile_checksum_v1(),
                &head.scope(),
                &head.journal_id(),
                &head.sequence().to_be_bytes(),
                &head.chain_checksum(),
                &self
                    .roles
                    .head
                    .terminal_fence_checksum_v1()
                    .context("joint attachment fence absent")?,
                &local_role_digest_v8(self.roles.old_signature.as_ref()),
                &local_role_digest_v8(self.roles.new_signature.as_ref()),
            ],
        );
        let target = EpochNodeCheckpointV1::new(fields)?;
        target.validate_successor_of(&source)?;
        Ok(target)
    }
    fn confirm_retained_attachment_v8(&mut self) -> Result<()> {
        confirm_attachment_custody_v8(&mut self.roles)?;
        validate_joint_kernel_v8(&self.roles, &self.kernel)?;
        let app = &self.roles.retired.source.application;
        let requirements =
            app.inspect_later_epoch_application_edge_requirements_v1(self.edge.checkpoint_block())?;
        let fresh = app.recover_later_epoch_application_edge_v1(&requirements)?;
        validate_attached_edge_v8(&self.roles, &fresh)?;
        ensure!(
            attached_edge_digest_v8(&fresh) == attached_edge_digest_v8(&self.edge),
            "joint attachment retained edge changed"
        );
        ensure!(
            self.target_checkpoint_v8()? == self.checkpoint,
            "joint attachment target changed"
        );
        Ok(())
    }

    fn confirm_native_and_custody_v8(&mut self) -> Result<()> {
        // V8 still requires the old retired cut to be the current application
        // cut.  V10+ uses `confirm_retained_attachment_v8` plus its own current
        // checkpoint/native readback instead.
        confirm_attachment_source_v8(&mut self.roles)?;
        self.confirm_retained_attachment_v8()
    }
    /// Fresh read-only comparison. Failure permanently fences this retained owner.
    pub fn confirm_attached_cut_v8(&mut self) -> Result<EpochNodeCheckpointV1> {
        ensure!(!self.fenced, "joint attached owner fenced");
        let result = (|| {
            self.roles
                .retired
                .checkpoint_store
                .confirm_exact(&self.checkpoint)?;
            self.confirm_native_and_custody_v8()?;
            self.roles
                .retired
                .checkpoint_store
                .confirm_exact(&self.checkpoint)?;
            Ok(self.checkpoint)
        })();
        if result.is_err() {
            self.fenced = true;
        }
        result
    }
    /// Exact original bytes only; no new signatures, native sequence or node CAS.
    pub fn confirm_joint_handoff_exact_v8(
        &mut self,
        kernel: &[u8],
    ) -> Result<EpochNodeCheckpointV1> {
        ensure!(!self.fenced, "joint attached owner fenced");
        if kernel != self.kernel.as_ref() {
            self.fenced = true;
            anyhow::bail!("joint attachment conflicting exact retry");
        }
        self.confirm_attached_cut_v8()
    }
}
