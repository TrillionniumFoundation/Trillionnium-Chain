// Native13/journal9 composition; the underlying schema1 signer remains the
// only owner of intent persistence, external advancement and signature replay.
use trnm_consensus_signer_journal::{
    ConfirmedHandoffJournalHeadV1, HandoffSignatureProducerV1, HandoffSignatureRequestV1,
    HandoffSignerJournalProfileV1, SignatureProducerErrorV0, SignerWatermarkV0,
    SqliteHandoffSignerJournalV1, StrictNewSetHandoffAdmissionV1, StrictOldSetHandoffAdmissionV1,
};
use trnm_consensus_types::{CanonicalHandoffSignIntentV1, HandoffSignerRoleV1, SignatureBytes};

/// Inert original signature and exact durable release cut. This grants neither
/// a complete joint quorum nor native attachment/Core activation authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedEpochHandoffSignatureV7 {
    intent: CanonicalHandoffSignIntentV1,
    signature: SignatureBytes,
    native_owner_cut: [u8; 32],
    node_checkpoint: [u8; 32],
    retirement_checksum: [u8; 32],
    role_profile_checksum: [u8; 32],
    role_watermark: SignerWatermarkV0,
}
impl RecordedEpochHandoffSignatureV7 {
    pub const fn intent_v7(&self) -> &CanonicalHandoffSignIntentV1 {
        &self.intent
    }
    pub const fn signature_v7(&self) -> SignatureBytes {
        self.signature
    }
    pub const fn native_owner_cut_v7(&self) -> [u8; 32] {
        self.native_owner_cut
    }
    pub const fn node_checkpoint_v7(&self) -> [u8; 32] {
        self.node_checkpoint
    }
    pub const fn retirement_checksum_v7(&self) -> [u8; 32] {
        self.retirement_checksum
    }
    pub const fn role_profile_checksum_v7(&self) -> [u8; 32] {
        self.role_profile_checksum
    }
    pub const fn role_watermark_v7(&self) -> SignerWatermarkV0 {
        self.role_watermark
    }
}

/// Live, consumed current-N retirement plus an independently selected actual
/// handoff journal. No ordinary signer, Core driver or recovery conversion escapes.
///
/// ```compile_fail
/// use trnm_poco_node::EpochHandoffRolesRuntimeV7;
/// use trnm_consensus_signer_journal::{ExternalSignerRetirementV1, ExternalMonotonicWatermarkV0};
/// fn copy<W: ExternalSignerRetirementV1, N: ExternalSignerRetirementV1, H: ExternalMonotonicWatermarkV0>(v: EpochHandoffRolesRuntimeV7<W,N,H>) {
///     let _ = v.clone();
/// }
/// ```
#[must_use]
pub struct EpochHandoffRolesRuntimeV7<
    W: ExternalSignerRetirementV1,
    N: ExternalSignerRetirementV1,
    H: ExternalMonotonicWatermarkV0,
> {
    retired: Box<EpochRetirementRuntimeV6<W, N>>,
    journal: SqliteHandoffSignerJournalV1<H>,
    head: ConfirmedHandoffJournalHeadV1,
    old_signature: Option<RecordedEpochHandoffSignatureV7>,
    new_signature: Option<RecordedEpochHandoffSignatureV7>,
    fenced: bool,
}

impl<W: ExternalSignerRetirementV1, N: ExternalSignerRetirementV1> EpochRetirementRuntimeV6<W, N> {
    /// Consume both independently selected owners. Only a virgin actual role
    /// journal can enter; cold/pending role custody requires a future recovery join.
    pub fn into_handoff_roles_v7<H: ExternalMonotonicWatermarkV0>(
        mut self,
        mut journal: SqliteHandoffSignerJournalV1<H>,
        selected: ConfirmedHandoffJournalHeadV1,
    ) -> Result<EpochHandoffRolesRuntimeV7<W, N, H>> {
        self.confirm_retired_cut_v6()?;
        confirm_role_profile_v7(&self, journal.profile())?;
        let path = journal.path().to_path_buf();
        ensure!(
            selected.belongs_to_owner_at_path_v1(&mut journal, &path)
                && selected.exact_watermark_v1().sequence() == 0
                && selected.pending_fingerprint_v1().is_none()
                && selected.terminal_fence_checksum_v1().is_none(),
            "handoff role commissioning requires exact virgin actual owner"
        );
        // The external role watermark callback precedes this final source read.
        self.confirm_retired_cut_v6()?;
        Ok(EpochHandoffRolesRuntimeV7 {
            retired: Box::new(self),
            journal,
            head: selected,
            old_signature: None,
            new_signature: None,
            fenced: false,
        })
    }
}

fn confirm_role_profile_v7<W: ExternalSignerRetirementV1, N: ExternalSignerRetirementV1>(
    retired: &EpochRetirementRuntimeV6<W, N>,
    profile: &HandoffSignerJournalProfileV1,
) -> Result<()> {
    let context = retired.source.receipt.strict_context();
    let outgoing = retired.retired.profile_v1();
    ensure!(
        profile.old_validator_set() == context.old_validator_set()
            && profile.new_validator_set() == context.new_validator_set()
            && profile.old_consensus_parameters() == context.old_consensus_parameters()
            && profile.new_consensus_parameters() == context.new_consensus_parameters()
            && profile.author() == outgoing.author()
            && profile.signer_profile_ref() == outgoing.signer_profile_ref()
            && profile
                .old_validator_set()
                .validator(profile.author())
                .is_some()
            && (profile
                .new_validator_set()
                .validator(profile.author())
                .is_none()
                || profile.new_set_handoff_enabled())
            && profile.external_watermark_scope()
                != retired.retirement.record_v1().source_v1().scope()
            && profile.external_watermark_scope()
                != retired
                    .source
                    .incoming_retirement
                    .record_v1()
                    .source_v1()
                    .scope(),
        "handoff role profile differs from exact native13/current retired N custody"
    );
    Ok(())
}

enum RoleAdmissionV7 {
    Old(Box<StrictOldSetHandoffAdmissionV1>),
    New(Box<StrictNewSetHandoffAdmissionV1>),
}

impl<
        W: ExternalSignerRetirementV1,
        N: ExternalSignerRetirementV1,
        H: ExternalMonotonicWatermarkV0,
    > EpochHandoffRolesRuntimeV7<W, N, H>
{
    /// Persist and sign only this exact role over the original strict context.
    /// Failure fences this owner; successful exact replay performs no key call.
    pub fn sign_handoff_exact_v7<P: HandoffSignatureProducerV1>(
        &mut self,
        role: HandoffSignerRoleV1,
        producer: &mut P,
    ) -> Result<RecordedEpochHandoffSignatureV7> {
        ensure!(!self.fenced, "handoff role owner fenced");
        let result = self.sign_joined_v7(role, producer);
        if result.is_err() {
            self.fenced = true;
        }
        result
    }

    fn sign_joined_v7<P: HandoffSignatureProducerV1>(
        &mut self,
        role: HandoffSignerRoleV1,
        producer: &mut P,
    ) -> Result<RecordedEpochHandoffSignatureV7> {
        let path = self.journal.path().to_path_buf();
        ensure!(
            self.head
                .belongs_to_owner_at_path_v1(&mut self.journal, &path),
            "handoff role selected head changed"
        );
        confirm_role_profile_v7(&self.retired, self.journal.profile())?;
        let checkpoint = self.retired.confirm_retired_cut_v6()?;
        let (intent, admission) = {
            let context = self.retired.source.receipt.strict_context();
            let make_intent = match role {
                HandoffSignerRoleV1::OldSet => CanonicalHandoffSignIntentV1::old_set,
                HandoffSignerRoleV1::NewSet => CanonicalHandoffSignIntentV1::new_set,
            };
            let intent = make_intent(
                context.descriptor(),
                context.old_validator_set(),
                context.new_validator_set(),
                context.old_consensus_parameters(),
                context.new_consensus_parameters(),
                self.journal.profile().author(),
            )
            .map_err(|e| anyhow::anyhow!("handoff role intent: {e:?}"))?;
            let admission = match role {
                HandoffSignerRoleV1::OldSet => RoleAdmissionV7::Old(Box::new(
                    StrictOldSetHandoffAdmissionV1::from_verified_context(&intent, context)?,
                )),
                HandoffSignerRoleV1::NewSet => RoleAdmissionV7::New(Box::new(
                    StrictNewSetHandoffAdmissionV1::from_verified_context(&intent, context)?,
                )),
            };
            (intent, admission)
        };
        let prior = match role {
            HandoffSignerRoleV1::OldSet => self.old_signature.as_ref(),
            HandoffSignerRoleV1::NewSet => self.new_signature.as_ref(),
        };
        let retired = &mut self.retired;
        let mut guarded = FreshHandoffSignatureProducerV7 {
            producer,
            expected: &intent,
            expected_profile: self.journal.profile().signer_profile_ref(),
            confirm: || {
                ensure!(
                    retired.confirm_retired_cut_v6()? == checkpoint,
                    "handoff key source changed"
                );
                Ok(())
            },
        };
        let signature = match &admission {
            RoleAdmissionV7::Old(a) => {
                self.journal
                    .sign_old_set_handoff_exact_v1(&intent, a, &mut guarded)?
            }
            RoleAdmissionV7::New(a) => {
                self.journal
                    .sign_new_set_handoff_exact_v1(&intent, a, &mut guarded)?
            }
        };
        let fresh = self.journal.confirm_head_exact_v1()?;
        ensure!(
            fresh.pending_fingerprint_v1().is_none()
                && fresh.profile_checksum_v1() == self.head.profile_checksum_v1()
                && fresh.exact_watermark_v1().scope() == self.head.exact_watermark_v1().scope()
                && fresh.exact_watermark_v1().journal_id()
                    == self.head.exact_watermark_v1().journal_id(),
            "handoff final role custody changed"
        );
        let receipt = if let Some(prior) = prior {
            ensure!(
                fresh.matches_exact_head_v1(&self.head)
                    && prior.intent == intent
                    && prior.signature == signature,
                "handoff exact role replay changed"
            );
            prior.clone()
        } else {
            ensure!(
                self.head.exact_watermark_v1().sequence().checked_add(2)
                    == Some(fresh.exact_watermark_v1().sequence()),
                "handoff role did not append exact prepare/sign events"
            );
            match role {
                HandoffSignerRoleV1::OldSet => ensure!(
                    self.head.terminal_fence_checksum_v1().is_none()
                        && fresh.terminal_fence_checksum_v1().is_some(),
                    "old role did not install original terminal fence"
                ),
                HandoffSignerRoleV1::NewSet => ensure!(
                    fresh.terminal_fence_checksum_v1() == self.head.terminal_fence_checksum_v1(),
                    "new role changed old-role terminal fence"
                ),
            }
            RecordedEpochHandoffSignatureV7 {
                intent,
                signature,
                native_owner_cut: self.retired.source.receipt.committed_owner_cut_ref_v1(),
                node_checkpoint: checkpoint.checksum(),
                retirement_checksum: self.retired.retirement.record_v1().checksum_v1(),
                role_profile_checksum: fresh.profile_checksum_v1(),
                role_watermark: fresh.exact_watermark_v1(),
            }
        };
        // Includes final exact independent checkpoint read after the role
        // watermark callback, before any signature is exposed to the caller.
        ensure!(
            self.retired.confirm_retired_cut_v6()? == checkpoint,
            "handoff source changed before signature release"
        );
        self.head = fresh;
        match role {
            HandoffSignerRoleV1::OldSet => self.old_signature = Some(receipt.clone()),
            HandoffSignerRoleV1::NewSet => self.new_signature = Some(receipt.clone()),
        }
        Ok(receipt)
    }
}

struct FreshHandoffSignatureProducerV7<'a, P, F> {
    producer: &'a mut P,
    expected: &'a CanonicalHandoffSignIntentV1,
    expected_profile: [u8; 32],
    confirm: F,
}
impl<P: HandoffSignatureProducerV1, F: FnMut() -> Result<()>> HandoffSignatureProducerV1
    for FreshHandoffSignatureProducerV7<'_, P, F>
{
    fn sign_handoff(
        &mut self,
        request: HandoffSignatureRequestV1<'_>,
    ) -> std::result::Result<SignatureBytes, SignatureProducerErrorV0> {
        if request.intent() != self.expected
            || request.signer_profile_ref() != self.expected_profile
        {
            return Err(SignatureProducerErrorV0::Rejected);
        }
        (self.confirm)().map_err(|_| SignatureProducerErrorV0::Rejected)?;
        let signature = self.producer.sign_handoff(request)?;
        (self.confirm)().map_err(|_| SignatureProducerErrorV0::Rejected)?;
        Ok(signature)
    }
}
