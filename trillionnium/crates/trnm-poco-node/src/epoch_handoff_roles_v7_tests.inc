// Build one real settled V5 owner per test. Thin staged helpers retain the
// default thread stack and every authentic source owner through the role call.
#[inline(never)]
fn build_actual_role_source_v7() -> Box<PreHandoffCaseV5> {
    let live = activate_actual_case_v1(build_epoch_runtime_case_v1());
    let unsigned = first_apply_unsigned_v2(live);
    let first = first_apply_children_v2(first_apply_start_v2(unsigned));
    let cutoff = ordinary_cutoff_advance_v3(ordinary_cutoff_begin_v3(first));
    let checkpoint = checkpoint_prepare_execute_v4(checkpoint_prepare_begin_v4(cutoff));
    let first_seal = pre_handoff_seal_and_apply_v5(pre_handoff_begin_v5(checkpoint));
    let second_seal = pre_handoff_seal_and_apply_v5(first_seal);
    pre_handoff_commit_v5(second_seal)
}

impl trnm_consensus_signer_journal::HandoffSignatureProducerV1 for Key {
    fn sign_handoff(
        &mut self,
        request: trnm_consensus_signer_journal::HandoffSignatureRequestV1<'_>,
    ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
        self.calls += 1;
        Ok(SignatureBytes::from_array(
            self.key.sign(request.signing_root().as_bytes()).to_bytes(),
        ))
    }
}

type RolesCaseV7 = (
    tempfile::TempDir,
    super::EpochHandoffRolesRuntimeV7<Watermark, Watermark, Watermark>,
    Key,
    Watermark,
);
#[inline(never)]
fn commission_actual_roles_v7(case: Box<PreHandoffCaseV5>) -> Box<RolesCaseV7> {
    use trnm_consensus_signer_journal::SqliteHandoffSignerJournalV1;
    let (directory, owner, key) = *case;
    let mut retired = owner.retire_outgoing_epoch_v6().unwrap();
    let checkpoint = retired.confirm_retired_cut_v6().unwrap();
    let strict = retired.source.receipt.strict_context();
    let profile = HandoffSignerJournalProfileV1::for_epoch_handoff(
        strict.old_validator_set().clone(),
        strict.new_validator_set().clone(),
        *strict.old_consensus_parameters(),
        *strict.new_consensus_parameters(),
        retired.retired.profile_v1().author(),
        retired.retired.profile_v1().signer_profile_ref(),
        [0xe7; 32],
        64,
        4096,
        32 * 1024 * 1024,
    )
    .unwrap();
    super::confirm_role_profile_v7(&retired, &profile).unwrap();
    let mut wrong = HandoffSignerJournalProfileV1::for_epoch_handoff(
        strict.old_validator_set().clone(),
        strict.new_validator_set().clone(),
        *strict.old_consensus_parameters(),
        *strict.new_consensus_parameters(),
        profile.author(),
        [0xff; 32],
        [0xe8; 32],
        64,
        4096,
        32 * 1024 * 1024,
    )
    .unwrap();
    assert!(super::confirm_role_profile_v7(&retired, &wrong).is_err());
    wrong = HandoffSignerJournalProfileV1::for_epoch_handoff(
        strict.old_validator_set().clone(),
        strict.new_validator_set().clone(),
        *strict.old_consensus_parameters(),
        *strict.new_consensus_parameters(),
        profile.author(),
        profile.signer_profile_ref(),
        retired.retirement.record_v1().source_v1().scope(),
        64,
        4096,
        32 * 1024 * 1024,
    )
    .unwrap();
    assert!(super::confirm_role_profile_v7(&retired, &wrong).is_err());
    let watermark = Watermark::default();
    let path = directory.path().join("outgoing-role.db");
    let mut journal =
        SqliteHandoffSignerJournalV1::create_new(&path, profile.clone(), watermark.clone())
            .unwrap();
    let selected = journal.confirm_head_exact_v1().unwrap();
    let foreign_path = directory.path().join("foreign-role.db");
    let mut foreign =
        SqliteHandoffSignerJournalV1::create_new(&foreign_path, profile, Watermark::default())
            .unwrap();
    let foreign_facts = foreign.confirm_head_exact_v1().unwrap();
    assert!(!foreign_facts.belongs_to_owner_at_path_v1(&mut journal, &path));
    let roles = retired.into_handoff_roles_v7(journal, selected).unwrap();
    assert_eq!(roles.retired.checkpoint, checkpoint);
    assert!(roles.old_signature.is_none() && roles.new_signature.is_none());
    Box::new((directory, roles, key, watermark))
}

#[inline(never)]
fn actual_role_signatures_v7(case: Box<RolesCaseV7>) {
    use trnm_consensus_crypto::StrictEd25519Verifier;
    use trnm_consensus_types::{HandoffSignerRoleV1, SignatureVerifier};
    let (_directory, mut roles, mut key, watermark) = *case;
    let checkpoint = roles.retired.checkpoint;
    let native_before = sqlite_logical_image_v3(roles.retired.source.application.path());
    let safety_before = sqlite_logical_image_v3(roles.retired.source.journal.path_v1());
    let ordinary_calls = key.calls;
    // NewSet is a distinct durable decision and does not install the old-role
    // fence. Exercise the permitted NewSet -> OldSet order explicitly.
    let new = roles
        .sign_handoff_exact_v7(HandoffSignerRoleV1::NewSet, &mut key)
        .unwrap();
    assert_eq!(key.calls, ordinary_calls + 1);
    assert_eq!(new.role_watermark_v7().sequence(), 2);
    assert_eq!(roles.head.terminal_fence_checksum_v1(), None);
    assert_eq!(watermark.0.lock().unwrap().0, Some(new.role_watermark_v7()));
    let old = roles
        .sign_handoff_exact_v7(HandoffSignerRoleV1::OldSet, &mut key)
        .unwrap();
    assert_eq!(key.calls, ordinary_calls + 2);
    assert_eq!(old.role_watermark_v7().sequence(), 4);
    assert_eq!(old.node_checkpoint_v7(), checkpoint.checksum());
    assert_eq!(
        old.retirement_checksum_v7(),
        roles.retired.retirement.record_v1().checksum_v1()
    );
    assert_eq!(
        old.native_owner_cut_v7(),
        roles.retired.source.receipt.committed_owner_cut_ref_v1()
    );
    let old_fence = roles.head.terminal_fence_checksum_v1().unwrap();
    assert_eq!(watermark.0.lock().unwrap().0, Some(old.role_watermark_v7()));
    assert_ne!(old.intent_v7().fingerprint(), new.intent_v7().fingerprint());
    assert_ne!(
        old.intent_v7().signing_root(),
        new.intent_v7().signing_root()
    );
    assert_eq!(
        old.intent_v7().preimage().descriptor(),
        new.intent_v7().preimage().descriptor()
    );
    assert_eq!(roles.head.terminal_fence_checksum_v1(), Some(old_fence));
    let strict = roles.retired.source.receipt.strict_context();
    for (receipt, set) in [
        (&old, strict.old_validator_set()),
        (&new, strict.new_validator_set()),
    ] {
        assert!(StrictEd25519Verifier.verify(
            set.validator(receipt.intent_v7().validator_id()).unwrap(),
            &receipt.intent_v7().signing_root(),
            &receipt.signature_v7()
        ));
    }
    assert_eq!(
        roles
            .sign_handoff_exact_v7(HandoffSignerRoleV1::OldSet, &mut key)
            .unwrap(),
        old
    );
    assert_eq!(
        roles
            .sign_handoff_exact_v7(HandoffSignerRoleV1::NewSet, &mut key)
            .unwrap(),
        new
    );
    assert_eq!(
        key.calls,
        ordinary_calls + 2,
        "exact role replay must not reach the key"
    );
    assert_eq!(roles.head.exact_watermark_v1().sequence(), 4);
    assert_eq!(roles.retired.confirm_retired_cut_v6().unwrap(), checkpoint);
    assert!(sqlite_logical_image_v3(roles.retired.source.application.path()) == native_before);
    assert!(sqlite_logical_image_v3(roles.retired.source.journal.path_v1()) == safety_before);
    assert_eq!(roles.retired.checkpoint_store.load().unwrap(), checkpoint);
}

#[test]
fn actual_epoch_retired_handoff_roles_preserve_custody_and_exact_replay_v7() {
    actual_role_signatures_v7(commission_actual_roles_v7(build_actual_role_source_v7()));
}

#[inline(never)]
fn actual_role_pre_key_namespace_refusal_v7(case: Box<RolesCaseV7>) {
    use trnm_consensus_types::HandoffSignerRoleV1;
    let (_directory, mut roles, mut key, watermark) = *case;
    let calls = key.calls;
    let path = roles.retired.source.application.path().to_path_buf();
    *watermark.1.lock().unwrap() = Some(path.clone());
    let error = roles
        .sign_handoff_exact_v7(HandoffSignerRoleV1::OldSet, &mut key)
        .unwrap_err();
    assert!(
        watermark.1.lock().unwrap().is_none(),
        "real prepared-intent external callback must run: {error:#}"
    );
    assert!(path.with_extension("displaced-before-key").exists());
    assert_eq!(
        key.calls, calls,
        "native replacement after role reservation must reject before key"
    );
    assert_eq!(watermark.0.lock().unwrap().0.unwrap().sequence(), 1);
    let head = roles.journal.confirm_head_exact_v1().unwrap();
    assert!(head.pending_fingerprint_v1().is_some());
    assert_eq!(head.terminal_fence_checksum_v1(), None);
    assert!(roles
        .sign_handoff_exact_v7(HandoffSignerRoleV1::OldSet, &mut key)
        .unwrap_err()
        .to_string()
        .contains("owner fenced"));
    assert_eq!(key.calls, calls);
}

#[test]
fn actual_epoch_retired_handoff_role_callback_native_replacement_blocks_key_v7() {
    actual_role_pre_key_namespace_refusal_v7(commission_actual_roles_v7(
        build_actual_role_source_v7(),
    ));
}
