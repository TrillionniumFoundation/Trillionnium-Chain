// Test-only monotonic diagnostics. No key, path, proof bytes or runtime
// authority is logged, and these timings never select a consensus transition.
fn trace_actual_attachment_phase_v8(started: std::time::Instant, phase: &str) {
    eprintln!(
        "V8_PHASE phase={phase} elapsed_ms={}",
        started.elapsed().as_millis()
    );
}

// One genuine owner builds both independently durable local roles. Remote
// signatures are original cryptographic peer evidence, not local custody.
#[inline(never)]
fn genuine_joint_kernel_v8(
    roles: &super::EpochHandoffRolesRuntimeV7<Watermark, Watermark, Watermark>,
    include_local: bool,
) -> Vec<u8> {
    use trnm_consensus_types::{
        EpochAnchorAuthorizationKernelV0, HandoffCertificateV0, SignatureShareV0,
    };
    let context = roles.retired.source.receipt.strict_context();
    let author = roles.journal.profile().author();
    let shares = |set: &trnm_consensus_types::ValidatorSet,
                  local: &super::RecordedEpochHandoffSignatureV7| {
        set.validators()
            .iter()
            .enumerate()
            .filter_map(|(index, validator)| {
                if validator.id() == author && !include_local {
                    return None;
                }
                let signature = if validator.id() == author {
                    local.signature_v7()
                } else {
                    SignatureBytes::from_array(
                        SigningKey::from_bytes(&[20 + index as u8; 32])
                            .sign(local.intent_v7().signing_root().as_bytes())
                            .to_bytes(),
                    )
                };
                Some(SignatureShareV0::new(validator.id(), signature).unwrap())
            })
            .collect()
    };
    let certificate = HandoffCertificateV0::new(
        context.descriptor().clone(),
        shares(
            context.old_validator_set(),
            roles.old_signature.as_ref().unwrap(),
        ),
        shares(
            context.new_validator_set(),
            roles.new_signature.as_ref().unwrap(),
        ),
        context.old_validator_set(),
        context.new_validator_set(),
    )
    .unwrap();
    if !include_local {
        assert!(certificate
            .old_signatures()
            .iter()
            .all(|s| s.validator_id() != author));
        assert!(certificate
            .new_signatures()
            .iter()
            .all(|s| s.validator_id() != author));
    }
    let proof = roles
        .retired
        .source
        .driver
        .state()
        .last_finalization_proof()
        .unwrap();
    EpochAnchorAuthorizationKernelV0::from_parts_v0(
        proof.grandchild().header().clone(),
        proof.grandchild().certifying_qc().clone(),
        certificate,
        context.old_validator_set(),
        context.new_validator_set(),
    )
    .unwrap()
    .try_cev0_bytes()
    .unwrap()
}

#[inline(never)]
fn prepare_joint_roles_v8(case: Box<RolesCaseV7>) -> Box<RolesCaseV7> {
    use trnm_consensus_types::HandoffSignerRoleV1;
    let mut case = case;
    let started = std::time::Instant::now();
    trace_actual_attachment_phase_v8(started, "roles.begin");
    case.1
        .sign_handoff_exact_v7(HandoffSignerRoleV1::OldSet, &mut case.2)
        .unwrap();
    trace_actual_attachment_phase_v8(started, "roles.old-signed");
    case.1
        .sign_handoff_exact_v7(HandoffSignerRoleV1::NewSet, &mut case.2)
        .unwrap();
    trace_actual_attachment_phase_v8(started, "roles.new-signed");
    case
}

#[inline(never)]
fn actual_joint_attachment_v8(case: Box<RolesCaseV7>, incoming_watermark: Watermark) {
    let started = std::time::Instant::now();
    trace_actual_attachment_phase_v8(started, "attachment.begin");
    let (directory, mut roles, key, watermark) = *case;
    let original = roles.retired.checkpoint;
    let calls = key.calls;
    let native_path = roles.retired.source.application.path().to_path_buf();
    let node_path = roles.retired.checkpoint_store.database_path().to_path_buf();
    let safety_path = roles.retired.source.journal.path_v1().to_path_buf();
    let role_path = roles.journal.path().to_path_buf();
    let safety_before = sqlite_logical_image_v3(&safety_path);
    let role_before = sqlite_logical_image_v3(&role_path);
    let native_before = sqlite_logical_image_v3(&native_path);
    trace_actual_attachment_phase_v8(started, "attachment.source-images-read");
    let kernel = genuine_joint_kernel_v8(&roles, false);
    let with_local = genuine_joint_kernel_v8(&roles, true);
    trace_actual_attachment_phase_v8(started, "attachment.quorums-built");
    super::validate_joint_kernel_v8(&roles, &kernel).unwrap();
    super::validate_joint_kernel_v8(&roles, &with_local).unwrap();
    assert!(super::validate_joint_kernel_v8(&roles, &[]).is_err());
    let mut trailing = kernel.clone();
    trailing.push(0);
    assert!(super::validate_joint_kernel_v8(&roles, &trailing).is_err());
    // The actual local receipt is private, and must remain independently joined
    // even when the complete certificate legitimately omits that validator.
    let local = roles.old_signature.as_mut().unwrap();
    local.node_checkpoint[0] ^= 1;
    assert!(super::validate_joint_kernel_v8(&roles, &kernel)
        .unwrap_err()
        .to_string()
        .contains("local role custody"));
    roles.old_signature.as_mut().unwrap().node_checkpoint[0] ^= 1;
    assert!(sqlite_logical_image_v3(&native_path) == native_before);
    // Foreign facts are minted by a real independent role-journal producer,
    // not a scalar replacement of the selected owner.
    let mut foreign = trnm_consensus_signer_journal::SqliteHandoffSignerJournalV1::create_new(
        directory.path().join("foreign-v8-role.db"),
        roles.journal.profile().clone(),
        Watermark::default(),
    )
    .unwrap();
    let foreign_head = foreign.confirm_head_exact_v1().unwrap();
    let original_head = std::mem::replace(&mut roles.head, foreign_head);
    assert!(super::confirm_attachment_source_v8(&mut roles)
        .unwrap_err()
        .to_string()
        .contains("exact role head/fence"));
    roles.head = original_head;
    trace_actual_attachment_phase_v8(started, "attachment.foreign-owner-rejected");
    super::confirm_attachment_source_v8(&mut roles).unwrap();
    trace_actual_attachment_phase_v8(started, "attachment.source-confirmed");
    assert!(sqlite_logical_image_v3(&native_path) == native_before);
    let selected = roles.head.exact_watermark_v1();
    let mut attached = roles.attach_joint_handoff_v8(&kernel).unwrap();
    trace_actual_attachment_phase_v8(started, "attachment.native-and-node-committed");
    let checkpoint = attached.confirm_attached_cut_v8().unwrap();
    trace_actual_attachment_phase_v8(started, "attachment.cut-confirmed");
    assert_eq!(
        checkpoint.fields().phase,
        EpochCheckpointPhaseV1::EpochHandoffAttachedNative13
    );
    assert_eq!(
        checkpoint.fields().generation,
        original.fields().generation + 1
    );
    assert_eq!(
        checkpoint.fields().predecessor_checksum,
        original.checksum()
    );
    assert_eq!(
        checkpoint.fields().target_safety,
        original.fields().target_safety
    );
    assert_eq!(
        checkpoint.fields().application,
        original.fields().application
    );
    assert_eq!(checkpoint.fields().retired, original.fields().retired);
    assert_eq!(attached.roles.retired.checkpoint, original);
    assert_eq!(
        checkpoint.fields().edge.native_authorization_id,
        attached.edge.successor_binding()
    );
    assert_ne!(
        checkpoint.fields().edge.native_authorization_id,
        original.fields().edge.native_authorization_id
    );
    assert_eq!(attached.roles.head.exact_watermark_v1(), selected);
    assert_eq!(watermark.0.lock().unwrap().0, Some(selected));
    let native_after = sqlite_logical_image_v3(&native_path);
    assert!(native_after != native_before);
    assert_eq!(
        attached.confirm_joint_handoff_exact_v8(&kernel).unwrap(),
        checkpoint
    );
    assert_eq!(
        attached.confirm_joint_handoff_exact_v8(&kernel).unwrap(),
        checkpoint
    );
    assert!(sqlite_logical_image_v3(&native_path) == native_after);
    assert!(sqlite_logical_image_v3(&safety_path) == safety_before);
    assert!(sqlite_logical_image_v3(&role_path) == role_before);
    assert_eq!(key.calls, calls, "attachment accepts no key producer");
    trace_actual_attachment_phase_v8(started, "attachment.exact-retries-confirmed");
    assert_ne!(
        kernel, with_local,
        "independently valid quorum encodings differ"
    );
    // The last incoming-retirement external callback changes the role path
    // AFTER its own external/local head check. The final callback-free M03
    // comparison must catch even byte-identical namespace replacement.
    *incoming_watermark.4.lock().unwrap() = Some(role_path.clone());
    let error = attached.confirm_attached_cut_v8().unwrap_err();
    assert!(
        incoming_watermark.4.lock().unwrap().is_none(),
        "actual retirement callback did not run: {error:#}"
    );
    let displaced = role_path.with_extension("retirement-callback-displaced");
    assert!(displaced.exists());
    assert!(
        format!("{error:#}").contains("FileIdentityChanged"),
        "{error:#}"
    );
    std::fs::remove_file(&role_path).unwrap();
    std::fs::rename(&displaced, &role_path).unwrap();
    assert!(attached
        .confirm_joint_handoff_exact_v8(&kernel)
        .unwrap_err()
        .to_string()
        .contains("owner fenced"));
    assert!(sqlite_logical_image_v3(&native_path) == native_after);
    assert!(sqlite_logical_image_v3(&role_path) == role_before);
    assert_eq!(key.calls, calls);
    let binding = attached.edge.successor_binding();
    drop(attached);
    trace_actual_attachment_phase_v8(started, "attachment.callback-substitution-fenced");
    let application =
        DurableNativeApplicationV0::open(&native_path, native_checkpoint_fixture_config_v1())
            .unwrap();
    trace_actual_attachment_phase_v8(started, "recovery.native-opened");
    let requirements = application
        .inspect_later_epoch_application_edge_requirements_v1(
            original.fields().application.block_id,
        )
        .unwrap();
    let recovered = application
        .recover_later_epoch_application_edge_v1(&requirements)
        .unwrap();
    trace_actual_attachment_phase_v8(started, "recovery.edge-recovered");
    assert_eq!(recovered.successor_binding(), binding);
    assert_eq!(
        recovered.checkpoint_commit_sequence(),
        original.fields().application.commit_sequence
    );
    let mut store =
        crate::SqliteEpochNodeCheckpointStoreV1::open_existing(&node_path, &checkpoint).unwrap();
    assert_eq!(store.load().unwrap(), checkpoint);
    trace_actual_attachment_phase_v8(started, "recovery.node-checkpoint-confirmed");
    // This cold comparison grants no V8 owner, Core driver or new signer.
    drop((store, application, directory));
}

// V8 is the end-to-end attachment test. The stage-specific V2--V7 tests
// already exercise malformed proposals, wrong profiles, foreign owners and
// redundant readbacks. Re-running those negative probes while constructing the
// V8 source used to dominate the real happy path on slower CI hosts. These
// helpers call the same product owners and persistence transitions, but perform
// only the positive transition once. They do not bypass any production check.
#[inline(never)]
fn settle_first_positive_v8(case: Box<FirstApplyCaseV2>) -> Box<FirstApplyCaseV2> {
    let (directory, owner, key) = *case;
    let third = owner.prepared[2].prepared.header().unwrap();
    let qc = first_apply_qc_v2(&third, owner.runtime.edge.new_validator_set());
    let owner = owner.observe_first_finality_qc_v2(qc).unwrap();
    let mut owner = owner
        .apply_first_finalization_v2(
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    owner.settled_checkpoint_v2().unwrap();
    Box::new((directory, owner, key))
}

#[inline(never)]
fn ordinary_cutoff_positive_v8(case: Box<FirstApplyCaseV2>) -> Box<OrdinaryCutoffCaseV3> {
    let (directory, settled, mut key) = *settle_first_positive_v8(case);
    let mut owner = settled.into_ordinary_continuation_v3().unwrap();
    for _ in 12..=15 {
        let proposal = first_apply_child_proposal_v2(&owner.inner);
        owner = owner.execute_ordinary_proposal_v3(proposal).unwrap();
        let (next, _) = owner.sign_ordinary_vote_v3(&mut key).unwrap();
        owner = next;
        let last = owner.inner.prepared[2].prepared.header().unwrap();
        let qc = first_apply_qc_v2(&last, owner.inner.runtime.edge.new_validator_set());
        owner = owner.observe_ordinary_finality_qc_v3(qc).unwrap();
        owner = owner
            .apply_ordinary_front_v3(
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
    }
    owner.settled_cutoff_checkpoint_v3().unwrap();
    Box::new((directory, owner, key, None))
}

#[inline(never)]
fn checkpoint_positive_v8(case: Box<OrdinaryCutoffCaseV3>) -> Box<CheckpointCaseV4> {
    let (directory, owner, mut key, _) = *case;
    let mut owner = owner.into_checkpoint_preparation_v4().unwrap();
    let good = {
        let inner = owner.inner.as_ref().unwrap();
        let selection = inner
            .runtime
            .application
            .compute_later_epoch_selection_v1(trnm_native_application::HeightV0::new(15))
            .unwrap();
        application_child_proposal_v4(inner, Some(selection.next_epoch_commitment().id()))
    };
    owner.execute_checkpoint_proposal_v4(good).unwrap();
    let (mut owner, _) = owner.sign_checkpoint_vote_v4(&mut key).unwrap();
    owner.prepared_checkpoint_cut_v4().unwrap();
    Box::new((directory, owner, key))
}

#[inline(never)]
fn pre_handoff_begin_positive_v8(case: Box<CheckpointCaseV4>) -> Box<PreHandoffCaseV5> {
    let (directory, owner, key) = *case;
    Box::new((directory, owner.into_pre_handoff_v5().unwrap(), key))
}

#[inline(never)]
fn seal_and_apply_positive_v8(case: Box<PreHandoffCaseV5>) -> Box<PreHandoffCaseV5> {
    let (directory, mut owner, mut key) = *case;
    let proposal = genuine_seal_proposal_v5(&owner, false, false);
    let seal = proposal.block().id();
    owner.admit_seal_proposal_v5(proposal).unwrap();
    owner = owner
        .apply_preceding_application_v5(
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    let (owner, vote) = owner.sign_seal_vote_v5(&mut key).unwrap();
    let trnm_consensus_core::OutboundMessage::Vote(vote) = vote else {
        panic!("real seal Vote required")
    };
    assert_eq!(vote.block_id(), seal);
    Box::new((directory, owner, key))
}

#[inline(never)]
fn pre_handoff_commit_positive_v8(case: Box<PreHandoffCaseV5>) -> Box<PreHandoffCaseV5> {
    let (directory, mut owner, key) = *case;
    let terminal = owner.seals[1].block().header();
    let qc = first_apply_qc_v2(
        terminal,
        owner
            .inner
            .as_ref()
            .unwrap()
            .runtime
            .edge
            .new_validator_set(),
    );
    owner.observe_terminal_qc_v5(qc).unwrap();
    owner = owner
        .apply_pre_handoff_checkpoint_v5(
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    owner.settled_pre_handoff_cut_v5().unwrap();
    Box::new((directory, owner, key))
}

#[inline(never)]
fn commission_roles_positive_v8(case: Box<PreHandoffCaseV5>) -> Box<RolesCaseV7> {
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
    let watermark = Watermark::default();
    let path = directory.path().join("outgoing-role.db");
    let mut journal =
        SqliteHandoffSignerJournalV1::create_new(&path, profile, watermark.clone()).unwrap();
    let selected = journal.confirm_head_exact_v1().unwrap();
    let roles = retired.into_handoff_roles_v7(journal, selected).unwrap();
    assert_eq!(roles.retired.checkpoint, checkpoint);
    Box::new((directory, roles, key, watermark))
}

#[inline(never)]
fn build_actual_attachment_case_v8() -> (Box<RolesCaseV7>, Watermark) {
    let started = std::time::Instant::now();
    trace_actual_attachment_phase_v8(started, "build.begin");
    let initial = build_epoch_runtime_case_v1();
    trace_actual_attachment_phase_v8(started, "build.genesis-ready");
    let incoming_watermark = initial.recovery.old_watermark.clone();
    let live = activate_actual_case_v1(initial);
    trace_actual_attachment_phase_v8(started, "build.activation-ready");
    let unsigned = first_apply_unsigned_v2(live);
    trace_actual_attachment_phase_v8(started, "build.first-proposal-ready");
    let first = first_apply_children_v2(first_apply_start_v2(unsigned));
    trace_actual_attachment_phase_v8(started, "build.first-finality-ready");
    let cutoff = ordinary_cutoff_positive_v8(first);
    trace_actual_attachment_phase_v8(started, "build.cutoff-ready");
    let checkpoint = checkpoint_positive_v8(cutoff);
    trace_actual_attachment_phase_v8(started, "build.checkpoint-prepared");
    let first_seal = seal_and_apply_positive_v8(pre_handoff_begin_positive_v8(checkpoint));
    trace_actual_attachment_phase_v8(started, "build.first-seal-ready");
    let second_seal = seal_and_apply_positive_v8(first_seal);
    trace_actual_attachment_phase_v8(started, "build.second-seal-ready");
    let roles = commission_roles_positive_v8(pre_handoff_commit_positive_v8(second_seal));
    trace_actual_attachment_phase_v8(started, "build.roles-commissioned");
    let roles = prepare_joint_roles_v8(roles);
    trace_actual_attachment_phase_v8(started, "build.ready");
    (roles, incoming_watermark)
}

#[test]
fn actual_epoch_handoff_joint_attachment_and_exact_retry_v8() {
    let (case, incoming_watermark) = build_actual_attachment_case_v8();
    actual_joint_attachment_v8(case, incoming_watermark);
}
