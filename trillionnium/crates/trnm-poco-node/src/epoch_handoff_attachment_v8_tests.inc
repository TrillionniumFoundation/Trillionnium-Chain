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

// Diagnostic-only monotonic timings. Keep every real owner call, negative,
// exact retry and cold reopen below; neither time nor these labels authorizes
// a transition or changes the runner's original per-case deadline.
fn trace_v8_phase(phase: &str, start: std::time::Instant) {
    eprintln!("V8_PHASE phase={phase} elapsed_ms={}", start.elapsed().as_millis());
}

#[inline(never)]
fn prepare_joint_roles_v8(case: Box<RolesCaseV7>) -> Box<RolesCaseV7> {
    use trnm_consensus_types::HandoffSignerRoleV1;
    let start = std::time::Instant::now();
    trace_v8_phase("roles-start", start);
    let mut case = case;
    case.1
        .sign_handoff_exact_v7(HandoffSignerRoleV1::OldSet, &mut case.2)
        .unwrap();
    trace_v8_phase("old-role-signed", start);
    case.1
        .sign_handoff_exact_v7(HandoffSignerRoleV1::NewSet, &mut case.2)
        .unwrap();
    trace_v8_phase("new-role-signed", start);
    case
}

#[inline(never)]
fn actual_joint_attachment_v8(case: Box<RolesCaseV7>, incoming_watermark: Watermark) {
    let start = std::time::Instant::now();
    trace_v8_phase("attachment-checks-start", start);
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
    trace_v8_phase("source-images-read", start);
    let kernel = genuine_joint_kernel_v8(&roles, false);
    let with_local = genuine_joint_kernel_v8(&roles, true);
    super::validate_joint_kernel_v8(&roles, &kernel).unwrap();
    super::validate_joint_kernel_v8(&roles, &with_local).unwrap();
    trace_v8_phase("both-joint-quorums-verified", start);
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
    super::confirm_attachment_source_v8(&mut roles).unwrap();
    assert!(sqlite_logical_image_v3(&native_path) == native_before);
    trace_v8_phase("source-and-custody-negatives-complete", start);
    let selected = roles.head.exact_watermark_v1();
    let mut attached = roles.attach_joint_handoff_v8(&kernel).unwrap();
    trace_v8_phase("joint-attached", start);
    let checkpoint = attached.confirm_attached_cut_v8().unwrap();
    trace_v8_phase("attached-cut-readback", start);
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
    trace_v8_phase("first-exact-retry", start);
    assert_eq!(
        attached.confirm_joint_handoff_exact_v8(&kernel).unwrap(),
        checkpoint
    );
    trace_v8_phase("second-exact-retry", start);
    assert!(sqlite_logical_image_v3(&native_path) == native_after);
    assert!(sqlite_logical_image_v3(&safety_path) == safety_before);
    assert!(sqlite_logical_image_v3(&role_path) == role_before);
    assert_eq!(key.calls, calls, "attachment accepts no key producer");
    assert_ne!(
        kernel, with_local,
        "independently valid quorum encodings differ"
    );
    // The last incoming-retirement external callback changes the role path
    // AFTER its own external/local head check. The final callback-free M03
    // comparison must catch even byte-identical namespace replacement.
    *incoming_watermark.4.lock().unwrap() = Some(role_path.clone());
    let error = attached.confirm_attached_cut_v8().unwrap_err();
    trace_v8_phase("late-callback-replacement-rejected", start);
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
    trace_v8_phase("cold-recovery-start", start);
    let application =
        DurableNativeApplicationV0::open(&native_path, native_checkpoint_fixture_config_v1())
            .unwrap();
    trace_v8_phase("native-cold-open", start);
    let requirements = application
        .inspect_later_epoch_application_edge_requirements_v1(
            original.fields().application.block_id,
        )
        .unwrap();
    let recovered = application
        .recover_later_epoch_application_edge_v1(&requirements)
        .unwrap();
    trace_v8_phase("native-edge-recovered", start);
    assert_eq!(recovered.successor_binding(), binding);
    assert_eq!(
        recovered.checkpoint_commit_sequence(),
        original.fields().application.commit_sequence
    );
    let mut store =
        crate::SqliteEpochNodeCheckpointStoreV1::open_existing(&node_path, &checkpoint).unwrap();
    assert_eq!(store.load().unwrap(), checkpoint);
    // This cold comparison grants no V8 owner, Core driver or new signer.
    drop((store, application, directory));
    trace_v8_phase("all-attachment-checks-complete", start);
}

#[inline(never)]
fn build_actual_attachment_case_v8() -> (Box<RolesCaseV7>, Watermark) {
    let start = std::time::Instant::now();
    trace_v8_phase("real-owner-build-start", start);
    let initial = build_epoch_runtime_case_v1();
    trace_v8_phase("initial-owner-built", start);
    let incoming_watermark = initial.recovery.old_watermark.clone();
    let live = activate_actual_case_v1(initial);
    trace_v8_phase("initial-owner-activated", start);
    let unsigned = first_apply_unsigned_v2(live);
    let first = first_apply_children_v2(first_apply_start_v2(unsigned));
    trace_v8_phase("first-new-blocks-applied", start);
    let cutoff = ordinary_cutoff_advance_v3(ordinary_cutoff_begin_v3(first));
    trace_v8_phase("cutoff-applied", start);
    let checkpoint = checkpoint_prepare_execute_v4(checkpoint_prepare_begin_v4(cutoff));
    trace_v8_phase("checkpoint-prepared", start);
    let first_seal = pre_handoff_seal_and_apply_v5(pre_handoff_begin_v5(checkpoint));
    trace_v8_phase("first-seal-applied", start);
    let second_seal = pre_handoff_seal_and_apply_v5(first_seal);
    trace_v8_phase("second-seal-applied", start);
    let roles = commission_actual_roles_v7(pre_handoff_commit_v5(second_seal));
    trace_v8_phase("pre-handoff-committed-roles-commissioned", start);
    let signed = prepare_joint_roles_v8(roles);
    trace_v8_phase("real-owner-build-complete", start);
    (signed, incoming_watermark)
}

#[test]
fn actual_epoch_handoff_joint_attachment_and_exact_retry_v8() {
    let (case, incoming_watermark) = build_actual_attachment_case_v8();
    actual_joint_attachment_v8(case, incoming_watermark);
}
