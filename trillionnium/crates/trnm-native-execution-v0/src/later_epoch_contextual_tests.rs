// Genuine M08 successor evidence. Every anchor below comes from complete
// strictly verified original evidence; no synthetic reference is constructed.

fn strict_fixture_runtime(
    evidence: &trnm_consensus_types::EpochActivationEvidenceBytesV0,
) -> trnm_consensus_crypto::StrictEpochRuntimeContextV1 {
    let old_set = decode_validator_set_v0_exact(&evidence.old_validator_set).unwrap();
    let parameters =
        decode_consensus_parameters_v0_exact(&evidence.old_consensus_parameters).unwrap();
    let decoded = trnm_consensus_types::decode_epoch_activation_evidence_v0_exact(
        evidence.as_preimages(),
        &old_set,
        &parameters,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let authority =
        trnm_consensus_crypto::verify_same_version_epoch_activation_authority_strict_v0(
            decoded.old_checkpoint_finality(),
            decoded.next_epoch_commitment(),
            decoded.authorization_kernel(),
            &old_set,
            &parameters,
            decoded.new_validator_set(),
            decoded.new_consensus_parameters(),
            decoded.authenticated_checkpoint_parent_header(),
        )
        .unwrap();
    trnm_consensus_crypto::StrictEpochRuntimeContextV1::from_activation_v1(authority).unwrap()
}

fn fixture_timeout(
    set: &ValidatorSet,
    parent_qc: QuorumCertificate,
    anchor: Option<&QcReferenceV0>,
    view: View,
) -> trnm_consensus_types::TimeoutCertificateV0 {
    use trnm_consensus_types::{SignatureBytes, TimeoutCertificateV0, TimeoutEntryV0, TimeoutVote};
    let ordinary = QcReferenceV0::ordinary(parent_qc);
    let entries = set
        .validators()
        .iter()
        .enumerate()
        .map(|(index, validator)| {
            let reference = if index == 0 {
                anchor.unwrap_or(&ordinary)
            } else {
                &ordinary
            };
            let root = TimeoutVote::signing_root_for_set(set, view, reference.qc_ref()).unwrap();
            TimeoutEntryV0::new(
                validator.id(),
                reference.qc_ref(),
                SignatureBytes::from_array(key(index).sign(root.as_bytes()).to_bytes()),
            )
            .unwrap()
        })
        .collect();
    let mut references = vec![ordinary.clone()];
    if let Some(anchor) = anchor {
        references.push(anchor.clone());
    }
    references.sort_by_key(QcReferenceV0::id);
    TimeoutCertificateV0::new(view, entries, references, ordinary.id(), set).unwrap()
}

fn contextual_checkpoint_proof(
    predecessor: &trnm_consensus_crypto::StrictEpochRuntimeContextV1,
    parent: &BlockHeader,
    headers: &[BlockHeader; 3],
    anchor: &QcReferenceV0,
    bad_proposal: bool,
) -> Vec<u8> {
    let set = predecessor.activation().new_validator_set();
    let parameters = predecessor.activation().new_consensus_parameters();
    assert_eq!(headers[2].view().get(), headers[1].view().get() + 2);
    let timeout = fixture_timeout(
        set,
        qc(&headers[1], set),
        Some(anchor),
        View::new(headers[2].view().get() - 1),
    );
    assert_eq!(timeout.selected_high_qc_digest(), qc(&headers[1], set).id());
    assert_eq!(timeout.referenced_qcs().len(), 2);
    assert!(timeout.referenced_qcs().contains(anchor));
    let terminal = certified_with_timeout(
        headers[2].clone(),
        qc(&headers[1], set),
        set,
        parameters,
        headers[1].timestamp_ms(),
        Some(timeout),
    );
    let terminal = if bad_proposal {
        let mut signature = *terminal.proposer_signature().as_bytes();
        signature[0] ^= 1;
        CertifiedHeaderV0::new(
            terminal.header().clone(),
            terminal.justify_qc().clone(),
            terminal.timeout_certificate().cloned(),
            None,
            Signature64::from_array(signature),
            terminal.certifying_qc().clone(),
            set,
            None,
            parameters,
            headers[1].timestamp_ms(),
        )
        .unwrap()
    } else {
        terminal
    };
    FinalityProofV0::new(
        certified(
            headers[0].clone(),
            qc(parent, set),
            set,
            parameters,
            parent.timestamp_ms(),
        ),
        certified(
            headers[1].clone(),
            qc(&headers[0], set),
            set,
            parameters,
            headers[0].timestamp_ms(),
        ),
        terminal,
        set,
        None,
        parameters,
        parent.timestamp_ms(),
    )
    .unwrap()
    .try_cev0_bytes()
    .unwrap()
}

// Produce a different, fully signed S20 from the same C18/C19 and selected set.
// Its view-zero anchor is authentic but is not the receiver's retained S20.
fn alternate_fixture_predecessor(
    original: &trnm_consensus_crypto::StrictEpochRuntimeContextV1,
) -> trnm_consensus_crypto::StrictEpochRuntimeContextV1 {
    let activation = original.activation();
    let set = activation.old_validator_set();
    let parameters = activation.old_consensus_parameters();
    let proof = activation.old_checkpoint_finality();
    let old_terminal = proof.grandchild().header();
    let parent = proof.child().header();
    let terminal = checkpoint_like_header_at_view(
        set,
        BlockKind::EpochSeal2,
        old_terminal.height().get(),
        parent.id(),
        old_terminal.state_root(),
        old_terminal.next_epoch_commitment_hash(),
        old_terminal.timestamp_ms(),
        old_terminal.payload_root(),
        old_terminal.receipts_root(),
        old_terminal.evidence_root(),
        parent.view().get() + 2,
    );
    let timeout = fixture_timeout(
        set,
        qc(parent, set),
        None,
        View::new(terminal.view().get() - 1),
    );
    let finality = FinalityProofV0::new(
        proof.finalized_block().clone(),
        proof.child().clone(),
        certified_with_timeout(
            terminal.clone(),
            qc(parent, set),
            set,
            parameters,
            parent.timestamp_ms(),
            Some(timeout),
        ),
        set,
        None,
        parameters,
        activation
            .authenticated_checkpoint_parent_header()
            .timestamp_ms(),
    )
    .unwrap();
    let mut fields = activation
        .authorization_kernel()
        .handoff_certificate()
        .descriptor()
        .fields()
        .clone();
    fields.terminal_old_block_id = terminal.id();
    fields.terminal_old_qc_digest = qc(&terminal, set).id();
    fields.terminal_old_view = terminal.view();
    let descriptor = HandoffDescriptorV0::new(fields).unwrap();
    let shares = |set: &ValidatorSet, root: trnm_consensus_types::SigningRoot| {
        set.validators()
            .iter()
            .enumerate()
            .take(3)
            .map(|(index, validator)| {
                SignatureShareV0::new(
                    validator.id(),
                    Signature64::from_array(key(index).sign(root.as_bytes()).to_bytes()),
                )
                .unwrap()
            })
            .collect()
    };
    let new_set = activation.new_validator_set();
    let certificate = HandoffCertificateV0::new(
        descriptor.clone(),
        shares(set, descriptor.old_set_signing_root()),
        shares(new_set, descriptor.new_set_signing_root()),
        set,
        new_set,
    )
    .unwrap();
    let kernel = EpochAnchorAuthorizationKernelV0::from_parts_v0(
        terminal.clone(),
        qc(&terminal, set),
        certificate,
        set,
        new_set,
    )
    .unwrap();
    let mut evidence = original.evidence_bytes().clone();
    evidence.old_checkpoint_finality = finality.try_cev0_bytes().unwrap();
    evidence.authorization_kernel = kernel.try_cev0_bytes().unwrap();
    let alternate = strict_fixture_runtime(&evidence);
    assert_eq!(
        alternate.activation().new_validator_set(),
        original.activation().new_validator_set()
    );
    assert_ne!(alternate.anchor_reference(), original.anchor_reference());
    alternate
}

fn historical_fixture_sequence(app: &DurableNativeApplicationV0) -> Vec<u8> {
    rusqlite::Connection::open(app.path())
        .unwrap()
        .query_row(
            "SELECT durable_sequence FROM native_application_metadata_v0 WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .unwrap()
}

#[inline(never)]
fn assert_contextual_checkpoint_rejections(
    app: &DurableNativeApplicationV0,
    predecessor: &trnm_consensus_crypto::StrictEpochRuntimeContextV1,
    parent: &BlockHeader,
    headers: &[BlockHeader; 3],
    original: &trnm_consensus_types::EpochActivationEvidenceBytesV0,
) {
    let set = predecessor.activation().new_validator_set();
    let parameters = predecessor.activation().new_consensus_parameters();
    assert!(
        trnm_consensus_types::decode_epoch_activation_evidence_v0_exact(
            original.as_preimages(),
            set,
            parameters,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .is_err(),
        "v0 cannot authorize the S20 synthetic TC reference"
    );
    let wrong_predecessor = alternate_fixture_predecessor(predecessor);
    let head = app.confirmed_committed_head_v0().unwrap();
    let sequence = historical_fixture_sequence(app);
    for (name, anchor, bad_proposal) in [
        (
            "canonical bad S30 proposal signature",
            predecessor.anchor_reference(),
            true,
        ),
        (
            "authentic but foreign S20 anchor",
            wrong_predecessor.anchor_reference(),
            false,
        ),
    ] {
        let mut evidence = original.clone();
        evidence.old_checkpoint_finality =
            contextual_checkpoint_proof(predecessor, parent, headers, anchor, bad_proposal);
        let structural_context = if bad_proposal {
            predecessor
        } else {
            &wrong_predecessor
        };
        let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
        let decoded = trnm_consensus_types::decode_epoch_activation_evidence_with_context_v1_exact(
            evidence.as_preimages(),
            structural_context.structural_context(),
            &mut budget,
        )
        .expect("negative retains complete canonical contextual framing");
        trnm_consensus_types::derive_successor_epoch_joint_structure_v1(
            &decoded,
            structural_context.structural_context(),
        )
        .expect("negative retains checkpoint/kernel/set field joins");
        if bad_proposal {
            assert!(predecessor
                .decode_verify_finality_v1(
                    &evidence.old_checkpoint_finality,
                    parent.timestamp_ms(),
                    &mut Cev0AdmissionBudgetV0::protocol_v0(),
                )
                .is_err());
        } else {
            wrong_predecessor
                .decode_verify_finality_v1(
                    &evidence.old_checkpoint_finality,
                    parent.timestamp_ms(),
                    &mut Cev0AdmissionBudgetV0::protocol_v0(),
                )
                .expect("foreign anchor proof has genuine valid signatures under its own context");
        }
        assert!(
            app.verify_later_epoch_checkpoint_finality_v1(
                app.inspect_later_epoch_checkpoint_context_v1().unwrap(),
                &evidence.authenticated_checkpoint_parent_header,
                &headers[0].try_cev0_bytes().unwrap(),
                &evidence.old_checkpoint_finality,
                &evidence.authorization_kernel,
                &evidence.next_epoch_commitment,
                &evidence.new_validator_set,
                &evidence.new_consensus_parameters,
            )
            .is_err(),
            "{name} must reject before a durable observation"
        );
        assert_eq!(app.confirmed_committed_head_v0().unwrap(), head, "{name}");
        assert_eq!(historical_fixture_sequence(app), sequence, "{name}");
    }
}

#[test]
fn repeated_contextual_s30_anchor_c28_c31_c32_commit_recover_and_sync() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("contextual.sqlite3");
    let seed = build_later_descendant_fixture(&path);
    let checkpoint = advance_repeated_checkpoint_variant(seed, &[], true);
    assert_eq!(checkpoint.terminal.view(), View::new(11));
    let runtime = checkpoint.runtime.as_ref().unwrap();
    let terminal = runtime.activation().old_checkpoint_finality().grandchild();
    assert_eq!(
        terminal.timeout_certificate().unwrap().timed_out_view(),
        View::new(10)
    );
    assert_eq!(
        terminal
            .timeout_certificate()
            .unwrap()
            .referenced_qcs()
            .len(),
        2
    );
    complete_repeated_handoff(&path, checkpoint);
}
