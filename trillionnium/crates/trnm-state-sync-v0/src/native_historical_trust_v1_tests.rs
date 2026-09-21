// Uses the real Ed25519 corpus and proof builder in native_trust_v1_tests.
// The application state roots remain inert fixture claims: these tests assert
// historical header trust/session binding, never execution or installation.

fn ordinary_epoch_finality_with_anchor_timeouts(
    activation: &trnm_consensus_crypto::StrictSameVersionEpochActivationAuthorityV0,
    first: &trnm_consensus_types::CertifiedHeaderV0,
) -> trnm_consensus_types::FinalityProofV0 {
    use ed25519_dalek::{Signer, SigningKey};
    use trnm_consensus_types::*;
    let set = activation.new_validator_set();
    let parameters = activation.new_consensus_parameters();
    let key = |validator: &Validator| {
        let mut seed = Sha256::new();
        seed.update(b"trnm.poco-bft.checkpoint-finality.private-fixture.v0:");
        seed.update(validator.id().as_bytes());
        let key = SigningKey::from_bytes(&seed.finalize().into());
        assert_eq!(
            key.verifying_key().to_bytes(),
            validator.consensus_key().into_bytes()
        );
        key
    };
    assert!(first.justify_qc().as_synthetic().is_some());
    let anchor = first.justify_qc();
    let mut parent = first.clone();
    let mut certified = Vec::new();
    for view in [4, 7, 10] {
        let proposer = &set.validators()[(view as usize - 1) % set.validators().len()];
        let header = BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(view),
            Height::new(parent.header().height().get() + 1),
            BlockKind::Regular,
            parent.header().id(),
            proposer.id(),
            set.id(),
            parameters.hash(),
            PayloadDigest::new([0x41; 32]),
            StateRoot::new([0x42; 32]),
            ReceiptsRoot::new([0x43; 32]),
            EvidenceRoot::new([0x44; 32]),
            parent.header().timestamp_ms() + 1,
            None,
        )
        .unwrap();
        let justify = QcReferenceV0::ordinary(parent.certifying_qc().clone());
        let entries = set
            .validators()
            .iter()
            .enumerate()
            .map(|(index, validator)| {
                let high = if index == 0 { anchor } else { &justify };
                let root =
                    TimeoutVote::signing_root_for_set(set, View::new(view - 1), high.qc_ref())
                        .unwrap();
                TimeoutEntryV0::new(
                    validator.id(),
                    high.qc_ref(),
                    SignatureBytes::from_array(key(validator).sign(root.as_bytes()).to_bytes()),
                )
                .unwrap()
            })
            .collect();
        let mut references = vec![anchor.clone(), justify.clone()];
        references.sort_by_key(QcReferenceV0::id);
        let timeout =
            TimeoutCertificateV0::new(View::new(view - 1), entries, references, justify.id(), set)
                .unwrap();
        let root =
            Vote::signing_root_for_set(set, header.view(), header.height(), header.id()).unwrap();
        let votes = set
            .validators()
            .iter()
            .map(|validator| {
                Vote::new(
                    set.chain_id(),
                    set.protocol_version(),
                    set.epoch(),
                    header.view(),
                    header.height(),
                    header.id(),
                    set.id(),
                    validator.id(),
                    SignatureBytes::from_array(key(validator).sign(root.as_bytes()).to_bytes()),
                    set,
                )
                .unwrap()
            })
            .collect();
        let qc = QuorumCertificate::new(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            header.view(),
            header.height(),
            header.id(),
            set.id(),
            votes,
            set,
        )
        .unwrap();
        let proposal_root =
            ProposalWitnessV0::signing_root_for(&header, &justify, Some(&timeout), None).unwrap();
        let block = CertifiedHeaderV0::new(
            header,
            justify,
            Some(timeout),
            None,
            SignatureBytes::from_array(key(proposer).sign(proposal_root.as_bytes()).to_bytes()),
            qc,
            set,
            None,
            parameters,
            parent.header().timestamp_ms(),
        )
        .unwrap();
        parent = block.clone();
        certified.push(block);
    }
    let [target, child, grandchild] = certified.try_into().unwrap();
    FinalityProofV0::new(
        target,
        child,
        grandchild,
        set,
        None,
        parameters,
        first.header().timestamp_ms(),
    )
    .unwrap()
}

#[test]
fn native_historical_trust_accepts_ordinary_terminal_with_synthetic_anchor_timeouts() {
    use trnm_consensus_types::{
        decode_epoch_runtime_finality_proof_v1_exact_with_budget, BlockKind,
        EpochRuntimeContextDataV1,
    };
    let (evidence, set, parameters, binding) = fixture("positive");
    let activation = recover_epoch_activation_authority_strict_v0(
        evidence.as_preimages(),
        &set,
        &parameters,
        binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let (raw_first, first_expected, _) = first_epoch_finality_bytes(&activation);
    let strict_first = decode_verify_epoch_first_finality_strict_v1(
        evidence.as_preimages(),
        &raw_first,
        &set,
        &parameters,
        first_expected,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let first = strict_first.proof().finalized_block();
    let proof = ordinary_epoch_finality_with_anchor_timeouts(&activation, first);
    for certified in [proof.finalized_block(), proof.child(), proof.grandchild()] {
        assert_eq!(certified.header().block_kind(), BlockKind::Regular);
        assert!(certified
            .timeout_certificate()
            .unwrap()
            .referenced_qcs()
            .iter()
            .any(|reference| reference.as_synthetic().is_some()));
    }
    let raw = proof.try_cev0_bytes().unwrap();
    let expected = expectation(proof.finalized_block().header(), first.header());
    assert!(decode_verify_finality_proof_strict_v0(
        POCO_THREE_CHAIN_PROOF_CLASS_V0,
        &raw,
        activation.new_validator_set(),
        activation.new_consensus_parameters(),
        expected,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .is_err());
    let checkpoint = activation.old_checkpoint_finality();
    let anchor = pinned(checkpoint.finalized_block().header(), &set, &parameters);
    let encoded = [
        checkpoint.child().header().try_cev0_bytes().unwrap(),
        checkpoint.grandchild().header().try_cev0_bytes().unwrap(),
        first.header().try_cev0_bytes().unwrap(),
        proof.finalized_block().header().try_cev0_bytes().unwrap(),
    ];
    let headers = encoded.each_ref().map(Vec::as_slice);
    let mut successful = Cev0AdmissionBudgetV0::protocol_v0();
    successful.charge_signature_work(7).unwrap();
    let verified = verify_native_historical_trust_path_v1(
        &anchor,
        &headers,
        &[evidence.as_preimages()],
        &raw,
        HistoricalAncestryLimitsV1::default(),
        &mut successful,
    )
    .unwrap();
    assert_eq!(verified.terminal_header(), proof.finalized_block().header());
    assert_eq!(verified.snapshot_trust_path().link_count(), 2);

    // An independently trusted first-new header does not also supply the
    // pre-anchor activation context needed by these synthetic TC references.
    let later_anchor = pinned(
        first.header(),
        activation.new_validator_set(),
        activation.new_consensus_parameters(),
    );
    assert!(verify_native_historical_trust_path_v1(
        &later_anchor,
        &headers[3..],
        &[],
        &raw,
        HistoricalAncestryLimitsV1::default(),
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .is_err());

    let signature = proof
        .finalized_block()
        .timeout_certificate()
        .unwrap()
        .entries()[0]
        .signature()
        .as_bytes();
    let offset = raw
        .windows(64)
        .position(|bytes| bytes == signature)
        .unwrap();
    let mut corrupt = raw;
    corrupt[offset] ^= 1;
    let decoded = decode_epoch_activation_evidence_v0_exact(
        evidence.as_preimages(),
        &set,
        &parameters,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let context = EpochRuntimeContextDataV1::from_decoded_evidence_v1(&decoded).unwrap();
    let structurally_valid = decode_epoch_runtime_finality_proof_v1_exact_with_budget(
        &corrupt,
        &context,
        first.header().timestamp_ms(),
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    assert_eq!(structurally_valid.try_cev0_bytes().unwrap(), corrupt);
    let mut failed = Cev0AdmissionBudgetV0::protocol_v0();
    failed.charge_signature_work(7).unwrap();
    assert!(verify_native_historical_trust_path_v1(
        &anchor,
        &headers,
        &[evidence.as_preimages()],
        &corrupt,
        HistoricalAncestryLimitsV1::default(),
        &mut failed,
    )
    .is_err());
    assert!(failed.signature_work() > 7);
    assert_eq!(failed.signature_work(), successful.signature_work());
}

#[test]
fn native_historical_trust_projects_handoff_with_distinct_session_binding() {
    let (evidence, set, parameters, binding) = fixture("positive");
    let activation = recover_epoch_activation_authority_strict_v0(
        evidence.as_preimages(),
        &set,
        &parameters,
        binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let (proof, expected, _) = first_epoch_finality_bytes(&activation);
    let first = decode_verify_epoch_first_finality_strict_v1(
        evidence.as_preimages(),
        &proof,
        &set,
        &parameters,
        expected,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let checkpoint = activation
        .old_checkpoint_finality()
        .finalized_block()
        .header();
    let anchor = pinned(checkpoint, &set, &parameters);
    let encoded = [
        activation
            .old_checkpoint_finality()
            .child()
            .header()
            .try_cev0_bytes()
            .unwrap(),
        activation
            .old_checkpoint_finality()
            .grandchild()
            .header()
            .try_cev0_bytes()
            .unwrap(),
        first
            .proof()
            .finalized_block()
            .header()
            .try_cev0_bytes()
            .unwrap(),
    ];
    let headers = encoded.each_ref().map(Vec::as_slice);
    let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
    budget.charge_signature_work(7).unwrap();
    let historical = verify_native_historical_trust_path_v1(
        &anchor,
        &headers,
        &[evidence.as_preimages()],
        &proof,
        HistoricalAncestryLimitsV1::default(),
        &mut budget,
    )
    .unwrap();
    assert!(budget.signature_work() > 7);
    let mut single_pass = Cev0AdmissionBudgetV0::protocol_v0();
    single_pass.charge_signature_work(7).unwrap();
    let decoded = trnm_consensus_types::decode_epoch_activation_evidence_v0_exact(
        evidence.as_preimages(),
        &set,
        &parameters,
        &mut single_pass,
    )
    .unwrap();
    trnm_consensus_types::decode_epoch_first_finality_proof_v1_exact_with_budget(
        &proof,
        &decoded,
        &mut single_pass,
    )
    .unwrap();
    assert_eq!(
        budget.signature_work(),
        single_pass.signature_work(),
        "terminal handoff charges activation once and terminal proof once"
    );
    assert_eq!(
        historical.terminal_header(),
        first.proof().finalized_block().header()
    );
    assert_eq!(
        historical.terminal_validator_set(),
        activation.new_validator_set()
    );
    assert_eq!(
        historical.terminal_parameters(),
        activation.new_consensus_parameters()
    );
    let projection = historical.snapshot_trust_path();
    assert_eq!(
        projection.link_count(),
        1,
        "seals are not application links"
    );
    assert_eq!(projection.anchor().checkpoint_digest, anchor.pin());
    assert_eq!(projection.terminal().parent_checkpoint_digest, anchor.pin());
    assert_eq!(
        projection.terminal().validator_set_digest.0,
        *set.id().as_bytes()
    );
    assert_eq!(
        projection.terminal().next_validator_set_digest.0,
        *activation.new_validator_set().id().as_bytes()
    );

    let repeated = verify_native_historical_trust_path_v1(
        &anchor,
        &headers,
        &[evidence.as_preimages()],
        &proof,
        HistoricalAncestryLimitsV1::default(),
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    assert_eq!(projection, repeated.snapshot_trust_path());
    let per_step = verify_native_trust_path_v1(
        &anchor,
        &[NativeTrustStepV1::EpochFirst {
            evidence: evidence.as_preimages(),
            proof: &proof,
            expected,
        }],
        NativeTrustPathLimitsV1::default(),
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    assert_eq!(historical.terminal_header(), per_step.terminal_header());
    assert_ne!(
        projection.path_digest(),
        per_step.snapshot_trust_path().path_digest()
    );
    assert_ne!(
        projection.terminal().checkpoint_digest,
        per_step.snapshot_trust_path().terminal().checkpoint_digest
    );
    let mut manifest = SnapshotManifestV0 {
        chain_id: projection.anchor().chain_id,
        protocol_digest: projection.anchor().protocol_digest,
        height: projection.terminal().height,
        epoch: projection.terminal().epoch,
        state_root: projection.terminal().state_root,
        chunk_root: Digest32V0([4; 32]),
        chunk_count: 1,
        maximum_chunk_bytes: 16,
        total_bytes: 16,
        schema_digest: Digest32V0([5; 32]),
        checkpoint_digest: projection.terminal().checkpoint_digest,
        manifest_digest: Digest32V0([0; 32]),
    };
    manifest.manifest_digest = manifest.canonical_digest();
    let application = NativeApplicationCheckpointV1 {
        schema_digest: manifest.schema_digest,
        application_version: 1,
    };
    assert!(NativeStateSyncSessionV1::begin(historical, manifest.clone(), application).is_ok());
    assert!(matches!(
        NativeStateSyncSessionV1::begin(per_step, manifest, application),
        Err(StateSyncErrorV0::ManifestTrustMismatch)
    ));
}

#[test]
fn native_historical_trust_rejects_unjoined_history_and_retains_failed_crypto_work() {
    let (evidence, set, parameters, binding) = fixture("positive");
    let activation = recover_epoch_activation_authority_strict_v0(
        evidence.as_preimages(),
        &set,
        &parameters,
        binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let (proof, expected, signature_offsets) = first_epoch_finality_bytes(&activation);
    let first = decode_verify_epoch_first_finality_strict_v1(
        evidence.as_preimages(),
        &proof,
        &set,
        &parameters,
        expected,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let checkpoint_proof = activation.old_checkpoint_finality();
    let anchor = pinned(
        activation.authenticated_checkpoint_parent_header(),
        &set,
        &parameters,
    );
    let encoded = [
        checkpoint_proof
            .finalized_block()
            .header()
            .try_cev0_bytes()
            .unwrap(),
        checkpoint_proof.child().header().try_cev0_bytes().unwrap(),
        checkpoint_proof
            .grandchild()
            .header()
            .try_cev0_bytes()
            .unwrap(),
        first
            .proof()
            .finalized_block()
            .header()
            .try_cev0_bytes()
            .unwrap(),
    ];
    let headers = encoded.each_ref().map(Vec::as_slice);
    let mut successful = Cev0AdmissionBudgetV0::protocol_v0();
    let verified = verify_native_historical_trust_path_v1(
        &anchor,
        &headers,
        &[evidence.as_preimages()],
        &proof,
        HistoricalAncestryLimitsV1::default(),
        &mut successful,
    )
    .unwrap();
    assert_eq!(verified.snapshot_trust_path().link_count(), 2);

    let total = proof.len()
        + headers.iter().map(|header| header.len()).sum::<usize>()
        + evidence_parts(evidence.as_preimages())
            .iter()
            .map(|root| root.len())
            .sum::<usize>();
    let exact = HistoricalAncestryLimitsV1 {
        maximum_headers: headers.len(),
        maximum_transitions: 1,
        maximum_total_bytes: total,
    };
    let bounded = verify_native_historical_trust_path_v1(
        &anchor,
        &headers,
        &[evidence.as_preimages()],
        &proof,
        exact,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    assert_eq!(
        verified.snapshot_trust_path(),
        bounded.snapshot_trust_path()
    );
    for limits in [
        HistoricalAncestryLimitsV1 {
            maximum_headers: headers.len() - 1,
            ..exact
        },
        HistoricalAncestryLimitsV1 {
            maximum_transitions: 0,
            ..exact
        },
        HistoricalAncestryLimitsV1 {
            maximum_total_bytes: total - 1,
            ..exact
        },
    ] {
        let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
        budget.charge_signature_work(7).unwrap();
        assert!(verify_native_historical_trust_path_v1(
            &anchor,
            &headers,
            &[evidence.as_preimages()],
            &proof,
            limits,
            &mut budget,
        )
        .is_err());
        assert_eq!(budget.signature_work(), 7, "bounds precede signature work");
    }

    for disconnected in [
        vec![headers[0], headers[2], headers[3]],
        vec![headers[0], headers[2], headers[1], headers[3]],
        vec![headers[0], headers[1], headers[2], headers[2], headers[3]],
    ] {
        assert!(verify_native_historical_trust_path_v1(
            &anchor,
            &disconnected,
            &[evidence.as_preimages()],
            &proof,
            HistoricalAncestryLimitsV1::default(),
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .is_err());
    }
    for activations in [
        vec![],
        vec![evidence.as_preimages(), evidence.as_preimages()],
    ] {
        assert!(verify_native_historical_trust_path_v1(
            &anchor,
            &headers,
            &activations,
            &proof,
            HistoricalAncestryLimitsV1::default(),
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .is_err());
    }
    let checkpoint_anchor = pinned(
        checkpoint_proof.finalized_block().header(),
        &set,
        &parameters,
    );
    assert!(verify_native_historical_trust_path_v1(
        &checkpoint_anchor,
        &headers,
        &[evidence.as_preimages()],
        &proof,
        HistoricalAncestryLimitsV1::default(),
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .is_err());
    let mut corrupt_proof = proof.clone();
    corrupt_proof[signature_offsets[0]] ^= 1;
    let mut charged = Cev0AdmissionBudgetV0::protocol_v0();
    charged.charge_signature_work(7).unwrap();
    assert!(verify_native_historical_trust_path_v1(
        &anchor,
        &headers,
        &[evidence.as_preimages()],
        &corrupt_proof,
        HistoricalAncestryLimitsV1::default(),
        &mut charged,
    )
    .is_err());
    assert!(charged.signature_work() > 7);
    let mut insufficient = Cev0AdmissionBudgetV0::new(
        successful.maximum_root_bytes(),
        successful.signature_work() - 1,
    );
    assert!(verify_native_historical_trust_path_v1(
        &anchor,
        &headers,
        &[evidence.as_preimages()],
        &proof,
        HistoricalAncestryLimitsV1::default(),
        &mut insufficient,
    )
    .is_err());
    assert!(insufficient.signature_work() > 0);
}
