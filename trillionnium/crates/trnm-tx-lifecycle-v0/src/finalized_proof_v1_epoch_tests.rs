use super::*;
use serde_json::Value;
use trnm_consensus_crypto::recover_epoch_activation_authority_strict_v0;
use trnm_consensus_types::{
    decode_consensus_parameters_v0_exact, decode_validator_set_v0_exact, ApplicationPayloadV0,
    EpochActivationEvidenceBytesV0, ExecutionReceiptsV0,
};

// Signed frozen handoff corpus, with real first-epoch proposal and QC signatures.
const CORPUS: &str = include_str!(
    "../../../../docs/protocol/poco-bft-v0/vectors/poco-authenticated-checkpoint-handoff-v0.json"
);

fn unhex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).unwrap())
        .collect()
}

fn fixture(
    profile: &str,
) -> (
    EpochActivationEvidenceBytesV0,
    ValidatorSet,
    ConsensusParametersV0,
    [u8; 32],
) {
    let corpus: Value = serde_json::from_str(CORPUS).unwrap();
    let case = &corpus[profile];
    let raw = |section: &str, field: &str| unhex(case[section][field].as_str().unwrap());
    let bytes = EpochActivationEvidenceBytesV0 {
        old_checkpoint_finality: raw("checkpoint_finality", "raw_finality_proof_cev0_hex"),
        next_epoch_commitment: raw("preheader", "commitment_cev0_hex"),
        authorization_kernel: raw("handoff", "raw_anchor_certificate_kernel_cev0_hex"),
        old_validator_set: raw("preheader", "old_validator_set_cev0_hex"),
        old_consensus_parameters: raw("preheader", "old_parameters_cev0_hex"),
        new_validator_set: raw("preheader", "new_validator_set_cev0_hex"),
        new_consensus_parameters: raw("preheader", "new_parameters_cev0_hex"),
        authenticated_checkpoint_parent_header: raw(
            "preheader",
            "checkpoint_parent_header_cev0_hex",
        ),
    };
    let old_set = decode_validator_set_v0_exact(&bytes.old_validator_set).unwrap();
    let old_parameters =
        decode_consensus_parameters_v0_exact(&bytes.old_consensus_parameters).unwrap();
    let binding = unhex(match profile {
        "positive" => "4ba70b831d3bd70a1be8669f654ac42148017fca0b83f84e999ac532b9c70e4f",
        "authenticated_fallback" => {
            "3f719cc7d84539da791a3206d46c4d529f390b2333c35128847f7b62dcd2fc73"
        }
        _ => panic!("unknown frozen fixture"),
    })
    .try_into()
    .unwrap();
    (bytes, old_set, old_parameters, binding)
}

fn first_epoch_finality_bytes(
    activation: &trnm_consensus_crypto::StrictSameVersionEpochActivationAuthorityV0,
    payload_root: trnm_consensus_types::PayloadDigest,
    receipts_root: trnm_consensus_types::ReceiptsRoot,
) -> (
    Vec<u8>,
    trnm_consensus_crypto::FinalityExpectationV0,
    Vec<usize>,
) {
    first_epoch_finality_with_views(activation, payload_root, receipts_root, [1, 2, 3], None)
}

fn first_epoch_finality_with_views(
    activation: &trnm_consensus_crypto::StrictSameVersionEpochActivationAuthorityV0,
    payload_root: trnm_consensus_types::PayloadDigest,
    receipts_root: trnm_consensus_types::ReceiptsRoot,
    views: [u64; 3],
    anchor_context: Option<(
        trnm_consensus_types::QcReferenceV0,
        trnm_consensus_types::EpochAnchorAuthorizationV0,
    )>,
) -> (
    Vec<u8>,
    trnm_consensus_crypto::FinalityExpectationV0,
    Vec<usize>,
) {
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use trnm_consensus_types::*;
    let set = activation.new_validator_set();
    let params = activation.new_consensus_parameters();
    let key = |validator: &Validator| {
        let mut h = Sha256::new();
        h.update(b"trnm.poco-bft.checkpoint-finality.private-fixture.v0:");
        h.update(validator.id().as_bytes());
        let key = SigningKey::from_bytes(&h.finalize().into());
        assert_eq!(
            key.verifying_key().to_bytes(),
            validator.consensus_key().into_bytes()
        );
        key
    };
    let common = || {
        let mut bytes = 0u16.to_be_bytes().to_vec();
        bytes.extend(set.genesis_hash().as_bytes());
        bytes.extend((set.chain_id().as_bytes().len() as u16).to_be_bytes());
        bytes.extend(set.chain_id().as_bytes());
        bytes.extend(set.protocol_version().get().to_be_bytes());
        bytes.extend(set.epoch().get().to_be_bytes());
        bytes.extend(set.id().as_bytes());
        bytes
    };
    let mut encoded = common();
    encoded.extend(params.hash().as_bytes());
    let terminal = activation.terminal_old_header();
    let mut anchor = common();
    anchor.extend(0u64.to_be_bytes());
    anchor.extend(terminal.height().get().to_be_bytes());
    anchor.extend(terminal.id().as_bytes());
    anchor.extend(0u32.to_be_bytes());
    let mut parent_id = terminal.id();
    let mut previous_qc = None;
    let mut expected = None;
    let mut signature_offsets = Vec::new();
    for (index, view) in views.into_iter().enumerate() {
        let height_offset = index as u64 + 1;
        let proposer = &set.validators()[(view as usize - 1) % set.validators().len()];
        let header = BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(view),
            Height::new(terminal.height().get() + height_offset),
            if index == 0 {
                BlockKind::EpochHandoff
            } else {
                BlockKind::Regular
            },
            parent_id,
            proposer.id(),
            set.id(),
            params.hash(),
            payload_root,
            StateRoot::new([0x42; 32]),
            receipts_root,
            EvidenceRoot::new([0x44; 32]),
            terminal.timestamp_ms() + height_offset,
            None,
        )
        .unwrap();
        let justify_for_timeout = if index == 0 {
            anchor_context.as_ref().map(|(anchor, _)| anchor.clone())
        } else {
            Some(QcReferenceV0::ordinary(previous_qc.clone().unwrap()))
        };
        let timeout = if let Some(justify) = justify_for_timeout {
            if justify.qc_ref().view().get() + 1 < view {
                let entries = set
                    .validators()
                    .iter()
                    .map(|validator| {
                        let root = TimeoutVote::signing_root_for_set(
                            set,
                            View::new(view - 1),
                            justify.qc_ref(),
                        )
                        .unwrap();
                        TimeoutEntryV0::new(
                            validator.id(),
                            justify.qc_ref(),
                            SignatureBytes::from_array(
                                key(validator).sign(root.as_bytes()).to_bytes(),
                            ),
                        )
                        .unwrap()
                    })
                    .collect();
                Some(
                    TimeoutCertificateV0::new(
                        View::new(view - 1),
                        entries,
                        vec![justify.clone()],
                        justify.id(),
                        set,
                    )
                    .unwrap(),
                )
            } else {
                None
            }
        } else {
            None
        };
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
        if index == 0 {
            let root = if let Some((anchor, authorization)) = &anchor_context {
                ProposalWitnessV0::signing_root_for(
                    &header,
                    anchor,
                    timeout.as_ref(),
                    Some(authorization),
                )
                .unwrap()
            } else {
                epoch_first_proposal_signing_root_v0(
                    &header,
                    activation.authorization_kernel(),
                    activation.old_validator_set(),
                    set,
                    params,
                )
                .unwrap()
            };
            let signature = key(proposer).sign(root.as_bytes()).to_bytes();
            encoded.extend(header.try_cev0_bytes().unwrap());
            encoded.extend(&anchor);
            if let Some(tc) = &timeout {
                encoded.push(1);
                encoded.extend(tc.try_cev0_bytes().unwrap());
            } else {
                encoded.push(0);
            }
            encoded.push(1); // exact authorization follows
            encoded.extend(activation.authorization_cev0_bytes().unwrap());
            signature_offsets.push(encoded.len());
            encoded.extend(signature);
            encoded.extend(qc.try_cev0_bytes().unwrap());
            expected = Some(trnm_consensus_crypto::FinalityExpectationV0 {
                block_id: header.id(),
                height: header.height(),
                state_root: header.state_root(),
                receipts_root: header.receipts_root(),
                evidence_root: header.evidence_root(),
                parent_id: terminal.id(),
                parent_height: terminal.height(),
                parent_timestamp_ms: terminal.timestamp_ms(),
            });
        } else {
            let justify = QcReferenceV0::ordinary(previous_qc.take().unwrap());
            let witness = ProposalWitnessV0::new(
                &header,
                justify.clone(),
                timeout.clone(),
                None,
                SignatureBytes::from_array([1; 64]),
                set,
                None,
                params,
                header.timestamp_ms() - 1,
            )
            .unwrap();
            let root = witness.signing_root_for_header(&header).unwrap();
            let signature =
                SignatureBytes::from_array(key(proposer).sign(root.as_bytes()).to_bytes());
            let certified = CertifiedHeaderV0::new(
                header.clone(),
                justify,
                timeout,
                None,
                signature,
                qc.clone(),
                set,
                None,
                params,
                header.timestamp_ms() - 1,
            )
            .unwrap();
            let raw = certified.try_cev0_bytes().unwrap();
            let signature_position = raw
                .windows(64)
                .position(|x| x == signature.as_bytes())
                .unwrap();
            signature_offsets.push(encoded.len() + signature_position);
            encoded.extend(raw);
        }
        parent_id = header.id();
        previous_qc = Some(qc);
    }
    (encoded, expected.unwrap(), signature_offsets)
}

#[test]
fn epoch_inclusion_requires_all_evidence_and_authenticates_both_odd_tail_branches() {
    let (evidence, set, params, binding) = fixture("positive");
    let activation = recover_epoch_activation_authority_strict_v0(
        evidence.as_preimages(),
        &set,
        &params,
        binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let payload = ApplicationPayloadV0::new(vec![vec![1, 2], vec![3, 4], vec![5, 6]]).unwrap();
    let receipts: Vec<_> = (0..3)
        .map(|i| {
            ExecutionReceiptCommitmentV0::for_transaction(
                &payload,
                i,
                10 + u64::from(i),
                20 + u128::from(i),
                vec![],
            )
            .unwrap()
        })
        .collect();
    let receipt_root = ExecutionReceiptsV0::new(&payload, receipts.clone())
        .unwrap()
        .receipts_root()
        .unwrap();
    let (proof, expected, signature_offsets) =
        first_epoch_finality_bytes(&activation, payload.payload_root().unwrap(), receipt_root);
    let finality = decode_verify_epoch_first_finality_strict_v1(
        evidence.as_preimages(),
        &proof,
        &set,
        &params,
        expected,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let transactions: Vec<_> = (0..3).map(|i| payload.transaction(i).unwrap()).collect();
    let receipt_bytes: Vec<_> = receipts
        .iter()
        .map(|r| r.try_cev0_bytes().unwrap())
        .collect();
    let mut package = NativeTxProofPackageV1 {
        target_header: finality
            .proof()
            .finalized_block()
            .header()
            .try_cev0_bytes()
            .unwrap(),
        finality_proof: proof,
        transaction: transactions[2].to_vec(),
        execution_receipt: receipt_bytes[2].clone(),
        index: 2,
        item_count: 3,
        payload_siblings: OrderedInclusionProofV0::from_items(RootKind::Payload, &transactions, 2)
            .unwrap()
            .siblings()
            .to_vec(),
        receipt_siblings: OrderedInclusionProofV0::from_items(
            RootKind::Receipts,
            &receipt_bytes,
            2,
        )
        .unwrap()
        .siblings()
        .to_vec(),
    };
    let bytes = package.encode().unwrap();
    let context = NativeTxEpochProofContextV1 {
        trusted_old_validator_set: &set,
        trusted_old_parameters: &params,
        evidence: evidence.as_preimages(),
        expected,
        maximum_transactions: 100,
        maximum_proof_bytes: MAX_NATIVE_TX_PROOF_BYTES_V1,
    };
    let verify = |raw: &[u8], context: NativeTxEpochProofContextV1<'_>| {
        verify_native_tx_epoch_inclusion_v1(raw, context, &mut Cev0AdmissionBudgetV0::protocol_v0())
    };
    let verified = verify(&bytes, context).unwrap();
    assert_eq!(verified.native_transaction_bytes(), transactions[2]);
    assert_eq!(verified.gas_used(), 12);
    assert_eq!(verified.fee_charged(), 22);
    assert_eq!(verified.header().id(), expected.block_id);
    let parts = [
        evidence.old_checkpoint_finality.as_slice(),
        &evidence.next_epoch_commitment,
        &evidence.authorization_kernel,
        &evidence.old_validator_set,
        &evidence.old_consensus_parameters,
        &evidence.new_validator_set,
        &evidence.new_consensus_parameters,
        &evidence.authenticated_checkpoint_parent_header,
        &bytes,
    ];
    assert_eq!(
        verified.proof_digest(),
        Digest32V0::hash(b"trnm.tx.native-epoch-inclusion-proof.v1", &parts)
    );
    let total: usize = parts.iter().map(|x| x.len()).sum();
    let mut bounded = context;
    bounded.maximum_proof_bytes = total;
    assert!(verify(&bytes, bounded).is_ok());
    bounded.maximum_proof_bytes -= 1;
    assert!(matches!(
        verify(&bytes, bounded),
        Err(NativeTxProofErrorV1::TooLarge)
    ));
    for offset in signature_offsets {
        package.finality_proof[offset] ^= 1;
        let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
        assert!(verify_native_tx_epoch_inclusion_v1(
            &package.encode().unwrap(),
            context,
            &mut budget
        )
        .is_err());
        assert!(budget.signature_work() > 0);
        package.finality_proof[offset] ^= 1;
    }
    package.receipt_siblings[0][0] ^= 1;
    assert!(verify(&package.encode().unwrap(), context).is_err());
    package.receipt_siblings[0][0] ^= 1;
    let mut bad = context;
    bad.evidence.new_validator_set = &evidence.old_validator_set;
    assert!(verify(&bytes, bad).is_err());
    bad = context;
    bad.evidence.authorization_kernel = &[];
    assert!(verify(&bytes, bad).is_err());
    assert!(verify_native_tx_inclusion_v1(
        &bytes,
        NativeTxProofContextV1 {
            trusted_validator_set: activation.new_validator_set(),
            trusted_parameters: activation.new_consensus_parameters(),
            expected,
            maximum_transactions: 100,
            maximum_proof_bytes: MAX_NATIVE_TX_PROOF_BYTES_V1
        },
        &mut Cev0AdmissionBudgetV0::protocol_v0()
    )
    .is_err());
    // The typed consumer also handles skipped views through fully signed TCs.
    let first = finality.proof().finalized_block();
    let anchor_context = (
        first.justify_qc().clone(),
        first.epoch_anchor_authorization().unwrap().clone(),
    );
    let (skipped, skipped_expected, _) = first_epoch_finality_with_views(
        &activation,
        payload.payload_root().unwrap(),
        receipt_root,
        [3, 5, 8],
        Some(anchor_context),
    );
    let strict = decode_verify_epoch_first_finality_strict_v1(
        evidence.as_preimages(),
        &skipped,
        &set,
        &params,
        skipped_expected,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    package.finality_proof = skipped;
    package.target_header = strict
        .proof()
        .finalized_block()
        .header()
        .try_cev0_bytes()
        .unwrap();
    let mut skipped_context = context;
    skipped_context.expected = skipped_expected;
    assert_eq!(
        verify(&package.encode().unwrap(), skipped_context)
            .unwrap()
            .header()
            .view()
            .get(),
        3
    );
}
