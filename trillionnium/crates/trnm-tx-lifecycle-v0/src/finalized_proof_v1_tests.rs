use super::*;
use ed25519_dalek::{Signer, SigningKey};
use trnm_consensus_types::{
    ApplicationPayloadV0, BlockId, BlockKind, CertifiedHeaderV0, ChainId, ConsensusPublicKey,
    Epoch, EvidenceRoot, ExecutionReceiptsV0, FinalityProofV0, GenesisHash, Height, OrderedRootV0,
    ProposalWitnessV0, ProtocolVersion, QcReferenceV0, QuorumCertificate, SignatureBytes,
    StateRoot, Validator, ValidatorId, View, Vote, VoteSignPreimageV0, VotingPower,
};

struct Fixture {
    set: ValidatorSet,
    parameters: ConsensusParametersV0,
    proof: FinalityProofV0,
    payload: ApplicationPayloadV0,
    receipts: Vec<ExecutionReceiptCommitmentV0>,
    expected: FinalityExpectationV0,
}

fn qc(
    set: &ValidatorSet,
    keys: &[SigningKey],
    view: u64,
    height: u64,
    block: BlockId,
) -> QuorumCertificate {
    let preimage =
        VoteSignPreimageV0::for_validator_set(set, View::new(view), Height::new(height), block)
            .unwrap();
    let votes = set
        .validators()
        .iter()
        .zip(keys)
        .take(3)
        .map(|(validator, key)| {
            Vote::new(
                set.chain_id(),
                set.protocol_version(),
                set.epoch(),
                View::new(view),
                Height::new(height),
                block,
                set.id(),
                validator.id(),
                SignatureBytes::from_slice(
                    &key.sign(preimage.signing_root().as_bytes()).to_bytes(),
                )
                .unwrap(),
                set,
            )
            .unwrap()
        })
        .collect();
    QuorumCertificate::new(
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(view),
        Height::new(height),
        block,
        set.id(),
        votes,
        set,
    )
    .unwrap()
}

fn fixture(count: usize) -> Fixture {
    let parameters = ConsensusParametersV0::reference_shadow_v0();
    let keys: Vec<_> = (1u8..=4)
        .map(|i| SigningKey::from_bytes(&[i; 32]))
        .collect();
    let validators = keys
        .iter()
        .enumerate()
        .map(|(i, key)| {
            Validator::new(
                ValidatorId::new([i as u8 + 1; 32]),
                ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                VotingPower::new(1).unwrap(),
            )
            .unwrap()
        })
        .collect();
    let set = ValidatorSet::new(
        GenesisHash::new([9; 32]),
        ChainId::from_static("native-inclusion-test"),
        ProtocolVersion::V0,
        Epoch::new(0),
        parameters.hash(),
        validators,
    )
    .unwrap();
    let transactions = (0..count).map(|i| vec![i as u8, 1, 2, 3]).collect();
    let payload = ApplicationPayloadV0::new(transactions).unwrap();
    let receipts: Vec<_> = (0..count)
        .map(|index| {
            ExecutionReceiptCommitmentV0::for_transaction(
                &payload,
                index as u32,
                11 + index as u64,
                21 + index as u128,
                Vec::new(),
            )
            .unwrap()
        })
        .collect();
    let receipt_root = ExecutionReceiptsV0::new(&payload, receipts.clone())
        .unwrap()
        .receipts_root()
        .unwrap();
    let empty_root = OrderedRootV0::from_items::<&[u8]>(RootKind::Evidence, &[])
        .unwrap()
        .digest();
    let parent_id = BlockId::new([19; 32]);
    let mut parent_qc = qc(&set, &keys, 1, 1, parent_id);
    let mut certified = Vec::new();
    for view in 2..=4u64 {
        let proposer_index = ((view - 1) % keys.len() as u64) as usize;
        let header = BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(view),
            Height::new(view),
            BlockKind::Regular,
            parent_qc.block_id(),
            set.validators()[proposer_index].id(),
            set.id(),
            parameters.hash(),
            payload.payload_root().unwrap(),
            StateRoot::new([30 + view as u8; 32]),
            receipt_root,
            EvidenceRoot::new(empty_root),
            view * 1000,
            None,
        )
        .unwrap();
        let justify = QcReferenceV0::Ordinary(Box::new(parent_qc));
        let signing_root =
            ProposalWitnessV0::signing_root_for(&header, &justify, None, None).unwrap();
        let signature = SignatureBytes::from_slice(
            &keys[proposer_index]
                .sign(signing_root.as_bytes())
                .to_bytes(),
        )
        .unwrap();
        parent_qc = qc(&set, &keys, view, view, header.id());
        certified.push(
            CertifiedHeaderV0::new(
                header,
                justify,
                None,
                None,
                signature,
                parent_qc.clone(),
                &set,
                None,
                &parameters,
                (view - 1) * 1000,
            )
            .unwrap(),
        );
    }
    let proof = FinalityProofV0::new(
        certified[0].clone(),
        certified[1].clone(),
        certified[2].clone(),
        &set,
        None,
        &parameters,
        1000,
    )
    .unwrap();
    let target = proof.finalized_block().header();
    let expected = FinalityExpectationV0 {
        block_id: target.id(),
        height: target.height(),
        state_root: target.state_root(),
        receipts_root: target.receipts_root(),
        evidence_root: target.evidence_root(),
        parent_id,
        parent_height: Height::new(1),
        parent_timestamp_ms: 1000,
    };
    Fixture {
        set,
        parameters,
        proof,
        payload,
        receipts,
        expected,
    }
}

fn package(f: &Fixture, index: u32) -> NativeTxProofPackageV1 {
    let transactions: Vec<_> = (0..f.payload.transaction_count())
        .map(|i| f.payload.transaction(i).unwrap())
        .collect();
    let receipts: Vec<_> = f
        .receipts
        .iter()
        .map(|r| r.try_cev0_bytes().unwrap())
        .collect();
    NativeTxProofPackageV1 {
        target_header: f.proof.finalized_block().header().try_cev0_bytes().unwrap(),
        finality_proof: f.proof.try_cev0_bytes().unwrap(),
        transaction: transactions[index as usize].to_vec(),
        execution_receipt: receipts[index as usize].clone(),
        index,
        item_count: transactions.len() as u32,
        payload_siblings: OrderedInclusionProofV0::from_items(
            RootKind::Payload,
            &transactions,
            index,
        )
        .unwrap()
        .siblings()
        .to_vec(),
        receipt_siblings: OrderedInclusionProofV0::from_items(RootKind::Receipts, &receipts, index)
            .unwrap()
            .siblings()
            .to_vec(),
    }
}

fn context(f: &Fixture) -> NativeTxProofContextV1<'_> {
    NativeTxProofContextV1 {
        trusted_validator_set: &f.set,
        trusted_parameters: &f.parameters,
        expected: f.expected,
        maximum_transactions: 1000,
        maximum_proof_bytes: MAX_NATIVE_TX_PROOF_BYTES_V1,
    }
}

fn verify(
    f: &Fixture,
    package: &NativeTxProofPackageV1,
) -> Result<VerifiedNativeTxInclusionV1, NativeTxProofErrorV1> {
    verify_native_tx_inclusion_v1(
        &package.encode()?,
        context(f),
        &mut Cev0AdmissionBudgetV0::for_validator_set(&f.parameters, &f.set),
    )
}

#[test]
fn verifies_real_ed25519_finality_and_both_branches_at_every_position() {
    for count in [1, 3, 5] {
        let f = fixture(count);
        for index in 0..count as u32 {
            let package = package(&f, index);
            let bytes = package.encode().unwrap();
            assert_eq!(
                NativeTxProofPackageV1::decode_exact(&bytes, bytes.len()).unwrap(),
                package
            );
            let accepted = verify(&f, &package).unwrap();
            assert_eq!(accepted.header().id(), f.expected.block_id);
            assert_eq!(accepted.transaction_index(), index);
            assert_eq!(accepted.item_count(), count as u32);
            assert_eq!(accepted.native_transaction_bytes(), package.transaction);
            assert_eq!(accepted.gas_used(), 11 + index as u64);
            assert_eq!(accepted.fee_charged(), 21 + index as u128);
            assert!(accepted.events().is_empty());
            assert_eq!(
                accepted.proof_digest(),
                verify(&f, &package).unwrap().proof_digest()
            );
        }
    }
}

#[test]
fn rejects_payload_receipt_count_index_target_and_sibling_substitutions() {
    let f = fixture(3);
    let original = package(&f, 2);
    let mut cases = Vec::new();
    let mut p = original.clone();
    p.transaction[0] ^= 1;
    cases.push(p);
    let mut p = original.clone();
    p.execution_receipt = f.receipts[0].try_cev0_bytes().unwrap();
    cases.push(p);
    let mut p = original.clone();
    p.item_count = 4;
    cases.push(p);
    let mut p = original.clone();
    p.index = 1;
    cases.push(p);
    let mut p = original.clone();
    p.payload_siblings[0][0] ^= 1;
    cases.push(p);
    let mut p = original.clone();
    p.receipt_siblings[1][0] ^= 1;
    cases.push(p);
    let mut p = original.clone();
    p.target_header = f.proof.child().header().try_cev0_bytes().unwrap();
    cases.push(p);
    let mut p = original.clone();
    p.payload_siblings = p.receipt_siblings.clone();
    cases.push(p);
    for p in cases {
        assert!(verify(&f, &p).is_err());
    }
    let mut extra = original.clone();
    extra.payload_siblings.push([0; 32]);
    assert!(extra.encode().is_err());
}

#[test]
fn refuses_proof_signature_corruption_and_wrong_trust_context() {
    let f = fixture(3);
    let mut p = package(&f, 1);
    let signature = f.proof.finalized_block().proposer_signature().as_bytes();
    let offset = p
        .finality_proof
        .windows(signature.len())
        .position(|v| v == signature)
        .unwrap();
    p.finality_proof[offset] ^= 1;
    let mut budget = Cev0AdmissionBudgetV0::for_validator_set(&f.parameters, &f.set);
    assert!(matches!(
        verify_native_tx_inclusion_v1(&p.encode().unwrap(), context(&f), &mut budget),
        Err(NativeTxProofErrorV1::Finality(_))
    ));
    assert!(budget.signature_work() > 0);
    let wrong_set = ValidatorSet::new(
        GenesisHash::new([99; 32]),
        f.set.chain_id(),
        f.set.protocol_version(),
        f.set.epoch(),
        f.parameters.hash(),
        f.set.validators().to_vec(),
    )
    .unwrap();
    let bytes = package(&f, 0).encode().unwrap();
    let mut ctx = context(&f);
    ctx.trusted_validator_set = &wrong_set;
    assert!(
        verify_native_tx_inclusion_v1(&bytes, ctx, &mut Cev0AdmissionBudgetV0::protocol_v0())
            .is_err()
    );
    let mut ctx = context(&f);
    ctx.expected.block_id = f.proof.grandchild().header().id();
    assert!(
        verify_native_tx_inclusion_v1(&bytes, ctx, &mut Cev0AdmissionBudgetV0::protocol_v0())
            .is_err()
    );
}

#[test]
fn strict_package_parser_rejects_all_truncations_overflow_unknown_and_extra_fields() {
    let f = fixture(1);
    let bytes = package(&f, 0).encode().unwrap();
    for end in 0..bytes.len() {
        assert!(NativeTxProofPackageV1::decode_exact(&bytes[..end], bytes.len()).is_err());
    }
    let mut bad = bytes.clone();
    bad.push(0);
    assert!(matches!(
        NativeTxProofPackageV1::decode_exact(&bad, bad.len()),
        Err(NativeTxProofErrorV1::TrailingBytes)
    ));
    let mut bad = bytes.clone();
    bad[1] = 2;
    assert!(matches!(
        NativeTxProofPackageV1::decode_exact(&bad, bad.len()),
        Err(NativeTxProofErrorV1::UnsupportedSchema(2))
    ));
    let mut bad = bytes.clone();
    bad[2..6].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(NativeTxProofPackageV1::decode_exact(&bad, bad.len()).is_err());
    assert!(NativeTxProofPackageV1::decode_exact(&bytes, bytes.len() - 1).is_err());
    assert!(NativeTxProofPackageV1::decode_exact(
        &vec![0; MAX_NATIVE_TX_PROOF_BYTES_V1 + 1],
        usize::MAX
    )
    .is_err());
    // Uncommitted status/intermediate-root suffixes have no accepted slot.
    let mut bad = bytes.clone();
    bad.extend_from_slice(b"execution_success=true");
    assert!(NativeTxProofPackageV1::decode_exact(&bad, bad.len()).is_err());
}

#[test]
fn obeys_authenticated_byte_count_and_signature_budgets() {
    let f = fixture(3);
    let bytes = package(&f, 0).encode().unwrap();
    let mut ctx = context(&f);
    ctx.maximum_proof_bytes = bytes.len() - 1;
    assert!(
        verify_native_tx_inclusion_v1(&bytes, ctx, &mut Cev0AdmissionBudgetV0::protocol_v0())
            .is_err()
    );
    let mut ctx = context(&f);
    ctx.maximum_transactions = 2;
    assert!(matches!(
        verify_native_tx_inclusion_v1(&bytes, ctx, &mut Cev0AdmissionBudgetV0::protocol_v0()),
        Err(NativeTxProofErrorV1::InvalidCount)
    ));
    assert!(verify_native_tx_inclusion_v1(
        &bytes,
        context(&f),
        &mut Cev0AdmissionBudgetV0::new(bytes.len(), 0)
    )
    .is_err());
}
