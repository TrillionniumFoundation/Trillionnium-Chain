use serde_json::Value;
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_types::{
    decode_application_payload_v0_exact, decode_block_header_v0_exact,
    decode_double_vote_evidence_v0_exact, decode_execution_receipt_commitment_v0_exact,
    decode_ordinary_qc_v0_exact, decode_validator_set_v0_exact, BlockBodyV0, CanonicalSignable,
    ConsensusParametersV0, ConsensusPublicKey, DecodeError, DecodeErrorCode, ExecutionReceiptsV0,
    ProposalWitnessV0, QcReferenceV0, Signature64, SignatureVerifier, SigningRoot, Validator,
    ValidatorId, VotingPower,
};

const VECTOR: &str =
    include_str!("../../../../docs/protocol/poco-bft-v0/vectors/block-body-kernel-v0.json");

#[test]
fn raw_body_kernel_decodes_reencodes_roots_and_strictly_verifies() {
    let root: Value = serde_json::from_str(VECTOR).expect("valid block-body vector JSON");
    assert_eq!(
        string(&root, "schema"),
        "trnm_poco_bft_block_body_kernel_vectors_v0"
    );
    assert_eq!(root["cryptographic_validity_claimed"], true);

    let parameters = ConsensusParametersV0::reference_shadow_v0();
    assert_eq!(
        parameters.max_block_bytes().to_string(),
        string(&root["active_context"], "active_max_block_bytes")
    );
    let set_vector = &root["active_validator_set"];
    let set = decode_validator_set_v0_exact(&hex_vec(string(set_vector, "cev0_hex")))
        .expect("the authenticated active set must exact-decode");
    assert_eq!(
        set.id().as_bytes(),
        &hex_array(string(set_vector, "validator_set_hash_hex"))
    );
    assert_eq!(
        set.total_power().to_string(),
        string(set_vector, "total_weight")
    );
    assert_eq!(
        set.quorum_power().to_string(),
        string(set_vector, "quorum_weight")
    );

    let valid = &root["valid_objects"];
    let empty_raw = hex_vec(string(valid, "seal_empty_application_payload_cev0_hex"));
    let empty = decode_application_payload_v0_exact(&empty_raw, &parameters)
        .expect("the exact empty payload must decode");
    assert_eq!(empty.transaction_count(), 0);
    assert_eq!(
        empty.try_cev0_bytes().expect("bounded empty payload"),
        empty_raw
    );

    let payload_vector = &valid["application_payload"];
    let payload_raw = hex_vec(string(payload_vector, "cev0_hex"));
    let payload = decode_application_payload_v0_exact(&payload_raw, &parameters)
        .expect("the application payload must exact-decode");
    assert_eq!(
        payload.try_cev0_bytes().expect("bounded payload CEV0"),
        payload_raw
    );
    assert_eq!(
        payload.payload_root().expect("payload root").as_bytes(),
        &hex_array(string(payload_vector, "payload_root_hex"))
    );

    let receipt_vectors = array(valid, "execution_receipts");
    let mut receipts = Vec::with_capacity(receipt_vectors.len());
    for vector in receipt_vectors {
        let raw = hex_vec(string(vector, "cev0_hex"));
        let receipt = decode_execution_receipt_commitment_v0_exact(&raw, &parameters)
            .unwrap_or_else(|error| panic!("receipt exact decode failed: {error:?}"));
        assert_eq!(receipt.try_cev0_bytes().expect("bounded receipt CEV0"), raw);
        assert_eq!(
            receipt.payload_leaf_hash(),
            &hex_array(string(vector, "payload_leaf_hash_hex"))
        );
        receipts.push(receipt);
    }
    let receipts = ExecutionReceiptsV0::new(&payload, receipts)
        .expect("caller-supplied receipt fixture must bind the payload");
    assert_eq!(
        receipts.try_cev0_bytes().expect("bounded receipt list"),
        hex_vec(string(valid, "execution_receipts_list_cev0_hex"))
    );
    assert_eq!(
        receipts.receipts_root().expect("receipts root").as_bytes(),
        &hex_array(string(valid, "receipts_root_hex"))
    );

    let verifier = StrictEd25519Verifier;
    let evidence_vectors = array(valid, "double_vote_evidence");
    let mut evidence = Vec::with_capacity(evidence_vectors.len());
    for vector in evidence_vectors {
        let raw = hex_vec(string(vector, "cev0_hex"));
        let item = decode_double_vote_evidence_v0_exact(&raw, &set)
            .unwrap_or_else(|error| panic!("double-vote exact decode failed: {error:?}"));
        assert_eq!(item.try_cev0_bytes().expect("bounded evidence CEV0"), raw);
        assert_eq!(
            item.evidence_id().as_bytes(),
            &hex_array(string(vector, "evidence_id_hex"))
        );
        assert_eq!(
            item.first().signing_root().as_bytes(),
            &hex_array(string(vector, "first_signing_root_hex"))
        );
        assert_eq!(
            item.second().signing_root().as_bytes(),
            &hex_array(string(vector, "second_signing_root_hex"))
        );
        item.verify(&set, &verifier)
            .expect("both committed Ed25519 vote signatures must strictly verify");
        evidence.push(item);
    }
    let body = BlockBodyV0::new(payload, evidence).expect("canonical ordinary body evidence");
    assert_eq!(
        body.evidence_root().expect("evidence root").as_bytes(),
        &hex_array(string(valid, "evidence_root_hex"))
    );
    let header_vector = &valid["block_header"];
    let header_raw = hex_vec(string(header_vector, "cev0_hex"));
    let header = decode_block_header_v0_exact(&header_raw)
        .expect("the ordinary block header must exact-decode");
    assert_eq!(
        header.try_cev0_bytes().expect("bounded header CEV0"),
        header_raw
    );
    assert_eq!(
        header.id().as_bytes(),
        &hex_array(string(header_vector, "block_id_hex"))
    );

    let qc_vector = &valid["ordinary_next_view_qc"];
    let qc_raw = hex_vec(string(qc_vector, "cev0_hex"));
    let justify_qc = decode_ordinary_qc_v0_exact(&qc_raw, &set)
        .expect("the ordinary next-view justify QC must exact-decode");
    assert_eq!(
        justify_qc.try_cev0_bytes().expect("bounded ordinary QC"),
        qc_raw
    );
    assert_eq!(
        justify_qc.id().as_bytes(),
        &hex_array(string(qc_vector, "digest_hex"))
    );
    assert_eq!(
        justify_qc.view().checked_next().expect("bounded next view"),
        header.view()
    );
    assert_eq!(
        justify_qc
            .height()
            .checked_next()
            .expect("bounded next height"),
        header.height()
    );
    assert_eq!(justify_qc.block_id(), header.parent_id());
    assert_eq!(
        justify_qc
            .votes()
            .first()
            .expect("ordinary QC has a quorum")
            .signing_root()
            .as_bytes(),
        &hex_array(string(qc_vector, "vote_signing_root_hex"))
    );
    justify_qc
        .verify(&set, &verifier)
        .expect("all ordinary justify-QC signatures must strictly verify");

    let justify_reference = QcReferenceV0::ordinary(justify_qc);
    let proposal_vector = &valid["ordinary_next_view_proposal_sign"];
    assert_eq!(proposal_vector["timeout_certificate_absent"], true);
    assert_eq!(proposal_vector["epoch_anchor_authorization_absent"], true);
    assert_eq!(proposal_vector["handoff_certificate_digest_absent"], true);
    let proposal_root =
        ProposalWitnessV0::signing_root_for(&header, &justify_reference, None, None)
            .expect("next-view proposal witness root must reconstruct");
    assert_eq!(
        proposal_root.as_bytes(),
        &hex_array(string(proposal_vector, "signing_root_hex"))
    );
    let proposer_signature =
        Signature64::from_array(hex_array(string(proposal_vector, "proposer_signature_hex")));
    let proposer = set
        .validator(header.proposer_id())
        .expect("header proposer must belong to the active set");
    assert!(
        verifier.verify(proposer, &proposal_root, &proposer_signature),
        "the valid next-view proposal signature must strictly verify"
    );

    let token = body
        .validate_ordinary_commitments(&header, &receipts, &parameters, &set, &verifier)
        .expect("raw ordinary corpus must produce the inert validated-commitments token");
    assert_eq!(token.block_id(), header.id());
    assert_eq!(
        token.logical_block_size().to_string(),
        string(header_vector, "logical_block_size")
    );
    assert_eq!(
        token.transaction_count(),
        body.application_payload().transaction_count()
    );
    assert_eq!(
        usize::try_from(token.evidence_count()).expect("evidence count fits usize"),
        body.evidence().len()
    );

    for case in array(&root, "strict_ed25519_cases") {
        let validator = Validator::new(
            ValidatorId::from_bytes(b"strict-vector-key").expect("bounded fixture validator ID"),
            ConsensusPublicKey::new(hex_array(string(case, "public_key_hex"))),
            VotingPower::new(1).expect("positive fixture power"),
        )
        .expect("shape-valid fixture validator");
        let signing_root = SigningRoot::new(hex_array(string(case, "signing_root_hex")));
        let signature = Signature64::from_array(hex_array(string(case, "signature_hex")));
        assert_eq!(
            verifier.verify(&validator, &signing_root, &signature),
            case["expected_valid"]
                .as_bool()
                .expect("expected_valid bool"),
            "strict Ed25519 case {} drifted",
            string(case, "id")
        );
    }
}

#[test]
fn raw_body_parser_campaign_has_exact_codes_and_offsets() {
    let root: Value = serde_json::from_str(VECTOR).expect("valid block-body vector JSON");
    let parameters = ConsensusParametersV0::reference_shadow_v0();
    let set =
        decode_validator_set_v0_exact(&hex_vec(string(&root["active_validator_set"], "cev0_hex")))
            .expect("active set exact decode");
    let campaigns = &root["parser_campaigns"];
    let prefix_campaign = &campaigns["all_noncomplete_prefixes"];
    let mut prefix_cases = 0usize;

    for object in array(prefix_campaign, "objects") {
        let id = string(object, "id");
        let parser = string(object, "parser");
        let raw = hex_vec(string(object, "cev0_hex"));
        for prefix_length in 0..raw.len() {
            let error = decode_for_parser(parser, &raw[..prefix_length], &parameters, &set)
                .expect_err("every non-complete prefix must fail");
            assert_eq!(
                error.code().as_str(),
                string(prefix_campaign, "expected_code"),
                "prefix code drift for {id} at {prefix_length}"
            );
            assert_eq!(
                error.byte_offset(),
                prefix_length,
                "prefix offset drift for {id} at {prefix_length}"
            );
            prefix_cases += 1;
        }

        let mut trailing = raw.clone();
        trailing.push(0);
        let error = decode_for_parser(parser, &trailing, &parameters, &set)
            .expect_err("one trailing byte must fail exact decoding");
        assert_eq!(
            error.code().as_str(),
            string(&campaigns["one_byte_trailing"], "expected_code"),
            "trailing code drift for {id}"
        );
        assert_eq!(
            error.byte_offset(),
            raw.len(),
            "trailing offset drift for {id}"
        );
    }
    assert_eq!(
        u64::try_from(prefix_cases).expect("prefix case count fits u64"),
        prefix_campaign["case_count"]
            .as_u64()
            .expect("prefix case_count u64")
    );

    for group in ["parser_boundaries", "semantic_negatives"] {
        for case in array(&root, group) {
            assert_raw_case(case, &parameters, &set);
        }
    }

    let maximum = usize::try_from(parameters.max_block_bytes())
        .expect("active maximum block bytes fits usize");
    let exact_item = vec![0xa5; maximum - 8];
    let mut exact_payload = Vec::with_capacity(maximum);
    exact_payload.extend_from_slice(&1u32.to_be_bytes());
    exact_payload.extend_from_slice(
        &u32::try_from(exact_item.len())
            .expect("active maximum payload item fits u32")
            .to_be_bytes(),
    );
    exact_payload.extend_from_slice(&exact_item);
    assert_eq!(exact_payload.len(), maximum);
    decode_application_payload_v0_exact(&exact_payload, &parameters)
        .expect("active payload root cap equality must be accepted");

    let over_cap = vec![0; maximum + 1];
    for parser in ["application_payload", "execution_receipt"] {
        let error = decode_for_parser(parser, &over_cap, &parameters, &set)
            .expect_err("active root cap plus one must fail before parsing");
        assert_eq!(error.code(), DecodeErrorCode::LengthLimitExceeded);
        assert_eq!(error.byte_offset(), 0);
    }
}

#[test]
fn typed_receipt_and_body_admission_negatives_are_machine_readable() {
    let root: Value = serde_json::from_str(VECTOR).expect("valid block-body vector JSON");
    let parameters = ConsensusParametersV0::reference_shadow_v0();
    let set =
        decode_validator_set_v0_exact(&hex_vec(string(&root["active_validator_set"], "cev0_hex")))
            .expect("active set exact decode");
    let valid = &root["valid_objects"];
    let payload = decode_application_payload_v0_exact(
        &hex_vec(string(&valid["application_payload"], "cev0_hex")),
        &parameters,
    )
    .expect("valid payload exact decode");
    let valid_receipt_values = array(valid, "execution_receipts")
        .iter()
        .map(|vector| {
            decode_execution_receipt_commitment_v0_exact(
                &hex_vec(string(vector, "cev0_hex")),
                &parameters,
            )
            .expect("valid receipt exact decode")
        })
        .collect();
    let valid_receipts = ExecutionReceiptsV0::new(&payload, valid_receipt_values)
        .expect("valid caller-supplied receipt fixture");
    let verifier = StrictEd25519Verifier;

    for case in array(&root, "receipt_admission_negatives") {
        let id = string(case, "id");
        let receipts = array(case, "receipt_cev0_hex")
            .iter()
            .map(|raw| {
                decode_execution_receipt_commitment_v0_exact(
                    &hex_vec(raw.as_str().expect("receipt CEV0 string")),
                    &parameters,
                )
                .expect("negative receipt relation still has exact receipt syntax")
            })
            .collect();
        let error = ExecutionReceiptsV0::new_admission(&payload, receipts)
            .expect_err("receipt admission negative must fail");
        assert_eq!(
            error.code().as_str(),
            string(case, "expected_code"),
            "receipt admission code drift for {id}"
        );
    }

    for case in array(&root, "body_admission_negatives") {
        let id = string(case, "id");
        let header = decode_block_header_v0_exact(&hex_vec(string(case, "header_cev0_hex")))
            .expect("negative body header still has exact syntax");
        let mut evidence = Vec::new();
        let mut exact_error = None;
        for raw in array(case, "evidence_cev0_hex") {
            match decode_double_vote_evidence_v0_exact(
                &hex_vec(raw.as_str().expect("evidence CEV0 string")),
                &set,
            ) {
                Ok(item) => evidence.push(item),
                Err(error) => {
                    exact_error = Some(error);
                    break;
                }
            }
        }

        if let Some(error) = exact_error {
            assert_eq!(
                error.code().as_str(),
                string(case, "expected_code"),
                "exact evidence-admission code drift for {id}"
            );
            continue;
        }

        let body = match BlockBodyV0::new_admission(payload.clone(), evidence) {
            Ok(body) => body,
            Err(error) => {
                assert_eq!(
                    error.code().as_str(),
                    string(case, "expected_code"),
                    "body construction code drift for {id}"
                );
                continue;
            }
        };
        let error = body
            .validate_ordinary_commitments(&header, &valid_receipts, &parameters, &set, &verifier)
            .expect_err("body admission negative must fail");
        assert_eq!(
            error.code().as_str(),
            string(case, "expected_code"),
            "ordinary body admission code drift for {id}"
        );
    }
}

fn assert_raw_case(
    case: &Value,
    parameters: &ConsensusParametersV0,
    set: &trnm_consensus_types::ValidatorSet,
) {
    let id = string(case, "id");
    let result = decode_for_parser(
        string(case, "parser"),
        &hex_vec(string(case, "raw_hex")),
        parameters,
        set,
    );
    let error = result
        .err()
        .unwrap_or_else(|| panic!("negative raw corpus case {id} unexpectedly passed"));
    assert_eq!(
        error.code().as_str(),
        string(case, "expected_code"),
        "error-code drift for {id}"
    );
    assert_eq!(
        error.byte_offset(),
        usize::try_from(
            case["expected_byte_offset"]
                .as_u64()
                .expect("expected_byte_offset u64"),
        )
        .expect("expected byte offset fits usize"),
        "error-offset drift for {id}"
    );
}

fn decode_for_parser(
    parser: &str,
    raw: &[u8],
    parameters: &ConsensusParametersV0,
    set: &trnm_consensus_types::ValidatorSet,
) -> Result<(), DecodeError> {
    match parser {
        "application_payload" => decode_application_payload_v0_exact(raw, parameters).map(|_| ()),
        "execution_receipt" => {
            decode_execution_receipt_commitment_v0_exact(raw, parameters).map(|_| ())
        }
        "double_vote_evidence" => decode_double_vote_evidence_v0_exact(raw, set).map(|_| ()),
        "block_header" => decode_block_header_v0_exact(raw).map(|_| ()),
        unknown => panic!("unknown corpus parser {unknown}"),
    }
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} array"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} string"))
}

fn hex_vec(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex must have an even length");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
        .collect()
}

fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    hex_vec(value).try_into().unwrap_or_else(|bytes: Vec<u8>| {
        panic!("expected {N} decoded bytes, received {}", bytes.len())
    })
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("invalid lowercase hex byte"),
    }
}
