use std::collections::BTreeMap;

use serde_json::Value;
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_types::{
    decode_ordinary_qc_v0_exact, decode_ordinary_timeout_certificate_v0_exact,
    decode_validator_set_v0_exact, BlockId, CanonicalSignable, CertificateId, ChainId,
    ConsensusParametersHash, ConsensusPublicKey, Epoch, GenesisHash, Height, ProtocolVersion,
    QcRef, QcReferenceV0, QuorumCertificate, Signature64, TimeoutCertificateV0, TimeoutEntryV0,
    TimeoutVote, ValidationError, Validator, ValidatorId, ValidatorSet, ValidatorSetId, View, Vote,
    VotingPower,
};

const VECTOR: &str =
    include_str!("../../../../docs/protocol/poco-bft-v0/vectors/qc-tc-threshold-v0.json");
const PARSER_VECTOR: &str = include_str!(
    "../../../../docs/protocol/poco-bft-v0/vectors/cev0-parser-certificate-kernel-v0.json"
);

#[test]
fn public_types_and_strict_ed25519_reconstruct_qc_tc_threshold_corpus() {
    let root: Value = serde_json::from_str(VECTOR).expect("valid QC/TC vector JSON");
    assert_eq!(
        string(&root, "schema"),
        "trnm_poco_bft_qc_tc_threshold_vectors_v0"
    );

    let context = object(&root, "context");
    let validator_set_vector = object(&root, "validator_set");
    let reconstructed_validator_set = build_validator_set(context, validator_set_vector);
    let validator_set =
        decode_validator_set_v0_exact(&hex_vec(string(validator_set_vector, "cev0_hex")))
            .expect("raw validator-set CEV0 must decode exactly");
    assert_eq!(validator_set, reconstructed_validator_set);
    assert_eq!(validator_set.total_power(), 10);
    assert_eq!(validator_set.quorum_power(), 7);
    assert_eq!(
        validator_set.id().as_bytes(),
        &hex_array(string(validator_set_vector, "validator_set_id_hex"))
    );

    let verifier = StrictEd25519Verifier;
    let qc_vectors = object(&root, "quorum_certificates");
    let mut valid_qcs = BTreeMap::new();
    for label in [
        "low_exact_7",
        "high_exact_7",
        "future_exact_7",
        "same_block_variant_exact_7",
        "high_alternate_exact_7",
    ] {
        let vector = object(qc_vectors, label);
        let reconstructed = build_qc(vector, &validator_set)
            .unwrap_or_else(|error| panic!("{label} construction failed: {error:?}"));
        let raw = hex_vec(string(vector, "cev0_hex"));
        let certificate = decode_ordinary_qc_v0_exact(&raw, &validator_set)
            .unwrap_or_else(|error| panic!("{label} raw decode failed: {error:?}"));
        assert_eq!(
            certificate, reconstructed,
            "QC field mapping mismatch for {label}"
        );
        certificate
            .verify(&validator_set, &verifier)
            .unwrap_or_else(|error| panic!("{label} verification failed: {error:?}"));
        assert_eq!(
            certificate.try_cev0_bytes().expect("bounded QC CEV0"),
            raw,
            "QC CEV0 mismatch for {label}"
        );
        assert_eq!(
            certificate.id().as_bytes(),
            &hex_array(string(vector, "digest_hex")),
            "QC digest mismatch for {label}"
        );
        for (vote, vote_vector) in certificate
            .votes()
            .iter()
            .zip(array(vector, "votes").iter())
        {
            assert_eq!(
                vote.signing_root().as_bytes(),
                &hex_array(string(vote_vector, "signing_root_hex")),
                "vote signing root mismatch for {label}"
            );
        }
        valid_qcs.insert(label, certificate);
    }

    for field in [
        "timeout_certificate_exact_7",
        "timeout_certificate_digest_tiebreak_exact_7",
    ] {
        let tc_vector = object(&root, field);
        let reconstructed = build_tc(tc_vector, &validator_set, &valid_qcs)
            .unwrap_or_else(|error| panic!("{field} construction failed: {error:?}"));
        let raw = hex_vec(string(tc_vector, "cev0_hex"));
        let certificate = decode_ordinary_timeout_certificate_v0_exact(&raw, &validator_set)
            .unwrap_or_else(|error| panic!("{field} raw decode failed: {error:?}"));
        assert_eq!(
            certificate, reconstructed,
            "TC field mapping mismatch for {field}"
        );
        certificate
            .verify(&validator_set, None, &verifier)
            .unwrap_or_else(|error| panic!("{field} verification failed: {error:?}"));
        assert_eq!(
            certificate.try_cev0_bytes().expect("bounded TC CEV0"),
            raw,
            "TC CEV0 mismatch for {field}"
        );
        assert_eq!(
            certificate.id().as_bytes(),
            &hex_array(string(tc_vector, "digest_hex")),
            "TC digest mismatch for {field}"
        );
        for (entry, entry_vector) in certificate
            .entries()
            .iter()
            .zip(array(tc_vector, "entries").iter())
        {
            let root = TimeoutVote::signing_root_for_set(
                &validator_set,
                certificate.timed_out_view(),
                entry.high_qc(),
            )
            .expect("shape-valid timeout signing root");
            assert_eq!(
                root.as_bytes(),
                &hex_array(string(entry_vector, "signing_root_hex"))
            );
        }
        if field == "timeout_certificate_digest_tiebreak_exact_7" {
            let referenced = certificate.referenced_qcs();
            assert_eq!(referenced.len(), 2);
            let first = referenced[0].qc_ref();
            let second = referenced[1].qc_ref();
            assert_eq!(first.view(), second.view());
            assert_eq!(first.block_id(), second.block_id());
            assert_ne!(first.qc_digest(), second.qc_digest());
            assert_eq!(
                certificate.selected_high_qc_digest(),
                core::cmp::max(first.qc_digest(), second.qc_digest()),
                "same-view same-block tie must select the greater QC digest"
            );
        }
    }

    let parser_root: Value =
        serde_json::from_str(PARSER_VECTOR).expect("valid B2-A parser vector JSON");
    let stable_expectations = array(&parser_root, "imported_b1_semantic_cases")
        .iter()
        .map(|case| {
            (
                string(case, "source_case_id"),
                string(case, "expected_error_code"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        stable_expectations.len(),
        array(&root, "negative_cases").len(),
        "the B2-A corpus must classify every B1 negative case"
    );

    for case in array(&root, "negative_cases") {
        let identifier = string(case, "id");
        let expected = stable_expectations
            .get(identifier)
            .unwrap_or_else(|| panic!("missing B2-A stable code for {identifier}"));
        let vector = object(case, "object");
        let rejection = match string(case, "object_type") {
            "qc" => raw_qc_rejection(vector, &validator_set, &verifier),
            "tc" => raw_tc_rejection(vector, &validator_set, &verifier),
            kind => panic!("unknown negative-case object type {kind}"),
        };
        assert_eq!(
            rejection, *expected,
            "{identifier} did not preserve the B2-A stable admission code"
        );
    }
}

fn build_validator_set(context: &Value, vector: &Value) -> ValidatorSet {
    let validators = array(vector, "validators")
        .iter()
        .map(|value| {
            Validator::new(
                validator_id(string(value, "id_ascii")),
                ConsensusPublicKey::new(hex_array(string(value, "public_key_hex"))),
                VotingPower::new(number(value, "power")).expect("positive fixture power"),
            )
            .expect("shape-valid fixture validator")
        })
        .collect();
    ValidatorSet::new(
        GenesisHash::new(hex_array(string(context, "genesis_hash_hex"))),
        ChainId::new(string(context, "chain_id")).expect("valid fixture chain ID"),
        ProtocolVersion::new(number_u32(context, "protocol_version"))
            .expect("valid fixture protocol version"),
        Epoch::new(number(context, "epoch")),
        ConsensusParametersHash::new(hex_array(string(context, "consensus_parameters_hash_hex"))),
        validators,
    )
    .expect("shape-valid unequal-power validator set")
}

fn build_qc(
    vector: &Value,
    validator_set: &ValidatorSet,
) -> trnm_consensus_types::Result<QuorumCertificate> {
    let chain_id = validator_set.chain_id();
    let protocol_version = validator_set.protocol_version();
    let epoch = validator_set.epoch();
    let view = View::new(number(vector, "view"));
    let height = Height::new(number(vector, "height"));
    let block_id = BlockId::new(hex_array(string(vector, "block_id_hex")));
    let votes = array(vector, "votes")
        .iter()
        .map(|vote| {
            Vote::new(
                chain_id,
                protocol_version,
                epoch,
                view,
                height,
                block_id,
                validator_set.id(),
                validator_id(string(vote, "signer_id_ascii")),
                Signature64::from_array(hex_array(string(vote, "signature_hex"))),
                validator_set,
            )
        })
        .collect::<trnm_consensus_types::Result<Vec<_>>>()?;
    QuorumCertificate::new(
        chain_id,
        protocol_version,
        epoch,
        view,
        height,
        block_id,
        validator_set.id(),
        votes,
        validator_set,
    )
}

fn build_tc(
    vector: &Value,
    validator_set: &ValidatorSet,
    qcs: &BTreeMap<&str, QuorumCertificate>,
) -> trnm_consensus_types::Result<TimeoutCertificateV0> {
    let entries = array(vector, "entries")
        .iter()
        .map(|entry| {
            TimeoutEntryV0::new(
                validator_id(string(entry, "signer_id_ascii")),
                parse_qc_ref(object(entry, "high_qc")),
                Signature64::from_array(hex_array(string(entry, "signature_hex"))),
            )
        })
        .collect::<trnm_consensus_types::Result<Vec<_>>>()?;
    let referenced = array(vector, "referenced_qcs")
        .iter()
        .map(|label| {
            let label = label.as_str().expect("referenced-QC label string");
            QcReferenceV0::ordinary(
                qcs.get(label)
                    .unwrap_or_else(|| panic!("unknown referenced-QC label {label}"))
                    .clone(),
            )
        })
        .collect();
    TimeoutCertificateV0::new(
        View::new(number(vector, "timed_out_view")),
        entries,
        referenced,
        CertificateId::new(hex_array(string(vector, "selected_high_qc_digest_hex"))),
        validator_set,
    )
}

fn raw_qc_rejection(
    vector: &Value,
    validator_set: &ValidatorSet,
    verifier: &StrictEd25519Verifier,
) -> &'static str {
    match decode_ordinary_qc_v0_exact(&hex_vec(string(vector, "cev0_hex")), validator_set) {
        Err(error) => error.code().as_str(),
        Ok(certificate) => {
            let error = certificate
                .verify(validator_set, verifier)
                .expect_err("negative raw QC must fail decoding or verification");
            match error {
                ValidationError::InvalidSignature(_) => "invalid_signature",
                other => panic!("unexpected post-decode QC error: {other:?}"),
            }
        }
    }
}

fn raw_tc_rejection(
    vector: &Value,
    validator_set: &ValidatorSet,
    verifier: &StrictEd25519Verifier,
) -> &'static str {
    match decode_ordinary_timeout_certificate_v0_exact(
        &hex_vec(string(vector, "cev0_hex")),
        validator_set,
    ) {
        Err(error) => error.code().as_str(),
        Ok(certificate) => {
            let error = certificate
                .verify(validator_set, None, verifier)
                .expect_err("negative raw TC must fail decoding or verification");
            match error {
                ValidationError::InvalidSignature(_) => "invalid_signature",
                other => panic!("unexpected post-decode TC error: {other:?}"),
            }
        }
    }
}

fn parse_qc_ref(value: &Value) -> QcRef {
    QcRef::new(
        CertificateId::new(hex_array(string(value, "qc_digest_hex"))),
        Epoch::new(number(value, "epoch")),
        View::new(number(value, "view")),
        Height::new(number(value, "height")),
        BlockId::new(hex_array(string(value, "block_id_hex"))),
        ValidatorSetId::new(hex_array(string(value, "validator_set_id_hex"))),
    )
}

fn validator_id(value: &str) -> ValidatorId {
    ValidatorId::from_bytes(value.as_bytes()).expect("bounded nonempty fixture validator ID")
}

fn object<'a>(value: &'a Value, field: &str) -> &'a Value {
    value
        .get(field)
        .unwrap_or_else(|| panic!("missing JSON object field {field}"))
}

fn array<'a>(value: &'a Value, field: &str) -> &'a [Value] {
    object(value, field)
        .as_array()
        .unwrap_or_else(|| panic!("JSON field {field} is not an array"))
}

fn string<'a>(value: &'a Value, field: &str) -> &'a str {
    object(value, field)
        .as_str()
        .unwrap_or_else(|| panic!("JSON field {field} is not a string"))
}

fn number(value: &Value, field: &str) -> u64 {
    object(value, field)
        .as_u64()
        .unwrap_or_else(|| panic!("JSON field {field} is not a u64"))
}

fn number_u32(value: &Value, field: &str) -> u32 {
    number(value, field)
        .try_into()
        .unwrap_or_else(|_| panic!("JSON field {field} exceeds u32"))
}

fn hex_vec(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex fixture has odd length");
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).expect("lowercase hex byte"))
        .collect()
}

fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    hex_vec(value)
        .try_into()
        .unwrap_or_else(|bytes: Vec<u8>| panic!("expected {N} bytes, got {}", bytes.len()))
}
