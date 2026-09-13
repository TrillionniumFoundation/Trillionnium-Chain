use std::collections::BTreeSet;

use serde_json::Value;
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_types::{
    decode_block_header_v0_exact, decode_epoch_anchor_authorization_kernel_v0_exact,
    decode_handoff_certificate_v0_exact, decode_handoff_descriptor_v0_exact,
    decode_ordinary_qc_v0_exact, decode_validator_set_v0_exact, CanonicalSignable, DecodeErrorCode,
    HandoffDescriptorV0, Signature64, SignatureShareV0, SignatureVerifier, SigningRoot,
    ValidationError, ValidatorSet,
};

const VECTOR: &str = include_str!(
    "../../../../docs/protocol/poco-bft-v0/vectors/handoff-certificate-kernel-v0.json"
);

const HASH_PREFIX: &[u8] = b"trnm.cev0.hash.v0";
const DOMAIN_QC: &[u8] = b"trnm.poco-bft.qc.v0";
const DOMAIN_HANDOFF_VOTE: &[u8] = b"trnm.poco-bft.handoff-vote.v0";

#[test]
fn exact_raw_handoff_kernel_decodes_reencodes_and_strictly_verifies() {
    let root: Value = serde_json::from_str(VECTOR).expect("valid handoff vector JSON");
    assert_eq!(
        string(&root, "schema"),
        "trnm_poco_bft_handoff_certificate_kernel_vectors_v0"
    );

    let sets = object(&root, "validator_sets");
    let old_set_vector = object(sets, "old");
    let new_set_vector = object(sets, "new");
    let old_set = decode_set(old_set_vector, "old");
    let new_set = decode_set(new_set_vector, "new");
    assert_eq!(old_set.total_power(), 10);
    assert_eq!(old_set.quorum_power(), 7);
    assert_eq!(new_set.total_power(), 10);
    assert_eq!(new_set.quorum_power(), 7);
    assert_ne!(old_set.id(), new_set.id());

    let header_vector = object(&root, "terminal_old_header");
    let header_raw = hex_vec(string(header_vector, "cev0_hex"));
    let header = decode_block_header_v0_exact(&header_raw)
        .expect("terminal EpochSeal2 header must exact-decode");
    assert_eq!(
        header.try_cev0_bytes().expect("bounded header CEV0"),
        header_raw
    );
    assert_eq!(number_u16(header_vector, "schema_version"), 0);
    assert_eq!(
        header.id().as_bytes(),
        &hex_array(string(header_vector, "block_id_hex"))
    );
    assert_eq!(header.genesis_hash(), old_set.genesis_hash());
    assert_eq!(header.chain_id(), old_set.chain_id());
    assert_eq!(header.protocol_version(), old_set.protocol_version());
    assert_eq!(header.epoch(), old_set.epoch());
    assert_eq!(header.validator_set_id(), old_set.id());
    assert_eq!(
        header.consensus_parameters_hash(),
        old_set.consensus_parameters_hash()
    );
    assert_eq!(header.view().get(), number(header_vector, "view"));
    assert_eq!(header.height().get(), number(header_vector, "height"));
    assert_eq!(
        header.block_kind() as u8,
        number_u8(header_vector, "block_kind")
    );
    assert_eq!(
        header.parent_id().as_bytes(),
        &hex_array(string(header_vector, "parent_block_id_hex"))
    );
    assert_eq!(
        header.proposer_id().as_bytes(),
        string(header_vector, "proposer_id_ascii").as_bytes()
    );
    assert_eq!(
        header.payload_digest().as_bytes(),
        &hex_array(string(header_vector, "payload_digest_hex"))
    );
    assert_eq!(
        header.state_root().as_bytes(),
        &hex_array(string(header_vector, "state_root_hex"))
    );
    assert_eq!(
        header.receipts_root().as_bytes(),
        &hex_array(string(header_vector, "receipts_root_hex"))
    );
    assert_eq!(
        header.evidence_root().as_bytes(),
        &hex_array(string(header_vector, "evidence_root_hex"))
    );
    assert_eq!(header.timestamp_ms(), number(header_vector, "timestamp_ms"));
    assert_eq!(
        header
            .next_epoch_commitment_hash()
            .expect("EpochSeal2 must commit the next epoch")
            .as_bytes(),
        &hex_array(string(header_vector, "next_epoch_commitment_hash_hex"))
    );

    let qcs = object(&root, "terminal_old_qcs");
    let terminal_qc_vector = object(qcs, "exact_7");
    let terminal_qc_raw = hex_vec(string(terminal_qc_vector, "cev0_hex"));
    let terminal_qc = decode_ordinary_qc_v0_exact(&terminal_qc_raw, &old_set)
        .expect("terminal ordinary QC must exact-decode");
    assert_eq!(
        terminal_qc.try_cev0_bytes().expect("bounded terminal QC"),
        terminal_qc_raw
    );
    assert_eq!(
        terminal_qc.id().as_bytes(),
        &hex_array(string(terminal_qc_vector, "digest_hex"))
    );
    assert_eq!(terminal_qc.block_id(), header.id());
    assert_eq!(terminal_qc.genesis_hash(), old_set.genesis_hash());
    assert_eq!(terminal_qc.chain_id(), old_set.chain_id());
    assert_eq!(terminal_qc.protocol_version(), old_set.protocol_version());
    assert_eq!(terminal_qc.epoch(), old_set.epoch());
    assert_eq!(terminal_qc.view(), header.view());
    assert_eq!(terminal_qc.height(), header.height());
    assert_eq!(terminal_qc.validator_set_id(), old_set.id());
    let verifier = StrictEd25519Verifier;
    terminal_qc
        .verify(&old_set, &verifier)
        .expect("terminal QC signatures must strictly verify");
    let mut terminal_signed_power = 0u128;
    for (vote, vector) in terminal_qc
        .votes()
        .iter()
        .zip(array(terminal_qc_vector, "votes"))
    {
        assert_eq!(
            vote.author().as_bytes(),
            string(vector, "signer_id_ascii").as_bytes()
        );
        assert_eq!(
            vote.signature().as_bytes(),
            &hex_array(string(vector, "signature_hex"))
        );
        assert_eq!(
            vote.signing_root().as_bytes(),
            &hex_array(string(vector, "signing_root_hex"))
        );
        terminal_signed_power += old_set
            .power_of(vote.author())
            .expect("terminal vote signer is in the old set");
    }
    assert_eq!(
        terminal_signed_power,
        number_u128(terminal_qc_vector, "signed_power")
    );

    let descriptor_vector = object(&root, "handoff_descriptor");
    let descriptor_raw = hex_vec(string(descriptor_vector, "cev0_hex"));
    let descriptor = decode_handoff_descriptor_v0_exact(&descriptor_raw)
        .expect("handoff descriptor must exact-decode");
    assert_eq!(
        descriptor.try_cev0_bytes().expect("bounded descriptor"),
        descriptor_raw
    );
    assert_eq!(
        descriptor.id().as_bytes(),
        &hex_array(string(descriptor_vector, "digest_hex"))
    );
    assert_descriptor_binding(
        &descriptor,
        descriptor_vector,
        &old_set,
        &new_set,
        &header,
        &terminal_qc,
    );

    let certificate_vector = object(&root, "handoff_certificate_exact_7");
    let certificate_raw = hex_vec(string(certificate_vector, "cev0_hex"));
    let certificate = decode_handoff_certificate_v0_exact(&certificate_raw, &old_set, &new_set)
        .expect("weighted handoff certificate must exact-decode");
    assert_eq!(
        certificate
            .try_cev0_bytes()
            .expect("bounded handoff certificate"),
        certificate_raw
    );
    assert_eq!(
        certificate.id().as_bytes(),
        &hex_array(string(certificate_vector, "digest_hex"))
    );
    assert_eq!(certificate.descriptor(), &descriptor);

    let role_vectors = object(&root, "handoff_vote_roots");
    let old_root = assert_role_root(&descriptor, object(role_vectors, "old"), HandoffRole::Old);
    let new_root = assert_role_root(&descriptor, object(role_vectors, "new"), HandoffRole::New);
    assert_role_shares(
        certificate.old_signatures(),
        array(certificate_vector, "old_signatures"),
        &old_set,
        old_root,
        &verifier,
    );
    assert_role_shares(
        certificate.new_signatures(),
        array(certificate_vector, "new_signatures"),
        &new_set,
        new_root,
        &verifier,
    );
    assert_eq!(
        signed_power(certificate.old_signatures(), &old_set),
        number_u128(certificate_vector, "old_signed_power")
    );
    assert_eq!(
        signed_power(certificate.new_signatures(), &new_set),
        number_u128(certificate_vector, "new_signed_power")
    );
    certificate
        .verify(&old_set, &new_set, &verifier)
        .expect("both handoff roles must strictly verify");

    let authorization_vector = object(&root, "epoch_anchor_authorization");
    assert!(object(authorization_vector, "digest_domain").is_null());
    assert!(object(authorization_vector, "digest_hex").is_null());
    let authorization_raw = hex_vec(string(authorization_vector, "cev0_hex"));
    let kernel =
        decode_epoch_anchor_authorization_kernel_v0_exact(&authorization_raw, &old_set, &new_set)
            .expect("inert epoch-anchor certificate kernel must exact-decode");
    assert_eq!(
        kernel.try_cev0_bytes().expect("bounded inert kernel CEV0"),
        authorization_raw
    );
    assert_eq!(kernel.terminal_old_header(), &header);
    assert_eq!(kernel.terminal_old_qc(), &terminal_qc);
    assert_eq!(kernel.handoff_certificate(), &certificate);
    kernel
        .verify_certificate_kernel(&old_set, &new_set, &verifier)
        .expect("certificate kernel signatures must verify");

    // This is an inert byte/field check only. No synthetic-anchor type is
    // instantiated and the kernel exposes no authorization/derivation API.
    let anchor_vector = object(&root, "derived_epoch_anchor_qc");
    let anchor_raw = anchor_bytes_from_json(anchor_vector);
    assert_eq!(anchor_raw, hex_vec(string(anchor_vector, "cev0_hex")));
    assert_eq!(
        anchor_raw,
        inert_anchor_binding_bytes(kernel.handoff_certificate().descriptor())
    );
    assert_eq!(
        canonical_digest(DOMAIN_QC, &anchor_raw),
        hex_array(string(anchor_vector, "digest_hex"))
    );
    assert_inert_anchor_fields(anchor_vector, kernel.handoff_certificate().descriptor());
}

#[test]
fn every_committed_handoff_negative_is_parser_admission_crypto_or_inert_binding() {
    let root: Value = serde_json::from_str(VECTOR).expect("valid handoff vector JSON");
    let sets = object(&root, "validator_sets");
    let old_set = decode_set(object(sets, "old"), "old");
    let new_set = decode_set(object(sets, "new"), "new");
    let verifier = StrictEd25519Verifier;
    let cases = array(&root, "negative_cases");
    assert_eq!(
        cases.len(),
        36,
        "the complete committed negative corpus moved"
    );
    let mut seen = BTreeSet::new();

    for case in cases {
        let case_id = string(case, "id");
        assert!(seen.insert(case_id), "duplicate negative case {case_id}");
        let expected = string(case, "expected_result");
        match expected {
            "invalid_signature" => {
                assert_eq!(string(case, "target"), "handoff_certificate");
                let vector = object(case, "artifact");
                let raw = hex_vec(string(vector, "cev0_hex"));
                let certificate = decode_handoff_certificate_v0_exact(&raw, &old_set, &new_set)
                    .unwrap_or_else(|error| {
                        panic!("{case_id} must decode before crypto failure: {error:?}")
                    });
                assert_eq!(
                    certificate.try_cev0_bytes().expect("bounded negative cert"),
                    raw
                );
                let error = certificate
                    .verify(&old_set, &new_set, &verifier)
                    .expect_err("crypto mutation must fail strict verification");
                assert!(
                    matches!(error, ValidationError::InvalidSignature(_)),
                    "{case_id} failed with the wrong post-decode error: {error:?}"
                );
                assert_alternate_signature_binding(
                    case,
                    &certificate,
                    &old_set,
                    &new_set,
                    &verifier,
                );
            }
            "derived_anchor_mismatch" => {
                assert_eq!(string(case, "target"), "derived_anchor_binding");
                assert_inert_derived_mismatch(case, &old_set, &new_set);
            }
            _ => {
                let expected_code = expected_decode_code(expected);
                let actual_code = decode_negative_case(case, &old_set, &new_set);
                assert_eq!(
                    actual_code, expected_code,
                    "{case_id} produced the wrong exact decoder/admission code"
                );
            }
        }
    }
    assert_eq!(seen.len(), cases.len());
}

fn decode_set(vector: &Value, label: &str) -> ValidatorSet {
    let raw = hex_vec(string(vector, "cev0_hex"));
    let set = decode_validator_set_v0_exact(&raw)
        .unwrap_or_else(|error| panic!("{label} validator set failed decoding: {error:?}"));
    assert_eq!(set.try_cev0_bytes().expect("bounded validator set"), raw);
    assert_eq!(number_u16(vector, "schema_version"), 0);
    assert_eq!(
        set.id().as_bytes(),
        &hex_array(string(vector, "validator_set_id_hex"))
    );
    assert_eq!(
        set.genesis_hash().as_bytes(),
        &hex_array(string(vector, "genesis_hash_hex"))
    );
    assert_eq!(
        set.chain_id().as_bytes(),
        string(vector, "chain_id").as_bytes()
    );
    assert_eq!(
        set.protocol_version().get(),
        number_u32(vector, "protocol_version")
    );
    assert_eq!(set.epoch().get(), number(vector, "epoch"));
    assert_eq!(
        set.consensus_parameters_hash().as_bytes(),
        &hex_array(string(vector, "consensus_parameters_hash_hex"))
    );
    assert_eq!(set.total_power(), number_u128(vector, "total_power"));
    assert_eq!(set.quorum_power(), number_u128(vector, "quorum_power"));
    assert_eq!(set.validators().len(), array(vector, "validators").len());
    for (validator, json) in set.validators().iter().zip(array(vector, "validators")) {
        assert_eq!(
            validator.id().as_bytes(),
            string(json, "id_ascii").as_bytes()
        );
        assert_eq!(
            validator.consensus_key().as_bytes(),
            &hex_array(string(json, "public_key_hex"))
        );
        assert_eq!(validator.voting_power().get(), number(json, "power"));
    }
    set
}

fn assert_descriptor_binding(
    descriptor: &HandoffDescriptorV0,
    vector: &Value,
    old_set: &ValidatorSet,
    new_set: &ValidatorSet,
    header: &trnm_consensus_types::BlockHeader,
    terminal_qc: &trnm_consensus_types::QuorumCertificate,
) {
    let fields = descriptor.fields();
    assert_eq!(fields.genesis_hash, old_set.genesis_hash());
    assert_eq!(fields.chain_id, old_set.chain_id());
    assert_eq!(number_u16(vector, "schema_version"), 0);
    assert_eq!(
        fields.genesis_hash.as_bytes(),
        &hex_array(string(vector, "genesis_hash_hex"))
    );
    assert_eq!(
        fields.chain_id.as_bytes(),
        string(vector, "chain_id").as_bytes()
    );
    assert_eq!(fields.old_epoch, old_set.epoch());
    assert_eq!(fields.new_epoch, new_set.epoch());
    assert_eq!(fields.old_protocol_version, old_set.protocol_version());
    assert_eq!(fields.new_protocol_version, new_set.protocol_version());
    assert_eq!(fields.old_validator_set_hash, old_set.id());
    assert_eq!(fields.new_validator_set_hash, new_set.id());
    assert_eq!(
        fields.old_consensus_parameters_hash,
        old_set.consensus_parameters_hash()
    );
    assert_eq!(
        fields.new_consensus_parameters_hash,
        new_set.consensus_parameters_hash()
    );
    assert_eq!(fields.terminal_old_height, header.height());
    assert_eq!(fields.terminal_old_view, header.view());
    assert_eq!(fields.terminal_old_block_id, header.id());
    assert_eq!(fields.terminal_old_qc_digest, terminal_qc.id());
    assert_eq!(fields.checkpoint_state_root, header.state_root());
    assert_eq!(
        Some(fields.next_epoch_commitment_digest),
        header.next_epoch_commitment_hash()
    );
    assert_eq!(fields.activation_height.get(), header.height().get() + 1);
    assert_eq!(fields.initial_new_view.get(), 1);
    assert_eq!(fields.old_epoch.get(), number(vector, "old_epoch"));
    assert_eq!(fields.new_epoch.get(), number(vector, "new_epoch"));
    assert_eq!(
        fields.old_protocol_version.get(),
        number_u32(vector, "old_protocol_version")
    );
    assert_eq!(
        fields.new_protocol_version.get(),
        number_u32(vector, "new_protocol_version")
    );
    assert_eq!(
        fields.old_validator_set_hash.as_bytes(),
        &hex_array(string(vector, "old_validator_set_hash_hex"))
    );
    assert_eq!(
        fields.new_validator_set_hash.as_bytes(),
        &hex_array(string(vector, "new_validator_set_hash_hex"))
    );
    assert_eq!(
        fields.old_consensus_parameters_hash.as_bytes(),
        &hex_array(string(vector, "old_consensus_parameters_hash_hex"))
    );
    assert_eq!(
        fields.new_consensus_parameters_hash.as_bytes(),
        &hex_array(string(vector, "new_consensus_parameters_hash_hex"))
    );
    assert_eq!(
        fields.checkpoint_height.get(),
        number(vector, "checkpoint_height")
    );
    assert_eq!(
        fields.checkpoint_block_id.as_bytes(),
        &hex_array(string(vector, "checkpoint_block_id_hex"))
    );
    assert_eq!(
        fields.checkpoint_state_root.as_bytes(),
        &hex_array(string(vector, "checkpoint_state_root_hex"))
    );
    assert_eq!(
        fields.next_epoch_commitment_digest.as_bytes(),
        &hex_array(string(vector, "next_epoch_commitment_digest_hex"))
    );
    assert_eq!(
        fields.terminal_old_height.get(),
        number(vector, "terminal_old_height")
    );
    assert_eq!(
        fields.terminal_old_block_id.as_bytes(),
        &hex_array(string(vector, "terminal_old_block_id_hex"))
    );
    assert_eq!(
        fields.terminal_old_qc_digest.as_bytes(),
        &hex_array(string(vector, "terminal_old_qc_digest_hex"))
    );
    assert_eq!(
        fields.terminal_old_view.get(),
        number(vector, "terminal_old_view")
    );
    assert_eq!(
        fields.activation_height.get(),
        number(vector, "activation_height")
    );
    assert_eq!(
        fields.initial_new_view.get(),
        number(vector, "initial_new_view")
    );
}

#[derive(Clone, Copy)]
enum HandoffRole {
    Old,
    New,
}

fn assert_role_root(
    descriptor: &HandoffDescriptorV0,
    vector: &Value,
    role: HandoffRole,
) -> [u8; 32] {
    let expected_preimage = handoff_vote_preimage(descriptor, role);
    let committed_preimage = hex_vec(string(vector, "cev0_hex"));
    assert_eq!(committed_preimage, expected_preimage);
    let root = canonical_digest(DOMAIN_HANDOFF_VOTE, &committed_preimage);
    assert_eq!(
        root,
        hex_array(string(vector, "signing_root_hex")),
        "handoff role root mismatch"
    );
    assert_eq!(
        descriptor.id().as_bytes(),
        &hex_array(string(vector, "handoff_descriptor_digest_hex"))
    );
    match role {
        HandoffRole::Old => {
            assert_eq!(string(vector, "role"), "old");
            assert_eq!(number_u8(vector, "message_kind"), 3);
        }
        HandoffRole::New => {
            assert_eq!(string(vector, "role"), "new");
            assert_eq!(number_u8(vector, "message_kind"), 4);
        }
    }
    root
}

fn assert_role_shares(
    shares: &[SignatureShareV0],
    vectors: &[Value],
    validator_set: &ValidatorSet,
    root: [u8; 32],
    verifier: &StrictEd25519Verifier,
) {
    assert_eq!(shares.len(), vectors.len());
    let signing_root = SigningRoot::new(root);
    for (share, vector) in shares.iter().zip(vectors) {
        assert_eq!(
            share.validator_id().as_bytes(),
            string(vector, "signer_id_ascii").as_bytes()
        );
        assert_eq!(
            share.signature().as_bytes(),
            &hex_array(string(vector, "signature_hex"))
        );
        assert_eq!(
            root,
            hex_array(string(vector, "signing_root_hex")),
            "share exposes the wrong role root"
        );
        let validator = validator_set
            .validator(share.validator_id())
            .expect("decoded share must name a set member");
        assert!(verifier.verify(validator, &signing_root, share.signature()));
    }
}

fn signed_power(shares: &[SignatureShareV0], validator_set: &ValidatorSet) -> u128 {
    shares.iter().fold(0u128, |total, share| {
        total
            .checked_add(
                validator_set
                    .power_of(share.validator_id())
                    .expect("decoded handoff signer is in its role set"),
            )
            .expect("bounded handoff power sum")
    })
}

fn handoff_vote_preimage(descriptor: &HandoffDescriptorV0, role: HandoffRole) -> Vec<u8> {
    let fields = descriptor.fields();
    let (version, epoch, set, view, kind) = match role {
        HandoffRole::Old => (
            fields.old_protocol_version.get(),
            fields.old_epoch.get(),
            fields.old_validator_set_hash.as_bytes(),
            fields.terminal_old_view.get(),
            3u8,
        ),
        HandoffRole::New => (
            fields.new_protocol_version.get(),
            fields.new_epoch.get(),
            fields.new_validator_set_hash.as_bytes(),
            fields.initial_new_view.get(),
            4u8,
        ),
    };
    let mut encoded = Vec::new();
    push_u16(&mut encoded, 0);
    encoded.extend_from_slice(fields.genesis_hash.as_bytes());
    push_consensus_string(&mut encoded, fields.chain_id.as_bytes());
    push_u32(&mut encoded, version);
    push_u64(&mut encoded, epoch);
    encoded.extend_from_slice(set);
    push_u64(&mut encoded, view);
    encoded.push(kind);
    encoded.extend_from_slice(descriptor.id().as_bytes());
    encoded
}

fn inert_anchor_binding_bytes(descriptor: &HandoffDescriptorV0) -> Vec<u8> {
    let fields = descriptor.fields();
    let mut encoded = Vec::new();
    push_u16(&mut encoded, 0);
    encoded.extend_from_slice(fields.genesis_hash.as_bytes());
    push_consensus_string(&mut encoded, fields.chain_id.as_bytes());
    push_u32(&mut encoded, fields.new_protocol_version.get());
    push_u64(&mut encoded, fields.new_epoch.get());
    encoded.extend_from_slice(fields.new_validator_set_hash.as_bytes());
    push_u64(&mut encoded, 0);
    push_u64(&mut encoded, fields.terminal_old_height.get());
    encoded.extend_from_slice(fields.terminal_old_block_id.as_bytes());
    push_u32(&mut encoded, 0);
    encoded
}

fn anchor_bytes_from_json(vector: &Value) -> Vec<u8> {
    assert!(array(vector, "votes").is_empty());
    let mut encoded = Vec::new();
    push_u16(&mut encoded, number_u16(vector, "schema_version"));
    encoded.extend_from_slice(&hex_array::<32>(string(vector, "genesis_hash_hex")));
    push_consensus_string(&mut encoded, string(vector, "chain_id").as_bytes());
    push_u32(&mut encoded, number_u32(vector, "protocol_version"));
    push_u64(&mut encoded, number(vector, "epoch"));
    encoded.extend_from_slice(&hex_array::<32>(string(vector, "validator_set_id_hex")));
    push_u64(&mut encoded, number(vector, "view"));
    push_u64(&mut encoded, number(vector, "height"));
    encoded.extend_from_slice(&hex_array::<32>(string(vector, "block_id_hex")));
    push_u32(&mut encoded, 0);
    encoded
}

fn assert_inert_anchor_fields(vector: &Value, descriptor: &HandoffDescriptorV0) {
    let fields = descriptor.fields();
    assert_eq!(number_u16(vector, "schema_version"), 0);
    assert_eq!(
        hex_array::<32>(string(vector, "genesis_hash_hex")),
        *fields.genesis_hash.as_bytes()
    );
    assert_eq!(
        string(vector, "chain_id").as_bytes(),
        fields.chain_id.as_bytes()
    );
    assert_eq!(
        number_u32(vector, "protocol_version"),
        fields.new_protocol_version.get()
    );
    assert_eq!(number(vector, "epoch"), fields.new_epoch.get());
    assert_eq!(
        hex_array::<32>(string(vector, "validator_set_id_hex")),
        *fields.new_validator_set_hash.as_bytes()
    );
    assert_eq!(number(vector, "view"), 0);
    assert_eq!(number(vector, "height"), fields.terminal_old_height.get());
    assert_eq!(
        hex_array::<32>(string(vector, "block_id_hex")),
        *fields.terminal_old_block_id.as_bytes()
    );
    assert!(array(vector, "votes").is_empty());
}

fn expected_decode_code(expected: &str) -> DecodeErrorCode {
    match expected {
        "insufficient_quorum" | "old_insufficient_quorum" | "new_insufficient_quorum" => {
            DecodeErrorCode::InsufficientQuorum
        }
        "old_duplicate_signer" | "new_duplicate_signer" => DecodeErrorCode::DuplicateSigner,
        "old_noncanonical_signer_order" | "new_noncanonical_signer_order" => {
            DecodeErrorCode::NonCanonicalSignerOrder
        }
        "old_unknown_signer" | "new_unknown_signer" => DecodeErrorCode::UnknownSigner,
        "descriptor_old_set_mismatch"
        | "descriptor_new_set_mismatch"
        | "descriptor_old_parameters_mismatch"
        | "descriptor_new_parameters_mismatch"
        | "descriptor_old_version_mismatch"
        | "descriptor_new_version_mismatch" => DecodeErrorCode::InvalidHandoffCertificate,
        "descriptor_epoch_mismatch"
        | "descriptor_activation_height_mismatch"
        | "descriptor_initial_view_mismatch" => DecodeErrorCode::InvalidHandoffDescriptor,
        "terminal_not_epoch_seal_2"
        | "terminal_header_id_mismatch"
        | "terminal_qc_digest_mismatch"
        | "terminal_header_height_mismatch"
        | "terminal_header_view_mismatch"
        | "terminal_qc_block_mismatch"
        | "terminal_qc_view_mismatch"
        | "terminal_qc_height_mismatch"
        | "terminal_header_set_mismatch" => DecodeErrorCode::InvalidEpochAnchorRelations,
        "validator_set_mismatch" => DecodeErrorCode::ContextMismatch,
        "unauthorized_synthetic_qc" => DecodeErrorCode::UnauthorizedSyntheticQc,
        other => panic!("unclassified negative expected_result {other}"),
    }
}

fn decode_negative_case(
    case: &Value,
    old_set: &ValidatorSet,
    new_set: &ValidatorSet,
) -> DecodeErrorCode {
    let case_id = string(case, "id");
    let artifact = object(case, "artifact");
    let raw = hex_vec(string(artifact, "cev0_hex"));
    let error = match string(case, "target") {
        "terminal_qc" => decode_ordinary_qc_v0_exact(&raw, old_set)
            .expect_err("negative terminal QC must fail exact admission"),
        "ordinary_qc" => {
            let role = string(case, "validator_role");
            let set = match role {
                "old" => old_set,
                "new" => new_set,
                other => panic!("{case_id} has unclassified validator role {other}"),
            };
            decode_ordinary_qc_v0_exact(&raw, set)
                .expect_err("negative ordinary QC must fail exact admission")
        }
        "handoff_certificate" => decode_handoff_certificate_v0_exact(&raw, old_set, new_set)
            .expect_err("negative handoff certificate must fail exact admission"),
        "epoch_anchor_authorization" => {
            decode_epoch_anchor_authorization_kernel_v0_exact(&raw, old_set, new_set)
                .expect_err("negative inert authorization kernel must fail exact admission")
        }
        other => panic!("{case_id} has unclassified parser target {other}"),
    };
    error.code()
}

fn assert_alternate_signature_binding(
    case: &Value,
    certificate: &trnm_consensus_types::HandoffCertificateV0,
    old_set: &ValidatorSet,
    new_set: &ValidatorSet,
    verifier: &StrictEd25519Verifier,
) {
    let Some(alternate) = case.get("alternate_signature_binding") else {
        return;
    };
    let domain = match string(alternate, "domain_ascii") {
        "trnm.poco-bft.handoff-vote.v0" => DOMAIN_HANDOFF_VOTE,
        "trnm.poco-bft.qc.v0" => DOMAIN_QC,
        other => panic!("unknown alternate signing domain {other}"),
    };
    let preimage = hex_vec(string(alternate, "signing_preimage_cev0_hex"));
    let root = canonical_digest(domain, &preimage);
    assert_eq!(
        root,
        hex_array(string(alternate, "signing_root_hex")),
        "alternate root is not bound to its committed domain/preimage"
    );
    let signer = string(alternate, "signer_id_ascii");
    let signature = Signature64::from_array(hex_array(string(alternate, "signature_hex")));
    let validator_id = trnm_consensus_types::ValidatorId::from_bytes(signer.as_bytes())
        .expect("bounded alternate signer ID");
    let validator = old_set
        .validator(validator_id)
        .or_else(|| new_set.validator(validator_id))
        .expect("alternate signer must belong to one committed set");
    assert!(verifier.verify(validator, &SigningRoot::new(root), &signature));
    assert!(certificate
        .old_signatures()
        .iter()
        .chain(certificate.new_signatures())
        .any(|share| share.validator_id() == validator_id && share.signature() == &signature));
}

fn assert_inert_derived_mismatch(case: &Value, old_set: &ValidatorSet, new_set: &ValidatorSet) {
    assert_eq!(string(case, "target"), "derived_anchor_binding");
    let artifact = object(case, "artifact");
    let authorization = object(artifact, "authorization");
    let raw = hex_vec(string(authorization, "cev0_hex"));
    let kernel = decode_epoch_anchor_authorization_kernel_v0_exact(&raw, old_set, new_set)
        .expect("derived mismatch must retain a valid inert certificate kernel");
    assert_eq!(kernel.try_cev0_bytes().expect("bounded inert kernel"), raw);

    let claimed = object(artifact, "claimed_epoch_anchor_qc");
    let claimed_raw = anchor_bytes_from_json(claimed);
    assert_eq!(claimed_raw, hex_vec(string(claimed, "cev0_hex")));
    assert_eq!(
        canonical_digest(DOMAIN_QC, &claimed_raw),
        hex_array(string(claimed, "digest_hex"))
    );
    let expected = inert_anchor_binding_bytes(kernel.handoff_certificate().descriptor());
    assert_ne!(claimed_raw, expected);
    assert_eq!(
        number(claimed, "height"),
        kernel
            .handoff_certificate()
            .descriptor()
            .fields()
            .terminal_old_height
            .get()
    );
    assert_ne!(
        hex_array::<32>(string(claimed, "block_id_hex")),
        *kernel
            .handoff_certificate()
            .descriptor()
            .fields()
            .terminal_old_block_id
            .as_bytes()
    );
}

fn canonical_digest(domain: &[u8], cev0: &[u8]) -> [u8; 32] {
    let mut input = Vec::new();
    push_frame(&mut input, HASH_PREFIX);
    push_frame(&mut input, domain);
    push_frame(&mut input, cev0);
    sha256(&input)
}

fn push_frame(output: &mut Vec<u8>, value: &[u8]) {
    push_u32(
        output,
        value.len().try_into().expect("test fixture frame fits u32"),
    );
    output.extend_from_slice(value);
}

fn push_consensus_string(output: &mut Vec<u8>, value: &[u8]) {
    push_u16(
        output,
        value
            .len()
            .try_into()
            .expect("test fixture ConsensusString fits u16"),
    );
    output.extend_from_slice(value);
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn sha256(input: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut bytes = input.to_vec();
    let bit_len = (bytes.len() as u64)
        .checked_mul(8)
        .expect("test fixture SHA-256 length fits u64");
    bytes.push(0x80);
    while bytes.len() % 64 != 56 {
        bytes.push(0);
    }
    bytes.extend_from_slice(&bit_len.to_be_bytes());

    let mut state = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    for chunk in bytes.chunks_exact(64) {
        let mut words = [0u32; 64];
        for (index, word) in words[..16].iter_mut().enumerate() {
            let start = index * 4;
            *word = u32::from_be_bytes(
                chunk[start..start + 4]
                    .try_into()
                    .expect("four-byte SHA-256 word"),
            );
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temporary1 = h
                .wrapping_add(sum1)
                .wrapping_add(choice)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temporary2 = sum0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temporary1);
            d = c;
            c = b;
            b = a;
            a = temporary1.wrapping_add(temporary2);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }
    let mut output = [0u8; 32];
    for (index, word) in state.iter().enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    output
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

fn number_u128(value: &Value, field: &str) -> u128 {
    u128::from(number(value, field))
}

fn number_u32(value: &Value, field: &str) -> u32 {
    number(value, field)
        .try_into()
        .unwrap_or_else(|_| panic!("JSON field {field} exceeds u32"))
}

fn number_u16(value: &Value, field: &str) -> u16 {
    number(value, field)
        .try_into()
        .unwrap_or_else(|_| panic!("JSON field {field} exceeds u16"))
}

fn number_u8(value: &Value, field: &str) -> u8 {
    number(value, field)
        .try_into()
        .unwrap_or_else(|_| panic!("JSON field {field} exceeds u8"))
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
