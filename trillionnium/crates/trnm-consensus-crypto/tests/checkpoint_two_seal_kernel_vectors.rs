use core::cell::Cell;

use serde_json::Value;
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_types::{
    decode_checkpoint_finality_proof_v0_exact, decode_consensus_parameters_v0_exact,
    decode_next_epoch_commitment_v0_exact, decode_ordinary_certified_header_v0_exact,
    decode_ordinary_qc_v0_exact, decode_validator_set_v0_exact, verify_finalized_cutoff_header_v0,
    BlockKind, DecodeErrorCode, SignatureBytes, SignatureVerifier, SigningRoot, ValidationError,
    Validator,
};

const VECTOR: &str = include_str!(
    "../../../../docs/protocol/poco-bft-v0/vectors/checkpoint-two-seal-kernel-v0.json"
);

#[test]
fn raw_checkpoint_two_seal_kernel_reencodes_and_strictly_verifies() {
    let root: Value = serde_json::from_str(VECTOR).expect("valid checkpoint/two-seal vector JSON");
    assert_eq!(
        string(&root, "schema"),
        "trnm_poco_bft_checkpoint_two_seal_kernel_vectors_v0"
    );
    assert_eq!(root["cryptographic_validity_claimed"], true);
    assert_eq!(root["authorization_output"], false);

    let valid = object(&root, "valid_objects");
    let parameters_vector = object(valid, "consensus_parameters");
    let parameters_raw = raw(parameters_vector);
    let parameters = decode_consensus_parameters_v0_exact(&parameters_raw)
        .expect("the complete committed parameter preimage must exact-decode");
    assert_eq!(parameters.canonical_bytes(), parameters_raw);
    assert_eq!(
        parameters.hash().as_bytes(),
        &hex_array(string(parameters_vector, "digest_hex"))
    );

    let set_vector = object(valid, "old_validator_set");
    let set_raw = raw(set_vector);
    let old_set = decode_validator_set_v0_exact(&set_raw)
        .expect("the authenticated old validator set must exact-decode");
    old_set
        .validate_against_parameters(&parameters)
        .expect("the old set must satisfy the decoded committed parameters");
    assert_eq!(
        old_set.try_cev0_bytes().expect("bounded validator set"),
        set_raw
    );
    assert_eq!(
        old_set.id().as_bytes(),
        &hex_array(string(set_vector, "digest_hex"))
    );
    let zero_key_case = array(&root, "parser_boundaries")
        .iter()
        .find(|case| string(case, "id") == "validator_set_zero_public_key")
        .expect("the committed corpus locks zero-key rejection");
    let zero_key_error = decode_validator_set_v0_exact(&hex_vec(string(zero_key_case, "raw_hex")))
        .expect_err("a zero consensus public key must fail closed");
    assert_eq!(
        zero_key_error.code().as_str(),
        string(zero_key_case, "expected_code")
    );
    assert_eq!(
        zero_key_error.byte_offset(),
        number_usize(zero_key_case, "expected_offset")
    );

    let fixture = object(&root, "fixture");
    assert_eq!(
        old_set.chain_id().as_bytes(),
        string(fixture, "chain_id_ascii").as_bytes()
    );
    assert_eq!(
        old_set.genesis_hash().as_bytes(),
        &hex_array(string(fixture, "genesis_hash_hex"))
    );
    assert_eq!(old_set.epoch().get(), number(fixture, "old_epoch"));
    assert_eq!(
        old_set.total_power(),
        number_u128(fixture, "validator_total_power")
    );
    assert_eq!(old_set.quorum_power(), number_u128(fixture, "quorum_power"));
    assert_eq!(
        parameters.epoch_length_blocks(),
        number(fixture, "epoch_length_blocks")
    );
    assert_eq!(
        old_set.validators().len(),
        array(fixture, "validators").len()
    );
    for (validator, vector) in old_set
        .validators()
        .iter()
        .zip(array(fixture, "validators"))
    {
        assert_eq!(
            validator.id().as_bytes(),
            string(vector, "validator_id_ascii").as_bytes()
        );
        assert_eq!(
            validator.consensus_key().as_bytes(),
            &hex_array(string(vector, "public_key_hex"))
        );
        assert_eq!(
            validator.voting_power().get(),
            number(vector, "voting_power")
        );
    }

    let commitment_vector = object(valid, "next_epoch_commitment");
    let commitment_raw = raw(commitment_vector);
    let commitment = decode_next_epoch_commitment_v0_exact(&commitment_raw)
        .expect("the inert next-epoch commitment must exact-decode");
    assert_eq!(
        commitment.try_cev0_bytes().expect("bounded commitment"),
        commitment_raw
    );
    assert_eq!(
        commitment.id().as_bytes(),
        &hex_array(string(commitment_vector, "digest_hex"))
    );
    assert_eq!(
        commitment.fields().snapshot_cutoff_height.get(),
        number(fixture, "snapshot_cutoff_height")
    );
    assert_eq!(
        commitment.fields().activation_height.get(),
        number(fixture, "activation_height")
    );
    let protocol_v1_vector = object(
        object(&root, "valid_commitment_variants"),
        "protocol_version_1_inert_commitment",
    );
    let protocol_v1_raw = raw(protocol_v1_vector);
    let protocol_v1_commitment = decode_next_epoch_commitment_v0_exact(&protocol_v1_raw)
        .expect("an inert commitment preserves an arbitrary protocol-version u32");
    assert_eq!(
        protocol_v1_commitment.fields().new_protocol_version.get(),
        u32::try_from(number(protocol_v1_vector, "expected_new_protocol_version",))
            .expect("committed protocol version fits u32")
    );
    assert_eq!(
        protocol_v1_commitment
            .try_cev0_bytes()
            .expect("bounded protocol-v1 commitment"),
        protocol_v1_raw
    );
    assert_eq!(
        protocol_v1_commitment.id().as_bytes(),
        &hex_array(string(protocol_v1_vector, "digest_hex"))
    );
    assert_eq!(protocol_v1_vector["transition_authorization"], false);

    let parent_qc_vector = object(valid, "parent_qc");
    let parent_qc_raw = raw(parent_qc_vector);
    let parent_qc = decode_ordinary_qc_v0_exact(&parent_qc_raw, &old_set)
        .expect("the checkpoint parent QC must exact-decode");
    assert_eq!(
        parent_qc.try_cev0_bytes().expect("bounded parent QC"),
        parent_qc_raw
    );
    assert_eq!(
        parent_qc.id().as_bytes(),
        &hex_array(string(parent_qc_vector, "digest_hex"))
    );

    let proof_vector = object(valid, "checkpoint_finality_proof");
    let proof_raw = raw(proof_vector);
    let authenticated_parent_timestamp_ms =
        number(fixture, "authenticated_checkpoint_parent_timestamp_ms");
    let proof = decode_checkpoint_finality_proof_v0_exact(
        &proof_raw,
        &old_set,
        &parameters,
        &commitment,
        authenticated_parent_timestamp_ms,
    )
    .expect("the exact checkpoint/two-seal proof must decode as an inert semantic value");
    assert_eq!(
        proof.try_cev0_bytes().expect("bounded finality proof"),
        proof_raw
    );
    assert_eq!(
        proof.id().as_bytes(),
        &hex_array(string(proof_vector, "digest_hex"))
    );
    assert_eq!(
        proof.finalized_block().certifying_qc().id().as_bytes(),
        &hex_array(string(fixture, "checkpoint_certifying_qc_digest_hex"))
    );

    let certified = [
        (proof.finalized_block(), "checkpoint_certified_header"),
        (proof.child(), "seal_1_certified_header"),
        (proof.grandchild(), "seal_2_certified_header"),
    ];
    for (value, id) in certified {
        assert_eq!(
            value.try_cev0_bytes().expect("bounded certified header"),
            raw(object(valid, id)),
            "{id} must round-trip from the raw proof without JSON reconstruction"
        );
        assert!(value.timeout_certificate().is_none());
        assert!(value.epoch_anchor_authorization().is_none());
    }

    let checkpoint_raw = raw(object(valid, "checkpoint_certified_header"));
    let standalone_checkpoint = decode_ordinary_certified_header_v0_exact(
        &checkpoint_raw,
        &old_set,
        &parameters,
        authenticated_parent_timestamp_ms,
    )
    .expect("the standalone checkpoint certified header must exact-decode");
    let seal_1_raw = raw(object(valid, "seal_1_certified_header"));
    let standalone_seal_1 = decode_ordinary_certified_header_v0_exact(
        &seal_1_raw,
        &old_set,
        &parameters,
        standalone_checkpoint.header().timestamp_ms(),
    )
    .expect("the standalone seal-1 certified header must exact-decode");
    let seal_2_raw = raw(object(valid, "seal_2_certified_header"));
    let standalone_seal_2 = decode_ordinary_certified_header_v0_exact(
        &seal_2_raw,
        &old_set,
        &parameters,
        standalone_seal_1.header().timestamp_ms(),
    )
    .expect("the standalone seal-2 certified header must exact-decode");
    assert_eq!(&standalone_checkpoint, proof.finalized_block());
    assert_eq!(&standalone_seal_1, proof.child());
    assert_eq!(&standalone_seal_2, proof.grandchild());
    assert_eq!(
        proof
            .finalized_block()
            .justify_qc()
            .as_ordinary()
            .expect("B2-E admits only an ordinary parent QC"),
        &parent_qc
    );

    let checkpoint = proof.finalized_block().header();
    let seal_1 = proof.child().header();
    let seal_2 = proof.grandchild().header();
    assert_eq!(checkpoint.block_kind(), BlockKind::EpochCheckpoint);
    assert_eq!(seal_1.block_kind(), BlockKind::EpochSeal1);
    assert_eq!(seal_2.block_kind(), BlockKind::EpochSeal2);
    assert_eq!(
        checkpoint.height().get(),
        number(fixture, "checkpoint_height")
    );
    assert_eq!(seal_1.height().get(), number(fixture, "seal_1_height"));
    assert_eq!(seal_2.height().get(), number(fixture, "seal_2_height"));
    assert_eq!(
        checkpoint.id().as_bytes(),
        &hex_array(string(fixture, "checkpoint_block_id_hex"))
    );
    assert_eq!(
        seal_1.id().as_bytes(),
        &hex_array(string(fixture, "seal_1_block_id_hex"))
    );
    assert_eq!(
        seal_2.id().as_bytes(),
        &hex_array(string(fixture, "seal_2_block_id_hex"))
    );
    assert_eq!(seal_1.state_root(), checkpoint.state_root());
    assert_eq!(seal_2.state_root(), checkpoint.state_root());
    let empty_roots = object(fixture, "frozen_empty_roots");
    for seal in [seal_1, seal_2] {
        assert_eq!(
            seal.payload_root().as_bytes(),
            &hex_array(string(empty_roots, "payload_root_hex"))
        );
        assert_eq!(
            seal.receipts_root().as_bytes(),
            &hex_array(string(empty_roots, "receipts_root_hex"))
        );
        assert_eq!(
            seal.evidence_root().as_bytes(),
            &hex_array(string(empty_roots, "evidence_root_hex"))
        );
    }
    for header in [checkpoint, seal_1, seal_2] {
        assert_eq!(header.next_epoch_commitment_hash(), Some(commitment.id()));
    }

    let verifier = StrictEd25519Verifier;
    let unique_qcs = [
        &parent_qc,
        proof.finalized_block().certifying_qc(),
        proof.child().certifying_qc(),
        proof.grandchild().certifying_qc(),
    ];
    let ed25519 = object(&root, "real_ed25519_checks");
    assert_eq!(unique_qcs.len(), number_usize(ed25519, "qc_objects"));
    for qc in unique_qcs {
        assert_eq!(qc.votes().len(), number_usize(ed25519, "signatures_per_qc"));
        qc.verify(&old_set, &verifier)
            .expect("every unique QC in the committed corpus must strictly verify");
    }

    let certified = [proof.finalized_block(), proof.child(), proof.grandchild()];
    assert_eq!(
        certified.len(),
        number_usize(ed25519, "proposer_signatures")
    );
    for value in certified {
        let proposer = old_set
            .validator(value.header().proposer_id())
            .expect("scheduled proposer belongs to the old set");
        assert!(verifier.verify(
            proposer,
            &value.proposal_signing_root(),
            value.proposer_signature(),
        ));
    }

    let counting_verifier = CountingStrictVerifier::default();
    let counted_token = proof
        .verify_checkpoint_two_seal_kernel(
            &old_set,
            &parameters,
            &commitment,
            authenticated_parent_timestamp_ms,
            &counting_verifier,
        )
        .expect("all 21 end-to-end signature checks must pass through strict Ed25519");
    assert_eq!(
        counting_verifier.calls(),
        number_usize(ed25519, "total_signature_verifications")
    );
    let token = proof
        .verify_checkpoint_two_seal_kernel(
            &old_set,
            &parameters,
            &commitment,
            authenticated_parent_timestamp_ms,
            &verifier,
        )
        .expect("production strict Ed25519 must produce the inert two-seal kernel token");
    assert_eq!(token, counted_token);
    assert!(
        verify_finalized_cutoff_header_v0(
            &proof,
            &old_set,
            &parameters,
            authenticated_parent_timestamp_ms,
            &verifier,
        )
        .is_err(),
        "a finalized checkpoint cannot be substituted for the earlier snapshot cutoff"
    );
    assert_eq!(token.proof_id(), proof.id());
    assert_eq!(token.old_epoch(), old_set.epoch());
    assert_eq!(token.checkpoint_height(), checkpoint.height());
    assert_eq!(token.checkpoint_block_id(), checkpoint.id());
    assert_eq!(token.checkpoint_state_root(), checkpoint.state_root());
    assert_eq!(token.seal_1_block_id(), seal_1.id());
    assert_eq!(token.terminal_old_height(), seal_2.height());
    assert_eq!(token.terminal_old_block_id(), seal_2.id());
    assert_eq!(
        token.terminal_old_qc_digest().as_bytes(),
        &hex_array(string(fixture, "terminal_qc_digest_hex"))
    );
    assert_eq!(token.next_epoch_commitment_digest(), commitment.id());
    assert_eq!(token.new_epoch().get(), number(fixture, "old_epoch") + 1);
    assert_eq!(
        token.activation_height().get(),
        number(fixture, "activation_height")
    );
}

#[test]
fn raw_checkpoint_and_seal_exact_decoders_reject_every_prefix_and_trailing_byte() {
    let root: Value = serde_json::from_str(VECTOR).expect("valid checkpoint/two-seal vector JSON");
    let valid = object(&root, "valid_objects");
    let fixture = object(&root, "fixture");
    let parameters =
        decode_consensus_parameters_v0_exact(&raw(object(valid, "consensus_parameters")))
            .expect("valid parameter preimage");
    let old_set = decode_validator_set_v0_exact(&raw(object(valid, "old_validator_set")))
        .expect("valid old set");
    let commitment =
        decode_next_epoch_commitment_v0_exact(&raw(object(valid, "next_epoch_commitment")))
            .expect("valid commitment");
    let parent_timestamp = number(fixture, "authenticated_checkpoint_parent_timestamp_ms");

    let checkpoint_raw = raw(object(valid, "checkpoint_certified_header"));
    let checkpoint = decode_ordinary_certified_header_v0_exact(
        &checkpoint_raw,
        &old_set,
        &parameters,
        parent_timestamp,
    )
    .expect("valid checkpoint certified header");
    let seal_1_raw = raw(object(valid, "seal_1_certified_header"));
    let seal_1 = decode_ordinary_certified_header_v0_exact(
        &seal_1_raw,
        &old_set,
        &parameters,
        checkpoint.header().timestamp_ms(),
    )
    .expect("valid seal-1 certified header");
    let seal_2_raw = raw(object(valid, "seal_2_certified_header"));
    let proof_raw = raw(object(valid, "checkpoint_finality_proof"));

    let header_cases = [
        (
            "checkpoint_certified_header",
            checkpoint_raw.as_slice(),
            parent_timestamp,
        ),
        (
            "seal_1_certified_header",
            seal_1_raw.as_slice(),
            checkpoint.header().timestamp_ms(),
        ),
        (
            "seal_2_certified_header",
            seal_2_raw.as_slice(),
            seal_1.header().timestamp_ms(),
        ),
    ];
    let mut prefix_count = 0usize;
    for (id, bytes, authenticated_parent_timestamp_ms) in header_cases {
        for length in 0..bytes.len() {
            let error = decode_ordinary_certified_header_v0_exact(
                &bytes[..length],
                &old_set,
                &parameters,
                authenticated_parent_timestamp_ms,
            )
            .unwrap_err();
            assert_eq!(
                error.code(),
                DecodeErrorCode::UnexpectedEof,
                "{id} prefix {length}"
            );
            prefix_count += 1;
        }
        let mut trailing = bytes.to_vec();
        trailing.push(0xa5);
        let error = decode_ordinary_certified_header_v0_exact(
            &trailing,
            &old_set,
            &parameters,
            authenticated_parent_timestamp_ms,
        )
        .unwrap_err();
        assert_eq!(
            error.code(),
            DecodeErrorCode::TrailingBytes,
            "{id} trailing"
        );
    }

    for length in 0..proof_raw.len() {
        let error = decode_checkpoint_finality_proof_v0_exact(
            &proof_raw[..length],
            &old_set,
            &parameters,
            &commitment,
            parent_timestamp,
        )
        .unwrap_err();
        assert_eq!(
            error.code(),
            DecodeErrorCode::UnexpectedEof,
            "checkpoint_finality_proof prefix {length}"
        );
        prefix_count += 1;
    }
    let mut trailing = proof_raw.clone();
    trailing.push(0xa5);
    let error = decode_checkpoint_finality_proof_v0_exact(
        &trailing,
        &old_set,
        &parameters,
        &commitment,
        parent_timestamp,
    )
    .unwrap_err();
    assert_eq!(error.code(), DecodeErrorCode::TrailingBytes);

    let campaigns = object(&root, "parser_campaigns");
    let prefix_campaign = object(campaigns, "all_noncomplete_prefixes");
    let expected_scoped_prefixes = array(prefix_campaign, "objects")
        .iter()
        .filter(|item| {
            matches!(
                string(item, "id"),
                "checkpoint_certified_header"
                    | "seal_1_certified_header"
                    | "seal_2_certified_header"
                    | "checkpoint_finality_proof"
            )
        })
        .map(|item| number_usize(item, "cev0_length"))
        .sum::<usize>();
    assert_eq!(prefix_count, expected_scoped_prefixes);
    assert_eq!(string(prefix_campaign, "expected_code"), "unexpected_eof");
    assert_eq!(
        string(object(campaigns, "trailing_byte"), "expected_code"),
        "trailing_bytes"
    );
}

#[test]
fn raw_bad_signatures_decode_inertly_but_strict_verification_fails_closed() {
    let root: Value = serde_json::from_str(VECTOR).expect("valid checkpoint/two-seal vector JSON");
    let valid = object(&root, "valid_objects");
    let fixture = object(&root, "fixture");
    let parameters =
        decode_consensus_parameters_v0_exact(&raw(object(valid, "consensus_parameters")))
            .expect("valid parameter preimage");
    let old_set = decode_validator_set_v0_exact(&raw(object(valid, "old_validator_set")))
        .expect("valid old set");
    let commitment =
        decode_next_epoch_commitment_v0_exact(&raw(object(valid, "next_epoch_commitment")))
            .expect("valid commitment");
    let proof_raw = raw(object(valid, "checkpoint_finality_proof"));
    let parent_timestamp = number(fixture, "authenticated_checkpoint_parent_timestamp_ms");
    let strict = StrictEd25519Verifier;

    let cases = [
        ("invalid_proposer_signature", 0x42),
        ("invalid_qc_signature", 0x24),
    ];
    assert_eq!(
        cases.len(),
        number_usize(
            object(&root, "real_ed25519_checks"),
            "invalid_signature_cases"
        )
    );
    for (id, replacement) in cases {
        let case = semantic_case(&root, id);
        assert_eq!(string(case, "expected_code"), "invalid_signature");
        let signature_offset = number_usize(case, "raw_mutation_offset");
        let end = signature_offset
            .checked_add(64)
            .expect("bounded test signature offset");
        assert!(
            end <= proof_raw.len(),
            "{id} signature span is in the raw proof"
        );
        let mut mutated = proof_raw.clone();
        mutated[signature_offset..end].fill(replacement);

        let proof = decode_checkpoint_finality_proof_v0_exact(
            &mutated,
            &old_set,
            &parameters,
            &commitment,
            parent_timestamp,
        )
        .unwrap_or_else(|error| {
            panic!(
                "{id}: signature bytes must remain inert during exact semantic decode: {error:?}"
            )
        });
        let error = proof
            .verify_checkpoint_two_seal_kernel(
                &old_set,
                &parameters,
                &commitment,
                parent_timestamp,
                &strict,
            )
            .expect_err("strict Ed25519 must reject the corrupted raw signature");
        assert!(
            matches!(error, ValidationError::InvalidSignature(_)),
            "{id}: unexpected strict verification error {error:?}"
        );
    }
}

#[derive(Default)]
struct CountingStrictVerifier {
    calls: Cell<usize>,
}

impl CountingStrictVerifier {
    fn calls(&self) -> usize {
        self.calls.get()
    }
}

impl SignatureVerifier for CountingStrictVerifier {
    fn verify(
        &self,
        validator: &Validator,
        signing_root: &SigningRoot,
        signature: &SignatureBytes,
    ) -> bool {
        self.calls.set(self.calls.get() + 1);
        StrictEd25519Verifier.verify(validator, signing_root, signature)
    }
}

fn semantic_case<'a>(root: &'a Value, id: &str) -> &'a Value {
    root["semantic_negatives"]
        .as_array()
        .expect("semantic_negatives must be an array")
        .iter()
        .find(|case| string(case, "id") == id)
        .unwrap_or_else(|| panic!("missing semantic negative {id}"))
}

fn raw(value: &Value) -> Vec<u8> {
    let bytes = hex_vec(string(value, "cev0_hex"));
    assert_eq!(bytes.len(), number_usize(value, "cev0_length"));
    bytes
}

fn object<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .get(key)
        .unwrap_or_else(|| panic!("missing object field {key}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    object(value, key)
        .as_array()
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    object(value, key)
        .as_str()
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn number(value: &Value, key: &str) -> u64 {
    string(value, key)
        .parse()
        .unwrap_or_else(|_| panic!("{key} must be a decimal u64"))
}

fn number_u128(value: &Value, key: &str) -> u128 {
    string(value, key)
        .parse()
        .unwrap_or_else(|_| panic!("{key} must be a decimal u128"))
}

fn number_usize(value: &Value, key: &str) -> usize {
    match object(value, key) {
        Value::Number(number) => number
            .as_u64()
            .and_then(|number| usize::try_from(number).ok())
            .unwrap_or_else(|| panic!("{key} must fit usize")),
        Value::String(number) => number
            .parse()
            .unwrap_or_else(|_| panic!("{key} must be a decimal usize")),
        _ => panic!("{key} must be an integer or decimal string"),
    }
}

fn hex_vec(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex has an even length");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = core::str::from_utf8(pair).expect("hex pair is UTF-8");
            u8::from_str_radix(text, 16).expect("lowercase hexadecimal byte")
        })
        .collect()
}

fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    hex_vec(value)
        .try_into()
        .unwrap_or_else(|_| panic!("expected exactly {N} bytes"))
}
