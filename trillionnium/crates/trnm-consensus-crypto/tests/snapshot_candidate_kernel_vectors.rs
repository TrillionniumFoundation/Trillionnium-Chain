use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_types::{
    compute_candidate_selection_kernel_v0, decode_validator_key_proof_of_possession_v0_exact,
    CandidateComputationV0, CandidateSelectionKernelV0, CertificateId, ChainId,
    ConsensusParametersV0, ConsensusParametersV0Fields, ConsensusPublicKey, Epoch,
    EpochFallbackReasonV0, GenesisHash, Height, ProtocolVersion, RolloutPhase,
    UnauthenticatedCandidateSelectionTranscriptV0, UnauthenticatedSnapshotCandidateV0,
    UnauthenticatedSnapshotContributionV0, Validator, ValidatorId,
    ValidatorKeyProofDecodeErrorCode, ValidatorKeyProofOfPossessionV0, ValidatorSet, VotingPower,
    MAX_SNAPSHOT_CANDIDATES, MAX_SNAPSHOT_CONTRIBUTIONS, MAX_SNAPSHOT_RELATION_ID_BYTES,
};

const VECTOR: &str =
    include_str!("../../../../docs/protocol/poco-bft-v0/vectors/snapshot-candidate-kernel-v0.json");

#[test]
fn raw_pop_objects_exact_decode_round_trip_and_strictly_verify() {
    let root = vector();
    assert_manifest(&root);
    let verifier = StrictEd25519Verifier;

    for fixture in array(&root, "pop_fixtures") {
        let id = string(fixture, "id");
        let raw = hex_vec(string(fixture, "cev0_hex"));
        let proof = decode_validator_key_proof_of_possession_v0_exact(&raw)
            .unwrap_or_else(|error| panic!("{id} exact PoP decode failed: {error:?}"));
        assert_eq!(
            proof.try_cev0_bytes().expect("bounded exact PoP"),
            raw,
            "{id} exact object round-trip"
        );
        assert_eq!(
            proof
                .try_signing_cev0_bytes()
                .expect("bounded PoP signing preimage"),
            hex_vec(string(fixture, "signing_preimage_cev0_hex")),
            "{id} seven-field signing preimage"
        );
        assert_eq!(
            proof.signing_root().as_bytes(),
            &hex_array::<32>(string(fixture, "signing_root_hex")),
            "{id} signing root"
        );

        let fields = proof.fields();
        assert_eq!(fields.schema_version, number_u16(fixture, "schema_version"));
        assert_eq!(
            fields.genesis_hash.as_bytes(),
            &hex_array::<32>(string(fixture, "genesis_hash_hex"))
        );
        assert_eq!(fields.chain_id.as_str(), string(fixture, "chain_id_ascii"));
        assert_eq!(
            fields.target_epoch.get(),
            decimal_u64(fixture, "target_epoch")
        );
        assert_eq!(
            fields.validator_id.as_bytes(),
            hex_vec(string(fixture, "validator_id_hex"))
        );
        assert_eq!(
            fields.public_key.as_bytes(),
            &hex_array::<32>(string(fixture, "public_key_hex"))
        );
        assert_eq!(
            fields.registration_nonce,
            decimal_u64(fixture, "registration_nonce")
        );
        assert_eq!(
            fields.signature.as_bytes(),
            &hex_array::<64>(string(fixture, "signature_hex"))
        );
        proof
            .verify_for_registration(
                fields.genesis_hash,
                fields.chain_id,
                fields.target_epoch,
                fields.validator_id,
                fields.public_key,
                &verifier,
            )
            .unwrap_or_else(|error| panic!("{id} strict Ed25519 verification failed: {error}"));

        for prefix_len in 0..raw.len() {
            let error = decode_validator_key_proof_of_possession_v0_exact(&raw[..prefix_len])
                .expect_err("every non-complete PoP prefix must fail");
            assert_eq!(
                error.code(),
                ValidatorKeyProofDecodeErrorCode::UnexpectedEnd,
                "{id} prefix error at {prefix_len}"
            );
        }
        let mut trailing = raw.clone();
        trailing.push(0);
        let error = decode_validator_key_proof_of_possession_v0_exact(&trailing)
            .expect_err("trailing PoP byte must fail exact decode");
        assert_eq!(
            error.code(),
            ValidatorKeyProofDecodeErrorCode::TrailingBytes,
            "{id} trailing-byte code"
        );
        assert_eq!(error.byte_offset(), raw.len(), "{id} trailing offset");
    }
}

#[test]
fn positive_rollout_profiles_match_every_committed_diagnostic_and_set() {
    let root = vector();
    assert_manifest(&root);
    let fixtures = decoded_pop_fixtures(&root);
    let old_parameters = parameters_from(object(&root, "old_parameters"));
    let old_set = old_validator_set(&root, &old_parameters);
    let verifier = StrictEd25519Verifier;

    let positives = array(&root, "positive_cases");
    assert_eq!(positives.len(), 4, "all four rollout profiles are required");
    let mut ids = BTreeSet::new();
    for case in positives {
        ids.insert(string(case, "id"));
        let (kernel, candidate_parameters) =
            compute_case(case, &fixtures, &old_set, &old_parameters, &verifier);
        assert_kernel_matches(
            &root,
            case,
            &kernel,
            &candidate_parameters,
            &old_parameters,
            &old_set,
        );
        assert!(
            !kernel.fallback_used(),
            "{} must not fallback",
            string(case, "id")
        );
    }
    assert_eq!(
        ids,
        BTreeSet::from(["capped_weight", "eligibility_only", "full_weight", "shadow"])
    );
}

#[test]
fn input_permutations_are_outcome_identical_and_boundaries_are_exact() {
    let root = vector();
    assert_manifest(&root);
    let fixtures = decoded_pop_fixtures(&root);
    let old_parameters = parameters_from(object(&root, "old_parameters"));
    let old_set = old_validator_set(&root, &old_parameters);
    let verifier = StrictEd25519Verifier;

    let full = array(&root, "positive_cases")
        .iter()
        .find(|case| string(case, "id") == "full_weight")
        .expect("full-weight positive case");
    let (baseline, _) = compute_case(full, &fixtures, &old_set, &old_parameters, &verifier);
    let permutations = array(&root, "permutation_cases");
    assert_eq!(permutations.len(), 1, "one retained full-input permutation");
    for case in permutations {
        let (permuted, candidate_parameters) =
            compute_case(case, &fixtures, &old_set, &old_parameters, &verifier);
        assert_kernel_matches(
            &root,
            case,
            &permuted,
            &candidate_parameters,
            &old_parameters,
            &old_set,
        );
        assert_eq!(baseline, permuted, "{} outcome drift", string(case, "id"));
    }

    let boundaries = array(&root, "calculation_boundary_cases");
    assert!(
        boundaries.len() >= 9,
        "calculation boundary coverage regressed"
    );
    for case in boundaries {
        assert_calculation_boundary(&root, case);
    }
}

#[test]
fn every_fallback_reason_is_atomic_and_numeric_minimum_is_stable() {
    let root = vector();
    assert_manifest(&root);
    let fixtures = decoded_pop_fixtures(&root);
    let old_parameters = parameters_from(object(&root, "old_parameters"));
    let old_set = old_validator_set(&root, &old_parameters);
    let verifier = StrictEd25519Verifier;
    let mut reasons = BTreeSet::new();

    for case in array(&root, "fallback_cases") {
        let (kernel, candidate_parameters) =
            compute_case(case, &fixtures, &old_set, &old_parameters, &verifier);
        assert_kernel_matches(
            &root,
            case,
            &kernel,
            &candidate_parameters,
            &old_parameters,
            &old_set,
        );
        let expected = object(case, "expected");
        let code = number_u16(expected, "fallback_reason_code");
        reasons.insert(code);
        assert!(
            kernel.fallback_used(),
            "{} must fallback",
            string(case, "id")
        );
        assert!(
            kernel.computed_candidates().is_empty(),
            "fallback diagnostics leak"
        );
        assert!(
            kernel.computed_candidate_validator_set().is_none(),
            "fallback computed-set leak"
        );
        assert_eq!(kernel.effective_parameters(), &old_parameters);
        assert_eq!(
            kernel.effective_validator_set().validators(),
            old_set.validators(),
            "fallback must atomically carry old membership/keys/weights"
        );
    }
    assert_eq!(reasons, (1u16..=9).collect(), "reason 1..9 coverage drift");
}

#[test]
fn hard_cardinality_bounds_fail_before_clone_without_diagnostics() {
    let root = vector();
    assert_manifest(&root);
    let fixtures = decoded_pop_fixtures(&root);
    let old_parameters = parameters_from(object(&root, "old_parameters"));
    let old_set = old_validator_set(&root, &old_parameters);
    let verifier = StrictEd25519Verifier;
    let base = array(&root, "positive_cases")
        .iter()
        .find(|case| string(case, "id") == "full_weight")
        .expect("full-weight positive case");
    let candidate_parameters = parameters_from(object(base, "candidate_parameters"));
    let mut transcript = transcript_from(object(base, "transcript"), &fixtures);

    let repeated_candidate = transcript.candidates[0].clone();
    transcript
        .candidates
        .resize(MAX_SNAPSHOT_CANDIDATES + 1, repeated_candidate);
    let kernel = compute_candidate_selection_kernel_v0(
        &transcript,
        &old_set,
        &old_parameters,
        &candidate_parameters,
        &verifier,
    )
    .expect("bounded old configuration");
    assert_bound_fallback(&kernel, &old_set, &old_parameters);

    transcript = transcript_from(object(base, "transcript"), &fixtures);
    let repeated_contribution = transcript.contributions[0].clone();
    transcript
        .contributions
        .resize(MAX_SNAPSHOT_CONTRIBUTIONS + 1, repeated_contribution);
    let kernel = compute_candidate_selection_kernel_v0(
        &transcript,
        &old_set,
        &old_parameters,
        &candidate_parameters,
        &verifier,
    )
    .expect("bounded old configuration");
    assert_bound_fallback(&kernel, &old_set, &old_parameters);
}

#[test]
fn retained_pop_negatives_fail_closed_under_the_strict_verifier() {
    let root = vector();
    assert_manifest(&root);
    let fixtures = decoded_pop_fixtures(&root);
    let old_parameters = parameters_from(object(&root, "old_parameters"));
    let old_set = old_validator_set(&root, &old_parameters);
    let verifier = StrictEd25519Verifier;
    let base_case = array(&root, "positive_cases")
        .iter()
        .find(|case| string(case, "id") == "full_weight")
        .expect("full-weight positive case");
    let candidate_parameters = parameters_from(object(base_case, "candidate_parameters"));
    let base_fixture = &array(&root, "pop_fixtures")[0];
    let base_id = validator_id_hex(string(base_fixture, "validator_id_hex"));
    let base_key = ConsensusPublicKey::new(hex_array(string(base_fixture, "public_key_hex")));
    let context = object(&root, "context");
    let expected_genesis = GenesisHash::new(hex_array(string(context, "genesis_hash_hex")));
    let expected_chain =
        ChainId::new(string(context, "chain_id_ascii")).expect("bounded vector chain ID");
    let expected_epoch = Epoch::new(decimal_u64(context, "target_epoch"));

    for case in array(&root, "pop_negative_cases") {
        let id = string(case, "id");
        let expected_decode = string(case, "expected_decode");
        let decoded = case["cev0_hex"]
            .as_str()
            .map(|raw| decode_validator_key_proof_of_possession_v0_exact(&hex_vec(raw)));
        let proof = match (expected_decode, decoded) {
            ("not_present", None) => None,
            ("valid", Some(Ok(proof))) => {
                let verification = proof.verify_for_registration(
                    expected_genesis,
                    expected_chain,
                    expected_epoch,
                    base_id,
                    base_key,
                    &verifier,
                );
                match string(case, "expected_verification") {
                    "valid_signature_but_stale_nonce" => assert!(verification.is_ok(), "{id}"),
                    "invalid_scope" | "invalid_signature" => {
                        assert!(verification.is_err(), "{id} unexpectedly verified")
                    }
                    other => panic!("{id} unknown verification result {other}"),
                }
                Some(proof)
            }
            (code, Some(Err(error))) => {
                assert_eq!(
                    error.code(),
                    pop_decode_code(code),
                    "{id} exact decode code drift"
                );
                if let Some(offset) = case
                    .get("expected_error_byte_offset")
                    .and_then(Value::as_u64)
                {
                    assert_eq!(
                        error.byte_offset(),
                        usize::try_from(offset).expect("decoder offset fits usize"),
                        "{id} exact decode offset drift"
                    );
                }
                None
            }
            (expected, actual) => panic!("{id} decode drift: expected {expected}, got {actual:?}"),
        };

        let mut transcript = transcript_from(object(base_case, "transcript"), &fixtures);
        let candidate = transcript
            .candidates
            .iter_mut()
            .find(|candidate| candidate.validator_id == base_id)
            .expect("negative fixture candidate");
        candidate.proof_of_possession = proof;
        candidate.previous_registration_nonce = case
            .get("previous_registration_nonce")
            .and_then(Value::as_str)
            .map(|value| parse_u64(value, "previous_registration_nonce"));
        let kernel = compute_candidate_selection_kernel_v0(
            &transcript,
            &old_set,
            &old_parameters,
            &candidate_parameters,
            &verifier,
        )
        .unwrap_or_else(|error| panic!("{id} kernel hard error: {error}"));
        assert!(kernel.fallback_used(), "{id} must fail closed");
        assert_eq!(
            u16::from(kernel.fallback_reason()),
            number_u16(case, "expected_kernel_reason"),
            "{id} fallback reason"
        );
        assert!(
            kernel.computed_candidates().is_empty(),
            "{id} diagnostics leak"
        );
        assert!(kernel.computed_candidate_validator_set().is_none());
        assert_eq!(kernel.effective_parameters(), &old_parameters);
    }
}

#[test]
fn strict_pop_verification_rejects_noncanonical_signature_encodings_and_small_order_key() {
    let root = vector();
    let fixture = &array(&root, "pop_fixtures")[0];
    let valid_raw = hex_vec(string(fixture, "cev0_hex"));
    let signature_offset = valid_raw
        .len()
        .checked_sub(64)
        .expect("exact PoP contains a fixed-width signature");

    // The Ed25519 subgroup order L encoded little-endian. S == L is not a
    // canonical scalar even though the fixed-width PoP decoder remains inert.
    let noncanonical_s =
        hex_array::<32>("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
    let mut raw = valid_raw.clone();
    raw[signature_offset + 32..].copy_from_slice(&noncanonical_s);
    assert_strict_pop_rejects(&raw, "noncanonical S");

    // y == 2^255 - 19 is outside the canonical field-element encoding for R.
    let noncanonical_r =
        hex_array::<32>("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    let mut raw = valid_raw.clone();
    raw[signature_offset..signature_offset + 32].copy_from_slice(&noncanonical_r);
    assert_strict_pop_rejects(&raw, "noncanonical R");

    // The identity point has a valid compressed-point encoding, but is small
    // order and must be rejected by verify_strict. The exact PoP decoder only
    // rejects the all-zero key and therefore intentionally remains inert here.
    let public_key = hex_array::<32>(string(fixture, "public_key_hex"));
    let public_key_offset = valid_raw
        .windows(public_key.len())
        .position(|window| window == public_key)
        .expect("fixture public key occurs in its exact PoP object");
    let mut raw = valid_raw;
    raw[public_key_offset..public_key_offset + 32].fill(0);
    raw[public_key_offset] = 1;
    assert_strict_pop_rejects(&raw, "small-order public key");
}

fn assert_strict_pop_rejects(raw: &[u8], label: &str) {
    let proof = decode_validator_key_proof_of_possession_v0_exact(raw)
        .unwrap_or_else(|error| panic!("{label} must remain inert at exact decode: {error:?}"));
    let fields = proof.fields();
    let error = proof
        .verify_for_registration(
            fields.genesis_hash,
            fields.chain_id,
            fields.target_epoch,
            fields.validator_id,
            fields.public_key,
            &StrictEd25519Verifier,
        )
        .expect_err("strict Ed25519 verification must fail closed");
    assert!(
        matches!(
            error,
            trnm_consensus_types::ValidationError::InvalidSignature(_)
        ),
        "{label}: unexpected verification error {error:?}"
    );
}

fn assert_manifest(root: &Value) {
    assert_eq!(
        string(root, "schema"),
        "trnm_poco_bft_snapshot_candidate_kernel_vectors_v0"
    );
    assert_eq!(number_u16(root, "schema_version"), 0);
    assert_eq!(number_usize(root, "authorization_outputs"), 0);
    assert_eq!(
        string(object(root, "pop_contract"), "domain"),
        "trnm.poco-bft.validator-key-pop.v0"
    );
    assert_eq!(
        string(object(root, "pop_contract"), "hash_prefix_ascii"),
        "trnm.cev0.hash.v0"
    );
    assert_eq!(
        object(root, "pop_contract")["signature_in_signing_preimage"],
        false
    );
    let bounds = object(root, "hard_bounds");
    assert_eq!(
        number_usize(bounds, "max_snapshot_candidates"),
        MAX_SNAPSHOT_CANDIDATES
    );
    assert_eq!(
        number_usize(bounds, "max_snapshot_contributions"),
        MAX_SNAPSHOT_CONTRIBUTIONS
    );
    assert_eq!(number_usize(bounds, "id_bytes_min"), 1);
    assert_eq!(
        number_usize(bounds, "id_bytes_max"),
        MAX_SNAPSHOT_RELATION_ID_BYTES
    );
    assert!(
        string(root, "fixture_secret_policy").contains("no private seed or private key"),
        "committed vector must not contain fixture secrets"
    );
}

fn vector() -> Value {
    serde_json::from_str(VECTOR).expect("valid B2-G snapshot-candidate vector JSON")
}

fn decoded_pop_fixtures(root: &Value) -> BTreeMap<String, ValidatorKeyProofOfPossessionV0> {
    array(root, "pop_fixtures")
        .iter()
        .map(|fixture| {
            let id = string(fixture, "id").to_owned();
            let proof = decode_validator_key_proof_of_possession_v0_exact(&hex_vec(string(
                fixture, "cev0_hex",
            )))
            .unwrap_or_else(|error| panic!("{id} exact decode failed: {error:?}"));
            (id, proof)
        })
        .collect()
}

fn parameters_from(value: &Value) -> ConsensusParametersV0 {
    let mut fields: ConsensusParametersV0Fields =
        ConsensusParametersV0::reference_shadow_v0().fields();
    fields.schema_version = number_u16(value, "schema_version");
    fields.protocol_version = number_u32(value, "protocol_version");
    fields.production_activation = boolean(value, "production_activation");
    fields.epoch_length_blocks = decimal_u64(value, "epoch_length_blocks");
    fields.rollout_phase =
        RolloutPhase::try_from(number_u8(value, "rollout_phase")).expect("known rollout phase");
    fields.max_chain_id_bytes = number_u16(value, "max_chain_id_bytes");
    fields.max_validator_id_bytes = number_u16(value, "max_validator_id_bytes");
    fields.scale_ppm = decimal_u64(value, "scale_ppm");
    fields.maturity_epochs = decimal_u64(value, "maturity_epochs");
    fields.max_certificate_age_epochs = decimal_u64(value, "max_certificate_age_epochs");
    fields.decay_step_ppm_per_epoch = decimal_u64(value, "decay_step_ppm_per_epoch");
    fields.per_certificate_unit_cap = decimal_u128(value, "per_certificate_unit_cap");
    fields.per_consumer_provider_epoch_unit_cap =
        decimal_u128(value, "per_consumer_provider_epoch_unit_cap");
    fields.per_task_provider_epoch_unit_cap =
        decimal_u128(value, "per_task_provider_epoch_unit_cap");
    fields.per_provider_epoch_unit_cap = decimal_u128(value, "per_provider_epoch_unit_cap");
    fields.units_per_power = decimal_u128(value, "units_per_power");
    fields.bond_atomic_units_per_power = decimal_u128(value, "bond_atomic_units_per_power");
    fields.min_validator_power = decimal_u64(value, "min_validator_power");
    fields.max_validator_power = decimal_u64(value, "max_validator_power");
    fields.min_validators = number_u32(value, "min_validators");
    fields.max_validators = number_u32(value, "max_validators");
    fields.max_total_voting_power = decimal_u64(value, "max_total_voting_power");
    fields.max_validator_share_ppm = decimal_u64(value, "max_validator_share_ppm");
    fields.capped_weight_alpha_ppm = decimal_u64(value, "capped_weight_alpha_ppm");
    fields.full_weight_alpha_ppm = decimal_u64(value, "full_weight_alpha_ppm");
    ConsensusParametersV0::new(fields).expect("valid complete B2-G parameter preimage")
}

fn old_validator_set(root: &Value, parameters: &ConsensusParametersV0) -> ValidatorSet {
    let context = object(root, "context");
    let vector = object(root, "old_active_validator_set");
    let mut validators: Vec<_> = array(vector, "validators")
        .iter()
        .map(validator_from)
        .collect();
    validators.sort_by_key(Validator::id);
    ValidatorSet::new(
        GenesisHash::new(hex_array(string(context, "genesis_hash_hex"))),
        ChainId::new(string(context, "chain_id_ascii")).expect("bounded vector chain ID"),
        ProtocolVersion::V0,
        Epoch::new(decimal_u64(vector, "epoch")),
        parameters.hash(),
        validators,
    )
    .expect("valid caller-supplied old validator set")
}

fn validator_from(value: &Value) -> Validator {
    Validator::new(
        validator_id_hex(string(value, "validator_id_hex")),
        ConsensusPublicKey::new(hex_array(string(value, "consensus_key_hex"))),
        VotingPower::new(decimal_u64(value, "effective_weight")).expect("positive vector weight"),
    )
    .expect("shape-valid vector validator")
}

fn transcript_from(
    value: &Value,
    fixtures: &BTreeMap<String, ValidatorKeyProofOfPossessionV0>,
) -> UnauthenticatedCandidateSelectionTranscriptV0 {
    UnauthenticatedCandidateSelectionTranscriptV0 {
        snapshot_epoch: Epoch::new(decimal_u64(value, "snapshot_epoch")),
        snapshot_height: Height::new(decimal_u64(value, "snapshot_height")),
        committed_snapshot_cutoff: Height::new(decimal_u64(value, "committed_snapshot_cutoff")),
        candidates: array(value, "candidates")
            .iter()
            .map(|candidate| candidate_from(candidate, fixtures))
            .collect(),
        contributions: array(value, "contributions")
            .iter()
            .map(contribution_from)
            .collect(),
    }
}

fn candidate_from(
    value: &Value,
    fixtures: &BTreeMap<String, ValidatorKeyProofOfPossessionV0>,
) -> UnauthenticatedSnapshotCandidateV0 {
    let proof_of_possession = match value.get("proof_fixture_id") {
        Some(Value::String(id)) => Some(
            *fixtures
                .get(id)
                .unwrap_or_else(|| panic!("unknown PoP fixture {id}")),
        ),
        Some(Value::Null) | None => None,
        _ => panic!("proof_fixture_id must be a string or null"),
    };
    UnauthenticatedSnapshotCandidateV0 {
        validator_id: validator_id_hex(string(value, "validator_id_hex")),
        consensus_key: ConsensusPublicKey::new(hex_array(string(value, "consensus_key_hex"))),
        active_slashable_bond: decimal_u128(value, "active_slashable_bond"),
        jailed: boolean(value, "jailed"),
        registration_valid: boolean(value, "registration_valid"),
        previous_registration_nonce: optional_decimal_u64(value, "previous_registration_nonce"),
        proof_of_possession,
    }
}

fn contribution_from(value: &Value) -> UnauthenticatedSnapshotContributionV0 {
    UnauthenticatedSnapshotContributionV0 {
        certificate_id: CertificateId::new(hex_array(string(value, "certificate_id_hex"))),
        provider_validator_id: validator_id_hex(string(value, "provider_validator_id_hex")),
        task_id: hex_vec(string(value, "task_id_hex")),
        consumer_id: hex_vec(string(value, "consumer_id_hex")),
        finalized_epoch: Epoch::new(decimal_u64(value, "finalized_epoch")),
        consumed_units: decimal_u128(value, "consumed_units"),
        eligible: boolean(value, "eligible"),
    }
}

fn compute_case(
    case: &Value,
    fixtures: &BTreeMap<String, ValidatorKeyProofOfPossessionV0>,
    old_set: &ValidatorSet,
    old_parameters: &ConsensusParametersV0,
    verifier: &StrictEd25519Verifier,
) -> (CandidateSelectionKernelV0, ConsensusParametersV0) {
    let candidate_parameters = parameters_from(object(case, "candidate_parameters"));
    let transcript = transcript_from(object(case, "transcript"), fixtures);
    let kernel = compute_candidate_selection_kernel_v0(
        &transcript,
        old_set,
        old_parameters,
        &candidate_parameters,
        verifier,
    )
    .unwrap_or_else(|error| panic!("{} kernel hard error: {error}", string(case, "id")));
    (kernel, candidate_parameters)
}

fn assert_kernel_matches(
    root: &Value,
    case: &Value,
    kernel: &CandidateSelectionKernelV0,
    candidate_parameters: &ConsensusParametersV0,
    old_parameters: &ConsensusParametersV0,
    old_set: &ValidatorSet,
) {
    let id = string(case, "id");
    let expected = object(case, "expected");
    let transcript = object(case, "transcript");
    assert_eq!(
        kernel.snapshot_epoch().get(),
        decimal_u64(transcript, "snapshot_epoch"),
        "{id} snapshot epoch"
    );
    assert_eq!(
        kernel.target_epoch().get(),
        old_set.epoch().get().checked_add(1).expect("target epoch"),
        "{id} target epoch"
    );
    assert_eq!(
        kernel.fallback_used(),
        boolean(expected, "fallback_used"),
        "{id} fallback flag"
    );
    assert_eq!(
        u16::from(kernel.fallback_reason()),
        number_u16(expected, "fallback_reason_code"),
        "{id} fallback reason"
    );
    assert_diagnostics(
        kernel.computed_candidates(),
        array(expected, "computed_candidates"),
        id,
    );

    match &expected["computed_candidate_validator_set"] {
        Value::Null => assert!(
            kernel.computed_candidate_validator_set().is_none(),
            "{id} unexpected computed candidate set"
        ),
        Value::Array(validators) => assert_validator_set_entries(
            kernel
                .computed_candidate_validator_set()
                .unwrap_or_else(|| panic!("{id} missing computed candidate set")),
            validators,
            id,
        ),
        _ => panic!("{id} computed_candidate_validator_set shape"),
    }
    assert_validator_set_entries(
        kernel.effective_validator_set(),
        array(expected, "effective_validator_set"),
        id,
    );
    assert_eq!(
        kernel.effective_validator_set().epoch(),
        kernel.target_epoch()
    );

    let expected_profile = string(expected, "effective_parameters_profile");
    let expected_parameters = if expected_profile == "old" {
        *old_parameters
    } else {
        let profile = array(root, "parameter_profiles")
            .iter()
            .find(|profile| string(profile, "id") == expected_profile)
            .unwrap_or_else(|| {
                panic!("{id} unknown expected parameter profile {expected_profile}")
            });
        parameters_from(object(profile, "parameters"))
    };
    assert_eq!(
        kernel.effective_parameters(),
        &expected_parameters,
        "{id} effective parameter preimage"
    );
    if !kernel.fallback_used() {
        assert_eq!(
            kernel.effective_parameters(),
            candidate_parameters,
            "{id} candidate parameter application"
        );
    }
    assert_eq!(number_usize(expected, "authorization_outputs"), 0);
}

fn assert_diagnostics(actual: &[CandidateComputationV0], expected: &[Value], id: &str) {
    assert_eq!(actual.len(), expected.len(), "{id} diagnostic count");
    for (actual, expected) in actual.iter().zip(expected) {
        assert_eq!(
            actual.validator_id().as_bytes(),
            hex_vec(string(expected, "validator_id_hex")),
            "{id} diagnostic validator ID"
        );
        assert_eq!(
            actual.consensus_key().as_bytes(),
            &hex_array::<32>(string(expected, "consensus_key_hex")),
            "{id} diagnostic key"
        );
        assert_eq!(
            actual.decayed_units(),
            decimal_u128(expected, "decayed_units")
        );
        assert_eq!(
            actual.poco_capacity(),
            decimal_u128(expected, "poco_capacity")
        );
        assert_eq!(
            actual.bond_capacity(),
            decimal_u128(expected, "bond_capacity")
        );
        assert_eq!(actual.raw_power(), decimal_u64(expected, "raw_power"));
        assert_eq!(actual.selected(), boolean(expected, "selected"));
        assert_eq!(
            actual.rollout_weight(),
            optional_decimal_u64(expected, "rollout_weight")
        );
        assert_eq!(
            actual.consumer_cap_hits(),
            number_u32(expected, "consumer_cap_hits")
        );
        assert_eq!(
            actual.task_cap_hits(),
            number_u32(expected, "task_cap_hits")
        );
        assert_eq!(
            actual.provider_cap_hit(),
            boolean(expected, "provider_cap_hit")
        );
    }
}

fn assert_validator_set_entries(set: &ValidatorSet, expected: &[Value], id: &str) {
    assert_eq!(
        set.validators().len(),
        expected.len(),
        "{id} set cardinality"
    );
    for (actual, expected) in set.validators().iter().zip(expected) {
        assert_eq!(
            actual.id().as_bytes(),
            hex_vec(string(expected, "validator_id_hex")),
            "{id} set validator ID"
        );
        assert_eq!(
            actual.consensus_key().as_bytes(),
            &hex_array::<32>(string(expected, "consensus_key_hex")),
            "{id} set key"
        );
        assert_eq!(
            actual.voting_power().get(),
            decimal_u64(expected, "effective_weight"),
            "{id} set weight"
        );
    }
}

fn assert_bound_fallback(
    kernel: &CandidateSelectionKernelV0,
    old_set: &ValidatorSet,
    old_parameters: &ConsensusParametersV0,
) {
    assert!(kernel.fallback_used());
    assert_eq!(
        kernel.fallback_reason(),
        EpochFallbackReasonV0::MalformedSnapshotInput
    );
    assert!(kernel.computed_candidates().is_empty());
    assert!(kernel.computed_candidate_validator_set().is_none());
    assert_eq!(kernel.effective_parameters(), old_parameters);
    assert_eq!(
        kernel.effective_validator_set().validators(),
        old_set.validators()
    );
}

fn assert_calculation_boundary(root: &Value, case: &Value) {
    let id = string(case, "id");
    let candidate_parameters = parameters_from(object(case, "parameters"));
    let snapshot_epoch = decimal_u64(case, "snapshot_epoch");
    let mut target = candidate_from(object(case, "candidate"), &decoded_pop_fixtures(root));
    target.proof_of_possession = None;

    let fixture_values = array(root, "pop_fixtures");
    let support_values = &fixture_values[1..5];
    let mut candidates = Vec::with_capacity(5);
    candidates.push(target.clone());
    for fixture in support_values {
        candidates.push(UnauthenticatedSnapshotCandidateV0 {
            validator_id: validator_id_hex(string(fixture, "validator_id_hex")),
            consensus_key: ConsensusPublicKey::new(hex_array(string(fixture, "public_key_hex"))),
            active_slashable_bond: 2_000,
            jailed: false,
            registration_valid: true,
            previous_registration_nonce: None,
            proof_of_possession: None,
        });
    }
    candidates.sort_by_key(|candidate| candidate.validator_id);

    let mut old_fields = candidate_parameters.fields();
    old_fields.production_activation = false;
    old_fields.rollout_phase = RolloutPhase::Shadow;
    old_fields.max_validators = 5;
    old_fields.max_total_voting_power = old_fields.max_total_voting_power.max(500);
    let old_parameters = ConsensusParametersV0::new(old_fields).expect("valid boundary old params");
    let context = object(root, "context");
    let validators = candidates
        .iter()
        .map(|candidate| {
            Validator::new(
                candidate.validator_id,
                candidate.consensus_key,
                VotingPower::new(1).expect("positive support weight"),
            )
            .expect("shape-valid support validator")
        })
        .collect();
    let old_set = ValidatorSet::new(
        GenesisHash::new(hex_array(string(context, "genesis_hash_hex"))),
        ChainId::new(string(context, "chain_id_ascii")).expect("bounded vector chain"),
        ProtocolVersion::V0,
        Epoch::new(snapshot_epoch),
        old_parameters.hash(),
        validators,
    )
    .expect("valid boundary old set");

    let mut contributions: Vec<_> = array(case, "contributions")
        .iter()
        .map(contribution_from)
        .collect();
    let mature_epoch = snapshot_epoch
        .checked_sub(candidate_parameters.maturity_epochs())
        .expect("boundary snapshot is after maturity delay");
    for (index, candidate) in candidates.iter().skip(1).enumerate() {
        contributions.push(UnauthenticatedSnapshotContributionV0 {
            certificate_id: CertificateId::new(
                [0xe0 + u8::try_from(index).expect("small index"); 32],
            ),
            provider_validator_id: candidate.validator_id,
            task_id: vec![b's', b't', u8::try_from(index).expect("small index")],
            consumer_id: vec![b's', b'c', u8::try_from(index).expect("small index")],
            finalized_epoch: Epoch::new(mature_epoch),
            consumed_units: 2_000,
            eligible: true,
        });
    }
    let transcript = UnauthenticatedCandidateSelectionTranscriptV0 {
        snapshot_epoch: Epoch::new(snapshot_epoch),
        snapshot_height: Height::new(900),
        committed_snapshot_cutoff: Height::new(900),
        candidates,
        contributions,
    };
    let kernel = compute_candidate_selection_kernel_v0(
        &transcript,
        &old_set,
        &old_parameters,
        &candidate_parameters,
        &StrictEd25519Verifier,
    )
    .unwrap_or_else(|error| panic!("{id} boundary hard error: {error}"));
    assert!(
        !kernel.fallback_used(),
        "{id} support frame must stay valid"
    );
    let actual = kernel
        .computed_candidates()
        .iter()
        .find(|entry| entry.validator_id() == target.validator_id)
        .unwrap_or_else(|| panic!("{id} target diagnostic missing"));
    let expected = object(case, "expected");
    assert_eq!(number_u16(expected, "fallback_reason_code"), 0, "{id}");
    assert_eq!(
        actual.decayed_units(),
        decimal_u128(expected, "decayed_units"),
        "{id}"
    );
    assert_eq!(
        actual.poco_capacity(),
        decimal_u128(expected, "poco_capacity"),
        "{id}"
    );
    assert_eq!(
        actual.bond_capacity(),
        decimal_u128(expected, "bond_capacity"),
        "{id}"
    );
    assert_eq!(
        actual.raw_power(),
        decimal_u64(expected, "raw_power"),
        "{id}"
    );
    assert_eq!(
        actual.consumer_cap_hits(),
        number_u32(expected, "consumer_cap_hits"),
        "{id}"
    );
    assert_eq!(
        actual.task_cap_hits(),
        number_u32(expected, "task_cap_hits"),
        "{id}"
    );
    assert_eq!(
        actual.provider_cap_hit(),
        boolean(expected, "provider_cap_hit"),
        "{id}"
    );
}

fn pop_decode_code(value: &str) -> ValidatorKeyProofDecodeErrorCode {
    match value {
        "unexpected_end" => ValidatorKeyProofDecodeErrorCode::UnexpectedEnd,
        "trailing_bytes" => ValidatorKeyProofDecodeErrorCode::TrailingBytes,
        "invalid_schema_version" => ValidatorKeyProofDecodeErrorCode::InvalidSchemaVersion,
        "zero_genesis_hash" => ValidatorKeyProofDecodeErrorCode::ZeroGenesisHash,
        "invalid_chain_id" => ValidatorKeyProofDecodeErrorCode::InvalidChainId,
        "empty_validator_id" => ValidatorKeyProofDecodeErrorCode::EmptyValidatorId,
        "validator_id_too_long" => ValidatorKeyProofDecodeErrorCode::ValidatorIdTooLong,
        "zero_public_key" => ValidatorKeyProofDecodeErrorCode::ZeroPublicKey,
        other => panic!("unknown committed PoP decode code {other}"),
    }
}

fn validator_id_hex(value: &str) -> ValidatorId {
    ValidatorId::from_bytes(&hex_vec(value)).expect("bounded nonempty validator ID")
}

fn object<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .get(key)
        .and_then(Value::as_object)
        .map(|_| &value[key])
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn boolean(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
}

fn number_usize(value: &Value, key: &str) -> usize {
    usize::try_from(
        value
            .get(key)
            .and_then(Value::as_u64)
            .unwrap_or_else(|| panic!("{key} must be a u64")),
    )
    .unwrap_or_else(|_| panic!("{key} must fit usize"))
}

fn number_u8(value: &Value, key: &str) -> u8 {
    u8::try_from(number_usize(value, key)).unwrap_or_else(|_| panic!("{key} must fit u8"))
}

fn number_u16(value: &Value, key: &str) -> u16 {
    u16::try_from(number_usize(value, key)).unwrap_or_else(|_| panic!("{key} must fit u16"))
}

fn number_u32(value: &Value, key: &str) -> u32 {
    u32::try_from(number_usize(value, key)).unwrap_or_else(|_| panic!("{key} must fit u32"))
}

fn optional_decimal_u64(value: &Value, key: &str) -> Option<u64> {
    match value.get(key) {
        Some(Value::String(value)) => Some(parse_u64(value, key)),
        Some(Value::Null) | None => None,
        _ => panic!("{key} must be canonical decimal text or null"),
    }
}

fn decimal_u64(value: &Value, key: &str) -> u64 {
    parse_u64(string(value, key), key)
}

fn decimal_u128(value: &Value, key: &str) -> u128 {
    parse_u128(string(value, key), key)
}

fn parse_u64(value: &str, label: &str) -> u64 {
    assert_canonical_decimal(value, label);
    value
        .parse()
        .unwrap_or_else(|_| panic!("{label} must fit u64"))
}

fn parse_u128(value: &str, label: &str) -> u128 {
    assert_canonical_decimal(value, label);
    value
        .parse()
        .unwrap_or_else(|_| panic!("{label} must fit u128"))
}

fn assert_canonical_decimal(value: &str, label: &str) {
    assert!(!value.is_empty(), "{label} decimal text is empty");
    assert!(
        value.as_bytes().iter().all(u8::is_ascii_digit),
        "{label} is not unsigned decimal"
    );
    assert!(
        value == "0" || !value.starts_with('0'),
        "{label} has a noncanonical leading zero"
    );
}

fn hex_vec(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex must contain complete octets");
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
