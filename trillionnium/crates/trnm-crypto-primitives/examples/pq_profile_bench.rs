//! Actual CPQ1 candidate message, signing and authentication observations.
//!
//! `cargo run --release --locked -p trnm-crypto-primitives --example pq_profile_bench -- --samples 64`
//! uses the actual candidate protocol APIs, not a benchmark-specific wire parser.
//! CPQ1 is not activated PNQ/NPQ, CURRENT or FinalUse authority. Public fixed
//! fixtures, local wall times and sample quantiles do not qualify a network,
//! deployment, hardware target or production latency tail. A separate command
//! receipt must bind source, toolchain, binary, host and terminal exit status.

use serde_json::{json, Value};
use sha2::{Digest, Sha512};
use std::{env, error::Error, hint::black_box, io, io::Write, time::Instant};
use trnm_crypto_primitives::{
    pq_candidate::{CandidateAlgorithm, CandidateError, CandidateSigningKey},
    pq_profile_auth::{CandidateProfileVerifier, ProfileAuthenticationError},
};
use trnm_protocol::crypto_profile::{
    native_work_configuration_digest, BoundCryptoProfile, CandidateEnvelope,
    CandidateVerificationBudget, CryptoProfile, CryptoProfilePolicy, CryptoPurpose, ProfileBinding,
    ProfileError, ProfileScope, CANDIDATE_HEADER_BYTES, CANDIDATE_MAX_ATTEMPTS,
    CANDIDATE_MAX_CUMULATIVE_BYTES, CANDIDATE_MAX_SIGNERS, CANDIDATE_MAX_WIRE_BYTES,
    MAX_SIGNED_MESSAGE_BYTES,
};
use zeroize::Zeroizing;

type BenchResult<T> = Result<T, Box<dyn Error>>;
const SCHEMA: &str = "trnm.cpq1-parameter-observation.v1";
const MIN_SAMPLES: usize = 64;
const MAX_SAMPLES: usize = 4_096;
const SIGNER_COUNTS: [usize; 4] = [1, 2, 4, 8];
const PAYLOAD_LABELS: [&str; 4] = ["empty", "176", "4096", "maximum"];
const SHORT_WIRE: &[u8; 7] = b"CPQ1\0\0\0";
const TIMING_SCOPE: &str = "inclusive operation, outcome checks and owned temporary drops; fixture key generation and initial signatures outside samples; output IO outside samples";
const BUDGET_SCOPE: &str = "each independent timing sample and warmup creates a new budget; shared_budget_exhaustion never resets its one budget within a sample";
const HARDWARE_SCOPE: &str = "single process on caller-recorded host; wall time includes scheduling; CPU, RSS, WAL, WAN and business confirmation are not measured";

fn require(ok: bool, message: &'static str) -> BenchResult<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidData, message).into())
    }
}

fn emit(value: Value) -> BenchResult<()> {
    let stdout = io::stdout();
    let mut stream = stdout.lock();
    serde_json::to_writer(&mut stream, &value)?;
    writeln!(stream)?;
    // A killed process retains only completed rows, never an invented sentinel.
    stream.flush()?;
    Ok(())
}

fn samples_from_args() -> BenchResult<Option<usize>> {
    let mut args = env::args().skip(1);
    let samples = match args.next().as_deref() {
        None => MIN_SAMPLES,
        Some("--help" | "-h") => {
            println!("pq_profile_bench [--samples N], {MIN_SAMPLES} <= N <= {MAX_SAMPLES}");
            return Ok(None);
        }
        Some("--samples") => args
            .next()
            .ok_or("--samples requires a count")?
            .parse::<usize>()?,
        Some(_) => return Err("expected --samples N or --help".into()),
    };
    require(
        args.next().is_none() && (MIN_SAMPLES..=MAX_SAMPLES).contains(&samples),
        "sample count must be 64..=4096, with no extra arguments",
    )?;
    Ok(Some(samples))
}

fn profile(algorithm: CandidateAlgorithm, network_byte: u8) -> BenchResult<BoundCryptoProfile> {
    Ok(match algorithm {
        CandidateAlgorithm::MlDsa65 => CryptoProfile::CandidateMlDsa65V1,
        CandidateAlgorithm::MlDsa87 => CryptoProfile::CandidateMlDsa87V1,
    }
    .bind(ProfileBinding {
        network: [network_byte; 32],
        parameters: [2; 32],
        genesis: [3; 32],
        protocol_version: 1,
        scope: ProfileScope::WholeSystemCandidate,
        activation_height: 10,
        retirement_height: Some(100),
    })?)
}

fn seed(index: usize) -> Zeroizing<[u8; 32]> {
    let mut seed = Zeroizing::new([0x42; 32]);
    seed[24..].copy_from_slice(&(index as u64).to_be_bytes());
    seed
}

fn payload(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| (index as u8).wrapping_mul(29).wrapping_add(17))
        .collect()
}

fn envelope<'a>(ids: &'a [[u8; 64]], body: &'a [u8]) -> CandidateEnvelope<'a> {
    CandidateEnvelope {
        purpose: CryptoPurpose::FinalUse,
        owner_generation: 7,
        key_epoch: 3,
        sequence: 11,
        valid_from_height: 10,
        valid_until_height: 99,
        signer_ids: ids,
        payload: body,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Decision {
    Accepted,
    Encoding,
    Size,
    Budget,
    SignatureRejected,
}

/// These are observed API results and budget reservations, NOT an assertion
/// that every reserved verification reached signature arithmetic.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Outcomes {
    encoded_frames: u64,
    sign_and_self_verify_calls: u64,
    verification_api_calls: u64,
    accepted_authentications: u64,
    returned_verified_signatures: u64,
    policy_encoding_rejections: u64,
    policy_size_rejections: u64,
    policy_budget_rejections: u64,
    signature_arithmetic_rejections: u64,
    reserved_verification_attempts: u64,
    reserved_wire_bytes: u64,
    sticky_budget_checks: u64,
    input_wire_bytes: u64,
}

impl Outcomes {
    fn json(&self) -> Value {
        json!({
            "encoded_frames": self.encoded_frames,
            "sign_and_self_verify_calls": self.sign_and_self_verify_calls,
            "verification_api_calls": self.verification_api_calls,
            "accepted_authentications": self.accepted_authentications,
            "returned_verified_signatures": self.returned_verified_signatures,
            "policy_encoding_rejections": self.policy_encoding_rejections,
            "policy_size_rejections": self.policy_size_rejections,
            "policy_budget_rejections": self.policy_budget_rejections,
            "signature_arithmetic_rejections": self.signature_arithmetic_rejections,
            "reserved_verification_attempts": self.reserved_verification_attempts,
            "reserved_wire_bytes": self.reserved_wire_bytes,
            "sticky_budget_checks": self.sticky_budget_checks,
            "input_wire_bytes": self.input_wire_bytes,
        })
    }

    fn add(&mut self, other: &Self) {
        self.encoded_frames += other.encoded_frames;
        self.sign_and_self_verify_calls += other.sign_and_self_verify_calls;
        self.verification_api_calls += other.verification_api_calls;
        self.accepted_authentications += other.accepted_authentications;
        self.returned_verified_signatures += other.returned_verified_signatures;
        self.policy_encoding_rejections += other.policy_encoding_rejections;
        self.policy_size_rejections += other.policy_size_rejections;
        self.policy_budget_rejections += other.policy_budget_rejections;
        self.signature_arithmetic_rejections += other.signature_arithmetic_rejections;
        self.reserved_verification_attempts += other.reserved_verification_attempts;
        self.reserved_wire_bytes += other.reserved_wire_bytes;
        self.sticky_budget_checks += other.sticky_budget_checks;
        self.input_wire_bytes += other.input_wire_bytes;
    }

    fn record_budget(&mut self, budget: &CandidateVerificationBudget) {
        self.reserved_verification_attempts = budget.attempts();
        self.reserved_wire_bytes = budget.charged_bytes();
    }
}

struct CheckedVerifier<'a> {
    verifier: &'a CandidateProfileVerifier,
    expected: &'a CandidateEnvelope<'a>,
    message: &'a [u8],
}

impl CheckedVerifier<'_> {
    fn verify(
        &self,
        budget: &mut CandidateVerificationBudget,
        wire: &[u8],
        decision: Decision,
        outcomes: &mut Outcomes,
    ) -> BenchResult<()> {
        outcomes.verification_api_calls += 1;
        outcomes.input_wire_bytes += wire.len() as u64;
        match self
            .verifier
            .verify(budget, black_box(wire), black_box(self.expected))
        {
            Ok(observed) => {
                require(
                    decision == Decision::Accepted,
                    "unexpected authentication success",
                )?;
                require(
                    observed.crypto_profile_id() == self.verifier.profile().id()
                        && observed.signer_count() == self.verifier.signer_ids().len()
                        && observed.message() == self.message,
                    "authentication returned the wrong profile, signer count or complete message",
                )?;
                outcomes.accepted_authentications += 1;
                outcomes.returned_verified_signatures += observed.signer_count() as u64;
            }
            Err(error) => match (decision, error) {
                (
                    Decision::Encoding,
                    ProfileAuthenticationError::Policy(ProfileError::Encoding),
                ) => {
                    outcomes.policy_encoding_rejections += 1;
                }
                (Decision::Size, ProfileAuthenticationError::Policy(ProfileError::Size)) => {
                    outcomes.policy_size_rejections += 1;
                }
                (Decision::Budget, ProfileAuthenticationError::Policy(ProfileError::Budget)) => {
                    outcomes.policy_budget_rejections += 1;
                }
                (
                    Decision::SignatureRejected,
                    ProfileAuthenticationError::Signature(CandidateError::SignatureRejected),
                ) => outcomes.signature_arithmetic_rejections += 1,
                (_, error) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("expected {decision:?}, observed {error:?}"),
                    )
                    .into());
                }
            },
        }
        Ok(())
    }
}

fn check_budget(
    budget: &CandidateVerificationBudget,
    attempts: u64,
    bytes: u64,
) -> BenchResult<()> {
    require(
        budget.attempts() == attempts && budget.charged_bytes() == bytes,
        "failed, successful or latched request changed the expected cumulative reservation",
    )
}

#[derive(Clone, Copy)]
enum Operation {
    Encode,
    SignAndEncode,
    ColdVerify,
    HotVerify,
    LateInvalid,
    WrongProfile,
    WrongPurpose,
    ShortWire,
    TrailingByte,
    WrongMessageLength,
    SharedBudget,
}

impl Operation {
    const ALL: [Self; 11] = [
        Self::Encode,
        Self::SignAndEncode,
        Self::ColdVerify,
        Self::HotVerify,
        Self::LateInvalid,
        Self::WrongProfile,
        Self::WrongPurpose,
        Self::ShortWire,
        Self::TrailingByte,
        Self::WrongMessageLength,
        Self::SharedBudget,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Encode => "cpq1_encode_with_existing_signatures",
            Self::SignAndEncode => "cpq1_sign_self_verify_and_encode",
            Self::ColdVerify => "cpq1_cold_pin_and_verify",
            Self::HotVerify => "cpq1_hot_verify",
            Self::LateInvalid => "cpq1_late_invalid_last_signature",
            Self::WrongProfile => "cpq1_wrong_profile",
            Self::WrongPurpose => "cpq1_wrong_purpose",
            Self::ShortWire => "cpq1_short_wire",
            Self::TrailingByte => "cpq1_trailing_byte",
            Self::WrongMessageLength => "cpq1_message_length_mismatch",
            Self::SharedBudget => "cpq1_shared_budget_exhaustion",
        }
    }
}

fn measure(
    samples: usize,
    mut operation: impl FnMut() -> BenchResult<Outcomes>,
) -> BenchResult<(Vec<u64>, Outcomes, Outcomes)> {
    // One complete warmup, including all correctness checks, outside sample_ns.
    let warmup = operation()?;
    let mut raw = Vec::with_capacity(samples);
    let mut total = Outcomes::default();
    for _ in 0..samples {
        let start = Instant::now();
        let actual = operation()?;
        require(
            actual == warmup,
            "sample outcome differs from the checked warmup",
        )?;
        let ns = u64::try_from(start.elapsed().as_nanos())?;
        raw.push(ns);
        total.add(&actual);
    }
    Ok((raw, warmup, total))
}

fn report(
    case_id: &str,
    operation: Operation,
    raw: Vec<u64>,
    warmup: &Outcomes,
    totals: &Outcomes,
) -> BenchResult<()> {
    let mut ordered = raw.clone();
    ordered.sort_unstable();
    let samples = raw.len();
    let total = raw
        .iter()
        .try_fold(0u64, |sum, n| sum.checked_add(*n))
        .ok_or("duration sum overflow")?;
    let quantile = |percentile: usize| ordered[(samples * percentile).div_ceil(100) - 1];
    emit(json!({
        "schema": SCHEMA, "kind": "measurement", "case_id": case_id,
        "operation": operation.name(), "samples": samples, "checked_samples": samples,
        "warmup_groups": 1, "latency_unit": "ns_per_independent_operation_group",
        "sample_ns": raw, "min_ns": ordered[0], "mean_ns": total / samples as u64,
        "p50_ns": quantile(50), "p95_ns": quantile(95), "p99_ns": quantile(99),
        "max_ns": ordered[samples - 1], "total_ns": total,
        "outcomes_per_sample": warmup.json(), "warmup_outcomes": warmup.json(),
        "measured_outcome_totals": totals.json(), "production_p99_ns": null,
        "performance_acceptance_gate": false,
    }))
}

fn run_case(
    algorithm: CandidateAlgorithm,
    signer_count: usize,
    payload_label: &str,
    payload_bytes: usize,
    samples: usize,
) -> BenchResult<Outcomes> {
    let setup = Instant::now();
    let selected = profile(algorithm, 1)?;
    let foreign = profile(algorithm, 4)?;
    let signers = (0..signer_count)
        .map(|index| CandidateSigningKey::from_owned_seed(algorithm, seed(index)))
        .collect::<Result<Vec<_>, _>>()?;
    let raw_keys: Vec<_> = signers
        .iter()
        .map(CandidateSigningKey::public_key)
        .collect();
    let verifier = CandidateProfileVerifier::from_pinned_keys(selected.clone(), &raw_keys)?;
    let foreign_verifier = CandidateProfileVerifier::from_pinned_keys(foreign.clone(), &raw_keys)?;
    let ordered_keys = verifier.pinned_keys();
    let signer_order = ordered_keys
        .iter()
        .map(|key| {
            signers
                .iter()
                .position(|signer| signer.public_key() == *key)
                .ok_or("pinned key disappeared from the fixture")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let body = payload(payload_bytes);
    let expected = envelope(verifier.signer_ids(), &body);
    let message = selected.candidate_message(&expected)?;
    let signatures = signer_order
        .iter()
        .map(|index| signers[*index].sign(&message))
        .collect::<Result<Vec<_>, _>>()?;
    let signature_refs: Vec<_> = signatures.iter().map(Vec::as_slice).collect();
    let wire = selected.candidate_wire(&expected, &ordered_keys, &signature_refs)?;
    let mut late = wire.clone();
    let late_offset = late.len() - algorithm.signature_bytes();
    late[late_offset] ^= 1; // Last signature's c_tilde, with identical syntax/size.
    let mut tail = wire.clone();
    tail.push(0);
    let mut wrong_length = wire.clone();
    wrong_length[4..8].copy_from_slice(&u32::try_from(message.len() + 1)?.to_be_bytes());
    let mut wrong_purpose = envelope(verifier.signer_ids(), &body);
    wrong_purpose.purpose = CryptoPurpose::Current;
    let foreign_expected = envelope(foreign_verifier.signer_ids(), &body);
    let checked = CheckedVerifier {
        verifier: &verifier,
        expected: &expected,
        message: &message,
    };
    let wrong_purpose_checked = CheckedVerifier {
        verifier: &verifier,
        expected: &wrong_purpose,
        message: &message,
    };
    let foreign_checked = CheckedVerifier {
        verifier: &foreign_verifier,
        expected: &foreign_expected,
        message: &message,
    };
    let mut setup_budget = CandidateVerificationBudget::new();
    let mut setup_outcomes = Outcomes {
        encoded_frames: 1,
        sign_and_self_verify_calls: signer_count as u64,
        ..Outcomes::default()
    };
    checked.verify(
        &mut setup_budget,
        &wire,
        Decision::Accepted,
        &mut setup_outcomes,
    )?;
    check_budget(&setup_budget, signer_count as u64, wire.len() as u64)?;
    setup_outcomes.record_budget(&setup_budget);
    let policy = CryptoProfilePolicy::from_trusted_state(selected.clone(), 20, 1, vec![])?;
    require(
        matches!(
            policy.select_current(selected.id()),
            Err(ProfileError::CandidateOnly)
        ),
        "candidate acquired current authorization",
    )?;
    let max_payload = MAX_SIGNED_MESSAGE_BYTES - CANDIDATE_HEADER_BYTES - 64 * signer_count;
    let case_id = format!("{}/{signer_count}/{payload_label}", algorithm.name());
    emit(json!({
        "schema": SCHEMA, "kind": "case", "case_id": case_id,
        "algorithm": algorithm.name(), "nist_category": algorithm.nist_category(),
        "signer_count": signer_count, "payload_label": payload_label,
        "payload_bytes": body.len(), "maximum_legal_payload_bytes": max_payload,
        "crypto_profile_id": selected.id().to_hex(), "wrong_profile_id": foreign.id().to_hex(),
        "signer_ids": verifier.signer_ids().iter().map(hex::encode).collect::<Vec<_>>(),
        "signer_seed_indices_in_wire_order": signer_order,
        "signed_message_bytes": message.len(), "cpq1_wire_bytes": wire.len(),
        "signed_metadata_bytes": message.len() - body.len(),
        "outer_framing_bytes": wire.len() - message.len() - signer_count * (algorithm.public_key_bytes() + algorithm.signature_bytes()),
        "public_key_bytes_each": algorithm.public_key_bytes(),
        "signature_bytes_each": algorithm.signature_bytes(),
        "signed_message_hex": hex::encode(&message), "cpq1_wire_hex": hex::encode(&wire),
        "signed_message_sha512": hex::encode(Sha512::digest(&message)),
        "cpq1_wire_sha512": hex::encode(Sha512::digest(&wire)),
        "late_invalid_byte_offset": late_offset, "late_invalid_xor": 1,
        "setup_wall_ns": u64::try_from(setup.elapsed().as_nanos())?,
        "setup_outcomes": setup_outcomes.json(), "current_authorization_refused": true,
    }))?;

    let mut case_totals = Outcomes::default();
    for operation in Operation::ALL {
        let (raw, warmup, totals) = measure(samples, || {
            let mut outcomes = Outcomes::default();
            let mut budget = CandidateVerificationBudget::new();
            let n = signer_count as u64;
            let bytes = wire.len() as u64;
            match operation {
                Operation::Encode => {
                    let encoded_message = selected.candidate_message(black_box(&expected))?;
                    let encoded = selected.candidate_wire(
                        black_box(&expected),
                        &ordered_keys,
                        &signature_refs,
                    )?;
                    require(
                        encoded_message == message && encoded == wire,
                        "CPQ1 encoding changed fixture bytes",
                    )?;
                    outcomes.encoded_frames += 1;
                }
                Operation::SignAndEncode => {
                    let signed_message = selected.candidate_message(black_box(&expected))?;
                    let signed = signer_order
                        .iter()
                        .map(|index| {
                            let signature = signers[*index].sign(black_box(&signed_message))?;
                            outcomes.sign_and_self_verify_calls += 1;
                            Ok(signature)
                        })
                        .collect::<BenchResult<Vec<_>>>()?;
                    let refs: Vec<_> = signed.iter().map(Vec::as_slice).collect();
                    let encoded = selected.candidate_wire(&expected, &ordered_keys, &refs)?;
                    require(
                        signed_message == message && encoded == wire,
                        "deterministic complete CPQ1 signing changed fixture bytes",
                    )?;
                    outcomes.encoded_frames += 1;
                }
                Operation::ColdVerify => {
                    let cold = CandidateProfileVerifier::from_pinned_keys(
                        selected.clone(),
                        black_box(&raw_keys),
                    )?;
                    CheckedVerifier {
                        verifier: &cold,
                        expected: &expected,
                        message: &message,
                    }
                    .verify(
                        &mut budget,
                        &wire,
                        Decision::Accepted,
                        &mut outcomes,
                    )?;
                    check_budget(&budget, n, bytes)?;
                }
                Operation::HotVerify => {
                    checked.verify(&mut budget, &wire, Decision::Accepted, &mut outcomes)?;
                    check_budget(&budget, n, bytes)?;
                }
                Operation::LateInvalid => {
                    require(late.len() == wire.len(), "late-invalid wire length changed")?;
                    checked.verify(
                        &mut budget,
                        &late,
                        Decision::SignatureRejected,
                        &mut outcomes,
                    )?;
                    check_budget(&budget, n, bytes)?;
                }
                Operation::WrongProfile => {
                    foreign_checked.verify(
                        &mut budget,
                        &wire,
                        Decision::Encoding,
                        &mut outcomes,
                    )?;
                    check_budget(&budget, n, bytes)?;
                }
                Operation::WrongPurpose => {
                    wrong_purpose_checked.verify(
                        &mut budget,
                        &wire,
                        Decision::Encoding,
                        &mut outcomes,
                    )?;
                    check_budget(&budget, n, bytes)?;
                }
                Operation::ShortWire => {
                    checked.verify(&mut budget, SHORT_WIRE, Decision::Size, &mut outcomes)?;
                    check_budget(&budget, n, SHORT_WIRE.len() as u64)?;
                }
                Operation::TrailingByte => {
                    checked.verify(&mut budget, &tail, Decision::Encoding, &mut outcomes)?;
                    check_budget(&budget, n, bytes + 1)?;
                }
                Operation::WrongMessageLength => {
                    checked.verify(&mut budget, &wrong_length, Decision::Size, &mut outcomes)?;
                    check_budget(&budget, n, bytes)?;
                }
                Operation::SharedBudget => {
                    let groups = CANDIDATE_MAX_ATTEMPTS / n;
                    require(
                        groups * n == CANDIDATE_MAX_ATTEMPTS,
                        "fixture signer count does not divide batch budget",
                    )?;
                    checked.verify(&mut budget, &wire, Decision::Accepted, &mut outcomes)?;
                    check_budget(&budget, n, bytes)?;
                    for index in 1..groups {
                        wrong_purpose_checked.verify(
                            &mut budget,
                            &wire,
                            Decision::Encoding,
                            &mut outcomes,
                        )?;
                        check_budget(&budget, (index + 1) * n, (index + 1) * bytes)?;
                    }
                    // The overflowing attempt is charged before the latch.
                    checked.verify(&mut budget, &wire, Decision::Budget, &mut outcomes)?;
                    check_budget(&budget, CANDIDATE_MAX_ATTEMPTS + n, (groups + 1) * bytes)?;
                    // A new malformed request cannot replenish that same budget.
                    checked.verify(&mut budget, SHORT_WIRE, Decision::Budget, &mut outcomes)?;
                    check_budget(&budget, CANDIDATE_MAX_ATTEMPTS + n, (groups + 1) * bytes)?;
                    outcomes.sticky_budget_checks += 1;
                }
            }
            outcomes.record_budget(&budget);
            Ok(outcomes)
        })?;
        report(&case_id, operation, raw, &warmup, &totals)?;
        case_totals.add(&totals);
    }
    Ok(case_totals)
}

fn main() -> BenchResult<()> {
    let Some(samples) = samples_from_args()? else {
        return Ok(());
    };
    let profiles = CandidateAlgorithm::ALL
        .iter()
        .map(|algorithm| {
            let selected = profile(*algorithm, 1)?;
            let bytes = selected.canonical_configuration();
            Ok(json!({
                "algorithm": algorithm.name(), "crypto_profile_id": selected.id().to_hex(),
                "canonical_configuration_bytes": bytes.len(),
                "canonical_configuration_hex": hex::encode(bytes),
                "wrong_network_profile_id": profile(*algorithm, 4)?.id().to_hex(),
            }))
        })
        .collect::<BenchResult<Vec<_>>>()?;
    emit(json!({
        "schema": SCHEMA, "kind": "run", "wire_format": "CPQ1",
        "scope": "actual CPQ1 candidate APIs; local repeated public fixtures only",
        "algorithms": ["ML-DSA-65", "ML-DSA-87"], "signer_counts": SIGNER_COUNTS,
        "payload_labels": PAYLOAD_LABELS, "samples_per_operation_case": samples,
        "operations": Operation::ALL.iter().map(|operation| operation.name()).collect::<Vec<_>>(),
        "warmup_groups_per_operation_case": 1, "fixture_repeated_each_sample": true,
        "signature_mode": "FIPS204-Pure", "fips_context_hex": "", "signing_variant": "deterministic",
        "seed_fixture": "32 bytes 0x42; last eight bytes replaced by signer index as u64be",
        "payload_fixture": "byte[i] = (i * 29 + 17) mod 256",
        "binding": {"network_hex": "01".repeat(32), "parameters_hex": "02".repeat(32),
            "genesis_hex": "03".repeat(32), "scope": "WholeSystemCandidate", "protocol_version": 1,
            "activation_height": 10, "retirement_height_exclusive": 100},
        "envelope": {"purpose": "FinalUse", "purpose_code": 9, "owner_generation": 7,
            "key_epoch": 3, "sequence": 11, "valid_from_height": 10, "valid_until_height_inclusive": 99},
        "work_configuration_digest": hex::encode(native_work_configuration_digest()),
        "profiles": profiles,
        "limits": {"signed_message_bytes": MAX_SIGNED_MESSAGE_BYTES, "wire_bytes": CANDIDATE_MAX_WIRE_BYTES,
            "signers": CANDIDATE_MAX_SIGNERS, "reserved_verification_attempts": CANDIDATE_MAX_ATTEMPTS,
            "reserved_wire_bytes": CANDIDATE_MAX_CUMULATIVE_BYTES, "signed_header_bytes": CANDIDATE_HEADER_BYTES},
        "clock": "std::time::Instant", "quantiles": "nearest-rank; integer mean; raw samples retained",
        "tail_note": "64-sample p99 is the observed maximum, not a production population tail",
        "timing_scope": TIMING_SCOPE, "budget_scope": BUDGET_SCOPE, "hardware_scope": HARDWARE_SCOPE,
        "execution_context": {"arch": env::consts::ARCH, "os": env::consts::OS,
            "debug_assertions": cfg!(debug_assertions), "crate_version": env!("CARGO_PKG_VERSION")},
        "caller_run_context_required": true,
        "caller_run_context": "record exact source and diff, binary hash, locked graph, rustc -Vv, cargo -V, target, flags, CPU, memory, kernel, load, command and terminal exit beside this output",
        "frame_is_PNQ_or_NPQ": false, "network_or_business_confirmation_measured": false,
        "production_tail_established": false, "activation_performed": false,
    }))?;
    let mut cases = 0;
    let mut totals = Outcomes::default();
    for signer_count in SIGNER_COUNTS {
        let maximum = MAX_SIGNED_MESSAGE_BYTES - CANDIDATE_HEADER_BYTES - 64 * signer_count;
        for (label, length) in PAYLOAD_LABELS.into_iter().zip([0, 176, 4096, maximum]) {
            for algorithm in CandidateAlgorithm::ALL {
                totals.add(&run_case(algorithm, signer_count, label, length, samples)?);
                cases += 1;
            }
        }
    }
    emit(json!({
        "schema": SCHEMA, "kind": "complete", "cases": cases,
        "measurement_rows": cases * Operation::ALL.len(), "samples_per_operation_case": samples,
        "raw_sample_values": cases * Operation::ALL.len() * samples,
        "warmup_groups": cases * Operation::ALL.len(), "all_expected_outcomes_checked": true,
        "measured_outcome_totals": totals.json(), "production_qualified": false,
        "activation_performed": false,
    }))
}
