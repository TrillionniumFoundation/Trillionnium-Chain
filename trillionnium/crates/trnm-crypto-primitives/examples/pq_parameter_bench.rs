//! Bounded, reproducible ML-DSA-65/87 candidate measurements.
//!
//! Run with an optimized build and the repository's locked dependency graph:
//! `cargo run --release --locked -p trnm-crypto-primitives --example pq_parameter_bench -- --samples 64`
//!
//! This is a local primitive/candidate-frame benchmark, not PNQ/NPQ admission,
//! business confirmation, a network benchmark or a production p99. Fixed public
//! seeds and deterministic signing deliberately repeat the same fixture. Quantile
//! variation therefore measures this workload and host scheduling, not key/message
//! diversity. At 64 samples the nearest-rank p99 is the sample maximum.

use std::{env, error::Error, hint::black_box, io, time::Instant};
use trnm_crypto_primitives::pq_candidate::{
    CandidateAlgorithm, CandidateError, CandidateSigningKey, CandidateVerifier,
    CANDIDATE_MAX_MESSAGE_BYTES,
};
use zeroize::Zeroizing;

type BenchResult<T> = Result<T, Box<dyn Error>>;

const MIN_SAMPLES: usize = 64;
const MAX_SAMPLES: usize = 4_096;
const MAX_SIGNERS: usize = 8;
const FRAME_MAGIC: &[u8; 8] = b"TRNMCPB1";

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn samples_from_args() -> BenchResult<Option<usize>> {
    let mut args = env::args().skip(1);
    let samples = match args.next().as_deref() {
        None => MIN_SAMPLES,
        Some("--help" | "-h") => {
            println!("pq_parameter_bench [--samples N], {MIN_SAMPLES} <= N <= {MAX_SAMPLES}");
            return Ok(None);
        }
        Some("--samples") => args
            .next()
            .ok_or_else(|| invalid("--samples requires a count"))?
            .parse::<usize>()?,
        Some(_) => return Err(invalid("expected --samples N or --help").into()),
    };
    if args.next().is_some() || !(MIN_SAMPLES..=MAX_SAMPLES).contains(&samples) {
        return Err(invalid("sample count must be in 64..=4096, with no extra arguments").into());
    }
    Ok(Some(samples))
}

fn fixture_seed(signer: usize) -> Zeroizing<[u8; 32]> {
    let mut seed = Zeroizing::new([0x42; 32]);
    seed[24..].copy_from_slice(&(signer as u64).to_be_bytes());
    seed
}

fn fixture_message(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| (index as u8).wrapping_mul(29).wrapping_add(17))
        .collect()
}

fn suite_tag(algorithm: CandidateAlgorithm) -> u8 {
    match algorithm {
        CandidateAlgorithm::MlDsa65 => 0x65,
        CandidateAlgorithm::MlDsa87 => 0x87,
    }
}

/// Actual serialized bytes of this benchmark's observation frame. It carries
/// no profile activation, role, nonce, generation or production authority.
/// Layout: magic[8], pinned-suite[1], message-len:u32be, signer-count:u16be,
/// message, then (raw-key-len:u16be, raw-key, signature-len:u16be, signature)*N.
fn encode_observation_frame(
    algorithm: CandidateAlgorithm,
    message: &[u8],
    public_keys: &[Vec<u8>],
    signatures: &[Vec<u8>],
) -> BenchResult<Vec<u8>> {
    if message.len() > CANDIDATE_MAX_MESSAGE_BYTES
        || public_keys.is_empty()
        || public_keys.len() > MAX_SIGNERS
        || public_keys.len() != signatures.len()
    {
        return Err(invalid("candidate frame cardinality or message bound").into());
    }
    let mut frame = Vec::new();
    frame.extend_from_slice(FRAME_MAGIC);
    frame.push(suite_tag(algorithm));
    frame.extend_from_slice(&u32::try_from(message.len())?.to_be_bytes());
    frame.extend_from_slice(&u16::try_from(public_keys.len())?.to_be_bytes());
    frame.extend_from_slice(message);
    for (key, signature) in public_keys.iter().zip(signatures) {
        if key.len() != algorithm.public_key_bytes()
            || signature.len() != algorithm.signature_bytes()
        {
            return Err(invalid("candidate frame key/signature length").into());
        }
        frame.extend_from_slice(&u16::try_from(key.len())?.to_be_bytes());
        frame.extend_from_slice(key);
        frame.extend_from_slice(&u16::try_from(signature.len())?.to_be_bytes());
        frame.extend_from_slice(signature);
    }
    Ok(frame)
}

fn take<'a>(remaining: &mut &'a [u8], len: usize) -> Result<&'a [u8], io::Error> {
    if len > remaining.len() {
        return Err(invalid("truncated candidate frame"));
    }
    let (value, rest) = remaining.split_at(len);
    *remaining = rest;
    Ok(value)
}

fn take_u16(remaining: &mut &[u8]) -> Result<usize, io::Error> {
    let bytes = take(remaining, 2)?;
    Ok(usize::from(u16::from_be_bytes([bytes[0], bytes[1]])))
}

struct BorrowedObservationFrame<'a> {
    message: &'a [u8],
    signatures: Vec<&'a [u8]>,
}

impl<'a> BorrowedObservationFrame<'a> {
    fn parse(
        expected_algorithm: CandidateAlgorithm,
        pinned: &[CandidateVerifier],
        bytes: &'a [u8],
    ) -> BenchResult<Self> {
        let mut remaining = bytes;
        if take(&mut remaining, FRAME_MAGIC.len())? != FRAME_MAGIC
            || take(&mut remaining, 1)? != [suite_tag(expected_algorithm)]
        {
            return Err(invalid("candidate frame version or pinned suite mismatch").into());
        }
        let bytes = take(&mut remaining, 4)?;
        let message_len =
            usize::try_from(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))?;
        let signer_count = take_u16(&mut remaining)?;
        if message_len > CANDIDATE_MAX_MESSAGE_BYTES
            || signer_count == 0
            || signer_count > MAX_SIGNERS
            || signer_count != pinned.len()
        {
            return Err(invalid("candidate frame message/count bound").into());
        }
        let message = take(&mut remaining, message_len)?;
        let mut signatures = Vec::with_capacity(signer_count);
        for verifier in pinned {
            if verifier.algorithm() != expected_algorithm
                || take_u16(&mut remaining)? != expected_algorithm.public_key_bytes()
                || take(&mut remaining, expected_algorithm.public_key_bytes())?
                    != verifier.public_key()
                || take_u16(&mut remaining)? != expected_algorithm.signature_bytes()
            {
                return Err(
                    invalid("candidate frame differs from independently pinned keys").into(),
                );
            }
            signatures.push(take(&mut remaining, expected_algorithm.signature_bytes())?);
        }
        if !remaining.is_empty() {
            return Err(invalid("trailing bytes in candidate frame").into());
        }
        Ok(Self {
            message,
            signatures,
        })
    }

    fn verify(&self, pinned: &[CandidateVerifier]) -> BenchResult<()> {
        if self.signatures.len() != pinned.len() {
            return Err(invalid("candidate frame verifier count changed").into());
        }
        for (verifier, signature) in pinned.iter().zip(&self.signatures) {
            verifier.verify(self.message, signature)?;
        }
        Ok(())
    }
}

struct Case {
    algorithm: CandidateAlgorithm,
    message_bytes: usize,
    signer_count: usize,
    wire_bytes: usize,
    framing_bytes: usize,
}

#[derive(Clone, Copy)]
enum Operation {
    Keygen,
    KeyImport,
    SignAndSelfVerify,
    ValidVerify,
    LateInvalidVerify,
    EarlySizeReject,
    FrameEncode,
    FramePreflight,
    FrameVerify,
}

impl Operation {
    const ALL: [Self; 9] = [
        Self::Keygen,
        Self::KeyImport,
        Self::SignAndSelfVerify,
        Self::ValidVerify,
        Self::LateInvalidVerify,
        Self::EarlySizeReject,
        Self::FrameEncode,
        Self::FramePreflight,
        Self::FrameVerify,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Keygen => "keygen_with_candidate_verifier_and_zeroizing_drop",
            Self::KeyImport => "pinned_raw_key_import_and_drop",
            Self::SignAndSelfVerify => "sign_encode_self_verify_and_drop",
            Self::ValidVerify => "valid_verify_with_preexpanded_key",
            Self::LateInvalidVerify => "late_invalid_verify_with_preexpanded_key",
            Self::EarlySizeReject => "early_signature_size_rejection",
            Self::FrameEncode => "candidate_observation_frame_encode_and_drop",
            Self::FramePreflight => "candidate_observation_frame_preflight",
            Self::FrameVerify => "candidate_observation_frame_preflight_and_verify",
        }
    }

    fn verify_calls(self, signer_count: usize) -> usize {
        match self {
            Self::SignAndSelfVerify
            | Self::ValidVerify
            | Self::LateInvalidVerify
            | Self::FrameVerify => signer_count,
            _ => 0,
        }
    }

    fn expected_rejections(self, signer_count: usize) -> usize {
        match self {
            Self::LateInvalidVerify | Self::EarlySizeReject => signer_count,
            _ => 0,
        }
    }
}

fn measure(
    samples: usize,
    mut operation: impl FnMut() -> BenchResult<()>,
) -> BenchResult<Vec<u128>> {
    // One disclosed warm-up group per stage, outside the measured population.
    operation()?;
    let mut durations = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        operation()?;
        durations.push(start.elapsed().as_nanos());
    }
    Ok(durations)
}

fn nearest_rank(sorted: &[u128], percentile: usize) -> u128 {
    let rank = (sorted.len() * percentile).div_ceil(100);
    sorted[rank - 1]
}

fn report(case: &Case, operation: Operation, durations: Vec<u128>) {
    let mut sorted = durations.clone();
    sorted.sort_unstable();
    let count = durations.len();
    let total: u128 = durations.iter().sum();
    println!(
        concat!(
            "{{\"kind\":\"measurement\",\"algorithm\":\"{}\",\"nist_category\":{},",
            "\"message_bytes\":{},\"signer_count\":{},\"samples\":{},\"operation\":\"{}\",",
            "\"latency_unit\":\"ns_per_signer_group\",\"min_ns\":{},\"mean_ns\":{},",
            "\"p50_ns\":{},\"p95_ns\":{},\"p99_ns\":{},\"max_ns\":{},\"total_ns\":{},",
            "\"public_key_bytes_each\":{},\"signature_bytes_each\":{},",
            "\"actual_candidate_frame_bytes\":{},\"actual_framing_bytes\":{},",
            "\"arithmetic_verify_calls_per_sample\":{},\"expected_rejections_per_sample\":{},",
            "\"production_message_budget_pass\":null,\"sample_ns\":{:?}}}"
        ),
        case.algorithm.name(),
        case.algorithm.nist_category(),
        case.message_bytes,
        case.signer_count,
        count,
        operation.name(),
        sorted[0],
        total / count as u128,
        nearest_rank(&sorted, 50),
        nearest_rank(&sorted, 95),
        nearest_rank(&sorted, 99),
        sorted[count - 1],
        total,
        case.algorithm.public_key_bytes(),
        case.algorithm.signature_bytes(),
        case.wire_bytes,
        case.framing_bytes,
        operation.verify_calls(case.signer_count),
        operation.expected_rejections(case.signer_count),
        durations,
    );
}

fn run_case(
    algorithm: CandidateAlgorithm,
    message_bytes: usize,
    signer_count: usize,
    samples: usize,
) -> BenchResult<()> {
    let message = fixture_message(message_bytes);
    let signers = (0..signer_count)
        .map(|index| CandidateSigningKey::from_owned_seed(algorithm, fixture_seed(index)))
        .collect::<Result<Vec<_>, _>>()?;
    let public_keys = signers
        .iter()
        .map(|key| key.public_key().to_vec())
        .collect::<Vec<_>>();
    let verifiers = public_keys
        .iter()
        .map(|raw| CandidateVerifier::from_pinned_raw(algorithm, raw))
        .collect::<Result<Vec<_>, _>>()?;
    let signatures = signers
        .iter()
        .map(|key| key.sign(&message))
        .collect::<Result<Vec<_>, _>>()?;
    let late_invalid = signatures
        .iter()
        .map(|valid| {
            let mut bad = valid.clone();
            // Change only c_tilde, preserving the canonical signature syntax.
            bad[0] ^= 1;
            bad
        })
        .collect::<Vec<_>>();
    let early_invalid = signatures
        .iter()
        .map(|valid| valid[..valid.len() - 1].to_vec())
        .collect::<Vec<_>>();
    let wire = encode_observation_frame(algorithm, &message, &public_keys, &signatures)?;
    BorrowedObservationFrame::parse(algorithm, &verifiers, &wire)?.verify(&verifiers)?;
    let material_bytes: usize = public_keys.iter().chain(&signatures).map(Vec::len).sum();
    let case = Case {
        algorithm,
        message_bytes,
        signer_count,
        wire_bytes: wire.len(),
        framing_bytes: wire.len() - message.len() - material_bytes,
    };

    for operation in Operation::ALL {
        let durations = measure(samples, || {
            match operation {
                Operation::Keygen => {
                    for index in 0..signer_count {
                        black_box(CandidateSigningKey::from_owned_seed(
                            algorithm,
                            fixture_seed(index),
                        )?);
                    }
                }
                Operation::KeyImport => {
                    for key in &public_keys {
                        black_box(CandidateVerifier::from_pinned_raw(
                            algorithm,
                            black_box(key),
                        )?);
                    }
                }
                Operation::SignAndSelfVerify => {
                    for key in &signers {
                        black_box(key.sign(black_box(&message))?);
                    }
                }
                Operation::ValidVerify => {
                    for (key, signature) in verifiers.iter().zip(&signatures) {
                        key.verify(black_box(&message), black_box(signature))?;
                    }
                }
                Operation::LateInvalidVerify => {
                    for (key, signature) in verifiers.iter().zip(&late_invalid) {
                        if key.verify(black_box(&message), black_box(signature))
                            != Err(CandidateError::SignatureRejected)
                        {
                            return Err(invalid(
                                "late invalid fixture did not reach arithmetic rejection",
                            )
                            .into());
                        }
                    }
                }
                Operation::EarlySizeReject => {
                    for (key, signature) in verifiers.iter().zip(&early_invalid) {
                        if !matches!(
                            key.verify(black_box(&message), black_box(signature)),
                            Err(CandidateError::SignatureLength { .. })
                        ) {
                            return Err(invalid(
                                "early invalid fixture did not reach length rejection",
                            )
                            .into());
                        }
                    }
                }
                Operation::FrameEncode => {
                    black_box(encode_observation_frame(
                        algorithm,
                        black_box(&message),
                        black_box(&public_keys),
                        black_box(&signatures),
                    )?);
                }
                Operation::FramePreflight => {
                    black_box(BorrowedObservationFrame::parse(
                        algorithm,
                        &verifiers,
                        black_box(&wire),
                    )?);
                }
                Operation::FrameVerify => {
                    BorrowedObservationFrame::parse(algorithm, &verifiers, black_box(&wire))?
                        .verify(&verifiers)?;
                }
            }
            Ok(())
        })?;
        report(&case, operation, durations);
    }
    Ok(())
}

fn main() -> BenchResult<()> {
    let Some(samples) = samples_from_args()? else {
        return Ok(());
    };
    println!(
        concat!(
            "{{\"kind\":\"run\",\"schema\":\"trnm.pq-candidate-bench.v1\",",
            "\"scope\":\"local candidate primitives and TRNMCPB1 observation frame only\",",
            "\"network_or_production_p99\":false,\"activation_performed\":false,",
            "\"algorithms\":[\"ML-DSA-65\",\"ML-DSA-87\"],",
            "\"message_lengths\":[0,176,4096,65536],\"signer_counts\":[1,2,4,8],",
            "\"samples_per_stage_case\":{},\"warmup_groups_per_stage_case\":1,",
            "\"signature_mode\":\"FIPS204-Pure\",\"fips_context_hex\":\"\",",
            "\"signing_variant\":\"deterministic\",\"implicit_randomness\":false,",
            "\"seed_fixture\":\"32 bytes 0x42 with final 8 bytes signer index u64be\",",
            "\"message_fixture\":\"byte[i] = (i * 29 + 17) mod 256\",",
            "\"fixture_repeated_each_sample\":true,\"clock\":\"std::time::Instant\",",
            "\"quantiles\":\"nearest-rank on observed group durations\",",
            "\"tail_note\":\"64-sample p99 equals the sample maximum; no population-tail claim\",",
            "\"invalid_verify_group\":\"each signer has a syntax-valid changed challenge; all attempts paid\",",
            "\"candidate_frame_layout\":\"magic[8],suite[1],message_len:u32be,count:u16be,message,(pk_len:u16be,pk,sig_len:u16be,sig)*count\",",
            "\"frame_is_PNQ_or_NPQ\":false,\"arch\":\"{}\",\"os\":\"{}\",",
            "\"debug_assertions\":{},\"crate_version\":\"{}\",",
            "\"caller_run_context_required\":true,",
            "\"caller_run_context\":\"record CPU, memory, OS/kernel, exact source SHA and diff, rustc -Vv, cargo -V, target, RUSTFLAGS, load and command alongside this output\"}}"
        ),
        samples,
        env::consts::ARCH,
        env::consts::OS,
        cfg!(debug_assertions),
        env!("CARGO_PKG_VERSION"),
    );
    let mut completed_cases = 0;
    for message_bytes in [0, 176, 4_096, CANDIDATE_MAX_MESSAGE_BYTES] {
        for signer_count in [1, 2, 4, 8] {
            for algorithm in CandidateAlgorithm::ALL {
                run_case(algorithm, message_bytes, signer_count, samples)?;
                completed_cases += 1;
            }
        }
    }
    println!(
        concat!(
            "{{\"kind\":\"complete\",\"cases\":{},\"measurement_rows\":{},",
            "\"samples_per_stage_case\":{},\"raw_sample_values\":{},",
            "\"all_expected_outcomes_checked\":true}}"
        ),
        completed_cases,
        completed_cases * Operation::ALL.len(),
        samples,
        completed_cases * Operation::ALL.len() * samples,
    );
    Ok(())
}
