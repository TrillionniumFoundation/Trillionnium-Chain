//! Research-only real STARK driver. No integration with Chain admission.
use anyhow::{anyhow, ensure, Context, Result};
use bincode::Options;
use risc0_binfmt::Digestible;
use risc0_zkvm::{
    compute_image_id, Executor, ExecutorEnv, ExternalProver, InnerReceipt, Prover, ProverOpts,
    Receipt, ReceiptKind, VerifierContext,
};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::time::Instant;
use trnm_w1_guest_relation::full_relation;

mod receipt_bounds;
use receipt_bounds::{BoundaryError, MAX_RECEIPT_BYTES};

const MAX_ELF_BYTES: usize = 16 * 1024 * 1024;
const MAX_SESSION_CYCLES: u64 = 256 * 1024 * 1024;

fn bounded_read(path: &Path, cap: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take((cap + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > cap {
        return Err(BoundaryError::Refused("input exceeds explicit byte cap").into());
    }
    Ok(bytes)
}

fn environment(input: &[u8], po2: u32) -> Result<ExecutorEnv<'_>> {
    ensure!(
        (16..=20).contains(&po2),
        "segment power must be 16 through 20"
    );
    ExecutorEnv::builder()
        .write_slice(input)
        .segment_limit_po2(po2)
        .session_limit(Some(MAX_SESSION_CYCLES))
        .build()
}

fn strict_verify(receipt: &Receipt, elf: &[u8], expected_journal: &[u8]) -> Result<()> {
    require_pinned_image(elf)?;
    // A public-output mismatch is a cheap rejection, never an authentication.
    // Matching bytes still require the complete cryptographic check below.
    ensure!(
        receipt.journal.bytes == expected_journal,
        "public journal does not match the complete bound W1 statement"
    );
    let composite = match &receipt.inner {
        InnerReceipt::Composite(value) => value,
        _ => {
            return Err(BoundaryError::Refused(
                "only actual transparent Composite receipts are supported",
            )
            .into())
        }
    };
    if composite.segments.is_empty() || composite.segments.len() > receipt_bounds::MAX_SEGMENTS {
        return Err(BoundaryError::Refused("segment count budget").into());
    }
    let mut padded_cycles = 0u64;
    for segment in &composite.segments {
        padded_cycles += receipt_bounds::check_seal(&segment.seal)?;
        receipt_bounds::check_padded_cycles(padded_cycles)?;
    }
    if !composite.assumption_receipts.is_empty() {
        return Err(BoundaryError::Refused("no nested assumptions supported").into());
    }
    if !composite
        .segments
        .iter()
        .all(|segment| segment.hashfn == "poseidon2")
    {
        return Err(BoundaryError::Refused("unsupported proof commitment hash").into());
    }
    let context = VerifierContext::default().with_dev_mode(false);
    let composite_parameters = context
        .composite_verifier_parameters()
        .context("pinned Composite verifier parameters missing")?
        .digest::<risc0_zkvm::sha::Impl>();
    if composite.verifier_parameters != composite_parameters {
        return Err(BoundaryError::Refused("unsupported Composite verifier parameters").into());
    }
    let parameters = context
        .segment_verifier_parameters
        .as_ref()
        .context("pinned segment verifier parameters missing")?
        .digest::<risc0_zkvm::sha::Impl>();
    if !composite
        .segments
        .iter()
        .all(|segment| segment.verifier_parameters == parameters)
    {
        return Err(BoundaryError::Refused("unsupported segment verifier parameters").into());
    }
    receipt.verify_with_context(&context, compute_image_id(elf)?)?;
    Ok(())
}

fn deserialize_receipt(bytes: &[u8]) -> Result<Receipt> {
    // with_limit alone is not our allocation or verification-cost policy.
    // Every nested length/variant is scanned without allocation first.
    receipt_bounds::preflight(bytes)?;
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_RECEIPT_BYTES as u64)
        .reject_trailing_bytes()
        .deserialize(bytes)?)
}

fn rejection(label: &str, check: impl FnOnce() -> Result<()>) -> Result<serde_json::Value> {
    let started = Instant::now();
    let result = check();
    let elapsed_ns = started.elapsed().as_nanos();
    ensure!(
        result.is_err(),
        "adversarial control unexpectedly accepted: {label}"
    );
    let error = result.unwrap_err();
    let outcome = match error.downcast_ref::<BoundaryError>() {
        Some(BoundaryError::Refused(_)) => "refused_not_evaluated",
        Some(BoundaryError::Malformed(_)) => "malformed_encoding",
        None => "verification_failed",
    };
    Ok(
        serde_json::json!({"case":label,"rejected":true,"outcome":outcome,
        "reject_wall_ns":elapsed_ns,"reason":format!("{error}")}),
    )
}

fn audit_receipt(receipt: &Receipt, elf: &[u8], input: &[u8], encoded: &[u8]) -> Result<()> {
    let journal = full_relation::unverified_claimed_journal(input).map_err(|e| anyhow!("{e:?}"))?;
    // Every negative control starts from a genuinely verified proof.
    strict_verify(receipt, elf, &journal)?;
    let mut cases = Vec::new();
    cases.push(rejection("wrong_image", || {
        receipt.verify_with_context(&VerifierContext::default().with_dev_mode(false), [0u32; 8])?;
        Ok(())
    })?);
    let mut changed_input = input.to_vec();
    changed_input[38 + 150] ^= 1; // Header.miner: a different payout statement.
    let changed_journal =
        full_relation::unverified_claimed_journal(&changed_input).map_err(|e| anyhow!("{e:?}"))?;
    cases.push(rejection("wrong_statement_miner", || {
        strict_verify(receipt, elf, &changed_journal)
    })?);
    cases.push(rejection("truncated_receipt", || {
        let changed = deserialize_receipt(&encoded[..encoded.len() - 1])?;
        strict_verify(&changed, elf, &journal)
    })?);
    for (label, offset, changed_word) in [
        ("segment_count_allocation_bomb", 4, u64::MAX),
        ("seal_length_allocation_bomb", 12, u64::MAX),
        ("empty_seal_before_sdk", 12, 0),
        (
            "outer_journal_allocation_bomb",
            encoded.len() - 32 - 228 - 8,
            u64::MAX,
        ),
        (
            "nested_assumptions_refused",
            encoded.len() - 32 - 228 - 8 - 32 - 8,
            1,
        ),
    ] {
        let mut changed = encoded.to_vec();
        changed[offset..offset + 8].copy_from_slice(&changed_word.to_le_bytes());
        cases.push(rejection(label, || {
            let decoded = deserialize_receipt(&changed)?;
            strict_verify(&decoded, elf, &journal)
        })?);
    }
    let mut dimension_bomb = encoded.to_vec();
    // u32 enum + u64 segment count + u64 first-seal words, then the v2 seal.
    let po2_offset = 20 + 4 * 91;
    dimension_bomb[po2_offset..po2_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    cases.push(rejection("seal_dimension_budget", || {
        let decoded = deserialize_receipt(&dimension_bomb)?;
        strict_verify(&decoded, elf, &journal)
    })?);
    let mut extended = encoded.to_vec();
    extended.push(0);
    cases.push(rejection("trailing_receipt_bytes", || {
        let decoded = deserialize_receipt(&extended)?;
        strict_verify(&decoded, elf, &journal)
    })?);
    for label in [
        "first_seal_tamper",
        "last_seal_tamper",
        "wrong_hash_profile",
        "wrong_verifier_parameters",
    ] {
        let mut changed = receipt.clone();
        let InnerReceipt::Composite(composite) = &mut changed.inner else {
            unreachable!()
        };
        if label == "last_seal_tamper" {
            *composite
                .segments
                .last_mut()
                .context("no last segment")?
                .seal
                .last_mut()
                .context("empty seal")? ^= 1;
        } else if label == "first_seal_tamper" {
            // Keep the complete fixed header and dimensions well-formed.
            composite.segments[0].seal[100] ^= 1;
        } else if label == "wrong_hash_profile" {
            composite.segments[0].hashfn = "sha-256".to_owned();
        } else {
            composite.segments[0].verifier_parameters = [0u32; 8].into();
        }
        cases.push(rejection(label, || strict_verify(&changed, elf, &journal))?);
    }
    let fake = Receipt::new(
        InnerReceipt::Fake(risc0_zkvm::FakeReceipt::new(receipt.claim()?)),
        journal.clone(),
    );
    cases.push(rejection("fake_receipt_refused", || {
        strict_verify(&fake, elf, &journal)
    })?);
    // This is intentionally an unsupported test object, not a generated proof.
    let groth16 = Receipt::new(
        InnerReceipt::Groth16(risc0_zkvm::Groth16Receipt::new(
            Vec::new(),
            receipt.claim()?,
            [0u32; 8].into(),
        )),
        journal.clone(),
    );
    cases.push(rejection("groth16_kind_refused", || {
        strict_verify(&groth16, elf, &journal)
    })?);
    println!(
        "{}",
        serde_json::json!({"schema":"pon-w1-risc0-research-v1","operation":"audit","real_proof_positive_control":true,"negative_cases":cases,"native_w1_recomputed":false,"public_ingress_qualified":false,"consensus_authority":false})
    );
    Ok(())
}

fn require_pinned_image(elf: &[u8]) -> Result<()> {
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("../../backend-manifest.json"))?;
    let expected = manifest["guest_image_id"]
        .as_str()
        .context("no reviewed guest image is pinned; execution/proof acceptance is disabled")?;
    if compute_image_id(elf)?.to_string() != expected {
        return Err(BoundaryError::Refused("unsupported full-W1 guest image").into());
    }
    Ok(())
}

fn main() -> Result<()> {
    ensure!(
        std::env::var_os("RISC0_DEV_MODE").is_none(),
        "unset RISC0_DEV_MODE; this driver never accepts development receipts"
    );
    let args: Vec<_> = std::env::args().collect();
    ensure!(args.len() >= 2, "expected execute, prove or verify");
    if args[1] == "bake" {
        ensure!(args.len() == 4, "bake <raw-guest-elf> <new-program-binary>");
        let raw_elf = bounded_read(Path::new(&args[2]), MAX_ELF_BYTES)?;
        let program =
            risc0_binfmt::ProgramBinary::new(&raw_elf, risc0_zkos_v1compat::V1COMPAT_ELF).encode();
        let image_id = compute_image_id(&program)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&args[3])?;
        output.write_all(&program)?;
        output.sync_all()?;
        println!("{{\"schema\":\"pon-w1-risc0-research-v1\",\"operation\":\"bake\",\"program_bytes\":{},\"image_id\":\"{}\",\"cryptographic_proof_verified\":false,\"consensus_authority\":false}}", program.len(), image_id);
        return Ok(());
    }
    if args[1] == "verify" || args[1] == "audit" {
        ensure!(args.len() == 5, "verify <elf> <fixed-input> <receipt>");
        let elf = bounded_read(Path::new(&args[2]), MAX_ELF_BYTES)?;
        require_pinned_image(&elf)?;
        let input = bounded_read(Path::new(&args[3]), full_relation::INPUT_BYTES)?;
        let expected_journal =
            full_relation::unverified_claimed_journal(&input).map_err(|e| anyhow!("{e:?}"))?;
        let statement =
            full_relation::PublicStatement::decode(&input[..full_relation::STATEMENT_BYTES])
                .map_err(|e| anyhow!("{e:?}"))?;
        let encoded = bounded_read(Path::new(&args[4]), MAX_RECEIPT_BYTES)?;
        let started = Instant::now();
        let receipt = deserialize_receipt(&encoded)?;
        if args[1] == "audit" {
            return audit_receipt(&receipt, &elf, &input, &encoded);
        }
        strict_verify(&receipt, &elf, &expected_journal)?;
        println!("{{\"schema\":\"pon-w1-risc0-research-v1\",\"operation\":\"verify\",\"real_composite_stark_verified\":true,\"receipt_bytes\":{},\"verify_wall_ns\":{},\"image_id\":\"{}\",\"statement_id\":\"{}\",\"native_w1_recomputed\":false,\"consensus_authority\":false}}", encoded.len(), started.elapsed().as_nanos(), compute_image_id(&elf)?, hex::encode(statement.statement_id()));
        return Ok(());
    }
    let prove = args[1] == "prove";
    ensure!(
        prove || args[1] == "execute",
        "expected execute, prove or verify"
    );
    ensure!(args.len() == if prove { 7 } else { 6 }, "execute <r0vm> <elf> <fixed-input> <segment-po2>; prove additionally requires a new receipt output path");
    let elf = bounded_read(Path::new(&args[3]), MAX_ELF_BYTES)?;
    require_pinned_image(&elf)?;
    let input = bounded_read(Path::new(&args[4]), full_relation::INPUT_BYTES)?;
    let expected = full_relation::execute_input(&input).map_err(|e| anyhow!("{e:?}"))?;
    let po2: u32 = args[5].parse().context("segment power")?;
    let prover = ExternalProver::new("pinned-local-r0vm", &args[2]);
    let started = Instant::now();
    if !prove {
        let session = prover.execute(environment(&input, po2)?, &elf)?;
        ensure!(
            session.journal.bytes == expected.journal(),
            "guest/native full-relation journal mismatch"
        );
        let execute_ns = started.elapsed().as_nanos();
        let mut histogram = BTreeMap::<u32, usize>::new();
        for segment in &session.segments {
            *histogram.entry(segment.po2).or_default() += 1;
        }
        println!(
            "{}",
            serde_json::json!({"schema":"pon-w1-risc0-research-v1",
            "operation":"execute", "guest_matches_native":true,
            "journal_hex":hex::encode(&session.journal.bytes), "user_cycles":session.cycles(),
            "segments":session.segments.len(), "segment_po2_limit":po2,
            "actual_segment_po2_histogram":histogram, "execute_wall_ns":execute_ns,
            "image_id":compute_image_id(&elf)?.to_string(),
            "cryptographic_proof_verified":false, "consensus_authority":false})
        );
        return Ok(());
    }
    // No default backend selection, remote proving, recursion or elliptic-curve
    // wrapper. The only backend is the explicitly supplied local r0vm binary.
    let options = ProverOpts::default()
        .with_dev_mode(false)
        .with_hashfn("poseidon2".to_owned())
        .with_receipt_kind(ReceiptKind::Composite);
    let context = VerifierContext::default().with_dev_mode(false);
    let info = prover.prove_with_ctx(environment(&input, po2)?, &context, &elf, &options)?;
    let prove_ns = started.elapsed().as_nanos();
    let encoded = bincode::serialize(&info.receipt)?;
    ensure!(
        encoded.len() <= MAX_RECEIPT_BYTES,
        "receipt exceeds research byte cap"
    );
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[6])?;
    output.write_all(&encoded)?;
    output.sync_all()?;
    // Retain a bounded returned candidate even if our stricter profile checks
    // fail. File existence is never an authentication or a successful result.
    // The SDK already verified integrity in prove_with_ctx; failures before it
    // returns still have only their process/log evidence.
    receipt_bounds::preflight(&encoded)?;
    let verify_started = Instant::now();
    strict_verify(&info.receipt, &elf, &expected.journal())?;
    let verify_ns = verify_started.elapsed().as_nanos();
    println!("{{\"schema\":\"pon-w1-risc0-research-v1\",\"operation\":\"prove\",\"real_composite_stark_verified\":true,\"user_cycles\":{},\"total_cycles\":{},\"segments\":{},\"segment_po2_limit\":{},\"prove_including_execution_and_integrity_verify_wall_ns\":{},\"additional_verify_wall_ns\":{},\"receipt_bytes\":{},\"image_id\":\"{}\",\"statement_id\":\"{}\",\"independent_hashcash\":false,\"consensus_authority\":false}}", info.stats.user_cycles, info.stats.total_cycles, info.stats.segments, po2, prove_ns, verify_ns, encoded.len(), compute_image_id(&elf)?, hex::encode(expected.statement_id()));
    Ok(())
}
