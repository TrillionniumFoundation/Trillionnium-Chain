//! Guest-execution controls, separate from invalid cryptographic receipt tests.
//! A native error cannot stand in for running the unchanged real guest.
use super::{bounded_read, environment, require_pinned_image, MAX_ELF_BYTES};
use anyhow::{anyhow, ensure, Result};
use risc0_zkvm::{Executor, ExternalProver};
use std::{fs::OpenOptions, io::Write, path::Path, time::Instant};
use trnm_w1_guest_relation::{full_relation, WorkError, CELLS, Q};

fn expected_error(case: &str) -> Result<full_relation::RelationError> {
    Ok(full_relation::RelationError::Work(match case {
        "correct-product-false-trace" => WorkError::Transcript,
        "correct-trace-wrong-product" => WorkError::Product,
        _ => anyhow::bail!("unsupported fixed full-W1 negative case"),
    }))
}

fn changed_input(input: &[u8], case: &str) -> Result<Vec<u8>> {
    // This positive native control runs only while preparing a public fixture,
    // outside the separately measured guest rejection command.
    full_relation::execute_input(input).map_err(|error| anyhow!("positive input: {error:?}"))?;
    let statement =
        full_relation::PublicStatement::decode(&input[..full_relation::STATEMENT_BYTES])
            .map_err(|error| anyhow!("{error:?}"))?;
    let mut witness = input[full_relation::STATEMENT_BYTES..].to_vec();
    match case {
        "correct-product-false-trace" => {
            *witness.last_mut().expect("fixed PNW1 witness") ^= 1;
        }
        "correct-trace-wrong-product" => {
            let offset = 4 + 2 * CELLS * 4;
            let word = u32::from_le_bytes(witness[offset..offset + 4].try_into()?);
            let changed = ((u128::from(word) + 1) % Q) as u32;
            witness[offset..offset + 4].copy_from_slice(&changed.to_le_bytes());
        }
        _ => anyhow::bail!("unsupported fixed full-W1 negative case"),
    }
    // Rebind the entire public witness commitment. These must reach the real
    // late transcript/product failure, not stop at a stale commitment hash.
    let rebound = full_relation::PublicStatement::bind(
        statement.header_bytes(),
        statement.expected_task(),
        statement.expected_target(),
        &witness,
    )
    .map_err(|error| anyhow!("{error:?}"))?;
    let mut changed = rebound.encode().to_vec();
    changed.extend_from_slice(&witness);
    ensure!(
        full_relation::execute_input(&changed).unwrap_err() == expected_error(case)?,
        "fixture did not reach its exact native late failure"
    );
    Ok(changed)
}

pub fn make_invalid(args: &[String]) -> Result<()> {
    ensure!(
        args.len() == 5,
        "make-invalid <valid-input> <case> <new-output>"
    );
    let input = bounded_read(Path::new(&args[2]), full_relation::INPUT_BYTES)?;
    let changed = changed_input(&input, &args[3])?;
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[4])?;
    out.write_all(&changed)?;
    out.sync_all()?;
    println!(
        "{}",
        serde_json::json!({"schema":"pon-w1-guest-negative-v1",
        "operation":"make-invalid","case":args[3],"input_bytes":changed.len(),
        "expected_error":format!("{:?}", expected_error(&args[3])?),
        "native_late_failure_checked":true,"witness_commitment_rebound":true,
        "guest_executed":false,"cryptographic_proof_generated":false,
        "consensus_authority":false})
    );
    Ok(())
}

pub fn reject_input(args: &[String]) -> Result<()> {
    ensure!(
        args.len() == 7,
        "reject-input <r0vm> <elf> <invalid-input> <segment-po2> <case>"
    );
    let elf = bounded_read(Path::new(&args[3]), MAX_ELF_BYTES)?;
    require_pinned_image(&elf)?;
    let input = bounded_read(Path::new(&args[4]), full_relation::INPUT_BYTES)?;
    ensure!(
        input.len() == full_relation::INPUT_BYTES,
        "incorrect fixed W1 input length"
    );
    let po2 = args[5].parse()?;
    let expected = expected_error(&args[6])?;
    let prover = ExternalProver::new("pinned-local-r0vm", &args[2]);
    let started = Instant::now();
    // Deliberately no native execute_input call or native fallback on this path.
    // An IPC error, timeout or unavailable backend is not a successful rejection.
    let error = prover
        .execute(environment(&input, po2)?, &elf)
        .err()
        .ok_or_else(|| anyhow!("invalid W1 input unexpectedly completed guest execution"))?;
    let elapsed = started.elapsed().as_nanos();
    let actual = format!("{error:#}");
    let expected_panic = format!("complete W1 relation: {expected:?}");
    ensure!(
        actual.contains("Guest panicked:") && actual.contains(&expected_panic),
        "guest did not report the exact expected relation failure: {actual}"
    );
    println!(
        "{}",
        serde_json::json!({"schema":"pon-w1-guest-negative-v1",
        "operation":"reject-input","case":args[6],"input_bytes":input.len(),
        "expected_error":format!("{expected:?}"),"actual_guest_error":actual,
        "guest_executed":true,"exact_guest_relation_rejection":true,
        "native_w1_recomputed":false,"guest_reject_wall_ns":elapsed,
        "segment_po2_limit":po2,"cryptographic_proof_generated":false,
        "invalid_proof_rejection_measured":false,"consensus_authority":false})
    );
    Ok(())
}
