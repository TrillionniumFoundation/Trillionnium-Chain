//! Paired real-proof comparisons. The reference keeps the SDK's original
//! authentication-before-public-claim order; it grants no alternate acceptance.
use super::prepared_verifier::{PreparedVerifier, Progress};
use super::{audit_one, claimed_context, deserialize_receipt};
use anyhow::{ensure, Context, Result};
use risc0_binfmt::Digestible;
use risc0_zkvm::sha::{Digest, Impl, Sha256};
use risc0_zkvm::{ExitCode, InnerReceipt, MaybePruned, Receipt};
use serde_json::{json, Value};
use std::time::Instant;

const CASES: &[&str] = &[
    "valid",
    "outer_journal_rebound",
    "late_link_tamper",
    "late_nonfinal_exit",
    "matching_claims_corrupt_seal",
    "coordinated_public_claim_forgery",
];

fn sha(bytes: &[u8]) -> String {
    Impl::hash_bytes(bytes).to_string()
}

fn mutation(case: &str, original: &Receipt, input: &[u8]) -> Result<(Receipt, Vec<u8>)> {
    let mut receipt = original.clone();
    let mut input = input.to_vec();
    if matches!(
        case,
        "outer_journal_rebound" | "coordinated_public_claim_forgery"
    ) {
        input[188] ^= 1;
        receipt.journal.bytes = claimed_context::prepare(&input)?.1;
    }
    let InnerReceipt::Composite(composite) = &mut receipt.inner else {
        unreachable!()
    };
    ensure!(
        composite.segments.len() >= 2,
        "claim audit requires a real multi-segment receipt"
    );
    match case {
        "valid" | "outer_journal_rebound" => {}
        "late_link_tamper" => {
            let pre = &mut composite.segments.last_mut().unwrap().claim.pre;
            match pre {
                MaybePruned::Value(state) => state.merkle_root = Digest::from([u32::MAX; 8]),
                MaybePruned::Pruned(digest) => *digest = Digest::from([u32::MAX; 8]),
            }
        }
        "late_nonfinal_exit" => {
            let index = composite.segments.len() - 2;
            composite.segments[index].claim.exit_code = ExitCode::Halted(0);
        }
        "matching_claims_corrupt_seal" => {
            *composite
                .segments
                .last_mut()
                .unwrap()
                .seal
                .last_mut()
                .context("empty real seal")? ^= 1;
        }
        "coordinated_public_claim_forgery" => {
            let last = &mut composite.segments.last_mut().unwrap().claim;
            let mut output = last
                .output
                .as_value()?
                .clone()
                .context("real terminal output missing")?;
            output.journal = MaybePruned::Pruned(receipt.journal.digest::<Impl>());
            last.output = Some(output).into();
        }
        _ => unreachable!(),
    }
    Ok((receipt, input))
}

fn receive(
    elf: &[u8],
    shared: &PreparedVerifier,
    bytes: &[u8],
    journal: &[u8],
    reference: bool,
    reuse: bool,
) -> Result<Value> {
    let started = Instant::now();
    let setup = Instant::now();
    let owned = if reuse {
        None
    } else {
        Some(PreparedVerifier::new(elf)?)
    };
    let setup_ns = if reuse {
        None
    } else {
        Some(setup.elapsed().as_nanos())
    };
    let verifier = owned.as_ref().unwrap_or(shared);
    let decode = Instant::now();
    let receipt = deserialize_receipt(bytes)?;
    let decode_ns = decode.elapsed().as_nanos();
    let verifying = Instant::now();
    let mut progress = Progress::default();
    let result = if reference {
        verifier.reference_traced(&receipt, journal, &mut progress)
    } else {
        verifier.verify_traced(&receipt, journal, &mut progress)
    };
    let verify_ns = verifying.elapsed().as_nanos();
    let dropping = Instant::now();
    drop(receipt);
    drop(owned);
    let drop_ns = dropping.elapsed().as_nanos();
    let total_ns = started.elapsed().as_nanos();
    Ok(
        json!({"route":if reference {"original_sdk_order"} else {"public_claims_first"},
        "context":if reuse {"reused"} else {"fresh"}, "accepted":result.is_ok(),
        "public_claims_entered":progress.public_claims_entered, "sdk_entered":progress.sdk_entered,
        "context_setup_wall_ns":setup_ns, "bounded_decode_wall_ns":decode_ns,
        "verification_wall_ns":verify_ns, "owned_objects_drop_wall_ns":drop_ns,
        "receiver_total_wall_ns":total_ns, "reason":result.err().map(|error| error.to_string())}),
    )
}

pub(super) fn run(elf: &[u8], input: &[u8], encoded: &[u8]) -> Result<()> {
    let setup = Instant::now();
    let shared = PreparedVerifier::new(elf)?;
    let setup_ns = setup.elapsed().as_nanos();
    let (statement, original_journal) = claimed_context::prepare(input)?;
    let positive = Instant::now();
    let receipt = deserialize_receipt(encoded)?;
    shared.verify(&receipt, &original_journal)?;
    let positive_ns = positive.elapsed().as_nanos();
    let mut cases = Vec::new();
    for (index, case) in CASES.iter().enumerate() {
        let (changed, changed_input) = mutation(case, &receipt, input)?;
        let changed_bytes = bincode::serialize(&changed)?;
        drop(changed);
        let (_, journal) = claimed_context::prepare(&changed_input)?;
        let public_consistent = matches!(
            *case,
            "valid" | "matching_claims_corrupt_seal" | "coordinated_public_claim_forgery"
        );
        let mut routes = Vec::new();
        // Alternate route ordering; this is not an exclusive or cold-cache host.
        for reuse in [false, true] {
            for reference in if index % 2 == 0 {
                [true, false]
            } else {
                [false, true]
            } {
                let row = receive(elf, &shared, &changed_bytes, &journal, reference, reuse)?;
                ensure!(
                    row["accepted"].as_bool() == Some(*case == "valid"),
                    "paired proof outcome differs: {case}"
                );
                ensure!(
                    row["sdk_entered"].as_bool() == Some(reference || public_consistent),
                    "unexpected SDK frontier: {case}"
                );
                ensure!(
                    row["public_claims_entered"].as_bool() == Some(!reference),
                    "missing public-claim check: {case}"
                );
                routes.push(row);
            }
        }
        cases.push(json!({"case":case, "input_sha256":sha(&changed_input),
            "receipt_sha256":sha(&changed_bytes), "receipt_bytes":changed_bytes.len(),
            "expected_journal_sha256":sha(&journal), "public_claims_consistent":public_consistent,
            "observations":routes}));
    }
    println!(
        "{}",
        json!({"schema":"pon-w1-public-claim-cost-audit-v1", "operation":"audit-claims",
        "prepared_context_setup_wall_ns":setup_ns, "positive_prerequisite_wall_ns":positive_ns,
        "real_proof_positive_control":true, "prerequisite_warms_runtime":true,
        "fresh_context_does_not_mean_cold_hardware":true, "exclusive_host":false,
        "receiver_scope":"optional-context-setup/bounded-decode/strict-profile/public-claims-if-selected/full-sdk-if-reached/owned-drop",
        "excluded_from_receiver_timing":["file-io","statement-binding","positive-prerequisite","case-construction","source-and-byte-hashes","error-formatting","json-output","process-startup"],
        "original_input_sha256":sha(input), "original_receipt_sha256":sha(encoded),
        "original_receipt_bytes":encoded.len(), "original_statement_id":hex::encode(statement.statement_id()),
        "image_id":shared.image().to_string(), "source_inputs":audit_one::source_inputs(), "cases":cases,
        "resource_caps":{"receipt_bytes":super::receipt_bounds::MAX_RECEIPT_BYTES,
          "segments":super::receipt_bounds::MAX_SEGMENTS,"seal_words":super::receipt_bounds::MAX_SEAL_WORDS,
          "padded_cycles":super::receipt_bounds::MAX_PADDED_CYCLES,"journal_bytes":super::receipt_bounds::JOURNAL_BYTES,
          "elf_bytes":super::MAX_ELF_BYTES,"input_bytes":trnm_w1_guest_relation::full_relation::INPUT_BYTES},
        "new_proof_generated":false, "minimum_work_cost_proved":false, "public_ingress_qualified":false,
        "pq_128_security_qualified":false, "worst_case_rejection_cost_closed":false, "consensus_authority":false})
    );
    Ok(())
}
