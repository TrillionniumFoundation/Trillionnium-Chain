//! A fixed real-receipt case, measured from encoded bytes through decoded drop.
//! Metadata hashing, case construction and the real positive prerequisite are
//! outside receiver timing. This path creates no admission or work authority.
use super::{claimed_context, deserialize_receipt, receipt_bounds, strict_verify};
use anyhow::{anyhow, ensure, Context, Result};
use risc0_zkvm::sha::Sha256;
use risc0_zkvm::{compute_image_id, InnerReceipt, Receipt};
use serde_json::{json, Value};
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    Valid,
    FirstSeal,
    LastSeal,
    Parameters,
    Miner,
    Truncated,
    Trailing,
    LengthBomb,
}

impl Case {
    fn parse(name: &str) -> Result<Self> {
        match name {
            "valid" => Ok(Self::Valid),
            "first_seal_tamper" => Ok(Self::FirstSeal),
            "last_seal_tamper" => Ok(Self::LastSeal),
            "wrong_verifier_parameters" => Ok(Self::Parameters),
            "wrong_statement_miner" => Ok(Self::Miner),
            "truncated_receipt" => Ok(Self::Truncated),
            "trailing_receipt_bytes" => Ok(Self::Trailing),
            "seal_length_allocation_bomb" => Ok(Self::LengthBomb),
            _ => Err(anyhow!("unsupported audit-one case")),
        }
    }
}

fn sha(bytes: &[u8]) -> String {
    risc0_zkvm::sha::Impl::hash_bytes(bytes).to_string()
}

fn source_inputs() -> Value {
    const PREFIX: &str = "trillionnium/crates/trnm-crypto-primitives/";
    let inputs: &[(&str, &[u8])] = &[
        (
            "guests/w1-risc0/host/src/main.rs",
            include_bytes!("main.rs"),
        ),
        (
            "guests/w1-risc0/host/src/claimed_context.rs",
            include_bytes!("claimed_context.rs"),
        ),
        (
            "guests/w1-risc0/host/src/audit_one.rs",
            include_bytes!("audit_one.rs"),
        ),
        (
            "guests/w1-risc0/host/src/receipt_bounds.rs",
            include_bytes!("receipt_bounds.rs"),
        ),
        (
            "guests/w1-risc0/host/src/phase_journal.rs",
            include_bytes!("phase_journal.rs"),
        ),
        (
            "src/pon_work/full_relation.rs",
            include_bytes!("../../../../src/pon_work/full_relation.rs"),
        ),
        (
            "guests/w1-risc0/relation/src/lib.rs",
            include_bytes!("../../relation/src/lib.rs"),
        ),
        (
            "guests/w1-risc0/relation/src/parameters.rs",
            include_bytes!("../../relation/src/parameters.rs"),
        ),
        (
            "guests/w1-risc0/guest/src/main.rs",
            include_bytes!("../../guest/src/main.rs"),
        ),
        (
            "guests/w1-risc0/backend-manifest.json",
            include_bytes!("../../backend-manifest.json"),
        ),
        (
            "guests/w1-risc0/Cargo.toml",
            include_bytes!("../../Cargo.toml"),
        ),
        (
            "guests/w1-risc0/Cargo.lock",
            include_bytes!("../../Cargo.lock"),
        ),
        (
            "guests/w1-risc0/host/Cargo.toml",
            include_bytes!("../Cargo.toml"),
        ),
        (
            "guests/w1-risc0/relation/Cargo.toml",
            include_bytes!("../../relation/Cargo.toml"),
        ),
        (
            "guests/w1-risc0/guest/Cargo.toml",
            include_bytes!("../../guest/Cargo.toml"),
        ),
    ];
    Value::Array(inputs.iter().map(|(path, bytes)| {
        json!({"path":format!("{PREFIX}{path}"),"bytes":bytes.len(),"sha256":sha(bytes)})
    }).collect())
}

fn mutate(
    case: Case,
    receipt: &Receipt,
    encoded: &[u8],
    input: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut changed_input = input.to_vec();
    let mut changed = encoded.to_vec();
    match case {
        Case::Valid => {}
        Case::Miner => changed_input[38 + 150] ^= 1,
        Case::Truncated => {
            changed.pop().context("empty original receipt")?;
        }
        Case::Trailing => changed.push(0),
        Case::LengthBomb => changed[12..20].copy_from_slice(&u64::MAX.to_le_bytes()),
        Case::FirstSeal | Case::LastSeal | Case::Parameters => {
            let mut object = receipt.clone();
            let InnerReceipt::Composite(composite) = &mut object.inner else {
                return Err(anyhow!("positive receipt is not Composite"));
            };
            match case {
                Case::FirstSeal => {
                    *composite
                        .segments
                        .first_mut()
                        .context("no first segment")?
                        .seal
                        .get_mut(100)
                        .context("short first seal")? ^= 1;
                }
                Case::LastSeal => {
                    *composite
                        .segments
                        .last_mut()
                        .context("no last segment")?
                        .seal
                        .last_mut()
                        .context("empty last seal")? ^= 1;
                }
                Case::Parameters => {
                    composite
                        .segments
                        .first_mut()
                        .context("no first segment")?
                        .verifier_parameters = [0u32; 8].into();
                }
                _ => unreachable!(),
            }
            changed = bincode::serialize(&object)?;
        }
    }
    Ok((changed, changed_input))
}

fn difference(before: &[u8], after: &[u8]) -> Result<Value> {
    let mut differences = Vec::new();
    for (offset, (old, new)) in before.iter().zip(after).enumerate() {
        if old != new {
            ensure!(
                differences.len() < 32,
                "case changes more than the fixed mutation budget"
            );
            differences.push(json!({"offset":offset,"before":old,"after":new}));
        }
    }
    Ok(json!({"byte_changes":differences,"before_bytes":before.len(),"after_bytes":after.len()}))
}

fn receive(encoded: &[u8], elf: &[u8], journal: &[u8]) -> Value {
    let started = Instant::now();
    let decoding = Instant::now();
    let decoded = deserialize_receipt(encoded);
    let decode_ns = decoding.elapsed().as_nanos();
    let (result, verify_ns, drop_ns, last_stage) = match decoded {
        Ok(receipt) => {
            let verifying = Instant::now();
            let result = strict_verify(&receipt, elf, journal);
            let verify_ns = verifying.elapsed().as_nanos();
            let dropping = Instant::now();
            drop(receipt);
            (
                result,
                Some(verify_ns),
                Some(dropping.elapsed().as_nanos()),
                "strict_verify",
            )
        }
        Err(error) => (Err(error), None, None, "bounded_preflight_or_sdk_decode"),
    };
    let receiver_ns = started.elapsed().as_nanos();
    // Error formatting, source hashing and JSON serialization are not receiver costs.
    let (accepted, outcome, reason) = match result {
        Ok(()) => (true, "verified", None),
        Err(error) => {
            let outcome = match error.downcast_ref::<receipt_bounds::BoundaryError>() {
                Some(receipt_bounds::BoundaryError::Refused(_)) => "refused_not_evaluated",
                Some(receipt_bounds::BoundaryError::Malformed(_)) => "malformed_encoding",
                None => "verification_failed",
            };
            (false, outcome, Some(error.to_string()))
        }
    };
    json!({"accepted":accepted,"outcome":outcome,"reason":reason,"last_stage":last_stage,
           "bounded_preflight_and_sdk_decode_wall_ns":decode_ns,
           "strict_verify_wall_ns":verify_ns,"decoded_receipt_drop_wall_ns":drop_ns,
           "receiver_total_wall_ns":receiver_ns})
}

pub(super) fn run(elf: &[u8], input: &[u8], encoded: &[u8], name: &str) -> Result<()> {
    let case = Case::parse(name)?;
    let (statement, journal) = claimed_context::prepare(input)?;
    let prerequisite = Instant::now();
    let receipt = deserialize_receipt(encoded)?;
    strict_verify(&receipt, elf, &journal)?;
    let prerequisite_ns = prerequisite.elapsed().as_nanos();
    let construction = Instant::now();
    let (changed, changed_input) = mutate(case, &receipt, encoded, input)?;
    drop(receipt);
    let (_, changed_journal) = claimed_context::prepare(&changed_input)?;
    let construction_ns = construction.elapsed().as_nanos();
    let result = receive(&changed, elf, &changed_journal);
    ensure!(
        result["accepted"].as_bool() == Some(case == Case::Valid),
        "audit-one case did not reach its fixed expected outcome: {name}: {result}"
    );
    let shape = receipt_bounds::preflight(encoded)?;
    println!(
        "{}",
        json!({
            "schema":"pon-w1-receiver-case-v1","operation":"audit-one","case":name,
            "real_proof_positive_control":true,"positive_prerequisite_warms_verifier":true,
            "positive_prerequisite_wall_ns":prerequisite_ns,"case_construction_wall_ns":construction_ns,
            "receiver":result,"receiver_scope":"bounded-preflight/sdk-decode/strict-verify/decoded-drop",
            "excluded_from_receiver_timing":["file-io","positive-prerequisite","case-construction","source-and-byte-hashes","error-formatting","json-output","process-startup"],
            "original_input":{"bytes":input.len(),"sha256":sha(input)},
            "original_receipt":{"bytes":encoded.len(),"sha256":sha(encoded)},
            "case_input":{"bytes":changed_input.len(),"sha256":sha(&changed_input)},
            "case_receipt":{"bytes":changed.len(),"sha256":sha(&changed)},
            "input_mutation":difference(input,&changed_input)?,
            "receipt_mutation":difference(encoded,&changed)?,
            "original_shape":{"segments":shape.segments,"padded_cycles":shape.padded_cycles,"maximum_po2":shape.maximum_po2},
            "original_statement_id":hex::encode(statement.statement_id()),
            "case_expected_journal_sha256":sha(&changed_journal),"image_id":compute_image_id(elf)?.to_string(),
            "source_inputs":source_inputs(),
            "resource_caps":{"receipt_bytes":receipt_bounds::MAX_RECEIPT_BYTES,"segments":receipt_bounds::MAX_SEGMENTS,
                             "seal_words":receipt_bounds::MAX_SEAL_WORDS,"padded_cycles":receipt_bounds::MAX_PADDED_CYCLES,
                             "journal_bytes":receipt_bounds::JOURNAL_BYTES,"elf_bytes":super::MAX_ELF_BYTES,
                             "input_bytes":trnm_w1_guest_relation::full_relation::INPUT_BYTES},
            "native_w1_recomputed":false,"new_proof_generated":false,"minimum_work_cost_proved":false,
            "public_ingress_qualified":false,"pq_128_security_qualified":false,"consensus_authority":false
        })
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_metadata_matches_the_standard_empty_and_abc_vectors() {
        assert_eq!(
            sha(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn arbitrary_case_names_cannot_select_an_implicit_default() {
        for name in [
            "",
            "VALID",
            "valid ",
            "fake",
            "verify",
            "first_seal_tamper\0",
        ] {
            assert!(Case::parse(name).is_err());
        }
    }

    #[test]
    fn mutation_reporting_refuses_unbounded_changes() {
        assert!(difference(&[1; 33], &[2; 33]).is_err());
        assert_eq!(
            difference(b"abc", b"adc").unwrap()["byte_changes"][0]["offset"],
            1
        );
    }
}
