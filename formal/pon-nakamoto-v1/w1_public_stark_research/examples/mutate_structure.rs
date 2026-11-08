//! Create malformed shapes from an actually admitted full research proof.
//! This is a negative-control producer, not an alternative prover/verifier.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use bincode::Options;
use p3_field::PrimeCharacteristicRing;
use serde_json::json;
use sha2::{Digest, Sha256};
use w1_full_public_stark_research::proof_config::{Challenge, W1Proof};
use w1_full_public_stark_research::proof_wire::{Component, limits, scan_proof};

fn run(args: &[String]) -> Result<serde_json::Value, String> {
    if args.len() != 4 {
        return Err("mutate_structure COMPONENT MODE INPUT_PROOF OUTPUT_PROOF".into());
    }
    let component = match args[0].as_str() {
        "sha" => Component::Sha,
        "arithmetic" => Component::Arithmetic,
        "carry" => Component::Carry,
        "packed" => Component::PackedCarry,
        _ => return Err("component must be sha, arithmetic, carry or packed".into()),
    };
    let file = File::open(&args[2]).map_err(|e| e.to_string())?;
    let mut input = Vec::new();
    file.take(limits(component).maximum_bytes as u64 + 1)
        .read_to_end(&mut input)
        .map_err(|e| e.to_string())?;
    scan_proof(&input, component).map_err(|e| e.to_string())?;
    let codec = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(limits(component).maximum_bytes as u64);
    let mut proof: W1Proof = codec.deserialize(&input[8..]).map_err(|e| e.to_string())?;
    match args[1].as_str() {
        "trace-width-short" => {
            proof.opened_values.trace_local.pop();
        }
        "last-input-row-short" => {
            proof.opening_proof.input_openings[2].opened_values[63][0].pop();
        }
        "last-fold-extra-query" => {
            proof
                .opening_proof
                .commit_phase_openings
                .last_mut()
                .ok_or("missing fold")?
                .sibling_values
                .push(vec![Challenge::ZERO]);
        }
        "final-polynomial-extra" => {
            proof.opening_proof.final_poly.push(Challenge::ZERO);
        }
        _ => return Err("unsupported shape mutation".into()),
    }
    let mut output = input[..8].to_vec();
    output.extend(codec.serialize(&proof).map_err(|e| e.to_string())?);
    let error =
        scan_proof(&output, component).expect_err("mutation must fail structural admission");
    let path = Path::new(&args[3]);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.write_all(&output).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    Ok(json!({
        "schema":"w1-fixed-wire-mutation-v1","qualification":"HOLD_NO_GO",
        "component":args[0],"mode":args[1],
        "input_bytes":input.len(),"input_sha256":hex::encode(Sha256::digest(&input)),
        "output_bytes":output.len(),"output_sha256":hex::encode(Sha256::digest(&output)),
        "wire_refusal_offset":error.offset,"wire_refusal_reason":error.reason,
        "cryptographic_rejection_not_executed":true
    }))
}

fn main() {
    match run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        Ok(value) => println!("{value}"),
        Err(error) => {
            println!(
                "{}",
                json!({"status":"MUTATION_FAILED","error":error,"qualification":"HOLD_NO_GO"})
            );
            std::process::exit(1);
        }
    }
}
