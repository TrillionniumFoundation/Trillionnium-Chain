//! Typed late-fold mutation controls for the pinned P3 0.8.0 proof format.
//!
//! This program writes an intentionally changed proof; it does not verify it.
//! A P3 0.8.0 round shares a multiproof across all queries. Consequently a
//! last-query value and a shared authentication digest are distinct controls.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use bincode::Options;
use p3_field::PrimeCharacteristicRing;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use w1_full_public_stark_research::proof_config::{Challenge, NUM_QUERIES, Val, W1Proof};

const MAX_PROOF_BYTES: usize = 64 * 1024 * 1024;
const SHA_MAGIC: &[u8; 8] = b"W1P3SHA1";
const ARITH_MAGIC: &[u8; 8] = b"W1P3ARI1";

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn codec() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit((MAX_PROOF_BYTES - 8) as u64)
        .reject_trailing_bytes()
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    codec()
        .serialize(value)
        .map_err(|e| format!("encoding: {e}"))
}

fn read_input(path: &Path) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|e| format!("open input: {e}"))?;
    let size = file.metadata().map_err(|e| e.to_string())?.len();
    if !(8..=MAX_PROOF_BYTES as u64).contains(&size) {
        return Err("input proof envelope length".into());
    }
    let mut bytes = Vec::with_capacity(size as usize);
    file.take(MAX_PROOF_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() != size as usize || bytes.len() > MAX_PROOF_BYTES {
        return Err("input changed during bounded read".into());
    }
    Ok(bytes)
}

fn decode(bytes: &[u8]) -> Result<(W1Proof, &'static str, usize), String> {
    let (component, degree_bits) = if bytes.starts_with(SHA_MAGIC) {
        ("sha", 13)
    } else if bytes.starts_with(ARITH_MAGIC) {
        ("arithmetic", 17)
    } else {
        return Err("unknown proof envelope".into());
    };
    let proof = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        codec().deserialize::<W1Proof>(&bytes[8..])
    }))
    .map_err(|_| "proof decode panic contained".to_owned())?
    .map_err(|e| format!("proof decoding: {e}"))?;
    if proof.degree_bits != degree_bits {
        return Err("unexpected fixed trace degree".into());
    }
    if encode(&proof)? != bytes[8..] {
        return Err("input proof is not canonical for the frozen codec".into());
    }
    let fri = &proof.opening_proof;
    if fri.commit_phase_commits.len() != degree_bits
        || fri.commit_pow_witnesses.len() != degree_bits
        || fri.commit_phase_openings.len() != degree_bits
        || fri.final_poly.len() != 1
    {
        return Err("unexpected fixed FRI round/final-polynomial shape".into());
    }
    if fri.commit_phase_openings.iter().any(|round| {
        round.sibling_values.len() != NUM_QUERIES
            || round.sibling_values.iter().any(|query| query.len() != 1)
    }) {
        return Err("unexpected fixed 64-query binary-fold shape".into());
    }
    Ok((proof, component, degree_bits))
}

/// All proof-carried values observed before the FRI query responses. The
/// statement and independently supplied expected inputs must also be kept
/// unchanged by the caller. Query response values themselves are not absorbed.
fn transcript_fields(proof: &W1Proof) -> Result<Vec<u8>, String> {
    let fri = &proof.opening_proof;
    encode(&(
        &proof.commitments,
        &proof.opened_values,
        proof.degree_bits,
        proof.ood_pow_witness,
        &fri.batch_pow_witness,
        &fri.commit_phase_commits,
        &fri.commit_pow_witnesses,
        &fri.final_poly,
        &fri.query_pow_witness,
    ))
}

fn mutate_last_fold_query_value(proof: &mut W1Proof) -> Result<Value, String> {
    let round_index = proof.opening_proof.commit_phase_openings.len() - 1;
    let round = &mut proof.opening_proof.commit_phase_openings[round_index];
    let query_index = round.sibling_values.len() - 1;
    let value_index = round.sibling_values[query_index].len() - 1;
    let value = &mut round.sibling_values[query_index][value_index];
    let before = encode(value)?;
    *value += Challenge::ONE;
    let after = encode(value)?;
    Ok(json!({
        "typed_path": format!("opening_proof.commit_phase_openings[{round_index}].sibling_values[{query_index}][{value_index}]"),
        "round_index_zero_based": round_index,
        "query_index_zero_based": query_index,
        "sibling_value_index_zero_based": value_index,
        "field_encoding_before_hex": hex::encode(before),
        "field_encoding_after_hex": hex::encode(after),
        "control_scope": "last fold of the last query; the verifier walks all query fold chains and final-polynomial checks before commit-phase MMCS authentication; actual rejection subtype must be observed"
    }))
}

fn mutate_last_fold_auth_sibling(proof: &mut W1Proof) -> Result<Value, String> {
    let sibling_hash_counts: Vec<usize> = proof
        .opening_proof
        .commit_phase_openings
        .iter()
        .map(|round| round.opening_proof.sibling_hashes.len())
        .collect();
    let round_index = sibling_hash_counts
        .iter()
        .rposition(|&count| count != 0)
        .ok_or("no external authentication digest in any FRI round")?;
    let round = &mut proof.opening_proof.commit_phase_openings[round_index];
    let sibling_hash_index = round.opening_proof.sibling_hashes.len() - 1;
    let digest_element_index = round.opening_proof.sibling_hashes[sibling_hash_index].len() - 1;
    let value = &mut round.opening_proof.sibling_hashes[sibling_hash_index][digest_element_index];
    let before = encode(value)?;
    *value += Val::ONE;
    let after = encode(value)?;
    Ok(json!({
        "typed_path": format!("opening_proof.commit_phase_openings[{round_index}].opening_proof.sibling_hashes[{sibling_hash_index}][{digest_element_index}]"),
        "round_index_zero_based": round_index,
        "query_index_zero_based": Value::Null,
        "sibling_hash_index_zero_based": sibling_hash_index,
        "digest_element_index_zero_based": digest_element_index,
        "sibling_hash_counts_by_round": sibling_hash_counts,
        "field_encoding_before_hex": hex::encode(before),
        "field_encoding_after_hex": hex::encode(after),
        "control_scope": "last round with external authentication digests, last shared digest, last field element; this is a shared multiproof frontier, not an independent path for the last query"
    }))
}

fn run(args: &[String]) -> Result<Value, String> {
    if args.len() != 3 {
        return Err("usage: mutate_last_query MODE INPUT_PROOF OUTPUT_PROOF".into());
    }
    let original = read_input(Path::new(&args[1]))?;
    let (mut proof, component, degree_bits) = decode(&original)?;
    let before_transcript = transcript_fields(&proof)?;
    let mutation = match args[0].as_str() {
        "last-fold-query-value" => mutate_last_fold_query_value(&mut proof)?,
        "last-fold-auth-sibling" => mutate_last_fold_auth_sibling(&mut proof)?,
        _ => return Err("unsupported mutation mode".into()),
    };
    let after_transcript = transcript_fields(&proof)?;
    if before_transcript != after_transcript {
        return Err("mutation unexpectedly changed transcript-bound fields".into());
    }
    let payload = encode(&proof)?;
    let mut changed = original[..8].to_vec();
    changed.extend_from_slice(&payload);
    if changed.len() != original.len() || changed == original {
        return Err("mutation must change a value while preserving the wire length".into());
    }
    let changed_byte_count = changed
        .iter()
        .zip(&original)
        .filter(|(a, b)| a != b)
        .count();
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[2])
        .map_err(|e| format!("create output: {e}"))?;
    output.write_all(&changed).map_err(|e| e.to_string())?;
    output.sync_all().map_err(|e| e.to_string())?;
    Ok(json!({
        "status": "MUTATED_RESEARCH_PROOF_ONLY",
        "qualification": "HOLD_NO_GO",
        "mode": args[0],
        "component": component,
        "degree_bits": degree_bits,
        "queries": NUM_QUERIES,
        "input": args[1],
        "output": args[2],
        "proof_bytes_before": original.len(),
        "proof_bytes_after": changed.len(),
        "proof_sha256_before": digest(&original),
        "proof_sha256_after": digest(&changed),
        "changed_byte_count": changed_byte_count,
        "transcript_fields_unchanged": true,
        "transcript_fields_sha256": digest(&before_transcript),
        "public_and_expected_inputs_must_remain_unchanged": true,
        "retained_verifier_order": "input multiproofs; all 64 query fold chains and final-polynomial checks; shared commit-phase authentication in round order",
        "cost_scope": "one controlled path only; last nonempty multiproof round is not a global worst-case rejection bound",
        "verification_pending": true,
        "mutation": mutation
    }))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(value) => println!("{value}"),
        Err(error) => {
            println!(
                "{}",
                json!({"status":"MUTATION_FAILED", "qualification":"HOLD_NO_GO", "error":error})
            );
            std::process::exit(1);
        }
    }
}
