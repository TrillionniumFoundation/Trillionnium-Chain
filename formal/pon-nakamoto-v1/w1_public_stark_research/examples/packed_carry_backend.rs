//! Complete public W1 carry-backend research comparison runner. Every verification rebuilds both AIRs and
//! preprocessing from bounded statement bytes and independent expectations.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::time::Instant;

use bincode::Options;
use p3_uni_stark::{prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use w1_full_public_stark_research::arith_carry_air::Dot8PackedCarryAir as Dot8CarryAir;
use w1_full_public_stark_research::proof_config::{
    PACKED_CARRY_COMPONENT, W1Proof, config, packed_carry_security_metadata as security_metadata,
};
use w1_full_public_stark_research::proof_wire::{Component, limits, scan_proof};
use w1_full_public_stark_research::public::{Expected, PUBLIC_BYTES, PublicStatement};
use w1_full_public_stark_research::sha_air::W1ShaAir;
use w1_full_public_stark_research::sha_plan::{HEADER_BYTES, INPUT_BYTES, PREFIX_BYTES};

const SCHEMA: &str = "trnm-w1-complete-public-packed-carry-stark-run-v3";
const MAX_PROOF_BYTES: usize = 64 * 1024 * 1024;
const SHA_MAGIC: &[u8; 8] = b"W1P3SHA1";
const ARITH_MAGIC: &[u8; 8] = b"W1P3APC3";

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn read_bounded(path: &Path, max: usize, exact: Option<usize>) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let size = file.metadata().map_err(|e| e.to_string())?.len();
    if size > max as u64 || exact.is_some_and(|n| size != n as u64) {
        return Err(format!("bounded file length {}: {size}", path.display()));
    }
    let mut bytes = Vec::with_capacity(size as usize);
    file.take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > max || exact.is_some_and(|n| bytes.len() != n) {
        return Err("file changed during bounded read".into());
    }
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("create {}: {e}", path.display()))?;
    out.write_all(bytes).map_err(|e| e.to_string())?;
    out.sync_all().map_err(|e| e.to_string())
}

fn expected(header: &str, artifacts: &str) -> Result<Expected, String> {
    let header = read_bounded(Path::new(header), HEADER_BYTES, Some(HEADER_BYTES))?;
    let artifacts = read_bounded(Path::new(artifacts), 64, Some(64))?;
    Expected::from_bytes(&header, &artifacts).map_err(str::to_owned)
}

fn load_statement(path: &str) -> Result<(Vec<u8>, PublicStatement), String> {
    let bytes = read_bounded(Path::new(path), PUBLIC_BYTES, Some(PUBLIC_BYTES))?;
    let statement = PublicStatement::decode(&bytes).map_err(str::to_owned)?;
    Ok((bytes, statement))
}

fn elapsed(phase: &str, start: Instant, timings: &mut Vec<Value>) {
    let event = json!({"phase":phase,"elapsed_ms":start.elapsed().as_secs_f64()*1000.0});
    println!("{event}");
    timings.push(event);
}

fn encode_proof(proof: &W1Proof, magic: &[u8; 8]) -> Result<Vec<u8>, String> {
    let encoded = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit((MAX_PROOF_BYTES - 8) as u64)
        .reject_trailing_bytes()
        .serialize(proof)
        .map_err(|e| format!("proof encoding: {e}"))?;
    if encoded.len() > MAX_PROOF_BYTES - 8 {
        return Err("proof exceeds envelope limit".into());
    }
    let mut bytes = Vec::with_capacity(8 + encoded.len());
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&encoded);
    Ok(bytes)
}

fn decode_admitted_proof(
    bytes: &[u8],
    magic: &[u8; 8],
    degree_bits: usize,
) -> Result<W1Proof, String> {
    if bytes.len() < 8 || bytes.len() > MAX_PROOF_BYTES || &bytes[..8] != magic {
        return Err("proof envelope".into());
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit((MAX_PROOF_BYTES - 8) as u64)
            .reject_trailing_bytes()
            .deserialize::<W1Proof>(&bytes[8..])
    }))
    .map_err(|_| "proof decode panic contained".to_owned())?;
    let proof = result.map_err(|e| format!("proof decoding: {e}"))?;
    if proof.degree_bits != degree_bits {
        return Err("proof trace degree".into());
    }
    Ok(proof)
}

fn prepare(args: &[String]) -> Result<Value, String> {
    if args.len() != 5 {
        return Err("prepare RAW PREFIX EXPECTED_HEADER EXPECTED_ARTIFACTS OUT_DIR".into());
    }
    let mut timings = Vec::new();
    let start = Instant::now();
    let raw = read_bounded(Path::new(&args[0]), INPUT_BYTES, Some(INPUT_BYTES))?;
    let prefix = read_bounded(Path::new(&args[1]), PREFIX_BYTES, Some(PREFIX_BYTES))?;
    let expected = expected(&args[2], &args[3])?;
    elapsed("fixture_and_expected_read", start, &mut timings);
    let start = Instant::now();
    let statement = PublicStatement::honest(raw, prefix)?;
    let bytes = statement.encode()?;
    elapsed("honest_public_witness_and_encoding", start, &mut timings);
    let start = Instant::now();
    let (sha, arith) = statement.plans(&expected)?;
    elapsed("canonical_relation_planning", start, &mut timings);
    let out = Path::new(&args[4]);
    fs::create_dir_all(out).map_err(|e| e.to_string())?;
    write_new(&out.join("statement.bin"), &bytes)?;
    Ok(
        json!({"status":"PUBLIC_WITNESS_PREPARED_NOT_PROVED", "statement_sha256":digest(&bytes),
        "public_bytes":bytes.len(), "hash_messages":sha.messages().len(),
        "sha_real_compressions":sha.real_compressions(),"arith_real_rows":arith.real_rows(),"timings":timings}),
    )
}

fn prove(args: &[String]) -> Result<Value, String> {
    if args.len() != 4 {
        return Err("prove PUBLIC EXPECTED_HEADER EXPECTED_ARTIFACTS OUT_DIR".into());
    }
    let mut timings = Vec::new();
    let start = Instant::now();
    let (public_bytes, statement) = load_statement(&args[0])?;
    let expected = expected(&args[1], &args[2])?;
    let (sha_plan, original_arith) = statement.plans(&expected)?;
    let arith = Dot8CarryAir::new(original_arith.rows().to_vec()).map_err(str::to_owned)?;
    drop(original_arith);
    elapsed("read_decode_and_canonical_plans", start, &mut timings);
    let out = Path::new(&args[3]);
    fs::create_dir_all(out).map_err(|e| e.to_string())?;
    let start = Instant::now();
    let sha = W1ShaAir::new(&sha_plan);
    elapsed("sha_air_and_chaining_witness", start, &mut timings);
    let start = Instant::now();
    let security = security_metadata(&sha, &arith);
    elapsed("actual_air_security_metadata", start, &mut timings);
    let sha_height = sha.trace_height();
    let arith_height = arith.trace_height();
    let sha_config = config(1);
    let start = Instant::now();
    let (sha_pp, _) = setup_preprocessed(&sha_config, &sha, sha_height.ilog2() as usize)
        .map_err(|e| format!("sha setup: {e:?}"))?
        .ok_or("missing sha preprocessing")?;
    elapsed("sha_prover_preprocessing_setup", start, &mut timings);
    let start = Instant::now();
    let trace = sha.generate_trace();
    elapsed("sha_trace_generation", start, &mut timings);
    let start = Instant::now();
    let proof = prove_with_preprocessed(&sha_config, &sha, trace, &[], Some(&sha_pp))
        .map_err(|e| format!("sha proof: {e:?}"))?;
    elapsed("sha_stark_prove", start, &mut timings);
    let start = Instant::now();
    let sha_bytes = encode_proof(&proof, SHA_MAGIC)?;
    write_new(&out.join("sha.proof.bin"), &sha_bytes)?;
    elapsed("sha_proof_serialize_and_persist", start, &mut timings);
    drop(proof);
    drop(sha_pp);
    drop(sha);
    let arith_config = config(PACKED_CARRY_COMPONENT);
    let start = Instant::now();
    let (arith_pp, _) = setup_preprocessed(&arith_config, &arith, arith_height.ilog2() as usize)
        .map_err(|e| format!("arith setup: {e:?}"))?
        .ok_or("missing arithmetic preprocessing")?;
    elapsed("arith_prover_preprocessing_setup", start, &mut timings);
    let start = Instant::now();
    let trace = arith.generate_trace();
    elapsed("arith_trace_generation", start, &mut timings);
    let start = Instant::now();
    let proof = prove_with_preprocessed(&arith_config, &arith, trace, &[], Some(&arith_pp))
        .map_err(|e| format!("arithmetic proof: {e:?}"))?;
    elapsed("arith_stark_prove", start, &mut timings);
    let start = Instant::now();
    let arith_bytes = encode_proof(&proof, ARITH_MAGIC)?;
    write_new(&out.join("arith.proof.bin"), &arith_bytes)?;
    elapsed("arith_proof_serialize_and_persist", start, &mut timings);
    let summary = json!({"status":"TWO_REAL_STARK_PROOFS_GENERATED_NOT_YET_VERIFIED",
        "statement_sha256":digest(&public_bytes), "public_bytes":public_bytes.len(),
        "sha_proof_bytes":sha_bytes.len(),"sha_proof_sha256":digest(&sha_bytes),
        "arith_proof_bytes":arith_bytes.len(),"arith_proof_sha256":digest(&arith_bytes),
        "sha_trace_height":sha_height,"arith_trace_height":arith_height,
        "security":security,"timings":timings});
    write_new(
        &out.join("prover_report.json"),
        &serde_json::to_vec_pretty(&summary).map_err(|e| e.to_string())?,
    )?;
    Ok(summary)
}

fn verify(args: &[String]) -> Result<Value, String> {
    if args.len() != 4 {
        return Err("verify PUBLIC EXPECTED_HEADER EXPECTED_ARTIFACTS PROOF_DIR".into());
    }
    let mut timings = Vec::new();
    let start = Instant::now();
    let (public_bytes, statement) = load_statement(&args[0])?;
    let expected = expected(&args[1], &args[2])?;
    let sha_bytes = read_bounded(
        &Path::new(&args[3]).join("sha.proof.bin"),
        limits(Component::Sha).maximum_bytes,
        None,
    )?;
    let arith_bytes = read_bounded(
        &Path::new(&args[3]).join("arith.proof.bin"),
        limits(Component::PackedCarry).maximum_bytes,
        None,
    )?;
    // Both immutable buffers must pass before either allocation-owning decode.
    let sha_wire =
        scan_proof(&sha_bytes, Component::Sha).map_err(|e| format!("proof decoding: {e}"))?;
    let arith_wire = scan_proof(&arith_bytes, Component::PackedCarry)
        .map_err(|e| format!("proof decoding: {e}"))?;
    let sha_proof = decode_admitted_proof(&sha_bytes, SHA_MAGIC, 13)?;
    let arith_proof = decode_admitted_proof(&arith_bytes, ARITH_MAGIC, 14)?;
    elapsed("bounded_read_decode_and_proof_shape", start, &mut timings);
    let start = Instant::now();
    let (sha_plan, original_arith) = statement.plans(&expected)?;
    let arith = Dot8CarryAir::new(original_arith.rows().to_vec()).map_err(str::to_owned)?;
    drop(original_arith);
    let sha = W1ShaAir::public_only(&sha_plan);
    elapsed(
        "canonical_plans_and_public_only_sha_air",
        start,
        &mut timings,
    );
    let sha_config = config(1);
    let start = Instant::now();
    let (pp, vk) = setup_preprocessed(&sha_config, &sha, sha.trace_height().ilog2() as usize)
        .map_err(|e| format!("sha verifier setup: {e:?}"))?
        .ok_or("missing sha verifier key")?;
    drop(pp);
    elapsed(
        "sha_verifier_independent_preprocessing_setup",
        start,
        &mut timings,
    );
    let start = Instant::now();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_with_preprocessed(&sha_config, &sha, &sha_proof, &[], Some(&vk))
    }))
    .map_err(|_| "sha verifier panic contained".to_owned())
    .and_then(|r| r.map_err(|e| format!("sha proof rejected: {e:?}")));
    elapsed("sha_stark_verify", start, &mut timings);
    outcome?;
    let arith_config = config(PACKED_CARRY_COMPONENT);
    let start = Instant::now();
    let (pp, vk) = setup_preprocessed(&arith_config, &arith, arith.trace_height().ilog2() as usize)
        .map_err(|e| format!("arithmetic verifier setup: {e:?}"))?
        .ok_or("missing arithmetic verifier key")?;
    drop(pp);
    elapsed(
        "arith_verifier_independent_preprocessing_setup",
        start,
        &mut timings,
    );
    let start = Instant::now();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_with_preprocessed(&arith_config, &arith, &arith_proof, &[], Some(&vk))
    }))
    .map_err(|_| "arithmetic verifier panic contained".to_owned())
    .and_then(|r| r.map_err(|e| format!("arithmetic proof rejected: {e:?}")));
    elapsed("arith_stark_verify", start, &mut timings);
    outcome?;
    Ok(
        json!({"status":"VERIFIED_COMPLETE_W1_RESEARCH_ONLY", "statement_sha256":digest(&public_bytes),
        "public_bytes":public_bytes.len(), "sha_proof_bytes":sha_bytes.len(),"sha_proof_sha256":digest(&sha_bytes),
        "arith_proof_bytes":arith_bytes.len(),"arith_proof_sha256":digest(&arith_bytes),"timings":timings,
        "preprocessing_source":"canonical public statement plus independent expected inputs; rebuilt in this process",
        "wire_admission":{
            "schema":"w1-fixed-p3-wire-admission-v2",
            "structural_admission_only":true,"global_rejection_cost_bound":false,
            "sha":{"field_elements":sha_wire.field_elements,"vector_headers":sha_wire.vector_headers,
                "merkle_siblings":sha_wire.merkle_siblings,"maximum_bytes":limits(Component::Sha).maximum_bytes},
            "arithmetic":{"field_elements":arith_wire.field_elements,"vector_headers":arith_wire.vector_headers,
                "merkle_siblings":arith_wire.merkle_siblings,"maximum_bytes":limits(Component::PackedCarry).maximum_bytes}},
        "security_claim":"research execution only; no concrete noninteractive security qualification"}),
    )
}

fn main() {
    let process_start = Instant::now();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("prepare") => prepare(&args[1..]),
        Some("prove") => prove(&args[1..]),
        Some("verify") => verify(&args[1..]),
        _ => Err("commands: prepare | prove | verify; all are research-only and HOLD_NO_GO".into()),
    };
    let (mut value, code) = match result {
        Ok(value) => (value, 0),
        Err(error) => (json!({"status":"REJECTED_OR_FAILED","error":error}), 1),
    };
    value["schema"] = SCHEMA.into();
    value["qualification"] = "HOLD_NO_GO".into();
    value["process_wall_ms"] = (process_start.elapsed().as_secs_f64() * 1000.0).into();
    println!("{value}");
    std::process::exit(code);
}
