use anyhow::{ensure, Result};
use bincode::Options;
use risc0_zkvm::{sha::Digestible, ApiClient, AssetRequest, ProverOpts, ReceiptClaim, SuccinctReceipt};
use sha2::{Digest, Sha256};
use std::{fs, time::Instant};
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    ensure!(args.len() == 5, "R0VM LEFT RIGHT EXPECTED");
    let engine = fs::read(&args[1])?;
    ensure!(format!("{:x}", Sha256::digest(&engine)) == "2acdf550f9aca4d05b74072463e4ed307c3824309c754a5cb5f93aa84f3390e6", "pinned engine required");
    let mut inputs = Vec::new();
    let mut hashes = Vec::new();
    for path in &args[2..] {
        let bytes = fs::read(path)?;
        ensure!(bytes.len() <= 16 * 1024 * 1024, "input bound");
        let r: SuccinctReceipt<ReceiptClaim> = bincode::DefaultOptions::new().with_fixint_encoding().with_limit(16 * 1024 * 1024).reject_trailing_bytes().deserialize(&bytes)?;
        r.verify_integrity()?;
        inputs.push(r);
        hashes.push(format!("{:x}", Sha256::digest(&bytes)));
    }
    let expected = inputs.pop().unwrap();
    let right = inputs.pop().unwrap();
    let left = inputs.pop().unwrap();
    let client = ApiClient::new_sub_process(&args[1])?;
    let started = Instant::now();
    let actual = client.join(&ProverOpts::succinct(), left.try_into()?, right.try_into()?, AssetRequest::Inline)?;
    let prover_ns = started.elapsed().as_nanos();
    actual.verify_integrity()?;
    ensure!(actual.claim.digest() == expected.claim.digest(), "expected joined claim mismatch");
    let bytes = bincode::serialize(&actual)?;
    println!("{}", serde_json::json!({"schema":"TRNM-W1-JOIN-DIAGNOSTIC1","full_proof_claim":false,"budget_acceptance_claim":false,"rayon_threads":std::env::var("RAYON_NUM_THREADS").ok(),"input_sha256":hashes,"prover_ns":prover_ns,"output_sha256":format!("{:x}",Sha256::digest(&bytes)),"output_bytes":bytes.len(),"cryptographic_integrity_verified":true,"expected_claim_matched":true}));
    Ok(())
}
