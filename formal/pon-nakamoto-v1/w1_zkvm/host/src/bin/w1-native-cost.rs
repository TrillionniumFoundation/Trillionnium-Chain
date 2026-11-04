//! Independently retain native full-verifier costs even if proving times out.
//! This executable neither invokes a prover nor emits an admission capability.
use anyhow::{ensure, Context, Result};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs::File, hint::black_box, io::Read, time::Instant};
use trnm_w1_zk_relation::{native_replay, INPUT_BYTES};

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let path = args.next().context("exact saved full W1 input required")?;
    ensure!(args.next().is_none(), "unexpected arguments");
    let mut input = Vec::new();
    File::open(path)?
        .take(INPUT_BYTES as u64 + 1)
        .read_to_end(&mut input)?;
    ensure!(input.len() == INPUT_BYTES, "fixed full-input bound");
    native_replay(&input).map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let mut elapsed_ns = Vec::with_capacity(1000);
    for _ in 0..1000 {
        let start = Instant::now();
        black_box(native_replay(black_box(&input)).map_err(|error| anyhow::anyhow!("{error:?}"))?);
        elapsed_ns.push(start.elapsed().as_nanos());
    }
    println!(
        "{}",
        json!({
            "schema": "trnm-w1-independent-native-cost-v1",
            "input_sha256": hex::encode(Sha256::digest(&input)),
            "input_bytes": input.len(),
            "completed_native_full_verifications": elapsed_ns.len(),
            "native_full_verifier_ns": elapsed_ns,
            "scope": "one fixed dense maximum-target witness; fixture generation and journal construction excluded",
            "cryptographic_proof_generated": false,
            "mining_cost_distribution_established": false,
            "production_tail_established": false,
            "consensus_admission": false
        })
    );
    Ok(())
}
