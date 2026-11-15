//! Independently retain native full-verifier costs even if proving times out.
//! This executable neither invokes a prover nor emits an admission capability.
use anyhow::{ensure, Context, Result};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs::File, hint::black_box, io::Read, time::Instant};
use trnm_w1_zk_relation::{
    check_complete_relation, check_public_journal, native_replay, INPUT_BYTES,
};

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let path = args.next().context("exact saved full W1 input required")?;
    ensure!(args.next().is_none(), "unexpected arguments");
    let mut input = Vec::new();
    File::open(path)?
        .take(INPUT_BYTES as u64 + 1)
        .read_to_end(&mut input)?;
    ensure!(input.len() == INPUT_BYTES, "fixed full-input bound");
    let (header, _) = native_replay(&input).map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let mut elapsed_ns = Vec::with_capacity(1000);
    for _ in 0..1000 {
        let start = Instant::now();
        black_box(native_replay(black_box(&input)).map_err(|error| anyhow::anyhow!("{error:?}"))?);
        elapsed_ns.push(start.elapsed().as_nanos());
    }
    // Bind the observation to the exact public statement after all samples;
    // journal construction and these extra checks are outside every timing.
    let header_bytes = header.encode();
    let journal = check_complete_relation(&input).map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let work_id = check_public_journal(&header_bytes, &journal)
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    println!(
        "{}",
        json!({
            "schema": "trnm-w1-independent-native-cost-v2",
            "input_sha256": hex::encode(Sha256::digest(&input)),
            "input_bytes": input.len(),
            "work_id_hex": hex::encode(work_id),
            "header_sha256": hex::encode(Sha256::digest(&header_bytes)),
            "journal_sha256": hex::encode(Sha256::digest(&journal)),
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
