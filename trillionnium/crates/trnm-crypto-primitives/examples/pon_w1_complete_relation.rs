//! Execute the complete native guest relation. This is not a succinct prover.
use anyhow::{anyhow, bail, Context, Result};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::time::Instant;
use trnm_crypto_primitives::pon_work::{self, full_relation};
use trnm_protocol::pon_wire::Header;

fn fixture(path: &Path) -> Result<()> {
    let a: Vec<_> = (0..pon_work::CELLS)
        .map(|i| ((13 * i + 17) % 257) as u32)
        .collect();
    let b: Vec<_> = (0..pon_work::CELLS)
        .map(|i| ((29 * i + 31) % 263) as u32)
        .collect();
    let header = Header {
        network: [1; 32],
        parameters: [2; 32],
        parent: [3; 32],
        height: 1,
        timestamp: 1,
        target: [255; 32],
        miner: [4; 32],
        transactions: [5; 32],
        state: [6; 32],
        receipts: [7; 32],
        work_task: pon_work::task_id(&a, &b).map_err(|error| anyhow!("{error:?}"))?,
        nonce: 0,
    };
    let witness =
        pon_work::prove(header.challenge(), &a, &b).map_err(|error| anyhow!("{error:?}"))?;
    let statement = full_relation::PublicStatement::bind(
        &header.encode(),
        header.work_task,
        header.target,
        &witness,
    )
    .map_err(|error| anyhow!("{error:?}"))?;
    let mut input = statement.encode().to_vec();
    input.extend_from_slice(&witness);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create new fixture {}", path.display()))?;
    output.write_all(&input)?;
    output.sync_all()?;
    println!("{{\"schema\":\"pon-w1-local-relation-v1\",\"operation\":\"fixture\",\"input_bytes\":{},\"research_target_all_ff\":true,\"succinct_proof_generated\":false,\"consensus_authority\":false}}", input.len());
    Ok(())
}

fn execute(path: &Path) -> Result<()> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut input = Vec::with_capacity(full_relation::INPUT_BYTES);
    file.take((full_relation::INPUT_BYTES + 1) as u64)
        .read_to_end(&mut input)?;
    if input.len() != full_relation::INPUT_BYTES {
        bail!(
            "input must contain exactly {} bytes",
            full_relation::INPUT_BYTES
        );
    }
    let started = Instant::now();
    let observed = full_relation::execute_input(&input)
        .map_err(|error| anyhow!("complete relation rejected: {error:?}"))?;
    let elapsed_ns = started.elapsed().as_nanos();
    println!("{{\"schema\":\"pon-w1-local-relation-v1\",\"operation\":\"execute\",\"result\":\"complete_local_recomputation_passed\",\"profile\":\"{}\",\"statement_id\":\"{}\",\"block_id\":\"{}\",\"journal_hex\":\"{}\",\"elapsed_wall_ns\":{},\"succinct_proof_generated\":false,\"cryptographic_proof_verified\":false,\"consensus_authority\":false}}",
        full_relation::PROFILE, hex::encode(observed.statement_id()),
        hex::encode(observed.block_id()), hex::encode(observed.journal()), elapsed_ns);
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 3 {
        bail!("usage: pon_w1_complete_relation <fixture|execute> <file>");
    }
    match args[1].to_str() {
        Some("fixture") => fixture(Path::new(&args[2])),
        Some("execute") => execute(Path::new(&args[2])),
        _ => bail!("expected fixture or execute"),
    }
}
