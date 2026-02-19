use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

#[derive(Parser)]
#[command(name = "trnm-verifier")]
#[command(about = "Rust sidecar verifier for Trillionnium commitment checks")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Verify one commitment input file
    Verify {
        /// Input JSON path
        #[arg(long)]
        input: PathBuf,
        /// Output JSON verdict path
        #[arg(long)]
        output: PathBuf,
    },
    /// Run verification over all json files in a directory
    Batch {
        /// Directory containing *.json input files
        #[arg(long)]
        input_dir: PathBuf,
        /// Output directory for verdict json files
        #[arg(long)]
        output_dir: PathBuf,
    },
}

#[derive(Debug, Deserialize)]
struct VerifyInput {
    task_id: u64,
    result_hash: String,
    reveal_salt: String,
    worker_address: String,
    committed_hash: String,
    trace_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct VerifyVerdict {
    task_id: u64,
    trace_id: Option<String>,
    expected_hash: String,
    committed_hash: String,
    matched: bool,
    reason: String,
}

fn normalize_hex(s: &str) -> String {
    s.trim().trim_start_matches("0x").to_ascii_lowercase()
}

fn compute_commit_hash(task_id: u64, result_hash: &str, reveal_salt: &str, worker_address: &str) -> String {
    let message = format!("{}|{}|{}|{}", task_id, result_hash, reveal_salt, worker_address);
    let digest = Sha256::digest(message.as_bytes());
    hex::encode(digest)
}

fn verify_one(input_path: &PathBuf) -> Result<VerifyVerdict> {
    let raw = fs::read_to_string(input_path)
        .with_context(|| format!("failed reading input: {}", input_path.display()))?;
    let input: VerifyInput = serde_json::from_str(&raw)
        .with_context(|| format!("failed parsing json: {}", input_path.display()))?;

    if input.result_hash.trim().is_empty() || input.reveal_salt.trim().is_empty() || input.worker_address.trim().is_empty() {
        bail!("result_hash/reveal_salt/worker_address must be non-empty");
    }

    let expected_hash = compute_commit_hash(
        input.task_id,
        &input.result_hash,
        &input.reveal_salt,
        &input.worker_address,
    );
    let committed_hash = normalize_hex(&input.committed_hash);
    let matched = expected_hash == committed_hash;

    Ok(VerifyVerdict {
        task_id: input.task_id,
        trace_id: input.trace_id,
        expected_hash,
        committed_hash,
        matched,
        reason: if matched {
            "commitment matched".to_string()
        } else {
            "commitment mismatch".to_string()
        },
    })
}

fn write_verdict(output: &PathBuf, verdict: &VerifyVerdict) -> Result<()> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed creating output dir: {}", parent.display()))?;
    }
    let body = serde_json::to_string_pretty(verdict)?;
    fs::write(output, body)
        .with_context(|| format!("failed writing verdict: {}", output.display()))?;
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Verify { input, output } => {
            let verdict = verify_one(&input)?;
            write_verdict(&output, &verdict)?;
            println!("verdict written: {}", output.display());
        }
        Commands::Batch { input_dir, output_dir } => {
            fs::create_dir_all(&output_dir)
                .with_context(|| format!("failed creating output dir: {}", output_dir.display()))?;

            let mut processed = 0usize;
            for entry in fs::read_dir(&input_dir)
                .with_context(|| format!("failed reading input_dir: {}", input_dir.display()))?
            {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) != Some("json") {
                    continue;
                }

                let verdict = verify_one(&path)
                    .with_context(|| format!("verification failed for: {}", path.display()))?;
                let output_file = output_dir.join(path.file_name().unwrap());
                write_verdict(&output_file, &verdict)?;
                processed += 1;
            }
            println!("batch complete: processed={} output_dir={}", processed, output_dir.display());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_hash_is_stable() {
        let got = compute_commit_hash(7, "result://ok", "salt-1", "trnm1abc");
        let expect = "36f1ca4a96a809b6e6ffac7538e87c0a13a592994f7f0d5de0f9612eb77a658b";
        assert_eq!(got, expect);
    }

    #[test]
    fn normalize_hex_works() {
        assert_eq!(normalize_hex("0xAbC"), "abc");
        assert_eq!(normalize_hex("abc"), "abc");
    }
}
