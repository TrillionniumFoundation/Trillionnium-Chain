//! Bounded file replay tool. Clock origin is supplied by the caller, elapsed
//! work time is added monotonically. It is an experiment, not deadline authority.
use serde_json::json;
use std::{fs::OpenOptions, io::Write, time::Instant};
use trnm_useful_cell_v2_reference::*;

type CliResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;
#[cfg(unix)]
fn bounded_read(path: &str, limit: usize) -> CliResult<Vec<u8>> {
    use std::{io::Read, os::unix::fs::OpenOptionsExt};
    // Nonblocking applies at open as well as read. Checking a path before a
    // blocking open would leave a replacement race. Validate this opened fd.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOCTTY)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err("FILE_TYPE".into());
    }
    if metadata.len() > limit as u64 {
        return Err("FILE_SIZE".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    (&file).take((limit + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("FILE_SIZE".into());
    }
    if bytes.len() as u64 != metadata.len() || file.metadata()?.len() != metadata.len() {
        return Err("FILE_LENGTH_CHANGED".into());
    }
    Ok(bytes)
}
#[cfg(not(unix))]
fn bounded_read(_path: &str, _limit: usize) -> CliResult<Vec<u8>> {
    Err("REGULAR_FILE_INPUT_UNSUPPORTED".into())
}

fn now(base: u64, start: Instant) -> u64 {
    base.saturating_add(u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX))
}
fn main() -> CliResult<()> {
    let args: Vec<_> = std::env::args().collect();
    if !(args.len() == 5 || args.len() == 6) || !matches!(args[1].as_str(), "produce" | "verify") {
        return Err("usage: trnm-useful-cell-v2-reference produce TASK.json CLAIM.bin NOW_NS [direct|grouped] | verify TASK.json CLAIM.bin NOW_NS".into());
    }
    if args[1] == "verify" && args.len() != 5 {
        return Err("VERIFY_ARGUMENTS".into());
    }
    let base: u64 = args[4].parse()?;
    let start = Instant::now();
    let (model, expected) = task_json::parse(&bounded_read(&args[2], task_json::MAX_TASK_BYTES)?)?;
    let claim = if args[1] == "produce" {
        let kernel = match args.get(5).map(String::as_str).unwrap_or("grouped") {
            "direct" => Kernel::Direct,
            "grouped" => Kernel::Grouped,
            _ => return Err("KERNEL".into()),
        };
        produce(&model, &expected, now(base, start), kernel)?
    } else {
        Claim::from_bytes(&bounded_read(&args[3], MAX_CLAIM_BYTES)?)?
    };
    let verified = verify(&model, &expected, &claim, || now(base, start))?;
    let bytes = claim.to_bytes()?;
    if args[1] == "produce" {
        // An explicit new output path keeps existing evidence intact.
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&args[3])?
            .write_all(&bytes)?;
    }
    println!(
        "{}",
        json!({
            "profile": PROFILE, "verification": "full-native-recomputation", "schema": "pon-useful-cell-result-v2",
            "contract_id": hex::encode(verified.contract_id()), "statement_commitment": hex::encode(verified.statement_commitment()),
            "input_commitment": hex::encode(expected.input_commitment()), "model_commitment": hex::encode(model.commitment()),
            "claim_bytes": bytes.len(), "completed_at_ns": verified.completed_at_ns(),
            "routes": claim.linear.product.routes, "groups": claim.linear.product.groups,
            "raw_logits": claim.linear.product.logits,
            "rows": verified.rows().iter().map(|row| json!({"quotient":row.quotient,"remainder":row.remainder,"clamped":row.clamped,"activated":row.activated,"prediction":row.prediction,"margin":row.margin,"stop":row.stop})).collect::<Vec<_>>(),
            "state_changed": false, "consensus_activation": false
        })
    );
    Ok(())
}
