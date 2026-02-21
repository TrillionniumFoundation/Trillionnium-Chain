use anyhow::Result;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fs, path::PathBuf, process::Command as ProcCommand, thread, time::{Duration, SystemTime, UNIX_EPOCH}};

const DEFAULT_MAX_RETRIES: u32 = 3;
const DEFAULT_BACKOFF_MS: u64 = 200;

const RC_OK: i32 = 0;
const RC_DUPLICATE: i32 = 9;
const RC_NONCE_REJECTED: i32 = 10;

#[derive(Debug, Parser)]
#[command(name = "trnm-worker-agent", version, about = "Trillionnium PoUW worker-agent (MVP skeleton)")]
struct Args {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    PullTask {
        #[arg(long, default_value = "worker-state.json")]
        state: PathBuf,
    },
    Execute {
        #[arg(long)]
        task_id: u64,
        #[arg(long)]
        worker: String,
        #[arg(long, default_value = "demo-result")]
        payload: String,
    },
    CommitReveal {
        #[arg(long)]
        task_id: u64,
        #[arg(long)]
        worker: String,
        #[arg(long)]
        result_hash: String,
        #[arg(long)]
        salt_hex: String,
        #[arg(long, default_value_t = false)]
        submit: bool,
        #[arg(long, default_value = "/tmp/trnm-worker-agent-submissions.jsonl")]
        submit_log: PathBuf,
    },
    RunOnce {
        #[arg(long, default_value = "worker-state.json")]
        state: PathBuf,
        #[arg(long)]
        worker: String,
        #[arg(long, default_value = "demo-result")]
        payload: String,
        #[arg(long, default_value_t = false)]
        submit: bool,
        #[arg(long, default_value = "/tmp/trnm-worker-agent-submissions.jsonl")]
        submit_log: PathBuf,
    },
    FlushSubmissions {
        #[arg(long, default_value = "/tmp/trnm-worker-agent-submissions.jsonl")]
        submit_log: PathBuf,
        #[arg(long, default_value_t = false)]
        execute: bool,
        #[arg(long, default_value = "./scripts/worker_tx_adapter.sh")]
        adapter_cmd: String,
        #[arg(long, default_value_t = DEFAULT_MAX_RETRIES)]
        max_retries: u32,
        #[arg(long, default_value_t = DEFAULT_BACKOFF_MS)]
        backoff_ms: u64,
        #[arg(long, default_value = "/tmp/trnm-worker-agent-acks.jsonl")]
        ack_log: PathBuf,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct WorkerState {
    last_task_id: u64,
}

#[derive(Debug, Serialize)]
struct RunOnceOutput {
    task_id: u64,
    worker: String,
    result_hash: String,
    salt_hex: String,
    commit_hash: String,
    template_commit: String,
    template_reveal: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SubmissionRecord {
    ts_unix_ms: u128,
    task_id: u64,
    worker: String,
    nonce: Option<u64>,
    commit_hash: String,
    result_hash: String,
    salt_hex: String,
    commit_cmd: String,
    reveal_cmd: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AckRecord {
    ts_unix_ms: u128,
    task_id: u64,
    status: String,
    commit_tx_hash: Option<String>,
    reveal_tx_hash: Option<String>,
}

#[derive(Debug)]
struct AdapterExecResult {
    ok: bool,
    rc: i32,
    tx_hash: Option<String>,
    terminal: bool,
}

fn commitment(task_id: u64, result_hash_hex: &str, salt_hex: &str, worker: &str) -> String {
    let payload = format!("{}|{}|{}|{}", task_id, result_hash_hex, salt_hex, worker);
    let mut h = Sha256::new();
    h.update(payload.as_bytes());
    hex::encode(h.finalize())
}

fn next_task_id(state: &PathBuf) -> Result<u64> {
    let mut s = if state.exists() {
        serde_json::from_str::<WorkerState>(&fs::read_to_string(state)?)?
    } else {
        WorkerState { last_task_id: 1000 }
    };
    s.last_task_id += 1;
    fs::write(state, serde_json::to_string_pretty(&s)?)?;
    Ok(s.last_task_id)
}

fn execute_payload(payload: &str, task_id: u64) -> (String, String) {
    let mut h = Sha256::new();
    h.update(payload.as_bytes());
    let result_hash = hex::encode(h.finalize());
    let salt_hex = format!("{:064x}", task_id);
    (result_hash, salt_hex)
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn append_submission(
    submit_log: &PathBuf,
    task_id: u64,
    worker: &str,
    commit_hash: &str,
    result_hash: &str,
    salt_hex: &str,
) -> Result<()> {
    let nonce = task_id;
    let commit_cmd = format!("trnm-node tx commit-result {} {} {} {}", task_id, worker, commit_hash, nonce);
    let reveal_cmd = format!("trnm-node tx reveal-result {} {} {}", task_id, result_hash, salt_hex);
    let rec = SubmissionRecord {
        ts_unix_ms: now_ms(),
        task_id,
        worker: worker.to_string(),
        nonce: Some(nonce),
        commit_hash: commit_hash.to_string(),
        result_hash: result_hash.to_string(),
        salt_hex: salt_hex.to_string(),
        commit_cmd,
        reveal_cmd,
    };
    let line = serde_json::to_string(&rec)?;
    let mut old = if submit_log.exists() { fs::read_to_string(submit_log)? } else { String::new() };
    old.push_str(&line);
    old.push('\n');
    fs::write(submit_log, old)?;
    Ok(())
}

fn load_acked(ack_log: &PathBuf) -> HashSet<u64> {
    let mut set = HashSet::new();
    if !ack_log.exists() {
        return set;
    }
    if let Ok(raw) = fs::read_to_string(ack_log) {
        for line in raw.lines().filter(|l| !l.trim().is_empty()) {
            if let Ok(rec) = serde_json::from_str::<AckRecord>(line) {
                if rec.status == "accepted" {
                    set.insert(rec.task_id);
                }
            }
        }
    }
    set
}

fn append_ack(
    ack_log: &PathBuf,
    task_id: u64,
    status: &str,
    commit_tx_hash: Option<String>,
    reveal_tx_hash: Option<String>,
) -> Result<()> {
    let rec = AckRecord {
        ts_unix_ms: now_ms(),
        task_id,
        status: status.to_string(),
        commit_tx_hash,
        reveal_tx_hash,
    };
    let line = serde_json::to_string(&rec)?;
    let mut old = if ack_log.exists() { fs::read_to_string(ack_log)? } else { String::new() };
    old.push_str(&line);
    old.push('\n');
    fs::write(ack_log, old)?;
    Ok(())
}

fn parse_tx_hash(text: &str) -> Option<String> {
    text.split_whitespace()
        .find_map(|w| w.strip_prefix("tx_hash=").map(|s| s.to_string()))
}

fn is_deterministic_rejection(rc: i32) -> bool {
    matches!(rc, RC_DUPLICATE | RC_NONCE_REJECTED)
}

fn is_idempotent_duplicate_ok(rc: i32) -> bool {
    rc == RC_DUPLICATE
}

fn backoff_delay_ms(base_ms: u64, attempt: u32) -> u64 {
    base_ms.saturating_mul(attempt as u64 + 1)
}

fn run_adapter_with_retry(cmd: &str, max_retries: u32, backoff_ms: u64) -> Result<AdapterExecResult> {
    let mut last_rc = 1;
    let mut last_tx_hash: Option<String> = None;

    for attempt in 0..=max_retries {
        let out = ProcCommand::new("sh").arg("-lc").arg(cmd).output()?;
        let rc = out.status.code().unwrap_or(1);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let tx_hash = parse_tx_hash(&stdout).or_else(|| parse_tx_hash(&stderr));

        if out.status.success() {
            return Ok(AdapterExecResult {
                ok: true,
                rc: RC_OK,
                tx_hash,
                terminal: true,
            });
        }

        last_rc = rc;
        if tx_hash.is_some() {
            last_tx_hash = tx_hash;
        }

        // deterministic rejections (duplicate/nonce_rejected) should not retry.
        if is_deterministic_rejection(rc) {
            return Ok(AdapterExecResult {
                ok: false,
                rc,
                tx_hash: last_tx_hash,
                terminal: true,
            });
        }

        if attempt < max_retries {
            thread::sleep(Duration::from_millis(backoff_delay_ms(backoff_ms, attempt)));
        }
    }

    Ok(AdapterExecResult {
        ok: false,
        rc: last_rc,
        tx_hash: last_tx_hash,
        terminal: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_rejection_codes_are_stable() {
        assert!(is_deterministic_rejection(RC_DUPLICATE));
        assert!(is_deterministic_rejection(RC_NONCE_REJECTED));
        assert!(!is_deterministic_rejection(RC_OK));
        assert!(!is_deterministic_rejection(42));
    }

    #[test]
    fn idempotent_only_accepts_duplicate() {
        assert!(is_idempotent_duplicate_ok(RC_DUPLICATE));
        assert!(!is_idempotent_duplicate_ok(RC_NONCE_REJECTED));
        assert!(!is_idempotent_duplicate_ok(RC_OK));
    }

    #[test]
    fn backoff_delay_is_linear_and_saturating() {
        assert_eq!(backoff_delay_ms(200, 0), 200);
        assert_eq!(backoff_delay_ms(200, 1), 400);
        assert_eq!(backoff_delay_ms(200, 2), 600);

        // saturation guard (no overflow panic/wrap)
        assert_eq!(backoff_delay_ms(u64::MAX, 1), u64::MAX);
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.cmd {
        Command::PullTask { state } => {
            let task_id = next_task_id(&state)?;
            println!("[agent] pulled task_id={}", task_id);
        }
        Command::Execute {
            task_id,
            worker,
            payload,
        } => {
            let (result_hash, salt_hex) = execute_payload(&payload, task_id);
            println!("[agent] executed task_id={} worker={}", task_id, worker);
            println!("result_hash={}", result_hash);
            println!("salt_hex={}", salt_hex);
        }
        Command::CommitReveal {
            task_id,
            worker,
            result_hash,
            salt_hex,
            submit,
            submit_log,
        } => {
            let c = commitment(task_id, &result_hash, &salt_hex, &worker);
            println!("[agent] task_id={} worker={}", task_id, worker);
            println!("commit_hash={}", c);
            println!(
                "template_commit=trnm-node tx commit-result {} {} {} {}",
                task_id, worker, c, task_id
            );
            println!(
                "template_reveal=trnm-node tx reveal-result {} {} {}",
                task_id, result_hash, salt_hex
            );
            if submit {
                append_submission(&submit_log, task_id, &worker, &c, &result_hash, &salt_hex)?;
                println!("submitted=true submit_log={}", submit_log.display());
            }
        }
        Command::RunOnce {
            state,
            worker,
            payload,
            submit,
            submit_log,
        } => {
            let task_id = next_task_id(&state)?;
            let (result_hash, salt_hex) = execute_payload(&payload, task_id);
            let commit_hash = commitment(task_id, &result_hash, &salt_hex, &worker);
            if submit {
                append_submission(&submit_log, task_id, &worker, &commit_hash, &result_hash, &salt_hex)?;
            }
            let out = RunOnceOutput {
                task_id,
                worker: worker.clone(),
                result_hash: result_hash.clone(),
                salt_hex: salt_hex.clone(),
                commit_hash: commit_hash.clone(),
                template_commit: format!(
                    "trnm-node tx commit-result {} {} {} {}",
                    task_id, worker, commit_hash, task_id
                ),
                template_reveal: format!(
                    "trnm-node tx reveal-result {} {} {}",
                    task_id, result_hash, salt_hex
                ),
            };
            println!("{}", serde_json::to_string_pretty(&out)?);
            if submit {
                eprintln!("submitted=true submit_log={}", submit_log.display());
            }
        }
        Command::FlushSubmissions {
            submit_log,
            execute,
            adapter_cmd,
            max_retries,
            backoff_ms,
            ack_log,
        } => {
            if !submit_log.exists() {
                println!("[agent] no submit log found: {}", submit_log.display());
                return Ok(());
            }
            let raw = fs::read_to_string(&submit_log)?;
            let mut n = 0usize;
            let mut skipped = 0usize;
            let mut acked = load_acked(&ack_log);
            for line in raw.lines().filter(|l| !l.trim().is_empty()) {
                let rec: SubmissionRecord = serde_json::from_str(line)?;
                n += 1;

                if acked.contains(&rec.task_id) {
                    skipped += 1;
                    println!("[skip] task_id={} already_acked=true", rec.task_id);
                    continue;
                }

                if !execute {
                    println!("[dry-run] adapter={} commit {} {} {}", adapter_cmd, rec.task_id, rec.worker, rec.commit_hash);
                    println!("[dry-run] adapter={} reveal {} {} {}", adapter_cmd, rec.task_id, rec.result_hash, rec.salt_hex);
                } else {
                    let nonce = rec.nonce.unwrap_or(rec.task_id);
                    let cmd1 = format!("{} commit {} {} {} {}", adapter_cmd, rec.task_id, rec.worker, rec.commit_hash, nonce);
                    let cmd2 = format!("{} reveal {} {} {}", adapter_cmd, rec.task_id, rec.result_hash, rec.salt_hex);

                    let commit_res = run_adapter_with_retry(&cmd1, max_retries, backoff_ms)?;
                    let reveal_res = run_adapter_with_retry(&cmd2, max_retries, backoff_ms)?;

                    println!(
                        "[submitted] task_id={} commit_ok={} reveal_ok={} commit_rc={} reveal_rc={} commit_tx_hash={} reveal_tx_hash={} adapter={} retries={} backoff_ms={}",
                        rec.task_id,
                        commit_res.ok,
                        reveal_res.ok,
                        commit_res.rc,
                        reveal_res.rc,
                        commit_res.tx_hash.as_deref().unwrap_or("-"),
                        reveal_res.tx_hash.as_deref().unwrap_or("-"),
                        adapter_cmd,
                        max_retries,
                        backoff_ms
                    );

                    let commit_idempotent_ok = commit_res.ok || is_idempotent_duplicate_ok(commit_res.rc);
                    let reveal_idempotent_ok = reveal_res.ok || is_idempotent_duplicate_ok(reveal_res.rc);

                    let (ack_status, ack_reason) = if commit_idempotent_ok && reveal_idempotent_ok {
                        ("accepted", format!("idempotent-ok commit_rc={} reveal_rc={}", commit_res.rc, reveal_res.rc))
                    } else if commit_res.terminal || reveal_res.terminal {
                        ("rejected", format!("deterministic-rejection commit_rc={} reveal_rc={}", commit_res.rc, reveal_res.rc))
                    } else {
                        ("failed", format!("transient-or-exhausted-retries commit_rc={} reveal_rc={}", commit_res.rc, reveal_res.rc))
                    };

                    append_ack(
                        &ack_log,
                        rec.task_id,
                        ack_status,
                        commit_res.tx_hash,
                        reveal_res.tx_hash,
                    )?;

                    if ack_status == "accepted" {
                        acked.insert(rec.task_id);
                    }

                    println!(
                        "[ack] task_id={} status={} reason={}",
                        rec.task_id, ack_status, ack_reason
                    );
                }
            }
            println!("[agent] flushed_records={} skipped={} execute={} ack_log={}", n, skipped, execute, ack_log.display());
        }
    }
    Ok(())
}
