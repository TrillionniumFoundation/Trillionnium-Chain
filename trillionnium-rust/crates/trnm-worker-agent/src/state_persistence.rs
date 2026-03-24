use crate::{
    now_ms, AckRecord, MessageIngressRecord, PersistedAckHashes, ProgressRecord, SubmissionRecord,
    TaskExecutionLock, WorkerEvent,
};
use anyhow::{anyhow, Result};
use std::{
    collections::HashSet,
    env, fs,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};
use trnm_types::RequestStatus;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct WorkerState {
    last_task_id: u64,
}

pub(crate) fn next_task_id(state: &PathBuf) -> Result<u64> {
    let mut s = if state.exists() {
        serde_json::from_str::<WorkerState>(&fs::read_to_string(state)?)?
    } else {
        WorkerState { last_task_id: 1000 }
    };
    s.last_task_id += 1;
    fs::write(state, serde_json::to_string_pretty(&s)?)?;
    Ok(s.last_task_id)
}

fn append_json_line(path: &PathBuf, line: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}

pub(crate) fn append_submission(
    submit_log: &PathBuf,
    task_id: u64,
    worker: &str,
    commit_hash: &str,
    result_hash: &str,
    salt_hex: &str,
) -> Result<()> {
    let nonce = task_id;
    let commit_cmd = format!(
        "trnm-node tx commit-result {} {} {} {}",
        task_id, worker, commit_hash, nonce
    );
    let reveal_cmd = format!(
        "trnm-node tx reveal-result {} {} {}",
        task_id, result_hash, salt_hex
    );
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
    append_json_line(submit_log, &line)
}

fn load_ack_records(ack_log: &PathBuf) -> Vec<AckRecord> {
    if !ack_log.exists() {
        return vec![];
    }
    fs::read_to_string(ack_log)
        .ok()
        .map(|raw| {
            raw.lines()
                .filter(|l| !l.trim().is_empty())
                .filter_map(|line| serde_json::from_str::<AckRecord>(line).ok())
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn load_acked(ack_log: &PathBuf) -> HashSet<u64> {
    load_ack_records(ack_log)
        .into_iter()
        .filter(|rec| rec.status == "accepted")
        .map(|rec| rec.task_id)
        .collect()
}

fn task_lock_path(ack_log: &PathBuf, task_id: u64) -> PathBuf {
    let parent = ack_log
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let base = ack_log
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("trnm-worker-agent-acks.jsonl");
    parent.join(format!(".{base}.task-{task_id}.lock"))
}

pub(crate) fn try_acquire_task_lock(
    ack_log: &PathBuf,
    task_id: u64,
) -> Result<Option<TaskExecutionLock>> {
    let path = task_lock_path(ack_log, task_id);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(_) => Ok(Some(TaskExecutionLock { path })),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub(crate) fn is_task_acked(ack_log: &PathBuf, task_id: u64) -> bool {
    load_acked(ack_log).contains(&task_id)
}

pub(crate) fn load_ingress_records(path: &PathBuf) -> Result<Vec<MessageIngressRecord>> {
    if !path.exists() {
        return Ok(vec![]);
    }
    let raw = fs::read_to_string(path)?;
    Ok(raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<MessageIngressRecord>(l).ok())
        .collect())
}

pub(crate) fn save_ingress_records(path: &PathBuf, records: &[MessageIngressRecord]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut out = String::new();
    for rec in records {
        out.push_str(&serde_json::to_string(rec)?);
        out.push('\n');
    }
    fs::write(path, out)?;
    Ok(())
}

pub(crate) fn transition_request_status(current: &str, to: RequestStatus) -> Result<String> {
    let from = RequestStatus::parse(current).map_err(|e| anyhow!("{}", e))?;
    let next = from.transition(to).map_err(|e| anyhow!("{}", e))?;
    Ok(next.as_str().to_string())
}

pub(crate) fn append_ack(
    ack_log: &PathBuf,
    task_id: u64,
    status: &str,
    commit_tx_hash: Option<String>,
    reveal_tx_hash: Option<String>,
    reason_code: Option<String>,
    run_id: Option<String>,
) -> Result<()> {
    let rec = AckRecord {
        ts_unix_ms: now_ms(),
        task_id,
        status: status.to_string(),
        commit_tx_hash,
        reveal_tx_hash,
        reason_code,
        run_id,
    };
    let line = serde_json::to_string(&rec)?;
    append_json_line(ack_log, &line)
}

pub(crate) fn append_event(event_log: &PathBuf, event: &WorkerEvent) -> Result<()> {
    let line = serde_json::to_string(event)?;
    append_json_line(event_log, &line)
}

pub(crate) fn append_progress(progress_log: &PathBuf, rec: &ProgressRecord) -> Result<()> {
    let line = serde_json::to_string(rec)?;
    append_json_line(progress_log, &line)
}

pub(crate) fn resolve_path_arg_from_env(
    path: PathBuf,
    env_name: &str,
    default_path: &str,
) -> PathBuf {
    if path == PathBuf::from(default_path) {
        if let Some(value) = env::var_os(env_name) {
            if !value.is_empty() {
                return PathBuf::from(value);
            }
        }
    }
    path
}

pub(crate) fn persisted_ack_hashes_for_task(ack_log: &PathBuf, task_id: u64) -> PersistedAckHashes {
    let mut hashes = PersistedAckHashes {
        commit_tx_hash: None,
        reveal_tx_hash: None,
    };

    for ack in load_ack_records(ack_log).into_iter().rev() {
        if ack.task_id != task_id {
            continue;
        }
        if hashes.commit_tx_hash.is_none() {
            hashes.commit_tx_hash = ack.commit_tx_hash;
        }
        if hashes.reveal_tx_hash.is_none() {
            hashes.reveal_tx_hash = ack.reveal_tx_hash;
        }
        if hashes.commit_tx_hash.is_some() && hashes.reveal_tx_hash.is_some() {
            break;
        }
    }

    hashes
}
