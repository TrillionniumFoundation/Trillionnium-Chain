use std::{fs, path::PathBuf};

use anyhow::{anyhow, Result};
use trnm_rpc::{TaskMeteringPolicyQueryResponse, TaskMeteringQueryResponse, TaskQueryResponse};
use trnm_state::StateStore;
use trnm_types::{
    GovProposalObject, GovProposalStatus, TaskMeteringSnapshot, TaskObject, TaskStatus,
};

use crate::envpaths::task_state_file;
use crate::metering::build_task_metering_query_response;
use crate::{AdapterRecord, EMERGENCY_PAUSE_KEY_ID};

fn normalize_adapter_record_line(line: &str) -> &str {
    line.trim().trim_start_matches('\u{feff}').trim()
}

fn is_adapter_record_line_candidate(line: &str) -> bool {
    let line = normalize_adapter_record_line(line);
    !line.is_empty() && !line.starts_with('#')
}

fn load_adapter_records_file(path: &PathBuf) -> Vec<AdapterRecord> {
    let Ok(raw) = fs::read(path) else {
        return vec![];
    };
    String::from_utf8_lossy(&raw)
        .lines()
        .filter(|line| is_adapter_record_line_candidate(line))
        .map(normalize_adapter_record_line)
        .filter_map(|l| serde_json::from_str::<AdapterRecord>(l).ok())
        .collect()
}

pub(crate) fn load_latest_adapter_records() -> Vec<AdapterRecord> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let dir = root.join("run/worker-agent");
    let Ok(entries) = fs::read_dir(&dir) else {
        return vec![];
    };

    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.starts_with("tx-adapter-") && s.ends_with(".jsonl"))
                .unwrap_or(false)
        })
        .collect();
    files.sort();

    for path in files.iter().rev() {
        let records = load_adapter_records_file(path);
        if !records.is_empty() {
            return records;
        }
    }

    vec![]
}

pub(crate) fn governance_state() -> StateStore {
    let mut st = StateStore::new();
    let _ = st.put_proposal_new(GovProposalObject {
        proposal_id: 9001,
        title: "update max_block_ms".into(),
        proposer: "alice".into(),
        status: GovProposalStatus::Voting,
        version: 1,
    });
    let _ = st.set_gov_param(0, 7001, "max_block_ms".into(), "10".into());
    let _ = st.set_gov_param(
        0,
        EMERGENCY_PAUSE_KEY_ID,
        "emergency_pause".into(),
        "false".into(),
    );
    st
}

fn normalize_task_state_snapshot_line(line: &str) -> &str {
    line.trim().trim_start_matches('\u{feff}').trim()
}

pub(crate) fn load_task_state_snapshot() -> Result<Vec<TaskObject>> {
    let Some(path) = task_state_file() else {
        return Ok(vec![]);
    };
    let raw = match fs::read(&path) {
        Ok(raw) => String::from_utf8_lossy(&raw).into_owned(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(err) => {
            return Err(anyhow!(
                "failed to read task state snapshot {}: {}",
                path.display(),
                err
            ))
        }
    };

    let mut tasks = Vec::new();
    for (idx, line) in raw.lines().enumerate() {
        let line = normalize_task_state_snapshot_line(line);
        if line.is_empty() {
            continue;
        }
        let task = serde_json::from_str::<TaskObject>(line).map_err(|err| {
            anyhow!(
                "failed to parse task state snapshot {} line {}: {}",
                path.display(),
                idx + 1,
                err
            )
        })?;
        tasks.push(task);
    }
    Ok(tasks)
}

pub(crate) fn task_status_path(status: TaskStatus) -> String {
    match status {
        TaskStatus::Open => "Open",
        TaskStatus::Assigned => "Assigned",
        TaskStatus::Committed => "Committed",
        TaskStatus::Revealed => "Revealed",
        TaskStatus::Challenged => "Challenged",
        TaskStatus::Completed => "Completed",
        TaskStatus::Slashed => "Slashed",
    }
    .to_string()
}

pub(crate) fn task_metering_query_response(
    snapshot: &TaskMeteringSnapshot,
    path: String,
) -> Option<TaskMeteringQueryResponse> {
    let policy = TaskMeteringPolicyQueryResponse {
        snapshot_version: snapshot.policy_snapshot_version,
        min_accept_work_units: snapshot.min_accept_work_units,
        challenge_success_bounty_base: snapshot.challenge_success_bounty_base,
        challenge_success_bounty_per_work_unit_num: snapshot
            .challenge_success_bounty_per_work_unit_num,
        challenge_success_bounty_per_work_unit_den: snapshot
            .challenge_success_bounty_per_work_unit_den,
        worker_completion_bonus_per_work_unit_num: snapshot
            .worker_completion_bonus_per_work_unit_num,
        worker_completion_bonus_per_work_unit_den: snapshot
            .worker_completion_bonus_per_work_unit_den,
        worker_slash_rebate_per_work_unit_num: snapshot.worker_slash_rebate_per_work_unit_num,
        worker_slash_rebate_per_work_unit_den: snapshot.worker_slash_rebate_per_work_unit_den,
    };
    if policy.snapshot_version == 0
        || policy.challenge_success_bounty_per_work_unit_den == 0
        || policy.worker_completion_bonus_per_work_unit_den == 0
        || policy.worker_slash_rebate_per_work_unit_den == 0
    {
        return None;
    }
    Some(build_task_metering_query_response(
        path,
        snapshot.workload_class.clone(),
        snapshot.metering_schema.clone(),
        snapshot.receipt_hash.clone(),
        snapshot.prompt_tokens,
        snapshot.generated_tokens,
        snapshot.decode_steps,
        snapshot.kv_bytes_moved,
        snapshot.normalized_work_units,
        snapshot.prompt_token_weight,
        snapshot.generated_token_weight,
        snapshot.decode_step_weight,
        snapshot.kv_byte_weight,
        policy,
    ))
}

pub(crate) fn query_task_from_state_snapshot(
    task_id: u64,
    tasks: &[TaskObject],
) -> Option<TaskQueryResponse> {
    let task = tasks
        .iter()
        .filter(|task| task.task_id == task_id)
        .max_by_key(|task| task.version)?;
    let metadata_report = task
        .metadata
        .as_ref()
        .map(|metadata| metadata.compatibility_report());

    Some(TaskQueryResponse {
        task_id: task.task_id,
        status: task.status,
        worker: task.worker.clone(),
        bounty: task.bounty,
        result_hash_hex: task.result_hash.map(hex::encode),
        version: task.version,
        metadata_compatibility: metadata_report.as_ref().map(|report| report.compatibility),
        metadata_runtime_compatible: metadata_report
            .as_ref()
            .map(|report| report.compatibility.is_runtime_compatible()),
        metadata_requires_governance_upgrade: metadata_report
            .as_ref()
            .map(|report| report.requires_governance_upgrade),
        metadata_primary_compatibility_finding: metadata_report
            .as_ref()
            .and_then(|report| report.primary_finding()),
        metadata_compatibility_findings: metadata_report
            .as_ref()
            .and_then(|report| report.findings_nonempty()),
        metering: task
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.metering.as_ref())
            .and_then(|snapshot| task_metering_query_response(snapshot, task_status_path(task.status))),
    })
}
