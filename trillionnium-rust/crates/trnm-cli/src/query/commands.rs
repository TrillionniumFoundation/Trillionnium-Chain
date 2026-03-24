use super::*;

use super::parsing::{
    parse_events_query_response, parse_request_full_query_response, parse_task_query_response,
};

fn rpc_workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

fn run_rpc_query(cmd: &str, failure_label: &str) -> Result<String> {
    let (program, args) = parse_template_command(cmd)?;
    let out = ProcCommand::new(program)
        .args(args)
        .current_dir(rpc_workspace())
        .output()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        bail!(
            "{} command failed rc={}: {}{}",
            failure_label,
            out.status.code().unwrap_or(1),
            stdout,
            stderr
        );
    }
    Ok(stdout.into_owned())
}

pub(crate) fn events_query(task_id: u64, limit: usize) -> Result<serde_json::Value> {
    if let Ok(template) = std::env::var("TRNM_QUERY_EVENTS_CMD") {
        let cmd = tpl(
            tpl(template, "task_id", &task_id.to_string()),
            "limit",
            &limit.to_string(),
        );
        let raw = run_template_raw(&cmd)?;
        return parse_events_query_response(&raw, task_id);
    }

    let cmd = format!(
        "cargo run -q -p trnm-rpc -- query-events {} --limit {}",
        task_id, limit
    );
    let raw = run_rpc_query(&cmd, "events query")?;
    parse_events_query_response(&raw, task_id)
}

pub(crate) fn request_full_query(request_id: &str, limit: usize) -> Result<serde_json::Value> {
    if let Ok(template) = std::env::var("TRNM_QUERY_REQUEST_FULL_CMD") {
        let cmd = tpl(
            tpl(template, "request_id", request_id),
            "limit",
            &limit.to_string(),
        );
        let raw = run_template_raw(&cmd)?;
        return parse_request_full_query_response(&raw, request_id);
    }

    let cmd = format!(
        "cargo run -q -p trnm-rpc -- query-request-full --request-id {} --limit {}",
        request_id, limit
    );
    let raw = run_rpc_query(&cmd, "request-full query")?;
    parse_request_full_query_response(&raw, request_id)
}

pub(crate) fn task_query(task_id: u64) -> Result<serde_json::Value> {
    if let Ok(template) = std::env::var("TRNM_QUERY_TASK_CMD") {
        let cmd = tpl(template, "task_id", &task_id.to_string());
        let raw = run_template_raw(&cmd)?;
        return parse_task_query_response(&raw, task_id);
    }

    let cmd = format!("cargo run -q -p trnm-rpc -- query-task {}", task_id);
    let raw = run_rpc_query(&cmd, "task query")?;
    parse_task_query_response(&raw, task_id)
}
