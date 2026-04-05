use super::*;

pub(crate) fn run_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

pub(crate) fn identity_registry_file() -> PathBuf {
    if let Some(path) = normalized_path_from_env("TRNM_RPC_IDENTITY_REGISTRY_FILE") {
        return path;
    }
    run_root().join("run/rpc/identity_registry.json")
}

pub(crate) fn load_identity_registry(path: &Path) -> IdentityRegistry {
    let Ok(raw) = fs::read_to_string(path) else {
        return IdentityRegistry::default();
    };
    serde_json::from_str::<IdentityRegistry>(&raw).unwrap_or_default()
}

pub(crate) fn ingress_file() -> PathBuf {
    if let Some(path) = normalized_path_from_env("TRNM_RPC_INGRESS_FILE") {
        return path;
    }
    run_root().join("run/message-gateway/requests.jsonl")
}

pub(crate) fn submit_message_max_bytes() -> u64 {
    env_u64_with_min(
        SUBMIT_MESSAGE_MAX_BYTES_ENV,
        SUBMIT_MESSAGE_MAX_BYTES_DEFAULT,
        SUBMIT_MESSAGE_MAX_BYTES_MIN,
    )
}

pub(crate) fn task_state_file() -> Option<PathBuf> {
    normalized_path_from_env(TASK_STATE_FILE_ENV)
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
