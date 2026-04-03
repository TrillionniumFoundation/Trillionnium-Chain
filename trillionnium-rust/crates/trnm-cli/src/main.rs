use anyhow::{anyhow, bail, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command as ProcCommand,
    thread,
    time::{Duration, Instant},
};

#[derive(Debug, Parser)]
#[command(
    name = "trnm-cli",
    version,
    about = "Trillionnium native CLI (wallet/query/tx MVP)"
)]
struct Args {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Transaction related commands
    Tx {
        #[command(subcommand)]
        tx: TxCommand,
    },
    /// Wallet related commands
    Wallet {
        #[command(subcommand)]
        wallet: WalletCommand,
    },
    /// Query commands (RPC/model-facing)
    Query {
        #[command(subcommand)]
        query: QueryCommand,
    },
}

#[derive(Debug, Subcommand)]
enum TxCommand {
    /// Legacy commit-result tx (kept for compatibility)
    CommitResult {
        task_id: u64,
        worker: String,
        commit_hash: String,
        nonce: u64,
    },
    /// Legacy reveal-result tx (kept for compatibility)
    RevealResult {
        task_id: u64,
        result_hash: String,
        salt_hex: String,
    },
    /// Query tx lifecycle status by hash
    Query { tx_hash: String },
    /// Wait until tx reaches committed/fail lifecycle state
    Wait {
        tx_hash: String,
        #[arg(long, default_value_t = 30)]
        timeout: u64,
        #[arg(long, default_value_t = 2)]
        interval: u64,
    },
    /// Transfer balance from one wallet to another
    Transfer {
        #[arg(long, default_value = "default")]
        from: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u128,
        #[arg(long, default_value = "trnm")]
        denom: String,
        #[arg(long)]
        store: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum WalletCommand {
    /// Create a new local wallet (MVP placeholder)
    Create {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Alias of wallet create (backward compatible)
    Generate {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Import private key hex into local wallet store
    Import {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        private_key_hex: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Print derived address from local wallet
    Address {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        store: Option<PathBuf>,
    },
    /// Sign arbitrary text (MVP deterministic signature)
    Sign {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        message: String,
        #[arg(long)]
        store: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum QueryCommand {
    /// Query account balance via new RPC/model contract
    Balance {
        #[arg(long)]
        address: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        store: Option<PathBuf>,
        #[arg(long, default_value = "trnm")]
        denom: String,
    },
    /// Query task status / audit view via RPC
    Task { task_id: u64 },
    /// Query task event timeline / audit view via RPC
    Events {
        task_id: u64,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long, default_value_t = false)]
        summary: bool,
    },
    /// Query full request timeline / audit view via RPC
    RequestFull {
        request_id: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long, default_value_t = false)]
        summary: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BalanceQueryResponse {
    address: String,
    balance: String,
    denom: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TransferTxRequest {
    from: String,
    to: String,
    amount: String,
    denom: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TransferTxResponse {
    tx_hash: String,
    status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TxQueryResponse {
    tx_hash: String,
    status: String,
    error: Option<String>,
}

fn validate_task_query_metadata_compatibility(parsed: &serde_json::Value) -> Result<()> {
    let Some(compatibility) = parsed.get("metadata_compatibility") else {
        if parsed.get("metadata_runtime_compatible").is_some() {
            bail!(
                "task query response metadata_runtime_compatible requires metadata_compatibility"
            );
        }
        if parsed.get("metadata_requires_governance_upgrade").is_some() {
            bail!(
                "task query response metadata_requires_governance_upgrade requires metadata_compatibility"
            );
        }
        if parsed
            .get("metadata_primary_compatibility_finding")
            .is_some()
        {
            bail!(
                "task query response metadata_primary_compatibility_finding requires metadata_compatibility"
            );
        }
        if parsed.get("metadata_compatibility_findings").is_some() {
            bail!(
                "task query response metadata_compatibility_findings requires metadata_compatibility"
            );
        }
        return Ok(());
    };

    let Some(compatibility_obj) = compatibility.as_object() else {
        bail!("task query response metadata_compatibility must be a json object");
    };
    let Some(legacy_note_only) = compatibility_obj
        .get("legacy_note_only")
        .and_then(|v| v.as_bool())
    else {
        bail!("task query response metadata_compatibility missing boolean legacy_note_only");
    };
    let Some(canonical_core_fields) = compatibility_obj
        .get("canonical_core_fields")
        .and_then(|v| v.as_bool())
    else {
        bail!("task query response metadata_compatibility missing boolean canonical_core_fields");
    };
    let Some(complete_metering_snapshot) = compatibility_obj
        .get("complete_metering_snapshot")
        .and_then(|v| v.as_bool())
    else {
        bail!(
            "task query response metadata_compatibility missing boolean complete_metering_snapshot"
        );
    };

    let expected_runtime_compatible = canonical_core_fields && complete_metering_snapshot;
    let Some(reported_runtime_compatible) = parsed
        .get("metadata_runtime_compatible")
        .and_then(|v| v.as_bool())
    else {
        bail!(
            "task query response metadata_compatibility requires boolean metadata_runtime_compatible"
        );
    };
    if reported_runtime_compatible != expected_runtime_compatible {
        bail!(
            "task query response metadata_runtime_compatible mismatch: expected={}, got={}",
            expected_runtime_compatible,
            reported_runtime_compatible
        );
    }

    let expected_requires_governance_upgrade = legacy_note_only || !expected_runtime_compatible;
    let Some(reported_requires_governance_upgrade) = parsed
        .get("metadata_requires_governance_upgrade")
        .and_then(|v| v.as_bool())
    else {
        bail!(
            "task query response metadata_compatibility requires boolean metadata_requires_governance_upgrade"
        );
    };
    if reported_requires_governance_upgrade != expected_requires_governance_upgrade {
        bail!(
            "task query response metadata_requires_governance_upgrade mismatch: expected={}, got={}",
            expected_requires_governance_upgrade,
            reported_requires_governance_upgrade
        );
    }

    let mut expected = Vec::new();
    if legacy_note_only {
        expected.push("legacy_note_only_payload");
    }
    if !canonical_core_fields {
        expected.push("non_canonical_core_fields");
    }
    if !complete_metering_snapshot {
        expected.push("incomplete_metering_snapshot");
    }

    let expected_primary = expected.first().copied();
    let reported_primary = match parsed.get("metadata_primary_compatibility_finding") {
        Some(value) => Some(value.as_str().ok_or_else(|| {
            anyhow!("task query response metadata_primary_compatibility_finding must be a string")
        })?),
        None => None,
    };
    if reported_primary != expected_primary {
        bail!(
            "task query response metadata_primary_compatibility_finding mismatch: expected={:?}, got={:?}",
            expected_primary,
            reported_primary
        );
    }

    if let Some(findings) = parsed.get("metadata_compatibility_findings") {
        let Some(findings) = findings.as_array() else {
            bail!("task query response metadata_compatibility_findings must be a json array");
        };
        if findings.is_empty() {
            bail!("task query response metadata_compatibility_findings must be omitted when empty");
        }
        let actual = findings
            .iter()
            .map(|value| {
                value.as_str().ok_or_else(|| {
                    anyhow!(
                        "task query response metadata_compatibility_findings must contain strings"
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if actual != expected {
            bail!(
                "task query response metadata_compatibility_findings mismatch: expected={:?}, got={:?}",
                expected,
                actual
            );
        }
    } else if !expected.is_empty() {
        bail!(
            "task query response metadata_compatibility_findings required when compatibility implies findings"
        );
    }

    Ok(())
}

fn parse_task_query_response(raw: &str, requested_task_id: u64) -> Result<serde_json::Value> {
    let parsed: serde_json::Value = serde_json::from_str(raw)
        .map_err(|err| anyhow!("failed to parse task query response as json: {err}"))?;
    let Some(task_id) = parsed.get("task_id").and_then(|v| v.as_u64()) else {
        bail!("task query response missing numeric task_id");
    };
    if task_id != requested_task_id {
        bail!(
            "task query response task_id mismatch: requested={}, got={}",
            requested_task_id,
            task_id
        );
    }
    validate_task_query_metadata_compatibility(&parsed)?;
    Ok(parsed)
}

fn parse_events_query_response(raw: &str, requested_task_id: u64) -> Result<serde_json::Value> {
    let parsed: serde_json::Value = serde_json::from_str(raw)
        .map_err(|err| anyhow!("failed to parse events query response as json: {err}"))?;
    let Some(events) = parsed.as_array() else {
        bail!("events query response must be a json array");
    };
    for (idx, event) in events.iter().enumerate() {
        let Some(task_id) = event.get("task_id").and_then(|v| v.as_u64()) else {
            bail!("events query response item {} missing numeric task_id", idx);
        };
        if task_id != requested_task_id {
            bail!(
                "events query response task_id mismatch at item {}: requested={}, got={}",
                idx,
                requested_task_id,
                task_id
            );
        }
    }
    Ok(parsed)
}

fn events_query(task_id: u64, limit: usize) -> Result<serde_json::Value> {
    if let Ok(template) = std::env::var("TRNM_QUERY_EVENTS_CMD") {
        let cmd = tpl(
            tpl(template, "task_id", &task_id.to_string()),
            "limit",
            &limit.to_string(),
        );
        let raw = run_template_raw(&cmd)?;
        return parse_events_query_response(&raw, task_id);
    }

    let rpc_workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let cmd = format!(
        "cargo run -q -p trnm-rpc -- query-events {} --limit {}",
        task_id, limit
    );
    let (program, args) = parse_template_command(&cmd)?;
    let out = ProcCommand::new(program)
        .args(args)
        .current_dir(&rpc_workspace)
        .output()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        bail!(
            "events query command failed rc={}: {}{}",
            out.status.code().unwrap_or(1),
            stdout,
            stderr
        );
    }
    parse_events_query_response(&stdout, task_id)
}

fn parse_request_full_query_response(
    raw: &str,
    requested_request_id: &str,
) -> Result<serde_json::Value> {
    let parsed: serde_json::Value = serde_json::from_str(raw)
        .map_err(|err| anyhow!("failed to parse request-full response as json: {err}"))?;
    let Some(request) = parsed.get("request") else {
        bail!("request-full response missing request object");
    };
    let Some(request_id) = request.get("request_id").and_then(|v| v.as_str()) else {
        bail!("request-full response missing string request.request_id");
    };
    if request_id != requested_request_id {
        bail!(
            "request-full response request_id mismatch: requested={}, got={}",
            requested_request_id,
            request_id
        );
    }
    let Some(task_id) = request.get("task_id").and_then(|v| v.as_u64()) else {
        bail!("request-full response missing numeric request.task_id");
    };
    let Some(events) = parsed.get("events").and_then(|v| v.as_array()) else {
        bail!("request-full response missing events array");
    };
    for (idx, event) in events.iter().enumerate() {
        let Some(event_task_id) = event.get("task_id").and_then(|v| v.as_u64()) else {
            bail!(
                "request-full response event {} missing numeric task_id",
                idx
            );
        };
        if event_task_id != task_id {
            bail!(
                "request-full response event task_id mismatch at item {}: request.task_id={}, got={}",
                idx,
                task_id,
                event_task_id
            );
        }
    }
    Ok(parsed)
}

fn request_full_query(request_id: &str, limit: usize) -> Result<serde_json::Value> {
    if let Ok(template) = std::env::var("TRNM_QUERY_REQUEST_FULL_CMD") {
        let cmd = tpl(
            tpl(template, "request_id", request_id),
            "limit",
            &limit.to_string(),
        );
        let raw = run_template_raw(&cmd)?;
        return parse_request_full_query_response(&raw, request_id);
    }

    let rpc_workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let cmd = format!(
        "cargo run -q -p trnm-rpc -- query-request-full --request-id {} --limit {}",
        request_id, limit
    );
    let (program, args) = parse_template_command(&cmd)?;
    let out = ProcCommand::new(program)
        .args(args)
        .current_dir(&rpc_workspace)
        .output()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        bail!(
            "request-full query command failed rc={}: {}{}",
            out.status.code().unwrap_or(1),
            stdout,
            stderr
        );
    }
    parse_request_full_query_response(&stdout, request_id)
}

fn scalar_summary(value: Option<&serde_json::Value>) -> Option<String> {
    let value = value?;
    match value {
        serde_json::Value::Null => None,
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        other => Some(other.to_string()),
    }
}

fn scalar_summary_u128(value: Option<&serde_json::Value>) -> Option<u128> {
    let value = value?;
    match value {
        serde_json::Value::Number(n) => n.as_u64().map(|v| v as u128),
        serde_json::Value::String(s) => s.parse::<u128>().ok(),
        _ => None,
    }
}

fn ceil_mul_div_u128(value: u128, numerator: u128, denominator: u128) -> Option<u128> {
    if denominator == 0 {
        return None;
    }
    if value == 0 || numerator == 0 {
        return Some(0);
    }
    let product = value.checked_mul(numerator)?;
    let adjusted = product.checked_add(denominator.checked_sub(1)?)?;
    Some(adjusted / denominator)
}

fn push_metering_summary_lines(
    lines: &mut Vec<String>,
    indent: &str,
    metering: &serde_json::Value,
    event: Option<&serde_json::Value>,
) {
    let normalized_work_units_str =
        scalar_summary(metering.get("normalized_work_units")).unwrap_or_else(|| "-".into());
    let normalized_work_units = scalar_summary_u128(metering.get("normalized_work_units"));
    let workload_class =
        scalar_summary(metering.get("workload_class")).unwrap_or_else(|| "-".into());
    let metering_schema =
        scalar_summary(metering.get("metering_schema")).unwrap_or_else(|| "-".into());
    let receipt_hash = scalar_summary(metering.get("receipt_hash")).unwrap_or_else(|| "-".into());
    lines.push(format!(
        "{}metering work_units={} class={} schema={} receipt_hash={}",
        indent, normalized_work_units_str, workload_class, metering_schema, receipt_hash
    ));

    if let Some(policy) = metering.get("policy") {
        let floor_str =
            scalar_summary(policy.get("min_accept_work_units")).unwrap_or_else(|| "-".into());
        let floor = scalar_summary_u128(policy.get("min_accept_work_units"));
        let bounty_base_str = scalar_summary(policy.get("challenge_success_bounty_base"))
            .unwrap_or_else(|| "-".into());
        let bounty_base = scalar_summary_u128(policy.get("challenge_success_bounty_base"));
        let chall_num_str =
            scalar_summary(policy.get("challenge_success_bounty_per_work_unit_num"))
                .unwrap_or_else(|| "-".into());
        let chall_den_str =
            scalar_summary(policy.get("challenge_success_bounty_per_work_unit_den"))
                .unwrap_or_else(|| "-".into());
        let chall_num =
            scalar_summary_u128(policy.get("challenge_success_bounty_per_work_unit_num"));
        let chall_den =
            scalar_summary_u128(policy.get("challenge_success_bounty_per_work_unit_den"));
        let worker_bonus_num_str =
            scalar_summary(policy.get("worker_completion_bonus_per_work_unit_num"))
                .unwrap_or_else(|| "-".into());
        let worker_bonus_den_str =
            scalar_summary(policy.get("worker_completion_bonus_per_work_unit_den"))
                .unwrap_or_else(|| "-".into());
        let worker_bonus_num =
            scalar_summary_u128(policy.get("worker_completion_bonus_per_work_unit_num"));
        let worker_bonus_den =
            scalar_summary_u128(policy.get("worker_completion_bonus_per_work_unit_den"));
        let worker_rebate_num_str =
            scalar_summary(policy.get("worker_slash_rebate_per_work_unit_num"))
                .unwrap_or_else(|| "-".into());
        let worker_rebate_den_str =
            scalar_summary(policy.get("worker_slash_rebate_per_work_unit_den"))
                .unwrap_or_else(|| "-".into());
        let worker_rebate_num =
            scalar_summary_u128(policy.get("worker_slash_rebate_per_work_unit_num"));
        let worker_rebate_den =
            scalar_summary_u128(policy.get("worker_slash_rebate_per_work_unit_den"));

        lines.push(format!(
            "{}policy snapshot={} floor={} bounty_base={} chall_bonus={}/{} worker_bonus={}/{} worker_rebate={}/{}",
            indent,
            scalar_summary(policy.get("snapshot_version")).unwrap_or_else(|| "-".into()),
            floor_str,
            bounty_base_str,
            chall_num_str,
            chall_den_str,
            worker_bonus_num_str,
            worker_bonus_den_str,
            worker_rebate_num_str,
            worker_rebate_den_str,
        ));

        let path = metering
            .get("derived")
            .and_then(|derived| scalar_summary(derived.get("path")))
            .or_else(|| event.and_then(|e| scalar_summary(e.get("to_status"))))
            .unwrap_or_else(|| "-".into());
        let accept_floor_status = if let Some(derived) = metering.get("derived") {
            match scalar_summary(derived.get("accept_floor_pass")).as_deref() {
                Some("true") => match (normalized_work_units, floor) {
                    (Some(work_units), Some(floor)) => format!("pass({}>={})", work_units, floor),
                    _ => "pass".into(),
                },
                Some("false") => match (normalized_work_units, floor) {
                    (Some(work_units), Some(floor)) => format!("fail({}<{})", work_units, floor),
                    _ => "fail".into(),
                },
                _ => "-".into(),
            }
        } else if let Some(work_units) = normalized_work_units {
            match floor {
                Some(floor) => {
                    if work_units >= floor {
                        format!("pass({}>={})", work_units, floor)
                    } else {
                        format!("fail({}<{})", work_units, floor)
                    }
                }
                None => "-".into(),
            }
        } else {
            "-".into()
        };
        let challenge_metered_bonus = if let Some(derived) = metering.get("derived") {
            scalar_summary(derived.get("challenge_metered_bonus")).unwrap_or_else(|| "-".into())
        } else if let Some(work_units) = normalized_work_units {
            match (chall_num, chall_den) {
                (Some(num), Some(den)) => ceil_mul_div_u128(work_units, num, den)
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "-".into()),
                _ => "-".into(),
            }
        } else {
            "-".into()
        };
        let challenge_total = if let Some(derived) = metering.get("derived") {
            scalar_summary(derived.get("challenge_bonus_total")).unwrap_or_else(|| "-".into())
        } else if let Some(work_units) = normalized_work_units {
            match (bounty_base, chall_num, chall_den) {
                (Some(base), Some(num), Some(den)) => ceil_mul_div_u128(work_units, num, den)
                    .and_then(|bonus| base.checked_add(bonus))
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "-".into()),
                _ => "-".into(),
            }
        } else {
            "-".into()
        };
        let worker_completion_bonus = if let Some(derived) = metering.get("derived") {
            scalar_summary(derived.get("worker_completion_bonus")).unwrap_or_else(|| "-".into())
        } else if let Some(work_units) = normalized_work_units {
            match (worker_bonus_num, worker_bonus_den) {
                (Some(num), Some(den)) => ceil_mul_div_u128(work_units, num, den)
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "-".into()),
                _ => "-".into(),
            }
        } else {
            "-".into()
        };
        let worker_slash_rebate = if let Some(derived) = metering.get("derived") {
            scalar_summary(derived.get("worker_slash_rebate")).unwrap_or_else(|| "-".into())
        } else if let Some(work_units) = normalized_work_units {
            match (worker_rebate_num, worker_rebate_den) {
                (Some(num), Some(den)) => ceil_mul_div_u128(work_units, num, den)
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "-".into()),
                _ => "-".into(),
            }
        } else {
            "-".into()
        };
        lines.push(format!(
            "{}derived path={} accept_floor={} challenge_bonus_total={} (metered={}) worker_completion_bonus={} worker_slash_rebate={}",
            indent,
            path,
            accept_floor_status,
            challenge_total,
            challenge_metered_bonus,
            worker_completion_bonus,
            worker_slash_rebate,
        ));
    }
}

fn render_events_query_summary(parsed: &serde_json::Value) -> Result<String> {
    let events = parsed
        .as_array()
        .ok_or_else(|| anyhow!("events summary requires a json array"))?;
    let mut lines = vec![format!("events_total={}", events.len())];
    for (idx, event) in events.iter().enumerate() {
        lines.push(format!(
            "[{}] {} {}->{} tx_id={} block_height={} actor={} resolution={} bond_disposition={}",
            idx,
            scalar_summary(event.get("event_type")).unwrap_or_else(|| "-".into()),
            scalar_summary(event.get("from_status")).unwrap_or_else(|| "-".into()),
            scalar_summary(event.get("to_status")).unwrap_or_else(|| "-".into()),
            scalar_summary(event.get("tx_id")).unwrap_or_else(|| "-".into()),
            scalar_summary(event.get("block_height")).unwrap_or_else(|| "-".into()),
            scalar_summary(event.get("actor")).unwrap_or_else(|| "-".into()),
            scalar_summary(event.get("resolution_code")).unwrap_or_else(|| "-".into()),
            scalar_summary(event.get("bond_disposition")).unwrap_or_else(|| "-".into()),
        ));
        if let Some(metering) = event.get("metering") {
            push_metering_summary_lines(&mut lines, "  ", metering, Some(event));
        }
    }
    Ok(lines.join(
        "
",
    ))
}

fn render_request_full_query_summary(parsed: &serde_json::Value) -> Result<String> {
    let request = parsed
        .get("request")
        .ok_or_else(|| anyhow!("request-full summary missing request"))?;
    let request_id = scalar_summary(request.get("request_id"))
        .ok_or_else(|| anyhow!("request-full summary missing request_id"))?;
    let task_id = scalar_summary(request.get("task_id"))
        .ok_or_else(|| anyhow!("request-full summary missing task_id"))?;
    let status = scalar_summary(request.get("status")).unwrap_or_else(|| "-".into());
    let channel = scalar_summary(request.get("channel")).unwrap_or_else(|| "-".into());
    let session_id = scalar_summary(request.get("session_id")).unwrap_or_else(|| "-".into());
    let verifier_status =
        scalar_summary(parsed.get("verifier_status")).unwrap_or_else(|| "-".into());
    let resolution_code =
        scalar_summary(parsed.get("resolution_code")).unwrap_or_else(|| "-".into());
    let result_hash = scalar_summary(parsed.get("result_hash")).unwrap_or_else(|| "-".into());
    let commit_tx_hash = scalar_summary(parsed.get("commit_tx_hash")).unwrap_or_else(|| "-".into());
    let reveal_tx_hash = scalar_summary(parsed.get("reveal_tx_hash")).unwrap_or_else(|| "-".into());
    let events = parsed
        .get("events")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("request-full summary missing events"))?;

    let mut lines = vec![
        format!("request_id={}", request_id),
        format!("task_id={}", task_id),
        format!(
            "status={} verifier_status={} resolution_code={}",
            status, verifier_status, resolution_code
        ),
        format!("channel={} session_id={}", channel, session_id),
        format!(
            "commit_tx_hash={} reveal_tx_hash={} result_hash={}",
            commit_tx_hash, reveal_tx_hash, result_hash
        ),
        format!("events_total={}", events.len()),
    ];
    for (idx, event) in events.iter().enumerate() {
        lines.push(format!(
            "[{}] {} {}->{} tx_id={} actor={} resolution={} bond_disposition={}",
            idx,
            scalar_summary(event.get("event_type")).unwrap_or_else(|| "-".into()),
            scalar_summary(event.get("from_status")).unwrap_or_else(|| "-".into()),
            scalar_summary(event.get("to_status")).unwrap_or_else(|| "-".into()),
            scalar_summary(event.get("tx_id")).unwrap_or_else(|| "-".into()),
            scalar_summary(event.get("actor")).unwrap_or_else(|| "-".into()),
            scalar_summary(event.get("resolution_code")).unwrap_or_else(|| "-".into()),
            scalar_summary(event.get("bond_disposition")).unwrap_or_else(|| "-".into()),
        ));
        if let Some(metering) = event.get("metering") {
            push_metering_summary_lines(&mut lines, "  ", metering, Some(event));
        }
    }
    Ok(lines.join(
        "
",
    ))
}

fn task_query(task_id: u64) -> Result<serde_json::Value> {
    if let Ok(template) = std::env::var("TRNM_QUERY_TASK_CMD") {
        let cmd = tpl(template, "task_id", &task_id.to_string());
        let raw = run_template_raw(&cmd)?;
        return parse_task_query_response(&raw, task_id);
    }

    let rpc_workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let cmd = format!("cargo run -q -p trnm-rpc -- query-task {}", task_id);
    let (program, args) = parse_template_command(&cmd)?;
    let out = ProcCommand::new(program)
        .args(args)
        .current_dir(&rpc_workspace)
        .output()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        bail!(
            "task query command failed rc={}: {}{}",
            out.status.code().unwrap_or(1),
            stdout,
            stderr
        );
    }
    parse_task_query_response(&stdout, task_id)
}

fn hash(parts: &[&str]) -> String {
    let mut h = Sha256::new();
    h.update(parts.join("|").as_bytes());
    hex::encode(h.finalize())
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

fn is_hidden_env_wrapper(c: char) -> bool {
    c.is_whitespace()
        || c.is_control()
        || matches!(
            c,
            '\u{200B}'
                | '\u{200C}'
                | '\u{200D}'
                | '\u{200E}'
                | '\u{200F}'
                | '\u{061C}'
                | '\u{2060}'
                | '\u{FEFF}'
                | '\u{202A}'
                | '\u{202B}'
                | '\u{202C}'
                | '\u{202D}'
                | '\u{202E}'
                | '\u{2066}'
                | '\u{2067}'
                | '\u{2068}'
                | '\u{2069}'
        )
}

fn is_single_sided_env_quote(c: char) -> bool {
    matches!(
        c,
        '"' | '\''
            | '`'
            | '“'
            | '”'
            | '‘'
            | '’'
            | '«'
            | '»'
            | '‹'
            | '›'
            | '「'
            | '」'
            | '『'
            | '』'
            | '《'
            | '》'
            | '〈'
            | '〉'
            | '｢'
            | '｣'
            | '（'
            | '）'
            | '［'
            | '］'
            | '｛'
            | '｝'
            | '<'
            | '>'
            | '＜'
            | '＞'
            | '【'
            | '】'
            | '〔'
            | '〕'
            | '〖'
            | '〗'
            | '〘'
            | '〙'
            | '〚'
            | '〛'
            | '〝'
            | '〞'
            | '〟'
    )
}

fn normalize_wallet_store_env(raw: &str) -> Option<&str> {
    let mut normalized = raw.trim_matches(is_hidden_env_wrapper);
    loop {
        let Some(first) = normalized.chars().next() else {
            return None;
        };
        let Some(last) = normalized.chars().last() else {
            return None;
        };
        let wrapped_by_quotes = matches!(
            (Some(first), Some(last)),
            (Some('"'), Some('"'))
                | (Some('\''), Some('\''))
                | (Some('`'), Some('`'))
                | (Some('“'), Some('”'))
                | (Some('‘'), Some('’'))
                | (Some('«'), Some('»'))
                | (Some('‹'), Some('›'))
                | (Some('「'), Some('」'))
                | (Some('『'), Some('』'))
                | (Some('《'), Some('》'))
                | (Some('〈'), Some('〉'))
                | (Some('｢'), Some('｣'))
                | (Some('（'), Some('）'))
                | (Some('［'), Some('］'))
                | (Some('｛'), Some('｝'))
                | (Some('<'), Some('>'))
                | (Some('＜'), Some('＞'))
                | (Some('【'), Some('】'))
                | (Some('〔'), Some('〕'))
                | (Some('〖'), Some('〗'))
                | (Some('〘'), Some('〙'))
                | (Some('〚'), Some('〛'))
                | (Some('〝'), Some('〞'))
                | (Some('〟'), Some('〟'))
        );
        if wrapped_by_quotes {
            normalized = normalized[first.len_utf8()..normalized.len() - last.len_utf8()]
                .trim_matches(is_hidden_env_wrapper);
            continue;
        }

        let trimmed_single_sided = normalized
            .trim_start_matches(is_single_sided_env_quote)
            .trim_end_matches(is_single_sided_env_quote)
            .trim_matches(is_hidden_env_wrapper);
        if trimmed_single_sided.len() == normalized.len() {
            break;
        }
        normalized = trimmed_single_sided;
    }
    if normalized.is_empty()
        || normalized
            .chars()
            .any(|c| c.is_whitespace() || contains_hidden_or_control(c))
    {
        return None;
    }
    Some(normalized)
}

fn path_text_has_dot_segments(path: &Path) -> bool {
    let raw = path.to_string_lossy();
    ["/./", "/../", "\\.\\", "\\..\\"]
        .iter()
        .any(|needle| raw.contains(needle))
        || ["/.", "/..", "\\.", "\\.."]
            .iter()
            .any(|suffix| raw.ends_with(suffix))
}

fn wallet_store_path_is_safe(path: &Path) -> bool {
    use std::path::Component;

    path.is_absolute()
        && path.parent().is_some()
        && !path_text_has_dot_segments(path)
        && path.to_string_lossy().chars().all(|c| {
            !c.is_whitespace() && !contains_hidden_or_control(c)
        })
        && !path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
}

fn ensure_wallet_store_path_is_safe(store: &Path) -> Result<()> {
    if !wallet_store_path_is_safe(store) {
        bail!(
            "wallet store '{}' must be an absolute normalized path without '.' or '..' segments",
            store.display()
        );
    }
    Ok(())
}

fn ensure_wallet_store_ancestors_not_symlink(store: &Path) -> Result<()> {
    for ancestor in store.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(meta) if meta.file_type().is_symlink() => {
                bail!(
                    "wallet store '{}' traverses symlinked ancestor '{}'; refusing non-canonical keystore path",
                    store.display(),
                    ancestor.display()
                );
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(anyhow!(
                    "failed to inspect wallet store ancestor '{}' for symlink safety: {err}",
                    ancestor.display()
                ));
            }
        }
    }
    Ok(())
}

fn wallet_store_path_and_ancestors_are_symlink_free(store: &Path) -> bool {
    std::iter::once(store)
        .chain(store.ancestors().skip(1))
        .all(|candidate| match fs::symlink_metadata(candidate) {
            Ok(meta) => !meta.file_type().is_symlink(),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => true,
            Err(_) => false,
        })
}

fn default_wallet_store() -> PathBuf {
    if let Ok(p) = std::env::var("TRNM_WALLET_STORE") {
        if let Some(normalized) = normalize_wallet_store_env(&p) {
            let candidate = PathBuf::from(normalized);
            if wallet_store_path_is_safe(&candidate)
                && wallet_store_path_and_ancestors_are_symlink_free(&candidate)
            {
                return candidate;
            }
        }
    }

    let home_root = std::env::var("HOME")
        .ok()
        .and_then(|raw| normalize_wallet_store_env(&raw).map(PathBuf::from))
        .filter(|path| wallet_store_path_is_safe(path) && wallet_store_path_and_ancestors_are_symlink_free(path))
        .or_else(|| {
            std::env::current_dir().ok().filter(|path| {
                wallet_store_path_is_safe(path) && wallet_store_path_and_ancestors_are_symlink_free(path)
            })
        })
        .unwrap_or_else(|| PathBuf::from("/"));

    home_root.join(".trnm").join("wallets")
}

fn resolve_wallet_store(store: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(store) = store {
        return Ok(store);
    }

    if let Ok(raw) = std::env::var("TRNM_WALLET_STORE") {
        let Some(normalized) = normalize_wallet_store_env(&raw) else {
            bail!(
                "TRNM_WALLET_STORE is set but invalid; refusing ambiguous keystore path fallback"
            );
        };
        let candidate = PathBuf::from(normalized);
        if !wallet_store_path_is_safe(&candidate)
            || !wallet_store_path_and_ancestors_are_symlink_free(&candidate)
        {
            bail!(
                "TRNM_WALLET_STORE '{}' must be an absolute normalized symlink-free path",
                candidate.display()
            );
        }
        return Ok(candidate);
    }

    Ok(default_wallet_store())
}

fn wallet_file(store: &Path, name: &str) -> PathBuf {
    store.join(format!("{}.key", name))
}

fn contains_hidden_or_control(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}'
                | '\u{200B}'
                | '\u{200C}'
                | '\u{200D}'
                | '\u{200E}'
                | '\u{200F}'
                | '\u{2060}'
                | '\u{FEFF}'
                | '\u{202A}'
                | '\u{202B}'
                | '\u{202C}'
                | '\u{202D}'
                | '\u{202E}'
                | '\u{2066}'
                | '\u{2067}'
                | '\u{2068}'
                | '\u{2069}'
        )
}

fn ensure_sign_message(message: &str) -> Result<()> {
    if message.is_empty() {
        bail!("sign message must not be empty");
    }
    if message.len() > 4096 {
        bail!("sign message must be <= 4096 bytes");
    }
    if message
        .chars()
        .next()
        .is_some_and(|c| c.is_whitespace())
        || message
            .chars()
            .next_back()
            .is_some_and(|c| c.is_whitespace())
    {
        bail!("sign message must not start or end with whitespace");
    }
    if message.chars().any(|c| {
        c == '\r'
            || c == '\n'
            || contains_hidden_or_control(c)
            || (c.is_whitespace() && c != ' ')
    }) {
        bail!(
            "sign message must be single-line printable text without control characters and with only interior ASCII spaces"
        );
    }
    Ok(())
}

fn ensure_wallet_name(name: &str) -> Result<()> {
    let has_hidden_or_whitespace = name
        .chars()
        .any(|c| c.is_whitespace() || contains_hidden_or_control(c));
    let uppercase = name.to_ascii_uppercase();
    let is_windows_reserved_device = matches!(
        uppercase.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    );

    if name.is_empty()
        || name == "."
        || name == ".."
        || name.starts_with('.')
        || name.ends_with('.')
        || name.starts_with('-')
        || name.starts_with(['‐', '‑', '‒', '–', '—', '―', '−', '﹣', '－'])
        || name.contains(['/', '\\', ':', '=', '|', '&', '$', '*', '?', '!'])
        || name.contains(['‐', '‑', '‒', '–', '—', '―', '−', '﹣', '－'])
        || name.contains(['：', '＝', '｜', '＆', '？', '，', '；', '！'])
        || name.contains(['∕', '⁄', '／', '＼', '⧵', '⟋', '⟍'])
        || name.contains(['.', '．', '。', '｡', '﹒', '․'])
        || name.contains([
            '"', '\'', '`', '<', '>', '(', ')', '[', ']', '{', '}', ',', ';',
        ])
        || name.contains([
            '“', '”', '‘', '’', '«', '»', '‹', '›', '「', '」', '『', '』', '《', '》',
            '〈', '〉', '｢', '｣', '（', '）', '［', '］', '｛', '｝', '＜', '＞', '【', '】',
            '〔', '〕', '〖', '〗', '〘', '〙', '〚', '〛', '〝', '〞', '〟',
        ])
        || has_hidden_or_whitespace
        || is_windows_reserved_device
    {
        bail!(
            "invalid wallet name '{}': use a simple local name without path separators or reserved device names",
            name
        );
    }
    Ok(())
}

fn ensure_hex_32_bytes(s: &str) -> Result<String> {
    let cleaned = s
        .trim_matches(|c: char| {
            c.is_whitespace()
                || c.is_control()
                || matches!(
                    c,
                    '"' | '\'' | '`' | '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}'
                )
                || matches!(
                    c,
                    '\u{00AD}'
                        | '\u{061C}'
                        | '\u{180E}'
                        | '\u{200B}'
                        | '\u{200C}'
                        | '\u{200D}'
                        | '\u{2060}'
                        | '\u{FEFF}'
                        | '\u{202A}'
                        | '\u{202B}'
                        | '\u{202C}'
                        | '\u{202D}'
                        | '\u{202E}'
                        | '\u{2066}'
                        | '\u{2067}'
                        | '\u{2068}'
                        | '\u{2069}'
                )
        })
        .trim();
    let x = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
        .unwrap_or(cleaned)
        .to_lowercase();
    if x.len() != 64 {
        bail!("private key hex must be 32 bytes (64 hex chars)");
    }
    let _ = hex::decode(&x).map_err(|e| anyhow!("invalid private_key_hex: {e}"))?;
    Ok(x)
}

#[cfg(unix)]
fn ensure_owner_only_permissions(meta: &fs::Metadata, path: &Path, kind: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "{} '{}' has insecure permissions {:o}; expected owner-only access",
            kind,
            path.display(),
            mode
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_owner_only_permissions(_meta: &fs::Metadata, _path: &Path, _kind: &str) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_owner_only_permissions(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_only_permissions(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

fn write_key(store: &Path, name: &str, priv_hex: &str) -> Result<PathBuf> {
    ensure_wallet_name(name)?;
    let normalized_priv_hex = ensure_hex_32_bytes(priv_hex)?;
    ensure_wallet_store_path_is_safe(store)?;
    ensure_wallet_store_ancestors_not_symlink(store)?;
    if let Ok(store_meta) = fs::symlink_metadata(store) {
        if store_meta.file_type().is_symlink() {
            bail!(
                "wallet store '{}' is a symlink; refusing to write keys through non-regular wallet store path",
                store.display()
            );
        }
        if !store_meta.file_type().is_dir() {
            bail!(
                "wallet store '{}' is not a directory; refusing to write keys through non-regular wallet store path",
                store.display()
            );
        }
        ensure_owner_only_permissions(&store_meta, store, "wallet store")?;
    }
    fs::create_dir_all(store)?;
    set_owner_only_permissions(store, 0o700)?;
    let f = wallet_file(store, name);
    if fs::symlink_metadata(&f).is_ok() {
        bail!(
            "wallet '{}' already exists at {}; refusing to overwrite existing key",
            name,
            f.display()
        );
    }
    fs::write(&f, format!("{}\n", normalized_priv_hex))?;
    set_owner_only_permissions(&f, 0o600)?;
    Ok(f)
}

fn read_key(store: &Path, name: &str) -> Result<String> {
    ensure_wallet_name(name)?;
    ensure_wallet_store_path_is_safe(store)?;
    ensure_wallet_store_ancestors_not_symlink(store)?;
    let store_meta = fs::symlink_metadata(store)
        .map_err(|e| anyhow!("failed to inspect wallet store '{}': {e}", store.display()))?;
    if store_meta.file_type().is_symlink() {
        bail!(
            "wallet store '{}' is a symlink; refusing to read keys through non-regular wallet store path",
            store.display()
        );
    }
    if !store_meta.file_type().is_dir() {
        bail!(
            "wallet store '{}' is not a directory; refusing to read keys through non-regular wallet store path",
            store.display()
        );
    }
    ensure_owner_only_permissions(&store_meta, store, "wallet store")?;
    let f = wallet_file(store, name);
    let file_meta = fs::symlink_metadata(&f)
        .map_err(|e| anyhow!("failed to inspect wallet '{}' at {}: {e}", name, f.display()))?;
    if file_meta.file_type().is_symlink() {
        bail!(
            "wallet '{}' at {} is a symlink; refusing to read key through non-regular wallet file path",
            name,
            f.display()
        );
    }
    if !file_meta.file_type().is_file() {
        bail!(
            "wallet '{}' at {} is not a regular file; refusing to read key through non-regular wallet file path",
            name,
            f.display()
        );
    }
    ensure_owner_only_permissions(&file_meta, &f, "wallet")?;
    let raw = fs::read_to_string(&f)
        .map_err(|e| anyhow!("failed to read wallet '{}' at {}: {e}", name, f.display()))?;
    ensure_hex_32_bytes(raw.trim())
}

fn derive_address_from_priv_hex(priv_hex: &str) -> Result<String> {
    let key = hex::decode(priv_hex)?;
    let key_bytes: [u8; 32] = key
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("private key hex must be 32 bytes (64 hex chars)"))?;
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let digest = Sha256::digest(signing_key.verifying_key().as_bytes());
    let addr_hex = hex::encode(&digest[..20]);
    Ok(format!("trnm1{}", addr_hex))
}

fn is_unsafe_sign_message_char(c: char) -> bool {
    (c.is_whitespace() && c != ' ')
        || c.is_control()
        || matches!(
            c,
            '\u{00ad}'
                | '\u{061c}'
                | '\u{180e}'
                | '\u{200b}'
                | '\u{200c}'
                | '\u{200d}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{2060}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
                | '\u{feff}'
        )
}

fn ensure_safe_sign_message(message: &str) -> Result<()> {
    if message.is_empty() {
        bail!("wallet sign message must not be empty");
    }
    if message.len() > 4096 {
        bail!("wallet sign message must be <= 4096 bytes");
    }
    if message.trim() != message {
        bail!(
            "wallet sign message contains leading or trailing whitespace; refusing ambiguous offline-signing output"
        );
    }
    if message.chars().any(|c| {
        is_unsafe_sign_message_char(c) || !c.is_ascii() || (!c.is_ascii_graphic() && c != ' ')
    }) {
        bail!(
            "wallet sign message must be single-line ASCII printable text with only interior ASCII spaces; refusing unsafe offline-signing output"
        );
    }
    Ok(())
}

fn random_priv_hex() -> Result<String> {
    let mut b = [0u8; 32];
    let mut f = fs::File::open("/dev/urandom")?;
    f.read_exact(&mut b)?;
    Ok(hex::encode(b))
}

fn normalize_tx_hash(raw: &str) -> Option<String> {
    let mut cleaned = raw.to_string();

    loop {
        let before = cleaned.len();
        cleaned = cleaned
            .trim_matches(|c: char| {
                c.is_whitespace()
                    || c.is_control()
                    || matches!(
                        c,
                        ',' | ';'
                            | ':'
                            | '('
                            | ')'
                            | '['
                            | ']'
                            | '{'
                            | '}'
                            | '<'
                            | '>'
                            | '"'
                            | '\''
                            | '`'
                            | '.'
                            | '!'
                            | '?'
                            | '“'
                            | '”'
                            | '‘'
                            | '’'
                            | '«'
                            | '»'
                            | '‹'
                            | '›'
                            | '（'
                            | '）'
                            | '［'
                            | '］'
                            | '｛'
                            | '｝'
                            | '＜'
                            | '＞'
                            | '「'
                            | '」'
                            | '『'
                            | '』'
                            | '《'
                            | '》'
                            | '〈'
                            | '〉'
                            | '｢'
                            | '｣'
                            | '【'
                            | '】'
                            | '〔'
                            | '〕'
                            | '〖'
                            | '〗'
                            | '〘'
                            | '〙'
                            | '〚'
                            | '〛'
                            | '〝'
                            | '〞'
                            | '〟'
                            | '，'
                            | '；'
                            | '：'
                            | '！'
                            | '？'
                            | '。'
                            | '｡'
                            | '．'
                            | '﹒'
                            | '․'
                    )
                    || matches!(
                        c,
                        '\u{061C}'
                            | '\u{200B}'
                            | '\u{200C}'
                            | '\u{200D}'
                            | '\u{200E}'
                            | '\u{200F}'
                            | '\u{2060}'
                            | '\u{FEFF}'
                            | '\u{202A}'
                            | '\u{202B}'
                            | '\u{202C}'
                            | '\u{202D}'
                            | '\u{202E}'
                            | '\u{2066}'
                            | '\u{2067}'
                            | '\u{2068}'
                            | '\u{2069}'
                    )
            })
            .to_string();

        if cleaned.len() == before {
            break;
        }
    }

    if cleaned.starts_with("0X") {
        cleaned.replace_range(..2, "0x");
    }
    cleaned = cleaned.to_ascii_lowercase();

    if cleaned.starts_with("0x") && cleaned.len() > 2 {
        let body = &cleaned[2..];
        if body.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(cleaned);
        }
        return None;
    }

    // Some adapters emit tx_hash without 0x prefix. Accept only plausible
    // hex-like values to avoid false positives from generic words.
    let is_hex_like = cleaned.chars().all(|c| c.is_ascii_hexdigit());
    if is_hex_like && cleaned.len() >= 6 {
        return Some(cleaned);
    }

    None
}

fn json_value_tx_hash(v: &serde_json::Value) -> Option<String> {
    let direct = [
        "tx_hash",
        "txhash",
        "txHash",
        "transaction_hash",
        "transactionHash",
    ];
    for key in direct {
        if let Some(h) = v.get(key).and_then(|x| x.as_str()) {
            if let Some(normalized) = normalize_tx_hash(h) {
                return Some(normalized);
            }
        }
    }

    for key in ["result", "tx_response", "txResponse", "response", "data"] {
        if let Some(found) = v.get(key).and_then(json_value_tx_hash) {
            return Some(found);
        }
    }

    None
}

fn is_text_tx_hash_key(key: &str) -> bool {
    let canonical = key
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect::<String>();
    matches!(canonical.as_str(), "txhash" | "transactionhash")
}

fn extract_tx_hash(text: &str) -> Option<String> {
    for line in text.lines() {
        if let Some((key, value)) = parse_kv_line(line) {
            if is_text_tx_hash_key(&key) {
                if let Some(normalized) = normalize_tx_hash(&value) {
                    return Some(normalized);
                }
            }
        }

        let tokens = line.split_whitespace().collect::<Vec<_>>();
        if let Some(v) = tokens.iter().find_map(|w| {
            let trimmed = w.trim_matches(|c: char| {
                c.is_ascii_whitespace()
                    || matches!(c, ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>')
            });
            let (k, v) = trimmed
                .split_once('=')
                .or_else(|| trimmed.split_once(':'))
                .or_else(|| trimmed.split_once('＝'))
                .or_else(|| trimmed.split_once('：'))?;
            let key = k.trim_matches(|c: char| {
                c.is_ascii_whitespace()
                    || matches!(c, ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>')
            });
            is_text_tx_hash_key(key).then(|| normalize_tx_hash(v)).flatten()
        }) {
            return Some(v);
        }

        for window in tokens.windows(3) {
            let key = window[0].trim_matches(|c: char| {
                c.is_ascii_whitespace()
                    || matches!(c, ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>')
            });
            let sep = window[1].trim();
            let value = window[2].trim_matches(|c: char| {
                c.is_ascii_whitespace()
                    || matches!(c, ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>')
            });
            if !matches!(sep, "=" | ":" | "＝" | "：") {
                continue;
            }
            if is_text_tx_hash_key(key) {
                if let Some(normalized) = normalize_tx_hash(value) {
                    return Some(normalized);
                }
            }
        }

        for window in tokens.windows(4) {
            let key = format!("{} {}", window[0], window[1]);
            let sep = window[2].trim();
            let value = window[3].trim_matches(|c: char| {
                c.is_ascii_whitespace()
                    || matches!(c, ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>')
            });
            if !matches!(sep, "=" | ":" | "＝" | "：") {
                continue;
            }
            if is_text_tx_hash_key(&key) {
                if let Some(normalized) = normalize_tx_hash(value) {
                    return Some(normalized);
                }
            }
        }
    }

    if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
        return json_value_tx_hash(&v);
    }

    None
}

fn parse_template_command(cmd: &str) -> Result<(String, Vec<String>)> {
    let parts = shell_words::split(cmd)
        .map_err(|e| anyhow!("invalid template command (shell-words parse failed): {e}"))?;
    let Some((program, args)) = parts.split_first() else {
        bail!("template command must not be empty");
    };
    Ok((program.clone(), args.to_vec()))
}

fn run_template(cmd: &str) -> Result<String> {
    let (program, args) = parse_template_command(cmd)?;
    let out = ProcCommand::new(&program).args(&args).output()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let merged = format!("{}\n{}", stdout, stderr);

    if !out.status.success() {
        bail!(
            "tx command failed rc={}: {}",
            out.status.code().unwrap_or(1),
            merged
        );
    }

    if let Some(txh) = extract_tx_hash(&merged) {
        return Ok(txh);
    }

    Ok(format!("0x{}", hash(&["fallback", &merged])))
}

fn run_template_raw(cmd: &str) -> Result<String> {
    let (program, args) = parse_template_command(cmd)?;
    let out = ProcCommand::new(&program).args(&args).output()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        bail!(
            "query command failed rc={}: {}{}",
            out.status.code().unwrap_or(1),
            stdout,
            stderr
        );
    }

    let mut merged = stdout.to_string();
    merged.push_str(&stderr);
    Ok(merged)
}

fn trim_kv_key_noise(raw: &str) -> &str {
    raw.trim_matches(|c: char| {
        c.is_whitespace()
            || c.is_control()
            || matches!(
                c,
                ',' | ';' | '{' | '}' | '[' | ']' | '(' | ')' | '<' | '>'
                    | '，' | '；' | '：' | '（' | '）' | '［' | '］' | '｛' | '｝' | '＜' | '＞'
                    | '「' | '」' | '『' | '』' | '《' | '》' | '〈' | '〉' | '｢' | '｣' | '【' | '】'
            )
            || matches!(
                c,
                '\u{200B}'
                    | '\u{200C}'
                    | '\u{200D}'
                    | '\u{200E}'
                    | '\u{200F}'
                    | '\u{061C}'
                    | '\u{2060}'
                    | '\u{FEFF}'
                    | '\u{202A}'
                    | '\u{202B}'
                    | '\u{202C}'
                    | '\u{202D}'
                    | '\u{202E}'
                    | '\u{2066}'
                    | '\u{2067}'
                    | '\u{2068}'
                    | '\u{2069}'
            )
    })
}

fn parse_kv_line(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim();
    let (key, value) = if let Some((k, v)) = trimmed.split_once('=') {
        (k.trim(), v.trim())
    } else if let Some((k, v)) = trimmed.split_once(':') {
        (k.trim(), v.trim())
    } else if let Some((k, v)) = trimmed.split_once('＝') {
        (k.trim(), v.trim())
    } else if let Some((k, v)) = trimmed.split_once('：') {
        (k.trim(), v.trim())
    } else {
        return None;
    };

    let key = key.trim_matches(|c: char| {
        c.is_whitespace()
            || c.is_control()
            || matches!(
                c,
                ',' | ';'
                    | '{'
                    | '}'
                    | '['
                    | ']'
                    | '('
                    | ')'
                    | '<'
                    | '>'
                    | '，'
                    | '；'
                    | '：'
                    | '（'
                    | '）'
                    | '［'
                    | '］'
                    | '｛'
                    | '｝'
                    | '＜'
                    | '＞'
                    | '「'
                    | '」'
                    | '『'
                    | '』'
                    | '《'
                    | '》'
                    | '〈'
                    | '〉'
                    | '｢'
                    | '｣'
                    | '【'
                    | '】'
            )
    });
    let value = value.trim_matches(|c: char| {
        c.is_whitespace()
            || c.is_control()
            || matches!(
                c,
                ',' | ';'
                    | '{'
                    | '}'
                    | '['
                    | ']'
                    | '('
                    | ')'
                    | '<'
                    | '>'
                    | '，'
                    | '；'
                    | '：'
                    | '（'
                    | '）'
                    | '［'
                    | '］'
                    | '｛'
                    | '｝'
                    | '＜'
                    | '＞'
                    | '「'
                    | '」'
                    | '『'
                    | '』'
                    | '《'
                    | '》'
                    | '〈'
                    | '〉'
                    | '｢'
                    | '｣'
                    | '【'
                    | '】'
            )
    });

    if key.is_empty() {
        return None;
    }

    Some((key.to_ascii_lowercase(), value.to_string()))
}

fn parse_inline_kv_token(token: &str) -> Option<(String, String)> {
    let trimmed = token.trim_matches(|c: char| {
        c.is_whitespace()
            || c.is_control()
            || matches!(
                c,
                ',' | ';'
                    | '{'
                    | '}'
                    | '['
                    | ']'
                    | '('
                    | ')'
                    | '<'
                    | '>'
                    | '，'
                    | '；'
                    | '：'
                    | '（'
                    | '）'
                    | '［'
                    | '］'
                    | '｛'
                    | '｝'
                    | '＜'
                    | '＞'
                    | '「'
                    | '」'
                    | '『'
                    | '』'
                    | '《'
                    | '》'
                    | '〈'
                    | '〉'
                    | '｢'
                    | '｣'
                    | '【'
                    | '】'
            )
            || matches!(
                c,
                '\u{200B}'
                    | '\u{200C}'
                    | '\u{200D}'
                    | '\u{200E}'
                    | '\u{200F}'
                    | '\u{061C}'
                    | '\u{2060}'
                    | '\u{FEFF}'
                    | '\u{202A}'
                    | '\u{202B}'
                    | '\u{202C}'
                    | '\u{202D}'
                    | '\u{202E}'
                    | '\u{2066}'
                    | '\u{2067}'
                    | '\u{2068}'
                    | '\u{2069}'
            )
    });
    let (key, value) = if let Some((k, v)) = trimmed.split_once('=') {
        (k.trim(), v.trim())
    } else if let Some((k, v)) = trimmed.split_once(':') {
        (k.trim(), v.trim())
    } else if let Some((k, v)) = trimmed.split_once('＝') {
        (k.trim(), v.trim())
    } else if let Some((k, v)) = trimmed.split_once('：') {
        (k.trim(), v.trim())
    } else {
        return None;
    };

    let key = trim_kv_key_noise(key);

    if key.is_empty() || value.is_empty() {
        return None;
    }

    Some((
        key.to_ascii_lowercase(),
        value
            .trim_matches(|c: char| {
                c.is_whitespace()
                    || c.is_control()
                    || matches!(
                        c,
                        ',' | ';'
                            | '{'
                            | '}'
                            | '['
                            | ']'
                            | '('
                            | ')'
                            | '<'
                            | '>'
                            | '，'
                            | '；'
                            | '：'
                            | '（'
                            | '）'
                            | '［'
                            | '］'
                            | '｛'
                            | '｝'
                            | '＜'
                            | '＞'
                            | '「'
                            | '」'
                            | '『'
                            | '』'
                            | '《'
                            | '》'
                            | '〈'
                            | '〉'
                            | '｢'
                            | '｣'
                            | '【'
                            | '】'
                    )
            })
            .trim_matches(|c| matches!(c, '"' | '\'' | '`' | '“' | '”' | '‘' | '’'))
            .to_string(),
    ))
}

fn normalize_tx_status(raw: &str) -> Option<String> {
    let cleaned = raw
        .trim()
        .trim_matches(|c: char| {
            c.is_whitespace()
                || c.is_control()
                || matches!(
                    c,
                    '"' | '\''
                        | '`'
                        | '“'
                        | '”'
                        | '‘'
                        | '’'
                        | '('
                        | ')'
                        | '['
                        | ']'
                        | '{'
                        | '}'
                        | '<'
                        | '>'
                        | ','
                        | ';'
                        | ':'
                        | '!'
                        | '?'
                        | '（'
                        | '）'
                        | '［'
                        | '］'
                        | '｛'
                        | '｝'
                        | '＜'
                        | '＞'
                        | '「'
                        | '」'
                        | '『'
                        | '』'
                        | '《'
                        | '》'
                        | '〈'
                        | '〉'
                        | '｢'
                        | '｣'
                        | '【'
                        | '】'
                        | '，'
                        | '；'
                        | '：'
                        | '！'
                        | '？'
                )
                || matches!(
                    c,
                    '\u{200B}'
                        | '\u{200C}'
                        | '\u{200D}'
                        | '\u{2060}'
                        | '\u{FEFF}'
                        | '\u{202A}'
                        | '\u{202B}'
                        | '\u{202C}'
                        | '\u{202D}'
                        | '\u{202E}'
                        | '\u{2066}'
                        | '\u{2067}'
                        | '\u{2068}'
                        | '\u{2069}'
                )
        })
        .trim_end_matches(|c: char| {
            c.is_ascii_punctuation()
                || matches!(
                    c,
                    '。' | '｡' | '．' | '﹒' | '․' | '！' | '？' | '，' | '；' | '：'
                )
        })
        .to_ascii_lowercase();
    let canonical = cleaned
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>()
        .trim_matches('_')
        .split('_')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("_");
    match canonical.as_str() {
        "pending" | "submitted" | "accepted" | "queued" | "broadcast" | "broadcasted"
        | "broadcasting" | "processing" | "executing" | "in_progress" | "inflight"
        | "in_flight" => Some("pending".to_string()),
        "committed" | "confirmed" | "success" | "succeeded" | "ok" | "included" | "finalized"
        | "finalised" | "finalising" | "finalizing" | "complete" | "completed" | "done" => {
            Some("committed".to_string())
        }
        "fail" | "failed" | "error" | "rejected" | "reverted" | "aborted" | "dropped"
        | "timeout" | "timed_out" | "expired" => Some("fail".to_string()),
        _ => None,
    }
}

fn is_nullish_kv_value(raw: &str) -> bool {
    let cleaned = raw
        .trim()
        .trim_matches(|c: char| {
            c.is_whitespace()
                || c.is_control()
                || matches!(
                    c,
                    '"' | '\''
                        | '`'
                        | '“'
                        | '”'
                        | '‘'
                        | '’'
                        | '<'
                        | '>'
                        | '('
                        | ')'
                        | '['
                        | ']'
                        | '{'
                        | '}'
                        | '（'
                        | '）'
                        | '［'
                        | '］'
                        | '｛'
                        | '｝'
                        | '＜'
                        | '＞'
                        | '「'
                        | '」'
                        | '『'
                        | '』'
                        | '《'
                        | '》'
                        | '〈'
                        | '〉'
                        | '｢'
                        | '｣'
                        | '«'
                        | '»'
                        | '‹'
                        | '›'
                        | '【'
                        | '】'
                        | '〔'
                        | '〕'
                        | '〖'
                        | '〗'
                        | '〘'
                        | '〙'
                        | '〚'
                        | '〛'
                        | '〝'
                        | '〞'
                        | '〟'
                )
                || matches!(
                    c,
                    '\u{200B}'
                        | '\u{200C}'
                        | '\u{200D}'
                        | '\u{2060}'
                        | '\u{FEFF}'
                        | '\u{202A}'
                        | '\u{202B}'
                        | '\u{202C}'
                        | '\u{202D}'
                        | '\u{202E}'
                        | '\u{2066}'
                        | '\u{2067}'
                        | '\u{2068}'
                        | '\u{2069}'
                )
        })
        .trim_end_matches(|c: char| {
            c.is_ascii_punctuation()
                || matches!(
                    c,
                    '。' | '｡' | '．' | '﹒' | '․' | '！' | '？' | '，' | '；' | '：'
                )
        })
        .to_ascii_lowercase();
    cleaned.is_empty() || cleaned == "null"
}

fn normalize_json_error(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Null => None,
        serde_json::Value::String(s) => {
            if is_nullish_kv_value(s) {
                None
            } else {
                Some(s.to_string())
            }
        }
        other => Some(other.to_string()),
    }
}

fn normalize_json_status(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => normalize_tx_status(s),
        serde_json::Value::Number(n) => n
            .as_i64()
            .map(|code| if code == 0 { "committed" } else { "fail" }.to_string()),
        serde_json::Value::Bool(b) => Some(if *b { "committed" } else { "fail" }.to_string()),
        _ => None,
    }
}

fn is_terminal_local_tx_status(status: &str) -> bool {
    matches!(normalize_tx_status(status).as_deref(), Some("committed" | "fail"))
}

fn json_u64_at_path(value: &serde_json::Value, path: &[&str]) -> Option<u64> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    match current {
        serde_json::Value::Number(n) => n.as_u64(),
        serde_json::Value::String(s) => s.trim().parse::<u64>().ok(),
        _ => None,
    }
}

fn infer_json_tx_status(value: &serde_json::Value) -> Option<String> {
    for path in [
        ["tx_result", "code"].as_slice(),
        ["deliver_tx", "code"].as_slice(),
        ["check_tx", "code"].as_slice(),
        ["code"].as_slice(),
        ["tx_code"].as_slice(),
        ["transaction_code"].as_slice(),
        ["deliver_tx_code"].as_slice(),
        ["check_tx_code"].as_slice(),
    ] {
        if let Some(code) = json_u64_at_path(value, path) {
            return Some(if code == 0 { "committed" } else { "fail" }.to_string());
        }
    }
    None
}

fn infer_kv_tx_status(key: &str, value: &str) -> Option<String> {
    match key {
        "code" | "tx_code" | "txcode" | "transaction_code" | "transactioncode"
        | "deliver_tx_code" | "delivertxcode" | "check_tx_code" | "checktxcode" => {
            let cleaned = value
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .trim_matches('`')
                .trim_end_matches(|c: char| c.is_ascii_punctuation());
            let code = cleaned.parse::<u64>().ok()?;
            Some(if code == 0 { "committed" } else { "fail" }.to_string())
        }
        _ => None,
    }
}

fn parse_tx_query_response(raw: &str, requested_tx_hash: &str) -> Result<TxQueryResponse> {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
        let payload = v.get("result").unwrap_or(&v);
        let nested_tx_response = payload
            .get("tx_response")
            .or_else(|| payload.get("txResponse"))
            .or_else(|| payload.get("response").and_then(|r| r.get("tx_response")))
            .or_else(|| payload.get("response").and_then(|r| r.get("txResponse")));
        let nested_response_data = payload
            .get("response")
            .and_then(|r| r.get("data"))
            .or_else(|| payload.get("responseData"));
        let primary = nested_tx_response
            .or(nested_response_data)
            .unwrap_or(payload);
        let raw_tx_hash = primary
            .get("tx_hash")
            .or_else(|| primary.get("txhash"))
            .or_else(|| primary.get("txHash"))
            .or_else(|| primary.get("transaction_hash"))
            .or_else(|| primary.get("transactionHash"))
            .or_else(|| payload.get("tx_hash"))
            .or_else(|| payload.get("txhash"))
            .or_else(|| payload.get("txHash"))
            .or_else(|| payload.get("transaction_hash"))
            .or_else(|| payload.get("transactionHash"))
            .and_then(|x| x.as_str());
        let tx_hash = match raw_tx_hash {
            Some(raw_hash) => normalize_tx_hash(raw_hash)
                .ok_or_else(|| anyhow!("invalid tx_hash field in tx query response"))?,
            None => normalize_tx_hash(requested_tx_hash)
                .unwrap_or_else(|| requested_tx_hash.to_string()),
        };
        let status = primary
            .get("status")
            .or_else(|| primary.get("tx_status"))
            .or_else(|| primary.get("txStatus"))
            .or_else(|| primary.get("transaction_status"))
            .or_else(|| primary.get("transactionStatus"))
            .or_else(|| primary.get("state"))
            .or_else(|| primary.get("tx_state"))
            .or_else(|| primary.get("txState"))
            .or_else(|| primary.get("transaction_state"))
            .or_else(|| primary.get("transactionState"))
            .or_else(|| payload.get("status"))
            .or_else(|| payload.get("tx_status"))
            .or_else(|| payload.get("txStatus"))
            .or_else(|| payload.get("transaction_status"))
            .or_else(|| payload.get("transactionStatus"))
            .or_else(|| payload.get("state"))
            .or_else(|| payload.get("tx_state"))
            .or_else(|| payload.get("txState"))
            .or_else(|| payload.get("transaction_state"))
            .or_else(|| payload.get("transactionState"))
            .and_then(normalize_json_status)
            .or_else(|| infer_json_tx_status(primary))
            .or_else(|| infer_json_tx_status(payload))
            .ok_or_else(|| anyhow!("missing/invalid status field in tx query response"))?;
        let error = primary
            .get("error")
            .or_else(|| primary.get("raw_log"))
            .or_else(|| primary.get("rawLog"))
            .or_else(|| primary.get("log"))
            .or_else(|| payload.get("error"))
            .or_else(|| payload.get("raw_log"))
            .or_else(|| payload.get("rawLog"))
            .or_else(|| payload.get("log"))
            .and_then(normalize_json_error);
        return Ok(TxQueryResponse {
            tx_hash,
            status,
            error,
        });
    }

    let mut tx_hash: Option<String> = None;
    let mut status: Option<String> = None;
    let mut error: Option<String> = None;
    for line in raw.lines() {
        let mut pairs = Vec::new();
        if let Some(pair) = parse_kv_line(line) {
            pairs.push(pair);
        }
        for token in line.split_whitespace() {
            if let Some(pair) = parse_inline_kv_token(token) {
                pairs.push(pair);
            }
        }

        for (key, value) in pairs {
            match key.as_str() {
                "tx_hash" | "txhash" | "tx-hash" | "transaction_hash" | "transactionhash"
                | "transaction-hash" => match normalize_tx_hash(&value) {
                    Some(normalized) => tx_hash = Some(normalized),
                    None => bail!("invalid tx_hash field in tx query response"),
                },
                "status" | "tx_status" | "txstatus" | "transaction_status"
                | "transactionstatus" | "state" | "tx_state" | "txstate" | "transaction_state"
                | "transactionstate" => {
                    if let Some(normalized) = normalize_tx_status(&value) {
                        status = Some(normalized);
                    }
                }
                "code" | "tx_code" | "txcode" | "transaction_code" | "transactioncode"
                | "deliver_tx_code" | "delivertxcode" | "check_tx_code" | "checktxcode" => {
                    if status.is_none() {
                        status = infer_kv_tx_status(&key, &value);
                    }
                }
                "error" | "raw_log" | "rawlog" | "log" => {
                    // Manual quote trimming since parse_kv_line no longer does it aggressively
                    let cleaned = value.trim_matches(|c| matches!(c, '"' | '\'' | '`'));
                    if !is_nullish_kv_value(cleaned) {
                        match &error {
                            Some(existing) if existing.len() >= cleaned.len() => {}
                            _ => error = Some(cleaned.to_string()),
                        }
                    }
                }
                _ => {}
            }
        }
    }

    if let Some(status) = status {
        return Ok(TxQueryResponse {
            tx_hash: tx_hash.unwrap_or_else(|| requested_tx_hash.to_string()),
            status,
            error,
        });
    }

    bail!("failed to parse tx query response: {}", raw.trim())
}

fn tx_query(tx_hash: &str) -> Result<TxQueryResponse> {
    let requested = normalize_tx_hash(tx_hash)
        .ok_or_else(|| anyhow!("invalid tx hash for query (expected hex-like tx hash)"))?;
    if !requested.starts_with("0x") {
        bail!("invalid tx hash for query (expected 0x-prefixed hex tx hash)");
    }

    if let Some(status) = query_local_tx_status(&requested) {
        return Ok(TxQueryResponse {
            tx_hash: requested,
            status,
            error: None,
        });
    }

    if let Ok(template) = std::env::var("TRNM_TX_QUERY_CMD") {
        let cmd = tpl(template, "tx_hash", &requested);
        let raw = run_template_raw(&cmd)?;
        let parsed = parse_tx_query_response(&raw, &requested)?;
        if let Some(got) = normalize_tx_hash(&parsed.tx_hash) {
            if requested != got {
                bail!(
                    "tx query response hash mismatch: requested={}, got={}",
                    requested,
                    got
                );
            }
        }
        return Ok(parsed);
    }

    let rpc_workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let cmd = format!("cargo run -q -p trnm-rpc -- get-tx --tx-hash {}", requested);
    match {
        let (program, args) = parse_template_command(&cmd)?;
        let out = ProcCommand::new(program)
            .args(args)
            .current_dir(&rpc_workspace)
            .output()?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !out.status.success() {
            Err(anyhow!(
                "query command failed rc={}: {}{}",
                out.status.code().unwrap_or(1),
                stdout,
                stderr
            ))
        } else {
            Ok(stdout.to_string())
        }
    } {
        Ok(raw) => {
            let parsed = parse_tx_query_response(&raw, &requested)?;
            if let Some(got) = normalize_tx_hash(&parsed.tx_hash) {
                if requested != got {
                    bail!(
                        "tx query response hash mismatch: requested={}, got={}",
                        requested,
                        got
                    );
                }
            }
            Ok(parsed)
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("TX_NOT_FOUND") {
                if let Some(status) = query_local_tx_status(&requested) {
                    return Ok(TxQueryResponse {
                        tx_hash: requested,
                        status,
                        error: None,
                    });
                }
            }
            Err(e)
        }
    }
}

fn is_terminal_tx_status(status: &str) -> bool {
    matches!(normalize_tx_status(status).as_deref(), Some("committed" | "fail"))
}

fn wait_for_tx<F>(
    tx_hash: &str,
    timeout: Duration,
    interval: Duration,
    mut query_fn: F,
) -> Result<TxQueryResponse>
where
    F: FnMut(&str) -> Result<TxQueryResponse>,
{
    if timeout.is_zero() {
        bail!("tx wait timeout must be greater than 0s");
    }
    if interval.is_zero() {
        bail!("tx wait interval must be greater than 0s");
    }

    let requested = normalize_tx_hash(tx_hash)
        .ok_or_else(|| anyhow!("invalid tx hash for wait (expected hex-like tx hash)"))?;
    if !requested.starts_with("0x") {
        bail!("invalid tx hash for wait (expected 0x-prefixed hex tx hash)");
    }
    let started = Instant::now();
    loop {
        let resp = query_fn(&requested)?;
        if resp.tx_hash.trim().is_empty() {
            bail!(
                "tx wait response missing tx_hash: requested={}",
                requested
            );
        }
        let got = normalize_tx_hash(&resp.tx_hash).ok_or_else(|| {
            anyhow!(
                "tx wait response hash invalid: requested={}, got={}",
                requested,
                resp.tx_hash
            )
        })?;
        if got != requested {
            bail!(
                "tx wait response hash mismatch: requested={}, got={}",
                requested,
                got
            );
        }
        if is_terminal_tx_status(&resp.status) {
            let mut canonical = resp;
            canonical.tx_hash = requested.clone();
            return Ok(canonical);
        }

        let elapsed = started.elapsed();
        if elapsed >= timeout {
            bail!(
                "tx wait timeout after {}s (last_status={})",
                timeout.as_secs(),
                resp.status
            );
        }

        let remaining = timeout.saturating_sub(elapsed);
        thread::sleep(interval.min(remaining));
    }
}

fn tpl(mut s: String, key: &str, val: &str) -> String {
    s = s.replace(&format!("{{{}}}", key), val);
    s
}

fn default_tx_state_file() -> PathBuf {
    if let Ok(path) = std::env::var("TRNM_RPC_TX_FILE") {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("run/rpc/txs.json"))
        .unwrap_or_else(|| PathBuf::from("run/rpc/txs.json"))
}

fn query_local_tx_status(tx_hash: &str) -> Option<String> {
    let path = default_tx_state_file();
    let raw = fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let requested = normalize_tx_hash(tx_hash).unwrap_or_else(|| tx_hash.to_string());
    let rec = v.as_object()?.iter().find_map(|(key, value)| {
        (normalize_tx_hash(key).as_deref() == Some(requested.as_str())).then_some(value)
    })?;
    [
        "status",
        "tx_status",
        "txStatus",
        "transaction_status",
        "transactionStatus",
        "state",
        "tx_state",
        "txState",
        "transaction_state",
        "transactionState",
    ]
    .into_iter()
    .find_map(|key| rec.get(key).and_then(normalize_json_status))
}

fn persist_local_pending_tx(tx_hash: &str) -> Result<()> {
    let canonical = normalize_tx_hash(tx_hash)
        .ok_or_else(|| anyhow!("invalid tx hash for local pending state (expected hex-like tx hash)"))?;
    if !canonical.starts_with("0x") {
        bail!("invalid tx hash for local pending state (expected 0x-prefixed hex tx hash)");
    }

    let path = default_tx_state_file();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut root: serde_json::Map<String, serde_json::Value> =
        if let Ok(raw) = fs::read_to_string(&path) {
            serde_json::from_str(&raw).unwrap_or_default()
        } else {
            serde_json::Map::new()
        };

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);

    let existing = root.get(&canonical).cloned();
    let existing_status = existing
        .as_ref()
        .and_then(|record| record.get("status"))
        .and_then(normalize_json_status);
    let status = existing_status
        .as_deref()
        .filter(|status| is_terminal_local_tx_status(status))
        .unwrap_or("pending");
    let submitted_at_unix_ms = existing
        .as_ref()
        .and_then(|record| record.get("submitted_at_unix_ms"))
        .and_then(|value| value.as_u64())
        .unwrap_or(now_ms as u64);

    root.insert(
        canonical.clone(),
        serde_json::json!({
            "tx_hash": canonical,
            "tx": {
                "from": "trnm1pendingplaceholderfrom",
                "to": "trnm1pendingplaceholderto",
                "amount": 0,
                "fee": 0,
                "nonce": 0,
                "signature": "pending"
            },
            "status": status,
            "error": null,
            "submitted_at_unix_ms": submitted_at_unix_ms,
            "updated_at_unix_ms": now_ms
        }),
    );

    fs::write(path, serde_json::to_string_pretty(&root)?)?;
    Ok(())
}

fn format_tx_hash_line(tx_hash: &str) -> String {
    format!("tx_hash=\"{}\"", tx_hash)
}

fn format_tx_hash_alias_line(tx_hash: &str) -> String {
    format!("txhash={}", tx_hash)
}

fn format_transaction_hash_alias_line(tx_hash: &str) -> String {
    format!("transaction_hash={}", tx_hash)
}

fn format_transaction_hash_camel_alias_line(tx_hash: &str) -> String {
    format!("transactionHash={}", tx_hash)
}

fn format_tx_hash_hyphen_alias_line(tx_hash: &str) -> String {
    format!("tx-hash={}", tx_hash)
}

fn format_transaction_hash_hyphen_alias_line(tx_hash: &str) -> String {
    format!("transaction-hash={}", tx_hash)
}

fn emit_tx_hash_lines(tx_hash: &str) {
    println!("{}", format_tx_hash_line(tx_hash));
    println!("{}", format_tx_hash_alias_line(tx_hash));
    println!("{}", format_transaction_hash_alias_line(tx_hash));
    println!("{}", format_transaction_hash_camel_alias_line(tx_hash));
    println!("{}", format_tx_hash_hyphen_alias_line(tx_hash));
    println!("{}", format_transaction_hash_hyphen_alias_line(tx_hash));
}

fn emit_pending_tx_hash(tx_hash: &str) -> Result<()> {
    persist_local_pending_tx(tx_hash)?;
    emit_tx_hash_lines(tx_hash);
    Ok(())
}

fn wallet_create(name: String, out: Option<PathBuf>) -> Result<()> {
    let store = resolve_wallet_store(out)?;
    let priv_hex = random_priv_hex()?;
    let path = write_key(&store, &name, &priv_hex)?;
    let addr = derive_address_from_priv_hex(&priv_hex)?;
    println!("wallet_name={}", name);
    println!("wallet_path={}", path.display());
    println!("address={}", addr);
    println!("public_key_hint={}", sha256_hex(priv_hex.as_bytes()));
    Ok(())
}

fn resolve_address_for_query(
    address: Option<String>,
    name: Option<String>,
    store: Option<PathBuf>,
) -> Result<String> {
    if let Some(a) = address {
        return Ok(a);
    }
    let wallet_name = name.unwrap_or_else(|| "default".to_string());
    let s = resolve_wallet_store(store)?;
    let priv_hex = read_key(&s, &wallet_name)?;
    derive_address_from_priv_hex(&priv_hex)
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.cmd {
        Command::Tx { tx } => match tx {
            TxCommand::CommitResult {
                task_id,
                worker,
                commit_hash,
                nonce,
            } => {
                if let Ok(template) = std::env::var("TRNM_TX_COMMIT_CMD") {
                    let mut cmd = template;
                    cmd = tpl(cmd, "task_id", &task_id.to_string());
                    cmd = tpl(cmd, "worker", &worker);
                    cmd = tpl(cmd, "commit_hash", &commit_hash);
                    cmd = tpl(cmd, "nonce", &nonce.to_string());
                    let tx_hash = run_template(&cmd)?;
                    emit_pending_tx_hash(&tx_hash)?;
                } else {
                    let tx_hash = format!(
                        "0x{}",
                        hash(&[
                            "commit-result",
                            &task_id.to_string(),
                            &worker,
                            &commit_hash,
                            &nonce.to_string(),
                        ])
                    );
                    emit_pending_tx_hash(&tx_hash)?;
                }
            }
            TxCommand::RevealResult {
                task_id,
                result_hash,
                salt_hex,
            } => {
                if let Ok(template) = std::env::var("TRNM_TX_REVEAL_CMD") {
                    let mut cmd = template;
                    cmd = tpl(cmd, "task_id", &task_id.to_string());
                    cmd = tpl(cmd, "result_hash", &result_hash);
                    cmd = tpl(cmd, "salt_hex", &salt_hex);
                    let tx_hash = run_template(&cmd)?;
                    emit_pending_tx_hash(&tx_hash)?;
                } else {
                    let tx_hash = format!(
                        "0x{}",
                        hash(&[
                            "reveal-result",
                            &task_id.to_string(),
                            &result_hash,
                            &salt_hex,
                        ])
                    );
                    emit_pending_tx_hash(&tx_hash)?;
                }
            }
            TxCommand::Query { tx_hash } => {
                let resp = tx_query(&tx_hash)?;
                emit_tx_hash_lines(&resp.tx_hash);
                println!("status={}", resp.status);
                if let Some(err) = resp.error {
                    println!("error={}", err);
                }
            }
            TxCommand::Wait {
                tx_hash,
                timeout,
                interval,
            } => {
                let resp = wait_for_tx(
                    &tx_hash,
                    Duration::from_secs(timeout),
                    Duration::from_secs(interval),
                    tx_query,
                )?;
                emit_tx_hash_lines(&resp.tx_hash);
                println!("status={}", resp.status);
                if let Some(err) = resp.error {
                    println!("error={}", err);
                }
            }
            TxCommand::Transfer {
                from,
                to,
                amount,
                denom,
                store,
            } => {
                let s = resolve_wallet_store(store)?;
                let from_priv_hex = read_key(&s, &from)?;
                let from_addr = derive_address_from_priv_hex(&from_priv_hex)?;
                let req = TransferTxRequest {
                    from: from_addr,
                    to,
                    amount: amount.to_string(),
                    denom,
                };

                if let Ok(template) = std::env::var("TRNM_TX_TRANSFER_CMD") {
                    let mut cmd = template;
                    cmd = tpl(cmd, "from", &req.from);
                    cmd = tpl(cmd, "to", &req.to);
                    cmd = tpl(cmd, "amount", &req.amount);
                    cmd = tpl(cmd, "denom", &req.denom);
                    let tx_hash = run_template(&cmd)?;
                    persist_local_pending_tx(&tx_hash)?;
                    let out = TransferTxResponse {
                        tx_hash,
                        status: "pending".into(),
                    };
                    println!("{}", serde_json::to_string_pretty(&out)?);
                } else {
                    let tx_hash = format!(
                        "0x{}",
                        hash(&["transfer", &req.from, &req.to, &req.amount, &req.denom])
                    );
                    persist_local_pending_tx(&tx_hash)?;
                    let out = TransferTxResponse {
                        tx_hash,
                        status: "pending".into(),
                    };
                    println!("{}", serde_json::to_string_pretty(&out)?);
                }
            }
        },
        Command::Wallet { wallet } => match wallet {
            WalletCommand::Create { name, out } | WalletCommand::Generate { name, out } => {
                wallet_create(name, out)?;
            }
            WalletCommand::Import {
                name,
                private_key_hex,
                out,
            } => {
                let store = resolve_wallet_store(out)?;
                let priv_hex = ensure_hex_32_bytes(&private_key_hex)?;
                let path = write_key(&store, &name, &priv_hex)?;
                let addr = derive_address_from_priv_hex(&priv_hex)?;
                println!("wallet_name={}", name);
                println!("wallet_path={}", path.display());
                println!("address={}", addr);
            }
            WalletCommand::Address { name, store } => {
                let store = resolve_wallet_store(store)?;
                let priv_hex = read_key(&store, &name)?;
                let addr = derive_address_from_priv_hex(&priv_hex)?;
                println!("wallet_name={}", name);
                println!("address={}", addr);
            }
            WalletCommand::Sign {
                name,
                message,
                store,
            } => {
                ensure_sign_message(&message)?;
                let store = resolve_wallet_store(store)?;
                ensure_safe_sign_message(&message)?;
                let priv_hex = read_key(&store, &name)?;
                let sig = hash(&["trnm-sign-v1", &priv_hex, &message]);
                let addr = derive_address_from_priv_hex(&priv_hex)?;
                let message_sha256 = sha256_hex(message.as_bytes());
                println!("wallet_name={}", name);
                println!("address={}", addr);
                println!("message={}", message);
                println!("message_sha256={}", message_sha256);
                println!("signature={}", sig);
            }
        },
        Command::Query { query } => match query {
            QueryCommand::Balance {
                address,
                name,
                store,
                denom,
            } => {
                let addr = resolve_address_for_query(address, name, store)?;

                if let Ok(template) = std::env::var("TRNM_QUERY_BALANCE_CMD") {
                    let mut cmd = template;
                    cmd = tpl(cmd, "address", &addr);
                    cmd = tpl(cmd, "denom", &denom);
                    let raw = run_template_raw(&cmd)?;
                    if let Ok(resp) = serde_json::from_str::<BalanceQueryResponse>(&raw) {
                        println!("{}", serde_json::to_string_pretty(&resp)?);
                    } else {
                        let out = BalanceQueryResponse {
                            address: addr,
                            balance: raw.trim().to_string(),
                            denom,
                        };
                        println!("{}", serde_json::to_string_pretty(&out)?);
                    }
                } else {
                    let seeded = hash(&["balance", &addr, &denom]);
                    let pseudo = u128::from_str_radix(&seeded[..16], 16).unwrap_or(0) % 1_000_000;
                    let out = BalanceQueryResponse {
                        address: addr,
                        balance: pseudo.to_string(),
                        denom,
                    };
                    println!("{}", serde_json::to_string_pretty(&out)?);
                }
            }
            QueryCommand::Task { task_id } => {
                let out = task_query(task_id)?;
                println!("{}", serde_json::to_string_pretty(&out)?);
            }
            QueryCommand::Events {
                task_id,
                limit,
                summary,
            } => {
                let out = events_query(task_id, limit)?;
                if summary {
                    println!("{}", render_events_query_summary(&out)?);
                } else {
                    println!("{}", serde_json::to_string_pretty(&out)?);
                }
            }
            QueryCommand::RequestFull {
                request_id,
                limit,
                summary,
            } => {
                let out = request_full_query(&request_id, limit)?;
                if summary {
                    println!("{}", render_request_full_query_summary(&out)?);
                } else {
                    println!("{}", serde_json::to_string_pretty(&out)?);
                }
            }
        },
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{path::PathBuf, sync::Mutex};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn canonical_temp_root() -> PathBuf {
        std::fs::canonicalize(std::env::temp_dir()).unwrap_or_else(|_| std::env::temp_dir())
    }

    #[test]
    fn wallet_import_hex_check() {
        let ok = ensure_hex_32_bytes(
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap();
        assert_eq!(ok.len(), 64);

        let upper = ensure_hex_32_bytes(
            "0XAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        .unwrap();
        assert_eq!(
            upper,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );

        let alm_wrapped = ensure_hex_32_bytes(
            "\u{061c}0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\u{061c}",
        )
        .unwrap();
        assert_eq!(
            alm_wrapped,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );

        assert!(ensure_hex_32_bytes("0x1234").is_err());
    }

    #[test]
    fn normalize_wallet_store_env_trims_shell_wrapped_quotes() {
        assert_eq!(
            normalize_wallet_store_env("  \"/tmp/trnm-wallets\"  "),
            Some("/tmp/trnm-wallets")
        );
        assert_eq!(
            normalize_wallet_store_env(" “《/tmp/trnm-wallets》” "),
            Some("/tmp/trnm-wallets")
        );
        assert_eq!(
            normalize_wallet_store_env("\u{2068} \"/tmp/trnm-wallets\" \u{2069}"),
            Some("/tmp/trnm-wallets")
        );
        assert_eq!(
            normalize_wallet_store_env("\u{200e}\u{061c}《/tmp/trnm-wallets》\u{200f}"),
            Some("/tmp/trnm-wallets")
        );
        assert_eq!(normalize_wallet_store_env("   \"\"   "), None);
    }

    #[test]
    fn normalize_wallet_store_env_rejects_hidden_or_whitespace_payloads() {
        assert_eq!(normalize_wallet_store_env("/tmp/trnm wallets"), None);
        assert_eq!(normalize_wallet_store_env("/tmp/trnm\u{200b}-wallets"), None);
        assert_eq!(normalize_wallet_store_env("/tmp/trnm\u{202e}wallets"), None);
    }

    #[test]
    fn default_wallet_store_rejects_relative_or_root_env_paths() {
        let _guard = ENV_LOCK.lock().unwrap();
        let original_store = std::env::var_os("TRNM_WALLET_STORE");
        let original_home = std::env::var_os("HOME");
        let home = canonical_temp_root().join(format!(
            "trnm-cli-wallet-home-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        std::env::set_var("HOME", &home);

        std::env::set_var("TRNM_WALLET_STORE", "wallets");
        assert_eq!(default_wallet_store(), home.join(".trnm").join("wallets"));

        std::env::set_var("TRNM_WALLET_STORE", "nested/wallets");
        assert_eq!(default_wallet_store(), home.join(".trnm").join("wallets"));

        std::env::set_var("TRNM_WALLET_STORE", "/");
        assert_eq!(default_wallet_store(), home.join(".trnm").join("wallets"));

        std::env::set_var("TRNM_WALLET_STORE", "/tmp/trnm/../wallets");
        assert_eq!(default_wallet_store(), home.join(".trnm").join("wallets"));

        std::env::set_var("TRNM_WALLET_STORE", "/tmp/./trnm-wallets");
        assert_eq!(default_wallet_store(), home.join(".trnm").join("wallets"));

        std::env::set_var("TRNM_WALLET_STORE", " /tmp/trnm-wallets ");
        let trimmed_absolute = std::path::PathBuf::from("/tmp/trnm-wallets");
        let expected_trimmed_absolute = if wallet_store_path_is_safe(&trimmed_absolute)
            && wallet_store_path_and_ancestors_are_symlink_free(&trimmed_absolute)
        {
            trimmed_absolute
        } else {
            home.join(".trnm").join("wallets")
        };
        assert_eq!(default_wallet_store(), expected_trimmed_absolute);

        match original_store {
            Some(value) => std::env::set_var("TRNM_WALLET_STORE", value),
            None => std::env::remove_var("TRNM_WALLET_STORE"),
        }
        match original_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn default_wallet_store_falls_back_to_absolute_cwd_when_home_missing_or_relative() {
        let _guard = ENV_LOCK.lock().unwrap();
        let original_store = std::env::var_os("TRNM_WALLET_STORE");
        let original_home = std::env::var_os("HOME");
        std::env::remove_var("TRNM_WALLET_STORE");

        let cwd = std::env::current_dir().unwrap();

        std::env::remove_var("HOME");
        assert_eq!(default_wallet_store(), cwd.join(".trnm").join("wallets"));

        std::env::set_var("HOME", "./relative-home");
        assert_eq!(default_wallet_store(), cwd.join(".trnm").join("wallets"));

        match original_store {
            Some(value) => std::env::set_var("TRNM_WALLET_STORE", value),
            None => std::env::remove_var("TRNM_WALLET_STORE"),
        }
        match original_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn default_wallet_store_accepts_wrapped_home_and_rejects_symlinked_home_ancestor() {
        let _guard = ENV_LOCK.lock().unwrap();
        let original_store = std::env::var_os("TRNM_WALLET_STORE");
        let original_home = std::env::var_os("HOME");
        std::env::remove_var("TRNM_WALLET_STORE");

        let root = canonical_temp_root().join(format!(
            "trnm-cli-home-guard-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let clean_home = root.join("clean-home");
        let real_parent = root.join("real-parent");
        let linked_parent = root.join("linked-parent");
        std::fs::create_dir_all(&clean_home).unwrap();
        std::fs::create_dir_all(&real_parent).unwrap();
        std::os::unix::fs::symlink(&real_parent, &linked_parent).unwrap();

        std::env::set_var("HOME", format!(" \"{}\" ", clean_home.display()));
        assert_eq!(default_wallet_store(), clean_home.join(".trnm").join("wallets"));

        std::env::set_var("HOME", format!("{}", linked_parent.display()));
        assert_eq!(default_wallet_store(), std::env::current_dir().unwrap().join(".trnm").join("wallets"));

        match original_store {
            Some(value) => std::env::set_var("TRNM_WALLET_STORE", value),
            None => std::env::remove_var("TRNM_WALLET_STORE"),
        }
        match original_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
        let _ = std::fs::remove_file(&linked_parent);
        let _ = std::fs::remove_dir_all(&real_parent);
        let _ = std::fs::remove_dir_all(&clean_home);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn resolve_wallet_store_fail_closes_on_invalid_env_and_prefers_explicit_store() {
        let _guard = ENV_LOCK.lock().unwrap();
        let original_store = std::env::var_os("TRNM_WALLET_STORE");

        std::env::set_var("TRNM_WALLET_STORE", "\u{2068}\"./wallets\"\u{2069}");
        let err = resolve_wallet_store(None).unwrap_err();
        assert!(
            err.to_string()
                .contains("must be an absolute normalized symlink-free path"),
            "unexpected error: {err}"
        );

        let explicit = std::env::temp_dir().join(format!(
            "trnm-cli-explicit-store-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        assert_eq!(resolve_wallet_store(Some(explicit.clone())).unwrap(), explicit);

        match original_store {
            Some(value) => std::env::set_var("TRNM_WALLET_STORE", value),
            None => std::env::remove_var("TRNM_WALLET_STORE"),
        }
    }

    #[test]
    fn default_wallet_store_rejects_unsafe_absolute_cwd_fallback() {
        let _guard = ENV_LOCK.lock().unwrap();
        let original_store = std::env::var_os("TRNM_WALLET_STORE");
        let original_home = std::env::var_os("HOME");
        let original_cwd = std::env::current_dir().unwrap();

        let unique = format!(
            "trnm cli cwd fallback test {} {}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let unsafe_cwd = canonical_temp_root().join(unique);
        std::fs::create_dir_all(&unsafe_cwd).unwrap();

        std::env::remove_var("TRNM_WALLET_STORE");
        std::env::remove_var("HOME");
        std::env::set_current_dir(&unsafe_cwd).unwrap();

        assert_eq!(
            default_wallet_store(),
            std::path::PathBuf::from("/").join(".trnm").join("wallets")
        );

        std::env::set_current_dir(&original_cwd).unwrap();
        match original_store {
            Some(value) => std::env::set_var("TRNM_WALLET_STORE", value),
            None => std::env::remove_var("TRNM_WALLET_STORE"),
        }
        match original_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
        let _ = std::fs::remove_dir_all(&unsafe_cwd);
    }

    #[test]
    fn explicit_wallet_store_path_must_be_absolute_and_normalized() {
        let write_err = write_key(
            std::path::Path::new("./wallets"),
            "alice",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap_err();
        assert!(
            write_err
                .to_string()
                .contains("must be an absolute normalized path"),
            "unexpected error: {write_err}"
        );

        let read_err = read_key(std::path::Path::new("/tmp/trnm/../wallets"), "alice").unwrap_err();
        assert!(
            read_err
                .to_string()
                .contains("must be an absolute normalized path"),
            "unexpected error: {read_err}"
        );

        let spaced_write_err = write_key(
            std::path::Path::new("/tmp/trnm wallets"),
            "alice",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap_err();
        assert!(
            spaced_write_err
                .to_string()
                .contains("must be an absolute normalized path"),
            "unexpected error: {spaced_write_err}"
        );

        let hidden_read_err =
            read_key(std::path::Path::new("/tmp/trnm\u{200b}wallets"), "alice").unwrap_err();
        assert!(
            hidden_read_err
                .to_string()
                .contains("must be an absolute normalized path"),
            "unexpected error: {hidden_read_err}"
        );
    }

    #[test]
    fn sign_message_rejects_multiline_or_control_text() {
        let oversized = "a".repeat(4097);
        for bad in [
            "".to_string(),
            " hello world".to_string(),
            "hello world ".to_string(),
            "\u{00a0}hello world".to_string(),
            "hello world\u{2003}".to_string(),
            "hello\nworld".to_string(),
            "hello\rworld".to_string(),
            "hello\tworld".to_string(),
            "hello\u{00a0}world".to_string(),
            "hello\u{2003}world".to_string(),
            "hello\u{0007}world".to_string(),
            "hello\u{061c}world".to_string(),
            "hello\u{200e}world".to_string(),
            "hello\u{200f}world".to_string(),
            "hello\u{202e}world".to_string(),
            "hello\u{2068}world".to_string(),
            oversized,
        ] {
            let err = ensure_sign_message(&bad).unwrap_err();
            assert!(
                err.to_string().contains("sign message"),
                "unexpected error for {bad:?}: {err}"
            );
        }

        ensure_sign_message("trnm mainnet attestation v1").unwrap();
        ensure_sign_message("签名用途: validator-bootstrap").unwrap();
        ensure_sign_message("operator approval v1").unwrap();
        ensure_sign_message(&"a".repeat(4096)).unwrap();
    }

    #[test]
    fn wallet_name_rejects_path_like_values() {
        for bad in [
            "",
            ".",
            "..",
            ".alice",
            "alice.",
            "alice..",
            "-alice",
            "--help",
            "alice/bob",
            "alice\\bob",
            "alice:bob",
            "alice：bob",
            "alice=debug",
            "alice＝debug",
            "alice|bob",
            "alice｜bob",
            "alice&bob",
            "alice＆bob",
            "alice!",
            "alice！",
            "alice$bob",
            "alice*bob",
            "alice?bob",
            "alice/bob",
            "alice∕bob",
            "alice⁄bob",
            "alice／bob",
            "alice\\bob",
            "alice＼bob",
            "alice⧵bob",
            "alice⟋bob",
            "alice⟍bob",
            "\"alice\"",
            "'alice'",
            "`alice`",
            "<alice>",
            "(alice)",
            "[alice]",
            "{alice}",
            "“alice”",
            "‘alice’",
            "「alice」",
            "『alice』",
            "《alice》",
            "〈alice〉",
            "｢alice｣",
            "（alice）",
            "［alice］",
            "｛alice｝",
            "＜alice＞",
            "【alice】",
            "〔alice〕",
            "〖alice〗",
            "〘alice〙",
            "〚alice〛",
            "alice,",
            "alice，",
            "alice;",
            "alice；",
            "alice\n",
            "alice bob",
            " alice",
            "alice\t",
            "alice\u{00a0}bob",
            "alice\u{200b}bob",
            "alice\u{2060}bob",
            "alice\u{feff}bob",
            "alice\u{200e}bob",
            "alice\u{200f}bob",
            "alice\u{061c}bob",
            "alice\u{202e}bob",
            "alice\u{2066}bob",
            "alice\u{2069}bob",
            "alice\u{0007}bob",
        ] {
            let err = ensure_wallet_name(bad).unwrap_err();
            assert!(
                err.to_string().contains("invalid wallet name"),
                "unexpected error for {bad:?}: {err}"
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn write_key_sets_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let unique = format!(
            "trnm-cli-wallet-perm-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let store = canonical_temp_root().join(unique);

        let wallet = write_key(
            &store,
            "alice",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap();

        let mode = std::fs::metadata(&wallet).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "unexpected wallet file mode: {:o}", mode);
        let store_mode = std::fs::metadata(&store).unwrap().permissions().mode() & 0o777;
        assert_eq!(store_mode, 0o700, "unexpected wallet store mode: {:o}", store_mode);

        let _ = std::fs::remove_file(&wallet);
        let _ = std::fs::remove_dir(&store);
    }

    #[test]
    #[cfg(unix)]
    fn read_key_refuses_group_or_world_accessible_wallet_file_or_store() {
        use std::os::unix::fs::PermissionsExt;

        let unique = format!(
            "trnm-cli-wallet-read-perm-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let store = canonical_temp_root().join(unique);
        std::fs::create_dir_all(&store).unwrap();
        let wallet = wallet_file(&store, "alice");
        std::fs::write(
            &wallet,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        )
        .unwrap();

        std::fs::set_permissions(&wallet, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = read_key(&store, "alice").unwrap_err();
        assert!(
            err.to_string().contains("wallet '")
                && err.to_string().contains("has insecure permissions"),
            "unexpected error: {err}"
        );

        std::fs::set_permissions(&wallet, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o755)).unwrap();
        let err = read_key(&store, "alice").unwrap_err();
        assert!(
            err.to_string().contains("wallet store '")
                && err.to_string().contains("has insecure permissions"),
            "unexpected error: {err}"
        );

        let _ = std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::remove_file(&wallet);
        let _ = std::fs::remove_dir(&store);
    }

    #[test]
    fn write_key_refuses_to_overwrite_existing_wallet_file() {
        let unique = format!(
            "trnm-cli-wallet-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let store = canonical_temp_root().join(unique);
        std::fs::create_dir_all(&store).unwrap();
        let existing = wallet_file(&store, "alice");
        std::fs::write(
            &existing,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        )
        .unwrap();

        let err = write_key(
            &store,
            "alice",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("refusing to overwrite existing key"),
            "unexpected error: {err}"
        );
        assert_eq!(
            std::fs::read_to_string(&existing).unwrap(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        );

        let _ = std::fs::remove_file(&existing);
        let _ = std::fs::remove_dir(&store);
    }

    #[test]
    #[cfg(unix)]
    fn write_key_refuses_existing_dangling_symlink_wallet_path() {
        use std::os::unix::fs::symlink;

        let unique = format!(
            "trnm-cli-wallet-symlink-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let store = canonical_temp_root().join(unique);
        std::fs::create_dir_all(&store).unwrap();
        let existing = wallet_file(&store, "alice");
        symlink(store.join("missing-target.key"), &existing).unwrap();

        let err = write_key(
            &store,
            "alice",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("refusing to overwrite existing key"),
            "unexpected error: {err}"
        );
        assert!(std::fs::symlink_metadata(&existing)
            .unwrap()
            .file_type()
            .is_symlink());

        let _ = std::fs::remove_file(&existing);
        let _ = std::fs::remove_dir(&store);
    }

    #[test]
    #[cfg(unix)]
    fn read_key_refuses_symlink_wallet_file_path() {
        use std::os::unix::fs::symlink;

        let unique = format!(
            "trnm-cli-wallet-read-symlink-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let store = canonical_temp_root().join(unique);
        std::fs::create_dir_all(&store).unwrap();

        let target = store.join("alice.real.key");
        std::fs::write(
            &target,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        )
        .unwrap();
        let wallet = wallet_file(&store, "alice");
        symlink(&target, &wallet).unwrap();

        let err = read_key(&store, "alice").unwrap_err();
        assert!(
            err.to_string()
                .contains("refusing to read key through non-regular wallet file path"),
            "unexpected error: {err}"
        );
        assert!(std::fs::symlink_metadata(&wallet)
            .unwrap()
            .file_type()
            .is_symlink());

        let _ = std::fs::remove_file(&wallet);
        let _ = std::fs::remove_file(&target);
        let _ = std::fs::remove_dir(&store);
    }

    #[test]
    fn read_key_refuses_non_directory_wallet_store() {
        let unique = format!(
            "trnm-cli-wallet-store-read-file-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root = canonical_temp_root().join(unique);
        std::fs::create_dir_all(&root).unwrap();
        let file_store = root.join("wallet-store-file");
        std::fs::write(&file_store, "not a directory\n").unwrap();

        let err = read_key(&file_store, "alice").unwrap_err();
        assert!(
            err.to_string().contains("wallet store")
                && err.to_string().contains("is not a directory")
                && err
                    .to_string()
                    .contains("refusing to read keys through non-regular wallet store path"),
            "unexpected error: {err}"
        );

        let _ = std::fs::remove_file(&file_store);
        let _ = std::fs::remove_dir(&root);
    }

    #[test]
    fn write_key_refuses_non_directory_wallet_store() {
        let unique = format!(
            "trnm-cli-wallet-store-write-file-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root = canonical_temp_root().join(unique);
        std::fs::create_dir_all(&root).unwrap();
        let file_store = root.join("wallet-store-file");
        std::fs::write(&file_store, "not a directory\n").unwrap();

        let err = write_key(
            &file_store,
            "alice",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("wallet store")
                && err.to_string().contains("is not a directory")
                && err
                    .to_string()
                    .contains("refusing to write keys through non-regular wallet store path"),
            "unexpected error: {err}"
        );
        assert!(!wallet_file(&file_store, "alice").exists());

        let _ = std::fs::remove_file(&file_store);
        let _ = std::fs::remove_dir(&root);
    }

    #[test]
    #[cfg(unix)]
    fn wallet_store_rejects_symlinked_ancestor_path_components() {
        use std::os::unix::fs::symlink;

        let unique = format!(
            "trnm-cli-wallet-ancestor-symlink-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root = std::env::temp_dir().join(unique);
        let real_parent = root.join("real-parent");
        let linked_parent = root.join("linked-parent");
        let store = linked_parent.join("wallets");
        std::fs::create_dir_all(&real_parent).unwrap();
        symlink(&real_parent, &linked_parent).unwrap();

        let write_err = write_key(
            &store,
            "alice",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap_err();
        assert!(
            write_err
                .to_string()
                .contains("traverses symlinked ancestor"),
            "unexpected error: {write_err}"
        );

        let wallet_path = real_parent.join("wallets").join("alice.key");
        std::fs::create_dir_all(wallet_path.parent().unwrap()).unwrap();
        std::fs::write(
            &wallet_path,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        )
        .unwrap();
        let read_err = read_key(&store, "alice").unwrap_err();
        assert!(
            read_err
                .to_string()
                .contains("traverses symlinked ancestor"),
            "unexpected error: {read_err}"
        );

        let _ = std::fs::remove_file(&wallet_path);
        let _ = std::fs::remove_dir(real_parent.join("wallets"));
        let _ = std::fs::remove_file(&linked_parent);
        let _ = std::fs::remove_dir(&real_parent);
        let _ = std::fs::remove_dir(&root);
    }

    #[test]
    #[cfg(unix)]
    fn write_key_refuses_symlink_wallet_store_path() {
        use std::os::unix::fs::symlink;

        let unique = format!(
            "trnm-cli-wallet-store-symlink-write-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root = canonical_temp_root().join(unique);
        let real_store = root.join("real-store");
        let linked_store = root.join("linked-store");
        std::fs::create_dir_all(&real_store).unwrap();
        symlink(&real_store, &linked_store).unwrap();

        let err = write_key(
            &linked_store,
            "alice",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("traverses symlinked ancestor"),
            "unexpected error: {err}"
        );
        assert!(!wallet_file(&linked_store, "alice").exists());

        let _ = std::fs::remove_file(&linked_store);
        let _ = std::fs::remove_dir(&real_store);
        let _ = std::fs::remove_dir(&root);
    }

    #[test]
    #[cfg(unix)]
    fn read_key_refuses_symlink_wallet_store_path() {
        use std::os::unix::fs::symlink;

        let unique = format!(
            "trnm-cli-wallet-store-symlink-read-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root = canonical_temp_root().join(unique);
        let real_store = root.join("real-store");
        let linked_store = root.join("linked-store");
        std::fs::create_dir_all(&real_store).unwrap();
        symlink(&real_store, &linked_store).unwrap();
        let wallet = real_store.join("alice.key");
        std::fs::write(
            &wallet,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        )
        .unwrap();

        let err = read_key(&linked_store, "alice").unwrap_err();
        assert!(
            err.to_string().contains("traverses symlinked ancestor"),
            "unexpected error: {err}"
        );

        let _ = std::fs::remove_file(&wallet);
        let _ = std::fs::remove_file(&linked_store);
        let _ = std::fs::remove_dir(&real_store);
        let _ = std::fs::remove_dir(&root);
    }

    #[test]
    #[cfg(unix)]
    fn wallet_create_rejects_symlinked_ancestor_from_env_store() {
        use std::os::unix::fs::symlink;

        let original_store = std::env::var_os("TRNM_WALLET_STORE");
        let unique = format!(
            "trnm-cli-wallet-env-ancestor-symlink-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root = std::env::temp_dir().join(unique);
        let real_parent = root.join("real-parent");
        let linked_parent = root.join("linked-parent");
        let store = linked_parent.join("wallets");
        std::fs::create_dir_all(&real_parent).unwrap();
        symlink(&real_parent, &linked_parent).unwrap();
        std::env::set_var("TRNM_WALLET_STORE", &store);

        let err = wallet_create("alice".to_string(), None).unwrap_err();
        assert!(
            err.to_string().contains("traverses symlinked ancestor")
                || err.to_string().contains("must be an absolute normalized symlink-free path"),
            "unexpected error: {err}"
        );

        match original_store {
            Some(value) => std::env::set_var("TRNM_WALLET_STORE", value),
            None => std::env::remove_var("TRNM_WALLET_STORE"),
        }
        let _ = std::fs::remove_file(&linked_parent);
        let _ = std::fs::remove_dir(&real_parent);
        let _ = std::fs::remove_dir(&root);
    }

    #[test]
    fn extract_tx_hash_supports_json_and_kv() {
        assert_eq!(extract_tx_hash("tx_hash=abc123").as_deref(), Some("abc123"));
        assert_eq!(
            extract_tx_hash("{\"tx_hash\":\"deadbeef\",\"status\":\"ok\"}").as_deref(),
            Some("deadbeef")
        );
    }

    #[test]
    fn extract_tx_hash_trims_quotes_and_trailing_punctuation() {
        assert_eq!(
            extract_tx_hash("tx_hash=\"0xabc123\", status=submitted").as_deref(),
            Some("0xabc123")
        );
        assert_eq!(
            extract_tx_hash("{\"txhash\":\"0xdef456;\"}").as_deref(),
            Some("0xdef456")
        );
    }

    #[test]
    fn extract_tx_hash_rejects_non_hex_prefixed_values() {
        assert_eq!(extract_tx_hash("tx_hash=0xzz99").as_deref(), None);
        assert_eq!(
            extract_tx_hash("{\"tx_hash\":\"0xhash-not-hex\"}").as_deref(),
            None
        );
    }

    #[test]
    fn format_tx_hash_line_quotes_value_for_shell_readiness_probes() {
        assert_eq!(
            format_tx_hash_line("0xabc123"),
            "tx_hash=\"0xabc123\"".to_string()
        );
        assert_eq!(
            format_tx_hash_alias_line("0xabc123"),
            "txhash=0xabc123".to_string()
        );
        assert_eq!(
            format_transaction_hash_alias_line("0xabc123"),
            "transaction_hash=0xabc123".to_string()
        );
        assert_eq!(
            format_transaction_hash_camel_alias_line("0xabc123"),
            "transactionHash=0xabc123".to_string()
        );
        assert_eq!(
            format_tx_hash_hyphen_alias_line("0xabc123"),
            "tx-hash=0xabc123".to_string()
        );
        assert_eq!(
            format_transaction_hash_hyphen_alias_line("0xabc123"),
            "transaction-hash=0xabc123".to_string()
        );
        assert_eq!(
            extract_tx_hash(&format_tx_hash_line("0xabc123")).as_deref(),
            Some("0xabc123")
        );
        assert_eq!(
            extract_tx_hash(&format_tx_hash_alias_line("0xabc123")).as_deref(),
            Some("0xabc123")
        );
        assert_eq!(
            extract_tx_hash(&format_transaction_hash_alias_line("0xabc123")).as_deref(),
            Some("0xabc123")
        );
        assert_eq!(
            extract_tx_hash(&format_transaction_hash_camel_alias_line("0xabc123")).as_deref(),
            Some("0xabc123")
        );
        assert_eq!(
            extract_tx_hash(&format_tx_hash_hyphen_alias_line("0xabc123")).as_deref(),
            Some("0xabc123")
        );
        assert_eq!(
            extract_tx_hash(&format_transaction_hash_hyphen_alias_line("0xabc123")).as_deref(),
            Some("0xabc123")
        );
    }

    #[test]
    fn extract_tx_hash_accepts_case_insensitive_keys_and_colon_separator() {
        assert_eq!(
            extract_tx_hash("INFO start TX_HASH:0xbeef01, done").as_deref(),
            Some("0xbeef01")
        );
        assert_eq!(
            extract_tx_hash("meta txHash=0xcafe02;").as_deref(),
            Some("0xcafe02")
        );
        assert_eq!(
            extract_tx_hash("operator transaction_hash:0xface03,").as_deref(),
            Some("0xface03")
        );
        assert_eq!(
            extract_tx_hash("note transactionHash=0xbabe04").as_deref(),
            Some("0xbabe04")
        );
        assert_eq!(
            extract_tx_hash("tx_hash = 0xfeed55").as_deref(),
            Some("0xfeed55")
        );
    }

    #[test]
    fn extract_tx_hash_accepts_hyphenated_key_aliases() {
        assert_eq!(
            extract_tx_hash("tx-hash=0xCAFE01").as_deref(),
            Some("0xcafe01")
        );
        assert_eq!(
            extract_tx_hash("transaction-hash: 0xBEEF02").as_deref(),
            Some("0xbeef02")
        );
    }

    #[test]
    fn extract_tx_hash_accepts_spaced_key_aliases() {
        assert_eq!(
            extract_tx_hash("tx hash=0xCAFE03").as_deref(),
            Some("0xcafe03")
        );
        assert_eq!(
            extract_tx_hash("transaction hash : 0xBEEF04").as_deref(),
            Some("0xbeef04")
        );
        assert_eq!(
            extract_tx_hash("INFO transaction hash = 0xBEEF05 done").as_deref(),
            Some("0xbeef05")
        );
    }

    #[test]
    fn extract_tx_hash_accepts_fullwidth_separators() {
        assert_eq!(
            extract_tx_hash("tx_hash＝0xFEED77").as_deref(),
            Some("0xfeed77")
        );
        assert_eq!(
            extract_tx_hash("transaction-hash：0xBEEF88").as_deref(),
            Some("0xbeef88")
        );
    }

    #[test]
    fn extract_tx_hash_accepts_uppercase_prefixed_hashes_and_json_aliases() {
        assert_eq!(
            extract_tx_hash("tx_hash=0xDEADBEEFCAFEBABE").as_deref(),
            Some("0xdeadbeefcafebabe")
        );
        assert_eq!(
            extract_tx_hash("{\"txHash\":\"ABCDEF012345\",\"status\":\"ok\"}").as_deref(),
            Some("abcdef012345")
        );
    }

    #[test]
    fn extract_tx_hash_accepts_nested_json_wrappers() {
        let wrapped = "{\"result\":{\"tx_response\":{\"txhash\":\"0xABC123\"}}}";
        assert_eq!(extract_tx_hash(wrapped).as_deref(), Some("0xabc123"));

        let response = "{\"response\":{\"data\":{\"transactionHash\":\"BEEF4567\"}}}";
        assert_eq!(extract_tx_hash(response).as_deref(), Some("beef4567"));
    }

    #[test]
    fn extract_tx_hash_accepts_angle_bracket_wrapped_hashes() {
        assert_eq!(
            extract_tx_hash("tx_hash=<0xBEEF42>").as_deref(),
            Some("0xbeef42")
        );
        assert_eq!(
            extract_tx_hash("see <transactionHash:0xCAFE99> now").as_deref(),
            Some("0xcafe99")
        );
    }

    #[test]
    fn extract_tx_hash_trims_sentence_punctuation_noise() {
        assert_eq!(
            extract_tx_hash("tx_hash=0xABCD1234.").as_deref(),
            Some("0xabcd1234")
        );
        assert_eq!(
            extract_tx_hash("transactionHash:0xBEEF42?!").as_deref(),
            Some("0xbeef42")
        );
    }

    #[test]
    fn extract_tx_hash_trims_hidden_unicode_wrappers() {
        assert_eq!(
            extract_tx_hash("tx_hash=\u{2068}<0xABCD1234>\u{2069}").as_deref(),
            Some("0xabcd1234")
        );
        assert_eq!(
            extract_tx_hash("transactionHash:\u{feff}0xBEEF42\u{200b}?!").as_deref(),
            Some("0xbeef42")
        );
    }

    #[test]
    fn extract_tx_hash_trims_hidden_unicode_from_key_names() {
        assert_eq!(
            extract_tx_hash("\u{2068}tx_hash\u{2069}=0xABCD1234").as_deref(),
            Some("0xabcd1234")
        );
        assert_eq!(
            extract_tx_hash("INFO \u{200e}transactionHash\u{200f}:0xBEEF42 done").as_deref(),
            Some("0xbeef42")
        );
    }

    #[test]
    fn extract_tx_hash_trims_unicode_whitespace_and_smart_quote_noise() {
        assert_eq!(
            extract_tx_hash("tx_hash=\u{00a0}“0xABCD1234”\u{2003}").as_deref(),
            Some("0xabcd1234")
        );
        assert_eq!(
            extract_tx_hash("transactionHash: ‘0xBEEF42’?!").as_deref(),
            Some("0xbeef42")
        );
    }

    #[test]
    fn extract_tx_hash_trims_fullwidth_wrapper_noise() {
        assert_eq!(
            extract_tx_hash("tx_hash=（《0xABCD1234》）；").as_deref(),
            Some("0xabcd1234")
        );
        assert_eq!(
            extract_tx_hash("transactionHash：『0xBEEF42』！？").as_deref(),
            Some("0xbeef42")
        );
    }

    #[test]
    fn extract_tx_hash_trims_guillemet_and_tortoise_shell_noise() {
        assert_eq!(
            extract_tx_hash("tx_hash=«0xABCD1234». ").as_deref(),
            Some("0xabcd1234")
        );
        assert_eq!(
            extract_tx_hash("transactionHash=〔〝0xBEEF42〞〕；").as_deref(),
            Some("0xbeef42")
        );
    }

    #[test]
    fn run_template_extracts_nested_json_tx_hash_without_fallback_surrogate() {
        let cmd = "python3 -c \"print('{\\\"result\\\":{\\\"tx_response\\\":{\\\"txhash\\\":\\\"0xABC123\\\"}}}')\"";
        let extracted = run_template(cmd).unwrap();
        assert_eq!(extracted, "0xabc123");
    }

    #[test]
    fn tx_query_parse_json_and_kv() {
        let json = "{\"tx_hash\":\"0xabc\",\"status\":\"committed\",\"error\":null}";
        let parsed = parse_tx_query_response(json, "0xabc").unwrap();
        assert_eq!(parsed.status, "committed");
        assert_eq!(parsed.error, None);

        let kv = "tx_hash=0xdef\nstatus=fail\nerror=insufficient balance\n";
        let parsed_kv = parse_tx_query_response(kv, "0xdef").unwrap();
        assert_eq!(parsed_kv.status, "fail");
        assert_eq!(parsed_kv.error.as_deref(), Some("insufficient balance"));
    }

    #[test]
    fn tx_query_parse_json_nested_result_payload() {
        let json = "{\"result\":{\"tx_hash\":\"0xabc\",\"status\":\"success\",\"error\":null}}";
        let parsed = parse_tx_query_response(json, "0xfallback").unwrap();
        assert_eq!(parsed.tx_hash, "0xabc");
        assert_eq!(parsed.status, "committed");
        assert_eq!(parsed.error, None);
    }

    #[test]
    fn tx_query_parse_json_accepts_nested_tx_response_wrappers() {
        let wrapped = "{\"tx_response\":{\"txhash\":\"ABC123\",\"code\":0}}";
        let parsed_wrapped = parse_tx_query_response(wrapped, "0xfallback").unwrap();
        assert_eq!(parsed_wrapped.tx_hash, "abc123");
        assert_eq!(parsed_wrapped.status, "committed");
        assert_eq!(parsed_wrapped.error, None);

        let nested = "{\"result\":{\"response\":{\"tx_response\":{\"transactionHash\":\"0xdef456\",\"transactionState\":\"FINALIZED\",\"error\":\"NULL\"}}}}";
        let parsed_nested = parse_tx_query_response(nested, "0xfallback").unwrap();
        assert_eq!(parsed_nested.tx_hash, "0xdef456");
        assert_eq!(parsed_nested.status, "committed");
        assert_eq!(parsed_nested.error, None);

        let nested_response_data = "{\"result\":{\"response\":{\"data\":{\"transactionHash\":\"0xfeed99\",\"transactionStatus\":\"confirmed\",\"rawLog\":\"NULL\"}}}}";
        let parsed_nested_response_data =
            parse_tx_query_response(nested_response_data, "0xfallback").unwrap();
        assert_eq!(parsed_nested_response_data.tx_hash, "0xfeed99");
        assert_eq!(parsed_nested_response_data.status, "committed");
        assert_eq!(parsed_nested_response_data.error, None);

        let result_response_data = "{\"result\":{\"responseData\":{\"txHash\":\"0xbeef77\",\"txStatus\":\"accepted\",\"rawLog\":\"null\"}}}";
        let parsed_result_response_data =
            parse_tx_query_response(result_response_data, "0xfallback").unwrap();
        assert_eq!(parsed_result_response_data.tx_hash, "0xbeef77");
        assert_eq!(parsed_result_response_data.status, "pending");
        assert_eq!(parsed_result_response_data.error, None);
    }

    #[test]
    fn tx_query_parse_json_accepts_camel_and_transaction_hash_keys() {
        let camel = "{\"result\":{\"txHash\":\"0xabc\",\"status\":\"success\"}}";
        let parsed_camel = parse_tx_query_response(camel, "0xfallback").unwrap();
        assert_eq!(parsed_camel.tx_hash, "0xabc");
        assert_eq!(parsed_camel.status, "committed");

        let transaction = "{\"transactionHash\":\"0xdef\",\"status\":\"committed\"}";
        let parsed_transaction = parse_tx_query_response(transaction, "0xfallback").unwrap();
        assert_eq!(parsed_transaction.tx_hash, "0xdef");
        assert_eq!(parsed_transaction.status, "committed");

        let tx_status_snake = "{\"tx_hash\":\"0xaaa\",\"tx_status\":\"accepted\"}";
        let parsed_tx_status_snake =
            parse_tx_query_response(tx_status_snake, "0xfallback").unwrap();
        assert_eq!(parsed_tx_status_snake.tx_hash, "0xaaa");
        assert_eq!(parsed_tx_status_snake.status, "pending");

        let tx_status_camel = "{\"txHash\":\"0xbbb\",\"txStatus\":\"finalized\"}";
        let parsed_tx_status_camel =
            parse_tx_query_response(tx_status_camel, "0xfallback").unwrap();
        assert_eq!(parsed_tx_status_camel.tx_hash, "0xbbb");
        assert_eq!(parsed_tx_status_camel.status, "committed");

        let transaction_status_snake =
            "{\"transactionHash\":\"0xccc\",\"transaction_status\":\"confirmed\"}";
        let parsed_transaction_status_snake =
            parse_tx_query_response(transaction_status_snake, "0xfallback").unwrap();
        assert_eq!(parsed_transaction_status_snake.tx_hash, "0xccc");
        assert_eq!(parsed_transaction_status_snake.status, "committed");

        let transaction_status_camel =
            "{\"transaction_hash\":\"0xddd\",\"transactionStatus\":\"timed-out\"}";
        let parsed_transaction_status_camel =
            parse_tx_query_response(transaction_status_camel, "0xfallback").unwrap();
        assert_eq!(parsed_transaction_status_camel.tx_hash, "0xddd");
        assert_eq!(parsed_transaction_status_camel.status, "fail");

        let state_alias = "{\"transactionHash\":\"0xeee\",\"transactionState\":\"included\"}";
        let parsed_state_alias = parse_tx_query_response(state_alias, "0xfallback").unwrap();
        assert_eq!(parsed_state_alias.tx_hash, "0xeee");
        assert_eq!(parsed_state_alias.status, "committed");
    }

    #[test]
    fn events_query_parse_json_accepts_metering_audit_payloads() {
        let raw = r#"[{"event_type":"resolve","task_id":42,"from_status":"Challenged","to_status":"Completed","actor":"authority","tx_id":12,"block_height":4,"state_root":"0xdef","ts_unix_ms":124,"metering":{"workload_class":"llm_inference","metering_schema":"llm_token_meter_v1","receipt_hash":"deadbeef","prompt_tokens":128,"generated_tokens":32,"decode_steps":32,"kv_bytes_moved":4096,"normalized_work_units":192,"prompt_token_weight":1,"generated_token_weight":1,"decode_step_weight":1,"kv_byte_weight":0,"policy":{"snapshot_version":1,"min_accept_work_units":100,"challenge_success_bounty_base":1,"challenge_success_bounty_per_work_unit_num":1,"challenge_success_bounty_per_work_unit_den":192,"worker_completion_bonus_per_work_unit_num":1,"worker_completion_bonus_per_work_unit_den":256,"worker_slash_rebate_per_work_unit_num":1,"worker_slash_rebate_per_work_unit_den":384}}}]"#;
        let parsed = parse_events_query_response(raw, 42).unwrap();
        assert_eq!(
            parsed[0]["metering"]["normalized_work_units"],
            serde_json::json!(192)
        );
        assert_eq!(
            parsed[0]["metering"]["policy"]["snapshot_version"],
            serde_json::json!(1)
        );
    }

    #[test]
    fn events_query_rejects_mismatched_task_id() {
        let raw = r#"[{"event_type":"commit","task_id":43,"from_status":"Assigned","to_status":"Committed","actor":"worker-a","tx_id":1,"block_height":1,"state_root":"abc","ts_unix_ms":1}]"#;
        let err = parse_events_query_response(raw, 42).unwrap_err();
        assert!(err
            .to_string()
            .contains("events query response task_id mismatch"));
    }

    #[test]
    fn events_query_uses_template_override_and_preserves_metering_block() {
        std::env::set_var(
            "TRNM_QUERY_EVENTS_CMD",
            r#"printf '%s' '[{"event_type":"resolve","task_id":42,"from_status":"Challenged","to_status":"Completed","actor":"authority","tx_id":12,"block_height":4,"state_root":"0xdef","ts_unix_ms":124,"metering":{"normalized_work_units":192,"policy":{"snapshot_version":1}}}]'"#,
        );
        let got = events_query(42, 5).unwrap();
        std::env::remove_var("TRNM_QUERY_EVENTS_CMD");
        assert_eq!(got[0]["task_id"], serde_json::json!(42));
        assert_eq!(
            got[0]["metering"]["normalized_work_units"],
            serde_json::json!(192)
        );
        assert_eq!(
            got[0]["metering"]["policy"]["snapshot_version"],
            serde_json::json!(1)
        );
    }

    #[test]
    fn render_events_query_summary_prefers_rpc_derived_block_when_present() {
        let raw = serde_json::json!([
            {
                "event_type": "resolve",
                "task_id": 42,
                "from_status": "Challenged",
                "to_status": "Completed",
                "actor": "authority",
                "tx_id": 12,
                "block_height": 4,
                "resolution_code": "completed",
                "bond_disposition": "forfeited",
                "metering": {
                    "workload_class": "llm_inference",
                    "metering_schema": "llm_token_meter_v1",
                    "receipt_hash": "deadbeef",
                    "normalized_work_units": 192,
                    "policy": {
                        "snapshot_version": 1,
                        "min_accept_work_units": 100,
                        "challenge_success_bounty_base": 1,
                        "challenge_success_bounty_per_work_unit_num": 99,
                        "challenge_success_bounty_per_work_unit_den": 1,
                        "worker_completion_bonus_per_work_unit_num": 99,
                        "worker_completion_bonus_per_work_unit_den": 1,
                        "worker_slash_rebate_per_work_unit_num": 99,
                        "worker_slash_rebate_per_work_unit_den": 1
                    },
                    "derived": {
                        "path": "Completed",
                        "accept_floor_pass": true,
                        "challenge_metered_bonus": 1,
                        "challenge_bonus_total": 2,
                        "worker_completion_bonus": 1,
                        "worker_slash_rebate": 1
                    }
                }
            }
        ]);
        let summary = render_events_query_summary(&raw).unwrap();
        assert!(summary.contains(
            "challenge_bonus_total=2 (metered=1) worker_completion_bonus=1 worker_slash_rebate=1"
        ));
        assert!(!summary.contains("challenge_bonus_total=19009"));
    }

    #[test]
    fn render_events_query_summary_includes_metering_policy_lines() {
        let raw = serde_json::json!([
            {
                "event_type": "resolve",
                "task_id": 42,
                "from_status": "Challenged",
                "to_status": "Completed",
                "actor": "authority",
                "tx_id": 12,
                "block_height": 4,
                "resolution_code": "completed",
                "bond_disposition": "forfeited",
                "metering": {
                    "workload_class": "llm_inference",
                    "metering_schema": "llm_token_meter_v1",
                    "receipt_hash": "deadbeef",
                    "normalized_work_units": 192,
                    "policy": {
                        "snapshot_version": 1,
                        "min_accept_work_units": 100,
                        "challenge_success_bounty_base": 1,
                        "challenge_success_bounty_per_work_unit_num": 1,
                        "challenge_success_bounty_per_work_unit_den": 192,
                        "worker_completion_bonus_per_work_unit_num": 1,
                        "worker_completion_bonus_per_work_unit_den": 256,
                        "worker_slash_rebate_per_work_unit_num": 1,
                        "worker_slash_rebate_per_work_unit_den": 384
                    }
                }
            }
        ]);
        let summary = render_events_query_summary(&raw).unwrap();
        assert!(summary.contains("events_total=1"));
        assert!(summary.contains("work_units=192"));
        assert!(summary.contains("policy snapshot=1 floor=100 bounty_base=1 chall_bonus=1/192 worker_bonus=1/256 worker_rebate=1/384"));
        assert!(summary.contains("derived path=Completed accept_floor=pass(192>=100) challenge_bonus_total=2 (metered=1) worker_completion_bonus=1 worker_slash_rebate=1"));
    }

    #[test]
    fn render_request_full_query_summary_includes_timeline_and_metering() {
        let raw = serde_json::json!({
            "request": {
                "request_id": "req-42",
                "task_id": 42,
                "channel": "telegram",
                "session_id": "session-1",
                "status": "resolved"
            },
            "verifier_status": "ok",
            "resolution_code": "completed",
            "result_hash": "abcd",
            "commit_tx_hash": "0x1",
            "reveal_tx_hash": "0x2",
            "events": [{
                "event_type": "resolve",
                "task_id": 42,
                "from_status": "Challenged",
                "to_status": "Completed",
                "actor": "authority",
                "tx_id": 3,
                "resolution_code": "completed",
                "bond_disposition": "forfeited",
                "metering": {
                    "workload_class": "llm_inference",
                    "metering_schema": "llm_token_meter_v1",
                    "receipt_hash": "deadbeef",
                    "normalized_work_units": 192,
                    "policy": {
                        "snapshot_version": 1,
                        "min_accept_work_units": 100,
                        "challenge_success_bounty_base": 1,
                        "challenge_success_bounty_per_work_unit_num": 1,
                        "challenge_success_bounty_per_work_unit_den": 192,
                        "worker_completion_bonus_per_work_unit_num": 1,
                        "worker_completion_bonus_per_work_unit_den": 256,
                        "worker_slash_rebate_per_work_unit_num": 1,
                        "worker_slash_rebate_per_work_unit_den": 384
                    }
                }
            }]
        });
        let summary = render_request_full_query_summary(&raw).unwrap();
        assert!(summary.contains("request_id=req-42"));
        assert!(summary.contains("task_id=42"));
        assert!(summary.contains("commit_tx_hash=0x1 reveal_tx_hash=0x2 result_hash=abcd"));
        assert!(summary.contains("work_units=192"));
        assert!(summary.contains("derived path=Completed accept_floor=pass(192>=100) challenge_bonus_total=2 (metered=1) worker_completion_bonus=1 worker_slash_rebate=1"));
    }

    #[test]
    fn request_full_query_parse_json_accepts_metering_timeline() {
        let raw = r#"{"request":{"request_id":"req-42","task_id":42,"channel":"telegram","user_id":"u1","session_id":"s1","text":"hi","idempotency_key":"k1","status":"resolved","created_at_unix_ms":123},"verifier_status":"ok","resolution_code":"completed","result_hash":"abcd","commit_tx_hash":"0x1","reveal_tx_hash":"0x2","events":[{"event_type":"reveal","task_id":42,"from_status":"Committed","to_status":"Revealed","actor":"worker-a","tx_id":2,"block_height":2,"state_root":"0xdef","ts_unix_ms":124,"metering":{"normalized_work_units":192,"policy":{"snapshot_version":1}}}]}"#;
        let parsed = parse_request_full_query_response(raw, "req-42").unwrap();
        assert_eq!(parsed["request"]["request_id"], serde_json::json!("req-42"));
        assert_eq!(
            parsed["events"][0]["metering"]["normalized_work_units"],
            serde_json::json!(192)
        );
        assert_eq!(
            parsed["events"][0]["metering"]["policy"]["snapshot_version"],
            serde_json::json!(1)
        );
    }

    #[test]
    fn request_full_query_rejects_mismatched_request_id() {
        let raw = r#"{"request":{"request_id":"req-43","task_id":42},"events":[]}"#;
        let err = parse_request_full_query_response(raw, "req-42").unwrap_err();
        assert!(err
            .to_string()
            .contains("request-full response request_id mismatch"));
    }

    #[test]
    fn request_full_query_rejects_event_task_id_mismatch() {
        let raw = r#"{"request":{"request_id":"req-42","task_id":42},"events":[{"task_id":43}]}"#;
        let err = parse_request_full_query_response(raw, "req-42").unwrap_err();
        assert!(err
            .to_string()
            .contains("request-full response event task_id mismatch"));
    }

    #[test]
    fn request_full_query_uses_template_override_and_preserves_metering_timeline() {
        std::env::set_var(
            "TRNM_QUERY_REQUEST_FULL_CMD",
            r#"printf '%s' '{"request":{"request_id":"req-42","task_id":42,"channel":"telegram","user_id":"u1","session_id":"s1","text":"hi","idempotency_key":"k1","status":"resolved","created_at_unix_ms":123},"events":[{"event_type":"resolve","task_id":42,"from_status":"Challenged","to_status":"Completed","actor":"authority","tx_id":3,"block_height":3,"state_root":"0xghi","ts_unix_ms":125,"metering":{"normalized_work_units":192,"policy":{"snapshot_version":1}}}]}'"#,
        );
        let got = request_full_query("req-42", 5).unwrap();
        std::env::remove_var("TRNM_QUERY_REQUEST_FULL_CMD");
        assert_eq!(got["request"]["request_id"], serde_json::json!("req-42"));
        assert_eq!(
            got["events"][0]["metering"]["normalized_work_units"],
            serde_json::json!(192)
        );
        assert_eq!(
            got["events"][0]["metering"]["policy"]["snapshot_version"],
            serde_json::json!(1)
        );
    }

    #[test]
    fn task_query_parse_json_accepts_metering_audit_payload() {
        let raw = r#"{"task_id":42,"status":"Revealed","worker":"worker-a","bounty":777,"result_hash_hex":"abcd","version":9,"metering":{"workload_class":"llm_inference","metering_schema":"llm_token_meter_v1","receipt_hash":"deadbeef","prompt_tokens":128,"generated_tokens":32,"decode_steps":32,"kv_bytes_moved":4096,"normalized_work_units":192,"prompt_token_weight":1,"generated_token_weight":1,"decode_step_weight":1,"kv_byte_weight":0,"policy":{"snapshot_version":1,"min_accept_work_units":100,"challenge_success_bounty_base":1,"challenge_success_bounty_per_work_unit_num":1,"challenge_success_bounty_per_work_unit_den":192,"worker_completion_bonus_per_work_unit_num":1,"worker_completion_bonus_per_work_unit_den":256,"worker_slash_rebate_per_work_unit_num":1,"worker_slash_rebate_per_work_unit_den":384}}}"#;
        let parsed = parse_task_query_response(raw, 42).unwrap();
        assert_eq!(
            parsed["metering"]["normalized_work_units"],
            serde_json::json!(192)
        );
        assert_eq!(
            parsed["metering"]["policy"]["snapshot_version"],
            serde_json::json!(1)
        );
    }

    #[test]
    fn task_query_accepts_consistent_metadata_compatibility_signals() {
        let raw = r#"{"task_id":42,"status":"Assigned","worker":"worker-a","bounty":777,"result_hash_hex":null,"version":9,"metadata_compatibility":{"legacy_note_only":true,"canonical_core_fields":true,"complete_metering_snapshot":true},"metadata_runtime_compatible":true,"metadata_requires_governance_upgrade":true,"metadata_primary_compatibility_finding":"legacy_note_only_payload","metadata_compatibility_findings":["legacy_note_only_payload"]}"#;
        let parsed = parse_task_query_response(raw, 42).unwrap();
        assert_eq!(
            parsed["metadata_runtime_compatible"],
            serde_json::json!(true)
        );
        assert_eq!(
            parsed["metadata_requires_governance_upgrade"],
            serde_json::json!(true)
        );
        assert_eq!(
            parsed["metadata_primary_compatibility_finding"],
            serde_json::json!("legacy_note_only_payload")
        );
        assert_eq!(
            parsed["metadata_compatibility_findings"],
            serde_json::json!(["legacy_note_only_payload"])
        );
    }

    #[test]
    fn task_query_rejects_inconsistent_metadata_runtime_compatible_signal() {
        let raw = r#"{"task_id":42,"status":"Assigned","worker":"worker-a","bounty":777,"result_hash_hex":null,"version":9,"metadata_compatibility":{"legacy_note_only":false,"canonical_core_fields":true,"complete_metering_snapshot":true},"metadata_runtime_compatible":false,"metadata_requires_governance_upgrade":true}"#;
        let err = parse_task_query_response(raw, 42).unwrap_err();
        assert!(err
            .to_string()
            .contains("metadata_runtime_compatible mismatch"));
    }

    #[test]
    fn task_query_rejects_inconsistent_metadata_findings() {
        let raw = r#"{"task_id":42,"status":"Assigned","worker":"worker-a","bounty":777,"result_hash_hex":null,"version":9,"metadata_compatibility":{"legacy_note_only":false,"canonical_core_fields":false,"complete_metering_snapshot":true},"metadata_runtime_compatible":false,"metadata_requires_governance_upgrade":true,"metadata_primary_compatibility_finding":"non_canonical_core_fields","metadata_compatibility_findings":["legacy_note_only_payload"]}"#;
        let err = parse_task_query_response(raw, 42).unwrap_err();
        assert!(err
            .to_string()
            .contains("metadata_compatibility_findings mismatch"));
    }

    #[test]
    fn task_query_rejects_inconsistent_metadata_primary_finding() {
        let raw = r#"{"task_id":42,"status":"Assigned","worker":"worker-a","bounty":777,"result_hash_hex":null,"version":9,"metadata_compatibility":{"legacy_note_only":false,"canonical_core_fields":false,"complete_metering_snapshot":true},"metadata_runtime_compatible":false,"metadata_requires_governance_upgrade":true,"metadata_primary_compatibility_finding":"legacy_note_only_payload","metadata_compatibility_findings":["non_canonical_core_fields"]}"#;
        let err = parse_task_query_response(raw, 42).unwrap_err();
        assert!(err
            .to_string()
            .contains("metadata_primary_compatibility_finding mismatch"));
    }

    #[test]
    fn task_query_rejects_missing_runtime_compatible_when_metadata_compatibility_present() {
        let raw = r#"{"task_id":42,"status":"Assigned","worker":"worker-a","bounty":777,"result_hash_hex":null,"version":9,"metadata_compatibility":{"legacy_note_only":false,"canonical_core_fields":true,"complete_metering_snapshot":true},"metadata_requires_governance_upgrade":false}"#;
        let err = parse_task_query_response(raw, 42).unwrap_err();
        assert!(err
            .to_string()
            .contains("metadata_compatibility requires boolean metadata_runtime_compatible"));
    }

    #[test]
    fn task_query_rejects_missing_governance_upgrade_when_metadata_compatibility_present() {
        let raw = r#"{"task_id":42,"status":"Assigned","worker":"worker-a","bounty":777,"result_hash_hex":null,"version":9,"metadata_compatibility":{"legacy_note_only":false,"canonical_core_fields":true,"complete_metering_snapshot":true},"metadata_runtime_compatible":true}"#;
        let err = parse_task_query_response(raw, 42).unwrap_err();
        assert!(err.to_string().contains(
            "metadata_compatibility requires boolean metadata_requires_governance_upgrade"
        ));
    }

    #[test]
    fn task_query_rejects_runtime_compatible_signal_without_metadata_compatibility() {
        let raw = r#"{"task_id":42,"status":"Assigned","worker":"worker-a","bounty":777,"result_hash_hex":null,"version":9,"metadata_runtime_compatible":true}"#;
        let err = parse_task_query_response(raw, 42).unwrap_err();
        assert!(err
            .to_string()
            .contains("metadata_runtime_compatible requires metadata_compatibility"));
    }

    #[test]
    fn task_query_rejects_governance_upgrade_signal_without_metadata_compatibility() {
        let raw = r#"{"task_id":42,"status":"Assigned","worker":"worker-a","bounty":777,"result_hash_hex":null,"version":9,"metadata_requires_governance_upgrade":true}"#;
        let err = parse_task_query_response(raw, 42).unwrap_err();
        assert!(err
            .to_string()
            .contains("metadata_requires_governance_upgrade requires metadata_compatibility"));
    }

    #[test]
    fn task_query_rejects_findings_without_metadata_compatibility() {
        let raw = r#"{"task_id":42,"status":"Assigned","worker":"worker-a","bounty":777,"result_hash_hex":null,"version":9,"metadata_compatibility_findings":["legacy_note_only_payload"]}"#;
        let err = parse_task_query_response(raw, 42).unwrap_err();
        assert!(err
            .to_string()
            .contains("metadata_compatibility_findings requires metadata_compatibility"));
    }

    #[test]
    fn task_query_rejects_primary_finding_without_metadata_compatibility() {
        let raw = r#"{"task_id":42,"status":"Assigned","worker":"worker-a","bounty":777,"result_hash_hex":null,"version":9,"metadata_primary_compatibility_finding":"legacy_note_only_payload"}"#;
        let err = parse_task_query_response(raw, 42).unwrap_err();
        assert!(err
            .to_string()
            .contains("metadata_primary_compatibility_finding requires metadata_compatibility"));
    }

    #[test]
    fn task_query_rejects_empty_metadata_compatibility_findings_array() {
        let raw = r#"{"task_id":42,"status":"Assigned","worker":"worker-a","bounty":777,"result_hash_hex":null,"version":9,"metadata_compatibility":{"legacy_note_only":false,"canonical_core_fields":true,"complete_metering_snapshot":true},"metadata_runtime_compatible":true,"metadata_requires_governance_upgrade":false,"metadata_compatibility_findings":[]}"#;
        let err = parse_task_query_response(raw, 42).unwrap_err();
        assert!(err
            .to_string()
            .contains("metadata_compatibility_findings must be omitted when empty"));
    }

    #[test]
    fn task_query_rejects_missing_findings_when_compatibility_implies_them() {
        let raw = r#"{"task_id":42,"status":"Assigned","worker":"worker-a","bounty":777,"result_hash_hex":null,"version":9,"metadata_compatibility":{"legacy_note_only":true,"canonical_core_fields":true,"complete_metering_snapshot":true},"metadata_runtime_compatible":true,"metadata_requires_governance_upgrade":true,"metadata_primary_compatibility_finding":"legacy_note_only_payload"}"#;
        let err = parse_task_query_response(raw, 42).unwrap_err();
        assert!(err.to_string().contains(
            "metadata_compatibility_findings required when compatibility implies findings"
        ));
    }

    #[test]
    fn task_query_rejects_missing_primary_finding_when_compatibility_implies_one() {
        let raw = r#"{"task_id":42,"status":"Assigned","worker":"worker-a","bounty":777,"result_hash_hex":null,"version":9,"metadata_compatibility":{"legacy_note_only":false,"canonical_core_fields":false,"complete_metering_snapshot":true},"metadata_runtime_compatible":false,"metadata_requires_governance_upgrade":true,"metadata_compatibility_findings":["non_canonical_core_fields"]}"#;
        let err = parse_task_query_response(raw, 42).unwrap_err();
        assert!(err
            .to_string()
            .contains("metadata_primary_compatibility_finding mismatch"));
    }

    #[test]
    fn task_query_rejects_mismatched_task_id() {
        let raw = r#"{"task_id":43,"status":"Open","worker":null,"bounty":100,"result_hash_hex":null,"version":1}"#;
        let err = parse_task_query_response(raw, 42).unwrap_err();
        assert!(err
            .to_string()
            .contains("task query response task_id mismatch"));
    }

    #[test]
    fn task_query_uses_template_override_and_preserves_metering_block() {
        std::env::set_var(
            "TRNM_QUERY_TASK_CMD",
            r#"printf '%s' '{"task_id":42,"status":"Revealed","worker":"worker-a","bounty":777,"result_hash_hex":"abcd","version":9,"metering":{"normalized_work_units":192,"policy":{"snapshot_version":1}}}'"#,
        );
        let got = task_query(42).unwrap();
        std::env::remove_var("TRNM_QUERY_TASK_CMD");
        assert_eq!(got["task_id"], serde_json::json!(42));
        assert_eq!(
            got["metering"]["normalized_work_units"],
            serde_json::json!(192)
        );
        assert_eq!(
            got["metering"]["policy"]["snapshot_version"],
            serde_json::json!(1)
        );
    }

    #[test]
    fn tx_query_rejects_mismatched_tx_hash() {
        std::env::set_var(
            "TRNM_TX_QUERY_CMD",
            "printf '{\"tx_hash\":\"0xaaaa\",\"status\":\"committed\"}'",
        );
        let got = tx_query("0xbbbb");
        std::env::remove_var("TRNM_TX_QUERY_CMD");
        assert!(got.is_err());
    }

    #[test]
    fn run_template_raw_merges_successful_stdout_and_stderr() {
        let merged = run_template_raw(
            "python3 -c \"import sys; print('tx_hash=0xabc123'); sys.stderr.write('status=committed\\n')\"",
        )
        .unwrap();
        assert!(merged.contains("tx_hash=0xabc123"), "unexpected: {merged}");
        assert!(merged.contains("status=committed"), "unexpected: {merged}");
    }

    #[test]
    fn tx_query_rejects_non_hex_like_tx_hash_before_shell_exec() {
        std::env::set_var(
            "TRNM_TX_QUERY_CMD",
            "printf '{\"tx_hash\":\"0xaaaa\",\"status\":\"committed\"}'",
        );
        let got = tx_query("0xabc; touch /tmp/pwned");
        std::env::remove_var("TRNM_TX_QUERY_CMD");
        assert!(got.is_err());
        let msg = got.err().unwrap().to_string();
        assert!(
            msg.contains("invalid tx hash for query"),
            "unexpected: {msg}"
        );
    }

    #[test]
    fn tx_query_parse_kv_is_tolerant_to_case_and_separator() {
        let kv = "TXHASH: 0x777\nSTATUS: committed\nERROR: null\n";
        let parsed = parse_tx_query_response(kv, "0xfallback").unwrap();
        assert_eq!(parsed.tx_hash, "0x777");
        assert_eq!(parsed.status, "committed");
        assert_eq!(parsed.error, None);
    }

    #[test]
    fn tx_query_parse_kv_treats_nullish_error_variants_as_empty() {
        let kv = "tx_hash=0x777\nstatus=committed\nerror='NULL,'\n";
        let parsed = parse_tx_query_response(kv, "0xfallback").unwrap();
        assert_eq!(parsed.tx_hash, "0x777");
        assert_eq!(parsed.status, "committed");
        assert_eq!(parsed.error, None);

        let backtick_kv = "tx_hash=0x778\nstatus=`COMMITTED`\nerror=`null`,\n";
        let parsed_backtick = parse_tx_query_response(backtick_kv, "0xfallback").unwrap();
        assert_eq!(parsed_backtick.tx_hash, "0x778");
        assert_eq!(parsed_backtick.status, "committed");
        assert_eq!(parsed_backtick.error, None);
    }

    #[test]
    fn tx_query_parse_kv_tolerates_unicode_wrapped_status_and_null_error() {
        let kv =
            "transactionHash：0xBEEF42\nstatus=\u{2068}“SUCCESS！”\u{2069}\nerror=『NULL？』\n";
        let parsed = parse_tx_query_response(kv, "0xfallback").unwrap();
        assert_eq!(parsed.tx_hash, "0xbeef42");
        assert_eq!(parsed.status, "committed");
        assert_eq!(parsed.error, None);

        let guillemet_wrapped = "transactionHash=0xBEEF44\nstatus=«confirmed»\nerror=〚NULL〛；\n";
        let parsed_guillemet = parse_tx_query_response(guillemet_wrapped, "0xfallback").unwrap();
        assert_eq!(parsed_guillemet.tx_hash, "0xbeef44");
        assert_eq!(parsed_guillemet.status, "committed");
        assert_eq!(parsed_guillemet.error, None);
    }

    #[test]
    fn tx_query_parse_kv_accepts_fullwidth_wrapped_inline_tokens() {
        let noisy = "【rpc】 《transactionHash：0xCAFE98》 《status：COMMITTED》 《error：NULL》";
        let parsed = parse_tx_query_response(noisy, "0xfallback").unwrap();
        assert_eq!(parsed.tx_hash, "0xcafe98");
        assert_eq!(parsed.status, "committed");
        assert_eq!(parsed.error, None);
    }

    #[test]
    fn tx_query_parse_kv_unwraps_single_and_backtick_quoted_error_values() {
        let single = "tx_hash=0x781\nstatus=fail\nerror='nonce mismatch'\n";
        let parsed_single = parse_tx_query_response(single, "0xfallback").unwrap();
        assert_eq!(parsed_single.error.as_deref(), Some("nonce mismatch"));

        let backtick = "tx_hash=0x782\nstatus=fail\nerror=`signature invalid`\n";
        let parsed_backtick = parse_tx_query_response(backtick, "0xfallback").unwrap();
        assert_eq!(parsed_backtick.error.as_deref(), Some("signature invalid"));

        let raw_log = "tx_hash=0x783\nstatus=fail\nraw_log='deliver tx failed'\n";
        let parsed_raw_log = parse_tx_query_response(raw_log, "0xfallback").unwrap();
        assert_eq!(parsed_raw_log.error.as_deref(), Some("deliver tx failed"));

        let log_alias = "tx_hash=0x784\nstatus=fail\nlog=`check tx failed`\n";
        let parsed_log_alias = parse_tx_query_response(log_alias, "0xfallback").unwrap();
        assert_eq!(parsed_log_alias.error.as_deref(), Some("check tx failed"));
    }

    #[test]
    fn tx_query_parse_kv_accepts_noisy_single_line_inline_tokens() {
        let noisy = "[adapter] ts=1700000000 status=committed tx_hash=0x8badf00d, error=null";
        let parsed = parse_tx_query_response(noisy, "0xfallback").unwrap();
        assert_eq!(parsed.tx_hash, "0x8badf00d");
        assert_eq!(parsed.status, "committed");
        assert_eq!(parsed.error, None);
    }

    #[test]
    fn tx_query_parse_json_treats_nullish_error_variants_as_empty() {
        let json = "{\"tx_hash\":\"0x777\",\"status\":\"committed\",\"error\":\"NULL,\"}";
        let parsed = parse_tx_query_response(json, "0xfallback").unwrap();
        assert_eq!(parsed.tx_hash, "0x777");
        assert_eq!(parsed.status, "committed");
        assert_eq!(parsed.error, None);
    }

    #[test]
    fn tx_query_parse_json_preserves_non_string_error_payloads() {
        let json_numeric = "{\"tx_hash\":\"0x777\",\"status\":\"fail\",\"error\":404}";
        let parsed_numeric = parse_tx_query_response(json_numeric, "0xfallback").unwrap();
        assert_eq!(parsed_numeric.error.as_deref(), Some("404"));

        let json_obj =
            "{\"tx_hash\":\"0x777\",\"status\":\"fail\",\"error\":{\"code\":\"E_NONCE\"}}";
        let parsed_obj = parse_tx_query_response(json_obj, "0xfallback").unwrap();
        assert_eq!(parsed_obj.error.as_deref(), Some("{\"code\":\"E_NONCE\"}"));

        let json_raw_log =
            "{\"tx_hash\":\"0x778\",\"status\":\"fail\",\"raw_log\":\"deliver tx failed\"}";
        let parsed_raw_log = parse_tx_query_response(json_raw_log, "0xfallback").unwrap();
        assert_eq!(parsed_raw_log.error.as_deref(), Some("deliver tx failed"));

        let json_log = "{\"tx_hash\":\"0x779\",\"status\":\"fail\",\"log\":\"check tx failed\"}";
        let parsed_log = parse_tx_query_response(json_log, "0xfallback").unwrap();
        assert_eq!(parsed_log.error.as_deref(), Some("check tx failed"));
    }

    #[test]
    fn tx_query_parse_json_accepts_scalar_status_aliases() {
        let json_numeric = "{\"tx_hash\":\"0x780\",\"status\":0}";
        let parsed_numeric = parse_tx_query_response(json_numeric, "0xfallback").unwrap();
        assert_eq!(parsed_numeric.tx_hash, "0x780");
        assert_eq!(parsed_numeric.status, "committed");

        let json_nested_numeric =
            "{\"result\":{\"transactionHash\":\"0x781\",\"transactionState\":12}}";
        let parsed_nested_numeric =
            parse_tx_query_response(json_nested_numeric, "0xfallback").unwrap();
        assert_eq!(parsed_nested_numeric.tx_hash, "0x781");
        assert_eq!(parsed_nested_numeric.status, "fail");

        let json_bool = "{\"tx_hash\":\"0x782\",\"status\":true}";
        let parsed_bool = parse_tx_query_response(json_bool, "0xfallback").unwrap();
        assert_eq!(parsed_bool.tx_hash, "0x782");
        assert_eq!(parsed_bool.status, "committed");

        let json_nested_bool =
            "{\"result\":{\"response\":{\"tx_response\":{\"transactionHash\":\"0x783\",\"transactionState\":false}}}}";
        let parsed_nested_bool = parse_tx_query_response(json_nested_bool, "0xfallback").unwrap();
        assert_eq!(parsed_nested_bool.tx_hash, "0x783");
        assert_eq!(parsed_nested_bool.status, "fail");
    }

    #[test]
    fn tx_query_parse_infers_status_from_common_code_fields() {
        let json_root_code = "{\"tx_hash\":\"0x701\",\"code\":0}";
        let parsed_root_code = parse_tx_query_response(json_root_code, "0xfallback").unwrap();
        assert_eq!(parsed_root_code.tx_hash, "0x701");
        assert_eq!(parsed_root_code.status, "committed");

        let json_nested_code = "{\"result\":{\"tx_hash\":\"0x702\",\"tx_result\":{\"code\":9}}}";
        let parsed_nested_code = parse_tx_query_response(json_nested_code, "0xfallback").unwrap();
        assert_eq!(parsed_nested_code.tx_hash, "0x702");
        assert_eq!(parsed_nested_code.status, "fail");

        let json_string_code = "{\"tx_hash\":\"0x703\",\"code\":\"0\"}";
        let parsed_string_code = parse_tx_query_response(json_string_code, "0xfallback").unwrap();
        assert_eq!(parsed_string_code.tx_hash, "0x703");
        assert_eq!(parsed_string_code.status, "committed");

        let json_nested_string_code =
            "{\"result\":{\"tx_hash\":\"0x704\",\"deliver_tx\":{\"code\":\"12\"}}}";
        let parsed_nested_string_code =
            parse_tx_query_response(json_nested_string_code, "0xfallback").unwrap();
        assert_eq!(parsed_nested_string_code.tx_hash, "0x704");
        assert_eq!(parsed_nested_string_code.status, "fail");

        let json_tx_code = "{\"tx_hash\":\"0x7041\",\"tx_code\":0}";
        let parsed_json_tx_code = parse_tx_query_response(json_tx_code, "0xfallback").unwrap();
        assert_eq!(parsed_json_tx_code.tx_hash, "0x7041");
        assert_eq!(parsed_json_tx_code.status, "committed");

        let json_transaction_code = "{\"transactionHash\":\"0x7042\",\"transaction_code\":7}";
        let parsed_json_transaction_code =
            parse_tx_query_response(json_transaction_code, "0xfallback").unwrap();
        assert_eq!(parsed_json_transaction_code.tx_hash, "0x7042");
        assert_eq!(parsed_json_transaction_code.status, "fail");

        let json_deliver_tx_code =
            "{\"result\":{\"tx_hash\":\"0x7043\",\"deliver_tx_code\":\"0\"}}";
        let parsed_json_deliver_tx_code =
            parse_tx_query_response(json_deliver_tx_code, "0xfallback").unwrap();
        assert_eq!(parsed_json_deliver_tx_code.tx_hash, "0x7043");
        assert_eq!(parsed_json_deliver_tx_code.status, "committed");

        let json_check_tx_code = "{\"result\":{\"tx_hash\":\"0x7044\",\"check_tx_code\":\"19\"}}";
        let parsed_json_check_tx_code =
            parse_tx_query_response(json_check_tx_code, "0xfallback").unwrap();
        assert_eq!(parsed_json_check_tx_code.tx_hash, "0x7044");
        assert_eq!(parsed_json_check_tx_code.status, "fail");

        let kv_root_code = "tx_hash=0x705\ncode=0\n";
        let parsed_kv_root_code = parse_tx_query_response(kv_root_code, "0xfallback").unwrap();
        assert_eq!(parsed_kv_root_code.tx_hash, "0x705");
        assert_eq!(parsed_kv_root_code.status, "committed");

        let kv_deliver_code = "tx_hash=0x706\ndeliver_tx_code=12\n";
        let parsed_kv_deliver_code =
            parse_tx_query_response(kv_deliver_code, "0xfallback").unwrap();
        assert_eq!(parsed_kv_deliver_code.tx_hash, "0x706");
        assert_eq!(parsed_kv_deliver_code.status, "fail");
    }

    #[test]
    fn tx_query_parse_supports_nested_response_data_operator_state_aliases() {
        let json = "{\"response\":{\"data\":{\"transactionHash\":\"`0xFACE55,`\",\"transactionState\":\"(in progress),\"}}}";
        let parsed = parse_tx_query_response(json, "0xface55").unwrap();
        assert_eq!(parsed.tx_hash, "0xface55");
        assert_eq!(parsed.status, "pending");
    }

    #[test]
    fn tx_query_parse_normalizes_status_aliases_and_punctuation() {
        let kv = "txhash=0xabc\nstatus=FAILED,\n";
        let parsed = parse_tx_query_response(kv, "0xfallback").unwrap();
        assert_eq!(parsed.tx_hash, "0xabc");
        assert_eq!(parsed.status, "fail");

        let json = "{\"tx_hash\":\"0xdef\",\"status\":\"ok\"}";
        let parsed_json = parse_tx_query_response(json, "0xfallback").unwrap();
        assert_eq!(parsed_json.status, "committed");

        let noisy_punct = "tx_hash=0xeee\nstatus=success!?\n";
        let parsed_noisy = parse_tx_query_response(noisy_punct, "0xfallback").unwrap();
        assert_eq!(parsed_noisy.status, "committed");

        let succeeded_alias = "tx_hash=0xeee1\nstatus=succeeded\n";
        let parsed_succeeded = parse_tx_query_response(succeeded_alias, "0xfallback").unwrap();
        assert_eq!(parsed_succeeded.status, "committed");

        let confirmed_alias = "tx_hash=0xeee2\nstatus=confirmed\n";
        let parsed_confirmed = parse_tx_query_response(confirmed_alias, "0xfallback").unwrap();
        assert_eq!(parsed_confirmed.status, "committed");

        let single_quoted = "tx_hash=0xeff\nstatus='committed'\n";
        let parsed_single_quoted = parse_tx_query_response(single_quoted, "0xfallback").unwrap();
        assert_eq!(parsed_single_quoted.status, "committed");

        let wrapped_status = "tx_hash=0xeff1\nstatus=(`confirmed`,)\n";
        let parsed_wrapped_status = parse_tx_query_response(wrapped_status, "0xfallback").unwrap();
        assert_eq!(parsed_wrapped_status.status, "committed");

        let rejected_alias = "tx_hash=0xef0\nstatus=REJECTED\n";
        let parsed_rejected = parse_tx_query_response(rejected_alias, "0xfallback").unwrap();
        assert_eq!(parsed_rejected.status, "fail");

        let timed_out_alias = "tx_hash=0xef1\nstatus=timed_out\n";
        let parsed_timed_out = parse_tx_query_response(timed_out_alias, "0xfallback").unwrap();
        assert_eq!(parsed_timed_out.status, "fail");

        let timed_out_hyphen_alias = "tx_hash=0xef2\nstatus=timed-out\n";
        let parsed_timed_out_hyphen =
            parse_tx_query_response(timed_out_hyphen_alias, "0xfallback").unwrap();
        assert_eq!(parsed_timed_out_hyphen.status, "fail");

        let timed_out_spaced_alias = "tx_hash=0xef21\nstatus='timed out'\n";
        let parsed_timed_out_spaced =
            parse_tx_query_response(timed_out_spaced_alias, "0xfallback").unwrap();
        assert_eq!(parsed_timed_out_spaced.status, "fail");

        let timed_out_noisy_alias = "tx_hash=0xef2\nstatus=Timed -  Out!!!\n";
        let parsed_timed_out_noisy =
            parse_tx_query_response(timed_out_noisy_alias, "0xfallback").unwrap();
        assert_eq!(parsed_timed_out_noisy.status, "fail");

        let submitted_alias = "tx_hash=0xef3\nstatus=submitted\n";
        let parsed_submitted = parse_tx_query_response(submitted_alias, "0xfallback").unwrap();
        assert_eq!(parsed_submitted.status, "pending");

        let accepted_alias = "tx_hash=0xef4\nstatus=accepted\n";
        let parsed_accepted = parse_tx_query_response(accepted_alias, "0xfallback").unwrap();
        assert_eq!(parsed_accepted.status, "pending");

        let processing_alias = "tx_hash=0xef41\nstatus=processing\n";
        let parsed_processing = parse_tx_query_response(processing_alias, "0xfallback").unwrap();
        assert_eq!(parsed_processing.status, "pending");

        let broadcasting_alias = "tx_hash=0xef411\nstatus=broadcasting\n";
        let parsed_broadcasting =
            parse_tx_query_response(broadcasting_alias, "0xfallback").unwrap();
        assert_eq!(parsed_broadcasting.status, "pending");

        let executing_alias = "tx_hash=0xef412\nstatus=executing\n";
        let parsed_executing = parse_tx_query_response(executing_alias, "0xfallback").unwrap();
        assert_eq!(parsed_executing.status, "pending");

        let in_progress_alias = "tx_hash=0xef42\nstatus=in_progress\n";
        let parsed_in_progress = parse_tx_query_response(in_progress_alias, "0xfallback").unwrap();
        assert_eq!(parsed_in_progress.status, "pending");

        let in_progress_spaced_alias = "tx_hash=0xef421\nstatus='in progress'\n";
        let parsed_in_progress_spaced =
            parse_tx_query_response(in_progress_spaced_alias, "0xfallback").unwrap();
        assert_eq!(parsed_in_progress_spaced.status, "pending");

        let in_flight_alias = "tx_hash=0xef43\nstatus=in-flight\n";
        let parsed_in_flight = parse_tx_query_response(in_flight_alias, "0xfallback").unwrap();
        assert_eq!(parsed_in_flight.status, "pending");

        let included_alias = "tx_hash=0xef5\nstatus=included\n";
        let parsed_included = parse_tx_query_response(included_alias, "0xfallback").unwrap();
        assert_eq!(parsed_included.status, "committed");

        let finalized_alias = "tx_hash=0xef6\nstatus=finalized\n";
        let parsed_finalized = parse_tx_query_response(finalized_alias, "0xfallback").unwrap();
        assert_eq!(parsed_finalized.status, "committed");

        let finalised_alias = "tx_hash=0xef60\nstatus=finalised\n";
        let parsed_finalised = parse_tx_query_response(finalised_alias, "0xfallback").unwrap();
        assert_eq!(parsed_finalised.status, "committed");

        let finalising_alias = "tx_hash=0xef61\nstatus=finalising\n";
        let parsed_finalising = parse_tx_query_response(finalising_alias, "0xfallback").unwrap();
        assert_eq!(parsed_finalising.status, "committed");

        let finalizing_alias = "tx_hash=0xef62\nstatus=finalizing\n";
        let parsed_finalizing = parse_tx_query_response(finalizing_alias, "0xfallback").unwrap();
        assert_eq!(parsed_finalizing.status, "committed");

        let expired_alias = "tx_hash=0xef7\nstatus=expired\n";
        let parsed_expired = parse_tx_query_response(expired_alias, "0xfallback").unwrap();
        assert_eq!(parsed_expired.status, "fail");
    }

    #[test]
    fn tx_query_parse_kv_ignores_noisy_lines_and_uses_valid_status() {
        let noisy = "[rpc] connecting...\nrandom line without kv\ntx_hash=0x999\nINFO: still processing\nstatus=committed\n";
        let parsed = parse_tx_query_response(noisy, "0xfallback").unwrap();
        assert_eq!(parsed.tx_hash, "0x999");
        assert_eq!(parsed.status, "committed");
        assert_eq!(parsed.error, None);
    }

    #[test]
    fn tx_query_parse_normalizes_quoted_or_punctuated_tx_hash() {
        let kv = "tx_hash='0xABCD1234',\nstatus=committed\n";
        let parsed = parse_tx_query_response(kv, "0xfallback").unwrap();
        assert_eq!(parsed.tx_hash, "0xabcd1234");

        let json = "{\"tx_hash\":\"0xDEADbeef,\",\"status\":\"committed\"}";
        let parsed_json = parse_tx_query_response(json, "0xfallback").unwrap();
        assert_eq!(parsed_json.tx_hash, "0xdeadbeef");

        let nested_wrappers = "tx_hash=(`\"0xBEEF42\"`,)\nstatus=committed\n";
        let parsed_nested = parse_tx_query_response(nested_wrappers, "0xfallback").unwrap();
        assert_eq!(parsed_nested.tx_hash, "0xbeef42");
    }

    #[test]
    fn tx_query_parse_kv_accepts_transaction_hash_aliases() {
        let snake = "transaction_hash=0xabc123\nstatus=committed\n";
        let parsed_snake = parse_tx_query_response(snake, "0xfallback").unwrap();
        assert_eq!(parsed_snake.tx_hash, "0xabc123");

        let compact = "transactionHash=0xdef456\nstatus=committed\n";
        let parsed_compact = parse_tx_query_response(compact, "0xfallback").unwrap();
        assert_eq!(parsed_compact.tx_hash, "0xdef456");

        let hyphenated = "transaction-hash=0xdef457\nstatus=committed\n";
        let parsed_hyphenated = parse_tx_query_response(hyphenated, "0xfallback").unwrap();
        assert_eq!(parsed_hyphenated.tx_hash, "0xdef457");

        let tx_hyphenated = "tx-hash=0xabc124\nstatus=committed\n";
        let parsed_tx_hyphenated = parse_tx_query_response(tx_hyphenated, "0xfallback").unwrap();
        assert_eq!(parsed_tx_hyphenated.tx_hash, "0xabc124");

        let tx_status_snake = "tx_hash=0xaaa111\ntx_status=queued\n";
        let parsed_tx_status_snake =
            parse_tx_query_response(tx_status_snake, "0xfallback").unwrap();
        assert_eq!(parsed_tx_status_snake.tx_hash, "0xaaa111");
        assert_eq!(parsed_tx_status_snake.status, "pending");

        let tx_status_compact = "txhash=0xbbb222\ntxStatus=timed-out\n";
        let parsed_tx_status_compact =
            parse_tx_query_response(tx_status_compact, "0xfallback").unwrap();
        assert_eq!(parsed_tx_status_compact.tx_hash, "0xbbb222");
        assert_eq!(parsed_tx_status_compact.status, "fail");

        let transaction_status_snake = "transaction_hash=0xccc333\ntransaction_status=confirmed\n";
        let parsed_transaction_status_snake =
            parse_tx_query_response(transaction_status_snake, "0xfallback").unwrap();
        assert_eq!(parsed_transaction_status_snake.tx_hash, "0xccc333");
        assert_eq!(parsed_transaction_status_snake.status, "committed");

        let transaction_status_camel = "transactionHash=0xddd444\ntransactionStatus=rejected\n";
        let parsed_transaction_status_camel =
            parse_tx_query_response(transaction_status_camel, "0xfallback").unwrap();
        assert_eq!(parsed_transaction_status_camel.tx_hash, "0xddd444");
        assert_eq!(parsed_transaction_status_camel.status, "fail");

        let transaction_state_camel = "transactionHash=0xeee555\ntransactionState=finalized\n";
        let parsed_transaction_state_camel =
            parse_tx_query_response(transaction_state_camel, "0xfallback").unwrap();
        assert_eq!(parsed_transaction_state_camel.tx_hash, "0xeee555");
        assert_eq!(parsed_transaction_state_camel.status, "committed");
    }

    #[test]
    fn tx_query_parse_rejects_invalid_tx_hash_if_field_is_present() {
        let bad_json = "{\"tx_hash\":\"not-a-hash\",\"status\":\"committed\"}";
        let err_json = parse_tx_query_response(bad_json, "0xabc").unwrap_err();
        assert!(
            err_json
                .to_string()
                .contains("invalid tx_hash field in tx query response"),
            "unexpected: {err_json}"
        );

        let bad_kv = "tx_hash=not-a-hash\nstatus=committed\n";
        let err_kv = parse_tx_query_response(bad_kv, "0xabc").unwrap_err();
        assert!(
            err_kv
                .to_string()
                .contains("invalid tx_hash field in tx query response"),
            "unexpected: {err_kv}"
        );
    }

    #[test]
    fn normalize_tx_hash_trims_directional_control_wrappers() {
        assert_eq!(
            normalize_tx_hash("\u{200e}\u{061c}0xABCD1234\u{200f}"),
            Some("0xabcd1234".to_string())
        );
        assert_eq!(
            normalize_tx_hash("\u{200e}<0xBEEF42>\u{200f}?!"),
            Some("0xbeef42".to_string())
        );
    }

    #[test]
    fn wait_for_tx_normalizes_directional_control_wrapped_hash() {
        let resp = wait_for_tx(
            "\u{200e}\u{061c}0xABCD1234\u{200f}",
            Duration::from_secs(1),
            Duration::from_millis(1),
            |requested| {
                assert_eq!(requested, "0xabcd1234");
                Ok(TxQueryResponse {
                    tx_hash: "\u{200e}0xABCD1234\u{200f}".to_string(),
                    status: "success".to_string(),
                    error: None,
                })
            },
        )
        .unwrap();
        assert_eq!(resp.status, "success");
    }

    #[test]
    fn ensure_safe_sign_message_accepts_plain_visible_text() {
        ensure_safe_sign_message("rotate signer to cold-key slot b").unwrap();
    }

    #[test]
    fn ensure_safe_sign_message_rejects_empty_text() {
        let err = ensure_safe_sign_message("").unwrap_err();
        assert!(err.to_string().contains("must not be empty"), "unexpected: {err}");
    }

    #[test]
    fn ensure_safe_sign_message_rejects_newline_injected_text() {
        let err = ensure_safe_sign_message("rotate\nsignature=fake").unwrap_err();
        assert!(
            err.to_string().contains("ASCII printable text"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn ensure_safe_sign_message_rejects_leading_whitespace() {
        let err = ensure_safe_sign_message(" rotate signer to cold-key slot b").unwrap_err();
        assert!(
            err.to_string()
                .contains("contains leading or trailing whitespace"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn ensure_safe_sign_message_rejects_trailing_whitespace() {
        let err = ensure_safe_sign_message("rotate signer to cold-key slot b ").unwrap_err();
        assert!(
            err.to_string()
                .contains("contains leading or trailing whitespace"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn ensure_safe_sign_message_rejects_non_ascii_whitespace_text() {
        let err = ensure_safe_sign_message("rotate signer\u{00a0}to cold-key slot b").unwrap_err();
        assert!(
            err.to_string().contains("ASCII printable text"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn ensure_safe_sign_message_rejects_bidi_override_text() {
        let err = ensure_safe_sign_message("rotate signer \u{202e}tx=approved").unwrap_err();
        assert!(
            err.to_string().contains("ASCII printable text"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn ensure_safe_sign_message_rejects_arabic_letter_mark_text() {
        let err = ensure_safe_sign_message("rotate signer \u{061c}tx=approved").unwrap_err();
        assert!(
            err.to_string().contains("ASCII printable text"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn ensure_safe_sign_message_rejects_soft_hyphen_text() {
        let err = ensure_safe_sign_message("rotate signer\u{00ad}slot-b").unwrap_err();
        assert!(
            err.to_string().contains("ASCII printable text"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn ensure_safe_sign_message_rejects_mongolian_vowel_separator_text() {
        let err = ensure_safe_sign_message("rotate signer\u{180e}slot-b").unwrap_err();
        assert!(
            err.to_string().contains("ASCII printable text"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn ensure_safe_sign_message_rejects_zero_width_space_text() {
        let err = ensure_safe_sign_message("rotate signer\u{200b}slot-b").unwrap_err();
        assert!(
            err.to_string().contains("ASCII printable text"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn ensure_safe_sign_message_rejects_zero_width_joiner_text() {
        let err = ensure_safe_sign_message("rotate signer\u{200d}slot-b").unwrap_err();
        assert!(
            err.to_string().contains("ASCII printable text"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn ensure_safe_sign_message_rejects_zero_width_non_joiner_text() {
        let err = ensure_safe_sign_message("rotate signer\u{200c}slot-b").unwrap_err();
        assert!(
            err.to_string().contains("ASCII printable text"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn ensure_safe_sign_message_rejects_left_to_right_mark_text() {
        let err = ensure_safe_sign_message("rotate signer\u{200e}slot-b").unwrap_err();
        assert!(
            err.to_string().contains("ASCII printable text"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn ensure_safe_sign_message_rejects_right_to_left_mark_text() {
        let err = ensure_safe_sign_message("rotate signer\u{200f}slot-b").unwrap_err();
        assert!(
            err.to_string().contains("ASCII printable text"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn ensure_safe_sign_message_rejects_word_joiner_text() {
        let err = ensure_safe_sign_message("rotate signer\u{2060}slot-b").unwrap_err();
        assert!(
            err.to_string().contains("ASCII printable text"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn ensure_safe_sign_message_rejects_first_strong_isolate_text() {
        let err = ensure_safe_sign_message("rotate signer\u{2068}slot-b").unwrap_err();
        assert!(
            err.to_string().contains("ASCII printable text"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn ensure_safe_sign_message_rejects_bom_prefixed_text() {
        let err = ensure_safe_sign_message("\u{feff}rotate signer to slot b").unwrap_err();
        assert!(
            err.to_string().contains("ASCII printable text"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn ensure_safe_sign_message_rejects_unicode_line_separator_text() {
        let err = ensure_safe_sign_message("rotate signer\u{2028}slot-b").unwrap_err();
        assert!(
            err.to_string().contains("ASCII printable text"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn ensure_safe_sign_message_rejects_unicode_paragraph_separator_text() {
        let err = ensure_safe_sign_message("rotate signer\u{2029}slot-b").unwrap_err();
        assert!(
            err.to_string().contains("ASCII printable text"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn ensure_safe_sign_message_rejects_non_ascii_visible_text() {
        let err = ensure_safe_sign_message("rotate signer 到 slot-b").unwrap_err();
        assert!(
            err.to_string().contains("ASCII printable text"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn ensure_safe_sign_message_rejects_oversized_text() {
        let err = ensure_safe_sign_message(&"a".repeat(4097)).unwrap_err();
        assert!(
            err.to_string().contains("<= 4096 bytes"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn ensure_safe_sign_message_accepts_max_length_ascii_text() {
        ensure_safe_sign_message(&"a".repeat(4096)).unwrap();
    }

    #[test]
    fn wait_for_tx_rejects_zero_timeout() {
        let result = wait_for_tx(
            "0xabc123",
            Duration::from_secs(0),
            Duration::from_secs(1),
            |_| {
                Ok(TxQueryResponse {
                    tx_hash: "0xabc123".to_string(),
                    status: "pending".to_string(),
                    error: None,
                })
            },
        );
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("tx wait timeout must be greater than 0s"));
    }

    #[test]
    fn wait_for_tx_rejects_zero_interval() {
        let result = wait_for_tx(
            "0xabc123",
            Duration::from_secs(1),
            Duration::from_secs(0),
            |_| {
                Ok(TxQueryResponse {
                    tx_hash: "0xabc123".to_string(),
                    status: "pending".to_string(),
                    error: None,
                })
            },
        );
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("tx wait interval must be greater than 0s"));
    }

    #[test]
    fn wait_for_tx_timeout() {
        let result = wait_for_tx(
            "0xaaa",
            Duration::from_millis(1),
            Duration::from_millis(1),
            |_| {
                Ok(TxQueryResponse {
                    tx_hash: "0xaaa".to_string(),
                    status: "pending".to_string(),
                    error: None,
                })
            },
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("tx wait timeout"),
            "expected timeout error, got: {msg}"
        );
    }

    #[test]
    fn wait_for_tx_does_not_oversleep_past_remaining_timeout_window() {
        let started = Instant::now();
        let result = wait_for_tx(
            "0xaaa",
            Duration::from_millis(20),
            Duration::from_millis(50),
            |_| {
                Ok(TxQueryResponse {
                    tx_hash: "0xaaa".to_string(),
                    status: "pending".to_string(),
                    error: None,
                })
            },
        );
        let elapsed = started.elapsed();
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("tx wait timeout"),
            "expected timeout error, got: {msg}"
        );
        assert!(
            elapsed < Duration::from_millis(250),
            "tx wait should cap sleep to the remaining timeout window without hanging for a full retry interval; elapsed={elapsed:?}"
        );
    }

    #[test]
    fn wait_for_tx_success() {
        let result = wait_for_tx(
            "0xbbb",
            Duration::from_millis(10),
            Duration::from_millis(1),
            |_| {
                Ok(TxQueryResponse {
                    tx_hash: "0xbbb".to_string(),
                    status: "committed".to_string(),
                    error: None,
                })
            },
        )
        .unwrap();
        assert_eq!(result.status, "committed");
    }

    #[test]
    fn wait_for_tx_returns_requested_canonical_hash_for_terminal_alias_response() {
        let result = wait_for_tx(
            "0xbbbccc",
            Duration::from_millis(10),
            Duration::from_millis(1),
            |_| {
                Ok(TxQueryResponse {
                    tx_hash: "0XBBBCCC".to_string(),
                    status: "confirmed".to_string(),
                    error: None,
                })
            },
        )
        .unwrap();
        assert_eq!(result.tx_hash, "0xbbbccc");
        assert_eq!(result.status, "confirmed");
    }

    #[test]
    fn wait_for_tx_rejects_hash_mismatch() {
        let result = wait_for_tx(
            "0xbbb",
            Duration::from_millis(10),
            Duration::from_millis(1),
            |_| {
                Ok(TxQueryResponse {
                    tx_hash: "0xccc".to_string(),
                    status: "committed".to_string(),
                    error: None,
                })
            },
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("tx wait response hash mismatch"),
            "unexpected: {msg}"
        );
    }

    #[test]
    fn wait_for_tx_rejects_missing_response_hash() {
        let result = wait_for_tx(
            "0xbbb",
            Duration::from_millis(10),
            Duration::from_millis(1),
            |_| {
                Ok(TxQueryResponse {
                    tx_hash: String::new(),
                    status: "committed".to_string(),
                    error: None,
                })
            },
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("tx wait response missing tx_hash"),
            "unexpected: {msg}"
        );
    }

    #[test]
    fn tpl_replacement_works() {
        let got = tpl("send {from} {to} {amount}".to_string(), "from", "alice");
        let got = tpl(got, "to", "bob");
        let got = tpl(got, "amount", "7");
        assert_eq!(got, "send alice bob 7");
    }

    #[test]
    fn persist_local_pending_tx_keeps_pending_state() {
        let _guard = ENV_LOCK.lock().unwrap();
        let unique = format!(
            "trnm-cli-test-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        std::env::set_var("TRNM_RPC_TX_FILE", &path);

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let tx_hash = format!("0x{:064x}", nonce);
        persist_local_pending_tx(&tx_hash).unwrap();

        let status = query_local_tx_status(&tx_hash).unwrap();
        assert_eq!(status, "pending");

        let _ = std::fs::remove_file(&path);
        std::env::remove_var("TRNM_RPC_TX_FILE");
    }

    #[test]
    fn persist_local_pending_tx_canonicalizes_wrapped_uppercase_hash_input() {
        let _guard = ENV_LOCK.lock().unwrap();
        let unique = format!(
            "trnm-cli-test-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        std::env::set_var("TRNM_RPC_TX_FILE", &path);

        let raw_tx_hash = "<0XAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA>";
        let canonical = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        persist_local_pending_tx(raw_tx_hash).unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert!(parsed.get(raw_tx_hash).is_none());
        assert_eq!(parsed[canonical]["tx_hash"].as_str(), Some(canonical));
        assert_eq!(query_local_tx_status(raw_tx_hash).as_deref(), Some("pending"));

        let _ = std::fs::remove_file(&path);
        std::env::remove_var("TRNM_RPC_TX_FILE");
    }

    #[test]
    fn persist_local_pending_tx_rejects_non_prefixed_hex_hashes() {
        let err = persist_local_pending_tx("deadbeef").unwrap_err().to_string();
        assert!(
            err.contains("expected 0x-prefixed hex tx hash"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn query_local_tx_status_normalizes_aliases_and_rejects_unknown() {
        let _guard = ENV_LOCK.lock().unwrap();
        let unique = format!(
            "trnm-cli-test-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        std::env::set_var("TRNM_RPC_TX_FILE", &path);

        let ok_hash = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let completed_hash = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let inflight_hash = "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let scalar_hash = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        let bool_hash = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let unknown_hash = "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let payload = format!(
            "{{\n  \"{}\": {{\"status\": \"success!\"}},\n  \"{}\": {{\"tx_status\": \"done\"}},\n  \"{}\": {{\"state\": \"in_progress\"}},\n  \"{}\": {{\"transactionStatus\": 0}},\n  \"{}\": {{\"txState\": false}},\n  \"{}\": {{\"status\": \"mystery\"}}\n}}",
            ok_hash, completed_hash, inflight_hash, scalar_hash, bool_hash, unknown_hash
        );
        std::fs::write(&path, payload).unwrap();

        assert_eq!(query_local_tx_status(ok_hash).as_deref(), Some("committed"));
        assert_eq!(
            query_local_tx_status(&ok_hash.to_ascii_uppercase()).as_deref(),
            Some("committed")
        );
        assert_eq!(
            query_local_tx_status(&format!("<{}>", ok_hash.to_ascii_uppercase())).as_deref(),
            Some("committed")
        );
        assert_eq!(
            query_local_tx_status(completed_hash).as_deref(),
            Some("committed")
        );
        assert_eq!(
            query_local_tx_status(inflight_hash).as_deref(),
            Some("pending")
        );
        assert_eq!(
            query_local_tx_status(scalar_hash).as_deref(),
            Some("committed")
        );
        assert_eq!(query_local_tx_status(bool_hash).as_deref(), Some("fail"));
        assert_eq!(query_local_tx_status(unknown_hash), None);

        let _ = std::fs::remove_file(&path);
        std::env::remove_var("TRNM_RPC_TX_FILE");
    }

    #[test]
    fn persist_local_pending_tx_preserves_existing_terminal_state() {
        let _guard = ENV_LOCK.lock().unwrap();
        let unique = format!(
            "trnm-cli-test-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        std::env::set_var("TRNM_RPC_TX_FILE", &path);

        let tx_hash = "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let payload = format!(
            "{{\n  \"{}\": {{\"status\": \"committed\", \"updated_at_unix_ms\": 1}}\n}}",
            tx_hash
        );
        std::fs::write(&path, payload).unwrap();

        persist_local_pending_tx(tx_hash).unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            parsed[tx_hash]["status"].as_str(),
            Some("committed"),
            "persist_local_pending_tx should preserve existing terminal state for tracked txs"
        );
        assert_eq!(query_local_tx_status(tx_hash).as_deref(), Some("committed"));

        let _ = std::fs::remove_file(&path);
        std::env::remove_var("TRNM_RPC_TX_FILE");
    }

    #[test]
    fn emit_pending_tx_hash_tracks_reveal_like_submissions() {
        let _guard = ENV_LOCK.lock().unwrap();
        let unique = format!(
            "trnm-cli-test-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        std::env::set_var("TRNM_RPC_TX_FILE", &path);

        let tx_hash = "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        emit_pending_tx_hash(tx_hash).unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed[tx_hash]["tx_hash"].as_str(), Some(tx_hash));
        assert_eq!(query_local_tx_status(tx_hash).as_deref(), Some("pending"));

        let _ = std::fs::remove_file(&path);
        std::env::remove_var("TRNM_RPC_TX_FILE");
    }

    #[test]
    fn query_and_wait_stdout_include_shell_safe_tx_hash_aliases() {
        let query = TxQueryResponse {
            tx_hash: "0xabc123".to_string(),
            status: "pending".to_string(),
            error: None,
        };

        let emitted = format!(
            "{}\n{}\n{}\n{}\n{}\n{}\nstatus={}\n",
            format_tx_hash_line(&query.tx_hash),
            format_tx_hash_alias_line(&query.tx_hash),
            format_transaction_hash_alias_line(&query.tx_hash),
            format_transaction_hash_camel_alias_line(&query.tx_hash),
            format_tx_hash_hyphen_alias_line(&query.tx_hash),
            format_transaction_hash_hyphen_alias_line(&query.tx_hash),
            query.status
        );

        assert!(emitted.contains("tx_hash=\"0xabc123\""));
        assert!(emitted.contains("txhash=0xabc123"));
        assert!(emitted.contains("transaction_hash=0xabc123"));
        assert!(emitted.contains("transactionHash=0xabc123"));
        assert!(emitted.contains("tx-hash=0xabc123"));
        assert!(emitted.contains("transaction-hash=0xabc123"));
        assert_eq!(extract_tx_hash(&emitted).as_deref(), Some("0xabc123"));
    }
}
