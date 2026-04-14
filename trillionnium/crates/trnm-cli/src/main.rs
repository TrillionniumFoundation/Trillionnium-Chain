use anyhow::{anyhow, bail, Result};
use clap::{Parser, Subcommand, ValueEnum};
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
    /// Submit a PoCO consumption receipt tx
    #[command(
        name = "submit-consumption-receipt",
        visible_alias = "submit-settlement-receipt"
    )]
    SubmitConsumptionReceipt {
        #[arg(long)]
        receipt_json: PathBuf,
        #[arg(long)]
        signer: Option<String>,
    },
    /// Challenge a PoCO consumption receipt tx
    #[command(name = "challenge-consumption", visible_alias = "challenge-settlement")]
    ChallengeConsumption {
        task_id: u64,
        #[arg(long)]
        consumer_id: String,
        #[arg(long)]
        output_hash: String,
        #[arg(long)]
        billing_window_id: String,
        #[arg(long)]
        challenger: String,
        #[arg(long)]
        signer: Option<String>,
    },
    /// Resolve a PoCO consumption receipt tx
    #[command(name = "resolve-consumption", visible_alias = "resolve-settlement")]
    ResolveConsumption {
        task_id: u64,
        #[arg(long)]
        consumer_id: String,
        #[arg(long)]
        output_hash: String,
        #[arg(long)]
        billing_window_id: String,
        #[arg(long, value_enum)]
        decision: ConsumptionResolutionDecisionArg,
        #[arg(long)]
        credited_consumption_units: Option<u128>,
        #[arg(long)]
        resolution_code: Option<String>,
        #[arg(long)]
        resolver: String,
        #[arg(long)]
        signer: Option<String>,
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
    /// Query task PoCO settlement preview via RPC
    #[command(visible_aliases = [
        "consumption-summary",
        "query-settlement-preview",
        "query-consumption-summary"
    ])]
    SettlementPreview { task_id: u64 },
    /// Query task PoCO settlement receipts via RPC
    #[command(name = "settlement-receipts", visible_aliases = [
        "consumption-receipts",
        "query-settlement-receipts",
        "query-consumption-receipts"
    ])]
    ConsumptionReceipts {
        task_id: u64,
        #[arg(long, default_value_t = 20)]
        limit: usize,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ConsumptionResolutionDecisionArg {
    Accept,
    Discount,
    Reject,
    Slash,
}

impl ConsumptionResolutionDecisionArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Discount => "discount",
            Self::Reject => "reject",
            Self::Slash => "slash",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct BalanceQueryResponse {
    address: String,
    balance: String,
    denom: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConsumptionReceiptTxInput {
    payload_json: String,
    task_id: u64,
    consumer_id: String,
    output_hash: String,
    billing_window_id: String,
    consumer_nonce: u64,
}

fn json_scalar_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn json_u64_alias(value: &serde_json::Value, aliases: &[&str]) -> Option<u64> {
    match json_get_alias(value, aliases)? {
        serde_json::Value::Number(n) => n.as_u64(),
        serde_json::Value::String(s) => s.trim().parse::<u64>().ok(),
        _ => None,
    }
}

fn required_json_string_field(
    value: &serde_json::Value,
    aliases: &[&str],
    field_name: &'static str,
) -> Result<String> {
    json_get_alias(value, aliases)
        .and_then(json_scalar_string)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("consumption receipt missing {}", field_name))
}

fn required_json_u64_field(
    value: &serde_json::Value,
    aliases: &[&str],
    field_name: &'static str,
) -> Result<u64> {
    json_u64_alias(value, aliases)
        .ok_or_else(|| anyhow!("consumption receipt missing {}", field_name))
}

fn validate_consumption_receipt_tx_input(receipt: &ConsumptionReceiptTxInput) -> Result<()> {
    if receipt.consumer_nonce == 0 {
        bail!("consumption receipt consumer_nonce must be non-zero");
    }
    Ok(())
}

fn load_consumption_receipt_tx_input(path: &Path) -> Result<ConsumptionReceiptTxInput> {
    let raw = fs::read_to_string(path).map_err(|err| {
        anyhow!(
            "failed to read consumption receipt file {}: {err}",
            path.display()
        )
    })?;
    let value: serde_json::Value = serde_json::from_str(&raw).map_err(|err| {
        anyhow!(
            "failed to parse consumption receipt file {} as json: {err}",
            path.display()
        )
    })?;
    if !value.is_object() {
        bail!(
            "consumption receipt file {} must contain a json object",
            path.display()
        );
    }

    let receipt = ConsumptionReceiptTxInput {
        payload_json: serde_json::to_string(&value).map_err(|err| {
            anyhow!(
                "failed to canonicalize consumption receipt file {}: {err}",
                path.display()
            )
        })?,
        task_id: required_json_u64_field(&value, &["task_id"], "task_id")?,
        consumer_id: required_json_string_field(&value, &["consumer_id"], "consumer_id")?,
        output_hash: required_json_string_field(&value, &["output_hash"], "output_hash")?,
        billing_window_id: required_json_string_field(
            &value,
            &["billing_window_id"],
            "billing_window_id",
        )?,
        consumer_nonce: required_json_u64_field(&value, &["consumer_nonce"], "consumer_nonce")?,
    };
    validate_consumption_receipt_tx_input(&receipt)?;
    Ok(receipt)
}

fn submit_consumption_receipt_template_override() -> Option<String> {
    [
        "TRNM_TX_SUBMIT_SETTLEMENT_RECEIPT_CMD",
        "TRNM_TX_SUBMIT_CONSUMPTION_RECEIPT_CMD",
    ]
    .into_iter()
    .find_map(|name| std::env::var(name).ok())
}

fn submit_consumption_receipt_tx(receipt_json: PathBuf, signer: Option<String>) -> Result<()> {
    let receipt = load_consumption_receipt_tx_input(&receipt_json)?;
    let signer = signer.unwrap_or_else(|| receipt.consumer_id.clone());

    if let Some(template) = submit_consumption_receipt_template_override() {
        let mut cmd = template;
        cmd = tpl(
            cmd,
            "receipt_json_path",
            &receipt_json.display().to_string(),
        );
        cmd = tpl(cmd, "receipt_json", &receipt.payload_json);
        cmd = tpl(cmd, "task_id", &receipt.task_id.to_string());
        cmd = tpl(cmd, "consumer_id", &receipt.consumer_id);
        cmd = tpl(cmd, "output_hash", &receipt.output_hash);
        cmd = tpl(cmd, "billing_window_id", &receipt.billing_window_id);
        cmd = tpl(cmd, "consumer_nonce", &receipt.consumer_nonce.to_string());
        cmd = tpl(cmd, "signer", &signer);
        let tx_hash = run_template(&cmd)?;
        emit_pending_tx_hash(&tx_hash)?;
    } else {
        let tx_hash = format!(
            "0x{}",
            hash(&[
                "submit-consumption-receipt",
                &receipt.task_id.to_string(),
                &receipt.consumer_id,
                &receipt.output_hash,
                &receipt.billing_window_id,
                &receipt.consumer_nonce.to_string(),
                &signer,
            ])
        );
        emit_pending_tx_hash(&tx_hash)?;
    }

    Ok(())
}

fn challenge_consumption_template_override() -> Option<String> {
    [
        "TRNM_TX_CHALLENGE_SETTLEMENT_CMD",
        "TRNM_TX_CHALLENGE_CONSUMPTION_CMD",
    ]
    .into_iter()
    .find_map(|name| std::env::var(name).ok())
}

fn challenge_consumption_tx(
    task_id: u64,
    consumer_id: String,
    output_hash: String,
    billing_window_id: String,
    challenger: String,
    signer: Option<String>,
) -> Result<()> {
    let signer = signer.unwrap_or_else(|| challenger.clone());

    if let Some(template) = challenge_consumption_template_override() {
        let mut cmd = template;
        cmd = tpl(cmd, "task_id", &task_id.to_string());
        cmd = tpl(cmd, "consumer_id", &consumer_id);
        cmd = tpl(cmd, "output_hash", &output_hash);
        cmd = tpl(cmd, "billing_window_id", &billing_window_id);
        cmd = tpl(cmd, "challenger", &challenger);
        cmd = tpl(cmd, "signer", &signer);
        let tx_hash = run_template(&cmd)?;
        emit_pending_tx_hash(&tx_hash)?;
    } else {
        let tx_hash = format!(
            "0x{}",
            hash(&[
                "challenge-consumption",
                &task_id.to_string(),
                &consumer_id,
                &output_hash,
                &billing_window_id,
                &challenger,
                &signer,
            ])
        );
        emit_pending_tx_hash(&tx_hash)?;
    }

    Ok(())
}

fn resolve_consumption_template_override() -> Option<String> {
    [
        "TRNM_TX_RESOLVE_SETTLEMENT_CMD",
        "TRNM_TX_RESOLVE_CONSUMPTION_CMD",
    ]
    .into_iter()
    .find_map(|name| std::env::var(name).ok())
}

#[allow(clippy::too_many_arguments)]
fn resolve_consumption_tx(
    task_id: u64,
    consumer_id: String,
    output_hash: String,
    billing_window_id: String,
    decision: ConsumptionResolutionDecisionArg,
    credited_consumption_units: Option<u128>,
    resolution_code: Option<String>,
    resolver: String,
    signer: Option<String>,
) -> Result<()> {
    let signer = signer.unwrap_or_else(|| resolver.clone());
    let decision = decision.as_str();
    let credited_consumption_units = credited_consumption_units
        .map(|value| value.to_string())
        .unwrap_or_default();
    let resolution_code = resolution_code.unwrap_or_default();

    if let Some(template) = resolve_consumption_template_override() {
        let mut cmd = template;
        cmd = tpl(cmd, "task_id", &task_id.to_string());
        cmd = tpl(cmd, "consumer_id", &consumer_id);
        cmd = tpl(cmd, "output_hash", &output_hash);
        cmd = tpl(cmd, "billing_window_id", &billing_window_id);
        cmd = tpl(cmd, "decision", decision);
        cmd = tpl(
            cmd,
            "credited_consumption_units",
            &credited_consumption_units,
        );
        cmd = tpl(cmd, "resolution_code", &resolution_code);
        cmd = tpl(cmd, "resolver", &resolver);
        cmd = tpl(cmd, "signer", &signer);
        let tx_hash = run_template(&cmd)?;
        emit_pending_tx_hash(&tx_hash)?;
    } else {
        let tx_hash = format!(
            "0x{}",
            hash(&[
                "resolve-consumption",
                &task_id.to_string(),
                &consumer_id,
                &output_hash,
                &billing_window_id,
                decision,
                &credited_consumption_units,
                &resolution_code,
                &resolver,
                &signer,
            ])
        );
        emit_pending_tx_hash(&tx_hash)?;
    }

    Ok(())
}

fn parse_balance_query_response(
    raw: &str,
    requested_address: &str,
    requested_denom: &str,
) -> Result<BalanceQueryResponse> {
    if let Ok(resp) = serde_json::from_str::<BalanceQueryResponse>(raw) {
        return Ok(resp);
    }

    if let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) {
        if let Some(balance) = json_scalar_string(&value) {
            return Ok(BalanceQueryResponse {
                address: requested_address.to_string(),
                balance,
                denom: requested_denom.to_string(),
            });
        }

        for candidate in [
            Some(&value),
            value.get("result"),
            value.get("data"),
            value.get("response"),
            value
                .get("response")
                .and_then(|response| response.get("data")),
        ] {
            let Some(candidate) = candidate else {
                continue;
            };

            let nested_balance = candidate
                .get("balance")
                .filter(|value| value.is_object())
                .or_else(|| candidate.get("amount").filter(|value| value.is_object()));
            let Some(balance) = candidate
                .get("balance")
                .and_then(json_scalar_string)
                .or_else(|| candidate.get("amount").and_then(json_scalar_string))
                .or_else(|| {
                    nested_balance
                        .and_then(|value| value.get("amount"))
                        .and_then(json_scalar_string)
                })
            else {
                continue;
            };

            let address = candidate
                .get("address")
                .and_then(json_scalar_string)
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| requested_address.to_string());
            let denom = nested_balance
                .and_then(|value| value.get("denom"))
                .and_then(json_scalar_string)
                .filter(|value| !value.is_empty())
                .or_else(|| {
                    candidate
                        .get("denom")
                        .and_then(json_scalar_string)
                        .filter(|value| !value.is_empty())
                })
                .unwrap_or_else(|| requested_denom.to_string());
            return Ok(BalanceQueryResponse {
                address,
                balance,
                denom,
            });
        }
    }

    let mut address = None;
    let mut balance = None;
    let mut denom = None;
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
                "address" => address = Some(value),
                "balance" | "amount" => balance = Some(value),
                "denom" => denom = Some(value),
                _ => {}
            }
        }
    }

    Ok(BalanceQueryResponse {
        address: address.unwrap_or_else(|| requested_address.to_string()),
        balance: balance.unwrap_or_else(|| raw.trim().to_string()),
        denom: denom.unwrap_or_else(|| requested_denom.to_string()),
    })
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
    let Some(task_id) = json_u64_at_path(&parsed, &["task_id"]) else {
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
        let Some(task_id) = json_u64_at_path(event, &["task_id"]) else {
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

fn parse_consumption_summary_query_response(
    raw: &str,
    requested_task_id: u64,
) -> Result<serde_json::Value> {
    let parsed: serde_json::Value = serde_json::from_str(raw)
        .map_err(|err| anyhow!("failed to parse consumption summary response as json: {err}"))?;
    let result = json_get_alias(&parsed, &["result"]);
    let data = json_get_alias(&parsed, &["data"]);
    let response = json_get_alias(&parsed, &["response"]);
    let response_data = response.and_then(|value| json_get_alias(value, &["data"]));
    let summary = [
        Some(&parsed),
        json_get_alias(
            &parsed,
            &["settlement_preview", "consumption_summary", "summary"],
        ),
        result,
        result.and_then(|value| {
            json_get_alias(value, &["settlement_preview", "consumption_summary", "summary"])
        }),
        data,
        data.and_then(|value| {
            json_get_alias(value, &["settlement_preview", "consumption_summary", "summary"])
        }),
        response,
        response_data,
        response_data.and_then(|value| {
            json_get_alias(value, &["settlement_preview", "consumption_summary", "summary"])
        }),
    ]
    .into_iter()
    .flatten()
    .find(|candidate| candidate.is_object() && json_u64_alias(candidate, &["task_id"]).is_some())
    .ok_or_else(|| anyhow!("consumption summary response missing task_id"))?;
    let task_id = json_u64_alias(summary, &["task_id"]).expect("summary payload must have task_id");
    if task_id != requested_task_id {
        bail!(
            "consumption summary response task_id mismatch: requested={}, got={}",
            requested_task_id,
            task_id
        );
    }
    Ok(summary.clone())
}

fn settlement_preview_template_override() -> Option<String> {
    [
        "TRNM_QUERY_SETTLEMENT_PREVIEW_CMD",
        "TRNM_QUERY_CONSUMPTION_SUMMARY_CMD",
    ]
    .into_iter()
    .find_map(|name| std::env::var(name).ok())
}

fn settlement_preview_query_commands(task_id: u64) -> [String; 2] {
    [
        format!(
            "cargo run -q -p trnm-rpc -- query-settlement-preview {}",
            task_id
        ),
        format!(
            "cargo run -q -p trnm-rpc -- query-consumption-summary {}",
            task_id
        ),
    ]
}

fn consumption_summary_query(task_id: u64) -> Result<serde_json::Value> {
    if let Some(template) = settlement_preview_template_override() {
        let cmd = tpl(template, "task_id", &task_id.to_string());
        let raw = run_template_raw(&cmd)?;
        return parse_consumption_summary_query_response(&raw, task_id);
    }

    let rpc_workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let mut failures = Vec::new();

    for cmd in settlement_preview_query_commands(task_id) {
        let (program, args) = parse_template_command(&cmd)?;
        let out = ProcCommand::new(program)
            .args(args)
            .current_dir(&rpc_workspace)
            .output()?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        if out.status.success() {
            return parse_consumption_summary_query_response(&stdout, task_id);
        }
        failures.push(format!(
            "`{}` rc={}: {}{}",
            cmd,
            out.status.code().unwrap_or(1),
            stdout,
            stderr
        ));
    }

    bail!(
        "settlement preview query command failed: {}",
        failures.join(" | ")
    )
}

fn parse_consumption_receipts_query_response(
    raw: &str,
    requested_task_id: u64,
) -> Result<serde_json::Value> {
    let parsed: serde_json::Value = serde_json::from_str(raw)
        .map_err(|err| anyhow!("failed to parse consumption receipts response as json: {err}"))?;

    let result = json_get_alias(&parsed, &["result"]);
    let data = json_get_alias(&parsed, &["data"]);
    let response = json_get_alias(&parsed, &["response"]);
    let response_data = response.and_then(|value| json_get_alias(value, &["data"]));
    let mut envelope_task_id = None;
    let mut receipts = None;
    for candidate in [
        Some(&parsed),
        json_get_alias(&parsed, &["settlement_receipts", "consumption_receipts"]),
        result,
        result.and_then(|value| {
            json_get_alias(value, &["settlement_receipts", "consumption_receipts"])
        }),
        data,
        data.and_then(|value| {
            json_get_alias(value, &["settlement_receipts", "consumption_receipts"])
        }),
        response,
        response_data,
        response_data.and_then(|value| {
            json_get_alias(value, &["settlement_receipts", "consumption_receipts"])
        }),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(array) = candidate.as_array() {
            receipts = Some(array);
            break;
        }
        if let Some(array) =
            json_get_alias(
                candidate,
                &["receipts", "settlement_receipts", "consumption_receipts"],
            )
            .and_then(|value| value.as_array())
        {
            envelope_task_id = json_u64_alias(candidate, &["task_id"]);
            receipts = Some(array);
            break;
        }
    }

    let Some(receipts) = receipts else {
        bail!("consumption receipts response must be a json array or wrapped receipts object");
    };

    if let Some(task_id) = envelope_task_id {
        if task_id != requested_task_id {
            bail!(
                "consumption receipts response task_id mismatch: requested={}, got={}",
                requested_task_id,
                task_id
            );
        }
    }

    for (idx, receipt) in receipts.iter().enumerate() {
        let Some(task_id) = json_u64_alias(receipt, &["task_id"]).or(envelope_task_id) else {
            bail!("consumption receipts response item {} missing task_id", idx);
        };
        if task_id != requested_task_id {
            bail!(
                "consumption receipts response task_id mismatch at item {}: requested={}, got={}",
                idx,
                requested_task_id,
                task_id
            );
        }
    }
    Ok(serde_json::Value::Array(receipts.to_vec()))
}

fn settlement_receipts_template_override() -> Option<String> {
    [
        "TRNM_QUERY_SETTLEMENT_RECEIPTS_CMD",
        "TRNM_QUERY_CONSUMPTION_RECEIPTS_CMD",
    ]
    .into_iter()
    .find_map(|name| std::env::var(name).ok())
}

fn settlement_receipts_query_commands(task_id: u64, limit: usize) -> [String; 2] {
    [
        format!(
            "cargo run -q -p trnm-rpc -- query-settlement-receipts {} --limit {}",
            task_id, limit
        ),
        format!(
            "cargo run -q -p trnm-rpc -- query-consumption-receipts {} --limit {}",
            task_id, limit
        ),
    ]
}

fn consumption_receipts_query(task_id: u64, limit: usize) -> Result<serde_json::Value> {
    if let Some(template) = settlement_receipts_template_override() {
        let cmd = tpl(
            tpl(template, "task_id", &task_id.to_string()),
            "limit",
            &limit.to_string(),
        );
        let raw = run_template_raw(&cmd)?;
        return parse_consumption_receipts_query_response(&raw, task_id);
    }

    let rpc_workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let mut failures = Vec::new();

    for cmd in settlement_receipts_query_commands(task_id, limit) {
        let (program, args) = parse_template_command(&cmd)?;
        let out = ProcCommand::new(program)
            .args(args)
            .current_dir(&rpc_workspace)
            .output()?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        if out.status.success() {
            return parse_consumption_receipts_query_response(&stdout, task_id);
        }
        failures.push(format!(
            "`{}` rc={}: {}{}",
            cmd,
            out.status.code().unwrap_or(1),
            stdout,
            stderr
        ));
    }

    bail!(
        "consumption receipts query command failed: {}",
        failures.join(" | ")
    )
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
    let Some(request_id) = request
        .get("request_id")
        .and_then(json_scalar_string)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    else {
        bail!("request-full response missing scalar request.request_id");
    };
    if request_id != requested_request_id {
        bail!(
            "request-full response request_id mismatch: requested={}, got={}",
            requested_request_id,
            request_id
        );
    }
    let Some(task_id) = json_u64_at_path(&parsed, &["request", "task_id"]) else {
        bail!("request-full response missing numeric request.task_id");
    };
    let Some(events) = parsed.get("events").and_then(|v| v.as_array()) else {
        bail!("request-full response missing events array");
    };
    for (idx, event) in events.iter().enumerate() {
        let Some(event_task_id) = json_u64_at_path(event, &["task_id"]) else {
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
            '\u{00AD}'
                | '\u{034F}'
                | '\u{061C}'
                | '\u{180E}'
                | '\u{200B}'
                | '\u{200C}'
                | '\u{200D}'
                | '\u{200E}'
                | '\u{200F}'
                | '\u{2060}'
                | '\u{2061}'..='\u{2065}'
                | '\u{206A}'..='\u{206F}'
                | '\u{FEFF}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
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
            | '〈'
            | '〉'
            | '⟨'
            | '⟩'
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
            | '｟'
            | '｠'
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
                | (Some('〈'), Some('〉'))
                | (Some('⟨'), Some('⟩'))
                | (Some('｢'), Some('｣'))
                | (Some('（'), Some('）'))
                | (Some('('), Some(')'))
                | (Some('［'), Some('］'))
                | (Some('['), Some(']'))
                | (Some('｛'), Some('｝'))
                | (Some('{'), Some('}'))
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
        || normalized.chars().any(|c| {
            c.is_whitespace()
                || contains_hidden_or_control(c)
                || matches!(
                    c,
                    '\\' | '∖' | '／' | '＼' | '﹨' | '∕' | '⁄' | '⧵' | '⧸' | '⧹' | '⟋' | '⟍'
                )
        })
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

    let rendered = path.to_string_lossy();
    path.is_absolute()
        && path.parent().is_some()
        && !rendered.contains("//")
        && !rendered.ends_with(std::path::MAIN_SEPARATOR)
        && !path_text_has_dot_segments(path)
        && rendered.chars().all(|c| {
            !c.is_whitespace()
                && !contains_hidden_or_control(c)
                && !matches!(
                    c,
                    '\\' | '∖'
                        | '／'
                        | '＼'
                        | '﹨'
                        | '∕'
                        | '⁄'
                        | '⧵'
                        | '⧸'
                        | '⧹'
                        | '⟋'
                        | '⟍'
                        | '．'
                        | '。'
                        | '｡'
                        | '﹒'
                        | '․'
                )
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
        .filter(|path| {
            wallet_store_path_is_safe(path)
                && wallet_store_path_and_ancestors_are_symlink_free(path)
        })
        .or_else(|| {
            std::env::current_dir().ok().filter(|path| {
                wallet_store_path_is_safe(path)
                    && wallet_store_path_and_ancestors_are_symlink_free(path)
            })
        })
        .unwrap_or_else(|| PathBuf::from("/"));

    home_root.join(".trnm").join("wallets")
}

fn resolve_wallet_store(store: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(store) = store {
        if !wallet_store_path_is_safe(&store)
            || !wallet_store_path_and_ancestors_are_symlink_free(&store)
        {
            bail!(
                "explicit wallet store '{}' must be an absolute normalized symlink-free path",
                store.display()
            );
        }
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
            '\u{00AD}'
                | '\u{034F}'
                | '\u{061C}'
                | '\u{180E}'
                | '\u{200B}'
                | '\u{200C}'
                | '\u{200D}'
                | '\u{200E}'
                | '\u{200F}'
                | '\u{2060}'
                | '\u{2061}'
                | '\u{2062}'
                | '\u{2063}'
                | '\u{2064}'
                | '\u{2065}'
                | '\u{206A}'
                | '\u{206B}'
                | '\u{206C}'
                | '\u{206D}'
                | '\u{206E}'
                | '\u{206F}'
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
    if message.chars().next().is_some_and(|c| c.is_whitespace())
        || message
            .chars()
            .next_back()
            .is_some_and(|c| c.is_whitespace())
    {
        bail!("sign message must not start or end with whitespace");
    }
    if message.chars().any(|c| {
        c == '\r' || c == '\n' || contains_hidden_or_control(c) || (c.is_whitespace() && c != ' ')
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
    let has_non_ascii = !name.is_ascii();
    let has_non_simple_ascii = name
        .chars()
        .any(|c| !c.is_ascii_alphanumeric() && c != '_' && c != '-');
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
        || has_non_ascii
        || name == "."
        || name == ".."
        || name.starts_with('.')
        || name.ends_with('.')
        || name.starts_with('-')
        || name.starts_with(['‐', '‑', '‒', '–', '—', '―', '−', '﹣', '－'])
        || name.contains(['/', '\\', ':', '=', '|', '&', '$', '*', '?', '!'])
        || name.contains(['‐', '‑', '‒', '–', '—', '―', '−', '﹣', '－'])
        || name.contains([
            '：', '﹕', '＝', '﹦', '｜', '￨', '＆', '﹠', '？', '﹖', '，', '；', '！', '﹗',
        ])
        || name.contains(['＊', '﹡'])
        || name.contains(['∕', '⁄', '／', '＼', '⧵', '⧸', '⧹', '⟋', '⟍'])
        || name.contains(['.', '．', '。', '｡', '﹒', '․'])
        || name.contains([
            '"', '\'', '`', '<', '>', '(', ')', '[', ']', '{', '}', ',', ';',
        ])
        || name.contains([
            '“', '”', '‘', '’', '«', '»', '‹', '›', '「', '」', '『', '』', '《', '》', '〈', '〉',
            '｢', '｣', '（', '）', '［', '］', '｛', '｝', '＜', '＞', '【', '】', '〔', '〕', '〖',
            '〗', '〘', '〙', '〚', '〛', '〝', '〞', '〟', '｟', '｠',
        ])
        || has_hidden_or_whitespace
        || has_non_simple_ascii
        || is_windows_reserved_device
    {
        bail!(
            "invalid wallet name '{}': use a simple ASCII local name with only letters, digits, '_' or '-' and no path separators or reserved device names",
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
                        | '\u{200E}'
                        | '\u{200F}'
                        | '\u{2060}'
                        | '\u{2061}'..='\u{2065}'
                        | '\u{206A}'..='\u{206F}'
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
    let file_meta = fs::symlink_metadata(&f).map_err(|e| {
        anyhow!(
            "failed to inspect wallet '{}' at {}: {e}",
            name,
            f.display()
        )
    })?;
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
            '='
                | '\u{00ad}'
                | '\u{034f}'
                | '\u{061c}'
                | '\u{180e}'
                | '\u{200b}'
                | '\u{200c}'
                | '\u{200d}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{2060}'
                | '\u{2061}'..='\u{2065}'
                | '\u{206a}'..='\u{206f}'
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
    if message.contains("  ") {
        bail!(
            "wallet sign message must not contain repeated interior spaces; refusing ambiguous offline-signing output"
        );
    }
    if message.chars().any(|c| {
        is_unsafe_sign_message_char(c)
            || !c.is_ascii()
            || (!c.is_ascii_graphic() && c != ' ')
            || matches!(
                c,
                '=' | ':'
                    | ';'
                    | ','
                    | '|'
                    | '"'
                    | '\''
                    | '`'
                    | '<'
                    | '>'
                    | '('
                    | ')'
                    | '['
                    | ']'
                    | '{'
                    | '}'
                    | '/'
                    | '\\'
                    | '∕'
                    | '⁄'
                    | '／'
                    | '＼'
                    | '⧵'
                    | '⧸'
                    | '⧹'
                    | '⟋'
                    | '⟍'
            )
    }) {
        bail!(
            "wallet sign message must be single-line ASCII printable text with only single interior ASCII spaces and no delimiter, wrapper punctuation, or path separators; refusing unsafe offline-signing output"
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
        "tx-hash",
        "txHash",
        "transaction_hash",
        "transaction-hash",
        "transactionHash",
    ];
    if let Some(h) = json_get_alias(v, &direct).and_then(|x| x.as_str()) {
        if let Some(normalized) = normalize_tx_hash(h) {
            return Some(normalized);
        }
    }

    for key in ["result", "tx_response", "txResponse", "response", "data"] {
        if let Some(found) = json_get_alias(v, &[key]).and_then(json_value_tx_hash) {
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
            is_text_tx_hash_key(key)
                .then(|| normalize_tx_hash(v))
                .flatten()
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
    })
}

fn canonical_kv_key(key: &str) -> String {
    trim_kv_key_noise(key)
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
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

    Some((canonical_kv_key(key), value.to_string()))
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
        canonical_kv_key(key),
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
    matches!(
        normalize_tx_status(status).as_deref(),
        Some("committed" | "fail")
    )
}

fn canonical_json_key(key: &str) -> String {
    key.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn json_get_alias<'a>(
    value: &'a serde_json::Value,
    aliases: &[&str],
) -> Option<&'a serde_json::Value> {
    let object = value.as_object()?;
    object.iter().find_map(|(key, value)| {
        let canonical = canonical_json_key(key);
        aliases
            .iter()
            .any(|alias| canonical == canonical_json_key(alias))
            .then_some(value)
    })
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
        "code" | "txcode" | "transactioncode" | "delivertxcode" | "checktxcode" => {
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
        let payload = json_get_alias(&v, &["result"]).unwrap_or(&v);
        let response = json_get_alias(payload, &["response"]);
        let nested_tx_response = json_get_alias(payload, &["tx_response", "txResponse"])
            .or_else(|| response.and_then(|r| json_get_alias(r, &["tx_response", "txResponse"])));
        let nested_response_data = response
            .and_then(|r| json_get_alias(r, &["data"]))
            .or_else(|| json_get_alias(payload, &["responseData"]));
        let primary = nested_tx_response
            .or(nested_response_data)
            .unwrap_or(payload);
        let tx_hash_aliases = [
            "tx_hash",
            "txhash",
            "tx-hash",
            "txHash",
            "transaction_hash",
            "transaction-hash",
            "transactionHash",
        ];
        let raw_tx_hash = json_get_alias(primary, &tx_hash_aliases)
            .or_else(|| response.and_then(|r| json_get_alias(r, &tx_hash_aliases)))
            .or_else(|| json_get_alias(payload, &tx_hash_aliases));
        let tx_hash = match raw_tx_hash {
            Some(raw_hash) => normalize_tx_hash(
                raw_hash
                    .as_str()
                    .ok_or_else(|| anyhow!("invalid tx_hash field in tx query response"))?,
            )
            .ok_or_else(|| anyhow!("invalid tx_hash field in tx query response"))?,
            None => normalize_tx_hash(requested_tx_hash)
                .unwrap_or_else(|| requested_tx_hash.to_string()),
        };
        let status_aliases = [
            "status",
            "tx_status",
            "tx-status",
            "txStatus",
            "transaction_status",
            "transaction-status",
            "transactionStatus",
            "state",
            "tx_state",
            "tx-state",
            "txState",
            "transaction_state",
            "transaction-state",
            "transactionState",
        ];
        let status = json_get_alias(primary, &status_aliases)
            .or_else(|| response.and_then(|r| json_get_alias(r, &status_aliases)))
            .or_else(|| json_get_alias(payload, &status_aliases))
            .and_then(normalize_json_status)
            .or_else(|| infer_json_tx_status(primary))
            .or_else(|| infer_json_tx_status(payload))
            .ok_or_else(|| anyhow!("missing/invalid status field in tx query response"))?;
        let error = json_get_alias(primary, &["error", "raw_log", "raw-log", "rawLog", "log"])
            .or_else(|| {
                response.and_then(|r| {
                    json_get_alias(r, &["error", "raw_log", "raw-log", "rawLog", "log"])
                })
            })
            .or_else(|| json_get_alias(payload, &["error", "raw_log", "raw-log", "rawLog", "log"]))
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
                "txhash" | "transactionhash" => match normalize_tx_hash(&value) {
                    Some(normalized) => tx_hash = Some(normalized),
                    None => bail!("invalid tx_hash field in tx query response"),
                },
                "status" | "txstatus" | "transactionstatus" | "state" | "txstate"
                | "transactionstate" => {
                    if let Some(normalized) = normalize_tx_status(&value) {
                        status = Some(normalized);
                    }
                }
                "code" | "txcode" | "transactioncode" | "delivertxcode" | "checktxcode" => {
                    if status.is_none() {
                        status = infer_kv_tx_status(&key, &value);
                    }
                }
                "error" | "rawlog" | "log" => {
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
    matches!(
        normalize_tx_status(status).as_deref(),
        Some("committed" | "fail")
    )
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
            bail!("tx wait response missing tx_hash: requested={}", requested);
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
    let canonical = normalize_tx_hash(tx_hash).ok_or_else(|| {
        anyhow!("invalid tx hash for local pending state (expected hex-like tx hash)")
    })?;
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

fn format_transaction_hash_spaced_alias_line(tx_hash: &str) -> String {
    format!("transaction hash={}", tx_hash)
}

fn format_tx_hash_spaced_alias_line(tx_hash: &str) -> String {
    format!("tx hash={}", tx_hash)
}

fn emit_tx_hash_lines(tx_hash: &str) {
    println!("{}", format_tx_hash_line(tx_hash));
    println!("{}", format_tx_hash_alias_line(tx_hash));
    println!("{}", format_transaction_hash_alias_line(tx_hash));
    println!("{}", format_transaction_hash_camel_alias_line(tx_hash));
    println!("{}", format_tx_hash_hyphen_alias_line(tx_hash));
    println!("{}", format_tx_hash_spaced_alias_line(tx_hash));
    println!("{}", format_transaction_hash_hyphen_alias_line(tx_hash));
    println!("{}", format_transaction_hash_spaced_alias_line(tx_hash));
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
            TxCommand::SubmitConsumptionReceipt {
                receipt_json,
                signer,
            } => {
                submit_consumption_receipt_tx(receipt_json, signer)?;
            }
            TxCommand::ChallengeConsumption {
                task_id,
                consumer_id,
                output_hash,
                billing_window_id,
                challenger,
                signer,
            } => {
                challenge_consumption_tx(
                    task_id,
                    consumer_id,
                    output_hash,
                    billing_window_id,
                    challenger,
                    signer,
                )?;
            }
            TxCommand::ResolveConsumption {
                task_id,
                consumer_id,
                output_hash,
                billing_window_id,
                decision,
                credited_consumption_units,
                resolution_code,
                resolver,
                signer,
            } => {
                resolve_consumption_tx(
                    task_id,
                    consumer_id,
                    output_hash,
                    billing_window_id,
                    decision,
                    credited_consumption_units,
                    resolution_code,
                    resolver,
                    signer,
                )?;
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
                ensure_safe_sign_message(&message)?;
                let store = resolve_wallet_store(store)?;
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
                    let out = parse_balance_query_response(&raw, &addr, &denom)?;
                    println!("{}", serde_json::to_string_pretty(&out)?);
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
            QueryCommand::SettlementPreview { task_id } => {
                let out = consumption_summary_query(task_id)?;
                println!("{}", serde_json::to_string_pretty(&out)?);
            }
            QueryCommand::ConsumptionReceipts { task_id, limit } => {
                let out = consumption_receipts_query(task_id, limit)?;
                println!("{}", serde_json::to_string_pretty(&out)?);
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
    use clap::CommandFactory;
    use std::{path::PathBuf, sync::Mutex};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn canonical_temp_root() -> PathBuf {
        std::fs::canonicalize(std::env::temp_dir()).unwrap_or_else(|_| std::env::temp_dir())
    }

    #[test]
    fn consumption_settlement_cli_parser_accepts_submit_receipt_command() {
        let args = Args::try_parse_from([
            "trnm-cli",
            "tx",
            "submit-consumption-receipt",
            "--receipt-json",
            "/tmp/receipt.json",
            "--signer",
            "consumer-bravo",
        ])
        .expect("parse submit-consumption-receipt args");

        match args.cmd {
            Command::Tx {
                tx:
                    TxCommand::SubmitConsumptionReceipt {
                        receipt_json,
                        signer,
                    },
            } => {
                assert_eq!(receipt_json, PathBuf::from("/tmp/receipt.json"));
                assert_eq!(signer.as_deref(), Some("consumer-bravo"));
            }
            other => panic!("unexpected parsed args: {other:?}"),
        }
    }

    #[test]
    fn consumption_settlement_cli_parser_accepts_submit_receipt_settlement_alias() {
        let args = Args::try_parse_from([
            "trnm-cli",
            "tx",
            "submit-settlement-receipt",
            "--receipt-json",
            "/tmp/receipt.json",
        ])
        .expect("parse submit-settlement-receipt args");

        match args.cmd {
            Command::Tx {
                tx:
                    TxCommand::SubmitConsumptionReceipt {
                        receipt_json,
                        signer,
                    },
            } => {
                assert_eq!(receipt_json, PathBuf::from("/tmp/receipt.json"));
                assert_eq!(signer, None);
            }
            other => panic!("unexpected parsed args: {other:?}"),
        }
    }

    #[test]
    fn consumption_settlement_cli_parser_accepts_challenge_command() {
        let args = Args::try_parse_from([
            "trnm-cli",
            "tx",
            "challenge-consumption",
            "42",
            "--consumer-id",
            "consumer-bravo",
            "--output-hash",
            "0xabc123",
            "--billing-window-id",
            "bw-7",
            "--challenger",
            "arbiter-alpha",
        ])
        .expect("parse challenge-consumption args");

        match args.cmd {
            Command::Tx {
                tx:
                    TxCommand::ChallengeConsumption {
                        task_id,
                        consumer_id,
                        output_hash,
                        billing_window_id,
                        challenger,
                        signer,
                    },
            } => {
                assert_eq!(task_id, 42);
                assert_eq!(consumer_id, "consumer-bravo");
                assert_eq!(output_hash, "0xabc123");
                assert_eq!(billing_window_id, "bw-7");
                assert_eq!(challenger, "arbiter-alpha");
                assert_eq!(signer, None);
            }
            other => panic!("unexpected parsed args: {other:?}"),
        }
    }

    #[test]
    fn consumption_settlement_cli_parser_accepts_challenge_settlement_alias() {
        let args = Args::try_parse_from([
            "trnm-cli",
            "tx",
            "challenge-settlement",
            "42",
            "--consumer-id",
            "consumer-bravo",
            "--output-hash",
            "0xabc123",
            "--billing-window-id",
            "bw-7",
            "--challenger",
            "arbiter-alpha",
        ])
        .expect("parse challenge-settlement args");

        match args.cmd {
            Command::Tx {
                tx:
                    TxCommand::ChallengeConsumption {
                        task_id,
                        consumer_id,
                        output_hash,
                        billing_window_id,
                        challenger,
                        signer,
                    },
            } => {
                assert_eq!(task_id, 42);
                assert_eq!(consumer_id, "consumer-bravo");
                assert_eq!(output_hash, "0xabc123");
                assert_eq!(billing_window_id, "bw-7");
                assert_eq!(challenger, "arbiter-alpha");
                assert_eq!(signer, None);
            }
            other => panic!("unexpected parsed args: {other:?}"),
        }
    }

    #[test]
    fn consumption_settlement_cli_parser_accepts_resolve_command() {
        let args = Args::try_parse_from([
            "trnm-cli",
            "tx",
            "resolve-consumption",
            "42",
            "--consumer-id",
            "consumer-bravo",
            "--output-hash",
            "0xabc123",
            "--billing-window-id",
            "bw-7",
            "--decision",
            "discount",
            "--credited-consumption-units",
            "11",
            "--resolution-code",
            "accepted_discounted",
            "--resolver",
            "arbiter-alpha",
            "--signer",
            "governance-key",
        ])
        .expect("parse resolve-consumption args");

        match args.cmd {
            Command::Tx {
                tx:
                    TxCommand::ResolveConsumption {
                        task_id,
                        consumer_id,
                        output_hash,
                        billing_window_id,
                        decision,
                        credited_consumption_units,
                        resolution_code,
                        resolver,
                        signer,
                    },
            } => {
                assert_eq!(task_id, 42);
                assert_eq!(consumer_id, "consumer-bravo");
                assert_eq!(output_hash, "0xabc123");
                assert_eq!(billing_window_id, "bw-7");
                assert_eq!(decision, ConsumptionResolutionDecisionArg::Discount);
                assert_eq!(credited_consumption_units, Some(11));
                assert_eq!(resolution_code.as_deref(), Some("accepted_discounted"));
                assert_eq!(resolver, "arbiter-alpha");
                assert_eq!(signer.as_deref(), Some("governance-key"));
            }
            other => panic!("unexpected parsed args: {other:?}"),
        }
    }

    #[test]
    fn consumption_settlement_cli_parser_accepts_resolve_settlement_alias() {
        let args = Args::try_parse_from([
            "trnm-cli",
            "tx",
            "resolve-settlement",
            "42",
            "--consumer-id",
            "consumer-bravo",
            "--output-hash",
            "0xabc123",
            "--billing-window-id",
            "bw-7",
            "--decision",
            "accept",
            "--resolver",
            "arbiter-alpha",
        ])
        .expect("parse resolve-settlement args");

        match args.cmd {
            Command::Tx {
                tx:
                    TxCommand::ResolveConsumption {
                        task_id,
                        consumer_id,
                        output_hash,
                        billing_window_id,
                        decision,
                        credited_consumption_units,
                        resolution_code,
                        resolver,
                        signer,
                    },
            } => {
                assert_eq!(task_id, 42);
                assert_eq!(consumer_id, "consumer-bravo");
                assert_eq!(output_hash, "0xabc123");
                assert_eq!(billing_window_id, "bw-7");
                assert_eq!(decision, ConsumptionResolutionDecisionArg::Accept);
                assert_eq!(credited_consumption_units, None);
                assert_eq!(resolution_code, None);
                assert_eq!(resolver, "arbiter-alpha");
                assert_eq!(signer, None);
            }
            other => panic!("unexpected parsed args: {other:?}"),
        }
    }

    #[test]
    fn consumption_settlement_cli_parser_rejects_unknown_resolution_decision() {
        let err = Args::try_parse_from([
            "trnm-cli",
            "tx",
            "resolve-consumption",
            "42",
            "--consumer-id",
            "consumer-bravo",
            "--output-hash",
            "0xabc123",
            "--billing-window-id",
            "bw-7",
            "--decision",
            "approve",
            "--resolver",
            "arbiter-alpha",
        ])
        .unwrap_err();

        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidValue);
        let rendered = err.to_string();
        assert!(rendered.contains("approve"), "unexpected error: {rendered}");
        assert!(rendered.contains("accept"), "unexpected error: {rendered}");
        assert!(
            rendered.contains("discount"),
            "unexpected error: {rendered}"
        );
        assert!(rendered.contains("reject"), "unexpected error: {rendered}");
        assert!(rendered.contains("slash"), "unexpected error: {rendered}");
    }

    #[test]
    fn consumption_settlement_cli_parser_accepts_settlement_preview_query_command() {
        let args = Args::try_parse_from(["trnm-cli", "query", "settlement-preview", "42"])
            .expect("parse settlement-preview args");

        match args.cmd {
            Command::Query {
                query: QueryCommand::SettlementPreview { task_id },
            } => {
                assert_eq!(task_id, 42);
            }
            other => panic!("unexpected parsed args: {other:?}"),
        }
    }

    #[test]
    fn consumption_settlement_cli_parser_accepts_consumption_summary_query_alias() {
        let args = Args::try_parse_from(["trnm-cli", "query", "consumption-summary", "42"])
            .expect("parse consumption-summary args");

        match args.cmd {
            Command::Query {
                query: QueryCommand::SettlementPreview { task_id },
            } => {
                assert_eq!(task_id, 42);
            }
            other => panic!("unexpected parsed args: {other:?}"),
        }
    }

    #[test]
    fn consumption_settlement_cli_parser_accepts_query_prefixed_settlement_preview_aliases() {
        for alias in ["query-settlement-preview", "query-consumption-summary"] {
            let args = Args::try_parse_from(["trnm-cli", "query", alias, "42"])
                .unwrap_or_else(|err| panic!("parse {alias} args: {err}"));

            match args.cmd {
                Command::Query {
                    query: QueryCommand::SettlementPreview { task_id },
                } => {
                    assert_eq!(task_id, 42, "unexpected task_id for alias {alias}");
                }
                other => panic!("unexpected parsed args for {alias}: {other:?}"),
            }
        }
    }

    #[test]
    fn consumption_settlement_cli_parser_accepts_settlement_receipts_query_command() {
        let args = Args::try_parse_from([
            "trnm-cli",
            "query",
            "settlement-receipts",
            "42",
            "--limit",
            "7",
        ])
        .expect("parse settlement-receipts args");

        match args.cmd {
            Command::Query {
                query: QueryCommand::ConsumptionReceipts { task_id, limit },
            } => {
                assert_eq!(task_id, 42);
                assert_eq!(limit, 7);
            }
            other => panic!("unexpected parsed args: {other:?}"),
        }
    }

    #[test]
    fn consumption_settlement_cli_parser_accepts_consumption_receipts_query_alias() {
        let args = Args::try_parse_from([
            "trnm-cli",
            "query",
            "consumption-receipts",
            "42",
            "--limit",
            "7",
        ])
        .expect("parse consumption-receipts args");

        match args.cmd {
            Command::Query {
                query: QueryCommand::ConsumptionReceipts { task_id, limit },
            } => {
                assert_eq!(task_id, 42);
                assert_eq!(limit, 7);
            }
            other => panic!("unexpected parsed args: {other:?}"),
        }
    }

    #[test]
    fn consumption_settlement_cli_parser_accepts_query_prefixed_settlement_receipts_aliases() {
        for alias in ["query-settlement-receipts", "query-consumption-receipts"] {
            let args = Args::try_parse_from(["trnm-cli", "query", alias, "42", "--limit", "7"])
                .unwrap_or_else(|err| panic!("parse {alias} args: {err}"));

            match args.cmd {
                Command::Query {
                    query: QueryCommand::ConsumptionReceipts { task_id, limit },
                } => {
                    assert_eq!(task_id, 42, "unexpected task_id for alias {alias}");
                    assert_eq!(limit, 7, "unexpected limit for alias {alias}");
                }
                other => panic!("unexpected parsed args for {alias}: {other:?}"),
            }
        }
    }

    #[test]
    fn consumption_settlement_cli_help_keeps_cutover_names_primary() {
        let mut root = Args::command();
        let query = root
            .find_subcommand_mut("query")
            .expect("query subcommand in clap tree");
        let mut query_help = Vec::new();
        query
            .write_long_help(&mut query_help)
            .expect("render query help");
        let query_help = String::from_utf8(query_help).expect("utf8 query help");
        assert!(query_help.contains("settlement-preview"));
        assert!(query_help.contains("consumption-summary"));
        assert!(query_help.contains("query-settlement-preview"));
        assert!(query_help.contains("query-consumption-summary"));
        assert!(query_help.contains("settlement-receipts"));
        assert!(query_help.contains("consumption-receipts"));
        assert!(query_help.contains("query-settlement-receipts"));
        assert!(query_help.contains("query-consumption-receipts"));
        assert!(
            query_help.find("settlement-preview") < query_help.find("consumption-summary"),
            "query help should keep settlement-preview primary: {query_help}"
        );
        assert!(
            query_help.find("settlement-preview") < query_help.find("query-settlement-preview"),
            "query help should keep settlement-preview primary ahead of query-prefixed alias: {query_help}"
        );
        assert!(
            query_help.find("settlement-receipts") < query_help.find("consumption-receipts"),
            "query help should keep settlement-receipts primary: {query_help}"
        );
        assert!(
            query_help.find("settlement-receipts") < query_help.find("query-settlement-receipts"),
            "query help should keep settlement-receipts primary ahead of query-prefixed alias: {query_help}"
        );

        let mut root = Args::command();
        let tx = root
            .find_subcommand_mut("tx")
            .expect("tx subcommand in clap tree");
        let mut tx_help = Vec::new();
        tx.write_long_help(&mut tx_help).expect("render tx help");
        let tx_help = String::from_utf8(tx_help).expect("utf8 tx help");
        assert!(tx_help.contains("submit-consumption-receipt"));
        assert!(tx_help.contains("submit-settlement-receipt"));
        assert!(tx_help.contains("challenge-consumption"));
        assert!(tx_help.contains("challenge-settlement"));
        assert!(tx_help.contains("resolve-consumption"));
        assert!(tx_help.contains("resolve-settlement"));
        assert!(tx_help.contains("commit-result"));
        assert!(tx_help.contains("reveal-result"));
        assert!(
            tx_help.find("submit-consumption-receipt") < tx_help.find("submit-settlement-receipt"),
            "tx help should keep submit-consumption-receipt primary: {tx_help}"
        );
        assert!(
            tx_help.find("challenge-consumption") < tx_help.find("challenge-settlement"),
            "tx help should keep challenge-consumption primary: {tx_help}"
        );
        assert!(
            tx_help.find("resolve-consumption") < tx_help.find("resolve-settlement"),
            "tx help should keep resolve-consumption primary: {tx_help}"
        );
        assert!(
            tx_help.find("submit-consumption-receipt") < tx_help.find("commit-result"),
            "tx help should surface submit-consumption-receipt ahead of legacy commit-result: {tx_help}"
        );
        assert!(
            tx_help.find("challenge-consumption") < tx_help.find("commit-result"),
            "tx help should surface challenge-consumption ahead of legacy commit-result: {tx_help}"
        );
        assert!(
            tx_help.find("resolve-consumption") < tx_help.find("reveal-result"),
            "tx help should surface resolve-consumption ahead of legacy reveal-result: {tx_help}"
        );
    }

    #[test]
    fn load_consumption_receipt_tx_input_extracts_replay_key_fields() {
        let unique = format!(
            "trnm-cli-consumption-receipt-input-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root = canonical_temp_root().join(unique);
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("receipt.json");
        std::fs::write(
            &path,
            r#"{
                "task_id":"42",
                "consumer_id":"consumer-bravo",
                "output_hash":"0xabc123",
                "billing_window_id":"bw-7",
                "consumer_nonce":9
            }"#,
        )
        .unwrap();

        let parsed = load_consumption_receipt_tx_input(&path).unwrap();
        assert_eq!(parsed.task_id, 42);
        assert_eq!(parsed.consumer_id, "consumer-bravo");
        assert_eq!(parsed.output_hash, "0xabc123");
        assert_eq!(parsed.billing_window_id, "bw-7");
        assert_eq!(parsed.consumer_nonce, 9);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&root);
    }

    #[test]
    fn load_consumption_receipt_tx_input_accepts_canonicalized_cutover_field_names() {
        let unique = format!(
            "trnm-cli-consumption-receipt-cutover-alias-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root = canonical_temp_root().join(unique);
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("receipt.json");
        std::fs::write(
            &path,
            r#"{
                "task-id":"42",
                "consumerId":"consumer-bravo",
                "outputHash":"0xabc123",
                "billingWindowId":"bw-7",
                "consumerNonce":"9"
            }"#,
        )
        .unwrap();

        let parsed = load_consumption_receipt_tx_input(&path).unwrap();
        assert_eq!(parsed.task_id, 42);
        assert_eq!(parsed.consumer_id, "consumer-bravo");
        assert_eq!(parsed.output_hash, "0xabc123");
        assert_eq!(parsed.billing_window_id, "bw-7");
        assert_eq!(parsed.consumer_nonce, 9);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&root);
    }

    #[test]
    fn load_consumption_receipt_tx_input_rejects_zero_consumer_nonce() {
        let unique = format!(
            "trnm-cli-consumption-receipt-zero-nonce-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root = canonical_temp_root().join(unique);
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("receipt.json");
        std::fs::write(
            &path,
            r#"{
                "task_id":42,
                "consumer_id":"consumer-bravo",
                "output_hash":"0xabc123",
                "billing_window_id":"bw-7",
                "consumer_nonce":0
            }"#,
        )
        .unwrap();

        let err = load_consumption_receipt_tx_input(&path).unwrap_err().to_string();
        assert!(
            err.contains("consumer_nonce must be non-zero"),
            "unexpected error: {err}"
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&root);
    }

    #[test]
    fn consumption_settlement_write_paths_emit_pending_hashes_with_default_signers() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("TRNM_TX_SUBMIT_CONSUMPTION_RECEIPT_CMD");
        std::env::remove_var("TRNM_TX_SUBMIT_SETTLEMENT_RECEIPT_CMD");
        std::env::remove_var("TRNM_TX_CHALLENGE_CONSUMPTION_CMD");
        std::env::remove_var("TRNM_TX_CHALLENGE_SETTLEMENT_CMD");
        std::env::remove_var("TRNM_TX_RESOLVE_CONSUMPTION_CMD");
        std::env::remove_var("TRNM_TX_RESOLVE_SETTLEMENT_CMD");

        let unique = format!(
            "trnm-cli-consumption-settlement-write-paths-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root = canonical_temp_root().join(unique);
        std::fs::create_dir_all(&root).unwrap();

        let receipt_path = root.join("receipt.json");
        std::fs::write(
            &receipt_path,
            r#"{
                "task_id":42,
                "consumer_id":"consumer-bravo",
                "output_hash":"0xabc123",
                "billing_window_id":"bw-7",
                "consumer_nonce":9
            }"#,
        )
        .unwrap();

        let tx_file = root.join("txs.json");
        std::env::set_var("TRNM_RPC_TX_FILE", &tx_file);

        submit_consumption_receipt_tx(receipt_path.clone(), None).unwrap();
        challenge_consumption_tx(
            42,
            "consumer-bravo".into(),
            "0xabc123".into(),
            "bw-7".into(),
            "arbiter-alpha".into(),
            None,
        )
        .unwrap();
        resolve_consumption_tx(
            42,
            "consumer-bravo".into(),
            "0xabc123".into(),
            "bw-7".into(),
            ConsumptionResolutionDecisionArg::Discount,
            Some(11),
            Some("accepted_discounted".into()),
            "arbiter-alpha".into(),
            None,
        )
        .unwrap();

        let submit_hash = format!(
            "0x{}",
            hash(&[
                "submit-consumption-receipt",
                "42",
                "consumer-bravo",
                "0xabc123",
                "bw-7",
                "9",
                "consumer-bravo",
            ])
        );
        let challenge_hash = format!(
            "0x{}",
            hash(&[
                "challenge-consumption",
                "42",
                "consumer-bravo",
                "0xabc123",
                "bw-7",
                "arbiter-alpha",
                "arbiter-alpha",
            ])
        );
        let resolve_hash = format!(
            "0x{}",
            hash(&[
                "resolve-consumption",
                "42",
                "consumer-bravo",
                "0xabc123",
                "bw-7",
                "discount",
                "11",
                "accepted_discounted",
                "arbiter-alpha",
                "arbiter-alpha",
            ])
        );

        let raw = std::fs::read_to_string(&tx_file).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        for tx_hash in [&submit_hash, &challenge_hash, &resolve_hash] {
            assert_eq!(
                parsed[tx_hash.as_str()]["tx_hash"].as_str(),
                Some(tx_hash.as_str())
            );
            assert_eq!(parsed[tx_hash.as_str()]["status"].as_str(), Some("pending"));
        }
        assert_eq!(
            query_local_tx_status(&resolve_hash).as_deref(),
            Some("pending")
        );

        std::env::remove_var("TRNM_RPC_TX_FILE");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn consumption_settlement_write_paths_accept_legacy_template_env_aliases() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("TRNM_TX_SUBMIT_CONSUMPTION_RECEIPT_CMD");
        std::env::remove_var("TRNM_TX_SUBMIT_SETTLEMENT_RECEIPT_CMD");
        std::env::remove_var("TRNM_TX_CHALLENGE_CONSUMPTION_CMD");
        std::env::remove_var("TRNM_TX_CHALLENGE_SETTLEMENT_CMD");
        std::env::remove_var("TRNM_TX_RESOLVE_CONSUMPTION_CMD");
        std::env::remove_var("TRNM_TX_RESOLVE_SETTLEMENT_CMD");

        let unique = format!(
            "trnm-cli-consumption-settlement-legacy-env-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root = canonical_temp_root().join(unique);
        std::fs::create_dir_all(&root).unwrap();

        let receipt_path = root.join("receipt.json");
        std::fs::write(
            &receipt_path,
            r#"{
                "task_id":42,
                "consumer_id":"consumer-bravo",
                "output_hash":"0xabc123",
                "billing_window_id":"bw-7",
                "consumer_nonce":9
            }"#,
        )
        .unwrap();

        let tx_file = root.join("txs.json");
        std::env::set_var("TRNM_RPC_TX_FILE", &tx_file);

        let submit_hash = format!("0x{}", "a".repeat(64));
        let challenge_hash = format!("0x{}", "b".repeat(64));
        let resolve_hash = format!("0x{}", "c".repeat(64));

        std::env::set_var(
            "TRNM_TX_SUBMIT_SETTLEMENT_RECEIPT_CMD",
            format!("printf '%s' 'tx_hash={}'", submit_hash),
        );
        std::env::set_var(
            "TRNM_TX_CHALLENGE_SETTLEMENT_CMD",
            format!("printf '%s' 'tx_hash={}'", challenge_hash),
        );
        std::env::set_var(
            "TRNM_TX_RESOLVE_SETTLEMENT_CMD",
            format!("printf '%s' 'tx_hash={}'", resolve_hash),
        );

        submit_consumption_receipt_tx(receipt_path, None).unwrap();
        challenge_consumption_tx(
            42,
            "consumer-bravo".into(),
            "0xabc123".into(),
            "bw-7".into(),
            "arbiter-alpha".into(),
            None,
        )
        .unwrap();
        resolve_consumption_tx(
            42,
            "consumer-bravo".into(),
            "0xabc123".into(),
            "bw-7".into(),
            ConsumptionResolutionDecisionArg::Accept,
            None,
            None,
            "arbiter-alpha".into(),
            None,
        )
        .unwrap();

        let raw = std::fs::read_to_string(&tx_file).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        for tx_hash in [&submit_hash, &challenge_hash, &resolve_hash] {
            assert_eq!(
                parsed[tx_hash.as_str()]["tx_hash"].as_str(),
                Some(tx_hash.as_str())
            );
            assert_eq!(parsed[tx_hash.as_str()]["status"].as_str(), Some("pending"));
        }

        std::env::remove_var("TRNM_TX_SUBMIT_SETTLEMENT_RECEIPT_CMD");
        std::env::remove_var("TRNM_TX_CHALLENGE_SETTLEMENT_CMD");
        std::env::remove_var("TRNM_TX_RESOLVE_SETTLEMENT_CMD");
        std::env::remove_var("TRNM_RPC_TX_FILE");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn consumption_settlement_write_paths_prefer_settlement_template_env_over_legacy_aliases() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("TRNM_TX_SUBMIT_CONSUMPTION_RECEIPT_CMD");
        std::env::remove_var("TRNM_TX_SUBMIT_SETTLEMENT_RECEIPT_CMD");
        std::env::remove_var("TRNM_TX_CHALLENGE_CONSUMPTION_CMD");
        std::env::remove_var("TRNM_TX_CHALLENGE_SETTLEMENT_CMD");
        std::env::remove_var("TRNM_TX_RESOLVE_CONSUMPTION_CMD");
        std::env::remove_var("TRNM_TX_RESOLVE_SETTLEMENT_CMD");

        let unique = format!(
            "trnm-cli-consumption-settlement-env-precedence-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root = canonical_temp_root().join(unique);
        std::fs::create_dir_all(&root).unwrap();

        let receipt_path = root.join("receipt.json");
        std::fs::write(
            &receipt_path,
            r#"{
                "task_id":42,
                "consumer_id":"consumer-bravo",
                "output_hash":"0xabc123",
                "billing_window_id":"bw-7",
                "consumer_nonce":9
            }"#,
        )
        .unwrap();

        let tx_file = root.join("txs.json");
        std::env::set_var("TRNM_RPC_TX_FILE", &tx_file);

        let submit_hash = format!("0x{}", "d".repeat(64));
        let legacy_submit_hash = format!("0x{}", "a".repeat(64));
        let challenge_hash = format!("0x{}", "e".repeat(64));
        let legacy_challenge_hash = format!("0x{}", "b".repeat(64));
        let resolve_hash = format!("0x{}", "f".repeat(64));
        let legacy_resolve_hash = format!("0x{}", "c".repeat(64));

        std::env::set_var(
            "TRNM_TX_SUBMIT_SETTLEMENT_RECEIPT_CMD",
            format!("printf '%s' 'tx_hash={}'", submit_hash),
        );
        std::env::set_var(
            "TRNM_TX_SUBMIT_CONSUMPTION_RECEIPT_CMD",
            format!("printf '%s' 'tx_hash={}'", legacy_submit_hash),
        );
        std::env::set_var(
            "TRNM_TX_CHALLENGE_SETTLEMENT_CMD",
            format!("printf '%s' 'tx_hash={}'", challenge_hash),
        );
        std::env::set_var(
            "TRNM_TX_CHALLENGE_CONSUMPTION_CMD",
            format!("printf '%s' 'tx_hash={}'", legacy_challenge_hash),
        );
        std::env::set_var(
            "TRNM_TX_RESOLVE_SETTLEMENT_CMD",
            format!("printf '%s' 'tx_hash={}'", resolve_hash),
        );
        std::env::set_var(
            "TRNM_TX_RESOLVE_CONSUMPTION_CMD",
            format!("printf '%s' 'tx_hash={}'", legacy_resolve_hash),
        );

        submit_consumption_receipt_tx(receipt_path, None).unwrap();
        challenge_consumption_tx(
            42,
            "consumer-bravo".into(),
            "0xabc123".into(),
            "bw-7".into(),
            "arbiter-alpha".into(),
            None,
        )
        .unwrap();
        resolve_consumption_tx(
            42,
            "consumer-bravo".into(),
            "0xabc123".into(),
            "bw-7".into(),
            ConsumptionResolutionDecisionArg::Accept,
            None,
            None,
            "arbiter-alpha".into(),
            None,
        )
        .unwrap();

        let raw = std::fs::read_to_string(&tx_file).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        for tx_hash in [&submit_hash, &challenge_hash, &resolve_hash] {
            assert_eq!(
                parsed[tx_hash.as_str()]["tx_hash"].as_str(),
                Some(tx_hash.as_str())
            );
            assert_eq!(parsed[tx_hash.as_str()]["status"].as_str(), Some("pending"));
        }
        for tx_hash in [
            &legacy_submit_hash,
            &legacy_challenge_hash,
            &legacy_resolve_hash,
        ] {
            assert!(parsed.get(tx_hash.as_str()).is_none());
        }

        std::env::remove_var("TRNM_TX_SUBMIT_CONSUMPTION_RECEIPT_CMD");
        std::env::remove_var("TRNM_TX_SUBMIT_SETTLEMENT_RECEIPT_CMD");
        std::env::remove_var("TRNM_TX_CHALLENGE_CONSUMPTION_CMD");
        std::env::remove_var("TRNM_TX_CHALLENGE_SETTLEMENT_CMD");
        std::env::remove_var("TRNM_TX_RESOLVE_CONSUMPTION_CMD");
        std::env::remove_var("TRNM_TX_RESOLVE_SETTLEMENT_CMD");
        std::env::remove_var("TRNM_RPC_TX_FILE");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn query_parsers_accept_stringified_task_ids_in_task_response() {
        let parsed = parse_task_query_response(r#"{"task_id":"42"}"#, 42).unwrap();
        assert_eq!(json_u64_at_path(&parsed, &["task_id"]), Some(42));
    }

    #[test]
    fn query_parsers_accept_stringified_task_ids_in_events_response() {
        let parsed =
            parse_events_query_response(r#"[{"task_id":"42","event_type":"accepted"}]"#, 42)
                .unwrap();
        assert_eq!(json_u64_at_path(&parsed[0], &["task_id"]), Some(42));
    }

    #[test]
    fn query_parsers_accept_stringified_task_ids_in_request_full_response() {
        let parsed = parse_request_full_query_response(
            r#"{"request":{"request_id":"req-42","task_id":"42"},"events":[{"task_id":"42"}]}"#,
            "req-42",
        )
        .unwrap();
        assert_eq!(json_u64_at_path(&parsed, &["request", "task_id"]), Some(42));
        assert_eq!(
            json_u64_at_path(&parsed["events"][0], &["task_id"]),
            Some(42)
        );
    }

    #[test]
    fn query_parsers_accept_scalar_request_ids_in_request_full_response() {
        let parsed = parse_request_full_query_response(
            r#"{"request":{"request_id":42,"task_id":42},"events":[{"task_id":42}]}"#,
            "42",
        )
        .unwrap();
        assert_eq!(parsed["request"]["request_id"], serde_json::json!(42));
        assert_eq!(json_u64_at_path(&parsed, &["request", "task_id"]), Some(42));
        assert_eq!(
            json_u64_at_path(&parsed["events"][0], &["task_id"]),
            Some(42)
        );
    }

    #[test]
    fn balance_query_parser_accepts_wrapped_partial_json() {
        let parsed = parse_balance_query_response(
            r#"{"result":{"balance":"42","denom":"utrnm"}}"#,
            "trnm1requested",
            "trnm",
        )
        .unwrap();
        assert_eq!(
            parsed,
            BalanceQueryResponse {
                address: "trnm1requested".into(),
                balance: "42".into(),
                denom: "utrnm".into(),
            }
        );
    }

    #[test]
    fn balance_query_parser_accepts_scalar_json_balance() {
        let parsed = parse_balance_query_response("12345\n", "trnm1requested", "trnm").unwrap();
        assert_eq!(
            parsed,
            BalanceQueryResponse {
                address: "trnm1requested".into(),
                balance: "12345".into(),
                denom: "trnm".into(),
            }
        );
    }

    #[test]
    fn balance_query_parser_accepts_nested_balance_amount_object() {
        let parsed = parse_balance_query_response(
            r#"{"response":{"data":{"address":"trnm1adapter","balance":{"amount":"77","denom":"utrnm"}}}}"#,
            "trnm1requested",
            "trnm",
        )
        .unwrap();
        assert_eq!(
            parsed,
            BalanceQueryResponse {
                address: "trnm1adapter".into(),
                balance: "77".into(),
                denom: "utrnm".into(),
            }
        );
    }

    #[test]
    fn balance_query_parser_accepts_kv_text_output() {
        let parsed = parse_balance_query_response(
            "address=trnm1adapter\nbalance=77\ndenom=utrnm\n",
            "trnm1requested",
            "trnm",
        )
        .unwrap();
        assert_eq!(
            parsed,
            BalanceQueryResponse {
                address: "trnm1adapter".into(),
                balance: "77".into(),
                denom: "utrnm".into(),
            }
        );
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

        let directional_marks_wrapped = ensure_hex_32_bytes(
            "\u{200e}\u{200f}0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\u{200f}\u{200e}",
        )
        .unwrap();
        assert_eq!(
            directional_marks_wrapped,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );

        let invisible_math_separator_wrapped = ensure_hex_32_bytes(
            "\u{2062}0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\u{2062}",
        )
        .unwrap();
        assert_eq!(
            invisible_math_separator_wrapped,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );

        let nominal_digit_shapes_wrapped = ensure_hex_32_bytes(
            "\u{206f}0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\u{206f}",
        )
        .unwrap();
        assert_eq!(
            nominal_digit_shapes_wrapped,
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
            normalize_wallet_store_env("\u{2066}\u{2068}\"/tmp/trnm-wallets\"\u{2069}\u{2067}"),
            Some("/tmp/trnm-wallets")
        );
        assert_eq!(
            normalize_wallet_store_env("\u{200e}\u{061c}《/tmp/trnm-wallets》\u{200f}"),
            Some("/tmp/trnm-wallets")
        );
        assert_eq!(
            normalize_wallet_store_env("\u{00ad}\u{180e}《/tmp/trnm-wallets》\u{180e}\u{00ad}"),
            Some("/tmp/trnm-wallets")
        );
        assert_eq!(
            normalize_wallet_store_env("\u{206a}《/tmp/trnm-wallets》\u{206f}"),
            Some("/tmp/trnm-wallets")
        );
        assert_eq!(
            normalize_wallet_store_env("〈/tmp/trnm-wallets〉"),
            Some("/tmp/trnm-wallets")
        );
        assert_eq!(
            normalize_wallet_store_env("⟨/tmp/trnm-wallets⟩"),
            Some("/tmp/trnm-wallets")
        );
        assert_eq!(
            normalize_wallet_store_env("｟/tmp/trnm-wallets｠"),
            Some("/tmp/trnm-wallets")
        );
        assert_eq!(
            normalize_wallet_store_env("(/tmp/trnm-wallets)"),
            Some("/tmp/trnm-wallets")
        );
        assert_eq!(
            normalize_wallet_store_env("[/tmp/trnm-wallets]"),
            Some("/tmp/trnm-wallets")
        );
        assert_eq!(
            normalize_wallet_store_env("{/tmp/trnm-wallets}"),
            Some("/tmp/trnm-wallets")
        );
        assert_eq!(
            normalize_wallet_store_env(" ({[/tmp/trnm-wallets]}) "),
            Some("/tmp/trnm-wallets")
        );
        assert_eq!(
            normalize_wallet_store_env("\u{2068}({/tmp/trnm-wallets})\u{2069}"),
            Some("/tmp/trnm-wallets")
        );
        assert_eq!(
            normalize_wallet_store_env("【『 /tmp/trnm-wallets 』】"),
            Some("/tmp/trnm-wallets")
        );
        assert_eq!(
            normalize_wallet_store_env("  /tmp/trnm-wallets\" "),
            Some("/tmp/trnm-wallets")
        );
        assert_eq!(
            normalize_wallet_store_env(" /tmp/trnm-wallets》 "),
            Some("/tmp/trnm-wallets")
        );
        assert_eq!(normalize_wallet_store_env("   \"\"   "), None);
        assert_eq!(normalize_wallet_store_env("〈〉"), None);
        assert_eq!(normalize_wallet_store_env("⟨⟩"), None);
        assert_eq!(normalize_wallet_store_env("\u{2068}\u{2069}"), None);
    }

    #[test]
    fn normalize_wallet_store_env_rejects_hidden_or_whitespace_payloads() {
        assert_eq!(normalize_wallet_store_env("/tmp/trnm wallets"), None);
        assert_eq!(normalize_wallet_store_env("/tmp/trnm\t-wallets"), None);
        assert_eq!(normalize_wallet_store_env("/tmp/trnm\n-wallets"), None);
        assert_eq!(
            normalize_wallet_store_env("/tmp/trnm\u{200b}-wallets"),
            None
        );
        assert_eq!(normalize_wallet_store_env("/tmp/trnm\u{202e}wallets"), None);
        assert_eq!(normalize_wallet_store_env("/tmp/trnm∖wallets"), None);
        assert_eq!(normalize_wallet_store_env("/tmp/trnm﹨wallets"), None);
        assert_eq!(normalize_wallet_store_env("/tmp/trnm⧸wallets"), None);
        assert_eq!(normalize_wallet_store_env("/tmp/trnm⧹wallets"), None);
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

        std::env::set_var("TRNM_WALLET_STORE", "/tmp\\trnm-wallets");
        assert_eq!(default_wallet_store(), home.join(".trnm").join("wallets"));

        std::env::set_var("TRNM_WALLET_STORE", "/tmp／trnm-wallets");
        assert_eq!(default_wallet_store(), home.join(".trnm").join("wallets"));

        std::env::set_var("TRNM_WALLET_STORE", "/tmp∖trnm-wallets");
        assert_eq!(default_wallet_store(), home.join(".trnm").join("wallets"));

        std::env::set_var("TRNM_WALLET_STORE", "/tmp﹨trnm-wallets");
        assert_eq!(default_wallet_store(), home.join(".trnm").join("wallets"));

        std::env::set_var("TRNM_WALLET_STORE", "/tmp⧸trnm-wallets");
        assert_eq!(default_wallet_store(), home.join(".trnm").join("wallets"));

        std::env::set_var("TRNM_WALLET_STORE", "//tmp/trnm-wallets");
        assert_eq!(default_wallet_store(), home.join(".trnm").join("wallets"));

        for wrapped_root in [" / ", "'/'", "《/》", "\u{2068}/\u{2069}", "＜/＞"] {
            std::env::set_var("TRNM_WALLET_STORE", wrapped_root);
            assert_eq!(
                default_wallet_store(),
                home.join(".trnm").join("wallets"),
                "wrapped root path should fail closed: {wrapped_root:?}"
            );
        }

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

        std::env::set_var("TRNM_WALLET_STORE", "/tmp/trnm-wallets/");
        assert_eq!(default_wallet_store(), home.join(".trnm").join("wallets"));

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
        assert_eq!(
            default_wallet_store(),
            clean_home.join(".trnm").join("wallets")
        );

        std::env::set_var(
            "HOME",
            format!(" \u{2068}《{}》\u{2069} ", clean_home.display()),
        );
        assert_eq!(
            default_wallet_store(),
            clean_home.join(".trnm").join("wallets"),
            "wrapped HOME should normalize before deriving the default keystore path"
        );

        std::env::set_var("HOME", format!("{}", linked_parent.display()));
        assert_eq!(
            default_wallet_store(),
            std::env::current_dir()
                .unwrap()
                .join(".trnm")
                .join("wallets")
        );

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

        for invalid_env in [
            "\u{2068}\"./wallets\"\u{2069}",
            "'/'",
            "《/》",
            " //tmp/trnm-wallets ",
            "/tmp/trnm-wallets/",
            "/tmp/trnm-wallets/․/keys",
            "/tmp/trnm-wallets/﹒/keys",
        ] {
            std::env::set_var("TRNM_WALLET_STORE", invalid_env);
            let err = resolve_wallet_store(None).unwrap_err();
            assert!(
                err.to_string()
                    .contains("must be an absolute normalized symlink-free path"),
                "unexpected error for {invalid_env:?}: {err}"
            );
        }

        for empty_invalid_env in ["", "   ", "\u{2068}\u{2069}", "  \"\"  "] {
            std::env::set_var("TRNM_WALLET_STORE", empty_invalid_env);
            let err = resolve_wallet_store(None).unwrap_err();
            assert!(
                err.to_string()
                    .contains("TRNM_WALLET_STORE is set but invalid; refusing ambiguous keystore path fallback"),
                "unexpected error for {empty_invalid_env:?}: {err}"
            );
        }

        std::env::set_var("TRNM_WALLET_STORE", "/tmp/trnm⧹wallets");
        let confusable_separator_err = resolve_wallet_store(None).unwrap_err();
        assert!(
            confusable_separator_err.to_string().contains(
                "TRNM_WALLET_STORE is set but invalid; refusing ambiguous keystore path fallback"
            ),
            "unexpected error for confusable separator env store: {confusable_separator_err}"
        );

        let explicit_root = std::env::temp_dir()
            .canonicalize()
            .unwrap_or_else(|_| std::env::temp_dir());
        let explicit = explicit_root.join(format!(
            "trnm-cli-explicit-store-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::env::set_var("TRNM_WALLET_STORE", "\u{2068}\u{2069}");
        assert_eq!(
            resolve_wallet_store(Some(explicit.clone())).unwrap(),
            explicit
        );

        let explicit_relative_err =
            resolve_wallet_store(Some(PathBuf::from("./wallets"))).unwrap_err();
        assert!(
            explicit_relative_err
                .to_string()
                .contains("explicit wallet store './wallets' must be an absolute normalized symlink-free path"),
            "unexpected error: {explicit_relative_err}"
        );

        for invalid_explicit in [
            PathBuf::from("/tmp/trnm-wallets "),
            PathBuf::from(" /tmp/trnm-wallets"),
            PathBuf::from("/tmp/trnm\u{200b}wallets"),
            PathBuf::from("/tmp/《trnm-wallets》"),
            PathBuf::from("/tmp/｟trnm-wallets｠"),
            PathBuf::from("/tmp/trnm⧹wallets"),
            PathBuf::from("/tmp/trnm-wallets/"),
            PathBuf::from("/tmp/trnm-wallets/․/keys"),
            PathBuf::from("/tmp/trnm-wallets/﹒/keys"),
        ] {
            let err = resolve_wallet_store(Some(invalid_explicit.clone())).unwrap_err();
            assert!(
                err.to_string().contains("explicit wallet store")
                    && err
                        .to_string()
                        .contains("must be an absolute normalized symlink-free path"),
                "unexpected error for explicit store {:?}: {err}",
                invalid_explicit
            );
        }

        match original_store {
            Some(value) => std::env::set_var("TRNM_WALLET_STORE", value),
            None => std::env::remove_var("TRNM_WALLET_STORE"),
        }
    }

    #[test]
    fn resolve_wallet_store_rejects_symlinked_final_store_component() {
        let _guard = ENV_LOCK.lock().unwrap();
        let original_store = std::env::var_os("TRNM_WALLET_STORE");

        let root = canonical_temp_root().join(format!(
            "trnm-cli-resolve-store-symlink-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let real_store = root.join("real-store");
        let linked_store = root.join("linked-store");
        std::fs::create_dir_all(&real_store).unwrap();
        std::os::unix::fs::symlink(&real_store, &linked_store).unwrap();

        let explicit_err = resolve_wallet_store(Some(linked_store.clone())).unwrap_err();
        assert!(
            explicit_err.to_string().contains("explicit wallet store")
                && explicit_err
                    .to_string()
                    .contains("must be an absolute normalized symlink-free path"),
            "unexpected error: {explicit_err}"
        );

        std::env::set_var("TRNM_WALLET_STORE", linked_store.as_os_str());
        let env_err = resolve_wallet_store(None).unwrap_err();
        assert!(
            env_err.to_string().contains("TRNM_WALLET_STORE")
                && env_err
                    .to_string()
                    .contains("must be an absolute normalized symlink-free path"),
            "unexpected error: {env_err}"
        );

        match original_store {
            Some(value) => std::env::set_var("TRNM_WALLET_STORE", value),
            None => std::env::remove_var("TRNM_WALLET_STORE"),
        }
        let _ = std::fs::remove_file(&linked_store);
        let _ = std::fs::remove_dir_all(&real_store);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn resolve_wallet_store_rejects_symlinked_ancestor_component() {
        let _guard = ENV_LOCK.lock().unwrap();
        let original_store = std::env::var_os("TRNM_WALLET_STORE");

        let root = canonical_temp_root().join(format!(
            "trnm-cli-resolve-ancestor-symlink-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let real_parent = root.join("real-parent");
        let linked_parent = root.join("linked-parent");
        let store = linked_parent.join("wallets");
        std::fs::create_dir_all(&real_parent).unwrap();
        std::os::unix::fs::symlink(&real_parent, &linked_parent).unwrap();

        let explicit_err = resolve_wallet_store(Some(store.clone())).unwrap_err();
        assert!(
            explicit_err.to_string().contains("explicit wallet store")
                && explicit_err
                    .to_string()
                    .contains("must be an absolute normalized symlink-free path"),
            "unexpected error: {explicit_err}"
        );

        std::env::set_var("TRNM_WALLET_STORE", store.as_os_str());
        let env_err = resolve_wallet_store(None).unwrap_err();
        assert!(
            env_err.to_string().contains("TRNM_WALLET_STORE")
                && env_err
                    .to_string()
                    .contains("must be an absolute normalized symlink-free path"),
            "unexpected error: {env_err}"
        );

        match original_store {
            Some(value) => std::env::set_var("TRNM_WALLET_STORE", value),
            None => std::env::remove_var("TRNM_WALLET_STORE"),
        }
        let _ = std::fs::remove_file(&linked_parent);
        let _ = std::fs::remove_dir_all(&real_parent);
        let _ = std::fs::remove_dir_all(&root);
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

        let dot_confusable_write_err = write_key(
            std::path::Path::new("/tmp/trnm-wallets/․/keys"),
            "alice",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap_err();
        assert!(
            dot_confusable_write_err
                .to_string()
                .contains("must be an absolute normalized path"),
            "unexpected error: {dot_confusable_write_err}"
        );

        let backslash_write_err = write_key(
            std::path::Path::new("/tmp\\trnm-wallets"),
            "alice",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap_err();
        assert!(
            backslash_write_err
                .to_string()
                .contains("must be an absolute normalized path"),
            "unexpected error: {backslash_write_err}"
        );

        let slash_confusable_read_err =
            read_key(std::path::Path::new("/tmp／trnm-wallets"), "alice").unwrap_err();
        assert!(
            slash_confusable_read_err
                .to_string()
                .contains("must be an absolute normalized path"),
            "unexpected error: {slash_confusable_read_err}"
        );

        let big_solidus_write_err = write_key(
            std::path::Path::new("/tmp⧸trnm-wallets"),
            "alice",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap_err();
        assert!(
            big_solidus_write_err
                .to_string()
                .contains("must be an absolute normalized path"),
            "unexpected error: {big_solidus_write_err}"
        );

        let big_reverse_solidus_read_err =
            read_key(std::path::Path::new("/tmp⧹trnm-wallets"), "alice").unwrap_err();
        assert!(
            big_reverse_solidus_read_err
                .to_string()
                .contains("must be an absolute normalized path"),
            "unexpected error: {big_reverse_solidus_read_err}"
        );

        let duplicate_slash_write_err = write_key(
            std::path::Path::new("//tmp/trnm-wallets"),
            "alice",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap_err();
        assert!(
            duplicate_slash_write_err
                .to_string()
                .contains("must be an absolute normalized path"),
            "unexpected error: {duplicate_slash_write_err}"
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
            "hello\u{00ad}world".to_string(),
            "hello\u{061c}world".to_string(),
            "hello\u{180e}world".to_string(),
            "hello\u{200e}world".to_string(),
            "hello\u{200f}world".to_string(),
            "hello\u{202e}world".to_string(),
            "hello\u{2060}world".to_string(),
            "hello\u{2063}world".to_string(),
            "hello\u{2068}world".to_string(),
            "hello\u{206a}world".to_string(),
            "hello\u{206f}world".to_string(),
            oversized,
        ] {
            let err = ensure_sign_message(&bad).unwrap_err();
            assert!(
                err.to_string().contains("sign message"),
                "unexpected error for {bad:?}: {err}"
            );
        }

        ensure_sign_message("trnm mainnet attestation v1").unwrap();
        ensure_sign_message("Signing purpose: validator-bootstrap").unwrap();
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
            "alice⧸bob",
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
            "alice+backup",
            "alice@prod",
            "alice~1",
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
            "con",
            "PRN",
            "aux",
            "nul",
            "com1",
            "CoM9",
            "lpt1",
            "LPT9",
            "аlice",
            "alice猫",
        ] {
            let err = ensure_wallet_name(bad).unwrap_err();
            assert!(
                err.to_string().contains("invalid wallet name"),
                "unexpected error for {bad:?}: {err}"
            );
        }

        ensure_wallet_name("alice").unwrap();
        ensure_wallet_name("alice_01").unwrap();
        ensure_wallet_name("alice-01").unwrap();
        ensure_wallet_name("ALICE01").unwrap();
    }

    #[test]
    fn wallet_name_error_mentions_ascii_requirement() {
        let err = ensure_wallet_name("аlice").unwrap_err();
        assert!(
            err.to_string().contains("ASCII local name"),
            "unexpected error: {err}"
        );
        assert!(
            err.to_string().contains("only letters, digits, '_' or '-'"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn wallet_name_error_mentions_simple_ascii_charset() {
        let err = ensure_wallet_name("alice+backup").unwrap_err();
        assert!(
            err.to_string().contains("only letters, digits, '_' or '-'"),
            "unexpected error: {err}"
        );
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
        assert_eq!(
            store_mode, 0o700,
            "unexpected wallet store mode: {:o}",
            store_mode
        );

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
                || err
                    .to_string()
                    .contains("must be an absolute normalized symlink-free path"),
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
            format_tx_hash_spaced_alias_line("0xabc123"),
            "tx hash=0xabc123".to_string()
        );
        assert_eq!(
            format_transaction_hash_hyphen_alias_line("0xabc123"),
            "transaction-hash=0xabc123".to_string()
        );
        assert_eq!(
            format_transaction_hash_spaced_alias_line("0xabc123"),
            "transaction hash=0xabc123".to_string()
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
            extract_tx_hash(&format_tx_hash_spaced_alias_line("0xabc123")).as_deref(),
            Some("0xabc123")
        );
        assert_eq!(
            extract_tx_hash(&format_transaction_hash_hyphen_alias_line("0xabc123")).as_deref(),
            Some("0xabc123")
        );
        assert_eq!(
            extract_tx_hash(&format_transaction_hash_spaced_alias_line("0xabc123")).as_deref(),
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
        assert_eq!(
            extract_tx_hash("{\"tx-hash\":\"0xFEED1234\",\"status\":\"ok\"}").as_deref(),
            Some("0xfeed1234")
        );
        assert_eq!(
            extract_tx_hash("{\"transaction-hash\":\"BEEF5678\",\"status\":\"ok\"}").as_deref(),
            Some("beef5678")
        );
    }

    #[test]
    fn extract_tx_hash_accepts_case_insensitive_json_key_aliases() {
        assert_eq!(
            extract_tx_hash("{\"TX_HASH\":\"0xFEED1234\",\"status\":\"ok\"}").as_deref(),
            Some("0xfeed1234")
        );
        assert_eq!(
            extract_tx_hash("{\"result\":{\"TX_RESPONSE\":{\"Transaction-Hash\":\"BEEF5678\"}}}")
                .as_deref(),
            Some("beef5678")
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
    fn tx_query_parse_json_accepts_case_insensitive_response_wrapped_hyphenated_keys() {
        let json = "{\"RESULT\":{\"RESPONSE\":{\"DATA\":{\"TX-HASH\":\"0xABCD\"},\"TX-STATUS\":\"SUCCESS\",\"RAW-LOG\":\"NULL\"}}}";
        let parsed = parse_tx_query_response(json, "0xfallback").unwrap();
        assert_eq!(parsed.tx_hash, "0xabcd");
        assert_eq!(parsed.status, "committed");
        assert_eq!(parsed.error, None);
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
        assert!(
            err.to_string().contains("must not be empty"),
            "unexpected: {err}"
        );
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
    fn ensure_safe_sign_message_rejects_repeated_interior_spaces() {
        let err = ensure_safe_sign_message("rotate  signer to cold-key slot b").unwrap_err();
        assert!(
            err.to_string().contains("repeated interior spaces"),
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
    fn ensure_safe_sign_message_rejects_inhibit_symmetric_swapping_text() {
        let err = ensure_safe_sign_message("rotate signer\u{206a}slot-b").unwrap_err();
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
        let err = ensure_safe_sign_message("rotate signer to slöt-b").unwrap_err();
        assert!(
            err.to_string().contains("ASCII printable text"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn ensure_safe_sign_message_rejects_kv_delimiter_text() {
        let err = ensure_safe_sign_message("approve=tx").unwrap_err();
        assert!(
            err.to_string().contains("wrapper punctuation")
                || err.to_string().contains("ASCII printable text"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn ensure_safe_sign_message_rejects_wrapper_punctuation_text() {
        for bad in [
            "\"approve tx\"",
            "'approve tx'",
            "`approve tx`",
            "<approve tx>",
            "(approve tx)",
            "[approve tx]",
            "{approve tx}",
        ] {
            let err = ensure_safe_sign_message(bad).unwrap_err();
            assert!(
                err.to_string().contains("wrapper punctuation"),
                "unexpected for {bad:?}: {err}"
            );
        }
    }

    #[test]
    fn ensure_safe_sign_message_rejects_path_separator_text() {
        for bad in [
            "approve /tmp/offline-payload",
            "approve C:\\offline\\payload",
        ] {
            let err = ensure_safe_sign_message(bad).unwrap_err();
            assert!(
                err.to_string().contains("path separators"),
                "unexpected for {bad:?}: {err}"
            );
        }
    }

    #[test]
    fn ensure_safe_sign_message_rejects_unicode_path_separator_homoglyph_text() {
        let err = ensure_safe_sign_message("approve tmp∕offline∕payload").unwrap_err();
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
        assert_eq!(
            query_local_tx_status(raw_tx_hash).as_deref(),
            Some("pending")
        );

        let _ = std::fs::remove_file(&path);
        std::env::remove_var("TRNM_RPC_TX_FILE");
    }

    #[test]
    fn persist_local_pending_tx_rejects_non_prefixed_hex_hashes() {
        let err = persist_local_pending_tx("deadbeef")
            .unwrap_err()
            .to_string();
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
            "{}\n{}\n{}\n{}\n{}\n{}\n{}\nstatus={}\n",
            format_tx_hash_line(&query.tx_hash),
            format_tx_hash_alias_line(&query.tx_hash),
            format_transaction_hash_alias_line(&query.tx_hash),
            format_transaction_hash_camel_alias_line(&query.tx_hash),
            format_tx_hash_hyphen_alias_line(&query.tx_hash),
            format_transaction_hash_hyphen_alias_line(&query.tx_hash),
            format_transaction_hash_spaced_alias_line(&query.tx_hash),
            query.status
        );

        assert!(emitted.contains("tx_hash=\"0xabc123\""));
        assert!(emitted.contains("txhash=0xabc123"));
        assert!(emitted.contains("transaction_hash=0xabc123"));
        assert!(emitted.contains("transactionHash=0xabc123"));
        assert!(emitted.contains("tx-hash=0xabc123"));
        assert!(emitted.contains("transaction-hash=0xabc123"));
        assert!(emitted.contains("transaction hash=0xabc123"));
        assert_eq!(extract_tx_hash(&emitted).as_deref(), Some("0xabc123"));
    }

    #[test]
    fn parse_consumption_summary_query_response_rejects_mismatched_task_id() {
        let err = parse_consumption_summary_query_response(
            r#"{"task_id":7,"receipt_count":1,"accepted_receipt_count":1,"challenged_receipt_count":0,"total_consumed_tokens":17,"total_claimed_consumption_units":17,"total_credited_consumption_units":17}"#,
            42,
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("requested=42, got=7"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_consumption_summary_query_response_accepts_stringified_task_id() {
        let parsed = parse_consumption_summary_query_response(
            r#"{"task_id":"42","receipt_count":1,"accepted_receipt_count":1,"challenged_receipt_count":0,"total_consumed_tokens":17,"total_claimed_consumption_units":17,"total_credited_consumption_units":17}"#,
            42,
        )
        .expect("parse consumption summary with string task_id");
        assert_eq!(json_u64_alias(&parsed, &["task_id"]), Some(42));
    }

    #[test]
    fn parse_consumption_summary_query_response_accepts_wrapped_summary_payload() {
        let parsed = parse_consumption_summary_query_response(
            r#"{"result":{"summary":{"task_id":"42","receipt_count":1,"accepted_receipt_count":1,"challenged_receipt_count":0,"total_consumed_tokens":17,"total_claimed_consumption_units":17,"total_credited_consumption_units":17}}}"#,
            42,
        )
        .expect("parse wrapped consumption summary payload");
        assert_eq!(json_u64_alias(&parsed, &["task_id"]), Some(42));
        assert_eq!(parsed.get("receipt_count"), Some(&serde_json::json!(1)));
    }

    #[test]
    fn parse_consumption_summary_query_response_accepts_settlement_preview_wrapper() {
        let parsed = parse_consumption_summary_query_response(
            r#"{"settlement_preview":{"task_id":"42","receipt_count":1,"accepted_receipt_count":1}}"#,
            42,
        )
        .expect("parse settlement_preview wrapper");
        assert_eq!(json_u64_alias(&parsed, &["task_id"]), Some(42));
        assert_eq!(parsed.get("receipt_count"), Some(&serde_json::json!(1)));
    }

    #[test]
    fn parse_consumption_summary_query_response_accepts_consumption_summary_wrapper() {
        let parsed = parse_consumption_summary_query_response(
            r#"{"consumption_summary":{"task_id":"42","receipt_count":1,"accepted_receipt_count":1}}"#,
            42,
        )
        .expect("parse consumption_summary wrapper");
        assert_eq!(json_u64_alias(&parsed, &["task_id"]), Some(42));
        assert_eq!(parsed.get("receipt_count"), Some(&serde_json::json!(1)));
    }

    #[test]
    fn consumption_summary_query_prefers_settlement_preview_template_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("TRNM_QUERY_SETTLEMENT_PREVIEW_CMD");
        std::env::remove_var("TRNM_QUERY_CONSUMPTION_SUMMARY_CMD");
        std::env::set_var(
            "TRNM_QUERY_SETTLEMENT_PREVIEW_CMD",
            r#"printf '%s' '{"task_id":42,"source":"settlement-preview"}'"#,
        );
        std::env::set_var(
            "TRNM_QUERY_CONSUMPTION_SUMMARY_CMD",
            r#"printf '%s' '{"task_id":42,"source":"legacy-consumption-summary"}'"#,
        );

        let got = consumption_summary_query(42).expect("query via settlement-preview env override");

        std::env::remove_var("TRNM_QUERY_SETTLEMENT_PREVIEW_CMD");
        std::env::remove_var("TRNM_QUERY_CONSUMPTION_SUMMARY_CMD");
        assert_eq!(
            got.get("source"),
            Some(&serde_json::json!("settlement-preview"))
        );
    }

    #[test]
    fn settlement_preview_query_commands_keep_legacy_fallback_after_cutover_name() {
        let commands = settlement_preview_query_commands(42);
        assert_eq!(
            commands[0],
            "cargo run -q -p trnm-rpc -- query-settlement-preview 42"
        );
        assert_eq!(
            commands[1],
            "cargo run -q -p trnm-rpc -- query-consumption-summary 42"
        );
    }

    #[test]
    fn consumption_receipts_query_prefers_settlement_receipts_template_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("TRNM_QUERY_SETTLEMENT_RECEIPTS_CMD");
        std::env::remove_var("TRNM_QUERY_CONSUMPTION_RECEIPTS_CMD");
        std::env::set_var(
            "TRNM_QUERY_SETTLEMENT_RECEIPTS_CMD",
            r#"printf '%s' '{"task_id":42,"receipts":[{"task_id":42,"source":"settlement-receipts"}]}'"#,
        );
        std::env::set_var(
            "TRNM_QUERY_CONSUMPTION_RECEIPTS_CMD",
            r#"printf '%s' '{"task_id":42,"receipts":[{"task_id":42,"source":"legacy-consumption-receipts"}]}'"#,
        );

        let got =
            consumption_receipts_query(42, 7).expect("query via settlement-receipts env override");

        std::env::remove_var("TRNM_QUERY_SETTLEMENT_RECEIPTS_CMD");
        std::env::remove_var("TRNM_QUERY_CONSUMPTION_RECEIPTS_CMD");
        assert_eq!(
            got[0].get("source"),
            Some(&serde_json::json!("settlement-receipts"))
        );
    }

    #[test]
    fn settlement_receipts_query_commands_keep_legacy_fallback_after_cutover_name() {
        let commands = settlement_receipts_query_commands(42, 7);
        assert_eq!(
            commands[0],
            "cargo run -q -p trnm-rpc -- query-settlement-receipts 42 --limit 7"
        );
        assert_eq!(
            commands[1],
            "cargo run -q -p trnm-rpc -- query-consumption-receipts 42 --limit 7"
        );
    }

    #[test]
    fn parse_consumption_receipts_query_response_accepts_matching_task_ids() {
        let parsed = parse_consumption_receipts_query_response(
            r#"[{"task_id":42,"consumer_id":"consumer-bravo","output_hash":"abc123","billing_window_id":"bw-1","worker_id":"worker-alpha","tokenizer_id":"tok","tokenizer_version":"1.0.0","consumer_class":"bonded_api_client","consumed_spans_root":"def456","consumed_token_count":17,"claimed_consumption_units":17,"credited_consumption_units":9,"consumer_nonce":7,"accepted_at_unix_ms":1775683200123,"status":"Discounted","resolution_code":"accepted_discounted"}]"#,
            42,
        )
        .expect("parse consumption receipts");
        assert_eq!(parsed.as_array().map(Vec::len), Some(1));
    }

    #[test]
    fn parse_consumption_receipts_query_response_accepts_stringified_task_ids() {
        let parsed = parse_consumption_receipts_query_response(
            r#"[{"task_id":"42","consumer_id":"consumer-bravo","output_hash":"abc123","billing_window_id":"bw-1","worker_id":"worker-alpha","tokenizer_id":"tok","tokenizer_version":"1.0.0","consumer_class":"bonded_api_client","consumed_spans_root":"def456","consumed_token_count":17,"claimed_consumption_units":17,"credited_consumption_units":9,"consumer_nonce":7,"accepted_at_unix_ms":1775683200123,"status":"Discounted","resolution_code":"accepted_discounted"}]"#,
            42,
        )
        .expect("parse consumption receipts with string task_id");
        assert_eq!(parsed.as_array().map(Vec::len), Some(1));
    }

    #[test]
    fn parse_consumption_receipts_query_response_accepts_wrapped_receipts_payload() {
        let parsed = parse_consumption_receipts_query_response(
            r#"{"result":{"task_id":42,"receipts":[{"consumer_id":"consumer-bravo","output_hash":"abc123","billing_window_id":"bw-1","worker_id":"worker-alpha","tokenizer_id":"tok","tokenizer_version":"1.0.0","consumer_class":"bonded_api_client","consumed_spans_root":"def456","consumed_token_count":17,"claimed_consumption_units":17,"credited_consumption_units":9,"consumer_nonce":7,"accepted_at_unix_ms":1775683200123,"status":"Discounted","resolution_code":"accepted_discounted"}]}}"#,
            42,
        )
        .expect("parse wrapped consumption receipts payload");
        assert_eq!(parsed.as_array().map(Vec::len), Some(1));
        assert_eq!(
            parsed[0].get("consumer_id"),
            Some(&serde_json::json!("consumer-bravo"))
        );
    }

    #[test]
    fn parse_consumption_receipts_query_response_accepts_settlement_receipts_wrapper() {
        let parsed = parse_consumption_receipts_query_response(
            r#"{"settlement_receipts":{"task_id":"42","receipts":[{"consumer_id":"consumer-bravo","output_hash":"abc123","billing_window_id":"bw-1"}]}}"#,
            42,
        )
        .expect("parse settlement_receipts wrapper");
        assert_eq!(parsed.as_array().map(Vec::len), Some(1));
        assert_eq!(
            parsed[0].get("consumer_id"),
            Some(&serde_json::json!("consumer-bravo"))
        );
    }

    #[test]
    fn parse_consumption_receipts_query_response_accepts_consumption_receipts_wrapper() {
        let parsed = parse_consumption_receipts_query_response(
            r#"{"consumption_receipts":{"task_id":"42","receipts":[{"consumer_id":"consumer-bravo","output_hash":"abc123","billing_window_id":"bw-1"}]}}"#,
            42,
        )
        .expect("parse consumption_receipts wrapper");
        assert_eq!(parsed.as_array().map(Vec::len), Some(1));
        assert_eq!(
            parsed[0].get("consumer_id"),
            Some(&serde_json::json!("consumer-bravo"))
        );
    }
}
