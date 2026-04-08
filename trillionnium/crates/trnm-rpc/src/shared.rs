use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use trnm_rpc::TaskMeteringQueryResponse;

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct AdapterRecord {
    pub(crate) ts: u64,
    pub(crate) kind: String,
    pub(crate) task_id: u64,
    pub(crate) worker: Option<String>,
    pub(crate) result_hash: Option<String>,
    pub(crate) status: String,
    #[serde(default)]
    pub(crate) tx_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MarketTask {
    pub(crate) task_id: u64,
    pub(crate) creator: String,
    pub(crate) bounty: u128,
    pub(crate) description: String,
    pub(crate) status: String,
    pub(crate) created_at_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MarketBid {
    pub(crate) task_id: u64,
    pub(crate) worker: String,
    pub(crate) price: u128,
    pub(crate) created_at_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MessageIngressRecord {
    pub(crate) request_id: String,
    pub(crate) task_id: u64,
    pub(crate) channel: String,
    pub(crate) user_id: String,
    pub(crate) session_id: String,
    pub(crate) text: String,
    pub(crate) idempotency_key: String,
    pub(crate) status: String,
    pub(crate) created_at_unix_ms: u128,
    #[serde(default)]
    pub(crate) assigned_worker: Option<String>,
    #[serde(default)]
    pub(crate) assigned_at_unix_ms: Option<u128>,
    #[serde(default)]
    pub(crate) model_output: Option<String>,
    #[serde(default)]
    pub(crate) result_hash: Option<String>,
    #[serde(default)]
    pub(crate) verifier_status: Option<String>,
    #[serde(default)]
    pub(crate) resolution_code: Option<String>,
    #[serde(default)]
    pub(crate) commit_tx_hash: Option<String>,
    #[serde(default)]
    pub(crate) reveal_tx_hash: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct NodeEventRecord {
    pub(crate) event_type: String,
    pub(crate) task_id: u64,
    pub(crate) from_status: String,
    pub(crate) to_status: String,
    pub(crate) actor: String,
    pub(crate) tx_id: u64,
    pub(crate) block_height: u64,
    pub(crate) state_root: String,
    pub(crate) ts_unix_ms: u128,
    pub(crate) signer: Option<String>,
    pub(crate) challenger: Option<String>,
    pub(crate) tx_hash: Option<String>,
    pub(crate) resolution_code: Option<String>,
    pub(crate) treasury_delta: Option<i128>,
    pub(crate) challenger_delta: Option<i128>,
    pub(crate) bond_disposition: Option<String>,
    pub(crate) metering: Option<TaskMeteringQueryResponse>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum OpsWindowArg {
    #[value(name = "24h")]
    H24,
    #[value(name = "7d")]
    D7,
    #[value(name = "custom")]
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NodeEventScanMode {
    Authoritative,
    #[cfg(test)]
    RecentTail,
}

impl NodeEventScanMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Authoritative => "authoritative",
            #[cfg(test)]
            Self::RecentTail => "recent_tail",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct LoadedNodeEvents {
    pub(crate) events: Vec<NodeEventRecord>,
    pub(crate) mode: NodeEventScanMode,
    pub(crate) truncated: bool,
}

pub(crate) fn normalize_actor_or_signer(raw: &str) -> Option<String> {
    let sanitized: String = raw
        .trim()
        .chars()
        .filter_map(|ch| match ch {
            '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FEFF}' => Some(' '),
            _ if ch.is_control() => Some(' '),
            _ => Some(ch),
        })
        .collect();
    let collapsed = sanitized
        .split_ascii_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if collapsed.is_empty() {
        None
    } else {
        Some(collapsed)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct IngressQuarantineRecord {
    pub(crate) source_path: String,
    pub(crate) line_number: usize,
    pub(crate) line_hash: u64,
    pub(crate) raw_line: String,
    pub(crate) error: String,
    pub(crate) quarantined_at_unix_ms: u128,
}

pub(crate) fn push_tail_limited<T>(items: &mut Vec<T>, item: T, limit: usize) {
    if limit == 0 {
        return;
    }
    items.push(item);
    if items.len() > limit {
        let keep_from = items.len() - limit;
        items.drain(0..keep_from);
    }
}

pub(crate) fn normalize_tx_hash_lookup(raw: &str) -> String {
    let mut normalized = raw.trim_matches(|c: char| {
        c.is_ascii_whitespace() || matches!(c, ',' | ';' | '.' | ':' | '(' | ')' | '[' | ']' | '{' | '}')
    });

    loop {
        let is_wrapped = normalized.len() >= 2
            && ["\"", "'", "`"]
                .iter()
                .any(|q| normalized.starts_with(q) && normalized.ends_with(q));

        if is_wrapped {
            normalized = normalized[1..normalized.len() - 1].trim_matches(|c: char| {
                c.is_ascii_whitespace()
                    || matches!(c, ',' | ';' | '.' | ':' | '(' | ')' | '[' | ']' | '{' | '}')
            });
            continue;
        }
        break;
    }

    let normalized = normalized.to_ascii_lowercase();
    for delimiter in ['=', ':'] {
        if let Some((k, v)) = normalized.split_once(delimiter) {
            let key = k.trim();
            let normalized_key: String =
                key.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
            if normalized_key == "txhash" || normalized_key == "hash" {
                let mut value = v.trim_matches(|c: char| {
                    c.is_ascii_whitespace()
                        || matches!(c, ',' | ';' | '.' | ':' | '(' | ')' | '[' | ']' | '{' | '}')
                });
                while let Some(stripped) = value.strip_prefix('=') {
                    value = stripped.trim_start_matches(|c: char| c.is_ascii_whitespace());
                }
                while let Some(stripped) = value.strip_prefix(':') {
                    value = stripped.trim_start_matches(|c: char| c.is_ascii_whitespace());
                }
                loop {
                    let is_wrapped = value.len() >= 2
                        && ["\"", "'", "`"]
                            .iter()
                            .any(|q| value.starts_with(q) && value.ends_with(q));
                    if is_wrapped {
                        value = value[1..value.len() - 1].trim_matches(|c: char| {
                            c.is_ascii_whitespace()
                                || matches!(c, ',' | ';' | '.' | ':' | '(' | ')' | '[' | ']' | '{' | '}')
                        });
                        continue;
                    }
                    break;
                }
                return value.to_string();
            }
        }
    }

    normalized
}

pub(crate) fn is_hex_like_tx_hash(raw: &str) -> bool {
    raw.strip_prefix("0x")
        .map(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_hexdigit()))
        .unwrap_or(false)
}
