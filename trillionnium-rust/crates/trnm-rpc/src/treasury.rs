use crate::node_events::load_node_events;
use crate::rpc_util::{clamp_limit, resolve_ops_window};
use crate::{NodeEventRecord, NodeEventScanMode, OpsWindowArg};
use anyhow::Result;
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};

const CHALLENGE_ESCROW_ACCOUNT: &str = "treasury.challenge_escrow";
const CHALLENGE_FORFEIT_TREASURY_ACCOUNT: &str = "treasury.challenge_forfeits";
pub(crate) const CHALLENGE_TREASURY_EVENTS_LIMIT_DEFAULT: usize = 20;
pub(crate) const CHALLENGE_TREASURY_EVENTS_LIMIT_MAX: usize = 200;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ChallengeTreasuryEventView {
    pub(crate) event_type: String,
    pub(crate) task_id: u64,
    pub(crate) tx_id: u64,
    pub(crate) block_height: u64,
    pub(crate) ts_unix_ms: u128,
    pub(crate) challenger: Option<String>,
    pub(crate) bond_disposition: Option<String>,
    pub(crate) bond_amount: u128,
    pub(crate) escrow_delta: i128,
    pub(crate) forfeits_delta: u128,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ChallengeDailySummary {
    pub(crate) posted: usize,
    pub(crate) refunded: usize,
    pub(crate) forfeited: usize,
    pub(crate) unresolved: usize,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ChallengeWindowView {
    pub(crate) mode: String,
    pub(crate) from_unix_ms: u128,
    pub(crate) to_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ChallengeTreasuryAnomaly {
    pub(crate) event_type: String,
    pub(crate) task_id: u64,
    pub(crate) tx_id: u64,
    pub(crate) code: String,
    pub(crate) detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ChallengeTreasuryQueryResponse {
    pub(crate) challenge_escrow_account: String,
    pub(crate) challenge_forfeits_account: String,
    pub(crate) current_escrow_balance: u128,
    pub(crate) current_forfeits_balance: u128,
    pub(crate) cumulative_forfeited: u128,
    pub(crate) events_total: usize,
    pub(crate) events: Vec<ChallengeTreasuryEventView>,
    pub(crate) anomaly_count: usize,
    pub(crate) anomalies: Vec<ChallengeTreasuryAnomaly>,
    pub(crate) daily_summary: Option<ChallengeDailySummary>,
    pub(crate) window: Option<ChallengeWindowView>,
    pub(crate) node_event_source_mode: String,
    pub(crate) node_event_log_truncated: bool,
}

pub(crate) fn handle_query_challenge_treasury(
    limit: usize,
    window: Option<OpsWindowArg>,
    from_unix_ms: Option<u128>,
    to_unix_ms: Option<u128>,
    json: bool,
    now_unix_ms: u128,
) -> Result<()> {
    let limit = clamp_limit(
        "QueryChallengeTreasury",
        limit,
        CHALLENGE_TREASURY_EVENTS_LIMIT_DEFAULT,
        CHALLENGE_TREASURY_EVENTS_LIMIT_MAX,
    );
    let summary_window = resolve_ops_window(window, from_unix_ms, to_unix_ms, now_unix_ms)?;
    let node_events = load_node_events(NodeEventScanMode::Authoritative);
    let out = summarize_challenge_treasury(
        &node_events.events,
        limit,
        summary_window,
        node_events.mode,
        node_events.truncated,
    );
    if json {
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&out)?);
    }
    Ok(())
}

pub(crate) fn summarize_challenge_treasury(
    node_events: &[NodeEventRecord],
    limit: usize,
    summary_window: Option<(u128, u128, String)>,
    node_event_source_mode: NodeEventScanMode,
    node_event_log_truncated: bool,
) -> ChallengeTreasuryQueryResponse {
    let mut related: Vec<&NodeEventRecord> = node_events
        .iter()
        .filter(|e| {
            e.event_type == "challenge"
                || ((e.event_type == "resolve" || e.event_type == "timeout")
                    && matches!(
                        e.bond_disposition.as_deref(),
                        Some("forfeited") | Some("refunded")
                    ))
        })
        .collect();

    related.sort_by_key(|e| (e.block_height, e.tx_id, e.ts_unix_ms));

    let mut posted_by_task = BTreeMap::<u64, u128>::new();
    let mut posted_open_in_window = BTreeMap::<u64, ()>::new();
    let mut escrow_balance: u128 = 0;
    let mut forfeits_balance: u128 = 0;
    let mut cumulative_forfeited: u128 = 0;

    let mut summary_posted: usize = 0;
    let mut summary_refunded: usize = 0;
    let mut summary_forfeited: usize = 0;

    let mut views = Vec::new();
    let mut anomalies = Vec::new();
    let mut seen_event_fingerprints = HashSet::<(
        String,
        u64,
        u64,
        Option<String>,
        Option<String>,
        Option<i128>,
    )>::new();
    for e in &related {
        let mut bond_amount: u128 = 0;
        let mut escrow_delta: i128 = 0;
        let mut forfeits_delta: u128 = 0;

        let in_window = summary_window
            .as_ref()
            .map(|(from, to, _)| e.ts_unix_ms >= *from && e.ts_unix_ms <= *to)
            .unwrap_or(false);

        let fingerprint = (
            e.event_type.clone(),
            e.task_id,
            e.tx_id,
            e.bond_disposition.clone(),
            e.resolution_code.clone(),
            e.challenger_delta,
        );
        if !seen_event_fingerprints.insert(fingerprint) {
            anomalies.push(ChallengeTreasuryAnomaly {
                event_type: e.event_type.clone(),
                task_id: e.task_id,
                tx_id: e.tx_id,
                code: "duplicate_event_replay".to_string(),
                detail: "event replay ignored because an equivalent challenge treasury event was already applied".to_string(),
            });
            views.push(ChallengeTreasuryEventView {
                event_type: e.event_type.clone(),
                task_id: e.task_id,
                tx_id: e.tx_id,
                block_height: e.block_height,
                ts_unix_ms: e.ts_unix_ms,
                challenger: e.challenger.clone(),
                bond_disposition: e.bond_disposition.clone(),
                bond_amount: 0,
                escrow_delta: 0,
                forfeits_delta: 0,
            });
            continue;
        }

        match e.event_type.as_str() {
            "challenge" => {
                bond_amount = e
                    .challenger_delta
                    .filter(|v| *v < 0)
                    .and_then(|v| u128::try_from(v.saturating_abs()).ok())
                    .unwrap_or(0);
                if bond_amount > 0 {
                    if let Some(existing_bond) = posted_by_task.get(&e.task_id).copied() {
                        anomalies.push(ChallengeTreasuryAnomaly {
                            event_type: e.event_type.clone(),
                            task_id: e.task_id,
                            tx_id: e.tx_id,
                            code: "duplicate_open_challenge".to_string(),
                            detail: format!(
                                "challenge ignored because task already has unresolved posted bond {}",
                                existing_bond
                            ),
                        });
                        bond_amount = 0;
                    } else {
                        posted_by_task.insert(e.task_id, bond_amount);
                        escrow_balance = escrow_balance.saturating_add(bond_amount);
                        escrow_delta = i128::try_from(bond_amount).ok().unwrap_or(i128::MAX);
                        if in_window {
                            summary_posted = summary_posted.saturating_add(1);
                            posted_open_in_window.insert(e.task_id, ());
                        }
                    }
                } else if e.challenger_delta.unwrap_or(0) != 0 {
                    anomalies.push(ChallengeTreasuryAnomaly {
                        event_type: e.event_type.clone(),
                        task_id: e.task_id,
                        tx_id: e.tx_id,
                        code: "invalid_challenge_delta_sign".to_string(),
                        detail: format!(
                            "challenge ignored because challenger_delta must be negative, got {}",
                            e.challenger_delta.unwrap_or(0)
                        ),
                    });
                }
            }
            "resolve" | "timeout" => match e.bond_disposition.as_deref() {
                Some("forfeited") => {
                    let maybe_bond = posted_by_task.remove(&e.task_id).unwrap_or(0);
                    bond_amount = maybe_bond;
                    if maybe_bond > 0 {
                        escrow_balance = escrow_balance.saturating_sub(maybe_bond);
                        forfeits_balance = forfeits_balance.saturating_add(maybe_bond);
                        cumulative_forfeited = cumulative_forfeited.saturating_add(maybe_bond);
                        escrow_delta = -i128::try_from(maybe_bond).ok().unwrap_or(i128::MAX);
                        forfeits_delta = maybe_bond;
                        if in_window {
                            summary_forfeited = summary_forfeited.saturating_add(1);
                        }
                    } else {
                        anomalies.push(ChallengeTreasuryAnomaly {
                            event_type: e.event_type.clone(),
                            task_id: e.task_id,
                            tx_id: e.tx_id,
                            code: "resolve_without_posted_bond".to_string(),
                            detail: "forfeited resolve ignored because no prior posted challenge bond found".to_string(),
                        });
                    }
                    posted_open_in_window.remove(&e.task_id);
                }
                Some("refunded") => {
                    let maybe_bond = posted_by_task.remove(&e.task_id).unwrap_or(0);
                    bond_amount = maybe_bond;
                    if maybe_bond > 0 {
                        escrow_balance = escrow_balance.saturating_sub(maybe_bond);
                        escrow_delta = -i128::try_from(maybe_bond).ok().unwrap_or(i128::MAX);
                        if in_window {
                            summary_refunded = summary_refunded.saturating_add(1);
                        }
                    } else {
                        anomalies.push(ChallengeTreasuryAnomaly {
                            event_type: e.event_type.clone(),
                            task_id: e.task_id,
                            tx_id: e.tx_id,
                            code: "resolve_without_posted_bond".to_string(),
                            detail: "refunded resolve ignored because no prior posted challenge bond found".to_string(),
                        });
                    }
                    posted_open_in_window.remove(&e.task_id);
                }
                _ => {}
            },
            _ => {}
        }

        views.push(ChallengeTreasuryEventView {
            event_type: e.event_type.clone(),
            task_id: e.task_id,
            tx_id: e.tx_id,
            block_height: e.block_height,
            ts_unix_ms: e.ts_unix_ms,
            challenger: e.challenger.clone(),
            bond_disposition: e.bond_disposition.clone(),
            bond_amount,
            escrow_delta,
            forfeits_delta,
        });
    }

    let events_total = views.len();
    if views.len() > limit {
        let keep_from = views.len() - limit;
        views = views.split_off(keep_from);
    }

    let daily_summary = summary_window.as_ref().map(|_| ChallengeDailySummary {
        posted: summary_posted,
        refunded: summary_refunded,
        forfeited: summary_forfeited,
        unresolved: posted_open_in_window.len(),
    });

    let window = summary_window.map(|(from, to, mode)| ChallengeWindowView {
        mode,
        from_unix_ms: from,
        to_unix_ms: to,
    });

    ChallengeTreasuryQueryResponse {
        challenge_escrow_account: CHALLENGE_ESCROW_ACCOUNT.to_string(),
        challenge_forfeits_account: CHALLENGE_FORFEIT_TREASURY_ACCOUNT.to_string(),
        current_escrow_balance: escrow_balance,
        current_forfeits_balance: forfeits_balance,
        cumulative_forfeited,
        events_total,
        events: views,
        anomaly_count: anomalies.len(),
        anomalies,
        daily_summary,
        window,
        node_event_source_mode: node_event_source_mode.as_str().to_string(),
        node_event_log_truncated,
    }
}
