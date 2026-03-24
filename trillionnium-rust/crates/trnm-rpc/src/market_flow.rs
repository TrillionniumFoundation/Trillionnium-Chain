use crate::envpaths::{market_bids_file, market_tasks_file};
use crate::market_io::{
    acquire_market_file_lock, load_market_bids, load_market_reputation, load_market_tasks,
    market_worker_tie_break_key, normalize_market_status_key, normalize_market_worker_key,
    save_market_bids, save_market_tasks,
};
use crate::market_score::{
    clamp_reputation_for_market, market_effective_score_with_config, market_score_config,
    MarketScoreConfigOutput,
};
use crate::{MarketBid, MarketTask};
use anyhow::Result;
use serde::Serialize;
use trnm_rpc::RpcErrorResponse;
use crate::rpc_util::rpc_fail;

#[derive(Debug, Clone, Serialize)]
struct MarketReport {
    task_count: usize,
    open_task_count: usize,
    matched_task_count: usize,
    unmatched_task_count: usize,
    bid_count: usize,
    orphan_bid_count: usize,
    unique_bidder_count: usize,
    tasks_with_bids_count: usize,
    bid_coverage_rate: f64,
    avg_bids_per_task: f64,
    match_rate: f64,
}

pub(crate) fn handle_market_create_task(
    creator: String,
    bounty: u128,
    description: String,
    now_unix_ms: u128,
) -> Result<()> {
    let creator = creator.trim().to_string();

    if creator.is_empty() {
        return Err(rpc_fail(RpcErrorResponse {
            code: "task-creator-invalid",
            message: "market task creator must be non-empty".to_string(),
        }));
    }
    if bounty == 0 {
        return Err(rpc_fail(RpcErrorResponse {
            code: "task-bounty-invalid",
            message: "market task bounty must be greater than zero".to_string(),
        }));
    }

    let task = {
        let tasks_path = market_tasks_file();
        let _lock = acquire_market_file_lock(&tasks_path)?;
        let mut tasks = load_market_tasks();
        let task_id = 20_000 + tasks.len() as u64 + 1;
        let task = MarketTask {
            task_id,
            creator,
            bounty,
            description,
            status: "open".into(),
            created_at_unix_ms: now_unix_ms,
        };
        tasks.push(task.clone());
        save_market_tasks(&tasks)?;
        task
    };
    println!("{}", serde_json::to_string_pretty(&task)?);
    Ok(())
}

pub(crate) fn handle_market_submit_bid(
    task_id: u64,
    worker: String,
    price: u128,
    now_unix_ms: u128,
) -> Result<()> {
    if worker.trim().is_empty() {
        return Err(rpc_fail(RpcErrorResponse {
            code: "worker-id-invalid",
            message: format!("market bid worker must be non-empty for task {}", task_id),
        }));
    }
    if price == 0 {
        return Err(rpc_fail(RpcErrorResponse {
            code: "bid-price-invalid",
            message: format!(
                "market bid price must be greater than zero for task {}",
                task_id
            ),
        }));
    }
    let normalized_worker = normalize_market_worker_key(&worker).expect("worker checked non-empty");
    let bid = {
        let tasks_path = market_tasks_file();
        let _tasks_lock = acquire_market_file_lock(&tasks_path)?;
        let tasks = load_market_tasks();
        let Some(task) = tasks.iter().find(|t| t.task_id == task_id) else {
            return Err(rpc_fail(RpcErrorResponse {
                code: "task-not-found",
                message: format!("market task not found: {}", task_id),
            }));
        };
        if normalize_market_status_key(&task.status) != "open" {
            return Err(rpc_fail(RpcErrorResponse {
                code: "task-not-open",
                message: format!("market task not in open status: {}", task.status),
            }));
        }
        if price > task.bounty {
            return Err(rpc_fail(RpcErrorResponse {
                code: "bid-above-bounty",
                message: format!(
                    "market bid price {} exceeds task bounty {} for task {}",
                    price, task.bounty, task_id
                ),
            }));
        }

        let bids_path = market_bids_file();
        let _bids_lock = acquire_market_file_lock(&bids_path)?;
        let mut bids = load_market_bids();
        if bids.iter().any(|b| {
            b.task_id == task_id
                && normalize_market_worker_key(&b.worker)
                    .map(|existing| existing == normalized_worker)
                    .unwrap_or(false)
        }) {
            return Err(rpc_fail(RpcErrorResponse {
                code: "duplicate-bid",
                message: format!("worker {} already has a bid for task {}", worker, task_id),
            }));
        }
        let bid = MarketBid {
            task_id,
            worker,
            price,
            created_at_unix_ms: now_unix_ms,
        };
        bids.push(bid.clone());
        save_market_bids(&bids)?;
        bid
    };
    println!("{}", serde_json::to_string_pretty(&bid)?);
    Ok(())
}

pub(crate) fn handle_market_match_task(task_id: u64) -> Result<()> {
    let tasks_path = market_tasks_file();
    let _tasks_lock = acquire_market_file_lock(&tasks_path)?;
    let bids_path = market_bids_file();
    let _bids_lock = acquire_market_file_lock(&bids_path)?;
    let mut tasks = load_market_tasks();
    let Some(task) = tasks.iter_mut().find(|t| t.task_id == task_id) else {
        return Err(rpc_fail(RpcErrorResponse {
            code: "task-not-found",
            message: format!("market task not found: {}", task_id),
        }));
    };
    if normalize_market_status_key(&task.status) != "open" {
        return Err(rpc_fail(RpcErrorResponse {
            code: "task-not-open",
            message: format!("market task not in open status: {}", task.status),
        }));
    }

    let bids = load_market_bids();
    let task_bids: Vec<&MarketBid> = bids.iter().filter(|b| b.task_id == task_id).collect();

    if task_bids.is_empty() {
        return Err(rpc_fail(RpcErrorResponse {
            code: "no-bids",
            message: format!("no bids found for task: {}", task_id),
        }));
    }

    let reputation = load_market_reputation();
    let score_cfg = market_score_config();
    let matched_bid_count = task_bids.len();
    let winner = task_bids
        .into_iter()
        .min_by_key(|b| {
            let rep = normalize_market_worker_key(&b.worker)
                .and_then(|k| reputation.get(&k).copied())
                .unwrap_or(0);
            let worker_key = market_worker_tie_break_key(&b.worker);
            (
                market_effective_score_with_config(b.price, rep, score_cfg),
                b.price,
                b.created_at_unix_ms,
                worker_key,
            )
        })
        .expect("non-empty bids");
    let winner_reputation = normalize_market_worker_key(&winner.worker)
        .and_then(|k| reputation.get(&k).copied())
        .unwrap_or(0);
    let winner_reputation_effective = clamp_reputation_for_market(winner_reputation, score_cfg);
    let base_score = winner.price.saturating_mul(score_cfg.price_weight);
    let reputation_weight = if winner_reputation_effective > 0 {
        (winner_reputation_effective as u128).saturating_mul(score_cfg.reputation_weight)
    } else {
        0
    };
    let penalty = if winner_reputation_effective < 0 {
        (winner_reputation_effective.unsigned_abs() as u128)
            .saturating_mul(score_cfg.reputation_weight)
    } else {
        0
    };
    let reputation_score_delta = if winner_reputation_effective >= 0 {
        -(reputation_weight as i128)
    } else {
        penalty as i128
    };
    let winner_score = if winner_reputation_effective >= 0 {
        base_score.saturating_sub(reputation_weight)
    } else {
        base_score.saturating_add(penalty)
    };

    task.status = "matched".into();
    save_market_tasks(&tasks)?;

    let out = serde_json::json!({
        "task_id": task_id,
        "winner": winner.worker,
        "price": winner.price,
        "status": "matched",
        "match_policy": "price_reputation_weighted",
        "matched_bid_count": matched_bid_count,
        "winner_reputation": winner_reputation,
        "winner_reputation_effective": winner_reputation_effective,
        "base_score": base_score,
        "reputation_weight": reputation_weight,
        "penalty": penalty,
        "reputation_score_delta": reputation_score_delta,
        "final_score": winner_score,
        "effective_score": winner_score,
        "match_config": MarketScoreConfigOutput::from(score_cfg),
    });
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}

pub(crate) fn handle_market_report() -> Result<()> {
    let tasks = load_market_tasks();
    let bids = load_market_bids();
    let task_count = tasks.len();
    let open_task_count = tasks
        .iter()
        .filter(|t| normalize_market_status_key(&t.status) == "open")
        .count();
    let matched_task_count = tasks
        .iter()
        .filter(|t| normalize_market_status_key(&t.status) == "matched")
        .count();
    let bid_count = bids.len();
    let unmatched_task_count = task_count.saturating_sub(matched_task_count);

    let unique_bidder_count = bids
        .iter()
        .filter_map(|b| normalize_market_worker_key(&b.worker))
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let known_task_ids = tasks
        .iter()
        .map(|t| t.task_id)
        .collect::<std::collections::BTreeSet<_>>();
    let tasks_with_bids_count = bids
        .iter()
        .filter_map(|b| normalize_market_worker_key(&b.worker).map(|_| b.task_id))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .filter(|task_id| known_task_ids.contains(task_id))
        .count();
    let orphan_bid_count = bids.iter().filter(|b| !known_task_ids.contains(&b.task_id)).count();
    let bid_coverage_rate = if task_count == 0 {
        0.0
    } else {
        tasks_with_bids_count as f64 / task_count as f64
    };
    let avg_bids_per_task = if task_count == 0 {
        0.0
    } else {
        bid_count as f64 / task_count as f64
    };
    let match_rate = if task_count == 0 {
        0.0
    } else {
        matched_task_count as f64 / task_count as f64
    };

    let out = MarketReport {
        task_count,
        open_task_count,
        matched_task_count,
        unmatched_task_count,
        bid_count,
        orphan_bid_count,
        unique_bidder_count,
        tasks_with_bids_count,
        bid_coverage_rate,
        avg_bids_per_task,
        match_rate,
    };
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}
