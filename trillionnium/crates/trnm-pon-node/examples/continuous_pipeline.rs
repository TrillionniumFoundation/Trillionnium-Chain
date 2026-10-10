//! Real durable producer -> TCP validator -> inclusion -> local client observation.
//! Public readiness and GPU throughput are deliberately not inferred from this campaign.
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_pon_node::{
    development_public,
    ingress::{self, AdmissionPolicy, ConfirmationQuery, Request},
    Node, Result, Settings,
};
use trnm_protocol::pon_wire::{hash, Envelope};

fn bytes_on_disk(path: &std::path::Path) -> std::io::Result<u64> {
    let mut size = 0;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            size += bytes_on_disk(&entry.path())?;
        } else {
            size += entry.metadata()?.len();
        }
    }
    Ok(size)
}
fn quantiles(values: &[u128]) -> Value {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let rank = |p: usize| sorted[(sorted.len() * p).div_ceil(100).saturating_sub(1)];
    json!({"count":sorted.len(),"p50_ns":if sorted.is_empty(){None}else{Some(rank(50))},"p95_ns":if sorted.len()<20{None}else{Some(rank(95))},"p99_ns":if sorted.len()<100{None}else{Some(rank(99))},"tail_rule":"empirical block sample quantiles only;20 samples for p95 resolution,100 for p99; correlation and confidence are not established"})
}
// These count actual completed boundaries, not an inferred executor or network rate.
#[derive(Default, Serialize)]
struct StageCounts {
    input_constructed: usize,
    execution_and_work_completed: usize,
    local_durable_admitted: usize,
    local_active: usize,
    remote_acknowledged: usize,
    remote_membership_verified: usize,
    policy_confirmed: usize,
}

// Remove an obligation only after a complete successful observation. In particular,
// an error must retain earlier deferred work, the failing item and the unread tail.
fn poll_pending<T>(
    pending: &mut Vec<T>,
    mut observe: impl FnMut(&T) -> Result<bool>,
) -> Result<()> {
    let mut index = 0;
    while index < pending.len() {
        if observe(&pending[index])? {
            drop(pending.remove(index));
        } else {
            index += 1;
        }
    }
    Ok(())
}

fn stop_and_join<T>(stop: &AtomicBool, server: thread::JoinHandle<Result<T>>) -> Result<T> {
    stop.store(true, Ordering::Release);
    server.join().map_err(|_| "SERVER_THREAD")?
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 6 {
        return Err("usage: continuous_pipeline NEW_DIRECTORY BLOCKS TX_PER_BLOCK PACE_MS hot|disjoint4|growth legacy|protected".into());
    }
    let directory = PathBuf::from(&args[0]);
    let blocks: usize = args[1].parse().map_err(|_| "BLOCKS")?;
    let batch: usize = args[2].parse().map_err(|_| "BATCH")?;
    let pace: u64 = args[3].parse().map_err(|_| "PACE")?;
    let pattern = args[4].as_str();
    let protected = match args[5].as_str() {
        "legacy" => false,
        "protected" => true,
        _ => return Err("PROFILE".into()),
    };
    if !(1..=4096).contains(&blocks)
        || !(1..=256).contains(&batch)
        || !matches!(pattern, "hot" | "disjoint4" | "growth")
        || pace > 60_000
    {
        return Err("CAMPAIGN_LIMIT".into());
    }
    // A new directory is a concrete run identity. Never reuse a prior database/report.
    fs::create_dir(&directory)?;
    let clock = ingress::now()?;
    let logical = pace < 1000;
    let genesis = if logical {
        clock
            .checked_sub(((blocks + 8) as u64) * 10)
            .ok_or("CLOCK")?
    } else {
        clock - 10
    };
    let settings = Settings::development_with_evaluation_policy(
        Some(genesis),
        "closed-round-all-eligible-min-v1",
    )?;
    let mut producer = Node::open(&directory.join("producer"), settings.clone(), 4)?;
    let validator = Node::open(&directory.join("validator"), settings.clone(), 4)?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = stop.clone();
    let server = thread::spawn(move || {
        let lifetime = Duration::from_secs(((blocks + 8) as u64) * pace / 1000 + 300);
        if protected {
            ingress::serve_protected(
                listener,
                validator,
                lifetime,
                server_stop,
                AdmissionPolicy::development(),
            )
        } else {
            ingress::serve(listener, validator, lifetime, server_stop)
        }
    });
    let call = |request: &Request| {
        if protected {
            ingress::call_protected(address, request, &settings)
        } else {
            ingress::call(address, request)
        }
    };
    let started = Instant::now();
    let mut records = Vec::new();
    let mut stages = StageCounts::default();
    let mut pending: Vec<(usize, Instant, Vec<ConfirmationQuery>)> = Vec::new();
    let mut inclusion_latencies = Vec::new();
    let mut confirmation_latencies = Vec::new();
    let mut last_timestamp = genesis;
    let mut first_intake = None;
    let mut last_inclusion = None;
    let campaign_result = (|| -> Result<()> {
        for index in 0..blocks + 6 {
            let scheduled = started + Duration::from_millis((index as u64) * pace);
            if let Some(delay) = scheduled.checked_duration_since(Instant::now()) {
                thread::sleep(delay);
            }
            let intake = Instant::now();
            let disk_before = bytes_on_disk(&directory)?;
            let ledger_disk_before = bytes_on_disk(&directory.join("producer"))?
                + bytes_on_disk(&directory.join("validator"))?;
            let mut next = BTreeMap::new();
            let mut transactions = Vec::new();
            if index < blocks {
                first_intake.get_or_insert(intake);
                for offset in 0..batch {
                    let sender_index = if pattern == "hot" {
                        0
                    } else {
                        (offset % 4) as u64
                    };
                    let sender = development_public(sender_index)?;
                    // One owner read per sender and block. An eager or_insert argument
                    // rereads the entire authenticated state for every transfer.
                    let nonce = match next.entry(sender_index) {
                        std::collections::btree_map::Entry::Vacant(entry) => {
                            entry.insert(producer.next_nonce(sender)?)
                        }
                        std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                    };
                    let receiver = match pattern {
                        "hot" => hash(b"pipeline-receiver-v1", &[&0u64.to_le_bytes()]),
                        "disjoint4" => {
                            hash(b"pipeline-receiver-v1", &[&sender_index.to_le_bytes()])
                        }
                        _ => hash(
                            b"pipeline-growth-receiver-v1",
                            &[
                                &(index as u64).to_le_bytes(),
                                &(offset as u64).to_le_bytes(),
                            ],
                        ),
                    };
                    let mut payload = receiver.to_vec();
                    payload.extend(1u64.to_le_bytes());
                    let mut tx = Envelope {
                        network: settings.network(),
                        sender,
                        nonce: *nonce,
                        expiry: 10000,
                        fee_limit: 1_000_000,
                        tag: 1,
                        payload,
                        signature: [0; 64],
                    };
                    let seed = hash(b"DEV-ONLY-KEY", &[&sender_index.to_le_bytes()]);
                    let key = signing_key_from_hex(&hex::encode(seed)).map_err(|_| "KEY")?;
                    tx.signature =
                        hex::decode(sign_hex(&key, &tx.signing_digest().map_err(|_| "SIGNING")?))
                            .map_err(|_| "SIGNATURE")?
                            .try_into()
                            .map_err(|_| "SIGNATURE")?;
                    transactions.push(tx.encode().map_err(|_| "ENCODE")?);
                    *nonce += 1;
                }
            }
            stages.input_constructed += transactions.len();
            let constructed = Instant::now();
            let timestamp = if logical {
                genesis + ((index + 1) as u64) * 10
            } else {
                while ingress::now()? <= last_timestamp {
                    thread::sleep(Duration::from_millis(5));
                }
                ingress::now()?
            };
            last_timestamp = timestamp;
            let parent = producer.active()?.0;
            let work_started = Instant::now();
            let packet = producer.make(
                parent,
                transactions,
                development_public(3)?,
                timestamp,
                4096,
            )?;
            stages.execution_and_work_completed += packet.transactions.len();
            let made = Instant::now();
            let id = producer.admit(&packet, ingress::now()?)?;
            stages.local_durable_admitted += packet.transactions.len();
            let checked = Instant::now();
            producer.activate_observed(id, ingress::now()?)?;
            stages.local_active += packet.transactions.len();
            let local_committed = Instant::now();
            let encoded = packet.encode()?;
            fs::write(directory.join(format!("block-{index:04}.bin")), &encoded)?;
            let submitted = Instant::now();
            let response = call(&Request::Submit {
                packet: hex::encode(&encoded),
            })?;
            let included = Instant::now();
            if response["block"] != hex::encode(id) {
                return Err("INCLUSION_RESPONSE".into());
            }
            stages.remote_acknowledged += packet.transactions.len();
            let queries: Vec<_> = packet
                .transactions
                .iter()
                .map(|tx| {
                    Ok(ConfirmationQuery {
                        transaction: hex::encode(
                            Envelope::decode(tx)
                                .map_err(|_| "TRANSACTION")?
                                .id()
                                .map_err(|_| "TRANSACTION_ID")?,
                        ),
                        block: hex::encode(id),
                    })
                })
                .collect::<Result<_>>()?;
            let membership_started = Instant::now();
            let membership = if queries.is_empty() {
                Value::Null
            } else {
                call(&Request::ConfirmMany {
                    queries: queries.clone(),
                })?
            };
            let membership_done = Instant::now();
            if !queries.is_empty() {
                let observations = membership["observations"]
                    .as_array()
                    .ok_or("MEMBERSHIP_FORMAT")?;
                if observations.len() != queries.len()
                    || observations.iter().any(|o| {
                        o["included_height"] != (index + 1) as u64 || o["reorged"] != false
                    })
                    || observations.iter().zip(&queries).any(|(o, q)| {
                        o["transaction"] != q.transaction
                            || o["included_block"] != q.block
                            || o["network"] != hex::encode(settings.network())
                            || o["parameters"] != hex::encode(settings.parameters())
                            || o["genesis"] != hex::encode(settings.genesis())
                    })
                {
                    return Err("MEMBERSHIP".into());
                }
                stages.remote_membership_verified += queries.len();
                inclusion_latencies.push(included.duration_since(intake).as_nanos());
                pending.push((index, intake, queries));
                last_inclusion = Some(included);
            }
            let record = json!({"block":hex::encode(id),"height":index+1,"transaction_count":packet.transactions.len(),"packet_bytes":encoded.len(),"timestamp":timestamp,"attempts":packet.header.nonce+1,"scheduled_lateness_ns":intake.saturating_duration_since(scheduled).as_nanos(),"construct_sign_ns":constructed.duration_since(intake).as_nanos(),"execute_and_mine_ns":made.duration_since(work_started).as_nanos(),"producer_full_verify_and_store_ns":checked.duration_since(made).as_nanos(),"producer_activate_ns":local_committed.duration_since(checked).as_nanos(),"socket_admission_verify_store_activate_ns":included.duration_since(submitted).as_nanos(),"membership_query_ns":membership_done.duration_since(membership_started).as_nanos(),"intake_to_inclusion_ns":included.duration_since(intake).as_nanos(),"disk_bytes_before":disk_before,"disk_bytes_after":bytes_on_disk(&directory)?,"producer_state_keys":producer.stats()?["state_keys"],"initial_membership":membership});
            records.push(record);
            records[index]["ledger_disk_bytes_before"] = json!(ledger_disk_before);
            records[index]["ledger_disk_bytes_after"] = json!(
                bytes_on_disk(&directory.join("producer"))?
                    + bytes_on_disk(&directory.join("validator"))?
            );
            poll_pending(&mut pending, |(record_index, intake, queries)| {
                let confirmation_started = Instant::now();
                let result = call(&Request::ConfirmMany {
                    queries: queries.clone(),
                })?;
                let observed = Instant::now();
                let observations = result["observations"]
                    .as_array()
                    .ok_or("CONFIRMATION_FORMAT")?;
                if observations.len() != queries.len()
                    || observations.iter().zip(queries).any(|(o, q)| {
                        o["transaction"] != q.transaction
                            || o["included_block"] != q.block
                            || o["network"] != hex::encode(settings.network())
                            || o["parameters"] != hex::encode(settings.parameters())
                            || o["genesis"] != hex::encode(settings.genesis())
                            || o["reorged"] != false
                    })
                {
                    return Err("CONFIRMATION_CONTEXT".into());
                }
                if observations.iter().all(|o| {
                    o["confirmed"] == true
                        && o["finalized"] == false
                        && o["execution_authority"] == false
                }) {
                    let latency = observed.duration_since(*intake).as_nanos();
                    confirmation_latencies.push(latency);
                    records[*record_index]["intake_to_confirmation_ns"] = json!(latency);
                    records[*record_index]["confirmation_query_ns"] =
                        json!(observed.duration_since(confirmation_started).as_nanos());
                    records[*record_index]["confirmation"] = result;
                    stages.policy_confirmed += queries.len();
                    Ok(true)
                } else {
                    Ok(false)
                }
            })?;
            fs::write(
                directory.join("progress.json"),
                serde_json::to_vec(
                    &json!({"records":records,"pending_confirmation_blocks":pending.len()}),
                )?,
            )?;
        }
        Ok(())
    })();
    // Readback failure is diagnostic, not permission to detach a running server.
    // Always request stop and join before any fallible final report construction.
    let final_head = call(&Request::Head);
    let producer_final = producer.stats();
    let heads_agree = match (&final_head, &producer_final) {
        (Ok(head), Ok(producer)) => ["tip", "height", "state_root", "chainwork_hex"]
            .iter()
            .all(|key| head[*key] == producer[*key]),
        _ => false,
    };
    let server_result = stop_and_join(&stop, server);
    let close_started = Instant::now();
    drop(producer);
    let producer_close_ns = close_started.elapsed().as_nanos();
    let completed = Instant::now();
    let offered_window = last_inclusion
        .zip(first_intake)
        .map(|(last, first)| last.duration_since(first).as_secs_f64());
    let accepted_transactions = stages.remote_membership_verified;
    let confirmed_transactions = stages.policy_confirmed;
    let inclusion_rate = offered_window
        .filter(|seconds| *seconds > 0.0)
        .map(|seconds| accepted_transactions as f64 / seconds);
    let summary = json!({
        "schema":"trnm-continuous-native-pipeline-v1",
        "scope":"single-host closed-loop durable CPU TCP service workload; local confirmation; no saturation, WAN or public qualification",
        "campaign_passed":campaign_result.is_ok() && pending.is_empty() && heads_agree && server_result.is_ok(),
        "campaign_error":campaign_result.as_ref().err().map(ToString::to_string),
        "logical_pacing":logical,"pace_ms":pace,
        "network":hex::encode(settings.network()),"parameters":hex::encode(settings.parameters()),
        "genesis":hex::encode(settings.genesis()),"genesis_timestamp":settings.genesis_time(),
        "transaction_type":"signed PNX1 transfer tag1 only","pattern":pattern,
        "funded_senders":if pattern=="hot"{1}else{4},"requested_blocks":blocks,"transactions_per_block":batch,
        "accepted_transactions":accepted_transactions,"confirmed_transactions":confirmed_transactions,
        "pending_confirmation_blocks":pending.len(),"inclusion_window_seconds":offered_window,
        "measured_inclusion_transactions_per_second":inclusion_rate,
        "whole_campaign_seconds":completed.duration_since(started).as_secs_f64(),
        "whole_campaign_confirmed_transactions_per_second":confirmed_transactions as f64/completed.duration_since(started).as_secs_f64(),
        "admission_profile":if protected{"connection-work-v1"}else{"legacy-development"},
        "socket_metrics":server_result.as_ref().ok(),"server_error":server_result.as_ref().err().map(ToString::to_string),"inclusion_latency_block_samples":quantiles(&inclusion_latencies),
        "confirmation_latency_block_samples":quantiles(&confirmation_latencies),
        "producer_final_state":producer_final.as_ref().ok(),"producer_final_error":producer_final.as_ref().err().map(ToString::to_string),"validator_final_head":final_head.as_ref().ok(),
        "final_head_error":final_head.as_ref().err().map(ToString::to_string),"producer_validator_heads_agree":heads_agree,
        "disk_bytes":bytes_on_disk(&directory)?,"disk_scope":"complete run directory before summary write, including exported proof/evidence",
        "ledger_disk_bytes":bytes_on_disk(&directory.join("producer"))? + bytes_on_disk(&directory.join("validator"))?,
        "producer_close_ns":producer_close_ns,"gpu_used":false,"gpu_device":null,"vram_bytes":null,
        "gpu_measurement":"no GPU inference/training in this CPU chain workload; model deployment VRAM unmeasured",
        "mempool_latency":null,"mempool_note":"prebuilt block submission; no standalone transaction RPC/mempool",
        "stage_counts":stages,
        "stage_count_scope":"completed local and remote-observation boundaries only; ACK is not membership or confirmation; execution/work are jointly observed, standalone executor completion is unmeasured",
        "application_executed_transactions":null,
        "pending_confirmation_scope":"membership-checked batches; earlier uncertain delivery remains a stage gap, not proof of non-execution",
        "pending_confirmation_record_indices":pending.iter().map(|(index, _, _)| *index).collect::<Vec<_>>(),
        "records":records
    });
    fs::write(
        directory.join("summary.json"),
        serde_json::to_vec_pretty(&summary)?,
    )?;
    println!(
        "{}",
        json!({"report":directory.join("summary.json"),"accepted_transactions":accepted_transactions,"confirmed_transactions":confirmed_transactions,"measured_inclusion_transactions_per_second":inclusion_rate,"public_qualified":false})
    );
    campaign_result?;
    producer_final?;
    server_result?;
    if !heads_agree {
        return Err("PRODUCER_VALIDATOR_HEAD_MISMATCH".into());
    }
    if !pending.is_empty() {
        return Err("UNCONFIRMED_CAMPAIGN".into());
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_poll_retains_deferred_failed_and_unread_obligations() {
        let mut pending = vec![0, 1, 2, 3];
        let mut seen = Vec::new();
        let error = poll_pending(&mut pending, |item| {
            seen.push(*item);
            match item {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err("OBSERVATION_FAILED".into()),
            }
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "OBSERVATION_FAILED");
        assert_eq!(seen, [0, 1, 2]);
        assert_eq!(pending, [0, 2, 3]);
        let mut retry = Vec::new();
        poll_pending(&mut pending, |item| {
            retry.push(*item);
            Ok(true)
        })
        .unwrap();
        assert_eq!(retry, [0, 2, 3]);
        assert!(pending.is_empty());
    }

    #[test]
    fn original_drain_loses_obligations_on_the_same_failure() {
        fn original(pending: &mut Vec<usize>) -> Result<()> {
            let mut remaining = Vec::new();
            for item in pending.drain(..) {
                let complete = match item {
                    0 => false,
                    1 => true,
                    _ => return Err("OBSERVATION_FAILED".into()),
                };
                if !complete {
                    remaining.push(item);
                }
            }
            *pending = remaining;
            Ok(())
        }
        let mut pending = vec![0, 1, 2, 3];
        assert!(original(&mut pending).is_err());
        assert!(pending.is_empty());
        let mut repaired = vec![0, 1, 2, 3];
        assert!(poll_pending(&mut repaired, |item| match item {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err("OBSERVATION_FAILED".into()),
        })
        .is_err());
        assert_eq!(repaired, [0, 2, 3]);
    }

    #[test]
    fn every_failure_cut_preserves_exact_remaining_order() {
        for cut in 0..=16 {
            let mut pending: Vec<usize> = (0..16).collect();
            let result = poll_pending(&mut pending, |item| {
                if *item == cut {
                    Err("CUT".into())
                } else {
                    Ok(item % 2 == 0)
                }
            });
            assert_eq!(result.is_err(), cut < 16);
            let expected: Vec<_> = (0..16)
                .filter(|item| *item >= cut || item % 2 == 1)
                .collect();
            assert_eq!(pending, expected);
        }
        let mut empty: Vec<usize> = Vec::new();
        poll_pending(&mut empty, |_| Err("EMPTY_CALLED".into())).unwrap();
    }

    #[test]
    fn shutdown_joins_before_returning_server_failure() {
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let exited = Arc::new(AtomicBool::new(false));
        let worker_exited = exited.clone();
        let server = thread::spawn(move || -> Result<()> {
            while !worker_stop.load(Ordering::Acquire) {
                thread::yield_now();
            }
            worker_exited.store(true, Ordering::Release);
            Err("SERVER_FAILED".into())
        });
        let error = stop_and_join(&stop, server).unwrap_err();
        assert_eq!(error.to_string(), "SERVER_FAILED");
        assert!(exited.load(Ordering::Acquire));
    }

    #[test]
    fn shutdown_preserves_success_and_reports_panicked_server() {
        let stop = AtomicBool::new(false);
        assert_eq!(stop_and_join(&stop, thread::spawn(|| Ok(7))).unwrap(), 7);
        assert!(stop.load(Ordering::Acquire));
        let server = thread::spawn(|| -> Result<()> { panic!("controlled server panic") });
        assert_eq!(
            stop_and_join(&stop, server).unwrap_err().to_string(),
            "SERVER_THREAD"
        );
    }
}
