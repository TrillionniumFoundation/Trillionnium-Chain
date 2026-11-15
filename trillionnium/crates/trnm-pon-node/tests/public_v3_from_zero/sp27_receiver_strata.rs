//! Separate SP27-02 stage controls. The historical pair/helper is unchanged.
//! The business path is copied from its exact native helper and retains its
//! original deadline and final gate. Only this new control's arrival plan and
//! legal-input acceptance classification differ, as recorded in every report.
use super::sp27_receiver_controls::write_new_json;
use super::*;

fn request_identity(wire: &str) -> Value {
    let bytes = serde_json::to_vec(&Request::Submit {
        packet: wire.to_owned(),
    })
    .unwrap();
    json!({"packet_hex": wire, "request_bytes": bytes.len(),
        "body_digest": hex::encode(hash(b"public-request-body-v3", &[&bytes])),
        "recorded_request_digest": hex::encode(hash(b"pressure-recorded-request-v1", &[&bytes]))})
}

pub(super) fn prepare_strata_inputs(
    path: &std::path::Path,
    settings: &Settings,
) -> (Vec<Arc<Vec<String>>>, Value) {
    fs::create_dir(path).unwrap();
    let start = Instant::now();
    let cpu = process_cpu_ns();
    let (a, b) = maintenance();
    let task = pon_work::task_id(&a, &b).unwrap();
    let reference = Node::open(&path.join("context"), settings.clone(), 1).unwrap();
    let target = reference.expected_target(settings.genesis()).unwrap();
    drop(reference);
    let mut arms: Vec<Vec<String>> = vec![Vec::new(), Vec::new(), Vec::new(), Vec::new()];
    let mut negative_history = Vec::new();
    for worker in 0..PRESSURE_WORKERS {
        let search = search_from_zero(
            genesis_header(settings, target, 700_000 + worker as u64, task),
            &a,
            &b,
            SEARCH_BUDGET,
        );
        // Preserve even an exhausted construction before deciding eligibility.
        write_new_json(
            &path.join(format!("negative-{worker:03}.json")),
            &search.observation,
        )
        .unwrap();
        negative_history.push(search.observation);
        let packet = search.packet.expect("SP27_NEGATIVE_CONSTRUCTION_EXHAUSTED");
        let late = packet.encode().unwrap();
        assert_eq!(&late[..4], b"PNH1");
        let mut transport = late.clone();
        transport[0] ^= 1;
        let mut early = packet.clone();
        let old = u32::from_le_bytes(early.proof[4..8].try_into().unwrap());
        let new = ((u128::from(old) + 1) % pon_work::Q) as u32;
        early.proof[4..8].copy_from_slice(&new.to_le_bytes());
        arms[0].push(hex::encode(transport));
        arms[1].push(hex::encode(early.encode().unwrap()));
        arms[2].push(hex::encode(late));
    }
    let negative_preparation_ended_ns = ns(start);
    let negative_preparation_process_cpu_ns = cpu
        .zip(process_cpu_ns())
        .and_then(|(a, b)| b.checked_sub(a));
    let mut valid_history = Vec::new();
    for worker in 0..PRESSURE_WORKERS {
        write_new_json(
            &path.join(format!("valid-{worker:03}-started.json")),
            &json!({"worker": worker, "status": "STARTED_NOT_YET_OBSERVED_COMPLETE"}),
        )
        .unwrap();
        let begin = Instant::now();
        let before = process_cpu_ns();
        let mut producer = Node::open(
            &path.join(format!("valid-producer-{worker:03}")),
            settings.clone(),
            1,
        )
        .unwrap();
        let packet = producer
            .mine(
                vec![],
                settings.genesis_time() + 1 + worker as u64,
                ingress::now().unwrap(),
            )
            .unwrap();
        assert_eq!(packet.header.parent, settings.genesis());
        assert_eq!(packet.header.height, 1);
        assert_eq!(packet.header.work_task, task);
        assert_eq!(packet.header.target, target);
        assert!(packet.transactions.is_empty());
        let wire = hex::encode(packet.encode().unwrap());
        let observation = json!({"worker": worker, "producer_mine_returned": true,
            "packet": wire, "packet_id": hex::encode(packet.id().unwrap()),
            "generation_wall_ns": ns(begin),
            "generation_process_cpu_ns": before.zip(process_cpu_ns()).and_then(|(a,b)| b.checked_sub(a)),
            "cost_scope": "fresh producer open, all mine attempts, execution, storage and packet encoding; enclosing process CPU, not a pure prover clock"});
        write_new_json(&path.join(format!("valid-{worker:03}.json")), &observation).unwrap();
        valid_history.push(observation);
        arms[3].push(wire);
    }
    let bytes = serde_json::to_vec(&Request::Submit {
        packet: arms[0][0].clone(),
    })
    .unwrap()
    .len();
    for wires in &arms {
        assert_eq!(wires.len(), PRESSURE_WORKERS);
        let mut identities = std::collections::BTreeSet::new();
        for wire in wires {
            let identity = request_identity(wire);
            assert_eq!(identity["request_bytes"].as_u64(), Some(bytes as u64));
            assert!(identities.insert(identity["body_digest"].as_str().unwrap().to_owned()));
        }
    }
    let complete_process_cpu_ns = cpu
        .zip(process_cpu_ns())
        .and_then(|(a, b)| b.checked_sub(a));
    let observation = json!({"schema": "sp27-strata-input-acquisition-v1",
        "arms": ["transport", "early-reject", "late-reject", "valid-expensive"],
        "workers_per_arm": PRESSURE_WORKERS, "calls_per_worker": 1,
        "canonical_submit_body_bytes_each": bytes,
        "negative_construction": negative_history, "valid_generation": valid_history,
        "inputs": arms.iter().map(|wires| wires.iter().map(|s| request_identity(s)).collect::<Vec<_>>()).collect::<Vec<_>>(),
        "negative_preparation_wall_ns": negative_preparation_ended_ns,
        "negative_preparation_process_cpu_ns": negative_preparation_process_cpu_ns,
        "complete_acquisition_wall_ns": ns(start), "complete_acquisition_process_cpu_ns": complete_process_cpu_ns,
        "nested_cost_intervals_are_not_additive": true,
        "cost_scope": "all process threads from public context setup through negative construction, valid producer histories, encoding and raw writes; output Value serialization occurs after the measured interval",
        "valid_expensive_is_not_a_pure_W1_intervention": true,
        "input_legality": ["valid paid Submit wrapper; invalid first PNH1 codec byte",
            "valid codec; same late header/challenge/target/ticket, one canonical A element changes task ID",
            "from-zero target-hit false transcript; original native verifier must actually reject after replay",
            "native mine-returned valid empty genesis siblings; may activate competing state and require explicit final-state control"]});
    (arms.into_iter().map(Arc::new).collect(), observation)
}

fn stage<'a>(record: &'a Value, name: &str) -> Option<&'a Value> {
    record["submit_phases"]
        .as_array()?
        .iter()
        .find(|row| row["phase"] == name)
}
fn accepted(record: &Value, name: &str) -> bool {
    stage(record, name).is_some_and(|row| {
        row["started"] == true && row["completed"] == true && row["accepted"] == true
    })
}
fn unstarted(record: &Value, name: &str) -> bool {
    stage(record, name).is_some_and(|row| row["started"] == false)
}
fn refused(record: &Value, name: &str) -> bool {
    stage(record, name).is_some_and(|row| {
        row["started"] == true && row["completed"] == true && row["accepted"] == false
    })
}
fn message(record: &Value, expected: &str) -> bool {
    record["error_diagnostics"]["dispatch"]["message_prefix"] == expected
        && record["error_diagnostics"]["dispatch"]["message_truncated"] == false
}

fn stage_readback(report: &Value, wires: &[String], arm: &str) -> Value {
    let identities = wires
        .iter()
        .map(|s| request_identity(s))
        .collect::<Vec<_>>();
    let mut matched = Vec::new();
    let mut attained = 0;
    let mut unexpected = false;
    for record in report["observations"]["records"].as_array().unwrap() {
        let digest = serde_json::from_value::<Option<Hash>>(record["body_digest"].clone())
            .ok()
            .flatten()
            .map(hex::encode);
        let index = digest
            .as_ref()
            .and_then(|d| identities.iter().position(|v| v["body_digest"] == *d));
        let Some(index) = index else {
            continue;
        };
        let cache = &record["work_rejection"]["cache"];
        let full = record["work_rejection"]["completed"] == true
            && cache["native_verifier_started"] == true
            && cache["native_verifier_returned"] == true
            && cache["full_replay_started"] == true
            && cache["cached_rejection_returned"] == false;
        let body_checked = accepted(record, "body_decode");
        let reached = body_checked
            && match arm {
                "transport" => {
                    refused(record, "decode")
                        && stage(record, "decode").unwrap()["error_code"] == "HEADER_CODEC"
                        && unstarted(record, "context")
                        && unstarted(record, "work")
                }
                "early-reject" => {
                    accepted(record, "decode")
                        && refused(record, "context")
                        && unstarted(record, "work")
                        && record["full_work_started"] == false
                        && message(record, "WORK:Task")
                }
                "late-reject" => {
                    accepted(record, "context")
                        && refused(record, "work")
                        && full
                        && message(record, "WORK:Transcript")
                }
                "valid-expensive" => {
                    accepted(record, "work")
                        && full
                        && record["full_work_accepted"] == true
                        && record["dispatch_accepted"] == true
                        && accepted(record, "submit_result")
                }
                _ => false,
            };
        if reached {
            attained += 1;
        }
        unexpected |= arm != "valid-expensive" && record["dispatch_accepted"] == true;
        unexpected |=
            matches!(arm, "transport" | "early-reject") && record["full_work_started"] == true;
        matched.push(json!({"packet_index": index, "connection_id": record["connection_id"],
            "body_digest": digest, "actual_body_checked": body_checked, "target_stage_attained": reached,
            "full_native_replay_observed": full, "dispatch_accepted": record["dispatch_accepted"],
            "lifecycle": record["lifecycle"], "paid_task_queue_wait": record["paid_task_queue_wait"],
            "work_rejection": record["work_rejection"], "submit_phases": record["submit_phases"],
            "terminal_phase": record["terminal_phase"], "terminal_error_code": record["terminal_error_code"]}));
    }
    let offered = report["attacks"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|w| w["calls"].as_array().unwrap())
        .filter(|row| row["started_ns"].as_u64().is_some())
        .count();
    json!({"schema": "sp27-native-stage-readback-v1", "arm": arm,
        "planned_offerings": 16, "actual_calls_started": offered,
        "matched_claimed_body_connections": matched.len(), "target_stage_attained": attained,
        "input_stage_identifiable": offered == 16 && attained > 0,
        "unexpected_stage_or_acceptance": unexpected, "matched_records": matched,
        "unknown_and_unmatched_connections_retained_in_original_observations": true,
        "at_least_one_stage_witness_is_not_equal_arrival_or_cpu_exposure": true,
        "body_identity_is_claimed_until_body_decode_accepts": true,
        "no_latency_or_causal_estimate_is_inferred_by_this_classifier": true})
}

pub(super) fn strata_phase(
    path: &std::path::Path,
    settings: &Settings,
    packets: &[Packet],
    wires: Arc<Vec<String>>,
    arm: &str,
) -> Value {
    assert_eq!(wires.len(), PRESSURE_WORKERS);
    fs::create_dir(path).unwrap();
    let mut verifier = Node::open(&path.join("independent-client"), settings.clone(), 1).unwrap();
    let mut receiver = Node::open(&path.join("receiver"), settings.clone(), 1).unwrap();
    receiver
        .enable_local_mempool(PoolLimits {
            max_records: 16,
            max_bytes: 32768,
            max_group_members: 4,
            critical_reserve: 0,
            max_removals: 64,
            preview_miner: development_public(0).unwrap(),
        })
        .unwrap();
    let initial = receiver.read_active().unwrap();
    let target = receiver.expected_target(settings.genesis()).unwrap();
    let owner = Arc::new(Mutex::new(receiver));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let metrics = Arc::new(Mutex::new(public_v3::PublicMetrics::default()));
    let observer = public_v3::PublicRequestObserver::new(16_384).unwrap();
    let server = PublicServer::new(identity(71), policy()).unwrap();
    let domain = server.mutation_cpu_domain();
    let initial_meter = domain.observe().unwrap();
    let (shared, signal, measurement, capture) =
        (owner.clone(), stop.clone(), metrics, observer.clone());
    let service = RunningService {
        stop,
        worker: Some(thread::spawn(move || {
            match public_v3::serve_public_protected_v3_with_request_observer(
                listener,
                shared,
                Duration::from_secs(30),
                signal,
                server,
                measurement,
                capture,
            ) {
                Ok(metrics) => json!({"metrics": metrics, "error": null}),
                Err(error) => json!({"metrics": null, "error": error.to_string()}),
            }
        })),
    };
    let epoch = Instant::now();
    let client = Client {
        address,
        settings: settings.clone(),
        epoch,
    };
    let workers = PRESSURE_WORKERS;
    let barrier = Arc::new(Barrier::new(workers + 2));
    let completed = Arc::new(AtomicU64::new(0));
    let end = epoch + Duration::from_millis(PRESSURE_MS);
    let mut attacks = Vec::new();
    for worker in 0..workers {
        let (client, barrier, wires, completed) = (
            client.clone(),
            barrier.clone(),
            wires.clone(),
            completed.clone(),
        );
        attacks.push(thread::spawn(move || {
            barrier.wait();
            let cpu = ThreadCpuStamp::start();
            let scheduled = epoch + Duration::from_millis(100);
            thread::sleep(scheduled.saturating_duration_since(Instant::now()));
            let arrival_started_ns = ns(epoch);
            let mut row = if Instant::now() < end {
                let row = compact_pressure_call(
                    client.call_before(
                        "sp27_stratum_load",
                        80 + worker as u8,
                        Request::Submit {
                            packet: wires[worker].clone(),
                        },
                        Some(end),
                    ),
                    Some(worker),
                );
                completed.fetch_add(1, Ordering::AcqRel);
                row
            } else {
                json!({"status": "not_started_original_deadline", "packet_index": worker})
            };
            row["scheduled_start_ns"] = json!(100_000_000_u64);
            row["offering_thread_ready_ns"] = json!(arrival_started_ns);
            row["offering_lateness_ns"] = json!(arrival_started_ns.saturating_sub(100_000_000));
            row["attempt_index"] = json!(0);
            json!({"worker": worker, "planned_attempts": 1,
                "calling_thread_cpu_ns": cpu_elapsed(cpu), "calls": [row]})
        }));
    }
    let (reader, read_barrier) = (client.clone(), barrier.clone());
    let reads = thread::spawn(move || {
        read_barrier.wait();
        let cpu = ThreadCpuStamp::start();
        let mut rows = Vec::new();
        while Instant::now() < end && rows.len() < 256 {
            rows.push(compact_pressure_call(
                reader.call_before("confirmation_honest_head", 72, Request::Head, Some(end)),
                None,
            ));
            thread::sleep(
                Duration::from_millis(40).min(end.saturating_duration_since(Instant::now())),
            );
        }
        (rows, cpu_elapsed(cpu))
    });
    barrier.wait();
    // Business begins independently of pressure completion. All four arms
    // have the same predeclared 100-ms offering slot and no retry feedback.
    let completed_before_business = completed.load(Ordering::Acquire);
    let business_started_ns = ns(epoch);
    let mut submissions = Vec::new();
    let mut next_packet = 0;
    while next_packet < packets.len() && Instant::now() < end && submissions.len() < 64 {
        let mut row = compact_pressure_call(
            client.call_before(
                "confirmation_honest_submit",
                73,
                Request::Submit {
                    packet: hex::encode(packets[next_packet].encode().unwrap()),
                },
                Some(end),
            ),
            Some(next_packet),
        );
        row["height"] = json!(packets[next_packet].header.height);
        if row["status"] == "ok" && row["returned_after_window"] == false {
            next_packet += 1;
        }
        submissions.push(row);
    }
    let tip = packets.last().unwrap().id().unwrap();
    let included = packets[0].id().unwrap();
    let transaction = hash(b"tx-id", &[&packets[0].transactions[0]]);
    let mut history_calls = Vec::new();
    // One actual independent-client replay interval for each successful
    // on-time History response. Failed network calls remain in history_calls.
    let mut independent_history_page_replay = Vec::new();
    let mut independent_final_confirmation_stage = None;
    let mut confirmation = None;
    let mut verification_errors = Vec::new();
    let replay_started = Instant::now();
    let replay_cpu = ThreadCpuStamp::start();
    let mut after = settings.genesis();
    let mut confirmation_ended_ns = None;
    while next_packet == packets.len() && Instant::now() < end && history_calls.len() < 16 {
        let row = client.call_before(
            "confirmation_honest_history",
            74,
            Request::History {
                tip: hex::encode(tip),
                after: hex::encode(after),
            },
            Some(end),
        );
        if row["status"] == "ok" && row["returned_after_window"] == false {
            let replay_started_ns = ns(epoch);
            let page_cpu = ThreadCpuStamp::start();
            let import_observer = ingress::HistoryImportObserver::new();
            let imported =
                serde_json::from_value::<ingress::Page>(row["response"]["value"].clone())
                    .map_err(|error| error.to_string())
                    .and_then(|page| {
                        ingress::receive_public_page_from_before_observed(
                            &mut verifier,
                            client.address,
                            page,
                            tip,
                            after,
                            ingress::now().unwrap(),
                            end,
                            Some(&import_observer),
                        )
                        .map_err(|error| error.to_string())
                    });
            let replay_ended_ns = ns(epoch);
            // Capture the actual calling-thread CPU once. Wall intervals may
            // overlap other threads; these two totals must not be summed.
            let replay_thread_cpu_ns = cpu_elapsed(page_cpu);
            independent_history_page_replay.push(json!({
                "history_call_index": history_calls.len(),
                "history_request_ended_ns": row["ended_ns"].clone(),
                "replay_started_ns": replay_started_ns,
                "replay_ended_ns": replay_ended_ns,
                "replay_wall_ns": replay_ended_ns - replay_started_ns,
                "replay_thread_cpu_ns": replay_thread_cpu_ns,
                "prior_after": hex::encode(after),
                "next_after": imported.as_ref().ok().map(hex::encode),
                "replay_accepted": imported.is_ok(),
                "replay_error": imported.as_ref().err(),
                "native_import_observation": import_observer.snapshot(),
                "clock_scope": "independent verifier caller thread; wall spans all waits, CPU only this thread",
            }));
            match imported {
                Ok(next) => {
                    after = next;
                    if after == tip {
                        let final_started_ns = ns(epoch);
                        let final_cpu = ThreadCpuStamp::start();
                        let observed =
                            verifier.confirmation(transaction, included, ingress::now().unwrap());
                        let final_ended_ns = ns(epoch);
                        independent_final_confirmation_stage = Some(json!({
                            "confirmation_started_ns": final_started_ns,
                            "confirmation_ended_ns": final_ended_ns,
                            "confirmation_wall_ns": final_ended_ns - final_started_ns,
                            "confirmation_thread_cpu_ns": cpu_elapsed(final_cpu),
                            "observation_returned": observed.is_ok(),
                            "clock_scope": "independent verifier caller thread; no consensus/host time claim",
                        }));
                        match observed {
                            Ok(observation) => {
                                confirmation = Some(observation);
                                confirmation_ended_ns = Some(ns(epoch));
                            }
                            Err(error) => verification_errors.push(error.to_string()),
                        }
                    }
                }
                Err(error) => verification_errors.push(error),
            }
        }
        history_calls.push(row);
        if confirmation.is_some() {
            break;
        }
    }
    let independent_replay_cpu_ns = cpu_elapsed(replay_cpu);
    let independent_replay_wall_ns = ns(replay_started);
    let completed_at_confirmation = completed.load(Ordering::Acquire);
    let client_confirmed_in_window = confirmation.as_ref().is_some_and(|observation| {
        observation.confirmed
            && !observation.finalized
            && !observation.execution_authority
            && observation.depth == Some(6)
    }) && Instant::now() < end;
    let attack_rows: Vec<_> = attacks
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    let (read_rows, reader_cpu_ns) = reads.join().unwrap();
    // Shutdown follows the original window. No post-attack replay, retry or drain
    // can turn an unconfirmed business request into a successful observation.
    let service_outcome = service.finish();
    let captured = observer.snapshot();
    let receiver = Arc::try_unwrap(owner).ok().unwrap().into_inner().unwrap();
    let actual = receiver.read_active().unwrap();
    let checked = verifier.read_active().unwrap();
    // Active generations count local publication events; page replay can publish
    // seven complete blocks in one activation and need not share that counter.
    let full_state_equal = actual.0 == checked.0 && actual.2 == checked.2;
    let actual_root = trnm_mvcc_fee::pon_executor::root(&actual.2).unwrap();
    let receiver_matches_valid_honest_prefix = if actual.0 == initial.0 {
        actual.2 == initial.2
    } else {
        packets
            .iter()
            .any(|packet| packet.id().unwrap() == actual.0 && packet.header.state == actual_root)
    };
    let call_rows: Vec<_> = attack_rows
        .iter()
        .flat_map(|worker| worker["calls"].as_array().unwrap())
        .collect();
    let overlap_end = confirmation_ended_ns.unwrap_or(PRESSURE_MS * 1_000_000);
    let overlapping_false_calls = call_rows
        .iter()
        .filter(|row| {
            row["started_ns"]
                .as_u64()
                .is_some_and(|started| started < overlap_end)
                && row["ended_ns"]
                    .as_u64()
                    .is_some_and(|finished| finished > business_started_ns)
        })
        .count();
    let no_attack_accepted = call_rows.iter().all(|row| row["status"] != "ok");
    let attacker_workers_cpu_ns = attack_rows.iter().try_fold(0u64, |sum, worker| {
        sum.checked_add(worker["calling_thread_cpu_ns"].as_u64()?)
    });
    let read_successes = read_rows
        .iter()
        .filter(|row| {
            row["status"] == "ok"
                && row["returned_after_deadline"] == false
                && row["returned_after_window"] == false
        })
        .count();
    let mut prior_success = 0;
    let mut maximum_honest_head_gap_ns = 0;
    for row in &read_rows {
        if row["status"] == "ok" && row["returned_after_window"] == false {
            let ended = row["ended_ns"].as_u64().unwrap();
            maximum_honest_head_gap_ns = maximum_honest_head_gap_ns.max(ended - prior_success);
            prior_success = ended;
        }
    }
    maximum_honest_head_gap_ns = maximum_honest_head_gap_ns
        .max(PRESSURE_MS * 1_000_000 - prior_success.min(PRESSURE_MS * 1_000_000));
    let m = &service_outcome["metrics"];
    let accounting_closed = m["mutation_cpu_charged_ns"]
        .as_u64()
        .zip(
            m["mutation_full_work_cpu_ns"]
                .as_u64()
                .zip(m["mutation_dispatch_excluding_work_cpu_ns"].as_u64()),
        )
        .is_some_and(|(all, (work, rest))| work.checked_add(rest) == Some(all))
        && m["work_started"] == m["work_finished"]
        && m["mutation_cpu_clock_failures"] == 0;
    let observations_complete = captured.coverage_complete();
    let invariant_target_met = (arm == "valid-expensive" || no_attack_accepted)
        && observations_complete
        && accounting_closed
        && service_outcome["error"].is_null()
        && receiver_matches_valid_honest_prefix;
    let overlap_demonstrated = overlapping_false_calls > 0;
    let finite_business_target_met = client_confirmed_in_window && verification_errors.is_empty();
    let mut report = json!({"schema": "sp27-native-stage-control-phase-v1", "mode": arm,
        "target": hex::encode(target), "task": hex::encode(packets[0].header.work_task),
        "initial_tip": hex::encode(initial.0),
        "initial_state_root": hex::encode(trnm_mvcc_fee::pon_executor::root(&initial.2).unwrap()),
        "requested_window_ns": PRESSURE_MS * 1_000_000, "workers": workers,
        "initial_meter": initial_meter, "final_meter": domain.observe().unwrap(),
        "attacks": attack_rows, "completed_false_calls_before_business": completed_before_business,
        "attacker_workers_cpu_ns": attacker_workers_cpu_ns,
        "attacker_workers_cpu_scope": "disjoint joined load-client threads; includes every failed negotiation, resource-ticket search, encoding and output record; excludes receiver and separately recorded complete input acquisition",
        "completed_false_calls_at_confirmation": completed_at_confirmation,
        "overlapping_false_calls": overlapping_false_calls, "overlap_demonstrated": overlap_demonstrated});
    report.as_object_mut().unwrap().extend(json!({
        "honest_submissions": submissions, "honest_history": history_calls,
        "business_started_ns": business_started_ns, "confirmation_ended_ns": confirmation_ended_ns,
        "client_confirmation_latency_ns": confirmation_ended_ns.map(|ended| ended - business_started_ns),
        "independent_client_confirmation": confirmation, "client_confirmed_transactions": usize::from(client_confirmed_in_window),
        "client_confirmed_before_original_window_end": client_confirmed_in_window,
        "independent_replay_and_confirmation_cpu_ns": independent_replay_cpu_ns,
        "independent_replay_and_confirmation_wall_ns": independent_replay_wall_ns,
        "independent_history_page_replay": independent_history_page_replay,
        "independent_final_confirmation_stage": independent_final_confirmation_stage,
        "verification_errors": verification_errors, "honest_heads": read_rows,
        "honest_head_successes_in_window": read_successes, "maximum_honest_head_gap_ns": maximum_honest_head_gap_ns,
        "reader_cpu_ns": reader_cpu_ns, "service": service_outcome, "observations": captured,
        "no_attack_accepted": no_attack_accepted, "accounting_closed": accounting_closed,
        "full_native_state_equal": full_state_equal, "invariant_target_met": invariant_target_met,
        "receiver_matches_valid_honest_prefix": receiver_matches_valid_honest_prefix,
        "finite_business_target_met": finite_business_target_met,
        "scope": "one host; separate native verifying client shares fixed parent; original strict four-second independent business gate; 16 single-attempt calls at a fixed 100-ms offering slot; no confirmation drain credit",
        "public_network_ready": false, "independent_operator_accepted": false,
        "work_profile_qualified": false, "resource_fairness_qualified": false, "production_activation": false})
        .as_object().unwrap().clone());
    // Convert the retained original traffic epoch after the run. No new clock
    // origin, deadline, retry or confirmation drain is introduced. The peer's
    // Hello digest is only a claimed request identity until actual body checks;
    // unknown/pre-Hello or unretained connections must remain in the denominator.
    let traffic_epoch_in_observer_ns = observer.timestamp_ns(epoch);
    let first_business_body = serde_json::to_vec(&Request::Submit {
        packet: hex::encode(packets[0].encode().unwrap()),
    })
    .unwrap();
    report["business_receive_clock"] = json!({
        "schema": "public-v3-business-receive-clock-v1",
        "clock_scope": "same-process-monotonic-observer",
        "traffic_epoch_in_observer_ns": traffic_epoch_in_observer_ns,
        "first_business_packet_body_digest": hex::encode(hash(b"public-request-body-v3", &[&first_business_body])),
        "independent_confirmation_in_observer_ns": traffic_epoch_in_observer_ns
            .zip(confirmation_ended_ns).and_then(|(offset, ended)| offset.checked_add(ended)),
        "request_binding_stage": "hello-claimed-body-digest",
        "has_control_authority": false,
    });
    report["arrival_plan"] = json!({"workers": 16, "attempts_per_worker": 1,
        "scheduled_start_ns": 100_000_000_u64, "retries": 0,
        "business_waits_for_pressure_completion": false,
        "equal_offered_plan_is_not_equal_observed_arrival_or_service_load": true});
    report["stage_readback"] = stage_readback(&report, &wires, arm);
    report["control_integrity_met"] = json!(
        invariant_target_met
            && report["stage_readback"]["input_stage_identifiable"] == true
            && report["stage_readback"]["unexpected_stage_or_acceptance"] == false
    );
    report["validity_control_scope"] = json!(if arm == "valid-expensive" {
        "native-valid empty genesis siblings; includes admission, execution, fork selection and storage, so not a pure verifier-cost intervention; final honest-prefix/state checks retain that confound"
    } else {
        "canonical paid Submit bodies of equal length; transport changes header magic; early changes one canonical A element; late reaches transcript mismatch; actual reached stage required"
    });
    report
}
