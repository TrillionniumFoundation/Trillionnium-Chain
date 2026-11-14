//! Separate native observation for never-replayed false statements. The original
//! four-second/six-depth service target is not weakened by this diagnostic.
use super::*;
use std::collections::BTreeSet;

const FIRST_FRESH_NONCE: u64 = 200_000;

fn fresh_builder(settings: &Settings, target: Hash) -> ConfirmationAttackBuilder {
    let settings = settings.clone();
    let (a, b) = maintenance();
    let task = pon_work::task_id(&a, &b).unwrap();
    Arc::new(move |worker, attempt| {
        assert!(worker < PRESSURE_WORKERS && attempt < PRESSURE_CALLS_PER_WORKER);
        let index = attempt * PRESSURE_WORKERS + worker;
        let header = genesis_header(
            &settings,
            target,
            FIRST_FRESH_NONCE + u64::try_from(index).unwrap(),
            task,
        );
        // Each request pays new task validation, allocation and all ticket
        // misses. No valid trace/product or verifier result enters this search.
        let mut searched = search_from_zero(header, &a, &b, SEARCH_BUDGET);
        let wire = searched
            .observation
            .as_object_mut()
            .unwrap()
            .remove("packet")
            .unwrap();
        let wire = wire.as_str().map(str::to_owned);
        // The exact header and every trace/ticket trial already reconstruct the
        // packet using the public maintenance task and zero claimed product.
        // Retain a complete-packet digest without copying every 98 KiB string
        // into the observation again. This extra encoding/hash is included in
        // the enclosing joined attacker-thread CPU, not the nested search CPU.
        searched.observation["packet_digest"] = json!(searched.packet.as_ref().map(|packet| {
            hex::encode(hash(
                b"fresh-challenge-attack-packet-v1",
                &[&packet.encode().unwrap()],
            ))
        }));
        searched.observation["packet_reconstruction"] = json!(
            "retained PNH1 header, current maintenance A/B, zero C, winner trace; complete canonical Packet with no transactions"
        );
        (index, wire, Some(searched.observation))
    })
}

fn construction_coverage(phase: &Value, settings: &Settings, target: Hash) -> Value {
    let mut challenges = BTreeSet::new();
    let mut indices = BTreeSet::new();
    let mut all_bound = true;
    let mut all_cpu_known = true;
    let mut total_search_cpu_ns = Some(0_u64);
    let mut constructed = 0;
    let mut exhausted = 0;
    let mut submitted = 0;
    let mut transcript_rejections = 0;
    let (a, b) = maintenance();
    let task = pon_work::task_id(&a, &b).unwrap();
    for worker in phase["attacks"].as_array().unwrap() {
        for row in worker["calls"].as_array().unwrap() {
            constructed += 1;
            let construction = &row["from_zero_construction"];
            let header =
                Header::decode(&hex::decode(construction["header"].as_str().unwrap()).unwrap())
                    .unwrap();
            let index = row["packet_index"].as_u64().unwrap();
            all_bound &= header.network == settings.network()
                && header.parameters == settings.parameters()
                && header.parent == settings.genesis()
                && header.target == target
                && header.work_task == task
                && header.height == 1
                && header.nonce == FIRST_FRESH_NONCE + index
                && construction["challenge"] == hex::encode(header.challenge());
            all_bound &= indices.insert(index) && challenges.insert(header.challenge());
            all_cpu_known &= [
                "attacker_cpu_ns",
                "setup_cpu_ns",
                "search_cpu_ns",
                "packet_encoding_cpu_ns",
            ]
            .iter()
            .all(|key| construction[key].as_u64().is_some());
            total_search_cpu_ns = total_search_cpu_ns
                .zip(construction["attacker_cpu_ns"].as_u64())
                .and_then(|(total, value)| total.checked_add(value));
            if construction["status"] == "exhausted" {
                exhausted += 1;
                all_bound &= row["status"] == "not_submitted_exhausted";
            } else {
                submitted += 1;
                transcript_rejections += usize::from(
                    row["status"] == "refused"
                        && row["response"]["value"]["error"] == "WORK:Transcript",
                );
                all_bound &= construction["status"] == "target_hit_unverified"
                    && construction["packet_digest"].as_str().is_some()
                    && row["status"] != "not_submitted_exhausted";
            }
        }
    }
    json!({
        "constructed": constructed, "unique_challenges": challenges.len(),
        "unique_packet_indices": indices.len(), "submitted": submitted, "exhausted": exhausted,
        "full_transcript_rejections": transcript_rejections,
        "all_context_bindings_and_challenges_unique": all_bound,
        "all_nested_cpu_measurements_known": all_cpu_known,
        "nested_from_zero_construction_cpu_ns": total_search_cpu_ns,
        "accounting_scope": "construction intervals are nested in joined attacker worker CPU; never add them twice; shared public material setup is separate",
    })
}

// Read only the completed traffic observations. Missing observations mean
// unknown, not a disabled cache; this adds no work or time to either phase.
fn observed_negative_cache_enabled(phases: [&Value; 2]) -> Option<bool> {
    for phase in phases {
        let records = phase.get("observations")?.get("records")?.as_array()?;
        let mut observed = false;
        for record in records {
            if record.get("full_work_started")?.as_bool()? {
                let cache = record.get("work_rejection")?;
                if cache.get("schema")?.as_str()? != "public-v3-work-rejection-observation-v1" {
                    return None;
                }
                observed = true;
            }
        }
        if !observed {
            return None;
        }
    }
    Some(true)
}

#[test]
#[ignore = "explicit native four-second/16-worker business acceptance; retains failures and asserts the actual six-depth target"]
fn fresh_challenge_signed_confirmation_keeps_original_pressure_budget() {
    let temporary = tempfile::tempdir().unwrap();
    let path = std::env::var_os("TRNM_PUBLIC_V3_FRESH_CONFIRMATION_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| temporary.path().join("fresh-confirmation"));
    fs::create_dir(&path).unwrap();
    let settings = Settings::development(Some(1_750_000_000)).unwrap();
    let mut producer = Node::open(&path.join("producer"), settings.clone(), 1).unwrap();
    let target = producer.expected_target(settings.genesis()).unwrap();
    let setup_started = Instant::now();
    let setup_cpu = ThreadCpuStamp::start();
    let builder = fresh_builder(&settings, target);
    let shared_material_setup_cpu_ns = cpu_elapsed(setup_cpu);
    let shared_material_setup_wall_ns = ns(setup_started);

    let tx = confirmation_transfer(
        &settings,
        producer.next_nonce(development_public(0).unwrap()).unwrap(),
    );
    let honest_started = Instant::now();
    let honest_process_cpu_started = process_cpu_ns();
    let mut packets = Vec::new();
    for height in 1..=7 {
        packets.push(
            producer
                .mine(
                    if height == 1 {
                        vec![tx.clone()]
                    } else {
                        vec![]
                    },
                    settings.genesis_time() + height * 10,
                    ingress::now().unwrap(),
                )
                .unwrap(),
        );
    }
    let honest_chain_acquisition_wall_ns = ns(honest_started);
    let honest_chain_process_cpu_ns = honest_process_cpu_started
        .zip(process_cpu_ns())
        .and_then(|(start, end)| end.checked_sub(start));
    let baseline = signed_confirmation_phase_with_builder(
        &path.join("baseline"),
        &settings,
        &packets,
        builder.clone(),
        false,
    );
    let mut pressure = signed_confirmation_phase_with_builder(
        &path.join("pressure"),
        &settings,
        &packets,
        builder,
        true,
    );
    // Override the old replay-stream description only for this new namespace.
    pressure["attacker_workers_cpu_scope"] = json!(
        "disjoint joined threads; fresh per-call setup, every failed/successful false-ticket trial, construction records, packet digest, negotiation, resource tickets and network I/O; shared public material setup recorded separately"
    );
    let coverage = construction_coverage(&pressure, &settings, target);
    let attacker_setup_and_workers_cpu_ns = shared_material_setup_cpu_ns
        .zip(pressure["attacker_workers_cpu_ns"].as_u64())
        .and_then(|(setup, workers)| setup.checked_add(workers));
    let construction_valid = coverage["constructed"].as_u64().unwrap() > 0
        && coverage["full_transcript_rejections"].as_u64().unwrap() > 0
        && coverage["all_context_bindings_and_challenges_unique"] == true
        && coverage["all_nested_cpu_measurements_known"] == true
        && shared_material_setup_cpu_ns.is_some();
    let passed = construction_valid
        && baseline["invariant_target_met"] == true
        && baseline["finite_business_target_met"] == true
        && pressure["invariant_target_met"] == true
        && pressure["finite_business_target_met"] == true;
    let negative_cache_enabled = observed_negative_cache_enabled([&baseline, &pressure]);
    let report = json!({
        "schema": "public-v3-fresh-challenge-confirmation-pressure-v1",
        "network": hex::encode(settings.network()), "parameters": hex::encode(settings.parameters()),
        "genesis": hex::encode(settings.genesis()), "target": hex::encode(target),
        "task": hex::encode(packets[0].header.work_task),
        "policy_id": hex::encode(policy().id()), "requested_window_ns": PRESSURE_MS * 1_000_000,
        "attack_workers": PRESSURE_WORKERS, "per_worker_attempt_cap": PRESSURE_CALLS_PER_WORKER,
        "shared_material_setup_cpu_ns": shared_material_setup_cpu_ns,
        "shared_material_setup_wall_ns": shared_material_setup_wall_ns,
        "attacker_setup_and_workers_cpu_ns": attacker_setup_and_workers_cpu_ns,
        "honest_chain_acquisition_wall_ns": honest_chain_acquisition_wall_ns,
        "honest_chain_process_cpu_ns": honest_chain_process_cpu_ns,
        "honest_chain_process_cpu_scope": "entire process during seven-block acquisition before service; not isolated W1 or exclusive producer CPU",
        "signed_honest_packets": packets.iter().map(|packet| hex::encode(packet.encode().unwrap())).collect::<Vec<_>>(),
        "construction_coverage": coverage, "phases": [baseline, pressure],
        "same_signed_business_packets": true, "negative_cache_enabled": negative_cache_enabled,
        "negative_cache_observation_source": "actual-request-work-rejection-observations-v1",
        "finite_target_met": passed,
        "scope": "explicit diagnostic with actual business assertion; separate from unchanged retained-packet original gate; one host/operator, no WAN fairness or cheapest-work claim",
        "public_network_ready": false, "work_profile_qualified": false,
        "resource_fairness_qualified": false, "production_activation": false,
    });
    fs::write(
        path.join("report.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!(
        "{}",
        json!({"schema": report["schema"], "finite_target_met": passed, "report_path": path.join("report.json")})
    );
    assert!(passed, "fresh challenges failed the original four-second/six-depth business target; retain report.json, no post-window success credit");
}
