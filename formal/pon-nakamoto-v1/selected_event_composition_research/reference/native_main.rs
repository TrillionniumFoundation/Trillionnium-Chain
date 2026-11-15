use selected_event_native_research::*;
use serde_json::{json, Value};
use std::fs::File;
use std::hint::black_box;
use std::io::Read;
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

fn bounded_read(path: &str, size: usize) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|e| format!("read {path}: {e}"))?;
    let mut bytes = Vec::with_capacity(size + 1);
    file.take((size + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    Ok(bytes)
}
fn load_matrix(path: &str) -> Result<MatrixBlocks, String> {
    let bytes = bounded_read(path, 16384)?;
    if bytes.len() != 16384 {
        return Err("MATRIX_LENGTH".into());
    }
    Ok(std::array::from_fn(|i| {
        std::array::from_fn(|j| {
            let offset = i * 256 + j * 4;
            u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("exact matrix"))
        })
    }))
}
fn render_result(result: &Result<VerifiedSelectedEvent, Refusal>) -> Value {
    match result {
        Ok(value) => {
            json!({"status":"ACCEPT_SELECTED_EVENT_ONLY", "context":hex(&value.context), "event_id":hex(&value.event_id), "ticket":hex(&value.ticket), "useful_product":value.useful_product.to_vec()})
        }
        Err(error) => json!({"status":"REJECT", "error":error}),
    }
}
fn process_metadata() -> Value {
    json!({
        "pid":std::process::id(),
        "unix_time_ns":SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(),
        "proc_status":std::fs::read_to_string("/proc/self/status").ok(),
        "proc_stat":std::fs::read_to_string("/proc/self/stat").ok(),
        "cgroup":std::fs::read_to_string("/proc/self/cgroup").ok(),
        "scope":"native exact selected-event v1 only; no STARK or W1 proof"
    })
}
fn positive_number(s: &str, maximum: usize) -> Result<usize, String> {
    let n: usize = s.parse().map_err(|_| "invalid count")?;
    if n == 0 || n > maximum {
        return Err("count outside research harness bound".into());
    }
    Ok(n)
}

fn run(args: &[String]) -> Result<Value, String> {
    let command = args.first().map(String::as_str).ok_or("missing command")?;
    match command {
        "verify" if args.len() == 3 => {
            let total = Instant::now();
            let expected = bounded_read(&args[1], EXPECTED_BYTES)?;
            let witness = bounded_read(&args[2], WITNESS_BYTES)?;
            let mut counts = Counts::default();
            let verification = Instant::now();
            let result = verify_bytes(&expected, &witness, &mut counts);
            let verify_elapsed_ns = verification.elapsed().as_nanos();
            let read_parse_verify_elapsed_ns = total.elapsed().as_nanos();
            Ok(json!({"result":render_result(&result), "counts":counts, "verify_elapsed_ns_instrumented":verify_elapsed_ns, "read_parse_verify_elapsed_ns_instrumented":read_parse_verify_elapsed_ns, "process":process_metadata()}))
        }
        "produce" if args.len() == 7 => {
            let expected_bytes = bounded_read(&args[1], EXPECTED_BYTES)?;
            let ctx = Expected::decode(&expected_bytes).map_err(str::to_string)?;
            let a = load_matrix(&args[2])?;
            let b = load_matrix(&args[3])?;
            let nonce: u64 = args[4].parse().map_err(|_| "NONCE")?;
            let cached = match args[5].as_str() { "cached" => true, "direct" => false, _ => return Err("unknown strategy".into()) };
            let mut prepare_counts = Counts::default();
            let prepared = PreparedTask::new(a, b, cached, &mut prepare_counts).map_err(str::to_string)?;
            let mut counts = Counts::default();
            let witness = prepared.produce(&ctx, nonce, &mut counts).map_err(str::to_string)?;
            std::fs::write(&args[6], witness.encode()).map_err(|e| e.to_string())?;
            let event = statement(&ctx, &witness, &mut NoMeter).map_err(str::to_string)?;
            Ok(json!({"status":"PRODUCED_ARITHMETIC_ONLY", "nonce":nonce, "coordinates":witness.coordinates, "event_id":hex(&event), "ticket":hex(&ticket(&event, &mut NoMeter)), "target_hit":ticket(&event, &mut NoMeter)<=ctx.target, "cached_useful_products":cached, "preparation_counts":prepare_counts, "candidate_counts":counts}))
        }
        "bench-verify" if args.len() == 6 => {
            let expected = bounded_read(&args[1], EXPECTED_BYTES)?;
            let witness = bounded_read(&args[2], WITNESS_BYTES)?;
            let samples = positive_number(&args[3], 10000)?;
            let batch = positive_number(&args[4], 1_000_000)?;
            let warmup = positive_number(&args[5], 100_000)?;
            let mut counts = Counts::default();
            let canonical = verify_bytes(&expected, &witness, &mut counts);
            for _ in 0..warmup { let _ = black_box(verify_bytes(black_box(&expected), black_box(&witness), &mut NoMeter)); }
            let before = process_metadata();
            let mut durations = Vec::with_capacity(samples);
            for index in 0..samples {
                let start = Instant::now();
                for _ in 0..batch {
                    let _ = black_box(verify_bytes(black_box(&expected), black_box(&witness), &mut NoMeter));
                }
                durations.push(json!({"sample":index, "calls":batch, "wall_ns":start.elapsed().as_nanos()}));
            }
            let after = process_metadata();
            Ok(json!({"kind":"in_process_warm_fixed_bytes_to_verdict", "status":render_result(&canonical), "counts_one_instrumented_call":counts, "samples":durations, "warmup_calls":warmup, "before":before, "after":after, "timing_meter":"NoMeter; counters collected separately"}))
        }
        "mine" if args.len() == 4 => {
            let strategy = &args[1];
            let cached = match strategy.as_str() { "direct"=>false, "cached"=>true, _=>return Err("unknown strategy".into()) };
            let contexts = positive_number(&args[2], 1000)?;
            let nonce_limit = positive_number(&args[3], 100_000)?;
            let outer_start = Instant::now();
            let preparation_start = Instant::now();
            let (a, b) = deterministic_task();
            let prepared = PreparedTask::new(a, b, cached, &mut NoMeter).map_err(str::to_string)?;
            let preparation_ns = preparation_start.elapsed().as_nanos();
            let (root_a, root_b) = prepared.roots();
            let mut target = [255; 32]; target[0] = 3; // Exactly p = 1/64 in a uniform 256-bit ticket model.
            let mut trials = Vec::new();
            let mut context_results = Vec::new();
            for experiment in 0..contexts {
                let mut header = [b'H'; 32]; header[24..].copy_from_slice(&(experiment as u64).to_le_bytes());
                let ctx = Expected {chain:[b'C';32],parent:[b'P';32],header_without_work:header,root_a,root_b,target};
                let context_start = Instant::now();
                let mut winner = None;
                for nonce in 0..nonce_limit {
                    let start = Instant::now();
                    let w = prepared.produce(black_box(&ctx), black_box(nonce as u64), &mut NoMeter).map_err(str::to_string)?;
                    let event = statement(&ctx, &w, &mut NoMeter).map_err(str::to_string)?;
                    let value = ticket(&event, &mut NoMeter);
                    let hit = value <= ctx.target;
                    let candidate_ns = start.elapsed().as_nanos();
                    trials.push(json!({"context_index":experiment,"nonce":nonce,"coordinates":w.coordinates,"event_id":hex(&event),"ticket":hex(&value),"target_hit":hit,"produce_statement_ticket_wall_ns":candidate_ns}));
                    if hit {
                        let verify_start = Instant::now();
                        let checked = verify(&ctx, &w, &mut NoMeter).map_err(str::to_string)?;
                        let verify_ns = verify_start.elapsed().as_nanos();
                        let context_search_plus_winner_verify_ns = context_start.elapsed().as_nanos();
                        winner = Some(json!({"nonce":nonce,"attempts":nonce+1,"event_id":hex(&checked.event_id),"ticket":hex(&checked.ticket),"verification_wall_ns":verify_ns,"search_plus_winner_verify_wall_ns":context_search_plus_winner_verify_ns}));
                        break;
                    }
                }
                context_results.push(json!({"context_index":experiment,"header_without_work":hex(&header),"target":hex(&target),"winner":winner,"nonce_limit":nonce_limit}));
            }
            let complete_ns = outer_start.elapsed().as_nanos();
            // Full preparation and one post-preparation candidate counted separately from timing.
            let mut prepare_counts = Counts::default();
            let _ = PreparedTask::new(a, b, cached, &mut prepare_counts).map_err(str::to_string)?;
            let ctx = Expected {chain:[b'C';32],parent:[b'P';32],header_without_work:[b'H';32],root_a,root_b,target};
            let mut candidate_counts = Counts::default();
            let w = prepared.produce(&ctx, 0, &mut candidate_counts).map_err(str::to_string)?;
            let event = statement(&ctx, &w, &mut candidate_counts).map_err(str::to_string)?;
            let _ = ticket(&event, &mut candidate_counts);
            Ok(json!({"kind":"native_selected_event_research_lottery_p_1_over_64", "strategy":strategy, "preparation_wall_ns":preparation_ns,"preparation_counts":prepare_counts,"one_candidate_counts":candidate_counts,"product_cache_payload_bytes":if cached {131072} else {0},"original_matrix_bytes":32768,"merkle_digest_payload_bytes":8128,"complete_campaign_wall_ns_including_record_construction":complete_ns,"contexts":context_results,"trials":trials,"process":process_metadata(),"production_winner_or_receiver_measurement":false,"work_lower_bound_established":false}))
        }
        "version" if args.len() == 1 => Ok(json!({"package":env!("CARGO_PKG_VERSION"),"profile":String::from_utf8_lossy(PROFILE),"domain_hex":hex(DOMAIN),"expected_bytes":EXPECTED_BYTES,"witness_bytes":WITNESS_BYTES,"qualification":"HOLD_NO_GO"})),
        _ => Err("usage: verify EXPECTED WITNESS | produce EXPECTED A B NONCE direct|cached OUTPUT | bench-verify EXPECTED WITNESS SAMPLES BATCH WARMUP | mine direct|cached CONTEXTS NONCE_LIMIT | version".into()),
    }
}

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match run(&arguments) {
        Ok(value) => println!("{}", serde_json::to_string_pretty(&value).unwrap()),
        Err(error) => {
            println!(
                "{}",
                json!({"status":"HARNESS_ERROR","error":error,"executable":std::env::current_exe().ok().as_deref().map(Path::display).map(|p|p.to_string())})
            );
            std::process::exit(2);
        }
    }
}
