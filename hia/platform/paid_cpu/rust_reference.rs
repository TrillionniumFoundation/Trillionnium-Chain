// Private cfg(test) child of the complete unmodified original scalar_cpu.rs.
// Captured native trace values enter only the budget-replay fixture. Real owner
// controls below call original clocks in the actual working threads.
use super::*;
use serde_json::{json, Value};

const MARKER: &str = "HIA_PAID_CPU_ORACLE:";
fn inputs() -> Value {
    let path = std::env::var("TRNM_HIA_PAID_CPU_REPLAYS").expect("bound private input path");
    serde_json::from_slice(&std::fs::read(path).expect("complete private inputs"))
        .expect("strict generated replay JSON")
}
fn number(value: &Value, key: &str) -> u64 {
    value[key].as_u64().unwrap_or_else(|| panic!("missing u64 field {key}"))
}
fn error_code(result: crate::Result<()>) -> u64 {
    match result {
        Ok(()) => 0,
        Err(error) if error.is(crate::ErrorCode::PublicMutationCpuUnavailable) => 1,
        Err(error) if error.is(crate::ErrorCode::PublicMutationCpuBudget) => 2,
        Err(error) => panic!("unexpected original budget error {error}"),
    }
}
fn snapshot(budget: &PaidMutationCpuBudget, anchor: Instant) -> Value {
    let delta = budget.updated.checked_duration_since(anchor).expect("replay watermark before anchor");
    let mut value = json!({
        "credit_ns": budget.credit_ns.to_string(),
        "unavailable": budget.unavailable,
        "in_flight": budget.in_flight,
        "termination_reserved_ns": budget.termination_reserved_ns,
        "verified_completions": budget.verified_completions,
        "flow_known": budget.flow.is_some(),
        "updated_relative_seconds": delta.as_secs(),
        "updated_relative_nanos": delta.subsec_nanos(),
    });
    if let Some(flow) = budget.flow.as_ref() {
        let fields = json!({
            "initial_credit_ns": flow.initial_credit_ns.to_string(),
            "credited_refill_ns": flow.credited_refill_ns,
            "discarded_refill_ns": flow.discarded_refill_ns,
            "booked_reservation_ns": flow.booked_reservation_ns,
            "live_debited_cpu_ns": flow.live_debited_cpu_ns,
            "settlement_residual_cpu_ns": flow.settlement_residual_cpu_ns,
            "settled_full_cpu_ns": flow.settled_full_cpu_ns,
            "settlement_discard_ns": flow.settlement_discard_ns,
        });
        value.as_object_mut().unwrap().extend(fields.as_object().unwrap().clone());
    }
    value
}

#[test]
fn original_budget_trace_replays() {
    let input = inputs();
    let mut seen = std::collections::BTreeSet::new();
    for case in input["cases"].as_array().expect("complete cases") {
        let label = case["label"].as_str().expect("label");
        assert!(seen.insert(label.to_owned()), "duplicate case");
        let mut budget = if case["cold"].as_bool().expect("cold bit") {
            PaidMutationCpuBudget::cold_start()
        } else {
            PaidMutationCpuBudget::new()
        };
        // Clock-coordinate fixture only: all complete production methods below
        // receive the real captured relative CLOCK_MONOTONIC values. No changes
        // to their arithmetic, errors, field ordering, or compiled source.
        let anchor = Instant::now();
        budget.updated = anchor;
        let mut results = Vec::new();
        for (index, event) in case["operations"].as_array().expect("operations").iter().enumerate() {
            let nanos = number(event, "relative_nanos");
            assert!(nanos < 1_000_000_000);
            let elapsed = Duration::new(number(event, "relative_seconds"), nanos as u32);
            let now = anchor.checked_add(elapsed).expect("actual trace duration fits Instant");
            let kind = event["kind"].as_str().expect("kind");
            let observed = match kind {
                "reserve" => json!({"error": error_code(budget.reserve(now))}),
                "charge_request_live" => json!({"error": error_code(budget.charge_request_live(
                    now, number(event,"measured_ns"), number(event,"request_total_ns")))}),
                "record_final_live" => json!({"error": error_code(budget.record_final_live(
                    now, number(event,"measured_ns")))}),
                "settle_observed" => json!({"settled": budget.settle_observed(
                    now, Some(number(event,"residual_ns")), Some(number(event,"full_ns")),
                    Some(number(event,"already_ns")))}),
                _ => panic!("unsupported replay operation {kind}"),
            };
            results.push(json!({"index":index,"kind":kind,"result":observed}));
        }
        println!("{MARKER}{}", json!({
            "kind":"budget-replay", "label":label, "operations":results,
            "final":snapshot(&budget,anchor),
            "flow_snapshot":budget.flow.as_ref().and_then(|flow|flow.snapshot(
                budget.credit_ns,budget.in_flight,budget.termination_reserved_ns)),
            "private_relative_clock_fixture":true,
            "original_budget_methods_executed":true
        }));
    }
    assert_eq!(seen.len(), 6, "native trace corpus must remain complete");
}

fn do_work(request: usize, tx: usize, units: u64, seed: u64) -> u64 {
    let mut value = seed ^ tx as u64 ^ (request as u64 + 1);
    for step in 0..units {
        value=std::hint::black_box(value.wrapping_mul(1_664_525)
            .wrapping_add(1_013_904_223).wrapping_add(step));
    }
    value
}
fn actual_request(domain: ServiceMutationCpuDomain, request: usize, profile: &Value) -> Value {
    let workers = number(profile, "workers") as usize;
    let txs = number(profile, "txs") as usize;
    let units = number(profile,"units");
    let seed = number(profile,"seed");
    assert!([1,2,4,8].contains(&workers) && txs<=32 && units<=1_000_000);
    let operation = domain.begin().expect("mandatory original real owner begin");
    let count = workers.min(txs);
    let mut rows: Vec<(usize,u64)> = if count<=1 {
        (0..txs).map(|index|{
            operation.checkpoint().expect("actual original owner checkpoint");
            (index,do_work(request,index,units,seed))
        }).collect()
    } else {
        std::thread::scope(|scope| {
            let accounting = operation.worker_accounting();
            let checkpoint = operation.checkpoint_handle();
            let mut handles=Vec::new();
            let mut spawn_failed=false;
            for worker in 0..count {
                let live = checkpoint.clone();
                match std::thread::Builder::new().name(format!("paid-original-{request}-{worker}"))
                    .spawn_scoped(scope,move||{
                        let _interval=accounting.worker_started()
                            .expect("mandatory original actual worker interval");
                        (worker..txs).step_by(count).map(|index|{
                            live.checkpoint().expect("actual original registered worker checkpoint");
                            (index,do_work(request,index,units,seed))
                        }).collect::<Vec<_>>()
                    }) {
                    Ok(handle)=>{accounting.worker_spawn_succeeded();handles.push(handle);}
                    Err(_)=>{spawn_failed=true;break;}
                }
            }
            let mut values=Vec::new();let mut panicked=false;
            // Every created original scope is joined even on a failed spawn or
            // child panic. This scaffold does not claim the full block executor.
            for handle in handles {
                match handle.join(){Ok(mut v)=>values.append(&mut v),Err(_)=>panicked=true}
            }
            assert!(!spawn_failed,"original real control WORKER_START");
            assert!(!panicked,"original real control WORKER_PANIC");
            values
        })
    };
    rows.sort_by_key(|row|row.0);
    assert_eq!(rows.len(),txs);
    for (index,(actual,_)) in rows.iter().enumerate(){assert_eq!(*actual,index);}
    let receipt=operation.finish();
    let expected_workers=if count>1{count as u64}else{0};
    assert!(!receipt.accounting_unavailable && !receipt.live_refused,
        "mandatory original known real CPU settlement");
    assert_eq!((receipt.spawned_workers,receipt.started_workers,receipt.finished_workers,receipt.known_workers),
        (expected_workers,expected_workers,expected_workers,expected_workers));
    let owner=receipt.owner_cpu_ns.expect("actual owner CPU");
    let worker=receipt.scoped_worker_cpu_ns.expect("actual scoped CPU");
    let total=receipt.total_cpu_ns.expect("actual full CPU");
    let live=receipt.live_paid_cpu_ns.expect("actual already charged CPU");
    let residual=receipt.residual_cpu_ns.expect("actual residual CPU");
    assert!(owner>0);
    assert_eq!(worker>0,expected_workers>0);
    assert_eq!(owner.checked_add(worker),Some(total));
    assert_eq!(total.checked_sub(live),Some(residual));
    json!({"request":request,"receipt":receipt,"work_rows":rows})
}

#[test]
fn original_real_scoped_profiles() {
    let input=inputs();
    let mut count=0;
    for case in input["cases"].as_array().expect("complete cases") {
        if case["cold"].as_bool().unwrap(){continue;}
        let plan=&case["plan"];
        let requests=number(plan,"requests") as usize;
        assert!((1..=2).contains(&requests));
        let domain=ServiceMutationCpuDomain::standalone();
        let shared=domain.clone();
        assert!(domain.shares_domain_with(&shared));
        let gate=AtomicBool::new(false);
        let owners=std::thread::scope(|scope|{
            let mut handles=Vec::new();let mut spawn_failed=false;
            for request in 0..requests {
                let own=shared.clone();let profile=&plan["profiles"][request];let ready=&gate;
                match std::thread::Builder::new().name(format!("paid-original-owner-{request}"))
                    .spawn_scoped(scope,move||{
                        while !ready.load(Ordering::Acquire){std::thread::yield_now();}
                        actual_request(own,request,profile)
                    }) {
                    Ok(handle)=>handles.push(handle),
                    Err(_)=>{spawn_failed=true;break;}
                }
            }
            gate.store(true,Ordering::Release);
            let mut results=Vec::new();let mut panicked=false;
            for handle in handles{
                match handle.join(){Ok(value)=>results.push(value),Err(_)=>panicked=true}
            }
            assert!(!spawn_failed,"original real owner spawn failed");
            assert!(!panicked,"original actual owner panicked");
            results
        });
        let budget=domain.budget.lock().expect("actual unpoisoned global Mutex");
        assert_eq!(budget.in_flight,0);
        assert!(!budget.unavailable);
        let flow=budget.flow.as_ref().and_then(|flow|flow.snapshot(
            budget.credit_ns,budget.in_flight,budget.termination_reserved_ns))
            .expect("actual original shared flow identity");
        let paid=owners.iter().map(|r|r["receipt"]["total_cpu_ns"].as_u64().unwrap()).sum::<u64>();
        assert_eq!(paid,flow.paid_cpu_debit_ns);
        assert_eq!(flow.settled_full_cpu_ns,paid);
        assert_eq!(flow.unsettled_known_live_cpu_ns,0);
        println!("{MARKER}{}",json!({"kind":"domain-positive","label":case["label"],
            "owners":owners,"flow":flow,"actual_original_domain_and_scoped_intervals":true,
            "complete_original_block_executor":false,
            "independent_physical_clocks_not_exact_ns_comparison":true}));
        count+=1;
    }
    assert_eq!(count,5);
}

#[test]
fn linux_clocks_are_mandatory() {
    assert!(cfg!(all(target_os="linux",target_arch="x86_64")));
    let start=Instant::now();
    let mut stamp=ThreadCpuStamp::start().expect("mandatory original CLOCK_THREAD_CPUTIME_ID start");
    std::hint::black_box(do_work(0,0,100_000,19));
    let measured=stamp.checkpoint().expect("mandatory original live CPU");
    std::hint::black_box(do_work(0,1,100_000,23));
    let tail=stamp.finish().expect("mandatory original final CPU");
    assert!(measured>0 && tail>0);
    let elapsed=Instant::now().checked_duration_since(start).expect("actual original CLOCK_MONOTONIC");
    assert!(!elapsed.is_zero());
    println!("{MARKER}{}",json!({"kind":"linux-positive","actual_cpu_ns":measured,
        "actual_tail_ns":tail,"monotonic_elapsed_ns":elapsed.as_nanos().to_string(),
        "clock_failure_cannot_skip":true}));
}

// Private seeded arithmetic boundaries use public Instant checked arithmetic to
// preserve full valid signed-timespec differences; no transmute or fake runtime
// clock samples enter the original real owner tests above.
fn signed128(low:u64,high:u64)->i128{((u128::from(high)<<64)|u128::from(low)) as i128}
fn boundary_instants(words:&[u64])->(Instant,Instant){
    let old_ns=(words[6] as i64 as i128)*1_000_000_000+i128::from(words[7]);
    let now_ns=(words[22] as i64 as i128)*1_000_000_000+i128::from(words[23]);
    assert!(words[7]<1_000_000_000 && words[23]<1_000_000_000);
    let delta=now_ns-old_ns;let absolute=delta.unsigned_abs();
    let seconds=u64::try_from(absolute/1_000_000_000).expect("valid timespec difference seconds");
    let nanos=(absolute%1_000_000_000) as u32;
    let duration=Duration::new(seconds,nanos);
    let base=Instant::now();
    if delta>=0{
        let old=base.checked_sub(Duration::from_secs(1_u64<<63))
            .expect("original signed Instant supports finite private negative epoch");
        let now=old.checked_add(duration).expect("original full positive timespec difference");
        (old,now)
    }else{
        let old=base.checked_add(Duration::from_secs(i64::MAX as u64-1_000_000_000))
            .expect("original signed Instant supports finite private positive epoch");
        let now=old.checked_sub(duration).expect("original full negative timespec difference");
        (old,now)
    }
}
fn flow_value(flow:&CpuFlow)->Value{
    json!({"initial_credit_ns":flow.initial_credit_ns.to_string(),
        "credited_refill_ns":flow.credited_refill_ns,"discarded_refill_ns":flow.discarded_refill_ns,
        "booked_reservation_ns":flow.booked_reservation_ns,"live_debited_cpu_ns":flow.live_debited_cpu_ns,
        "settlement_residual_cpu_ns":flow.settlement_residual_cpu_ns,
        "settled_full_cpu_ns":flow.settled_full_cpu_ns,"settlement_discard_ns":flow.settlement_discard_ns})
}
fn observation_value(flow:ServiceMutationCpuFlowObservation)->Value{
    json!({"paid_cpu_debit_ns":flow.paid_cpu_debit_ns,
        "remaining_paid_credit_ns":flow.remaining_paid_credit_ns.to_string(),
        "unsettled_known_live_cpu_ns":flow.unsettled_known_live_cpu_ns,
        "initial_credit_ns":flow.initial_credit_ns.to_string(),
        "credited_refill_ns":flow.credited_refill_ns,"discarded_refill_ns":flow.discarded_refill_ns,
        "booked_reservation_ns":flow.booked_reservation_ns,"live_debited_cpu_ns":flow.live_debited_cpu_ns,
        "settlement_residual_cpu_ns":flow.settlement_residual_cpu_ns,"settled_full_cpu_ns":flow.settled_full_cpu_ns,
        "settlement_discard_ns":flow.settlement_discard_ns,"termination_reserved_ns":flow.termination_reserved_ns,
        "live_owners":flow.live_owners,"stored_credit_ns":flow.stored_credit_ns.to_string(),
        "balance_identity_verified":flow.balance_identity_verified})
}
#[test]
fn original_private_arithmetic_boundaries(){
    let input=inputs();let cases=input["boundaries"].as_array().expect("complete private boundary corpus");
    assert_eq!(cases.len(),67);
    for case in cases{
        let words=case["seed_words"].as_array().unwrap().iter()
            .map(|v|v.as_u64().expect("complete u64 boundary word")).collect::<Vec<_>>();
        assert_eq!(words.len(),64);assert_eq!(words[0],0x3130305849464350);
        assert_eq!(words[2],0x3130303055504350);
        let method=words[1];let(old,now)=boundary_instants(&words);
        let mut budget=PaidMutationCpuBudget::new();
        budget.credit_ns=signed128(words[4],words[5]);
        budget.updated=old;budget.in_flight=usize::try_from(words[8]).unwrap();
        budget.unavailable=words[3]!=0;budget.termination_reserved_ns=words[9];
        budget.verified_completions=usize::try_from(words[10]).unwrap();
        budget.flow=if words[11]!=0{Some(CpuFlow{
            initial_credit_ns:signed128(words[12],words[13]),credited_refill_ns:words[14],
            discarded_refill_ns:words[15],booked_reservation_ns:words[16],live_debited_cpu_ns:words[17],
            settlement_residual_cpu_ns:words[18],settled_full_cpu_ns:words[19],settlement_discard_ns:words[20]
        })}else{None};
        let result=match method{
            0=>{
                budget=if words[31]!=0{PaidMutationCpuBudget::cold_start()}else{PaidMutationCpuBudget::new()};
                budget.updated=now;0
            },
            1=>{budget.refill(now);0},
            2=>error_code(budget.reserve(now)),
            3=>error_code(budget.charge_live(now,words[24])),
            4=>error_code(budget.charge_request_live(now,words[24],words[25])),
            5=>error_code(budget.record_final_live(now,words[24])),
            6=>u64::from(budget.settle_observed(now,
                (words[26]!=0).then_some(words[27]),(words[28]!=0).then_some(words[29]),
                (words[28]!=0).then_some(words[30]))),
            7=>u64::from(budget.flow.as_ref().and_then(|flow|flow.snapshot(
                budget.credit_ns,budget.in_flight,budget.termination_reserved_ns)).is_some()),
            8=>u64::from(budget.credit_freshness_at(now).is_some()),
            _=>panic!("invalid method")
        };
        let(updated_seconds_bits,updated_nanos)=if budget.updated==now{(words[22],words[23])}
            else{assert_eq!(budget.updated,old,"unexpected production watermark");(words[6],words[7])};
        let flow_snapshot=budget.flow.as_ref().and_then(|flow|flow.snapshot(
            budget.credit_ns,budget.in_flight,budget.termination_reserved_ns)).map(observation_value);
        let freshness=budget.credit_freshness_at(now).map(|value|json!({
            "watermark_age_ns":value.watermark_age_ns,
            "projected_credited_refill_ns":value.projected_credited_refill_ns,
            "projected_discarded_refill_ns":value.projected_discarded_refill_ns,
            "projected_stored_credit_ns":value.projected_stored_credit_ns.to_string(),
            "projected_paid_credit_ns":value.projected_paid_credit_ns.to_string(),
            "projected_scalar_start_eligible":value.projected_scalar_start_eligible}));
        let comparison=json!({"result":result,"credit_ns":budget.credit_ns.to_string(),
            "unavailable":budget.unavailable,"updated_seconds_bits":updated_seconds_bits,
            "updated_nanos":updated_nanos,"in_flight":budget.in_flight,
            "termination_reserved_ns":budget.termination_reserved_ns,
            "verified_completions":budget.verified_completions,
            "flow":budget.flow.as_ref().map(flow_value),
            "flow_snapshot":flow_snapshot,"freshness":freshness});
        println!("{MARKER}{}",json!({"kind":"private-boundary","name":case["name"],
            "comparison":comparison,"original_complete_methods_executed":true,
            "private_seeded_account_and_relative_clock_fixture":true,
            "production_runtime_counter_abi":false}));
    }
}

// This extra child is a controlled fault observer. It calls the unchanged
// original domain/operation/RAII methods. Its markers publish only the actual
// executing Linux TID and finite role; they contain no clock or CPU values.
fn fault_role(role:u64,index:u64) {
    use std::io::Write;
    let link=std::fs::read_link("/proc/thread-self").expect("actual private kernel thread link");
    let tid:u64=link.file_name().expect("actual thread link component").to_str()
        .expect("ASCII actual Linux TID").parse().expect("decimal actual Linux TID");
    assert!(tid>0,"actual own thread link must identify a TID");
    let mut frame=[0_u8;32];frame[..8].copy_from_slice(b"PCROLE01");
    frame[8..16].copy_from_slice(&(tid as u64).to_le_bytes());
    frame[16..24].copy_from_slice(&role.to_le_bytes());
    frame[24..32].copy_from_slice(&index.to_le_bytes());
    std::io::stderr().lock().write_all(&frame).expect("private role marker write");
}
fn fault_code(error:crate::Error)->u64 {
    if error.is(crate::ErrorCode::PublicMutationCpuUnavailable){1}
    else if error.is(crate::ErrorCode::PublicMutationCpuBudget){2}
    else {panic!("unexpected actual original fault error {error}")}
}
fn fault_scope(operation:&ServiceMutationCpuOperation,workers:usize,txs:usize)->u64 {
    let count=workers.min(txs);
    if count<=1 {
        for index in 0..txs {
            if let Err(error)=operation.checkpoint(){return fault_code(error);}
            std::hint::black_box(do_work(0,index,1000,19));
        }
        return 0;
    }
    std::thread::scope(|scope|{
        let accounting=operation.worker_accounting();
        let checkpoint=operation.checkpoint_handle();
        let mut handles=Vec::new();let mut partial=false;
        for worker in 0..count {
            let live=checkpoint.clone();
            match std::thread::Builder::new().name(format!("paid-fault-worker-{worker}"))
                .spawn_scoped(scope,move||->std::result::Result<Vec<(usize,u64)>,u64>{
                    fault_role(3,worker as u64);
                    let _interval=accounting.worker_started().expect("original worker interval object");
                    let mut rows=Vec::new();
                    for index in (worker..txs).step_by(count) {
                        live.checkpoint().map_err(fault_code)?;
                        rows.push((index,do_work(0,index,1000,19)));
                    }
                    Ok(rows)
                }) {
                Ok(handle)=>{accounting.worker_spawn_succeeded();handles.push(handle);}
                Err(_)=>{partial=true;break;}
            }
        }
        let mut first=0;let mut panicked=false;let mut rows=Vec::new();
        // The exact source's retained precedence: all actual handles are
        // joined; a partial start wins, then child panic, then first Err.
        for handle in handles {
            match handle.join() {
                Ok(Ok(mut values))=>rows.append(&mut values),
                Ok(Err(error))=>{if first==0{first=error;}},
                Err(_)=>panicked=true,
            }
        }
        if partial{return 1001;}
        if panicked{return 1002;}
        if first!=0{return first;}
        rows.sort_by_key(|row|row.0);
        if rows.len()!=txs || rows.iter().enumerate().any(|(i,row)|i!=row.0){return 1003;}
        0
    })
}
fn fault_live_observation(live:&LiveRequestCpu)->Value {
    let poisoned=live.state.is_poisoned();
    let state=live.state.lock().unwrap_or_else(|error|error.into_inner());
    json!({"poisoned":poisoned,"unavailable":state.unavailable,"refused":state.refused,
      "charged_ns":state.charged_ns,"registered_threads":state.threads.len(),
      "termination_reserved":state.termination_reserved})
}
#[test]
fn original_actual_fault_profile() {
    let label=std::env::var("TRNM_HIA_PAID_FAULT_LABEL").expect("private case name");
    let workers:usize=std::env::var("TRNM_HIA_PAID_FAULT_WORKERS").expect("workers").parse().unwrap();
    let txs:usize=std::env::var("TRNM_HIA_PAID_FAULT_TXS").expect("txs").parse().unwrap();
    assert!([1,2,4,8].contains(&workers) && txs<=32);
    fault_role(1,0);
    let created=std::panic::catch_unwind(std::panic::AssertUnwindSafe(ServiceMutationCpuDomain::standalone));
    let domain=match created {
        Ok(domain)=>domain,
        Err(_)=>{
            println!("{MARKER}{}",json!({"kind":"actual-fault","label":label,
              "constructor_panicked":true,"operation_returned":false,
              "original_domain_and_raii_executed":true,"complete_original_executor":false}));
            return;
        }
    };
    fault_role(4,0);
    let observed=Arc::new(Mutex::new(json!({"begin_error":null,"scope_error":null,
       "owner_panicked":false,"owner_spawn_failed":false,"operation_returned":false,
       "receipt":null,"worker_counts_before_finish":null,"live_before_finish":null})));
    let saved_live:Arc<Mutex<Option<Arc<LiveRequestCpu>>>>=Arc::new(Mutex::new(None));
    let owner_observed=observed.clone();let owner_live=saved_live.clone();let shared=domain.clone();
    let owner=std::thread::Builder::new().name("paid-fault-owner".to_owned()).spawn(move||{
        fault_role(2,0);
        let attempt=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||{
            let operation=match shared.begin() {
                Ok(operation)=>operation,
                Err(error)=>{owner_observed.lock().unwrap()["begin_error"]=json!(fault_code(error));return;}
            };
            *owner_live.lock().unwrap()=Some(operation.live.clone());
            owner_observed.lock().unwrap()["begin_error"]=json!(0);
            let scope_error=fault_scope(&operation,workers,txs);
            {
                let mut target=owner_observed.lock().unwrap();
                target["scope_error"]=json!(scope_error);
                target["worker_counts_before_finish"]=json!({
                  "spawned":operation.workers.spawned.load(Ordering::Acquire),
                  "started":operation.workers.started.load(Ordering::Acquire),
                  "finished":operation.workers.finished.load(Ordering::Acquire),
                  "known":operation.workers.known.load(Ordering::Acquire),
                  "unavailable":operation.workers.unavailable.load(Ordering::Acquire)});
                target["live_before_finish"]=fault_live_observation(&operation.live);
            }
            let receipt=operation.finish();
            let mut target=owner_observed.lock().unwrap();
            target["receipt"]=serde_json::to_value(receipt).expect("actual original returned settlement");
            target["operation_returned"]=json!(true);
        }));
        if attempt.is_err(){owner_observed.lock().unwrap()["owner_panicked"]=json!(true);}
    });
    match owner {
        Ok(handle)=>assert!(handle.join().is_ok(),"private catch must contain original owner panic"),
        Err(_)=>observed.lock().unwrap()["owner_spawn_failed"]=json!(true),
    }
    let live=saved_live.lock().unwrap().as_ref().map(|live|fault_live_observation(live));
    let poisoned=domain.budget.is_poisoned();
    let budget=domain.budget.lock().unwrap_or_else(|error|error.into_inner());
    let global=json!({"poisoned":poisoned,"unavailable":budget.unavailable,
      "in_flight":budget.in_flight,"credit_ns":budget.credit_ns.to_string(),
      "flow":budget.flow.as_ref().map(flow_value),
      "termination_reserved_ns":budget.termination_reserved_ns,
      "verified_completions":budget.verified_completions});
    println!("{MARKER}{}",json!({"kind":"actual-fault","label":label,
      "constructor_panicked":false,"global":global,"live":live,
      "owner":observed.lock().unwrap().clone(),"original_domain_and_raii_executed":true,
      "complete_original_executor":false,"independent_physical_clocks_not_equal_ns":true}));
}
