// Private child of the complete original Host resource_tests include.
// The existing HIA qualification fixture is included byte for byte. It calls
// original read_context / ScopedParentDirectory / sample_counters methods;
// private paths and actual fixture UID are explicitly not production authority.
include!("hia_work_owner_resource_fixture.rs");
use sha2::{Digest, Sha256};
use std::{
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};
use trnm_crypto_primitives::pon_work::{self, VerificationError, VerificationProgress, WorkError};

const WORK_MARKER: &str = "HIA_WORK_OWNER_ORACLE:";

fn actual_tid() -> u32 {
    // The unchanged Node rustix feature set has no `thread` feature. Observe
    // this real calling thread through Linux's kernel-generated proc symlink;
    // no Cargo feature or production dependency is changed for the oracle.
    fs::read_link("/proc/thread-self").unwrap().file_name().unwrap()
        .to_str().unwrap().parse().unwrap()
}

fn relation_code(error: WorkError) -> u64 {
    match error {
        WorkError::Length => 1,
        WorkError::Version => 2,
        WorkError::Field => 3,
        WorkError::Task => 4,
        WorkError::Transcript => 5,
        WorkError::Product => 6,
        WorkError::Target => 7,
        WorkError::NoiseBudget => 8,
    }
}

fn outcome_code(error: &crate::Error) -> (u64, u64) {
    let text=error.to_string();
    if let Some(raw)=text.strip_prefix("HIA_WORK_RELATION_") {
        return (1,raw.parse().unwrap());
    }
    match text.as_str() {
        "PUBLIC_REQUEST_CANCELLED" => (2,1),
        "PUBLIC_REQUEST_DEADLINE" => (2,2),
        _ => (3,error_code(error)),
    }
}

fn progress_row(point: VerificationProgress, sequence: u64) -> [u64;5] {
    match point {
        VerificationProgress::BeforeReplay => [64,0,0,0,sequence],
        VerificationProgress::Noise {label,counter} => [65,u64::from(label),u64::from(counter),0,sequence],
        VerificationProgress::MatrixRow {row} => [66,u64::try_from(row).unwrap(),0,0,sequence],
        VerificationProgress::TranscriptTile {row,column,inner} => [67,u64::try_from(row).unwrap(),u64::try_from(column).unwrap(),u64::try_from(inner).unwrap(),sequence],
        VerificationProgress::BeforeProduct => [68,0,0,0,sequence],
        VerificationProgress::BeforeVerifiedWork => [69,0,0,0,sequence],
    }
}

fn gate(
    owner: &FixtureOwner,
    case: &Value,
    stage: u64,
    sequence: u64,
    seen: &Cell<bool>,
    cancel: &AtomicBool,
    stop: &AtomicBool,
) {
    if seen.get() || case["gate_stage"].as_u64().unwrap()!=stage || case["gate_sequence"].as_u64().unwrap()!=sequence {return;}
    seen.set(true);
    apply(&owner.root,case["actions"].as_array().unwrap());
    match case["signal"].as_u64().unwrap() {
        0 => (),
        1 => cancel.store(true,Ordering::Release),
        2 => stop.store(true,Ordering::Release),
        _ => panic!("unsupported private cancellation fixture"),
    }
    let delay=case["delay_ms"].as_u64().unwrap();
    if delay!=0 {thread::sleep(Duration::from_millis(delay));}
}

fn count_check(owner: &FixtureOwner, checks: &Cell<u64>, calls: &Cell<u64>) -> crate::Result<()> {
    calls.set(calls.get()+1);
    let opened=owner.checked()?;
    checks.set(checks.get()+1);
    drop(opened);
    Ok(())
}

fn run_original_work(case: &Value) -> Value {
    let input=decoded(case["request_hex"].as_str().unwrap());
    assert!(input.len()>=96);
    let challenge: [u8;32]=input[0..32].try_into().unwrap();
    let task: [u8;32]=input[32..64].try_into().unwrap();
    let target: [u8;32]=input[64..96].try_into().unwrap();
    let temp=tempfile::tempdir().unwrap();provision(temp.path());
    let initial_tid=actual_tid();
    let before_checks=Cell::new(0u64);
    let deadline=Instant::now()+Duration::from_secs(4);
    let cancel=AtomicBool::new(false);let stop=AtomicBool::new(false);let seen=Cell::new(false);
    let owner=match FixtureOwner::acquire(temp.path()) {
        Ok(owner)=>owner,
        Err(error)=>return json!({"name":case["name"],"domain":3,"code":error_code(&error),"progress":[],"product_hex":null,"worker_tid":null}),
    };
    let first=(|| -> crate::Result<_> {
        let opened=owner.checked()?;drop(opened);before_checks.set(1);
        gate(&owner,case,1,0,&seen,&cancel,&stop);
        let sample=owner.sample(0,&[],&before_checks,&Cell::new(false))?;
        gate(&owner,case,2,0,&seen,&cancel,&stop);
        Ok(sample)
    })();
    let before=match first {
        Ok(sample)=>sample,
        Err(error)=>return json!({"name":case["name"],"domain":3,"code":error_code(&error),"progress":[],"product_hex":null,"worker_tid":null,"main_tid":initial_tid,"before_checks":before_checks.get()}),
    };
    let inherited_gate=seen.get();
    let (mut outcome,progress,worker_tid,host_calls,worker_checks,worker_gate,work_code)=thread::scope(|scope| {
        let job=scope.spawn(|| {
            let worker_tid=actual_tid();
            assert_ne!(initial_tid,worker_tid);
            let calls=Cell::new(0);let checks=Cell::new(0);let gate_seen=Cell::new(inherited_gate);
            let mut progress=Vec::<[u64;5]>::new();let mut work_code=0;
            let native=(|| -> crate::Result<pon_work::VerifiedWork> {
                count_check(&owner,&checks,&calls)?;
                crate::ingress::public_v3::hia_work_owner_bridge::alive(deadline,&stop,&cancel)?;
                let checked=pon_work::verify_with_progress(challenge,task,target,&input[96..],&mut |point| {
                    let sequence=u64::try_from(progress.len()).unwrap()+1;
                    progress.push(progress_row(point,sequence));
                    gate(&owner,case,3,sequence,&gate_seen,&cancel,&stop);
                    crate::ingress::public_v3::hia_work_owner_bridge::alive(deadline,&stop,&cancel)?;
                    gate(&owner,case,4,sequence,&gate_seen,&cancel,&stop);
                    count_check(&owner,&checks,&calls)?;
                    gate(&owner,case,5,sequence,&gate_seen,&cancel,&stop);
                    crate::ingress::public_v3::hia_work_owner_bridge::alive(deadline,&stop,&cancel)
                });
                match checked {
                    Ok(value)=>Ok(value),
                    Err(VerificationError::Cancelled(error))=>Err(error),
                    Err(VerificationError::Relation(error))=>{
                        work_code=relation_code(error);
                        Err(format!("HIA_WORK_RELATION_{work_code}").into())
                    }
                }
            })();
            let sequence=u64::try_from(progress.len()).unwrap();
            gate(&owner,case,6,sequence,&gate_seen,&cancel,&stop);
            let was_ok=native.is_ok();
            let outcome=crate::ingress::public_v3::hia_work_owner_bridge::finish(native,deadline,|| {
                count_check(&owner,&checks,&calls)?;
                if was_ok {gate(&owner,case,7,sequence,&gate_seen,&cancel,&stop);}
                Ok(())
            });
            (outcome,progress,worker_tid,calls.get(),checks.get(),gate_seen.get(),work_code)
        });
        // This is a real std scoped child; no parent counter value or boolean
        // replaces its execution, cleanup, or the actual ordered join.
        job.join().expect("original worker unexpectedly panicked")
    });
    let checks=Cell::new(before_checks.get());
    seen.set(worker_gate);
    gate(&owner,case,8,u64::try_from(progress.len()).unwrap(),&seen,&cancel,&stop);
    let mut after_values=None;let mut delta_values=None;
    match owner.sample(0,&[],&checks,&Cell::new(false)) {
        Err(error)=>outcome=Err(error),
        Ok(after)=>match after.cpu_delta_since(before) {
            Err(error)=>outcome=Err(error),
            Ok(delta)=>{
                after_values=Some(values(after));
                delta_values=Some([delta.usage_usec,delta.nr_periods,delta.nr_throttled,delta.throttled_usec]);
            }
        }
    }
    let (domain,code,error_text,product,actual_task,ticket,actual_challenge)=match outcome {
        Ok(value)=>(0,0,None,Some(hex::encode(value.product().iter().flat_map(|word|word.to_le_bytes()).collect::<Vec<_>>())),Some(hex::encode(value.task())),Some(hex::encode(value.ticket())),Some(hex::encode(value.challenge()))),
        Err(error)=>{let (domain,code)=outcome_code(&error);(domain,code,Some(error.to_string()),None,None,None,None)}
    };
    json!({"name":case["name"],"domain":domain,"code":code,"error_text":error_text,
        "work_code":work_code,"progress":progress,"product_hex":product,
        "challenge_hex":actual_challenge,"task_hex":actual_task,"ticket_hex":ticket,
        "main_tid":initial_tid,"worker_tid":worker_tid,"joined":true,
        "host_calls":host_calls,"worker_checks":worker_checks,"before_checks":before_checks.get(),
        "after_checks":checks.get(),"before_values":values(before),"after_values":after_values,
        "delta_values":delta_values,"gate_observed":seen.get(),
        "input_sha256":hex::encode(Sha256::digest(&input)),
        "actual_original_W1":true,"actual_original_Host_primitives":true,
        "actual_original_task_alive_and_final_resource":true,
        "fixture_uses_actual_AtomicBool_cancel_inputs":true,
        "production_fixed_parent_authority":false,"complete_Node_or_paid_checkpoint":false})
}

#[test]
fn same_worker_evaluate() {
    let path=std::env::var_os("TRNM_HIA_WORK_OWNER_CORPUS").expect("mandatory exact native corpus required");
    let input=fs::File::open(path).unwrap();
    for line in io::BufReader::new(input).lines() {
        let case: Value=serde_json::from_str(&line.unwrap()).unwrap();
        println!("{WORK_MARKER}{}",run_original_work(&case));
    }
}
