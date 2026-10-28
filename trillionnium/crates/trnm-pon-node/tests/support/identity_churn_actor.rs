//! One actual child process, one caller at a time; every input has real W1.
use super::{
    identity_work as work,
    plan::{Job, Mode, JOB_SCHEMA, SCHEMA},
    support,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    net::SocketAddr,
    path::Path,
    time::{Duration, Instant},
};
use trnm_crypto_primitives::pon_work::PreparedTask;
use trnm_pon_node::{ingress::public_v3::Request, Packet};

pub fn cgroup() -> String {
    fs::read_to_string("/proc/self/cgroup").unwrap()
}
pub fn binary_sha256() -> String {
    let mut file = fs::File::open(std::env::current_exe().unwrap()).unwrap();
    let mut h = Sha256::new();
    let mut buf = [0; 65536];
    loop {
        let n = file.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    hex::encode(h.finalize())
}
fn wait(path: &Path, seconds: u64) -> Value {
    let end = Instant::now() + Duration::from_secs(seconds);
    while !path.exists() && Instant::now() < end {
        support::ready_sleep();
    }
    serde_json::from_slice(&fs::read(path).expect("immutable parent marker before deadline"))
        .unwrap()
}
fn call(
    job: &Job,
    packet: &Packet,
    index: usize,
    stage: &str,
    epoch: u64,
    end: u64,
    construction_ref: &str,
) -> Value {
    let result = support::call(
        job.address.parse::<SocketAddr>().unwrap(),
        &support::settings(),
        Request::Submit {
            packet: hex::encode(packet.encode().unwrap()),
        },
        80 + (job.worker % 150) as u8,
        epoch,
        end,
    );
    json!({"schema":SCHEMA,"kind":"call","stage":stage,"worker":job.worker,"index":index,
        "construction_ref":construction_ref,"absolute_started_ns":epoch+result["started_ns"].as_u64().unwrap(),
        "absolute_ended_ns":epoch+result["ended_ns"].as_u64().unwrap(),"call":result})
}
pub fn run(job_path: &Path) {
    let job: Job = serde_json::from_slice(&fs::read(job_path).unwrap()).unwrap();
    assert_eq!(job.schema, JOB_SCHEMA);
    job.plan.validate();
    assert!(job.worker < job.plan.actors);
    let whole_cpu = work::cpu();
    let whole = Instant::now();
    let template = Packet::decode(&hex::decode(&job.template_packet).unwrap()).unwrap();
    let (_, _, a, b) = support::settings()
        .consensus_maintenance_material()
        .unwrap();
    let setup_cpu = work::cpu();
    let setup = Instant::now();
    let producer = PreparedTask::new(&a, &b).unwrap();
    let setup_cpu_ns = work::elapsed(setup_cpu);
    let setup_wall_ns = setup.elapsed().as_nanos();
    fs::create_dir(job.output.join("prefix")).unwrap();
    fs::create_dir(job.output.join("pressure")).unwrap();
    let binary = binary_sha256();
    if job.plan.qualification {
        assert_eq!(binary, job.binary_sha256);
    }
    // SAFETY: getppid takes no pointers and only observes this process's parent.
    let ppid = unsafe { libc::getppid() };
    support::write_new(
        &job.output.join("ready.json"),
        &json!({"schema":SCHEMA,"kind":"actor-ready",
        "worker":job.worker,"pid":std::process::id(),"cgroup":cgroup(),"executable":std::env::current_exe().unwrap(),
        "ppid":ppid,"binary_sha256":binary,"source_commit":job.source_commit,"source_tree":job.source_tree,
        "producer":"prepared-generic","setup_calls":1,"setup_cpu_ns":setup_cpu_ns,"setup_wall_ns":setup_wall_ns}),
    );
    let prefix = wait(&job.prefix_marker, job.plan.readiness_seconds);
    let prefix_epoch = prefix["epoch_ns"].as_u64().unwrap();
    let prefix_end = prefix["end_ns"].as_u64().unwrap();
    let mut prefix_slots = Vec::new();
    let mut replay = None;
    let prefix_cpu = work::cpu();
    for slot in 0..job.plan.prefix_calls_per_actor {
        let index = job.plan.index(job.worker, slot);
        if support::monotonic() >= prefix_end {
            prefix_slots.push(json!({"slot":slot,"index":index,"status":"deadline-unoffered"}));
            continue;
        }
        let remaining = prefix_end.saturating_sub(support::monotonic());
        let acquired = work::acquire(
            &template,
            &producer,
            index,
            &job.output.join("prefix"),
            Instant::now() + Duration::from_nanos(remaining),
        );
        if let Some((packet, receipt)) = acquired {
            assert!(work::valid_construction(&receipt, &template, index));
            let reference = format!("prefix/{index:05}-construction.json");
            if replay.is_none() {
                replay = Some((packet.clone(), reference.clone()));
            }
            let row = call(
                &job,
                &packet,
                index,
                "prefix",
                prefix_epoch,
                prefix_end,
                &reference,
            );
            let file = format!("prefix/{index:05}-call.json");
            support::write_new(&job.output.join(&file), &row);
            prefix_slots.push(json!({"slot":slot,"index":index,"status":"called","file":file}));
        } else {
            prefix_slots.push(json!({"slot":slot,"index":index,"status":"construction-failed"}));
        }
    }
    let prefix_cpu_ns = work::elapsed(prefix_cpu);
    support::write_new(
        &job.output.join("prefix-finished.json"),
        &json!({"schema":SCHEMA,"kind":"actor-prefix",
        "worker":job.worker,"pid":std::process::id(),"slots":prefix_slots,"cpu_ns":prefix_cpu_ns,
        "finished_ns":support::monotonic()}),
    );
    let pressure = wait(
        &job.pressure_marker,
        job.plan.prefix_seconds + job.plan.cleanup_seconds,
    );
    let epoch = pressure["epoch_ns"].as_u64().unwrap();
    let end = pressure["end_ns"].as_u64().unwrap();
    let pressure_cpu = work::cpu();
    let mut pressure_slots = Vec::new();
    if job.mode != Mode::HonestOnly {
        for slot in 0..job.plan.pressure_calls_per_actor {
            let index = job
                .plan
                .index(job.worker, job.plan.prefix_calls_per_actor + slot);
            if support::monotonic() >= end {
                pressure_slots
                    .push(json!({"slot":slot,"index":index,"status":"window-ended-unoffered"}));
                continue;
            }
            let obtained = match job.mode {
                Mode::FreshIdentities => {
                    let remaining = end.saturating_sub(support::monotonic());
                    work::acquire(
                        &template,
                        &producer,
                        index,
                        &job.output.join("pressure"),
                        Instant::now() + Duration::from_nanos(remaining),
                    )
                    .map(|(p, r)| {
                        assert!(work::valid_construction(&r, &template, index));
                        (p, format!("pressure/{index:05}-construction.json"))
                    })
                }
                Mode::ReplayOnly => replay.clone(),
                Mode::HonestOnly => unreachable!(),
            };
            if let Some((packet, reference)) = obtained {
                let row = call(&job, &packet, index, "pressure", epoch, end, &reference);
                let file = format!("pressure/{index:05}-call.json");
                support::write_new(&job.output.join(&file), &row);
                pressure_slots
                    .push(json!({"slot":slot,"index":index,"status":"called","file":file}));
            } else {
                pressure_slots
                    .push(json!({"slot":slot,"index":index,"status":"construction-failed"}));
            }
        }
    }
    support::write_new(
        &job.output.join("report.json"),
        &json!({"schema":SCHEMA,"kind":"actor","worker":job.worker,
        "pid":std::process::id(),"mode":job.mode,"plan":job.plan,"prefix_slots":prefix_slots,"pressure_slots":pressure_slots,
        "prefix_cpu_ns":prefix_cpu_ns,"pressure_cpu_ns":work::elapsed(pressure_cpu),"entire_actor_cpu_ns":work::elapsed(whole_cpu),
        "entire_actor_wall_ns":whole.elapsed().as_nanos(),"cgroup":cgroup(),"rss":support::rss(),
        "scope":"real child process; setup/stage clocks nested in entire CPU; unoffered slots and unknown clocks retained; no independent-operator claim"}),
    );
}
