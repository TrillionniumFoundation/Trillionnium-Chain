//! Real v2 actor with bounded full-proof evidence and a separately reserved terminal.
use super::{
    actor,
    evidence::{self, Budget},
    exec_identity, identity_work as work, limits,
    plan::{Job, Mode},
    support,
};
use serde_json::{json, Value};
use std::{
    fs, io,
    net::SocketAddr,
    path::Path,
    time::{Duration, Instant},
};
use trnm_crypto_primitives::pon_work::PreparedTask;
use trnm_pon_node::{ingress::public_v3::Request, Packet};

pub const SCHEMA: &str = "native-public-v3-identity-churn-supplement-v2";
pub const JOB_SCHEMA: &str = "native-public-v3-identity-actor-job-v2";
const TERMINAL_BYTES: u64 = 64 * 1024;
struct Owner<'a> {
    job: &'a Job,
    metadata: Budget,
    terminal: Budget,
    stopped: bool,
    completed: bool,
}
impl<'a> Owner<'a> {
    fn new(job: &'a Job, job_bytes: u64) -> io::Result<Self> {
        let mut metadata = Budget::new(evidence::MIB / 2 - TERMINAL_BYTES);
        if job_bytes > metadata.limit {
            return Err(io::Error::other("v2 job exceeds actor metadata budget"));
        }
        metadata.used = job_bytes;
        Ok(Self {
            job,
            metadata,
            terminal: Budget::new(TERMINAL_BYTES),
            stopped: false,
            completed: false,
        })
    }
    fn fail(
        &mut self,
        stage: &str,
        index: Option<usize>,
        reason: &str,
        extra: Value,
    ) -> io::Result<()> {
        self.stopped = true;
        if self.terminal.used == 0 {
            let row = json!({"schema":SCHEMA,"kind":"actor-stage-terminal","worker":self.job.worker,
                "pid":std::process::id(),"stage":stage,"index":index,"reason":reason,"extra":extra,
                "observed_ns":support::monotonic(),"no_more_proofs_or_calls":true,"full_campaign_qualified":false});
            self.terminal.write(
                &self.job.output.join("stage-terminal.json"),
                &row,
                TERMINAL_BYTES,
            )?;
        }
        Ok(())
    }
    fn save(&mut self, name: &str, row: &Value) -> io::Result<()> {
        if let Err(error) =
            self.metadata
                .write(&self.job.output.join(name), row, self.metadata.limit)
        {
            self.fail(
                "metadata",
                None,
                &error.to_string(),
                json!({"file":name,"budget":self.metadata.summary()}),
            )?;
            return Err(error);
        }
        Ok(())
    }
}
impl Drop for Owner<'_> {
    fn drop(&mut self) {
        if !self.completed {
            let _ = self.fail(
                "owner-exit",
                None,
                "owner-left-before-final-report",
                json!({"thread_panicking":std::thread::panicking(),"generic_drop_diagnostic":true,
                    "original_error_status":"UNKNOWN until actor.log and parent exit reconciliation"}),
            );
        }
    }
}
struct Machine<'a> {
    owner: Owner<'a>,
    template: Packet,
    producer: PreparedTask,
    prefix: Budget,
    pressure: Budget,
    replay: Option<(Packet, String)>,
}
impl Machine<'_> {
    fn stage(&mut self, prefix: bool, window: &Value) -> io::Result<Vec<Value>> {
        let job = self.owner.job;
        let stage = if prefix { "prefix" } else { "pressure" };
        let epoch = window["epoch_ns"]
            .as_u64()
            .ok_or_else(|| io::Error::other("stage epoch"))?;
        let end = window["end_ns"]
            .as_u64()
            .ok_or_else(|| io::Error::other("stage end"))?;
        let mode = if prefix {
            Mode::FreshIdentities
        } else {
            job.mode
        };
        let count = if prefix {
            job.plan.prefix_calls_per_actor
        } else if mode == Mode::HonestOnly {
            0
        } else {
            job.plan.pressure_calls_per_actor
        };
        let mut slots = Vec::with_capacity(count);
        for slot in 0..count {
            let index = job.plan.index(
                job.worker,
                if prefix {
                    slot
                } else {
                    job.plan.prefix_calls_per_actor + slot
                },
            );
            if self.owner.stopped {
                slots.push(json!({"slot":slot,"index":index,"status":"evidence-stop-unoffered"}));
                continue;
            }
            if support::monotonic() >= end {
                slots.push(json!({"slot":slot,"index":index,"status":if prefix{"deadline-unoffered"}else{"window-ended-unoffered"}}));
                continue;
            }
            let budget = if prefix {
                &mut self.prefix
            } else {
                &mut self.pressure
            };
            if budget.remaining() < 2 * evidence::CALL_BYTES {
                budget.cap_reached = true;
                self.owner.fail(
                    stage,
                    Some(index),
                    "stage-budget-before-start",
                    json!({"budget":budget.summary(),"started":false}),
                )?;
                slots.push(json!({"slot":slot,"index":index,"status":"evidence-stop-unoffered"}));
                continue;
            }
            let obtained = match mode {
                Mode::FreshIdentities => {
                    let remaining = end.saturating_sub(support::monotonic());
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        work::acquire_v2(
                            &self.template,
                            &self.producer,
                            index,
                            &job.output.join(stage),
                            Instant::now() + Duration::from_nanos(remaining),
                            budget,
                        )
                    }));
                    let found = match result {
                        Ok(found) => found,
                        Err(payload) => {
                            budget.poisoned = true;
                            let reason = payload
                                .downcast_ref::<String>()
                                .cloned()
                                .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                                .unwrap_or_else(|| "non-string construction panic".into());
                            self.owner.fail(stage,Some(index),"construction-panicked",
                                json!({"error":reason,"budget":budget.summary(),
                                    "started":job.output.join(format!("{stage}/{index:05}-started.json")).exists()}))?;
                            None
                        }
                    };
                    if budget.cap_reached || budget.poisoned {
                        self.owner.fail(stage,Some(index),"construction-evidence-stop",json!({"budget":budget.summary(),
                            "started":job.output.join(format!("{stage}/{index:05}-started.json")).exists()}))?;
                    }
                    found.map(|(packet, receipt)| {
                        assert!(work::valid_construction_v2(&receipt, &self.template, index));
                        (packet, format!("{stage}/{index:05}-construction.json"))
                    })
                }
                Mode::ReplayOnly => self.replay.clone(),
                Mode::HonestOnly => unreachable!(),
            };
            let Some((packet, reference)) = obtained else {
                slots.push(json!({"slot":slot,"index":index,"status":"construction-failed"}));
                continue;
            };
            if self.owner.stopped {
                slots.push(json!({"slot":slot,"index":index,"status":"evidence-stop-unoffered"}));
                continue;
            }
            if prefix && self.replay.is_none() {
                self.replay = Some((packet.clone(), reference.clone()));
            }
            let row = call(job, &packet, index, stage, epoch, end, &reference);
            let file = format!("{stage}/{index:05}-call.json");
            if let Err(error) = budget.write(&job.output.join(&file), &row, evidence::CALL_BYTES) {
                self.owner.fail(stage,Some(index),"call-evidence-write",json!({"file":file,"error":error.to_string(),"unpersisted_call":row,"budget":budget.summary()}))?;
                slots.push(json!({"slot":slot,"index":index,"status":"called-evidence-failed","file":file}));
            } else {
                slots.push(json!({"slot":slot,"index":index,"status":"called","file":file}));
            }
        }
        Ok(slots)
    }
}
fn wait(path: &Path, seconds: u64) -> io::Result<Value> {
    let end = Instant::now() + Duration::from_secs(seconds);
    while !path.exists() && Instant::now() < end {
        support::ready_sleep();
    }
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}
fn call(
    job: &Job,
    packet: &Packet,
    index: usize,
    stage: &str,
    epoch: u64,
    end: u64,
    reference: &str,
) -> Value {
    let row = support::call(
        job.address.parse::<SocketAddr>().unwrap(),
        &support::settings(),
        Request::Submit {
            packet: hex::encode(packet.encode().unwrap()),
        },
        80 + (job.worker % 150) as u8,
        epoch,
        end,
    );
    json!({"schema":SCHEMA,"kind":"call","stage":stage,"worker":job.worker,"index":index,"construction_ref":reference,
        "absolute_started_ns":epoch+row["started_ns"].as_u64().unwrap(),"absolute_ended_ns":epoch+row["ended_ns"].as_u64().unwrap(),"call":row})
}
pub fn run(job_path: &Path) -> io::Result<()> {
    let input = exec_identity::Input::read(job_path)?;
    let mut job: Job = serde_json::from_slice(&input.bytes)?;
    assert_eq!(job.schema, JOB_SCHEMA);
    job.plan.validate();
    assert!(job.worker < job.plan.actors);
    let whole_cpu = work::cpu();
    let whole = Instant::now();
    let job_bytes = input.bytes.len() as u64;
    let (output, phase) = input.paths();
    job.output = output;
    job.prefix_marker = phase.join("prefix-start.json");
    job.pressure_marker = phase.join("pressure-start.json");
    let mut owner = Owner::new(&job, job_bytes)?;
    let execution = input
        .verify(&serde_json::to_value(&job.plan)?, &job.binary_sha256)
        .inspect_err(|error| {
            let _ = owner.fail(
                "startup",
                None,
                "actual-executable-or-plan",
                json!({"error":error.to_string(),"proofs_started":false}),
            );
        })?;
    let installed = match limits::install(true) {
        Ok(value) => value,
        Err(error) => {
            owner.fail(
                "startup",
                None,
                "owned-process-limits",
                json!({"error":error.to_string()}),
            )?;
            return Err(error);
        }
    };
    owner.save("process-limits.json", &installed)?;
    let template = Packet::decode(&hex::decode(&job.template_packet).unwrap()).unwrap();
    let (_, _, a, b) = support::settings()
        .consensus_maintenance_material()
        .unwrap();
    let setup_cpu = work::cpu();
    let setup = Instant::now();
    let producer = PreparedTask::new(&a, &b).unwrap();
    let setup_cpu_ns = work::elapsed(setup_cpu);
    let setup_wall_ns = setup.elapsed().as_nanos();
    fs::create_dir(job.output.join("prefix"))?;
    fs::create_dir(job.output.join("pressure"))?;
    let binary = execution.binary_sha256;
    if job.plan.qualification {
        assert_eq!(binary, job.binary_sha256);
    }
    // SAFETY: getppid has no input pointers and observes only this owned child.
    let ppid = unsafe { libc::getppid() };
    owner.save("ready.json",&json!({"schema":SCHEMA,"kind":"actor-ready","worker":job.worker,
        "pid":std::process::id(),"ppid":ppid,"cgroup":actor::cgroup(),"executable":std::env::current_exe()?,
        "binary_sha256":binary,"execution_binding":execution.receipt,"source_commit":job.source_commit,"source_tree":job.source_tree,
        "producer":"prepared-generic","setup_calls":1,"setup_cpu_ns":setup_cpu_ns,"setup_wall_ns":setup_wall_ns}))?;
    let pressure_limit = match job.mode {
        Mode::ReplayOnly => evidence::REPLAY_BYTES,
        Mode::FreshIdentities => evidence::FRESH_BYTES,
        Mode::HonestOnly => 0,
    };
    let mut machine = Machine {
        owner,
        template,
        producer,
        prefix: Budget::new(evidence::PREFIX_BYTES),
        pressure: Budget::new(pressure_limit),
        replay: None,
    };
    let prefix = wait(&job.prefix_marker, job.plan.readiness_seconds)?;
    let prefix_cpu = work::cpu();
    let prefix_slots = machine.stage(true, &prefix)?;
    let prefix_cpu_ns = work::elapsed(prefix_cpu);
    machine.owner.save("prefix-finished.json",&json!({"schema":SCHEMA,"kind":"actor-prefix","worker":job.worker,
        "pid":std::process::id(),"slots":prefix_slots,"cpu_ns":prefix_cpu_ns,"finished_ns":support::monotonic(),
        "stage_budget":machine.prefix.summary(),"evidence_stopped":machine.owner.stopped}))?;
    let pressure = wait(
        &job.pressure_marker,
        job.plan.prefix_seconds + job.plan.cleanup_seconds,
    )?;
    let pressure_cpu = work::cpu();
    let pressure_slots = machine.stage(false, &pressure)?;
    let report = json!({"schema":SCHEMA,"kind":"actor","worker":job.worker,"pid":std::process::id(),"mode":job.mode,"plan":job.plan,
        "prefix_slots":prefix_slots,"pressure_slots":pressure_slots,"prefix_cpu_ns":prefix_cpu_ns,
        "pressure_cpu_ns":work::elapsed(pressure_cpu),"entire_actor_cpu_ns":work::elapsed(whole_cpu),"entire_actor_wall_ns":whole.elapsed().as_nanos(),
        "cgroup":actor::cgroup(),"rss":support::rss(),"process_after":limits::observation()?,
        "prefix_budget":machine.prefix.summary(),"pressure_budget":machine.pressure.summary(),"evidence_stopped":machine.owner.stopped,
        "metadata_before_report":machine.owner.metadata.summary(),"terminal_budget":machine.owner.terminal.summary(),
        "full_ledger_implemented":limits::full_route_ready(),"scope":"actual child, complete proof bytes and original calls; full qualification remains closed"});
    machine.owner.save("report.json", &report)?;
    machine.owner.completed = true;
    Ok(())
}

#[test]
fn exhausted_metadata_still_retains_a_terminal_without_reusing_the_poisoned_owner() {
    let out = tempfile::tempdir().unwrap();
    let job = Job {
        schema: JOB_SCHEMA.into(),
        plan: super::plan::Plan::control(),
        mode: Mode::FreshIdentities,
        worker: 0,
        address: "127.0.0.1:1".into(),
        template_packet: String::new(),
        output: out.path().into(),
        prefix_marker: out.path().join("prefix"),
        pressure_marker: out.path().join("pressure"),
        source_commit: String::new(),
        source_tree: String::new(),
        binary_sha256: String::new(),
    };
    let mut owner = Owner::new(&job, 0).unwrap();
    owner.metadata = Budget::new(1);
    assert!(owner
        .save("ready.json", &json!({"too_large":true}))
        .is_err());
    assert!(
        owner.stopped && owner.metadata.poisoned && out.path().join("stage-terminal.json").exists()
    );
    let first = fs::read(out.path().join("stage-terminal.json")).unwrap();
    assert!(owner.save("report.json", &json!({"later":true})).is_err());
    assert_eq!(
        fs::read(out.path().join("stage-terminal.json")).unwrap(),
        first
    );
    assert!(!out.path().join("ready.json").exists() && !out.path().join("report.json").exists());
}
