//! Linux observations and explicitly selected pure-PoN v2 clients. No policy
//! fallback, extra credit, relaxed deadline, or guest execution authority.
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read, Write},
    net::SocketAddr,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use trnm_crypto_primitives::{pon_work, sign_hex, signing_key_from_hex};
use trnm_pon_node::{
    development_public,
    ingress::{self, public_v3, DevelopmentIdentity},
    Settings,
};
use trnm_protocol::pon_wire::{hash, Envelope, Header};

#[path = "pure_process_cost_v1.rs"]
pub mod process_cost;

pub const WINDOW_NS: u64 = 30_000_000_000;
pub const ATTACKERS: usize = 24;
pub const CALL_CAP: usize = 480;
pub const ROUNDS: usize = 3;
pub const ATTACKER_COST_SCHEMA: &str = "pon-pure-attacker-cost-v1";
pub const COST_BINDING_SCHEMA: &str = "pon-pure-attacker-cost-binding-v1";
pub const COST_BINDING_FILE: &str = "attacker-cost-binding-v1.json";
pub const COST_CPU_WALL_TOLERANCE_NS: u64 = 1_000_000;
const COST_CAPTURE_BUDGET_NS: u64 = 5_000_000_000;
const ACTOR_REPORT_LIMIT: u64 = 64 * 1024 * 1024;
const ACTOR_COST_LIMIT: u64 = 2 * 1024 * 1024;
const COST_BINDING_LIMIT: usize = 1024 * 1024;

/// A diagnostic sample of this actor thread, with the CPU read bracketed by
/// monotonic reads. These observations never change a request or phase deadline.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct ThreadCostBoundary {
    pub started_monotonic_ns: u64,
    pub thread_cpu_ns: Option<u64>,
    pub ended_monotonic_ns: u64,
}
impl ThreadCostBoundary {
    pub fn capture() -> Self {
        let started_monotonic_ns = monotonic();
        let thread_cpu_ns = thread_cpu();
        Self {
            started_monotonic_ns,
            thread_cpu_ns,
            ended_monotonic_ns: monotonic(),
        }
    }
}
pub fn thread_cpu_between(start: ThreadCostBoundary, end: ThreadCostBoundary) -> Option<u64> {
    start
        .thread_cpu_ns
        .zip(end.thread_cpu_ns)
        .and_then(|(a, b)| b.checked_sub(a))
}

/// Bounded diagnostic retention, not another admission or resource owner. The
/// original loop can produce at most CALL_CAP preparations, including its final
/// unissued preparation. Missing CPU observations remain null, never zero.
#[derive(Default)]
pub struct AttackerCostLedger {
    preparations: Vec<Value>,
}
impl AttackerCostLedger {
    pub fn new() -> Self {
        Self {
            preparations: Vec::with_capacity(CALL_CAP),
        }
    }
    pub fn retain(
        &mut self,
        mut preparation: Value,
        call_entry_monotonic_ns: Option<u64>,
        call: Option<&Value>,
    ) {
        assert!(
            self.preparations.len() < CALL_CAP,
            "preparation evidence cap"
        );
        assert_eq!(
            preparation["sequence"].as_u64(),
            Some(self.preparations.len() as u64),
            "every preparation retained exactly once"
        );
        assert!(call.is_none() || call_entry_monotonic_ns.is_some());
        preparation["disposition"] = json!(if call.is_some() {
            "issued"
        } else if call_entry_monotonic_ns.is_some() {
            "phase_closed_at_call_entry"
        } else {
            "phase_closed_after_preparation"
        });
        preparation["call_entry_monotonic_ns"] = json!(call_entry_monotonic_ns);
        preparation["call_index"] = json!(call.map(|_| self.preparations.len()));
        preparation["call_body_digest"] = json!(call.map(|row| &row["body_digest"]));
        self.preparations.push(preparation);
    }
    pub fn into_value(self) -> Value {
        let issued = self
            .preparations
            .iter()
            .filter(|p| p["disposition"] == "issued")
            .count();
        let known_cpu = self
            .preparations
            .iter()
            .filter_map(|p| p["preparation_thread_cpu_ns"].as_u64())
            .try_fold(0_u64, u64::checked_add)
            .expect("bounded preparation CPU sum");
        let unknown_cpu = self
            .preparations
            .iter()
            .filter(|p| p["preparation_thread_cpu_ns"].is_null())
            .count();
        let trials = self
            .preparations
            .iter()
            .map(|p| p["generation_trials"].as_u64().unwrap())
            .try_fold(0_u64, u64::checked_add)
            .expect("bounded generation trials");
        json!({"schema":ATTACKER_COST_SCHEMA,
            "summary":{"prepared_attempts":self.preparations.len(),"issued_calls":issued,
                "unissued_preparations":self.preparations.len()-issued,
                "loop_generation_trials":trials,"known_preparation_thread_cpu_ns":known_cpu,
                "unknown_preparation_cpu_count":unknown_cpu,
                "preparation_thread_cpu_ns":if unknown_cpu==0 {Some(known_cpu)} else {None}},
            "preparations":self.preparations})
    }
}

pub(super) fn cost_directory(path: &Path) -> io::Result<fs::File> {
    let flags = rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::DIRECTORY
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::CLOEXEC;
    let mut held: fs::File = rustix::fs::open(
        if path.is_absolute() { "/" } else { "." },
        flags,
        rustix::fs::Mode::empty(),
    )?
    .into();
    for component in path.components() {
        match component {
            Component::Normal(name) => {
                held = rustix::fs::openat(&held, name, flags, rustix::fs::Mode::empty())?.into();
            }
            Component::RootDir | Component::CurDir => {}
            _ => return Err(io::Error::other("COST_DIRECTORY_TRAVERSAL")),
        }
    }
    Ok(held)
}

pub(super) fn cost_file_bytes(
    directory: &fs::File,
    name: &str,
    limit: u64,
    deadline: Instant,
) -> io::Result<Vec<u8>> {
    if Instant::now() >= deadline {
        return Err(io::Error::other("COST_CAPTURE_DEADLINE"));
    }
    let mut file: fs::File = rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?
    .into();
    let before = file.metadata()?;
    if !before.is_file() || before.len() > limit {
        return Err(io::Error::other("COST_FILE_TYPE_OR_BYTES"));
    }
    let mut raw = Vec::new();
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::other("COST_CAPTURE_DEADLINE"));
        }
        let count = file.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        if raw.len() as u64 + count as u64 > limit {
            return Err(io::Error::other("COST_FILE_TYPE_OR_BYTES"));
        }
        raw.extend_from_slice(&chunk[..count]);
    }
    let after = file.metadata()?;
    if Instant::now() >= deadline
        || raw.len() as u64 != before.len()
        || !raw.ends_with(b"\n")
        || (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        )
    {
        return Err(io::Error::other("COST_FILE_CHANGED_OR_INCOMPLETE"));
    }
    Ok(raw)
}

fn captured_cost_file(
    directory: Option<&fs::File>,
    name: &str,
    limit: u64,
    deadline: Instant,
) -> (Value, Option<Value>) {
    let raw = directory
        .ok_or_else(|| io::Error::other("COST_ACTOR_DIRECTORY_UNAVAILABLE"))
        .and_then(|directory| cost_file_bytes(directory, name, limit, deadline));
    match raw {
        Ok(raw) => {
            let parsed = serde_json::from_slice::<Value>(&raw);
            let error = parsed.as_ref().err().map(|_| "COST_JSON_INCOMPLETE");
            (
                json!({"bytes":raw.len(),"sha256":hex::encode(Sha256::digest(&raw)),"error":error}),
                parsed.ok(),
            )
        }
        Err(error) => (
            json!({"bytes":null,"sha256":null,"error":error.to_string()}),
            None,
        ),
    }
}

/// Parent capture happens only after original actor joins and service stop.
/// All opens walk fixed basenames without following symlinks. The read deadline
/// is cooperative between bounded reads, not preemption of a filesystem syscall.
/// This binds observed bytes; a hostile host can forge all files and clocks.
pub fn capture_attacker_cost_bindings(path: &Path, report: &Value) -> io::Result<()> {
    let started = monotonic();
    let deadline = Instant::now() + Duration::from_nanos(COST_CAPTURE_BUDGET_NS);
    let directory = cost_directory(path)?;
    let wrappers = report["actors"]
        .as_array()
        .ok_or_else(|| io::Error::other("COST_ACTOR_LIST"))?;
    let expected = if report["phase"] == "baseline" {
        0
    } else {
        ATTACKERS
    };
    let mut rows = Vec::new();
    for (actor, wrapper) in wrappers.iter().enumerate() {
        let name = format!("actor-{actor}");
        let child = rustix::fs::openat(
            &directory,
            name.as_str(),
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map(fs::File::from);
        let (report_file, actor_report) = captured_cost_file(
            child.as_ref().ok(),
            "report.json",
            ACTOR_REPORT_LIMIT,
            deadline,
        );
        let (cost_file, cost) = captured_cost_file(
            child.as_ref().ok(),
            "attacker-cost-v1.json",
            ACTOR_COST_LIMIT,
            deadline,
        );
        let matches_phase = actor_report
            .as_ref()
            .is_some_and(|value| *value == wrapper["report"]);
        let result = actor_report.as_ref().map(|value| &value["result"]);
        let report_calls = result
            .and_then(|value| value["calls"].as_array())
            .map(Vec::len);
        let report_finished = result.and_then(|value| value["finished_ns"].as_u64());
        let terminal = cost.as_ref().map(|value| value["loop_terminal"].clone());
        let counts = cost.as_ref().map(|value| value["summary"].clone());
        let complete = wrapper["exit_success"] == true
            && wrapper["parent_forced_kill"] == false
            && matches_phase
            && report_calls.is_some()
            && report_finished.is_some()
            && actor_report
                .as_ref()
                .is_some_and(|value| value["error"].is_null())
            && cost.as_ref().is_some_and(|value| {
                value["schema"] == ATTACKER_COST_SCHEMA
                    && value["actor"].as_u64() == Some(actor as u64)
                    && value["pid"] == wrapper["pid"]
                    && value["summary"].is_object()
                    && value["loop_terminal"].is_object()
            });
        rows.push(json!({"actor":actor,"actor_directory":name,"pid":wrapper["pid"],
            "exit_success":wrapper["exit_success"],"parent_forced_kill":wrapper["parent_forced_kill"],
            "files":{"report.json":report_file,"attacker-cost-v1.json":cost_file},
            "actor_report_matches_phase":matches_phase,"report_issued_calls":report_calls,
            "report_finished_ns":report_finished,"sidecar_summary":counts,"sidecar_terminal":terminal,
            "capture_complete":complete}));
    }
    let ended = monotonic();
    let complete = wrappers.len() == expected
        && rows.iter().all(|row| row["capture_complete"] == true)
        && ended.saturating_sub(started) <= COST_CAPTURE_BUDGET_NS;
    let value = json!({"schema":COST_BINDING_SCHEMA,"phase":report["phase"],
        "parent_pid":std::process::id(),"started_monotonic_ns":started,"ended_monotonic_ns":ended,
        "read_budget_ns":COST_CAPTURE_BUDGET_NS,"actor_report_limit":ACTOR_REPORT_LIMIT,
        "actor_cost_limit":ACTOR_COST_LIMIT,"expected_actors":expected,"actors":rows,
        "capture_complete":complete,"physical_authentication":false,
        "scope":"Parent capture of fixed actor file bytes after original joins and service stop; independent SHA256/length/terminal/count binding, not hostile-host authenticity or CPU attestation. Read deadline is cooperative between bounded filesystem reads."});
    let mut raw = serde_json::to_vec(&value)?;
    raw.push(b'\n');
    if raw.len() > COST_BINDING_LIMIT {
        return Err(io::Error::other("COST_BINDING_BYTES"));
    }
    let mut file: fs::File = rustix::fs::openat(
        &directory,
        COST_BINDING_FILE,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::from_bits_truncate(0o600),
    )?
    .into();
    file.write_all(&raw)?;
    file.sync_all()
}

/// Single-reap whole-actor observations, published after the original service
/// shutdown. The old v3 service report and its deadline predicates stay intact.
pub fn capture_actor_process_costs(
    path: &Path,
    report: &Value,
    records: &[Value],
) -> io::Result<()> {
    const LOG_LIMIT: u64 = 1024 * 1024;
    let started = monotonic();
    let deadline = Instant::now() + Duration::from_nanos(COST_CAPTURE_BUDGET_NS);
    let directory = cost_directory(path)?;
    let wrappers = report["actors"]
        .as_array()
        .ok_or_else(|| io::Error::other("PROCESS_COST_ACTOR_LIST"))?;
    let expected = if report["phase"] == "baseline" {
        0
    } else {
        ATTACKERS
    };
    let mut rows = Vec::new();
    for (index, wrapper) in wrappers.iter().enumerate() {
        let name = format!("actor-{index}");
        let child = rustix::fs::openat(
            &directory,
            name.as_str(),
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map(fs::File::from);
        let mut files = serde_json::Map::new();
        let mut complete = records.get(index).is_some();
        for (file, limit) in [
            ("report.json", ACTOR_REPORT_LIMIT),
            ("attacker-cost-v1.json", ACTOR_COST_LIMIT),
            ("actor.log", LOG_LIMIT),
            ("actor-family-observation-v1.json", LOG_LIMIT),
        ] {
            let value = child
                .as_ref()
                .map_err(|_| io::Error::other("PROCESS_COST_DIRECTORY"))
                .and_then(|held| cost_file_bytes(held, file, limit, deadline));
            let identity = match value {
                Ok(raw) => {
                    json!({"bytes":raw.len(),"sha256":hex::encode(Sha256::digest(&raw)),"error":null})
                }
                Err(error) => {
                    complete = false;
                    json!({"bytes":null,"sha256":null,"error":error.to_string()})
                }
            };
            files.insert(file.to_owned(), identity);
        }
        let cost = records.get(index);
        complete &= cost.is_some_and(|record| {
            record["pid"] == wrapper["pid"]
                && record["exit_success"] == wrapper["exit_success"]
                && record["parent_forced_kill"] == wrapper["parent_forced_kill"]
        });
        rows.push(
            json!({"actor":index,"actor_directory":name,"pid":wrapper["pid"],
            "cost":cost,"files":files,"capture_complete":complete}),
        );
    }
    let binding = cost_file_bytes(
        &directory,
        COST_BINDING_FILE,
        COST_BINDING_LIMIT as u64,
        deadline,
    );
    let (binding, binding_ok) = match binding {
        Ok(raw) => (
            json!({"bytes":raw.len(),"sha256":hex::encode(Sha256::digest(&raw)),"error":null}),
            true,
        ),
        Err(error) => (
            json!({"bytes":null,"sha256":null,"error":error.to_string()}),
            false,
        ),
    };
    let ended = monotonic();
    let complete = wrappers.len() == expected
        && records.len() == expected
        && binding_ok
        && rows.iter().all(|row| row["capture_complete"] == true)
        && ended.saturating_sub(started) <= COST_CAPTURE_BUDGET_NS;
    let value = json!({"schema":"pon-pure-attacker-process-cost-v1","phase":report["phase"],
        "parent_pid":std::process::id(),"epoch_monotonic_ns":report["epoch_monotonic_ns"],
        "started_monotonic_ns":started,"ended_monotonic_ns":ended,
        "read_budget_ns":COST_CAPTURE_BUDGET_NS,"actor_report_limit":ACTOR_REPORT_LIMIT,
        "actor_cost_limit":ACTOR_COST_LIMIT,"actor_log_limit":LOG_LIMIT,
        "expected_actors":expected,"actors":rows,"thread_cost_parent_binding":binding,
        "capture_complete":complete,"physical_authentication":false,
        "scope":"Parent single-reap wait4 observations for each original actor PID, bound to complete report, thread-cost sidecar and final log bytes after original cleanup. Whole actor process costs are separate from receiver costs; nested CPU is not added twice."});
    let mut raw = serde_json::to_vec(&value)?;
    raw.push(b'\n');
    if raw.len() > COST_BINDING_LIMIT {
        return Err(io::Error::other("PROCESS_COST_BINDING_BYTES"));
    }
    let mut file: fs::File = rustix::fs::openat(
        &directory,
        "attacker-process-cost-v1.json",
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::from_bits_truncate(0o600),
    )?
    .into();
    file.write_all(&raw)?;
    file.sync_all()
}

/// A new independent binding, so historical proc-only files and their failures
/// remain immutable. Parent cost manifests are themselves byte-bound here.
pub fn capture_child_ownership_binding(
    path: &Path,
    report: &Value,
    receiver: bool,
) -> io::Result<()> {
    let started = monotonic();
    let deadline = Instant::now() + Duration::from_secs(5);
    let held = cost_directory(path)?;
    let (kind, filename, parent_file, probe_file) = if receiver {
        (
            "receiver",
            "receiver-child-ownership-binding-v1.json",
            "receiver-owner-binding-v1.json",
            "receiver-child-ownership-v1.json",
        )
    } else {
        (
            "actor",
            "attacker-child-ownership-binding-v1.json",
            "attacker-process-cost-v1.json",
            "actor-child-ownership-v1.json",
        )
    };
    let parent_raw = cost_file_bytes(&held, parent_file, COST_BINDING_LIMIT as u64, deadline);
    let (parent_binding, parent_complete) = match parent_raw {
        Ok(raw) => (
            json!({"bytes":raw.len(),"sha256":hex::encode(Sha256::digest(&raw)),"error":null}),
            true,
        ),
        Err(e) => (
            json!({"bytes":null,"sha256":null,"error":e.to_string()}),
            false,
        ),
    };
    let expected = if receiver {
        1
    } else if report["phase"] == "baseline" {
        0
    } else {
        ATTACKERS
    };
    let pids: Vec<_> = if receiver {
        vec![report["receiver_pid"].clone()]
    } else {
        report["actors"]
            .as_array()
            .ok_or_else(|| io::Error::other("CHILD_PROBE_ACTORS"))?
            .iter()
            .map(|a| a["pid"].clone())
            .collect()
    };
    let mut rows = Vec::new();
    for (index, pid) in pids.iter().enumerate() {
        let subdir = if receiver {
            None
        } else {
            Some(format!("actor-{index}"))
        };
        let child = subdir.as_ref().map(|name| {
            rustix::fs::openat(
                &held,
                name.as_str(),
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map(fs::File::from)
        });
        let directory = if receiver {
            Some(&held)
        } else {
            child.as_ref().and_then(|v| v.as_ref().ok())
        };
        let captured = directory
            .ok_or_else(|| io::Error::other("CHILD_PROBE_DIRECTORY"))
            .and_then(|directory| cost_file_bytes(directory, probe_file, 1024 * 1024, deadline));
        let (binding, complete) = match captured {
            Ok(raw) => {
                let parsed = serde_json::from_slice::<Value>(&raw);
                let valid = parsed.as_ref().is_ok_and(|v| {
                    v["schema"] == "pon-child-ownership-probe-v1" && v["pid"] == *pid
                });
                (
                    json!({"bytes":raw.len(),"sha256":hex::encode(Sha256::digest(&raw)),"error":null}),
                    valid,
                )
            }
            Err(e) => (
                json!({"bytes":null,"sha256":null,"error":e.to_string()}),
                false,
            ),
        };
        rows.push(json!({"index":index,"pid":pid,"directory":subdir,"file":probe_file,"binding":binding,"capture_complete":complete}));
    }
    let ended = monotonic();
    let complete = parent_complete
        && rows.len() == expected
        && rows.iter().all(|r| r["capture_complete"] == true)
        && ended.saturating_sub(started) <= COST_CAPTURE_BUDGET_NS;
    let value = json!({"schema":"pon-child-ownership-binding-v1","kind":kind,"phase":report["phase"],
        "parent_pid":std::process::id(),"parent_cost_file":parent_file,"parent_cost_binding":parent_binding,
        "started_monotonic_ns":started,"ended_monotonic_ns":ended,"read_budget_ns":COST_CAPTURE_BUDGET_NS,
        "probe_limit":1024*1024,"expected_children":expected,"children":rows,"capture_complete":complete,
        "physical_authentication":false,"scope":"Parent exact-byte binding of independent non-reaping child-ownership probes after single-reap cost capture; not authentication or a replacement for preserved procfs failures."});
    let mut raw = serde_json::to_vec(&value)?;
    raw.push(b'\n');
    if raw.len() > COST_BINDING_LIMIT {
        return Err(io::Error::other("CHILD_PROBE_BINDING_BYTES"));
    }
    let mut file: fs::File = rustix::fs::openat(
        &held,
        filename,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::from_bits_truncate(0o600),
    )?
    .into();
    file.write_all(&raw)?;
    file.sync_all()
}

pub fn clock(id: rustix::time::ClockId) -> Option<u64> {
    let time = rustix::time::clock_gettime_dynamic(rustix::time::DynamicClockId::Known(id)).ok()?;
    let nanos = u64::try_from(time.tv_nsec).ok()?;
    (nanos < 1_000_000_000)
        .then_some(u64::try_from(time.tv_sec).ok()?)?
        .checked_mul(1_000_000_000)?
        .checked_add(nanos)
}
pub fn monotonic() -> u64 {
    clock(rustix::time::ClockId::Monotonic).expect("Linux monotonic observation")
}
pub fn thread_cpu() -> Option<u64> {
    clock(rustix::time::ClockId::ThreadCPUTime)
}
pub fn cpu_delta(start: Option<u64>) -> Option<u64> {
    start.zip(thread_cpu()).and_then(|(a, b)| b.checked_sub(a))
}
pub fn pause() {
    thread::sleep(Duration::from_millis(2));
}
pub fn now() -> u64 {
    ingress::now().unwrap()
}
pub fn identity(seed: u8) -> DevelopmentIdentity {
    DevelopmentIdentity::from_secret_hex(&hex::encode([seed; 32])).unwrap()
}
pub fn policy() -> public_v3::PublicPolicy {
    public_v3::PublicPolicy::pure_pon(Duration::from_secs(2)).unwrap()
}
pub fn policy_observation() -> Value {
    json!({"transport_profile":public_v3::PURE_PON_V2_PROFILE,
        "policy_id":hex::encode(policy().pure_admission_v2_id()),
        "ticket_bits":0,"lifetime_ms":2000,"call_deadline_ns":2_000_000_000u64})
}
pub fn settings() -> Settings {
    Settings::development_with_profiles(
        Some(1_750_000_000),
        "native-public-evaluation-dev-v1",
        trnm_mvcc_fee::continuity_v1::PROFILE,
    )
    .unwrap()
}
pub fn signed_transfer(settings: &Settings, nonce: u64, recipient: [u8; 32]) -> Vec<u8> {
    let mut payload = recipient.to_vec();
    payload.extend_from_slice(&1_u64.to_le_bytes());
    let mut env = Envelope {
        network: settings.network(),
        sender: development_public(0).unwrap(),
        nonce,
        expiry: 10000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()]))).unwrap();
    env.signature = hex::decode(sign_hex(&key, &env.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    env.encode().unwrap()
}
pub fn write_new(path: &Path, value: &Value) {
    let bytes = serde_json::to_vec(value).unwrap();
    assert!(bytes.len() <= 64 * 1024 * 1024, "bounded evidence file");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    file.write_all(&bytes).unwrap();
    file.write_all(b"\n").unwrap();
    file.sync_all().unwrap();
}
pub fn body_digest(request: &public_v3::Request) -> [u8; 32] {
    hash(
        b"public-request-body-v3",
        &[&serde_json::to_vec(request).unwrap()],
    )
}
pub fn phase_entry_ns(epoch: u64, sampled: u64) -> Option<u64> {
    sampled
        .checked_sub(epoch)
        .filter(|offset| *offset < WINDOW_NS)
}

/// The Instant anchor must be captured before the monotonic sample. Adding
/// only the original remaining allowance to that earlier anchor is
/// conservative: sampling, argument preparation and scheduling cannot buy
/// additional time. A closed window never invokes `issue` or creates a call
/// row; a call issued inside the window keeps its full outcome, even if late.
pub fn within_call_window<T>(
    epoch: u64,
    anchor: Instant,
    started: u64,
    issue: impl FnOnce(Instant, u64, u64) -> T,
) -> Option<T> {
    let started_ns = phase_entry_ns(epoch, started)?;
    let remaining = WINDOW_NS - started_ns;
    let allowance = remaining.min(2_000_000_000);
    let deadline = anchor.checked_add(Duration::from_nanos(allowance))?;
    Some(issue(deadline, started_ns, started_ns + allowance))
}

pub fn call(
    address: SocketAddr,
    settings: &Settings,
    request: public_v3::Request,
    who: u8,
    epoch: u64,
) -> Option<Value> {
    call_with_entry_observation(address, settings, request, who, epoch).0
}

/// Preserve the original entry sample even when the original call window is
/// closed. This only exposes a diagnostic of the existing gate; it cannot issue
/// an extra call or extend the original absolute deadline.
pub fn call_with_entry_observation(
    address: SocketAddr,
    settings: &Settings,
    request: public_v3::Request,
    who: u8,
    epoch: u64,
) -> (Option<Value>, u64) {
    // Call arguments can take time to construct after the caller's loop
    // check. Check the original phase again here, before any client API.
    let anchor = Instant::now();
    let started = monotonic();
    let result = within_call_window(
        epoch,
        anchor,
        started,
        |deadline, started_ns, deadline_ns| {
            let start_cpu = thread_cpu();
            let (reply, metrics) = public_v3::call_public_pure_pon_v2(
                address,
                &request,
                settings,
                identity(71).public_key(),
                &identity(who),
                policy(),
                Some(deadline),
            );
            let ended = monotonic();
            let (status, response, error) = match reply {
                Ok(reply) => (
                    if reply.ok { "ok" } else { "refused" },
                    Some(serde_json::to_value(reply).unwrap()),
                    None,
                ),
                Err(error) => ("error", None, Some(error.to_string())),
            };
            json!({"started_ns":started_ns,"ended_ns":ended.saturating_sub(epoch),
            "deadline_ns":deadline_ns,
            "thread_cpu_ns":cpu_delta(start_cpu),"status":status,"response":response,"error":error,
            "body_digest":hex::encode(body_digest(&request)),"metrics":metrics})
        },
    );
    (result, started)
}
pub fn on_time(row: &Value) -> bool {
    row["status"] == "ok"
        && row["ended_ns"]
            .as_u64()
            .zip(row["deadline_ns"].as_u64())
            .is_some_and(|(end, deadline)| end < WINDOW_NS && end <= deadline)
}

/// A/B and, optionally, C are acquired once per actor. No correct transcript
/// for the submitted challenge is purchased. Every rejected target trial is
/// reconstructible from the retained challenge, call index and trial count.
pub fn false_proof(prefix: &[u8], header: &Header, call: u64) -> (Vec<u8>, u64) {
    let challenge = header.challenge();
    for trial in 0_u64..4096 {
        let trace = hash(
            b"pure-pressure-false-trace-v2",
            &[&challenge, &call.to_le_bytes(), &trial.to_le_bytes()],
        );
        if hash(b"ticket", &[&challenge, &trace]) <= header.target {
            let mut proof = prefix.to_vec();
            proof.extend(trace);
            pon_work::precheck_proof_statement(challenge, header.work_task, header.target, &proof)
                .unwrap();
            return (proof, trial + 1);
        }
    }
    panic!("false-trace target search exhausted all 4096 trials");
}

pub struct Actor {
    child: process_cost::ObservedChild,
    path: PathBuf,
}
impl Actor {
    pub fn spawn(path: &Path, job: Value) -> Self {
        fs::create_dir(path).unwrap();
        write_new(&path.join("job.json"), &job);
        let stdout = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path.join("actor.log"))
            .unwrap();
        let stderr = stdout.try_clone().unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "pure_pressure_v2_actor_entry",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("TRNM_PURE_PRESSURE_V2_JOB", path.join("job.json"))
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        let child = process_cost::ObservedChild::spawn(&mut command).unwrap();
        Self {
            child,
            path: path.to_owned(),
        }
    }
    pub fn ready(&self) -> bool {
        self.path.join("ready.json").is_file()
    }
    pub fn finish_with_process_cost(mut self, deadline: Instant) -> (Value, Value) {
        let cost = self.child.finish(deadline);
        let report = fs::read(self.path.join("report.json"))
            .ok()
            .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok());
        (
            json!({"pid":self.child.id(),"exit_success":cost["exit_success"],
            "parent_forced_kill":cost["parent_forced_kill"],"report":report,
            "report_path":self.path.join("report.json")}),
            cost,
        )
    }
}
