//! Linux observations and explicitly selected pure-PoN v2 clients. No policy
//! fallback, extra credit, relaxed deadline, or guest execution authority.
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
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

pub const WINDOW_NS: u64 = 30_000_000_000;
pub const ATTACKERS: usize = 24;
pub const CALL_CAP: usize = 480;
pub const ROUNDS: usize = 3;

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
    // Call arguments can take time to construct after the caller's loop
    // check. Check the original phase again here, before any client API.
    let anchor = Instant::now();
    let started = monotonic();
    within_call_window(
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
    )
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
    child: Child,
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
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "pure_pressure_v2_actor_entry",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("TRNM_PURE_PRESSURE_V2_JOB", path.join("job.json"))
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .unwrap();
        Self {
            child,
            path: path.to_owned(),
        }
    }
    pub fn ready(&self) -> bool {
        self.path.join("ready.json").is_file()
    }
    pub fn finish(mut self, deadline: Instant) -> Value {
        let mut forced = false;
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                self.child.kill().unwrap();
                forced = true;
                break self.child.wait().unwrap();
            }
            pause();
        };
        let report = fs::read(self.path.join("report.json"))
            .ok()
            .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok());
        json!({"pid":self.child.id(),"exit_success":status.success(),
            "parent_forced_kill":forced,"report":report,"report_path":self.path.join("report.json")})
    }
}
impl Drop for Actor {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
