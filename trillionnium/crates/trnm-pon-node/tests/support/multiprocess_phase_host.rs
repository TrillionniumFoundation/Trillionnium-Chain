//! Explicit process placement for the original finite campaign. The original
//! controller owns every hostile OS child in its 400% domain; receiver and
//! History verifier execute in a separate process under the unchanged public
//! Host parent. The file broker transports lifecycle requests, never Node,
//! work, budget, confirmation or State authority.
use super::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{cell::RefCell, collections::BTreeMap, io::Read, os::unix::fs::OpenOptionsExt};

const PROFILE: &str = "fixed-public-phase-external-actors-v1";
const JOB_BYTES: usize = 4 * 1024 * 1024;
const REPORT_BYTES: usize = 64 * 1024 * 1024;
const PHASE_PROCESS_SECONDS: u64 = 300;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PhaseJob {
    schema: String,
    phase_path: PathBuf,
    controller_cgroup: String,
    binary_sha256: String,
    state_backend: String,
    work_profile: String,
    mode: Option<String>,
    method: usize,
    seed: Vec<String>,
    business: Vec<String>,
}

struct Client {
    control: PathBuf,
    next: usize,
}
thread_local! {
    static CLIENT: RefCell<Option<Client>> = const { RefCell::new(None) };
}

fn read(path: &Path, bound: usize) -> Value {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .unwrap();
    assert!(file.metadata().unwrap().is_file());
    let mut bytes = Vec::new();
    file.take(bound as u64 + 1).read_to_end(&mut bytes).unwrap();
    assert!(bytes.len() <= bound, "bounded lifecycle payload");
    serde_json::from_slice(&bytes).unwrap()
}

fn publish(path: &Path, value: &Value) {
    // The owner uses one fresh control directory and monotonically numbered
    // requests. Readers never parse a partly written JSON file.
    let temporary = path.with_extension("tmp");
    assert!(!path.exists() && !temporary.exists());
    support::write_new(&temporary, value);
    fs::rename(&temporary, path).unwrap();
}

fn await_value(path: &Path, deadline: Instant, bound: usize) -> Value {
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "phase lifecycle acknowledgement timeout"
        );
        support::ready_sleep();
    }
    read(path, bound)
}

fn binary_sha() -> String {
    let bytes = fs::read(std::env::current_exe().unwrap()).unwrap();
    hex::encode(Sha256::digest(bytes))
}

pub(super) struct RemoteActor {
    pub(super) pid: u32,
    control: PathBuf,
    ordinal: usize,
    finished: bool,
}
impl RemoteActor {
    pub(super) fn spawn(path: &Path, job: &Value) -> Option<Self> {
        CLIENT.with(|slot| {
            let mut client = slot.borrow_mut();
            let client = client.as_mut()?;
            assert_eq!(job["kind"], "attack");
            assert_eq!(job["worker"], client.next);
            assert!(client.next < ATTACKERS);
            let ordinal = client.next;
            client.next += 1;
            publish(
                &client.control.join(format!("spawn-{ordinal:02}.json")),
                &json!({"ordinal":ordinal,"path":path,"job":job}),
            );
            let response = await_value(
                &client.control.join(format!("spawn-{ordinal:02}-ack.json")),
                Instant::now() + Duration::from_secs(30),
                4096,
            );
            let pid = u32::try_from(response["pid"].as_u64().unwrap()).unwrap();
            assert!(pid > 1);
            Some(Self {
                pid,
                control: client.control.clone(),
                ordinal,
                finished: false,
            })
        })
    }

    pub(super) fn finish(mut self, deadline: Instant) -> Value {
        // Capture the destination clock first: clock sampling and IPC must
        // shorten the original deadline, never add their own elapsed time.
        let monotonic_before = support::monotonic();
        let remaining = deadline.saturating_duration_since(Instant::now());
        let end_ns = monotonic_before
            .checked_add(u64::try_from(remaining.as_nanos()).unwrap())
            .unwrap();
        publish(
            &self
                .control
                .join(format!("finish-{:02}.json", self.ordinal)),
            &json!({"ordinal":self.ordinal,"pid":self.pid,"original_cleanup_deadline_ns":end_ns}),
        );
        let value = await_value(
            &self
                .control
                .join(format!("finish-{:02}-ack.json", self.ordinal)),
            deadline + Duration::from_secs(5),
            REPORT_BYTES,
        );
        assert_eq!(value["pid"], self.pid);
        self.finished = true;
        value
    }
}
impl Drop for RemoteActor {
    fn drop(&mut self) {
        if !self.finished {
            // The actual parent retains a Child handle and performs kill+wait.
            // A dead phase owner also causes the broker to drop all live handles.
            let path = self
                .control
                .join(format!("cancel-{:02}.json", self.ordinal));
            if !path.exists() {
                let _ = fs::write(path, b"cancel");
            }
        }
    }
}

pub(super) fn entry() {
    let job_path = PathBuf::from(std::env::var_os("TRNM_MULTIPROCESS_PHASE_JOB").unwrap());
    let job: PhaseJob = serde_json::from_value(read(&job_path, JOB_BYTES)).unwrap();
    assert_eq!(job.schema, PROFILE);
    assert_eq!(job.binary_sha256, binary_sha());
    assert_eq!(job.seed.len(), 4);
    assert_eq!(job.business.len(), ROUNDS * 7);
    assert!(job.method < work::METHODS.len());
    assert!(matches!(
        job.mode.as_deref(),
        None | Some("from-zero" | "late-product")
    ));
    let control = job_path.parent().unwrap().to_path_buf();
    assert!(control.is_absolute() && job.phase_path.is_absolute());
    assert_eq!(job.phase_path.parent(), control.parent());
    let backend = match job.state_backend.as_str() {
        "legacy-v2" => StateBackendChoice::LegacyV2,
        "authenticated-v1" => StateBackendChoice::AuthenticatedV1,
        _ => panic!("explicit original backend required"),
    };
    let profile = match job.work_profile.as_str() {
        "raw-r14" => support::WorkProfile::RawR14,
        "arithmetic-facts-v1" => support::WorkProfile::ArithmeticFactsV1,
        _ => panic!("explicit original work profile required"),
    };
    let configuration = CampaignConfiguration::new(backend, profile).unwrap();
    let decode = |rows: &[String]| {
        rows.iter()
            .map(|raw| Packet::decode(&hex::decode(raw).unwrap()).unwrap())
            .collect::<Vec<_>>()
    };
    let seed = decode(&job.seed);
    let business = decode(&job.business);
    let kernel = trnm_pon_node::host_kernel_parent::require_host_kernel_budget(
        "127.0.0.1:1".parse().unwrap(),
        Some(trnm_pon_node::host_kernel_parent::FIXED_PUBLIC_KERNEL_PARENT),
    )
    .unwrap()
    .expect("actual fixed public Host, including loopback fixture");
    let before = kernel.resource_sample().unwrap();
    assert_ne!(unified_cgroup(), job.controller_cgroup);
    CLIENT.with(|slot| {
        assert!(slot.borrow().is_none());
        *slot.borrow_mut() = Some(Client {
            control: control.clone(),
            next: 0,
        });
    });
    let mut result = phase(
        &job.phase_path,
        &support::settings(),
        &seed,
        &business,
        job.mode.as_deref(),
        job.method,
        configuration,
    );
    CLIENT.with(|slot| {
        let state = slot.borrow_mut().take().unwrap();
        assert_eq!(state.next, if job.mode.is_some() { ATTACKERS } else { 0 });
    });
    kernel.verify().unwrap();
    result["phase_process_context"] = json!({
        "schema":PROFILE,"phase_pid":std::process::id(),
        "phase_cgroup":unified_cgroup(),"controller_cgroup":job.controller_cgroup,
        "host_before":before,"host_after":kernel.resource_sample().unwrap(),
        "same_original_receiver_and_verifier_owners":true,
        "attackers_launched_by_external_controller":true,
        "runtime_business_deadline_changed":false,"scalar_policy_changed":false,
        "independent_administration":false,"wan_qualified":false,
    });
    publish(&control.join("phase-result.json"), &result);
}

fn declared_placement(value: Option<&str>) -> Result<bool, &'static str> {
    match value {
        None => Ok(false),
        Some(PROFILE) => Ok(true),
        _ => Err("UNKNOWN_EXPLICIT_PHASE_PLACEMENT"),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run(
    path: &Path,
    settings: &Settings,
    seed: &[Packet],
    business: &[Packet],
    mode: Option<&str>,
    method: usize,
    configuration: CampaignConfiguration,
) -> Value {
    let placement = match std::env::var("TRNM_MULTIPROCESS_PHASE_HOST") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => panic!("non-Unicode phase placement"),
    };
    if !declared_placement(placement.as_deref()).unwrap() {
        // The historical local route remains observable as its original route;
        // it cannot silently obtain the explicit fixed-Host qualification.
        return phase(path, settings, seed, business, mode, method, configuration);
    }
    assert_eq!(settings.network(), support::settings().network());
    assert_eq!(settings.parameters(), support::settings().parameters());
    assert_eq!(settings.genesis(), support::settings().genesis());
    let parent = path.parent().unwrap().canonicalize().unwrap();
    let path = parent.join(path.file_name().unwrap());
    let control = path.with_file_name(format!(
        "{}-host-control",
        path.file_name().unwrap().to_str().unwrap()
    ));
    fs::create_dir(&control).unwrap();
    let context = unified_cgroup();
    assert!(!context.starts_with("/trnmponpublic.slice"));
    let resource = Path::new("/sys/fs/cgroup").join(context.trim_start_matches('/'));
    assert_eq!(
        fs::read_to_string(resource.join("cpu.max")).unwrap().trim(),
        "400000 100000"
    );
    assert_eq!(
        fs::read_to_string(resource.join("memory.max"))
            .unwrap()
            .trim(),
        "17179869184"
    );
    let job = PhaseJob {
        schema: PROFILE.to_owned(),
        phase_path: path.clone(),
        controller_cgroup: context.clone(),
        binary_sha256: binary_sha(),
        state_backend: configuration.state_backend.label().to_owned(),
        work_profile: match configuration.work_profile {
            support::WorkProfile::RawR14 => "raw-r14",
            support::WorkProfile::ArithmeticFactsV1 => "arithmetic-facts-v1",
        }
        .to_owned(),
        mode: mode.map(str::to_owned),
        method,
        seed: seed
            .iter()
            .map(|packet| hex::encode(packet.encode().unwrap()))
            .collect(),
        business: business
            .iter()
            .map(|packet| hex::encode(packet.encode().unwrap()))
            .collect(),
    };
    let job_path = control.join("phase-job.json");
    publish(&job_path, &serde_json::to_value(&job).unwrap());
    assert!(fs::metadata(&job_path).unwrap().len() <= JOB_BYTES as u64);
    let launcher = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../scripts/ci/run_native_phase_host.py")
        .canonicalize()
        .unwrap();
    // Cargo starts this integration test in its package directory. The Host
    // launcher requires the exact repository root, independently of caller cwd.
    let repository_root = launcher.ancestors().nth(3).unwrap().to_path_buf();
    let stdout = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(control.join("phase-launcher.log"))
        .unwrap();
    let stderr = stdout.try_clone().unwrap();
    let child_usage_before = support::children_usage();
    let started = Instant::now();
    let mut phase_child = PhaseChild(
        Command::new("python3")
            .current_dir(repository_root)
            .arg(launcher)
            .arg("--job")
            .arg(&job_path)
            .arg("--binary")
            .arg(std::env::current_exe().unwrap())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .unwrap(),
    );
    let mut actors: BTreeMap<usize, Actor> = BTreeMap::new();
    let mut launched = 0;
    let mut finished = 0;
    let mut contexts = Vec::new();
    let deadline = started + Duration::from_secs(PHASE_PROCESS_SECONDS);
    let status = loop {
        for ordinal in 0..ATTACKERS {
            let request = control.join(format!("spawn-{ordinal:02}.json"));
            let ack = control.join(format!("spawn-{ordinal:02}-ack.json"));
            if request.exists() && !ack.exists() {
                assert_eq!(ordinal, launched);
                let request = read(&request, JOB_BYTES);
                let actor_path = path.join(format!("attacker-{ordinal:02}"));
                assert_eq!(request["ordinal"], ordinal);
                assert_eq!(request["path"], json!(actor_path));
                assert_eq!(request["job"]["kind"], "attack");
                assert_eq!(request["job"]["worker"], ordinal);
                assert_eq!(request["job"]["mode"], json!(mode));
                let actor = Actor::spawn_local(&actor_path, request["job"].clone());
                let pid = actor.pid();
                let actual = fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap();
                assert_eq!(actual.trim(), format!("0::{context}"));
                let observation =
                    json!({"ordinal":ordinal,"pid":pid,"actual_cgroup":actual.trim()});
                publish(
                    &control.join(format!("spawn-{ordinal:02}-observation.json")),
                    &observation,
                );
                contexts.push(observation);
                assert!(actors.insert(ordinal, actor).is_none());
                launched += 1;
                publish(&ack, &json!({"pid":pid}));
            }
            let request = control.join(format!("finish-{ordinal:02}.json"));
            let ack = control.join(format!("finish-{ordinal:02}-ack.json"));
            if request.exists() && !ack.exists() {
                let request = read(&request, 4096);
                let actor = actors.remove(&ordinal).expect("original unreaped actor");
                assert_eq!(request["pid"], actor.pid());
                assert_eq!(request["ordinal"], ordinal);
                let end = request["original_cleanup_deadline_ns"].as_u64().unwrap();
                let instant_before = Instant::now();
                let remaining = end.saturating_sub(support::monotonic());
                assert!(remaining <= (WINDOW_SECONDS + 5) * 1_000_000_000);
                let result = actor.finish(instant_before + Duration::from_nanos(remaining));
                finished += 1;
                publish(&ack, &result);
            }
            if control.join(format!("cancel-{ordinal:02}.json")).exists() {
                actors.remove(&ordinal);
            }
        }
        if let Some(status) = phase_child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "bounded actual phase process timed out"
        );
        support::ready_sleep();
    };
    assert!(
        status.success(),
        "actual public phase or Host failed; raw logs retained"
    );
    assert!(actors.is_empty());
    assert_eq!(launched, if mode.is_some() { ATTACKERS } else { 0 });
    assert_eq!(finished, launched);
    let mut result = read(&control.join("phase-result.json"), REPORT_BYTES);
    result["public_phase_children_os_usage_before"] = result["children_os_usage_before"].clone();
    result["public_phase_children_os_usage_after"] = result["children_os_usage_after"].clone();
    result["children_os_usage_before"] = child_usage_before;
    result["children_os_usage_after"] = support::children_usage();
    result["external_controller_observation"] = json!({
        "schema":PROFILE,"pid":std::process::id(),"controller_cgroup":context,
        "actual_attack_process_contexts":contexts,"launched":launched,"reaped":finished,
        "whole_placement_wall_ns":started.elapsed().as_nanos(),
        "children_os_usage_scope":"original controller's reaped attacker processes and Host launcher; excludes the systemd-owned public phase process",
        "host_launcher_process_exit":status.code(),"host_qualification_is_not_service_success":true,
    });
    result
}

struct PhaseChild(Child);
impl Drop for PhaseChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            // Let the launcher's signal handler stop its exact owned systemd
            // unit. RuntimeMaxSec additionally bounds a controller SIGKILL.
            // SAFETY: this is the live direct Child PID, representable by the
            // kernel pid_t. No process-group or caller-provided PID is used.
            unsafe {
                libc::kill(i32::try_from(self.0.id()).unwrap(), libc::SIGTERM);
            }
            let deadline = Instant::now() + Duration::from_secs(3);
            while self.0.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
                support::ready_sleep();
            }
            if self.0.try_wait().ok().flatten().is_none() {
                let _ = self.0.kill();
            }
            let _ = self.0.wait();
        }
    }
}

#[test]
fn explicit_placement_has_no_unknown_or_partial_fallback() {
    assert!(!declared_placement(None).unwrap());
    assert!(declared_placement(Some(PROFILE)).unwrap());
    for invalid in ["", "public", "fixed-public-phase-external-actors-v2"] {
        assert!(declared_placement(Some(invalid)).is_err());
    }
}

#[test]
fn phase_job_refuses_unknown_fields_and_broker_never_claims_actor_authority() {
    assert!(serde_json::from_value::<PhaseJob>(json!({"schema":PROFILE,"bypass":true})).is_err());
    let directory = tempfile::tempdir().unwrap();
    let p = directory.path().join("once.json");
    publish(&p, &json!({"n":1}));
    assert_eq!(read(&p, 4096), json!({"n":1}));
    assert!(std::panic::catch_unwind(|| publish(&p, &json!({"n":2}))).is_err());
    assert!(std::panic::catch_unwind(|| read(&p, 1)).is_err());
    let link = directory.path().join("link.json");
    std::os::unix::fs::symlink(&p, &link).unwrap();
    assert!(std::panic::catch_unwind(|| read(&link, 4096)).is_err());
}

// Separate explicit entry only. The old entry and whitelist stay unchanged.
pub(super) fn with_separate_broker<T>(
    control: &Path,
    expected_actors: usize,
    run: impl FnOnce() -> T,
) -> T {
    assert!(matches!(expected_actors, 0 | ATTACKERS));
    CLIENT.with(|slot| {
        assert!(slot.borrow().is_none(), "one explicit broker scope");
        *slot.borrow_mut() = Some(Client {
            control: control.to_path_buf(),
            next: 0,
        });
    });
    struct Scope;
    impl Drop for Scope {
        fn drop(&mut self) {
            CLIENT.with(|slot| {
                slot.borrow_mut().take();
            });
        }
    }
    let scope = Scope;
    let value = run();
    CLIENT.with(|slot| assert_eq!(slot.borrow().as_ref().unwrap().next, expected_actors));
    drop(scope);
    value
}

#[test]
fn separate_broker_scope_clears_on_unwind_and_refuses_missing_actors() {
    let directory = tempfile::tempdir().unwrap();
    assert_eq!(with_separate_broker(directory.path(), 0, || 7), 7);
    assert!(std::panic::catch_unwind(|| {
        with_separate_broker(directory.path(), ATTACKERS, || ())
    })
    .is_err());
    CLIENT.with(|slot| assert!(slot.borrow().is_none()));
    assert!(std::panic::catch_unwind(|| {
        with_separate_broker(directory.path(), 0, || panic!("fixture unwind"));
    })
    .is_err());
    CLIENT.with(|slot| assert!(slot.borrow().is_none()));
    assert!(std::panic::catch_unwind(|| {
        with_separate_broker(directory.path(), 0, || {
            with_separate_broker(directory.path(), 0, || ())
        });
    })
    .is_err());
    CLIENT.with(|slot| assert!(slot.borrow().is_none()));
}
