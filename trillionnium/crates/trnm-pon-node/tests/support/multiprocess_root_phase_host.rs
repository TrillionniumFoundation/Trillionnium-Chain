//! F0 reconstruction after the r8 ephemeral workspace loss. The original
//! cf845/364600 Rust bytes were not recovered. This distinct source keeps the
//! complete old W1/M06 phase relation and adds explicit verified placement.
//! No environment string is a controller capability. Source controls and Host
//! placement do not establish service, work security or WAN qualification.
use super::*;
#[path = "multiprocess_root_phase_host_resources.rs"]
mod controller_resources;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
};

const PROFILE: &str = "fixed-public-root-phase-external-actors-v1";
const JOB_BYTES: usize = 4 * 1024 * 1024;
const REPORT_BYTES: usize = 64 * 1024 * 1024;
const PHASE_PROCESS_SECONDS: u64 = 300;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutableIdentity {
    device: u64,
    inode: u64,
    bytes: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessIdentity {
    pid: u32,
    parent_pid: u32,
    start_ticks: u64,
    boot_id: String,
    cgroup: String,
    executable: ExecutableIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControllerIdentity {
    process: ProcessIdentity,
    cgroup: GroupIdentity,
}

// Private and not deserializable. Untrusted job identities need live checks.
struct VerifiedController {
    identity: ControllerIdentity,
}

fn require(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

fn kernel_text(path: &Path, limit: usize) -> Result<String, String> {
    let file = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    require(bytes.len() <= limit, "BOUNDED_KERNEL_IDENTITY")?;
    String::from_utf8(bytes).map_err(|e| e.to_string())
}

fn process_stat(raw: &str, pid: u32) -> Result<(u32, u64), String> {
    let (prefix, fields) = raw.rsplit_once(") ").ok_or("PROC_STAT_CLOSE")?;
    let (number, _) = prefix.split_once(" (").ok_or("PROC_STAT_OPEN")?;
    require(pid > 1 && number == pid.to_string(), "EXACT_PROC_PID")?;
    let fields: Vec<_> = fields.split_whitespace().collect();
    let parent = fields
        .get(1)
        .ok_or("PROC_STAT_PARENT")?
        .parse::<u32>()
        .map_err(|e| e.to_string())?;
    let start = fields
        .get(19)
        .ok_or("PROC_STAT_START")?
        .parse::<u64>()
        .map_err(|e| e.to_string())?;
    require(parent > 0 && start > 0, "POSITIVE_PROC_IDENTITY")?;
    Ok((parent, start))
}

fn executable_identity(path: &Path) -> Result<ExecutableIdentity, String> {
    let metadata = fs::metadata(path).map_err(|e| e.to_string())?;
    require(metadata.is_file(), "REGULAR_CONTROLLER_EXECUTABLE")?;
    Ok(ExecutableIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        bytes: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
    })
}

fn external_group(value: &str) -> Result<PathBuf, String> {
    require(
        value.starts_with('/')
            && !value.starts_with("/trnmponpublic.slice")
            && value[1..]
                .split('/')
                .all(|part| !matches!(part, "" | "." | "..")),
        "EXACT_EXTERNAL_CONTROLLER_GROUP",
    )?;
    Ok(Path::new("/sys/fs/cgroup").join(&value[1..]))
}

fn group_identity(value: &str) -> Result<GroupIdentity, String> {
    let path = external_group(value)?;
    let metadata = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
    require(
        metadata.is_dir()
            && metadata.uid() == 0
            && metadata.mode() & 0o022 == 0
            && path.canonicalize().map_err(|e| e.to_string())? == path,
        "ROOT_OWNED_CONTROLLER_GROUP",
    )?;
    require(
        kernel_text(&path.join("cpu.max"), 128)?.trim() == "400000 100000"
            && kernel_text(&path.join("memory.max"), 128)?.trim() == "17179869184",
        "ORIGINAL_CONTROLLER_RESOURCE_PROFILE",
    )?;
    Ok(GroupIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode() & 0o7777,
    })
}

fn observe_process(pid: u32) -> Result<ProcessIdentity, String> {
    let path = Path::new("/proc").join(pid.to_string());
    let stat = kernel_text(&path.join("stat"), 16384)?;
    let (parent_pid, start_ticks) = process_stat(&stat, pid)?;
    let cgroup_raw = kernel_text(&path.join("cgroup"), 4096)?;
    let cgroup = cgroup_raw
        .trim()
        .strip_prefix("0::")
        .ok_or("UNIFIED_CONTROLLER_GROUP")?;
    require(!cgroup.contains('\n'), "SINGLE_UNIFIED_CONTROLLER_GROUP")?;
    external_group(cgroup)?;
    let executable = executable_identity(&path.join("exe"))?;
    let current = std::env::current_exe().map_err(|e| e.to_string())?;
    require(
        executable == executable_identity(&current)?,
        "EXACT_CONTROLLER_ELF_IDENTITY",
    )?;
    let boot_id = kernel_text(Path::new("/proc/sys/kernel/random/boot_id"), 128)?
        .trim()
        .to_owned();
    require(boot_id.len() == 36, "EXACT_BOOT_ID")?;
    require(
        process_stat(&kernel_text(&path.join("stat"), 16384)?, pid)? == (parent_pid, start_ticks)
            && kernel_text(&path.join("cgroup"), 4096)? == cgroup_raw
            && executable_identity(&path.join("exe"))? == executable,
        "CONTROLLER_CHANGED_DURING_OBSERVATION",
    )?;
    Ok(ProcessIdentity {
        pid,
        parent_pid,
        start_ticks,
        boot_id,
        cgroup: cgroup.to_owned(),
        executable,
    })
}

impl VerifiedController {
    fn current() -> Result<Self, String> {
        let process = observe_process(std::process::id())?;
        let cgroup = group_identity(&process.cgroup)?;
        Self::checked(ControllerIdentity { process, cgroup })
    }
    fn checked(identity: ControllerIdentity) -> Result<Self, String> {
        let token = Self { identity };
        token.verify()?;
        Ok(token)
    }
    fn verify(&self) -> Result<(), String> {
        require(
            observe_process(self.identity.process.pid)? == self.identity.process
                && group_identity(&self.identity.process.cgroup)? == self.identity.cgroup,
            "EXACT_LIVE_CONTROLLER_REQUIRED",
        )
    }
    fn actor(&self, pid: u32) -> Result<ProcessIdentity, String> {
        self.verify()?;
        let process = observe_process(pid)?;
        require(
            process.parent_pid == self.identity.process.pid
                && process.cgroup == self.identity.process.cgroup
                && process.boot_id == self.identity.process.boot_id
                && process.executable == self.identity.process.executable,
            "ACTUAL_EXTERNAL_ACTOR_MEMBERSHIP_REQUIRED",
        )?;
        Ok(process)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootPhaseJob {
    schema: String,
    phase_path: PathBuf,
    controller: ControllerIdentity,
    binary_sha256: String,
    state_backend: String,
    work_profile: String,
    mode: Option<String>,
    method: usize,
    seed: Vec<String>,
    business: Vec<String>,
}

impl RootPhaseJob {
    fn validate_shape(&self) -> Result<(), String> {
        require(
            self.schema == PROFILE
                && self.state_backend == "authenticated-v1"
                && self.work_profile == "raw-r14"
                && self.method == 0
                && matches!(self.mode.as_deref(), None | Some("valid-work-root")),
            "EXACT_FIXED_ROOT_JOB_PROFILE",
        )?;
        require(
            self.phase_path.is_absolute()
                && self.phase_path.file_name().and_then(|name| name.to_str())
                    == Some(self.mode.as_deref().unwrap_or("baseline")),
            "EXACT_FIXED_ROOT_PHASE_NAME",
        )?;
        require(
            self.seed.len() == 4 && self.business.len() == ROUNDS * 7,
            "COMPLETE_ORIGINAL_FIXED_ROOT_WORKLOAD",
        )?;
        require(
            self.binary_sha256.len() == 64
                && self
                    .binary_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "EXACT_FIXED_ROOT_ELF_DIGEST",
        )?;
        require(
            self.seed.iter().chain(&self.business).all(|p| {
                !p.is_empty()
                    && p.len() % 2 == 0
                    && p.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            }),
            "CANONICAL_FIXED_ROOT_PACKET_HEX",
        )
    }
}

struct PhaseOwner<'a> {
    controller: &'a VerifiedController,
    control: &'a Path,
}

fn actor_membership(actors: &[Actor], owner: &PhaseOwner<'_>, expected: usize) -> Value {
    let controller_check = owner.controller.verify();
    let mut pids = BTreeSet::new();
    let rows: Vec<_> = actors.iter().enumerate().map(|(ordinal, actor)| {
        let pid = actor.pid();
        let distinct = pids.insert(pid);
        let observation = (|| -> Result<Value, String> {
            require(distinct, "DISTINCT_ACTUAL_ACTOR_PID")?;
            let identity = owner.controller.actor(pid)?;
            let spawn = read(&owner.control.join(format!("spawn-{ordinal:02}-observation.json")), JOB_BYTES);
            let ready = read(&actor.ready, JOB_BYTES);
            require(spawn["ordinal"] == ordinal && spawn["pid"] == pid
                && spawn["identity"] == serde_json::to_value(&identity).map_err(|e| e.to_string())?
                && ready["pid"] == pid && ready["mode"] == "valid-work-root"
                && ready["cgroup"] == identity.cgroup, "ACTOR_READINESS_AND_LIVE_IDENTITY_BINDING")?;
            Ok(json!({"identity":identity,"spawn_observation":spawn,"ready":ready}))
        })();
        json!({"ordinal":ordinal,"pid":pid,"verified":observation.is_ok(),"observation":observation})
    }).collect();
    let verified = controller_check.is_ok()
        && actors.len() == expected
        && pids.len() == expected
        && rows.iter().all(|row| row["verified"] == true);
    json!({"verified":verified,"controller_check":controller_check,
        "controller_identity":owner.controller.identity,"expected_actors":expected,
        "observed_actors":actors.len(),"distinct_pids":pids.len(),"actors":rows})
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

fn binary_sha() -> String {
    let bytes = fs::read(std::env::current_exe().unwrap()).unwrap();
    hex::encode(Sha256::digest(bytes))
}

pub(super) fn entry() {
    let job_path =
        PathBuf::from(std::env::var_os("TRNM_FIXED_ROOT_PHASE_JOB").expect("explicit F0 job"));
    assert_eq!(job_path.canonicalize().unwrap(), job_path);
    assert_eq!(job_path.file_name().unwrap(), "root-phase-job.json");
    let job: RootPhaseJob = serde_json::from_value(read(&job_path, JOB_BYTES)).unwrap();
    job.validate_shape().unwrap();
    assert_eq!(job.binary_sha256, binary_sha());
    let control = job_path.parent().unwrap();
    assert_eq!(job.phase_path.parent(), control.parent());
    assert_eq!(
        control.file_name().unwrap().to_str().unwrap(),
        format!(
            "{}-fixed-root-host-control",
            job.mode.as_deref().unwrap_or("baseline")
        )
    );
    let controller = VerifiedController::checked(job.controller).unwrap();
    assert_ne!(unified_cgroup(), controller.identity.process.cgroup);
    let decode = |rows: &[String]| {
        rows.iter()
            .map(|raw| {
                let packet = Packet::decode(&hex::decode(raw).unwrap()).unwrap();
                assert_eq!(hex::encode(packet.encode().unwrap()), *raw);
                packet
            })
            .collect::<Vec<_>>()
    };
    let seed = decode(&job.seed);
    let business = decode(&job.business);
    assert!(seed.iter().all(|packet| packet.transactions.len() == 256));
    assert_eq!(business[0].header.parent, seed[3].id().unwrap());
    let kernel = trnm_pon_node::host_kernel_parent::require_host_kernel_budget(
        "127.0.0.1:1".parse().unwrap(),
        Some(trnm_pon_node::host_kernel_parent::FIXED_PUBLIC_KERNEL_PARENT),
    )
    .unwrap()
    .expect("actual unchanged fixed public Host");
    let before = kernel.resource_sample().unwrap();
    let placement = PhaseOwner {
        controller: &controller,
        control,
    };
    let mut result = phase_host::with_separate_broker(
        control,
        if job.mode.is_some() { ATTACKERS } else { 0 },
        || {
            fixed_phase(
                &job.phase_path,
                &support::settings(),
                &seed,
                &business,
                job.mode.as_deref(),
                job.method,
                &placement,
            )
        },
    );
    controller.verify().unwrap();
    kernel.verify().unwrap();
    result["phase_process_context"] = json!({
        "schema":PROFILE,"phase_pid":std::process::id(),"phase_cgroup":unified_cgroup(),
        "controller_identity":controller.identity,"controller_live_identity_after_verified":true,
        "host_before":before,"host_after":kernel.resource_sample().unwrap(),
        "same_original_receiver_and_verifier_owners":true,"attackers_launched_by_external_controller":true,
        "runtime_business_deadline_changed":false,"scalar_policy_changed":false,
        "independent_administration":false,"wan_qualified":false,
    });
    publish(&control.join("phase-result.json"), &result);
}

fn fixed_phase(
    path: &Path,
    settings: &Settings,
    seed: &[Packet],
    business: &[Packet],
    mode: Option<&str>,
    method: usize,
    placement: &PhaseOwner<'_>,
) -> Value {
    placement.controller.verify().unwrap();
    let configuration = CampaignConfiguration::new(
        StateBackendChoice::AuthenticatedV1,
        support::WorkProfile::RawR14,
    )
    .unwrap();
    let CampaignConfiguration {
        state_backend,
        work_profile,
    } = configuration;
    fs::create_dir(path).unwrap();
    let root_mode = mode == Some("valid-work-root");
    let controller_cgroup = root_mode.then(|| placement.controller.identity.process.cgroup.clone());
    let whole_started = Instant::now();
    let whole_cpu = support::cpu();
    let setup_started = Instant::now();
    let setup_cpu = support::cpu();
    let mut receiver = state_backend.open(&path.join("receiver"), settings.clone());
    replay(&mut receiver, seed);
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
    let mut verifier = state_backend.open(&path.join("independent-client"), settings.clone());
    replay(&mut verifier, seed);
    let initial = receiver.read_active().unwrap();
    let native_history_before = receiver.native_history_arithmetic_observation();
    let client_native_history_before = verifier.native_history_arithmetic_observation();
    let owner = Arc::new(Mutex::new(receiver));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let metrics = Arc::new(Mutex::new(public_v3::PublicMetrics::default()));
    let live_metrics = metrics.clone();
    let observer = public_v3::PublicRequestObserver::new(16_384).unwrap();
    let (server, arithmetic_owner) = campaign_server(work_profile);
    let domain = server.mutation_cpu_domain();
    let initial_meter = domain.observe().unwrap();
    let (shared, signal, capture) = (owner.clone(), stop.clone(), observer.clone());
    let service = Service {
        stop,
        worker: Some(thread::spawn(move || {
            public_v3::serve_public_protected_v3_with_request_observer(
                listener,
                shared,
                Duration::from_secs(240),
                signal,
                server,
                metrics,
                capture,
            )
            .map_err(|error| error.to_string())
        })),
    };
    let receiver_and_verifier_setup_cpu_ns = support::elapsed_cpu(setup_cpu);
    let receiver_and_verifier_setup_wall_ns = setup_started.elapsed().as_nanos();
    let marker = path.join("start.json");
    let mut actors = Vec::new();
    let children_usage_before = support::children_usage();
    if let Some(mode) = mode {
        for worker in 0..ATTACKERS {
            let mut template = business[0].header.clone();
            template.nonce = 2_000_000 + worker as u64 * 10_000;
            let mut job = json!({"kind":"attack","mode":mode,"method":method,
            "worker":worker,"address":address.to_string(),"header":hex::encode(template.encode()),
            "transactions":business[0].transactions.iter().map(hex::encode).collect::<Vec<_>>(),"start_marker":marker});
            work_profile.bind_actor_job(&mut job);
            actors.push(Actor::spawn(
                &path.join(format!("attacker-{worker:02}")),
                job,
            ));
        }
    }
    let readiness_end = Instant::now() + Duration::from_secs(180);
    while actors
        .iter()
        .any(|actor| !actor.ready.exists() && !actor.report.exists())
        && Instant::now() < readiness_end
    {
        support::ready_sleep();
    }
    let ready_count = actors.iter().filter(|actor| actor.ready.exists()).count();
    let root_readiness: Vec<Value> = if root_mode {
        actors
            .iter()
            .map(|actor| {
                fs::read(&actor.ready)
                    .ok()
                    .and_then(|raw| serde_json::from_slice(&raw).ok())
                    .unwrap_or(Value::Null)
            })
            .collect()
    } else {
        Vec::new()
    };
    let root_acquisitions: Vec<Value> = if root_mode {
        actors
            .iter()
            .map(|actor| {
                fs::read(actor.ready.parent().unwrap().join("acquisition.json"))
                    .ok()
                    .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok())
                    .unwrap_or(Value::Null)
            })
            .collect()
    } else {
        Vec::new()
    };
    let root_packet_ids: Vec<[u8; 32]> = root_acquisitions
        .iter()
        .filter(|v| v["valid_work_for_root_rejection"] == true)
        .filter_map(|v| hex::decode(v["packet_id"].as_str()?).ok()?.try_into().ok())
        .collect();
    let hostile_digests: Vec<Vec<u8>> = actors
        .iter()
        .filter_map(|actor| fs::read(actor.ready.parent().unwrap().join("acquisition.json")).ok())
        .filter_map(|raw| serde_json::from_slice::<Value>(&raw).ok())
        .filter_map(|value| {
            value["public_request_body_digest"]
                .as_str()
                .and_then(|s| hex::decode(s).ok())
        })
        .collect();
    let f0_membership = actor_membership(&actors, placement, if root_mode { ATTACKERS } else { 0 });
    // Separate boundary evidence before the original pressure clock begins.
    // Existing public-phase /proc RSS diagnostics remain unchanged and may be
    // unknown for external children; they are never replaced by this whole group.
    let controller_resource_ready = controller_resources::sample(
        placement.controller,
        "actors_ready",
        &actors,
        if root_mode { ATTACKERS } else { 0 },
    );
    // Capture the Rust deadline once, just before the existing measured epoch.
    // It can only be earlier than that same 30-second pressure end; imports
    // must not acquire another 30 seconds when each History page arrives.
    let import_deadline = Instant::now() + Duration::from_secs(WINDOW_SECONDS);
    let epoch = support::monotonic();
    let end = epoch + WINDOW_SECONDS * 1_000_000_000;
    let temporary_marker = path.join("start.tmp.json");
    support::write_new(&temporary_marker, &json!({"epoch_ns":epoch,"end_ns":end}));
    fs::rename(&temporary_marker, &marker).unwrap();
    let samples = Arc::new(Mutex::new(Vec::<Value>::new()));
    let sampling = samples.clone();
    let sample_domain = domain.clone();
    let sample_metrics = live_metrics.clone();
    let pids: Vec<_> = actors.iter().map(Actor::pid).collect();
    let sampler = thread::spawn(move || {
        while support::monotonic() < end {
            let observation_started_ns = support::monotonic().saturating_sub(epoch);
            let observation = sample_domain
                .observe()
                .map(|meter| {
                    let actual = sample_domain.observe_actual_flow().ok().flatten();
                    paid_depletion(
                        &meter,
                        &sample_metrics.lock().unwrap(),
                        actual.as_ref(),
                        support::monotonic().saturating_sub(epoch),
                    )
                })
                .map_err(|e| e.to_string());
            let observation_ended_ns = support::monotonic().saturating_sub(epoch);
            // Separate optional diagnostic, after the original sample interval.
            // It neither refills credit nor changes the original predicate.
            let freshness_started_ns = support::monotonic().saturating_sub(epoch);
            let credit_freshness = sample_domain
                .observe_credit_freshness()
                .map_err(|error| error.to_string());
            let freshness_ended_ns = support::monotonic().saturating_sub(epoch);
            sampling.lock().unwrap().push(json!({"at_ns":observation_ended_ns,"observation_started_ns":observation_started_ns,
                "observation_ended_ns":observation_ended_ns,"meter":observation,"attacker_process_rss":support::live_children_rss(&pids),
                "credit_freshness_started_ns":freshness_started_ns,"credit_freshness_ended_ns":freshness_ended_ns,
                "credit_freshness":credit_freshness}));
            thread::sleep(Duration::from_millis(50));
        }
    });
    // Fixed t=1,5,9 seconds, regardless of whether this finite workload reaches
    // paid-credit depletion. Honest progress and depletion stay separate facts.
    while support::monotonic() < epoch + 1_000_000_000 {
        support::ready_sleep();
    }
    let business_started = support::monotonic().saturating_sub(epoch);
    let mut submissions = Vec::new();
    let mut history = Vec::new();
    let mut confirmations = Vec::new();
    let mut errors = Vec::new();
    let mut after = initial.0;
    let mut next = 0;
    {
        for round in 0..ROUNDS {
            let scheduled = epoch
                .saturating_add(1_000_000_000)
                .saturating_add(round as u64 * 4_000_000_000);
            while support::monotonic() < scheduled.min(end) {
                support::ready_sleep();
            }
            let round_start = support::monotonic().saturating_sub(epoch);
            let hostile_before = hostile_work(&observer, &hostile_digests);
            let root_before = root_mode.then(|| hostile_admission(&observer, &hostile_digests));
            let final_index = (round + 1) * 7;
            while next < final_index && support::monotonic() < end && submissions.len() < 128 {
                let mut row = support::call_with_work_profile(
                    address,
                    settings,
                    Request::Submit {
                        packet: hex::encode(business[next].encode().unwrap()),
                    },
                    73,
                    epoch,
                    end,
                    work_profile,
                );
                row["packet_index"] = json!(next);
                row["height"] = json!(business[next].header.height);
                if support::on_time(&row) {
                    next += 1;
                }
                submissions.push(row);
            }
            let tip = business[final_index - 1].id().unwrap();
            let included = business[round * 7].id().unwrap();
            let transaction = hash(b"tx-id", &[&business[round * 7].transactions[0]]);
            let mut observation = None;
            while next == final_index && support::monotonic() < end && history.len() < 64 {
                let mut row = support::call_with_work_profile(
                    address,
                    settings,
                    Request::History {
                        tip: hex::encode(tip),
                        after: hex::encode(after),
                    },
                    74,
                    epoch,
                    end,
                    work_profile,
                );
                if support::on_time(&row) {
                    let import_stamp = ClientOperationStamp::start(epoch);
                    let imported =
                        serde_json::from_value::<ingress::Page>(row["response"]["value"].clone())
                            .map_err(|e| e.to_string())
                            .and_then(|page| {
                                ingress::receive_public_page_from_before(
                                    &mut verifier,
                                    address,
                                    page,
                                    tip,
                                    after,
                                    support::now(),
                                    import_deadline,
                                )
                                .map_err(|e| e.to_string())
                            });
                    row["client_import"] = import_stamp.finish(epoch);
                    row["client_import"]["operation"] = json!(
                        "deserialize Page and ordinary receive_page, including activation only on the original complete page"
                    );
                    row["client_import"]["succeeded"] = json!(imported.is_ok());
                    match imported {
                        Ok(next_after) => after = next_after,
                        Err(error) => errors.push(error),
                    }
                    if after == tip {
                        let confirmation_stamp = ClientOperationStamp::start(epoch);
                        let result = verifier.confirmation(transaction, included, support::now());
                        row["client_confirmation"] = confirmation_stamp.finish(epoch);
                        row["client_confirmation"]["operation"] =
                            json!("ordinary verifier confirmation after the original complete-page activation");
                        row["client_confirmation"]["succeeded"] = json!(result.is_ok());
                        match result {
                            Ok(value) => observation = Some(value),
                            Err(e) => errors.push(e.to_string()),
                        }
                    }
                }
                history.push(row);
                if observation.is_some() {
                    break;
                }
            }
            let hostile_after = hostile_work(&observer, &hostile_digests);
            let root_after = root_mode.then(|| hostile_admission(&observer, &hostile_digests));
            // Live snapshots are not atomic. ROOT evidence conservatively ends
            // after both snapshots, still inside the original fixed phase end.
            let ended = support::monotonic().saturating_sub(epoch);
            let receiver_hostile_work_rejected_during_round = hostile_before["work_rejected"]
                .as_u64()
                .zip(hostile_after["work_rejected"].as_u64())
                .is_some_and(|(a, b)| b > a)
                && hostile_before["rejected_work_cpu_ns"]
                    .as_u64()
                    .zip(hostile_after["rejected_work_cpu_ns"].as_u64())
                    .is_some_and(|(a, b)| b > a);
            let confirmed = observation.as_ref().is_some_and(|value| {
                value.confirmed
                    && !value.finalized
                    && !value.execution_authority
                    && value.depth == Some(6)
            }) && support::monotonic() < end;
            confirmations.push(json!({"round":round,"scheduled_offset_ns":scheduled.saturating_sub(epoch),"started_ns":round_start,"ended_ns":ended,"confirmed_inside_pressure_window":confirmed,
                "transaction":hex::encode(transaction),"included_block":hex::encode(included),"tip":hex::encode(tip),"observation":observation,
                "receiver_hostile_before":hostile_before,"receiver_hostile_after":hostile_after,"receiver_hostile_work_rejected_during_round":receiver_hostile_work_rejected_during_round}));
            if let Some((before, after)) = root_before.zip(root_after) {
                let progressed = ["accepted_work_admission_refusals", "admission_cpu_ns"]
                    .iter()
                    .all(|key| {
                        before[key]
                            .as_u64()
                            .zip(after[key].as_u64())
                            .is_some_and(|(a, b)| b > a)
                    });
                let row = confirmations.last_mut().unwrap();
                row["receiver_hostile_admission_before"] = before;
                row["receiver_hostile_admission_after"] = after;
                row["accepted_work_admission_refusal_during_round"] = json!(progressed);
            }
            if !confirmed {
                break;
            }
        }
    }
    // Keep the fixed hostile window running after business, never drain first and
    // then retroactively count a recovery confirmation as overlap.
    let cleanup_deadline = Instant::now()
        + Duration::from_nanos(end.saturating_sub(support::monotonic()))
        + Duration::from_secs(5);
    let children: Vec<_> = actors
        .into_iter()
        .map(|actor| actor.finish(cleanup_deadline))
        .collect();
    let children_usage_after = support::children_usage();
    sampler.join().unwrap();
    let service_outcome = service.finish();
    // Diagnostic snapshots after the original service window. They do not
    // change any workload, deadline, budget, confirmation or success criterion.
    let native_history_after = owner
        .lock()
        .ok()
        .map(|node| node.native_history_arithmetic_observation());
    let client_native_history_after = verifier.native_history_arithmetic_observation();
    let captured = observer.snapshot();
    let budget_samples = samples.lock().unwrap().clone();
    let depletion_meter = budget_samples
        .iter()
        .filter_map(|row| row["meter"].get("Ok"))
        .find(|row| row["depleted"] == true)
        .cloned();
    let depletion_at = depletion_meter
        .as_ref()
        .and_then(|row| row["sample_at_ns"].as_u64());
    for round in &mut confirmations {
        let start = round["started_ns"].as_u64().unwrap();
        let end = round["ended_ns"].as_u64().unwrap();
        round["paid_credit_depletion_observed_during_round"] =
            json!(budget_samples
                .iter()
                .any(|sample| sample["observation_started_ns"]
                    .as_u64()
                    .zip(sample["observation_ended_ns"].as_u64())
                    .is_some_and(|(a, b)| start <= a && a <= b && b <= end)
                    && sample["meter"]["Ok"]["depleted"] == true));
    }
    let actual = owner.lock().unwrap().read_active().unwrap();
    let checked = verifier.read_active().unwrap();
    let final_meter = domain.observe().unwrap();
    let all_confirmed = confirmations.len() == ROUNDS
        && confirmations
            .iter()
            .all(|row| row["confirmed_inside_pressure_window"] == true);
    let attack_calls: Vec<_> = children
        .iter()
        .filter_map(|child| child["report"]["result"]["calls"].as_array())
        .flat_map(|rows| rows.iter())
        .collect();
    let overlaps: Vec<_> = confirmations
        .iter()
        .map(|round| {
            let start = round["started_ns"].as_u64().unwrap();
            let end = round["ended_ns"].as_u64().unwrap();
            attack_calls
                .iter()
                .filter(|call| {
                    call["started_ns"].as_u64().is_some_and(|v| v < end)
                        && call["ended_ns"].as_u64().is_some_and(|v| v > start)
                })
                .count()
        })
        .collect();
    let successful_actors = children.iter().all(|child| {
        child["exit_success"] == true
            && child["parent_forced_kill"] == false
            && child["report"]["error"].is_null()
            && child["report"]["result"]["attempt_cap_reached"] == false
    });
    let relation_failed = captured
        .records
        .iter()
        .filter(|row| row.full_work_accepted == Some(false))
        .count();
    let relation_accepted = captured
        .records
        .iter()
        .filter(|row| row.full_work_accepted == Some(true))
        .count();
    let observer_complete = captured.coverage_complete();
    let common_criteria = all_confirmed
        && actual.0 == checked.0
        && actual.2 == checked.2
        && observer_complete
        && service_outcome.get("Ok").is_some()
        && service_outcome["Ok"]["mutation_cpu_clock_failures"] == 0
        && final_meter.in_flight == 0
        && !final_meter.accounting_unavailable
        && errors.is_empty();
    let phase_criteria = !root_mode
        && common_criteria
        && (mode.is_none()
            || (depletion_at.is_some()
                && ready_count == ATTACKERS
                && successful_actors
                && overlaps.len() == ROUNDS
                && overlaps.iter().all(|n| *n > 0)
                && relation_failed > 0
                && relation_accepted >= ROUNDS * 7
                && confirmations
                    .iter()
                    .any(|row| row["paid_credit_depletion_observed_during_round"] == true)
                && confirmations
                    .iter()
                    .all(|row| row["receiver_hostile_work_rejected_during_round"] == true)
                && attack_calls.iter().all(|row| row["status"] != "ok")));
    let mut report = json!({"mode":mode.unwrap_or("baseline"),"state_backend":state_backend.label(),"address":address.to_string(),"duration_seconds":WINDOW_SECONDS,
        "attacker_processes_requested":if mode.is_some(){ATTACKERS}else{0},"attacker_processes_ready":ready_count,
        "depletion_at_ns":depletion_at,"depletion_meter":depletion_meter,"genuine_budget_depletion_observed":depletion_at.is_some(),"business_started_ns":business_started,
        "receiver_and_verifier_setup_cpu_ns":receiver_and_verifier_setup_cpu_ns,"receiver_and_verifier_setup_wall_ns":receiver_and_verifier_setup_wall_ns,
        "submissions":submissions,"history":history,"confirmations":confirmations,"all_signed_rounds_confirmed_in_window":all_confirmed,
        "verifier_errors":errors,"children":children,"service_outcome":service_outcome,"receiver_observation":captured,
        "native_history_arithmetic_before":native_history_before,"native_history_arithmetic_after":native_history_after,
        "observer_complete":observer_complete,"full_work_failed":relation_failed,"full_work_accepted":relation_accepted,
        "actor_reports_successful_without_cap_or_kill":successful_actors,"attack_calls_overlapping_each_signed_round":overlaps,
        "children_os_usage_before":children_usage_before,"children_os_usage_after":children_usage_after,
        "finite_phase_criteria_met":phase_criteria,
        "budget_samples":budget_samples,"initial_meter":initial_meter,"final_meter":final_meter,
        "final_actual_flow":domain.observe_actual_flow().ok().flatten(),
        "receiver_client_state_equal":actual.0==checked.0&&actual.2==checked.2,
        "initial_tip":hex::encode(initial.0),"final_receiver_tip":hex::encode(actual.0),"final_client_tip":hex::encode(checked.0),
        "whole_parent_phase_cpu_ns":support::elapsed_cpu(whole_cpu),"whole_parent_phase_wall_ns":whole_started.elapsed().as_nanos(),"rss":support::rss()});
    report["public_resource_policy"] = work_profile.policy_observation();
    if let Some(arithmetic_owner) = arithmetic_owner {
        report["work_profile"] = json!("arithmetic-facts-v1");
        report["work_arithmetic_owner"] = arithmetic_owner;
    }
    report["completion_work_observation"] = json!(domain.observe_completion_work().ok());
    report["client_native_history_arithmetic_before"] = client_native_history_before;
    report["client_native_history_arithmetic_after"] = client_native_history_after;
    report["client_observation_scope"] = json!("bounded by the original 64 history calls; import includes complete-page activation, confirmation is separate; native snapshots exclude setup and final read_active; nested costs are not additive");
    if root_mode {
        // Concurrent mutations share this domain. Reconcile the entire closed
        // domain, never attribute overlapping paid deltas to individual calls.
        let flow = domain.observe_actual_flow().unwrap();
        let owner_cpu = captured
            .records
            .iter()
            .filter(|row| row.operation == Some(1) && row.dispatch_started)
            .try_fold(0_u64, |sum, row| {
                sum.checked_add(row.dispatch_thread_cpu_ns?)
            });
        let settled = flow.as_ref().is_some_and(|f| {
            f.balance_identity_verified
                && f.live_owners == 0
                && f.booked_reservation_ns == 0
                && f.unsettled_known_live_cpu_ns == 0
                && f.paid_cpu_debit_ns > 0
                && f.paid_cpu_debit_ns == f.settled_full_cpu_ns
                && Some(f.paid_cpu_debit_ns) == owner_cpu
                && service_outcome["Ok"]["mutation_cpu_charged_ns"].as_u64() == owner_cpu
        });
        let membership = root_readiness.len() == ATTACKERS
            && root_readiness
                .iter()
                .all(|r| r["cgroup"].as_str() == controller_cgroup.as_deref());
        let acquisition_complete = root_acquisitions.len() == ATTACKERS
            && children.len() == ATTACKERS
            && root_acquisitions
                .iter()
                .zip(children.iter())
                .zip(root_readiness.iter())
                .enumerate()
                .all(|(worker, ((acquisition, child), ready))| {
                    let result = &child["report"]["result"];
                    checked_root_acquisition(acquisition, worker, method)
                        && result["acquisition"] == *acquisition
                        && result["worker"] == worker
                        && result["pid"] == child["pid"]
                        && ready["pid"] == child["pid"]
                        && result["calls"].as_array().is_some_and(|calls| {
                            !calls.is_empty()
                                && calls.iter().all(|call| {
                                    call["public_request_body_digest"]
                                        == acquisition["public_request_body_digest"]
                                })
                        })
                })
            && root_packet_ids
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == ATTACKERS
            && hostile_digests
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == ATTACKERS
            && root_acquisitions
                .iter()
                .filter_map(|v| v["header"].as_str())
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == ATTACKERS;
        for round in report["confirmations"].as_array_mut().unwrap() {
            let start = round["started_ns"].as_u64().unwrap();
            let end = round["ended_ns"].as_u64().unwrap();
            round["signed_root_responses_inside_round"] = json!(attack_calls
                .iter()
                .filter(|call| signed_root_response_inside(call, start, end, &hostile_digests))
                .count());
        }
        let final_stats = owner.lock().unwrap().stats().unwrap();
        let absent = |node: &Node| {
            root_packet_ids.len() == ATTACKERS
                && root_packet_ids.iter().all(|id| {
                    node.packet(*id)
                        .err()
                        .is_some_and(|e| e.to_string() == "UNKNOWN_PARENT")
                })
        };
        let live_absent = absent(&owner.lock().unwrap());
        drop(owner);
        let reopened = state_backend.open(&path.join("receiver"), settings.clone());
        let cold_equal =
            reopened.read_active().unwrap() == actual && reopened.stats().unwrap() == final_stats;
        let cold_absent = absent(&reopened);
        let expected_tip = business.last().unwrap().id().unwrap();
        let expected_counts = final_stats["stored_blocks"] == 26
            && final_stats["events"] == 25
            && final_stats["height"] == 25
            && actual.0 == expected_tip;
        let root_criteria = common_criteria
            && f0_membership["verified"] == true
            && depletion_at.is_some()
            && ready_count == ATTACKERS
            && successful_actors
            && membership
            && acquisition_complete
            && settled
            && hostile_digests.len() == ATTACKERS
            && overlaps.len() == ROUNDS
            && overlaps.iter().all(|n| *n > 0)
            && report["confirmations"].as_array().unwrap().iter().all(|r| {
                r["accepted_work_admission_refusal_during_round"] == true
                    && r["signed_root_responses_inside_round"]
                        .as_u64()
                        .is_some_and(|n| n > 0)
            })
            && report["confirmations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["paid_credit_depletion_observed_during_round"] == true)
            && attack_calls.iter().all(|r| r["status"] != "ok")
            && live_absent
            && cold_absent
            && cold_equal
            && expected_counts;
        report["root_supplement"] = json!({"criteria_met":root_criteria,
            "controller_cgroup":controller_cgroup,"actor_readiness":root_readiness,"aggregate_membership_verified":membership,
            "checked_acquisitions_complete":acquisition_complete,"acquisitions":root_acquisitions,
            "whole_domain_paid_reconciled":settled,"mutation_owner_cpu_ns":owner_cpu,
            "aggregate_scoped_cpu_ns":flow.as_ref().zip(owner_cpu).and_then(|(f,c)|f.paid_cpu_debit_ns.checked_sub(c)),
            "hostile_packet_ids":root_packet_ids.iter().map(hex::encode).collect::<Vec<_>>(),
            "hostile_packets_absent_live":live_absent,"hostile_packets_absent_cold":cold_absent,
            "cold_state_equal":cold_equal,"expected_legal_counts_and_tip":expected_counts,"final_stats":final_stats,
            "final_state_rows":actual.2.iter().map(|(k,v)|(hex::encode(k),hex::encode(serde_json::to_vec(v).unwrap()))).collect::<Vec<_>>(),
            "scope":"whole-domain paid CPU includes honest and hostile Submit; known zero scoped CPU from one M06 worker; ROOT reply evidence and observer refusal evidence are separate; cold reopen is after the window",
            "round_snapshot_scope":"live observer snapshots are non-atomic; ROOT round end follows the last after snapshot and must remain before the fixed phase end",
            "original_campaign_qualified":false});
    }
    report["fixed_root_external_actor_membership"] = f0_membership;
    report["controller_resource_ready"] = controller_resource_ready;
    report
}

fn run_phase(
    path: &Path,
    settings: &Settings,
    seed: &[Packet],
    business: &[Packet],
    mode: Option<&str>,
    controller: &VerifiedController,
) -> Value {
    controller.verify().unwrap();
    assert_eq!(controller.identity.process.pid, std::process::id());
    assert!(matches!(mode, None | Some("valid-work-root")));
    let method = 0;
    let configuration = CampaignConfiguration::new(
        StateBackendChoice::AuthenticatedV1,
        support::WorkProfile::RawR14,
    )
    .unwrap();
    assert_eq!(settings.network(), support::settings().network());
    assert_eq!(settings.parameters(), support::settings().parameters());
    assert_eq!(settings.genesis(), support::settings().genesis());
    let parent = path.parent().unwrap().canonicalize().unwrap();
    let path = parent.join(path.file_name().unwrap());
    let control = path.with_file_name(format!(
        "{}-fixed-root-host-control",
        path.file_name().unwrap().to_str().unwrap()
    ));
    fs::create_dir(&control).unwrap();
    let controller_resource_before =
        controller_resources::sample(controller, "before_launch", &[], 0);
    publish(
        &control.join("controller-resource-before-launch.json"),
        &controller_resource_before,
    );
    let context = unified_cgroup();
    assert_eq!(context, controller.identity.process.cgroup);
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
    let job = RootPhaseJob {
        schema: PROFILE.to_owned(),
        phase_path: path.clone(),
        controller: controller.identity.clone(),
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
    let job_path = control.join("root-phase-job.json");
    publish(&job_path, &serde_json::to_value(&job).unwrap());
    assert!(fs::metadata(&job_path).unwrap().len() <= JOB_BYTES as u64);
    let launcher = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../scripts/ci/run_fixed_root_phase_host.py")
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
                let identity = controller.actor(pid).unwrap();
                let observation = json!({"ordinal":ordinal,"pid":pid,"actual_cgroup":actual.trim(),"identity":identity});
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
    controller.verify().unwrap();
    let mut result = read(&control.join("phase-result.json"), REPORT_BYTES);
    let controller_resource_after = controller_resources::sample(controller, "after_reap", &[], 0);
    publish(
        &control.join("controller-resource-after-reap.json"),
        &controller_resource_after,
    );
    result["external_controller_resources"] = controller_resources::finish(
        &controller.identity,
        mode.unwrap_or("baseline"),
        controller_resource_before,
        result["controller_resource_ready"].clone(),
        controller_resource_after,
        &contexts,
        result["children"].as_array().unwrap(),
    );
    result["public_phase_children_os_usage_before"] = result["children_os_usage_before"].clone();
    result["public_phase_children_os_usage_after"] = result["children_os_usage_after"].clone();
    result["children_os_usage_before"] = child_usage_before;
    result["children_os_usage_after"] = support::children_usage();
    result["external_controller_observation"] = json!({
        "schema":PROFILE,"pid":std::process::id(),"controller_cgroup":context,
        "controller_identity":controller.identity,"controller_live_identity_after_verified":true,
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

fn planned_rounds(value: &Value) -> Vec<Value> {
    let names = ["baseline", "valid-work-root"];
    let mut result = Vec::with_capacity(2 * ROUNDS);
    for (phase_index, phase_name) in names.iter().enumerate() {
        let phase = &value["phases"][phase_index];
        for round in 0..ROUNDS {
            let matches: Vec<_> = phase["confirmations"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|row| {
                    phase["mode"] == *phase_name && row["round"].as_u64() == Some(round as u64)
                })
                .collect();
            let observed = matches.len() == 1;
            let row = if observed { matches[0] } else { &Value::Null };
            let scheduled = (1 + 4 * round as u64) * 1_000_000_000;
            let started = &row["started_ns"];
            let ended = &row["ended_ns"];
            let known = started
                .as_u64()
                .zip(ended.as_u64())
                .is_some_and(|(a, b)| scheduled <= a && a <= b);
            let confirmed = observed && row["confirmed_inside_pressure_window"] == true;
            let elapsed = ended.as_u64().and_then(|end| end.checked_sub(scheduled));
            let slo = confirmed
                && known
                && elapsed.is_some_and(|n| n < 4_000_000_000)
                && ended
                    .as_u64()
                    .is_some_and(|end| end < WINDOW_SECONDS * 1_000_000_000);
            let start_late = known.then(|| started.as_u64().unwrap() - scheduled);
            let end_late = known.then(|| {
                ended
                    .as_u64()
                    .unwrap()
                    .saturating_sub(scheduled + 4_000_000_000)
            });
            result.push(
                json!({"phase":phase_name,"round":round,"scheduled_offset_ns":scheduled,
                "actual_started_ns":started,"actual_ended_ns":ended,
                "elapsed_from_scheduled_ns":elapsed,"start_lateness_from_schedule_ns":start_late,
                "end_lateness_from_four_second_deadline_ns":end_late,
                "observed_exactly_once":observed,"confirmed_inside_original_window":confirmed,
                "four_second_slo_met":slo,"old_root_code_already_enforced_four_second_slo":false}),
            );
        }
    }
    result
}

fn planned_packets(value: &Value) -> Vec<Value> {
    let mut result = Vec::with_capacity(42);
    for (phase_index, phase_name) in ["baseline", "valid-work-root"].iter().enumerate() {
        let phase = &value["phases"][phase_index];
        for packet_index in 0..21 {
            let attempts: Vec<_> = phase["submissions"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|row| {
                    phase["mode"] == *phase_name
                        && row["packet_index"].as_u64() == Some(packet_index)
                })
                .collect();
            let on_time = attempts
                .iter()
                .any(|row| row["status"] == "ok" && row["returned_after_window"] == false);
            result.push(json!({"phase":phase_name,"packet_index":packet_index,
                "observed_attempts":attempts.len(),"timely_network_ack":on_time,"ack_is_not_confirmation":true}));
        }
    }
    result
}

pub(super) fn diagnostic() {
    let output = PathBuf::from(
        std::env::var_os("TRNM_FIXED_HOST_ROOT_REPORT_DIR")
            .expect("explicit fresh F0 report directory"),
    );
    fs::create_dir(&output).unwrap();
    support::write_new(
        &output.join("predeclared-denominators.json"),
        &json!({
        "schema":"fixed-host-root-f0-native-predeclaration-v1","planned_confirmations":6,
        "planned_business_packet_exposures":42,"all_planned_rounds":planned_rounds(&Value::Null),
        "all_planned_business_packets":planned_packets(&Value::Null),"phase_seconds":30,
        "cpu_burst_ns":2_000_000_000_u64,"cpu_refill_ns_per_second":250_000_000_u64,
        "actual_depletion_required":true,"native_complete":false,
        "controller_resource_schema":controller_resources::SCHEMA,
        "planned_controller_resource_boundary_samples":6,
        "controller_resources_complete":false,"per_actor_rss_qualified":false,
        "recovery_scope":"r10 reconstructed Rust; no identity with missing cf845/364600 bytes"}),
    );
    let controller = VerifiedController::current().unwrap();
    let setup_started = Instant::now();
    let setup_cpu = support::cpu();
    let settings = support::settings();
    let backend = StateBackendChoice::AuthenticatedV1;
    let mut producer = backend.open(&output.join("honest-miner"), settings.clone());
    let seed = signed_campaign_seed(&mut producer, &settings);
    let business = signed_campaign_business(&mut producer, &settings);
    assert_eq!(seed.len(), 4);
    assert!(seed.iter().all(|p| p.transactions.len() == 256));
    assert_eq!(business.len(), 21);
    assert_eq!(business[0].header.parent, seed[3].id().unwrap());
    assert_eq!(business[0].header.height, 5);
    assert_eq!(business[0].transactions.len(), 1);
    assert_eq!(
        trnm_protocol::pon_wire::Envelope::decode(&business[0].transactions[0])
            .unwrap()
            .nonce,
        1025
    );
    let expected = producer.read_active().unwrap();
    let expected_stats = producer.stats().unwrap();
    let expected_rows: Vec<_> = expected
        .2
        .iter()
        .map(|(k, v)| (hex::encode(k), hex::encode(serde_json::to_vec(v).unwrap())))
        .collect();
    let preparation = json!({"cpu_ns":support::elapsed_cpu(setup_cpu),"wall_ns":setup_started.elapsed().as_nanos(),
        "seed_packets":seed.iter().map(|p|hex::encode(p.encode().unwrap())).collect::<Vec<_>>(),
        "business_packets":business.iter().map(|p|hex::encode(p.encode().unwrap())).collect::<Vec<_>>(),
        "expected_stats":expected_stats,"expected_state_rows":expected_rows,
        "scope":"all real signing, Node search attempts, execution and durable reference preparation; Node search denominator unavailable; no injected State"});
    support::write_new(&output.join("preparation.json"), &preparation);
    drop(producer);
    let mut phases = Vec::new();
    for mode in [None, Some("valid-work-root")] {
        let name = mode.unwrap_or("baseline");
        let result = std::panic::catch_unwind(|| run_phase(&output.join(name), &settings, &seed, &business, mode, &controller))
            .unwrap_or_else(|error| json!({"mode":name,"startup_or_campaign_error":error.downcast_ref::<String>()
                .cloned().or_else(||error.downcast_ref::<&str>().map(|s|s.to_string())).unwrap_or_else(||"non-string panic".to_owned())}));
        support::write_new(&output.join(format!("{name}.json")), &result);
        phases.push(result);
    }
    let controller_after = controller.verify().map(|()| controller.identity.clone());
    let stable = controller_after.is_ok();
    let controller_resources_complete = controller_resources::campaign_complete(&phases);
    let root = &phases[1]["root_supplement"];
    let producer_state_equal =
        root["final_stats"] == expected_stats && root["final_state_rows"] == json!(expected_rows);
    let preparation_known = known_positive(&preparation, &["cpu_ns", "wall_ns"]);
    let placement_complete = stable
        && phases.iter().all(|phase| {
            phase["fixed_root_external_actor_membership"]["verified"] == true
                && phase["phase_process_context"]["controller_live_identity_after_verified"] == true
                && phase["external_controller_observation"]
                    ["controller_live_identity_after_verified"]
                    == true
        });
    let mut report = json!({"schema":"native-public-v3-fixed-host-root-f0-v1",
        "state_backend":"authenticated-v1","m06_workers":1,"producer_method":work::METHODS[0],
        "seed_transfers":1024,"seed_blocks":4,"business_blocks":21,"phase_seconds":30,
        "actor_call_cap":CALL_CAP,"planned_complete_runs":1,"producer_state_equal":producer_state_equal,
        "preparation_cost_known":preparation_known,"preparation":preparation,"phases":phases,
        "placement_profile":PROFILE,"placement_complete":placement_complete,
        "controller_identity_before":controller.identity,"controller_identity_after":controller_after,
        "controller_stable":stable,"planned_confirmations":6,"planned_business_packet_exposures":42,
        "controller_resources_complete":controller_resources_complete,
        "controller_resource_schema":controller_resources::SCHEMA,
        "new_f1_parameters_implemented":false,"original_scalar_profile_changed":false,
        "source_reconstructed_after_workspace_reset":true,
        "scope":"one predeclared same-host baseline and full-W1 late-M06 ROOT cohort; no independent WAN claim",
        "original_campaign_qualified":false,"work_profile_qualified":false,"independent_operators":false,
        "wan_qualified":false,"production_candidate":false,"production_activation":false});
    let rounds = planned_rounds(&report);
    let packets = planned_packets(&report);
    let passed = preparation_known
        && placement_complete
        && controller_resources_complete
        && report["phases"][0]["finite_phase_criteria_met"] == true
        && report["phases"][1]["root_supplement"]["criteria_met"] == true
        && producer_state_equal
        && rounds.iter().all(|r| r["four_second_slo_met"] == true)
        && packets.iter().all(|p| p["timely_network_ack"] == true);
    report["supplemental_criteria_met"] = json!(passed);
    report["all_planned_rounds"] = json!(rounds);
    report["all_planned_business_packets"] = json!(packets);
    support::write_new(&output.join("report.json"), &report);
    assert!(
        passed,
        "F0 criteria failed; all raw evidence retained at {}",
        output.display()
    );
}

#[test]
fn fixed_root_proc_identity_requires_exact_pid_and_start_despite_command_parentheses() {
    let mut fields = vec!["0"; 20];
    fields[0] = "S";
    fields[1] = "10";
    fields[19] = "12345";
    let raw = format!("42 (a) command (with parentheses)) {}", fields.join(" "));
    assert_eq!(process_stat(&raw, 42).unwrap(), (10, 12345));
    assert!(process_stat(&raw, 43).is_err());
    fields[19] = "0";
    assert!(process_stat(&format!("42 (a) {}", fields.join(" ")), 42).is_err());
    assert!(process_stat("42 (short) S 10", 42).is_err());
    for group in [
        "",
        "/",
        "/trnmponpublic.slice",
        "/trnmponpublic.slice/child",
        "/a/../b",
        "/a//b",
    ] {
        assert!(external_group(group).is_err());
    }
}

fn timing_fixture() -> Value {
    let phases: Vec<_> = ["baseline", "valid-work-root"]
        .iter()
        .map(|phase| {
            let confirmations: Vec<_> = (0..ROUNDS)
                .map(|round| {
                    json!({"round":round,
            "started_ns":(1 + 4 * round as u64) * 1_000_000_000,
            "ended_ns":(2 + 4 * round as u64) * 1_000_000_000,
            "confirmed_inside_pressure_window":true})
                })
                .collect();
            json!({"mode":phase,"confirmations":confirmations})
        })
        .collect();
    json!({"phases":phases})
}

#[test]
fn fixed_root_denominators_retain_all_missing_failed_and_duplicate_rounds() {
    let empty = Value::Null;
    assert_eq!(planned_rounds(&empty).len(), 6);
    assert_eq!(planned_packets(&empty).len(), 42);
    assert!(planned_rounds(&empty)
        .iter()
        .all(|row| row["four_second_slo_met"] == false));
    let mut value = timing_fixture();
    let duplicate = value["phases"][0]["confirmations"][0].clone();
    value["phases"][0]["confirmations"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    value["phases"][1]["confirmations"][1]["round"] = json!(true);
    let rows = planned_rounds(&value);
    assert_eq!(rows.len(), 6);
    assert_eq!(
        rows.iter()
            .filter(|row| row["four_second_slo_met"] == true)
            .count(),
        4
    );
    assert_eq!(planned_packets(&value).len(), 42);
}

#[test]
fn fixed_root_four_second_slo_cannot_remove_queue_or_prior_round_delay() {
    let mut value = timing_fixture();
    assert!(planned_rounds(&value)
        .iter()
        .all(|row| row["four_second_slo_met"] == true));
    value["phases"][0]["confirmations"][0]["started_ns"] = json!(4_000_000_000_u64);
    value["phases"][0]["confirmations"][0]["ended_ns"] = json!(5_000_000_001_u64);
    let rows = planned_rounds(&value);
    assert_eq!(rows[0]["elapsed_from_scheduled_ns"], 4_000_000_001_u64);
    assert_eq!(rows[0]["four_second_slo_met"], false);
    value["phases"][0]["confirmations"][0]["ended_ns"] = json!(5_000_000_000_u64);
    assert_eq!(planned_rounds(&value)[0]["four_second_slo_met"], false);
    value["phases"][0]["confirmations"][1]["started_ns"] = json!(9_000_000_000_u64);
    value["phases"][0]["confirmations"][1]["ended_ns"] = json!(9_000_000_001_u64);
    assert_eq!(planned_rounds(&value)[1]["four_second_slo_met"], false);
}

#[test]
fn fixed_root_job_requires_its_exact_profile_and_complete_workload() {
    // Shape fixture only. These hex strings are not valid packets or work and
    // cannot create VerifiedController or enter a Host phase.
    let value = json!({"schema":PROFILE,"phase_path":"/fixture/baseline",
        "controller":{"process":{"pid":42,"parent_pid":10,"start_ticks":1,
            "boot_id":"00000000-0000-0000-0000-000000000001","cgroup":"/fixture",
            "executable":{"device":1,"inode":2,"bytes":3,"modified_seconds":4,"modified_nanoseconds":5}},
            "cgroup":{"device":1,"inode":2,"uid":0,"gid":0,"mode":493}},
        "binary_sha256":"a".repeat(64),"state_backend":"authenticated-v1","work_profile":"raw-r14",
        "mode":null,"method":0,"seed":vec!["00";4],"business":vec!["00";21]});
    let job: RootPhaseJob = serde_json::from_value(value.clone()).unwrap();
    job.validate_shape().unwrap();
    for (key, field) in [
        ("schema", json!("fixed-public-phase-external-actors-v1")),
        ("state_backend", json!("legacy-v2")),
        ("work_profile", json!("arithmetic-facts-v1")),
        ("mode", json!("from-zero")),
        ("method", json!(1)),
        ("seed", json!(vec!["00"; 3])),
        ("business", json!(vec!["00"; 20])),
    ] {
        let mut changed = value.clone();
        changed[key] = field;
        assert!(serde_json::from_value::<RootPhaseJob>(changed)
            .unwrap()
            .validate_shape()
            .is_err());
    }
    let mut extra = value;
    extra["fallback"] = json!(true);
    assert!(serde_json::from_value::<RootPhaseJob>(extra).is_err());
}
