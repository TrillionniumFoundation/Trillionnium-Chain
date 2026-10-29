//! Opt-in fixed-parent experiment only. The ordinary runtime never opens a
//! migration capability. A root-opened cgroup.procs descriptor can migrate
//! tasks to its one leaf; writing only "0\n" is this trusted harness's rule,
//! not a narrower capability enforced by the kernel.
use super::*;
use std::{
    io::{self, Read},
    mem::MaybeUninit,
    os::fd::{AsRawFd, FromRawFd},
    os::unix::{fs::MetadataExt, process::CommandExt},
    process::Command,
};
use trnm_pon_node::host_kernel_parent::{require_host_kernel_budget, FIXED_PUBLIC_KERNEL_PARENT};

const CONTEXT_SCHEMA: &str = "pon-fixed-parent-fixture-context-v1";
const FILE_LIMIT: u64 = 64 * 1024;
pub const LIMITS: [(&str, &str); 5] = [
    ("cpu.max", "25000 100000"),
    ("cpu.max.burst", "0"),
    ("memory.max", "2147483648"),
    ("memory.swap.max", "0"),
    ("pids.max", "256"),
];

fn require(ok: bool, message: &'static str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}
fn read(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let mut value = Vec::new();
    fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut value)?;
    require(value.len() as u64 <= limit, "FIXED_PARENT_READ_BOUND")?;
    Ok(value)
}
fn identity(meta: &fs::Metadata) -> Value {
    json!({"device":meta.dev(),"inode":meta.ino(),"uid":meta.uid(),
        "gid":meta.gid(),"mode":meta.mode()})
}
fn checked_directory(path: &Path, expected: &Value) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    require(
        meta.is_dir()
            && meta.uid() == 0
            && meta.mode() & 0o022 == 0
            && identity(&meta) == *expected,
        "FIXED_PARENT_DIRECTORY_IDENTITY",
    )
}
fn checked_context(context: &Value) -> io::Result<()> {
    require(
        context["schema"] == CONTEXT_SCHEMA
            && context["parent_path"] == FIXED_PUBLIC_KERNEL_PARENT
            && context["physical_authentication"] == false
            && context["production_qualified"] == false,
        "FIXED_PARENT_CONTEXT",
    )?;
    let parent = Path::new(FIXED_PUBLIC_KERNEL_PARENT);
    let leaf = Path::new(
        context["leaf_path"]
            .as_str()
            .ok_or_else(|| io::Error::other("FIXED_PARENT_LEAF"))?,
    );
    require(
        leaf.parent() == Some(parent)
            && leaf
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("owned-") && s.ends_with(".group")),
        "FIXED_PARENT_LEAF",
    )?;
    checked_directory(parent, &context["parent_identity"])?;
    checked_directory(leaf, &context["leaf_identity"])?;
    require(
        String::from_utf8(read(Path::new("/proc/sys/kernel/random/boot_id"), 128)?)
            .map_err(io::Error::other)?
            .trim()
            == context["boot_id"],
        "FIXED_PARENT_BOOT_CHANGED",
    )?;
    for (file, expected) in LIMITS {
        require(
            context["limits"][file] == expected
                && String::from_utf8(read(&parent.join(file), 128)?)
                    .map_err(io::Error::other)?
                    .trim()
                    == expected,
            "FIXED_PARENT_LIMIT_CHANGED",
        )?;
    }
    require(
        read(&parent.join("cgroup.type"), 64)? == b"domain\n"
            && read(&leaf.join("cgroup.type"), 64)? == b"domain\n",
        "FIXED_PARENT_DOMAIN_ONLY",
    )?;
    Ok(())
}
fn descriptor(fd: &fs::File, context: &Value) -> io::Result<Value> {
    let metadata = fd.metadata()?;
    require(
        identity(&metadata) == context["migration_file_identity"],
        "FIXED_PARENT_DESCRIPTOR_IDENTITY",
    )?;
    let mut filesystem = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: fd is live and filesystem is writable storage for fstatfs.
    require(
        unsafe { libc::fstatfs(fd.as_raw_fd(), filesystem.as_mut_ptr()) } == 0,
        "FIXED_PARENT_DESCRIPTOR_FILESYSTEM",
    )?;
    // SAFETY: the successful fstatfs initialized this storage.
    let filesystem = unsafe { filesystem.assume_init() };
    require(
        filesystem.f_type as u64 == 0x6367_7270,
        "FIXED_PARENT_DESCRIPTOR_NOT_CGROUP2",
    )?;
    // SAFETY: read-only fcntl commands on one live inherited descriptor.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    // SAFETY: F_GETFD reads descriptor-local flags.
    let descriptor_flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    require(
        flags >= 0
            && flags & libc::O_ACCMODE == libc::O_WRONLY
            && descriptor_flags >= 0
            && descriptor_flags & libc::FD_CLOEXEC != 0,
        "FIXED_PARENT_DESCRIPTOR_FLAGS",
    )?;
    require(
        fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))?
            == Path::new(context["leaf_path"].as_str().unwrap()).join("cgroup.procs"),
        "FIXED_PARENT_DESCRIPTOR_PATH",
    )?;
    Ok(json!({"fd":fd.as_raw_fd(),"identity":identity(&metadata),
        "open_flags":flags,"descriptor_flags":descriptor_flags,"close_on_exec":true,
        "filesystem_magic":filesystem.f_type as u64,
        "kernel_enforced_write_zero_only":false}))
}
fn group(pid: u32) -> io::Result<String> {
    String::from_utf8(read(&PathBuf::from(format!("/proc/{pid}/cgroup")), 4096)?)
        .map_err(io::Error::other)
}
fn role(pid: u32, expected_group: &str, forbidden: &Value) -> io::Result<Value> {
    let started = support::monotonic();
    let root = PathBuf::from(format!("/proc/{pid}"));
    let observed_group = group(pid)?;
    let mut descriptors = Vec::new();
    let mut matching = Vec::new();
    let mut failures = Vec::new();
    for entry in fs::read_dir(root.join("fd"))? {
        let entry = entry?;
        require(descriptors.len() < 256, "FIXED_PARENT_FD_CENSUS_BOUND")?;
        let number = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or_else(|| io::Error::other("FIXED_PARENT_FD_NAME"))?;
        match fs::metadata(entry.path()) {
            Ok(meta) => {
                if meta.dev() == forbidden["device"].as_u64().unwrap()
                    && meta.ino() == forbidden["inode"].as_u64().unwrap()
                {
                    matching.push(number);
                }
                descriptors.push(json!({"fd":number,"device":meta.dev(),"inode":meta.ino()}));
            }
            Err(error) => failures.push(json!({"fd":number,"error":error.to_string()})),
        }
    }
    let mut threads = Vec::new();
    for entry in fs::read_dir(root.join("task"))? {
        let entry = entry?;
        require(threads.len() < 256, "FIXED_PARENT_THREAD_BOUND")?;
        let tid = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or_else(|| io::Error::other("FIXED_PARENT_TID"))?;
        let raw = read(&entry.path().join("cgroup"), 4096)?;
        threads.push(json!({"tid":tid,"cgroup":String::from_utf8(raw).map_err(io::Error::other)?}));
    }
    require(!threads.is_empty(), "FIXED_PARENT_EMPTY_THREAD_CENSUS")?;
    let complete = failures.is_empty();
    Ok(
        json!({"pid":pid,"started_monotonic_ns":started,"ended_monotonic_ns":support::monotonic(),
        "cgroup":observed_group,"expected_cgroup":expected_group,"descriptors":descriptors,
        "matching_migration_descriptors":matching,"descriptor_errors":failures,
        "descriptor_capture_complete":complete,"threads":threads,
        "capability_descriptor_absent":complete && matching.is_empty(),
        "membership_matches":observed_group==expected_group
            && threads.iter().all(|t|t["cgroup"]==expected_group)}),
    )
}
fn assert_role(value: &Value) -> io::Result<()> {
    require(
        value["capability_descriptor_absent"] == true && value["membership_matches"] == true,
        "FIXED_PARENT_ROLE_MEMBERSHIP_OR_DESCRIPTOR",
    )
}

/// Only the new phase-controller selector can construct this capability owner.
pub struct Placement {
    migration: Option<fs::File>,
    context: Value,
    context_sha256: String,
    initial: Value,
    configured: bool,
}
impl Placement {
    pub fn from_environment() -> io::Result<Self> {
        let raw = std::env::var("TRNM_FIXED_PARENT_FD")
            .ok()
            .and_then(|s| s.parse::<libc::c_int>().ok())
            .filter(|fd| *fd >= 3)
            .ok_or_else(|| io::Error::other("FIXED_PARENT_DESCRIPTOR_REQUIRED"))?;
        // Set close-on-exec before any test preparation can spawn a process.
        // SAFETY: F_GETFD/F_SETFD only inspect/update this explicit inherited fd.
        let old_flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
        require(old_flags >= 0, "FIXED_PARENT_DESCRIPTOR_CLOSED")?;
        // SAFETY: same live descriptor; no file permissions or kernel quotas change.
        if unsafe { libc::fcntl(raw, libc::F_SETFD, old_flags | libc::FD_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the new selector exclusively takes the explicitly inherited fd.
        let migration = unsafe { fs::File::from_raw_fd(raw) };
        let context_path = PathBuf::from(
            std::env::var_os("TRNM_FIXED_PARENT_CONTEXT")
                .ok_or_else(|| io::Error::other("FIXED_PARENT_CONTEXT_REQUIRED"))?,
        );
        let metadata = fs::symlink_metadata(&context_path)?;
        require(
            metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
            "FIXED_PARENT_ROOT_CONTEXT",
        )?;
        let context_raw = read(&context_path, FILE_LIMIT)?;
        let context: Value = serde_json::from_slice(&context_raw).map_err(io::Error::other)?;
        checked_context(&context)?;
        // SAFETY: uid/gid/ppid accessors have no pointer or mutation.
        require(
            context["runner_uid"] == unsafe { libc::geteuid() }
                && context["runner_gid"] == unsafe { libc::getegid() }
                && context["root_fixture_pid"] == unsafe { libc::getppid() }
                && unsafe { libc::geteuid() } != 0,
            "FIXED_PARENT_UNPRIVILEGED_CONTROLLER",
        )?;
        require(
            group(std::process::id())? == context["outer_cgroup"],
            "FIXED_PARENT_CONTROLLER_OUTSIDE",
        )?;
        let initial = descriptor(&migration, &context)?;
        Ok(Self {
            migration: Some(migration),
            context,
            context_sha256: hex::encode(Sha256::digest(&context_raw)),
            initial,
            configured: false,
        })
    }

    pub fn configure(&mut self, command: &mut Command, path: &Path) -> io::Result<()> {
        require(!self.configured, "FIXED_PARENT_CAPABILITY_SINGLE_USE")?;
        checked_context(&self.context)?;
        let migration = self
            .migration
            .take()
            .ok_or_else(|| io::Error::other("FIXED_PARENT_CAPABILITY_CONSUMED"))?;
        descriptor(&migration, &self.context)?;
        let job = json!({"schema":"pon-fixed-parent-placement-v1","context":self.context,
            "context_sha256":self.context_sha256,"controller_pid":std::process::id(),
            "inherited_descriptor":self.initial,
            "scope":"One trusted pre-exec write of zero to the root-opened target-leaf capability; fork and pre-migration work are outside that cgroup but remain in wait4.",
            "kernel_enforced_write_zero_only":false,"physical_authentication":false});
        let job_path = path.join("fixed-parent-placement-v1.json");
        support::write_new(&job_path, &job);
        command.env("TRNM_FIXED_PARENT_PLACEMENT", &job_path);
        // SAFETY: after fork the closure performs only write(2), and creates
        // raw-errno errors. No allocations, locks, formatting or filesystem
        // lookup occur. The descriptor is held, CLOEXEC and one exact target.
        unsafe {
            command.pre_exec(move || {
                let written = libc::write(migration.as_raw_fd(), b"0\n".as_ptr().cast(), 2);
                if written == 2 {
                    Ok(())
                } else if written < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Err(io::Error::from_raw_os_error(libc::EIO))
                }
            });
        }
        self.configured = true;
        Ok(())
    }

    pub fn after_spawn(&self, path: &Path, receiver_pid: u32) -> io::Result<()> {
        require(
            self.configured && self.migration.is_none(),
            "FIXED_PARENT_CAPABILITY_NOT_CONSUMED",
        )?;
        checked_context(&self.context)?;
        let parent = role(
            std::process::id(),
            self.context["outer_cgroup"].as_str().unwrap(),
            &self.context["migration_file_identity"],
        )?;
        let receiver_group = format!(
            "0::{}\n",
            Path::new(self.context["leaf_path"].as_str().unwrap())
                .strip_prefix("/sys/fs/cgroup")
                .map_err(io::Error::other)?
                .display()
        );
        let receiver = role(
            receiver_pid,
            &receiver_group,
            &self.context["migration_file_identity"],
        )?;
        support::write_new(
            &path.join("fixed-parent-after-exec-v1.json"),
            &json!({"schema":"pon-fixed-parent-after-exec-v1","context_sha256":self.context_sha256,
                "controller":parent,"receiver":receiver,"physical_authentication":false}),
        );
        assert_role(&parent)?;
        assert_role(&receiver)
    }

    pub fn actors_ready(&self, path: &Path, population: usize) -> io::Result<()> {
        let mut actors = Vec::new();
        for index in 0..population {
            let raw = read(&path.join(format!("actor-{index}/ready.json")), FILE_LIMIT)?;
            let ready: Value = serde_json::from_slice(&raw).map_err(io::Error::other)?;
            let pid = ready["pid"]
                .as_u64()
                .and_then(|p| u32::try_from(p).ok())
                .ok_or_else(|| io::Error::other("FIXED_PARENT_ACTOR_PID"))?;
            let mut value = role(
                pid,
                self.context["outer_cgroup"].as_str().unwrap(),
                &self.context["migration_file_identity"],
            )?;
            value["actor"] = json!(index);
            actors.push(value);
        }
        let controller = role(
            std::process::id(),
            self.context["outer_cgroup"].as_str().unwrap(),
            &self.context["migration_file_identity"],
        )?;
        support::write_new(
            &path.join("fixed-parent-actors-ready-v1.json"),
            &json!({"schema":"pon-fixed-parent-actors-ready-v1","controller":controller,
                "actors":actors,"physical_authentication":false}),
        );
        assert_role(&controller)?;
        for value in &actors {
            assert_role(value)?;
        }
        Ok(())
    }

    fn observation(&self) -> Value {
        json!({"context_sha256":self.context_sha256,"initial_descriptor":self.initial,
            "capability_consumed":self.configured && self.migration.is_none(),
            "controller_pid":std::process::id(),"physical_authentication":false})
    }
}

pub fn receiver_entry(path: &Path) -> io::Result<()> {
    let Some(job_path) = std::env::var_os("TRNM_FIXED_PARENT_PLACEMENT") else {
        return Ok(());
    };
    let raw = read(&PathBuf::from(job_path), FILE_LIMIT)?;
    let job: Value = serde_json::from_slice(&raw).map_err(io::Error::other)?;
    require(
        job["schema"] == "pon-fixed-parent-placement-v1",
        "FIXED_PARENT_PLACEMENT",
    )?;
    checked_context(&job["context"])?;
    let expected = format!(
        "0::{}\n",
        Path::new(job["context"]["leaf_path"].as_str().unwrap())
            .strip_prefix("/sys/fs/cgroup")
            .map_err(io::Error::other)?
            .display()
    );
    let role = role(
        std::process::id(),
        &expected,
        &job["context"]["migration_file_identity"],
    )?;
    let kernel = require_host_kernel_budget(
        "127.0.0.1:1".parse().unwrap(),
        Some(FIXED_PUBLIC_KERNEL_PARENT),
    )
    .map_err(io::Error::other)?
    .ok_or_else(|| io::Error::other("FIXED_PARENT_NATIVE_GUARD_REQUIRED"))?;
    let bound = kernel.bound_resource_sample().map_err(io::Error::other)?;
    support::write_new(
        &path.join("fixed-parent-receiver-entry-v1.json"),
        &json!({"schema":"pon-fixed-parent-receiver-entry-v1","controller_pid":job["controller_pid"],
            "context_sha256":job["context_sha256"],"role":role,"kernel":bound,
            "before_node_construction":true,"physical_authentication":false}),
    );
    assert_role(&role)
}

fn common_inputs(output: &Path, settings: &Settings, mode: &str) -> (Vec<Packet>, Vec<Packet>) {
    if mode == "baseline" {
        require(
            !output.join("preparation.json").exists(),
            "FIXED_PARENT_PREPARATION_EXISTS",
        )
        .unwrap();
        return prepare(output, settings);
    }
    let raw = read(&output.join("preparation.json"), REPORT_BYTES).unwrap();
    let expected = std::env::var("TRNM_FIXED_PARENT_PREPARATION_SHA256").unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&raw)),
        expected,
        "immutable common preparation"
    );
    let value: Value = serde_json::from_slice(&raw).unwrap();
    let decode = |name| {
        value[name]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| Packet::decode(&hex::decode(v.as_str().unwrap()).unwrap()).unwrap())
            .collect::<Vec<_>>()
    };
    let seed = decode("seed");
    let business = decode("business");
    assert_eq!((seed.len(), business.len()), (4, 21));
    (seed, business)
}
const REPORT_BYTES: u64 = 64 * 1024 * 1024;

#[test]
#[ignore = "one of three separately owned fixed-parent observation phases; root fixture required"]
fn fixed_parent_receiver_phase_v1() {
    let output = PathBuf::from(std::env::var_os("TRNM_FIXED_PARENT_OUT").unwrap());
    let mode = std::env::var("TRNM_FIXED_PARENT_PHASE").unwrap();
    assert!(matches!(
        mode.as_str(),
        "baseline" | "from-zero" | "correct-product-false-trace"
    ));
    let mut placement = Placement::from_environment().unwrap();
    let settings = support::settings();
    let (seed, business) = common_inputs(&output, &settings, &mode);
    let common = read(&output.join("preparation.json"), REPORT_BYTES).unwrap();
    let common_sha256 = hex::encode(Sha256::digest(&common));
    let started = support::monotonic();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        receiver_owner::fixed_parent_phase(
            &output.join(&mode),
            &settings,
            &seed,
            &business,
            &mode,
            &mut placement,
        )
    }));
    let mut failure = None;
    let mut all_rounds_confirmed = false;
    match result {
        Ok(report) => {
            all_rounds_confirmed = report["rounds"].as_array().is_some_and(|rounds| {
                rounds.len() == ROUNDS
                    && rounds
                        .iter()
                        .all(|r| r["confirmed_inside_pressure_window"] == true)
            });
            support::write_new(&output.join(format!("{mode}.json")), &report);
        }
        Err(error) => {
            failure = Some(
                error
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| error.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_else(|| "fixed parent phase panic".to_owned()),
            );
        }
    }
    support::write_new(
        &output.join(format!("{mode}-controller-v1.json")),
        &json!({"schema":"pon-fixed-parent-phase-controller-v1","phase":mode,
            "started_monotonic_ns":started,"ended_monotonic_ns":support::monotonic(),
            "common_preparation_sha256":common_sha256,"placement":placement.observation(),
            "all_rounds_confirmed":all_rounds_confirmed,"error":failure,
            "original_campaign_qualification":false,"physical_authentication":false,
            "public_fairness_qualified":false,"production_qualified":false}),
    );
    // This new selector observes one phase. Honest service and the unchanged
    // paid-depletion predicates are reported separately by the independent
    // reader, never silently required or promoted by the host-fixture result.
    assert!(
        failure.is_none(),
        "fixed-parent phase failed; originals retained: {failure:?}"
    );
}

#[test]
fn native_fixed_parent_descriptor_rejects_ordinary_files() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("not-a-cgroup");
    fs::write(&path, b"unchanged").unwrap();
    let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
    let context = json!({"migration_file_identity":identity(&file.metadata().unwrap())});
    let failure = descriptor(&file, &context).unwrap_err();
    assert_eq!(failure.to_string(), "FIXED_PARENT_DESCRIPTOR_NOT_CGROUP2");
    assert_eq!(fs::read(path).unwrap(), b"unchanged");
}
