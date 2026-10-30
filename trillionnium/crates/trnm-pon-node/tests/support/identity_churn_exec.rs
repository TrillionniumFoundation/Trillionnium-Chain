//! Linux v2 actor identity. This is a dedicated harness owner, not a sandbox.
//! Every participating spawn holds LOCK; other libraries must not spawn here.
use rustix::io::{fcntl_dupfd_cloexec, fcntl_getfd, fcntl_setfd, FdFlags};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command},
    sync::Mutex,
};

pub const SCHEMA: &str = "pon-identity-actor-fd-binding-v1";
const SCOPE: &str = "dedicated-v2-exact-single-test-serialized-harness-spawn-v1";
const JOB_ENV: &str = "TRNM_IDENTITY_ACTOR_EXEC_BINDING";
const JOB_LIMIT: u64 = 448 * 1024;
static LOCK: Mutex<()> = Mutex::new(());

fn check(value: bool, message: &str) -> io::Result<()> {
    if value {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}
fn proc_fd(fd: i32) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{fd}"))
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub device: u64,
    pub inode: u64,
}
fn identity(metadata: &fs::Metadata) -> Identity {
    Identity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}
fn input_owner(metadata: &fs::Metadata, directory: bool) -> io::Result<()> {
    check(
        metadata.uid() == rustix::process::geteuid().as_raw()
            && if directory {
                metadata.is_dir() && metadata.nlink() >= 2
            } else {
                metadata.is_file() && metadata.nlink() == 1
            },
        "owned no-link-alias input required",
    )
}
fn owned(metadata: &fs::Metadata, directory: bool) -> io::Result<()> {
    input_owner(metadata, directory)?;
    check(metadata.mode() & 0o022 == 0, "private owned input required")
}
pub fn create_directory(path: &Path) -> io::Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)
}
/// The original job owner/count/one-sync/NOREPLACE order, with atomic 0600.
/// This is deliberately local to new v2 jobs; the shared writer is unchanged.
pub fn write_job(
    output: &Held,
    budget: &mut super::evidence::Budget,
    value: &Value,
) -> io::Result<u64> {
    if budget.poisoned {
        return Err(io::Error::other("v2 evidence owner poisoned"));
    }
    let result = (|| {
        let bytes = super::evidence::encoded_bytes(value)?;
        if bytes > JOB_LIMIT || bytes > budget.remaining() {
            budget.cap_reached = true;
            return Err(io::Error::other("v2 evidence byte cap"));
        }
        let path = output.path().join("job.json");
        check(!path.try_exists()?, "immutable receipt")?;
        let temporary = path.with_extension("partial.json");
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        budget.used += bytes;
        serde_json::to_writer(&mut file, value)?;
        file.sync_all()?;
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            &temporary,
            rustix::fs::CWD,
            &path,
            rustix::fs::RenameFlags::NOREPLACE,
        )?;
        Ok(bytes)
    })();
    if result.is_err() {
        budget.poisoned = true;
    }
    result
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn read(file: &File, limit: u64) -> io::Result<Vec<u8>> {
    let before = file.metadata()?;
    owned(&before, false)?;
    check(before.len() <= limit, "input byte cap")?;
    let mut stream = file.try_clone()?;
    stream.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    stream.take(limit + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    check(
        identity(&before) == identity(&after)
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.ctime() == after.ctime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime_nsec() == after.ctime_nsec()
            && bytes.len() as u64 == before.len(),
        "input changed during read",
    )?;
    Ok(bytes)
}
fn image_pin(file: &File) -> io::Result<ImagePin> {
    let before = file.metadata()?;
    owned(&before, false)?;
    check(before.len() <= 192 * 1024 * 1024, "original binary cap")?;
    let mut stream = file.try_clone()?;
    stream.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    let after = file.metadata()?;
    check(
        identity(&before) == identity(&after)
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.ctime() == after.ctime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime_nsec() == after.ctime_nsec(),
        "actual executable changed during hash",
    )?;
    Ok(ImagePin {
        identity: identity(&before),
        bytes: before.len(),
        sha256: hex::encode(hash.finalize()),
    })
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImagePin {
    pub identity: Identity,
    pub bytes: u64,
    pub sha256: String,
}

pub struct Held {
    file: File,
    pub identity: Identity,
}
impl Held {
    fn new(file: File, directory: bool) -> io::Result<Self> {
        owned(&file.metadata()?, directory)?;
        let duplicate: File = fcntl_dupfd_cloexec(&file, 3)?.into();
        check(
            fcntl_getfd(&duplicate)?.contains(FdFlags::CLOEXEC),
            "CLOEXEC owner required",
        )?;
        Ok(Self {
            identity: identity(&duplicate.metadata()?),
            file: duplicate,
        })
    }
    pub fn directory(path: &Path) -> io::Result<Self> {
        let fd = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        Self::new(fd.into(), true)
    }
    pub fn path(&self) -> PathBuf {
        proc_fd(self.file.as_raw_fd())
    }
    /// A safe duplicate of this already owned directory capability. Never
    /// canonicalize/reopen its pathname; every native role parent consumes a
    /// CLOEXEC duplicate of this exact inode.
    pub fn try_clone_directory_file(&self) -> io::Result<File> {
        let before = self.file.metadata()?;
        owned(&before, true)?;
        check(
            identity(&before) == self.identity && before.mode() & 0o077 == 0,
            "private original held directory required",
        )?;
        check(
            fcntl_getfd(&self.file)?.contains(FdFlags::CLOEXEC),
            "held directory must be CLOEXEC at rest",
        )?;
        let duplicate: File = fcntl_dupfd_cloexec(&self.file, 3)?.into();
        check(
            identity(&duplicate.metadata()?) == self.identity
                && identity(&self.file.metadata()?) == self.identity
                && fcntl_getfd(&duplicate)?.contains(FdFlags::CLOEXEC),
            "held directory duplicate identity/CLOEXEC changed",
        )?;
        Ok(duplicate)
    }
    pub fn try_clone_directory(&self) -> io::Result<Self> {
        Self::new(self.try_clone_directory_file()?, true)
    }
    /// Create exactly one fresh basename under this held inode. Existing
    /// entries, including directories/symlinks from an earlier attempt, fail.
    pub fn create_child_directory(&self, name: &OsStr) -> io::Result<Self> {
        use std::os::unix::ffi::OsStrExt;
        let bytes = name.as_bytes();
        check(
            !bytes.is_empty()
                && bytes != b"."
                && bytes != b".."
                && !bytes.contains(&b'/')
                && !bytes.contains(&0),
            "one fresh directory basename required",
        )?;
        let parent = self.try_clone_directory_file()?;
        rustix::fs::mkdirat(&parent, name, rustix::fs::Mode::from_bits_truncate(0o700))?;
        let child = rustix::fs::openat(
            &parent,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        check(
            identity(&parent.metadata()?) == self.identity,
            "held parent inode changed",
        )?;
        Self::new(child.into(), true)
    }
    fn fd(&self) -> i32 {
        self.file.as_raw_fd()
    }
    fn job(path: &Path, expected: &Value) -> io::Result<Self> {
        let fd = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        let held = Self::new(fd.into(), false)?;
        check(
            read(&held.file, JOB_LIMIT)? == serde_json::to_vec(expected)?,
            "published job bytes changed",
        )?;
        Ok(held)
    }
}

// Only F_GETFD/F_SETFD, with scalar arguments and no memory pointers/borrows.
// Callers keep owned FDs live, or identify the immutable Python caller inputs.
// This runs in the parent/ordinary child entry, never in a pre_exec callback.
fn raw_flags(fd: i32) -> io::Result<i32> {
    check(fd >= 3, "nonstdio live input descriptor required")?;
    let before = fs::metadata(proc_fd(fd))?;
    // SAFETY: fcntl F_GETFD consumes an integer descriptor and no pointer.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    check(
        identity(&before) == identity(&fs::metadata(proc_fd(fd))?),
        "raw input descriptor replaced",
    )?;
    Ok(flags)
}
fn raw_cloexec(fd: i32, expected: &Identity) -> io::Result<()> {
    check(
        identity(&fs::metadata(proc_fd(fd))?) == *expected,
        "raw input identity changed",
    )?;
    let flags = raw_flags(fd)?;
    // SAFETY: F_SETFD takes only two scalar integers; the live descriptor was
    // identified above and remains a caller-owned input for this process.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    check(
        raw_flags(fd)? & libc::FD_CLOEXEC != 0
            && identity(&fs::metadata(proc_fd(fd))?) == *expected,
        "raw CLOEXEC input transition failed",
    )
}
fn inherited() -> io::Result<Vec<i32>> {
    let mut descriptors = Vec::new();
    for entry in fs::read_dir("/proc/self/fd")? {
        let name = entry?.file_name();
        let fd = name
            .to_string_lossy()
            .parse::<i32>()
            .map_err(io::Error::other)?;
        if fd >= 3 {
            // Enumeration can include an ordinary CLOEXEC descriptor closed by
            // a completed log reader. Missing expected inputs are still caught
            // by the exact whitelist and their separate live identity checks.
            // SAFETY: scalar F_GETFD only, never a pre_exec callback.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if flags < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EBADF) {
                    continue;
                }
                return Err(error);
            }
            if flags & libc::FD_CLOEXEC == 0 {
                descriptors.push(fd);
            }
        }
    }
    descriptors.sort_unstable();
    Ok(descriptors)
}

pub struct Caller {
    executable: Held,
    // Original Python-owned descriptor stays open in this process; it is
    // quarantined CLOEXEC before any actor spawn. Not recovered from public
    // mutable receipt JSON and never used as an unrestricted pathname.
    python_output: Option<(i32, Identity)>,
    pub pin: ImagePin,
    pub receipt: Value,
}
impl Caller {
    pub fn new(qualification: bool) -> io::Result<Self> {
        let _lock = LOCK
            .lock()
            .map_err(|_| io::Error::other("spawn lock poisoned"))?;
        let args: Vec<_> = std::env::args().collect();
        check(
            args.iter().any(|s| s == "--exact") && args.iter().any(|s| s == "--test-threads=1"),
            "dedicated exact single-test native owner required",
        )?;
        let file = File::open("/proc/self/exe")?;
        let pin = image_pin(&file)?; // Replaces the parent's original one binary hash.
        let executable = Held::new(file, false)?;
        let cwd = identity(&File::open(".")?.metadata()?);
        let initial = inherited()?;
        let mut inputs = Vec::new();
        let mut python_output = None;
        if let Ok(raw) = std::env::var("TRNM_IDENTITY_CAMPAIGN_DIR") {
            if let Some(fd) = raw
                .strip_prefix("/proc/self/fd/")
                .and_then(|s| s.strip_suffix("/raw"))
            {
                let output = fd.parse::<i32>().map_err(io::Error::other)?;
                let mut kinds = std::collections::BTreeSet::new();
                for fd in &initial {
                    let metadata = fs::metadata(proc_fd(*fd))?;
                    let id = identity(&metadata);
                    let kind = if *fd == output {
                        input_owner(&metadata, true)?;
                        python_output = Some((*fd, id.clone()));
                        "output"
                    } else if metadata.is_dir() && id == cwd {
                        input_owner(&metadata, true)?;
                        "source-cwd"
                    } else if metadata.is_file() && id == pin.identity {
                        owned(&metadata, false)?;
                        "executable"
                    } else {
                        return Err(io::Error::other("unexpected inheritable caller descriptor"));
                    };
                    check(kinds.insert(kind), "duplicate caller descriptor class")?;
                    inputs.push(json!({"fd":fd,"kind":kind,"identity":id,"before_cloexec":false}));
                }
                check(
                    kinds.len() == 3 && initial.contains(&output),
                    "three exact Python caller inputs required",
                )?;
                for fd in &initial {
                    raw_cloexec(*fd, &identity(&fs::metadata(proc_fd(*fd))?))?;
                }
            }
        }
        check(
            !qualification || inputs.len() == 3,
            "qualification requires three exact Python FD inputs",
        )?;
        check(
            inherited()?.is_empty(),
            "extra nonstdio inheritable descriptor",
        )?;
        Ok(Self {
            executable,
            python_output,
            pin,
            receipt: json!({"schema":SCHEMA,"kind":"caller-scope","scope":SCOPE,
            "parent_pid":std::process::id(),"python_inputs":inputs,"remaining_inheritable":[],
            "external_library_concurrent_spawn_supported":false,"full_campaign_qualified":false}),
        })
    }
    /// New native-I/O profile requires the actual original Python output
    /// capability. Absence is an error; there is no pathname/legacy fallback.
    pub fn try_clone_python_output_directory(&self) -> io::Result<Held> {
        let (fd, expected) = self.python_output.as_ref().ok_or_else(|| {
            io::Error::other("native I/O profile requires original Python output FD")
        })?;
        check(
            identity(&fs::metadata(proc_fd(*fd))?) == *expected
                && raw_flags(*fd)? & libc::FD_CLOEXEC != 0,
            "original Python output descriptor identity/CLOEXEC changed",
        )?;
        // This explicit /proc/self/fd lookup duplicates the already admitted
        // kernel capability. It does not resolve the former output pathname.
        let file = File::open(proc_fd(*fd))?;
        let duplicate = Held::new(file, true)?;
        check(
            duplicate.identity == *expected && identity(&fs::metadata(proc_fd(*fd))?) == *expected,
            "original Python output capability changed while duplicated",
        )?;
        let _verified_private_duplicate = duplicate.try_clone_directory_file()?;
        Ok(duplicate)
    }
    pub fn bind(
        &self,
        phase: &Held,
        output: &Held,
        job_path: &Path,
        value: &Value,
    ) -> io::Result<Dispatch> {
        let job = Held::job(job_path, value)?;
        let bytes = read(&job.file, JOB_LIMIT)?;
        let binding = Binding {
            schema: SCHEMA.into(),
            scope: SCOPE.into(),
            parent_pid: std::process::id(),
            executable: self.pin.clone(),
            fds: [self.executable.fd(), phase.fd(), output.fd(), job.fd()],
            phase: phase.identity.clone(),
            output: output.identity.clone(),
            job_identity: job.identity.clone(),
            job_bytes: bytes.len() as u64,
            job_sha256: digest(&bytes),
            plan_sha256: digest(&serde_json::to_vec(&value["plan"])?),
        };
        Ok(Dispatch { binding, job })
    }
    pub fn command(&self) -> Command {
        Command::new(self.executable.path())
    }
    pub fn spawn(
        &self,
        command: &mut Command,
        phase: &Held,
        output: &Held,
        dispatch: &Dispatch,
    ) -> io::Result<(Child, Value)> {
        let _lock = LOCK
            .lock()
            .map_err(|_| io::Error::other("spawn lock poisoned"))?;
        check(
            inherited()?.is_empty(),
            "unexpected inheritable descriptor before actor spawn",
        )?;
        let files = [
            &self.executable.file,
            &phase.file,
            &output.file,
            &dispatch.job.file,
        ];
        let mut guard = Inheritance {
            files,
            restored: false,
        };
        for file in files {
            check(
                fcntl_getfd(file)?.contains(FdFlags::CLOEXEC),
                "input not CLOEXEC at rest",
            )?;
        }
        for file in files {
            fcntl_setfd(file, FdFlags::empty())?;
        }
        let mut expected = dispatch.binding.fds.to_vec();
        expected.sort_unstable();
        check(
            inherited()? == expected,
            "actor inheritance whitelist mismatch",
        )?;
        command
            .env(JOB_ENV, serde_json::to_string(&dispatch.binding)?)
            .env("TRNM_IDENTITY_ACTOR_JOB", dispatch.job.path());
        let spawned = command.spawn();
        let restored = guard.restore();
        if let Err(error) = restored {
            if let Ok(mut child) = spawned {
                let _ = child.kill();
                let _ = child.wait();
            }
            return Err(error);
        }
        Ok((
            spawned?,
            json!({"schema":SCHEMA,"kind":"parent-dispatch","binding":dispatch.binding,
            "inherited_nonstdio":expected,"parent_restored_cloexec":true,"caller":self.receipt,
            "full_campaign_qualified":false}),
        ))
    }
}
struct Inheritance<'a> {
    files: [&'a File; 4],
    restored: bool,
}
impl Inheritance<'_> {
    fn restore(&mut self) -> io::Result<()> {
        let mut failure = None;
        for file in self.files {
            if let Err(error) = fcntl_setfd(file, FdFlags::CLOEXEC) {
                failure = Some(io::Error::from(error));
            }
        }
        self.restored = true;
        if let Some(error) = failure {
            Err(error)
        } else {
            Ok(())
        }
    }
}
impl Drop for Inheritance<'_> {
    fn drop(&mut self) {
        if !self.restored {
            let _ = self.restore();
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    schema: String,
    scope: String,
    parent_pid: u32,
    executable: ImagePin,
    fds: [i32; 4],
    phase: Identity,
    output: Identity,
    job_identity: Identity,
    job_bytes: u64,
    job_sha256: String,
    plan_sha256: String,
}
pub struct Dispatch {
    binding: Binding,
    job: Held,
}
pub struct Input {
    binding: Binding,
    pub bytes: Vec<u8>,
}
pub struct Verified {
    pub binary_sha256: String,
    pub output: PathBuf,
    pub phase: PathBuf,
    pub receipt: Value,
}
impl Input {
    pub fn paths(&self) -> (PathBuf, PathBuf) {
        (proc_fd(self.binding.fds[2]), proc_fd(self.binding.fds[1]))
    }
    pub fn read(job_path: &Path) -> io::Result<Self> {
        let encoded = std::env::var(JOB_ENV).map_err(io::Error::other)?;
        check(encoded.len() <= 4096, "actor binding environment cap")?;
        let binding: Binding = serde_json::from_str(&encoded)?;
        check(
            binding.schema == SCHEMA
                && binding.scope == SCOPE
                && binding.fds.iter().all(|fd| *fd >= 3)
                && binding
                    .fds
                    .iter()
                    .copied()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    == 4,
            "exact four nonstdio actor inputs required",
        )?;
        let mut expected = binding.fds.to_vec();
        expected.sort_unstable();
        check(
            inherited()? == expected && job_path == proc_fd(binding.fds[3]),
            "child FD whitelist/job path mismatch",
        )?;
        for (index, (fd, id)) in binding
            .fds
            .iter()
            .zip([
                &binding.executable.identity,
                &binding.phase,
                &binding.output,
                &binding.job_identity,
            ])
            .enumerate()
        {
            owned(&fs::metadata(proc_fd(*fd))?, index == 1 || index == 2)?;
            raw_cloexec(*fd, id)?;
        }
        check(
            inherited()?.is_empty(),
            "child failed to quarantine actor inputs",
        )?;
        let job = File::open(job_path)?;
        check(
            identity(&job.metadata()?) == binding.job_identity,
            "actual job identity changed",
        )?;
        let bytes = read(&job, JOB_LIMIT)?;
        check(
            bytes.len() as u64 == binding.job_bytes && digest(&bytes) == binding.job_sha256,
            "actual job raw bytes changed",
        )?;
        Ok(Self { binding, bytes })
    }
    pub fn verify(self, plan: &Value, binary: &str) -> io::Result<Verified> {
        check(
            rustix::process::getppid().map(|pid| pid.as_raw_pid() as u32)
                == Some(self.binding.parent_pid),
            "actor parent changed",
        )?;
        check(
            digest(&serde_json::to_vec(plan)?) == self.binding.plan_sha256,
            "actor plan changed",
        )?;
        let pin = image_pin(&File::open("/proc/self/exe")?)?; // Replaces the child's original one binary hash.
        check(
            pin == self.binding.executable && pin.sha256 == binary,
            "actual child executable inode/hash changed",
        )?;
        Ok(Verified {
            binary_sha256: pin.sha256.clone(),
            output: proc_fd(self.binding.fds[2]),
            phase: proc_fd(self.binding.fds[1]),
            receipt: json!({"schema":SCHEMA,"kind":"child-verified","binding":self.binding,"actual_executable":pin,
                "inherited_nonstdio_after_quarantine":[],"job_raw_and_plan_checked":true,
                "input_lifetime":"process-lifetime-cloexec-quarantine-os-close-on-exit",
                "scope":SCOPE,"general_process_sandbox":false,"full_campaign_qualified":false}),
        })
    }
}

#[test]
#[ignore = "ordinary FD marker child only; never opens a Node or constructs W1"]
fn fd_marker_child() {
    let path = std::env::var_os("TRNM_IDENTITY_ACTOR_JOB").unwrap();
    let input = Input::read(Path::new(&path)).expect("child exact inherited inputs");
    let value: Value = serde_json::from_slice(&input.bytes).unwrap();
    let verified = input
        .verify(&value["plan"], value["binary_sha256"].as_str().unwrap())
        .expect("child actual executable and plan");
    let installed = super::limits::install(true).unwrap();
    assert_eq!(
        fs::read(verified.phase.join("marker.txt")).unwrap(),
        b"ORIGINAL"
    );
    let ready = json!({"schema":SCHEMA,"kind":"ordinary-marker-child","execution":verified.receipt,
        "process_limits":installed,"phase_identity":identity(&fs::metadata(&verified.phase).unwrap()),
        "output_identity":identity(&fs::metadata(&verified.output).unwrap()),
        "proof_calls":0,"node_opens":0,"full_campaign_qualified":false});
    super::evidence::Budget::new(64 * 1024)
        .write(&verified.output.join("ready.json"), &ready, 64 * 1024)
        .unwrap();
    println!("{ready}");
}

#[test]
#[ignore = "owned ordinary process FD control; no W1, original native campaign or public qualification"]
fn actual_descendant_identity_control() {
    use std::time::{Duration, Instant};
    let root = PathBuf::from(std::env::var_os("TRNM_IDENTITY_FD_CONTROL_DIR").unwrap());
    create_directory(&root).unwrap();
    let installed = super::limits::install(false).unwrap();
    let caller = Caller::new(false).unwrap();
    let active = root.join("active");
    create_directory(&active).unwrap();
    let logical_phase = active.join("phase");
    create_directory(&logical_phase).unwrap();
    let phase = Held::directory(&logical_phase).unwrap();
    fs::write(phase.path().join("marker.txt"), b"ORIGINAL").unwrap();
    let image_ancestor =
        PathBuf::from(std::env::var_os("TRNM_IDENTITY_FD_BINARY_ANCESTOR").unwrap());
    let physical_executable = std::env::current_exe().unwrap();
    assert_eq!(physical_executable.parent().unwrap(), image_ancestor);
    let moved_image = image_ancestor.with_file_name("moved-image");
    let mut retained = Vec::new();
    let mut rows = Vec::new();
    for (index, mode) in [
        "ancestor-shadow",
        "wrong-plan",
        "wrong-hash",
        "zero-fd",
        "extra-inheritable",
    ]
    .iter()
    .enumerate()
    {
        let name = format!("actor-{index:02}");
        let actual = phase.path().join(&name);
        create_directory(&actual).unwrap();
        let output = Held::directory(&actual).unwrap();
        let value = json!({"schema":"pon-identity-ordinary-fd-marker-job-v1","plan":super::plan::Plan::control(),
            "binary_sha256":caller.pin.sha256,"logical_output":logical_phase.join(&name),"test_marker_only":true});
        write_job(
            &output,
            &mut super::evidence::Budget::new(JOB_LIMIT),
            &value,
        )
        .unwrap();
        let mut dispatch = caller
            .bind(&phase, &output, &output.path().join("job.json"), &value)
            .unwrap();
        let mut command = caller.command();
        command.args([
            "--exact",
            "exec_identity::fd_marker_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ]);
        super::limits::configure_actor(&mut command);
        super::logs::Logs::pipe(&mut command);
        if index == 0 {
            // Both rebinding operations happen after command/input preparation.
            fs::rename(&image_ancestor, &moved_image).unwrap();
            create_directory(&image_ancestor).unwrap();
            let shadow = image_ancestor.join(physical_executable.file_name().unwrap());
            fs::write(&shadow, b"#!/bin/sh\nexit 77\n").unwrap();
            fs::set_permissions(&shadow, fs::Permissions::from_mode(0o500)).unwrap();
            fs::rename(&active, root.join("moved")).unwrap();
            fs::create_dir_all(logical_phase.join(&name)).unwrap();
            fs::write(logical_phase.join("marker.txt"), b"SHADOW").unwrap();
        }
        if *mode == "wrong-plan" {
            dispatch.binding.plan_sha256 = "0".repeat(64);
        }
        if *mode == "wrong-hash" {
            dispatch.binding.executable.sha256 = "0".repeat(64);
        }
        if *mode == "zero-fd" {
            dispatch.binding.fds[3] = 0;
        }
        let foreign = if *mode == "extra-inheritable" {
            let path = root.join("foreign");
            create_directory(&path).unwrap();
            let held = Held::directory(&path).unwrap();
            fcntl_setfd(&held.file, FdFlags::empty()).unwrap();
            Some(held)
        } else {
            None
        };
        let launched = caller.spawn(&mut command, &phase, &output, &dispatch);
        if let Some(foreign) = &foreign {
            fcntl_setfd(&foreign.file, FdFlags::CLOEXEC).unwrap();
        }
        let row = match launched {
            Err(error) => {
                assert!(["zero-fd", "extra-inheritable"].contains(mode));
                json!({"mode":mode,"spawned":false,"error":error.to_string(),"ready":null,
                    "parent_inheritable_after":inherited().unwrap(),"negative_pass":true})
            }
            Ok((mut child, parent)) => {
                let logs = super::logs::Logs::start(
                    &mut child,
                    &output.path().join("actor.log"),
                    64 * 1024,
                )
                .unwrap();
                let deadline = Instant::now() + Duration::from_secs(2);
                let mut killed = false;
                let status = loop {
                    if let Some(status) = child.try_wait().unwrap() {
                        break status;
                    }
                    if Instant::now() >= deadline {
                        child.kill().unwrap();
                        killed = true;
                        break child.wait().unwrap();
                    }
                    std::thread::sleep(Duration::from_millis(1));
                };
                let capture = logs.finish();
                let ready = fs::read(output.path().join("ready.json"))
                    .ok()
                    .map(|bytes| serde_json::from_slice::<Value>(&bytes).unwrap());
                assert!(
                    !killed,
                    "ordinary child exceeded original two-second control deadline"
                );
                if *mode == "ancestor-shadow" {
                    assert!(status.success());
                    let ready = ready.as_ref().unwrap();
                    assert_eq!(
                        ready["execution"]["actual_executable"],
                        serde_json::to_value(&caller.pin).unwrap()
                    );
                    assert_eq!(
                        ready["phase_identity"],
                        serde_json::to_value(&phase.identity).unwrap()
                    );
                    assert_eq!(
                        ready["output_identity"],
                        serde_json::to_value(&output.identity).unwrap()
                    );
                    assert!(!logical_phase.join(&name).join("ready.json").exists());
                } else {
                    assert!(!status.success() && ready.is_none());
                }
                json!({"mode":mode,"spawned":true,"pid":child.id(),"status":status.to_string(),
                    "success":status.success(),"forced_kill":killed,"ready":ready,"parent":parent,
                    "log_capture":capture,"parent_inheritable_after":inherited().unwrap(),"component_pass":true})
            }
        };
        assert!(inherited().unwrap().is_empty());
        rows.push(row);
        retained.push((output, dispatch));
    }
    let report = json!({"schema":SCHEMA,"kind":"ordinary-descendant-control","parent_process_limits":installed,
        "caller":caller.receipt,"actual_parent_executable":caller.pin,"rows":rows,"case_count":5,
        "all_children_joined":true,"parent_remaining_inheritable":inherited().unwrap(),
        "native_w1_calls":0,"node_opens":0,"full_campaign_qualified":false,
        "original_two_second_failure_closed":false,"sqlite_io_boundary_complete":false,
        "scope":SCOPE,"general_process_sandbox":false});
    super::evidence::Budget::new(1024 * 1024)
        .write(&root.join("report.json"), &report, 1024 * 1024)
        .unwrap();
    println!("{report}");
}
