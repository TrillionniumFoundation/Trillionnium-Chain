// These ordinary temporary directories exercise only reads and inode fences.
// They cannot qualify as the fixed root-owned public cgroup or alter its limits.
use super::*;
use std::os::unix::fs::symlink;

const LIMIT_FIXTURE: [(&str, &str); 5] = [
    ("cpu.max", "25000 100000\n"),
    ("cpu.max.burst", "0\n"),
    ("memory.max", "268435456\n"),
    ("memory.swap.max", "0\n"),
    ("pids.max", "32\n"),
];

fn write_limits(parent: &Path) {
    for (name, text) in LIMIT_FIXTURE {
        fs::write(parent.join(name), text).unwrap();
    }
}

fn fixture() -> (tempfile::TempDir, PathBuf, ParentDirectory, Limits) {
    let temporary = tempfile::tempdir().unwrap();
    let parent = temporary.path().join("parent");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    write_limits(&parent);
    let directory =
        ParentDirectory::open(&parent, &fs::symlink_metadata(&parent).unwrap()).unwrap();
    let limits = read_limits(&limit_paths(&parent)).unwrap();
    (temporary, parent, directory, limits)
}

#[test]
fn relative_limits_read_replacement_bytes_and_every_current_file() {
    let (_temporary, parent, directory, initial) = fixture();
    assert_eq!(directory.read_limits().unwrap(), initial);
    for (name, original) in LIMIT_FIXTURE {
        let path = parent.join(name);
        let before = fs::symlink_metadata(&path).unwrap();
        let replacement = parent.join("replacement");
        let changed = match name {
            "cpu.max" => "10000 100000\n",
            "cpu.max.burst" | "memory.swap.max" => "1\n",
            "memory.max" => "536870912\n",
            "pids.max" => "64\n",
            _ => unreachable!(),
        };
        fs::write(&replacement, changed).unwrap();
        fs::rename(&replacement, &path).unwrap();
        let after = fs::symlink_metadata(&path).unwrap();
        assert_ne!((before.dev(), before.ino()), (after.dev(), after.ino()));
        let name = std::ffi::CString::new(name).unwrap();
        let mut bytes = [0; MAX_LIMIT_BYTES + 1];
        assert_eq!(directory.read_limit(&name, &mut bytes).unwrap(), changed);
        let expected = read_limits(&limit_paths(&parent)).map_err(|error| error.to_string());
        let observed = directory.read_limits().map_err(|error| error.to_string());
        assert_eq!(observed, expected);
        assert_ne!(observed, Ok(initial));
        let expected_error = observed
            .err()
            .unwrap_or_else(|| "PUBLIC_HOST_KERNEL_LIMITS_CHANGED".into());
        assert_eq!(
            directory
                .verify_limits(&parent, initial)
                .unwrap_err()
                .to_string(),
            expected_error
        );
        fs::write(&path, original).unwrap();
    }
    assert_eq!(directory.read_limits().unwrap(), initial);
}

#[test]
fn relative_limits_preserve_eof_size_utf8_and_late_io_error_precedence() {
    let (_temporary, parent, directory, initial) = fixture();
    for (name, original) in LIMIT_FIXTURE {
        let path = parent.join(name);
        let mut padded = original.as_bytes().to_vec();
        padded.resize(MAX_LIMIT_BYTES, b' ');
        fs::write(&path, &padded).unwrap();
        assert_eq!(directory.read_limits().unwrap(), initial);
        for invalid in [
            [padded.as_slice(), b" "].concat(),
            [original.as_bytes(), &[0xff]].concat(),
            vec![b'x'; 1024 * 1024],
        ] {
            fs::write(&path, invalid).unwrap();
            assert_eq!(
                directory.read_limits().unwrap_err().to_string(),
                read_limits(&limit_paths(&parent)).unwrap_err().to_string()
            );
        }
        fs::write(&path, original).unwrap();
    }
    fs::write(parent.join("cpu.max"), "malformed").unwrap();
    fs::remove_file(parent.join("pids.max")).unwrap();
    assert_eq!(
        directory.read_limits().unwrap_err().to_string(),
        "PUBLIC_HOST_KERNEL_UNAVAILABLE",
        "all five reads still precede parsing the first file"
    );
    fs::write(parent.join("pids.max"), "32\n").unwrap();
    assert_eq!(
        directory.read_limits().unwrap_err().to_string(),
        "PUBLIC_HOST_KERNEL_LIMITS"
    );
}

#[test]
fn relative_limits_never_follow_replacement_symlinks() {
    let (_temporary, parent, directory, _) = fixture();
    for (name, original) in LIMIT_FIXTURE {
        let path = parent.join(name);
        let replacement = parent.join("detached-limit");
        fs::rename(&path, &replacement).unwrap();
        symlink(&replacement, &path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        assert_eq!(
            directory.read_limits().unwrap_err().to_string(),
            "PUBLIC_HOST_KERNEL_UNAVAILABLE"
        );
        fs::remove_file(&path).unwrap();
        fs::rename(&replacement, &path).unwrap();
    }
}

const LIMIT_CHILD_PARENT: &str = "TRNM_TEST_HOST_LIMIT_CHILD_PARENT";
const LIMIT_CHILD_SELECTOR: &str =
    "host_kernel_parent::kernel_parent::relative_tests::relative_limit_child_probe";

#[test]
fn relative_limit_child_probe() {
    let Some(parent) = std::env::var_os(LIMIT_CHILD_PARENT) else {
        return;
    };
    let parent = PathBuf::from(parent);
    let directory =
        ParentDirectory::open(&parent, &fs::symlink_metadata(&parent).unwrap()).unwrap();
    let expected = validate_limits("25000 100000", "0", "268435456", "0", "32").unwrap();
    directory.verify_path(&parent).unwrap();
    eprintln!("host_limit_child_started_v1");
    assert_eq!(
        directory
            .verify_limits(&parent, expected)
            .unwrap_err()
            .to_string(),
        "PUBLIC_HOST_KERNEL_UNAVAILABLE"
    );
    eprintln!("host_limit_child_rejected_v1");
}

fn assert_limit_probe_finishes(parent: &Path, name: &str, kind: &str) {
    use std::{
        process::{Child, Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    struct ReapChild(Option<Child>);
    impl Drop for ReapChild {
        fn drop(&mut self) {
            if let Some(child) = self.0.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
    let mut guard = ReapChild(Some(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                LIMIT_CHILD_SELECTOR,
                "--nocapture",
                "--test-threads=1",
            ])
            .env(LIMIT_CHILD_PARENT, parent)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    ));
    let child = guard.0.as_mut().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let completed = loop {
        if child.try_wait().unwrap().is_some() {
            break true;
        }
        if Instant::now() >= deadline {
            // A regressed blocking open/read is killed and reaped before
            // this assertion can fail; no test thread is left on the FIFO.
            child.kill().unwrap();
            break false;
        }
        thread::sleep(Duration::from_millis(10));
    };
    let output = guard.0.take().unwrap().wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        completed,
        "{name} / {kind}: limit child exceeded five seconds and was reaped\n{stdout}\n{stderr}"
    );
    assert!(
        output.status.success(),
        "{name} / {kind}: limit child failed\n{stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("test result: ok. 1 passed;")
            && stderr.contains("host_limit_child_started_v1")
            && stderr.contains("host_limit_child_rejected_v1"),
        "{name} / {kind}: the exact native child must execute its assertion\n{stdout}\n{stderr}"
    );
}

#[test]
fn relative_limits_refuse_nonregular_children_in_bounded_native_processes() {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    for (name, original) in LIMIT_FIXTURE {
        for kind in ["fifo-empty", "fifo-buffered", "directory", "symlink"] {
            let (_temporary, parent, directory, initial) = fixture();
            directory.verify_limits(&parent, initial).unwrap();
            let path = parent.join(name);
            let detached = parent.join("detached-limit");
            fs::rename(&path, &detached).unwrap();
            let mut fifo_reader = None;
            match kind {
                "fifo-empty" | "fifo-buffered" => {
                    let name = std::ffi::CString::new(name).unwrap();
                    rustix::fs::mkfifoat(
                        &directory.file,
                        name.as_c_str(),
                        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                    )
                    .unwrap();
                    if kind == "fifo-buffered" {
                        // Retain only a reader so the FIFO keeps this valid
                        // payload after its writer closes. Without the FD
                        // type check, a nonblocking reader could accept these
                        // exact limit bytes and their real EOF.
                        let reader = fs::OpenOptions::new()
                            .read(true)
                            .custom_flags(libc::O_NONBLOCK)
                            .open(&path)
                            .unwrap();
                        let mut writer = fs::OpenOptions::new()
                            .write(true)
                            .custom_flags(libc::O_NONBLOCK)
                            .open(&path)
                            .unwrap();
                        writer.write_all(original.as_bytes()).unwrap();
                        drop(writer);
                        fifo_reader = Some(reader);
                    }
                }
                "directory" => fs::create_dir(&path).unwrap(),
                "symlink" => symlink(&detached, &path).unwrap(),
                _ => unreachable!(),
            }
            assert_limit_probe_finishes(&parent, name, kind);
            drop(fifo_reader);
            if kind == "directory" {
                fs::remove_dir(&path).unwrap();
            } else {
                fs::remove_file(&path).unwrap();
            }
            fs::rename(&detached, &path).unwrap();
            directory.verify_limits(&parent, initial).unwrap();
        }
    }
}

#[test]
fn held_parent_refuses_renamed_recreated_and_symlink_paths_then_rechecks_restore() {
    let (temporary, parent, directory, initial) = fixture();
    directory.verify_path(&parent).unwrap();
    let detached = temporary.path().join("detached-parent");
    fs::rename(&parent, &detached).unwrap();
    assert_eq!(directory.read_limits().unwrap(), initial);
    assert_eq!(
        directory.verify_path(&parent).unwrap_err().to_string(),
        "PUBLIC_HOST_KERNEL_REPLACED"
    );
    fs::create_dir(&parent).unwrap();
    write_limits(&parent);
    assert_eq!(
        directory.verify_path(&parent).unwrap_err().to_string(),
        "PUBLIC_HOST_KERNEL_REPLACED",
        "matching replacement values cannot identify the held directory"
    );
    fs::remove_dir_all(&parent).unwrap();
    symlink(&detached, &parent).unwrap();
    assert_eq!(
        directory.verify_path(&parent).unwrap_err().to_string(),
        "PUBLIC_HOST_KERNEL_REPLACED"
    );
    fs::remove_file(&parent).unwrap();
    fs::rename(&detached, &parent).unwrap();
    directory.verify_path(&parent).unwrap();
    fs::write(parent.join("pids.max"), "64\n").unwrap();
    assert_ne!(directory.read_limits().unwrap(), initial);
}

#[test]
fn held_parent_binds_actual_opened_fd_and_accepts_search_only_directory() {
    let (temporary, parent, directory, initial) = fixture();
    let expected = fs::symlink_metadata(&parent).unwrap();
    let detached = temporary.path().join("detached-parent");
    fs::rename(&parent, &detached).unwrap();
    fs::create_dir(&parent).unwrap();
    assert_eq!(
        ParentDirectory::open(&parent, &expected)
            .err()
            .unwrap()
            .to_string(),
        "PUBLIC_HOST_KERNEL_REPLACED"
    );
    fs::remove_dir(&parent).unwrap();
    symlink(&detached, &parent).unwrap();
    assert_eq!(
        ParentDirectory::open(&parent, &expected)
            .err()
            .unwrap()
            .to_string(),
        "PUBLIC_HOST_KERNEL_REPLACED"
    );
    fs::remove_file(&parent).unwrap();
    fs::rename(&detached, &parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o111)).unwrap();
    let searchable =
        ParentDirectory::open(&parent, &fs::symlink_metadata(&parent).unwrap()).unwrap();
    searchable.verify_path(&parent).unwrap();
    assert_eq!(searchable.read_limits().unwrap(), initial);
    assert_eq!(directory.read_limits().unwrap(), initial);
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn held_parent_final_fence_refuses_changes_after_successful_limit_reads() {
    let (temporary, parent, directory, initial) = fixture();
    directory.verify_path(&parent).unwrap();
    assert_eq!(directory.read_limits().unwrap(), initial);
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(
        directory.verify_path(&parent).unwrap_err().to_string(),
        "PUBLIC_HOST_KERNEL_REPLACED"
    );
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    directory.verify_path(&parent).unwrap();
    assert_eq!(directory.read_limits().unwrap(), initial);
    let detached = temporary.path().join("detached-parent");
    fs::rename(&parent, &detached).unwrap();
    fs::create_dir(&parent).unwrap();
    write_limits(&parent);
    assert_eq!(
        directory.verify_path(&parent).unwrap_err().to_string(),
        "PUBLIC_HOST_KERNEL_REPLACED"
    );
}

#[derive(Clone, Copy)]
enum LateChange {
    Rename,
    Permissions,
}

type AfterLimitRead = Box<dyn FnOnce()>;
std::thread_local! {
    static AFTER_LAST_LIMIT_READ: std::cell::RefCell<Option<AfterLimitRead>> =
        const { std::cell::RefCell::new(None) };
}

pub(super) fn after_limit_read(name: &CStr) {
    if name == c"pids.max" {
        let hook = AFTER_LAST_LIMIT_READ.with(|slot| slot.borrow_mut().take());
        if let Some(hook) = hook {
            hook();
        }
    }
}

fn with_after_last_limit_read<T>(hook: impl FnOnce() + 'static, action: impl FnOnce() -> T) -> T {
    struct ResetHook;
    impl Drop for ResetHook {
        fn drop(&mut self) {
            AFTER_LAST_LIMIT_READ.with(|slot| {
                let _ = slot.borrow_mut().take();
            });
        }
    }
    let _reset = ResetHook;
    AFTER_LAST_LIMIT_READ.with(|slot| {
        let mut pending = slot.borrow_mut();
        assert!(pending.is_none(), "only one scoped final-read mutation");
        *pending = Some(Box::new(hook));
    });
    action()
}

fn change_after_last_read(change: LateChange, malformed_cpu: bool) -> String {
    use std::{cell::Cell, rc::Rc};
    let (temporary, parent, directory, initial) = fixture();
    if malformed_cpu {
        fs::write(parent.join("cpu.max"), "malformed").unwrap();
    }
    directory.verify_path(&parent).unwrap();
    let changed_parent = parent.clone();
    let detached = temporary.path().join("detached-parent");
    let observed = Rc::new(Cell::new(false));
    let changed = observed.clone();
    let result = with_after_last_limit_read(
        move || {
            // The production helper has opened all five current regular
            // files and read the fifth through EOF. Mutate the actual parent
            // before parsing/final-fencing; a FIFO is no longer an admissible
            // synchronization fixture. The hook is thread-local and test-only.
            assert!(!changed.replace(true));
            match change {
                LateChange::Rename => {
                    fs::rename(&changed_parent, &detached).unwrap();
                    fs::create_dir(&changed_parent).unwrap();
                    write_limits(&changed_parent);
                }
                LateChange::Permissions => {
                    fs::set_permissions(&changed_parent, fs::Permissions::from_mode(0o777))
                        .unwrap();
                }
            }
        },
        || directory.verify_limits(&parent, initial),
    );
    assert!(
        observed.get(),
        "the actual fifth complete read must run the cut"
    );
    result.unwrap_err().to_string()
}

#[test]
fn held_parent_production_final_fence_observes_change_after_actual_fifth_open() {
    for change in [LateChange::Rename, LateChange::Permissions] {
        assert_eq!(
            change_after_last_read(change, false),
            "PUBLIC_HOST_KERNEL_REPLACED"
        );
    }
}

#[test]
fn held_parent_final_fence_does_not_replace_an_earlier_limit_parse_error() {
    for change in [LateChange::Rename, LateChange::Permissions] {
        assert_eq!(
            change_after_last_read(change, true),
            "PUBLIC_HOST_KERNEL_LIMITS"
        );
    }
}

#[derive(Clone, Copy, Debug)]
enum Arm {
    Original,
    Refenced,
    Relative,
}

impl Arm {
    fn name(self) -> &'static str {
        match self {
            Self::Original => "original-absolute-path",
            Self::Refenced => "absolute-path-plus-final-parent-fence",
            Self::Relative => "held-parent-fresh-openat-plus-final-parent-fence",
        }
    }
}

struct Component<'a> {
    parent: &'a Path,
    directory: &'a ParentDirectory,
    paths: [PathBuf; 5],
    limits: Limits,
    boot: String,
    membership: String,
}

impl Component<'_> {
    fn check(&self, arm: Arm) -> Result<()> {
        let mut boot_bytes = [0; CONTEXT_STACK_BYTES + 1];
        let boot = read_context(
            Path::new("/proc/sys/kernel/random/boot_id"),
            &mut boot_bytes,
        )?;
        if boot.trim() != self.boot.trim() {
            return Err("PUBLIC_HOST_KERNEL_REPLACED".into());
        }
        self.directory.verify_path(self.parent)?;
        let mut membership_bytes = [0; CONTEXT_STACK_BYTES + 1];
        let membership =
            read_context(Path::new("/proc/thread-self/cgroup"), &mut membership_bytes)?;
        if membership.as_ref() != self.membership.as_str() {
            return Err("PUBLIC_HOST_KERNEL_CONTEXT".into());
        }
        // Run the original parser on the current complete proc text. The
        // measuring process need not belong to the public Host; this component
        // never converts that relation into resource/admission authority.
        let _ = std::hint::black_box(cgroup_within_parent(&membership, PARENT_NAME));
        let limits = match arm {
            Arm::Original | Arm::Refenced => read_limits(&self.paths)?,
            Arm::Relative => return self.directory.verify_limits(self.parent, self.limits),
        };
        if limits != self.limits {
            return Err("PUBLIC_HOST_KERNEL_LIMITS_CHANGED".into());
        }
        match arm {
            Arm::Original => Ok(()),
            Arm::Refenced => self.directory.verify_path(self.parent),
            Arm::Relative => unreachable!(),
        }
    }
}

fn thread_cpu_ns() -> Option<u64> {
    use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
    let now = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ThreadCPUTime)).ok()?;
    let nanos = u64::try_from(now.tv_nsec).ok()?;
    if nanos >= 1_000_000_000 {
        return None;
    }
    u64::try_from(now.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(nanos)
}

#[test]
#[ignore = "one explicit complete three-arm ABBA cost observation, not fixed Host acceptance"]
fn host_parent_relative_reads_complete_three_arm_abba_cost_observation() {
    use std::{hint::black_box, time::Instant};
    assert!(
        black_box(!cfg!(debug_assertions)),
        "release observation required"
    );
    let (_temporary, parent, directory, limits) = fixture();
    let component = Component {
        parent: &parent,
        directory: &directory,
        paths: limit_paths(&parent),
        limits,
        boot: fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap(),
        membership: fs::read_to_string("/proc/thread-self/cgroup").unwrap(),
    };
    const GROUPS: usize = 16;
    const CHECKS_PER_SAMPLE: usize = 64;
    let pairs = [
        [Arm::Original, Arm::Refenced],
        [Arm::Original, Arm::Relative],
        [Arm::Refenced, Arm::Relative],
    ];
    eprintln!(
        "pon_host_parent_relative_predeclared_v1 {}",
        serde_json::json!({
            "groups":GROUPS,"checks_per_sample":CHECKS_PER_SAMPLE,"pairs_per_group":pairs.len(),
            "order":"ABBA for each of the three fixed pairs; pair order reversed on odd groups",
            "planned_samples":GROUPS*pairs.len()*4,"planned_checks":GROUPS*pairs.len()*4*CHECKS_PER_SAMPLE,
            "scope":"fresh real proc boot/current-thread membership plus five fresh temporary limit files and all per-arm parent fences; current owner CPU and wall; no cgroup qualification",
            "original_checkpoint_policy_changed":false,"fixed_host_acceptance_qualified":false,
            "early_stop_or_best_sample_selection":false
        })
    );
    let mut samples = Vec::new();
    let mut accepted = true;
    for group in 0..GROUPS {
        for pair_index in if group % 2 == 0 { [0, 1, 2] } else { [2, 1, 0] } {
            let [a, b] = pairs[pair_index];
            for (slot, arm) in [a, b, b, a].into_iter().enumerate() {
                let cpu_before = thread_cpu_ns();
                let started = Instant::now();
                let mut errors = Vec::new();
                let mut completed = 0usize;
                for index in 0..CHECKS_PER_SAMPLE {
                    match black_box(component.check(arm)) {
                        Ok(()) => completed += 1,
                        Err(error) => errors.push((index, error.to_string())),
                    }
                }
                let wall_ns = started.elapsed().as_nanos();
                let cpu_ns = cpu_before
                    .zip(thread_cpu_ns())
                    .and_then(|(before, after)| after.checked_sub(before));
                accepted &= errors.is_empty() && completed == CHECKS_PER_SAMPLE && cpu_ns.is_some();
                samples.push(serde_json::json!({
                    "group":group,"pair":pair_index,"slot":slot,"arm":arm.name(),
                    "scheduled_checks":CHECKS_PER_SAMPLE,"successful_checks":completed,
                    "wall_ns":wall_ns,"thread_cpu_ns":cpu_ns,"errors":errors
                }));
            }
        }
    }
    eprintln!(
        "pon_host_parent_relative_cost_v1 {}",
        serde_json::json!({
            "complete":accepted,"samples":samples,
            "no_fixed_host_or_business_confirmation_qualification":true,
            "retained_parent_fds":1,"retained_limit_fds":0,"cached_resource_verdicts":0
        })
    );
    assert!(accepted, "retain every failed or unknown-cost observation");
}
