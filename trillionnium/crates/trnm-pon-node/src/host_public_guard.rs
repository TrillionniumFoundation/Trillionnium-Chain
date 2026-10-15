//! One Linux network-namespace lease for the actual V3 CLI process.
//! This is kernel admission ownership, not a payment or Chain ledger. No
//! filesystem path, daemon, arbitrary guest-supplied name or cleanup hook.
//! This does not prove host-wide CPU under separate network namespaces.
#[cfg(target_os = "linux")]
use std::{
    io,
    os::{
        linux::net::SocketAddrExt,
        unix::net::{SocketAddr, UnixListener},
    },
};

#[cfg(target_os = "linux")]
const HOST_SLOT_PREFIX: &[u8] = b"trnm-pon-public-v3-host-slot-v1-";
/// One development CLI V3 instance per slot in the SAME Linux network
/// namespace. This is a four-process physical-process *count* cap, NOT a
/// kernel CPU/memory cgroup, durable CPU journal or an identity entitlement.
/// Four slots retain the original multi-node/peer tests without unbounded
/// process-relaunch fanout in a single shared network namespace.
#[cfg(target_os = "linux")]
pub(crate) const MAX_PROCESS_SLOTS: u8 = 4;

#[cfg(target_os = "linux")]
pub(crate) struct Guard {
    _held: UnixListener,
    pub(crate) slot: u8,
}
#[cfg(target_os = "linux")]
impl Guard {
    pub(crate) fn acquire() -> trnm_pon_node::Result<Self> {
        for slot in 0..MAX_PROCESS_SLOTS {
            let mut name = HOST_SLOT_PREFIX.to_vec();
            name.push(b'0' + slot);
            let address = SocketAddr::from_abstract_name(&name)
                .map_err(|_| trnm_pon_node::Error::from("PUBLIC_HOST_SLOT_ADDRESS"))?;
            match UnixListener::bind_addr(&address) {
                Ok(held) => return Ok(Self { _held: held, slot }),
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => continue,
                Err(_) => return Err("PUBLIC_HOST_PROCESS_UNAVAILABLE".into()),
            }
        }
        Err("PUBLIC_HOST_PROCESS_CAPACITY".into())
    }
}

// macOS has no Linux abstract namespace. Keep its existing V3 developer CLI
// operable using four cooperative OS file locks under the system root-owned
// sticky temporary directory. This is a weaker SAME-UID local-process bound:
// a compromised same-UID process or administrator could unlink its own lock
// and recreate an inode. It is not a production security qualification.
#[cfg(target_os = "macos")]
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};
#[cfg(target_os = "macos")]
pub(crate) const MAX_PROCESS_SLOTS: u8 = 4;

#[cfg(target_os = "macos")]
pub(crate) struct Guard {
    _held: File,
    pub(crate) slot: u8,
}
#[cfg(target_os = "macos")]
impl Guard {
    pub(crate) fn acquire() -> trnm_pon_node::Result<Self> {
        let root = Path::new("/tmp")
            .canonicalize()
            .map_err(|_| trnm_pon_node::Error::from("PUBLIC_HOST_PROCESS_UNAVAILABLE"))?;
        let parent = fs::metadata(&root)
            .map_err(|_| trnm_pon_node::Error::from("PUBLIC_HOST_PROCESS_UNAVAILABLE"))?;
        if !parent.is_dir() || parent.uid() != 0 || parent.mode() & 0o1000 == 0 {
            return Err("PUBLIC_HOST_PROCESS_UNAVAILABLE".into());
        }
        for slot in 0..MAX_PROCESS_SLOTS {
            let path = root.join(format!("trnm-pon-public-v3-host-slot-v1-{slot}.lock"));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)
                .map_err(|_| trnm_pon_node::Error::from("PUBLIC_HOST_PROCESS_UNAVAILABLE"))?;
            let meta = file
                .metadata()
                .map_err(|_| trnm_pon_node::Error::from("PUBLIC_HOST_PROCESS_UNAVAILABLE"))?;
            if !meta.is_file()
                || meta.nlink() != 1
                || meta.uid() != rustix::process::geteuid().as_raw()
                || meta.mode() & 0o777 != 0o600
            {
                return Err("PUBLIC_HOST_PROCESS_UNAVAILABLE".into());
            }
            match file.try_lock() {
                Ok(()) => return Ok(Self { _held: file, slot }),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(_) => return Err("PUBLIC_HOST_PROCESS_UNAVAILABLE".into()),
            }
        }
        Err("PUBLIC_HOST_PROCESS_CAPACITY".into())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) struct Guard {
    // Never constructed because acquire() always fails; retain a portable
    // diagnostic type so unsupported targets compile and fail closed.
    pub(crate) slot: u8,
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl Guard {
    pub(crate) fn acquire() -> trnm_pon_node::Result<Self> {
        Err("PUBLIC_HOST_PROCESS_GUARD_UNSUPPORTED".into())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{
        env,
        process::{Command, Stdio},
    };

    #[test]
    fn child_guard_probe() {
        if env::var_os("TRNM_TEST_HOST_GUARD_CHILD").is_none() {
            return;
        }
        let acquired = Guard::acquire();
        match env::var("TRNM_TEST_HOST_GUARD_CHILD").unwrap().as_str() {
            "EXPECT_BUSY" => assert_eq!(
                acquired.err().unwrap().to_string(),
                "PUBLIC_HOST_PROCESS_CAPACITY"
            ),
            "EXPECT_FREE" => {
                let _held = acquired.expect("test child must bind released host slot");
            }
            other => panic!("unknown probe: {other}"),
        }
    }

    fn probe(mode: &str) -> std::process::Output {
        Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "host_public_guard::tests::child_guard_probe",
                "--nocapture",
            ])
            .env("TRNM_TEST_HOST_GUARD_CHILD", mode)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .unwrap()
    }

    #[test]
    fn actual_second_linux_process_cannot_mint_a_second_host_slot() {
        let owners: Vec<_> = (0..MAX_PROCESS_SLOTS)
            .map(|_| Guard::acquire().expect("four native peer service slots are available"))
            .collect();
        let mut slots: Vec<_> = owners.iter().map(|x| x.slot).collect();
        slots.sort_unstable();
        assert_eq!(slots, (0..MAX_PROCESS_SLOTS).collect::<Vec<_>>());
        let duplicate = probe("EXPECT_BUSY");
        assert!(
            duplicate.status.success(),
            "second actual process bypassed: {}",
            String::from_utf8_lossy(&duplicate.stdout)
        );
        // Changing PID does not mint a fifth process slot; normal exit returns it.
        assert_eq!(
            Guard::acquire().err().unwrap().to_string(),
            "PUBLIC_HOST_PROCESS_CAPACITY"
        );
        drop(owners);
        let released = probe("EXPECT_FREE");
        assert!(
            released.status.success(),
            "freed slot cannot be recovered: {}",
            String::from_utf8_lossy(&released.stdout)
        );
    }
}

// Explicit root-provisioned kernel *parent* required for non-loopback public
// CLI service. The existing netns four-slot guard is only a development count
// cap. It is NOT a host CPU cap: Linux network namespaces can be multiplied.
// A cgroup-v2 parent is an actual aggregate kernel CPU, memory and pids cap
// over all descendant services, including different network namespaces.
//
// This code is an unprivileged reader: it cannot create, replace, widen,
// delegate, remount or migrate an OS resource group. Only an administrator can
// provision/start the fixed parent and place the process inside it. The
// original continuous ledger still owns durable operation reconciliation.
#[cfg(target_os = "linux")]
mod kernel_parent {
    use std::{
        fs,
        net::SocketAddr,
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::{Path, PathBuf},
    };

    type Result<T> = trnm_pon_node::Result<T>;
    const CGROUP_ROOT: &str = "/sys/fs/cgroup";
    const PARENT_DIRECTORY: &str = "/sys/fs/cgroup/system.slice";
    // This is ONE administrator-provisioned parent for all public V3
    // processes. Allowing caller-chosen trnmpon*.slice names would let
    // multiple independent 25%-CPU parents multiply the physical budget.
    const PARENT_NAME: &str = "trnmponpublic.slice";
    fn approved_parent_path(path: &Path) -> bool {
        path.parent() == Some(Path::new(PARENT_DIRECTORY))
            && path.file_name().and_then(|part| part.to_str()) == Some(PARENT_NAME)
    }
    const MAX_MEMORY_BYTES: u64 = 2 * 1024 * 1024 * 1024;
    const MAX_TASKS: u64 = 256;
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Limits {
        cpu_quota_us: u64,
        cpu_period_us: u64,
        memory_bytes: u64,
        tasks: u64,
    }

    fn numeric(text: &str, limit: u64) -> Option<u64> {
        let value = text.trim().parse::<u64>().ok()?;
        (value > 0 && value <= limit).then_some(value)
    }

    // The maximum CPU bandwidth is strictly <= 250,000 ns per second per
    // entire host parent. Explicit finite ceilings only; never accept "max".
    fn validate_limits(
        cpu: &str,
        burst: &str,
        memory: &str,
        swap: &str,
        pids: &str,
    ) -> Result<Limits> {
        let parts: Vec<_> = cpu.split_ascii_whitespace().collect();
        if parts.len() != 2 {
            return Err("PUBLIC_HOST_KERNEL_LIMITS".into());
        }
        let quota = numeric(parts[0], 250_000).ok_or("PUBLIC_HOST_KERNEL_LIMITS")?;
        let period = numeric(parts[1], 1_000_000).ok_or("PUBLIC_HOST_KERNEL_LIMITS")?;
        let memory = numeric(memory, MAX_MEMORY_BYTES).ok_or("PUBLIC_HOST_KERNEL_LIMITS")?;
        let tasks = numeric(pids, MAX_TASKS).ok_or("PUBLIC_HOST_KERNEL_LIMITS")?;
        if quota.checked_mul(4).is_none_or(|value| value > period)
            || burst.trim() != "0"
            || swap.trim() != "0"
        {
            return Err("PUBLIC_HOST_KERNEL_LIMITS".into());
        }
        Ok(Limits {
            cpu_quota_us: quota,
            cpu_period_us: period,
            memory_bytes: memory,
            tasks,
        })
    }

    fn own_cgroup() -> Result<String> {
        let text = fs::read_to_string("/proc/self/cgroup")
            .map_err(|_| trnm_pon_node::Error::from("PUBLIC_HOST_KERNEL_CONTEXT"))?;
        let mut entries = text.lines();
        let only = entries.next().ok_or("PUBLIC_HOST_KERNEL_CONTEXT")?;
        if entries.next().is_some() {
            return Err("PUBLIC_HOST_KERNEL_CONTEXT".into());
        }
        let relative = only
            .strip_prefix("0::/")
            .ok_or("PUBLIC_HOST_KERNEL_CONTEXT")?;
        if relative.is_empty()
            || relative
                .split('/')
                .any(|x| x.is_empty() || x == "." || x == "..")
        {
            return Err("PUBLIC_HOST_KERNEL_CONTEXT".into());
        }
        Ok(relative.to_owned())
    }

    pub(crate) struct KernelBudget {
        parent: PathBuf,
        identity: (u64, u64),
        boot_id: String,
        limits: Limits,
    }
    impl KernelBudget {
        fn check(&self) -> Result<()> {
            let now_boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .map_err(|_| trnm_pon_node::Error::from("PUBLIC_HOST_KERNEL_CONTEXT"))?;
            if now_boot.trim() != self.boot_id {
                return Err("PUBLIC_HOST_KERNEL_REPLACED".into());
            }
            let meta = fs::symlink_metadata(&self.parent)
                .map_err(|_| trnm_pon_node::Error::from("PUBLIC_HOST_KERNEL_REPLACED"))?;
            if !meta.file_type().is_dir()
                || meta.uid() != 0
                || meta.mode() & 0o022 != 0
                || (meta.dev(), meta.ino()) != self.identity
            {
                return Err("PUBLIC_HOST_KERNEL_REPLACED".into());
            }
            let parent_rel = self
                .parent
                .strip_prefix(CGROUP_ROOT)
                .map_err(|_| trnm_pon_node::Error::from("PUBLIC_HOST_KERNEL_CONTEXT"))?
                .to_str()
                .ok_or("PUBLIC_HOST_KERNEL_CONTEXT")?
                .trim_start_matches('/');
            let current = own_cgroup()?;
            if current != parent_rel && !current.starts_with(&format!("{parent_rel}/")) {
                return Err("PUBLIC_HOST_KERNEL_CONTEXT".into());
            }
            let read = |name: &str| -> Result<String> {
                let text = fs::read_to_string(self.parent.join(name))
                    .map_err(|_| trnm_pon_node::Error::from("PUBLIC_HOST_KERNEL_UNAVAILABLE"))?;
                if text.len() > 128 {
                    return Err("PUBLIC_HOST_KERNEL_UNAVAILABLE".into());
                }
                Ok(text)
            };
            let observed = validate_limits(
                &read("cpu.max")?,
                &read("cpu.max.burst")?,
                &read("memory.max")?,
                &read("memory.swap.max")?,
                &read("pids.max")?,
            )?;
            if observed != self.limits {
                return Err("PUBLIC_HOST_KERNEL_LIMITS_CHANGED".into());
            }
            Ok(())
        }
        fn open(path: &str) -> Result<Self> {
            let user_path = Path::new(path);
            if !user_path.is_absolute() {
                return Err("PUBLIC_HOST_KERNEL_PARENT".into());
            }
            let parent = fs::canonicalize(user_path)
                .map_err(|_| trnm_pon_node::Error::from("PUBLIC_HOST_KERNEL_PARENT"))?;
            // A strict systemd-owned *single parent*, not the common cgroup
            // root, any child/service, or a caller-created user.slice.
            if !approved_parent_path(&parent) || parent != user_path {
                return Err("PUBLIC_HOST_KERNEL_PARENT".into());
            }
            if !Path::new("/sys/fs/cgroup/cgroup.controllers").is_file() {
                return Err("PUBLIC_HOST_KERNEL_UNSUPPORTED".into());
            }
            let meta = fs::symlink_metadata(&parent)?;
            if !meta.is_dir() || meta.uid() != 0 || meta.permissions().mode() & 0o022 != 0 {
                return Err("PUBLIC_HOST_KERNEL_PARENT".into());
            }
            let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .map_err(|_| trnm_pon_node::Error::from("PUBLIC_HOST_KERNEL_CONTEXT"))?;
            let budget = Self {
                identity: (meta.dev(), meta.ino()),
                boot_id: boot.trim().to_owned(),
                parent,
                limits: Limits {
                    cpu_quota_us: 0,
                    cpu_period_us: 0,
                    memory_bytes: 0,
                    tasks: 0,
                },
            };
            let read = |name: &str| -> Result<String> {
                fs::read_to_string(budget.parent.join(name))
                    .map_err(|_| trnm_pon_node::Error::from("PUBLIC_HOST_KERNEL_UNAVAILABLE"))
            };
            let limits = validate_limits(
                &read("cpu.max")?,
                &read("cpu.max.burst")?,
                &read("memory.max")?,
                &read("memory.swap.max")?,
                &read("pids.max")?,
            )?;
            let checked = Self { limits, ..budget };
            checked.check()?;
            Ok(checked)
        }
        pub(crate) fn verify(&self) -> Result<()> {
            self.check()
        }
    }

    pub(crate) fn require(
        address: SocketAddr,
        parent: Option<&str>,
    ) -> Result<Option<KernelBudget>> {
        match parent {
            Some(path) => KernelBudget::open(path).map(Some),
            None if !address.ip().is_loopback() => Err("PUBLIC_HOST_KERNEL_REQUIRED".into()),
            None => Ok(None), // Retained loopback-only development tools.
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn no_public_nonloopback_without_root_owned_kernel_parent() {
            let any: SocketAddr = "0.0.0.0:31337".parse().unwrap();
            let loopback: SocketAddr = "127.0.0.1:31337".parse().unwrap();
            assert_eq!(
                require(any, None).err().unwrap().to_string(),
                "PUBLIC_HOST_KERNEL_REQUIRED"
            );
            assert!(require(loopback, None).unwrap().is_none());
            assert_eq!(
                require(loopback, Some("/tmp/none"))
                    .err()
                    .unwrap()
                    .to_string(),
                "PUBLIC_HOST_KERNEL_PARENT"
            );
        }
        #[test]
        fn finite_cpu_memory_process_limits_and_burst_required() {
            let good =
                validate_limits("25000 100000\n", "0\n", "268435456\n", "0\n", "32\n").unwrap();
            assert_eq!(good.cpu_quota_us, 25000);
            for cpu in [
                "max 100000",
                "100000 100000",
                "25001 100000",
                "0 100000",
                "25000 0",
                "25000 100000 1",
                "-1 100000",
                "1 1",
            ] {
                assert!(
                    validate_limits(cpu, "0", "268435456", "0", "32").is_err(),
                    "{cpu}"
                );
            }
            for (burst, mem, swap, pids) in [
                ("1", "268435456", "0", "32"),
                ("0", "max", "0", "32"),
                ("0", "268435456", "1", "32"),
                ("0", "268435456", "0", "max"),
                ("0", "268435456", "0", "257"),
            ] {
                assert!(validate_limits("25000 100000", burst, mem, swap, pids).is_err());
            }
            assert!(validate_limits("1000 10000", "0", "33554432", "0", "4").is_ok());
        }
        #[test]
        fn exactly_one_fixed_system_parent_name_is_eligible() {
            assert!(approved_parent_path(Path::new(
                "/sys/fs/cgroup/system.slice/trnmponpublic.slice"
            )));
            for bad in [
                "/sys/fs/cgroup/system.slice/trnmponextra.slice",
                "/sys/fs/cgroup/system.slice/trnmponother.slice",
                "/sys/fs/cgroup/system.slice/trnmponpublic.service",
                "/sys/fs/cgroup/user.slice/trnmponpublic.slice",
                "/sys/fs/cgroup/system.slice/trnmponpublic.slice/child.service",
            ] {
                assert!(!approved_parent_path(Path::new(bad)), "{bad}");
            }
        }
        #[test]
        fn fake_root_or_wrong_parent_never_counts_as_root_kernel_budget() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("trnmponfake.slice");
            std::fs::create_dir(&path).unwrap();
            assert_eq!(
                KernelBudget::open(path.to_str().unwrap())
                    .err()
                    .unwrap()
                    .to_string(),
                "PUBLIC_HOST_KERNEL_PARENT"
            );
        }
    }
}
#[cfg(target_os = "linux")]
pub(crate) use kernel_parent::require as require_host_kernel_budget;
#[cfg(target_os = "linux")]
#[cfg(not(target_os = "linux"))]
pub(crate) struct HostKernelBudget;
#[cfg(not(target_os = "linux"))]
impl HostKernelBudget {
    pub(crate) fn verify(&self) -> trnm_pon_node::Result<()> {
        Err("PUBLIC_HOST_KERNEL_UNSUPPORTED".into())
    }
}
#[cfg(not(target_os = "linux"))]
pub(crate) fn require_host_kernel_budget(
    address: std::net::SocketAddr,
    parent: Option<&str>,
) -> trnm_pon_node::Result<Option<HostKernelBudget>> {
    if parent.is_some() || !address.ip().is_loopback() {
        Err("PUBLIC_HOST_KERNEL_UNSUPPORTED".into())
    } else {
        Ok(None)
    }
}
