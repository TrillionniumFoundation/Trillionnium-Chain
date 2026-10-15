// One root-provisioned kernel parent checker shared by the V3 Rust library
// and CLI. The CLI's network-namespace slots count processes locally but are
// NOT host-wide CPU limits: Linux network namespaces can be multiplied.
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

    type Result<T> = crate::Result<T>;
    const CGROUP_ROOT: &str = "/sys/fs/cgroup";
    // systemd.slice(5): a no-dash slice name belongs directly to -.slice.
    // system.slice children must instead be named system-<child>.slice.
    // Keep the one original fixed name; do NOT admit caller-selectable slices.
    const PARENT_DIRECTORY: &str = "/sys/fs/cgroup";
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
            .map_err(|_| crate::Error::from("PUBLIC_HOST_KERNEL_CONTEXT"))?;
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

    pub struct KernelBudget {
        parent: PathBuf,
        identity: (u64, u64),
        boot_id: String,
        limits: Limits,
    }
    impl KernelBudget {
        fn check(&self) -> Result<()> {
            let now_boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .map_err(|_| crate::Error::from("PUBLIC_HOST_KERNEL_CONTEXT"))?;
            if now_boot.trim() != self.boot_id {
                return Err("PUBLIC_HOST_KERNEL_REPLACED".into());
            }
            let meta = fs::symlink_metadata(&self.parent)
                .map_err(|_| crate::Error::from("PUBLIC_HOST_KERNEL_REPLACED"))?;
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
                .map_err(|_| crate::Error::from("PUBLIC_HOST_KERNEL_CONTEXT"))?
                .to_str()
                .ok_or("PUBLIC_HOST_KERNEL_CONTEXT")?
                .trim_start_matches('/');
            let current = own_cgroup()?;
            if current != parent_rel && !current.starts_with(&format!("{parent_rel}/")) {
                return Err("PUBLIC_HOST_KERNEL_CONTEXT".into());
            }
            let read = |name: &str| -> Result<String> {
                let text = fs::read_to_string(self.parent.join(name))
                    .map_err(|_| crate::Error::from("PUBLIC_HOST_KERNEL_UNAVAILABLE"))?;
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
                .map_err(|_| crate::Error::from("PUBLIC_HOST_KERNEL_PARENT"))?;
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
                .map_err(|_| crate::Error::from("PUBLIC_HOST_KERNEL_CONTEXT"))?;
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
                    .map_err(|_| crate::Error::from("PUBLIC_HOST_KERNEL_UNAVAILABLE"))
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
        pub fn verify(&self) -> Result<()> {
            self.check()
        }
    }

    pub fn require(address: SocketAddr, parent: Option<&str>) -> Result<Option<KernelBudget>> {
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
        fn fixed_parent_constant_is_exactly_the_canonical_directory_and_name() {
            assert_eq!(
                Path::new(super::super::FIXED_PUBLIC_KERNEL_PARENT),
                Path::new(PARENT_DIRECTORY).join(PARENT_NAME)
            );
        }
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
        fn canonical_systemd_slice_name_maps_to_the_actual_root_cgroup() {
            // systemd.slice(5): "foo-bar.slice" means /foo.slice/foo-bar.slice.
            // A name with no dash is a CHILD OF -.slice, not system.slice.
            // Existing PARENT_NAME must match the only actual systemd path.
            assert!(
                approved_parent_path(Path::new("/sys/fs/cgroup/trnmponpublic.slice")),
                "actual top-level systemd slice is otherwise impossible to select"
            );
            assert!(!approved_parent_path(Path::new(
                "/sys/fs/cgroup/system.slice/trnmponpublic.slice"
            )));
        }
        #[test]
        fn exactly_one_fixed_system_parent_name_is_eligible() {
            assert!(approved_parent_path(Path::new(
                "/sys/fs/cgroup/trnmponpublic.slice"
            )));
            for bad in [
                "/sys/fs/cgroup/system.slice/trnmponpublic.slice",
                "/sys/fs/cgroup/system-trnmponpublic.slice",
                "/sys/fs/cgroup/trnmponextra.slice",
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
pub use kernel_parent::{require as require_host_kernel_budget, KernelBudget as HostKernelBudget};
#[cfg(not(target_os = "linux"))]
pub struct HostKernelBudget;
#[cfg(not(target_os = "linux"))]
impl HostKernelBudget {
    pub fn verify(&self) -> crate::Result<()> {
        Err("PUBLIC_HOST_KERNEL_UNSUPPORTED".into())
    }
}
#[cfg(not(target_os = "linux"))]
pub fn require_host_kernel_budget(
    address: std::net::SocketAddr,
    parent: Option<&str>,
) -> crate::Result<Option<HostKernelBudget>> {
    if parent.is_some() || !address.ip().is_loopback() {
        Err("PUBLIC_HOST_KERNEL_UNSUPPORTED".into())
    } else {
        Ok(None)
    }
}

/// Single protocol-neutral, administrator-provisioned host resource parent.
/// The public V3 library and development CLI use the EXACT same eligibility.
pub const FIXED_PUBLIC_KERNEL_PARENT: &str = "/sys/fs/cgroup/trnmponpublic.slice";
/// Direct library callers cannot bypass the CLI's kernel-parent requirement.
/// A loopback test service needs no administrator privileges; an externally
/// reachable service must already be placed under the one fixed parent.
pub fn require_for_listener(
    address: std::net::SocketAddr,
) -> crate::Result<Option<HostKernelBudget>> {
    require_host_kernel_budget(
        address,
        (!address.ip().is_loopback()).then_some(FIXED_PUBLIC_KERNEL_PARENT),
    )
}
