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
/// Actual kernel counters for the *whole original parent*, not a guest,
/// a given V3 listener or the volatile CPU-credit epoch. Resource samples
/// must never grant W1/transaction/model authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct KernelResourceSample {
    pub cpu_usage_usec: u64,
    pub cpu_nr_periods: u64,
    pub cpu_nr_throttled: u64,
    pub cpu_throttled_usec: u64,
    pub memory_current_bytes: u64,
    pub pids_current: u64,
}

/// These are cumulative kernel CPU deltas; the current memory/task values
/// belong to independent point-in-time samples, not to a delta.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct KernelCpuDelta {
    pub usage_usec: u64,
    pub nr_periods: u64,
    pub nr_throttled: u64,
    pub throttled_usec: u64,
}

impl KernelResourceSample {
    pub fn cpu_delta_since(self, before: Self) -> crate::Result<KernelCpuDelta> {
        let changed = || crate::Error::from("PUBLIC_HOST_KERNEL_COUNTER_REWIND");
        Ok(KernelCpuDelta {
            usage_usec: self
                .cpu_usage_usec
                .checked_sub(before.cpu_usage_usec)
                .ok_or_else(changed)?,
            nr_periods: self
                .cpu_nr_periods
                .checked_sub(before.cpu_nr_periods)
                .ok_or_else(changed)?,
            nr_throttled: self
                .cpu_nr_throttled
                .checked_sub(before.cpu_nr_throttled)
                .ok_or_else(changed)?,
            throttled_usec: self
                .cpu_throttled_usec
                .checked_sub(before.cpu_throttled_usec)
                .ok_or_else(changed)?,
        })
    }
}

#[cfg(target_os = "linux")]
mod kernel_parent {
    use super::KernelResourceSample;
    use std::{
        fs,
        io::{self, Read},
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

    // Open the current path on EVERY invocation, with current credentials.
    // No descriptor, content, permission or resource verdict is retained.
    // Small procfs/kernfs values do not need read_to_string's size probing and
    // growth loop. Still read to a real EOF, including after a short read;
    // Interrupted is retried and every other read failure stays a failure.
    // Only the existing quota recheck has a 128-byte ceiling. Boot identity,
    // thread membership and initial limit parsing retain their original size
    // behavior instead of imposing a new successful-input restriction.
    fn read_fresh_kernel_text(
        path: impl AsRef<Path>,
        maximum: Option<usize>,
    ) -> io::Result<String> {
        read_kernel_text(&mut fs::File::open(path)?, maximum)
    }

    fn read_kernel_text(reader: &mut impl Read, maximum: Option<usize>) -> io::Result<String> {
        let limit = maximum
            .map(|maximum| {
                maximum
                    .checked_add(1)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "kernel text limit"))
            })
            .transpose()?
            .unwrap_or(usize::MAX);
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let available = (limit - bytes.len()).min(buffer.len());
            let count = match reader.read(&mut buffer[..available]) {
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            if count == 0 {
                return String::from_utf8(bytes)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error));
            }
            bytes.extend_from_slice(&buffer[..count]);
            if maximum.is_some_and(|maximum| bytes.len() > maximum) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "kernel text limit",
                ));
            }
        }
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
        // A process may have independently placed native worker threads in a
        // cgroup-v2 threaded subtree. /proc/self identifies the thread-group
        // leader and cannot attest the actual calling worker's CPU cgroup.
        // The kernel's /proc/thread-self resolves to the current TID.
        let text = read_fresh_kernel_text("/proc/thread-self/cgroup", None)
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

    /// Accept additional future kernel cpu.stat keys, but never fabricate the
    /// four required counters, accept duplicates or accept malformed/huge input.
    /// The actual sysfs files are read only after the fixed parent was checked.
    fn resource_sample(cpu: &str, memory: &str, tasks: &str) -> Result<KernelResourceSample> {
        const INVALID: &str = "PUBLIC_HOST_KERNEL_COUNTERS";
        if cpu.len() > 2048 || memory.len() > 64 || tasks.len() > 64 {
            return Err(INVALID.into());
        }
        let mut fields = std::collections::BTreeMap::<&str, u64>::new();
        for line in cpu.lines() {
            let mut words = line.split_ascii_whitespace();
            let key = words.next().ok_or(INVALID)?;
            let raw = words.next().ok_or(INVALID)?;
            if words.next().is_some() {
                return Err(INVALID.into());
            }
            let value = raw
                .parse::<u64>()
                .map_err(|_| crate::Error::from(INVALID))?;
            if fields.insert(key, value).is_some() {
                return Err(INVALID.into());
            }
        }
        let required = |key| {
            fields
                .get(key)
                .copied()
                .ok_or_else(|| crate::Error::from(INVALID))
        };
        let current = |raw: &str| -> Result<u64> {
            let mut parts = raw.split_ascii_whitespace();
            let value = parts
                .next()
                .ok_or(INVALID)?
                .parse::<u64>()
                .map_err(|_| crate::Error::from(INVALID))?;
            if parts.next().is_some() {
                return Err(INVALID.into());
            }
            Ok(value)
        };
        Ok(KernelResourceSample {
            cpu_usage_usec: required("usage_usec")?,
            cpu_nr_periods: required("nr_periods")?,
            cpu_nr_throttled: required("nr_throttled")?,
            cpu_throttled_usec: required("throttled_usec")?,
            memory_current_bytes: current(memory)?,
            pids_current: current(tasks)?,
        })
    }

    pub struct KernelBudget {
        parent: PathBuf,
        identity: (u64, u64),
        boot_id: String,
        limits: Limits,
    }
    impl KernelBudget {
        fn check(&self) -> Result<()> {
            let now_boot = read_fresh_kernel_text("/proc/sys/kernel/random/boot_id", None)
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
                let text = read_fresh_kernel_text(self.parent.join(name), Some(128))
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
            let boot = read_fresh_kernel_text("/proc/sys/kernel/random/boot_id", None)
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
                read_fresh_kernel_text(budget.parent.join(name), None)
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

        /// Read-only aggregate kernel accounting. Verify the same fixed
        /// boot/inode/quotas/membership both before and after sampling; if any
        /// counter is unavailable or malformed, never issue a qualified receipt.
        pub fn resource_sample(&self) -> Result<KernelResourceSample> {
            self.check()?;
            let read = |name| -> Result<String> {
                read_fresh_kernel_text(self.parent.join(name), None)
                    .map_err(|_| crate::Error::from("PUBLIC_HOST_KERNEL_COUNTERS"))
            };
            let sample = resource_sample(
                &read("cpu.stat")?,
                &read("memory.current")?,
                &read("pids.current")?,
            )?;
            self.check()?;
            Ok(sample)
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
    mod fresh_read_tests {
        use super::*;

        struct ShortReader<'a> {
            remaining: &'a [u8],
            consumed: usize,
            interrupt: bool,
            tail_error: Option<io::ErrorKind>,
        }
        impl Read for ShortReader<'_> {
            fn read(&mut self, destination: &mut [u8]) -> io::Result<usize> {
                if self.interrupt {
                    self.interrupt = false;
                    return Err(io::ErrorKind::Interrupted.into());
                }
                if self.remaining.is_empty() {
                    return self.tail_error.map_or(Ok(0), |kind| Err(kind.into()));
                }
                let count = destination.len().min(self.remaining.len()).min(3);
                destination[..count].copy_from_slice(&self.remaining[..count]);
                self.remaining = &self.remaining[count..];
                self.consumed += count;
                Ok(count)
            }
        }

        #[test]
        fn exact_limit_requires_real_eof_and_overlimit_read_stays_bounded() {
            for length in [0, 1, 127, 128, 129, 16_384] {
                let value = vec![b'7'; length];
                let mut reader = ShortReader {
                    remaining: &value,
                    consumed: 0,
                    interrupt: false,
                    tail_error: None,
                };
                let result = read_kernel_text(&mut reader, Some(128));
                if length <= 128 {
                    assert_eq!(result.unwrap().as_bytes(), value);
                    assert_eq!(reader.consumed, length);
                } else {
                    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
                    assert_eq!(reader.consumed, 129);
                }
            }
            let mut exact_with_late_error = ShortReader {
                remaining: &[b'7'; 128],
                consumed: 0,
                interrupt: false,
                tail_error: Some(io::ErrorKind::PermissionDenied),
            };
            assert_eq!(
                read_kernel_text(&mut exact_with_late_error, Some(128))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
        }

        #[test]
        fn short_reads_and_interruption_preserve_unbounded_original_text() {
            let value = "0::/trnmponpublic.slice/".to_owned() + &"a".repeat(9000) + ".service\n";
            let mut reader = ShortReader {
                remaining: value.as_bytes(),
                consumed: 0,
                interrupt: true,
                tail_error: None,
            };
            assert_eq!(read_kernel_text(&mut reader, None).unwrap(), value);
            assert_eq!(reader.consumed, value.len());
        }

        #[test]
        fn invalid_utf8_and_io_errors_never_become_a_successful_prefix() {
            for maximum in [None, Some(128)] {
                let mut invalid = &b"25000 100000\n\xff"[..];
                assert_eq!(
                    read_kernel_text(&mut invalid, maximum).unwrap_err().kind(),
                    io::ErrorKind::InvalidData
                );
                for prefix in [&b""[..], &b"25000 100000\n"[..]] {
                    let mut failed = ShortReader {
                        remaining: prefix,
                        consumed: 0,
                        interrupt: false,
                        tail_error: Some(io::ErrorKind::PermissionDenied),
                    };
                    assert_eq!(
                        read_kernel_text(&mut failed, maximum).unwrap_err().kind(),
                        io::ErrorKind::PermissionDenied
                    );
                }
            }
        }

        #[test]
        fn every_call_reopens_replaced_removed_and_permission_changed_paths() {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("current");
            fs::write(&path, "25000 100000\n").unwrap();
            assert_eq!(
                read_fresh_kernel_text(&path, Some(128)).unwrap(),
                "25000 100000\n"
            );
            fs::rename(&path, directory.path().join("old")).unwrap();
            fs::write(&path, "50000 100000\n").unwrap();
            assert_eq!(
                read_fresh_kernel_text(&path, Some(128)).unwrap(),
                "50000 100000\n"
            );
            fs::set_permissions(&path, fs::Permissions::from_mode(0o0)).unwrap();
            // The kernel decides access for the ACTUAL current credentials.
            // A privileged test process may retain DAC override; compare the
            // original fresh-open behavior rather than inventing a denial.
            let original = fs::read_to_string(&path).map_err(|error| error.kind());
            let observed = read_fresh_kernel_text(&path, Some(128)).map_err(|error| error.kind());
            assert_eq!(observed, original);
            fs::remove_file(&path).unwrap();
            assert_eq!(
                read_fresh_kernel_text(&path, Some(128)).unwrap_err().kind(),
                io::ErrorKind::NotFound
            );
            std::os::unix::fs::symlink(directory.path().join("old"), &path).unwrap();
            assert_eq!(
                read_fresh_kernel_text(&path, Some(128)).unwrap(),
                "25000 100000\n"
            );
        }

        #[test]
        fn actual_native_thread_and_boot_reads_match_original_current_paths() {
            std::thread::spawn(|| {
                let thread = fs::read_link("/proc/thread-self").unwrap();
                let current = Path::new("/proc").join(thread).join("cgroup");
                assert_eq!(
                    read_fresh_kernel_text("/proc/thread-self/cgroup", None).unwrap(),
                    fs::read_to_string(current).unwrap()
                );
                assert_eq!(
                    read_fresh_kernel_text("/proc/sys/kernel/random/boot_id", None).unwrap(),
                    fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap()
                );
            })
            .join()
            .unwrap();
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const CPU_SAMPLE: &str = "usage_usec 600\nuser_usec 400\nsystem_usec 200\nnr_periods 16\nnr_throttled 4\nthrottled_usec 150\nnr_bursts 0\n";
        #[test]
        fn kernel_resource_counters_require_complete_bounded_real_format() {
            let normal = resource_sample(CPU_SAMPLE, "1000\n", "7\n").unwrap();
            assert_eq!(
                (
                    normal.cpu_usage_usec,
                    normal.cpu_nr_throttled,
                    normal.memory_current_bytes,
                    normal.pids_current
                ),
                (600, 4, 1000, 7)
            );
            for malformed in [
                "usage_usec 600\nnr_periods 16\nnr_throttled 4\n", // missing throttled_usec
                "usage_usec 600\nusage_usec 700\nnr_periods 16\nnr_throttled 4\nthrottled_usec 150\n",
                "usage_usec -1\nnr_periods 16\nnr_throttled 4\nthrottled_usec 150\n",
                "usage_usec 1 2\nnr_periods 16\nnr_throttled 4\nthrottled_usec 150\n",
                "usage_usec max\nnr_periods 16\nnr_throttled 4\nthrottled_usec 150\n",
            ] {
                assert!(resource_sample(malformed, "0", "0").is_err(), "{malformed}");
            }
            assert!(resource_sample(CPU_SAMPLE, "max", "7").is_err());
            assert!(resource_sample(CPU_SAMPLE, "7", "-1").is_err());
            assert!(resource_sample(CPU_SAMPLE, "8 9", "7").is_err());
            assert!(resource_sample(&"z".repeat(2049), "1", "1").is_err());
        }

        #[test]
        fn read_kernel_membership_from_current_os_thread_not_process_leader() {
            // No cgroup mutation: compare the two genuine procfs views for a
            // distinct Rust worker thread and the same kernel TID.
            let join = std::thread::spawn(|| {
                let path = fs::read_link("/proc/thread-self").unwrap();
                let by_tid =
                    fs::read_to_string(Path::new("/proc").join(path).join("cgroup")).unwrap();
                let by_thread_self = fs::read_to_string("/proc/thread-self/cgroup").unwrap();
                assert_eq!(by_thread_self, by_tid);
                assert!(by_tid.starts_with("0::/"), "unified v2 thread entry");
                assert_eq!(by_tid.lines().count(), 1);
            });
            join.join().unwrap();
        }
        #[test]
        fn real_linux_cgroup_v2_cpu_stat_is_parsed_without_claiming_a_quota() {
            let real = fs::read_to_string("/sys/fs/cgroup/cpu.stat").unwrap();
            // Root cgroup has no required memory.current or pids.current on
            // Linux; the test uses only the real cumulative cpu.stat input.
            let parsed = resource_sample(&real, "0", "0").unwrap();
            assert!(parsed.cpu_usage_usec > 0);
            // Zero nr_periods is expected if the root has no CPU bandwidth cap.
            // Never infer quota enforcement from a successfully parsed sample.
            println!("ACTUAL_KERNEL_CPU_STAT_PARSE_OK real_cpu_usage_positive=true quota_qualified=false");
        }

        #[test]
        fn two_aggregate_samples_never_accept_cpu_counter_rewind_or_mem_task_delta() {
            let first = resource_sample(CPU_SAMPLE, "100", "2").unwrap();
            let second = resource_sample(
                "usage_usec 900\nnr_periods 20\nnr_throttled 5\nthrottled_usec 180\n",
                "20",
                "4",
            )
            .unwrap();
            let delta = second.cpu_delta_since(first).unwrap();
            assert_eq!(
                (
                    delta.usage_usec,
                    delta.nr_periods,
                    delta.nr_throttled,
                    delta.throttled_usec
                ),
                (300, 4, 1, 30)
            );
            assert_eq!(second.memory_current_bytes, 20);
            assert_eq!(second.pids_current, 4);
            let rewind = resource_sample(
                "usage_usec 1000\nnr_periods 20\nnr_throttled 4\nthrottled_usec 180\n",
                "20",
                "4",
            )
            .unwrap();
            assert_eq!(
                rewind.cpu_delta_since(second).unwrap_err().to_string(),
                "PUBLIC_HOST_KERNEL_COUNTER_REWIND"
            );
        }
        #[test]
        fn shipped_systemd_slice_is_the_one_fixed_finite_kernel_parent() {
            // This validates the shipped operator package, not live kernel
            // enforcement. A live systemd service still needs independent
            // membership, controller and real CPU/quota observations.
            let unit = include_str!("../../../../config/systemd/trnmponpublic.slice");
            let mut section = "";
            let mut entries = std::collections::BTreeMap::new();
            for original in unit.lines() {
                let line = original.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if line.starts_with('[') {
                    assert!(line.ends_with(']'));
                    section = &line[1..line.len() - 1];
                    assert!(matches!(section, "Unit" | "Slice"));
                    continue;
                }
                let (name, value) = line.split_once('=').expect("unit property");
                assert!(
                    entries.insert((section, name), value).is_none(),
                    "duplicate systemd directive would override the audited parent"
                );
            }
            let expected = [
                (("Unit", "StopWhenUnneeded"), "no"),
                (("Slice", "CPUAccounting"), "yes"),
                (("Slice", "CPUQuota"), "25%"),
                (("Slice", "CPUQuotaPeriodSec"), "100ms"),
                (("Slice", "MemoryAccounting"), "yes"),
                (("Slice", "MemoryMax"), "2G"),
                (("Slice", "MemorySwapMax"), "0"),
                (("Slice", "TasksAccounting"), "yes"),
                (("Slice", "TasksMax"), "256"),
            ];
            for (name, expected_value) in expected {
                assert_eq!(
                    entries.get(&name).copied(),
                    Some(expected_value),
                    "{name:?}"
                );
            }
            assert_eq!(
                entries.len(),
                expected.len() + 2,
                "unexpected unit property"
            );
            assert_eq!(
                validate_limits("25000 100000", "0", "2147483648", "0", "256").unwrap(),
                Limits {
                    cpu_quota_us: 25_000,
                    cpu_period_us: 100_000,
                    memory_bytes: 2 * 1024 * 1024 * 1024,
                    tasks: 256,
                }
            );
        }

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
    pub fn resource_sample(&self) -> crate::Result<KernelResourceSample> {
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
