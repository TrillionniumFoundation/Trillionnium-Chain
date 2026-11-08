//! Test harness support, reachable only from an explicitly ignored isolated
//! native suite. Never changes the production provisioning/root selection.
use super::frontier::{invalid, Result};
use super::native_build_fixture::bounded;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub(super) const RUNTIME_UID: u32 = 1000;
pub(super) const SERVICE_UID: u32 = 1001;
pub(super) const HELPER: &str =
    "operator_pq_startup::tests::m15_native_fixture::export_existing_npq6_inputs_for_isolated_m15_native_suite";
const MAX_LINE: usize = 4 * 1024 * 1024;
const MAX_LOG: usize = 64 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Isolation {
    pub schema: String,
    pub host_user_namespace: u64,
    pub host_mount_namespace: u64,
    pub host_pid_namespace: u64,
    pub build_input_sha256: String,
    pub node_sha256: String,
    pub test_elf_sha256: String,
}
pub(super) fn require_isolation() -> Result<Isolation> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(invalid(
            "native harness requires namespace-root, never host provisioning",
        ));
    }
    let uid_map = fs::read_to_string("/proc/self/uid_map")?;
    let rows = uid_map
        .lines()
        .map(|line| {
            line.split_whitespace()
                .map(str::parse::<u64>)
                .collect::<std::result::Result<Vec<_>, _>>()
        })
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(std::io::Error::other)?;
    if rows.iter().any(|row| row.len() != 3)
        || !rows
            .iter()
            .any(|row| row[0] == 0 && row[1] != 0 && row[2] == 1)
        || !rows.iter().any(|row| {
            row[0] <= u64::from(SERVICE_UID)
                && row[0]
                    .checked_add(row[2])
                    .is_some_and(|end| u64::from(SERVICE_UID) < end)
        })
    {
        return Err(invalid(
            "real rootless UID mapping for both independent native principals required",
        ));
    }
    let marker = Path::new("/m15/isolated-suite.json");
    let metadata = fs::symlink_metadata(marker)?;
    if metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o400 {
        return Err(invalid("native isolation marker custody"));
    }
    let value: Isolation =
        serde_json::from_slice(&bounded(marker, 16384)?).map_err(std::io::Error::other)?;
    if value.schema != "trnm-m15-isolated-native-fixture-v1"
        || fs::metadata("/proc/self/ns/user")?.ino() == value.host_user_namespace
        || fs::metadata("/proc/self/ns/mnt")?.ino() == value.host_mount_namespace
        || fs::metadata("/proc/self/ns/pid")?.ino() == value.host_pid_namespace
    {
        return Err(invalid("new user/mount/PID namespaces are mandatory"));
    }
    let mounts = fs::read_to_string("/proc/self/mountinfo")?;
    if !mounts.lines().any(|line| {
        let Some((left, right)) = line.split_once(" - ") else {
            return false;
        };
        left.split_whitespace().nth(4) == Some("/")
            && right.split_whitespace().next() == Some("tmpfs")
    }) || Path::new("/etc/trillionnium").exists()
    {
        return Err(invalid(
            "native suite requires fresh tmpfs root; refuses existing /etc provisioning",
        ));
    }
    for (path, digest, maximum) in [
        (
            "/m15/bin/node",
            &value.node_sha256,
            super::execution_wire::MAX_PROGRAM_BYTES,
        ),
        (
            "/m15/bin/tests",
            &value.test_elf_sha256,
            4 * 1024 * 1024 * 1024,
        ),
    ] {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)?;
        let before = super::sealed::identity(&file)?;
        if !file.metadata()?.is_file()
            || file.metadata()?.nlink() != 1
            || before.size == 0
            || before.size > maximum
            || super::sealed::digest(&file, before.size)?
                != super::native_build_fixture::hex_digest(digest)?
            || before != super::sealed::identity(&file)?
        {
            return Err(invalid("native exact executable copy binding"));
        }
    }
    Ok(value)
}

pub(super) fn directory(path: &Path, uid: u32, mode: u32) -> Result<()> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    rustix::fs::chown(
        path,
        Some(rustix::process::Uid::from_raw(uid)),
        Some(rustix::process::Gid::from_raw(uid)),
    )?;
    File::open(
        path.parent()
            .ok_or_else(|| invalid("native directory parent"))?,
    )?
    .sync_all()
}
pub(super) fn write(path: &Path, raw: &[u8], uid: u32, mode: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(raw)?;
    rustix::fs::fchown(
        &file,
        Some(rustix::process::Uid::from_raw(uid)),
        Some(rustix::process::Gid::from_raw(uid)),
    )?;
    file.sync_all()?;
    File::open(path.parent().ok_or_else(|| invalid("native file parent"))?)?.sync_all()
}

fn reader(
    input: impl Read + Send + 'static,
    path: PathBuf,
    lines: Option<mpsc::Sender<Result<Vec<u8>>>>,
) -> Result<JoinHandle<Result<()>>> {
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    Ok(std::thread::spawn(move || {
        let mut input = BufReader::new(input);
        let mut total = 0_usize;
        loop {
            let mut line = Vec::new();
            let n = Read::by_ref(&mut input)
                .take((MAX_LINE + 1) as u64)
                .read_until(b'\n', &mut line)?;
            if n == 0 {
                break;
            }
            total = total
                .checked_add(n)
                .ok_or_else(|| invalid("native log overflow"))?;
            output.write_all(&line)?;
            if n > MAX_LINE || total > MAX_LOG || !line.ends_with(b"\n") {
                output.sync_all()?;
                if let Some(sender) = &lines {
                    let _ = sender.send(Err(invalid("native bounded complete line/log")));
                }
                return Err(invalid(
                    "native output exceeds bound or lacks complete line",
                ));
            }
            if let Some(sender) = &lines {
                if sender.send(Ok(line)).is_err() {
                    break;
                }
            }
        }
        output.sync_all()
    }))
}

pub(super) struct Process {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<Result<Vec<u8>>>,
    readers: Vec<JoinHandle<Result<()>>>,
    pub stdout: PathBuf,
    pub stderr: PathBuf,
}
impl Process {
    pub fn spawn(
        name: &str,
        uid: u32,
        executable: &Path,
        arguments: &[String],
        extra_environment: &[(&str, &str)],
    ) -> Result<Self> {
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || ![RUNTIME_UID, SERVICE_UID].contains(&uid)
            || !executable.is_absolute()
        {
            return Err(invalid("native child fixed principal/name/executable"));
        }
        let mut command = Command::new("/usr/bin/setpriv");
        command
            .args([
                "--reuid",
                &uid.to_string(),
                "--regid",
                &uid.to_string(),
                "--clear-groups",
                "--no-new-privs",
                "--",
            ])
            .arg(executable)
            .args(arguments)
            .env_clear()
            .envs(super::execution_environment::restricted_environment())
            .current_dir("/m15")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in extra_environment {
            command.env(key, value);
        }
        let mut child = command.spawn()?;
        let stdin = child.stdin.take();
        let stdout = PathBuf::from(format!("/m15/evidence/{name}.stdout"));
        let stderr = PathBuf::from(format!("/m15/evidence/{name}.stderr"));
        let (sender, lines) = mpsc::channel();
        let mut readers = Vec::new();
        let prepared = (|| {
            readers.push(reader(
                child
                    .stdout
                    .take()
                    .ok_or_else(|| invalid("native child stdout"))?,
                stdout.clone(),
                Some(sender),
            )?);
            readers.push(reader(
                child
                    .stderr
                    .take()
                    .ok_or_else(|| invalid("native child stderr"))?,
                stderr.clone(),
                None,
            )?);
            Ok(())
        })();
        if let Err(error) = prepared {
            let _ = child.kill();
            let _ = child.wait();
            for reader in readers {
                let _ = reader.join();
            }
            return Err(error);
        }
        Ok(Self {
            child,
            stdin,
            lines,
            readers,
            stdout,
            stderr,
        })
    }
    pub fn id(&self) -> u32 {
        self.child.id()
    }
    pub fn send(&mut self, value: &serde_json::Value) -> Result<()> {
        let raw = serde_json::to_vec(value).map_err(std::io::Error::other)?;
        if raw.len() + 1 > MAX_LINE {
            return Err(invalid("native original frame bound"));
        }
        let input = self
            .stdin
            .as_mut()
            .ok_or_else(|| invalid("native child stdin closed"))?;
        input.write_all(&raw)?;
        input.write_all(b"\n")?;
        input.flush()
    }
    pub fn json(&self, marker: Option<&[u8]>, until: Instant) -> Result<serde_json::Value> {
        loop {
            let remaining = until
                .checked_duration_since(Instant::now())
                .ok_or(std::io::ErrorKind::TimedOut)?;
            let raw = self
                .lines
                .recv_timeout(remaining)
                .map_err(std::io::Error::other)??;
            let bytes = if let Some(marker) = marker {
                let Some(offset) = raw.windows(marker.len()).position(|part| part == marker) else {
                    continue;
                };
                &raw[offset + marker.len()..]
            } else {
                raw.as_slice()
            };
            return serde_json::from_slice(bytes).map_err(std::io::Error::other);
        }
    }
    pub fn close_input(&mut self) {
        self.stdin.take();
    }
    pub fn wait(&mut self, until: Instant) -> Result<ExitStatus> {
        loop {
            if let Some(status) = self.child.try_wait()? {
                for reader in self.readers.drain(..) {
                    reader
                        .join()
                        .map_err(|_| invalid("native evidence reader panicked"))??;
                }
                return Ok(status);
            }
            if Instant::now() >= until {
                return Err(std::io::ErrorKind::TimedOut.into());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
    }
}
