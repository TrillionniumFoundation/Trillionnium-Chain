//! M10: the one bounded child-process collector used by the real Worker CLI.
use anyhow::Result;
use std::{process::Output, time::Duration};

/// Total captured stdout + stderr, not a chain-validity or model-token limit.
#[cfg(unix)]
const MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
#[cfg(unix)]
const CLEANUP_BUDGET: Duration = Duration::from_secs(1);

pub(crate) fn run_command_with_timeout(
    program: &str,
    base_args: &[String],
    extra_args: &[String],
    timeout: Duration,
) -> Result<Output> {
    #[cfg(unix)]
    {
        unix::run(program, base_args, extra_args, timeout)
    }
    #[cfg(not(unix))]
    {
        let _ = (program, base_args, extra_args, timeout);
        anyhow::bail!("bounded worker adapter process isolation is unsupported on this platform")
    }
}

#[cfg(unix)]
mod unix {
    use super::{CLEANUP_BUDGET, MAX_OUTPUT_BYTES};
    use anyhow::{Context, Result};
    use rustix::{
        fs::{fcntl_getfl, fcntl_setfl, OFlags},
        process::{kill_process_group, waitid, Pid, Signal, WaitId, WaitIdOptions},
    };
    use std::{
        io::{ErrorKind, Read},
        os::{fd::AsFd, unix::process::CommandExt},
        process::{Command, Output, Stdio},
        thread,
        time::{Duration, Instant},
    };
    use wait_timeout::ChildExt;

    #[cfg(target_os = "linux")]
    mod descendant_owner {
        use anyhow::{Context, Result};
        use rustix::process::{
            child_subreaper, getpid, pidfd_open, set_child_subreaper, waitid, Pid, PidfdFlags,
            WaitId, WaitIdOptions,
        };
        use std::{
            collections::BTreeSet,
            fs::{self, File},
            io::{ErrorKind, Read},
            path::Path,
            sync::OnceLock,
            thread,
            time::{Duration, Instant},
        };

        const MAX_PROC_BYTES: u64 = 1024 * 1024;
        static INSTALLED: OnceLock<std::result::Result<(), String>> = OnceLock::new();

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        struct Identity {
            pid: u32,
            parent: u32,
            group: u32,
            starttime: u64,
        }

        fn read_bounded(path: &Path) -> Result<Vec<u8>> {
            let mut bytes = Vec::new();
            File::open(path)?
                .take(MAX_PROC_BYTES + 1)
                .read_to_end(&mut bytes)?;
            anyhow::ensure!(
                bytes.len() as u64 <= MAX_PROC_BYTES,
                "worker proc input limit"
            );
            Ok(bytes)
        }

        fn parse_identity(bytes: &[u8]) -> Result<Identity> {
            let value = std::str::from_utf8(bytes)?;
            // comm may contain whitespace and ')'; the final ')' precedes state.
            let (prefix, fields) = value.rsplit_once(')').context("worker proc stat shape")?;
            let pid = prefix
                .split_once(' ')
                .context("worker proc pid")?
                .0
                .parse()?;
            let fields: Vec<_> = fields.split_whitespace().collect();
            anyhow::ensure!(fields.len() >= 20, "worker proc stat fields");
            Ok(Identity {
                pid,
                parent: fields[1].parse()?,
                group: fields[2].parse()?,
                starttime: fields[19].parse()?,
            })
        }

        fn identity(pid: u32) -> Result<Option<Identity>> {
            match read_bounded(Path::new(&format!("/proc/{pid}/stat"))) {
                Ok(bytes) => Ok(Some(parse_identity(&bytes)?)),
                Err(error)
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == ErrorKind::NotFound) =>
                {
                    Ok(None)
                }
                Err(error) => Err(error),
            }
        }

        // Linux adoption is process-wide. Install once, never temporarily toggle
        // it around a threaded call, and never consume another owner's wait.
        pub(super) fn install() -> Result<()> {
            let result = INSTALLED.get_or_init(|| {
                set_child_subreaper(Some(getpid())).map_err(|error| error.to_string())
            });
            anyhow::ensure!(result.is_ok(), "worker subreaper install: {result:?}");
            anyhow::ensure!(
                child_subreaper()?.is_some(),
                "worker subreaper was disabled"
            );
            let own = getpid();
            identity(own.as_raw_nonzero().get() as u32)?.context("worker proc unavailable")?;
            fs::read_dir("/proc/self/task")?;
            // Refuse unsupported pidfd-wait kernels before spawning an adapter.
            let descriptor = pidfd_open(own, PidfdFlags::empty())?;
            match waitid(
                WaitId::PidFd(descriptor.as_fd()),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
            ) {
                Err(rustix::io::Errno::CHILD) => Ok(()),
                other => anyhow::bail!("worker pidfd wait availability: {other:?}"),
            }
        }

        use std::os::fd::AsFd;

        fn child_ids(deadline: Instant) -> Result<(BTreeSet<u32>, bool)> {
            let mut children = BTreeSet::new();
            let mut changed_tasks = false;
            for task in fs::read_dir("/proc/self/task")? {
                anyhow::ensure!(
                    Instant::now() < deadline,
                    "worker descendant cleanup deadline"
                );
                let task = task?;
                let name = task.file_name();
                let name = name.to_str().context("worker task id")?;
                anyhow::ensure!(name.parse::<u32>().is_ok(), "worker task id shape");
                let path = task.path().join("children");
                let bytes = match read_bounded(&path) {
                    Ok(bytes) => bytes,
                    Err(error)
                        if error
                            .downcast_ref::<std::io::Error>()
                            .is_some_and(|e| e.kind() == ErrorKind::NotFound) =>
                    {
                        // Never declare closure from a partial task snapshot.
                        changed_tasks = true;
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                for value in std::str::from_utf8(&bytes)?.split_whitespace() {
                    children.insert(value.parse()?);
                }
            }
            Ok((children, changed_tasks))
        }

        pub(super) fn reap(group: Pid, deadline: Instant) -> Result<()> {
            let owner = getpid().as_raw_nonzero().get() as u32;
            let group_number = group.as_raw_nonzero().get() as u32;
            let leader = identity(group_number)?.context("worker leader identity missing")?;
            anyhow::ensure!(
                leader.pid == group_number
                    && leader.parent == owner
                    && leader.group == group_number,
                "worker leader ownership changed"
            );
            loop {
                anyhow::ensure!(
                    Instant::now() < deadline,
                    "worker descendant cleanup deadline"
                );
                let current = identity(group_number)?.context("worker leader pin missing")?;
                anyhow::ensure!(current == leader, "worker leader identity changed");
                let leader_exited = match waitid(
                    WaitId::Pid(group),
                    WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
                ) {
                    Ok(status) => status.is_some(),
                    Err(rustix::io::Errno::INTR) => continue,
                    Err(error) => return Err(error.into()),
                };
                let (children, changed_tasks) = child_ids(deadline)?;
                let mut found = changed_tasks;
                for pid in children {
                    anyhow::ensure!(
                        Instant::now() < deadline,
                        "worker descendant cleanup deadline"
                    );
                    if pid == group_number {
                        continue;
                    }
                    let Some(before) = identity(pid)? else {
                        continue;
                    };
                    if before.pid != pid || before.parent != owner || before.group != group_number {
                        continue;
                    }
                    found = true;
                    let pid = Pid::from_raw(i32::try_from(pid)?).context("worker child pid")?;
                    let descriptor = pidfd_open(pid, PidfdFlags::empty())?;
                    anyhow::ensure!(
                        identity(before.pid)? == Some(before),
                        "worker adopted child identity changed"
                    );
                    // This descriptor identifies the actual adopted child. The
                    // unreaped leader still pins the group; no wait(-1), no wait
                    // on a foreign group, no signal to an unclassified process.
                    match waitid(
                        WaitId::PidFd(descriptor.as_fd()),
                        WaitIdOptions::EXITED | WaitIdOptions::NOHANG,
                    ) {
                        Ok(_) | Err(rustix::io::Errno::INTR) => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                anyhow::ensure!(
                    Instant::now() < deadline,
                    "worker descendant cleanup deadline"
                );
                // An exit can reparent another generation after our snapshot.
                // Repeat after any found child, even when it was just reaped.
                if leader_exited && !found {
                    return Ok(());
                }
                thread::sleep(
                    Duration::from_millis(1)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
            }
        }

        #[cfg(test)]
        mod tests {
            use super::*;
            #[test]
            fn proc_identity_uses_last_comm_parenthesis_and_exact_starttime() {
                let mut fields = vec!["Z", "17", "29"];
                fields.extend(std::iter::repeat_n("0", 16));
                fields.push("987654321");
                let raw = format!("29 (command with ) spaces) {}", fields.join(" "));
                assert_eq!(
                    parse_identity(raw.as_bytes()).unwrap(),
                    Identity {
                        pid: 29,
                        parent: 17,
                        group: 29,
                        starttime: 987654321
                    }
                );
                assert!(parse_identity(b"29 (broken) Z 17 29").is_err());
            }

            fn run_nested_family() {
                let code = r#"import os,time,json
r,w=os.pipe()
child=os.fork()
if child==0:
 os.close(r)
 grand=os.fork()
 if grand==0:
  os.close(w);os.close(1);os.close(2);time.sleep(30)
 else:
  def token(p): return [p,int(open('/proc/%d/stat'%p).read().rsplit(')',1)[1].split()[19])]
  os.write(w,json.dumps([token(os.getpid()),token(grand)]).encode())
  os.close(w);os.close(1);os.close(2);time.sleep(30)
else:
 os.close(w)
 print(os.read(r,4096).decode(),flush=True)
 os.close(r)
"#;
                let output = crate::command_runtime_exec::run_command_with_timeout(
                    "python3",
                    &["-c".into(), code.into()],
                    &[],
                    Duration::from_secs(3),
                )
                .unwrap();
                assert!(output.status.success());
                let tokens: Vec<(u32, u64)> = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(tokens.len(), 2);
                for (pid, starttime) in tokens {
                    assert!(
                        identity(pid)
                            .unwrap()
                            .is_none_or(|actual| actual.starttime != starttime),
                        "an owned ordinary descendant is still live or unreaped after return"
                    );
                }
            }

            #[test]
            fn successful_leader_reaps_two_ordinary_descendant_generations() {
                run_nested_family();
            }

            #[test]
            fn concurrent_groups_do_not_reap_an_unrelated_direct_child() {
                use std::process::Command;
                let mut unrelated = Command::new("python3")
                    .args(["-c", "import time;time.sleep(.25);raise SystemExit(7)"])
                    .spawn()
                    .unwrap();
                let first = thread::spawn(run_nested_family);
                let second = thread::spawn(run_nested_family);
                first.join().unwrap();
                second.join().unwrap();
                assert_eq!(unrelated.wait().unwrap().code(), Some(7));
            }
        }
    }

    fn nonblocking(pipe: &impl AsFd) -> Result<()> {
        fcntl_setfl(pipe, fcntl_getfl(pipe)? | OFlags::NONBLOCK)?;
        Ok(())
    }

    // Fair bounded work per stream: a continuously writing stdout cannot starve
    // stderr or the deadline. There are no reader threads left blocked on EOF.
    fn drain<R: Read>(
        pipe: &mut Option<R>,
        bytes: &mut Vec<u8>,
        remaining: &mut usize,
    ) -> Result<bool> {
        let Some(reader) = pipe.as_mut() else {
            return Ok(false);
        };
        let mut progressed = false;
        let mut buffer = [0u8; 8192];
        for _ in 0..8 {
            match reader.read(&mut buffer) {
                Ok(0) => {
                    *pipe = None;
                    return Ok(true);
                }
                Ok(n) => {
                    anyhow::ensure!(
                        n <= *remaining,
                        "worker adapter output limit exceeded ({MAX_OUTPUT_BYTES} bytes)"
                    );
                    *remaining -= n;
                    bytes.extend_from_slice(&buffer[..n]);
                    progressed = true;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(progressed)
    }

    // Darwin killpg1 excludes SZOMB and returns EPERM when nfound == 0,
    // although our unreaped leader pins the group. Accept that only after
    // waitid proved exit AND both pipes reached EOF. Live/ambiguous EPERM
    // remains failure. This is not isolation from credential/group escapes.
    fn cleanup_already_terminal(error: rustix::io::Errno, terminal: bool) -> bool {
        error == rustix::io::Errno::SRCH
            || (cfg!(target_os = "macos") && terminal && error == rustix::io::Errno::PERM)
    }

    #[test]
    fn permission_failure_is_never_excused_for_a_live_child() {
        assert!(!cleanup_already_terminal(rustix::io::Errno::PERM, false));
        assert!(!cleanup_already_terminal(rustix::io::Errno::IO, true));
        assert!(cleanup_already_terminal(rustix::io::Errno::SRCH, false));
        assert_eq!(
            cleanup_already_terminal(rustix::io::Errno::PERM, true),
            cfg!(target_os = "macos")
        );
    }

    pub(super) fn run(
        program: &str,
        base_args: &[String],
        extra_args: &[String],
        timeout: Duration,
    ) -> Result<Output> {
        anyhow::ensure!(
            !timeout.is_zero(),
            "worker adapter timeout must be positive"
        );
        let started = Instant::now();
        #[cfg(target_os = "linux")]
        descendant_owner::install()?;
        // Ownership setup is part of the caller's original command deadline.
        anyhow::ensure!(
            started.elapsed() < timeout,
            "llm adapter timeout before spawn after {}ms",
            timeout.as_millis()
        );
        let mut child = Command::new(program)
            .args(base_args)
            .args(extra_args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()?;
        let group = Pid::from_child(&child);
        let collected = (|| -> Result<(Vec<u8>, Vec<u8>)> {
            let mut stdout = child.stdout.take();
            let mut stderr = child.stderr.take();
            nonblocking(stdout.as_ref().context("missing worker stdout pipe")?)?;
            nonblocking(stderr.as_ref().context("missing worker stderr pipe")?)?;
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let mut budget = MAX_OUTPUT_BYTES;
            loop {
                anyhow::ensure!(
                    started.elapsed() < timeout,
                    "llm adapter timeout after {}ms",
                    timeout.as_millis()
                );
                let progressed_out = drain(&mut stdout, &mut out, &mut budget)?;
                let progressed_err = drain(&mut stderr, &mut err, &mut budget)?;
                // NOWAIT pins the leader PID until group cleanup. Reaping early
                // could let a reused PID target an unrelated process group.
                let exited = match waitid(
                    WaitId::Pid(group),
                    WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
                ) {
                    Ok(status) => status.is_some(),
                    Err(rustix::io::Errno::INTR) => continue,
                    Err(e) => return Err(e.into()),
                };
                if exited && stdout.is_none() && stderr.is_none() {
                    return Ok((out, err));
                }
                if !progressed_out && !progressed_err {
                    thread::sleep(
                        Duration::from_millis(1).min(timeout.saturating_sub(started.elapsed())),
                    );
                }
            }
        })();
        // Always clean the owned group before reaping, including successful
        // leaders that left descendants running. This is not a sandbox against
        // a hostile child that deliberately escapes its process group.
        let cleanup_deadline = Instant::now() + CLEANUP_BUDGET;
        let group_cleanup = kill_process_group(group, Signal::KILL);
        #[cfg(target_os = "linux")]
        let descendant_cleanup = descendant_owner::reap(group, cleanup_deadline);
        let reaped = child
            .wait_timeout(cleanup_deadline.saturating_duration_since(Instant::now()))
            .with_context(|| {
                format!(
                    "worker adapter reap failed; collection={:?}",
                    collected.as_ref().err()
                )
            })?;
        if let Err(e) = group_cleanup {
            anyhow::ensure!(
                cleanup_already_terminal(e, collected.is_ok()),
                "worker adapter group cleanup failed: {e}; collection={:?}",
                collected.as_ref().err()
            );
        }
        let status = reaped.with_context(|| {
            format!(
                "worker adapter cleanup deadline exceeded; process reaping incomplete; collection={:?}",
                collected.as_ref().err()
            )
        })?;
        #[cfg(target_os = "linux")]
        descendant_cleanup.with_context(|| {
            format!(
                "worker adapter descendant reaping incomplete; collection={:?}",
                collected.as_ref().err()
            )
        })?;
        anyhow::ensure!(
            Instant::now() <= cleanup_deadline,
            "worker adapter cleanup deadline exceeded; collection={:?}",
            collected.as_ref().err()
        );
        let (stdout, stderr) = collected?;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::time::Instant;

    fn python(code: &str, timeout: Duration) -> Result<Output> {
        run_command_with_timeout("python3", &["-c".into(), code.into()], &[], timeout)
    }

    #[test]
    fn worker_drains_both_streams_above_pipe_capacity() {
        let out = python("import sys; sys.stdout.buffer.write(b'o'*262144); sys.stdout.flush(); sys.stderr.buffer.write(b'e'*262144); sys.stderr.flush()", Duration::from_secs(5)).unwrap();
        assert!(out.status.success());
        assert_eq!(out.stdout, vec![b'o'; 262144]);
        assert_eq!(out.stderr, vec![b'e'; 262144]);
    }

    #[test]
    fn worker_rejects_aggregate_output_over_budget() {
        let started = Instant::now();
        let err = python(
            "import os; b=b'x'*65536\nwhile True: os.write(1,b); os.write(2,b)",
            Duration::from_secs(5),
        )
        .unwrap_err();
        assert!(err.to_string().contains("output limit exceeded"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(6));
    }

    #[test]
    fn worker_deadline_includes_descendant_pipe_lifetime() {
        let started = Instant::now();
        let err = python(
            "import os,time; p=os.fork(); time.sleep(30) if p==0 else None",
            Duration::from_millis(200),
        )
        .unwrap_err();
        assert!(err.to_string().contains("timeout"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn worker_timeout_kills_group_before_delayed_effect() {
        use std::{fs, process};
        let marker = std::env::temp_dir().join(format!(
            "trnm-worker-cancel-{}-{}",
            process::id(),
            crate::now_ms()
        ));
        let code = format!(
            "import os,time; p=os.fork(); time.sleep(0.8); open({:?},'w').write('escaped')",
            marker.to_str().unwrap()
        );
        let err = python(&code, Duration::from_millis(150)).unwrap_err();
        assert!(err.to_string().contains("timeout"), "{err}");
        std::thread::sleep(Duration::from_secs(1));
        let exists = marker.exists();
        if exists {
            let _ = fs::remove_file(&marker);
        }
        assert!(
            !exists,
            "ordinary descendants must be terminated with the leader"
        );
    }

    #[test]
    fn worker_stdin_is_eof_and_nonzero_status_is_preserved() {
        let out = python(
            "import sys; assert sys.stdin.read()==''; sys.stderr.write('bad'); sys.exit(7)",
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(out.status.code(), Some(7));
        assert_eq!(out.stderr, b"bad");
    }

    #[test]
    fn worker_zero_deadline_refuses_before_spawn() {
        assert!(
            python("raise AssertionError('must not execute')", Duration::ZERO)
                .unwrap_err()
                .to_string()
                .contains("positive")
        );
    }
    #[test]
    fn real_llm_caller_parses_json_above_pipe_capacity() {
        let response = crate::run_llm_adapter_once(
            r#"python3 -c 'import json; print(json.dumps({"output_text":"x"*262144}))'"#,
            "",
            Duration::from_secs(5),
            &crate::proof_adapter::StandardProofAdapter,
        )
        .expect("actual adapter caller must drain before child exit");
        assert_eq!(response.output_text.len(), 262144);
    }
    #[test]
    fn successful_leader_still_cleans_descendants_that_close_their_pipes() {
        use std::{fs, process};
        let marker = std::env::temp_dir().join(format!(
            "trnm-worker-success-child-{}-{}",
            process::id(),
            crate::now_ms()
        ));
        let code = format!("import os,time; p=os.fork()\nif p==0:\n os.close(1); os.close(2); time.sleep(0.8); open({:?},'w').write('escaped')\nelse:\n os._exit(0)", marker.to_str().unwrap());
        let output = python(&code, Duration::from_secs(3))
            .expect("zombie-only Darwin groups must not turn success into EPERM");
        assert!(output.status.success());
        std::thread::sleep(Duration::from_secs(1));
        let exists = marker.exists();
        if exists {
            let _ = fs::remove_file(&marker);
        }
        assert!(
            !exists,
            "cleanup cannot be skipped just because the leader exited"
        );
    }
}
