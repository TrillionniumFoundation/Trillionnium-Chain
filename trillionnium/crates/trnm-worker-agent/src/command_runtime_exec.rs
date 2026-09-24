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
        let group_cleanup = kill_process_group(group, Signal::KILL);
        let reaped = child
            .wait_timeout(CLEANUP_BUDGET)
            .context("worker adapter reap failed")?;
        if let Err(e) = group_cleanup {
            anyhow::ensure!(
                e == rustix::io::Errno::SRCH,
                "worker adapter group cleanup failed: {e}; collection={:?}",
                collected.as_ref().err()
            );
        }
        let status = reaped
            .context("worker adapter cleanup deadline exceeded; process reaping incomplete")?;
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
}
