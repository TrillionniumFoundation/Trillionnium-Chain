//! Bounded combined pipes for one owned v2 actor; a pidfd cannot kill a reused PID.
use rustix::process::{pidfd_open, pidfd_send_signal, Pid, PidfdFlags, Signal};
use serde_json::{json, Value};
use std::{
    fs, io,
    io::{Read, Write},
    os::fd::OwnedFd,
    path::Path,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    thread,
};

struct State {
    file: fs::File,
    limit: u64,
    retained: u64,
    seen: u64,
    cap: bool,
    error: Option<String>,
    kill_attempts: usize,
    kill_error: Option<String>,
}
impl State {
    fn record(&mut self, bytes: &[u8]) {
        self.seen = self
            .seen
            .checked_add(bytes.len() as u64)
            .expect("bounded log byte counter");
        if self.cap || self.error.is_some() {
            return;
        }
        let count = (self.limit - self.retained).min(bytes.len() as u64) as usize;
        if let Err(error) = self.file.write_all(&bytes[..count]) {
            self.error = Some(error.to_string());
        } else {
            self.retained += count as u64;
        }
        self.cap = self.retained == self.limit;
    }
    fn stop_if_failed(&mut self, target: &OwnedFd) {
        if (self.cap || self.error.is_some()) && self.kill_attempts == 0 {
            self.kill_attempts += 1;
            if let Err(error) = pidfd_send_signal(target, Signal::KILL) {
                self.kill_error = Some(error.to_string());
            }
        }
    }
    fn report(&self) -> Value {
        json!({"file":"actor.log","limit_bytes":self.limit,"retained_bytes":self.retained,
            "actual_file_bytes":self.file.metadata().ok().map(|m|m.len()),"observed_pipe_bytes":self.seen,
            "cap_reached":self.cap,"io_error":self.error,"pidfd_kill_attempts":self.kill_attempts,
            "pidfd_kill_error":self.kill_error,"sync_calls_added":0})
    }
}
pub struct Logs {
    state: Arc<Mutex<State>>,
    target: Arc<OwnedFd>,
    threads: Vec<thread::JoinHandle<()>>,
}
impl Logs {
    pub fn pipe(command: &mut Command) {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
    }
    /// If setup fails after spawn, stop and reap the exact owned child here.
    pub fn start(child: &mut Child, path: &Path, limit: u64) -> io::Result<Self> {
        let result = Self::attach(child, path, limit);
        if result.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        result
    }
    fn attach(child: &mut Child, path: &Path, limit: u64) -> io::Result<Self> {
        let pid = i32::try_from(child.id())
            .ok()
            .and_then(Pid::from_raw)
            .ok_or_else(|| io::Error::other("owned actor PID"))?;
        let target = Arc::new(pidfd_open(pid, PidfdFlags::empty())?);
        let file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)?;
        let state = Arc::new(Mutex::new(State {
            file,
            limit,
            retained: 0,
            seen: 0,
            cap: false,
            error: None,
            kill_attempts: 0,
            kill_error: None,
        }));
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("owned stdout pipe missing"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("owned stderr pipe missing"))?;
        let first = Self::reader(stdout, state.clone(), target.clone())?;
        let second = match Self::reader(stderr, state.clone(), target.clone()) {
            Ok(handle) => handle,
            Err(error) => {
                let _ = pidfd_send_signal(&target, Signal::KILL);
                let _ = first.join();
                return Err(error);
            }
        };
        let threads = vec![first, second];
        Ok(Self {
            state,
            target,
            threads,
        })
    }
    fn reader(
        mut input: impl Read + Send + 'static,
        state: Arc<Mutex<State>>,
        target: Arc<OwnedFd>,
    ) -> io::Result<thread::JoinHandle<()>> {
        thread::Builder::new()
            .name("pn1-v2-log-owner".into())
            .spawn(move || {
                let mut buffer = [0; 4096];
                loop {
                    match input.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(n) => {
                            let mut state = state.lock().unwrap();
                            state.record(&buffer[..n]);
                            state.stop_if_failed(&target);
                        }
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) => {
                            let mut state = state.lock().unwrap();
                            if state.error.is_none() {
                                state.error = Some(error.to_string());
                            }
                            state.stop_if_failed(&target);
                            break;
                        }
                    }
                }
            })
    }
    pub fn finish(mut self) -> Value {
        let mut panics = 0;
        let mut joined = 0;
        for handle in self.threads.drain(..) {
            if handle.join().is_err() {
                panics += 1;
            }
            joined += 1;
        }
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if (panics > 0 || self.state.is_poisoned()) && state.error.is_none() {
            state.error =
                Some("log reader panicked or owner mutex poisoned; all readers joined".into());
        }
        let mut report = state.report();
        report["reader_threads_joined"] = json!(joined);
        report["reader_thread_panics"] = json!(panics);
        report
    }
}
impl Drop for Logs {
    fn drop(&mut self) {
        if !self.threads.is_empty() {
            let _ = pidfd_send_signal(&self.target, Signal::KILL);
            for handle in self.threads.drain(..) {
                let _ = handle.join();
            }
        }
    }
}

#[test]
#[ignore = "owned log-only child entry; no network, W1 or service qualification"]
fn owned_log_diagnostic_entry() {
    let mode = std::env::var("TRNM_IDENTITY_LOG_CONTROL").expect("explicit owned log control");
    assert!(mode == "normal" || mode == "overflow");
    if mode == "normal" {
        println!("PN1_STDOUT");
        eprintln!("PN1_STDERR");
    } else {
        let block = [b'x'; 1024];
        for _ in 0..2000 {
            std::io::stdout().write_all(&block).unwrap();
            std::io::stderr().write_all(&block).unwrap();
            thread::sleep(std::time::Duration::from_millis(1));
        }
    }
}
#[test]
fn owned_pipes_are_bounded_and_the_cap_terminates_and_reaps_the_same_child() {
    for mode in ["normal", "overflow"] {
        let out = tempfile::tempdir().unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "logs::owned_log_diagnostic_entry",
                "--ignored",
                "--quiet",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("TRNM_IDENTITY_LOG_CONTROL", mode);
        Logs::pipe(&mut command);
        let mut child = command.spawn().unwrap();
        let cap = if mode == "normal" { 4096 } else { 128 };
        let logs = Logs::start(&mut child, &out.path().join("actor.log"), cap).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut forced = false;
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                forced = true;
                child.kill().unwrap();
                break child.wait().unwrap();
            }
            thread::sleep(std::time::Duration::from_millis(2));
        };
        let report = logs.finish();
        assert!(!forced && report["io_error"].is_null(), "{report}");
        assert_eq!(report["actual_file_bytes"], report["retained_bytes"]);
        assert!(report["retained_bytes"].as_u64().unwrap() <= cap);
        if mode == "normal" {
            assert!(status.success());
            assert_eq!(report["cap_reached"], false);
            assert_eq!(report["observed_pipe_bytes"], report["retained_bytes"]);
            let raw = fs::read_to_string(out.path().join("actor.log")).unwrap();
            assert!(raw.contains("PN1_STDOUT") && raw.contains("PN1_STDERR"));
        } else {
            assert!(!status.success());
            assert_eq!(report["cap_reached"], true);
            assert_eq!(report["pidfd_kill_attempts"], 1);
            assert!(report["pidfd_kill_error"].is_null());
            assert_eq!(report["retained_bytes"], cap);
        }
    }
}
