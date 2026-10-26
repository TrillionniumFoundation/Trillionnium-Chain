//! Explicit small owned-process limit control; it does not run the full workload.
use super::{evidence, limits};
use serde_json::{json, Value};
use std::{fs, io::Write, path::PathBuf, process::Command};

fn output() -> PathBuf {
    PathBuf::from(
        std::env::var_os("TRNM_IDENTITY_LIMIT_CONTROL_DIR")
            .expect("fresh explicit limit-control output"),
    )
}
#[test]
#[ignore = "child entry for the explicit local v2 owned-process limit control"]
fn owned_process_limits_v2_child_entry() {
    let out = output();
    fs::create_dir(&out).unwrap();
    let mut metadata = evidence::Budget::new(evidence::MIB / 2);
    let observed = limits::install(true).unwrap();
    metadata
        .write(&out.join("limits.json"), &observed, evidence::MIB / 2)
        .unwrap();
    // A single file actually reaches the tighter cap; the next byte must fail.
    // No original work/test resource budget or historical receipt is changed.
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(out.join("cap.bin"))
        .unwrap();
    let buffer = [0_u8; 65536];
    for _ in 0..limits::ACTOR_FILE / buffer.len() as u64 {
        file.write_all(&buffer).unwrap();
    }
    file.sync_all().unwrap();
    let failure = file.write_all(b"x").unwrap_err();
    assert_eq!(failure.raw_os_error(), Some(libc::EFBIG));
    assert_eq!(file.metadata().unwrap().len(), limits::ACTOR_FILE);
    // Reserve an inaccessible virtual mapping only; never touch a large buffer.
    // SAFETY: an anonymous PROT_NONE mapping has no input pointers and remains
    // inaccessible; any unexpected successful mapping is immediately unmapped.
    let address = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            (limits::ACTOR_VM + 1) as usize,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    let vm_error = std::io::Error::last_os_error();
    if address != libc::MAP_FAILED {
        // SAFETY: this is exactly the returned mapping and requested size.
        unsafe {
            libc::munmap(address, (limits::ACTOR_VM + 1) as usize);
        }
        panic!("owned actor unexpectedly exceeded v2 address-space limit");
    }
    assert_eq!(vm_error.raw_os_error(), Some(libc::ENOMEM));
    metadata
        .write(
            &out.join("report.json"),
            &json!({"file_cap_error":failure.raw_os_error(),
        "file_bytes":file.metadata().unwrap().len(),"vm_cap_error":vm_error.raw_os_error(),
        "after":limits::observation().unwrap(),"full_campaign_qualified":false}),
            evidence::MIB / 2,
        )
        .unwrap();
}

#[test]
#[ignore = "small actual parent/child limit probe only; no capacity, pressure or service qualification"]
fn owned_parent_and_child_limits_v2_control() {
    let out = output();
    fs::create_dir(&out).unwrap();
    let mut metadata = evidence::Budget::new(32 * evidence::MIB);
    metadata
        .write(
            &out.join("descriptor.json"),
            &limits::descriptor(),
            evidence::MIB,
        )
        .unwrap();
    let parent = limits::install(false).unwrap();
    metadata
        .write(&out.join("parent-limits.json"), &parent, evidence::MIB)
        .unwrap();
    let started = super::support::monotonic();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "limit_control::owned_process_limits_v2_child_entry",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("TRNM_IDENTITY_LIMIT_CONTROL_DIR", out.join("child"));
    limits::configure_actor(&mut command);
    let mut child = command.spawn().unwrap();
    let pid = child.id();
    let status = child.wait().unwrap();
    let child_report: Option<Value> = fs::read(out.join("child/report.json"))
        .ok()
        .and_then(|r| serde_json::from_slice(&r).ok());
    metadata.write(&out.join("report.json"), &json!({"schema":limits::SCHEMA,"kind":"owned-limit-control",
        "child":{"spawned_pid":pid,"reaped_ns":super::support::monotonic(),"started_ns":started,
            "exit_success":status.success(),"exit_status":status.to_string(),"report":child_report},
        "parent_after":limits::observation().unwrap(),"complete":status.success(),
        "full_route_ready":limits::full_route_ready(),"full_campaign_qualified":false,"merge_ready":false}), evidence::MIB).unwrap();
    assert!(status.success());
}

#[test]
#[ignore = "short diagnostic for exact native empty-store initialization; run under owned file-event trace; no workload qualification"]
fn owned_native_node_initialization_trace_v2_control() {
    let out = output();
    fs::create_dir(&out).unwrap();
    let mut metadata = evidence::Budget::new(evidence::MIB);
    let installed = limits::install(false).unwrap();
    metadata
        .write(&out.join("process-limits.json"), &installed, evidence::MIB)
        .unwrap();
    let path = out.join("honest-miner");
    let node =
        trnm_pon_node::Node::open_with_authenticated_state(&path, super::support::settings(), 1)
            .unwrap();
    let live = node.read_active().unwrap();
    let stats = node.stats().unwrap();
    let live_files = limits::node_files(&out).unwrap();
    drop(node);
    let cold =
        trnm_pon_node::Node::open_with_authenticated_state(&path, super::support::settings(), 1)
            .unwrap();
    let equal = cold.read_active().unwrap() == live && cold.stats().unwrap() == stats;
    drop(cold);
    metadata
        .write(
            &out.join("report.json"),
            &json!({"schema":limits::SCHEMA,
        "kind":"native-initialization-file-diagnostic","live_files":live_files,
        "closed_files":limits::node_files(&out).unwrap(),"cold_equal":equal,
        "transient_file_absence_proven":false,"full_campaign_qualified":false,"merge_ready":false}),
            evidence::MIB,
        )
        .unwrap();
    assert!(equal);
}
