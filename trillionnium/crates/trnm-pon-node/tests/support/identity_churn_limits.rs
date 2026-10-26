//! Stricter v2 collection limits, installed only inside an owned native process.
use super::evidence::{self, MIB};
use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};
use serde_json::{json, Value};
use std::{fs, io, path::Path};

pub const SCHEMA: &str = "native-public-v3-identity-evidence-limits-v2";
pub const ACTOR_VM: u64 = 512 * MIB;
pub const PARENT_VM: u64 = 3072 * MIB;
pub const PARENT_FILE: u64 = 16 * MIB;
pub const ACTOR_FILE: u64 = 8 * MIB;
pub const PHASE_BYTES: u64 = 16 * MIB;
pub const ROOT_NATIVE_BYTES: u64 = MIB;
pub const NODE_ROOTS: [&str; 7] = [
    "honest-miner",
    "honest-only/receiver",
    "honest-only/independent-client",
    "replay-only/receiver",
    "replay-only/independent-client",
    "fresh-identities/receiver",
    "fresh-identities/independent-client",
];

pub fn descriptor() -> Value {
    let mut descriptor = json!({"schema":SCHEMA,"artifact_total_bytes":8192*MIB,
        "actor_prefix_bytes":evidence::PREFIX_BYTES,"actor_fresh_pressure_bytes":evidence::FRESH_BYTES,
        "actor_replay_pressure_bytes":evidence::REPLAY_BYTES,"construction_bytes":evidence::CONSTRUCTION_BYTES,
        "actor_working_data_bytes":evidence::WORKING_BYTES,"actor_vm_bytes":ACTOR_VM,"parent_vm_bytes":PARENT_VM,
        "parent_file_bytes":PARENT_FILE,"actor_file_bytes":ACTOR_FILE,
        "node_roots":NODE_ROOTS,"node_database_bytes_each":16*MIB,"node_database_total_bytes":336*MIB,
        "node_metadata_total_bytes":MIB,"node_file_names":{"native.sqlite":16*MIB,"native.sqlite-wal":16*MIB,
            "native.sqlite-shm":16*MIB,"owner.lock":0,"initializing.json":1024}});
    let outputs = json!({"sample_chunk_bytes":8*MIB,"sample_chunks_per_phase":12,"sample_total_bytes":288*MIB,
        "frozen_binary_bytes":192*MIB,"phase_report_bytes_each":PHASE_BYTES,"phase_report_total_bytes":3*PHASE_BYTES,
        "actor_metadata_bytes_each":MIB/2,"actor_metadata_total_bytes":36*MIB,
        "actor_log_bytes_each":64*1024,"actor_log_total_bytes":9*MIB/2,
        "outer_outputs_total_bytes":128*MIB,"preparation_bytes":8*MIB,"root_outputs_total_bytes":32*MIB,
        "raw_root_outputs_bytes":ROOT_NATIVE_BYTES,"inventory_bytes":31*MIB,
        "reserved_total_bytes":16355*MIB/2,"unassigned_bytes":29*MIB/2});
    descriptor
        .as_object_mut()
        .unwrap()
        .extend(outputs.as_object().unwrap().clone());
    descriptor["bucket_members"] = json!({"actor_stage":"started, construction, call and retained partial files under prefix/pressure",
            "actor_metadata":"actor-root job, ready, prefix-finished, report, process-limits and stage-terminal JSON, including partials",
            "actor_log":"actor.log only; combined stdout/stderr must be bounded by its owner",
            "phase":"phase report, prefix-start, pressure-start and terminal JSON, including partials",
            "samples":"only the exact report sample_files chunks; summed sample_count preserves every row",
            "root":"artifact-files.json and raw top-level plan, report, process-limits and node-files JSON",
            "outer":"all other frozen/source/resource/native streams/results; excludes the single frozen binary",
            "partial_policy":"retain and charge the matching bucket; any partial or initializing marker prevents qualification",
            "honest_only_pressure":"must remain empty"});
    descriptor["namespace_rules"] = json!({"raw_root_json":["plan.json","report.json","process-limits.json","node-files.json","cap-terminal.json"],
            "actor_metadata_json":["job.json","ready.json","prefix-finished.json","report.json","process-limits.json","stage-terminal.json"],
            "phase_metadata_json":["report.json","prefix-start.json","pressure-start.json","terminal.json"],
            "sample_name_pattern":"samples-[0-9][0-9].jsonl","sample_indices":"00..11",
            "strict_success_forbidden":["*.partial.json","*.tmp.json","initializing.json","cap-terminal.json","stage-terminal.json","terminal.json"]});
    descriptor["all_cap_hits"] =
        json!("FAIL; preserve partial and terminal; never increase caps or retry as qualification");
    descriptor["scope"] = json!(
        "stricter local evidence limits; original 4CPU/16GiB cgroup and workload limits remain"
    );
    descriptor
}
pub fn full_route_ready() -> bool {
    // Kept closed until all native writers, log owners, samples and reader agree.
    false
}
fn lower(resource: Resource, bytes: u64) -> io::Result<()> {
    let previous = getrlimit(resource);
    if previous.maximum.is_some_and(|n| n < bytes) || previous.current.is_some_and(|n| n < bytes) {
        return Err(io::Error::other(
            "inherited owned-process limit below v2 declaration",
        ));
    }
    setrlimit(
        resource,
        Rlimit {
            current: Some(bytes),
            maximum: Some(bytes),
        },
    )
    .map_err(Into::into)
}
pub fn observation() -> io::Result<Value> {
    let address = getrlimit(Resource::As);
    let file = getrlimit(Resource::Fsize);
    let status = fs::read_to_string("/proc/self/status")?;
    let vm: Vec<_> = status
        .lines()
        .filter(|line| line.starts_with("Vm"))
        .collect();
    Ok(
        json!({"pid":std::process::id(),"address_space":{"soft_bytes":address.current,"hard_bytes":address.maximum},
        "file_size":{"soft_bytes":file.current,"hard_bytes":file.maximum},"proc_status_vm":vm,
        "cgroup":fs::read_to_string("/proc/self/cgroup")?}),
    )
}
pub fn install(actor: bool) -> io::Result<Value> {
    let before = observation()?;
    lower(Resource::As, if actor { ACTOR_VM } else { PARENT_VM })?;
    lower(
        Resource::Fsize,
        if actor { ACTOR_FILE } else { PARENT_FILE },
    )?;
    // SAFETY: the owned collector process ignores only file-cap signals. Writes
    // then return EFBIG, preserving ordinary error/unwind and partial receipts.
    if unsafe { libc::signal(libc::SIGXFSZ, libc::SIG_IGN) } == libc::SIG_ERR {
        return Err(io::Error::last_os_error());
    }
    Ok(
        json!({"schema":SCHEMA,"role":if actor{"actor"}else{"campaign-parent"},"before":before,
        "after":observation()?,"original_cgroup_required":true,"full_ledger_implemented":false}),
    )
}
pub fn configure_actor(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: only async-signal-safe setrlimit syscalls run between fork and
    // exec; constants are copied on stack. No lock, allocation or filesystem I/O.
    unsafe {
        command.pre_exec(|| {
            let address = libc::rlimit {
                rlim_cur: ACTOR_VM,
                rlim_max: ACTOR_VM,
            };
            let file = libc::rlimit {
                rlim_cur: ACTOR_FILE,
                rlim_max: ACTOR_FILE,
            };
            if libc::setrlimit(libc::RLIMIT_AS, &address) != 0
                || libc::setrlimit(libc::RLIMIT_FSIZE, &file) != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}
/// Validate the exact source-owned file namespace without deleting a failed init.
/// Store::open writes only a fixed three-hash canonical initializing marker;
/// the 1-KiB bound is independent of the larger kernel file limit.
pub fn node_files(root: &Path) -> io::Result<Value> {
    let mut files = Vec::new();
    let mut metadata = 0;
    for name in NODE_ROOTS {
        let directory = root.join(name);
        if !directory.exists() {
            continue;
        }
        let info = fs::symlink_metadata(&directory)?;
        if !info.is_dir() || info.file_type().is_symlink() {
            return Err(io::Error::other("Node root type"));
        }
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let info = entry.file_type()?;
            let file = entry
                .file_name()
                .into_string()
                .map_err(|_| io::Error::other("non-UTF8 Node file"))?;
            let limit = match file.as_str() {
                "native.sqlite" | "native.sqlite-wal" | "native.sqlite-shm" => PARENT_FILE,
                "owner.lock" => 0,
                "initializing.json" => 1024,
                _ => {
                    return Err(io::Error::other(
                        "unexpected Node artifact; preserve and fail",
                    ))
                }
            };
            let bytes = entry.metadata()?.len();
            if !info.is_file() || info.is_symlink() || bytes > limit {
                return Err(io::Error::other(
                    "Node artifact cap/type; preserve and fail",
                ));
            }
            if file == "owner.lock" || file == "initializing.json" {
                metadata += bytes;
            }
            files.push(json!({"path":format!("{name}/{file}"),"bytes":bytes,"limit_bytes":limit}));
        }
    }
    if metadata > MIB {
        return Err(io::Error::other("Node metadata total cap"));
    }
    Ok(json!({"files":files,"metadata_bytes":metadata,"metadata_limit_bytes":MIB}))
}

#[test]
fn descriptor_counts_all_owned_files_and_leaves_original_envelope_unchanged() {
    let d = descriptor();
    let buckets = [
        "node_database_total_bytes",
        "node_metadata_total_bytes",
        "sample_total_bytes",
        "frozen_binary_bytes",
        "phase_report_total_bytes",
        "actor_metadata_total_bytes",
        "actor_log_total_bytes",
        "outer_outputs_total_bytes",
        "preparation_bytes",
        "root_outputs_total_bytes",
    ];
    let stage =
        72 * evidence::PREFIX_BYTES + 24 * evidence::FRESH_BYTES + 24 * evidence::REPLAY_BYTES;
    let total = buckets
        .iter()
        .map(|key| d[key].as_u64().unwrap())
        .sum::<u64>()
        + stage;
    assert_eq!(total, d["reserved_total_bytes"].as_u64().unwrap());
    assert_eq!(total + d["unassigned_bytes"].as_u64().unwrap(), 8192 * MIB);
    assert!(
        24 * d["actor_vm_bytes"].as_u64().unwrap() + d["parent_vm_bytes"].as_u64().unwrap()
            < 16 * 1024 * MIB
    );
    assert!(!full_route_ready());
}
#[test]
fn failed_initialization_marker_is_retained_and_unknown_files_fail() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("honest-miner");
    fs::create_dir(&directory).unwrap();
    fs::write(directory.join("initializing.json"), b"failure evidence").unwrap();
    fs::write(directory.join("owner.lock"), b"").unwrap();
    assert_eq!(node_files(temp.path()).unwrap()["metadata_bytes"], 16);
    fs::write(directory.join("unknown"), b"do not remove").unwrap();
    assert!(node_files(temp.path()).is_err());
    assert!(directory.join("initializing.json").exists() && directory.join("unknown").exists());
}
