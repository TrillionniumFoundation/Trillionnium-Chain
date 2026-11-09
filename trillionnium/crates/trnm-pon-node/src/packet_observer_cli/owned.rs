//! Explicit finite-principal observer adapter. The old observer has no implicit
//! adoption, refill or fallback. A failed/unknown child keeps its reservation.
use super::{execute_until, install_cpu_ceiling, WORKER_OPTION};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use trnm_pon_node::resource_owner_v1::{
    AdmissionV1, ChargeV1, CompletionV1, ResourceOwnerV1, ResourceProfileV1,
};
use trnm_pon_node::{
    observe_existing_packet_owned, Error, PacketObservationBackend,
    PacketObservationResourceContractV1, Result, Settings,
    DEFAULT_PACKET_OBSERVATION_SNAPSHOT_BYTE_LIMIT,
};
use trnm_protocol::pon_wire::Hash;

const OWNED_WORKER: &str = "resource-owner-v1";
const PACKET_LIMIT: u64 = 1_048_576;
const BINDING_OPTIONS: [&str; 5] = [
    "--observation-resource-profile-sha256",
    "--observation-operation-id",
    "--observation-parent-state",
    "--observation-deadline-unix-ms",
    "--observation-packet-sha256",
];

fn need<'a>(args: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str> {
    args.get(key)
        .map(String::as_str)
        .ok_or_else(|| Error::from(format!("PACKET_OBSERVATION_REQUIRED:{key}")))
}
fn number(args: &BTreeMap<String, String>, key: &str, default: u64) -> Result<u64> {
    args.get(key)
        .map(|value| {
            value
                .parse()
                .map_err(|_| Error::from("PACKET_OBSERVATION_BUDGET"))
        })
        .unwrap_or(Ok(default))
}
fn hash(text: &str) -> Result<Hash> {
    hex::decode(text)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| "PACKET_OBSERVATION_RESOURCE_BINDING".into())
}
fn now_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or_else(|| "PACKET_OBSERVATION_CLOCK".into())
}

/// Open a regular input without following a symlink or blocking on a FIFO.
/// The complete bounded bytes, descriptor and pathname are checked together.
fn bounded_file(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() > maximum {
        return Err("PACKET_OBSERVATION_INPUT_LIMIT".into());
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum || bytes.len() as u64 != before.len() {
        return Err("PACKET_OBSERVATION_INPUT_LIMIT".into());
    }
    let identity = |metadata: &fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
    };
    for after in [file.metadata()?, fs::symlink_metadata(path)?] {
        if !after.is_file()
            || after.file_type().is_symlink()
            || identity(&after) != identity(&before)
        {
            return Err("PACKET_OBSERVATION_INPUT_CHANGED".into());
        }
    }
    Ok(bytes)
}

pub(super) fn selected(args: &BTreeMap<String, String>, source: &Path) -> Result<bool> {
    if BINDING_OPTIONS.iter().any(|key| args.contains_key(*key)) {
        return Ok(true);
    }
    if ResourceOwnerV1::is_present(source)? {
        return Err("PACKET_OBSERVATION_RESOURCE_PROFILE_REQUIRED".into());
    }
    Ok(false)
}

fn contract(
    args: &BTreeMap<String, String>,
    cpu: u64,
    wall: u64,
) -> Result<(Settings, PacketObservationResourceContractV1)> {
    // This first adapter deliberately accepts only the original plain local
    // complete-State contexts. No expensive model loader or outside owner is
    // opened while constructing a new reservation.
    const LOCAL_OPTIONS: [&str; 11] = [
        "--development",
        "--store",
        "--packet",
        "--state-backend",
        "--genesis-time",
        "--workers",
        "--logical-now",
        "--observation-cpu-seconds",
        "--observation-wall-seconds",
        "--observation-snapshot-bytes",
        WORKER_OPTION,
    ];
    if args.contains_key("--packet-stdin") || !args.contains_key("--packet") {
        return Err("PACKET_OBSERVATION_OWNED_FILE_REQUIRED".into());
    }
    if args.keys().any(|key| {
        !LOCAL_OPTIONS.contains(&key.as_str()) && !BINDING_OPTIONS.contains(&key.as_str())
    }) {
        return Err("PACKET_OBSERVATION_OWNED_OPTIONS".into());
    }
    if let Some(worker) = args.get(WORKER_OPTION) {
        if worker != OWNED_WORKER {
            return Err("PACKET_OBSERVATION_WORKER".into());
        }
    }
    let genesis = args
        .get("--genesis-time")
        .map(|value| value.parse().map_err(|_| Error::from("GENESIS_TIME")))
        .transpose()?;
    let settings = Settings::development(genesis)?;
    let backend = match args
        .get("--state-backend")
        .map(String::as_str)
        .unwrap_or("legacy-v2")
    {
        "legacy-v2" => PacketObservationBackend::LegacyV2,
        "authenticated-v1" => PacketObservationBackend::AuthenticatedV1,
        _ => return Err("PACKET_OBSERVATION_BACKEND".into()),
    };
    let contract = PacketObservationResourceContractV1 {
        profile_id: hash(need(args, BINDING_OPTIONS[0])?)?,
        operation_id: hash(need(args, BINDING_OPTIONS[1])?)?,
        parent_state: hash(need(args, BINDING_OPTIONS[2])?)?,
        deadline_unix_ms: need(args, BINDING_OPTIONS[3])?
            .parse()
            .map_err(|_| Error::from("PACKET_OBSERVATION_BUDGET"))?,
        packet_sha256: hash(need(args, BINDING_OPTIONS[4])?)?,
        backend,
        workers: usize::try_from(number(args, "--workers", 1)?)
            .map_err(|_| Error::from("WORKERS"))?,
        snapshot_byte_limit: number(
            args,
            "--observation-snapshot-bytes",
            DEFAULT_PACKET_OBSERVATION_SNAPSHOT_BYTE_LIMIT,
        )?,
        cpu_seconds: cpu,
        wall_seconds: wall,
        logical_now: args
            .get("--logical-now")
            .map(|value| {
                value
                    .parse()
                    .map_err(|_| Error::from("PACKET_OBSERVATION_BUDGET"))
            })
            .transpose()?,
    };
    contract.request(&settings)?;
    Ok((settings, contract))
}

pub(super) fn supervise(
    args: &BTreeMap<String, String>,
    source: &Path,
    cpu: u64,
    wall: u64,
) -> Result<Value> {
    let (settings, contract) = contract(args, cpu, wall)?;
    let request = contract.request(&settings)?;
    let owner = ResourceOwnerV1::open(source, contract.profile_id)?;
    // Pair the clocks before durable admission. Journal I/O, input freezing
    // and process startup must consume, rather than renew, this wall budget.
    let original_instant = Instant::now();
    let now = now_ms()?;
    if args.contains_key(WORKER_OPTION) {
        install_cpu_ceiling(cpu)?;
        // Claim before bounded input reading or any native snapshot. A direct
        // worker invocation cannot initialize or reserve a second allowance.
        let reservation = owner.claim_existing(&request, now)?;
        let packet = bounded_file(Path::new(need(args, "--packet")?), PACKET_LIMIT)?;
        let result =
            observe_existing_packet_owned(source, settings, &packet, &contract, reservation)?;
        return Ok(json!({
            "result":result,
            "clock_scope":if contract.logical_now.is_some(){"logical-test"}else{"local-wall"},
            "production_activation":false,
        }));
    }
    let reservation = match owner.reserve(&request, now)? {
        AdmissionV1::Fresh(reservation) => reservation,
        AdmissionV1::Existing(record) => {
            return Ok(json!({
                "schema":"pon-resource-owned-packet-status-v1",
                "resource_record":record,
                "dispatched":false,
                "safe_retry_authorized":false,
                "production_activation":false,
            }))
        }
    };
    let remaining = request
        .binding
        .deadline_unix_ms
        .checked_sub(now)
        .ok_or("RESOURCE_OWNER_DEADLINE")?;
    let deadline = original_instant
        .checked_add(Duration::from_millis(remaining).min(Duration::from_secs(wall)))
        .ok_or("PACKET_OBSERVATION_BUDGET")?;
    // The original reservation is already durable before packet reading,
    // temporary creation, freezing, process spawn or native snapshot copying.
    let packet = bounded_file(Path::new(need(args, "--packet")?), PACKET_LIMIT)?;
    let actual: Hash = Sha256::digest(&packet).into();
    if actual != contract.packet_sha256 {
        return Err("PACKET_OBSERVATION_PACKET_BINDING".into());
    }
    let temporary_root = fs::canonicalize("/tmp")?;
    if temporary_root.starts_with(owner.node_path()) {
        return Err("GROWTH_OBSERVATION_SNAPSHOT_LOCATION".into());
    }
    let temporary = tempfile::Builder::new()
        .prefix("trnm-resource-packet-supervisor-")
        .tempdir_in(temporary_root)?;
    let frozen_path = temporary.path().join("packet.bin");
    let mut frozen = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&frozen_path)?;
    frozen.write_all(&packet)?;
    frozen.sync_all()?;
    drop(frozen);
    drop(packet);
    let mut child_args = args.clone();
    child_args.insert(
        "--store".into(),
        owner
            .node_path()
            .to_str()
            .ok_or("PACKET_OBSERVATION_PATH")?
            .into(),
    );
    child_args.insert(
        "--packet".into(),
        frozen_path
            .to_str()
            .ok_or("PACKET_OBSERVATION_PATH")?
            .into(),
    );
    child_args.insert(WORKER_OPTION.into(), OWNED_WORKER.into());
    let mut child = Command::new(std::env::current_exe()?);
    child.arg("packet-status");
    for (key, value) in child_args {
        child.arg(&key);
        if key != "--development" {
            child.arg(value);
        }
    }
    child
        .env_clear()
        .env("TMPDIR", temporary.path())
        .stdin(Stdio::null());
    // execute_until returns success only after authoritative wait and both pipe
    // joins. Every error retains the durable hold, even if best-effort Drop
    // cleanup happened; an error cannot supply completion evidence.
    let result = execute_until(child, deadline);
    let cleanup = temporary.close();
    let mut value = result?;
    cleanup?;
    let receipt = &value["result"];
    if receipt["schema"] != "pon-resource-owned-packet-observation-v1"
        || receipt["resource_profile"] != hex::encode(contract.profile_id)
        || receipt["operation_id"] != hex::encode(contract.operation_id)
        || receipt["request_digest"] != hex::encode(request.binding.request_digest)
        || receipt["packet_sha256"] != hex::encode(contract.packet_sha256)
        || receipt["parent_state"] != hex::encode(contract.parent_state)
        || receipt["deadline_unix_ms"] != contract.deadline_unix_ms
        || receipt["native_source_unchanged"] != true
        || receipt["source_scope"] != json!(["native.sqlite", "owner.lock"])
        || receipt["native_read_only"] != true
    {
        return Err("PACKET_OBSERVATION_RESOURCE_RECEIPT".into());
    }
    let mut digest = Sha256::new();
    digest.update(b"pon-resource-owned-packet-completion-v1\0");
    digest.update(serde_json::to_vec(&value)?);
    let record = reservation.finish(
        CompletionV1 {
            worker_stopped: true,
            effect_readback: true,
            cleanup_complete: true,
            receipt_digest: digest.finalize().into(),
        },
        ChargeV1::Conservative,
    )?;
    value
        .as_object_mut()
        .ok_or("PACKET_OBSERVATION_RESOURCE_RECEIPT")?
        .insert(
            "resource_settlement".into(),
            json!({
                "record":record,
                "charge_basis":"full-original-reservation",
                "actual_cpu_measured":false,
                "actual_io_measured":false,
            }),
        );
    Ok(value)
}

/// Deliberate local provisioning, never called by a reader. The existing Node
/// must already exist, and the underlying owner refuses any previous journal.
pub(crate) fn initialize(args: &BTreeMap<String, String>) -> Result<Value> {
    const ALLOWED: [&str; 4] = [
        "--development",
        "--store",
        "--resource-profile",
        "--resource-profile-sha256",
    ];
    if args.len() != ALLOWED.len() || args.keys().any(|key| !ALLOWED.contains(&key.as_str())) {
        return Err("RESOURCE_OWNER_INITIALIZE_OPTIONS".into());
    }
    let raw = bounded_file(Path::new(need(args, "--resource-profile")?), 4096)?;
    if <Hash>::from(Sha256::digest(&raw)) != hash(need(args, "--resource-profile-sha256")?)? {
        return Err("RESOURCE_OWNER_PROFILE_FILE_HASH".into());
    }
    let profile: ResourceProfileV1 = serde_json::from_slice(&raw)?;
    let owner = ResourceOwnerV1::initialize(Path::new(need(args, "--store")?), &profile)?;
    Ok(json!({
        "schema":"pon-local-resource-owner-initialized-v1",
        "resource_profile":hex::encode(profile.id()?),
        "resource_account":owner.snapshot()?,
        "production_activation":false,
    }))
}
