//! V2 same-operation replay support. The original V1 entry remains byte-for-byte unchanged.
//! The CHB1/Python execution protocol stays V1; V2 adds a complete TCP transfer
//! before retention and an explicit dense CTS1 admission before sealing.

use std::{
    collections::BTreeMap,
    error::Error,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::{
        fd::OwnedFd,
        unix::{
            fs::{OpenOptionsExt, PermissionsExt},
            net::UnixStream,
        },
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::AtomicBool,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

mod bep52;
mod paged;
mod snapshot;

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use trnm_crypto_primitives::pq_auth::PqNativeSigningKey;
use trnm_data_availability::cell::{pq::*, *};
use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
const BOOTSTRAP: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../scripts/cell_sealed_bootstrap_v1.py"
));
const WORKER: &str = "scripts/llm_cell_sealed_worker_v1.py";
const SNAPSHOT: &str = "runtime/runtime-snapshot.json";
const SNAPSHOT_BOUND: u64 = 512 * 1024 * 1024;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    path: PathBuf,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    family: String,
    base: String,
    parent: String,
    tokenizer: String,
    layout: String,
    runtime: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    operation: String,
    context: Context,
    environment_generation: u64,
    network: bep52::Network,
    snapshot: snapshot::SnapshotSpec,
    model: BTreeMap<String, Input>,
    environment: BTreeMap<String, Input>,
    python: Input,
    output: PathBuf,
    seconds: u64,
    max_snapshot_bytes: u64,
    runtime_rss_bytes: u64,
    threads: u32,
    material_profile: String,
    parent: CellHostResearchParentV1,
    requests: Vec<CellHostResearchQueryV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PagedExpected {
    previous_operation: String,
    tcv1: String,
    tcv2: String,
    cts1: String,
    bep52_plan: String,
    payload_bytes: u64,
    manifest_count: usize,
    chunks: u64,
}

impl PagedExpected {
    fn validate(&self) -> Result<()> {
        check(
            digest(&self.previous_operation)? != [0; 32],
            "original operation pin required",
        )?;
        for pin in [&self.tcv1, &self.tcv2, &self.cts1, &self.bep52_plan] {
            check(
                pin.len() == 128
                    && pin
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "canonical independent complete-version pin",
            )?;
        }
        check(
            (1..=SNAPSHOT_BOUND).contains(&self.payload_bytes)
                && (1..=128).contains(&self.manifest_count)
                && (1..=2048).contains(&self.chunks),
            "bounded independent complete-version scope",
        )
    }
    fn verify(
        &self,
        version: &CellVersionManifestV1,
        content: &CellVersionContentV2,
        snapshot: &CellReleaseSnapshotV1,
        total: u64,
    ) -> Result<()> {
        self.validate()?;
        let chunks: u64 = version
            .manifests()
            .iter()
            .map(|m| m.chunks().len() as u64)
            .sum();
        check(
            self.tcv1 == hex::encode(version.commitment())
                && self.tcv2 == hex::encode(content.commitment())
                && self.cts1 == hex::encode(snapshot.commitment())
                && self.payload_bytes == total
                && self.manifest_count == version.manifests().len()
                && self.chunks == chunks,
            "original independently pinned version/content/snapshot must remain exact",
        )
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(
    dead_code,
    reason = "Shared module supports separately selected copy and paged example entry points."
)]
struct PagedSpec {
    schema: String,
    source: Spec,
    custody: paged::Profile,
    expected: PagedExpected,
}
#[allow(
    dead_code,
    reason = "Shared module supports separately selected copy and paged example entry points."
)]
impl PagedSpec {
    fn validate(&self) -> Result<()> {
        check(
            self.schema == "trnm.cell-sealed-paged-research-source.v1"
                && self.source.schema == "trnm.cell-sealed-research-source.v2",
            "explicit fresh paged research source required",
        )?;
        self.custody.validate()?;
        self.expected.validate()?;
        check(
            digest(&self.source.operation)? != [0; 32]
                && self.source.operation != self.expected.previous_operation,
            "fresh paged research operation must differ from original one-shot",
        )
    }
}

fn check(value: bool, reason: &'static str) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(reason.into())
    }
}

fn digest(value: &str) -> Result<[u8; 32]> {
    check(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "canonical independent SHA-256 pin required",
    )?;
    Ok(hex::decode(value)?
        .try_into()
        .map_err(|_| "digest length")?)
}

fn id(operation: &[u8; 32], domain: &[u8], extra: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"TRNM/Cell/SealedResearchOperation/v2\0");
    hash.update(operation);
    hash.update((domain.len() as u32).to_be_bytes());
    hash.update(domain);
    hash.update(extra);
    hash.finalize().into()
}

fn read_pinned(input: &Input, maximum: u64) -> Result<Vec<u8>> {
    check(
        input.path.is_absolute(),
        "independent input path must be absolute",
    )?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&input.path)?;
    let before = file.metadata()?;
    check(
        before.is_file() && before.len() > 0 && before.len() <= maximum,
        "bounded regular input required",
    )?;
    let mut raw = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut raw)?;
    check(
        raw.len() as u64 == before.len()
            && file.metadata()?.len() == before.len()
            && <[u8; 32]>::from(Sha256::digest(&raw)) == digest(&input.sha256)?,
        "independent input bytes changed",
    )?;
    Ok(raw)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn read_observation(path: &Path) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let info = file.metadata()?;
    check(
        info.is_file() && info.len() > 0 && info.len() <= 131072,
        "bounded original observation",
    )?;
    let mut raw = Vec::new();
    Read::by_ref(&mut file).take(131073).read_to_end(&mut raw)?;
    check(
        raw.len() as u64 == info.len(),
        "original observation length",
    )?;
    Ok(raw)
}

fn cache(path: &Path) -> Result<CellStoreV1> {
    Ok(CellStoreV1::open(
        path,
        CellCacheConfigV4 {
            max_database_bytes: 1024 * 1024 * 1024,
            max_logical_bytes: SNAPSHOT_BOUND,
            max_chunk_rows: 2048,
            max_manifest_rows: 128,
        },
    )?)
}

fn owner(
    closure: &CellReleaseClosureV1,
    roles: Vec<CellFileRoleV1>,
    maximum: u64,
) -> CellLoaderContextV1 {
    CellLoaderContextV1 {
        closure_id: closure.id(),
        context: closure.release().context().clone(),
        selected_generation: closure.selected_generation(),
        loader_profile: closure.loader_profile(),
        required_roles: roles,
        max_payload_bytes: maximum,
        max_chunks: 2048,
    }
}

fn session(deadline: Instant, maximum: u64) -> Result<CellContentReadSessionV2> {
    Ok(CellContentReadSessionV2::new(
        CellReleaseLimitsV1 {
            max_payload_bytes: maximum,
            max_chunks: 2048,
            deadline,
        },
        1,
    )?)
}

fn pack(
    store: &CellStoreV1,
    inputs: &BTreeMap<String, Input>,
    context: &CellContextV1,
    environment: bool,
    deadline: Instant,
) -> Result<(Vec<CellManifestV1>, Vec<CellClosureFileV1>)> {
    let mut manifests = Vec::new();
    let mut files = Vec::new();
    for (path, input) in inputs {
        check(Instant::now() < deadline, "original research deadline")?;
        check(input.path.is_absolute(), "absolute original payload source")?;
        let mut source = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&input.path)?;
        let info = source.metadata()?;
        check(
            info.is_file() && info.len() > 0 && info.len() <= SNAPSHOT_BOUND,
            "bounded original payload source",
        )?;
        // Capture from one original regular FD with the caller's deadline
        // checked at each bounded chunk. Only these same captured bytes
        // enter the original CAS; no later mutable source reopen is used.
        let chunk_bytes = MAX_CHUNK_BYTES as usize;
        let mut buffer = vec![0; chunk_bytes];
        let mut remaining = info.len();
        let mut full = Sha256::new();
        let mut chunks = Vec::new();
        while remaining > 0 {
            check(
                Instant::now() < deadline,
                "original payload capture deadline",
            )?;
            let size = remaining.min(chunk_bytes as u64) as usize;
            source.read_exact(&mut buffer[..size])?;
            check(Instant::now() < deadline, "original payload read deadline")?;
            let chunk = CellChunkV1 {
                size: size as u32,
                sha256: Sha256::digest(&buffer[..size]).into(),
            };
            store.put_chunk(&chunk, &buffer[..size])?;
            full.update(&buffer[..size]);
            chunks.push(chunk);
            remaining -= size as u64;
        }
        check(
            source.read(&mut [0; 1])? == 0 && source.metadata()?.len() == info.len(),
            "original payload length changed",
        )?;
        // Enter through the public canonical decoder, which retains the
        // manifest owner's complete validation. The path-only pack_file
        // API cannot preserve this already-open FD and chunk deadline.
        context.validate()?;
        let payload_sha256: [u8; 32] = full.finalize().into();
        let mut wire = Vec::new();
        wire.extend_from_slice(b"TCM1");
        wire.push(u8::try_from(context.family.len())?);
        wire.extend_from_slice(context.family.as_bytes());
        for value in [
            context.base,
            context.parent,
            context.tokenizer,
            context.layout,
            context.runtime,
        ] {
            wire.extend_from_slice(&value);
        }
        wire.extend_from_slice(&info.len().to_be_bytes());
        wire.extend_from_slice(&payload_sha256);
        wire.extend_from_slice(&(chunk_bytes as u32).to_be_bytes());
        wire.extend_from_slice(&u32::try_from(chunks.len())?.to_be_bytes());
        for chunk in chunks {
            wire.extend_from_slice(&chunk.size.to_be_bytes());
            wire.extend_from_slice(&chunk.sha256);
        }
        let manifest = CellManifestV1::decode(&wire)?;
        check(manifest.encode() == wire, "canonical captured manifest")?;
        check(
            manifest.payload_sha256() == digest(&input.sha256)?,
            "packed input differs from independent pin",
        )?;
        check(
            Instant::now() < deadline,
            "original payload final capture deadline",
        )?;
        store.put_manifest(manifest.id(), &manifest.encode())?;
        let role = if environment {
            CellFileRoleV1::Configuration
        } else if path == "base/model.safetensors" {
            CellFileRoleV1::Base
        } else if path.starts_with("base/tokenizer") || path == "base/special_tokens_map.json" {
            CellFileRoleV1::Tokenizer
        } else if path == "adapter/artifact.safetensors" {
            CellFileRoleV1::Adapter
        } else {
            CellFileRoleV1::Configuration
        };
        files.push(CellClosureFileV1 {
            path: path.clone(),
            role,
            manifest: manifest.id(),
            payload_sha256: manifest.payload_sha256(),
            payload_bytes: manifest.size(),
            dependencies: vec![],
        });
        manifests.push(manifest);
    }
    Ok((manifests, files))
}

/// Research-only replacement for the retained-byte stage. It consumes this
/// operation's two new caches, keeps the original absolute deadline and returns
/// the cold consumer readback used by the same complete CTS1 selection and
/// sealed-worker path. This grants neither storage nor execution authority.
#[allow(
    dead_code,
    reason = "Shared source also supports the separately selected Node/M12 research entry."
)]
pub struct CellResearchRetentionInputsV2<'a> {
    pub operation: [u8; 32],
    pub output: &'a Path,
    pub deadline: Instant,
    pub version: &'a CellVersionManifestV1,
    pub snapshot: &'a CellReleaseSnapshotV1,
    pub content: &'a CellVersionContentV2,
    pub model_owner: &'a CellLoaderContextV1,
    pub environment_owner: &'a CellLoaderContextV1,
    pub source: CellStoreV1,
    pub source_path: &'a Path,
    pub received: CellStoreV1,
    pub received_path: &'a Path,
}

type RetentionCallbackV2 =
    for<'a> fn(CellResearchRetentionInputsV2<'a>, &mut Value) -> Result<CellStoreV1>;

/// The original paged contract and the explicit native callback are different
/// research routes. One operation must not execute both retention owners.
#[derive(Clone, Copy)]
enum ResearchCustodyRouteV2<'a> {
    Copy,
    Paged(&'a paged::Profile, &'a PagedExpected),
    Native(RetentionCallbackV2),
}

fn observe_with_custody(
    spec: &Spec,
    report: &mut Value,
    route: ResearchCustodyRouteV2<'_>,
) -> Result<()> {
    let paged_route = match route {
        ResearchCustodyRouteV2::Paged(profile, expected) => Some((profile, expected)),
        ResearchCustodyRouteV2::Copy | ResearchCustodyRouteV2::Native(_) => None,
    };
    check(
        (1..=300).contains(&spec.seconds),
        "original bounded research duration",
    )?;
    let started = Instant::now();
    let deadline = started + Duration::from_secs(spec.seconds);
    report["latency_observation_v1"] = json!({
        "clock": "std::time::Instant monotonic wall clock",
        "origin": "custody observation entry after input-file read/parse and fresh output setup; before source checks, packing and transport",
        "values_are_cumulative_not_additive": true,
        "pinned_snapshot_ready_ns": null, "transport_complete_ns": null,
        "cold_recovery_complete_ns": null, "selected_typed_release_ready_ns": null,
        "sealed_model_environment_ready_ns": null, "two_forward_receipt_ns": null,
        "first_use_scope": "complete CTS1/TCV1 selected and admitted for typed local byte use; not first token or first model output",
        "loopback_only": true, "wan_qualified": false
    });
    let cancelled = AtomicBool::new(false);
    let operation = digest(&spec.operation)?;
    check(
        spec.schema == "trnm.cell-sealed-research-source.v2"
            && operation != [0; 32]
            && (1..=300).contains(&spec.seconds)
            && (1..=SNAPSHOT_BOUND).contains(&spec.max_snapshot_bytes)
            && (1..=8 * 1024_u64.pow(3)).contains(&spec.runtime_rss_bytes)
            && (1..=4).contains(&spec.threads)
            && spec.model.len() == 11
            && spec.environment.len() <= 32
            && spec.environment_generation > 0,
        "fresh research profile and finite original bounds",
    )?;
    spec.network.validate()?;
    spec.snapshot.validate()?;
    check(
        spec.snapshot.material_profile == spec.material_profile,
        "snapshot and actual worker material profile must agree",
    )?;
    let worker_input = spec
        .environment
        .get(WORKER)
        .ok_or("complete sealed worker absent")?;
    check(
        read_pinned(
            spec.environment
                .get("scripts/cell_sealed_bootstrap_v1.py")
                .ok_or("bootstrap absent")?,
            2 * 1024 * 1024,
        )? == BOOTSTRAP.as_bytes(),
        "compiled bootstrap does not match admitted environment",
    )?;
    let context = CellContextV1 {
        family: spec.context.family.clone(),
        base: digest(&spec.context.base)?,
        parent: digest(&spec.context.parent)?,
        tokenizer: digest(&spec.context.tokenizer)?,
        layout: digest(&spec.context.layout)?,
        runtime: digest(&spec.context.runtime)?,
    };
    check(
        context.runtime == digest(&worker_input.sha256)?
            && context.runtime == digest(&spec.snapshot.worker_sha256)?,
        "worker context pin",
    )?;
    context.validate()?;
    read_pinned(&spec.python, 512 * 1024 * 1024)?;
    report["stage"] = json!("pack independently pinned actual sources");
    let source_path = spec.output.join("publisher.sqlite");
    let source = cache(&source_path)?;
    let (environment_manifests, environment_files) =
        pack(&source, &spec.environment, &context, true, deadline)?;
    let environment = CellReleaseClosureV1::new(
        context.clone(),
        spec.environment_generation,
        spec.snapshot.environment_loader_profile()?,
        (0..environment_files.len() as u16).collect(),
        environment_files,
    )?;
    let mut model_context = context.clone();
    model_context.runtime = environment.id();
    let (model_manifests, mut model_files) =
        pack(&source, &spec.model, &model_context, false, deadline)?;
    check(
        model_files
            .first()
            .is_some_and(|f| f.path == "adapter/artifact.safetensors"),
        "complete model root",
    )?;
    model_files[0].dependencies = (1..model_files.len() as u16).collect();
    let model = CellModelReleaseRootV1::new(
        CellReleaseClosureV1::new(
            model_context,
            spec.parent.generation,
            spec.snapshot.model_loader_profile()?,
            vec![0],
            model_files,
        )?,
        vec![],
    )?;
    let model_owner = owner(
        model.closure(),
        vec![
            CellFileRoleV1::Base,
            CellFileRoleV1::Tokenizer,
            CellFileRoleV1::Adapter,
            CellFileRoleV1::Configuration,
        ],
        spec.max_snapshot_bytes,
    );
    let environment_owner = owner(
        &environment,
        vec![CellFileRoleV1::Configuration],
        spec.max_snapshot_bytes,
    );
    let mut manifests = model_manifests;
    manifests.extend(environment_manifests);
    manifests.sort_by_key(CellManifestV1::id);
    let version = CellVersionManifestV1::new(model, environment, manifests)?;
    let owner_view = CellVersionLoaderContextV1 {
        commitment: version.commitment(),
        model: &model_owner,
        environment: &environment_owner,
    };
    let total: u64 = version.manifests().iter().map(CellManifestV1::size).sum();
    check(
        total <= spec.max_snapshot_bytes,
        "complete-version original memory allowance",
    )?;
    let content = CellVersionContentV2::capture_cached(
        &version,
        &source,
        &owner_view,
        &mut session(deadline, spec.max_snapshot_bytes)?,
    )?;
    report["input"] = json!({"payload_bytes": total, "manifest_count": version.manifests().len(),
        "tcv1": hex::encode(version.commitment()), "tcv2": hex::encode(content.commitment()),
        "independent_input_pins": true});

    let release_snapshot = snapshot::capture(&source, &version, &spec.snapshot, deadline)?;
    let snapshot_context = CellReleaseSnapshotLoaderContextV1 {
        snapshot: release_snapshot.commitment(),
        composition_profile: release_snapshot.composition_profile(),
        version: CellVersionLoaderContextV1 {
            commitment: version.commitment(),
            model: &model_owner,
            environment: &environment_owner,
        },
    };
    write_new(
        &spec.output.join("owner-release-snapshot.cts1"),
        &release_snapshot.encode(),
    )?;
    report["snapshot"] = json!({
        "cts1": hex::encode(release_snapshot.commitment()),
        "tma1": hex::encode(release_snapshot.tensors().id()),
        "composition_file": spec.snapshot.composition_file,
        "composition_profile": spec.snapshot.composition_profile,
        "typed_snapshot_admitted": false,
        "composition_worker_executed": false,
        "compatibility_from_hashes_alone": false,
    });
    if let Some((_, expected)) = paged_route {
        expected.verify(&version, &content, &release_snapshot, total)?;
        report["original_version_pins_verified"] = json!(true);
        report["expected_version"] = json!({
            "previous_operation": expected.previous_operation, "tcv1": expected.tcv1,
            "tcv2": expected.tcv2, "cts1": expected.cts1, "bep52_plan": expected.bep52_plan,
            "payload_bytes": expected.payload_bytes, "manifest_count": expected.manifest_count,
            "chunks": expected.chunks,
        });
    }
    report["latency_observation_v1"]["pinned_snapshot_ready_ns"] =
        json!(started.elapsed().as_nanos());
    report["stage"] = json!("complete pinned release over actual loopback TCP");
    let received_path = spec.output.join("bep52-received.sqlite");
    let received = cache(&received_path)?;
    let transport_plan = bep52::transfer(
        bep52::Transfer {
            source: &source,
            source_path: &source_path,
            received: &received,
            version: &version,
            owner: &owner_view,
            operation,
            deadline,
            output: &spec.output,
            network: &spec.network,
        },
        report,
    )?;

    if let Some((_, expected)) = paged_route {
        check(
            expected.bep52_plan == hex::encode(transport_plan),
            "original independently pinned BEP52 plan must remain exact",
        )?;
        report["original_transport_plan_verified"] = json!(true);
    }
    report["operation_pins"] = json!({
        "operation": hex::encode(operation),
        "tcv1": hex::encode(version.commitment()),
        "tcv2": hex::encode(content.commitment()),
        "cts1": hex::encode(release_snapshot.commitment()),
        "bep52_plan": hex::encode(transport_plan),
    });
    report["latency_observation_v1"]["transport_complete_ns"] = json!(started.elapsed().as_nanos());
    let consumer = if let ResearchCustodyRouteV2::Native(retention) = route {
        retention(
            CellResearchRetentionInputsV2 {
                operation,
                output: &spec.output,
                deadline,
                version: &version,
                snapshot: &release_snapshot,
                content: &content,
                model_owner: &model_owner,
                environment_owner: &environment_owner,
                source,
                source_path: &source_path,
                received,
                received_path: &received_path,
            },
            report,
        )?
    } else {
        report["stage"] = json!("original TCA3 complete physical retention");
        let config = CellVersionRetentionConfigV3 {
            retention: CellRetentionConfigV1 {
                store_id: id(&operation, b"store", &[]),
                capacity_bytes: SNAPSHOT_BOUND,
                maximum_obligations: 128,
            },
            maximum_versions: 16,
            maximum_metadata_bytes: 64 << 20,
        };
        let contract = CellVersionRetentionContractV3 {
            operation,
            funding_operation: id(&operation, b"declared-local-funding", &[]),
            responsible_owner: id(&operation, b"local-research-owner", &[]),
            failure_domain: id(&operation, b"single-host-domain", &[]),
            replica_index: 0,
            required_replicas: 1,
            retain_from_height: 1,
            retain_until_height: 100,
            repair_deadline_height: 90,
            version: version.clone(),
            model: CellVersionLoaderPinV3::from_context(&model_owner),
            environment: CellVersionLoaderPinV3::from_context(&environment_owner),
            tensor_model: Some(release_snapshot.tensors().clone()),
            snapshot: None,
            objects: version
                .manifests()
                .iter()
                .map(|m| CellRetentionContractV1 {
                    operation: id(&operation, b"object", &m.id()),
                    funding_operation: id(&operation, b"object-funding", &m.id()),
                    manifest: m.clone(),
                    retain_from_height: 1,
                    retain_until_height: 100,
                    maximum_repair_bytes: m.size(),
                    successor: None,
                })
                .collect(),
        };
        let archive_path = spec.output.join("retained");
        let mut archive = CellVersionRetentionStoreV3::create(&archive_path, config.clone())?;
        archive.reserve_version(contract, archive.anchor(deadline)?, deadline)?;
        archive.acknowledge_version(operation, &received, deadline)?;
        let anchor = archive.anchor(deadline)?;
        write_new(
            &spec.output.join("independent-catalog-anchor.cva3"),
            &anchor.encode(),
        )?;
        if let Some((profile, _)) = paged_route {
            paged::restore(
                paged::Restore {
                    source,
                    received,
                    archive,
                    config,
                    anchor,
                    version: &version,
                    content: &content,
                    owner: &owner_view,
                    source_path: &source_path,
                    received_path: &received_path,
                    archive_path: &archive_path,
                    output: &spec.output,
                    operation,
                    deadline,
                    started,
                    cancelled: &cancelled,
                },
                profile,
                report,
            )?
        } else {
            drop(archive);
            drop(source);
            drop(received);
            remove_cache(&source_path)?;
            remove_cache(&received_path)?;
            report["stage"] = json!("reopen anchored owner and actual cold arena restore");
            let mut archive = CellVersionRetentionStoreV3::open(&archive_path, config, anchor)?;
            let consumer = cache(&spec.output.join("consumer.sqlite"))?;
            check(
                consumer.cache_usage()?.chunk_rows == 0,
                "consumer must be actually cold",
            )?;
            archive.populate_cache(operation, &consumer, deadline)?;
            report["cold_restore"] = json!({"source_cache_absent": !source_path.exists(),
            "bep52_cache_absent": !received_path.exists(),
            "retained_from_bep52_received_cache": true,
            "anchored_reopen": true, "actual_target_readback": true,
            "consumer_chunks": consumer.cache_usage()?.chunk_rows,
            "m12_funding_admitted": false, "retention_heights_are_research_terms": true});

            consumer
        }
    };

    report["latency_observation_v1"]["cold_recovery_complete_ns"] =
        json!(started.elapsed().as_nanos());
    report["stage"] = json!("actual CPV4 consumer verification and joint residency");
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut seed = Zeroizing::new([0_u8; 32]);
    getrandom::getrandom(seed.as_mut()).map_err(|_| "research key generation failed")?;
    let spki = PqNativeSigningKey::public_spki_from_seed(&seed);
    let key_id = ml_dsa_65_key_id_from_spki(&spki).map_err(|_| "research SPKI")?;
    let key = PqNativeSigningKey::from_owned_seed(seed, key_id)?;
    let key_pin = CellPqKeyPinV2 {
        key_id,
        generation: 1,
        spki,
        not_before: timestamp.saturating_sub(1),
        expires_at: timestamp + 300,
        revoked_at: None,
    };
    let authorization = CellPqContentAuthorizationV4::sign(
        CellPqContentStatementV4 {
            network: id(&operation, b"research-network", &[]),
            parameters: id(&operation, b"research-parameters", &[]),
            content: content.commitment(),
            signer_key_id: key_pin.key_id,
            signer_spki_sha512: CellPqContentStatementV4::signer_commitment(&key_pin.spki),
            generation: 1,
            sequence: 1,
            issued_at: timestamp,
            expires_at: timestamp + 300,
            withdrawn: false,
        },
        &key,
    )?;
    let expected = CellPqContentExpectationV4 {
        authority: CellPqReleaseExpectationV2 {
            network: id(&operation, b"research-network", &[]),
            parameters: id(&operation, b"research-parameters", &[]),
            key: &key_pin,
            sequence: 1,
            now: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        },
        loader: owner_view,
        content: content.commitment(),
    };
    let mut read_session = session(deadline, spec.max_snapshot_bytes)?;
    let verified =
        authorization.verify_cached_at(&content, &consumer, &expected, &mut read_session)?;
    let limits = CellResidencyConfigV1 {
        max_resident_bytes: spec.max_snapshot_bytes,
        max_resident_closures: 2,
        max_chunk_references: 2048,
    };
    let mut pool = CellResidencyV1::new(limits)?;
    for (closure, owner) in [
        (version.model().closure(), &model_owner),
        (version.environment(), &environment_owner),
    ] {
        pool.prepare_cached(&consumer, closure, owner, deadline, &cancelled)?;
    }
    // Both closures must be admitted together under the same finite RAM
    // owner before creating any process-visible snapshot.
    let selected = pool.select_local_release_snapshot(
        None,
        operation,
        &release_snapshot,
        &snapshot_context,
        limits,
        deadline,
        &cancelled,
    )?;
    let admitted = pool.admit_selected_local_release_snapshot(
        selected,
        operation,
        &release_snapshot,
        &snapshot_context,
        limits,
        deadline,
        &cancelled,
    )?;
    admitted.with_local(operation, &snapshot_context, |_| ())?;
    report["snapshot"]["complete_local_selection"] = json!({
        "revision": selected.revision(), "cts1": hex::encode(selected.snapshot()),
        "tcv1": hex::encode(selected.version()), "durable_current": false,
        "execution_authorized": false
    });
    report["latency_observation_v1"]["selected_typed_release_ready_ns"] =
        json!(started.elapsed().as_nanos());
    report["snapshot"]["typed_snapshot_admitted"] = json!(true);
    report["typed_snapshot_admitted"] = json!(true);
    let seal_limits = CellSealedLoaderLimitsV1 {
        max_snapshot_bytes: spec.max_snapshot_bytes,
        max_files: 64,
    };
    let model_bundle =
        pool.seal_declared_loader(&model_owner, seal_limits, deadline, &cancelled)?;
    let environment_bundle =
        pool.seal_declared_loader(&environment_owner, seal_limits, deadline, &cancelled)?;
    admitted.with_local(operation, &snapshot_context, |_| ())?;
    drop(admitted);
    report["latency_observation_v1"]["sealed_model_environment_ready_ns"] =
        json!(started.elapsed().as_nanos());
    let descriptor = CellHostHandoffDescriptorV1 {
        operation,
        owner_generation: 1,
        content: content.commitment(),
        version: version.commitment(),
        model_closure: version.model().closure().id(),
        environment_closure: version.environment().id(),
        model_generation: spec.parent.generation,
        environment_generation: spec.environment_generation,
        worker_context: context,
        worker_path: WORKER.into(),
        runtime_snapshot_path: SNAPSHOT.into(),
        runtime_snapshot_sha256: digest(
            &spec
                .environment
                .get(SNAPSHOT)
                .ok_or("runtime snapshot absent")?
                .sha256,
        )?,
    };
    let descriptor_pin = descriptor.commitment()?;
    report["operation_pins"]["chb1"] = json!(hex::encode(descriptor_pin));
    let handoff = descriptor.bind_authenticated(
        descriptor_pin,
        &verified,
        &expected,
        (&model_bundle, &environment_bundle),
        deadline,
    )?;
    write_new(
        &spec.output.join("owner-handoff.chb1"),
        &descriptor.encode()?,
    )?;
    write_new(&spec.output.join("owner-content.tcv2"), &content.encode())?;
    write_new(
        &spec.output.join("owner-authorization.cpv4"),
        &authorization.encode()?,
    )?;
    // The two actual task reads must remain possible without either local
    // cache pathname. Only this operation's newly created cache is removed;
    // the original input materials and retained owner remain untouched.
    drop(consumer);
    let consumer_path = spec.output.join("consumer.sqlite");
    fs::remove_file(&consumer_path)?;
    for extension in ["sqlite-wal", "sqlite-shm"] {
        let path = consumer_path.with_extension(extension);
        if path.exists() {
            fs::remove_file(path)?;
        }
    }
    report["sealed_cache_independence"] = json!({
        "publisher_cache_absent": !source_path.exists(),
        "bep52_cache_absent": !received_path.exists(),
        "consumer_cache_absent": !consumer_path.exists(),
        "original_source_materials_preserved": true,
    });
    let execution = CellHostResearchExecutionV1 {
        schema: "trnm.cell-sealed-research-execution.v1".into(),
        operation: spec.operation.clone(),
        descriptor: hex::encode(descriptor_pin),
        environment_pins: spec
            .environment
            .iter()
            .map(|(path, input)| (path.clone(), input.sha256.clone()))
            .collect(),
        max_snapshot_bytes: spec.max_snapshot_bytes,
        runtime_rss_bytes: spec.runtime_rss_bytes,
        python: spec.python.path.to_str().ok_or("Python path UTF-8")?.into(),
        python_sha256: spec.python.sha256.clone(),
        output: spec.output.to_str().ok_or("output path UTF-8")?.into(),
        threads: spec.threads,
        material_profile: spec.material_profile.clone(),
        parent: spec.parent.clone(),
        requests: spec.requests.clone(),
    };
    write_new(
        &spec.output.join("independent-execution-inputs.json"),
        &serde_json::to_vec_pretty(&execution)?,
    )?;
    report["handoff"] = json!({"descriptor": hex::encode(descriptor_pin),
        "worker_sha256": worker_input.sha256, "model_bytes": model_bundle.snapshot_bytes(),
        "environment_bytes": environment_bundle.snapshot_bytes(),
        "kernel_descriptors": model_bundle.file_count() + environment_bundle.file_count(),
        "signer_key_id": hex::encode(key_id), "single_operator_research_key": true});

    report["stage"] = json!("original wait4 owner and two actual sealed-byte forwards");
    check(Instant::now() < deadline, "original process start deadline")?;
    let (mut producer, receiver) = UnixStream::pair()?;
    let receiver: OwnedFd = receiver.into();
    let stdout = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(spec.output.join("supervisor.stdout"))?;
    let stderr = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(spec.output.join("supervisor.stderr"))?;
    let temporary = spec.output.join("python-tmp");
    fs::create_dir(&temporary)?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o700))?;
    let bootstrap_sha = hex::encode(Sha256::digest(BOOTSTRAP.as_bytes()));
    // The only executed bootstrap is the exact source embedded in this
    // binary and compared above with its independently pinned sealed member.
    let mut child = Command::new(&spec.python.path)
        .args(["-I", "-S", "-B", "-X"])
        .arg(format!(
            "pycache_prefix={}",
            spec.output.join("unused-supervisor-bytecode").display()
        ))
        .args(["-c", BOOTSTRAP])
        .arg(hex::encode(descriptor_pin))
        .arg(&worker_input.sha256)
        .args(["supervisor", "stdin"])
        .arg(&bootstrap_sha)
        .env_clear()
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "C.UTF-8")
        .env("TMPDIR", &temporary)
        .stdin(Stdio::from(receiver))
        .stdout(stdout)
        .stderr(stderr)
        .spawn()?;
    report["actual_model_run"] = json!("started_without_complete_receipt");
    let handed = handoff.send_research_fds_v1(&mut producer, &execution, deadline, &cancelled);
    drop(producer);
    let mut terminated = false;
    let mut termination_error = None;
    if handed.is_err() {
        if let Err(error) = rustix::process::kill_process(
            rustix::process::Pid::from_child(&child),
            rustix::process::Signal::TERM,
        ) {
            termination_error = Some(error.to_string());
        }
        terminated = true;
    }
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline && !terminated {
            // TERM invokes the original cooperative supervisor, which owns
            // termination and the exact wait4 of its child. We retain all
            // sealed data until that owner has itself exited. No refund or
            // successful-use receipt is emitted while cleanup is pending.
            if let Err(error) = rustix::process::kill_process(
                rustix::process::Pid::from_child(&child),
                rustix::process::Signal::TERM,
            ) {
                termination_error = Some(error.to_string());
            }
            terminated = true;
        }
        thread::sleep(Duration::from_millis(20));
    };
    report["process"] = json!({"exit_code": status.code(), "termination_requested": terminated,
        "termination_error": termination_error,
        "elapsed_ms": started.elapsed().as_millis(), "original_seconds": spec.seconds,
        "sealed_bundles_held_until_supervisor_exit": true});
    handed?;
    check(
        status.success() && !terminated && Instant::now() < deadline,
        "actual research worker or original deadline failed; retain raw observations",
    )?;
    let final_result: Value = serde_json::from_slice(&read_observation(
        &spec.output.join("next-use-result.json"),
    )?)?;
    check(
        final_result["observations"] == 2
            && final_result["connector_complete"] == true
            && final_result["failures"]
                .as_array()
                .is_some_and(Vec::is_empty)
            && final_result["supervisor"]["outcome"] == "success"
            && final_result["supervisor"]["waited_child_reaped"] == true,
        "original wait4 and two fresh actual forward receipts required",
    )?;
    report["latency_observation_v1"]["two_forward_receipt_ns"] =
        json!(started.elapsed().as_nanos());
    report["stage"] = json!("complete research next-use");
    report["actual_next_use"] = final_result;
    report["snapshot"]["composition_worker_executed"] = json!(true);
    report["actual_model_run"] = json!("observed_two_forwards");
    report["composition_worker_executed"] = json!(true);
    check(
        Instant::now() < deadline,
        "original final observation deadline",
    )?;
    Ok(())
}

fn run_source(retention: Option<RetentionCallbackV2>) -> Result<()> {
    let arguments: Vec<_> = std::env::args().collect();
    check(
        arguments.len() == 3,
        "usage: cell_sealed_research_next_use_v2 SOURCE_JSON INDEPENDENT_SHA256",
    )?;
    let raw = read_pinned(
        &Input {
            path: PathBuf::from(&arguments[1]),
            sha256: arguments[2].clone(),
        },
        128 * 1024,
    )?;
    let spec: Spec = serde_json::from_slice(&raw)?;
    check(
        spec.output.is_absolute(),
        "absolute create-only output required",
    )?;
    fs::create_dir(&spec.output)?;
    fs::set_permissions(&spec.output, fs::Permissions::from_mode(0o700))?;
    write_new(&spec.output.join("original-source-inputs.json"), &raw)?;
    let mut report = json!({"schema": "trnm.cell-sealed-research-native.v2", "stage": "initial",
        "source_input_sha256": arguments[2], "original_hepta_owner_used": false,
        "hepta_final_use": false, "installation_authorized": false, "m12_funding_admitted": false,
        "independent_operators": false, "production_activation": false,
        "loopback_only": true, "typed_snapshot_admitted": false,
        "composition_worker_executed": false,
        "actual_model_run": "not_started"});
    let route = match retention {
        Some(retention) => ResearchCustodyRouteV2::Native(retention),
        None => ResearchCustodyRouteV2::Copy,
    };
    let result = observe_with_custody(&spec, &mut report, route);
    report["passed"] = json!(result.is_ok());
    if let Err(error) = &result {
        report["error"] = json!(error.to_string());
    }
    write_new(
        &spec.output.join("native-result.json"),
        &serde_json::to_vec_pretty(&report)?,
    )?;
    println!("{}", serde_json::to_string(&report)?);
    result
}

/// Preserve the original V2 complete-copy entry and every original bound.
pub fn run() -> Result<()> {
    run_source(None)
}

/// Explicit Node/M12 research entry. It accepts the original independently
/// pinned V2 source input, never the different paged-source wrapper. Callback
/// completion still requires the original content verification, complete
/// selection, sealed bytes and actual two-forward receipt below.
#[allow(
    dead_code,
    reason = "Shared source also supports the separately selected Node/M12 research entry."
)]
pub fn run_with_retention(retention: RetentionCallbackV2) -> Result<()> {
    run_source(Some(retention))
}

#[allow(
    dead_code,
    reason = "Shared module supports separately selected copy and paged example entry points."
)]
pub fn run_paged() -> Result<()> {
    let arguments: Vec<_> = std::env::args().collect();
    check(
        arguments.len() == 3,
        "usage: cell_sealed_research_paged_next_use_v1 SOURCE_JSON INDEPENDENT_SHA256",
    )?;
    let raw = read_pinned(
        &Input {
            path: PathBuf::from(&arguments[1]),
            sha256: arguments[2].clone(),
        },
        128 * 1024,
    )?;
    let input: PagedSpec = serde_json::from_slice(&raw)?;
    input.validate()?;
    let spec = &input.source;
    check(
        spec.output.is_absolute(),
        "absolute create-only output required",
    )?;
    fs::create_dir(&spec.output)?;
    fs::set_permissions(&spec.output, fs::Permissions::from_mode(0o700))?;
    write_new(&spec.output.join("original-paged-source-inputs.json"), &raw)?;
    let mut report = json!({
        "schema": "trnm.cell-sealed-paged-research-native.v1", "stage": "initial",
        "source_input_sha256": arguments[2], "storage_profile": "trnm.cell-sealed-paged-custody.v1",
        "original_hepta_owner_used": false, "hepta_final_use": false,
        "installation_authorized": false, "m12_funding_admitted": false,
        "independent_operators": false, "production_activation": false,
        "loopback_only": true, "typed_snapshot_admitted": false,
        "composition_worker_executed": false, "actual_model_run": "not_started",
        "original_version_pins_verified": false, "original_transport_plan_verified": false,
        "original_seconds": spec.seconds, "snapshot_payload_limit": spec.max_snapshot_bytes,
        "worker_rss_limit": spec.runtime_rss_bytes, "threads": spec.threads,
    });
    let started = Instant::now();
    let result = observe_with_custody(
        spec,
        &mut report,
        ResearchCustodyRouteV2::Paged(&input.custody, &input.expected),
    );
    report["entry_elapsed_ms"] = json!(started.elapsed().as_millis());
    report["passed"] = json!(result.is_ok());
    if let Err(error) = &result {
        report["error"] = json!(error.to_string());
    }
    write_new(
        &spec.output.join("native-result.json"),
        &serde_json::to_vec_pretty(&report)?,
    )?;
    println!("{}", serde_json::to_string(&report)?);
    result
}

fn remove_cache(path: &Path) -> Result<()> {
    fs::remove_file(path)?;
    for extension in ["sqlite-wal", "sqlite-shm"] {
        let sidecar = path.with_extension(extension);
        if sidecar.exists() {
            fs::remove_file(sidecar)?;
        }
    }
    Ok(())
}
