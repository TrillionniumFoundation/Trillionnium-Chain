//! CHB1 data transfer to an independently admitted local research process.
//!
//! SCM_RIGHTS retains the original immutable objects. This module neither
//! clears CLOEXEC nor starts a process. The caller owns process admission,
//! current authority, cancellation, resources and exact terminal wait/reap.

use std::{
    collections::BTreeMap,
    io::{self, IoSlice, Write},
    mem::MaybeUninit,
    os::{fd::AsFd, unix::net::UnixStream},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

use rustix::{
    fs::{fcntl_get_seals, SealFlags},
    net::{sendmsg, SendAncillaryBuffer, SendAncillaryMessage, SendFlags},
    time::{clock_gettime, ClockId},
};
use serde::{Deserialize, Serialize};

use super::CellHostHandoffV1;
use crate::cell::{require, CellErrorV1, CellResultV1, CellSealedLoaderFileV1};

pub const MAX_CELL_RESEARCH_FD_FILES_V1: usize = 64;
pub const MAX_CELL_RESEARCH_FD_HEADER_V1: usize = 128 * 1024;

/// Operator inputs for this fresh research profile. These are not a CURRENT,
/// M12, CPV4 or FinalUse grant. A process owner must independently admit them.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellHostResearchExecutionV1 {
    pub schema: String,
    pub operation: String,
    pub descriptor: String,
    /// Complete environment roster, including every source/config/snapshot.
    pub environment_pins: BTreeMap<String, String>,
    pub max_snapshot_bytes: u64,
    pub runtime_rss_bytes: u64,
    pub python: String,
    pub python_sha256: String,
    pub output: String,
    pub threads: u32,
    pub material_profile: String,
    pub parent: CellHostResearchParentV1,
    pub requests: Vec<CellHostResearchQueryV1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellHostResearchParentV1 {
    pub generation: u64,
    pub operation_id: String,
    pub contract: String,
    pub adapter: String,
    pub file_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellHostResearchQueryV1 {
    pub request_id: String,
    pub prompt: String,
}

impl CellHostHandoffV1<'_, '_, '_> {
    /// Transmit the complete already-verified pair. Every environment member
    /// must also match the independent process owner's complete SHA-256 roster.
    /// There is no partial/member-subset or mutable-path fallback.
    pub fn send_research_fds_v1(
        &self,
        stream: &mut UnixStream,
        execution: &CellHostResearchExecutionV1,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> CellResultV1<()> {
        check(deadline, cancelled)?;
        let descriptor = self.descriptor();
        require(
            execution.schema == "trnm.cell-sealed-research-execution.v1"
                && execution.operation == hex(&descriptor.operation)
                && execution.descriptor == hex(&descriptor.commitment()?)
                && (1..=4).contains(&execution.threads)
                && matches!(
                    execution.material_profile.as_str(),
                    "current-contract-v1" | "smollm2-public-v2-material-runtime-bridge-v1"
                )
                && (1..=8 * 1024_u64.pow(3)).contains(&execution.runtime_rss_bytes)
                && (1..=1024_u64.pow(3)).contains(&execution.max_snapshot_bytes)
                && execution.requests.len() == 2
                && execution.requests[0].request_id != execution.requests[1].request_id
                && execution.python.starts_with('/')
                && execution.python.len() <= 4096
                && execution.output.starts_with('/')
                && execution.output.len() <= 4096
                && canonical_digest(&execution.python_sha256)
                && execution.parent.generation > 0
                && execution.parent.generation == descriptor.model_generation
                && execution.parent.contract == hex(&descriptor.worker_context.layout)
                && execution.parent.file_sha256 == hex(&descriptor.worker_context.parent)
                && !execution.parent.operation_id.is_empty()
                && execution.parent.operation_id.len() <= 128
                && canonical_digest(&execution.parent.contract)
                && canonical_digest(&execution.parent.adapter)
                && canonical_digest(&execution.parent.file_sha256),
            "host research original execution pins",
        )?;
        for request in &execution.requests {
            require(
                !request.request_id.is_empty()
                    && request.request_id.len() <= 128
                    && !request.prompt.is_empty()
                    && request.prompt.len() <= 2048,
                "host research bounded original request",
            )?;
        }
        let model = self.observed.model().bundle();
        let environment = self.observed.environment().bundle();
        require(
            execution.environment_pins.len() == environment.file_count()
                && model.file_count() + environment.file_count() <= MAX_CELL_RESEARCH_FD_FILES_V1
                && model
                    .snapshot_bytes()
                    .checked_add(environment.snapshot_bytes())
                    .is_some_and(|size| size <= execution.max_snapshot_bytes),
            "host research complete snapshot allowance",
        )?;
        let mut files: Vec<CellSealedLoaderFileV1<'_>> = Vec::new();
        let mut rows = Vec::new();
        let mut worker = None;
        for (scope, bundle) in [("model", model), ("environment", environment)] {
            for declared in bundle.closure().files() {
                check(deadline, cancelled)?;
                let file = bundle.file(&declared.path, declared.role)?;
                let seals = fcntl_get_seals(file.as_fd()).map_err(io::Error::from)?;
                require(
                    seals.contains(
                        SealFlags::SEAL
                            | SealFlags::SHRINK
                            | SealFlags::GROW
                            | SealFlags::WRITE
                            | SealFlags::EXEC,
                    ),
                    "host research immutable non-executable descriptor",
                )?;
                if scope == "environment" {
                    require(
                        execution.environment_pins.get(file.path())
                            == Some(&hex(&file.payload_sha256())),
                        "host research independent environment pin",
                    )?;
                    if file.path() == descriptor.worker_path {
                        require(
                            file.payload_sha256() == descriptor.worker_context.runtime,
                            "host research independent worker pin",
                        )?;
                        worker = Some(files.len());
                    }
                }
                rows.push(serde_json::json!({
                    "scope": scope, "path": file.path(), "role": file.role() as u8,
                    "bytes": file.payload_bytes(),
                    "sha256": hex(&file.payload_sha256()),
                    "sha512": hex(&file.payload_sha512()),
                }));
                files.push(file);
            }
        }
        // CLOCK_MONOTONIC is shared with Python on this same Linux host. Sample
        // it before the remaining Instant duration, so preparation never grants
        // the receiver a fresh or longer operation deadline.
        let sampled = clock_gettime(ClockId::Monotonic);
        let remaining = deadline.saturating_duration_since(Instant::now());
        require(
            !remaining.is_zero() && remaining.as_nanos() <= 600_000_000_000,
            "host research original finite deadline",
        )?;
        let monotonic_ns = u64::try_from(sampled.tv_sec)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .and_then(|value| value.checked_add(sampled.tv_nsec as u64))
            .and_then(|value| value.checked_add(u64::try_from(remaining.as_nanos()).ok()?))
            .ok_or(CellErrorV1::Invalid("host research monotonic clock"))?;
        let header = serde_json::to_vec(&serde_json::json!({
            "schema": "trnm.cell-sealed-research-fds.v1",
            "descriptor": hex(&descriptor.encode()?),
            "descriptor_sha512": hex(&descriptor.commitment()?),
            "worker": worker.ok_or(CellErrorV1::Invalid("host research worker absent"))?,
            "files": rows,
            "execution": execution,
            "deadline_monotonic_ns": monotonic_ns,
        }))
        .map_err(|_| CellErrorV1::Invalid("host research header encoding"))?;
        require(
            header.len() <= MAX_CELL_RESEARCH_FD_HEADER_V1,
            "host research header bound",
        )?;
        check(deadline, cancelled)?;
        let mut frame = (header.len() as u32).to_be_bytes().to_vec();
        frame.extend(header);
        let mut position = 0;
        while position < frame.len() {
            check(deadline, cancelled)?;
            stream.set_write_timeout(Some(deadline.saturating_duration_since(Instant::now())))?;
            match stream.write(&frame[position..]) {
                Ok(0) => return Err(CellErrorV1::Invalid("host research frame write stopped")),
                Ok(count) => position += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
        for file in files {
            check(deadline, cancelled)?;
            stream.set_write_timeout(Some(deadline.saturating_duration_since(Instant::now())))?;
            let fds = [file.as_fd()];
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
            let mut control = SendAncillaryBuffer::new(&mut space);
            require(
                control.push(SendAncillaryMessage::ScmRights(&fds)),
                "host research ancillary capacity",
            )?;
            let sent = sendmsg(
                &*stream,
                &[IoSlice::new(b"F")],
                &mut control,
                SendFlags::NOSIGNAL,
            )
            .map_err(io::Error::from)?;
            require(sent == 1, "host research descriptor transfer")?;
        }
        check(deadline, cancelled)
    }
}

fn check(deadline: Instant, cancelled: &AtomicBool) -> CellResultV1<()> {
    require(
        !cancelled.load(Ordering::SeqCst) && Instant::now() < deadline,
        "host research original deadline or cancellation",
    )
}

fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 15)] as char);
    }
    output
}

fn canonical_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
