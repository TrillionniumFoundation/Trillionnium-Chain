//! Bounded local client ingress owned by the actual consensus actor.
//! Exact admitted bytes feed ContinuousValidatorAuthority; no load is generated.
use crate::{
    config::LoadedValidatorConfig,
    continuous_runtime::ContinuousValidatorAuthorityV0,
    native_client_profile::{
        NativeClientProfileV1, NativeProfileClockV1, NativeProfileSignerResolverV1,
    },
};
use anyhow::{anyhow, ensure, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{
        fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use trnm_consensus_types::{SignedProposalV0, ValidatorSet};
use trnm_poco_node::{
    NativeAdmissionErrorV1, NativeAdmissionRecordV1, NativeAdmissionStatusV1,
    NativePendingAdmissionV1, NodeOwnedTxAdmissionBoundaryV0,
};
const REQUEST_MAX: usize = 528_384;
const RESPONSE_MAX: usize = 8 * 1024 * 1024 + 16 * 1024;
const CONNECTION_MAX: usize = 16;
const IO_SLICE: usize = 64 * 1024;
const MAX_ARTIFACT_COUNT: usize = 4096;
const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
const REQUEST_SCHEMA: &str = "trnm.native-client.request.v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyData {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmitData {
    signed_outer_hex: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HashData {
    native_tx_hash: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncManifestData {
    target_height: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncChunkData {
    height: u64,
    index: u64,
    record_sha256: String,
}
#[derive(Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
enum Request {
    #[serde(rename = "sync_manifest")]
    SyncManifest {
        schema: String,
        request_id: String,
        data: SyncManifestData,
    },
    #[serde(rename = "sync_chunk")]
    SyncChunk {
        schema: String,
        request_id: String,
        data: SyncChunkData,
    },
    #[serde(rename = "capabilities")]
    Capabilities {
        schema: String,
        request_id: String,
        data: EmptyData,
    },
    #[serde(rename = "submit")]
    Submit {
        schema: String,
        request_id: String,
        data: SubmitData,
    },
    #[serde(rename = "transaction")]
    Transaction {
        schema: String,
        request_id: String,
        data: HashData,
    },
    #[serde(rename = "proof")]
    Proof {
        schema: String,
        request_id: String,
        data: HashData,
    },
    #[serde(rename = "status")]
    Status {
        schema: String,
        request_id: String,
        data: EmptyData,
    },
}
impl Request {
    fn context(&self) -> (&str, &str) {
        match self {
            Self::SyncManifest {
                schema, request_id, ..
            }
            | Self::SyncChunk {
                schema, request_id, ..
            }
            | Self::Capabilities {
                schema, request_id, ..
            }
            | Self::Submit {
                schema, request_id, ..
            }
            | Self::Transaction {
                schema, request_id, ..
            }
            | Self::Proof {
                schema, request_id, ..
            }
            | Self::Status {
                schema, request_id, ..
            } => (schema, request_id),
        }
    }
}

/// Decode a request only when its wire bytes are the exact closed-profile
/// encoding.  `serde_json` validates the typed shape, but by itself accepts
/// insignificant whitespace and alternate object-member order.  The native
/// socket profile treats the request bytes as the retry identity, so those
/// alternate encodings must not reach the admission owner.
fn decode_request_v1(bytes: &[u8]) -> Result<Request> {
    let request: Request = serde_json::from_slice(bytes).context("decode native client request")?;
    let canonical = canonical_request_bytes_v1(&request)?;
    ensure!(
        canonical == bytes,
        "native client request is not canonical JSON"
    );
    Ok(request)
}

fn canonical_request_bytes_v1(request: &Request) -> Result<Vec<u8>> {
    let value = match request {
        Request::SyncManifest {
            schema,
            request_id,
            data,
        } => json!({
            "schema": schema,
            "request_id": request_id,
            "op": "sync_manifest",
            "data": {"target_height": data.target_height},
        }),
        Request::SyncChunk {
            schema,
            request_id,
            data,
        } => json!({
            "schema": schema,
            "request_id": request_id,
            "op": "sync_chunk",
            "data": {
                "height": data.height,
                "index": data.index,
                "record_sha256": data.record_sha256,
            },
        }),
        Request::Capabilities {
            schema, request_id, ..
        } => json!({
            "schema": schema,
            "request_id": request_id,
            "op": "capabilities",
            "data": {},
        }),
        Request::Submit {
            schema,
            request_id,
            data,
        } => json!({
            "schema": schema,
            "request_id": request_id,
            "op": "submit",
            "data": {"signed_outer_hex": data.signed_outer_hex},
        }),
        Request::Transaction {
            schema,
            request_id,
            data,
        } => json!({
            "schema": schema,
            "request_id": request_id,
            "op": "transaction",
            "data": {"native_tx_hash": data.native_tx_hash},
        }),
        Request::Proof {
            schema,
            request_id,
            data,
        } => json!({
            "schema": schema,
            "request_id": request_id,
            "op": "proof",
            "data": {"native_tx_hash": data.native_tx_hash},
        }),
        Request::Status {
            schema, request_id, ..
        } => json!({
            "schema": schema,
            "request_id": request_id,
            "op": "status",
            "data": {},
        }),
    };
    serde_json::to_vec(&value).context("encode canonical native client request")
}
struct Client {
    id: u64,
    proof_pending: bool,
    stream: UnixStream,
    started: Instant,
    bytes: Vec<u8>,
    expected: Option<usize>,
    reply: Option<Vec<u8>>,
    written: usize,
}

pub struct NativeClientRuntimeV1 {
    profile: NativeClientProfileV1,
    set: ValidatorSet,
    root: PathBuf,
    socket: PathBuf,
    socket_identity: (u64, u64),
    listener: UnixListener,
    clients: Vec<Client>,
    next_client_id: u64,
    proof_jobs: Vec<(u64, std::thread::JoinHandle<()>)>,
    admission: NodeOwnedTxAdmissionBoundaryV0,
    ready: VecDeque<NativePendingAdmissionV1>,
    in_flight: BTreeMap<[u8; 32], NativePendingAdmissionV1>,
    next_proposal: Instant,
    accepting: bool,
    finite_pending_ceiling: Option<usize>,
    last_business_height: u64,
    last_archived_finalized_height: u64,
    artifact_count: usize,
    artifact_bytes: u64,
    #[cfg(test)]
    cut_after_proof: bool,
}
impl NativeClientRuntimeV1 {
    pub fn open_v1(
        config: &LoadedValidatorConfig,
        authority: &ContinuousValidatorAuthorityV0,
    ) -> Result<Option<Self>> {
        let Some(profile) = config.native_client_profile_v1().cloned() else {
            return Ok(None);
        };
        Self::open_parts_with_recovery_v1(
            config.run_root(),
            config.validator_set(),
            config.local_validator(),
            profile,
            Some(authority),
        )
        .map(Some)
    }
    #[cfg(test)]
    pub(crate) fn open_parts_v1(
        run_root: &Path,
        validator_set: &ValidatorSet,
        local_validator: trnm_consensus_types::ValidatorId,
        profile: NativeClientProfileV1,
    ) -> Result<Self> {
        Self::open_parts_with_recovery_v1(run_root, validator_set, local_validator, profile, None)
    }
    pub(crate) fn open_parts_with_recovery_v1(
        run_root: &Path,
        validator_set: &ValidatorSet,
        local_validator: trnm_consensus_types::ValidatorId,
        profile: NativeClientProfileV1,
        recovery_authority: Option<&ContinuousValidatorAuthorityV0>,
    ) -> Result<Self> {
        profile.validate_v1(
            validator_set.chain_id().as_str(),
            &validator_set
                .validators()
                .iter()
                .map(|v| v.consensus_key().into_bytes())
                .collect::<Vec<_>>(),
        )?;
        profile.chain_now_ms_v1()?;
        let root = run_root.join("native-client-v1");
        if !root.exists() {
            fs::DirBuilder::new().mode(0o700).create(&root)?;
            File::open(run_root)?.sync_all()?;
        }
        let metadata = fs::symlink_metadata(&root)?;
        ensure!(
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.mode() & 0o777 == 0o700
                && metadata.uid() == rustix::process::geteuid().as_raw(),
            "native client data root must be owner-private"
        );
        let mut namespace = Sha256::new();
        namespace.update(b"trnm.native-client.wal.v1\0");
        namespace.update(validator_set.genesis_hash().as_bytes());
        namespace.update(local_validator.as_bytes());
        namespace.update(profile.digest_v1()?);
        // Opening WAL takes the exclusive owner lock before a stale socket can
        // be removed. Restarted HandedOff inventory refuses readiness here.
        let mut admission = NodeOwnedTxAdmissionBoundaryV0::open_native_candidate_v1(
            root.join("admission.sqlite"),
            namespace.finalize().into(),
            profile.admission_profile_v1()?,
            NativeProfileSignerResolverV1(profile.clone()),
            NativeProfileClockV1(profile.clone()),
            recovery_authority.is_some(),
        )?;
        let reader = NativeProofReaderV1 {
            root: root.clone(),
            profile: profile.clone(),
            set: validator_set.clone(),
        };
        let unresolved = admission
            .native_pending_inventory_v1()?
            .into_iter()
            .filter(|record| record.status() == NativeAdmissionStatusV1::InFlight)
            .collect::<Vec<_>>();
        for record in unresolved {
            let authority = recovery_authority
                .context("RECOVERY_REQUIRED: native handoff has no live recovery authority")?;
            let stored = reader
                .read_stored_v1(record.native_tx_hash())
                .context("RECOVERY_REQUIRED: exact historical native proof is unavailable")?;
            let encoded = reader.verify_stored_proof_v1(&stored, record.native_tx_hash())?;
            let package = trnm_tx_lifecycle_v0::NativeTxProofPackageV1::decode_exact(
                &encoded,
                trnm_tx_lifecycle_v0::MAX_NATIVE_TX_PROOF_BYTES_V1,
            )?;
            ensure!(
                package.transaction == record.exact_outer_bytes(),
                "native recovery proof body differs from WAL"
            );
            let parent = trnm_consensus_types::decode_block_header_v0_exact(&canonical_hex(
                &stored.parent_header_hex,
                16 * 1024,
            )?)
            .map_err(|e| anyhow!("stored native parent: {e}"))?
            .timestamp_ms();
            let proof = trnm_consensus_types::decode_finality_proof_v0_exact(
                &package.finality_proof,
                validator_set,
                &trnm_consensus_types::ConsensusParametersV0::reference_shadow_v0(),
                parent,
            )
            .map_err(|e| anyhow!("native recovery finality decode: {e:?}"))?;
            let built =
                trnm_application_tx_builder_v0::BuiltCanonicalTxV0::from_exact_outer_bytes_v0(
                    record.exact_outer_bytes(),
                )?;
            authority.recover_native_admission_with_finality_v1(
                &mut admission,
                &built,
                &proof,
                parent,
            )?;
        }
        admission.restore_native_pending_v1()?;
        let mut artifact_count = 0usize;
        let mut artifact_bytes = 0u64;
        for entry in fs::read_dir(&root)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.starts_with("selection-") || name.starts_with("proof-") {
                let metadata = fs::symlink_metadata(entry.path())?;
                ensure!(
                    metadata.is_file()
                        && !metadata.file_type().is_symlink()
                        && metadata.len() <= RESPONSE_MAX as u64,
                    "native artifact inventory shape"
                );
                artifact_count = artifact_count
                    .checked_add(1)
                    .context("native artifact count overflow")?;
                artifact_bytes = artifact_bytes
                    .checked_add(metadata.len())
                    .context("native artifact bytes overflow")?;
                ensure!(
                    artifact_count <= MAX_ARTIFACT_COUNT && artifact_bytes <= MAX_ARTIFACT_BYTES,
                    "native artifact retention capacity exhausted"
                );
            }
        }
        let socket = root.join(&profile.socket_basename);
        ensure!(
            socket.as_os_str().as_encoded_bytes().len() < 104,
            "native client socket path exceeds portable Unix bound"
        );
        if let Ok(metadata) = fs::symlink_metadata(&socket) {
            ensure!(
                metadata.file_type().is_socket()
                    && metadata.uid() == rustix::process::geteuid().as_raw(),
                "stale native client endpoint is not an owned socket"
            );
            fs::remove_file(&socket)?;
        }
        let listener = UnixListener::bind(&socket)?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let metadata = fs::symlink_metadata(&socket)?;
        Ok(Self {
            profile,
            set: validator_set.clone(),
            root,
            socket,
            socket_identity: (metadata.dev(), metadata.ino()),
            listener,
            clients: Vec::new(),
            next_client_id: 0,
            proof_jobs: Vec::new(),
            admission,
            ready: VecDeque::new(),
            in_flight: BTreeMap::new(),
            next_proposal: Instant::now(),
            accepting: true,
            finite_pending_ceiling: None,
            last_business_height: 0,
            last_archived_finalized_height: 0,
            artifact_count,
            artifact_bytes,
            #[cfg(test)]
            cut_after_proof: false,
        })
    }
    fn persist_artifact_v1(&mut self, path: &Path, bytes: &[u8]) -> Result<()> {
        let new = !path.exists();
        if new {
            ensure!(
                self.artifact_count < MAX_ARTIFACT_COUNT
                    && self
                        .artifact_bytes
                        .checked_add(bytes.len() as u64)
                        .is_some_and(|n| n <= MAX_ARTIFACT_BYTES),
                "native artifact retention backpressure"
            );
        }
        persist_exact(path, bytes)?;
        if new {
            self.artifact_count += 1;
            self.artifact_bytes += bytes.len() as u64;
        }
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn cut_after_next_durable_proof_v1(&mut self) {
        self.cut_after_proof = true;
    }
    pub fn stop_admission_v1(&mut self) {
        self.accepting = false;
    }
    /// Operational admission only. It cannot remove accepted WAL records or
    /// change consensus validity; the current owner refreshes it before polling.
    pub(crate) fn update_finality_capacity_v1(
        &mut self,
        parent_height: u64,
        target_height: u64,
    ) -> Result<()> {
        self.finite_pending_ceiling = Some(finite_pending_capacity_v1(
            &self.profile,
            self.set.validators().len(),
            parent_height,
            target_height,
        )?);
        Ok(())
    }
    fn capacity_refusal_v1(&self) -> Option<(&'static str, bool)> {
        match self.finite_pending_ceiling {
            Some(0) => Some(("finality_capacity_exhausted", false)),
            Some(limit)
                if self
                    .ready
                    .len()
                    .checked_add(self.admission.queued_counts().2)
                    .is_none_or(|pending| pending >= limit) =>
            {
                Some(("backpressure", true))
            }
            _ => None,
        }
    }
    pub fn last_business_height_v1(&self) -> u64 {
        self.last_business_height
    }
    pub fn drained_v1(&self, finalized: u64) -> bool {
        self.in_flight.is_empty()
            && self.ready.is_empty()
            && self.admission.queued_counts().2 == 0
            && self.last_business_height <= finalized
    }
    pub fn poll_v1(&mut self, parent_timestamp: u64, finalized_height: u64) -> Result<bool> {
        self.poll_resolving_parent_v1(finalized_height, || Ok(parent_timestamp))
    }
    /// Serve bounded reads and exact durable retries while Core holds a signed
    /// phase. No cached timestamp is used to authorize new admission.
    pub(crate) fn poll_read_only_v1(&mut self, finalized_height: u64) -> Result<bool> {
        self.poll_with_admission_parent_v1(false, finalized_height, || Ok(None))
    }
    /// A read/idle tick does not request mutable-application admission facts.
    /// Every new submit still obtains a fresh parent; errors remain fail-closed.
    pub(crate) fn poll_resolving_parent_v1(
        &mut self,
        finalized_height: u64,
        mut resolve_parent: impl FnMut() -> Result<u64>,
    ) -> Result<bool> {
        self.poll_with_admission_parent_v1(true, finalized_height, || resolve_parent().map(Some))
    }
    fn poll_with_admission_parent_v1(
        &mut self,
        admission_ready: bool,
        finalized_height: u64,
        mut resolve_parent: impl FnMut() -> Result<Option<u64>>,
    ) -> Result<bool> {
        let mut progress = false;
        let mut index = 0;
        while index < self.proof_jobs.len() {
            if !self.proof_jobs[index].1.is_finished() {
                index += 1;
                continue;
            }
            let (id, job) = self.proof_jobs.swap_remove(index);
            // Read workers own delivery. Reaping must never write a second
            // response or turn a peer disconnect into a consensus failure.
            let _ = job.join();
            self.clients.retain(|client| client.id != id);
            progress = true;
        }
        while self.clients.len() < CONNECTION_MAX {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(true)?;
                    self.next_client_id = self
                        .next_client_id
                        .checked_add(1)
                        .context("client sequence overflow")?;
                    self.clients.push(Client {
                        id: self.next_client_id,
                        proof_pending: false,
                        stream,
                        started: Instant::now(),
                        bytes: Vec::new(),
                        expected: None,
                        reply: None,
                        written: 0,
                    });
                    progress = true
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e.into()),
            }
        }
        let clients = std::mem::take(&mut self.clients);
        let mut handled = 0;
        for mut client in clients {
            if client.started.elapsed()
                > Duration::from_secs(if client.reply.is_some() || client.proof_pending {
                    5
                } else {
                    2
                })
            {
                let _ = client.stream.shutdown(std::net::Shutdown::Both);
                continue;
            }
            let mut keep = true;
            if client.reply.is_none() && !client.proof_pending {
                let mut buffer = [0u8; IO_SLICE];
                if client.expected.is_none_or(|n| client.bytes.len() < n + 4) {
                    match client.stream.read(&mut buffer) {
                        Ok(0) => keep = false,
                        Ok(count) => {
                            progress = true;
                            client.bytes.extend_from_slice(&buffer[..count]);
                            if client.expected.is_none() && client.bytes.len() >= 4 {
                                let count =
                                    u32::from_be_bytes(client.bytes[..4].try_into().unwrap())
                                        as usize;
                                if count == 0 || count > REQUEST_MAX {
                                    keep = false
                                } else {
                                    client.expected = Some(count)
                                }
                            }
                            if client.bytes.len() > REQUEST_MAX + 4 {
                                keep = false;
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                        Err(_) => keep = false,
                    }
                }
                if keep
                    && handled < 8
                    && client
                        .expected
                        .is_some_and(|count| client.bytes.len() >= count + 4)
                {
                    let expected = client.expected.unwrap();
                    if client.bytes.len() == expected + 4
                        && bounded_json_depth(&client.bytes[4..], 64)
                    {
                        if let Ok(request) = decode_request_v1(&client.bytes[4..]) {
                            let (schema, request_id) = request.context();
                            if valid_request_context(schema, request_id) {
                                // Committed Transaction lookups and exact
                                // Submit retries perform proof-file reads,
                                // bounded package decoding, and strict
                                // signature verification. Keep the WAL lookup
                                // on the owner, then offload only the
                                // committed proof work to the same bounded
                                // two-worker pool used by Proof/Sync queries.
                                if let Ok(Some(record)) =
                                    self.committed_record_for_query_v1(&request)
                                {
                                    if self.proof_jobs.len() < 2 {
                                        let reader = self.proof_reader_v1();
                                        let request_id = request_id.to_owned();
                                        if self
                                            .spawn_read_query_v1(&mut client, move || {
                                                match record_response_with_reader_v1(
                                                    &reader, &record,
                                                ) {
                                                    Ok(data) => reader.reply(&request_id, data),
                                                    Err(_) => reader.error_reply(
                                                        &request_id,
                                                        "recovery_required",
                                                        true,
                                                    ),
                                                }
                                            })
                                            .is_err()
                                        {
                                            client.reply =
                                                Some(frame_response(&self.error_reply(
                                                    request.context().1,
                                                    "backpressure",
                                                    true,
                                                ))?);
                                        }
                                        client.bytes.clear();
                                        self.clients.push(client);
                                        handled += 1;
                                        continue;
                                    }
                                    client.reply = Some(frame_response(&self.error_reply(
                                        request_id,
                                        "backpressure",
                                        true,
                                    ))?);
                                    client.bytes.clear();
                                    self.clients.push(client);
                                    handled += 1;
                                    continue;
                                }
                                let query_request = matches!(
                                    request,
                                    Request::Proof { .. }
                                        | Request::SyncManifest { .. }
                                        | Request::SyncChunk { .. }
                                );
                                if query_request {
                                    if self.proof_jobs.len() < 2 {
                                        let reader = self.proof_reader_v1();
                                        let request_id = request_id.to_owned();
                                        if self
                                            .spawn_read_query_v1(&mut client, move || {
                                                reader
                                                    .read_query_reply_v1(request, finalized_height)
                                            })
                                            .is_err()
                                        {
                                            client.reply =
                                                Some(frame_response(&self.error_reply(
                                                    &request_id,
                                                    "backpressure",
                                                    true,
                                                ))?);
                                        }
                                        client.bytes.clear();
                                        self.clients.push(client);
                                        handled += 1;
                                        continue;
                                    }
                                    client.reply = Some(frame_response(&self.error_reply(
                                        request_id,
                                        "backpressure",
                                        true,
                                    ))?);
                                    client.bytes.clear();
                                    self.clients.push(client);
                                    handled += 1;
                                    continue;
                                }
                            }
                        }
                    }
                    let reply = if client.bytes.len() != expected + 4
                        || !bounded_json_depth(&client.bytes[4..], 64)
                    {
                        self.error_reply("", "invalid_request", false)
                    } else {
                        self.handle_request(
                            &client.bytes[4..],
                            admission_ready,
                            finalized_height,
                            &mut resolve_parent,
                        )?
                    };
                    client.reply = Some(frame_response(&reply)?);
                    client.bytes.clear();
                    handled += 1;
                }
            }
            if let Some(reply) = &client.reply {
                match client
                    .stream
                    .write(&reply[client.written..reply.len().min(client.written + IO_SLICE)])
                {
                    Ok(0) => keep = false,
                    Ok(count) => {
                        client.written += count;
                        progress = true;
                        if client.written == reply.len() {
                            keep = false
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => keep = false,
                }
            }
            if keep {
                self.clients.push(client);
            }
        }
        Ok(progress)
    }
    fn spawn_read_query_v1(
        &mut self,
        client: &mut Client,
        query: impl FnOnce() -> Value + Send + 'static,
    ) -> io::Result<()> {
        let mut connection = ReadQueryConnectionV1(client.stream.try_clone()?);
        // Reuse the connection's original budget; work and writes do not reset it.
        let deadline = client.started + Duration::from_secs(5);
        let job = std::thread::Builder::new()
            .name("native-read-query".to_owned())
            .spawn(move || {
                if Instant::now() < deadline {
                    let reply = query();
                    let _ = write_read_reply_v1(&mut connection.0, &reply, deadline);
                }
                // RAII also closes the connection if a query panics.
            })?;
        self.proof_jobs.push((client.id, job));
        client.proof_pending = true;
        Ok(())
    }
    fn reply(&self, id: &str, data: Value) -> Value {
        json!({"schema":"trnm.native-client.response.v1","request_id":id,"candidate_only":true,"chain_id":self.set.chain_id().as_str(),"genesis_hash":hex::encode(self.set.genesis_hash().as_bytes()),"profile_sha256":hex::encode(self.profile.digest_v1().expect("validated canonical profile")),"ok":true,"data":data})
    }
    fn error_reply(&self, id: &str, code: &str, retryable: bool) -> Value {
        let mut reply = self.reply(id, Value::Null);
        reply["ok"] = json!(false);
        reply.as_object_mut().unwrap().remove("data");
        reply["error"] = json!({"code":code,"retryable":retryable});
        reply
    }
    fn handle_request(
        &mut self,
        bytes: &[u8],
        admission_ready: bool,
        finalized: u64,
        resolve_parent: &mut impl FnMut() -> Result<Option<u64>>,
    ) -> Result<Value> {
        let request: Request = match decode_request_v1(bytes) {
            Ok(r) => r,
            Err(_) => return Ok(self.error_reply("", "invalid_request", false)),
        };
        let (schema, id) = request.context();
        let id = id.to_owned();
        if schema != REQUEST_SCHEMA
            || id.is_empty()
            || id.len() > 64
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Ok(self.error_reply(&id, "invalid_request", false));
        }
        // Exact Pending/InFlight readback needs no new admission parent.
        if let Request::Submit { data, .. } = &request {
            if let Ok(bytes) =
                canonical_hex(&data.signed_outer_hex, self.profile.maximum_outer_bytes)
            {
                // Exact durable retries remain answerable during stop/skew.
                if let Ok(built) =
                    trnm_application_tx_builder_v0::BuiltCanonicalTxV0::from_exact_outer_bytes_v0(
                        &bytes,
                    )
                {
                    if let Ok(hash) = built.envelope().tx_hash() {
                        let retained = match self.admission.native_record_v1(hash) {
                            Ok(record) => record,
                            Err(_) => return Ok(self.error_reply(&id, "recovery_required", true)),
                        };
                        if let Some(record) = retained {
                            if record.exact_outer_bytes() == bytes {
                                return Ok(match self.record_response_v1(&record) {
                                    Ok(data) => self.reply(&id, data),
                                    Err(_) => self.error_reply(&id, "recovery_required", true),
                                });
                            }
                        }
                    }
                }
            }
        }
        if matches!(&request, Request::Submit { .. }) {
            if let Some((code, retryable)) = self.capacity_refusal_v1() {
                return Ok(self.error_reply(&id, code, retryable));
            }
        }
        let parent =
            if admission_ready && self.accepting && matches!(&request, Request::Submit { .. }) {
                resolve_parent()?
            } else {
                None
            };
        Ok(self.handle_admitted_request_v1(request, &id, parent, admission_ready, finalized))
    }
    fn handle_admitted_request_v1(
        &mut self,
        request: Request,
        id: &str,
        parent: Option<u64>,
        admission_ready: bool,
        finalized: u64,
    ) -> Value {
        match request {
            Request::SyncManifest { .. } | Request::SyncChunk { .. } => {
                self.error_reply(id, "invalid_request", false)
            }
            Request::Capabilities { data, .. } => {
                let _ = data;
                self.reply(id,json!({"profile":self.profile.schema,"wall_clock_epoch_ms":self.profile.wall_clock_epoch_ms.to_string(),"time_domain":"milliseconds_since_profile_wall_clock_epoch","maximum_outer_bytes":self.profile.maximum_outer_bytes,"maximum_pending":self.profile.maximum_pending,"proof_class":"poco-three-chain-v0","m05_intent_binding":false}))
            }
            Request::Status { data, .. } => {
                let _ = data;
                self.reply(id,json!({"accepting":self.accepting && admission_ready && self.capacity_refusal_v1().is_none(),"finalized_height":finalized.to_string(),"pending":self.ready.len()+self.admission.queued_counts().2,"in_flight":self.in_flight.len(),"proof_verified":false}))
            }
            Request::Submit { data, .. } => {
                let bytes =
                    match canonical_hex(&data.signed_outer_hex, self.profile.maximum_outer_bytes) {
                        Ok(b) => b,
                        Err(_) => return self.error_reply(id, "invalid_request", false),
                    };
                let Some(parent) = parent.filter(|_| self.accepting) else {
                    return self.error_reply(id, "backpressure", true);
                };
                if !self
                    .profile
                    .proposal_timestamp_v1(parent, 60_000)
                    .is_ok_and(|(_, ready)| ready)
                {
                    return self.error_reply(id, "time_unready", true);
                }
                match self.admission.submit_native_bytes_v1(&bytes) {
                    Ok(record) => match self.record_response_v1(&record) {
                        Ok(data) => self.reply(id, data),
                        Err(_) => self.error_reply(id, "recovery_required", true),
                    },
                    Err(NativeAdmissionErrorV1::Backpressure) => {
                        self.error_reply(id, "backpressure", true)
                    }
                    Err(NativeAdmissionErrorV1::Uncertain) => {
                        self.error_reply(id, "recovery_required", true)
                    }
                    Err(NativeAdmissionErrorV1::Decode) => {
                        self.error_reply(id, "invalid_request", false)
                    }
                    Err(NativeAdmissionErrorV1::Wal(_)) => {
                        self.error_reply(id, "recovery_required", true)
                    }
                    Err(_) => self.error_reply(id, "admission_rejected", false),
                }
            }
            Request::Transaction { data, .. } => {
                let hash = match hash32(&data.native_tx_hash) {
                    Ok(h) => h,
                    Err(_) => return self.error_reply(id, "invalid_request", false),
                };
                match self.admission.native_record_v1(hash) {
                    Ok(Some(record)) => match self.record_response_v1(&record) {
                        Ok(data) => self.reply(id, data),
                        Err(_) => self.error_reply(id, "recovery_required", true),
                    },
                    Ok(None) => self.error_reply(id, "not_found", false),
                    Err(_) => self.error_reply(id, "recovery_required", true),
                }
            }
            Request::Proof { data, .. } => match hash32(&data.native_tx_hash) {
                Ok(hash) => self.proof_reader_v1().proof_reply_v1(id, hash),
                Err(_) => self.error_reply(id, "invalid_request", false),
            },
        }
    }
    fn committed_record_for_query_v1(
        &self,
        request: &Request,
    ) -> Result<Option<NativeAdmissionRecordV1>> {
        let hash = match request {
            Request::Transaction { data, .. } => match hash32(&data.native_tx_hash) {
                Ok(hash) => Some(hash),
                Err(_) => return Ok(None),
            },
            Request::Submit { data, .. } => {
                let bytes =
                    match canonical_hex(&data.signed_outer_hex, self.profile.maximum_outer_bytes) {
                        Ok(bytes) => bytes,
                        Err(_) => return Ok(None),
                    };
                let built = match trnm_application_tx_builder_v0::BuiltCanonicalTxV0::from_exact_outer_bytes_v0(&bytes) {
                    Ok(built) => built,
                    Err(_) => return Ok(None),
                };
                match built.envelope().tx_hash() {
                    Ok(hash) => Some(hash),
                    Err(_) => return Ok(None),
                }
            }
            _ => None,
        };
        let Some(hash) = hash else { return Ok(None) };
        let Some(record) = self.admission.native_record_v1(hash)? else {
            return Ok(None);
        };
        if record.status() == NativeAdmissionStatusV1::Committed {
            if let Request::Submit { data, .. } = request {
                let bytes =
                    match canonical_hex(&data.signed_outer_hex, self.profile.maximum_outer_bytes) {
                        Ok(bytes) => bytes,
                        Err(_) => return Ok(None),
                    };
                if record.exact_outer_bytes() != bytes.as_slice() {
                    return Ok(None);
                }
            }
            Ok(Some(record))
        } else {
            Ok(None)
        }
    }
    fn record_response_v1(&self, record: &NativeAdmissionRecordV1) -> Result<Value> {
        record_response_with_reader_v1(&self.proof_reader_v1(), record)
    }
    pub fn maybe_proposal_v1(
        &mut self,
        authority: &mut ContinuousValidatorAuthorityV0,
        allow_business: bool,
        maximum_step: u64,
    ) -> Result<Option<SignedProposalV0>> {
        if Instant::now() < self.next_proposal {
            return Ok(None);
        }
        let parent = authority.native_parent_timestamp_v1()?;
        let (timestamp, ready_time) = match self.profile.proposal_timestamp_v1(parent, maximum_step)
        {
            Ok(value) => value,
            Err(_) => return Ok(None),
        };
        // Cadence follows the committed parent time, so rotating leaders
        // cannot multiply the configured block rate by validator count.
        if ready_time
            && timestamp
                < parent
                    .checked_add(self.profile.block_cadence_ms)
                    .context("native cadence timestamp overflow")?
        {
            return Ok(None);
        }
        while let Some(pending) = self.admission.pop_native_ready_v1()? {
            self.ready.push_back(pending)
        }
        let mut body = Vec::new();
        let mut selected = Vec::new();
        let mut size = 4usize;
        if allow_business && ready_time {
            while let Some(pending) = self.ready.pop_front() {
                if pending.transaction().envelope().expires_at_unix_ms < timestamp {
                    self.admission
                        .reject_native_pending_v1(pending.metadata().digest().as_bytes(), true)?;
                    continue;
                }
                let next = size
                    .checked_add(4 + pending.transaction().exact_outer_bytes().len())
                    .context("batch size overflow")?;
                if selected.len() >= self.profile.maximum_batch_transactions
                    || next > self.profile.maximum_batch_bytes
                {
                    self.ready.push_front(pending);
                    break;
                }
                size = next;
                body.push(pending.transaction().exact_outer_bytes().to_vec());
                selected.push(pending);
            }
        }
        let preimage = match authority.native_proposal_preimage_v1(body, timestamp) {
            Ok(p) => p,
            Err(_) => {
                // Preview currently erases deterministic/storage error classes.
                // Preserve every body; never turn an unknown storage fault into a
                // local transaction rejection or silently manufacture a payload.
                for pending in selected.into_iter().rev() {
                    self.ready.push_front(pending)
                }
                self.next_proposal =
                    Instant::now() + Duration::from_millis(self.profile.block_cadence_ms);
                return Ok(None);
            }
        };
        let header = preimage.block_v0().header();
        if !selected.is_empty() {
            let selection = json!({"schema":"trnm.native-selection.v1","profile_sha256":hex::encode(self.profile.digest_v1()?),"block_id":hex::encode(header.id().as_bytes()),"parent_id":hex::encode(header.parent_id().as_bytes()),"height":header.height().get().to_string(),"view":header.view().get().to_string(),"native_tx_hashes":selected.iter().map(|p|hex::encode(p.metadata().digest().as_bytes())).collect::<Vec<_>>()});
            self.persist_artifact_v1(
                &self.root.join(format!(
                    "selection-{}.json",
                    hex::encode(header.id().as_bytes())
                )),
                &serde_json::to_vec(&selection)?,
            )?;
            self.last_business_height = self.last_business_height.max(header.height().get());
            for mut pending in selected {
                pending
                    .handoff()
                    .map_err(|e| anyhow!("native durable handoff: {e:?}"))?;
                self.in_flight
                    .insert(pending.metadata().digest().as_bytes(), pending);
            }
        }
        let proposal = authority.seal_native_proposal_v1(preimage)?;
        self.next_proposal = Instant::now() + Duration::from_millis(self.profile.block_cadence_ms);
        Ok(Some(proposal))
    }
}
// Every queued transaction is charged at maximum outer size. Complete leader
// rotations are a conservative service allowance under otherwise healthy
// progress, not a liveness promise under arbitrary faults or invalid execution.
fn finite_pending_capacity_v1(
    profile: &NativeClientProfileV1,
    validator_count: usize,
    parent_height: u64,
    target_height: u64,
) -> Result<usize> {
    let validators = u64::try_from(validator_count).context("validator count overflow")?;
    ensure!(validators > 0, "finite admission requires validators");
    let item_bytes = profile
        .maximum_outer_bytes
        .checked_add(4)
        .context("finite admission item size overflow")?;
    let batch_bytes = profile
        .maximum_batch_bytes
        .checked_sub(4)
        .context("finite admission batch header missing")?;
    let per_turn = (batch_bytes / item_bytes).min(profile.maximum_batch_transactions);
    ensure!(
        per_turn > 0,
        "finite admission profile cannot fit one transaction"
    );
    let turns = target_height
        .saturating_sub(parent_height)
        .saturating_sub(2)
        / validators;
    let turns = usize::try_from(turns.min(profile.maximum_pending as u64))
        .context("finite admission turn count overflow")?;
    Ok(turns
        .checked_mul(per_turn)
        .context("finite admission capacity overflow")?
        .min(profile.maximum_pending))
}

impl Drop for NativeClientRuntimeV1 {
    fn drop(&mut self) {
        for client in &self.clients {
            // In-flight read workers hold a clone, not authority. Close both
            // handles' I/O before releasing the endpoint namespace.
            let _ = client.stream.shutdown(std::net::Shutdown::Both);
        }
        if let Ok(metadata) = fs::symlink_metadata(&self.socket) {
            if (metadata.dev(), metadata.ino()) == self.socket_identity {
                let _ = fs::remove_file(&self.socket);
            }
        }
    }
}
fn persist_exact(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.len() == bytes.len() as u64,
            "native durable artifact changed"
        );
        ensure!(fs::read(path)? == bytes, "native durable artifact conflict");
        return Ok(());
    }
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).map_err(|_| anyhow!("artifact temporary name entropy"))?;
    let parent = path.parent().context("artifact parent")?;
    let temporary = parent.join(format!(".native-write-{}", hex::encode(nonce)));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    // link is atomic and cannot overwrite an existing target. The complete
    // bytes are durable before a canonical artifact name becomes visible.
    fs::hard_link(&temporary, path)?;
    File::open(parent)?.sync_all()?;
    fs::remove_file(&temporary)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn canonical_hex(value: &str, max: usize) -> Result<Vec<u8>> {
    ensure!(
        value.len() <= max * 2
            && value.len().is_multiple_of(2)
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid hex"
    );
    Ok(hex::decode(value)?)
}
fn hash32(value: &str) -> Result<[u8; 32]> {
    canonical_hex(value, 32)?
        .try_into()
        .map_err(|_| anyhow!("hash length"))
}
fn bounded_json_depth(bytes: &[u8], max: usize) -> bool {
    let (mut depth, mut quoted, mut escaped) = (0usize, false, false);
    for b in bytes {
        if quoted {
            if escaped {
                escaped = false
            } else if *b == b'\\' {
                escaped = true
            } else if *b == b'"' {
                quoted = false
            }
        } else {
            match b {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > max {
                        return false;
                    }
                }
                b'}' | b']' => {
                    let Some(next) = depth.checked_sub(1) else {
                        return false;
                    };
                    depth = next
                }
                _ => {}
            }
        }
    }
    depth == 0 && !quoted
}

impl NativeClientRuntimeV1 {
    pub(crate) fn sync_prefix_ready_v1(&self) -> bool {
        self.root.join("replay-003.id").is_file()
    }
    pub(crate) fn persist_sync_bootstrap_v1(
        &self,
        proofs: &[trnm_consensus_types::FinalityProofV0; 3],
    ) -> Result<()> {
        for proof in proofs {
            crate::native_replay_sync_v1::persist_export(&self.root, proof, &[])?;
        }
        Ok(())
    }
    pub const fn last_archived_finalized_height_v1(&self) -> u64 {
        self.last_archived_finalized_height
    }
    /// Current-tip convenience adapter; the parent is hash-bound below.
    pub fn observe_finality_v1(
        &mut self,
        authority: &ContinuousValidatorAuthorityV0,
        parent: &trnm_consensus_types::BlockHeader,
    ) -> Result<()> {
        if authority.facts_v0()?.finalized_height_v0() < 4 {
            return Ok(());
        }
        let query = authority.native_finalized_query_v1()?;
        self.observe_finality_evidence_v1(authority, query.proof_v0().proof_v0(), parent)
    }
    /// Persist a strictly proved historical native row before resolving WAL.
    pub fn observe_finality_evidence_v1(
        &mut self,
        authority: &ContinuousValidatorAuthorityV0,
        proof: &trnm_consensus_types::FinalityProofV0,
        parent: &trnm_consensus_types::BlockHeader,
    ) -> Result<()> {
        let header = proof.finalized_block().header();
        if header.height().get() <= self.last_archived_finalized_height {
            return Ok(());
        }
        ensure!(
            parent.id() == header.parent_id()
                && parent.height().get().checked_add(1) == Some(header.height().get())
                && parent.chain_id() == self.set.chain_id()
                && parent.genesis_hash() == self.set.genesis_hash()
                && parent.epoch() == self.set.epoch()
                && parent.validator_set_id() == self.set.id()
                && parent.consensus_parameters_hash() == self.set.consensus_parameters_hash(),
            "native parent header is not bound to finalized target scope"
        );
        let read =
            authority.read_native_finalized_with_finality_v1(proof, parent.timestamp_ms())?;
        let executed = read.executed_v0();
        let transactions = executed.request().transactions();
        ensure!(
            transactions.len() <= self.profile.maximum_batch_transactions,
            "finalized native batch exceeds committed local profile"
        );
        let mut receipts = Vec::new();
        for receipt in executed.receipts() {
            let events = receipt
                .events()
                .iter()
                .map(|event| {
                    let attributes = event
                        .attributes()
                        .iter()
                        .map(|attribute| {
                            trnm_consensus_types::ExecutionEventAttributeV0::new(
                                attribute.key().as_bytes().to_vec(),
                                attribute.value().as_bytes().to_vec(),
                            )
                            .map_err(|e| anyhow!("native event attribute: {e:?}"))
                        })
                        .collect::<Result<Vec<_>>>()?;
                    trnm_consensus_types::ExecutionEventV0::new(
                        event.kind().as_bytes().to_vec(),
                        attributes,
                    )
                    .map_err(|e| anyhow!("native event: {e:?}"))
                })
                .collect::<Result<Vec<_>>>()?;
            let canonical = trnm_consensus_types::ExecutionReceiptCommitmentV0::new(
                receipt.transaction_index(),
                *receipt.transaction_digest().as_bytes(),
                receipt.gas_used(),
                receipt.fee_charged(),
                events,
            )
            .map_err(|e| anyhow!("native receipt: {e:?}"))?
            .try_cev0_bytes()
            .map_err(|e| anyhow!("native receipt encoding: {e:?}"))?;
            ensure!(
                trnm_finality_types::hash_domain(
                    "trnm.native-application.execution-receipt.v0",
                    &[&canonical]
                ) == *receipt.commitment().as_bytes(),
                "native receipt commitment reconstruction mismatch"
            );
            receipts.push(canonical);
        }
        crate::native_replay_sync_v1::persist_export(&self.root, proof, transactions)?;
        for (index, transaction) in transactions.iter().enumerate() {
            let built =
                trnm_application_tx_builder_v0::BuiltCanonicalTxV0::from_exact_outer_bytes_v0(
                    transaction,
                )?;
            let hash = built.envelope().tx_hash()?;
            let payload = trnm_consensus_types::OrderedInclusionProofV0::from_items(
                trnm_consensus_types::RootKind::Payload,
                transactions,
                index as u32,
            )
            .map_err(|e| anyhow!("payload proof: {e:?}"))?;
            let receipt = trnm_consensus_types::OrderedInclusionProofV0::from_items(
                trnm_consensus_types::RootKind::Receipts,
                &receipts,
                index as u32,
            )
            .map_err(|e| anyhow!("receipt proof: {e:?}"))?;
            let package = trnm_tx_lifecycle_v0::NativeTxProofPackageV1 {
                target_header: header
                    .try_cev0_bytes()
                    .map_err(|e| anyhow!("target header: {e:?}"))?,
                finality_proof: proof
                    .try_cev0_bytes()
                    .map_err(|e| anyhow!("finality bytes: {e:?}"))?,
                transaction: transaction.clone(),
                execution_receipt: receipts[index].clone(),
                index: index as u32,
                item_count: transactions.len() as u32,
                payload_siblings: payload.siblings().to_vec(),
                receipt_siblings: receipt.siblings().to_vec(),
            };
            let encoded = package.encode()?;
            let stored = StoredProofV1 {
                schema: "trnm.native-stored-proof.v2".to_owned(),
                profile_sha256: hex::encode(self.profile.digest_v1()?),
                native_tx_hash: hex::encode(hash),
                parent_header_hex: hex::encode(
                    parent
                        .try_cev0_bytes()
                        .map_err(|e| anyhow!("native parent encode: {e}"))?,
                ),
                package_hex: hex::encode(encoded),
            };
            self.proof_reader_v1()
                .verify_stored_proof_v1(&stored, hash)?;
            // No claimed commit is published before this historical proof is
            // durable. A subsequent WAL failure leaves an explicit handoff.
            self.persist_artifact_v1(
                &self.root.join(format!("proof-{}.json", hex::encode(hash))),
                &serde_json::to_vec(&stored)?,
            )?;
            #[cfg(test)]
            if self.cut_after_proof {
                return Err(anyhow!("test cut after durable proof before WAL commit"));
            }
            if let Some(mut admission) = self.in_flight.remove(&hash) {
                authority.commit_native_admission_with_finality_v1(
                    &mut self.admission,
                    &mut admission,
                    proof,
                    parent.timestamp_ms(),
                )?;
            }
        }
        self.last_archived_finalized_height = header.height().get();
        Ok(())
    }
    fn proof_reader_v1(&self) -> NativeProofReaderV1 {
        NativeProofReaderV1 {
            root: self.root.clone(),
            profile: self.profile.clone(),
            set: self.set.clone(),
        }
    }
}

fn record_response_with_reader_v1(
    reader: &NativeProofReaderV1,
    record: &NativeAdmissionRecordV1,
) -> Result<Value> {
    let proof_verified = if record.status() == NativeAdmissionStatusV1::Committed {
        let stored = reader.read_stored_v1(record.native_tx_hash())?;
        reader.verify_stored_proof_v1(&stored, record.native_tx_hash())?;
        true
    } else {
        false
    };
    Ok(json!({
        "native_tx_hash": hex::encode(record.native_tx_hash()),
        "receive_sequence": record.receive_sequence().to_string(),
        "status": match record.status() {
            NativeAdmissionStatusV1::Pending => "pending",
            NativeAdmissionStatusV1::InFlight => "in_flight",
            NativeAdmissionStatusV1::Committed => "committed",
            NativeAdmissionStatusV1::Expired => "expired",
            NativeAdmissionStatusV1::Rejected => "rejected",
        },
        "proof_verified": proof_verified,
        "m05_intent_binding": false
    }))
}

#[derive(Clone)]
struct NativeProofReaderV1 {
    root: PathBuf,
    profile: NativeClientProfileV1,
    set: ValidatorSet,
}
impl NativeProofReaderV1 {
    fn read_query_reply_v1(&self, request: Request, finalized: u64) -> Value {
        let id = request.context().1.to_owned();
        match request {
            Request::Proof { data, .. } => match hash32(&data.native_tx_hash) {
                Ok(hash) => self.proof_reply_v1(&id, hash),
                Err(_) => self.error_reply(&id, "invalid_request", false),
            },
            Request::SyncManifest { data, .. } => {
                if data.target_height > finalized {
                    return self.error_reply(&id, "not_finalized", true);
                }
                match crate::native_replay_sync_v1::manifest(
                    &self.root,
                    &self.set,
                    self.profile.digest_v1().expect("validated profile"),
                    data.target_height,
                ) {
                    Ok(manifest) => self.reply(&id, json!(manifest)),
                    Err(_) => self.error_reply(&id, "sync_unavailable", false),
                }
            }
            Request::SyncChunk { data, .. } => {
                if data.height > finalized {
                    return self.error_reply(&id, "not_finalized", true);
                }
                match crate::native_replay_sync_v1::chunk(&self.root, data.height, data.index, &data.record_sha256) {
                    Ok(bytes) => self.reply(&id, json!({"height":data.height,"index":data.index,"record_sha256":data.record_sha256,"bytes_hex":hex::encode(bytes)})),
                    Err(_) => self.error_reply(&id, "sync_unavailable", false),
                }
            }
            _ => self.error_reply(&id, "invalid_request", false),
        }
    }
    fn reply(&self, id: &str, data: Value) -> Value {
        json!({"schema":"trnm.native-client.response.v1","request_id":id,"candidate_only":true,"chain_id":self.set.chain_id().as_str(),"genesis_hash":hex::encode(self.set.genesis_hash().as_bytes()),"profile_sha256":hex::encode(self.profile.digest_v1().expect("validated canonical profile")),"ok":true,"data":data})
    }
    fn error_reply(&self, id: &str, code: &str, retryable: bool) -> Value {
        let mut reply = self.reply(id, Value::Null);
        reply["ok"] = json!(false);
        reply.as_object_mut().unwrap().remove("data");
        reply["error"] = json!({"code":code,"retryable":retryable});
        reply
    }
    fn verify_stored_proof_v1(&self, stored: &StoredProofV1, hash: [u8; 32]) -> Result<Vec<u8>> {
        ensure!(
            stored.schema == "trnm.native-stored-proof.v2"
                && stored.profile_sha256 == hex::encode(self.profile.digest_v1()?)
                && stored.native_tx_hash == hex::encode(hash),
            "stored proof context mismatch"
        );
        let encoded = canonical_hex(
            &stored.package_hex,
            trnm_tx_lifecycle_v0::MAX_NATIVE_TX_PROOF_BYTES_V1,
        )?;
        let parent = canonical_hex(&stored.parent_header_hex, 16 * 1024)?;
        let parameters = trnm_consensus_types::ConsensusParametersV0::reference_shadow_v0();
        let verified = trnm_tx_lifecycle_v0::verify_native_tx_inclusion_with_parent_header_v1(
            &encoded,
            &parent,
            trnm_tx_lifecycle_v0::NativeTxParentHeaderContextV1 {
                trusted_validator_set: &self.set,
                trusted_parameters: &parameters,
                maximum_transactions: self.profile.maximum_batch_transactions as u32,
                maximum_proof_bytes: trnm_tx_lifecycle_v0::MAX_NATIVE_TX_PROOF_BYTES_V1,
            },
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::for_validator_set(
                &parameters,
                &self.set,
            ),
        )?;
        let built = trnm_application_tx_builder_v0::BuiltCanonicalTxV0::from_exact_outer_bytes_v0(
            verified.native_transaction_bytes(),
        )?;
        ensure!(
            built.envelope().tx_hash()? == hash,
            "stored proof does not authenticate requested native hash"
        );
        Ok(encoded)
    }
    fn read_stored_v1(&self, hash: [u8; 32]) -> Result<StoredProofV1> {
        let path = self.root.join(format!("proof-{}.json", hex::encode(hash)));
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.len() <= RESPONSE_MAX as u64,
            "stored proof file bound"
        );
        let mut bytes = Vec::new();
        File::open(path)?
            .take(RESPONSE_MAX as u64 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= RESPONSE_MAX, "stored proof file grew");
        let stored: StoredProofV1 = serde_json::from_slice(&bytes)?;
        ensure!(
            serde_json::to_vec(&stored)? == bytes,
            "stored proof bytes changed"
        );
        Ok(stored)
    }
    fn proof_reply_v1(&self, id: &str, hash: [u8; 32]) -> Value {
        let result = self.read_stored_v1(hash).and_then(|stored| {
            self.verify_stored_proof_v1(&stored, hash)
                .map(|package| (package, stored.parent_header_hex))
        });
        match result{Ok((package,parent_header_hex))=>self.reply(id,json!({"parent_header_hex":parent_header_hex,"native_tx_hash":hex::encode(hash),"proof_class":"poco-three-chain-v0","package_hex":hex::encode(package),"proof_verified":true,"m05_intent_binding":false})),Err(_)=>self.error_reply(id,"proof_unavailable",true)}
    }
}
#[derive(serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredProofV1 {
    schema: String,
    profile_sha256: String,
    native_tx_hash: String,
    parent_header_hex: String,
    package_hex: String,
}

fn valid_request_context(schema: &str, id: &str) -> bool {
    schema == REQUEST_SCHEMA
        && !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}
fn frame_response(reply: &Value) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(reply)?;
    ensure!(bytes.len() <= RESPONSE_MAX, "native response exceeds bound");
    let mut framed = (bytes.len() as u32).to_be_bytes().to_vec();
    framed.extend(bytes);
    Ok(framed)
}

/// Own only this read response's socket; no mutable application or signing state.
struct ReadQueryConnectionV1(UnixStream);
impl Drop for ReadQueryConnectionV1 {
    fn drop(&mut self) {
        let _ = self.0.shutdown(std::net::Shutdown::Both);
    }
}

fn write_read_reply_v1(stream: &mut UnixStream, reply: &Value, deadline: Instant) -> Result<()> {
    let framed = frame_response(reply)?;
    let mut remaining = framed.as_slice();
    while !remaining.is_empty() {
        ensure!(
            Instant::now() < deadline,
            "native read response deadline expired"
        );
        match stream.write(&remaining[..remaining.len().min(IO_SLICE)]) {
            Ok(0) => return Err(anyhow!("native read response peer closed")),
            Ok(count) => remaining = &remaining[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                let budget = deadline
                    .checked_duration_since(Instant::now())
                    .filter(|duration| !duration.is_zero())
                    .context("native read response deadline expired")?;
                let timeout = rustix::event::Timespec::try_from(budget)?;
                let mut poll = [rustix::event::PollFd::new(
                    &*stream,
                    rustix::event::PollFlags::OUT,
                )];
                match rustix::event::poll(&mut poll, Some(&timeout)) {
                    Ok(0) => return Err(anyhow!("native read response deadline expired")),
                    Ok(_) => {}
                    Err(error) if error == rustix::io::Errno::INTR => continue,
                    Err(error) => return Err(error.into()),
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod read_delivery_tests {
    use super::*;

    #[test]
    fn read_reply_expired_budget_writes_nothing_v1() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        reader.set_nonblocking(true).unwrap();
        assert!(write_read_reply_v1(&mut writer, &json!({"ok":true}), Instant::now()).is_err());
        let mut byte = [0];
        assert_eq!(
            reader.read(&mut byte).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn read_reply_nonreading_peer_has_one_deadline_v1() {
        let (mut writer, _reader) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        let reply = json!({"payload":"x".repeat(4 * 1024 * 1024)});
        let started = Instant::now();
        assert!(
            write_read_reply_v1(&mut writer, &reply, started + Duration::from_millis(150)).is_err()
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn read_reply_closed_peer_is_local_error_v1() {
        let (mut writer, reader) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        drop(reader);
        assert!(write_read_reply_v1(
            &mut writer,
            &json!({"ok":true}),
            Instant::now() + Duration::from_secs(1)
        )
        .is_err());
    }

    #[test]
    fn read_query_connection_drop_closes_cloned_socket_v1() {
        let (writer, mut reader) = UnixStream::pair().unwrap();
        let retained = writer.try_clone().unwrap();
        drop(ReadQueryConnectionV1(writer));
        reader
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        assert_eq!(reader.read(&mut [0]).unwrap(), 0);
        drop(retained);
    }
}

#[cfg(test)]
mod finite_capacity_tests_v1 {
    use super::*;

    #[test]
    fn reserve_counts_rotation_tail_and_maximum_framed_transaction() {
        let temp = tempfile::tempdir().unwrap();
        let mut profile = crate::native_client_profile::generate_isolated_native_client_profile_v1(
            &temp.path().join("keys"),
            "capacity-chain",
        )
        .unwrap();
        profile.maximum_pending = 256;
        profile.maximum_outer_bytes = 1024;
        profile.maximum_batch_bytes = 4 + 2 * (1024 + 4);
        profile.maximum_batch_transactions = 64;
        assert_eq!(finite_pending_capacity_v1(&profile, 4, 3, 8).unwrap(), 0);
        assert_eq!(finite_pending_capacity_v1(&profile, 4, 3, 9).unwrap(), 2);
        assert_eq!(finite_pending_capacity_v1(&profile, 4, 3, 13).unwrap(), 4);
        profile.maximum_batch_bytes -= 1;
        assert_eq!(finite_pending_capacity_v1(&profile, 4, 3, 9).unwrap(), 1);
        profile.maximum_batch_transactions = 1;
        assert_eq!(finite_pending_capacity_v1(&profile, 4, 3, 13).unwrap(), 2);
        assert_eq!(
            finite_pending_capacity_v1(&profile, 4, 0, u64::MAX).unwrap(),
            256
        );
        for parent in 0..20 {
            let current = finite_pending_capacity_v1(&profile, 4, parent, 20).unwrap();
            let next = finite_pending_capacity_v1(&profile, 4, parent + 1, 20).unwrap();
            assert!(next <= current);
        }
        assert_eq!(finite_pending_capacity_v1(&profile, 4, 21, 20).unwrap(), 0);
        assert!(finite_pending_capacity_v1(&profile, 0, 0, 20).is_err());
        profile.maximum_outer_bytes = usize::MAX;
        assert!(finite_pending_capacity_v1(&profile, 4, 0, 20).is_err());
    }
}
