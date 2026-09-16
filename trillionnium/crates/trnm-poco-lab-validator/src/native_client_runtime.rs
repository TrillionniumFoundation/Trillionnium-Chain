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
#[serde(tag = "op", deny_unknown_fields)]
enum Request {
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
            Self::Capabilities {
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
    proof_jobs: Vec<(u64, std::thread::JoinHandle<Value>)>,
    admission: NodeOwnedTxAdmissionBoundaryV0,
    ready: VecDeque<NativePendingAdmissionV1>,
    in_flight: BTreeMap<[u8; 32], NativePendingAdmissionV1>,
    next_proposal: Instant,
    accepting: bool,
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
            let parent = stored.parent_timestamp_ms.parse::<u64>()?;
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
    pub fn last_business_height_v1(&self) -> u64 {
        self.last_business_height
    }
    pub fn drained_v1(&self, finalized: u64) -> bool {
        self.in_flight.is_empty()
            && self.ready.is_empty()
            && self.admission.queued_counts().0 == 0
            && self.last_business_height <= finalized
    }
    pub fn poll_v1(&mut self, parent_timestamp: u64, finalized_height: u64) -> Result<bool> {
        let mut progress = false;
        let mut index = 0;
        while index < self.proof_jobs.len() {
            if !self.proof_jobs[index].1.is_finished() {
                index += 1;
                continue;
            }
            let (id, job) = self.proof_jobs.swap_remove(index);
            let reply = job
                .join()
                .unwrap_or_else(|_| self.error_reply("", "proof_unavailable", true));
            if let Some(client) = self.clients.iter_mut().find(|c| c.id == id) {
                client.proof_pending = false;
                client.reply = Some(frame_response(&reply)?);
            }
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
                        if let Ok(Request::Proof {
                            schema,
                            request_id,
                            data,
                        }) = serde_json::from_slice::<Request>(&client.bytes[4..])
                        {
                            if valid_request_context(&schema, &request_id) {
                                if let Ok(hash) = hash32(&data.native_tx_hash) {
                                    if self.proof_jobs.len() < 2 {
                                        let reader = self.proof_reader_v1();
                                        let job = std::thread::Builder::new()
                                            .name("native-proof-query".to_owned())
                                            .spawn(move || {
                                                reader.proof_reply_v1(&request_id, hash)
                                            })?;
                                        self.proof_jobs.push((client.id, job));
                                        client.proof_pending = true;
                                        client.bytes.clear();
                                        self.clients.push(client);
                                        handled += 1;
                                        continue;
                                    }
                                    client.reply = Some(frame_response(&self.error_reply(
                                        &request_id,
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
                        self.handle_request(&client.bytes[4..], parent_timestamp, finalized_height)
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
    fn handle_request(&mut self, bytes: &[u8], parent: u64, finalized: u64) -> Value {
        let request: Request = match serde_json::from_slice(bytes) {
            Ok(r) => r,
            Err(_) => return self.error_reply("", "invalid_request", false),
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
            return self.error_reply(&id, "invalid_request", false);
        }
        match request {
            Request::Capabilities { data, .. } => {
                let _ = data;
                self.reply(&id,json!({"profile":self.profile.schema,"wall_clock_epoch_ms":self.profile.wall_clock_epoch_ms.to_string(),"time_domain":"milliseconds_since_profile_wall_clock_epoch","maximum_outer_bytes":self.profile.maximum_outer_bytes,"maximum_pending":self.profile.maximum_pending,"proof_class":"poco-three-chain-v0","m05_intent_binding":false}))
            }
            Request::Status { data, .. } => {
                let _ = data;
                self.reply(&id,json!({"accepting":self.accepting,"finalized_height":finalized.to_string(),"pending":self.ready.len()+self.admission.queued_counts().0,"in_flight":self.in_flight.len(),"proof_verified":false}))
            }
            Request::Submit { data, .. } => {
                let bytes =
                    match canonical_hex(&data.signed_outer_hex, self.profile.maximum_outer_bytes) {
                        Ok(b) => b,
                        Err(_) => return self.error_reply(&id, "invalid_request", false),
                    };
                // Exact durable retries remain answerable during stop/skew.
                if let Ok(built) =
                    trnm_application_tx_builder_v0::BuiltCanonicalTxV0::from_exact_outer_bytes_v0(
                        &bytes,
                    )
                {
                    if let Ok(hash) = built.envelope().tx_hash() {
                        if let Ok(Some(record)) = self.admission.native_record_v1(hash) {
                            if record.exact_outer_bytes() == bytes {
                                return self.reply(&id, record_json(&record));
                            }
                        }
                    }
                }
                if !self.accepting {
                    return self.error_reply(&id, "backpressure", true);
                }
                if !self
                    .profile
                    .proposal_timestamp_v1(parent, 60_000)
                    .is_ok_and(|(_, ready)| ready)
                {
                    return self.error_reply(&id, "time_unready", true);
                }
                match self.admission.submit_native_bytes_v1(&bytes) {
                    Ok(record) => self.reply(&id, record_json(&record)),
                    Err(NativeAdmissionErrorV1::Backpressure) => {
                        self.error_reply(&id, "backpressure", true)
                    }
                    Err(NativeAdmissionErrorV1::Uncertain) => {
                        self.error_reply(&id, "recovery_required", true)
                    }
                    Err(NativeAdmissionErrorV1::Decode) => {
                        self.error_reply(&id, "invalid_request", false)
                    }
                    Err(NativeAdmissionErrorV1::Wal(_)) => {
                        self.error_reply(&id, "recovery_required", true)
                    }
                    Err(_) => self.error_reply(&id, "admission_rejected", false),
                }
            }
            Request::Transaction { data, .. } => {
                let hash = match hash32(&data.native_tx_hash) {
                    Ok(h) => h,
                    Err(_) => return self.error_reply(&id, "invalid_request", false),
                };
                match self.admission.native_record_v1(hash) {
                    Ok(Some(record)) => self.reply(&id, record_json(&record)),
                    Ok(None) => self.error_reply(&id, "not_found", false),
                    Err(_) => self.error_reply(&id, "recovery_required", true),
                }
            }
            Request::Proof { data, .. } => match hash32(&data.native_tx_hash) {
                Ok(hash) => self.proof_reader_v1().proof_reply_v1(&id, hash),
                Err(_) => self.error_reply(&id, "invalid_request", false),
            },
        }
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
impl Drop for NativeClientRuntimeV1 {
    fn drop(&mut self) {
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
fn record_json(record: &NativeAdmissionRecordV1) -> Value {
    json!({"native_tx_hash":hex::encode(record.native_tx_hash()),"receive_sequence":record.receive_sequence().to_string(),"status":match record.status(){NativeAdmissionStatusV1::Pending=>"pending",NativeAdmissionStatusV1::InFlight=>"in_flight",NativeAdmissionStatusV1::Committed=>"committed",NativeAdmissionStatusV1::Expired=>"expired",NativeAdmissionStatusV1::Rejected=>"rejected"},"proof_verified":false,"m05_intent_binding":false})
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
    /// Capture each newly finalized ordinary tip while Core still retains its
    /// proof, persist checked packages, then resolve corresponding WAL tokens.
    pub fn observe_finality_v1(
        &mut self,
        authority: &ContinuousValidatorAuthorityV0,
    ) -> Result<()> {
        let facts = authority.facts_v0()?;
        if facts.finalized_height_v0() <= self.last_archived_finalized_height {
            return Ok(());
        }
        let query = authority.native_finalized_query_v1()?;
        let executed = query.read_v0().executed_v0();
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
        let proof = query.proof_v0();
        let header = proof.proof_v0().finalized_block().header();
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
                    .proof_v0()
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
                schema: "trnm.native-stored-proof.v1".to_owned(),
                profile_sha256: hex::encode(self.profile.digest_v1()?),
                native_tx_hash: hex::encode(hash),
                parent_timestamp_ms: proof.authenticated_parent_timestamp_ms_v0().to_string(),
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
                authority.commit_native_admission_at_finalized_tip_v1(
                    &mut self.admission,
                    &mut admission,
                )?;
            }
        }
        self.last_archived_finalized_height = facts.finalized_height_v0();
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
#[derive(Clone)]
struct NativeProofReaderV1 {
    root: PathBuf,
    profile: NativeClientProfileV1,
    set: ValidatorSet,
}
impl NativeProofReaderV1 {
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
            stored.schema == "trnm.native-stored-proof.v1"
                && stored.profile_sha256 == hex::encode(self.profile.digest_v1()?)
                && stored.native_tx_hash == hex::encode(hash),
            "stored proof context mismatch"
        );
        let encoded = canonical_hex(
            &stored.package_hex,
            trnm_tx_lifecycle_v0::MAX_NATIVE_TX_PROOF_BYTES_V1,
        )?;
        let package = trnm_tx_lifecycle_v0::NativeTxProofPackageV1::decode_exact(
            &encoded,
            trnm_tx_lifecycle_v0::MAX_NATIVE_TX_PROOF_BYTES_V1,
        )?;
        let header = trnm_consensus_types::decode_block_header_v0_exact(&package.target_header)
            .map_err(|e| anyhow!("stored native header: {e:?}"))?;
        let parent_time = stored.parent_timestamp_ms.parse::<u64>()?;
        ensure!(
            parent_time.to_string() == stored.parent_timestamp_ms,
            "noncanonical stored parent time"
        );
        let expected = trnm_consensus_crypto::FinalityExpectationV0 {
            block_id: header.id(),
            height: header.height(),
            state_root: header.state_root(),
            receipts_root: header.receipts_root(),
            evidence_root: header.evidence_root(),
            parent_id: header.parent_id(),
            parent_height: trnm_consensus_types::Height::new(
                header
                    .height()
                    .get()
                    .checked_sub(1)
                    .context("proof height zero")?,
            ),
            parent_timestamp_ms: parent_time,
        };
        let parameters = trnm_consensus_types::ConsensusParametersV0::reference_shadow_v0();
        let verified = trnm_tx_lifecycle_v0::verify_native_tx_inclusion_v1(
            &encoded,
            trnm_tx_lifecycle_v0::NativeTxProofContextV1 {
                trusted_validator_set: &self.set,
                trusted_parameters: &parameters,
                expected,
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
        let result = self
            .read_stored_v1(hash)
            .and_then(|stored| self.verify_stored_proof_v1(&stored, hash));
        match result{Ok(package)=>self.reply(id,json!({"native_tx_hash":hex::encode(hash),"proof_class":"poco-three-chain-v0","package_hex":hex::encode(package),"proof_verified":true,"m05_intent_binding":false})),Err(_)=>self.error_reply(id,"proof_unavailable",true)}
    }
}
#[derive(serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredProofV1 {
    schema: String,
    profile_sha256: String,
    native_tx_hash: String,
    parent_timestamp_ms: String,
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
