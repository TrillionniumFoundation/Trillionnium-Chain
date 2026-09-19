//! M13 candidate: bounded finalized-body transfer and actual schema-3 replay.
//! This never imports replay sets or returns consensus/signing authority.
use anyhow::{anyhow, ensure, Context, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use trnm_consensus_types::{BlockKind, Cev0AdmissionBudgetV0, FinalityProofV0};
use trnm_native_application::{
    ApplicationHeadV0, BlockIdV0, ChainIdV0, GenesisHashV0, Hash32V0, HeightV0,
    NativeApplicationGenesisRequestV0, NativeApplicationV0, NativeBlockExecutionRequestV0,
    NativeBlockExecutionResultV0, NativeExpectedBlockCommitmentsV0, ReceiptsRootV0, StateRootV0,
    ValidatorSetIdV0,
};
use trnm_native_execution_v0::{
    DurableNativeApplicationV0, FinalizedNativeApplicationCommitRequestV0,
    NativeApplicationConfigV0,
};

pub const MAX_RECORDS: u64 = 128;
pub const MAX_RECORD_BYTES: usize = 1024 * 1024;
pub const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
pub const CHUNK_BYTES: usize = 64 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 128 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReplayRecordV1 {
    pub schema: String,
    pub finality_hex: String,
    pub transactions_hex: Vec<String>,
}
impl ReplayRecordV1 {
    pub fn from_finalized(proof: &FinalityProofV0, transactions: &[Vec<u8>]) -> Result<Self> {
        let record = Self {
            schema: "trnm.native-replay-record.v1".into(),
            finality_hex: hex::encode(
                proof
                    .try_cev0_bytes()
                    .map_err(|e| anyhow!("finality encoding: {e}"))?,
            ),
            transactions_hex: transactions.iter().map(hex::encode).collect(),
        };
        ensure!(
            serde_json::to_vec(&record)?.len() <= MAX_RECORD_BYTES,
            "sync record exceeds candidate bound"
        );
        Ok(record)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecordDescriptorV1 {
    pub bytes: u64,
    pub sha256: String,
    pub chunk_sha256: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReplayManifestV1 {
    pub schema: String,
    pub chain_id: String,
    pub genesis_hash: String,
    pub profile_sha256: String,
    pub target_height: u64,
    pub target_block_id: String,
    pub records: Vec<RecordDescriptorV1>,
}
impl ReplayManifestV1 {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == "trnm.native-replay-manifest.v1"
                && (1..=MAX_RECORDS).contains(&self.target_height)
                && self.records.len() as u64 == self.target_height,
            "sync manifest shape"
        );
        hash32(&self.genesis_hash)?;
        hash32(&self.profile_sha256)?;
        hash32(&self.target_block_id)?;
        let mut total = 0u64;
        for record in &self.records {
            ensure!(
                record.bytes > 0 && record.bytes <= MAX_RECORD_BYTES as u64,
                "sync record byte bound"
            );
            hash32(&record.sha256)?;
            ensure!(
                record.chunk_sha256.len() == (record.bytes as usize).div_ceil(CHUNK_BYTES),
                "sync chunk hash cardinality"
            );
            for digest in &record.chunk_sha256 {
                hash32(digest)?;
            }
            total = total
                .checked_add(record.bytes)
                .context("sync total overflow")?;
        }
        ensure!(total <= MAX_TOTAL_BYTES, "sync total byte bound");
        Ok(())
    }
    pub fn digest(&self) -> Result<[u8; 32]> {
        self.validate()?;
        Ok(Sha256::digest(serde_json::to_vec(self)?).into())
    }
}
pub(crate) fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= max as u64 && metadata.nlink() == 1,
        "sync file kind/size/link bound"
    );
    let mut bytes = Vec::new();
    file.take(max as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= max && bytes.len() as u64 == metadata.len(),
        "sync file changed or grew"
    );
    Ok(bytes)
}
fn hash32(s: &str) -> Result<[u8; 32]> {
    decode_hex(s, 32)?
        .try_into()
        .map_err(|_| anyhow!("sync hash size"))
}
fn decode_hex(s: &str, max: usize) -> Result<Vec<u8>> {
    ensure!(
        s.len() <= max * 2
            && s.len().is_multiple_of(2)
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "sync canonical hex bound"
    );
    Ok(hex::decode(s)?)
}
fn private_dir(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) => ensure!(
            m.is_dir()
                && !m.file_type().is_symlink()
                && m.uid() == rustix::process::geteuid().as_raw()
                && m.mode() & 0o777 == 0o700,
            "sync directory must be private real owner directory"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::DirBuilder::new().mode(0o700).create(path)?;
            File::open(path.parent().context("sync directory parent")?)?.sync_all()?;
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}
fn cleanup_interrupted_write(path: &Path) -> Result<()> {
    let parent = path.parent().context("sync parent")?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .context("sync filename")?;
    let temporary = parent.join(format!(".{name}.sync-next"));
    if let Ok(next) = fs::symlink_metadata(&temporary) {
        ensure!(
            next.is_file()
                && !next.file_type().is_symlink()
                && next.uid() == rustix::process::geteuid().as_raw()
                && next.len() <= MAX_RECORD_BYTES as u64,
            "sync temporary file shape"
        );
        if let Ok(committed) = fs::symlink_metadata(path) {
            ensure!(
                next.dev() == committed.dev() && next.ino() == committed.ino() && next.nlink() == 2,
                "sync temporary is not exact published alias"
            );
        } else {
            ensure!(
                next.nlink() == 1,
                "sync unpublished temporary is externally linked"
            );
        }
        // Only this exact deterministic temporary is disposable. A published
        // alias retains the canonical inode; an interrupted unpublished write
        // has no authority and is reconstructed from the caller's exact bytes.
        fs::remove_file(&temporary)?;
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}
fn persist_exact(path: &Path, bytes: &[u8]) -> Result<()> {
    cleanup_interrupted_write(path)?;
    let parent = path.parent().context("sync parent")?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .context("sync filename")?;
    let temporary = parent.join(format!(".{name}.sync-next"));
    if fs::symlink_metadata(path).is_ok() {
        ensure!(
            read_bounded(path, bytes.len())? == bytes,
            "sync immutable file substitution"
        );
        File::open(path)?.sync_all()?;
        File::open(parent)?.sync_all()?;
        return Ok(());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)?;
    #[cfg(test)]
    if test_persist_cut_matches_v1("partial", path) {
        file.write_all(&bytes[..bytes.len() / 2])?;
        file.sync_all()?;
        test_persist_cut_v1("partial", path);
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    #[cfg(test)]
    test_persist_cut_v1("file-synced", path);
    fs::hard_link(&temporary, path)?;
    #[cfg(test)]
    test_persist_cut_v1("linked", path);
    File::open(parent)?.sync_all()?;
    fs::remove_file(&temporary)?;
    File::open(parent)?.sync_all()?;
    #[cfg(test)]
    test_persist_cut_v1("published", path);
    Ok(())
}
fn record_path(root: &Path, height: u64) -> PathBuf {
    root.join(format!("replay-{height:03}.json"))
}
/// Provider data comes from actual finalized readback, including empty blocks.
pub(crate) fn persist_record(
    root: &Path,
    proof: &FinalityProofV0,
    transactions: &[Vec<u8>],
) -> Result<()> {
    let height = proof.finalized_block().header().height().get();
    // A bounded candidate service stops extending its replay export at its cap;
    // consensus and admission continue unchanged above that height.
    if height > MAX_RECORDS {
        return Ok(());
    }
    ensure!(height > 0, "no genesis replay record");
    persist_exact(
        &record_path(root, height),
        &serde_json::to_vec(&ReplayRecordV1::from_finalized(proof, transactions)?)?,
    )
}
pub(crate) fn manifest(
    root: &Path,
    set: &trnm_consensus_types::ValidatorSet,
    profile: [u8; 32],
    target: u64,
) -> Result<ReplayManifestV1> {
    ensure!((1..=MAX_RECORDS).contains(&target), "sync target bound");
    let mut records = Vec::new();
    let mut target_id = String::new();
    for height in 1..=target {
        let bytes = read_bounded(&record_path(root, height), MAX_RECORD_BYTES)?;
        if height == target {
            // Receivers authenticate this ID with the complete strict replay.
            let id = read_bounded(&root.join(format!("replay-{height:03}.id")), 64)?;
            target_id = String::from_utf8(id)?;
            hash32(&target_id)?;
        }
        records.push(RecordDescriptorV1 {
            bytes: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(&bytes)),
            chunk_sha256: bytes
                .chunks(CHUNK_BYTES)
                .map(|chunk| hex::encode(Sha256::digest(chunk)))
                .collect(),
        });
    }
    let result = ReplayManifestV1 {
        schema: "trnm.native-replay-manifest.v1".into(),
        chain_id: set.chain_id().as_str().into(),
        genesis_hash: hex::encode(set.genesis_hash().as_bytes()),
        profile_sha256: hex::encode(profile),
        target_height: target,
        target_block_id: target_id,
        records,
    };
    result.validate()?;
    Ok(result)
}
pub(crate) fn persist_export(
    root: &Path,
    proof: &FinalityProofV0,
    transactions: &[Vec<u8>],
) -> Result<()> {
    // Export availability cannot turn a valid oversized consensus batch into
    // a node failure. The explicit small sync profile reports a missing record.
    if ReplayRecordV1::from_finalized(proof, transactions).is_err() {
        return Ok(());
    }
    persist_record(root, proof, transactions)?;
    let h = proof.finalized_block().header();
    if h.height().get() <= MAX_RECORDS {
        persist_exact(
            &root.join(format!("replay-{:03}.id", h.height().get())),
            hex::encode(h.id().as_bytes()).as_bytes(),
        )?;
    }
    Ok(())
}
pub(crate) fn chunk(root: &Path, height: u64, index: u64, expected_hash: &str) -> Result<Vec<u8>> {
    ensure!(
        (1..=MAX_RECORDS).contains(&height) && index < (MAX_RECORD_BYTES / CHUNK_BYTES) as u64,
        "sync chunk coordinate"
    );
    hash32(expected_hash)?;
    let bytes = read_bounded(&record_path(root, height), MAX_RECORD_BYTES)?;
    ensure!(
        hex::encode(Sha256::digest(&bytes)) == expected_hash,
        "sync record hash changed"
    );
    let start = index as usize * CHUNK_BYTES;
    ensure!(start < bytes.len(), "sync chunk out of range");
    Ok(bytes[start..(start + CHUNK_BYTES).min(bytes.len())].to_vec())
}

/// One locked application-only replica. Disk bytes are never proof authority.
pub struct NativeReplayReceiverV1 {
    base: PathBuf,
    root: PathBuf,
    root_file: File,
    stage_file: File,
    _lock: File,
    manifest: ReplayManifestV1,
    config: Option<NativeApplicationConfigV0>,
}
impl NativeReplayReceiverV1 {
    pub fn open(
        root: &Path,
        config: NativeApplicationConfigV0,
        profile: [u8; 32],
        expected_target: u64,
        manifest: ReplayManifestV1,
    ) -> Result<Self> {
        manifest.validate()?;
        ensure!(
            manifest.target_height == expected_target
                && manifest.chain_id == config.chain_id_v0()
                && hash32(&manifest.genesis_hash)? == config.genesis_hash_v0()
                && hash32(&manifest.profile_sha256)? == profile
                && config.validator_set_v0().epoch().get() == 0
                && config.initial_block_id_v0() == config.genesis_hash_v0(),
            "sync independent genesis/profile/target mismatch"
        );
        private_dir(root)?;
        let root = root.canonicalize()?;
        let root_file = File::open(&root)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(root.join("receiver.lock"))?;
        ensure!(
            lock.metadata()?.is_file() && lock.metadata()?.nlink() == 1,
            "sync lock file shape"
        );
        lock.try_lock_exclusive()
            .context("sync receiver already owned")?;
        let encoded = serde_json::to_vec(&manifest)?;
        ensure!(
            encoded.len() <= MAX_MANIFEST_BYTES,
            "sync manifest byte bound"
        );
        let base = root;
        let stage_name = format!("stage-{}", hex::encode(manifest.digest()?));
        let root = base.join(&stage_name);
        let mut stage_count = 0;
        for entry in fs::read_dir(&base)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().context("sync namespace filename")?;
            if let Some(digest) = name.strip_prefix("stage-") {
                hash32(digest)?;
                let metadata = fs::symlink_metadata(entry.path())?;
                ensure!(
                    metadata.is_dir() && !metadata.file_type().is_symlink(),
                    "sync stage namespace shape"
                );
                stage_count += 1;
                ensure!(stage_count <= 2, "sync staging capacity exhausted");
            }
        }
        if fs::symlink_metadata(&root).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
            ensure!(
                stage_count < 2,
                "sync staging capacity exhausted; choose a fresh explicit replica directory"
            );
            ensure!(
                !base.join("CURRENT").exists(),
                "sync completed replica already selects another manifest"
            );
        }
        private_dir(&root)?;
        let stage_file = File::open(&root)?;
        persist_exact(&root.join("manifest.json"), &encoded)?;
        #[cfg(test)]
        test_replay_cut_v1("manifest-published", &root);
        Ok(Self {
            base,
            root,
            root_file,
            stage_file,
            _lock: lock,
            manifest,
            config: Some(config),
        })
    }
    fn fresh_root(&self) -> Result<()> {
        let pinned = self.root_file.metadata()?;
        let current = fs::symlink_metadata(&self.base)?;
        ensure!(
            current.is_dir()
                && !current.file_type().is_symlink()
                && current.dev() == pinned.dev()
                && current.ino() == pinned.ino()
                && current.uid() == rustix::process::geteuid().as_raw()
                && current.mode() & 0o777 == 0o700,
            "sync receiver root replaced"
        );
        let pinned_stage = self.stage_file.metadata()?;
        let current_stage = fs::symlink_metadata(&self.root)?;
        ensure!(
            current_stage.is_dir()
                && !current_stage.file_type().is_symlink()
                && current_stage.dev() == pinned_stage.dev()
                && current_stage.ino() == pinned_stage.ino(),
            "sync stage root replaced"
        );
        let lock = self._lock.metadata()?;
        let named = fs::symlink_metadata(self.base.join("receiver.lock"))?;
        ensure!(
            named.is_file()
                && !named.file_type().is_symlink()
                && named.dev() == lock.dev()
                && named.ino() == lock.ino()
                && named.nlink() == 1,
            "sync receiver lock replaced"
        );
        Ok(())
    }
    pub fn application_path(&self) -> PathBuf {
        self.root.join("application.sqlite")
    }
    fn chunk_path(&self, height: u64, index: usize) -> PathBuf {
        self.root.join(format!("chunk-{height:03}-{index:02}"))
    }
    fn descriptor(&self, height: u64) -> Result<&RecordDescriptorV1> {
        ensure!(height > 0, "sync height zero");
        self.manifest
            .records
            .get((height - 1) as usize)
            .context("sync height outside manifest")
    }
    pub fn has_chunk(&self, height: u64, index: usize) -> Result<bool> {
        self.fresh_root()?;
        let descriptor = self.descriptor(height)?;
        let start = index
            .checked_mul(CHUNK_BYTES)
            .context("sync index overflow")?;
        ensure!(
            start < descriptor.bytes as usize,
            "sync chunk outside record"
        );
        let path = self.chunk_path(height, index);
        cleanup_interrupted_write(&path)?;
        if fs::symlink_metadata(&path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
            return Ok(false);
        }
        let bytes = read_bounded(&path, CHUNK_BYTES)?;
        ensure!(
            bytes.len() == CHUNK_BYTES.min(descriptor.bytes as usize - start)
                && hex::encode(Sha256::digest(&bytes)) == descriptor.chunk_sha256[index],
            "sync persisted chunk length/hash mismatch"
        );
        Ok(true)
    }
    pub fn accept_chunk(&self, height: u64, index: usize, bytes: &[u8]) -> Result<()> {
        self.fresh_root()?;
        let descriptor = self.descriptor(height)?;
        let start = index
            .checked_mul(CHUNK_BYTES)
            .context("sync index overflow")?;
        ensure!(
            start < descriptor.bytes as usize
                && bytes.len() == CHUNK_BYTES.min(descriptor.bytes as usize - start)
                && hex::encode(Sha256::digest(bytes)) == descriptor.chunk_sha256[index],
            "sync chunk exact length/hash"
        );
        persist_exact(&self.chunk_path(height, index), bytes)
    }
    fn record_bytes(&self, height: u64) -> Result<Vec<u8>> {
        let descriptor = self.descriptor(height)?;
        let mut bytes = Vec::with_capacity(descriptor.bytes as usize);
        for index in 0..(descriptor.bytes as usize).div_ceil(CHUNK_BYTES) {
            let path = self.chunk_path(height, index);
            cleanup_interrupted_write(&path)?;
            let chunk = read_bounded(&path, CHUNK_BYTES)?;
            ensure!(
                hex::encode(Sha256::digest(&chunk)) == descriptor.chunk_sha256[index],
                "sync persisted chunk hash mismatch"
            );
            bytes.extend(chunk);
        }
        ensure!(
            bytes.len() as u64 == descriptor.bytes
                && hex::encode(Sha256::digest(&bytes)) == descriptor.sha256,
            "sync record incomplete or substituted"
        );
        Ok(bytes)
    }
    /// Reverify the complete received prefix every restart. Native K is the
    /// authoritative progress cursor, and every K row is checked against proof.
    pub fn replay_and_publish(
        &mut self,
        reopen_config: NativeApplicationConfigV0,
    ) -> Result<ApplicationHeadV0> {
        self.fresh_root()?;
        let path = self.root.join("application.sqlite");
        let app = DurableNativeApplicationV0::open(
            &path,
            self.config
                .take()
                .context("sync replay already consumed; reopen receiver after an error")?,
        )?;
        let config = app.config_v0();
        let genesis = config.chain_genesis_facts_v0();
        if app.confirmed_committed_head_v0().is_err() {
            app.initialize(NativeApplicationGenesisRequestV0::new(
                ChainIdV0::new(config.chain_id_v0())?,
                GenesisHashV0::new(config.genesis_hash_v0())?,
                Hash32V0::new(config.chain_descriptor_hash_v0()),
                Hash32V0::new(config.signer_policy_commitment_v0()),
                StateRootV0::new(genesis.initial_state_root_v0())?,
                config.initial_validator_set().clone(),
            )?)?;
        }
        app.confirm_ordinary_schema_v0()?;
        let start = app.confirmed_committed_head_v0()?;
        ensure!(
            start.height().get() <= self.manifest.target_height,
            "sync application beyond pinned target"
        );
        let mut previous_id = config.initial_block_id_v0();
        let mut previous_time = 0;
        for height in 1..=self.manifest.target_height {
            self.fresh_root()?;
            let raw = self.record_bytes(height)?;
            trnm_application_tx_builder_v0::validate_strict_json_structure_v0(&raw)?;
            let record: ReplayRecordV1 = serde_json::from_slice(&raw)?;
            ensure!(
                record.schema == "trnm.native-replay-record.v1",
                "sync record schema"
            );
            let proof_bytes = decode_hex(&record.finality_hex, MAX_RECORD_BYTES)?;
            let set = config.validator_set_v0();
            let parameters = config.consensus_parameters_v0();
            let mut budget = Cev0AdmissionBudgetV0::for_validator_set(parameters, set);
            let proof=if height==1 {trnm_consensus_types::decode_finality_proof_v0_exact_with_trusted_genesis_and_budget(&proof_bytes,set,parameters,previous_time,&mut budget)} else {trnm_consensus_types::decode_finality_proof_v0_exact_with_budget(&proof_bytes,set,parameters,previous_time,&mut budget)}.map_err(|e|anyhow!("sync finality decode: {e}"))?;
            proof
                .verify(
                    set,
                    None,
                    parameters,
                    previous_time,
                    &trnm_consensus_crypto::StrictEd25519Verifier,
                )
                .map_err(|e| anyhow!("sync strict finality: {e}"))?;
            let header = proof.finalized_block().header();
            ensure!(
                header.height().get() == height
                    && header.parent_id().as_bytes() == &previous_id
                    && header.epoch().get() == 0
                    && [proof.finalized_block(), proof.child(), proof.grandchild()]
                        .iter()
                        .all(|c| c.header().block_kind() == BlockKind::Regular),
                "sync noncontiguous or unsupported epoch/boundary"
            );
            let transactions = record
                .transactions_hex
                .iter()
                .map(|tx| decode_hex(tx, MAX_RECORD_BYTES))
                .collect::<Result<Vec<_>>>()?;
            if height <= start.height().get() {
                let row = app.read_finalized_by_height_v0(HeightV0::new(height))?;
                let request = row.executed_v0().request();
                ensure!(
                    request.block_id().as_bytes() == header.id().as_bytes()
                        && request.transactions() == transactions
                        && request.timestamp_ms() == header.timestamp_ms()
                        && request.expected().post_state_root().as_bytes()
                            == header.state_root().as_bytes()
                        && request.expected().payload_root().as_bytes()
                            == header.payload_root().as_bytes()
                        && request.expected().receipts_root().as_bytes()
                            == header.receipts_root().as_bytes()
                        && request.expected().evidence_root().as_bytes()
                            == header.evidence_root().as_bytes(),
                    "sync persisted application differs from verified prefix"
                );
            } else {
                let parent = app.confirmed_committed_head_v0()?;
                ensure!(
                    parent.height().get() + 1 == height
                        && parent.block_id().as_bytes() == &previous_id,
                    "sync actual application parent differs"
                );
                let expected = NativeExpectedBlockCommitmentsV0::new(
                    Hash32V0::new(*header.payload_root().as_bytes()),
                    StateRootV0::new(*header.state_root().as_bytes())?,
                    ReceiptsRootV0::new(*header.receipts_root().as_bytes())?,
                    Hash32V0::new(*header.evidence_root().as_bytes()),
                )?;
                let request = NativeBlockExecutionRequestV0::new(
                    ChainIdV0::new(config.chain_id_v0())?,
                    GenesisHashV0::new(config.genesis_hash_v0())?,
                    parent,
                    BlockIdV0::new(*header.id().as_bytes())?,
                    HeightV0::new(height),
                    header.timestamp_ms(),
                    ValidatorSetIdV0::new(*header.validator_set_id().as_bytes())?,
                    transactions,
                    expected,
                )?;
                let executed = match app.execute_block(request)? {
                    NativeBlockExecutionResultV0::Valid(executed) => *executed,
                    other => return Err(anyhow!("sync native execution rejected: {other:?}")),
                };
                #[cfg(test)]
                if height == 4 {
                    test_replay_cut_v1("native-prepared-h4", &path);
                }
                app.commit_finalized_block_v0(FinalizedNativeApplicationCommitRequestV0::new(
                    executed,
                    proof.clone(),
                    previous_time,
                ))?;
                #[cfg(test)]
                if height == 4 {
                    test_replay_cut_v1("native-committed-h4", &path);
                }
            }
            previous_id = *header.id().as_bytes();
            previous_time = header.timestamp_ms();
        }
        ensure!(
            previous_id == hash32(&self.manifest.target_block_id)?,
            "sync final target differs from pinned manifest"
        );
        let head = app.confirmed_committed_head_v0()?;
        drop(app);
        let reopened = DurableNativeApplicationV0::open(&path, reopen_config)?;
        reopened.confirm_ordinary_schema_v0()?;
        ensure!(
            reopened.confirmed_committed_head_v0()? == head,
            "sync reopened application head mismatch"
        );
        drop(reopened);
        let published = serde_json::to_vec(
            &serde_json::json!({"schema":"trnm.native-replay-current.v1","application_directory":self.root.file_name().and_then(|n|n.to_str()).context("sync stage name")?,"manifest_sha256":hex::encode(self.manifest.digest()?),"height":head.height().get(),"block_id":hex::encode(head.block_id().as_bytes()),"state_root":hex::encode(head.state_root().as_bytes()),"application_only":true,"signing_authority":false}),
        )?;
        self.fresh_root()?;
        persist_exact(&self.base.join("CURRENT"), &published)?;
        Ok(head)
    }
}

// These hooks are absent from every library/binary deployment build. Only an
// explicitly armed child test thread can pause; other parallel tests are inert.
#[cfg(test)]
thread_local! {
    static REPLAY_TEST_CUT_V1: std::cell::RefCell<Option<(String, PathBuf)>> = const {
        std::cell::RefCell::new(None)
    };
}
#[cfg(test)]
pub(crate) fn arm_replay_test_cut_v1(cut: String, marker: PathBuf) {
    REPLAY_TEST_CUT_V1.with(|slot| {
        assert!(slot.borrow().is_none());
        *slot.borrow_mut() = Some((cut, marker));
    });
}
#[cfg(test)]
fn test_persist_cut_name_v1(phase: &str, path: &Path) -> Option<String> {
    match path.file_name()?.to_str()? {
        "chunk-001-00" => Some(format!("chunk-{phase}")),
        "CURRENT" => Some(format!("current-{phase}")),
        _ => None,
    }
}
#[cfg(test)]
fn test_persist_cut_matches_v1(phase: &str, path: &Path) -> bool {
    let Some(name) = test_persist_cut_name_v1(phase, path) else {
        return false;
    };
    REPLAY_TEST_CUT_V1.with(|slot| slot.borrow().as_ref().is_some_and(|(cut, _)| *cut == name))
}
#[cfg(test)]
fn test_persist_cut_v1(phase: &str, path: &Path) {
    if let Some(name) = test_persist_cut_name_v1(phase, path) {
        test_replay_cut_v1(&name, path);
    }
}
#[cfg(test)]
fn test_replay_cut_v1(name: &str, path: &Path) {
    REPLAY_TEST_CUT_V1.with(|slot| {
        let armed = slot.borrow();
        let Some((cut, marker)) = armed.as_ref() else {
            return;
        };
        if cut != name {
            return;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(marker)
            .expect("create child crash-cut notification");
        file.write_all(
            &serde_json::to_vec(&serde_json::json!({
                "cut":name,"pid":std::process::id(),"path":path,
            }))
            .unwrap(),
        )
        .unwrap();
        file.sync_all().unwrap();
        File::open(marker.parent().unwrap())
            .unwrap()
            .sync_all()
            .unwrap();
        // The parent checks this durable marker, sends actual SIGKILL, and
        // waits for its status. No destructor/normal shutdown runs at the cut.
        loop {
            std::thread::park();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replay_publication_recovers_exact_link_cut_and_rejects_substitution() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("CURRENT");
        let next = temp.path().join(".CURRENT.sync-next");
        fs::write(&next, b"exact-published-head").unwrap();
        fs::hard_link(&next, &path).unwrap();
        persist_exact(&path, b"exact-published-head").unwrap();
        assert!(!next.exists());
        assert_eq!(read_bounded(&path, 64).unwrap(), b"exact-published-head");
        assert!(persist_exact(&path, b"different-head").is_err());
        fs::write(&next, b"alien-alias").unwrap();
        assert!(persist_exact(&path, b"exact-published-head").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"exact-published-head");
    }
    #[test]
    fn replay_unpublished_partial_write_is_reconstructed_but_links_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("chunk-001-00");
        let next = temp.path().join(".chunk-001-00.sync-next");
        fs::write(&next, b"partial").unwrap();
        persist_exact(&path, b"complete-exact-chunk").unwrap();
        assert_eq!(read_bounded(&path, 64).unwrap(), b"complete-exact-chunk");
        let link = temp.path().join("symlink");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_bounded(&link, 64).is_err());
        let hard = temp.path().join("hardlink");
        fs::hard_link(&path, &hard).unwrap();
        assert!(read_bounded(&path, 64).is_err());
        let oversized = temp.path().join("oversized");
        fs::write(&oversized, vec![0; 65]).unwrap();
        assert!(read_bounded(&oversized, 64).is_err());
    }
    #[test]
    fn replay_manifest_closed_bounds_reject_empty_overflow_and_noncanonical_hash() {
        let mut manifest = ReplayManifestV1 {
            schema: "trnm.native-replay-manifest.v1".into(),
            chain_id: "test".into(),
            genesis_hash: hex::encode([1; 32]),
            profile_sha256: hex::encode([2; 32]),
            target_height: 1,
            target_block_id: hex::encode([3; 32]),
            records: vec![RecordDescriptorV1 {
                bytes: 1,
                sha256: hex::encode([4; 32]),
                chunk_sha256: vec![hex::encode([4; 32])],
            }],
        };
        manifest.validate().unwrap();
        manifest.records[0].bytes = 0;
        assert!(manifest.validate().is_err());
        manifest.records[0].bytes = MAX_RECORD_BYTES as u64 + 1;
        assert!(manifest.validate().is_err());
        manifest.records[0].bytes = 1;
        manifest.records[0].sha256 = "AB".repeat(32);
        assert!(manifest.validate().is_err());
        manifest.records[0].sha256 = hex::encode([4; 32]);
        manifest.target_height = MAX_RECORDS + 1;
        assert!(manifest.validate().is_err());
        manifest.target_height = MAX_RECORDS;
        manifest.records = vec![
            RecordDescriptorV1 {
                bytes: MAX_RECORD_BYTES as u64,
                chunk_sha256: vec![hex::encode([4; 32]); MAX_RECORD_BYTES / CHUNK_BYTES],
                sha256: hex::encode([4; 32])
            };
            MAX_RECORDS as usize
        ];
        assert!(manifest.validate().is_err());
    }
}
