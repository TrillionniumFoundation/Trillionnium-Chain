//! Native schema-5 owner. Incremental JMT and authenticated replay deltas are
//! prepared/committed in this owner's one SQLite transaction, without snapshot
//! encoding or a second filesystem/signing authority.
use super::*;
use crate::store::incremental_store_v1 as ni;
use anyhow::Result;
use jmt::{
    storage::{HasPreimage, LeafNode, Node, NodeKey, TreeReader},
    KeyHash, RootHash,
};
#[path = "incremental_replay_v1.rs"]
mod replay;
use replay::{ReplayDelta, ReplayHead, ReplayReader};
pub(super) const SCHEMA_VERSION: u64 = 5;
const MAX_PREPARED: usize = 128;
const MAX_P_BYTES: usize = 2 * 1024 * 1024 * 1024;
const MAX_REPLAY_DELTA: usize = 16 * 1024 * 1024;
pub(super) const SCHEMA:&str="
CREATE TABLE native_incremental_owner_v1 (
 id INTEGER PRIMARY KEY CHECK(id=1), source_head BLOB NOT NULL CHECK(length(source_head)=104),
 source_sequence BLOB NOT NULL CHECK(length(source_sequence)=8), source_snapshot BLOB NOT NULL CHECK(length(source_snapshot)=32),
 source_commands BLOB NOT NULL CHECK(length(source_commands)=32), source_nonces BLOB NOT NULL CHECK(length(source_nonces)=32),
 source_header BLOB NOT NULL CHECK(length(source_header)<=4096), source_replay_root BLOB NOT NULL CHECK(length(source_replay_root)=32),
 source_anchor BLOB NOT NULL CHECK(length(source_anchor)=32), head_commit_sequence BLOB NOT NULL CHECK(length(head_commit_sequence)=8),
 storage_checksum BLOB NOT NULL CHECK(length(storage_checksum)=32), replay_version BLOB NOT NULL CHECK(length(replay_version)=8),
 replay_root BLOB NOT NULL CHECK(length(replay_root)=32), owner_checksum BLOB NOT NULL CHECK(length(owner_checksum)=32)
) STRICT;
CREATE TABLE native_incremental_p_v1 (
 block BLOB PRIMARY KEY CHECK(length(block)=32), sequence BLOB NOT NULL UNIQUE CHECK(length(sequence)=8),
 status INTEGER NOT NULL CHECK(status IN(0,1)), parent BLOB NOT NULL CHECK(length(parent)=104), parent_p BLOB CHECK(parent_p IS NULL OR length(parent_p)=32),
 artifact BLOB NOT NULL CHECK(length(artifact)<=16777216), header BLOB NOT NULL CHECK(length(header)<=4096),
 storage_artifact BLOB NOT NULL CHECK(length(storage_artifact)=32), storage_sequence BLOB NOT NULL CHECK(length(storage_sequence)=8),
 replay_parent_version BLOB NOT NULL CHECK(length(replay_parent_version)=8), replay_parent_root BLOB NOT NULL CHECK(length(replay_parent_root)=32),
 replay_delta BLOB NOT NULL CHECK(length(replay_delta)<=16777216), lifecycle BLOB NOT NULL CHECK(length(lifecycle)<=1048576),
 digest BLOB NOT NULL CHECK(length(digest)=32), commit_sequence BLOB CHECK(commit_sequence IS NULL OR length(commit_sequence)=8),
 CHECK((status=0 AND commit_sequence IS NULL) OR(status=1 AND commit_sequence IS NOT NULL))
) STRICT, WITHOUT ROWID;
CREATE INDEX native_incremental_p_phase ON native_incremental_p_v1(status);
";
fn fail(_: impl std::fmt::Display) -> NativeApplicationExecutionErrorV0 {
    error(
        NativeApplicationExecutionErrorCodeV0::CorruptStore,
        "incremental_owner.audit",
    )
}
fn fixed<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("incremental fixed field length"))
}
fn number(bytes: Vec<u8>) -> Result<u64> {
    Ok(u64::from_be_bytes(fixed(bytes)?))
}
fn head_bytes(head: &ApplicationHeadV0) -> Vec<u8> {
    [
        head.height().get().to_be_bytes().as_slice(),
        head.block_id().as_bytes(),
        head.state_root().as_bytes(),
        head.commit_id().as_bytes(),
    ]
    .concat()
}
fn decode_head(bytes: &[u8]) -> Result<ApplicationHeadV0> {
    ensure!(bytes.len() == 104, "incremental application head length");
    Ok(ApplicationHeadV0::new(
        HeightV0::new(u64::from_be_bytes(bytes[..8].try_into()?)),
        BlockIdV0::new(bytes[8..40].try_into()?)?,
        StateRootV0::new(bytes[40..72].try_into()?)?,
        ApplicationCommitIdV0::new(bytes[72..].try_into()?)?,
    ))
}
fn namespace(config: &NativeApplicationConfigV0) -> ni::IncrementalNamespaceV1 {
    ni::IncrementalNamespaceV1 {
        chain: config.chain_id.clone(),
        genesis: config.genesis_hash,
        namespace: config.store_id,
        owner_generation: 1,
    }
}
fn header(bytes: &[u8]) -> Result<BlockHeader> {
    trnm_consensus_types::decode_block_header_v0_exact(bytes)
        .map_err(|e| anyhow::anyhow!("incremental header: {e:?}"))
}
#[derive(Clone)]
struct P {
    block: [u8; 32],
    sequence: u64,
    status: u8,
    parent: ApplicationHeadV0,
    parent_p: Option<[u8; 32]>,
    artifact: Vec<u8>,
    header: Vec<u8>,
    storage_artifact: [u8; 32],
    storage_sequence: u64,
    replay_parent: ReplayHead,
    replay_delta: Vec<u8>,
    lifecycle: Vec<u8>,
    digest: [u8; 32],
    commit_sequence: Option<u64>,
}
impl P {
    fn executed(&self) -> Result<NativeExecutedBlockV0> {
        Ok(decode_native_executed_block_artifact_v0(&self.artifact)?)
    }
    fn replay(&self) -> Result<ReplayDelta> {
        ReplayDelta::decode(&self.replay_delta)
    }
    fn calculate_digest(&self, config: &NativeApplicationConfigV0) -> [u8; 32] {
        let parent = self
            .parent_p
            .map_or_else(|| vec![0], |id| [vec![1], id.to_vec()].concat());
        hash_domain(
            "trnm.native-application.incremental-p.v1",
            &[
                &config.store_id,
                &self.sequence.to_be_bytes(),
                &head_bytes(&self.parent),
                &parent,
                &sha256_v0(&self.artifact),
                &sha256_v0(&self.header),
                &self.storage_artifact,
                &self.storage_sequence.to_be_bytes(),
                &self.replay_parent.version.to_be_bytes(),
                &self.replay_parent.root,
                &sha256_v0(&self.replay_delta),
                &sha256_v0(&self.lifecycle),
            ],
        )
    }
    fn target(&self) -> Result<ApplicationHeadV0> {
        let execution = self.executed()?;
        let request = execution.request();
        let replay = self.replay()?;
        let commit = hash_domain(
            "trnm.native-application.incremental-commit.v1",
            &[
                &self.digest,
                &self.block,
                request.expected().post_state_root().as_bytes(),
                &replay.head.root,
            ],
        );
        Ok(ApplicationHeadV0::new(
            request.height(),
            request.block_id(),
            request.expected().post_state_root(),
            ApplicationCommitIdV0::new(commit)?,
        ))
    }
    fn storage(&self) -> Result<ni::PreparedIncrementalDeltaV1> {
        let target = self.target()?;
        Ok(ni::PreparedIncrementalDeltaV1 {
            artifact: self.storage_artifact,
            block: self.block,
            height: target.height().get(),
            root: *target.state_root().as_bytes(),
            persist_sequence: self.storage_sequence,
        })
    }
    fn validate(&self, config: &NativeApplicationConfigV0) -> Result<()> {
        self.validate_context(config, &config.validator_set, &config.parameters)
    }
    fn validate_context(
        &self,
        config: &NativeApplicationConfigV0,
        set: &ValidatorSet,
        parameters: &ConsensusParametersV0,
    ) -> Result<()> {
        ensure!(
            self.sequence > 1 && self.digest == self.calculate_digest(config),
            "incremental P digest"
        );
        ensure!(
            matches!((self.status, self.commit_sequence), (0, None))
                || (self.status == 1 && self.commit_sequence.is_some_and(|s| s > self.sequence)),
            "incremental P phase"
        );
        let executed = self.executed()?;
        let request = executed.request();
        let h = header(&self.header)?;
        ensure!(
            request.parent() == &self.parent
                && request.block_id().as_bytes() == &self.block
                && request.chain_id().as_str() == config.chain_id
                && request.genesis_hash().as_bytes() == &config.genesis_hash
                && request.active_validator_set_id().as_bytes() == set.id().as_bytes(),
            "incremental P request"
        );
        ensure_finalized_header_binding_v0(&h, request)?;
        validate_native_finalized_execution_receipts_v0(&executed)?;
        ensure!(
            h.block_kind() == trnm_consensus_types::BlockKind::Regular
                && h.validator_set_id() == set.id()
                && h.epoch() == set.epoch()
                && h.consensus_parameters_hash() == parameters.hash(),
            "incremental ordinary context"
        );
        ensure!(
            self.replay()?.head.version
                == self
                    .replay_parent
                    .version
                    .checked_add(1)
                    .context("replay height exhausted")?,
            "incremental replay successor"
        );
        Ok(())
    }
}
fn load_p(connection: &Connection, block: [u8; 32]) -> Result<Option<P>> {
    let sizes:Option<(i64,i64,i64,i64)>=connection.query_row("SELECT length(artifact),length(header),length(replay_delta),length(lifecycle) FROM native_incremental_p_v1 WHERE block=?1",[block.as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
    let Some(sizes) = sizes else { return Ok(None) };
    ensure!(
        [sizes.0, sizes.1, sizes.2, sizes.3]
            .into_iter()
            .zip([16 * 1024 * 1024, 4096, MAX_REPLAY_DELTA, 1024 * 1024])
            .all(|(n, cap)| n >= 0 && n as usize <= cap),
        "incremental P byte cap"
    );
    connection
        .query_row(
            "SELECT * FROM native_incremental_p_v1 WHERE block=?1",
            [block.as_slice()],
            |r| {
                let convert = |e: anyhow::Error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Blob,
                        e.into(),
                    )
                };
                Ok(P {
                    block,
                    sequence: number(r.get("sequence")?).map_err(convert)?,
                    status: r.get("status")?,
                    parent: decode_head(&r.get::<_, Vec<u8>>("parent")?).map_err(convert)?,
                    parent_p: r
                        .get::<_, Option<Vec<u8>>>("parent_p")?
                        .map(fixed)
                        .transpose()
                        .map_err(convert)?,
                    artifact: r.get("artifact")?,
                    header: r.get("header")?,
                    storage_artifact: fixed(r.get("storage_artifact")?).map_err(convert)?,
                    storage_sequence: number(r.get("storage_sequence")?).map_err(convert)?,
                    replay_parent: ReplayHead {
                        version: number(r.get("replay_parent_version")?).map_err(convert)?,
                        root: fixed(r.get("replay_parent_root")?).map_err(convert)?,
                    },
                    replay_delta: r.get("replay_delta")?,
                    lifecycle: r.get("lifecycle")?,
                    digest: fixed(r.get("digest")?).map_err(convert)?,
                    commit_sequence: r
                        .get::<_, Option<Vec<u8>>>("commit_sequence")?
                        .map(number)
                        .transpose()
                        .map_err(convert)?,
                })
            },
        )
        .map(Some)
        .map_err(Into::into)
}
#[derive(Clone)]
struct Owner {
    source: ApplicationHeadV0,
    source_sequence: u64,
    source_snapshot: [u8; 32],
    source_commands: [u8; 32],
    source_nonces: [u8; 32],
    source_header: Vec<u8>,
    source_replay: [u8; 32],
    anchor: [u8; 32],
    commit_sequence: u64,
    storage_checksum: [u8; 32],
    replay: ReplayHead,
    checksum: [u8; 32],
}
impl Owner {
    fn source_digest(&self, config: &NativeApplicationConfigV0) -> [u8; 32] {
        hash_domain(
            "trnm.native-application.incremental-migration.v1",
            &[
                &config.store_id,
                &config.chain_descriptor_hash,
                &config.signer_policy_commitment,
                &head_bytes(&self.source),
                &self.source_sequence.to_be_bytes(),
                &self.source_snapshot,
                &self.source_commands,
                &self.source_nonces,
                &sha256_v0(&self.source_header),
                &self.source_replay,
            ],
        )
    }
    fn current_digest(&self, head: &ApplicationHeadV0) -> [u8; 32] {
        hash_domain(
            "trnm.native-application.incremental-owner.v1",
            &[
                &self.anchor,
                &head_bytes(head),
                &self.commit_sequence.to_be_bytes(),
                &self.storage_checksum,
                &self.replay.version.to_be_bytes(),
                &self.replay.root,
            ],
        )
    }
}
fn load_owner(connection: &Connection) -> Result<Owner> {
    let r=connection.query_row("SELECT source_head,source_sequence,source_snapshot,source_commands,source_nonces,CASE WHEN length(source_header)<=4096 THEN source_header ELSE NULL END,source_replay_root,source_anchor,head_commit_sequence,storage_checksum,replay_version,replay_root,owner_checksum FROM native_incremental_owner_v1 WHERE id=1",[],|r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,Vec<u8>>(2)?,r.get::<_,Vec<u8>>(3)?,r.get::<_,Vec<u8>>(4)?,r.get::<_,Vec<u8>>(5)?,r.get::<_,Vec<u8>>(6)?,r.get::<_,Vec<u8>>(7)?,r.get::<_,Vec<u8>>(8)?,r.get::<_,Vec<u8>>(9)?,r.get::<_,Vec<u8>>(10)?,r.get::<_,Vec<u8>>(11)?,r.get::<_,Vec<u8>>(12)?)))?;
    Ok(Owner {
        source: decode_head(&r.0)?,
        source_sequence: number(r.1)?,
        source_snapshot: fixed(r.2)?,
        source_commands: fixed(r.3)?,
        source_nonces: fixed(r.4)?,
        source_header: r.5,
        source_replay: fixed(r.6)?,
        anchor: fixed(r.7)?,
        commit_sequence: number(r.8)?,
        storage_checksum: fixed(r.9)?,
        replay: ReplayHead {
            version: number(r.10)?,
            root: fixed(r.11)?,
        },
        checksum: fixed(r.12)?,
    })
}

struct ResolvedParent {
    state: ni::IncrementalParentV1,
    replay: Vec<ReplayDelta>,
    digest: Option<[u8; 32]>,
}
fn resolve_parent(
    tx: &rusqlite::Transaction<'_>,
    config: &NativeApplicationConfigV0,
    metadata: &MetadataV0,
    owner: &Owner,
    parent: &ApplicationHeadV0,
) -> Result<ResolvedParent> {
    if parent == &metadata.head {
        let digest = load_p(tx, *parent.block_id().as_bytes())?.map(|p| p.digest);
        return Ok(ResolvedParent {
            state: ni::IncrementalParentV1::Committed(*parent.block_id().as_bytes()),
            replay: Vec::new(),
            digest,
        });
    }
    let mut p = load_p(tx, *parent.block_id().as_bytes())?
        .context("incremental prepared parent missing")?;
    p.validate(config)?;
    ensure!(
        p.target()? == *parent,
        "incremental prepared parent identity"
    );
    let state = ni::IncrementalParentV1::Prepared(p.storage_artifact);
    let digest = Some(p.digest);
    let mut replay = Vec::new();
    let mut bytes = 0usize;
    loop {
        p.validate(config)?;
        ensure!(
            p.status == 0 && p.sequence <= metadata.durable_sequence,
            "incremental prepared ancestor status/sequence"
        );
        ensure!(replay.len() < 8, "incremental prepared ancestry capacity");
        bytes = bytes
            .checked_add(p.replay_delta.len())
            .context("replay suffix overflow")?;
        ensure!(bytes <= 64 * 1024 * 1024, "replay suffix capacity");
        replay.push(p.replay()?);
        if p.parent == metadata.head {
            ensure!(
                p.replay_parent == owner.replay,
                "incremental prepared replay anchor"
            );
            break;
        }
        let previous =
            load_p(tx, *p.parent.block_id().as_bytes())?.context("incremental ancestor missing")?;
        ensure!(
            Some(previous.digest) == p.parent_p
                && previous.sequence < p.sequence
                && previous.target()? == p.parent
                && p.replay_parent == previous.replay()?.head,
            "incremental ancestor splice"
        );
        p = previous;
    }
    Ok(ResolvedParent {
        state,
        replay,
        digest,
    })
}
struct ExecutionView<'a> {
    state: ni::IncrementalJmtReaderV1<'a>,
    replay: ReplayReader<'a>,
    config: &'a NativeApplicationConfigV0,
    parameters: ConsensusParametersV0,
}
impl TreeReader for ExecutionView<'_> {
    fn get_node_option(&self, key: &NodeKey) -> Result<Option<Node>> {
        self.state.get_node_option(key)
    }
    fn get_value_option(&self, version: u64, key: KeyHash) -> Result<Option<Vec<u8>>> {
        self.state.get_value_option(version, key)
    }
    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        self.state.get_rightmost_leaf()
    }
}
impl HasPreimage for ExecutionView<'_> {
    fn preimage(&self, key: KeyHash) -> Result<Option<Vec<u8>>> {
        self.state.preimage(key)
    }
}
impl NativeExecutionStoreV0 for ExecutionView<'_> {
    fn parent_version_v0(&self) -> Result<u64> {
        Ok(self.state.version())
    }
    fn parent_root_v0(&self) -> Result<RootHash> {
        Ok(self.state.root())
    }
    fn chain_id_v0(&self) -> Result<&str> {
        Ok(&self.config.chain_id)
    }
    fn authorized_signers_v0(&self) -> Result<&[AuthorizedSignerV0]> {
        Ok(&self.config.signers)
    }
    fn signer_policy_commitment_v0(&self) -> Result<[u8; 32]> {
        Ok(self.config.signer_policy_commitment)
    }
    fn consensus_parameters_v0(&self) -> Result<ConsensusParametersV0> {
        Ok(self.parameters)
    }
    fn committed_command_id_v0(&self, id: &str) -> Result<bool> {
        self.replay.contains(replay::command_key(id)?)
    }
    fn committed_signer_nonce_v0(&self, id: &str, nonce: u64) -> Result<bool> {
        self.replay.contains(replay::nonce_key(id, nonce)?)
    }
}
impl crate::complete::CompleteExecutionStoreV1 for ExecutionView<'_> {
    fn complete_live_values_v1(&self, version: u64) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
        ensure!(
            version == self.state.version(),
            "incremental execution projection version"
        );
        self.state.verified_live_values_v1()
    }
}
fn execution_view<'a>(
    tx: &'a rusqlite::Transaction<'a>,
    config: &'a NativeApplicationConfigV0,
    owner: &Owner,
    parent: &'a ResolvedParent,
) -> Result<ExecutionView<'a>> {
    Ok(ExecutionView {
        state: ni::open_incremental_reader_v1(tx, &namespace(config), parent.state)?,
        replay: ReplayReader::new(tx, Some(owner.replay), &parent.replay)?,
        config,
        parameters: config.parameters,
    })
}
fn validate_source_replay(
    tx: &rusqlite::Transaction<'_>,
    config: &NativeApplicationConfigV0,
    owner: &Owner,
) -> Result<()> {
    let (commands, nonces) = if owner.source.height().get() == 0 {
        ensure!(
            owner.source.block_id().as_bytes() == &config.initial_block_id
                && owner.source.state_root().as_bytes() == &config.initial_state_root
                && owner.source.commit_id().as_bytes() == &config.initial_commit_id,
            "incremental genesis migration source"
        );
        (BTreeSet::new(), BTreeSet::new())
    } else {
        type SourceRow = (
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            Vec<u8>,
            Vec<u8>,
        );
        let r:SourceRow=tx.query_row("SELECT CASE WHEN length(target_replay_command_ids)<=16777216 THEN target_replay_command_ids ELSE NULL END,CASE WHEN length(target_replay_signer_nonces)<=16777216 THEN target_replay_signer_nonces ELSE NULL END,target_snapshot_digest,p_digest,artifact_digest,commit_id,commit_sequence,p_sequence,CASE WHEN length(target_lifecycle_json)<=1048576 THEN target_lifecycle_json ELSE NULL END FROM native_durable_execution_p_v0 WHERE block_id=?1 AND status=?2",params![owner.source.block_id().as_bytes().as_slice(),P_STATUS_COMMITTED.to_be_bytes().as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?)))?;
        let p_digest = fixed::<32>(r.3)?;
        let snapshot = fixed::<32>(r.2)?;
        ensure!(
            p_digest
                == p_digest_v0(
                    config.store_id,
                    number(r.7)?,
                    fixed(r.4)?,
                    snapshot,
                    &r.0,
                    &r.1,
                    &r.8
                )
                && hash_domain(
                    COMMIT_ID_DOMAIN_V0,
                    &[&p_digest, owner.source.block_id().as_bytes(), &snapshot]
                ) == *owner.source.commit_id().as_bytes(),
            "incremental source P commitment"
        );
        ensure!(
            sha256_v0(&r.0) == owner.source_commands
                && sha256_v0(&r.1) == owner.source_nonces
                && snapshot == owner.source_snapshot
                && r.5.map(fixed).transpose()? == Some(*owner.source.commit_id().as_bytes())
                && r.6
                    .map(number)
                    .transpose()?
                    .is_some_and(|n| n <= owner.source_sequence),
            "incremental migration source replay binding"
        );
        (
            decode_borsh_v0::<BTreeSet<String>>(&r.0, "incremental.source_commands")?,
            decode_borsh_v0::<BTreeSet<(String, u64)>>(&r.1, "incremental.source_nonces")?,
        )
    };
    let reader = ReplayReader::new(
        tx,
        Some(ReplayHead {
            version: 0,
            root: owner.source_replay,
        }),
        &[],
    )?;
    let keys = commands
        .iter()
        .map(|id| replay::command_key(id))
        .chain(
            nonces
                .iter()
                .map(|(id, nonce)| replay::nonce_key(id, *nonce)),
        )
        .collect::<Result<BTreeSet<_>>>()?;
    reader.verify_exact_cardinality(keys.len())?;
    for key in keys {
        ensure!(
            reader.contains(key)?,
            "migration replay baseline lost membership"
        );
    }
    Ok(())
}
fn validate_tx(
    tx: &rusqlite::Transaction<'_>,
    config: &NativeApplicationConfigV0,
    metadata: &MetadataV0,
) -> Result<Owner> {
    ensure!(
        metadata.snapshot.is_empty()
            && metadata.snapshot_digest == sha256_v0(&[])
            && metadata.command_ids.is_empty()
            && metadata.signer_nonces.is_empty(),
        "incremental metadata retained a shadow snapshot"
    );
    let owner = load_owner(tx)?;
    ensure!(
        owner.anchor == owner.source_digest(config)
            && owner.checksum == owner.current_digest(&metadata.head)
            && owner.commit_sequence <= metadata.durable_sequence,
        "incremental owner binding"
    );
    let source_header = header(&owner.source_header)?;
    ensure!(
        source_header.id().as_bytes() == owner.source.block_id().as_bytes()
            && source_header.height().get() == owner.source.height().get()
            && source_header.state_root().as_bytes() == owner.source.state_root().as_bytes(),
        "incremental migration header binding"
    );
    let storage = ni::read_incremental_head_v1(tx, &namespace(config))?;
    ensure!(
        storage.block == *metadata.head.block_id().as_bytes()
            && storage.height == metadata.head.height().get()
            && storage.root == *metadata.head.state_root().as_bytes()
            && storage.intent == *metadata.head.commit_id().as_bytes()
            && storage.checksum == owner.storage_checksum,
        "incremental native/storage head mismatch"
    );
    let _replay = ReplayReader::new(tx, Some(owner.replay), &[])?;
    if metadata.head == owner.source {
        ensure!(
            owner.replay
                == ReplayHead {
                    version: 0,
                    root: owner.source_replay
                }
                && owner.commit_sequence == owner.source_sequence,
            "incremental migration head changed"
        );
    } else {
        let p = load_p(tx, *metadata.head.block_id().as_bytes())?
            .context("incremental committed P missing")?;
        p.validate(config)?;
        ensure!(
            p.status == 1
                && p.target()? == metadata.head
                && p.commit_sequence == Some(owner.commit_sequence)
                && p.replay()?.head == owner.replay,
            "incremental committed P binding"
        );
    }
    let pending: u64 = tx.query_row(
        "SELECT count(*) FROM native_incremental_p_v1 WHERE status=0",
        [],
        |r| r.get(0),
    )?;
    ensure!(
        pending <= MAX_PREPARED as u64,
        "incremental pending capacity"
    );
    let maximum: Option<Vec<u8>> = tx.query_row(
        "SELECT max(sequence) FROM native_incremental_p_v1 WHERE status=0",
        [],
        |r| r.get(0),
    )?;
    ensure!(
        maximum
            .map(number)
            .transpose()?
            .unwrap_or(0)
            .max(owner.commit_sequence)
            == metadata.durable_sequence,
        "incremental durable sequence mismatch"
    );
    Ok(owner)
}
pub(super) fn audited_migration_anchor(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    metadata: &MetadataV0,
) -> DurableResult<[u8; 32]> {
    (|| -> Result<_> {
        let tx = connection.unchecked_transaction()?;
        let owner = validate_tx(&tx, config, metadata)?;
        validate_source_replay(&tx, config, &owner)?;
        Ok(owner.anchor)
    })()
    .map_err(fail)
}
pub(super) fn validate_metadata(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    metadata: &MetadataV0,
) -> DurableResult<Vec<ValidatedPInventoryEntryV0>> {
    (|| -> Result<_> {
        let tx = connection.unchecked_transaction()?;
        let owner = validate_tx(&tx, config, metadata)?;
        validate_source_replay(&tx, config, &owner)?;
        Ok(Vec::new())
    })()
    .map_err(fail)
}
pub(super) fn verify_schema(connection: &Connection) -> DurableResult<()> {
    (||->Result<_>{
  fn objects(c:&Connection)->Result<Vec<(String,String,String)>>{let mut q=c.prepare("SELECT type,name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")?;let result=q.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;Ok(result.into_iter().map(|(t,n,s)|(t,n,normalize_sql_v0(&s))).collect())}
  let mut reference=Connection::open_in_memory()?;initialize_schema_v0(&reference)?;let tx=reference.transaction()?;ni::install_incremental_schema_v1(&tx)?;tx.execute_batch(SCHEMA)?;tx.execute_batch(replay::SCHEMA)?;tx.commit()?;
  ensure!(objects(connection)?==objects(&reference)?,"incremental owner closed schema");Ok(())
 })().map_err(fail)
}

/// Actual native preparation backed only by incremental state/replay deltas.
/// No public constructor, Clone, commit or signing authority is provided.
#[must_use]
pub struct PreparedNativeIncrementalExecutionV1 {
    owner: Arc<()>,
    p: P,
}
impl PreparedNativeIncrementalExecutionV1 {
    pub fn executed(&self) -> Result<NativeExecutedBlockV0> {
        self.p.executed()
    }
    pub fn header(&self) -> Result<BlockHeader> {
        header(&self.p.header)
    }
    pub fn application_parent(&self) -> &ApplicationHeadV0 {
        &self.p.parent
    }
    pub fn target_head(&self) -> Result<ApplicationHeadV0> {
        self.p.target()
    }
    pub const fn p_digest(&self) -> [u8; 32] {
        self.p.digest
    }
    pub const fn persist_sequence(&self) -> u64 {
        self.p.sequence
    }
    pub const fn storage_artifact(&self) -> [u8; 32] {
        self.p.storage_artifact
    }
}

/// Fresh reconstruction of an actual native P. Comparison fields alone are
/// never Core authority; the consumer must join this receipt to the live owner.
/// ```compile_fail
/// use trnm_native_execution_v0::ConfirmedPreparedNativeIncrementalExecutionV1;
/// let receipt = ConfirmedPreparedNativeIncrementalExecutionV1 {};
/// ```
#[must_use]
pub struct ConfirmedPreparedNativeIncrementalExecutionV1 {
    prepared: PreparedNativeIncrementalExecutionV1,
}
impl ConfirmedPreparedNativeIncrementalExecutionV1 {
    pub fn prepared(&self) -> &PreparedNativeIncrementalExecutionV1 {
        &self.prepared
    }
    pub fn artifact_checksum(&self) -> [u8; 32] {
        sha256_v0(&self.prepared.p.artifact)
    }
    pub fn application_payload_and_receipts(
        &self,
    ) -> Result<(
        trnm_consensus_types::ApplicationPayloadV0,
        trnm_consensus_types::ExecutionReceiptsV0,
    )> {
        let executed = self.prepared.executed()?;
        let exact = crate::poco_checkpoint::native_execution_from_receipts_v0(
            executed.request().transactions(),
            executed.receipts(),
        )?;
        Ok((
            exact.application_payload().clone(),
            exact.execution_receipts().clone(),
        ))
    }
    pub fn overlay_checksum(&self) -> [u8; 32] {
        let p = &self.prepared.p;
        hash_domain(
            "trnm.native-application.incremental-overlay.v1",
            &[
                &p.storage_artifact,
                &p.replay_parent.root,
                &sha256_v0(&p.replay_delta),
                &sha256_v0(&p.lifecycle),
            ],
        )
    }
    pub const fn commit_sequence(&self) -> Option<u64> {
        self.prepared.p.commit_sequence
    }
    pub fn belongs_to_application_at_path(
        &self,
        app: &DurableNativeApplicationV0,
        expected_path: &Path,
    ) -> bool {
        app.path() == expected_path
            && app
                .confirm_prepared_incremental_execution_v1(&self.prepared)
                .is_ok_and(|fresh| {
                    fresh.prepared.p.status == self.prepared.p.status
                        && fresh.commit_sequence() == self.commit_sequence()
                })
    }
}
#[must_use]
pub struct CommittedNativeIncrementalExecutionV1 {
    owner: Arc<()>,
    head: ApplicationHeadV0,
    digest: [u8; 32],
    sequence: u64,
}
impl CommittedNativeIncrementalExecutionV1 {
    pub fn head(&self) -> &ApplicationHeadV0 {
        &self.head
    }
    pub const fn p_digest(&self) -> [u8; 32] {
        self.digest
    }
    pub const fn commit_sequence(&self) -> u64 {
        self.sequence
    }
    pub fn belongs_to_application(&self, app: &DurableNativeApplicationV0) -> bool {
        if !Arc::ptr_eq(&self.owner, &app.owner_affinity) {
            return false;
        }
        (|| -> Result<bool> {
            let _guard = app.lock_operation()?;
            let connection = open_immutable_connection_v0(&app.path)?;
            verify_schema_v0(&connection)?;
            let tx = connection.unchecked_transaction()?;
            let metadata = load_metadata_v0(&tx, &app.config)?;
            let owner = app.pinned_incremental_owner(&tx, &metadata)?;
            let p = load_p(&tx, *self.head.block_id().as_bytes())?
                .context("committed incremental receipt P missing")?;
            p.validate(&app.config)?;
            Ok(metadata.head == self.head
                && p.target()? == self.head
                && p.status == 1
                && p.digest == self.digest
                && p.commit_sequence == Some(self.sequence)
                && owner.commit_sequence == self.sequence)
        })()
        .unwrap_or(false)
    }
}
impl DurableNativeApplicationV0 {
    /// Explicit ordinary schema3→5 migration. The exact source header supplies
    /// the committed parent timestamp and is bound by the already trusted head ID.
    pub fn upgrade_incremental_schema_v1(
        &self,
        expected: &ApplicationHeadV0,
        source_header: &BlockHeader,
    ) -> Result<()> {
        let _guard = self.lock_operation()?;
        let mut connection = open_writable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        let metadata = load_metadata_v0(&connection, &self.config)?;
        ensure!(
            metadata.head == *expected,
            "incremental migration expected head"
        );
        if epoch_durable::schema_version(&connection)? == SCHEMA_VERSION {
            let tx = connection.transaction()?;
            let owner = validate_tx(&tx, &self.config, &metadata)?;
            ensure!(
                owner.source_header
                    == source_header
                        .try_cev0_bytes()
                        .map_err(|e| anyhow::anyhow!("source header: {e:?}"))?,
                "conflicting migration retry"
            );
            validate_source_replay(&tx, &self.config, &owner)?;
            drop(tx);
            drop(connection);
            sync_store_commit_boundary_v0(&self.path)?;
            fresh_validate_v0(&self.path, &self.config)?;
            *self
                .incremental_migration_pin
                .lock()
                .map_err(|_| anyhow::anyhow!("migration pin poisoned"))? = Some(owner.anchor);
            return Ok(());
        }
        ensure!(
            epoch_durable::schema_version(&connection)? == APPLICATION_SCHEMA_VERSION_V0,
            "ordinary incremental migration requires schema3"
        );
        validate_metadata_v0(&connection, &self.config, &metadata)?;
        let ps = load_all_p_v0(&connection)?;
        ensure!(
            ps.iter().all(|p| p.status == P_STATUS_COMMITTED),
            "incremental migration requires resolved preparations"
        );
        ensure!(
            source_header.id().as_bytes() == expected.block_id().as_bytes()
                && source_header.height().get() == expected.height().get()
                && source_header.state_root().as_bytes() == expected.state_root().as_bytes()
                && source_header.chain_id().as_str() == self.config.chain_id
                && source_header.genesis_hash().as_bytes() == &self.config.genesis_hash,
            "incremental migration source header"
        );
        let source = metadata.to_store(&self.config)?;
        let mut roots = vec![(
            ni::IncrementalHeadV1 {
                height: 0,
                block: self.config.initial_block_id,
                root: self.config.initial_state_root,
                commit_sequence: 0,
                intent: self.config.initial_commit_id,
                checksum: [0; 32],
            },
            self.config.validator_set.epoch().get(),
        )];
        for p in &ps {
            let execution = decode_native_executed_block_artifact_v0(&p.artifact)?;
            roots.push((
                ni::IncrementalHeadV1 {
                    height: p.target_height,
                    block: p.block_id,
                    root: *execution.request().expected().post_state_root().as_bytes(),
                    commit_sequence: p.target_height,
                    intent: p.commit_id.context("source commit missing")?,
                    checksum: [0; 32],
                },
                self.config.validator_set.epoch().get(),
            ));
        }
        roots.sort_by_key(|(h, _)| h.height);
        let mut owner = Owner {
            source: metadata.head.clone(),
            source_sequence: metadata.durable_sequence,
            source_snapshot: metadata.snapshot_digest,
            source_commands: sha256_v0(&borsh::to_vec(&metadata.command_ids)?),
            source_nonces: sha256_v0(&borsh::to_vec(&metadata.signer_nonces)?),
            source_header: source_header
                .try_cev0_bytes()
                .map_err(|e| anyhow::anyhow!("source header: {e:?}"))?,
            source_replay: [0; 32],
            anchor: [0; 32],
            commit_sequence: metadata.durable_sequence,
            storage_checksum: [0; 32],
            replay: ReplayHead {
                version: 0,
                root: [0; 32],
            },
            checksum: [0; 32],
        };
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ni::install_incremental_schema_v1(&tx)?;
        tx.execute_batch(SCHEMA)?;
        tx.execute_batch(replay::SCHEMA)?;
        let keys = metadata
            .command_ids
            .iter()
            .map(|id| replay::command_key(id))
            .chain(
                metadata
                    .signer_nonces
                    .iter()
                    .map(|(id, nonce)| replay::nonce_key(id, *nonce)),
            )
            .collect::<Result<Vec<_>>>()?;
        ensure!(keys.len() <= 65_536, "migration replay baseline capacity");
        let replay = ReplayReader::new(&tx, None, &[])?.append(keys)?;
        replay::apply(&tx, &replay)?;
        owner.source_replay = replay.head.root;
        owner.replay = replay.head;
        owner.anchor = owner.source_digest(&self.config);
        let storage = ni::import_incremental_history_v1(
            &tx,
            &namespace(&self.config),
            &roots,
            &source,
            owner.anchor,
        )?;
        owner.storage_checksum = storage.checksum;
        owner.checksum = owner.current_digest(&metadata.head);
        tx.execute(
            "INSERT INTO native_incremental_owner_v1 VALUES(1,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            params![
                head_bytes(&owner.source),
                owner.source_sequence.to_be_bytes().as_slice(),
                owner.source_snapshot.as_slice(),
                owner.source_commands.as_slice(),
                owner.source_nonces.as_slice(),
                owner.source_header,
                owner.source_replay.as_slice(),
                owner.anchor.as_slice(),
                owner.commit_sequence.to_be_bytes().as_slice(),
                owner.storage_checksum.as_slice(),
                owner.replay.version.to_be_bytes().as_slice(),
                owner.replay.root.as_slice(),
                owner.checksum.as_slice()
            ],
        )?;
        ensure!(tx.execute("UPDATE native_application_metadata_v0 SET schema_version=?,authenticated_snapshot=?,authenticated_snapshot_digest=?,replay_command_ids=?,replay_signer_nonces=? WHERE singleton=1 AND schema_version=? AND durable_sequence=?",params![SCHEMA_VERSION.to_be_bytes().as_slice(),Vec::<u8>::new(),sha256_v0(&[]).as_slice(),borsh::to_vec(&BTreeSet::<String>::new())?,borsh::to_vec(&BTreeSet::<(String,u64)>::new())?,APPLICATION_SCHEMA_VERSION_V0.to_be_bytes().as_slice(),metadata.durable_sequence.to_be_bytes().as_slice()])?==1,"incremental migration CAS");
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("incremental_migration_before_commit");
        tx.commit()?;
        drop(connection);
        sync_store_commit_boundary_v0(&self.path)?;
        let actual = fresh_validate_v0(&self.path, &self.config)?;
        ensure!(
            actual.head == metadata.head && actual.durable_sequence == metadata.durable_sequence,
            "incremental migration readback"
        );
        *self
            .incremental_migration_pin
            .lock()
            .map_err(|_| anyhow::anyhow!("migration pin poisoned"))? = Some(owner.anchor);
        Ok(())
    }
    pub(super) fn confirmed_incremental_head_locked(&self) -> DurableResult<ApplicationHeadV0> {
        (|| -> Result<_> {
            let connection = open_immutable_connection_v0(&self.path)?;
            verify_schema_v0(&connection)?;
            let tx = connection.unchecked_transaction()?;
            let metadata = load_metadata_v0(&tx, &self.config)?;
            self.pinned_incremental_owner(&tx, &metadata)?;
            Ok(metadata.head)
        })()
        .map_err(fail)
    }

    /// Run one explicit, bounded node-only maintenance pass as the live
    /// schema-5 incremental owner.
    ///
    /// The storage collector is intentionally crate-private: a caller cannot
    /// provide an arbitrary `Transaction` or namespace and claim GC
    /// authority. This owner boundary takes the process-local operation lock,
    /// revalidates the held namespace identity, opens an immediate SQLite
    /// writer transaction, verifies the independently pinned migration owner,
    /// and only then invokes the collector. A successful pass is fsynced and
    /// re-audited before its report is returned. No block commit calls this
    /// method automatically; scheduling remains an explicit maintenance
    /// decision by the owner.
    pub fn collect_incremental_nodes_v1(
        &self,
        max_nodes: usize,
    ) -> Result<ni::IncrementalGcReportV1> {
        let _guard = self.lock_operation()?;
        let mut connection = open_writable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        ensure!(
            epoch_durable::schema_version(&connection)? == SCHEMA_VERSION,
            "incremental GC owner schema unavailable"
        );
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = load_metadata_v0(&tx, &self.config)?;
        let owner = self.pinned_incremental_owner(&tx, &metadata)?;
        let mut report =
            ni::collect_incremental_nodes_v1(&tx, &namespace(&self.config), max_nodes)?;
        // The storage primitive has no owner authority and therefore leaves
        // this field empty. Fill it only after the owner and writer checks
        // above have succeeded.
        report.owner_anchor = Some(owner.anchor);
        tx.commit()?;
        drop(connection);
        sync_store_commit_boundary_v0(&self.path)?;
        // Reopen through the same owner audit so a successful report cannot
        // hide a broken owner/head join introduced by maintenance.
        fresh_validate_v0(&self.path, &self.config)?;
        Ok(report)
    }

    fn pinned_incremental_owner(
        &self,
        tx: &rusqlite::Transaction<'_>,
        metadata: &MetadataV0,
    ) -> Result<Owner> {
        let owner = validate_tx(tx, &self.config, metadata)?;
        ensure!(
            *self
                .incremental_migration_pin
                .lock()
                .map_err(|_| anyhow::anyhow!("migration pin poisoned"))?
                == Some(owner.anchor),
            "incremental migration anchor changed since owner audit"
        );
        Ok(owner)
    }
    pub fn preview_incremental_block_v1(
        &self,
        request: &NativeBlockPreviewRequestV0,
    ) -> Result<NativeBlockPreviewV0> {
        let _guard = self.lock_operation()?;
        let connection = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        ensure!(
            epoch_durable::schema_version(&connection)? == SCHEMA_VERSION,
            "incremental owner schema unavailable"
        );
        let tx = connection.unchecked_transaction()?;
        let metadata = load_metadata_v0(&tx, &self.config)?;
        let owner = self.pinned_incremental_owner(&tx, &metadata)?;
        let parent = resolve_parent(&tx, &self.config, &metadata, &owner, request.parent())?;
        let view = execution_view(&tx, &self.config, &owner, &parent)?;
        preview_complete_native_block_v0(
            &view,
            &self.config.validator_set,
            GenesisHash::new(self.config.genesis_hash),
            request,
        )
    }
    pub fn execute_incremental_block_v1(
        &self,
        request: NativeBlockExecutionRequestV0,
        block_header: &BlockHeader,
    ) -> Result<PreparedNativeIncrementalExecutionV1> {
        let _guard = self.lock_operation()?;
        let mut connection = open_writable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        ensure!(
            epoch_durable::schema_version(&connection)? == SCHEMA_VERSION,
            "incremental owner schema unavailable"
        );
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = load_metadata_v0(&tx, &self.config)?;
        let owner = self.pinned_incremental_owner(&tx, &metadata)?;
        if let Some(p) = load_p(&tx, *request.block_id().as_bytes())? {
            p.validate(&self.config)?;
            ensure!(
                p.executed()?.request() == &request && header(&p.header)? == *block_header,
                "incremental P conflicting retry"
            );
            drop(tx);
            drop(connection);
            sync_store_commit_boundary_v0(&self.path)?;
            return self.reopen_incremental_locked(p.block, p.digest);
        }
        let parent = resolve_parent(&tx, &self.config, &metadata, &owner, request.parent())?;
        let view = execution_view(&tx, &self.config, &owner, &parent)?;
        let complete = execute_complete_native_block_v0(
            &view,
            &self.config.validator_set,
            GenesisHash::new(self.config.genesis_hash),
            &request,
        )?;
        let (executed, plan, identities, lifecycle) = complete.into_parts();
        ensure_finalized_header_binding_v0(block_header, &request)?;
        ensure!(
            block_header.block_kind() == trnm_consensus_types::BlockKind::Regular,
            "incremental epoch/header path not enabled"
        );
        let keys = identities
            .iter()
            .map(|i| replay::command_key(i.command_id()))
            .chain(
                identities
                    .iter()
                    .map(|i| replay::nonce_key(i.signer_id(), i.nonce())),
            )
            .collect::<Result<Vec<_>>>()?;
        let replay_parent = view
            .replay
            .head
            .context("incremental replay parent missing")?;
        let replay = view.replay.append(keys)?;
        drop(view);
        let delta = ni::stage_incremental_plan_v1(
            &tx,
            &namespace(&self.config),
            parent.state,
            *request.block_id().as_bytes(),
            &plan,
        )?;
        let mut p = P {
            block: *request.block_id().as_bytes(),
            sequence: metadata
                .durable_sequence
                .checked_add(1)
                .context("native sequence exhausted")?,
            status: 0,
            parent: request.parent().clone(),
            parent_p: parent.digest,
            artifact: encode_native_executed_block_artifact_v0(&executed)?,
            header: block_header
                .try_cev0_bytes()
                .map_err(|e| anyhow::anyhow!("incremental header: {e:?}"))?,
            storage_artifact: delta.artifact,
            storage_sequence: delta.persist_sequence,
            replay_parent,
            replay_delta: replay.encode()?,
            lifecycle: serde_json::to_vec(&lifecycle)?,
            digest: [0; 32],
            commit_sequence: None,
        };
        p.digest = p.calculate_digest(&self.config);
        p.validate(&self.config)?;
        let(count,bytes):(u64,u64)=tx.query_row("SELECT count(*),coalesce(sum(length(artifact)+length(header)+length(replay_delta)+length(lifecycle)),0) FROM native_incremental_p_v1 WHERE status=0",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
        ensure!(
            count < MAX_PREPARED as u64
                && bytes
                    .checked_add(
                        (p.artifact.len()
                            + p.header.len()
                            + p.replay_delta.len()
                            + p.lifecycle.len()) as u64
                    )
                    .is_some_and(|n| n <= MAX_P_BYTES as u64),
            "native incremental P capacity"
        );
        tx.execute(
            "INSERT INTO native_incremental_p_v1 VALUES(?,?,0,?,?,?,?,?,?,?,?,?,?,?,NULL)",
            params![
                p.block.as_slice(),
                p.sequence.to_be_bytes().as_slice(),
                head_bytes(&p.parent),
                p.parent_p.map(|v| v.to_vec()),
                p.artifact,
                p.header,
                p.storage_artifact.as_slice(),
                p.storage_sequence.to_be_bytes().as_slice(),
                p.replay_parent.version.to_be_bytes().as_slice(),
                p.replay_parent.root.as_slice(),
                p.replay_delta,
                p.lifecycle,
                p.digest.as_slice()
            ],
        )?;
        ensure!(tx.execute("UPDATE native_application_metadata_v0 SET durable_sequence=? WHERE singleton=1 AND durable_sequence=?",params![p.sequence.to_be_bytes().as_slice(),metadata.durable_sequence.to_be_bytes().as_slice()])?==1,"incremental native prepare CAS");
        tx.commit()?;
        drop(connection);
        sync_store_commit_boundary_v0(&self.path)?;
        self.reopen_incremental_locked(p.block, p.digest)
    }
    fn reopen_incremental_locked(
        &self,
        block: [u8; 32],
        expected: [u8; 32],
    ) -> Result<PreparedNativeIncrementalExecutionV1> {
        let connection = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        let tx = connection.unchecked_transaction()?;
        let metadata = load_metadata_v0(&tx, &self.config)?;
        let owner = self.pinned_incremental_owner(&tx, &metadata)?;
        let p = load_p(&tx, block)?.context("incremental prepared P missing")?;
        p.validate(&self.config)?;
        ensure!(p.digest == expected, "incremental prepared P substituted");
        let state = ni::open_incremental_reader_v1(
            &tx,
            &namespace(&self.config),
            ni::IncrementalParentV1::Prepared(p.storage_artifact),
        )?;
        ensure!(
            state.version() == p.target()?.height().get()
                && state.root().0 == *p.target()?.state_root().as_bytes(),
            "incremental prepared root substituted"
        );
        if p.status == 0 {
            let parent = resolve_parent(&tx, &self.config, &metadata, &owner, &p.parent)?;
            let mut deltas = vec![p.replay()?];
            deltas.extend(parent.replay);
            let _ = ReplayReader::new(&tx, Some(owner.replay), &deltas)?;
        }
        Ok(PreparedNativeIncrementalExecutionV1 {
            owner: Arc::clone(&self.owner_affinity),
            p,
        })
    }
    pub fn reopen_prepared_incremental_execution_v1(
        &self,
        block: [u8; 32],
    ) -> Result<PreparedNativeIncrementalExecutionV1> {
        let _guard = self.lock_operation()?;
        let connection = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        let p = load_p(&connection, block)?.context("incremental prepared P missing")?;
        drop(connection);
        self.reopen_incremental_locked(block, p.digest)
    }

    pub fn confirm_prepared_incremental_execution_v1(
        &self,
        prepared: &PreparedNativeIncrementalExecutionV1,
    ) -> Result<ConfirmedPreparedNativeIncrementalExecutionV1> {
        ensure!(
            Arc::ptr_eq(&prepared.owner, &self.owner_affinity),
            "incremental prepared readback foreign owner"
        );
        let _guard = self.lock_operation()?;
        let fresh = self.reopen_incremental_locked(prepared.p.block, prepared.p.digest)?;
        ensure!(
            fresh.p.sequence == prepared.p.sequence
                && fresh.p.artifact == prepared.p.artifact
                && fresh.p.header == prepared.p.header
                && fresh.p.storage_artifact == prepared.p.storage_artifact
                && fresh.p.storage_sequence == prepared.p.storage_sequence,
            "incremental prepared readback substituted"
        );
        Ok(ConfirmedPreparedNativeIncrementalExecutionV1 { prepared: fresh })
    }
}
impl DurableNativeApplicationV0 {
    pub fn commit_incremental_finality_bytes_v1(
        &self,
        prepared: &PreparedNativeIncrementalExecutionV1,
        proof: &[u8],
        budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
    ) -> Result<CommittedNativeIncrementalExecutionV1> {
        ensure!(
            Arc::ptr_eq(&prepared.owner, &self.owner_affinity),
            "incremental finality foreign owner"
        );
        let _guard = self.lock_operation()?;
        let connection = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        let tx = connection.unchecked_transaction()?;
        let metadata = load_metadata_v0(&tx, &self.config)?;
        let owner = self.pinned_incremental_owner(&tx, &metadata)?;
        let p = load_p(&tx, prepared.p.block)?.context("incremental finality P missing")?;
        p.validate(&self.config)?;
        ensure!(
            p.digest == prepared.p.digest
                && p.artifact == prepared.p.artifact
                && p.header == prepared.p.header,
            "incremental finality P substituted"
        );
        let h = header(&p.header)?;
        let parent_timestamp = if p.parent == owner.source {
            header(&owner.source_header)?.timestamp_ms()
        } else {
            let parent = load_p(&tx, *p.parent.block_id().as_bytes())?
                .context("incremental finality parent missing")?;
            parent.validate(&self.config)?;
            ensure!(
                parent.target()? == p.parent,
                "incremental finality parent binding"
            );
            header(&parent.header)?.timestamp_ms()
        };
        drop(tx);
        drop(connection);
        let expected = trnm_consensus_crypto::FinalityExpectationV0 {
            block_id: h.id(),
            height: h.height(),
            state_root: h.state_root(),
            receipts_root: h.receipts_root(),
            evidence_root: h.evidence_root(),
            parent_id: h.parent_id(),
            parent_height: trnm_consensus_types::Height::new(prepared.p.parent.height().get()),
            parent_timestamp_ms: parent_timestamp,
        };
        let verified = trnm_consensus_crypto::decode_verify_finality_proof_strict_v0(
            trnm_consensus_crypto::POCO_THREE_CHAIN_PROOF_CLASS_V0,
            proof,
            &self.config.validator_set,
            &self.config.parameters,
            expected,
            budget,
        )
        .map_err(|e| anyhow::anyhow!("incremental strict finality: {e}"))?;
        ensure!(
            verified.proof().finalized_block().header() == &h,
            "incremental finality exact header mismatch"
        );
        self.commit_incremental_p(prepared)
    }
    fn commit_incremental_p(
        &self,
        prepared: &PreparedNativeIncrementalExecutionV1,
    ) -> Result<CommittedNativeIncrementalExecutionV1> {
        let mut connection = open_writable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = load_metadata_v0(&tx, &self.config)?;
        let mut owner = self.pinned_incremental_owner(&tx, &metadata)?;
        let p = load_p(&tx, prepared.p.block)?.context("incremental commit P missing")?;
        p.validate(&self.config)?;
        ensure!(
            p.digest == prepared.p.digest
                && p.artifact == prepared.p.artifact
                && p.header == prepared.p.header,
            "incremental commit P substituted"
        );
        let head = p.target()?;
        if p.status == 1 {
            let sequence = p
                .commit_sequence
                .context("incremental committed sequence missing")?;
            drop(tx);
            drop(connection);
            sync_store_commit_boundary_v0(&self.path)?;
            let fresh = self.reopen_incremental_locked(p.block, p.digest)?;
            ensure!(
                fresh.p.commit_sequence == Some(sequence),
                "incremental retry commit changed"
            );
            return Ok(CommittedNativeIncrementalExecutionV1 {
                owner: Arc::clone(&self.owner_affinity),
                head,
                digest: p.digest,
                sequence,
            });
        }
        ensure!(
            metadata.head == p.parent && owner.replay == p.replay_parent,
            "incremental commit predecessor mismatch"
        );
        let executed = p.executed()?;
        let mut keys = Vec::new();
        for raw in executed.request().transactions() {
            let envelope: trnm_finality_types::SignedCommandEnvelopeV1 =
                serde_json::from_slice(raw)?;
            keys.push(replay::command_key(&envelope.command_id)?);
            keys.push(replay::nonce_key(&envelope.signer_id, envelope.nonce)?);
        }
        let replay = ReplayReader::new(&tx, Some(owner.replay), &[])?.append(keys)?;
        ensure!(
            replay.encode()? == p.replay_delta,
            "incremental replay plan differs from exact transactions"
        );
        let storage = ni::read_incremental_head_v1(&tx, &namespace(&self.config))?;
        let next = ni::apply_incremental_delta_v1(
            &tx,
            &namespace(&self.config),
            &storage,
            &p.storage()?,
            *head.commit_id().as_bytes(),
            self.config.validator_set.epoch().get(),
        )?;
        replay::apply(&tx, &replay)?;
        let sequence = metadata
            .durable_sequence
            .checked_add(1)
            .context("incremental commit sequence exhausted")?;
        ensure!(tx.execute("UPDATE native_application_metadata_v0 SET durable_sequence=?,head_height=?,head_block_id=?,head_state_root=?,head_commit_id=? WHERE singleton=1 AND durable_sequence=? AND head_block_id=? AND head_state_root=? AND head_commit_id=?",params![sequence.to_be_bytes().as_slice(),head.height().get().to_be_bytes().as_slice(),head.block_id().as_bytes().as_slice(),head.state_root().as_bytes().as_slice(),head.commit_id().as_bytes().as_slice(),metadata.durable_sequence.to_be_bytes().as_slice(),metadata.head.block_id().as_bytes().as_slice(),metadata.head.state_root().as_bytes().as_slice(),metadata.head.commit_id().as_bytes().as_slice()])?==1,"incremental native commit CAS");
        ensure!(tx.execute("UPDATE native_incremental_p_v1 SET status=1,commit_sequence=? WHERE block=? AND status=0 AND digest=?",params![sequence.to_be_bytes().as_slice(),p.block.as_slice(),p.digest.as_slice()])?==1,"incremental P commit CAS");
        owner.commit_sequence = sequence;
        owner.storage_checksum = next.checksum;
        owner.replay = replay.head;
        owner.checksum = owner.current_digest(&head);
        tx.execute("UPDATE native_incremental_owner_v1 SET head_commit_sequence=?,storage_checksum=?,replay_version=?,replay_root=?,owner_checksum=? WHERE id=1",params![sequence.to_be_bytes().as_slice(),owner.storage_checksum.as_slice(),owner.replay.version.to_be_bytes().as_slice(),owner.replay.root.as_slice(),owner.checksum.as_slice()])?;
        let mut statement =
            tx.prepare("SELECT block FROM native_incremental_p_v1 WHERE status=0")?;
        let ids = statement
            .query_map([], |r| r.get::<_, Vec<u8>>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        let mut pending = BTreeMap::new();
        for id in ids {
            let id = fixed(id)?;
            pending.insert(id, load_p(&tx, id)?.context("pending P missing")?);
        }
        let mut retired = Vec::new();
        for candidate in pending.values() {
            let mut parent = *candidate.parent.block_id().as_bytes();
            let mut depth = 0;
            while parent != p.block {
                depth += 1;
                ensure!(depth <= MAX_PREPARED, "incremental fork ancestry cycle");
                match pending.get(&parent) {
                    Some(ancestor) => parent = *ancestor.parent.block_id().as_bytes(),
                    None => break,
                }
            }
            if parent != p.block {
                retired.push(candidate.storage_artifact);
            }
        }
        ni::retire_incremental_prepared_v1(&tx, &namespace(&self.config), &retired)?;
        for artifact in retired {
            tx.execute(
                "DELETE FROM native_incremental_p_v1 WHERE storage_artifact=? AND status=0",
                [artifact.as_slice()],
            )?;
        }
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("incremental_before_commit");
        tx.commit()?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("incremental_after_commit");
        drop(connection);
        sync_store_commit_boundary_v0(&self.path)?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("incremental_after_fsync");
        let fresh = self.reopen_incremental_locked(p.block, p.digest)?;
        ensure!(
            fresh.p.commit_sequence == Some(sequence),
            "incremental commit readback"
        );
        Ok(CommittedNativeIncrementalExecutionV1 {
            owner: Arc::clone(&self.owner_affinity),
            head,
            digest: p.digest,
            sequence,
        })
    }
}

#[cfg(feature = "incremental-epoch-candidate")]
#[path = "incremental_epoch_owner_v1.rs"]
pub(super) mod epoch_candidate_v1;
