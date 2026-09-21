//! Bounded, inert SQL transport for schema12 ordinary replay continuation.
//!
//! These rows contain execution facts only.  They do not verify finality or
//! grant an owner capability; the continuation owner performs those checks.

use super::*;
use rusqlite::{params, types::ValueRef, Connection};

const MAX_ARTIFACT: usize = 16 * 1024 * 1024;
const MAX_COMPONENT: usize = 16 * 1024 * 1024;
const MAX_LIFECYCLE: usize = 1024 * 1024;
const MAX_PROOF: usize = 8 * 1024 * 1024;

pub(super) struct ReplayPRowV1 {
    pub(super) base_digest: [u8; 32],
    pub(super) block_id: [u8; 32],
    pub(super) p_sequence: u64,
    pub(super) status: u8,
    pub(super) parent_kind: u8,
    pub(super) parent_head: ApplicationHeadV0,
    pub(super) parent_p_digest: Option<[u8; 32]>,
    pub(super) header: BlockHeader,
    pub(super) artifact: Vec<u8>,
    pub(super) artifact_digest: [u8; 32],
    pub(super) snapshot: Vec<u8>,
    pub(super) snapshot_digest: [u8; 32],
    pub(super) commands: Vec<u8>,
    pub(super) commands_digest: [u8; 32],
    pub(super) nonces: Vec<u8>,
    pub(super) nonces_digest: [u8; 32],
    pub(super) lifecycle: Vec<u8>,
    pub(super) lifecycle_digest: [u8; 32],
    pub(super) p_digest: [u8; 32],
    pub(super) commit_sequence: Option<u64>,
    pub(super) commit_id: Option<[u8; 32]>,
}

pub(super) struct ReplayFinalityRowV1 {
    pub(super) block_id: [u8; 32],
    pub(super) p_digest: [u8; 32],
    pub(super) commit_sequence: u64,
    pub(super) proof: Vec<u8>,
    pub(super) proof_digest: [u8; 32],
    pub(super) record_digest: [u8; 32],
}

impl ReplayFinalityRowV1 {
    pub(super) fn verify_digests(&self, base_digest: [u8; 32]) -> Result<()> {
        ensure!(
            sha256_v0(&self.proof) == self.proof_digest,
            "replay finality proof digest"
        );
        ensure!(
            hash_domain(
                "trnm.native.replay-execution-finality.v1",
                &[
                    &base_digest,
                    &self.block_id,
                    &self.p_digest,
                    &self.commit_sequence.to_be_bytes(),
                    &self.proof_digest,
                ],
            ) == self.record_digest,
            "replay finality record digest"
        );
        Ok(())
    }
}

fn fixed<const N: usize>(row: &rusqlite::Row<'_>, column: &str) -> Result<[u8; N]> {
    match row.get_ref(column)? {
        ValueRef::Blob(value) => value
            .try_into()
            .map_err(|_| anyhow::anyhow!("replay fixed width: {column}")),
        _ => anyhow::bail!("replay fixed type: {column}"),
    }
}

fn bounded_blob(
    row: &rusqlite::Row<'_>,
    column: &str,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<u8>> {
    match row.get_ref(column)? {
        ValueRef::Blob(value) if (minimum..=maximum).contains(&value.len()) => Ok(value.to_vec()),
        _ => anyhow::bail!("replay bounded blob: {column}"),
    }
}

fn u64_field(row: &rusqlite::Row<'_>, column: &str) -> Result<u64> {
    Ok(u64::from_be_bytes(fixed(row, column)?))
}

fn decode_head(bytes: [u8; 104]) -> Result<ApplicationHeadV0> {
    Ok(ApplicationHeadV0::new(
        HeightV0::new(u64::from_be_bytes(bytes[..8].try_into()?)),
        BlockIdV0::new(bytes[8..40].try_into()?)?,
        StateRootV0::new(bytes[40..72].try_into()?)?,
        ApplicationCommitIdV0::new(bytes[72..].try_into()?)?,
    ))
}

fn optional_fixed<const N: usize>(
    row: &rusqlite::Row<'_>,
    column: &str,
) -> Result<Option<[u8; N]>> {
    match row.get_ref(column)? {
        ValueRef::Null => Ok(None),
        ValueRef::Blob(value) => {
            Ok(Some(value.try_into().map_err(|_| {
                anyhow::anyhow!("replay optional fixed width: {column}")
            })?))
        }
        _ => anyhow::bail!("replay optional fixed type: {column}"),
    }
}

fn p_digest_v1(row: &ReplayPRowV1) -> Result<[u8; 32]> {
    let mut parent_frame = Vec::with_capacity(if row.parent_p_digest.is_some() { 33 } else { 1 });
    parent_frame.push(row.parent_p_digest.is_some() as u8);
    if let Some(parent) = row.parent_p_digest {
        parent_frame.extend_from_slice(&parent);
    }
    let header = row
        .header
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("replay header encoding: {error:?}"))?;
    let parent_head = row.parent_head_bytes();
    let header_digest = sha256_v0(&header);
    let artifact_digest = sha256_v0(&row.artifact);
    let snapshot_digest = sha256_v0(&row.snapshot);
    let commands_digest = sha256_v0(&row.commands);
    let nonces_digest = sha256_v0(&row.nonces);
    let lifecycle_digest = sha256_v0(&row.lifecycle);
    Ok(hash_domain(
        "trnm.native.replay-execution-p.v1",
        &[
            &row.base_digest,
            &row.p_sequence.to_be_bytes(),
            &[row.parent_kind],
            &parent_head,
            &parent_frame,
            &header_digest,
            &artifact_digest,
            &snapshot_digest,
            &commands_digest,
            &nonces_digest,
            &lifecycle_digest,
        ],
    ))
}

impl ReplayPRowV1 {
    fn parent_head_bytes(&self) -> [u8; 104] {
        let mut bytes = [0u8; 104];
        bytes[..8].copy_from_slice(&self.parent_head.height().get().to_be_bytes());
        bytes[8..40].copy_from_slice(self.parent_head.block_id().as_bytes());
        bytes[40..72].copy_from_slice(self.parent_head.state_root().as_bytes());
        bytes[72..].copy_from_slice(self.parent_head.commit_id().as_bytes());
        bytes
    }

    pub(super) fn verify_digests(&self) -> Result<()> {
        ensure!(
            self.header.id().as_bytes() == &self.block_id,
            "replay P header identity"
        );
        ensure!(
            self.status <= 1 && self.parent_kind <= 1,
            "replay P status/kind"
        );
        ensure!(
            self.parent_kind == 0 || self.parent_p_digest.is_some(),
            "replay parent digest"
        );
        ensure!(
            (self.status == 0 && self.commit_sequence.is_none() && self.commit_id.is_none())
                || (self.status == 1 && self.commit_sequence.is_some() && self.commit_id.is_some()),
            "replay P commit fields"
        );
        ensure!(
            sha256_v0(&self.artifact) == self.artifact_digest,
            "replay artifact digest"
        );
        ensure!(
            sha256_v0(&self.snapshot) == self.snapshot_digest,
            "replay snapshot digest"
        );
        ensure!(
            sha256_v0(&self.commands) == self.commands_digest,
            "replay commands digest"
        );
        ensure!(
            sha256_v0(&self.nonces) == self.nonces_digest,
            "replay nonces digest"
        );
        ensure!(
            sha256_v0(&self.lifecycle) == self.lifecycle_digest,
            "replay lifecycle digest"
        );
        ensure!(p_digest_v1(self)? == self.p_digest, "replay P digest");
        Ok(())
    }

    pub(super) fn target_head(&self) -> Result<ApplicationHeadV0> {
        let stable_commit_id = self.commit_identity();
        Ok(ApplicationHeadV0::new(
            HeightV0::new(self.header.height().get()),
            BlockIdV0::new(*self.header.id().as_bytes())?,
            StateRootV0::new(*self.header.state_root().as_bytes())?,
            ApplicationCommitIdV0::new(stable_commit_id)?,
        ))
    }

    pub(super) fn new_prepared(
        base_digest: [u8; 32],
        p_sequence: u64,
        parent_kind: u8,
        parent_head: ApplicationHeadV0,
        parent_p_digest: Option<[u8; 32]>,
        header: BlockHeader,
        computed: super::execution::ComputedReplayExecutionV1,
    ) -> Result<Self> {
        let artifact_digest = sha256_v0(&computed.artifact);
        let snapshot_digest = sha256_v0(&computed.snapshot);
        let commands_digest = sha256_v0(&computed.commands);
        let nonces_digest = sha256_v0(&computed.nonces);
        let lifecycle_digest = sha256_v0(&computed.lifecycle);
        let row = Self {
            base_digest,
            block_id: *header.id().as_bytes(),
            p_sequence,
            status: 0,
            parent_kind,
            parent_head,
            parent_p_digest,
            header,
            artifact: computed.artifact,
            artifact_digest,
            snapshot: computed.snapshot,
            snapshot_digest,
            commands: computed.commands,
            commands_digest,
            nonces: computed.nonces,
            nonces_digest,
            lifecycle: computed.lifecycle,
            lifecycle_digest,
            p_digest: [0; 32],
            commit_sequence: None,
            commit_id: None,
        };
        let p_digest = p_digest_v1(&row)?;
        Ok(Self { p_digest, ..row })
    }

    pub(super) fn commit_identity(&self) -> [u8; 32] {
        hash_domain(
            "trnm.native.replay-execution-commit.v1",
            &[
                &self.base_digest,
                &self.p_digest,
                &self.block_id,
                &self.snapshot_digest,
            ],
        )
    }
}

pub(super) fn load_all_replay_p_ordered_v1(connection: &Connection) -> Result<Vec<ReplayPRowV1>> {
    let mut statement = connection.prepare(
        "SELECT * FROM native_replay_execution_p_v1 ORDER BY p_sequence ASC, block_id ASC",
    )?;
    let mut rows = statement.query([])?;
    let mut output = Vec::new();
    while let Some(row) = rows.next()? {
        let value = ReplayPRowV1 {
            base_digest: fixed(row, "base_digest")?,
            block_id: fixed(row, "block_id")?,
            p_sequence: u64_field(row, "p_sequence")?,
            status: row
                .get::<_, i64>("status")?
                .try_into()
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            parent_kind: row
                .get::<_, i64>("parent_kind")?
                .try_into()
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            parent_head: decode_head(fixed(row, "parent_head")?)?,
            parent_p_digest: optional_fixed(row, "parent_p_digest")?,
            header: decode_header(&bounded_blob(row, "header", 1, 4096)?)?,
            artifact: bounded_blob(row, "artifact", 1, MAX_ARTIFACT)?,
            artifact_digest: fixed(row, "artifact_digest")?,
            snapshot: bounded_blob(row, "snapshot", 1, 256 * 1024 * 1024)?,
            snapshot_digest: fixed(row, "snapshot_digest")?,
            commands: bounded_blob(row, "commands", 4, MAX_COMPONENT)?,
            commands_digest: fixed(row, "commands_digest")?,
            nonces: bounded_blob(row, "nonces", 4, MAX_COMPONENT)?,
            nonces_digest: fixed(row, "nonces_digest")?,
            lifecycle: bounded_blob(row, "lifecycle", 1, MAX_LIFECYCLE)?,
            lifecycle_digest: fixed(row, "lifecycle_digest")?,
            p_digest: fixed(row, "p_digest")?,
            commit_sequence: optional_u64(row, "commit_sequence")?,
            commit_id: optional_fixed(row, "commit_id")?,
        };
        value.verify_digests()?;
        output.push(value);
    }
    Ok(output)
}

fn optional_u64(row: &rusqlite::Row<'_>, column: &str) -> Result<Option<u64>> {
    match row.get_ref(column)? {
        ValueRef::Null => Ok(None),
        ValueRef::Blob(value) => {
            Ok(Some(u64::from_be_bytes(value.try_into().map_err(
                |_| anyhow::anyhow!("replay optional u64 width: {column}"),
            )?)))
        }
        _ => anyhow::bail!("replay optional u64 type: {column}"),
    }
}

pub(super) fn load_all_replay_finality_v1(
    connection: &Connection,
) -> Result<Vec<ReplayFinalityRowV1>> {
    let mut statement = connection.prepare(
        "SELECT * FROM native_replay_execution_finality_v1 ORDER BY commit_sequence ASC, block_id ASC",
    )?;
    let mut rows = statement.query([])?;
    let mut output = Vec::new();
    while let Some(row) = rows.next()? {
        let proof = bounded_blob(row, "proof", 1, MAX_PROOF)?;
        let proof_digest = fixed(row, "proof_digest")?;
        output.push(ReplayFinalityRowV1 {
            block_id: fixed(row, "block_id")?,
            p_digest: fixed(row, "p_digest")?,
            commit_sequence: u64_field(row, "commit_sequence")?,
            proof,
            proof_digest,
            record_digest: fixed(row, "record_digest")?,
        });
    }
    Ok(output)
}

pub(super) fn insert_replay_p_v1(connection: &Connection, row: &ReplayPRowV1) -> Result<()> {
    row.verify_digests()?;
    connection.execute(
        "INSERT INTO native_replay_execution_p_v1
         (block_id,base_digest,p_sequence,status,parent_kind,parent_head,parent_p_digest,header,
          artifact,artifact_digest,snapshot,snapshot_digest,commands,commands_digest,nonces,
          nonces_digest,lifecycle,lifecycle_digest,p_digest,commit_sequence,commit_id)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)",
        params![
            row.block_id.as_slice(),
            row.base_digest.as_slice(),
            row.p_sequence.to_be_bytes().as_slice(),
            row.status as i64,
            row.parent_kind as i64,
            row.parent_head_bytes().as_slice(),
            row.parent_p_digest.as_ref().map(|v| v.as_slice()),
            row.header
                .try_cev0_bytes()
                .map_err(|error| anyhow::anyhow!("replay header encoding: {error:?}"))?,
            &row.artifact,
            row.artifact_digest.as_slice(),
            &row.snapshot,
            row.snapshot_digest.as_slice(),
            &row.commands,
            row.commands_digest.as_slice(),
            &row.nonces,
            row.nonces_digest.as_slice(),
            &row.lifecycle,
            row.lifecycle_digest.as_slice(),
            row.p_digest.as_slice(),
            row.commit_sequence.map(|v| v.to_be_bytes()),
            row.commit_id.as_ref().map(|v| v.as_slice()),
        ],
    )?;
    Ok(())
}

pub(super) fn commit_replay_p_and_insert_finality_v1(
    connection: &Connection,
    block_id: [u8; 32],
    p_digest: [u8; 32],
    commit_sequence: u64,
    commit_id: [u8; 32],
    proof: &[u8],
    base_digest: [u8; 32],
) -> Result<()> {
    ensure!(
        (1..=MAX_PROOF).contains(&proof.len()),
        "replay finality proof bound"
    );
    let proof_digest = sha256_v0(proof);
    let record_digest = hash_domain(
        "trnm.native.replay-execution-finality.v1",
        &[
            &base_digest,
            &block_id,
            &p_digest,
            &commit_sequence.to_be_bytes(),
            &proof_digest,
        ],
    );
    let changed = connection.execute(
        "UPDATE native_replay_execution_p_v1 SET status=1,commit_sequence=?1,commit_id=?2
         WHERE block_id=?3 AND p_digest=?4 AND status=0 AND commit_sequence IS NULL AND commit_id IS NULL",
        params![commit_sequence.to_be_bytes().as_slice(), commit_id.as_slice(), block_id.as_slice(), p_digest.as_slice()],
    )?;
    ensure!(changed == 1, "replay P commit CAS");
    connection.execute(
        "INSERT INTO native_replay_execution_finality_v1
         (block_id,p_digest,commit_sequence,proof,proof_digest,record_digest)
         VALUES (?1,?2,?3,?4,?5,?6)",
        params![
            block_id.as_slice(),
            p_digest.as_slice(),
            commit_sequence.to_be_bytes().as_slice(),
            proof,
            proof_digest.as_slice(),
            record_digest.as_slice()
        ],
    )?;
    Ok(())
}
