//! Narrow retained-header reads for an already authenticated epoch prefix.
//! Full P/execution/snapshot auditing remains the outer inventory's job.
use super::*;

const MAX_HEADERS: usize = 256;
const MAX_ANCESTRY_BYTES: usize = 1024 * 1024;

struct Row {
    block: [u8; 32],
    p_sequence: u64,
    p_digest: [u8; 32],
    commit_sequence: u64,
    commit_id: [u8; 32],
    snapshot_digest: [u8; 32],
    artifact_kind: i64,
    parent_kind: i64,
    parent: ApplicationHeadV0,
    parent_p_digest: Option<[u8; 32]>,
    consensus_parent_height: u64,
    consensus_parent_block: [u8; 32],
    height: u64,
    header: Vec<u8>,
}

fn read_row(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    block: &[u8; 32],
    lineage: &[u8],
    remaining_bytes: usize,
) -> Result<Row> {
    // Scalar screening precedes the only variable-sized copy below. Fixed
    // columns use ValueRef-backed col32/col64 and never allocate a blob first.
    let (count, header_len, lineage_len): (i64, i64, i64) = connection.query_row(
        "SELECT count(*),
            coalesce(max(CASE WHEN typeof(header)='blob' THEN length(header) ELSE -1 END),-1),
            coalesce(max(CASE WHEN typeof(edge_lineage)='blob' THEN length(edge_lineage) ELSE -1 END),-1)
         FROM native_durable_execution_p_v1 WHERE block_id=?1",
        [block.as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    ensure!(
        count == 1
            && header_len > 0
            && header_len as usize <= MAX_HEADER_BYTES
            && header_len as usize <= remaining_bytes
            && lineage_len == i64::try_from(lineage.len())?,
        "later successor ancestry row count/type/byte bound"
    );
    let value = connection.query_row(
        "SELECT block_id,store_id,p_sequence,status,artifact_kind,header,parent_kind,
                parent_height,parent_block,parent_root,parent_commit_id,parent_p_digest,
                consensus_parent_height,consensus_parent_block,target_height,
                edge_lineage,lineage_digest,snapshot_digest,p_digest,commit_sequence,commit_id
         FROM native_durable_execution_p_v1 WHERE block_id=?1",
        [block.as_slice()],
        |row| {
            use rusqlite::types::ValueRef;
            let header = match row.get_ref("header")? {
                ValueRef::Blob(bytes) if bytes.len() == header_len as usize => bytes,
                _ => return Err(rusqlite::Error::InvalidQuery),
            };
            match row.get_ref("edge_lineage")? {
                ValueRef::Blob(bytes) if bytes == lineage => {}
                _ => return Err(rusqlite::Error::InvalidQuery),
            }
            if col32(row, "store_id")? != config.store_id
                || col32(row, "block_id")? != *block
                || col32(row, "lineage_digest")? != sha256_v0(lineage)
                || row.get::<_, i64>("status")? != 1
            {
                return Err(rusqlite::Error::InvalidQuery);
            }
            let parent = ApplicationHeadV0::new(
                HeightV0::new(col64(row, "parent_height")?),
                BlockIdV0::new(col32(row, "parent_block")?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                StateRootV0::new(col32(row, "parent_root")?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                ApplicationCommitIdV0::new(col32(row, "parent_commit_id")?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
            );
            Ok(Row {
                block: *block,
                p_sequence: col64(row, "p_sequence")?,
                p_digest: col32(row, "p_digest")?,
                commit_sequence: col64(row, "commit_sequence")?,
                commit_id: col32(row, "commit_id")?,
                snapshot_digest: col32(row, "snapshot_digest")?,
                artifact_kind: row.get("artifact_kind")?,
                parent_kind: row.get("parent_kind")?,
                parent,
                parent_p_digest: opt32(row, "parent_p_digest")?,
                consensus_parent_height: col64(row, "consensus_parent_height")?,
                consensus_parent_block: col32(row, "consensus_parent_block")?,
                height: col64(row, "target_height")?,
                header: header.to_vec(),
            })
        },
    )?;
    // Count competing committed rows; never choose an ancestor by height.
    let at_height: i64 = connection.query_row(
        "SELECT count(*) FROM native_durable_execution_p_v1
         WHERE status=1 AND target_height=?1",
        [value.height.to_be_bytes().as_slice()],
        |row| row.get(0),
    )?;
    ensure!(at_height == 1, "later successor ancestry committed fork");
    Ok(value)
}

#[inline(never)]
pub(super) fn load(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    prefix: &Prefix,
    parent: &StoredEpochPV1,
) -> Result<Vec<BlockHeader>> {
    ensure!(
        prefix.entries.len() <= MAX_EDGES,
        "epoch lineage count budget"
    );
    let lineage = encode_lineage(&prefix.bindings())?;
    let predecessor = prefix
        .entries
        .last()
        .context("later predecessor edge missing")?;
    let consumed = predecessor
        .consumed
        .context("later predecessor consumer missing")?;
    let consumed_sequence = predecessor
        .consumed_sequence
        .context("later predecessor consumer sequence missing")?;
    ensure!(
        predecessor.phase == 1 && parent.lineage == lineage && parent.status == 1,
        "later successor requires consumed prefix and committed parent"
    );
    let activation = &predecessor.audit.activation;
    ensure!(
        parent.target_set
            == activation
                .new_validator_set()
                .try_cev0_bytes()
                .map_err(|e| anyhow::anyhow!("later successor active set: {e:?}"))?
            && parent.target_parameters == activation.new_consensus_parameters().canonical_bytes(),
        "later successor parent active configuration"
    );
    let terminal = activation.terminal_old_header();
    let mut bytes = terminal
        .try_cev0_bytes()
        .map_err(|e| anyhow::anyhow!("later successor terminal: {e:?}"))?
        .len();
    ensure!(
        bytes <= MAX_HEADER_BYTES,
        "later successor terminal byte bound"
    );
    let mut reversed = Vec::new();
    let mut seen = BTreeSet::new();
    let mut expected_head = parent.target_head()?;
    let mut expected_p_digest = parent.p_digest;
    let mut child_sequence = None;
    loop {
        // Reserve one position and its bytes for the original terminal seal.
        ensure!(
            reversed.len() + 1 < MAX_HEADERS,
            "later successor ancestry count bound"
        );
        let block = *expected_head.block_id().as_bytes();
        ensure!(seen.insert(block), "later successor ancestry cycle");
        let row = read_row(
            connection,
            config,
            &block,
            &lineage,
            MAX_ANCESTRY_BYTES - bytes,
        )?;
        bytes += row.header.len();
        let header = decode_header(&row.header)?;
        let commit_id = hash_domain(
            "trnm.native-application.commit-id.v1",
            &[&row.p_digest, &row.block, &row.snapshot_digest],
        );
        ensure!(
            row.p_sequence > 1
                && row.commit_sequence > row.p_sequence
                && row.p_digest == expected_p_digest
                && row.commit_id == commit_id
                && expected_head.height().get() == row.height
                && expected_head.commit_id().as_bytes() == &commit_id
                && expected_head.state_root().as_bytes() == header.state_root().as_bytes()
                && header.id().as_bytes() == &row.block
                && header.height().get() == row.height
                && header.parent_id().as_bytes() == &row.consensus_parent_block
                && row.consensus_parent_height.checked_add(1) == Some(row.height)
                && header.chain_id().as_str() == config.chain_id
                && header.genesis_hash().as_bytes() == &config.genesis_hash
                && child_sequence.is_none_or(|child| row.commit_sequence < child),
            "later successor ancestry committed identity or sequence"
        );
        if reversed.is_empty() {
            ensure!(
                row.header == parent.header
                    && row.p_sequence == parent.p_sequence
                    && Some(row.commit_sequence) == parent.commit_sequence,
                "later successor parent readback changed"
            );
        }
        if row.block == consumed {
            ensure!(
                row.artifact_kind == 1
                    && header.block_kind() == BlockKind::EpochHandoff
                    && row.commit_sequence == consumed_sequence
                    && row.commit_sequence > predecessor.checkpoint_sequence
                    && row.parent == predecessor.checkpoint
                    && row.consensus_parent_height == terminal.height().get()
                    && row.consensus_parent_block == *terminal.id().as_bytes()
                    && ((row.parent_kind == 1
                        && row.parent_p_digest == Some(predecessor.checkpoint_p_digest))
                        || (predecessor.later_facts.is_none()
                            && prefix.entries.len() == 1
                            && row.parent_kind == 0
                            && row.parent_p_digest.is_none())),
                "later successor first application binding"
            );
            reversed.push(header);
            break;
        }
        ensure!(
            row.artifact_kind == 0
                && header.block_kind() == BlockKind::Regular
                && row.parent_kind == 1
                && row.parent_p_digest.is_some()
                && row.parent.height().get() == row.consensus_parent_height
                && row.parent.block_id().as_bytes() == &row.consensus_parent_block
                && row.height > terminal.height().get(),
            "later successor ordinary ancestry parent"
        );
        reversed.push(header);
        expected_head = row.parent;
        expected_p_digest = row
            .parent_p_digest
            .context("later successor parent P digest")?;
        child_sequence = Some(row.commit_sequence);
    }
    reversed.push(terminal.clone());
    reversed.reverse();
    Ok(reversed)
}
