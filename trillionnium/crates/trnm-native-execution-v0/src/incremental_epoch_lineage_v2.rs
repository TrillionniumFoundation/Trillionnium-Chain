//! Bounded, iterative schema11 recovery. Original migration records never become
//! a substitute for the independently authenticated current application chain.
use super::*;
use pre_handoff::attachment;
use progress::{checkpoint, pre_handoff};

type Runtime = trnm_consensus_crypto::StrictEpochRuntimeContextV1;
struct Frame {
    runtime: Box<Runtime>,
    binding: [u8; 32],
    prefix: Vec<[u8; 32]>,
    checkpoint: ApplicationHeadV0,
    checkpoint_sequence: u64,
    first: Option<commit::Commit>,
}
impl Frame {
    fn first_p<'a>(&self, epochs: &'a BTreeMap<[u8; 32], EpochP>) -> Result<&'a EpochP> {
        epochs
            .get(
                &self
                    .first
                    .as_ref()
                    .context("schema11 unconsumed predecessor")?
                    .block,
            )
            .context("schema11 consumed first P missing")
    }
}
fn proof_row(
    config: &NativeApplicationConfigV0,
    anchor: [u8; 32],
    table: usize,
    binding: [u8; 32],
    r: &commit::Commit,
) -> Result<ProjectedRow> {
    ProjectedRow::new(
        table,
        vec![
            blob(r.block),
            blob(binding),
            blob(r.p_digest),
            number_value(r.sequence),
            blob(head_bytes(&r.head)),
            blob(&r.proof),
            blob(sha256_v0(&r.proof)),
        ],
    )
    .finish(config, anchor, &[5], &[], &[])
}
pub(super) fn load_first_records(tx: &rusqlite::Transaction<'_>) -> Result<Vec<commit::Commit>> {
    let mut q = tx.prepare("SELECT block,p_digest,sequence,head,proof,checksum FROM native_incremental_epoch_first_commit_v2 ORDER BY block LIMIT 33")?;
    let mut rows = q.query([])?;
    let mut result = Vec::new();
    while let Some(r) = rows.next()? {
        ensure!(result.len() < 32, "schema11 first proof capacity");
        result.push(commit::Commit {
            block: fixed(row_blob(r, 0, 32, 32)?)?,
            p_digest: fixed(row_blob(r, 1, 32, 32)?)?,
            sequence: number(row_blob(r, 2, 8, 8)?)?,
            head: decode_head(&row_blob(r, 3, 104, 104)?)?,
            proof: row_blob(r, 4, 1, MAX_PROOF)?,
            checksum: fixed(row_blob(r, 5, 32, 32)?)?,
        });
    }
    Ok(result)
}
fn frame_for<'a>(frames: &'a [Frame], h: &BlockHeader) -> Result<&'a Frame> {
    frames
        .iter()
        .find(|f| f.runtime.activation().new_validator_set().epoch() == h.epoch())
        .context("schema11 P epoch absent from authenticated prefix")
}
fn parent_header(
    p: &P,
    ordinary: &BTreeMap<[u8; 32], P>,
    epochs: &BTreeMap<[u8; 32], EpochP>,
) -> Result<BlockHeader> {
    if let Some(parent) = ordinary.get(p.parent.block_id().as_bytes()) {
        ensure!(
            parent.target()? == p.parent
                && p.parent_p == Some(parent.digest)
                && parent.sequence < p.sequence,
            "schema11 ordinary parent identity"
        );
        header(&parent.header)
    } else {
        let parent = epochs
            .get(p.parent.block_id().as_bytes())
            .context("schema11 epoch parent missing")?;
        ensure!(
            parent.target()? == p.parent
                && p.parent_p == Some(parent.digest)
                && parent.sequence < p.sequence,
            "schema11 first parent identity"
        );
        header(&parent.header)
    }
}
fn replay_parent(
    p: &P,
    ordinary: &BTreeMap<[u8; 32], P>,
    epochs: &BTreeMap<[u8; 32], EpochP>,
    consumed: &BTreeSet<[u8; 32]>,
) -> Result<(ReplayHead, Vec<ReplayDelta>)> {
    let mut current = p;
    let mut suffix = Vec::new();
    let mut bytes = 0usize;
    loop {
        if let Some(parent) = epochs.get(current.parent.block_id().as_bytes()) {
            let delta = ReplayDelta::decode(&parent.replay_delta)?;
            ensure!(
                parent.target()? == current.parent
                    && current.parent_p == Some(parent.digest)
                    && parent.sequence < current.sequence
                    && current.replay_parent == delta.head,
                "schema11 first replay parent differs"
            );
            if consumed.contains(&parent.block) {
                return Ok((delta.head, suffix));
            }
            bytes = bytes
                .checked_add(parent.replay_delta.len())
                .context("schema11 replay size overflow")?;
            ensure!(
                suffix.len() < 8 && bytes <= 64 * 1024 * 1024,
                "schema11 pending first replay bound"
            );
            suffix.push(delta);
            return Ok((parent.replay_parent, suffix));
        }
        let parent = ordinary
            .get(current.parent.block_id().as_bytes())
            .context("schema11 replay parent missing")?;
        let delta = parent.replay()?;
        ensure!(
            parent.target()? == current.parent
                && current.parent_p == Some(parent.digest)
                && parent.sequence < current.sequence
                && current.replay_parent == delta.head,
            "schema11 ordinary replay parent differs"
        );
        if parent.status == 1 {
            return Ok((delta.head, suffix));
        }
        bytes = bytes
            .checked_add(parent.replay_delta.len())
            .context("schema11 replay size overflow")?;
        ensure!(
            suffix.len() < 8 && bytes <= 64 * 1024 * 1024,
            "schema11 pending replay bound"
        );
        suffix.push(delta);
        current = parent;
    }
}
fn require_pending_ancestry(
    p: &P,
    ordinary: &BTreeMap<[u8; 32], P>,
    epochs: &BTreeMap<[u8; 32], EpochP>,
    head: &ApplicationHeadV0,
    replay: ReplayHead,
) -> Result<()> {
    let mut cursor = p;
    let mut depth = 0;
    let mut bytes = 0usize;
    loop {
        depth += 1;
        bytes = bytes
            .checked_add(cursor.replay_delta.len())
            .context("schema11 pending ancestry size overflow")?;
        ensure!(
            depth <= 8 && bytes <= 64 * 1024 * 1024 && cursor.status == 0,
            "schema11 pending ancestry capacity/phase"
        );
        if cursor.parent == *head {
            ensure!(
                cursor.replay_parent == replay,
                "schema11 pending current replay anchor"
            );
            return Ok(());
        }
        if let Some(first) = epochs.get(cursor.parent.block_id().as_bytes()) {
            bytes = bytes
                .checked_add(first.replay_delta.len())
                .context("schema11 pending first size overflow")?;
            ensure!(
                depth < 8
                    && bytes <= 64 * 1024 * 1024
                    && first.parent == *head
                    && first.replay_parent == replay,
                "schema11 pending first current anchor/bound"
            );
            return Ok(());
        }
        cursor = ordinary
            .get(cursor.parent.block_id().as_bytes())
            .context("schema11 pending parent absent")?;
    }
}

fn no_seals(tx: &rusqlite::Transaction<'_>, frame: &Frame) -> Result<()> {
    let coordinates = crate::epoch_edge::EpochApplicationCoordinatesV1 {
        checkpoint_version: frame.checkpoint.height().get(),
        checkpoint_root: *frame.checkpoint.state_root().as_bytes(),
        terminal_version: frame
            .runtime
            .activation()
            .terminal_old_header()
            .height()
            .get(),
        first_version: frame
            .checkpoint
            .height()
            .get()
            .checked_add(3)
            .context("schema11 first height overflow")?,
        authorization_id: frame.binding,
    };
    coordinates.validate()?;
    ni::require_absent_incremental_seals_v1(tx, coordinates)?;
    let pins: u64 = tx.query_row(
        "SELECT count(*) FROM ni_pin WHERE version>?1 AND version<?2",
        params![
            coordinates.checkpoint_version.to_be_bytes().as_slice(),
            coordinates.first_version.to_be_bytes().as_slice()
        ],
        |r| r.get(0),
    )?;
    ensure!(pins == 0, "schema11 seal has a sparse root pin");
    Ok(())
}

pub(super) fn verify_header_proof(
    runtime: &Runtime,
    proof: &[u8],
    parent_timestamp: u64,
    expected: &BlockHeader,
    budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
) -> Result<()> {
    let verified = runtime
        .decode_verify_finality_v1(proof, parent_timestamp, budget)
        .map_err(|e| anyhow::anyhow!("schema11 strict finality: {e}"))?;
    ensure!(
        verified.finalized_block().header() == expected,
        "schema11 complete finalized header differs"
    );
    Ok(())
}

struct AuditedHandoff {
    head: ApplicationHeadV0,
    strict: Box<trnm_consensus_crypto::StrictPreHandoffContextV1>,
}

// Authenticate all P/proof/sidecar records in an epoch before its successor can
// consume that epoch's checkpoint. No mutable caller context enters this walk.
#[allow(clippy::too_many_arguments)]
fn audit_frame(
    tx: &rusqlite::Transaction<'_>,
    config: &NativeApplicationConfigV0,
    base: &Owner,
    pin: [u8; 32],
    frame: &Frame,
    epochs: &BTreeMap<[u8; 32], EpochP>,
    ordinary: &BTreeMap<[u8; 32], P>,
    records: &[commit::Commit],
    prehands: &[pre_handoff::PreHandoff],
    rows: &mut Vec<ProjectedRow>,
    budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
) -> Result<Option<AuditedHandoff>> {
    let set = frame.runtime.activation().new_validator_set();
    let parameters = frame.runtime.activation().new_consensus_parameters();
    let geometry = trnm_consensus_types::EpochGeometryV0::new(set.epoch(), parameters)
        .map_err(|e| anyhow::anyhow!("schema11 frame geometry: {e:?}"))?;
    no_seals(tx, frame)?;
    let staged: Vec<_> = epochs
        .values()
        .filter(|p| p.edge == frame.binding)
        .collect();
    if frame.first.is_some() || !staged.is_empty() {
        let (phase, block): (u8, Option<Vec<u8>>) = tx.query_row(
            "SELECT phase,committed_block FROM ni_epoch_edge WHERE strict_binding=?1",
            [frame.binding.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure!(
            phase == u8::from(frame.first.is_some())
                && block.as_deref() == frame.first.as_ref().map(|r| r.block.as_slice()),
            "schema11 native/sparse edge consumption differs"
        );
    }
    let checkpoint_replay = if frame.checkpoint == base.source {
        ReplayHead {
            version: 0,
            root: base.source_replay,
        }
    } else {
        ordinary
            .get(frame.checkpoint.block_id().as_bytes())
            .context("schema11 frame checkpoint absent")?
            .replay()?
            .head
    };
    for p in staged {
        ensure!(
            frame.first.as_ref().is_none_or(|r| r.block == p.block),
            "schema11 losing first P retained after consumption"
        );
        p.validate_context(
            config,
            &EpochPContext {
                parent: &frame.checkpoint,
                checkpoint_sequence: frame.checkpoint_sequence,
                binding: frame.binding,
                terminal: frame.runtime.activation().terminal_old_header(),
                set,
                parameters,
            },
        )?;
        ensure!(
            p.replay_parent == checkpoint_replay,
            "schema11 epoch replay checkpoint differs"
        );
        rows.push(
            ProjectedRow::new(
                2,
                vec![
                    blob(p.block),
                    blob(p.digest),
                    Value::Integer(1),
                    blob(prefix(&frame.prefix)?),
                    Value::Null,
                    Value::Null,
                    Value::Null,
                ],
            )
            .finish(config, base.anchor, &[], &[4, 5, 6], &[])?,
        );
    }
    if let Some(r) = &frame.first {
        let p = frame.first_p(epochs)?;
        ensure!(
            p.edge == frame.binding
                && p.target()? == r.head
                && p.digest == r.p_digest
                && r.sequence > p.sequence,
            "schema11 first record/P differs"
        );
        verify_header_proof(
            &frame.runtime,
            &r.proof,
            frame
                .runtime
                .activation()
                .terminal_old_header()
                .timestamp_ms(),
            &header(&p.header)?,
            budget,
        )?;
        rows.push(proof_row(config, base.anchor, 4, frame.binding, r)?);
    }
    for p in ordinary.values() {
        let h = header(&p.header)?;
        if h.epoch() != set.epoch() {
            continue;
        }
        let parent = parent_header(p, ordinary, epochs)?;
        ensure!(
            parent.epoch() == h.epoch(),
            "schema11 ordinary crosses epoch without first P"
        );
        if h.block_kind() == trnm_consensus_types::BlockKind::EpochCheckpoint {
            ensure!(
                frame.first.is_some(),
                "schema11 checkpoint before first commit"
            );
            p.validate_context_kind(
                config,
                set,
                parameters,
                trnm_consensus_types::BlockKind::EpochCheckpoint,
            )?;
            ensure!(
                p.target()?.height().get() == geometry.checkpoint_height().get(),
                "schema11 checkpoint geometry"
            );
            rows.push(checkpoint::checkpoint_context(
                tx,
                config,
                base,
                &frame.prefix,
                ordinary,
                set,
                parameters,
                p,
            )?);
            checkpoint::audit_sidecar_for_context(
                tx,
                config,
                &checkpoint::PlanningContext {
                    base,
                    ordinary,
                    runtime: &frame.runtime,
                    bindings: &frame.prefix,
                    pin,
                },
                p,
                budget,
            )?;
        } else {
            descendant::validate_p(p, config, set, parameters, frame.checkpoint.height().get())?;
            rows.push(
                ProjectedRow::new(
                    2,
                    vec![
                        blob(p.block),
                        blob(p.digest),
                        Value::Integer(0),
                        blob(prefix(&frame.prefix)?),
                        Value::Null,
                        Value::Null,
                        Value::Null,
                    ],
                )
                .finish(config, base.anchor, &[], &[4, 5, 6], &[])?,
            );
        }
        ensure!(
            frame.first.is_some() || p.status == 0,
            "schema11 ordinary committed before edge consumption"
        );
    }
    for r in records {
        let p = ordinary
            .get(&r.block)
            .context("schema11 ordinary record P absent")?;
        let h = header(&p.header)?;
        if h.epoch() != set.epoch() {
            continue;
        }
        ensure!(
            h.block_kind() == trnm_consensus_types::BlockKind::Regular,
            "schema11 ordinary proof kind"
        );
        let parent = parent_header(p, ordinary, epochs)?;
        verify_header_proof(&frame.runtime, &r.proof, parent.timestamp_ms(), &h, budget)?;
        rows.push(proof_row(config, base.anchor, 5, frame.binding, r)?);
    }
    let matching: Vec<_> = prehands
        .iter()
        .filter(|r| {
            ordinary
                .get(&r.record.block)
                .is_some_and(|p| header(&p.header).is_ok_and(|h| h.epoch() == set.epoch()))
        })
        .collect();
    ensure!(
        matching.len() <= 1,
        "schema11 multiple pre-handoffs in one epoch"
    );
    let mut handoff = None;
    for r in matching {
        let (row, strict) = pre_handoff::audit(
            tx,
            config,
            base,
            &frame.prefix,
            frame.first_p(epochs)?,
            ordinary,
            &frame.runtime,
            r,
            budget,
        )?;
        rows.push(row);
        handoff = Some(AuditedHandoff {
            head: r.record.head.clone(),
            strict,
        });
    }
    Ok(handoff)
}

pub(super) fn projection(
    tx: &rusqlite::Transaction<'_>,
    config: &NativeApplicationConfigV0,
    m: &MetadataV0,
    budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
) -> Result<Projection> {
    screen_inventory(tx, SCHEMA_VERSION)?;
    let migration_sequence = number(tx.query_row(
        "SELECT migration_sequence FROM native_incremental_epoch_owner_v2 WHERE id=1",
        [],
        |r| row_blob(r, 0, 8, 8),
    )?)?;
    let (base, edge, audited) = audit_source_owner(tx, config, m, budget)?;
    validate_source_replay(tx, config, &base)?;
    let original_first = commit::load(tx)?.context("schema11 consumed original edge absent")?;
    let original_first_p = commit::audit_record_shape(
        tx,
        config,
        &edge,
        &base.source,
        &audited.activation,
        &original_first,
    )?;
    ensure!(
        original_first.sequence <= migration_sequence && migration_sequence <= m.durable_sequence,
        "schema11 immutable migration sequence"
    );
    let original_records = bounded_blocks(tx, "native_incremental_epoch_descendant_commit_v1")?
        .into_iter()
        .map(|b| descendant::load_commit(tx, b)?.context("schema11 original record missing"))
        .collect::<Result<Vec<_>>>()?;
    for r in &original_records {
        ensure!(
            r.sequence <= migration_sequence
                && r.checksum == descendant::commit_digest(config, &edge, r),
            "schema11 original proof changed"
        );
    }
    let mut digests = vec![edge.checksum, original_first.checksum];
    digests.extend(original_records.iter().map(|r| r.checksum));
    digests.sort();
    let mut fields = vec![
        base.anchor.to_vec(),
        migration_sequence.to_be_bytes().to_vec(),
    ];
    fields.extend(digests.iter().map(|d| d.to_vec()));
    let pin = hash_domain(
        "trnm.native-application.incremental-epoch-migration.v2",
        &fields.iter().map(Vec::as_slice).collect::<Vec<_>>(),
    );
    let mut epochs = BTreeMap::new();
    let mut ordinary = BTreeMap::new();
    let mut blocks = BTreeSet::new();
    let mut sequences = BTreeSet::new();
    for block in bounded_blocks(tx, "native_incremental_epoch_p_v1")? {
        let p = load_epoch_p(tx, block)?.context("schema11 epoch P missing")?;
        p.validate_storage(tx)?;
        ensure!(
            p.sequence > base.source_sequence
                && p.sequence <= m.durable_sequence
                && sequences.insert(p.sequence)
                && blocks.insert(p.block),
            "schema11 epoch sequence/block collision"
        );
        ensure!(
            ReplayReader::new(tx, Some(p.replay_parent), &[])?
                .append(replay_keys(
                    p.executed()?.request().preview().transactions()
                )?)?
                .encode()?
                == p.replay_delta,
            "schema11 epoch replay substitution"
        );
        let reader = ni::open_incremental_reader_v1(
            tx,
            &namespace(config),
            ni::IncrementalParentV1::Prepared(p.storage_artifact),
        )?;
        ensure!(
            reader.version() == p.target()?.height().get()
                && reader.root().0 == *p.target()?.state_root().as_bytes(),
            "schema11 epoch sparse target"
        );
        let _ = reader.verified_live_values_v1()?;
        epochs.insert(block, p);
    }
    ensure!(
        epochs
            .get(&original_first.block)
            .is_some_and(|p| p.digest == original_first_p.digest),
        "schema11 original first artifact missing"
    );
    for block in bounded_blocks(tx, "native_incremental_p_v1")? {
        let p = load_p(tx, block)?.context("schema11 ordinary P missing")?;
        descendant::validate_storage_p(tx, &p)?;
        ensure!(
            p.sequence > original_first_p.sequence
                && p.sequence <= m.durable_sequence
                && sequences.insert(p.sequence)
                && blocks.insert(p.block),
            "schema11 ordinary sequence/block collision"
        );
        ordinary.insert(block, p);
    }
    let first_records = load_first_records(tx)?;
    let ordinary_records = load_ordinary_records(tx)?;
    let mut prehands = pre_handoff::load_all(tx)?;
    ensure!(
        first_records.iter().any(|r| r.block == original_first.block
            && r.p_digest == original_first.p_digest
            && r.sequence == original_first.sequence
            && r.head == original_first.head
            && r.proof == original_first.proof),
        "schema11 original first proof changed"
    );
    for original in &original_records {
        ensure!(
            ordinary_records.iter().any(|r| r.block == original.block
                && r.p_digest == original.p_digest
                && r.sequence == original.sequence
                && r.head == original.head
                && r.proof == original.proof),
            "schema11 original ordinary proof changed"
        );
    }
    let mut records = BTreeMap::new();
    let mut generation = 0u64;
    for r in first_records
        .iter()
        .chain(ordinary_records.iter())
        .chain(prehands.iter().map(|r| &r.record))
    {
        ensure!(
            r.sequence <= m.durable_sequence
                && sequences.insert(r.sequence)
                && records.insert(r.block, r).is_none(),
            "schema11 commit sequence/block collision"
        );
        if r.sequence > migration_sequence {
            generation = generation
                .checked_add(1)
                .context("schema11 generation overflow")?;
        } else {
            ensure!(
                r.block == original_first.block
                    || original_records.iter().any(|old| old.block == r.block),
                "schema11 new proof below migration"
            );
        }
    }
    let mut attachments = attachment::load(tx)?;
    generation = generation
        .checked_add(u64::try_from(attachments.len())?)
        .context("schema11 attachment generation overflow")?;
    let source_runtime = Runtime::from_activation_v1(audited.activation)
        .map_err(|e| anyhow::anyhow!("schema11 source runtime: {e}"))?;
    let mut frames = vec![Frame {
        runtime: Box::new(source_runtime),
        binding: edge.binding,
        prefix: vec![edge.binding],
        checkpoint: base.source.clone(),
        checkpoint_sequence: edge.sequence,
        first: Some(original_first.clone()),
    }];
    let mut rows = Vec::new();
    let mut signing_context = None;
    for attachment in &attachments {
        let previous = frames.last().context("schema11 empty prefix")?;
        if let Some(handoff) = audit_frame(
            tx,
            config,
            &base,
            pin,
            previous,
            &epochs,
            &ordinary,
            &ordinary_records,
            &prehands,
            &mut rows,
            budget,
        )? {
            if handoff.head == m.head {
                signing_context = Some(handoff.strict);
            }
        }
        let checkpoint = prehands
            .iter()
            .find(|r| r.record.head == attachment.checkpoint)
            .context("schema11 edge checkpoint record missing")?;
        let runtime = attachment::verify_record(
            config,
            &base,
            attachment,
            &previous.prefix,
            previous.first_p(&epochs)?,
            &ordinary,
            &previous.runtime,
            checkpoint,
            budget,
        )?;
        let mut bindings = previous.prefix.clone();
        bindings.push(attachment.binding);
        let first = attachment
            .consumed
            .as_ref()
            .map(|c| -> Result<_> {
                let r = first_records
                    .iter()
                    .find(|r| r.block == c.block)
                    .context("schema11 consumed edge first proof missing")?;
                ensure!(
                    r.p_digest == c.p_digest && r.sequence == c.sequence,
                    "schema11 consumed edge first identity"
                );
                Ok(r.clone())
            })
            .transpose()?;
        frames.push(Frame {
            runtime,
            binding: attachment.binding,
            prefix: bindings,
            checkpoint: attachment.checkpoint.clone(),
            checkpoint_sequence: attachment.checkpoint_sequence,
            first,
        });
        rows.push(attachment.projected(config, base.anchor)?);
    }
    if let Some(handoff) = audit_frame(
        tx,
        config,
        &base,
        pin,
        frames.last().context("schema11 empty frames")?,
        &epochs,
        &ordinary,
        &ordinary_records,
        &prehands,
        &mut rows,
        budget,
    )? {
        if handoff.head == m.head {
            signing_context = Some(handoff.strict);
        }
    }
    ensure!(
        frames.iter().filter(|f| f.first.is_some()).count() == first_records.len(),
        "schema11 orphan first proof"
    );
    for p in epochs.values() {
        ensure!(
            frames.iter().any(|f| f.binding == p.edge),
            "schema11 epoch P has no strict context"
        );
    }
    let consumed: BTreeSet<_> = first_records.iter().map(|r| r.block).collect();
    for p in ordinary.values() {
        let _ = frame_for(&frames, &header(&p.header)?)?;
        if p.status == 0 {
            require_pending_ancestry(p, &ordinary, &epochs, &m.head, base.replay)?;
        }
        let (parent, suffix) = replay_parent(p, &ordinary, &epochs, &consumed)?;
        ensure!(
            ReplayReader::new(tx, Some(parent), &suffix)?
                .append(replay_keys(p.executed()?.request().transactions())?)?
                .encode()?
                == p.replay_delta,
            "schema11 ordinary replay substitution"
        );
        let reader = ni::open_incremental_reader_v1(
            tx,
            &namespace(config),
            ni::IncrementalParentV1::Prepared(p.storage_artifact),
        )?;
        ensure!(
            reader.version() == p.target()?.height().get()
                && reader.root().0 == *p.target()?.state_root().as_bytes(),
            "schema11 ordinary sparse target"
        );
        let _ = reader.verified_live_values_v1()?;
    }
    let (ni_p, ni_edges): (usize, usize) = tx.query_row(
        "SELECT (SELECT count(*) FROM ni_prepared),(SELECT count(*) FROM ni_epoch_edge)",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    ensure!(
        ni_p == epochs.len() + ordinary.len()
            && ni_edges
                == frames
                    .iter()
                    .filter(|f| f.first.is_some() || epochs.values().any(|p| p.edge == f.binding))
                    .count(),
        "schema11 exact sparse inventory differs"
    );
    // One global backward application/replay walk accounts for every committed
    // row, including real C→C+3 transitions. Speculative persist sequences are
    // ordered by their actual parent P; commits are ordered by committed parent.
    let mut cursor = m.head.clone();
    let mut replay = base.replay;
    let mut child_sequence = None;
    let mut visited = BTreeSet::new();
    while cursor != base.source {
        ensure!(
            visited.len() < 256 && visited.insert(*cursor.block_id().as_bytes()),
            "schema11 backward lineage bound/cycle"
        );
        let r = records
            .get(cursor.block_id().as_bytes())
            .context("schema11 committed head proof absent")?;
        ensure!(
            r.head == cursor && child_sequence.is_none_or(|seq| r.sequence < seq),
            "schema11 backward commit chronology"
        );
        if child_sequence.is_none() {
            ensure!(
                r.sequence == base.commit_sequence,
                "schema11 owner head sequence"
            );
        }
        child_sequence = Some(r.sequence);
        if let Some(p) = epochs.get(&r.block) {
            let frame = frames
                .iter()
                .find(|f| f.binding == p.edge)
                .context("schema11 committed first context absent")?;
            ensure!(
                frame
                    .first
                    .as_ref()
                    .is_some_and(|first| first.block == r.block)
                    && p.digest == r.p_digest
                    && p.target()? == r.head
                    && r.sequence > p.sequence
                    && ReplayDelta::decode(&p.replay_delta)?.head == replay
                    && p.parent.height().get().checked_add(3) == Some(cursor.height().get()),
                "schema11 committed first ancestry"
            );
            cursor = p.parent.clone();
            replay = p.replay_parent;
        } else {
            let p = ordinary
                .get(&r.block)
                .context("schema11 committed ordinary P absent")?;
            ensure!(
                p.status == 1
                    && p.commit_sequence == Some(r.sequence)
                    && p.digest == r.p_digest
                    && p.target()? == r.head
                    && r.sequence > p.sequence
                    && p.replay()?.head == replay
                    && p.parent.height().get().checked_add(1) == Some(cursor.height().get()),
                "schema11 committed ordinary ancestry"
            );
            let _ = parent_header(p, &ordinary, &epochs)?;
            cursor = p.parent.clone();
            replay = p.replay_parent;
        }
    }
    ensure!(
        visited.len() == records.len()
            && ordinary.values().filter(|p| p.status == 1).count()
                == ordinary_records.len() + prehands.len()
            && replay
                == (ReplayHead {
                    version: 0,
                    root: base.source_replay
                })
            && child_sequence.is_some_and(|seq| seq > base.source_sequence)
            && sequences.last().copied() == Some(m.durable_sequence),
        "schema11 closed current lineage"
    );
    let _ = ReplayReader::new(tx, Some(base.replay), &[])?;
    let evidence = EpochRecoveryEvidenceV1::decode(&edge.evidence)?;
    let empty = 0u32.to_be_bytes();
    let context = hash_domain(
        "trnm.native-application.incremental-epoch-context.v2",
        &[
            &config.store_id,
            &base.anchor,
            &edge.checkpoint_p,
            &head_bytes(&base.source),
            &edge.sequence.to_be_bytes(),
            &empty,
            &sha256_v0(&evidence.old_set),
            &sha256_v0(&evidence.old_parameters),
            &sha256_v0(&evidence.cutoff_finality),
        ],
    );
    rows.push(
        ProjectedRow::new(
            1,
            vec![
                blob(edge.binding),
                number_value(0),
                Value::Null,
                blob(empty),
                blob(head_bytes(&base.source)),
                blob(edge.checkpoint_p),
                number_value(edge.sequence),
                blob(context),
                Value::Integer(0),
                blob(&edge.evidence),
                Value::Integer(1),
                blob(original_first.block),
                blob(original_first.p_digest),
                number_value(original_first.sequence),
            ],
        )
        .finish(config, base.anchor, &[9], &[2, 11, 12, 13], &[])?,
    );
    let owner_prefix = frames
        .last()
        .context("schema11 empty prefix")?
        .prefix
        .clone();
    rows.push(
        ProjectedRow::new(
            0,
            vec![
                Value::Integer(1),
                Value::Integer(2),
                blob(base.anchor),
                number_value(migration_sequence),
                blob(pin),
                blob(*owner_prefix.last().context("schema11 empty owner prefix")?),
                blob(prefix(&owner_prefix)?),
                number_value(generation),
            ],
        )
        .finish(
            config,
            base.anchor,
            &[],
            &[],
            &[&base.checksum, &head_bytes(&m.head)],
        )?,
    );
    let pending = if frames.last().is_some_and(|f| f.first.is_none()) {
        let frame = frames.pop().context("schema11 installed frame missing")?;
        ensure!(
            frame.checkpoint == m.head,
            "schema11 installed edge not at current checkpoint"
        );
        let record = attachments
            .pop()
            .context("schema11 installed record missing")?;
        Some(attachment::Pending {
            record,
            runtime: frame.runtime,
        })
    } else {
        None
    };
    let active = frames
        .pop()
        .context("schema11 consumed active frame absent")?;
    let first = active.first.context("schema11 active frame unconsumed")?;
    let first_p = epochs
        .get(&first.block)
        .context("schema11 active first P absent")?
        .clone();
    let pre_handoff = prehands
        .iter()
        .position(|p| p.record.head == m.head)
        .map(|i| prehands.remove(i));
    Ok(Projection {
        rows,
        pin,
        old_pin: edge.checksum,
        signing_context,
        current: Current {
            base,
            first_p,
            ordinary,
            epochs,
            runtime: active.runtime,
            active_binding: active.binding,
            active_prefix: active.prefix,
            historical: frames
                .into_iter()
                .map(|f| HistoricalContext {
                    runtime: f.runtime,
                    binding: f.binding,
                    prefix: f.prefix,
                })
                .collect(),
            migration_sequence,
            generation,
            pre_handoff,
            pending,
        },
    })
}
