//! Original native transactions own these markers; a recovery caller cannot
//! insert a marker after the fact or make a marker stand in for original State.
use super::*;

pub(super) fn owner_marker(identity: &policy::Identity, path: &Path) -> Result<Vec<u8>> {
    ensure(path.is_absolute(), "HISTORY_V6_JOURNAL_PATH")?;
    policy::encoded(
        &serde_json::json!({"schema":"restricted-history-effect-required-owner-v6",
        "identity":identity,"identity_sha256":identity.digest()?,"journal_path":path}),
    )
}
pub(super) fn frontier(db: &Connection) -> Result<Frontier> {
    let (tip, root, generation): (Vec<u8>, Vec<u8>, u64) = db.query_row(
        "SELECT a.tip,b.state_root,a.generation FROM active a JOIN blocks b ON b.id=a.tip WHERE a.singleton=1", [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
    let frontier = Frontier {
        block: hex::encode(bytes32(tip)?),
        root: hex::encode(bytes32(root)?),
        generation,
    };
    frontier.validate()?;
    Ok(frontier)
}
pub(super) fn no_pending_reorg(db: &Connection) -> Result<()> {
    let count: u64 = db.query_row("SELECT COUNT(*) FROM reorg WHERE done!=1", [], |r| r.get(0))?;
    ensure(count == 0, "HISTORY_V6_PARTIAL_REORG_REQUIRES_CONTINUATION")
}
pub(super) fn check_reorg_authority(
    db: &Connection,
    journal: &journal::Journal,
    operation: &policy::Operation,
    progress: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    let Some(permit) = journal.reorg_continuation() else {
        return no_pending_reorg(db);
    };
    permit.check_operation(operation)?;
    ensure(
        reorg_continuation_v1::snapshot(db, progress)? == permit.snapshot,
        "HISTORY_REORG_V1_SQL_SNAPSHOT",
    )
}
pub(super) fn read_marker(db: &Connection, operation: &str) -> Result<Option<EffectMarker>> {
    policy::id(operation, 32)?;
    let row: Option<(Vec<u8>, Vec<u8>, u64)> = db
        .query_row(
            "SELECT substr(intent,1,33),substr(marker,1,16385),length(marker) FROM history_effect_v6 WHERE operation=?",
            [operation],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    row.map(|(intent, raw, length)| {
        ensure(
            raw.len() <= 16384 && raw.len() as u64 == length,
            "HISTORY_V6_SQL_MARKER_LIMIT",
        )?;
        let marker: EffectMarker = serde_json::from_slice(&raw)?;
        ensure(
            marker.operation_id == operation
                && hex::encode(bytes32(intent)?) == marker.intent_sha256
                && policy::encoded(&marker)? == raw,
            "HISTORY_V6_SQL_MARKER_CANONICAL",
        )?;
        Ok(marker)
    })
    .transpose()
}
pub(super) fn require_validation_marker(
    db: &Connection,
    journal: &journal::Journal,
    op: &policy::Operation,
) -> Result<()> {
    let validation = op
        .validation_operation_id
        .as_deref()
        .ok_or("HISTORY_V6_PAIR")?;
    let marker = read_marker(db, validation)?.ok_or("HISTORY_V6_VALIDATION_MARKER_REQUIRED")?;
    ensure(
        journal.markers().get(validation) == Some(&marker),
        "HISTORY_V6_VALIDATION_JOURNAL_REQUIRED",
    )?;
    ensure(
        marker.purpose == Purpose::Validation
            && marker.identity_sha256 == op.identity.digest()?
            && marker.owner == op.identity.owner
            && marker.store == op.identity.store
            && marker.epoch == op.epoch
            && marker.before == op.owner_frontier
            && marker.after == op.owner_frontier
            && Some(&marker.packet_sha256) == op.packet_sha256.as_ref()
            && marker.target == op.target
            && marker.target_root == op.target_root
            && Some(&marker.activation_operation_id) == op.activation_operation_id.as_ref(),
        "HISTORY_V6_VALIDATION_MARKER_BINDING",
    )
}

fn require_reusable_validation(
    db: &Connection,
    journal: &journal::Journal,
    op: &policy::Operation,
) -> Result<()> {
    // A syntax-valid stored packet does not establish that the W1 relation or
    // original State execution ran. A previous validation fact must survive in
    // BOTH independently anchored journal and this SQLite store. Its historical
    // epoch is kept intact; this new operation separately supplies fresh signed
    // current authority, frontier, task binding and delegated nonce fences.
    let identity = op.identity.digest()?;
    let marker = journal
        .markers()
        .values()
        .find(|marker| {
            marker.purpose == Purpose::Validation
                && marker.identity_sha256 == identity
                && marker.owner == op.identity.owner
                && marker.store == op.identity.store
                && Some(&marker.packet_sha256) == op.packet_sha256.as_ref()
                && marker.target == op.target
                && marker.target_root == op.target_root
        })
        .ok_or("HISTORY_V6_REUSE_VALIDATION_FACT_REQUIRED")?;
    ensure(
        read_marker(db, &marker.operation_id)?.as_ref() == Some(marker),
        "HISTORY_V6_REUSE_VALIDATION_SQL_REQUIRED",
    )
}
pub(super) fn verify_known_markers(
    db: &Connection,
    journal: &journal::Journal,
    pending: Option<&EffectMarker>,
) -> Result<()> {
    let mut expected = journal.markers().clone();
    if let Some(marker) = pending {
        if let Some(previous) = expected.insert(marker.operation_id.clone(), marker.clone()) {
            ensure(previous == *marker, "HISTORY_V6_SQL_MARKER_BINDING")?;
        }
    }
    let actual: Vec<String> = db
        .prepare("SELECT operation FROM history_effect_v6 ORDER BY operation LIMIT 257")?
        .query_map([], |r| r.get(0))?
        .collect::<std::result::Result<_, _>>()?;
    ensure(
        actual.len() <= 256 && actual == expected.keys().cloned().collect::<Vec<_>>(),
        "HISTORY_V6_SQL_MARKER_SET",
    )?;
    for (operation, marker) in &expected {
        ensure(
            read_marker(db, operation)?.as_ref() == Some(marker),
            "HISTORY_V6_SQL_MARKER_ROLLBACK",
        )?;
        let target = hex::decode(&marker.target).map_err(|_| "HISTORY_V6_ID")?;
        let (raw, root, length): (Vec<u8>, Vec<u8>, u64) = db.query_row(
            "SELECT substr(packet,1,1048577),substr(state_root,1,33),length(packet) FROM blocks WHERE id=?",
            [target],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        ensure(
            raw.len() <= 1024 * 1024
                && raw.len() as u64 == length
                && policy::digest(&raw) == marker.packet_sha256
                && hex::encode(bytes32(root)?) == marker.target_root,
            "HISTORY_V6_SQL_EFFECT_READBACK",
        )?;
    }
    // This fresh namespace admits no unaccounted block cache. Otherwise an
    // injected/rolled-back block row could take the native Existing fast path
    // without ever carrying the full W1+State validation fact.
    let validated: std::collections::BTreeSet<String> = expected
        .values()
        .filter(|marker| marker.purpose == Purpose::Validation)
        .map(|marker| marker.target.clone())
        .collect();
    let genesis = hex::decode(&journal.identity().genesis).map_err(|_| "HISTORY_V6_ID")?;
    let blocks: Vec<Vec<u8>> = db
        .prepare("SELECT substr(id,1,33) FROM blocks WHERE id!=? ORDER BY id LIMIT 257")?
        .query_map([genesis], |r| r.get(0))?
        .collect::<std::result::Result<_, _>>()?;
    ensure(blocks.len() <= 256, "HISTORY_V6_SQL_BLOCK_LIMIT")?;
    let actual_blocks: std::collections::BTreeSet<String> = blocks
        .into_iter()
        .map(|id| bytes32(id).map(hex::encode))
        .collect::<Result<_>>()?;
    ensure(
        actual_blocks == validated,
        "HISTORY_V6_SQL_BLOCK_VALIDATION_COVERAGE",
    )?;
    Ok(())
}
fn insert(db: &Connection, active: &Active, after: Frontier) -> Result<()> {
    active.check()?;
    let op = &active.pending.operation;
    let marker = EffectMarker {
        schema: "restricted-history-effect-sql-marker-v6".into(),
        identity_sha256: op.identity.digest()?,
        owner: op.identity.owner.clone(),
        store: op.identity.store.clone(),
        epoch: op.epoch.clone(),
        operation_id: op.operation_id.clone(),
        purpose: op.purpose,
        intent_sha256: active.pending.intent_sha256.clone(),
        packet_sha256: op.packet_sha256.clone().ok_or("HISTORY_V6_PACKET")?,
        target: op.target.clone(),
        target_root: op.target_root.clone(),
        validation_operation_id: op
            .validation_operation_id
            .clone()
            .ok_or("HISTORY_V6_PAIR")?,
        activation_operation_id: op
            .activation_operation_id
            .clone()
            .ok_or("HISTORY_V6_PAIR")?,
        before: op.owner_frontier.clone(),
        after,
    };
    journal::check_marker(&active.pending, &marker)?;
    ensure(
        db.execute(
            "INSERT INTO history_effect_v6(operation,intent,marker) VALUES(?,?,?)",
            params![
                op.operation_id,
                hex::decode(&marker.intent_sha256).map_err(|_| "HISTORY_V6_ID")?,
                policy::encoded(&marker)?
            ],
        )? == 1,
        "HISTORY_V6_SQL_MARKER_WRITE",
    )?;
    ensure(
        read_marker(db, &op.operation_id)?.as_ref() == Some(&marker),
        "HISTORY_V6_SQL_MARKER_READBACK",
    )
}
impl Node {
    pub(super) fn history_effect_packet_binding(
        &self,
        op: &policy::Operation,
        packet: &Packet,
        progress: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        progress()?;
        let owner = self
            .history_effect_owner
            .as_ref()
            .ok_or("HISTORY_V6_OWNER_REQUIRED")?;
        owner.checkpoint()?;
        ensure(
            frontier(&self.db)? == op.owner_frontier,
            "HISTORY_V6_OWNER_FRONTIER",
        )?;
        let parent = op.execution_parent.as_ref().ok_or("HISTORY_V6_PARENT")?;
        let parent_record = self.record(packet.header.parent)?;
        let binding = op.binding.as_ref().ok_or("HISTORY_V6_TASK")?;
        ensure(
            hex::encode(packet.header.parent) == parent.block
                && hex::encode(parent_record.root) == parent.root
                && parent_record.height == parent.height
                && packet.header.height == parent.height.checked_add(1).ok_or("HEIGHT")?
                && hex::encode(packet.id()?) == op.target
                && hex::encode(packet.header.state) == op.target_root
                && Some(policy::digest(&packet.encode()?)) == op.packet_sha256
                && hex::encode(packet.header.work_task) == binding.task.native_task,
            "HISTORY_V6_PACKET_BINDING",
        )?;
        owner.journal()?.work_nonce(packet.header.nonce)?;
        pon_work::precheck_proof_statement(
            packet.header.challenge(),
            packet.header.work_task,
            packet.header.target,
            &packet.proof,
        )
        .map_err(|e| Error::from(format!("WORK:{e:?}")))?;
        let manifest = self
            .eligible_work_task_with_progress(
                packet.header.parent,
                packet.header.work_task,
                packet.header.height,
                progress,
            )?
            .ok_or("HISTORY_V6_COMPLETE_REGISTRATION_REQUIRED")?;
        let lease = self
            .lifecycle_task_lease_with_progress(
                packet.header.parent,
                packet.header.work_task,
                packet.header.height,
                progress,
            )?
            .encode()
            .map_err(|_| "HISTORY_V6_LEASE")?;
        super::operator_continuous_owner::check_actual_task_fields(
            &binding.task,
            manifest.purpose,
            manifest.model,
            manifest.input,
            &lease,
            &packet.proof,
        )?;
        progress()
    }
    pub(in crate::store) fn history_effect_admission_marker(
        &self,
        tx: &rusqlite::Transaction<'_>,
        packet: &Packet,
    ) -> Result<()> {
        let Some(owner) = &self.history_effect_owner else {
            return Ok(());
        };
        let active = owner
            .slot()?
            .ok_or("HISTORY_V6_EXPLICIT_PAID_SCOPE_REQUIRED")?;
        let op = &active.pending.operation;
        ensure(
            op.purpose == Purpose::Validation
                && op.target == hex::encode(packet.id()?)
                && op.target_root == hex::encode(packet.header.state)
                && Some(policy::digest(&packet.encode()?)) == op.packet_sha256,
            "HISTORY_V6_ADMISSION_PURPOSE",
        )?;
        let actual = frontier(tx)?;
        ensure(actual == op.owner_frontier, "HISTORY_V6_OWNER_FRONTIER")?;
        insert(tx, &active, actual)
    }
    pub(super) fn history_effect_reuse_marker(&self, packet: &Packet) -> Result<()> {
        let owner = self
            .history_effect_owner
            .as_ref()
            .ok_or("HISTORY_V6_OWNER_REQUIRED")?;
        let active = owner
            .slot()?
            .ok_or("HISTORY_V6_EXPLICIT_PAID_SCOPE_REQUIRED")?;
        let tx = rusqlite::Transaction::new_unchecked(
            &self.db,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        require_reusable_validation(&tx, &*owner.journal()?, &active.pending.operation)?;
        self.history_effect_admission_marker(&tx, packet)?;
        tx.commit()?;
        Ok(())
    }
    pub(in crate::store) fn history_effect_activation_gate(&self, target: Hash) -> Result<()> {
        let Some(owner) = &self.history_effect_owner else {
            return Ok(());
        };
        let active = owner
            .slot()?
            .ok_or("HISTORY_V6_EXPLICIT_PAID_SCOPE_REQUIRED")?;
        active.check()?;
        let op = &active.pending.operation;
        ensure(
            op.purpose == Purpose::Activation
                && op.target == hex::encode(target)
                && frontier(&self.db)? == op.owner_frontier,
            "HISTORY_V6_ACTIVATION_PURPOSE",
        )?;
        require_validation_marker(&self.db, &*owner.journal()?, op)?;
        // A fresh pair is still mandatory. The V1 authority can select only
        // its exact stored target/cursor; ordinary activation remains refused.
        check_reorg_authority(&self.db, &*owner.journal()?, op, &mut || active.check())
    }
    pub(in crate::store) fn history_effect_activation_marker(
        &self,
        tx: &rusqlite::Transaction<'_>,
    ) -> Result<()> {
        let Some(owner) = &self.history_effect_owner else {
            return Ok(());
        };
        let active = owner
            .slot()?
            .ok_or("HISTORY_V6_EXPLICIT_PAID_SCOPE_REQUIRED")?;
        if active.pending.operation.purpose != Purpose::Activation {
            return Ok(());
        }
        let after = frontier(tx)?;
        if after == active.pending.operation.owner_frontier {
            return Ok(());
        }
        // Intermediate reorg cursor writes retain the old frontier and do not
        // fabricate finality. Only the real final publish can write this row.
        insert(tx, &active, after)
    }
}
