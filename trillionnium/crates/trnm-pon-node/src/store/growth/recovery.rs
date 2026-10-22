use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrowthProgress {
    BeforeWork,
    Execution(pon_executor::ExecutionProgress),
    BeforePersistence,
    AccountNode,
    /// Existing original-parent multiproof verification boundaries.
    ParentProof(multiproof::MultiproofProgress),
    /// Proof-derived root computation inside the unchanged M06 callback.
    CommitmentProof(multiproof::MultiproofProgress),
    /// Independent final successor recomputation before persistence.
    FinalSuccessorProof(multiproof::MultiproofProgress),
    /// Before each pair of ancestor reads, in the existing fork-walk order.
    ReorgAncestor {
        index: usize,
    },
    /// Before each ordered undo/apply journal write pair.
    ReorgWrite {
        index: usize,
    },
    /// Before each steps/events row read, including EOF, then the reorg singleton.
    ReorgReadback {
        index: usize,
    },
    BeforeCommit,
}

impl Node {
    pub fn make_growth_consensus_maintenance(
        &self,
        parent_id: Hash,
        transactions: Vec<Vec<u8>>,
        miner: Hash,
        timestamp: u64,
        max_attempts: u64,
    ) -> Result<GrowthPacket> {
        self.growth_guard()?;
        ensure(
            transactions.len() <= 256 && max_attempts > 0,
            "PACKET_LIMIT",
        )?;
        let read = self.db.unchecked_transaction()?;
        let parent = self.growth_parent(parent_id)?;
        let owners = requested(&parent, &transactions, miner)?;
        let (accounts, _) =
            multiproof::from_native_database(&self.db, &parent.checkpoint, &owners, &|_| {
                Ok::<_, archive::ArchiveError>(())
            })
            .map_err(archive_error)?;
        let height = parent.height.checked_add(1).ok_or("HEIGHT")?;
        let mut packet = GrowthPacket {
            header: GrowthHeader {
                ledger: Header {
                    network: self.settings.network(),
                    parameters: self.settings.parameters(),
                    parent: parent_id,
                    height,
                    timestamp,
                    target: self.growth_target(parent_id)?,
                    miner,
                    transactions: sequence_root("transactions", &transactions),
                    state: [0; 32],
                    receipts: [0; 32],
                    work_task: continuity_v1::maintenance_task()?,
                    nonce: 0,
                },
                witness: GrowthPacket::witness_digest(&accounts)?,
            },
            transactions,
            accounts,
            proof: vec![0; pon_work::PROOF_BYTES],
        };
        // Includes all actual bytes before spending on work search.
        packet.encode()?;
        let executed = execute(&self.settings, &parent, &packet, &|_| Ok(()))?;
        packet.header.ledger.state = executed.state.commitment.id;
        packet.header.ledger.receipts = sequence_root("receipts", &executed.receipts);
        self.growth_guard()?;
        read.rollback()?;
        let (a, b) = continuity_v1::maintenance_matrices();
        let task =
            pon_work::PreparedTask::new(&a, &b).map_err(|e| Error::from(format!("WORK:{e:?}")))?;
        for nonce in 0..max_attempts {
            packet.header.ledger.nonce = nonce;
            packet.proof = task
                .prove(packet.header.challenge())
                .map_err(|e| Error::from(format!("WORK:{e:?}")))?;
            match pon_work::verify(
                packet.header.challenge(),
                packet.header.ledger.work_task,
                packet.header.ledger.target,
                &packet.proof,
            ) {
                Ok(_) => {
                    self.growth_guard()?;
                    return Ok(packet);
                }
                Err(pon_work::WorkError::Target) => continue,
                Err(error) => return Err(format!("WORK:{error:?}").into()),
            }
        }
        Err("SEARCH_EXHAUSTED".into())
    }

    pub(super) fn check_growth_header(
        &self,
        packet: &GrowthPacket,
        observed_now: u64,
    ) -> Result<()> {
        let h = &packet.header.ledger;
        ensure(
            h.network == self.settings.network() && h.parameters == self.settings.parameters(),
            "NETWORK",
        )?;
        ensure(
            self.record(h.parent)?.height.checked_add(1) == Some(h.height)
                && h.height <= i64::MAX as u64,
            "HEIGHT",
        )?;
        ensure(h.target == self.growth_target(h.parent)?, "TARGET")?;
        ensure(
            h.transactions == sequence_root("transactions", &packet.transactions),
            "ROOT",
        )?;
        ensure(
            h.work_task == continuity_v1::maintenance_task()?,
            "CONTINUITY_MAINTENANCE",
        )?;
        let times: Vec<_> = self
            .growth_recent(h.parent)?
            .iter()
            .take(11)
            .map(|p| p.0)
            .collect();
        consensus::check_time(
            h.timestamp,
            &times,
            observed_now,
            self.settings.limit("future_skew_seconds")?,
        )
    }

    pub fn admit_growth(&mut self, packet: &GrowthPacket, observed_now: u64) -> Result<Hash> {
        self.admit_growth_with_progress(packet, observed_now, &|_| Ok(()))
    }
    pub fn admit_growth_with_progress(
        &mut self,
        packet: &GrowthPacket,
        observed_now: u64,
        progress: &(impl Fn(GrowthProgress) -> Result<()> + Sync),
    ) -> Result<Hash> {
        self.growth_guard()?;
        let bytes = packet.encode()?;
        self.check_growth_header(packet, observed_now)?;
        let id = packet.id()?;
        let previous: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT packet FROM blocks WHERE id=?",
                [id.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(previous) = previous {
            ensure(previous == bytes, "DUPLICATE_CONTENT")?;
            return Ok(id);
        }
        progress(GrowthProgress::BeforeWork)?;
        pon_work::verify(
            packet.header.challenge(),
            packet.header.ledger.work_task,
            packet.header.ledger.target,
            &packet.proof,
        )
        .map_err(|e| Error::from(format!("WORK:{e:?}")))?;
        let h = &packet.header.ledger;
        // The single owner rebinds the parent in its actual write transaction.
        let tx = rusqlite::Transaction::new_unchecked(
            &self.db,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        self.growth_guard()?;
        let active_before = self.active()?;
        let parent = self.growth_parent(h.parent)?;
        let mut executed = execute(&self.settings, &parent, packet, progress)?;
        ensure(
            h.state == executed.state.commitment.id
                && h.receipts == sequence_root("receipts", &executed.receipts),
            "ROOT",
        )?;
        let chainwork = self
            .record(h.parent)?
            .work
            .checked_add(consensus::required_work(h.target)?)?;
        progress(GrowthProgress::BeforePersistence)?;
        ensure(
            tx.execute(
                "INSERT INTO blocks VALUES(?,?,?,?,?,?)",
                params![
                    id.as_slice(),
                    h.parent.as_slice(),
                    h.height,
                    chainwork.bytes().as_slice(),
                    &bytes,
                    h.state.as_slice(),
                ],
            )? == 1,
            "STORAGE_WRITE",
        )?;
        for (key, before, after) in &executed.deltas {
            ensure(
                tx.execute(
                    "INSERT INTO deltas VALUES(?,?,?,?)",
                    params![id.as_slice(), key, before, after],
                )? == 1,
                "STORAGE_WRITE",
            )?;
        }
        let accounts = native_store::apply_growth(
            &tx,
            parent.source.accounts(),
            &executed.deltas,
            &mut || progress(GrowthProgress::AccountNode),
        )?;
        ensure(
            accounts.digest == executed.state.commitment.permanent_account_root
                && accounts.count == executed.state.commitment.permanent_account_count
                && accounts.balance == executed.state.commitment.permanent_account_balance,
            "GROWTH_COW_MISMATCH",
        )?;
        executed.state.accounts = accounts;
        save(&tx, id, &executed.state)?;
        // Exact write-set and parent/root readback before the only durable commit.
        ensure(
            self.delta_rows_with_progress(id, &mut || Ok(()))? == executed.deltas
                && self.growth_load_packet(id)?.encode()? == bytes
                && self.growth_parent(h.parent)?.source.stored == parent.source.stored
                && self.growth_parent(id)?.source.stored == executed.state
                && self.active()? == active_before,
            "STORAGE_WRITE",
        )?;
        progress(GrowthProgress::BeforeCommit)?;
        self.growth_guard()?;
        tx.commit()?;
        Ok(id)
    }

    pub(in crate::store) fn growth_recover(&mut self) -> Result<Hash> {
        self.growth_guard()?;
        let best: Vec<u8> = self.db.query_row(
            "SELECT id FROM blocks ORDER BY chainwork DESC,height,id LIMIT 1",
            [],
            |r| r.get(0),
        )?;
        self.growth_activate(bytes32(best)?)
    }
    pub(in crate::store) fn growth_activate(&mut self, target: Hash) -> Result<Hash> {
        self.growth_activate_with_progress(target, &|_| Ok(()))
    }
    pub fn growth_activate_with_progress(
        &mut self,
        target: Hash,
        progress: &impl Fn(GrowthProgress) -> Result<()>,
    ) -> Result<Hash> {
        self.growth_guard()?;
        let tx = rusqlite::Transaction::new_unchecked(
            &self.db,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let (old, generation) = self.active()?;
        if self.record(target)?.work <= self.record(old)?.work {
            tx.rollback()?;
            return Ok(old);
        }
        self.growth_parent(old)?;
        self.growth_parent(target)?;
        let next = generation
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or("GENERATION")?;
        let mut left = old;
        let mut right = target;
        let mut undo = Vec::new();
        let mut apply = Vec::new();
        let mut ancestor_index = 0;
        while left != right {
            progress(GrowthProgress::ReorgAncestor {
                index: ancestor_index,
            })?;
            ancestor_index += 1;
            let l = self.record(left)?;
            let r = self.record(right)?;
            if l.height >= r.height {
                undo.push(left);
                left = l.parent.ok_or("GROWTH_ANCESTRY")?;
            } else {
                apply.push(right);
                right = r.parent.ok_or("GROWTH_ANCESTRY")?;
            }
        }
        let changes = undo
            .iter()
            .map(|id| (0u64, *id))
            .chain(apply.iter().rev().map(|id| (1u64, *id)));
        let change_count = undo.len() + apply.len();
        tx.execute("DELETE FROM steps", [])?;
        for (index, (kind, id)) in changes.clone().enumerate() {
            progress(GrowthProgress::ReorgWrite { index })?;
            ensure(
                tx.execute(
                    "INSERT INTO steps VALUES(?,?,?)",
                    params![index as u64, kind, id.as_slice()],
                )? == 1,
                "STORAGE_WRITE",
            )?;
            ensure(
                tx.execute(
                    "INSERT INTO events VALUES(?,?,?,?)",
                    params![next, index as u64, kind, id.as_slice()],
                )? == 1,
                "STORAGE_WRITE",
            )?;
        }
        ensure(tx.execute("INSERT INTO reorg VALUES(1,?,?,?,?,1) ON CONFLICT(singleton) DO UPDATE SET old_tip=excluded.old_tip,new_tip=excluded.new_tip,generation=excluded.generation,cursor=excluded.cursor,done=excluded.done",
            params![old.as_slice(),target.as_slice(),next,change_count as u64])? == 1, "STORAGE_WRITE")?;
        ensure(tx.execute("UPDATE active SET tip=?,generation=?,state_slot=? WHERE singleton=1 AND tip=? AND generation=?",
            params![target.as_slice(),next,next,old.as_slice(),generation])? == 1, "STALE_VIEW")?;
        ensure(
            self.active()? == (target, next)
                && self.slot()? == next
                && load(&tx, target)?.commitment.id == self.record(target)?.root,
            "STORAGE_WRITE",
        )?;
        self.growth_check_latest_journal_with_progress(old, target, next, changes, progress)?;
        progress(GrowthProgress::BeforeCommit)?;
        self.growth_guard()?;
        tx.commit()?;
        Ok(target)
    }

    pub(super) fn growth_check_latest_journal(
        &self,
        old: Hash,
        target: Hash,
        generation: u64,
        changes: &[(u64, Hash)],
    ) -> Result<()> {
        self.growth_check_latest_journal_with_progress(
            old,
            target,
            generation,
            changes.iter().copied(),
            &|_| Ok(()),
        )
    }

    fn growth_check_latest_journal_with_progress(
        &self,
        old: Hash,
        target: Hash,
        generation: u64,
        changes: impl Iterator<Item = (u64, Hash)> + Clone,
        progress: &impl Fn(GrowthProgress) -> Result<()>,
    ) -> Result<()> {
        let change_count = changes.clone().count();
        let mut matches = true;
        let mut index = 0;
        for (sql, selected_generation) in [
            (
                "SELECT ordinal,kind,block FROM steps ORDER BY ordinal",
                None,
            ),
            (
                "SELECT ordinal,kind,block FROM events WHERE generation=? ORDER BY ordinal",
                Some(generation),
            ),
        ] {
            let mut statement = self.db.prepare(sql)?;
            let mut rows = match selected_generation {
                Some(generation) => statement.query([generation])?,
                None => statement.query([])?,
            };
            let mut expected = changes.clone().enumerate();
            loop {
                progress(GrowthProgress::ReorgReadback { index })?;
                index += 1;
                let Some(row) = rows.next()? else {
                    matches &= expected.next().is_none();
                    break;
                };
                let actual: (u64, u64, Vec<u8>) = (row.get(0)?, row.get(1)?, row.get(2)?);
                matches &= expected.next().is_some_and(|(ordinal, (kind, id))| {
                    actual.0 == ordinal as u64 && actual.1 == kind && actual.2 == id
                });
            }
        }
        progress(GrowthProgress::ReorgReadback { index })?;
        let reorg: (Vec<u8>, Vec<u8>, u64, u64, u64) = self.db.query_row(
            "SELECT old_tip,new_tip,generation,cursor,done FROM reorg WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )?;
        ensure(
            matches
                && reorg
                    == (
                        old.to_vec(),
                        target.to_vec(),
                        generation,
                        change_count as u64,
                        1,
                    ),
            "GROWTH_REORG_JOURNAL",
        )
    }

    fn growth_check_journal(&self) -> Result<()> {
        let rows: Vec<(u64, u64, u64, Vec<u8>)> = self
            .db
            .prepare(
                "SELECT generation,ordinal,kind,block FROM events ORDER BY generation,ordinal",
            )?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<std::result::Result<_, _>>()?;
        let mut tip = self.settings.genesis();
        let mut generation = 0u64;
        let mut old = tip;
        let mut changes = Vec::new();
        for (g, ordinal, kind, raw) in rows {
            if g != generation {
                ensure(g == generation + 1, "GROWTH_REORG_JOURNAL")?;
                generation = g;
                old = tip;
                changes.clear();
            }
            ensure(ordinal == changes.len() as u64, "GROWTH_REORG_JOURNAL")?;
            let id = bytes32(raw)?;
            match kind {
                0 => {
                    ensure(tip == id, "GROWTH_REORG_JOURNAL")?;
                    tip = self.record(id)?.parent.ok_or("GROWTH_REORG_JOURNAL")?;
                }
                1 => {
                    ensure(self.record(id)?.parent == Some(tip), "GROWTH_REORG_JOURNAL")?;
                    tip = id;
                }
                _ => return Err("GROWTH_REORG_JOURNAL".into()),
            }
            changes.push((kind, id));
        }
        ensure(
            self.active()? == (tip, generation) && self.slot()? == generation,
            "GROWTH_REORG_JOURNAL",
        )?;
        if generation > 0 {
            self.growth_check_latest_journal(old, tip, generation, &changes)
        } else {
            let rows: u64 = self.db.query_row(
                "SELECT (SELECT count(*) FROM reorg)+(SELECT count(*) FROM steps)",
                [],
                |r| r.get(0),
            )?;
            ensure(rows == 0, "GROWTH_REORG_JOURNAL")
        }
    }

    /// Cold integrity is deliberately separate from request latency. Every retained
    /// branch is reexecuted against its parent witness, and every retained root is
    /// checked against real COW nodes before the operation epoch is published.
    pub(in crate::store) fn growth_cold_open(&mut self) -> Result<()> {
        profile::require(&self.settings)?;
        let read = self.db.unchecked_transaction()?;
        let version: u64 = self.db.query_row("PRAGMA data_version", [], |r| r.get(0))?;
        let expected =
            growth_commitment_from_complete_state_v2(&self.settings, &self.settings.initial)
                .map_err(execution_error)?;
        let genesis = self.growth_parent(self.settings.genesis())?;
        let genesis_record = self.record(self.settings.genesis())?;
        let genesis_packet: Option<Vec<u8>> = self.db.query_row(
            "SELECT packet FROM blocks WHERE id=?",
            [self.settings.genesis().as_slice()],
            |r| r.get(0),
        )?;
        ensure(
            genesis_record.height == 0
                && genesis_record.parent.is_none()
                && genesis_packet.is_none()
                && genesis.source.stored.commitment == *expected.observation()
                && genesis.source.stored.working == working(&self.settings.initial)
                && genesis.source.stored.parent_commitment.is_none()
                && genesis.source.stored.deltas == delta_hash(&[])?
                && self.record(self.settings.genesis())?.work == consensus::Work::default(),
            "GROWTH_GENESIS",
        )?;
        let rows: Vec<Hash> = self
            .db
            .prepare("SELECT id FROM blocks ORDER BY height,id")?
            .query_map([], |r| r.get::<_, Vec<u8>>(0))?
            .map(|r| bytes32(r?))
            .collect::<Result<_>>()?;
        let mut checked = BTreeSet::from([self.settings.genesis()]);
        let mut roots = vec![genesis.source.stored.accounts];
        for id in rows {
            if id == self.settings.genesis() {
                continue;
            }
            let packet = self.growth_load_packet(id)?;
            let h = &packet.header.ledger;
            ensure(checked.contains(&h.parent), "GROWTH_ANCESTRY")?;
            self.check_growth_header(&packet, u64::MAX)?;
            pon_work::verify(
                packet.header.challenge(),
                h.work_task,
                h.target,
                &packet.proof,
            )
            .map_err(|e| Error::from(format!("WORK:{e:?}")))?;
            let parent = self.growth_parent(h.parent)?;
            let executed = execute(&self.settings, &parent, &packet, &|_| Ok(()))?;
            let stored = self.growth_parent(id)?;
            let record = self.record(id)?;
            ensure(
                record.parent == Some(h.parent)
                    && record.height == h.height
                    && record.root == h.state
                    && record.work
                        == self
                            .record(h.parent)?
                            .work
                            .checked_add(consensus::required_work(h.target)?)?
                    && executed.state.commitment == stored.source.stored.commitment
                    && executed.state.working == stored.source.stored.working
                    && executed.state.parent_commitment == stored.source.stored.parent_commitment
                    && executed.state.deltas == stored.source.stored.deltas
                    && self.delta_rows_with_progress(id, &mut || Ok(()))? == executed.deltas
                    && h.receipts == sequence_root("receipts", &executed.receipts),
                "GROWTH_COLD_REPLAY",
            )?;
            roots.push(stored.source.stored.accounts);
            checked.insert(id);
        }
        native_store::audit_growth_roots(&self.db, &roots)?;
        let states: u64 = self
            .db
            .query_row("SELECT count(*) FROM growth_states", [], |r| r.get(0))?;
        let orphans: u64 = self.db.query_row("SELECT count(*) FROM deltas d LEFT JOIN blocks b ON b.id=d.block WHERE b.id IS NULL OR b.height=0", [], |r| r.get(0))?;
        let legacy_rows: u64 = self.db.query_row(
            "SELECT (SELECT count(*) FROM kv)+(SELECT count(*) FROM snapshots)",
            [],
            |r| r.get(0),
        )?;
        ensure(
            states == checked.len() as u64 && orphans == 0 && legacy_rows == 0,
            "GROWTH_STORAGE_PARTITION",
        )?;
        ensure(checked.contains(&self.active()?.0), "GROWTH_ACTIVE_ROOT")?;
        self.growth_check_journal()?;
        let expected_schema = schema(&self.db)?;
        read.rollback()?;
        let after: u64 = self.db.query_row("PRAGMA data_version", [], |r| r.get(0))?;
        ensure(version == after, "GROWTH_STORAGE_EPOCH_CHANGED")?;
        self.growth_epoch = Some(Epoch {
            version,
            schema: expected_schema,
        });
        self.growth_recover()?;
        Ok(())
    }
}
