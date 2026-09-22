//! Explicit schema7 commit owner; retained first-new finality is independent
//! of the immutable preparation codec. No legacy entry point accepts this mode.
use super::*;
pub(super) const SQL: &str = "CREATE TABLE native_incremental_epoch_commit_v1 (
 id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL CHECK(revision=1),
 block BLOB NOT NULL UNIQUE CHECK(length(block)=32), p_digest BLOB NOT NULL CHECK(length(p_digest)=32),
 sequence BLOB NOT NULL UNIQUE CHECK(length(sequence)=8), head BLOB NOT NULL CHECK(length(head)=104),
 proof BLOB NOT NULL CHECK(length(proof)<=67108864), checksum BLOB NOT NULL CHECK(length(checksum)=32)) STRICT;
CREATE TABLE native_incremental_epoch_descendant_commit_v1 (
 block BLOB PRIMARY KEY CHECK(length(block)=32), p_digest BLOB NOT NULL CHECK(length(p_digest)=32),
 sequence BLOB NOT NULL UNIQUE CHECK(length(sequence)=8), head BLOB NOT NULL CHECK(length(head)=104),
 proof BLOB NOT NULL CHECK(length(proof)<=67108864), checksum BLOB NOT NULL CHECK(length(checksum)=32)) STRICT, WITHOUT ROWID;";
#[derive(Clone)]
pub(super) struct Commit {
    pub block: [u8; 32],
    pub p_digest: [u8; 32],
    pub sequence: u64,
    pub head: ApplicationHeadV0,
    pub proof: Vec<u8>,
    pub checksum: [u8; 32],
}
impl Commit {
    pub(super) fn digest(&self, config: &NativeApplicationConfigV0, edge: &EdgeRow) -> [u8; 32] {
        hash_domain(
            "trnm.native-application.incremental-epoch-commit-record.v1",
            &[
                &config.store_id,
                &edge.checksum,
                &self.block,
                &self.p_digest,
                &self.sequence.to_be_bytes(),
                &head_bytes(&self.head),
                &sha256_v0(&self.proof),
            ],
        )
    }
}
pub(super) fn installed(c: &Connection) -> Result<bool> {
    Ok(c.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='native_incremental_epoch_commit_v1')",[],|r|r.get(0))?)
}
pub(super) fn load(c: &Connection) -> Result<Option<Commit>> {
    if !installed(c)? {
        return Ok(None);
    }
    let value=c.query_row("SELECT revision,block,p_digest,sequence,head,proof,checksum FROM native_incremental_epoch_commit_v1 WHERE id=1",[],|r|Ok((r.get::<_,u8>(0)?,row_blob(r,1,32,32)?,row_blob(r,2,32,32)?,row_blob(r,3,8,8)?,row_blob(r,4,104,104)?,row_blob(r,5,1,MAX_EPOCH_EVIDENCE_BYTES_V1)?,row_blob(r,6,32,32)?))).optional()?;
    value
        .map(|r| {
            ensure!(r.0 == 1, "epoch commit revision");
            Ok(Commit {
                block: fixed(r.1)?,
                p_digest: fixed(r.2)?,
                sequence: number(r.3)?,
                head: decode_head(&r.4)?,
                proof: r.5,
                checksum: fixed(r.6)?,
            })
        })
        .transpose()
}
fn verify_proof(
    config: &NativeApplicationConfigV0,
    edge: &EdgeRow,
    p: &EpochP,
    proof: &[u8],
    budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
) -> Result<()> {
    ensure!(
        proof.len() <= MAX_EPOCH_EVIDENCE_BYTES_V1,
        "first-new proof capacity"
    );
    let evidence = EpochRecoveryEvidenceV1::decode(&edge.evidence)?;
    let audit = evidence.audit_strict(&config.validator_set, &config.parameters, budget)?;
    let terminal = audit
        .activation
        .old_checkpoint_finality()
        .grandchild()
        .header();
    let h = header(&p.header)?;
    let expected = trnm_consensus_crypto::FinalityExpectationV0 {
        block_id: h.id(),
        height: h.height(),
        state_root: h.state_root(),
        receipts_root: h.receipts_root(),
        evidence_root: h.evidence_root(),
        parent_id: terminal.id(),
        parent_height: terminal.height(),
        parent_timestamp_ms: terminal.timestamp_ms(),
    };
    let verified = trnm_consensus_crypto::decode_verify_epoch_first_finality_strict_v1(
        evidence.proof_preimages(),
        proof,
        &config.validator_set,
        &config.parameters,
        expected,
        budget,
    )
    .map_err(|e| anyhow::anyhow!("incremental epoch strict finality: {e}"))?;
    ensure!(
        verified.proof().finalized_block().header() == &h
            && verified.checkpoint_header().id().as_bytes() == p.parent.block_id().as_bytes(),
        "incremental epoch complete finality binding"
    );
    Ok(())
}
pub(super) fn audit(
    tx: &rusqlite::Transaction<'_>,
    config: &NativeApplicationConfigV0,
    edge: &EdgeRow,
    parent: &ApplicationHeadV0,
    evidence: &crate::epoch_recovery::AuditedEpochEvidenceV1,
    record: &Commit,
) -> Result<EpochP> {
    audit_with_budget(
        tx,
        config,
        edge,
        parent,
        evidence,
        record,
        &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
    )
}
#[allow(clippy::too_many_arguments)]
pub(super) fn audit_with_budget(
    tx: &rusqlite::Transaction<'_>,
    config: &NativeApplicationConfigV0,
    edge: &EdgeRow,
    parent: &ApplicationHeadV0,
    evidence: &crate::epoch_recovery::AuditedEpochEvidenceV1,
    record: &Commit,
    budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
) -> Result<EpochP> {
    let p = audit_record_shape(tx, config, edge, parent, &evidence.activation, record)?;
    verify_proof(config, edge, &p, &record.proof, budget)?;
    Ok(p)
}
// Private shape join allows schema11 to verify all retained proofs with its
// already audited strict runtime, without repeatedly decoding the prefix.
pub(super) fn audit_record_shape(
    tx: &rusqlite::Transaction<'_>,
    config: &NativeApplicationConfigV0,
    edge: &EdgeRow,
    parent: &ApplicationHeadV0,
    activation: &trnm_consensus_crypto::StrictSameVersionEpochActivationAuthorityV0,
    record: &Commit,
) -> Result<EpochP> {
    let p = load_epoch_p(tx, record.block)?.context("committed epoch P missing")?;
    p.validate_context(
        config,
        &EpochPContext {
            parent,
            checkpoint_sequence: edge.sequence,
            binding: edge.binding,
            terminal: activation.authorization_kernel().terminal_old_header(),
            set: activation.new_validator_set(),
            parameters: activation.new_consensus_parameters(),
        },
    )?;
    p.validate_storage(tx)?;
    let executed = p.executed()?;
    let keys: Vec<_> = executed
        .request()
        .preview()
        .transactions()
        .iter()
        .map(|raw| -> Result<_> {
            let e: trnm_finality_types::SignedCommandEnvelopeV1 = serde_json::from_slice(raw)?;
            Ok([
                replay::command_key(&e.command_id)?,
                replay::nonce_key(&e.signer_id, e.nonce)?,
            ])
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();
    ensure!(
        ReplayReader::new(tx, Some(p.replay_parent), &[])?
            .append(keys)?
            .encode()?
            == p.replay_delta,
        "epoch committed replay identities"
    );
    ensure!(
        record.checksum == record.digest(config, edge)
            && record.p_digest == p.digest
            && p.digest == p.digest(config)
            && record.sequence > p.sequence
            && record.head == p.target()?
            && p.edge == edge.binding,
        "epoch committed record binding"
    );
    let (phase, block): (u8, Vec<u8>) = tx.query_row(
        "SELECT phase,committed_block FROM ni_epoch_edge WHERE strict_binding=?1",
        [edge.binding.as_slice()],
        |r| Ok((r.get(0)?, row_blob(r, 1, 32, 32)?)),
    )?;
    ensure!(
        phase == 1 && fixed::<32>(block)? == p.block,
        "epoch consumed storage edge"
    );
    let reader = ni::open_incremental_reader_v1(
        tx,
        &namespace(config),
        ni::IncrementalParentV1::Prepared(p.storage_artifact),
    )?;
    ensure!(
        reader.version() == record.head.height().get()
            && reader.root().0 == *record.head.state_root().as_bytes(),
        "epoch committed state root"
    );
    Ok(p)
}
#[must_use]
pub struct CommittedNativeIncrementalEpochExecutionV1 {
    pub(super) owner: Arc<()>,
    pub(super) head: ApplicationHeadV0,
    pub(super) digest: [u8; 32],
    pub(super) sequence: u64,
}
impl CommittedNativeIncrementalEpochExecutionV1 {
    pub fn head(&self) -> &ApplicationHeadV0 {
        &self.head
    }
    pub const fn p_digest(&self) -> [u8; 32] {
        self.digest
    }
    pub const fn commit_sequence(&self) -> u64 {
        self.sequence
    }
    pub fn belongs_to_application_at_path(
        &self,
        app: &DurableNativeApplicationV0,
        path: &Path,
    ) -> bool {
        app.path() == path && self.belongs_to_application(app)
    }
    pub fn belongs_to_application(&self, app: &DurableNativeApplicationV0) -> bool {
        if !Arc::ptr_eq(&self.owner, &app.owner_affinity) {
            return false;
        }
        (|| -> Result<bool> {
            let _guard = app.lock_operation()?;
            let c = open_immutable_connection_v0(&app.path)?;
            verify_schema_v0(&c)?;
            let tx = c.unchecked_transaction()?;
            let m = load_metadata_v0(&tx, &app.config)?;
            let (base, edge) = audit_owner(&tx, &app.config, &m)?;
            let first = load(&tx)?.context("epoch commit missing")?;
            let r = if first.head == self.head {
                first
            } else {
                descendant::load_commit(&tx, *self.head.block_id().as_bytes())?
                    .context("descendant commit missing")?
            };
            Ok(m.head == self.head
                && base.commit_sequence == self.sequence
                && r.head == self.head
                && r.sequence == self.sequence
                && r.p_digest == self.digest
                && *app
                    .incremental_migration_pin
                    .lock()
                    .map_err(|_| anyhow::anyhow!("migration pin"))?
                    == Some(edge.checksum))
        })()
        .unwrap_or(false)
    }
}
impl DurableNativeApplicationV0 {
    /// Ensure the schema7 commit owner exists, while retaining the schema6
    /// preparation owner and its exact migration pin. This is deliberately a
    /// single-owner, resumable dispatcher: retrying after an uncertain close
    /// re-audits the live edge and the retained commit row instead of assuming
    /// that a previous response was lost before SQLite committed.
    ///
    /// The method only installs/validates the local commit owner. It does not
    /// execute a block, verify finality, move the application head, or return a
    /// receipt. Those actions remain behind the strict finality methods below.
    pub fn ensure_incremental_epoch_commit_owner_v1(
        &self,
        edge: &AuthenticatedEpochApplicationEdgeV1,
    ) -> Result<()> {
        drop(self.confirm_epoch_application_edge_v1(edge)?);
        let _guard = self.lock_operation()?;
        let mut c = open_writable_connection_v0(&self.path)?;
        verify_schema_v0(&c)?;
        ensure!(epoch_schema(&c)?, "schema7 commit owner requires schema6/7");
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let m = load_metadata_v0(&tx, &self.config)?;
        let (_, row) = audit_owner(&tx, &self.config, &m)?;
        ensure!(
            row.binding == edge.authorization_id()
                && *self
                    .incremental_migration_pin
                    .lock()
                    .map_err(|_| anyhow::anyhow!("migration pin"))?
                    == Some(row.checksum),
            "epoch revision owner"
        );
        if epoch_durable::schema_version(&tx)? == SCHEMA_VERSION {
            ensure!(!installed(&tx)?, "schema6 unexpected commit table");
            tx.execute_batch(SQL)?;
            ensure!(tx.execute("UPDATE native_application_metadata_v0 SET schema_version=?1 WHERE singleton=1 AND schema_version=?2",params![COMMIT_SCHEMA_VERSION.to_be_bytes().as_slice(),SCHEMA_VERSION.to_be_bytes().as_slice()])?==1,"schema7 migration CAS");
        } else {
            ensure!(
                epoch_durable::schema_version(&tx)? == COMMIT_SCHEMA_VERSION && installed(&tx)?,
                "schema7 commit owner missing"
            );
            // A retry is only resumable when any retained record still decodes
            // under the bounded schema. Empty is valid before first finality;
            // malformed bytes reject the owner operation rather than being
            // silently treated as an empty commit ledger.
            let _ = load(&tx)?;
        }
        tx.commit()?;
        drop(c);
        sync_store_commit_boundary_v0(&self.path)?;
        fresh_validate_v0(&self.path, &self.config)?;
        Ok(())
    }

    /// Compatibility name retained for candidate callers that used the
    /// original one-shot migration API. The owner is now explicitly resumable
    /// and validates the same live pin on every retry.
    pub fn upgrade_incremental_epoch_commit_v1(
        &self,
        edge: &AuthenticatedEpochApplicationEdgeV1,
    ) -> Result<()> {
        self.ensure_incremental_epoch_commit_owner_v1(edge)
    }
    pub fn commit_incremental_epoch_finality_bytes_v1(
        &self,
        prepared: &PreparedNativeIncrementalEpochExecutionV1,
        proof: &[u8],
        budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
    ) -> Result<CommittedNativeIncrementalEpochExecutionV1> {
        ensure!(
            Arc::ptr_eq(&prepared.owner, &self.owner_affinity),
            "incremental epoch finality foreign owner"
        );
        let edge = self.recover_incremental_epoch_edge_v1()?;
        let _guard = self.lock_operation()?;
        let mut c = open_writable_connection_v0(&self.path)?;
        verify_schema_v0(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure!(
            epoch_durable::schema_version(&tx)? == COMMIT_SCHEMA_VERSION && installed(&tx)?,
            "explicit schema7 commit revision required"
        );
        let m = load_metadata_v0(&tx, &self.config)?;
        let (mut base, row) = audit_owner(&tx, &self.config, &m)?;
        require_live_edge(self, &row, &edge)?;
        ensure!(
            *self
                .incremental_migration_pin
                .lock()
                .map_err(|_| anyhow::anyhow!("migration pin"))?
                == Some(row.checksum),
            "epoch commit live pin"
        );
        let p = load_epoch_p(&tx, prepared.p.block)?.context("epoch commit P missing")?;
        p.validate(&self.config, &edge)?;
        ensure!(
            p.digest == prepared.p.digest
                && p.sequence == prepared.p.sequence
                && p.artifact == prepared.p.artifact
                && p.header == prepared.p.header,
            "epoch commit P substitution"
        );
        verify_proof(&self.config, &row, &p, proof, budget)?;
        if let Some(r) = load(&tx)? {
            ensure!(
                r.block == p.block && r.p_digest == p.digest,
                "epoch commit conflicting retry"
            );
            drop(tx);
            drop(c);
            sync_store_commit_boundary_v0(&self.path)?;
            fresh_validate_v0(&self.path, &self.config)?;
            return Ok(CommittedNativeIncrementalEpochExecutionV1 {
                owner: Arc::clone(&self.owner_affinity),
                head: r.head,
                digest: r.p_digest,
                sequence: r.sequence,
            });
        }
        ensure!(
            m.head == p.parent && base.replay == p.replay_parent,
            "epoch commit exact predecessor"
        );
        let executed = p.executed()?;
        let keys: Vec<_> = executed
            .request()
            .preview()
            .transactions()
            .iter()
            .map(|raw| -> Result<_> {
                let e: trnm_finality_types::SignedCommandEnvelopeV1 = serde_json::from_slice(raw)?;
                Ok([
                    replay::command_key(&e.command_id)?,
                    replay::nonce_key(&e.signer_id, e.nonce)?,
                ])
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();
        let delta = ReplayReader::new(&tx, Some(base.replay), &[])?.append(keys)?;
        ensure!(
            delta.encode()? == p.replay_delta,
            "epoch exact replay identities"
        );
        let head = p.target()?;
        let before = ni::read_incremental_head_v1(&tx, &namespace(&self.config))?;
        let next = ni::epoch_candidate_v1::apply(
            &tx,
            &namespace(&self.config),
            &edge,
            &before,
            &p.storage()?,
            *head.commit_id().as_bytes(),
        )?;
        replay::apply(&tx, &delta)?;
        let sequence = m
            .durable_sequence
            .checked_add(1)
            .context("epoch commit sequence exhausted")?;
        let mut record = Commit {
            block: p.block,
            p_digest: p.digest,
            sequence,
            head: head.clone(),
            proof: proof.to_vec(),
            checksum: [0; 32],
        };
        record.checksum = record.digest(&self.config, &row);
        tx.execute(
            "INSERT INTO native_incremental_epoch_commit_v1 VALUES(1,1,?,?,?,?,?,?)",
            params![
                record.block.as_slice(),
                record.p_digest.as_slice(),
                sequence.to_be_bytes().as_slice(),
                head_bytes(&head),
                record.proof,
                record.checksum.as_slice()
            ],
        )?;
        ensure!(tx.execute("UPDATE native_application_metadata_v0 SET durable_sequence=?,head_height=?,head_block_id=?,head_state_root=?,head_commit_id=? WHERE singleton=1 AND durable_sequence=? AND head_block_id=? AND head_state_root=? AND head_commit_id=?",params![sequence.to_be_bytes().as_slice(),head.height().get().to_be_bytes().as_slice(),head.block_id().as_bytes().as_slice(),head.state_root().as_bytes().as_slice(),head.commit_id().as_bytes().as_slice(),m.durable_sequence.to_be_bytes().as_slice(),m.head.block_id().as_bytes().as_slice(),m.head.state_root().as_bytes().as_slice(),m.head.commit_id().as_bytes().as_slice()])?==1,"epoch native commit CAS");
        base.commit_sequence = sequence;
        base.storage_checksum = next.checksum;
        base.replay = delta.head;
        base.checksum = base.current_digest(&head);
        tx.execute("UPDATE native_incremental_owner_v1 SET head_commit_sequence=?,storage_checksum=?,replay_version=?,replay_root=?,owner_checksum=? WHERE id=1",params![sequence.to_be_bytes().as_slice(),base.storage_checksum.as_slice(),base.replay.version.to_be_bytes().as_slice(),base.replay.root.as_slice(),base.checksum.as_slice()])?;
        descendant::retire_forks(&tx, &self.config, p.block)?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("incremental_epoch_commit_before_commit");
        tx.commit()?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("incremental_epoch_commit_after_commit");
        drop(c);
        sync_store_commit_boundary_v0(&self.path)?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("incremental_epoch_commit_after_fsync");
        fresh_validate_v0(&self.path, &self.config)?;
        Ok(CommittedNativeIncrementalEpochExecutionV1 {
            owner: Arc::clone(&self.owner_affinity),
            head,
            digest: p.digest,
            sequence,
        })
    }
}

#[cfg(all(test, feature = "test-fixtures"))]
mod tests {
    use super::*;
    use crate::test_fixtures::{
        build_native_checkpoint_fixture_v1, native_checkpoint_fixture_config_v1,
    };
    use trnm_consensus_types::{
        BlockKind, EvidenceRoot, Height, PayloadDigest, ReceiptsRoot, StateRoot, View,
    };
    use trnm_native_application::{ChainIdV0, GenesisHashV0};
    fn signed_runtime(
        app: &DurableNativeApplicationV0,
        nonce: u64,
        command: trnm_protocol::CanonicalCommandV1,
    ) -> Vec<u8> {
        let tx = trnm_protocol::CanonicalTxV1 {
            schema: trnm_protocol::CANONICAL_TX_SCHEMA_V1.into(),
            sender: "did:operator:1".into(),
            nonce,
            max_gas: 100_000,
            fee_limit: 100_000,
            command,
        };
        let bytes = serde_json::to_vec(&tx).unwrap();
        serde_json::to_vec(
            &trnm_finality_types::SignedCommandEnvelopeV1::sign(
                &app.config.chain_id,
                format!("epoch-runtime-{nonce}"),
                "did:operator:1",
                "operator",
                nonce,
                10_000,
                20_000,
                trnm_protocol::CANONICAL_TX_PAYLOAD_TYPE_V1,
                &bytes,
                &ed25519_dalek::SigningKey::from_bytes(&[81; 32]),
            )
            .unwrap(),
        )
        .unwrap()
    }
    fn setup(
        path: &Path,
    ) -> (
        DurableNativeApplicationV0,
        AuthenticatedEpochApplicationEdgeV1,
        PreparedNativeIncrementalEpochExecutionV1,
        Vec<u8>,
        Vec<descendant::PreparedNativeIncrementalEpochDescendantV1>,
    ) {
        let f = build_native_checkpoint_fixture_v1(path);
        let app = f.application;
        let edge = app
            .confirm_poco_checkpoint_v0(
                f.checkpoint,
                &f.checkpoint_finality_bytes,
                &f.handoff_anchor_bytes,
            )
            .unwrap()
            .into_epoch_application_edge_v1()
            .unwrap();
        let checkpoint = header(&edge.recovery_evidence().checkpoint_header).unwrap();
        app.upgrade_incremental_schema_v1(edge.application_parent(), &checkpoint)
            .unwrap();
        app.upgrade_incremental_epoch_schema_v1(&edge).unwrap();
        let credit = signed_runtime(
            &app,
            1,
            trnm_protocol::CanonicalCommandV1::CreditAccount {
                account: "did:operator:1".into(),
                amount: 1_000_000,
            },
        );
        let request = edge.preview_request_v1(11_000, vec![credit]).unwrap();
        let preview = app
            .preview_incremental_epoch_block_v1(&edge, &request)
            .unwrap();
        let set = edge.new_validator_set();
        let mut parent = edge.consensus_parent().id();
        let mut headers = Vec::new();
        for height in 11..=13 {
            let h = BlockHeader::new(
                set.genesis_hash(),
                set.chain_id(),
                set.protocol_version(),
                set.epoch(),
                View::new(height - 10),
                Height::new(height),
                if height == 11 {
                    BlockKind::EpochHandoff
                } else {
                    BlockKind::Regular
                },
                parent,
                set.validators()[(height - 11) as usize % set.validators().len()].id(),
                set.id(),
                edge.new_parameters().hash(),
                PayloadDigest::new(*preview.payload_root().as_bytes()),
                StateRoot::new(*preview.post_state_root().as_bytes()),
                ReceiptsRoot::new(*preview.receipts_root().as_bytes()),
                EvidenceRoot::new(*preview.evidence_root().as_bytes()),
                height * 1000,
                None,
            )
            .unwrap();
            parent = h.id();
            headers.push(h);
        }
        let r = NativeEpochBlockExecutionRequestV1::new(
            request,
            BlockIdV0::new(*headers[0].id().as_bytes()).unwrap(),
            trnm_native_application::NativeExpectedBlockCommitmentsV0::new(
                preview.payload_root(),
                preview.post_state_root(),
                preview.receipts_root(),
                preview.evidence_root(),
            )
            .unwrap(),
        )
        .unwrap();
        let p = app
            .execute_incremental_epoch_block_v1(&edge, r, &headers[0])
            .unwrap();
        let proof = crate::poco_checkpoint::native_checkpoint_fixture_v1::epoch_first_finality(
            &edge, &headers,
        );
        assert!(app
            .commit_incremental_epoch_finality_bytes_v1(
                &p,
                &proof,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0()
            )
            .is_err());
        app.upgrade_incremental_epoch_commit_v1(&edge).unwrap();
        app.upgrade_incremental_epoch_commit_v1(&edge).unwrap();
        let mut descendants = Vec::new();
        let mut actual_headers = vec![p.header().unwrap()];
        for height in [12, 13] {
            let transactions = if height == 12 {
                (2..=9)
                    .map(|nonce| {
                        signed_runtime(
                            &app,
                            nonce,
                            trnm_protocol::CanonicalCommandV1::Transfer {
                                to: format!("did:recipient:{nonce}"),
                                amount: 10,
                            },
                        )
                    })
                    .collect()
            } else {
                Vec::new()
            };
            let parent = if descendants.is_empty() {
                descendant::IncrementalEpochParentV1::First(&p)
            } else {
                descendant::IncrementalEpochParentV1::Descendant(descendants.last().unwrap())
            };
            let head = if descendants.is_empty() {
                p.target_head().unwrap()
            } else {
                descendants.last().unwrap().target_head().unwrap()
            };
            let request = NativeBlockPreviewRequestV0::new(
                ChainIdV0::new(app.config.chain_id.clone()).unwrap(),
                GenesisHashV0::new(app.config.genesis_hash).unwrap(),
                head.clone(),
                HeightV0::new(height),
                height * 1000,
                ValidatorSetIdV0::new(*edge.new_validator_set().id().as_bytes()).unwrap(),
                transactions.clone(),
            )
            .unwrap();
            descendant::assert_worker_parity(&app, parent, &request);
            let preview = app
                .preview_incremental_epoch_descendant_v1(parent, &request)
                .unwrap();
            let set = edge.new_validator_set();
            let h = BlockHeader::new(
                set.genesis_hash(),
                set.chain_id(),
                set.protocol_version(),
                set.epoch(),
                View::new(height - 10),
                Height::new(height),
                BlockKind::Regular,
                trnm_consensus_types::BlockId::new(*head.block_id().as_bytes()),
                set.validators()[(height - 11) as usize % set.validators().len()].id(),
                set.id(),
                edge.new_parameters().hash(),
                PayloadDigest::new(*preview.payload_root().as_bytes()),
                StateRoot::new(*preview.post_state_root().as_bytes()),
                ReceiptsRoot::new(*preview.receipts_root().as_bytes()),
                EvidenceRoot::new(*preview.evidence_root().as_bytes()),
                height * 1000,
                None,
            )
            .unwrap();
            let r = NativeBlockExecutionRequestV0::new(
                request.chain_id().clone(),
                request.genesis_hash(),
                head,
                BlockIdV0::new(*h.id().as_bytes()).unwrap(),
                request.height(),
                request.timestamp_ms(),
                request.active_validator_set_id(),
                transactions,
                trnm_native_application::NativeExpectedBlockCommitmentsV0::new(
                    preview.payload_root(),
                    preview.post_state_root(),
                    preview.receipts_root(),
                    preview.evidence_root(),
                )
                .unwrap(),
            )
            .unwrap();
            descendants.push(
                app.execute_incremental_epoch_descendant_v1(parent, r, &h)
                    .unwrap(),
            );
            actual_headers.push(h);
        }
        let proof = crate::poco_checkpoint::native_checkpoint_fixture_v1::epoch_first_finality(
            &edge,
            &actual_headers,
        );
        (app, edge, p, proof, descendants)
    }
    include!("incremental_epoch_selection_tests_v1.inc");
    include!("incremental_epoch_migration_tests_v2.inc");

    #[test]
    fn schema7_first_new_strict_commit_and_restart_bind_actual_native_cut() {
        let d = tempfile::tempdir().unwrap();
        let path = std::env::var_os("TRNM_NATIVE_INCREMENTAL_EPOCH_COMMIT_SIGKILL_STORE")
            .map(PathBuf::from)
            .unwrap_or_else(|| d.path().join("native.sqlite3"));
        let (app, edge, p, proof, descendants) = setup(&path);
        let mut bad = proof.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(app
            .commit_incremental_epoch_finality_bytes_v1(
                &p,
                &bad,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0()
            )
            .is_err());
        assert_eq!(app.confirmed_committed_head_v0().unwrap().height().get(), 8);
        std::fs::write(path.with_extension("first-block"), p.p.block).unwrap();
        std::fs::write(path.with_extension("first-proof"), &proof).unwrap();
        std::fs::write(path.with_extension("first-p"), p.p.digest).unwrap();
        let committed = app
            .commit_incremental_epoch_finality_bytes_v1(
                &p,
                &proof,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        assert_eq!(committed.head().height().get(), 11);
        assert!(committed.belongs_to_application(&app));
        assert!(!p.belongs_to_application_at_path(&app, &path));
        assert!(app.confirm_epoch_application_edge_v1(&edge).is_err());
        let fresh = app
            .reopen_prepared_incremental_epoch_v1(p.p.block, p.p.digest)
            .unwrap();
        assert_eq!(fresh.commit_sequence(), Some(committed.commit_sequence()));
        let retry = app
            .commit_incremental_epoch_finality_bytes_v1(
                &fresh,
                &proof,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        assert_eq!(retry.commit_sequence(), committed.commit_sequence());
        let descendants_ids = descendants
            .iter()
            .map(|p| (*p.header().unwrap().id().as_bytes(), p.p_digest()))
            .collect::<Vec<_>>();
        for p in &descendants {
            assert!(p.belongs_to_application_at_path(&app, &path));
        }
        let target = committed.head().clone();
        let block = p.p.block;
        let digest = p.p.digest;
        let sequence = committed.commit_sequence();
        drop(app);
        let reopened =
            DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
        assert_eq!(reopened.confirmed_committed_head_v0().unwrap(), target);
        assert!(!committed.belongs_to_application(&reopened));
        for (id, digest) in descendants_ids {
            let p = reopened
                .reopen_prepared_incremental_epoch_descendant_v1(id, digest)
                .unwrap();
            assert!(p.belongs_to_application_at_path(&reopened, &path));
        }
        let restored = reopened
            .reopen_prepared_incremental_epoch_v1(block, digest)
            .unwrap();
        assert_eq!(restored.commit_sequence(), Some(sequence));
        assert!(restored.belongs_to_application_at_path(&reopened, &path));
        let c = Connection::open(&path).unwrap();
        let old: Vec<u8> = c
            .query_row(
                "SELECT proof FROM native_incremental_epoch_commit_v1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let mut bad = old.clone();
        *bad.last_mut().unwrap() ^= 1;
        c.execute(
            "UPDATE native_incremental_epoch_commit_v1 SET proof=?1",
            [bad],
        )
        .unwrap();
        assert!(!restored.belongs_to_application_at_path(&reopened, &path));
        c.execute(
            "UPDATE native_incremental_epoch_commit_v1 SET proof=?1",
            [old],
        )
        .unwrap();
        assert!(restored.belongs_to_application_at_path(&reopened, &path));
        assert_eq!(
            c.query_row(
                "SELECT count(*) FROM ni_roots WHERE version IN(?1,?2)",
                params![
                    9u64.to_be_bytes().as_slice(),
                    10u64.to_be_bytes().as_slice()
                ],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn schema7_commit_owner_resumes_cold_and_fences_tampered_record() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("native.sqlite3");
        let (app, edge, _p, _proof, _descendants) = setup(&path);
        app.ensure_incremental_epoch_commit_owner_v1(&edge).unwrap();
        // The migration is a resumable owner operation, not a one-shot flag.
        app.ensure_incremental_epoch_commit_owner_v1(&edge).unwrap();
        drop(app);

        // Keep the authenticated edge while reopening the native owner from a
        // fresh process-equivalent handle.  The method must rejoin the actual
        // path and schema7 table before returning.
        let reopened =
            DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
        let reopened_edge = reopened.recover_incremental_epoch_edge_v1().unwrap();
        reopened
            .ensure_incremental_epoch_commit_owner_v1(&reopened_edge)
            .unwrap();

        // A syntactically present but malformed retained record is corruption;
        // a retry must fence rather than silently treating it as an empty owner.
        let c = Connection::open(&path).unwrap();
        c.execute(
            "INSERT INTO native_incremental_epoch_commit_v1
             VALUES(1,1,zeroblob(32),zeroblob(32),zeroblob(8),zeroblob(104),zeroblob(1),zeroblob(32))",
            [],
        )
        .unwrap();
        c.pragma_update(None, "ignore_check_constraints", true)
            .unwrap();
        c.execute(
            "UPDATE native_incremental_epoch_commit_v1 SET revision=2 WHERE id=1",
            [],
        )
        .unwrap();
        drop(c);
        assert!(reopened
            .ensure_incremental_epoch_commit_owner_v1(&reopened_edge)
            .is_err());
    }

    #[test]
    fn schema7_cold_audit_rejects_rehashed_retained_first_artifact_and_storage_identity() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("native.sqlite3");
        let (app, _edge, p, proof, _descendants) = setup(&path);
        let _committed = app
            .commit_incremental_epoch_finality_bytes_v1(
                &p,
                &proof,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        drop(app);
        let clean = std::fs::read(&path).unwrap();
        // Rehash every local native/head checksum so integrity checks alone do
        // not reject the mutation. The signed header/proof is left unchanged.
        for mutant in ["storage", "parent", "artifact"] {
            std::fs::write(&path, &clean).unwrap();
            let config = native_checkpoint_fixture_config_v1();
            let mut c = Connection::open(&path).unwrap();
            let tx = c.transaction().unwrap();
            let edge = edge_row(&tx).unwrap();
            let mut p = load_epoch_p(&tx, p.p.block).unwrap().unwrap();
            let mut record = load(&tx).unwrap().unwrap();
            match mutant {
                "storage" => p.storage_sequence += 1,
                "parent" => {
                    p.parent = ApplicationHeadV0::new(
                        p.parent.height(),
                        p.parent.block_id(),
                        p.parent.state_root(),
                        ApplicationCommitIdV0::new([71; 32]).unwrap(),
                    )
                }
                "artifact" => {
                    let e = p.executed().unwrap();
                    let r = e.request();
                    let v = r.preview();
                    let preview = NativeEpochBlockPreviewRequestV1::new(
                        v.chain_id().clone(),
                        v.genesis_hash(),
                        v.application_parent().clone(),
                        v.consensus_parent_id(),
                        v.consensus_parent_height(),
                        v.edge_binding(),
                        v.height(),
                        v.timestamp_ms() + 1,
                        v.active_validator_set_id(),
                        v.transactions().to_vec(),
                    )
                    .unwrap();
                    let request = NativeEpochBlockExecutionRequestV1::new(
                        preview,
                        r.block_id(),
                        r.expected(),
                    )
                    .unwrap();
                    let executed = NativeExecutedEpochBlockV1::new(
                        request,
                        r.expected(),
                        e.receipts().to_vec(),
                    )
                    .unwrap();
                    p.artifact =
                        trnm_native_application::encode_native_executed_epoch_block_artifact_v1(
                            &executed,
                        )
                        .unwrap();
                }
                _ => unreachable!(),
            }
            p.digest = p.digest(&config);
            record.p_digest = p.digest;
            record.head = p.target().unwrap();
            record.checksum = record.digest(&config, &edge);
            tx.execute("UPDATE native_incremental_epoch_p_v1 SET parent=?,artifact=?,storage_sequence=?,digest=? WHERE block=?", params![head_bytes(&p.parent),p.artifact,p.storage_sequence.to_be_bytes().as_slice(),p.digest.as_slice(),p.block.as_slice()]).unwrap();
            tx.execute(
                "UPDATE native_incremental_epoch_commit_v1 SET p_digest=?,head=?,checksum=?",
                params![
                    record.p_digest.as_slice(),
                    head_bytes(&record.head),
                    record.checksum.as_slice()
                ],
            )
            .unwrap();
            let ns = namespace(&config);
            let mut storage = ni::read_incremental_head_v1(&tx, &ns).unwrap();
            storage.intent = *record.head.commit_id().as_bytes();
            fn storage_hash(parts: &[&[u8]]) -> [u8; 32] {
                let mut h = Sha256::new();
                for p in parts {
                    h.update((p.len() as u64).to_be_bytes());
                    h.update(p);
                }
                h.finalize().into()
            }
            let ns_digest = storage_hash(&[
                b"trnm.native-incremental.namespace.v1",
                ns.chain.as_bytes(),
                &ns.genesis,
                &ns.namespace,
                &ns.owner_generation.to_be_bytes(),
            ]);
            storage.checksum = storage_hash(&[
                b"trnm.native-incremental.head.v1",
                &ns_digest,
                &storage.height.to_be_bytes(),
                &storage.block,
                &storage.root,
                &storage.commit_sequence.to_be_bytes(),
                &storage.intent,
            ]);
            tx.execute(
                "UPDATE ni_meta SET head_intent=?,head_checksum=?",
                params![storage.intent.as_slice(), storage.checksum.as_slice()],
            )
            .unwrap();
            tx.execute(
                "UPDATE ni_roots SET intent=? WHERE block_id=?",
                params![storage.intent.as_slice(), storage.block.as_slice()],
            )
            .unwrap();
            let encoded_storage_head = [
                storage.height.to_be_bytes().as_slice(),
                &storage.block,
                &storage.root,
                &storage.commit_sequence.to_be_bytes(),
                &storage.intent,
                &storage.checksum,
            ]
            .concat();
            tx.execute(
                "UPDATE ni_commit SET operation=?,result=? WHERE artifact=?",
                params![
                    storage.intent.as_slice(),
                    encoded_storage_head,
                    p.storage_artifact.as_slice()
                ],
            )
            .unwrap();
            let mut owner = load_owner(&tx).unwrap();
            owner.storage_checksum = storage.checksum;
            owner.checksum = owner.current_digest(&record.head);
            tx.execute(
                "UPDATE native_incremental_owner_v1 SET storage_checksum=?,owner_checksum=?",
                params![owner.storage_checksum.as_slice(), owner.checksum.as_slice()],
            )
            .unwrap();
            tx.execute(
                "UPDATE native_application_metadata_v0 SET head_commit_id=?",
                [record.head.commit_id().as_bytes().as_slice()],
            )
            .unwrap();
            ni::read_incremental_head_v1(&tx, &ns).unwrap();
            let m = load_metadata_v0(&tx, &config).unwrap();
            let err = match audit_owner(&tx, &config, &m) {
                Ok(_) => panic!("accepted {mutant}"),
                Err(e) => e.to_string(),
            };
            let expected = match mutant {
                "storage" => "storage identity/sequence",
                "parent" => "P digest/parent",
                _ => "exact first-new header",
            };
            assert!(err.contains(expected), "{mutant}: {err}");
            tx.commit().unwrap();
            drop(c);
            assert!(
                DurableNativeApplicationV0::open(&path, config).is_err(),
                "cold {mutant}"
            );
        }
        std::fs::write(&path, clean).unwrap();
        assert!(
            DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).is_ok()
        );
    }

    fn empty_descendant(
        app: &DurableNativeApplicationV0,
        edge: &AuthenticatedEpochApplicationEdgeV1,
        parent: descendant::IncrementalEpochParentV1<'_>,
        timestamp: u64,
    ) -> descendant::PreparedNativeIncrementalEpochDescendantV1 {
        let head = match parent {
            descendant::IncrementalEpochParentV1::First(p) => p.target_head().unwrap(),
            descendant::IncrementalEpochParentV1::Descendant(p) => p.target_head().unwrap(),
        };
        let height = head.height().get() + 1;
        let set = edge.new_validator_set();
        let request = NativeBlockPreviewRequestV0::new(
            ChainIdV0::new(app.config.chain_id.clone()).unwrap(),
            GenesisHashV0::new(app.config.genesis_hash).unwrap(),
            head.clone(),
            HeightV0::new(height),
            timestamp,
            ValidatorSetIdV0::new(*set.id().as_bytes()).unwrap(),
            Vec::new(),
        )
        .unwrap();
        let preview = app
            .preview_incremental_epoch_descendant_v1(parent, &request)
            .unwrap();
        let h = BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(height - 10),
            Height::new(height),
            BlockKind::Regular,
            trnm_consensus_types::BlockId::new(*head.block_id().as_bytes()),
            set.validators()[(height - 11) as usize % set.validators().len()].id(),
            set.id(),
            edge.new_parameters().hash(),
            PayloadDigest::new(*preview.payload_root().as_bytes()),
            StateRoot::new(*preview.post_state_root().as_bytes()),
            ReceiptsRoot::new(*preview.receipts_root().as_bytes()),
            EvidenceRoot::new(*preview.evidence_root().as_bytes()),
            timestamp,
            None,
        )
        .unwrap();
        let r = NativeBlockExecutionRequestV0::new(
            request.chain_id().clone(),
            request.genesis_hash(),
            head,
            BlockIdV0::new(*h.id().as_bytes()).unwrap(),
            request.height(),
            request.timestamp_ms(),
            request.active_validator_set_id(),
            Vec::new(),
            trnm_native_application::NativeExpectedBlockCommitmentsV0::new(
                preview.payload_root(),
                preview.post_state_root(),
                preview.receipts_root(),
                preview.evidence_root(),
            )
            .unwrap(),
        )
        .unwrap();
        app.execute_incremental_epoch_descendant_v1(parent, r, &h)
            .unwrap()
    }
    #[test]
    fn schema7_descendant_finality_selects_branch_and_restarts_with_exact_replay() {
        use descendant::IncrementalEpochParentV1 as Parent;
        let d = tempfile::tempdir().unwrap();
        let path = std::env::var_os("TRNM_NATIVE_INCREMENTAL_DESC_COMMIT_SIGKILL_STORE")
            .map(PathBuf::from)
            .unwrap_or_else(|| d.path().join("native.sqlite3"));
        let (app, edge, first, proof, descendants) = setup(&path);
        let next = empty_descendant(&app, &edge, Parent::Descendant(&descendants[1]), 14_000);
        let proof12 = crate::poco_checkpoint::native_checkpoint_fixture_v1::ordinary_epoch_finality(
            &edge,
            &first.header().unwrap(),
            &[
                descendants[0].header().unwrap(),
                descendants[1].header().unwrap(),
                next.header().unwrap(),
            ],
        );
        assert!(app
            .commit_incremental_epoch_descendant_finality_bytes_v1(
                &descendants[0],
                &proof12,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0()
            )
            .is_err());
        let committed11 = app
            .commit_incremental_epoch_finality_bytes_v1(
                &first,
                &proof,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        let fork = empty_descendant(&app, &edge, Parent::First(&first), 12_001);
        let fork_child = empty_descendant(&app, &edge, Parent::Descendant(&fork), 13_001);
        let mut invalid = proof12.clone();
        *invalid.last_mut().unwrap() ^= 1;
        assert!(app
            .commit_incremental_epoch_descendant_finality_bytes_v1(
                &descendants[0],
                &invalid,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0()
            )
            .is_err());
        assert!(committed11.belongs_to_application(&app));
        std::fs::write(
            path.with_extension("desc-block"),
            descendants[0].header().unwrap().id().as_bytes(),
        )
        .unwrap();
        std::fs::write(path.with_extension("desc-p"), descendants[0].p_digest()).unwrap();
        std::fs::write(path.with_extension("desc-proof"), &proof12).unwrap();
        let committed12 = app
            .commit_incremental_epoch_descendant_finality_bytes_v1(
                &descendants[0],
                &proof12,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        assert_eq!(committed12.head().height().get(), 12);
        assert!(committed12.belongs_to_application(&app));
        assert!(!committed11.belongs_to_application(&app));
        assert!(!fork.belongs_to_application_at_path(&app, &path));
        assert!(!fork_child.belongs_to_application_at_path(&app, &path));
        assert!(next.belongs_to_application_at_path(&app, &path));
        let retry = app
            .commit_incremental_epoch_descendant_finality_bytes_v1(
                &descendants[0],
                &proof12,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        assert_eq!(retry.commit_sequence(), committed12.commit_sequence());
        let head = committed12.head().clone();
        let id = *descendants[0].header().unwrap().id().as_bytes();
        let digest = descendants[0].p_digest();
        let finalid = *next.header().unwrap().id().as_bytes();
        let finaldigest = next.p_digest();
        drop(app);
        let app =
            DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
        assert_eq!(app.confirmed_committed_head_v0().unwrap(), head);
        let p = app
            .reopen_prepared_incremental_epoch_descendant_v1(id, digest)
            .unwrap();
        assert_eq!(p.commit_sequence(), Some(committed12.commit_sequence()));
        assert!(p.belongs_to_application_at_path(&app, &path));
        assert!(app
            .reopen_prepared_incremental_epoch_descendant_v1(finalid, finaldigest)
            .unwrap()
            .belongs_to_application_at_path(&app, &path));
        let duplicate = p.executed().unwrap().request().transactions()[0].clone();
        let request = NativeBlockPreviewRequestV0::new(
            ChainIdV0::new(app.config.chain_id.clone()).unwrap(),
            GenesisHashV0::new(app.config.genesis_hash).unwrap(),
            head,
            HeightV0::new(13),
            13_001,
            ValidatorSetIdV0::new(*edge.new_validator_set().id().as_bytes()).unwrap(),
            vec![duplicate],
        )
        .unwrap();
        assert!(app
            .preview_incremental_epoch_descendant_v1(Parent::Descendant(&p), &request)
            .is_err());
        let c = Connection::open(&path).unwrap();
        {
            let tx = c.unchecked_transaction().unwrap();
            let mut mutant = load_p(&tx, id).unwrap().unwrap();
            mutant.storage_sequence += 1;
            mutant.digest = mutant.calculate_digest(&app.config);
            mutant
                .validate_context(&app.config, edge.new_validator_set(), edge.new_parameters())
                .unwrap();
            let error = descendant::validate_storage_p(&tx, &mutant).unwrap_err();
            assert!(error.to_string().contains("storage identity/sequence"));
        }
        let actual: Vec<u8> = c
            .query_row(
                "SELECT proof FROM native_incremental_epoch_descendant_commit_v1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let mut bad = actual.clone();
        *bad.last_mut().unwrap() ^= 1;
        c.execute(
            "UPDATE native_incremental_epoch_descendant_commit_v1 SET proof=?1",
            [bad],
        )
        .unwrap();
        assert!(!p.belongs_to_application_at_path(&app, &path));
        c.execute(
            "UPDATE native_incremental_epoch_descendant_commit_v1 SET proof=?1",
            [actual],
        )
        .unwrap();
        assert!(p.belongs_to_application_at_path(&app, &path));
    }
    #[cfg(unix)]
    #[test]
    fn schema7_sigkill_commit_cuts_preserve_descendants_replay_and_exact_receipt() {
        for stage in [
            "incremental_epoch_commit_before_commit",
            "incremental_epoch_commit_after_commit",
            "incremental_epoch_commit_after_fsync",
        ] {
            let d = tempfile::tempdir().unwrap();
            let path = d.path().join("native.sqlite3");
            let marker = d.path().join("ready");
            let mut child=std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact","durable::incremental_owner_v1::epoch_candidate_v1::commit::tests::schema7_first_new_strict_commit_and_restart_bind_actual_native_cut","--nocapture"])
                .env("TRNM_NATIVE_INCREMENTAL_EPOCH_COMMIT_SIGKILL_STORE",&path).env("TRNM_NATIVE_EXECUTION_TEST_KILL_STAGE",stage).env("TRNM_NATIVE_EXECUTION_TEST_KILL_MARKER",&marker).spawn().unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
            while !marker.exists() && std::time::Instant::now() < deadline {
                if child.try_wait().unwrap().is_some() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            if !marker.exists() {
                let _ = child.kill();
                let _ = child.wait();
                panic!("schema7 child did not reach {stage}");
            }
            child.kill().unwrap();
            assert!(!child.wait().unwrap().success());
            let app =
                DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1())
                    .unwrap();
            let expected = if stage == "incremental_epoch_commit_before_commit" {
                8
            } else {
                11
            };
            assert_eq!(
                app.confirmed_committed_head_v0().unwrap().height().get(),
                expected
            );
            let block = std::fs::read(path.with_extension("first-block"))
                .unwrap()
                .try_into()
                .unwrap();
            let digest = std::fs::read(path.with_extension("first-p"))
                .unwrap()
                .try_into()
                .unwrap();
            let proof = std::fs::read(path.with_extension("first-proof")).unwrap();
            let p = app
                .reopen_prepared_incremental_epoch_v1(block, digest)
                .unwrap();
            let result = app
                .commit_incremental_epoch_finality_bytes_v1(
                    &p,
                    &proof,
                    &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
                )
                .unwrap();
            assert_eq!(result.commit_sequence(), 21);
            assert!(result.belongs_to_application(&app));
            let c = Connection::open(&path).unwrap();
            let mut q = c
                .prepare("SELECT block,digest FROM native_incremental_p_v1")
                .unwrap();
            let ids = q
                .query_map([], |r| {
                    Ok((row_blob(r, 0, 32, 32)?, row_blob(r, 1, 32, 32)?))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert_eq!(ids.len(), 2);
            for (block, digest) in ids {
                let p = app
                    .reopen_prepared_incremental_epoch_descendant_v1(
                        block.try_into().unwrap(),
                        digest.try_into().unwrap(),
                    )
                    .unwrap();
                assert!(p.belongs_to_application_at_path(&app, &path));
            }
            assert_eq!(
                c.query_row(
                    "SELECT length(authenticated_snapshot) FROM native_application_metadata_v0",
                    [],
                    |r| r.get::<_, u64>(0)
                )
                .unwrap(),
                0
            );
        }
    }
    #[cfg(unix)]
    #[test]
    fn schema7_sigkill_descendant_commit_cuts_are_atomic_and_retry_exact() {
        for stage in [
            "incremental_epoch_descendant_commit_before_commit",
            "incremental_epoch_descendant_commit_after_commit",
            "incremental_epoch_descendant_commit_after_fsync",
        ] {
            let d = tempfile::tempdir().unwrap();
            let path = d.path().join("native.sqlite3");
            let marker = d.path().join("ready");
            let exe = d.path().join("child-tests");
            std::fs::hard_link(std::env::current_exe().unwrap(), &exe).unwrap();
            let mut child=std::process::Command::new(&exe).args(["--exact","durable::incremental_owner_v1::epoch_candidate_v1::commit::tests::schema7_descendant_finality_selects_branch_and_restarts_with_exact_replay","--nocapture"])
                .env("TRNM_NATIVE_INCREMENTAL_DESC_COMMIT_SIGKILL_STORE",&path).env("TRNM_NATIVE_EXECUTION_TEST_KILL_STAGE",stage).env("TRNM_NATIVE_EXECUTION_TEST_KILL_MARKER",&marker).spawn().unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
            while !marker.exists() && std::time::Instant::now() < deadline {
                if child.try_wait().unwrap().is_some() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            if !marker.exists() {
                let _ = child.kill();
                let _ = child.wait();
                panic!("descendant child did not reach {stage}");
            }
            child.kill().unwrap();
            assert!(!child.wait().unwrap().success());
            let app =
                DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1())
                    .unwrap();
            assert_eq!(
                app.confirmed_committed_head_v0().unwrap().height().get(),
                if stage == "incremental_epoch_descendant_commit_before_commit" {
                    11
                } else {
                    12
                }
            );
            let block = std::fs::read(path.with_extension("desc-block"))
                .unwrap()
                .try_into()
                .unwrap();
            let digest = std::fs::read(path.with_extension("desc-p"))
                .unwrap()
                .try_into()
                .unwrap();
            let proof = std::fs::read(path.with_extension("desc-proof")).unwrap();
            let p = app
                .reopen_prepared_incremental_epoch_descendant_v1(block, digest)
                .unwrap();
            let committed = app
                .commit_incremental_epoch_descendant_finality_bytes_v1(
                    &p,
                    &proof,
                    &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
                )
                .unwrap();
            assert_eq!(committed.commit_sequence(), 25);
            assert!(committed.belongs_to_application_at_path(&app, &path));
            let c = Connection::open(&path).unwrap();
            assert_eq!(
                c.query_row("SELECT count(*) FROM native_incremental_p_v1", [], |r| r
                    .get::<_, u64>(0))
                    .unwrap(),
                3
            );
            assert_eq!(
                c.query_row(
                    "SELECT count(*) FROM native_incremental_epoch_descendant_commit_v1",
                    [],
                    |r| r.get::<_, u64>(0)
                )
                .unwrap(),
                1
            );
        }
    }
}
