use super::*;
use crate::store::AuthenticatedReplayDecision;
use crate::{development_public, ErrorCode, Packet, PoolLimits, Settings};
use rusqlite::params;
use std::collections::BTreeMap;
use std::path::PathBuf;
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::continuity_v1;
use trnm_protocol::pon_wire::{hash, Envelope};
use trnm_transport::{AuthenticatedPeerFrameV0, IoDigest32V0, PeerSessionIdentityV0};

fn settings() -> Settings {
    Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap()
}

fn public(index: u64) -> Hash {
    development_public(index).unwrap()
}

fn transfer(settings: &Settings, nonce: u64, recipient: u64, amount: u64) -> Vec<u8> {
    let mut payload = public(recipient).to_vec();
    payload.extend(amount.to_le_bytes());
    let mut tx = Envelope {
        network: settings.network(),
        sender: public(0),
        nonce,
        expiry: 2000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()]))).unwrap();
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}

fn packet(node: &Node, parent: Hash, height: u64, miner: u64, txs: Vec<Vec<u8>>) -> Packet {
    node.make_consensus_maintenance(parent, txs, public(miner), 1 + height * 10 + miner, 4096)
        .unwrap()
}

fn admit(node: &mut Node, parent: Hash, height: u64, miner: u64, txs: Vec<Vec<u8>>) -> Hash {
    let packet = packet(node, parent, height, miner, txs);
    node.admit(&packet, 100_000).unwrap()
}

fn frame(node: &Node, session: u8, nonce: u64, payload: &[u8]) -> AuthenticatedPeerFrameV0 {
    let session = PeerSessionIdentityV0::new(
        IoDigest32V0::new(node.settings.genesis()).unwrap(),
        IoDigest32V0::new(node.settings.parameters()).unwrap(),
        IoDigest32V0::new([session + 1; 32]).unwrap(),
        IoDigest32V0::new([session; 32]).unwrap(),
        IoDigest32V0::new(crate::authenticated_profile_digest()).unwrap(),
        1,
    )
    .unwrap();
    AuthenticatedPeerFrameV0::new(
        session,
        nonce,
        IoDigest32V0::new(crate::authenticated_payload_digest(payload)).unwrap(),
        payload.len(),
    )
    .unwrap()
}

fn logical_rows(db: &Connection) -> BTreeMap<String, Vec<Vec<SqlValue>>> {
    table_names(db)
        .unwrap()
        .into_iter()
        .map(|table| {
            let (select, columns) = ordered_select(db, &table).unwrap();
            let mut statement = db.prepare(&select).unwrap();
            let mut cursor = statement.query([]).unwrap();
            let mut rows = Vec::new();
            while let Some(row) = cursor.next().unwrap() {
                rows.push(values(row, columns).unwrap());
            }
            (table, rows)
        })
        .collect()
}

fn durable_bytes(path: &Path) -> BTreeMap<String, Vec<u8>> {
    // SQLite shared-memory lock/read marks are coordination state. The durable
    // database, WAL and owner payload must remain byte-for-byte unchanged.
    ["native.sqlite", "native.sqlite-wal", "owner.lock"]
        .into_iter()
        .filter_map(|name| {
            fs::read(path.join(name))
                .ok()
                .map(|bytes| (name.into(), bytes))
        })
        .collect()
}

fn assert_pending(path: &Path) {
    assert!(path.join(PENDING).is_file());
    for result in [
        Node::open(path, settings(), 1),
        Node::open_with_authenticated_state(path, settings(), 1),
    ] {
        assert_eq!(
            result.err().unwrap().to_string(),
            "NATIVE_STATE_MIGRATION_PENDING"
        );
    }
}

struct Fixture {
    dir: tempfile::TempDir,
    node: Node,
    branch_tip: Hash,
    cached: AuthenticatedPeerFrameV0,
    inbound: AuthenticatedPeerFrameV0,
    outbound: AuthenticatedPeerFrameV0,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut node = Node::open(&dir.path().join("source"), settings(), 2).unwrap();
        let genesis = node.settings.genesis();
        let tx = transfer(node.settings(), 1, 1, 5);
        let a = admit(&mut node, genesis, 1, 0, vec![tx]);
        node.activate(a).unwrap();
        let tx = transfer(node.settings(), 2, 1, 2);
        let a2 = admit(&mut node, a, 2, 0, vec![tx]);
        node.activate(a2).unwrap();
        let tx = transfer(node.settings(), 1, 2, 6);
        let b = admit(&mut node, genesis, 1, 3, vec![tx]);
        let b2 = admit(&mut node, b, 2, 3, Vec::new());
        let tx = transfer(node.settings(), 2, 2, 3);
        let branch_tip = admit(&mut node, b2, 3, 3, vec![tx]);
        node.enable_local_mempool(PoolLimits {
            max_records: 16,
            max_bytes: 32768,
            max_group_members: 16,
            critical_reserve: 0,
            max_removals: 16,
            preview_miner: public(0),
        })
        .unwrap();
        node.pool_submit(transfer(node.settings(), 3, 4, 1))
            .unwrap();
        let cached = frame(&node, 31, 1, b"completed request");
        node.begin_authenticated_request(cached, b"completed request")
            .unwrap();
        node.finish_authenticated_request(cached, b"retained response")
            .unwrap();
        let inbound = frame(&node, 32, 1, b"incomplete request");
        node.begin_authenticated_request(inbound, b"incomplete request")
            .unwrap();
        let outbound = frame(&node, 33, 1, b"outbound request");
        node.reserve_authenticated_outbound(outbound, b"outbound request", b"exact signed wire")
            .unwrap();
        Self {
            dir,
            node,
            branch_tip,
            cached,
            inbound,
            outbound,
        }
    }

    fn complete_branch(&mut self) {
        self.node.activate(self.branch_tip).unwrap();
        let tx = transfer(self.node.settings(), 3, 4, 1);
        let included = self.node.pool_submit(tx.clone()).unwrap();
        assert!(included.duplicate);
        let final_block = admit(&mut self.node, self.branch_tip, 4, 3, vec![tx]);
        self.node.activate(final_block).unwrap();
        self.node.pool_reconcile().unwrap();
        self.node
            .pool_prune_terminal(hex::decode(included.group).unwrap().try_into().unwrap())
            .unwrap();
        self.node
            .pool_submit(transfer(self.node.settings(), 4, 5, 1))
            .unwrap();
    }

    fn assert_replay(&self, target: &mut Node) {
        assert!(matches!(
            target.begin_authenticated_request(self.cached, b"completed request").unwrap(),
            AuthenticatedReplayDecision::Cached(bytes) if bytes == b"retained response"
        ));
        assert_eq!(target.authenticated_replay_counts().unwrap(), (2, 1, 2));
        assert_eq!(
            target
                .authenticated_outbound_reservation(self.outbound.session())
                .unwrap(),
            (1, Some(b"exact signed wire".to_vec())),
        );
        assert_eq!(
            target
                .authenticated_replay_state(self.inbound.session())
                .unwrap(),
            self.node
                .authenticated_replay_state(self.inbound.session())
                .unwrap()
        );
    }
}

fn export_observation(
    node: &Node,
    target: &Path,
    receipt: &AuthenticatedMigrationReceipt,
    export: &Path,
) {
    fs::create_dir(export).unwrap();
    node.db
        .execute(
            "VACUUM INTO ?",
            [export.join("source.sqlite").to_str().unwrap()],
        )
        .unwrap();
    let db = Connection::open(target.join("native.sqlite")).unwrap();
    db.execute(
        "VACUUM INTO ?",
        [export.join("native.sqlite").to_str().unwrap()],
    )
    .unwrap();
    let mut statement = node
        .db
        .prepare("SELECT id FROM blocks ORDER BY height,id")
        .unwrap();
    let ids = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .unwrap()
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();
    let blocks: Vec<_> = ids
        .into_iter()
        .map(|id| {
            let id = bytes32(id).unwrap();
            serde_json::json!({"id":hex::encode(id),"state":node.state_at(id).unwrap()})
        })
        .collect();
    let (tip, generation) = node.active().unwrap();
    let observation = serde_json::json!({
        "schema":"pon-native-authenticated-storage-native-observation-v1",
        "database":"native.sqlite", "genesis_timestamp":1,
        "context":{"network":hex::encode(node.settings.network()),"parameters":hex::encode(node.settings.parameters()),"genesis":hex::encode(node.settings.genesis())},
        "initial":node.settings.initial,
        "active":{"tip":hex::encode(tip),"generation":generation,"state_slot":node.slot().unwrap()},
        "blocks":blocks, "migrated":true, "receipt":receipt,
        "scope":"actual native signed branches and local replay/outbox/pool copy before target reopen; local-development migration only; no external owner operation or production activation"
    });
    fs::write(
        export.join("native.json"),
        serde_json::to_vec_pretty(&observation).unwrap(),
    )
    .unwrap();
}

#[test]
fn authenticated_migration_preserves_signed_branches_and_irreversible_local_facts() {
    let mut fixture = Fixture::new();
    fixture.complete_branch();
    let source = fixture.node.directory.clone();
    let before = logical_rows(&fixture.node.db);
    let files = durable_bytes(&source);
    let active = fixture.node.read_active().unwrap();
    let target = fixture.dir.path().join("migrated");
    let receipt = fixture
        .node
        .migrate_to_authenticated_state(&target)
        .unwrap();
    assert_eq!(receipt.retained_blocks, 7);
    assert_eq!(receipt.replayed_blocks, 6);
    assert_eq!(receipt.replayed_transactions, 5);
    assert_eq!(receipt.external_owner_operations_executed, 0);
    assert!(!receipt.pending_reorganization);
    assert_eq!(logical_rows(&fixture.node.db), before);
    assert_eq!(durable_bytes(&source), files);
    assert!(!target.join(PENDING).exists());
    if let Some(export) = std::env::var_os("TRNM_AUTHENTICATED_MIGRATION_EXPORT") {
        export_observation(&fixture.node, &target, &receipt, Path::new(&export));
    }
    let copied = Connection::open(target.join("native.sqlite")).unwrap();
    assert_eq!(
        compare_preserved(
            &fixture.node.db,
            &copied,
            &table_names(&fixture.node.db).unwrap(),
            &|_| Ok(())
        )
        .unwrap(),
        receipt.preserved_tables
    );
    drop(copied);
    assert!(Node::open(&target, settings(), 2).is_err());
    let mut migrated = Node::open_with_authenticated_state(&target, settings(), 2).unwrap();
    assert_eq!(migrated.read_active().unwrap(), active);

    let source_state = migrated.read_active().unwrap().2;
    let growth =
        crate::account_archive_execution::state_witness::growth_commitment_from_complete_state_v2(
            migrated.settings(),
            &source_state,
        )
        .unwrap();
    let binding = crate::account_archive_execution::state_witness::growth_profile_binding_v2(
        migrated.settings(),
        &growth,
        "authenticated-growth-v2/migrated",
    )
    .unwrap();
    let plan = migrated
        .prepare_growth_profile_migration_v2(&binding)
        .unwrap();
    assert_eq!(
        plan.schema,
        "pon-permanent-account-growth-migration-plan-v2"
    );
    assert_eq!(plan.source_tip, hex::encode(active.0));
    assert_eq!(plan.source_generation, active.1);
    assert_eq!(plan.source_commitment, hex::encode(growth.id));
    assert_eq!(plan.profile_binding, hex::encode(binding.id));
    assert!(plan.complete_source_state_checked);
    assert!(!plan.target_storage_reserved);
    assert!(!plan.migration_executed);
    assert!(!plan.consensus_activation);

    let mut forged_binding = binding.clone();
    forged_binding.candidate_parameters[0] ^= 1;
    assert!(migrated
        .prepare_growth_profile_migration_v2(&forged_binding)
        .is_err());
    assert_eq!(
        fixture
            .node
            .prepare_growth_profile_migration_v2(&binding)
            .unwrap_err()
            .to_string(),
        "GROWTH_MIGRATION_SOURCE_PROFILE"
    );

    fixture.assert_replay(&mut migrated);
    let source_pool = serde_json::to_value(fixture.node.pool_status_snapshot().unwrap()).unwrap();
    assert_eq!(
        serde_json::to_value(migrated.pool_status_snapshot().unwrap()).unwrap(),
        source_pool
    );
    assert_eq!(migrated.next_nonce(public(0)).unwrap(), 4);
    assert!(migrated
        .migrate_to_authenticated_state(&fixture.dir.path().join("again"))
        .is_err());
    assert!(!fixture.dir.path().join("again").exists());
    assert!(fixture
        .node
        .migrate_to_authenticated_state(&target)
        .is_err());
    drop(migrated);
    let reopened = Node::open_with_authenticated_state(&target, settings(), 2).unwrap();
    assert_eq!(reopened.read_active().unwrap(), active);
    assert_eq!(logical_rows(&fixture.node.db), before);
}

#[test]
fn authenticated_migration_retains_partial_reorganization_then_target_recovers_once() {
    for cut in ["intent", "detach:0", "attach:2", "before-publish"] {
        let mut fixture = Fixture::new();
        let mut stop = |point: &str| {
            if point == cut {
                Err(Error::new(ErrorCode::PeerPollCancelled))
            } else {
                Ok(())
            }
        };
        assert!(fixture
            .node
            .activate_with_fault(fixture.branch_tip, Some(&mut stop))
            .unwrap_err()
            .is(ErrorCode::PeerPollCancelled));
        let prior = fixture.node.active().unwrap();
        let before = logical_rows(&fixture.node.db);
        let files = durable_bytes(&fixture.node.directory);
        let target = fixture.dir.path().join("migrated");
        let receipt = fixture
            .node
            .migrate_to_authenticated_state(&target)
            .unwrap();
        assert!(receipt.pending_reorganization);
        assert_eq!(fixture.node.active().unwrap(), prior);
        assert_eq!(logical_rows(&fixture.node.db), before);
        assert_eq!(durable_bytes(&fixture.node.directory), files);
        let copied = Connection::open(target.join("native.sqlite")).unwrap();
        compare_preserved(
            &fixture.node.db,
            &copied,
            &table_names(&fixture.node.db).unwrap(),
            &|_| Ok(()),
        )
        .unwrap();
        drop(copied);
        let mut migrated = Node::open_with_authenticated_state(&target, settings(), 2).unwrap();
        assert_eq!(
            migrated.active().unwrap(),
            (fixture.branch_tip, prior.1 + 1)
        );
        assert_eq!(
            migrated.state_at(fixture.branch_tip).unwrap(),
            fixture.node.state_at(fixture.branch_tip).unwrap()
        );
        fixture.assert_replay(&mut migrated);
        let after_recovery = logical_rows(&migrated.db);
        for name in [
            "peer_replay",
            "peer_request_audit",
            "peer_outbox",
            "local_pool_metadata",
            "local_pool_groups",
            "local_pool_rows",
            "local_pool_removals",
            "sqlite_sequence",
        ] {
            assert_eq!(after_recovery[name], before[name], "{cut}: {name}");
        }
        drop(migrated);
        let reopened = Node::open_with_authenticated_state(&target, settings(), 2).unwrap();
        assert_eq!(
            reopened.active().unwrap(),
            (fixture.branch_tip, prior.1 + 1)
        );
        assert_eq!(logical_rows(&reopened.db), after_recovery);
        assert_eq!(logical_rows(&fixture.node.db), before);
    }
}

#[test]
fn authenticated_migration_cancellation_never_publishes_partial_destination() {
    let mut fixture = Fixture::new();
    fixture.complete_branch();
    let before = logical_rows(&fixture.node.db);
    let files = durable_bytes(&fixture.node.directory);
    for stage in 0..11 {
        let target = fixture.dir.path().join(format!("cancel-{stage}"));
        let result = fixture
            .node
            .migrate_to_authenticated_state_with_progress(&target, &|point| {
                let stop = matches!(
                    (stage, point),
                    (0, AuthenticatedMigrationProgress::SourceLocked)
                        | (1, AuthenticatedMigrationProgress::TargetCreated)
                        | (2, AuthenticatedMigrationProgress::CopyRow { .. })
                        | (3, AuthenticatedMigrationProgress::BeforeBlock { height: 1 })
                        | (4, AuthenticatedMigrationProgress::Work { height: 1 })
                        | (5, AuthenticatedMigrationProgress::Execution { height: 1 })
                        | (
                            6,
                            AuthenticatedMigrationProgress::AuthenticatedState { height: 1 }
                        )
                        | (7, AuthenticatedMigrationProgress::BeforeCommit)
                        | (8, AuthenticatedMigrationProgress::Committed)
                        | (9, AuthenticatedMigrationProgress::BeforePublish)
                        | (10, AuthenticatedMigrationProgress::BeforeTargetVisible)
                );
                if stop {
                    Err(Error::new(ErrorCode::PeerPollCancelled))
                } else {
                    Ok(())
                }
            });
        assert!(
            result.unwrap_err().is(ErrorCode::PeerPollCancelled),
            "stage {stage}"
        );
        if stage == 0 || stage == 10 {
            assert!(!target.exists());
        } else {
            assert_pending(&target);
        }
        assert_eq!(logical_rows(&fixture.node.db), before);
        assert_eq!(durable_bytes(&fixture.node.directory), files);
    }
}

#[test]
fn authenticated_migration_rechecks_retained_authority_including_inactive_branches() {
    for corruption in 0..5 {
        let mut fixture = Fixture::new();
        fixture.complete_branch();
        let target = fixture.dir.path().join("migrated");
        let inactive: Vec<u8> = fixture.node.db.query_row(
            "SELECT id FROM blocks WHERE height=1 AND id IN (SELECT block FROM events WHERE generation=1)",
            [], |row| row.get(0),
        ).unwrap();
        match corruption {
            0 => {
                let mut packet = fixture
                    .node
                    .packet(bytes32(inactive.clone()).unwrap())
                    .unwrap();
                packet.proof[4] ^= 1;
                fixture
                    .node
                    .db
                    .execute(
                        "UPDATE blocks SET packet=? WHERE id=?",
                        params![packet.encode().unwrap(), inactive],
                    )
                    .unwrap();
            }
            1 => {
                fixture
                    .node
                    .db
                    .execute(
                        "UPDATE blocks SET chainwork=? WHERE id=?",
                        params![[0_u8; 64].as_slice(), inactive],
                    )
                    .unwrap();
            }
            2 => {
                fixture.node.db.execute("UPDATE deltas SET after=? WHERE block=? AND key=(SELECT key FROM deltas WHERE block=? ORDER BY key LIMIT 1)", params![b"null".as_slice(), inactive, inactive]).unwrap();
            }
            3 => {
                fixture
                    .node
                    .db
                    .execute(
                        "UPDATE events SET block=? WHERE generation=1",
                        [fixture.node.settings.genesis().as_slice()],
                    )
                    .unwrap();
            }
            _ => {
                fixture
                    .node
                    .db
                    .execute(
                        "UPDATE peer_request_audit SET payload=? WHERE status=0",
                        [b"corrupt pending bytes".as_slice()],
                    )
                    .unwrap();
            }
        }
        let before = logical_rows(&fixture.node.db);
        assert!(
            fixture
                .node
                .migrate_to_authenticated_state(&target)
                .is_err(),
            "case {corruption}"
        );
        assert_eq!(logical_rows(&fixture.node.db), before);
        if target.exists() {
            assert_pending(&target);
        }
    }
}

#[test]
fn authenticated_migration_rejects_external_owner_journal_and_required_marker() {
    use crate::operator_task_policy::{self as policy, tests as fixtures};
    use std::cell::RefCell;
    use std::sync::{
        atomic::{AtomicBool, AtomicU64},
        Arc,
    };
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = fixtures::directory();
    let mut node = Node::open(&dir.path().join("source"), settings(), 1).unwrap();
    let policy = fixtures::authenticated(fixtures::body());
    let marker = policy.marker(journal_dir.path()).unwrap();
    let journal = policy::Journal::open(journal_dir.path(), fixtures::uid(), &policy).unwrap();
    // Private unit assembly installs a real local policy journal. This refusal
    // test does not claim the external signed-input opener was exercised.
    node.owner_policy = Some(crate::store::OwnerPolicy {
        pool_policies: Vec::new(),
        epoch: Arc::new(AtomicU64::new(1)),
        outside_keys: (String::new(), String::new()),
        policy: Arc::new(policy),
        required_marker: marker,
        journal: RefCell::new(journal),
        unavailable: Arc::new(AtomicBool::new(false)),
    });
    let before = logical_rows(&node.db);
    let files: BTreeMap<_, _> = fs::read_dir(journal_dir.path())
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (entry.file_name(), fs::read(entry.path()).unwrap())
        })
        .collect();
    let target = dir.path().join("target");
    assert_eq!(
        node.migrate_to_authenticated_state(&target)
            .unwrap_err()
            .to_string(),
        "AUTHENTICATED_MIGRATION_EXTERNAL_OWNER"
    );
    assert!(!target.exists());
    node.owner_policy = None;
    fs::write(
        node.directory.join("owner-task-policy.required"),
        b"real required-mode fence",
    )
    .unwrap();
    assert_eq!(
        node.migrate_to_authenticated_state(&target)
            .unwrap_err()
            .to_string(),
        "AUTHENTICATED_MIGRATION_EXTERNAL_OWNER"
    );
    assert!(!target.exists());
    assert_eq!(logical_rows(&node.db), before);
    let after: BTreeMap<_, _> = fs::read_dir(journal_dir.path())
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (entry.file_name(), fs::read(entry.path()).unwrap())
        })
        .collect();
    assert_eq!(after, files);
}

#[test]
fn authenticated_migration_snapshot_blocks_source_sql_writer_and_rejects_changed_target() {
    let mut fixture = Fixture::new();
    fixture.complete_branch();
    let source = fixture.node.directory.join("native.sqlite");
    let target = fixture.dir.path().join("migrated");
    let before = logical_rows(&fixture.node.db);
    let result = fixture
        .node
        .migrate_to_authenticated_state_with_progress(&target, &|point| {
            if point == AuthenticatedMigrationProgress::SourceLocked {
                let db = Connection::open(&source)?;
                db.busy_timeout(std::time::Duration::ZERO)?;
                assert!(db
                    .execute("UPDATE active SET generation=generation+1", [])
                    .is_err());
            }
            if point == AuthenticatedMigrationProgress::Committed {
                let db = Connection::open(target.join("native.sqlite"))?;
                db.execute("UPDATE native_state_commitments SET data=X'00'", [])?;
            }
            Ok(())
        });
    assert_eq!(
        result.unwrap_err().to_string(),
        "AUTHENTICATED_MIGRATION_DURABLE_BYTES"
    );
    assert_pending(&target);
    assert_eq!(logical_rows(&fixture.node.db), before);
}

#[test]
fn authenticated_migration_refuses_source_descendants_and_existing_destinations() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::open(&dir.path().join("source"), settings(), 1).unwrap();
    let before = logical_rows(&node.db);
    let files = durable_bytes(&node.directory);
    let nested = node.directory.join("nested-target");
    assert_eq!(
        node.migrate_to_authenticated_state(&nested)
            .unwrap_err()
            .to_string(),
        "AUTHENTICATED_MIGRATION_SOURCE_DESTINATION"
    );
    assert!(!nested.exists());
    let alias = dir.path().join("source-alias");
    std::os::unix::fs::symlink(&node.directory, &alias).unwrap();
    assert_eq!(
        node.migrate_to_authenticated_state(&alias.join("nested-target"))
            .unwrap_err()
            .to_string(),
        "AUTHENTICATED_MIGRATION_SOURCE_DESTINATION"
    );
    assert!(!nested.exists());
    let existing = dir.path().join("existing");
    fs::create_dir(&existing).unwrap();
    fs::write(existing.join("retained"), b"unrelated existing data").unwrap();
    assert!(node.migrate_to_authenticated_state(&existing).is_err());
    assert_eq!(
        fs::read(existing.join("retained")).unwrap(),
        b"unrelated existing data"
    );
    assert_eq!(fs::read_dir(existing).unwrap().count(), 1);
    assert_eq!(logical_rows(&node.db), before);
    assert_eq!(durable_bytes(&node.directory), files);
}

#[test]
fn authenticated_migration_atomic_target_creation_never_overwrites_a_racing_destination() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::open(&dir.path().join("source"), settings(), 1).unwrap();
    let target = dir.path().join("destination");
    let result = node.migrate_to_authenticated_state_with_progress(&target, &|point| {
        if point == AuthenticatedMigrationProgress::BeforeTargetVisible {
            assert!(!target.exists());
            let staged: Vec<_> = fs::read_dir(dir.path())?
                .filter_map(|entry| {
                    let entry = entry.ok()?;
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with("native-authenticated-migration-staging-")
                        .then(|| entry.path())
                })
                .collect();
            assert_eq!(staged.len(), 1);
            assert_pending(&staged[0]);
            fs::create_dir(&target)?;
            fs::write(target.join("existing-owner"), b"retained race winner")?;
        }
        Ok(())
    });
    assert!(result.is_err());
    assert_eq!(
        fs::read(target.join("existing-owner")).unwrap(),
        b"retained race winner"
    );
    assert_eq!(fs::read_dir(&target).unwrap().count(), 1);
}

#[test]
fn authenticated_migration_last_callback_cannot_hide_raw_file_or_receipt_changes() {
    for damaged in 0..4 {
        let dir = tempfile::tempdir().unwrap();
        let node = Node::open(&dir.path().join("source"), settings(), 1).unwrap();
        let target = dir.path().join("destination");
        let source_path = node.directory.join("native.sqlite");
        let source_bytes = fs::read(&source_path).unwrap();
        let result = node.migrate_to_authenticated_state_with_progress(&target, &|point| {
            if point == AuthenticatedMigrationProgress::BeforePublish {
                let path = match damaged {
                    0 => target.join("native.sqlite"),
                    1 => target.join(RECEIPT),
                    2 => target.join(PENDING),
                    _ => source_path.clone(),
                };
                let mut bytes = fs::read(&path)?;
                let last = bytes.len() - 1;
                bytes[last] ^= 1;
                let mut file = OpenOptions::new().write(true).open(path)?;
                file.write_all(&bytes)?;
                file.sync_all()?;
            }
            Ok(())
        });
        let expected = match damaged {
            0 => "AUTHENTICATED_MIGRATION_DURABLE_BYTES",
            1 | 2 => "AUTHENTICATED_MIGRATION_MARKER",
            _ => "AUTHENTICATED_MIGRATION_SOURCE_CHANGED",
        };
        assert_eq!(result.unwrap_err().to_string(), expected);
        assert_pending(&target);
        if damaged == 3 {
            let mut file = OpenOptions::new().write(true).open(&source_path).unwrap();
            file.write_all(&source_bytes).unwrap();
            file.sync_all().unwrap();
        }
        assert_eq!(fs::read(&source_path).unwrap(), source_bytes);
        assert_eq!(node.read_active().unwrap().0, node.settings.genesis());
    }
}

#[test]
fn authenticated_migration_process_exit_leaves_pending_and_source_reopens() {
    const CHILD: &str = "TRNM_AUTHENTICATED_MIGRATION_CRASH_CHILD";
    if let Some(root) = std::env::var_os(CHILD) {
        let root = PathBuf::from(root);
        let node = Node::open(&root.join("source"), settings(), 1).unwrap();
        let cut: u8 = std::env::var("TRNM_AUTHENTICATED_MIGRATION_CRASH_CUT")
            .unwrap()
            .parse()
            .unwrap();
        let _ = node.migrate_to_authenticated_state_with_progress(&root.join("target"), &|point| {
            if matches!(
                (cut, point),
                (0, AuthenticatedMigrationProgress::BeforeCommit)
                    | (1, AuthenticatedMigrationProgress::Committed)
                    | (2, AuthenticatedMigrationProgress::BeforePublish)
                    | (3, AuthenticatedMigrationProgress::BeforeTargetVisible)
                    | (4, AuthenticatedMigrationProgress::TargetCreated)
            ) {
                std::process::exit(87);
            }
            Ok(())
        });
        panic!("migration crash point was not reached");
    }
    for cut in 0..5 {
        let dir = tempfile::tempdir().unwrap();
        let mut source = Node::open(&dir.path().join("source"), settings(), 1).unwrap();
        let genesis = source.settings.genesis();
        let tx = transfer(source.settings(), 1, 1, 1);
        let id = admit(&mut source, genesis, 1, 0, vec![tx]);
        source.activate(id).unwrap();
        let before = logical_rows(&source.db);
        let active = source.read_active().unwrap();
        drop(source);
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("store::authenticated_migration::tests::authenticated_migration_process_exit_leaves_pending_and_source_reopens")
            .arg("--nocapture").env(CHILD, dir.path())
            .env("TRNM_AUTHENTICATED_MIGRATION_CRASH_CUT", cut.to_string())
            .status().unwrap();
        assert_eq!(status.code(), Some(87));
        if cut == 3 {
            assert!(!dir.path().join("target").exists());
            let staging: Vec<_> = fs::read_dir(dir.path())
                .unwrap()
                .filter_map(|entry| {
                    let entry = entry.unwrap();
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with("native-authenticated-migration-staging-")
                        .then(|| entry.path())
                })
                .collect();
            assert_eq!(staging.len(), 1);
            assert_pending(&staging[0]);
        } else {
            assert_pending(&dir.path().join("target"));
        }
        let reopened = Node::open(&dir.path().join("source"), settings(), 1).unwrap();
        assert_eq!(reopened.read_active().unwrap(), active);
        assert_eq!(logical_rows(&reopened.db), before);
        let completed = reopened
            .migrate_to_authenticated_state(&dir.path().join("retry-fresh"))
            .unwrap();
        assert_eq!(completed.replayed_blocks, 1);
    }
}
