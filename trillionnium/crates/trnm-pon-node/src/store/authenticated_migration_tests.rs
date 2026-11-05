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

fn transfer(settings: &Settings, account_sequence: u64, recipient: u64, amount: u64) -> Vec<u8> {
    let mut payload = public(recipient).to_vec();
    payload.extend(amount.to_le_bytes());
    let mut tx = Envelope {
        network: settings.network(),
        sender: public(0),
        nonce: account_sequence,
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

fn frame(
    node: &Node,
    session: u8,
    frame_sequence: u64,
    payload: &[u8],
) -> AuthenticatedPeerFrameV0 {
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
        frame_sequence,
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
    let migrated = Node::open_with_authenticated_state(&target, settings(), 2).unwrap();
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

    let reserved_target = fixture.dir.path().join("growth-reserved");
    let reservation = migrated
        .reserve_growth_profile_storage_v2(
            &binding,
            "authenticated-growth-v2/migrated",
            &reserved_target,
            1024 * 1024,
        )
        .unwrap();
    assert!(reservation.target_storage_reserved);
    assert!(reservation.complete_source_state_checked);
    assert!(reservation.physically_reserved_bytes >= reservation.requested_bytes);
    assert!(!reservation.capacity_sufficiency_qualified);
    assert!(!reservation.migration_executed);
    assert!(!reservation.consensus_activation);
    assert_eq!(
        fs::metadata(reserved_target.join("growth-storage-reservation.bin"))
            .unwrap()
            .len(),
        1024 * 1024
    );
    assert!(!reserved_target.join("native.sqlite").exists());
    assert_eq!(
        migrated
            .verify_growth_profile_storage_reservation_v2(
                &binding,
                "authenticated-growth-v2/migrated",
                &reserved_target,
            )
            .unwrap(),
        reservation
    );
    assert!(migrated
        .reserve_growth_profile_storage_v2(
            &binding,
            "authenticated-growth-v2/migrated",
            &reserved_target,
            1024 * 1024,
        )
        .is_err());

    let refused_target = fixture.dir.path().join("growth-refused");
    assert!(migrated
        .reserve_growth_profile_storage_v2(
            &binding,
            "authenticated-growth-v2/wrong",
            &refused_target,
            1024 * 1024,
        )
        .is_err());
    assert!(!refused_target.exists());

    // A new owner instance must revalidate the exact physical reservation and
    // current source/profile binding rather than trusting the returned value.
    drop(migrated);
    let mut migrated = Node::open_with_authenticated_state(&target, settings(), 2).unwrap();
    assert_eq!(
        migrated
            .verify_growth_profile_storage_reservation_v2(
                &binding,
                "authenticated-growth-v2/migrated",
                &reserved_target,
            )
            .unwrap(),
        reservation
    );

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
                // A genuine non-control failure leaves unfinished staging;
                // ordinary cancellation now has its own terminal lifecycle.
                Err(Error::new(ErrorCode::StoragePacket))
            } else {
                Ok(())
            }
        };
        assert!(fixture
            .node
            .activate_with_fault(fixture.branch_tip, Some(&mut stop))
            .unwrap_err()
            .is(ErrorCode::StoragePacket));
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

fn rehearsal_signed(
    settings: &Settings,
    sender: u64,
    nonce: u64,
    tag: u8,
    payload: Vec<u8>,
) -> Vec<u8> {
    let mut tx = Envelope {
        network: settings.network(),
        sender: public(sender),
        nonce,
        expiry: 2000,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    let key = signing_key_from_hex(&hex::encode(hash(
        b"DEV-ONLY-KEY",
        &[&sender.to_le_bytes()],
    )))
    .unwrap();
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}
fn rehearsal_with_obligations_and_zero_nonce() -> Fixture {
    let mut fixture = Fixture::new();
    fixture.complete_branch();
    let settings = fixture.node.settings.clone();
    let provider = public(1);
    let budget = 5_000u64;
    let deadline = 30u64;
    let task = hash(
        b"task-instance-v3",
        &[
            &settings.network(),
            &settings.parameters(),
            &public(0),
            &4u64.to_le_bytes(),
            &provider,
            &budget.to_le_bytes(),
            &deadline.to_le_bytes(),
        ],
    );
    let mut payload = task.to_vec();
    payload.extend(provider);
    payload.extend(budget.to_le_bytes());
    payload.extend(deadline.to_le_bytes());
    let reserve_task = rehearsal_signed(&settings, 0, 4, 2, payload);
    let units = 2u64;
    let consumer = public(2);
    let quota = hash(
        b"quota-instance-v3",
        &[
            &settings.network(),
            &settings.parameters(),
            &public(0),
            &5u64.to_le_bytes(),
            &consumer,
            &provider,
            &units.to_le_bytes(),
            &deadline.to_le_bytes(),
        ],
    );
    let mut payload = quota.to_vec();
    payload.extend(consumer);
    payload.extend(provider);
    payload.extend(units.to_le_bytes());
    payload.extend(deadline.to_le_bytes());
    let reserve_quota = rehearsal_signed(&settings, 0, 5, 10, payload);
    let parent = fixture.node.active().unwrap().0;
    let block = admit(
        &mut fixture.node,
        parent,
        5,
        3,
        vec![reserve_task, reserve_quota],
    );
    fixture.node.activate(block).unwrap();
    let mut payload = public(4).to_vec();
    payload.extend(101u64.to_le_bytes());
    let spend = rehearsal_signed(&settings, 99, 1, 1, payload);
    let amount =
        101 + settings.app.fees[1] + spend.len() as u64 * settings.limit("byte_fee_units").unwrap();
    let fund = transfer(&settings, 6, 99, amount);
    let block = admit(&mut fixture.node, block, 6, 3, vec![fund, spend]);
    fixture.node.activate(block).unwrap();
    fixture.node.pool_reconcile().unwrap();
    fixture
}

#[test]
fn growth_rehearsal_preserves_all_native_facts_nonce_liabilities_and_cold_checkpoint() {
    use crate::account_archive_prototype::{multiproof, native_store, Context};
    let export = std::env::var_os("TRNM_GROWTH_REHEARSAL_EXPORT_DIR").map(PathBuf::from);
    if let Some(path) = &export {
        assert!(path.is_absolute());
        fs::create_dir(path).unwrap();
        fs::write(path.join("source-settings.json"),canonical(&serde_json::json!({
            "schema":"native-growth-rehearsal-fixture-input-v2","genesis_timestamp":1,
            "evaluation_profile":"native-public-evaluation-dev-v1","continuity_profile":continuity_v1::PROFILE,
            "namespace":"growth-rehearsal/checked-local-v2","source_state_in_each_archive":true,
            "production_enabled":false,"migration_executed":false,"external_journals_imported":false
        })).unwrap()).unwrap();
    }
    for authenticated in [false, true] {
        let fixture = rehearsal_with_obligations_and_zero_nonce();
        let authenticated_path = fixture.dir.path().join("authenticated-source");
        let authenticated_node = if authenticated {
            fixture
                .node
                .migrate_to_authenticated_state(&authenticated_path)
                .unwrap();
            Some(Node::open_with_authenticated_state(&authenticated_path, settings(), 1).unwrap())
        } else {
            None
        };
        let source = authenticated_node.as_ref().unwrap_or(&fixture.node);
        let before = logical_rows(&source.db);
        let files = durable_bytes(&source.directory);
        let (tip, generation, state) = source.read_active().unwrap();
        assert_eq!(
            state[&format!("account:{}", hex::encode(public(99)))],
            serde_json::json!({"balance":0,"nonce":1})
        );
        let destination = export
            .as_ref()
            .map(|p| {
                p.join(if authenticated {
                    "authenticated-source-candidate"
                } else {
                    "legacy-source-candidate"
                })
            })
            .unwrap_or_else(|| fixture.dir.path().join("candidate"));
        let receipt = source
            .rehearse_growth_migration_v2(&destination, "growth-rehearsal/checked-local-v2")
            .unwrap();
        assert_eq!(source.active().unwrap(), (tip, generation));
        assert_eq!(logical_rows(&source.db), before);
        assert_eq!(durable_bytes(&source.directory), files);
        assert_eq!(receipt.source_height, 6);
        assert_eq!(receipt.source_tip, tip);
        assert_eq!(receipt.source_generation, generation);
        assert_eq!(receipt.retained_blocks, 9);
        assert!(receipt.replayed_transactions >= 8);
        assert!(receipt.candidate_materialized && receipt.independent_cold_readback);
        assert!(
            !receipt.migration_executed
                && !receipt.consensus_activation
                && !receipt.production_enabled
                && !receipt.old_work_promoted
        );
        assert!(receipt.candidate_commitment.escrow_balance >= 5_000);
        assert!(receipt.candidate_commitment.reward_balance > 0);
        assert_eq!(
            verify_growth_rehearsal_v2(settings(), &destination).unwrap(),
            receipt
        );
        let db = Connection::open_with_flags(
            destination.join("native.sqlite"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let raw: Vec<u8> = db
            .query_row("SELECT data FROM growth_checkpoint", [], |r| r.get(0))
            .unwrap();
        let stored: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        let working: State = serde_json::from_value(stored["working"].clone()).unwrap();
        assert_eq!(
            working,
            state
                .iter()
                .filter(|(k, _)| !k.starts_with("account:"))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        );
        assert!(working
            .iter()
            .filter(|(k, _)| k.starts_with("task:") || k.starts_with("quota:"))
            .all(|(_, v)| v["deadline"] == 30));
        let accounts: native_store::Root =
            serde_json::from_value(stored["accounts"].clone()).unwrap();
        let context = Context {
            network: receipt.candidate_commitment.network,
            parameters: receipt.candidate_commitment.parameters,
            genesis: receipt.candidate_commitment.genesis,
        };
        let checkpoint = native_store::query_growth_checkpoint(
            &db,
            context,
            context.genesis,
            receipt.source_height,
            receipt.candidate_commitment.id,
            &accounts,
        )
        .unwrap();
        let (proof, _) = multiproof::from_native_database(&db, &checkpoint, &[public(99)], &|_| {
            Ok::<_, crate::account_archive_prototype::ArchiveError>(())
        })
        .unwrap();
        let checked = multiproof::CheckedMultiproof::verify(context, &checkpoint, &proof).unwrap();
        let zero = checked.account(public(99)).unwrap().unwrap();
        assert_eq!((zero.balance, zero.nonce), (0, 1));
        drop(db);
        // Existing entrypoints cannot treat this rehearsal as a runnable ledger.
        assert!(Node::open(&destination, settings(), 1).is_err());
        assert!(Node::open_with_permanent_account_growth_v2(
            &destination,
            settings()
                .with_permanent_account_growth_v2("separate-native-runtime")
                .unwrap()
        )
        .is_err());
        assert_eq!(
            verify_growth_rehearsal_v2(settings(), &destination).unwrap(),
            receipt
        );
        assert!(source
            .rehearse_growth_migration_v2(&destination, "growth-rehearsal/checked-local-v2")
            .is_err());
        assert_eq!(source.read_active().unwrap().2, state);
    }
}

#[test]
fn growth_rehearsal_rejects_inactive_source_corruption_without_publication() {
    let fixture = rehearsal_with_obligations_and_zero_nonce();
    let mut ancestors = BTreeSet::new();
    let mut tip = fixture.node.active().unwrap().0;
    loop {
        ancestors.insert(tip);
        if tip == fixture.node.settings.genesis() {
            break;
        }
        tip = fixture.node.parent(tip).unwrap();
    }
    let ids = fixture
        .node
        .db
        .prepare("SELECT id FROM blocks WHERE packet IS NOT NULL")
        .unwrap()
        .query_map([], |r| r.get::<_, Vec<u8>>(0))
        .unwrap()
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();
    let inactive = ids
        .into_iter()
        .map(|id| bytes32(id).unwrap())
        .find(|id| !ancestors.contains(id))
        .unwrap();
    let mut packet = fixture.node.packet(inactive).unwrap().encode().unwrap();
    let last = packet.len() - 1;
    packet[last] ^= 1;
    fixture
        .node
        .db
        .execute(
            "UPDATE blocks SET packet=? WHERE id=?",
            params![packet, inactive.as_slice()],
        )
        .unwrap();
    let before = durable_bytes(&fixture.node.directory);
    let destination = fixture.dir.path().join("candidate");
    assert!(fixture
        .node
        .rehearse_growth_migration_v2(&destination, "growth-rehearsal/bad-source")
        .is_err());
    assert!(!destination.exists());
    assert_eq!(durable_bytes(&fixture.node.directory), before);
}

#[test]
fn growth_rehearsal_cancel_and_late_disk_tamper_preserve_failed_stages_and_source() {
    for corrupt in [false, true] {
        let fixture = rehearsal_with_obligations_and_zero_nonce();
        let before = durable_bytes(&fixture.node.directory);
        let target = fixture.dir.path().join("candidate");
        let result = fixture.node.rehearse_growth_migration_v2_with_progress(
            &target,
            "growth-rehearsal/fault",
            &|point| {
                if !corrupt && point == GrowthRehearsalProgressV2::SourceCopied {
                    return Err("REHEARSAL_TEST_CANCEL".into());
                }
                if corrupt && point == GrowthRehearsalProgressV2::BeforePublish {
                    let stage = fs::read_dir(fixture.dir.path())?
                        .map(|e| e.map(|e| e.path()))
                        .collect::<std::result::Result<Vec<_>, _>>()?
                        .into_iter()
                        .find(|p| {
                            p.file_name()
                                .unwrap()
                                .to_string_lossy()
                                .starts_with("native-growth-rehearsal-staging-")
                        })
                        .unwrap();
                    let db = Connection::open(stage.join("native.sqlite"))?;
                    db.execute(
                        "DELETE FROM archive_nodes WHERE id=(SELECT id FROM archive_nodes LIMIT 1)",
                        [],
                    )?;
                }
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(!target.exists());
        assert_eq!(durable_bytes(&fixture.node.directory), before);
        let stages: Vec<_> = fs::read_dir(fixture.dir.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("native-growth-rehearsal-staging-")
            })
            .collect();
        assert_eq!(stages.len(), 1);
        assert!(stages[0].join("growth-rehearsal.pending").is_file());
        assert!(verify_growth_rehearsal_v2(settings(), &stages[0]).is_err());
        let retry = fixture.dir.path().join("fresh-retry");
        assert!(fixture
            .node
            .rehearse_growth_migration_v2(&retry, "growth-rehearsal/retry")
            .is_ok());
    }
}

#[test]
fn growth_rehearsal_cold_verifier_rejects_resealed_source_and_activation_claim() {
    for fake_activation in [false, true] {
        let fixture = rehearsal_with_obligations_and_zero_nonce();
        let target = fixture.dir.path().join("candidate");
        let mut receipt = fixture
            .node
            .rehearse_growth_migration_v2(&target, "growth-rehearsal/cold-adversary")
            .unwrap();
        if fake_activation {
            receipt.consensus_activation = true;
        } else {
            let db = Connection::open(target.join("source/native.sqlite")).unwrap();
            let slot = fixture.node.slot().unwrap();
            let key = format!("account:{}", hex::encode(public(99)));
            db.execute(
                "UPDATE kv SET value=? WHERE slot=? AND key=?",
                params![
                    canonical(&serde_json::json!({"balance":0,"nonce":0})).unwrap(),
                    slot,
                    key
                ],
            )
            .unwrap();
            db.close().unwrap();
            let bytes = fs::read(target.join("source/native.sqlite")).unwrap();
            receipt.source_archive_sha256 = Sha256::digest(bytes).into();
        }
        fs::write(
            target.join("growth-rehearsal.json"),
            canonical(&receipt).unwrap(),
        )
        .unwrap();
        assert!(verify_growth_rehearsal_v2(settings(), &target).is_err());
        assert_eq!(
            fixture.node.read_active().unwrap().2[&format!("account:{}", hex::encode(public(99)))]
                ["nonce"],
            1
        );
    }
}

#[test]
fn growth_rehearsal_process_exit_retains_pending_and_source_reopens() {
    const CHILD: &str = "TRNM_GROWTH_REHEARSAL_CRASH_CHILD";
    if let Ok(path) = std::env::var(CHILD) {
        let root = PathBuf::from(path);
        let mut source = Node::open(&root.join("source"), settings(), 1).unwrap();
        let genesis = source.settings.genesis();
        let block = admit(&mut source, genesis, 1, 3, vec![]);
        source.activate(block).unwrap();
        let _ = source.rehearse_growth_migration_v2_with_progress(
            &root.join("candidate"),
            "growth-rehearsal/process-cut",
            &|point| {
                if point == GrowthRehearsalProgressV2::CheckpointCommitted {
                    std::process::exit(93);
                }
                Ok(())
            },
        );
        panic!("process cut not reached");
    }
    let dir = tempfile::tempdir().unwrap();
    let status=std::process::Command::new(std::env::current_exe().unwrap())
        .args(["store::authenticated_migration::tests::growth_rehearsal_process_exit_retains_pending_and_source_reopens","--exact","--nocapture"])
        .env(CHILD,dir.path()).status().unwrap();
    assert_eq!(status.code(), Some(93));
    assert!(!dir.path().join("candidate").exists());
    let source = Node::open(&dir.path().join("source"), settings(), 1).unwrap();
    assert_eq!(source.record(source.active().unwrap().0).unwrap().height, 1);
    let stage = fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("native-growth-rehearsal-staging-")
        })
        .unwrap();
    assert!(stage.join("growth-rehearsal.pending").is_file());
    assert!(verify_growth_rehearsal_v2(settings(), &stage).is_err());
    let receipt = source
        .rehearse_growth_migration_v2(
            &dir.path().join("fresh-retry"),
            "growth-rehearsal/fresh-after-crash",
        )
        .unwrap();
    assert!(receipt.candidate_materialized && !receipt.consensus_activation);
}

#[test]
fn growth_rehearsal_late_destination_collision_keeps_pending_and_does_not_replace() {
    let fixture = rehearsal_with_obligations_and_zero_nonce();
    let before = durable_bytes(&fixture.node.directory);
    let destination = fixture.dir.path().join("racing-destination");
    let result = fixture.node.rehearse_growth_migration_v2_with_progress(
        &destination,
        "growth-rehearsal/no-replace",
        &|point| {
            if point == GrowthRehearsalProgressV2::BeforePublish {
                fs::create_dir(&destination)?;
                fs::write(
                    destination.join("other-owner.txt"),
                    b"must remain unchanged",
                )?;
            }
            Ok(())
        },
    );
    assert!(result.is_err());
    assert_eq!(
        fs::read(destination.join("other-owner.txt")).unwrap(),
        b"must remain unchanged"
    );
    assert_eq!(fs::read_dir(&destination).unwrap().count(), 1);
    assert_eq!(durable_bytes(&fixture.node.directory), before);
    let stage = fs::read_dir(fixture.dir.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("native-growth-rehearsal-staging-")
        })
        .unwrap();
    assert!(stage.join("growth-rehearsal.pending").is_file());
    assert!(verify_growth_rehearsal_v2(settings(), &stage).is_err());
}

#[test]
fn growth_rehearsal_rejects_complete_state_reference_before_creating_a_candidate() {
    let dir = tempfile::tempdir().unwrap();
    let reference = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        trnm_mvcc_fee::growth_profile_v2::PROFILE,
    )
    .unwrap();
    let source = Node::open(&dir.path().join("source"), reference, 1).unwrap();
    let before = logical_rows(&source.db);
    let files = durable_bytes(&source.directory);
    let target = dir.path().join("candidate");
    assert_eq!(
        source
            .rehearse_growth_migration_v2(&target, "growth-rehearsal/reference-refused")
            .err()
            .unwrap()
            .to_string(),
        "GROWTH_REFERENCE_MIGRATION_UNSUPPORTED"
    );
    assert!(!target.exists());
    assert_eq!(logical_rows(&source.db), before);
    assert_eq!(durable_bytes(&source.directory), files);
}

#[test]
fn growth_rehearsal_preserves_reference_budget_history_and_rejects_resealed_corruption() {
    let mut fixture = rehearsal_with_obligations_and_zero_nonce();
    let state = fixture.node.read_active().unwrap().2;
    let key = state.keys().find(|key| key.starts_with("task:")).unwrap();
    let task = crate::digest(key.strip_prefix("task:").unwrap()).unwrap();
    let request = crate::NativeBudgetRequestV1 {
        operation: [167; 32],
        subject: [168; 32],
        beneficiary: public(1),
        lane: crate::NativeBudgetLaneV1::Storage,
        source: task,
        amount: 1_000,
        source_cap: 5_000,
        resource_cap: [100, 1_000],
        resource_reservation: [40, 400],
        contribution: None,
    };
    let observed = fixture
        .node
        .reserve_native_budget_v1(request.clone())
        .unwrap();
    assert!(observed.funding_current && observed.resources_consumed.is_none());
    assert!(!observed.payment_executed && !observed.execution_authority);
    let before = logical_rows(&fixture.node.db);
    let target = fixture.dir.path().join("candidate-with-local-observations");
    let mut receipt = fixture
        .node
        .rehearse_growth_migration_v2(&target, "growth-rehearsal/local-observations")
        .unwrap();
    assert_eq!(
        verify_growth_rehearsal_v2(settings(), &target).unwrap(),
        receipt
    );
    assert!(
        !receipt.migration_executed
            && !receipt.external_journals_imported
            && !receipt.consensus_activation
    );
    let archived = Connection::open_with_flags(
        target.join("source/native.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    assert_eq!(logical_rows(&archived), before);
    archived.close().unwrap();
    assert_eq!(logical_rows(&fixture.node.db), before);

    let operation_key = format!("pon-native-budget-v1:op:{}", hex::encode(request.operation));
    fixture
        .node
        .db
        .execute("DELETE FROM metadata WHERE key=?1", [&operation_key])
        .unwrap();
    let corrupt_source = logical_rows(&fixture.node.db);
    let absent = fixture.dir.path().join("must-not-publish");
    assert_eq!(
        fixture
            .node
            .rehearse_growth_migration_v2(&absent, "growth-rehearsal/bad-local-observation")
            .err()
            .unwrap()
            .to_string(),
        "BUDGET_RECORD_SET"
    );
    assert!(!absent.exists());
    assert_eq!(logical_rows(&fixture.node.db), corrupt_source);

    // Recompute every public file/table digest after corrupting the archived
    // budget set. Independent cold verification must still check its real local
    // relation; a matching copy/receipt hash cannot authenticate these records.
    let archived = Connection::open(target.join("source/native.sqlite")).unwrap();
    archived
        .execute("DELETE FROM metadata WHERE key=?1", [&operation_key])
        .unwrap();
    let (select, columns) = ordered_select(&archived, "metadata").unwrap();
    let mut statement = archived.prepare(&select).unwrap();
    let mut rows = statement.query([]).unwrap();
    let mut digest = Sha256::new();
    digest.update(b"native-growth-rehearsal-table-v2\0");
    digest.update(("metadata".len() as u64).to_le_bytes());
    digest.update(b"metadata");
    let mut count = 0u64;
    while let Some(row) = rows.next().unwrap() {
        hash_values(&mut digest, &values(row, columns).unwrap());
        count += 1;
    }
    digest.update(count.to_le_bytes());
    let table = receipt
        .source_tables
        .iter_mut()
        .find(|table| table.table == "metadata")
        .unwrap();
    table.rows = count;
    table.digest = digest.finalize().into();
    drop(rows);
    drop(statement);
    archived.close().unwrap();
    receipt.source_archive_sha256 =
        Sha256::digest(fs::read(target.join("source/native.sqlite")).unwrap()).into();
    fs::write(
        target.join("growth-rehearsal.json"),
        canonical(&receipt).unwrap(),
    )
    .unwrap();
    assert_eq!(
        verify_growth_rehearsal_v2(settings(), &target)
            .err()
            .unwrap()
            .to_string(),
        "BUDGET_RECORD_SET"
    );
}

#[test]
fn growth_rehearsal_cold_verifier_refuses_wal_archives_without_writes() {
    fn archive_files(directory: &Path) -> BTreeMap<PathBuf, Option<Hash>> {
        let mut files = BTreeMap::new();
        for parent in [directory.to_path_buf(), directory.join("source")] {
            for entry in fs::read_dir(parent).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                let digest = if entry.file_type().unwrap().is_dir() {
                    None
                } else {
                    Some(Sha256::digest(fs::read(&path).unwrap()).into())
                };
                files.insert(path.strip_prefix(directory).unwrap().to_path_buf(), digest);
            }
        }
        files
    }
    for checkpoint in [false, true] {
        let fixture = rehearsal_with_obligations_and_zero_nonce();
        let target = fixture.dir.path().join("wal-candidate");
        let mut receipt = fixture
            .node
            .rehearse_growth_migration_v2(&target, "growth-rehearsal/wal-refusal")
            .unwrap();
        let database = if checkpoint {
            target.join("native.sqlite")
        } else {
            target.join("source/native.sqlite")
        };
        let db = Connection::open(&database).unwrap();
        let mode: String = db
            .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        db.close().unwrap();
        let bytes = fs::read(&database).unwrap();
        assert_eq!(&bytes[18..20], &[2, 2]);
        assert!(!database.with_extension("sqlite-wal").exists());
        assert!(!database.with_extension("sqlite-shm").exists());
        let digest = Sha256::digest(bytes).into();
        if checkpoint {
            receipt.checkpoint_sha256 = digest;
        } else {
            receipt.source_archive_sha256 = digest;
        }
        fs::write(
            target.join("growth-rehearsal.json"),
            canonical(&receipt).unwrap(),
        )
        .unwrap();
        let before = archive_files(&target);
        let source_before = durable_bytes(&fixture.node.directory);
        let result = verify_growth_rehearsal_v2(settings(), &target);
        assert_eq!(
            archive_files(&target),
            before,
            "cold verification must not create WAL/SHM sidecars"
        );
        assert!(
            result.is_err(),
            "a resealed WAL-mode file is not the standalone rehearsal format"
        );
        assert_eq!(durable_bytes(&fixture.node.directory), source_before);
    }
}

fn cold_rehearsal_files(directory: &Path) -> BTreeMap<PathBuf, Option<Hash>> {
    let mut files = BTreeMap::new();
    for parent in [directory.to_path_buf(), directory.join("source")] {
        for entry in fs::read_dir(parent).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let digest = if entry.file_type().unwrap().is_dir() {
                None
            } else {
                Some(Sha256::digest(fs::read(&path).unwrap()).into())
            };
            files.insert(path.strip_prefix(directory).unwrap().to_path_buf(), digest);
        }
    }
    files
}

#[test]
fn growth_rehearsal_cold_snapshot_budget_is_aggregate_and_cleans_success() {
    let fixture = rehearsal_with_obligations_and_zero_nonce();
    let target = fixture.dir.path().join("bounded-candidate");
    let receipt = fixture
        .node
        .rehearse_growth_migration_v2(&target, "growth-rehearsal/copy-budget")
        .unwrap();
    let source_before = durable_bytes(&fixture.node.directory);
    let before = cold_rehearsal_files(&target);
    let bytes = fs::metadata(target.join("source/native.sqlite"))
        .unwrap()
        .len()
        .checked_add(fs::metadata(target.join("native.sqlite")).unwrap().len())
        .unwrap();
    assert_eq!(
        verify_growth_rehearsal_v2_with_snapshot_byte_limit(settings(), &target, bytes - 1)
            .err()
            .unwrap()
            .to_string(),
        "GROWTH_REHEARSAL_SNAPSHOT_LIMIT"
    );
    assert_eq!(cold_rehearsal_files(&target), before);
    assert_eq!(durable_bytes(&fixture.node.directory), source_before);
    assert_eq!(
        verify_growth_rehearsal_v2_with_snapshot_byte_limit(settings(), &target, bytes).unwrap(),
        receipt
    );

    let mut snapshot = None;
    let actual =
        growth_rehearsal::verify_with_snapshot_hook(settings(), &target, bytes, |private| {
            assert!(!private.starts_with(&target));
            for directory in [private.to_path_buf(), private.join("source")] {
                assert_eq!(
                    fs::metadata(directory).unwrap().permissions().mode() & 0o7777,
                    0o700
                );
            }
            for file in [
                "native.sqlite",
                "owner.lock",
                "source/native.sqlite",
                "source/owner.lock",
            ] {
                assert_eq!(
                    fs::metadata(private.join(file))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o7777,
                    0o600
                );
            }
            snapshot = Some(private.to_path_buf());
            Ok(())
        })
        .unwrap();
    assert_eq!(actual, receipt);
    assert!(
        !snapshot.unwrap().exists(),
        "successful readback removes its private copy"
    );
    assert_eq!(cold_rehearsal_files(&target), before);
    assert_eq!(durable_bytes(&fixture.node.directory), source_before);
}

#[test]
fn growth_rehearsal_cold_snapshot_replays_copies_and_rejects_replaced_wal_paths() {
    for checkpoint in [false, true] {
        let fixture = rehearsal_with_obligations_and_zero_nonce();
        let target = fixture.dir.path().join("replaced-candidate");
        let receipt = fixture
            .node
            .rehearse_growth_migration_v2(&target, "growth-rehearsal/replaced-after-copy")
            .unwrap();
        let database = if checkpoint {
            target.join("native.sqlite")
        } else {
            target.join("source/native.sqlite")
        };
        let original_bytes = fs::read(&database).unwrap();
        let source_before = durable_bytes(&fixture.node.directory);
        let replacement = fixture.dir.path().join("unrelated-wal.sqlite");
        let retained = fixture.dir.path().join("retained-original.sqlite");
        let db = Connection::open(&replacement).unwrap();
        db.execute_batch("CREATE TABLE unrelated(value INTEGER);")
            .unwrap();
        let mode: String = db
            .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        db.close().unwrap();
        let replacement_bytes = fs::read(&replacement).unwrap();
        assert_eq!(&replacement_bytes[18..20], &[2, 2]);
        assert!(!replacement.with_extension("sqlite-wal").exists());
        assert!(!replacement.with_extension("sqlite-shm").exists());

        let mut snapshot = None;
        let mut after_replacement = None;
        let result = growth_rehearsal::verify_with_snapshot_hook(
            settings(),
            &target,
            DEFAULT_GROWTH_REHEARSAL_SNAPSHOT_BYTE_LIMIT_V2,
            |private| {
                // The receipt-bound copies already exist. Replacing either
                // original pathname must not redirect the subsequent SQLite opens.
                snapshot = Some(private.to_path_buf());
                fs::rename(&database, &retained)?;
                fs::rename(&replacement, &database)?;
                after_replacement = Some(cold_rehearsal_files(&target));
                Ok(())
            },
        );
        assert_eq!(
            result.err().unwrap().to_string(),
            "GROWTH_REHEARSAL_FILE_CHANGED"
        );
        assert_eq!(cold_rehearsal_files(&target), after_replacement.unwrap());
        assert_eq!(fs::read(&database).unwrap(), replacement_bytes);
        assert_eq!(fs::read(&retained).unwrap(), original_bytes);
        assert!(!database.with_extension("sqlite-wal").exists());
        assert!(!database.with_extension("sqlite-shm").exists());
        assert!(
            !snapshot.unwrap().exists(),
            "failed readback removes its private copy"
        );

        fs::rename(&database, &replacement).unwrap();
        fs::rename(&retained, &database).unwrap();
        assert_eq!(
            verify_growth_rehearsal_v2(settings(), &target).unwrap(),
            receipt
        );
        assert_eq!(durable_bytes(&fixture.node.directory), source_before);
    }
}

#[test]
fn growth_rehearsal_file_hash_bounds_append_without_hiding_corruption() {
    use growth_rehearsal::FileReadProgress;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("input");
    for bytes in [Vec::new(), b"receipt bytes".to_vec(), vec![17; 65_536]] {
        fs::write(&path, &bytes).unwrap();
        let expected: Hash = Sha256::digest(&bytes).into();
        assert_eq!(
            growth_rehearsal::file_hash_with_progress(&path, &mut |_| Ok(())).unwrap(),
            expected
        );
    }
    let initial = vec![17; 65_536];
    fs::write(&path, &initial).unwrap();
    let mut observed = None;
    let mut hashed = 0u64;
    let mut appended = false;
    let result = growth_rehearsal::file_hash_with_progress(&path, &mut |point| {
        match point {
            FileReadProgress::BeforeOpen => (),
            FileReadProgress::Observed { bytes } => observed = Some(bytes),
            FileReadProgress::Consumed { bytes } => {
                hashed = hashed.checked_add(bytes).unwrap();
                if !appended {
                    OpenOptions::new()
                        .append(true)
                        .open(&path)?
                        .write_all(&[23; 4_096])?;
                    appended = true;
                }
            }
        }
        Ok(())
    });
    assert!(
        result.is_err(),
        "a changed file must not yield an accepted digest"
    );
    assert_eq!(observed, Some(initial.len() as u64));
    assert!(appended);
    assert!(
        hashed <= initial.len() as u64,
        "file hash consumed appended bytes beyond its observed length: {hashed}"
    );
    assert_eq!(
        fs::metadata(&path).unwrap().len(),
        initial.len() as u64 + 4_096
    );
}

#[test]
fn growth_rehearsal_file_reads_refuse_fifo_replacement_before_open() {
    const CHILD: &str = "TRNM_GROWTH_REHEARSAL_READ_FIFO_CHILD";
    const MODE: &str = "TRNM_GROWTH_REHEARSAL_READ_FIFO_MODE";
    if let Some(directory) = std::env::var_os(CHILD) {
        let directory = PathBuf::from(directory);
        let receipt = std::env::var(MODE).unwrap() == "receipt";
        let name = if receipt {
            "growth-rehearsal.json"
        } else {
            "input"
        };
        let path = directory.join(name);
        fs::write(&path, b"regular before open").unwrap();
        let mut replace = |point| {
            if point == growth_rehearsal::FileReadProgress::BeforeOpen {
                fs::rename(&path, directory.join("retained"))?;
                rustix::fs::mknodat(
                    File::open(&directory)?,
                    name,
                    rustix::fs::FileType::Fifo,
                    rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                    0,
                )
                .map_err(std::io::Error::from)?;
                fs::write(directory.join("fifo-ready"), b"ready")?;
            }
            Ok(())
        };
        let result = if receipt {
            growth_rehearsal::read_receipt_with_progress(&directory, &mut replace).map(|_| ())
        } else {
            growth_rehearsal::file_hash_with_progress(&path, &mut replace).map(|_| ())
        };
        assert_eq!(result.err().unwrap().to_string(), "GROWTH_REHEARSAL_FILE");
        assert_eq!(
            fs::read(directory.join("retained")).unwrap(),
            b"regular before open"
        );
        return;
    }
    let mut failed = Vec::new();
    for mode in ["hash", "receipt"] {
        let directory = tempfile::tempdir().unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "store::authenticated_migration::tests::growth_rehearsal_file_reads_refuse_fifo_replacement_before_open",
                "--exact", "--nocapture",
            ])
            .env(CHILD, directory.path()).env(MODE, mode)
            .spawn().unwrap();
        let startup_deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut fifo_deadline = None;
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                if !status.success() {
                    failed.push(mode);
                }
                break;
            }
            let now = std::time::Instant::now();
            if fifo_deadline.is_none() && directory.path().join("fifo-ready").exists() {
                fifo_deadline = Some(now + std::time::Duration::from_secs(2));
            }
            if now >= fifo_deadline.unwrap_or(startup_deadline) {
                child.kill().unwrap();
                child.wait().unwrap();
                failed.push(mode);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(
            fs::read(directory.path().join("retained")).unwrap(),
            b"regular before open"
        );
    }
    assert!(
        failed.is_empty(),
        "file reads blocked or failed after regular-to-FIFO replacement: {failed:?}"
    );
}

#[test]
fn growth_rehearsal_file_receipt_retains_one_mib_limit() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("growth-rehearsal.json");
    fs::write(&path, vec![b' '; 1_048_577]).unwrap();
    assert_eq!(
        growth_rehearsal::read_receipt_with_progress(directory.path(), &mut |_| Ok(()))
            .err()
            .unwrap()
            .to_string(),
        "GROWTH_REHEARSAL_RECEIPT_LIMIT"
    );
    assert_eq!(fs::metadata(&path).unwrap().len(), 1_048_577);
}
