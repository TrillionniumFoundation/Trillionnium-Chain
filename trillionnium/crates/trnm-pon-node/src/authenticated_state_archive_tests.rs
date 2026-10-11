use super::*;
use crate::account_archive_execution::{obligations, state_witness::StateWitness};
use crate::account_archive_prototype::{
    Checkpoint as AccountCheckpoint, Limits as AccountLimits, Witness,
};
use crate::{development_public, Settings};
use rusqlite::params;
use serde_json::json;
use std::path::PathBuf;
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::{continuity_v1, pon_executor};
use trnm_protocol::pon_wire::Envelope;

fn public(owner: u64) -> Hash {
    development_public(owner).unwrap()
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
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0u64.to_le_bytes()]))).unwrap();
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}
fn rows(path: &Path) -> Vec<String> {
    Connection::open(path)
        .unwrap()
        .prepare(
            "SELECT 'meta:'||key||':'||hex(value) FROM authenticated_meta
             UNION ALL SELECT 'cp:'||hex(id)||':'||hex(branch)||':'||coalesce(hex(parent),'')||':'||height||':'||hex(data) FROM authenticated_checkpoints
             UNION ALL SELECT 'delta:'||hex(checkpoint)||':'||ordinal||':'||hex(data) FROM authenticated_deltas
             UNION ALL SELECT 'snapshot:'||hex(checkpoint)||':'||hex(data) FROM authenticated_snapshots
             UNION ALL SELECT 'active:'||singleton||':'||hex(checkpoint)||':'||generation FROM authenticated_active ORDER BY 1",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(|row| row.unwrap())
        .collect()
}
fn account_rows(path: &Path) -> Vec<String> {
    Connection::open(path)
        .unwrap()
        .prepare(
            "SELECT 'meta:'||key||':'||hex(value) FROM archive_meta
             UNION ALL SELECT 'node:'||hex(id)||':'||hex(data) FROM archive_nodes
             UNION ALL SELECT 'cp:'||hex(id)||':'||hex(branch)||':'||hex(data) FROM archive_checkpoints
             UNION ALL SELECT 'active:'||singleton||':'||hex(checkpoint)||':'||generation FROM archive_active ORDER BY 1",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(|row| row.unwrap())
        .collect()
}
fn copy_database(source: &Path, target: &Path) {
    Connection::open(source)
        .unwrap()
        .execute("VACUUM INTO ?", [target.to_str().unwrap()])
        .unwrap();
}
struct Evidence {
    accounts: Vec<Witness>,
    state: StateWitness,
}
impl Evidence {
    fn input(&self) -> StateExecutionInput<'_> {
        StateExecutionInput {
            accounts: &self.accounts,
            state: &self.state,
        }
    }
}
struct Fixture {
    dir: tempfile::TempDir,
    path: PathBuf,
    account_path: PathBuf,
    node: Node,
    account: AccountArchive,
    archive: AuthenticatedStateArchive,
    genesis: Checkpoint,
    account_genesis: AccountCheckpoint,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authenticated-state.sqlite");
        let account_path = dir.path().join("account.sqlite");
        let settings = Settings::development_with_profiles(
            Some(1),
            "native-public-evaluation-dev-v1",
            continuity_v1::PROFILE,
        )
        .unwrap();
        let node = Node::open(&dir.path().join("node"), settings, 4).unwrap();
        let state = node.state_at(node.settings().genesis()).unwrap();
        let mut account =
            AccountArchive::open(&account_path, context(&node), AccountLimits::default()).unwrap();
        let account_genesis = account
            .project_initial(&state, pon_executor::root(&state).unwrap())
            .unwrap();
        let mut archive = AuthenticatedStateArchive::open(&path, &node, Limits::default()).unwrap();
        let genesis = archive
            .import_genesis(
                &node,
                &account,
                account_genesis.id(),
                Selection::Activate { expected: None },
            )
            .unwrap();
        Self {
            dir,
            path,
            account_path,
            node,
            account,
            archive,
            genesis,
            account_genesis,
        }
    }
    fn child(&mut self, parent: &Checkpoint, nonce: u64, recipient: u64, amount: u64) -> Hash {
        let tx = transfer(self.node.settings(), nonce, recipient, amount);
        let packet = self
            .node
            .make_consensus_maintenance(
                parent.branch(),
                vec![tx],
                public(7),
                1 + (parent.height() + 1) * 10,
                4096,
            )
            .unwrap();
        self.node.admit(&packet, 100_000).unwrap()
    }
    fn evidence(&self, parent: &AccountCheckpoint, child: Hash) -> Evidence {
        let packet = self.node.packet(child).unwrap();
        let state = self.node.state_at(parent.branch()).unwrap();
        let accounts = obligations::prepare(
            self.node.settings(),
            &self.account,
            parent.id(),
            &state,
            BlockInput {
                transactions: &packet.transactions,
                height: packet.header.height,
                miner: packet.header.miner,
                parent_id: packet.header.parent,
            },
        )
        .unwrap()
        .accounts;
        let state = account_archive_execution::prepare_state_witness(
            self.node.settings(),
            &self.account,
            parent.id(),
            &state,
        )
        .unwrap();
        Evidence { accounts, state }
    }
    fn account_child(&mut self, parent: &AccountCheckpoint, child: Hash) -> AccountCheckpoint {
        self.account
            .project_successor(
                parent.id(),
                &self.node.state_at(parent.branch()).unwrap(),
                &self.node.state_at(child).unwrap(),
                child,
                parent.height() + 1,
                &mut || Ok(()),
            )
            .unwrap()
    }
    fn publish(
        &mut self,
        parent: &Checkpoint,
        account: &AccountCheckpoint,
        child: Hash,
    ) -> Checkpoint {
        let evidence = self.evidence(account, child);
        self.archive
            .publish(
                &self.node,
                &self.account,
                PublishInput {
                    parent: parent.id(),
                    child,
                    archive_parent: account.id(),
                    evidence: evidence.input(),
                    selection: Selection::Activate {
                        expected: self.archive.active().unwrap(),
                    },
                },
            )
            .unwrap()
    }
}

#[test]
fn authenticated_archive_import_binds_actual_genesis_and_fresh_namespace() {
    let f = Fixture::new();
    let unchanged = rows(&f.path);
    let (checkpoint, state) = f.archive.read(&f.node, f.genesis.id()).unwrap();
    assert_eq!(checkpoint, f.genesis);
    assert_eq!(state, f.node.state_at(f.node.settings().genesis()).unwrap());
    assert_eq!(f.archive.observation().unwrap().snapshot_rows, 1);
    assert_eq!(f.archive.observation().unwrap().delta_rows, 0);
    assert!(matches!(
        AuthenticatedStateArchive::open(&f.account_path, &f.node, Limits::default()),
        Err(Error::Context)
    ));
    let foreign = Node::open(
        &f.dir.path().join("foreign"),
        Settings::development(Some(2)).unwrap(),
        1,
    )
    .unwrap();
    assert!(matches!(
        AuthenticatedStateArchive::open(&f.path, &foreign, Limits::default()),
        Err(Error::Context)
    ));
    let mut other = AuthenticatedStateArchive::open(&f.path, &f.node, Limits::default()).unwrap();
    assert!(matches!(
        other.import_genesis(
            &f.node,
            &f.account,
            f.account_genesis.id(),
            Selection::Inactive
        ),
        Err(Error::Conflict)
    ));
    assert_eq!(rows(&f.path), unchanged);

    let fresh = f.dir.path().join("cancelled-import.sqlite");
    let mut cancelled =
        AuthenticatedStateArchive::open(&fresh, &f.node, Limits::default()).unwrap();
    let empty = rows(&fresh);
    assert!(matches!(
        cancelled.import_genesis_with_progress(
            &f.node,
            &f.account,
            f.account_genesis.id(),
            Selection::Activate { expected: None },
            &|p| p != Progress::BeforeCommit,
        ),
        Err(Error::Cancelled)
    ));
    assert_eq!(rows(&fresh), empty);
    assert_eq!(cancelled.active().unwrap(), None);
    let sql = Connection::open(&fresh).unwrap();
    sql.execute_batch(
        "CREATE TRIGGER ignore_selection BEFORE INSERT ON authenticated_active
         BEGIN SELECT RAISE(IGNORE); END;",
    )
    .unwrap();
    assert!(matches!(
        cancelled.import_genesis(
            &f.node,
            &f.account,
            f.account_genesis.id(),
            Selection::Activate { expected: None },
        ),
        Err(Error::CorruptRecord)
    ));
    assert_eq!(rows(&fresh), empty);
}

#[test]
fn authenticated_archive_publication_rolls_back_cancellation_sql_failure_and_quotas() {
    let mut f = Fixture::new();
    let parent = f.genesis.clone();
    let child = f.child(&parent, 1, 1, 1000);
    let evidence = f.evidence(&f.account_genesis, child);
    let expected = f.archive.active().unwrap();
    let input = PublishInput {
        parent: parent.id(),
        child,
        archive_parent: f.account_genesis.id(),
        evidence: evidence.input(),
        selection: Selection::Activate { expected },
    };
    let original = rows(&f.path);
    let original_accounts = account_rows(&f.account_path);
    let original_node = f.node.read_active().unwrap();
    for stop in [
        Progress::BeforeNativeBinding,
        Progress::Execution(StateWitnessProgress::BeforeBinding),
        Progress::Execution(StateWitnessProgress::BeforeOutput),
        Progress::BeforeTransaction,
        Progress::AfterBegin,
        Progress::DeltaWritten { index: 0 },
        Progress::CheckpointWritten,
        Progress::SelectionWritten,
        Progress::BeforeCommit,
    ] {
        assert!(
            matches!(
                f.archive
                    .publish_with_progress(&f.node, &f.account, input, &|p| p != stop),
                Err(Error::Cancelled)
            ),
            "{stop:?}"
        );
        assert_eq!(rows(&f.path), original, "{stop:?}");
        assert_eq!(account_rows(&f.account_path), original_accounts);
        assert_eq!(f.node.read_active().unwrap(), original_node);
    }
    let sql = Connection::open(&f.path).unwrap();
    sql.execute_batch(
        "CREATE TRIGGER fail_checkpoint BEFORE INSERT ON authenticated_checkpoints
         BEGIN SELECT RAISE(ABORT,'injected checkpoint write failure'); END;",
    )
    .unwrap();
    assert!(matches!(
        f.archive.publish(&f.node, &f.account, input),
        Err(Error::Storage(_))
    ));
    assert_eq!(rows(&f.path), original);
    sql.execute_batch("DROP TRIGGER fail_checkpoint;").unwrap();
    sql.execute_batch(
        "CREATE TRIGGER ignore_selection BEFORE UPDATE ON authenticated_active
         BEGIN SELECT RAISE(IGNORE); END;",
    )
    .unwrap();
    assert!(matches!(
        f.archive.publish(&f.node, &f.account, input),
        Err(Error::CorruptRecord)
    ));
    assert_eq!(rows(&f.path), original);
    sql.execute_batch("DROP TRIGGER ignore_selection;").unwrap();
    sql.execute_batch(
        "CREATE TRIGGER delete_anchor AFTER UPDATE ON authenticated_active
         BEGIN DELETE FROM authenticated_snapshots; END;",
    )
    .unwrap();
    assert!(matches!(
        f.archive.publish(&f.node, &f.account, input),
        Err(Error::CorruptRecord)
    ));
    assert_eq!(rows(&f.path), original);
    sql.execute_batch("DROP TRIGGER delete_anchor;").unwrap();
    for limits in [
        Limits {
            max_history: 1,
            ..Limits::default()
        },
        Limits {
            max_checkpoints: 1,
            ..Limits::default()
        },
        Limits {
            max_delta_rows: 1,
            ..Limits::default()
        },
        Limits {
            max_payload_bytes: f.archive.observation().unwrap().payload_bytes + 1,
            ..Limits::default()
        },
    ] {
        let mut bounded = AuthenticatedStateArchive::open(&f.path, &f.node, limits).unwrap();
        assert!(matches!(
            bounded.publish(&f.node, &f.account, input),
            Err(Error::Budget)
        ));
        assert_eq!(rows(&f.path), original);
        drop(bounded);
        let reopened = AuthenticatedStateArchive::open(&f.path, &f.node, limits).unwrap();
        assert_eq!(reopened.active().unwrap(), expected);
        assert_eq!(
            reopened.read(&f.node, parent.id()).unwrap().1,
            original_node.2
        );
    }
    let checkpoint = f.archive.publish(&f.node, &f.account, input).unwrap();
    assert_eq!(
        f.archive.read(&f.node, checkpoint.id()).unwrap().1,
        f.node.state_at(child).unwrap()
    );
    assert_eq!(account_rows(&f.account_path), original_accounts);
    assert_eq!(f.node.read_active().unwrap(), original_node);
}

#[test]
fn authenticated_archive_signed_native_branches_reopen_and_monotonic_selection() {
    let mut f = Fixture::new();
    let genesis = f.genesis.clone();
    let account_genesis = f.account_genesis.clone();
    let genesis_active = f.archive.active().unwrap();
    let mut operations = vec![json!({"kind":"publish","checkpoint":genesis.id(),
                                    "active_before":null,"active_after":genesis_active})];
    let a = f.child(&genesis, 1, 1, 1000);
    let a_checkpoint = f.publish(&genesis, &account_genesis, a);
    let a_active = f.archive.active().unwrap();
    operations.push(json!({"kind":"publish","checkpoint":a_checkpoint.id(),
                           "active_before":genesis_active,"active_after":a_active}));
    let account_a = f.account_child(&account_genesis, a);
    let a2 = f.child(&a_checkpoint, 2, 2, 500);
    let a2_checkpoint = f.publish(&a_checkpoint, &account_a, a2);
    let a2_selection = f.archive.active().unwrap().unwrap();
    operations.push(json!({"kind":"publish","checkpoint":a2_checkpoint.id(),
                           "active_before":a_active,"active_after":a2_selection}));
    assert_eq!(a2_selection.generation, 3);
    let b = f.child(&genesis, 1, 3, 700);
    let evidence = f.evidence(&account_genesis, b);
    let original = rows(&f.path);
    let stale = Some(ActiveCheckpoint {
        checkpoint: genesis.id(),
        generation: 1,
    });
    assert!(matches!(
        f.archive.publish(
            &f.node,
            &f.account,
            PublishInput {
                parent: genesis.id(),
                child: b,
                archive_parent: account_genesis.id(),
                evidence: evidence.input(),
                selection: Selection::Activate { expected: stale },
            }
        ),
        Err(Error::StaleActive)
    ));
    assert_eq!(rows(&f.path), original);
    let b_checkpoint = f
        .archive
        .publish(
            &f.node,
            &f.account,
            PublishInput {
                parent: genesis.id(),
                child: b,
                archive_parent: account_genesis.id(),
                evidence: evidence.input(),
                selection: Selection::Inactive,
            },
        )
        .unwrap();
    operations.push(json!({"kind":"publish","checkpoint":b_checkpoint.id(),
                           "active_before":a2_selection,"active_after":a2_selection}));
    assert_eq!(f.archive.active().unwrap(), Some(a2_selection));
    let before_selection = rows(&f.path);
    let sql = Connection::open(&f.path).unwrap();
    sql.execute_batch(
        "CREATE TRIGGER delete_anchor AFTER UPDATE ON authenticated_active
         BEGIN DELETE FROM authenticated_snapshots; END;",
    )
    .unwrap();
    assert!(matches!(
        f.archive
            .activate(&f.node, Some(a2_selection), b_checkpoint.id()),
        Err(Error::CorruptRecord)
    ));
    assert_eq!(rows(&f.path), before_selection);
    sql.execute_batch("DROP TRIGGER delete_anchor;").unwrap();
    assert!(matches!(
        f.archive
            .activate_with_progress(&f.node, Some(a2_selection), b_checkpoint.id(), &|p| p
                != Progress::BeforeCommit,),
        Err(Error::Cancelled)
    ));
    assert_eq!(rows(&f.path), before_selection);
    let b_selection = f
        .archive
        .activate(&f.node, Some(a2_selection), b_checkpoint.id())
        .unwrap();
    operations.push(json!({"kind":"activate","checkpoint":b_checkpoint.id(),
                           "active_before":a2_selection,"active_after":b_selection}));
    assert_eq!(b_selection.generation, 4);
    assert!(matches!(
        f.archive
            .activate(&f.node, Some(a2_selection), a2_checkpoint.id()),
        Err(Error::StaleActive)
    ));
    let genesis_selection = f
        .archive
        .activate(&f.node, Some(b_selection), genesis.id())
        .unwrap();
    operations.push(json!({"kind":"activate","checkpoint":genesis.id(),
                           "active_before":b_selection,"active_after":genesis_selection}));
    assert_eq!(genesis_selection.generation, 5);
    let restored = f
        .archive
        .activate(&f.node, Some(genesis_selection), a2_checkpoint.id())
        .unwrap();
    operations.push(json!({"kind":"activate","checkpoint":a2_checkpoint.id(),
                           "active_before":genesis_selection,"active_after":restored}));
    assert_eq!(restored.generation, 6);
    for checkpoint in [&genesis, &a_checkpoint, &a2_checkpoint, &b_checkpoint] {
        assert_eq!(
            f.archive.read(&f.node, checkpoint.id()).unwrap().1,
            f.node.state_at(checkpoint.branch()).unwrap()
        );
    }
    // Changing the sidecar branch has not changed Node's selected genesis or
    // the separately owned account archive's own selection.
    assert_eq!(f.node.active().unwrap().0, genesis.branch());
    assert_eq!(f.account.active().unwrap(), None);
    let reopened = AuthenticatedStateArchive::open(&f.path, &f.node, Limits::default()).unwrap();
    assert_eq!(reopened.active().unwrap(), Some(restored));
    assert_eq!(
        reopened.read_active(&f.node).unwrap().unwrap().1,
        f.node.state_at(a2).unwrap()
    );
    assert_eq!(reopened.observation().unwrap().checkpoint_rows, 4);
    assert_eq!(reopened.observation().unwrap().snapshot_rows, 1);
    assert_eq!(
        reopened.observation().unwrap().delta_rows,
        a_checkpoint.delta_count() + a2_checkpoint.delta_count() + b_checkpoint.delta_count()
    );
    export_success(
        &f,
        &[genesis, a_checkpoint, a2_checkpoint, b_checkpoint],
        &operations,
    );
}

fn export_success(f: &Fixture, checkpoints: &[Checkpoint], operations: &[Value]) {
    let Some(path) = std::env::var_os("TRNM_AUTHENTICATED_STATE_VECTORS") else {
        return;
    };
    let path = PathBuf::from(path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    let database = path.with_extension("sqlite");
    assert!(
        !path.exists() && !database.exists(),
        "fresh artifact paths required"
    );
    copy_database(&f.path, &database);
    let native: Vec<_> = checkpoints
        .iter()
        .map(|checkpoint| {
            let packet = (checkpoint.height() > 0).then(|| {
                hex::encode(
                    f.node
                        .packet(checkpoint.branch())
                        .unwrap()
                        .encode()
                        .unwrap(),
                )
            });
            let archive_parent = checkpoint
                .record
                .execution
                .as_ref()
                .map_or(f.account_genesis.id(), |execution| execution.archive_parent);
            json!({
                "checkpoint": checkpoint,
                "state": f.node.state_at(checkpoint.branch()).unwrap(),
                "packet_hex": packet,
                "archive_parent_checkpoint": f.account.checkpoint(archive_parent).unwrap(),
            })
        })
        .collect();
    let artifact = json!({
        "schema": "pon-authenticated-state-archive-native-observation-v1",
        "database": database.file_name().unwrap().to_str().unwrap(),
        "genesis_timestamp": f.node.settings().genesis_time(),
        "context": context(&f.node), "limits": Limits::default(),
        "checkpoints": native, "operations": operations,
        "final_active": f.archive.active().unwrap(),
        "final_observation": f.archive.observation().unwrap(),
        "reopened": true,
        "scope": {
            "native_active": f.node.active().unwrap().0,
            "account_archive_active": f.account.active().unwrap(),
            "complete_native_execution": true, "full_state_reference": true,
            "node_backend_changed": false, "production_qualification": false,
        },
    });
    std::fs::write(path, serde_json::to_vec_pretty(&artifact).unwrap()).unwrap();
}

#[test]
fn authenticated_archive_rejects_missing_tampered_and_forged_stored_sources() {
    let mut f = Fixture::new();
    let genesis = f.genesis.clone();
    let account_genesis = f.account_genesis.clone();
    let child = f.child(&genesis, 1, 1, 1000);
    let child = f.publish(&genesis, &account_genesis, child);
    for (name, sql) in [
        ("missing-delta", "DELETE FROM authenticated_deltas WHERE ordinal=0"),
        ("tampered-delta", "UPDATE authenticated_deltas SET data=x'7b7d' WHERE ordinal=0"),
        ("reordered-delta", "UPDATE authenticated_deltas SET ordinal=ordinal+1000"),
        ("missing-genesis", "DELETE FROM authenticated_snapshots"),
        ("tampered-genesis", "UPDATE authenticated_snapshots SET data=x'7b7d'"),
        ("tampered-checkpoint", "UPDATE authenticated_checkpoints SET data=x'7b7d' WHERE height=1"),
        ("foreign-schema", "UPDATE authenticated_meta SET value=x'666f726569676e' WHERE key='schema'"),
        ("missing-parent", "DELETE FROM authenticated_checkpoints WHERE height=0"),
        ("orphan-delta", "UPDATE authenticated_deltas SET checkpoint=zeroblob(32) WHERE ordinal=0"),
        ("negative-generation", "UPDATE authenticated_active SET generation=-1"),
        ("duplicate-active", "PRAGMA ignore_check_constraints=ON; INSERT INTO authenticated_active(singleton,checkpoint,generation) SELECT 2,checkpoint,generation FROM authenticated_active"),
    ] {
        let path = f.dir.path().join(format!("{name}.sqlite"));
        copy_database(&f.path, &path);
        Connection::open(&path).unwrap().execute_batch(sql).unwrap();
        assert!(AuthenticatedStateArchive::open(&path, &f.node, Limits::default()).is_err(), "{name}");
    }
    // A coherent checkpoint hash cannot turn forged sums into authority. The
    // actual native state/aggregate comparison must still reject on reopen.
    let path = f.dir.path().join("forged-aggregate.sqlite");
    copy_database(&f.path, &path);
    let mut record = child.record.clone();
    record.commitment.account_balance += 1;
    record.commitment.issued += 1;
    record.id = record.digest().unwrap();
    let db = Connection::open(&path).unwrap();
    db.execute(
        "UPDATE authenticated_checkpoints SET id=?,data=? WHERE id=?",
        params![
            record.id.as_slice(),
            encode(&record).unwrap(),
            child.id().as_slice()
        ],
    )
    .unwrap();
    db.execute(
        "UPDATE authenticated_deltas SET checkpoint=? WHERE checkpoint=?",
        params![record.id.as_slice(), child.id().as_slice()],
    )
    .unwrap();
    db.execute(
        "UPDATE authenticated_active SET checkpoint=?",
        [record.id.as_slice()],
    )
    .unwrap();
    assert!(matches!(
        AuthenticatedStateArchive::open(&path, &f.node, Limits::default()),
        Err(Error::CorruptRecord)
    ));

    let path = f.dir.path().join("changed-after-read.sqlite");
    copy_database(&f.path, &path);
    let mut changed = AuthenticatedStateArchive::open(&path, &f.node, Limits::default()).unwrap();
    let expected = changed.active().unwrap();
    assert!(matches!(
        changed.activate_with_progress(&f.node, expected, child.id(), &|point| {
            if point == Progress::BeforeTransaction {
                Connection::open(&path)
                    .unwrap()
                    .execute("DELETE FROM authenticated_snapshots", [])
                    .unwrap();
            }
            true
        },),
        Err(Error::CorruptRecord)
    ));
    assert_eq!(changed.active().unwrap(), expected);
}

#[derive(Serialize, Deserialize)]
struct CrashInput {
    context: Context,
    source: PathBuf,
    target: PathBuf,
    checkpoint: Hash,
    expected: (Hash, u64),
}

#[test]
fn authenticated_archive_abrupt_exit_before_commit_recovers_original_selection() {
    // Exiting the child skips every Rust/SQLite destructor, leaving the OS to
    // close an uncommitted write transaction. The child never opens Node.
    if let Some(path) = std::env::var_os("TRNM_AUTHENTICATED_STATE_CRASH_INPUT") {
        let input: CrashInput = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let source = Database::open(&input.source, input.context, Limits::default()).unwrap();
        let loaded = source
            .read(|db| storage::load(db, input.context, input.checkpoint))
            .unwrap();
        let parent = source
            .read(|db| storage::load_record(db, input.context, loaded.record.parent.unwrap()))
            .unwrap();
        let mut target = Database::open(&input.target, input.context, Limits::default()).unwrap();
        target
            .publish(
                Prepared {
                    record: loaded.record,
                    deltas: loaded.deltas,
                    snapshot: loaded.snapshot,
                },
                Some(&parent),
                Selection::Activate {
                    expected: Some(ActiveCheckpoint {
                        checkpoint: input.expected.0,
                        generation: input.expected.1,
                    }),
                },
                &|point| {
                    if point == Progress::BeforeCommit {
                        std::process::exit(87);
                    }
                    true
                },
            )
            .unwrap();
        panic!("crash boundary did not execute");
    }
    let mut f = Fixture::new();
    let target = f.dir.path().join("abrupt-target.sqlite");
    let expected = f.archive.active().unwrap().unwrap();
    copy_database(&f.path, &target);
    let original = rows(&target);
    let genesis = f.genesis.clone();
    let account_genesis = f.account_genesis.clone();
    let child = f.child(&genesis, 1, 1, 1000);
    let checkpoint = f.publish(&genesis, &account_genesis, child);
    let input = CrashInput {
        context: context(&f.node),
        source: f.path.clone(),
        target: target.clone(),
        checkpoint: checkpoint.id(),
        expected: (expected.checkpoint, expected.generation),
    };
    let input_path = f.dir.path().join("crash-input.json");
    std::fs::write(&input_path, serde_json::to_vec(&input).unwrap()).unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "authenticated_state_archive::tests::authenticated_archive_abrupt_exit_before_commit_recovers_original_selection", "--nocapture"])
        .env("TRNM_AUTHENTICATED_STATE_CRASH_INPUT", &input_path)
        .output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(87),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let reopened = AuthenticatedStateArchive::open(&target, &f.node, Limits::default()).unwrap();
    assert_eq!(rows(&target), original);
    assert_eq!(reopened.active().unwrap(), Some(expected));
    assert_eq!(
        reopened.read_active(&f.node).unwrap().unwrap().1,
        f.node.state_at(genesis.branch()).unwrap()
    );
    assert!(matches!(
        reopened.read(&f.node, checkpoint.id()),
        Err(Error::MissingCheckpoint)
    ));
}

#[test]
fn authenticated_archive_source_and_witness_refusals_publish_no_rows() {
    let mut f = Fixture::new();
    let genesis = f.genesis.clone();
    let account_genesis = f.account_genesis.clone();
    let child = f.child(&genesis, 1, 1, 1000);
    let mut evidence = f.evidence(&account_genesis, child);
    let unchanged = rows(&f.path);
    let last = evidence.accounts.pop().unwrap();
    assert!(matches!(
        f.archive.publish(
            &f.node,
            &f.account,
            PublishInput {
                parent: genesis.id(),
                child,
                archive_parent: account_genesis.id(),
                evidence: evidence.input(),
                selection: Selection::Inactive,
            }
        ),
        Err(Error::Execution(
            CheckedExecutionError::MissingWitness { .. }
        ))
    ));
    assert_eq!(rows(&f.path), unchanged);
    evidence.accounts.push(last);
    evidence.state.commitment.account_balance += 1;
    assert!(f
        .archive
        .publish(
            &f.node,
            &f.account,
            PublishInput {
                parent: genesis.id(),
                child,
                archive_parent: account_genesis.id(),
                evidence: evidence.input(),
                selection: Selection::Inactive,
            }
        )
        .is_err());
    assert_eq!(rows(&f.path), unchanged);
    let checkpoint = f.publish(&genesis, &account_genesis, child);
    let evidence = f.evidence(&account_genesis, child);
    let unchanged = rows(&f.path);
    assert!(matches!(
        f.archive.publish(
            &f.node,
            &f.account,
            PublishInput {
                parent: checkpoint.id(),
                child,
                archive_parent: account_genesis.id(),
                evidence: evidence.input(),
                selection: Selection::Inactive,
            }
        ),
        Err(Error::Source)
    ));
    assert_eq!(rows(&f.path), unchanged);
}

#[test]
fn authenticated_archive_delta_encoding_preserves_present_null_and_exact_before() {
    let mut state = State::from([("retained:old".into(), Value::Null)]);
    let deltas = vec![
        Delta {
            key: "retained:new".into(),
            before: None,
            after: Some(StoredValue { value: Value::Null }),
        },
        Delta {
            key: "retained:old".into(),
            before: Some(StoredValue { value: Value::Null }),
            after: None,
        },
    ];
    assert_eq!(
        serde_json::to_value(&deltas[0]).unwrap(),
        json!({"key":"retained:new","before":null,"after":{"value":null}})
    );
    let encoded = encode(&deltas).unwrap();
    assert_eq!(decode::<Vec<Delta>>(&encoded).unwrap(), deltas);
    apply(&mut state, &deltas).unwrap();
    assert_eq!(state, State::from([("retained:new".into(), Value::Null)]));
    assert!(matches!(
        apply(&mut state, &deltas),
        Err(Error::CorruptRecord)
    ));
}
