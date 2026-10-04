//! Component research fixtures. Real signed Node projections are in the sibling test.
#[path = "../examples/support/account_archive_artifact.rs"]
mod account_archive_artifact;
use account_archive_artifact::{create_working_archive_path, finish_archive_artifact, vacuum_into};
use rusqlite::{params, Connection, OpenFlags};
use serde_json::json;
use std::collections::BTreeMap;
use trnm_mvcc_fee::pon_executor::{root, State};
use trnm_pon_node::account_archive_prototype::{
    account_root, Account, AccountArchive, ArchiveError as E, CheckedAccounts, Context, Limits,
    ResearchUpdate, Witness, MAX_VIEW_ACCOUNTS, MAX_WITNESS_BYTES,
};
use trnm_protocol::pon_wire::{hash, Hash};

fn owner(n: u64) -> Hash {
    let mut out = [0; 32];
    out[..8].copy_from_slice(&n.to_le_bytes());
    out
}
fn context() -> Context {
    Context {
        network: [1; 32],
        parameters: [2; 32],
        genesis: [3; 32],
    }
}
fn values(n: u64) -> BTreeMap<Hash, Account> {
    (0..n)
        .map(|i| {
            (
                owner(i),
                Account {
                    balance: i,
                    nonce: i % 19,
                },
            )
        })
        .collect()
}
fn state(values: &BTreeMap<Hash, Account>) -> State {
    values
        .iter()
        .map(|(owner, account)| {
            (
                format!("account:{}", hex::encode(owner)),
                serde_json::to_value(account).unwrap(),
            )
        })
        .collect()
}
fn open(path: &std::path::Path) -> AccountArchive {
    AccountArchive::open(path, context(), Limits::default()).unwrap()
}

#[test]
fn compressed_nonmembership_and_bounded_views_never_erase_a_nonce() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive.sqlite");
    let mut archive = open(&path);
    let accounts = BTreeMap::from([(
        owner(1),
        Account {
            balance: 0,
            nonce: 7,
        },
    )]);
    let first = archive
        .seed_research_accounts([4; 32], &accounts, &mut || Ok(()))
        .unwrap();
    assert_eq!(first.account_root(), account_root(&accounts).unwrap());
    // These two independently supplied owners share twelve hash-path prefix bits.
    let (present, reads) = archive.witness(first.id(), owner(1)).unwrap();
    let absent = archive.witness(first.id(), owner(3800)).unwrap().0;
    assert_eq!(reads, 1);
    assert_eq!(absent.account, None);
    let view = CheckedAccounts::verify(
        context(),
        &first,
        &[owner(1), owner(3800)],
        &[present.clone(), absent.clone()],
    )
    .unwrap();
    assert_eq!(
        view.account(owner(1)).unwrap(),
        Some(Account {
            balance: 0,
            nonce: 7
        })
    );
    assert_eq!(view.check_next_nonce(owner(1), 1), Err(E::Nonce));
    assert_eq!(view.check_next_nonce(owner(1), 8), Ok(()));
    assert_eq!(view.check_next_nonce(owner(3800), 1), Ok(()));
    assert_eq!(view.account(owner(99)), Err(E::MissingWitness));
    assert_eq!(present.encode().unwrap().len(), MAX_WITNESS_BYTES);
    assert_eq!(absent.encode().unwrap().len(), MAX_WITNESS_BYTES - 16);
    for witness in [&present, &absent] {
        let bytes = witness.encode().unwrap();
        assert_eq!(&Witness::decode(&bytes).unwrap(), witness);
        assert_eq!(
            Witness::decode(&bytes[..bytes.len() - 1]),
            Err(E::InvalidWitness)
        );
        let mut extended = bytes.clone();
        extended.push(0);
        assert_eq!(Witness::decode(&extended), Err(E::InvalidWitness));
    }
    let mut malformed = Vec::new();
    let mut no_value = present.clone();
    no_value.account = None;
    malformed.push(no_value);
    let mut wrong_owner = present.clone();
    wrong_owner.owner = owner(3800);
    malformed.push(wrong_owner);
    let mut truncated = absent.clone();
    truncated.siblings.pop();
    malformed.push(truncated);
    let mut changed = absent.clone();
    changed.siblings[12][0] ^= 1;
    malformed.push(changed);
    let mut swapped = absent.clone();
    swapped.siblings.swap(0, 12);
    malformed.push(swapped);
    for witness in malformed {
        assert!(matches!(
            CheckedAccounts::verify(context(), &first, &[witness.owner], &[witness]),
            Err(E::InvalidWitness)
        ));
    }
    assert!(matches!(
        CheckedAccounts::verify(
            Context {
                genesis: [9; 32],
                ..context()
            },
            &first,
            &[owner(1)],
            std::slice::from_ref(&present)
        ),
        Err(E::Context)
    ));
    assert!(matches!(
        CheckedAccounts::verify(
            context(),
            &first,
            &[owner(1), owner(1)],
            &[present.clone(), present.clone()]
        ),
        Err(E::InvalidWitness)
    ));
    assert!(matches!(
        CheckedAccounts::verify(
            context(),
            &first,
            &[owner(1); MAX_VIEW_ACCOUNTS + 1],
            &vec![present; MAX_VIEW_ACCOUNTS + 1]
        ),
        Err(E::Budget)
    ));
    let second = archive
        .research_successor(
            first.id(),
            [5; 32],
            &[ResearchUpdate {
                owner: owner(3800),
                before: None,
                after: Account {
                    balance: 1,
                    nonce: 0,
                },
            }],
            &mut || Ok(()),
        )
        .unwrap();
    let second_witness = archive.witness(second.id(), owner(3800)).unwrap().0;
    assert_eq!(
        second_witness.account,
        Some(Account {
            balance: 1,
            nonce: 0
        })
    );
    assert!(matches!(
        CheckedAccounts::verify(context(), &second, &[owner(3800)], &[absent]),
        Err(E::InvalidWitness)
    ));
}

#[test]
fn cancellation_rolls_back_nodes_checkpoints_and_active_publication_before_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive.sqlite");
    let mut archive = open(&path);
    let initial = archive.observation().unwrap();
    let mut calls = 0;
    let failure = archive.seed_research_accounts([4; 32], &values(32), &mut || {
        calls += 1;
        if calls == 10 {
            Err(E::Cancelled)
        } else {
            Ok(())
        }
    });
    assert_eq!(failure.unwrap_err(), E::Cancelled);
    assert_eq!(calls, 10);
    assert_eq!(archive.observation().unwrap(), initial);
    assert_eq!(archive.active().unwrap(), None);
    drop(archive);
    let mut archive = open(&path);
    assert_eq!(archive.observation().unwrap(), initial);
    let first = archive
        .seed_research_accounts([4; 32], &values(32), &mut || Ok(()))
        .unwrap();
    let retained = archive.observation().unwrap();
    assert_eq!(retained.node_rows, 63);
    let update = ResearchUpdate {
        owner: owner(1),
        before: Some(Account {
            balance: 1,
            nonce: 1,
        }),
        after: Account {
            balance: 0,
            nonce: 2,
        },
    };
    let mut calls = 0;
    assert_eq!(
        archive
            .research_successor(first.id(), [5; 32], &[update], &mut || {
                calls += 1;
                if calls == 3 {
                    Err(E::Cancelled)
                } else {
                    Ok(())
                }
            })
            .unwrap_err(),
        E::Cancelled
    );
    assert_eq!(archive.observation().unwrap(), retained);
    assert_eq!(
        archive
            .activate(None, first.id(), &mut || Err(E::Cancelled))
            .unwrap_err(),
        E::Cancelled
    );
    assert_eq!(archive.active().unwrap(), None);
    drop(archive);
    let mut archive = open(&path);
    assert_eq!(archive.observation().unwrap(), retained);
    assert_eq!(archive.active().unwrap(), None);
    let active = archive.activate(None, first.id(), &mut || Ok(())).unwrap();
    assert_eq!(active.generation, 1);
}

#[test]
fn immutable_branch_checkpoints_and_compare_exchange_do_not_rewind_other_branches() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive.sqlite");
    let mut archive = open(&path);
    let first = archive
        .seed_research_accounts([4; 32], &values(4), &mut || Ok(()))
        .unwrap();
    let baseline = archive.activate(None, first.id(), &mut || Ok(())).unwrap();
    let update = |nonce| ResearchUpdate {
        owner: owner(1),
        before: Some(Account {
            balance: 1,
            nonce: 1,
        }),
        after: Account { balance: 0, nonce },
    };
    let a = archive
        .research_successor(first.id(), [5; 32], &[update(2)], &mut || Ok(()))
        .unwrap();
    let b = archive
        .research_successor(first.id(), [6; 32], &[update(3)], &mut || Ok(()))
        .unwrap();
    let retained = archive.observation().unwrap();
    assert!(retained.node_rows > 2 * first.account_count() - 1);
    let active_a = archive
        .activate(Some(baseline), a.id(), &mut || Ok(()))
        .unwrap();
    let mut second_handle = open(&path);
    assert_eq!(
        second_handle
            .activate(Some(baseline), b.id(), &mut || Ok(()))
            .unwrap_err(),
        E::StaleActive
    );
    assert_eq!(second_handle.active().unwrap(), Some(active_a));
    let active_b = second_handle
        .activate(Some(active_a), b.id(), &mut || Ok(()))
        .unwrap();
    let old = archive.witness(a.id(), owner(1)).unwrap().0;
    assert!(matches!(
        CheckedAccounts::verify(context(), &b, &[owner(1)], std::slice::from_ref(&old)),
        Err(E::InvalidWitness)
    ));
    assert_eq!(
        CheckedAccounts::verify(context(), &a, &[owner(1)], &[old])
            .unwrap()
            .account(owner(1))
            .unwrap()
            .unwrap()
            .nonce,
        2
    );
    assert_eq!(archive.observation().unwrap(), retained);
    assert_eq!(
        archive
            .activate(Some(active_b), a.id(), &mut || Ok(()))
            .unwrap()
            .generation,
        4
    );
    drop(second_handle);
    drop(archive);
    assert_eq!(open(&path).checkpoint(a.id()).unwrap(), a);
}

#[test]
fn missing_or_corrupt_required_records_are_not_nonmembership_or_successful_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive.sqlite");
    let mut archive = open(&path);
    let checkpoint = archive
        .seed_research_accounts([4; 32], &values(8), &mut || Ok(()))
        .unwrap();
    archive
        .activate(None, checkpoint.id(), &mut || Ok(()))
        .unwrap();
    let db = Connection::open(&path).unwrap();
    let (leaf_id, bytes): (Vec<u8>, Vec<u8>) = db
        .query_row(
            "SELECT id,data FROM archive_nodes WHERE length(data)=49 AND substr(data,2,32)=?",
            [owner(1).as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    db.execute("DELETE FROM archive_nodes WHERE id=?", [&leaf_id])
        .unwrap();
    assert_eq!(
        archive.witness(checkpoint.id(), owner(1)).unwrap_err(),
        E::DataUnavailable
    );
    // Open validates active metadata/root, not every untouched descendant.
    drop(archive);
    let archive = open(&path);
    assert_eq!(
        archive.witness(checkpoint.id(), owner(1)).unwrap_err(),
        E::DataUnavailable
    );
    db.execute(
        "INSERT INTO archive_nodes(id,data) VALUES(?,?)",
        params![&leaf_id, &bytes],
    )
    .unwrap();
    let mut corrupt = bytes.clone();
    corrupt[40] ^= 1;
    db.execute(
        "UPDATE archive_nodes SET data=? WHERE id=?",
        params![corrupt, &leaf_id],
    )
    .unwrap();
    assert_eq!(
        archive.witness(checkpoint.id(), owner(1)).unwrap_err(),
        E::CorruptRecord
    );
    db.execute(
        "UPDATE archive_nodes SET data=? WHERE id=?",
        params![&bytes, &leaf_id],
    )
    .unwrap();
    let observed = serde_json::to_value(&checkpoint).unwrap();
    let root_id: Vec<u8> = serde_json::from_value(observed["root_node"].clone()).unwrap();
    let root_bytes: Vec<u8> = db
        .query_row(
            "SELECT data FROM archive_nodes WHERE id=?",
            [&root_id],
            |r| r.get(0),
        )
        .unwrap();
    db.execute("DELETE FROM archive_nodes WHERE id=?", [&root_id])
        .unwrap();
    assert!(matches!(
        AccountArchive::open(&path, context(), Limits::default()),
        Err(E::DataUnavailable)
    ));
    db.execute(
        "INSERT INTO archive_nodes(id,data) VALUES(?,?)",
        params![&root_id, root_bytes],
    )
    .unwrap();
    db.execute(
        "UPDATE archive_nodes SET data=zeroblob(1000000) WHERE id=?",
        [&root_id],
    )
    .unwrap();
    assert!(matches!(
        AccountArchive::open(&path, context(), Limits::default()),
        Err(E::CorruptRecord)
    ));
}

#[test]
fn complete_projection_rejects_nonce_erasure_wrong_source_and_malformed_accounts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive.sqlite");
    let mut archive = open(&path);
    let mut before = state(&values(4));
    before
        .get_mut(&format!("account:{}", hex::encode(owner(1))))
        .unwrap()["balance"] = json!(0);
    let first = archive
        .project_initial(&before, root(&before).unwrap())
        .unwrap();
    let before_observation = archive.observation().unwrap();
    let mut removed = before.clone();
    removed.remove(&format!("account:{}", hex::encode(owner(1))));
    assert_eq!(
        archive
            .project_successor(first.id(), &before, &removed, [8; 32], 1, &mut || Ok(()))
            .unwrap_err(),
        E::InvalidTransition
    );
    let mut erased = before.clone();
    erased
        .get_mut(&format!("account:{}", hex::encode(owner(1))))
        .unwrap()["nonce"] = json!(0);
    assert_eq!(
        archive
            .project_successor(first.id(), &before, &erased, [8; 32], 1, &mut || Ok(()))
            .unwrap_err(),
        E::InvalidTransition
    );
    let mut wrong_before = before.clone();
    wrong_before.insert("unrelated".into(), json!(0));
    assert_eq!(
        archive
            .project_successor(
                first.id(),
                &wrong_before,
                &wrong_before,
                [8; 32],
                1,
                &mut || Ok(())
            )
            .unwrap_err(),
        E::SourceRoot
    );
    assert_eq!(
        archive
            .project_successor(first.id(), &before, &before, [8; 32], 2, &mut || Ok(()))
            .unwrap_err(),
        E::InvalidTransition
    );
    for value in [
        json!({"balance":0,"nonce":true}),
        json!({"balance":0,"nonce":1,"extra":0}),
        json!({"balance":-1,"nonce":0}),
    ] {
        let malformed = State::from([(format!("account:{}", hex::encode(owner(1))), value)]);
        assert_eq!(
            archive
                .project_initial(&malformed, root(&malformed).unwrap())
                .unwrap_err(),
            E::InvalidState
        );
    }
    assert_eq!(archive.observation().unwrap(), before_observation);
    let mut after = before.clone();
    after
        .get_mut(&format!("account:{}", hex::encode(owner(1))))
        .unwrap()["nonce"] = json!(2);
    let child = archive
        .project_successor(first.id(), &before, &after, [8; 32], 1, &mut || Ok(()))
        .unwrap();
    assert_eq!(child.source_state_root(), Some(root(&after).unwrap()));
    assert_eq!(
        archive
            .research_successor(first.id(), [9; 32], &[], &mut || Ok(()))
            .unwrap_err(),
        E::InvalidTransition
    );
}

#[test]
fn strict_checkpoint_identity_and_operator_budgets_reject_without_publication() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive.sqlite");
    let mut archive = open(&path);
    let first = archive
        .seed_research_accounts([4; 32], &values(4), &mut || Ok(()))
        .unwrap();
    let db = Connection::open(&path).unwrap();
    db.execute(
        "UPDATE archive_checkpoints SET id=? WHERE id=?",
        params![[8_u8; 32].as_slice(), first.id().as_slice()],
    )
    .unwrap();
    assert_eq!(
        archive
            .seed_research_accounts([4; 32], &values(4), &mut || Ok(()))
            .unwrap_err(),
        E::CorruptRecord
    );
    db.execute(
        "UPDATE archive_checkpoints SET id=? WHERE id=?",
        params![first.id().as_slice(), [8_u8; 32].as_slice()],
    )
    .unwrap();
    assert!(matches!(
        AccountArchive::open(
            &path,
            context(),
            Limits {
                max_accounts: 3,
                ..Limits::default()
            }
        ),
        Err(E::Budget)
    ));
    assert!(matches!(
        AccountArchive::open(
            &path,
            Context {
                network: [0; 32],
                ..context()
            },
            Limits::default()
        ),
        Err(E::Context)
    ));
    let limited_path = dir.path().join("limited.sqlite");
    let mut limited = AccountArchive::open(
        &limited_path,
        context(),
        Limits {
            max_node_rows: 3,
            ..Limits::default()
        },
    )
    .unwrap();
    let before = limited.observation().unwrap();
    assert_eq!(
        limited
            .seed_research_accounts([4; 32], &values(4), &mut || Ok(()))
            .unwrap_err(),
        E::Budget
    );
    assert_eq!(limited.observation().unwrap(), before);
    assert_eq!(limited.active().unwrap(), None);
}

#[test]
fn archive_artifact_refuses_busy_checkpoint_and_closes_after_reader_release() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("archive.sqlite");
    let blocked = directory.path().join("blocked");
    let closed = directory.path().join("closed");
    std::fs::create_dir(&blocked).unwrap();
    std::fs::create_dir(&closed).unwrap();
    let writer = Connection::open(&path).unwrap();
    writer.busy_timeout(std::time::Duration::ZERO).unwrap();
    writer
        .execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA wal_autocheckpoint=0; CREATE TABLE fixture(value INTEGER); INSERT INTO fixture VALUES(1);")
        .unwrap();
    let reader = Connection::open(&path).unwrap();
    reader.execute_batch("BEGIN").unwrap();
    assert_eq!(
        reader
            .query_row("SELECT COUNT(*) FROM fixture", [], |row| row
                .get::<_, u64>(0))
            .unwrap(),
        1
    );
    writer.execute("INSERT INTO fixture VALUES(2)", []).unwrap();
    assert!(finish_archive_artifact(writer, &path, &blocked).is_err());
    let refused: serde_json::Value =
        serde_json::from_slice(&std::fs::read(blocked.join("finalization.json")).unwrap()).unwrap();
    assert_eq!(refused["result"], "FAIL");
    assert_eq!(refused["source"]["checkpoint"]["busy"], 1);
    assert_eq!(
        refused["source"]["checkpoint_error"],
        serde_json::Value::Null
    );
    assert_eq!(refused["source"]["close"]["result"], "OK");
    assert!(
        refused["source"]["wal_after_close"]["bytes"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_eq!(refused["export"]["vacuum_into"]["result"], "NOT_ATTEMPTED");
    assert_eq!(refused["export"]["open"]["result"], "NOT_ATTEMPTED");
    assert!(!blocked.join("archive.sqlite").exists());
    reader.execute_batch("ROLLBACK").unwrap();
    reader.close().unwrap();
    let control = Connection::open(&path).unwrap();
    assert_eq!(
        control
            .query_row("SELECT COUNT(*) FROM fixture", [], |row| row
                .get::<_, u64>(0))
            .unwrap(),
        2
    );
    let accepted = finish_archive_artifact(control, &path, &closed).unwrap();
    assert_eq!(accepted.result, "PASS");
    assert_eq!(accepted.source.checkpoint.unwrap().busy, 0);
    assert_eq!(accepted.export.journal_mode.as_deref(), Some("delete"));
}

#[test]
fn archive_snapshot_reads_committed_wal_and_isolates_later_source_changes() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("export");
    std::fs::create_dir(&output).unwrap();
    let path = create_working_archive_path(&output).unwrap();
    let writer = Connection::open(&path).unwrap();
    writer
        .execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA wal_autocheckpoint=0; CREATE TABLE fixture(value INTEGER); INSERT INTO fixture VALUES(1);")
        .unwrap();
    let checkpoint: (i64, i64, i64) = writer
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .unwrap();
    assert_eq!(checkpoint, (0, 0, 0));
    let main_before_commit = std::fs::read(&path).unwrap();
    writer.execute("INSERT INTO fixture VALUES(2)", []).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), main_before_commit);
    assert!(
        std::fs::metadata(path.with_file_name("archive.sqlite-wal"))
            .unwrap()
            .len()
            > 0
    );
    // Exercise the actual shared VACUUM step before checkpointing this commit.
    let wal_view = path.with_file_name("uncheckpointed-view.sqlite");
    assert_eq!(vacuum_into(&writer, &wal_view).result, "OK");
    let reader = Connection::open_with_flags(&wal_view, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    assert_eq!(
        reader
            .query_row("SELECT COUNT(*) FROM fixture", [], |row| row
                .get::<_, u64>(0))
            .unwrap(),
        2
    );
    reader.close().unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), main_before_commit);

    let exported = finish_archive_artifact(writer, &path, &output).unwrap();
    assert_eq!(exported.result, "PASS");
    assert_eq!(exported.source.synchronous, Some(2));
    assert_eq!(exported.export.journal_mode.as_deref(), Some("delete"));
    let snapshot = std::fs::read(&exported.export_database).unwrap();
    let later = Connection::open(&path).unwrap();
    later.execute("INSERT INTO fixture VALUES(3)", []).unwrap();
    assert_eq!(
        later
            .query_row("SELECT COUNT(*) FROM fixture", [], |row| row
                .get::<_, u64>(0))
            .unwrap(),
        3
    );
    assert_eq!(
        vacuum_into(&later, &exported.export_database).result,
        "ERROR"
    );
    later.close().unwrap();
    let reader =
        Connection::open_with_flags(&exported.export_database, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    assert_eq!(
        reader
            .query_row("SELECT COUNT(*) FROM fixture", [], |row| row
                .get::<_, u64>(0))
            .unwrap(),
        2
    );
    reader.close().unwrap();
    assert_eq!(std::fs::read(&exported.export_database).unwrap(), snapshot);
}

#[test]
#[ignore = "explicit release-only synthetic 65,537-account archive; not ledger admission"]
fn synthetic_archive_beyond_legacy_cap_retains_nonce_and_bounds_views() -> Result<(), String> {
    if cfg!(debug_assertions) {
        return Err("run this campaign with --release".into());
    }
    let output = std::path::PathBuf::from(
        std::env::var_os("TRNM_ACCOUNT_ARCHIVE_LARGE_OUTPUT")
            .expect("explicit new artifact output directory is required"),
    );
    std::fs::create_dir(&output)
        .expect("large observation output directory must not already exist");
    let path = create_working_archive_path(&output)?;
    let mut archive = open(&path);
    let accounts = values(65_537);
    let initial = archive
        .seed_research_accounts(hash(b"archive-large-fixture", &[]), &accounts, &mut || {
            Ok(())
        })
        .unwrap();
    let initial_storage = archive.observation().unwrap();
    assert_eq!(initial.account_count(), 65_537);
    assert_eq!(initial_storage.node_rows, 131_073);
    assert_eq!(initial.source_state_root(), None);
    let requested: Vec<_> = (0..31)
        .map(|i| owner(i * 2114))
        .chain(std::iter::once(owner(100_000)))
        .collect();
    let observed: Vec<_> = requested
        .iter()
        .map(|&who| archive.witness(initial.id(), who).unwrap())
        .collect();
    let max_reads = observed.iter().map(|(_, reads)| *reads).max().unwrap();
    assert!(max_reads <= 257);
    let witnesses: Vec<_> = observed
        .iter()
        .map(|(witness, _)| witness.clone())
        .collect();
    let queries: Vec<_> = observed.iter().map(|(witness, reads)| json!({"owner":witness.owner,"witness":witness,"node_reads":reads,"binary_hex":hex::encode(witness.encode().unwrap())})).collect();
    let view = CheckedAccounts::verify(context(), &initial, &requested, &witnesses).unwrap();
    assert_eq!(view.len(), 32);
    assert_eq!(view.account(owner(100_000)).unwrap(), None);
    let update = ResearchUpdate {
        owner: owner(1),
        before: accounts.get(&owner(1)).copied(),
        after: Account {
            balance: 0,
            nonce: 2,
        },
    };
    let next = archive
        .research_successor(initial.id(), [8; 32], &[update], &mut || Ok(()))
        .unwrap();
    let next_storage = archive.observation().unwrap();
    assert!(next_storage.node_rows > initial_storage.node_rows);
    let (next_witness, next_reads) = archive.witness(next.id(), owner(1)).unwrap();
    let active = archive.activate(None, next.id(), &mut || Ok(())).unwrap();
    let view = CheckedAccounts::verify(
        context(),
        &next,
        &[owner(1)],
        std::slice::from_ref(&next_witness),
    )
    .unwrap();
    assert_eq!(view.check_next_nonce(owner(1), 2), Err(E::Nonce));
    assert_eq!(view.check_next_nonce(owner(1), 3), Ok(()));
    drop(archive);
    let reopened = open(&path);
    assert_eq!(reopened.active().unwrap(), Some(active));
    assert_eq!(
        reopened.witness(next.id(), owner(1)).unwrap().0,
        next_witness
    );
    assert_eq!(
        reopened.witness(initial.id(), owner(1)).unwrap().0.account,
        update.before
    );
    drop(reopened);
    let db = Connection::open(&path).unwrap();
    let finalization = finish_archive_artifact(db, &path, &output)?;
    let page_count = finalization.export.page_count.unwrap();
    let page_size = finalization.export.page_size.unwrap();
    let database = finalization.export_database.clone();
    let input_accounts: Vec<_> = accounts
        .iter()
        .map(|(&owner, &account)| json!({"owner":owner,"account":account}))
        .collect();
    let report = json!({"schema":"pon-account-archive-large-observation-v1","result":"PASS","context":context(),"accounts":input_accounts,"queries":queries,"update":update,"next_query":{"owner":owner(1),"witness":next_witness,"node_reads":next_reads,"binary_hex":hex::encode(next_witness.encode().unwrap())},"initial":initial,"after_update":next,"initial_storage":initial_storage,"after_update_storage":next_storage,"checked_view_accounts":32,"maximum_observed_node_reads":max_reads,"node_read_upper_bound":257,"maximum_witness_bytes":MAX_WITNESS_BYTES,"sqlite_page_count":page_count,"sqlite_page_size":page_size,"sqlite_logical_file_bytes":page_count*page_size,"reopened_active":active,"database":database,"working_database":path,"finalization":finalization,"actual_ledger_account_growth":false,"protocol_capacity_changed":false,"data_availability_accepted":false,"production_accepted":false});
    std::fs::write(
        output.join("observation.json"),
        serde_json::to_vec(&report).unwrap(),
    )
    .unwrap();
    println!(
        "{}",
        json!({"schema":"pon-account-archive-large-artifact-v1","result":"PASS","directory":output,"initial_accounts":65_537,"initial_root":initial.account_root(),"after_update_root":next.account_root(),"initial_storage":initial_storage,"after_update_storage":next_storage,"maximum_observed_node_reads":max_reads,"protocol_capacity_changed":false,"actual_ledger_account_growth":false})
    );
    Ok(())
}
