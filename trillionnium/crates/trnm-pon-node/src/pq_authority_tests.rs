use super::*;
use std::sync::{Arc, Barrier};

const KEY: &[u8] = include_bytes!("../tests/fixtures/pq/public.der");
const FIRST: &[u8] = include_bytes!("../tests/fixtures/pq/operation1.bin");
const FIRST_RANDOMIZED: &[u8] = include_bytes!("../tests/fixtures/pq/operation1_randomized.bin");
const SECOND: &[u8] = include_bytes!("../tests/fixtures/pq/operation2.bin");
const THIRD: &[u8] = include_bytes!("../tests/fixtures/pq/operation3.bin");
const PAYLOAD: &[u8] = b"native PQ local authorization experiment";

fn scope() -> PqAuthorizationScope {
    PqAuthorizationScope {
        purpose: 4,
        network: [1; 32],
        owner_context: [2; 32],
        generation: 7,
        max_future_seconds: 60,
        public_key_spki: KEY.to_vec(),
    }
}

#[test]
fn three_real_pq_operations_survive_reopen_without_nonce_rewind() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("pq.sqlite");
    let mut owner = PqAuthorizationOwner::open(&path, scope()).unwrap();
    assert_eq!(
        owner
            .record_authorization(FIRST, PAYLOAD, 3999)
            .unwrap()
            .sequence(),
        1
    );
    let mut bad = SECOND.to_vec();
    bad[178] ^= 1;
    assert!(owner.record_authorization(&bad, PAYLOAD, 3999).is_err());
    assert_eq!(
        owner
            .record_authorization(SECOND, PAYLOAD, 3999)
            .unwrap()
            .sequence(),
        2
    );
    drop(owner);
    let mut owner = PqAuthorizationOwner::open(&path, scope()).unwrap();
    assert!(owner.record_authorization(FIRST, PAYLOAD, 3999).is_err());
    assert_eq!(
        owner
            .record_authorization(THIRD, PAYLOAD, 3999)
            .unwrap()
            .sequence(),
        3
    );
    let rows: i64 = owner
        .database
        .query_row("SELECT count(*) FROM pq_authorizations_v1", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(rows, 3);
}

#[test]
fn signature_randomness_cannot_replay_one_operation() {
    let temp = tempfile::tempdir().unwrap();
    let mut owner = PqAuthorizationOwner::open(&temp.path().join("pq.sqlite"), scope()).unwrap();
    assert_ne!(FIRST, FIRST_RANDOMIZED);
    assert_eq!(&FIRST[..176], &FIRST_RANDOMIZED[..176]);
    owner.record_authorization(FIRST, PAYLOAD, 3999).unwrap();
    assert!(owner
        .record_authorization(FIRST_RANDOMIZED, PAYLOAD, 3999)
        .is_err());
}

#[test]
fn two_connections_cannot_consume_the_same_sequence() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("pq.sqlite");
    let first = PqAuthorizationOwner::open(&path, scope()).unwrap();
    let second = PqAuthorizationOwner::open(&path, scope()).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let threads: Vec<_> = [first, second]
        .into_iter()
        .map(|mut owner| {
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                owner.record_authorization(FIRST, PAYLOAD, 3999).is_ok()
            })
        })
        .collect();
    let successes = threads
        .into_iter()
        .map(|thread| usize::from(thread.join().unwrap()))
        .sum::<usize>();
    assert_eq!(successes, 1);
}

#[test]
fn changed_scope_unrelated_database_and_classical_inputs_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("pq.sqlite");
    drop(PqAuthorizationOwner::open(&path, scope()).unwrap());
    let mut changed = scope();
    changed.generation += 1;
    assert!(matches!(
        PqAuthorizationOwner::open(&path, changed),
        Err(PqOwnerError::StoreIdentity)
    ));
    let mut changed = scope();
    changed.owner_context[0] ^= 1;
    assert!(matches!(
        PqAuthorizationOwner::open(&path, changed),
        Err(PqOwnerError::StoreIdentity)
    ));
    let foreign = temp.path().join("foreign.sqlite");
    Connection::open(&foreign)
        .unwrap()
        .execute("CREATE TABLE unrelated (value INTEGER)", [])
        .unwrap();
    assert!(matches!(
        PqAuthorizationOwner::open(&foreign, scope()),
        Err(PqOwnerError::StoreIdentity)
    ));
    let mut owner = PqAuthorizationOwner::open(&path, scope()).unwrap();
    assert!(owner.record_authorization(&[0; 64], PAYLOAD, 3999).is_err());
    assert!(owner.record_authorization(FIRST, PAYLOAD, 3000).is_err());
    assert!(owner.record_authorization(FIRST, PAYLOAD, 4001).is_err());
    assert!(owner
        .record_authorization(FIRST, b"other payload", 3999)
        .is_err());
    assert!(owner
        .record_authorization(FIRST, &vec![0; MAX_PAYLOAD + 1], 3999)
        .is_err());
    assert_eq!(
        owner
            .record_authorization(FIRST, PAYLOAD, 3999)
            .unwrap()
            .sequence(),
        1
    );
}

#[test]
fn unexpected_abort_trigger_is_rejected_without_consuming_sequence() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("pq.sqlite");
    let mut owner = PqAuthorizationOwner::open(&path, scope()).unwrap();
    owner
        .database
        .execute_batch(
            "CREATE TRIGGER fail_insert BEFORE INSERT ON pq_authorizations_v1
         BEGIN SELECT RAISE(ABORT, 'injected storage failure'); END;",
        )
        .unwrap();
    assert!(matches!(
        owner.record_authorization(FIRST, PAYLOAD, 3999),
        Err(PqOwnerError::StoreIdentity)
    ));
    owner
        .database
        .execute_batch("DROP TRIGGER fail_insert")
        .unwrap();
    drop(owner);
    let mut owner = PqAuthorizationOwner::open(&path, scope()).unwrap();
    assert_eq!(
        owner
            .record_authorization(FIRST, PAYLOAD, 3999)
            .unwrap()
            .sequence(),
        1
    );
}

#[test]
fn silent_insert_ignore_is_rejected_before_granting_authority() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("pq.sqlite");
    let mut owner = PqAuthorizationOwner::open(&path, scope()).unwrap();
    let other = Connection::open(&path).unwrap();
    other
        .execute_batch(
            "CREATE TRIGGER ignore_insert BEFORE INSERT ON pq_authorizations_v1
         BEGIN SELECT RAISE(IGNORE); END;",
        )
        .unwrap();
    let result = owner.record_authorization(FIRST, PAYLOAD, 3999);
    let sequence: i64 = other
        .query_row("SELECT sequence FROM main.pq_owner_v1", [], |r| r.get(0))
        .unwrap();
    let rows: i64 = other
        .query_row("SELECT count(*) FROM main.pq_authorizations_v1", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(
        result.is_err(),
        "issued a record with sequence={sequence}, stored rows={rows}"
    );
    assert_eq!((sequence, rows), (0, 0));
    other.execute_batch("DROP TRIGGER ignore_insert").unwrap();
    assert_eq!(
        owner
            .record_authorization(FIRST, PAYLOAD, 3999)
            .unwrap()
            .sequence(),
        1
    );
}

#[test]
fn temporary_tables_cannot_redirect_a_durable_authorization() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("pq.sqlite");
    let mut owner = PqAuthorizationOwner::open(&path, scope()).unwrap();
    owner
        .database
        .execute_batch(
            "CREATE TEMP TABLE pq_owner_v1 AS SELECT * FROM main.pq_owner_v1;
         CREATE TEMP TABLE pq_authorizations_v1 AS SELECT * FROM main.pq_authorizations_v1;",
        )
        .unwrap();
    let result = owner.record_authorization(FIRST, PAYLOAD, 3999);
    let main_sequence: i64 = owner
        .database
        .query_row("SELECT sequence FROM main.pq_owner_v1", [], |r| r.get(0))
        .unwrap();
    assert!(
        result.is_err(),
        "issued a record while durable sequence={main_sequence}"
    );
    assert_eq!(main_sequence, 0);
    owner
        .database
        .execute_batch("DROP TABLE temp.pq_owner_v1; DROP TABLE temp.pq_authorizations_v1;")
        .unwrap();
    drop(owner);
    let mut owner = PqAuthorizationOwner::open(&path, scope()).unwrap();
    assert_eq!(
        owner
            .record_authorization(FIRST, PAYLOAD, 3999)
            .unwrap()
            .sequence(),
        1
    );
}

#[test]
fn counter_reset_trigger_cannot_make_one_signature_replayable() {
    let temp = tempfile::tempdir().unwrap();
    let mut owner = PqAuthorizationOwner::open(&temp.path().join("pq.sqlite"), scope()).unwrap();
    owner
        .database
        .execute_batch(
            "CREATE TRIGGER reset_sequence AFTER INSERT ON pq_authorizations_v1 BEGIN
         UPDATE pq_owner_v1 SET sequence=0;
         DELETE FROM pq_authorizations_v1;
         END;",
        )
        .unwrap();
    assert!(
        owner.record_authorization(FIRST, PAYLOAD, 3999).is_err(),
        "reset trigger allowed first signature to grant authority"
    );
    assert!(owner
        .record_authorization(FIRST_RANDOMIZED, PAYLOAD, 3999)
        .is_err());
    owner
        .database
        .execute_batch("DROP TRIGGER reset_sequence")
        .unwrap();
    assert_eq!(
        owner
            .record_authorization(FIRST, PAYLOAD, 3999)
            .unwrap()
            .sequence(),
        1
    );
    assert!(owner
        .record_authorization(FIRST_RANDOMIZED, PAYLOAD, 3999)
        .is_err());
}

#[test]
fn changed_schema_is_not_an_identically_pinned_owner() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("pq.sqlite");
    let owner = PqAuthorizationOwner::open(&path, scope()).unwrap();
    owner
        .database
        .execute_batch(
            "ALTER TABLE pq_authorizations_v1 RENAME TO discarded;
         CREATE TABLE pq_authorizations_v1 (sequence INTEGER PRIMARY KEY,
             statement BLOB, digest BLOB);
         DROP TABLE discarded;",
        )
        .unwrap();
    drop(owner);
    assert!(matches!(
        PqAuthorizationOwner::open(&path, scope()),
        Err(PqOwnerError::StoreIdentity)
    ));
}

#[test]
fn scope_identity_is_rechecked_in_the_actual_write_transaction() {
    let temp = tempfile::tempdir().unwrap();
    let mut owner = PqAuthorizationOwner::open(&temp.path().join("pq.sqlite"), scope()).unwrap();
    owner
        .database
        .execute("UPDATE pq_owner_v1 SET identity=zeroblob(48)", [])
        .unwrap();
    assert!(matches!(
        owner.record_authorization(FIRST, PAYLOAD, 3999),
        Err(PqOwnerError::StoreIdentity)
    ));
    let sequence: i64 = owner
        .database
        .query_row("SELECT sequence FROM pq_owner_v1", [], |r| r.get(0))
        .unwrap();
    assert_eq!(sequence, 0);
    owner
        .database
        .execute(
            "UPDATE pq_owner_v1 SET identity=?1",
            [owner.identity.as_slice()],
        )
        .unwrap();
    assert_eq!(
        owner
            .record_authorization(FIRST, PAYLOAD, 3999)
            .unwrap()
            .sequence(),
        1
    );
}

#[test]
fn missing_or_corrupt_tip_is_rejected_without_resetting_sequence() {
    for delete in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("pq.sqlite");
        let mut owner = PqAuthorizationOwner::open(&path, scope()).unwrap();
        owner.record_authorization(FIRST, PAYLOAD, 3999).unwrap();
        owner
            .database
            .execute_batch(if delete {
                "DELETE FROM pq_authorizations_v1"
            } else {
                "UPDATE pq_authorizations_v1 SET digest=zeroblob(48)"
            })
            .unwrap();
        assert!(matches!(
            owner.record_authorization(SECOND, PAYLOAD, 3999),
            Err(PqOwnerError::StoreIntegrity)
        ));
        let sequence: i64 = owner
            .database
            .query_row("SELECT sequence FROM pq_owner_v1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(sequence, 1);
        drop(owner);
        assert!(matches!(
            PqAuthorizationOwner::open(&path, scope()),
            Err(PqOwnerError::StoreIntegrity)
        ));
    }
}

#[test]
fn real_sqlite_full_failure_rolls_back_sequence_and_record_together() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("pq.sqlite");
    let setup = Connection::open(&path).unwrap();
    setup.pragma_update(None, "page_size", 512).unwrap();
    // An empty unopened file does not retain a connection-only page-size hint.
    // VACUUM materializes the fresh database header before the owner reopens it.
    setup.execute_batch("VACUUM").unwrap();
    drop(setup);
    let mut owner = PqAuthorizationOwner::open(&path, scope()).unwrap();
    let page_size: i64 = owner
        .database
        .pragma_query_value(None, "page_size", |r| r.get(0))
        .unwrap();
    assert_eq!(page_size, 512);
    let pages: i64 = owner
        .database
        .pragma_query_value(None, "page_count", |r| r.get(0))
        .unwrap();
    owner
        .database
        .pragma_update(None, "max_page_count", pages)
        .unwrap();
    for (index, frame) in [FIRST, SECOND, THIRD].into_iter().enumerate() {
        match owner.record_authorization(frame, PAYLOAD, 3999) {
            Ok(record) => assert_eq!(record.sequence(), index as u64 + 1),
            Err(PqOwnerError::Storage(rusqlite::Error::SqliteFailure(error, _)))
                if error.code == rusqlite::ErrorCode::DiskFull =>
            {
                let sequence: i64 = owner
                    .database
                    .query_row("SELECT sequence FROM pq_owner_v1", [], |r| r.get(0))
                    .unwrap();
                let rows: i64 = owner
                    .database
                    .query_row("SELECT count(*) FROM pq_authorizations_v1", [], |r| {
                        r.get(0)
                    })
                    .unwrap();
                assert_eq!((sequence, rows), (index as i64, index as i64));
                owner
                    .database
                    .pragma_update(None, "max_page_count", 1_000_000)
                    .unwrap();
                assert_eq!(
                    owner
                        .record_authorization(frame, PAYLOAD, 3999)
                        .unwrap()
                        .sequence(),
                    index as u64 + 1
                );
                return;
            }
            other => panic!("unexpected result during actual SQLite page exhaustion: {other:?}"),
        }
    }
    panic!("test did not reach the intended real SQLite FULL failure");
}
