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
fn failed_durable_insert_rolls_back_sequence_in_same_transaction() {
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
        Err(PqOwnerError::Storage(_))
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
