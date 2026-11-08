//! Real ML-DSA signatures, durable SQLite state and adversarial lease histories.
//! Synthetic supplied clocks exercise exact boundaries without wall-clock sleeps.
use super::*;
use crate::cell::pq::CellPqKeyPinV2;
use rusqlite::{params, types::Value, Connection};
use std::{
    net::IpAddr,
    path::Path,
    time::{Duration, Instant},
};
use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;
use zeroize::Zeroizing;

fn context() -> CellDiscoveryContextV1 {
    CellDiscoveryContextV1 {
        namespace: [31; 32],
        network: [32; 32],
        parameters: [33; 32],
        genesis: [34; 32],
    }
}
fn request(index: u64) -> CellDiscoveryRequestV1 {
    let mut manifest = [35; 32];
    manifest[..8].copy_from_slice(&index.to_be_bytes());
    CellDiscoveryRequestV1 {
        context: context(),
        cell_context: [36; 32],
        manifest,
    }
}
fn key(seed: u8) -> (PqNativeSigningKey, CellPqKeyPinV2) {
    let seed = Zeroizing::new([seed; 32]);
    let spki = PqNativeSigningKey::public_spki_from_seed(&seed);
    let key_id = ml_dsa_65_key_id_from_spki(&spki).unwrap();
    (
        PqNativeSigningKey::from_owned_seed(seed, key_id).unwrap(),
        CellPqKeyPinV2 {
            key_id,
            generation: 1,
            spki,
            not_before: 1,
            expires_at: u64::MAX,
            revoked_at: None,
        },
    )
}
fn roster(count: u8) -> (Vec<PqNativeSigningKey>, CellPqKeyPinsV2) {
    let (keys, pins): (Vec<_>, Vec<_>) = (1..=count).map(key).unzip();
    (keys, CellPqKeyPinsV2::new(pins).unwrap())
}
fn endpoint() -> SocketAddr {
    "127.0.0.1:19001".parse().unwrap()
}
fn policy() -> CellDiscoveryAddressPolicyV1 {
    CellDiscoveryAddressPolicyV1::LoopbackDevOnly {
        ports: vec![endpoint().port()],
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn next_epoch() -> u64 {
    (wall_now().unwrap().as_secs() / CELL_DISCOVERY_LEASE_EPOCH_SECONDS_V3 + 1)
        * CELL_DISCOVERY_LEASE_EPOCH_SECONDS_V3
}
fn record(
    key: &PqNativeSigningKey,
    index: u64,
    sequence: u64,
    issued: u64,
    expires: u64,
    withdrawn: bool,
) -> CellProviderRecordV3 {
    CellProviderRecordV3::sign(
        CellProviderStatementV3 {
            request: request(index),
            owner: key.public_key_id(),
            owner_generation: 1,
            endpoint: endpoint(),
            sequence,
            lease_epoch: issued / CELL_DISCOVERY_LEASE_EPOCH_SECONDS_V3,
            issued_unix_seconds: issued,
            expires_unix_seconds: expires,
            withdrawn,
        },
        key,
    )
    .unwrap()
}
fn accept(
    directory: &CellProviderDirectoryV3,
    record: &CellProviderRecordV3,
    source: IpAddr,
    now: u64,
) -> CellResultV1<()> {
    record.verify_at(record.statement.request, now, &policy(), directory.keys())?;
    directory.accept_verified(record, source, now, deadline())
}
fn snapshot(path: &Path) -> Vec<Vec<Value>> {
    let db = Connection::open(path).unwrap();
    [
        "SELECT * FROM discovery_meta_v3 ORDER BY singleton",
        "SELECT * FROM discovery_providers_v3 ORDER BY manifest,owner",
    ]
    .iter()
    .flat_map(|sql| {
        let mut query = db.prepare(sql).unwrap();
        let columns = query.column_count();
        query
            .query_map([], |row| (0..columns).map(|i| row.get(i)).collect())
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    })
    .collect()
}
fn capacity<T: std::fmt::Debug>(value: CellResultV1<T>) {
    assert!(
        matches!(
            value,
            Err(CellErrorV1::Invalid("discovery identity capacity"))
        ),
        "{value:?}"
    );
}

#[test]
fn actual_mldsa_v3_binds_every_unsigned_byte_and_rejects_other_namespaces() {
    let (key, pin) = key(42);
    let keys = CellPqKeyPinsV2::new(vec![pin]).unwrap();
    let record = record(&key, 77, 9, 610, 899, false);
    let wire = record.encode();
    assert_eq!(wire.len(), 3600);
    assert_eq!(&wire[..8], &[b'C', b'D', b'P', b'3', 3, 0x65, 0, 0]);
    assert_eq!(&wire[267..275], &2_u64.to_be_bytes());
    assert_eq!(
        record
            .verify_at(request(77), 610, &policy(), &keys)
            .unwrap(),
        899
    );
    for index in 0..291 {
        let mut changed = wire.clone();
        changed[index] ^= 1;
        assert!(
            CellProviderRecordV3::decode(&changed)
                .and_then(|v| v.verify_at(request(77), 610, &policy(), &keys))
                .is_err(),
            "byte {index}"
        );
    }
    for index in [291, 1000, 3599] {
        let mut changed = wire.clone();
        changed[index] ^= 1;
        assert!(CellProviderRecordV3::decode(&changed)
            .unwrap()
            .verify_at(request(77), 610, &policy(), &keys)
            .is_err());
    }
    for length in [0, 335, 3592, 3599, 3601] {
        let mut changed = wire.clone();
        changed.resize(length, 0);
        assert!(CellProviderRecordV3::decode(&changed).is_err());
    }
    assert!(super::super::CellProviderRecordV1::decode(&wire).is_err());
    assert!(super::super::pq::CellProviderRecordV2::decode(&wire).is_err());
    let v2 = super::super::pq::CellProviderRecordV2::sign(
        super::super::pq::CellProviderStatementV2 {
            request: request(77),
            owner: key.public_key_id(),
            owner_generation: 1,
            endpoint: endpoint(),
            sequence: 9,
            issued_unix_seconds: 610,
            expires_unix_seconds: 899,
            withdrawn: false,
        },
        &key,
    )
    .unwrap();
    assert!(CellProviderRecordV3::decode(&v2.encode()).is_err());
}

#[test]
fn signed_epoch_limits_ttl_skew_and_integer_overflow() {
    let (key, pin) = key(1);
    let keys = CellPqKeyPinsV2::new(vec![pin]).unwrap();
    let at_end = record(&key, 1, 1, 599, 600, false);
    assert!(at_end.verify_at(request(1), 594, &policy(), &keys).is_ok());
    assert!(at_end.verify_at(request(1), 593, &policy(), &keys).is_err());
    assert!(at_end.verify_at(request(1), 600, &policy(), &keys).is_err());
    let next = record(&key, 1, 1, 600, 900, false);
    assert!(
        next.verify_at(request(1), 599, &policy(), &keys).is_err(),
        "skew does not import next epoch"
    );
    assert!(next.verify_at(request(1), 600, &policy(), &keys).is_ok());
    for (epoch, issued, expires) in [
        (1, 599, 601),
        (0, 599, 600),
        (2, 600, 901),
        (u64::MAX, 600, 601),
        (u64::MAX / 300, u64::MAX - 1, u64::MAX),
    ] {
        let mut statement = next.statement.clone();
        statement.lease_epoch = epoch;
        statement.issued_unix_seconds = issued;
        statement.expires_unix_seconds = expires;
        assert!(CellProviderRecordV3::sign(statement, &key).is_err());
    }
}

#[test]
fn manifest_expiry_reclaims_active_slots_across_operations_and_restart() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("directory");
    let (keys, pins) = roster(17);
    let now = next_epoch() + 10;
    let directory = CellProviderDirectoryV3::open(&path, context(), pins.clone()).unwrap();
    for key in &keys[..16] {
        accept(
            &directory,
            &record(key, 1, 1, now, now + 1, false),
            endpoint().ip(),
            now,
        )
        .unwrap();
    }
    let honest = record(&keys[16], 1, 1, now, now + 100, false);
    let before = snapshot(&path);
    capacity(accept(&directory, &honest, endpoint().ip(), now));
    assert_eq!(snapshot(&path), before);
    drop(directory);
    let directory = CellProviderDirectoryV3::open(&path, context(), pins).unwrap();
    accept(&directory, &honest, endpoint().ip(), now + 2).unwrap();
    let usage = directory.usage().unwrap();
    assert_eq!(
        (
            usage.active_identities,
            usage.tombstone_identities,
            usage.retained_identities
        ),
        (1, 16, 17)
    );
    assert_eq!(usage.observed_unix_seconds, now + 2);
    assert_eq!(
        directory
            .records(request(1), now + 2, deadline())
            .unwrap()
            .len(),
        17
    );
}

#[test]
fn owner_expiry_reclaims_active_quota_and_renewal_must_repay_it() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("directory");
    let (keys, pins) = roster(1);
    let now = next_epoch() + 10;
    let directory = CellProviderDirectoryV3::open(&path, context(), pins).unwrap();
    for i in 0..16 {
        accept(
            &directory,
            &record(&keys[0], i, 1, now, now + 1, false),
            endpoint().ip(),
            now,
        )
        .unwrap();
    }
    capacity(accept(
        &directory,
        &record(&keys[0], 16, 1, now, now + 100, false),
        endpoint().ip(),
        now,
    ));
    for i in 16..32 {
        accept(
            &directory,
            &record(&keys[0], i, 1, now, now + 100, false),
            endpoint().ip(),
            now + 2,
        )
        .unwrap();
    }
    // A previously expired identity cannot bypass the active limit by UPDATE.
    let renewal = record(&keys[0], 0, 2, now + 2, now + 100, false);
    let before = snapshot(&path);
    capacity(accept(&directory, &renewal, endpoint().ip(), now + 2));
    assert_eq!(snapshot(&path), before);
    let usage = directory.usage().unwrap();
    assert_eq!(
        (usage.active_identities, usage.tombstone_identities),
        (16, 16)
    );
}

#[test]
fn shorter_latest_ttl_cannot_resurrect_a_long_lived_lower_sequence() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("directory");
    let (keys, pins) = roster(1);
    let now = next_epoch() + 10;
    let directory = CellProviderDirectoryV3::open(&path, context(), pins.clone()).unwrap();
    let old = record(&keys[0], 1, 1, now, now + 200, false);
    let newer = record(&keys[0], 1, 2, now, now + 1, false);
    for value in [&old, &newer] {
        accept(&directory, value, endpoint().ip(), now).unwrap();
    }
    assert_eq!(
        directory
            .usage_at(now + 2, deadline())
            .unwrap()
            .active_identities,
        0
    );
    old.verify_at(request(1), now + 2, &policy(), directory.keys())
        .unwrap();
    let before = snapshot(&path);
    assert!(matches!(
        accept(&directory, &old, endpoint().ip(), now + 2),
        Err(CellErrorV1::Invalid("discovery sequence replay"))
    ));
    assert_eq!(snapshot(&path), before);
    drop(directory);
    let directory = CellProviderDirectoryV3::open(&path, context(), pins).unwrap();
    assert!(accept(&directory, &old, endpoint().ip(), now + 3).is_err());
    assert_eq!(
        directory.records(request(1), now + 3, deadline()).unwrap()[0]
            .statement
            .sequence,
        2
    );
}

#[test]
fn withdrawal_returns_active_quota_but_persists_replay_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("directory");
    let (keys, pins) = roster(17);
    let now = next_epoch() + 10;
    let directory = CellProviderDirectoryV3::open(&path, context(), pins).unwrap();
    for key in &keys[..16] {
        accept(
            &directory,
            &record(key, 1, 1, now, now + 100, false),
            endpoint().ip(),
            now,
        )
        .unwrap();
    }
    let old = record(&keys[0], 1, 1, now, now + 100, false);
    let withdrawal = record(&keys[0], 1, 2, now, now + 100, true);
    accept(&directory, &withdrawal, endpoint().ip(), now).unwrap();
    accept(
        &directory,
        &record(&keys[16], 1, 1, now, now + 100, false),
        endpoint().ip(),
        now,
    )
    .unwrap();
    assert!(accept(&directory, &old, endpoint().ip(), now).is_err());
    capacity(accept(
        &directory,
        &record(&keys[0], 1, 3, now, now + 100, false),
        endpoint().ip(),
        now,
    ));
    let usage = directory.usage().unwrap();
    assert_eq!(
        (usage.active_identities, usage.tombstone_identities),
        (16, 1)
    );
}

#[test]
fn source_and_prefix_limits_release_expired_capacity_without_origin_reassignment() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("directory");
    let (keys, pins) = roster(9);
    let now = next_epoch() + 10;
    let directory = CellProviderDirectoryV3::open(&path, context(), pins).unwrap();
    let first: IpAddr = "192.0.2.1".parse().unwrap();
    let second: IpAddr = "192.0.2.2".parse().unwrap();
    let third: IpAddr = "192.0.2.3".parse().unwrap();
    for i in 0..64 {
        accept(
            &directory,
            &record(&keys[i / 16], i as u64, 1, now, now + 1, false),
            first,
            now,
        )
        .unwrap();
    }
    capacity(accept(
        &directory,
        &record(&keys[4], 64, 1, now, now + 100, false),
        first,
        now,
    ));
    for i in 64..128 {
        accept(
            &directory,
            &record(&keys[i / 16], i as u64, 1, now, now + 1, false),
            second,
            now,
        )
        .unwrap();
    }
    capacity(accept(
        &directory,
        &record(&keys[8], 128, 1, now, now + 100, false),
        third,
        now,
    ));
    accept(
        &directory,
        &record(&keys[8], 128, 1, now, now + 100, false),
        first,
        now + 2,
    )
    .unwrap();
    // A new source on an existing identity never transfers its first-source charge.
    accept(
        &directory,
        &record(&keys[8], 128, 2, now + 2, now + 100, false),
        third,
        now + 2,
    )
    .unwrap();
    let db = Connection::open(&path).unwrap();
    let source: Vec<u8> = db
        .query_row(
            "SELECT source FROM discovery_providers_v3 WHERE manifest=?1",
            [request(128).manifest.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(source, ip_bytes(first));
    assert_eq!(directory.usage().unwrap().active_identities, 1);
}

#[test]
fn bounded_epoch_churn_cannot_consume_permanent_owner_capacity() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("directory");
    let (keys, pins) = roster(1);
    let now = next_epoch() + 10;
    let directory = CellProviderDirectoryV3::open(&path, context(), pins.clone()).unwrap();
    for i in 0..64 {
        accept(
            &directory,
            &record(&keys[0], i, 1, now, now + 1, true),
            endpoint().ip(),
            now,
        )
        .unwrap();
    }
    capacity(accept(
        &directory,
        &record(&keys[0], 64, 1, now, now + 100, false),
        endpoint().ip(),
        now + 2,
    ));
    assert_eq!(
        directory
            .usage_at(now + 2, deadline())
            .unwrap()
            .tombstone_identities,
        64
    );
    let fresh = (now / 300 + 1) * 300;
    accept(
        &directory,
        &record(&keys[0], 64, 1, fresh, fresh + 100, false),
        endpoint().ip(),
        fresh,
    )
    .unwrap();
    assert_eq!(directory.usage().unwrap().retained_identities, 1);
    assert!(directory.records(request(64), now, deadline()).is_err());
    drop(directory);
    let directory = CellProviderDirectoryV3::open(&path, context(), pins).unwrap();
    assert!(directory.records(request(64), now, deadline()).is_err());
    assert_eq!(
        directory
            .records(request(64), fresh, deadline())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn full_512_slot_epoch_recovers_without_widening_database_or_replay_limits() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("directory");
    let (keys, pins) = roster(9);
    let now = next_epoch() + 10;
    let directory = CellProviderDirectoryV3::open(&path, context(), pins).unwrap();
    for i in 0..512 {
        let source: IpAddr = format!("192.0.2.{}", i / 128 + 1).parse().unwrap();
        accept(
            &directory,
            &record(&keys[i / 64], i as u64, 1, now, now + 100, true),
            source,
            now,
        )
        .unwrap();
    }
    let blocked = record(&keys[8], 512, 1, now, now + 100, false);
    let before = snapshot(&path);
    capacity(accept(
        &directory,
        &blocked,
        "198.51.100.1".parse().unwrap(),
        now,
    ));
    assert_eq!(snapshot(&path), before);
    let usage = directory.usage().unwrap();
    assert_eq!(
        (
            usage.retained_identities,
            usage.maximum_identities,
            usage.active_identities
        ),
        (512, 512, 0)
    );
    assert_eq!(usage.retained_wire_bytes, 512 * 3600);
    assert_eq!(usage.maximum_database_bytes, 16 * 1024 * 1024);
    assert!(usage.database_bytes <= usage.maximum_database_bytes);
    let fresh = (now / 300 + 1) * 300;
    assert_eq!(
        directory
            .usage_at(fresh, deadline())
            .unwrap()
            .retained_identities,
        0
    );
    assert!(accept(&directory, &blocked, endpoint().ip(), fresh).is_err());
    accept(
        &directory,
        &record(&keys[8], 512, 1, fresh, fresh + 100, false),
        endpoint().ip(),
        fresh,
    )
    .unwrap();
    for step in 1..=3 {
        let next = fresh + step * 300;
        assert_eq!(
            directory
                .usage_at(next, deadline())
                .unwrap()
                .retained_identities,
            0
        );
        accept(
            &directory,
            &record(&keys[8], 512, 1, next, next + 100, false),
            endpoint().ip(),
            next,
        )
        .unwrap();
    }
    assert!(directory.usage().unwrap().database_bytes <= 16 * 1024 * 1024);
}

#[test]
fn randomized_mldsa_equivalence_keeps_original_wire_and_changed_statement_fails() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("directory");
    let (key, pin) = key(42);
    let keys = CellPqKeyPinsV2::new(vec![pin]).unwrap();
    let now = next_epoch() + 10;
    let directory = CellProviderDirectoryV3::open(&path, context(), keys).unwrap();
    let first = record(&key, 1, 1, now, now + 100, false);
    let mut second = first.clone();
    let key_internal =
        ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&ml_dsa::Seed::from([42; 32]));
    let signature = key_internal
        .expanded_key()
        .sign_internal(&[&[0, 0], &first.message()], &[99; 32].into());
    second.signature.copy_from_slice(&signature.encode());
    assert_ne!(first.encode(), second.encode());
    assert_eq!(first, second);
    assert_eq!(first.digest(), second.digest());
    for value in [&first, &second] {
        accept(&directory, value, endpoint().ip(), now).unwrap();
    }
    assert_eq!(
        directory.records(request(1), now, deadline()).unwrap()[0].encode(),
        first.encode()
    );
    let conflict = record(&key, 1, 1, now, now + 99, false);
    let before = snapshot(&path);
    assert!(matches!(
        accept(&directory, &conflict, endpoint().ip(), now),
        Err(CellErrorV1::Invalid("discovery sequence equivocation"))
    ));
    assert_eq!(snapshot(&path), before);
}

#[test]
fn key_expiry_returns_active_quota_and_is_rechecked_after_verification() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("directory");
    let now = next_epoch() + 10;
    let (key, mut pin) = key(1);
    pin.revoked_at = Some(now + 1);
    let pins = CellPqKeyPinsV2::new(vec![pin]).unwrap();
    let directory = CellProviderDirectoryV3::open(&path, context(), pins).unwrap();
    let first = record(&key, 1, 1, now, now + 100, false);
    accept(&directory, &first, endpoint().ip(), now).unwrap();
    let later = record(&key, 1, 2, now, now + 100, false);
    later
        .verify_at(request(1), now, &policy(), directory.keys())
        .unwrap();
    assert!(directory
        .accept_verified(&later, endpoint().ip(), now + 1, deadline())
        .is_err());
    let usage = directory.usage_at(now + 1, deadline()).unwrap();
    assert_eq!(
        (usage.active_identities, usage.tombstone_identities),
        (0, 1)
    );
    assert_eq!(
        directory.records(request(1), now + 1, deadline()).unwrap()[0]
            .statement
            .sequence,
        1
    );
}

#[test]
fn v3_never_migrates_v1_v2_or_changes_pinned_roster_and_namespace() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("v3");
    let (_, pins) = roster(1);
    drop(CellProviderDirectoryV3::open(&path, context(), pins.clone()).unwrap());
    let before = snapshot(&path);
    assert!(super::super::CellProviderDirectoryV1::open(&path, context()).is_err());
    assert!(
        super::super::pq::CellProviderDirectoryV2::open(&path, context(), pins.clone()).is_err()
    );
    assert!(CellProviderDirectoryV3::open(&path, context(), roster(2).1).is_err());
    let mut changed = context();
    changed.namespace = [55; 32];
    assert!(CellProviderDirectoryV3::open(&path, changed, pins.clone()).is_err());
    assert_eq!(snapshot(&path), before);
    let old = temp.path().join("v2");
    drop(super::super::pq::CellProviderDirectoryV2::open(&old, context(), pins.clone()).unwrap());
    assert!(CellProviderDirectoryV3::open(&old, context(), pins).is_err());
    let db = Connection::open(&old).unwrap();
    assert_eq!(
        db.pragma_query_value(None, "user_version", |r| r.get::<_, u64>(0))
            .unwrap(),
        2
    );
}

#[test]
fn epoch_and_wire_column_corruption_fail_before_pruning_or_ack() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("directory");
    let (keys, pins) = roster(1);
    let now = next_epoch() + 10;
    let directory = CellProviderDirectoryV3::open(&path, context(), pins).unwrap();
    let first = record(&keys[0], 1, 1, now, now + 100, false);
    let second = record(&keys[0], 1, 2, now, now + 100, false);
    for value in [&first, &second] {
        accept(&directory, value, endpoint().ip(), now).unwrap();
    }
    let db = Connection::open(&path).unwrap();
    // Replacing only the signed wire cannot rewind sequence/digest bookkeeping.
    db.execute(
        "UPDATE discovery_providers_v3 SET wire=?1",
        [first.encode()],
    )
    .unwrap();
    assert!(directory.records(request(1), now, deadline()).is_err());
    assert!(
        directory
            .usage_at((now / 300 + 1) * 300, deadline())
            .is_err(),
        "rotation cannot erase corrupt prior evidence"
    );
    db.execute(
        "UPDATE discovery_providers_v3 SET wire=?1",
        [second.encode()],
    )
    .unwrap();
    db.execute(
        "UPDATE discovery_meta_v3 SET epoch=?1",
        [(now / 300 - 1).to_be_bytes().as_slice()],
    )
    .unwrap();
    assert!(directory.records(request(1), now, deadline()).is_err());
    db.execute(
        "UPDATE discovery_meta_v3 SET epoch=?1",
        [(now / 300).to_be_bytes().as_slice()],
    )
    .unwrap();
    db.execute(
        "UPDATE discovery_providers_v3 SET prefix=?1",
        params![[0u8; 17].as_slice()],
    )
    .unwrap();
    assert!(directory.records(request(1), now, deadline()).is_err());
}

#[test]
fn failed_deadline_does_not_retire_epoch_or_change_durable_state() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("directory");
    let (keys, pins) = roster(1);
    let now = next_epoch() + 10;
    let directory = CellProviderDirectoryV3::open(&path, context(), pins).unwrap();
    accept(
        &directory,
        &record(&keys[0], 1, 1, now, now + 100, false),
        endpoint().ip(),
        now,
    )
    .unwrap();
    let before = snapshot(&path);
    assert!(directory
        .usage_at(
            (now / 300 + 1) * 300,
            Instant::now() - Duration::from_millis(1)
        )
        .is_err());
    assert_eq!(snapshot(&path), before);
}

#[test]
fn read_only_usage_refuses_rewinding_a_revision_already_observed_in_process() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("directory");
    let (keys, pins) = roster(1);
    let now = next_epoch() + 10;
    let directory = CellProviderDirectoryV3::open(&path, context(), pins).unwrap();
    accept(
        &directory,
        &record(&keys[0], 1, 1, now, now + 100, false),
        endpoint().ip(),
        now,
    )
    .unwrap();
    let db = Connection::open(&path).unwrap();
    db.execute(
        "UPDATE discovery_meta_v3 SET revision=?1",
        [0u64.to_be_bytes().as_slice()],
    )
    .unwrap();
    assert!(matches!(
        directory.usage(),
        Err(CellErrorV1::Invalid("discovery clock/revision rollback"))
    ));
    assert!(directory.records(request(1), now, deadline()).is_err());
}

#[test]
fn read_only_usage_advances_its_fence_after_reconciling_a_higher_revision() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("directory");
    let (keys, pins) = roster(1);
    let now = next_epoch() + 10;
    let directory = CellProviderDirectoryV3::open(&path, context(), pins).unwrap();
    accept(
        &directory,
        &record(&keys[0], 1, 1, now, now + 100, false),
        endpoint().ip(),
        now,
    )
    .unwrap();
    let db = Connection::open(&path).unwrap();
    // Model a committed write whose post-COMMIT response was not observed.
    // The local diagnostic reads a self-consistent higher revision snapshot.
    db.execute(
        "UPDATE discovery_meta_v3 SET revision=?1",
        [10u64.to_be_bytes().as_slice()],
    )
    .unwrap();
    assert_eq!(directory.usage().unwrap().retained_identities, 1);
    db.execute(
        "UPDATE discovery_meta_v3 SET revision=?1",
        [1u64.to_be_bytes().as_slice()],
    )
    .unwrap();
    assert!(matches!(
        directory.usage(),
        Err(CellErrorV1::Invalid("discovery clock/revision rollback"))
    ));
    assert!(directory.records(request(1), now, deadline()).is_err());
}

#[test]
fn unrepresentable_epoch_end_cannot_commit_an_unrecoverable_directory_clock() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("directory");
    let (_, pins) = roster(1);
    let directory = CellProviderDirectoryV3::open(&path, context(), pins).unwrap();
    let before = snapshot(&path);
    for invalid_now in [u64::MAX, u64::MAX / 300 * 300] {
        assert!(matches!(
            directory.usage_at(invalid_now, deadline()),
            Err(CellErrorV1::Invalid("discovery lease epoch overflow"))
        ));
        assert!(directory
            .records(request(1), invalid_now, deadline())
            .is_err());
        assert_eq!(snapshot(&path), before);
    }
}
