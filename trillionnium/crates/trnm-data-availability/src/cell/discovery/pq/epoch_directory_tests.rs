use super::*;
use crate::cell::pq::CellPqKeyPinV2;
use rusqlite::types::Value;
use std::{sync::mpsc, thread, time::Duration};
use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;
use zeroize::Zeroizing;

fn time(now: u64) -> CellDiscoveryTimeV3 {
    CellDiscoveryTimeV3::for_test(Duration::from_secs(now), Instant::now())
}
fn context() -> CellDiscoveryContextV1 {
    CellDiscoveryContextV1 {
        namespace: [71; 32],
        network: [72; 32],
        parameters: [73; 32],
        genesis: [74; 32],
    }
}
fn manifest(index: u64) -> CellDigestV1 {
    let mut digest = [75; 32];
    digest[24..].copy_from_slice(&index.to_be_bytes());
    digest
}
fn request(index: u64, now: u64) -> CellDiscoveryRequestV3 {
    CellDiscoveryRequestV3 {
        base: CellDiscoveryRequestV1 {
            context: context(),
            cell_context: [76; 32],
            manifest: manifest(index),
        },
        epoch: CellDiscoveryRequestV3::epoch_at(now),
    }
}
fn policy() -> CellDiscoveryAddressPolicyV1 {
    CellDiscoveryAddressPolicyV1::LoopbackDevOnly { ports: vec![19003] }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(15)
}
struct Fixture {
    _temp: tempfile::TempDir,
    path: PathBuf,
    keys: CellPqKeyPinsV2,
    signers: Vec<PqNativeSigningKey>,
    source_pins: CellDiscoverySourcePinsV3,
    sources: Vec<CellDiscoverySourceV3>,
    now: u64,
    end: u64,
}
impl Fixture {
    fn new(owners: usize, sources: usize) -> Self {
        let origins = (0..sources)
            .map(|index| CellDiscoverySourceV3 {
                authenticated_key_id: [180 + index as u8; 32],
                generation: 1,
                ip: format!("10.{index}.0.1").parse().unwrap(),
            })
            .collect();
        Self::with_sources(owners, origins)
    }
    fn with_sources(owners: usize, sources: Vec<CellDiscoverySourceV3>) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("directory.sqlite");
        let mut signers = Vec::new();
        let mut pins = Vec::new();
        for index in 0..owners {
            let seed = Zeroizing::new([20 + index as u8; 32]);
            let spki = PqNativeSigningKey::public_spki_from_seed(&seed);
            let key_id = ml_dsa_65_key_id_from_spki(&spki).unwrap();
            signers.push(PqNativeSigningKey::from_owned_seed(seed, key_id).unwrap());
            pins.push(CellPqKeyPinV2 {
                key_id,
                generation: 1,
                spki,
                not_before: 1,
                expires_at: u64::MAX,
                revoked_at: None,
            });
        }
        let source_pins = CellDiscoverySourcePinsV3::new(
            sources
                .iter()
                .map(|source| CellDiscoverySourcePinV3 {
                    authenticated_key_id: source.authenticated_key_id,
                    generation: source.generation,
                    ip: source.ip,
                })
                .collect(),
        )
        .unwrap();
        // Start a complete logical epoch after real file initialization time.
        // The test clock is explicit; a second rollover during open is harmless.
        let start = (CellDiscoveryRequestV3::epoch_at(wall_now().unwrap().as_secs()) + 1)
            * CELL_DISCOVERY_EPOCH_SECONDS_V3;
        Self {
            _temp: temp,
            path,
            keys: CellPqKeyPinsV2::new(pins).unwrap(),
            signers,
            source_pins,
            sources,
            now: start + 10,
            end: start + CELL_DISCOVERY_EPOCH_SECONDS_V3,
        }
    }
    fn open(&self) -> CellProviderDirectoryV3 {
        CellProviderDirectoryV3::open(
            &self.path,
            context(),
            self.keys.clone(),
            self.source_pins.clone(),
        )
        .unwrap()
    }
    fn record(
        &self,
        owner: usize,
        manifest: u64,
        sequence: u64,
        issued: u64,
        expires: u64,
        withdrawn: bool,
    ) -> CellProviderRecordV3 {
        CellProviderRecordV3::sign(
            CellProviderStatementV3 {
                request: request(manifest, issued),
                owner: self.signers[owner].public_key_id(),
                owner_generation: 1,
                endpoint: "127.0.0.1:19003".parse().unwrap(),
                sequence,
                issued_unix_seconds: issued,
                expires_unix_seconds: expires,
                withdrawn,
            },
            &self.signers[owner],
        )
        .unwrap()
    }
    fn verify(&self, record: &CellProviderRecordV3, now: u64) -> CellVerifiedProviderRecordV3 {
        record
            .verify_at(record.statement().request, time(now), &policy(), &self.keys)
            .unwrap()
    }
    fn accept(
        &self,
        directory: &CellProviderDirectoryV3,
        record: &CellProviderRecordV3,
        source: usize,
        now: u64,
    ) -> CellResultV1<()> {
        directory.accept_verified(
            &self.verify(record, now),
            self.sources[source],
            now,
            deadline(),
        )
    }
}
fn snapshot(directory: &CellProviderDirectoryV3) -> Vec<Vec<Value>> {
    let state = directory.state.lock().unwrap();
    [
        "SELECT * FROM discovery_meta_v3 ORDER BY singleton",
        "SELECT * FROM discovery_providers_v3 ORDER BY epoch,manifest,owner",
    ]
    .iter()
    .flat_map(|sql| {
        let mut query = state.db.prepare(sql).unwrap();
        let columns = query.column_count();
        query
            .query_map([], |row| (0..columns).map(|index| row.get(index)).collect())
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    })
    .collect()
}
fn assert_capacity(error: CellErrorV1, expected: &'static str) {
    assert!(
        matches!(error, CellErrorV1::Invalid(actual) if actual == expected),
        "{error:?}"
    );
}

#[test]
fn expiry_refunds_active_owner_capacity_but_preserves_bounded_history_and_reactivation_checks() {
    let fixture = Fixture::new(1, 2);
    let directory = fixture.open();
    for index in 0..16 {
        fixture
            .accept(
                &directory,
                &fixture.record(0, index, 7, fixture.now, fixture.now + 5, false),
                0,
                fixture.now,
            )
            .unwrap();
    }
    let denied = fixture.record(0, 16, 1, fixture.now, fixture.end, false);
    assert_capacity(
        fixture
            .accept(&directory, &denied, 0, fixture.now)
            .unwrap_err(),
        "discovery active capacity",
    );
    let now = fixture.now + 5;
    let usage = directory.usage_at(now, deadline()).unwrap();
    assert_eq!(
        (
            usage.active_identities,
            usage.retained_identities,
            usage.replay_only_identities
        ),
        (0, 16, 16)
    );
    assert_eq!(usage.reclaimed_closed_epoch_identities, 0);
    for index in 16..32 {
        fixture
            .accept(
                &directory,
                &fixture.record(0, index, 1, now, now + 5, false),
                1,
                now,
            )
            .unwrap();
    }
    let before = snapshot(&directory);
    let reactivation = fixture.record(0, 0, 8, now, fixture.end, false);
    assert_capacity(
        fixture
            .accept(&directory, &reactivation, 1, now)
            .unwrap_err(),
        "discovery active capacity",
    );
    assert_eq!(snapshot(&directory), before);
    let unseen = fixture.record(0, 32, 1, now, fixture.end, false);
    assert_capacity(
        fixture.accept(&directory, &unseen, 1, now).unwrap_err(),
        "discovery replay capacity",
    );
    let expired = now + 5;
    let reactivation = fixture.record(0, 0, 8, expired, fixture.end, false);
    fixture
        .accept(&directory, &reactivation, 1, expired)
        .unwrap();
    let usage = directory.usage_at(expired, deadline()).unwrap();
    assert_eq!(
        (usage.active_identities, usage.retained_identities),
        (1, 32)
    );
    assert_eq!(usage.replay_limits, CELL_DISCOVERY_REPLAY_LIMITS_V3);
    assert_eq!(usage.active_limits, CELL_DISCOVERY_ACTIVE_LIMITS_V3);
    assert_eq!(usage.retained_wire_bytes, 32 * 3600);
    assert!(!usage.database_bound_includes_journal_or_rss);
    assert!(usage.database_bytes <= 16 * 1024 * 1024);
    let retired = directory.usage_at(fixture.end, deadline()).unwrap();
    assert_eq!(
        (retired.active_identities, retired.retained_identities),
        (0, 0)
    );
    assert_eq!(retired.reclaimed_closed_epoch_identities, 32);
    fixture
        .accept(
            &directory,
            &fixture.record(0, 32, 1, fixture.end, fixture.end + 60, false),
            1,
            fixture.end,
        )
        .unwrap();
}

#[test]
fn shortening_high_sequence_expiry_never_revives_old_or_newly_resigned_low_sequence() {
    let fixture = Fixture::new(1, 1);
    let directory = fixture.open();
    let old = fixture.record(0, 1, 3, fixture.now, fixture.end, false);
    let high = fixture.record(0, 1, 7, fixture.now, fixture.now + 3, false);
    fixture.accept(&directory, &old, 0, fixture.now).unwrap();
    fixture.accept(&directory, &high, 0, fixture.now).unwrap();
    let after_expiry = fixture.now + 4;
    assert_eq!(
        directory
            .usage_at(after_expiry, deadline())
            .unwrap()
            .active_identities,
        0
    );
    assert!(fixture.accept(&directory, &old, 0, after_expiry).is_err());
    let resigned = fixture.record(0, 1, 1, after_expiry, fixture.end, false);
    assert!(fixture
        .accept(&directory, &resigned, 0, after_expiry)
        .is_err());
    assert_eq!(
        directory
            .records(request(1, after_expiry), after_expiry, deadline())
            .unwrap()[0]
            .statement()
            .sequence,
        7
    );
    drop(directory);
    let directory = fixture.open();
    assert!(fixture.accept(&directory, &old, 0, after_expiry).is_err());
    assert!(fixture
        .accept(&directory, &resigned, 0, after_expiry)
        .is_err());
    assert!(directory.usage_at(fixture.now, deadline()).is_err());
    let old_receipt = fixture.verify(&old, after_expiry);
    let fresh = fixture.record(0, 1, 1, fixture.end, fixture.end + 60, false);
    fixture.accept(&directory, &fresh, 0, fixture.end).unwrap();
    assert!(directory
        .accept_verified(&old_receipt, fixture.sources[0], fixture.end, deadline())
        .is_err());
    assert!(old
        .verify_at(
            old.statement().request,
            time(fixture.end),
            &policy(),
            &fixture.keys
        )
        .is_err());
    assert!(directory
        .records(request(1, after_expiry), after_expiry, deadline())
        .is_err());
    let usage = directory.usage_at(fixture.end, deadline()).unwrap();
    assert_eq!(
        (
            usage.retained_identities,
            usage.reclaimed_closed_epoch_identities
        ),
        (1, 1)
    );
    drop(directory);
    let directory = fixture.open();
    assert!(directory.usage_at(after_expiry, deadline()).is_err());
    assert_eq!(
        directory
            .records(request(1, fixture.end), fixture.end, deadline())
            .unwrap()[0]
            .statement()
            .sequence,
        1
    );
}

#[test]
fn repeated_prior_operations_reopen_and_epoch_retirement_recover_manifest_capacity() {
    let fixture = Fixture::new(17, 5);
    for owner in 0..16 {
        let directory = fixture.open();
        fixture
            .accept(
                &directory,
                &fixture.record(owner, 1, 1, fixture.now, fixture.end, false),
                owner / 4,
                fixture.now,
            )
            .unwrap();
    }
    let directory = fixture.open();
    let denied = fixture.record(16, 1, 1, fixture.now, fixture.end, false);
    assert_capacity(
        fixture
            .accept(&directory, &denied, 4, fixture.now)
            .unwrap_err(),
        "discovery active capacity",
    );
    drop(directory);
    let directory = fixture.open();
    let later = fixture.end + 301;
    let newcomer = fixture.record(16, 1, 1, later, later + 120, false);
    fixture.accept(&directory, &newcomer, 4, later).unwrap();
    let usage = directory.usage_at(later, deadline()).unwrap();
    assert_eq!(
        (
            usage.active_identities,
            usage.retained_identities,
            usage.reclaimed_closed_epoch_identities
        ),
        (1, 1, 16)
    );
    assert!(directory.usage_at(fixture.now, deadline()).is_err());
}

#[test]
fn per_source_manifest_reservation_and_withdrawal_reactivation_share_active_caps() {
    let fixture = Fixture::new(18, 5);
    let directory = fixture.open();
    for owner in 0..4 {
        fixture
            .accept(
                &directory,
                &fixture.record(owner, 1, 1, fixture.now, fixture.end, false),
                0,
                fixture.now,
            )
            .unwrap();
    }
    let fifth = fixture.record(4, 1, 1, fixture.now, fixture.end, false);
    assert_capacity(
        fixture
            .accept(&directory, &fifth, 0, fixture.now)
            .unwrap_err(),
        "discovery active capacity",
    );
    fixture.accept(&directory, &fifth, 1, fixture.now).unwrap();
    for owner in 5..16 {
        let expiry = if owner == 5 {
            fixture.now + 2
        } else {
            fixture.end
        };
        fixture
            .accept(
                &directory,
                &fixture.record(owner, 1, 1, fixture.now, expiry, false),
                owner / 4,
                fixture.now,
            )
            .unwrap();
    }
    let withdrawn = fixture.record(16, 1, 1, fixture.now, fixture.end, true);
    fixture
        .accept(&directory, &withdrawn, 1, fixture.now)
        .unwrap();
    let before = snapshot(&directory);
    let revived = fixture.record(16, 1, 2, fixture.now, fixture.end, false);
    assert_capacity(
        fixture
            .accept(&directory, &revived, 4, fixture.now)
            .unwrap_err(),
        "discovery active capacity",
    );
    assert_eq!(snapshot(&directory), before);
    let now = fixture.now + 3;
    fixture
        .accept(
            &directory,
            &fixture.record(16, 1, 2, now, fixture.end, false),
            4,
            now,
        )
        .unwrap();
    assert_eq!(
        directory
            .usage_at(now, deadline())
            .unwrap()
            .active_identities,
        16
    );
    let source_id: Vec<u8> = directory
        .state
        .lock()
        .unwrap()
        .db
        .query_row(
            "SELECT source_id FROM discovery_providers_v3 WHERE owner=?1",
            [fixture.signers[16].public_key_id().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(source_id, fixture.sources[1].authenticated_key_id);
}

#[test]
fn history_manifest_and_source_manifest_caps_remain_after_withdrawal() {
    let fixture = Fixture::new(33, 5);
    let directory = fixture.open();
    for owner in 0..8 {
        fixture
            .accept(
                &directory,
                &fixture.record(owner, 1, 1, fixture.now, fixture.end, true),
                0,
                fixture.now,
            )
            .unwrap();
    }
    let ninth = fixture.record(8, 1, 1, fixture.now, fixture.end, true);
    assert_capacity(
        fixture
            .accept(&directory, &ninth, 0, fixture.now)
            .unwrap_err(),
        "discovery replay capacity",
    );
    for owner in 8..32 {
        fixture
            .accept(
                &directory,
                &fixture.record(owner, 1, 1, fixture.now, fixture.end, true),
                owner / 8,
                fixture.now,
            )
            .unwrap();
    }
    assert_capacity(
        fixture
            .accept(
                &directory,
                &fixture.record(32, 1, 1, fixture.now, fixture.end, true),
                4,
                fixture.now,
            )
            .unwrap_err(),
        "discovery replay capacity",
    );
    let usage = directory.usage_at(fixture.now, deadline()).unwrap();
    assert_eq!(
        (usage.active_identities, usage.retained_identities),
        (0, 32)
    );
    assert_eq!(
        directory
            .records(request(1, fixture.now), fixture.now, deadline())
            .unwrap()
            .len(),
        32
    );
}

#[test]
fn expired_or_revoked_provider_authority_releases_active_quota_without_releasing_replay_history() {
    for revoke in [false, true] {
        let mut fixture = Fixture::new(5, 1);
        let mut pins: Vec<_> = fixture.keys.pins().cloned().collect();
        for pin in &mut pins {
            if fixture.signers[..4]
                .iter()
                .any(|key| key.public_key_id() == pin.key_id)
            {
                if revoke {
                    pin.revoked_at = Some(fixture.now + 2);
                } else {
                    pin.expires_at = fixture.now + 2;
                }
            }
        }
        fixture.keys = CellPqKeyPinsV2::new(pins).unwrap();
        let directory = fixture.open();
        for owner in 0..4 {
            fixture
                .accept(
                    &directory,
                    &fixture.record(owner, 1, 1, fixture.now, fixture.end, false),
                    0,
                    fixture.now,
                )
                .unwrap();
        }
        let fifth = fixture.record(4, 1, 1, fixture.now, fixture.end, false);
        assert_capacity(
            fixture
                .accept(&directory, &fifth, 0, fixture.now)
                .unwrap_err(),
            "discovery active capacity",
        );
        let now = fixture.now + 2;
        let usage = directory.usage_at(now, deadline()).unwrap();
        assert_eq!((usage.active_identities, usage.retained_identities), (0, 4));
        fixture.accept(&directory, &fifth, 0, now).unwrap();
        for owner in 0..4 {
            let resurrection = fixture.record(owner, 1, 2, now, fixture.end, false);
            assert!(resurrection
                .verify_at(
                    resurrection.statement().request,
                    time(now),
                    &policy(),
                    &fixture.keys
                )
                .is_err());
        }
        drop(directory);
        let directory = fixture.open();
        let usage = directory.usage_at(now, deadline()).unwrap();
        assert_eq!(
            (
                usage.active_identities,
                usage.retained_identities,
                usage.replay_only_identities
            ),
            (1, 5, 4)
        );
    }
}

fn network_sources() -> Vec<CellDiscoverySourceV3> {
    let addresses = [
        "10.0.0.1", "10.0.0.1", "10.0.0.2", "10.1.0.1", "10.2.0.1", "10.3.0.1", "10.9.0.1",
        "10.0.0.3",
    ];
    addresses
        .iter()
        .enumerate()
        .map(|(index, ip)| CellDiscoverySourceV3 {
            authenticated_key_id: [180 + if index == 6 { 0 } else { index as u8 }; 32],
            generation: if index == 6 { 2 } else { 1 },
            ip: ip.parse().unwrap(),
        })
        .collect()
}

#[test]
fn active_source_ip_and_prefix_limits_reject_before_global_capacity() {
    let fixture = Fixture::with_sources(9, network_sources());
    let directory = fixture.open();
    for index in 0..64 {
        fixture
            .accept(
                &directory,
                &fixture.record(index % 4, index as u64, 1, fixture.now, fixture.end, false),
                0,
                fixture.now,
            )
            .unwrap();
    }
    let next = fixture.record(4, 64, 1, fixture.now, fixture.end, false);
    for source in [0, 1, 6] {
        assert_capacity(
            fixture
                .accept(&directory, &next, source, fixture.now)
                .unwrap_err(),
            "discovery active capacity",
        );
    }
    for index in 64..128 {
        fixture
            .accept(
                &directory,
                &fixture.record(
                    4 + index % 4,
                    index as u64,
                    1,
                    fixture.now,
                    fixture.end,
                    false,
                ),
                2,
                fixture.now,
            )
            .unwrap();
    }
    let next = fixture.record(8, 128, 1, fixture.now, fixture.end, false);
    assert_capacity(
        fixture
            .accept(&directory, &next, 7, fixture.now)
            .unwrap_err(),
        "discovery active capacity",
    );
    fixture.accept(&directory, &next, 3, fixture.now).unwrap();
    assert_eq!(
        directory
            .usage_at(fixture.now, deadline())
            .unwrap()
            .active_identities,
        129
    );
}

#[test]
fn retained_source_ip_prefix_and_global_caps_are_exact_and_epoch_reclaims_all_512() {
    let fixture = Fixture::with_sources(32, network_sources());
    let directory = fixture.open();
    for index in 0..512 {
        let source = match index / 128 {
            0 => 0,
            1 => 2,
            2 => 3,
            _ => 4,
        };
        if index == 128 {
            let candidate = fixture.record(0, index as u64, 1, fixture.now, fixture.end, true);
            for blocked in [0, 1, 6] {
                assert_capacity(
                    fixture
                        .accept(&directory, &candidate, blocked, fixture.now)
                        .unwrap_err(),
                    "discovery replay capacity",
                );
            }
        }
        if index == 256 {
            let candidate = fixture.record(0, index as u64, 1, fixture.now, fixture.end, true);
            assert_capacity(
                fixture
                    .accept(&directory, &candidate, 7, fixture.now)
                    .unwrap_err(),
                "discovery replay capacity",
            );
        }
        fixture
            .accept(
                &directory,
                &fixture.record(index % 32, index as u64, 1, fixture.now, fixture.end, true),
                source,
                fixture.now,
            )
            .unwrap();
    }
    let before = snapshot(&directory);
    let unseen = fixture.record(0, 512, 1, fixture.now, fixture.end, true);
    assert_capacity(
        fixture
            .accept(&directory, &unseen, 5, fixture.now)
            .unwrap_err(),
        "discovery replay capacity",
    );
    assert_eq!(snapshot(&directory), before);
    let usage = directory.usage_at(fixture.now, deadline()).unwrap();
    assert_eq!(
        (
            usage.active_identities,
            usage.retained_identities,
            usage.replay_only_identities
        ),
        (0, 512, 512)
    );
    drop(directory);
    let directory = fixture.open();
    let usage = directory.usage_at(fixture.end, deadline()).unwrap();
    assert_eq!(
        (
            usage.retained_identities,
            usage.reclaimed_closed_epoch_identities
        ),
        (0, 512)
    );
    fixture
        .accept(
            &directory,
            &fixture.record(0, 512, 1, fixture.end, fixture.end + 60, false),
            5,
            fixture.end,
        )
        .unwrap();
}

#[test]
fn randomized_valid_signatures_preserve_durable_wire_and_first_source() {
    let fixture = Fixture::new(1, 2);
    let directory = fixture.open();
    let first = fixture.record(0, 1, 1, fixture.now, fixture.end, false);
    let mut randomized = first.encode();
    let seed = ml_dsa::Seed::from([20; 32]);
    let key = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&seed);
    let mut message = b"TRNM/Cell/Provider/Epoch/ML-DSA-65/v3\0".to_vec();
    message.extend(&randomized[..291]);
    let signature = key
        .expanded_key()
        .sign_internal(&[&[0, 0], &message], &[99; 32].into());
    randomized[291..].copy_from_slice(&signature.encode());
    let second = CellProviderRecordV3::decode(&randomized).unwrap();
    assert_ne!(first.encode(), second.encode());
    assert_eq!(first, second);
    fixture.accept(&directory, &first, 0, fixture.now).unwrap();
    fixture.accept(&directory, &second, 1, fixture.now).unwrap();
    assert_eq!(
        directory
            .records(first.statement().request, fixture.now, deadline())
            .unwrap()[0]
            .encode(),
        first.encode()
    );
    let before = snapshot(&directory);
    let conflict = fixture.record(0, 1, 1, fixture.now, fixture.end - 1, false);
    assert!(fixture
        .accept(&directory, &conflict, 1, fixture.now)
        .is_err());
    assert_eq!(snapshot(&directory), before);
    let state = directory.state.lock().unwrap();
    let source_id: Vec<u8> = state
        .db
        .query_row("SELECT source_id FROM discovery_providers_v3", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(source_id, fixture.sources[0].authenticated_key_id);
}

#[test]
fn sealed_receipts_expire_and_reject_another_authority_without_durable_mutation() {
    let fixture = Fixture::new(1, 1);
    let directory = fixture.open();
    let record = fixture.record(0, 1, 1, fixture.now, fixture.now + 2, false);
    let verified = fixture.verify(&record, fixture.now);
    let before = snapshot(&directory);
    assert!(directory
        .accept_verified(&verified, fixture.sources[0], fixture.now + 2, deadline())
        .is_err());
    assert!(directory
        .accept_verified(&verified, fixture.sources[0], fixture.now - 1, deadline())
        .is_err());
    let mut changed: Vec<_> = fixture.keys.pins().cloned().collect();
    changed[0].revoked_at = Some(fixture.now + 100);
    let other = CellPqKeyPinsV2::new(changed).unwrap();
    let foreign = record
        .verify_at(
            record.statement().request,
            time(fixture.now),
            &policy(),
            &other,
        )
        .unwrap();
    assert!(directory
        .accept_verified(&foreign, fixture.sources[0], fixture.now, deadline())
        .is_err());
    let mut unpinned = fixture.sources[0];
    unpinned.authenticated_key_id[0] ^= 1;
    assert!(directory
        .accept_verified(&verified, unpinned, fixture.now, deadline())
        .is_err());
    assert_eq!(snapshot(&directory), before);
}

#[test]
fn fixed_namespace_provider_and_source_rosters_refuse_migration_and_reopen_changes() {
    let fixture = Fixture::new(1, 1);
    let directory = fixture.open();
    fixture
        .accept(
            &directory,
            &fixture.record(0, 1, 1, fixture.now, fixture.end, false),
            0,
            fixture.now,
        )
        .unwrap();
    drop(directory);
    let mut changed = context();
    changed.namespace[0] ^= 1;
    assert!(CellProviderDirectoryV3::open(
        &fixture.path,
        changed,
        fixture.keys.clone(),
        fixture.source_pins.clone()
    )
    .is_err());
    let mut keys: Vec<_> = fixture.keys.pins().cloned().collect();
    keys[0].revoked_at = Some(fixture.now + 50);
    assert!(CellProviderDirectoryV3::open(
        &fixture.path,
        context(),
        CellPqKeyPinsV2::new(keys).unwrap(),
        fixture.source_pins.clone()
    )
    .is_err());
    let mut source = fixture.sources[0];
    source.generation += 1;
    let sources = CellDiscoverySourcePinsV3::new(vec![CellDiscoverySourcePinV3 {
        authenticated_key_id: source.authenticated_key_id,
        generation: source.generation,
        ip: source.ip,
    }])
    .unwrap();
    assert!(
        CellProviderDirectoryV3::open(&fixture.path, context(), fixture.keys.clone(), sources)
            .is_err()
    );
    assert!(CellProviderDirectoryV2::open(&fixture.path, context(), fixture.keys.clone()).is_err());
    assert!(super::super::super::CellProviderDirectoryV1::open(&fixture.path, context()).is_err());
    let directory = fixture.open();
    assert_eq!(
        directory
            .usage_at(fixture.now, deadline())
            .unwrap()
            .retained_identities,
        1
    );
    drop(directory);
    let old = fixture._temp.path().join("v2.sqlite");
    drop(CellProviderDirectoryV2::open(&old, context(), fixture.keys.clone()).unwrap());
    assert!(CellProviderDirectoryV3::open(
        &old,
        context(),
        fixture.keys.clone(),
        fixture.source_pins.clone()
    )
    .is_err());
}

#[test]
fn source_pins_are_bounded_canonical_and_cannot_multiply_v4_mapped_identity() {
    let pin = CellDiscoverySourcePinV3 {
        authenticated_key_id: [1; 32],
        generation: 1,
        ip: "127.0.0.1".parse().unwrap(),
    };
    assert!(CellDiscoverySourcePinsV3::new(Vec::new()).is_err());
    assert!(CellDiscoverySourcePinsV3::new(vec![pin; 65]).is_err());
    let mapped = CellDiscoverySourcePinV3 {
        ip: "::ffff:127.0.0.1".parse().unwrap(),
        ..pin
    };
    assert_eq!(
        CellDiscoverySourcePinsV3::new(vec![pin]).unwrap().digest(),
        CellDiscoverySourcePinsV3::new(vec![mapped])
            .unwrap()
            .digest()
    );
    assert!(CellDiscoverySourcePinsV3::new(vec![pin, mapped]).is_err());
    assert!(
        CellDiscoverySourcePinsV3::new(vec![CellDiscoverySourcePinV3 {
            generation: 0,
            ..pin
        }])
        .is_err()
    );
    assert!(
        CellDiscoverySourcePinsV3::new(vec![CellDiscoverySourcePinV3 {
            authenticated_key_id: [0; 32],
            ..pin
        }])
        .is_err()
    );
    let other = CellDiscoverySourcePinV3 {
        authenticated_key_id: [2; 32],
        ..pin
    };
    assert_eq!(
        CellDiscoverySourcePinsV3::new(vec![pin, other])
            .unwrap()
            .digest(),
        CellDiscoverySourcePinsV3::new(vec![other, pin])
            .unwrap()
            .digest()
    );
}

#[test]
fn corruption_is_checked_before_retirement_and_overflow_rolls_back_clock_rows_and_refunds() {
    let fixture = Fixture::new(1, 1);
    let directory = fixture.open();
    let record = fixture.record(0, 1, 1, fixture.now, fixture.end, false);
    fixture.accept(&directory, &record, 0, fixture.now).unwrap();
    {
        let state = directory.state.lock().unwrap();
        state
            .db
            .execute(
                "UPDATE discovery_providers_v3 SET expires=?1",
                [(fixture.end - 1).to_be_bytes().as_slice()],
            )
            .unwrap();
    }
    let corrupt = snapshot(&directory);
    assert!(directory.usage_at(fixture.end, deadline()).is_err());
    assert_eq!(snapshot(&directory), corrupt);
    {
        let state = directory.state.lock().unwrap();
        state
            .db
            .execute(
                "UPDATE discovery_providers_v3 SET expires=?1",
                [fixture.end.to_be_bytes().as_slice()],
            )
            .unwrap();
        state
            .db
            .execute(
                "UPDATE discovery_meta_v3 SET reclaimed=?1",
                [u64::MAX.to_be_bytes().as_slice()],
            )
            .unwrap();
    }
    let before = snapshot(&directory);
    assert!(directory.usage_at(fixture.end, deadline()).is_err());
    assert_eq!(snapshot(&directory), before);
    {
        let state = directory.state.lock().unwrap();
        state
            .db
            .execute(
                "UPDATE discovery_meta_v3 SET reclaimed=?1",
                [0u64.to_be_bytes().as_slice()],
            )
            .unwrap();
    }
    let usage = directory.usage_at(fixture.end, deadline()).unwrap();
    assert_eq!(
        (
            usage.retained_identities,
            usage.reclaimed_closed_epoch_identities
        ),
        (0, 1)
    );
    {
        let state = directory.state.lock().unwrap();
        state
            .db
            .execute(
                "UPDATE discovery_meta_v3 SET revision=?1",
                [0u64.to_be_bytes().as_slice()],
            )
            .unwrap();
    }
    assert!(directory.usage_at(fixture.end, deadline()).is_err());
}

fn assert_while_blocked(action: impl FnOnce() -> CellResultV1<()> + Send, release: impl FnOnce()) {
    thread::scope(|scope| {
        let (done_tx, done_rx) = mpsc::channel();
        let worker = scope.spawn(move || done_tx.send(action()).unwrap());
        let result = done_rx.recv_timeout(Duration::from_secs(3));
        release();
        worker.join().unwrap();
        let error = result
            .expect("operation waited for held lock after its deadline")
            .expect_err("contended operation succeeded");
        match error {
            CellErrorV1::Invalid("discovery absolute deadline") => (),
            CellErrorV1::Sql(rusqlite::Error::SqliteFailure(code, _))
                if code.code == rusqlite::ErrorCode::DatabaseBusy => {}
            other => panic!("unexpected deadline failure: {other:?}"),
        }
    });
}

#[test]
fn owner_lock_wait_is_limited_by_sealed_receipt_expiry_without_clock_or_quota_changes() {
    let fixture = Fixture::new(1, 1);
    let directory = fixture.open();
    let short = fixture.record(0, 1, 1, fixture.now, fixture.now + 1, false);
    let receipt = fixture.verify(&short, fixture.now);
    let before = snapshot(&directory);
    let owner = directory.state.lock().unwrap();
    assert_while_blocked(
        || directory.accept_verified(&receipt, fixture.sources[0], fixture.now, deadline()),
        || drop(owner),
    );
    assert_eq!(snapshot(&directory), before);
    fixture
        .accept(
            &directory,
            &fixture.record(0, 1, 1, fixture.now, fixture.end, false),
            0,
            fixture.now,
        )
        .unwrap();
}

#[test]
fn fractional_last_second_receipt_refuses_while_owner_still_holds_lock() {
    let fixture = Fixture::new(1, 1);
    let directory = fixture.open();
    let short = fixture.record(0, 1, 1, fixture.now, fixture.now + 1, false);
    let at = Instant::now();
    let time = CellDiscoveryTimeV3::for_test(
        Duration::from_secs(fixture.now) + Duration::from_millis(900),
        at,
    );
    let receipt = short
        .verify_at(short.statement().request, time, &policy(), &fixture.keys)
        .unwrap();
    assert_eq!(receipt.monotonic_expiry(), at + Duration::from_millis(100));
    let before = snapshot(&directory);
    let owner = directory.state.lock().unwrap();
    assert_while_blocked(
        || directory.accept_verified(&receipt, fixture.sources[0], fixture.now, deadline()),
        || drop(owner),
    );
    assert_eq!(snapshot(&directory), before);
}

#[test]
fn sqlite_writer_and_commit_contention_preserve_deadline_clock_high_water_and_epoch_retirement() {
    for reader_blocks_commit in [false, true] {
        for publish in [false, true] {
            let fixture = Fixture::new(1, 1);
            let directory = fixture.open();
            fixture
                .accept(
                    &directory,
                    &fixture.record(0, 1, 9, fixture.now, fixture.end, false),
                    0,
                    fixture.now,
                )
                .unwrap();
            let next = fixture.record(0, 1, 1, fixture.end, fixture.end + 60, false);
            let receipt = fixture.verify(&next, fixture.end);
            let before = snapshot(&directory);
            directory
                .state
                .lock()
                .unwrap()
                .db
                .busy_timeout(Duration::from_secs(10))
                .unwrap();
            let mut blocker = Connection::open(&fixture.path).unwrap();
            let transaction = blocker
                .transaction_with_behavior(if reader_blocks_commit {
                    TransactionBehavior::Deferred
                } else {
                    TransactionBehavior::Immediate
                })
                .unwrap();
            if reader_blocks_commit {
                let _: u64 = transaction
                    .query_row("SELECT count(*) FROM discovery_meta_v3", [], |row| {
                        row.get(0)
                    })
                    .unwrap();
            }
            assert_while_blocked(
                || {
                    let stop = Instant::now() + Duration::from_millis(100);
                    if publish {
                        directory.accept_verified(&receipt, fixture.sources[0], fixture.end, stop)
                    } else {
                        directory
                            .records(request(1, fixture.end), fixture.end, stop)
                            .map(|_| ())
                    }
                },
                || transaction.rollback().unwrap(),
            );
            assert_eq!(snapshot(&directory), before);
            let restored: u64 = directory
                .state
                .lock()
                .unwrap()
                .db
                .pragma_query_value(None, "busy_timeout", |row| row.get(0))
                .unwrap();
            assert_eq!(restored, 10_000);
            fixture.accept(&directory, &next, 0, fixture.end).unwrap();
            let usage = directory.usage_at(fixture.end, deadline()).unwrap();
            assert_eq!(
                (
                    usage.retained_identities,
                    usage.reclaimed_closed_epoch_identities
                ),
                (1, 1)
            );
            assert!(directory.usage_at(fixture.now, deadline()).is_err());
        }
    }
}
