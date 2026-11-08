//! Red control for unchanged 0dc13a92 discovery V2. Include as a child module
//! of cell::discovery::pq in a separate exact-baseline worktree. No mock verifier
//! or forged wire is used: all seventeen keys are real, explicitly pinned ones.

use super::*;
use crate::cell::pq::CellPqKeyPinV2;
use std::{net::IpAddr, time::{Duration, Instant}};
use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;
use zeroize::Zeroizing;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

#[test]
fn pq_expired_prior_operations_cannot_permanently_exclude_a_new_pinned_provider() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("discovery.sqlite");
    let context = CellDiscoveryContextV1 {
        namespace: [0x51; 32],
        network: [0x52; 32],
        parameters: [0x53; 32],
        genesis: [0x54; 32],
    };
    let request = CellDiscoveryRequestV1 {
        context,
        cell_context: [0x55; 32],
        manifest: [0x56; 32],
    };
    let endpoint = "127.0.0.1:31001".parse().unwrap();
    let policy = CellDiscoveryAddressPolicyV1::LoopbackDevOnly {
        ports: vec![31001],
    };
    let mut owners = Vec::new();
    let mut pins = Vec::new();
    for seed_byte in 1_u8..=17 {
        let seed = Zeroizing::new([seed_byte; 32]);
        let spki = PqNativeSigningKey::public_spki_from_seed(&seed);
        let key_id = ml_dsa_65_key_id_from_spki(&spki).unwrap();
        owners.push(PqNativeSigningKey::from_owned_seed(seed, key_id).unwrap());
        pins.push(CellPqKeyPinV2 {
            key_id,
            generation: 1,
            spki,
            not_before: 1,
            expires_at: u64::MAX,
            revoked_at: None,
        });
    }
    let pins = CellPqKeyPinsV2::new(pins).unwrap();
    let now = 1_800_000_001_u64;
    for (index, key) in owners[..16].iter().enumerate() {
        let directory = CellProviderDirectoryV2::open(&path, context, pins.clone()).unwrap();
        let record = CellProviderRecordV2::sign(
            CellProviderStatementV2 {
                request,
                owner: key.public_key_id(),
                owner_generation: 1,
                endpoint,
                sequence: 1,
                issued_unix_seconds: now,
                expires_unix_seconds: now + 1,
                withdrawn: false,
            },
            key,
        ).unwrap();
        record.verify_at(request, now, &policy, &pins).unwrap();
        let source: IpAddr = format!("127.0.0.{}", 1 + index / 4).parse().unwrap();
        directory.accept_verified(&record, source, now, deadline()).unwrap();
    }

    let later = now + 601;
    let directory = CellProviderDirectoryV2::open(&path, context, pins.clone()).unwrap();
    let retained = directory.records(request, later, deadline()).unwrap();
    assert_eq!(retained.len(), 16);
    assert!(retained.iter().all(|r| r.live_at(later).is_err()));
    drop(directory);
    let directory = CellProviderDirectoryV2::open(&path, context, pins.clone()).unwrap();
    assert_eq!(directory.usage().unwrap().retained_identities, 16);

    let key = &owners[16];
    let honest = CellProviderRecordV2::sign(
        CellProviderStatementV2 {
            request,
            owner: key.public_key_id(),
            owner_generation: 1,
            endpoint,
            sequence: 1,
            issued_unix_seconds: later,
            expires_unix_seconds: later + 30,
            withdrawn: false,
        },
        key,
    ).unwrap();
    honest.verify_at(request, later, &policy, &pins).unwrap();
    let admitted = directory.accept_verified(
        &honest, "127.0.0.9".parse().unwrap(), later, deadline(),
    );
    assert!(admitted.is_ok(), "expired pinned identities permanently exclude a fresh pinned provider: {admitted:?}");
}
