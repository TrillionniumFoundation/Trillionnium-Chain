//! Red control for unchanged 0dc13a92 discovery V1. Include as a child module
//! of cell::discovery in a separate exact-baseline worktree. This deliberately
//! asserts the desired reclamation behavior, so the old implementation fails.

use super::*;
use std::{net::IpAddr, time::{Duration, Instant}};

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

#[test]
fn expired_prior_operations_cannot_permanently_exclude_a_new_signed_provider() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("discovery.sqlite");
    let context = CellDiscoveryContextV1 {
        namespace: [0x41; 32],
        network: [0x42; 32],
        parameters: [0x43; 32],
        genesis: [0x44; 32],
    };
    let request = CellDiscoveryRequestV1 {
        context,
        cell_context: [0x45; 32],
        manifest: [0x46; 32],
    };
    let endpoint = "127.0.0.1:31001".parse().unwrap();
    let policy = CellDiscoveryAddressPolicyV1::LoopbackDevOnly {
        ports: vec![31001],
    };
    let now = 1_800_000_001_u64;
    for owner in 1_u8..=16 {
        // Every operation reopens the durable owner. No individual reply or
        // transport batch is large enough to explain the eventual saturation.
        let directory = CellProviderDirectoryV1::open(&path, context).unwrap();
        let key = SigningKey::from_bytes(&[owner; 32]);
        let record = CellProviderRecordV1::sign(
            CellProviderStatementV1 {
                request,
                owner: key.verifying_key().to_bytes(),
                endpoint,
                sequence: 1,
                issued_unix_seconds: now,
                expires_unix_seconds: now + 1,
            },
            &key,
        ).unwrap();
        record.verify_at(request, now, &policy).unwrap();
        let source: IpAddr = format!("127.0.0.{}", 1 + (owner - 1) / 4).parse().unwrap();
        directory.accept_verified(&record, source, now, deadline()).unwrap();
    }

    // The clock advances beyond both every lease and two V3-sized windows.
    // V1 still stores all sixteen identities after observation and restart.
    let later = now + 601;
    let directory = CellProviderDirectoryV1::open(&path, context).unwrap();
    let retained = directory.records(request, later, deadline()).unwrap();
    assert_eq!(retained.len(), 16);
    assert!(retained.iter().all(|r| r.live_at(later).is_err()));
    drop(directory);
    let directory = CellProviderDirectoryV1::open(&path, context).unwrap();
    assert_eq!(directory.usage().unwrap().retained_identities, 16);

    let key = SigningKey::from_bytes(&[17; 32]);
    let honest = CellProviderRecordV1::sign(
        CellProviderStatementV1 {
            request,
            owner: key.verifying_key().to_bytes(),
            endpoint,
            sequence: 1,
            issued_unix_seconds: later,
            expires_unix_seconds: later + 30,
        },
        &key,
    ).unwrap();
    honest.verify_at(request, later, &policy).unwrap();
    let admitted = directory.accept_verified(
        &honest, "127.0.0.9".parse().unwrap(), later, deadline(),
    );
    assert!(admitted.is_ok(), "expired identities permanently exclude a fresh signed provider: {admitted:?}");
}
