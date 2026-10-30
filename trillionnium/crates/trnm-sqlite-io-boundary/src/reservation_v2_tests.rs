//! Ledger transition controls, not real filesystem or full-component evidence.
use super::*;

fn v2() -> Ledger {
    Ledger::with_policy(GrowthPolicy::Reserve64KiBV2)
}
fn identity(number: u64) -> Identity {
    Identity {
        dev: 7,
        ino: number,
    }
}
fn water(ledger: &Ledger, slot: usize) -> u64 {
    ledger.slots[slot]
        .as_ref()
        .unwrap()
        .receipt
        .high_water_bytes
}

#[test]
fn original_v1_exact_growth_and_event_serialization_remain() {
    let mut ledger = Ledger::new();
    let slot = ledger.reserve_open("native.sqlite", true).unwrap();
    ledger.bind(slot, identity(1), 0, 0, true).unwrap();
    ledger.reserve_growth(slot, 1).unwrap();
    ledger.reserve_growth(slot, 2).unwrap();
    assert_eq!(water(&ledger, slot), 2);
    assert_eq!(ledger.lifecycle.len(), 4);
    assert_eq!(ledger.policy().domain(), DOMAIN);
    assert_eq!(ledger.policy().quantum(), None);
    let raw = serde_json::to_string(&ledger.lifecycle[3]).unwrap();
    assert_eq!(raw, "{\"sequence\":3,\"action\":\"reserve-growth\",\"generation\":1,\"basename\":\"native.sqlite\",\"device\":7,\"inode\":1,\"linked\":true,\"handles\":0,\"pending_opens\":0,\"shm_references\":0,\"high_water_bytes\":2,\"actual_last_bytes\":0}");
    // The V1 post-observation behavior remains confined to its old domain.
    ledger.bind(slot, identity(1), 3, 0, true).unwrap();
    assert_eq!(water(&ledger, slot), 3);
    assert_eq!(ledger.lifecycle.len(), 4);
}

#[test]
fn v2_every_page_to_three_original_inode_caps_has_recorded_reservation() {
    assert_eq!(FILE_BYTES, 16 * 1024 * 1024);
    assert_eq!(GROWTH_QUANTUM_BYTES_V2, 64 * 1024);
    assert_eq!(OBJECTS_PER_ROOT, 3);
    let mut ledger = v2();
    for (index, name) in ["native.sqlite", "native.sqlite-wal", "native.sqlite-shm"]
        .iter()
        .enumerate()
    {
        let slot = ledger.reserve_open(name, index == 0).unwrap();
        ledger
            .bind(slot, identity(index as u64 + 1), 0, 0, true)
            .unwrap();
        for endpoint in (4096..=FILE_BYTES).step_by(4096) {
            let events_before = ledger.lifecycle.len();
            let reservation_before = water(&ledger, slot);
            ledger.reserve_growth(slot, endpoint).unwrap();
            let reserved = water(&ledger, slot);
            assert!(endpoint <= reserved && reserved <= FILE_BYTES);
            assert_eq!(reserved % GROWTH_QUANTUM_BYTES_V2, 0);
            if endpoint > reservation_before {
                assert_eq!(ledger.lifecycle.len(), events_before + 1);
                let event = ledger.lifecycle.last().unwrap();
                assert_eq!(event.requested_endpoint, Some(endpoint));
                assert_eq!(event.high_water_bytes, reserved);
            } else {
                assert_eq!(ledger.lifecycle.len(), events_before);
            }
            // Simulated post-I/O observation never supplies additional credit.
            ledger
                .bind(slot, identity(index as u64 + 1), endpoint, 0, true)
                .unwrap();
        }
    }
    assert_eq!(ledger.lifecycle.len(), 3 * (2 + 256));
    assert_eq!(ledger.retained_logical_bytes_peak, 3 * FILE_BYTES);
    assert!(ledger.failed.is_none());
    assert!(ledger.lifecycle_complete);
    assert_eq!(
        ledger.reserve_open("native.sqlite-journal", false),
        Err(ffi::SQLITE_FULL)
    );
    assert_eq!(ledger.first_failure_code, Some(ffi::SQLITE_FULL));
}

#[test]
fn v2_subquantum_writes_do_not_drop_or_rewrite_reservation_events() {
    let mut ledger = v2();
    let slot = ledger.reserve_open("native.sqlite", true).unwrap();
    ledger.bind(slot, identity(1), 0, 0, true).unwrap();
    ledger.reserve_growth(slot, 1).unwrap();
    let retained = serde_json::to_vec(&ledger.lifecycle).unwrap();
    for endpoint in [
        2,
        24,
        4096,
        GROWTH_QUANTUM_BYTES_V2 - 1,
        GROWTH_QUANTUM_BYTES_V2,
    ] {
        ledger.reserve_growth(slot, endpoint).unwrap();
        ledger.bind(slot, identity(1), endpoint, 0, true).unwrap();
        assert_eq!(serde_json::to_vec(&ledger.lifecycle).unwrap(), retained);
        assert_eq!(water(&ledger, slot), GROWTH_QUANTUM_BYTES_V2);
    }
    ledger
        .reserve_growth(slot, GROWTH_QUANTUM_BYTES_V2 + 1)
        .unwrap();
    assert_eq!(ledger.lifecycle.len(), 4);
    assert_eq!(water(&ledger, slot), 2 * GROWTH_QUANTUM_BYTES_V2);
}

#[test]
fn v2_post_io_first_bind_cannot_retroactively_authorize_growth() {
    let mut ledger = v2();
    let slot = ledger.reserve_open("native.sqlite", true).unwrap();
    assert_eq!(
        ledger.bind(slot, identity(1), 1, 1, true),
        Err(ffi::SQLITE_FULL)
    );
    assert_eq!(water(&ledger, slot), 0);
    assert_eq!(ledger.lifecycle.len(), 1);
    assert_eq!(ledger.first_failure_code, Some(ffi::SQLITE_FULL));
    assert_eq!(ledger.reserve_growth(slot, 1), Err(ffi::SQLITE_IOERR));
}

#[test]
fn v2_initial_existing_observation_is_explicit_and_cannot_be_repeated_for_credit() {
    let mut ledger = v2();
    let slot = ledger.reserve_open("native.sqlite", true).unwrap();
    ledger
        .observe_existing_before_io(slot, identity(1), 1, 1, true)
        .unwrap();
    let event = ledger.lifecycle.last().unwrap();
    assert_eq!(event.action, "bind-existing-before-io-v2");
    assert_eq!(event.requested_endpoint, Some(1));
    assert_eq!(event.high_water_bytes, GROWTH_QUANTUM_BYTES_V2);
    assert_eq!(
        ledger.observe_existing_before_io(slot, identity(1), GROWTH_QUANTUM_BYTES_V2 + 1, 1, true),
        Err(ffi::SQLITE_FULL)
    );
    assert_eq!(water(&ledger, slot), GROWTH_QUANTUM_BYTES_V2);
    assert_eq!(ledger.lifecycle.len(), 2);
}

#[test]
fn v2_shm_can_bind_only_within_its_prior_unbound_reservation() {
    let mut ledger = v2();
    let slot = ledger.reserve_open("native.sqlite-shm", false).unwrap();
    ledger.reserve_growth(slot, 3).unwrap();
    ledger.bind(slot, identity(3), 32768, 1, true).unwrap();
    let event = ledger.lifecycle.last().unwrap();
    assert_eq!(event.action, "bind-real-inode");
    assert_eq!(event.requested_endpoint, None);
    assert_eq!(event.high_water_bytes, GROWTH_QUANTUM_BYTES_V2);
    assert_eq!(
        ledger.bind(slot, identity(3), GROWTH_QUANTUM_BYTES_V2 + 1, 1, true),
        Err(ffi::SQLITE_FULL)
    );
    assert_eq!(ledger.lifecycle.len(), 3);
}

#[test]
fn v2_cap_is_checked_before_rounding_and_no_failure_refund_occurs() {
    for endpoint in [FILE_BYTES + 1, u64::MAX] {
        let mut ledger = v2();
        let slot = ledger.reserve_open("native.sqlite", true).unwrap();
        ledger.bind(slot, identity(1), 0, 0, true).unwrap();
        ledger.reserve_growth(slot, FILE_BYTES).unwrap();
        let count = ledger.lifecycle.len();
        assert_eq!(ledger.reserve_growth(slot, endpoint), Err(ffi::SQLITE_FULL));
        assert_eq!(water(&ledger, slot), FILE_BYTES);
        assert_eq!(ledger.lifecycle.len(), count);
        assert_eq!(ledger.reserve_growth(slot, 0), Err(ffi::SQLITE_IOERR));
    }
}

#[test]
fn v2_unlinked_open_object_keeps_full_reservation_until_underlying_close() {
    let mut ledger = v2();
    let slot = ledger.reserve_open("native.sqlite-journal", false).unwrap();
    ledger.bind(slot, identity(2), 0, 0, true).unwrap();
    ledger.reserve_handle(slot).unwrap();
    ledger.opened(slot).unwrap();
    ledger.reserve_growth(slot, 1).unwrap();
    ledger.unlinked(slot);
    assert_eq!(water(&ledger, slot), GROWTH_QUANTUM_BYTES_V2);
    assert_eq!(ledger.slots[slot].as_ref().unwrap().receipt.handles, 1);
    ledger.close_handle(slot);
    assert!(ledger.slots[slot].is_none());
    assert_eq!(ledger.cleanup.len(), 2);
    assert_eq!(ledger.cleanup[1].high_water_bytes, GROWTH_QUANTUM_BYTES_V2);
}

#[test]
fn v2_original_evidence_margin_admits_last_handle_then_retains_cleanup() {
    let mut ledger = v2();
    for (index, name) in [
        "native.sqlite",
        "native.sqlite-wal",
        "native.sqlite-journal",
    ]
    .iter()
    .enumerate()
    {
        let slot = ledger.reserve_open(name, index == 0).unwrap();
        ledger
            .bind(slot, identity(index as u64 + 1), 0, 0, true)
            .unwrap();
        for endpoint in (1..FILE_BYTES).step_by(GROWTH_QUANTUM_BYTES_V2 as usize) {
            ledger.reserve_growth(slot, endpoint).unwrap();
        }
        ledger
            .bind(slot, identity(index as u64 + 1), FILE_BYTES, 0, true)
            .unwrap();
    }
    // Actual Ledger transitions, not direct insertion of fictitious records.
    assert_eq!(ledger.lifecycle.len(), 774);
    for _ in 0..121 {
        ledger.reserve_handle(0).unwrap();
        ledger.opened(0).unwrap();
        ledger.close_handle(0);
    }
    assert_eq!(ledger.lifecycle.len(), 1016);
    ledger.reserve_handle(0).unwrap();
    assert_eq!(ledger.lifecycle.len(), 1017);
    // opened consumes the already reserved margin; underlying cleanup remains
    // available even though a subsequent admission must fail.
    ledger.opened(0).unwrap();
    ledger.close_handle(0);
    assert_eq!(ledger.lifecycle.len(), 1018);
    assert_eq!(ledger.cleanup.len(), 122);
    assert!(ledger.failed.is_none());
    assert_eq!(ledger.reserve_handle(0), Err(ffi::SQLITE_FULL));
    assert_eq!(ledger.first_failure_code, Some(ffi::SQLITE_FULL));
    assert_eq!(
        ledger.failed.as_deref(),
        Some("bounded lifecycle evidence capacity")
    );
    assert_eq!(ledger.lifecycle.len(), 1018);
}

#[test]
fn v2_named_pre_io_observation_cannot_claim_an_unlinked_inode() {
    let mut ledger = v2();
    let slot = ledger.reserve_open("native.sqlite", true).unwrap();
    assert_eq!(
        ledger.observe_existing_before_io(slot, identity(1), 1, 1, false),
        Err(ffi::SQLITE_IOERR)
    );
    assert_eq!(water(&ledger, slot), 0);
    assert!(ledger.slots[slot].as_ref().unwrap().identity.is_none());
    assert_eq!(ledger.lifecycle.len(), 1);
    assert_eq!(
        ledger.failed.as_deref(),
        Some("named pre-I/O observation must be linked")
    );
}
