//! Interval arithmetic controls only; no authenticated service/deployment claim.
use super::*;

fn contract() -> Contract {
    Contract {
        profile: "trnm-m15-boottime-bounded-clock-v1".into(),
        integer_seconds_are_floor: true,
        forward_steps_forbidden: true,
        monotonic_nondecreasing: true,
        maximum_rate_ppm: 1_000_000,
    }
}
fn sample(rate: u32, start: u128) -> Sample {
    let mut contract = contract();
    contract.maximum_rate_ppm = rate;
    Ticket {
        contract,
        start: Stamp {
            boot: [1; 32],
            namespace: (2, 3),
            nanos: start,
        },
    }
    .authenticated(10)
}
fn stamp_at(nanos: u128) -> Stamp {
    Stamp {
        boot: [1; 32],
        namespace: (2, 3),
        nanos,
    }
}

#[test]
fn quantization_upper_boundary_rate_rounding_and_persisted_lower_are_distinct() {
    let value = sample(1_000_000, 100);
    assert_eq!(value.upper_at(&stamp_at(100)).unwrap(), 11 * NS);
    value
        .check_at(
            Validity {
                not_before: 10,
                expires_at: 11,
            },
            &stamp_at(100),
        )
        .unwrap();
    assert!(value
        .check_at(
            Validity {
                not_before: 10,
                expires_at: 11
            },
            &stamp_at(101)
        )
        .is_err());
    assert!(value
        .check_at(
            Validity {
                not_before: 11,
                expires_at: 20
            },
            &stamp_at(100)
        )
        .is_err());
    let fractional = sample(1_000_001, 0);
    assert_eq!(fractional.upper_at(&stamp_at(1)).unwrap(), 11 * NS + 2);
    let fast = sample(2_000_000, 0);
    assert_eq!(fast.upper_at(&stamp_at(NS)).unwrap(), 13 * NS);
    assert_eq!(value.floor_seconds(), 10);
    assert_eq!(fractional.floor_seconds(), 10);
    assert_eq!(fast.floor_seconds(), 10);
}

#[test]
fn boot_namespace_backwards_elapsed_overflow_and_budget_refuse() {
    let value = sample(2_000_000, 10);
    let mut boot = stamp_at(10);
    boot.boot[0] ^= 1;
    let mut namespace = stamp_at(10);
    namespace.namespace.1 += 1;
    for current in [
        boot,
        namespace,
        stamp_at(9),
        stamp_at(u128::MAX),
        stamp_at(2 * NS + 11),
    ] {
        assert!(value.checked_upper(&current).is_err());
    }
    assert_eq!(value.floor_seconds(), 10);
}

#[test]
fn clock_contract_has_no_default_and_requires_both_direction_and_rate_bounds() {
    let valid = contract();
    valid.validate().unwrap();
    let raw = serde_json::to_value(&valid).unwrap();
    for field in [
        "profile",
        "integer_seconds_are_floor",
        "forward_steps_forbidden",
        "monotonic_nondecreasing",
        "maximum_rate_ppm",
    ] {
        let mut missing = raw.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<Contract>(missing).is_err());
    }
    for cut in 0..6 {
        let mut bad = valid.clone();
        match cut {
            0 => bad.profile.push('x'),
            1 => bad.integer_seconds_are_floor = false,
            2 => bad.forward_steps_forbidden = false,
            3 => bad.monotonic_nondecreasing = false,
            4 => bad.maximum_rate_ppm = 999_999,
            _ => bad.maximum_rate_ppm = 2_000_001,
        }
        assert!(bad.validate().is_err());
    }
}
