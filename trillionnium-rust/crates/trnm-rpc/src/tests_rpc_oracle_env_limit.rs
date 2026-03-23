use super::*;

#[test]
fn clamp_limit_enforces_max() {
    let got = clamp_limit(
        "QueryEvents",
        QUERY_EVENTS_LIMIT_MAX + 1,
        QUERY_EVENTS_LIMIT_DEFAULT,
        QUERY_EVENTS_LIMIT_MAX,
    );
    assert_eq!(got, QUERY_EVENTS_LIMIT_MAX);
}

#[test]
fn clamp_limit_uses_default_when_zero() {
    let got = clamp_limit(
        "DispatchOpen",
        0,
        DISPATCH_OPEN_LIMIT_DEFAULT,
        DISPATCH_OPEN_LIMIT_MAX,
    );
    assert_eq!(got, DISPATCH_OPEN_LIMIT_DEFAULT);
}

#[test]
fn clamp_limit_keeps_in_range_value() {
    let got = clamp_limit(
        "QueryRequestFull",
        17,
        QUERY_FULL_LIMIT_DEFAULT,
        QUERY_FULL_LIMIT_MAX,
    );
    assert_eq!(got, 17);
}

#[test]
fn clamp_limit_clamps_oversized_default_when_zero_requested() {
    let got = clamp_limit("FeeBoundaryPrep", 0, 9, 4);
    assert_eq!(got, 4);
}
