use super::*;

#[test]
fn parse_u64_kv_value_tolerates_log_token_wrapping() {
    assert_eq!(parse_u64_kv_value("42"), Some(42));
    assert_eq!(parse_u64_kv_value("\"42\","), Some(42));
    assert_eq!(parse_u64_kv_value(" '42';"), Some(42));
    assert_eq!(parse_u64_kv_value("`42`"), Some(42));
    assert_eq!(parse_u64_kv_value("(42)"), Some(42));
    assert_eq!(parse_u64_kv_value("[42]"), Some(42));
    assert_eq!(parse_u64_kv_value("{42}"), Some(42));
    assert_eq!(parse_u64_kv_value("42."), Some(42));
    assert_eq!(parse_u64_kv_value("42:"), Some(42));
    assert_eq!(parse_u64_kv_value("bad42"), None);
    assert_eq!(parse_u64_kv_value("42ms"), None);
}

#[test]
fn parse_u128_kv_value_tolerates_log_token_wrapping_without_suffix_false_positives() {
    assert_eq!(
        parse_u128_kv_value("1700000000123"),
        Some(1_700_000_000_123)
    );
    assert_eq!(
        parse_u128_kv_value("\"1700000000123\","),
        Some(1_700_000_000_123)
    );
    assert_eq!(
        parse_u128_kv_value("(1700000000123)"),
        Some(1_700_000_000_123)
    );
    assert_eq!(
        parse_u128_kv_value("1700000000123."),
        Some(1_700_000_000_123)
    );
    assert_eq!(parse_u128_kv_value("1700000000123ms"), None);
    assert_eq!(parse_u128_kv_value("ts=1700000000123"), None);
}

#[test]
fn parse_i128_kv_value_tolerates_signed_wrapping_without_suffix_false_positives() {
    assert_eq!(parse_i128_kv_value("-42"), Some(-42));
    assert_eq!(parse_i128_kv_value("\"-42\","), Some(-42));
    assert_eq!(parse_i128_kv_value("(+7)"), Some(7));
    assert_eq!(parse_i128_kv_value("-42."), Some(-42));
    assert_eq!(parse_i128_kv_value("-42ms"), None);
    assert_eq!(parse_i128_kv_value("delta=-42"), None);
}
