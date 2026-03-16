use super::*;
#[test]
fn normalized_compliance_profile_accepts_64_char_boundary() {
    let profile = format!("{}-{}", "a".repeat(31), "b".repeat(32));
    assert_eq!(profile.len(), 64);
    assert_eq!(
        normalized_compliance_profile(Some(&profile)).as_deref(),
        Some(profile.as_str())
    );
}

#[test]
fn normalized_compliance_profile_rejects_over_64_chars() {
    let profile = "a".repeat(65);
    assert_eq!(normalized_compliance_profile(Some(&profile)), None);
}

#[test]
fn normalized_compliance_profile_rejects_numeric_only_values() {
    assert_eq!(normalized_compliance_profile(Some("202602")), None);
}

#[test]
fn normalized_compliance_profile_rejects_single_token_values() {
    assert_eq!(normalized_compliance_profile(Some("restricted")), None);
}

#[test]
fn normalized_compliance_profile_accepts_alphanumeric_when_contains_alpha() {
    assert_eq!(
        normalized_compliance_profile(Some("cn-202602")).as_deref(),
        Some("cn-202602")
    );
}

#[test]
fn normalized_compliance_profile_accepts_dot_separators_and_normalizes_to_hyphen() {
    assert_eq!(
        normalized_compliance_profile(Some("CN.PII.Restricted")).as_deref(),
        Some("cn-pii-restricted")
    );
}

#[test]
fn normalized_compliance_profile_accepts_slash_separators_and_normalizes_to_hyphen() {
    assert_eq!(
        normalized_compliance_profile(Some("CN/PII/Restricted")).as_deref(),
        Some("cn-pii-restricted")
    );
}

#[test]
fn normalized_compliance_profile_accepts_backslash_separators_and_normalizes_to_hyphen() {
    assert_eq!(
        normalized_compliance_profile(Some("CN\\PII\\Restricted")).as_deref(),
        Some("cn-pii-restricted")
    );
}

#[test]
fn normalized_compliance_profile_accepts_space_separators_and_normalizes_to_hyphen() {
    assert_eq!(
        normalized_compliance_profile(Some("CN PII Restricted")).as_deref(),
        Some("cn-pii-restricted")
    );
}

#[test]
fn normalized_compliance_profile_rejects_adjacent_space_separators() {
    assert_eq!(
        normalized_compliance_profile(Some("cn  pii restricted")),
        None
    );
}

#[test]
fn normalized_compliance_profile_rejects_control_whitespace_separators() {
    assert_eq!(
        normalized_compliance_profile(Some("cn\tpii restricted")),
        None
    );
}

#[test]
fn normalized_compliance_profile_rejects_newline_separators() {
    assert_eq!(
        normalized_compliance_profile(Some("cn\npii restricted")),
        None
    );
}

#[test]
fn normalized_compliance_profile_rejects_adjacent_dot_separators() {
    assert_eq!(
        normalized_compliance_profile(Some("cn..pii.restricted")),
        None
    );
}

#[test]
fn normalized_compliance_profile_rejects_adjacent_mixed_path_separators() {
    assert_eq!(
        normalized_compliance_profile(Some("cn\\/pii-restricted")),
        None
    );
}

#[test]
fn normalized_compliance_profile_rejects_values_starting_with_digit() {
    assert_eq!(
        normalized_compliance_profile(Some("1cn-pii-restricted")),
        None
    );
}

#[test]
fn normalized_compliance_profile_canonicalizes_underscore_to_hyphen() {
    assert_eq!(
        normalized_compliance_profile(Some("CN_PII_RESTRICTED")).as_deref(),
        Some("cn-pii-restricted")
    );
}
