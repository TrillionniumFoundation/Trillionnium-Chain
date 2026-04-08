use super::*;

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
fn normalized_compliance_profile_rejects_values_starting_with_digit() {
    assert_eq!(
        normalized_compliance_profile(Some("1cn-pii-restricted")),
        None
    );
}
