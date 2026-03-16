use super::*;

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
fn normalized_compliance_profile_canonicalizes_underscore_to_hyphen() {
    assert_eq!(
        normalized_compliance_profile(Some("CN_PII_RESTRICTED")).as_deref(),
        Some("cn-pii-restricted")
    );
}
