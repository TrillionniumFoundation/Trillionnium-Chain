use super::*;

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
