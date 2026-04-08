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
