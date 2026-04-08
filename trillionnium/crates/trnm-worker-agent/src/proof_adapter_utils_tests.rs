#[test]
fn has_non_empty_auditable_value_handles_whitespace_and_quotes() {
    assert!(!super::has_non_empty_auditable_value(None));
    assert!(!super::has_non_empty_auditable_value(Some("   \"\"   ")));
    assert!(super::has_non_empty_auditable_value(Some("abc")));
}
