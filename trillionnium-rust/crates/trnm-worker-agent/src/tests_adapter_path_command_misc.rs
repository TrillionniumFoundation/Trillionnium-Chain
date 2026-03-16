use super::*;
#[test]
fn truncate_for_error_marks_truncated_payloads() {
    let raw = "x".repeat(600);
    let truncated = truncate_for_error(&raw, 32);
    assert!(truncated.starts_with("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
    assert!(truncated.contains("truncated"));
    assert!(truncated.contains("600 chars total"));
}
