use super::*;

#[test]
fn find_numeric_field_rejects_identifier_suffix_spoof() {
    let body = r#"{"not_task_id":7,"task_idx":9}"#;
    assert_eq!(find_numeric_field(body, "task_id"), None);
}

#[test]
fn find_numeric_field_accepts_exact_field_name() {
    let body = r#"{"task_id":7,"worker":"w1"}"#;
    assert_eq!(find_numeric_field(body, "task_id"), Some(7));
}

#[test]
fn find_numeric_field_rejects_trailing_non_delimiter_bytes() {
    let body = r#"{"task_id":7oops,"worker":"w1"}"#;
    assert_eq!(find_numeric_field(body, "task_id"), None);
}

#[test]
fn find_numeric_field_rejects_unclosed_quoted_value() {
    let body = r#"{"task_id":"7,"worker":"w1"}"#;
    assert_eq!(find_numeric_field(body, "task_id"), None);
}

#[test]
fn find_numeric_field_rejects_quoted_value_with_leading_space() {
    let body = r#"{"task_id":" 7","worker":"w1"}"#;
    assert_eq!(find_numeric_field(body, "task_id"), None);
}

#[test]
fn find_numeric_field_rejects_quoted_value_with_trailing_space() {
    let body = r#"{"task_id":"7 ","worker":"w1"}"#;
    assert_eq!(find_numeric_field(body, "task_id"), None);
}

#[test]
fn find_numeric_field_rejects_fullwidth_separator_spoof() {
    let body = "task_id：7,worker=w1";
    assert_eq!(find_numeric_field(body, "task_id"), None);
}

