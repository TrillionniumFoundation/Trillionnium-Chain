use super::*;

#[test]
fn find_token_field_rejects_identifier_prefix_spoof() {
    let body = "xproof_type=zk,proof_type=tee";
    assert_eq!(
        find_token_field(body, "proof_type"),
        Some("tee".to_string())
    );
}

#[test]
fn find_token_field_rejects_identifier_suffix_spoof() {
    let body = "proof_typex=zk,proof_type=tee";
    assert_eq!(
        find_token_field(body, "proof_type"),
        Some("tee".to_string())
    );
}

#[test]
fn find_token_field_rejects_trailing_non_delimiter_bytes() {
    let body = "proof_type=tee%2Cfraud";
    assert_eq!(find_token_field(body, "proof_type"), None);
}

#[test]
fn find_token_field_rejects_quoted_value_with_trailing_space_before_quote() {
    let body = r#"worker=\"worker1 \""#;
    assert_eq!(find_token_field(body, "worker"), None);
}

#[test]
fn find_token_field_rejects_quoted_value_with_leading_space_after_quote() {
    let body = r#"worker=\" worker1\""#;
    assert_eq!(find_token_field(body, "worker"), None);
}

#[test]
fn find_token_field_rejects_unclosed_quoted_value() {
    let body = r#"proof_type=\"tee"#;
    assert_eq!(find_token_field(body, "proof_type"), None);
}

