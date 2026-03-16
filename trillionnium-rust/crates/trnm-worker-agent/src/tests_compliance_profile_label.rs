use super::*;
#[test]
fn normalized_provenance_label_accepts_ascii_audit_text() {
    assert_eq!(
        normalized_provenance_label(Some("openai gpt-5.3:preview"), 64).as_deref(),
        Some("openai gpt-5.3:preview")
    );
}

#[test]
fn normalized_provenance_label_rejects_non_ascii_homoglyphs() {
    assert_eq!(
        normalized_provenance_label(Some("оpenai"), 64),
        None,
        "non-ascii provenance labels should be rejected to avoid audit ambiguity"
    );
}

#[test]
fn normalized_provenance_label_rejects_embedded_control_characters() {
    assert_eq!(
        normalized_provenance_label(Some("openai\nmodel"), 64),
        None,
        "embedded control chars should fail-closed for provenance labels"
    );
}
