//! Freeze the public authority-session admission surface.
//!
//! This is a source-shape regression in addition to the behavioral black-box
//! tests. It prevents a convenience method from silently reopening naked
//! ingress or stage-digest mutation authority.

#[test]
fn production_session_exports_verified_tokens_not_naked_digest_mutators() {
    let source = include_str!("../src/lib.rs");

    for forbidden in [
        "pub fn begin_prepared(",
        "pub fn begin_digest(",
        "pub fn advance(\n",
        "pub fn advance_digest(",
    ] {
        assert!(
            !source.contains(forbidden),
            "public naked authority mutation surface reintroduced: {forbidden}"
        );
    }

    for required in [
        "pub trait AuthorityIngressSourceV0",
        "pub struct VerifiedAuthorityIngressV0",
        "pub fn verify_ingress<",
        "pub fn begin_verified(",
        "pub trait AuthorityFactSourceV0",
        "pub struct VerifiedAuthorityFactV0",
        "pub fn verify_fact<",
        "pub fn advance_verified(",
    ] {
        assert!(
            source.contains(required),
            "verified authority boundary missing: {required}"
        );
    }
}

#[test]
fn verification_tokens_are_not_cloneable_or_publicly_constructible() {
    let source = include_str!("../src/lib.rs");

    for declaration in [
        "pub struct VerifiedAuthorityIngressV0 {",
        "pub struct VerifiedAuthorityFactV0 {",
    ] {
        let start = source.find(declaration).expect("token declaration");
        let prefix = &source[start.saturating_sub(160)..start];
        assert!(
            !prefix.contains("Clone"),
            "authority verification token became Clone: {declaration}"
        );
    }

    assert!(!source.contains("pub const fn new_verified_authority"));
    assert!(!source.contains("pub fn new_verified_authority"));
}
