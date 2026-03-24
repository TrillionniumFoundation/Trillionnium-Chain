use super::*;

#[test]
fn resolve_authority_role_separation_merge_gate_constants_remain_distinct() {
    // Merge-gate hardening: custody (escrow), governance placeholder, and reserved
    // system identities must remain disjoint. If any collide, resolver authorization
    // checks can silently degrade into centralized/single-party control.
    let escrow = CHALLENGE_ESCROW_ACCOUNT.trim();
    let forfeits = CHALLENGE_FORFEIT_TREASURY_ACCOUNT.trim();
    let worker_slash = WORKER_SLASH_TREASURY_ACCOUNT.trim();
    let placeholder = DEFAULT_RESOLVE_AUTHORITY.trim();
    let system = "system";

    assert!(!escrow.is_empty());
    assert!(!forfeits.is_empty());
    assert!(!worker_slash.is_empty());
    assert!(!placeholder.is_empty());
    assert_ne!(escrow, forfeits);
    assert_ne!(escrow, worker_slash);
    assert_ne!(forfeits, worker_slash);
    assert_ne!(escrow, placeholder);
    assert_ne!(forfeits, placeholder);
    assert_ne!(worker_slash, placeholder);
    assert_ne!(escrow, system);
    assert_ne!(forfeits, system);
    assert_ne!(worker_slash, system);
    assert_ne!(placeholder, system);
    assert_ne!(placeholder.to_ascii_lowercase(), system);
}

#[test]
fn resolve_role_accounts_remain_case_insensitively_disjoint() {
    // Hardening invariant: reserved/system, custody, and governance placeholder
    // identities must remain disjoint even after normalization so case-drift cannot
    // collapse minimal multi-party control into a single authority string.
    let normalized = [
        CHALLENGE_ESCROW_ACCOUNT.trim().to_ascii_lowercase(),
        CHALLENGE_FORFEIT_TREASURY_ACCOUNT
            .trim()
            .to_ascii_lowercase(),
        WORKER_SLASH_TREASURY_ACCOUNT.trim().to_ascii_lowercase(),
        DEFAULT_RESOLVE_AUTHORITY.trim().to_ascii_lowercase(),
        "system".to_string(),
    ];

    for value in &normalized {
        assert!(
            !value.is_empty(),
            "normalized authority/control identifier must be non-empty"
        );
    }

    for i in 0..normalized.len() {
        for j in (i + 1)..normalized.len() {
            assert_ne!(
                normalized[i], normalized[j],
                "normalized identifiers must remain disjoint to preserve multi-party control"
            );
        }
    }
}
