use super::*;

#[test]
fn resolve_rejects_non_ascii_separator_in_authority_set_without_escrow_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority-a，authority-b");

    let r1 = apply_create_task(&mut st, 8_962_1, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_962_1, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();
    let pending_task_id = r5.id;

    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let err = apply_resolve(
            &mut st,
            r5,
            true,
            "authority-a".into(),
            "authority-a".into(),
        )
        .expect_err(
            "non-ASCII separator must be rejected so resolver sets cannot degrade into ambiguous single-signer authority",
        );
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(8_962_1).unwrap();
    assert_eq!(task.status, TaskStatus::Challenged);
    assert_eq!(task.challenge_bond_forfeited, None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), 90);
    assert_eq!(st.pending_resolve_approval(pending_task_id), None);
}
#[test]

fn resolve_rejects_control_char_authority_member_without_escrow_mutation() {
    // Canonical signer hardening: invisible control bytes must never be
    // accepted as authority members.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority\u{0000}");

    let r1 = apply_create_task(&mut st, 8_966_9, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_966_9, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let err = apply_resolve(
        &mut st,
        r5,
        true,
        "authority\u{0000}".into(),
        "authority\u{0000}".into(),
    )
    .expect_err("authority members with control bytes must be rejected");
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(8_966_9).unwrap();
    assert_eq!(task.status, TaskStatus::Challenged);
    assert_eq!(task.challenge_bond_forfeited, None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), 90);
}
#[test]

fn resolve_rejects_semicolon_delimited_signer_without_escrow_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority");

    let r1 = apply_create_task(&mut st, 8_967_0, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_967_0, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let err = apply_resolve(
            &mut st,
            r5,
            true,
            "authority;shadow".into(),
            "authority;shadow".into(),
        )
        .expect_err("semicolon-delimited signer tokens must be rejected to preserve canonical authority identity");
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(8_967_0).unwrap();
    assert_eq!(task.status, TaskStatus::Challenged);
    assert_eq!(task.challenge_bond_forfeited, None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), 90);
}
#[test]

fn resolve_rejects_non_ascii_authority_member_without_escrow_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    // Canonical identity hardening: non-ASCII authority ids can enable
    // homoglyph spoofing and must fail closed.
    let spoofed_authority = "authоrity"; // Cyrillic 'о' (U+043E)
    set_resolve_authority(&mut st, spoofed_authority);

    let r1 = apply_create_task(&mut st, 8_967_3, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_967_3, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let err = apply_resolve(
        &mut st,
        r5,
        true,
        spoofed_authority.into(),
        spoofed_authority.into(),
    )
    .expect_err("non-ASCII resolve authority ids must be rejected");
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(8_967_3).unwrap();
    assert_eq!(task.status, TaskStatus::Challenged);
    assert_eq!(task.challenge_bond_forfeited, None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), 90);
}
#[test]

fn resolve_rejects_non_ascii_signer_payload_without_escrow_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority");

    let r1 = apply_create_task(&mut st, 8_967_4, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_967_4, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    // Canonical identity hardening: signer/resolver payloads must be ASCII-only
    // account IDs so homoglyph spoofing cannot bypass authority checks.
    let spoofed_signer = "authоrity"; // Cyrillic 'о' (U+043E)
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let err = apply_resolve(
        &mut st,
        r5,
        true,
        spoofed_signer.into(),
        spoofed_signer.into(),
    )
    .expect_err("non-ASCII signer/resolver payload must be rejected");
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(8_967_4).unwrap();
    assert_eq!(task.status, TaskStatus::Challenged);
    assert_eq!(task.challenge_bond_forfeited, None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), 90);
}
#[test]

fn resolve_rejects_non_ascii_resolver_payload_without_escrow_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority");

    let r1 = apply_create_task(&mut st, 8_967_5, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_967_5, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    // Canonical identity hardening: resolver payload must remain ASCII-only
    // even when signer is a valid configured authority.
    let spoofed_resolver = "authоrity"; // Cyrillic 'о' (U+043E)
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let err = apply_resolve(
        &mut st,
        r5,
        true,
        spoofed_resolver.into(),
        "authority".into(),
    )
    .expect_err("non-ASCII resolver payload must be rejected");
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(8_967_5).unwrap();
    assert_eq!(task.status, TaskStatus::Challenged);
    assert_eq!(task.challenge_bond_forfeited, None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), 90);
}
#[test]

fn resolve_rejects_case_drift_in_authority_payload_without_escrow_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "Authority");

    let r1 = apply_create_task(&mut st, 9_000, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(9_000, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before = st.clone();
    let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
        .expect_err("case-drifted payload must not authorize resolve actor");
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(9_000).unwrap();
    assert_eq!(task.status, TaskStatus::Challenged);
    assert_eq!(task.challenge_bond_forfeited, None);
    assert_eq!(st.balance_of("challenger"), before.balance_of("challenger"));
    assert_eq!(
        st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
        before.balance_of(CHALLENGE_ESCROW_ACCOUNT)
    );
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
    );
}
#[test]

fn resolve_rejects_signer_with_forbidden_separator_without_escrow_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority");

    let r1 = apply_create_task(&mut st, 9_001_72, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(9_001_72, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before = st.clone();
    let err = apply_resolve(
        &mut st,
        r5,
        true,
        "authority".into(),
        "authority;ops".into(),
    )
    .expect_err("signer separators must fail closed to prevent authority-list spoofing");
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(9_001_72).unwrap();
    assert_eq!(task.status, TaskStatus::Challenged);
    assert_eq!(task.challenge_bond_forfeited, None);
    assert_eq!(st.balance_of("challenger"), before.balance_of("challenger"));
    assert_eq!(
        st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
        before.balance_of(CHALLENGE_ESCROW_ACCOUNT)
    );
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
    );
}
#[test]

fn resolve_rejects_signer_with_unicode_forbidden_separator_without_escrow_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority");

    let r1 = apply_create_task(&mut st, 9_001_73, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(9_001_73, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before = st.clone();
    let err = apply_resolve(
        &mut st,
        r5,
        true,
        "authority".into(),
        "authority；ops".into(),
    )
    .expect_err("unicode separator aliases must fail closed to prevent authority-list spoofing");
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(9_001_73).unwrap();
    assert_eq!(task.status, TaskStatus::Challenged);
    assert_eq!(task.challenge_bond_forfeited, None);
    assert_eq!(st.balance_of("challenger"), before.balance_of("challenger"));
    assert_eq!(
        st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
        before.balance_of(CHALLENGE_ESCROW_ACCOUNT)
    );
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
    );
}
#[test]

fn resolve_rejects_resolver_with_forbidden_separator_without_escrow_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority");

    let r1 = apply_create_task(&mut st, 9_001_74, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(9_001_74, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before = st.clone();
    let err = apply_resolve(
        &mut st,
        r5,
        true,
        "authority;ops".into(),
        "authority".into(),
    )
    .expect_err("resolver separators must fail closed to prevent payload actor spoofing");
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(9_001_74).unwrap();
    assert_eq!(task.status, TaskStatus::Challenged);
    assert_eq!(task.challenge_bond_forfeited, None);
    assert_eq!(st.balance_of("challenger"), before.balance_of("challenger"));
    assert_eq!(
        st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
        before.balance_of(CHALLENGE_ESCROW_ACCOUNT)
    );
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
    );
}
#[test]

fn resolve_rejects_configured_authority_member_with_forbidden_separator_without_escrow_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    let authority = "authority;ops";
    set_resolve_authority(&mut st, authority);

    let r1 = apply_create_task(&mut st, 9_001_74_1, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(9_001_74_1, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before = st.clone();
    let err = apply_resolve(&mut st, r5, true, authority.into(), authority.into())
        .expect_err("configured authority members containing separators must fail closed");
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(9_001_74_1).unwrap();
    assert_eq!(task.status, TaskStatus::Challenged);
    assert_eq!(task.challenge_bond_forfeited, None);
    assert_eq!(st.balance_of("challenger"), before.balance_of("challenger"));
    assert_eq!(
        st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
        before.balance_of(CHALLENGE_ESCROW_ACCOUNT)
    );
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
    );
}
#[test]

fn resolve_rejects_configured_authority_member_with_unicode_forbidden_separator_without_escrow_mutation(
) {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    let authority = "authority；ops";
    set_resolve_authority(&mut st, authority);

    let r1 = apply_create_task(&mut st, 9_001_74_2, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(9_001_74_2, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before = st.clone();
    let err = apply_resolve(&mut st, r5, true, authority.into(), authority.into())
        .expect_err("configured authority members containing unicode separators must fail closed");
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(9_001_74_2).unwrap();
    assert_eq!(task.status, TaskStatus::Challenged);
    assert_eq!(task.challenge_bond_forfeited, None);
    assert_eq!(st.balance_of("challenger"), before.balance_of("challenger"));
    assert_eq!(
        st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
        before.balance_of(CHALLENGE_ESCROW_ACCOUNT)
    );
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
    );
}
#[test]

fn resolve_rejects_configured_authority_member_with_ideographic_comma_without_escrow_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    let authority = "authority、ops";
    set_resolve_authority(&mut st, authority);

    let r1 = apply_create_task(&mut st, 9_001_74_3, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(9_001_74_3, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before = st.clone();
    let err = apply_resolve(&mut st, r5, true, authority.into(), authority.into()).expect_err(
        "configured authority members containing ideographic comma separators must fail closed",
    );
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(9_001_74_3).unwrap();
    assert_eq!(task.status, TaskStatus::Challenged);
    assert_eq!(task.challenge_bond_forfeited, None);
    assert_eq!(st.balance_of("challenger"), before.balance_of("challenger"));
    assert_eq!(
        st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
        before.balance_of(CHALLENGE_ESCROW_ACCOUNT)
    );
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
    );
}
#[test]

fn resolve_rejects_semicolon_delimited_authority_token_without_escrow_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    // Canonical token hardening: semicolon-delimited authority aliases must
    // fail closed so signer payload cannot smuggle pseudo-multisig syntax.
    let malformed_authority = "authority;guardian";
    set_resolve_authority(&mut st, malformed_authority);

    let r1 = apply_create_task(&mut st, 9_001_6_0, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(9_001_6_0, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before = st.clone();
    let err = apply_resolve(
        &mut st,
        r5,
        true,
        malformed_authority.into(),
        malformed_authority.into(),
    )
    .expect_err("semicolon-delimited authority token must fail closed");
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(9_001_6_0).unwrap();
    assert_eq!(task.status, TaskStatus::Challenged);
    assert_eq!(task.challenge_bond_forfeited, None);
    assert_eq!(st.balance_of("challenger"), before.balance_of("challenger"));
    assert_eq!(
        st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
        before.balance_of(CHALLENGE_ESCROW_ACCOUNT)
    );
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
    );
}
#[test]

fn resolve_rejects_pipe_delimited_authority_token_without_escrow_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    // Canonical token hardening: pipe-delimited authority aliases must
    // fail closed so signer payload cannot smuggle pseudo-multisig syntax.
    let malformed_authority = "authority|guardian";
    set_resolve_authority(&mut st, malformed_authority);

    let r1 = apply_create_task(&mut st, 9_001_6_3, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(9_001_6_3, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before = st.clone();
    let err = apply_resolve(
        &mut st,
        r5,
        true,
        malformed_authority.into(),
        malformed_authority.into(),
    )
    .expect_err("pipe-delimited authority token must fail closed");
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(9_001_6_3).unwrap();
    assert_eq!(task.status, TaskStatus::Challenged);
    assert_eq!(task.challenge_bond_forfeited, None);
    assert_eq!(st.balance_of("challenger"), before.balance_of("challenger"));
    assert_eq!(
        st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
        before.balance_of(CHALLENGE_ESCROW_ACCOUNT)
    );
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
    );
}
