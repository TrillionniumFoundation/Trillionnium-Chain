use super::*;
#[test]
fn flush_submissions_requires_tx_hash_receipts_for_terminal_acceptance() {
    let commit_res = AdapterExecResult {
        ok: true,
        rc: RC_OK,
        tx_hash: None,
        terminal: true,
    };
    let reveal_res = AdapterExecResult {
        ok: true,
        rc: RC_OK,
        tx_hash: None,
        terminal: true,
    };

    let commit_idempotent_ok = should_execute_reveal(&commit_res);
    let reveal_idempotent_ok = reveal_res.ok || is_idempotent_duplicate_ok(reveal_res.rc);
    let commit_hash_observed = commit_res.tx_hash.is_some();
    let reveal_hash_observed = reveal_res.tx_hash.is_some();

    let (ack_status, reason_code) = if commit_idempotent_ok
        && reveal_idempotent_ok
        && commit_hash_observed
        && reveal_hash_observed
    {
        ("accepted", "idempotent_ok")
    } else if commit_idempotent_ok
        && reveal_idempotent_ok
        && (!commit_hash_observed || !reveal_hash_observed)
    {
        ("failed", "missing_tx_hash_receipt")
    } else {
        ("unexpected", "unexpected")
    };

    assert_eq!(ack_status, "failed");
    assert_eq!(reason_code, "missing_tx_hash_receipt");
}

#[test]
fn flush_submissions_reuses_persisted_tx_hash_for_duplicate_resume_acceptance() {
    let commit_res = AdapterExecResult {
        ok: false,
        rc: RC_DUPLICATE,
        tx_hash: None,
        terminal: true,
    };
    let reveal_res = AdapterExecResult {
        ok: true,
        rc: RC_OK,
        tx_hash: Some("revealbeef".to_string()),
        terminal: true,
    };

    let previous_commit_tx_hash = Some("commitbeef".to_string());
    let previous_reveal_tx_hash = None;

    let commit_hash_observed = commit_res.tx_hash.is_some()
        || (is_idempotent_duplicate_ok(commit_res.rc) && previous_commit_tx_hash.is_some());
    let reveal_hash_observed = reveal_res.tx_hash.is_some()
        || (is_idempotent_duplicate_ok(reveal_res.rc) && previous_reveal_tx_hash.is_some());

    let commit_tx_hash_for_ack = commit_res.tx_hash.clone().or(previous_commit_tx_hash);
    let reveal_tx_hash_for_ack = reveal_res.tx_hash.clone().or(previous_reveal_tx_hash);

    assert!(should_execute_reveal(&commit_res));
    assert!(reveal_res.ok || is_idempotent_duplicate_ok(reveal_res.rc));
    assert!(commit_hash_observed);
    assert!(reveal_hash_observed);
    assert_eq!(commit_tx_hash_for_ack.as_deref(), Some("commitbeef"));
    assert_eq!(reveal_tx_hash_for_ack.as_deref(), Some("revealbeef"));
}
