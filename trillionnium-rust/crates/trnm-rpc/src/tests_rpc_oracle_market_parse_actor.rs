use super::*;

#[test]
fn normalize_market_worker_key_strips_soft_hyphen_alias_spoofing() {
    let got = normalize_market_worker_key("Worker\u{00AD} A").expect("normalized");
    assert_eq!(got, "worker a");
    assert_eq!(
        normalize_market_worker_key("Worker A").expect("normalized"),
        got
    );
}

#[test]
fn normalize_actor_or_signer_strips_controls_and_zero_width() {
    let got = normalize_actor_or_signer(" \u{200B}alice\u{2060}\u{0007} bob ").expect("normalized");
    assert_eq!(got, "alice bob");
    assert!(normalize_actor_or_signer("\u{200B}\u{2060}\u{0000}").is_none());
}

#[test]
fn normalize_actor_or_signer_treats_controls_as_separators_not_concatenation() {
    let got = normalize_actor_or_signer("alice\u{0007}bob").expect("normalized");
    assert_eq!(got, "alice bob");
}
