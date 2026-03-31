use super::*;

#[test]
fn relay_session_hash_cache_matches_queue_hashes() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::new(router);
    relay
        .open(RelayOpenRequest {
            session_id: "sp-cache-check".into(),
        })
        .unwrap();

    relay
        .send(RelaySendRequest {
            session_id: "sp-cache-check".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"p1".to_vec(),
            source: None,
        })
        .unwrap();

    let g = relay.sessions.lock().unwrap();
    let state = g.get("sp-cache-check").unwrap();
    assert_eq!(state.queue.len(), state.envelope_hashes.len());
    for (i, env) in state.queue.iter().enumerate() {
        let h = hash_envelope(env).unwrap();
        assert_eq!(h, state.envelope_hashes[i]);
    }
}

#[test]
fn risk_quota_error_key_is_elided_for_overlong_session_ids() {
    let overlong = "s".repeat(RISK_ERROR_KEY_MAX_CHARS + 32);
    let msg = too_many_requests(
        "quota_exceeded",
        format!(
            "domain={} dim={} key={} limit={} window_ms={}",
            RiskDomain::Relay.as_str(),
            "session",
            elide_risk_error_key(&overlong),
            1,
            1_000
        ),
    )
    .to_string();

    assert!(msg.contains("too_many_requests/quota_exceeded"));
    assert!(msg.contains("key=ss"));
    assert!(msg.contains('…'));
    assert!(!msg.contains(&overlong));
}

#[test]
fn source_attribution_canonicalization_collapses_whitespace_without_trailing_space() {
    let canonical = canonicalize_risk_source(Some("   Bot\t\n Worker   "));
    assert_eq!(canonical, "bot worker");

    let canonical_nbsp = canonicalize_risk_source(Some("bot\u{00a0}worker"));
    assert_eq!(canonical_nbsp, "bot worker");

    assert_eq!(
        canonicalize_risk_source(Some("relay-source-1")),
        "relay-source-1"
    );

    assert_eq!(
        canonicalize_risk_source(Some("  `\"Proof-Source\"`  ")),
        "proof-source"
    );

    let canonical_proof_fullwidth_space = canonicalize_risk_source(Some(
        "  「Proof\u{3000}Source」\u{2060}  ",
    ));
    assert_eq!(canonical_proof_fullwidth_space, "proof source");

    let canonical_unicode_case = canonicalize_risk_source(Some("İSTANBUL source"));
    assert_eq!(canonical_unicode_case, "i̇stanbul source");

    let exact = "A".repeat(RISK_SOURCE_MAX_CHARS);
    let with_suffix = format!("{}   z", exact);
    assert_eq!(
        canonicalize_risk_source(Some(&with_suffix)),
        exact.to_ascii_lowercase()
    );
}
