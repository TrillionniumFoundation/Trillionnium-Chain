use super::*;

#[test]
fn market_capability_scopes_work_as_expected() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:market-agent".to_string(),
        "org:market-maker".to_string(),
        100,
    )
    .unwrap();

    let pub_token = reg
        .issue_capability(
            "org:market-maker".to_string(),
            "did:trnm:market-agent".to_string(),
            CapabilityScope::MarketPublish,
            110,
            None,
        )
        .unwrap();

    let exec_token = reg
        .issue_capability(
            "org:market-maker".to_string(),
            "did:trnm:market-agent".to_string(),
            CapabilityScope::MarketExecute,
            120,
            None,
        )
        .unwrap();

    // 1. Verify MarketPublish scope works
    reg.verify_capability(
        "org:market-maker",
        pub_token,
        CapabilityScope::MarketPublish,
        115,
    )
    .unwrap();

    // 2. Verify MarketExecute scope works
    reg.verify_capability(
        "org:market-maker",
        exec_token,
        CapabilityScope::MarketExecute,
        125,
    )
    .unwrap();

    // 3. Verify scope mismatch is rejected
    let err = reg
        .verify_capability(
            "org:market-maker",
            pub_token,
            CapabilityScope::MarketExecute,
            115,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        InteropIdentityError::CapabilityScopeMismatch {
            expected: CapabilityScope::MarketExecute,
            actual: CapabilityScope::MarketPublish,
            ..
        }
    ));

    // 4. Verify revocation works for market scopes
    reg.revoke_capability(
        "org:market-maker".to_string(),
        pub_token,
        130,
        Some("market_ban".to_string()),
    )
    .unwrap();

    let err = reg
        .verify_capability(
            "org:market-maker",
            pub_token,
            CapabilityScope::MarketPublish,
            131,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        InteropIdentityError::CapabilityInactive { .. }
    ));
}
