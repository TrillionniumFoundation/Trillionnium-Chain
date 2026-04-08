use super::*;

#[test]
fn nonexpiring_rejected_post_boundary_renew_after_same_height_renew_then_revoke_is_side_effect_free(
) {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-i3-nonexpiring-sideeffect".to_string(),
        "org:lane-xi-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane-xi-admin".to_string(),
            "did:trnm:agent-i3-nonexpiring-sideeffect".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            None,
        )
        .unwrap();

    reg.renew_capability("org:lane-xi-admin".to_string(), token_id, 35, None)
        .unwrap();
    reg.revoke_capability(
        "org:lane-xi-admin".to_string(),
        token_id,
        35,
        Some("nonexpiring_renew_then_revoke".to_string()),
    )
    .unwrap();

    let audit_len_before = reg.audit_trail().len();
    let token_before = reg.capability(token_id).cloned().expect("token exists");

    let err = reg
        .renew_capability("org:lane-xi-admin".to_string(), token_id, 36, None)
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::CapabilityInactive {
            token_id: err_token_id,
            at_height: 36,
            expires_at: None,
            revoked_at: Some(35),
            ..
        } if err_token_id == token_id
    ));

    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert_eq!(reg.capability(token_id), Some(&token_before));
}
