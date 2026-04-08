use super::*;

#[test]
fn did_revoke_same_height_replay_is_idempotent_without_duplicate_cascade_audit() {
    let mut reg = IdentityRegistry::default();
    let did = "did:trnm:agent-i3-did-cascade-same-height-replay".to_string();
    let actor = "org:lane-xi-admin".to_string();

    reg.register_did(did.clone(), actor.clone(), 10).unwrap();

    let token = reg
        .issue_capability(
            actor.clone(),
            did.clone(),
            CapabilityScope::BridgeSettle,
            20,
            Some(80),
        )
        .unwrap();

    reg.revoke_did(actor.clone(), &did, 30).unwrap();

    let audit_len_after_first_revoke = reg.audit_trail().len();
    let first_token_revoked_at = reg.capability(token).expect("token exists").revoked_at;

    // I3 replay contract: same-height DID revoke replay is idempotent and must
    // not append duplicate cascade revoke audit events.
    reg.revoke_did(actor.clone(), &did, 30).unwrap();

    assert_eq!(reg.did(&did).expect("did exists").revoked_at, Some(30));
    assert_eq!(
        reg.capability(token).expect("token exists").revoked_at,
        first_token_revoked_at
    );
    assert_eq!(reg.audit_trail().len(), audit_len_after_first_revoke);

    let cascade_revokes: Vec<_> = reg
        .audit_trail()
        .iter()
        .filter(|ev| {
            ev.action == AuditAction::CapabilityRevoked
                && ev.actor == "system:cascade"
                && ev
                    .note
                    .as_deref()
                    .is_some_and(|note| note.starts_with("cascade_on_did_revoke token_id="))
        })
        .collect();
    assert_eq!(cascade_revokes.len(), 1);
}
