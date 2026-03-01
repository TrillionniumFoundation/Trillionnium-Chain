use trnm_types::DidRecord;

#[test]
fn did_is_inactive_before_creation_and_starting_at_revocation_height() {
    let did = DidRecord {
        did: "did:trnm:boundary-agent".to_string(),
        controller: "org:lane-xi".to_string(),
        created_at: 100,
        revoked_at: Some(130),
    };

    assert!(!did.is_active_at(99));
    assert!(did.is_active_at(100));
    assert!(did.is_active_at(129));
    assert!(!did.is_active_at(130));
    assert!(!did.is_active_at(131));
}

#[test]
fn did_revoked_at_creation_height_is_never_active() {
    let did = DidRecord {
        did: "did:trnm:instant-revoke".to_string(),
        controller: "org:lane-xi".to_string(),
        created_at: 200,
        revoked_at: Some(200),
    };

    assert!(!did.is_active_at(199));
    assert!(!did.is_active_at(200));
    assert!(!did.is_active_at(201));
}
