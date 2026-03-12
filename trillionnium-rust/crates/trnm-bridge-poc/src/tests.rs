use crate::bridge_status::{
    BridgeStatus, CapabilityToken, SettlementCapability, SettlementError, SettlementRequest,
};

fn settlement_operator() -> CapabilityToken {
    CapabilityToken {
        subject: "did:trn:settlement-operator".to_string(),
        capabilities: vec![SettlementCapability::Revert],
    }
}

#[test]
fn settlement_request_rejects_ogham_space_mark_in_tx_hash() {
    let mut request = SettlementRequest::new(7, "0xabc\u{1680}def".to_string());
    let err = request.revert_authorized(&settlement_operator(), "target relay timeout".to_string());
    assert_eq!(
        err,
        Err(SettlementError::MalformedRequest {
            reason: "non-canonical tx_hash",
        })
    );
}

#[test]
fn settlement_request_collapses_ogham_space_mark_in_revert_reason() {
    let mut request = SettlementRequest::new(7, "0xabcdef".to_string());
    request
        .revert_authorized(
            &settlement_operator(),
            "target\u{1680}relay timeout".to_string(),
        )
        .expect("ogham-only spacing should be normalized in revert reason");

    assert_eq!(
        request.status,
        BridgeStatus::Reverted("target relay timeout".to_string())
    );
}

#[test]
fn settlement_request_rejects_non_canonical_subject_with_word_joiner() {
    let mut request = SettlementRequest::new(7, "0xabcdef".to_string());
    let token = CapabilityToken {
        subject: "did:trn:settlement\u{2060}-operator".to_string(),
        capabilities: vec![SettlementCapability::Revert],
    };

    let err = request.revert_authorized(&token, "target relay timeout".to_string());
    assert_eq!(
        err,
        Err(SettlementError::MalformedToken {
            reason: "non-canonical subject",
        })
    );
    assert_eq!(request.status, BridgeStatus::Pending);
}

#[test]
fn settlement_request_rejects_hangul_fillers_in_tx_hash_and_subject() {
    let mut request = SettlementRequest::new(7, "0xabc\u{115F}def\u{1160}ghi\u{3164}".to_string());
    let token = CapabilityToken {
        subject: "did:trn:settlement\u{115F}-operator\u{3164}".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    };

    let finalize_err = request.settle_authorized(&token, 77);
    assert_eq!(
        finalize_err,
        Err(SettlementError::MalformedRequest {
            reason: "non-canonical tx_hash",
        })
    );
    assert_eq!(request.status, BridgeStatus::Pending);

    request.tx_hash = "0xabcdef".to_string();

    let revert_err = request.revert_authorized(&token, "target relay timeout".to_string());
    assert_eq!(
        revert_err,
        Err(SettlementError::MalformedToken {
            reason: "non-canonical subject",
        })
    );
    assert_eq!(request.status, BridgeStatus::Pending);
}
