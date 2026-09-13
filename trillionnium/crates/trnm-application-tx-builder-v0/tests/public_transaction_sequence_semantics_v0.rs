use trnm_application_tx_builder_v0::derive_command_id_v0;

/// The canonical transaction sequence is public, positive replay-order data.
/// It is domain-bound into the retry-stable command identifier and serialized
/// under the frozen protocol field name `nonce`; it is not cryptographic
/// randomness, an AEAD IV, or signing entropy.
#[test]
fn public_transaction_sequence_is_retry_stable_and_domain_bound() {
    let exact_body = br#"{"schema":"trnm.canonical-tx.v1","sender":"did:trnm:alice"}"#;

    let first = derive_command_id_v0("trnm-devnet", "did:trnm:alice", 1, exact_body);
    let retry = derive_command_id_v0("trnm-devnet", "did:trnm:alice", 1, exact_body);
    let next_sequence = derive_command_id_v0("trnm-devnet", "did:trnm:alice", 2, exact_body);
    let other_chain = derive_command_id_v0("trnm-testnet", "did:trnm:alice", 1, exact_body);
    let other_sender = derive_command_id_v0("trnm-devnet", "did:trnm:bob", 1, exact_body);
    let penultimate_sequence =
        derive_command_id_v0("trnm-devnet", "did:trnm:alice", u64::MAX - 1, exact_body);
    let largest_sequence =
        derive_command_id_v0("trnm-devnet", "did:trnm:alice", u64::MAX, exact_body);
    let other_body =
        br#"{"schema":"trnm.canonical-tx.v1","sender":"did:trnm:alice","memo":"bounded"}"#;
    let rebound_body = derive_command_id_v0("trnm-devnet", "did:trnm:alice", 1, other_body);

    assert_eq!(first, retry, "an exact retry must retain its command id");
    assert_ne!(
        first, next_sequence,
        "sequence advancement must rebind the id"
    );
    assert_ne!(first, other_chain, "chain identity must domain-bind the id");
    assert_ne!(
        first, other_sender,
        "sender identity must domain-bind the id"
    );
    assert_ne!(
        penultimate_sequence, largest_sequence,
        "the full public u64 sequence range must remain bound"
    );
    assert_ne!(first, rebound_body, "canonical body bytes must bind the id");
}
