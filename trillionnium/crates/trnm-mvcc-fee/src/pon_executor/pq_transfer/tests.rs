use super::*;
use std::collections::BTreeSet;

const PUBLIC: &[u8] =
    include_bytes!("../../../../trnm-protocol/tests/fixtures/pq_transfer/public.der");
const TRANSFER: &[u8] =
    include_bytes!("../../../../trnm-protocol/tests/fixtures/pq_transfer/transfer.bin");

fn config() -> Config {
    let mut fees = [0; 25];
    fees[1] = 17;
    Config {
        network: [1; 32],
        parameters: [2; 32],
        family: [3; 32],
        plan: [4; 32],
        evaluators: BTreeSet::new(),
        fees,
        params: json!({"byte_fee_units": 1, "max_fee_limit": 10_000_000}),
        model_registry: json!({}),
        task_windows: None,
    }
}

fn initial() -> (Config, State, Vec<u8>, Vec<u8>) {
    let public = PUBLIC.to_vec();
    let raw = TRANSFER.to_vec();
    let sender = ml_dsa_65_key_id_from_spki(&public).unwrap();
    let mut state = State::new();
    state.insert(
        format!("account:{}", hex::encode(sender)),
        json!({"balance": 100_000, "nonce": 0}),
    );
    (config(), state, public, raw)
}

#[test]
fn real_pq_signature_reaches_existing_native_nonce_fee_and_transfer_rules() {
    let (config, parent, public, raw) = initial();
    let old_parent = parent.clone();
    let preview = preview_fresh_transfer(&parent, &raw, &public, 1_800_000_000, &config).unwrap();
    let sender = format!(
        "account:{}",
        hex::encode(ml_dsa_65_key_id_from_spki(&public).unwrap())
    );
    let recipient = format!("account:{}", hex::encode([7; 32]));
    assert_eq!(preview.fee, 17 + raw.len() as u64);
    assert_eq!(
        preview.state[&sender]["balance"],
        100_000 - 1_000 - preview.fee
    );
    assert_eq!(preview.state[&sender]["nonce"], 1);
    assert_eq!(preview.state[&recipient]["balance"], 1_000);
    assert_eq!(
        preview.parent_root,
        root_for_config(&parent, &config).unwrap()
    );
    assert_eq!(
        preview.state_root,
        root_for_config(&preview.state, &config).unwrap()
    );
    assert_eq!(parent, old_parent);
    let receipt: serde_json::Value = serde_json::from_slice(&preview.receipt).unwrap();
    assert_eq!(receipt["native_pq_node_integrated"], false);
    assert_eq!(receipt["status"], "preview_only");
    // Installed legacy bytes remain closed to the new transaction family.
    assert!(trnm_protocol::pon_wire::Envelope::decode(&raw).is_err());
}

#[test]
fn replay_and_alternate_parent_nonce_are_rechecked_without_mutation() {
    let (config, parent, public, raw) = initial();
    let first = preview_fresh_transfer(&parent, &raw, &public, 1_800_000_000, &config).unwrap();
    let before = first.state.clone();
    assert_eq!(
        preview_fresh_transfer(&first.state, &raw, &public, 1_800_000_000, &config).unwrap_err(),
        "NONCE"
    );
    assert_eq!(first.state, before);
    // Replaying on the original fork recreates exactly that branch's state.
    // No durable reorg or chain-external effect journal is claimed here.
    let again = preview_fresh_transfer(&parent, &raw, &public, 1_800_000_000, &config).unwrap();
    assert_eq!(first.state_root, again.state_root);
    assert_eq!(first.statement_id, again.statement_id);
}

#[test]
fn valid_crypto_does_not_override_fresh_owner_fee_nonce_or_purpose() {
    let (config, parent, public, _) = initial();
    let cases: [(&[u8], &str); 6] = [
        (
            include_bytes!("../../../../trnm-protocol/tests/fixtures/pq_transfer/low-fee.bin"),
            "FEE",
        ),
        (
            include_bytes!("../../../../trnm-protocol/tests/fixtures/pq_transfer/nonce-two.bin"),
            "NONCE",
        ),
        (
            include_bytes!(
                "../../../../trnm-protocol/tests/fixtures/pq_transfer/generation-two.bin"
            ),
            "PQ_FRESH_ONLY",
        ),
        (
            include_bytes!(
                "../../../../trnm-protocol/tests/fixtures/pq_transfer/wrong-network.bin"
            ),
            "PQ_NETWORK",
        ),
        (
            include_bytes!(
                "../../../../trnm-protocol/tests/fixtures/pq_transfer/wrong-purpose.bin"
            ),
            "PQ_SIGNATURE",
        ),
        (
            include_bytes!(
                "../../../../trnm-protocol/tests/fixtures/pq_transfer/duplicate-hint.bin"
            ),
            "PQ_SIGNATURE",
        ),
    ];
    for (encoded, expected) in cases {
        let raw = encoded.to_vec();
        assert_eq!(
            preview_fresh_transfer(&parent, &raw, &public, 1_800_000_000, &config).unwrap_err(),
            expected
        );
    }
}

#[test]
fn randomized_signatures_do_not_multiply_transaction_identities() {
    let (config, parent, public, raw) = initial();
    let second = include_bytes!(
        "../../../../trnm-protocol/tests/fixtures/pq_transfer/same-statement-second-signature.bin"
    )
    .to_vec();
    let one = preview_fresh_transfer(&parent, &raw, &public, 1_800_000_000, &config).unwrap();
    let two = preview_fresh_transfer(&parent, &second, &public, 1_800_000_000, &config).unwrap();
    assert_eq!(one.statement_id, two.statement_id);
    assert_eq!(one.state_root, two.state_root);
}

#[test]
fn invalid_signature_key_expiry_funds_and_overflow_leave_parent_unchanged() {
    let (mut config, mut parent, public, raw) = initial();
    let wrong =
        include_bytes!("../../../../trnm-protocol/tests/fixtures/pq_transfer/wrong-public.der")
            .to_vec();
    assert_eq!(
        preview_fresh_transfer(&parent, &raw, &wrong, 1_800_000_000, &config).unwrap_err(),
        "PQ_OWNER"
    );
    assert_eq!(
        preview_fresh_transfer(&parent, &raw, &public, 1_800_001_001, &config).unwrap_err(),
        "PQ_EXPIRED"
    );
    let mut fake = raw.clone();
    let start = fake.len() - 3309;
    fake[start..].fill(0);
    assert_eq!(
        preview_fresh_transfer(&parent, &fake, &public, 1_800_000_000, &config).unwrap_err(),
        "PQ_SIGNATURE"
    );
    let sender = format!(
        "account:{}",
        hex::encode(ml_dsa_65_key_id_from_spki(&public).unwrap())
    );
    parent.get_mut(&sender).unwrap()["balance"] = json!(1);
    let before = parent.clone();
    assert_eq!(
        preview_fresh_transfer(&parent, &raw, &public, 1_800_000_000, &config).unwrap_err(),
        "FUNDS"
    );
    assert_eq!(parent, before);
    config.params["byte_fee_units"] = json!(u64::MAX);
    assert_eq!(
        preview_fresh_transfer(&parent, &raw, &public, 1_800_000_000, &config).unwrap_err(),
        "RANGE"
    );
    assert_eq!(parent, before);
}
