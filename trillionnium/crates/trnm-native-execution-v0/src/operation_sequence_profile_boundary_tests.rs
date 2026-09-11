//! The frozen historical operation corpus cannot mint current profile authority.
//!
//! This is a negative compatibility regression, not a successful durable replay
//! of the corpus. Its initial JMT history is valid; its signer-policy commitment
//! belongs to an earlier domain profile and must not bypass the native owner.

use ed25519_dalek::SigningKey;
use serde_json::Value;

use crate::{
    auth_tree::validator_state_key, poco_checkpoint::active_consensus_configuration,
    poco_transition::take_and_validate_production_poco_projection_v0, signer_policy_commitment_v0,
    AuthorizedSignerV0, InMemoryNativeExecutionStoreV0, NativeApplicationConfigV0,
    NativeStateWriteV0,
};

const CORPUS: &str = include_str!(
    "../../../../docs/protocol/poco-bft-v0/vectors/poco-application-operation-sequences-v0.json"
);

fn bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().expect("hex string")).expect("canonical hex")
}

fn hash(value: &Value) -> [u8; 32] {
    bytes(value).try_into().expect("32-byte hash")
}

#[test]
fn frozen_old_operation_profile_cannot_obtain_current_native_authority() {
    let corpus: Value = serde_json::from_str(CORPUS).unwrap();
    let sequences = corpus["sequences"].as_array().unwrap();
    assert_eq!(sequences.len(), 9);
    assert_eq!(
        sequences
            .iter()
            .map(|sequence| sequence["steps"].as_array().unwrap().len())
            .sum::<usize>(),
        18,
    );
    assert_eq!(
        sequences
            .iter()
            .map(|sequence| sequence["negatives"].as_array().unwrap().len())
            .sum::<usize>(),
        9,
    );
    let initial = &corpus["sequences"][0]["initial"];
    let full_store_sequences = sequences
        .iter()
        .filter(|sequence| sequence["execution_scope"] == "full_application_store")
        .collect::<Vec<_>>();
    assert_eq!(full_store_sequences.len(), 5);
    for sequence in full_store_sequences {
        assert_eq!(&sequence["initial"], initial);
    }
    assert_eq!(initial["version"], 0);
    assert_eq!(initial["history"].as_array().unwrap().len(), 1);
    assert_eq!(initial["history"][0]["writes"].as_array().unwrap().len(), 8);
    let context = &initial["production_context"];
    let parameters = trnm_consensus_types::decode_consensus_parameters_v0_exact(&bytes(
        &context["active_parameters_cev0_hex"],
    ))
    .unwrap();
    let signers = [11u8, 12u8]
        .iter()
        .enumerate()
        .map(|(index, seed)| {
            AuthorizedSignerV0::new(
                format!("did:operator:{}", index + 1),
                "operator",
                hex::encode(
                    SigningKey::from_bytes(&[*seed; 32])
                        .verifying_key()
                        .as_bytes(),
                ),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let initial_writes = initial["history"][0]["writes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|write| {
            NativeStateWriteV0::raw(
                bytes(&write["physical_key_hex"]),
                bytes(&write["value_hex"]),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let chain = context["chain_id_utf8"].as_str().unwrap();
    let mut tree = InMemoryNativeExecutionStoreV0::new(chain, signers.clone(), parameters).unwrap();
    let initial_root = tree.apply_seed_v0(0, initial_writes.clone()).unwrap();
    assert_eq!(initial_root.0, hash(&initial["jmt_root_hex"]));
    let mut live = tree.verified_live_values_v0(0).unwrap();
    let projection = take_and_validate_production_poco_projection_v0(0, &mut live)
        .unwrap()
        .expect("frozen genesis contains the authenticated PoCO namespace");
    let (validators, active_parameters) = active_consensus_configuration(&projection).unwrap();
    assert_eq!(parameters, active_parameters);
    let lifecycle = bytes(&initial["active_genesis"]["validator_lifecycle"]["value_hex"]);
    let json_start = lifecycle.iter().position(|byte| *byte == b'{').unwrap();
    let lifecycle_json = lifecycle[json_start..].to_vec();
    let lifecycle_fields: Value = serde_json::from_slice(&lifecycle_json).unwrap();
    let frozen_policy = hash(&lifecycle_fields["authorized_signers_hash_hex"]);
    let current_policy = signer_policy_commitment_v0(&signers).unwrap();
    assert_eq!(
        hex::encode(frozen_policy),
        "a562c55d093a166f3f9e9d95161baed838cdb0a0ada99c5bdd982772ca6b622f",
    );
    assert_eq!(
        hex::encode(current_policy),
        "99b8f5c1b8e9e84de212e04853506898d18705fba85181216d17913fe401e9de",
    );
    assert_ne!(frozen_policy, current_policy);
    let lifecycle_key = validator_state_key().unwrap();
    let error = NativeApplicationConfigV0::new(
        chain,
        hash(&context["genesis_hash_hex"]),
        [31; 32],
        [32; 32],
        [33; 32],
        [34; 32],
        validators,
        parameters,
        lifecycle_json,
        signers,
        initial_writes
            .into_iter()
            .filter(|write| write.key() != lifecycle_key)
            .collect(),
    )
    .expect_err("an old profile cannot acquire current native application authority");
    assert_eq!(
        error.to_string(),
        "bootstrap lifecycle signer-policy mismatch"
    );
}
