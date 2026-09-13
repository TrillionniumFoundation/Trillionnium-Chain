//! The frozen historical operation corpus cannot mint current profile authority.
//!
//! Kernel tests replay exact historical operations and authenticated JMT writes.
//! The historical context is fixture input only: no test here admits its signer
//! policy through the current application owner, runs signed command admission,
//! or establishes full durable application replay. The negative compatibility
//! regression below keeps that profile boundary explicit.

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

// These tests intentionally invoke the crate-private semantic kernel using
// frozen fixture context. They do not construct NativeApplicationConfigV0 or
// claim that historical hashes are current-profile runtime authority.
fn fixture_kernel_context(
    context: &Value,
) -> crate::poco_application::AuthenticatedPocoApplicationContextV0 {
    use trnm_consensus_types::{ChainId, Epoch, GenesisHash, Height};
    crate::poco_application::AuthenticatedPocoApplicationContextV0::new(
        context["source_version"].as_u64().unwrap(),
        hash(&context["source_root_hex"]),
        Height::new(context["target_height"].as_u64().unwrap()),
        ChainId::new(context["chain_id_utf8"].as_str().unwrap()).unwrap(),
        GenesisHash::new(hash(&context["genesis_hash_hex"])),
        Epoch::new(context["active_epoch"].as_u64().unwrap()),
        trnm_consensus_types::decode_consensus_parameters_v0_exact(&bytes(
            &context["active_parameters_cev0_hex"],
        ))
        .unwrap(),
        hash(&context["authority_signer_commitment_hex"]),
    )
    .unwrap()
}

fn frozen_projection(
    store: &InMemoryNativeExecutionStoreV0,
    version: u64,
    expected: &Value,
) -> crate::poco_transition::ProductionPocoProjectionV0 {
    let mut live = store.verified_live_values_v0(version).unwrap();
    let projection = take_and_validate_production_poco_projection_v0(version, &mut live)
        .unwrap()
        .unwrap();
    assert_eq!(
        projection.manifest().encode(),
        bytes(&expected["manifest_hex"])
    );
    if let Some(entries) = expected.get("entries") {
        assert_eq!(
            projection.entries().len(),
            entries.as_array().unwrap().len()
        );
        for (actual, frozen) in projection.entries().iter().zip(entries.as_array().unwrap()) {
            assert_eq!(actual.kind as u64, frozen["kind"].as_u64().unwrap());
            assert_eq!(actual.logical_key, bytes(&frozen["logical_key_hex"]));
            assert_eq!(actual.value, bytes(&frozen["value_hex"]));
            assert_eq!(
                actual.canonical_bytes(),
                bytes(&frozen["canonical_entry_cev0_hex"])
            );
        }
        assert_eq!(
            projection.manifest().entries_root(),
            hash(&expected["entries_root_hex"])
        );
    }
    if let Some(authority) = expected.get("authority") {
        let actual = projection
            .entries()
            .iter()
            .find(|entry| {
                entry.kind
                    == crate::poco_snapshot::PocoSnapshotEntryKindV0::ApplicationAuthorityState
            })
            .unwrap();
        assert_eq!(actual.value, bytes(&authority["envelope_hex"]));
    }
    projection
}

fn replay_frozen_sequence_in_semantic_kernel(sequence_id: &str, expected_steps: usize) {
    use crate::{
        poco_application::{
            poco_application_operation_id_v0, PocoApplicationApplyFailureV0,
            PocoApplicationBlockOverlayV0, PocoApplicationDeterministicInvalidV0,
            PocoApplicationOperationV0,
        },
        poco_snapshot::{
            poco_snapshot_entry_key, poco_snapshot_manifest_key, PocoSnapshotEntryKindV0,
        },
        store::{plan_complete_state_update_v0, CompleteStateWriteV0, NativeExecutionStoreV0},
    };
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    assert_eq!(
        hex::encode(Sha256::digest(CORPUS.as_bytes())),
        "d472d0964f585bc9357ebf7dc18d1d808b6b308807d38ae6f807475f1dabcf5e"
    );
    let corpus: Value = serde_json::from_str(CORPUS).unwrap();
    let sequence = corpus["sequences"]
        .as_array()
        .unwrap()
        .iter()
        .find(|sequence| sequence["id"] == sequence_id)
        .unwrap();
    let initial = &sequence["initial"];
    let initial_context = &initial["production_context"];
    let parameters = trnm_consensus_types::decode_consensus_parameters_v0_exact(&bytes(
        &initial_context["active_parameters_cev0_hex"],
    ))
    .unwrap();
    // Store metadata supplies no execution authority in this fixture kernel.
    // The historical lifecycle bytes remain untouched inside authenticated history.
    let signer = AuthorizedSignerV0::new(
        "did:kernel-fixture",
        "operator",
        hex::encode(SigningKey::from_bytes(&[11; 32]).verifying_key().as_bytes()),
    )
    .unwrap();
    let mut store = InMemoryNativeExecutionStoreV0::new(
        initial_context["chain_id_utf8"].as_str().unwrap(),
        vec![signer],
        parameters,
    )
    .unwrap();
    for (expected_version, history) in initial["history"].as_array().unwrap().iter().enumerate() {
        let version = history["version"].as_u64().unwrap();
        assert_eq!(version, expected_version as u64);
        let writes = history["writes"]
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
            .collect();
        let root = store.apply_seed_v0(version, writes).unwrap();
        assert_eq!(
            root.0,
            hash(&history["jmt_root_hex"]),
            "{sequence_id} history {version}"
        );
    }
    assert_eq!(
        store.parent_version_v0().unwrap(),
        initial["version"].as_u64().unwrap()
    );
    assert_eq!(
        store.parent_root_v0().unwrap().0,
        hash(&initial["jmt_root_hex"])
    );
    frozen_projection(
        &store,
        store.parent_version_v0().unwrap(),
        &initial["projection"],
    );
    let steps = sequence["steps"].as_array().unwrap();
    assert_eq!(steps.len(), expected_steps);
    for step in steps {
        let event = &step["rust_event"];
        let context = &step["context"];
        assert_eq!(context, &event["context"]);
        let version = store.parent_version_v0().unwrap();
        assert_eq!(version, context["source_version"].as_u64().unwrap());
        assert_eq!(
            store.parent_root_v0().unwrap().0,
            hash(&context["source_root_hex"])
        );
        let projection = frozen_projection(&store, version, &event["source"]);
        let mut overlay = PocoApplicationBlockOverlayV0::from_projection(
            fixture_kernel_context(context),
            &projection,
        )
        .unwrap();
        let raw_operations = step["operations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|operation| {
                let raw = bytes(&operation["raw_operation_json_hex"]);
                assert_eq!(
                    poco_application_operation_id_v0(&raw).unwrap(),
                    hash(&operation["operation_id_hex"])
                );
                overlay
                    .apply_raw(&raw)
                    .unwrap_or_else(|error| panic!("{sequence_id} {}: {error:#}", step["id"]));
                raw
            })
            .collect::<Vec<_>>();
        let plan = overlay.seal().unwrap();
        assert!(plan.binds_exact_operations_v0(&raw_operations));
        assert_eq!(
            u64::from(plan.operation_count()),
            step["operation_count"].as_u64().unwrap()
        );
        assert_eq!(plan.operation_root(), hash(&step["operation_root_hex"]));
        assert_eq!(
            u64::from(plan.mutation_count()),
            event["mutations"]["mutation_count"].as_u64().unwrap()
        );
        assert_eq!(
            plan.mutation_root(),
            hash(&event["mutations"]["mutation_root_hex"])
        );
        assert_eq!(
            plan.target_manifest().encode(),
            bytes(&event["target"]["manifest_hex"])
        );

        let live = store.verified_live_values_v0(version).unwrap();
        let mut expected_writes = BTreeMap::new();
        for mutation in event["mutations"]["items"].as_array().unwrap() {
            let key = poco_snapshot_entry_key(
                PocoSnapshotEntryKindV0::from_u8(
                    mutation["kind"].as_u64().unwrap().try_into().unwrap(),
                )
                .unwrap(),
                &bytes(&mutation["logical_key_hex"]),
            )
            .unwrap();
            let expected_source = mutation["expected_value_hex"]
                .as_str()
                .map(|value| hex::decode(value).unwrap());
            assert_eq!(live.get(&key), expected_source.as_ref());
            let successor = mutation["next_value_hex"]
                .as_str()
                .map(|value| hex::decode(value).unwrap());
            assert!(expected_writes.insert(key, successor).is_none());
        }
        assert!(expected_writes
            .insert(
                poco_snapshot_manifest_key().unwrap(),
                Some(bytes(&event["target"]["manifest_hex"]))
            )
            .is_none());
        let mut actual_writes = BTreeMap::new();
        for (key, value) in plan.namespace_writes() {
            assert!(
                actual_writes
                    .insert(key.to_vec(), value.map(<[u8]>::to_vec))
                    .is_none(),
                "kernel plan must not repeat a physical write key"
            );
        }
        assert_eq!(
            actual_writes, expected_writes,
            "{sequence_id} {} writes",
            step["id"]
        );
        let state_plan = plan_complete_state_update_v0(
            &store,
            version,
            version + 1,
            actual_writes
                .into_iter()
                .map(|(key, value)| CompleteStateWriteV0::new(key, value).unwrap())
                .collect(),
        )
        .unwrap();
        assert_eq!(
            state_plan.state_root().as_bytes(),
            &hash(&event["target"]["jmt_root_hex"]),
            "{sequence_id} {} kernel JMT root",
            step["id"]
        );
        store.apply_complete_state_plan_v0(state_plan).unwrap();
        frozen_projection(&store, version + 1, &event["target"]);
    }
    let negatives = sequence["negatives"].as_array().unwrap();
    assert_eq!(negatives.len(), 1);
    for negative in negatives {
        let version = store.parent_version_v0().unwrap();
        assert_eq!(version, negative["source"]["version"].as_u64().unwrap());
        assert_eq!(
            store.parent_root_v0().unwrap().0,
            hash(&negative["source"]["jmt_root_hex"])
        );
        assert_eq!(
            version,
            negative["context"]["source_version"].as_u64().unwrap()
        );
        assert_eq!(
            store.parent_root_v0().unwrap().0,
            hash(&negative["context"]["source_root_hex"])
        );
        let before_snapshot = store.encode_authenticated_snapshot_v0().unwrap();
        let projection = frozen_projection(&store, version, &negative["source"]);
        let mut overlay = PocoApplicationBlockOverlayV0::from_projection(
            fixture_kernel_context(&negative["context"]),
            &projection,
        )
        .unwrap();
        let before_overlay = format!("{overlay:?}");
        let raw_operations = negative["raw_operation_json_hexes"].as_array().unwrap();
        assert_eq!(raw_operations.len(), 1);
        let raw = bytes(&raw_operations[0]);
        let operation = PocoApplicationOperationV0::decode_exact(&raw).unwrap();
        let actual = overlay
            .apply_decoded_exact(&raw, &operation)
            .expect_err("frozen replay must reject");
        let (expected_stage, expected_reason) =
            match negative["expected_reject"]["error_code"].as_str().unwrap() {
                "challenge_not_pending" => (
                    "authority",
                    PocoApplicationDeterministicInvalidV0::ChallengeNotPending,
                ),
                "governance_approval_lacks_authenticated_proposal" => (
                    "authority",
                    PocoApplicationDeterministicInvalidV0::GovernanceApprovalMissing,
                ),
                "validator_consensus_key_already_active" => (
                    "authority",
                    PocoApplicationDeterministicInvalidV0::ValidatorConsensusKeyAlreadyActive,
                ),
                "nullifier_non_membership_root_mismatch" => (
                    "proof",
                    PocoApplicationDeterministicInvalidV0::NullifierNonMembershipRootMismatch,
                ),
                other => panic!("uncovered frozen rejection: {other}"),
            };
        assert_eq!(negative["expected_reject"]["stage"], expected_stage);
        assert_eq!(
            actual,
            PocoApplicationApplyFailureV0::DeterministicallyInvalid(expected_reason)
        );
        assert_eq!(
            format!("{overlay:?}"),
            before_overlay,
            "rejection must not partially mutate kernel"
        );
        assert_eq!(overlay.operation_count(), 0);
        assert!(overlay.seal().is_err());
        assert_eq!(
            store.encode_authenticated_snapshot_v0().unwrap(),
            before_snapshot
        );
        assert_eq!(negative["expected_writes"], 0);
        assert_eq!(negative["rust_event"]["writes"], 0);
        assert_eq!(
            store.parent_root_v0().unwrap().0,
            hash(&negative["expected_unchanged"]["jmt_root_hex"])
        );
        frozen_projection(&store, version, &negative["expected_unchanged"]);
    }
}

macro_rules! frozen_semantic_kernel_test {
    ($test_name:ident, $sequence:literal, $steps:literal) => {
        #[test]
        fn $test_name() {
            replay_frozen_sequence_in_semantic_kernel($sequence, $steps);
        }
    };
}

frozen_semantic_kernel_test!(
    frozen_semantic_kernel_certificate_challenge_rejected,
    "certificate_challenge_rejected",
    4
);
frozen_semantic_kernel_test!(
    frozen_semantic_kernel_certificate_challenge_sustained,
    "certificate_challenge_sustained",
    4
);
frozen_semantic_kernel_test!(
    frozen_semantic_kernel_governance_propose_approve,
    "governance_propose_approve",
    2
);
frozen_semantic_kernel_test!(
    frozen_semantic_kernel_validator_register_rotate,
    "validator_register_rotate",
    2
);
frozen_semantic_kernel_test!(
    frozen_semantic_kernel_release_refund_replay,
    "release_refund_replay",
    2
);
frozen_semantic_kernel_test!(
    frozen_semantic_kernel_certificate_prune_replay,
    "certificate_prune_replay",
    1
);
frozen_semantic_kernel_test!(
    frozen_semantic_kernel_consumer_key_prune_replay,
    "consumer_key_prune_replay",
    1
);
frozen_semantic_kernel_test!(
    frozen_semantic_kernel_meter_prune_replay,
    "meter_prune_replay",
    1
);
frozen_semantic_kernel_test!(
    frozen_semantic_kernel_validator_prune_replay,
    "validator_prune_replay",
    1
);
