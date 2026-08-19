use ed25519_dalek::SigningKey;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use trnm_consensus_types::ConsensusParametersV0;
use trnm_finality_types::{crypto::public_key_hex, SignedCommandEnvelopeV1};
use trnm_protocol::{
    account_key, task_key, AccountV1, CanonicalCommandV1, CanonicalTxV1,
    CANONICAL_TX_PAYLOAD_TYPE_V1, CANONICAL_TX_SCHEMA_V1,
};

use super::*;

const CHAIN_ID: &str = "trnm-native-execution-test";
const PARENT_HEIGHT: u64 = 1;
const TARGET_HEIGHT: u64 = 2;
const TIMESTAMP_MS: u64 = 1_700_000_001_000;

#[derive(Deserialize)]
struct LegacyDifferentialVectorV0 {
    schema: String,
    authority: String,
    chain_id: String,
    parent_height: u64,
    target_height: u64,
    timestamp_ms: u64,
    parameters_cev0_hex: String,
    authorized_signers: Vec<LegacySignerVectorV0>,
    signer_policy_commitment_hex: String,
    parent_snapshot_borsh_hex: String,
    parent_state_root_hex: String,
    exact_outer_transactions_hex: Vec<String>,
    expected: LegacyExpectedExecutionVectorV0,
}

#[derive(Deserialize)]
struct LegacySignerVectorV0 {
    signer_id: String,
    signer_role: String,
    public_key_hex: String,
}

#[derive(Deserialize)]
struct LegacyExpectedExecutionVectorV0 {
    payload_root_hex: String,
    receipts_root_hex: String,
    evidence_root_hex: String,
    runtime_object_delta_root_hex: String,
    execution_receipts_cev0_hex: String,
    runtime_writes: Vec<LegacyRuntimeWriteVectorV0>,
}

#[derive(Deserialize)]
struct LegacyRuntimeWriteVectorV0 {
    logical_object_key: String,
    object_type: String,
    object_version: u64,
    value_bytes_hex: String,
    authenticated_key_hex: String,
    authenticated_record_borsh_hex: String,
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn signer(seed: u8, id: &str, role: &str) -> AuthorizedSignerV0 {
    AuthorizedSignerV0::new(id, role, public_key_hex(&key(seed))).unwrap()
}

fn fixture_store() -> InMemoryNativeExecutionStoreV0 {
    let mut store = InMemoryNativeExecutionStoreV0::new(
        CHAIN_ID,
        vec![
            signer(81, "did:operator:1", "operator"),
            signer(82, "did:client:1", "hepta"),
        ],
        ConsensusParametersV0::reference_shadow_v0(),
    )
    .unwrap();
    // Version 0 and 1 intentionally contain no runtime objects. The empty
    // version-1 parent is still a real JMT root/proof source.
    store.apply_seed_v0(0, Vec::new()).unwrap();
    store.apply_seed_v0(1, Vec::new()).unwrap();
    store
}

fn transactions() -> (CanonicalTxV1, CanonicalTxV1) {
    (
        CanonicalTxV1 {
            schema: CANONICAL_TX_SCHEMA_V1.to_string(),
            sender: "did:operator:1".to_string(),
            nonce: 1,
            max_gas: 100_000,
            fee_limit: 100_000,
            command: CanonicalCommandV1::CreditAccount {
                account: "did:client:1".to_string(),
                amount: 10_000,
            },
        },
        CanonicalTxV1 {
            schema: CANONICAL_TX_SCHEMA_V1.to_string(),
            sender: "did:client:1".to_string(),
            nonce: 1,
            max_gas: 100_000,
            fee_limit: 100_000,
            command: CanonicalCommandV1::CreateTask {
                task_id: "native-task-0".to_string(),
                reward: 1_000,
                worker_stake: 500,
                result_deadline_height: 20,
                challenge_window_blocks: 10,
            },
        },
    )
}

fn signed_outer(seed: u8, id: &str, role: &str, command_id: &str, tx: &CanonicalTxV1) -> Vec<u8> {
    let inner = serde_json::to_vec(tx).unwrap();
    signed_outer_with_inner(seed, id, role, command_id, tx.nonce, &inner)
}

fn signed_outer_with_inner(
    seed: u8,
    id: &str,
    role: &str,
    command_id: &str,
    nonce: u64,
    inner: &[u8],
) -> Vec<u8> {
    let envelope = SignedCommandEnvelopeV1::sign(
        CHAIN_ID,
        command_id,
        id,
        role,
        nonce,
        1_700_000_000_000,
        1_700_000_100_000,
        CANONICAL_TX_PAYLOAD_TYPE_V1,
        inner,
        &key(seed),
    )
    .unwrap();
    serde_json::to_vec(&envelope).unwrap()
}

fn exact_transactions() -> Vec<Vec<u8>> {
    let (credit, create) = transactions();
    vec![
        signed_outer(81, "did:operator:1", "operator", "credit-1", &credit),
        signed_outer(82, "did:client:1", "hepta", "create-1", &create),
    ]
}

fn request(txs: Vec<Vec<u8>>) -> NativeExecutionRequestV0 {
    NativeExecutionRequestV0::new_empty_evidence(PARENT_HEIGHT, TARGET_HEIGHT, TIMESTAMP_MS, txs)
        .unwrap()
}

#[test]
fn real_runtime_second_transaction_reads_first_delta_and_jmt_plan_reopens() {
    let mut store = fixture_store();
    let candidate = execute_authenticated_block_candidate_v0(&store, request(exact_transactions()))
        .expect("execute real two-transaction runtime block");

    assert_eq!(candidate.executed_transactions().len(), 2);
    let client_key = account_key("did:client:1");
    let second_client = candidate.executed_transactions()[1]
        .runtime_receipt()
        .mutations
        .iter()
        .find(|mutation| mutation.object_key_hex == client_key)
        .expect("second transaction updates client created by first transaction");
    assert_eq!(second_client.expected_version, Some(1));
    assert_eq!(second_client.next_version, 2);
    let final_client = candidate.final_objects().get(&client_key).unwrap();
    let account: AccountV1 = serde_json::from_slice(&final_client.value_bytes).unwrap();
    assert_eq!(account.nonce, 1);
    assert_eq!(final_client.version, 2);
    assert!(candidate
        .final_objects()
        .contains_key(&task_key("native-task-0")));

    assert_eq!(candidate.application_payload().transaction_count(), 2);
    assert_eq!(candidate.execution_receipts().receipts().len(), 2);
    assert_eq!(
        candidate.runtime_object_delta_plan().version(),
        TARGET_HEIGHT
    );
    assert_eq!(
        candidate.runtime_object_delta_root(),
        candidate
            .runtime_object_delta_plan()
            .runtime_object_delta_root()
    );
    let expected_empty_evidence = BlockBodyV0::new(
        ApplicationPayloadV0::new(exact_transactions()).unwrap(),
        Vec::new(),
    )
    .unwrap()
    .evidence_root()
    .unwrap();
    assert_eq!(candidate.evidence_root(), expected_empty_evidence);

    let expected_root = candidate.runtime_object_delta_root();
    store
        .apply_runtime_object_delta_plan_v0(candidate.into_runtime_object_delta_plan())
        .unwrap();
    assert_eq!(store.parent_root_v0().unwrap().0, *expected_root.as_bytes());
    let reopened = store.read_object_v0(&client_key).unwrap().unwrap();
    assert_eq!(reopened.object_version(), 2);
    let reopened: AccountV1 = serde_json::from_slice(reopened.value()).unwrap();
    assert_eq!(reopened, account);
}

#[test]
fn exact_outer_json_is_not_reencoded_as_authority() {
    let store = fixture_store();
    let txs = exact_transactions();
    let first: serde_json::Value = serde_json::from_slice(&txs[0]).unwrap();
    let pretty = serde_json::to_vec_pretty(&first).unwrap();
    assert_ne!(pretty, txs[0]);
    let candidate =
        execute_authenticated_block_candidate_v0(&store, request(vec![pretty, txs[1].clone()]))
            .expect("semantic envelope JSON whitespace is not a new consensus rule");
    assert_eq!(
        candidate.application_payload().transaction(0).unwrap(),
        first_outer_pretty(&txs[0])
    );

    fn first_outer_pretty(canonical: &[u8]) -> Vec<u8> {
        let value: serde_json::Value = serde_json::from_slice(canonical).unwrap();
        serde_json::to_vec_pretty(&value).unwrap()
    }
}

#[test]
fn exact_inner_json_is_not_reencoded_as_authority() {
    let store = fixture_store();
    let (credit, _) = transactions();
    let pretty_inner = serde_json::to_vec_pretty(&credit).unwrap();
    assert_ne!(pretty_inner, serde_json::to_vec(&credit).unwrap());
    let pretty_outer = signed_outer_with_inner(
        81,
        "did:operator:1",
        "operator",
        "credit-1",
        credit.nonce,
        &pretty_inner,
    );
    let mut txs = exact_transactions();
    txs[0] = pretty_outer;

    let candidate = execute_authenticated_block_candidate_v0(&store, request(txs))
        .expect("semantic inner JSON whitespace is not a new consensus rule");
    assert_eq!(
        candidate.executed_transactions()[0].exact_inner_bytes(),
        pretty_inner
    );
}

#[test]
fn signature_policy_parent_and_order_substitutions_fail_closed() {
    let store = fixture_store();
    let mut txs = exact_transactions();
    let mut first: SignedCommandEnvelopeV1 = serde_json::from_slice(&txs[0]).unwrap();
    first.signature_hex.replace_range(0..2, "00");
    txs[0] = serde_json::to_vec(&first).unwrap();
    assert!(execute_authenticated_block_candidate_v0(&store, request(txs)).is_err());

    let mut reversed = exact_transactions();
    reversed.reverse();
    assert!(execute_authenticated_block_candidate_v0(&store, request(reversed)).is_err());
}

#[test]
fn caller_cannot_supply_policy_or_nonempty_evidence() {
    let store = fixture_store();
    let candidate =
        execute_authenticated_block_candidate_v0(&store, request(exact_transactions())).unwrap();
    assert!(!candidate.payload_root().is_zero());
    assert!(!candidate.receipts_root().is_zero());
    assert_ne!(candidate.runtime_object_delta_root().as_bytes(), &[0; 32]);

    let mut bad = NativeExecutionRequestV0 {
        parent_height: PARENT_HEIGHT,
        target_height: TARGET_HEIGHT,
        timestamp_ms: TIMESTAMP_MS,
        exact_outer_transactions: exact_transactions(),
        evidence_count: 1,
    };
    assert!(bad.validate().is_err());
    bad.evidence_count = 0;
    assert!(bad.validate().is_ok());
}

#[test]
fn store_bound_committed_replay_indices_reject_command_and_signer_nonce() {
    let mut command_replay = fixture_store();
    command_replay
        .mark_committed_command_v0("credit-1", "unrelated", 99)
        .unwrap();
    assert!(execute_authenticated_block_candidate_v0(
        &command_replay,
        request(exact_transactions()),
    )
    .is_err());

    let mut nonce_replay = fixture_store();
    nonce_replay
        .mark_committed_command_v0("unrelated", "did:operator:1", 1)
        .unwrap();
    assert!(
        execute_authenticated_block_candidate_v0(&nonce_replay, request(exact_transactions()),)
            .is_err()
    );
}

#[test]
fn store_bound_committed_parameters_control_payload_admission() {
    let mut fields = ConsensusParametersV0::reference_shadow_v0().fields();
    fields.max_block_bytes = 1;
    let parameters = ConsensusParametersV0::new(fields).unwrap();
    let mut store = InMemoryNativeExecutionStoreV0::new(
        CHAIN_ID,
        vec![
            signer(81, "did:operator:1", "operator"),
            signer(82, "did:client:1", "hepta"),
        ],
        parameters,
    )
    .unwrap();
    store.apply_seed_v0(0, Vec::new()).unwrap();
    store.apply_seed_v0(1, Vec::new()).unwrap();
    assert!(
        execute_authenticated_block_candidate_v0(&store, request(exact_transactions())).is_err()
    );
}

#[test]
fn tampered_parent_root_is_rejected_before_runtime_execution() {
    struct WrongRootStore(InMemoryNativeExecutionStoreV0);

    impl jmt::storage::TreeReader for WrongRootStore {
        fn get_node_option(
            &self,
            key: &jmt::storage::NodeKey,
        ) -> anyhow::Result<Option<jmt::storage::Node>> {
            self.0.get_node_option(key)
        }
        fn get_value_option(
            &self,
            version: u64,
            key: jmt::KeyHash,
        ) -> anyhow::Result<Option<Vec<u8>>> {
            self.0.get_value_option(version, key)
        }
        fn get_rightmost_leaf(
            &self,
        ) -> anyhow::Result<Option<(jmt::storage::NodeKey, jmt::storage::LeafNode)>> {
            self.0.get_rightmost_leaf()
        }
    }
    impl jmt::storage::HasPreimage for WrongRootStore {
        fn preimage(&self, key: jmt::KeyHash) -> anyhow::Result<Option<Vec<u8>>> {
            self.0.preimage(key)
        }
    }
    impl NativeExecutionStoreV0 for WrongRootStore {
        fn parent_version_v0(&self) -> anyhow::Result<u64> {
            self.0.parent_version_v0()
        }
        fn parent_root_v0(&self) -> anyhow::Result<jmt::RootHash> {
            Ok(jmt::RootHash([9; 32]))
        }
        fn chain_id_v0(&self) -> anyhow::Result<&str> {
            self.0.chain_id_v0()
        }
        fn authorized_signers_v0(&self) -> anyhow::Result<&[AuthorizedSignerV0]> {
            self.0.authorized_signers_v0()
        }
        fn signer_policy_commitment_v0(&self) -> anyhow::Result<[u8; 32]> {
            self.0.signer_policy_commitment_v0()
        }
        fn consensus_parameters_v0(&self) -> anyhow::Result<ConsensusParametersV0> {
            self.0.consensus_parameters_v0()
        }
        fn committed_command_id_v0(&self, id: &str) -> anyhow::Result<bool> {
            self.0.committed_command_id_v0(id)
        }
        fn committed_signer_nonce_v0(&self, id: &str, nonce: u64) -> anyhow::Result<bool> {
            self.0.committed_signer_nonce_v0(id, nonce)
        }
    }
    assert!(execute_authenticated_block_candidate_v0(
        &WrongRootStore(fixture_store()),
        request(exact_transactions()),
    )
    .is_err());
}

#[test]
fn excluded_legacy_authored_vector_matches_native_runtime_and_jmt_bytes() {
    const VECTOR_BYTES: &[u8] = include_bytes!("../vectors/legacy-runtime-jmt-v0.json");
    const VECTOR_SHA256: &str = include_str!("../vectors/legacy-runtime-jmt-v0.json.sha256");
    assert_eq!(
        hex::encode(Sha256::digest(VECTOR_BYTES)),
        VECTOR_SHA256.trim(),
        "checked vector raw-file hash changed"
    );
    let vector: LegacyDifferentialVectorV0 =
        serde_json::from_slice(VECTOR_BYTES).expect("decode checked legacy differential vector");
    assert_eq!(
        vector.schema,
        "trnm.native-execution-v0.legacy-differential.v1"
    );
    assert_eq!(vector.authority, "excluded-trnm-consensus-app-test");

    let parameters = ConsensusParametersV0::reference_shadow_v0();
    assert_eq!(
        hex::encode(parameters.canonical_bytes()),
        vector.parameters_cev0_hex,
        "checked vector parameters differ from frozen reference bytes"
    );
    let signers = vector
        .authorized_signers
        .iter()
        .map(|signer| {
            AuthorizedSignerV0::new(
                &signer.signer_id,
                &signer.signer_role,
                &signer.public_key_hex,
            )
            .expect("decode checked vector signer")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        hex::encode(signer_policy_commitment_v0(&signers).unwrap()),
        vector.signer_policy_commitment_hex,
        "native signer-policy commitment drifted from excluded legacy bytes"
    );
    let snapshot = hex::decode(&vector.parent_snapshot_borsh_hex)
        .expect("decode checked legacy parent snapshot hex");
    let store = InMemoryNativeExecutionStoreV0::from_legacy_snapshot_v0(
        &vector.chain_id,
        signers,
        parameters,
        &snapshot,
    )
    .expect("reconstruct checked legacy parent snapshot");
    assert_eq!(store.parent_version_v0().unwrap(), vector.parent_height);
    assert_eq!(
        hex::encode(store.parent_root_v0().unwrap().0),
        vector.parent_state_root_hex,
        "native JMT parent differs from excluded legacy snapshot"
    );
    let exact_outer_transactions = vector
        .exact_outer_transactions_hex
        .iter()
        .map(|encoded| hex::decode(encoded).expect("decode checked exact transaction hex"))
        .collect::<Vec<_>>();
    let request = NativeExecutionRequestV0::new_empty_evidence(
        vector.parent_height,
        vector.target_height,
        vector.timestamp_ms,
        exact_outer_transactions,
    )
    .unwrap();
    let candidate = execute_authenticated_block_candidate_v0(&store, request)
        .expect("execute checked legacy-authored differential vector");

    assert_eq!(
        hex::encode(candidate.payload_root().as_bytes()),
        vector.expected.payload_root_hex
    );
    assert_eq!(
        hex::encode(candidate.receipts_root().as_bytes()),
        vector.expected.receipts_root_hex
    );
    assert_eq!(
        hex::encode(candidate.evidence_root().as_bytes()),
        vector.expected.evidence_root_hex
    );
    assert_eq!(
        hex::encode(candidate.runtime_object_delta_root().as_bytes()),
        vector.expected.runtime_object_delta_root_hex
    );
    assert_eq!(
        hex::encode(candidate.execution_receipts().try_cev0_bytes().unwrap()),
        vector.expected.execution_receipts_cev0_hex
    );
    assert_eq!(
        candidate.runtime_object_delta_plan().writes().len(),
        vector.expected.runtime_writes.len()
    );
    for (expected, actual_write) in vector
        .expected
        .runtime_writes
        .iter()
        .zip(candidate.runtime_object_delta_plan().writes())
    {
        let object = candidate
            .final_objects()
            .get(&expected.logical_object_key)
            .expect("checked logical object is absent from native runtime result");
        assert_eq!(object.object_type, expected.object_type);
        assert_eq!(object.version, expected.object_version);
        assert_eq!(hex::encode(&object.value_bytes), expected.value_bytes_hex);
        assert_eq!(
            hex::encode(actual_write.key()),
            expected.authenticated_key_hex
        );
        assert_eq!(
            hex::encode(actual_write.value()),
            expected.authenticated_record_borsh_hex
        );
        assert_eq!(
            actual_write.key(),
            stored_object_key_v0(&expected.logical_object_key)
                .unwrap()
                .as_slice()
        );
    }
}
