use ed25519_dalek::SigningKey;
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
