//! Native complete-body scheduling differentials. The zero-worker path skips
//! speculation but shares the frozen runtime and codecs; it is not an
//! independently implemented protocol oracle.

use ed25519_dalek::SigningKey;
use trnm_consensus_types::{
    ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch, ProtocolVersion, Validator,
    ValidatorId, VotingPower,
};
use trnm_finality_types::crypto::public_key_hex;
use trnm_native_application::{ApplicationCommitIdV0, BlockIdV0};
use trnm_protocol::{
    account_key, AccountV1, CanonicalCommandV1, ACCOUNT_OBJECT_TYPE_V1, CANONICAL_TX_SCHEMA_V1,
};

use super::*;
use crate::validator_lifecycle::{ValidatorGovernanceV1, VALIDATOR_GOVERNANCE_SCHEMA_V1};

#[path = "native_parallel_fee_oracle_tests.rs"]
mod fee_oracle_tests;

const CHAIN: &str = "native-parallel-test";
const GENESIS: [u8; 32] = [7; 32];
const TIMESTAMP: u64 = 1_700_000_001_000;

fn signing_key(index: u8) -> SigningKey {
    SigningKey::from_bytes(&[81 + index; 32])
}

fn signer_id(index: u8) -> String {
    format!("did:native-parallel:{index}")
}

fn fixture(balance: u128) -> (InMemoryNativeExecutionStoreV0, ValidatorSet) {
    let parameters = ConsensusParametersV0::reference_shadow_v0();
    let validators = (0..4u8)
        .map(|index| {
            Validator::new(
                ValidatorId::from_bytes(format!("validator-{index}").as_bytes()).unwrap(),
                ConsensusPublicKey::new(
                    SigningKey::from_bytes(&[20 + index; 32])
                        .verifying_key()
                        .to_bytes(),
                ),
                VotingPower::new(1).unwrap(),
            )
            .unwrap()
        })
        .collect();
    let set = ValidatorSet::new(
        GenesisHash::new(GENESIS),
        ChainId::new(CHAIN).unwrap(),
        ProtocolVersion::V0,
        Epoch::new(0),
        parameters.hash(),
        validators,
    )
    .unwrap();
    let signers = (0..9u8)
        .map(|index| {
            AuthorizedSignerV0::new(
                signer_id(index),
                if index == 0 { "operator" } else { "hepta" },
                public_key_hex(&signing_key(index)),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let lifecycle = ValidatorLifecycleStateV1::from_genesis(
        CHAIN.to_string(),
        1,
        hex::encode(signer_policy_commitment_v0(&signers).unwrap()),
        ValidatorGovernanceV1 {
            schema: VALIDATOR_GOVERNANCE_SCHEMA_V1.to_string(),
            signer_id: signer_id(0),
            min_activation_delay_blocks: 2,
            unsafe_allow_single_validator_genesis: false,
        },
        set.validators()
            .iter()
            .map(|validator| ConsensusValidatorV1 {
                public_key_hex: hex::encode(validator.consensus_key().as_bytes()),
                voting_power: validator.voting_power().get(),
            })
            .collect(),
    )
    .unwrap();
    let mut store = InMemoryNativeExecutionStoreV0::new(CHAIN, signers, parameters).unwrap();
    store.apply_seed_v0(0, Vec::new()).unwrap();
    let mut seeds = vec![validator_lifecycle_seed_write_v0(1, &lifecycle).unwrap()];
    for index in 1..9 {
        seeds.push(
            NativeStateWriteV0::from_object(
                &account_key(&signer_id(index)),
                ACCOUNT_OBJECT_TYPE_V1,
                1,
                serde_json::to_vec(&AccountV1 {
                    account: signer_id(index),
                    balance,
                    nonce: 0,
                })
                .unwrap(),
            )
            .unwrap(),
        );
    }
    store.apply_seed_v0(1, seeds).unwrap();
    (store, set)
}

fn transaction(index: u8, nonce: u64, command: CanonicalCommandV1) -> CanonicalTxV1 {
    CanonicalTxV1 {
        schema: CANONICAL_TX_SCHEMA_V1.to_string(),
        sender: signer_id(index),
        nonce,
        max_gas: 100_000,
        fee_limit: 100_000,
        command,
    }
}

fn outer(index: u8, label: &str, transaction: &CanonicalTxV1) -> Vec<u8> {
    let inner = serde_json::to_vec(transaction).unwrap();
    serde_json::to_vec(
        &SignedCommandEnvelopeV1::sign(
            CHAIN,
            label,
            signer_id(index),
            if index == 0 { "operator" } else { "hepta" },
            transaction.nonce,
            TIMESTAMP - 1000,
            TIMESTAMP + 1000,
            CANONICAL_TX_PAYLOAD_TYPE_V1,
            &inner,
            &signing_key(index),
        )
        .unwrap(),
    )
    .unwrap()
}

fn transfer(index: u8, nonce: u64) -> Vec<u8> {
    outer(
        index,
        &format!("transfer-{index}-{nonce}"),
        &transaction(
            index,
            nonce,
            CanonicalCommandV1::Transfer {
                to: format!("did:recipient:{index}"),
                amount: 10,
            },
        ),
    )
}

fn request(
    store: &InMemoryNativeExecutionStoreV0,
    set: &ValidatorSet,
    transactions: Vec<Vec<u8>>,
) -> NativeBlockPreviewRequestV0 {
    NativeBlockPreviewRequestV0::new(
        ChainIdV0::new(CHAIN).unwrap(),
        GenesisHashV0::new(GENESIS).unwrap(),
        ApplicationHeadV0::new(
            HeightV0::new(1),
            BlockIdV0::new([9; 32]).unwrap(),
            StateRootV0::new(store.parent_root_v0().unwrap().0).unwrap(),
            ApplicationCommitIdV0::new([10; 32]).unwrap(),
        ),
        HeightV0::new(2),
        TIMESTAMP,
        ValidatorSetIdV0::new(*set.id().as_bytes()).unwrap(),
        transactions,
    )
    .unwrap()
}

fn compute(
    store: &InMemoryNativeExecutionStoreV0,
    set: &ValidatorSet,
    request: &NativeBlockPreviewRequestV0,
    workers: usize,
) -> Result<ComputedCompleteExecutionV0> {
    compute_complete_native_block_with_workers_v0(
        store,
        set,
        GenesisHash::new(GENESIS),
        request,
        workers,
    )
}

fn assert_same_complete(
    expected: &ComputedCompleteExecutionV0,
    actual: &ComputedCompleteExecutionV0,
) {
    assert_eq!(actual.payload_root, expected.payload_root);
    assert_eq!(actual.post_state_root, expected.post_state_root);
    assert_eq!(actual.receipts_root, expected.receipts_root);
    assert_eq!(actual.evidence_root, expected.evidence_root);
    assert_eq!(actual.native_receipts, expected.native_receipts);
    assert_eq!(actual.plan.writes(), expected.plan.writes());
    assert_eq!(actual.replay_identities, expected.replay_identities);
    assert_eq!(actual.final_lifecycle, expected.final_lifecycle);
}

#[test]
fn native_workers_compute_real_runtime_receipts_and_mutations_on_eight_threads() {
    let (store, set) = fixture(1_000_000);
    let request = request(
        &store,
        &set,
        (1..9).map(|index| transfer(index, 1)).collect(),
    );
    let before = store.encode_authenticated_snapshot_v0().unwrap();
    let outcomes = native_parallel::speculate_transactions_v0(
        native_parallel::NativeSpeculationContextV0 {
            store: &store,
            parent_version: 1,
            parent_root: store.parent_root_v0().unwrap(),
            height: 2,
            chain_id: CHAIN,
            timestamp_ms: TIMESTAMP,
            signers: store.authorized_signers_v0().unwrap(),
            changes: &BTreeMap::new(),
        },
        request.transactions(),
        8,
    );
    let mut threads = std::collections::HashSet::new();
    for result in outcomes {
        let attempt = result.expect("valid runtime input was computed");
        threads.insert(attempt.worker_id);
        assert_ne!(attempt.worker_id, std::thread::current().id());
        let receipt = attempt.outcome.unwrap();
        assert!(receipt.gas_used > 0 && receipt.fee_charged > 0);
        assert!(receipt.mutations.len() >= 3);
        assert!(!receipt.events.is_empty());
    }
    assert_eq!(threads.len(), 8);
    let expected = compute(&store, &set, &request, 0).unwrap();
    for workers in [1, 2, 4, 8] {
        let actual = compute(&store, &set, &request, workers).unwrap();
        assert_same_complete(&expected, &actual);
        let mut applied = store.clone();
        assert_eq!(
            applied
                .apply_complete_state_plan_v0(actual.plan)
                .unwrap()
                .into_bytes(),
            expected.post_state_root
        );
        let snapshot = applied.encode_authenticated_snapshot_v0().unwrap();
        let reopened = InMemoryNativeExecutionStoreV0::decode_authenticated_snapshot_v0(
            CHAIN,
            store.authorized_signers_v0().unwrap().to_vec(),
            store.consensus_parameters_v0().unwrap(),
            BTreeSet::new(),
            BTreeSet::new(),
            &snapshot,
        )
        .unwrap();
        assert_eq!(
            reopened.parent_root_v0().unwrap().0,
            expected.post_state_root
        );
    }
    assert_eq!(store.encode_authenticated_snapshot_v0().unwrap(), before);
}

#[test]
fn native_parent_failure_is_reexecuted_after_credit_and_nonce_predecessors() {
    let (store, set) = fixture(0);
    let credit = outer(
        0,
        "initial-credit",
        &transaction(
            0,
            1,
            CanonicalCommandV1::CreditAccount {
                account: signer_id(1),
                amount: 1_000_000,
            },
        ),
    );
    let mut transactions = vec![credit];
    transactions.extend((1..=40).map(|nonce| transfer(1, nonce)));
    let request = request(&store, &set, transactions);
    let expected = compute(&store, &set, &request, 0).unwrap();
    for workers in [1, 2, 4, 8] {
        assert_same_complete(
            &expected,
            &compute(&store, &set, &request, workers).unwrap(),
        );
    }
    assert_eq!(expected.native_receipts.len(), 41);
}

#[test]
fn native_policy_change_invalidates_speculation_without_changing_fee_semantics() {
    let (store, set) = fixture(1_000_000);
    let policy = outer(
        0,
        "policy-change",
        &transaction(
            0,
            1,
            CanonicalCommandV1::SetFeePolicy {
                gas_price: 2,
                base_gas: 1000,
                byte_gas: 1,
            },
        ),
    );
    let request = request(&store, &set, vec![transfer(1, 1), policy, transfer(2, 1)]);
    let expected = compute(&store, &set, &request, 0).unwrap();
    for workers in [1, 2, 4, 8] {
        assert_same_complete(
            &expected,
            &compute(&store, &set, &request, workers).unwrap(),
        );
    }
}

#[test]
fn native_validator_transition_is_an_ordered_barrier_with_identical_system_writes() {
    let (store, set) = fixture(1_000_000);
    let live = store.verified_live_values_v0(1).unwrap();
    let lifecycle = load_validator_lifecycle_from_live_v0(&live, 1).unwrap();
    let mut target = lifecycle.active_validators.clone();
    for validator in &mut target {
        validator.voting_power *= 2;
    }
    let transition = ValidatorSetTransitionV1 {
        schema: VALIDATOR_TRANSITION_SCHEMA_V1.to_string(),
        chain_id: CHAIN.to_string(),
        transition_id: "scheduled-transition".to_string(),
        base_validator_set_hash_hex: lifecycle.active_set_hash_hex().unwrap(),
        activation_height: 4,
        target_validators: target,
        new_validator_proofs: Vec::new(),
    };
    let envelope = SignedCommandEnvelopeV1::sign(
        CHAIN,
        &transition.transition_id,
        signer_id(0),
        "operator",
        1,
        TIMESTAMP - 1000,
        TIMESTAMP + 1000,
        VALIDATOR_TRANSITION_PAYLOAD_TYPE_V1,
        &serde_json::to_vec(&transition).unwrap(),
        &signing_key(0),
    )
    .unwrap();
    let request = request(
        &store,
        &set,
        vec![
            transfer(1, 1),
            serde_json::to_vec(&envelope).unwrap(),
            transfer(2, 1),
        ],
    );
    let expected = compute(&store, &set, &request, 0).unwrap();
    assert!(expected.final_lifecycle.pending_transition.is_some());
    assert_eq!(expected.final_lifecycle.governance_sequence, 1);
    for workers in [1, 2, 4, 8] {
        assert_same_complete(
            &expected,
            &compute(&store, &set, &request, workers).unwrap(),
        );
    }
}

#[test]
fn native_speculative_success_cannot_bypass_canonical_policy_rejection_or_publish_partial_writes() {
    let (store, set) = fixture(1_000_000);
    let policy = outer(
        0,
        "expensive-policy",
        &transaction(
            0,
            1,
            CanonicalCommandV1::SetFeePolicy {
                gas_price: 1000,
                base_gas: 1000,
                byte_gas: 1,
            },
        ),
    );
    let request = request(&store, &set, vec![transfer(1, 1), policy, transfer(2, 1)]);
    let before = store.encode_authenticated_snapshot_v0().unwrap();
    let expected = compute(&store, &set, &request, 0).err().unwrap();
    assert!(expected
        .downcast_ref::<CompleteNativeExecutionFailureV0>()
        .is_some());
    for workers in [1, 2, 4, 8] {
        assert_eq!(
            compute(&store, &set, &request, workers)
                .err()
                .unwrap()
                .to_string(),
            expected.to_string()
        );
        assert_eq!(store.encode_authenticated_snapshot_v0().unwrap(), before);
    }
}

#[test]
fn native_outer_and_runtime_failures_are_selected_in_canonical_transaction_order() {
    let (store, set) = fixture(1_000_000);
    let bad_nonce = transfer(1, 9);
    let malformed = b"not-an-envelope".to_vec();
    let duplicate = transfer(1, 1);
    for transactions in [
        vec![bad_nonce.clone(), malformed.clone()],
        vec![malformed, bad_nonce.clone()],
        vec![duplicate.clone(), duplicate, bad_nonce],
    ] {
        let request = request(&store, &set, transactions);
        let expected = compute(&store, &set, &request, 0).err().unwrap();
        for workers in [1, 2, 4, 8] {
            assert_eq!(
                compute(&store, &set, &request, workers)
                    .err()
                    .unwrap()
                    .to_string(),
                expected.to_string()
            );
        }
    }
}
