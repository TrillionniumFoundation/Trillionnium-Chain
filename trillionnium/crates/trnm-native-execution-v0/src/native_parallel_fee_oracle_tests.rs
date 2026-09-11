//! Independently authored scheduling differentials for ordinary fee-paying
//! transfers. The zero-worker baseline uses the unchanged serial runtime.

use super::*;
use trnm_protocol::FEE_COLLECTOR_ACCOUNT_V1;

fn fixture_with_collector(
    balance: u128,
    object_version: u64,
) -> (InMemoryNativeExecutionStoreV0, ValidatorSet) {
    let (source, set) = fixture(1_000_000);
    let mut seeds = source
        .verified_live_values_v0(1)
        .unwrap()
        .into_iter()
        .map(|(key, value)| NativeStateWriteV0::raw(key, value).unwrap())
        .collect::<Vec<_>>();
    seeds.push(
        NativeStateWriteV0::from_object(
            &account_key(FEE_COLLECTOR_ACCOUNT_V1),
            ACCOUNT_OBJECT_TYPE_V1,
            object_version,
            serde_json::to_vec(&AccountV1 {
                account: FEE_COLLECTOR_ACCOUNT_V1.to_owned(),
                balance,
                nonce: 0,
            })
            .unwrap(),
        )
        .unwrap(),
    );
    let mut store = InMemoryNativeExecutionStoreV0::new(
        CHAIN,
        source.authorized_signers_v0().unwrap().to_vec(),
        source.consensus_parameters_v0().unwrap(),
    )
    .unwrap();
    store.apply_seed_v0(0, Vec::new()).unwrap();
    store.apply_seed_v0(1, seeds).unwrap();
    (store, set)
}

#[test]
fn independent_fee_paying_transfers_reuse_every_runtime_attempt_with_exact_serial_outputs() {
    // Cover both an absent collector and a real existing authenticated object.
    for collector in [None, Some((41_000_u128, 7_u64))] {
        let (store, set) = collector.map_or_else(
            || fixture(1_000_000),
            |(balance, version)| fixture_with_collector(balance, version),
        );
        let request = request(
            &store,
            &set,
            (1..9).map(|index| transfer(index, 1)).collect(),
        );
        let before = store.encode_authenticated_snapshot_v0().unwrap();
        let expected = compute(&store, &set, &request, 0).unwrap();
        let fees = expected
            .native_receipts
            .iter()
            .map(NativeExecutionReceiptV0::fee_charged)
            .sum::<u128>();
        assert!(fees > 0);
        for workers in [1, 2, 4, 8] {
            let actual = compute(&store, &set, &request, workers).unwrap();
            assert_same_complete(&expected, &actual);
            assert_eq!(actual.scheduling_counts.exact_reused, 1);
            assert_eq!(actual.scheduling_counts.fee_rebased, 7);
            assert_eq!(actual.scheduling_counts.reexecuted, 0);
            let mut applied = store.clone();
            applied.apply_complete_state_plan_v0(actual.plan).unwrap();
            let object = applied
                .read_object_v0(&account_key(FEE_COLLECTOR_ACCOUNT_V1))
                .unwrap()
                .unwrap();
            let account: AccountV1 = serde_json::from_slice(object.value()).unwrap();
            assert_eq!(
                account.balance,
                collector.map_or(0, |(balance, _)| balance) + fees
            );
            assert_eq!(account.nonce, 0);
            assert_eq!(
                object.object_version(),
                collector.map_or(0, |(_, version)| version) + 8
            );
        }
        assert_eq!(store.encode_authenticated_snapshot_v0().unwrap(), before);
    }
}

#[test]
fn collector_overflow_falls_back_to_the_same_canonical_error_without_publishing_a_prefix() {
    let (baseline, set) = fixture(1_000_000);
    let one = request(&baseline, &set, vec![transfer(1, 1)]);
    let fee = compute(&baseline, &set, &one, 0).unwrap().native_receipts[0].fee_charged();
    assert!(fee > 0);
    for (balance, version) in [(u128::MAX - fee, 1), (0, u64::MAX - 1)] {
        let (store, set) = fixture_with_collector(balance, version);
        // The first transfer really succeeds. The second speculative attempt
        // is also valid at the parent, but cannot be rebased at the new head.
        let first = request(&store, &set, vec![transfer(1, 1)]);
        compute(&store, &set, &first, 0).unwrap();
        let request = request(&store, &set, vec![transfer(1, 1), transfer(2, 1)]);
        let before = store.encode_authenticated_snapshot_v0().unwrap();
        let expected = compute(&store, &set, &request, 0)
            .err()
            .expect("second canonical fee/version increment must overflow");
        assert!(expected
            .downcast_ref::<CompleteNativeExecutionFailureV0>()
            .is_some());
        for workers in [1, 2, 4, 8] {
            let actual = compute(&store, &set, &request, workers)
                .err()
                .expect("speculation must not suppress the second error");
            assert_eq!(actual.to_string(), expected.to_string());
            assert_eq!(
                std::mem::discriminant(
                    actual
                        .downcast_ref::<CompleteNativeExecutionFailureV0>()
                        .unwrap()
                ),
                std::mem::discriminant(
                    expected
                        .downcast_ref::<CompleteNativeExecutionFailureV0>()
                        .unwrap()
                )
            );
            assert_eq!(store.encode_authenticated_snapshot_v0().unwrap(), before);
        }
    }
}

#[test]
fn explicit_collector_transfer_and_operator_credit_are_ordered_barriers() {
    for explicit in [
        outer(
            2,
            "explicit-collector-recipient",
            &transaction(
                2,
                1,
                CanonicalCommandV1::Transfer {
                    to: FEE_COLLECTOR_ACCOUNT_V1.to_owned(),
                    amount: 19,
                },
            ),
        ),
        outer(
            0,
            "explicit-collector-credit",
            &transaction(
                0,
                1,
                CanonicalCommandV1::CreditAccount {
                    account: FEE_COLLECTOR_ACCOUNT_V1.to_owned(),
                    amount: 19,
                },
            ),
        ),
    ] {
        let (store, set) = fixture(1_000_000);
        let request = request(
            &store,
            &set,
            vec![transfer(1, 1), explicit, transfer(3, 1), transfer(4, 1)],
        );
        let expected = compute(&store, &set, &request, 0).unwrap();
        for workers in [1, 2, 4, 8] {
            let actual = compute(&store, &set, &request, workers).unwrap();
            assert_same_complete(&expected, &actual);
            assert_eq!(actual.scheduling_counts.exact_reused, 2);
            assert_eq!(actual.scheduling_counts.fee_rebased, 1);
            assert_eq!(actual.scheduling_counts.reexecuted, 1);
        }
    }
}
