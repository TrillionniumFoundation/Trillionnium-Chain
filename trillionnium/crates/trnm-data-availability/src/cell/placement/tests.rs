use std::collections::BTreeSet;

use super::*;

fn provider(index: u8) -> CellRecoveryProviderPinV1 {
    CellRecoveryProviderPinV1 {
        provider_id: [index + 1; 32],
        operator: [index + 40; 32],
        administrator: [index + 80; 32],
        failure_domain: [index + 120; 32],
        domain_evidence: [index + 180; 32],
    }
}

fn providers(count: u8) -> Vec<CellRecoveryProviderPinV1> {
    (0..count).map(provider).collect()
}

fn policy(axes: &[CellRecoveryFaultAxisV1], maximum_lost_events: u8) -> CellRecoveryFaultPolicyV1 {
    CellRecoveryFaultPolicyV1 {
        axes: axes.to_vec(),
        maximum_lost_events,
    }
}

fn shards(pins: &[CellRecoveryProviderPinV1]) -> Vec<CellRecoveryPlacementV1> {
    pins.iter()
        .enumerate()
        .map(|(index, pin)| CellRecoveryPlacementV1 {
            provider_id: pin.provider_id,
            part: CellRecoveryPartV1::Rs46(index as u8),
        })
        .collect()
}

fn whole_copies(pins: &[CellRecoveryProviderPinV1]) -> Vec<CellRecoveryPlacementV1> {
    pins.iter()
        .map(|pin| CellRecoveryPlacementV1 {
            provider_id: pin.provider_id,
            part: CellRecoveryPartV1::WholeChunk,
        })
        .collect()
}

fn evaluate(
    pins: &[CellRecoveryProviderPinV1],
    placements: &[CellRecoveryPlacementV1],
    fault_policy: &CellRecoveryFaultPolicyV1,
) -> CellRecoveryPlacementReportV1 {
    evaluate_recovery_placement(pins, placements, fault_policy, 100_000).unwrap()
}

fn fails_with<T>(result: CellResultV1<T>, expected: &str) {
    match result {
        Err(CellErrorV1::Invalid(message)) => assert_eq!(message, expected),
        Err(error) => panic!("unexpected error: {error}"),
        Ok(_) => panic!("expected refusal: {expected}"),
    }
}

#[test]
fn six_distinct_shards_survive_any_two_declared_operators() {
    let pins = providers(6);
    let report = evaluate(
        &pins,
        &shards(&pins),
        &policy(&[CellRecoveryFaultAxisV1::Operator], 2),
    );
    assert!(report.recoverable_now());
    assert!(report.survives_declared_faults());
    assert_eq!(report.minimum_distinct_shards(), 4);
    assert_eq!(report.worst_case_distinct_shards(), 4);
    assert!(!report.worst_case_whole_chunk_survives());
    assert_eq!(report.scenarios(), 22);
    assert_eq!(report.steps(), 6 * 6 + 22 * 7);
    assert_eq!(report.worst_case_events().len(), 2);
    assert_eq!(report.worst_case_events()[0].identity, pins[0].operator);
    assert_eq!(report.worst_case_events()[1].identity, pins[1].operator);
}

#[test]
fn four_observed_shards_are_recoverable_but_have_no_extra_loss_margin() {
    let pins = providers(6);
    let report = evaluate(
        &pins,
        &shards(&pins)[..4],
        &policy(&[CellRecoveryFaultAxisV1::FailureDomain], 1),
    );
    assert!(report.recoverable_now());
    assert!(!report.survives_declared_faults());
    assert_eq!(report.minimum_distinct_shards(), 3);
    assert_eq!(report.worst_case_events().len(), 1);
}

#[test]
fn one_operator_can_remove_six_differently_named_providers() {
    let mut pins = providers(6);
    for pin in &mut pins {
        pin.operator = [42; 32];
    }
    let report = evaluate(
        &pins,
        &shards(&pins),
        &policy(&[CellRecoveryFaultAxisV1::Operator], 2),
    );
    assert!(report.recoverable_now());
    assert!(!report.survives_declared_faults());
    assert_eq!(report.minimum_distinct_shards(), 0);
    assert_eq!(report.scenarios(), 2);
    assert_eq!(report.worst_case_events().len(), 1);
}

#[test]
fn one_domain_removes_six_distinct_operators() {
    let mut pins = providers(6);
    for pin in &mut pins {
        pin.failure_domain = [21; 32];
    }
    let report = evaluate(
        &pins,
        &shards(&pins),
        &policy(&[CellRecoveryFaultAxisV1::FailureDomain], 1),
    );
    assert!(report.recoverable_now());
    assert!(!report.survives_declared_faults());
    assert_eq!(report.minimum_distinct_shards(), 0);
}

#[test]
fn a_shared_administrator_is_a_correlated_loss() {
    let mut pins = providers(6);
    for pin in &mut pins[..3] {
        pin.administrator = [11; 32];
    }
    let report = evaluate(
        &pins,
        &shards(&pins),
        &policy(&[CellRecoveryFaultAxisV1::Administrator], 1),
    );
    assert!(!report.survives_declared_faults());
    assert_eq!(report.minimum_distinct_shards(), 3);
    assert_eq!(
        report.worst_case_events()[0].axis,
        CellRecoveryFaultAxisV1::Administrator
    );
}

#[test]
fn three_shards_per_domain_fail_on_one_lost_domain() {
    let mut pins = providers(6);
    for (index, pin) in pins.iter_mut().enumerate() {
        pin.failure_domain = [20 + (index / 3) as u8; 32];
    }
    let report = evaluate(
        &pins,
        &shards(&pins),
        &policy(&[CellRecoveryFaultAxisV1::FailureDomain], 1),
    );
    assert!(!report.survives_declared_faults());
    assert_eq!(report.minimum_distinct_shards(), 3);
}

#[test]
fn mixed_operator_and_domain_events_are_enumerated_together() {
    // Every shard has two copies: one in each of two operators and two domains.
    // Losing either operator or either domain alone is harmless. Losing operator
    // A together with domain Y removes every copy; checking the axes separately
    // at one loss would miss this correlated two-event failure.
    let mut pins = providers(4);
    pins[0].operator = [10; 32];
    pins[1].operator = [10; 32];
    pins[2].operator = [11; 32];
    pins[3].operator = [11; 32];
    pins[0].failure_domain = [20; 32];
    pins[1].failure_domain = [21; 32];
    pins[2].failure_domain = [20; 32];
    pins[3].failure_domain = [21; 32];
    let mut placements = Vec::new();
    for index in [0, 3] {
        for shard in 0..6 {
            placements.push(CellRecoveryPlacementV1 {
                provider_id: pins[index].provider_id,
                part: CellRecoveryPartV1::Rs46(shard),
            });
        }
    }
    for axis in [
        CellRecoveryFaultAxisV1::Operator,
        CellRecoveryFaultAxisV1::FailureDomain,
    ] {
        assert!(evaluate(&pins, &placements, &policy(&[axis], 1)).survives_declared_faults());
    }
    let report = evaluate(
        &pins,
        &placements,
        &policy(
            &[
                CellRecoveryFaultAxisV1::Operator,
                CellRecoveryFaultAxisV1::FailureDomain,
            ],
            2,
        ),
    );
    assert!(!report.survives_declared_faults());
    assert_eq!(report.minimum_distinct_shards(), 0);
    assert_eq!(report.scenarios(), 11);
    // An explicit mixed pair is a permitted failing scenario, even when an
    // equally bad pure-axis pair appears first in the canonical witness order.
    assert_eq!(
        independent_support(
            &pins,
            &placements,
            &[
                CellRecoveryFaultEventV1 {
                    axis: CellRecoveryFaultAxisV1::Operator,
                    identity: [10; 32]
                },
                CellRecoveryFaultEventV1 {
                    axis: CellRecoveryFaultAxisV1::FailureDomain,
                    identity: [21; 32]
                },
            ]
        ),
        (false, 0)
    );
}

#[test]
fn cross_axis_loss_can_be_worse_than_either_two_loss_axis_audit() {
    // Nine providers span three operators by three domains. Three RS indices
    // have copies confined to row 0 OR column 0; the remaining three are fully
    // replicated. Any two rows or any two columns leave all six indices, while
    // one row plus one column can erase the three confined indices together.
    let mut pins = providers(9);
    let mut placements = Vec::new();
    for (index, pin) in pins.iter_mut().enumerate() {
        let row = index / 3;
        let column = index % 3;
        pin.operator = [20 + row as u8; 32];
        pin.failure_domain = [30 + column as u8; 32];
        for shard in 0..6 {
            if shard >= 3 || row == 0 || column == 0 {
                placements.push(CellRecoveryPlacementV1 {
                    provider_id: pin.provider_id,
                    part: CellRecoveryPartV1::Rs46(shard),
                });
            }
        }
    }
    for axis in [
        CellRecoveryFaultAxisV1::Operator,
        CellRecoveryFaultAxisV1::FailureDomain,
    ] {
        assert!(evaluate(&pins, &placements, &policy(&[axis], 2)).survives_declared_faults());
    }
    let report = evaluate(
        &pins,
        &placements,
        &policy(
            &[
                CellRecoveryFaultAxisV1::Operator,
                CellRecoveryFaultAxisV1::FailureDomain,
            ],
            2,
        ),
    );
    assert!(!report.survives_declared_faults());
    assert_eq!(report.minimum_distinct_shards(), 3);
    assert_eq!(
        report.worst_case_events(),
        &[
            CellRecoveryFaultEventV1 {
                axis: CellRecoveryFaultAxisV1::Operator,
                identity: [20; 32]
            },
            CellRecoveryFaultEventV1 {
                axis: CellRecoveryFaultAxisV1::FailureDomain,
                identity: [30; 32]
            },
        ]
    );
}

#[test]
fn copies_of_one_shard_do_not_create_four_distinct_rows() {
    let pins = providers(6);
    let placements: Vec<_> = pins
        .iter()
        .map(|pin| CellRecoveryPlacementV1 {
            provider_id: pin.provider_id,
            part: CellRecoveryPartV1::Rs46(0),
        })
        .collect();
    let report = evaluate(&pins, &placements, &policy(&[], 0));
    assert!(!report.recoverable_now());
    assert!(!report.survives_declared_faults());
    assert_eq!(report.minimum_distinct_shards(), 1);
    assert!(report.worst_case_events().is_empty());
}

#[test]
fn replication_of_each_index_can_preserve_four_rows_after_loss() {
    let pins = providers(8);
    let placements: Vec<_> = pins
        .iter()
        .enumerate()
        .map(|(index, pin)| CellRecoveryPlacementV1 {
            provider_id: pin.provider_id,
            part: CellRecoveryPartV1::Rs46((index % 4) as u8),
        })
        .collect();
    let one_loss = evaluate(
        &pins,
        &placements,
        &policy(&[CellRecoveryFaultAxisV1::Operator], 1),
    );
    assert!(one_loss.survives_declared_faults());
    assert_eq!(one_loss.minimum_distinct_shards(), 4);
    let two_losses = evaluate(
        &pins,
        &placements,
        &policy(&[CellRecoveryFaultAxisV1::Operator], 2),
    );
    assert!(!two_losses.survives_declared_faults());
    assert_eq!(two_losses.minimum_distinct_shards(), 3);
}

#[test]
fn three_whole_copies_survive_two_losses_without_manufacturing_shards() {
    let pins = providers(3);
    let report = evaluate(
        &pins,
        &whole_copies(&pins),
        &policy(&[CellRecoveryFaultAxisV1::Operator], 2),
    );
    assert!(report.recoverable_now());
    assert!(report.survives_declared_faults());
    assert_eq!(report.minimum_distinct_shards(), 0);
    assert_eq!(report.worst_case_distinct_shards(), 0);
    assert!(report.worst_case_whole_chunk_survives());
}

#[test]
fn whole_copy_does_not_hide_loss_of_insufficient_shard_fallback() {
    let pins = providers(4);
    let mut placements = whole_copies(&pins[..1]);
    placements.extend(
        pins[1..]
            .iter()
            .enumerate()
            .map(|(index, pin)| CellRecoveryPlacementV1 {
                provider_id: pin.provider_id,
                part: CellRecoveryPartV1::Rs46(index as u8),
            }),
    );
    let report = evaluate(
        &pins,
        &placements,
        &policy(&[CellRecoveryFaultAxisV1::Operator], 1),
    );
    assert!(report.recoverable_now());
    assert!(!report.survives_declared_faults());
    // The global minimum raw shard count occurs while the whole copy survives;
    // the worst recovery witness instead removes that whole copy.
    assert_eq!(report.minimum_distinct_shards(), 2);
    assert_eq!(report.worst_case_distinct_shards(), 3);
    assert!(!report.worst_case_whole_chunk_survives());
    assert_eq!(report.worst_case_events()[0].identity, pins[0].operator);
}

#[test]
fn empty_observations_remain_unrecoverable_and_account_every_scenario() {
    let pins = providers(6);
    let report = evaluate(&pins, &[], &policy(&[CellRecoveryFaultAxisV1::Operator], 2));
    assert!(!report.recoverable_now());
    assert!(!report.survives_declared_faults());
    assert_eq!(report.scenarios(), 22);
    assert_eq!(report.steps(), 190);
    assert_eq!(report.minimum_distinct_shards(), 0);
    assert!(report.worst_case_events().is_empty());
}

#[test]
fn exact_work_budget_is_required_and_not_refreshed_by_early_success() {
    let pins = providers(6);
    let fault_policy = policy(&[CellRecoveryFaultAxisV1::Operator], 2);
    for placements in [shards(&pins), whole_copies(&pins), Vec::new()] {
        assert_eq!(
            evaluate_recovery_placement(&pins, &placements, &fault_policy, 190)
                .unwrap()
                .steps(),
            190
        );
        fails_with(
            evaluate_recovery_placement(&pins, &placements, &fault_policy, 189),
            "recovery placement evaluation budget",
        );
        fails_with(
            evaluate_recovery_placement(&pins, &placements, &fault_policy, 0),
            "recovery placement evaluation budget",
        );
    }
}

#[test]
fn all_axes_and_maximum_roster_have_bounded_exact_work() {
    let pins = providers(16);
    let fault_policy = policy(
        &[
            CellRecoveryFaultAxisV1::Operator,
            CellRecoveryFaultAxisV1::Administrator,
            CellRecoveryFaultAxisV1::FailureDomain,
        ],
        2,
    );
    let report =
        evaluate_recovery_placement(&pins, &whole_copies(&pins), &fault_policy, 20_777).unwrap();
    assert_eq!(report.scenarios(), MAX_CELL_RECOVERY_FAULT_SCENARIOS_V1);
    assert_eq!(report.steps(), 48 * 16 + 1_177 * 17);
    assert!(report.survives_declared_faults());
    fails_with(
        evaluate_recovery_placement(&pins, &whole_copies(&pins), &fault_policy, 20_776),
        "recovery placement evaluation budget",
    );
}

#[test]
fn equal_bytes_on_different_axes_are_distinct_typed_events() {
    let mut pins = providers(1);
    pins[0].operator = [7; 32];
    pins[0].administrator = [7; 32];
    pins[0].failure_domain = [7; 32];
    let report = evaluate(
        &pins,
        &whole_copies(&pins),
        &policy(
            &[
                CellRecoveryFaultAxisV1::Operator,
                CellRecoveryFaultAxisV1::Administrator,
                CellRecoveryFaultAxisV1::FailureDomain,
            ],
            2,
        ),
    );
    assert_eq!(report.scenarios(), 7);
    assert_eq!(report.steps(), 3 + 7 * 2);
    assert_eq!(
        report.worst_case_events()[0].axis,
        CellRecoveryFaultAxisV1::Operator
    );
}

#[test]
fn no_loss_policy_checks_only_the_current_declared_parts() {
    let pins = providers(6);
    let placements = shards(&pins);
    for axes in [vec![], vec![CellRecoveryFaultAxisV1::Operator]] {
        let report = evaluate(&pins, &placements[..4], &policy(&axes, 0));
        assert!(report.recoverable_now());
        assert!(report.survives_declared_faults());
        assert_eq!(report.scenarios(), 1);
        assert_eq!(report.steps(), 7);
    }
}

#[test]
fn invalid_roster_identity_order_duplicate_and_bounds_are_rejected() {
    let pins = providers(6);
    let fault_policy = policy(&[], 0);
    let invalid = |pins: &[CellRecoveryProviderPinV1], expected| {
        fails_with(
            evaluate_recovery_placement(pins, &[], &fault_policy, 100_000),
            expected,
        );
    };
    invalid(&[], "recovery placement bounds");
    invalid(&providers(17), "recovery placement bounds");
    let mut changed = pins.clone();
    changed.swap(0, 1);
    invalid(&changed, "recovery provider order/duplicates");
    changed = pins.clone();
    changed[1] = changed[0];
    invalid(&changed, "recovery provider order/duplicates");
    for field in 0..5 {
        let mut changed = pins.clone();
        match field {
            0 => changed[0].provider_id = [0; 32],
            1 => changed[0].operator = [0; 32],
            2 => changed[0].administrator = [0; 32],
            3 => changed[0].failure_domain = [0; 32],
            _ => changed[0].domain_evidence = [0; 32],
        }
        invalid(&changed, "recovery provider identity");
    }
}

#[test]
fn invalid_placements_are_refused_instead_of_silently_deduplicated() {
    let pins = providers(6);
    let fault_policy = policy(&[], 0);
    let invalid = |placements: &[CellRecoveryPlacementV1], expected| {
        fails_with(
            evaluate_recovery_placement(&pins, placements, &fault_policy, 100_000),
            expected,
        );
    };
    let mut changed = shards(&pins);
    changed.swap(0, 1);
    invalid(&changed, "recovery placement order/duplicates");
    changed = shards(&pins);
    changed.insert(0, changed[0]);
    invalid(&changed, "recovery placement order/duplicates");
    invalid(
        &[CellRecoveryPlacementV1 {
            provider_id: [250; 32],
            part: CellRecoveryPartV1::WholeChunk,
        }],
        "recovery unknown provider",
    );
    invalid(
        &[CellRecoveryPlacementV1 {
            provider_id: pins[0].provider_id,
            part: CellRecoveryPartV1::Rs46(6),
        }],
        "recovery RS46 shard index",
    );
    invalid(
        &vec![shards(&pins)[0]; MAX_CELL_RECOVERY_PLACEMENTS_V1 + 1],
        "recovery placement bounds",
    );
    // Within one provider, WholeChunk then RS0 is canonical; the reverse is not.
    let mut same_provider = vec![
        CellRecoveryPlacementV1 {
            provider_id: pins[0].provider_id,
            part: CellRecoveryPartV1::WholeChunk,
        },
        CellRecoveryPlacementV1 {
            provider_id: pins[0].provider_id,
            part: CellRecoveryPartV1::Rs46(0),
        },
    ];
    assert!(evaluate(&pins, &same_provider, &fault_policy).recoverable_now());
    same_provider.reverse();
    invalid(&same_provider, "recovery placement order/duplicates");
}

#[test]
fn invalid_axis_order_duplicates_empty_fault_model_and_large_budget_are_rejected() {
    let pins = providers(1);
    for fault_policy in [
        policy(
            &[
                CellRecoveryFaultAxisV1::FailureDomain,
                CellRecoveryFaultAxisV1::Operator,
            ],
            1,
        ),
        policy(
            &[
                CellRecoveryFaultAxisV1::Operator,
                CellRecoveryFaultAxisV1::Operator,
            ],
            1,
        ),
        policy(&[], 1),
    ] {
        fails_with(
            evaluate_recovery_placement(&pins, &[], &fault_policy, 100_000),
            "recovery fault axes",
        );
    }
    for fault_policy in [
        policy(&[CellRecoveryFaultAxisV1::Operator; 4], 0),
        policy(&[CellRecoveryFaultAxisV1::Operator], 3),
    ] {
        fails_with(
            evaluate_recovery_placement(&pins, &[], &fault_policy, 100_000),
            "recovery placement bounds",
        );
    }
}

// Independent, set-based reference: no production masks, bit arithmetic for
// shards, or production scenario enumeration. Parts are selected by searching
// their original providers and matching each explicitly removed event.
fn independent_support(
    pins: &[CellRecoveryProviderPinV1],
    placements: &[CellRecoveryPlacementV1],
    failures: &[CellRecoveryFaultEventV1],
) -> (bool, u8) {
    let mut indices = BTreeSet::new();
    let mut whole = false;
    for placement in placements {
        let pin = pins
            .iter()
            .find(|pin| pin.provider_id == placement.provider_id)
            .unwrap();
        let removed = failures.iter().any(|event| match event.axis {
            CellRecoveryFaultAxisV1::Operator => pin.operator == event.identity,
            CellRecoveryFaultAxisV1::Administrator => pin.administrator == event.identity,
            CellRecoveryFaultAxisV1::FailureDomain => pin.failure_domain == event.identity,
        });
        if !removed {
            match placement.part {
                CellRecoveryPartV1::WholeChunk => whole = true,
                CellRecoveryPartV1::Rs46(index) => {
                    indices.insert(index);
                }
            }
        }
    }
    (whole, indices.len() as u8)
}

#[test]
fn bounded_failure_enumerator_matches_independent_subset_oracle() {
    for seed in 0..96_usize {
        let mut pins = providers(6);
        let mut placements = Vec::new();
        for (index, pin) in pins.iter_mut().enumerate() {
            pin.operator = [10 + ((index + seed) % 2) as u8; 32];
            pin.failure_domain = [20 + ((index * (seed % 3 + 1) + seed / 3) % 3) as u8; 32];
            if !(seed + index).is_multiple_of(5) {
                placements.push(CellRecoveryPlacementV1 {
                    provider_id: pin.provider_id,
                    part: CellRecoveryPartV1::Rs46(index as u8),
                });
            }
            if (seed + index).is_multiple_of(7) {
                placements.push(CellRecoveryPlacementV1 {
                    provider_id: pin.provider_id,
                    part: CellRecoveryPartV1::WholeChunk,
                });
            }
            if seed.is_multiple_of(3) && index.is_multiple_of(2) {
                placements.push(CellRecoveryPlacementV1 {
                    provider_id: pin.provider_id,
                    part: CellRecoveryPartV1::Rs46(((index + 1) % 6) as u8),
                });
            }
        }
        placements.sort_unstable();
        let axes = [
            CellRecoveryFaultAxisV1::Operator,
            CellRecoveryFaultAxisV1::FailureDomain,
        ];
        let mut reference_events = BTreeSet::new();
        for pin in &pins {
            reference_events.insert(CellRecoveryFaultEventV1 {
                axis: axes[0],
                identity: pin.operator,
            });
            reference_events.insert(CellRecoveryFaultEventV1 {
                axis: axes[1],
                identity: pin.failure_domain,
            });
        }
        let reference_events: Vec<_> = reference_events.into_iter().collect();
        assert!(reference_events.len() <= 5);
        for maximum_lost in 0..=2 {
            let fault_policy = policy(&axes, maximum_lost);
            let report = evaluate(&pins, &placements, &fault_policy);
            let mut expected_survives = true;
            let mut expected_minimum = 6;
            let mut expected_scenarios = 0;
            let mut expected_worst = (true, 7);
            for subset in 0_u32..1_u32 << reference_events.len() {
                if subset.count_ones() > u32::from(maximum_lost) {
                    continue;
                }
                let failed: Vec<_> = reference_events
                    .iter()
                    .enumerate()
                    .filter_map(|(index, event)| (subset & (1 << index) != 0).then_some(*event))
                    .collect();
                let support = independent_support(&pins, &placements, &failed);
                expected_survives &= support.0 || support.1 >= 4;
                expected_minimum = expected_minimum.min(support.1);
                expected_worst = expected_worst.min(support);
                expected_scenarios += 1;
            }
            let now = independent_support(&pins, &placements, &[]);
            assert_eq!(report.recoverable_now(), now.0 || now.1 >= 4, "seed {seed}");
            assert_eq!(
                report.survives_declared_faults(),
                expected_survives,
                "seed {seed}"
            );
            assert_eq!(
                report.minimum_distinct_shards(),
                expected_minimum,
                "seed {seed}"
            );
            assert_eq!(report.scenarios(), expected_scenarios, "seed {seed}");
            assert_eq!(
                (
                    report.worst_case_whole_chunk_survives(),
                    report.worst_case_distinct_shards()
                ),
                expected_worst,
                "seed {seed}"
            );
            assert_eq!(
                independent_support(&pins, &placements, report.worst_case_events()),
                expected_worst,
                "seed {seed}"
            );
        }
    }
}
