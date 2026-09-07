#!/usr/bin/env python3
"""One-shot PR #84 source patcher. Deleted after the verified fix is committed."""

from pathlib import Path


MAIN_PATH = Path("trillionnium/crates/trnm-node/src/main.rs")
GATE_PATH = Path("trillionnium/scripts/check_event_fields.sh")


def replace_test(source: str, old_name: str, replacement: str) -> str:
    fn_marker = f"    fn {old_name}("
    fn_pos = source.find(fn_marker)
    if fn_pos < 0:
        return source
    start = source.rfind("    #[test]", 0, fn_pos)
    next_attr = source.find("\n    #[test]", fn_pos)
    if start < 0 or next_attr < 0:
        raise RuntimeError(f"could not bound test {old_name}")
    return source[:start] + replacement.rstrip() + "\n" + source[next_attr + 1 :]


def patch_main() -> None:
    main = MAIN_PATH.read_text()

    selector = r'''fn task_frontier_indices(mempool: &VecDeque<MockTx>) -> Vec<usize> {
    let mut seen_task_ids = HashSet::new();
    mempool
        .iter()
        .enumerate()
        .filter_map(|(idx, tx)| seen_task_ids.insert(task_id_of(tx)).then_some(idx))
        .collect()
}

fn pick_txs_with_critical_guard(
    mempool: &mut VecDeque<MockTx>,
    txs_per_block: usize,
) -> Vec<MockTx> {
    if txs_per_block == 0 || mempool.is_empty() {
        return Vec::new();
    }

    // A task lifecycle is state-dependent. Only the first queued operation for each
    // task may enter a block; otherwise challenge/resolve can leapfrog create/reveal,
    // fail pre-execution against the prior state snapshot, and be dropped permanently.
    let frontier_indices = task_frontier_indices(mempool);
    let pick_limit = txs_per_block.min(frontier_indices.len());
    if pick_limit == 0 {
        return Vec::new();
    }

    let any_critical = frontier_indices
        .iter()
        .any(|&idx| is_critical_tx(&mempool[idx]));
    let all_critical = frontier_indices
        .iter()
        .all(|&idx| is_critical_tx(&mempool[idx]));

    let selected_indices: Vec<usize> = if !any_critical || all_critical {
        frontier_indices.into_iter().take(pick_limit).collect()
    } else {
        // Preserve critical-lane anti-starvation, but only among dependency-safe task
        // frontiers. Admission ids address frontier positions rather than raw queue ids.
        let mut lane = LaneAdmissionGate::new(frontier_indices.len(), 1);
        for (frontier_pos, &mempool_idx) in frontier_indices.iter().enumerate() {
            let class = if is_critical_tx(&mempool[mempool_idx]) {
                IngressClass::Critical
            } else {
                IngressClass::Normal
            };
            let _ = lane.admit(frontier_pos as u64, class);
        }

        let mut selected = Vec::with_capacity(pick_limit);
        while selected.len() < pick_limit {
            let Some(frontier_id) = lane.pop_ready() else {
                break;
            };
            if let Some(&mempool_idx) = frontier_indices.get(frontier_id as usize) {
                selected.push(mempool_idx);
            }
        }
        selected
    };

    let mut indexed: Vec<(usize, usize)> = selected_indices
        .into_iter()
        .enumerate()
        .map(|(position, index)| (index, position))
        .collect();
    let mut picked_slots: Vec<Option<MockTx>> =
        (0..indexed.len()).map(|_| None).collect();
    indexed.sort_unstable_by(|(lhs, _), (rhs, _)| rhs.cmp(lhs));

    for (index, position) in indexed {
        if let Some(tx) = mempool.remove(index) {
            picked_slots[position] = Some(tx);
        }
    }

    picked_slots.into_iter().flatten().collect()
}'''

    if "fn task_frontier_indices(" not in main:
        start = main.index("fn pick_txs_with_critical_guard(")
        end = main.index("\nfn actor_of(", start)
        main = main[:start] + selector + "\n\n" + main[end + 1 :]

    old_demo_resolve = '''        q.push_back(MockTx::Resolve {
            task_id,
            slash_worker: false,
            resolver: "governance.resolve_authority".into(),
        });
'''
    new_demo_resolve = '''        q.push_back(MockTx::Resolve {
            task_id,
            slash_worker: false,
            resolver: "demo-resolver-a".into(),
        });
        q.push_back(MockTx::Resolve {
            task_id,
            slash_worker: false,
            resolver: "demo-resolver-b".into(),
        });
'''
    if old_demo_resolve in main:
        main = main.replace(old_demo_resolve, new_demo_resolve, 1)
    elif 'resolver: "demo-resolver-b".into()' not in main:
        raise RuntimeError("demo resolve fixture marker not found")

    state_marker = '''    let mut state = StateStore::new();
    state.set_balance("challenger", 1_000_000);
'''
    seeded_state = '''    let mut state = StateStore::new();
    state
        .set_gov_param_bootstrap_unchecked(
            9_500,
            "resolve_authority".into(),
            "demo-resolver-a,demo-resolver-b".into(),
        )
        .map_err(|err| anyhow::anyhow!("seed demo resolve authority failed: {}", err))?;
    state.set_balance("challenger", 1_000_000);
'''
    if state_marker in main:
        main = main.replace(state_marker, seeded_state, 1)
    elif "demo-resolver-a,demo-resolver-b" not in main:
        raise RuntimeError("state bootstrap marker not found")

    main = replace_test(
        main,
        "critical_txs_are_selected_even_when_normal_queue_is_long",
        r'''    #[test]
    fn critical_guard_does_not_jump_same_task_prerequisites() {
        let mut mempool = VecDeque::from(vec![
            MockTx::CreateTask {
                task_id: 1,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::AcceptTask {
                task_id: 1,
                worker: "w1".into(),
            },
            MockTx::Commit {
                task_id: 1,
                worker: "w1".into(),
                committed_hash: [3u8; 32],
            },
            MockTx::CreateTask {
                task_id: 2,
                creator: "bob".into(),
                bounty: 20,
            },
            MockTx::Challenge {
                task_id: 1,
                challenger: "c1".into(),
                bond: 10,
            },
            MockTx::Resolve {
                task_id: 1,
                slash_worker: false,
                resolver: "gov".into(),
            },
        ]);

        let picked = pick_txs_with_critical_guard(&mut mempool, 2);
        assert_eq!(picked.len(), 2);
        assert!(matches!(picked[0], MockTx::CreateTask { task_id: 1, .. }));
        assert!(matches!(picked[1], MockTx::CreateTask { task_id: 2, .. }));
        assert!(mempool
            .iter()
            .any(|tx| matches!(tx, MockTx::Challenge { task_id: 1, .. })));
        assert!(mempool
            .iter()
            .any(|tx| matches!(tx, MockTx::Resolve { task_id: 1, .. })));
    }
''',
    )

    main = replace_test(
        main,
        "critical_guard_fast_path_drains_fifo_when_capacity_covers_queue",
        r'''    #[test]
    fn critical_guard_capacity_does_not_bypass_same_task_frontier() {
        let mut mempool = VecDeque::from(vec![
            MockTx::CreateTask {
                task_id: 1,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::AcceptTask {
                task_id: 1,
                worker: "w1".into(),
            },
            MockTx::Challenge {
                task_id: 1,
                challenger: "c1".into(),
                bond: 10,
            },
        ]);

        let first = pick_txs_with_critical_guard(&mut mempool, 3);
        assert_eq!(first.len(), 1);
        assert!(matches!(first[0], MockTx::CreateTask { .. }));

        let second = pick_txs_with_critical_guard(&mut mempool, 3);
        assert_eq!(second.len(), 1);
        assert!(matches!(second[0], MockTx::AcceptTask { .. }));

        let third = pick_txs_with_critical_guard(&mut mempool, 3);
        assert_eq!(third.len(), 1);
        assert!(matches!(third[0], MockTx::Challenge { .. }));
        assert!(mempool.is_empty());
    }
''',
    )

    main = replace_test(
        main,
        "critical_guard_normal_only_backlog_drains_fifo_prefix_without_reordering",
        r'''    #[test]
    fn critical_guard_normal_backlog_advances_each_task_frontier() {
        let mut mempool = VecDeque::from(vec![
            MockTx::CreateTask {
                task_id: 31,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::AcceptTask {
                task_id: 31,
                worker: "w31".into(),
            },
            MockTx::Commit {
                task_id: 31,
                worker: "w31".into(),
                committed_hash: [1u8; 32],
            },
            MockTx::CreateTask {
                task_id: 32,
                creator: "bob".into(),
                bounty: 20,
            },
        ]);

        let picked = pick_txs_with_critical_guard(&mut mempool, 2);
        assert_eq!(picked.len(), 2);
        assert!(matches!(picked[0], MockTx::CreateTask { task_id: 31, .. }));
        assert!(matches!(picked[1], MockTx::CreateTask { task_id: 32, .. }));
        assert_eq!(mempool.len(), 2);
        assert!(matches!(mempool[0], MockTx::AcceptTask { task_id: 31, .. }));
        assert!(matches!(mempool[1], MockTx::Commit { task_id: 31, .. }));
    }
''',
    )

    main = replace_test(
        main,
        "critical_guard_selection_respects_lane_fairness_pop_order",
        r'''    #[test]
    fn critical_guard_lane_fairness_applies_between_task_frontiers() {
        let mut mempool = VecDeque::from(vec![
            MockTx::CreateTask {
                task_id: 11,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::Challenge {
                task_id: 12,
                challenger: "c2".into(),
                bond: 10,
            },
            MockTx::Resolve {
                task_id: 12,
                slash_worker: false,
                resolver: "gov".into(),
            },
            MockTx::AcceptTask {
                task_id: 11,
                worker: "w1".into(),
            },
        ]);

        let picked = pick_txs_with_critical_guard(&mut mempool, 2);
        assert_eq!(picked.len(), 2);
        assert!(matches!(picked[0], MockTx::Challenge { task_id: 12, .. }));
        assert!(matches!(picked[1], MockTx::CreateTask { task_id: 11, .. }));
        assert!(matches!(mempool[0], MockTx::Resolve { task_id: 12, .. }));
        assert!(matches!(mempool[1], MockTx::AcceptTask { task_id: 11, .. }));
    }
''',
    )

    main = replace_test(
        main,
        "critical_guard_only_reorders_scanned_prefix_and_leaves_suffix_fifo",
        r'''    #[test]
    fn critical_guard_selects_frontiers_only_and_leaves_dependent_suffix_fifo() {
        let mut mempool = VecDeque::from(vec![
            MockTx::CreateTask {
                task_id: 21,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::AcceptTask {
                task_id: 21,
                worker: "w1".into(),
            },
            MockTx::Challenge {
                task_id: 21,
                challenger: "c1".into(),
                bond: 10,
            },
            MockTx::Resolve {
                task_id: 21,
                slash_worker: false,
                resolver: "gov".into(),
            },
            MockTx::CreateTask {
                task_id: 22,
                creator: "bob".into(),
                bounty: 20,
            },
        ]);

        let picked = pick_txs_with_critical_guard(&mut mempool, 3);
        assert_eq!(picked.len(), 2);
        assert!(matches!(picked[0], MockTx::CreateTask { task_id: 21, .. }));
        assert!(matches!(picked[1], MockTx::CreateTask { task_id: 22, .. }));
        assert_eq!(mempool.len(), 3);
        assert!(matches!(mempool[0], MockTx::AcceptTask { task_id: 21, .. }));
        assert!(matches!(mempool[1], MockTx::Challenge { task_id: 21, .. }));
        assert!(matches!(mempool[2], MockTx::Resolve { task_id: 21, .. }));
    }
''',
    )

    zero_test = '''    #[test]
    fn build_demo_mempool_respects_zero_demo_tasks() {
        let mempool = build_demo_mempool(0, 2);
        assert!(mempool.is_empty());
    }
'''
    demo_regression = r'''
    #[test]
    fn build_demo_mempool_advances_one_lifecycle_frontier_per_task() {
        let mut mempool = build_demo_mempool(2, 2);
        for expected_event_type in [
            "create",
            "accept",
            "commit",
            "reveal",
            "challenge",
            "resolve",
            "resolve",
        ] {
            let picked = pick_txs_with_critical_guard(&mut mempool, 4);
            assert_eq!(picked.len(), 2);
            assert!(picked
                .iter()
                .all(|tx| event_type_of(tx) == expected_event_type));
            let task_ids = picked.iter().map(task_id_of).collect::<HashSet<_>>();
            assert_eq!(task_ids.len(), 2);
        }
        assert!(mempool.is_empty());
    }
'''
    if "fn build_demo_mempool_advances_one_lifecycle_frontier_per_task(" not in main:
        if zero_test not in main:
            raise RuntimeError("zero demo test marker not found")
        main = main.replace(zero_test, zero_test + demo_regression, 1)

    MAIN_PATH.write_text(main)


def patch_gate() -> None:
    gate = GATE_PATH.read_text()
    permissive_fallback = '''  cargo test -q -p trnm-node --features legacy-harness --bin trnm-sim legacy_resolve_event_line_keeps_frozen_fields
  echo "[OK] event field check passed with deterministic resolve contract: $OUT"
  exit 0
'''
    strict_failure = '''  echo "no runtime resolve event line found in $OUT; set ALLOW_MISSING_RESOLVE_EVENT=1 only for explicit contract-only checks" >&2
  exit 4
'''
    if permissive_fallback in gate:
        gate = gate.replace(permissive_fallback, strict_failure, 1)
    elif "no runtime resolve event line found" not in gate:
        raise RuntimeError("event gate fallback marker not found")
    GATE_PATH.write_text(gate)


def main() -> None:
    patch_main()
    patch_gate()
    print("PR84 one-shot patch applied")


if __name__ == "__main__":
    main()
