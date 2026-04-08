    use super::*;
    use trnm_state::GovParamUpdateOutcome;

    #[test]
    fn resolve_hotspot_summary_includes_shared_treasury_and_approval_labels() {
        let mut state = StateStore::new();
        state.set_balance("worker5001", 1_000);
        state.set_balance("challenger5001", 1_000);

        let r1 = apply_create_task(&mut state, 5001, "alice".into(), 100).unwrap();
        let r2 = apply_accept_task_at_height(&mut state, r1, "worker5001".into(), 10).unwrap();
        let committed = compute_commitment(5001, &[1u8; 32], &[2u8; 32], "worker5001");
        let r3 = apply_commit_result_at_height(&mut state, r2, "worker5001".into(), committed, 10)
            .unwrap();
        let r4 =
            apply_reveal_result_at_height(&mut state, r3, [1u8; 32], [2u8; 32], None, 11).unwrap();
        let _r5 = apply_challenge_at_height(
            &mut state,
            r4,
            "challenger5001".into(),
            10,
            "challenger5001".into(),
            12,
        )
        .unwrap();

        let summary = summarize_hot_objects(
            &state,
            &[MockTx::Resolve {
                task_id: 5001,
                slash_worker: true,
                resolver: "authority-a".into(),
            }],
        );

        assert_eq!(summary.hot_tx_count, 1);
        assert!(summary.labels.contains_key(CHALLENGE_ESCROW_ACCOUNT));
        assert!(summary
            .labels
            .contains_key(CHALLENGE_FORFEIT_TREASURY_ACCOUNT));
        assert!(summary.labels.contains_key(WORKER_SLASH_TREASURY_ACCOUNT));
        assert!(summary
            .labels
            .contains_key(RESOLVE_PENDING_APPROVAL_HOT_LABEL));
        assert!(summary.labels.contains_key(RESOLVE_AUTHORITY_HOT_LABEL));
    }

    #[test]
    fn requeue_uncommitted_txs_preserves_order_at_tail() {
        let mut mempool = VecDeque::from(vec![
            MockTx::CreateTask {
                task_id: 2001,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::CreateTask {
                task_id: 2002,
                creator: "bob".into(),
                bounty: 20,
            },
        ]);
        let picked = vec![
            MockTx::AcceptTask {
                task_id: 1001,
                worker: "worker1001".into(),
            },
            MockTx::Commit {
                task_id: 1001,
                worker: "worker1001".into(),
                committed_hash: [9u8; 32],
            },
        ];

        requeue_uncommitted_txs(&mut mempool, picked);

        let task_ids: Vec<u64> = mempool.iter().map(task_id_of).collect();
        assert_eq!(task_ids, vec![2001, 2002, 1001, 1001]);
    }

    #[test]
    fn requeue_uncommitted_txs_noop_on_empty_pick() {
        let mut mempool = VecDeque::from(vec![MockTx::CreateTask {
            task_id: 3001,
            creator: "alice".into(),
            bounty: 10,
        }]);

        requeue_uncommitted_txs(&mut mempool, vec![]);

        let task_ids: Vec<u64> = mempool.iter().map(task_id_of).collect();
        assert_eq!(task_ids, vec![3001]);
    }

    #[test]
    fn da_ordering_decouple_switch_off_and_on_keep_same_commit_order_on_happy_path() {
        let state = StateStore::new();
        let picked = vec![
            MockTx::CreateTask {
                task_id: 4001,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::CreateTask {
                task_id: 4002,
                creator: "bob".into(),
                bounty: 20,
            },
        ];

        let legacy = decide_order_for_commit(&state, &picked, 2, false, 1);
        let decoupled = decide_order_for_commit(&state, &picked, 2, true, 1);

        assert_eq!(legacy.ordered_ids, vec![1, 2]);
        assert_eq!(decoupled.ordered_ids, legacy.ordered_ids);
        assert_eq!(legacy.rejected, 0);
        assert_eq!(decoupled.rejected, 0);
    }

    #[test]
    fn da_ordering_decouple_preserves_group_surface_for_conflicting_txs() {
        let state = StateStore::new();
        let picked = vec![
            MockTx::CreateTask {
                task_id: 4_005,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::AcceptTask {
                task_id: 4_005,
                worker: "worker4005".into(),
            },
        ];

        let legacy = decide_order_for_commit(&state, &picked, 2, false, 1);
        let decoupled = decide_order_for_commit(&state, &picked, 2, true, 1);

        assert_eq!(legacy.ordered_ids, vec![1, 2]);
        assert_eq!(decoupled.ordered_ids, legacy.ordered_ids);
        assert_eq!(legacy.group_count, 2);
        assert_eq!(decoupled.group_count, legacy.group_count);
        assert_eq!(legacy.critical_wait_blocks, 1);
        assert_eq!(decoupled.critical_wait_blocks, legacy.critical_wait_blocks);
    }

    #[test]
    fn da_ordering_decouple_keeps_dependency_order_for_stateful_conflicts() {
        let state = StateStore::new();
        let picked = vec![
            MockTx::CreateTask {
                task_id: 4_006,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::AcceptTask {
                task_id: 4_006,
                worker: "worker4006".into(),
            },
            MockTx::Commit {
                task_id: 4_006,
                worker: "worker4006".into(),
                committed_hash: [4u8; 32],
            },
        ];

        let legacy = decide_order_for_commit(&state, &picked, 3, false, 10);
        let decoupled = decide_order_for_commit(&state, &picked, 3, true, 10);

        assert_eq!(legacy.ordered_ids, vec![1, 2, 3]);
        assert_eq!(decoupled.ordered_ids, legacy.ordered_ids);
        assert_eq!(legacy.rejected, 0);
        assert_eq!(decoupled.rejected, 0);
        assert_eq!(decoupled.group_count, legacy.group_count);
        assert_eq!(decoupled.critical_wait_blocks, legacy.critical_wait_blocks);
    }

    #[test]
    fn preexec_parallel_workers_match_single_worker_results() {
        let state = StateStore::new();
        let picked = vec![
            MockTx::CreateTask {
                task_id: 4051,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::CreateTask {
                task_id: 4052,
                creator: "bob".into(),
                bounty: 20,
            },
            MockTx::AcceptTask {
                task_id: 999_999,
                worker: "worker4053".into(),
            },
        ];

        let pool_single = PreExecPool::new(Arc::new(state.clone()), Arc::new(picked.clone()), 1, 1);
        let single = pre_execute_group_parallel(&pool_single, vec![1, 2, 3]);

        let pool_parallel = PreExecPool::new(Arc::new(state), Arc::new(picked), 3, 1);
        let parallel = pre_execute_group_parallel(&pool_parallel, vec![1, 2, 3]);

        assert_eq!(single, (vec![1, 2], 1));
        assert_eq!(parallel, single);
    }

    #[test]
    fn preexec_preserves_requested_group_order_for_successful_ids() {
        let state = StateStore::new();
        let picked = vec![
            MockTx::CreateTask {
                task_id: 4061,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::CreateTask {
                task_id: 4062,
                creator: "bob".into(),
                bounty: 20,
            },
            MockTx::AcceptTask {
                task_id: 999_998,
                worker: "worker4063".into(),
            },
        ];

        let pool = PreExecPool::new(Arc::new(state), Arc::new(picked), 3, 1);
        let result = pre_execute_group_parallel(&pool, vec![2, 1, 3]);

        assert_eq!(result, (vec![2, 1], 1));
    }

    #[test]
    fn preexec_uses_candidate_height_for_deadline_sensitive_reveal() {
        let mut state = StateStore::new();
        state.set_balance("worker4100", 1_000);

        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let r1 = apply_create_task(&mut state, 4100, "alice".into(), 100).unwrap();
        let r2 = apply_accept_task_at_height(&mut state, r1, "worker4100".into(), 100).unwrap();
        let committed = compute_commitment(4100, &result_hash, &reveal_salt, "worker4100");
        let _r3 =
            apply_commit_result_at_height(&mut state, r2, "worker4100".into(), committed, 100)
                .unwrap();

        let reveal_deadline = state
            .get_task(4100)
            .and_then(|t| t.reveal_deadline_height)
            .expect("reveal deadline must exist after commit");
        let reveal_tx = MockTx::Reveal {
            task_id: 4100,
            result_hash,
            reveal_salt,
        };

        let accepted_at_deadline = decide_order_for_commit(
            &state,
            std::slice::from_ref(&reveal_tx),
            1,
            false,
            reveal_deadline,
        );
        assert_eq!(accepted_at_deadline.ordered_ids, vec![1]);
        assert_eq!(accepted_at_deadline.rejected, 0);

        let rejected_after_deadline = decide_order_for_commit(
            &state,
            std::slice::from_ref(&reveal_tx),
            1,
            false,
            reveal_deadline.saturating_add(1),
        );
        assert!(rejected_after_deadline.ordered_ids.is_empty());
        assert_eq!(rejected_after_deadline.rejected, 1);

        let rejected_after_deadline_decoupled = decide_order_for_commit(
            &state,
            std::slice::from_ref(&reveal_tx),
            1,
            true,
            reveal_deadline.saturating_add(1),
        );
        assert!(rejected_after_deadline_decoupled.ordered_ids.is_empty());
        assert_eq!(rejected_after_deadline_decoupled.rejected, 1);

        let err = apply_one(
            &mut state.clone(),
            reveal_tx,
            reveal_deadline.saturating_add(1),
        )
        .unwrap_err();
        assert_eq!(classify_apply_error(&err), "deadline_exceeded");
    }

    #[test]
    fn preexec_pool_reuses_workers_across_multiple_groups() {
        let state = Arc::new(StateStore::new());
        let picked = Arc::new(vec![
            MockTx::CreateTask {
                task_id: 4201,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::CreateTask {
                task_id: 4202,
                creator: "bob".into(),
                bounty: 20,
            },
            MockTx::CreateTask {
                task_id: 4203,
                creator: "carol".into(),
                bounty: 30,
            },
            MockTx::CreateTask {
                task_id: 4204,
                creator: "dave".into(),
                bounty: 40,
            },
        ]);

        let pool = PreExecPool::new(Arc::clone(&state), Arc::clone(&picked), 2, 1);
        let first = pre_execute_group_parallel(&pool, vec![1, 2]);
        let second = pre_execute_group_parallel(&pool, vec![3, 4]);

        assert_eq!(first.0, vec![1, 2]);
        assert_eq!(first.1, 0);
        assert_eq!(second.0, vec![3, 4]);
        assert_eq!(second.1, 0);
    }

    #[test]
    fn preexec_rejects_out_of_range_tx_ids_without_worker_panic() {
        let state = Arc::new(StateStore::new());
        let picked = Arc::new(vec![MockTx::CreateTask {
            task_id: 4_250,
            creator: "alice".into(),
            bounty: 10,
        }]);

        let pool = PreExecPool::new(Arc::clone(&state), Arc::clone(&picked), 2, 1);
        let (ordered_ids, rejected) = pre_execute_group_parallel(&pool, vec![0, 1, 2]);

        assert_eq!(ordered_ids, vec![1]);
        assert_eq!(rejected, 2);
    }

    #[test]
    fn preexec_preserves_input_order_of_successful_ids_within_group() {
        let state = Arc::new(StateStore::new());
        let picked = Arc::new(vec![
            MockTx::CreateTask {
                task_id: 4_260,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::CreateTask {
                task_id: 4_261,
                creator: "bob".into(),
                bounty: 11,
            },
        ]);

        let pool = PreExecPool::new(Arc::clone(&state), Arc::clone(&picked), 2, 1);
        let (ordered_ids, rejected) = pre_execute_group_parallel(&pool, vec![2, 1]);

        assert_eq!(ordered_ids, vec![2, 1]);
        assert_eq!(rejected, 0);
    }

    #[test]
    fn preexec_dedups_duplicate_tx_ids_to_keep_ordering_surface_stable() {
        let state = Arc::new(StateStore::new());
        let picked = Arc::new(vec![
            MockTx::CreateTask {
                task_id: 4_262,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::CreateTask {
                task_id: 4_263,
                creator: "bob".into(),
                bounty: 11,
            },
        ]);

        let pool = PreExecPool::new(Arc::clone(&state), Arc::clone(&picked), 2, 1);
        let (ordered_ids, rejected) = pre_execute_group_parallel(&pool, vec![2, 1, 2, 1]);

        assert_eq!(ordered_ids, vec![2, 1]);
        assert_eq!(rejected, 0);
    }

    #[test]
    fn rl_shadow_advisor_only_suggests_and_does_not_mutate_baseline_order() {
        let baseline = vec![1, 2, 3, 4];
        let advisor = ShadowOnlyRlAdvisor { topk: 2 };
        let advice = advisor
            .advise(&RlAdviceContext {
                height: 7,
                ordered_ids: baseline.clone(),
            })
            .expect("advice");

        assert_eq!(baseline, vec![1, 2, 3, 4]);
        assert_eq!(advice.suggested_ids, vec![4, 3]);
        assert_eq!(advice.reason, "shadow_reverse_baseline");
    }

    #[test]
    fn critical_txs_are_selected_even_when_normal_queue_is_long() {
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
        assert!(matches!(picked[0], MockTx::Challenge { .. }));
        assert!(matches!(picked[1], MockTx::CreateTask { task_id: 1, .. }));
        assert_eq!(mempool.len(), 4);
        assert!(mempool
            .iter()
            .any(|tx| matches!(tx, MockTx::Resolve { .. })));
    }

    #[test]
    fn critical_guard_fast_path_drains_fifo_when_capacity_covers_queue() {
        let mut mempool = VecDeque::from(vec![
            MockTx::CreateTask {
                task_id: 1,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::Challenge {
                task_id: 1,
                challenger: "c1".into(),
                bond: 10,
            },
            MockTx::AcceptTask {
                task_id: 1,
                worker: "w1".into(),
            },
        ]);

        let picked = pick_txs_with_critical_guard(&mut mempool, 3);
        assert_eq!(picked.len(), 3);
        assert!(mempool.is_empty());
        assert!(matches!(picked[0], MockTx::CreateTask { .. }));
        assert!(matches!(picked[1], MockTx::Challenge { .. }));
        assert!(matches!(picked[2], MockTx::AcceptTask { .. }));
    }

    #[test]
    fn critical_guard_mixed_backlog_drains_fifo_when_capacity_covers_queue() {
        let mut mempool = VecDeque::from(vec![
            MockTx::CreateTask {
                task_id: 11,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::Challenge {
                task_id: 11,
                challenger: "c11".into(),
                bond: 10,
            },
            MockTx::AcceptTask {
                task_id: 11,
                worker: "w11".into(),
            },
            MockTx::Resolve {
                task_id: 11,
                slash_worker: false,
                resolver: "gov".into(),
            },
        ]);

        // Even for heterogeneous backlog, once block budget can absorb the whole
        // queue we should stay on the fast path: drain FIFO and skip lane-fairness
        // reordering/bookkeeping entirely.
        let picked = pick_txs_with_critical_guard(&mut mempool, 4);

        assert!(mempool.is_empty());
        assert_eq!(picked.len(), 4);
        assert!(matches!(picked[0], MockTx::CreateTask { task_id: 11, .. }));
        assert!(matches!(picked[1], MockTx::Challenge { task_id: 11, .. }));
        assert!(matches!(picked[2], MockTx::AcceptTask { task_id: 11, .. }));
        assert!(matches!(picked[3], MockTx::Resolve { task_id: 11, .. }));
    }

    #[test]
    fn critical_guard_zero_block_budget_is_noop_and_preserves_queue_order() {
        let mut mempool = VecDeque::from(vec![
            MockTx::CreateTask {
                task_id: 1,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::Challenge {
                task_id: 1,
                challenger: "c1".into(),
                bond: 10,
            },
            MockTx::AcceptTask {
                task_id: 1,
                worker: "w1".into(),
            },
        ]);

        let picked = pick_txs_with_critical_guard(&mut mempool, 0);
        assert!(picked.is_empty());

        let remaining_task_ids: Vec<u64> = mempool.iter().map(task_id_of).collect();
        assert_eq!(remaining_task_ids, vec![1, 1, 1]);
        assert!(matches!(mempool[0], MockTx::CreateTask { .. }));
        assert!(matches!(mempool[1], MockTx::Challenge { .. }));
        assert!(matches!(mempool[2], MockTx::AcceptTask { .. }));
    }

    #[test]
    fn critical_guard_normal_only_backlog_drains_fifo_prefix_without_reordering() {
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
        assert!(matches!(picked[1], MockTx::AcceptTask { task_id: 31, .. }));

        assert_eq!(mempool.len(), 2);
        assert!(matches!(mempool[0], MockTx::Commit { task_id: 31, .. }));
        assert!(matches!(mempool[1], MockTx::CreateTask { task_id: 32, .. }));
    }

    #[test]
    fn rollback_block_rate_counts_only_blocks_with_any_rollback() {
        let rollback_samples = vec![0, 2, 0, 1];
        let rollback_block_total =
            rollback_samples.iter().filter(|count| **count > 0).count() as u64;
        let rollback_block_rate = rollback_block_total as f64 / rollback_samples.len() as f64;

        assert_eq!(rollback_block_total, 2);
        assert!((rollback_block_rate - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn consensus_share_ppm_is_zero_when_finality_avg_is_zero() {
        assert_eq!(ratio_ppm(10, 0), 0);
    }

    #[test]
    fn consensus_share_ppm_makes_component_regressions_visible() {
        let finality_avg = 200u128;
        let scheduler_avg = 50u128;
        let preexec_avg = 120u128;
        let commit_avg = 20u128;
        let state_root_total_avg = 10u128;

        assert_eq!(ratio_ppm(scheduler_avg, finality_avg), 250_000);
        assert_eq!(ratio_ppm(preexec_avg, finality_avg), 600_000);
        assert_eq!(ratio_ppm(commit_avg, finality_avg), 100_000);
        assert_eq!(ratio_ppm(state_root_total_avg, finality_avg), 50_000);
    }

    #[test]
    fn scheduler_peak_share_metric_makes_tail_latency_regressions_visible() {
        let finality_max = 320u128;
        let scheduler_max = 96u128;

        assert_eq!(ratio_ppm(scheduler_max, finality_max), 300_000);
        assert_eq!(ratio_ppm(scheduler_max, 0), 0);
    }

    #[test]
    fn preexec_peak_share_metric_makes_tail_latency_regressions_visible() {
        let finality_max = 320u128;
        let preexec_max = 160u128;

        assert_eq!(ratio_ppm(preexec_max, finality_max), 500_000);
        assert_eq!(ratio_ppm(preexec_max, 0), 0);
    }

    #[test]
    fn commit_and_state_root_peak_share_metrics_make_tail_latency_regressions_visible() {
        let finality_max = 320u128;
        let commit_max = 96u128;
        let state_root_total_max = 144u128;

        assert_eq!(ratio_ppm(commit_max, finality_max), 300_000);
        assert_eq!(ratio_ppm(state_root_total_max, finality_max), 450_000);
        assert_eq!(ratio_ppm(commit_max, 0), 0);
        assert_eq!(ratio_ppm(state_root_total_max, 0), 0);
    }

    #[test]
    fn rollback_share_metrics_make_rollback_regressions_visible() {
        let finality_avg = 200u128;
        let rollback_avg = 40u128;
        let finality_max = 320u128;
        let rollback_max = 80u128;
        let rollback_total = 3u64;
        let rollback_block_total = 2u64;
        let rollback_active_heights = rollback_block_total;
        let finality_sample_count = 4u64;
        let rollback_block_rate_ppm = ratio_ppm_u64(rollback_block_total, finality_sample_count);
        let rollback_active_height_rate_ppm = rollback_block_rate_ppm;
        let rollback_density_avg = rollback_total / rollback_block_total;
        let rollback_density_avg_milli = ratio_milli_u64(rollback_total, rollback_block_total);

        assert_eq!(ratio_ppm(rollback_avg, finality_avg), 200_000);
        assert_eq!(ratio_ppm(rollback_max, finality_max), 250_000);
        assert_eq!(rollback_active_heights, rollback_block_total);
        assert_eq!(rollback_block_rate_ppm, 500_000);
        assert_eq!(rollback_active_height_rate_ppm, rollback_block_rate_ppm);
        assert_eq!(rollback_density_avg, 1);
        assert_eq!(rollback_density_avg_milli, 1_500);
    }

    #[test]
    fn percentage_bps_guardrails_make_preexec_and_rollback_regressions_visible() {
        assert_eq!(ratio_percent_bps(3, 12), 2_500);
        assert_eq!(ratio_percent_bps(2, 5), 4_000);
        assert_eq!(ratio_percent_bps(1, 0), 0);
    }

    #[test]
    fn hot_object_top_label_share_metric_exposes_concentrated_hotspots() {
        let mut summary = HotObjectSummary::default();
        summary.labels.insert("resolve.pending_approval".into(), 6);
        summary.labels.insert("treasury.challenge_escrow".into(), 2);
        summary.labels.insert("gov.resolve_authority".into(), 2);

        assert_eq!(hot_object_top_label_share_ppm(&summary), 600_000);
    }

    #[test]
    fn hot_object_top_label_share_metric_is_zero_without_hot_labels() {
        assert_eq!(
            hot_object_top_label_share_ppm(&HotObjectSummary::default()),
            0
        );
    }

    #[test]
    fn hot_object_tail_share_metric_exposes_remaining_parallelizable_surface() {
        let mut summary = HotObjectSummary::default();
        summary.labels.insert("resolve.pending_approval".into(), 6);
        summary.labels.insert("treasury.challenge_escrow".into(), 2);
        summary.labels.insert("gov.resolve_authority".into(), 2);

        assert_eq!(hot_object_tail_share_ppm(&summary), 400_000);
    }

    #[test]
    fn hot_object_tail_share_metric_is_zero_without_hot_labels() {
        assert_eq!(hot_object_tail_share_ppm(&HotObjectSummary::default()), 0);
    }

    #[test]
    fn hot_object_top_and_tail_share_metrics_partition_hot_reference_surface() {
        let mut summary = HotObjectSummary::default();
        summary.labels.insert("resolve.pending_approval".into(), 6);
        summary.labels.insert("treasury.challenge_escrow".into(), 2);
        summary.labels.insert("gov.resolve_authority".into(), 2);

        let top_share_ppm = hot_object_top_label_share_ppm(&summary);
        let tail_share_ppm = hot_object_tail_share_ppm(&summary);

        assert_eq!(top_share_ppm, 600_000);
        assert_eq!(tail_share_ppm, 400_000);
        assert_eq!(top_share_ppm + tail_share_ppm, 1_000_000);
    }

    #[test]
    fn active_hot_object_share_averages_ignore_inactive_heights() {
        let finality_sample_count = 4u64;
        let hot_object_active_heights = 2u64;
        let hot_object_top_label_share_samples_ppm = vec![0u128, 800_000, 0, 400_000];
        let hot_object_tail_share_samples_ppm = vec![0u128, 200_000, 0, 600_000];
        let hot_object_active_top_label_share_total_ppm = 1_200_000u128;
        let hot_object_active_tail_share_total_ppm = 800_000u128;
        let hot_object_top_label_share_avg_ppm =
            average_or_zero(&hot_object_top_label_share_samples_ppm);
        let hot_object_tail_share_avg_ppm = average_or_zero(&hot_object_tail_share_samples_ppm);
        let hot_object_active_top_label_share_avg_ppm =
            hot_object_active_top_label_share_total_ppm / hot_object_active_heights as u128;
        let hot_object_active_tail_share_avg_ppm =
            hot_object_active_tail_share_total_ppm / hot_object_active_heights as u128;
        let hot_object_active_height_rate_ppm =
            ratio_ppm_u64(hot_object_active_heights, finality_sample_count);
        let hot_object_active_observed_height_rate_ppm =
            ratio_ppm_u64(hot_object_active_heights, 6u64);
        let hot_object_active_height_share_ppm = (hot_object_active_top_label_share_total_ppm
            + hot_object_active_tail_share_total_ppm)
            / hot_object_active_heights as u128;

        assert_eq!(hot_object_top_label_share_avg_ppm, 300_000);
        assert_eq!(hot_object_tail_share_avg_ppm, 200_000);
        assert_eq!(hot_object_active_top_label_share_avg_ppm, 600_000);
        assert_eq!(hot_object_active_tail_share_avg_ppm, 400_000);
        assert_eq!(hot_object_active_height_rate_ppm, 500_000);
        assert_eq!(hot_object_active_observed_height_rate_ppm, 333_333);
        assert_eq!(hot_object_active_height_share_ppm, 1_000_000);
        assert!(hot_object_active_observed_height_rate_ppm < hot_object_active_height_rate_ppm);
        assert!(hot_object_active_top_label_share_avg_ppm > hot_object_top_label_share_avg_ppm);
        assert!(hot_object_active_tail_share_avg_ppm > hot_object_tail_share_avg_ppm);
    }

    #[test]
    fn hot_object_metric_names_keep_coverage_and_budget_share_distinct() {
        let active_height_rate_field_name = "hot_object_active_height_rate_ppm";
        let active_observed_height_rate_field_name = "hot_object_active_observed_height_rate_ppm";
        let active_height_share_field_name = "hot_object_active_height_share_ppm";

        assert!(active_height_rate_field_name.ends_with("_rate_ppm"));
        assert!(active_observed_height_rate_field_name.ends_with("_rate_ppm"));
        assert!(active_height_share_field_name.ends_with("_share_ppm"));
        assert_ne!(
            active_height_rate_field_name,
            active_observed_height_rate_field_name
        );
        assert_ne!(
            active_height_rate_field_name,
            active_height_share_field_name
        );
        assert_ne!(
            active_observed_height_rate_field_name,
            active_height_share_field_name
        );
    }

    #[test]
    fn hot_object_review_bundle_keeps_commit_skip_coverage_pair_near_hotspot_pressure() {
        let hotspot_review_fields = [
            "hot_object_active_height_rate_ppm",
            "hot_object_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_observed_height_rate_ppm",
            "hot_object_active_top_label_share_avg_ppm",
            "hot_object_active_tail_share_avg_ppm",
            "hot_object_active_height_share_ppm",
        ];

        assert_eq!(hotspot_review_fields.len(), 7);
        assert!(hotspot_review_fields[0].ends_with("_rate_ppm"));
        assert!(hotspot_review_fields[1].ends_with("_rate_ppm"));
        assert!(hotspot_review_fields[2].ends_with("_rate_ppm"));
        assert!(hotspot_review_fields[3].ends_with("_rate_ppm"));
        assert!(hotspot_review_fields[4].ends_with("_share_avg_ppm"));
        assert!(hotspot_review_fields[5].ends_with("_share_avg_ppm"));
        assert!(hotspot_review_fields[6].ends_with("_share_ppm"));
        assert_ne!(hotspot_review_fields[0], hotspot_review_fields[1]);
        assert_ne!(hotspot_review_fields[2], hotspot_review_fields[3]);
        assert_ne!(hotspot_review_fields[4], hotspot_review_fields[5]);
        assert_ne!(hotspot_review_fields[5], hotspot_review_fields[6]);
    }

    #[test]
    fn active_hot_object_share_averages_are_zero_without_hot_heights() {
        let hot_object_active_heights = 0u64;
        let hot_object_active_top_label_share_avg_ppm = if hot_object_active_heights == 0 {
            0
        } else {
            1_200_000u128 / hot_object_active_heights as u128
        };
        let hot_object_active_tail_share_avg_ppm = if hot_object_active_heights == 0 {
            0
        } else {
            800_000u128 / hot_object_active_heights as u128
        };

        assert_eq!(hot_object_active_top_label_share_avg_ppm, 0);
        assert_eq!(hot_object_active_tail_share_avg_ppm, 0);
    }

    #[test]
    fn critical_wait_density_metrics_make_fairness_stalls_visible() {
        let finality_avg = 200u128;
        let critical_wait_blocks_avg = 50u128;
        let finality_max = 320u128;
        let critical_wait_blocks_max = 160u128;

        assert_eq!(ratio_ppm(critical_wait_blocks_avg, finality_avg), 250_000);
        assert_eq!(ratio_ppm(critical_wait_blocks_max, finality_max), 500_000);
        assert_eq!(ratio_ppm(critical_wait_blocks_max, 0), 0);
    }

    #[test]
    fn critical_wait_active_height_rate_metrics_make_fairness_stall_concentration_visible() {
        let critical_wait_active_heights = 2u64;
        let finality_sample_count = 4u64;
        let bft_observed_heights = 5u64;
        let critical_wait_total = 5u64;
        let critical_wait_density_avg = critical_wait_total / critical_wait_active_heights;
        let critical_wait_density_avg_milli =
            ratio_milli_u64(critical_wait_total, critical_wait_active_heights);
        let critical_wait_active_height_rate_ppm =
            ratio_ppm_u64(critical_wait_active_heights, finality_sample_count);
        let critical_wait_active_observed_height_rate_ppm =
            ratio_ppm_u64(critical_wait_active_heights, bft_observed_heights);

        assert_eq!(critical_wait_active_height_rate_ppm, 500_000);
        assert_eq!(critical_wait_active_observed_height_rate_ppm, 400_000);
        assert!(
            critical_wait_active_observed_height_rate_ppm < critical_wait_active_height_rate_ppm
        );
        assert_eq!(critical_wait_density_avg, 2);
        assert_eq!(critical_wait_density_avg_milli, 2_500);
    }

    #[test]
    fn critical_wait_metric_names_keep_committed_and_observed_coverage_distinct() {
        let active_height_rate_field_name = "critical_wait_active_height_rate_ppm";
        let active_observed_height_rate_field_name =
            "critical_wait_active_observed_height_rate_ppm";
        let density_field_name = "critical_wait_density_avg";
        let milli_density_field_name = "critical_wait_density_avg_milli";
        let active_height_share_field_name = "critical_wait_active_height_share_ppm";

        assert!(active_height_rate_field_name.ends_with("_rate_ppm"));
        assert!(active_observed_height_rate_field_name.ends_with("_rate_ppm"));
        assert!(density_field_name.ends_with("_avg"));
        assert!(milli_density_field_name.ends_with("_avg_milli"));
        assert!(active_height_share_field_name.ends_with("_share_ppm"));
        assert_ne!(
            active_height_rate_field_name,
            active_observed_height_rate_field_name
        );
        assert_ne!(active_observed_height_rate_field_name, density_field_name);
        assert_ne!(density_field_name, milli_density_field_name);
        assert_ne!(milli_density_field_name, active_height_share_field_name);
    }

    #[test]
    fn critical_wait_observed_height_rate_exposes_skipped_height_coverage_gap() {
        let critical_wait_active_heights = 2u64;
        let committed_heights = 2u64;
        let observed_heights = 5u64;
        let committed_height_rate_ppm =
            ratio_ppm_u64(critical_wait_active_heights, committed_heights);
        let observed_height_rate_ppm =
            ratio_ppm_u64(critical_wait_active_heights, observed_heights);

        assert_eq!(committed_height_rate_ppm, 1_000_000);
        assert_eq!(observed_height_rate_ppm, 400_000);
        assert!(observed_height_rate_ppm < committed_height_rate_ppm);
    }

    #[test]
    fn critical_wait_review_bundle_keeps_commit_skip_coverage_pair_near_fairness_stall_pressure() {
        let fairness_review_fields = [
            "critical_wait_active_heights",
            "critical_wait_active_height_rate_ppm",
            "critical_wait_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
            "critical_wait_density_avg_milli",
            "critical_wait_active_height_share_ppm",
        ];

        assert_eq!(fairness_review_fields.len(), 8);
        assert!(fairness_review_fields[0].ends_with("_heights"));
        assert!(fairness_review_fields[1].ends_with("_rate_ppm"));
        assert!(fairness_review_fields[2].ends_with("_rate_ppm"));
        assert!(fairness_review_fields[3].ends_with("_rate_ppm"));
        assert!(fairness_review_fields[4].ends_with("_total"));
        assert!(fairness_review_fields[5].ends_with("_rate_ppm"));
        assert!(fairness_review_fields[6].ends_with("_avg_milli"));
        assert!(fairness_review_fields[7].ends_with("_share_ppm"));
        assert_ne!(fairness_review_fields[1], fairness_review_fields[2]);
        assert_ne!(fairness_review_fields[2], fairness_review_fields[3]);
        assert_ne!(fairness_review_fields[3], fairness_review_fields[5]);
        assert_ne!(fairness_review_fields[6], fairness_review_fields[7]);
    }

    #[test]
    fn critical_wait_density_avg_handles_empty_active_height_set() {
        let critical_wait_total = 5u64;
        let critical_wait_active_heights = 0u64;
        let critical_wait_density_avg = if critical_wait_active_heights == 0 {
            0
        } else {
            critical_wait_total / critical_wait_active_heights
        };
        let critical_wait_density_avg_milli =
            ratio_milli_u64(critical_wait_total, critical_wait_active_heights);
        let critical_wait_active_height_share_ppm =
            finality_budget_share_ppm(critical_wait_density_avg_milli, 200u128);

        assert_eq!(critical_wait_density_avg, 0);
        assert_eq!(critical_wait_density_avg_milli, 0);
        assert_eq!(critical_wait_active_height_share_ppm, 0);
    }

    #[test]
    fn critical_wait_active_height_share_tracks_clustered_fairness_stall_budget_pressure() {
        let critical_wait_density_avg_milli = 2_500u64;
        let finality_avg = 200u128;
        let critical_wait_active_height_share_ppm =
            finality_budget_share_ppm(critical_wait_density_avg_milli, finality_avg);

        assert_eq!(critical_wait_active_height_share_ppm, 12_500);
        assert!(critical_wait_active_height_share_ppm < 1_000_000);
    }

    #[test]
    fn preexec_reject_share_metric_highlights_guardrail_pressure() {
        assert_eq!(ratio_percent_bps(6, 15), 4_000);
        assert_eq!(ratio_percent_bps(0, 15), 0);
        assert_eq!(ratio_percent_bps(4, 0), 0);
    }

    #[test]
    fn preexec_reject_density_metrics_expose_concentrated_guardrail_pressure() {
        let preexec_reject_total = 7u64;
        let preexec_reject_active_heights = 2u64;
        let bft_committed_heights = 3u64;
        let bft_observed_heights = 5u64;
        let finality_avg = 200u128;
        let preexec_reject_density_avg = preexec_reject_total / preexec_reject_active_heights;
        let preexec_reject_density_avg_milli =
            ratio_milli_u64(preexec_reject_total, preexec_reject_active_heights);
        let preexec_reject_active_height_rate_ppm =
            ratio_ppm_u64(preexec_reject_active_heights, bft_committed_heights);
        let preexec_reject_active_observed_height_rate_ppm =
            ratio_ppm_u64(preexec_reject_active_heights, bft_observed_heights);
        let preexec_reject_active_height_share_ppm =
            finality_budget_share_ppm(preexec_reject_density_avg_milli, finality_avg);

        assert_eq!(preexec_reject_density_avg, 3);
        assert_eq!(preexec_reject_density_avg_milli, 3_500);
        assert_eq!(preexec_reject_active_height_rate_ppm, 666_666);
        assert_eq!(preexec_reject_active_observed_height_rate_ppm, 400_000);
        assert_eq!(preexec_reject_active_height_share_ppm, 17_500);
        assert!(
            preexec_reject_active_observed_height_rate_ppm < preexec_reject_active_height_rate_ppm
        );
        assert_eq!(ratio_milli_u64(0, bft_committed_heights), 0);
        assert_eq!(ratio_milli_u64(preexec_reject_total, 0), 0);
    }

    #[test]
    fn preexec_reject_metric_names_keep_height_coverage_and_budget_semantics_distinct() {
        let active_height_count_field_name = "preexec_reject_active_heights";
        let active_height_rate_field_name = "preexec_reject_active_height_rate_ppm";
        let active_observed_height_rate_field_name =
            "preexec_reject_active_observed_height_rate_ppm";
        let active_height_share_field_name = "preexec_reject_active_height_share_ppm";
        let density_avg_milli_field_name = "preexec_reject_density_avg_milli";

        assert!(active_height_count_field_name.ends_with("_heights"));
        assert!(active_height_rate_field_name.ends_with("_height_rate_ppm"));
        assert!(active_observed_height_rate_field_name.ends_with("_rate_ppm"));
        assert!(active_height_share_field_name.ends_with("_share_ppm"));
        assert!(density_avg_milli_field_name.ends_with("_avg_milli"));
        assert_ne!(
            active_height_count_field_name,
            active_height_rate_field_name
        );
        assert_ne!(
            active_height_rate_field_name,
            active_observed_height_rate_field_name
        );
        assert_ne!(
            active_observed_height_rate_field_name,
            active_height_share_field_name
        );
        assert_ne!(active_height_share_field_name, density_avg_milli_field_name);
    }

    #[test]
    fn unprofiled_finality_gap_metric_captures_hidden_block_time() {
        assert_eq!(gap_percent_bps(200, 80, 40), 4_000);
        assert_eq!(gap_percent_bps(200, 150, 80), 0);
        assert_eq!(gap_percent_bps(0, 10, 5), 0);
    }

    #[test]
    fn round_change_guardrail_metrics_make_bft_jitter_visible() {
        let bft_round_change_total = 6u64;
        let bft_round_change_active_heights = 2u64;
        let bft_committed_heights = 4u64;
        let bft_round_change_backoff_total_ms = 18u64;
        let bft_round_change_backoff_max_ms = 8u64;

        assert_eq!(
            ratio_ppm_u64(bft_round_change_total, bft_committed_heights),
            1_500_000
        );
        assert_eq!(
            bft_round_change_backoff_total_ms / bft_round_change_total,
            3
        );
        assert_eq!(
            bft_round_change_backoff_total_ms / bft_round_change_active_heights,
            9
        );
        assert_eq!(
            ratio_milli_u64(
                bft_round_change_backoff_total_ms,
                bft_round_change_active_heights,
            ),
            9_000
        );
        assert_eq!(
            ratio_ppm_u64(bft_round_change_backoff_total_ms, bft_committed_heights),
            4_500_000
        );
        assert!(
            bft_round_change_backoff_max_ms
                > bft_round_change_backoff_total_ms / bft_round_change_total
        );
    }

    #[test]
    fn preexec_metric_names_keep_tail_and_guardrail_semantics_distinct() {
        let peak_field_name = "preexec_peak_share_ppm";
        let reject_density_avg_milli_field_name = "preexec_reject_density_avg_milli";
        let reject_share_field_name = "preexec_reject_share_bps";
        let conflict_miss_share_field_name = "preexec_conflict_miss_share_bps";

        assert!(peak_field_name.ends_with("_share_ppm"));
        assert!(reject_density_avg_milli_field_name.ends_with("_avg_milli"));
        assert!(reject_share_field_name.ends_with("_share_bps"));
        assert!(conflict_miss_share_field_name.ends_with("_share_bps"));
        assert_ne!(peak_field_name, reject_density_avg_milli_field_name);
        assert_ne!(peak_field_name, reject_share_field_name);
        assert_ne!(peak_field_name, conflict_miss_share_field_name);
        assert_ne!(reject_density_avg_milli_field_name, reject_share_field_name);
        assert_ne!(
            reject_density_avg_milli_field_name,
            conflict_miss_share_field_name
        );
        assert_ne!(reject_share_field_name, conflict_miss_share_field_name);
    }

    #[test]
    fn preexec_reject_review_bundle_keeps_commit_skip_coverage_pair_near_guardrail_pressure() {
        let guardrail_review_fields = [
            "preexec_peak_share_ppm",
            "preexec_reject_active_heights",
            "preexec_reject_active_height_rate_ppm",
            "preexec_reject_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
            "preexec_reject_density_avg_milli",
            "preexec_reject_active_height_share_ppm",
            "preexec_reject_share_bps",
            "preexec_conflict_miss_share_bps",
        ];

        assert_eq!(guardrail_review_fields.len(), 11);
        assert!(guardrail_review_fields[0].ends_with("_share_ppm"));
        assert!(guardrail_review_fields[1].ends_with("_heights"));
        assert!(guardrail_review_fields[2].ends_with("_rate_ppm"));
        assert!(guardrail_review_fields[3].ends_with("_rate_ppm"));
        assert!(guardrail_review_fields[4].ends_with("_rate_ppm"));
        assert!(guardrail_review_fields[5].ends_with("_total"));
        assert!(guardrail_review_fields[6].ends_with("_rate_ppm"));
        assert!(guardrail_review_fields[7].ends_with("_avg_milli"));
        assert!(guardrail_review_fields[8].ends_with("_share_ppm"));
        assert!(guardrail_review_fields[9].ends_with("_share_bps"));
        assert!(guardrail_review_fields[10].ends_with("_share_bps"));
        assert_ne!(guardrail_review_fields[2], guardrail_review_fields[3]);
        assert_ne!(guardrail_review_fields[4], guardrail_review_fields[6]);
        assert_ne!(guardrail_review_fields[5], guardrail_review_fields[6]);
        assert_ne!(guardrail_review_fields[7], guardrail_review_fields[8]);
        assert_ne!(guardrail_review_fields[9], guardrail_review_fields[10]);
    }

    #[test]
    fn rollback_active_height_metric_names_keep_compatibility_and_height_semantics_distinct() {
        let compatibility_count_field_name = "rollback_block_total";
        let height_count_field_name = "rollback_active_heights";
        let compatibility_rate_field_name = "rollback_block_rate_ppm";
        let height_rate_field_name = "rollback_active_height_rate_ppm";
        let observed_height_rate_field_name = "rollback_active_observed_height_rate_ppm";

        assert!(compatibility_count_field_name.ends_with("_total"));
        assert!(height_count_field_name.ends_with("_heights"));
        assert!(compatibility_rate_field_name.ends_with("_rate_ppm"));
        assert!(height_rate_field_name.ends_with("_height_rate_ppm"));
        assert!(observed_height_rate_field_name.ends_with("_rate_ppm"));
        assert_ne!(compatibility_count_field_name, height_count_field_name);
        assert_ne!(compatibility_rate_field_name, height_rate_field_name);
        assert_ne!(height_rate_field_name, observed_height_rate_field_name);
        assert_ne!(
            compatibility_rate_field_name,
            observed_height_rate_field_name
        );
    }

    #[test]
    fn rollback_observed_height_rate_exposes_skipped_height_coverage_gap() {
        let rollback_active_heights = 2u64;
        let rollback_committed_height_rate_ppm = ratio_ppm_u64(rollback_active_heights, 2u64);
        let rollback_observed_height_rate_ppm = ratio_ppm_u64(rollback_active_heights, 5u64);

        assert_eq!(rollback_committed_height_rate_ppm, 1_000_000);
        assert_eq!(rollback_observed_height_rate_ppm, 400_000);
        assert!(rollback_observed_height_rate_ppm < rollback_committed_height_rate_ppm);
    }

    #[test]
    fn rollback_active_height_share_tracks_clustered_rollback_budget_pressure() {
        let rollback_density_avg_milli = 2_500u64;
        let finality_avg = 2u128;

        let rollback_active_height_share_ppm =
            finality_budget_share_ppm(rollback_density_avg_milli, finality_avg);

        assert_eq!(rollback_active_height_share_ppm, 1_250_000);
        assert!(rollback_active_height_share_ppm > 1_000_000);
    }

    #[test]
    fn rollback_metric_names_keep_budget_share_and_coverage_distinct() {
        let peak_field_name = "rollback_peak_share_ppm";
        let active_height_rate_field_name = "rollback_active_height_rate_ppm";
        let active_observed_height_rate_field_name = "rollback_active_observed_height_rate_ppm";
        let density_avg_milli_field_name = "rollback_density_avg_milli";
        let active_height_share_field_name = "rollback_active_height_share_ppm";

        assert!(peak_field_name.ends_with("_share_ppm"));
        assert!(active_height_rate_field_name.ends_with("_rate_ppm"));
        assert!(active_observed_height_rate_field_name.ends_with("_rate_ppm"));
        assert!(density_avg_milli_field_name.ends_with("_avg_milli"));
        assert!(active_height_share_field_name.ends_with("_share_ppm"));
        assert_ne!(peak_field_name, active_height_rate_field_name);
        assert_ne!(
            active_height_rate_field_name,
            active_observed_height_rate_field_name
        );
        assert_ne!(
            active_observed_height_rate_field_name,
            density_avg_milli_field_name
        );
        assert_ne!(density_avg_milli_field_name, active_height_share_field_name);
    }

    #[test]
    fn rollback_review_bundle_keeps_commit_skip_coverage_pair_near_guardrail_pressure() {
        let guardrail_review_fields = [
            "rollback_peak_share_ppm",
            "rollback_active_heights",
            "rollback_active_height_rate_ppm",
            "rollback_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
            "rollback_density_avg_milli",
            "rollback_active_height_share_ppm",
            "apply_error_rollback_share_bps",
        ];

        assert_eq!(guardrail_review_fields.len(), 10);
        assert!(guardrail_review_fields[0].ends_with("_share_ppm"));
        assert!(guardrail_review_fields[1].ends_with("_heights"));
        assert!(guardrail_review_fields[2].ends_with("_rate_ppm"));
        assert!(guardrail_review_fields[3].ends_with("_rate_ppm"));
        assert!(guardrail_review_fields[4].ends_with("_rate_ppm"));
        assert!(guardrail_review_fields[5].ends_with("_total"));
        assert!(guardrail_review_fields[6].ends_with("_rate_ppm"));
        assert!(guardrail_review_fields[7].ends_with("_avg_milli"));
        assert!(guardrail_review_fields[8].ends_with("_share_ppm"));
        assert!(guardrail_review_fields[9].ends_with("_share_bps"));
        assert_ne!(guardrail_review_fields[2], guardrail_review_fields[3]);
        assert_ne!(guardrail_review_fields[4], guardrail_review_fields[6]);
        assert_ne!(guardrail_review_fields[5], guardrail_review_fields[6]);
        assert_ne!(guardrail_review_fields[7], guardrail_review_fields[8]);
    }

    #[test]
    fn round_change_backoff_metric_names_keep_tail_and_share_semantics_distinct() {
        let max_field_name = "bft_round_change_backoff_max_ms";
        let wall_share_field_name = "bft_round_change_backoff_wall_share_ppm";
        let compatibility_field_name = "bft_round_change_backoff_share_ppm";

        assert!(max_field_name.ends_with("_max_ms"));
        assert!(wall_share_field_name.ends_with("_share_ppm"));
        assert!(compatibility_field_name.ends_with("_share_ppm"));
        assert_ne!(max_field_name, wall_share_field_name);
        assert_ne!(max_field_name, compatibility_field_name);
    }

    #[test]
    fn scheduler_peak_share_metric_name_stays_distinct_from_average_share_field() {
        let avg_field_name = "scheduler_share_avg_ppm";
        let peak_field_name = "scheduler_peak_share_ppm";

        assert!(avg_field_name.ends_with("_avg_ppm"));
        assert!(peak_field_name.ends_with("_share_ppm"));
        assert!(!peak_field_name.contains("avg"));
        assert_ne!(avg_field_name, peak_field_name);
    }

    #[test]
    fn consensus_summary_guardrail_field_list_keeps_active_height_and_observed_coverage_views() {
        let observed_coverage_fields = [
            "critical_wait_active_observed_height_rate_ppm",
            "hot_object_active_observed_height_rate_ppm",
            "preexec_reject_active_observed_height_rate_ppm",
            "rollback_active_observed_height_rate_ppm",
            "bft_round_change_active_observed_height_rate_ppm",
            "bft_round_change_backoff_active_observed_height_rate_ppm",
            "bft_leader_missed_active_observed_height_rate_ppm",
        ];
        let active_budget_share_fields = [
            "critical_wait_active_height_share_ppm",
            "hot_object_active_height_share_ppm",
            "preexec_reject_active_height_share_ppm",
            "rollback_active_height_share_ppm",
            "bft_round_change_active_height_share_ppm",
            "bft_round_change_backoff_active_height_share_ppm",
            "bft_leader_missed_active_height_share_ppm",
        ];

        assert_eq!(observed_coverage_fields.len(), 7);
        assert_eq!(active_budget_share_fields.len(), 7);
        assert!(observed_coverage_fields
            .iter()
            .all(|field| field.ends_with("_rate_ppm")));
        assert!(active_budget_share_fields
            .iter()
            .all(|field| field.ends_with("_share_ppm")));
        for observed_field in observed_coverage_fields {
            assert!(
                !active_budget_share_fields.contains(&observed_field),
                "observed coverage field should stay distinct: {observed_field}"
            );
        }
    }

    #[test]
    fn consensus_summary_backoff_field_list_keeps_wall_alias_separate_from_budget_share_fields() {
        let backoff_fields = [
            "bft_round_change_backoff_active_height_share_ppm",
            "bft_round_change_backoff_wall_share_ppm",
            "bft_round_change_backoff_share_ppm",
        ];

        assert_eq!(backoff_fields.len(), 3);
        assert!(backoff_fields
            .iter()
            .all(|field| field.ends_with("_share_ppm")));
        assert_ne!(backoff_fields[0], backoff_fields[1]);
        assert_ne!(backoff_fields[0], backoff_fields[2]);
        assert_ne!(backoff_fields[1], backoff_fields[2]);
    }

    #[test]
    fn consensus_summary_bursty_review_bundles_keep_active_height_counts_next_to_coverage_and_budget_views(
    ) {
        let review_bundles: &[&[&str]] = &[
            &[
                "critical_wait_active_heights",
                "critical_wait_active_height_rate_ppm",
                "critical_wait_active_observed_height_rate_ppm",
                "critical_wait_density_avg_milli",
                "critical_wait_active_height_share_ppm",
            ],
            &[
                "hot_object_active_heights",
                "hot_object_active_height_rate_ppm",
                "hot_object_active_observed_height_rate_ppm",
                "hot_object_active_top_label_share_avg_ppm",
                "hot_object_active_tail_share_avg_ppm",
                "hot_object_active_height_share_ppm",
            ],
            &[
                "rollback_active_heights",
                "rollback_active_height_rate_ppm",
                "rollback_active_observed_height_rate_ppm",
                "rollback_density_avg_milli",
                "rollback_active_height_share_ppm",
            ],
            &[
                "preexec_reject_active_heights",
                "preexec_reject_active_height_rate_ppm",
                "preexec_reject_active_observed_height_rate_ppm",
                "preexec_reject_density_avg_milli",
                "preexec_reject_active_height_share_ppm",
            ],
            &[
                "bft_round_change_active_heights",
                "bft_round_change_active_height_rate_ppm",
                "bft_round_change_active_observed_height_rate_ppm",
                "bft_round_change_density_avg_milli",
                "bft_round_change_active_height_share_ppm",
            ],
            &[
                "bft_round_change_backoff_active_heights",
                "bft_round_change_backoff_active_height_rate_ppm",
                "bft_round_change_backoff_active_observed_height_rate_ppm",
                "bft_round_change_backoff_density_avg_milli",
                "bft_round_change_backoff_active_height_share_ppm",
            ],
            &[
                "bft_leader_missed_active_heights",
                "bft_leader_missed_active_height_rate_ppm",
                "bft_leader_missed_active_observed_height_rate_ppm",
                "bft_leader_missed_density_avg_milli",
                "bft_leader_missed_active_height_share_ppm",
            ],
        ];

        for bundle in review_bundles {
            assert!(bundle[0].ends_with("_active_heights"));
            assert!(bundle[1].ends_with("_active_height_rate_ppm"));
            assert!(bundle[2].ends_with("_active_observed_height_rate_ppm"));
            assert_ne!(bundle[0], bundle[1]);
            assert_ne!(bundle[0], bundle[2]);
            assert_ne!(bundle[1], bundle[2]);
            assert!(
                bundle[3].ends_with("_avg_milli") || bundle[3].ends_with("_share_avg_ppm"),
                "expected density or active-share companion field, got {}",
                bundle[3]
            );
            assert!(bundle.last().unwrap().ends_with("_active_height_share_ppm"));
        }
    }

    #[test]
    fn hot_object_review_bundle_keeps_commit_skip_denominator_context_next_to_shape_and_budget_pressure(
    ) {
        let hotspot_review_fields = [
            "hot_object_active_heights",
            "hot_object_active_height_rate_ppm",
            "hot_object_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
            "hot_object_active_top_label_share_avg_ppm",
            "hot_object_active_tail_share_avg_ppm",
            "hot_object_active_height_share_ppm",
        ];

        assert_eq!(hotspot_review_fields.len(), 9);
        assert!(hotspot_review_fields[0].ends_with("_active_heights"));
        assert!(hotspot_review_fields[1].ends_with("_active_height_rate_ppm"));
        assert!(hotspot_review_fields[2].ends_with("_active_observed_height_rate_ppm"));
        assert_eq!(
            hotspot_review_fields[3],
            "bft_commit_observed_height_rate_ppm"
        );
        assert_eq!(hotspot_review_fields[4], "bft_skipped_height_total");
        assert_eq!(
            hotspot_review_fields[5],
            "bft_skipped_observed_height_rate_ppm"
        );
        assert_eq!(
            hotspot_review_fields[6],
            "hot_object_active_top_label_share_avg_ppm"
        );
        assert_eq!(
            hotspot_review_fields[7],
            "hot_object_active_tail_share_avg_ppm"
        );
        assert_eq!(
            hotspot_review_fields[8],
            "hot_object_active_height_share_ppm"
        );
        assert_ne!(hotspot_review_fields[1], hotspot_review_fields[2]);
        assert_ne!(hotspot_review_fields[3], hotspot_review_fields[5]);
        assert_ne!(hotspot_review_fields[6], hotspot_review_fields[8]);
        assert_ne!(hotspot_review_fields[7], hotspot_review_fields[8]);
    }

    #[test]
    fn round_change_backoff_review_bundle_keeps_coverage_wall_and_budget_views_together() {
        let jitter_review_fields = [
            "bft_round_change_backoff_active_heights",
            "bft_round_change_backoff_active_height_rate_ppm",
            "bft_round_change_backoff_active_observed_height_rate_ppm",
            "bft_round_change_backoff_density_avg_milli",
            "bft_round_change_backoff_active_height_share_ppm",
            "bft_round_change_backoff_wall_share_ppm",
            "bft_round_change_backoff_share_ppm",
        ];

        assert_eq!(jitter_review_fields.len(), 7);
        assert!(jitter_review_fields[0].ends_with("_heights"));
        assert!(jitter_review_fields[1].ends_with("_rate_ppm"));
        assert!(jitter_review_fields[2].ends_with("_rate_ppm"));
        assert!(jitter_review_fields[3].ends_with("_avg_milli"));
        assert!(jitter_review_fields[4].ends_with("_share_ppm"));
        assert!(jitter_review_fields[5].ends_with("_share_ppm"));
        assert!(jitter_review_fields[6].ends_with("_share_ppm"));
        assert_ne!(jitter_review_fields[1], jitter_review_fields[2]);
        assert_ne!(jitter_review_fields[4], jitter_review_fields[5]);
        assert_ne!(jitter_review_fields[4], jitter_review_fields[6]);
        assert_ne!(jitter_review_fields[5], jitter_review_fields[6]);
    }

    #[test]
    fn round_change_backoff_review_bundle_keeps_skipped_width_next_to_coverage_and_share_context() {
        let jitter_review_fields = [
            "bft_round_change_backoff_active_heights",
            "bft_round_change_backoff_active_height_rate_ppm",
            "bft_round_change_backoff_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
            "bft_round_change_backoff_density_avg_milli",
            "bft_round_change_backoff_active_height_share_ppm",
            "bft_round_change_backoff_wall_share_ppm",
            "bft_round_change_backoff_share_ppm",
        ];

        assert_eq!(jitter_review_fields.len(), 10);
        assert!(jitter_review_fields[0].ends_with("_active_heights"));
        assert!(jitter_review_fields[1].ends_with("_active_height_rate_ppm"));
        assert!(jitter_review_fields[2].ends_with("_active_observed_height_rate_ppm"));
        assert_eq!(
            jitter_review_fields[3],
            "bft_commit_observed_height_rate_ppm"
        );
        assert_eq!(jitter_review_fields[4], "bft_skipped_height_total");
        assert_eq!(
            jitter_review_fields[5],
            "bft_skipped_observed_height_rate_ppm"
        );
        assert!(jitter_review_fields[6].ends_with("_avg_milli"));
        assert!(jitter_review_fields[7].ends_with("_share_ppm"));
        assert!(jitter_review_fields[8].ends_with("_share_ppm"));
        assert!(jitter_review_fields[9].ends_with("_share_ppm"));
        assert_ne!(jitter_review_fields[1], jitter_review_fields[2]);
        assert_ne!(jitter_review_fields[3], jitter_review_fields[5]);
        assert_ne!(jitter_review_fields[7], jitter_review_fields[8]);
        assert_ne!(jitter_review_fields[7], jitter_review_fields[9]);
        assert_ne!(jitter_review_fields[8], jitter_review_fields[9]);
    }

    #[test]
    fn round_change_backoff_review_bundle_keeps_budget_share_ahead_of_wall_time_aliases() {
        let jitter_review_fields = [
            "bft_round_change_backoff_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
            "bft_round_change_backoff_density_avg_milli",
            "bft_round_change_backoff_active_height_share_ppm",
            "bft_round_change_backoff_wall_share_ppm",
            "bft_round_change_backoff_share_ppm",
        ];

        assert_eq!(jitter_review_fields.len(), 8);
        assert!(jitter_review_fields[0].ends_with("_active_observed_height_rate_ppm"));
        assert_eq!(
            jitter_review_fields[1],
            "bft_commit_observed_height_rate_ppm"
        );
        assert_eq!(jitter_review_fields[2], "bft_skipped_height_total");
        assert_eq!(
            jitter_review_fields[3],
            "bft_skipped_observed_height_rate_ppm"
        );
        assert!(jitter_review_fields[4].ends_with("_avg_milli"));
        assert_eq!(
            jitter_review_fields[5],
            "bft_round_change_backoff_active_height_share_ppm"
        );
        assert_eq!(
            jitter_review_fields[6],
            "bft_round_change_backoff_wall_share_ppm"
        );
        assert_eq!(
            jitter_review_fields[7],
            "bft_round_change_backoff_share_ppm"
        );
        assert_ne!(jitter_review_fields[5], jitter_review_fields[6]);
        assert_ne!(jitter_review_fields[5], jitter_review_fields[7]);
        assert_ne!(jitter_review_fields[6], jitter_review_fields[7]);
    }

    #[test]
    fn leader_missed_review_bundle_keeps_validator_spread_next_to_height_pressure_fields() {
        let fairness_review_fields = [
            "bft_leader_missed_top_share_ppm",
            "bft_leader_missed_active_validators",
            "bft_leader_missed_active_validator_share_ppm",
            "bft_leader_missed_active_heights",
            "bft_leader_missed_active_height_rate_ppm",
            "bft_leader_missed_active_observed_height_rate_ppm",
            "bft_leader_missed_density_avg_milli",
            "bft_leader_missed_active_height_share_ppm",
        ];

        assert_eq!(fairness_review_fields.len(), 8);
        assert!(fairness_review_fields[0].ends_with("_share_ppm"));
        assert!(fairness_review_fields[1].ends_with("_validators"));
        assert!(fairness_review_fields[2].ends_with("_share_ppm"));
        assert!(fairness_review_fields[3].ends_with("_active_heights"));
        assert!(fairness_review_fields[4].ends_with("_active_height_rate_ppm"));
        assert!(fairness_review_fields[5].ends_with("_active_observed_height_rate_ppm"));
        assert!(fairness_review_fields[6].ends_with("_avg_milli"));
        assert!(fairness_review_fields[7].ends_with("_active_height_share_ppm"));
        assert_ne!(fairness_review_fields[0], fairness_review_fields[2]);
        assert_ne!(fairness_review_fields[2], fairness_review_fields[7]);
        assert_ne!(fairness_review_fields[4], fairness_review_fields[5]);
    }

    #[test]
    fn guardrail_review_bundles_keep_cause_fields_next_to_coverage_and_budget_pressure() {
        let review_bundles: &[&[&str]] = &[
            &[
                "preexec_reject_active_heights",
                "preexec_reject_active_height_rate_ppm",
                "preexec_reject_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_height_total",
                "bft_skipped_observed_height_rate_ppm",
                "preexec_reject_density_avg_milli",
                "preexec_reject_active_height_share_ppm",
                "preexec_reject_share_bps",
                "preexec_conflict_miss_share_bps",
            ],
            &[
                "rollback_active_heights",
                "rollback_active_height_rate_ppm",
                "rollback_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_height_total",
                "bft_skipped_observed_height_rate_ppm",
                "rollback_density_avg_milli",
                "rollback_active_height_share_ppm",
                "apply_error_rollback_share_bps",
            ],
        ];

        assert_eq!(review_bundles.len(), 2);
        for bundle in review_bundles {
            assert!(bundle[0].ends_with("_active_heights"));
            assert!(bundle[1].ends_with("_active_height_rate_ppm"));
            assert!(bundle[2].ends_with("_active_observed_height_rate_ppm"));
            assert_eq!(bundle[3], "bft_commit_observed_height_rate_ppm");
            assert_eq!(bundle[4], "bft_skipped_height_total");
            assert_eq!(bundle[5], "bft_skipped_observed_height_rate_ppm");
            assert!(bundle[6].ends_with("_avg_milli"));
            assert!(bundle[7].ends_with("_active_height_share_ppm"));
            assert!(bundle.last().unwrap().ends_with("_share_bps"));
        }
        assert_eq!(
            review_bundles[0].last().copied(),
            Some("preexec_conflict_miss_share_bps")
        );
        assert_eq!(
            review_bundles[1].last().copied(),
            Some("apply_error_rollback_share_bps")
        );
    }

    #[test]
    fn leader_missed_review_bundle_keeps_commit_vs_skipped_coverage_context_near_fairness_pressure()
    {
        let fairness_review_fields = [
            "bft_leader_missed_top_share_ppm",
            "bft_leader_missed_active_validators",
            "bft_leader_missed_active_validator_share_ppm",
            "bft_leader_missed_active_heights",
            "bft_leader_missed_active_height_rate_ppm",
            "bft_leader_missed_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_observed_height_rate_ppm",
            "bft_leader_missed_density_avg_milli",
            "bft_leader_missed_active_height_share_ppm",
        ];

        assert_eq!(fairness_review_fields.len(), 10);
        assert!(fairness_review_fields[0].ends_with("_share_ppm"));
        assert!(fairness_review_fields[1].ends_with("_validators"));
        assert!(fairness_review_fields[2].ends_with("_share_ppm"));
        assert!(fairness_review_fields[3].ends_with("_active_heights"));
        assert!(fairness_review_fields[4].ends_with("_active_height_rate_ppm"));
        assert!(fairness_review_fields[5].ends_with("_active_observed_height_rate_ppm"));
        assert_eq!(
            fairness_review_fields[6],
            "bft_commit_observed_height_rate_ppm"
        );
        assert_eq!(
            fairness_review_fields[7],
            "bft_skipped_observed_height_rate_ppm"
        );
        assert!(fairness_review_fields[8].ends_with("_avg_milli"));
        assert!(fairness_review_fields[9].ends_with("_active_height_share_ppm"));
        assert_ne!(fairness_review_fields[4], fairness_review_fields[5]);
        assert_ne!(fairness_review_fields[6], fairness_review_fields[7]);
    }

    #[test]
    fn leader_missed_review_bundle_keeps_absolute_skipped_width_next_to_fairness_spread_and_budget_pressure(
    ) {
        let fairness_review_fields = [
            "bft_leader_missed_top_share_ppm",
            "bft_leader_missed_active_validators",
            "bft_leader_missed_active_validator_share_ppm",
            "bft_leader_missed_active_heights",
            "bft_leader_missed_active_height_rate_ppm",
            "bft_leader_missed_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
            "bft_leader_missed_density_avg_milli",
            "bft_leader_missed_active_height_share_ppm",
        ];

        assert_eq!(fairness_review_fields.len(), 11);
        assert!(fairness_review_fields[0].ends_with("_share_ppm"));
        assert!(fairness_review_fields[1].ends_with("_validators"));
        assert!(fairness_review_fields[2].ends_with("_share_ppm"));
        assert!(fairness_review_fields[3].ends_with("_active_heights"));
        assert!(fairness_review_fields[4].ends_with("_active_height_rate_ppm"));
        assert!(fairness_review_fields[5].ends_with("_active_observed_height_rate_ppm"));
        assert_eq!(
            fairness_review_fields[6],
            "bft_commit_observed_height_rate_ppm"
        );
        assert_eq!(fairness_review_fields[7], "bft_skipped_height_total");
        assert_eq!(
            fairness_review_fields[8],
            "bft_skipped_observed_height_rate_ppm"
        );
        assert!(fairness_review_fields[9].ends_with("_avg_milli"));
        assert!(fairness_review_fields[10].ends_with("_active_height_share_ppm"));
        assert_ne!(fairness_review_fields[4], fairness_review_fields[5]);
        assert_ne!(fairness_review_fields[6], fairness_review_fields[8]);
        assert_ne!(fairness_review_fields[7], fairness_review_fields[8]);
    }

    #[test]
    fn leader_missed_review_bundle_keeps_skipped_width_between_commit_coverage_and_skip_rate() {
        let fairness_review_fields = [
            "bft_leader_missed_top_share_ppm",
            "bft_leader_missed_active_validators",
            "bft_leader_missed_active_validator_share_ppm",
            "bft_leader_missed_active_heights",
            "bft_leader_missed_active_height_rate_ppm",
            "bft_leader_missed_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
            "bft_leader_missed_density_avg_milli",
            "bft_leader_missed_active_height_share_ppm",
        ];

        let commit_idx = fairness_review_fields
            .iter()
            .position(|field| *field == "bft_commit_observed_height_rate_ppm")
            .expect("commit coverage field present");
        let skipped_total_idx = fairness_review_fields
            .iter()
            .position(|field| *field == "bft_skipped_height_total")
            .expect("skipped width field present");
        let skipped_rate_idx = fairness_review_fields
            .iter()
            .position(|field| *field == "bft_skipped_observed_height_rate_ppm")
            .expect("skipped coverage field present");
        let density_idx = fairness_review_fields
            .iter()
            .position(|field| *field == "bft_leader_missed_density_avg_milli")
            .expect("density field present");
        let share_idx = fairness_review_fields
            .iter()
            .position(|field| *field == "bft_leader_missed_active_height_share_ppm")
            .expect("budget share field present");

        assert_eq!(skipped_total_idx, commit_idx + 1);
        assert_eq!(skipped_rate_idx, skipped_total_idx + 1);
        assert!(density_idx > skipped_rate_idx);
        assert!(share_idx > density_idx);
    }

    #[test]
    fn consensus_bursty_review_bundles_keep_commit_vs_observed_coverage_pair_near_active_height_rates(
    ) {
        let review_bundles: &[&[&str]] = &[
            &[
                "hot_object_active_heights",
                "hot_object_active_height_rate_ppm",
                "hot_object_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_observed_height_rate_ppm",
                "hot_object_active_height_share_ppm",
            ],
            &[
                "bft_round_change_active_heights",
                "bft_round_change_active_height_rate_ppm",
                "bft_round_change_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_observed_height_rate_ppm",
                "bft_round_change_active_height_share_ppm",
            ],
            &[
                "bft_round_change_backoff_active_heights",
                "bft_round_change_backoff_active_height_rate_ppm",
                "bft_round_change_backoff_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_observed_height_rate_ppm",
                "bft_round_change_backoff_active_height_share_ppm",
            ],
            &[
                "bft_leader_missed_active_heights",
                "bft_leader_missed_active_height_rate_ppm",
                "bft_leader_missed_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_observed_height_rate_ppm",
                "bft_leader_missed_active_height_share_ppm",
            ],
        ];

        assert_eq!(review_bundles.len(), 4);
        for bundle in review_bundles {
            assert!(bundle[0].ends_with("_active_heights"));
            assert!(bundle[1].ends_with("_active_height_rate_ppm"));
            assert!(bundle[2].ends_with("_active_observed_height_rate_ppm"));
            assert_eq!(bundle[3], "bft_commit_observed_height_rate_ppm");
            assert_eq!(bundle[4], "bft_skipped_observed_height_rate_ppm");
            assert!(bundle[5].ends_with("_active_height_share_ppm"));
            assert_ne!(bundle[1], bundle[2]);
            assert_ne!(bundle[3], bundle[4]);
        }
    }

    #[test]
    fn consensus_bursty_review_bundles_keep_absolute_skipped_height_width_next_to_observed_coverage_rates(
    ) {
        let review_bundles: &[&[&str]] = &[
            &[
                "critical_wait_active_height_rate_ppm",
                "critical_wait_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_height_total",
                "bft_skipped_observed_height_rate_ppm",
            ],
            &[
                "hot_object_active_height_rate_ppm",
                "hot_object_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_height_total",
                "bft_skipped_observed_height_rate_ppm",
            ],
            &[
                "preexec_reject_active_height_rate_ppm",
                "preexec_reject_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_height_total",
                "bft_skipped_observed_height_rate_ppm",
            ],
            &[
                "rollback_active_height_rate_ppm",
                "rollback_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_height_total",
                "bft_skipped_observed_height_rate_ppm",
            ],
            &[
                "bft_round_change_active_height_rate_ppm",
                "bft_round_change_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_height_total",
                "bft_skipped_observed_height_rate_ppm",
            ],
            &[
                "bft_round_change_backoff_active_height_rate_ppm",
                "bft_round_change_backoff_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_height_total",
                "bft_skipped_observed_height_rate_ppm",
            ],
            &[
                "bft_leader_missed_active_height_rate_ppm",
                "bft_leader_missed_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_height_total",
                "bft_skipped_observed_height_rate_ppm",
            ],
        ];

        assert_eq!(review_bundles.len(), 7);
        for bundle in review_bundles {
            assert!(bundle[0].ends_with("_active_height_rate_ppm"));
            assert!(bundle[1].ends_with("_active_observed_height_rate_ppm"));
            assert_eq!(bundle[2], "bft_commit_observed_height_rate_ppm");
            assert_eq!(bundle[3], "bft_skipped_height_total");
            assert_eq!(bundle[4], "bft_skipped_observed_height_rate_ppm");
            assert_ne!(bundle[0], bundle[1]);
            assert_ne!(bundle[2], bundle[4]);
        }
    }

    #[test]
    fn fairness_and_guardrail_review_bundles_keep_skipped_width_adjacent_to_skip_rate() {
        let review_bundles: &[&[&str]] = &[
            &[
                "critical_wait_active_height_rate_ppm",
                "critical_wait_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_height_total",
                "bft_skipped_observed_height_rate_ppm",
                "critical_wait_density_avg_milli",
                "critical_wait_active_height_share_ppm",
            ],
            &[
                "preexec_reject_active_height_rate_ppm",
                "preexec_reject_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_height_total",
                "bft_skipped_observed_height_rate_ppm",
                "preexec_reject_density_avg_milli",
                "preexec_reject_active_height_share_ppm",
                "preexec_reject_share_bps",
                "preexec_conflict_miss_share_bps",
            ],
            &[
                "rollback_active_height_rate_ppm",
                "rollback_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_height_total",
                "bft_skipped_observed_height_rate_ppm",
                "rollback_density_avg_milli",
                "rollback_active_height_share_ppm",
                "apply_error_rollback_share_bps",
            ],
            &[
                "bft_round_change_active_height_rate_ppm",
                "bft_round_change_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_height_total",
                "bft_skipped_observed_height_rate_ppm",
                "bft_round_change_active_height_share_ppm",
            ],
            &[
                "bft_round_change_backoff_active_height_rate_ppm",
                "bft_round_change_backoff_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_height_total",
                "bft_skipped_observed_height_rate_ppm",
                "bft_round_change_backoff_active_height_share_ppm",
            ],
            &[
                "bft_leader_missed_active_height_rate_ppm",
                "bft_leader_missed_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_height_total",
                "bft_skipped_observed_height_rate_ppm",
                "bft_leader_missed_density_avg_milli",
                "bft_leader_missed_active_height_share_ppm",
            ],
        ];

        assert_eq!(review_bundles.len(), 6);
        for bundle in review_bundles {
            let skipped_total_idx = bundle
                .iter()
                .position(|field| *field == "bft_skipped_height_total")
                .expect("skipped total must stay present in review bundle");
            let skipped_rate_idx = bundle
                .iter()
                .position(|field| *field == "bft_skipped_observed_height_rate_ppm")
                .expect("skipped observed rate must stay present in review bundle");

            assert_eq!(skipped_rate_idx, skipped_total_idx + 1);
            assert_eq!(
                bundle[skipped_total_idx - 1],
                "bft_commit_observed_height_rate_ppm"
            );
            assert!(bundle[0].ends_with("_active_height_rate_ppm"));
            assert!(bundle[1].ends_with("_active_observed_height_rate_ppm"));
            assert_ne!(bundle[0], bundle[1]);
            assert_ne!(bundle[skipped_total_idx], bundle[skipped_rate_idx]);
        }
    }

    #[test]
    fn recovery_error_rate_field_name_stays_explicitly_incident_focused() {
        let recovery_error_rate_field_name = "recovery_error_rate";
        let apply_error_total_field_name = "apply_error_total";
        let rollback_total_field_name = "rollback_total";
        let timeout_migrated_total_field_name = "timeout_migrated_total";

        assert!(recovery_error_rate_field_name.ends_with("_rate"));
        assert!(apply_error_total_field_name.ends_with("_total"));
        assert!(rollback_total_field_name.ends_with("_total"));
        assert!(timeout_migrated_total_field_name.ends_with("_total"));
        assert_ne!(recovery_error_rate_field_name, apply_error_total_field_name);
        assert_ne!(recovery_error_rate_field_name, rollback_total_field_name);
        assert_ne!(recovery_error_rate_field_name, timeout_migrated_total_field_name);
    }

    #[test]
    fn consensus_summary_incident_bundle_keeps_timeout_and_recovery_signals_adjacent() {
        let incident_bundle = [
            "apply_error_total",
            "rollback_total",
            "apply_error_rollback_share_bps",
            "timeout_migrated_total",
            "recovery_error_rate",
            "bft_observed_heights",
        ];

        assert_eq!(incident_bundle.len(), 6);
        assert!(incident_bundle[0].ends_with("_total"));
        assert!(incident_bundle[1].ends_with("_total"));
        assert!(incident_bundle[2].ends_with("_share_bps"));
        assert!(incident_bundle[3].ends_with("_total"));
        assert!(incident_bundle[4].ends_with("_rate"));
        assert!(incident_bundle[5].ends_with("_heights"));
        assert_eq!(incident_bundle[3], "timeout_migrated_total");
        assert_eq!(incident_bundle[4], "recovery_error_rate");
        assert_eq!(incident_bundle[5], "bft_observed_heights");
        assert_ne!(incident_bundle[3], incident_bundle[4]);
        assert_ne!(incident_bundle[4], incident_bundle[5]);
    }

    #[test]
    fn consensus_summary_incident_bundle_keeps_height_counters_after_recovery_rate() {
        let incident_bundle = [
            "apply_error_total",
            "rollback_total",
            "apply_error_rollback_share_bps",
            "timeout_migrated_total",
            "recovery_error_rate",
            "bft_observed_heights",
            "bft_committed_heights",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
        ];

        assert_eq!(incident_bundle.len(), 10);
        assert!(incident_bundle[4].ends_with("_rate"));
        assert!(incident_bundle[5].ends_with("_heights"));
        assert!(incident_bundle[6].ends_with("_heights"));
        assert!(incident_bundle[7].ends_with("_rate_ppm"));
        assert!(incident_bundle[8].ends_with("_total"));
        assert!(incident_bundle[9].ends_with("_rate_ppm"));
        assert_eq!(incident_bundle[4], "recovery_error_rate");
        assert_eq!(incident_bundle[5], "bft_observed_heights");
        assert_eq!(incident_bundle[6], "bft_committed_heights");
        assert_eq!(incident_bundle[7], "bft_commit_observed_height_rate_ppm");
        assert_eq!(incident_bundle[8], "bft_skipped_height_total");
        assert_eq!(incident_bundle[9], "bft_skipped_observed_height_rate_ppm");
    }

    #[test]
    fn recovery_error_rate_uses_finality_sample_count_as_denominator() {
        let apply_error_total = 3u64;
        let finality_samples_ms = [12u64, 18, 24, 30, 36];
        let recovery_error_rate = if finality_samples_ms.is_empty() {
            0.0
        } else {
            apply_error_total as f64 / finality_samples_ms.len() as f64
        };

        assert_eq!(recovery_error_rate, 0.6);
        assert!(recovery_error_rate > 0.0);
        assert!(recovery_error_rate < 1.0);
    }

    #[test]
    fn round_change_backoff_wall_share_metric_name_stays_ppm_based() {
        let field_name = "bft_round_change_backoff_wall_share_ppm";
        assert!(field_name.ends_with("_share_ppm"));
        assert!(!field_name.ends_with("_per_height_ms"));
    }

    #[test]
    fn round_change_backoff_share_metric_keeps_compatibility_alias_name() {
        let field_name = "bft_round_change_backoff_share_ppm";
        assert!(field_name.ends_with("_share_ppm"));
        assert!(!field_name.contains("wall_share_ppm"));
    }

    #[test]
    fn round_change_backoff_metric_names_keep_wall_alias_and_budget_share_distinct() {
        let wall_share_field_name = "bft_round_change_backoff_wall_share_ppm";
        let compatibility_alias_field_name = "bft_round_change_backoff_share_ppm";
        let active_height_share_field_name = "bft_round_change_backoff_active_height_share_ppm";

        assert!(wall_share_field_name.ends_with("_share_ppm"));
        assert!(compatibility_alias_field_name.ends_with("_share_ppm"));
        assert!(active_height_share_field_name.ends_with("_share_ppm"));
        assert_ne!(wall_share_field_name, compatibility_alias_field_name);
        assert_ne!(wall_share_field_name, active_height_share_field_name);
        assert_ne!(
            compatibility_alias_field_name,
            active_height_share_field_name
        );
    }

    #[test]
    fn round_change_backoff_wall_share_metric_normalizes_per_committed_height_budget() {
        let bft_round_change_backoff_total_ms = 18u64;
        let bft_committed_heights = 4u64;
        let finality_avg_ms = 20u128;
        let wall_share_ppm = wall_time_share_ppm(
            bft_round_change_backoff_total_ms,
            bft_committed_heights,
            finality_avg_ms,
        );
        let active_height_share_ppm = finality_budget_share_ppm(
            ratio_milli_u64(bft_round_change_backoff_total_ms, bft_committed_heights),
            finality_avg_ms,
        );

        assert_eq!(wall_share_ppm, 225_000);
        assert_eq!(active_height_share_ppm, 225_000);
    }

    #[test]
    fn round_change_backoff_compatibility_alias_matches_wall_share_metric() {
        let bft_round_change_backoff_total_ms = 18u64;
        let bft_committed_heights = 4u64;
        let finality_avg_ms = 20u128;
        let wall_share_ppm = wall_time_share_ppm(
            bft_round_change_backoff_total_ms,
            bft_committed_heights,
            finality_avg_ms,
        );
        let compatibility_alias_ppm = wall_share_ppm;

        assert_eq!(wall_share_ppm, 225_000);
        assert_eq!(compatibility_alias_ppm, wall_share_ppm);
    }

    #[test]
    fn round_change_backoff_wall_share_metric_can_exceed_one_million_when_backoff_dominates() {
        let bft_round_change_backoff_total_ms = 12u64;
        let bft_committed_heights = 3u64;
        let finality_avg_ms = 2u128;
        let wall_share_ppm = wall_time_share_ppm(
            bft_round_change_backoff_total_ms,
            bft_committed_heights,
            finality_avg_ms,
        );

        assert_eq!(wall_share_ppm, 2_000_000);
        assert!(wall_share_ppm > 1_000_000);
    }

    #[test]
    fn bft_commit_and_skipped_height_rates_make_no_commit_pressure_visible() {
        let bft_observed_heights = 5u64;
        let bft_committed_heights = 4u64;
        let bft_skipped_height_total = bft_observed_heights - bft_committed_heights;
        let bft_commit_observed_height_rate_ppm =
            ratio_ppm_u64(bft_committed_heights, bft_observed_heights);
        let bft_skipped_observed_height_rate_ppm =
            ratio_ppm_u64(bft_skipped_height_total, bft_observed_heights);

        assert_eq!(bft_commit_observed_height_rate_ppm, 800_000);
        assert_eq!(bft_skipped_height_total, 1);
        assert_eq!(bft_skipped_observed_height_rate_ppm, 200_000);
        assert_eq!(
            bft_commit_observed_height_rate_ppm + bft_skipped_observed_height_rate_ppm,
            1_000_000
        );
    }

    #[test]
    fn bft_commit_and_skipped_height_metric_names_keep_commit_and_skip_views_distinct() {
        let commit_rate_field_name = "bft_commit_observed_height_rate_ppm";
        let skipped_total_field_name = "bft_skipped_height_total";
        let skipped_rate_field_name = "bft_skipped_observed_height_rate_ppm";

        assert!(commit_rate_field_name.ends_with("_rate_ppm"));
        assert!(skipped_total_field_name.ends_with("_total"));
        assert!(skipped_rate_field_name.ends_with("_rate_ppm"));
        assert_ne!(commit_rate_field_name, skipped_total_field_name);
        assert_ne!(commit_rate_field_name, skipped_rate_field_name);
        assert_ne!(skipped_total_field_name, skipped_rate_field_name);
    }

    #[test]
    fn bft_commit_and_skipped_height_review_bundle_keeps_observed_coverage_pair_together() {
        let coverage_review_fields = [
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
        ];

        assert_eq!(coverage_review_fields.len(), 3);
        assert!(coverage_review_fields[0].ends_with("_rate_ppm"));
        assert!(coverage_review_fields[1].ends_with("_total"));
        assert!(coverage_review_fields[2].ends_with("_rate_ppm"));
        assert_ne!(coverage_review_fields[0], coverage_review_fields[2]);
    }

    #[test]
    fn round_change_active_height_rate_metrics_make_jitter_concentration_visible() {
        let bft_round_change_total = 6u64;
        let bft_round_change_active_heights = 2u64;
        let bft_committed_heights = 4u64;
        let bft_observed_heights = 5u64;

        assert_eq!(
            ratio_ppm_u64(bft_round_change_active_heights, bft_committed_heights),
            500_000
        );
        assert_eq!(
            ratio_ppm_u64(bft_round_change_active_heights, bft_observed_heights),
            400_000
        );
        assert_eq!(bft_round_change_total / bft_round_change_active_heights, 3);
        assert_eq!(
            ratio_ppm_u64(bft_round_change_total, bft_round_change_active_heights),
            3_000_000
        );
    }

    #[test]
    fn round_change_metric_names_keep_committed_budget_and_observed_coverage_distinct() {
        let active_height_rate_field_name = "bft_round_change_active_height_rate_ppm";
        let active_observed_height_rate_field_name =
            "bft_round_change_active_observed_height_rate_ppm";
        let active_height_share_field_name = "bft_round_change_active_height_share_ppm";
        let density_avg_milli_field_name = "bft_round_change_density_avg_milli";

        assert!(active_height_rate_field_name.ends_with("_rate_ppm"));
        assert!(active_observed_height_rate_field_name.ends_with("_rate_ppm"));
        assert!(active_height_share_field_name.ends_with("_share_ppm"));
        assert!(density_avg_milli_field_name.ends_with("_avg_milli"));
        assert_ne!(
            active_height_rate_field_name,
            active_observed_height_rate_field_name
        );
        assert_ne!(
            active_height_rate_field_name,
            active_height_share_field_name
        );
        assert_ne!(
            active_observed_height_rate_field_name,
            active_height_share_field_name
        );
        assert_ne!(density_avg_milli_field_name, active_height_share_field_name);
    }

    #[test]
    fn round_change_observed_height_rate_exposes_skipped_height_coverage_gap() {
        let bft_round_change_active_heights = 2u64;
        let bft_committed_heights = 2u64;
        let bft_observed_heights = 5u64;
        let committed_height_rate_ppm =
            ratio_ppm_u64(bft_round_change_active_heights, bft_committed_heights);
        let observed_height_rate_ppm =
            ratio_ppm_u64(bft_round_change_active_heights, bft_observed_heights);

        assert_eq!(committed_height_rate_ppm, 1_000_000);
        assert_eq!(observed_height_rate_ppm, 400_000);
        assert!(observed_height_rate_ppm < committed_height_rate_ppm);
    }

    #[test]
    fn round_change_coverage_pair_with_commit_and_skip_rates_exposes_denominator_shift() {
        let bft_round_change_active_heights = 2u64;
        let bft_committed_heights = 2u64;
        let bft_observed_heights = 5u64;
        let bft_skipped_height_total = bft_observed_heights - bft_committed_heights;

        let bft_round_change_active_height_rate_ppm =
            ratio_ppm_u64(bft_round_change_active_heights, bft_committed_heights);
        let bft_round_change_active_observed_height_rate_ppm =
            ratio_ppm_u64(bft_round_change_active_heights, bft_observed_heights);
        let bft_commit_observed_height_rate_ppm =
            ratio_ppm_u64(bft_committed_heights, bft_observed_heights);
        let bft_skipped_observed_height_rate_ppm =
            ratio_ppm_u64(bft_skipped_height_total, bft_observed_heights);

        assert_eq!(bft_round_change_active_height_rate_ppm, 1_000_000);
        assert_eq!(bft_round_change_active_observed_height_rate_ppm, 400_000);
        assert_eq!(bft_commit_observed_height_rate_ppm, 400_000);
        assert_eq!(bft_skipped_observed_height_rate_ppm, 600_000);
        assert_eq!(
            bft_commit_observed_height_rate_ppm + bft_skipped_observed_height_rate_ppm,
            1_000_000
        );
        assert!(
            bft_round_change_active_observed_height_rate_ppm
                < bft_round_change_active_height_rate_ppm
        );
        assert_eq!(
            bft_round_change_active_observed_height_rate_ppm,
            bft_commit_observed_height_rate_ppm
        );
        assert!(bft_skipped_observed_height_rate_ppm > bft_commit_observed_height_rate_ppm);
    }

    #[test]
    fn round_change_review_bundle_keeps_commit_skip_and_coverage_denominator_views_together() {
        let jitter_review_fields = [
            "bft_round_change_active_heights",
            "bft_round_change_active_height_rate_ppm",
            "bft_round_change_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
            "bft_round_change_density_avg_milli",
            "bft_round_change_active_height_share_ppm",
        ];

        assert_eq!(jitter_review_fields.len(), 8);
        assert!(jitter_review_fields[0].ends_with("_heights"));
        assert!(jitter_review_fields[1].ends_with("_rate_ppm"));
        assert!(jitter_review_fields[2].ends_with("_rate_ppm"));
        assert!(jitter_review_fields[3].ends_with("_rate_ppm"));
        assert!(jitter_review_fields[4].ends_with("_total"));
        assert!(jitter_review_fields[5].ends_with("_rate_ppm"));
        assert!(jitter_review_fields[6].ends_with("_avg_milli"));
        assert!(jitter_review_fields[7].ends_with("_share_ppm"));
        assert_ne!(jitter_review_fields[1], jitter_review_fields[2]);
        assert_ne!(jitter_review_fields[2], jitter_review_fields[3]);
        assert_ne!(jitter_review_fields[3], jitter_review_fields[5]);
        assert_ne!(jitter_review_fields[6], jitter_review_fields[7]);
    }

    #[test]
    fn round_change_density_avg_milli_preserves_sub_integer_jitter_signal() {
        let bft_round_change_total = 5u64;
        let bft_round_change_active_heights = 2u64;
        let bft_round_change_density_avg = bft_round_change_total / bft_round_change_active_heights;
        let bft_round_change_density_avg_milli =
            ratio_milli_u64(bft_round_change_total, bft_round_change_active_heights);

        assert_eq!(bft_round_change_density_avg, 2);
        assert_eq!(bft_round_change_density_avg_milli, 2_500);
    }

    #[test]
    fn round_change_backoff_density_avg_milli_preserves_clustered_jitter_signal() {
        let bft_round_change_backoff_total_ms = 5u64;
        let bft_round_change_backoff_active_heights = 2u64;
        let bft_round_change_backoff_density_avg_ms =
            bft_round_change_backoff_total_ms / bft_round_change_backoff_active_heights;
        let bft_round_change_backoff_density_avg_milli = ratio_milli_u64(
            bft_round_change_backoff_total_ms,
            bft_round_change_backoff_active_heights,
        );

        assert_eq!(bft_round_change_backoff_density_avg_ms, 2);
        assert_eq!(bft_round_change_backoff_density_avg_milli, 2_500);
    }

    #[test]
    fn consensus_log_contract_keeps_round_change_density_milli_fields() {
        let field_name = "bft_round_change_density_avg_milli";
        let integer_avg_field_name = "bft_round_change_density_avg";
        let active_share_field_name = "bft_round_change_active_height_share_ppm";
        let backoff_field_name = "bft_round_change_backoff_density_avg_milli";
        let backoff_integer_avg_field_name = "bft_round_change_backoff_density_avg_ms";
        let backoff_active_share_field_name = "bft_round_change_backoff_active_height_share_ppm";

        assert!(field_name.ends_with("_avg_milli"));
        assert!(active_share_field_name.ends_with("_share_ppm"));
        assert!(backoff_field_name.ends_with("_avg_milli"));
        assert!(backoff_integer_avg_field_name.ends_with("_avg_ms"));
        assert!(backoff_active_share_field_name.ends_with("_share_ppm"));
        assert_ne!(field_name, integer_avg_field_name);
        assert_ne!(active_share_field_name, field_name);
        assert_ne!(backoff_field_name, backoff_integer_avg_field_name);
        assert_ne!(backoff_active_share_field_name, backoff_field_name);
    }

    #[test]
    fn round_change_density_milli_fields_preserve_sub_integer_signal_vs_integer_averages() {
        let bft_round_change_total = 5u64;
        let bft_round_change_backoff_total_ms = 5u64;
        let bft_round_change_active_heights = 2u64;
        let bft_round_change_backoff_active_heights = 2u64;
        let finality_avg = 10u128;

        let density_avg = bft_round_change_total / bft_round_change_active_heights;
        let density_avg_milli =
            ratio_milli_u64(bft_round_change_total, bft_round_change_active_heights);
        let active_height_share_ppm =
            ratio_ppm_u64(density_avg_milli, (finality_avg as u64) * 1_000);
        let backoff_density_avg_ms =
            bft_round_change_backoff_total_ms / bft_round_change_backoff_active_heights;
        let backoff_density_avg_milli = ratio_milli_u64(
            bft_round_change_backoff_total_ms,
            bft_round_change_backoff_active_heights,
        );
        let backoff_active_height_share_ppm =
            ratio_ppm_u64(backoff_density_avg_milli, (finality_avg as u64) * 1_000);

        assert_eq!(density_avg, 2);
        assert_eq!(density_avg_milli, 2_500);
        assert!(density_avg_milli > density_avg * 1_000);
        assert_eq!(active_height_share_ppm, 250_000);
        assert_eq!(backoff_density_avg_ms, 2);
        assert_eq!(backoff_density_avg_milli, 2_500);
        assert!(backoff_density_avg_milli > backoff_density_avg_ms * 1_000);
        assert_eq!(backoff_active_height_share_ppm, 250_000);
    }

    #[test]
    fn round_change_backoff_density_uses_backoff_active_heights_not_round_change_coverage() {
        let bft_round_change_backoff_total_ms = 5u64;
        let bft_round_change_active_heights = 4u64;
        let bft_round_change_backoff_active_heights = 2u64;
        let finality_avg = 10u128;

        let diluted_density_avg_milli = ratio_milli_u64(
            bft_round_change_backoff_total_ms,
            bft_round_change_active_heights,
        );
        let backoff_density_avg_milli = ratio_milli_u64(
            bft_round_change_backoff_total_ms,
            bft_round_change_backoff_active_heights,
        );
        let backoff_active_height_share_ppm =
            finality_budget_share_ppm(backoff_density_avg_milli, finality_avg);

        assert_eq!(diluted_density_avg_milli, 1_250);
        assert_eq!(backoff_density_avg_milli, 2_500);
        assert!(backoff_density_avg_milli > diluted_density_avg_milli);
        assert_eq!(backoff_active_height_share_ppm, 250_000);
    }

    #[test]
    fn active_height_budget_share_metrics_can_exceed_one_million_when_jitter_or_fairness_dominates_finality(
    ) {
        let finality_avg = 2u128;
        let round_change_density_avg_milli = 3_000u64;
        let round_change_backoff_density_avg_milli = 4_500u64;
        let leader_missed_density_avg_milli = 2_500u64;

        let round_change_active_height_share_ppm =
            finality_budget_share_ppm(round_change_density_avg_milli, finality_avg);
        let round_change_backoff_active_height_share_ppm =
            finality_budget_share_ppm(round_change_backoff_density_avg_milli, finality_avg);
        let leader_missed_active_height_share_ppm =
            finality_budget_share_ppm(leader_missed_density_avg_milli, finality_avg);

        assert_eq!(round_change_active_height_share_ppm, 1_500_000);
        assert_eq!(round_change_backoff_active_height_share_ppm, 2_250_000);
        assert_eq!(leader_missed_active_height_share_ppm, 1_250_000);
        assert!(round_change_active_height_share_ppm > 1_000_000);
        assert!(round_change_backoff_active_height_share_ppm > 1_000_000);
        assert!(leader_missed_active_height_share_ppm > 1_000_000);
    }

    #[test]
    fn hot_object_active_share_metrics_avoid_zero_block_dilution() {
        let all_block_top_label_share_samples_ppm = vec![0u128, 500_000, 800_000];
        let all_block_tail_share_samples_ppm = vec![0u128, 500_000, 200_000];
        let hot_object_active_heights = 2u64;
        let hot_object_active_top_label_share_total_ppm = 1_300_000u128;
        let hot_object_active_tail_share_total_ppm = 700_000u128;
        let total_heights = 3u64;

        let diluted_top_label_share_avg_ppm =
            average_or_zero(&all_block_top_label_share_samples_ppm);
        let diluted_tail_share_avg_ppm = average_or_zero(&all_block_tail_share_samples_ppm);
        let active_top_label_share_avg_ppm =
            hot_object_active_top_label_share_total_ppm / hot_object_active_heights as u128;
        let active_tail_share_avg_ppm =
            hot_object_active_tail_share_total_ppm / hot_object_active_heights as u128;
        let hot_object_active_height_rate_ppm =
            ratio_ppm_u64(hot_object_active_heights, total_heights);
        let hot_object_active_observed_height_rate_ppm =
            ratio_ppm_u64(hot_object_active_heights, 5u64);

        assert_eq!(diluted_top_label_share_avg_ppm, 433_333);
        assert_eq!(active_top_label_share_avg_ppm, 650_000);
        assert!(active_top_label_share_avg_ppm > diluted_top_label_share_avg_ppm);
        assert_eq!(diluted_tail_share_avg_ppm, 233_333);
        assert_eq!(active_tail_share_avg_ppm, 350_000);
        assert!(active_tail_share_avg_ppm > diluted_tail_share_avg_ppm);
        assert_eq!(hot_object_active_height_rate_ppm, 666_666);
        assert_eq!(hot_object_active_observed_height_rate_ppm, 400_000);
        assert!(hot_object_active_observed_height_rate_ppm < hot_object_active_height_rate_ppm);
    }

    #[test]
    fn leader_missed_concentration_metrics_make_single_proposer_hotspots_visible() {
        let leader_missed_final = vec![4u64, 1u64, 1u64, 0u64];
        let bft_leader_missed_total: u64 = leader_missed_final.iter().copied().sum();
        let bft_leader_missed_max = leader_missed_final.iter().copied().max().unwrap_or(0);
        let bft_leader_missed_top_share_ppm =
            ratio_ppm_u64(bft_leader_missed_max, bft_leader_missed_total);
        let bft_leader_missed_active_validators = leader_missed_final
            .iter()
            .filter(|missed| **missed > 0)
            .count() as u64;
        let bft_leader_missed_active_validator_share_ppm = ratio_ppm_u64(
            bft_leader_missed_active_validators,
            leader_missed_final.len() as u64,
        );

        assert_eq!(bft_leader_missed_total, 6);
        assert_eq!(bft_leader_missed_max, 4);
        assert_eq!(bft_leader_missed_top_share_ppm, 666_666);
        assert_eq!(bft_leader_missed_active_validators, 3);
        assert_eq!(bft_leader_missed_active_validator_share_ppm, 750_000);
    }

    #[test]
    fn leader_missed_concentration_metrics_are_zero_without_any_misses() {
        let leader_missed_final = vec![0u64, 0u64, 0u64, 0u64];
        let bft_leader_missed_total: u64 = leader_missed_final.iter().copied().sum();
        let bft_leader_missed_max = leader_missed_final.iter().copied().max().unwrap_or(0);
        let bft_leader_missed_top_share_ppm =
            ratio_ppm_u64(bft_leader_missed_max, bft_leader_missed_total);
        let bft_leader_missed_active_validators = leader_missed_final
            .iter()
            .filter(|missed| **missed > 0)
            .count() as u64;
        let bft_leader_missed_active_validator_share_ppm = ratio_ppm_u64(
            bft_leader_missed_active_validators,
            leader_missed_final.len() as u64,
        );

        assert_eq!(bft_leader_missed_total, 0);
        assert_eq!(bft_leader_missed_max, 0);
        assert_eq!(bft_leader_missed_top_share_ppm, 0);
        assert_eq!(bft_leader_missed_active_validators, 0);
        assert_eq!(bft_leader_missed_active_validator_share_ppm, 0);
    }

    #[test]
    fn leader_missed_metric_names_keep_hotspot_and_distribution_semantics_distinct() {
        let total_field_name = "bft_leader_missed_total";
        let max_field_name = "bft_leader_missed_max";
        let top_share_field_name = "bft_leader_missed_top_share_ppm";
        let active_validators_field_name = "bft_leader_missed_active_validators";
        let active_validator_share_field_name = "bft_leader_missed_active_validator_share_ppm";
        let active_heights_field_name = "bft_leader_missed_active_heights";
        let active_height_rate_field_name = "bft_leader_missed_active_height_rate_ppm";
        let active_observed_height_rate_field_name =
            "bft_leader_missed_active_observed_height_rate_ppm";
        let distribution_field_name = "bft_leader_missed_proposals";

        assert!(total_field_name.ends_with("_total"));
        assert!(max_field_name.ends_with("_max"));
        assert!(top_share_field_name.ends_with("_share_ppm"));
        assert!(active_validators_field_name.ends_with("_validators"));
        assert!(active_validator_share_field_name.ends_with("_share_ppm"));
        assert!(active_heights_field_name.ends_with("_heights"));
        assert!(
            active_height_rate_field_name.ends_with("_share_ppm")
                || active_height_rate_field_name.ends_with("_rate_ppm")
        );
        assert!(active_observed_height_rate_field_name.ends_with("_rate_ppm"));
        assert!(distribution_field_name.ends_with("_proposals"));
        assert_ne!(total_field_name, max_field_name);
        assert_ne!(max_field_name, top_share_field_name);
        assert_ne!(top_share_field_name, active_validators_field_name);
        assert_ne!(
            active_validators_field_name,
            active_validator_share_field_name
        );
        assert_ne!(active_validator_share_field_name, active_heights_field_name);
        assert_ne!(active_heights_field_name, active_height_rate_field_name);
        assert_ne!(
            active_height_rate_field_name,
            active_observed_height_rate_field_name
        );
        assert_ne!(
            active_observed_height_rate_field_name,
            distribution_field_name
        );
    }

    #[test]
    fn leader_missed_active_height_rate_metrics_make_fairness_stall_concentration_visible() {
        let bft_leader_missed_active_heights = 3u64;
        let bft_committed_heights = 4u64;
        let bft_observed_heights = 6u64;
        let bft_leader_missed_active_height_rate_ppm =
            ratio_ppm_u64(bft_leader_missed_active_heights, bft_committed_heights);
        let bft_leader_missed_active_observed_height_rate_ppm =
            ratio_ppm_u64(bft_leader_missed_active_heights, bft_observed_heights);

        assert_eq!(bft_leader_missed_active_heights, 3);
        assert_eq!(bft_leader_missed_active_height_rate_ppm, 750_000);
        assert_eq!(bft_leader_missed_active_observed_height_rate_ppm, 500_000);
    }

    #[test]
    fn leader_missed_active_heights_count_only_new_miss_bursts() {
        let mut active_heights = 0u64;
        let mut previous_snapshot = vec![0u64, 0u64, 0u64, 0u64];
        let snapshots = [
            vec![0u64, 1u64, 0u64, 0u64],
            vec![0u64, 1u64, 0u64, 0u64],
            vec![0u64, 1u64, 0u64, 1u64],
        ];

        for snapshot in snapshots {
            if missed_proposals_added_since(&previous_snapshot, &snapshot) > 0 {
                active_heights += 1;
            }
            previous_snapshot = snapshot;
        }

        assert_eq!(active_heights, 2);
    }

    #[test]
    fn leader_missed_added_since_ignores_repeated_cumulative_snapshots() {
        let previous_snapshot = vec![0u64, 2u64, 1u64, 0u64];
        let repeated_snapshot = vec![0u64, 2u64, 1u64, 0u64];

        assert_eq!(
            missed_proposals_added_since(&previous_snapshot, &repeated_snapshot),
            0
        );
    }

    #[test]
    fn leader_missed_observed_height_rate_exposes_skipped_height_coverage_gap() {
        let bft_leader_missed_active_heights = 2u64;
        let bft_committed_heights = 2u64;
        let bft_observed_heights = 5u64;
        let committed_height_rate_ppm =
            ratio_ppm_u64(bft_leader_missed_active_heights, bft_committed_heights);
        let observed_height_rate_ppm =
            ratio_ppm_u64(bft_leader_missed_active_heights, bft_observed_heights);

        assert_eq!(committed_height_rate_ppm, 1_000_000);
        assert_eq!(observed_height_rate_ppm, 400_000);
        assert!(observed_height_rate_ppm < committed_height_rate_ppm);
    }

    #[test]
    fn leader_missed_density_avg_milli_preserves_bursted_fairness_stall_signal() {
        let bft_leader_missed_total = 5u64;
        let bft_leader_missed_active_heights = 2u64;
        let bft_leader_missed_density_avg =
            bft_leader_missed_total / bft_leader_missed_active_heights;
        let bft_leader_missed_density_avg_milli =
            ratio_milli_u64(bft_leader_missed_total, bft_leader_missed_active_heights);

        assert_eq!(bft_leader_missed_density_avg, 2);
        assert_eq!(bft_leader_missed_density_avg_milli, 2_500);
        assert!(bft_leader_missed_density_avg_milli > bft_leader_missed_density_avg * 1_000);
    }

    #[test]
    fn leader_missed_metric_names_include_density_fields_for_active_height_bursts() {
        let density_field_name = "bft_leader_missed_density_avg";
        let milli_density_field_name = "bft_leader_missed_density_avg_milli";
        let active_height_share_field_name = "bft_leader_missed_active_height_share_ppm";
        let active_heights_field_name = "bft_leader_missed_active_heights";
        let active_observed_height_rate_field_name =
            "bft_leader_missed_active_observed_height_rate_ppm";

        assert!(density_field_name.ends_with("_avg"));
        assert!(milli_density_field_name.ends_with("_avg_milli"));
        assert!(active_height_share_field_name.ends_with("_share_ppm"));
        assert!(active_heights_field_name.ends_with("_heights"));
        assert!(active_observed_height_rate_field_name.ends_with("_rate_ppm"));
        assert_ne!(density_field_name, milli_density_field_name);
        assert_ne!(milli_density_field_name, active_height_share_field_name);
        assert_ne!(active_height_share_field_name, active_heights_field_name);
        assert_ne!(
            active_heights_field_name,
            active_observed_height_rate_field_name
        );
    }

    #[test]
    fn leader_missed_metric_names_keep_validator_spread_distinct_from_height_budget_pressure() {
        let active_validator_share_field_name = "bft_leader_missed_active_validator_share_ppm";
        let active_height_share_field_name = "bft_leader_missed_active_height_share_ppm";
        let density_field_name = "bft_leader_missed_density_avg_milli";
        let active_observed_height_rate_field_name =
            "bft_leader_missed_active_observed_height_rate_ppm";

        assert!(active_validator_share_field_name.ends_with("_share_ppm"));
        assert!(active_height_share_field_name.ends_with("_share_ppm"));
        assert!(density_field_name.ends_with("_avg_milli"));
        assert!(active_observed_height_rate_field_name.ends_with("_rate_ppm"));
        assert_ne!(
            active_validator_share_field_name,
            active_height_share_field_name
        );
        assert_ne!(active_validator_share_field_name, density_field_name);
        assert_ne!(
            active_height_share_field_name,
            active_observed_height_rate_field_name
        );
    }

    #[test]
    fn leader_missed_review_bundle_keeps_validator_spread_coverage_and_budget_views_together() {
        let fairness_review_fields = [
            "bft_leader_missed_top_share_ppm",
            "bft_leader_missed_active_validators",
            "bft_leader_missed_active_validator_share_ppm",
            "bft_leader_missed_active_heights",
            "bft_leader_missed_active_height_rate_ppm",
            "bft_leader_missed_active_observed_height_rate_ppm",
            "bft_leader_missed_density_avg_milli",
            "bft_leader_missed_active_height_share_ppm",
        ];

        assert_eq!(fairness_review_fields.len(), 8);
        assert!(fairness_review_fields[0].ends_with("_share_ppm"));
        assert!(fairness_review_fields[1].ends_with("_validators"));
        assert!(fairness_review_fields[2].ends_with("_share_ppm"));
        assert!(fairness_review_fields[3].ends_with("_heights"));
        assert!(fairness_review_fields[4].ends_with("_rate_ppm"));
        assert!(fairness_review_fields[5].ends_with("_rate_ppm"));
        assert!(fairness_review_fields[6].ends_with("_avg_milli"));
        assert!(fairness_review_fields[7].ends_with("_share_ppm"));
        assert_ne!(fairness_review_fields[2], fairness_review_fields[7]);
        assert_ne!(fairness_review_fields[4], fairness_review_fields[5]);
    }

    #[test]
    fn leader_missed_review_bundle_keeps_commit_skip_coverage_pair_near_fairness_hotspots() {
        let fairness_review_fields = [
            "bft_leader_missed_active_height_rate_ppm",
            "bft_leader_missed_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
            "bft_leader_missed_density_avg_milli",
            "bft_leader_missed_active_height_share_ppm",
        ];

        assert_eq!(fairness_review_fields.len(), 7);
        assert!(fairness_review_fields[0].ends_with("_rate_ppm"));
        assert!(fairness_review_fields[1].ends_with("_rate_ppm"));
        assert!(fairness_review_fields[2].ends_with("_rate_ppm"));
        assert!(fairness_review_fields[3].ends_with("_total"));
        assert!(fairness_review_fields[4].ends_with("_rate_ppm"));
        assert!(fairness_review_fields[5].ends_with("_avg_milli"));
        assert!(fairness_review_fields[6].ends_with("_share_ppm"));
        assert_ne!(fairness_review_fields[0], fairness_review_fields[1]);
        assert_ne!(fairness_review_fields[1], fairness_review_fields[2]);
        assert_ne!(fairness_review_fields[2], fairness_review_fields[4]);
        assert_ne!(fairness_review_fields[5], fairness_review_fields[6]);
    }

    #[test]
    fn leader_missed_metric_names_keep_validator_spread_coverage_and_budget_views_distinct() {
        let active_validators_field_name = "bft_leader_missed_active_validators";
        let active_validator_share_field_name = "bft_leader_missed_active_validator_share_ppm";
        let active_heights_field_name = "bft_leader_missed_active_heights";
        let active_height_rate_field_name = "bft_leader_missed_active_height_rate_ppm";
        let active_observed_height_rate_field_name =
            "bft_leader_missed_active_observed_height_rate_ppm";
        let density_avg_milli_field_name = "bft_leader_missed_density_avg_milli";
        let active_height_share_field_name = "bft_leader_missed_active_height_share_ppm";

        assert!(active_validators_field_name.ends_with("_validators"));
        assert!(active_validator_share_field_name.ends_with("_share_ppm"));
        assert!(active_heights_field_name.ends_with("_heights"));
        assert!(active_height_rate_field_name.ends_with("_rate_ppm"));
        assert!(active_observed_height_rate_field_name.ends_with("_rate_ppm"));
        assert!(density_avg_milli_field_name.ends_with("_avg_milli"));
        assert!(active_height_share_field_name.ends_with("_share_ppm"));
        assert_ne!(active_validators_field_name, active_heights_field_name);
        assert_ne!(
            active_validator_share_field_name,
            active_height_share_field_name
        );
        assert_ne!(
            active_height_rate_field_name,
            active_observed_height_rate_field_name
        );
        assert_ne!(density_avg_milli_field_name, active_height_share_field_name);
    }

    #[test]
    fn leader_missed_active_height_share_handles_zero_finality_budget() {
        let bft_leader_missed_density_avg_milli = 2_500u64;
        let finality_avg = 0u128;

        assert_eq!(
            finality_budget_share_ppm(bft_leader_missed_density_avg_milli, finality_avg),
            0
        );
    }

    #[test]
    fn leader_missed_active_height_share_can_exceed_budget_when_fairness_stalls_dominate() {
        let bft_leader_missed_density_avg_milli = 6_000u64;
        let finality_avg = 4u128;

        assert_eq!(
            finality_budget_share_ppm(bft_leader_missed_density_avg_milli, finality_avg),
            1_500_000
        );
    }

    #[test]
    fn leader_missed_hotspot_metrics_stay_visible_when_distribution_looks_benign() {
        let leader_missed_final = vec![2u64, 2u64, 1u64, 1u64];
        let bft_leader_missed_total: u64 = leader_missed_final.iter().copied().sum();
        let bft_leader_missed_max = leader_missed_final.iter().copied().max().unwrap_or(0);
        let bft_leader_missed_top_share_ppm =
            ratio_ppm_u64(bft_leader_missed_max, bft_leader_missed_total);
        let bft_leader_missed_active_validators = leader_missed_final
            .iter()
            .filter(|missed| **missed > 0)
            .count() as u64;
        let bft_leader_missed_active_validator_share_ppm = ratio_ppm_u64(
            bft_leader_missed_active_validators,
            leader_missed_final.len() as u64,
        );
        let bft_leader_missed_active_heights = 2u64;
        let bft_committed_heights = 6u64;
        let bft_observed_heights = 8u64;
        let finality_avg = 2u128;
        let bft_leader_missed_density_avg_milli =
            ratio_milli_u64(bft_leader_missed_total, bft_leader_missed_active_heights);
        let bft_leader_missed_active_height_rate_ppm =
            ratio_ppm_u64(bft_leader_missed_active_heights, bft_committed_heights);
        let bft_leader_missed_active_observed_height_rate_ppm =
            ratio_ppm_u64(bft_leader_missed_active_heights, bft_observed_heights);
        let bft_leader_missed_active_height_share_ppm =
            finality_budget_share_ppm(bft_leader_missed_density_avg_milli, finality_avg);

        assert_eq!(bft_leader_missed_total, 6);
        assert_eq!(bft_leader_missed_top_share_ppm, 333_333);
        assert_eq!(bft_leader_missed_active_validator_share_ppm, 1_000_000);
        assert_eq!(bft_leader_missed_active_height_rate_ppm, 333_333);
        assert_eq!(bft_leader_missed_active_observed_height_rate_ppm, 250_000);
        assert_eq!(bft_leader_missed_density_avg_milli, 3_000);
        assert_eq!(bft_leader_missed_active_height_share_ppm, 1_500_000);
        assert!(bft_leader_missed_active_height_share_ppm > 1_000_000);
        assert!(
            bft_leader_missed_top_share_ppm < 500_000
                && bft_leader_missed_active_validator_share_ppm == 1_000_000
        );
    }

    #[test]
    fn leader_missed_active_height_share_stays_distinct_from_validator_distribution_share() {
        let bft_leader_missed_total = 6u64;
        let bft_leader_missed_active_heights = 2u64;
        let bft_observed_heights = 8u64;
        let leader_missed_final = vec![2u64, 2u64, 1u64, 1u64];
        let finality_avg = 2u128;

        let bft_leader_missed_active_validator_share_ppm = ratio_ppm_u64(
            leader_missed_final
                .iter()
                .filter(|missed| **missed > 0)
                .count() as u64,
            leader_missed_final.len() as u64,
        );
        let bft_leader_missed_active_observed_height_rate_ppm =
            ratio_ppm_u64(bft_leader_missed_active_heights, bft_observed_heights);
        let bft_leader_missed_active_height_share_ppm = finality_budget_share_ppm(
            ratio_milli_u64(bft_leader_missed_total, bft_leader_missed_active_heights),
            finality_avg,
        );

        assert_eq!(bft_leader_missed_active_validator_share_ppm, 1_000_000);
        assert_eq!(bft_leader_missed_active_observed_height_rate_ppm, 250_000);
        assert_eq!(bft_leader_missed_active_height_share_ppm, 1_500_000);
        assert_ne!(
            bft_leader_missed_active_height_share_ppm,
            bft_leader_missed_active_validator_share_ppm
        );
        assert!(
            bft_leader_missed_active_height_share_ppm
                > bft_leader_missed_active_validator_share_ppm
        );
    }

    #[test]
    fn round_change_backoff_budget_share_metric_stays_distinct_from_wall_share_signal() {
        let bft_round_change_backoff_total_ms = 18u64;
        let bft_round_change_active_heights = 2u64;
        let bft_committed_heights = 4u64;
        let finality_avg = 36u128;

        let backoff_active_height_share_ppm = finality_budget_share_ppm(
            ratio_milli_u64(
                bft_round_change_backoff_total_ms,
                bft_round_change_active_heights,
            ),
            finality_avg,
        );
        let backoff_wall_share_ppm =
            ratio_ppm_u64(bft_round_change_backoff_total_ms, bft_committed_heights);

        assert_eq!(backoff_active_height_share_ppm, 250_000);
        assert_eq!(backoff_wall_share_ppm, 4_500_000);
        assert_ne!(backoff_active_height_share_ppm, backoff_wall_share_ppm);
    }

    #[test]
    fn round_change_backoff_active_height_rate_exposes_zero_backoff_round_change_gap() {
        let bft_round_change_active_heights = 3u64;
        let bft_round_change_backoff_active_heights = 2u64;
        let bft_committed_heights = 4u64;
        let bft_observed_heights = 5u64;

        let committed_height_rate_ppm = ratio_ppm_u64(
            bft_round_change_backoff_active_heights,
            bft_committed_heights,
        );
        let observed_height_rate_ppm = ratio_ppm_u64(
            bft_round_change_backoff_active_heights,
            bft_observed_heights,
        );

        assert_eq!(committed_height_rate_ppm, 500_000);
        assert_eq!(observed_height_rate_ppm, 400_000);
        assert!(bft_round_change_backoff_active_heights < bft_round_change_active_heights);
        assert!(observed_height_rate_ppm < committed_height_rate_ppm);
    }

    #[test]
    fn round_change_backoff_observed_coverage_stays_distinct_from_wall_share_alias() {
        let bft_round_change_backoff_total_ms = 12u64;
        let bft_round_change_backoff_active_heights = 2u64;
        let bft_committed_heights = 3u64;
        let bft_observed_heights = 5u64;
        let finality_avg = 8u128;

        let wall_share_ppm =
            ratio_ppm_u64(bft_round_change_backoff_total_ms, bft_committed_heights);
        let compatibility_alias_ppm = wall_share_ppm;
        let active_observed_height_rate_ppm = ratio_ppm_u64(
            bft_round_change_backoff_active_heights,
            bft_observed_heights,
        );
        let active_height_share_ppm = finality_budget_share_ppm(
            ratio_milli_u64(
                bft_round_change_backoff_total_ms,
                bft_round_change_backoff_active_heights,
            ),
            finality_avg,
        );

        assert_eq!(wall_share_ppm, 4_000_000);
        assert_eq!(compatibility_alias_ppm, wall_share_ppm);
        assert_eq!(active_observed_height_rate_ppm, 400_000);
        assert_eq!(active_height_share_ppm, 750_000);
        assert_ne!(active_observed_height_rate_ppm, compatibility_alias_ppm);
        assert_ne!(active_height_share_ppm, compatibility_alias_ppm);
        assert!(active_observed_height_rate_ppm < active_height_share_ppm);
    }

    #[test]
    fn round_change_backoff_coverage_pair_with_commit_and_skip_rates_exposes_denominator_shift() {
        let bft_round_change_backoff_active_heights = 2u64;
        let bft_committed_heights = 2u64;
        let bft_observed_heights = 5u64;
        let bft_skipped_height_total = bft_observed_heights - bft_committed_heights;

        let bft_round_change_backoff_active_height_rate_ppm = ratio_ppm_u64(
            bft_round_change_backoff_active_heights,
            bft_committed_heights,
        );
        let bft_round_change_backoff_active_observed_height_rate_ppm = ratio_ppm_u64(
            bft_round_change_backoff_active_heights,
            bft_observed_heights,
        );
        let bft_commit_observed_height_rate_ppm =
            ratio_ppm_u64(bft_committed_heights, bft_observed_heights);
        let bft_skipped_observed_height_rate_ppm =
            ratio_ppm_u64(bft_skipped_height_total, bft_observed_heights);

        assert_eq!(bft_round_change_backoff_active_height_rate_ppm, 1_000_000);
        assert_eq!(
            bft_round_change_backoff_active_observed_height_rate_ppm,
            400_000
        );
        assert_eq!(bft_commit_observed_height_rate_ppm, 400_000);
        assert_eq!(bft_skipped_observed_height_rate_ppm, 600_000);
        assert_eq!(
            bft_commit_observed_height_rate_ppm + bft_skipped_observed_height_rate_ppm,
            1_000_000
        );
        assert!(
            bft_round_change_backoff_active_observed_height_rate_ppm
                < bft_round_change_backoff_active_height_rate_ppm
        );
        assert_eq!(
            bft_round_change_backoff_active_observed_height_rate_ppm,
            bft_commit_observed_height_rate_ppm
        );
        assert!(bft_skipped_observed_height_rate_ppm > bft_commit_observed_height_rate_ppm);
    }

    #[test]
    fn round_change_backoff_active_height_metric_names_stay_distinct_from_round_change_coverage() {
        let round_change_active_heights_field_name = "bft_round_change_active_heights";
        let backoff_active_heights_field_name = "bft_round_change_backoff_active_heights";
        let backoff_active_height_rate_field_name =
            "bft_round_change_backoff_active_height_rate_ppm";
        let backoff_active_observed_height_rate_field_name =
            "bft_round_change_backoff_active_observed_height_rate_ppm";

        assert!(round_change_active_heights_field_name.ends_with("_heights"));
        assert!(backoff_active_heights_field_name.ends_with("_heights"));
        assert!(backoff_active_height_rate_field_name.ends_with("_rate_ppm"));
        assert!(backoff_active_observed_height_rate_field_name.ends_with("_rate_ppm"));
        assert_ne!(
            round_change_active_heights_field_name,
            backoff_active_heights_field_name
        );
        assert_ne!(
            backoff_active_heights_field_name,
            backoff_active_height_rate_field_name
        );
        assert_ne!(
            backoff_active_height_rate_field_name,
            backoff_active_observed_height_rate_field_name
        );
    }

    #[test]
    fn round_change_backoff_metric_names_keep_observed_coverage_distinct_from_wall_and_budget_views(
    ) {
        let active_observed_height_rate_field_name =
            "bft_round_change_backoff_active_observed_height_rate_ppm";
        let active_height_share_field_name = "bft_round_change_backoff_active_height_share_ppm";
        let wall_share_field_name = "bft_round_change_backoff_wall_share_ppm";
        let compatibility_alias_field_name = "bft_round_change_backoff_share_ppm";

        assert!(active_observed_height_rate_field_name.ends_with("_rate_ppm"));
        assert!(active_height_share_field_name.ends_with("_share_ppm"));
        assert!(wall_share_field_name.ends_with("_share_ppm"));
        assert!(compatibility_alias_field_name.ends_with("_share_ppm"));
        assert_ne!(
            active_observed_height_rate_field_name,
            active_height_share_field_name
        );
        assert_ne!(
            active_observed_height_rate_field_name,
            wall_share_field_name
        );
        assert_ne!(
            active_observed_height_rate_field_name,
            compatibility_alias_field_name
        );
    }

    #[test]
    fn round_change_backoff_share_metric_handles_empty_consensus_samples() {
        assert_eq!(ratio_ppm_u64(18, 0), 0);
        assert_eq!(ratio_ppm_u64(0, 0), 0);
    }

    #[test]
    fn round_change_density_avg_handles_empty_active_height_set() {
        let bft_round_change_total = 6u64;
        let bft_round_change_active_heights = 0u64;
        let bft_round_change_density_avg = if bft_round_change_active_heights == 0 {
            0
        } else {
            bft_round_change_total / bft_round_change_active_heights
        };

        assert_eq!(bft_round_change_density_avg, 0);
    }

    #[test]
    fn round_change_backoff_active_height_share_handles_zero_finality_budget() {
        let bft_round_change_backoff_density_avg_milli = 2_500u64;
        let finality_avg = 0u128;
        let backoff_active_height_share_ppm =
            finality_budget_share_ppm(bft_round_change_backoff_density_avg_milli, finality_avg);

        assert_eq!(backoff_active_height_share_ppm, 0);
    }

    #[test]
    fn round_change_backoff_active_height_share_can_exceed_budget_when_jitter_dominates() {
        let bft_round_change_backoff_density_avg_milli = 6_000u64;
        let finality_avg = 4u128;
        let backoff_active_height_share_ppm =
            finality_budget_share_ppm(bft_round_change_backoff_density_avg_milli, finality_avg);

        assert_eq!(backoff_active_height_share_ppm, 1_500_000);
        assert!(backoff_active_height_share_ppm > 1_000_000);
    }

    #[test]
    fn finality_budget_share_helper_matches_round_change_density_semantics() {
        let bft_round_change_density_avg_milli = 2_500u64;
        let finality_avg = 10u128;

        assert_eq!(
            finality_budget_share_ppm(bft_round_change_density_avg_milli, finality_avg),
            250_000
        );
    }

    #[test]
    fn round_change_active_height_share_handles_zero_finality_budget() {
        let bft_round_change_density_avg_milli = 2_500u64;
        let finality_avg = 0u128;

        assert_eq!(
            finality_budget_share_ppm(bft_round_change_density_avg_milli, finality_avg),
            0
        );
    }

    #[test]
    fn round_change_active_height_share_can_exceed_budget_when_jitter_dominates() {
        let bft_round_change_density_avg_milli = 6_000u64;
        let finality_avg = 4u128;

        assert_eq!(
            finality_budget_share_ppm(bft_round_change_density_avg_milli, finality_avg),
            1_500_000
        );
    }

    #[test]
    fn finality_budget_share_helper_saturates_huge_finality_budgets_without_overflow() {
        let bft_round_change_density_avg_milli = 2_500u64;
        let finality_avg = (u64::MAX as u128) + 1;

        assert_eq!(
            finality_budget_share_ppm(bft_round_change_density_avg_milli, finality_avg),
            0
        );
    }

    #[test]
    fn ratio_helpers_saturate_huge_metric_inputs_without_overflow() {
        assert_eq!(ratio_ppm_u64(u64::MAX, 1), u64::MAX);
        assert_eq!(ratio_milli_u64(u64::MAX, 1), u64::MAX);
        assert_eq!(ratio_percent_bps(u128::MAX, 1), u128::MAX);
        assert_eq!(ratio_ppm(u128::MAX, 1), u128::MAX);
    }

    #[test]
    fn critical_guard_critical_only_backlog_preserves_fifo_prefix_within_domain() {
        let mut mempool = VecDeque::from(vec![
            MockTx::Challenge {
                task_id: 41,
                challenger: "c1".into(),
                bond: 10,
            },
            MockTx::Resolve {
                task_id: 41,
                slash_worker: false,
                resolver: "gov".into(),
            },
            MockTx::Challenge {
                task_id: 42,
                challenger: "c2".into(),
                bond: 20,
            },
            MockTx::Resolve {
                task_id: 42,
                slash_worker: true,
                resolver: "gov".into(),
            },
        ]);

        let picked = pick_txs_with_critical_guard(&mut mempool, 2);
        assert_eq!(picked.len(), 2);
        assert!(matches!(picked[0], MockTx::Challenge { task_id: 41, .. }));
        assert!(matches!(picked[1], MockTx::Resolve { task_id: 41, .. }));

        assert_eq!(mempool.len(), 2);
        assert!(matches!(mempool[0], MockTx::Challenge { task_id: 42, .. }));
        assert!(matches!(mempool[1], MockTx::Resolve { task_id: 42, .. }));
    }

    #[test]
    fn critical_guard_full_queue_budget_keeps_mixed_backlog_fifo() {
        let mut mempool = VecDeque::from(vec![
            MockTx::CreateTask {
                task_id: 51,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::Challenge {
                task_id: 51,
                challenger: "c1".into(),
                bond: 10,
            },
            MockTx::AcceptTask {
                task_id: 51,
                worker: "w1".into(),
            },
        ]);

        // When the block budget can absorb the whole queue, the selector should
        // keep FIFO dequeue semantics even for mixed-class backlogs instead of
        // taking the fairness/reordering path unnecessarily.
        let picked = pick_txs_with_critical_guard(&mut mempool, 3);
        assert_eq!(picked.len(), 3);
        assert!(matches!(picked[0], MockTx::CreateTask { task_id: 51, .. }));
        assert!(matches!(picked[1], MockTx::Challenge { task_id: 51, .. }));
        assert!(matches!(picked[2], MockTx::AcceptTask { task_id: 51, .. }));
        assert!(mempool.is_empty());
    }

    #[test]
    fn critical_guard_selection_respects_lane_fairness_pop_order() {
        let mut mempool = VecDeque::from(vec![
            MockTx::CreateTask {
                task_id: 11,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::Challenge {
                task_id: 11,
                challenger: "c1".into(),
                bond: 10,
            },
            MockTx::Resolve {
                task_id: 11,
                slash_worker: false,
                resolver: "gov".into(),
            },
            MockTx::AcceptTask {
                task_id: 11,
                worker: "w1".into(),
            },
        ]);

        let picked = pick_txs_with_critical_guard(&mut mempool, 3);
        assert_eq!(picked.len(), 3);
        assert!(matches!(picked[0], MockTx::Challenge { .. }));
        assert!(matches!(picked[1], MockTx::CreateTask { .. }));
        assert!(matches!(picked[2], MockTx::Resolve { .. }));
    }

    #[test]
    fn critical_guard_only_reorders_scanned_prefix_and_leaves_suffix_fifo() {
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
        assert_eq!(picked.len(), 3);
        assert!(matches!(picked[0], MockTx::Challenge { .. }));
        assert!(matches!(picked[1], MockTx::CreateTask { task_id: 21, .. }));
        assert!(matches!(picked[2], MockTx::AcceptTask { .. }));

        assert_eq!(mempool.len(), 2);
        assert!(matches!(mempool[0], MockTx::Resolve { .. }));
        assert!(matches!(mempool[1], MockTx::CreateTask { task_id: 22, .. }));
    }

    #[test]
    fn critical_guard_single_slot_still_surfaces_tail_critical_domain_work() {
        let mut mempool = VecDeque::from(vec![
            MockTx::CreateTask {
                task_id: 31,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::AcceptTask {
                task_id: 31,
                worker: "w1".into(),
            },
            MockTx::CreateTask {
                task_id: 32,
                creator: "bob".into(),
                bounty: 20,
            },
            MockTx::Challenge {
                task_id: 31,
                challenger: "c1".into(),
                bond: 10,
            },
        ]);

        let picked = pick_txs_with_critical_guard(&mut mempool, 1);
        assert_eq!(picked.len(), 1);
        assert!(matches!(picked[0], MockTx::Challenge { task_id: 31, .. }));

        assert_eq!(mempool.len(), 3);
        assert!(matches!(mempool[0], MockTx::CreateTask { task_id: 31, .. }));
        assert!(matches!(mempool[1], MockTx::AcceptTask { task_id: 31, .. }));
        assert!(matches!(mempool[2], MockTx::CreateTask { task_id: 32, .. }));
    }

    #[test]
    fn backoff_is_capped() {
        assert_eq!(round_change_backoff_ms(0, 5, 40), 0);
        assert_eq!(round_change_backoff_ms(1, 5, 40), 5);
        assert_eq!(round_change_backoff_ms(2, 5, 40), 10);
        assert_eq!(round_change_backoff_ms(3, 5, 40), 20);
        assert_eq!(round_change_backoff_ms(4, 5, 40), 40);
        assert_eq!(round_change_backoff_ms(10, 5, 40), 40);
    }

    #[test]
    fn auth_rejects_zero_height_before_nonce_and_signature_checks() {
        let vote = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h1".into(),
            byzantine: false,
            height: 0,
            round: 0,
        };

        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        accept_signed_vote(
            SignedVote {
                vote: vote.clone(),
                nonce: 1,
                signature: vote_signature(&vote, 1),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert!(accepted.is_empty());
        assert_eq!(reject_stats.bad_sig, 1);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);
        assert!(last_nonce.is_empty());
    }

    #[test]
    fn auth_rejects_empty_validator_before_nonce_and_signature_checks() {
        let vote = BftVote {
            validator: "   ".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h1".into(),
            byzantine: false,
            height: 1,
            round: 0,
        };

        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        accept_signed_vote(
            SignedVote {
                vote: vote.clone(),
                nonce: 0,
                // even with nonce=0 and matching signature, ingress must reject empty validator first
                signature: vote_signature(&vote, 0),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert!(accepted.is_empty());
        assert_eq!(reject_stats.bad_sig, 1);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);
        assert!(last_nonce.is_empty());
    }

    #[test]
    fn auth_rejects_noncanonical_validator_before_nonce_and_signature_checks() {
        let vote = BftVote {
            validator: " v1 ".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h1".into(),
            byzantine: false,
            height: 1,
            round: 0,
        };

        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        accept_signed_vote(
            SignedVote {
                vote: vote.clone(),
                nonce: 0,
                signature: vote_signature(&vote, 0),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert!(accepted.is_empty());
        assert_eq!(reject_stats.bad_sig, 1);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);
        assert!(last_nonce.is_empty());
    }

    #[test]
    fn auth_rejects_uppercase_validator_before_nonce_and_signature_checks() {
        let vote = BftVote {
            validator: "V1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h1".into(),
            byzantine: false,
            height: 1,
            round: 0,
        };

        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        accept_signed_vote(
            SignedVote {
                vote: vote.clone(),
                nonce: 1,
                signature: vote_signature(&vote, 1),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert!(accepted.is_empty());
        assert_eq!(reject_stats.bad_sig, 1);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);
        assert!(last_nonce.is_empty());
    }

    #[test]
    fn auth_rejects_hyphen_only_validator_before_nonce_and_signature_checks() {
        let vote = BftVote {
            validator: "---".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h1".into(),
            byzantine: false,
            height: 1,
            round: 0,
        };

        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        accept_signed_vote(
            SignedVote {
                vote: vote.clone(),
                nonce: 1,
                signature: vote_signature(&vote, 1),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert!(accepted.is_empty());
        assert_eq!(reject_stats.bad_sig, 1);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);
        assert!(last_nonce.is_empty());
    }

    #[test]
    fn auth_rejects_edge_hyphen_validator_before_nonce_and_signature_checks() {
        for validator in ["-v1", "v1-"] {
            let vote = BftVote {
                validator: validator.into(),
                vote_type: VoteType::Prevote,
                block_hash: "h1".into(),
                byzantine: false,
                height: 1,
                round: 0,
            };

            let mut last_nonce = HashMap::new();
            let mut accepted = Vec::new();
            let mut reject_stats = AuthRejectStats::default();

            accept_signed_vote(
                SignedVote {
                    vote: vote.clone(),
                    nonce: 1,
                    signature: vote_signature(&vote, 1),
                },
                &mut last_nonce,
                &mut accepted,
                &mut reject_stats,
            );

            assert!(accepted.is_empty());
            assert_eq!(reject_stats.bad_sig, 1);
            assert_eq!(reject_stats.replay, 0);
            assert_eq!(reject_stats.stale_nonce, 0);
            assert!(last_nonce.is_empty());
        }
    }

    #[test]
    fn auth_rejects_consecutive_hyphen_validator_before_nonce_and_signature_checks() {
        let vote = BftVote {
            validator: "v1--worker".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h1".into(),
            byzantine: false,
            height: 1,
            round: 0,
        };

        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        accept_signed_vote(
            SignedVote {
                vote: vote.clone(),
                nonce: 1,
                signature: vote_signature(&vote, 1),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert!(accepted.is_empty());
        assert_eq!(reject_stats.bad_sig, 1);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);
        assert!(last_nonce.is_empty());
    }

    #[test]
    fn auth_rejects_hyphen_only_block_hash_before_nonce_and_signature_checks() {
        let vote = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "---".into(),
            byzantine: false,
            height: 1,
            round: 0,
        };

        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        accept_signed_vote(
            SignedVote {
                vote: vote.clone(),
                nonce: 1,
                signature: vote_signature(&vote, 1),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert!(accepted.is_empty());
        assert_eq!(reject_stats.bad_sig, 1);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);
        assert!(last_nonce.is_empty());
    }

    #[test]
    fn auth_rejects_edge_hyphen_block_hash_before_nonce_and_signature_checks() {
        for block_hash in ["-h1", "h1-"] {
            let vote = BftVote {
                validator: "v1".into(),
                vote_type: VoteType::Prevote,
                block_hash: block_hash.into(),
                byzantine: false,
                height: 1,
                round: 0,
            };

            let mut last_nonce = HashMap::new();
            let mut accepted = Vec::new();
            let mut reject_stats = AuthRejectStats::default();

            accept_signed_vote(
                SignedVote {
                    vote: vote.clone(),
                    nonce: 1,
                    signature: vote_signature(&vote, 1),
                },
                &mut last_nonce,
                &mut accepted,
                &mut reject_stats,
            );

            assert!(accepted.is_empty());
            assert_eq!(reject_stats.bad_sig, 1);
            assert_eq!(reject_stats.replay, 0);
            assert_eq!(reject_stats.stale_nonce, 0);
            assert!(last_nonce.is_empty());
        }
    }

    #[test]
    fn auth_rejects_consecutive_hyphen_block_hash_before_nonce_and_signature_checks() {
        let vote = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h1--fork".into(),
            byzantine: false,
            height: 1,
            round: 0,
        };

        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        accept_signed_vote(
            SignedVote {
                vote: vote.clone(),
                nonce: 1,
                signature: vote_signature(&vote, 1),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert!(accepted.is_empty());
        assert_eq!(reject_stats.bad_sig, 1);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);
        assert!(last_nonce.is_empty());
    }

    #[test]
    fn auth_rejects_overlong_validator_before_nonce_and_signature_checks() {
        let vote = BftVote {
            validator: "v".repeat(MAX_BFT_TOKEN_LEN + 1),
            vote_type: VoteType::Prevote,
            block_hash: "h1".into(),
            byzantine: false,
            height: 1,
            round: 0,
        };

        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        accept_signed_vote(
            SignedVote {
                vote: vote.clone(),
                nonce: 1,
                signature: vote_signature(&vote, 1),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert!(accepted.is_empty());
        assert_eq!(reject_stats.bad_sig, 1);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);
        assert!(last_nonce.is_empty());
    }

    #[test]
    fn auth_rejects_overlong_block_hash_before_nonce_and_signature_checks() {
        let vote = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h".repeat(MAX_BFT_TOKEN_LEN + 1),
            byzantine: false,
            height: 1,
            round: 0,
        };

        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        accept_signed_vote(
            SignedVote {
                vote: vote.clone(),
                nonce: 1,
                signature: vote_signature(&vote, 1),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert!(accepted.is_empty());
        assert_eq!(reject_stats.bad_sig, 1);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);
        assert!(last_nonce.is_empty());
    }

    #[test]
    fn auth_rejects_zero_nonce_vote_before_signature_check() {
        let vote = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h1".into(),
            byzantine: false,
            height: 1,
            round: 0,
        };

        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        accept_signed_vote(
            SignedVote {
                vote: vote.clone(),
                nonce: 0,
                // even with a syntactically valid signature for nonce=0, ingress must reject
                signature: vote_signature(&vote, 0),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert!(accepted.is_empty());
        assert_eq!(reject_stats.bad_sig, 0);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 1);
        assert!(last_nonce.is_empty());
    }

    #[test]
    fn auth_rejects_noncanonical_block_hash_before_nonce_and_signature_checks() {
        let vote = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: " h1 ".into(),
            byzantine: false,
            height: 1,
            round: 0,
        };

        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        accept_signed_vote(
            SignedVote {
                vote: vote.clone(),
                nonce: 0,
                // even with nonce=0 and matching signature, ingress must reject non-canonical hash first
                signature: vote_signature(&vote, 0),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert!(accepted.is_empty());
        assert_eq!(reject_stats.bad_sig, 1);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);
        assert!(last_nonce.is_empty());
    }

    #[test]
    fn auth_rejects_uppercase_block_hash_before_nonce_and_signature_checks() {
        let vote = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "A1b2".into(),
            byzantine: false,
            height: 1,
            round: 0,
        };

        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        accept_signed_vote(
            SignedVote {
                vote: vote.clone(),
                nonce: 1,
                // even with nonce>0 and matching signature, ingress must reject non-canonical hash first
                signature: vote_signature(&vote, 1),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert!(accepted.is_empty());
        assert_eq!(reject_stats.bad_sig, 1);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);
        assert!(last_nonce.is_empty());
    }

    #[test]
    fn auth_nonce_tracking_is_scoped_per_height() {
        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        let vote_h10 = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h10".into(),
            byzantine: false,
            height: 10,
            round: 0,
        };
        accept_signed_vote(
            SignedVote {
                vote: vote_h10.clone(),
                nonce: 9_999,
                signature: vote_signature(&vote_h10, 9_999),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        let vote_h11 = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h11".into(),
            byzantine: false,
            height: 11,
            round: 0,
        };
        accept_signed_vote(
            SignedVote {
                vote: vote_h11.clone(),
                nonce: 1,
                signature: vote_signature(&vote_h11, 1),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert_eq!(accepted.len(), 2);
        assert_eq!(reject_stats.bad_sig, 0);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);
    }

    #[test]
    fn auth_nonce_tracking_is_scoped_per_round() {
        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        let vote_r0 = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h10-r0".into(),
            byzantine: false,
            height: 10,
            round: 0,
        };
        accept_signed_vote(
            SignedVote {
                vote: vote_r0.clone(),
                nonce: 9_999,
                signature: vote_signature(&vote_r0, 9_999),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        let vote_r1 = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h10-r1".into(),
            byzantine: false,
            height: 10,
            round: 1,
        };
        accept_signed_vote(
            SignedVote {
                vote: vote_r1.clone(),
                nonce: 1,
                signature: vote_signature(&vote_r1, 1),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert_eq!(accepted.len(), 2);
        assert_eq!(reject_stats.bad_sig, 0);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);
    }

    #[test]
    fn auth_rejects_excessive_forward_nonce_jump_within_same_round_domain() {
        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        let vote1 = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h10-r0".into(),
            byzantine: false,
            height: 10,
            round: 0,
        };
        accept_signed_vote(
            SignedVote {
                vote: vote1.clone(),
                nonce: 10,
                signature: vote_signature(&vote1, 10),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        let vote2 = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h10-r0-alt".into(),
            byzantine: false,
            height: 10,
            round: 0,
        };
        let jumped_nonce = 10 + MAX_BFT_NONCE_FORWARD_JUMP + 1;
        accept_signed_vote(
            SignedVote {
                vote: vote2.clone(),
                nonce: jumped_nonce,
                signature: vote_signature(&vote2, jumped_nonce),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert_eq!(accepted.len(), 1);
        assert_eq!(reject_stats.bad_sig, 0);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 1);

        let key = ("v1".to_string(), 10, 0, VoteType::Prevote);
        assert_eq!(last_nonce.get(&key), Some(&10));
    }

    #[test]
    fn auth_accepts_forward_nonce_jump_at_boundary_within_same_round_domain() {
        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        let vote1 = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h10-r0".into(),
            byzantine: false,
            height: 10,
            round: 0,
        };
        accept_signed_vote(
            SignedVote {
                vote: vote1.clone(),
                nonce: 10,
                signature: vote_signature(&vote1, 10),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        let vote2 = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h10-r0-alt".into(),
            byzantine: false,
            height: 10,
            round: 0,
        };
        let boundary_nonce = 10 + MAX_BFT_NONCE_FORWARD_JUMP;
        accept_signed_vote(
            SignedVote {
                vote: vote2.clone(),
                nonce: boundary_nonce,
                signature: vote_signature(&vote2, boundary_nonce),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert_eq!(accepted.len(), 2);
        assert_eq!(reject_stats.bad_sig, 0);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);

        let key = ("v1".to_string(), 10, 0, VoteType::Prevote);
        assert_eq!(last_nonce.get(&key), Some(&boundary_nonce));
    }

    #[test]
    fn auth_rejects_first_nonce_bootstrap_jump_without_prior_domain_nonce() {
        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        let vote = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h11-r0".into(),
            byzantine: false,
            height: 11,
            round: 0,
        };
        let jumped_nonce = MAX_BFT_NONCE_FORWARD_JUMP + 1;
        accept_signed_vote(
            SignedVote {
                vote: vote.clone(),
                nonce: jumped_nonce,
                signature: vote_signature(&vote, jumped_nonce),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert_eq!(accepted.len(), 0);
        assert_eq!(reject_stats.bad_sig, 0);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 1);

        let key = ("v1".to_string(), 11, 0, VoteType::Prevote);
        assert_eq!(last_nonce.get(&key), None);
    }

    #[test]
    fn aggregate_votes_dedups_validator_duplicates_per_hash() {
        let votes = vec![
            BftVote {
                validator: "v1".into(),
                vote_type: VoteType::Prevote,
                block_hash: "h1".into(),
                byzantine: false,
                height: 7,
                round: 0,
            },
            // Same validator + same hash duplicate must not increase tally.
            BftVote {
                validator: "v1".into(),
                vote_type: VoteType::Prevote,
                block_hash: "h1".into(),
                byzantine: false,
                height: 7,
                round: 0,
            },
            BftVote {
                validator: "v2".into(),
                vote_type: VoteType::Prevote,
                block_hash: "h1".into(),
                byzantine: false,
                height: 7,
                round: 0,
            },
        ];

        let tally = aggregate_votes(&votes, VoteType::Prevote);
        assert_eq!(tally.get("h1"), Some(&2));
    }

    #[test]
    fn auth_nonce_tracking_is_scoped_per_vote_type() {
        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        let prevote = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h10-r0".into(),
            byzantine: false,
            height: 10,
            round: 0,
        };
        accept_signed_vote(
            SignedVote {
                vote: prevote.clone(),
                nonce: 10,
                signature: vote_signature(&prevote, 10),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        let precommit = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Precommit,
            block_hash: "h10-r0".into(),
            byzantine: false,
            height: 10,
            round: 0,
        };
        // Reusing a lower nonce across vote types must be accepted: replay domain is
        // (validator, height, round, vote_type), not a cross-type global counter.
        accept_signed_vote(
            SignedVote {
                vote: precommit.clone(),
                nonce: 1,
                signature: vote_signature(&precommit, 1),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert_eq!(accepted.len(), 2);
        assert_eq!(reject_stats.bad_sig, 0);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);
    }

    #[test]
    fn auth_rejects_same_nonce_equivocation_as_nonce_equivocation_not_replay() {
        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        let vote1 = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h10-r0-a".into(),
            byzantine: false,
            height: 10,
            round: 0,
        };
        let nonce = 77;
        accept_signed_vote(
            SignedVote {
                vote: vote1.clone(),
                nonce,
                signature: vote_signature(&vote1, nonce),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        let vote2 = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h10-r0-b".into(),
            byzantine: false,
            height: 10,
            round: 0,
        };
        accept_signed_vote(
            SignedVote {
                vote: vote2.clone(),
                nonce,
                signature: vote_signature(&vote2, nonce),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert_eq!(accepted.len(), 1);
        assert_eq!(reject_stats.bad_sig, 1);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);
        let key = ("v1".to_string(), 10, 0, VoteType::Prevote);
        assert_eq!(last_nonce.get(&key), Some(&nonce));
    }

    fn expected_high_risk_tx_exhaustive(tx: &MockTx) -> bool {
        // Exhaustive match intentionally used as a merge-gate guard:
        // if a new tx variant is introduced, this test must be reviewed.
        match tx {
            MockTx::CreateTask { .. }
            | MockTx::AcceptTask { .. }
            | MockTx::Commit { .. }
            | MockTx::Reveal { .. }
            | MockTx::Challenge { .. } => true,
            // Resolve performs terminal challenged escrow settlement and must stay
            // frozen while emergency pause is active.
            MockTx::Resolve { .. } => true,
        }
    }

    #[test]
    fn emergency_pause_gates_only_high_risk_tx_when_paused() {
        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let committed_hash = compute_commitment(1, &result_hash, &reveal_salt, "worker");

        let txs = [
            MockTx::CreateTask {
                task_id: 1,
                creator: "alice".into(),
                bounty: 100,
            },
            MockTx::AcceptTask {
                task_id: 1,
                worker: "worker".into(),
            },
            MockTx::Commit {
                task_id: 1,
                worker: "worker".into(),
                committed_hash,
            },
            MockTx::Reveal {
                task_id: 1,
                result_hash,
                reveal_salt,
            },
            MockTx::Challenge {
                task_id: 1,
                challenger: "challenger".into(),
                bond: 10,
            },
            MockTx::Resolve {
                task_id: 1,
                slash_worker: true,
                resolver: "governance.resolve_authority".into(),
            },
        ];

        for tx in &txs {
            assert_eq!(
                is_rejected_by_emergency_pause(true, tx),
                expected_high_risk_tx_exhaustive(tx),
                "pause gate drifted for tx variant while paused: {:?}",
                tx
            );
            assert!(
                !is_rejected_by_emergency_pause(false, tx),
                "pause gate unexpectedly active while unpaused for tx variant: {:?}",
                tx
            );
        }
    }

    #[test]
    fn emergency_pause_risk_gate_classification_is_stable() {
        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let committed_hash = compute_commitment(1, &result_hash, &reveal_salt, "worker");

        let txs = [
            MockTx::CreateTask {
                task_id: 1,
                creator: "alice".into(),
                bounty: 100,
            },
            MockTx::AcceptTask {
                task_id: 1,
                worker: "worker".into(),
            },
            MockTx::Commit {
                task_id: 1,
                worker: "worker".into(),
                committed_hash,
            },
            MockTx::Reveal {
                task_id: 1,
                result_hash,
                reveal_salt,
            },
            MockTx::Challenge {
                task_id: 1,
                challenger: "challenger".into(),
                bond: 10,
            },
            MockTx::Resolve {
                task_id: 1,
                slash_worker: true,
                resolver: "governance.resolve_authority".into(),
            },
        ];

        for tx in &txs {
            assert_eq!(
                is_high_risk_tx(tx),
                expected_high_risk_tx_exhaustive(tx),
                "pause risk gate drifted for tx variant: {:?}",
                tx
            );
        }
    }

    #[test]
    fn emergency_pause_rejection_formula_is_exact_boolean_gate() {
        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let committed_hash = compute_commitment(42, &result_hash, &reveal_salt, "worker");

        let txs = [
            MockTx::CreateTask {
                task_id: 42,
                creator: "alice".into(),
                bounty: 100,
            },
            MockTx::AcceptTask {
                task_id: 42,
                worker: "worker".into(),
            },
            MockTx::Commit {
                task_id: 42,
                worker: "worker".into(),
                committed_hash,
            },
            MockTx::Reveal {
                task_id: 42,
                result_hash,
                reveal_salt,
            },
            MockTx::Challenge {
                task_id: 42,
                challenger: "challenger".into(),
                bond: 10,
            },
            MockTx::Resolve {
                task_id: 42,
                slash_worker: false,
                resolver: "governance.resolve_authority".into(),
            },
        ];

        for tx in &txs {
            for paused in [false, true] {
                assert_eq!(
                    is_rejected_by_emergency_pause(paused, tx),
                    paused && is_high_risk_tx(tx),
                    "emergency pause formula drifted: paused={} tx={:?}",
                    paused,
                    tx
                );
            }
        }
    }

    #[test]
    fn proposer_selection_skips_penalized_or_missed_leader() {
        let control = BftJitterControl {
            missed_threshold: 2,
            penalty_rounds: 2,
            round_change_backoff_ms: 5,
            round_change_backoff_cap_ms: 40,
            leader_health: vec![
                LeaderHealth {
                    missed_proposals: 3,
                    penalty_until_round: 5,
                },
                LeaderHealth::default(),
                LeaderHealth::default(),
                LeaderHealth::default(),
            ],
        };

        let (idx, shifted) = select_proposer(1, 1, &control, 4); // base proposer is v3(index=2)
        assert_eq!(idx, 2);
        assert!(!shifted);

        let (idx2, shifted2) = select_proposer(4, 0, &control, 4); // base proposer is v1(index=0), should be skipped
        assert_eq!(idx2, 1);
        assert!(shifted2);
    }

    fn challenged_task_fixture(
        st: &mut StateStore,
        task_id: u64,
    ) -> (ObjectRef, [u8; 32], [u8; 32]) {
        st.set_balance("challenger", 1_000_000);
        st.set_balance(&format!("worker{}", task_id), 1_000);
        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let committed = compute_commitment(
            task_id,
            &result_hash,
            &reveal_salt,
            &format!("worker{}", task_id),
        );
        let r1 = apply_create_task(st, task_id, "alice".into(), 100).unwrap();
        let r2 = apply_accept_task(st, r1, format!("worker{}", task_id)).unwrap();
        let r3 = trnm_pouw::apply_commit_result_at_height(
            st,
            r2,
            format!("worker{}", task_id),
            committed,
            100,
        )
        .unwrap();
        let r4 =
            trnm_pouw::apply_reveal_result_at_height(st, r3, result_hash, reveal_salt, None, 110)
                .unwrap();
        let r5 = trnm_pouw::apply_challenge_at_height(
            st,
            r4,
            "challenger".into(),
            10,
            "challenger".into(),
            120,
        )
        .unwrap();
        (r5, result_hash, reveal_salt)
    }

    #[test]
    fn rollback_snapshot_restores_task_balances_and_pending_resolve_state() {
        let mut st = StateStore::new();
        st.set_gov_param_bootstrap_unchecked(
            9_499,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .unwrap();
        let _ = challenged_task_fixture(&mut st, 8100);
        let current_task_version = st
            .get_task(8100)
            .expect("challenged task must exist before staging approval")
            .version;
        st.stage_or_confirm_resolve_approval(
            8100,
            current_task_version,
            true,
            "authority-a",
            "authority-a,authority-b",
        )
        .unwrap();
        let before_task = st.get_task(8100).unwrap();
        let before_worker = st.balance_of("worker8100");
        let before_challenger = st.balance_of("challenger");
        let before_escrow = st.balance_of("treasury.challenge_escrow");
        let before_pending = st.pending_resolve_approval_snapshot(8100);

        let snapshot = capture_rollback_snapshot(
            &st,
            &MockTx::Resolve {
                task_id: 8100,
                slash_worker: true,
                resolver: "authority-b".into(),
            },
        );

        st.set_balance("worker8100", 0);
        st.set_balance("challenger", 0);
        st.set_balance("treasury.challenge_escrow", 0);
        let mut mutated_task = before_task.clone();
        mutated_task.status = TaskStatus::Completed;
        mutated_task.version += 1;
        st.restore_task(8100, Some(mutated_task));
        st.clear_pending_resolve_approval(8100);

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8100).unwrap(), before_task);
        assert_eq!(st.balance_of("worker8100"), before_worker);
        assert_eq!(st.balance_of("challenger"), before_challenger);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(st.pending_resolve_approval_snapshot(8100), before_pending);
    }

    #[test]
    fn rollback_snapshot_restores_pending_resolve_state_against_pending_replacement_authority() {
        let mut st = StateStore::new();
        let bootstrap = st
            .set_gov_param(
                98_160,
                7_310,
                "resolve_authority".into(),
                "authority-a,authority-b".into(),
            )
            .expect("bootstrap resolve_authority write should succeed");
        assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
        let applied = st
            .set_gov_param(
                98_180,
                7_310,
                "resolve_authority".into(),
                "authority-a,authority-b".into(),
            )
            .expect("bootstrap resolve_authority should apply after timelock");
        assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

        let replacement = st
            .set_gov_param(
                98_181,
                7_310,
                "resolve_authority".into(),
                "authority-c,authority-d".into(),
            )
            .expect("replacement resolve_authority update should be scheduled");
        assert!(matches!(
            replacement,
            GovParamUpdateOutcome::Scheduled { .. }
        ));

        let _ = challenged_task_fixture(&mut st, 8_109);
        let before_task = st.get_task(8_109).unwrap();
        let before_escrow = st.balance_of("treasury.challenge_escrow");

        let snapshot = TxRollbackSnapshot {
            task_id: 8_109,
            task: Some(before_task.clone()),
            balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
            pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-c".into(),
                authority_set: "authority-c,authority-d".into(),
                task_version: before_task.version,
            }),
        };

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8_109).unwrap(), before_task);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(st.pending_resolve_approval(8_109), Some((true, 1)));
        assert_eq!(
            st.pending_resolve_first_approver(8_109).as_deref(),
            Some("authority-c")
        );
        assert_eq!(
            st.pending_resolve_approval_snapshot(8_109),
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-c".into(),
                authority_set: "authority-c,authority-d".into(),
                task_version: before_task.version,
            })
        );
    }

    #[test]
    fn rollback_snapshot_restores_case_and_order_equivalent_pending_replacement_authority_while_paused(
    ) {
        let mut st = StateStore::new();
        let bootstrap = st
            .set_gov_param(
                98_283,
                7_310,
                "resolve_authority".into(),
                "authority-a,authority-b".into(),
            )
            .expect("bootstrap resolve_authority write should succeed");
        assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
        let applied = st
            .set_gov_param(
                98_303,
                7_310,
                "resolve_authority".into(),
                "authority-a,authority-b".into(),
            )
            .expect("bootstrap resolve_authority should apply after timelock");
        assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

        let replacement = st
            .set_gov_param(
                98_304,
                7_310,
                "resolve_authority".into(),
                "authority-c,authority-d".into(),
            )
            .expect("replacement resolve_authority update should be scheduled");
        assert!(matches!(
            replacement,
            GovParamUpdateOutcome::Scheduled { .. }
        ));

        let _ = challenged_task_fixture(&mut st, 8_115);
        st.set_gov_param(98_305, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause toggle must apply immediately");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_115).unwrap();
        let before_escrow = st.balance_of("treasury.challenge_escrow");
        let before_forfeits = st.balance_of("treasury.challenge_forfeits");
        let before_slashes = st.balance_of("treasury.worker_slashes");

        let snapshot = TxRollbackSnapshot {
            task_id: 8_115,
            task: Some(before_task.clone()),
            balances: vec![
                ("treasury.challenge_escrow".into(), Some(before_escrow)),
                ("treasury.challenge_forfeits".into(), Some(before_forfeits)),
                ("treasury.worker_slashes".into(), Some(before_slashes)),
            ],
            pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
                slash_worker: false,
                confirmations: 1,
                first_approver: "Authority-D".into(),
                authority_set: "Authority-D,Authority-C".into(),
                task_version: before_task.version,
            }),
        };

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8_115).unwrap(), before_task);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(
            st.balance_of("treasury.challenge_forfeits"),
            before_forfeits
        );
        assert_eq!(st.balance_of("treasury.worker_slashes"), before_slashes);
        assert_eq!(st.pending_resolve_approval(8_115), Some((false, 1)));
        assert_eq!(
            st.pending_resolve_first_approver(8_115).as_deref(),
            Some("authority-d")
        );
        assert_eq!(
            st.pending_resolve_approval_snapshot(8_115),
            Some(PendingResolveApprovalSnapshot {
                slash_worker: false,
                confirmations: 1,
                first_approver: "authority-d".into(),
                authority_set: "authority-c,authority-d".into(),
                task_version: before_task.version,
            })
        );
        let pending = st
            .pending_gov_update("resolve_authority")
            .expect("pending replacement resolve_authority timelock should remain staged");
        assert_eq!(pending.value, "authority-c,authority-d");
        assert_eq!(
            st.gov_param_string("resolve_authority"),
            Some("authority-a,authority-b".into()),
            "rollback restore must preserve the active configured authority until the replacement matures"
        );
        assert!(st.is_emergency_paused());
    }

    #[test]
    fn rollback_snapshot_scrubs_exact_emergency_pause_placeholder_second_approver_against_pending_replacement_authority_while_paused(
    ) {
        let mut st = StateStore::new();
        let bootstrap = st
            .set_gov_param(
                98_360,
                7_310,
                "resolve_authority".into(),
                "authority-a,authority-b".into(),
            )
            .expect("bootstrap resolve_authority write should succeed");
        assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
        let applied = st
            .set_gov_param(
                98_380,
                7_310,
                "resolve_authority".into(),
                "authority-a,authority-b".into(),
            )
            .expect("bootstrap resolve_authority should apply after timelock");
        assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

        let replacement = st
            .set_gov_param(
                98_381,
                7_310,
                "resolve_authority".into(),
                "authority-c,authority-d".into(),
            )
            .expect("replacement resolve_authority update should be scheduled");
        assert!(matches!(
            replacement,
            GovParamUpdateOutcome::Scheduled { .. }
        ));

        let _ = challenged_task_fixture(&mut st, 8_116);

        st.set_gov_param(98_382, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause toggle must apply immediately");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_116).unwrap();
        let before_escrow = st.balance_of("treasury.challenge_escrow");
        let before_forfeits = st.balance_of("treasury.challenge_forfeits");
        let before_slashes = st.balance_of("treasury.worker_slashes");

        let snapshot = TxRollbackSnapshot {
            task_id: 8_116,
            task: Some(before_task.clone()),
            balances: vec![
                ("treasury.challenge_escrow".into(), Some(before_escrow)),
                ("treasury.challenge_forfeits".into(), Some(before_forfeits)),
                ("treasury.worker_slashes".into(), Some(before_slashes)),
            ],
            pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 2,
                first_approver: "authority-c".into(),
                authority_set: "authority-c,authority-d".into(),
                task_version: before_task.version,
            }),
        };

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8_116).unwrap(), before_task);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(
            st.balance_of("treasury.challenge_forfeits"),
            before_forfeits
        );
        assert_eq!(st.balance_of("treasury.worker_slashes"), before_slashes);
        assert_eq!(st.pending_resolve_approval(8_116), None);
        assert_eq!(st.pending_resolve_first_approver(8_116), None);
        assert_eq!(st.pending_resolve_approval_snapshot(8_116), None);
        let pending = st
            .pending_gov_update("resolve_authority")
            .expect("pending replacement resolve_authority timelock should remain staged");
        assert_eq!(pending.value, "authority-c,authority-d");
        assert_eq!(
            st.gov_param_string("resolve_authority"),
            Some("authority-a,authority-b".into()),
            "rollback scrub must not mutate the active configured authority while the replacement stays pending"
        );
        assert!(st.is_emergency_paused());
    }

    #[test]
    fn rollback_snapshot_scrubs_exact_emergency_pause_placeholder_first_approver_against_pending_replacement_authority_while_paused(
    ) {
        let mut st = StateStore::new();
        let bootstrap = st
            .set_gov_param(
                98_384,
                7_310,
                "resolve_authority".into(),
                "authority-a,authority-b".into(),
            )
            .expect("bootstrap resolve_authority write should succeed");
        assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
        let applied = st
            .set_gov_param(
                98_404,
                7_310,
                "resolve_authority".into(),
                "authority-a,authority-b".into(),
            )
            .expect("bootstrap resolve_authority should apply after timelock");
        assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

        let replacement = st
            .set_gov_param(
                98_405,
                7_310,
                "resolve_authority".into(),
                "authority-c,authority-d".into(),
            )
            .expect("replacement resolve_authority update should be scheduled");
        assert!(matches!(
            replacement,
            GovParamUpdateOutcome::Scheduled { .. }
        ));

        let _ = challenged_task_fixture(&mut st, 8_117);

        st.set_gov_param(98_406, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause toggle must apply immediately");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_117).unwrap();
        let before_escrow = st.balance_of("treasury.challenge_escrow");
        let before_forfeits = st.balance_of("treasury.challenge_forfeits");
        let before_slashes = st.balance_of("treasury.worker_slashes");

        let snapshot = TxRollbackSnapshot {
            task_id: 8_117,
            task: Some(before_task.clone()),
            balances: vec![
                ("treasury.challenge_escrow".into(), Some(before_escrow)),
                ("treasury.challenge_forfeits".into(), Some(before_forfeits)),
                ("treasury.worker_slashes".into(), Some(before_slashes)),
            ],
            pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "governance.emergency_pause".into(),
                authority_set: "authority-c,authority-d".into(),
                task_version: before_task.version,
            }),
        };

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8_117).unwrap(), before_task);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(
            st.balance_of("treasury.challenge_forfeits"),
            before_forfeits
        );
        assert_eq!(st.balance_of("treasury.worker_slashes"), before_slashes);
        assert_eq!(st.pending_resolve_approval(8_117), None);
        assert_eq!(st.pending_resolve_first_approver(8_117), None);
        assert_eq!(st.pending_resolve_approval_snapshot(8_117), None);
        let pending = st
            .pending_gov_update("resolve_authority")
            .expect("pending replacement resolve_authority timelock should remain staged");
        assert_eq!(pending.value, "authority-c,authority-d");
        assert_eq!(
            st.gov_param_string("resolve_authority"),
            Some("authority-a,authority-b".into()),
            "rollback scrub must not mutate the active configured authority while the replacement stays pending"
        );
        assert!(st.is_emergency_paused());
    }

    #[test]
    fn rollback_snapshot_scrubs_stale_configured_resolve_state_when_pending_replacement_exists() {
        let mut st = StateStore::new();
        let bootstrap = st
            .set_gov_param(
                98_260,
                7_310,
                "resolve_authority".into(),
                "authority-a,authority-b".into(),
            )
            .expect("bootstrap resolve_authority write should succeed");
        assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
        let applied = st
            .set_gov_param(
                98_280,
                7_310,
                "resolve_authority".into(),
                "authority-a,authority-b".into(),
            )
            .expect("bootstrap resolve_authority should apply after timelock");
        assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

        let replacement = st
            .set_gov_param(
                98_281,
                7_310,
                "resolve_authority".into(),
                "authority-c,authority-d".into(),
            )
            .expect("replacement resolve_authority update should be scheduled");
        assert!(matches!(
            replacement,
            GovParamUpdateOutcome::Scheduled { .. }
        ));

        let _ = challenged_task_fixture(&mut st, 8_114);

        st.set_gov_param(98_282, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause toggle must apply immediately");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_114).unwrap();
        let before_escrow = st.balance_of("treasury.challenge_escrow");
        let before_forfeits = st.balance_of("treasury.challenge_forfeits");
        let before_slashes = st.balance_of("treasury.worker_slashes");

        let snapshot = TxRollbackSnapshot {
            task_id: 8_114,
            task: Some(before_task.clone()),
            balances: vec![
                ("treasury.challenge_escrow".into(), Some(before_escrow)),
                ("treasury.challenge_forfeits".into(), Some(before_forfeits)),
                ("treasury.worker_slashes".into(), Some(before_slashes)),
            ],
            pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: before_task.version,
            }),
        };

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8_114).unwrap(), before_task);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(
            st.balance_of("treasury.challenge_forfeits"),
            before_forfeits
        );
        assert_eq!(st.balance_of("treasury.worker_slashes"), before_slashes);
        assert_eq!(st.pending_resolve_approval(8_114), None);
        assert_eq!(st.pending_resolve_first_approver(8_114), None);
        assert_eq!(st.pending_resolve_approval_snapshot(8_114), None);
        let pending = st
            .pending_gov_update("resolve_authority")
            .expect("pending replacement resolve_authority timelock should remain staged");
        assert_eq!(pending.value, "authority-c,authority-d");
        assert_eq!(
            st.gov_param_string("resolve_authority"),
            Some("authority-a,authority-b".into()),
            "rollback scrub must not mutate the active configured authority set"
        );
        assert!(st.is_emergency_paused());
    }

    #[test]
    fn rollback_snapshot_scrubs_invalid_pending_resolve_state() {
        let mut st = StateStore::new();
        let _ = challenged_task_fixture(&mut st, 8_110);
        let before_task = st.get_task(8_110).unwrap();
        let before_escrow = st.balance_of("treasury.challenge_escrow");

        let snapshot = TxRollbackSnapshot {
            task_id: 8_110,
            task: Some(before_task.clone()),
            balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
            pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 3,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: before_task.version,
            }),
        };

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8_110).unwrap(), before_task);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(
            st.pending_resolve_approval(8_110),
            None,
            "rollback must not revive malformed pending resolve quorum state"
        );
    }

    #[test]
    fn rollback_snapshot_scrubs_pending_resolve_state_when_task_version_drifts() {
        let mut st = StateStore::new();
        st.set_gov_param_bootstrap_unchecked(
            9_501,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .unwrap();
        let _ = challenged_task_fixture(&mut st, 8_111);
        let before_task = st.get_task(8_111).unwrap();
        let before_escrow = st.balance_of("treasury.challenge_escrow");

        let snapshot = TxRollbackSnapshot {
            task_id: 8_111,
            task: Some(before_task.clone()),
            balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
            pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: before_task.version + 1,
            }),
        };

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8_111).unwrap(), before_task);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(
            st.pending_resolve_approval(8_111),
            None,
            "rollback must not revive staged resolve quorum for a stale task version"
        );
    }

    #[test]
    fn rollback_snapshot_scrubs_finalized_pending_resolve_snapshot_missing_second_approver() {
        let mut st = StateStore::new();
        let _ = challenged_task_fixture(&mut st, 8_112);
        let before_task = st.get_task(8_112).unwrap();
        let before_escrow = st.balance_of("treasury.challenge_escrow");

        let snapshot = TxRollbackSnapshot {
            task_id: 8_112,
            task: Some(before_task.clone()),
            balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
            pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 2,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: before_task.version,
            }),
        };

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8_112).unwrap(), before_task);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(
            st.pending_resolve_approval(8_112),
            None,
            "rollback must not revive finalized resolve quorum without a distinct second approver audit trail"
        );
    }

    #[test]
    fn rollback_snapshot_scrubs_pending_resolve_snapshot_with_forbidden_approver_separator() {
        let mut st = StateStore::new();
        let _ = challenged_task_fixture(&mut st, 8_111);
        let before_task = st.get_task(8_111).unwrap();
        let before_escrow = st.balance_of("treasury.challenge_escrow");

        let snapshot = TxRollbackSnapshot {
            task_id: 8_111,
            task: Some(before_task.clone()),
            balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
            pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority|a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: before_task.version,
            }),
        };

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8_111).unwrap(), before_task);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(
            st.pending_resolve_approval(8_111),
            None,
            "rollback must scrub snapshot approvers that live parsing would reject"
        );
    }

    #[test]
    fn rollback_snapshot_scrubs_pending_resolve_snapshot_with_forbidden_authority_separator() {
        let mut st = StateStore::new();
        st.set_gov_param_bootstrap_unchecked(
            9_502,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .unwrap();
        let _ = challenged_task_fixture(&mut st, 8_112);
        let before_task = st.get_task(8_112).unwrap();
        let before_escrow = st.balance_of("treasury.challenge_escrow");

        let snapshot = TxRollbackSnapshot {
            task_id: 8_112,
            task: Some(before_task.clone()),
            balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
            pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a；authority-b".into(),
                task_version: before_task.version,
            }),
        };

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8_112).unwrap(), before_task);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(
            st.pending_resolve_approval(8_112),
            None,
            "rollback must scrub authority snapshots with forbidden separators before replay"
        );
    }

    #[test]
    fn rollback_snapshot_scrubs_pending_resolve_snapshot_with_whitespace_padded_first_approver() {
        let mut st = StateStore::new();
        st.set_gov_param_bootstrap_unchecked(
            9_505,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .unwrap();
        let _ = challenged_task_fixture(&mut st, 8_115);
        let before_task = st.get_task(8_115).unwrap();
        let before_escrow = st.balance_of("treasury.challenge_escrow");

        let snapshot = TxRollbackSnapshot {
            task_id: 8_115,
            task: Some(before_task.clone()),
            balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
            pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: " authority-a ".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: before_task.version,
            }),
        };

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8_115).unwrap(), before_task);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(
            st.pending_resolve_approval(8_115),
            None,
            "rollback must scrub whitespace-padded approvers instead of silently normalizing them"
        );
        assert_eq!(st.pending_resolve_first_approver(8_115), None);
        assert_eq!(st.pending_resolve_approval_snapshot(8_115), None);
    }

    #[test]
    fn rollback_snapshot_scrubs_pending_resolve_snapshot_with_case_folded_duplicate_authorities() {
        let mut st = StateStore::new();
        st.set_gov_param_bootstrap_unchecked(
            9_503,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .unwrap();
        let _ = challenged_task_fixture(&mut st, 8_113);
        let before_task = st.get_task(8_113).unwrap();
        let before_escrow = st.balance_of("treasury.challenge_escrow");

        let snapshot = TxRollbackSnapshot {
            task_id: 8_113,
            task: Some(before_task.clone()),
            balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
            pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "Authority-A,authority-a".into(),
                task_version: before_task.version,
            }),
        };

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8_113).unwrap(), before_task);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(
            st.pending_resolve_approval(8_113),
            None,
            "rollback must reject case-folded duplicate authority members during replay"
        );
    }

    #[test]
    fn rollback_snapshot_scrubs_finalized_pending_resolve_snapshot_with_case_variant_duplicate_second_approver(
    ) {
        let mut st = StateStore::new();
        let _ = challenged_task_fixture(&mut st, 8_113);
        let before_task = st.get_task(8_113).unwrap();
        let before_escrow = st.balance_of("treasury.challenge_escrow");

        let snapshot = TxRollbackSnapshot {
            task_id: 8_113,
            task: Some(before_task.clone()),
            balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
            pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 2,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: before_task.version,
            }),
        };

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8_113).unwrap(), before_task);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(
            st.pending_resolve_approval(8_113),
            None,
            "rollback must not revive finalized resolve quorum with a case-variant duplicate second approver"
        );
        assert_eq!(st.pending_resolve_first_approver(8_113), None);
        assert_eq!(st.pending_resolve_approval_snapshot(8_113), None);
    }

    #[test]
    fn node_resolve_multisig_first_approval_persists_and_second_finalizes() {
        let mut st = StateStore::new();
        st.set_gov_param_bootstrap_unchecked(
            9_500,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .unwrap();
        let (r5, _, _) = challenged_task_fixture(&mut st, 8101);

        let first = apply_one(
            &mut st,
            MockTx::Resolve {
                task_id: r5.id,
                slash_worker: true,
                resolver: "authority-a".into(),
            },
            130,
        );
        assert!(matches!(
            first.unwrap_err().downcast::<trnm_pouw::PouwError>(),
            Ok(trnm_pouw::PouwError::ResolveApprovalStaged)
        ));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));
        assert_eq!(st.get_task(r5.id).unwrap().status, TaskStatus::Challenged);

        apply_one(
            &mut st,
            MockTx::Resolve {
                task_id: r5.id,
                slash_worker: true,
                resolver: "authority-b".into(),
            },
            131,
        )
        .expect("second signer should finalize through node-facing path");
        assert_eq!(st.pending_resolve_approval(r5.id), None);
        assert_eq!(st.get_task(r5.id).unwrap().status, TaskStatus::Slashed);
        assert!(st.get_ref(r5.id).unwrap().version > r5.version);
    }

    #[test]
    fn paused_node_gate_skips_second_multisig_resolve_without_mutating_staged_or_escrow_state() {
        let mut st = StateStore::new();
        st.set_gov_param_bootstrap_unchecked(
            9_500,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .unwrap();
        let (r5, _, _) = challenged_task_fixture(&mut st, 8109);

        let first = apply_one(
            &mut st,
            MockTx::Resolve {
                task_id: r5.id,
                slash_worker: true,
                resolver: "authority-a".into(),
            },
            130,
        );
        assert!(matches!(
            first.unwrap_err().downcast::<trnm_pouw::PouwError>(),
            Ok(trnm_pouw::PouwError::ResolveApprovalStaged)
        ));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

        st.set_gov_param(9_999, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause toggle must apply immediately");
        assert!(st.is_emergency_paused());

        let paused_tx = MockTx::Resolve {
            task_id: r5.id,
            slash_worker: true,
            resolver: "authority-b".into(),
        };
        assert!(is_rejected_by_emergency_pause(true, &paused_tx));

        let task_before = st.get_task(r5.id).expect("challenged task must exist");
        let pending_before = st.pending_resolve_approval(r5.id);
        let first_approver_before = st.pending_resolve_first_approver(r5.id);
        let escrow_before = st.balance_of("treasury.challenge_escrow");
        let forfeit_before = st.balance_of("treasury.challenge_forfeits");

        // Commit-loop behavior under pause is to reject/skip high-risk tx before apply_one.
        if !is_rejected_by_emergency_pause(st.is_emergency_paused(), &paused_tx) {
            let _ = apply_one(&mut st, paused_tx, 131);
        }

        assert_eq!(
            st.pending_resolve_approval(r5.id),
            pending_before,
            "pause gate must preserve previously staged multisig approval"
        );
        assert_eq!(
            st.pending_resolve_first_approver(r5.id),
            first_approver_before,
            "pause gate must preserve staged first approver identity"
        );
        assert_eq!(
            st.get_task(r5.id).expect("task should remain challenged"),
            task_before
        );
        assert_eq!(st.balance_of("treasury.challenge_escrow"), escrow_before);
        assert_eq!(st.balance_of("treasury.challenge_forfeits"), forfeit_before);
    }

    #[test]
    fn paused_node_gate_skips_version_drift_resolve_replay_without_clearing_staged_quorum() {
        let mut st = StateStore::new();
        st.set_gov_param_bootstrap_unchecked(
            9_500,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .unwrap();
        let (r5, _, _) = challenged_task_fixture(&mut st, 8_109_2);

        let first = apply_one(
            &mut st,
            MockTx::Resolve {
                task_id: r5.id,
                slash_worker: true,
                resolver: "authority-a".into(),
            },
            130,
        );
        assert!(matches!(
            first.unwrap_err().downcast::<trnm_pouw::PouwError>(),
            Ok(trnm_pouw::PouwError::ResolveApprovalStaged)
        ));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));
        assert_eq!(
            st.pending_resolve_first_approver(r5.id).as_deref(),
            Some("authority-a")
        );

        st.set_gov_param(9_999, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause toggle must apply immediately");
        assert!(st.is_emergency_paused());

        let mut task_before = st.get_task(r5.id).expect("challenged task must exist");
        task_before.version += 1;
        st.restore_task(r5.id, Some(task_before.clone()));

        let paused_tx = MockTx::Resolve {
            task_id: r5.id,
            slash_worker: true,
            resolver: "authority-b".into(),
        };
        assert!(is_rejected_by_emergency_pause(true, &paused_tx));

        let pending_before = st.pending_resolve_approval_snapshot(r5.id);
        let escrow_before = st.balance_of("treasury.challenge_escrow");
        let forfeit_before = st.balance_of("treasury.challenge_forfeits");

        // If this replay reached apply_one after the challenged task version moved forward,
        // resolve quorum staging would be cleared as stale. Emergency pause must block the tx
        // before it can mutate pending approval state.
        if !is_rejected_by_emergency_pause(st.is_emergency_paused(), &paused_tx) {
            let _ = apply_one(&mut st, paused_tx, 131);
        }

        assert_eq!(
            st.pending_resolve_approval_snapshot(r5.id),
            pending_before,
            "pause gate must preserve staged multisig quorum across version-drift replay"
        );
        assert_eq!(
            st.get_task(r5.id).expect("task should remain challenged"),
            task_before
        );
        assert_eq!(st.balance_of("treasury.challenge_escrow"), escrow_before);
        assert_eq!(st.balance_of("treasury.challenge_forfeits"), forfeit_before);
    }

    #[test]
    fn paused_node_gate_skips_first_multisig_resolve_without_staging_or_escrow_drift() {
        let mut st = StateStore::new();
        st.set_gov_param_bootstrap_unchecked(
            9_500,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .unwrap();
        let (r5, _, _) = challenged_task_fixture(&mut st, 8_109_1);

        st.set_gov_param(9_999, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause toggle must apply immediately");
        assert!(st.is_emergency_paused());

        let paused_tx = MockTx::Resolve {
            task_id: r5.id,
            slash_worker: true,
            resolver: "authority-a".into(),
        };
        assert!(is_rejected_by_emergency_pause(true, &paused_tx));

        let task_before = st.get_task(r5.id).expect("challenged task must exist");
        let pending_before = st.pending_resolve_approval(r5.id);
        let first_approver_before = st.pending_resolve_first_approver(r5.id);
        let escrow_before = st.balance_of("treasury.challenge_escrow");
        let forfeit_before = st.balance_of("treasury.challenge_forfeits");

        if !is_rejected_by_emergency_pause(st.is_emergency_paused(), &paused_tx) {
            let _ = apply_one(&mut st, paused_tx, 131);
        }

        assert_eq!(
            st.pending_resolve_approval(r5.id),
            pending_before,
            "pause gate must block first multisig approval staging"
        );
        assert_eq!(
            st.pending_resolve_first_approver(r5.id),
            first_approver_before,
            "pause gate must not synthesize staged first approver state"
        );
        assert_eq!(
            st.get_task(r5.id).expect("task should remain challenged"),
            task_before
        );
        assert_eq!(st.balance_of("treasury.challenge_escrow"), escrow_before);
        assert_eq!(st.balance_of("treasury.challenge_forfeits"), forfeit_before);
    }

    #[test]
    fn paused_node_gate_skips_pending_replacement_resolve_without_mutating_timelock_or_escrow_state(
    ) {
        let mut st = StateStore::new();
        st.set_gov_param_bootstrap_unchecked(
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .unwrap();
        let (r5, _, _) = challenged_task_fixture(&mut st, 8_109_3);

        let scheduled = st
            .set_gov_param(
                9_998,
                7_310,
                "resolve_authority".into(),
                "authority-c,authority-d".into(),
            )
            .expect("replacement resolve_authority should schedule before pause");
        assert!(matches!(scheduled, GovParamUpdateOutcome::Scheduled { .. }));
        let pending_gov_before = st
            .pending_gov_update("resolve_authority")
            .expect("replacement resolve_authority timelock should remain staged");

        st.set_gov_param(9_999, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause toggle must apply immediately");
        assert!(st.is_emergency_paused());

        let paused_tx = MockTx::Resolve {
            task_id: r5.id,
            slash_worker: true,
            resolver: "authority-a".into(),
        };
        assert!(is_rejected_by_emergency_pause(true, &paused_tx));

        let task_before = st.get_task(r5.id).expect("challenged task must exist");
        let pending_quorum_before = st.pending_resolve_approval_snapshot(r5.id);
        let escrow_before = st.balance_of("treasury.challenge_escrow");
        let forfeit_before = st.balance_of("treasury.challenge_forfeits");

        if !is_rejected_by_emergency_pause(st.is_emergency_paused(), &paused_tx) {
            let _ = apply_one(&mut st, paused_tx, 131);
        }

        assert_eq!(
            st.pending_resolve_approval_snapshot(r5.id),
            pending_quorum_before,
            "pause gate must not synthesize or clear staged quorum while a replacement authority is pending"
        );
        assert_eq!(
            st.pending_gov_update("resolve_authority"),
            Some(pending_gov_before),
            "pause gate must not mutate pending resolve_authority timelock state"
        );
        assert_eq!(
            st.gov_param_string("resolve_authority").as_deref(),
            Some("authority-a,authority-b"),
            "pending replacement authority must not apply early while paused"
        );
        assert_eq!(
            st.get_task(r5.id).expect("task should remain challenged"),
            task_before
        );
        assert_eq!(st.balance_of("treasury.challenge_escrow"), escrow_before);
        assert_eq!(st.balance_of("treasury.challenge_forfeits"), forfeit_before);
    }

    #[test]
    fn verified_signer_for_multisig_resolve_uses_actual_resolver_member() {
        let mut st = StateStore::new();
        st.set_gov_param_bootstrap_unchecked(
            9_501,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .unwrap();
        let tx = MockTx::Resolve {
            task_id: 42,
            slash_worker: false,
            resolver: "authority-b".into(),
        };
        assert_eq!(verified_signer_of(&st, &tx), "authority-b");
    }

    #[test]
    fn staged_resolve_approval_uses_distinct_event_type() {
        let tx = MockTx::Resolve {
            task_id: 7,
            slash_worker: true,
            resolver: "authority-a".into(),
        };
        assert_eq!(
            event_type_for_apply_outcome(&tx, Some("resolve_approval_staged")),
            "resolve_approval_staged"
        );
        assert_eq!(event_type_for_apply_outcome(&tx, None), "resolve");
    }

    #[test]
    fn resolve_challenger_fallback_does_not_alias_resolver() {
        let tx = MockTx::Resolve {
            task_id: 9,
            slash_worker: false,
            resolver: "authority-b".into(),
        };
        assert_eq!(challenger_of(&tx), None);
    }

    fn temp_wal_dir(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("trnm-node-{}-{}", name, now_unix_ms()));
        p
    }

    #[test]
    fn sorted_timeout_candidate_ids_stabilizes_event_scan_order() {
        let known: HashSet<u64> = [7003u64, 7001u64, 7002u64].into_iter().collect();

        assert_eq!(sorted_timeout_candidate_ids(&known), vec![7001, 7002, 7003]);
    }

    #[test]
    fn sorted_timeout_candidate_ids_filters_synthetic_ids_above_scan_cap() {
        let known: HashSet<u64> = [7003u64, TIMEOUT_SCAN_MAX_TASK_ID + 1, 7001u64, 7002u64]
            .into_iter()
            .collect();

        assert_eq!(sorted_timeout_candidate_ids(&known), vec![7001, 7002, 7003]);
    }

    #[test]
    fn timeout_event_tx_id_starts_after_seed_and_preserves_scan_order_visibility() {
        assert_eq!(timeout_event_tx_id(9_000_000, 0), 9_000_001);
        assert_eq!(timeout_event_tx_id(9_000_000, 1), 9_000_002);
        assert_eq!(timeout_event_tx_id(u64::MAX, 0), u64::MAX);
        assert_eq!(timeout_event_tx_id(9_000_000, u64::MAX), u64::MAX);
    }

    #[test]
    fn timeout_event_tx_metadata_keeps_tx_id_and_overflow_flag_consistent_at_boundary() {
        assert_eq!(timeout_event_tx_metadata(9_000_000, 0), (9_000_001, false));
        assert_eq!(timeout_event_tx_metadata(u64::MAX - 1, 0), (u64::MAX, false));
        assert_eq!(timeout_event_tx_metadata(u64::MAX - 1, 1), (u64::MAX, true));
        assert_eq!(timeout_event_tx_metadata(u64::MAX, 0), (u64::MAX, true));
    }

    #[test]
    fn timeout_event_tx_metadata_marks_saturated_ordinal_as_overflow_for_visibility() {
        assert_eq!(timeout_event_tx_metadata(0, u64::MAX), (u64::MAX, true));
    }

    #[test]
    fn timeout_scan_auto_migrates_committed_revealed_and_challenged() {
        let mut st = StateStore::new();
        st.set_balance("challenger", 1_000_000);
        st.set_balance("worker7001", 1_000);
        st.set_balance("worker7002", 1_000);
        st.set_balance("worker7003", 1_000);

        let r1 = apply_create_task(&mut st, 7001, "alice".into(), 100).unwrap();
        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let committed = compute_commitment(7001, &result_hash, &reveal_salt, "worker7001");
        let r2 = apply_accept_task(&mut st, r1, "worker7001".into()).unwrap();
        let _r3 = trnm_pouw::apply_commit_result_at_height(
            &mut st,
            r2,
            "worker7001".into(),
            committed,
            100,
        )
        .unwrap();

        let r4 = apply_create_task(&mut st, 7002, "alice".into(), 100).unwrap();
        let committed2 = compute_commitment(7002, &result_hash, &reveal_salt, "worker7002");
        let r5 = apply_accept_task(&mut st, r4, "worker7002".into()).unwrap();
        let r6 = trnm_pouw::apply_commit_result_at_height(
            &mut st,
            r5,
            "worker7002".into(),
            committed2,
            100,
        )
        .unwrap();
        let r7 = trnm_pouw::apply_reveal_result_at_height(
            &mut st,
            r6,
            result_hash,
            reveal_salt,
            None,
            110,
        )
        .unwrap();
        let _r8 = trnm_pouw::apply_challenge_at_height(
            &mut st,
            r7,
            "challenger".into(),
            10,
            "challenger".into(),
            120,
        )
        .unwrap();

        let r9 = apply_create_task(&mut st, 7003, "alice".into(), 100).unwrap();
        let committed3 = compute_commitment(7003, &result_hash, &reveal_salt, "worker7003");
        let r10 = apply_accept_task(&mut st, r9, "worker7003".into()).unwrap();
        let r11 = trnm_pouw::apply_commit_result_at_height(
            &mut st,
            r10,
            "worker7003".into(),
            committed3,
            100,
        )
        .unwrap();
        let _r12 = trnm_pouw::apply_reveal_result_at_height(
            &mut st,
            r11,
            result_hash,
            reveal_salt,
            None,
            110,
        )
        .unwrap();

        let known: HashSet<u64> = [7001u64, 7002u64, 7003u64].into_iter().collect();
        let migrated = scan_and_apply_timeouts(&mut st, &known, 10_000, 9_000_000);

        assert_eq!(migrated, 3);
        assert_eq!(st.get_task(7001).unwrap().status, TaskStatus::Slashed);
        assert_eq!(st.get_task(7002).unwrap().status, TaskStatus::Completed);
        assert_eq!(st.get_task(7003).unwrap().status, TaskStatus::Completed);
    }

    #[test]
    fn timeout_scan_revealed_boundary_at_deadline_and_after() {
        let mut st = StateStore::new();
        st.set_balance("worker7004", 1_000);

        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let r1 = apply_create_task(&mut st, 7004, "alice".into(), 100).unwrap();
        let committed = compute_commitment(7004, &result_hash, &reveal_salt, "worker7004");
        let r2 = apply_accept_task(&mut st, r1, "worker7004".into()).unwrap();
        let r3 = trnm_pouw::apply_commit_result_at_height(
            &mut st,
            r2,
            "worker7004".into(),
            committed,
            100,
        )
        .unwrap();
        let _r4 = trnm_pouw::apply_reveal_result_at_height(
            &mut st,
            r3,
            result_hash,
            reveal_salt,
            None,
            110,
        )
        .unwrap();

        let challenge_deadline = st
            .get_task(7004)
            .and_then(|t| t.challenge_deadline_height)
            .expect("challenge deadline must be present after reveal");

        let known: HashSet<u64> = [7004u64].into_iter().collect();

        let migrated_at_deadline =
            scan_and_apply_timeouts(&mut st, &known, challenge_deadline, 9_100_000);
        assert_eq!(migrated_at_deadline, 0);
        assert_eq!(st.get_task(7004).unwrap().status, TaskStatus::Revealed);

        let migrated_after_deadline = scan_and_apply_timeouts(
            &mut st,
            &known,
            challenge_deadline.saturating_add(1),
            9_100_100,
        );
        assert_eq!(migrated_after_deadline, 1);
        assert_eq!(st.get_task(7004).unwrap().status, TaskStatus::Completed);
    }

    #[test]
    fn timeout_scan_revealed_task_still_finalizes_while_emergency_paused() {
        // Safety boundary scope: emergency pause should block challenged escrow
        // settlement paths only, not uncontested revealed timeout completion.
        let mut st = StateStore::new();
        st.set_balance("worker7005", 1_000);

        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let r1 = apply_create_task(&mut st, 7005, "alice".into(), 100).unwrap();
        let committed = compute_commitment(7005, &result_hash, &reveal_salt, "worker7005");
        let r2 = apply_accept_task(&mut st, r1, "worker7005".into()).unwrap();
        let r3 = trnm_pouw::apply_commit_result_at_height(
            &mut st,
            r2,
            "worker7005".into(),
            committed,
            100,
        )
        .unwrap();
        let _r4 = trnm_pouw::apply_reveal_result_at_height(
            &mut st,
            r3,
            result_hash,
            reveal_salt,
            None,
            110,
        )
        .unwrap();

        st.set_gov_param(9_230, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let challenge_deadline = st
            .get_task(7005)
            .and_then(|t| t.challenge_deadline_height)
            .expect("challenge deadline must be present after reveal");

        let known: HashSet<u64> = [7005u64].into_iter().collect();
        let migrated = scan_and_apply_timeouts(
            &mut st,
            &known,
            challenge_deadline.saturating_add(1),
            9_100_200,
        );

        assert_eq!(migrated, 1);
        let task = st
            .get_task(7005)
            .expect("task must exist after timeout scan");
        assert_eq!(task.status, TaskStatus::Completed);
        assert_eq!(task.challenge_bond_forfeited, None);
    }

    #[test]
    fn timeout_scan_skips_challenged_task_while_paused_without_mutating_staged_resolve_state() {
        // Governance boundary hardening: the node-level timeout scanner must not touch
        // challenged settlement while paused, preserving staged resolve quorum and escrow.
        let mut st = StateStore::new();
        st.set_balance("worker7006", 1_000);
        st.set_balance("challenger7006", 100);
        st.set_gov_param_bootstrap_unchecked(
            9_500,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve authority should succeed");

        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let r1 = apply_create_task(&mut st, 7006, "alice".into(), 100).unwrap();
        let committed = compute_commitment(7006, &result_hash, &reveal_salt, "worker7006");
        let r2 = apply_accept_task(&mut st, r1, "worker7006".into()).unwrap();
        let r3 = trnm_pouw::apply_commit_result_at_height(
            &mut st,
            r2,
            "worker7006".into(),
            committed,
            100,
        )
        .unwrap();
        let r4 = trnm_pouw::apply_reveal_result_at_height(
            &mut st,
            r3,
            result_hash,
            reveal_salt,
            None,
            110,
        )
        .unwrap();
        let r5 = trnm_pouw::apply_challenge_at_height(
            &mut st,
            r4,
            "challenger7006".into(),
            10,
            "challenger7006".into(),
            210,
        )
        .unwrap();

        let staged = apply_resolve_at_height(
            &mut st,
            r5.clone(),
            true,
            "authority-a".into(),
            "authority-a".into(),
            211,
        )
        .expect_err("first resolve approval should only stage quorum");
        assert!(matches!(
            staged,
            trnm_pouw::PouwError::ResolveApprovalStaged
        ));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));
        assert_eq!(
            st.pending_resolve_first_approver(r5.id).as_deref(),
            Some("authority-a")
        );

        st.set_gov_param(9_231, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let resolve_deadline = st
            .get_task(7006)
            .and_then(|t| t.resolve_deadline_height)
            .expect("resolve deadline must be present after challenge");
        let before_task = st.get_task(7006).expect("challenged task must exist");
        let before_escrow = st.balance_of("treasury.challenge_escrow");
        let before_forfeit = st.balance_of("treasury.challenge_forfeits");
        let before_worker_slash = st.balance_of("treasury.worker_slashes");
        let before_challenger = st.balance_of("challenger7006");

        let known: HashSet<u64> = [7006u64].into_iter().collect();
        let migrated = scan_and_apply_timeouts(
            &mut st,
            &known,
            resolve_deadline.saturating_add(1),
            9_100_201,
        );

        assert_eq!(migrated, 0);
        let after_task = st
            .get_task(7006)
            .expect("challenged task must remain after paused scan");
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.pending_resolve_approval(7006), Some((true, 1)));
        assert_eq!(
            st.pending_resolve_first_approver(7006).as_deref(),
            Some("authority-a")
        );
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(st.balance_of("treasury.challenge_forfeits"), before_forfeit);
        assert_eq!(
            st.balance_of("treasury.worker_slashes"),
            before_worker_slash
        );
        assert_eq!(st.balance_of("challenger7006"), before_challenger);
    }

    #[test]
    fn event_deltas_match_balance_movements_on_revealed_timeout_complete() {
        let mut st = StateStore::new();
        st.set_balance("worker8100", 1_000);

        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let r1 = apply_create_task(&mut st, 8100, "alice".into(), 100).unwrap();
        let committed = compute_commitment(8100, &result_hash, &reveal_salt, "worker8100");
        let r2 = apply_accept_task(&mut st, r1, "worker8100".into()).unwrap();
        let r3 = trnm_pouw::apply_commit_result_at_height(
            &mut st,
            r2,
            "worker8100".into(),
            committed,
            1,
        )
        .unwrap();
        let revealed = trnm_pouw::apply_reveal_result_at_height(
            &mut st,
            r3,
            result_hash,
            reveal_salt,
            None,
            2,
        )
        .unwrap();

        let before = st.clone();
        let _ = apply_timeout(&mut st, revealed, 1_000).unwrap();

        let (treasury_delta, challenger_delta) =
            balance_deltas_for_transition(&before, &st, 8100, None);

        assert_eq!(st.get_task(8100).unwrap().status, TaskStatus::Completed);
        assert_eq!(
            treasury_delta.numeric,
            diff_u128_to_i128(treasury_total(&st), treasury_total(&before))
        );
        assert_eq!(challenger_delta, None);
        assert_eq!(treasury_delta.numeric, Some(0));
    }

    #[test]
    fn event_deltas_match_balance_movements_on_resolve_slashed() {
        let mut st = StateStore::new();
        st.set_balance("challenger", 100);
        st.set_balance("worker8101", 1_000);

        let r1 = apply_create_task(&mut st, 8101, "alice".into(), 100).unwrap();
        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let committed = compute_commitment(8101, &result_hash, &reveal_salt, "worker8101");

        let r2 = apply_accept_task(&mut st, r1, "worker8101".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker8101".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let challenger = before
            .get_task(8101)
            .and_then(|t| t.challenger)
            .expect("challenger must exist");
        let resolve_authority = "authority8101,authority8101b".to_string();
        st.set_gov_param_bootstrap_unchecked(
            18_101,
            "resolve_authority".into(),
            resolve_authority.clone(),
        )
        .unwrap();
        let staged = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority8101".into(),
            "authority8101".into(),
        )
        .expect_err("first multisig approver should stage only");
        assert!(matches!(
            staged,
            trnm_pouw::PouwError::ResolveApprovalStaged
        ));
        let _r7 = apply_resolve(
            &mut st,
            r5,
            true,
            "authority8101b".into(),
            "authority8101b".into(),
        )
        .unwrap();

        let (treasury_delta, challenger_delta) =
            balance_deltas_for_transition(&before, &st, 8101, Some(challenger.as_str()));

        assert_eq!(
            treasury_delta.numeric,
            diff_u128_to_i128(treasury_total(&st), treasury_total(&before))
        );
        assert_eq!(
            challenger_delta.as_ref().and_then(|d| d.numeric),
            diff_u128_to_i128(st.balance_of(&challenger), before.balance_of(&challenger))
        );
        assert!(
            challenger_delta
                .as_ref()
                .and_then(|d| d.numeric)
                .unwrap_or(0)
                > 0
        );
    }

    #[test]
    fn event_deltas_match_balance_movements_on_resolve_forfeited() {
        let mut st = StateStore::new();
        st.set_balance("challenger", 100);
        st.set_balance("worker8102", 1_000);

        let r1 = apply_create_task(&mut st, 8102, "alice".into(), 100).unwrap();
        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let committed = compute_commitment(8102, &result_hash, &reveal_salt, "worker8102");

        let r2 = apply_accept_task(&mut st, r1, "worker8102".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker8102".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let challenger = before
            .get_task(8102)
            .and_then(|t| t.challenger)
            .expect("challenger must exist");
        let resolve_authority = "authority8102,authority8102b".to_string();
        st.set_gov_param_bootstrap_unchecked(
            18_102,
            "resolve_authority".into(),
            resolve_authority.clone(),
        )
        .unwrap();
        let staged = apply_resolve(
            &mut st,
            r5.clone(),
            false,
            "authority8102".into(),
            "authority8102".into(),
        )
        .expect_err("first multisig approver should stage only");
        assert!(matches!(
            staged,
            trnm_pouw::PouwError::ResolveApprovalStaged
        ));
        let _r7 = apply_resolve(
            &mut st,
            r5,
            false,
            "authority8102b".into(),
            "authority8102b".into(),
        )
        .unwrap();

        let (treasury_delta, challenger_delta) =
            balance_deltas_for_transition(&before, &st, 8102, Some(challenger.as_str()));

        assert_eq!(
            treasury_delta.numeric,
            diff_u128_to_i128(treasury_total(&st), treasury_total(&before))
        );
        assert_eq!(
            challenger_delta.as_ref().and_then(|d| d.numeric),
            diff_u128_to_i128(st.balance_of(&challenger), before.balance_of(&challenger))
        );
        assert_eq!(challenger_delta.as_ref().and_then(|d| d.numeric), Some(0));
    }

    #[test]
    fn event_deltas_match_balance_movements_on_challenged_timeout_refund() {
        let mut st = StateStore::new();
        st.set_balance("challenger", 100);
        st.set_balance("worker8103", 1_000);

        let r1 = apply_create_task(&mut st, 8103, "alice".into(), 100).unwrap();
        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let committed = compute_commitment(8103, &result_hash, &reveal_salt, "worker8103");

        let r2 = apply_accept_task(&mut st, r1, "worker8103".into()).unwrap();
        let r3 = trnm_pouw::apply_commit_result_at_height(
            &mut st,
            r2,
            "worker8103".into(),
            committed,
            1,
        )
        .unwrap();
        let r4 = trnm_pouw::apply_reveal_result_at_height(
            &mut st,
            r3,
            result_hash,
            reveal_salt,
            None,
            2,
        )
        .unwrap();
        let challenged = trnm_pouw::apply_challenge_at_height(
            &mut st,
            r4,
            "challenger".into(),
            10,
            "challenger".into(),
            3,
        )
        .unwrap();

        let before = st.clone();
        let challenger = before
            .get_task(8103)
            .and_then(|t| t.challenger)
            .expect("challenger must exist");
        let _ = apply_timeout(&mut st, challenged, 1_000).unwrap();

        let (treasury_delta, challenger_delta) =
            balance_deltas_for_transition(&before, &st, 8103, Some(challenger.as_str()));

        assert_eq!(
            treasury_delta.numeric,
            diff_u128_to_i128(treasury_total(&st), treasury_total(&before))
        );
        assert_eq!(
            challenger_delta.as_ref().and_then(|d| d.numeric),
            diff_u128_to_i128(st.balance_of(&challenger), before.balance_of(&challenger))
        );
        assert_eq!(challenger_delta.as_ref().and_then(|d| d.numeric), Some(10));
        assert_eq!(
            st.get_task(8103).and_then(|t| t.challenge_bond_forfeited),
            Some(false)
        );
    }

    #[test]
    fn format_task_metering_event_fields_includes_normalized_work_units_and_policy_summary() {
        let snapshot = TaskMeteringSnapshot {
            workload_class: "llm_inference".into(),
            metering_schema: "llm_token_meter_v1".into(),
            policy_snapshot_version: 1,
            receipt_hash: "deadbeef".into(),
            prompt_tokens: 128,
            generated_tokens: 32,
            decode_steps: 32,
            kv_bytes_moved: 4096,
            normalized_work_units: 192,
            prompt_token_weight: 1,
            generated_token_weight: 1,
            decode_step_weight: 1,
            kv_byte_weight: 0,
            min_accept_work_units: 100,
            challenge_success_bounty_base: 1,
            challenge_success_bounty_per_work_unit_num: 1,
            challenge_success_bounty_per_work_unit_den: 192,
            worker_completion_bonus_per_work_unit_num: 1,
            worker_completion_bonus_per_work_unit_den: 256,
            worker_slash_rebate_per_work_unit_num: 1,
            worker_slash_rebate_per_work_unit_den: 384,
        };
        let line = format_task_metering_event_fields(&snapshot);
        assert!(line.contains("metering_schema=llm_token_meter_v1"));
        assert!(line.contains("metering_normalized_work_units=192"));
        assert!(line.contains("metering_policy_snapshot_version=1"));
        assert!(line.contains("metering_min_accept_work_units=100"));
        assert!(line.contains("metering_worker_slash_rebate_per_work_unit_den=384"));
    }

    #[test]
    fn event_delta_fallback_is_deterministic_for_large_balances() {
        let before = i128::MAX as u128 + 10;
        let after = before + 25;

        let delta = event_delta_from_balances(after, before);
        assert_eq!(delta.numeric, None);
        assert_eq!(delta.text, "u128:+25");
        assert_ne!(delta.text, "-");

        let reverse = event_delta_from_balances(before, after);
        assert_eq!(reverse.numeric, None);
        assert_eq!(reverse.text, "u128:-25");
    }

    #[test]
    fn event_delta_normal_range_text_matches_previous_numeric_output() {
        let before = 100u128;
        let after = 82u128;

        let delta = event_delta_from_balances(after, before);
        assert_eq!(delta.numeric, Some(-18));
        assert_eq!(delta.text, "-18");
    }

    #[test]
    fn persist_checkpoint_meta_canonicalizes_equal_height_entries_for_auditable_ordering() {
        let wal_dir = temp_wal_dir("persist-checkpoint-meta-canonical-order");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 7,
                    state_root_hex: "root-b".into(),
                    wal_entry_hash_hex: "hash-b".into(),
                },
                CheckpointMeta {
                    height: 7,
                    state_root_hex: "root-a".into(),
                    wal_entry_hash_hex: "hash-c".into(),
                },
                CheckpointMeta {
                    height: 7,
                    state_root_hex: "root-a".into(),
                    wal_entry_hash_hex: "hash-a".into(),
                },
            ],
        )
        .unwrap();

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(
            checkpoints,
            vec![
                CheckpointMeta {
                    height: 7,
                    state_root_hex: "root-a".into(),
                    wal_entry_hash_hex: "hash-a".into(),
                },
                CheckpointMeta {
                    height: 7,
                    state_root_hex: "root-a".into(),
                    wal_entry_hash_hex: "hash-c".into(),
                },
                CheckpointMeta {
                    height: 7,
                    state_root_hex: "root-b".into(),
                    wal_entry_hash_hex: "hash-b".into(),
                },
            ]
        );

        let raw = fs::read_to_string(checkpoint_file(&wal_dir)).unwrap();
        let first = raw.find("root-a").unwrap();
        let second = raw.rfind("root-b").unwrap();
        assert!(first < second);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_checkpoint_meta_canonicalizes_existing_equal_height_entries_for_auditable_replay() {
        let wal_dir = temp_wal_dir("load-checkpoint-meta-canonical-order");
        fs::create_dir_all(&wal_dir).unwrap();

        let raw = r#"[[checkpoints]]
height = 9
state_root_hex = "root-b"
wal_entry_hash_hex = "hash-b"

[[checkpoints]]
height = 9
state_root_hex = "root-a"
wal_entry_hash_hex = "hash-c"

[[checkpoints]]
height = 9
state_root_hex = "root-a"
wal_entry_hash_hex = "hash-a"
"#;
        fs::write(checkpoint_file(&wal_dir), raw).unwrap();

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(
            checkpoints,
            vec![
                CheckpointMeta {
                    height: 9,
                    state_root_hex: "root-a".into(),
                    wal_entry_hash_hex: "hash-a".into(),
                },
                CheckpointMeta {
                    height: 9,
                    state_root_hex: "root-a".into(),
                    wal_entry_hash_hex: "hash-c".into(),
                },
                CheckpointMeta {
                    height: 9,
                    state_root_hex: "root-b".into(),
                    wal_entry_hash_hex: "hash-b".into(),
                },
            ]
        );

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_clears_orphan_checkpoints_when_wal_is_empty() {
        let wal_dir = temp_wal_dir("recover-orphan-checkpoints");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 7,
                state_root_hex: "stale-root".into(),
                wal_entry_hash_hex: "stale-hash".into(),
            }],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 0);

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_clears_checkpoint_only_snapshot_even_when_consensus_wal_file_exists() {
        let wal_dir = temp_wal_dir("recover-checkpoint-only-snapshot");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 8,
                last_round: 3,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 7,
                state_root_hex: "stale-root".into(),
                wal_entry_hash_hex: "stale-hash".into(),
            }],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 0);

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());
        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_clears_checkpoint_only_snapshot_even_when_empty_wal_meta_file_exists() {
        let wal_dir = temp_wal_dir("recover-checkpoint-only-with-empty-wal-meta");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 15,
                last_round: 2,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();
        persist_wal_meta_entries(&wal_dir, &[]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 14,
                state_root_hex: "stale-root".into(),
                wal_entry_hash_hex: "stale-hash".into(),
            }],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 0);
        assert_eq!(recovered.checkpoint_height_retained, None);

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert!(entries.is_empty());
        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());
        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_resets_stale_consensus_wal_when_only_blank_checkpoint_file_exists() {
        let wal_dir = temp_wal_dir("recover-stale-consensus-wal-with-blank-checkpoint-file");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 29,
                last_round: 4,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();
        fs::write(checkpoint_file(&wal_dir), "  \n\t").unwrap();

        assert_stale_consensus_wal_reset_after_recovery(&wal_dir);
        assert!(checkpoint_file(&wal_dir).exists());
        assert!(wal_file(&wal_dir).exists());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_resets_stale_consensus_wal_when_metadata_files_are_empty() {
        let wal_dir = temp_wal_dir("recover-stale-consensus-wal-without-metadata");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 41,
                last_round: 6,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 0);
        assert_eq!(recovered.checkpoint_height_retained, None);

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert!(entries.is_empty());
        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());
        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    fn assert_stale_consensus_wal_reset_after_recovery(wal_dir: &Path) {
        let recovered = recover_wal_state(wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 0);
        assert_eq!(recovered.checkpoint_height_retained, None);

        let entries = load_wal_meta_entries(wal_dir).unwrap();
        assert!(entries.is_empty());
        let checkpoints = load_checkpoint_meta(wal_dir).unwrap();
        assert!(checkpoints.is_empty());
        let wal = fs::read_to_string(wal_file(wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());
    }

    #[test]
    fn recover_resets_stale_consensus_wal_when_only_empty_wal_meta_file_exists() {
        let wal_dir = temp_wal_dir("recover-stale-consensus-wal-with-empty-wal-meta");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 23,
                last_round: 5,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();
        persist_wal_meta_entries(&wal_dir, &[]).unwrap();

        assert_stale_consensus_wal_reset_after_recovery(&wal_dir);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_resets_stale_consensus_wal_when_only_blank_wal_meta_file_exists() {
        let wal_dir = temp_wal_dir("recover-stale-consensus-wal-with-blank-wal-meta");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 23,
                last_round: 5,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();
        fs::write(wal_meta_file(&wal_dir), "\n  \t").unwrap();

        assert_stale_consensus_wal_reset_after_recovery(&wal_dir);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_resets_stale_consensus_wal_when_only_empty_checkpoint_file_exists() {
        let wal_dir = temp_wal_dir("recover-stale-consensus-wal-with-empty-checkpoint-file");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 29,
                last_round: 4,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();
        persist_checkpoint_meta(&wal_dir, &[]).unwrap();

        assert_stale_consensus_wal_reset_after_recovery(&wal_dir);

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert!(entries.is_empty());
        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());
        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_rejects_uncommitted_genesis_entry_even_with_checkpoint_metadata() {
        let wal_dir = temp_wal_dir("recover-uncommitted-genesis-entry");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: false,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };

        persist_wal_meta_entries(&wal_dir, &[e1.clone()]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: e1.content_hash_hex(),
            }],
        )
        .unwrap();
        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 77,
                last_round: 9,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 0);
        assert_eq!(recovered.checkpoint_height_retained, None);

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert!(entries.is_empty());
        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());
        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_rejects_genesis_entry_with_non_genesis_prev_hash_even_with_checkpoint_metadata() {
        let wal_dir = temp_wal_dir("recover-genesis-prev-hash");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: Some("forged-parent".into()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1.clone()]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: e1.content_hash_hex(),
            }],
        )
        .unwrap();
        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 42,
                last_round: 5,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 0);
        assert_eq!(recovered.checkpoint_height_retained, None);

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert!(entries.is_empty());
        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());
        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_rejects_checkpointed_wal_chain_that_starts_above_genesis_height() {
        let wal_dir = temp_wal_dir("recover-starts-above-genesis-height");
        fs::create_dir_all(&wal_dir).unwrap();

        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: None,
        };

        persist_wal_meta_entries(&wal_dir, &[e2.clone()]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: e2.content_hash_hex(),
            }],
        )
        .unwrap();
        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 88,
                last_round: 7,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 0);
        assert_eq!(recovered.checkpoint_height_retained, None);

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert!(entries.is_empty());
        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());
        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_discards_metadata_only_tail_without_restoring_stale_lock() {
        let wal_dir = temp_wal_dir("recover-metadata-only-tail-no-stale-lock");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();
        let e3 = WalMeta {
            height: 3,
            round: 0,
            proposal_hash: "stale-tail-lock".into(),
            committed: false,
            state_root_hex: "r3".into(),
            prev_hash_hex: Some(h2.clone()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e2, e3]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1,
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2,
                },
            ],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(recovered.truncated);
        assert!(recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 2);
        assert_eq!(
            recovered.last_checkpoint.as_ref().map(|cp| cp.height),
            Some(2)
        );
        assert!(recovered.restored_lock.is_none());
        assert_ne!(recovered.restored_lock.as_deref(), Some("stale-tail-lock"));

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|entry| entry.committed));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_prunes_checkpoint_for_metadata_only_tail() {
        let wal_dir = temp_wal_dir("recover-prune-metadata-only-tail-checkpoint");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();
        let e3 = WalMeta {
            height: 3,
            round: 0,
            proposal_hash: "metadata-only-tail".into(),
            committed: false,
            state_root_hex: "r3".into(),
            prev_hash_hex: Some(h2.clone()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e2, e3.clone()]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1,
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2,
                },
                CheckpointMeta {
                    height: 3,
                    state_root_hex: "r3".into(),
                    wal_entry_hash_hex: e3.content_hash_hex(),
                },
            ],
        )
        .unwrap();
        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 99,
                last_round: 7,
                locked_block_hash: Some("stale-tail-lock".into()),
            },
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(recovered.truncated);
        assert!(recovered.metadata_only_recovery);
        assert_eq!(
            recovered.last_checkpoint.as_ref().map(|cp| cp.height),
            Some(2)
        );
        assert!(recovered.restored_lock.is_none());

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert!(checkpoints.iter().all(|cp| cp.height <= 2));
        assert!(checkpoints
            .iter()
            .all(|cp| cp.wal_entry_hash_hex != e3.content_hash_hex()));

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 3);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_metadata_only_tail_prunes_stale_duplicate_checkpoint_at_retained_height() {
        let wal_dir = temp_wal_dir("recover-metadata-only-tail-prunes-stale-duplicate-checkpoint");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();
        let e3 = WalMeta {
            height: 3,
            round: 0,
            proposal_hash: "metadata-only-tail".into(),
            committed: false,
            state_root_hex: "r3".into(),
            prev_hash_hex: Some(h2.clone()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e2, e3.clone()]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1,
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2-stale".into(),
                    wal_entry_hash_hex: "stale-h2".into(),
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2.clone(),
                },
                CheckpointMeta {
                    height: 3,
                    state_root_hex: "r3".into(),
                    wal_entry_hash_hex: e3.content_hash_hex(),
                },
            ],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(recovered.restored_lock.is_none());
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(recovered.wal_entries_retained, 2);
        assert!(recovered.truncated);
        assert!(recovered.metadata_only_recovery);

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[0].height, 1);
        assert_eq!(checkpoints[1].height, 2);
        assert_eq!(checkpoints[1].state_root_hex, "r2");
        assert_eq!(checkpoints[1].wal_entry_hash_hex, h2);

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 3);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_prunes_exact_duplicate_checkpoint_at_retained_height() {
        let wal_dir = temp_wal_dir("recover-prune-exact-duplicate-checkpoint");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 5,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();

        persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1,
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2.clone(),
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2.clone(),
                },
            ],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(recovered.wal_entries_retained, 2);
        assert_eq!(recovered.restored_lock.as_deref(), Some("h2"));

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[0].height, 1);
        assert_eq!(checkpoints[1].height, 2);
        assert_eq!(checkpoints[1].state_root_hex, "r2");
        assert_eq!(checkpoints[1].wal_entry_hash_hex, h2);

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 3);
        assert_eq!(wal.last_round, 5);
        assert_eq!(wal.locked_block_hash.as_deref(), Some("h2"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_prunes_stale_duplicate_checkpoint_and_rewrites_consensus_wal_to_retained_tip() {
        let wal_dir = temp_wal_dir("recover-prune-duplicate-checkpoint-rewrites-wal");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 2,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 5,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();

        persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1,
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "stale-r2".into(),
                    wal_entry_hash_hex: "stale-h2".into(),
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2.clone(),
                },
            ],
        )
        .unwrap();
        fs::write(
            wal_file(&wal_dir),
            r#"next_height = 99
last_round = 42
locked_block_hash = "stale-lock"
"#,
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(recovered.wal_entries_retained, 2);
        assert_eq!(recovered.restored_lock.as_deref(), Some("h2"));

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[0].height, 1);
        assert_eq!(checkpoints[1].height, 2);
        assert_eq!(checkpoints[1].state_root_hex, "r2");
        assert_eq!(checkpoints[1].wal_entry_hash_hex, h2);

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 3);
        assert_eq!(wal.last_round, 5);
        assert_eq!(wal.locked_block_hash.as_deref(), Some("h2"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_truncates_to_latest_valid_checkpoint() {
        let wal_dir = temp_wal_dir("recover");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();
        let e3_bad = WalMeta {
            height: 3,
            round: 1,
            proposal_hash: "h3".into(),
            committed: true,
            state_root_hex: "r3".into(),
            prev_hash_hex: Some("broken".into()),
        };
        persist_wal_meta_entries(&wal_dir, &[e1, e2, e3_bad]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1,
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2,
                },
            ],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 2);
        assert_eq!(
            recovered.last_checkpoint.as_ref().map(|cp| cp.height),
            Some(2)
        );
        assert_eq!(recovered.restored_lock.as_deref(), Some("h2"));

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(entries.len(), 2);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_discards_committed_tail_beyond_checkpoint_without_restoring_stale_lock() {
        let wal_dir = temp_wal_dir("recover-committed-tail-beyond-checkpoint-no-stale-lock");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();
        let e3 = WalMeta {
            height: 3,
            round: 0,
            proposal_hash: "stale-committed-tail-lock".into(),
            committed: true,
            state_root_hex: "r3".into(),
            prev_hash_hex: Some(h2.clone()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e2, e3.clone()]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1,
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2,
                },
            ],
        )
        .unwrap();
        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 4,
                last_round: 0,
                locked_block_hash: Some("stale-committed-tail-lock".into()),
            },
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(recovered.truncated);
        assert!(recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 2);
        assert_eq!(
            recovered.last_checkpoint.as_ref().map(|cp| cp.height),
            Some(2)
        );
        assert!(recovered.restored_lock.is_none());
        assert_ne!(
            recovered.restored_lock.as_deref(),
            Some("stale-committed-tail-lock")
        );

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|entry| entry.height <= 2));

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert!(checkpoints.iter().all(|cp| cp.height <= 2));
        assert!(checkpoints
            .iter()
            .all(|cp| cp.wal_entry_hash_hex != e3.content_hash_hex()));

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 3);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_discards_committed_duplicate_height_tail_without_restoring_stale_lock() {
        let wal_dir = temp_wal_dir("recover-committed-duplicate-height-tail-no-stale-lock");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();
        let replayed_e2 = WalMeta {
            height: 2,
            round: 1,
            proposal_hash: "stale-duplicate-tail-lock".into(),
            committed: true,
            state_root_hex: "r2-replayed".into(),
            prev_hash_hex: Some(h1.clone()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e2, replayed_e2.clone()]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1,
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2.clone(),
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: replayed_e2.state_root_hex.clone(),
                    wal_entry_hash_hex: replayed_e2.content_hash_hex(),
                },
            ],
        )
        .unwrap();
        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 3,
                last_round: 1,
                locked_block_hash: Some("stale-duplicate-tail-lock".into()),
            },
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(recovered.truncated);
        assert!(
            !recovered.metadata_only_recovery,
            "discarding a corrupt duplicate-height committed WAL tail should preserve recoverable state at the retained checkpoint"
        );
        assert_eq!(recovered.wal_entries_retained, 2);
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(
            recovered.last_checkpoint.as_ref().map(|cp| cp.height),
            Some(2)
        );
        assert_eq!(recovered.restored_lock.as_deref(), Some("h2"));
        assert_ne!(
            recovered.restored_lock.as_deref(),
            Some("stale-duplicate-tail-lock")
        );

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].height, 2);
        assert_eq!(entries[1].proposal_hash, "h2");

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[1].height, 2);
        assert_eq!(checkpoints[1].state_root_hex, "r2");
        assert_eq!(checkpoints[1].wal_entry_hash_hex, h2);
        assert!(checkpoints
            .iter()
            .all(|cp| cp.wal_entry_hash_hex != replayed_e2.content_hash_hex()));

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 3);
        assert_eq!(wal.last_round, 0);
        assert_eq!(wal.locked_block_hash.as_deref(), Some("h2"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_committed_tail_beyond_checkpoint_prunes_stale_duplicate_checkpoint_at_retained_height(
    ) {
        let wal_dir = temp_wal_dir(
            "recover-committed-tail-beyond-checkpoint-prunes-stale-duplicate-checkpoint",
        );
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();
        let e3 = WalMeta {
            height: 3,
            round: 0,
            proposal_hash: "stale-committed-tail".into(),
            committed: true,
            state_root_hex: "r3".into(),
            prev_hash_hex: Some(h2.clone()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e2, e3.clone()]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1,
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "stale-r2".into(),
                    wal_entry_hash_hex: "stale-h2".into(),
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2.clone(),
                },
                CheckpointMeta {
                    height: 3,
                    state_root_hex: "stale-r3".into(),
                    wal_entry_hash_hex: "stale-h3".into(),
                },
            ],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(recovered.truncated);
        assert!(recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 2);
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(
            recovered.last_checkpoint.as_ref().map(|cp| cp.height),
            Some(2)
        );
        assert!(recovered.restored_lock.is_none());

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|entry| entry.height <= 2));

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[0].height, 1);
        assert_eq!(checkpoints[1].height, 2);
        assert_eq!(checkpoints[1].state_root_hex, "r2");
        assert_eq!(checkpoints[1].wal_entry_hash_hex, h2);
        assert!(checkpoints.iter().all(|cp| cp.height <= 2));
        assert!(checkpoints
            .iter()
            .all(|cp| cp.wal_entry_hash_hex != e3.content_hash_hex()));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_discards_uncheckpointed_wal_without_claiming_recovery() {
        let wal_dir = temp_wal_dir("recover-uncheckpointed");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 9,
                last_round: 4,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        persist_wal_meta_entries(&wal_dir, &[e1]).unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 0);
        assert!(load_wal_meta_entries(&wal_dir).unwrap().is_empty());

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_discards_uncheckpointed_wal_that_starts_above_genesis_without_claiming_recovery() {
        let wal_dir = temp_wal_dir("recover-uncheckpointed-starts-above-genesis");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 12,
                last_round: 5,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();

        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: None,
        };
        persist_wal_meta_entries(&wal_dir, &[e2]).unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 0);
        assert_eq!(recovered.checkpoint_height_retained, None);
        assert!(load_wal_meta_entries(&wal_dir).unwrap().is_empty());
        assert!(load_checkpoint_meta(&wal_dir).unwrap().is_empty());

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_rejects_checkpointed_wal_chain_without_genesis_base() {
        let wal_dir = temp_wal_dir("recover-no-genesis-base");
        fs::create_dir_all(&wal_dir).unwrap();

        let e10 = WalMeta {
            height: 10,
            round: 0,
            proposal_hash: "h10".into(),
            committed: true,
            state_root_hex: "r10".into(),
            prev_hash_hex: None,
        };

        persist_wal_meta_entries(&wal_dir, &[e10.clone()]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 10,
                state_root_hex: "r10".into(),
                wal_entry_hash_hex: e10.content_hash_hex(),
            }],
        )
        .unwrap();
        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 99,
                last_round: 7,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 0);
        assert_eq!(recovered.checkpoint_height_retained, None);

        let retained = load_wal_meta_entries(&wal_dir).unwrap();
        assert!(retained.is_empty());
        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());
        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_prunes_future_checkpoints_even_without_extra_wal_entries() {
        let wal_dir = temp_wal_dir("recover-prune-future-checkpoints");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        persist_wal_meta_entries(&wal_dir, &[e1]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1,
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "stale".into(),
                    wal_entry_hash_hex: "stale-hash".into(),
                },
            ],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 2);
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 1);
        assert_eq!(
            recovered.last_checkpoint.as_ref().map(|cp| cp.height),
            Some(1)
        );

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 1);
        assert_eq!(checkpoints[0].height, 1);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_prunes_future_checkpoints_and_rewrites_consensus_wal_to_retained_tip() {
        let wal_dir = temp_wal_dir("recover-prune-future-checkpoints-rewrites-wal");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 7,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        persist_wal_meta_entries(&wal_dir, &[e1]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1,
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "stale".into(),
                    wal_entry_hash_hex: "stale-hash".into(),
                },
            ],
        )
        .unwrap();
        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 99,
                last_round: 42,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 2);
        assert_eq!(recovered.restored_lock.as_deref(), Some("h1"));
        assert_eq!(recovered.checkpoint_height_retained, Some(1));
        assert_eq!(recovered.wal_entries_retained, 1);
        assert!(!recovered.metadata_only_recovery);
        assert!(recovered.truncated);

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 2);
        assert_eq!(wal.last_round, 7);
        assert_eq!(wal.locked_block_hash.as_deref(), Some("h1"));

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 1);
        assert_eq!(checkpoints[0].height, 1);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_prunes_stale_duplicate_checkpoint_at_retained_height() {
        let wal_dir = temp_wal_dir("recover-prune-stale-duplicate-checkpoint");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();
        persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1,
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "stale-r2".into(),
                    wal_entry_hash_hex: "stale-h2".into(),
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2.clone(),
                },
            ],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 2);
        assert_eq!(recovered.checkpoint_height_retained, Some(2));

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[0].height, 1);
        assert_eq!(checkpoints[1].height, 2);
        assert_eq!(checkpoints[1].state_root_hex, "r2");
        assert_eq!(checkpoints[1].wal_entry_hash_hex, h2);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_canonicalizes_retained_checkpoint_order_after_pruning() {
        let wal_dir = temp_wal_dir("recover-canonicalize-retained-checkpoint-order");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();
        persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2.clone(),
                },
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1,
                },
            ],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(recovered.wal_entries_retained, 2);
        assert_eq!(
            recovered.last_checkpoint,
            Some(CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: h2.clone(),
            })
        );

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[0].height, 1);
        assert_eq!(checkpoints[0].state_root_hex, "r1");
        assert_eq!(checkpoints[1].height, 2);
        assert_eq!(checkpoints[1].state_root_hex, "r2");
        assert_eq!(checkpoints[1].wal_entry_hash_hex, h2);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_checkpoint_meta_canonicalizes_same_height_order_for_recovery_surface() {
        let wal_dir = temp_wal_dir("load-checkpoint-meta-canonical-same-height-order");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 7,
                    state_root_hex: "r-z".into(),
                    wal_entry_hash_hex: "h-z".into(),
                },
                CheckpointMeta {
                    height: 7,
                    state_root_hex: "r-a".into(),
                    wal_entry_hash_hex: "h-a".into(),
                },
                CheckpointMeta {
                    height: 7,
                    state_root_hex: "r-b".into(),
                    wal_entry_hash_hex: "h-a".into(),
                },
            ],
        )
        .unwrap();

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 3);
        assert_eq!(checkpoints[0].height, 7);
        assert_eq!(checkpoints[0].wal_entry_hash_hex, "h-a");
        assert_eq!(checkpoints[0].state_root_hex, "r-a");
        assert_eq!(checkpoints[1].height, 7);
        assert_eq!(checkpoints[1].wal_entry_hash_hex, "h-a");
        assert_eq!(checkpoints[1].state_root_hex, "r-b");
        assert_eq!(checkpoints[2].height, 7);
        assert_eq!(checkpoints[2].wal_entry_hash_hex, "h-z");
        assert_eq!(checkpoints[2].state_root_hex, "r-z");

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_canonicalizes_retained_checkpoint_order_without_truncating_clean_wal() {
        let wal_dir = temp_wal_dir("recover-canonicalize-checkpoints-clean-wal");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 3,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 5,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();
        persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2.clone(),
                },
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1.clone(),
                },
            ],
        )
        .unwrap();
        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 99,
                last_round: 99,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(!recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(recovered.restored_lock.as_deref(), Some("h2"));

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[0].height, 1);
        assert_eq!(checkpoints[0].state_root_hex, "r1");
        assert_eq!(checkpoints[0].wal_entry_hash_hex, h1);
        assert_eq!(checkpoints[1].height, 2);
        assert_eq!(checkpoints[1].state_root_hex, "r2");
        assert_eq!(checkpoints[1].wal_entry_hash_hex, h2);

        let wal_raw = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal_raw).unwrap();
        assert_eq!(wal.next_height, 3);
        assert_eq!(wal.last_round, 5);
        assert_eq!(wal.locked_block_hash.as_deref(), Some("h2"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_prunes_identical_duplicate_checkpoint_at_retained_height() {
        let wal_dir = temp_wal_dir("recover-prune-identical-duplicate-checkpoint");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();
        persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1,
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2.clone(),
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2.clone(),
                },
            ],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 2);
        assert_eq!(recovered.checkpoint_height_retained, Some(2));

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[0].height, 1);
        assert_eq!(checkpoints[1].height, 2);
        assert_eq!(checkpoints[1].state_root_hex, "r2");
        assert_eq!(checkpoints[1].wal_entry_hash_hex, h2);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_prunes_stale_lower_checkpoint_that_no_longer_matches_retained_wal() {
        let wal_dir = temp_wal_dir("recover-prune-stale-lower-checkpoint");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();
        persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "stale-r1".into(),
                    wal_entry_hash_hex: "stale-h1".into(),
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2.clone(),
                },
            ],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 2);
        assert_eq!(recovered.checkpoint_height_retained, Some(2));

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 1);
        assert_eq!(checkpoints[0].height, 2);
        assert_eq!(checkpoints[0].state_root_hex, "r2");
        assert_eq!(checkpoints[0].wal_entry_hash_hex, h2);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_metadata_only_tail_prunes_stale_lower_checkpoint_that_no_longer_matches_retained_wal(
    ) {
        let wal_dir = temp_wal_dir("recover-metadata-only-tail-prune-stale-lower-checkpoint");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();
        let e3 = WalMeta {
            height: 3,
            round: 0,
            proposal_hash: "metadata-only-tail".into(),
            committed: false,
            state_root_hex: "r3".into(),
            prev_hash_hex: Some(h2.clone()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e2, e3]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "stale-r1".into(),
                    wal_entry_hash_hex: "stale-h1".into(),
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2.clone(),
                },
            ],
        )
        .unwrap();
        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 99,
                last_round: 7,
                locked_block_hash: Some("stale-tail-lock".into()),
            },
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(recovered.truncated);
        assert!(recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 2);
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert!(recovered.restored_lock.is_none());

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 1);
        assert_eq!(checkpoints[0].height, 2);
        assert_eq!(checkpoints[0].state_root_hex, "r2");
        assert_eq!(checkpoints[0].wal_entry_hash_hex, h2);

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 3);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_fully_checkpointed_multiple_entries_is_not_metadata_only() {
        let wal_dir = temp_wal_dir("recover-fully-checkpointed-multiple-entries");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(e1.content_hash_hex()),
        };
        let h1 = e1.content_hash_hex();
        let h2 = e2.content_hash_hex();
        persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1,
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2,
                },
            ],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert_eq!(recovered.restored_lock.as_deref(), Some("h2"));
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(recovered.wal_entries_retained, 2);
        assert!(!recovered.metadata_only_recovery);
        assert!(!recovered.truncated);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_checkpoint_only_metadata_scaffold_clears_retained_checkpoint_surface() {
        let wal_dir = temp_wal_dir("recover-checkpoint-only-metadata-scaffold");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 7,
                state_root_hex: "stale-root".into(),
                wal_entry_hash_hex: "stale-hash".into(),
            }],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert_eq!(recovered.checkpoint_height_retained, None);
        assert_eq!(recovered.wal_entries_retained, 0);
        assert!(!recovered.metadata_only_recovery);
        assert!(recovered.truncated);

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_committed_tail_beyond_checkpoint_is_metadata_only_recovery() {
        let wal_dir = temp_wal_dir("recover-committed-tail-beyond-checkpoint");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "forked-h2".into(),
            committed: true,
            state_root_hex: "r2-fork".into(),
            prev_hash_hex: Some("foreign-tip".into()),
        };
        let h1 = e1.content_hash_hex();

        persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            }],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 2);
        assert!(recovered.restored_lock.is_none());
        assert_eq!(recovered.checkpoint_height_retained, Some(1));
        assert_eq!(recovered.wal_entries_retained, 1);
        assert!(
            recovered.metadata_only_recovery,
            "committed WAL beyond last checkpoint must stay fail-closed until StateStore restore/replay exists"
        );
        assert!(recovered.truncated);

        let retained = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].height, 1);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_committed_tail_beyond_checkpoint_rewrites_consensus_wal_fail_closed() {
        let wal_dir = temp_wal_dir("recover-committed-tail-beyond-checkpoint-rewrites-wal");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 3,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 4,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            }],
        )
        .unwrap();
        fs::write(
            wal_file(&wal_dir),
            r#"next_height = 99
last_round = 42
locked_block_hash = "stale-lock"
"#,
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 2);
        assert!(recovered.truncated);
        assert!(recovered.metadata_only_recovery);
        assert!(recovered.restored_lock.is_none());
        assert_eq!(recovered.checkpoint_height_retained, Some(1));
        assert_eq!(recovered.wal_entries_retained, 1);

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 2);
        assert_eq!(
            wal.last_round, 3,
            "fail-closed metadata-only recovery should still retain the round of the last verified committed checkpoint"
        );
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_height_regression_tail_truncates_to_last_valid_checkpoint() {
        let wal_dir = temp_wal_dir("recover-height-regression-tail");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
            committed: true,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "p2".into(),
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
            committed: true,
        };
        let h2 = e2.content_hash_hex();
        let regressed_e1 = WalMeta {
            height: 1,
            round: 1,
            proposal_hash: "p1-regressed".into(),
            state_root_hex: "r1-regressed".into(),
            prev_hash_hex: Some(h2.clone()),
            committed: true,
        };

        persist_wal_meta_entries(&wal_dir, &[e1.clone(), e2.clone(), regressed_e1]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: e1.state_root_hex.clone(),
                    wal_entry_hash_hex: h1,
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: e2.state_root_hex.clone(),
                    wal_entry_hash_hex: h2,
                },
            ],
        )
        .unwrap();
        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 99,
                last_round: 7,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert_eq!(recovered.restored_lock, Some("p2".into()));
        assert_eq!(
            recovered.last_checkpoint.as_ref().map(|cp| cp.height),
            Some(2)
        );
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 2);
        assert_eq!(recovered.checkpoint_height_retained, Some(2));

        let retained_entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(retained_entries.len(), 2);
        assert_eq!(retained_entries[0].height, 1);
        assert_eq!(retained_entries[1].height, 2);

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[0].height, 1);
        assert_eq!(checkpoints[1].height, 2);

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 3);
        assert_eq!(wal.last_round, 0);
        assert_eq!(wal.locked_block_hash, Some("p2".into()));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_replayed_duplicate_height_tail_truncates_to_last_valid_checkpoint() {
        let wal_dir = temp_wal_dir("recover-replayed-duplicate-height-tail");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();
        let replayed_e2 = WalMeta {
            height: 2,
            round: 1,
            proposal_hash: "h2-replay".into(),
            committed: true,
            state_root_hex: "r2-replay".into(),
            prev_hash_hex: Some(h2.clone()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e2, replayed_e2]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1,
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2,
                },
            ],
        )
        .unwrap();
        fs::write(
            wal_file(&wal_dir),
            r#"next_height = 99
last_round = 42
locked_block_hash = "stale-replay-lock"
"#,
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert_eq!(recovered.restored_lock.as_deref(), Some("h2"));
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(recovered.wal_entries_retained, 2);
        assert!(recovered.truncated);
        assert!(
            !recovered.metadata_only_recovery,
            "duplicate-height replay tail should truncate back to the verified checkpoint without claiming application-state recovery"
        );

        let retained = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(retained.len(), 2);
        assert_eq!(retained[0].height, 1);
        assert_eq!(retained[1].height, 2);
        assert_eq!(retained[1].proposal_hash, "h2");

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 3);
        assert_eq!(wal.last_round, 0);
        assert_eq!(wal.locked_block_hash.as_deref(), Some("h2"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_duplicate_height_tail_that_continues_past_checkpoint_is_metadata_only_recovery() {
        let wal_dir = temp_wal_dir("recover-duplicate-height-tail-continues-past-checkpoint");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();
        let replayed_e2 = WalMeta {
            height: 2,
            round: 1,
            proposal_hash: "h2-replay".into(),
            committed: true,
            state_root_hex: "r2-replay".into(),
            prev_hash_hex: Some(h2.clone()),
        };
        let e3 = WalMeta {
            height: 3,
            round: 0,
            proposal_hash: "h3".into(),
            committed: true,
            state_root_hex: "r3".into(),
            prev_hash_hex: Some(replayed_e2.content_hash_hex()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e2, replayed_e2, e3]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1,
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2,
                },
            ],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(recovered.restored_lock.is_none());
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(recovered.wal_entries_retained, 2);
        assert!(
            recovered.metadata_only_recovery,
            "committed replay metadata that continues past the retained checkpoint must stay fail-closed until StateStore restore/replay exists"
        );
        assert!(recovered.truncated);

        let retained = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(retained.len(), 2);
        assert_eq!(retained[0].height, 1);
        assert_eq!(retained[1].height, 2);
        assert_eq!(retained[1].proposal_hash, "h2");

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_replayed_duplicate_genesis_height_tail_truncates_to_genesis_checkpoint() {
        let wal_dir = temp_wal_dir("recover-replayed-duplicate-genesis-height-tail");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let replayed_e1 = WalMeta {
            height: 1,
            round: 1,
            proposal_hash: "h1-replay".into(),
            committed: true,
            state_root_hex: "r1-replay".into(),
            prev_hash_hex: Some(h1.clone()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, replayed_e1]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1,
                },
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1-replay".into(),
                    wal_entry_hash_hex: "stale-replayed-h1".into(),
                },
            ],
        )
        .unwrap();
        fs::write(
            wal_file(&wal_dir),
            r#"next_height = 99
last_round = 42
locked_block_hash = "stale-genesis-replay-lock"
"#,
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 2);
        assert_eq!(recovered.restored_lock.as_deref(), Some("h1"));
        assert_eq!(
            recovered.last_checkpoint.as_ref().map(|cp| cp.height),
            Some(1)
        );
        assert_eq!(recovered.checkpoint_height_retained, Some(1));
        assert_eq!(recovered.wal_entries_retained, 1);
        assert!(recovered.truncated);
        assert!(
            !recovered.metadata_only_recovery,
            "duplicate genesis-height replay tail should truncate back to the verified genesis checkpoint without claiming metadata-only recovery"
        );

        let retained = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].height, 1);
        assert_eq!(retained[0].proposal_hash, "h1");

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 1);
        assert_eq!(checkpoints[0].height, 1);
        assert_eq!(checkpoints[0].state_root_hex, "r1");

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 2);
        assert_eq!(wal.last_round, 0);
        assert_eq!(wal.locked_block_hash.as_deref(), Some("h1"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_committed_identical_duplicate_genesis_height_tail_truncates_to_genesis_checkpoint() {
        let wal_dir = temp_wal_dir("recover-committed-identical-duplicate-genesis-height-tail");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let duplicate_e1 = e1.clone();

        persist_wal_meta_entries(&wal_dir, &[e1, duplicate_e1]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1,
                },
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "stale-r1".into(),
                    wal_entry_hash_hex: "stale-identical-h1".into(),
                },
            ],
        )
        .unwrap();
        fs::write(
            wal_file(&wal_dir),
            r#"next_height = 88
last_round = 9
locked_block_hash = "stale-duplicate-genesis-lock"
"#,
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 2);
        assert_eq!(recovered.restored_lock.as_deref(), Some("h1"));
        assert_eq!(
            recovered.last_checkpoint.as_ref().map(|cp| cp.height),
            Some(1)
        );
        assert_eq!(recovered.checkpoint_height_retained, Some(1));
        assert_eq!(recovered.wal_entries_retained, 1);
        assert!(recovered.truncated);
        assert!(
            !recovered.metadata_only_recovery,
            "exact duplicate genesis-height tail should truncate back to the verified genesis checkpoint without claiming metadata-only recovery"
        );

        let retained = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].height, 1);
        assert_eq!(retained[0].proposal_hash, "h1");

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 1);
        assert_eq!(checkpoints[0].height, 1);
        assert_eq!(checkpoints[0].state_root_hex, "r1");

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 2);
        assert_eq!(wal.last_round, 0);
        assert_eq!(wal.locked_block_hash.as_deref(), Some("h1"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_committed_identical_duplicate_height_tail_truncates_to_last_valid_checkpoint() {
        let wal_dir = temp_wal_dir("recover-committed-identical-duplicate-height-tail");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();
        let duplicate_e2 = e2.clone();

        persist_wal_meta_entries(&wal_dir, &[e1, e2, duplicate_e2]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1,
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2,
                },
            ],
        )
        .unwrap();
        fs::write(
            wal_file(&wal_dir),
            r#"next_height = 88
last_round = 9
locked_block_hash = "stale-duplicate-lock"
"#,
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert_eq!(recovered.restored_lock.as_deref(), Some("h2"));
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(recovered.wal_entries_retained, 2);
        assert!(recovered.truncated);
        assert!(
            !recovered.metadata_only_recovery,
            "exact duplicate committed tail should truncate back to the verified checkpoint without claiming metadata-only recovery"
        );

        let retained = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(retained.len(), 2);
        assert_eq!(retained[0].height, 1);
        assert_eq!(retained[1].height, 2);
        assert_eq!(retained[1].proposal_hash, "h2");

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 3);
        assert_eq!(wal.last_round, 0);
        assert_eq!(wal.locked_block_hash.as_deref(), Some("h2"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_duplicate_height_tail_prunes_stale_duplicate_checkpoint_at_retained_height() {
        let wal_dir = temp_wal_dir("recover-duplicate-height-tail-prunes-stale-checkpoint");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();
        let replayed_e2 = WalMeta {
            height: 2,
            round: 1,
            proposal_hash: "h2-replay".into(),
            committed: true,
            state_root_hex: "r2-replay".into(),
            prev_hash_hex: Some(h2.clone()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e2, replayed_e2]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1,
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2-stale".into(),
                    wal_entry_hash_hex: "stale-hash".into(),
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2.clone(),
                },
            ],
        )
        .unwrap();
        fs::write(
            wal_file(&wal_dir),
            r#"next_height = 99
last_round = 42
locked_block_hash = "stale-replay-lock"
"#,
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert_eq!(recovered.restored_lock.as_deref(), Some("h2"));
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(recovered.wal_entries_retained, 2);
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);

        let retained = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(retained.len(), 2);
        assert_eq!(retained[0].height, 1);
        assert_eq!(retained[1].height, 2);
        assert_eq!(retained[1].proposal_hash, "h2");

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[0].height, 1);
        assert_eq!(checkpoints[1].height, 2);
        assert_eq!(checkpoints[1].state_root_hex, "r2");
        assert_eq!(checkpoints[1].wal_entry_hash_hex, h2);

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 3);
        assert_eq!(wal.last_round, 0);
        assert_eq!(wal.locked_block_hash.as_deref(), Some("h2"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_uncommitted_duplicate_height_tail_is_metadata_only_recovery() {
        let wal_dir = temp_wal_dir("recover-uncommitted-duplicate-height-tail");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();
        let replayed_e2 = WalMeta {
            height: 2,
            round: 1,
            proposal_hash: "h2-replay-uncommitted".into(),
            committed: false,
            state_root_hex: "r2-replay".into(),
            prev_hash_hex: Some(h2.clone()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e2, replayed_e2]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1,
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2,
                },
            ],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(recovered.restored_lock.is_none());
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(recovered.wal_entries_retained, 2);
        assert!(recovered.truncated);
        assert!(
            recovered.metadata_only_recovery,
            "uncommitted replay metadata beyond the retained checkpoint must stay classified as metadata-only recovery"
        );

        let retained = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(retained.len(), 2);
        assert_eq!(retained[0].height, 1);
        assert_eq!(retained[1].height, 2);
        assert_eq!(retained[1].proposal_hash, "h2");

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_uncommitted_duplicate_height_tail_prunes_stale_duplicate_checkpoint_at_retained_height(
    ) {
        let wal_dir =
            temp_wal_dir("recover-uncommitted-duplicate-height-tail-prunes-stale-checkpoint");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();
        let replayed_e2 = WalMeta {
            height: 2,
            round: 1,
            proposal_hash: "h2-replay-uncommitted".into(),
            committed: false,
            state_root_hex: "r2-replay".into(),
            prev_hash_hex: Some(h2.clone()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e2, replayed_e2]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1,
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2-stale".into(),
                    wal_entry_hash_hex: "stale-h2".into(),
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2.clone(),
                },
            ],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(recovered.truncated);
        assert!(recovered.metadata_only_recovery);
        assert!(recovered.restored_lock.is_none());
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(recovered.wal_entries_retained, 2);

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[0].height, 1);
        assert_eq!(checkpoints[1].height, 2);
        assert_eq!(checkpoints[1].state_root_hex, "r2");
        assert_eq!(checkpoints[1].wal_entry_hash_hex, h2);

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 3);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_gap_skipping_tail_truncates_to_last_valid_checkpoint() {
        let wal_dir = temp_wal_dir("recover-gap-skipping-tail");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 4,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e3 = WalMeta {
            height: 3,
            round: 9,
            proposal_hash: "h3".into(),
            committed: true,
            state_root_hex: "r3".into(),
            prev_hash_hex: Some(h1.clone()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e3.clone()]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1.clone(),
                },
                CheckpointMeta {
                    height: 3,
                    state_root_hex: "r3".into(),
                    wal_entry_hash_hex: e3.content_hash_hex(),
                },
            ],
        )
        .unwrap();
        fs::write(
            wal_file(&wal_dir),
            r#"next_height = 99
last_round = 42
locked_block_hash = "stale-lock"
"#,
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 2);
        assert!(recovered.restored_lock.is_none());
        assert_eq!(recovered.checkpoint_height_retained, Some(1));
        assert_eq!(recovered.wal_entries_retained, 1);
        assert!(recovered.truncated);
        assert!(
            recovered.metadata_only_recovery,
            "gap-skipping committed tail beyond the retained checkpoint must stay classified as metadata-only recovery until StateStore snapshot+replay exists"
        );

        let retained = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].height, 1);
        assert_eq!(retained[0].proposal_hash, "h1");

        let retained_checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(retained_checkpoints.len(), 1);
        assert_eq!(retained_checkpoints[0].height, 1);
        assert_eq!(retained_checkpoints[0].state_root_hex, "r1");
        assert_eq!(retained_checkpoints[0].wal_entry_hash_hex, h1);

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 2);
        assert_eq!(wal.last_round, 4);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_discards_corrupt_committed_tail_without_claiming_metadata_only_recovery() {
        let wal_dir = temp_wal_dir("recover-corrupt-committed-tail-non-metadata-only");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 2,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let corrupt_e2 = WalMeta {
            height: 2,
            round: 5,
            proposal_hash: "h2-corrupt".into(),
            committed: true,
            state_root_hex: "r2-corrupt".into(),
            prev_hash_hex: Some("not-the-retained-tip".into()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, corrupt_e2]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            }],
        )
        .unwrap();
        fs::write(
            wal_file(&wal_dir),
            r#"next_height = 99
last_round = 42
locked_block_hash = "stale-lock"
"#,
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.next_height, 2);
        assert_eq!(recovered.checkpoint_height_retained, Some(1));
        assert_eq!(recovered.wal_entries_retained, 1);
        assert_eq!(recovered.restored_lock.as_deref(), Some("h1"));

        let retained = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].height, 1);
        assert_eq!(retained[0].proposal_hash, "h1");

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 2);
        assert_eq!(wal.last_round, 2);
        assert_eq!(wal.locked_block_hash.as_deref(), Some("h1"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_corrupt_committed_tail_prunes_future_checkpoint_metadata() {
        let wal_dir = temp_wal_dir("recover-corrupt-committed-tail-prunes-future-checkpoint");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 2,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let corrupt_e2 = WalMeta {
            height: 2,
            round: 5,
            proposal_hash: "h2-corrupt".into(),
            committed: true,
            state_root_hex: "r2-corrupt".into(),
            prev_hash_hex: Some("not-the-retained-tip".into()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, corrupt_e2.clone()]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "stale-r1".into(),
                    wal_entry_hash_hex: "stale-h1".into(),
                },
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1.clone(),
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2-corrupt".into(),
                    wal_entry_hash_hex: corrupt_e2.content_hash_hex(),
                },
            ],
        )
        .unwrap();
        fs::write(
            wal_file(&wal_dir),
            r#"next_height = 99
last_round = 42
locked_block_hash = "stale-lock"
"#,
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.next_height, 2);
        assert_eq!(recovered.checkpoint_height_retained, Some(1));
        assert_eq!(recovered.wal_entries_retained, 1);
        assert_eq!(recovered.restored_lock.as_deref(), Some("h1"));

        let retained = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].height, 1);
        assert_eq!(retained[0].proposal_hash, "h1");

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 1);
        assert_eq!(checkpoints[0].height, 1);
        assert_eq!(checkpoints[0].state_root_hex, "r1");
        assert_eq!(checkpoints[0].wal_entry_hash_hex, h1);
        assert!(checkpoints
            .iter()
            .all(|cp| cp.wal_entry_hash_hex != corrupt_e2.content_hash_hex()));

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 2);
        assert_eq!(wal.last_round, 2);
        assert_eq!(wal.locked_block_hash.as_deref(), Some("h1"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_mixed_committed_tail_marks_metadata_only_even_if_later_tail_is_corrupt() {
        let wal_dir = temp_wal_dir("recover-mixed-committed-tail-metadata-only");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 2,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 3,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let corrupt_e3 = WalMeta {
            height: 3,
            round: 4,
            proposal_hash: "h3-corrupt".into(),
            committed: true,
            state_root_hex: "r3-corrupt".into(),
            prev_hash_hex: Some("not-the-retained-tip".into()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e2, corrupt_e3]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            }],
        )
        .unwrap();
        fs::write(
            wal_file(&wal_dir),
            r#"next_height = 99
last_round = 42
locked_block_hash = "stale-lock"
"#,
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert!(recovered.truncated);
        assert!(
            recovered.metadata_only_recovery,
            "discarding any directly continuing committed tail beyond the retained checkpoint must stay fail-closed even if later tail entries are corrupt"
        );
        assert_eq!(recovered.next_height, 2);
        assert_eq!(recovered.checkpoint_height_retained, Some(1));
        assert_eq!(recovered.wal_entries_retained, 1);
        assert!(recovered.restored_lock.is_none());

        let retained = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].height, 1);
        assert_eq!(retained[0].proposal_hash, "h1");

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 2);
        assert_eq!(wal.last_round, 2);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_mixed_committed_tail_prunes_stale_duplicate_checkpoint_at_retained_height() {
        let wal_dir =
            temp_wal_dir("recover-mixed-committed-tail-prunes-stale-checkpoint-at-retained-height");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 2,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 3,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let corrupt_e3 = WalMeta {
            height: 3,
            round: 4,
            proposal_hash: "h3-corrupt".into(),
            committed: true,
            state_root_hex: "r3-corrupt".into(),
            prev_hash_hex: Some("not-the-retained-tip".into()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e2, corrupt_e3]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1-stale".into(),
                    wal_entry_hash_hex: "stale-h1".into(),
                },
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1.clone(),
                },
            ],
        )
        .unwrap();
        fs::write(
            wal_file(&wal_dir),
            r#"next_height = 99
last_round = 42
locked_block_hash = "stale-lock"
"#,
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert!(recovered.truncated);
        assert!(recovered.metadata_only_recovery);
        assert_eq!(recovered.next_height, 2);
        assert_eq!(recovered.checkpoint_height_retained, Some(1));
        assert_eq!(recovered.wal_entries_retained, 1);
        assert!(recovered.restored_lock.is_none());

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 1);
        assert_eq!(checkpoints[0].height, 1);
        assert_eq!(checkpoints[0].state_root_hex, "r1");
        assert_eq!(checkpoints[0].wal_entry_hash_hex, h1);

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 2);
        assert_eq!(wal.last_round, 2);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_metadata_only_error_reports_retained_wal_entries() {
        let wal_dir = temp_wal_dir("recover-metadata-only-error");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        persist_wal_meta_entries(&wal_dir, &[e1]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            }],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 1);
        assert_eq!(recovered.checkpoint_height_retained, Some(1));
        assert_eq!(recovered.next_height, 2);

        let err = metadata_only_recovery_error(&wal_dir, &recovered);
        assert!(err.contains("retained 1 committed WAL entry through height 1"));
        assert!(err.contains("last retained checkpoint: 1"));
        assert!(err.contains("checkpoint_evidence: checkpoint_height=1 state_root=r1 wal_entry_hash="));
        assert!(err.contains("checkpoint_da_surface: da_light_surface=checkpoint-wal-v1"));
        assert_eq!(crate::recovery::metadata_only_recovery_error(&wal_dir, &recovered), err);

        let would_require_snapshot_restore = recovered
            .checkpoint_height_retained
            .map(|checkpoint_height| checkpoint_height < recovered.next_height.saturating_sub(1))
            .unwrap_or(recovered.wal_entries_retained > 0);
        assert!(
            !would_require_snapshot_restore,
            "fully checkpointed WAL metadata must not be escalated to metadata-only recovery misuse"
        );

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn metadata_only_recovery_error_surfaces_da_unavailability_reason_when_checkpoint_wal_linkage_is_missing() {
        let wal_dir = temp_wal_dir("recover-da-surface-missing-wal-linkage");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        persist_wal_meta_entries(&wal_dir, &[e1]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: "ff".repeat(32),
            }],
        )
        .unwrap();

        let recovered = RecoveredWalState {
            wal_entries_retained: 1,
            next_height: 2,
            restored_round: 0,
            last_checkpoint: Some(CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: "ff".repeat(32),
            }),
            metadata_only_recovery: true,
            checkpoint_height_retained: Some(1),
        };

        let err = metadata_only_recovery_error(&wal_dir, &recovered);
        assert!(err.contains("checkpoint_da_surface: unavailable:no_matching_wal_entry"));
        assert_eq!(crate::recovery::metadata_only_recovery_error(&wal_dir, &recovered), err);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_fully_checkpointed_wal_rewrites_stale_consensus_wal_lock_to_retained_tip() {
        let wal_dir = temp_wal_dir("recover-fully-checkpointed-no-wal-rewrite");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 7,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        persist_wal_meta_entries(&wal_dir, &[e1]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 1,
                wal_entry_hash_hex: h1,
                state_root_hex: "r1".into(),
            }],
        )
        .unwrap();
        fs::write(
            wal_file(&wal_dir),
            r#"next_height = 99
last_round = 42
locked_block_hash = "stale-lock"
"#,
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.next_height, 2);
        assert_eq!(recovered.checkpoint_height_retained, Some(1));
        assert_eq!(recovered.restored_lock.as_deref(), Some("h1"));
        assert_ne!(recovered.restored_lock.as_deref(), Some("stale-lock"));

        let wal_raw = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal_raw).unwrap();
        assert_eq!(wal.next_height, 2);
        assert_eq!(wal.last_round, 7);
        assert_eq!(wal.locked_block_hash.as_deref(), Some("h1"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_fully_checkpointed_multiple_entries_rewrite_stale_consensus_wal_to_retained_tip() {
        let wal_dir = temp_wal_dir("recover-fully-checkpointed-multi-no-wal-rewrite");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 3,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 4,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();
        persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    wal_entry_hash_hex: h1,
                    state_root_hex: "r1".into(),
                },
                CheckpointMeta {
                    height: 2,
                    wal_entry_hash_hex: h2,
                    state_root_hex: "r2".into(),
                },
            ],
        )
        .unwrap();
        fs::write(
            wal_file(&wal_dir),
            r#"next_height = 99
last_round = 42
locked_block_hash = "stale-lock"
"#,
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert!(!recovered.metadata_only_recovery);
        assert!(!recovered.truncated);
        assert_eq!(recovered.next_height, 3);
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(recovered.restored_lock.as_deref(), Some("h2"));
        assert_ne!(recovered.restored_lock.as_deref(), Some("stale-lock"));

        let wal_raw = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal_raw).unwrap();
        assert_eq!(wal.next_height, 3);
        assert_eq!(wal.last_round, 4);
        assert_eq!(wal.locked_block_hash.as_deref(), Some("h2"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_rewrites_consensus_wal_to_retained_checkpoint_after_metadata_only_truncation() {
        let wal_dir = temp_wal_dir("recover-metadata-only-tail-rewrites-consensus-wal");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 3,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 4,
            proposal_hash: "h2".into(),
            committed: false,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 1,
                wal_entry_hash_hex: h1,
                state_root_hex: "r1".into(),
            }],
        )
        .unwrap();
        fs::write(
            wal_file(&wal_dir),
            r#"next_height = 99
last_round = 42
locked_block_hash = "stale-lock"
"#,
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert!(recovered.metadata_only_recovery);
        assert!(recovered.truncated);
        assert_eq!(recovered.next_height, 2);
        assert!(recovered.restored_lock.is_none());

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 2);
        assert_eq!(wal.last_round, 3);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_truncates_uncheckpointed_tail_without_claiming_metadata_recovery() {
        let wal_dir = temp_wal_dir("recover-truncates-uncheckpointed-tail");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            }],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert!(recovered.truncated);
        assert!(
            recovered.metadata_only_recovery,
            "committed WAL beyond last checkpoint must stay fail-closed until StateStore restore/replay exists"
        );
        assert_eq!(recovered.next_height, 2);
        assert_eq!(recovered.checkpoint_height_retained, Some(1));
        assert!(recovered.restored_lock.is_none());
        assert_eq!(recovered.wal_entries_retained, 1);
        assert_eq!(load_wal_meta_entries(&wal_dir).unwrap().len(), 1);
        assert_eq!(load_checkpoint_meta(&wal_dir).unwrap().len(), 1);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_allows_non_metadata_only_restart_when_checkpoint_covers_last_wal_entry() {
        let wal_dir = temp_wal_dir("recover-fully-checkpointed");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();
        persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1,
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2,
                },
            ],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.next_height, 3);
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(recovered.restored_lock.as_deref(), Some("h2"));
        assert_eq!(recovered.wal_entries_retained, 2);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_fully_checkpointed_max_height_saturates_next_height() {
        let wal_dir = temp_wal_dir("recover-fully-checkpointed-max-height");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: u64::MAX,
            round: 0,
            proposal_hash: "h-max".into(),
            committed: true,
            state_root_hex: "r-max".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        persist_wal_meta_entries(&wal_dir, &[e1]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: u64::MAX,
                state_root_hex: "r-max".into(),
                wal_entry_hash_hex: h1,
            }],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.next_height, u64::MAX);
        assert_eq!(recovered.checkpoint_height_retained, Some(u64::MAX));
        assert_eq!(recovered.restored_lock.as_deref(), Some("h-max"));
        assert_eq!(recovered.wal_entries_retained, 1);

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, u64::MAX);
        assert_eq!(wal.last_round, 0);
        assert_eq!(wal.locked_block_hash.as_deref(), Some("h-max"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_fully_checkpointed_max_height_keeps_join_rejoin_summary_saturated() {
        let recovered = RecoveredWalState {
            next_height: u64::MAX,
            restored_lock: Some("h-max".into()),
            last_checkpoint: Some(CheckpointMeta {
                height: u64::MAX,
                state_root_hex: "r-max".into(),
                wal_entry_hash_hex: "h-max".into(),
            }),
            truncated: false,
            metadata_only_recovery: false,
            wal_entries_retained: 1,
            checkpoint_height_retained: Some(u64::MAX),
        };

        assert_eq!(
            retained_wal_summary(&recovered),
            format!(
                "retained 1 committed WAL entry through height {}",
                u64::MAX - 1
            )
        );
        assert_eq!(
            recovery_startup_summary(&recovered),
            format!(
                "retained_wal_entries=1 checkpoint_height_retained={} checkpoint_tip_relation=aligned next_startup_height={} wal_tail_truncated=false metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume",
                u64::MAX,
                u64::MAX,
            )
        );
    }

    #[test]
    fn ensure_recoverable_wal_state_allows_truncated_checkpoint_only_rejoin_bootstrap_at_max_height() {
        let wal_dir = temp_wal_dir("recover-guard-max-truncated-checkpoint-only-rejoin");
        fs::create_dir_all(&wal_dir).unwrap();

        let recovered = RecoveredWalState {
            next_height: u64::MAX,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: u64::MAX - 1,
                state_root_hex: "r-max-minus-1".into(),
                wal_entry_hash_hex: "h-max-minus-1".into(),
            }),
            truncated: true,
            metadata_only_recovery: false,
            wal_entries_retained: 0,
            checkpoint_height_retained: Some(u64::MAX - 1),
        };

        ensure_recoverable_wal_state(&wal_dir, &recovered).expect(
            "truncated max-height checkpoint-only rejoin bootstrap should remain recoverable",
        );
        assert_eq!(
            retained_wal_summary(&recovered),
            format!(
                "retained no committed WAL entries (last retained checkpoint height {}); repaired WAL tail required truncation",
                u64::MAX - 1,
            )
        );
        assert_eq!(
            recovery_startup_summary(&recovered),
            format!(
                "retained_wal_entries=0 checkpoint_height_retained={} checkpoint_tip_relation=checkpoint_only:{} next_startup_height={} wal_tail_truncated=true metadata_only_recovery=false join_rejoin_status=ready:checkpoint_only_rejoin_bootstrap_after_tail_repair",
                u64::MAX - 1,
                u64::MAX - 1,
                u64::MAX,
            )
        );

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_metadata_only_error_reports_absent_checkpoint() {
        let wal_dir = temp_wal_dir("recover-metadata-only-error-no-checkpoint");
        fs::create_dir_all(&wal_dir).unwrap();

        let recovered = RecoveredWalState {
            next_height: 1,
            restored_lock: None,
            last_checkpoint: None,
            truncated: false,
            metadata_only_recovery: true,
            wal_entries_retained: 0,
            checkpoint_height_retained: None,
        };

        let err = metadata_only_recovery_error(&wal_dir, &recovered);

        assert!(err.contains("retained no committed WAL entries"));
        assert!(!err.contains("through height 0"));
        assert!(err.contains("last retained checkpoint: none"));
        assert!(err.contains("next startup height: 1"));
        assert!(err.contains(
            "incident clue: retained_wal_entries=0 checkpoint_height_retained=none checkpoint_tip_relation=none next_startup_height=1 wal_tail_truncated=false metadata_only_recovery=true"
        ));
        assert!(err.contains("checkpoint_evidence: none"));
        assert!(err.contains("checkpoint_da_surface: unavailable:no_checkpoint"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_metadata_only_error_reports_plural_retained_entries_and_height() {
        let wal_dir = temp_wal_dir("recover-metadata-only-error-plural");
        fs::create_dir_all(&wal_dir).unwrap();

        let recovered = RecoveredWalState {
            next_height: 3,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: "h1".into(),
            }),
            truncated: true,
            metadata_only_recovery: true,
            wal_entries_retained: 2,
            checkpoint_height_retained: Some(1),
        };

        let err = metadata_only_recovery_error(&wal_dir, &recovered);

        assert!(err.contains("retained 2 committed WAL entries through height 2"));
        assert!(err.contains("checkpoint lags retained WAL tip by 1 block"));
        assert!(err.contains("repaired WAL tail required truncation"));
        assert!(err.contains("last retained checkpoint: 1"));
        assert!(err.contains("next startup height: 3"));
        assert!(err.contains(
            "does not yet restore application StateStore snapshots or replay committed blocks"
        ));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_metadata_only_error_reports_missing_checkpoint_metadata() {
        let wal_dir = temp_wal_dir("recover-metadata-only-error-no-checkpoint-metadata");
        fs::create_dir_all(&wal_dir).unwrap();

        let recovered = RecoveredWalState {
            next_height: 2,
            restored_lock: None,
            last_checkpoint: None,
            truncated: false,
            metadata_only_recovery: true,
            wal_entries_retained: 1,
            checkpoint_height_retained: None,
        };

        let err = metadata_only_recovery_error(&wal_dir, &recovered);

        assert!(err.contains("retained 1 committed WAL entry through height 1"));
        assert!(err.contains("no retained checkpoint metadata"));
        assert!(err.contains("last retained checkpoint: none"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_metadata_only_error_does_not_overstate_uncommitted_tail_as_committed() {
        let wal_dir = temp_wal_dir("recover-metadata-only-error-uncommitted-tail");
        fs::create_dir_all(&wal_dir).unwrap();

        let recovered = RecoveredWalState {
            next_height: 2,
            restored_lock: None,
            last_checkpoint: None,
            truncated: true,
            metadata_only_recovery: true,
            wal_entries_retained: 1,
            checkpoint_height_retained: None,
        };

        let err = metadata_only_recovery_error(&wal_dir, &recovered);

        assert!(err.contains("retained 1 WAL entry through height 1"));
        assert!(!err.contains("retained 1 committed WAL entry through height 1"));
        assert!(err.contains("last retained checkpoint: none"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_metadata_only_error_reports_singular_checkpoint_ahead_block() {
        let wal_dir = temp_wal_dir("recover-metadata-only-error-ahead-block-singular");
        fs::create_dir_all(&wal_dir).unwrap();

        let recovered = RecoveredWalState {
            next_height: 12,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 12,
                state_root_hex: "r12".into(),
                wal_entry_hash_hex: "h12".into(),
            }),
            truncated: true,
            metadata_only_recovery: true,
            wal_entries_retained: 2,
            checkpoint_height_retained: Some(12),
        };

        let err = metadata_only_recovery_error(&wal_dir, &recovered);

        assert!(err.contains("retained 2 committed WAL entries through height 11"));
        assert!(err.contains(
            "retained checkpoint height 12 is ahead of retained WAL tip height 11 by 1 block"
        ));
        assert!(!err.contains(
            "retained checkpoint height 12 is ahead of retained WAL tip height 11 by 1 blocks"
        ));
        assert!(err.contains("last retained checkpoint: 12"));
        assert!(err.contains("next startup height: 12"));
        assert!(err.contains(
            "incident clue: retained_wal_entries=2 checkpoint_height_retained=12 checkpoint_tip_relation=ahead:1 next_startup_height=12 wal_tail_truncated=true metadata_only_recovery=true join_rejoin_status=blocked:metadata_only_recovery"
        ));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn ensure_recoverable_wal_state_rejects_metadata_only_recovery() {
        let wal_dir = temp_wal_dir("recover-guard-metadata-only");
        fs::create_dir_all(&wal_dir).unwrap();

        let recovered = RecoveredWalState {
            next_height: 4,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: "h2".into(),
            }),
            truncated: true,
            metadata_only_recovery: true,
            wal_entries_retained: 3,
            checkpoint_height_retained: Some(2),
        };

        let err = ensure_recoverable_wal_state(&wal_dir, &recovered).unwrap_err();
        let err = format!("{err:#}");

        assert!(err.contains("refusing metadata-only recovery"));
        assert!(err.contains("retained 3 committed WAL entries through height 3"));
        assert!(err.contains("checkpoint lags retained WAL tip by 1 block"));
        assert!(err.contains("last retained checkpoint: 2"));
        assert!(err.contains("next startup height: 4"));
        assert!(err.contains(
            "incident clue: retained_wal_entries=3 checkpoint_height_retained=2 checkpoint_tip_relation=behind:1 next_startup_height=4 wal_tail_truncated=true metadata_only_recovery=true join_rejoin_status=blocked:metadata_only_recovery"
        ));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_metadata_only_error_reports_aligned_retained_wal_operator_action() {
        let wal_dir = temp_wal_dir("recover-metadata-only-error-aligned-retained-wal");
        fs::create_dir_all(&wal_dir).unwrap();

        let recovered = RecoveredWalState {
            next_height: 12,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 11,
                state_root_hex: "r11".into(),
                wal_entry_hash_hex: "h11".into(),
            }),
            truncated: false,
            metadata_only_recovery: true,
            wal_entries_retained: 2,
            checkpoint_height_retained: Some(11),
        };

        let err = metadata_only_recovery_error(&wal_dir, &recovered);

        assert!(err.contains("retained 2 committed WAL entries through height 11"));
        assert!(err.contains("last retained checkpoint: 11"));
        assert!(err.contains("next startup height: 12"));
        assert!(err.contains(
            "incident clue: retained_wal_entries=2 checkpoint_height_retained=11 checkpoint_tip_relation=aligned next_startup_height=12 wal_tail_truncated=false metadata_only_recovery=true join_rejoin_status=blocked:metadata_only_recovery"
        ));
        assert!(err.contains(
            "operator action: restore the corresponding application snapshot before retrying join/rejoin; do not resume from metadata alone"
        ));
        assert_eq!(crate::recovery::metadata_only_recovery_error(&wal_dir, &recovered), err);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn ensure_recoverable_wal_state_allows_fully_checkpointed_recovery() {
        let wal_dir = temp_wal_dir("recover-guard-safe");
        fs::create_dir_all(&wal_dir).unwrap();

        let recovered = RecoveredWalState {
            next_height: 3,
            restored_lock: Some("h2".into()),
            last_checkpoint: Some(CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: "h2".into(),
            }),
            truncated: false,
            metadata_only_recovery: false,
            wal_entries_retained: 2,
            checkpoint_height_retained: Some(2),
        };

        ensure_recoverable_wal_state(&wal_dir, &recovered).unwrap();

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_without_checkpoint_and_without_retained_wal_is_not_metadata_only() {
        let wal_dir = temp_wal_dir("recover-no-checkpoint-no-retained-wal");
        fs::create_dir_all(&wal_dir).unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert!(!recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 0);
        assert_eq!(recovered.checkpoint_height_retained, None);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_clears_stale_consensus_wal_when_no_verified_metadata_exists() {
        let wal_dir = temp_wal_dir("recover-stale-consensus-wal-only");
        fs::create_dir_all(&wal_dir).unwrap();
        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 42,
                last_round: 9,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 0);
        assert_eq!(recovered.checkpoint_height_retained, None);

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn resolve_wal_dir_auto_isolates_existing_builtin_default_state() {
        let root = temp_wal_dir("default-wal-root");
        let base = root.join(DEFAULT_BFT_WAL_DIR);
        fs::create_dir_all(&base).unwrap();
        fs::write(wal_file(&base), "existing").unwrap();

        let args = Args {
            config: "configs/node1.toml".into(),
            block_ms: 1000,
            max_blocks: 10,
            demo_tasks: 2,
            demo_keys: 2,
            parallel_workers: 4,
            txs_per_block: 4,
            validators: 4,
            byzantine: 0,
            bft_max_rounds: 3,
            bft_fault_rounds: 0,
            bft_missed_proposal_threshold: 2,
            bft_leader_penalty_rounds: 2,
            bft_round_change_backoff_ms: 5,
            bft_round_change_backoff_max_ms: 40,
            bft_wal_dir: DEFAULT_BFT_WAL_DIR.into(),
            bft_wal_mode: WalDirMode::Auto,
            bft_checkpoint_interval: 5,
            pouw_timeout_scan: true,
            pouw_timeout_scan_every_blocks: 1,
            enable_da_ordering_decouple: false,
            rl_advisor_shadow: false,
            rl_advisor_shadow_topk: 4,
        };

        let cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&root).unwrap();
        let (resolved, notice) = resolve_wal_dir(&args).unwrap();
        std::env::set_current_dir(cwd).unwrap();

        assert_ne!(resolved, PathBuf::from(DEFAULT_BFT_WAL_DIR));
        assert!(resolved.starts_with(PathBuf::from(DEFAULT_BFT_WAL_DIR)));
        assert!(notice.unwrap().contains("isolating this run"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn resolve_wal_dir_auto_keeps_explicit_custom_dir_even_if_state_exists() {
        let wal_dir = temp_wal_dir("custom-reuse");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(wal_file(&wal_dir), "existing").unwrap();

        let args = Args {
            config: "configs/node1.toml".into(),
            block_ms: 1000,
            max_blocks: 10,
            demo_tasks: 2,
            demo_keys: 2,
            parallel_workers: 4,
            txs_per_block: 4,
            validators: 4,
            byzantine: 0,
            bft_max_rounds: 3,
            bft_fault_rounds: 0,
            bft_missed_proposal_threshold: 2,
            bft_leader_penalty_rounds: 2,
            bft_round_change_backoff_ms: 5,
            bft_round_change_backoff_max_ms: 40,
            bft_wal_dir: wal_dir.display().to_string(),
            bft_wal_mode: WalDirMode::Auto,
            bft_checkpoint_interval: 5,
            pouw_timeout_scan: true,
            pouw_timeout_scan_every_blocks: 1,
            enable_da_ordering_decouple: false,
            rl_advisor_shadow: false,
            rl_advisor_shadow_topk: 4,
        };

        let (resolved, notice) = resolve_wal_dir(&args).unwrap();
        assert_eq!(resolved, wal_dir);
        assert!(notice.is_none());

        let _ = fs::remove_dir_all(&resolved);
    }

    #[test]
    fn resolve_wal_dir_auto_isolates_builtin_default_when_only_checkpoint_metadata_exists() {
        let root = temp_wal_dir("default-wal-checkpoint-only-root");
        let base = root.join(DEFAULT_BFT_WAL_DIR);
        fs::create_dir_all(&base).unwrap();
        fs::write(checkpoint_file(&base), "existing").unwrap();

        let args = Args {
            config: "configs/node1.toml".into(),
            block_ms: 1000,
            max_blocks: 10,
            demo_tasks: 2,
            demo_keys: 2,
            parallel_workers: 4,
            txs_per_block: 4,
            validators: 4,
            byzantine: 0,
            bft_max_rounds: 3,
            bft_fault_rounds: 0,
            bft_missed_proposal_threshold: 2,
            bft_leader_penalty_rounds: 2,
            bft_round_change_backoff_ms: 5,
            bft_round_change_backoff_max_ms: 40,
            bft_wal_dir: DEFAULT_BFT_WAL_DIR.into(),
            bft_wal_mode: WalDirMode::Auto,
            bft_checkpoint_interval: 5,
            pouw_timeout_scan: true,
            pouw_timeout_scan_every_blocks: 1,
            enable_da_ordering_decouple: false,
            rl_advisor_shadow: false,
            rl_advisor_shadow_topk: 4,
        };

        let cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&root).unwrap();
        let (resolved, notice) = resolve_wal_dir(&args).unwrap();
        std::env::set_current_dir(cwd).unwrap();

        assert_ne!(resolved, PathBuf::from(DEFAULT_BFT_WAL_DIR));
        assert!(resolved.starts_with(PathBuf::from(DEFAULT_BFT_WAL_DIR)));
        assert!(notice.unwrap().contains("isolating this run"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn resolve_wal_dir_fail_if_exists_rejects_stale_state() {
        let wal_dir = temp_wal_dir("fail-if-exists");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(wal_meta_file(&wal_dir), "existing").unwrap();

        let args = Args {
            config: "configs/node1.toml".into(),
            block_ms: 1000,
            max_blocks: 10,
            demo_tasks: 2,
            demo_keys: 2,
            parallel_workers: 4,
            txs_per_block: 4,
            validators: 4,
            byzantine: 0,
            bft_max_rounds: 3,
            bft_fault_rounds: 0,
            bft_missed_proposal_threshold: 2,
            bft_leader_penalty_rounds: 2,
            bft_round_change_backoff_ms: 5,
            bft_round_change_backoff_max_ms: 40,
            bft_wal_dir: wal_dir.display().to_string(),
            bft_wal_mode: WalDirMode::FailIfExists,
            bft_checkpoint_interval: 5,
            pouw_timeout_scan: true,
            pouw_timeout_scan_every_blocks: 1,
            enable_da_ordering_decouple: false,
            rl_advisor_shadow: false,
            rl_advisor_shadow_topk: 4,
        };

        let err = resolve_wal_dir(&args).unwrap_err();
        assert!(err
            .to_string()
            .contains("refusing to reuse existing BFT WAL state"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn resolve_wal_dir_fail_if_exists_rejects_checkpoint_only_state() {
        let wal_dir = temp_wal_dir("fail-if-exists-checkpoint-only");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(checkpoint_file(&wal_dir), "existing").unwrap();

        let args = Args {
            config: "configs/node1.toml".into(),
            block_ms: 1000,
            max_blocks: 10,
            demo_tasks: 2,
            demo_keys: 2,
            parallel_workers: 4,
            txs_per_block: 4,
            validators: 4,
            byzantine: 0,
            bft_max_rounds: 3,
            bft_fault_rounds: 0,
            bft_missed_proposal_threshold: 2,
            bft_leader_penalty_rounds: 2,
            bft_round_change_backoff_ms: 5,
            bft_round_change_backoff_max_ms: 40,
            bft_wal_dir: wal_dir.display().to_string(),
            bft_wal_mode: WalDirMode::FailIfExists,
            bft_checkpoint_interval: 5,
            pouw_timeout_scan: true,
            pouw_timeout_scan_every_blocks: 1,
            enable_da_ordering_decouple: false,
            rl_advisor_shadow: false,
            rl_advisor_shadow_topk: 4,
        };

        let err = resolve_wal_dir(&args).unwrap_err();
        assert!(err
            .to_string()
            .contains("refusing to reuse existing BFT WAL state"));

        let _ = fs::remove_dir_all(&wal_dir);
    }
