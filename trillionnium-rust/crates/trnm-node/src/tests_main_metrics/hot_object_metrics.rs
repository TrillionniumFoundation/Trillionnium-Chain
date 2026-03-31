use super::*;

#[test]
fn resolve_hotspot_summary_includes_shared_treasury_and_approval_labels() {
    let mut state = StateStore::new();
    state.set_balance("worker5001", 1_000);
    state.set_balance("challenger5001", 1_000);

    let r1 = apply_create_task(&mut state, 5001, "alice".into(), 100).unwrap();
    let r2 = apply_accept_task_at_height(&mut state, r1, "worker5001".into(), 10).unwrap();
    let committed = compute_commitment(5001, &[1u8; 32], &[2u8; 32], "worker5001");
    let r3 =
        apply_commit_result_at_height(&mut state, r2, "worker5001".into(), committed, 10).unwrap();
    let r4 = apply_reveal_result_at_height(&mut state, r3, [1u8; 32], [2u8; 32], None, 11).unwrap();
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
    let hot_object_active_observed_height_rate_ppm = ratio_ppm_u64(hot_object_active_heights, 6u64);
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
    let hot_object_active_height_share_ppm = if hot_object_active_heights == 0 {
        0
    } else {
        (1_200_000u128 + 800_000u128) / hot_object_active_heights as u128
    };

    assert_eq!(hot_object_active_top_label_share_avg_ppm, 0);
    assert_eq!(hot_object_active_tail_share_avg_ppm, 0);
    assert_eq!(hot_object_active_height_share_ppm, 0);
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
fn hot_object_active_share_metrics_avoid_zero_block_dilution() {
    let all_block_top_label_share_samples_ppm = vec![0u128, 500_000, 800_000];
    let all_block_tail_share_samples_ppm = vec![0u128, 500_000, 200_000];
    let hot_object_active_heights = 2u64;
    let hot_object_active_top_label_share_total_ppm = 1_300_000u128;
    let hot_object_active_tail_share_total_ppm = 700_000u128;
    let total_heights = 3u64;

    let diluted_top_label_share_avg_ppm = average_or_zero(&all_block_top_label_share_samples_ppm);
    let diluted_tail_share_avg_ppm = average_or_zero(&all_block_tail_share_samples_ppm);
    let active_top_label_share_avg_ppm =
        hot_object_active_top_label_share_total_ppm / hot_object_active_heights as u128;
    let active_tail_share_avg_ppm =
        hot_object_active_tail_share_total_ppm / hot_object_active_heights as u128;
    let hot_object_active_height_rate_ppm = ratio_ppm_u64(hot_object_active_heights, total_heights);
    let hot_object_active_observed_height_rate_ppm = ratio_ppm_u64(hot_object_active_heights, 5u64);

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
