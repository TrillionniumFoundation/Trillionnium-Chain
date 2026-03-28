use super::*;

#[test]
fn hot_bucket_interleave_seeds_initial_round_from_first_hot_key() {
    let mut txs = vec![
        tx(501, vec![], vec![o(5)]),  // bucket 5 when TRNM_HOT_BUCKETS=8
        tx(101, vec![], vec![o(0)]),  // bucket 0
        tx(102, vec![], vec![o(8)]),  // bucket 0
        tx(103, vec![], vec![o(16)]), // bucket 0
    ];

    reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
    assert_eq!(txs.first().map(|t| t.id), Some(501));
}

#[test]
fn hot_bucket_interleave_empty_batch_is_noop() {
    let mut txs = Vec::<Tx>::new();
    reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
    assert!(txs.is_empty());
}

#[test]
fn hot_bucket_interleave_prefers_sparse_non_empty_bucket_under_heavy_skew() {
    let mut txs = vec![
        tx(201, vec![], vec![o(0)]),  // hot bucket (depth 3)
        tx(202, vec![], vec![o(8)]),  // same hot bucket
        tx(203, vec![], vec![o(16)]), // same hot bucket
        tx(204, vec![], vec![o(3)]),  // sparse bucket (depth 1)
    ];

    reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
    assert_eq!(txs.first().map(|t| t.id), Some(204));
}

#[test]
fn hot_bucket_interleave_prefers_a_sparse_bucket_under_moderate_two_to_one_skew() {
    let mut txs = vec![
        tx(301, vec![], vec![o(0)]), // hot bucket (depth 2)
        tx(302, vec![], vec![o(8)]), // same hot bucket
        tx(303, vec![], vec![o(3)]), // sparse bucket A (depth 1)
        tx(304, vec![], vec![o(5)]), // sparse bucket B (depth 1); keeps len >= 4
    ];

    reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
    assert!(matches!(txs.first().map(|t| t.id), Some(303 | 304)));
}

#[test]
fn hot_bucket_interleave_keeps_first_hint_when_skew_is_below_two_to_one_threshold() {
    let mut txs = vec![
        tx(391, vec![], vec![o(0)]),  // first hot hint bucket 0
        tx(392, vec![], vec![o(8)]),  // same bucket (depth 3)
        tx(393, vec![], vec![o(16)]), // same bucket (depth 3)
        tx(394, vec![], vec![o(1)]),  // second bucket (depth 2)
        tx(395, vec![], vec![o(9)]),  // second bucket (depth 2)
    ];

    reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
    // Sparse anti-starvation seeding should only engage at >=2x skew. For 3:2,
    // keep first-hot-hint ordering and deterministic pass rotation from bucket 0.
    assert_eq!(
        txs.iter().map(|t| t.id).collect::<Vec<_>>(),
        vec![391, 393, 392, 395, 394]
    );
}

#[test]
fn hot_bucket_interleave_sparse_tie_rotates_from_first_hot_hint() {
    let mut txs = vec![
        tx(401, vec![], vec![o(5)]),  // first hot hint bucket 5
        tx(402, vec![], vec![o(13)]), // same hot bucket (depth 2)
        tx(403, vec![], vec![o(1)]),  // sparse bucket 1
        tx(404, vec![], vec![o(6)]),  // sparse bucket 6
    ];

    reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
    // Both bucket 1 and 6 are equally sparse; prefer the one nearest the first
    // hot-key hint to avoid fixed low-index sparse bias across batches.
    assert_eq!(txs.first().map(|t| t.id), Some(404));
}

#[test]
fn hot_bucket_interleave_sparse_tie_prefers_nearest_bucket_across_ring_wrap() {
    let mut txs = vec![
        tx(411, vec![], vec![o(0)]), // first hot hint bucket 0
        tx(412, vec![], vec![o(8)]), // same hot bucket (depth 2)
        tx(413, vec![], vec![o(1)]), // sparse bucket +1 clockwise
        tx(414, vec![], vec![o(7)]), // sparse bucket -1 counter-clockwise
    ];

    reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
    // When sparse buckets straddle the ring boundary, prefer the truly nearest
    // bucket instead of always scanning clockwise from the first hint.
    assert_eq!(txs.first().map(|t| t.id), Some(414));
}

#[test]
fn hot_bucket_interleave_keeps_first_hint_when_it_is_already_sparse_seed() {
    let mut txs = vec![
        tx(421, vec![], vec![o(5)]),  // first hot hint bucket 5 (also sparse)
        tx(422, vec![], vec![o(0)]),  // dominant bucket 0 depth 4
        tx(423, vec![], vec![o(8)]),  // dominant bucket 0 depth 4
        tx(424, vec![], vec![o(16)]), // dominant bucket 0 depth 4
        tx(425, vec![], vec![o(24)]), // dominant bucket 0 depth 4
        tx(426, vec![], vec![o(6)]),  // equally sparse bucket 6 depth 1
        tx(427, vec![], vec![o(1)]),  // sparse bucket 1 depth 1
        tx(428, vec![], vec![o(2)]),  // sparse bucket 2 depth 1
    ];

    reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
    // Keep len >= default bucket fanout (8) so object ids map directly to buckets.
    // If the first-hot hint already points at one of the sparsest buckets,
    // keep that bucket as the anti-starvation seed (distance 0) instead of
    // rotating away to a neighboring sparse lane.
    assert_eq!(txs.first().map(|t| t.id), Some(421));
}

#[test]
fn hot_bucket_interleave_keeps_first_sparse_seed_when_bucket_fanout_is_clamped() {
    let _env = env_lock();
    let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", "4");

    let mut txs = vec![
        tx(431, vec![], vec![o(5)]),  // first hot hint bucket 1 (also sparse)
        tx(432, vec![], vec![o(0)]),  // dominant bucket 0 depth 4
        tx(433, vec![], vec![o(4)]),  // dominant bucket 0 depth 4
        tx(434, vec![], vec![o(8)]),  // dominant bucket 0 depth 4
        tx(435, vec![], vec![o(12)]), // dominant bucket 0 depth 4
        tx(436, vec![], vec![o(6)]),  // equally sparse bucket 2 depth 1
        tx(437, vec![], vec![o(7)]),  // equally sparse bucket 3 depth 1
    ];

    reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
    // Even when ops trims fanout below the default 8 buckets, the sparse-seed
    // anti-starvation path should still anchor to the first sparse hint instead
    // of drifting toward another equally sparse bucket after modulo remapping.
    assert_eq!(txs.first().map(|t| t.id), Some(431));
}

#[test]
fn hot_bucket_interleave_skips_micro_batches_to_preserve_low_latency_order() {
    let mut txs = vec![
        tx(21, vec![], vec![o(8)]),
        tx(22, vec![], vec![o(1)]),
        tx(23, vec![], vec![o(16)]),
    ];

    reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
    assert_eq!(
        txs.iter().map(|t| t.id).collect::<Vec<_>>(),
        vec![21, 22, 23]
    );
}

#[test]
fn hot_bucket_interleave_short_circuits_empty_access_batches() {
    let mut txs = vec![
        tx(31, vec![], vec![]),
        tx(32, vec![], vec![]),
        tx(33, vec![], vec![]),
        tx(34, vec![], vec![]),
    ];

    reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
    // Empty-access free-ingress has no conflict-domain signal; keep stable
    // order and avoid bucket allocation/probing overhead.
    assert_eq!(
        txs.iter().map(|t| t.id).collect::<Vec<_>>(),
        vec![31, 32, 33, 34]
    );
}

#[test]
fn hot_bucket_interleave_short_circuits_single_bucket_hotspot() {
    let mut txs = vec![
        tx(61, vec![], vec![o(8)]),
        tx(62, vec![], vec![o(16)]),
        tx(63, vec![], vec![o(24)]),
        tx(64, vec![], vec![o(32)]),
    ];

    reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
    // All keys map to bucket 0 under the default 8-bucket layout; interleave
    // is a no-op and should return early without extra round-robin passes.
    assert_eq!(
        txs.iter().map(|t| t.id).collect::<Vec<_>>(),
        vec![61, 62, 63, 64]
    );
}

#[test]
fn hot_bucket_interleave_short_circuits_all_singleton_buckets() {
    let mut txs = vec![
        tx(71, vec![], vec![o(0)]),
        tx(72, vec![], vec![o(1)]),
        tx(73, vec![], vec![o(2)]),
        tx(74, vec![], vec![o(3)]),
    ];

    reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
    // With singleton occupancy across non-empty buckets there are no same-key
    // streaks to break; keep ingress order and avoid extra round-robin probing.
    assert_eq!(
        txs.iter().map(|t| t.id).collect::<Vec<_>>(),
        vec![71, 72, 73, 74]
    );
}

#[test]
fn hot_bucket_interleave_short_circuits_single_mixed_domain_lane_without_role_flip_drift() {
    let mut txs = vec![
        tx(81, vec![o(0)], vec![o(8)]),
        tx(82, vec![o(8)], vec![o(0)]),
        tx(83, vec![o(16)], vec![o(24)]),
        tx(84, vec![o(24)], vec![o(16)]),
    ];

    reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
    // Equivalent mixed execution domains should keep the same canonical lane hint
    // even when read/write roles flip. If every tx still lands in one bucket,
    // the single-bucket hotspot fast path must preserve ingress order instead of
    // doing a pointless round-robin reorder.
    assert_eq!(
        txs.iter().map(|t| t.id).collect::<Vec<_>>(),
        vec![81, 82, 83, 84]
    );
}

#[test]
fn hot_bucket_hint_fail_closes_to_bucket_zero_when_fanout_collapses() {
    let mixed = tx(1, vec![o(5), o(13)], vec![o(7)]);
    let write_only = tx(2, vec![], vec![o(1 + (1u64 << 40))]);

    // Misconfigured callers can collapse the fanout to zero or one bucket.
    // Keep the lane hint total and deterministic instead of deriving a drift-prone
    // modulo path from the mixed execution domain.
    assert_eq!(hot_bucket_hint(&mixed, 0), 0);
    assert_eq!(hot_bucket_hint(&mixed, 1), 0);
    assert_eq!(hot_bucket_hint(&write_only, 0), 0);
    assert_eq!(hot_bucket_hint(&write_only, 1), 0);
}

#[test]
fn hot_bucket_hint_uses_full_u64_keyspace_before_bucket_reduce() {
    let buckets_n = 97usize;
    let low = tx(1, vec![], vec![o(1)]);
    let high = tx(2, vec![], vec![o(1 + (1u64 << 40))]);

    let low_bucket = hot_bucket_hint(&low, buckets_n);
    let high_bucket = hot_bucket_hint(&high, buckets_n);

    // Distinct high bits must influence bucket selection; truncating to usize
    // before modulo would collapse these on 32-bit targets.
    assert_ne!(low_bucket, high_bucket);
    assert_eq!(
        high_bucket,
        ((1 + (1u64 << 40)) % buckets_n as u64) as usize
    );
}

#[test]
fn hot_bucket_hint_power_of_two_fast_path_matches_modulo_mapping() {
    let txs = [
        tx(1, vec![], vec![o(1)]),
        tx(2, vec![], vec![o(1 + (1u64 << 40))]),
        tx(3, vec![o(7)], vec![]),
        tx(4, vec![o(11), o(13)], vec![]),
        tx(5, vec![], vec![o(23), o(29)]),
    ];
    let buckets_n = 8usize;

    for t in txs {
        let expected = ((t
            .write_set
            .first()
            .or_else(|| t.read_set.first())
            .map(|o| o.id)
            .unwrap_or(0)
            ^ t.write_set
                .get(1)
                .or_else(|| t.read_set.get(1))
                .map(|o| o.id)
                .unwrap_or(0)
                .rotate_left(7))
            % buckets_n as u64) as usize;
        assert_eq!(hot_bucket_hint(&t, buckets_n), expected);
    }
}

#[test]
fn hot_bucket_hint_zero_bucket_count_fails_closed_to_bucket_zero() {
    let t = tx(999, vec![], vec![o(42)]);
    assert_eq!(hot_bucket_hint(&t, 0), 0);
}

#[test]
fn hot_bucket_hint_single_bucket_count_fails_closed_to_bucket_zero() {
    let t = tx(999, vec![o(7)], vec![o(42)]);
    assert_eq!(hot_bucket_hint(&t, 1), 0);
}
