use super::*;
use std::sync::{Mutex, MutexGuard, OnceLock};
use trnm_types::{ObjectRef, Tx};

fn o(id: u64) -> ObjectRef {
    ObjectRef { id, version: 1 }
}

fn tx(id: u64, r: Vec<ObjectRef>, w: Vec<ObjectRef>) -> Tx {
    Tx {
        id,
        read_set: r,
        write_set: w,
        payload: vec![],
    }
}

fn env_lock() -> MutexGuard<'static, ()> {
    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    match ENV_LOCK.get_or_init(|| Mutex::new(())).lock() {
        Ok(guard) => guard,
        Err(err) => err.into_inner(),
    }
}

struct EnvGuard {
    key: &'static str,
    old: Option<String>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let old = std::env::var(key).ok();
        unsafe {
            std::env::set_var(key, value);
        }
        Self { key, old }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        if let Some(v) = &self.old {
            unsafe {
                std::env::set_var(self.key, v);
            }
        } else {
            unsafe {
                std::env::remove_var(self.key);
            }
        }
    }
}

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
    let _env = env_lock();
    let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", "8");

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
fn hot_bucket_interleave_ignores_empty_access_noise_around_single_signaled_lane() {
    let mut txs = vec![
        tx(91, vec![], vec![]),      // empty-access noise would default to bucket 0
        tx(92, vec![], vec![o(1)]),  // real signaled lane bucket 1 under fanout=4
        tx(93, vec![], vec![]),      // same empty-access noise
        tx(94, vec![], vec![o(5)]),  // same real lane bucket 1 under fanout=4
    ];

    reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
    // Empty-access txs carry no conflict-domain hint. If all signaled traffic is
    // still a single lane, preserve ingress order instead of letting bucket-0
    // empties manufacture a fake second lane and perturb isolation.
    assert_eq!(
        txs.iter().map(|t| t.id).collect::<Vec<_>>(),
        vec![91, 92, 93, 94]
    );
}

#[test]
fn hot_bucket_interleave_ignores_empty_access_noise_around_single_role_flipped_mixed_lane() {
    let mut txs = vec![
        tx(95, vec![], vec![]),          // empty-access noise defaults to bucket 0
        tx(96, vec![o(0)], vec![o(8)]),  // canonical mixed lane {0,8}
        tx(97, vec![], vec![]),          // same empty-access noise
        tx(98, vec![o(8)], vec![o(0)]),  // same mixed lane after read/write role flip
    ];

    reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
    // Empty-access txs carry no lane signal, and equivalent mixed domains should
    // keep one canonical bucket even when read/write roles flip. If all signaled
    // traffic still belongs to that single lane, preserve ingress order.
    assert_eq!(
        txs.iter().map(|t| t.id).collect::<Vec<_>>(),
        vec![95, 96, 97, 98]
    );
}

#[test]
fn hot_bucket_interleave_preserves_single_role_flipped_mixed_lane_under_clamped_fanout() {
    let _env = env_lock();
    let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", "4");

    let mut txs = vec![
        tx(99, vec![], vec![]),           // empty-access noise still defaults to bucket 0
        tx(100, vec![o(1)], vec![o(5)]),  // canonical mixed lane {1,5} -> bucket 1 when fanout=4
        tx(101, vec![], vec![]),          // same empty-access noise
        tx(102, vec![o(5)], vec![o(1)]),  // same mixed lane after read/write role flip
    ];

    reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
    // Shrinking hot-bucket fanout must not let bucket-0 empty-access noise
    // fabricate a second lane when the only signaled mixed domain remains
    // canonical and stable across read/write role flips.
    assert_eq!(
        txs.iter().map(|t| t.id).collect::<Vec<_>>(),
        vec![99, 100, 101, 102]
    );
}

#[test]
fn hot_bucket_interleave_preserves_single_signaled_lane_under_input_clamped_fanout_with_empty_noise() {
    let _env = env_lock();
    let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", "8");

    let mut txs = vec![
        tx(103, vec![], vec![]),      // empty-access noise defaults to bucket 0
        tx(104, vec![], vec![o(1)]),  // only signaled lane once fanout clamps to len=5
        tx(105, vec![], vec![]),      // same empty-access noise
        tx(106, vec![], vec![o(6)]),  // same signaled lane under input-clamped fanout=5
        tx(107, vec![], vec![]),      // same empty-access noise
    ];

    reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
    // Input-size fanout clamping (`min(TRNM_HOT_BUCKETS, txs.len())`) must keep
    // empty-access bucket-0 noise from fabricating a second lane when all
    // signaled traffic still belongs to one real lane.
    assert_eq!(
        txs.iter().map(|t| t.id).collect::<Vec<_>>(),
        vec![103, 104, 105, 106, 107]
    );
}

#[test]
fn hot_bucket_interleave_keeps_real_two_lane_rotation_despite_empty_access_noise() {
    let _env = env_lock();

    let mut txs = vec![
        tx(108, vec![], vec![]),     // empty-access noise bucket 0
        tx(109, vec![], vec![]),     // same empty-access noise bucket 0
        tx(110, vec![], vec![o(1)]), // real signaled lane bucket 1 under fanout=6
        tx(111, vec![], vec![o(7)]), // same real signaled lane bucket 1 under fanout=6
        tx(112, vec![], vec![o(2)]), // second real signaled lane bucket 2 under fanout=6
        tx(113, vec![], vec![o(8)]), // same second signaled lane bucket 2 under fanout=6
    ];

    reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
    // Empty-access txs should not suppress interleave once there are two real
    // signaled lanes. Keep the stable bucket-0 noise, but still rotate between
    // the actual signaled lanes so lane isolation is preserved.
    assert_eq!(
        txs.iter().map(|t| t.id).collect::<Vec<_>>(),
        vec![108, 110, 112, 111, 113, 109]
    );
}

#[test]
fn hot_bucket_interleave_preserves_single_modulo_signaled_lane_with_empty_noise() {
    let _env = env_lock();
    let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", "6");

    let mut txs = vec![
        tx(114, vec![], vec![]),      // empty-access noise bucket 0
        tx(115, vec![], vec![o(5)]),  // real signaled lane bucket 5 under fanout=6
        tx(116, vec![], vec![]),      // more empty-access noise bucket 0
        tx(117, vec![], vec![o(11)]), // same real signaled lane bucket 5 via modulo path
        tx(118, vec![], vec![o(17)]), // same real signaled lane bucket 5 via modulo path
        tx(119, vec![], vec![]),      // keeps input len >= requested modulo fanout
    ];

    reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
    // Non-power-of-two fanout still uses the modulo reduction path. Empty-access
    // noise must not fabricate a second lane when all signaled traffic lands on
    // the same real bucket there.
    assert_eq!(
        txs.iter().map(|t| t.id).collect::<Vec<_>>(),
        vec![114, 115, 116, 117, 118, 119]
    );
}

#[test]
fn hot_bucket_interleave_fails_closed_to_stable_order_when_fanout_collapses_to_one_bucket() {
    let _env = env_lock();
    let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", "1");

    let mut txs = vec![
        tx(111, vec![], vec![]),
        tx(112, vec![o(5), o(13)], vec![o(7)]),
        tx(113, vec![], vec![o(1 + (1u64 << 40))]),
        tx(114, vec![o(7)], vec![o(5)]),
    ];

    reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
    // When ops clamps hot-bucket fanout to a single bucket, interleave should
    // fail closed to stable ingress order instead of fabricating pseudo-lanes
    // from mixed-domain or high-bit keys.
    assert_eq!(
        txs.iter().map(|t| t.id).collect::<Vec<_>>(),
        vec![111, 112, 113, 114]
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
fn hot_bucket_hint_power_of_two_fast_path_stays_stable_for_high_bit_role_flips() {
    let high_a = 1u64 << 40;
    let high_b = (1u64 << 55) + 3;
    let high_c = (1u64 << 55) + 11;
    let buckets_n = 64usize;
    let write_heavy = tx(
        91,
        vec![o(high_b), o(high_c), o(high_c)],
        vec![o(high_a), o(high_a), o(high_b)],
    );
    let read_heavy = tx(
        92,
        vec![o(high_a), o(high_a), o(high_b)],
        vec![o(high_b), o(high_c), o(high_c)],
    );
    let expected = ((high_a ^ high_b.rotate_left(7)) & ((buckets_n as u64) - 1)) as usize;

    // Even on the power-of-two fast path, duplicate-heavy equivalent mixed
    // domains must keep the same executor lane when read/write roles flip.
    assert_eq!(hot_bucket_hint(&write_heavy, buckets_n), expected);
    assert_eq!(hot_bucket_hint(&read_heavy, buckets_n), expected);
}

#[test]
fn hot_bucket_hint_modulo_path_stays_stable_for_high_bit_role_flips() {
    let high_a = 1u64 << 40;
    let high_b = (1u64 << 55) + 3;
    let high_c = (1u64 << 55) + 11;
    let buckets_n = 97usize;
    let write_heavy = tx(
        93,
        vec![o(high_b), o(high_c), o(high_c)],
        vec![o(high_a), o(high_a), o(high_b)],
    );
    let read_heavy = tx(
        94,
        vec![o(high_a), o(high_a), o(high_b)],
        vec![o(high_b), o(high_c), o(high_c)],
    );
    let expected = ((high_a ^ high_b.rotate_left(7)) % buckets_n as u64) as usize;

    // The non-power-of-two modulo path must preserve the same canonical
    // object-domain lane for equivalent mixed domains even when read/write
    // roles flip under wide high-bit keys.
    assert_eq!(hot_bucket_hint(&write_heavy, buckets_n), expected);
    assert_eq!(hot_bucket_hint(&read_heavy, buckets_n), expected);
}

#[test]
fn hot_bucket_hint_is_stable_for_single_write_single_read_role_flips() {
    let buckets_n = 97usize;
    let write_then_read = tx(951, vec![o(2)], vec![o(1)]);
    let read_then_write = tx(952, vec![o(1)], vec![o(2)]);
    let expected = ((1u64 ^ 2u64.rotate_left(7)) % buckets_n as u64) as usize;

    // Equivalent one-write/one-read mixed domains should stay in the same
    // scheduler lane even when read/write roles flip. Previously the fallback
    // second-key probe skipped the lone opposite-domain key and drifted.
    assert_eq!(hot_bucket_hint(&write_then_read, buckets_n), expected);
    assert_eq!(hot_bucket_hint(&read_then_write, buckets_n), expected);
}

#[test]
fn hot_bucket_hint_stays_stable_when_echoed_primary_has_asymmetric_secondary_width() {
    let buckets_n = 97usize;
    let write_heavy = tx(
        961,
        vec![o(5), o(9), o(11), o(11)],
        vec![o(5), o(7), o(7)],
    );
    let read_heavy = tx(
        962,
        vec![o(5), o(7), o(7)],
        vec![o(5), o(9), o(11), o(11)],
    );
    let expected = ((5u64 ^ 7u64.rotate_left(7)) % buckets_n as u64) as usize;

    // If the canonical primary key is echoed across read/write domains but one
    // side contributes a narrower non-primary footprint, role flips must still
    // preserve the same lane anchor instead of drifting to the wider side's
    // local secondary.
    assert_eq!(hot_bucket_hint(&write_heavy, buckets_n), expected);
    assert_eq!(hot_bucket_hint(&read_heavy, buckets_n), expected);
}

#[test]
fn hot_bucket_hint_treats_object_zero_as_real_canonical_lane_under_role_flips() {
    let buckets_n = 97usize;
    let write_heavy = tx(971, vec![o(0), o(9), o(9)], vec![o(0), o(5), o(5)]);
    let read_heavy = tx(972, vec![o(0), o(5), o(5)], vec![o(0), o(9), o(9)]);
    let expected = ((0u64 ^ 5u64.rotate_left(7)) % buckets_n as u64) as usize;

    // Object id 0 is a valid execution-domain key, not a sentinel. Equivalent
    // mixed domains should keep the same canonical lane even when read/write
    // roles flip and duplicate-heavy echoes surround the zero-key object.
    assert_eq!(hot_bucket_hint(&write_heavy, buckets_n), expected);
    assert_eq!(hot_bucket_hint(&read_heavy, buckets_n), expected);
}

#[test]
fn hot_bucket_hint_power_of_two_path_keeps_zero_primary_stable_under_asymmetric_role_flips() {
    let buckets_n = 64usize;
    let write_heavy = tx(973, vec![o(0), o(17), o(33), o(33)], vec![o(0), o(9), o(9)]);
    let read_heavy = tx(974, vec![o(0), o(9), o(9)], vec![o(0), o(17), o(33), o(33)]);
    let expected = ((0u64 ^ 9u64.rotate_left(7)) & ((buckets_n as u64) - 1)) as usize;

    // The power-of-two reduction path should preserve the same canonical lane
    // when object id 0 is the primary execution-domain key and the echoed
    // non-primary footprint is asymmetric across read/write role flips.
    assert_eq!(hot_bucket_hint(&write_heavy, buckets_n), expected);
    assert_eq!(hot_bucket_hint(&read_heavy, buckets_n), expected);
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
