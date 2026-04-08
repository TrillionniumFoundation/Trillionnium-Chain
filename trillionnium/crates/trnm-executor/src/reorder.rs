use trnm_types::Tx;

use crate::env_config::hot_bucket_count;
use crate::GroupingStrategy;

pub(crate) fn hot_bucket_hint(tx: &Tx, buckets_n: usize) -> usize {
    // Defensive guard: keep helper total for misconfigured callers and tests.
    // Production reorder path always uses buckets_n>=1, but this preserves
    // fail-closed deterministic behavior if future call sites collapse fanout
    // to zero/one bucket.
    if buckets_n <= 1 {
        return 0;
    }

    #[inline]
    fn next_distinct_access_key(tx: &Tx, first: u64) -> u64 {
        tx.write_set
            .iter()
            .chain(tx.read_set.iter())
            .map(|obj| obj.id)
            .find(|&id| id != first)
            .unwrap_or(0)
    }

    // Keep hash mixing deterministic across targets (32/64-bit) by using a
    // fixed-width integer domain before reducing to bucket count.
    let key_a = tx
        .write_set
        .first()
        .or_else(|| tx.read_set.first())
        .map(|o| o.id)
        .unwrap_or(0);
    let key_b = next_distinct_access_key(tx, key_a);
    let mixed = key_a ^ key_b.rotate_left(7);
    if buckets_n.is_power_of_two() {
        // Fast-path hot scheduler probes: avoid division in the common power-of-two
        // bucket layout while keeping deterministic bucket mapping.
        (mixed as usize) & (buckets_n - 1)
    } else {
        // Reduce in u64-space first; casting mixed directly to usize would truncate
        // high bits on 32-bit targets and skew bucket selection under wide key domains.
        (mixed % buckets_n as u64) as usize
    }
}

pub(crate) fn reorder_for_strategy(txs: &mut [Tx], strategy: GroupingStrategy) {
    match strategy {
        GroupingStrategy::Original => {}
        GroupingStrategy::FootprintDesc => {
            txs.sort_by_key(|tx| {
                let footprint = tx.read_set.len() + tx.write_set.len();
                (std::cmp::Reverse(footprint), tx.id)
            });
        }
        GroupingStrategy::WriteFirst => {
            txs.sort_by_key(|tx| {
                (
                    std::cmp::Reverse(tx.write_set.len()),
                    std::cmp::Reverse(tx.read_set.len()),
                    tx.id,
                )
            });
        }
        GroupingStrategy::WriteLast => {
            txs.sort_by_key(|tx| {
                (
                    tx.write_set.len(),
                    std::cmp::Reverse(tx.read_set.len()),
                    tx.id,
                )
            });
        }
        GroupingStrategy::HotBucketInterleave => {
            // Heuristic reorder; see should_use_hot_bucket_interleave for adaptive trigger.
            // Heuristic: shard txs by a stable access-key hint, then round-robin buckets.
            // Goal is to avoid long same-key streaks in input order under hotspot workloads.
            if txs.len() <= 1 {
                return;
            }
            // Micro-batches (2-3 txs) do not benefit from bucket interleave and only pay
            // allocation/probing overhead. Keep original order for better free-ingress latency
            // at low concurrency while preserving deterministic behavior.
            if txs.len() < 4 {
                return;
            }
            // Free-ingress (empty read/write sets) has no conflict-domain signal to
            // interleave on. Skip bucket materialization/probing and preserve stable
            // order to reduce scheduler overhead on the no-access hot path.
            if txs
                .iter()
                .all(|tx| tx.read_set.is_empty() && tx.write_set.is_empty())
            {
                return;
            }
            // Cap bucket fanout by input size: for tiny batches this avoids allocating
            // and probing empty buckets while preserving the same interleave semantics.
            let buckets_n = hot_bucket_count().min(txs.len());
            // Misconfigured/trimmed bucket fanout can collapse to a single bucket,
            // where interleave degenerates to identity while still paying probe cost.
            if buckets_n <= 1 {
                return;
            }
            let mut bucket_depths = vec![0usize; buckets_n];
            let mut tx_bucket_hints = Vec::with_capacity(txs.len());
            let mut non_empty_buckets = 0usize;
            let mut signaled_non_empty_buckets = 0usize;
            let mut signaled_bucket_seen = vec![false; buckets_n];

            for tx in txs.iter() {
                // First pass: count occupancy only. This lets hotspot/singleton
                // short-circuits bail out before cloning tx payloads into buckets.
                let bucket = hot_bucket_hint(tx, buckets_n);
                tx_bucket_hints.push(bucket);
                if bucket_depths[bucket] == 0 {
                    non_empty_buckets += 1;
                }
                bucket_depths[bucket] += 1;

                // Empty-access txs do not carry any conflict-domain hint. Keep them
                // from fabricating an extra bucket-0 lane in mixed batches when all
                // signaled traffic still belongs to one actual hot bucket.
                if !(tx.read_set.is_empty() && tx.write_set.is_empty()) && !signaled_bucket_seen[bucket]
                {
                    signaled_bucket_seen[bucket] = true;
                    signaled_non_empty_buckets += 1;
                }
            }

            // Degenerate hotspot fast path: if all txs landed in the same bucket,
            // round-robin interleave would reproduce the original order while paying
            // n-bucket probing overhead. Keep stable input order for lower scheduler cost.
            if non_empty_buckets <= 1 {
                return;
            }
            // Mixed batches with only one real conflict-domain lane and some empty-access
            // txs also gain nothing from interleave. Empty txs should not synthesize a
            // second bucket-0 lane that perturbs otherwise stable single-lane ingress.
            if signaled_non_empty_buckets <= 1 {
                return;
            }
            // Free-ingress fast path: when every non-empty bucket is singleton,
            // interleave cannot reduce same-key streaks and only adds probe/rotation
            // overhead. Preserve stable input order to reduce micro-batch scheduler cost.
            // We already track how many buckets are non-empty; equality here means each
            // tx landed in its own bucket (all singleton), avoiding an extra max-depth scan.
            if non_empty_buckets == txs.len() {
                return;
            }

            // Reuse the precomputed first bucket hint instead of re-hashing the
            // first tx on the hot-path round-robin seed selection.
            let first_hint = tx_bucket_hints.first().copied().unwrap_or(0);

            // Stable round-robin with move semantics (avoid per-tx clone cost).
            let n = buckets_n;
            let mut merged = Vec::with_capacity(txs.len());
            // Under highly skewed hot-bucket loads, start from the sparsest non-empty
            // bucket so low-volume conflict domains are serviced promptly instead of
            // always waiting behind the dominant lane at cycle start.
            let sparse_start = {
                let mut min_non_zero = usize::MAX;
                let mut max_depth = 0usize;
                for &depth in &bucket_depths {
                    if depth == 0 {
                        continue;
                    }
                    max_depth = max_depth.max(depth);
                    min_non_zero = min_non_zero.min(depth);
                }

                if min_non_zero != usize::MAX && max_depth >= min_non_zero.saturating_mul(2) {
                    // When multiple equally sparse buckets exist, rotate the sparse
                    // anti-starvation seed around the first hot-key hint to avoid
                    // repeatedly preferring the lowest bucket index.
                    let mut best_idx = None;
                    let mut best_distance = usize::MAX;
                    let mut best_counter_clockwise = usize::MAX;
                    for (idx, &depth) in bucket_depths.iter().enumerate() {
                        if depth != min_non_zero {
                            continue;
                        }
                        let clockwise = (idx + n - first_hint) % n;
                        let counter_clockwise = (first_hint + n - idx) % n;
                        let distance = clockwise.min(counter_clockwise);
                        if distance < best_distance
                            || (distance == best_distance
                                && counter_clockwise < best_counter_clockwise)
                        {
                            best_distance = distance;
                            best_counter_clockwise = counter_clockwise;
                            best_idx = Some(idx);
                        }
                    }
                    best_idx
                } else {
                    None
                }
            };

            let mut buckets: Vec<Vec<Tx>> = bucket_depths
                .iter()
                .map(|depth| Vec::with_capacity(*depth))
                .collect();
            for (tx, bucket) in txs.iter().cloned().zip(tx_bucket_hints.into_iter()) {
                // Prefer write-set as stronger conflict signal; fold a second key when present
                // to reduce bucket skew for mixed workloads.
                buckets[bucket].push(tx);
            }

            // Keep insertion order inside each bucket (already stable by input stream);
            // avoid extra O(n log n) sorting cost.
            let mut iters: Vec<std::vec::IntoIter<Tx>> =
                buckets.into_iter().map(|b| b.into_iter()).collect();
            // Seed the initial bucket probe from either sparse anti-starvation hint
            // or first tx hot-key hint so repeated batches do not always favor bucket 0.
            let mut rr_start = sparse_start.unwrap_or(first_hint);
            // Rotate the round-robin start bucket each pass to reduce consistent
            // first-bucket preference under uneven bucket depths.
            loop {
                let mut moved = false;
                for step in 0..n {
                    let idx = (rr_start + step) % n;
                    if let Some(tx) = iters[idx].next() {
                        merged.push(tx);
                        moved = true;
                    }
                }
                if !moved {
                    break;
                }
                rr_start = (rr_start + 1) % n;
            }

            for (dst, src) in txs.iter_mut().zip(merged.into_iter()) {
                *dst = src;
            }
        }
        GroupingStrategy::AutoAdaptive => {
            // Auto strategy is resolved before calling reorder_for_strategy.
        }
        GroupingStrategy::AggressiveGreedy => {
            // Keep original order by default; aggressive placement logic handles packing.
        }
    }
}
