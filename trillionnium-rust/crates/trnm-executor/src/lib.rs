use std::collections::{HashMap, HashSet};
use trnm_types::{ObjectRef, Tx};

#[cfg(test)]
#[path = "tests/hot_bucket_tests.rs"]
mod hot_bucket_tests;

#[derive(Debug, Clone, Copy)]
pub enum GroupingStrategy {
    Original,
    FootprintDesc,
    WriteFirst,
    WriteLast,
    HotBucketInterleave,
    AutoAdaptive,
    AggressiveGreedy,
}

#[derive(Debug, Clone)]
pub struct GroupingProfile {
    pub tx_count: usize,
    pub group_count: usize,
    pub grouped_count: usize,
    pub max_group_size: usize,
    pub min_group_size: usize,
    pub avg_group_size: f64,
    pub hot_object_share: f64,
    pub conflict_checks: usize,
    pub conflict_hits: usize,
    pub candidate_groups_scanned: usize,
    pub retry_fallback_new_groups: usize,
    // Aggressive-only stage attribution counters.
    pub stage_ww_checks: usize,
    pub stage_ww_hits: usize,
    pub stage_wr_checks: usize,
    pub stage_wr_hits: usize,
    pub stage_rw_checks: usize,
    pub stage_rw_hits: usize,
}

#[inline]
fn ratio_usize(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

impl GroupingProfile {
    #[inline]
    pub fn conflict_checks_per_tx(&self) -> f64 {
        ratio_usize(self.conflict_checks, self.tx_count)
    }

    #[inline]
    pub fn conflict_hits_per_tx(&self) -> f64 {
        ratio_usize(self.conflict_hits, self.tx_count)
    }

    #[inline]
    pub fn candidate_groups_per_tx(&self) -> f64 {
        ratio_usize(self.candidate_groups_scanned, self.tx_count)
    }

    #[inline]
    pub fn retry_fallback_new_group_share(&self) -> f64 {
        ratio_usize(self.retry_fallback_new_groups, self.tx_count)
    }

    #[inline]
    pub fn retry_fallback_share_of_new_groups(&self) -> f64 {
        ratio_usize(self.retry_fallback_new_groups, self.group_count)
    }

    #[inline]
    pub fn retry_fallback_share_of_retry_hits(&self) -> f64 {
        ratio_usize(self.retry_fallback_new_groups, self.conflict_hits)
    }

    #[inline]
    pub fn retry_fallback_scan_share(&self) -> f64 {
        ratio_usize(
            self.retry_fallback_new_groups,
            self.candidate_groups_scanned,
        )
    }

    #[inline]
    pub fn retry_pressure(&self) -> f64 {
        ratio_usize(self.conflict_hits, self.group_count)
    }

    #[inline]
    pub fn reused_group_placements(&self) -> usize {
        self.tx_count.saturating_sub(self.group_count)
    }

    #[inline]
    pub fn reused_group_share(&self) -> f64 {
        ratio_usize(self.reused_group_placements(), self.tx_count)
    }

    #[inline]
    pub fn new_group_share(&self) -> f64 {
        ratio_usize(self.group_count, self.tx_count)
    }

    #[inline]
    pub fn candidate_groups_per_retry_hit(&self) -> f64 {
        ratio_usize(self.candidate_groups_scanned, self.conflict_hits)
    }

    #[inline]
    pub fn candidate_groups_per_reused_placement(&self) -> f64 {
        ratio_usize(
            self.candidate_groups_scanned,
            self.reused_group_placements(),
        )
    }

    #[inline]
    pub fn retry_scan_reuse_rate(&self) -> f64 {
        ratio_usize(
            self.reused_group_placements(),
            self.candidate_groups_scanned,
        )
    }

    #[inline]
    pub fn retry_reuse_salvage_rate(&self) -> f64 {
        ratio_usize(
            self.reused_group_placements(),
            self.reused_group_placements() + self.retry_fallback_new_groups,
        )
    }

    #[inline]
    pub fn retry_scan_hit_rate(&self) -> f64 {
        ratio_usize(self.conflict_hits, self.candidate_groups_scanned)
    }

    #[inline]
    pub fn retry_scan_misses(&self) -> usize {
        self.candidate_groups_scanned
            .saturating_sub(self.conflict_hits)
    }

    #[inline]
    pub fn retry_scan_miss_rate(&self) -> f64 {
        ratio_usize(self.retry_scan_misses(), self.candidate_groups_scanned)
    }

    #[inline]
    pub fn retry_scan_misses_per_tx(&self) -> f64 {
        ratio_usize(self.retry_scan_misses(), self.tx_count)
    }

    #[inline]
    pub fn retry_scan_misses_per_group(&self) -> f64 {
        ratio_usize(self.retry_scan_misses(), self.group_count)
    }

    #[inline]
    pub fn retry_scan_overhang_per_hit(&self) -> f64 {
        ratio_usize(self.retry_scan_misses(), self.conflict_hits)
    }

    #[inline]
    pub fn retry_scan_overhang_per_reused_placement(&self) -> f64 {
        ratio_usize(self.retry_scan_misses(), self.reused_group_placements())
    }

    #[inline]
    pub fn retry_fallback_share_of_retry_misses(&self) -> f64 {
        ratio_usize(self.retry_fallback_new_groups, self.retry_scan_misses())
    }

    #[inline]
    pub fn ww_retry_hit_rate(&self) -> f64 {
        ratio_usize(self.stage_ww_hits, self.stage_ww_checks)
    }

    #[inline]
    pub fn wr_retry_hit_rate(&self) -> f64 {
        ratio_usize(self.stage_wr_hits, self.stage_wr_checks)
    }

    #[inline]
    pub fn rw_retry_hit_rate(&self) -> f64 {
        ratio_usize(self.stage_rw_hits, self.stage_rw_checks)
    }

    #[inline]
    pub fn ww_retry_hits_per_tx(&self) -> f64 {
        ratio_usize(self.stage_ww_hits, self.tx_count)
    }

    #[inline]
    pub fn wr_retry_hits_per_tx(&self) -> f64 {
        ratio_usize(self.stage_wr_hits, self.tx_count)
    }

    #[inline]
    pub fn rw_retry_hits_per_tx(&self) -> f64 {
        ratio_usize(self.stage_rw_hits, self.tx_count)
    }

    #[inline]
    pub fn ww_retry_share(&self) -> f64 {
        ratio_usize(self.stage_ww_hits, self.conflict_hits)
    }

    #[inline]
    pub fn wr_retry_share(&self) -> f64 {
        ratio_usize(self.stage_wr_hits, self.conflict_hits)
    }

    #[inline]
    pub fn rw_retry_share(&self) -> f64 {
        ratio_usize(self.stage_rw_hits, self.conflict_hits)
    }

    #[inline]
    pub fn dominant_retry_stage(&self) -> &'static str {
        let ranking = [
            ("ww", self.stage_ww_hits),
            ("wr", self.stage_wr_hits),
            ("rw", self.stage_rw_hits),
        ];

        let max_hits = ranking.iter().map(|(_, hits)| *hits).max().unwrap_or(0);

        if max_hits == 0 {
            return "none";
        }

        let leaders = ranking.iter().filter(|(_, hits)| *hits == max_hits).count();

        if leaders > 1 {
            "mixed"
        } else {
            ranking
                .iter()
                .find(|(_, hits)| *hits == max_hits)
                .map(|(label, _)| *label)
                .unwrap_or("none")
        }
    }

    #[inline]
    pub fn dominant_retry_share(&self) -> f64 {
        let dominant_hits = [self.stage_ww_hits, self.stage_wr_hits, self.stage_rw_hits]
            .into_iter()
            .max()
            .unwrap_or(0);
        ratio_usize(dominant_hits, self.conflict_hits)
    }

    #[inline]
    pub fn dominant_attributed_retry_share(&self) -> f64 {
        let dominant_hits = [self.stage_ww_hits, self.stage_wr_hits, self.stage_rw_hits]
            .into_iter()
            .max()
            .unwrap_or(0);
        ratio_usize(dominant_hits, self.attributed_retry_hits())
    }

    #[inline]
    pub fn dominant_retry_lead_hits(&self) -> usize {
        let mut ranking = [self.stage_ww_hits, self.stage_wr_hits, self.stage_rw_hits];
        ranking.sort_unstable_by(|a, b| b.cmp(a));
        ranking[0].saturating_sub(ranking[1])
    }

    #[inline]
    pub fn dominant_retry_lead_share(&self) -> f64 {
        ratio_usize(self.dominant_retry_lead_hits(), self.conflict_hits)
    }

    #[inline]
    pub fn dominant_attributed_retry_lead_share(&self) -> f64 {
        ratio_usize(
            self.dominant_retry_lead_hits(),
            self.attributed_retry_hits(),
        )
    }

    #[inline]
    pub fn attributed_retry_hits(&self) -> usize {
        self.stage_ww_hits + self.stage_wr_hits + self.stage_rw_hits
    }

    #[inline]
    pub fn unattributed_retry_hits(&self) -> usize {
        self.conflict_hits
            .saturating_sub(self.attributed_retry_hits())
    }

    #[inline]
    pub fn unattributed_retry_share(&self) -> f64 {
        ratio_usize(self.unattributed_retry_hits(), self.conflict_hits)
    }

    #[inline]
    pub fn retry_attribution_coverage(&self) -> f64 {
        ratio_usize(
            self.attributed_retry_hits().min(self.conflict_hits),
            self.conflict_hits,
        )
    }

    #[inline]
    pub fn retry_stage_overlap_hits(&self) -> usize {
        self.attributed_retry_hits()
            .saturating_sub(self.conflict_hits)
    }

    #[inline]
    pub fn retry_stage_overlap_share(&self) -> f64 {
        ratio_usize(self.retry_stage_overlap_hits(), self.conflict_hits)
    }

    #[inline]
    pub fn retry_stage_overlap_share_of_attributed(&self) -> f64 {
        ratio_usize(
            self.retry_stage_overlap_hits(),
            self.attributed_retry_hits(),
        )
    }

    #[inline]
    pub fn singly_attributed_retry_hits(&self) -> usize {
        self.attributed_retry_hits()
            .saturating_sub(self.retry_stage_overlap_hits())
    }

    #[inline]
    pub fn singly_attributed_retry_share(&self) -> f64 {
        ratio_usize(self.singly_attributed_retry_hits(), self.conflict_hits)
    }

    #[inline]
    pub fn singly_attributed_retry_share_of_attributed(&self) -> f64 {
        ratio_usize(
            self.singly_attributed_retry_hits(),
            self.attributed_retry_hits(),
        )
    }

    #[inline]
    pub fn retry_stage_concentration(&self) -> f64 {
        if self.conflict_hits == 0 {
            return 0.0;
        }

        let ww = self.ww_retry_share();
        let wr = self.wr_retry_share();
        let rw = self.rw_retry_share();
        (ww * ww) + (wr * wr) + (rw * rw)
    }

    #[inline]
    pub fn retry_stage_mix_entropy(&self) -> f64 {
        let attributed_hits = self.attributed_retry_hits();
        if attributed_hits == 0 {
            return 0.0;
        }

        let weights = [self.stage_ww_hits, self.stage_wr_hits, self.stage_rw_hits];
        let entropy = weights
            .into_iter()
            .filter(|hits| *hits > 0)
            .map(|hits| {
                let share = hits as f64 / attributed_hits as f64;
                -share * share.ln()
            })
            .sum::<f64>();

        entropy / 3.0f64.ln()
    }
}

#[derive(Debug, Clone)]
pub struct AutoAdaptiveDecision {
    pub use_hot_bucket: bool,
    pub reason: &'static str,
    pub sample_len: usize,
    pub streak_ratio: f64,
    pub streak_threshold: f64,
    pub min_margin: f64,
    pub hot_key_share: f64,
    pub min_hot_key_share: f64,
    pub expected_gain_score: f64,
    pub min_expected_gain_score: f64,
}

pub fn detect_conflict(a: &Tx, b: &Tx) -> bool {
    assert_tx_access_domain_versions_are_consistent(a);
    assert_tx_access_domain_versions_are_consistent(b);

    // Read-only pairs can never conflict; skip three intersection probes in
    // the common telemetry/transfer path where writes are absent.
    if a.write_set.is_empty() && b.write_set.is_empty() {
        return false;
    }

    // Asymmetric fast paths: when one side is read-only, only a single probe can
    // produce a write/read hazard. This trims two unnecessary intersections from
    // hot free-ingress scheduling probes under mixed read-only traffic.
    if a.write_set.is_empty() {
        return intersects(&a.read_set, &b.write_set);
    }
    if b.write_set.is_empty() {
        return intersects(&a.write_set, &b.read_set);
    }

    // Pure write/write pairs cannot produce read hazards; keep the hot Sui-like
    // writer lane on a single probe while preserving conservative conflict
    // semantics for mixed read/write domains below.
    if a.read_set.is_empty() && b.read_set.is_empty() {
        return intersects(&a.write_set, &b.write_set);
    }

    intersects(&a.write_set, &b.write_set)
        || intersects(&a.write_set, &b.read_set)
        || intersects(&a.read_set, &b.write_set)
}

#[inline]
fn access_key(obj: &ObjectRef) -> u64 {
    // Conflict grouping stays object-scoped, not version-scoped: different
    // versions of the same logical object must serialize through the same
    // access domain so executor scheduling stays aligned with trnm-state.
    obj.id
}

#[inline]
fn dedup_access_keys(objs: &[ObjectRef]) -> Vec<u64> {
    debug_assert!(
        access_domain_versions_are_consistent(objs),
        "access domain contains the same object id with multiple versions"
    );

    // Small-set fast path avoids HashSet allocation for common tiny access lists.
    if objs.len() <= 8 {
        let mut out: Vec<u64> = Vec::with_capacity(objs.len());
        for obj in objs {
            let key = access_key(obj);
            if !out.contains(&key) {
                out.push(key);
            }
        }
        return out;
    }

    let mut seen: HashSet<u64> = HashSet::with_capacity(objs.len());
    let mut out: Vec<u64> = Vec::with_capacity(objs.len());
    for obj in objs {
        let key = access_key(obj);
        if seen.insert(key) {
            out.push(key);
        }
    }
    out
}

#[inline]
fn dedup_access_keys_no_version(objs: &[ObjectRef]) -> Vec<u64> {
    if objs.len() <= 8 {
        let mut out: Vec<u64> = Vec::with_capacity(objs.len());
        for obj in objs {
            let key = access_key(obj);
            if !out.contains(&key) {
                out.push(key);
            }
        }
        return out;
    }

    let mut seen: HashSet<u64> = HashSet::with_capacity(objs.len());
    let mut out: Vec<u64> = Vec::with_capacity(objs.len());
    for obj in objs {
        let key = access_key(obj);
        if seen.insert(key) {
            out.push(key);
        }
    }
    out
}

#[inline]
fn extend_unique_access_keys(dst: &mut Vec<u64>, objs: &[ObjectRef]) {
    debug_assert!(
        access_domain_versions_are_consistent(objs),
        "access domain contains the same object id with multiple versions"
    );

    if objs.is_empty() {
        if dst.len() <= 1 {
            return;
        }

        let mut unique_len = 1usize;
        for idx in 1..dst.len() {
            let key = dst[idx];
            if !dst[..unique_len].contains(&key) {
                dst[unique_len] = key;
                unique_len += 1;
            }
        }
        dst.truncate(unique_len);
        return;
    }

    // Tiny mixed domains are common in executor telemetry. Keep the merge path
    // allocation-free there while still deduplicating same-version read/write echoes.
    if dst.len() + objs.len() <= 8 {
        if dst.len() > 1 {
            let mut unique_len = 1usize;
            for idx in 1..dst.len() {
                let key = dst[idx];
                if !dst[..unique_len].contains(&key) {
                    dst[unique_len] = key;
                    unique_len += 1;
                }
            }
            dst.truncate(unique_len);
        }

        for obj in objs {
            let key = access_key(obj);
            if !dst.contains(&key) {
                dst.push(key);
            }
        }
        return;
    }

    let mut seen: HashSet<u64> = HashSet::with_capacity(dst.len() + objs.len());
    let mut unique_len = 0usize;
    for idx in 0..dst.len() {
        let key = dst[idx];
        if seen.insert(key) {
            dst[unique_len] = key;
            unique_len += 1;
        }
    }
    dst.truncate(unique_len);
    for obj in objs {
        let key = access_key(obj);
        if seen.insert(key) {
            dst.push(key);
        }
    }
}

fn access_domain_versions_are_consistent(objs: &[ObjectRef]) -> bool {
    if objs.len() <= 1 {
        return true;
    }

    // Hot singleton/echo domains dominate executor read/write probes. Keep the
    // two-entry path allocation-free so duplicate same-version echoes or exact
    // two-version skew checks stay on a branch-only fail-closed guard.
    if objs.len() == 2 {
        return objs[0].id != objs[1].id || objs[0].version == objs[1].version;
    }

    // Tiny single-domain access lists are common on Sui-like object probes.
    // Mirror the mixed-domain helper's small-set guard so same-version echoes
    // and version skew checks stay allocation-light before the larger HashMap
    // path kicks in for broader footprints.
    if objs.len() <= 8 {
        let mut seen: Vec<(u64, u64)> = Vec::with_capacity(objs.len());
        for obj in objs {
            match seen.iter().find(|(id, _)| *id == obj.id) {
                Some((_, version)) if *version != obj.version => return false,
                Some(_) => {}
                None => seen.push((obj.id, obj.version)),
            }
        }
        return true;
    }

    let mut versions_by_id: HashMap<u64, u64> = HashMap::with_capacity(objs.len());
    for obj in objs {
        match versions_by_id.insert(obj.id, obj.version) {
            Some(version) if version != obj.version => return false,
            Some(_) | None => {}
        }
    }

    true
}

fn combined_access_domain_versions_are_consistent(
    reads: &[ObjectRef],
    writes: &[ObjectRef],
) -> bool {
    if reads.is_empty() {
        return access_domain_versions_are_consistent(writes);
    }
    if writes.is_empty() {
        return access_domain_versions_are_consistent(reads);
    }

    let total_len = reads.len() + writes.len();
    if total_len <= 1 {
        return true;
    }

    // Mixed singleton path is common on Sui-like read/write echoes. Keep it
    // branch-only so the fail-closed skew guard avoids even the tiny vector
    // allocation used by the broader small-domain fast path.
    if reads.len() == 1 && writes.len() == 1 {
        return reads[0].id != writes[0].id || reads[0].version == writes[0].version;
    }

    // Keep tiny mixed domains allocation-light on the common Sui-like single-object
    // read/write echo path while preserving the same fail-closed skew guard.
    if total_len <= 8 {
        let mut seen: Vec<(u64, u64)> = Vec::with_capacity(total_len);
        for obj in writes.iter().chain(reads.iter()) {
            match seen.iter().find(|(id, _)| *id == obj.id) {
                Some((_, version)) if *version != obj.version => return false,
                Some(_) => {}
                None => seen.push((obj.id, obj.version)),
            }
        }
        return true;
    }

    let mut versions_by_id: HashMap<u64, u64> = HashMap::with_capacity(total_len);
    for obj in writes.iter().chain(reads.iter()) {
        match versions_by_id.insert(obj.id, obj.version) {
            Some(version) if version != obj.version => return false,
            Some(_) | None => {}
        }
    }

    true
}

#[inline]
fn assert_tx_access_domain_versions_are_consistent(tx: &Tx) {
    assert!(
        combined_access_domain_versions_are_consistent(&tx.read_set, &tx.write_set),
        "mixed access domain contains the same object id with multiple versions"
    );
}

fn assert_tx_access_domain_versions_are_consistent_batch(txs: &[Tx]) {
    for tx in txs {
        assert_tx_access_domain_versions_are_consistent(tx);
    }
}

fn intersects(x: &[ObjectRef], y: &[ObjectRef]) -> bool {
    if x.is_empty() || y.is_empty() {
        return false;
    }

    // Singleton fast path: common for simple transfer-like txs; avoid HashSet and
    // reduce iterator overhead in hot conflict probes.
    if x.len() == 1 {
        let key = access_key(&x[0]);
        return y.iter().any(|obj| access_key(obj) == key);
    }
    if y.len() == 1 {
        let key = access_key(&y[0]);
        return x.iter().any(|obj| access_key(obj) == key);
    }

    // Tiny-set fast path: avoid HashSet allocation on common low-footprint txs.
    // Iterate the smaller side first to reduce pairwise comparisons under skewed
    // tiny footprints (e.g. 1x8), while preserving duplicate-tolerant semantics.
    if x.len() <= 8 && y.len() <= 8 {
        let (small, large) = if x.len() <= y.len() { (x, y) } else { (y, x) };

        // Duplicate-heavy small footprints can otherwise rescan `large` for the same
        // key many times. Keep this tiny-path dedup allocation bounded by <=8 keys.
        let mut unique_small_keys: Vec<u64> = Vec::with_capacity(small.len());
        for a in small {
            let key = access_key(a);
            if !unique_small_keys.contains(&key) {
                unique_small_keys.push(key);
            }
        }

        for key in unique_small_keys {
            if large.iter().any(|b| access_key(b) == key) {
                return true;
            }
        }
        return false;
    }

    // Build a set from the smaller side to reduce comparisons.
    let (small, large) = if x.len() <= y.len() { (x, y) } else { (y, x) };

    // Skewed low-footprint path: avoid HashSet allocation when one side has only a
    // handful of keys (common in transfer-like writes against large read domains).
    if small.len() <= 4 {
        // Duplicate-heavy small footprints can otherwise rescan the large side
        // multiple times for the same key under hot-key bursts.
        let mut keys: Vec<u64> = Vec::with_capacity(small.len());
        for a in small {
            let key = access_key(a);
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
        for key in keys {
            if large.iter().any(|b| access_key(b) == key) {
                return true;
            }
        }
        return false;
    }

    // Medium-small skew path: for 5..=8 keys against a moderately larger domain,
    // avoid HashSet allocation and probe linearly. Extend the guard slightly so
    // duplicate-heavy domains just above the old 64-key cutoff stay on the same
    // bounded path before falling back to the HashSet branch.
    if small.len() <= 8 && (16..=128).contains(&large.len()) {
        let mut keys: Vec<u64> = Vec::with_capacity(small.len());
        for a in small {
            let key = access_key(a);
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
        for key in keys {
            if large.iter().any(|b| access_key(b) == key) {
                return true;
            }
        }
        return false;
    }

    let seen: HashSet<u64> = small.iter().map(access_key).collect();
    large.iter().any(|obj| seen.contains(&access_key(obj)))
}

#[inline]
fn vec_hashset_intersects(a: &[u64], b: &HashSet<u64>) -> bool {
    if a.is_empty() || b.is_empty() {
        return false;
    }

    // Singleton fast path shows up frequently in conflict-domain probes and
    // avoids iterator/closure overhead in the hottest branch.
    if a.len() == 1 {
        return b.contains(&a[0]);
    }

    // Symmetric singleton fast path: deep-scan stages can probe wide vectors
    // against one-key group domains; avoid walking the whole vector in that case.
    if b.len() == 1 {
        let only = *b
            .iter()
            .next()
            .expect("single-key set must contain one element");
        return a.contains(&only);
    }

    // Small/medium vector fast path: duplicate-heavy conflict domains can
    // repeatedly probe the same key in hot scheduling loops. Dedup the probe
    // side in-place to keep hash lookups bounded without paying HashSet
    // allocation cost.
    if a.len() <= 32 {
        let mut seen: Vec<u64> = Vec::with_capacity(a.len());
        for k in a {
            if !seen.contains(k) {
                if b.contains(k) {
                    return true;
                }
                seen.push(*k);
            }
        }
        return false;
    }

    // Large duplicate-heavy probe vectors can show up when object-scoped read
    // domains are widened before dedup reaches the aggressive stage checks.
    // Collapse repeated keys once so scheduling guardrails stay bounded even on
    // long duplicate bursts from shared-object access domains.
    let mut seen: HashSet<u64> = HashSet::with_capacity(a.len().min(64));
    for k in a {
        if seen.insert(*k) && b.contains(k) {
            return true;
        }
    }
    false
}

/// Build parallel-safe groups:
/// - txs within the same group are pairwise non-conflicting (can run in parallel)
/// - groups themselves are applied in order
pub fn build_parallel_groups(txs: &[Tx]) -> Vec<Vec<Tx>> {
    build_parallel_groups_profile(txs).0
}

#[inline]
fn read_domain_only_keys(read_set: &[ObjectRef], write_keys: &[u64]) -> Vec<u64> {
    let keys = dedup_access_keys(read_set);
    if keys.is_empty() || write_keys.is_empty() {
        return keys;
    }

    // Keep object-scoped access domains deterministic while avoiding quadratic
    // write-key probes once shared domains become large.
    if write_keys.len() <= 8 {
        return keys
            .into_iter()
            .filter(|key| !write_keys.contains(key))
            .collect();
    }

    let write_domain: HashSet<u64> = write_keys.iter().copied().collect();
    keys.into_iter()
        .filter(|key| !write_domain.contains(key))
        .collect()
}

#[inline]
fn tx_access_domain_keys(tx: &Tx) -> Vec<u64> {
    // Fail-closed at the helper boundary as well: internal callers should not be
    // able to derive a canonical execution-domain keyset from a tx that mixes the
    // same object id across read/write sets with mismatched versions.
    assert_tx_access_domain_versions_are_consistent(tx);

    // Keep telemetry/object-domain reporting aligned with scheduler hotspot
    // selection: writes carry the stronger conflict signal, while reads extend the
    // object scope only when they introduce additional keys. Reuse the same
    // read-domain filtering helper as the scheduler so grouping and reporting
    // stay on a single deterministic object-scoped path.
    let write_keys = dedup_access_keys(&tx.write_set);
    let read_keys = read_domain_only_keys(&tx.read_set, &write_keys);

    let mut keys = Vec::with_capacity(write_keys.len() + read_keys.len());
    keys.extend(write_keys);
    keys.extend(read_keys);
    keys
}

pub(crate) fn primary_access_domain_key(tx: &Tx) -> Option<u64> {
    // Fail-closed if a tx carries mixed read/write footprints for the same object id
    // with mismatched versions.
    assert_tx_access_domain_versions_are_consistent(tx);

    let write_keys = dedup_access_keys(&tx.write_set);
    if let Some(key) = write_keys.into_iter().min() {
        return Some(key);
    }

    read_domain_only_keys(&tx.read_set, &[]).into_iter().min()
}

fn hot_object_share(txs: &[Tx]) -> f64 {
    let mut counts: HashMap<u64, usize> = HashMap::new();
    let mut total = 0usize;

    for tx in txs {
        assert_tx_access_domain_versions_are_consistent(tx);
        let keys = tx_access_domain_keys(tx);
        total += keys.len();
        for key in keys {
            *counts.entry(key).or_insert(0) += 1;
        }
    }

    if total == 0 {
        return 0.0;
    }

    let hottest = counts.values().copied().max().unwrap_or(0);
    hottest as f64 / total as f64
}

pub fn build_parallel_groups_profile(txs: &[Tx]) -> (Vec<Vec<Tx>>, GroupingProfile) {
    build_parallel_groups_profile_with_strategy(txs, GroupingStrategy::Original)
}

pub fn build_parallel_groups_profile_with_strategy(
    txs: &[Tx],
    strategy: GroupingStrategy,
) -> (Vec<Vec<Tx>>, GroupingProfile) {
    if txs.is_empty() {
        return (
            Vec::new(),
            GroupingProfile {
                tx_count: 0,
                group_count: 0,
                grouped_count: 0,
                max_group_size: 0,
                min_group_size: 0,
                avg_group_size: 0.0,
                hot_object_share: 0.0,
                conflict_checks: 0,
                conflict_hits: 0,
                candidate_groups_scanned: 0,
                retry_fallback_new_groups: 0,
                stage_ww_checks: 0,
                stage_ww_hits: 0,
                stage_wr_checks: 0,
                stage_wr_hits: 0,
                stage_rw_checks: 0,
                stage_rw_hits: 0,
            },
        );
    }

    assert_tx_access_domain_versions_are_consistent_batch(txs);

    let mut selected = strategy;
    if matches!(selected, GroupingStrategy::AutoAdaptive) {
        let d = auto_adaptive_decision(txs);
        selected = if d.use_hot_bucket {
            GroupingStrategy::HotBucketInterleave
        } else {
            GroupingStrategy::Original
        };
    }

    let mut ordered: Vec<Tx> = txs.to_vec();
    reorder_for_strategy(&mut ordered, selected);

    // Free-ingress fast path: when no tx carries read/write footprint, all txs are
    // conflict-independent and land in a single execution group. Skip per-key map
    // bookkeeping in this hot path to reduce scheduler overhead at high ingress.
    if ordered
        .iter()
        .all(|tx| tx.read_set.is_empty() && tx.write_set.is_empty())
    {
        let grouped_count = ordered.len();
        let avg_group_size = grouped_count as f64;
        return (
            vec![ordered],
            GroupingProfile {
                tx_count: txs.len(),
                group_count: 1,
                grouped_count,
                max_group_size: grouped_count,
                min_group_size: grouped_count,
                avg_group_size,
                hot_object_share: 0.0,
                conflict_checks: 0,
                conflict_hits: 0,
                candidate_groups_scanned: 0,
                retry_fallback_new_groups: 0,
                stage_ww_checks: 0,
                stage_ww_hits: 0,
                stage_wr_checks: 0,
                stage_wr_hits: 0,
                stage_rw_checks: 0,
                stage_rw_hits: 0,
            },
        );
    }

    if matches!(selected, GroupingStrategy::AggressiveGreedy) {
        return build_parallel_groups_aggressive_profile(txs, ordered);
    }

    let mut groups: Vec<Vec<Tx>> = Vec::new();

    // Pre-size maps from access-footprint hint to reduce rehashing on
    // wide-object workloads while keeping bounded overhead on tiny batches.
    let map_cap = access_map_capacity_hint(txs);
    // object(id) -> latest group that has a writer touching this object
    let mut latest_writer_group: HashMap<u64, usize> = HashMap::with_capacity(map_cap);
    // object(id) -> latest group that has a reader touching this object
    let mut latest_reader_group: HashMap<u64, usize> = HashMap::with_capacity(map_cap);

    // Profiling counters (lightweight approximation instead of pairwise O(n^2) scans)
    let mut conflict_checks = 0usize;
    let mut conflict_hits = 0usize;

    for tx in ordered {
        // minimal group index forced by previous conflicting accesses
        let mut required_group = 0usize;

        // Deduplicate per-tx access keys while avoiding HashSet allocation in hot path.
        let write_keys = dedup_access_keys(&tx.write_set);
        let read_keys = read_domain_only_keys(&tx.read_set, &write_keys);

        // read conflicts with previous writers on the same object
        for key in &read_keys {
            conflict_checks += 1;
            if let Some(&g) = latest_writer_group.get(key) {
                conflict_hits += 1;
                required_group = required_group.max(g + 1);
            }
        }

        // write conflicts with previous writers and readers on the same object
        for key in &write_keys {
            conflict_checks += 1;
            if let Some(&g) = latest_writer_group.get(key) {
                conflict_hits += 1;
                required_group = required_group.max(g + 1);
            }
            conflict_checks += 1;
            if let Some(&g) = latest_reader_group.get(key) {
                conflict_hits += 1;
                required_group = required_group.max(g + 1);
            }
        }

        if groups.len() <= required_group {
            groups.resize_with(required_group + 1, Vec::new);
        }
        groups[required_group].push(tx);

        for key in read_keys {
            latest_reader_group.insert(key, required_group);
        }
        for key in write_keys {
            latest_writer_group.insert(key, required_group);
        }
    }

    let group_count = groups.len();
    let grouped_count: usize = groups.iter().map(|g| g.len()).sum();
    let max_group_size = groups.iter().map(|g| g.len()).max().unwrap_or(0);
    let min_group_size = groups.iter().map(|g| g.len()).min().unwrap_or(0);
    let avg_group_size = if group_count == 0 {
        0.0
    } else {
        grouped_count as f64 / group_count as f64
    };
    let hot_object_share = hot_object_share(txs);

    (
        groups,
        GroupingProfile {
            tx_count: txs.len(),
            group_count,
            grouped_count,
            max_group_size,
            min_group_size,
            avg_group_size,
            hot_object_share,
            conflict_checks,
            conflict_hits,
            candidate_groups_scanned: 0,
            retry_fallback_new_groups: 0,
            stage_ww_checks: 0,
            stage_ww_hits: 0,
            stage_wr_checks: 0,
            stage_wr_hits: 0,
            stage_rw_checks: 0,
            stage_rw_hits: 0,
        },
    )
}

fn build_parallel_groups_aggressive_profile(
    original_txs: &[Tx],
    ordered: Vec<Tx>,
) -> (Vec<Vec<Tx>>, GroupingProfile) {
    // Fast path (default): identical dependency-bound placement semantics as Original,
    // but keeps Aggressive strategy identity/flags and metrics interface stable.
    if !aggr_deep_scan_enabled() {
        let mut groups: Vec<Vec<Tx>> = Vec::new();
        let map_cap = access_map_capacity_hint(original_txs);
        let mut latest_writer_group: HashMap<u64, usize> = HashMap::with_capacity(map_cap);
        let mut latest_reader_group: HashMap<u64, usize> = HashMap::with_capacity(map_cap);

        let mut conflict_checks = 0usize;
        let mut conflict_hits = 0usize;

        for tx in ordered {
            let write_keys = dedup_access_keys(&tx.write_set);
            let read_keys = read_domain_only_keys(&tx.read_set, &write_keys);

            let mut min_group = 0usize;
            for key in &read_keys {
                conflict_checks += 1;
                if let Some(&g) = latest_writer_group.get(key) {
                    conflict_hits += 1;
                    min_group = min_group.max(g + 1);
                }
            }
            for key in &write_keys {
                conflict_checks += 1;
                if let Some(&g) = latest_writer_group.get(key) {
                    conflict_hits += 1;
                    min_group = min_group.max(g + 1);
                }
                conflict_checks += 1;
                if let Some(&g) = latest_reader_group.get(key) {
                    conflict_hits += 1;
                    min_group = min_group.max(g + 1);
                }
            }

            if groups.len() <= min_group {
                groups.resize_with(min_group + 1, Vec::new);
            }
            groups[min_group].push(tx);

            for key in read_keys {
                latest_reader_group.insert(key, min_group);
            }
            for key in write_keys {
                latest_writer_group.insert(key, min_group);
            }
        }

        let group_count = groups.len();
        let grouped_count: usize = groups.iter().map(|g| g.len()).sum();
        let max_group_size = groups.iter().map(|g| g.len()).max().unwrap_or(0);
        let min_group_size = groups.iter().map(|g| g.len()).min().unwrap_or(0);
        let avg_group_size = if group_count == 0 {
            0.0
        } else {
            grouped_count as f64 / group_count as f64
        };
        let hot_object_share = hot_object_share(original_txs);

        return (
            groups,
            GroupingProfile {
                tx_count: original_txs.len(),
                group_count,
                grouped_count,
                max_group_size,
                min_group_size,
                avg_group_size,
                hot_object_share,
                conflict_checks,
                conflict_hits,
                candidate_groups_scanned: 0,
                retry_fallback_new_groups: 0,
                stage_ww_checks: 0,
                stage_ww_hits: 0,
                stage_wr_checks: 0,
                stage_wr_hits: 0,
                stage_rw_checks: 0,
                stage_rw_hits: 0,
            },
        );
    }

    // Deep scan path (experiment-only).
    let mut groups: Vec<Vec<Tx>> = Vec::new();
    let mut group_read_keys: Vec<HashSet<u64>> = Vec::new();
    let mut group_write_keys: Vec<HashSet<u64>> = Vec::new();

    let map_cap = access_map_capacity_hint(original_txs);
    let mut latest_writer_group: HashMap<u64, usize> = HashMap::with_capacity(map_cap);
    let mut latest_reader_group: HashMap<u64, usize> = HashMap::with_capacity(map_cap);

    let mut conflict_checks = 0usize;
    let mut conflict_hits = 0usize;
    let mut candidate_groups_scanned = 0usize;
    let mut retry_fallback_new_groups = 0usize;
    let mut stage_ww_checks = 0usize;
    let mut stage_ww_hits = 0usize;
    let mut stage_wr_checks = 0usize;
    let mut stage_wr_hits = 0usize;
    let mut stage_rw_checks = 0usize;
    let mut stage_rw_hits = 0usize;
    let scan_window = aggr_scan_window();
    let skip_empty_stage_checks = aggr_skip_empty_stage_checks();
    let rr_enabled = aggr_scan_round_robin_enabled();
    let mut rr_cursor = aggr_scan_round_robin_seed();

    for tx in ordered {
        let mut tx_slot = Some(tx);
        let write_keys = dedup_access_keys(&tx_slot.as_ref().expect("tx must exist").write_set);
        let read_keys = read_domain_only_keys(
            &tx_slot.as_ref().expect("tx must exist").read_set,
            &write_keys,
        );
        let read_empty = read_keys.is_empty();
        let write_empty = write_keys.is_empty();

        let mut min_group = 0usize;
        for key in &read_keys {
            if let Some(&g) = latest_writer_group.get(key) {
                min_group = min_group.max(g + 1);
            }
        }
        for key in &write_keys {
            if let Some(&g) = latest_writer_group.get(key) {
                min_group = min_group.max(g + 1);
            }
            if let Some(&g) = latest_reader_group.get(key) {
                min_group = min_group.max(g + 1);
            }
        }

        let mut placed = false;
        let mut scanned = 0usize;
        let candidate_span = groups.len().saturating_sub(min_group);

        if skip_empty_stage_checks && read_empty && write_empty && candidate_span > 0 {
            groups[min_group].push(tx_slot.take().expect("tx already moved"));
            placed = true;
        }

        let start_offset = if rr_enabled && candidate_span > 1 {
            rr_cursor % candidate_span
        } else {
            0
        };
        for step in 0..candidate_span {
            if placed {
                break;
            }
            if scan_window > 0 && scanned >= scan_window {
                break;
            }
            let idx = min_group + ((start_offset + step) % candidate_span);
            scanned += 1;
            candidate_groups_scanned += 1;

            if !skip_empty_stage_checks || !write_empty {
                conflict_checks += 1;
                stage_ww_checks += 1;
                if vec_hashset_intersects(&write_keys, &group_write_keys[idx]) {
                    conflict_hits += 1;
                    stage_ww_hits += 1;
                    continue;
                }

                conflict_checks += 1;
                stage_wr_checks += 1;
                if vec_hashset_intersects(&write_keys, &group_read_keys[idx]) {
                    conflict_hits += 1;
                    stage_wr_hits += 1;
                    continue;
                }
            }

            if !skip_empty_stage_checks || !read_empty {
                conflict_checks += 1;
                stage_rw_checks += 1;
                if vec_hashset_intersects(&read_keys, &group_write_keys[idx]) {
                    conflict_hits += 1;
                    stage_rw_hits += 1;
                    continue;
                }
            }

            groups[idx].push(tx_slot.take().expect("tx already moved"));
            group_read_keys[idx].extend(read_keys.iter().copied());
            group_write_keys[idx].extend(write_keys.iter().copied());

            for key in &read_keys {
                latest_reader_group.insert(*key, idx);
            }
            for key in &write_keys {
                latest_writer_group.insert(*key, idx);
            }

            placed = true;
            break;
        }

        if !placed {
            if candidate_span > 0 {
                retry_fallback_new_groups += 1;
            }
            let idx = groups.len();
            groups.push(vec![tx_slot.take().expect("tx already moved")]);
            group_read_keys.push(read_keys.iter().copied().collect());
            group_write_keys.push(write_keys.iter().copied().collect());

            for key in &group_read_keys[idx] {
                latest_reader_group.insert(*key, idx);
            }
            for key in &group_write_keys[idx] {
                latest_writer_group.insert(*key, idx);
            }
        }

        if rr_enabled && candidate_span > 1 {
            rr_cursor = rr_cursor.wrapping_add(1);
        }
    }

    let group_count = groups.len();
    let grouped_count: usize = groups.iter().map(|g| g.len()).sum();
    let max_group_size = groups.iter().map(|g| g.len()).max().unwrap_or(0);
    let min_group_size = groups.iter().map(|g| g.len()).min().unwrap_or(0);
    let avg_group_size = if group_count == 0 {
        0.0
    } else {
        grouped_count as f64 / group_count as f64
    };
    let hot_object_share = hot_object_share(original_txs);

    (
        groups,
        GroupingProfile {
            tx_count: original_txs.len(),
            group_count,
            grouped_count,
            max_group_size,
            min_group_size,
            avg_group_size,
            hot_object_share,
            conflict_checks,
            conflict_hits,
            candidate_groups_scanned,
            retry_fallback_new_groups,
            stage_ww_checks,
            stage_ww_hits,
            stage_wr_checks,
            stage_wr_hits,
            stage_rw_checks,
            stage_rw_hits,
        },
    )
}

#[inline]
fn access_map_capacity_hint(txs: &[Tx]) -> usize {
    const MIN_CAP: usize = 64;
    const MAX_CAP: usize = 1 << 20;

    let mut footprint = 0usize;
    for tx in txs {
        assert_tx_access_domain_versions_are_consistent(tx);

        // Size conflict-domain maps from the tx's unique access domain rather than
        // raw read/write list lengths. This keeps same-version read/write echoes and
        // duplicate keys from inflating hot-path map capacity under mixed Sui-like
        // read/write workloads while preserving the same fail-closed skew guard.
        let mut keys = dedup_access_keys(&tx.write_set);
        extend_unique_access_keys(&mut keys, &tx.read_set);
        footprint = footprint.saturating_add(keys.len());
    }

    // HashMap load-factor friendly sizing. Keep a floor for tiny batches and
    // cap for pathological bursts so this remains a low-risk sizing hint.
    let hinted = footprint
        .saturating_mul(4)
        .saturating_div(3)
        .saturating_add(1);
    hinted.clamp(MIN_CAP, MAX_CAP)
}

#[inline]
fn parse_env_numeric(name: &str) -> Option<String> {
    std::env::var(name).ok().and_then(|v| {
        let trimmed = v.trim();
        if trimmed.is_empty() {
            return None;
        }

        let unquoted = trimmed
            .strip_prefix('"')
            .and_then(|inner| inner.strip_suffix('"'))
            .or_else(|| {
                trimmed
                    .strip_prefix('\'')
                    .and_then(|inner| inner.strip_suffix('\''))
            })
            .map(str::trim)
            .unwrap_or(trimmed);
        if unquoted.is_empty() {
            return None;
        }

        // Accept common human-friendly separators in ops configs.
        if unquoted.contains('_') || unquoted.contains(',') {
            let mut compact = String::with_capacity(unquoted.len());
            for ch in unquoted.chars() {
                if ch != '_' && ch != ',' {
                    compact.push(ch);
                }
            }
            if compact.is_empty() {
                None
            } else {
                Some(compact)
            }
        } else {
            Some(unquoted.to_owned())
        }
    })
}

#[inline]
fn parse_env_usize(name: &str) -> Option<usize> {
    parse_env_numeric(name).and_then(|v| {
        let normalized = v.strip_prefix('+').unwrap_or(&v);
        (!normalized.is_empty())
            .then(|| normalized.parse::<usize>().ok())
            .flatten()
    })
}

#[inline]
fn parse_grouped_env_usize(name: &str) -> Option<usize> {
    std::env::var(name).ok().and_then(|v| {
        let trimmed = v.trim();
        if trimmed.is_empty() {
            return None;
        }

        let unquoted = trimmed
            .strip_prefix('"')
            .and_then(|inner| inner.strip_suffix('"'))
            .or_else(|| {
                trimmed
                    .strip_prefix('\'')
                    .and_then(|inner| inner.strip_suffix('\''))
            })
            .map(str::trim)
            .unwrap_or(trimmed);
        if unquoted.is_empty() {
            return None;
        }

        let compact: String = unquoted.chars().filter(|&ch| ch != '_').collect();
        if compact.is_empty() || compact.chars().all(|ch| ch == ',') {
            return None;
        }

        let normalized = compact.strip_prefix('+').unwrap_or(&compact);
        if normalized.is_empty() {
            return None;
        }

        if normalized.contains(',') {
            let mut parts = normalized.split(',');
            let first = parts.next().unwrap_or("");
            let rest: Vec<&str> = parts.collect();
            let comma_is_grouping = !first.is_empty()
                && first.chars().all(|ch| ch.is_ascii_digit())
                && rest.iter().all(|segment| {
                    segment.len() == 3 && segment.chars().all(|ch| ch.is_ascii_digit())
                });
            if !comma_is_grouping {
                return None;
            }
            return normalized.replace(',', "").parse::<usize>().ok();
        }

        normalized.parse::<usize>().ok()
    })
}

#[inline]
fn parse_env_f64(name: &str) -> Option<f64> {
    std::env::var(name).ok().and_then(|v| {
        let trimmed = v.trim();
        if trimmed.is_empty() {
            return None;
        }

        let unquoted = trimmed
            .strip_prefix('"')
            .and_then(|inner| inner.strip_suffix('"'))
            .or_else(|| {
                trimmed
                    .strip_prefix('\'')
                    .and_then(|inner| inner.strip_suffix('\''))
            })
            .map(str::trim)
            .unwrap_or(trimmed);
        if unquoted.is_empty() {
            return None;
        }

        let mut compact = String::with_capacity(unquoted.len());
        for ch in unquoted.chars() {
            if ch != '_' {
                compact.push(ch);
            }
        }
        if compact.is_empty() || compact.chars().all(|ch| ch == ',') {
            return None;
        }

        let percent = compact.ends_with('%');
        let numeric = if percent {
            compact.strip_suffix('%').unwrap_or(&compact)
        } else {
            &compact
        };
        if numeric.is_empty() {
            return None;
        }

        let normalized = if numeric.contains(',') && !numeric.contains('.') {
            let comma_count = numeric.chars().filter(|&ch| ch == ',').count();
            if comma_count == 1 {
                let (whole, frac) = numeric.split_once(',').unwrap_or((numeric, ""));
                let whole_is_optional_sign = whole.is_empty() || whole == "+" || whole == "-";
                if whole_is_optional_sign
                    && !frac.is_empty()
                    && frac.chars().all(|ch| ch.is_ascii_digit())
                {
                    let sign = if whole == "-" { "-" } else { "" };
                    format!("{sign}0.{frac}")
                } else if !whole.is_empty()
                    && !frac.is_empty()
                    && whole
                        .chars()
                        .all(|ch| ch == '+' || ch == '-' || ch.is_ascii_digit())
                    && frac.chars().all(|ch| ch.is_ascii_digit())
                {
                    let whole_digits = whole.trim_start_matches(['+', '-']);
                    let whole_is_zero =
                        !whole_digits.is_empty() && whole_digits.chars().all(|ch| ch == '0');
                    let comma_is_grouping = frac.len() == 3
                        && whole.chars().any(|ch| ch.is_ascii_digit())
                        && !whole_is_zero;
                    if comma_is_grouping {
                        numeric.replace(',', "")
                    } else {
                        numeric.replace(',', ".")
                    }
                } else {
                    numeric.replace(',', "")
                }
            } else {
                let mut parts = numeric.split(',');
                let whole = parts.next().unwrap_or("");
                let frac_or_groups: Vec<&str> = parts.collect();
                let comma_is_grouping = !whole.is_empty()
                    && whole
                        .chars()
                        .all(|ch| ch == '+' || ch == '-' || ch.is_ascii_digit())
                    && whole.chars().any(|ch| ch.is_ascii_digit())
                    && frac_or_groups.iter().all(|segment| {
                        segment.len() == 3 && segment.chars().all(|ch| ch.is_ascii_digit())
                    });
                if !comma_is_grouping {
                    return None;
                }
                numeric.replace(',', "")
            }
        } else {
            numeric.replace(',', "")
        };

        let parsed = normalized.parse::<f64>().ok()?;
        if !parsed.is_finite() {
            return None;
        }
        let value = if percent { parsed / 100.0 } else { parsed };
        value.is_finite().then_some(value)
    })
}

fn aggr_scan_window() -> usize {
    const DEFAULT_SCAN_WINDOW: usize = 0;
    const MAX_SCAN_WINDOW: usize = 4096;

    parse_grouped_env_usize("TRNM_AGGR_SCAN_WINDOW")
        .map(|v| v.min(MAX_SCAN_WINDOW))
        .filter(|&v| v > 0)
        .unwrap_or_else(|| {
            if aggr_deep_scan_enabled() {
                DEFAULT_SCAN_WINDOW
            } else {
                0
            }
        })
}

fn env_toggle_enabled(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| {
            let trimmed = v.trim();
            let unquoted = trimmed
                .strip_prefix('"')
                .and_then(|inner| inner.strip_suffix('"'))
                .or_else(|| {
                    trimmed
                        .strip_prefix('\'')
                        .and_then(|inner| inner.strip_suffix('\''))
                })
                .unwrap_or(trimmed);
            let s = unquoted.trim().to_ascii_lowercase();
            if s.is_empty() || s.chars().all(|ch| ch == '_' || ch == ',') {
                return default;
            }
            !(s == "0" || s == "false" || s == "off" || s == "no")
        })
        .unwrap_or(default)
}

fn aggr_skip_empty_stage_checks() -> bool {
    env_toggle_enabled("TRNM_AGGR_SKIP_EMPTY_STAGE_CHECKS", true)
}

fn aggr_deep_scan_enabled() -> bool {
    env_toggle_enabled("TRNM_AGGR_DEEP_SCAN", false)
}

fn aggr_scan_round_robin_enabled() -> bool {
    env_toggle_enabled("TRNM_AGGR_SCAN_ROUND_ROBIN", true)
}

fn aggr_scan_round_robin_seed() -> usize {
    parse_grouped_env_usize("TRNM_AGGR_SCAN_RR_SEED").unwrap_or(0)
}

fn auto_hot_streak_threshold() -> f64 {
    parse_env_f64("TRNM_AUTO_HOT_STREAK_RATIO")
        .map(|v| v.clamp(0.0, 1.0))
        .unwrap_or(0.22)
}

fn auto_reorder_min_margin() -> f64 {
    parse_env_f64("TRNM_AUTO_REORDER_MIN_MARGIN")
        .map(|v| v.clamp(0.0, 1.0))
        .unwrap_or(0.04)
}

fn auto_reorder_min_hot_key_share() -> f64 {
    parse_env_f64("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE")
        .map(|v| v.clamp(0.0, 1.0))
        .unwrap_or(0.0075)
}

fn hot_bucket_count() -> usize {
    parse_env_usize("TRNM_HOT_BUCKETS")
        .map(|v| v.clamp(4, 64))
        .unwrap_or(8)
}

fn auto_min_expected_gain_score() -> f64 {
    parse_env_f64("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE")
        .map(|v| v.clamp(0.0, 1.0))
        .unwrap_or(0.01)
}

fn auto_adaptive_min_batch_len() -> usize {
    const DEFAULT_MIN_BATCH_LEN: usize = 512;
    const MIN_BATCH_LEN_FLOOR: usize = 64;
    const MIN_BATCH_LEN_CEIL: usize = 4096;

    parse_grouped_env_usize("TRNM_AUTO_MIN_BATCH_LEN")
        .map(|v| v.clamp(MIN_BATCH_LEN_FLOOR, MIN_BATCH_LEN_CEIL))
        .unwrap_or(DEFAULT_MIN_BATCH_LEN)
}

fn auto_adaptive_sample_len(batch_len: usize) -> usize {
    const MAX_SAMPLE_LEN: usize = 2048;
    const MIN_SAMPLE_LEN_FLOOR: usize = 64;
    const MIN_SAMPLE_LEN_CEIL: usize = MAX_SAMPLE_LEN;

    let configured = parse_grouped_env_usize("TRNM_AUTO_SAMPLE_LEN")
        .map(|v| v.clamp(MIN_SAMPLE_LEN_FLOOR, MIN_SAMPLE_LEN_CEIL))
        .unwrap_or(MAX_SAMPLE_LEN);

    batch_len.min(configured)
}

pub fn auto_adaptive_decision(txs: &[Tx]) -> AutoAdaptiveDecision {
    assert_tx_access_domain_versions_are_consistent_batch(txs);
    let threshold = auto_hot_streak_threshold();
    let min_margin = auto_reorder_min_margin();
    let min_hot_key_share = auto_reorder_min_hot_key_share();
    let min_expected_gain_score = auto_min_expected_gain_score();
    let min_batch_len = auto_adaptive_min_batch_len();

    if txs.len() < min_batch_len {
        return AutoAdaptiveDecision {
            use_hot_bucket: false,
            reason: "small_batch",
            sample_len: txs.len(),
            streak_ratio: 0.0,
            streak_threshold: threshold,
            min_margin,
            hot_key_share: 0.0,
            min_hot_key_share,
            expected_gain_score: 0.0,
            min_expected_gain_score,
        };
    }

    // Sample a bounded, evenly-spaced window across the whole batch to avoid
    // first-window bias when hotspots arrive later in queue order. Keep the
    // sample window env-tunable for experimental adaptive lanes, but clamp it
    // fail-closed so misconfiguration cannot trigger unbounded scan work.
    let sample_len = auto_adaptive_sample_len(txs.len());
    let mut same_key_streak_hits = 0usize;
    let mut total_pairs = 0usize;
    let mut prev_key: Option<(u64, u64)> = None;
    let mut key_hist: HashMap<(u64, u64), usize> = HashMap::new();
    let mut observed = 0usize;

    let batch_len = txs.len();
    let direct_scan = sample_len == batch_len;
    let mut prev_idx: Option<usize> = None;
    for i in 0..sample_len {
        // Keep endpoints visible in bounded sampling windows so late-batch
        // hotspots contribute to adaptive scheduler decisions.
        // When sample_len==batch_len (most medium batches), index directly to
        // avoid per-item division in this hot scheduler probe.
        let idx = if direct_scan {
            i
        } else if sample_len > 1 {
            i.saturating_mul(batch_len.saturating_sub(1)) / (sample_len - 1)
        } else {
            0
        };
        if prev_idx == Some(idx) {
            continue;
        }
        prev_idx = Some(idx);
        let tx = &txs[idx];
        let key = {
            let (key_a, key_b) = hot_bucket_keys(tx);
            if tx.read_set.is_empty() && tx.write_set.is_empty() {
                None
            } else if tx.read_set.is_empty() || tx.write_set.is_empty() {
                Some((key_a, key_b))
            } else if primary_access_domain_key(tx) == Some(key_a) {
                // Preserve the existing write-primary hotspot detector contract for
                // mixed domains whose canonical lane anchor already matches the
                // primary access key. Only fall through to the two-key hint when
                // mixed-domain canonicalization would otherwise drift onto a
                // different execution-domain lane than the write-primary fast path.
                Some((key_a, 0))
            } else {
                Some((key_a, key_b))
            }
        };
        if let Some(k) = key {
            observed += 1;
            *key_hist.entry(k).or_insert(0) += 1;
            if let Some(pk) = prev_key {
                total_pairs += 1;
                if pk == k {
                    same_key_streak_hits += 1;
                }
            }
            prev_key = Some(k);
        } else {
            // Keyless txs should break streak continuity instead of allowing
            // later keyed samples to look adjacent in the hotspot probe.
            prev_key = None;
        }
    }

    if total_pairs == 0 || observed == 0 {
        return AutoAdaptiveDecision {
            use_hot_bucket: false,
            reason: "insufficient_sample",
            sample_len,
            streak_ratio: 0.0,
            streak_threshold: threshold,
            min_margin,
            hot_key_share: 0.0,
            min_hot_key_share,
            expected_gain_score: 0.0,
            min_expected_gain_score,
        };
    }

    let streak_ratio = same_key_streak_hits as f64 / total_pairs as f64;
    let max_key_count = key_hist.values().copied().max().unwrap_or(0);
    let hot_key_share = max_key_count as f64 / observed as f64;

    let expected_gain_score = streak_ratio * hot_key_share;
    let use_hot_bucket = streak_ratio >= threshold + min_margin
        && hot_key_share >= min_hot_key_share
        && expected_gain_score >= min_expected_gain_score;
    let reason = if use_hot_bucket {
        "hotspot_detected"
    } else if hot_key_share < min_hot_key_share {
        "low_hot_key_share"
    } else if expected_gain_score < min_expected_gain_score {
        "low_expected_gain"
    } else {
        "below_streak_budget"
    };

    AutoAdaptiveDecision {
        use_hot_bucket,
        reason,
        sample_len,
        streak_ratio,
        streak_threshold: threshold,
        min_margin,
        hot_key_share,
        min_hot_key_share,
        expected_gain_score,
        min_expected_gain_score,
    }
}

fn hot_bucket_keys(tx: &Tx) -> (u64, u64) {
    // Fail closed before deriving scheduler hotspot buckets: mixed read/write
    // footprints for the same object id must not silently collapse across
    // mismatched versions and drift the execution-domain lane signal.
    assert_tx_access_domain_versions_are_consistent(tx);

    // Canonicalize access-domain buckets by deduping object ids independently of
    // version. Use the smallest combined key as primary to preserve mixed-domain
    // role-flip stability, then keep the secondary key deterministic without
    // drifting when read/write roles flip: if the primary comes from writes,
    // prefer the next write key before falling back to reads; otherwise anchor to
    // the smallest distinct write key so mixed domains keep the same global two-
    // key hint across equivalent role permutations.
    let mut write_keys = dedup_access_keys_no_version(&tx.write_set);
    let mut read_keys = dedup_access_keys_no_version(&tx.read_set);
    write_keys.sort_unstable();
    read_keys.sort_unstable();

    if write_keys.is_empty() {
        return (
            read_keys.first().copied().unwrap_or(0),
            read_keys.get(1).copied().unwrap_or(0),
        );
    }
    if read_keys.is_empty() {
        return (
            write_keys.first().copied().unwrap_or(0),
            write_keys.get(1).copied().unwrap_or(0),
        );
    }

    let mut all_keys: Vec<u64> = Vec::with_capacity(write_keys.len() + read_keys.len());
    all_keys.extend(write_keys.iter().copied());
    all_keys.extend(read_keys.iter().copied());
    all_keys.sort_unstable();
    all_keys.dedup();
    if all_keys.is_empty() {
        return (0, 0);
    }

    let primary = all_keys[0];
    if primary == 0 {
        // Object id 0 is a valid access-domain key, not an internal sentinel.
        // Anchor the secondary to the smallest distinct global key so equivalent
        // mixed domains touching {0,...} do not drift lanes when read/write roles flip.
        let secondary = all_keys.iter().copied().find(|k| *k != primary).unwrap_or(0);
        return (primary, secondary);
    }

    let primary_is_echoed_across_domains = write_keys.binary_search(&primary).is_ok()
        && read_keys.binary_search(&primary).is_ok();
    if primary_is_echoed_across_domains {
        let write_only_secondary = write_keys.iter().copied().find(|k| *k != primary);
        let read_only_secondary = read_keys.iter().copied().find(|k| *k != primary);
        let has_single_write_only_secondary = write_keys
            .iter()
            .copied()
            .filter(|k| *k != primary)
            .nth(1)
            .is_none();
        let has_single_read_only_secondary = read_keys
            .iter()
            .copied()
            .filter(|k| *k != primary)
            .nth(1)
            .is_none();
        if has_single_write_only_secondary && has_single_read_only_secondary {
            let secondary = match (write_only_secondary, read_only_secondary) {
                (Some(write_key), Some(read_key)) => write_key.min(read_key),
                (Some(write_key), None) => write_key,
                (None, Some(read_key)) => read_key,
                (None, None) => 0,
            };
            return (primary, secondary);
        }

        if has_single_write_only_secondary || has_single_read_only_secondary {
            // When the primary object key is echoed across read/write domains and
            // one side contributes at most one distinct non-primary key, keep the
            // secondary anchored to the smallest available global non-primary key.
            // This prevents equivalent mixed domains from drifting execution lanes
            // just because the narrower side flips between reads and writes.
            let secondary = match (write_only_secondary, read_only_secondary) {
                (Some(write_key), Some(read_key)) => write_key.min(read_key),
                (Some(write_key), None) => write_key,
                (None, Some(read_key)) => read_key,
                (None, None) => 0,
            };
            return (primary, secondary);
        }
    }

    if write_keys[0] == primary {
        let secondary = write_keys
            .iter()
            .copied()
            .find(|k| *k != primary)
            .or_else(|| read_keys.iter().copied().find(|k| *k != primary))
            .unwrap_or(0);
        return (primary, secondary);
    }

    let secondary = write_keys
        .first()
        .copied()
        .or_else(|| read_keys.iter().copied().find(|k| *k != primary))
        .unwrap_or(0);
    (primary, secondary)
}

fn hot_bucket_hint(tx: &Tx, buckets_n: usize) -> usize {
    assert!(
        combined_access_domain_versions_are_consistent(&tx.read_set, &tx.write_set),
        "mixed access domain contains the same object id with multiple versions"
    );

    // Defensive guard: keep helper total for misconfigured callers and tests.
    // Production reorder path always uses buckets_n>=1, but this preserves
    // fail-closed deterministic behavior if future call sites pass zero or a
    // collapsed single-bucket fanout.
    if buckets_n <= 1 {
        return 0;
    }

    // Singleton access domains dominate simple transfer-like batches. Keep that
    // hot path allocation-light by avoiding the global sort/dedup pass when the
    // canonical execution lane is already a one-key object domain.
    let mut domain_keys = tx_access_domain_keys(tx);
    let mixed = match domain_keys.len() {
        0 => 0,
        1 => domain_keys[0],
        _ => {
            // Derive the bucket hint from the canonical object-scoped domain rather than
            // a role-local secondary choice. Once the smallest key is fixed, hash over the
            // two smallest distinct access keys so equivalent read/write role flips stay on
            // the same Avalanche-style execution lane even when writes carry a larger local
            // secondary than reads.
            domain_keys.sort_unstable();
            domain_keys.dedup();
            let key_a = domain_keys[0];
            let key_b = domain_keys.iter().copied().find(|k| *k != key_a).unwrap_or(0);
            key_a ^ key_b.rotate_left(7)
        }
    };
    if buckets_n.is_power_of_two() {
        // Fast-path hot scheduler probes: keep the reduction in u64-space so
        // high-bit object ids cannot truncate on 32-bit targets before bucket
        // selection. For power-of-two divisors this matches modulo exactly.
        (mixed & ((buckets_n as u64) - 1)) as usize
    } else {
        // Reduce in u64-space first; casting mixed directly to usize would truncate
        // high bits on 32-bit targets and skew bucket selection under wide key domains.
        (mixed % buckets_n as u64) as usize
    }
}

fn reorder_for_strategy(txs: &mut [Tx], strategy: GroupingStrategy) {
    match strategy {
        GroupingStrategy::Original => {}
        GroupingStrategy::FootprintDesc => {
            // Keep direct footprint probes on the same fail-closed execution-domain
            // contract as the other scheduler reorder paths. Otherwise mixed
            // read/write version skew could silently collapse into a width-only hint
            // and drift lane selection instead of tripping the guardrail.
            for tx in txs.iter() {
                assert_tx_access_domain_versions_are_consistent(tx);
            }
            txs.sort_by_key(|tx| {
                let footprint = tx_access_domain_keys(tx).len();
                (std::cmp::Reverse(footprint), tx.id)
            });
        }
        GroupingStrategy::WriteFirst => {
            // Keep direct helper callers on the same fail-closed execution-domain
            // contract as the main scheduler path. Otherwise a mixed read/write
            // version skew could be silently collapsed into raw object-count hints
            // and drift across lane selection instead of tripping the guard.
            for tx in txs.iter() {
                assert_tx_access_domain_versions_are_consistent(tx);
            }
            txs.sort_by_key(|tx| {
                let write_keys = dedup_access_keys_no_version(&tx.write_set);
                let read_keys = dedup_access_keys_no_version(&tx.read_set);
                (
                    std::cmp::Reverse(write_keys.len()),
                    std::cmp::Reverse(read_keys.len()),
                    tx.id,
                )
            });
        }
        GroupingStrategy::WriteLast => {
            // Mirror WriteFirst: direct reorder probes must fail closed on mixed
            // access-domain version skew before deriving object-scoped lane hints.
            for tx in txs.iter() {
                assert_tx_access_domain_versions_are_consistent(tx);
            }
            txs.sort_by_key(|tx| {
                let write_keys = dedup_access_keys_no_version(&tx.write_set);
                let read_keys = dedup_access_keys_no_version(&tx.read_set);
                (write_keys.len(), std::cmp::Reverse(read_keys.len()), tx.id)
            });
        }
        GroupingStrategy::HotBucketInterleave => {
            // Heuristic reorder; see should_use_hot_bucket_interleave for adaptive trigger.
            // Heuristic: shard txs by a stable access-key hint, then round-robin buckets.
            // Goal is to avoid long same-key streaks in input order under hotspot workloads.
            // Validate mixed read/write domains up front so fail-closed skew guards still
            // fire even when micro-batch and degenerate-bucket short-circuits return early.
            for tx in txs.iter() {
                assert_tx_access_domain_versions_are_consistent(tx);
            }
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
            // Input-size capping (or a future lower env floor) can collapse fanout
            // to a single bucket, where interleave degenerates to identity while
            // still paying probe cost.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    fn o(id: u64) -> ObjectRef {
        ObjectRef { id, version: 1 }
    }
    fn ov(id: u64, version: u64) -> ObjectRef {
        ObjectRef { id, version }
    }
    fn tx(id: u64, r: Vec<ObjectRef>, w: Vec<ObjectRef>) -> Tx {
        Tx {
            id,
            read_set: r,
            write_set: w,
            payload: vec![],
        }
    }

    fn profile_with_stage_hits(
        ww: usize,
        wr: usize,
        rw: usize,
        conflict_hits: usize,
    ) -> GroupingProfile {
        GroupingProfile {
            tx_count: 0,
            group_count: 0,
            grouped_count: 0,
            max_group_size: 0,
            min_group_size: 0,
            avg_group_size: 0.0,
            hot_object_share: 0.0,
            conflict_checks: 0,
            conflict_hits,
            candidate_groups_scanned: 0,
            retry_fallback_new_groups: 0,
            stage_ww_checks: 0,
            stage_ww_hits: ww,
            stage_wr_checks: 0,
            stage_wr_hits: wr,
            stage_rw_checks: 0,
            stage_rw_hits: rw,
        }
    }

    fn profile_with_retry_scan(
        tx_count: usize,
        group_count: usize,
        conflict_hits: usize,
        candidate_groups_scanned: usize,
    ) -> GroupingProfile {
        GroupingProfile {
            tx_count,
            group_count,
            grouped_count: tx_count,
            max_group_size: tx_count,
            min_group_size: group_count.min(tx_count),
            avg_group_size: if group_count == 0 {
                0.0
            } else {
                tx_count as f64 / group_count as f64
            },
            hot_object_share: 0.0,
            conflict_checks: candidate_groups_scanned,
            conflict_hits,
            candidate_groups_scanned,
            retry_fallback_new_groups: 0,
            stage_ww_checks: 0,
            stage_ww_hits: 0,
            stage_wr_checks: 0,
            stage_wr_hits: 0,
            stage_rw_checks: 0,
            stage_rw_hits: 0,
        }
    }

    #[test]
    fn dominant_retry_lead_share_tracks_clear_stage_skew() {
        let profile = profile_with_stage_hits(9, 3, 1, 10);

        assert_eq!(profile.dominant_retry_stage(), "ww");
        assert_eq!(profile.dominant_retry_lead_hits(), 6);
        assert!((profile.dominant_retry_lead_share() - 0.6).abs() < f64::EPSILON);
        assert!((profile.dominant_attributed_retry_lead_share() - (6.0 / 13.0)).abs() < 1e-12);
    }

    #[test]
    fn dominant_retry_lead_share_collapses_for_mixed_stage_ties() {
        let profile = profile_with_stage_hits(4, 4, 1, 8);

        assert_eq!(profile.dominant_retry_stage(), "mixed");
        assert_eq!(profile.dominant_retry_lead_hits(), 0);
        assert_eq!(profile.dominant_retry_lead_share(), 0.0);
        assert_eq!(profile.dominant_attributed_retry_lead_share(), 0.0);
    }

    #[test]
    fn dominant_retry_lead_share_stays_zero_without_conflicts() {
        let profile = profile_with_stage_hits(0, 0, 0, 0);

        assert_eq!(profile.dominant_retry_stage(), "none");
        assert_eq!(profile.dominant_retry_lead_hits(), 0);
        assert_eq!(profile.dominant_retry_lead_share(), 0.0);
        assert_eq!(profile.dominant_attributed_retry_lead_share(), 0.0);
    }

    #[test]
    fn retry_stage_concentration_peaks_for_single_stage_retries() {
        let profile = profile_with_stage_hits(10, 0, 0, 10);

        assert!((profile.retry_stage_concentration() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn retry_stage_concentration_drops_for_evenly_mixed_retries() {
        let profile = profile_with_stage_hits(3, 3, 3, 9);

        assert!((profile.retry_stage_concentration() - (1.0 / 3.0)).abs() < 1e-12);
    }

    #[test]
    fn retry_stage_mix_entropy_peaks_for_evenly_mixed_non_overlapping_retries() {
        let profile = profile_with_stage_hits(3, 3, 3, 9);

        assert_eq!(profile.attributed_retry_hits(), 9);
        assert_eq!(profile.retry_stage_overlap_hits(), 0);
        assert_eq!(profile.retry_stage_overlap_share(), 0.0);
        assert_eq!(profile.retry_stage_overlap_share_of_attributed(), 0.0);
        assert!((profile.retry_stage_mix_entropy() - 1.0).abs() < 1e-12);
    }

    #[test]
    fn retry_stage_concentration_stays_zero_without_conflicts() {
        let profile = profile_with_stage_hits(0, 0, 0, 0);

        assert_eq!(profile.retry_stage_concentration(), 0.0);
    }

    #[test]
    fn stage_retry_rate_and_per_tx_helpers_handle_zero_denominators() {
        let profile = GroupingProfile {
            tx_count: 8,
            group_count: 0,
            grouped_count: 0,
            max_group_size: 0,
            min_group_size: 0,
            avg_group_size: 0.0,
            hot_object_share: 0.0,
            conflict_checks: 0,
            conflict_hits: 0,
            candidate_groups_scanned: 0,
            retry_fallback_new_groups: 0,
            stage_ww_checks: 4,
            stage_ww_hits: 2,
            stage_wr_checks: 0,
            stage_wr_hits: 3,
            stage_rw_checks: 5,
            stage_rw_hits: 1,
        };

        assert!((profile.ww_retry_hit_rate() - 0.5).abs() < f64::EPSILON);
        assert_eq!(profile.wr_retry_hit_rate(), 0.0);
        assert!((profile.rw_retry_hit_rate() - 0.2).abs() < 1e-12);
        assert!((profile.ww_retry_hits_per_tx() - 0.25).abs() < f64::EPSILON);
        assert!((profile.wr_retry_hits_per_tx() - 0.375).abs() < 1e-12);
        assert!((profile.rw_retry_hits_per_tx() - 0.125).abs() < f64::EPSILON);

        let zero = profile_with_stage_hits(0, 0, 0, 0);
        assert_eq!(zero.ww_retry_hit_rate(), 0.0);
        assert_eq!(zero.wr_retry_hit_rate(), 0.0);
        assert_eq!(zero.rw_retry_hit_rate(), 0.0);
        assert_eq!(zero.ww_retry_hits_per_tx(), 0.0);
        assert_eq!(zero.wr_retry_hits_per_tx(), 0.0);
        assert_eq!(zero.rw_retry_hits_per_tx(), 0.0);
    }

    #[test]
    fn retry_scan_metrics_track_misses_hits_and_zero_denominators() {
        let profile = profile_with_retry_scan(12, 3, 4, 10);

        assert_eq!(profile.retry_scan_misses(), 6);
        assert!((profile.candidate_groups_per_retry_hit() - 2.5).abs() < f64::EPSILON);
        assert_eq!(profile.retry_fallback_share_of_retry_hits(), 0.0);
        assert!((profile.retry_scan_hit_rate() - 0.4).abs() < f64::EPSILON);
        assert!((profile.retry_scan_miss_rate() - 0.6).abs() < f64::EPSILON);
        assert!((profile.retry_scan_misses_per_tx() - 0.5).abs() < f64::EPSILON);
        assert!((profile.retry_scan_misses_per_group() - 2.0).abs() < f64::EPSILON);
        assert!((profile.retry_scan_overhang_per_hit() - 1.5).abs() < f64::EPSILON);
        assert!((profile.retry_scan_overhang_per_reused_placement() - (2.0 / 3.0)).abs() < 1e-12);
        assert_eq!(profile.retry_reuse_salvage_rate(), 1.0);

        let zero = profile_with_retry_scan(0, 0, 0, 0);
        assert_eq!(zero.candidate_groups_per_retry_hit(), 0.0);
        assert_eq!(zero.retry_reuse_salvage_rate(), 0.0);
        assert_eq!(zero.retry_scan_hit_rate(), 0.0);
        assert_eq!(zero.retry_scan_miss_rate(), 0.0);
        assert_eq!(zero.retry_scan_misses_per_tx(), 0.0);
        assert_eq!(zero.retry_scan_misses_per_group(), 0.0);
        assert_eq!(zero.retry_scan_overhang_per_hit(), 0.0);
        assert_eq!(zero.retry_scan_overhang_per_reused_placement(), 0.0);
    }

    #[test]
    fn retry_attribution_metrics_surface_overlap_and_unattributed_hits() {
        let profile = GroupingProfile {
            tx_count: 9,
            group_count: 3,
            grouped_count: 9,
            max_group_size: 4,
            min_group_size: 2,
            avg_group_size: 3.0,
            hot_object_share: 0.0,
            conflict_checks: 0,
            conflict_hits: 5,
            candidate_groups_scanned: 7,
            retry_fallback_new_groups: 0,
            stage_ww_checks: 0,
            stage_ww_hits: 3,
            stage_wr_checks: 0,
            stage_wr_hits: 2,
            stage_rw_checks: 0,
            stage_rw_hits: 2,
        };

        assert_eq!(profile.attributed_retry_hits(), 7);
        assert_eq!(profile.unattributed_retry_hits(), 0);
        assert_eq!(profile.retry_stage_overlap_hits(), 2);
        assert!((profile.retry_stage_overlap_share() - 0.4).abs() < f64::EPSILON);
        assert!((profile.retry_stage_overlap_share_of_attributed() - (2.0 / 7.0)).abs() < 1e-12);
        assert_eq!(profile.singly_attributed_retry_hits(), 5);
        assert!((profile.singly_attributed_retry_share() - 1.0).abs() < f64::EPSILON);
        assert!((profile.singly_attributed_retry_share_of_attributed() - (5.0 / 7.0)).abs() < 1e-12);
        assert_eq!(profile.retry_attribution_coverage(), 1.0);
        assert!((profile.unattributed_retry_share() - 0.0).abs() < f64::EPSILON);

        let partial = profile_with_stage_hits(2, 1, 0, 6);
        assert_eq!(partial.attributed_retry_hits(), 3);
        assert_eq!(partial.unattributed_retry_hits(), 3);
        assert_eq!(partial.retry_stage_overlap_hits(), 0);
        assert_eq!(partial.singly_attributed_retry_hits(), 3);
        assert!((partial.singly_attributed_retry_share() - 0.5).abs() < f64::EPSILON);
        assert!((partial.singly_attributed_retry_share_of_attributed() - 1.0).abs() < f64::EPSILON);
        assert!((partial.retry_attribution_coverage() - 0.5).abs() < f64::EPSILON);
        assert!((partial.unattributed_retry_share() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn ww_conflict() {
        assert!(detect_conflict(
            &tx(1, vec![], vec![o(1)]),
            &tx(2, vec![], vec![o(1)])
        ));
    }

    #[test]
    fn ww_conflict_treats_object_versions_as_one_write_domain() {
        assert!(detect_conflict(
            &tx(1, vec![], vec![ov(7, 1)]),
            &tx(2, vec![], vec![ov(7, 9)])
        ));
        assert!(!detect_conflict(
            &tx(1, vec![], vec![ov(7, 1)]),
            &tx(2, vec![], vec![ov(8, 9)])
        ));
    }

    #[test]
    fn rw_conflict() {
        assert!(detect_conflict(
            &tx(1, vec![o(2)], vec![]),
            &tx(2, vec![], vec![o(2)])
        ));
    }

    #[test]
    fn write_only_pairs_use_ww_semantics_for_hit_and_miss() {
        let write_only_hit_a = tx(1, vec![], vec![o(7), o(7), o(11)]);
        let write_only_hit_b = tx(2, vec![], vec![o(9), o(11)]);
        let write_only_miss = tx(3, vec![], vec![o(99), o(100)]);

        assert!(detect_conflict(&write_only_hit_a, &write_only_hit_b));
        assert!(detect_conflict(&write_only_hit_b, &write_only_hit_a));
        assert!(!detect_conflict(&write_only_hit_a, &write_only_miss));
        assert!(!detect_conflict(&write_only_miss, &write_only_hit_a));
    }

    #[test]
    fn no_conflict() {
        assert!(!detect_conflict(
            &tx(1, vec![o(1)], vec![]),
            &tx(2, vec![o(2)], vec![])
        ));
    }

    #[test]
    #[should_panic(
        expected = "mixed access domain contains the same object id with multiple versions"
    )]
    fn detect_conflict_rejects_cross_domain_version_skew_for_same_object_id() {
        let skewed = tx(
            1,
            vec![ObjectRef { id: 7, version: 2 }],
            vec![ObjectRef { id: 7, version: 1 }],
        );
        let other = tx(2, vec![], vec![o(9)]);

        let _ = detect_conflict(&skewed, &other);
    }

    #[test]
    fn read_only_overlap_is_non_conflicting() {
        assert!(!detect_conflict(
            &tx(1, vec![o(7), o(8)], vec![]),
            &tx(2, vec![o(8), o(9)], vec![])
        ));
    }

    #[test]
    fn detect_conflict_is_symmetric_for_read_write_fast_paths() {
        let read_only = tx(1, vec![o(42), o(42), o(9)], vec![]);
        let write_only_hit = tx(2, vec![], vec![o(42)]);
        let write_only_miss = tx(3, vec![], vec![o(99)]);

        assert!(detect_conflict(&read_only, &write_only_hit));
        assert!(detect_conflict(&write_only_hit, &read_only));
        assert!(!detect_conflict(&read_only, &write_only_miss));
        assert!(!detect_conflict(&write_only_miss, &read_only));
    }

    #[test]
    fn tiny_footprint_conflict_check_handles_duplicates_without_false_positive() {
        let a = tx(1, vec![o(10), o(10), o(11)], vec![]);
        let b = tx(2, vec![o(12), o(12), o(13)], vec![]);
        let c = tx(3, vec![], vec![o(11)]);

        assert!(!detect_conflict(&a, &b));
        assert!(detect_conflict(&a, &c));
    }

    #[test]
    fn singleton_access_conflict_path_handles_skewed_footprints() {
        let singleton_write = tx(1, vec![], vec![o(42)]);
        let wide_read_hit = tx(2, vec![o(7), o(8), o(42), o(9), o(10)], vec![]);
        let wide_read_miss = tx(3, vec![o(7), o(8), o(9), o(10)], vec![]);

        assert!(detect_conflict(&singleton_write, &wide_read_hit));
        assert!(!detect_conflict(&singleton_write, &wide_read_miss));
    }

    #[test]
    fn vec_hashset_intersects_handles_singleton_hashset_domain() {
        let mut singleton = HashSet::new();
        singleton.insert(42u64);

        assert!(vec_hashset_intersects(&[7, 8, 42, 9], &singleton));
        assert!(!vec_hashset_intersects(&[7, 8, 9], &singleton));
    }

    #[test]
    fn vec_hashset_intersects_tiny_duplicate_probe_path_preserves_semantics() {
        let domain: HashSet<u64> = [11u64, 12u64].into_iter().collect();

        // Duplicate-heavy tiny probe vectors should behave identically to the
        // generic path while avoiding repeated hash probes for the same key.
        assert!(vec_hashset_intersects(&[9, 9, 9, 12, 12], &domain));
        assert!(!vec_hashset_intersects(&[9, 9, 10, 10], &domain));
    }

    #[test]
    fn vec_hashset_intersects_medium_duplicate_probe_path_preserves_semantics() {
        let domain: HashSet<u64> = [77u64, 88u64].into_iter().collect();

        // Medium duplicate-heavy probe vectors should still preserve hit/miss
        // correctness while capping repeated hash probes.
        let hit = [
            1, 1, 2, 2, 3, 3, 4, 4, 77, 77, 77, 5, 5, 6, 6, 7, 7, 8, 8, 9,
        ];
        let miss = [
            1, 1, 2, 2, 3, 3, 4, 4, 55, 55, 56, 56, 57, 57, 58, 58, 59, 59, 60, 60,
        ];

        assert!(vec_hashset_intersects(&hit, &domain));
        assert!(!vec_hashset_intersects(&miss, &domain));
    }

    #[test]
    fn vec_hashset_intersects_large_duplicate_probe_path_preserves_semantics() {
        let domain: HashSet<u64> = [777u64, 888u64].into_iter().collect();

        let mut hit = Vec::new();
        for key in 1..=20u64 {
            hit.push(key);
            hit.push(key);
        }
        hit.extend([777, 777, 777, 21, 21, 22, 22]);

        let mut miss = Vec::new();
        for key in 1..=24u64 {
            miss.push(10_000 + key);
            miss.push(10_000 + key);
        }

        // Large duplicate-heavy probe vectors should keep the same hit/miss
        // behavior while avoiding repeated lookups for the same object-domain key.
        assert!(vec_hashset_intersects(&hit, &domain));
        assert!(!vec_hashset_intersects(&miss, &domain));
    }

    #[test]
    fn skewed_small_vs_large_conflict_path_handles_large_domains() {
        let small_write = tx(1, vec![], vec![o(101), o(202), o(303), o(404)]);
        let mut wide_read_hit: Vec<ObjectRef> = (1..=64).map(o).collect();
        wide_read_hit.push(o(303));
        let wide_read_miss: Vec<ObjectRef> = (1..=64).map(|id| o(id + 10_000)).collect();

        assert!(detect_conflict(&small_write, &tx(2, wide_read_hit, vec![])));
        assert!(!detect_conflict(
            &small_write,
            &tx(3, wide_read_miss, vec![])
        ));
    }

    #[test]
    fn medium_small_vs_large_conflict_path_avoids_hashset_and_preserves_semantics() {
        let small_write = tx(
            1,
            vec![],
            vec![o(501), o(502), o(503), o(503), o(504), o(505)],
        );
        let mut wide_read_hit: Vec<ObjectRef> = (1..=64).map(|id| o(10_000 + id)).collect();
        wide_read_hit.push(o(504));
        let wide_read_miss: Vec<ObjectRef> = (1..=64).map(|id| o(20_000 + id)).collect();

        assert!(detect_conflict(&small_write, &tx(2, wide_read_hit, vec![])));
        assert!(!detect_conflict(
            &small_write,
            &tx(3, wide_read_miss, vec![])
        ));
    }

    #[test]
    fn medium_small_vs_very_large_conflict_path_preserves_semantics() {
        let small_write = tx(1, vec![], vec![o(901), o(902), o(903), o(904), o(905)]);
        let mut very_wide_read_hit: Vec<ObjectRef> = (1..=256).map(|id| o(30_000 + id)).collect();
        very_wide_read_hit.push(o(904));
        let very_wide_read_miss: Vec<ObjectRef> = (1..=256).map(|id| o(40_000 + id)).collect();

        assert!(detect_conflict(
            &small_write,
            &tx(2, very_wide_read_hit, vec![])
        ));
        assert!(!detect_conflict(
            &small_write,
            &tx(3, very_wide_read_miss, vec![])
        ));
    }

    #[test]
    fn medium_small_vs_just_over_old_large_cutoff_preserves_semantics() {
        let small_write = tx(
            1,
            vec![],
            vec![o(1_101), o(1_102), o(1_103), o(1_104), o(1_105)],
        );
        let mut read_hit: Vec<ObjectRef> = (1..=65).map(|id| o(50_000 + id)).collect();
        read_hit.push(o(1_104));
        let read_miss: Vec<ObjectRef> = (1..=65).map(|id| o(60_000 + id)).collect();

        assert!(detect_conflict(&small_write, &tx(2, read_hit, vec![])));
        assert!(!detect_conflict(&small_write, &tx(3, read_miss, vec![])));
    }

    #[test]
    fn access_domain_versions_are_consistent_for_duplicate_same_version_refs() {
        assert!(access_domain_versions_are_consistent(&[
            o(42),
            o(42),
            ObjectRef { id: 42, version: 1 },
            o(99),
        ]));
    }

    #[test]
    fn access_domain_versions_are_inconsistent_for_mixed_version_refs() {
        assert!(!access_domain_versions_are_consistent(&[
            ObjectRef { id: 42, version: 1 },
            ObjectRef { id: 42, version: 2 },
            o(99),
        ]));
    }

    #[test]
    fn access_domain_versions_two_entry_fast_path_preserves_echo_and_skew_semantics() {
        assert!(access_domain_versions_are_consistent(&[
            ObjectRef { id: 42, version: 7 },
            ObjectRef { id: 42, version: 7 },
        ]));
        assert!(access_domain_versions_are_consistent(&[
            ObjectRef { id: 42, version: 7 },
            ObjectRef { id: 99, version: 1 },
        ]));
        assert!(!access_domain_versions_are_consistent(&[
            ObjectRef { id: 42, version: 7 },
            ObjectRef { id: 42, version: 8 },
        ]));
    }

    #[test]
    fn access_domain_versions_small_domain_fast_path_preserves_echo_and_skew_semantics() {
        assert!(access_domain_versions_are_consistent(&[
            ObjectRef { id: 42, version: 7 },
            ObjectRef { id: 99, version: 1 },
            ObjectRef { id: 42, version: 7 },
            ObjectRef { id: 7, version: 3 },
        ]));
        assert!(!access_domain_versions_are_consistent(&[
            ObjectRef { id: 42, version: 7 },
            ObjectRef { id: 99, version: 1 },
            ObjectRef { id: 42, version: 8 },
            ObjectRef { id: 7, version: 3 },
        ]));
    }

    #[test]
    fn combined_access_domain_versions_are_consistent_across_read_write_split() {
        assert!(combined_access_domain_versions_are_consistent(
            &[ObjectRef { id: 42, version: 1 }],
            &[ObjectRef { id: 42, version: 1 }, o(99)],
        ));
    }

    #[test]
    fn combined_access_domain_versions_are_consistent_for_mixed_singleton_distinct_ids() {
        assert!(combined_access_domain_versions_are_consistent(
            &[ObjectRef { id: 42, version: 1 }],
            &[ObjectRef { id: 7, version: 9 }],
        ));
    }

    #[test]
    fn combined_access_domain_versions_are_consistent_for_small_duplicate_cross_domain_echoes() {
        assert!(combined_access_domain_versions_are_consistent(
            &[
                ObjectRef { id: 42, version: 1 },
                ObjectRef { id: 42, version: 1 },
                o(99),
            ],
            &[
                o(99),
                ObjectRef { id: 42, version: 1 },
                ObjectRef { id: 7, version: 1 },
            ],
        ));
    }

    #[test]
    fn combined_access_domain_versions_are_inconsistent_across_read_write_split() {
        assert!(!combined_access_domain_versions_are_consistent(
            &[ObjectRef { id: 42, version: 1 }],
            &[ObjectRef { id: 42, version: 2 }],
        ));
    }

    #[test]
    fn combined_access_domain_versions_are_inconsistent_when_writes_are_empty() {
        assert!(!combined_access_domain_versions_are_consistent(
            &[
                ObjectRef { id: 42, version: 1 },
                ObjectRef { id: 42, version: 2 },
            ],
            &[],
        ));
    }

    #[test]
    fn combined_access_domain_versions_are_inconsistent_when_reads_are_empty() {
        assert!(!combined_access_domain_versions_are_consistent(
            &[],
            &[
                ObjectRef { id: 42, version: 1 },
                ObjectRef { id: 42, version: 2 },
            ],
        ));
    }

    #[test]
    fn dedup_access_keys_large_path_preserves_first_seen_order() {
        let keys = dedup_access_keys(&[
            o(100),
            o(200),
            o(100),
            o(300),
            o(400),
            o(300),
            o(500),
            o(600),
            o(700),
            o(600),
        ]);

        assert_eq!(keys, vec![100, 200, 300, 400, 500, 600, 700]);
    }

    #[test]
    fn tx_access_domain_keys_dedups_shared_object_scope_across_read_and_write_sets() {
        let keys = tx_access_domain_keys(&tx(
            1,
            vec![o(11), o(11), o(22), o(33)],
            vec![o(22), o(44), o(44), o(11)],
        ));

        // Object-scoped access domains should stay deduplicated across both read
        // and write footprints, with writes first so telemetry matches the
        // scheduler's stronger conflict signal.
        assert_eq!(keys, vec![22, 44, 11, 33]);
    }

    #[test]
    fn read_domain_only_keys_small_write_domain_preserves_read_order_after_filtering() {
        let write_keys = vec![11, 22, 33, 44, 55, 66, 77, 88];

        let keys = read_domain_only_keys(
            &[o(22), o(5), o(44), o(5), o(99), o(77), o(99), o(123)],
            &write_keys,
        );

        // The small write-domain fast path should filter shared objects without
        // disturbing first-seen ordering for surviving read-only keys.
        assert_eq!(keys, vec![5, 99, 123]);
    }

    #[test]
    fn read_domain_only_keys_large_write_domain_preserves_read_order_after_filtering() {
        let write_keys = vec![100, 200, 300, 400, 500, 600, 700, 800, 900, 1_000];

        let keys = read_domain_only_keys(
            &[
                o(200),
                o(42),
                o(500),
                o(42),
                o(77),
                o(800),
                o(77),
                o(900),
                o(123),
            ],
            &write_keys,
        );

        // Shared objects should be filtered once, while surviving read-only
        // objects keep first-seen order for deterministic access-domain reporting.
        assert_eq!(keys, vec![42, 77, 123]);
    }

    #[test]
    fn read_domain_only_keys_treats_object_zero_as_real_shared_domain_key() {
        let write_keys = vec![
            0, 100, 200, 300, 400, 500, 600, 700, 800, 900,
        ];

        let keys = read_domain_only_keys(
            &[o(0), o(42), o(0), o(42), o(900), o(7), o(7)],
            &write_keys,
        );

        // Object id 0 is a real execution-domain member. Large write-domain
        // filtering must remove it just like any other shared key rather than
        // treating it as an empty/sentinel lane marker.
        assert_eq!(keys, vec![42, 7]);
    }

    #[test]
    fn tx_access_domain_keys_match_hot_bucket_write_first_scope() {
        let tx = tx(
            1,
            vec![o(9), o(9), o(40), o(50)],
            vec![o(7), o(7), o(9), o(30)],
        );

        let keys = tx_access_domain_keys(&tx);
        let (key_a, key_b) = hot_bucket_keys(&tx);

        assert_eq!(keys, vec![7, 9, 30, 40, 50]);
        assert_eq!((key_a, key_b), (keys[0], keys[1]));
    }

    #[test]
    #[should_panic(
        expected = "mixed access domain contains the same object id with multiple versions"
    )]
    fn tx_access_domain_keys_rejects_cross_domain_version_skew_for_same_object_id() {
        let tx = tx(
            1,
            vec![ObjectRef { id: 7, version: 2 }],
            vec![ObjectRef { id: 7, version: 1 }],
        );

        let _ = tx_access_domain_keys(&tx);
    }

    #[test]
    fn hot_bucket_keys_filter_shared_read_keys_before_selecting_second_domain_key() {
        let tx = tx(
            1,
            vec![o(8), o(8), o(9), o(10)],
            vec![o(8), o(8), o(40), o(40), o(50)],
        );

        let keys = tx_access_domain_keys(&tx);
        let (key_a, key_b) = hot_bucket_keys(&tx);

        assert_eq!(keys, vec![8, 40, 50, 9, 10]);
        assert_eq!((key_a, key_b), (8, 40));
        assert_eq!((key_a, key_b), (keys[0], keys[1]));
    }

    #[test]
    fn tx_access_domain_keys_treat_object_zero_as_real_write_domain_member() {
        let tx = tx(1, vec![o(5), o(0), o(5)], vec![o(0), o(11), o(11)]);

        // Object id 0 is a real execution-domain member, not a sentinel. When it
        // participates in the write domain, write-first scope reporting should
        // keep it as the leading canonical lane key.
        assert_eq!(tx_access_domain_keys(&tx), vec![0, 11, 5]);
    }

    #[test]
    fn primary_access_domain_key_treats_object_zero_as_real_key_for_write_and_read_fallback() {
        let write_primary = tx(1, vec![o(5)], vec![o(0), o(11)]);
        let read_only = tx(2, vec![o(0), o(11)], vec![]);

        // The canonical primary execution-domain key should preserve object id 0
        // both when it leads the write domain and when the helper falls back to a
        // read-only domain.
        assert_eq!(primary_access_domain_key(&write_primary), Some(0));
        assert_eq!(primary_access_domain_key(&read_only), Some(0));
    }

    #[test]
    fn hot_bucket_keys_keep_object_zero_secondary_stable_across_role_flips() {
        let write_zero = tx(1, vec![o(0), o(11)], vec![o(17)]);
        let read_zero = tx(2, vec![o(17)], vec![o(0), o(11)]);

        // Object id 0 is a real lane key. Equivalent mixed domains touching
        // {0, 11, 17} must keep the same secondary anchor even when read/write
        // roles flip, otherwise hot-lane isolation can drift across retries.
        assert_eq!(hot_bucket_keys(&write_zero), (0, 11));
        assert_eq!(hot_bucket_keys(&read_zero), (0, 11));
    }

    #[test]
    #[should_panic(
        expected = "mixed access domain contains the same object id with multiple versions"
    )]
    fn hot_bucket_keys_rejects_cross_domain_version_skew_for_same_object_id() {
        let tx = tx(
            1,
            vec![ObjectRef { id: 7, version: 2 }],
            vec![ObjectRef { id: 7, version: 1 }],
        );

        let _ = hot_bucket_keys(&tx);
    }

    #[test]
    fn overlapping_read_write_domains_do_not_double_count_shared_object_conflicts() {
        let txs = vec![tx(1, vec![o(7)], vec![o(7)]), tx(2, vec![], vec![o(7)])];

        let (groups, profile) =
            build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::Original);

        assert_eq!(groups.len(), 2);
        assert_eq!(
            groups[0].iter().map(|tx| tx.id).collect::<Vec<_>>(),
            vec![1]
        );
        assert_eq!(
            groups[1].iter().map(|tx| tx.id).collect::<Vec<_>>(),
            vec![2]
        );
        // The first tx still pays its normal write-domain probes, but the shared
        // read/write key should not be recorded twice and inflate later hit counts.
        assert_eq!(profile.conflict_checks, 4);
        assert_eq!(profile.conflict_hits, 1);
    }

    #[test]
    fn grouping_parallel_safe() {
        let g = build_parallel_groups(&[
            tx(1, vec![], vec![o(1)]),
            tx(2, vec![], vec![o(2)]),
            tx(3, vec![o(1)], vec![]),
        ]);
        assert_eq!(g.len(), 2);
        assert_eq!(g.iter().map(|x| x.len()).sum::<usize>(), 3);
        // first group can contain tx1+tx2 (non-conflict), tx3 should be separate
        assert!(g
            .iter()
            .any(|grp| grp.iter().any(|t| t.id == 3) && grp.len() == 1));
    }

    #[test]
    fn original_free_ingress_fast_path_keeps_profile_stable_and_ordered() {
        let txs = vec![
            tx(31, vec![], vec![]),
            tx(32, vec![], vec![]),
            tx(33, vec![], vec![]),
            tx(34, vec![], vec![]),
        ];

        let (groups, profile) =
            build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::Original);

        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].iter().map(|tx| tx.id).collect::<Vec<_>>(), vec![31, 32, 33, 34]);
        assert_eq!(profile.tx_count, 4);
        assert_eq!(profile.group_count, 1);
        assert_eq!(profile.grouped_count, 4);
        assert_eq!(profile.max_group_size, 4);
        assert_eq!(profile.min_group_size, 4);
        assert_eq!(profile.avg_group_size, 4.0);
        assert_eq!(profile.hot_object_share, 0.0);
        assert_eq!(profile.conflict_checks, 0);
        assert_eq!(profile.conflict_hits, 0);
        assert_eq!(profile.candidate_groups_scanned, 0);
        assert_eq!(profile.stage_ww_checks, 0);
        assert_eq!(profile.stage_ww_hits, 0);
        assert_eq!(profile.stage_wr_checks, 0);
        assert_eq!(profile.stage_wr_hits, 0);
        assert_eq!(profile.stage_rw_checks, 0);
        assert_eq!(profile.stage_rw_hits, 0);
    }

    #[test]
    fn auto_adaptive_free_ingress_fast_path_keeps_profile_stable_and_ordered() {
        let txs = vec![
            tx(41, vec![], vec![]),
            tx(42, vec![], vec![]),
            tx(43, vec![], vec![]),
            tx(44, vec![], vec![]),
        ];

        let (groups, profile) =
            build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::AutoAdaptive);

        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].iter().map(|tx| tx.id).collect::<Vec<_>>(), vec![41, 42, 43, 44]);
        assert_eq!(profile.tx_count, 4);
        assert_eq!(profile.group_count, 1);
        assert_eq!(profile.grouped_count, 4);
        assert_eq!(profile.max_group_size, 4);
        assert_eq!(profile.min_group_size, 4);
        assert_eq!(profile.avg_group_size, 4.0);
        assert_eq!(profile.hot_object_share, 0.0);
        assert_eq!(profile.conflict_checks, 0);
        assert_eq!(profile.conflict_hits, 0);
        assert_eq!(profile.candidate_groups_scanned, 0);
        assert_eq!(profile.stage_ww_checks, 0);
        assert_eq!(profile.stage_ww_hits, 0);
        assert_eq!(profile.stage_wr_checks, 0);
        assert_eq!(profile.stage_wr_hits, 0);
        assert_eq!(profile.stage_rw_checks, 0);
        assert_eq!(profile.stage_rw_hits, 0);
    }

    #[test]
    fn strategy_preserves_tx_count() {
        let txs = vec![
            tx(1, vec![o(1)], vec![o(2)]),
            tx(2, vec![o(2)], vec![o(3)]),
            tx(3, vec![o(4)], vec![]),
        ];
        let (g1, _) = build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::Original);
        let (g2, _) =
            build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::FootprintDesc);
        let (g3, _) =
            build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::AutoAdaptive);
        let (g4, _) =
            build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::AggressiveGreedy);
        let c1: usize = g1.iter().map(|g| g.len()).sum();
        let c2: usize = g2.iter().map(|g| g.len()).sum();
        let c3: usize = g3.iter().map(|g| g.len()).sum();
        let c4: usize = g4.iter().map(|g| g.len()).sum();
        assert_eq!(c1, txs.len());
        assert_eq!(c2, txs.len());
        assert_eq!(c3, txs.len());
        assert_eq!(c4, txs.len());
    }

    #[test]
    fn aggressive_groups_are_pairwise_non_conflicting() {
        let txs = vec![
            tx(1, vec![o(1)], vec![o(2)]),
            tx(2, vec![o(3)], vec![o(4)]),
            tx(3, vec![o(2)], vec![]),
            tx(4, vec![o(5)], vec![o(1)]),
            tx(5, vec![o(9)], vec![o(10)]),
        ];
        let (groups, _) =
            build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::AggressiveGreedy);

        for grp in groups {
            for i in 0..grp.len() {
                for j in (i + 1)..grp.len() {
                    assert!(!detect_conflict(&grp[i], &grp[j]));
                }
            }
        }
    }

    #[test]
    fn aggressive_fast_path_matches_original_when_deep_scan_is_disabled() {
        let _env = env_lock();
        let _deep = EnvGuard::set("TRNM_AGGR_DEEP_SCAN", "0");

        let txs = vec![
            tx(1, vec![], vec![o(10)]),
            tx(2, vec![o(10)], vec![]),
            tx(3, vec![o(30)], vec![o(40)]),
            tx(4, vec![o(40)], vec![]),
            tx(5, vec![], vec![]),
            tx(6, vec![o(90)], vec![o(91)]),
        ];

        let (original_groups, original_profile) =
            build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::Original);
        let (aggressive_groups, aggressive_profile) =
            build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::AggressiveGreedy);

        let original_ids: Vec<Vec<u64>> = original_groups
            .iter()
            .map(|group| group.iter().map(|tx| tx.id).collect())
            .collect();
        let aggressive_ids: Vec<Vec<u64>> = aggressive_groups
            .iter()
            .map(|group| group.iter().map(|tx| tx.id).collect())
            .collect();

        assert_eq!(aggressive_ids, original_ids);
        assert_eq!(aggressive_profile.group_count, original_profile.group_count);
        assert_eq!(
            aggressive_profile.grouped_count,
            original_profile.grouped_count
        );
        assert_eq!(
            aggressive_profile.max_group_size,
            original_profile.max_group_size
        );
        assert_eq!(
            aggressive_profile.min_group_size,
            original_profile.min_group_size
        );
        assert_eq!(
            aggressive_profile.conflict_checks,
            original_profile.conflict_checks
        );
        assert_eq!(
            aggressive_profile.conflict_hits,
            original_profile.conflict_hits
        );
        assert_eq!(aggressive_profile.candidate_groups_scanned, 0);
        assert_eq!(aggressive_profile.stage_ww_checks, 0);
        assert_eq!(aggressive_profile.stage_wr_checks, 0);
        assert_eq!(aggressive_profile.stage_rw_checks, 0);
    }

    #[test]
    fn aggressive_fast_path_does_not_double_count_shared_read_write_domains() {
        let _env = env_lock();
        let _deep = EnvGuard::set("TRNM_AGGR_DEEP_SCAN", "0");

        let txs = vec![tx(1, vec![o(7)], vec![o(7)]), tx(2, vec![], vec![o(7)])];

        let (groups, profile) =
            build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::AggressiveGreedy);

        assert_eq!(groups.len(), 2);
        assert_eq!(
            groups[0].iter().map(|tx| tx.id).collect::<Vec<_>>(),
            vec![1]
        );
        assert_eq!(
            groups[1].iter().map(|tx| tx.id).collect::<Vec<_>>(),
            vec![2]
        );
        assert_eq!(profile.conflict_checks, 4);
        assert_eq!(profile.conflict_hits, 1);
        assert_eq!(profile.candidate_groups_scanned, 0);
        assert_eq!(profile.retry_fallback_new_groups, 0);
    }

    fn env_lock() -> MutexGuard<'static, ()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        match ENV_LOCK.get_or_init(|| Mutex::new(())).lock() {
            Ok(guard) => guard,
            Err(err) => err.into_inner(),
        }
    }

    #[test]
    fn aggressive_round_robin_cursor_avoids_even_id_bias() {
        let _env = env_lock();
        let _deep = EnvGuard::set("TRNM_AGGR_DEEP_SCAN", "1");
        let _rr = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", "1");
        let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "1");

        let txs = vec![
            tx(1, vec![], vec![o(7)]),    // group 0
            tx(3, vec![], vec![o(7)]),    // forced to group 1 (conflicts with tx1)
            tx(10, vec![o(101)], vec![]), // independent even ids that previously pinned to offset 0
            tx(12, vec![o(102)], vec![]),
            tx(14, vec![o(103)], vec![]),
            tx(16, vec![o(104)], vec![]),
        ];

        let (groups, _) =
            build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::AggressiveGreedy);

        assert!(groups.len() >= 2);
        assert!(groups[0].len() >= 2);
        assert!(groups[1].len() >= 2);
    }

    #[test]
    fn hot_bucket_hint_is_stable_across_equivalent_access_domain_orderings() {
        let write_first = tx(500, vec![o(2)], vec![o(9), o(1)]);
        let reordered = tx(501, vec![o(9)], vec![o(2), o(1)]);

        assert_eq!(
            hot_bucket_hint(&write_first, 8),
            hot_bucket_hint(&reordered, 8)
        );
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
    fn hot_bucket_interleave_keeps_first_sparse_seed_when_bucket_fanout_is_input_clamped() {
        let _env = env_lock();

        let mut txs = vec![
            tx(441, vec![], vec![o(1)]),  // first hot hint bucket 1 (also sparse)
            tx(442, vec![], vec![o(0)]),  // dominant bucket 0 depth 3 after len-clamp to 5 buckets
            tx(443, vec![], vec![o(5)]),  // dominant bucket 0 depth 3
            tx(444, vec![], vec![o(10)]), // dominant bucket 0 depth 3
            tx(445, vec![], vec![o(2)]),  // equally sparse bucket 2 depth 1
        ];

        reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
        // Input-size clamping (`min(TRNM_HOT_BUCKETS, txs.len())`) should preserve
        // the same sparse-seed anti-starvation contract: if the first hot hint is
        // already one of the sparsest buckets, keep it as the lane seed instead of
        // drifting after the effective bucket fanout shrinks with the batch size.
        assert_eq!(txs.first().map(|t| t.id), Some(441));
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
    fn hot_bucket_interleave_short_circuits_single_bucket_hotspot_under_clamped_fanout() {
        let _env = env_lock();
        let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", "4");

        let mut txs = vec![
            tx(65, vec![], vec![o(4)]),
            tx(66, vec![], vec![o(8)]),
            tx(67, vec![], vec![o(12)]),
            tx(68, vec![], vec![o(16)]),
        ];

        reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
        // When ops clamps fanout below the default, a batch that still collapses
        // into one effective bucket should remain in ingress order rather than
        // paying round-robin overhead for a degenerate lane split.
        assert_eq!(
            txs.iter().map(|t| t.id).collect::<Vec<_>>(),
            vec![65, 66, 67, 68]
        );
    }

    #[test]
    fn hot_bucket_interleave_ignores_empty_access_noise_when_only_one_real_lane_exists() {
        let mut txs = vec![
            tx(81, vec![], vec![o(8)]),
            tx(82, vec![], vec![]),
            tx(83, vec![], vec![o(16)]),
            tx(84, vec![], vec![]),
        ];

        reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
        // Empty-access ingress should not fabricate a second hot bucket. When all
        // signaled traffic still lands in one real lane, keep stable input order
        // and avoid round-robin churn from synthetic bucket-0 noise.
        assert_eq!(
            txs.iter().map(|t| t.id).collect::<Vec<_>>(),
            vec![81, 82, 83, 84]
        );
    }

    #[test]
    #[should_panic(
        expected = "mixed access domain contains the same object id with multiple versions"
    )]
    fn hot_bucket_interleave_rejects_cross_domain_version_skew_before_micro_batch_short_circuit() {
        let mut txs = vec![
            tx(
                1,
                vec![ObjectRef { id: 7, version: 2 }],
                vec![ObjectRef { id: 7, version: 1 }],
            ),
            tx(2, vec![], vec![o(9)]),
            tx(3, vec![o(10)], vec![]),
        ];

        reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
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
    fn hot_bucket_hint_uses_first_read_key_as_secondary_mixed_domain_signal() {
        let buckets_n = 97usize;
        let baseline = tx(1, vec![], vec![o(5)]);
        let mixed = tx(2, vec![o(7)], vec![o(5)]);

        let baseline_bucket = hot_bucket_hint(&baseline, buckets_n);
        let mixed_bucket = hot_bucket_hint(&mixed, buckets_n);

        // A single-write + read tx should hash over the mixed access domain rather
        // than ignoring the first read key and collapsing onto the write-only bucket.
        assert_ne!(baseline_bucket, mixed_bucket);
        assert_eq!(
            mixed_bucket,
            ((5u64 ^ 7u64.rotate_left(7)) % buckets_n as u64) as usize
        );
    }

    #[test]
    fn hot_bucket_hint_keeps_singleton_bucket_for_same_version_cross_domain_echoes() {
        let buckets_n = 97usize;
        let write_only = tx(1, vec![], vec![o(5)]);
        let echoed = tx(2, vec![o(5)], vec![o(5)]);

        // Same-version read/write echoes should stay on the singleton domain
        // bucket rather than manufacturing a synthetic two-key mix.
        assert_eq!(
            hot_bucket_hint(&write_only, buckets_n),
            hot_bucket_hint(&echoed, buckets_n)
        );
        assert_eq!(
            hot_bucket_hint(&echoed, buckets_n),
            (5u64 % buckets_n as u64) as usize
        );
    }

    #[test]
    fn hot_bucket_hint_skips_duplicate_primary_key_when_mixing_read_write_domain() {
        let buckets_n = 97usize;
        let duplicate_primary = tx(1, vec![o(5), o(7)], vec![o(5)]);
        let deduped_domain = tx(2, vec![o(7)], vec![o(5)]);

        // Repeated primary-key echoes across read/write sets should not collapse the
        // secondary signal back to zero; the first distinct access key should drive
        // the mixed-domain bucket hint.
        assert_eq!(
            hot_bucket_hint(&duplicate_primary, buckets_n),
            hot_bucket_hint(&deduped_domain, buckets_n)
        );
    }

    #[test]
    fn hot_bucket_hint_skips_duplicate_primary_echoes_before_using_read_domain_key() {
        let buckets_n = 97usize;
        let duplicate_echoes = tx(1, vec![o(5), o(7)], vec![o(5), o(5)]);
        let deduped_domain = tx(2, vec![o(7)], vec![o(5)]);

        // Duplicate primary echoes inside the write domain should not shadow the
        // first distinct read-domain key when deriving the mixed bucket hint.
        assert_eq!(
            hot_bucket_hint(&duplicate_echoes, buckets_n),
            hot_bucket_hint(&deduped_domain, buckets_n)
        );
    }

    #[test]
    fn hot_bucket_hint_is_stable_when_read_write_roles_flip_for_same_domain() {
        let buckets_n = 97usize;
        let write_then_read = tx(1, vec![o(7)], vec![o(5)]);
        let read_then_write = tx(2, vec![o(5)], vec![o(7)]);

        // Equivalent two-key access domains should land in the same bucket even
        // when the read/write roles flip between the keys.
        assert_eq!(
            hot_bucket_hint(&write_then_read, buckets_n),
            hot_bucket_hint(&read_then_write, buckets_n)
        );
    }

    #[test]
    fn hot_bucket_hint_uses_stable_secondary_key_across_permuted_three_key_domains() {
        let buckets_n = 97usize;
        let baseline = tx(1, vec![o(11), o(13)], vec![o(7)]);
        let permuted = tx(2, vec![o(13), o(11)], vec![o(7)]);

        // Equivalent three-key access domains should not drift buckets just because
        // the first distinct secondary key appeared in a different read-set order.
        assert_eq!(
            hot_bucket_hint(&baseline, buckets_n),
            hot_bucket_hint(&permuted, buckets_n)
        );
        assert_eq!(
            hot_bucket_hint(&baseline, buckets_n),
            ((7u64 ^ 11u64.rotate_left(7)) % buckets_n as u64) as usize
        );
    }

    #[test]
    fn hot_bucket_hint_keeps_stable_secondary_when_primary_echo_roles_flip_with_wide_domains() {
        let buckets_n = 97usize;
        let write_heavy = tx(1, vec![o(5), o(13), o(19)], vec![o(5), o(17), o(23)]);
        let read_heavy = tx(2, vec![o(5), o(17), o(23)], vec![o(5), o(13), o(19)]);

        // Equivalent mixed domains should stay on the same bucket even when the
        // smaller secondary keys migrate between read/write ownership.
        assert_eq!(
            hot_bucket_hint(&write_heavy, buckets_n),
            hot_bucket_hint(&read_heavy, buckets_n)
        );
        assert_eq!(
            hot_bucket_hint(&write_heavy, buckets_n),
            ((5u64 ^ 13u64.rotate_left(7)) % buckets_n as u64) as usize
        );
    }

    #[test]
    fn hot_bucket_keys_keep_global_two_key_mixed_domain_hint_when_read_domain_is_primary() {
        let tx = tx(3, vec![o(5), o(13), o(11), o(13)], vec![o(7), o(19), o(19)]);

        // Even when the canonical primary key comes from the read domain, keep the
        // mixed-domain hint anchored to the two smallest distinct access keys across
        // the whole tx. That preserves stable Avalanche-style lane classification
        // instead of drifting toward a larger read-local secondary.
        assert_eq!(hot_bucket_keys(&tx), (5, 7));
    }

    #[test]
    fn hot_bucket_keys_stay_stable_when_primary_echo_exists_in_both_domains() {
        let baseline = tx(1, vec![o(13), o(17)], vec![o(5), o(13)]);
        let permuted = tx(2, vec![o(17), o(5), o(17)], vec![o(13), o(5), o(13)]);

        // If the smallest key is echoed across read/write domains, preserve the same
        // two-key execution-domain hint instead of drifting toward a larger
        // lane-local secondary just because role-local ordering changed.
        assert_eq!(hot_bucket_keys(&baseline), (5, 13));
        assert_eq!(hot_bucket_keys(&baseline), hot_bucket_keys(&permuted));
    }

    #[test]
    fn hot_bucket_keys_keep_global_secondary_when_primary_echo_roles_flip() {
        let write_heavy = tx(1, vec![o(7), o(9)], vec![o(7), o(11)]);
        let read_heavy = tx(2, vec![o(7), o(11)], vec![o(7), o(9)]);

        // If the canonical primary key is echoed in both domains, lane selection
        // must anchor to the same global secondary key regardless of whether the
        // smaller non-primary key happens to live in reads or writes.
        assert_eq!(hot_bucket_keys(&write_heavy), (7, 9));
        assert_eq!(hot_bucket_keys(&write_heavy), hot_bucket_keys(&read_heavy));
    }

    #[test]
    fn hot_bucket_keys_preserve_write_priority_under_duplicate_heavy_primary_echo() {
        let baseline = tx(1, vec![o(8), o(8), o(9), o(10)], vec![o(8), o(8), o(40), o(50)]);
        let permuted = tx(
            2,
            vec![o(10), o(8), o(9), o(8), o(10)],
            vec![o(50), o(8), o(40), o(8), o(40)],
        );

        // Once the shared primary is fixed, duplicate-heavy permutations must keep
        // the same write-first secondary lane signal instead of drifting with local order.
        assert_eq!(hot_bucket_keys(&baseline), (8, 40));
        assert_eq!(hot_bucket_keys(&baseline), hot_bucket_keys(&permuted));
    }

    #[test]
    fn hot_bucket_keys_keep_write_first_secondary_stable_under_shared_primary_echo_noise() {
        let baseline = tx(
            1,
            vec![o(5), o(5), o(7), o(7), o(29)],
            vec![o(5), o(13), o(13), o(21)],
        );
        let permuted = tx(
            2,
            vec![o(29), o(7), o(5), o(7), o(5)],
            vec![o(21), o(5), o(13), o(13)],
        );

        // Avalanche-style lane isolation should stay on the same write-primary lane
        // when the canonical primary key is echoed across domains and read-side noise
        // is permuted independently. The smallest write-only secondary remains the
        // stable execution-lane hint.
        assert_eq!(hot_bucket_keys(&baseline), (5, 13));
        assert_eq!(hot_bucket_keys(&baseline), hot_bucket_keys(&permuted));
    }

    #[test]
    fn hot_bucket_keys_keep_global_secondary_when_primary_echo_role_flip_is_asymmetric() {
        let write_wide = tx(1, vec![o(5), o(7)], vec![o(5), o(13), o(21)]);
        let read_wide = tx(2, vec![o(5), o(13), o(21)], vec![o(5), o(7)]);

        // If one side contributes only a single distinct non-primary key while the
        // other side fans out wider, keep the mixed-domain lane hint anchored to the
        // same smallest global secondary across read/write role flips.
        assert_eq!(hot_bucket_keys(&write_wide), (5, 7));
        assert_eq!(hot_bucket_keys(&write_wide), hot_bucket_keys(&read_wide));
    }

    #[test]
    fn hot_bucket_keys_keep_smallest_secondary_when_shared_primary_echo_has_one_distinct_suffix_per_side() {
        let write_suffix = tx(1, vec![o(5), o(13)], vec![o(5), o(7)]);
        let read_suffix = tx(2, vec![o(5), o(7)], vec![o(5), o(13)]);

        // When the canonical primary key is echoed across both domains and each
        // side contributes exactly one distinct non-primary key, lane isolation
        // should anchor to the smallest global secondary instead of drifting with
        // the read/write role assignment.
        assert_eq!(hot_bucket_keys(&write_suffix), (5, 7));
        assert_eq!(hot_bucket_keys(&write_suffix), hot_bucket_keys(&read_suffix));
    }

    #[test]
    fn hot_bucket_keys_treat_object_zero_as_real_primary_domain_key() {
        let write_then_read = tx(1, vec![o(0), o(11)], vec![o(5)]);
        let read_then_write = tx(2, vec![o(5)], vec![o(0), o(11)]);

        // Object id 0 is a valid domain member, not an internal sentinel.
        // Equivalent mixed domains touching {0,5,11} should preserve the same
        // canonical two-key lane hint even when read/write roles flip.
        assert_eq!(hot_bucket_keys(&write_then_read), (0, 5));
        assert_eq!(hot_bucket_keys(&write_then_read), hot_bucket_keys(&read_then_write));
    }

    #[test]
    fn hot_bucket_keys_keep_zero_primary_echo_stable_when_single_suffix_flips_roles() {
        let write_suffix = tx(1, vec![o(0), o(13)], vec![o(0), o(7)]);
        let read_suffix = tx(2, vec![o(0), o(7)], vec![o(0), o(13)]);

        // When object id 0 is echoed across both domains and each side contributes
        // one distinct non-primary key, lane isolation should keep the smallest
        // global suffix instead of drifting with read/write ownership.
        assert_eq!(hot_bucket_keys(&write_suffix), (0, 7));
        assert_eq!(hot_bucket_keys(&write_suffix), hot_bucket_keys(&read_suffix));
    }

    #[test]
    fn hot_bucket_hint_treats_object_zero_as_real_secondary_domain_key() {
        let buckets_n = 97usize;
        let write_then_read = tx(1, vec![o(0)], vec![o(5)]);
        let read_then_write = tx(2, vec![o(5)], vec![o(0)]);

        // Object id 0 is a valid domain member, not an internal sentinel.
        // Equivalent mixed domains touching {0,5} should remain bucket-stable even
        // when the read/write roles flip.
        assert_eq!(
            hot_bucket_hint(&write_then_read, buckets_n),
            hot_bucket_hint(&read_then_write, buckets_n)
        );
        assert_eq!(
            hot_bucket_hint(&write_then_read, buckets_n),
            ((0u64 ^ 5u64.rotate_left(7)) % buckets_n as u64) as usize
        );
    }

    #[test]
    fn hot_bucket_hint_keeps_object_zero_primary_stable_across_asymmetric_role_flips() {
        let buckets_n = 97usize;
        let write_narrow = tx(1, vec![o(0), o(5)], vec![o(0), o(11), o(19)]);
        let read_narrow = tx(2, vec![o(0), o(11), o(19)], vec![o(0), o(5)]);

        // When object id 0 is the canonical primary domain key, lane selection must
        // still anchor to the smallest distinct global secondary key instead of
        // drifting toward a wider role-local suffix after read/write role flips.
        assert_eq!(hot_bucket_keys(&write_narrow), (0, 5));
        assert_eq!(hot_bucket_keys(&write_narrow), hot_bucket_keys(&read_narrow));
        assert_eq!(
            hot_bucket_hint(&write_narrow, buckets_n),
            hot_bucket_hint(&read_narrow, buckets_n)
        );
        assert_eq!(
            hot_bucket_hint(&write_narrow, buckets_n),
            ((0u64 ^ 5u64.rotate_left(7)) % buckets_n as u64) as usize
        );
    }

    #[test]
    fn hot_bucket_hint_keeps_high_bit_domains_stable_when_zero_primary_flips_roles() {
        let buckets_n = 64usize;
        let high_a = 1u64 << 40;
        let high_b = (1u64 << 40) + 17;
        let write_then_read = tx(1, vec![o(0), o(high_b)], vec![o(high_a)]);
        let read_then_write = tx(2, vec![o(high_a)], vec![o(0), o(high_b)]);

        // Equivalent mixed domains touching {0, high_a, high_b} must keep the same
        // canonical two-key hint even when object 0 flips between read/write sets.
        // This guards executor lane isolation against future bucket-key regressions
        // on wide object-id ranges while preserving the zero-is-real-key contract.
        assert_eq!(hot_bucket_keys(&write_then_read), (0, high_a));
        assert_eq!(
            hot_bucket_keys(&write_then_read),
            hot_bucket_keys(&read_then_write)
        );
        assert_eq!(
            hot_bucket_hint(&write_then_read, buckets_n),
            hot_bucket_hint(&read_then_write, buckets_n)
        );
        assert_eq!(
            hot_bucket_hint(&write_then_read, buckets_n),
            ((0u64 ^ high_a.rotate_left(7)) % buckets_n as u64) as usize
        );
    }

    #[test]
    fn hot_bucket_hint_power_of_two_fast_path_keeps_zero_primary_mixed_domains_lane_stable() {
        let buckets_n = 64usize;
        let high_a = 1u64 << 40;
        let high_b = (1u64 << 48) + 9;
        let write_narrow = tx(1, vec![o(0), o(high_b)], vec![o(0), o(high_a)]);
        let read_narrow = tx(2, vec![o(0), o(high_a)], vec![o(0), o(high_b)]);

        // Keep the zero-primary lane anchor stable on the power-of-two bucket fast
        // path as well: equivalent mixed domains that flip read/write ownership of
        // high-bit suffixes must stay on the same executor lane instead of drifting
        // after the bitmask reduction.
        assert_eq!(hot_bucket_keys(&write_narrow), (0, high_a));
        assert_eq!(hot_bucket_keys(&write_narrow), hot_bucket_keys(&read_narrow));
        assert_eq!(
            hot_bucket_hint(&write_narrow, buckets_n),
            hot_bucket_hint(&read_narrow, buckets_n)
        );
        assert_eq!(
            hot_bucket_hint(&write_narrow, buckets_n),
            ((0u64 ^ high_a.rotate_left(7)) & ((buckets_n as u64) - 1)) as usize
        );
    }

    #[test]
    fn hot_bucket_keys_keep_zero_primary_lane_stable_under_duplicate_heavy_role_flips() {
        let write_narrow = tx(1, vec![o(0), o(11), o(11), o(13)], vec![o(0), o(7), o(7)]);
        let read_narrow = tx(2, vec![o(0), o(7), o(7)], vec![o(0), o(11), o(11), o(13)]);

        // Even when duplicate-heavy mixed domains echo object 0 across both sides,
        // keep the canonical lane anchor on the smallest distinct global suffix so
        // executor lane isolation does not drift when read/write ownership flips.
        assert_eq!(hot_bucket_keys(&write_narrow), (0, 7));
        assert_eq!(hot_bucket_keys(&write_narrow), hot_bucket_keys(&read_narrow));
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
            let (key_a, key_b) = hot_bucket_keys(&t);
            let expected = ((key_a ^ key_b.rotate_left(7)) % buckets_n as u64) as usize;
            assert_eq!(hot_bucket_hint(&t, buckets_n), expected);
        }
    }

    #[test]
    fn hot_bucket_hint_non_power_of_two_path_preserves_high_bit_lane_mapping() {
        let high_a = 1u64 << 40;
        let high_b = (1u64 << 55) + 3;
        let t = tx(1, vec![o(high_a)], vec![o(high_b)]);
        let buckets_n = 97usize;

        // Keep modulo reduction in u64-space on the non-power-of-two path so
        // wide access-domain keys cannot truncate through usize casts and skew
        // mixed-domain execution lane selection on narrower targets.
        let expected = ((high_a ^ high_b.rotate_left(7)) % buckets_n as u64) as usize;
        assert_eq!(hot_bucket_keys(&t), (high_a, high_b));
        assert_eq!(hot_bucket_hint(&t, buckets_n), expected);
    }

    #[test]
    fn hot_bucket_hint_power_of_two_fast_path_preserves_high_bit_lane_mapping() {
        let high_a = 1u64 << 40;
        let high_b = (1u64 << 55) + 3;
        let t = tx(1, vec![o(high_a)], vec![o(high_b)]);
        let buckets_n = 64usize;

        // Keep the bitmask fast path in u64-space too so high-bit mixed-domain
        // keys preserve their executor-lane mapping under power-of-two fanout.
        let expected = ((high_a ^ high_b.rotate_left(7)) & ((buckets_n as u64) - 1)) as usize;
        assert_eq!(hot_bucket_keys(&t), (high_a, high_b));
        assert_eq!(hot_bucket_hint(&t, buckets_n), expected);
    }

    #[test]
    fn hot_bucket_keys_skip_duplicate_leading_refs_and_preserve_write_priority() {
        let t = tx(1, vec![o(77), o(88)], vec![o(42), o(42), o(99)]);
        assert_eq!(hot_bucket_keys(&t), (42, 99));

        let read_fallback = tx(2, vec![o(7), o(7), o(8)], vec![]);
        assert_eq!(hot_bucket_keys(&read_fallback), (7, 8));
    }

    #[test]
    fn hot_bucket_hint_zero_bucket_count_fails_closed_to_bucket_zero() {
        let t = tx(999, vec![], vec![o(42)]);
        assert_eq!(hot_bucket_hint(&t, 0), 0);
    }

    #[test]
    fn hot_bucket_hint_singleton_domain_matches_direct_bucket_mapping() {
        let write_only = tx(998, vec![], vec![o(42)]);
        let read_only = tx(997, vec![o(42)], vec![]);

        // One-key execution domains should hash directly to that object key without
        // needing the broader two-key sort/dedup path. This keeps simple transfer-
        // like lanes aligned across read-only and write-only singleton footprints.
        assert_eq!(hot_bucket_hint(&write_only, 97), (42u64 % 97) as usize);
        assert_eq!(hot_bucket_hint(&read_only, 97), (42u64 % 97) as usize);
        assert_eq!(hot_bucket_hint(&write_only, 64), (42u64 & 63u64) as usize);
        assert_eq!(hot_bucket_hint(&read_only, 64), (42u64 & 63u64) as usize);
    }

    #[test]
    fn hot_bucket_hint_single_bucket_count_fails_closed_to_bucket_zero() {
        let t = tx(999, vec![o(7)], vec![o(42)]);
        assert_eq!(hot_bucket_hint(&t, 1), 0);
    }

    #[test]
    fn hot_bucket_hint_is_stable_for_duplicate_heavy_equivalent_read_only_domains() {
        let buckets_n = 97usize;
        let duplicate_heavy = tx(1, vec![o(11), o(5), o(11), o(13), o(13)], vec![]);
        let canonical = tx(2, vec![o(5), o(11), o(13)], vec![]);

        // Read-only duplicate-heavy domains should collapse to the same two
        // smallest distinct access keys as their canonical equivalent so lane
        // hints stay stable under telemetry/order noise.
        assert_eq!(
            hot_bucket_hint(&duplicate_heavy, buckets_n),
            hot_bucket_hint(&canonical, buckets_n)
        );
        assert_eq!(
            hot_bucket_hint(&duplicate_heavy, buckets_n),
            ((5u64 ^ 11u64.rotate_left(7)) % buckets_n as u64) as usize
        );
    }

    #[test]
    fn hot_bucket_hint_tracks_two_smallest_distinct_keys_when_new_min_arrives_last() {
        let t = tx(1, vec![o(3)], vec![o(5), o(4)]);
        let buckets_n = 8usize;
        let expected = ((3u64 ^ 4u64.rotate_left(7)) % buckets_n as u64) as usize;

        assert_eq!(hot_bucket_hint(&t, buckets_n), expected);
    }

    #[test]
    fn hot_bucket_hint_dedups_same_version_cross_domain_echoes_before_mixing() {
        let buckets_n = 97usize;
        let duplicate_echoes = tx(1, vec![o(7), o(7)], vec![o(5), o(5), o(7)]);
        let deduped_domain = tx(2, vec![o(7)], vec![o(5)]);

        // Same-version read/write echoes for the same object id are valid access
        // domains and should hash identically to their deduplicated equivalent.
        assert_eq!(
            hot_bucket_hint(&duplicate_echoes, buckets_n),
            hot_bucket_hint(&deduped_domain, buckets_n)
        );
    }

    #[test]
    fn hot_bucket_hint_keeps_asymmetric_primary_echo_domains_on_same_lane() {
        let buckets_n = 97usize;
        let write_wide = tx(1, vec![o(5), o(7)], vec![o(5), o(13), o(21)]);
        let read_wide = tx(2, vec![o(5), o(13), o(21)], vec![o(5), o(7)]);
        let expected = ((5u64 ^ 7u64.rotate_left(7)) % buckets_n as u64) as usize;

        // When the primary object key is echoed across both domains and only one
        // side contributes a single non-primary suffix, keep the hot-lane bucket
        // anchored to the same smallest global secondary even if read/write roles
        // flip on the wider suffix set.
        assert_eq!(hot_bucket_hint(&write_wide, buckets_n), expected);
        assert_eq!(
            hot_bucket_hint(&write_wide, buckets_n),
            hot_bucket_hint(&read_wide, buckets_n)
        );
    }

    #[test]
    fn hot_bucket_hint_is_stable_for_duplicate_heavy_equivalent_mixed_domains() {
        let buckets_n = 97usize;
        let duplicate_heavy = tx(
            3,
            vec![o(11), o(5), o(11), o(13), o(13)],
            vec![o(7), o(7), o(5), o(13)],
        );
        let canonical = tx(4, vec![o(5), o(11), o(13)], vec![o(7)]);

        // Duplicate-heavy mixed domains should collapse to the same two-smallest
        // distinct access keys as their canonical equivalent.
        assert_eq!(
            hot_bucket_hint(&duplicate_heavy, buckets_n),
            hot_bucket_hint(&canonical, buckets_n)
        );
        assert_eq!(
            hot_bucket_hint(&duplicate_heavy, buckets_n),
            ((5u64 ^ 7u64.rotate_left(7)) % buckets_n as u64) as usize
        );
    }

    #[test]
    #[should_panic(
        expected = "mixed access domain contains the same object id with multiple versions"
    )]
    fn hot_bucket_hint_rejects_cross_domain_version_skew_for_same_object_id() {
        let t = tx(
            1,
            vec![ObjectRef { id: 7, version: 2 }],
            vec![ObjectRef { id: 7, version: 1 }],
        );

        let _ = hot_bucket_hint(&t, 8);
    }

    #[test]
    fn hot_object_share_stays_stable_for_duplicate_heavy_equivalent_mixed_domains() {
        let baseline = vec![
            tx(
                1,
                vec![o(2), o(41), o(2), o(41), o(99)],
                vec![o(19), o(13), o(19), o(13), o(13)],
            ),
            tx(
                2,
                vec![o(2), o(41), o(2), o(41), o(99)],
                vec![o(23), o(13), o(23), o(13), o(13)],
            ),
        ];
        let echoed = vec![
            tx(
                3,
                vec![o(41), o(13), o(2), o(19), o(99), o(13)],
                vec![o(19), o(13), o(19), o(13)],
            ),
            tx(
                4,
                vec![o(41), o(13), o(2), o(23), o(99), o(13)],
                vec![o(23), o(13), o(23), o(13)],
            ),
        ];

        // Equivalent duplicate-heavy mixed execution domains should contribute the
        // same distinct access-domain cardinality regardless of echo order. If
        // this drifts, hotspot telemetry can fragment one execution lane into
        // different shares purely because ingress repeated the same domain keys.
        assert_eq!(hot_object_share(&baseline), hot_object_share(&echoed));
        assert_eq!(hot_object_share(&baseline), 0.2);
    }

    #[test]
    fn access_map_capacity_hint_sizes_from_unique_access_domain_keys() {
        let txs = vec![tx(
            1,
            (0..40u64)
                .flat_map(|i| [o(1_000 + i), o(1_000 + i)])
                .collect(),
            (0..40u64)
                .flat_map(|i| [o(2_000 + i), o(2_000 + i), o(1_000 + i)])
                .collect(),
        )];

        // Capacity sizing should track the tx's distinct object-domain footprint,
        // not raw duplicate/echo volume. Otherwise mixed read/write echoes can
        // inflate scheduler map reservations and blur lane-isolation telemetry.
        assert_eq!(tx_access_domain_keys(&txs[0]).len(), 80);
        assert_eq!(access_map_capacity_hint(&txs), 107);
    }

    #[test]
    fn access_map_capacity_hint_keeps_minimum_floor_for_tiny_unique_domains() {
        let txs = vec![
            tx(1, vec![o(7), o(7)], vec![]),
            tx(2, vec![o(7)], vec![o(7)]),
            tx(3, vec![], vec![o(9), o(9)]),
        ];

        // Tiny duplicate-heavy batches should still keep the scheduler's minimum
        // map capacity floor so lane-local micro-batches don't oscillate between
        // undersized allocations and rehash churn.
        assert_eq!(tx_access_domain_keys(&txs[0]).len(), 1);
        assert_eq!(tx_access_domain_keys(&txs[1]).len(), 1);
        assert_eq!(tx_access_domain_keys(&txs[2]).len(), 1);
        assert_eq!(access_map_capacity_hint(&txs), 64);
    }

    #[test]
    #[should_panic(
        expected = "mixed access domain contains the same object id with multiple versions"
    )]
    fn access_map_capacity_hint_rejects_cross_domain_version_skew_for_same_object_id() {
        let txs = vec![tx(
            1,
            vec![ObjectRef { id: 7, version: 2 }],
            vec![ObjectRef { id: 7, version: 1 }],
        )];

        let _ = access_map_capacity_hint(&txs);
    }

    #[test]
    #[should_panic(
        expected = "mixed access domain contains the same object id with multiple versions"
    )]
    fn hot_object_share_rejects_cross_domain_version_skew_for_same_object_id() {
        let txs = vec![tx(
            1,
            vec![ObjectRef { id: 7, version: 2 }],
            vec![ObjectRef { id: 7, version: 1 }],
        )];

        let _ = hot_object_share(&txs);
    }

    #[test]
    #[should_panic(
        expected = "mixed access domain contains the same object id with multiple versions"
    )]
    fn build_parallel_groups_rejects_cross_domain_version_skew_for_same_object_id() {
        let txs = vec![tx(
            1,
            vec![ObjectRef { id: 7, version: 2 }],
            vec![ObjectRef { id: 7, version: 1 }],
        )];

        let _ = build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::Original);
    }

    #[test]
    fn reorder_only_grouping_strategies_keep_mixed_access_domain_skew_guardrails() {
        let strategies = [
            GroupingStrategy::FootprintDesc,
            GroupingStrategy::WriteFirst,
            GroupingStrategy::WriteLast,
        ];

        for strategy in strategies {
            let txs = vec![tx(
                1,
                vec![ObjectRef { id: 7, version: 2 }],
                vec![ObjectRef { id: 7, version: 1 }],
            )];

            let panic = std::panic::catch_unwind(|| {
                let _ = build_parallel_groups_profile_with_strategy(&txs, strategy);
            });

            let msg = panic
                .expect_err("reorder-only strategy must reject cross-domain version skew")
                .downcast::<String>()
                .map(|s| *s)
                .or_else(|payload| payload.downcast::<&'static str>().map(|s| s.to_string()))
                .expect("panic payload should be string-like");
            assert!(
                msg.contains(
                    "mixed access domain contains the same object id with multiple versions"
                ),
                "unexpected panic for {strategy:?}: {msg}"
            );
        }
    }

    #[test]
    fn auto_adaptive_hot_bucket_path_keeps_mixed_access_domain_skew_guardrails() {
        let _env = env_lock();
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "4");
        let _sample = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "4");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.20");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.0");

        let txs = vec![
            tx(1, vec![], vec![o(5)]),
            tx(2, vec![], vec![o(5)]),
            tx(
                3,
                vec![ObjectRef { id: 5, version: 2 }],
                vec![ObjectRef { id: 5, version: 1 }],
            ),
            tx(4, vec![], vec![o(5)]),
        ];

        let panic = std::panic::catch_unwind(|| {
            let _ =
                build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::AutoAdaptive);
        });

        let msg = panic
            .expect_err("auto-adaptive hot-bucket path must reject cross-domain version skew")
            .downcast::<String>()
            .map(|s| *s)
            .or_else(|payload| payload.downcast::<&'static str>().map(|s| s.to_string()))
            .expect("panic payload should be string-like");
        assert!(
            msg.contains("mixed access domain contains the same object id with multiple versions"),
            "unexpected panic: {msg}"
        );
    }

    #[test]
    fn auto_adaptive_mixed_domains_do_not_collapse_distinct_secondary_lane_hints() {
        let _env = env_lock();
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "4");
        let _sample = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "4");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.20");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.0");

        let txs = vec![
            tx(1, vec![o(7)], vec![o(5)]),
            tx(2, vec![o(11)], vec![o(5)]),
            tx(3, vec![o(7)], vec![o(5)]),
            tx(4, vec![o(11)], vec![o(5)]),
        ];

        let decision = auto_adaptive_decision(&txs);

        assert!(
            !decision.use_hot_bucket,
            "distinct mixed execution domains should not collapse onto one hotspot hint"
        );
    }

    #[test]
    fn auto_adaptive_treats_object_zero_as_real_singleton_hotspot_key() {
        let _env = env_lock();
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
        let _sample = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "64");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.20");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.0");

        let txs: Vec<Tx> = (0..64u64)
            .map(|id| tx(id, vec![], vec![o(0)]))
            .collect();

        let d = auto_adaptive_decision(&txs);
        assert_eq!(d.sample_len, 64);
        assert!(
            d.use_hot_bucket,
            "object id 0 is a real execution-domain key and should trigger hotspot detection"
        );
        assert_eq!(d.reason, "hotspot_detected");
        assert!((d.hot_key_share - 1.0).abs() < f64::EPSILON);
        assert!((d.streak_ratio - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn aggressive_round_robin_seed_rotates_initial_probe_start() {
        let _env = env_lock();
        let _deep = EnvGuard::set("TRNM_AGGR_DEEP_SCAN", "1");
        let _rr = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", "1");
        let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "1");
        let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", "1");

        let txs = vec![
            tx(1, vec![], vec![o(7)]),    // group 0
            tx(3, vec![], vec![o(7)]),    // forced to group 1
            tx(10, vec![o(101)], vec![]), // first free candidate should honor seed offset
        ];

        let (groups, _) =
            build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::AggressiveGreedy);

        assert!(groups.len() >= 2);
        assert!(groups[1].iter().any(|t| t.id == 10));
    }

    #[test]
    fn aggressive_respects_skip_empty_stage_checks_toggle() {
        let _env = env_lock();
        let _deep = EnvGuard::set("TRNM_AGGR_DEEP_SCAN", "1");
        let _rr = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", "0");
        let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "2");
        let _skip_empty = EnvGuard::set("TRNM_AGGR_SKIP_EMPTY_STAGE_CHECKS", "0");

        let txs = vec![
            tx(1, vec![], vec![o(7)]), // group 0
            tx(3, vec![], vec![o(7)]), // forced to group 1
            tx(10, vec![], vec![]),    // empty access set, scans existing groups first
        ];

        let (_groups, profile) =
            build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::AggressiveGreedy);

        assert!(
            profile.stage_ww_checks > 0,
            "disable-skip toggle must keep ww stage checks observable"
        );
        assert!(
            profile.stage_wr_checks > 0,
            "disable-skip toggle must keep wr stage checks observable"
        );
        assert!(
            profile.stage_rw_checks > 0,
            "disable-skip toggle must keep rw stage checks observable"
        );
    }

    #[test]
    fn aggressive_skip_empty_stage_checks_keeps_conflict_check_metric_at_zero_for_empty_access() {
        let _env = env_lock();
        let _deep = EnvGuard::set("TRNM_AGGR_DEEP_SCAN", "1");
        let _rr = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", "0");
        let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "2");
        let _skip_empty = EnvGuard::set("TRNM_AGGR_SKIP_EMPTY_STAGE_CHECKS", "1");

        let txs = vec![
            tx(1, vec![], vec![o(7)]), // group 0
            tx(3, vec![], vec![o(7)]), // forced to group 1
            tx(10, vec![], vec![]),    // empty access set, should not execute stage probes
        ];

        let (_groups, profile) =
            build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::AggressiveGreedy);

        assert_eq!(profile.stage_ww_checks, 0);
        assert_eq!(profile.stage_wr_checks, 0);
        assert_eq!(profile.stage_rw_checks, 0);
        assert_eq!(profile.conflict_checks, 0);
        assert_eq!(profile.conflict_hits, 0);
    }

    #[test]
    fn aggressive_skip_empty_stage_checks_avoids_candidate_group_scans_for_empty_access() {
        let _env = env_lock();
        let _deep = EnvGuard::set("TRNM_AGGR_DEEP_SCAN", "1");
        let _rr = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", "1");
        let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", "1");
        let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "2");
        let _skip_empty = EnvGuard::set("TRNM_AGGR_SKIP_EMPTY_STAGE_CHECKS", "1");

        let txs = vec![
            tx(1, vec![], vec![o(7)]), // group 0
            tx(3, vec![], vec![o(7)]), // forced to group 1
            tx(10, vec![], vec![]),    // empty access set should not pay scan cost
        ];

        let (groups, profile) =
            build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::AggressiveGreedy);

        assert_eq!(groups.len(), 2);
        assert_eq!(
            groups[0].iter().map(|tx| tx.id).collect::<Vec<_>>(),
            vec![1, 10]
        );
        assert_eq!(
            groups[1].iter().map(|tx| tx.id).collect::<Vec<_>>(),
            vec![3]
        );
        assert_eq!(profile.candidate_groups_scanned, 0);
        assert_eq!(profile.stage_ww_checks, 0);
        assert_eq!(profile.stage_wr_checks, 0);
        assert_eq!(profile.stage_rw_checks, 0);
        assert_eq!(profile.conflict_checks, 0);
        assert_eq!(profile.conflict_hits, 0);
    }

    #[test]
    fn aggressive_scan_window_caps_candidate_probe_cost() {
        let _env = env_lock();
        let _deep = EnvGuard::set("TRNM_AGGR_DEEP_SCAN", "1");
        let _rr = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", "1");
        let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "1");

        // Force many independent txs to create an expanding candidate span.
        // With scan window=1, each tx can probe at most one candidate group,
        // bounding probe work to O(n) and preventing deep-scan blowups.
        let mut txs = Vec::new();
        txs.push(tx(1, vec![], vec![o(7)]));
        txs.push(tx(2, vec![], vec![o(7)]));
        for i in 0..32u64 {
            txs.push(tx(100 + i, vec![o(10_000 + i)], vec![]));
        }

        let (_groups, profile) =
            build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::AggressiveGreedy);

        assert!(
            profile.candidate_groups_scanned <= txs.len().saturating_sub(1),
            "scan window must cap candidate scans to ~1 probe per tx"
        );
    }

    #[test]
    fn aggressive_scan_window_is_clamped_to_prevent_misconfigured_probe_blowups() {
        let _env = env_lock();
        let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "999999");

        assert_eq!(aggr_scan_window(), 4096);
    }

    #[test]
    fn aggressive_scan_window_parses_trimmed_numeric_env_values() {
        let _env = env_lock();
        let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", " 128 ");

        assert_eq!(aggr_scan_window(), 128);
    }

    #[test]
    fn aggressive_scan_window_ignores_zero_and_separator_only_values() {
        let _env = env_lock();

        let _zero = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "0");
        assert_eq!(aggr_scan_window(), 0);
        drop(_zero);

        let _underscores = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "__,,__");
        assert_eq!(aggr_scan_window(), 0);
    }

    #[test]
    fn aggressive_round_robin_seed_parses_trimmed_numeric_env_values() {
        let _env = env_lock();
        let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", " 7 ");

        assert_eq!(aggr_scan_round_robin_seed(), 7);
    }

    #[test]
    fn integer_env_parsers_accept_underscored_numeric_values() {
        let _env = env_lock();
        let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "1_024");
        let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", "9_001");
        let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", "3_2");

        assert_eq!(aggr_scan_window(), 1024);
        assert_eq!(aggr_scan_round_robin_seed(), 9001);
        assert_eq!(hot_bucket_count(), 32);
    }

    #[test]
    fn aggressive_scan_window_accepts_comma_grouped_values() {
        let _env = env_lock();
        let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "1,024");

        assert_eq!(aggr_scan_window(), 1024);
    }

    #[test]
    fn aggressive_scan_window_rejects_ambiguous_comma_decimal_values() {
        let _env = env_lock();
        let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "1,5");

        assert_eq!(aggr_scan_window(), 0);
    }

    #[test]
    fn aggressive_round_robin_seed_rejects_ambiguous_comma_decimal_values() {
        let _env = env_lock();
        let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", "1,5");

        assert_eq!(aggr_scan_round_robin_seed(), 0);
    }

    #[test]
    fn integer_env_parsers_accept_plus_prefixed_grouped_values() {
        let _env = env_lock();
        let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", " '+1_536' ");
        let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", " '+1_024' ");
        let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", " '+3_2' ");

        assert_eq!(aggr_scan_window(), 1536);
        assert_eq!(aggr_scan_round_robin_seed(), 1024);
        assert_eq!(hot_bucket_count(), 32);
    }

    #[test]
    fn aggressive_integer_env_parsers_accept_quoted_plus_prefixed_comma_grouped_values() {
        let _env = env_lock();
        let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", " \"+1,024\" ");
        let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", " '+9,001' ");
        let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", " \"+1,6\" ");

        assert_eq!(aggr_scan_window(), 1024);
        assert_eq!(aggr_scan_round_robin_seed(), 9001);
        assert_eq!(hot_bucket_count(), 16);
    }

    #[test]
    fn aggressive_unsigned_env_knobs_fail_closed_on_negative_values() {
        let _env = env_lock();
        let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "-128");
        let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", "'-7'");
        let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", "-32");

        assert_eq!(aggr_scan_window(), 0);
        assert_eq!(aggr_scan_round_robin_seed(), 0);
        assert_eq!(hot_bucket_count(), 8);
    }

    #[test]
    fn aggressive_round_robin_toggle_parser_handles_trimmed_false_and_true_tokens() {
        let _env = env_lock();

        let _off = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", " OFF ");
        assert!(!aggr_scan_round_robin_enabled());
        drop(_off);

        let _yes = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", " yes ");
        assert!(aggr_scan_round_robin_enabled());
    }

    #[test]
    fn aggressive_round_robin_toggle_parser_accepts_quoted_tokens() {
        let _env = env_lock();

        let _off = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", " \"off\" ");
        assert!(!aggr_scan_round_robin_enabled());
        drop(_off);

        let _on = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", " \"on\" ");
        assert!(aggr_scan_round_robin_enabled());
    }

    #[test]
    fn aggressive_round_robin_toggle_parser_accepts_single_quoted_tokens() {
        let _env = env_lock();

        let _off = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", " 'off' ");
        assert!(!aggr_scan_round_robin_enabled());
        drop(_off);

        let _on = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", " 'on' ");
        assert!(aggr_scan_round_robin_enabled());
    }

    #[test]
    fn aggressive_toggle_parsers_accept_quoted_tokens_for_skip_empty_and_deep_scan() {
        let _env = env_lock();

        let _skip_off = EnvGuard::set("TRNM_AGGR_SKIP_EMPTY_STAGE_CHECKS", " \"off\" ");
        assert!(!aggr_skip_empty_stage_checks());
        drop(_skip_off);

        let _skip_on = EnvGuard::set("TRNM_AGGR_SKIP_EMPTY_STAGE_CHECKS", " 'on' ");
        assert!(aggr_skip_empty_stage_checks());
        drop(_skip_on);

        let _deep_off = EnvGuard::set("TRNM_AGGR_DEEP_SCAN", " 'off' ");
        assert!(!aggr_deep_scan_enabled());
        drop(_deep_off);

        let _deep_on = EnvGuard::set("TRNM_AGGR_DEEP_SCAN", " \"on\" ");
        assert!(aggr_deep_scan_enabled());
    }

    #[test]
    fn aggressive_toggle_parsers_accept_quoted_no_tokens() {
        let _env = env_lock();

        let _rr_no = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", " \"no\" ");
        assert!(!aggr_scan_round_robin_enabled());
        drop(_rr_no);

        let _deep_no = EnvGuard::set("TRNM_AGGR_DEEP_SCAN", " 'no' ");
        assert!(!aggr_deep_scan_enabled());
        drop(_deep_no);

        let _skip_no = EnvGuard::set("TRNM_AGGR_SKIP_EMPTY_STAGE_CHECKS", " \"no\" ");
        assert!(!aggr_skip_empty_stage_checks());
    }

    #[test]
    fn aggressive_toggle_parsers_fall_back_to_defaults_on_empty_or_separator_only_values() {
        let _env = env_lock();

        let _rr_empty = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", "  ''  ");
        assert!(aggr_scan_round_robin_enabled());
        drop(_rr_empty);

        let _rr_separators = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", " __,,__ ");
        assert!(aggr_scan_round_robin_enabled());
        drop(_rr_separators);

        let _deep_empty = EnvGuard::set("TRNM_AGGR_DEEP_SCAN", "  \"\"  ");
        assert!(!aggr_deep_scan_enabled());
        drop(_deep_empty);

        let _skip_separators = EnvGuard::set("TRNM_AGGR_SKIP_EMPTY_STAGE_CHECKS", " _,,_ ");
        assert!(aggr_skip_empty_stage_checks());
    }

    #[test]
    fn auto_threshold_env_parsers_accept_trimmed_numeric_values() {
        let _env = env_lock();
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", " 0.35 ");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", " 0.12 ");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", " 0.018 ");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", " 0.03 ");

        assert!((auto_hot_streak_threshold() - 0.35).abs() < f64::EPSILON);
        assert!((auto_reorder_min_margin() - 0.12).abs() < f64::EPSILON);
        assert!((auto_reorder_min_hot_key_share() - 0.018).abs() < f64::EPSILON);
        assert!((auto_min_expected_gain_score() - 0.03).abs() < f64::EPSILON);
    }

    #[test]
    fn auto_threshold_env_parsers_accept_grouped_numeric_values() {
        let _env = env_lock();
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.2_5");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0,1");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.0_125");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0,0_5");

        assert!((auto_hot_streak_threshold() - 0.25).abs() < f64::EPSILON);
        assert!((auto_reorder_min_margin() - 0.1).abs() < f64::EPSILON);
        assert!((auto_reorder_min_hot_key_share() - 0.0125).abs() < f64::EPSILON);
        assert!((auto_min_expected_gain_score() - 0.05).abs() < f64::EPSILON);
    }

    #[test]
    fn hot_bucket_count_parser_accepts_trimmed_numeric_values() {
        let _env = env_lock();
        let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", " 16 ");

        assert_eq!(hot_bucket_count(), 16);
    }

    #[test]
    fn hot_bucket_count_parser_accepts_grouped_numeric_values() {
        let _env = env_lock();
        let _underscored = EnvGuard::set("TRNM_HOT_BUCKETS", " 6_4 ");
        assert_eq!(hot_bucket_count(), 64);
        drop(_underscored);

        let _comma_grouped = EnvGuard::set("TRNM_HOT_BUCKETS", " 1,6 ");
        assert_eq!(hot_bucket_count(), 16);
    }

    #[test]
    fn hot_bucket_count_is_clamped_to_safe_bounds() {
        let _env = env_lock();

        let _low = EnvGuard::set("TRNM_HOT_BUCKETS", "0");
        assert_eq!(hot_bucket_count(), 4);
        drop(_low);

        let _positive_below_floor = EnvGuard::set("TRNM_HOT_BUCKETS", "1");
        assert_eq!(hot_bucket_count(), 4);
        drop(_positive_below_floor);

        let _high = EnvGuard::set("TRNM_HOT_BUCKETS", "999");
        assert_eq!(hot_bucket_count(), 64);
    }

    #[test]
    fn auto_adaptive_numeric_env_parser_accepts_quoted_values() {
        let _env = env_lock();

        let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "\"1_024\"");
        let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", "'9_001'");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "\"0.2_5\"");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "'0.1'");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "\"0.0_125\"");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "'0.05'");
        let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", "\"1,6\"");
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "'2_048'");
        let _sample_len = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "\"1_024\"");

        assert_eq!(aggr_scan_window(), 1024);
        assert_eq!(aggr_scan_round_robin_seed(), 9001);
        assert_eq!(auto_hot_streak_threshold(), 0.25);
        assert_eq!(auto_reorder_min_margin(), 0.1);
        assert_eq!(auto_reorder_min_hot_key_share(), 0.0125);
        assert_eq!(auto_min_expected_gain_score(), 0.05);
        assert_eq!(hot_bucket_count(), 16);
        assert_eq!(auto_adaptive_min_batch_len(), 2048);
        assert_eq!(auto_adaptive_sample_len(5000), 1024);
    }

    #[test]
    fn auto_adaptive_numeric_env_parser_accepts_plus_prefixed_values() {
        let _env = env_lock();

        let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", " +1_024 ");
        let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", " '+9_001' ");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", " +0.2_5 ");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", " '+0.1' ");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", " +0.0_125 ");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", " '+0.05' ");
        let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", " '+1,6' ");
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", " '+1_024' ");
        let _sample_len = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", " '+0' ");

        assert_eq!(aggr_scan_window(), 1024);
        assert_eq!(aggr_scan_round_robin_seed(), 9001);
        assert_eq!(auto_hot_streak_threshold(), 0.25);
        assert_eq!(auto_reorder_min_margin(), 0.1);
        assert_eq!(auto_reorder_min_hot_key_share(), 0.0125);
        assert_eq!(auto_min_expected_gain_score(), 0.05);
        assert_eq!(hot_bucket_count(), 16);
        assert_eq!(auto_adaptive_min_batch_len(), 1024);
        assert_eq!(auto_adaptive_sample_len(5000), 64);
    }

    #[test]
    fn grouped_integer_env_parsers_accept_quoted_comma_grouped_values() {
        let _env = env_lock();

        let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", " \"1,024\" ");
        let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", " '9,001' ");
        let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", " \"1,6\" ");
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", " '2,048' ");
        let _sample_len = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", " \"1,536\" ");

        assert_eq!(aggr_scan_window(), 1024);
        assert_eq!(aggr_scan_round_robin_seed(), 9001);
        assert_eq!(hot_bucket_count(), 16);
        assert_eq!(auto_adaptive_min_batch_len(), 2048);
        assert_eq!(auto_adaptive_sample_len(5000), 1536);
        assert_eq!(auto_adaptive_sample_len(1400), 1400);
    }

    #[test]
    fn auto_adaptive_numeric_env_parser_accepts_percent_suffix_for_ratio_knobs() {
        let _env = env_lock();

        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "25%");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", " 10% ");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "'1.25%' ");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", " \"5%\" ");

        assert_eq!(auto_hot_streak_threshold(), 0.25);
        assert_eq!(auto_reorder_min_margin(), 0.1);
        assert_eq!(auto_reorder_min_hot_key_share(), 0.0125);
        assert_eq!(auto_min_expected_gain_score(), 0.05);
    }

    #[test]
    fn auto_adaptive_numeric_env_parser_accepts_comma_decimal_percent_values() {
        let _env = env_lock();

        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "25,5%");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", " '10,5%' ");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "\"1,25%\"");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", " 0,5% ");

        assert_eq!(auto_hot_streak_threshold(), 0.255);
        assert_eq!(auto_reorder_min_margin(), 0.105);
        assert_eq!(auto_reorder_min_hot_key_share(), 0.0125);
        assert_eq!(auto_min_expected_gain_score(), 0.005);
    }

    #[test]
    fn auto_adaptive_numeric_env_parser_accepts_quoted_plus_prefixed_comma_decimal_percent_values()
    {
        let _env = env_lock();

        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", " '+25,5%' ");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", " \"+10,5%\" ");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", " '+1,25%' ");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", " \"+0,5%\" ");

        assert_eq!(auto_hot_streak_threshold(), 0.255);
        assert_eq!(auto_reorder_min_margin(), 0.105);
        assert_eq!(auto_reorder_min_hot_key_share(), 0.0125);
        assert_eq!(auto_min_expected_gain_score(), 0.005);
    }

    #[test]
    fn auto_adaptive_numeric_env_parser_accepts_grouped_comma_decimal_percent_values() {
        let _env = env_lock();

        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", " '+2_5,5%' ");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", " \"+1_0,5%\" ");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", " '+1,2_5%' ");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", " \"+0,5_0%\" ");

        assert_eq!(auto_hot_streak_threshold(), 0.255);
        assert_eq!(auto_reorder_min_margin(), 0.105);
        assert_eq!(auto_reorder_min_hot_key_share(), 0.0125);
        assert_eq!(auto_min_expected_gain_score(), 0.005);
    }

    #[test]
    fn auto_adaptive_numeric_env_parser_treats_zero_whole_comma_values_as_decimals() {
        let _env = env_lock();

        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0,250");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", " '+0,125' ");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "\"0,375\"");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", " '0,050' ");

        assert_eq!(auto_hot_streak_threshold(), 0.25);
        assert_eq!(auto_reorder_min_margin(), 0.125);
        assert_eq!(auto_reorder_min_hot_key_share(), 0.375);
        assert_eq!(auto_min_expected_gain_score(), 0.05);
    }

    #[test]
    fn auto_adaptive_numeric_env_parser_treats_all_zero_whole_comma_values_as_decimals() {
        let _env = env_lock();

        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "000,250");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", " '+000,125' ");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "\"000,375\"");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", " '000,050' ");

        assert_eq!(auto_hot_streak_threshold(), 0.25);
        assert_eq!(auto_reorder_min_margin(), 0.125);
        assert_eq!(auto_reorder_min_hot_key_share(), 0.375);
        assert_eq!(auto_min_expected_gain_score(), 0.05);
    }

    #[test]
    fn auto_adaptive_numeric_env_parser_treats_leading_comma_values_as_decimals() {
        let _env = env_lock();

        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", ",250");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", " '+,125' ");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "\",375\"");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", " '-,050' ");

        assert_eq!(auto_hot_streak_threshold(), 0.25);
        assert_eq!(auto_reorder_min_margin(), 0.125);
        assert_eq!(auto_reorder_min_hot_key_share(), 0.375);
        assert_eq!(auto_min_expected_gain_score(), 0.0);
    }

    #[test]
    fn auto_adaptive_numeric_env_parser_treats_plus_prefixed_leading_comma_values_as_decimals() {
        let _env = env_lock();

        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "'+,250'");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", " \"+,125\" ");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", " '+,375' ");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", " \"+,050\" ");

        assert_eq!(auto_hot_streak_threshold(), 0.25);
        assert_eq!(auto_reorder_min_margin(), 0.125);
        assert_eq!(auto_reorder_min_hot_key_share(), 0.375);
        assert_eq!(auto_min_expected_gain_score(), 0.05);
    }

    #[test]
    fn auto_adaptive_numeric_env_parser_treats_leading_comma_percent_values_as_decimals() {
        let _env = env_lock();

        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", ",25%");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", " '+,5%' ");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "\",75%\"");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", " '-,5%' ");

        assert_eq!(auto_hot_streak_threshold(), 0.0025);
        assert_eq!(auto_reorder_min_margin(), 0.005);
        assert_eq!(auto_reorder_min_hot_key_share(), 0.0075);
        assert_eq!(auto_min_expected_gain_score(), 0.0);
    }

    #[test]
    fn auto_adaptive_numeric_env_parser_falls_back_to_defaults_on_invalid_values() {
        let _env = env_lock();

        let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "not-a-number");
        let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", "seed??");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "NaN%");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "margin");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "share");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "gain");
        let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", "bucket-count");
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "batch??");

        assert_eq!(aggr_scan_window(), 0);
        assert_eq!(aggr_scan_round_robin_seed(), 0);
        assert_eq!(auto_hot_streak_threshold(), 0.22);
        assert_eq!(auto_reorder_min_margin(), 0.04);
        assert_eq!(auto_reorder_min_hot_key_share(), 0.0075);
        assert_eq!(auto_min_expected_gain_score(), 0.01);
        assert_eq!(hot_bucket_count(), 8);
        assert_eq!(auto_adaptive_min_batch_len(), 512);
    }

    #[test]
    fn auto_adaptive_numeric_env_parser_rejects_ambiguous_multi_comma_ratio_values() {
        let _env = env_lock();

        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0,2,5");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "'+0,1,0'");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "1,2,5%");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "\"0,0,5\"");

        assert_eq!(auto_hot_streak_threshold(), 0.22);
        assert_eq!(auto_reorder_min_margin(), 0.04);
        assert_eq!(auto_reorder_min_hot_key_share(), 0.0075);
        assert_eq!(auto_min_expected_gain_score(), 0.01);
    }

    #[test]
    fn auto_adaptive_min_batch_len_rejects_ambiguous_grouped_comma_values() {
        let _env = env_lock();

        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "'+5,1,2'");

        assert_eq!(auto_adaptive_min_batch_len(), 512);
    }

    #[test]
    fn auto_adaptive_sample_len_rejects_ambiguous_grouped_comma_values() {
        let _env = env_lock();

        let _sample_len = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "'+1,5,3,6'");

        assert_eq!(auto_adaptive_sample_len(5000), 2048);
        assert_eq!(auto_adaptive_sample_len(128), 128);
    }

    #[test]
    fn auto_adaptive_numeric_env_parser_ignores_empty_or_separator_only_values() {
        let _env = env_lock();

        let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "   ");
        let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", "__,,__");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", " '' ");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", " \"\" ");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", " _,_ ");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", " '__,,__' ");
        let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", " \"_,,\" ");
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", " '__,,__' ");

        assert_eq!(aggr_scan_window(), 0);
        assert_eq!(aggr_scan_round_robin_seed(), 0);
        assert_eq!(auto_hot_streak_threshold(), 0.22);
        assert_eq!(auto_reorder_min_margin(), 0.04);
        assert_eq!(auto_reorder_min_hot_key_share(), 0.0075);
        assert_eq!(auto_min_expected_gain_score(), 0.01);
        assert_eq!(hot_bucket_count(), 8);
        assert_eq!(auto_adaptive_min_batch_len(), 512);
    }

    #[test]
    fn auto_adaptive_ratio_knobs_are_clamped_to_safe_bounds() {
        let _env = env_lock();

        let _streak_low = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "-25%");
        let _margin_low = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "-0.5");
        let _share_low = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "-1");
        let _gain_low = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "-2%");

        assert_eq!(auto_hot_streak_threshold(), 0.0);
        assert_eq!(auto_reorder_min_margin(), 0.0);
        assert_eq!(auto_reorder_min_hot_key_share(), 0.0);
        assert_eq!(auto_min_expected_gain_score(), 0.0);

        drop(_streak_low);
        drop(_margin_low);
        drop(_share_low);
        drop(_gain_low);

        let _streak_high = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "250%");
        let _margin_high = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "5");
        let _share_high = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "125%");
        let _gain_high = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "3.5");

        assert_eq!(auto_hot_streak_threshold(), 1.0);
        assert_eq!(auto_reorder_min_margin(), 1.0);
        assert_eq!(auto_reorder_min_hot_key_share(), 1.0);
        assert_eq!(auto_min_expected_gain_score(), 1.0);
    }

    #[test]
    fn auto_adaptive_min_batch_len_is_clamped_to_safe_bounds() {
        let _env = env_lock();

        let _low = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "8");
        assert_eq!(auto_adaptive_min_batch_len(), 64);
        drop(_low);

        let _high = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "99999");
        assert_eq!(auto_adaptive_min_batch_len(), 4096);
    }

    #[test]
    fn auto_adaptive_sample_len_is_env_tunable_and_clamped() {
        let _env = env_lock();

        let _default = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "batch??");
        assert_eq!(auto_adaptive_sample_len(5000), 2048);
        drop(_default);

        let _ambiguous = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "1,5");
        assert_eq!(auto_adaptive_sample_len(5000), 2048);
        assert_eq!(auto_adaptive_sample_len(128), 128);
        drop(_ambiguous);

        let _zero = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "0");
        assert_eq!(auto_adaptive_sample_len(5000), 64);
        drop(_zero);

        let _low = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "8");
        assert_eq!(auto_adaptive_sample_len(5000), 64);
        drop(_low);

        let _high = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "99999");
        assert_eq!(auto_adaptive_sample_len(5000), 2048);
        drop(_high);

        let _trimmed = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", " '1_024' ");
        assert_eq!(auto_adaptive_sample_len(5000), 1024);
        assert_eq!(auto_adaptive_sample_len(256), 256);
        drop(_trimmed);

        let _comma_grouped = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", " '1,0_2_4' ");
        assert_eq!(auto_adaptive_sample_len(5000), 1024);
        assert_eq!(auto_adaptive_sample_len(768), 768);
        drop(_comma_grouped);

        let _plus_grouped = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", " '+1,5_3_6' ");
        assert_eq!(auto_adaptive_sample_len(5000), 1536);
        assert_eq!(auto_adaptive_sample_len(1400), 1400);
        drop(_plus_grouped);

        let _separator_only = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", " '__,,__' ");
        assert_eq!(auto_adaptive_sample_len(5000), 2048);
        assert_eq!(auto_adaptive_sample_len(128), 128);
        drop(_separator_only);

        let _plus = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", " '+1_536' ");
        assert_eq!(auto_adaptive_sample_len(5000), 1536);
        assert_eq!(auto_adaptive_sample_len(1024), 1024);
    }

    #[test]
    fn auto_adaptive_sample_len_preserves_zero_for_empty_batches_even_with_env_floor() {
        let _env = env_lock();
        let _sample = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "8");

        // The experimental sample-size floor must not manufacture probe work
        // for empty batches. Keep the helper fail-closed at zero so later
        // callers cannot accidentally treat an empty batch as sampled.
        assert_eq!(auto_adaptive_sample_len(0), 0);
    }

    #[test]
    fn auto_adaptive_unsigned_env_knobs_fail_closed_on_negative_values() {
        let _env = env_lock();

        let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", "-16");
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", " '-512' ");
        let _sample = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "-1_024");

        assert_eq!(hot_bucket_count(), 8);
        assert_eq!(auto_adaptive_min_batch_len(), 512);
        assert_eq!(auto_adaptive_sample_len(5000), 2048);
        assert_eq!(auto_adaptive_sample_len(128), 128);
    }

    #[test]
    fn auto_adaptive_small_batch_threshold_accepts_quoted_grouped_env_values() {
        let _env = env_lock();
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", " '6_4' ");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0%");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "20%");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0%");

        let mut txs = Vec::with_capacity(64);
        for i in 0..64u64 {
            txs.push(tx(i, vec![], vec![o(42)]));
        }

        let d = auto_adaptive_decision(&txs);
        assert_eq!(d.sample_len, 64);
        assert!(
            d.use_hot_bucket,
            "quoted/grouped env values should preserve small-batch hotspot detection"
        );
        assert_eq!(d.reason, "hotspot_detected");
    }

    #[test]
    fn auto_adaptive_small_batch_threshold_is_env_tunable() {
        let _env = env_lock();
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.0");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.2");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.0");

        let mut txs = Vec::with_capacity(64);
        for i in 0..64u64 {
            txs.push(tx(i, vec![], vec![o(42)]));
        }

        let d = auto_adaptive_decision(&txs);
        assert_eq!(d.sample_len, 64);
        assert!(
            d.use_hot_bucket,
            "env-tuned min batch should allow small-batch hotspot detection"
        );
        assert_eq!(d.reason, "hotspot_detected");
    }

    #[test]
    fn auto_adaptive_small_batch_threshold_accepts_comma_grouped_env_values() {
        let _env = env_lock();
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "1,024");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.0");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.0");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.0");

        // Experimental lanes tune adaptive entry thresholds via env knobs.
        // Comma-grouped numeric values should parse for min-batch gating so a
        // medium hotspot batch still stays fail-closed below the configured
        // threshold instead of switching strategies early.
        let mut txs = Vec::with_capacity(600);
        for i in 0..600u64 {
            txs.push(tx(i, vec![], vec![o(42)]));
        }

        let d = auto_adaptive_decision(&txs);
        assert_eq!(d.sample_len, txs.len());
        assert!(!d.use_hot_bucket);
        assert_eq!(d.reason, "small_batch");
        assert_eq!(d.streak_ratio, 0.0);
        assert_eq!(d.hot_key_share, 0.0);
        assert_eq!(d.expected_gain_score, 0.0);
    }

    #[test]
    fn auto_adaptive_threshold_boundaries_are_inclusive() {
        let _env = env_lock();
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
        let _sample = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "64");

        // Keep a precise boundary regression for the experimental adaptive lane:
        // when observed streak/share/gain land exactly on the configured
        // thresholds, the selector should stay inclusive (`>=`) instead of
        // fail-closing one notch below due to future comparator drift.
        let mut txs = Vec::with_capacity(64);
        for i in 0..16u64 {
            txs.push(tx(i, vec![], vec![o(7)]));
        }
        for i in 16..32u64 {
            txs.push(tx(i, vec![], vec![o(100 + i)]));
        }
        for i in 32..64u64 {
            txs.push(tx(i, vec![], vec![o(200 + i)]));
        }

        let _baseline_streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.0");
        let _baseline_margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _baseline_share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.0");
        let _baseline_gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.0");
        let baseline = auto_adaptive_decision(&txs);
        drop(_baseline_gain);
        drop(_baseline_share);
        drop(_baseline_margin);
        drop(_baseline_streak);

        let threshold = baseline.streak_ratio.to_string();
        let hot_key_share = baseline.hot_key_share.to_string();
        let gain = baseline.expected_gain_score.to_string();

        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", &threshold);
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", &hot_key_share);
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", &gain);

        let d = auto_adaptive_decision(&txs);
        assert_eq!(d.sample_len, 64);
        assert!(
            d.use_hot_bucket,
            "exact boundary match should still enable hot-bucket strategy"
        );
        assert_eq!(d.reason, "hotspot_detected");
        assert!(d.streak_ratio >= d.streak_threshold + d.min_margin);
        assert!(d.hot_key_share >= d.min_hot_key_share);
        assert!(d.expected_gain_score >= d.min_expected_gain_score);
    }

    #[test]
    fn auto_adaptive_default_min_batch_boundary_runs_hotspot_probe() {
        let _env = env_lock();
        let _sample = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "2048");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.20");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.05");

        // The default adaptive entry gate is 512 txs. Keep an exact-boundary
        // regression so future tuning does not accidentally treat this as a
        // small batch and skip the hotspot probe on the first eligible batch.
        let mut txs = Vec::with_capacity(512);
        for i in 0..256u64 {
            txs.push(tx(i, vec![], vec![o(10_000 + i)]));
        }
        for i in 0..256u64 {
            txs.push(tx(1_000 + i, vec![], vec![o(42)]));
        }

        let d = auto_adaptive_decision(&txs);
        assert_eq!(d.sample_len, txs.len());
        assert!(
            d.use_hot_bucket,
            "default min-batch boundary should still run adaptive hotspot detection"
        );
        assert_eq!(d.reason, "hotspot_detected");
    }

    #[test]
    fn auto_adaptive_empty_access_samples_break_hot_streak_continuity() {
        let _env = env_lock();
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
        let _sample = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "64");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.656");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.30");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.0");

        let mut txs = Vec::with_capacity(64);
        for i in 0..16u64 {
            txs.push(tx(i, vec![], vec![o(42)]));
        }
        for i in 16..32u64 {
            txs.push(tx(i, vec![], vec![]));
        }
        for i in 32..48u64 {
            txs.push(tx(i, vec![], vec![o(42)]));
        }
        for i in 48..64u64 {
            txs.push(tx(i, vec![], vec![o(10_000 + i)]));
        }

        let d = auto_adaptive_decision(&txs);
        assert_eq!(d.sample_len, 64);
        assert!(!d.use_hot_bucket);
        assert_eq!(d.reason, "below_streak_budget");
        assert!((d.hot_key_share - (32.0 / 48.0)).abs() < 1e-12);
        assert!((d.streak_ratio - (30.0 / 46.0)).abs() < 1e-12);
        assert!(
            d.streak_ratio < d.streak_threshold + d.min_margin,
            "empty-access samples must break streak continuity instead of stitching hotspot runs together"
        );
    }

    #[test]
    fn auto_adaptive_sub_min_batch_hotspots_stay_fail_closed() {
        let _env = env_lock();
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
        let _sample = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "2048");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.0");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.0");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.0");

        // Keep the just-below-threshold boundary fail-closed even when every
        // adaptive hotspot knob is permissive. Experimental sampling/window
        // tuning must not override the minimum batch gate.
        let mut txs = Vec::with_capacity(63);
        for i in 0..63u64 {
            txs.push(tx(i, vec![], vec![o(42)]));
        }

        let d = auto_adaptive_decision(&txs);
        assert_eq!(d.sample_len, 63);
        assert_eq!(d.reason, "small_batch");
        assert!(!d.use_hot_bucket);
        assert_eq!(d.hot_key_share, 0.0);
        assert_eq!(d.streak_ratio, 0.0);
        assert_eq!(d.expected_gain_score, 0.0);
    }

    #[test]
    fn auto_adaptive_sampling_detects_late_batch_hotspots() {
        let _env = env_lock();
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.10");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.01");

        let mut txs = Vec::with_capacity(4096);
        for i in 0..2048u64 {
            txs.push(tx(i, vec![], vec![o(10_000 + i)]));
        }
        for i in 0..2048u64 {
            txs.push(tx(3_000 + i, vec![], vec![o(42)]));
        }

        let d = auto_adaptive_decision(&txs);
        assert!(
            d.use_hot_bucket,
            "late hotspot should be visible in adaptive sample"
        );
        assert_eq!(d.reason, "hotspot_detected");
    }

    #[test]
    fn auto_adaptive_min_clamped_sample_len_still_detects_tail_hotspots() {
        let _env = env_lock();
        let _sample = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "8");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.10");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.01");

        // Experimental sample tuning clamps to a 64-item floor. Keep a tail-hotspot
        // regression here so overly small requested windows do not lose batch-tail
        // visibility while adaptive experimentation changes probe sizing.
        let mut txs = Vec::with_capacity(5000);
        for i in 0..2500u64 {
            txs.push(tx(i, vec![], vec![o(10_000 + i)]));
        }
        for i in 0..2500u64 {
            txs.push(tx(4_000 + i, vec![], vec![o(42)]));
        }

        let d = auto_adaptive_decision(&txs);
        assert_eq!(d.sample_len, 64);
        assert!(
            d.use_hot_bucket,
            "clamped minimum sample should still preserve tail hotspot visibility"
        );
        assert_eq!(d.reason, "hotspot_detected");
    }

    #[test]
    fn auto_adaptive_min_clamped_sample_len_still_detects_tail_hotspots_for_read_only_batches() {
        let _env = env_lock();
        let _sample = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "8");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.10");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.01");

        // Mirror the clamped-minimum tail-hotspot regression for read-only
        // batches. Experimental sample tuning still clamps to a 64-item floor,
        // and the detector must preserve late-batch visibility when it falls
        // back from write_set to read_set keys.
        let mut txs = Vec::with_capacity(5000);
        for i in 0..2500u64 {
            txs.push(tx(i, vec![o(10_000 + i)], vec![]));
        }
        for i in 0..2500u64 {
            txs.push(tx(4_000 + i, vec![o(42)], vec![]));
        }

        let d = auto_adaptive_decision(&txs);
        assert_eq!(d.sample_len, 64);
        assert!(
            d.use_hot_bucket,
            "clamped minimum sample should still preserve read-only tail hotspot visibility"
        );
        assert_eq!(d.reason, "hotspot_detected");
    }

    #[test]
    fn auto_adaptive_direct_scan_detects_tail_hotspots_in_medium_batches() {
        let _env = env_lock();
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.20");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.05");

        // Medium batches stay on the direct-scan fast path (sample_len == batch_len).
        // Keep a late-batch hotspot regression here so the optimized path does not
        // reintroduce first-window bias while adaptive tuning evolves.
        let mut txs = Vec::with_capacity(600);
        for i in 0..300u64 {
            txs.push(tx(i, vec![], vec![o(10_000 + i)]));
        }
        for i in 0..300u64 {
            txs.push(tx(1_000 + i, vec![], vec![o(42)]));
        }

        let d = auto_adaptive_decision(&txs);
        assert_eq!(d.sample_len, txs.len());
        assert!(
            d.use_hot_bucket,
            "direct-scan path should see tail hotspot runs"
        );
        assert_eq!(d.reason, "hotspot_detected");
    }

    #[test]
    fn auto_adaptive_sampling_detects_late_batch_hotspots_for_read_only_batches() {
        let _env = env_lock();
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.10");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.01");

        // Large adaptive batches use the bounded evenly-spaced sampling path.
        // Keep a read-only late-hotspot regression here so experiments around
        // sampling windows do not reintroduce first-window bias when write_set
        // is empty and the detector falls back to read_set keys.
        let mut txs = Vec::with_capacity(4096);
        for i in 0..2048u64 {
            txs.push(tx(i, vec![o(10_000 + i)], vec![]));
        }
        for i in 0..2048u64 {
            txs.push(tx(3_000 + i, vec![o(42)], vec![]));
        }

        let d = auto_adaptive_decision(&txs);
        assert!(
            d.use_hot_bucket,
            "late read-only hotspot should be visible in adaptive sample"
        );
        assert_eq!(d.reason, "hotspot_detected");
    }

    #[test]
    fn auto_adaptive_default_sample_boundary_uses_direct_scan_for_tail_hotspots() {
        let _env = env_lock();
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.20");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.05");

        // The default adaptive sample window tops out at 2048 txs. Keep the
        // exact boundary on the direct-scan fast path so future tuning does not
        // accidentally sample a partial prefix and miss a hotspot that appears
        // only in the batch tail.
        let mut txs = Vec::with_capacity(2048);
        for i in 0..1024u64 {
            txs.push(tx(i, vec![], vec![o(10_000 + i)]));
        }
        for i in 0..1024u64 {
            txs.push(tx(2_000 + i, vec![], vec![o(42)]));
        }

        let d = auto_adaptive_decision(&txs);
        assert_eq!(d.sample_len, txs.len());
        assert!(
            d.use_hot_bucket,
            "default sample boundary should stay on direct-scan and keep tail hotspots visible"
        );
        assert_eq!(d.reason, "hotspot_detected");
    }

    #[test]
    fn auto_adaptive_default_sample_boundary_uses_direct_scan_for_read_only_tail_hotspots() {
        let _env = env_lock();
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.20");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.05");

        // Mirror the exact 2048-tx default-sample boundary for read-only
        // batches. The adaptive fast path should stay on direct scan here so a
        // hotspot concentrated only in the batch tail cannot be lost when
        // experimental sample-window tuning evolves.
        let mut txs = Vec::with_capacity(2048);
        for i in 0..1024u64 {
            txs.push(tx(i, vec![o(10_000 + i)], vec![]));
        }
        for i in 0..1024u64 {
            txs.push(tx(2_000 + i, vec![o(42)], vec![]));
        }

        let d = auto_adaptive_decision(&txs);
        assert_eq!(d.sample_len, txs.len());
        assert!(
            d.use_hot_bucket,
            "default sample boundary should stay on direct-scan and keep read-only tail hotspots visible"
        );
        assert_eq!(d.reason, "hotspot_detected");
    }

    #[test]
    fn auto_adaptive_first_sampled_batch_boundary_preserves_tail_hotspot_visibility() {
        let _env = env_lock();
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.20");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.05");

        // 2049 txs is the first batch that exits the default direct-scan fast
        // path and enters bounded sampling. Keep a tight boundary regression so
        // experimental sampling changes do not lose a real tail hotspot on the
        // first sampled batch.
        let mut txs = Vec::with_capacity(2049);
        for i in 0..1024u64 {
            txs.push(tx(i, vec![], vec![o(10_000 + i)]));
        }
        for i in 0..1025u64 {
            txs.push(tx(2_000 + i, vec![], vec![o(42)]));
        }

        let d = auto_adaptive_decision(&txs);
        assert_eq!(d.sample_len, 2048);
        assert!(
            d.use_hot_bucket,
            "first sampled batch should preserve tail hotspot visibility"
        );
        assert_eq!(d.reason, "hotspot_detected");
    }

    #[test]
    fn auto_adaptive_direct_scan_detects_tail_hotspots_for_read_only_batches() {
        let _env = env_lock();
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.20");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.05");

        // Experimental adaptive detection falls back to read_set when write_set is
        // empty. Keep a read-only late-hotspot regression so future tuning of the
        // direct-scan path does not silently lose this signal.
        let mut txs = Vec::with_capacity(600);
        for i in 0..300u64 {
            txs.push(tx(i, vec![o(10_000 + i)], vec![]));
        }
        for i in 0..300u64 {
            txs.push(tx(1_000 + i, vec![o(42)], vec![]));
        }

        let d = auto_adaptive_decision(&txs);
        assert_eq!(d.sample_len, txs.len());
        assert!(
            d.use_hot_bucket,
            "direct-scan path should preserve read-only tail hotspot detection"
        );
        assert_eq!(d.reason, "hotspot_detected");
    }

    #[test]
    fn auto_adaptive_first_sampled_batch_preserves_read_only_tail_hotspot_visibility() {
        let _env = env_lock();
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.20");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.05");

        // Mirror the first sampled-batch boundary for read-only batches. Once the
        // batch grows from 2048 to 2049 txs, adaptive detection switches from
        // direct scan to bounded sampling and still needs to see a hotspot that
        // appears only in the tail through the read_set fallback path.
        let mut txs = Vec::with_capacity(2049);
        for i in 0..1024u64 {
            txs.push(tx(i, vec![o(10_000 + i)], vec![]));
        }
        for i in 0..1025u64 {
            txs.push(tx(2_000 + i, vec![o(42)], vec![]));
        }

        let d = auto_adaptive_decision(&txs);
        assert_eq!(d.sample_len, 2048);
        assert!(
            d.use_hot_bucket,
            "first sampled batch should preserve read-only tail hotspot visibility"
        );
        assert_eq!(d.reason, "hotspot_detected");
    }

    #[test]
    fn auto_adaptive_sampling_includes_batch_tail_for_hotspot_estimate() {
        let _env = env_lock();
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.0");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.0007");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.0");

        // sample_len clamps to 2048. Duplicate key appears only at the first and
        // final tx. Endpoint-inclusive sampling must capture both to avoid
        // underestimating tail hotspots.
        let mut txs = Vec::with_capacity(3000);
        txs.push(tx(1, vec![], vec![o(777)]));
        for i in 1..2999u64 {
            txs.push(tx(10_000 + i, vec![], vec![o(20_000 + i)]));
        }
        txs.push(tx(9_999, vec![], vec![o(777)]));

        let d = auto_adaptive_decision(&txs);
        assert!(d.use_hot_bucket, "tail hotspot should be counted in sample");
        assert_eq!(d.reason, "hotspot_detected");
    }

    #[test]
    fn auto_adaptive_sampling_includes_batch_tail_for_read_only_hotspot_estimate() {
        let _env = env_lock();
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.0");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.0007");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.0");

        // Keep the read-only counterpart to the endpoint-inclusive sampling
        // regression so adaptive tuning does not lose tail visibility when the
        // detector falls back from write_set to read_set keys.
        let mut txs = Vec::with_capacity(3000);
        txs.push(tx(1, vec![o(777)], vec![]));
        for i in 1..2999u64 {
            txs.push(tx(10_000 + i, vec![o(20_000 + i)], vec![]));
        }
        txs.push(tx(9_999, vec![o(777)], vec![]));

        let d = auto_adaptive_decision(&txs);
        assert!(
            d.use_hot_bucket,
            "read-only tail hotspot should be counted in sample"
        );
        assert_eq!(d.reason, "hotspot_detected");
    }

    #[test]
    fn auto_adaptive_expected_gain_gate_blocks_low_value_hotspot_switches() {
        let _env = env_lock();
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.0");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.0007");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.001");

        // Same endpoint-visible hotspot shape as the tail-sampling regression,
        // but with a gain threshold slightly above the observed streak*share.
        // Adaptive mode should fail closed instead of switching strategies on a
        // low-value hotspot signal.
        let mut txs = Vec::with_capacity(3000);
        txs.push(tx(1, vec![], vec![o(777)]));
        for i in 1..2999u64 {
            txs.push(tx(10_000 + i, vec![], vec![o(20_000 + i)]));
        }
        txs.push(tx(9_999, vec![], vec![o(777)]));

        let d = auto_adaptive_decision(&txs);
        assert!(d.expected_gain_score < d.min_expected_gain_score);
        assert!(
            !d.use_hot_bucket,
            "low-value hotspot signal should not switch adaptive strategy"
        );
        assert_eq!(d.reason, "low_expected_gain");
    }

    #[test]
    fn auto_adaptive_read_only_expected_gain_gate_blocks_low_value_hotspot_switches() {
        let _env = env_lock();
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.0");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.0007");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.001");

        // Mirror the low-value endpoint-hotspot regression for read-only
        // batches, where adaptive detection falls back to read_set keys.
        // Endpoint-visible sampling should stay fail-closed instead of
        // switching strategies on a trivial read-domain signal.
        let mut txs = Vec::with_capacity(3000);
        txs.push(tx(1, vec![o(777)], vec![]));
        for i in 1..2999u64 {
            txs.push(tx(10_000 + i, vec![o(20_000 + i)], vec![]));
        }
        txs.push(tx(9_999, vec![o(777)], vec![]));

        let d = auto_adaptive_decision(&txs);
        assert!(d.expected_gain_score < d.min_expected_gain_score);
        assert!(
            !d.use_hot_bucket,
            "low-value read-only hotspot signal should not switch adaptive strategy"
        );
        assert_eq!(d.reason, "low_expected_gain");
    }

    #[test]
    fn auto_adaptive_expected_gain_gate_accepts_percent_form_env_values() {
        let _env = env_lock();
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
        let _sample_len = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "64");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "25%");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "25%");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "25.5%");

        // Experimental lanes tune the expected-gain guard via env knobs. Keep
        // percent-form values wired through the parser so operators can raise
        // the gain floor without accidentally enabling adaptive mode.
        let mut txs = Vec::with_capacity(64);
        for i in 0..16u64 {
            txs.push(tx(120_000 + i * 4, vec![], vec![o(42)]));
            txs.push(tx(120_001 + i * 4, vec![], vec![o(42)]));
            txs.push(tx(120_002 + i * 4, vec![], vec![o(1_000 + i)]));
            txs.push(tx(120_003 + i * 4, vec![], vec![o(2_000 + i)]));
        }

        let d = auto_adaptive_decision(&txs);
        assert_eq!(d.sample_len, 64);
        assert!((d.streak_ratio - (16.0 / 63.0)).abs() < f64::EPSILON);
        assert!((d.hot_key_share - 0.5).abs() < f64::EPSILON);
        assert!((d.expected_gain_score - ((16.0 / 63.0) * 0.5)).abs() < f64::EPSILON);
        assert!((d.min_expected_gain_score - 0.255).abs() < f64::EPSILON);
        assert!(d.expected_gain_score < d.min_expected_gain_score);
        assert!(!d.use_hot_bucket);
        assert_eq!(d.reason, "low_expected_gain");
    }

    #[test]
    fn auto_adaptive_expected_gain_boundary_is_inclusive() {
        let _env = env_lock();
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
        let _sample_len = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "64");
        let _baseline_streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.0");
        let _baseline_margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _baseline_share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.0");
        let _baseline_gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.0");

        // Keep the expected-gain gate inclusive (`>=`) at exact equality so
        // experimental adaptive tuning can set a precise floor without a
        // float-boundary off-by-one silently suppressing the hotspot switch.
        let mut txs = Vec::with_capacity(64);
        for i in 0..16u64 {
            txs.push(tx(130_000 + i * 4, vec![], vec![o(77)]));
            txs.push(tx(130_001 + i * 4, vec![], vec![o(77)]));
            txs.push(tx(130_002 + i * 4, vec![], vec![o(3_000 + i)]));
            txs.push(tx(130_003 + i * 4, vec![], vec![o(4_000 + i)]));
        }

        let baseline = auto_adaptive_decision(&txs);
        assert!(
            baseline.use_hot_bucket,
            "baseline hotspot should clear permissive adaptive gates"
        );

        let gain = baseline.expected_gain_score.to_string();
        let hot_key_share = baseline.hot_key_share.to_string();
        let streak = baseline.streak_ratio.to_string();

        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", &streak);
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", &hot_key_share);
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", &gain);

        let d = auto_adaptive_decision(&txs);
        assert!(
            d.use_hot_bucket,
            "expected-gain threshold should stay inclusive at exact equality"
        );
        assert_eq!(d.reason, "hotspot_detected");
        assert!(d.expected_gain_score >= d.min_expected_gain_score);
        assert!(d.hot_key_share >= d.min_hot_key_share);
        assert!(d.streak_ratio >= d.streak_threshold + d.min_margin);
    }

    #[test]
    fn auto_adaptive_sampling_with_sparse_window_keeps_duplicate_indices_fail_closed() {
        let _env = env_lock();
        let _sample_len = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "2048");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.25");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.10");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.03");

        // Keep a regression with a just-over-half window to exercise sparse
        // integer-step sampling, where nearby sample points can collapse onto
        // the same tx index. The decision should remain fail-closed for a broad
        // unique-key batch instead of overestimating hotspot streaks.
        let mut txs = Vec::with_capacity(3000);
        for i in 0..3000u64 {
            txs.push(tx(50_000 + i, vec![], vec![o(100_000 + i)]));
        }

        let d = auto_adaptive_decision(&txs);
        assert_eq!(d.sample_len, 2048);
        assert_eq!(d.reason, "low_hot_key_share");
        assert!(!d.use_hot_bucket);
        assert!(
            d.hot_key_share <= (1.0 / d.sample_len as f64),
            "duplicate sparse-sample indices must not inflate hot-key share"
        );
        assert_eq!(
            d.streak_ratio, 0.0,
            "duplicate sparse-sample indices must not manufacture streak runs"
        );
    }

    #[test]
    fn auto_adaptive_read_only_sparse_sampling_keeps_duplicate_indices_fail_closed() {
        let _env = env_lock();
        let _sample_len = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "2048");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.25");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.10");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.03");

        // Mirror the sparse-window duplicate-index regression for read-only
        // batches, where adaptive detection falls back to read_set keys.
        // Duplicate sample indices must stay fail-closed instead of creating
        // artificial hotspot share or streaks under broad unique-key traffic.
        let mut txs = Vec::with_capacity(3000);
        for i in 0..3000u64 {
            txs.push(tx(80_000 + i, vec![o(130_000 + i)], vec![]));
        }

        let d = auto_adaptive_decision(&txs);
        assert_eq!(d.sample_len, 2048);
        assert_eq!(d.reason, "low_hot_key_share");
        assert!(!d.use_hot_bucket);
        assert!(
            d.hot_key_share <= (1.0 / d.sample_len as f64),
            "duplicate sparse-sample indices must not inflate read-only hot-key share"
        );
        assert_eq!(
            d.streak_ratio, 0.0,
            "duplicate sparse-sample indices must not manufacture read-only streak runs"
        );
    }

    #[test]
    fn auto_adaptive_keyless_batches_fail_closed_as_insufficient_sample() {
        let _env = env_lock();
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.0");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.0");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.0");

        // Experimental adaptive probes must stay fail-closed when a batch has
        // no observable read/write keys at all. Even with permissive thresholds,
        // keyless traffic should never manufacture a hotspot switch.
        let mut txs = Vec::with_capacity(600);
        for i in 0..600u64 {
            txs.push(tx(90_000 + i, vec![], vec![]));
        }

        let d = auto_adaptive_decision(&txs);
        assert_eq!(d.sample_len, txs.len());
        assert_eq!(d.reason, "insufficient_sample");
        assert!(!d.use_hot_bucket);
        assert_eq!(d.hot_key_share, 0.0);
        assert_eq!(d.streak_ratio, 0.0);
        assert_eq!(d.expected_gain_score, 0.0);
    }

    #[test]
    #[should_panic(
        expected = "mixed access domain contains the same object id with multiple versions"
    )]
    fn auto_adaptive_decision_rejects_cross_domain_version_skew_for_same_object_id() {
        let mut txs = Vec::with_capacity(512);
        txs.push(tx(
            1,
            vec![ObjectRef { id: 7, version: 2 }],
            vec![ObjectRef { id: 7, version: 1 }],
        ));
        for i in 1..512u64 {
            txs.push(tx(1_000 + i, vec![], vec![o(10_000 + i)]));
        }

        let _ = auto_adaptive_decision(&txs);
    }

    #[test]
    fn auto_adaptive_empty_batches_fail_closed_even_with_permissive_env_knobs() {
        let _env = env_lock();
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.0");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.0");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.0");

        // Empty batches must stay fail-closed in the experimental lane even if
        // every adaptive threshold is configured permissively.
        let txs: Vec<Tx> = Vec::new();

        let d = auto_adaptive_decision(&txs);
        assert_eq!(d.sample_len, 0);
        assert_eq!(d.reason, "small_batch");
        assert!(!d.use_hot_bucket);
        assert_eq!(d.hot_key_share, 0.0);
        assert_eq!(d.streak_ratio, 0.0);
        assert_eq!(d.expected_gain_score, 0.0);
    }

    #[test]
    fn auto_adaptive_keyless_gaps_break_same_key_streaks_fail_closed() {
        let _env = env_lock();
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.5");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.0");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.0");

        // Keyless txs should break streak continuity instead of letting the
        // detector count two same-key observations as adjacent when they are
        // separated by empty-access traffic.
        let mut txs = Vec::with_capacity(64);
        for i in 0..32u64 {
            txs.push(tx(100_000 + i * 2, vec![], vec![o(42)]));
            txs.push(tx(100_001 + i * 2, vec![], vec![]));
        }

        let d = auto_adaptive_decision(&txs);
        assert_eq!(d.sample_len, txs.len());
        assert_eq!(d.hot_key_share, 0.0);
        assert_eq!(d.streak_ratio, 0.0);
        assert!(!d.use_hot_bucket);
        assert_eq!(d.reason, "insufficient_sample");
        assert_eq!(d.expected_gain_score, 0.0);
    }

    #[test]
    fn primary_access_domain_key_preserves_keyless_singleton_and_duplicate_write_domains() {
        assert_eq!(primary_access_domain_key(&tx(1, vec![], vec![])), None);
        assert_eq!(
            primary_access_domain_key(&tx(2, vec![o(7)], vec![])),
            Some(7)
        );
        assert_eq!(
            primary_access_domain_key(&tx(3, vec![o(99)], vec![o(11)])),
            Some(11)
        );
        assert_eq!(
            primary_access_domain_key(&tx(4, vec![o(99)], vec![o(11), o(11), o(17)])),
            Some(11)
        );
    }

    #[test]
    fn primary_access_domain_key_two_entry_fast_path_canonicalizes_write_and_read_domains() {
        assert_eq!(
            primary_access_domain_key(&tx(10, vec![], vec![o(17), o(11)])),
            Some(11)
        );
        assert_eq!(
            primary_access_domain_key(&tx(11, vec![o(23), o(19)], vec![])),
            Some(19)
        );
        assert_eq!(
            primary_access_domain_key(&tx(12, vec![o(99)], vec![o(13), o(13)])),
            Some(13)
        );
    }

    #[test]
    fn primary_access_domain_key_ignores_same_version_cross_domain_echoes() {
        let echoed_write = tx(5, vec![o(7), o(5)], vec![o(5), o(11), o(7)]);
        let echoed_read = tx(6, vec![o(11), o(11), o(7)], vec![o(5), o(7)]);
        let deduped_write = tx(7, vec![o(7)], vec![o(5), o(11)]);
        let deduped_read = tx(8, vec![o(7), o(11)], vec![o(5)]);

        assert_eq!(primary_access_domain_key(&echoed_write), Some(5));
        assert_eq!(
            primary_access_domain_key(&echoed_write),
            primary_access_domain_key(&deduped_write)
        );
        assert_eq!(primary_access_domain_key(&echoed_read), Some(5));
        assert_eq!(
            primary_access_domain_key(&echoed_read),
            primary_access_domain_key(&deduped_read)
        );
    }

    #[test]
    fn primary_access_domain_key_canonicalizes_duplicate_heavy_read_only_domains() {
        let duplicate_heavy = tx(81, vec![o(17), o(29), o(17), o(11), o(29), o(11)], vec![]);
        let canonical = tx(82, vec![o(29), o(11), o(17)], vec![]);

        // Read-only hotspot detection should stay stable across duplicate-heavy
        // permutations of the same access domain so adaptive grouping does not
        // drift when telemetry or ingress ordering echoes the same keys.
        assert_eq!(primary_access_domain_key(&duplicate_heavy), Some(11));
        assert_eq!(
            primary_access_domain_key(&duplicate_heavy),
            primary_access_domain_key(&canonical)
        );
    }

    #[test]
    fn primary_access_domain_key_prefers_write_domain_over_lower_shared_read_keys() {
        let baseline = tx(9, vec![o(3), o(3), o(42)], vec![o(11), o(17), o(11)]);
        let echoed = tx(
            10,
            vec![o(3), o(11), o(42), o(17)],
            vec![o(17), o(11), o(11)],
        );
        let permuted = tx(11, vec![o(42), o(3)], vec![o(17), o(11)]);

        // Adaptive hotspot detection intentionally keys on the preferred write domain
        // when writes are present. Shared read-only dependencies with lower ids must
        // not pull the key away from the write-domain minimum, and same-version
        // cross-domain echoes should not perturb that write-first signal.
        assert_eq!(primary_access_domain_key(&baseline), Some(11));
        assert_eq!(
            primary_access_domain_key(&baseline),
            primary_access_domain_key(&echoed)
        );
        assert_eq!(
            primary_access_domain_key(&baseline),
            primary_access_domain_key(&permuted)
        );
    }

    #[test]
    fn primary_access_domain_key_stays_on_canonical_write_lane_under_duplicate_heavy_mixed_domains() {
        let baseline = tx(
            13,
            vec![o(2), o(41), o(2), o(41), o(99)],
            vec![o(19), o(13), o(19), o(13), o(13)],
        );
        let echoed = tx(
            14,
            vec![o(41), o(13), o(2), o(19), o(99), o(13)],
            vec![o(19), o(13), o(19), o(13)],
        );
        let permuted = tx(
            15,
            vec![o(99), o(41), o(2), o(2)],
            vec![o(19), o(13), o(19), o(13), o(19)],
        );

        // Avalanche-style lane isolation benefits from a stable primary execution
        // domain key even when telemetry/ingress repeats the same write-domain keys
        // and mixed read/write echoes arrive in different orders. Lower read-only
        // keys must not steal the canonical write-lane signal.
        assert_eq!(primary_access_domain_key(&baseline), Some(13));
        assert_eq!(
            primary_access_domain_key(&baseline),
            primary_access_domain_key(&echoed)
        );
        assert_eq!(
            primary_access_domain_key(&baseline),
            primary_access_domain_key(&permuted)
        );
    }

    #[test]
    #[should_panic(
        expected = "mixed access domain contains the same object id with multiple versions"
    )]
    fn primary_access_domain_key_rejects_cross_domain_version_skew_for_same_object_id() {
        let t = tx(
            1,
            vec![ObjectRef { id: 7, version: 2 }],
            vec![ObjectRef { id: 7, version: 1 }],
        );

        let _ = primary_access_domain_key(&t);
    }

    #[test]
    #[should_panic(
        expected = "mixed access domain contains the same object id with multiple versions"
    )]
    fn primary_access_domain_key_rejects_write_only_version_skew_for_same_object_id() {
        let t = tx(
            2,
            vec![],
            vec![ObjectRef { id: 7, version: 2 }, ObjectRef { id: 7, version: 1 }],
        );

        let _ = primary_access_domain_key(&t);
    }

    #[test]
    #[should_panic(
        expected = "mixed access domain contains the same object id with multiple versions"
    )]
    fn primary_access_domain_key_rejects_read_only_version_skew_for_same_object_id() {
        let t = tx(
            3,
            vec![ObjectRef { id: 9, version: 4 }, ObjectRef { id: 9, version: 3 }],
            vec![],
        );

        let _ = primary_access_domain_key(&t);
    }

    #[test]
    fn auto_adaptive_canonicalizes_primary_access_key_across_equivalent_domain_orderings() {
        let _env = env_lock();
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
        let _sample = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "64");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.20");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.05");

        let mut baseline = Vec::with_capacity(64);
        let mut permuted = Vec::with_capacity(64);
        for i in 0..32u64 {
            baseline.push(tx(140_000 + i, vec![o(99)], vec![o(50_000 + i), o(7)]));
            permuted.push(tx(150_000 + i, vec![o(99)], vec![o(7), o(50_000 + i)]));
        }
        for i in 0..32u64 {
            baseline.push(tx(
                140_100 + i,
                vec![o(99)],
                vec![o(60_000 + i), o(70_000 + i)],
            ));
            permuted.push(tx(
                150_100 + i,
                vec![o(99)],
                vec![o(70_000 + i), o(60_000 + i)],
            ));
        }

        let baseline_decision = auto_adaptive_decision(&baseline);
        let permuted_decision = auto_adaptive_decision(&permuted);

        assert_eq!(baseline_decision.sample_len, 64);
        assert_eq!(permuted_decision.sample_len, 64);
        assert_eq!(
            baseline_decision.use_hot_bucket,
            permuted_decision.use_hot_bucket
        );
        assert_eq!(baseline_decision.reason, permuted_decision.reason);
        assert_eq!(
            baseline_decision.streak_ratio,
            permuted_decision.streak_ratio
        );
        assert_eq!(
            baseline_decision.hot_key_share,
            permuted_decision.hot_key_share
        );
        assert_eq!(
            baseline_decision.expected_gain_score,
            permuted_decision.expected_gain_score
        );
        assert!(baseline_decision.use_hot_bucket);
        assert_eq!(baseline_decision.reason, "hotspot_detected");
    }

    #[test]
    fn auto_adaptive_read_only_keyless_gaps_break_same_key_streaks_fail_closed() {
        let _env = env_lock();
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.5");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.0");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.0");

        // Mirror the keyless-gap regression for read-only batches, where the
        // experimental detector falls back to read_set keys.
        let mut txs = Vec::with_capacity(64);
        for i in 0..32u64 {
            txs.push(tx(110_000 + i * 2, vec![o(42)], vec![]));
            txs.push(tx(110_001 + i * 2, vec![], vec![]));
        }

        let d = auto_adaptive_decision(&txs);
        assert_eq!(d.sample_len, txs.len());
        assert_eq!(d.hot_key_share, 0.0);
        assert_eq!(d.streak_ratio, 0.0);
        assert!(!d.use_hot_bucket);
        assert_eq!(d.reason, "insufficient_sample");
        assert_eq!(d.expected_gain_score, 0.0);
    }

    #[test]
    fn auto_adaptive_keeps_duplicate_heavy_mixed_domains_on_same_write_lane_signal() {
        let _env = env_lock();
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
        let _sample = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "64");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.20");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.05");

        let mut baseline = Vec::with_capacity(64);
        let mut echoed = Vec::with_capacity(64);
        for i in 0..64u64 {
            baseline.push(tx(
                160_000 + i,
                vec![o(2), o(41), o(2), o(41), o(99)],
                vec![o(19), o(13), o(19), o(13), o(13)],
            ));
            echoed.push(tx(
                170_000 + i,
                vec![o(41), o(13), o(2), o(19), o(99), o(13)],
                vec![o(19), o(13), o(19), o(13)],
            ));
        }

        // Avalanche-style mixed-domain lanes should stay anchored to the same
        // canonical write-lane key even when duplicate-heavy read/write echoes
        // arrive in different orders. Otherwise the adaptive hotspot probe can
        // drift across equivalent execution domains and fragment lane isolation.
        let baseline_decision = auto_adaptive_decision(&baseline);
        let echoed_decision = auto_adaptive_decision(&echoed);

        assert_eq!(baseline_decision.sample_len, 64);
        assert_eq!(echoed_decision.sample_len, 64);
        assert_eq!(baseline_decision.use_hot_bucket, echoed_decision.use_hot_bucket);
        assert_eq!(baseline_decision.reason, echoed_decision.reason);
        assert_eq!(baseline_decision.streak_ratio, echoed_decision.streak_ratio);
        assert_eq!(baseline_decision.hot_key_share, echoed_decision.hot_key_share);
        assert_eq!(
            baseline_decision.expected_gain_score,
            echoed_decision.expected_gain_score
        );
        assert!(baseline_decision.use_hot_bucket);
        assert_eq!(baseline_decision.reason, "hotspot_detected");
    }

    #[test]
    fn auto_adaptive_prefers_write_hotspot_signal_over_shared_read_domains() {
        let _env = env_lock();
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.20");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.05");

        // Mixed read/write batches often share a broad read dependency (e.g. a
        // common config object) while writes stay unique. Adaptive detection
        // should prefer write_set keys when present so experiments do not switch
        // strategies based only on a shared read domain that does not imply a
        // write hotspot.
        let mut txs = Vec::with_capacity(600);
        for i in 0..600u64 {
            txs.push(tx(i, vec![o(42)], vec![o(10_000 + i)]));
        }

        let d = auto_adaptive_decision(&txs);
        assert_eq!(d.sample_len, txs.len());
        assert!(!d.use_hot_bucket);
        assert_eq!(d.reason, "low_hot_key_share");
        assert!(d.hot_key_share <= (1.0 / d.sample_len as f64));
        assert_eq!(d.streak_ratio, 0.0);
        assert_eq!(d.expected_gain_score, 0.0);
    }

    #[test]
    fn auto_adaptive_keeps_equivalent_mixed_domains_on_same_lane_signal_when_roles_flip() {
        let _env = env_lock();
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
        let _sample = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "64");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.20");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.05");

        let mut write_primary = Vec::with_capacity(64);
        let mut read_primary = Vec::with_capacity(64);
        for i in 0..64u64 {
            write_primary.push(tx(180_000 + i, vec![o(23)], vec![o(5)]));
            read_primary.push(tx(190_000 + i, vec![o(5)], vec![o(23)]));
        }

        // Equivalent two-key mixed access domains should keep the same
        // Avalanche-style lane signal even when read/write roles flip between the
        // same objects. Otherwise adaptive scheduling can fragment one hotspot
        // into separate lanes purely because ingress classified the same domain
        // with opposite local read/write roles.
        let write_primary_decision = auto_adaptive_decision(&write_primary);
        let read_primary_decision = auto_adaptive_decision(&read_primary);

        assert_eq!(write_primary_decision.sample_len, 64);
        assert_eq!(read_primary_decision.sample_len, 64);
        assert_eq!(
            write_primary_decision.use_hot_bucket,
            read_primary_decision.use_hot_bucket
        );
        assert_eq!(write_primary_decision.reason, read_primary_decision.reason);
        assert_eq!(
            write_primary_decision.streak_ratio,
            read_primary_decision.streak_ratio
        );
        assert_eq!(
            write_primary_decision.hot_key_share,
            read_primary_decision.hot_key_share
        );
        assert_eq!(
            write_primary_decision.expected_gain_score,
            read_primary_decision.expected_gain_score
        );
        assert!(write_primary_decision.use_hot_bucket);
        assert_eq!(write_primary_decision.reason, "hotspot_detected");
    }

    #[test]
    fn auto_adaptive_mixed_hot_key_probe_avoids_false_hotspots_from_shared_leading_writes() {
        let _env = env_lock();
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
        let _sample = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "64");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.20");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.05");

        // Executor conflict grouping stays object-scoped and write-first, but a
        // shared leading write object can coexist with a unique adjacent owned
        // object. Adaptive hotspot detection should follow the same mixed
        // two-key hint as hot-bucket scheduling instead of collapsing the batch
        // into a false hotspot on the shared leading key alone.
        let mut txs = Vec::with_capacity(64);
        for i in 0..64u64 {
            txs.push(tx(i, vec![], vec![o(42), o(10_000 + i)]));
        }

        let d = auto_adaptive_decision(&txs);
        assert_eq!(d.sample_len, 64);
        assert!(!d.use_hot_bucket);
        assert_eq!(d.reason, "low_hot_key_share");
        assert!(d.hot_key_share <= (1.0 / d.sample_len as f64));
        assert_eq!(d.streak_ratio, 0.0);
        assert_eq!(d.expected_gain_score, 0.0);
    }

    #[test]
    fn auto_adaptive_large_sample_prefers_write_signal_over_shared_read_domains() {
        let _env = env_lock();
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.20");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.05");

        // Mirror the shared-read-domain regression on the large-batch sampled
        // path. Even when adaptive mode samples a wide queue, unique writes
        // must prevent a false hotspot switch caused only by a common read key.
        let mut txs = Vec::with_capacity(3_000);
        for i in 0..3_000u64 {
            txs.push(tx(i, vec![o(42)], vec![o(10_000 + i)]));
        }

        let d = auto_adaptive_decision(&txs);
        assert_eq!(d.sample_len, 2048);
        assert!(!d.use_hot_bucket);
        assert_eq!(d.reason, "low_hot_key_share");
        assert!(d.hot_key_share <= (1.0 / d.sample_len as f64));
        assert_eq!(d.streak_ratio, 0.0);
        assert_eq!(d.expected_gain_score, 0.0);
    }

    #[test]
    fn auto_adaptive_detects_write_hotspots_even_with_shared_read_domains() {
        let _env = env_lock();
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.20");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.05");

        // Large mixed batches can share a broad read dependency while only a
        // late contiguous region develops a true write hotspot. Adaptive
        // experiments should still switch based on the write signal rather than
        // being diluted by the shared read domain.
        let mut txs = Vec::with_capacity(3_000);
        for i in 0..1_800u64 {
            txs.push(tx(i, vec![o(42)], vec![o(10_000 + i)]));
        }
        for i in 1_800..3_000u64 {
            txs.push(tx(i, vec![o(42)], vec![o(7)]));
        }

        let d = auto_adaptive_decision(&txs);
        assert_eq!(d.sample_len, 2048);
        assert!(d.use_hot_bucket);
        assert_eq!(d.reason, "hotspot_detected");
        assert!(d.hot_key_share >= 0.20);
        assert!(d.streak_ratio >= 0.20);
        assert!(d.expected_gain_score >= 0.05);
    }

    #[test]
    fn auto_adaptive_detects_late_write_hotspots_after_keyless_prefixes() {
        let _env = env_lock();
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.20");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.05");

        // Experimental adaptive sampling should stay fail-open for a real late
        // write hotspot even when much of the earlier sampled region is keyless
        // traffic. Keyless samples may break streak continuity locally, but they
        // must not suppress a dense tail hotspot that still clears the adaptive
        // switch thresholds.
        let mut txs = Vec::with_capacity(3_000);
        for i in 0..1_500u64 {
            txs.push(tx(i, vec![], vec![]));
        }
        for i in 1_500..1_800u64 {
            txs.push(tx(i, vec![], vec![o(10_000 + i)]));
        }
        for i in 1_800..3_000u64 {
            txs.push(tx(i, vec![], vec![o(7)]));
        }

        let d = auto_adaptive_decision(&txs);
        assert_eq!(d.sample_len, 2048);
        assert!(d.use_hot_bucket);
        assert_eq!(d.reason, "hotspot_detected");
        assert!(d.hot_key_share >= 0.20);
        assert!(d.streak_ratio >= 0.20);
        assert!(d.expected_gain_score >= 0.05);
    }

    #[test]
    fn auto_adaptive_detects_late_read_only_hotspots_after_keyless_prefixes() {
        let _env = env_lock();
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.20");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.05");

        // Read-only batches fall back to sampled read_set keys. Adaptive
        // experiments should still surface a real late tail hotspot even when
        // much of the earlier sampled region is keyless traffic.
        let mut txs = Vec::with_capacity(3_000);
        for i in 0..1_500u64 {
            txs.push(tx(i, vec![], vec![]));
        }
        for i in 1_500..1_800u64 {
            txs.push(tx(i, vec![o(10_000 + i)], vec![]));
        }
        for i in 1_800..3_000u64 {
            txs.push(tx(i, vec![o(7)], vec![]));
        }

        let d = auto_adaptive_decision(&txs);
        assert_eq!(d.sample_len, 2048);
        assert!(d.use_hot_bucket);
        assert_eq!(d.reason, "hotspot_detected");
        assert!(d.hot_key_share >= 0.20);
        assert!(d.streak_ratio >= 0.20);
        assert!(d.expected_gain_score >= 0.05);
    }

    #[test]
    fn free_ingress_batches_short_circuit_to_single_group_after_strategy_reorder() {
        let txs = vec![
            tx(9, vec![], vec![]),
            tx(3, vec![], vec![]),
            tx(7, vec![], vec![]),
        ];

        let (groups, profile) =
            build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::WriteFirst);

        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].len(), txs.len());
        // WriteFirst tie-breaks by tx id; fast path must preserve strategy reorder.
        assert_eq!(
            groups[0].iter().map(|t| t.id).collect::<Vec<_>>(),
            vec![3, 7, 9]
        );
        assert_eq!(profile.conflict_checks, 0);
        assert_eq!(profile.conflict_hits, 0);
        assert_eq!(profile.group_count, 1);
        assert_eq!(profile.max_group_size, txs.len());
        assert_eq!(profile.min_group_size, txs.len());
    }

    #[test]
    fn footprint_desc_reorder_uses_object_scoped_domains_not_raw_version_counts() {
        let mut txs = vec![
            tx(
                9,
                vec![ov(77, 1), ov(77, 1), ov(77, 1), ov(77, 1)],
                vec![ov(77, 1), ov(77, 1)],
            ),
            tx(3, vec![ov(10, 1), ov(20, 1)], vec![ov(30, 1), ov(40, 1)]),
        ];

        reorder_for_strategy(&mut txs, GroupingStrategy::FootprintDesc);

        // FootprintDesc should rank by the deduped object-scoped access domain so
        // duplicate/version-heavy footprints do not outrank genuinely wider work.
        assert_eq!(txs.iter().map(|tx| tx.id).collect::<Vec<_>>(), vec![3, 9]);
    }

    #[test]
    fn write_first_reorder_uses_object_scoped_domains_not_raw_version_counts() {
        let mut txs = vec![
            tx(
                9,
                vec![ov(77, 1), ov(77, 1), ov(77, 1), ov(77, 1)],
                vec![ov(77, 1), ov(77, 1)],
            ),
            tx(3, vec![ov(10, 1), ov(20, 1)], vec![ov(30, 1), ov(40, 1)]),
        ];

        reorder_for_strategy(&mut txs, GroupingStrategy::WriteFirst);

        // WriteFirst should rank by deduped object-scoped write/read domains so
        // duplicate/version-heavy footprints do not outrank genuinely wider work.
        assert_eq!(txs.iter().map(|tx| tx.id).collect::<Vec<_>>(), vec![3, 9]);
    }

    #[test]
    fn write_last_reorder_uses_object_scoped_domains_not_raw_version_counts() {
        let mut txs = vec![
            tx(
                9,
                vec![ov(77, 1), ov(77, 1), ov(77, 1), ov(77, 1)],
                vec![ov(77, 1), ov(77, 1)],
            ),
            tx(3, vec![ov(10, 1), ov(20, 1)], vec![ov(30, 1), ov(40, 1)]),
        ];

        reorder_for_strategy(&mut txs, GroupingStrategy::WriteLast);

        // WriteLast should also follow deduped object-scoped domains so
        // version-heavy footprints do not drift from the executor's scheduler.
        assert_eq!(txs.iter().map(|tx| tx.id).collect::<Vec<_>>(), vec![9, 3]);
    }

    #[test]
    #[should_panic(expected = "mixed access domain contains the same object id with multiple versions")]
    fn footprint_desc_reorder_panics_on_mixed_domain_version_skew() {
        let mut txs = vec![tx(9, vec![ov(77, 1)], vec![ov(77, 2)])];
        reorder_for_strategy(&mut txs, GroupingStrategy::FootprintDesc);
    }

    #[test]
    #[should_panic(expected = "mixed access domain contains the same object id with multiple versions")]
    fn write_first_reorder_panics_on_mixed_domain_version_skew() {
        let mut txs = vec![tx(9, vec![ov(77, 1)], vec![ov(77, 2)])];
        reorder_for_strategy(&mut txs, GroupingStrategy::WriteFirst);
    }

    #[test]
    #[should_panic(expected = "mixed access domain contains the same object id with multiple versions")]
    fn write_last_reorder_panics_on_mixed_domain_version_skew() {
        let mut txs = vec![tx(9, vec![ov(77, 1)], vec![ov(77, 2)])];
        reorder_for_strategy(&mut txs, GroupingStrategy::WriteLast);
    }

    #[test]
    fn empty_batch_fast_path_is_profile_stable_across_strategies() {
        let strategies = [
            GroupingStrategy::Original,
            GroupingStrategy::HotBucketInterleave,
            GroupingStrategy::AggressiveGreedy,
            GroupingStrategy::AutoAdaptive,
        ];

        for strategy in strategies {
            let (groups, profile) = build_parallel_groups_profile_with_strategy(&[], strategy);
            assert!(groups.is_empty());
            assert_eq!(profile.tx_count, 0);
            assert_eq!(profile.group_count, 0);
            assert_eq!(profile.grouped_count, 0);
            assert_eq!(profile.max_group_size, 0);
            assert_eq!(profile.min_group_size, 0);
            assert_eq!(profile.avg_group_size, 0.0);
            assert_eq!(profile.conflict_checks, 0);
            assert_eq!(profile.conflict_hits, 0);
            assert_eq!(profile.candidate_groups_scanned, 0);
            assert_eq!(profile.stage_ww_checks, 0);
            assert_eq!(profile.stage_ww_hits, 0);
            assert_eq!(profile.stage_wr_checks, 0);
            assert_eq!(profile.stage_wr_hits, 0);
            assert_eq!(profile.stage_rw_checks, 0);
            assert_eq!(profile.stage_rw_hits, 0);
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
    fn original_conflict_only_batch_reports_singleton_profile_shape() {
        let txs = vec![
            tx(51, vec![], vec![o(99)]),
            tx(52, vec![], vec![o(99)]),
            tx(53, vec![], vec![o(99)]),
        ];

        let (groups, profile) =
            build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::Original);

        assert_eq!(groups.len(), 3);
        assert_eq!(
            groups
                .iter()
                .map(|group| group.iter().map(|tx| tx.id).collect::<Vec<_>>())
                .collect::<Vec<_>>(),
            vec![vec![51], vec![52], vec![53]]
        );
        assert_eq!(profile.tx_count, 3);
        assert_eq!(profile.group_count, 3);
        assert_eq!(profile.grouped_count, 3);
        assert_eq!(profile.max_group_size, 1);
        assert_eq!(profile.min_group_size, 1);
        assert_eq!(profile.avg_group_size, 1.0);
        assert_eq!(profile.conflict_hits, 2);
    }
}

