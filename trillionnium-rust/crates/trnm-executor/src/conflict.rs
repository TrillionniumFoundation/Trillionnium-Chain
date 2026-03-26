use std::collections::{HashMap, HashSet};
use trnm_types::{ObjectRef, Tx};

fn access_domain_versions_are_consistent(objs: &[ObjectRef]) -> bool {
    if objs.len() <= 1 {
        return true;
    }

    if objs.len() == 2 {
        return objs[0].id != objs[1].id || objs[0].version == objs[1].version;
    }

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

    if reads.len() == 1 && writes.len() == 1 {
        return reads[0].id != writes[0].id || reads[0].version == writes[0].version;
    }

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

pub(crate) fn detect_conflict(a: &Tx, b: &Tx) -> bool {
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

    intersects(&a.write_set, &b.write_set)
        || intersects(&a.write_set, &b.read_set)
        || intersects(&a.read_set, &b.write_set)
}

#[inline]
pub(crate) fn object_access_domain_key(obj: &ObjectRef) -> u64 {
    // Execution conflict domains are object-scoped, not version-scoped.
    // This keeps scheduler grouping aligned with the current TRNM state model:
    // a newer ObjectRef version still aliases the same mutable object lane and
    // therefore must serialize against older refs to that object id.
    obj.id
}

#[inline]
pub(crate) fn access_key(obj: &ObjectRef) -> u64 {
    object_access_domain_key(obj)
}

#[inline]
pub(crate) fn dedup_access_keys(objs: &[ObjectRef]) -> Vec<u64> {
    assert!(
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

pub(crate) fn intersects(x: &[ObjectRef], y: &[ObjectRef]) -> bool {
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
pub(crate) fn vec_hashset_intersects(a: &[u64], b: &HashSet<u64>) -> bool {
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

    for k in a {
        if b.contains(k) {
            return true;
        }
    }
    false
}

pub(crate) fn hot_object_share(txs: &[Tx]) -> f64 {
    let mut counts: HashMap<u64, usize> = HashMap::new();
    let mut total = 0usize;

    for tx in txs {
        assert_tx_access_domain_versions_are_consistent(tx);
        let mut keys = dedup_access_keys(&tx.read_set);
        for key in dedup_access_keys(&tx.write_set) {
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
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

#[inline]
pub(crate) fn access_map_capacity_hint(txs: &[Tx]) -> usize {
    const MIN_CAP: usize = 64;
    const MAX_CAP: usize = 1 << 20;

    let mut footprint = 0usize;
    for tx in txs {
        assert_tx_access_domain_versions_are_consistent(tx);
        footprint = footprint
            .saturating_add(tx.read_set.len())
            .saturating_add(tx.write_set.len());
    }

    // HashMap load-factor friendly sizing. Keep a floor for tiny batches and
    // cap for pathological bursts so this remains a low-risk sizing hint.
    let hinted = footprint
        .saturating_mul(4)
        .saturating_div(3)
        .saturating_add(1);
    hinted.clamp(MIN_CAP, MAX_CAP)
}
