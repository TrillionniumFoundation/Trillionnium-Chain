use super::*;

use std::collections::HashSet;

#[test]
fn ww_conflict() {
    assert!(detect_conflict(
        &tx(1, vec![], vec![o(1)]),
        &tx(2, vec![], vec![o(1)])
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
fn no_conflict() {
    assert!(!detect_conflict(
        &tx(1, vec![o(1)], vec![]),
        &tx(2, vec![o(2)], vec![])
    ));
}

#[test]
fn read_only_overlap_is_non_conflicting() {
    assert!(!detect_conflict(
        &tx(1, vec![o(7), o(8)], vec![]),
        &tx(2, vec![o(8), o(9)], vec![])
    ));
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
fn object_version_updates_still_conflict_on_same_object_id() {
    let older = tx(
        1,
        vec![ObjectRef { id: 77, version: 1 }],
        vec![],
    );
    let newer = tx(
        2,
        vec![],
        vec![ObjectRef { id: 77, version: 2 }],
    );

    assert!(detect_conflict(
        &older,
        &newer
    ), "executor conflict domains must stay object-scoped even when refs carry different versions");
}

#[test]
fn dedup_access_keys_collapses_same_object_across_versions() {
    let keys = dedup_access_keys(&[
        ObjectRef { id: 100, version: 1 },
        ObjectRef { id: 200, version: 1 },
        ObjectRef { id: 100, version: 2 },
        ObjectRef { id: 300, version: 1 },
        ObjectRef { id: 400, version: 1 },
        ObjectRef { id: 300, version: 9 },
        ObjectRef { id: 500, version: 1 },
        ObjectRef { id: 600, version: 1 },
        ObjectRef { id: 700, version: 1 },
        ObjectRef { id: 600, version: 8 },
    ]);

    assert_eq!(keys, vec![100, 200, 300, 400, 500, 600, 700]);
}
