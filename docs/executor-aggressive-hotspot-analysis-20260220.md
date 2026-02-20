# Executor AggressiveGreedy Hotspot Analysis (2026-02-20)

## Scope
- Target: `crates/trnm-executor/src/lib.rs`
- Function: `build_parallel_groups_aggressive_profile`
- Workload sampled:
  - `txs=20000 keys=2000 workload=mixed read_fanout=3 write_every=2`

## Measured Baseline (before micro-opt)
- Original: ~36-37ms
- AggressiveGreedy: ~116-125ms
- Observation: Aggressive performs fewer `conflict_checks` but still much slower.

## Confirmed Cost Drivers
1. **Allocation-heavy set operations**
   - Per tx builds `HashSet` for read/write keys.
   - Per candidate group runs 2-3 `HashSet` intersection scans.
2. **Clone overhead in hot path (fixed in this step)**
   - `tx.clone()` on successful placement.
   - `read_keys.clone()` / `write_keys.clone()` on new group path.
3. **Group-level key set growth**
   - `group_read_keys/group_write_keys` become large; intersections get expensive.

## Implemented in this step
- Removed `tx.clone()` in placement path by moving ownership via `Option<Tx>`.
- Removed `read_keys/write_keys` clone on new-group path (move instead).
- Kept semantics unchanged; tests pass.

## Post-change spot check
- Round 1 (clone removal):
  - Original: ~36-37ms (unchanged)
  - AggressiveGreedy: ~113-115ms (small improvement, still ~3x slower)
- Round 2 (keyset allocation/intersection hot-path reduction):
  - Original: ~37ms
  - AggressiveGreedy: ~84-85ms
  - Improvement vs prior aggressive baseline: ~25%

## Next optimization backlog (priority)
1. **Replace HashSet keys with sorted small-vec / compact vec**
   - Use deduped vector for tx access keys (already exists in Original path).
   - For group keys, evaluate bitmap/roaring or compact hash (FxHash) depending on key domain.
2. **Introduce candidate pruning by key-index**
   - Maintain object->candidate groups index to avoid scanning all groups from `min_group`.
3. **Split strategy activation from strategy implementation**
   - Aggressive only for explicit hotspot signatures; default path remains Original.
4. **Add per-strategy overhead metrics**
   - `candidate_groups_scanned`, `set_intersection_ops`, `avg_group_keyset_size`.

## Decision
- Keep `AggressiveGreedy` as experimental/non-default.
- Continue gate to prevent silent regression on CI.
