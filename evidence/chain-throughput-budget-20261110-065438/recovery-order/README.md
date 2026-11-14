# Existing recovery-order index: source and SQL observation

The resource document said that the heaviest retained candidate was selected
without a dedicated chainwork-order index. The inspected source already defines
`work_order ON blocks(chainwork DESC,height,id)` in `BASE_DDL` and uses the exact
same ordering in `recovery_target`. This continuation corrects that statement;
it does not add an index or change native storage, selection or recovery.

## Exact scope

The observation extracts the existing schema and query from commit
`e4abb172147e941b62483652b0ceabaae4317624`, source blob
`a8bd7b9c8d9b02617060bea955b3bb21d905129f`. The complete source, extracted SQL and
observer script SHA-256 digests, source tree, Python/SQLite versions and actual
plans are in [observation.json](observation.json).

Each arm opens a new in-memory Python SQLite database. The fixture contains
4,099 synthetic records, including equal-work records that exercise ascending
height and ID tie rules. They are not mined or admitted native blocks. The
original `BASE_DDL` is used in both arms; the second arm removes `work_order`
only in its private in-memory database. No live database is opened or modified.

On SQLite 3.53.1, the original schema yields
`SCAN blocks USING COVERING INDEX work_order` with no temporary order B-tree.
The index-removal control yields a block scan and `USE TEMP B-TREE FOR ORDER BY`.
Both return the complete ID selected by an independent Python sort, including
the two tie rules. SQL planner output is a component observation, not a measured
native-node speedup or a bound on all recovery work.

## Reproduce

Run from the repository root. Keep the result outside this committed evidence
path when comparing another source or SQLite version.

```bash
python3 evidence/chain-throughput-budget-20261110-065438/recovery-order/reproduce.py \
  --repo . \
  --source e4abb172147e941b62483652b0ceabaae4317624 \
  --output /tmp/chain-recovery-order-observation.json
```

The script resolves the source once, reads committed bytes, and refuses an
unreviewed DDL literal/query shape. It does not rely on the current worktree's
uncommitted native source. A changed query plan or selected ID exits nonzero
rather than emitting a successful observation.

## Remaining limits

No native Node is executed. The Python SQLite version need not equal the native
binary's SQLite version. This observation does not verify stored state, intent
recovery, active-state/root/index checks, retained-history verification, cold
replay, deadlines, disk retention or business throughput. Old branch recovery
can still walk to genesis and replay every required delta; the existing index
does not establish constant-time recovery or a global history bound. Original
service and History acceptance failures remain unchanged.
