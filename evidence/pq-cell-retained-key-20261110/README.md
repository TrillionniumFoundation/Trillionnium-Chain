# Cell publisher retained-key evidence

Implementation source: `81f89b01b1fe0bb23cb8b885a30bb8fcb11a8455`, tree
`a3899186dc25721f3bc04d1e043b3ce979119de8`, parent fixed M14
`ac8501a85a770ba34f34e1bed507ca747e5c3f8d`.

## Recovered original hosted execution

The original [required baseline run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42744039935)
completed both runtime and quality shards on the exact head and prospective
merge. The prospective merge is `8d57aa4add724ba8d70e4c96717911869aa4680c`,
with the same complete tree. Original before/after source records agree on
27,655 entries and 2,527,824,853 bytes. These are source-consistency records,
not independently authenticated execution.

| Original observation | Actual outcome |
| --- | --- |
| Head and prospective-merge runtime shards | Passed; original exact commands retained |
| Head and prospective-merge quality shards | Passed; strict workspace/all-target/all-feature Clippy with `-D warnings`, formatting, dependency policy and doc checks retained |
| Head complete DA library | 720 passed, zero failed or ignored; all five new retained-key controls executed |
| Head original NPQ CLI | Four passed, zero failed, one original ignored export experiment |
| Dedicated PQ workflow | Failed; not a complete native protocol acceptance |
| All 18 original workflows | Ten success, eight failure |

The complete original workspace-test log and head quality job log are retained
as deterministic gzip, with original-byte hashes. The workspace log contains
437 harness summary lines, including child execution; they are deliberately
not added into a whole-workspace test total. A successful `--all-targets` build
does not establish that the signed sealed example's `main` ran.

## Two preserved source-registration failures

The [dedicated PQ run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42744039718)
retains both failures:

1. The old fifteen-path lifetime lock selected revision `66b7064` and refused
   the changed `cell/pq.rs`. The current reviewed mapping is explicitly rebound
   to actual regular Git blobs at `81f89b01`. Fourteen digests remain equal;
   only `cell/pq.rs` changes to
   `906e3c38a8f038a346e589c514b69dcb585f4d930bd7167d83aa6c495dd2ed33`.
   The separate declared scope remains incomplete. No failure bound is inferred.
2. The actual compile-fail doctest passed with E0308 at line 423, but its reader
   required the preceding line 364. The new exact registration and actual
   [current fixture](../../tests/fixtures/ci/cell-current-api-readback-v3-81f89b0.json)
   preserve the original error, count, context and duplicate-refusal checks.
   The old `66b7064` log and provenance JSON remain unchanged and are explicitly
   refused by the current reader.

The repair also adds a source-recorded execution of the signed sealed example
to the existing native workflow. Its outcome remains pending until a terminal
receipt exists. Runtime Rust source and signed/stored formats are unchanged
relative to `81f89b01`; prior native runs retain their original source identity.

## Retention and validation boundary

[Archive index](archive-index.json) records all downloaded ZIP and member hashes,
including complete original failures. Selected complete members, four original
shard commands/receipts and provider build/smoke records are retained; complete
ZIPs, binaries, private keys and a second source checkout are not republished.
`staged-lifetime-review/` retains the initial refusal and 58 passing original
lifetime tests, inspector and arithmetic example on staged binding changes.
Those are staged observations, not a newly committed-source qualification.

The preceding local scratch execution did not retain terminal native receipts
across restoration. It supplies no additional pass count. Recovered GitHub
records above are attributed only to their actual executed identities.

**HOLD_NO_GO remains.** No Cell performance improvement, model quality,
independent custody, rollback-surviving freshness, algorithm replacement,
production effect integration or whole-chain lifetime/QROM qualification is
established. Actual lifetime failure bounds remain null; composition coverage,
whole-chain PQ qualification and production activation remain false.
