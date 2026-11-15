# Cell contract continuation — 2026-11-05

This is implementation and scoped evidence for the existing Chain PR #688 and
ordinary Hepta PR #4812 (`TrillionniumFoundation/hepta-private-ci`). It is not a
release approval or a replacement development plan. All production, independent
WAN, ordinary model-use and economic acceptance flags remain false.

## Scope

| Owner | Concrete continuation | Evidence boundary |
| --- | --- | --- |
| Discovery directory | Classic/PQ mutex and SQLite contention spend the caller's original deadline; late committed state remains durable without a success ACK. | Twelve actual contention regressions; no DHT, eclipse or operator-independence claim. |
| Delta | Original timeout starts before metadata work; explicit cancellation retains the real transport reservation and preserves a published target on late refusal. | Four new controls include partial TCP and direct-base reconstruction after 32 versions; no broad model benchmark. |
| Ordinary runtime | Independently pinned interpreter, installed inventory and project-source closure; explicit new owner/worker/execution namespaces; pre-spawn bootstrap checks and verified Python source loading. | Static/native refusal controls and actual CPython subprocesses; full model/FinalUse/device use remains unexecuted here. |
| Source/CI | Exact dependency pins include both directory owners and all imported project/configuration dependencies; runtime controls are mandatory in the existing CI lane. | Source integrity is independent of cryptographic, model and product acceptance. |

The source continuation starts after Chain
`657bf2a462ff13a6101ebcb4fbe0fb91c515c972` and runtime
`7530e4bc7aa61a0c23a5933fef4a65d86a586cf8`. Earlier Chain work began at
`6ee529046d295e3175f09112492abee373f1f54c`; all seven intervening commits were
preserved by fast-forward before integration. Later concurrent commits are
preserved through explicit merge parents. No previous green is assigned to a
later combined tree. The completed source-bound receipts below retain the
failed and preparation attempts separately.

## Completed source-bound results

| Recorded source | Actual execution | Receipt |
| --- | --- | --- |
| Local `f03be25066fefa1674b104f22cbc6aea09652a80`, tree `155213c2468edc411325f4f1853b471a6b25f355` | **378 Rust/doc tests**: 337 library, 31 integration and 10 doctest; zero failed or ignored. **220 Python controls**. Workspace all-target Clippy with `-D warnings`, format, source pins, repository links and inventory passed. | [Combined recorder](records/cell-final-combined.json), [raw log](records/cell-final-combined.log), [counts and actual executable hashes](records/summary.json) |
| Same local source and tree | Locked, offline Cargo metadata: **26 workspace members, 175 resolved packages/nodes**. | [Graph recorder](records/cell-final-cargo-graph.json), [raw graph log](records/cell-final-cargo-graph.log) |
| Local concurrent integration `1d627bb1e95a24a185ab5ef638e45d0428614fbf`, tree `cb20b888405423f67088eaa39ce11fbea67b791e` | **196 Python controls**, strict workspace Clippy, format, source pins, inventory and **3,062 repository links** passed. This run did not execute a complete new M09 native suite. | [Integration recorder](records/cell-concurrent-integration.json), [raw log](records/cell-concurrent-integration.log) |

The 220 Python controls are nine suites of 7, 4, 8, 14, 5, 6, 43, 35 and 98
tests. The 44 runtime/handoff controls are already included in those 220.
Likewise, the 12 discovery contention tests and 11 delta tests are included in
the native total. The separate 196-test integration observation is not added to
the frozen source's count as unique test coverage.

The GitHub source object
[`cfa57cd04751427451302b5c10539b3984d7f8db`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/cfa57cd04751427451302b5c10539b3984d7f8db)
has exactly the same tree and parent as the locally tested `f03be250` object;
only commit metadata differs. Both raw commit objects are retained
([local](records/chain-source-local-tested-commit.raw),
[GitHub](records/chain-source-remote-commit.raw)) so their Git object hashes and
common tree can be checked independently. The source object is an explicit
parent of the integration delivered to the existing draft PR. No unrelated
later source is substituted for this fixed runtime pair.

Ordinary Hepta execution-source **V11** pins this exact `cfa57cd` / `155213c`
pair, verifies **53 source files**, and has manifest SHA-256
`a951e866f66b0e251fc5a9f81d02a7f86954d1b3ca8ac483890fcb23a4955647`.
Runtime's separate archive is in
`TrillionniumFoundation/hepta-private-ci/evidence/cell-runtime-binding-20261105`.
Its source, schema and runtime-admission results do not establish model Ready
or FinalUse.

Later preserved upstream work includes production crypto, mining, store,
Growth, owner controls and research cost relations. The frozen tree's native
result and the earlier integration's Clippy result do not qualify those later
changes. Their exact merged source checks, when present, are separately
identified in the final delivery rather than silently inheriting these greens.

## Counterexamples and preparation history

The discovery regressions executed against the old production directory code
with **0 passing / 12 failing**, then passed against the corrected directory.
The initial missing-vector preparation failure remains in
[its original log](records/discovery-red-attempt1-missing-vectors.log).
The tests use actual mutex and SQLite contention under the original request
budget; a durable transaction remains durable after late refusal.

An initial strict Clippy attempt found a duplicate module declaration; the
module arrangement was corrected and the
[second strict attempt](records/workspace-clippy-second.log) passed. The
[original failure](records/workspace-clippy-first.log) is retained, without
changing the lint policy.

A shared target initially selected an old seven-test delta executable. That
observation is explicitly rejected in the
[stale-target receipt](records/stale-target-observation.json), with its
[original output](records/delta-targeted-attempt1-stale-shared-target.log).
After explicit package-cache preparation, the
[fresh 11-test run](records/delta-targeted-fresh.log) passed. The later complete
source-frozen execution records the actual executable hashes; file identity
alone is not treated as proof that a desired binary executed.

`records/` contains completed observations, not reconstructed terminal output.
The failed attempts are not counted as passing gates. [SHA256SUMS](SHA256SUMS)
covers the final archive files; verify it with `sha256sum -c SHA256SUMS` from
this directory.

## Detailed controls

- [Discovery original RED and first targeted observations](../cell-discovery-deadline-20261105/README.md).
- [Delta changes, local cancellation limits and semantic audit](../cell-delta-cancellation-20261105/README.md).
- [Independent runtime import/bootstrap review](../cell-python-runtime-review-20261105/README.md).
- [Ordinary handoff and installed-runtime input contract](../../docs/development/specs/pon/CELL_ORDINARY_HOST_HANDOFF_V2.md).

## Unclosed acceptance gates

TMR1 binds identities and closure; its opaque loader pin does not implement
architecture semantics or expert ABI. TMT1 verifies declared dense tensor
containers and payload bytes; it does not turn CPU views into a device owner.
TCX1 already selects one complete direct base rather than recursive delta
recipes; actual disk work and useful savings across model workloads still need
measurement. Multisource local TCP tests do not supply independent long-term
WAN fairness or genuine administrator diversity. Retention reservations,
funding/task identities and repair journals are not native coin locks, payments,
renewal funding or independent storage custody.

No real model weights, Torch/Transformers runtime or GPU device are supplied in
this execution environment. No former one-shot model campaign is rerun. The
previous 272,189,990-byte cold transfer failure, with zero consumer payload bytes,
is not reclassified as a successful load. Immutable native runtime namespaces,
full ordinary multi-Cell use/FinalUse, device/VRAM ownership, independent 72-hour
WAN operation and real paid renewal retain their separate owners and tests.
