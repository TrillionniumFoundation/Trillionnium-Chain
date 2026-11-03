# Exact local CPU controls and preserved remaining failures

The reviewed **local** source is `b518e0639b56175ce0fc8361d8be3d479ae113e4`, tree `9db0f5b634cd7e64c84faddd605b806359a78d63`. Both original CPU selectors still fail `PUBLIC_MUTATION_CPU_BUDGET`. No budget, held schedule, safety check, source verifier or acceptance denominator was reduced.

## Exact source and behavior

[local-source-history.json](local-source-history.json) records the local `3f3a5c5` → `09d56ed6` → `86ae806b` → `481f6965` → `1cdc8338` → `b518e063` parents, complete trees and changed paths. [local-source.bundle](local-source.bundle), with the published `3f3a5c5` as prerequisite, and [source-series.patch.xz](source-series.patch.xz) preserve the local source history. Canonical provider commits may have different SHAs. Local executions must be attributed to these local commits and exact trees; a tree mapping does not mean a different canonical commit was executed.

`09d56ed6` adds exact unescaped ASCII decoding of freshly read SQL strings, retaining serde for every other input. `86ae806b` adds packet envelope parsing compared against the real original streaming parser and complete errors. `481f6965` uses existing arithmetic in configured Legacy readback while retaining PQ → growth → ordinary root order. `1cdc8338` changes only the chunk representation in the original ASCII predicates.

`b518e063` derives a private one-use non-account leaf projection only after the complete actual input root succeeds. At the original later subset callback, complete grammar and every actual key/canonical value byte are checked against the same immutably borrowed State. Mismatch or retention refusal uses the original path. Tokens never enter persistent entries or a SQL verdict cache. SQL reads, account graphs, conservation and cancellation points keep their original order. Actual hashes and compared rows have separate counters. Persistent limits are unchanged; the operation-local hash projection has a 2 MiB payload bound. Temporary Vec capacity and total RSS are separate.

## Actual original CPU outcomes

| Local source | Legacy branch paid CPU, ns | Standalone Auth paid CPU, ns | Original selector outcomes |
| --- | ---: | ---: | --- |
| `3f3a5c5` (code `12fe5f2`) | 3,673,086,940 | 2,774,009,147 | Both fail |
| `09d56ed6` | 3,141,448,758 | 2,804,676,256 | Both fail |
| `86ae806b` | 3,117,776,531 | 2,795,011,881 | Both fail |
| `1cdc8338` | 1,205,424,040 | 2,744,519,145 | Legacy branch passes; both full selectors fail |
| `b518e063` | 1,150,628,991 | 2,847,231,272 | Legacy branch passes; both full selectors fail |

On `b518e063`, the first selector's Auth branch pays 2,772,250,757 ns, receives 754,669,721 ns refill and ends at −17,581,036 ns credit. Standalone Auth pays 2,847,231,272 ns, receives 762,166,304 ns refill and ends at −85,064,968 ns. The outer dispatch returns normally; the inner native result refuses the mutation. Both exact tests exit 101 and the original named-test reader exits 1.

Standalone Auth advances from nine complete commitments at `1cdc8338` (1,323,448,539 ns) to ten at `b518e063` (960,475,834 ns), now reaching one original activation call. Ten projections compare 21,042 current rows; 35,864 other rows are actually hashed. Full-root work remains 728,172,843 ns/10 calls and persisted-root work 509,077,751 ns/7 calls. Nested stages overlap and must not be summed. Different budget stopping points are not equal-work throughput comparisons. [observations.json](observations.json) derives counters and stage increments from the complete logs.

## Passed controls and execution limits

At local `b518e063`: protocol arithmetic 8/8, M06 projection 4/4, original encoder 7/7, configured full-root 7/7 and canonical byte-budget 1/1 pass. Strict Node/M06/protocol Clippy passes. All 14 other selected Node command groups pass: large-State current-input controls, parser/SQL equivalence, current SQL damage, trigger rollback, reorg tail, post-write readback, prepared History changes and reactor lifetime. The parser prefix retains its one explicitly ignored CPU observation.

The normal workflow changes only the expected full-root count 5 → 7, retaining the original five and adding `configured_root_rechecks_original_grammar_context_and_current_values` and `configured_root_preserves_real_pq_and_growth_validation_on_warm_arithmetic`.

Formatting, source pins/negative controls, project-boundary controls and links pass. The committed-clean repository check reports 26 workspace packages, 1,062 Rust files and 1,658 local links. The exact locked/offline Linux x86_64 Cargo graph passes. The separate unfiltered offline graph fails on the uncached `sqlite-wasm-rs 0.5.5`; that original failure is retained.

The first `b518e063` build succeeds and its ELF is hashed/listed. The target directory later becomes unavailable for an unknown reason. Two startup guards fail before any test executes. A clean same-source rebuild succeeds in 536.034124605 seconds and reproduces ELF SHA-256 `d5b31f23b0936825ea34fbd677e3fe11d7fd102d3f1c1c523ef747c08192a99f`. A regular-file copy is preserved and hash-checked immediately. All 16 command groups execute the original Cargo artifact path from the original package cwd, with identical ELF hashes before and after.

These are local Linux x86_64, default-feature observations: Node opt-level 3, debug assertions and overflow checks enabled. Host exclusivity is not claimed. They are not a new complete workspace, all-features or ARM run. Earlier hosted failures remain historical failures until separately validated new source is measured.

## Preserved bytes and other remaining gates

Run `python3 verify_receipts.py` here. It verifies archive members, command/log hashes, complete source identities and actual failures without running embedded commands. [manifest.json](manifest.json) inventories [raw-observations.zip](raw-observations.zip). Compiled binaries and temporary Rust snippets are excluded. The source patch is losslessly XZ-compressed: decompression recovers the original git-format-patch bytes. The first packaging whitespace check rejected literal mbox context/signature whitespace; [publication-precommit-validation.zip](publication-precommit-validation.zip) preserves that failure and the preceding passing checks. Compression preserves the patch without weakening the whitespace check. [encoder-review.zip](encoder-review.zip) preserves the separate 30-file review, including the development typo caught by tests.

The [original DAG evidence](../pon-pq-dag-parent-refusal-20261103/README.md) retains both lanes, all 18 samples per lane and the actual `PUBLIC_HOST_KERNEL_PARENT` refusals. It locates the fixed-Host prerequisite; without a kernel-parent snapshot it does not establish a particular filesystem cause. Its original runtime gate remains failed.

The [V5 terminal evidence](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/2f0ad551f63be3acc0580997f5867597f3b1cef4/evidence/pq-full-followup-20261103/README.md) records installation/startup/History/growth controls passing and five native process exits of zero, followed by independent `CONFIRMATION_TARGET` failure: seven blocks submit in 1.879015810 seconds; two History pages download, one independently replays, then `PUBLIC_REQUEST_DEADLINE`. Retaining this evidence runs no new workload.

Whole-chain PQ, PN0-PN6, independent WAN operation and production activation remain HOLD. These component improvements do not close the still-failed original runtime or CPU gates.
