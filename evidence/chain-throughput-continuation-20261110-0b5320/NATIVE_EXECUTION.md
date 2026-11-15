# First native component observations and exact fixture correction

## Scope

These are actual Linux x86-64 native component observations, separate from the
original exclusive-History service campaign. They use Rust/Cargo 1.95.0, locked
Cargo inputs and the unchanged release profile. Both local source arms use two
build workers, incremental compilation disabled, a two-CPU/16-GiB outer process
limit and single-threaded test invocations. The hosted four-source driver uses
its own one-build-worker policy; these local runs are not relabeled as that
workflow or as execution of a later delivery commit.

The [selected raw observations](native-first-observations.tar.gz) and
[member manifest](native-first-observations-manifest.json) preserve the original
job scripts, process rows, available source receipts, raw designated failures,
and the clean `6de2d420` source checks. The archive does not contain the compiled
executables or every full-suite stream, and does not claim to be a complete
binary packet. Native binaries were retained by the original runtime; the
following hashes identify the actual recorded pre-test executables.

| Subject | Commit | Release libtest bytes | SHA-256 |
| --- | --- | ---: | --- |
| Fixed reconciliation implementation | `5ec9b4490fbfd22df4527e3b75ec74d6986572cf` | 102,248,176 | `2b623b3c4b55edaa2b6c1c11c9df7790053c64be52d3b161594aeaeec1c719af` |
| Old reconciliation plus identical new tests | `ae657e262278ae4a058220f66a6a0495721eb9ad` | 102,244,104 | `c90aebb3e0a18ca5a76e4dedfaee9b1662590c5767c140a0bcae36673186ccfe` |

## Fixed implementation: actual 20/21 targeted result

The `5ec9b449` release build completed and ran all 21 named controls. Twenty
passed: the three original History debt/refill controls, all five writer-handoff
controls, all four registered-preparation controls, both new retained-scan
controls, and six of the seven ordinary-pool controls. The previously failed
History Continue case passed on this source. Its original-account, complete
import, packet and cold-reopen assertions remain present in the native test.

The remaining positive control,
`mining::pool_run_control_tests::pool_run_completed_packet_and_reconcile_failure_remain_durable`,
exited 101. Its exact panic was at `pool_run_control_tests.rs:510:74` when the
cold `Node::open` returned `SCHEMA`. The preceding packet-byte, nonce and
admitted/activated assertions in the reached subcase had passed. The raw log
does not label the loop subcase; the source diagnosis below explains the
deterministic fixture condition rather than inventing such an observation.

The original source-after-targeted check passed and the full retained library
invocation then started. The original pool integration/CLI stage remains part
of the ongoing job; their eventual results require their own completed receipts.
This document does not turn a targeted pass into
a full-library, integration, strict-Clippy or campaign pass.

## Old reconciliation: two actual designated failures

Both unchanged `ae657e26` native scan controls ran and exited 101, without a
wrapper timeout, at `pool_reconcile_control_tests.rs:181:5`. Each printed the
exact named assertion `POOL_RUN_RECONCILIATION_ROWS_IGNORED_ORIGINAL_CONTROL:
pool-batch`, with `left: 6` and `right: 2`. Source-before and source-after
receipts match the pinned commit and tree.

The original ad hoc wrapper's whitespace regex was overescaped, so its own
summary remained false and its process exited 1. That failed wrapper outcome
is preserved. A [separate readback](before-ae-native-transcript-readback.json)
loads the frozen `6de2d420` validator (SHA-256
`6acf7c2db61a4af3ee346ce497cc1a46a4f801a68656d13d7d4f995e0931259c`), checks
the recorded native exits and stream hashes, and matches both original
transcripts. It requires one exact test-thread panic, the exact source/line,
marker and six-versus-two values. It does not change the earlier wrapper result.

Each old test stops at the first Legacy/initial-batch case. These are two
observed negative test processes, not eight separately observed old-case
failures. Each passing fixed scan control completes its four declared cases.

## Fixture repair and revised old-pool subject

The durability fixture deliberately creates `pool_control_count` and an update
trigger to make final pool reconciliation fail after native block activation.
Its cleanup dropped the trigger but left the auxiliary table. Production
`store::schema` includes every non-internal SQLite schema object, and cold
`Node::open` requires the exact shipped schema. Refusing the leftover table is
the intended production behavior.

Test-only commit `36f803033ca342a966fe6a8c6d5bf8b68355b5b9` changes the cleanup
string to drop both the trigger and its counter table. It changes no production
code, packet/nonce/state/reopen assertion, failure injection threshold or
original run deadline. Corrected native success requires a fresh execution;
the `5ec9b449` result remains 20/21.

The [source-pair receipt](pool-before-v2-source.json) binds the same corrected
test bytes to old-production subject
`84e68b4f7a9b2f48f9c47ed05c9a44229d186e30`, tree
`4e85966ae98b0081fcc2f9d0e8af313bc4f7d005`. It is a test-only child of
`db93026b9314bfd8bc4350945036998f1b7d34aa`; its production bytes are unchanged.
The test Git blob is `e2c8f8224270449587907a0a5607efaab147eb70`, SHA-256
`ca6009352e67fe8fe20719102a95b3714b8d9946e30d3cc53266b621df9c1d2e`.
The five designated old-pool negative assertion sites did not move.

The workflow now explicitly uses `pool-before-v2` and refuses the original
unversioned mode or old subject under the V2 label. Old budget and old scan
subjects are unchanged. The fixed roster remains 21 library controls plus the
original ten integration tests and actual CLI.

## Earlier compilation failure and source checks

The first desktop release compilation reached the node library, then LLVM
reported `No space left on device`. No native test ran in that attempt. Its
remaining on-disk stderr ends at 4,096 bytes, SHA-256
`e0022276452e5cf5e216237a0e4f59bb3cc76272941140add238fd1ecb1a2519`.
The supervisor remained `unknown/finalizing` without a confirmed terminal
receipt; no clean exit was inferred. Recovery discarded only this task's
regenerable failed compiler cache, verified no active owned process, and checked
executable tmpfs capacity before the fresh build. The larger concurrent change
in shared free space is not attributed to that cleanup.

The archived clean `6de2d420` checks passed ten commands, including source
verification before and after, project preflight, 39 reader tests, the original
source-map/corpus inspectors, inventory, CI contract and repository links.
These are source and reader observations. The revised V2 reader also passed its
39 controls, including refusal of an incorrectly relabeled old-pool source.

Complete original-budget confirmation, sustained TPS, WAN performance, complete
history bounds and production activation remain unqualified.
