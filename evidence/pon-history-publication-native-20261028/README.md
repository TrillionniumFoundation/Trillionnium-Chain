# History publication and settled-epoch native continuation

**The seven new recovery windows passed on the final local runtime. The complete
final native batch failed: 14 passed, 1 failed, 1 ignored. Whole History P0 remains
open.** This directory preserves successful scoped observations and complete failed
batches separately. No cross-batch combination is a 15/15 acceptance.

## Exact source and staged provenance

PR #518 base is `44601b92f786613194a6098158abe663296d4f3e`. The independent local
candidate retains these reviewable stages:

| Commit | Scope |
| --- | --- |
| `2e325e78e508bfe72d342d210a27b17ed53e2d24` | Inherited owner/error accounting continuation and its prior evidence. |
| `6b40375d08265aa19e570756fc67cdffc163fb5e` | Frozen inherited hardlink publication repair, originally uncommitted in the prior workspace. |
| `a3a651cdc6b5d51302fdce1ade0e15be7b2ce474` | This turn's new settled-epoch namespace, conservative debit, independent pins, expiry semantics and pinned publication wrapper. |
| `8d7741028eb650f0600e61fcab46ff3d14b50767` | Final locally executed runtime: atomic guardian JSON publication and deterministic link-boundary control. |
| `72b7cb10e28f07343b7a0fc96072975906ceae85` | CI-only followup requiring a fresh exact-source hosted release build and complete native suite. |

The tested runtime tree is `da2d7c4ca9358f588c4fa8a2909c2be5b59e4739`; the CI-only
tree is `053cd7cbe9e4cf2824387af624431b19611d3b6c`. All runtime and guardian source
blobs are unchanged between those two commits. Evidence packaging is committed
afterward, without relabeling the measured runtime or binary as the later head.
[The source manifest](publication-source-manifest.json) records all changed source
paths and phase ancestry. The final publication manifest supplied beside the
checkout covers every changed path, including this evidence, from the #518 base.

The locally executed binary has SHA-256
`136bbeb0b474dc9d0bcb3c254ab3bf21d47666f4fb4e04957752f69ea905729b`.
[Its compressed original bytes, split into five ordered exact ranges](native-binary-runtime-8d774102-parts.json)
and [binary metadata/readback](native-binary-runtime-8d774102.json) are retained.
The publication transport rejected the unmodified gzip above its 16 MiB request
limit; [the original error](publication-body-limit-failure.json) is preserved.
This packaging change does not rerun or change the tested runtime. The original
20,052,436-byte gzip and decompressed 96,678,560-byte ELF were both reconstructed
and independently hashed; see the [transport readback](required-gates/publication-parts-readback.json).

Reconstruct the exact gzip from this directory, then compare its SHA-256 with
the parts manifest before decompressing:

~~~sh
cat native-binary-runtime-8d774102.gz.part-00{0,1,2,3,4}.bin > native-binary-runtime-8d774102.gz
sha256sum native-binary-runtime-8d774102.gz
~~~

The build used package-local opt-level 0 to fit the local resource envelope;
all measured durations are test observations, **not performance qualification**.

The fixture identity's `source_commit` remains
`1116ae390e4ed408ab0899e13aec5d1f90f2192c`. That fixture string is not the actual
compiled-source commit. The build receipt and raw source readback bind this
execution to `8d774102...`; protected-input equality checks prove independent
source/binary pin enforcement within the disclosed fixture trust model. This is
not an external production builder or Registry2 attestation.

## What the new recovery operation establishes

The [protocol note](../../docs/protocol/pon-nakamoto-v1/details/SETTLED_EPOCH_RECOVERY_V1.md)
defines the new signature domain `TRNM-HISTORY-SETTLED-EPOCH-RECOVERY-V1` and record
namespace `restricted-history-settled-epoch-record-v1`. Both authority signatures,
exact closed-process bytes, independently supplied source/executable pins, the old
epoch, budget, last known settlement, native frontier, external journal anchor,
fresh reconciliation ID and increasing nonce are required.

Recovery applies only when the dead epoch's last operation already has a durable
known settlement and there is no pending operation. It preserves all old frame
bytes, spends one new signed operation allowance, and conservatively charges the
**whole dead process CPU upper bound again** within the original lifetime ceiling.
It does not claim an exact residual split, refund old predebits, fabricate a clean
close, turn an unknown outcome into a known settlement, or repeat the native effect.

The fresh domain may close an epoch after the old budget expires. It grants no
Startup or effect authority: the original expiry check still rejects running work
until a separately signed ordinary Budget renewal. Expired new authorization,
excess allowance, exhausted original ceiling and reused nonce/operation ID remain
refusals.

Journal, native directory, owner lock, SQLite file, owner marker and read-only
transaction stay held through the append. Before append, held-versus-visible file
identities and marker bytes are checked again. Pending reorganization is refused.
The generic publication API rejects this new record; only the pinned wrapper may
publish its exact original complete frame. It authenticates the original event at
the original `frame.at_ns` and checks fresh publication authority at current time.
The original signed bytes, closed-process bytes, frame hash and independent pins
must match. Guards remain held through link/unlink/fsync/readback.

## Same-batch successful new windows

[The seven-window readback](epoch-window-summary.json) validates these cases from
`native-03` only:

- Settled activation killed before clean close, then conservative reconciliation.
- Actual old-budget expiry, fresh closure, rejection of old running authority,
  separate ordinary renewal and restart.
- New recovery-record publication after complete-file fsync, after hardlink,
  after final-directory fsync, after pending unlink and after durable publication.

The five publication cases preserve the exact frame and exercise idempotent retry.
The complete-file case also waits until the original event authorization has
actually expired before a fresh publication repair. Expired current publication
authority, a wrong independent executable pin and changed original signed bytes
are rejected. Administrative repair processes are actually killed after link and
unlink, and the next process retries the exact publication.

Across these seven cases there are **7 original native SIGKILL/wait4 closures and
7 administrative SIGKILL/wait4 observations**. Administrative receipts are never
used as the original native death receipt. Every successful continuation starts
with zero stored CPU credit, performs full W1 validation with two joined M06
workers, activates again, pays for close, and cold-reopens the journal/store.

Each cold journal reports 8 used operations, 7 known settlements, exactly one new
settled-epoch reconciliation, zero unknown-prepaid reconciliations, no pending
operation or live epoch, and 32,000,000,000 ns in signed CPU predebits. The original
12,000,000,000 ns remains spent; the new conservative closure adds 4,000,000,000 ns
before subsequent work. All original journal-frame hashes are unchanged. The
next native frontier has generation 2 and four effect markers.

Negative controls include missing task signature, old signature domain, wrong
independent source pin, re-signed wrong executable, insufficient whole-process
allowance, wrong budget/settlement/frontier, nonce or ID reuse, lifetime overdraft,
wrong operation count, missing owner lock without recreation, new-event relabeling
as an old V6 record and generic publication bypass. These are actual native calls
with retained error records, not just JSON-shape assertions.

## Full batches and failures remain failures

| Observation | Actual terminal | Reason / scope |
| --- | --- | --- |
| `native-initial` | One intermediate case passed | Earlier incomplete source; not final qualification. |
| `native-01`, runtime `a3a651...` | 14 passed / 1 failed / 1 ignored; 284.263 s | Guardian exposed the final JSON filename before writing the complete bytes. The reader observed EOF. |
| `native-02`, runtime `8d7741...` | 14 / 1 / 1; 337.055 s | New final-synced administrative guardian could not establish two equal complete parent graphs in the original maximum four snapshots. Cleanup used actual SIGKILL/wait4; no death receipt was fabricated. |
| `native-03`, same final binary | 14 / 1 / 1; 390.839 s | All seven new windows passed. An older `publication-intent-final-synced` case refused its resumed Startup for owner CPU capacity. |
| Isolated final-synced recheck, same binary | Failed in 10.109 s | Three complete but differing process graphs, then a missing status row. It did not reach resumed Startup, so it is inconclusive about that capacity failure. |

Every full native batch retained the original 600-second outer bound, 2-second
stored burst, 4-second signed operation allowance, zero-credit epoch start and
maximum four parent-graph snapshots. The single isolated recheck used its separately
recorded 150-second outer bound; it changed none of the runtime or observer rules.
No second isolated retry or budget increase was used to manufacture success.

The actual JSON race was fixed by exclusively creating a private temporary file,
writing and fsyncing all bytes, create-only hardlinking the final name, fsyncing
the directory, unlinking the temporary alias and fsyncing again. Existing final
names are never replaced. A deterministic barrier test verifies final-name absence
before link, complete bytes after link, correct links/mode, refused overwrite and
retained failed temporary file. It does not poll away parse errors.

### Startup CPU failure and next engineering cut

[The persisted CPU observation](startup-capacity-observation.json) reports
2,087,314,423 ns owner/total CPU, 2,086,987,006 ns live-paid CPU and 327,417 ns
residual. `live_refused=true`, accounting is available, and there are no workers.
The original local burst is 2,000,000,000 ns; the signed operation ceiling remains
4,000,000,000 ns. The reopened native fixture has one genesis block, no effect
markers, ten KV rows, one 3,479-byte snapshot and no reorg or peer queues.

The paid Startup calls `Settings::development_with_operator_checkpoint_tile`,
which fully replays checkpoint material through `prepare`. `Node::open_selected`
then calls `Settings::replay_checkpoint_tile_material`, replaying those materials
again. It also reads active state before and after `recover`; History V6 recovery
returns the current frontier. The material replay's inner progress callback checks
a 90-second wall limit but does not propagate the History owner CPU/cancellation
checkpoint. `HeldCatalog::ready` checks metadata; it is not a repeated full-byte hash.
The new settled-epoch API is not called in this failing older case.

These are source call-chain facts. There are no per-function CPU samples, so this
evidence cannot assign a fraction of 2.087 seconds to each stage or claim that all
repeated work is removable. A separate next candidate must propagate internal
CPU/cancel checkpoints and prove any same-Startup sealed-material reuse while
retaining second-boundary identity, content hash, exact inputs, authority and
frontier/generation checks. This frozen runtime makes no such optimization.

## Required checks and independent hosted gate

The final local build passed with unchanged source and binary hash. Strict Clippy
for `trnm-pon-node --lib --tests -- -D warnings` passed on the final runtime.
The final four guardian tests, 34 source-integrity negatives and 38 evidence-source
negatives passed. The earlier guardian attempt that failed under process churn and
the earlier Clippy failure remain in the evidence. Final package formatting and
locked Cargo graph passed; the graph still has 25 workspace packages. Four separate
CI-runner controls passed on the CI-only followup, including real owned-child cleanup
and exception-path wait4; they are not native History acceptance tests.

Canonical whole-tree local source verification and repository Markdown links
remain failed because this inherited partial checkout lacks historical evidence
files and marks those entries skip-worktree. Their failing logs are preserved; the
checker was not weakened. Narrow exact raw-blob readback passed for all 1,614
tracked non-evidence files at the measured runtime and all 1,617 at the CI-only
followup. Those checks are not substitutes for a complete hosted checkout.

The new workflow is
`.github/workflows/pon-history-epoch-v1-native.yml`, job `history-native`.
It triggers for relevant PR source changes or an explicit 40-character dispatch
SHA, checks out that exact candidate, verifies every tracked byte, builds one
same-source release test binary with Rust 1.95.0, and requires the exact test roster.
The roster has **16 entries: 15 tests plus one ignored process-child helper**.
The real process tests invoke that helper with `--exact --ignored`, protected fixture
inputs and an independently owning guardian. Its presence is not counted as a
sixteenth passed test, and ignoring one of the real fifteen is refused.

The workflow runs all fifteen in one serial native invocation with the original
600-second full-suite bound. It requires exactly 15 passed, 0 failed, 1 ignored and
one terminal summary; missing, duplicated or substituted test names are refused.
The 600-second bound comes from the original local full-suite runner and was not
increased for hosting. The new build owner has a separate 2,400-second build bound,
1 GiB available-disk floor and 64 MiB log limit. Job timeout is 75 minutes, including
compiler installation/build and artifact collection. Runtime CPU and snapshot
limits remain unchanged. The bounded owner pins its leader with WNOWAIT through
the last owned-group signal, then records actual wait4; it does not attest all
escaped sessions or every descendant's terminal state. Native death witnesses
remain independently checked by the original fixture guardians.

Complete logs, source records, native fixtures and terminal state upload even on
failure. A skipped or failed native step does not become a successful observation.
**The new hosted workflow has not executed in this local evidence.** The older
recent-batch workflow only checks part of History; its observer expectation was
updated from three to four tests, and unrelated PQ source pins were not changed.

## Complete raw observations

Every archive has a companion `-members.json` with each member's original SHA-256,
size, type, permission bits, uid/gid, nanosecond mtime, original inode/link count and
symlink target. Tar stores permissions, ownership, mtime and hardlink/symlink
relationships. Archives were read back member by member, and original inventories
were unchanged during packaging. Negative-test symlinks are retained intentionally;
extract into an isolated test directory. Original fixture bytes were not rewritten.

| Archive | Bytes | Meaning |
| --- | ---: | --- |
| [Initial intermediate](raw-native-initial-intermediate.tar.gz) | 94,848 | Early incomplete-source observation. |
| [First full failure](raw-native-attempt-04-failed.tar.gz) | 813,412 | Entire `native-01`, including the publication race. |
| [Second full failure](raw-native-attempt-05-failed.tar.gz) | 1,015,713 | Entire `native-02`, including strict graph-snapshot refusal. |
| [Final full failure](raw-native-attempt-06-failed.tar.gz) | 1,226,431 | Entire `native-03`, including the 2.087-second Startup refusal. |
| [Isolated failure](raw-isolated-final-synced-failed.tar.gz) | 44,007 | The recheck that never reached resumed Startup. |
| [Seven scoped successes](raw-settled-seven-window-success.tar.gz) | 706,365 | Exact seven new case directories from `native-03`; not whole-batch acceptance. |

All keys, signed inputs, SQLite databases and material files in these packages are
fresh test fixtures with disclosed local test seeds, not production credentials or
deployed data. Raw local directories are also retained outside the checkout after
archive verification; the archives preserve their original member names and
metadata. A later observation found same-byte, different-inode copies at the original
untracked paths again; their cause was not established. The publication uses an explicit file list that excludes
those duplicate directories, the earlier draft and caches. Current workspace inode
numbers are not relabeled as original measurement metadata. Build logs, source
snapshots, failed attempts, successful gate receipts and the measured binary are
retained separately in this directory.

Two explicit own-target cache retirements were permitted only after filtered,
read-only process-reference audits found no candidate references and no unreadable
PIDs. Their candidate lists and terminals are retained. They deleted rebuildable
owned intermediates only and preserved the measured binary. No other task's files
or processes were altered.

## Remaining blockers

Whole History P0 remains unclosed: one complete exact-source native suite has not
passed, local Startup capacity exceeded the original burst, and strict parent-graph
observation can refuse under host churn. Pending Startup/Close debt, authorized
multistep reorg continuation, recovery when the old lifetime ceiling cannot fund
the conservative extra debit, arbitrary subprocess-tree adoption, partial-frame
reconstruction, physical power loss and full journal/store capacity qualification
remain separate requirements. The 4,096-frame bound is still enforced; there is no
claim of long-lived capacity or compaction. No operational path was permanently
disabled to produce the successful new cases, and no production activation,
protected-branch merge or whole-P0 acceptance is authorized by this evidence.
