# Explicit complete-frame History journal publication repair

The final frozen native run completed **12 passed, 0 failed, 1 ignored helper**
in **171.219 seconds**, inside the original 600-second budget. The selected helper
is an ignored parent entry point; the guardian actually executes it with the
exact selector and `--ignored` in the owned subprocesses. It is not a skipped
acceptance control. The native source and executable hashes were equal before
and after the run. The two preceding failed native runs remain retained.

This is a tested repair component, **not closure of whole History P0**. In
particular, an unclean exit with a known last settlement but a still-open epoch,
startup/close windows, incomplete frames and signed multistep reorganization
continuation remain open. No production gate, signed V6 namespace, W1 rule or
original resource allowance was weakened.

The actual local verdict and independent readback are in
[final-validation.json](final-validation.json) and [summary.json](summary.json).
The [archive manifest](manifest.json) binds every retained raw member and part.
The [protocol contract](../../docs/protocol/pon-nakamoto-v1/details/HISTORY_JOURNAL_PUBLICATION_REPAIR_V1.md)
describes the separate authorization and exact-byte algorithm.

## What changed

The new `ProtectedHistoryJournalPublicationV1Input::load` and
`repair_history_journal_publication_v1` API require a protected, digest-pinned
local input and two distinct pinned authority signatures. Their fresh domain is
`TRNM-HISTORY-JOURNAL-PUBLICATION-REPAIR-V1`. It is separate from the unchanged
V6 recovery domain, original events and stored native schema.

The outside authorities select the exact acknowledged prefix, next published
anchor, complete frame length and digest, identity, and finite validity window.
The protected input's `outside_latest_anchor` must equal that signed new anchor.
Neither a disk suffix nor the guardian's candidate barrier becomes an approved
latest anchor merely by being read. Fixture signatures use disclosed deterministic
test authorities; they are not external Registry2 admission.

Under the existing owner lock, the repair replays the complete canonical prefix
and candidate through the original state machine. Original operation signatures,
chain links, identity, nonce and lifetime ceilings still have to pass. It accepts
one complete pending file, its canonical final name, or the two names as the
same inode with exactly two links. It fsyncs the existing bytes, publishes the
final name without replacement, fsyncs the directory, removes only that verified
temporary alias, fsyncs again, and rereads the exact final bytes with one link.

The API does not create a journal or its owner lock, reconstruct an incomplete
frame, discard a conflicting suffix, manufacture a native effect, settle unknown
CPU, refund a predebit, create an epoch, or authorize a reorganization. Repeating
the same still-valid request at its exact final frontier creates no new event.
After the journal advances, the old request fails without rewinding it.

The existing normal opener remains strict. Publication repair is followed by
the original separately authorized V6 unknown-process reconciliation and a fresh
startup claim; repair success alone cannot make an unresolved operation usable.

## Executed durable controls

Five new original-append cut points each execute a real owned native child,
SIGKILL, wait4, externally authorized repair, unchanged V6 reconciliation,
fresh-process startup, full original W1, two joined M06 workers, activation,
paid close and cold readback:

| Original append cut | Exact on-disk shape inspected and repaired |
| --- | --- |
| Complete pending-file fsync | One complete pending file |
| Final-name hard link | Pending and final names share one inode |
| Final-name directory fsync | Same two-link shape after the directory sync |
| Pending-name unlink | Canonical final file alone |
| Final directory fsync, before local apply/return | Durable final file ahead of the old outside anchor |

The pending-file case also kills **two fresh administrative repair processes**:
one immediately after the new final-name link and one after removing the pending
alias. Both have actual SIGKILL/wait4 records. The same authorization completes
and retries idempotently afterward. These administrative processes start no
native operation or CPU epoch and produce no V6 original-process closure receipt.

The two existing native V6 crash controls also pass: actual registered-worker
interruption and activation COMMIT before settlement. There are therefore seven
native-epoch crash controls plus two administrative repair crash controls, with
their distinct roles preserved in the raw records. The other original controls
retain actual two-worker cancellation, late persistence failure, validation facts
and unsigned/delegated-authority refusals.

Independent readback checks every original journal record's SHA-256, original
unknown receipt split, separately authorized reconciliation, exact retained frame
bytes, zero initial credit after fresh startup, two spawned/started/finished/known
workers, positive scoped-worker CPU, owner-plus-worker CPU equality, final marker
count and cold journal state.

| Cases | Final used operations | Known settlements | Unknown reconciliations | Lifetime CPU allowance still spent | Final markers |
| --- | ---: | ---: | ---: | ---: | ---: |
| Five publication cuts and registered-worker crash | 6 | 5 | 1 | 24,000,000,000 ns | 2 |
| Activation-COMMIT crash followed by the next activation | 7 | 6 | 1 | 28,000,000,000 ns | 4 |

These spent values are **full allowance predebits**, not measured CPU runtimes.
Exact actual process and scoped-thread counter observations are retained in the
summary and raw artifacts. They do not qualify physical host cost.

Before repair/recovery, the publication cases retain two used operations,
8,000,000,000 ns prepaid CPU, one known settlement and the original unresolved
Intent. Publication alone leaves its unknown CPU split unchanged.

## Refusal and retry evidence

Each of the five publication cases refuses the old signature domain, the old
outside anchor, a wrong prefix, a wrong frame size and expired authorization.
It verifies ordinary old-anchor open refusal, successful exact repair, idempotent
retry, and rejection of that old repair request after subsequent advancement.

The separate native refusal test executes **14 cases**, checking that file names,
content hashes and link counts are unchanged on refusal:

- Partial bytes, same-length tampering and noncanonical serialization.
- An invalid original signature, an original lifetime-ceiling violation, wrong
  previous chain digest and wrong chain identity, despite a valid repair signature.
- An extra tail, unexpected additional hard link, two distinct inodes with equal
  bytes, and a final-name symlink.
- Missing prefix, unsafe file mode and an actually held owner lock.

The extra-link execution is a pending name plus an unexpected alias, with
`nlink=2` where a single selected name requires one link. It is **not** an executed
three-link fixture. The production code separately requires exact link counts of
one or two according to the selected shape; that static check is not relabeled as
an additional executed control.

## Frozen source, toolchain and terminal outcomes

The worktree starts from preserved local base
`2e325e78e508bfe72d342d210a27b17ed53e2d24` on
`fix/chain-history-publication-repair-20261027`. No previous delivered head was
amended. There are 1,611 materialized non-evidence inputs in the actual source map,
whose SHA-256 is
`d4352313c0ffc013167519fdfbaaf3ef649434c1078002c0813ca8fec5446840`.
The exact map is retained as `source-after-build.json` in the raw archive.

Final executable SHA-256:
`73a4ae3107888b7997ce2de62a8b1ca6c5492f532e5bdeb6db77ffc8aff49e9b`.
It is also retained locally, separately from the shared target, as
`/tmp/pon-history-publication-final-elf-20261027` (50,458,600 bytes).

The actual compiler is Rust/Cargo 1.95.0 on x86_64 Linux. The unchanged original
25-package graph uses lockfile SHA-256
`6efe75ea2f9293e3f0d003d6896e89e795c1ef021b9e15179db4d2e37317b864`.
Builds use one job, no incremental compilation, the original test optimization
level 3, debug information 0, and enabled debug assertions and overflow checks.
The existing target is reused; it is not copied or replaced with a reduced graph.

| Actual attempt | Result | Wall time | Original budget / qualification |
| --- | --- | ---: | --- |
| Build 01, before the explicit-match lint cleanup | PASS compilation; no native test execution | 950.459 s | 1,800 s |
| Strict Clippy 01 | PASS | 176.336 s | 900 s; M01/Node, all targets/features, warnings denied |
| Build 02 | PASS compilation | 1,057.759 s | 1,800 s |
| Native 01 | **FAIL: 11 passed, 1 failed, 1 ignored** | 167.461 s | 600 s; final-name JSON publication race |
| Strict Clippy 02, after atomic guardian publication | PASS | 58.857 s | Same 900 s and full strict command |
| Build 03 | PASS compilation | 813.148 s | Same 1,800 s and profile |
| Native 02 | **FAIL: 11 passed, 1 failed, 1 ignored** | 168.434 s | 600 s; complete parent graph unavailable |
| Native 03, same ELF/source as Native 02 | **PASS: 12 passed, 0 failed, 1 ignored** | 171.219 s | Same 600 s, 13 selectors, four-snapshot rule |

The initial known `err().expect()` lint was found by source review while Build 01
was already running. That runner had no safe external cancellation request path;
it was allowed to reach its real terminal before the minimal explicit-match
change. No pre-cleanup Clippy pass or failure is invented. The original executable,
producer runner, source snapshot and receipt are retained. A later runner adds
an explicit owned cancellation-file path without changing budgets.

Native 01 caught a real observation-publication race: the guardian created the
final JSON pathname before filling it, while Rust used existence as its read
signal. The correction writes and fsyncs a private pending file, links the final
name without replacement, and fsyncs/removes the temporary name. Two deterministic
Python regressions prove that the final name is absent during an incomplete write
and an existing observation is never replaced. The three original actual
owned-process observer tests remain; all five pass.

Native 02 correctly retained UNKNOWN when its four complete-parent-graph attempts
contained a missing PID and then three different complete graphs. Its owned
child was actually killed and reaped; **no closed-process receipt was created**.
Native 03 used an independently created fixture and the identical ELF/source,
selectors, assertions, resource limits and four-snapshot rule. Collaborators were
asked to reduce local process starts, and this agent stopped intermediate local
exec probes. This is not proof of global host quiescence or closure of the failed
Native 02 fixture. Its refusal remains retained rather than reclassified.

Other completed controls are 34 source-integrity negatives, 16 project-boundary
tests, final formatting, the 25-package locked metadata graph and refreshed
distributed-source inventory. The repository-wide local link check remains
**NOT PASS** because this inherited materialization lacks
`evidence/pon-v1/README.md`; its raw failure and materialization inventory are
retained. This increment does not claim a whole-Node-suite pass or replace the
earlier full-suite/capacity failures in the
[predecessor evidence](../pon-history-error-provenance-20261027/README.md).

## Retained evidence and reconstruction

The archive has 1,534 members and is split into 54 ordered 65,536-byte parts
(the last is shorter). Concatenating `raw-parts/part-*.bin` reconstructs
`history-publication-repair-raw.tar.gz`, 3,484,741 bytes, SHA-256
`8db7915bd050cd1a49c699a59c828288d244caf02bc815c4ea61fb1349c03079`.
Every reconstructed member was read back and matched its declared length and
SHA-256, then compared again with the retained original file.

Raw members include all three build and native attempts, both strict Clippy
attempts, original producer scripts, full logs, budget/resource samples, source
maps, each actual process/store fixture, original failure observations and the
independent summary program. Setup formatting failures and the temporary platform
interruption are also disclosed; neither is a passing test.

The 21 retained checkpoints are verified against the public fixture's exact
576-by-576 BF16 all-one tensor relation; model tiles are the public constant bytes.
They are synthetic codec fixtures, not Hepta trained weights, a real neural task,
an actual model-forward qualification or measured model efficacy. Archive copies
do not preserve live inode identity; physical link assertions are evidence from
the actual native execution, not from later archive extraction.

The native source snapshot is commit `25e6e6e71c6856962348a892835f176a38beb4ed` with
tree `c223ed4a7b5d19adc4fde9b3e0c533efdd9b7458`. The CI selector update is intentionally a separate successor
to that native source snapshot. It retains the original six V6 selectors, adds all six new
selectors, and updates the actual Python observer count to five. The exact
[YAML-only non-evidence source mapping](ci-successor-validation.json) verifies
that all compiled Rust and guardian bytes are unchanged. No local native
execution is claimed merely because YAML changes. Remote exact-head and
prospective-merge CI remain separate required observations.

## Boundaries still open

Complete-frame publication is qualified here only at the named validation-Intent
and administrative repair cuts. This does not qualify every journal event or
every crash point. An unclean exit after a known last settlement may leave
`pending=None` and `epoch=Some`; existing recovery requires a pending scope while
fresh Startup requires no live epoch. This distinct durable epoch-closure path
is not implemented by publication repair.

Startup/clean-close crashes, torn or missing frame reconstruction, SQLite internal
write cuts, and signed bounded multistep reorganization continuation also remain
open. The existing activation gate still refuses a pending reorg rather than
claiming its continuation completed. General historical subprocess adoption,
physical power loss, physical cost, external Registry2 truth, a public Host
campaign, and an end-to-end PQ or real neural product loop are outside this
component's acceptance. **Whole History P0 and production qualification remain
false.**
