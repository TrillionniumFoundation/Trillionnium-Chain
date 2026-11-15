# History original-owner next candidate — 2026-10-28

**WP2B remains HOLD: both original large-State service gates still fail, crash
debt recovery is incomplete, and the corrected hosted placement is unmeasured.** This isolated
candidate preserves pure PoN, the complete W1 relation, the original two-second
CPU burst, 0.25 CPU-second/second refill, 100 ms start principal, all original
business deadlines and the 8 MiB detached-snapshot ceiling.

## Provenance

This branch starts at `ac469237422d43805845e8b9a6839ad14e1028e7`. The selected
M06/History source inputs were recovered byte-for-byte from the retained measured
ELF SHA-256 `56ac4ec3eb2f75bf02146db9d02c4ce41138d7f55c588626000609aa8e7a58cc`.
Its original Git commit objects and old raw streams remain unavailable. This is
new reconstructed source on an explicit base, not a claim to have restored the
old commit. Unrelated current Crypto/PQ/Cell source and Cargo.lock are retained.
The exact differences are in [source-reconstruction-delta.json](source-reconstruction-delta.json).

## Candidate changes

Ordinary explicit metered W1/fact ingress now runs the existing bounded header
precheck before full W1; restricted owners keep their full task-before-work gate.
The large-parent fallback retains a private, single-use parent checked by the
same Node instead of discarding and reconstructing it. Every use rechecks
namespace, storage, owner identity, complete header predicates and SQLite epoch;
a changed epoch performs full fresh parent validation. M06 and publication use
the original held execution path, including original transactional readbacks.

History binds the original absolute deadline before work. Only an actual full,
unique W1 can promote the existing operation. The exclusive `&mut Node`
embedding owns no Node mutex and may continue the exact paid stack through
actual refill, checking the original resource callback and deadline during every
wait. Its final activation remains in that admission operation. Shared Mutex
embedding has nonwaiting held checkpoints; its existing begin-time refill and
W1/M06 detached scheduling remain outside the writer. This does not solve a
shared indivisible held phase that exceeds its available paid credit.

The two original honest selectors, deadlines and assertions remain. The large
State helper is additionally called independently for Authenticated state,
so an earlier Legacy failure cannot hide that backend from the observed
attempted denominator. A new original-resource cancellation control spends
actual W1 CPU to reach real refill; it is not labeled a malicious-network attack.

## Preserved first narrow attempt

The narrow duplicate-read repair compiled with Rust 1.95 and was measured before
adding the History continuation. Both original controls failed; raw streams and
receipts are retained in [narrow-inactive-history](narrow-inactive-history/receipt.json)
and [narrow-large-state](narrow-large-state/receipt.json), with the complete
[narrow-source-manifest.json](narrow-source-manifest.json).

- Inactive History: 0/1, `PUBLIC_MUTATION_CPU_BUDGET`, 2.424697 s process elapsed.
- 8,625,548-byte Legacy State: 0/1, same budget refusal, 2,763,945,230 ns paid
  CPU. Two actual M06 workers started/joined/known (the recovered earlier build
  started zero); all accounting remained known. Authenticated was unreached in
  that original loop.

The rejected full-burst prefill draft was compiled but never measured or
qualified: it would spend a short caller deadline before a previously reachable
activation control. It is absent from this candidate. No deadline was extended
and no zero-test invocation counts as acceptance.

Frozen results and executable/source hashes are recorded below. Local component
controls do not establish independent
WAN service, complete malicious-network coverage or release readiness.

## Retained continuation observations and poison correction

The frozen `d5a4652d3b3fd3aa4015b747d865aae906933851` executable completed all
seven original inactive History pages; activation occurred only at the original
last page. Its original resource callback also cancelled actual paid work during
refill without creating credit. Exact executable, source and stream hashes are
in the retained receipts. These observations do not cover shared held-phase
service or independent network budgets.

The existing poisoned-registry control exposed a regression in the new policy
read preceding the sampler: it returned unavailable without setting the shared
budget's unavailable fence. The correction releases the poisoned guard and
calls the same original `unknown()` fence before returning. The original failed
test and its raw streams remain in `poison-registry-before-followup`; the
correction requires a fresh build and the unchanged original control.

The fresh `3ca96292ccc7815f4c7f49b34445f3d28687b5f4` build and all raw
observations are retained in [poison-followup](poison-followup/build.json):

- Original poison fence: 1/1 passed; original scalar controls: 57/57 passed;
  original live-CPU controls: 4/4 passed.
- Original History group: 9/9 passed. The one ignored child-only fixture was
  actually invoked by the parent at all five real SIGKILL cuts: epoch, W1, M06,
  admission and activation. Reopens retained the active marker and refused a
  fresh CPU account. These are process crashes, not physical power-loss tests;
  unknown debt remains fenced, not reconstructed as a known zero.
- Original inactive History: 7/7 pages succeeded; only the final page activated.
  Total paid CPU was 425,899,172 ns from initial zero credit.
- Original process-cold real-W1 depletion: 118 invalid transcript replays,
  134,816,372 ns measured CPU, -49,897 ns settled credit; the original TCP Head
  and signed Submit then recovered and matched an independent native State.
  This measures recovery after depletion, not honest success under continuing
  overlapping hostile load.
- Original >8 MiB honest controls remain failed for **both** backends. Legacy
  paid 2,816,416,676 ns, Authenticated paid 3,379,931,210 ns. Both started and
  joined two known M06 workers and refused `PUBLIC_MUTATION_CPU_BUDGET`.
- The first withheld-frame selection ran zero tests because the original gate
  is ignored; that invocation is retained as non-evidence. The explicit original
  `--ignored` invocation passed 1/1 with the original ten-second timeout and all
  raw signed frames retained; it does not establish the separate scalar gate.

The narrow cost correction avoids reserializing equal before/after JSON
cells solely to discover unchanged deltas. Every per-row progress checkpoint,
canonical full-State/execution check and original transactional readback remains.
Its fresh measurements below still fail both original honest gates. The single
observations do not establish a repeatable speedup, and they do not reinterpret
or replace the two preceding failures.

## Frozen native continuation and all original failures

The full tracked checkout was verified before and after the build and native
controls: 5,583 entries and 708,204,641 bytes at measured source
`48aa81da0435e55504503b25ccaaf58db013d94f`, tree
`9b64bb807def976edbe16aa5171492ffdc3bb7fb`. This complete raw-byte verification is
distinct from the earlier reconstructed sparse input manifests. The complete
[native receipts](phase-qualified/native-controls.json),
[raw artifact manifest](phase-qualified/artifact-manifest.json) and
[structured original observations](phase-qualified/actual-controls-summary.json)
retain every selected test, failure, timeout outcome, ignored fixture, argv,
executable hash and raw stream. No failed invocation was discarded.

| Original control | Actual result | Scope and remaining limitation |
| --- | --- | --- |
| History group | 9 passed; one child-only harness fixture ignored | The parent actually executed all five SIGKILL cuts. Original resource cancellation and continuation controls remain. |
| Scalar CPU group | 57/57 passed | Exact original arithmetic, reservation and settlement controls; not hostile-network acceptance. |
| Poisoned request registry | 1/1 passed | The original unavailable fence and no-deadlock assertions are unchanged. |
| Inactive History | 7/7 original pages succeeded | Initial credit zero; final cumulative paid CPU 405,037,187 ns. Only page seven activated. |
| Detached admission integrity | 12/12 passed; one benchmark ignored | Both large controls were excluded from this group only to execute them separately below. |
| Original large-State Legacy | **0/1; `PUBLIC_MUTATION_CPU_BUDGET`** | Complete State 8,625,548 bytes; total CPU 2,772,420,977 ns. |
| Original large-State Authenticated | **0/1; `PUBLIC_MUTATION_CPU_BUDGET`** | Same complete State; total CPU 3,580,792,072 ns. This backend was run independently because the original loop failed first on Legacy. |
| Original process-cold real W1 depletion | 1/1 passed | 179 actual invalid transcript replays; measured CPU 133,389,821 ns; settled credit -2,885 ns; subsequent native read/Submit recovery and independent State agree. Continuing attack overlap is unqualified. |
| Original withheld-frame gate, explicit `--ignored` | 1/1 passed | Original ten-second deadline, signed frames and assertions retained. This fixture explicitly has no registered scalar CPU domain. |

Both large-State failures started and joined two known scoped M06 workers;
accounting remained available. Their process walls, including fixture setup,
were 26.752 s and 65.331 s. Those outer observations are not new business
deadlines. The original ten-second operation budget, two-second CPU burst,
250 ms/s refill, 100 ms reserve and detached snapshot ceiling were unchanged.
The cost correction left the complete-State held phase as a concrete honest
counterexample. It is not an admission success hidden by a reporting error.

All five actual crash cuts (`epoch`, `w1`, `m06`, `admitted`, `activated`) observed
signal 9. Reopened stores retained `active-v1`, and each refused a fresh CPU
account. The receipts explicitly say `debt_reconciliation_complete: false` and
`physical_power_loss: false`: the safety fence prevents a credit reset but does
not reconstruct the unknown debt or restore service. Full crash settlement and
physical power-loss acceptance remain open.

## Actual process separation source and exact executable binding

The hosted workflow now selects `fixed-public-phase-external-actors-v1` for the
unchanged original three-run, three-mode campaign. The receiver and independent
History client execute in a separately launched native process under the one
fixed 25% CPU / 2 GiB / zero-swap / 256-task public parent. The original producer,
controller and all 24 attacker children remain in the observed 400% / 16 GiB
domain. The public child keeps original Nice=10. The controller owns actual
`Child` handles, records attacker membership, and kills/reaps those children
under the original absolute cleanup deadline. Clock conversion takes the
destination clock first, so sampling/IPC can only shorten that deadline.

The broker passes complete original packet bytes and lifecycle requests; it has
no work, budget, State or confirmation authority. The launcher performs no
build, checks the actual fixed parent and exact native ELF, and retains all
setup, child, Host and cleanup failures. It never increases an existing Host
limit. The original business windows, honest schedule, inputs and depletion
predicates remain. See [the applicability analysis](HOST_BUDGET_APPLICABILITY.md)
for the equal-rate and delayed-debit limitations.

The final executable source is
`fe43f7c7f8971df37cbb7eda7080dac8ae4887aa`. Its only change since the original
measured source is the conservative deadline conversion in the test broker.
The repeated exact Cargo build selected the **identical** library test ELF:
SHA-256 `0f82f1a43c785ac6610789df27379c3bba166036bb39b5589d75b92ef6fdc927`,
126,556,056 bytes. The newly rebuilt multiprocess ELF is
`5cb30a8ebad891bf7181c9ae0eed72abd811e137741789010ff31da76670087d`,
75,283,280 bytes; its two original broker negative controls passed.
[Compiler artifacts](phase-qualified/deadline-correction/native-artifacts.json)
and [full source binding](phase-qualified/deadline-correction/source-binding.json)
record the distinction. The build is the existing Node test profile with
optimization level 3, debug assertions/overflow checks enabled and Node debug
symbols disabled. It is **not** a release-profile measurement.

On the final source, strict Clippy passed for **all Node targets and all
features**, with `--offline --locked -- -D warnings`; workspace Rust formatting
and the locked 25-member Cargo graph also passed. The unchanged Python launcher
had 10/10 negative controls and Ruff lint/format passes; source-integrity
controls had 34/34 passes. An initial source-test command used a nonexistent
filename and ran no tests: its nonzero result remains beside the corrected
34-test invocation. The prior source-applicability failures also remain.

The substantive native timing batch ran while the peer W1 prover was paused.
Its original W1 wall budget continued to run, and that pause is retained by its
owner. Later single-job, Nice=19 builds and Clippy overlapped the resumed W1
prover and make no isolated performance claim. Exact UTC intervals are retained
in [the final command receipts](phase-qualified/deadline-correction/commands.json).

**This is implemented placement, not hosted acceptance.** The new actual
systemd/broker campaign has not yet run on this source. The separate valid-W1
false-root supplement still uses its historical direct route and has no new
fixed-Host qualification. No independent administrator, WAN or multi-day
service result follows from local 2-test/10-test parser controls.

## Remaining concrete gates

1. Run every original hosted campaign phase on the final integrated source,
   retaining the original all-honest and actual-depletion denominators.
2. Replace unbounded held full-State work with bounded, resumable operations
   while preserving original SQL/root/readback integrity. A nonwaiting shared
   Mutex owner cannot borrow the exclusive `&mut Node` continuation semantics.
3. Complete conservative durable crash-debt recovery. The current persistent
   unknown fence is not known zero debt, a clean settlement or restored service.
4. Attribute physical Host CPU, authentication, independent replay and queues
   before claiming a lower mutation refill solves confirmation service. The
   original four-second hosted counterexample is retained separately in
   [the source-bound readback excerpt](phase-qualified/fc23-readback-applicability.json).
