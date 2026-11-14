# Original CI failures, bounded repairs and retained service outcomes

This continuation preserves published head
`bebb1f3289cd7050fefde89ea8f2cf33c6c37588`, tree
`58c31e8a6220c6be20029b33cb060f3a2034d1a7`, and its actual prospective merge
`0153600a002c420d20128983c3280ff6c16e70c4` against main
`dd6e1c3cbeacbdc532b0679297835b3a0aac78f0`.
The observations below belong to those exact sources. A subsequent repair is
not retroactively credited to them. Original budgets, deadlines, denominator
rows, native assertions and qualification flags remain in force.

## Exact published-source outcomes

| Original lane | Observed result | Interpretation |
| --- | --- | --- |
| Required baseline | 21 completed jobs: 11 success, 10 failure | Aggregate jobs are not additional business failures. |
| Fuzz smoke, HEAD and actual merge | Original locked fetch and all three original ASan targets pass on each source | The missing lock edge and these smoke executions are resolved; exhaustive security coverage is not claimed. |
| Recent authenticated module, four lanes | 83 passed, including 23 post-write controls and all 60 earlier controls | Each job subsequently fails strict Clippy. |
| Branch wire, four lanes | 22 passed, 1 ignored | Each job subsequently fails the same strict Clippy finding. |
| PQ selected controls, four lanes | 43/43 each, 172/172 total | These controls are separate from complete-library outcomes. |
| PQ complete Node library, x64 HEAD and merge | 934 passed, 0 failed, 23 ignored each | Both new observation tests pass. Strict Clippy still fails separately. |
| PQ complete Node library, ARM HEAD and merge | 932 passed, 2 failed, 23 ignored each | The two original large-state CPU-policy selectors fail; both new observation tests pass. |
| Original complete-workspace test-profile CPU | x64 HEAD/merge pass; ARM HEAD/merge fail both original large-state selectors | Release-profile successes are not substituted for these failures. |
| Required runtime, HEAD and merge | Both stop in data-availability: 171 passed, 1 failed | Different Cell sequence fixture failures occur before any Node-library invocation in these jobs. |
| CodeQL producer/export | Three-language production and source-bound export complete; Rust has 506 warnings | 500 hardcoded-value and 6 cleartext warnings remain; export does not supply an authenticated PR-gate verdict. |

The [required-job readback](bebb-hosted/bebb-required-baseline-final.json),
[fuzz source-bound results](bebb-hosted/bebb-fuzz-outcomes.json),
[CodeQL warning review](bebb-hosted/bebb-codeql-outcomes.json), and
[PQ full-library ARM audit](pq-diagnostics/pq-full-library-arm-failure-audit.json)
retain original run/artifact IDs, hashes, commands and limitations. The two new
CodeQL locations are deterministic transfer nonces in actual test-only code;
no finding was dismissed and no scanning rule was changed.

### Original CPU refusal, with actual work denominators

The [four original workspace CPU artifacts](bebb-hosted/bebb-original-cpu-outcomes.json)
bind the complete unchanged workspace build, Rust 1.95.0, M06 optimization 1,
Node optimization 3, debug assertions, overflow checks and original PQ features.
All four ARM authenticated samples refuse with `PUBLIC_MUTATION_CPU_BUDGET` at
2.686–2.725 seconds settled CPU. Each executes ten complete commitments, costing
0.935–0.940 seconds CPU, with 0.463–0.466 seconds of nested complete-root work.
The corresponding x64 successful operations each execute eleven commitments;
their different completed work cannot be used as equal-denominator speedups.

The original shared string pool retains only 445 or 446 of the large fixture's
strings. Its 2 MiB payload and 16 MiB retained software-charge ceilings remain
unchanged. Full State rows, canonical validation and cache-offer encoding still
have real costs. Retained charge is not RSS, peak allocation or a bound on all
temporary work.

The separate PQ whole-library ARM samples cost 2.700–2.796 seconds and retain
negative paid credit. They are not pooled with the workspace CPU samples.
Outer dispatch `Ok` means a `MeteredWorkFactOutcome` was returned; its inner
`native` result is already an error. `operation.finish()` settles the CPU tail
without rewriting that native result. The old fixture observed active-state
equality only on outer failure, so its null readback remains **unknown**.

The next diagnostic change observes both outer and inner refusal forms after
the original operation and CPU settlement, records the separate native result,
and keeps readback failure as null plus its actual error. It neither retries
admission nor changes the original native result, CPU receipt or strict assertion.

### Fixed touched owners and growing account/history sets

The [separate Growth V2 execution](bebb-hosted/bebb-growth-execution-supplement.json)
passes in all four source/architecture lanes, even where the CPU-policy step
fails. Each lane retains nine cohorts (64/1,024/16,384 accounts crossed with
0/16/128 history blocks), 72 measured signed native blocks, nine cancelled
admissions and nine cold reopens. At fixed witness owners, separate query point
reads grow from 16 to 37 and witness bytes from 917 to 2,303 across that account
range. This is component evidence of bounded path work, not constant work or
ordinary History qualification. Cold reopen still grows substantially: the
x64 HEAD observation moves from about 58 ms at 64 accounts/no warmup history to
2.833 seconds at 16,384 accounts/128 history blocks. Eight measured blocks per
cohort provide no p99 claim.

## Repairs supported by completed local evidence

### Shared immutable values in the original arithmetic pool

The final five-file root candidate is frozen as production tree
`367bf61031f47fecc64123de644c3bf23b9d39b5` over `bebb`, before the other repairs.
It shares allocation bytes for equal plain JSON strings while every key keeps
its own independently computed original hashes. Full current key/value equality,
complete canonical validation, tree-array priority, original encoder misses,
failure non-publication and the existing retained budgets remain required.
A length/edge index has one candidate and always compares full bytes. Colliding
different values retain separately charged allocations; equal contents in
different allocations are also charged independently.

The [predeclared comparison](value-pool/benchmark-plan.json) and
[full result](value-pool/benchmark-result.json) retain all ten separately
launched processes and 700/700 planned observations: 660 successful calls and
40 expected late-grammar/late-wire refusals. Both sides use the same driver and
complete input hashes, independent targets and distinct ELF hashes, Rust 1.95.0,
protocol optimization 3, M06 optimization 1, and enabled debug/overflow checks.
Each warm process value sums eight correlated calls; the decision uses the
median of five paired candidate/baseline CPU ratios.

| Predeclared component condition | Observed paired median | Original limit |
| --- | ---: | ---: |
| Repeated values, warm complete root | 0.146361711 | 0.85 |
| Repeated values, warm complete commitment | 0.621036472 | 0.95 |
| Eight unique/common-edge cold/warm root/commitment conditions | All pass; closest is 1.049715288 | 1.05 each |

The complete commitment timer includes `derive_snapshot_with_arithmetic`, its
original `encode_for_cache`, canonical validation and fallback. No preliminary
encoding was removed from that interval. Repeated input retention rises from
445 to 2,100 strings while retained payload falls from 2,094,369 to 455,566 bytes
(459,720 on the changed call). Warm actual leaf hashes fall from 1,655 to zero;
all 2,100 current inputs are still observed. These are retained-material and
finite CPU observations, not RSS or a change to the two original budgets.

The narrow margin is retained explicitly: common-edge warm root has paired
median 1.049715288, and one pair is 1.222894. This finite median gate does not
establish general non-regression, statistical independence, p95/p99, ARM CPU
acceptance or public-service qualification. All changed/restored/error/setup
costs and whole-process VmHWM remain in the raw observations; no sample was
excluded or replaced. The M06 cache's private retained-charge observation is
not exposed and remains null; no public inspection hole was added.

The [independent finite-campaign audit](value-pool/value-pool-independent-benchmark-audit.json)
reconstructs all ten raw process outputs and exact rational paired medians.
The [complete frozen delivery](value-pool/value-pool-delivery.tar.gz) and its
[member manifest](value-pool/delivery-manifest.json) preserve the five full
source files, original failed observation, receipts, preregistration and all
700 observations. This internal replication does not supply independent
external security or end-to-end performance acceptance.

Functional controls pass 14 protocol arithmetic tests, nine M06 root tests,
five original M06 full-root tests, one opaque-builder compile-fail doctest and
seven original Node cache controls. A first Node assertion incorrectly expected
only the 2,100 fixture strings and omitted the existing `model:current` string.
That failed log/source freeze is preserved; the corrected test derives the
complete non-account string set independently instead of hardcoding 2,101.
Five added protocol controls increase the broad wire gate from 22 to 27 ordinary
tests while retaining its one ignored test. No old test is removed or weakened.

### Test-only PQ action boundary

The shared `observe_operation!` test macro triggers `clippy::redundant_closure_call` in
one TcpRequest expansion. Other invocations need the action-local `?` and return
boundary, so deleting the closure globally is incorrect. A private test-only
`invoke(FnOnce)` helper preserves that boundary, exact error, unwind and one-call
behavior without suppressing a lint. The non-test macro is unchanged.

[Complete-workspace strict Clippy](invoke-only-clippy/exit.json) passes on
`bebb` plus the two invoke files, using all targets/features and `-D warnings`.
This receipt predates the combined Cell and root-arithmetic continuation; it is
not a combined-source or hosted success claim.

The later [combined working-source strict Clippy](combined-working-validation/strict-clippy.result.json)
also passes the complete workspace, all targets and all features with
`-D warnings`; [workspace formatting](combined-working-validation/format.result.json)
passes. These receipts identify the actual uncommitted source patch and original
provider. Exact committed-source and hosted results must be recorded separately.

### Cell fixture readiness and bounded failure observations

The original HEAD runtime failure is an ANNOUNCE `WouldBlock`/errno 11; the
actual merge failure never records the required live manifest arrival at its
expiry proxy. Peer startup previously returned before the serving thread's DB
open completed. These facts do not establish startup as the sole errno-11 cause.

The single test-file repair acknowledges real DB/listener/address/bounds setup
before the fixture signs its TTL-bearing records. All workers share one fixed
ten-second setup cutoff; setup work is measured and never renewed. The original
200/250 ms requests, four-second short-TTL request, two-second signed expiry,
ten-second operation deadlines, thirty-second finite servers, 64-connection
limits and all 32 original assertions remain. There are no probe connections,
request retries, extra sleeps or production-serving changes.
The setup cutoff governs accepting completed readiness, not forced interruption
of a synchronous DB open or a worker join. Readiness also cannot guarantee later
scheduling headroom; the next hosted outcomes retain that distinction.

The [delivery receipt](cell-readiness/cell-readiness-delivery.json) retains the
initial package-feature runs separately from the verified original-workspace
reachable feature closure (91 packages, no feature differences). With that
closure and the original test profile, both exact previously failing selectors
pass, all three original sequence controls pass, and strict package all-target
Clippy passes. The observations are from a different local host and uncommitted
candidate; fresh exact-source hosted runtime execution remains required.

## Original public service remains unqualified

The [service readback](bebb-hosted/bebb-original-service-outcomes.json) verifies
archive and member hashes and keeps all original planned rounds, packet
exposures, failed/late imports and unknown timing values.
Separate raw-artifact reviews retain the
[initial late-success finding](bebb-hosted/bebb-reader-independent-audit.json),
[timeliness correction](bebb-hosted/bebb-reader-independent-final-review.json),
[clock/snapshot scope comparison](bebb-hosted/bebb-reader-source-scope-review.json),
and [live Host boundary audit](bebb-hosted/bebb-live-host-service-boundary-audit.json).
These are internal evidence cross-checks, not an independent security acceptance.

| Original experiment | Actual confirmations | Original planned denominator |
| --- | --- | --- |
| Four-second original pressure, HEAD | 0 | 1 confirmation / 7 signed packets / 16 hostile workers |
| Four-second fresh pressure, HEAD | 0 | Same original denominator |
| Four-second original pressure, actual merge | 0 | Same original denominator |
| Four-second fresh pressure, actual merge | 0 | Same original denominator |
| F0, original thirty-second window | 1 | 6 confirmations / 42 packet exposures |
| F0, original four-second SLO | 0 | 6 confirmations |
| Three original thirty-second campaigns | 3 | 27 confirmations / 189 packet exposures |

The four attack-free controls confirm one transaction each, at 3.097900 and
3.099209 seconds on HEAD, and 1.705074 and 1.879526 seconds on actual merge.
These are different hosted observations, not paired optimization measurements.
All four pressure phases obtain seven timely ACKs but fail confirmation.
The three thirty-second campaigns retain 12 observed and 15 unobserved rounds,
72 actual submission attempts and 69 timely ACKs; those ACKs do not replace the
189 planned exposures or 27 confirmation denominator.

Run 2's late-product phase includes a natively successful import ending at
30.082335559 seconds, beyond the original thirty-second window. The reader keeps
its 691.557585 ms caller CPU and success result, but separates `timely_accepted`
from `accepted_at_or_after_window`; the phase still has zero confirmations.

The fresh HEAD's observed replay returns `PUBLIC_REQUEST_DEADLINE` after
4.047862 seconds; the fresh merge's final replay fails after 4.050829 seconds.
Earlier successful page imports do not establish full-chain confirmation.
The full-limb W1 and current Host checks are used on both receiver and importer.
Neither path silently enables arithmetic-fact caching. Different challenges
cannot borrow a mathematical fact whose input contract requires the full
current challenge and proof context.

Packet, page and Host spans are nested. Host CPU can include different actual
calling threads; it must not be subtracted from importer-only CPU as an exclusive
cost. The multiprocess RPC caller metric is process CPU, whereas the four-second
RPC caller metric is thread CPU; the reader preserves the original field per
call. Client account-graph snapshots include imports and subsequent confirmation
internal reads, but exclude the final standalone `read_active`; no graph/import
percentage is derived. The earlier rejected Host-path p95
experiment stays rejected. No performance success is inferred by dropping
refused, cancelled, late or unobserved work.

The F0 baseline's nine imports include eight native successes and one deadline
failure. Its 100,810 Host checkpoints cost 4.704213918 seconds of aggregate Host
CPU, nested with 5.577814982 seconds of importer-thread page CPU. The separate
valid-work-root phase never enters History or import: 15 Submit attempts touch
four distinct packets and yield three timely ACKs. Its upstream failure cannot
be assigned to client import merely because that is expensive in baseline.

The audit finds no further measured small Host optimization that preserves every
current boundary. Each check already uses immutable names and bounded short-text
buffers while opening and fully reading current boot, calling-thread membership
and all five limits, with current parent metadata. Ordinary graph reads already
share a prepared statement within one graph and borrow the actual SQL blob.
Cross-transaction or general read-path reuse would need a separately specified
read-snapshot capability with the original schema/write/ABA/callback negatives;
the existing write receipt cannot authorize it.

## Recovery and source integrity

The executor reset after publication removed the old local checkout and build
outputs. The complete published repository was cloned again; its 7,315 tracked
files and 862,029,405 bytes match `bebb` before edits. The pinned Rust 1.95.0 and
OpenSSL 3.5.9 provider were restored, with the original real ML-DSA65 sign,
verify and wrong-message rejection smoke check. Lost local files are not linked
or claimed to remain available. Reconstructed summaries are identified as such.
Both locked graphs are rechecked after recovery: 26 workspace packages / 138
Linux nodes, and the separate fuzz workspace / 106 Linux nodes. The initial
fuzz fetch command named a nonexistent manifest path; its exit 101 is retained
alongside the corrected `tests/fuzz/Cargo.toml` locked fetch and offline graph
success. This local preparation mistake is separate from the original hosted
fuzz success.

The [initial evidence inventory](initial-evidence-inventory.json) records exact
copied bytes. The extraction scripts are read-only and need the original ZIPs
listed by their immutable artifact IDs and SHA256 values. They run no native
test and confer no acceptance authority.

The [combined source review](post-ci-integration-review.json) finds no unresolved
source-semantic blocker in the nine Rust files, 375 corpus pins and 20 inline
pins, while explicitly retaining its missing native/hardware/service evidence.
The working-source repository, inventory and pin checks pass, along with
34 PQ negative controls, 34 source-integrity controls and 98 CI-contract tests.
The [final working-source repository check](combined-working-static/07-repository-final-links.json)
checks 1,800 local links. Native sources and configurations remain identical
across these checks; the only source-inventory change is adding 31 byte-identical
original logs to the index. The complete before/after manifests are retained in
[byte-preserving compressed form](combined-working-static/compressed-source-manifests.json).
These records precede adding their own evidence files and are not represented
as validation of a later committed tree.

Raw patches preserve their required context-space lines, and original test
stdout and the original reader preserve their terminal blank lines. An extra
whole-staged-tree `git diff --check` reports those exact retained bytes; the
source, documentation and configuration check passes. Raw evidence has not been
whitespace-normalized and no Git or CI whitespace policy has been changed.

**DRAFT / HOLD.** This record does not close original public-service performance,
cheapest-work, heterogeneous hardware, quantum/DAA, independent operators or
security review, model utility, long-term custody, economics, whole-chain PQ,
or production activation. The sole development plan remains
[the canonical plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
