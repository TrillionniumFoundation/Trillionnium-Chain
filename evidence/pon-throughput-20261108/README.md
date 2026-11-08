# Throughput continuation — 2026-11-08

**HOLD_NO_GO: no qualified end-to-end TPS.** This delivery adds executable
transaction, Cell, loading and computation accounting, repairs lost timeout
receipts, reproduces source-pinned historical measurements, and records one new
native development experiment. It does not close original Host pressure, WAN,
independent custody, whole-model cold loading or actual model-adoption gates.

The implementation is stacked on #793 source
`812589d9bb189b6abbf33b916a424121199dee75`, tree
`84c173e874ce4be6a62b0b05c9c1b4116acbf32c`. The [metric contract and commands](../../formal/throughput-v1/README.md)
define each observation's numerator, interval and qualification limits.

## Delivered corrections

1. Derive unique transaction identities from original PNX1 bytes; keep accepted
   blocks, repeated packets and confirmed transactions separate. Require both
   depth and work, the original strict deadline and one consistent canonical
   retention cut before aggregating eligibility observations.
2. Reuse the original Host confirmation owner. Contradictory zero summaries and
   earlier native-positive receipts produce unknown, not an invented zero rate.
3. Preserve exact returned or timeout output bytes and monotonic outcome
   receipts. Launch errors, interruption and decoding failure also retain
   receipts; interrupted subprocess output is not guaranteed recoverable and
   remains explicitly incomplete. Original timeout and exception behavior
   remain; no fresh time or CPU allowance is supplied.
4. Project complete-release transport, loading substages, action-scoring
   forwards, training stages and NoUpdate from their original raw records.
   Unsupported generated-token, GPU, complete cold-start and adoption rates stay
   null. Signals and unrelated endpoints are not successful refusal evidence.
5. Recompute proof CPU work from the original eight runs, retain failed/missing
   denominators, and reject contradictory GNU time exit diagnostics. Historical
   scheduled-SHA and tagged-SHA3 improvements are not multiplied.

## New native development execution

The release build and collector actually ran on the current shared Linux
executor. All **2,365 non-evidence tracked source files** matched the exact #793
Git blobs before and after collection. Historical evidence was excluded by a
sparse checkout; **whole-tracked-tree verification was not claimed**. The
[execution receipt](native-fresh/execution.json), archived full original
process directory, raw stdout/stderr, source-byte receipts and retained build
logs distinguish this new execution from the historical measurement.

| Observation | This execution |
| --- | --- |
| Frozen original starts / actual processes | 4 / 9 |
| Outcomes | 1 accepted, 1 exact duplicate, 1 `WORK:Product` rejection, 1 terminal cancellation |
| Distinct transaction bytes / newly accepted blocks | 1 / 1 |
| Last canonical depth | 0 |
| Actual total observed interval | 206,661,467 ns, about 0.2067 s |
| Parent-plus-child recorded CPU | 119,978,000 ns |
| Conservative recorded peak-RSS bound | 48,848,896 bytes |
| Actual input-pipe bytes across attempts | 200,040 bytes |
| Complete original four-second observation window | **No** |
| Independent native confirmation / qualified TPS | **Unknown / null** |

The short local component observation is not a completed service window. It
has no six-successor confirmation, protected resource domain, WAN, production
queue or sixteen-hostile campaign. The reader deliberately returns null for its
window rate. The fixed transaction and block are also the same development
fixture as the historical experiment; the two runs cannot be pooled as two new
independent transactions. [New transaction readback](native-fresh/transaction-readback.json).

## Historical native readback

The original #793 archive is read with fixed Git blob and SHA-256 identity.
Its four starts remain in the denominator. One transaction appears in the
valid, duplicate, hostile and cancelled packets; this is one unique byte
identity. There is zero retained mathematical depth-and-work eligibility in
the original window, while independently confirmed TPS stays unknown because
growth observations do not provide the required native confirmation authority.

The old 7.322108454-second independent readback and its failed original deadline
remain historical observations. They are not replaced by the current shared-host
0.2067-second control-set interval; those intervals and execution environments
have different boundaries. [Original readback](native-history/transaction-readback.json)
and [archive reproduction receipt](native-history/reproduction.json).

## Proof CPU readback

The [proof CPU report](proof-cpu/report.json) verifies ten exact original blobs
from #795 and retains all eight planned observations. It performs **zero new
proof executions**.

| Tagged verifier cohort | User + system CPU observations | Median |
| --- | --- | --- |
| retained | 2.43, 2.29 CPU-s | 2.36 CPU-s |
| dense | 2.56, 2.20 CPU-s | 2.38 CPU-s |
| pooled four tagged observations | all four above | **2.36 CPU-s** |

The pooled wall-time median is 0.544260107 s on eight Rayon threads and CPU
affinity 0–7. The nominal original service allowance is one CPU-second over
four seconds at 0.25 CPU, shared by all required work. The mismatch motivates an
actual matched-resource campaign; it is not a new wall-time measurement or a
proof of a universal CPU lower bound. GNU time prints CPU with centisecond
precision, so these are reported observations, not exact physical costs.

The measured resolved-merge source and the later evidence-publication commit
are distinct and retained in the report. The [CPU detail](proof-cpu/README.md)
also specifies the fresh four-arm combination obligation.

## Historical Cell, load and computation readback

The [Cell/model projection](cell-model/projection.json) verifies 44 original
files and the externally pinned [input manifest](cell-model/input-manifest.json).
These are historical results retained at #787, not new transport, training,
model or WAN executions by this delivery.

| Observation | Publisher / baseline | Replica / candidate |
| --- | --- | --- |
| Complete release bytes | 272,190,131 | 272,190,131 |
| Native fetch-command interval | 86.974985624 s | 64.298681646 s |
| Useful decimal MB per fetch-command second | **3.129522** | **4.233215** |
| Forward execution interval for 32 requests | 10.316958780 s | 26.788947234 s |
| Action-scoring forwards per execution second | **3.101689** | **1.194522** |
| Correct answers | 16/32 | 16/32 |
| Original selection result | — | **NoUpdate** |

The reader checks all eleven original cache materializations, both complete
TCR1 markers, the offline publisher refusal and the earlier optimized-transfer
failure. It keeps the complete global-attempt denominator unknown and does not
turn two successful fetch commands into an independent recovery probability.

The three CPU training-stage observations are 34.570408, 30.858016 and
34.780742 seconds. Their approximately 409/454/408-ms model-load substages do
not include complete cold acquisition or download-to-first-response. GPU
transfer, generated token/s, complete product-iteration cost and actual
adoption rate remain null. The original 35-second, 272,189,990-byte failed cold
cohort is separate from this historical 180-second transfer cohort and stays
unclosed.

## Original resource gate: actual prerequisite refusal

Fresh read-only observations of the current [cloud executor](host-prerequisites/cloud-observation.json)
and [desktop host](host-prerequisites/desktop-observation.json) both show the
required `/sys/fs/cgroup/trnmponpublic.slice` is absent. The original parent
identity, fixed kernel limits and reviewed runtime unit therefore do not pass
the unchanged validator.

These are **NOT_RUN** pressure campaigns. Valid admission and cryptographic
refusal counts are null, not zero. No process was launched as a substitute for
the original quarter-CPU, 2-GiB, zero-swap, 256-PID, four-second, sixteen-hostile
campaign, and no system configuration was changed to conceal the missing
precondition. The remote observer's exit 1 is its explicit HOLD result.

## Validation and remaining gates

The retained validation directory records exact commands, exits, raw logs and
source hashes. New controls cover complete denominators, duplicate transaction
IDs, easy-descendant work deficits, strict deadlines, reorg return, conflicting
fork cuts, contradictory zero confirmations, missing receipts, wrong hashes,
malformed JSON/types, unsupported token units, failed stages and actual
subprocess timeout behavior. Initial fixture/test mistakes remain in their
original logs alongside corrected-source runs.

Native build, default/all-feature locked dependency graphs, the correctly
located fuzz graph, formatting, focused strict Clippy and the retained four
native context/header/cancellation tests are separate source controls. The first
fuzz metadata command mistakenly used a nonexistent `trillionnium/fuzz` path;
that actual exit 101 is retained, with the correct `tests/fuzz/Cargo.toml`
command and its exit zero recorded separately. No runtime or acceptance
threshold changed.

The dedicated exact-head CI performs full tracked-source checks and fresh
report reproduction. Its hosted status is reported separately from local
validation and from inherited repository gates. Passing these reader controls
does not close original confirmation, complete History/capacity/churn, WAN,
quantum-work, cryptographic-composition or product-adoption gates.

The next qualifying data must come from an actual owned original-resource
campaign with frozen exact offers, native independent confirmation and risk
evidence; a complete provider-diverse Cell recovery campaign; a fully timed
physical model-load path; and cost-matched real model evaluation with original
adoption readback. Missing inputs remain explicit, and no field in these tools
can promote local observations to production.
