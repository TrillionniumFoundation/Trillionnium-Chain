# Actual work and native execution certificate continuation

Starting commit: `f8362822b406463ac3dfcc911a0c3eda1686e32d`.
Publication continues the existing work-scale candidate. No consensus parameter,
activation rule, six-successor threshold or production service is activated here.

This record adds actual local evidence and proved conditional reductions. It
does **not** close the two all-strategy/all-world scientific certificates. The
fixed-probability/variable-unit candidate remains conditional research, and the
native six-successor failure probability remains unknown.

## 1. Concrete native implementation and independent bridge

The new [owner census](../../formal/pon-nakamoto-v1/NATIVE_OWNER_OBSERVATION_V1.md)
enumerates every current admitted row in one source-schema-checked read snapshot
for supported native PNP1 owners. It replays full W1 and application execution,
compares actual retained state and deltas, computes ancestor timestamp eligibility
and fences owner/namespace/generation/SQLite changes. Cancellation or exhausted
limits produce no successful partial census. A filtered SQL view cannot stand
in for the source-defined block table. Complete history before this snapshot,
unadmitted packets, other owners and hidden remote work remain outside its scope.

The [independent reader](../../formal/pon-nakamoto-v1/NATIVE_OWNER_SCORE_BRIDGE_V1.md)
recomputes 512-bit native work, all ancestors, the active path and the exact
eligible maximum from the export. It binds actual native confirmation outputs
to installed settings, tip, generation and validation time. It preserves both
confirmation gates, the local inclusive `K >= 7*w(b)` result and every local
availability/selection deficit. It never calls an entire competing suffix
new adversarial production.

Fresh actual execution:

- [Native owner run](native_owner/actual_native_owner_run.json): two fresh owners,
  11 successful complete snapshots, 82 native operations, 19 actual produced
  packets plus one malformed-product packet retained as a rejection control.
- [Fresh independent bridge invocation](native_score_bridge/attempt-01/run/invocation.json)
  runs the native program again; [32 controls](native_score_bridge/attempt-01/stderr.txt)
  pass against that new record and its actual packets.
- [Exact score comparisons](native_score_bridge/attempt-01/run/score_bridge.json)
  retain an unknown global failure probability and all global qualification
  flags false.

The actual development target gives weight **2** per block in this run:

| Actual local observation | Active score | Maximum eligible admitted score | Raw selection deficit | Deterministic consequence |
| --- | ---: | ---: | ---: | --- |
| Alice confirms the first block with six successors | 14 | 14 | 0 | Depth 6, successor work 12, inclusive `K=14=7*w(b)` |
| Bob has not seen that block | 0 | 0 | 0 | Relative to Alice's score 14, availability deficit is 14; competing suffix is zero |
| Alice has admitted its ninth block but still selects its seventh | 14 | 18 | 4 | Admission alone has not selected the eligible maximum |
| Alice actually reorganizes to Bob's eighth block | 16 | 18 | 2 | Original transaction is reorged; a known heavier target-containing chain remains unselected |
| Future ancestor and its child become time-eligible | 16 | 22 | 6 | Maturity changes the eligible maximum before a selection call |
| Alice selects the mature target-containing chain | 22 | 22 | 0 | Current local selection catches up |

The deficit capped at the original reference score 14 is zero in the two
score-16 rows; it must not be confused with raw deficits two and six. Before
timestamp maturity the child's own current timestamp cannot make its future
ancestor eligible. Validation clocks are controlled inputs, while invocation
`Instant` intervals are local measurements; neither certifies physical network
time or full adoptability latency.

## 2. Actual work observations and finite public help

[WLC1](../../formal/pon-nakamoto-v1/WORK_LIFECYCLE_CERTIFICATE_V1.md) defines a new
off-chain observation namespace. Actual ML-DSA-65 signatures authenticate source
statements against independently supplied public-key and initial/final endpoint
pins. The verifier checks complete event chains, actual full W1/MU1 artifacts,
and recursively signed public-help source references. It rejects missing,
reordered or truncated records, substituted pins and unsupported promotions to
resource or initial-state certificates.

The [final source-bound actual run](work_lifecycle/run-02-final/summary.json) records five native
W1 exchanges: four successes and one expected exit-2 invalid-work rejection.
An existing RustCrypto oracle independently checks twelve actual PQ items:
four valid checkpoint signatures and eight negative controls. The two temporary
recorder private keys are not exported. Distinct keys in one laboratory process
do not establish independent trust administration.

The [first run](work_lifecycle/run-01/summary.json) is also retained. A subsequent
documentation clarification of baseline commit versus current source manifest
is followed by the new final run; the first record is not rewritten. Counts above
are per run, not the sum of these runs and separate unit-test executions.

The public `native-work-verification` receipt is an unkeyed digest. Its exact
value can be computed without running the claimed work verification. The same
public computation yields a digest for malformed work that the actual native
verifier rejects. This demonstrates why a bound input digest is not an execution
or resource attestation; full relation verification remains necessary.

The finite classical-help reduction is a separate conditional theorem. If every
complete helper transcript lies in one globally fixed alphabet of size `D`, and
every forced-transcript receiver obeys the same fresh-oracle query/output caps,
the existing uniform bound `B` yields `min(1,D*B)`. All payload values, lengths,
sources, ordering, timing, errors and observable metadata must be covered; no
unrecorded quantum or initial correlated state is allowed. A large actual packet
alphabet correctly gives the vacuous bound one. A signed observed message count
does not certify any of these global premises.

Actual local Python execution uses cryptography 50.0.0 with its reported bundled
OpenSSL backend. This is recorded explicitly; it is not relabelled execution
under the repository CI requirement cryptography 50.0.2. Full remote CI retains
its own exact dependency and source checks.

## 3. Observability and repeated origins

[The mathematical certificate](../../formal/pon-nakamoto-v1/CERTIFICATE_OBSERVABILITY_V1.md)
formalizes the missing coverage. Under a noninterference construction, different
hidden remote inventories or oracle-correlated initial advice can extend the
same local observation projection. Local signatures and hashes cannot identify
those unobserved quantities. The actual two-owner record binds an example with
the same Alice logical-view commitment before and after Bob's hidden branch;
its invocation clocks and attempt numbers are deliberately not claimed equal.

For repeated starts, windows `I_j` with new unique credit at least `d_j` admit
nonnegative multipliers `lambda_j` only when their total coverage is at most one
at **every** possible causal cut. Then global unique credit is at least
`sum(lambda_j*d_j)`. This pathwise statement permits adaptive window selection
without charging the same output repeatedly. A probability application uses a
previously fixed threshold and one valid whole-lifetime tail; it does not reset
the oracle or initial state at each selected confirmation.

A separate exact finite probability-tree checker computes conditional risks
from the entire declared joint law, checks allowances at each starting history,
and checks total spending along each path. It rejects a first-success restart
with a falsely fresh risk allowance. These probability laws are explicit model
inputs, not distributions estimated from the native test schedule.

## 4. Verification, retained failures and publication boundary

The completed native component run passes ten integration tests; the independent
fresh owner bridge passes 32 tests. WLC1 passes 27 tests and the finite
observability/accounting suite passes 19. The existing 24 work-scale and 35
native execution-certificate tests also pass in the
[retained-model run](integration/attempt-02-retained-models/checks.json).
These component results do not substitute for all original remote CI or
performance/capacity campaigns.

The broader [retained native group](integration/attempt-04-complete-components/checks.json)
is **not all green**. `continuity_authenticated` passes its retained control.
The unchanged `native_node` target reports 29 passed, one failed, and one
pre-existing ignored owned-subprocess helper. Authenticated CLI synchronization
fails with `PUBLIC_HOST_KERNEL_PARENT`: its existing fixed resource owner
requires `/sys/fs/cgroup/trnmponpublic.slice`, which does not exist on this
host. The guard and test are byte-identical to the starting commit. The failure
occurs before this new diagnostic is called. No fake cgroup directory, CI
identity, relaxed host check or test skip is introduced.

The [source/host diagnostic](native_owner/host_gate_source_diagnostic.json)
and [independent refusal analysis](observability/retained-host-refusal.json)
retain the precise unchanged guard path, read-only host observations and raw
failure hashes. The shared error string is not promoted into a claim that all
later process identity or resource-membership checks actually ran.

That Cargo group exits 101 before `work_header_binding` runs. The
[remaining-components invocation](integration/attempt-05-remaining-components/checks.json)
therefore executes the previously unrun header-binding target independently,
followed by the new owner tests, strict Clippy and formatting. Completing the
remaining checks does not convert the original failed group into a pass. A
qualified host must still execute the unchanged retained host gate.

The [stale-source-pin refusal](integration/attempt-01-stale-source-pin/observation.json)
preserves rejection after the intentionally added native owner field/module
changed `store.rs`. The existing whole-file guard is updated to the reviewed
new source; the guard, old native controls and their failure propagation remain.
Native development build/test failures and their explanations are also retained
by the native owner evidence. Raw failed observations are not rewritten as
successful executions.

The [model source rebinding](integration/model-source-rebinding/checks.json)
also preserves a deliberate refusal: the previous source-pinned model artifact
is not accepted as current after the native owner changed. A new artifact is
generated and checked against the present source. Neither record qualifies
physical execution or supplies a confirmation failure probability.

CI requires pure finite-law tests once in repository-truth and actual work/PQ
and fresh owner observations once after their current builds in protocol-contract.
Missing binaries, historical substitutions, omitted commands, relocated controls
or altered outputs are rejected by CI negative controls. Publication validation
on the final committed source is recorded separately from these working-tree
component observations.

| Candidate | Retained model conclusion | Qualification after this continuation |
| --- | --- | --- |
| Common fixed target for the complete experimental window | Removes amplification from target changes inside that window | Controlled experiment condition; actual work tail, inventory and native network mapping remain open |
| Common absolute difficulty interval on all branches | Bounds difficulty-induced efficiency variation under the stated cost model and rounding | Trusted common interval, legal-strategy cost coefficients and full failure-event probability remain open |
| Fixed `p0`, variable `u` | `u^(1-alpha)` remains a scaling relation under its stated cost model | Conditional research; no safety qualification |
| Current six-successor rule | Both gates and actual local inclusive `K >= 7*w(b)` verified | Failure probability unknown; no abstract numerical approval |
