# Time, branch work and quantum credit: continuation evidence

Status: **HOLD_NO_GO**. Recorded implementation and validation do not qualify
production activation, minimum acquisition cost, a lifetime quantum-credit tail,
or mixed classical/quantum consensus security.

This continues PR #811 from `081da763ed8647fc3bf54f44a7b9706116390cda`.
Execution source: **`bd696c35f8b838823fad7ccf2868582554f33559`**.
Execution tree: `7e049475b90c89ec7910ea28da9a406398f71584`.
The publication child adds evidence only and must preserve every pre-existing
tracked file. It does not acquire a different native execution identity.

The [native path inventory](native-path-audit.md),
[continuation contract](../../docs/protocol/pon-nakamoto-v1/details/TIME_CREDIT_CONTINUATION_V1.md),
[incremental research contract](../../docs/protocol/pon-nakamoto-v1/details/INCREMENTAL_WORK_SCHEDULE_RESEARCH_V1.md),
and [quantum source audit](../../formal/pon-nakamoto-v1/QUANTUM_BERNOULLI_SOURCE_AUDIT_V1.md)
define the scopes. The [prior archive](../pon-fixed-probability-contract-20261108/README.md)
and its inherited failures remain intact.

## 1. Old-source and fixed-source regression executions

The old-source run used an independent checkout of `081da763...` and applied
only [the added public test](red-attempt-01/regression-test.patch).
No production change was applied. The [stderr](red-attempt-01/red-regression.stderr),
[stdout](red-attempt-01/red-regression.stdout) and
[commands](red-attempt-01/commands.json) retain the complete result.

Compilation succeeded. The exact test ran and failed with exit 101. On its
first, fresh-packet case, the actual local development listener returned
`admitted=true` and activated the candidate despite the retained future
ancestor. This was the intended behavioral assertion, not a compiler,
CPU-budget or missing-fixture failure. It stopped the old execution before
the duplicate case; that second old-source case was not exercised.

The fixed-source [exact regression](validation-native-01/green-public-regression.stdout)
passes fresh, duplicate and separate eligible-branch cases. Deferral precedes
another W1 verification, while prior active state and existing packet bytes
remain intact. This is local development evidence, not a deployed-service test.

Four new owner controls cover ancestor time, original cancellation/resource
errors, header read scope, foreign SQL epoch fencing and local header
integrity. The real CLI command-path control injects wall-clock rollback
around actual work, submit and opening. Explicit logical time remains fixed;
the default clock is sampled again at the current admission/activation gates.

Historical opening may recover retained history. A submit can admit a
historically valid packet before a later activation-time refusal. Generated
artifacts and retained credit are not deleted on refusal. The original signed
postcommit activation/cancellation contract is preserved.

## 2. Exact-source native validation

The [command record](validation-native-01/commands.json) and
[test inventory](native-results-summary.json) retain arguments, exact test names,
exit codes, backend distinctions and exclusions.

| Native target | Passed | Ignored |
| --- | ---: | ---: |
| green-public-regression | 1 | 0 |
| growth-branch-clock | 4 | 0 |
| research-terminal-height | 1 | 0 |
| cli-resampled-clock | 1 | 0 |
| research-work-schedule | 14 | 0 |
| growth-cli | 6 | 0 |
| growth-public-cli | 4 | 0 |
| growth-persistence-cancellation | 2 | 0 |
| growth-owner | 73 | 2 |
| public-growth | 7 | 0 |
| consensus | 10 | 0 |
| legacy-reorg | 5 | 0 |
| reorg-readback | 6 | 0 |
| append-readback | 2 | 0 |
| joint-daa | 2 | 0 |
| daa-adversarial | 2 | 0 |

There are **140 successful native test invocations covering 135 distinct
harness-qualified names**. The exact public regression and four owner controls
also run in their complete affected suites; the five repeats are not additional
distinct tests. Two original Growth scale observations remain ignored.

Five reader-control runs select 72 cases: **71 pass; one PNH1-inapplicable
Growth-specific case is skipped**. Reader outputs retain their own admission,
State execution, provenance and cost boundaries.

The 4096-height control uses a disclosed synthetic prefix of 4095 points and
one actual complete terminal W1 proof. It is not a 4096-full-proof campaign.
The public incremental constructor has no synthetic-prefix/checkpoint import.

Fresh research campaigns retain and independently replay **14 complete proofs**,
seven per backend. The retained joint DAA campaigns independently replay
**114 complete proofs per backend** and preserve the old-policy comparison
of height 64 / work 793 versus height 65 / work 130. This does not activate C1
or prove attack profitability.

Strict Clippy passes with
`--workspace --all-targets --all-features -- -D warnings`.
Execution uses Rust/Cargo 1.95.0 and the
[identified provider](provider/provider-identity.json). Compile concurrency is
eight jobs; libtest uses one thread. The old baseline compiled with two jobs.
These functional tests are not a latency or original-resource comparison.

## 3. Static, source and dependency checks

The complete [repository-truth lane](validation-static-01/repository-truth.stderr)
passes: **67 unittest suite summaries / 1,836 method invocations**, with no
failed or skipped suite cases. The separate source-integrity run contributes
one suite / 43 invocations, for **68 summaries / 1,879 invocations** in the
static job. These are execution counts, not distinct-test counts: the 77-case
CI execution suite repeats the same 43 source-integrity controls.

| Named static control | Cases | Result |
| --- | ---: | --- |
| CI contract | 112 | OK |
| Source integrity, separately run | 43 | OK |
| CI execution, including those 43 controls again | 77 | OK |
| Project boundary | 16 | OK |
| Quantum Bernoulli source audit | 13 | OK |
| MU1 context/query | 16 | OK |
| Lifecycle query | 26 | OK |
| Finite joint state | 34 | OK |
| Joint consensus boundaries | 12 | OK |

All nine top-level static commands return zero. Repository checking validates
**1,202 Rust files and 4,383 local links**, with 26 workspace packages and
25 normal dependency edges. The full lane takes 2,242.919 seconds; its
37-case applicability suite accounts for 1,226.781 seconds.

Each of the two executions of the source-integrity class prints five deliberate
FAIL receipts from rejected fixtures. Both unittest executions pass.
Those ten fixture receipts are neither actual validation failures nor ten
additional test methods. The [static result inventory](static-results-summary.json)
and [independent count audit](agent-validation/static-results-audit/stdout.log)
retain the counting boundary.

The native [before](validation-native-01/source-before.json) and
[after](validation-native-01/source-after.json) records agree, as do the
static [before](validation-static-01/source-before.json) and
[after](validation-static-01/source-after.json) records.
Each verifies **18,471 tracked entries / 1,804,323,490 bytes** on the tested
commit/tree. An identity check is not itself a test execution.

The locked default-feature workspace graph contains 26 members / 175 packages.
The all-feature graph contains **26 members / 180 packages**.
The fuzz graph contains **one member / 147 packages**.
[Graph summaries](all-feature-graphs-01/summary.json) and
[lock hashes](all-feature-graphs-01/locks.json) are retained.
Feature selection explains 175 versus 180; no lockfile changed.

This is focused native validation plus the complete repository-truth lane.
The full Cargo workspace test matrix and `native_node` were not rerun.
Inherited #794 results of 28 passed / 2 failed / 1 ignored remain in the prior
archive and are not upgraded. The original 0.25-CPU / 2-GiB hostile-load service
campaign was not rerun.

## 4. Quantum result: reject the printed general source bound

At p=1/16, three independent one-query Grover experiments on disjoint
16-point domains give

\[
q=\frac{13073}{32768},\qquad
q^3=\frac{2234219220017}{35184372088832}\approx0.063500329475.
\]

The printed general Bernoulli-query expression at the same counts is

\[
\frac{1786065+461160\sqrt{15}}{67108864}\approx0.053228884934.
\]

The strict comparison uses integers. Thirteen source-audit controls cover an
independent state-vector calculation, all 65,536 truth tables on a 16-point
domain, radical comparison and the fail-closed interface. A separate
[JavaScript BigInt check](independent-bigint-crosscheck.json) is retained.

The [machine report](validation-static-01/quantum-source-report.stdout) returns
`REJECT_PRINTED_SOURCE_BOUND` and `source_bound_usable=false`.
A passing audit reproduces the counterexample and refusal. The former
0.9379882177048045 expression is retained as algebra from the rejected printed
expression; it is not a certified chain tail.

This concerns the general Boolean-query theorem as printed. It does not
directly refute the separate 2N chain diagonal, demonstrate an actual W1/MU1
attack or execute quantum hardware. The existing independent conservative
bound covers the counterexample at p=1/16; its tested 2k/k slice for k=1..64
returns one. No unsupported nontrivial replacement is provided.

The audit is mandatory in repository-truth. Its CI contract rejects deletion,
duplication, replacement by success, false conditional execution, swallowed
failure and migration into another lane.

## 5. Preserved failures and repairs

- The [first static precheck](preliminary-static-01/commands.json) failed because
  the active recent-batch workflow retained the previous `store.rs` blob pin.
  Repository checking and three CI contract cases detected it. Exactly one
  expected blob was updated to the reviewed source. The guard structure,
  25 other guards and historical pins remain intact.
  The [pin repair](agent-validation/pins/stdout.log) and
  [CI audit control](agent-validation/ci-source-audit-gate/stdout.log)
  retain exact commands/results.
- One early read-only scan had an incorrectly escaped path. Its
  [original error](agent-validation/preflight-scan-failure/stderr.log)
  remains recorded.
- The old-source native regression remains a failed test; fixed-source success
  is a separate execution.
- Ignored controls and inherited project failures remain explicit.

## 6. Remaining gates

Production needs branch context owned by the original Node commit, reorg and
cold-recovery boundaries, with coherent invalidation and controlled capacity.
The new incremental object is bounded research. The production clock walk
uses header projections and original request checkpoints but remains O(height).

C1 target credit and MU1 fixed-probability 16u research credit remain different
contracts. New native consensus needs a parameter/wire/storage transition and
all actual admission, mining, import, recovery and migration paths. PGH2
currently exposes no sync or History import service; future entry points do
not inherit coverage by name alone.

Actual classical/quantum work-scale bounds, allowed preparation and shared
state, lifetime initial inventory, resource units, all permitted action
operators, honest growth and network/dynamic-participation composition remain
open. Nominal work units and complete verification are not cost lower bounds.

## 7. Archive interpretation

`manifest.json` records SHA-256 and byte length for every archive file except
itself. Raw packets and command-output bytes are preserved. Per-command records
and retained runner scripts provide exact arguments and explicit environment
choices; absolute paths identify this execution and must be selected for a
new run.

Counts describe recorded tests and reader cases. They do not count synthetic
fixtures as deployed events, skipped cases as passes, or a rejected certificate
as a security proof.
