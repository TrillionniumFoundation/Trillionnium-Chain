# W1 CI successor union with retained named tests

This independent v2 preparation supersedes the proposed CI target in
`upstream-union-ci/`. That v1 directory and its 4,808-byte patch remain unchanged.
No frozen C2/C3 source, integration-owner file, repository checkout or remote
branch was edited. This directory contains preparation bytes, not a successful
test or merge receipt.

## Exact prepared scope

The incremental `c3-upstream-retained-test-union.patch` is against the exact
frozen C3 inputs recorded by `manifest.json`. It changes only:

- `scripts/ci/w1_native_controls.py`
- `scripts/ci/test_w1_factorial_native_gate.py`

The candidate W1 workflow is included as a byte-identical copy of the frozen C3
helper-based workflow for conflict resolution. It is not another patch delta
against C3. The helper equals the v1 prepared helper: the two example suites
require zero filtered tests; all zero-measured, exact-name, serial/nocapture,
bounded-reader, ignored-child, log-hash and completion-report checks remain.

## Retained named test roster

The prepared file contains exactly 18 named test methods:

- All 12 original C3 methods, with their original class and method names.
- All 9 upstream df927 methods, with their original class and method names.
  Four names are shared with C3 and appear once, so this adds five methods.
- One positive test for nonzero filtered counts in the four suites that use
  native harness filters: kernel, history-W1, history-import and CPU-completion.

`retained-test-roster.json` lists every qualified class/method identity and the
intersection. It can supply the later actual-execution denominator; its count
does not claim that any test has run.

The two upstream-only `NativeGateTests` methods retain their original bodies:

- `test_factorial_example_rejects_missing_duplicate_replaced_or_failed_named_control`
- `test_factorial_example_does_not_accept_filtered_or_measured_tests`

The three upstream `LegalGateTests` methods also retain their original bodies:

- `test_complete_current_native_roster_passes`
- `test_every_retained_versioned_material_and_observer_control_executes_once`
- `test_summary_only_stale_filtered_duplicate_or_failed_summaries_are_refused`

Their fixtures now supply the serial harness header expected by the C3 helper,
and their runner invokes the real helper CLI instead of extracting removed
inline workflow code. The unique five method bodies are AST-identical to the
upstream source. They execute their own positive or refusal matrices; no method
is an empty wrapper or merely calls another test. The legal runner additionally
checks successful report names, byte counts and hashes, and absence of a
completion file on refusal.

Eleven C3 test bodies remain AST-identical. The remaining C3 test retains its
original summary-refusal matrix and adds upstream's duplicate FAILED-summary
case. The explicit History name list equals the upstream list; the complete
frozen suite roster is unchanged. V1's broad new summary test is replaced here
by the upstream named methods, so it does not create an extra duplicate count.

## Static preparation and remaining execution

The preparation script checked exact source hashes, parsed the Python ASTs,
compared the retained method-name union and five original method bodies, and
verified the unchanged SUITES/GROUPS values and upstream example-name sets.
It did not import the gate or execute any tests, native code, Cargo command or
merge. The input upstream test blob is
`f48a131c4167222a3e0f020ad8822a46e27840eb` at
`df927b6ffaecff293b9e9428e3ba516f47cd101a`.

Project preflight was attempted before editing on the retained partial baseline
and returned 128 because it is not a Git checkout. The exact observation is in
`preflight.json`; no preflight pass is claimed. The later actual merged checkout
must run its own project preflight and validation cohort.

The upstream merge, corpus union and generated source inventory remain separate
integration steps. Preserve frozen C2/C3/C4 and upstream evidence identities;
normal two-parent ancestry does not make either side's earlier results results
of the merged commit. Keep the earlier C2 selected-source bindings where their
selected source paths remain identical; do not relabel them as fresh execution.
