# Native execution certificate evidence

This directory contains **synthetic finite-model accounting**, a readback of
pinned native source bytes, and tests of a refusal-preserving record checker.
It contains no newly observed native network execution and no calibrated
physical, quantum, or confirmation-risk parameter.

## Files and evidence classes

- `model_evidence_v1.json`: eight explicitly labeled model fixtures, nine
  failure-observation pairs, recomputed deterministic results, and SHA-256
  bindings to the checker, tests, theorem note, and principal native source.
- `native_source_readback.json`: local source files read back against Git
  commit `2789e9d9999920d858c1b65d3bff29122079cb4e`; source facts only.
- `unittest_initial.log`: the first 35-test run, including the retained
  fixture expectation failure. The expected pacer event sequence was 40;
  replay correctly placed it at 39. The test expectation was corrected.
- `unittest_final.log`: all 35 tests passing after that expectation correction.
- `verification.json`: exact commands, model scope, refusal flags, and evidence
  readback outcome. Model numbers do not represent native security risk.

The tests cover 2,601 score triples for the exact availability/selection
deficit identity, the eight model counterexamples and nine pair witnesses,
early partial delivery, hidden and honest competing inventory, stale parent
completion, same-timestamp causal boundaries, unit-weight batches,
six-successor plus work arithmetic, event/owner/generation/coverage failures,
deadline censoring and retention loss, provenance relabeling, separate
resource dimensions, source/report tampering, and explicit native
qualification refusal.

## Reproduction

Run from the repository root:

```sh
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_native_execution_certificate.py' -v
python3 formal/pon-nakamoto-v1/native_execution_certificate.py --verify-evidence evidence/pon-work-native-certificates-20261107/native_execution/model_evidence_v1.json
```

The first command runs model-record tests. The second recomputes the exact
model evidence and source bindings. Neither executes native node mining,
authenticates private-world coverage, or derives an actual risk probability.

## Qualification boundary

`native_runtime_attested`, `probabilistic_environment_bound`,
`six_successor_risk_qualified`, and `native_execution_qualified` remain false
for every model and for records merely relabeled as native. There is no
implemented trusted native execution adapter. A source hash or supplied
clock/signature/owner string is not such an adapter.

The theorem note is
[`NATIVE_EXECUTION_CERTIFICATE_V1.md`](../../../formal/pon-nakamoto-v1/NATIVE_EXECUTION_CERTIFICATE_V1.md).
Its deterministic ledger and conditional pacer lemma do not equate the
research MU1 `16*u` counter with current native `required_work(target)`.
No weight-identity bridge or conditional fresh-state theorem is supplied.
