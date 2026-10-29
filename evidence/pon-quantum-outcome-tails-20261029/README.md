# Quantum finite-domain outcome-tail correction

These are original local observations of the conditional research correction
on parent `0682274361e529cd6a8e13285324c3c9ee0744b8`. The four reviewed source
files form candidate tree `8254f7f9e0675d73263849f7ab9c0dd0a0c3dbe6` before
this evidence directory was attached. The published tree therefore has a
different identity. The source-file hashes in `final-validation.json` bind the
code and documentation actually checked; evidence attachment does not relabel
the local run as a hosted run or a full-workspace verification.

## Reproduced failures

The final original-source regression executes the final tests against the
unchanged parent implementation. It records **three behavioral failures and
two missing-new-API errors across five methods**. These are two numerical
defects, not five independent vulnerabilities:

1. With `N=2**64, M=N-1, j=0`, the original single-worker budget and
   multiple-worker race both erased the actual `2**-64` failed tail.
2. With `M=3*N/4 +/- 1, j=1`, the original success projection was approximately
   `733325.0771172694` times the independent exact cubic result. At exactly
   `M=3*N/4`, its small nonzero residual also differed from the correct zero.

The new dual-tail API does not exist in the parent; its two missing-API errors
are retained explicitly rather than counted as additional numerical defects.
An earlier development red run reported two failures and three errors before
the scalar-projection check was added; the final retained red log is the one
named `final-regression-original-source.stderr`.

## Actual validation

All **56 methods passed, zero skipped**: 11 actual reversible-template/full-W1
classical controls; seven native DAA controls with actual Rust 1.95.0
compilation; 26 known-M stopping controls; and 12 unchanged unknown-M controls.
The 21 original stopping methods retain their original ASTs. Four complete
model reports were also generated with successful process exits. The original
failed sparse-checkout attempt lacked `config/pon/ledger-v1.json`; after
materializing the unchanged pinned configuration, all 11 W1 controls ran and
passed. That failed discovery is not counted as a successful execution.

`final-validation.json` records exact commands, process exits, wall times,
compiler identity, output hashes and changed-file hashes before/after the
run. `manifest.json` hashes the copied original outputs. Native W1, native DAA,
complete logical oracle and unknown-M source files remain byte-identical to
the parent. The finite-stopping JSON uses the new v2 report schema.

From a complete checkout, reproduce the selected controls with:

```sh
export RUSTC="$(command -v rustc)"
python3 -B -m unittest discover -s formal/pon-nakamoto-v1 -p test_w1_oracle_blueprint.py -v
python3 -B -m unittest discover -s formal/pon-nakamoto-v1 -p test_quantum_daa.py -v
python3 -B -m unittest discover -s formal/pon-nakamoto-v1 -p test_quantum_stopping.py -v
python3 -B -m unittest discover -s formal/pon-nakamoto-v1 -p test_quantum_unknown_marked.py -v
```

The local checkout materialized only selected exact Git blobs. Full-workspace
Cargo, strict Clippy and hosted exact-head workflows are not claimed by these
records. Production activation, minimum-cost legal quantum oracle, physical
quantum timing and whole-chain security remain unqualified. No W1 predicate,
native DAA, mining budget or additional-PoW policy was changed.
