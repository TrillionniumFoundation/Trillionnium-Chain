# Lifetime and independent acceptance observations

Base source: `7150d96a2112875b4afcf3023361a5cef4a0e4b1`.
This directory records new exact accounting/source-survey observations.
It does not certify a deployed budget, signature, receipt, quantum resource
lower bound, consensus admission or post-quantum Chain.

- [Project input](project-input.json) explicitly leaves lifetime/query/error
  values unknown.
- [Project report](project-report.json) binds twenty selected source files and
  retains three independent unqualified acceptance lines.
- [Counterexamples](counterexamples.json) reproduce budget-reset, adaptive
  selection, whole-life target and conditional weight/cost discrepancies.
- [Observation manifest](observation.json) binds commands, exit codes and
  script/input/output hashes.
- [Unit-test log](unit-tests.stderr.log) retains nineteen controls.
- [Detailed contract and interpretation](../../docs/security/W1_LIFETIME_AND_INDEPENDENT_ACCEPTANCE_20261107.md)
  states the premises and exclusions.

To regenerate a report from the repository root:

```sh
python3 scripts/w1_lifetime_ledger.py \
  --input evidence/pon-w1-lifetime-20261107/project-input.json
python3 -m unittest discover -s scripts/ci \
  -p 'test_w1_lifetime_ledger.py' -v
```

Source anchors are reviewed source observations, not a semantic proof or fresh
execution of the programs they describe. The selected purpose roster is not
an exhaustive whole-system inventory. All real lifetime counts/error bounds
remain unknown; no numerical project target is passed.
