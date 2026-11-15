# Conditional composition and joint-oracle evidence

Date: 2026-11-07. Fixed candidate:
`7150d96a2112875b4afcf3023361a5cef4a0e4b1`.

This directory retains independent, exact hypothetical arithmetic and a finite
joint-oracle countermodel. It does not contain a latest-paper PDF, a complete
cryptographic proof, a fresh native receipt verification, or consensus approval.
See [the formal-obligations note](../../docs/security/W1_QROM_FORMAL_OBLIGATIONS_20261107.md).

| File | Scope |
|---|---|
| `theorem-review.json` | Reviewed manuscript statements, access/version boundary, and unresolved dependency map |
| `composition-unknown.json` | Missing component and relation inputs remain unknown |
| `composition-example-input.json` | Explicit hypothetical specifications and component envelopes |
| `composition-example.json` | Exact January Theorem 10.6 expression for that example |
| `joint-oracle-unknown.json` | No actual output cardinality or encoded input is inferred |
| `joint-oracle-alias-input.json` | Toy range of 16 outputs and equal encoded inputs |
| `joint-oracle-alias.json` | Uniform marginals with equality gap `15/16` |
| `joint-oracle-separated-input.json` | Toy two-input positive control |
| `joint-oracle-separated.json` | Zero gap for that particular separated-input experiment |
| `tests.log` | Actual local execution of the two new suites |
| `validation.json` | Exact named results, command outcomes, source hashes before/after, and artifact hashes |

`initial-validation.json` and `initial-tests.log` preserve the first local
observation. Its `tests.log` digest refers to `initial-tests.log`. The final
observation follows correction of two punctuation characters in the note's
LaTeX exponents; executable source bytes and numeric report outputs did not
change. These are local observations, not two remote CI runs.

The input digests in the composition example identify invented specifications.
They do not certify implementations. Every actual security qualification stays
false and every unconditional project bit count stays null, including examples
whose hypothetical target comparison succeeds.

## Reproduction

Run preflight, then generate outputs in a new observation directory. The
following commands produce the numeric reports; redirect to the corresponding
filenames above or to a new `RUNNER_TEMP` directory. The scripts never write
into the repository by themselves.

```sh
bash scripts/project-preflight.sh --audit
export PYTHONDONTWRITEBYTECODE=1
python3 scripts/w1_qrom_composition_budget.py
python3 scripts/w1_qrom_composition_budget.py --example-input
python3 scripts/w1_qrom_composition_budget.py --example
python3 scripts/w1_qrom_joint_oracle_diagnostic.py
python3 scripts/w1_qrom_joint_oracle_diagnostic.py --example-input alias
python3 scripts/w1_qrom_joint_oracle_diagnostic.py --example alias
python3 scripts/w1_qrom_joint_oracle_diagnostic.py --example-input separated
python3 scripts/w1_qrom_joint_oracle_diagnostic.py --example separated
python3 -m unittest scripts.ci.test_w1_qrom_composition_budget scripts.ci.test_w1_qrom_joint_oracle_diagnostic -v
```

Alternatively, either script accepts its retained example input via `--input`.
Malformed input returns structured JSON on stderr and exit code 2. The tests
include deep JSON below the byte limit, duplicate keys, invalid number types,
scope mismatches, and attempts to supply actual-system qualification fields.

The local validation is not a remote CI or prospective-merge result. Hashing
source bytes binds this observation under the ordinary trusted local runtime;
it does not create an isolation or hostile-interpreter guarantee. The current
proof obligations are recorded in `theorem-review.json`, and none are discharged
merely by passing these evaluator tests.
