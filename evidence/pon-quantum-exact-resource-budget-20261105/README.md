# Exact failure-budget decisions in conditional quantum resource accounting

Status: **research-only; no security or deployment qualification**.

## Fixed input and scope

The baseline is Chain `ffb43113b2e0065e6a8053bdb25fc5a9d7cf0637`.
The original `quantum_oracle_resources.py` Git blob is
`c923cd5e5d2b3bf5aa704fec8dec7f9409297568`; the original test blob is
`4880a5f3d04f620559a7f2fa90cde73f1a47e4ed`.
The two changed files are under `formal/pon-nakamoto-v1/`.
Exact final bytes, hashes, commands and raw-output hashes are in `manifest.json`,
`red-result.json` and `green-result.json`.

This change compares the model's magic-state and total failure budgets using
exact rational values of the supplied decimal inputs. The existing 100-digit
Decimal arithmetic and 30-significant-digit output formatting are retained for
presentation. No physical assumption, allowable code distance, error budget,
T-gate decomposition, activation flag or proof parameter is changed.

## Reproduced failures

The distance counterexample is an exact negative Pell solution:
start with `x = y = 1`, then apply
`(x, y) = (3*x + 4*y, 2*x + 3*y)` 123 times. Thus `x*x - 2*y*y = -1`.
The legal 100-character inputs use `physical_error = y / 10^98` and
`threshold = x / 10^98`. For the declared one-gate workload and distance 3,
the model's exact failure estimate is

```text
30 * 0.01 * (y/x)^2 = 3/20 + 3/(20*x*x) > 0.15.
```

At precision 100 the original implementation rounds away the positive excess
and returns `CONDITIONAL_ESTIMATE` at distance 3. With maximum distance 3 the
correct result is `NO_DISTANCE_IN_DECLARED_RANGE`; when the existing allowed
range is extended to 11, the first feasible distance is 11. The complete
original input and actual output are preserved in `before-fix.json`.

A second control uses `t_count = 10^60 + 1` and
`magic_state_error = (10^60 - 1) / 10^121`. The exact magic-state term is
`0.1 - 10^-121`, leaving positive headroom within the declared budget.
The supplied logical-error term is smaller than that headroom. The original
Decimal comparison rounds the magic-state term to 0.1 and incorrectly rejects
the model. Exact comparisons accept the valid distance without changing the
rounded presentation.

## Executed validation

| Check | Actual result |
| --- | --- |
| Original source with three new controls | 3 run: 2 FAIL, 1 PASS; exit 1 |
| Patched source, all resource controls | 25 PASS (22 existing + 3 new); exit 0 |
| Exact total-failure equality | Still accepted at the existing inclusive boundary |
| Existing incomplete-W1 and hypothetical example reports | Both complete report objects unchanged |
| Python compile, final newlines, trailing whitespace | PASS for both changed files |

`red.stderr.log` and `green.stderr.log` are unmodified captured unittest
output. Both corresponding stdout logs are empty. The patch is preserved as
`exact-budget.patch`. Commands ran in an independent small directory; they did
not modify the integration checkout or restart the interrupted W1 proof.

## Source-contract impact and open claims

Neither changed file is pinned or required by the baseline
`config/pon/pq-cross-branch-corpus-v1.json`
(blob `32714148c0c737c0f8532c4777013953420201e8`, 468 pins).
This patch requires no substitution of an existing corpus pin. Its exact bytes
must still be covered by the final frozen-commit source check, and the combined
quantum suites must be rerun there; those integration checks are separate from
the isolated results above.

This is arithmetic correctness for an explicitly hypothetical surface-code
model. It supplies no circuit calibration, fastest legal solver lower bound,
full W1 proof, complete quantum attack model, QROM proof, protocol security
threshold, or production authorization. Existing research/HOLD assertions
remain unchanged.
