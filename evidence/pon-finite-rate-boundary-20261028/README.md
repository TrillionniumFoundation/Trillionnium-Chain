# Finite classical-rate numerical boundary: independent correction

This successor preserves the finite-nonce model's namespace and all physical
cost assumptions. It closes one numerical correctness gap; it does not qualify
quantum PoN, a minimum-cost oracle, native consensus or production activation.

## Reproduced failure

On measured predecessor `d32401076e47b0a2fe1f9067049c4c7d932571e6`, the classical
baseline accepted positive finite rates near `1e-310/s` but returned infinity
and NaN for its unbounded expected time and win probabilities. Two finite
competing rates of `1e308/s` also escaped the model's typed refusal as an
unhandled summation overflow. The original [RED run](red.json) and
[raw output](red.stderr.log) retain three subcase failures and one error.

## Correction and independent checks

The classical baseline now applies the same finite-positive expected-time
boundary as the quantum campaign. An unrepresentable time raises
`EXPECTED_TIME_NUMERIC_RANGE`; competing-rate summation overflow raises
`TOTAL_RATE`. Supported tiny-rate bounded campaigns remain accepted and are
compared against a 90-digit Decimal exponential integral and probabilities.
No rate, timeout, acceptance criterion, original assertion, W1 relation,
consensus DAA, native source or report namespace was changed.

The first [GREEN run](green.json) passed 36 methods but retained one skipped
class because `rustc` was not in PATH. It is not a native DAA result. After
selecting the existing actual Rust 1.95.0 executable, the
[final execution](final-controls.json) ran **39 tests, all passing, no skips**:
21 finite-stop controls, 7 native/conditional DAA controls and 11 reversible
oracle-template controls. The native controls compiled the original pinned
consensus source with `-D warnings`; no Cargo workspace run is claimed.
All selected before/after source hashes are recorded. The complete
[raw final output](final-controls.stderr.log) is retained.

The [fixed-scenario comparison](report-comparison.json) confirms that the
[regenerated conditional report](finite-stopping.json) is unchanged apart from
the model source hash. This is a control of model arithmetic, not a measured
quantum rate or a complete quantum circuit execution. Original full W1 gate
counts remain conditional construction upper bounds. Existing whole-repository
historical evidence gaps and their prior failures remain unchanged.

## Repository checks retained separately

The source inventory, project preflight and CI contract checks pass. All 34
source-integrity negative controls pass in the corrected named invocation.
An earlier mistaken discovery pattern executed zero tests and returned 5; its
raw output remains in this evidence and receives no passing credit. The full
repository checker retains the inherited sparse-checkout failure for
`docs/README.md -> ../evidence/pon-v1/README.md`. The missing historical evidence
was not fabricated, dropped from the tree or excluded from that checker.
