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

## Independent hosted execution of the published source

The exact published source `c3a13bcf50a46826974681f4b837f291278bcaf5`, tree
`cb0fd0babc23a5edbd4db72512ea97f2aae00b2e`, completed
[run 40607357176](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40607357176),
job `122550076247`. The full source reader checked all 5,900 tracked entries /
767,349,936 bytes before and after execution; both observations identify that
same source and tree. The original job log contains the after observation;
the workflow did not create a separate source-after file.

The original 11 reversible-template, 7 native/conditional-DAA and 21 finite-stop
tests all executed and passed, with zero skips. These are a second observation
of the same 39 methods, not 78 distinct tests. The real compiler was Rust
1.95.0. The scoped workflow does not execute the complete Cargo workspace or
qualify physical quantum cost, independent security or consensus activation.

Artifact `12780873625` is 13,436 bytes, SHA-256
`b18b1082219001ff2a96cded0e42e10225fa8da29ad9409e6a57bcfaa79f2bd0`.
All nine original ZIP members passed CRC, size and SHA-256 readback. The
[original archive](hosted-c3a13bcf/artifact.zip),
[complete compressed job log](hosted-c3a13bcf/job.log.gz),
[archive manifest](hosted-c3a13bcf/archive-readback.json) and
[independent result checks](hosted-c3a13bcf/verified-readback.json) are retained.
The initial sandbox network refusal is recorded in
[acquisition provenance](hosted-c3a13bcf/acquisition.json); the separate approved
read-only download matched the expected archive hash. No executable source or
test assertion changed while preserving this observation.
