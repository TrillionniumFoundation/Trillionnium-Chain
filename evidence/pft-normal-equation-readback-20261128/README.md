# Conditional PFT normal-equation readback

This independent stdlib reader checks the weights against a complete, separately
SHA-256-pinned contribution bundle. The existing #1016 candidate identity reader
is a dependency. No training module, NumPy solver, native model owner or payment
owner is imported. The only numerical acceptance statement is
`normal_equations_consistent_with_supplied_bound_statistics`.

## Frozen numerical profile

[PROTOCOL.json](PROTOCOL.json) was committed as
`b981237d3538e02bd537150942d9d1b62a8e72c3` before implementation controls or any
historical residual computation. Its raw SHA-256 is
`f45cd7d98f2a3367575ade2608e53ade1b02614ede0f001e3cf39ae7eef51353`.
Neither threshold nor numerical profile was adjusted after observing results.

For each output column, the acceptance statistic is
`||A W_j - H_j||inf / (||A||inf * ||W_j||inf + ||H_j||inf) <= 1e-10`,
where `A = sum(G) + lambda I` and `H = sum(rhs)`.
Each scalar aggregate uses `math.fsum` in ascending batch-ID order; lambda is
included once per aggregate diagonal. Residuals use `fsum` of binary64 products.
Gram and yTy symmetry uses `1e-11 * max(1, abs(left), abs(right))`, with no averaging.
The zero-denominator case requires an exactly zero computed residual.

Inputs and working sums/products must be finite and zero or normal binary64;
overflow, subnormal values and zero products of nonzero factors refuse. Extreme
but otherwise legitimate scales can therefore be refused without concluding
that their normal equations are inconsistent. The final scaled-error division
can round an extremely small ratio to zero; reported zero is a floating-point
observation, not an exact-arithmetic certificate. It cannot cross the fixed
`1e-10` acceptance threshold through that underflow.

## Identity and refusal boundary

The expected candidate tuple and raw bundle digest must be retained independently
of the submitted inputs. Every packet payload is rehashed. Contract, complete
head material, revision, sample count, shapes and declared sample IDs must agree.
Repeated batch IDs, including identical packets, refuse; this does not change
the producer ledger's idempotent-append behavior. Sample-ID reuse within or
across supplied packets refuses. This establishes uniqueness of declarations
in this bundle, not authenticated distinct people, raw data or compute.

The frozen profile caps bytes, packets, scalar elements, samples and dimensions.
Wrong digests, mixed contracts, malformed JSON, booleans and nonfinite values
refuse before acceptance. The CLI reserves its receipt path exclusively and
preserves numerical failures and caught input exceptions. An interrupted writer
can leave a partial file; this is not a crash-durable transaction protocol.

## First observations

[CONTROLS_FIRST_RUN.log](CONTROLS_FIRST_RUN.log) records 16/16 passing tests.
[CONTROLS_FIRST_OBSERVATIONS.json](CONTROLS_FIRST_OBSERVATIONS.json) retains
returned numerical refusals and observed input exceptions, as well as accepts.
Controls include rehashed wrong weights, per-packet lambda, fsum cancellation,
duplicates, reuse, mixed contracts, malformed shapes, NaN, bool and range/size
limits. An intentionally indefinite Gram also satisfies its supplied equation;
the corresponding PSD and global-optimality claims remain false.

[NINE_PARENT_NORMAL_EQUATIONS.json](NINE_PARENT_NORMAL_EQUATIONS.json) contains
the first read-only numerical observations for all nine existing historical
synthetic-source research caches: 9/9 consistent, each with four packets and
192 declared samples. Shapes are 41 x 3, 161 x 3 and 321 x 3. Maximum scaled
backward error is `4.2177906270975174e-17`; the nine maxima range down to
`1.4840879815466563e-17`. This is a verification observation, not training speed.
The old committed #1016 tuple and previously retained inventory pinned all inputs.
[FROZEN_SOURCE.json](FROZEN_SOURCE.json) records the exact first-run source hashes.

Only authored small synthetic matrices are included here. Historical receipts
contain hashes, shapes and scalar diagnostics; private weights, statistics,
training shards and final-test data are not copied into this repository.
No retraining or final-test read occurred.

## Reproduction and remaining limits

Run `python3 -B -m unittest discover -s scripts -p 'test_pft_normal_equation_readback.py' -v`.
The CLI takes candidate, contributions, independent expectations and a fresh
receipt path. `scripts/pft_normal_equation_historical_readback.py` takes the
existing private cache root and a fresh output directory; its prior inventory
and readback pins are fixed, and it retains every parent result or exception.
The PR workflow adds the 16 synthetic controls to the retained 75 controls.

Residual acceptance does not prove real sample provenance, authentic Gram/rhs,
PSD, global optimality, independent evaluation, useful gain, execution, replay
or Sybil resistance, native compatibility, adoption, consumer use or payment.
All corresponding receipt claims and all authority/activation flags stay false.
Full native Cargo, Clippy and Rust formatting gates were not run in this local
Python-only environment. Existing remote checks remain independent requirements;
no gate is relaxed or replaced by these observations.
