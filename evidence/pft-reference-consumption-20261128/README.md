# Same-candidate PFT reference consumption

This slice performs an actual bounded `XW` reference computation after checking
the same independently pinned candidate and complete statistics through #1017.
The result remains a research readout computation, with no native Adoption,
FinalUse, quality, payment or execution authority.

## Input and arithmetic frozen before execution

[PROTOCOL.json](PROTOCOL.json) was published as commit
`40a56f1bf1561145c8abcbe2131805941c1cfb2a` before any reference inference.
Its raw SHA-256 is `276782c46caa1df62ddc73537fc6ce002108743c03fec197759ff0aa76f9e70b`.
The caller must retain the expected request ID, feature-input SHA-256 and
normal-expectation-envelope SHA-256 independently of submitted inputs.
Request IDs are exactly 64 lowercase hexadecimal characters. JSON duplicate
keys and nonfinite constants refuse; expected and feature objects have exact
field sets. Candidate, complete bundle and all feature-semantic digests bind.

Each supplied row already contains all feature expansion, normalization and
bias. The consumer performs none of those transformations. For each output it
forms binary64 products in ascending feature-index order and uses `math.fsum`.
Finite zero-or-normal inputs, products and sums are required; product underflow
to zero with nonzero factors refuses. Outputs use binary64 little-endian row
order. The unchanged normal-equation threshold is checked before inference.
No transpose, quantization or native-family conversion is attempted.

## First control failure and correction

[CONTROLS_ATTEMPT_1.log](CONTROLS_ATTEMPT_1.log) preserves 11 passing controls
and one failure: the existing sum wrapper reclassified a generator's specific
`NEQ_PRODUCT_UNDERFLOW` as `NEQ_NUMERIC_RANGE`. Both refused the input, but the
expected specific diagnostic was lost. Products are now materialized in a
bounded list before summation, matching the earlier normal-equation reader.
The numerical profile and test expectation were unchanged.
[FIRST_SOURCE_SHA256.json](FIRST_SOURCE_SHA256.json) and
[FIRST_FIX.patch](FIRST_FIX.patch) retain the original source identity and exact
correction. Both attempts' detailed observations remain here.

[CONTROLS_ATTEMPT_2.log](CONTROLS_ATTEMPT_2.log) records 12/12 controls passing.
They include hand-computed outputs, fsum cancellation, rehashed wrong weights,
wrong pins, mixed feature semantics, request types, duplicate keys/rows, other
schemas, range/size refusals, a real CLI run and receipt overwrite refusal.

## One historical reference computation

[HISTORICAL_OBSERVATION.json](HISTORICAL_OBSERVATION.json) records the first
and only invocation for the frozen `n8-s17011` candidate. The producer opened
only `x.npy` in the previously SHA-pinned train `shard0.npz`, selecting that
shard's local rows 0 through 3. It did not open or decode the label array, execute the feature
program again, recompute normalization, retrain or access DEV/final-test data.
These are four local shard rows, not a claim about the first rows of all TRAIN.

The reference consumer received a 4 x 41 supplied feature matrix and the exact
previously pinned 41 x 3 candidate. Its 4 x 3 prediction byte digest is
`a254e8385df48372e9cc35ef307521976c3eca5f77e7c65b503018a626364285`.
Input and source hashes remained unchanged after the run. Full private outputs,
features, historical weights and statistics are not included in this repository.
Only the authored small synthetic feature fixture and metadata are public.
The observed wall time includes file reads, normal-equation verification and
interpreter startup; it is not a training benchmark or comparative speed result.

## Scope and reproduction

Run `python3 -B -m unittest discover -s scripts -p 'test_pft_reference_consumption.py' -v`.
The CLI takes candidate, contributions, normal expectations, features,
independent consumer expectations and a fresh receipt path. The fixed historical
runner requires the existing private cache and feature export; it opens no NPZ.
Failed normal equations preserve their original numerical observation and do
not proceed to inference. Other refusals and partial interrupted receipts retain
the same limits as earlier readers; crash durability is not claimed.

Source authenticity, actual feature-program/normalization execution, PSD,
global optimum, model improvement, consumer identity, authenticated execution,
native compatibility, native adoption/use/payment and production flags remain
false. The declared reference arithmetic does not certify cross-platform
consensus determinism or full runtime closure. Existing 98 workflow controls,
permissions, pinned actions and timeout remain; these 12 are additional.
