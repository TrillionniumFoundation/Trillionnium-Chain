# PFT typed binary64 preparation v1

Frozen before execution. Parent: `4f0a1ea9c37a545a454dd17b3901cf800340311e`.
This independent M15 research module does not change int257, TMT1, adoption,
ordinary dispatch, FinalUse, payment or consensus. No user B is created.

## Types and comparison pins

Model schema: `trnm.pft.typed-f64-readout.v1`; family:
`hcsn-pft-readout-research-v1`; arithmetic profile:
`trnm.pft.binary64-rounded-products-exact-sum-rne.v1`.
The model descriptor contains candidate/contract/head/weight SHA-256 labels,
feature-program/normalization/time-semantics SHA-256 labels and shape `d × m`.
All labels are nonzero 32-byte values; `1 <= d <= 1024`, `1 <= m <= 32`.

The caller supplies a separately retained expected descriptor and expected
weight bytes. Both descriptor and complete bytes must compare exactly before
preparation. Binary encoding is IEEE binary64, little-endian, C row-major;
length must be exactly `8*d*m`. The module decodes and owns its immutable copy.
It does not hash the labels or authenticate their source. A caller controlling
both inputs can supply matching false claims. This is input consistency only.
The existing #1016/#1019 readers remain the separate SHA verification layer.

Input schema: `trnm.pft.typed-f64-input.v1`. Its exact Rust fields bind candidate,
weight, contract, feature-program, normalization and time-semantics labels,
request ID, source, ordered-row digest, feature-packet digest, rows and dimension.
All digest/ID values are nonzero 32-byte values. A separate expected descriptor
and complete feature bytes must compare exactly. `1 <= rows <= 256`; dimension
must equal `d`; exact length is `8*rows*d`. Prepared input is tied to the model
descriptor, so another model cannot consume that typed handle. No bias,
normalization, feature execution, transpose, quantization or class selection is
performed. Outputs are dense `rows × m` readout values, not actions or labels.

## Arithmetic

Host binary64 multiplication must use round-to-nearest, ties-to-even, without
fast-math or contraction. Each product `X[row,k]*W[k,col]` is an ordinary, separate
binary64 multiply, visited in ascending `k`; no FMA or floating-point accumulation
is used. Inputs must be finite and zero or normal. Nonfinite products refuse;
nonzero factors producing zero or a subnormal product refuse.

Every nonzero rounded product is decomposed into sign, 53-bit significand and
an integer multiple of `2^-1074`. Positive and negative magnitudes accumulate
separately in 33 fixed `u64` limbs, are subtracted exactly, and are rounded only
once to binary64 with nearest/ties-even. Each finite product magnitude is less
than `2^2098` integer units; at most 1024 terms sum to less than `2^2108` units.
33 limbs provide 2112 bits, including the full worst-case unsigned magnitude.
There is no intermediate floating-point sum overflow: large cancellation is
allowed. Final overflow or a nonzero subnormal sum refuses. Exact cancellation
and all signed-zero products produce positive zero. Input signed zeros retain
their original byte identity even though a zero output is canonical positive.

This is a new arithmetic profile, not a claim of all-input equivalence with
Python `math.fsum`. In particular, Python can refuse an intermediate overflow
that the exact accumulator cancels. Host floating-point environment and compiler
behavior are assumptions; this preparation does not attest them or establish
cross-platform consensus determinism. Output rounding is implemented with
integer bit operations, without a second floating-point rounding step.

## Frozen verification scope

Pure-std controls cover independent known IEEE octets: large cancellation,
small tails, halfway-even and halfway-odd rounding, permutation invariance,
signed zero, minimum normal values, product underflow/overflow, cancellation to
subnormal, output overflow, all shape boundaries, wrong descriptors, byte
mutation, owned-buffer stability and cross-model typed-input refusal.
One bounded `rustc --test` command uses the exact frozen source. The complete
crate's source/graph/build/Clippy checks remain distinct CI requirements.

The only private observation may reuse the already frozen historical
`n8-s17011` candidate and `FEATURE_INPUT.json` SHA-256
`26456299b8fc9ac79914f8ac5762280329ebf3ced28c3e2d4420f7e95d1dd9e0`:
the original shard0 local rows 0..3, shape `4 × 41`, with `41 × 3` weights.
Compare all resulting binary64 output bytes with the existing #1019 output.
Do not read labels, DEV or final data, execute features, refit or expand samples.
Public evidence contains only small synthetic data, digests, shapes and refusal
semantics. Original private weights, features and predictions stay private.
Preserve the first failure and all numerical refusals; do not adjust the profile
after seeing results. All provenance, quality, native-adoption, current-permission,
FinalUse, production, reward, settlement and consensus claims remain false.
