# Carry arithmetic backend research

This candidate replaces only the arithmetic AIR. It retains every original
`Dot8Row` produced by `PublicStatement::plans`: the same 81,920 arithmetic rows,
the same complete native SHA-256 plan, the same independently supplied header
and artifact expectations, and the same canonical public statement. Verification
reconstructs the public preprocessing from that statement in a fresh process.
There is no proof-provided verification key and no preprocessing cache.

The arithmetic transcript component is 3 and its wire magic is `W1P3ACR2`.
The original arithmetic component 2 / `W1P3ARI1` remains available as the
comparison baseline. This is a research-only example executable; it does not
activate a production verifier or change the node's acceptance policy.

## Integer relation and constraints

Let B = 65,536 and q = B² - 5 = 4,294,967,291. The public relation is

    start + sum(i=0..7, a_i * b_i) = goal + q * k.

Every public word is canonical in [0,q). Deterministically split each public
word into two base-B limbs. Preprocessed columns are the 32 input limbs,
`start_low,start_high,goal_low,goal_high`: 36 columns total. These are literal
limb decompositions of the public statement, not an external multiplication
oracle. The AIR evaluates every limb product itself.

The main trace has 35 quotient bits, 19 low-carry bits and 20 high-carry bits.
Write k = k0 + B*k1 + B²*k2, where k0,k1 have 16 bits and k2 has 3 bits. The
74 Boolean constraints and the following three equations make 77 constraints:

    sum(a_low*b_low) + start_low + 5*k0 = goal_low + B*c0
    sum(a_low*b_high + a_high*b_low) + start_high + 5*k1 + c0
        = goal_high + B*c1
    sum(a_high*b_high) + 5*k2 + c1 = k0 + B*k1 + B²*k2

Multiply the second equality by B and the third by B², and add all three.
Both carries cancel. The result is the exact public relation above.

### Soundness of integer lifting

After Boolean constraints, k < 2^35, c0 < 2^19 and c1 < 2^20. Every public limb
is less than B. Both nonnegative sides of each displayed equality are below
2^36. Goldilocks has modulus 18,446,744,069,414,584,321 > 2^63, so equality in
that field implies equality of these bounded integers. In particular, the
unreduced sum of eight 64-bit products is never evaluated in a single field
equation. This avoids the known whole-dot Goldilocks alias.

### Completeness and exact widths

For canonical public words, total <= 8(q-1)² + (q-1) = 8q² - 15q + 7. Therefore
k <= 8q - 15 < 8B² = 2^35. For a valid row, the first numerator is divisible by
B and is greater than -B, so c0 is nonnegative. Its upper bound is

    c0 <= floor((8(B-1)² + 6(B-1))/B) = 8B - 10 < 2^19.

The middle numerator is likewise divisible by B and greater than -B. Its
upper bound is

    c1 <= floor((16(B-1)² + 6(B-1) + (8B-10))/B)
        = 16B - 18 < 2^20.

Thus every true canonical row has a witness in the specified columns. Padding
rows are all zero and satisfy the same equations. The constructor rejects
empty, oversized and noncanonical tables. False canonical goals may produce
a rejecting witness; witness generation is not an acceptance test.

This is an algebraic equivalence argument for the AIR relation. It does not
supply the still-open concrete noninteractive PCS/hash/Fiat–Shamir theorem or
its lifecycle budget. Conditional RBR metadata is recomputed from the actual
new AIR, and remains explicitly conditional and non-quantum.

## Reproducible comparison

Build in the standalone crate with the exact Cargo.lock, Rust 1.95.0 and
`RUSTFLAGS='-C target-cpu=native'`, retaining the original runner as baseline:

```sh
cargo build --offline --locked --release --bin w1-full-public-stark-research --example carry_backend --example packed_carry_backend
```

`carry_backend prepare`, `prove`, and `verify` use the same argument layout as
the baseline runner. Every `prove` invocation generates both a fresh SHA proof
and a fresh arithmetic proof. The unchanged public statement is transmitted
with both proofs. Tests exercise the full retained row set, extreme inputs,
all witness-bit mutations, non-Boolean witnesses, the known Goldilocks alias,
and actual PCS proofs under changed goals, verification keys, openings and
old transcript domains. Benchmarks must include full proof generation and
independent preprocessing at verification; a faster arithmetic subphase alone
does not establish a positive end-to-end result against the native verifier.

Measurement evidence will be recorded separately after execution. The
production qualification remains HOLD_NO_GO.

## Five-lane packing candidate

`Dot8PackedCarryAir` places five consecutive original Dot8 rows into independent
lanes of one trace row. Its full table has 16,384 rows, 370 main columns and
180 public columns, with no padding for the 81,920 original relations. Each
lane enforces precisely the three equations and Boolean constraints above;
there are no cross-lane dependencies or omitted rows. Other admitted smaller
tables are zero-padded after preserving all rows in their original order.

This reduces public preprocessing cells from the ungrouped carry candidate's
4,718,592 to 2,949,120. The prior backend has 2,359,296 public cells. The wider
per-query openings are a real tradeoff and must be measured. Packing has fresh
component 4, magic `W1P3APC3`, and a separate `packed_carry_backend` example;
component 3 / `carry_backend` is retained to preserve the earlier experiment.
Neither example imports a verification key from the prover.

## Wire admission and qualification boundary

Both added examples always emit `qualification: HOLD_NO_GO`; an accepted proof
is labeled `VERIFIED_COMPLETE_W1_RESEARCH_ONLY`. They are research comparison
executables, not node ingress adapters. Their envelope decoder retains the
original research decoder. The bounded allocation/shape scanner developed for
the original component-1/component-2 profile has **not** been extended to these
new arithmetic profiles. No global malicious-rejection cost bound follows for
component 3 or 4. They must remain outside production admission until a fixed
shape scanner, allocation budget, cross-profile rejection tests and resource
qualification are implemented for each new profile.

| Arithmetic profile | Component | Wire magic | Full trace degree bits | Main columns | Public columns |
| --- | ---: | --- | ---: | ---: | ---: |
| Original per-product quotient/remainder | 2 | `W1P3ARI1` | 17 | 516 | 18 |
| Carry, one lane | 3 | `W1P3ACR2` | 17 | 74 | 36 |
| Carry, five lanes | 4 | `W1P3APC3` | 14 | 370 | 180 |

All three retain the original SHA component 1, magic `W1P3SHA1`, degree bits 13,
7,728 main columns and 27 public columns. These shape differences are not
selected by any untrusted wire field: each example fixes its own profile.
A new profile also needs its own explicit verifier input admission rule; merely
adding another accepted component integer to the original scanner would be
insufficient.

The same concrete noninteractive PCS/hash/Fiat–Shamir and lifecycle-accounting
obligations remain open. The complete statement is public and nonsuccinct.
An improvement relative to the previous STARK implementation does not establish
positive end-to-end benefit relative to native W1, a universal physical work
lower bound, or production Node qualification.

## Completed measurement evidence

The observed comparison, including the unpacked verifier regression and the
separate 2 GiB single-fixture resource check, is recorded in
[CARRY_MEASUREMENTS.md](CARRY_MEASUREMENTS.md). The complete raw manifests,
resource outputs, strict-check logs and failure ledger are retained under
[evidence/carry-backend-20261108](evidence/carry-backend-20261108).

To repeat the ABBA experiment on an already built checkout, choose a new output
directory and arrange the external CPU/memory controls before invoking:

```sh
python3 run_carry_comparison.py --out /tmp/w1-packed-carry-new-run --variant packed --blocks 2 --threads 8
```

The harness rejects an existing output directory, binds both variants to the
same allowed CPU set, records the observed cgroup controls and retains each
failed run. `--variant carry` selects the ungrouped comparison. The harness
never changes the FRI profile or authorizes production acceptance.
