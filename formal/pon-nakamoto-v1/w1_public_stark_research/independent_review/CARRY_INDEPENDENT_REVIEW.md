# Independent carry AIR review

## Outcome and scope

The separate source and mathematics review found no blocking defect in the single-lane carry AIR at commit `ac4927c52266e7bd1fae547f92a1d0753f4f96d6`, or in the subsequently reviewed five-lane source snapshot identified below. The result covers the integer relation, witness ranges, canonical preprocessing, row packing and emitted AIR constraints.

The production qualification remains **HOLD_NO_GO**. These findings do not establish the concrete noninteractive PCS/hash/Fiat–Shamir theorem, its lifecycle budget, quantum security, physical work hardness, production resource bounds, Node admission or end-to-end performance.

Both reviews were read-only. No Rust build, Rust test or performance run was executed by this reviewer. Existing Rust tests were read as source; their presence is not recorded as an independently observed pass. The reviewer checked exact integer bounds and, for packing, enumerated all 81,920 logical row indices using integer arithmetic.

## Evidence and source identity

[The original read-only evidence](readonly-review-ac4927c.json) retains the committed v2 source, selected supporting source, Git identities, exact arithmetic results and the fixed-revision Node checks. It is copied byte for byte, without adding the later packed review to that JSON:

- Schema: `trnm-readonly-carry-and-node-review-evidence-v1`.
- Size: 91,458 bytes.
- SHA-256: `c3d15b152a73dd5103c177f0c950d716b80f27f7a47ff3b5ae4232fa93b0cd33`.

### Review A: committed single-lane v2

The reviewer read Git objects at `ac4927c52266e7bd1fae547f92a1d0753f4f96d6`. All following paths are relative to `formal/pon-nakamoto-v1/w1_public_stark_research/`.

| Source | SHA-256 |
|---|---|
| `src/arith_carry_air.rs` | `7ffa6f080126b38e035adf793d1e83c0bf8415d9b13bb6ccd8505f5aa5259734` |
| `CARRY_BACKEND.md` | `595ea82150b6d1b67067a63419e896240d63c7aea57ff19bc906a811e3207131` |
| `src/arith_air.rs` | `c320c54560b8e7cf645b37721f23622b69685d83c4ed965afece009cb71cb363` |
| `src/proof_config.rs` | `3e5dad9185e4218e375d465e3ea0a0d90407c85a000aa9a60474b7cbfb78d3d8` |
| `examples/carry_backend.rs` | `7d2e5bd4df088c76b8ede3cad18bd1e2669c2dd7b52296285703a0dd586c2cb2` |
| `tests/carry_proof.rs` | `0a62231cd23c94d9ba20068f30e90afa117b7cec50e3dca3f70b41257e570889` |

The main AIR Git blob is `b4c3938fc9827b8c2c781d6e251cd4958a9b403a`; the reviewed design note blob is `41b923ab0d7180e032ab86ccc7c3191f3ec8c490`. Both blob identities were independently recomputed from the retained bytes. The retained Cargo.lock SHA-256 is `35e29723f30ca10dd6712403456755ac41cb8d73d963ab73f8cbd7a8d69d3ae1`.

### Review B: five-lane source snapshot

This review was performed on the local source snapshot at `/workspace/scratch/f16ac5871196/backend_gain/w1_public_stark_research/`. No final packed commit was supplied to this review. The review is bound to these exact file hashes, not to the directory name or a subsequently reported benchmark:

| Source | SHA-256 |
|---|---|
| `src/arith_carry_air.rs` | `6524719eaa69e1c24e67ff4e82f26676612dcfc9b45da8d4a8ce08885dc56ec1` |
| `src/proof_config.rs` | `255596c0a1bc226916f18a50f6c04b3b8c057c0bd15914d6dc79cfc990902283` |
| `examples/packed_carry_backend.rs` | `35e01c56689273ce989bf80b4018bfd10476c40af36412cdd70960828fad2ddd` |
| `tests/carry_proof.rs` | `96659e082dd50dacdc08856576e4cbb47ebabf32786bb3c44a2f24620f1b3639` |

A final integration commit can associate itself with this review by retaining the matching bytes or explicitly reconciling any changed scope. Later edits are not implicitly included in the reviewed snapshot.

## Single-lane integer relation

Let B = 65,536, q = B² − 5 = 4,294,967,291, and P = 18,446,744,069,414,584,321 be the Goldilocks modulus. All original `Dot8Row` words are canonical integers in [0,q). The constructor checks this, and the verifier reconstructs their two base-B limbs in 36 preprocessed columns.

Write each input as a low and high limb, and define S0 = sum(a_low*b_low), S1 = sum(a_low*b_high + a_high*b_low), and S2 = sum(a_high*b_high). The witness uses k = k0 + B*k1 + B²*k2, with 16, 16 and 3 bits respectively, plus 19-bit c0 and 20-bit c1.

The three separately asserted equations are:

```text
S0 + start_low + 5*k0 = goal_low + B*c0
S1 + start_high + 5*k1 + c0 = goal_high + B*c1
S2 + 5*k2 + c1 = k0 + B*k1 + B²*k2
```

After lifting each equation to the integers, adding them with weights 1, B and B² cancels both carries. The result is exactly

```text
start + sum(a_i*b_i) = goal + (B² − 5)*k.
```

The signs and all three quotient coefficients match the source. Crucially, the lifting is performed separately before this weighted integer addition. The full eight-product sum is not required to fit in Goldilocks.

### Bounds for arbitrary Boolean witnesses

The bounds below use only the stated Boolean witness widths and canonical public limb bounds. They do not assume that an adversarial witness came from the honest generator.

| Equation | Maximum left side | Maximum right side |
|---|---:|---:|
| Low limb | 34,359,083,010 | 34,359,738,367 |
| Middle limb | 68,718,297,097 | 68,719,476,735 |
| High limb | 34,359,738,410 | 34,359,738,367 |

All six sides are nonnegative and strictly below 2³⁶ = 68,719,476,736, which is below P. Equality modulo P therefore implies equality of the corresponding bounded integers. This excludes the previous whole-dot Goldilocks wraparound within the reviewed AIR relation.

### Completeness and range margins

For a true canonical row, T = start + sum(a_i*b_i) is at most 8(q−1)² + (q−1) = 8q² − 15q + 7. Thus its quotient fits in the specified bits:

| Witness | Valid-row upper bound | Bit capacity minus bound |
|---|---:|---:|
| k | 34,359,738,313 = 8q−15 | 55 below 2³⁵ |
| c0 | 524,278 = 8B−10 | 10 below 2¹⁹ |
| c1 | 1,048,558 = 16B−18 | 18 below 2²⁰ |

Each carry numerator is divisible by B for a true row and is greater than −B; hence it is nonnegative. The upper bounds follow from

```text
c0 <= floor((8(B−1)² + 6(B−1))/B) = 8B−10
c1 <= floor((16(B−1)² + 6(B−1) + (8B−10))/B) = 16B−18.
```

Consequently the generator's saturating subtractions do not change valid witnesses. An incorrect canonical goal can produce a rejecting witness; witness generation does not decide acceptance. The u128 total, its u64 quotient conversion and the u64 limb accumulators all fit their respective integer types under the constructor's input bounds.

### Preprocessing, padding and symbolic shape

The preprocessed cells are literal limb decompositions of the original rows. The AIR evaluates their limb products itself. The reviewed verifier clones all original rows produced by `PublicStatement::plans(&expected)` and rebuilds preprocessing with `setup_preprocessed`; it does not accept a proof-supplied verifier key.

A padding lane has all-zero public limbs. The lifted relation forces q*k = 0, and then the low and middle equations force c0 = c1 = 0. Its witness is therefore uniquely zero. Padding has a satisfying extension for every valid real-row table and introduces no extra requirement on its real statement.

The single-lane AIR emits 74 Boolean constraints and three separate equations, for 77 constraints. All accesses are to the current row. There is no transition selector; the highest constraint degree is two. The reviewed metadata constructs `AirLayout` from the actual 74/36 widths. In the fixed non-ZK configuration, the statically derived quotient count is one and the batched-function count is 74 + 36 + 2 = 112.

## Five-lane assembly

`CarryAir<LANES>::new` admits only LANES = 1 or 5. It retains the original logical rows in order and sets the physical height to `max(4, next_power_of_two(ceil(real_rows/LANES)))`.

For five lanes, write logical row i as i = 5*r + lane, with 0 <= lane < 5. The generated main and preprocessed slices have exactly these starts:

```text
main:         i*74 = r*370 + lane*74
preprocessed: i*36 = r*180 + lane*36.
```

The same lane offsets are used in `eval`. The index check enumerated all i from 0 through 81,919, established both identities, and verified that every position maps into one physical row/lane pair. Since 81,920 / 5 = 16,384 = 2¹⁴, the full table fills every lane without padding. There is no dropped or duplicated logical row.

For shorter tables, both allocated buffers are initially zero and only real logical rows are filled. This covers unused lanes in the final partial physical row as well as later padding rows. Each unused lane independently obeys the zero-row argument above.

Inside `eval`, each iteration slices its own 74 witness bits and 36 public limbs, initializes its own three accumulators, and makes its own 74 Boolean assertions and three equality assertions. Residuals from different lanes are not added together before assertion. The single-lane algebraic proof thus applies separately to every lane. Normal P3 batching of these emitted constraints remains part of the separately unresolved proof-system soundness analysis.

The resulting full-table shape is:

| Item | Single lane | Five lanes |
|---|---:|---:|
| Original logical Dot8 rows | 81,920 | 81,920 |
| Physical trace height | 131,072 | 16,384 |
| Main width | 74 | 370 |
| Preprocessed width | 36 | 180 |
| Emitted constraints | 77 | 385 |
| Maximum constraint degree | 2 | 2 |
| Arithmetic degree bits | 17 | 14 |

The packed prover, verifier and metadata select component 4. The challenger actually observes that component identifier after the fixed application prefix. The packed envelope magic is `W1P3APC3`, and the decoder checks arithmetic degree bits 14. Single-lane component 3 and `W1P3ACR2` remain distinct. This is application namespace separation; it does not assert that shared hash roles are independent random functions.

## Qualification boundary

The outcome is a source-bound algebraic and assembly review with no blocking finding. Native test logs, resource-cap observations and performance measurements belong to separate evidence and were not independently rerun here. The full noninteractive security proof and production Node qualification remain open; the latter is documented in [Node profile status](NODE_PROFILE_STATUS.md).
