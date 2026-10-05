# W1 implementation equivalence and cost comparison

This work preserves the admitted `pon-matmul-transcript-64-v1` relation, proof grammar,
task identity, challenge, ticket, target and fork weight. It changes local algorithms
and adds an executable comparison. It does not activate a profile or establish mining
hardness, permissionless admission safety, model usefulness or external acceptance.

## Task sources and the preparation boundary

The diagnostic input classes are distinct structures, not a measured distribution
of user demand. Keep these source and admission cases separate:

| Material | Actual boundary | Cost interpretation |
|---|---|---|
| Canonical zero, identity, rank-one, diagonal and hash-generated controls | The version-1 matrix recipe permits canonical 4096-element operands; a live source statement, lease and actual-parent registration are separate requirements | A constructible permitted structure, not proof of real demand or its frequency |
| Bootstrap periodic material | Exact native development bootstrap with its own task and lease window | A fixed development input, not all registered tasks |
| Continuity maintenance | Exact public policy formula and explicit maintenance selection | Persistent work availability, not resource-fairness or hardness qualification |
| Checkpoint tile material | Exact pinned checkpoint, activation, quantization recipe and supplied A/B must replay under the selected checkpoint policy | Only that verified source tile; arbitrary replacement matrices are not eligible |

Checkpoint extraction allows 1..64 real token columns and pads the remaining B
columns with zeros. Consequently rank(B) is at most the number of real columns;
quantization can add zero values and field encodings of negative coefficients.
These are source-dependent structures, not grounds to call all full-rank or padded
tasks equally costly. A supplied benchmark matrix file alone does not establish
checkpoint provenance. Actual raw source availability and replay receipts remain
necessary before giving such a row that description.

`pon_reused_cost` measures only the mathematical producer constructor as setup.
Native `prepare_from_checked_parent` constructs a new `PreparedTask` for each
candidate; checking the parent, source signature, lease, material bytes and task
binding occurs outside that constructor. Checkpoint source replay during Settings
construction and Node opening is also outside the benchmark's setup measurement.
The reused experiment does not implement native cross-parent or cross-renewal
prepared caching. A mathematical task remains the same across some lease changes,
but an old statement or withdrawn task cannot obtain current admission from that
prepared object. Native admission continues to check the actual selected parent.

The signed [zero-task lifecycle regression](../../../../trillionnium/crates/trnm-pon-node/tests/zero_task_preparation_lifecycle.rs)
executes both ordinary V4 and explicit continuity settings. It registers canonical
zero operands through real signed source statements and leases, prepares full work
against the actual parent, verifies and admits ordinary packets, renews the task, and
rejects old statements, changed material, revoked and expired contexts. Real fork
selection and cold reopen retain those boundaries. Explicit maintenance is separately
constructed and admitted; a selected zero-task refusal never silently switches tasks.
This is protocol conformance, not evidence of real user demand or a service-pressure
campaign. The locality experiment's producer remains separate from Node selection.

The lowest cost among the concrete producers on one supplied task is an observed
implementation comparison, never a minimum possible complete-proof cost. Keep
preprocessing lifetime, eligible input identity and task-independent algorithmic
alternatives separate from the correctness of the accepted relation.

## Blocked zero-prefix alternative

`pon_work::blocked_zero::BlockedZeroPreparedTask` is a separate complete producer
for exactly A=B=0. Noncanonical material returns the ordinary field/length error;
other canonical operands return `None`. It grants neither `VerifiedWork` nor a
current-parent task admission. The original zero producer, tiled kernels, native
producer selection and both verifier implementations remain unchanged.

The algebra is the same exact cumulative relation as the old zero producer:
`S_k=ER[:,0:8k]*FL[0:8k,:]` and `C'_k=EL*S_k*FR`. The new algorithm retains eight
8x8 middle matrices (2 KiB), then eight 8x8 left factors for just the current output
row tile (another 2 KiB). Each original bi,bj,bk output tile is calculated and hashed
immediately. It avoids materializing the old eight full 64x64 output prefixes
(128 KiB). The stated 4 KiB is only these mathematical prefix arrays, not total
stack/heap/process memory: noise vectors, a 2 KiB FR transpose, a 256-byte output
tile, hashing state and the complete proof buffer also exist.

Both zero algorithms perform 299,008 scalar multiplications per challenge and hash
every one of the original 32,768 prefix words. This change targets intermediate
storage and locality; no multiplication-count speedup is asserted. It cannot be
selected for the nonzero continuity maintenance matrices, and does not improve
their work qualification. Previous slower zero and Strassen observations remain
historical evidence, even if a later implementation performs differently.

The separate `pon_zero_locality_cost` example uses schema
`pon-w1-zero-locality-v1`. It measures only the exact zero material under three
strategies: `prepared-generic`, `structured-zero-reference`, and `blocked-zero`.
Every strategy runs cold-per-search and reused-one-setup with real constructors;
there is no unsupported task substitution or hidden warmed cache. CLI bounds and
defaults match the numeric options of `pon_reused_cost`, but this example does
not accept caller-supplied material. For example, after the actual source is built:

    target/release/examples/pon_zero_locality_cost --samples 4 --searches 4 --attempt-budget 64 --seed 0
    target/release/examples/pon_zero_locality_cost --samples 2 --searches 4 --attempt-budget 8 --seed 1

Its challenge domain is `zero-locality-cost-v1`; full proof and ticket streams use
separate `TRNM-PON-W1-ZERO-LOCALITY-*` hash domains. The six producer/mode positions
rotate by sample. Every target miss, exhausted search, actual setup duration and
winner is retained. Ordinary and scalar verifier costs are measured separately
after all six generation runs; exact winning bytes and complete attempted-proof
commitments must agree. Source/compiler/binary/runner receipts and failed process
outputs remain necessary outside the example. Do not interpret this new schema
using the old seven-material checker, or divide timings across schemas.

`pon_zero_io` is the bounded complete-proof correctness bridge: select `generic`,
`structured-zero-reference` or `blocked-zero`; stdin is exactly a 32-byte challenge
followed by two canonical 16,384-byte matrix operands. Supported output is one
complete 49,188-byte proof. Zero-only operations explicitly reject nonzero
operands instead of selecting another structured method. The existing independent
Python scalar oracle can compare complete bytes and check nonzero unsupported
controls outside any native timing run. Correct byte parity is not a hardness
certificate or permission to keep mining an expired or withdrawn task.

## Exactly one zero operand and a nonzero rank-one counterpart

`pon_work::blocked_one_zero::BlockedOneZeroRankOnePreparedTask` is another separate
complete-proof producer. It validates both complete canonical operands, requires
exactly one zero operand, derives a factorization `u*v` of the other operand from
its first nonzero field pivot, and checks all 4096 reconstructed cells. Both-zero,
both-nonzero, and rank greater than one inputs return `None`; malformed lengths and
field values remain errors. No caller-supplied factors, approximate rank, implicit
generic fallback, current lease, or verification capability is accepted.

The challenge matrices are unchanged: `A'=A+EL*ER` and `B'=B+FL*FR`. For each
original inner prefix `K={0,...,8k-1}`, the two supported cases are:

| Exact source material | Retained contracted factor | Complete original output prefix |
|---|---|---|
| `A=0`, `B=u*v` | `D_k=(ER[:,K]*u[K])*v+(ER[:,K]*FL[K,:])*FR` | `EL*D_k` |
| `A=u*v`, `B=0` | `L_k=u*(v[K]*FL[K,:])+EL*(ER[:,K]*FL[K,:])` | `L_k*FR` |

All operations are exact in the existing field. Each incremental middle update
contains at most eight products plus its previous canonical value; each contracted
factor cell contains nine products. Both bounds fit the existing reducer's
documented `<2^70` input requirement. All eight original prefixes still produce
every one of the 32,768 transcript words in the unchanged `bi,bj,bk,i,j` order.
The complete PNW1 proof retains the exact original A/B bytes and zero product.
Canonical proof bytes, task identity, challenge binding, ticket, target, ordinary
and scalar verification, and native default producer selection are unchanged.

| Per-challenge multiplication operation | Count |
|---|---:|
| Eight cumulative noise and rank-one middle updates, `64*(8*8+8)` | 4,608 |
| All eight contracted factors, `8*64*8*9` | 36,864 |
| Every original output prefix word, `32,768*8` | 262,144 |
| Total for either direction | 303,616 |
| Generic prepared transcript | 327,680 |

The 7.34375% multiplication-count difference excludes noise derivation, hashing,
canonical checks, pivot inversion, factor detection, byte construction, and memory
costs. It is neither a measured speedup nor an adversarial work lower bound. The
algorithm retains eight 64x8 contracted factors (16 KiB) and one 72-field middle
state (288 bytes). The right-zero direction also transposes FR (2 KiB). Four noise
arrays, two stored rank-one vectors, a 256-byte output tile, hash state, and complete
proof buffers exist outside these bounds; these are not stack, heap, or RSS claims.

`pon_one_zero_locality_cost` uses its own schema `pon-w1-one-zero-locality-v1`.
Its two synthetic materials place the same exact nonzero matrix
`M[i,j]=(i+1)*(j+3)` beside a zero operand:

| Class | Actual field ranks `(A,B)` | Exact W1 task |
|---|---|---|
| `left-zero-rank-one` | `(0,1)` | `fde0e480d2cdc414c17eeb58909b0c349ac6a0af1572ceead65fa5227b64f027` |
| `right-zero-rank-one` | `(1,0)` | `a311ab05c13b5472c437485ee693c7f98fbb69fe3b18869bf1f3706c3867cca9` |

The example separately calculates actual field rank by ordinary-remainder Gaussian
elimination outside producer timing. It compares `prepared-generic`,
`structured-zero-product-reference`, and `blocked-one-zero-rank-one` under actual
`cold-per-search` and `reused-one-setup` constructors. The original structured
reference optimizes the zero product during setup and still computes its ordinary
complete noisy transcript. Each measured blocked constructor performs its own
complete canonical and factor validation, inversion, and proof-prefix construction;
the separately calculated benchmark rank never substitutes for these checks.

The numeric CLI bounds are the same as the zero-locality suite; there is no supplied
material option. The two retained campaigns are:

    target/release/examples/pon_one_zero_locality_cost --samples 4 --searches 4 --attempt-budget 64 --seed 0
    target/release/examples/pon_one_zero_locality_cost --samples 2 --searches 4 --attempt-budget 8 --seed 1

The challenge domain is `one-zero-locality-cost-v1`, and complete ticket/proof
streams use `TRNM-PON-W1-ONE-ZERO-LOCALITY-*` domains. The winner commitment tag is
`one-zero-locality-cost-winner-v1`. Both targets, every miss, exhausted search,
actual setup invocation and full losing-proof commitment remain in the output.
All six paths for one exact material/target/sample must have equal complete proof
and ticket streams and equal winners before ordinary and scalar verifiers are
timed separately. Invocation positions rotate by sample. Source, runner, binary,
failed-process and elapsed-time receipts remain necessary; timings across the
zero, reused, and one-zero schemas are not interchangeable. Only these two fixed
materials are measured; this is not a distribution of checkpoint or user demand.

`pon_one_zero_io` is a separate bounded correctness bridge. Its stdin is exactly
32 challenge bytes followed by two canonical 16,384-byte operands. Select
`generic`, `structured-zero-product-reference`, or `blocked-one-zero-rank-one`.
Success returns exactly one 49,188-byte proof. The original reference operation
supports exactly-one-zero materials regardless of the other operand's rank; the
blocked operation supports only the exact nonzero rank-one counterpart. Unsupported
requests return exit2 without proof bytes; no generic path is substituted. Static
original Python scalar vectors, full Rust proof/ticket comparisons, late pivots,
near-q values, zero coordinates, and caller mutation controls cover both directions.

The signed [one-zero task regression](../../../../trillionnium/crates/trnm-pon-node/tests/one_zero_task_preparation_lifecycle.rs)
registers these non-bothzero materials under actual V4 and continuity profiles,
rejects their use before parent registration and after source-byte mutation,
compares the complete blocked proof with native and original scalar generation,
admits ordinary packets, and checks durable reopen. Their explicit maintenance
purpose retains zero useful-output credit. This is finite native conformance with
disclosed development keys. It supplies no source-provenance, real-demand,
permissionless admission, mining-cost, public-service, or useful-model acceptance.

## Fixed genesis maintenance and complete producer research

The separate
[`PairedPreparedTask`](../../../../trillionnium/crates/trnm-crypto-primitives/src/pon_work/paired_product.rs)
implements another complete W1 producer. It accepts both complete canonical
operands and computes their actual fixed product during construction. The native
`PreparedTask` arithmetic, ordinary and scalar verifier relation, proof grammar,
task/challenge/ticket domains, target, fork weight and profile activation remain unchanged. Returned
proof bytes and mathematical caches carry no current-parent admission capability.

### Exact arithmetic and transcript

For every consecutive pair of inner coordinates the field identity is

```text
x0*y0 + x1*y1 = (x0+y1)*(x1+y0) - x0*x1 - y0*y1  (mod q).
```

Each cross sum is formed in `u64` and canonicalized with one conditional subtraction
of q before multiplying. For one original eight-coordinate block, row and column
factors each sum four products and are separately reduced to `[0,q)`. Given the
previous canonical prefix `prior`, the emitted increment is computed as

```text
reduce(prior + 2q - row_factor - column_factor
       + sum of the four canonical cross products).
```

The unsigned value is nonnegative and less than `4q^2 + 3q < 2^67`. The constructor's
full 64-coordinate product has 32 cross products per dot and is below `2^69`.
Both fit the existing reducer's `<2^70` precondition. Full canonical input checks,
near-q sum wrapping and factor cancellation are necessary; no floating point,
approximate rank or caller-supplied product/factors are used.

All four challenge-noise arrays are expanded with the existing rejection sampler.
Both complete noise matrix products use the paired identity, then the unchanged
`A'=A+EL*ER`, `B'=B+FL*FR` are formed. Row and column factors for every eight-coordinate
block come from these actual challenge-specific operands and are recomputed on each
call. Every original `bi,bj,bk,i,j` cell is emitted: 512 tiles, 32,768 prefix words and
the same complete trace hash. The proof still contains 49,188 canonical bytes,
including the original operands and actual fixed product; it contains the trace
digest, not an array of all transcript words.

| Scalar multiplication schedule | Ordinary prepared | Paired product |
|---|---:|---:|
| Actual fixed product during each constructor | 262,144 | 135,168 |
| Both noise products, including paired factors | 65,536 | 33,792 |
| Every transcript prefix, including paired factors | 262,144 | 135,168 |
| Per challenge total | 327,680 | 168,960 |

The 48.4375% multiplication-count reduction is not a speed measurement. The paired
path adds canonical cross sums, factor construction and storage, and different
arithmetic and memory behavior. Hashing, allocation, validation, product serialization
and cancellation calls exist outside that scalar-product count. A slower result on
either architecture remains a result; it does not license dropping an arm or changing
the advertised denominator.

`prove_with_progress` checks cooperative cancellation before replay, at every noise
hash, each noise-product output row, each transcript-factor row, each transcript
tile, and immediately before assembling the final proof. A refusal returns no proof
and retains no challenge-dependent state. The last checkpoint precedes the bounded
prefix clone and digest append. This is not instantaneous wall-clock cancellation;
the constructor and bounded work between checkpoints are not preempted. Native
mining cancellation and either verifier's observation sequence are unchanged.

### Frozen material, admission and preprocessing scope

[`pon_maintenance_cost`](../../../../trillionnium/crates/trnm-crypto-primitives/examples/pon_maintenance_cost.rs)
uses only the explicit genesis policy's fixed material:

```text
A[i] = (13*i + 17) mod 257
B[i] = (29*i + 31) mod 263
task = c982eea0545c228d0bf48d6d06e623020b4031f2ba79da56cc6bdccde2c63496
```

Its source classification is `genesis-policy-public-deterministic-fixture` under
`consensus-maintenance-continuity-dev-v1`. Independent ordinary-remainder field
elimination inside the example observes ranks 56/32 before the producer timers.
Those classifications never replace constructor validation or computation. It
accepts no supplied-material option, zero-task substitute, invented source signature,
infinite lease, checkpoint claim or real-user demand classification.

The separate
[`maintenance_paired_conformance`](../../../../trillionnium/crates/trnm-pon-node/tests/maintenance_paired_conformance.rs)
regression obtains the operands from actual `Settings::consensus_maintenance_material`,
checks their policy formula/task identity, compares complete scalar/native/paired/
periodic-setup/integer-paired/periodic-prefix/split-limb proofs for three real parent-bound
blocks, admits the split-limb proofs in
ordinary packets, activates them, and reopens the store after each block. The same
mathematical objects survive
the reopens and regenerates changed and repeated challenges exactly. Changed source
bytes and legacy-profile maintenance selection remain rejected. Useful-output credit
remains zero. This is finite native conformance, not external work qualification.

The mathematical cache retains only exact A/B and their product/proof prefix; all
challenge noise, factors and transcript are local to one call. It can be reused for
the same fixed task, but it cannot certify any actual selected parent's maintenance
record or current profile. The production Node still constructs its ordinary
`PreparedTask` per candidate. This experiment does not install a cross-parent cache
or allow a refused leased task to switch to maintenance.

### Exact periodic fixed-product preparation

[`MaintenancePeriodicPreparedTask`](../../../../trillionnium/crates/trnm-crypto-primitives/src/pon_work/maintenance_periodic.rs)
specializes only the fixed-product constructor for the exact two maintenance
operands. Both canonical length/field checks run first; every A and B entry must
then equal the public policy formulas above. Other canonical operands return
`None`, while malformed operands retain their ordinary length/field error. The
constructor accepts no caller-supplied product, factor, source statement or cache.

For column j, let `b_j = (29*j + 31) mod263`. Since `29*64 mod263 = 15`,

```text
B[k,j] = b_j + 15*k - 263*sum_m 1{k >= t_jm},
t_jm = ceil((263*m - b_j) / 15),
1 <= m <= floor((b_j + 15*63) / 263) <= 4.
```

These are exact integer identities. For each row of A, the constructor computes
all prefix sums `P_i(K) = sum(k<K, A[i,k])` and its weighted sum
`Q_i = sum(k<64, k*A[i,k])`. The complete fixed product is then

```text
(AB)[i,j] = b_j*P_i(64) + 15*Q_i
            - 263*sum_m (P_i(64) - P_i(t_jm)).
```

Each product cell uses at most four suffix corrections. The positive expression
before subtraction is at most 12,034,048, and the exact nonnegative result is at
most `64*256*262 = 4,292,608 < q`; the implementation uses bounded `u64` arithmetic.
All column plans, row prefixes, weighted sums, actual product bytes, owned operand
copies and the proof prefix are constructed inside the setup call. They are not
external preprocessing supplied free to the measured producer.

The retained object contains an ordinary `PreparedTask`. Its `prove` and
`prove_with_progress` delegate to that task's existing complete per-challenge
implementation: fresh noise expansion, both noise products, all 512 original
transcript tiles and the same complete proof. No noisy prefix or challenge result
is reused. Both generic and periodic producers share the newly exposed cancellation
observation order; ordinary arithmetic and proof bytes remain unchanged. The
constructor itself remains bounded nonpreemptive setup. The research object
can be reused for its exact material, but carries no branch, lease, profile or
current-parent admission capability and is not the Node's selected producer.

The source regressions compare every sawtooth intercept and all prefix lengths
with direct integer sums, require exact-material detection, compare complete
proofs and tickets with generic/paired/scalar implementations, reject mutated
products/traces, and check cancellation plus repeated-challenge reuse. Their
existence does not assert execution on a later source or any measured speedup.

### Challenge-dependent periodic prefixes and their direct competitor

The explicit
[`MaintenanceIntegerPairedPreparedTask` and `MaintenancePrefixPreparedTask`](../../../../trillionnium/crates/trnm-crypto-primitives/src/pon_work/maintenance_prefix.rs)
retain the full fixed-material constructor above. Both check all 8192 input elements,
compute AB and serialize their complete proof prefix inside setup. The prefix path
also builds its retained column plans inside that timer. Both reject other canonical
materials with `None` and malformed materials with their length/field errors. Neither
accepts a supplied product, stored challenge factor, native parent capability or
caller-selected affine formula.

The shared private
[`integer_paired`](../../../../trillionnium/crates/trnm-crypto-primitives/src/pon_work/integer_paired.rs)
kernel uses the same paired identity over integers, with **unreduced** row and column
factors. It first accumulates

```text
S = prior + sum_pairs (x0+y1)*(x1+y0)
  = prior + row_factor + column_factor + sum_k x[k]*y[k].
```

It then subtracts both exact factors and reduces once modulo q. Addition is widened
before it occurs: each pair sum can require 33 bits. For eight coordinates, S is
less than `16*(q-1)^2+(q-1)<2^68`; the nonnegative value after subtraction is less
than `2^67`. For 64 coordinates, S can exceed `2^70` but remains below `2^71`;
**only after** both subtractions is it below `64*(q-1)^2+(q-1)<2^70`, the existing
reducer's limit. Reducing factors early, subtracting before accumulating S, or
passing S directly to that reducer would violate this integer implementation's
contract. The older field-paired producer retains its original algorithm.

The direct competitor forms both E and F and traverses the complete ordinary
transcript with this kernel. Its method is
`maintenance-integer-paired-full-transcript`. It controls for a kernel improvement
that would otherwise be incorrectly attributed to the periodic decomposition.

For the prefix strategy, write `X=A+EL*ER (mod q)` and let `m=(bk+1)*8`. It forms E,
but does not materialize F. Within each fresh challenge it computes

```text
H_m[i,t] = sum(k<m, X[i,k]*FL[k,t]) mod q,
C'_m[i,j] = (sum(k<m, X[i,k]*B[k,j]) + sum_t H_m[i,t]*FR[t,j]) mod q.
```

H is updated once per eight-coordinate block. A different canonical H and its exact
paired row factor are retained for each of the eight prefixes. FR's column factors
are computed from that same challenge, once, and all such factors are charged to
search. No previous challenge's H, trace, prefix or noise is reused.

For each row, fresh canonical X values give integer prefix sums `P_i(m)` and weighted
sums `W_i(m)`. Using the already verified B column plan,

```text
sum(k<m, X[i,k]*B[k,j])
  = b_j*P_i(m) + 15*W_i(m)
    - 263*sum(t_jl<m, P_i(m)-P_i(t_jl)).
```

The positive expression is at most `47008*(q-1)<2^48`; the exact nonnegative result
is at most `64*262*(q-1)<2^47`. Thus `u64` is sufficient even though X is now a full
field element, unlike the small fixed A used by setup. Adding the reduced H*FR
term and applying the existing reducer yields each original canonical transcript
prefix. This computes the entire prefix, not just the latest tile's contribution.
The exact `bi,bj,bk,i,j` serialization remains 512 tiles and 32768 words, with the
same trace/ticket and 49188-byte proof. Its method is
`maintenance-periodic-prefix-integer-paired-full-transcript`.

| General scalar multiplications per challenge, including paired factors | Direct integer-paired | Periodic-prefix |
|---|---:|---:|
| E | 16,896 | 16,896 |
| F | 16,896 | 0 |
| Incremental H, including X/FL factors | 0 | 18,688 |
| Output prefix dots and their row/column factors | 135,168 | 133,376 |
| Total | 168,960 | 168,960 |

The periodic strategy has **no general-multiplication-count advantage over its new
direct competitor**. It additionally performs fixed-coefficient sums/corrections,
stores prefix data, and changes memory access. The integer pair's products can
need 66 bits, unlike products of two canonical field elements. Actual complete
cost may improve or regress on either architecture; neither the count nor the
algebra is a latency measurement or fastest-adversary lower bound.

Both new progress APIs stop before replay, every noise hash, each noise-factor and
noise-product row, each transcript-factor row, every original transcript tile and
proof assembly. The prefix strategy adds a checkpoint before each row's actual
sum/H construction. These are new algorithm-specific sequences, not a promise to
imitate the old producer's checkpoints. Cancellation drops all local intermediates,
returns no proof, and preserves only the exact fixed material for a fresh call.
Constructor work, bounded transposes/allocations and work between callbacks remain
nonpreemptive; no wall-time preemption guarantee is added.

Native definitions cover integer-pair extremes and nonnegative subtraction, all
periodic intercepts/prefix lengths with canonical near-q coefficients, every 32768
prefix word for two extreme arithmetic fixtures, complete scalar/generic/producer
proof equivalence, exact verifier failures, missing/invalid/unsupported material,
actual callback tile order and cancellation plus reuse. These are source contracts;
execution on a final candidate must have its own retained result.

### Bounded split-limb arithmetic for the complete transcript

[`MaintenanceLimbPreparedTask`](../../../../trillionnium/crates/trnm-crypto-primitives/src/pon_work/maintenance_limb.rs)
is a separate eighth complete producer for the same exact maintenance operands.
Its constructor delegates to the periodic fixed-product constructor, so complete
canonical/material checks, AB computation, owned A/B copies and proof-prefix
construction remain inside each actual setup. It accepts no supplied product,
noise, current-parent capability or challenge-dependent cache.

The new arithmetic uses the identity `2^32 = 5 (mod q)`. For eight canonical
products, write `p_k=x_k*y_k=lo_k+2^32*hi_k`. With a canonical previous prefix `c`,

```text
L = c + sum_k lo_k       < 9*2^32
H = sum_k hi_k           < 8*2^32
S = L + 5H              < 49*2^32
F = (S mod 2^32) + 5*floor(S/2^32) < 2^32+240 < 2q.
```

Each product fits `u64`, and so do L, H, S and F. A single conditional subtraction
of q from F gives the canonical value of `c+sum_k x_k*y_k`. No overflowing
accumulation, floating-point approximation, early field truncation or unreduced
33-bit paired product is used. The private kernel accepts exactly eight inner
coordinates; its bounds are not asserted for arbitrary matrix dimensions. Addition
of each canonical noise value to the corresponding fixed operand also uses a
bounded `u64` sum below 2q and one conditional subtraction.

Every challenge still expands all four original noise arrays, computes E and F,
forms both noisy operands, transposes the actual right operands and emits all
512 original transcript tiles, 32,768 canonical prefix words and the complete
49,188-byte proof in the original order. There is no periodic decomposition of
the challenge-dependent transcript in this producer. The per-challenge scalar
multiplication count is still 327,680, the same as ordinary prepared generation;
the change separates low/high accumulation into bounded native-width sums.
Compiler scheduling, additions, shifts, memory traffic and hashing determine
whether its complete measured cost improves. A cheaper kernel or fewer wide
accumulations is not a multiplication-count reduction or a work-hardness bound.

Its progress API retains the complete ordinary `PreparedTask` observation order:
before replay, every noise hash, each E/F output row, every transcript tile and
before proof assembly. Tests compare the complete observation sequences, then
cancel representative first/middle/last noise and row observations, boundary
tiles and both end points. Each refusal returns no proof; changed and repeated
challenges after refusal are checked against a fresh ordinary proof. This finite
test selection does not claim that every callback position was separately
cancelled. Setup, bounded transposes/allocations and work between observations
remain nonpreemptive. Neither verifier nor native producer selection changes.

Arithmetic controls compare ordinary `u128` remainder with maximum, zero, mixed
and 1,024 hash-derived eight-coordinate inputs and canonical prior values. Two
complete maximum/mixed-field transcript controls compare every individual prefix
word with independent scalar prefix sums. Complete fixed-material proofs agree
with generic and original scalar generation for changed and repeated challenges;
both verifiers retain exact task, challenge, length, field, product, transcript and
target rejection outcomes. The Python bridge adds four complete raw-proof
comparisons and twelve explicit rejection cases for this producer. These are
finite implementation controls, not an independent institutional assessment,
physical-hardware measurement or a cheapest-legal-producer proof.

### Cost contract

The current emitted schema is `pon-w1-maintenance-limb-v4`. It compares
`prepared-generic`, `tiled-classical`, `tiled-strassen-one-level`, `paired-product`,
`maintenance-periodic-setup`, `maintenance-integer-paired` and
`maintenance-periodic-prefix`, plus `maintenance-split-limb`, each under actual `cold-per-search` and
`reused-one-setup` constructors. Structured zero/identity/rank-one methods do not
support these exact nonzero maintenance operands and are not silently substituted.
All three older cost suites retain their existing schemas and input grids.

Historical `pon-w1-maintenance-paired-v1` means its original four strategies/eight
positions; `pon-w1-maintenance-preprocessing-v2` retains five strategies/ten positions;
`pon-w1-maintenance-prefix-v3` retains seven strategies/fourteen positions.
The artifact checker selects those meanings only with explicit
`--maintenance-version 1`, `--maintenance-version 2` or `--maintenance-version 3`.
Its default and the current runner use version4. No historical grid gains new producers or input files by
normalization or rehashing. The suite remains `maintenance-paired` and owns the
existing fourth artifact directory, with explicit execution/comparison schemas
`trnm-cross-arch-maintenance-cost-execution-v4` and
`trnm-cross-arch-maintenance-cost-comparison-v4`; this is not a fifth cost suite or a
new consensus profile.

The fixed hosted campaigns, after building the exact committed source, are:

```text
pon_maintenance_cost --samples 4 --searches 4 --attempt-budget 64 --seed 0
pon_maintenance_cost --samples 2 --searches 4 --attempt-budget 8 --seed 1
```

Each uses both unchanged diagnostic targets `7f` followed by 31 `ff` bytes and `07`
followed by 31 `ff` bytes. Each search changes its diagnostic challenge using

```text
H("maintenance-paired-cost-v1", task, LE64(seed), LE64(sample),
  LE64(search_index), target, LE64(nonce)).
```

This harness hashes diagnostic challenge inputs; it does not time a Node's actual
header preparation or selected-parent admission. Cold mode invokes the actual
constructor for each search; reused mode invokes it once for the complete cohort.
Both include all fixed-product preparation, canonical checks, and prefix construction
performed inside that constructor. No prepared product or setup fraction is supplied
for free. The cost harness also boxes the large retained prefix producer inside
that same measured preparation call, so its allocation remains in setup cost.
Every nonce attempt, including every target miss and exhausted search,
remains in the measured search and complete proof/ticket stream commitments.
Winner-only division is defined only with a nonzero actual winner count, and its
numerator includes all setup and search durations from the selected cohort.

The sixteen strategy/mode positions are balanced in adjacent samples: sample `2k`
uses invocation `(k+offset) mod 16`, and sample `2k+1` uses `(k+15-offset) mod 16`.
Thus each complete pair places every arm at average position 7.5, including both
fixed campaigns. A caller choosing an odd sample count leaves one unmatched sample.
This schedule alone does not eliminate thermal, cache, scheduler or architecture
confounders and does not establish statistical significance.

All sixteen paths must agree on every search status, attempt count, complete attempted
proof and ticket commitments, and exact winning challenge/proof bytes. Both original
scalar and ordinary verifiers then check each actual winner, with their costs reported
separately after all generation arms. Losing proofs are fully hashed but are not all
retained as raw arrays. Their stream domains are respectively
`TRNM-PON-W1-MAINTENANCE-PAIRED-PROOF-STREAM1\0` and
`TRNM-PON-W1-MAINTENANCE-PAIRED-TICKET-STREAM1\0`; the winner commitment tag is
`maintenance-paired-cost-winner-v1`. These challenge and stream domains deliberately
retain their v1 identities so the same deterministic searches remain identifiable.
The changed strategy grid and raw schema still require explicit version selection;
they do not make old/new timing distributions interchangeable.

Material construction, descriptive task/rank checks, cross-strategy comparisons,
post-generation verification, output formatting and final prepared-object destruction
remain outside setup/search timers. Retain source/compiler/binary/runner receipts,
all failures and stderr, real setup-call counts and finite exhaustion. Monotonic wall
time is not CPU accounting, energy, RSS, native admission or public-service cost.

[`pon_paired_io`](../../../../trillionnium/crates/trnm-crypto-primitives/examples/pon_paired_io.rs)
is a bounded complete-proof bridge. With no argument it selects paired products;
the exact optional arguments `maintenance-periodic`, `maintenance-integer-paired`,
`maintenance-prefix` and `maintenance-limb` select the corresponding fixed-material constructors.
Stdin must be exactly 32 challenge
bytes followed by the two canonical 16,384-byte operands. Success emits one complete
49,188-byte proof; missing/extra bytes, noncanonical fields, unrecognized or extra
CLI arguments, and nonmaintenance operands under any maintenance selector fail with
exit 2 and no proof. It permits independent Python scalar comparison of
complete bytes for maintenance and canonical arithmetic controls, without using a
timing ratio as a correctness assertion.

The retained
[`test_paired_work.py`](../../../../formal/pon-nakamoto-v1/test_paired_work.py)
compares the bridge against the existing scalar `work_oracle.py`, without deriving
expected values from paired or periodic arithmetic. The explicit
`pon-w1-paired-maintenance-python-native-v4` report requires 32 complete-proof byte
comparisons: four challenge patterns on maintenance through all five producer selections, plus
the same patterns on three paired arithmetic controls (near-q, hash-dense and
left-zero). The controls do not assert source provenance, rank, current task
admission or useful demand. Fifty-four bounded length/field/argument/unsupported-material
rejection cases require exit 2 and empty stdout. Every case
retains its exact input, Python expected proof where applicable, native stdout and
stderr, command, exit and hashes. A missing binary fails rather than skips. The whole
suite requires `TRNM_PAIRED_WORK_OUTPUT` to name a fresh retained directory, writes
the before/after source and binary identities, and cannot report PASS with fewer
than all 86 invocations. The actual runner's build receipt is still required to bind
the binary to the inspected source. This is independence of arithmetic implementation
within the project, not an independent institution's review.

### Remaining fixed-material and lowest-cost questions

The paired identities are input-general. The explicit current producers also
exploit the exact maintenance formula, but do not close all preprocessing questions. In particular,
the fixed A has `A[i,k]=(a_i+d_k) mod257`, where
`a_i=(13*64*i+17) mod257` and `d_k=13*k mod257`. For any original prefix K,

```text
sum(K, A[i,k]*v[k]) = a_i*sum(K,v[k]) + sum(K,d_k*v[k])
                     - 257*sum(k in K where d_k >= 257-a_i, v[k])  (mod q).
```

The analogous identity holds for B modulo 263. Sorting and prefix sums can make a
fixed-matrix vector product cheap; all challenge-dependent work and every original
transcript prefix still need a complete algorithm. Simply caching `A[:,K]*B[K,:]`
and evaluating two rank-eight output corrections doubles the output dot dimension
from eight to sixteen in that decomposition, so rank 56/32 or a cheap matvec alone
does not establish a faster complete proof. The prefix producer above instead uses
one output rank-eight dot plus a periodic sum, and provides a complete
challenge-dependent algorithm with its direct integer-paired control. It does not
supply a fastest-possible noisy-prefix algorithm, GPU/ASIC strategy, unlimited
preprocessing bound, real useful-input distribution or hardness lower bound.
The two unchanged campaigns now request 128 and 64 cohorts per architecture, respectively
512 and 256 search records. Historical v3 keeps its 112/56 cohorts and 448/224 searches.
Repeated algorithms/modes/architectures do not create
new independent deterministic workloads, and a zero-winner cost stays undefined.
Compare each new producer with the fastest eligible existing strategy and compare
the prefix producer separately with its same-kernel direct competitor; compare the
split-limb producer with the ordinary periodic setup sharing its constructor. Retain slow
or exhausted results instead of selecting only successful or favorable samples.
All existing acceptance and activation flags remain false.

## Verifier boundary

`trnm-crypto-primitives/src/pon_work.rs` retains two complete arithmetic paths:

| Entry | Arithmetic and transcript | Use |
|---|---|---|
| `verify` / `verify_with_progress` | Transposed right operands, exact reduction for q=2^32-5, 256-byte tile hash updates | Ordinary native W1 verification |
| `verify_reference` / `verify_reference_with_progress` | Original row-major scalar products, u128 remainder, per-cell hash updates | Explicit reference and differential verification |
| `evaluate` / `prove` | Original complete scalar generation | Reference producer |

Both verifier paths perform the same grammar and task checks before replay. They emit
the same ordered `VerificationProgress` observations: before replay, each noise hash,
each multiplication row, each transcript tile, before product reconstruction and before
constructing `VerifiedWork`. Cancellation discards all intermediate state. No decoded
product, matched digest, callback success or prepared task grants verification authority.

For a mismatched transcript the verifier still replays the entire transcript and then
skips product corrections. A matched transcript still requires the complete exact product
check. Consequently the known cheap-forgery/expensive-rejection mechanism remains, even
if the implementation takes less time. Full recomputation remains full recomputation.

The original Rust scalar arithmetic and Python oracle provide independent arithmetic
implementations within the same development authorship. Their agreement is not an
external security assessment. Extreme-field/product/grammar cases compare both Rust
paths; a complete success records equal observation sequences, and representative cuts
through every noise/matrix/tile/product stage compare cancelled outcomes. Existing
wire, task, challenge and Python byte-parity tests remain applicable.

## Concrete structured producers

`pon_work::structured::StructuredPreparedTask::new` returns `None` for unsupported
structure and an error for invalid dimensions or field elements. It never silently
labels a generic fallback as a structure-specific optimization. Every returned proof
must pass the ordinary verifier. The native miner's selected `PreparedTask` path is
unchanged; the additional producers are directly callable comparison implementations.

| Checked structure | Product preparation | Per-challenge transcript |
|---|---|---|
| A=B=0 | Known canonical zero product | Reassociated low-rank prefix products |
| Exactly one zero operand | Known zero product | Complete prepared transcript |
| Left or right identity | Copy the other operand | Complete prepared transcript |
| Both operands diagonal | One scalar product per diagonal cell | Complete prepared transcript |
| Both operands rank one | Exact rank-one factor check, scalar contraction and outer product | Complete prepared transcript |

Rank detection is over the exact field and checks every reconstructed matrix cell.
It does not accept approximate rank, floating-point tolerance or an unverified supplied
factorization. Setup timing includes structure detection, product construction and
prefix allocation. Within this original structured producer, the rank-one and
product-only paths reuse the full prepared transcript kernel; only its zero-zero
path changes transcript multiplication order. The separately named blocked
one-zero producer above has its own narrower support and full-prefix algorithm.

For A=B=0, let K_j be the first 8j inner coordinates and set

    S_j = ER[:, K_j] FL[K_j, :]
    C'_j = EL S_j FR.

Update S_j by adding the next 8-coordinate product. Retain the eight cumulative C'_j
matrices, then emit every cell in the original bi,bj,bk,i,j order. The transcript bytes
and final zero product are unchanged. With n=64, r=8 and L=n/r=8, the scalar multiplication
counts are:

| Operation | Count |
|---|---:|
| All middle-matrix updates, L*r^3 | 4,096 |
| All EL*S_j, L*n*r^2 | 32,768 |
| All (EL*S_j)*FR, L*n^2*r | 262,144 |
| Total per challenge | 299,008 |
| Generic PreparedTask per challenge | 327,680 |

The 8.75% reduction is in multiplication count only. It is not a measured latency or
CPU improvement: the alternative retains 32,768 field elements (128 KiB) of cumulative
outputs and has different allocation/cache behavior. All 32,768 intermediate words
still enter SHA-256. Zero-product preparation avoids the generic 262,144 multiplications,
while canonical checks, allocation and byte construction still have costs.

`cost_class=1` fixes the relation's shape, not equal cost across inputs or implementations.
V4 revision9 explicitly permits zero/identity/low-rank materials subject to authenticated
lease and parent registration. Revision10's checkpoint policy pins exact material and
does not allow arbitrary substitution; structure in those actual pinned bytes remains
legal. Restricted owner descriptors also bind exact materials and operation scope.
Correct task attribution and signatures do not establish a work-cost lower bound.

## Reproducible comparison command and schema

From `trillionnium/`, build the exact source before starting a serial observation:

    cargo build --locked --release -p trnm-crypto-primitives --example pon_producer_comparison
    target/release/examples/pon_producer_comparison > comparison.json

Optional exact canonical artifacts can be included with `--model PATH --input PATH`.
Both files must contain precisely 4096 canonical little-endian u32 field elements.
The example does not authenticate their provenance, demand, checkpoint origin or right
to use them. It records their joint task identity and observed field ranks. Supplied
materials are additional cases; omitted material is not represented as a real-model run.

`--samples N` accepts 1..64 (default8); `--attempt-budget N` accepts 1..4096 (default4096).
The bounded budget is applied to every strategy; an exhausted search produces a retained
row with its full attempted count and elapsed duration, null verifier/proof results and
an exact ticket-stream commitment. No exhausted search is converted into a success or
discarded from the output. An unsupported structured case retains its detection/setup
cost with status `unsupported`, zero attempted searches and null verifier observations.

Schema `pon-w1-producer-comparison-v1` includes six built-in material cases:

- `periodic-dense-fixture`: the historical A[i]=i%31, B[i]=7i%37 inputs, whose exact
  field ranks are 31 and 37; the name does not imply generic full-rank matrices.
- `full-rank-field`: deterministic hash-generated canonical field matrices, each
  independently checked by exact Gaussian elimination to have rank64.
- Zero, identity, rank-one and sparse diagonal fixtures with recorded ranks.

Task material construction and its descriptive Gaussian elimination are outside the
timed mining algorithm and explicitly labelled. This is a supplied task comparison,
not a measurement of demand creation. Each material/target/sample uses the same task,
challenge stream and target for the original, prepared-generic and prepared-structured
strategies. Strategy invocation order rotates across samples; production/reference
verifier invocation order alternates. Every supported strategy must produce the same
attempt count, complete ticket-stream commitment and winning proof bytes.

Rows retain setup, search and total elapsed nanoseconds, attempts, winning/exhausted/
unsupported status, proof commitment, ranks, both verifier durations, invocation orders
and the exact target. Times use a monotonic wall clock; they are not CPU accounting.
Search timing includes every losing attempt and the common harness's challenge/ticket/
stream hashing. No unmeasured setup reuse is amortized into these raw observations.

The two requested targets are 7fff... and 07ff... . They are standalone relation
microbenchmarks, not changed genesis parameters or a claim that these arbitrary
challenges are valid block templates. Compare matching target/input identities only.
The program leaves hardness, public-service, provenance and production-activation
flags false. Source/lockfile/compiler/binary identity, command, filesystem, hardware
and competing processes require a separate exact-source execution receipt.

## Existing observations stay historical

`pon_prepared_cost` retains its 64-row schema and explicitly invokes `verify_reference`;
its `original_verifier_ns` remains a scalar baseline. `pon_adversarial_cost` measures the
ordinary verifier, including invalid transcript rejection. The existing cost reporter
does not consume this new comparison schema. Its reference-verifier denominator must
not be presented as a production-verifier measurement after this implementation change.
Historical receipts, measured source hashes, slower samples and failed gates are not
rewritten. A current comparison requires new executions on the final committed source.

An observed faster verifier is an engineering result. Faster structured producers can
reduce the effective mining cost. Neither result closes algebraic shortcuts outside
these implementations, preprocessing across challenges, accelerator/pool advantages,
uniform independent lottery assumptions or hostile public ingress service obligations.

## Actual setup reuse across distinct challenge searches

`pon_reused_cost` is a separate experiment with schema `pon-w1-reused-search-v1`.
The older examples and their schemas retain their meaning. Build before observing:

    cargo build --locked --release -p trnm-crypto-primitives --example pon_reused_cost
    target/release/examples/pon_reused_cost --samples 4 --searches 4 --attempt-budget 64 --seed 0
    target/release/examples/pon_reused_cost --samples 2 --searches 4 --attempt-budget 8 --seed 1

`--samples` and `--searches` accept 1..32, with defaults of 4; `--attempt-budget`
accepts 1..4096, default 256; `--seed` is an unsigned 64-bit value, default 0.
Optional `--model PATH --input PATH` adds the same strictly bounded canonical file
format as the original comparison. Six existing material classes plus the exact
continuity fixture are included by default. That seventh class is explicitly the
public deterministic maintenance formula A[i]=(13i+17) mod257 and B[i]=(29i+31)
mod263; its measured field ranks are 56/32. It is not authenticated user demand,
a pretrained model, or a work-hardness qualification. Supplied material is an eighth
case, not a replacement for an omitted fixture.

Each input/target/sample is a cohort of distinctly challenged searches for the
same exact task. Five producers are run in both modes:

| Producer | `cold-per-search` | `reused-one-setup` |
|---|---|---|
| Scalar original | No prepared setup; full scalar proof for each attempt | Same scalar algorithm, no hidden cache |
| Prepared generic | Construct a new `PreparedTask` for every search | Construct exactly one `PreparedTask`, then reuse it for all searches |
| Prepared structured | Detect and prepare structure for every search | Detect and prepare once, then reuse the same instance |
| Tiled classical | Construct a new tiled task for every search | Reuse one complete tiled task |
| Tiled one-level Strassen | Construct a new tiled task for every search | Reuse one complete tiled task |

The actual setup calls and their separate durations are retained. A supported cold
prepared cohort has `searches` setup calls; a reused prepared cohort has one. Scalar
has zero in both modes. An unsupported structured cohort retains the same attempted
setup-call counts and reports every requested search as unsupported, without mining.
There is no synthetic division of an unexecuted setup cost, hidden warmed cache, or
free unreported constructor. Cohort `total_elapsed_ns` is the sum of actual setup
and all attempted search durations. Dividing this by the number of requested
supported searches gives the observed cohort amortization; it is not a claim about
an unlimited number of future blocks or the optimal preprocessing strategy.

The challenge stream is

    H("reused-cost-v1", task, LE64(seed), LE64(sample), LE64(search_index), target, LE64(nonce)).

Thus all producer/mode combinations see identical statements and nonce streams,
while a new search changes its challenge even if its nonce restarts at zero.
The ten producer/mode invocation positions rotate across samples. Every attempted
proof contributes its complete bytes to a stream commitment, and every ticket
contributes to the ticket stream commitment. Supported rows must agree on status,
attempt count, both stream commitments, and exact winning challenge/proof bytes.
The commitments compare losing-attempt streams without retaining unbounded arrays
of 49,188-byte certificates; they are cryptographic commitments, not a claim that
every losing byte array is retained in the report.

Each search reports `winner`, `exhausted` or `unsupported`. Exhaustion retains the
whole attempt budget, search duration and both streams, with null winner/verifier
fields. It is never converted into a win or excluded from the cohort cost. Every
winning certificate is checked by both `verify` and `verify_reference`, with
alternating verifier order. Verification and cross-producer comparisons are outside
generation timing. Challenge, ticket and full-proof stream hashing are common
measured harness costs, not omitted overhead. Input construction and descriptive
field-rank elimination remain outside the producer measurements.
The older comparison hashes ticket streams but does not hash every complete
attempted certificate into an additional stream. Consequently raw search times
across these two schemas have different harness costs and are not a direct
before/after measure of an arithmetic change.

The report retains the complete row grid and each ordered outcome, explicit seed,
targets, input identity and ranks, setup calls, timing order and proof extent.
Times remain monotonic wall elapsed durations. Preserve actual failures, stderr,
timeouts and exact source/compiler/binary identities in an external run receipt.
Compare deterministic non-timing outcomes across architectures before summarizing
costs; differences in wall time alone do not establish a portable speedup.

## Complete tiled producer alternatives

`pon_work::structured::{TileKernel, TiledPreparedTask}` provides two separately
selected complete producer implementations. It does not replace the production
miner's `PreparedTask`, either verifier, or any cancellation checkpoint. Construction
validates exact field inputs and computes the actual cached product with the selected
kernel. Each challenge expands all original noise, computes both dense noise
matrices with that kernel, visits every original transcript tile, and emits exactly
the same product, trace digest and PNW1 bytes. No returned byte buffer is a
`VerifiedWork` capability.

Both implementations use 8x8 blocks. `TileKernel::Classical` performs the ordinary
eight-term dot products. `TileKernel::StrassenOneLevel` splits a block into four 4x4
quadrants and computes the seven standard Strassen products, without recursing
further. Signed i64 operand sums/differences and signed i128 accumulators preserve
exact integer intermediates; no floating point or approximate arithmetic is used.
Intermediates are bounded below 2^71. Recombination yields the exact nonnegative
eight-term product below 8q^2 < 2^67 before the existing exact field reduction.
The transcript accumulator is reduced at the same 8-coordinate boundaries.

| Per-challenge multiplication schedule | Scalar products |
|---|---:|
| Two noise products plus all transcript tiles, classical | 640 * 512 = 327,680 |
| Same complete work with one-level Strassen | 640 * 448 = 286,720 |

The tiled fixed-product setup also executes the selected kernel and is timed;
it is not credited with a cost-free precomputed product. Strassen introduces more
signed additions, wider arithmetic, packing and local storage. The operation-count
reduction is a property of this implemented arithmetic schedule, not a latency
result, energy result, cheapest-producer bound or promise of improvement on either
x64 or ARM64. Retain slower runs and use the ordinary prepared implementation as
an additional baseline; a slower tiled implementation is still an observed result.

Tests compare unreduced integer tile products, including signed-intermediate and
maximal-field cases; complete certificates agree with the scalar producer and both
verifiers. Fixed full-certificate SHA256 vectors for extreme-field and continuity
inputs come from the independent Python oracle for challenges 00, 07 and ff repeated
32 times. Reusing one task across changed and repeated challenges must not reuse a
trace from a different challenge. The new cohort tests also exercise actual setup
reuse, finite exhaustion and exact producer/mode agreement.

`pon_tiled_io classical` and `pon_tiled_io strassen-one-level` are bounded offline
bridges for an independent process to compare actual native certificate bytes.
Stdin is exactly the 32-byte challenge followed by the two 4096-element canonical
little-endian u32 matrices; stdout is the 49,188-byte PNW1 certificate. Extra or
missing bytes, invalid fields and unknown operations fail explicitly. The bridge
has no network, signing, chain or verification authority. Independent checks can
write the scalar Python oracle's complete proof and compare the two byte arrays,
while preserving the actual input/output files and executable/source identities.

Cheap affine maintenance matvecs, lower rank, or a full-rank input classification
do not independently qualify the complete transcript's hardness. Neither this
producer experiment nor two hosted architectures resolve GPU/ASIC implementations,
arbitrary preprocessing, all useful-input distributions, fastest adversaries or
the full recomputation verifier's rejection cost. All existing qualification and
activation flags remain false.
