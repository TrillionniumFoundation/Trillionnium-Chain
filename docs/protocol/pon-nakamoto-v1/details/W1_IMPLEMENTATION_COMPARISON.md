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
prefix allocation. The rank-one and product-only paths reuse the full prepared
transcript kernel; only the zero-zero path changes the transcript multiplication order.

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
