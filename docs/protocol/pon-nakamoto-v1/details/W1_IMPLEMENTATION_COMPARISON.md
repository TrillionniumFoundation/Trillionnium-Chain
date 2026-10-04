# W1 implementation equivalence and cost comparison

This work preserves the admitted `pon-matmul-transcript-64-v1` relation, proof grammar,
task identity, challenge, ticket, target and fork weight. It changes local algorithms
and adds an executable comparison. It does not activate a profile or establish mining
hardness, permissionless admission safety, model usefulness or external acceptance.

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
