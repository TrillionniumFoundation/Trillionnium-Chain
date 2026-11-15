# W1 factorial legal attempts and actual reuse V3

This is a separate PN1 experiment within the [canonical development plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
It preserves the [V1 experiment](W1_LEGAL_STRATEGY_V1.md), its two-sample captures,
readers and failures. No observation is relabelled as V3 or promoted to work,
hardware, public-service, model, quantum or production qualification. PN1 remains HOLD.

## Frozen two-factor comparison

| Cell | Complete transcript arithmetic | PNW1 proof materialization |
| --- | --- | --- |
| `eager-transposed` | Transposed | Every attempt |
| `lazy-transposed` | Transposed | Only a target hit |
| `eager-full-limb` | FullLimb | Every attempt |
| `lazy-full-limb` | FullLimb | Only a target hit |

All four cells pay the same original `PreparedTask::new` AB/prefix preparation.
Only challenge-dependent arithmetic and proof materialization vary. Every attempt
computes the entire original transcript and ticket; a lazy miss avoids copying
49,188 proof bytes, not any transcript work. Every hit produces the original full
PNW1 bytes. `Attempt` grants no verification or task-admission authority.

The cells share existing complete transcript kernels and their cancellation
boundaries. V3 transposed retains the kernel's CP intermediate, unlike V1's
prepared-generic path, so the two experiments are not interchangeable baselines.
Four-cell call order rotates. The same `black_box` observations protect actual
attempt values and eager losing bytes from dead-code elimination in every cell.
The production producer, verifier choice, relation, ticket and fork weight do not change.

## Eight samples, thirty complete shards

The fixed grid is five material classes, two target indices and reuse horizons
1/8/64. Each shard has eight distinct challenge sample identifiers and four cells.
Classes are full-rank field, zero, continuity maintenance, left-zero/right-rank-one
and right-zero/left-rank-one. Targets remain `7f` or `07` followed by 31 `ff` bytes.
The ideal uniform-ticket model gives probabilities 1/2 and 1/32; it is an assumption.

Each cell/sample/horizon pays one actual setup and keeps that object through all
searches. Each search permits 4,096 complete attempts and stops at its first hit.
Exhaustion retains every miss and its paid cost, without inventing a winner.
Task, target, seed zero, sample, search index and nonce bind the V3 challenge.
Horizon prefixes intentionally repeat and are not new independent work samples.
These primitive challenges do not establish live PNH1 parent or task eligibility.

## Timing, retained bytes and refusal

Producer CPU/wall includes setup, all complete transcripts and tickets, actual
proof materializations, eager losing-proof destruction and binary trial retention.
Successful PNW1 serialization is included. Common material generation is reported
separately. Later destruction of retained objects is outside the producer interval.

Complete attempt proof digests and JSON Value construction have a separate
`evidence_timing`, after the producer timer. Prefix-hash state is reused for these
digests. JSON output serialization/I/O and native verification are outside both
intervals. These explicit scopes are not an end-to-end mining or service cost.
The reader binds every nonce, trace, ticket, digest and actual materialization flag,
and checks measured proof counts/serialized bytes against the selected cell.

Every winner and a separately timed canonical last-product mutation are checked
by production, scalar reference, limb and explicit FullLimb verifiers. Production
and explicit FullLimb currently share arithmetic and are not independent kernels.
The original `Product` refusal, complete returned statement and every unexpected
verdict remain visible; semantic alerts suppress the comparative cost effects.
The separate false-trace experiment retains its own measured denominator.

## Execution and interpretation

```sh
pon_w1_legal_strategy_v3 --legal-strategy-v3 --class full-rank-field --target-index 1 --reuse-winners 64
```

The V3 reader's `analyze_shard(path)` labels one complete shard only; `analyze(paths)`
requires all thirty unique shards and matched cross-horizon prefixes. The runner
retains the original 300-second cap per shard and 900-second build cap. Missing,
failed, partial or timed-out shards remain failures. Raw sample totals support both
simple effects of each factor and their interaction; no per-sample fastest oracle
or hypothetical setup division substitutes for an executable strategy.

Eight samples satisfy only the unchanged sample-count condition. Full-grid record
consistency and source/binary checks do not prove clock truth, a cheapest legal
algorithm, physical energy cost, independent hardware, quantum security or service.
No native cost outcome is asserted by this specification; expected call counts
are not observations. Every qualification flag remains false and status remains HOLD.

## Related History check deduplication

The accompanying History change keeps Host checks at every original W1 boundary
and throughout refill waits. It removes only a second, adjacent check at selected
boundaries. The no-refill fixture's source-derived callback reduction is about
2.3% for false-trace rejection and 2.7% for valid work; these are counting estimates,
not measured CPU savings, physical cgroup-read reductions or confirmation gains.
Original CPU/Host budgets, deadline, cancellation, accounting and refusal semantics
remain. Public-service and original-budget acceptance require their own execution.
