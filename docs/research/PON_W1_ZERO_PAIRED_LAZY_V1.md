# W1 zero-paired arithmetic with winner-only proof construction V1

Status: **component research; work security and production qualification HOLD**.
This continues the [authoritative development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
It adds a legal strategy to the tested set, not a minimum-cost theorem.

## Concrete gap

The [implementation comparison](../protocol/pon-nakamoto-v1/details/W1_IMPLEMENTATION_COMPARISON.md)
already records the generic prepared schedule (262,144 one-time products and
327,680 products per challenge) and later integer-paired schedules. The zero
integer-paired kernel has 152,832 scalar-product operations per challenge.
Those operations include products of 33-bit sums and are not interchangeable
with ordinary 32-bit representative products or measured hardware costs.

The retained V5 rank/batch experiment supports lazy proof construction for
its generic FullLimb arms, while its specialized zero-paired arm calls the old
eager `prove`. Consequently that grid did not compose these two legal choices.
The new API and separate experiment close that specific combination gap.

The [zero-paired producer](../../trillionnium/crates/trnm-crypto-primitives/src/pon_work/blocked_zero_paired.rs)
now also exposes `attempt` and cancellable `attempt_with_progress`, returning
the existing unverified `legal_attempt::Attempt`. It replays all four noise
arrays and all 512 transcript tiles with the original arithmetic kernel.
The original `prove` methods and their observation order remain intact.
`EveryAttempt` materializes the complete PNW1 bytes before computing the ticket;
`TargetHit` computes the ticket first and materializes bytes only on a hit.
Every hit still requires complete verification and current Node admission.

The specialized constructor validates the complete canonical operands and
supports only exact A=B=0. A different task is unsupported, not silently
substituted. An all-zero target remains an error under the existing API.
No consensus relation, target rule, task-selection authority, chain weight,
reward, production default or receiver budget changes.

## Registered comparison

The [native entry](../../trillionnium/crates/trnm-crypto-primitives/examples/pon_w1_zero_paired_lazy_v1.rs)
fixes these five arms before execution:

| Arm | Fixed product preparation and transcript kernel | Complete proof bytes |
| --- | --- | --- |
| full-limb-sparse-eager | Existing sparse preparation and FullLimb transcript | Every attempt |
| full-limb-sparse-lazy | Same as preceding arm | Target hits only |
| zero-paired-legacy | Existing zero-paired constructor and original prove method | Every attempt |
| zero-paired-eager | Same zero-paired constructor and new target-aware API | Every attempt |
| zero-paired-lazy | Same zero-paired constructor and new target-aware API | Target hits only |

The FullLimb comparator uses its existing sparse preparation on zero material;
it is not charged a deliberately expensive dense product. Each cohort pays its
own actual preparation. There is no per-sample choice of the observed fastest arm.
The old producer provides a compatibility and implementation-overhead control.

Each of the six shards has eight sample identities and all five arms:

| Target index | Target bytes | Searches per actual preparation | Attempt cap |
| --- | --- | --- | --- |
| 0 | 7f followed by 31 ff bytes | 1 and 8, in separate shards | 4,096 per search |
| 1 | 07 followed by 31 ff bytes | 1 and 8, in separate shards | 4,096 per search |
| 2 | 31 zero bytes followed by 01 | 1 | 3 |
| 3 | 32 ff bytes | 1 | 3 |

The last two shards are exhaustion and first-hit controls. They are not cost
samples at the ordinary targets. Horizons count actual searches, not promised
winners. Searches stop at their first hit or retain every attempt at exhaustion;
no replacement winner or retry fills a missing observation. There are 240
registered cohorts and 800 registered searches across the complete grid.

Arm order rotates as `(position + sample) % 5`. With eight samples this is
deterministic rotation, not perfect position balance or a statistical power
guarantee. Challenge input binds task, target, sample, search and nonce, excluding
arm and horizon. Complete streams must match across arms and nested horizons.
Nested prefixes are intentionally correlated, not additional independent samples.

## Complete accounting and interrupted observations

The producer cost is the sum of disjoint setup, attempt, losing-buffer disposal,
winner cleanup and prepared-object teardown intervals. Attempt time includes
challenge construction, full transcript, ticket, chosen materialization and
the same best-effort optimization barriers. Every materialized proof's complete
slice is observed before the producer timer ends. Separately timed audit work
hashes its actual 49,188 bytes; a lazy miss instead hashes the canonical prefix
and trace without claiming that a proof buffer existed. Eager disposal is paid.
Rust `black_box` is a benchmark aid, not an execution-authentication proof.

Audit digest/identity time, full verifier time, inclusive search/cohort time and
outer process usage are separate scopes. Inclusive times overlap the components
and must not be added to them. JSON construction, flush, comparisons, mutant and
exhaustion-replay reconstruction contribute to inclusive cohort/process cost,
not to a fictitious native mining primitive. Material preparation precedes the
header and has a reported interval; process startup, final journal output,
collector work and host/device costs require their external receipts.

Each cohort, search, attempt, verifier and winning-buffer cleanup has a flushed
begin record before its operation. A sink failure prevents the next operation.
Missing completion, partial final bytes, failure or unknown/nonzero process exit
remain incomplete with unknown unfinished cost. A begin does not prove that the
following native call started, completed or became power-loss durable. The final
cohort interval ends before its own output record, which is included only by the
outer process receipt. Prepared-object teardown occurs between the last complete
search and cohort completion; a missing cohort end cannot assume zero teardown.

A completed observation requires every winner to be accepted by the original
production and scalar-reference full verifiers. Both must reject the canonical
last-product-word mutation as `Product`. Every miss in an exhausted control
search is reconstructed and fully replayed by both verifiers at maximum target,
retaining its original-target miss identity.
Verifier records bind the actual target and complete proof digest.

The [reader](../../scripts/pon_w1_zero_paired_lazy_v1.py) checks the fixed roster,
sequence grammar, exact task/challenge/ticket/proof commitments, materialization,
stop position, verifier roster, counts and all-arm stream agreement. Its report
does not itself replay W1 or authenticate an execution. It reports aggregate
costs and paired cohort observations; zero-winner cost-per-win remains null.
The six-shard campaign check also compares nested horizon prefixes.

## Reproduction and validation

Use the normal project preflight and a complete clean committed checkout. The
[runner](../../scripts/ci/run_w1_zero_paired_lazy_v1.py) reuses the original V5
whole-source guard, sole wait4 reaper, 900-second build cap and 300-second per-shard
cap. It retains original stdout/stderr, timeouts, exact source/tree before and
after, host observations, Rust 1.95.0 identity and actual retained release ELF
hashes. Output must be a new directory outside the checkout. No source guard,
deadline, original campaign or failed observation is weakened.

```sh
bash scripts/project-preflight.sh
export CARGO_TARGET_DIR=/absolute/w1-build-target
python3 scripts/ci/run_w1_zero_paired_lazy_v1.py --arch x64 \
  --expected-commit "$(git rev-parse HEAD)" --output /absolute/new-observation
python3 scripts/ci/test_pon_w1_zero_paired_lazy_v1.py
```

Native controls exercise exact ticket and ticket-minus-one boundaries, eager
and lazy bytes against the original producer and both verifiers, all transcript
tiles and cancellation stages, changed task binding, complete operand
validation and zero-target refusal. Reader mutation controls distinguish
synthetic record grammar from actual native execution. Finite passing controls
and a complete local grid cannot establish all-algorithm optimality.

## Work-security interpretation

For independent uniform 256-bit tickets and an inclusive target T, the ideal
success probability is `(T+1)/2^256`. This is an explicit model assumption, not
a result of the observed finite grid. For one shared preparation P, per-miss
cost c_f and per-success cost c_s, independent stationary trials to the first
winner give `E[C] = P + (1-p)c_f/p + c_s`. If every trial costs c and only the
winner adds proof-construction cost f, this becomes `P + c/p + f`.
Finite caps, correlated tickets, adaptive task/branch choice and retained
classical or quantum state require their full lifecycle model instead.

The [ESA 2026 primary paper](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.ESA.2026.2)
still states optimal adversarial hardness as a conjecture. Its asymptotic
assumption and separate streaming definitions do not supply a concrete lower
bound for this 64-by-64, rank-8 implementation. A successfully executed cheaper
legal strategy lowers an achievable-cost baseline; it does not prove that no
even cheaper strategy exists.

The tested material is zero. Existing sparse, low-rank, diagonal, maintenance,
false-transcript and finite-lifecycle evidence retain their own source scopes.
Actual short-column extraction, shared preparation across miners/epochs,
GPU/ASIC/energy costs, self-selected demand, current admission, joint DAA and
chainwork security remain distinct obligations. This grid does not measure
maintenance costs when real demand is absent, sponsor self-traffic, repeated
reward collection, or false-transcript search and receiver rejection costs.
Arithmetic-output counting,
consensus credit, mining subsidy, model contribution and service fees must not
be conflated. This observer grants zero consensus credit or economic payment.

## Recorded native observation

The [frozen-source results and complete strategy-coverage ledger](../../evidence/pon-w1-zero-paired-lazy-20261112/README.md) retain all six registered shards on source `165d286b687e0a73d7fe68148d2179274fc0c0b8`. The four cost cells observed the same fixed `full-limb-sparse-lazy` arm below the new `zero-paired-lazy` arm in aggregate CPU and wall cost per accepted winner. The new composition is a measured legal alternative, not the fastest measured arm or an attacker lower bound. The original OpenSSL compile failure, source-index refusal and separate successful pinned-provider supplement remain distinct. The evidence child keeps the measurement source unchanged; production and work-security qualification remain HOLD.
