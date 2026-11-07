# Complete W1 rank and batch experiment V5

This component experiment implements an exact bounded low-rank product
preparation and an actual bounded parallel search. It preserves the original
PNW1 bytes, challenge-dependent transcript, lottery, verifier and default
producer. It grants no work eligibility, admission, state transition or
external-effect authority. The sole development plan remains
[the existing plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

## Exact preparation and its paid failure path

[`Task::with_rank_preparation`](../../trillionnium/crates/trnm-crypto-primitives/src/pon_work/legal_attempt.rs)
validates all canonical words of both matrices before either probe. The
[new factorization](../../trillionnium/crates/trnm-crypto-primitives/src/pon_work/legal_attempt/low_rank.rs)
constructs a normalized row basis over the existing prime field
q = 2^32 - 5, retaining at most eight basis rows. It uses exact modular
arithmetic with no floating-point tolerance, trusted rank claim or supplied
factor witness. Coefficients and pivots are local to one preparation.

If A has rank r <= 8, the constructor computes A = UV and AB = U(VB).
If nine independent rows are found, that failed probe has already consumed
time and temporary memory; the constructor then probes B. If B has rank
r <= 8, it computes B = UV and AB = (AU)V. If both probes exceed eight,
it invokes the ordinary dense preparation after paying both probes.
The selected path and actual rank are explicit observations. All dot-product
dimensions remain at most 64, preserving the existing exact reducer bound
of less than 2^70. Rank zero still requires full input validation and complete
canonical A/B/C proof-prefix serialization.

This is an algorithm over arbitrary canonical inputs. The rank-two,
rank-four and rank-eight materials exercise it with a dense full-rank partner;
the rank-nine material exercises detection failure and dense fallback. The
old rank-one and zero-specialized producers remain competitors. A chosen
low-rank fixture alone is not evidence of a new low-rank algorithm or of real
encoder/material provenance.

## Complete trace and lawful early stopping

Only the challenge-independent AB/prefix preparation is reused. Every
attempt still expands the original bounded rejection-sampled noise and
executes the same ordered 512 transcript tiles through FullLimb. A target
miss may avoid allocating the final proof buffer only after the complete
trace and ticket are known. A caller cancellation returns no proof and
retains no trace checkpoint for a different challenge. Zero target is
refused before starting work.

The [native sampler](../../trillionnium/crates/trnm-crypto-primitives/examples/pon_w1_rank_batch_v5.rs)
creates at most four scoped workers per batch, including a smaller final
batch when the fixed attempt budget has fewer than four entries left. Every
launched worker is joined, even after an error, panic or earlier ticket hit.
The winner is the first hit in the predeclared nonce order; completion order
does not select a favorable sample. All already computed attempts after
that winner remain in the ledger and cost denominator. There is no abort
saving inside an issued batch. This models one speculative producer, not
four independent miners or four independently credited winners.

All post-winner attempts receive full production and independent scalar
replay at maximum target, separately timed. The chosen winner is checked by
both verifiers at the original target. Its canonical last-C-word mutant
must fail with Product on both paths. A miss is retained with its complete
trace/ticket/proof commitment even when no proof buffer was materialized.
The reader reconstructs AB and all commitments but does not itself replay W1.

## Frozen comparison and accounting

The new command selects exactly one of 66 shards: eleven declared materials,
two search-cost targets (ideal probabilities 1/2 and 1/32) at actual reuse
horizons one and eight, plus one three-attempt exhaustion and one
three-attempt first-hit control per material. Each shard uses eight sample
identifiers and all seventeen fixed strategies. Samples rotate invocation
order deterministically. Cost searches retain the original 4,096-attempt
cap; controls cannot replace cost shards. The older V3/V4 horizon-64
observations remain separate evidence and are not relabelled as V5.

The strategies are dense, sparse and rank-bounded lazy FullLimb; the
rank-bounded four-worker batch; and all thirteen existing scalar, prepared,
structured, tiled, paired, zero, one-zero and maintenance producers. Every
strategy pays its constructor in every sample, including a constructor that
reports unsupported. There is no per-sample fastest-strategy oracle.

Producer cost includes actual preparation, failed rank probes, dense fallback,
every complete hit and miss, speculative work, thread creation/join, losing
and winning proof-buffer destruction and task teardown. Process CPU clocks
include all worker threads; an unavailable CPU clock remains unknown.
Commitment checking/JSON values and verification are separately measured.
Inclusive cohorts and the enclosing wait4 command measurements retain
output, audit and other overhead without adding overlapping timers twice.
Shared material generation, rank checking and the independent reference
prefix constructor are reported once per shard, not silently granted to each
producer or divided by an invented reuse count.

[`run_w1_rank_batch_v5.py`](../../scripts/ci/run_w1_rank_batch_v5.py)
requires one clean committed source and rechecks complete tracked bytes
before and after every command. It compiles the original Rust 1.95.0 release
configuration, retains its exact ELF, and checks original/retained binary
hashes around execution. Its original limits are 30 seconds for identity,
900 for build, 300 per shard and five seconds of TERM grace. Output paths
must be new and outside the source tree. Failed commands retain partial
stdout/stderr, exit/signal/timeout and kernel wait4 CPU/RSS. It does not retry
or discard failed shards. Missing or truncated ledgers stay HOLD.

Example after source integration and freezing, with an existing valid
`CARGO_HOME`, `CARGO_TARGET_DIR` and Rust 1.95.0 on PATH:

```sh
bash scripts/project-preflight.sh
unset RUSTC CARGO_INCREMENTAL
python3 scripts/ci/run_w1_rank_batch_v5.py --arch x64 \
  --expected-commit "$(git rev-parse HEAD)" --output /absolute/new/observation
```

The runner preserves the existing build-override refusal rather than
allowing a different compiler or code-generation flags. Host/cgroup identity
is recorded. wait4 peak RSS is not aggregate simultaneous global memory,
and unreaped descendants of a failed build may be missing from CPU totals.
These observations cannot substitute for the original quarter-CPU, 2-GiB,
no-swap public-service experiment.

## Security assumptions and proof boundary

The rank arithmetic requires the existing prime-field and reducer bounds.
The nominal target probabilities assume uniformly distributed SHA-256
tickets; this finite campaign does not prove independence, a random-oracle
security theorem or a lower bound on cheapest legal work. Horizons share
challenge prefixes intentionally and cannot be pooled as independent
observations. Best observed fixed-strategy rates are finite comparisons,
not a guarantee over all materials, targets, CPUs, GPUs, FPGAs or ASICs.
Energy, hardware purchase cost and quantum cost are not measured here.

The current [complete v2 guest](w1_zkvm/methods/guest-v2/src/main.rs)
already calls the [full native relation](w1_zkvm/relation/src/lib.rs) and
[binds original A/B commitments](w1_zkvm/relation/src/v2.rs), complete header,
trace, ticket, original block identity and all product bytes. Current native
verification already selects FullLimb, and the guest SHA-256 extension is
pinned. This preparation optimization does not remove the guest's full
noise/trace/product replay or its recursive STARK work. A changed guest
requires a distinct image ID and a fresh real proof; old receipts cannot
establish its cost or validity.

The retained complete proof and the later failed deadline campaign remain
separate observations. No proof generation is performed by this V5 sampler.
An alternative dedicated circuit must enforce every canonical word, ordered
transcript prefix, rejection rule and public binding, then demonstrate real
generation latency and verifier benefit. A smaller journal or an AB-only
certificate cannot substitute for this relation. Encoder provenance,
routing, output/state transitions and external-effect exclusion additionally
belong to the full Cell relation and remain outside this matrix component.
Nothing here closes those proof, resource, security or adoption gates.
