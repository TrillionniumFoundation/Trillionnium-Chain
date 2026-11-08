# Grouped Cell legal-work and lottery audit v0

Status: **implemented research audit / HOLD**. Continue the sole development
plan and existing integration candidate PR #688 from
`3d1b6507671ec694ce58e86d4063a125c8deeb66`. This audit neither registers a work
profile nor changes native W1, chainwork, DAA, fork choice or activation.

The [grouped operator](GROUPED_CELL_OPERATOR_V0.md) already checks the router,
stable groups, selected expert and complete scatter/output relation. Correct
arithmetic and expensive fresh lottery queries are separate requirements. The
audit makes that distinction executable and compares lawful producers without
requiring an unnecessarily dense implementation.

## Implementation and ownership

- [Canonical lottery audit](../../../../formal/pon-nakamoto-v1/grouped_work_lottery_v0.py)
  and [independent adversarial tests](../../../../formal/pon-nakamoto-v1/test_grouped_work_lottery_adversarial_v0.py).
- [Legal strategies and complete operation counters](../../../../formal/pon-nakamoto-v1/grouped_legal_strategy_v0.py)
  and [strategy tests](../../../../formal/pon-nakamoto-v1/test_grouped_legal_strategy_v0.py).
- [Frozen strategy campaign](../../../../formal/pon-nakamoto-v1/experiments/grouped_legal_strategy_v0.py).
- [Source-bound lottery and native cross-check campaign](../../../../formal/pon-nakamoto-v1/experiments/grouped_work_lottery_audit_v0.py).
- [Bounded GPU comparison](../../../../formal/pon-nakamoto-v1/experiments/grouped_gpu_legal_v0.py).
- [Existing conditional query bound](../../../../formal/pon-nakamoto-v1/work_query_bound.py).

M01 retains the arithmetic-verification boundary. These Python audit modules
own no production admission, identity, demand, payment or durable query journal.
The external expected candidate must come from the caller's independently
established task/parent/target policy. Supplying a miner's candidate as its own
policy does not authenticate that policy. Local execution order is not an
externally witnessed chronological commitment.

## One fixed relation for the lottery experiment

`pon-grouped-int257-lottery-audit-v0` fixes 16 ordered requests, three classes,
three experts and 257 features. It reuses the original
`pon-routed-int257-grouped-research-v0` arithmetic: signed original coefficients
in `[-32767,32767]`, features in `[-8,8]`, bias coordinate 8, exact i64 sums and
lowest-index argmax ties. The profile identity binds this numeric contract and
batch size. No shape, dtype, partition, routing policy or alternative weight rule
is selectable inside one candidate.

Every complete model, model-version identity, request identity, authorized-scope
identifier, original arrival/deadline and feature value is committed. The expected
model and request list are independently supplied to the verifier. Scope strings
remain identifiers: the audit does not authenticate external authorization.

The per-logit conservative absolute bound is `257 * 65534 * 8 = 134737904`.
The router bound is `257 * 32767 * 8 = 67368952`. The fixed dense merged strategy
uses 24,672 MAC positions at batch 16. Those positions describe an implementation,
not mandatory producer work, measured FLOPs, business demand or reward.

## Acyclic candidate, challenge and ticket

The dependency order is explicit:

1. Validate and freeze the original model and ordered request bytes. Compute the
   fresh `pon-grouped-preinput-audit-v0` commitment. It contains no challenge,
   output, proof, ticket or post-execution state.
2. Encode the fixed candidate: network, parameters, parent, target, payee, task,
   model commitment, preinput commitment, batch ID, independently determined
   transaction commitment, **prior** state root, height, timestamp and nonce.
3. Derive `pon-grouped-challenge-audit-v0` from that candidate.
4. Use this challenge in the existing grouped context and input/statement
   commitments. Validate the complete router/gather/expert/scatter product.
5. Derive the ticket from the challenge and unique canonical statement; derive
   the research receipt identity from candidate, statement and ticket afterward.

The new wire prefix is `PGLA` plus version bytes. Its header is exactly 414 bytes.
Fixed hash fields use 32 bytes; integers use unsigned big-endian u64. The profile
hash binds the operator profile, numeric rules and batch size. Decoding requires
the one exact length, prefix, profile and re-encoding. Hash strings must be
lowercase 64-digit hex; booleans and floats cannot alias integer fields.

The external expected header is checked before full verification. A target
changed after observing a ticket must produce a different challenge and cannot
replace that expected context. Unknown fields such as `resulting_state_root`,
`proof`, `ticket`, `challenge`, `shape` or `dtype` cannot enter the preimage.
The audit does not assert that every field of an arbitrary future production
header can be computed before work; such a header needs its own dependency audit.

The JSON carrier is bounded and rejects duplicate keys. JSON ordering and the
bounded opaque transport auxiliary bytes are excluded from ticket identity.
Auxiliary bytes are not a succinct proof. Correctness is established by full
independent recomputation from original matrices and inputs. Arbitrarily
randomizing an actual future proof is legal only if its own verifier accepts it;
that future proof format is not implemented here.

## Confirmed counterexample: correct cached work can produce new tickets

The original grouped operator's arithmetic does not depend on `Context.challenge`.
For fixed model and requests, router scores, routes, stable groups, logits and
predictions are unchanged when the nonce, parent or another independently fixed
candidate field changes. A producer can therefore retain one exact product and
perform only validation, serialization and hashing to construct further audit
tickets. The implemented cached producer pays invariant byte encoding once,
retains an immutable product, and reuses those bytes for fresh context-dependent
hashes. It is compared with the uncached canonical builder. Full verification
still accepts the arithmetic relation; neither implementation is declared the
globally cheapest producer.

This is a demonstrated obstacle to promoting the **new hash-only lottery
wrapper**, not an accepted attack on native W1. The native W1 transcript includes
challenge-dependent noisy work; its fixed PNW1 encoding and ticket construction
are unchanged. No 64-way free-proof variant vulnerability in W1 is claimed.

Every audit receipt therefore returns `chainwork_awarded = 0`, zero business and
model credit, `minimum_fresh_work_proved = false`, `pow_qualified = false`, and
`HOLD_CHALLENGE_INVARIANT_ARITHMETIC`. There is no configuration flag that converts
a passing audit receipt into consensus work.

## Lawful strategy comparison

| Arm or input class | Required comparison and accounting |
| --- | --- |
| Direct original coefficients | Router plus only selected base and delta; no unselected experts. |
| Cached merged weights | Charge exact base-plus-delta preparation once, then selected contractions. |
| Stable grouped execution | Charge gather/scatter and the same selected outputs; no padding credit. |
| Sparse inputs | Scan and key costs remain; the bias cannot be silently zeroed. |
| Repeated activations | Reuse only exact model/input/representation/scope/generation keys; fresh request authority/lifetime checks remain necessary. |
| Exact factors | Validate the entire `B A` against the original delta before reuse; charge normalization, base, router and `B(Ax)`. |
| Low rank, zero non-bias, repeated rows, extreme values | Keep the same fixed arithmetic and compare every route/logit/prediction with an independent original-coefficient reference. |
| Quantization, saturation or floating-point reassociation | Reject changes to this relation; use a separately defined numeric profile for any changed semantics. |

The retained trained model is distinct from explicitly synthetic structured or
factorized fixtures. A factor strategy is unavailable when its factors have not
been established exactly; the runner records that outcome rather than silently
using a dense implementation. Normal factor execution is not cheating.

The familiar `d=4096, r=16` ratio of 128 compares a pure factored adapter branch
with a dense expanded adapter contraction. It excludes the base and router,
does not apply to this three-output profile, and is not a W1 attack factor or
an end-to-end LLM speedup. For narrow output matrices, cached merged inference
can be cheaper than an exact factor strategy.

Shared encoder weights reduce residency, not the encoding required for different
inputs. Activation reuse additionally requires identical requested representation,
model/generation and a compatible authorized scope. This audit measures pure
arithmetic reuse and cannot grant cross-owner access.

## Queries, misses, failure cost and timing denominators

Use the existing exact rational conditional query model. For fixed-before-query
target `T`, ideal independent uniform tickets give `p=(T+1)/2^256` and
`w=floor(2^256/(T+1))`, hence `E[wX] <= 1`. The nominal weight is diagnostic only.
The formula does not bound CPU/GPU/energy per first query, quantum coherent
queries, adversarial choice after seeing the ticket, or total service costs.

The finite audit records the plan before execution, including repeated nonces.
It records a query as soon as its ticket is computed, **before** semantic or
deadline verification. An expired/refused request cannot disappear from the
distinct-query denominator. Repeating the same input is an attempt with cost
but is not a new distinct oracle query. Misses, producer cost, full verifier
cost, setup and total supervisor time are retained. Unattributed phase time
remains in total attempt cost; it is not replaced by zero.

The independent toy control deliberately allows choosing `T` after an 8-bit
ticket and obtains expected nominal credit `669/128`, demonstrating why the
predictable-target hypothesis matters. Another control shows how hypothetical
64 independent free encodings would multiply low-probability opportunities.
These controls do not say that either freedom is accepted by native W1.

Python operation counts and timings, native kernels, native full verification,
GPU kernel timings, transfer/setup, and complete remote task time have distinct
denominators. Repeated warm samples do not create new application demand. A
binary64 backend is exact for this integer relation only after proving all
products and absolute partial-sum bounds lie inside its exact-integer range;
generic floating-point tolerance is not sufficient for lottery equality.

## Qualification still required

The executable binding and correctness checks close specific engineering gaps.
They do not supply the missing fresh-work relation. Before any registration or
positive chainwork, a successor must address all lawful reuse and input/context
choice strategies, state its computational assumptions, compare the strongest
known lawful implementations and all failed work under fixed resources, bind
real demand/authority, and include proof/verification/availability/propagation.
Hardware comparisons cannot establish an unknown global minimum by themselves.

Authenticated challenge ownership, target admission, Sybil/bulk precommit cost,
cross-parent amortization, quantum security, original hostile-service budgets,
independent future model benefit and funded effects remain separate gates.
No old failure, UNKNOWN task, resource limit or cost denominator is overwritten.

## Reproduction

Use a clean allowed development checkout at the selected source SHA and the
locked native release example. Store observations outside the source checkout
while the repository's strict source-integrity guards are running:

```bash
bash scripts/project-preflight.sh
cargo build --locked --release --manifest-path trillionnium/Cargo.toml \
  -p trnm-crypto-primitives --example pon_routed_int257_grouped
TRNM_GROUPED_NATIVE=/absolute/path/to/pon_routed_int257_grouped \
  python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_grouped*.py' -v
python3 formal/pon-nakamoto-v1/experiments/grouped_legal_strategy_v0.py \
  --source-sha EXACT_SOURCE_SHA --batch-size 16 --rounds 3 --replay-source \
  --out /absolute/new/strategy-observation
python3 formal/pon-nakamoto-v1/experiments/grouped_work_lottery_audit_v0.py \
  --source-sha EXACT_SOURCE_SHA --runner /absolute/path/to/pon_routed_int257_grouped \
  --out /absolute/new/lottery-observation
```

These commands require the historical corpus Git objects as well as the current
source. Missing original blobs are a replay failure, not permission to replace
features with a new corpus. The GPU runner consumes a frozen payload containing
the same model/16 inputs and an independent expected product. Its embedded
payload mode has an explicit no-CLI entrypoint for the retained Colab `runpy`
launcher; ordinary `--payload` execution remains available. Device eligibility,
allocation, workload submission, execution, artifact readback and owned-resource
release must each retain their own authoritative identity and outcome.
