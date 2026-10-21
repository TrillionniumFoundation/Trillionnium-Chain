# W1 same-target producer and receiver budget report

`pon_w1_budget_report` is a bounded native diagnostic for the installed
`pon-matmul-transcript-64-v1` primitive. It measures complete producer searches
and full verification on the **same public task and target**, then replays the
retained winning candidates through one original `ServiceMutationCpuDomain`.
It does not change W1, PNW1 bytes, ticket construction, required work, cumulative
work selection, block admission or the installed verifier.

The [local security profile](W1_LOCAL_SECURITY_PROFILE.md) records the exact
2026-10-18 source observation, retained raw hashes, complete measured ratios,
distinct proof counts and actual original-budget depletion/refill. It also gives
the read-only reader/derivation commands and preserves that batch's other failures.

The source is
[`pon_w1_budget_report.rs`](../../../../trillionnium/crates/trnm-pon-node/examples/pon_w1_budget_report.rs).
The direct false-trace primitive is shared with the existing
[`public_v3_from_zero`](../../../../trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero.rs)
service regression. That service regression remains the separate evidence for
actual packet dispatch, shared service accounting, state preservation and signed
business confirmation under false-trace traffic. This report does not reproduce
or replace that regression.

## Inputs and reproducibility

Run from the repository root after the original project preflight. Use a new
output path for each run; retain stdout, stderr and exit status, including failed
or exhausted observations. An example small run is:

```sh
bash scripts/project-preflight.sh
cargo run --locked --release --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --example pon_w1_budget_report -- \
  --samples 2 --attempts 32 --receiver-replays 1 --seed 1
```

The interface accepts `--samples 1..16`, `--attempts 1..4096`,
`--receiver-replays 1..1024`, a `u64` seed and an exact 32-byte hexadecimal
`--target`. Defaults are one sample, eight attempts, one receiver replay and
`7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`.
A zero target deliberately retains complete bounded exhausted searches and
produces no winning candidates. No exhausted arm is replaced with an easier
or different target. Increasing `--receiver-replays` repeats the retained
candidates on the same receiver domain; a run that never exhausts credit reports
that observation instead of claiming cancellation occurred.

Four deterministic material classes are dense, all-zero, rank-one and sparse.
The public material recipe, seed, exact task digest and target are reported.
Material construction has its own measured row. It is outside every per-arm
producer denominator because all arms receive the same public operands. These
are constructible diagnostic tasks, not a claim about real task provenance,
useful demand or the frequency of a structure in the installed network.

| Arm | Work actually performed | Unsupported material |
| --- | --- | --- |
| `generic` | Original `PreparedTask` validation, product/prefix setup and complete transcript generation for every trial | No structural restriction |
| `structured` | Original checked `StructuredPreparedTask`, including its structure validation and complete proof construction | An explicit `unsupported` row; no implicit generic fallback |
| `blocked-zero` | Existing zero-only preparation and complete blocked-prefix transcript implementation | An explicit `unsupported` row |
| `from-zero-false-trace` | Public A/B proof prefix, zero claimed C, and hash search over a claimed transcript; no product or valid trace acquisition | Canonical public input is still required |

The legal producer arms use the exact same challenge stream for each
class/sample/nonce. Their winning proof commitments and full-verifier outcomes
can be compared directly. The false-trace arm instead holds the first challenge
fixed and varies its **claimed** transcript using the existing
`public-v3-from-zero-v1` trial function. A matching target is named
`target-hit-unverified`: it supplies no `VerifiedWork` or admission authority.

## JSONL observations and denominators

Each line uses schema `pon-w1-same-target-budget-v1`. The output is flushed after
each observation, so earlier cases remain available if a later native call,
clock, output write or process fails. No missing line is an implicit pass.

| Row kind | Meaning and measured scope |
| --- | --- |
| `campaign` | Input bounds, target, seed and unchanged W1 profile |
| `public-task-material` | Public A/B construction and task digest computation |
| `producer` | One setup plus every failed and successful trial, or explicit unsupported/exhausted status |
| `raw-verifier-diagnostic` | Complete production, scalar-reference or limb primitive verification without receiver budget cancellation |
| `receiver-domain-start` | The one original standalone domain and its original resource parameters |
| `receiver` | Start refusal, or original metered production verification, native outcome and actual CPU settlement |
| `receiver-summary` | All requested/started replays, separate verified/relation/cancelled/refused counts and the shared accounting balance |

Producer `total` includes preparation, the entire search, allocation, proof
construction and in-memory trial records. `setup`, `search` and per-trial timing
are nested within that total; they must not be added to the total a second time.
Final JSONL serialization is excluded from producer totals. No ratio divides a
complete verifier by only the final successful hash or the final winning proof.
`receiver_cpu_over_full_producer_search_cpu` divides one full raw verifier CPU
interval by that arm's complete setup-plus-search CPU interval, including all
misses. It remains null if either clock is unavailable or the denominator is
zero. This is a sampled ratio for one implementation/target/material/seed, not a
minimum attacker cost or an economic security bound.

Clocks record the calling thread's actual CPU and monotonic elapsed wall time
separately. A missing Linux clock, a moved interval, numeric overflow or a
reversed interval remains null. No wall estimate fills a missing CPU value.
The producers and primitive verifiers in this example run sequentially without
scoped child workers. Actual service evidence that spawns workers must continue
to use the original owner-plus-scoped-worker settlement rather than this
single-thread producer timing.

Raw verification and budgeted replay are deliberately separate observations.
A full diagnostic relation error describes what the complete verifier found.
A `local-cancellation` row says the receiver stopped before reaching its verdict;
it does not prove the relation invalid. `not-started` means the original domain
refused the start. Neither outcome is changed into a failed proof, a successful
proof or a zero-cost verification.

The receiver phase starts one explicit local domain after generation and raw
diagnostics, then keeps that same domain across every class, arm and repetition.
Its original burst, wall-time refill, start reserve, live checkpoint debit,
residual settlement and unknown-clock fencing remain active. There is no new
per-key balance or per-case reset. The reported actual flow includes refill and
remaining credit, so time spent recording prior rows cannot be mistaken for an
absence of refill. The summary denominator includes all requested replays,
including refusals and cancellations. The example does not measure packet
parsing, admission tickets, signatures, M06, durable state or distinct confirmed
business throughput.

## Interpretation

A cheap claimed transcript can satisfy the ticket target while still requiring
an expensive receiver replay to reject it. Local CPU accounting limits the work
that this receiver accepts and preserves its original cancellation semantics;
it does not make a false trace into a costly-to-produce valid W1 proof. Likewise,
a faster legal zero or rank-one implementation demonstrates an implementation
advantage for that input, not the cheapest possible producer over every allowed
input and hardware implementation.

Use the raw relation outcomes, exhausted searches, all attempt denominators,
actual shared balance and the existing real-service from-zero evidence together.
Energy cost, independent operators, WAN behavior, cheapest-producer resistance,
permissionless economics and production qualification remain unmeasured by this
example. No automatic alternative PoW or BFT fallback is installed.
