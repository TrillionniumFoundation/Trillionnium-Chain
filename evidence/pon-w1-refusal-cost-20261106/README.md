# W1 refusal costs and actual owner locks

Status: **research / HOLD / no production activation**.
Date: 2026-11-06 America/New_York. Base: `0ca272d09d1522b0ffd740e441b6d3de1ed81de6`.
This #688 continuation composes the subsequent upstream source
`a3e9002cd12ef90d62f8b252cad570e72dab6fa3` before final verification. It preserves
that source's generic bounded-rank/batch experiment and read-query changes,
while retaining this separate specialized rank-one comparison. Parallel
#740/#741 remain outside this composition.

## Implementation contract

Ticket-valid false transcripts cause full replay and then refusal. They do not
produce `VerifiedWork`. The old optional negative cache also let canonical C
mutations bypass the same Transcript failure without a new ticket. A real
native red control observes four 512-tile replays; all four proofs still reject.

The new negative Transcript key binds profile/challenge/task/target/A/B/trace.
The separately domain-separated Product key also binds exact C. Current cheap
checks precede lookup; misses reuse only the current invocation's checked input.
Hits retain cancellation. Completed failures alone enter the bounded cache.
Defaults, TTL and nonblocking behavior remain. Fresh claims, changed context,
expiry and eviction still owe replay; this is not an attacker cost floor.

Submit, History and Growth bind CPU waiting to the actual Node guard and original
request. Held phases refuse depleted CPU with the existing budget error; unlocked
phases retain original refill, deadline and Host checks. The mutex drops before
its scope. Worker accounting shares that request; another request is unaffected.
Live workers prevent new owner-scope registration and fence the original account.
The explicit namespace `r14-owner-lock-v1` retains historical r10-r14 vectors.
No budget, deadline, W1 bytes or default work profile changes.

Explicit checked-rank-one preparation validates all words and both exact ranks,
with no dense fallback. It computes `AB = u (v^T x) y^T`. Every challenge still
pays the complete original transcript and ticket.

## Frozen local measurements

Rejection: four synthetic classes, targets 1/2 and 1/32, eight samples, 32 C
variants. Search starts from zero and retains every miss/exhaustion. Setup,
allocation, cache lifecycle and each verification are separately timed. Compare
candidate no-cache and configured-cache calls with alternating order. The
dense-periodic fixture has no full-rank claim. Positive controls at their own
ticket target prove relation acceptance, not production at the attack target;
actual same-target positives are retained only when that target is met.

Legal production: dense/sparse/checked-rank-one, per-search/warm preparation,
FullLimb/lazy, two classes, targets 1/2 and 1/32, horizons 1/8/64: twelve cost
shards plus four exhaustion/first-hit controls. Six rotated samples per shard.
Retain setup/destruction and every full attempt; verify winner bytes with native
and scalar positive/negative controls. Correlated prefixes are not independent
samples. Common material, evidence and verifier costs are separate; nested timers
are not added twice. Unknown CPU remains null. These are finite component costs,
not mathematical minima, whole-process/network totals or real model outputs.

## Evidence scope

Source-bound receipts and raw results follow actual execution. Earlier dependency
failures and the native C-mutation red failure are retained. The tests-only Node
red source is `6228b3da159c0bb69f9dbe50815f70a1a53a3171`; its explicit injected
credit deficit is a scheduling control, not original-service qualification.
The original four-second / quarter-CPU / 2 GiB / sixteen-hostile-worker /
six-depth independent-confirmation gate remains open. General low-rank, actual
batched transcripts, cross-task algebra, GPU/ASIC and energy remain unmeasured.

See the [original workpackages](../pon-six-workpackages-20261106/README.md) and
[single development authority](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
