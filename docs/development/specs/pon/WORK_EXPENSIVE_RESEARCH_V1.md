# Cheapest legal work: finite experiment and Mode-A chronology

This specification continues the [single development plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and the [shared complete-operator experiment](SHARED_CELL_WORK_V1.md). It does not
register or activate the separate grouped arithmetic relation as chain work, change W1 bytes, retargeting, fork choice,
task eligibility or production activation. All work-hardness gates remain open.

## Security object and interpretation

The proposed research object is

\[
\Gamma(B)=\frac{\sup_{\mathcal A}E[W_{\rm accepted}(\mathcal A,B)]}
{E[W_{\rm accepted}(\text{best known honest implementation},B)]}.
\]

An eventual protocol-level measurement must fix a resource vector (CPU, elapsed
deadline, peak resident memory, I/O and network budgets), the eligible task and
challenge distribution, parent ancestry and all preparation/cache lifetimes.
Count required work only for unique qualified opportunities in the particular
evaluated ancestry. Competing branches are not additive. Proof randomization,
serialization and optional commitment fields cannot mint another opportunity.
Useful application outputs have a different identity and accounting owner.

A faster legal algorithm is available to honest miners as well. It belongs in
the honest implementation set; its speed relative to a slow reference is not
automatically an attack advantage. Zero honest observations make a ratio
undefined, rather than zero or an experimentally certified infinity. An average
over a small set of sampled challenges is not a theorem about the supremum.

The [ESA 2026 source](https://doi.org/10.4230/LIPIcs.ESA.2026.2), Definition 3,
permits preprocessing, and Assumption 10 concerns an asymptotic intermediate
computation problem involving random low-rank matrices. The rectangular
algorithm discussion and the separate streaming definition in Appendix B do
not instantiate a finite CPU, hardware or accepted-vote lower bound for this
repository's N=64/R=8 W1, nor for the separately implemented signed-integer
grouped research relation in [GROUPED_CELL_OPERATOR_V0.md](GROUPED_CELL_OPERATOR_V0.md). The current
experiment makes no such transfer. Its constructed algorithms and measured
times are upper-cost witnesses for those implementations.

## Native strategy census

The opt-in [native example](../../../../trillionnium/crates/trnm-crypto-primitives/examples/pon_work_expensive_v1.rs)
retains the fourteen-algorithm v1 observations and adds an explicit sparse
preparation arm in v2: generic prepared, structured, classical and
Strassen tiles, paired products, blocked zero/zero and zero/rank-one variants,
maintenance variants, scalar original, and dense/sparse lazy full-limb. The
original `lazy-full-limb` remains dense; `lazy-full-limb-sparse` uses the separately
implemented canonical sparse preparation. Both execute the complete W1 transcript.
Unsupported material
is a paid constructor refusal, with no silent generic fallback.

Nine fixed synthetic material classes include dense/full-rank, zero, rank-one,
identity, sparse diagonal, continuity and both one-zero directions. An exact
32,768-byte canonical A/B input option accepts each of the five existing complete
source-routing model tiles. The model is real trained integer source-routing
code; this is not an LLM, independent future demand or ordinary Hepta adoption.

Every arm runs a fixed number of attempts; a hit does not stop this census.
Every losing attempt remains. A declared reuse horizon controls actual object
construction and destruction, not a division by imagined future uses. Calls
rotate arm order by sample. Every target hit is checked by the complete native
and separately implemented scalar W1 verifiers. Exact trace/ticket streams must
agree across applicable arms. All setup, attempt, cleanup and destructor costs
are separately recorded, as are unsupported and failed cells.

The original fourteen-arm record namespace is `pon-work-expensive-native-v1`;
the fifteen-arm registry is `pon-work-expensive-native-v2`. The CLI experiment
selector remains `--work-expensive-v1`; the emitted schema selects the exact
arm registry, and the strict reader refuses mixed namespaces or relabeled old
observations. Its report namespace is now `pon-work-expensive-reader-v2` and
explicitly records the input namespace and observed arms. The challenge is
`H(pon-work-expensive-challenge-v1, task, seed, sample_le64, index_le64)`.
The revised work identity is
`H(pon-work-expensive-work-v2, challenge, task, target)` and excludes both trace
and proof bytes. The unpublished development v1 identity included trace and is
explicitly not interpreted as v2. The mathematical challenge intentionally does
not include target: target cohorts can reuse work and **must not be added** as
new parent work. No native-header eligibility is inferred.

The [reader](../../../../scripts/pon_work_expensive_reader_v1.py) reconstructs
every material hash, challenge, ticket, nonce, work identity, exact row schedule,
phase sum and actual cache lifetime. Missing losers, missing/duplicated epochs,
boolean numeric aliases, shifted windows, false verdicts and omitted scalar
checks refuse comparison. Rejected raw streams and process failures remain in
the campaign output; reader rejection is not a completed successful experiment.

### Three distinct clock scopes

1. **Producer components:** actual preparation, challenge derivation, arithmetic,
   ticket/proof production, attempt cleanup and completed cache destruction.
2. **Continuous instrumented cell:** setup through the last destructor, including
   intervening verification, proof hashes, evidence and output. It excludes the
   cell-summary output itself and the separately reported global material preparation.
3. **Owned process:** an external supervisor observes startup, all native work,
   diagnostic serialization, output, exit and cleanup. Its child RSS value is a
   running maximum, not an isolated per-shard measurement or an RSS quota.

Nested clocks must not be added. The fixed-B reader counts only actual completed
and destroyed cache-epoch boundaries. It does not borrow a later destructor to
invent an earlier stopping cost. These are postprocessed component/continuous
cell prefixes; an actual early-stop miner, network and Node admission were not
executed. The original material acquisition and identity/rank preparation are
reported separately and never spread over unobserved future reuse.

Earlier samples select one strategy per material by aggregate producer CPU,
with a fixed tie order. Later samples evaluate that choice. Selection never
takes the fastest arm separately for each evaluation sample. Budget counts
state the per-replicate budget, replicate count, aggregate ceiling and mean.
This still does not establish independence, confidence coverage or the global
best algorithm. `gamma`, its upper bound and native-branch accepted work remain
null; no finite comparison is mislabeled as a security bound.

## Mode A: freeze before revealing a challenge

The [bounded research state machine](../../../../formal/pon-nakamoto-v1/work_expensive_mode_a.py)
uses `pon-work-expensive-mode-a-research-v2`. It freezes exact model, task,
Cell/generation, state, input order, batch/request set, route, shape, numeric and
output contract digests. It also binds the complete configuration, target,
declared search count, per-search attempt limit, challenge owner and stopping
rule. This Mode A adapter implements only W1 and refuses grouped v0 statements.
The separate grouped operator and independent arithmetic verifier exist, but
this adapter does not connect them to a challenge lottery, chain-work accounting,
an authenticated external owner or a qualified minimum legal-cost model.

Registration is permitted only before the cutoff. Freeze closes the candidate
set; reveal requires the frozen phase and cutoff. The new seed binds externally
observed entropy, the complete frozen set, configuration, round, parent and
branch. A routing hash by itself supplies none of these ordering guarantees.

The source-bound driver actually writes and fsyncs the frozen journal before
asking the local OS for entropy. A supplied replay seed is labeled known-seed
replay. Local timestamps, a digest naming an owner and OS entropy **do not**
authenticate an external beacon, its unpredictability or resistance to bias.
These remain explicit accepting-owner obligations.

The shared-material executable uses its existing challenge domain. Its complete
nonce streams are imported, and successful proofs are independently replayed by
the Python scalar W1 oracle before an observation is recorded. This differs
from the fourteen-arm census challenge domain; the driver does not pretend the
second domain was accepted by the first state machine.

Each declared search follows first-hit-or-exhaustion. Nonces are consecutive;
later searches require the preceding search to have completed. A hit can be
withheld, but its attempts remain paid. Closing a round lists unstarted and
unfinished searches. Candidate caps are global and per local actor; the latter
is not a Sybil defence. Rejected registrations retain reported preparation
costs. Undisclosed attacker work cannot be proven absent from this local log.

Work identity excludes proof randomness and Cell packaging. Same-task wrappers
cannot duplicate a challenge's observed work. Repeated challenges over one
application contract/product have one application outcome. Per-parent branch
scopes are kept separate, and selecting another scope does not erase application
history. Real ancestry/fork choice still belongs to Node.

The five W1 tile products are component outcomes of one complete model operator.
Only after their complete consumed output equals the original integer operator
may the driver report one distinct complete application output. Five tiles are
not five independent useful requests or five complete model executions.

Saved journals require an externally retained exact checkpoint on restore.
Replay checks ordering, configuration, costs and full successful proofs. A hash
chain by itself is not rollback protection. The maximum is 32,768 events with a
128-MiB snapshot cap; the driver explicitly reserves enough events for five
4,096-attempt searches. Refusal calls also consume capacity. Capacity exhaustion
cannot be reported as a complete journal or a successful recovery.
The idealized selection envelope additionally bounds exact rational arithmetic
before exponentiation; this is a computational guard, not a process RSS quota.

The state-machine cost subtotal contains only declared registration preparation
and recorded attempt components. The driver additionally retains native setup,
whole-search, full-verifier and process envelopes, as well as pre-freeze model
material reconstruction and waiting time. None may be silently omitted from a
claimed complete budget.

## Verifier cost and concrete repair

The optional [negative cache](../../../../trillionnium/crates/trnm-crypto-primitives/src/pon_work/rejection_cache.rs)
previously hashed all 49,188 proof bytes before the native verifier rejected bad
version, zero target or a noncanonical field. The repaired entry keeps the
original Length, Version, zero-Target, Field error order before this optional
digest. The actual proof-digest byte counter regression checks zero hashing on
those cases and calibrates against a full valid 512-tile verification.

The cache remains explicitly opt-in; default public verification is unchanged.
A miss still performs complete native verification; a cached mathematical
refusal grants no present-parent authority. Cancellation, contention, poison,
TTL and capacity semantics remain. The additional canonical scan on ordinary
cache misses must be charged, rather than hidden behind the cheap malformed
case. The separate arithmetic-fact cache has different reuse semantics.

The [native verifier experiment](../../../../trillionnium/crates/trnm-crypto-primitives/examples/pon_work_expensive_verifier_v1.rs)
and [strict runner](../../../../scripts/ci/run_work_expensive_verifier_v1.py)
exercise different-material cold submissions, retransmission, new forged traces,
new challenges, forced one-slot eviction, actual cache-owner recreation, TTL
expiry, valid cold/warm controls and cheap malformed input. All completed
from-zero searches, losers and material preparations are retained. Operational
attack preparation/search costs are distinguished from proof-hex/hash diagnostic
construction, while the larger complete-process envelope remains available.

Warm-cache observations do not qualify sustained fresh-material service. The
existing Node queues, global CPU admission and signed Host limits are separate
owners. No per-task fairness, RSS isolation, honest-task p99, WAN or original
4-second/16-hostile-work confirmation gate is promoted by these component tests.

## Coverage and remaining research

| Requested strategy | Implemented observation | Remaining boundary |
| --- | --- | --- |
| Zero, one-zero, rank-one, sparse input | Existing legal kernels on complete W1 attempts | Globally cheapest strategy and hardware normalization |
| Fixed weights and preprocessing | Actual setup, reuse horizons and destruction | Cross-device, long deployed model lifetimes |
| Repeated/known result | Work/application identities and cache lifecycles | Live reward/owner integration |
| Shared input, base and multiple Cells | Frozen complete operator and wrapper replay controls | Competitive multi-Cell end-to-end shared execution |
| Shape, padding and group size | Exact fixed W1 encoding and frozen shape metadata | Independent challenge/admission integration and minimum legal-cost qualification for the separate grouped v0 research relation |
| Batch, route and commitment choice | Frozen candidate/search schedules and rejected post-reveal edits | Authenticated external cutoff, bulk precommit economics and biased challenges |
| Approximation and rounding | Unchanged exact W1 field and complete integer operator; grouped v0 also uses exact signed-integer arithmetic | Separate semantics and qualification for any approximate/quantized variant |
| Parent/private branch/replay | Separate scopes, full proof replay and external-checkpoint restore | Actual Node ancestry, network/private mining security |
| Verifier exhaustion | Native cold/churn/new-challenge/expiry costs | Complete Host-budget service and per-task fairness |

The [campaign driver](../../../../scripts/ci/run_work_expensive_campaign_v1.py)
and the evidence record contain reproducible commands and source/binary/raw
digests. Neither a larger number of tests nor a favorable sampled runtime closes
the final mathematical and operational boundaries in this table.
