# Pure PoN quantum cost and difficulty research

Status: executable conditional arithmetic, **not a quantum attack, security proof,
production DAA change, or mainnet readiness claim**. The source baseline is
4b6b8a91b6dfe41fbd7f40f40b359d535c2c4251 (PR #498). This work adds only formal
research, fixtures, tests and receipts. Native node consensus remains unchanged.

## What this package establishes

[quantum_daa_model.py](quantum_daa_model.py) executes the current development
profile's periodic target/chainwork/time arithmetic and explicit alternative
cost hypotheses. It also evaluates isolated raw-timestamp and median11 ASERT
arithmetic, plus a **new, unproved fixed-probability/variable-work candidate**.
Every alternative is a counterfactual research policy. None has an activation
path here.

The model exposes a concrete distinction: a chain can award credit proportional
to difficulty while an assumed quantum search costs only its square root.
For selected schedules this permits a slower-at-baseline private miner to
accumulate more credited work and subsequently restore a recent tip timestamp.
It also records bounded schedules that fail either test. This shows which
cost premises a proposed mitigation needs; it does not establish those premises
for W1, real hardware, proof generation, state execution or a public network.

The existing [classical query bound](work_query_bound.py) is conditional on
classical first queries to an ideal uniform ticket oracle. Its expected-credit
bound does not become a bound on quantum queries, elapsed time, energy, or
arbitrary neural compute. The native
[work/DAA boundary](../../docs/protocol/pon-nakamoto-v1/details/WORK_COST_DAA_BOUNDARIES.md)
and the actual packet experiments remain separate evidence.

## Source ownership and integer semantics

At the frozen baseline, [consensus.rs](../../trillionnium/crates/trnm-pon-node/src/consensus.rs)
owns required work, retarget arithmetic and timestamp checks. The node's
expected_target path in
[store.rs](../../trillionnium/crates/trnm-pon-node/src/store.rs) evaluates the
candidate branch's actual ancestors. The formal model imports their existing
[arithmetic reference](reference.py), not the node, a proof generator, or a
network receiver.

The [development profile](../../config/pon/devnet-v1.json) supplies:

| Parameter | Modeled value |
| --- | --- |
| Periodic interval | 16 blocks |
| Target spacing | 10 seconds |
| Expected retarget span | 15 × 10 = 150 seconds |
| Observed span clamp | [38, 600] seconds |
| Median timestamp window | Previous 11 branch timestamps |
| Future allowance | 120 seconds |
| Maximum target | 2^255 − 1 |
| Required work | floor(2^256 / (target + 1)) |

The lower clamp uses **ceil(150/4) = 38**, not 37 or 37.5. Target inclusivity
is preserved: the ideal lottery probability is (target + 1)/2^256.
Time in this model is relative to zero; an additive genesis offset does not
change these arithmetic tests. The common prefix is synthetic arithmetic:
eight short retarget windows followed by an ordinary window produce a target
well below the maximum. No prefix header has a W1 proof or native admission.

The [#487 research candidate](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/84a0c697a3178eaee31ff9f60851a42c479b73f9/trillionnium/crates/trnm-pon-node/src/consensus.rs)
contains a separately scoped ASERT research interface. This package neither overwrites
that candidate nor treats its shadow/research paths as current native DAA.
The Python implementation uses exact raw u256 targets and the same absolute
anchor convention. It does not introduce Bitcoin compact-target rounding into
PoN.

The independently specified numerical checks are the 18 CalculateASERT
unit vectors from
[Bitcoin Cash Node, pinned commit 07576013](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/test/pow_tests.cpp#L649-L772).
The [immutable fixture](vectors/quantum-daa-asert-bchn-v1.json) records source,
blob and parameter hashes, exact targets and expected compact encodings.
It covers negative exponents, clamp boundaries, underflow and overflow.
This is **18 upstream unit vectors, not the full external ASERT vector corpus,
and not execution of #487's native implementation**.

The algorithm follows the pinned
[BCHN implementation](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/pow.cpp).
Signed fixed-point division truncates toward zero, as in Rust/C++; Python's
negative floor division would produce a different result. The vector adapter
adds 600 to the upstream table's time difference and one to its height
difference, exactly as the upstream test does. The raw and median11 branches
each have a steady 10-second honest control; they use consistent anchors.

## Cost model and exact limits of an attack observation

Write p = (T+1)/2^256. The current weight is approximately 1/p.
If one full challenge-bound PoN lottery evaluation has stable cost k_C,
classical expected search cost is k_C/p. Under an additional ideal quantum
search hypothesis, a full reversible winner oracle with stable cost k_Q
would instead cost proportionally to k_Q/sqrt(p).

Thus weight per modeled classical resource is approximately 1/k_C, while
weight per modeled quantum resource scales as 1/(k_Q sqrt(p)).
Increasing difficulty can increase the second quantity. This derivation
assumes the complete oracle, including required neural work and ticket
transcript, can be evaluated coherently. It is not an estimate obtained by
applying Grover search to the final SHA-256 alone.

In this package the attacker's baseline rate is **assumed** to be 0.25 times
the honest network rate: 40 modeled seconds per baseline block against the
honest control's 10. That is a relative rate, not a measured hardware share;
if the same rates were additive classical rates it would correspond to 20%
of their total. Quantum constant factors are absorbed into this unmeasured
baseline. The model does not infer the number or capability of real QPUs.

For each branch, mandatory cost is charged before its candidate timestamp can
become admissible. A proposed future timestamp incurs an explicit wait.
Targets/weights are exact integers; the hypothesized square-root costs use
70-digit decimal arithmetic, with 24-digit reporting. The honest competitor
receives floor(elapsed/10) baseline blocks at a constant target. This is a
deterministic expectation-based control, not a stochastic execution or
confidence bound for private-chain success.

The phase schedule compresses timestamp increments to 5 seconds, holds them
at 10, relaxes them to 20, then advances a catch-up tail at 10. All generated
timestamps exceed median11 and respect the future allowance at the modeled
completion time. A report marks a conditional reorganization schedule only
when its private chain both has greater modeled chainwork and has brought its
tip to within 10 seconds of modeled current time. This additional recent-tip
condition is a research challenge, not a newly introduced consensus rule.

The standard campaign contains the following distinct observations:

| Scenario | Purpose |
| --- | --- |
| Periodic/classical | Control: cost and credited difficulty grow together |
| Periodic/quantum-query hypothesis | Test the assumed square-root mismatch |
| ASERT160 raw and median11, 12,000 tail blocks | Retain bounded runs that have excess work but do not catch up in that budget |
| ASERT160 raw and median11, 16,000 tail blocks | Check an explicitly larger budget, retaining the earlier failures |
| ASERT7200 raw, short budget | A slower response with no successful path in this finite schedule |
| Fixed p, linear mandatory cost | Candidate premise under which work adjustment adds no scale-dependent advantage |
| Fixed p, square-root mandatory cost | Counterexample when that key premise fails |
| Periodic plus 5-second proof delay, original budget | Charge a hypothetical post-winner cost and retain the bounded failure |
| Same proof delay, longer tail | Test whether constant proof latency alone closes the modeled path |

No failure above proves a DAA secure, and no successful model run proves a
deployable attack. There is no actual nonce search, task-lease selection,
proof acceptance, fork admission, replay/state synchronization or networking.
The finite schedule is not an exhaustive adversarial search. Pooling,
interruption of quantum search, target-dependent oracle costs, fork-choice
resource bounds, stochastic variance and honest responses remain outside it.

### Relation to the quantum difficulty-increase paper

[Bailey and Sattath, v2](https://arxiv.org/html/2403.08023v2) analyze how a small
quantum miner can use difficulty changes to amplify credited work relative to
quantum search cost. Their constructions include raising/lowering difficulty
gradually and restoring recent tip time. Consequently, factor-four clamping
or rejecting an obviously stale final timestamp is not by itself a general
answer to that mechanism. The paper's setting is Bitcoin-style proof of work;
it does not supply a reversible W1 implementation or a theorem for this chain.

The raw/median11 ASERT experiments here are new conditional model observations,
not a claim that the paper proved these particular policies unsafe. No evidence
here supports replacing chainwork with its square root or choosing the longest
block count. Such changes alter classical incentives and security and would
require their own analyses. No BFT, PoS, TEE authority or hash-only work is used
to replace PoN in this candidate.

## Fixed probability and variable mandatory neural work

This branch is a research hypothesis, not an available security primitive.
Keep p0 fixed (or eventually prove a tightly bounded variation) and adjust
the amount u of mandatory challenge-bound neural work. The arithmetic model
inverts the periodic span:

    next_u = clamp(ceil(parent_u × desired / bounded_observed), 1, max_u)
    block_weight = u × floor(1/p0)

The unit budget is a declared integer count, **not measured FLOPs, energy,
model quality, useful outputs, or an existing W1 profile parameter**.
Its initial value is 1024 and the modeled maximum is 1,048,576.

Under full winner-oracle cost assumptions k_C(u)=a_C u and k_Q(u)=a_Q u,
expected costs scale as a_C u/p0 and a_Q u/sqrt(p0). Weight per resource is
then independent of u in either case. This removes this particular
work-size amplification in the model. A fixed quantum advantage proportional
to 1/sqrt(p0) remains; it must be included in the resource-adversary threshold.
The linear example therefore does not prove classical/quantum fairness.

If quantum winner-oracle cost is instead proportional to u^alpha, with
alpha < 1, weight per resource grows as u^(1-alpha). The included
alpha=1/2 counterexample restores the conditional attack while the lottery
probability stays fixed. The test is deliberately sensitive to the missing
lower bound; it cannot certify that lower bound by assuming it.

### Necessary statement and cost gates

All of the following remain required before this can become a PoN proposal:

1. **Challenge binding before ticket evaluation.** Bind the parent, chain and
   work-profile identity, miner/reward destination, nonce, unit count and ordered
   task input commitments into one domain-separated input context. Every unit
   seed must depend on that whole input context and its index. Derive outputs
   from those inputs; then bind their complete, canonically ordered commitment
   into the lottery. The output commitment must not be included in its own
   generating seed. This is a future bundle statement, not a change to the
   existing W1 transcript under its current profile.
   A miner must not keep u-1 old units while varying one cheap last unit,
   choose a cheaper subset, reorder units, split a winner into extra credited
   blocks, reuse old work, or change claimed work after seeing a ticket.
2. **Complete relation and unique lottery semantics.** All required outputs
   must be checked or proven. Proof randomness, padding, equivalent encodings,
   aggregation choices and noncanonical representations must not create free
   tickets for the same work. An all-unit relation must bind before the
   lottery even if a succinct proof is generated only after winning. Binding
   an invented output root does not show work: proof soundness must also
   survive grinding such roots and selecting those that meet the target.
   The main W1/W2 relation package owns these cryptographic statements.
3. **Lower bounds for the actual winner predicate.** Proving correct matrix
   products does not prove minimum physical cost. Require a stated classical
   and quantum cost model, representative and adversarial tasks, cross-unit,
   cross-nonce and cross-parent amortization experiments, and an analysis of
   reversible oracle construction, rather than a FLOP-count assertion.
4. **Distribution and structure.** Challenge-derived inputs may be correlated;
   useful neural tasks may be sparse, low-rank, repeated or algorithmically
   compressible. Query direct-product results such as
   [Lee and Roland](https://arxiv.org/abs/1104.4468) do not directly prove
   linear wall-clock, gate-count or energy cost for these distributions.
   [Ben-David and Ebtehaj](https://arxiv.org/abs/2610.06835) also distinguish
   distributional query bounds from worst-case formulations. Neither is a
   neural compute cost certificate.
5. **Liveness and hardware feasibility.** Bound per-block work, witness memory,
   verification and propagation; measure block latency and stale rates.
   Parallel execution can reduce latency without reducing gate count.
   Work-size changes can favor hardware with more memory/parallelism.
   At minimum/maximum unit caps, fixed probability may no longer maintain the
   desired rate. Task availability and continuation work are separate gates.
6. **Whole-chain security.** A post-quantum signature path alone does not
   qualify the work oracle, Fiat-Shamir soundness, transcript commitments,
   networking, state synchronization or economic threshold. No gate here
   authorizes a whole-chain post-quantum claim.

## Reproduction, receipts and costs

Run from the repository root using Python 3 with its standard library. The
output path must be new. The reader also requires the same source-file hashes;
source changes invalidate its replay rather than silently accepting old data.

~~~bash
bash scripts/project-preflight.sh --audit
python3 formal/pon-nakamoto-v1/test_quantum_daa_model.py
python3 formal/pon-nakamoto-v1/experiments/quantum_daa_campaign.py --out /tmp/new-pon-quantum-daa
python3 formal/pon-nakamoto-v1/experiments/quantum_daa_campaign.py --verify /tmp/new-pon-quantum-daa
~~~

The producer writes one deterministic gzip JSONL stream per scenario, a report
with parameters/assumptions and a SHA-256 inventory. It records source commit,
whether the model inputs match that commit, actual Python CPU/wall time and
whole-process peak RSS. Actual Python measurements are separate from every
field named modeled_*. No QPU, reversible oracle or native W1 cost was
measured; corresponding resource estimates remain **null**, not zero.

The reader checks exact file inventory/digests, source hashes and bounded JSON
decompression. It separately recomputes integer work and median/future checks,
then deterministically replays the shared model. Tests include mutated
chainwork/time, altered source/qualification claims, duplicate JSON keys,
unlisted files and output-overwrite refusal. This is a local single-operator
readback; neither SHA-256 manifests nor a repeated model execution
independently attest the recorded CPU time or the physical premises.

The retained receipt reports actual costs on its exact source. All cases keep
native_packets_generated=0, quantum_circuit_executed=false,
w1_cost_measured=false, security_theorem=false,
production_consensus_activation=false and release_ready=false.
The release gate remains **NO_GO** until the missing cost/soundness/native
and independent validation work is completed.
