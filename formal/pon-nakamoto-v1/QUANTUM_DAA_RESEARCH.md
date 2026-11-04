# Pure PoN quantum cost and difficulty research

Status: executable conditional arithmetic, **not a quantum attack, security proof,
production DAA change, or mainnet readiness claim**. The source baseline is
4b6b8a91b6dfe41fbd7f40f40b359d535c2c4251 (PR #498). This work adds only formal
research, fixtures, tests and receipts. Native node consensus remains unchanged.

## Resource accounting and event scheduling continuation, 2026-11-04

The continuation starts from integration PR #688 at
`a4a0e2b561f057cfa3189979c5bf11f3a0eb2353`, with protected main at
`dd6e1c3cbeacbdc532b0679297835b3a0aac78f0`. These are source observations,
not an activation or a claim that unrelated native gates are complete. The
native validation was also repeated after preserving the concurrent integration
commit `d0737cf5434894ce47fad8082376fc417313c2cb`. The older deterministic
model and its failed schedules below remain intact. The
[reproduction manifest](../../evidence/pon-quantum-event-resources-20261104/README.md)
records the tested source composition and the limits of each observation.

Two additional experiments address different missing parts:

- [Winner-predicate resource accounting](quantum_oracle_resources.py) separates
  task preprocessing, per-search setup, preparation, forward winner computation,
  phase marking, inverse computation, diffusion, interrupted work, classical
  checking after every complete measurement, and post-winner proof/propagation.
  Failed candidates and zero-iteration trials still pay their candidate check.
  A missing full W1 circuit produces an unknown
  cost, not a multiplication of isolated SHA component counts into a fabricated
  oracle. Caller-supplied circuit budgets enable explicitly conditional logical
  qubit/gate/depth and error-correction sensitivity calculations.
- [Event-based network experiment](quantum_network_sim.py) replaces the older
  expected honest clock with sampled classical arrivals and finite Grover
  trials. Proof completion and message delivery are separate events. Public-tip
  restart and private-fork continuation have distinct rules; participation
  changes, failed searches, discarded progress and unfinished trials remain
  visible. The [campaign entry point](experiments/quantum_network_campaign.py)
  produces bounded, seeded observations rather than a consensus security proof.

### The minimal legal winner predicate

For the current PNW1 relation, the ticket depends on the challenge and the exact
ordered tiled-prefix transcript. Canonical fixed task matrices, their task
identity and a useful `A B` product may be prepared classically. In contrast,
challenge-derived noise, challenge-modified matrices, ordered intermediate
prefixes, trace hashing and target comparison cannot be discarded merely because
the input task is public. The actual cheapest implementation of that predicate
remains an open adversarial optimization problem.

The native [relation](../../trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs)
already separates `TranscriptEvaluation` from corrected-product construction;
[legal attempts](../../trillionnium/crates/trnm-crypto-primitives/src/pon_work/legal_attempt.rs)
also expose public task reuse. This is why a cost model must not mechanically
charge the full verifier, corrected product, SQL, logging, network transport or
a separately generated succinct proof on every coherent query. A winning
candidate must still yield a complete valid proof before native acceptance.
Preprocessing is charged at its actual reuse scope; it does not confer current
task eligibility or authorization.

The resource calculator's circuit stages are supplied assertions. Even when
every stage has numerical values, it has not synthesized or verified a complete
W1 phase oracle, proved a minimum cost, calibrated a physical QPU, or established
the quantum security of the proof system. Its surface-code equation, gate
decomposition, factory throughput, residual magic-state error, routing factors
and clock period are explicit assumptions. Estimates that cannot satisfy their
declared error budget are reported as unavailable. The default W1 case remains
unknown; the fully populated demonstration is a small non-W1 arithmetic example.

### What the network experiment can and cannot establish

The periodic backend keeps the current branch-local target, integer required
work, median-time and future-time rules. Equal work retains the existing local
tip. Work from different profile identities is not comparable. The ASERT
backends reuse the earlier isolated exact-u256 arithmetic and remain research
policies; they are not alternative installed protocols.

For a specified marked fraction `p` and `q` Grover iterations, one ideal trial
has success probability `sin((2*q+1)*asin(sqrt(p)))**2`. Increasing `q` beyond
the peak can reduce success. Equating the marked fraction of a finite W1 search
space with the uniform ticket probability `(target+1)/2**256` is a separate
assumption. Unknown or zero marked counts, BBHT search, correlations, hardware
noise and the actual reversible predicate are not inferred from this formula.
The automatic iteration choice is near the first success-probability peak;
it is not claimed to maximize throughput or attacker profit. Explicit iteration
counts allow other bounded strategies to be tested.

A new public block can invalidate the parent of an honest-tip search; it does
not force an attacker mining a private branch to abandon that branch. The
experiment therefore records restart costs without building this incorrect
defence into its private-fork policy. A future-dated private parent does not stop
construction of its private descendants. Receiving miners separately enforce
the future-time rule for every ancestor; eligible prefixes can be adopted while
later descendants wait. Bounded phased timestamp strategies expose compression,
holding, relaxation and a configured tail as explicit inputs. Candidate checking,
post-winner proof and propagation costs must finish before a remote modeled receiver
can adopt that block. These are synthetic header events without W1 proofs,
task/effect execution or native networking.

Probe confirmation follows the native conjunction: six descendants and at least
six times the inclusion block's required work, with the inclusion block excluded
from both counts. Six easier descendants alone need not satisfy confirmation.
Trace readback independently checks integer credit, ancestry and admission-time
constraints and replays the seeded experiment. Source hashes and claims about
which files existed at the recorded Git commit are also checked. This is a
separate implementation check within this development task, not an external
cryptographic audit.

Reorganization, growth, quality, prefix and transaction-wait observations from
a finite run are empirical diagnostics under its declared assumptions. They
are not common-prefix, chain-growth, chain-quality or transaction-liveness
theorems, and they do not provide a mixed classical/quantum security threshold.
No bounded campaign, including a run without a reorganization, establishes that
the protocol is secure. No successful modeled private fork establishes a
physically realizable attack on Trillionnium.

### Candidate literature and implementation boundary

[Bailey and Sattath, arXiv:2403.08023v2](https://arxiv.org/html/2403.08023v2)
provide a variable-difficulty quantum attack construction and variants that
address timestamp lag and bounded adjustment factors. Their idealized mining
model does not supply a W1 oracle. The current exact 16-block clamp and integer
rules still have to be respected by any Trillionnium-specific schedule.

[Garay, Kiayias and Shen, Fast Difficulty Adjustment in Proof-of-Work Consensus](https://eprint.iacr.org/2026/1116)
is a CRYPTO 2026 paper, with a revised ePrint dated 2026-09-10. Its construction
uses parallel chains and approximate agreement over previous-epoch information.
The public abstract, [author-institution page](https://www.iog.io/papers/fast-difficulty-adjustment-in-proof-of-work-consensus)
and its two-page [explainer](https://www.iog.io/api/research/pdf/explainer/CMS48YZX)
were accessible for this continuation; the complete ePrint PDF was unavailable
through the research interface. There is no complete pseudocode-to-source
mapping here. Requesting its backend must fail explicitly. A trimmed mean,
median of targets, or faster single-chain adjustment is not a reproduction of
this construction. The paper's asymptotic adjustment result is not a seconds
guarantee for PoN or a quantum-mining theorem.

[Baig, Guenther and Pietrzak, Nakamoto Consensus from Multiple Resources](https://doi.org/10.4230/LIPIcs.AFT.2025.16)
classify weight functions in an ideal continuous-resource model against private
double spending. Monotonicity and joint degree-one homogeneity in timed resources
are central: `Gamma(S, alpha*V, alpha*W) = alpha*Gamma(S,V,W)`. The discrete model
needs additional resource-variation and majority assumptions. Replotting,
selfish-mining economics and implementation-specific network losses have their
own boundaries. This is a theoretical comparison, not a proposal to sum arbitrary
scores or replace current required work with `sqrt(D)`.

Full W1 reversible synthesis and adversarial cost minimization, a complete Fast
DAA protocol reproduction, and a proved mixed-resource PoN security model remain
separate research exit conditions. The native pure-PoN engineering line retains
its present consensus and original acceptance budgets.

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
