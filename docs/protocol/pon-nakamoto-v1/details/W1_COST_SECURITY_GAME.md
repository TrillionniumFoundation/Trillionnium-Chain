# W1 cost-security research game

Status: research specification and exact arithmetic controls. Pure matrix PoN is
the primary research path; a separately specified hybrid is a safety comparison.
Neither path is activated by this document. This continues PN1 / I01 of the
[sole development plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and the existing [computational qualification obligations](WORK_COST_DAA_BOUNDARIES.md).
It changes no W1 bytes, task eligibility, target, required work, fork choice,
reward, receiver budget, signed domain or qualification flag.

The baseline inspected for this specification is
`630f871293e48588e0a1ceae7ceb64973d3ec31d`. A subsequent measurement must name its
own actual source, tree, binary and environment; that baseline cannot authenticate
a later executable. Mathematical examples below are not native observations.

## 1. Question and explicit limits

The question is how many **distinct fully valid lottery tickets** an adversary
can obtain within a declared resource budget, including preparation, selection,
failed work and reuse. A correct certificate does not prove that its producer
executed the reference algorithm, consumed its counted operations, trained a
model, or paid an independent customer. Even ordinary hash PoW permits a first
attempt win: a per-winning-block deterministic expenditure claim is the wrong
goal. The useful target is a resource-to-success bound, including its upper tail.

Keep three statements separate:

1. Exact relation validity: canonical W1 inputs, transcript, product and target.
2. Computational qualification: resource-to-ticket bounds for a stated adversary
   model, preprocessing allowance, selectable tasks and challenge process.
3. Native availability and usefulness: actual block admission, honest service,
   task fulfillment, evaluation and model release, under their existing owners.

An expensive failed verification is a receiver-cost observation, not a valid
mining ticket. A passed local timing comparison is not a computational lower
bound. An adversary faster than a reference supplies an **upper bound** on the
minimum possible producer cost, and evidence against a stronger fairness claim.
Failure to find such an adversary supplies no universal lower bound.

## 2. Existing coverage and the research increment

The retained work already provides substantial prerequisites; do not recreate
them under a new success label or move historical results to the new source.

| Existing contract | Coverage already present | Increment specified here |
| --- | --- | --- |
| [Same-target report](W1_SAME_TARGET_BUDGET_REPORT.md) and [local observations](W1_LOCAL_SECURITY_PROFILE.md) | Complete setup, misses, unsupported/exhausted arms, full verification, distinct proof counts, false traces and original receiver CPU settlement | A resource-bounded, semantic-ticket game; separate primitive, eligible and admitted counts; all wins within budget |
| [Implementation comparison](W1_IMPLEMENTATION_COMPARISON.md) | Actual cold/reused setup, structured and blocked-zero producers, one-level Strassen, periodic maintenance and split-limb alternatives, exact bytes and independent arithmetic controls | Explicit advice lifetime, shared preprocessing across a parent forest, adaptive-selection costs and registered adversary families |
| [Zero paired accounting](W1_ZERO_PAIRED_COST_ACCOUNTING.md) | Complete cohorts, fastest fixed-arm comparisons, retained slower outcomes and prohibition of hindsight dispatch | Predeclared sensitivity targets and valid finite-family statistical interpretation |
| Native zero-task lifecycle and maintenance paired conformance linked from the implementation comparison | Signed eligibility, renewal/revocation, real parents, fork/reopen checks and mathematical reuse | Resource accounting over those transitions and simultaneous parents; these are not the first parent-conformance tests |
| [Work-cost/DAA boundaries](WORK_COST_DAA_BOUNDARIES.md) | Effective-work share formula; freeze tasks, targets, reuse horizons and hardware; charge executable adaptive selection; native target/chainwork cases | A common probability game, explicit composition premises, upper-tail obligations and falsifiable acceptance records |
| [Mathematical-fact reuse](W1_FACT_REUSE_V1.md) | Exact verified facts, context rechecks, concurrency/cancellation and local metered integration | No new mining credit from replay, cache hit, process identity or receiver reservation |

The existing first-win comparisons remain meaningful complete-search
measurements. They do not become a fixed-resource, all-winning-ticket experiment
by relabeling their final winner or conditioning a binomial calculation on the
observed stopping time.

## 3. Freeze the game before its evaluation

Each campaign declares one immutable game record. Exploratory development can
precede it, but exploration and held-out evaluation have separate receipts.

| Field | Required declaration |
| --- | --- |
| Protocol context | Chain/genesis and parameter commitments, W1 relation, canonical encodings, target policy and exact native eligibility version |
| Workload policy | Supplied operands versus source-extracted material; allowed task families; eligible task sets; reference task-selection policy; provenance evidence if claimed |
| Adversary | Executable and algorithm hash, allowed public/private state, selection/dispatch policy, hardware, parallelism and any training/search used to select it |
| Preprocessing | What is known before challenge release, advice/cache bytes, actual preparation cost or explicitly unknown historical cost, storage bound and reuse horizon |
| Challenge process | Input-commitment/reveal order, allowed header fields, parent supply/advancement, seed generation and any selection or abort rights |
| Scope | Number of tasks and parents, epochs/renewals/restarts, cache sharing, target strata, budget and stopping rule |
| Measurement | Resource units and instruments, included/excluded work, start/end boundaries, worker aggregation, transport and output retention |
| Inference | Preselected kappa target, registered comparisons, repetitions, holdout construction, confidence allocation and assumptions for any tail bound |

Current W1 already binds its complete header. Its existing
[wire contract](LEDGER_WIRE.md) commits network, parameters, parent, height,
timestamp, target, miner, transaction/state/receipt roots, task and nonce before
deriving the challenge. Research must preserve that fact. A synthetic challenge
stream is labeled synthetic; it cannot stand in for a legal branch-derived
header or a live task lease.

### 3.1 Preparation and adaptive challenge selection

Allow the adversary to know long-lived public matrices, fixed maintenance
material, protocol code and earlier transcripts. Declare which additional advice
it receives. A public precomputed product is possible knowledge, not a prohibition
that can be enforced by asking a miner to run a constructor.

The cold experiment starts from the declared raw inputs and charges its actual
construction. The warm experiment starts with a committed cache and records both
its preparation receipt and online cost. If the cache's historical cost is
unknown, label the result **conditional online cost with unaccounted preparation**;
do not manufacture an amortized full cost. A preprocessing claim requires its
time, memory, input dependence and lifetime to be specified.

The adversary may select among eligible tasks, inspect public challenge-derived
material, discard unfavorable seeds, choose kernels, batch work, and stop early,
unless an actual protocol rule forbids that action. Charge all such activity.
Do not give a free verifier/selection oracle to the measured algorithm: its own
verification calls are producer work. A separate post-run checker establishes
the record's truth and is outside the producer budget, with no feedback into the
held-out run.

In a random-oracle analysis, fresh, distinct oracle inputs have independent
outputs even when the inputs are chosen adaptively. This does not make the
resource cost of obtaining valid transcript inputs independent or constant.
The reduction must cover cheap guessed traces, screening, aborts and adaptive
input selection; defining an opportunity as a full reference execution would
exclude the shortcuts that the game is intended to test.

The simple oracle-query and binomial models below concern classical adaptive
queries. They do not cover quantum superposition queries or assert a physical
hash-cost lower bound. Any broader adversary class requires its own stated
query/resource model and reduction.

### 3.2 Several parents, tasks and reuse horizons

Maintain one adversary state and one aggregate campaign budget over a forest of
actual parents. A fork, renewed lease, selected task, new key, restarted process
or reorganization must not reset already spent resources. Charge shared setup
once when it is actually performed, not once per fork; charge every subsequent
branch-specific operation. Work discarded after a reorganization is still work
performed. No physical-compute refund follows from its loss of reward eligibility.

Each candidate is checked against its own exact parent state and branch-derived
target. Mathematical A/B/product reuse carries no current-parent lease,
revocation, clock, state-root or application authority. An offline supplied-parent
experiment must say which parent construction and task-source costs are excluded.
An advancing-parent experiment charges the work needed to produce its new
parents; it cannot obtain an unlimited free history oracle.

Record reuse horizons explicitly, including one search, many challenges for one
task, several simultaneous parents and lease/profile changes. A measured finite
horizon is not unlimited amortization. Pooling tasks from many customers is an
allowed adversary strategy when its data rights and actual protocol eligibility
permit it; the campaign must charge scheduling, acquisition and transfer costs.

## 4. What counts as a ticket

Use semantic statement identity, not a count of proof files, signatures, clients
or successful verifier invocations. For current W1, the existing block identity
binds the exact header and canonical transcript digest. Retain the chain/profile,
header, task and proof commitments needed to reconstruct that identity. Under the
explicit collision-resistance assumption, equivalent encodings, repeated proofs,
alternate producer algorithms and randomized wrappers do not create new credit.

| Counter | Required predicate | Permitted interpretation |
| --- | --- | --- |
| Attempt | Actual attempted production/selection operation, including misses and aborts | Work performed; not a valid ticket |
| Unverified target hit | Claimed digest meets the threshold | Admission-filter result only |
| Distinct full-valid W1 ticket, `N_W` | Exact ordinary full W1 verification and target pass for a new semantic identity | Primitive lottery result |
| Distinct parent-eligible ticket, `N_E` | `N_W` plus the actual selected parent's task, profile, clock and target eligibility | Eligible work; application/root validity remains explicit |
| Distinct admitted block, `N_B` | Complete native application/root checks and ordinary block admission | Accepted block on a named branch |
| Canonical confirmed result | Existing fork-choice and confirmation rules on actual admitted history | Separate ledger outcome; not equal to all fork tickets |

The primary cost report must identify which counter it actually measures.
Primitive-only runs cannot claim `N_E` or `N_B`. Valid W1 with intentionally
false state roots belongs in a receiver/admission experiment, not the admitted
block numerator. A cancelled or incomplete verification is unknown validity,
not a full-valid ticket or a proved-invalid ticket.

Within each run, count a semantic identity once across all retries, processes,
algorithms and receipt encodings. Across counterfactual strategy runs, compare
the same deterministic ticket sets; do not add them into newly produced work.
Different parent-bound identities may count in an adversary's all-branch search
capability, but cannot all be called canonical rewards. Reject stale-parent
claims where the game requires current eligibility.

Preparation or native context acquisition can itself mine valid parent/template
proofs. Record those auxiliary outcomes and their semantic identities separately
from the selected producer's outputs. In an end-to-end budget game, the numerator
is their deduplicated union at the chosen validity tier. Charging acquisition
while discarding every acquisition win understates that game's attainable rate;
it cannot support an upper bound on adversarial ticket production. A supplied-
parent conditional game may exclude both the external acquisition budget and
its outputs, but must name that assumption. If only total acquisition time is
known and it crosses the budget, individual acquisition wins have unknown
within-budget status; retain a count interval rather than inventing completion
times or assuming there were zero such wins.

Use equal, frozen targets for raw ticket-rate comparisons. If targets vary,
stratify results and separately sum the installed exact `required_work` over
distinct eligible/admitted statements. An easier ticket is not equal chainwork
to a harder ticket. A weighted, adaptive-DAA tail analysis is a separate
obligation; substituting an unweighted ticket count does not satisfy it.

## 5. Complete resource accounting

Report a resource vector rather than adding unlike units:

`(arithmetic/hash counts, aggregate CPU ns, accelerator work/time, wall ns,
peak live memory, transferred bytes, measured joules)`.

Keep estimated dollars separate with an explicit price, utilization, rental,
capital and residual-value model. A CPU thread clock omits concurrent worker or
GPU work unless it is explicitly aggregated. A fixed-host wall-time rate is a
throughput observation under that parallelism; it is not aggregate physical
work. Missing energy/CPU/transport measurements remain unknown. Reference FLOPs,
scalar multiplication counts and nominal accelerator throughput are not lower
bounds on any of these resources.

For one declared scalar resource `C`, record actual disjoint charges:

`C_total = C_prepare + C_select + C_challenge + C_compute + C_transcript
         + C_proof + C_transfer + C_failed_or_cancelled_tail`.

This is an accounting partition, not a theorem that these phases are independent
or cannot be fused. Nested setup/search/trial timers are not added again to total
time. Shared computations are paid once; all work of every unsuccessful strategy
selection or aborted attempt is paid. State excluded common supplied inputs and
offline compilation explicitly. A full operational claim additionally accounts
for material acquisition, actual header/application preparation and transport.

The residual `whole cohort - charged stages - measured observers` is not
automatically logging overhead. It may also contain producer dispatch, queue
growth, selection bookkeeping, cache destruction and failed-call cleanup.
Separate those obligations by instrumentation, or label the result as a
timed-kernel budget with unallocated overhead. A conservative envelope charging
all residual work can be reported separately with its inclusion rules; it is
not interchangeable with a measured complete producer cost. A missing final
record after an early error leaves the affected total unknown, never zero.

At horizon `m`, an amortized full-cost observation is

`(actual shared preparation + sum(actual online charges)) / distinct_valid_count`.

With zero valid tickets the denominator is undefined. Retain the full budget,
zero count and exhaustion/failure; never print zero cost, discard the cohort, or
impute a winner. Do not divide setup by an unexecuted future horizon. Do not use
`mean(cost / winners)` interchangeably with `sum(cost) / sum(winners)`.

### 5.1 Enforcing and observing the budget

Freeze the budget and stopping rule before seeing held-out outputs. For each
completed attempt, retain cumulative charges, outcome and semantic identity.
Continue after a hit when measuring all valid tickets within the budget. A
first-win arm can remain a separately labeled stopping-time experiment.

Check for budget exhaustion before starting more work and retain the actual
charge of in-flight work. Nonpreemptive proof/batch overshoot must be measured.
Outputs completed after the declared resource boundary do not become within-
budget wins, and their spent work cannot be silently carried into a free next
cohort. If the instrumentation cannot enforce or reconstruct the boundary,
report a bounded-attempt observation and actual overshoot, not a hard budget
claim. Cancellation cleanup and worker settlement remain charged.

Receiver start reservations are not miner effort. Returning an unused
reservation is compatible with charging all actual CPU; refunding an attempted
lottery after a miss is not. Restoring a branch snapshot or a cache must not
rewind the research budget ledger. Instrumentation is evidence about the
registered experiment, not an on-chain meter enforcing honest adversary reports.

## 6. Resource-to-success definitions and upper tails

Let `A` range over the declared adversary class, `P` its preprocessing allowance,
`B` its online budget in one declared resource model, and `N_A(P,B)` its distinct
valid count at the selected validity tier. Record both budgets; a cold claim may
charge `P+B`, whereas a conditional online claim keeps `P` fixed and visible.

For a frozen reference algorithm and workload policy, a useful finite-horizon
research quantity is

`kappa_registered(B,P) = max_A E[N_A(P,B)] / E[N_reference(P_reference,B)]`.

Include the reference itself in that registered family, so its exact
expectation-ratio maximum is at least one. The maximum is over registered
executable policies and declared environments,
not all possible algorithms or hardware. The reference policy is fixed before
measurement. Its denominator must be positive. A matched fixed-input ratio
measures implementation advantage; a task-selection game must also allow the
adversary its actual task choices and charge selection. Hindsight minimum cost
per sample is an oracle selector, not a measured executable miner.

A theoretical cost-rate objective could instead assert

`E[N_A(P,B)] <= kappa * (B / c_reference) * p + delta`,

where `c_reference` is resource per defined reference opportunity, `p` its
lottery probability, and `delta` is a bound on the **expected extra count**.
If a proof supplies only bad-event probability `epsilon`, converting it into
this expectation bound requires a finite maximum output count, for example
`delta <= N_max * epsilon`. Do not add a probability to a count without that
step. Preprocessing and initial reusable opportunity credits must be included
in the theorem's parameters. This document does not assert this inequality
for W1.

### 6.1 Conditions for a binomial upper bound

For current W1's inclusive uniform 256-bit ticket comparison, nonzero target `T`
has `p=(T+1)/2^256`; target zero is explicitly refused, so `p=0` there. Thus the
existing `7f...ff` and `07...ff` diagnostic targets have probabilities `1/2` and
`1/32`, respectively, under the uniform-ticket model.

A binomial domination argument needs a reduction establishing all of:

1. At most a deterministic `Q(P,B)` fresh, distinct effective opportunities can
   be obtained within budget, including adaptive screening and preprocessing.
2. Conditional on the prior history, each opportunity has success probability
   at most `p` with an appropriate fresh-randomness coupling. A valid output
   obtained without such an opportunity has a separately bounded bad-event
   probability `epsilon`.
3. Duplicate credit, post-budget outputs, task eligibility and all branch
   transitions obey the specified game. `Q` is a precommitted maximum, not a
   random stopping count selected after a win.

Only under those premises may one claim

`Pr[N_A(P,B) >= k] <= Pr[Binomial(Q(P,B), p) >= k] + epsilon`,

clipped to one. The right side is dimensionless. A budget-to-opportunity
reduction is precisely the missing work-hardness obligation; assuming that
every opportunity costs one complete reference execution would beg the question.
For arbitrary adversarial publication/withholding, use a domination or a
conditional counting bound, not a requirement that its published stream be
exactly Poisson.

For a binomial variable, an independently checkable rational bound is

`Pr[N >= k] <= min(1, (1-p+p*z)^Q / z^k)` for rational `z >= 1`.

More general adaptive resource/target processes need an explicitly proved
conditional moment-generating-function or supermartingale premise. An empirical
mean or histogram cannot supply that premise. Without it, a mean bound supplies
only Markov's inequality `Pr[N >= k] <= E[N]/k` for `k>0`.

### 6.2 Small countermodels the inference must survive

* Eight independent fair opportunities have mean four and probability `1/256`
  of eight successes. Eight perfectly correlated fair indicators have the same
  marginals and mean, but probability `1/2` of eight successes. Marginal
  unpredictability and equal average rate do not establish the required tail.
* After stopping at the first hit, conditioning on the observed attempt count
  being one makes success certain. Substituting that observed count into an
  independent one-trial experiment would incorrectly give probability `1/2`.
* At probability `1/2`, eight actual attempts yield at least one success with
  probability `255/256`. If misses are refunded and only the winner is charged,
  calling this a one-attempt budget would incorrectly bound it by `1/2`.
* One shared setup costing eight units and four parent searches costing two
  units each cost sixteen units jointly, not forty. Losing three forks does not
  refund the resources spent on them.

The [exact arithmetic controls](../../../../formal/pon-nakamoto-v1/experiments/w1_cost_security_math.py)
and [finite checks](../../../../formal/pon-nakamoto-v1/experiments/test_w1_cost_security_math.py)
reproduce these examples using rational arithmetic. They prove no W1 reduction.

## 7. Preselected kappa sensitivity targets and evidence grades

The following are **research sensitivity targets selected for this campaign**,
not existing PoN security parameters, release thresholds or automatic acceptance
rules. Report results against all four; do not select one after seeing outcomes.

| Target `kappa_*` | Research interpretation | Conditional raw resource share reaching half effective work |
| --- | --- | --- |
| `11/10` | Study whether a ten-percent advantage envelope is even plausible | `10/21` |
| `5/4` | Study a twenty-five-percent advantage envelope | `4/9` |
| `2` | Stress a twofold advantage envelope | `1/3` |
| `4` | Stress a fourfold advantage envelope | `1/5` |

The share calculation is

`q_effective = kappa*q / (1-q+kappa*q)`;

for any chosen effective-share threshold `tau`, inversion gives

`q_at_threshold = tau / (kappa*(1-tau)+tau)`.

These formulas require linear resource-to-throughput conversion, the same
resource unit, reference honest throughput, comparable eligible task/target
availability and no omitted hardware/network asymmetry. A mean-only kappa does
not provide the upper tail or honest-growth lower bound needed for chain
security. Half effective work is a sensitivity point, not a complete finality
theorem under delay, withholding, DAA or changing demand.

Use explicit evidence grades:

| Grade | What it establishes | What remains open |
| --- | --- | --- |
| Specified | Frozen game, implementation identities and falsifiable claims | Whether any run completed |
| Reproduced relation | Full native/oracle validity and negative controls | Producer cost, freshness distribution and tail |
| Measured strategy | Complete resource observations for a named executable | Optimal adversary and untested workloads/hardware |
| Finite-family statistical envelope | A stated simultaneous interval over registered strategies/environments, under its sampling assumptions | Unregistered algorithms, nonstationarity and theoretical hardness |
| Conditional theoretical bound | A proved reduction under explicit complexity/randomness/resource assumptions | Whether finite W1 and physical hardware meet those assumptions |

No grade is a production-qualification flag. A source-bound, reproducible
counterexample exceeding a claimed envelope can falsify that claim. An absence
of found counterexamples cannot establish a universal envelope.

### 7.1 Statistical acceptance within a registered family

Use independent held-out cohort seeds, or state why independence is unavailable.
Deterministic replays on different machines, or the same inputs through several
kernels, are paired controls, not new independent lottery samples. Register
family size and confidence allocation before evaluation. Retain all arms,
timeouts, unsupported cases, zero-win cohorts, slower observations and missing
measurements. An unsupported arm is not a zero-cost successful adversary.

One conservative option for independent equal-budget cohorts is to bound their
integer counts in `[0,L]` with a **predeclared** cap. With `m` such samples,
Hoeffding gives a one-sided mean-count margin

`L * sqrt(log(1/alpha)/(2*m))`.

Construct an upper bound `U_A` for each attack mean and a lower bound `L_H` for
the reference mean with a declared simultaneous error allocation. A conditional
finite-family ratio upper bound is `max_A U_A/L_H` only when `L_H>0`. Otherwise
the result is inconclusive, not zero advantage. The bound assumes independent
cohorts and a fixed evaluated policy/distribution. Persistent adaptive state
between cohorts needs a different conditional analysis or a frozen complete
stateful campaign as the sampling unit.

Such a confidence interval concerns registered mean performance; it does not
establish rare-event domination, future nonstationary operation, or a universal
minimum cost. Use a predeclared fixed sampling plan or an appropriate
time-uniform procedure; repeated optional stopping on ordinary fixed-sample
intervals is not valid. A very wide interval is an informative inconclusive
result, not grounds to silently relax the target or omit failures.

## 8. Conditional hybrid comparison

The pure matrix game remains the primary target. This section defines what a
hash-floor comparison would have to establish; it installs no fallback or new
consensus rule.

### 8.1 What an independently bound hash floor can guarantee

Assume an AND construction requires both a valid useful-work statement and a
fresh hash-floor success. The floor input must commit to the complete relevant
context and semantic useful-work identity; proof randomness, alternate encoding,
parent changes and extra nonce choices must have declared lottery consequences.
Credit cannot reuse one floor success for many distinct counted outcomes.

If a model allows at most `Q_H` distinct floor-oracle queries, each with
conditional success probability `p_H`, then complete valid outputs are a subset
of those successes, up to an explicit guessing/binding failure term. The
binomial bound from section 6 applies to the floor under these premises.
Converting physical budget `B` to `Q_H` requires its own resource assumption;
the random-oracle query model does not prove joules, dollars or ASIC equality.

Without a useful-work cost theorem, the guaranteed component is only this
independent floor. One must not add an unproved useful-work lower bound. Even
two valid individual lower bounds imply only their maximum unless a composition
argument rules out resource overlap and shared work. Fix whether a useful
result can be reused while scanning many floor nonces, whether a floor can be
screened first, and which misses trigger another useful computation. These
different schedules have different expected costs. Multiplying two target
probabilities or adding two advertised costs without that schedule is invalid.

### 8.2 Additive-cost sensitivity calculation

For comparison only, assume the reference expected cost of a **comparable
complete opportunity**, including failed work, is normalized to one. Let `beta`
be its independently accounted floor fraction. Assume the useful component can
be accelerated by at most `kappa_U`, the floor by at most `kappa_H`, and their
charges add without hidden reuse or overlap. Then

`kappa_combined <= 1 / (beta/kappa_H + (1-beta)/kappa_U)`.

Equality is the sensitivity model in which both component accelerations are
simultaneously attained under the declared schedule. Independently measured
best speeds may be incompatible on the same hardware, so equality is not
automatic. This conditional cost bound is not a theorem about any unspecified
AND protocol. It does not turn expected component costs into a finite-budget
tail bound; that needs the separate opportunity/rate reduction. `beta` is not
the fraction of code lines, nominal FLOPs or successful checks. It is a
measured/justified cost fraction under the same resource model, failure schedule
and hardware assumptions used for both participants.

With `kappa_H=1`, unknown/unbounded useful acceleration has limiting advantage
`1/beta` for `beta>0`; at `beta=0` there is no finite bound from the floor. With
a bounded floor hardware advantage it becomes `kappa_H/beta`. A ten-percent
floor would therefore leave a limiting advantage of ten, or twenty if its own
hardware acceleration is two. A small floor is not automatically a small-risk
insurance policy.

For `1 <= kappa_H < kappa_* < kappa_U`, the minimum floor fraction in this model is

`beta >= (1/kappa_* - 1/kappa_U) / (1/kappa_H - 1/kappa_U)`.

If the useful arm already meets the target, zero floor suffices **in the model**.
If both components exceed the target, no fraction can meet it. For
`kappa_H=1`, `kappa_U=4`, and `kappa_*=5/4`, the fraction is `11/15`.
If useful acceleration is entirely unbounded, the fractions for research
targets `11/10`, `5/4`, `2` and `4` are at least `10/11`, `4/5`, `1/2` and `1/4`
respectively.
These results explain the cost of relying only on the floor; they do not select
a production mixture or replace research on the pure matrix primitive.

## 9. Research obligations and executable acceptance

The four stages below refine the existing PN1 work, without creating another
development plan or claiming completion before evidence exists.

| Stage | Executable evidence required | Exit interpretation |
| --- | --- | --- |
| 1. Freeze the game | Source-bound game record; semantic deduplication; tiered validity counts; exact budget/target/stopping and preparation policy; mathematical controls below | Specification and arithmetic consistency only |
| 2. Attack the relation and cost model | Complete legal producers over zero, identity, low-rank, sparse and special dense inputs; fixed-task reuse, batches, adaptive task/seed selection, multi-parent contexts, exact low-precision arithmetic, cancellation and duplicate-proof controls | Named attacks reproduced or ruled out only for their exact inputs/implementations; rejected false traces add zero valid work |
| 3. Measure complete cost | Cold/hot/batch cohorts, fastest known fixed and executable adaptive baselines, complete failures, resource vectors and actual transfers, source/host/compiler identities and independent checking | Descriptive results and, if justified, finite-family intervals; no universal lower bound |
| 4. Compare architectures | Apply the same game to pure matrix and an explicitly specified hypothetical hybrid; separately evaluate numerical error/useful quality, verification proof cost and any multiple-ticket mapping | Conditional comparison; no automatic profile, reward or verifier change |

Use the full native verifier and independent arithmetic checker for retained
winners. To infer bounds from complete attempt streams, additionally establish
validity coverage of the relevant losing attempts or the generator's exact
relation; a hash commitment to unretained losing bytes alone is not independent
replay of those bytes. State the coverage and retain bounded deterministic
replay inputs. A checker mismatch, lost cost interval or missing raw record
prevents the affected measurement claim, even if other arms completed.

For stage 2, noise cancellation is a research control, not an assumed attack on
current W1. In KW's separate rotation appendix as written, `R=H D` and `d=1`
give `(AHD)[i,k]*(D^T H^T B)[k,j]=(AH)[i,k]*(H^T B)[k,j]`: signs cancel locally.
This exposes a preprocessing possibility in that stated subcase, not a break
of the main additive low-rank construction or W1. Any adopted rotation/quantized
variant needs its own exact relation and security game. Merely passing rank,
noise-sensitivity or reconstruction checks cannot replace its cost argument.

Float/error and Hepta quality work remains separate: bit-exact reconstruction,
acceptable model perturbation, genuine task fulfillment, held-out improvement
and release authority have different predicates. A ZK proof can compress a
specified correctness relation; it does not by itself establish costly witness
generation. If several tiles, proof randomizations or encodings can produce
lottery opportunities, specify overlap and charge each eligible opportunity in
a fresh game rather than importing W1's one-transcript-one-ticket analysis.

### 9.1 Exact arithmetic reproduction

Run the existing project preflight before edits/builds, then from the repository
root:

```sh
python3 -B formal/pon-nakamoto-v1/experiments/test_w1_cost_security_math.py -v
python3 -B formal/pon-nakamoto-v1/experiments/w1_cost_security_math.py
```

The second command emits `pon-w1-cost-security-math-v1` to stdout. Capture it only
to a fresh path with the usual source/command/exit receipt. All displayed
probabilities and hybrid/share calculations use `fractions.Fraction`; no native
work timing, empirical confidence result or hardness qualification is emitted.
Tests enumerate small Bernoulli spaces independently, check generating-function
bounds, expose correlation/stopping/refund countermodels, and verify hybrid
threshold inversions and explicit floor hardware advantages. Their success is
arithmetic evidence under the stated premises, not evidence that W1 meets them.

## 10. Primary references and their applicability

* Komargodski and Weinstein, [Proofs of Useful Work from Arbitrary Matrix
  Multiplication, arXiv v4](https://arxiv.org/abs/2504.09971v4), 2025-11-13;
  [ESA 2026 proceedings](https://doi.org/10.4230/LIPIcs.ESA.2026.2), published
  2026-08-25. ESA Definition 3, pp.2:6-2:7 gives a single-instance success bound;
  Assumption 10, p.2:10 concerns correlated low-rank intermediate computations;
  Appendix B, p.2:16 states the stronger blockchain-process target. The optimal
  security claim remains conditional. Asymptotic hardness and unspecified
  constants do not supply an n64/r8 hardware-cost bound. Appendix A, p.2:15 is a
  separate candidate; its literal `d=1` cancellation is the local algebra above.
* Ball, Rosen, Sabin and Vasudevan, [Proofs of Work from Worst-Case
  Assumptions](https://eprint.iacr.org/2018/559), CRYPTO 2018,
  [DOI](https://doi.org/10.1007/978-3-319-96884-1_26). Non-amortization and
  multi-proof success are relevant qualification goals; its assumptions and
  constructions are not a theorem about arbitrary ML inputs or W1 hardware.
* Ding, [On Pearl Blockchain's Proof of Useful Work: Systematization and
  Flexibility](https://arxiv.org/abs/2610.25347v1), 2026-10-18. Its Theorem 4.1
  establishes efficient sensitivity checking. That local numerical condition
  is not a proof of resource-to-lottery optimality for W1.

The [KW ePrint entry](https://eprint.iacr.org/2025/685) lists a 2025-12-08
revision; the preceding literature review could read its metadata but not its
PDF. The detailed references here identify the arXiv and ESA texts actually
read, rather than asserting an unchecked byte-for-byte equivalence.
