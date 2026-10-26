# W1 resource advantage and the chain-security envelope

Research status: conditional mathematical interfaces and exact finite controls.
**O03 remains open.** This document selects no production parameters, promotes no
qualification, and changes no consensus, target, work class, confirmation policy
or activation rule. The inspected source baseline is
`4081bf6f397b74cf4f928e845259a18d68211181`; generated evidence binds the actual
configuration and consensus files by SHA-256. Literature was checked on
2026-10-26.

The [cost-security game](W1_COST_SECURITY_GAME.md) already defines the adversarial
preprocessing bank, fresh queries, unqueried submissions, credit multiplicity,
optional stopping and resource-budget obligations. This increment supplies the
next interfaces: native integer chainwork; explicitly assumed arrival processes;
validated propagation delay; a signed chainwork-lead certificate; and the missing
connection to branch-local difficulty adjustment. It does not manufacture the
resource lower bound required at the start of that chain.

## 1. Bind the model to the actual implementation

The authoritative rules are [CONSENSUS](../CONSENSUS.md), the
[native arithmetic](../../../../trillionnium/crates/trnm-pon-node/src/consensus.rs)
and the [development configuration](../../../../config/pon/devnet-v1.json).
The source is a development contract, not an activated public-network profile.

| Component | Inspected rule | Consequence for a security argument |
| --- | --- | --- |
| Valid lottery | Canonical work digest is at most the branch-derived 256-bit target | A uniform fresh digest has probability `(T+1)/2^256`; the `+1` matters |
| Weight | `required_work(T) = floor(2^256/(T+1))`; zero target rejected | Use the actual integer weight, not a floating difficulty proxy |
| Cumulative work | Checked 512-bit unsigned arithmetic | Overflow cannot silently create chainwork |
| Fork choice | Strictly greatest fully validated cumulative work; equal work retains the current valid tip | Header receipt or an equal-work private chain is not automatically a reorganization |
| Work identity | Complete template and task context bind the challenge before the relevant work-digest reveal | Post-reveal target/header selection is outside the admitted statement |
| Quality | Model quality and reported FLOPs do not multiply chainwork | A useful or expensive task is not an extra vote |
| DAA | Branch-local 16-block interval; `(N-1)*spacing`; integer clamp and floor | Forks can have different future targets; epoch boundaries are endogenous |
| Time | Strictly above the upper median of up to 11 ancestors; at most `now+120 s` | Adjacent timestamps may decrease; future blocks may become acceptable later |
| Confirmation | Both named depth and work delta; development defaults are 6 and 6 | These settings are risk controls, not finality or a six-block reorg limit |
| Activation | `production_activation = false` | Passing this model cannot enable a public network |

The development target limit is `2^255-1`, and the configured spacing is 10 s.
That spacing is an input to retarget arithmetic, **not a measurement or guarantee
of the realized interarrival distribution**. The 20-block reward maturity is an
economic policy and supplies no missing common-prefix theorem.

## 2. Exact target-to-work mapping

Let `M=2^256`, `d=T+1`, `p=d/M`, `w=floor(M/d)`, and `eta(T)=p*w`.
Uniformity here is an explicit lottery assumption supplied by O01; the native
comparison does not prove that assumption for adversarial SHA-256 interactions.
For one fresh opportunity whose target is fixed before its answer,

```text
E[credited chainwork] = eta(T)
1 - p < eta(T) <= 1.
```

This is an arithmetic identity and floor bound. It does not charge computation.
For development targets `1 <= T <= M/2-1`, `w >= 2` and
`eta(T) > w/(w+1) >= 2/3`. The minimum is attained at `T=floor(M/3)`:

```text
eta_min = 2/3 + 4/(3*M),       eta_max = 1.
eta_max / eta_min < 3/2.
```

To see the minimum, partition targets by `w=k`. Their least permissible
`d` exceeds `M/(k+1)`, so `eta > k/(k+1)`. The `k=2` interval starts at
`d=floor(M/3)+1` and has a smaller minimum than every `k>=3` interval.
Since `2^256 mod 3 = 1`, the displayed exact minimum follows. The harness
checks the analogous minimum by exhaustive smaller integer spaces as well as
the full-width formula.

| Target | Lottery probability | Native weight | Expected work per fresh opportunity |
| --- | ---: | ---: | ---: |
| `M/2-1` | `1/2` | 2 | 1 |
| `floor(M/3)` | `1/3 + 2/(3*M)` | 2 | `2/3 + 4/(3*M)` |
| `M/4-1` | `1/4` | 4 | 1 |
| `M/1024-1` | `1/1024` | 1024 | 1 |
| 1 | `2/M` | `M/2` | 1 |

A bound on fresh opportunity count therefore converts to a bound on expected
weighted output using the actual target schedule. With conditional uniformity,
weights predictable before every reveal, bounded opportunity count `Q`, and
one credit per fresh answer, expected new adversarial chainwork is at most `Q`.
A tail bound must retain the weights: rare large weights cannot be replaced by
unit increments merely because their expectation is at most one. The existing
cost game's one-sided predictable-lottery process and Section 6 below provide
interfaces; neither supplies an honest-chain lower bound by itself.

Across different target schedules, a resource-to-opportunity mean ratio may
need the factor `eta_max/eta_min`. For example, under an otherwise justified
common resource metric and honest active fraction `s`, a no-delay *mean output*
ratio is bounded by

```text
adversarial expected work / honest expected work
    <= kappa*q*eta_max / ((1-q)*s*eta_min).
```

This factor is a conservative arithmetic envelope, **not a demonstrated DAA
manipulation or a security threshold**. Targets require valid ancestry; a miner
cannot freely choose the most profitable floor interval after seeing a digest.
The harness deliberately permits post-reveal selection in a separate invalid
model and obtains expected credited work greater than one. That countermodel
explains why the actual challenge binding is a necessary premise.

For small lottery probability the relative floor loss is below `p`, but the
current easy development targets must not be analyzed by silently dropping it.
No rounding-rule change is proposed here.

## 3. The resource interface needs a process, not just a mean

Use the existing game's symbols without resetting them at epoch boundaries:

- `Q_A(P,B)+G(P,B)` bounds fresh adversarial answers, including verifier-triggered
  answers to previously unqueried submissions and all early guesses.
- `K_0(P)` bounds already revealed credit capacity. For chainwork, derive a
  **weighted** bank `W_0` from its eligible targets. Include work on hidden parents
  and unconsumed witnesses; a public tip change does not erase it.
- `L` bounds admitted credit per answer. If credits have different weights, bound
  the sum of those weights. Proof encodings and nonces are not extra work by fiat.
- `epsilon` accounts for the concrete reduction/collision/soundness/coupling
  failures at the declared lifetime and resource scope. Do not replace a finite
  failure bound by the word negligible.

An adversarial upper bound on all admitted candidates may safely count mutually
incompatible siblings conservatively. An honest *growth* lower bound cannot:
only ancestry-compatible, fully validated progress contributes to the relevant
chain or to a theorem's proved growth surrogate.

The following constant-rate model is an explicit sensitivity scenario. Let `q`
be the adversary's fraction of one predeclared common raw resource, `kappa>=1`
its bounded resource-to-opportunity advantage, `s` the honest active fraction,
and `lambda_0` the hit rate at a fixed target if all raw resources executed the
reference algorithm. **Assume**, separately, the required independent Poisson
arrivals and their coupling to actual valid blocks:

```text
a = lambda_0 * kappa * q
h = lambda_0 * (1-q) * s.
```

When `s=1`, the event share is `kappa*q/(1-q+kappa*q)`. With inactive honest
resources it is `kappa*q/((1-q)*s+kappa*q)`. This is a resource normalization;
it does not follow from a benchmark speed ratio, a SHA query count alone, or
successful-ticket counts divided by elapsed time. Different energy, memory,
latency and bandwidth budgets are not interchangeable without a specified
conversion argument.

The harness includes a countermodel in which every step has adversarial marginal
probability `1/4`, but a hidden initial coin chooses an all-adversarial run or an
all-honest run. The chance of an eight-step positive lead is `1/4`, greater than
`2^-8`. After the first adversarial event, its next conditional probability is
one. A mean-only fraction does not justify a conditional exponential bound.
The same caution applies to batched winners and selectively released banks.

## 4. A precise fixed-target delay region

Under the constant-rate, equal-weight, fully validated bounded-delay Nakamoto
model, the asymptotic feasibility region is

```text
a < h / (1 + h*Delta).
```

Here `Delta` bounds dissemination of usable honest progress. Cao and Guo's
continuous-time analysis gives this strict region and finite-latency guarantees
under its stated model; its finite-depth analysis also accounts for balanced
honest heights [S1]. Substituting the declared resource rates gives, for positive
`q` and `lambda_0`,

```text
kappa < ((1-q)*s) / (q*(1 + lambda_0*(1-q)*s*Delta)).
```

Equality is not a certified operating point. `lambda_0=0` supplies no liveness;
`h=0` supplies no honest growth. The executable result records these cases
explicitly. `q=0` removes this adversarial ratio bound, but still does not prove
availability or a public-network delay bound.

For an **assumed** raw resource share `q=1/3`, active fraction `s=1`, and reference
rate `lambda_0=1/10 s^-1`, the exact ceilings are:

| Fully validated delay `Delta` | Strict ceiling on `kappa` | Consequence in this declared model |
| ---: | ---: | --- |
| 0 s | 2 | The usual event-share half boundary is only the zero-delay limit |
| 1 s | `15/8 = 1.875` | Some margin is already consumed by propagation |
| 10 s | `6/5 = 1.2` | `kappa=5/4` is outside despite event share `5/13 < 1/2` |
| 20 s | `6/7` | Even `kappa=1` is outside this assumed envelope |

The configured 10 s target spacing motivated this sensitivity point; there is
no claim that `lambda_0=1/10` has been measured. Realized total rate changes when
`kappa` changes. One cannot simultaneously fix this reference rate and assert
that the total network continues to produce exactly one block every 10 s.

`Delta` includes body availability, transcript/proof transfer, verification
queues, validation service, state execution and dissemination to the honest
miners whose progress the theorem uses. A ping, a median proof time, or a
single-node round trip cannot establish it. An honest availability multiplier
`s` is a declared rate premise; congested or correlated work is not automatically
independent Poisson thinning. Unbounded isolation, task exhaustion or adversarial
queue starvation breaks the model.

This region is **asymptotic and fixed-target**. The calculator does not import
S1's finite-confirmation bound or assert a safe production depth. It also does
not treat a delayed honest-growth process as a simple random walk. Blake,
Feng, Wang and Yu's January 2026 preprint supplies a useful weighted-process
perspective and identifies precisely such a random-walk pitfall; its arrival
model has fixed block-type Poisson rates [S2]. That is not an automatic theorem
for this repository's adaptive branch-local targets.

## 5. Distinguish opportunity, reward count and private catchup

### 5.1 A virtual OR does not preserve the full block-count law

The October 2026 PoML preprint provides a recent explicit inference-cost-to-
backbone interface. Its Appendix F assumes accurate complexity, non-amortizing
inference/proof cost, sufficient available work and synchronous flat parties.
F.5 couples a complexity-`C` lottery to the OR of `C` Bernoulli outcomes [S3].
For a reuse in W1, distinguish what this coupling preserves:

```text
C=2, p=1/2
actual one-pair block-count PMF:      (1/4, 3/4)
virtual two-trial success-count PMF:  (1/4, 1/2, 1/4).
```

Both have probability `3/4` of at least one success. They do not have the same
count distribution or expectation. Under an explicit coupling, the one-pair
indicator is bounded above by the virtual sum. Summing groups preserves this
adversarial count domination. Honest unique-round/growth predicates and actual
chain credit still require their own mapping. This is a limited transfer
obligation, not a claim to refute every result in S3.

Two additional transfer checks matter: proof cost before publication does not
by itself force proof computation on lottery misses; and miner-controlled
transaction/header choices are not automatically fresh unpredictable input at
a round boundary. Their resource accounting belongs in O01/O07. No claim about
W1 follows merely from S3's simulated block times or assumed proof independence.

### 5.2 Exact probabilities for a specified zero-delay private race

Let `r` be the adversarial *event* share after any justified resource conversion.
Assume independent arrivals, zero delay, a fixed common weight, a known honest
lead of `d` increments, and an adversary withholding until it is strictly heavier
at the attacked node. Equal-weight retention means it must gain `d+1`:

```text
P(eventual strictly heavier | known deficit d)
    = (r/(1-r))^(d+1),  for r < 1/2;
    = 1,               for r >= 1/2.
```

If an alternate model treats a tie as immediate success, the exponent is `d`.
This alternate tie model is explicit in the harness; it does not replace native
fork choice. Network-wide equal-work races have different local views and must
be modeled separately.

A user waiting for `z` honest increments has not established a known adversarial
deficit `z`. The adversary may mine throughout the wait. If it starts with `b`
private increments, the number `K` it finds before the `z`th honest increment has
mass `C(z+k-1,k)*(1-r)^z*r^k`. Define `m=z-b+1` for strict heavier. When `m>0`
and `r<1/2`, the exact specified-strategy probability is

```text
sum_{k=0}^{m-1} P(K=k)*(r/(1-r))^(m-k)
    + 1 - sum_{k=0}^{m-1} P(K=k).
```

For `m<=0` it is one. For `1/2<=r<1` eventual catchup is one; `r=1` is rejected
because the honest waiting time never finishes. The harness compares the finite
negative-binomial expression against a separately written absorbing recursion.

| Assumed event share `r` | Known deficit 6, strict catchup | Wait for 6 honest increments, `b=0` | Same wait, `b=2` |
| ---: | ---: | ---: | ---: |
| `1/10` | `0.000000209075` | `0.000110317207` | `0.002957060800` |
| `1/4` | `0.000457247371` | `0.032386859258` | `0.137310028076` |
| `1/3` | `0.007812500000` | `0.155308867776` | `0.366255144033` |

These are rounded displays of exact rationals for the stated private strategy.
They are **not upper bounds against all attacks**, a common-prefix proof, or the
risk of the repository's development six-confirmation policy. That policy also
uses work delta; the event count and initial state in this model are deliberately
specified independently. Erasing the wait-period work or initial bank can
understate even this simple attack by orders of magnitude.

## 6. A conditional signed-chainwork certificate

The existing game's one-sided ticket process does not certify honest progress.
The following two-sided interface states exactly what a chain reduction would
need to supply. It allows predictable adaptive choices, weighted adversarial
jumps, optional stopping and an initial weighted bank.

Let `F_(i-1)` contain all revealed history before step `i`. Suppose an ideal
coupled process has mutually exclusive adversarial, honest-progress and idle
events with increment `X_i` equal to `+w_A,i`, `-w_H,i`, or zero. The positive
weights and probability bounds are predictable and satisfy

```text
P(A_i | F_(i-1)) <= alpha_i
P(H_i | F_(i-1)) >= beta_i
alpha_i + beta_i <= 1.
```

The harness uses this explicit compatible-bound subcase. If multiple relevant
events occur in a time bin, the reduction must refine the event sequence or
supply its full conditional moment bound; it cannot discard those events.
Most importantly, `H_i` must imply the settled progress claimed by the reduction,
or a precisely defined growth surrogate sufficient for its settlement theorem.
An honest sibling, early header, or unverifiable body does not satisfy that
predicate.

For one fixed `z>1`, define

```text
psi_i = 1 + alpha_i*(z^w_A,i - 1)
          + beta_i*(z^(-w_H,i) - 1).
```

The adversarial coefficient is positive and the honest coefficient negative,
so the conditional moment of `z^X_i` is at most `psi_i`. If `psi_i<=1` at every
history and `S_t=W_0+sum_(i<=t) X_i`, then `z^S_t` is a nonnegative
supermartingale. Ville's inequality gives

```text
P(ever S_t >= D) <= min(1, z^(W_0-D))  when D > W_0;
                 = 1                  when D <= W_0.
```

This follows directly by applying the maximal inequality to
`z^(S_t-W_0)`, initially one; infinite-horizon crossing follows from the
increasing union of finite horizons. The weights and event choices may depend
on prior history; no independence claim is made beyond the stated conditional
moment bound. A random initial bank needs a bound on its exponential moment,
or a deterministic upper envelope with a separately charged failure event.

For a real execution, require an actual coupling such that the failure event has
probability at most `epsilon` and a real safety violation implies either this
ideal crossing or coupling failure. Then add `epsilon` once and clip at one.
Conditioning on an arbitrary global no-failure event is not a proof that the
conditional moment inequalities survive. The executable function takes this
failure budget separately; it does not estimate it from samples.

Without `psi_i<=1`, the compensated process
`z^(S_t-W_0)/product_(i<=t) psi_i` is still a candidate supermartingale when the
positive conditional moment bounds are established. Its crossing boundary
includes that accumulated compensator. Dropping it would restore an invalid
fixed-deficit guarantee. A chosen `z` must work at all relevant histories;
retuning it after observing a favorable path requires a separately valid
mixture or predictable process.

The exact control switches between two policies based on the previous event:
`(alpha,beta,w_A,w_H)=(1/5,3/10,1,1)` or `(1/10,3/5,2,1)` after an honest event.
At `z=3/2`, their moment bounds are respectively `1` and `37/40`. Exhaustive
history enumeration through eight steps gives crossing probability
`2625313/100000000 = 0.02625313` for hurdle 4 and bank zero; the all-time bound is
`16/81`. This is a finite check of the conditional theorem, **not a model of
Node settlement**. The report's settlement-coupling flag remains false.

## 7. Why actual DAA and reorganization remain a separate obligation

For the native retarget function, let `D=(N-1)*spacing`:

```text
observed = clamp(max(1, last.saturating_sub(first)), ceil(D/4), 4*D)
next_target = clamp(floor(parent_target*observed/D), 1, pow_limit).
```

The implementation checks `D` and `4*D` for unsigned 64-bit overflow; multiplication
uses wide work arithmetic. Median-time admission and future deferral remain
separate from that calculation. No timestamp rule here establishes actual
elapsed production time.

The retained [native DAA adversarial schedule test](../../../../trillionnium/crates/trnm-pon-node/tests/daa_adversarial_schedule.rs)
and [boundary analysis](WORK_COST_DAA_BOUNDARIES.md) already exercise legal
branch schedules. After two intervals clamped to `38/150` of the previous target,
the independent arithmetic reconstruction in this increment yields:

| Branch timestamps used for the next adjustment | Next native required work |
| --- | ---: |
| Ordinary: `320..470` | 31 |
| Lower clamp: `32..47` | 123 |
| Upper clamp: `27..627` | 7 |

The backward first timestamp `27` can be legal after parent time `31` because the
median is `26`. Time `628` can be deferred at wall time `507` and accepted at
`508`, with skew 120. These are rule-boundary observations; neither profitability
nor a mainnet attack probability follows. This increment ran the arithmetic
reconstruction, not a new execution of the native test.

Applying a fixed-target theorem separately to every observed epoch is not a
proof. Epoch length and endpoints, hidden branches, work spent before the epoch,
resource reallocation, timestamps and public observation times can all be
adaptive. The variable-difficulty backbone literature imposes explicit dynamic
participation conditions [S4, S5]; none are established here for `N=16` merely
because the code resembles a familiar retarget rule.

| Needed bridge | Required concrete result | Current evidence boundary |
| --- | --- | --- |
| Resources to fresh chances | Lifetime bounds for actual W1 `Q_A,G,K_0,L`, instantiated primitive assumptions and failure allocation | O01/O02 still supply this obligation; local operation counts are insufficient |
| Fresh chances to weighted adversarial growth | Native targets fixed before answers; weighted bank and adaptive tail domination across all forks | Integer mapping and conditional interface supplied; actual budget reduction absent |
| Honest work to honest growth | Available tasks, full verification service, safe publication/availability, honest participation, validated delay and growth-tail lower bound | Single-host timing or proof acceptance cannot certify this |
| Variable difficulty | Actual 16-block DAA, timestamp median/skew, changing resource population, fork targets and initial history fit one stated theorem or a new proof | Arithmetic boundary coverage only |
| Settlement and reorg | Common prefix plus growth and quality under the native tie rule; depth and work confirmation mapping; horizon-wide error allocation | Private-race examples and the signed-lead lemma do not establish this coupling |
| Parameter choice | Upper bounds on resource advantage and delay, lower bound on honest active work, safety target, lifetime/asset exposure and uncertainty margin | No production values selected or measured by this increment |

## 8. Assumption failure and upgrade discipline

The following is a proposed qualification and application policy, not an
implemented consensus emergency switch. It fits the existing
[effect boundary](../CONSENSUS.md) and preserves valid chain history.

1. Before selecting a release profile, publish a frozen envelope containing the
   exact W1 relation and primitive assumptions, resource metric, adversary class,
   lifetime preprocessing/bank limits, `kappa` and tail guarantees, task
   availability premise, validated-delay bound, DAA/participation conditions,
   settlement theorem and total error budget. Mark each bound as theorem,
   assumption, measured evidence or operational assertion.
2. Register falsification triggers against that envelope: a legal algorithm
   exceeding the permitted resource advantage; proof/encoding fanout; an
   uncharged reusable bank; validation-delay excursions; service backlog or
   task starvation; target-path behavior excluded by the proof; or divergence
   between the proved and actual confirmation/effect semantics. Absence of an
   observed attack is not a lower bound on adversarial cost.
3. If a premise is falsified, withdraw the affected security/qualification claim
   and fence optional irreversible application effects under the already
   specified local effect policy. Record evidence, invalidate stale generation-
   bound receipts, and preserve revocation history. A larger confirmation depth
   may be proposed only with a new valid bound; it cannot repair an unbounded
   attacker advantage or loss of honest growth by itself.
4. Continue to follow existing validity and cumulative-work rules. This research
   must not silently install finality, freeze consensus, reject a valid heavier
   branch, grant model evaluators fork-choice power, rewrite local history, or
   substitute a different work function. A protocol emergency policy would need
   separate explicit consensus design and authorization.
5. A new work relation, lottery, weight normalization, DAA or proof identity
   requires its own reviewed profile and fresh namespace/context as applicable,
   migration and activation rules, differential vectors, and the same end-to-end
   security analysis. Product rollback and chain rollback remain distinct.

Monitors can reveal some premise violations; they cannot observe secret ASICs,
unrevealed winning banks or every faster algorithm. The envelope must therefore
remain publicly stated and revisable, not certified by monitoring alone.

## 9. Reproduction and evidence interpretation

The [exact calculator](../../../../formal/pon-nakamoto-v1/experiments/w1_chain_security_envelope.py)
and [independent finite controls](../../../../formal/pon-nakamoto-v1/experiments/test_w1_chain_security_envelope.py)
use standard-library integers and rational arithmetic. Decimal strings are
rounded display fields beside exact numerator/denominator pairs. No random
simulation, performance claim or floating-point probability calculation is
used. The controls cover uniform-outcome enumeration, floor geometry, native-rule
arithmetic, separate negative-binomial recursion, bit-path enumeration, adaptive
conditional histories, invalid binding, correlated marginals and qualification
flags. Reproduce from the repository root:

```sh
bash scripts/project-preflight.sh
python3 -B -m unittest discover -s formal/pon-nakamoto-v1/experiments -p 'test_w1_chain_security_envelope.py' -v
python3 -B formal/pon-nakamoto-v1/experiments/w1_chain_security_envelope.py
```

The full-width target/work calculations use exact 256-bit target values. The
finite adaptive enumerator is intentionally capped at 12 steps, with weights,
hurdles and banks capped at 4096; the private-wait calculator caps honest wait
at 512 and private bank at 2048. These are bounded research-control inputs,
**not protocol limits or claims to exhaust all target schedules**. The general
conditional statement in Section 6 is not restricted to those executable caps.

The report refuses unreviewed changes to the displayed development DAA/time/
confirmation parameters or production activation, and hashes the actual inspected
configuration, consensus implementation and normative consensus document. It exposes `production_activation=false`,
`O03_closed=false`, `actual_W1_resource_bound_established=false`,
`all_adversarial_network_security_established=false`, and
`actual_Node_settlement_coupling_established=false`. A report is evidence of
exact calculations under the displayed premises, not native execution evidence,
independent hardware evidence, or evidence that any premise holds in production.

This increment closes the explicit arithmetic/count/probability interface
omissions and supplies falsifiable conditional parameter regions. Closing O03
itself requires the missing rows in Section 7 to be established together for the
same actual release profile and resource adversary, followed by a parameterized
settlement argument. Changing labels or obtaining more successful toy runs
cannot close those rows.

## 10. Primary sources and applicability

- **S1:** Cao and Guo, [Trade-off of Security, Latency, and Throughput of the
  Nakamoto Consensus, v3](https://arxiv.org/html/2312.05506v3), 2024-05-22,
  Sections 2, 4 and 5. Independent constant Poisson mining, bounded delay and
  longest-chain assumptions support the fixed-target region used here. The
  paper's finite-depth treatment includes balanced heights; this calculator
  intentionally does not claim to implement its finite-depth theorem.
- **S2:** Blake, Feng, Wang and Yu, [Rigorous and Generalized Proof of Security of
  Bitcoin Protocol with Bounded Network Delay, v1](https://arxiv.org/html/2601.09082v1),
  2026-01-14, Sections II-C, III and IV, Appendix A. Weighted block types and
  fully delayed honest score growth are relevant. Their fixed-rate arrival
  assumptions and corrected punctured-process argument do not instantiate an
  adaptive 16-block DAA.
- **S3:** Wong, Ciampi and Sarkar, [Proof-of-Machine-Learning-Inference: Mining
  Knowledge, Not Hashes, v1](https://arxiv.org/html/2610.26713v1), 2026-10-19,
  Appendix F. Its explicit cost and uniqueness premises are useful review
  structure; its symbol `kappa` is a cryptographic security parameter, not this
  document's resource-advantage factor. No W1, physical-cost or production
  confirmation conclusion is imported.
- **S4:** Garay, Kiayias and Leonardos, [The Bitcoin Backbone Protocol with Chains
  of Variable Difficulty](https://eprint.iacr.org/2016/1048), CRYPTO 2017,
  revised 2019-08-25. Its dynamic-population analysis makes participation
  restrictions part of the theorem. The checked official abstract does not
  establish that the current development DAA meets those restrictions.
- **S5:** Garay, Lu, Prat, Testa and Zikas, [A Composability Treatment of Bitcoin's
  Transaction Ledger with Variable Difficulty](https://eprint.iacr.org/2024/1823),
  2024-11-07 preprint. The checked official abstract describes a composable
  dynamic-difficulty formulation under participation restrictions. Its stated
  contribution is not a composability proof for W1 or Hepta adoption.
- **S6:** Garay, Kiayias and Shen, [Fast Difficulty Adjustment in Proof-of-Work
  Consensus](https://www.iog.io/papers/fast-difficulty-adjustment-in-proof-of-work-consensus),
  official CRYPTO 2026 research page, August 2026. Its abstract describes
  parallel chains and approximate-agreement-based target recalculation. This
  is an architecture research candidate; the full-paper link was unavailable
  in this retrieval. It is not a drop-in justification for shortening the
  current DAA interval, nor a proved throughput gain for this code.

The mathematical derivations and finite countermodels above are local results
under their explicit premises. Primary sources motivate the required interfaces;
they do not replace verification of those premises against the actual protocol.
