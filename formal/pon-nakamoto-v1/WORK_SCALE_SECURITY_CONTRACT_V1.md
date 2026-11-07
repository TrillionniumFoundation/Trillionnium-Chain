# Fixed probability, mandatory work scale, and conditional chain security

Date: 2026-11-07, America/New_York. Starting integration source:
`3d1b6507671ec694ce58e86d4063a125c8deeb66` on the existing PR #688 lineage.
Status: **conditional research, HOLD**. This is a finite arithmetic component
and a set of mathematical interfaces. No native work profile, lottery, target,
chainwork, confirmation rule, activation flag, or deployment is changed.

Implementation: [exact arithmetic](work_scale_contract.py),
[adversarial tests](test_work_scale_contract.py),
[retained evidence](../../evidence/pon-work-scale-contract-20261107/README.md).
The [existing quantum DAA research](QUANTUM_DAA_RESEARCH.md) already contains
fixed-probability/linear-cost and square-root-cost schedules, complete and
restricted W1 oracles, literal marked-set censuses, and paid resource clocks.
Those are prior results, not discoveries of this continuation. The existing
[classical first-query bound](work_query_bound.py) is also retained unchanged.

## 1. The question and the result of this continuation

Can difficulty adjustment be replaced by a fixed ticket probability and a
variable number of mandatory work units, without allowing credited work to
outgrow the cheapest legal classical or quantum cost?

The answer is conditional. A uniform bound on complete accepted-work efficiency
would remove the specified scale amplification. Neither an implemented oracle
with linear cost nor a linear single-winner expectation proves that bound.
This continuation adds four things that the previous deterministic schedules
did not establish:

1. A common, exact parameter comparison for an experiment-wide fixed target,
   a common absolute target band, and fixed probability with variable units.
2. A multi-winner resource contract, with explicit counterexamples for reusable
   setup, misleading means, and large credited jumps.
3. A proved abstract exponential crossing lemma with hidden-inventory,
   propagation-margin and repeated-attack accounting; exact arithmetic and
   an independent finite adaptive-policy recursion check the examples.
4. Conditional reductions for common prefix, weighted chain growth and weighted
   chain quality that expose, rather than assume away, the missing native
   fork-accounting and quantum work-tail results.

The martingale argument is standard probability, not a claim of a new general
consensus theorem. The intended contribution is the explicit contract and its
refusal boundaries for this candidate.

## 2. A shared comparison model

Let a ticket have b bits, M=2^b, and inclusive target T. Use the native integer
convention rather than replacing it by a real approximation:

\[
p(T)=\frac{T+1}{M},\qquad D(T)=\frac{M}{T+1},\qquad
w(T,u)=u\lfloor D(T)\rfloor.
\]

The unit count u is a declared statement parameter. It is not a measured FLOP,
joule, hardware second, unique useful result, or currently deployed W1 field.
The factor floor(D)/D need not equal one. The existing first-query component
already handles that rounding issue. The exact comparison examples use
integer difficulties 16, 64 and 256, so rounding is exact there; the parameter
checker preserves inclusive-target semantics at other targets.

For one deliberately idealized reference strategy, define complete successful
search costs in a specified additive resource:

\[
K_C(D,u)=c_CuD,\qquad
K_Q(D,u)=a u^\alpha\sqrt D+b_Qu.
\tag{1}
\]

The last term is an optional nonreusable cost paid once for a complete winning
block, after search. It is not charged on each coherent oracle query. Failed
measured-candidate checks, preparation, reversible computation, uncomputation
and any other relevant phase must already be included in the coefficients or
separately bounded. Equation (1) is an assumed strategy-cost law, not an
optimal quantum-search theorem. Interrupted search, unknown marked counts,
parallel portfolios and availability may produce a different law.

| Candidate | Parameters shared across the comparison | Scale conclusion under (1), b_Q=0 | What it leaves open |
| --- | --- | --- | --- |
| Experiment-wide fixed target | T=T0 and u=1 on every competing fork for the full horizon | No target-driven scale amplification during that horizon | Base quantum advantage, changing resources, latency, future parameter transitions |
| Common absolute target band | D in [D_min,D_max], u=1; one externally fixed profile for all relevant forks | Quantum efficiency variation is at most sqrt(D_max/D_min), apart from rounding and coefficient variation | Anchor authenticity, availability of the band, resource thresholds, finite jump tails |
| Fixed probability, variable units | T=T0 and u in [u_min,u_max] | Quantum efficiency scales as u^(1-alpha); constant only for alpha=1 | Cheapest accepted-work cost, amortization, resource mix, maximum weight, latency |

The absolute-band statement assumes the oracle-cost coefficient a does not
change with the target or the legally chosen work subset. In the general case
the quantity to compare is w(D2)/K_Q(D2) divided by w(D1)/K_Q(D1). The square-root
formula is not valid after silently changing that coefficient.

For general target rounding write eta(D)=floor(D)/D. The band ratio under the
pure search model is eta(D2)/eta(D1) times sqrt(D2/D1), not exactly the latter.
For a whole band with eta_min>0 and eta_max<=1, an upper bound is
eta_max/eta_min times sqrt(D_max/D_min). A native easy target must not be treated
as asymptotically large difficulty to erase this factor.

### 2.1 A local clamp is not a common absolute band

If each fork is allowed D_next <= c D_parent, it can still reach c^n D0 after
n adjustments. Giving each fork its own moving anchor has the same defect.
Fixing target within each epoch is already standard periodic adjustment and
does not implement the first candidate.

The Scope checker requires one predeclared target interval and anchor identity
for every supplied context. It refuses changed anchors, out-of-band targets,
non-fixed targets under a fixed-target policy, and disallowed unit counts.
It checks finite configuration consistency only. A string called anchor_id
does not authenticate an anchor, prove that all forks were supplied, or prove
that future forks obey the profile. Those remain protocol obligations.

A common finite experiment can use immutable parameters. A continuing protocol
could use an immutable absolute range or a predeclared globally bounded rule.
If it instead relies on a checkpoint or an allegedly confirmed prefix, it must
state the added trust/finality premise or give a noncircular induction from
the already-proved prefix. A height-dependent schedule by itself does not
ensure a common absolute bound when competing forks have different heights.

### 2.2 A common weight cannot equalize different cost exponents

**Algebraic lemma.** Suppose both miner classes receive the same positive
credit w(u), with costs K_C(u)=a_C u^alpha_C and K_Q(u)=a_Q u^alpha_Q. At fixed
resource rates H and Q in the specified resource model,

\[
\frac{Qw(u)/K_Q(u)}{Hw(u)/K_C(u)}
=\frac QH\frac{a_C}{a_Q}u^{\alpha_C-\alpha_Q}.
\tag{2}
\]

Proof: cancel the common positive w(u). In particular, replacing linear weight
by u^alpha_Q does not remove a classical/quantum exponent mismatch at a common
u. It can change one class's incentives between different work sizes, while
altering those of the other class. This is not a proposal to change chainwork.

For (1) without its tail, the same-u quantum/classical rate ratio is
(Q/H)(c_C/a)u^(1-alpha)/sqrt(p0). Resource participation H and Q must therefore
be recorded along with u. A changing H must not be hidden by reporting only
the u exponent. A cross-fork comparison must separately specify u_H, u_A and
the feasibility/cost of reaching those parameters.

### 2.3 A mandatory linear accepted-block tail can cap amplification

At fixed p0 absorb sqrt(D0) into A. If the COMPLETE winning cost is

\[
K_Q(u)=A u^\alpha+b_Qu,\quad A>0,\quad b_Q>0,\quad0<\alpha<1,
\]

then, relative to u=1, linear-credit efficiency grows by

\[
F(u)=\frac{A+b_Q}{A u^{\alpha-1}+b_Q}
\le\frac{A+b_Q}{b_Q}.
\tag{3}
\]

Thus a sublinear oracle component does not automatically imply unbounded
amplification of complete accepted work. For A=1, b_Q=1/16, alpha=1/2 and u=256,
F=17/2=8.5, whereas the zero-tail example gives 16. The limiting bound is 17.
These are assumed-cost arithmetic, not measured W1 costs. A long output gives
a bandwidth/time lower bound only under an explicit bandwidth model; it does
not prove u independent expensive matrix evaluations.

## 3. The resource contract must cover many winners and their history

Let R_A be an explicitly specified resource vector or additive resource
account. It must include setup, failed attempts, reversible search, measured
checks, winning proof construction and the work necessary for an accepted and
available block. Define, for fresh challenge context and prior state sigma,

\[
\Psi_Q(B,x\mid\sigma)
=\sup_{\mathcal A\in\mathcal S_Q}
\Pr[W_{\rm new,valid}\ge x\ \land\ R_{\mathcal A}\preceq B\mid\sigma].
\tag{4}
\]

Here S_Q is the complete permitted strategy class, including legal subsets,
all relevant forks, adaptive stopping/restarts, task selection, parallel-width
choices, preprocessing, retained coherent states and shared calculations.
Counting only the branch eventually published omits attack expenditures and
alternative successful work. Counting newly released blocks as newly computed
work is also invalid.

A useful theorem must upper-bound (4) uniformly over the allowed states and
strategies, with explicit cryptographic failure terms. A proposed form is a
work-tail envelope Phi_Q(B,x), rather than a single measured mean. This text
does NOT prove such an envelope for W1. Analogous honest progress guarantees
must use legal optimized implementations, rather than an artificially slow
reference miner.

### 3.1 Single-winner linear cost does not imply amortized linear cost

**Countermodel.** Suppose the legal cost of k distinct winners at size u is

\[
K_Q(k,u)=u+k-1.
\]

The first winner costs exactly u, so every isolated k=1 measurement has linear
scaling. If each winner receives credit u, total efficiency relative to u=1 is

\[
F(k,u)=\frac{ku}{u+k-1}.
\tag{5}
\]

For k=1 this equals 1. For k=u=256 it is 65536/511, approximately 128.25. This
is a logical reusable-setup counterexample, not an implemented legal W1 attack.
It shows why the hypothesis must concern multi-winner cost, not only one
complete oracle invocation or one block. A strong batch proof can lower proof
cost without lowering every search cost; those components must be separated.

### 3.2 Paid work remains available after the measurement window changes

An adversary may pay before a window starts and publish a stock of blocks with
almost no new CPU during that window. A coherent state near a useful
measurement also carries previously paid progress. A per-window bound that
resets either account to zero is false even if its all-time cost accounting is
correct.

Either count resources from challenge generation, carry a justified inventory
or potential into the next window, or prove a protocol-forced reset. The bound
on hidden inventory must cover every resource-to-credit conversion it uses;
a number of private classical blocks does not bound an arbitrary residual
quantum state without a reduction.

### 3.3 Total operations, depth and physical time are distinct

Executing u independent units in parallel can preserve linear total gate count
while reducing elapsed time by paying for more width and memory. Report logical
queries, gate count, sequential depth, parallel width, qubits, error correction,
classical processing, bandwidth and acceptance latency separately. No generic
operation turns a query lower bound into a physical-second lower bound.

The serialized statement and all-unit correctness proof must bind parent,
profile, reward destination, nonce, unit count and ordered input commitments.
The previous research already states those requirements. Their cryptographic
enforcement proves relation correctness; it does not itself prove a cheapest
work lower bound. Fake output-root grinding, proof randomness, encodings,
duplicate credit and selection of low-cost legal tasks remain inside the
adversary definition until separately excluded.

## 4. A complete abstract crossing lemma

Let F_i contain the classical history used by the analysis and whatever
accounting of residual state makes the following assertion valid for every
reachable adversarial state. Let A_i be new adversarial available credit and
U_i a protocol-justified honest barrier. Put X_i=A_i-U_i. U_i is NOT automatically
the sum of all honest blocks: honest forks and delayed blocks can be wasted.

**Conditional-moment premise.** There is z>1 such that, for every i and every
allowed strategy,

\[
\mathbb E[z^{X_i}\mid\mathcal F_{i-1}]\le1.
\tag{6}
\]

**Lemma.** If the true initial deficit is d>0, then

\[
\Pr[\exists n\ge1:\sum_{i=1}^n X_i\ge d]\le z^{-d}.
\tag{7}
\]

**Proof.** M_n=z^(sum_{i=1}^n X_i) is nonnegative, M_0=1, and (6) makes it a
supermartingale by conditional expectation. Stop at the first M_n>=z^d or at
a finite deterministic N. The bounded stopping theorem yields expectation
at most 1; hence the probability of crossing before N is at most z^(-d).
Let N increase and use monotone convergence of the crossing events. No
independence, identical distribution or Poisson assumption was used. The
uniform conditional premise, however, has not been proved for W1. QED.

The finite implementation uses exact rational z and finite distributions of
integer X. It checks sum_x P(X=x) z^x<=1 for every law in a supplied menu.
Any history-dependent selection or convex mixture of those laws then satisfies
(6). This proves a fact about the stated menu, not that every legal quantum
strategy belongs to it. The independent dynamic-programming routine maximizes
finite-horizon crossing probability over adaptive menu choices and checks the
bound without assuming a particular fixed schedule.

### 4.1 Initial inventory, network margin, and many attack starts

Let K be an observed credit gap, B0 a valid upper bound on hidden inventory and
L_Delta a justified margin for propagation, validation and in-flight work.
Use d=K-B0-L_Delta. If d<=0 the interface returns 1. If there are at most J
relevant attack starts and the moment and mapping premises hold from each
start, then a union bound gives

\[
\Pr[\text{some modeled crossing}]
\le \min\{1,\epsilon_{\rm bad}+Jz^{-(K-B_0-L_\Delta)}\}.
\tag{8}
\]

The bad-event term bounds the UNION of premise failures over the entire claimed
execution and all J starts, including failed inventory bounds, cryptographic
soundness or reduction errors. If only per-start error bounds are available,
they must be combined before adding this term. Equation (6) must hold for the
dominating process, or for a justified stopped/coupled process before the first
premise failure. Conditioning on an eventual good event alone need not preserve
the moment bound. J may be
one only if the process dominates all relevant choices or only one start is
being claimed. An unlimited execution cannot inherit a finite J without an
anytime construction or a summable error allocation. Inventory bounds must
include withheld ancestors, not only blocks seen by the observer.

Equation (8) becomes a *confirmation-risk* bound only after proving that every
relevant confirmation failure entails the modeled crossing. The module does
not implement that missing native reduction and labels all examples abstract.

### 4.2 Negative means do not determine the tail

Consider these mutually exclusive per-step events:

| Law | Adversarial jump | Honest barrier jump | Idle probability | E[X] |
| --- | --- | --- | --- | --- |
| Unit jumps | +1 with probability 2/5 | -1 with probability 3/5 | 0 | -1/5 |
| Eight-unit burst | +8 with probability 1/20 | -1 with probability 3/5 | 7/20 | -1/5 |

Both have adversarial expected work 2/5 and honest expected work 3/5. For unit
jumps, z=3/2 satisfies E[z^X]=1 and the exact eventual hitting probability from
integer deficit K is (2/3)^K. For the burst law, the same z has moment greater
than one and is rejected. At K=8 its first step alone crosses with probability
1/20, greater than (2/3)^8=256/6561. Therefore the unit-jump risk formula cannot
be transferred using only the same average work rates.

The smaller rational z=17/16 is valid for both laws and the included idle law.
For the *assumed menu*, the exact minimum integer deficit making the chosen
bound at most 10^-6 is 35 for z=3/2 and 228 for z=17/16. These are sufficient
weighted gaps for two different chosen envelopes, not optimal confirmations,
seconds, or a prescription for PoN. With inventory 5 and network margin 3 the
first gap becomes 43; with J=100 attack starts and no margins it becomes 46.

**Another countermodel.** At the start choose an unobserved fixed mode. With
probability 1/10 adversarial rate is 2h for the entire attack; otherwise it is
h/4. Honest rate is h. Unconditional adversarial mean rate is 0.425h, but every
finite deficit is eventually overcome in the first mode. The failure floor is
at least 1/10 despite an apparently favorable average. This is not a W1 attack;
it demonstrates the need for a conditional, strategy-uniform contract.

### 4.3 A bounded-increment sufficient condition

Suppose -h_max<=X_i<=a_max and E[X_i|F_{i-1}]<=-delta<0 uniformly. Let
L=a_max+h_max. Conditional Hoeffding gives

\[
\mathbb E[e^{\theta X_i}\mid\mathcal F_{i-1}]
\le\exp(-\theta\delta+\theta^2L^2/8).
\]

Taking theta=4 delta/L^2 and psi=2 delta^2/L^2 makes the right side e^(-psi)<1.
For every fixed interval of m steps,

\[
\Pr[\sum X_i\ge-b]\le e^{\theta b-\psi m}.
\tag{9}
\]

Proof: iterate conditional expectation, obtaining E[e^(theta sum X)]<=e^(-psi m),
then apply Markov. The bounded-increment condition concerns total credit per
analysis step, not merely one block. A per-block u_max does not prevent many
blocks or a stock of previously completed work from appearing in one step.

## 5. The exact remaining bridge to CP, CG and CQ

### 5.1 Common prefix requires a native fork witness

The required deterministic reduction is:

> Every violation removing at least K weighted credit from a relevant honest
> prefix entails an interval I of at least m(K) steps on which
> A(I)-U(I)>=-beta_Delta, except on an explicitly bounded bad event.

The reduction must match the native heaviest-valid-chain rule, unit differences
between branches, ties, withholding, multi-parent work portfolios, eligibility,
proof/data availability, and timestamp validation. It must specify a useful
bound m(K); a maximum single block weight alone is insufficient when arbitrarily
many blocks can arrive within a step. Mere public-chain growth is not U(I).

The witness must use the same globally defined adapted process, or a proved
simultaneous domination of all relevant forks. Separate per-fork bounds require
additional selection/union accounting; T counts time starts, not arbitrary forks.
If that reduction and (9) are established, a finite execution of T steps obeys

\[
\Pr[\mathrm{CP}_K\text{ fails}]
\le \min\left\{1,
\frac{T e^{\theta\beta_\Delta-\psi m(K)}}{1-e^{-\psi}}
+\epsilon_{\rm bad}\right\}.
\tag{10}
\]

Proof: for each of at most T starts, sum (9) over all m>=m(K), a geometric
series. Then union-bound starts and the declared bad event. This is a valid
conditional reduction, not a proof of its native witness premise.

### 5.2 Weighted chain growth

Suppose native accounting proves that chain weight at an endpoint increases
by at least sum G_i-beta_G over an n-step interval, and 0<=G_i<=g_max with
conditional mean at least g. Then for epsilon>0,

\[
\Pr[W(C_{s+n})-W(C_s)<(g-\epsilon)n-\beta_G]
\le\exp(-2\epsilon^2n/g_{\max}^2).
\tag{11}
\]

This follows from the conditional bounded-difference inequality for a fixed
interval (or a valid stopping-time start with fixed length under the same
uniform premises). Simultaneous claims over all windows need an additional
union bound or anytime argument. It is a weight-growth statement. A heavier
adopted chain can have fewer blocks, so
block-count growth requires an additional stable-prefix/count reduction.
Time n must be measured by the analysis clock, not miner-chosen timestamps.

### 5.3 Weighted chain quality and count quality are different

For a stable segment, suppose a protocol reduction supplies
A_segment<=A(I)+beta_A and W_segment>=G(I)-beta_G. If uniform tail bounds over
the relevant interval family yield A(I)<=(a+epsilon_A)n and
G(I)>=(g-epsilon_G)n, the honest WEIGHT fraction is at least

\[
\mu_W\ge1-
\frac{(a+\epsilon_A)n+\beta_A}{(g-\epsilon_G)n-\beta_G},
\tag{12}
\]

provided the denominator is positive and the resulting lower bound is positive.
The two tail failures and interval-selection failures must be union-bounded.
With w in [w_min,w_max], an honest weight fraction mu_W guarantees only

\[
\mu_{\rm count}\ge
\frac{\mu_W w_{\min}}
{\mu_W w_{\min}+(1-\mu_W)w_{\max}}.
\tag{13}
\]

Proof: honest block count is at least honest weight/w_max, while adversarial
count is at most adversarial weight/w_min; substitute these extreme counts.
A large u_max/u_min can therefore weaken count-quality guarantees even when
weighted quality is acceptable. Neither property is implied by small observed
reorganization counts in a finite simulation.

## 6. Research evidence and literature boundaries

The following sources were inspected on 2026-11-07. Their results are not
interchangeable with the conditional arithmetic in this component.

| Primary source | What it supplies | What it does not supply here |
| --- | --- | --- |
| [Cojocaru et al., Quantum 7:944, 2023](https://quantum-journal.org/papers/q-2023-03-09-944/pdf/) | Quantum multi-solution Bernoulli/chain-of-PoW query tails and fixed-difficulty backbone analysis | Minimum W1 gate cost or a variable-u weighted tail |
| [Bailey and Sattath, 2403.08023v2](https://arxiv.org/html/2403.08023v2) | Difficulty-increase attack and the mismatch between linear credit and square-root quantum search | A deployed W1 attack or a proof for this counterfactual policy |
| [Park and Spooner, FC 2023](https://fc23.ifca.ai/preproceedings/162.pdf) | Superlinearity result for a stated class of smooth/proportional PoW reward functions | A theorem ruling out every mandatory-work construction regardless of its hypotheses |
| [Beame, Kornerup and Whitmeyer, 2609.26678v2](https://arxiv.org/html/2609.26678v2) | Selective and list-decoding quantum direct-product tools | A reduction from correlated, structured W1 instances to those query problems |
| [Blocki and Holman, QCrypt 2026 accepted-poster abstract](https://qcrypt.net/2026/technical/accepted-papers/) | Motivation for adaptive parallel-query schedules beyond some earlier restricted models | A full inspected W1 theorem; only the official abstract is relied upon |
| [Garay, Kiayias and Shen, CRYPTO 2026](https://www.iog.io/papers/fast-difficulty-adjustment-in-proof-of-work-consensus) | Parallel-chain/approximate-agreement approach to fast target adjustment | Automatic security against mixed classical/quantum strategies |

For orientation, Theorem 4.3 of Cojocaru et al. gives the following useful
form of a bound for the paper's fixed-density Chain-of-PoWs query model:

\[
\Pr[\text{at least k chain PoWs with N quantum queries}]
\le\min\{1,[e^2p(N/k+1)^2]^k\}.
\tag{14}
\]

p denotes the success density in that paper's oracle convention; native
inclusive-target conversion must use p=(T+1)/M. Equation (14) is a genuine
multi-solution query-tail template. Substituting a constructive W1 oracle gate
count for a required minimum query cost would reverse the direction of the
needed bound. A weighted variable-u extension remains to be established.

The 2026 selective direct-product preprint explicitly distinguishes ordinary
direct products from adaptively selecting easy instances. Its relevant warning
is methodological: a worst-case lower bound times u does not establish a
selective average-case bound for a miner. The preprint status is retained; its
abstract says submitted to QIP 2027, not accepted there.

The FC 2023 impossibility uses specific smooth-reward hypotheses. A genuine
mandatory preparation delay at a fixed physical time unit might violate a
hypothesis, so the theorem must not be quoted as a universal exclusion of this
candidate. Conversely, being outside that hypothesis does not establish
security, and coherent search over each fixed-u attempt can still have a
quantum advantage. No beacon or alternative consensus authority is introduced.

## 7. Executable scope and reproduction

The component uses Python's standard library and exact Fraction arithmetic.
Irrational square-root examples are refused instead of rounded into a false
certificate. This is a finite implementation restriction, not a restriction of
the symbolic statements. Model coefficients are assumptions; physical qubits,
quantum seconds and minimum accepted-block cost remain null in the report.

From the repository root:

```bash
bash scripts/project-preflight.sh
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_work_scale_contract.py' -v
python3 formal/pon-nakamoto-v1/work_scale_contract.py --out /tmp/pon-work-scale-new.json
python3 formal/pon-nakamoto-v1/work_scale_contract.py --verify /tmp/pon-work-scale-new.json
python3 formal/pon-nakamoto-v1/work_scale_contract.py --verify evidence/pon-work-scale-contract-20261107/results.json
```

The output path must be new. Verification recomputes the complete result and
listed source-file hashes, refuses duplicate JSON keys and preserves JSON type
distinctions such as false versus 0. It cannot independently attest hardware
cost or infer the truth of an input probability law. The CI entry runs the new
tests alongside the existing research tests; its source pin must be updated
without weakening the existing guard.

All claim flags remain false, including minimum W1 cost, native fork accounting,
W1 conditional-law coverage, common prefix, chain growth, chain quality,
production activation and release readiness. Passing tests certifies the finite
arithmetic and refusal behavior on the checked source only.

## 8. The two next scientific gates

**Gate A: complete accepted-work tail.** Establish a classical/quantum
resource-to-weight envelope for the actual mandatory-unit relation, with
adaptive legal strategies, selection, preprocessing and residual states. A
single cheaper legal construction can refute a proposed lower bound; failure
to find such a construction in a finite strategy suite cannot prove the bound.

**Gate B: native weighted fork witness.** Prove the mapping from every relevant
native confirmation/common-prefix failure to the tail event, with timestamps,
delay, data availability, maximum weights and private inventories explicitly
handled. The current native rule's six descendants and weight-depth check are
not replaced or retroactively certified by the numbers 35, 43, 46 or 228.

Engineering feasibility must accompany both gates: u caps, validation and
proof delays, task supply, bounded participation changes and stalls at the caps.
Until both scientific gates and those operational contracts close, this
continuation remains a research candidate and the integration remains HOLD.
