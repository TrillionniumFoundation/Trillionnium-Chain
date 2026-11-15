# Cost-prefix tails: conditional transfer to expected resource

Date: 2026-11-09. Status: **research arithmetic; HOLD_NO_GO**.

This continuation strengthens the single-cut conversion in Section 5 of
[the fixed-success query frontier](FIXED_SUCCESS_QUERY_FRONTIER_V1.md).
It combines all certified resource-prefix bounds by summing their tail
implications. It also keeps the initial-state probability loss and the
resource-simulation overhead in their correct places.

Implementation: [cost_tail_transfer.py](cost_tail_transfer.py).
Controls: [test_cost_tail_transfer.py](test_cost_tail_transfer.py).
An arithmetic certificate checks the supplied numbers and their combination;
it does not establish the simulation or initial-state premises for W1.
All sixteen actual classical/quantum rows in the
[fixed-probability contract](fixed_probability_contract_v1.json) retain
`lower=null`, `upper=null`, and `status=unproved`. Native admission, credit and
production activation are unchanged.

## 1. Fix one complete experiment and a legal truncation

Fix the accepted success event `E` by the original deadline, the data that may
be used, the initial joint-state family, the allowed algorithm class, and one
nonnegative scalar resource `C`. The cost account includes failed, cancelled,
abandoned and unpublished attempts. Any initial work, old inventory, public
help, proof handling, transport and recovery must either be counted in this
same account or covered explicitly by its initial-state and simulation
premises. A weighted resource price requires specified units and nonnegative
prices; a query count does not itself specify physical time or memory cost.

For every allowed strategy `A` and every resource cap `t`, assume there is a
legal truncation `A[t]` which respects that cap and the original deadline.
It must preserve the law and success outcome of every completed history of
`A` with `C_A <= t`. Abort is permitted on the other histories. In particular,

\[
\Pr[E_A\cap\{C_A\le t\}]\le\Pr[E_{A[t]}].                 \tag{1}
\]

The truncation must not restart with a fresh state, forget earlier resources,
change data eligibility, or read a future completion to choose whether to
abort. Monitoring and abort overhead must fit its stated budget, or enter an
explicit simulation overhead. The same premise must hold under any reference
initial state to which a reference query theorem is applied.

A classically observed cumulative counter with a legal abort before the next
charged action is one sufficient setting. The premise is not automatic for a
coherent variable-runtime or branch-weighted quantum resource definition.
Retained quantum registers are permitted only when the stated legal,
history-preserving truncation has actually been established.

## 2. Tail transfer theorem

Suppose `H(t)` is a proved upper bound on the success of the capped strategy
in the same experiment, uniformly over all strategies and initial states
required by the proposed cost envelope. If `Pr[E_A] >= alpha`, then (1) gives

\[
\begin{aligned}
\alpha
 &\le\Pr[E_{A[t]}]+\Pr[C_A>t]\\
 &\le H(t)+\Pr[C_A>t],
\end{aligned}
\qquad
\Pr[C_A>t]\ge(\alpha-H(t))_+.                             \tag{2}
\]

Consequently, for a nonnegative real-valued resource, Tonelli's identity gives

\[
\boxed{\mathbb E[C_A]\ge
 \int_0^\infty(\alpha-H(t))_+\,dt.}                       \tag{3}
\]

For a nonnegative **integer-valued** resource the exact tail-sum identity
instead gives

\[
\boxed{\mathbb E[C_A]\ge
 \sum_{j=0}^\infty(\alpha-H(j))_+.}                        \tag{4}
\]

The inequalities include infinite expectations. They never condition the
cost on success. The term at `j=0` belongs in (4), including when a model
allows free outputs or initial inventory to produce success at zero new cost.
Real-valued and integer-valued resources use different identities; one cannot
substitute a sum for an integral merely by naming a physical resource unit.

If `H` is nondecreasing, its positive gap is nonincreasing. Thus (4) dominates
every single-cut bound

\[
\sum_{j=0}^{\infty}(\alpha-H(j))_+
 \ge (q+1)(\alpha-H(q))_+,
 \qquad q\in\mathbb Z_{\ge0}.                            \tag{5}
\]

Likewise (3) dominates `t (alpha-H(t))_+` for each continuous cap `t`.
These are lower-bound implications. They do not assert that an algorithm
attains either expression or that the resulting cost envelope is tight.

## 3. A finite prefix and monotone strengthening

A finite certificate at integer caps `0,...,T` already yields a valid partial
sum. Missing later bounds may conservatively be taken as one, contributing
zero. No infinite-series or eventual-saturation claim is needed to certify
that finite lower bound.

When every row bounds the same experiment and allowed class, a strategy
capped at `j` is also capped at any `s >= j`. Therefore define

\[
H_{\rm eff}(j)=\min_{j\le s\le T}H(s),\qquad
L_T=\sum_{j=0}^{T}(\alpha-H_{\rm eff}(j))_+.              \tag{6}
\]

Then `H_eff` is nondecreasing, is a valid bound at each cap in the prefix,
and can only improve its direct partial sum. The proof is simply set
inclusion of the capped strategy classes. Suffix minima cannot combine rows
from different success events, deadlines, data laws, initial-state coverage,
algorithm classes or resource definitions. A common scope label does not
prove that those scientific premises hold.

For a fully proved infinite family the corresponding strengthening is
`inf_{s >= t} H(s)`; a minimum need not exist. The calculator deliberately
accepts only nondecreasing declared reference-cap tables and checks their
finite prefixes; it does not implement suffix minima
for arbitrary supplied grids. The strengthening in (6) is optional mathematical
preprocessing. The calculator checks rational arithmetic and its exact numeric
inputs, not the authenticity, common scientific scope or completeness of the
underlying model.

## 4. Direct resource-prefix simulation and initial-state domination

A useful sufficient way to obtain `H` fixes the simulation direction before
transferring any cost. For every legal real strategy `A` and cap `t`, suppose
its legal truncated execution admits an ideal strategy `B[A,t]` with:

1. the same success event and original deadline, or a justified relaxation;
2. at most `q(t) = floor(a t + b)` ideal queries on **every** path, for fixed
   `a >= 0` and `b >= 0`;
3. real truncated success at most its ideal actual-state success plus a
   proved loss `eta(t)`.

The ideal cap must also hold on the reference-state paths used below.
An expected-query simulation bound is insufficient for this hard-cap step.
The floor is justified only because the simulated query count is integer and
is pathwise bounded above by `a t+b`. It is not a rounding rule for measured
physical cost. The factor `a` has the required query-per-resource units.
Zero rate is a permitted degenerate case when the stated simulation really has a
resource-independent query cap.

Suppose a reference theorem bounds **every** admissible ideal capped
strategy's success by `B_ref(q)`. Suppose, additionally, the complete actual
joint initial state obeys the
[FJS1 domination premise](FINITE_JOINT_STATE_CERTIFICATE_V1.md), with the
same oracle-independent reference state and positive excess:

\[
\rho\preceq\lambda\omega+\Delta,\quad
\lambda\ge1,\quad\Delta\succeq0,\quad
\operatorname{Tr}\Delta\le\epsilon.                       \tag{7}
\]

All later correlated help must be included in the declared joint evolution
or arise through counted interactions. For the same capped strategy, positive
linearity and the final success effect give

\[
\Pr_\rho[E_{B[A,t]}]
 \le\lambda B_{\rm ref}(q(t))+\epsilon.
\]

Together with the simulation premise this proves the usable cap curve

\[
\boxed{H(t)=\min\{1,\lambda B_{\rm ref}(\lfloor a t+b\rfloor)
                          +\epsilon+\eta(t)\}.}           \tag{8}
\]

Here `eta` is explicitly a loss **after** the domination comparison in the
stated inequality. An error introduced inside a reference bound can instead
be multiplied by `lambda`; the order of a different reduction must be proved,
not inferred from (8). FJS1's recomputed positive excess may be used in place
of the larger declared allowance.

The extra `b` queries may include final virtual output checks or extraction
work. They stay inside the reference query cap. They do not become producer
resource, and they are not subtracted from the tail-sum as a producer bill.
Neither (7) nor a reference query bound alone proves `a`, `b`, `eta`, legal
truncation, actual hidden-state coverage, or an actual W1 physical-cost law.
In particular (8) does not replace `q` by an expected query count in a
quadratic quantum hard-cap probability bound.

## 5. Worked probability-loss transfer

Consider an ideal classical independent-Bernoulli table with mark probability
`p=1/16`, at least eleven available addresses, no unchecked final outputs,
and success target `alpha=1/2`. Its reference hard-cap success bound is
`B_ref(q)=1-(15/16)^q` until the available domain is exhausted. Take the
conditional parameters `a=1`, `b=0`, `lambda=2`, `epsilon=eta=0`.
Then (8) gives the following prefix:

| Integer cap `q` | `H(q)` | `(1/2-H(q))_+` |
| --- | --- | --- |
| 0 | `0` | `1/2` |
| 1 | `1/8` | `3/8` |
| 2 | `31/128` | `33/128` |
| 3 | `721/2048` | `303/2048` |
| 4 | `14911/32768` | `1473/32768` |
| 5 | `289201/524288` | `0` |

The finite prefix alone proves

\[
\mathbb E[C]\ge
 \frac12+\frac38+\frac{33}{128}+\frac{303}{2048}
          +\frac{1473}{32768}
 =\frac{43441}{32768}\approx1.325714.                       \tag{9}
\]

For this complete nondecreasing capped curve, every later gap is zero, so its
full tail-sum has the same value. The largest single-cut bound is `99/128`, at
`q=2`; combining the cuts is stronger. Equation (9) is a conditional transfer
bound, not the exact optimum for the correlated-state strategy class and not
an actual W1 cost point.

## 6. Why probability domination does not transfer an expected frontier

An exact finite counterexample prevents an incorrect shortcut. Let there be
eleven independent Bernoulli-`1/16` addresses. The actual advice is one bit
`S` indicating whether the table contains at least one mark. Use an independent
uniform advice bit as the reference. For every table `f`, the actual
conditional advice density matrix is the basis-state projector onto `S(f)`,
whereas the reference matrix is `I/2`. Thus `rho_f <= 2 (I/2)` holds for every
table: (7) has `lambda=2` and zero excess.

The actual strategy aborts without a query when `S=0`. When `S=1`, it queries
addresses in order until the first mark or exhaustion of all eleven, and
outputs a checked winner if one was found.
The complete query cap is eleven in both actual and reference experiments.
Its actual success and unconditional expected paid queries are

\[
\begin{aligned}
\Pr_\rho[E]&=1-(15/16)^{11}
 =\frac{8942430185041}{17592186044416}>\frac12,\\
\mathbb E_\rho[Q]
 &=\sum_{j=1}^{11}j\frac1{16}(15/16)^{j-1}
 =\frac{47931568507531}{17592186044416}
 \approx2.724594.
\end{aligned}                                             \tag{10}
\]

Blindly applying the independent-state exact frontier to `alpha/lambda=1/4`
would claim `E_rho[Q] >= (1/4)/(1/16)=4`, contradicting (10).
The invalid step equates costs under different initial laws. Domination
bounds actual success by twice reference success. It does not bound the
reference expected cost by the actual expected cost. The reference strategy
sometimes runs on an all-unmarked table, while the correlated advice avoids
that work in the actual experiment.

The tail transfer (2)--(8) uses only probability bounds for real resource
prefixes and avoids that false expectation comparison. The counterexample
is a finite mathematical advice model, not an implemented W1 shortcut.
A one-bit memory limit therefore cannot replace a theorem about the content
and correlation of the allowed initial state.

## 7. Reproduction and remaining gate

Run from the repository root:

```bash
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_cost_tail_transfer.py' -v
python3 formal/pon-nakamoto-v1/cost_tail_transfer.py --check
```

The full W1/MU1 research gate remains a coverage and resource theorem for
**all** legal algorithms, uniformly over the admitted initial histories and
help. It must preserve legal caching, shared and low-rank work, batching,
preprocessing, failed and unpublished work, competing branches, proof costs,
propagation, verification and recovery under the same success and deadline
contract. Finite strategy enumeration, correct-execution proofs, source pins
and native measurements do not establish that universal simulation.

The new certificate supplies a checked conditional lower-bound calculation.
It cannot promote any actual cost row or authorize production. Qualification
remains **HOLD_NO_GO**.
