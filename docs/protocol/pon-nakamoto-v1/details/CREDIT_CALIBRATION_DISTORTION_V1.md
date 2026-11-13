# Scalar credit: exact calibration and minimax distortion

Status: **conditional algebra for stipulated cost functions; native consensus
qualification remains HOLD_NO_GO**.

This note quantifies a scoring limitation. It is not a physical cost certificate
for W1, a protocol recommendation, or a common-prefix, growth or quality proof.

## 1. Cost model and definition

Fix a nonempty difficulty set containing its distinct positive minimum and
maximum, `d0 < d1`, and put `R = d1/d0`. The set may be discrete. Stipulate the
ideal classical and constant-success quantum cost surrogates

\[
 C_C(D)=c_C D,\qquad C_Q(D)=c_Q\sqrt D,
 \qquad c_C,c_Q>0.
\]

The constants are fixed across difficulties. They may encode different costs
per query or fixed success-probability conventions. These assumptions do not
make the functions exact descriptions of physical hardware. A change in oracle
implementation, preprocessing, setup, restart behavior, success probability,
proof construction or transport can invalidate this cost model.

For any positive scalar score `s`, define calibration distortion by the ratio
between its largest and smallest score per unit cost:

\[
 \kappa_X(s)=
 \frac{\sup_D s(D)/C_X(D)}{\inf_D s(D)/C_X(D)},
 \qquad X\in\{C,Q\}.
\]

If the score-per-cost ratio is unbounded above or has infimum zero, its
distortion is infinity. Otherwise the distortion is at least one. Positive
constant rescaling of either cost function or of the score does not change
distortion. Exact calibration means distortion one. Scores here are arbitrary
positive real functions of difficulty alone, without integer or protocol
constraints.

## 2. Exact minimax value

**Proposition.** Every positive scalar score satisfies

\[
 \max\{\kappa_C(s),\kappa_Q(s)\}\ge R^{1/4}.
\]

The mathematical witness `s(D)=D^(3/4)`, up to a positive constant, attains
equality. Consequently

\[
 \inf_{s>0}\max\{\kappa_C(s),\kappa_Q(s)\}=R^{1/4}.
\]

This witness is not a proposal to replace native credit.

**Proof.** Set `a=s(d1)/s(d0)`. The endpoint ratios of classical and quantum
score per cost are respectively `a/R` and `a/sqrt(R)`. Their logarithms differ
by `(log R)/2`. At least one logarithm therefore has absolute value at least
`(log R)/4`. For any positive function, its supremum-to-infimum ratio is at
least an endpoint ratio and its reciprocal. Thus at least one distortion is
at least `R^(1/4)`.

For the witness, classical score per cost is proportional to `D^(-1/4)` and
quantum score per cost to `D^(1/4)`. Both distortions equal `R^(1/4)`. This
proves the optimum. No differentiability or power-law assumption is made about
the competing score. The proof works on any difficulty set retaining the two
endpoints. QED.

Exact simultaneous proportionality to `D` and `sqrt(D)` is therefore impossible
on any such set with `R>1`. The statement concerns these two specified cost
functions, not every possible hybrid consensus architecture.

## 3. Exact geometric control

Take `D_j=16^j` for `j=0,...,m`, with integer `m>=1`. Then `R=16^m` and the
witness scores are the integers `s_j=8^j`. After removing fixed positive cost
constants, the classical and quantum score-per-cost ratios are `2^(-j)` and
`2^j`. Both distortions equal `2^m=R^(1/4)`.

Linear credit instead has quantum distortion `4^m`; square-root credit has
classical distortion `4^m`. These are exact arithmetic controls of stipulated
cost functions, not mining experiments. Increasing the ideal difficulty ratio
from `R` to `K R`, for `K>=1`, increases the optimal distortion by `K^(1/4)`.

## 4. General positive costs and varying coefficients

For any two specified positive cost functions `C_1,C_2` on the same set, suppose
their ratio has finite positive infimum and finite supremum. Put

\[
 K=\frac{\sup_D C_1(D)/C_2(D)}{\inf_D C_1(D)/C_2(D)}.
\]

Then the exact optimum over positive real scores is

\[
 \inf_{s>0}\max\{\kappa_1(s),\kappa_2(s)\}=\sqrt K.
\]

To see the lower bound, let `osc(g)=sup(g)-inf(g)`. The identity

\[
 \log(C_1/C_2)=\log(s/C_2)-\log(s/C_1)
\]

and subadditivity of oscillation give

\[
 \log K\le \log\kappa_1(s)+\log\kappa_2(s).
\]

At least one distortion is at least `sqrt(K)`. The witness
`s=sqrt(C_1 C_2)` attains this value: its two score-per-cost functions are
reciprocals, each with distortion `sqrt(K)`. Supremum or infimum attainment is
not required. This identity does not identify the actual W1 cost functions.

Suppose more specifically that

\[
 C_C(D)=a_C(D)D,\qquad C_Q(D)=a_Q(D)\sqrt D,
\]

where the positive coefficient functions have known finite variation factors

\[
 V_C=\frac{\sup a_C}{\inf a_C},\qquad
 V_Q=\frac{\sup a_Q}{\inf a_Q}.
\]

Endpoint comparison gives

\[
 \frac{C_C(d_1)/C_Q(d_1)}{C_C(d_0)/C_Q(d_0)}
 \ge \frac{\sqrt R}{V_C V_Q}.
\]

Applying the general result, and the universal lower bound of one on
distortion, yields

\[
 \max\{\kappa_C(s),\kappa_Q(s)\}\ge
 \max\{1,R^{1/4}/\sqrt{V_C V_Q}\}.
\]

Without coefficient-variation bounds, the ideal `R^(1/4)` result does not
establish a physical calibration bound. Additive setup, proof or communication
costs must be included in the specified cost functions rather than absorbed
without justification into difficulty-independent constants.

## 5. Inclusive target and native integer credit

Under the additional uniform-256-bit-ticket premise, inclusive target `T` has
success probability `p(T)=(T+1)/2^256`. Its ideal mean-query difficulty is

\[
 D(T)=\frac{2^{256}}{T+1}.
\]

The native contribution is `W(T)=floor(D(T))`, subject to separate nonzero-target
and target-limit rules. `D` in the proposition is the ideal real quantity, not
native integer `W`. On a permitted target set, `R` must be computed from exact
`D(T)` endpoints. Replacing `D` by `W` may merge different difficulties,
especially near the easiest targets.

Integer-root scores introduce additional rounding and ties and do not inherit
the witness's exact equality without a separate argument. The geometric control
in section 3 illustrates ideal cost functions; it does not assert that every
listed difficulty has an allowed native target or a reachable native history.
Any proposed target encoding and transition schedule require their own checks.

Uniform-ticket premises, legality of parent-dependent target histories, and a
reduction from every complete legal W1 strategy to the ideal search model remain
unproved obligations here. Neither this calibration result nor an expected-cost
ratio gives a common-prefix, chain-growth, chain-quality or settlement-failure
bound. It supplies no security probability for six confirmations.

## 6. Primary-source boundaries

- [Garay, Kiayias and Leonardos, *The Bitcoin Backbone Protocol with Chains
  of Variable Difficulty*, ePrint 2016/1048](https://eprint.iacr.org/2016/1048).
  The classical variable-difficulty analysis uses an explicit synchronous query
  model and constraints on changing participation. A population-share statement
  alone cannot replace these conditions.
- [Cojocaru, Garay, Kiayias, Song and Wallden, *Quantum Multi-Solution Bernoulli
  Search with Applications to Bitcoin's Post-Quantum Security*, Quantum 7,
  944 (2023)](https://quantum-journal.org/papers/q-2023-03-09-944/).
  The analyzed backbone has fixed target probability and classical honest
  parties. Its quantum query bound is not a physical W1 cost certificate.
- [Bailey and Sattath, *51% Attack via Difficulty Increase with a Small Quantum
  Miner*, arXiv:2403.08023v2](https://arxiv.org/html/2403.08023v2).
  The simplified search model motivates comparing cumulative credit against
  ideal Grover scaling; it does not establish this candidate's physical costs.
  The minimax proposition above is a separate elementary derivation, not a
  theorem attributed to that paper.
- [Garay, Kiayias and Shen, *Fast Difficulty Adjustment in Proof-of-Work
  Consensus*, ePrint 2026/1116](https://eprint.iacr.org/2026/1116).
  This is a parallel-chain and approximate-agreement construction. Its advertised
  adjustment speed does not qualify the candidate's existing retarget or mixed
  classical/quantum security. No unverified theorem constant is imported here.

The [joint production-tail note](JOINT_PRODUCTION_TAIL_V1.md) addresses a
different, conditional probabilistic interface. Neither note changes the
[joint qualification register](JOINT_CONSENSUS_QUALIFICATION_V1.md).
