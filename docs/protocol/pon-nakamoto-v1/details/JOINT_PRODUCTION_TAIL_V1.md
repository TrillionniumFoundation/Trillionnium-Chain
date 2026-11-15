# Composing dynamic ready credit and honest progress without independence

Status: **conditional mathematics and finite-model certification; native
qualification remains HOLD_NO_GO**.

This note continues the dynamic fork witness at PR #843 head
`0ff81958a611d2c0be54d2ca839b955ae7cb2772`. It supplies a sufficient interface
for composing separately proved conditional production certificates. It does
not establish those premises for W1 or assign a security probability to native
six-successor confirmation. The independently developed M14 candidate is not
claimed to have integrated this research track.

## 1. Preserve the dynamic witness and its debt

Keep the existing all-branch ready-credit accounts: adversarial credit `A`,
entry/carryover debt `E`, and the single globally selected qualified pacer
process `J`. At the chosen reference use incremental accounts starting at zero.
Set `Y=A+E` and `D=Y-J`. The existing necessary crossing margin is

\[
 d_b=K_b-B_0-B_H-w_{\max}.
\]

The installed depth-and-required-credit gate gives `K_b>=7w(b)`; it gives no
risk probability. If the useful margin is nonpositive, the resulting crossing
bound is the trivial bound one. A certificate for `A` alone cannot replace a
certificate for `Y=A+E`. Alternatively, pay a separately justified simultaneous
upper bound on `E` by subtracting it from the margin and adding its failure
probability. Debt must not be omitted from both accounts.

The [dynamic participation contract](DYNAMIC_PARTICIPATION_V1.md) retains the
original task identities, parent bindings, participant generations, service
deadlines and restart/carryover accounting. The probability interface below
does not establish those operational premises.

## 2. Conditional Cauchy-Schwarz certificate

Condition on one fixed initial history, retaining its actual initial potential.
For a random initial history, average the entire corresponding conditional
bound `min(1,f_0 sqrt(Qbar) z^(-d))`. Here `z`, `d` and `Qbar` are fixed under
the conditioned initial history, or replaced by justified fixed bounds. Only
when the other factors are fixed may a bound on the expected initial potential
alone be used. Let `F_n` be the common
classical history used by the proof. Fix `z>1` before examining outcomes, and
let `f_n>=1` be a finite positive adapted residual-state potential. Assume every
reachable history and every permitted action obeys, for finite positive
predictable `a_n,b_n`,

\[
 \mathbb E\!\left[(f_n/f_{n-1})^2z^{2\Delta Y_n}\mid F_{n-1}\right]
 \le a_n,                                                     \tag{C1}
\]

\[
 \mathbb E\!\left[z^{-2\Delta J_n}\mid F_{n-1}\right]
 \le b_n.                                                     \tag{C2}
\]

The two inequalities use the same conditioning history, physical analysis
clock, task lifecycle and complete allowed action class. Separate marginal
expectations, favorable mean resource shares, or fixed-window empirical tails
do not establish them. Independence between honest and adversarial production
is not required.

Put `Q_n=product_(i=1..n)(a_i b_i)`, with `Q_0=1`. Then

\[
 M_n=\frac{f_n z^{D_n}}{\sqrt{Q_n}}
\]

is a nonnegative supermartingale with `M_0=f_0`.

**Proof.** Conditional Cauchy-Schwarz bounds the expected one-step multiplier
of `f_n z^(D_n)` by

\[
 \sqrt{
  \mathbb E[(f_n/f_{n-1})^2z^{2\Delta Y_n}\mid F_{n-1}]
  \mathbb E[z^{-2\Delta J_n}\mid F_{n-1}]}
 \le\sqrt{a_n b_n}.
\]

The compensator ratio is predictable. Dividing by it gives the
supermartingale inequality. The finite conditional moment assumptions provide
the required one-step integrability. QED.

Since `f_n>=1`, Ville's inequality gives the moving-boundary result

\[
 \Pr\!\left[\exists n:\frac{z^{D_n}}{\sqrt{Q_n}}\ge z^d\right]
 \le\min\{1,f_0z^{-d}\}.                                      \tag{C3}
\]

If `Q_n<=Qbar` at every relevant cut, including `Q_0=1` and thus `Qbar>=1`,
then

\[
 \Pr[\exists n:D_n\ge d]
 \le\min\{1,f_0\sqrt{Qbar}\,z^{-d}\}.                         \tag{C4}
\]

Checking `a_n b_n<=1` at each step is a sufficient way to obtain `Qbar=1`.
It is stronger than necessary: a bounded cumulative compensator can tolerate
some individual positive-drift steps. Unbounded `Q_n` gives no fixed-gap
lifetime bound. Multiplying unconditional average compensators is invalid.

An exact rational target-allowance comparison is possible even when the bound
contains an irrational square root. For positive allowance `epsilon`, compare

\[
 f_0^2Qbar\le\epsilon^2z^{2d}.
\]

This only squares nonnegative numbers in a bound. It does not assert that
`M_n^2` is a supermartingale. If an exact square root is unavailable, report the
exact squared bound or a justified upward rounding; never round an upper bound
downward.

## 3. Residual quantum state and the distinction between f and V

The [existing residual-state theorem](../../../../formal/pon-nakamoto-v1/STATEFUL_RESOURCE_TAIL_V1.md)
uses `V_n=Tr(K_h rho_n)>=1`. Its conditional joint density operator includes
retained adversarial progress and the proof's oracle-reference registers. A
quantum register is not a classical sigma-algebra containing its fully observed
contents.

Take `f_n=sqrt(V_n)`. Then (C1) becomes

\[
 \mathbb E[(V_n/V_{n-1})z^{2\Delta Y_n}\mid F_{n-1}]\le a_n.
\]

An actual instrument/operator certificate at exponent `2 log z` can imply
this inequality. Its transitions must cover entry/carryover debt as well as
adversarial ready credit. The initial multiplier in (C4) is now `sqrt(V_0)`;
the exact squared-allowance comparison uses `V_0 Qbar`.

Alternatively a finite scalar model may directly certify a rational potential
`f` using (C1). This requires the quadratic conditional moment of its potential
ratio. An existing first-moment certificate for that same `f` is insufficient.
The finite scalar table is not a certificate for all private quantum states
or all legal native strategies.

Do not reset the initial potential to one at an epoch, restart, cancellation or
rejoin. If an operator certificate includes a resource discount, preserve that
discount through composition and justify the cumulative physical-resource
budget. An honest receiver's input limit does not bound an adversary's external
work.

More generally, conjugate exponents `r,s>1`, with `1/r+1/s=1`, permit
conditional Holder. If

\[
 \mathbb E[(f_n/f_{n-1})^r\exp(r\theta\Delta Y_n)\mid F_{n-1}]
 \le\exp(c_n),
\]

\[
 \mathbb E[\exp(-s\theta\Delta J_n)\mid F_{n-1}]
 \le\exp(-h_n),
\]

for predictable bounds, then

\[
 f_n\exp\!\left(\theta D_n-
       \sum_{i=1}^n(c_i/r-h_i/s)\right)
\]

is a nonnegative supermartingale. The exact rational Cauchy-Schwarz interface
above specializes to `r=s=2`, `theta=log z`. Retrospective parameter selection
for a time-varying boundary requires a prior mixture, explicit selection
allowance, or another justified simultaneous construction.

## 4. Exact dependence and residual-state controls

Consider this one-step benign declared model with `f=1`:

| Delta Y | Delta J | Probability |
| ---: | ---: | ---: |
| 1 | 0 | 1/4 |
| 0 | 1 | 2/5 |
| 0 | 0 | 7/20 |

At `z=2`, the two separate first moments are `5/4` and `4/5`. Their product
is one, but the actual joint moment is

\[
 \mathbb E[2^{\Delta Y-\Delta J}]=21/20>1.
\]

Multiplying the marginal moments would falsely certify a supermartingale.
The valid doubled-exponent check has `a=7/4`, `b=7/10`, hence
`ab=49/40>1`, and refuses a nonpositive-drift certificate. The sufficient
Cauchy-Schwarz inequality may be conservative; it does not reconstruct a joint
law from marginals.

For a positive exact control, let `Delta Y` be Bernoulli(1/4), `Delta J=1`
deterministically, `f=1`, and `z=2`. Then `a=7/4`, `b=1/4`, so
`ab=7/16<1`. History-dependent selection among certified actions remains valid
when every action is checked under the same sufficient-state and conditional
history contract.

For a residual-state control, use a deterministic zero-cost release with
`Delta Y=1`, `Delta J=0`, initial `f=2`, and next `f=1`. At `z=2`,
`a=b=1`. Its crossing probability for `d=1` is one, and (C4) correctly gives
one. Resetting the initial multiplier to one would falsely give `1/2`.

These are finite mathematical controls. They produce no native blocks, make no
network requests, and establish no native vulnerability or work-cost advantage.

## 5. Adaptive starts and bad events

At a stopping-time reference retain its actual conditional potential, gap,
compensator allowance, outstanding tasks and debt. Uniform reachable-state
certificates give the conditional version of (C4). Allocate each claim's risk
allowance before that claim and establish that its conditional bound is at most
that allowance. Summing every registered allowance covers adaptive starts
without an independence assumption. Failed, censored and restarted claims do
not receive a refund.

The [persistent risk ledger](../../../../formal/pon-nakamoto-v1/NATIVE_RISK_LEDGER_V1.md)
records declared expenditure; it does not establish these probabilistic
premises or authenticate global start coverage.

A native conclusion still needs a complete reduction of the form

\[
 \{\text{native prefix failure}\}
 \subseteq B_{\rm bad}\ \cup\ \{\exists n:D_n\ge d_b\},
\]

where the dominating process obeys the certificate under its actual law, and
the probability of the entire-lifetime bad-event union is bounded. Add that
bad-event bound to (C4), capped at one.

If laws can fail on bad transitions, use a proved ideal-real coupling or killed-
subinstrument construction. Conditioning on eventual clock, bootstrap or
delivery success can change the conditional laws and is insufficient. Stopping
just before a failure detected from the current outcome is not automatically a
predictable killing rule.

## 6. Growth and quality require their own mappings

From (C2), the compensated process
`z^(-2J_n)/product_(i=1..n)b_i` is a nonnegative supermartingale. For a
specified window and endpoint, a justified pathwise upper bound
`product b_i<=B` implies

\[
 \Pr[J_{\rm window}\le g]\le\min\{1,z^{2g}B\}.
\]

Without a pathwise bound, the same calculation bounds the intersection with
`product b_i<=B`; it does not justify conditioning on future compensator
success. Window references, selection and initial history must be covered.

Native growth additionally needs the delivery/score-floor mapping. A floor
relative to the original `S0` does not bound growth from an arbitrarily later,
already higher active tip. Each claimed window needs its own justified
reference, and simultaneous windows require selection accounting. Arbitrarily
long absence of qualified producers rules out a positive physical-time growth
conclusion.

Weighted quality requires a stable-segment mapping and simultaneous upper and
lower production bounds. Block-count quality additionally requires a justified
weight ratio. Business inclusion requires an inclusion and service argument.
None follows merely from the common-prefix crossing inequality.

## 7. Exact finite implementation and scope

The [finite checker](../../../../formal/pon-nakamoto-v1/joint_production_tail_v1.py)
and [independent controls](../../../../formal/pon-nakamoto-v1/test_joint_production_tail_v1.py)
use exact rational arithmetic. The code's `potential` is scalar **f** in this
note, not the first-moment quantum **V** in section 3. It checks every declared
state/action, including unreachable states and actions a fixed policy never
selects. Direct mode checks the joint conditional multiplier. Conditional
Cauchy-Schwarz mode checks the two exact squared moments and requires their
product at most one. The general compensated positive-drift interface in
section 2 is mathematical only: the code implements the `Qbar=1` case.

Every transition law is supplied jointly. Its state must contain all
information on which the conditional law depends; otherwise the state-
sufficiency premise is absent. Calling a field unconditioned does not
authenticate its law or exclude hidden future conditioning.

For a certified finite model the bound is `min(1,f(initial)*z^(-gap))`.
The independent Bellman recursion maximizes finite-horizon crossing probability
over all adaptive policies and absorbs the first crossing permanently. It may
diagnose an invalid certificate, but an invalid certificate cannot issue an
anytime bound. Independent Catalan first-passage identities check the
recursion. A nonpositive mathematical margin can use the trivial bound one;
the CLI accepts nonnegative integer gaps only.

The checker accepts at most 1 MiB, 32 states, 128 total actions, 1,024 total
branches, rational parts at most 1,000,000, and a common probability-denominator
LCM at most 1,000,000. Per-field credit is at most 32, gap at most 256, and
horizon at most 32. Arithmetic exceeding 8,192 bits, 200,000 DP cells, or
1,000,000 branch expansions is refused. These are finite-checker limits, not
native consensus or network resource rules.

```bash
python3 formal/pon-nakamoto-v1/test_joint_production_tail_v1.py -v
python3 formal/pon-nakamoto-v1/joint_production_tail_v1.py --check /path/to/model.json --gap 1 --horizon 8
```

`--require-native-qualification` always refuses. Actual W1 conditional laws,
all-strategy physical-resource envelopes, joint initial-state bounds,
quantitative churn, clock/service bounds, native failure reduction and lifetime
composition remain unproved here. Native CP/CG/CQ and six-successor failure
bounds remain null; activation remains false and qualification HOLD_NO_GO.

This continuation retains the existing
[joint qualification register](JOINT_CONSENSUS_QUALIFICATION_V1.md),
[dynamic witness](DYNAMIC_PARTICIPATION_V1.md), and
[single development plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
The [calibration distortion result](CREDIT_CALIBRATION_DISTORTION_V1.md)
quantifies an ideal scoring limitation without proposing a new credit policy.
