# Joint lifetime, service and credit composition V1

Status: **conditional theorem and exact finite-model checker; HOLD_NO_GO**.
This continuation composes interfaces that were previously checked separately:
parent-bound target/time/credit, the `A+E-J` production gap, residual state,
dynamic participation and entry debt, complete delivery/service, adaptive starts
and non-refundable lifetime spending. It changes no installed consensus rule,
confirmation threshold, work profile, signed domain, stored schema or activation
flag. All eighteen joint-environment inputs and thirteen actual qualification
obligations remain open; native CP/CG/CQ, six-successor and lifetime bounds remain
null.

The [exact checker](../../../../formal/pon-nakamoto-v1/joint_lifetime_service_v1.py)
and [independent controls](../../../../formal/pon-nakamoto-v1/test_joint_lifetime_service_v1.py)
operate only on a supplied finite conditional law. A valid finite certificate is
not a claim that the law is authentic, that all legal strategies are represented,
or that any native failure is included in the modeled event.

## 1. One filtration and one unconditioned law

Let `F_t` contain the complete declared public history before the next action is
chosen. A declared adaptive policy may select any action available at that state.
Its next outcome is then drawn from one joint conditional row. The row is not
factorized into independently favorable resource, delivery, clock or participation
marginals.

On a non-bad transition define

\[
\Delta D_t=A_t+\Delta E_t-J_t,
\]

where `A` is adversarial ready credit, `E` is retained entry/carryover debt and
`J` is fully eligible honest pacer progress. The checker verifies the exact debt
recurrence

\[
E_{t+1}=E_t+E_t^{\rm new}-E_t^{\rm served}
\]

and aggregate qualified-participation recurrence in the same successor. A
declared leave/rejoin transition therefore cannot silently erase aggregate debt;
native member generation and identity authentication remain outside this schema.

For a supplied potential `V >= 1` and `z > 1`, every declared action must satisfy

\[
\sum_{o\in\{\mathrm{good},\mathrm{crossing}\}}
 p_o z^{\Delta D_o}\frac{V(s_o)}{V(s)}\le 1. \tag{1}
\]

Threshold-crossing outcomes remain inside (1) before becoming absorbing. External
bad outcomes are killed and retain their original probability mass; the remaining
law is never renormalized. This prevents a receiver timeout or incomplete service
from disappearing merely because the successful subkernel looks contractive.

## 2. Adaptive starts and lifetime spending

At a predictable history, before seeing the next outcome, an action may register
a start with identity, remaining gap `d`, remaining horizon `h` and charged
crossing allowance `c`. Registration requires

\[
c\ge V(s)z^{-d}.
\]

Every good-kernel increment updates all active gaps together and decrements every
active horizon. A crossing is absorbing. Expired starts may leave the active set,
but their charge is not refunded. Each action also charges an external-bad
allowance `b` before its outcome and verifies

\[
\Pr[\text{declared external bad next}\mid F_t,a_t]\le b.
\]

The successor must retain the exact cumulative spend and start count on every
branch, including failure branches. Along every declared path the total spend is
at most the one lifetime budget `B`. Restart, reorganization, departure and
rejoining receive no fresh budget.

For active starts already present at an analysis cut, the checker retains their
residual gaps and charges. The future conditional union allowance is

\[
\min\left\{1,
 \sum_{i\in I_0} V(s_0)z^{-d_i}+B-S_0
\right\}. \tag{2}
\]

Equation (2) adds crossing and external-bad allowances. It does not multiply
marginal failure bounds and does not require independence. A second Bellman
calculation returns the exact maximal bad-or-crossing probability over the
declared finite actions for a selected finite horizon. The Bellman result is a
finite-model diagnostic, not a replacement for (1), a lifetime theorem over an
unbounded native process or an actual network risk estimate.

The Bellman diagnostic may stop before its requested horizon only at an explicit
`safe_absorbing=true` state with no actions and no active starts. Every other
non-bad state must declare at least one action. Thus an omitted continuation or a
still-pending start cannot be treated as zero future failure probability.

## 3. Parent target, time and required credit in the same transition

Every branch binds its parent height and target to the current declared state.
A good branch must satisfy the declared time eligibility

\[
\mathrm{timestamp}>\mathrm{MTP},\qquad
\mathrm{timestamp}\le\mathrm{observed\_now}+\mathrm{future\_skew},
\]

and the successor must retain nondecreasing observed time. Required credit is
recomputed as

\[
w(T)=\left\lfloor\frac{2^{256}}{T+1}\right\rfloor,
\]

then added exactly to cumulative credit. A caller-supplied alternate credit is
rejected. The checker does not reconstruct MTP from full ancestry or prove that
the declared child target is the native DAA output of a complete parent history;
both facts remain explicit native-reduction obligations.

## 4. Complete delivery and service

A good outcome requires both complete delivery and complete service. The intended
native qualification remains broader: data availability, transport, queues, full
verification, state readiness, parent freshness, eligible admission and business
service before the original deadline. This finite checker uses two conservative
declared booleans and therefore cannot authenticate any of those components.

A `delivery` label requires an incomplete-delivery witness, and a `service` label
requires an incomplete-service witness. Other declared external-bad labels are
not root-cause authenticated by this finite schema. Every such probability stays
in the original row and is charged from the lifetime budget. A receiver
acknowledgement, source digest, process exit or observed timeout is not a physical
resource or latency theorem.

## 5. Exact finite controls

The retained finite example registers one start before a three-outcome transition:

- crossing with probability `1/4`;
- incomplete delivery with probability `1/4`;
- complete good service with probability `1/2` and honest increment one.

For `z=2` and `V=1`, the pre-bad joint moment is `3/4`. The exact one-step union
failure probability is `1/2`, not the product `1/16` of two marginal quarter
probabilities. The external-bad mass is `1/4` on the original law; discarding it
and renormalizing the remaining moment would incorrectly turn `3/4` into `1`.
The start charges `1/2` for crossing and `1/4` for external bad events, producing
a conservative lifetime allowance `3/4`.

Twenty-five independent controls cover exact Bellman results, inclusive `T+1`
credit, parent binding, strict MTP/future-skew eligibility, complete service,
non-refundable sequential adaptive starts and restart/rejoin state, entry debt and
participation conservation, a residual-start analysis cut, unreachable actions,
explicit safe absorption, bounded exponent/input handling (including FIFO and
symlink refusal), duplicate JSON keys, invalid moments and mandatory
`HOLD_NO_GO` output.

## 6. Primary results and transfer boundaries

- Garay, Kiayias and Leonardos,
  [The Bitcoin Backbone Protocol with Chains of Variable Difficulty](https://eprint.iacr.org/2016/1048.pdf),
  supplies a variable-difficulty synchronous model with explicit participation
  restrictions and difficulty-weighted properties. Its rounds are not native
  MTP/future-skew time, and its concentration results do not automatically
  qualify the installed epoch parameters.
- Cojocaru, Garay, Kiayias, Song and Wallden,
  [Quantum 7:944 (2023)](https://quantum-journal.org/papers/q-2023-03-09-944/),
  supplies fixed-density quantum search/backbone results under its oracle and
  party model. It does not establish variable W1 target costs, active cross-fork
  quantum memory, physical latency or this system's lifetime budget.
- Bailey and Sattath,
  [51% Attack via Difficulty Increase with a Small Quantum Miner](https://arxiv.org/abs/2403.08023),
  demonstrates why credit proportional to difficulty and ideal Grover cost
  proportional to its square root cannot be treated as one calibrated scalar.
  It does not prove native W1 implementability or authorize square-root credit.
- Terner,
  [Permissionless Consensus in the Resource Model](https://eprint.iacr.org/2020/355.pdf),
  makes resource-rate and network-delay assumptions explicit. Its resource DAG
  protocol is not a native reduction for the installed heaviest-credit chain.
- Tzinas, Sridhar and Zindros,
  [On-Chain Timestamps Are Accurate](https://eprint.iacr.org/2023/1648.pdf),
  derives time properties under explicit CP/CG/CQ and round-number premises.
  Native MTP11 plus a future-skew check is not that premise.
- Kreder et al.,
  [A Better Proof-of-Work Fork Choice Rule](https://eprint.iacr.org/2024/200.pdf),
  proves results for a modified intrinsic-work rule. Those results do not apply
  to the unchanged cumulative required-credit rule.

## 7. Qualification boundary

The checker fixes every native-facing claim below to false or null:

- authenticated probability, resource and wall-clock laws;
- all-legal-strategy and active-quantum-memory coverage;
- parent-target ancestry, full MTP and complete-delivery authentication;
- world confirmation-start coverage and native-to-model reduction;
- common prefix, chain growth and chain quality qualification;
- six-successor, CP/CG/CQ and actual lifetime failure bounds;
- finality, execution authority and production activation.

Closing any actual obligation requires an independently reviewed native reduction
and the corresponding complete joint environment. Passing this finite checker
does not change the joint qualification register or assign a failure probability
to six confirmations.
