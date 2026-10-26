# W1 service to visible honest work: a conditional finite-horizon interface

Date: 2026-10-26. Inspected source: `5301a319d4011f24f808f8644583cb4322cdbc97`.
Status: **conditional mathematical integration and exact counterexamples**.
O03 remains OPEN. This note belongs to the
[sole development plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
It changes no runtime, target, DAA, timestamp, queue, budget or production flag.

The new result connects a stated honest service guarantee to a finite lower
tail on minimum visible honest chainwork, then combines it with the existing
adversarial weighted-forest upper bound for a **purely private-fork overtake at
predeclared deadlines**. The guarantee is conditional on explicit hypotheses
which the current measurements do not establish. No all-fork common-prefix or
production settlement theorem follows.

The [exact model](../../../../formal/pon-nakamoto-v1/experiments/w1_service_growth_v4.py)
and [controls](../../../../formal/pon-nakamoto-v1/experiments/test_w1_service_growth_v4.py)
use rational arithmetic. Toy digests and event schedules are mathematical
controls, not native execution or hardware measurements.

## 1. What the existing source and evidence supply

The [native consensus owner](../../../../trillionnium/crates/trnm-pon-node/src/consensus.rs)
assigns `w(T)=floor(2^256/(T+1))` to an inclusive target hit. The
[storage/admission owner](../../../../trillionnium/crates/trnm-pon-node/src/store.rs)
requires complete native admission; fork choice selects strictly greater
validated cumulative work and retains the active tip on equality. A successful
work transcript alone is insufficient for a valid block.

The current public-intake
[CPU account](../../../../trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs)
has a shared 2 CPU-second burst, 0.25 CPU-second/second refill, 0.1 CPU-second
start reservation and two mutation workers. `reserve`, `charge_request_live`
and settlement account for measured work and uncertainty. These are admission
and accounting rules. They do not promise any honest request a minimum share.
The [intake owner](../../../../trillionnium/crates/trnm-pon-node/src/ingress/public_v3/intake.rs)
also has finite connection/resource leases and cancellation. A refused request
is not a packet retained indefinitely in a FIFO service model.

The [compact campaign](../../../../evidence/pon-work-compact-v1/RESULTS.md)
measured 9.220749347 CPU-seconds in the receiver phase over its registered jobs.
Admission occurred after the mining seal; research canonical growth was zero.
That sum supplies neither a wall-time service curve nor all-node delivery. Its
same-parent winners cannot be added as consecutive honest chain increments.

The existing [DAA resource interface](W1_NATIVE_DAA_RESOURCE_V2.md), section 2.1,
correctly uses `rho` in its comparison mean. A fresh audit finds its Markov and
bounded-jump convexity arguments consistent with its declared deterministic
caps. In particular, old winning **weight**, external ancestry and all forks
are retained. Its argument bounds adversarial candidate forest work; it makes
no honest service claim. Nothing here upgrades an actual-SHA coupling term
from unknown to zero.

## 2. The probability space must exist before good outcomes are observed

Fix one finite horizon and a fixed cohort of honest nodes. Supply a joint
reference experiment with the following properties:

1. Each counted honest trial is a distinct, fresh, canonical ticket lottery.
   Its exact parent, header, task, target and complete valid work relation are
   fixed before the ticket answer. Noise-expansion failure, duplicate challenge,
   unsupported task authority, stale material, wrong state and missing ancestors
   are not successful trials or free additional trials.
2. Before every fresh answer, in a filtration in which these honest trials are
   predictable, its conditional success probability has the stated lower bound.
   The comparison experiment has the necessary trials unless an earlier hit has
   already ended the slot. No independence between trials or slots is required.
3. The actual run and this reference construction agree on the relevant trials,
   service, validity and chainwork outside one named event `E_world`, with a
   supplied bound `Pr[E_world] <= epsilon_world`. It covers the complete declared
   horizon, resource-cap failures and all resource/lottery/visibility assumptions
   needed for the transfer. If it is not bounded, the production conclusion is
   unavailable.

This is a **single joint** reference experiment: it must simultaneously carry
the honest lower conditional laws here and the capped adversarial comparison
used in section 5. Separate marginal couplings do not automatically construct
that joint experiment or justify sharing one world-failure event.

The [v3 composition](W1_TICKET_COMPOSITION_V3.md) permits the elementary lower
conditional envelope for a fresh ticket-final response in its fully captured
classical ideal-permutation world. It establishes an adversarial **upper**
marking process. It does not establish hypotheses 1–3 for native honest mining.
In particular, thinning to a superset of possibly valid adversarial candidates
cannot provide a lower bound on valid honest service.

Under that ideal model, put `M=2^256` and predeclare the **global** exposure cap
`1<=C<=M`, covering preprocessing, all miners, all forks, inverse queries and
audit calls in this horizon. For a genuinely fresh ticket-final entry:

\[
\ell_T=\max\left(0,\frac{T+2-C}{M-C+1}\right),\qquad
\rho=\frac{M}{M-C+1}.
\]

The lower expression can be zero. This yields a vacuous growth guarantee, not
permission to substitute `(T+1)/M`. Actual SHA and unrecorded oracle-dependent
advice still need a separate instantiation argument. If v3's Join event is used,
include its ordinary-history bound once in `epsilon_world`; do not condition
the comparison law on future no-Join. The same rule applies to future queue
availability, completion and network success. A reference scheduler plus a
bounded coupling failure is a hypothesis, not an empirical certification.

## 3. A service guarantee that would justify a visibility deadline

Keep resources separate. For one retained honest flow at one stage, suppose its
offered work has an all-window arrival bound `alpha(u)=sigma+lambda*u`, in bytes
or CPU-seconds or storage work units, and it receives the service curve

\[
\beta(u)=R[u-L]_+,\qquad R>0.
\]

Here service counts completed work for that flow, including packetization or
nonpreemptive completion latency. A CPU quota is not a service curve. Under FIFO
order within this flow, no loss/refusal, adequate buffer capacity and
`lambda<=R`, every packet has delay at most

\[
d=L+\sigma/R.
\]

For `u>=0`, `beta(u+d)=R*u+sigma >= lambda*u+sigma`; the usual horizontal
deviation argument gives the bound. Backlog is bounded above by
`sigma+lambda*L`, so that buffer allocation is sufficient under the same
complete-packet conventions. This is not a lower bound on observed occupancy.
Request expiry,
material withdrawal and queue admission must remain valid through this delay.
The initial queue, every packet size and earlier incomplete work belong in the
stated curves or an additional bound. Ignoring them is not an approximation.

For a tandem, separately justify each stage's input curve and full-packet delay,
including burst increases caused by preceding stages. Then add those delays.
Bytes are not converted to CPU by an unexplained work scalar. To obtain an
all-node bound, cover every node and required route/ancestor/material transfer;
the delay is the worst resulting complete-admission time. Header receipt and
availability sampling alone do not establish this full-data guarantee.

### 3.1 A sufficient leftover-service construction

Suppose during every honest-backlogged interval of duration u the server supplies
at least `C_srv[u-L0]_+` aggregate resource work. Suppose all interference that
can occupy it during that interval is at most `sigma_A+r_A*u+B0`, where `B0`
covers supplied backlog and bounded nonpreemptive/unmetered residual work not
already in the first terms. If `C_srv>r_A`, subtracting interference supplies

\[
R_H=C_{\rm srv}-r_A,\qquad
L_H=\frac{C_{\rm srv}L_0+\sigma_A+B_0}{C_{\rm srv}-r_A},
\qquad\beta_H(u)=R_H[u-L_H]_+.
\]

This needs an actual backlogged minimum service guarantee and an all-window
**executed interference** bound. An arrival envelope alone needs its prior
backlog accounted for. If the scheduler can withhold service from the retained
honest flow, the subtraction premise must include that loss or fails. If
`C_srv<=r_A`, or the residual blocking work is unbounded, this construction
supplies no positive service. It does not silently put `B0=0`.

Invalid transcripts, invalid roots, rejected signatures, repeated packets,
control traffic and parsing can consume CPU or bandwidth without any valid
winning ticket. Their resource envelope must be included independently of the
adversarial consensus-work bound. A cheaper rejection path is valuable, but
its cost ratio is not a valid-ticket production advantage.

### 3.2 Two exact obstructions to reading service from current averages

An aggregate bucket with burst 1 and refill 1/4 permits one unit of non-honest
work at times 0, 4, 8, ... and zero honest work. Every contiguous event interval
conforms to its upper quota. This disproves deriving any positive honest share
from the aggregate quota alone. It is an abstract allocation counterexample;
it does not claim the current scheduler has been attacked with that trace.

Similarly, ten units completed one per second and ten units completed only at
time 10 have the same endpoint average. The latter supplies no work by time 9.
An aggregate campaign mean cannot establish all-window minimum service or tail
latency. The controls enumerate all intervals of the toy arrival traces and
distinguish these cases. Neither example is a new physical measurement.

## 4. Nonoverlapping honest slots yield a visible-work lower tail

Predeclare boundaries `s0<s1<...<sm`. In slot j, designate an honest producer
before the answers used in that slot. It selects one already validated native
parent whose chainwork is at least `H_min(sj)`, the minimum active fully
validated work among the fixed honest cohort at the slot start. The parent and
its native target stay fixed within that slot. A stale job started before the
boundary does not satisfy this condition automatically.

Before `sj+bj`, this producer completes `nj` fresh canonical opportunities on
that parent, **unless an earlier one already won**. The `nj` values and target
ranges are fixed before the experiment. These are guaranteed real opportunities,
not a count reconstructed from the best observed CPU average. Every winning
packet used for the slot has full native admissibility, authorized task/material,
correct state and timestamp, and is retained and fully admitted by all honest
nodes within `Delta_j`. Require `bj+Delta_j<=s(j+1)-sj`.

Every honest node's active validated work is monotone in this comparison.
Changing the eligible cohort, local revocation/demotion, restart rollback,
unavailable dependencies or an owner policy that prevents fork-choice activation
must be covered separately. Honest parent selection, current task eligibility,
full validation, and persistence are hypotheses even when the work proof is
mathematically correct. The ordinary wall-clock fix does not prove them.

Let `S_j` indicate at least one hit in slot j, and let its target be `T_j`.
Conditional on the complete past at the boundary, the probability of all nj
failures is at most `(1-ell_Tj)^nj`, by iterating the conditional failure bound.
Thus

\[
\Pr[S_j=1\mid\mathcal F_{s_j}]\ge
q_j(T_j)=1-(1-\ell_{T_j})^{n_j}.
\]

This statement permits dependent/adaptive answers. Stopping on the first
success does not change the all-failure product. Nothing supplies independent
Poisson arrivals or an independent weighted binomial process.

On a hit, by the next boundary every honest node either activates the offered
valid block or already has work at least as large. Therefore

\[
H_{\min}(s_{j+1})\ge H_{\min}(s_j)+w(T_j)S_j.
\]

The statement concerns the minimum **work frontier**, not a common block
prefix. It does not assume all nodes choose the same chain on a tie. Counting
at most one winner per slot prevents adding sibling weight as consecutive
growth. For example, two visible weight 7 siblings of a work 100 parent produce
a frontier 107, even though their successful forest weight is 14.

For predeclared ranges `a_j<=T_j<=b_j`, put

\[
q_j^-=1-(1-\ell_{a_j})^{n_j},\qquad
w_j^-=\left\lfloor\frac{M}{b_j+1}\right\rfloor,\qquad
\gamma_j(z)=1-q_j^-(1-z^{-w_j^-}),\ z>1.
\]

If `Y_j=w(T_j)S_j`, predictability and monotonicity give
`E[z^(-Y_j)|past]<=gamma_j(z)`. Iterating conditional expectations, and using
integer work for a predeclared integer h>=1, gives the finite lower tail

\[
\Pr[H_{\min}(s_m)-H_{\min}(s_0)<h]
\le\min\left(1,z^{h-1}\prod_{j=0}^{m-1}\gamma_j(z)\right)
\]

**inside the reference comparison**. Add the outside world-failure probability
when transferring to actual execution. For h=0 the shortfall event is empty.
Exact predictable target factors can be tighter, but a favorable realized
product cannot replace the predeclared envelope in an unconditional bound.
The conservative endpoint ranges allow nonstationary targets and DAA changes
between slots; their validity for all chosen parents must itself be justified.
All nested source/hardware failure probabilities remain explicit.

## 5. Coupling to the adversarial forest at fixed deadlines

Let the initial honest minimum work exceed a named private fork's supplied base
work by an integer d0>=0. Let `w0` bound all old unconsumed winning weight on that
fork, and let `N_A` be a predeclared cap on all new adversarial opportunities,
including preprocessing, relevant external help and all parallel forks. These
are the established [resource/DAA interface](W1_NATIVE_DAA_RESOURCE_V2.md)
obligations. A measured CPU speed ratio does not supply `N_A`.

For a purely adversarial private extension, no new honest blocks can appear
on it. On the event that honest work grew by at least h, a strict native overtake
requires at least

\[
D=d_0+h+1
\]

new-or-old adversarial extension weight. If D>w0, the comparison forest bound
is `F_A=min(1,rho*N_A/(D-w0))`; otherwise use 1. The heavier branch cannot contain
more new adversarial weight than the complete candidate forest. Let `F_H` be
the honest shortfall bound above. Then

\[
\Pr[\text{private overtake at }s_m]
\le\min(1,F_H+F_A+\epsilon_{\rm world}).
\]

This is a union bound; it assumes no independence between adversarial and honest
events, service and mining, or past and future target choices. Where the
preconditions for the DAA note's deterministic jump bound hold, its
rho-adjusted MGF tail may replace the Markov `F_A`. No realized easier branch,
stopping time, retirement count or selected winner target creates a new budget.

For a finite **predeclared** deadline set, sum the corresponding comparison
failure bounds and add one common whole-horizon `epsilon_world`. Alternatively
use separate correctly scoped failure budgets; do not assume independence.
This is not a guarantee for an unbounded lifetime or arbitrarily chosen later
deadline. An attacker who uses honest blocks on conflicting branches is outside
this private-fork containment. General reorganization/common-prefix security
still requires its own all-fork argument, even if this inequality is useful.

## 6. Controls, evidence boundary and what can now be decided

The exact controls cover exhaustive small-permutation depletion, dependent
slot-failure choices, a Bellman maximization over adaptive targets and
conditional success choices, conservative target/weight endpoint factors,
native floor weights, zero/vacuous service, stale sibling frontiers, explicit
old weighted banks, strict integer overtake thresholds, correlated failures,
finite deadline unions, distinct resource units, nonpreemptive residual bounds
and every interval of the toy quota traces. Exact-power limits raise errors;
they never fabricate a finite numerical answer.

The example output is deliberately a small-digest synthetic calculation with
`native_execution=false` and `production_parameter_certificate=false`.
Its values are not proposed production parameters. The argument above provides
the conditional theorem; finite enumeration is an implementation check and
counterexample witness, not a proof of an actual-SHA or physical lower bound.

This result tells the next real campaign exactly what has to be observed and
what still needs an assumption: complete declared honest search opportunities;
pre-answer parent/target/task/data feasibility; full packet and ancestor
availability; retained request-to-admission latency under bounded invalid and
valid interfering traffic; a minimum service share at each resource owner;
nondecreasing all-node validated-work frontiers; and the common finite exposure,
resource and failure budgets. An observed finite trace can refute a proposed
service envelope, but does not by itself prove that envelope for all futures.

Production kappa, a confirmation depth and emergency action cannot be selected
from the current same-parent compact campaign. The conditional honest-growth
and fixed-deadline private-overtake integration gap is now specified and tested;
actual service, SHA coupling, resource conversion and all-fork settlement remain
the original O03 obligations. Hybrid/ZK adoption and Hepta quality authority are
unchanged.

## 7. Primary sources and non-imported assumptions

[1] Blake, Feng, Wang and Yu, *Rigorous and Generalized Proof of Security of
Bitcoin Protocol with Bounded Network Delay*, 2026-01-14:
https://arxiv.org/html/2601.09082v1 . Its section II uses fixed block-type rates
and Poisson arrivals; its Appendix A gives a counterexample to an independence
step in an earlier delayed-chain random-walk argument. Those arrival hypotheses
are not established for W1. No security theorem from that paper is imported.

[2] Wang et al., *Securing Parallel-chain Protocols under Variable Mining
Power*, v2: https://arxiv.org/html/2105.02927v2 . It treats protocol-specific
difficulty coupling in parallel chains and difficulty-weighted analysis. Its
parallel-chain construction and security conditions are not this native DAA.

[3] Neu et al., *Longest Chain Consensus Under Bandwidth Constraint*, v3,
2022-05-18: https://arxiv.org/pdf/2111.12332 . It explicitly models bounded
download capacity and protocol-dependent download selection. Its PoS results
are not a proof that W1 can assume bounded full-validation delay under spam.

[4] Le Boudec, *An Introduction to Network Calculus*, 2019-04-05,
sections 3–5 and the packetization discussion:
https://leboudec.github.io/netcal/resources/tutorial-nc-dagstuhl-EPFL-2019-LEB.pdf .
This supplies the standard arrival/service-curve vocabulary. The subtraction,
slot induction and finite coupling inequalities used here are stated with their
own hypotheses above; a quota or an endpoint mean is not a service guarantee.

All four primary sources were opened directly in this continuation. The new
integration is a conditional derivation for the repository's work/selection
interface; it does not certify the external premises cited papers also require.
