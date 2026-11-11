# Quantum tip measurement and current-clock admission

Status: **HOLD / NO-GO**. This is a development experiment and implementation
boundary, not a quantum-security qualification.

## Source and scope

The continuation starts at
`e4abb172147e941b62483652b0ceabaae4317624` (#876). It extends the existing
[network simulator](../../../../formal/pon-nakamoto-v1/quantum_network_sim.py)
and its [controls](../../../../formal/pon-nakamoto-v1/test_quantum_network_sim.py).
The current-clock admission change is a selective transplant of the reviewed
#811 source `bd696c35f8b838823fad7ccf2868582554f33559`, adapted to the current
public Growth owner. Evidence from either original source remains attached to
that source. A successor must obtain its own execution results.

Two boundaries are addressed:

1. A quantum miner following an observed tip can measure its existing search
   after adopting a newer tip, with the old candidate context and all incurred
   costs retained.
2. A public Growth submission checks its retained parent history under the
   receiving clock before expensive W1 verification, and again after
   reacquiring the owner before durable admission.

The native target, retarget and cumulative required-work arithmetic remain the
existing rules. No square-root replacement score is introduced.

## Explicit conditional strategy

`NetworkScenario.quantum_tip_policy` accepts `discard-restart` (the historical
default) and `measure-on-tip`. The latter requires `quantum_strategy="honest-tip"`
and `quantum_clock_rounding="upward"`. It is a declared, bounded policy, not an
optimizer over every permitted quantum algorithm.

A notice only triggers this policy when the miner actually adopts a newer tip.
An unchanged or tied view cannot repeatedly measure one quantum state.

| Stage at adopted-tip notice | Action |
| --- | --- |
| Domain setup or state preparation incomplete | Cancel and charge consumed work; start at the new view |
| Prepared state with an iteration in progress | Finish that iteration, then measure once |
| Readout or candidate checks already in progress | Complete the original readout/check batch |
| Proof already in progress | Complete and charge the original proof |
| A prior notice has latched a readout | Update the public view without scheduling a second measurement |

The old trial keeps its parent, timestamp, required target, probe inclusion and
finite-domain identity. Updating a classical view is not permission to change
the oracle under an existing coherent state. A later search binds a new context
when needed.

Let preparation (including domain setup) finish at elapsed time $a$, each
whole Grover iteration cost $d>0$, and the original plan contain $K$
iterations. At elapsed time $t\geq a$, the policy chooses

$$
k = \min(K,\max(0,\lceil(t-a)/d\rceil)).
$$

The implementation uses exact rational representations of the supplied binary
floating-point times and rounds the final event time upward. A notice just
after a boundary cannot be treated as having arrived on that boundary. This
policy waits for the next complete iteration; it does not claim an
arbitrary-gate interruption primitive or free reversal of a partial unitary.

For a fixed domain with $N$ candidates and $M$ marked candidates,

$$
P_1(k\mid M,N)
=\sin^2((2k+1)\arcsin\sqrt{M/N}),\qquad
P_P=1-(1-P_1)^P .
$$

The second expression assumes the simulator's independent synchronous
processors and conditions all processors on the same fixed marked set.
Unknown $M$, zero-solution domains and the modeled refresh policy retain
their existing meanings. A notice never redraws $M$. At $k=0$, a prepared
uniform state has success probability $M/N$; an unprepared state is not
silently treated as ready.

A fresh event serial invalidates the old completion event when the completion
is moved earlier. This is still one search: its original start time is kept
and `searches_started` is not incremented. Measurement success leads to paid
candidate checking and serial proof production. It is not immediate block
adoption. A successful old-parent proof can be stale and still incur its full
proof and propagation cost.

## Accounting and finite resource envelope

The event experiment retains consumed setup, preparation, search time,
completed iterations, measurement, candidate checks and proof time. Interrupted
and horizon-censored work remains visible. Processor-time counters charge all
configured processors. `tip_measurement_requests` counts latched requests,
including retention of an already-started readout; it is not a count of
physically completed measurements.

`logical_iterations_completed` counts only complete iterations. A partial
iteration at a shock or horizon still consumes elapsed resources; this counter
must not be relabelled as all consumed quantum gates or queries.

The existing resource adapter reserves a full planned search envelope per
real start. A measurement reschedule adds no real start and chooses at most
the original planned depth. The bound of
`1 + max_events * max_blocks` starts is therefore not enlarged by this policy.
The adapter checks actual starts, at most $P$ candidate checks per start and
at most one proof per start, and binds the current simulator source. Its
coherent-stage/T-service error budget remains conditional. Initialization,
reset, readout and controller failures do not acquire an end-to-end physical
machine failure bound from this change.

The standalone resource workload's "interrupted iterations" describe discarded
work without readout. A shortened search that actually measures must not be
encoded as that category to omit checks or proofs. The event adapter instead
uses its full campaign envelope and actual event accounting.

Constructing one reversible W1 winner predicate supplies an implementation and
an attack-cost upper bound under its declared components. It does not prove a
minimum over all legal quantum algorithms. A cheaper legal strategy may
prepare or reuse data and generate a proof only after measuring a candidate.
Proof generation must not automatically be charged inside every Grover
iteration if the actual legal algorithm does not require it.

## Current network boundary

The existing experiment has one fixed delay per receiver, complete ancestor
bundles, and a fork rule that retains the current tip at equal required work.
It does not model bandwidth, eclipses, heterogeneous paths or native W1 service.

In the ordinary same-parent race with a common propagation delay $\delta$,
the quantum miner and the other receivers learn of an honest publication at
the same time. The quantum miner then pays the remaining iteration, readout,
check, proof and propagation costs for its competing old-parent block. Other
receivers have already seen the honest block and retain it on an equal-work
tie. Thus the ordinary race has the effective adoption parameter
$\gamma=0$ in this particular model.

A panel that observes additional stale proofs or no adoption gain therefore
does not refute aggressive quantum mining in networks with different
observation/propagation paths or tie rules. Those environments remain explicit
uncovered cases. Measurement probability, proof creation and fork adoption
are separate observations.

The separately named [paired runner](../../../../formal/pon-nakamoto-v1/quantum_tip_measurement_campaign.py)
uses the same declared parameters and seed for both policies,
with upward clocks in both arms. Policies change subsequent event ordering
and random-number consumption. A shared seed is not an identical-arrival
counterfactual trace, and repeated seeds are not independent native-network
experiments.

## Native current-clock admission

The public PGH2 owner already checked all retained ancestors at activation.
The missing early checks allowed a fresh request to spend W1 work and persist
a candidate before current-time activation rejected a future ancestor. A
duplicate followed its own current-time activation path.

The public dispatch now samples one clock under the first owner lease, runs
the existing candidate precheck and walks the retained parent history with
the original progress/deadline/CPU callbacks. It refuses an ineligible history
before starting W1, including the exact-duplicate case. After unlocked W1,
it samples the receiving clock again under the reacquired owner and rechecks
the parent history before durable admission using that same clock.

The existing postcommit activation check remains independently exercised.
Its test constructs an already-admitted historical packet and directly calls
the original activation helper. It checks that current-time refusal does not
erase a durable packet or change the active branch.

The separate real TCP test covers fresh refusal with no new durable record,
duplicate refusal with no W1 work, and a successful eligible branch. It does
not by itself simulate every clock rollback or owner race during W1. The
ancestor walk still has its existing resource and scale costs; this change is
not a hostile-load liveness result.

## Joint qualification obligations

| User question | Bound scope in this continuation | Still required |
| --- | --- | --- |
| Permitted quantum algorithms and parallelism | Explicit finite policy and independent synchronous processors | All legal strategies, alternative oracles, multi-miner scheduling and resource calibration |
| Complete W1 oracle cost | Existing fixed-context reversible winner/resource work, with explicit post-success costs | Evolving native contexts, cheaper legal implementations and physical end-to-end budget |
| Stop, restart and abandon | Existing discard/private policies plus one latched measurement policy | General adaptive schedules, asynchronous processors and other network conditions |
| Reachable timestamp/DAA states | Existing arithmetic experiment and earlier current-clock native refusal | Complete native-to-model reduction over all reachable branches |
| Delay, resource share and finite domain | Declared synthetic inputs; fixed or sampled finite marked sets | Justified real delay/service/resource distributions, heterogeneous paths and task supply |
| Common prefix, growth and quality | Finite event observations and conditional resource bounds | Joint production tails, initial state, dynamic participation and lifetime composition |

The integrated [joint qualification manifest](JOINT_CONSENSUS_QUALIFICATION_V1.md)
and [dynamic participation model](DYNAMIC_PARTICIPATION_V1.md) make the remaining
unknowns machine-readable. Their 23-source roster is a reviewed model boundary:
it includes `store.rs`, but not the public ingress dispatch or its tests.
Whole-candidate source verification and the separate native regression must
bind those ingress files. The roster is not a full runtime/build closure.

All production security bounds and quantum qualification remain false or
unknown. A passing source checker, replay, unit test or finite experiment
cannot assign a failure probability to the installed confirmation policy.

## Primary references

- Bailey and Sattath, [51% Attack via Difficulty Increase with a Small Quantum
  Miner, v2](https://arxiv.org/html/2403.08023v2). Its speed parameter is relative
  independent quantum block production versus the honest network. Its model,
  including bounded per-epoch changes, is not a native W1 implementation.
- Sattath, [On the insecurity of quantum Bitcoin mining](https://arxiv.org/abs/1804.08118).
  Receipt-triggered quantum measurement motivates explicit fork behavior.
- Nerem and Gaur, [Conditions for Advantageous Quantum Bitcoin Mining](https://arxiv.org/abs/2110.00878).
  Measurement success, resource cost and adoption assumptions are distinct.
- Cojocaru et al., [Quantum Multi-Solution Bernoulli Search with Applications to
  Bitcoin's Post-Quantum Security](https://arxiv.org/abs/2012.15254). Its
  fixed-difficulty backbone/QRO result is not a variable-DAA certificate.
