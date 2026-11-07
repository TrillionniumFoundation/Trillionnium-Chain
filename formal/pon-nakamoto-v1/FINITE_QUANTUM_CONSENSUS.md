# Exact finite conditional W1 fork certificates

`w1_finite_consensus.py` produces a checkable probability calculation for one
explicit, finite model. It does not establish the security of PoN, a profitable
quantum attack, a physical cost lower bound, or a quantum mining qualification.
The existing consensus rules and qualification flags remain unchanged.

## The experiment being certified

The input is an actual, finite candidate DAG exported by the native bridge, or a
clearly labelled reduced-shape test control using the same schema. The bridge
starts from a classically generated, native-validated height-15 prefix. It also
generates a competing classical height-16 public block. Private candidates cross
the height-16 retarget and can extend through height 17. Every legal nonce has a
separate complete header, block identifier and successor context. The observer
recomputes each literal SHA/noise/trace/ticket relation and scalar-verifies every
native-shape winner. Other native admission checks are external bridge evidence.

The prefix, public block and offline census are explicit initial resources. Their
generation costs and provenance are retained separately. They are not charged as
zero-cost online work, and this model does not claim to generate that starting
position from a common ancestor within its private-search horizon. The public
classical history is fixed: there is no additional honest mining after that
declared extension. Consequently its result is a conditional fork-replacement
probability, not a mixed-network settlement bound.

The constructed-quantum private action class contains one processor, fresh uniform Grover
preparation, a declared finite set of iteration counts, complete readout, a full
legal-predicate candidate check, a serial proof clock on success, private
extension, whole-bundle publication, waiting for the public tip, and stopping.
Failed checks consume an attempt. Successful proofs can be withheld while the
next private context is searched. Classical checks do not retain coherent state.
The single resident exact template can be reused after a miss; changing the
parent invalidates it. The class does not include arbitrary quantum algorithms,
multiple entangled processors, adaptive partial-iteration measurement, arbitrary
timestamp choices, classical nonce-elimination strategies, or network attacks.

A separate `execution_kind="classical-uniform-q0"` implementation permits only
`q=(0,)` and the full legal predicate. It draws a fresh classical uniform nonce
and requires no QPU, quantum preparation, W1 quantum workspace initialization,
factory, or code distance. It retains task/template setup, each candidate check,
proof and propagation. The existing `per_trial_reset_readout_ns` input is
explicitly used as its assumed per-attempt classical RNG host-call duration.
This implementation is a distinct classical baseline; it does not make an
expensive quantum q=0 initialization disappear from the quantum model.

Publication pays the sum of the per-block propagation clocks for the withheld
bundle, then waits if the native future-time rule still defers a header. A model
replacement requires a completed publication by the deadline, a public tip that
has already arrived, a divergent private branch, and strictly greater cumulative
required work. A tie retains the public tip. Publishing before the public tip
arrives does not count as replacing that tip. There is one terminal publication.

## Exact probability kernel

Let the complete declared nonce domain have size `N`, and let `S` be the subset
marked by the phase oracle, with `m = |S|` and `p = m/N`. Write the per-nonce
amplitudes as `a/sqrt(N)` on `S` and `b/sqrt(N)` on its complement. Starting from
`a = b = 1`, one oracle-plus-diffusion iteration gives

```text
a_next = (1 - 2p) a + 2(1 - p) b
b_next = -2p a + (1 - 2p) b.
```

All values are rational. The probability of each marked nonce is `a²/N`, and
that of each unmarked nonce is `b²/N`. The implementation uses `Fraction`, an
explicit small-q cap of 64, and no trigonometric or directed-interval kernel.
Independent controls evolve every basis amplitude and compare all nonce masses.
This kernel preserves exact zero-probability overshoot and full/empty sets.

The legal acceptance set can strictly contain the phase-marked set. If it has
size `F`, total accepted mass is `(m a² + (F-m) b²)/N`. A legal winner that was
not phase-marked must still pass the completed classical candidate check. For
consensus continuation, the implementation retains the individual nonce and
block identifier instead of collapsing all successes into one artificial parent.

## Finite-model theorem and certificate

Let `G` be the complete reachable finite state graph for the declared inputs and
actions. Its states retain exact elapsed time, the private block path, completed
attempt count and resident template. Every nonterminal transition either consumes
an attempt or strictly advances time without resetting the attempt count. The
graph is therefore acyclic under lexicographic order `(attempts, time)`.

Every action has a complete probability distribution whose masses sum exactly to
one. A terminal edge has value 1 precisely for the replacement event above and 0
otherwise. Suppose a function `V` in `[0,1]` satisfies, at every state `s` and for
every declared action `a`,

```text
V(s) >= sum_t P(t | s,a) V(t),
```

where terminal continuation values are their event indicators. Then the
probability of replacement under every history-dependent randomized policy in
this finite action class is at most `V(initial)`.

Proof: proceed backwards through the finite graph. At terminal edges the claim
is equality. Conditional on a chosen action, the induction hypothesis bounds
each continuation probability by its certificate value; summation preserves the
bound. A randomized choice is a convex combination of these action values and
cannot exceed their common upper bound. The initial-state assertion follows.
Choosing the maximum action value at each state gives the exact optimum of this
declared model. This is an elementary finite-horizon induction, not a reduction
from structured W1 hardness or a theorem about the deployed chain.

The verifier does not call the optimizer. It regenerates literal predicates,
construction clocks, every legal action and every transition. It checks complete
reachable-state coverage, exact mass, the rank, every Bellman inequality and the
maximizer. Fixed-q probabilities are independently checked by forward mass flow.
A self-consistent hash alone cannot authenticate a certificate. Hitting the state
cap returns `INCOMPLETE` with no risk bound; omitted states do not become safe
terminal states. Partial phases retain paid time and do not acquire unfinished
measurement, proof or publication benefits.

## Advice, fixed policies, and positive paths

The optimizer reads the observer's census, so its action table is an
observer-selected envelope that permits instance-specific advice. It must not be
described as an optimal executable miner that does not know the winner set.
The separate fixed-q policy reads only the elapsed state, its completed private
chain and declared public visibility. It never reads marked counts, probability
masses or Bellman values to select an action. Its exact categorical sampler uses
one predeclared seed and retains misses. No seed, nonce domain or strategy is
changed after inspecting its result. Source binding is not an external timestamped
precommitment attestation.

A positive-path certificate is an existential witness selected by the observer,
with the exact product of its edge probabilities. It is distinct from the seeded
sample. The native bridge can replay either path with honest labels, submitting
only proof-complete published packets. A q=0 path is a uniform-sampling baseline;
even a real native reorganization along it does not demonstrate a quantum speedup.
If a q=1 action is censored before completing an iteration, it provides no evidence
of executed coherent quantum search.

## Cost and physical boundaries

The full lifecycle model reserves one common code distance over a conservative
envelope: every supplied domain is provisioned for `K` trials with the largest
declared q, plus `K` proof and propagation events. Every actual path is contained
in that envelope. There are at most `K` attempts, every q is at most the declared
maximum, and increasing private heights prohibit a later return to an earlier
domain. Misses retain the same resident template. Thus the per-path setup count
for a domain is at most one. Per-action initialization, transfers, gates,
controller waits, factory retries/resets and readout use this same distance and
allocation. A q=0 quantum action has no T-state factory startup or service, but
does initialize its declared quantum workspace. Early success never resets the
failure budget. All lifecycle clocks and the decimal horizon are exact fractions.
Partial iteration time is not a count of partial gates.

The lifecycle contract bounds each fault event conditional on the entire earlier
history, including clock overruns and cached-input corruption. It assumes the
actual timed execution equals the ideal execution outside the union of those
events. If the common envelope bounds that union by epsilon, each fixed policy's
actual replacement probability lies in `[max(0,p-epsilon), min(1,p+epsilon)]`.
The same uniform coupling bounds the finite action-class optimum around its ideal
value. This follows because the two event indicators agree outside the fault
union; no independence between faults or multiplication by `(1-epsilon)` is
assumed. The verifier recomputes this arithmetic and the full reserved envelope.
An `INCOMPLETE` graph has no composed replacement bound.

For the classical uniform implementation, the reserved fault events are only
classical setup/RNG/check/proof host calls and propagation. Its QPU count and
quantum-fault bound are exactly zero because no quantum operation is in that
implementation. The input physical model supplies only the unchanged declared
total failure budget for this comparison; its hardware parameters do not price
the classical baseline. Classical host runtime and fresh-uniform-RNG premises
remain uncalibrated. The bridge retains actual native path timing separately.

The older coherent-only constructed clocks remain an explicit comparison mode
when `lifecycle_model=None`, with no whole-machine coupling claim. They must not
replace the full lifecycle record in the main native experiment. All modes are
constructions under stated assumptions. A slow construction does not exclude a
faster legal attacker implementation. The union contract is not a hardware
calibration, compiled fault-tolerant implementation, energy/economic cost model,
or a proof about arbitrary network behavior. The probability calculation is
exact for the declared finite process, not for unmeasured hardware.

## Continuing public-branch extension

The separately versioned [competition model](w1_competing_consensus.py) and
[native competition bridge](experiments/w1_native_competition.py) retain the v1
fixed-tip records and add a finite continuing-public-branch experiment. They do
not reinterpret an old fixed-tip certificate as one covering future mining.

The native exporter produces two complete additional public blocks, at heights
17 and 18, from the already admitted public height-16 tip. Its producer has an
explicit **isolated public view**: private publication is not delivered to that
producer before the four-second horizon. It follows its own admitted tip. This
is a declared network-view condition, not a claim that an honest miner ignores
a better branch it has received. The receiver is a separate authenticated Node
and processes the public and private packets in the declared event order.

Two schedules are fixed in source before those honest packets are generated:

| Schedule | Public height 17 arrives | Public height 18 arrives |
| --- | ---: | ---: |
| `honest-before-private-publication` | 1 second | 3 seconds |
| `honest-after-private-publication` | 2.5 seconds | 3.5 seconds |

These are exact conditional arrival times. Actual CPU production clocks do not
calibrate them. Every honest proof attempt, including target misses, is retained
in a packet and an append-only JSONL ledger before the next attempt. The first
successful nonce ends the bounded search; exhaustion leaves its attempts in the
ledger and fails the experiment. Each native replay uses a fresh public producer
and regenerates all its attempts. The reader scalar-replays the complete product
and transcript even when the target test fails, and checks a bijection between
the fixture attempts and the retained ledger. Stage timings, history replay and
later evidence serialization have explicit cost scopes.

The private nonce window, seed 9, at most two attempts, four-second deadline,
proof/propagation charges and quantum lifecycle parameters are unchanged. The
fixed policy reads the public work that has already arrived; it does not inspect
future arrival times, the census or Bellman values when choosing an action.
The action envelope can also wait for the next public arrival. It still permits
only one terminal private-bundle publication. The public event stream continues
through the horizon after the private miner stops, fails or publishes.
The optimizing envelope sees both the census and the complete future public
schedule, including block identities. Its value is a conditional clairvoyant
envelope within the declared action class, not the value of a non-anticipating
network miner. The separately sampled fixed policy does not use that advice.
Private actions are non-preemptive. Search including any winning proof, and
propagation, complete or meet the unchanged horizon before another private
decision. Public arrivals during an action update the receiver on schedule and
are visible at the next private decision. Mid-action measurement, abort/restart
and switching to mine the public branch are outside this finite action class.

The certificate separately evaluates two indicators:

1. **Ever private replacement:** a complete private publication makes the receiver
   select the divergent private branch at least once before the horizon.
2. **Private active at horizon:** the receiver still selects that private branch
   after every declared public arrival through the horizon.

At equal exact times, public arrivals precede private-bundle admissions; within
each branch, parents precede children. Every admission uses strictly greater
native cumulative work. Equal work preserves the already selected tip, including
a private tip selected earlier. The native replay checks every intermediate tip
and work value, not just a terminal boolean, and reopens the authenticated
receiver to verify its retained packets and selected state.

Conditioned on this public schedule, its authenticated block identities and its
isolated-view premise, receiver selection is a deterministic function of the
private trajectory. The same finite graph induction above therefore applies to
either event indicator. Exact public-event times do not reset attempt counts,
and waits strictly advance time, so the graph remains acyclic. The independent
checker regenerates every event and transition and checks fixed policies by
forward probability flow. An incomplete graph again yields no bound.

The private-machine coupling statement also remains conditional on the external
public process being exactly as declared. The private fault union does **not**
bound honest production faults, receiver service failures or uncertain network
delays. Consequently `whole_network_machine_error_bound_composed=false` and
`stochastic_continuing_honest_mining_covered=false` remain explicit. This finite
schedule does not cover reactive globally informed honest miners, arbitrary
timestamp strategies, arbitrary quantum algorithms, long DAA trajectories or
settlement security. A temporary replacement alone cannot close those gates.

After exporting the base native DAG into a fresh observation directory, the new
sequence is:

```bash
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib --all-features quantum_native_bridge_tests::competition::export_source_bound_native_competition_fixture -- --exact --ignored --nocapture --test-threads=1
python3 formal/pon-nakamoto-v1/experiments/w1_native_competition.py --observe "$TRNM_W1_NATIVE_BRIDGE_EVIDENCE_DIR"
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib --all-features quantum_native_bridge_tests::competition::replay_source_bound_native_competition_samples -- --exact --ignored --nocapture --test-threads=1
```

Both native tests must actually execute. A compilation result or default ignored
test count is not a replay result. The native verifier holds the original raw
input bytes before calling Python, binds the returned receipt to those bytes
and the Python source/runtime, then checks inputs and consumed packet/ledger
hashes again after replay. The two seeded implementations and observer-selected
private-path controls are separately labelled, including an unsuccessful
observer publication. No CPU replay is labelled QPU execution.

## Relation to primary literature

[Cojocaru, Garay and Song, ASIACRYPT 2024](https://doi.org/10.1007/978-981-96-0947-5_3)
give hybrid black-box query bounds. In the
[author preprint, Section 4.1, equation 10](https://arxiv.org/pdf/2311.03723),
`nu_D = max_x Pr[f(x)=1]`, not the average marked fraction of an arbitrary fixed
instance. Their success bound is `nu_D (2 sqrt(q_c) + 2 q_q + 1)^2`, capped at 1.
For a point distribution on a known fixed function with a known winner,
`nu_D = 1`: there is no nontrivial query lower bound from a public census alone.
Function-dependent preprocessing or advice must be accounted for before applying
a black-box theorem. These query bounds do not establish a structured W1 gate,
memory, energy or wall-clock lower bound.

[Bailey and Sattath, version 2](https://arxiv.org/html/2403.08023v2) explain why
fixed-difficulty backbone conclusions cannot automatically extend to adaptive
chainwork. Their idealized difficulty-increase mechanism credits a factor `c`
while Grover search scales as `sqrt(c)`. This finite module checks actual integer
retarget arithmetic but does not reproduce their long-horizon economic attack,
prove an appropriate mixed-miner fork-choice rule, or justify square-root work
weighting as a protocol repair.

[Sattath's quantum-mining analysis](https://arxiv.org/abs/1804.08118) identifies
competition-triggered measurements as another source of correlated forks. The
July 2026 preprint
[Manson and Sanders, Strategies for quantum-enabled Bitcoin miners](https://arxiv.org/abs/2607.23952)
studies repeated attempts and aggressive quantum strategies in a two-miner game.
Its abstract's game-specific conclusion is not a PoN variable-difficulty theorem.
The present closed action class does not claim to cover those correlated
multi-miner strategies. The full mixed quantum/classical consensus security gate
therefore remains open.
