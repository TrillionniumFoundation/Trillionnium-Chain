# Native execution accounting with paid view deficits, v1

Status: **research certificate and deterministic model checker; native security
qualification remains HOLD**. Date: 2026-11-07 UTC. Source baseline:
`2789e9d9999920d858c1b65d3bff29122079cb4e`.

This note strengthens the conditional mapping in
[`NATIVE_FORK_MAPPING_V1.md`](NATIVE_FORK_MAPPING_V1.md). It replaces an assumed
instantaneous maximum-chain selection with two explicitly paid score deficits.
It covers an observation made before the original confirming chain has reached
another node, including observations with no local rollback. It also gives a
positive early-window reduction when that node already has a shorter complete
chain containing the target block. The deterministic statements below are
proved. Their probabilistic premises, actual physical execution attestation,
and the native six-successor risk are **not** established by these fixtures.

The implementation is
[`native_execution_certificate.py`](native_execution_certificate.py), with
[`test_native_execution_certificate.py`](test_native_execution_certificate.py).
All committed trace fixtures are explicitly synthetic finite models. No
production crate, consensus rule, mining path, or runtime observer is changed.

## 1. Native facts and the missing observation contract

The following are source facts, not measurements of a running network. The
source bridge in
[`native_execution_source_facts.json`](../../evidence/pon-work-native-certificates-20261107/native_w1/native_execution_source_facts.json)
records exact Git blobs and SHA-256 values at the baseline. The event checker
also binds its evidence to the bytes of the principal source files.

| Source and function | Fact used here | Consequence |
| --- | --- | --- |
| `trillionnium/crates/trnm-pon-node/src/store.rs`, `activate_with_fault_and_progress` | Compares the submitted target with the current active tip. Only strictly greater work replaces the incumbent. | This function does not itself establish that the active tip maximizes work over every currently adoptable candidate. |
| Same file, `recover` | Scans `blocks` in descending chainwork order, then activates its selected target. | A global scan exists in a recovery path; it does not prove instantaneous global maximality for every admission, activation, or observation path. |
| Same file, `confirmations_with_progress` | Checks inclusion, successor depth, work delta, all observed ancestry timestamps, and the final active tip/generation. | The returned observation does not enumerate all eligible competing candidates. |
| Same file, `check_observed_history_with_progress` | Tests ancestry timestamps against supplied observation time plus the configured future skew. | A timestamp eligibility test is not a physical clock synchronization or network-delay certificate. |
| `store/growth/recovery.rs` | Growth activation also compares one target to the incumbent; growth recovery scans globally. | The same selection-lag distinction applies. |
| `ingress/public_v3/request_observation.rs` | Request lifecycle times are observer-local `Instant` measurements; the observation store is bounded, and unknown/incomplete observations remain explicit. | These records do not authenticate all private branches, global ready times, final parent bindings, or the world's initial inventory. |

The exact SHA-256 values for the three primary files above are:

```
store.rs
8e65b358f83e7be4863879dd719fd7bf17af7ff78dae60e7b8ebb30c64605541
store/growth/recovery.rs
e00f2b736cb22c42468cd494eece859eb78fe1005a7c83c621f14c319c74f743
ingress/public_v3/request_observation.rs
fdd161cfee7e994f092e048020ae8dce140e852edf0c9e99ec9edce1cc838d21
```

In particular, neither miner-parent maximality nor the existence of a recovery
scan substitutes for maximality at an observation node. A score-100 chain
containing `b` can be complete and adoptable while active score 7 is replaced by
a submitted score-8 chain excluding `b`. Strict target-versus-incumbent
activation alone permits that sequence. The new accounting pays its remaining
score-92 selection deficit instead of assuming that sequence impossible.

## 2. One execution clock and one output-credit ledger

An execution is a locally finite rooted block tree with positive additive
block weights and a single causal total order on events. Each event also has
physical time; this time is nondecreasing in the causal order. Local finiteness
excludes infinitely many events in bounded time. A causal cut, rather than a
timestamp alone, identifies every quantity in the theorems. A completion at
the same physical timestamp but after a comparison cut is not already present
at that cut. Parent-first expansion of a completed batch is deterministic
bookkeeping; it does not split the batch into independent random trials.

`ready` is the first time a block's body, work proof, application dependencies,
and required ancestry are all complete. Historical readiness is monotone and
prefix closed. It does not disappear when a cache is pruned, a node loses data,
or current timestamp eligibility changes. It does not require publication.
A block with a future timestamp may already be ready and hidden, even while
it is not yet adoptable by a node. Its eventual release or timestamp eligibility
does not create another work credit.

This credit clock must be used by both the resource-tail certificate and this
mapping. If an individual proof was finished before the analysis cut but its
ancestry becomes complete afterwards, the unfinished state at the cut must
carry its future output potential. If a cost certificate gives credit at an
earlier stage than ancestor-complete readiness, an additional carry-in term is
required when connecting the certificates. No finite output list certifies
that the residual classical or quantum state is empty.

For each analyzed honest node or miner `v`, let `V_v(c)` be its complete, valid,
currently adoptable chain candidates at cut `c`. The selected chain must belong
to this set at an analyzed observation or parent binding. Set

\[
M_v(c)=\max_{C\in V_v(c)}S(C).
\]

This is the maximum over the actual complete candidate view, not merely a
reported active score. A finite model can compute it from its declared view.
A native execution must independently establish that the exported view covers
all relevant candidates. Omitting candidates cannot certify a physical
availability or selection deficit. The checker authenticates neither this
world coverage nor the claimed physical clock.

## 3. Full-cut deterministic accounting, including pre-propagation failures

Fix a confirmation cut `tau`, a selected chain `C0` containing target block `b`,
and a later honest observation of selected chain `D` excluding `b`. Write
`a = LCA(C0,D)` and `p = parent(b)`. For any reference `R(c) >= S(C0)`, define

\[
\begin{aligned}
L_{\rm avail}(c)&=[R(c)-M_v(c)]_+,\\
L_{\rm select}(c)&=[\min\{R(c),M_v(c)\}-S(D)]_+,\\
q_v(c)&=M_v(c)-S(D)\ge0.
\end{aligned}
\]

Then, exactly,

\[
L_{\rm avail}+L_{\rm select}=[R-S(D)]_+.\tag{1}
\]

The capped selection charge avoids paying the portion of raw lag `q_v` above
the reference. Equation (1) requires `S(D) <= M_v`; it must not be derived
from an incomplete candidate list that omits the selected chain. It does not
require that the selected chain is a maximizer. `R` is an analytical reference,
not an asserted globally selected tip. The executable comparisons choose the
maximum of `S(C0)` and the scores of all `b`-containing candidates in the
declared complete views at that same cut. Any other `R >= S(C0)` gives the
same theorem with its explicitly computed deficits.

Partition the suffix `D \\ a` into three disjoint groups:

- `I`: weight already ancestor-complete ready at `tau`, from either producer;
- `A_comp`: new adversarial weight on this suffix after `tau`;
- `H_comp`: new honest weight on this suffix after `tau`.

**Theorem 1 — exact fork-cut witness with paid comparison deficits.**

\[
I+A_{\rm comp}+H_{\rm comp}+L_{\rm avail}+L_{\rm select}
\ \ge\ S(C0)-S(a)+R-S(C0).\tag{2}
\]

**Proof.** The three groups partition a positive-weight suffix, so their sum
is `S(D)-S(a)`. Adding (1) gives `max(S(D),R)-S(a)`, which is at least
`R-S(a)`. No communication or parent-choice premise is used. The same proof
therefore covers both local rollback and cross-node observations before
propagation. At an actual first local strict replacement, the new chain has
strictly greater score than the old incumbent; a cross-node comparison can
have equal scores and does not imply a local replacement. This theorem does
not convert that latter case into a strict inequality. QED.

For a common whole-execution ledger define

\[
\begin{aligned}
K_b&=S(C0)-S(p),\\
B_0&=\max_{F\text{ ready at }\tau,\ b\notin F}[S(F)-S(p)]_+,\\
A(c)&=\sum_{x\text{ newly ready in }(\tau,c],\ x\text{ adversarial}} w(x),\\
H_{\rm off}(c)&=\sum_{x\text{ newly ready in }(\tau,c],\ x\text{ honest},\ b\notin x} w(x).
\end{aligned}
\]

`B0` includes unpublished and time-deferred complete inventory on every
competing chain; it includes honest inventory as well as adversarial
inventory. `A` counts each new adversarial output once across **all** forks.
`H_off` is not total honest production: it counts only blocks on chains
excluding `b`. These are one ledger for a fixed `(b,tau)`, so selecting the
eventual competing fork does not incur an additional count of possible forks.
Selecting `(b,tau)` adaptively still requires a valid stopping-time argument
or a separately paid multiple-comparison bound.

**Theorem 2 — all-fork witness at every analyzed failure cut.**

\[
A(c)+H_{\rm off}(c)+L_{\rm avail}(c)+L_{\rm select}(c)
\ \ge\ K_b+R(c)-S(C0)-B_0.\tag{3}
\]

**Proof.** Readiness is prefix closed, so the blocks of `D \\ a` already ready
at `tau` form its initial prefix ending at some `F`. Since `a` is on `C0`, it
was ready at `tau` and belongs to this prefix. Since `b` is absent from `D`,
`F` is one of the chains covered by `B0`. Thus

\[
I=S(F)-S(a)\le B_0+S(p)-S(a).
\]

Also `A_comp <= A` and `H_comp <= H_off`. Substitute these inequalities into
(2) and cancel `S(p)-S(a)`. QED.

Equation (3) is a reduction to a combined score ledger, not by itself a small
probability claim. It openly charges an unseen anchor, pending validation,
unavailable data, delayed activation, concurrent honest off-branch progress,
and hidden completed inventory. Choosing a very large `R` merely raises a
corresponding deficit unless the execution supplies real progress and view
delivery. That cannot create a security bound by algebra alone.

### 3.1 A nontrivial early-window reduction

Suppose the later node already has any complete adoptable chain `Q` containing
`b`, even if `Q` omits some or all of the six successors seen at `tau`. Let

\[
g=S(Q)-S(p)>0.
\]

Since `S(D)=M_v-q_v >= S(Q)-q_v`, the same prefix decomposition yields

\[
A(c)+H_{\rm off}(c)\ge g-q_v(c)-B_0.\tag{4}
\]

If an independently justified envelope gives `g >= g_*`, `q_v <= s`,
`H_off <= h`, and `B0 <= i`, then

\[
A(c)\ge g_*-s-i-h.\tag{5}
\]

The early threshold is positive exactly when the delivered score margin
exceeds those charged terms. This does not require full anchor delivery or
all honest nodes already sharing `b`. The synthetic partial-delivery fixture
has `g=1`, `q=0`, `B0=0`, and `H_off=0`, and a rival unit-weight adversarial
block reaches the lower bound `A=1`. Those integers are model units, not a
calibration of native attacks.

If the observation node has not received `b` at all, no positive `g` is
available. The all-honest unseen-anchor fixture has `D=genesis`, `A=0`, and
`L_avail=K_b=7` immediately after another node confirms. It witnesses a
cross-view prefix mismatch without any local rollback or adversarial work.
Finite propagation delay and six successors alone do not exclude this early
event. A positive universal early threshold therefore cannot be obtained from
those premises alone.

## 4. A conditional later-window pacer lemma with paid selection lag

This section is a mathematical implication under explicit environment
contracts. The finite checker audits some of those contracts on a declared
window; it explicitly does **not** claim to verify this stopped-process theorem
or to estimate its probability of holding in a real network.

Let the finite analysis set contain every honest observation node under
comparison, the initial confirming node, and every relevant honest miner. A
new node needs an explicit bootstrap contract before inclusion. Assume:

1. At `tau`, an honest provider can actually serve every required part of
   `C0`. Confirmation alone does not establish restoration after pruning.
2. `C0`, and every honest pacer used below, becomes a complete, valid,
   timestamp-eligible candidate at every node in the analysis set within
   `Delta_pub` after its designated start/completion time. Queueing,
   transmission, full proof and application validation, timestamp eligibility,
   and admission delays belong in this contract. An already delivered baseline
   or a no-lower-score qualified chain containing `b` remains usable for parent
   selection and comparison. A cached number is insufficient. This contract
   need not require arbitrary future-dated private chains to become eligible
   within `Delta_pub`.
3. Every relevant honest completion occurs within `Gamma` after its final
   binding to the parent on which it produces its proof. A justified stale-task
   cancellation bound can supply this premise. A bound measured only from
   proof completion to publication cannot supply it.
4. Every relevant honest binding has raw score lag at most `s_H`; every failure
   observation has raw score lag at most `s_V`. Define `ell=max(s_H,s_V)`.
   These are score deficits. Bounded elapsed selection time does not imply
   bounded score deficit without a separate arrival/inventory envelope.
5. All honest pacer weights are at most `w_max`; all quantities use the same
   causal cuts and physical clock. Ready accounting and initial inventory
   coverage are as in Sections 2–3.

At a cut define the common lower frontier

\[
P_b(c)=\min_v\max_{C\in V_v(c),\ b\in C}S(C).
\]

The delivery/retention contract gives `P_b >= S(C0)` after the anchor is fully
delivered. Set `r=t_tau+Delta_pub` and `s=r+Gamma`. At each physical deadline,
take the cut after **all events** at that time, including completions and
deliveries; a cut earlier in the same
timestamp still belongs to the pre-delivery case. Let `rho` be the first cut
at or after `r` at which any ready `b`-free chain `F` has

\[
S(F)\ge P_b(\rho)-\ell.\tag{6}
\]

This first crossing ranges over **all causal cuts**, including view loss or
frontier change, rather than only new block completions. A `b`-free
observation at a cut `c` **at or after the full anchor-delivery deadline cut
`r`** implies such a crossing with `rho <= c`, because its selected score is at least
its own available `b` frontier minus `s_V`, and hence at least `P_b-ell`.
Starting the search only at `s` would be incorrect: a `b`-free parent chosen
between `r` and `s` can complete after `s`. The search starts at `r` even
though pacers start after `s`.

Let `H_init` be all new honest `b`-free ready weight in `(tau,s]`. Greedily
choose honest ready completions strictly after `s`, with physical completion
spacing strictly greater than `L=Delta_pub+Gamma`, up to cut `rho`. Each pacer
of weight `w_j` is credited paid progress

\[
g_j=[w_j-s_H]_+,\qquad J_g(\rho)=\sum_{j\text{ by }\rho}g_j.
\]

**Conditional pacer lemma.** Under the five contracts, a failure observation at
a cut `c >= r` implies a cut `r <= rho <= c` satisfying

\[
A(\rho)-J_g(\rho)
\ \ge\ K_b-B_0-H_{\rm init}-w_{\max}-\ell.\tag{7}
\]

An observation before the deadline cut `r`, including one earlier within its
physical timestamp, is handled by (3)–(5), not by (7).

**Proof.** Before `rho`, no honest binding at a cut `beta >= r` can use a
`b`-free parent. Otherwise that ready parent has score at least the binding
node's maximum minus `s_H`, hence at least `P_b(beta)-ell`, producing an
earlier crossing. Consequently every honest `b`-free completion before or at
`rho` was either bound before `r` and completes by `s`, or, if `rho <= s`,
already lies in `(tau,s]`. In both cases `H_off(rho) <= H_init`.

When `rho <= s`, no pacer has yet been selected and `J_g=0`. For `rho > s`,
every pacer before the crossing contains `b`. Its final parent binding is
strictly after `r`, and, after the first pacer, strictly after full delivery
of the previous pacer: `t_j-Gamma > t_(j-1)+Delta_pub`. Retention therefore
lets the binding node compare against the best previously delivered pacer
baseline. A raw parent lag of `s_H` makes the next pacer's score at least
the previous baseline plus `w_j-s_H`. Retaining the old baseline when the
increment is negative gives an increase of at least `[w_j-s_H]_+`.

At the crossing, any not-yet-fully-delivered selected pacer completed in the
closed physical interval `[t_rho-Delta_pub,t_rho]`; a same-timestamp but
causally later completion is not included. Strict spacing greater than
`L >= Delta_pub` leaves at most one such pacer. Since `g_j <= w_j <= w_max`,
the common frontier is at least

\[
P_b(\rho)\ge S(C0)+J_g(\rho)-w_{\max}.
\]

The ready chain `F` witnessing (6) has score at least that quantity minus
`ell`. Its pre-`tau` prefix is covered by `B0`, its new adversarial suffix by
`A`, and its new honest suffix by `H_init`. Subtract `S(p)` and rearrange to
obtain (7). This proof never assumes that CP itself already holds on an
unnamed good event. QED.

The loss `s_H` is paid for each pacer. Replacing it by a single endpoint loss
would overstate accumulated honest progress. If every `w_j <= s_H`, the
lemma permits `J_g=0`; it does not manufacture positive progress. `w_max`
pays one unresolved spaced pacer, not an arbitrary batch. The unit-weight
batch fixture demonstrates why a per-block cap does not bound all arrivals
within a time interval.

## 5. Probability composition without conditioning away the problem

The resource and execution certificates can be composed only after a proved
identity bridge: the **same accepted work relation**, distinct-output identity,
credit timing, and score/weight normalization must define their process `A`.
The MU1 research counter's `16*u` credit is not the current native
`required_work(target)` score. That future credit rule has not been activated
and no conversion theorem in this note makes the two processes identical.
Giving them the same letter does not authorize substitution into present
six-successor arithmetic. The bridge also needs compatible origin and state
admissibility: a fresh-epoch resource theorem cannot silently assume fresh
state again at a later random confirmation cut.

For a probabilistic statement, `tau` must be a stopping time of the **joint**
filtration containing honest, adversarial, network, clock, scheduler, and
residual-state information. Every chosen parameter or envelope at `tau` must
be measurable there. Subsequent `A`, resource use `R_res`, view deficits,
inventory carry-in, and pacer progress must be adapted to that filtration.
An unconditional fresh-lifetime query bound can instead cover a fixed epoch:
the epoch's total output dominates post-confirmation new output, and valid
event inclusion or a paid union bound may be applied under that original
epoch law. It does not thereby become a conditional post-confirmation bound.
A conditional state certificate is needed for the latter claim.

For example, if `d>0` is a `tau`-measurable lower bound on the right side of
(7), and the failure of the explicit later-window contracts has conditional
probability at most `epsilon_late`, then

\[
\Pr[\text{later failure}\mid\mathcal F_\tau]
\le\epsilon_{\rm late}
+\Pr[\exists c:\ A(c)-J_g(c)\ge d\mid\mathcal F_\tau].\tag{8}
\]

The probability in the second term is under the **original probability law**,
not the law conditioned on the future contracts holding. A per-block failure
probability for `Gamma` is not a whole-execution `epsilon_late`; random block
counts and adaptive schedules require a valid union/anytime argument. Without
such an argument, the contract failure term remains unknown.

An optional bridge to the resource certificate is valid if that same law has
a nonnegative supermartingale dominating
`exp(theta*A-kappa*R_res)`, with value `V_tau` at the initial cut, and an
environment envelope. Require `theta>0`, `kappa>=0`, finite `V_tau`, and
`theta`, `kappa`, and `m` measurable in `F_tau`. The envelope must hold at every
analyzed cut, or its whole-execution failure probability must be included in
`epsilon_late` (otherwise add a separate `epsilon_env`):

\[
\kappa R_{\rm res}(c)-\theta J_g(c)\le\theta m.
\]

The crossing then implies

\[
\theta A(c)-\kappa R_{\rm res}(c)\ge\theta(d-m),
\]

so the conditional later-window bound is at most

\[
\min\{1,\ \epsilon_{\rm late}+V_\tau e^{-\theta(d-m)}\}.\tag{9}
\]

All four terms are hypotheses to certify; no file here supplies native values.
If the resource/progress envelope holds only on an environment good event,
its failure probability must also be included in `epsilon_late`, along with
the failures of any proposed random `B0` or `H_init` upper bounds. Future good
events must not be conditioned away. Measurability of `d` at `tau` requires
proved prior lower/upper envelopes; it forbids selecting `d` after observing
the eventual `H_init` or the favorable realized execution.
For `d<=0` only a trivial risk bound is asserted. Residual preprocessing and
partly finished output belong in `V_tau` or an explicit carry-in; a plain
output inventory does not account for those states.

For the early window, (5) instead gives an explicit crossing threshold when
the delivered-prefix, score-lag, honest off-branch, and inventory envelopes
have a positive net margin. Their failure probability is a separate
`epsilon_early`, not “the probability CP fails early.” Split early and later
events using (3)–(7), then combine their valid tail events and contract-failure
probabilities by a union bound or a proved single-boundary supermartingale.
Without a positive early delivered-prefix premise, the early contribution
can be one. Neither an abstract later-window exponential nor an optimistic
default may remove it.

## 6. Six successors: native arithmetic and limits

The installed six-successor profile requires both successor count at least
six and subsequent work at least `6*required_work(target(b))`. In the present
native unit relation, `w(b)=required_work(target(b))`, so

\[
S(C0)-S(b)\ge6w(b),\quad K_b=S(C0)-S(parent(b))\ge7w(b).
\]

The target block's own weight is part of the fork-cut margin, while the work
confirmation threshold covers its successors. Six low-work successors need
not satisfy the work condition. The Python fixture applies this formula to
supplied weights, and reports `native_weight_relation_validated=false`: it
does not derive those weights from actual targets or execute W1 validation.

If a future mandatory-unit design changes credit to `w(b)=u_b*d_b` but leaves
the current confirmation code at `6*d_b`, the justified arithmetic is
`K_b >= w(b)+6*d_b`, not automatically `7*w(b)`. A formula test cannot silently
ratify a new production credit rule. The actual six-successor risk still
needs the resource-tail theorem, source-valid weight relation, physical
execution/environment envelopes, and the early/later mapping above.

## 7. Executable certificate contract and evidence classes

The checker accepts bounded JSON with exact fields, duplicate-key rejection,
integer score/time fields, unique blocks, a positive rooted tree, a complete
initial record, owner/generation bindings, a causally ordered event sequence,
and explicit window/coverage declarations. Limits are 512 non-genesis blocks,
8192 events, 32 owners, 256 comparisons, and 2,000,000 snapshot cells. Input
files larger than 8 MiB are refused. These bounds are checker limits, not
protocol parameters.

| Event or field | What the finite replay checks | What it does not establish |
| --- | --- | --- |
| `ready` | First unique credit; parent already ready; all declared body/proof/application material present; honest output has prior final parent binding. | Authentic proof validity, true physical completion, or completeness of a malicious party's hidden inventory. |
| `available` | Declares a complete eligible candidate and its ancestry in this node's view. | A header receipt is insufficient; actual W1/application/timestamp replay is absent. |
| `header` | Records no new full candidate. | Header time is not used as an execution clock. |
| `lose_available` | Removes candidates depending on the lost data, without deleting historical ready credit. | Recovery or retained provider service is not invented. |
| `bind` | Binds a declared honest output to that owner's currently active available parent and records its raw score deficit. | A real miner cancellation/elapsed-completion guarantee. |
| `select` | Strict submitted-target versus incumbent rule, owner instance, and generation transition. | Instantaneous global maximality. |
| `observe` | Current owner/generation/tip, inclusion, and six-plus-work formula in the supplied score model. | Actual native confirmation attestation or consensus validity. |
| `resource` | Separate logical gates, CPU ns, and bytes; no dimensional conversion. | Minimum unavoidable cost, quantum accounting, or a calibrated resource-to-output tail. |
| provenance / hashes | Syntactic origin role consistency and source-bound evidence readback. | Authenticity merely because a string says native or resembles a signature. |

Omitting clock, owners, scope/coverage, initial state, or residual-state fields
fails schema checking. Unknown residual state or explicitly partial coverage
can be represented for an incomplete record, but never qualifies native
security. Claimed complete finite coverage must include every block in the
declared universe in its ready ledger by the end. This detects a missing
catalogued output; it cannot detect a deliberately omitted private universe.

The report keeps these classes separate:

| Result class | Meaning in this version |
| --- | --- |
| `record_schema_and_finite_algebra_valid` | True only after structural replay and requested deterministic inequalities pass. |
| `complete_declared_model_checked` | True only for the supplied finite universe with both completeness declarations. This is model completeness, not attested world coverage. |
| `native_runtime_attested` | Always false: no independent native lifecycle/clock trust adapter is implemented. |
| `probabilistic_environment_bound` | Always false: no physical rate, scheduling, delay, retention, or inventory failure envelope is proved. |
| `six_successor_risk_qualified` | Always false. |
| `native_execution_qualified` | Always false; `--require-native-qualification` exits 2 with an explicit refusal. |

An input coherently relabeled `observed_native`, with owner strings, hash
digests and a claimed physical clock receipt, remains an **unattested native
record conversion**. It cannot turn these flags true. There is no successful
native attestation stub, native probability default, or fake numerical tail
parameter in the schema.

`check_window_contract` checks declared finite-window weight bounds, binding
durations, sampled binding/observation score lags, anchor/pacer publication,
and view retention. It checks the state at the end of each delivery deadline,
then later cuts; lack of a later event cannot make a missing delivery pass
vacuously. A deadline beyond the supplied window is explicitly censored.
Comparisons at earlier causal cuts within the same deadline timestamp keep
their own deficits. The helper sets `checks_are_not_a_stopped_pacer_theorem`
to true and does not certify a probability or an unsupplied infinite window.

## 8. Model counterexamples, reproduction, and open obligations

The evidence contains eight model fixtures and nine compared observation
pairs: unseen anchor, positive partial delivery, known heavier pending chain,
hidden completed inventory, honest stale-parent pipeline, all-honest burst
within a finite eight-tick full-delivery bound, same-timestamp future
completion, and unit-weight batch release. Every pair is accounted by (2) and
(3). The early positive fixture illustrates (4); it is not a native risk
estimate. The weight-100 fixture makes selection lag observable instead of
assuming it away. The honest pipeline and honest burst show why total honest
production cannot simply be subtracted as useful competing-chain resistance.

From the repository root:

```sh
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_native_execution_certificate.py' -v
python3 formal/pon-nakamoto-v1/native_execution_certificate.py --verify-evidence evidence/pon-work-native-certificates-20261107/native_execution/model_evidence_v1.json
```

`--write-evidence NEW_PATH` creates a new source-bound evidence file without
overwriting an existing one. Evidence verification recomputes the model
traces, reports, and exact source bindings. Tampering with a result or bound
does not pass readback.

The remaining security obligations are concrete: authenticate physical ready
and final-parent-binding events and all analyzed views, cover initial and
hidden state and all competing forks, prove the actual mandatory-work
resource tail including selection/reuse/batching/residual state, and provide
joint-filtration environment bounds for the score deficits, honest competing
work, propagation/validation/availability, progress, and parameter transitions.
Source inspection plus finite model algebra is a useful verified bridge, but
does not close those empirical and scientific obligations. No general CP
probability, actual native six-successor risk, or qualification of the third
candidate is claimed here.
