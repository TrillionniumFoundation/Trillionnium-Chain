# Dynamic participation without resetting the consensus argument

Status: **conditional mathematical extension and finite declared-record checker;
native common prefix, chain growth and chain quality remain HOLD_NO_GO**.

This extends the fixed finite honest-node set in
[Native fork mapping, section 3.4](../../../../formal/pon-nakamoto-v1/NATIVE_FORK_MAPPING_V1.md).
That contract already handles full propagation/validation delay, stale parent
tasks, private inventory, honest competing branches, all-candidate selection and
same-timestamp causal order. Those results are retained. The added boundary is
how joining, leaving and returning participants enter that argument without
resetting its score floor, outstanding tasks or resource account.

Implementation: [finite checker](../../../../formal/pon-nakamoto-v1/dynamic_participation_v1.py)
and [lifecycle tests](../../../../formal/pon-nakamoto-v1/test_dynamic_participation_v1.py).
The [development plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
remains the sole engineering plan. This is not a new membership authority,
checkpoint, native confirmation policy, permission to mine, or deployment rule.

## 1. Different kinds of participation

An online machine, an honest miner, a fully synchronized observer and a producer
whose complete output is available to the relevant observers are different
objects. Only the process justified by the analysis can supply its honest
progress term. The classification does not stop other machines from operating;
their relevant output and cost remain accounted for.

Let `Q(c)` be the finite set of qualified honest participants at causal cut `c`.
It can change. Qualification is an analysis condition on an actual complete
view and task lifecycle, not a signature or a self-declared class of miner.
The model is locally finite and uses a common physical analysis time together
with a total causal event order. Header timestamps do not supply this clock.

Every task retains its original participant generation, parent binding and
resource account. A new process or a return after absence does not create a
fresh copy of an old task. Qualification at parent binding is retained; later
synchronization cannot retroactively improve it. An output from a departed or
replaced generation is conservatively put in the carryover account. Cancel
requests do not certify that computation stopped or that no late output exists.

Historical confirmations also survive departure. A returning observer's new
view is compared against the original reference and outstanding obligations;
the observer does not acquire a fresh safety budget merely by reconnecting.

## 2. A current score floor and inherited deadlines

Fix an actual confirmed reference `(b, tau, C0)` with score `S0=S(C0)`. As in
the existing native mapping, define

\[
K_b=S(C_0)-S(\operatorname{parent}(b))\ge 7w(b).
\]

The last inequality uses the installed six-descendant **and** six-times-work
gates. It is not a risk probability. The checker below does not replay these
gates; its `reference_score` is a supplied model number.

Retain the existing full-service bound `Delta_pub`, parent-binding-to-complete-
output bound `Gamma`, and positive maximum block weight `w_max`. Full service
includes body, proof, ancestry, state dependencies, time eligibility, validation,
retention and selection readiness at each relevant recipient. Set
`L=Delta_pub+Gamma`. These are conditional bounds, not measured WAN parameters.

After `tau+L`, select qualifying honest complete outputs by the same fixed greedy
rule: the first eligible output, and then the first whose completion time is
strictly more than `L` after the previous selected output. Let `J(c)` be the
sum of their weights by cut `c`. A selected output is called a *pacer*. Its
full-service deadline is its completion time plus `Delta_pub`.

Use the nondecreasing analysis floor

\[
F(c)=S_0+J_{\rm matured}(c),
\]

where maturation means the original full-service deadline has resolved on the
same causal timeline. The sufficient dynamic-cohort contract requires:

1. At entry, a participant has a fully valid, time-eligible and retained chain
   of score at least the **current** `F(c)`, and selects a maximum-score chain
   from its complete eligible view when binding a counted task.
2. Existing participants retain the required floor. Each pacer's original
   delivery deadline applies to every participant qualified at that deadline.
   A participant joining while a deadline is pending inherits that deadline;
   joining does not grant a new `Delta_pub` interval.
3. Departure does not cancel a provider's service responsibility, make its
   outstanding tasks disappear, erase previously ready output, or reset the
   carried classical/quantum progress account. If the contract cannot still be
   served, its failure remains a bad event or an explicit accounting deficit.

Entry at the original `S0` is insufficient after the floor has advanced.
Waiting until a bootstrap is complete may be necessary. This statement supplies
no bound on how quickly bootstrap can finish or on the number of participants
that can remain qualified.

The entry condition does **not** assume that the entrant already agrees on `b`.
Before the first complete `b`-free chain reaches the current floor, any complete
chain meeting the floor necessarily contains `b`. This observation supplies the
prefix conclusion inside the proof; it is not a trusted-finality premise.

For a finite supplied trace, deadlines at one timestamp are conservatively
resolved after all supplied events at that timestamp. Earlier cuts at that same
time still use the previous floor. A later view cannot repair an earlier missed
deadline. A deadline beyond the evidence window is censored, not successful.

## 3. A conditional dynamic-cohort fork witness

Use the same all-branch, first-ancestry-complete ready accounting as the existing
native mapping. In particular, partial work before a window belongs to its
initial residual state; later publication of a previously counted identity does
not create fresh credit. Let:

| Quantity | Meaning |
| --- | --- |
| `A(tau,c)` | New adversarial ready credit across all relevant branches, each distinct identity counted once |
| `B0` | A proved upper bound on relative `b`-free ready inventory at `tau`, including hidden chains |
| `B_H` | A proved bound on **all** new honest ready weight in the startup interval `(tau,tau+L]` |
| `E(tau,c)` | Honest ready weight after startup excluded from the qualified process: entry tasks, old generations, cancellation carryover, absent service and other explicitly excluded outputs |
| `J(c)` | The single globally defined qualifying pacer process, without a separate retrospective selection for each fork |

The startup interval uses causal cuts: it starts just after the reference cut
`tau` and ends after all supplied events at physical time `time(tau)+L`. It
therefore includes later events at the reference timestamp, also when `L=0`;
those events are not silently treated as empty elapsed-time history.

`E` is a conservative credit debt, not an assertion that honest newcomers are
malicious. It may include safe work. Its purpose is to avoid losing potentially
competing work when the participant set changes. Work that fails the actual
validity relation gets no consensus credit, but its resource costs still remain.

**Conditional proposition.** Assume the original fork-mapping premises for
work validity, complete views, maximum-score selection, retention, readiness,
initial residual state and physical time. Replace the fixed participant set by
the dynamic contract in section 2. All outputs in the qualified process obey
its binding and lifecycle assumptions; its selected pacers obey the stated
bounds. Relevant honest outputs outside that process are charged to `B_H` or
`E`. Eligible but unpaced outputs remain in the qualified process and need
not be charged to the entry debt.
If the original confirmation is later removed at a qualified observer, or a
qualified observer has a relevant conflicting prefix after the required initial
service window, there is a prior causal cut `rho` for which

\[
\boxed{A(\tau,\rho)+E(\tau,\rho)-J(\rho)
       \ge K_b-B_0-B_H-w_{\max}.}
\tag{D1}
\]

**Proof.** Consider the first ready `b`-free chain reaching the analysis floor.
If such a chain is already present at `tau`, then `B0>=K_b` and the useful gap
is already nonpositive. Otherwise, before this first competition, a qualified
maximum-score parent meets the floor and therefore contains `b`.

A qualifying output completed after `tau+L` has its final parent bound after
`tau+Delta_pub`. Every subsequently selected pacer is separated by more than
`Delta_pub+Gamma`; thus its parent-binding cut occurs after the preceding
pacer's original delivery deadline. A participant already present then retains
that floor; a participant entering later must bootstrap to the same current
floor. Induction gives the pacer's completed chain score at least `S0` plus
all paced weight through that output. No shared physical ancestry between
pacers is required; the additive score lower bound suffices.

At each original maturation deadline the delivery obligation establishes the
accumulated score floor at every then-qualified observer. Later entrants
bootstrap to that same current floor; their qualifying chain may differ from
earlier pacer chains. Retention preserves this lower bound on each currently
qualified observer's maximum fully eligible score. A conflicting selected chain at a qualified
observer consequently implies a first competition cut `rho`. In local native
replacement the actual comparison is strict; the necessary first-competition
event uses the conservative non-strict comparison needed across observers too.

Before `rho`, any honest output after startup not charged to `E` descends from
a qualifying parent and contains `b`. A competing chain's score above
`parent(b)` is therefore at most `B0+A+B_H+E`. At `rho` it is at least
`K_b+J_matured`. The pacer spacing is strictly greater than `L>=Delta_pub`, so
at any causal cut at most one already completed pacer has an unresolved
delivery deadline. Hence `J-J_matured<=w_max`. Combining these inequalities
gives (D1). Departures do not remove terms, and entry cannot lower the floor.
The argument is conditional on the explicitly listed operation contracts.
QED.

The theorem concerns the process stopped at first competition. Requiring the
same floor/view contract on an entire finite record is a stronger diagnostic
condition. A later deficit does not retroactively falsify an earlier mathematical
cut; it does prevent the checker from labeling the whole supplied window a pass.

## 4. Probability, growth and quality still require new premises

The existing exponential crossing lemma can be applied only after proving a
uniform conditional law for the **combined** increments

\[
X_i=\Delta A_i+\Delta E_i-\Delta J_i.
\]

Alternatively one may pay a justified simultaneous bound on `E` as an added
margin. A tail for adversarial production alone does not cover newly excluded
honest work. Average machine counts, an average hash share, or favorable average
costs do not prove this conditional law under adaptive participation.

If, as a separate mathematical premise, `E[z^X_i | F_(i-1)]<=1` uniformly for
some `z>1`, the existing crossing lemma supplies its conditional weighted-gap
bound. Actual W1 resources, quantum residual states, helper information, all
strategies, repeated starts and the union of timing/qualification failures
remain part of that premise. The checker neither estimates `z` nor emits a
numerical native failure probability. Conditioning on a future event that all
bootstrap or delay bounds succeeded is not a valid substitute for a stopped or
coupled process with paid bad-event probability.

Dynamic participation also requires a lower-tail law for qualifying progress
to establish chain growth. If all qualified producers can leave for an
arbitrarily long interval, no positive physical-time growth rate follows.
Admitting more entrants with unknown views cannot repair that logical gap.
Weighted chain quality needs the existing stable-segment mapping and production
bounds with `E` included; count quality additionally requires a bounded weight
ratio. A finite cohort trace proves none of these stochastic or native premises.

## 5. Finite checker and exact scope

`audit_dynamic_participation(document)` accepts only schema
`pon-dynamic-participation-v1`. It records a finite supplied model, using exact
integer arithmetic and a causal event sequence. The event kinds are `join`,
`view`, `qualify`, `leave`, `bind`, `ready`, `charge`, `cancel`, and
`finish_without_output`. Initial carry-in tasks retain their original identities.

`view_score` denotes the declared maximum score of a fully verified, eligible,
retained chain; a `ready` task denotes one distinct complete eligible output.
The checker sees labels and scores. It does not authenticate maximum views,
native target/work validity, output uniqueness, cryptographic proof, hidden
branches, real clock observations or complete provider retention. A source hash
or `complete_events_as_declared=true` does not supply those facts.

The checker separately totals startup debt, entry/carryover debt, paced credit,
eligible but unpaced credit, and unclassified credit. These form an exact
partition of the declared ready weight. Failed tasks and cancelled or unfinished
attempts retain their original cost account. `initial.resource_units` is the
declared common, non-task initial charge; it must be disjoint from the separately
listed charges in `carry_in_tasks`. The arithmetic cannot authenticate that
allocation or make model units physical resource measurements.

All bound, cost, parent, provider and view unknowns stay unknown. An absent
completion is an unresolved task. Missing coverage, censored deadlines,
old-generation rewrites, task duplication, unknowns and view deficits cannot
silently become successful progress. Even a finite diagnostic pass with zero
pacers explicitly reports that no paced progress was observed.

The limits are 10,000 supplied events, a 4 MiB CLI input, 64-bit model times and
512-bit nonnegative accounting values. These are checker resource limits, not
claims about a network-wide task count, admissible work range or mining cost.
The result always retains:

```text
qualification = HOLD_NO_GO
native_common_prefix_qualified = false
native_chain_growth_qualified = false
native_chain_quality_qualified = false
native_six_successor_risk_bound = null
native_common_prefix_failure_bound = null
native_chain_growth_bound = null
native_chain_quality_bound = null
production_activation = false
```

Run the scoped controls from the repository root:

```bash
bash scripts/project-preflight.sh --audit
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p test_dynamic_participation_v1.py -v
python3 formal/pon-nakamoto-v1/dynamic_participation_v1.py --check /path/to/declared-model.json
```

The CLI returns success only for a complete passing declared finite contract.
`--require-native-qualification` always returns a refusal, including after a
finite pass. The tests use benign score/lifecycle records, malformed inputs and
missing evidence. They generate no native blocks, conduct no network experiment
and establish no production membership mechanism.

Actual continuation requires an authenticated adapter from the original
native owners, independently justified clock and service bounds, complete
carry-in and resource coverage, quantitative dynamic participation assumptions,
and the same-source native failure reduction. This finite extension identifies
and checks the missing handover contract; it does not close those qualifications.
