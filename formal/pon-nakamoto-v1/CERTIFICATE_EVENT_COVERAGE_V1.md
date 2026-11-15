# EC1: complete finite-record events before conditional risk accounting

## 1. Result and exact scope

EC1 closes a finite-model event-coverage gap in the existing risk bank. It
replays **every raw execution assigned to every probability-tree leaf**,
derives every recorded confirmation, and derives every later recorded view or
selection cut at which that confirmation's included block is absent. A risk
declaration must contain exactly this complete event catalogue. It cannot
silently omit a second confirmation, omit a failing leaf, or move the first
confirmation to a history selected after its outcome.

This is an executable theorem about a **declared finite joint execution law**.
It is not a validation of the world's probability law, a measurement of hidden
inventory, a native execution attestation, or a six-successor security level.
The law and its complete records remain mathematical premises. The output
retains `native_six_successor_risk_certified=false`, a null native failure
probability, and `production_qualified=false`.

Implementation: [certificate_event_coverage.py](certificate_event_coverage.py).
Adversarial tests:
[certificate_event_coverage_tests.py](certificate_event_coverage_tests.py).
Dependencies are the unchanged deterministic
[native execution model](native_execution_certificate.py) and the existing
[conditional risk bank](certificate_observability_models.py). EC1 does not
change native chain scoring, W1 or MU1 bytes, a signing domain, or stored
production schemas.

## 2. What the old bank proves, and what EC1 adds

The old `check_predictable_risk_bank` correctly verifies the events supplied
to it. Its caller specifies each event's `failure_leaves`. A caller can supply
only the first of two relevant events, and the bank will correctly bound that
first event. This does not establish a bound on the second event or on both.
The old API explicitly claims only its declared-event scope; EC1 adds a
source for the complete event set rather than changing that arithmetic.

`check_event_coverage` never accepts a serialized verified catalogue. It:

1. Reconstructs `ProbabilityTree` from its leaves, rechecking probabilities,
   prefix-free histories, and total mass. Cached mutable node sets are ignored.
2. Requires the execution mapping's keys to equal the whole leaf set. Every
   value must contain a raw `Execution` document and its history cuts.
3. Copies each document through strict canonical JSON, replays it with
   `native_execution_certificate.Execution`, and requires its two complete
   finite-record scope declarations. These declarations remain assumptions
   about the supplied model, not authenticated world coverage.
4. Checks the filtration rules in section 3 and derives all relevant events
   under the definition in section 4. The document's optional `comparisons`
   list is validated but never used as the coverage catalogue.
5. Requires exact equality of the allocated start set, each origin history,
   and each failure-leaf set with the independently derived catalogue.
6. Invokes the old bank on those derived events under the same reconstructed
   law. Conditional risks are recomputed from the entire joint law; no LQC
   theorem label or self-declared probability is trusted instead.

There is no requirement that the different failure events be independent.
There is also no promotion from a passing numeric check to a true physical
resource or random-oracle premise.

## 3. A record filtration with observable branches

For a leaf with probability history `(h1, ..., hd)`, `history_cuts` supplies
one original event-sequence cut for each of `()`, `(h1)`, ..., the full leaf.
Cuts are strictly increasing and the final cut equals the complete record's
last event. Every recorded confirmation must occur **exactly** at one cut.
This prevents batching past a confirmation and assigning it a later origin.

At each history node, all descendant leaves must have exactly the same record
prefix and cut. Prefix equality compares the original canonical frames, not
only their SHA-256 hashes. The initial frame includes source anchor, clock
declaration, fixed horizon, owners, complete initial record, and descriptions
of initially ready blocks. Each later frame includes its original event and
descriptions of newly referenced blocks and ancestors. Unused future blocks,
leaf-specific evidence names, and requested comparison lists are not revealed
by a prefix. Hashes in the output identify these checked inputs; they do not
authenticate their physical origin.

Distinct children of one history node must have **incomparable record
prefixes**. Neither child's complete prefix may equal or be a prefix of the
other's. Thus different future-outcome labels attached to the same unchanged
record are rejected with `HISTORY_SPLIT_NOT_OBSERVED`. A caller cannot choose
different prefix lengths along an identical record and treat the difference
as an observed random outcome either.

These are deliberately restrictive admissibility conditions for a finite
record tree. They exclude unrecorded random revelations and unresolved hidden
branches. They are not a general reconstruction of every possible stopping
time or public filtration. In particular, EC1's observer sees the **complete
declared execution record**, including recorded private-ready and resource
events. It is not automatically the knowledge of an individual node, the
public, or an adversarial quantum coalition. A theorem using one of those
filtrations needs a separate proved bridge. The explicit flag
`actual_public_or_coalition_knowledge_authenticated` remains false.

Unary history steps are allowed. They represent deterministic further record
prefixes without new branching. A root cut may contain a common deterministic
prefix, but it may not skip an earlier recorded confirmation. A later process
or owner name cannot remove an earlier origin from the complete catalogue.

## 4. The complete target event within the supplied records

For each original `observe` event for which `Execution` independently
recomputes `confirmed=True`, EC1 creates a start. Its identity binds the
namespace, owner, configuration digest, observation identifier, and exact
history cell. The included block and selected tip are taken from the replay.
The start must occur in every leaf descending from that cell.

For each start, EC1 enumerates every later original `observe` event and every
later original `select` event in that execution, across the declared owners.
A selection is evaluated at its original post-event `Execution.cuts` state.
The unchanged `Execution.compare` checks every pair and, when the included
block is absent, recomputes its existing paid-deficit inequality.

A selection-cut evaluation is labeled `replayed_selection_cut`. It is a
deterministic inspection of an original recorded transition, **not** an
additional native observation, execution, or stochastic sample. This closes
an important finite-record hole: an inclusion can be removed and restored
between two explicit observations. Testing only the later observation would
miss that transient removal. A dedicated test constructs both possibilities,
checks that the old explicit comparison reports no failure, and checks that
EC1 still derives failure from the intervening selection.

The leaf belongs to that start's event if at least one of these later views
omits its included block. Several failing views on the same leaf contribute
one event occurrence. All starts, including starts with empty finite-horizon
failure events, must be present in the allocation. Repeated confirmations
are separate starts and their allowances must all be paid on a path.

This is the target event **only over the supplied bounded record horizon**.
It does not certify future persistence beyond the last event, omitted
observers, unrecorded recovery transitions, or real-world adoption. Network
availability, timestamp eligibility, physical clocks, relation validity and
all-world coverage are not established by this model check.

## 5. Complete-event composition theorem

Let the finite probability tree have leaves `omega` with positive masses
`p(omega)` summing to one. For each automatically derived start `j`, let
`S_j` be its history cylinder and `F_j` the derived failure leaves. The checks
above establish, within this declared record model:

\[
F_{\rm records}=\bigcup_j F_j,\qquad F_j\subseteq S_j.
\]

Let `a_j` be an allowance fixed at that start's history cell. The bank checks

\[
\frac{\Pr(F_j)}{\Pr(S_j)}\le a_j,
\qquad
\sum_{j:\,\omega\in S_j}a_j\le\alpha
\quad\text{for every leaf }\omega.
\]

All probabilities and allowances use exact rational arithmetic. Then

\[
\begin{aligned}
\Pr(F_{\rm records})
&\le \sum_j\Pr(F_j)\\
&\le \sum_j\Pr(S_j)a_j\\
&=\sum_\omega p(\omega)
       \sum_{j:\,\omega\in S_j}a_j\\
&\le\alpha.
\end{aligned}
\]

The first equality defining the target union is the extra fact EC1 checks.
The inequalities are the existing bank's calculation. Correlated events,
overlapping windows, and history-dependent starts do not require an
independence assumption. They require one joint law and complete spending.
The conditional ratios in this theorem are properties of the supplied law;
they are not estimated from one native run.

## 6. Executable counterexample: an omitted second confirmation

The fixture uses two sequential confirmation opportunities with independent
Bernoulli outcome probability `p=1/16`. These labels are implemented by full
synthetic `Execution` records. The first inclusion is restored before the
second confirmation. The second competing branch preserves the first
inclusion, so later comparisons do not introduce an unintended extra first
failure. Both original comparison lists are empty: EC1 must derive the events.

There are four probability leaves and three history-specific start cells:
the first confirmation at the root, and the second confirmation in each of
the first outcome's two cells. Every start has conditional risk `1/16`.
Every path pays two allowances, so the shared budget is `1/8`.

\[
\Pr(F_1\cup F_2)=1-(15/16)^2=31/256.
\]

Giving only the first event to the old bank correctly yields `1/16` for that
event. Giving the same partial declaration to EC1 fails with
`CONFIRMATION_START_COVERAGE_MISMATCH`. Removing one failing leaf fails with
`FAILURE_EVENT_COVERAGE_MISMATCH`. Moving the first allocation to a later
history fails with `START_HISTORY_MISMATCH`. An attempted future-label
refinement before any record difference fails with
`HISTORY_SPLIT_NOT_OBSERVED`.

## 7. Executable counterexample: identical marginals, different joint risk

Two additional full execution families have the same initial competing
inventory marginal and the same honest reference-progress marginal:

\[
\Pr(B=0)=\Pr(B=8)=1/2,\qquad
\Pr(G=0)=\Pr(G=2)=1/2.
\]

The confirmed inclusion has seven units of total score from its parent.
An eight-unit competing packet is complete before confirmation on stocked
leaves, remains unavailable to the confirming owner until later, and is then
presented to native-model strict selection. Honest progress, when present,
extends the inclusion's branch to score nine. The examples use the existing
model's exact selection and deficit rules, not a caller-authored failure bit.

| Joint law | Equal-probability outcomes `(B,G)` | Derived failure probability |
|---|---|---:|
| Together | `(0,0)`, `(8,2)` | `0` |
| Opposite | `(0,2)`, `(8,0)` | `1/2` |

The evidence recomputes both marginals from replayed initial-ready and final
reference cuts and checks their equality. It derives the distinct failure
risks from the actual model selections. The independent coupling would give
`1/4`, which is not justified by the two marginals alone.

This example's complete-record observer already knows the stock state at
confirmation. Under the opposite law, its stocked start has conditional
failure probability one. The existing pathwise bank therefore requires an
allowance of one on that path, although the prior union probability is one
half. The output does not confuse prior risk with conditional risk or claim
that this conservative pathwise bank attains the best prior bound.

## 8. Remaining actual-certificate implications

An eventual native security theorem still needs a proved connection from all
actual failure executions to the covered event set, together with physical
view and clock coverage, complete inventory, honest progress, correct native
identity/weight mapping, and the actual resource/initial-state assumptions of
the work theorem. EC1 supplies none of these missing premises.

If separate arguments establish failure-event containment and bounds on bad
coverage, clock, relation, resource, inventory and progress events under the
same law, they can be added to the work-event budget by a union bound. They
cannot be silently set to zero. Conditioning first on a future good event
does not preserve a previous unconditional work tail without a further
argument. Nor does a passing finite tree establish a nonnegative
supermartingale for the real process.

Relevant primary references, checked on 2026-11-07:

- Howard, Ramdas, McAuliffe and Sekhon,
  [Time-uniform Chernoff bounds via nonnegative supermartingales](https://arxiv.org/abs/1808.03204).
  Time-uniform control requires the appropriate martingale premise. EC1's
  finite union calculation does not assert such a premise for native traces.
- Garay, Kiayias and Leonardos,
  [The Bitcoin Backbone Protocol: Analysis and Applications](https://eprint.iacr.org/2014/765).
  The common-prefix conclusions depend on matched adversarial-resource and
  network assumptions; a work-query tail alone does not supply those.
- Carolan, Poremba and Zhandry,
  [(Quantum) Indifferentiability and Pre-Computation](https://arxiv.org/abs/2410.16595).
  Ordinary indifferentiability is generally insufficient for preprocessing.
  Its specialized results do not instantiate the missing SHA-256/Poseidon2
  lifecycle and actual-resource reduction here.
- Cojocaru, Garay and Song,
  [Generalized Hybrid Search and Applications](https://eprint.iacr.org/2023/798).
  Hybrid-query bounds address a specified ideal search game; they do not
  measure the all-algorithm physical cost of an accepted W1 packet.

## 9. Reproduction and bounds on the checker

From the repository root:

```sh
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p certificate_event_coverage_tests.py -v
python3 formal/pon-nakamoto-v1/certificate_event_coverage.py --write-evidence /absolute/new/output/directory
```

The driver retains the raw finite laws, every original model document,
history cuts, all automatically derived comparisons, exact risk arithmetic,
negative controls, and source hashes. It invokes no native producer or
quantum hardware. It samples the relevant source hashes before and after
generation and refuses changed inputs. Existing evidence directories are
never overwritten; failed generation retains an `attempt.json` with the
failure. Test runs and these model checks do not satisfy a production gate.

The implementation bounds each family to 64 leaves, each raw JSON document
to 2 MiB, the aggregate record to 32,768 events, the derived comparisons to
8,192, and the derived history-specific starts to 64. The existing execution
and probability-tree limits also apply. Exceeding a limit is refusal, never
silent truncation. These are verifier limits, not asymptotic security claims.
