# LQC1: one lifetime, paid classical prefix, and retained coherent state

Status: **proved conditional ideal-query reduction and executable reference
binding; unactivated research work. No physical or native confirmation
qualification.** The frozen MU1 v1 bytes and production Rust are unchanged.

This note closes two narrower problems that the older `2Q+M` query envelope
and WLC1's finite-help alphabet bound leave unnecessarily loose. A fixed output
index union removes the *analysis-only* M virtual checks. A complete paid
classical prefix can be averaged through an exact binomial law, while the
entire remaining coalition, retained state, helper activity and preprocessing
are charged to one coherent-query budget. No transcript-alphabet factor D is
needed under this stronger query-coverage assumption. Authentication of that
assumption remains open.

Implementation: [lifecycle_query_bound.py](lifecycle_query_bound.py),
[lifecycle_query_runtime.py](lifecycle_query_runtime.py),
[lifecycle_query_tests.py](lifecycle_query_tests.py), and
[lifecycle_query_evidence.py](lifecycle_query_evidence.py).
Dependencies: the frozen [MU1 relation](MANDATORY_UNITS_RELATION_V1.md) and its
[recording bound](mandatory_units_query.py). WLC1 and CO1 remain unchanged.

## 1. The same relation and the same oracle throughout a lifetime

MU1 hashes a fixed tag `ticket` and two 32-byte parts: context digest d and
ordered complete-unit root r. In this note only that terminal function is
replaced by an independent uniform 256-bit random oracle

\[
 F:\mathcal X\longrightarrow\{0,1\}^{256},\qquad
 \mathcal X=\{0,1\}^{256}\times\{0,1\}^{256}.
\]

The full terminal input includes the existing MU1 domain, constant tag and
length framing. Thus the pair (d,r) is a unique terminal address; the ambient
domain size is 2^512. Some pairs may not be reachable by valid MU1 packets.
Allowing every pair, and granting all complete W1 units and nonterminal
computation for free, only strengthens the adversary in this reduction.
All such free auxiliary operations/state must be independent of the unknown
terminal oracle except through the accounted queries. Actual SHA-256 shares
an implementation across domains; this idealization is not a proved reduction
for that actual hash composition.

The frozen target is T0 = 2^252 − 1, inclusive. Consequently p = 1/16 **in this
uniform-oracle model**. A fixed SHA-256 output is not a random variable made
uniform or independent by this arithmetic. The observed fraction of winners
in deterministic native fixtures is not an estimate or proof of p.
The two MU1 weight-bound APIs reject a different p rather than labeling a
different lottery as the frozen MU1 profile. Only the lower-level Bernoulli
arithmetic helpers accept a general probability parameter.

MU1 identity is the other fixed tagged hash `identity(d,r)`. Therefore

\[
 \text{distinct credited identities}\ \Longrightarrow\
 \text{distinct terminal address pairs }(d,r).
\]

This implication is deterministic and does not assume hash injectivity:
equal pairs give the same identity. The converse is unnecessary. With a
single all-branch, all-delivery identity deduplication scope and research
credit 16u, 1 <= u <= 8, each credited identity has weight at most 128.
Hence W >= x requires at least k = ceil(x/128) distinct marked addresses.
The bound 128 and credit 16u belong to **unactivated MU1 research accounting**.
They are not current native `required_work(target)` or native block score.
No identity/weight bridge to the six-successor rule is supplied here.

## 2. Exact assumptions and the common phase boundary

One coalition includes every producer, classical or quantum preprocessor,
public helper, validation-feedback source, retained storage and relevant
environment. Its complete initial joint state, including any shared
entanglement, is independent of F. Arbitrary mixed states and measurements
are covered by purification. Classical/quantum communication and local
computation within this coalition may be free. Every F-correlated external
information source must either be incorporated with its generating queries
or be covered by a separate justified initial-state certificate. An unknown
source, signed receipt or private marginal state does not meet this condition.

Before the coalition's first coherent terminal query, at most C distinct
terminal addresses are completely revealed classically. A revelation retains
the complete classical address and answer. Repeated reads of this known table
can be replaced by local lookups without new oracle queries. The prefix may
stop adaptively, but its stopping time has the hard cap C on every path.
All prefix information and the complete retained joint state are preserved.
There is no erasure/reset assumption on that state.

There is then **one irreversible common boundary**. Every remaining terminal
oracle call, classical or coherent, by every coalition participant is charged
to Q, apart from calls actually replaced by known-table computation. In
particular a classical reveal after an earlier quantum search is not a fresh
Bernoulli prefix trial. A helper joining late inherits the existing phase.
Separate owners' local clocks or local first-coherent events cannot be used
to sum several fresh prefixes. Quantum preprocessing that happened earlier
moves this common boundary earlier; it is not excused as preprocessing.

C, Q, M and the event threshold x are fixed before sampling F/executing this
global game and hold on every possible path. M bounds the entire complete
output history, including intermediate adaptive publications, losing
candidates and blind guesses. All actual oracle-dependent acceptance or
membership feedback used in later computation is a query under C or Q. The
final external success test in the mathematical game is not available as
free online feedback.

Here W is the unique valid MU1 credit in that declared complete output
history. To apply the theorem to hidden completed or ancestor-ready inventory,
one must additionally extract those full candidate packets without a new
terminal query and prove that the same hard M covers the extracted inventory.
A local publication/`emit` count is not a bound on privately retained outputs.
An internal quantum state that cannot yet yield complete classical packets
is part of the query strategy; it is not silently treated as a list of ready
valid outputs. This note supplies no actual inventory-completeness certificate.

These assumptions are more demanding than a signed observation of some
calls. They allow a useful charging theorem in place of a huge help-support D;
they do not prove that an adversarial real deployment has complete coverage.
An empty cache at process startup also does not establish the initial-state
condition. All real coverage, initial-state and physical-qualification flags
remain false.

## 3. Recording theorem and direct output lists

Let B(N,k) denote the frozen exact-rational recording bound for N Boolean
oracle queries and an algorithm that outputs k distinct candidate addresses,
all required to be marked. The output addresses may be selected adaptively
from the final quantum state, and may never have been queried. In particular
B(0,k) = p^k. Direct guesses are already part of this theorem.

For clarity, its two computable consequences are

\[
 B_1(N,k)=\min\!\left\{1,
 p^k\left[\sum_{i=0}^{\min(N,k)}
 {N\choose i}{k\choose i}[2(1-p)]^i\right]^2\right\},
\]

\[
 B_2(N,k)=\min\!\left\{1,(k+1)
 \sum_{i=0}^{\min(N,k)}{k\choose i}p^{k-i}(1-p)^i
 \min\{1,{N\choose i}^2[4p(1-p)]^i\}\right\},
 \qquad B=\min(B_1,B_2).
\]

These are conservative, not optimal, inequalities. In the recording basis,
one query changes the Hamming weight by at most one, with off-diagonal norm
c = 2 sqrt(p(1-p)). For the global tail norm a(N,i), the recurrence
a(N,i) <= a(N−1,i) + c a(N−1,i−1), starting with an independent oracle
record, gives a(N,i) <= min(1, binom(N,i)c^i). For each final selected list,
decompose by the number i of excitations on those k selected coordinates,
not by exact weight of the entire oracle record. The success-projection norm
on that layer is sqrt(binom(k,i)) p^((k−i)/2)(1−p)^(i/2), and the layer's
state norm is bounded by the global tail a(N,i). Triangle plus
sqrt(binom(k,i)) <= binom(k,i) gives B1; Cauchy and the saturated tail give
B2. Unselected coordinates may retain arbitrary excitations. This argument
does not discard them or use a private reduced-state substitute.

**Fixed-list theorem.** For at most M candidate outputs, the probability of
at least k distinct marked addresses is at most

\[
 L(N,M,k)=\min\{1,{M\choose k}B(N,k)\}.
 \tag{1}
\]

Set L = 1 for k = 0 and L = 0 for k > M. First extract and deduplicate the
terminal addresses without calling F. Invalid framing can be discarded;
unit-invalid candidates may instead be retained to strengthen the game.
Keep the entire output history as an ordered final register. For a **fixed**
index subset I of size k in M slots, a new algorithm outputs those slots,
or aborts if the list is too short. This is an N-query k-output strategy,
so its all-marked event has probability at most B(N,k). If the whole list
contains at least k marked addresses, at least one fixed I succeeds. A union
over the binom(M,k) subsets proves (1). No post-hoc uncharged search for
the winning subset occurs; the union factor explicitly pays for it.

Intermediate publications can be retained in the final register for this
proof even when the real application cannot retract them. Oracle-dependent
feedback from those publications remains part of the actual query count.
Removing M **virtual** membership checks does not remove real validator calls.

A full 256-bit random-oracle XOR query can be simulated with at most two
Bernoulli queries: query its marked bit, use independent conditional-output
tables to XOR a uniformly sampled marked/unmarked value, and uncompute the
bit. Granting those independent tables free strengthens the simulator.
Consequently N = 2Q suffices. This is an oracle-query reduction, not a lower
bound of two SHA executions or any number of physical gates.

## 4. Conditional continuation after a complete classical prefix

Suppose the complete prefix reveals d distinct addresses, s of them marked.
Let U = |X| − d be the number of untouched addresses. Conditional on the
entire prefix and retained joint state construction, the untouched F values
remain iid and the retained state is independent of those untouched values.
This is the substantive condition, not something validated by the two
integers d and s. Any unaccounted quantum preprocessor or helper may violate it.

If k > M or k > |X|, success is impossible. If s >= k, use the bound one.
Otherwise s < k <= M. We may replace the output algorithm by the following
stronger relaxed algorithm, without querying F: insert all s known winners,
discard known losers, and retain at most M−s unknown addresses. If the
original output had r <= s known winners and n <= M−r unknown addresses,
the transformation removes at most s−r unknowns. Even if all removed unknowns
are marked, adding s−r known winners never lowers the total number of hits.
This is a pathwise comparison and requires no ability to identify unknown
winners. The final unknown list has at most m_s = min(U,M−s) entries.

Thus a uniform conditional upper bound is

\[
 G(d,s,Q,M,k)=L(2Q,\min(U,M-s),k-s),\quad s<k\le M.
 \tag{2}
\]

Known prefix values can be supplied coherently by free lookup. To simulate a
full-domain query using only the unknown-domain oracle, compute membership
in the known table. On a known-address branch, swap the actual target into
scratch, put the oracle target in the all-plus state and route its address
to a fixed unused dummy. The XOR oracle leaves that target invariant. Undo
the swap/routing and XOR the known value. The unknown branch performs the
actual query. This uses one unknown full-value query, not an unproved free
controlled oracle. If U = 0, no dummy is required: every value is known and
no new distinct unknown success can be produced. Equation (2) handles that
case with zero unknown slots.

For Q = 0 the relaxed game is exactly solvable:

\[
 G(d,s,0,M,k)=
 \Pr[\operatorname{Bin}(\min(U,M-s),p)\ge k-s],\quad s<k\le M.
 \tag{3}
\]

The augmentation proves that using every known winner is optimal. Any
remaining oracle-free selection of distinct untouched addresses has iid
marks, even when selected using retained quantum randomness independent of
those marks. Choosing the maximum allowed number achieves (3) in the
relaxed address-output game. It is not an exact MU1 or native success law:
complete-unit reachability was deliberately granted for free.

`continuation_given_complete_prefix` implements (2)/(3) with the supplied
actual s and labels the scope `conditional_on_complete_coalition_prefix`.
It neither resamples s nor certifies the completeness of the prefix supplied
by its caller.

## 5. Global lifetime convolution, including bounded stopping

Let C_eff = min(C,|X|). At an adaptively chosen prefix stop, gift the coalition
additional revelations at fresh distinct addresses until C_eff have been
revealed. There is enough unused domain unless the full domain is exhausted,
in which case C_eff = |X| and the complement is empty. Each next fresh value
is iid conditional on all earlier revelations. Thus the total padded count
S has the **unconditional** law Bin(C_eff,p), regardless of stopping choices.
This extension only grants information and never weakens the attacker.

For every complete padded transcript, apply the uniform continuation bound
with the same all-path Q and M. Averaging over the global prefix law gives

\[
 \Pr[W\ge x]\le
 \sum_{s=0}^{C_{\rm eff}}{C_{\rm eff}\choose s}p^s(1-p)^{C_{\rm eff}-s}
 G(C_{\rm eff},s,Q,M,\lceil x/128\rceil).
 \tag{4}
\]

The convention for G includes the zero/impossible and s>=k cases above.
The implementation aggregates the s>=k terms as an exact binomial tail;
it does not numerically truncate small masses. It also takes the minimum
with the independently valid all-coherent list bound
L(2(C_eff+Q), min(M,|X|), k). All probability arithmetic uses `Fraction`.
The implementation caps C+Q at 4096 and M at 64 as finite checker limits;
the mathematical theorem applies to arbitrary finite caps.

Retained quantum memory after the common boundary is unrestricted. It is
part of the same Q-query algorithm, including reuse across helper calls,
process restarts or candidate branches. There is no new independent state
at those later boundaries and no repeated charge of the same free lookup.
The query coverage must still be proved for the entire coalition; a public
helper's queries cannot be discounted merely because another party pays it.

**A paid prefix does not authorize a conditional restart.** With C=1,
Q=0, M=k=1, (4) equals p+(1−p)p = 31/256. At a prefix transcript that
already reveals a winner, however, s=1 and the conditional success is one.
Both facts hold in the same fully accounted law; no omitted query is needed
for this counterexample. The global number 31/256 cannot be used as the
risk at that selected start. The separate conditional API returns one.
This distinction is required before any random-start native confirmation
argument can consume a query theorem.

## 6. What the actual reference experiment establishes

`ReferenceQueryOwner` routes the frozen Python relation's actual terminal
SHA-256 calls through one shared cache. It preserves the first observed
address/answer reference, charges a first revelation to C before its local
barrier or Q afterward, refuses a call before hashing when its cap is full,
and makes every complete emission consume M. Cache reuse adds no logical
oracle call; a repeated valid identity adds no research credit. A helper
cannot reopen the owner's prefix. A foreign reference or a new empty owner
cannot import a prior paid origin.

The output extractor reproduces only canonical frozen framing and nonterminal
hashes. It never queries the terminal lottery and never claims unit validity.
Native emissions separately invoke the unchanged complete PNW1 verifier.
The extractor's shape-only negative demonstrates that successful extraction
is not a valid-work certificate.

The required native run constructs all fixed dense u1 candidates at nonces
0 through 7, preserves every loss, and rechecks each complete unit natively.
After the common local barrier it delivers a cached winner through a helper,
rechecks and rejects double credit, then constructs nonce 8 and charges its
fresh terminal query to Q. It also compares the complete native-fresh and
native-prepared packet bytes and submits a deliberately corrupted full trace
to the native verifier. Actual stdin, stdout, stderr, packet bytes and source
hashes are retained. Bounded-exchange failures retain their observed byte
prefixes and truncation indicators and are marked FAILED even if the child
exit code is zero. Source and binary hashes are sampled before and after
the run and must match; these samples are not execution attestation.
No quantum device or coherent query is claimed to have
been executed by this classical reference experiment.

The records use the new unsigned hash-chain namespace `TRNM-PON-LQC1\0`.
They are observations, not authenticated execution receipts. Actor labels
are not authenticated. The hook is single-thread Python instrumentation,
not a sandbox, operating-system gate or unforgeable capability. An external
algorithm can compute SHA-256 outside it; a producer may already know a
winning packet before this owner starts. Therefore
`global_budget_certificate()` always refuses with
`GLOBAL_QUERY_CLOSURE_AND_JOINT_INITIAL_STATE_UNATTESTED`, even when every
local dispatch and predicate check passed. Signed WLC1 source chains do not
remove that limitation either.

Run the finite tests:

```sh
python3 formal/pon-nakamoto-v1/lifecycle_query_tests.py
```

Run required actual native binding into a **new** evidence directory:

```sh
LQC_NATIVE_WORK=/absolute/path/pon_work_io \
LQC_NATIVE_PREPARED=/absolute/path/pon_zero_io \
python3 formal/pon-nakamoto-v1/lifecycle_query_evidence.py \
  --out evidence/pon-lifecycle-query-charging-20261107/run-01
```

The second command fails if either executable is absent. It has no scalar,
shape-only or synthetic native fallback. Failure/partial evidence is retained
and an existing output directory is not overwritten. Its source manifest,
not a baseline Git anchor alone, identifies the exact new implementation.

## 7. Qualification boundary and primary research

The progress is a sharper explicit all-lifetime query reduction with a useful
classical preprocessing term, complete finite arithmetic checks, and actual
full-relation dispatch/cache binding. It does **not** prove a nontrivial
all-algorithm minimum cost for one complete W1 unit, linear cost in u, or a
conversion from energy/time/gates into the required global C/Q/M caps.
It does not supply an actual SHA-256 preprocessing-safe idealization, a
complete actual initial-state certificate, a trustworthy global query meter,
or a native identity/weight/common-prefix mapping. All corresponding flags
remain false, including native six-successor risk and production qualification.

Related primary sources help delimit, but do not instantiate, these claims:

- Cojocaru, Garay and Song, [Generalized Hybrid Search and Applications](https://eprint.iacr.org/2023/798).
  Their stated hybrid bound concerns finding a marked preimage under a given
  distribution. It is not by itself the distinct credited-weight tail or a
  W1 gate-cost lower bound. Equations (1)–(4) above have their own proofs.
- Rosmanis, [Hybrid Quantum-Classical Search Algorithms](https://arxiv.org/abs/2202.11443).
  This is query-complexity research; its abstract does not certify a real
  SHA-256 workload or physical resource meter.
- Carolan, Poremba and Zhandry,
  [(Quantum) Indifferentiability and Pre-Computation](https://eprint.iacr.org/2024/1727).
  They show that ordinary indifferentiability is generically insufficient for
  preprocessing and propose a strengthened notion. A domain separator plus
  ordinary oracle heuristics is therefore not used here as the missing
  actual-hash preprocessing proof.
- Beame, Kornerup and Whitmeyer,
  [Strong Selective and List-Decoding Direct Product Theorems for Quantum Query Complexity](https://arxiv.org/abs/2609.26678).
  Their function/relational and selective/list distinctions explain why a
  theorem must match the exact output success event. This note uses the
  explicit fixed-index union, without importing unverified constants or
  asserting a general direct-product theorem for actual W1.

Research pages were checked on 2026-11-07. No claim of an error in those papers
is required for this result.
