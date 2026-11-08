# CO1: observability, shared-lifetime witnesses, and repeated starts

**Research certificate scope, not consensus activation or a native risk estimate.**
This addition closes three limited statements: the precise information boundary
of the new local owner census, a pathwise reduction for overlapping adaptive
windows, and a predictable risk bank under one complete joint probability law.
It also gives exact counterexamples to unpaid fresh restarts and to treating
finite retained advice as evidence of small residual risk.

The baseline source is `f8362822b406463ac3dfcc911a0c3eda1686e32d`.
New source is bound by the evidence manifest; the baseline identifier does not
claim that these new files already existed in that commit. Executable models
are in [certificate_observability_models.py](certificate_observability_models.py),
with [exact tests](certificate_observability_tests.py) and a
[required-native-input evidence reader](certificate_observability_evidence.py).

## 1. What the actual native owner certificate establishes

The new [native implementation](../../trillionnium/crates/trnm-pon-node/src/store/native_owner_observation.rs)
and [its specification](NATIVE_OWNER_OBSERVATION_V1.md) cover the current local
admitted collection in one consistent SQLite snapshot, for the supported PNP1
`legacy-task-v1` relation and the stated state backends. Every retained row,
including inactive competitors, is enumerated; every non-genesis packet is
replayed through complete native W1, native application execution, state and
delta checks, native weight arithmetic, and its ancestry. Current timestamp
eligibility is an ancestry predicate. An eligible child does not repair a
future-dated ancestor.

The exact source-defined SQLite schema is compared before enumeration and
before output. A real adversarial review identified why a stable schema-version
counter alone was insufficient: an earlier rename of `blocks` plus a filtering
view can keep a competing row outside the query while the counter stays stable
during the snapshot. The implementation now rejects that schema, and the native
integration test exercises the actual filtering-view attempt. Packet/row
budgets, cancellation, unsupported profiles, inconsistent ancestry and fences
produce whole-operation refusal; no partial census is promoted to completeness.

This is local completeness **relative to the rows currently present in that
snapshot and the trusted native owner/SQLite boundary**. It is not an audit of
all rows ever admitted. A previously deleted inactive branch, an unadmitted
local packet, a worker's partial state, a remote packet, or a public helper's
preprocessing is outside that set. Epoch checks are race fences, not a log of
every external transaction. Source hashes and exported JSON do not independently
attest execution of the binary or the operating system.

The [score bridge](NATIVE_OWNER_SCORE_BRIDGE_V1.md) independently rechecks exported
tree, target/512-bit score, ancestry eligibility, local commitments, retained
packet hashes, and confirmation arithmetic. Its result still leaves execution
authenticity and world coverage false. CO1 reuses that strict reader before
adding any scenario binding.

### 1.1 Actual counterexample to automatic all-candidate activation

The retained native run is produced by real `Node::make`, `admit`,
`activate_observed`, `confirmation` and `native_owner_census` calls. Each ordinary
block in this experiment has native required work 2.

| Actual observation | Selected score | Eligible local maximum | Consequence |
| --- | ---: | ---: | --- |
| Alice at A7, containing target A1 | 14 | 14 | Six descendants and descendant work 12 both satisfy the installed confirmation rule |
| Alice after A8 and A9 are admitted without activation | 14 | 18 | Admission does not imply selection of the complete-view maximum |
| Alice after strict activation of delivered Bob B8 | 16 | 18 | A real rollback occurs while a heavier eligible A9 is already retained; selection deficit is 2 |
| Future ancestor becomes eligible, before another activation | 16 | 22 | Timestamp maturation changes the candidate maximum; selection deficit is 6 |

The full replay proves these statements for this invocation. It does not give
their probability under an adversarial resource or network model. In
particular, a theorem assuming instantaneous all-candidate maximality cannot be
silently applied to this native activation API. The previous deterministic
deficit accounting can represent these actual deficits exactly; attributing
them to new adversarial work requires additional world inventory information.

### 1.2 Actual evidence of the remote-inventory boundary

Before and after Bob privately constructs its complete legal B1 through B8,
Alice's stable `local_view_commitment` and retained rows are identical. Bob's
separate owner census has score 16; Alice's selected A7 has score 14. The eight
non-genesis Bob ancestors are absent from Alice's census. After delivery,
strict native activation selects B8 and the previously confirmed target is
reported reorged.

The two Alice observations have **different attempt numbers and process clock
intervals**. Equality of their stable projection does not mean their entire
OS, timing, or interaction transcripts are identical. CO1 records both intervals
and explicitly refuses that stronger inference. The mathematical two-world
argument below requires its own same-schedule coupling assumption; it is not
established by comparing these two hashes in one run.

## 2. An exact non-identifiability theorem

Let O be the complete observation available to a proposed certificate issuer.
Fix an allowed class of worlds. Assume that class permits two extensions of
one observation history with the following properties:

1. They have the same public schedule, observation times, local randomness and
   local state. Remote preparation has no influence on any channel included in
   O before the observation cut.
2. In world 0 there is no competing chain and the target remains selected over
   the specified future horizon. In world 1 a complete valid competing chain
   with greater score is retained privately and delivered within that horizon;
   the selection rule rolls back the target.
3. No separately enforced resource, inventory, timing or availability bound
   excludes either extension.

Put a Dirac probability law on each extension. Then

\[
\mathcal L_0(O)=\mathcal L_1(O),\qquad
\Pr_0(\text{failure})=0,\quad \Pr_1(\text{failure})=1.
\tag{1}
\]

Any upper bound determined solely by this observation and sound for both worlds
must therefore be at least one. Any binary world-classifier, even randomized,
has success probability at most one half under a balanced mixture. More
generally, any inferred inventory upper bound must cover the supremum of the
inventories in the observation's entire allowed equivalence class. If arbitrary
unobserved preprocessing expenditure is permitted, a local log cannot upper
bound that expenditure. The statement does not deny finite bounds imposed by
a finite protocol namespace; it denies inferring a stronger bound from the
unchanged observation.

**Proof.** The classifier or bound has the same input distribution in both
worlds. A bound smaller than one is false in world 1. The balanced classifier
receives no information about which world was selected. The inventory argument
is the same pointwise argument over all allowed extensions. No computational
assumption is used.

The executable `synthetic_counterpair` supplies a complete additive-score
instance with exact 0/1 probabilities under these declared laws. It does not
construct native proofs. The separately bound native invocation demonstrates
that the relevant hidden legal competitor and rollback are realizable by the
actual implementation. Neither result estimates a real network distribution.

If O includes timing, source identities, ordering, message sizes, errors,
absence, resource telemetry or other channels, the two-world premise must hold
for those channels too. A remote noninterference construction may couple the
same local idle schedule in both worlds; simply omitting a visible channel from
a transcript is invalid. This matches the complete-transcript premise of the
[finite classical-help reduction](WORK_LIFECYCLE_CERTIFICATE_V1.md).

Additional assumptions that can defeat a particular counterpair include an
externally enforced bound on all charged computation and retained initial
inventory, complete mediation of help, and an authenticated delay/availability
envelope. An observed packet count, a fresh session name, a signed local log or
a label asserting completeness supplies none of those assumptions by itself.

## 3. Shared-lifetime reduction for overlapping adaptive windows

Work in one fixed probability space and one global experiment from its actual
charged initial state. Give every distinct accepted output a unique identity
and nonnegative credit w(e), and count it once at its first ancestor-complete
ready cut r(e). Let

\[
W=\sum_e w(e),\qquad
A((s,t])=\sum_{e:s<r(e)\le t}w(e).
\]

This is a semantic global ledger; an admission timestamp is not automatically
a first-ready timestamp. Re-delivery, re-verification, a new process and a new
confirmation attempt do not create a new identity or new credit. The executable
ledger rejects conflicting credits and assigns duplicate deliveries zero new
credit. It does not attest that a supplied ledger covers the world.

For finitely many windows I_j=(s_j,t_j], suppose a proposed joint witness requires
A(I_j) >= d_j. Choose nonnegative multipliers lambda_j with

\[
\sum_{j:r\in I_j}\lambda_j\le1
\quad\text{at every possible causal cut }r.
\tag{2}
\]

Then the following **pathwise** implication holds:

\[
\bigwedge_j\{A(I_j)\ge d_j\}
\quad\Longrightarrow\quad
W\ge\sum_j\lambda_jd_j.
\tag{3}
\]

**Proof.** Exchange the finite sums:

\[
\sum_j\lambda_jd_j
\le\sum_j\lambda_j A(I_j)
=\sum_e w(e)\sum_{j:r(e)\in I_j}\lambda_j
\le W.
\]

For integer causal cuts, the exact checker sweeps changes at s_j+1 and t_j+1.
It checks all cuts, including cuts with no observed output; checking only the
realized output atoms would not validate the asserted all-path coverage
certificate. Same-time actions require a common causal ordering. Half-open
windows prevent an endpoint atom from being charged to both adjacent windows.

Disjoint windows permit lambda_j=1. If overlap is at most r, lambda_j=1/r gives
W >= sum_j d_j/r. A weighted choice can be stronger: two disjoint requirements
of 128 and one covering requirement of 128 have uniform-overlap margin 192,
whereas weights (1,1,0) give 256. Multipliers may be selected after observing a
path, because (3) is a deterministic implication on every accepted path.

### 3.1 One global tail, without free conditional restarts

Fix x0 **before** the probability statement. Let E be the event that there
exists any accepted window witness satisfying (2) and
sum_j lambda_j d_j >= x0. Windows, starts and weights may be adaptive or
retrospectively selected. Then

\[
E\subseteq\{W\ge x_0\},\qquad
\Pr(E)\le\Pr(W\ge x_0).
\tag{4}
\]

There is no window-count union factor and no independence assumption. The
global budget, initial state, output identity, credit and oracle law must be
the same for every window. A witness for several failures requires their
conjunction; for an event of any one failure, each possible failure must itself
imply some accepted witness of the required fixed margin. It is invalid to add
thresholds belonging to failures that did not occur, or to choose a different
reported probability threshold after observing the path without accounting for
that selection.

For the conditional MU1 ideal-oracle model, the existing bound is
B_MU1(Q,M,ceil(x0)), with one hard lifecycle Q and one complete output cap M.
The executable example has 32 coincident windows, each requiring 4096 credit;
weights 1/32 give one 4096-credit event. Under the stated fresh model Q=1,M=32,
its bound is approximately 0.0657560382. This number is neither a conditional
risk at any selected start nor a native six-successor failure probability.

The same inclusion can feed a separately established global stateful tail.
For example, if V_n >= 1 and
Z_n=exp(theta A_n-kappa R_n)V_n is a nonnegative supermartingale from the actual
initial state, with theta>0, kappa>=0, finite E[V_0], then

\[
\Pr[\exists n:E_n,\ R_n\le B]
\le \min\{1,\mathbb E[V_0]e^{-\theta x_0+\kappa B}\}
\tag{5}
\]

whenever every E_n has a packing witness using only first-ready atoms through
n. Ville's inequality applies to the original global process. Known initial
ready stock must be represented in that process or paid once as initial stock;
it cannot be counted as new work at multiple starts. Equation (5) does not
establish that physical resources of actual W1 satisfy the supermartingale
premise.

## 4. A genuine conditional risk bank for random starts

Global event domination and conditional restart analysis are different tools.
For the latter, let tau_j be starts on the same filtration. Let E_j be the
failure event for attempt j, contained in {tau_j<infinity}. On each start
history choose an F_tau_j-measurable allowance alpha_j >= 0, and establish

\[
\Pr(E_j\mid\mathcal F_{\tau_j})\le\alpha_j,
\qquad
\sum_{j:\tau_j<\infty}\alpha_j\le\alpha
\quad\text{pathwise}.
\tag{6}
\]

Then, without independence,

\[
\Pr\Big[\bigcup_jE_j\Big]
\le\sum_j\mathbb E[1_{\{\tau_j<\infty\}}\alpha_j]
\le\alpha.
\tag{7}
\]

This follows from the conditional tower property and the union bound. A
separately established expectation bound on the sum of allowances is also
sufficient; pathwise accounting is a convenient stronger interface, not a
necessary condition. Countable attempts follow by monotone convergence when
the displayed bounds are valid. The executable certificate checks a bounded
finite tree and at most 64 declared attempts.

The probability-tree checker takes an entire prefix-free finite outcome law
whose exact positive rational masses sum to one. For every declared start
prefix it computes the descendant mass, failure mass and their ratio. It
refuses failures outside that prefix and refuses a small user-supplied allowance
when the computed conditional risk is larger. It then checks all path budgets
and the exact correlated union. A prefix can already reveal a winner; the
checker handles that case by computing risk one, not by treating it as fresh.

A real application could pay alpha_j using a valid **conditional joint residual
potential** at tau_j and a valid conditional environment envelope. The residual
state and the oracle must be treated jointly under the posterior law at that
history. Finiteness of the state space, the numerical parameter V, or the
number of starts does not establish those conditional inequalities. Passing a
complete declared probability tree does not authenticate the actual network's
probability law.

### 4.1 Exact counterexample to an unpaid fresh reset

Inspect at most L=16 independent Bernoulli addresses with p=1/16, and start the
online attempt immediately after the first hit. At each selected start the
known address succeeds with conditional probability one and requires zero
additional queries. The probability that any start exists is

\[
1-(1-p)^{16}.
\tag{8}
\]

The proposed unpaid zero-online-query fresh bound from the existing conservative
output-check formula is strictly smaller than (8). The finite probability tree
rejects it specifically as `INVALID_CONDITIONAL_RISK_AT_START`. Paying the
whole lifetime, or using the correct known-winner joint residual profile
(1,1-p), yields the valid bound one in this example. This is an exact model
counterexample, not a sample from actual SHA-256.

## 5. Finite joint retained advice can already permit high success

Let the ideal Bernoulli oracle have D addresses. Permit arbitrary finite
classical advice correlated with the oracle. Advice containing its full D-bit
truth table allows the receiver to output k distinct marked addresses whenever
at least k exist, without any new queries. No strategy can succeed when fewer
than k exist. Hence the sharp success probability over this unrestricted finite
advice class is

\[
\sum_{j=k}^{D}{D\choose j}p^j(1-p)^{D-j}.
\tag{9}
\]

For D=64,k=1,p=1/16 this exceeds 0.98. Its advice is finite and classical.
Thus a claim merely asserting finite residual state cannot imply a small risk.

There is also an explicit joint recording-state calculation. Purify the
truth-table distribution and copy each truth bit into its advice register.
After the same dual-basis rotation used by the MU1 theorem, a single recording
bit is excited with squared norm q=2p(1-p): the two orthogonal advice labels
each contribute p(1-p). Across D coordinates this joint state is a tensor
product. Its exact squared global-record tail is

\[
b_i=\sum_{j=i}^{D}{D\choose j}q^j(1-q)^{D-j}.
\tag{10}
\]

The implementation supplies this derived profile to the existing residual
propagation theorem with N=0, and checks that the resulting bound dominates
(9). A separate four-coordinate exhaustive calculation keeps the advice
register and reproduces (10). Dropping that register and asserting a fresh
all-zero recording state would discard precisely the relevant correlation.
This construction certifies the profile of this explicit mathematical model,
not any actual W1 worker's opaque retained state.

## 6. Evidence and reproducibility

Run the exact finite checks from the repository root:

```bash
python3 formal/pon-nakamoto-v1/certificate_observability_tests.py -v
```

Bind an existing real native invocation and its retained packet directory:

```bash
python3 formal/pon-nakamoto-v1/certificate_observability_evidence.py \
  --native-owner-json evidence/pon-actual-certificates-20261107/native_score_bridge/attempt-01/run/native.json \
  --out /tmp/pon-observability-new-output.json
```

The output path must be new. Missing or invalid native input, missing packet
bytes, or a violated scenario predicate fails the command. There is no native
stub, automatic build, synthetic fallback or silent skip. Exact rational
probabilities are serialized as numerator/denominator pairs; floats are not
used for certificate decisions. The manifest binds the exact model, test,
reader, specification and relevant native source bytes read for this result.

Retained observations are under
[the observability evidence directory](../../evidence/pon-actual-certificates-20261107/observability/).
The actual native run, source-bound invocation and negative native controls
remain in their original evidence directories. A successful arithmetic replay
does not convert an arbitrary JSON file into an authenticated OS transcript.

## 7. Consequence for the two outstanding scientific obligations

The current local admitted census and its score deficits are now concrete
native evidence. The global-ready/private-inventory interpretation is still a
separate premise, with both a realizable native hidden-branch scenario and a
precise identifiability obstruction. Native six-successor semantics remain the
installed depth **and** required-work rule; neither its work nor its probability
has been replaced by MU1 research credit.

The shared-lifetime packing reduction and conditional risk bank close useful
composition steps without assuming independent windows or fresh resets. They
do not supply the actual W1 minimum-cost theorem, the physical query bridge,
the missing conditional initial-state certificate, or the world network
envelope. Combining these results requires the same probability law and the
same authenticated identity/weight accounting on both sides. Those missing
bridges remain explicit; no security qualification or numerical native risk
is issued by CO1.
