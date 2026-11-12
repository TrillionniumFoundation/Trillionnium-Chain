# W1, branch difficulty, timestamps and cumulative work: joint audit

## Decision and source boundary

The four components require one security argument. Correct W1 verification,
correct integer retargeting, a median timestamp rule and overflow-safe work
addition are necessary implementation properties. Their conjunction does not
establish a bound on an adversary's cost or a common-prefix failure probability.
The whole-chain quantum-work decision remains **HOLD_NO_GO**.

The native baseline is
`b5c655ebe9611b3d62cf739e61e6867decc053e3`, the head of the joint-state/risk-ledger
candidate at inspection. The public default branch is not this candidate.
`trillionnium/crates/trnm-pon-node/src/consensus.rs` has Git blob
`989ac5f08b8e4f707cda613617fd5245eb6a6463` at both that baseline and the separately
inspected PQ candidate `12e510b211110d93d9ead07e02c07a1eecc28ae9`.
Equality of this file does not make the complete branches equivalent.

The quantum-competition continuation has its own source identity,
`360556e9664fcb563877c05e74fd83974a5d9dba` (PR #781). Its assumed resource clocks
and fixed-context oracle observations are not native executions of this audit's
candidate. In particular, PNH1 and PGH2 have different encoded headers and hash
domains. An observation must identify the actual packet/profile it executed.

This audit adds executable research and controls. It retains linear required
work, the existing target and timestamp rules, and the production HOLD flags.
No new consensus namespace or production deployment is activated.

## Exact native contract

For a nonzero 256-bit target `T`, the stored contribution is

\[
 W(T)=\left\lfloor\frac{2^{256}}{T+1}\right\rfloor.
\]

`required_work` uses an inclusive target. `T=0` is rejected even though the
arithmetic expression alone has a value there. Work has 512-bit checked
addition; arithmetic overflow is a refusal. Neither the winning ticket's
unexpectedly small value nor a peer's advertised work increases this credit.

At height `h`, the selected parent's own validated history determines the
target. At a boundary `h mod I = 0`, the endpoints are heights `h-I` and
`h-1`; their desired separation is `S=(I-1)*spacing`. The target is

\[
 T'=\min\!\left(T_{\max},\max\!\left(1,
   \left\lfloor T\frac{\operatorname{clamp}
   (\max(1,t_{h-1}\mathbin{\dot-}t_{h-I}),\lceil S/4\rceil,4S)}{S}\right\rfloor
   \right)\right),
\]

where dotted subtraction saturates at zero. This definition also covers an
endpoint with `last < first`; it reaches the lower timespan clamp.

For each admitted header, its timestamp must strictly exceed the upper median
of the most recent at most eleven ancestors, and must be no greater than the
caller's observed clock plus the configured skew. The median history belongs
to that header's parent. With eleven ancestors, a single high parent timestamp
does not require its successor timestamp to be higher. The future limit is an
upper bound, not a certificate of elapsed mining time.

After complete admission, activation compares accumulated *required* work.
A shorter branch can win; equal work does not replace the current tip merely
because a different timestamp history was supplied. State recovery and
reorganization must preserve the same branch arithmetic and complete validity.

## Why the single-period clamp is insufficient

The development parameters are `I=16`, spacing `10`, MTP window `11`, future
skew `120`, and `Tmax=2^255-1`. Thus `S=150`, lower span `38`, upper span
`600`. Repeated lower-clamp retargets use the exact recurrence

\[
 T_{j+1}=\max\!\left(1,\left\lfloor\frac{19T_j}{75}\right\rfloor\right).
\]

The first required-work values starting at the development limit are
`2, 7, 31, 123, 485`. They are not obtained by blindly multiplying an integer
work value by four. The span clamp is local to one retarget; its changes can
compound across multiple legal epochs.

Even the *single-block integer credit* need not be bounded by a factor of four.
Put `Q(T)=2^256/(T+1)`. At a lower-clamp adjustment, the inclusive denominator
gives `Q(T') <= 4 Q(T)`, but flooring only implies

\[
 W(T')\le 4W(T)+3.
\]

Indeed `T=floor(2^256/3)` gives `W(T)=2` and `W(T')=11`, although its ideal
uniform-query cost ratio is below four. The development-limit recurrence itself
contains `7 -> 31`, another ratio above four. These are rounding effects in the
credit, not cost-free valid blocks: `p(T)*W(T) <= 1` under the uniform-ticket
premise. A security model must distinguish the span multiplier, the target
ratio, the inclusive mean-query ratio and the rounded credited-work ratio.

The repeated-endpoint experiment starts from a common prefix. Each manipulated
epoch has one high first timestamp and otherwise uses the minimum timestamp
strictly above that branch's MTP. The last timestamp can then be less than the
first while every header remains time-valid. The experiment checks complete W1
proofs, parent-specific target selection, admission, cumulative credit,
activation and cold recovery together. The earlier native boundary fixture
retains median and future-clock refusals. The new fixture adds repeated negative
endpoints and direct W1-verifier controls rejecting reused proofs after parent,
target, timestamp, nonce and, for PGH2, witness changes. These proof-binding
controls are distinct from a wrong-required-target node-admission refusal.

The same schedule is exercised independently under authenticated PNH1 and the
actual PGH2/PNP2 growth owner. Their packet bytes, challenge domains, task
profiles and state paths remain separate. PNH1 `activate_observed` checks the
current clock against ancestry. Growth activation has no observed-clock
argument; the experiment records its admission-time checks and local head
selection, without claiming that PNH1's activation-time clock contract ran on
PGH2. No remote caller clock-control bypass was established by this difference.

The supplied clocks are explicit logical validation inputs. They are not
measurements of a live ten-second production cadence. All blocks are genuinely
computed on a classical host; the experiment does not assume a quantum machine
mined them at the requested logical times. Complete relation validity is a
reachability result, not an attacker-share or profitability estimate.

The successful retained native execution includes 114 distinct accepted packets
per profile: 15 common-prefix packets, 49 on each competing branch, and one
additional ordinary packet. Each profile independently reaches the following
retarget observations; times in this table are relative to genesis.

| New-target height | First endpoint | Last endpoint | Signed span | Effective span | New block work |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 16 | 0 | 150 | 150 | 150 | 2 |
| 32 | 160 | 118 | -42 | 38 | 7 |
| 48 | 320 | 121 | -199 | 38 | 31 |
| 64 | 480 | 124 | -356 | 38 | 123 |

The ordinary tip has height 65 and work 130. The altered tip has height 64 and
work 793. The latter replaces the former, the lower-work branch cannot retake
the tip, and cold reopening preserves the active state, work and exact retained
packet bytes. All 228 accepted packets carry newly computed classical PNW1
proofs; this is not a measurement of a quantum miner competing with live honest
progress.

Four PNH1 and five PGH2 changed-header probes reuse the old proof. In addition
to the real-target rejection, a diagnostic verifier call with an all-`ff`
filter reaches and rejects the complete transcript check. Its challenge still
contains the changed header's actual target. This diagnostic filter is never
admitted as a node target and awards no consensus work.

## Conditional cost/score mismatch

Let `D=1/p` denote ideal search difficulty, separately from the rounded native
integer `W`. Under the additional uniform-search and fixed per-query cost
premises, classical search has expected query cost proportional to `D`, and
constant-success Grover search scales as `sqrt(D)`. These are conditional query
models; the actual W1 marked set and physical query cost require their own
evidence.

For a score `s(D)=D^alpha`, the respective score per unit query cost is

\[
 R_C(D)\propto D^{\alpha-1},\qquad
 R_Q(D)\propto D^{\alpha-1/2}.
\]

Linear scoring makes the first expression constant while the second grows
with difficulty. Square-root scoring makes the second constant while the
first grows as difficulty is reduced. More generally, on any set containing
two different positive difficulties, no nonzero score depending only on
difficulty can be proportional to both `D` and `sqrt(D)` with fixed positive
proportionality constants. This is a narrow algebraic statement, not an
impossibility theorem for every hybrid consensus protocol.

For an exact illustrative control, use targets `2^236-1` and `2^246-1`.
Their required work is exactly `2^20` and `2^10`. Under the classical uniform
query model, the easier target reduces expected search cost by `1024`, but
square-root scoring reduces the award only by `32`. Its stationary score per
query is therefore `32` times larger. A complete easier-branch attack would
still have to pay its transition costs and satisfy the real timestamp,
availability, propagation and activation rules. The example alone does not
establish such an attack.

There is also a distinction between `sum(sqrt(W_i))` and
`sqrt(sum(W_i))`. An exact square root of the *total* is strictly increasing and
preserves the original fork ordering; it cannot repair that ordering's cost
mismatch. An integer square root of the total may additionally create ties.
The per-block square-root proposal changes the ordering and requires the
classical analysis above.

The bounded recurrence also must not be described as unbounded difficulty.
Native `T>=1` limits per-block required work to `2^255`. A fixed 64-bit nonce
space can have no winner at high difficulty. Changing the target changes the
challenged header, so a new target needs a newly evaluated W1 relation; an old
ticket list cannot simply be rethresholded. Initial-state advice, task/matrix
choices, setup reuse, multiple search domains, failed attempts, clean
uncomputation, proof construction and transmission remain part of the cost
contract.

## What the literature establishes

[Bailey and Sattath, arXiv:2403.08023v2](https://arxiv.org/html/2403.08023v2)
give a difficulty-increase attack in an ideal quantum-search model. Their
Variant 4 uses twofold increases and decreases, inside a fourfold bound.
The paper's model and optimistic hardware analysis do not supply a W1 physical
cost reduction. This result invalidates using a clamp alone as a quantum
security argument.

[Cojocaru et al., Quantum 7, 944 (2023)](https://quantum-journal.org/papers/q-2023-03-09-944/)
relate chains of PoWs to multi-solution Bernoulli search and prove a quantum
backbone result under explicit query-budget conditions. A fixed-success-rate
bound cannot silently be reused when adversarial branch history changes that
rate.

[BIP94](https://github.com/bitcoin/bips/blob/master/bip-0094.mediawiki)
illustrates a narrowly scoped epoch-seam rule: Testnet4 restricts how far a new
epoch's first timestamp may lag its predecessor. It retains the fourfold clamp.
That repair targets a different classical timewarp mechanism; adding its seam
condition alone would not reject a high-first/low-last epoch in this audit.

[Garay, Kiayias and Shen, Fast Difficulty Adjustment (CRYPTO 2026)](https://www.iog.io/papers/fast-difficulty-adjustment-in-proof-of-work-consensus)
use parallel chains and approximate agreement to reduce adjustment time.
Its advertised constant-time adjustment property does not establish the
project's mixed classical/quantum W1 security. The existing research component
and its incomplete-protocol boundary remain recorded in
[QUANTUM_DAA_RESEARCH.md](../../../../formal/pon-nakamoto-v1/QUANTUM_DAA_RESEARCH.md).

## Acceptance obligations

| Obligation | Evidence required before promotion |
| --- | --- |
| Complete work relation | Fresh target-specific proofs with exact parent, body, task eligibility, state and profile binding |
| Legal branch history | Actual source retarget, MTP and future-clock validation through every epoch seam |
| Fork choice | Complete admission and strict accumulated-work comparison, including ties, rejection and recovery |
| Economic/physical advantage | Best known legal classical and quantum strategies, all setup/reuse/restart/proof/transport costs, honest progress and withholding |
| Security theorem | Explicit adversarial resources, dynamic participation, delay/clock bounds, lifetime and failure event; a justified native-to-model reduction |
| Protocol change | Separate versioned candidate with classical and quantum safety and liveness analysis, plus differential native regressions |

An epoch-end monotonicity rule would reject this particular negative-span
schedule but not a monotonically increasing, compressed timestamp schedule.
A hard difficulty range would bound one score/cost amplification mechanism but
would also alter response to participation changes. A trusted clock or finality
anchor changes the assumptions. These are candidate design choices requiring
their own contracts; none is activated by this audit.

## Reproduction and retained execution

The exact execution receipt and independent replay results accompany this
audit in `evidence/pon-joint-consensus-daa-20261108`. They distinguish source
checks, native execution, independent relation replay and conditional cost
arithmetic. Any failed command remains in that record. A successful finite
fixture does not close the physical work or whole-network security obligations.

## Strictly increasing compression control (2026-11-11)

The continuation on #863 at `249f772cc2a2ace5e363fd5fbfec4241a26f4d4d`
makes the monotone-compression limitation executable without changing the
installed timestamp, target, fork-choice or confirmation rules. The existing
`BranchTimeDaa` periodic reference shares heights 0 through 15 between two
branches. Ordinary timestamps continue at ten seconds per height; the other
branch uses exactly `parent.timestamp + 1` from height 16. Every timestamp is
strictly greater than its immediate parent as well as its branch's MTP.

| New-target height | Compressed first endpoint | Compressed last endpoint | Signed span | Effective span | New block work |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 16 | 0 | 150 | 150 | 150 | 2 |
| 32 | 151 | 166 | 15 | 38 | 7 |
| 48 | 167 | 182 | 15 | 38 | 31 |
| 64 | 183 | 198 | 15 | 38 | 123 |

Endpoints in the table are seconds after genesis. Exact accumulated work,
excluding genesis, is again 130 at ordinary height 65 and 793 at compressed
height 64. Thus negative epoch spans are not necessary for this finite
lower-clamp behavior. A strict-parent timestamp proposal would reject the old
negative-span trajectory while still permitting this one. This observation
does not establish that the more expensive classical branch can be produced
within an adversary's budget, or that an honest confirmation is reversed under
a real network schedule.

The two new tests in `daa_joint_consensus.rs` exercise this schedule through
the existing PNH1 and PGH2 owners. They require actual complete PNW1 generation,
admission, observed-clock activation and cold readback, with a separate
`pon-native-monotone-daa-v1` export. The old negative-span tests and their
`pon-native-joint-daa-v1` reader retain their original contracts. The new
`scripts/pon_monotone_daa_reader.py` independently recomputes all 114 packet
relations and the exact positive-span trajectory; it does not execute M06,
SQLite or a native cold reopen itself. Execution status and original logs
belong to the [continuation evidence](../../../../evidence/pon-monotone-daa-20261111/README.md).

Each run contains 15 common, 50 ordinary and 49 compressed packets. These are
114 unique packets within that run, not 114 independent attack samples. Some
PNH1 common/ordinary packets can be byte-identical to the previous experiment.
Logical validation clocks and native execution duration remain distinct; no
ten-second wall-clock mining cadence, quantum cost or profitability is inferred.

The same continuation tightens the existing native risk-ledger reader's
outcome binding. A bank wrapper must match the separately checked native
terminal's parsed JSON types and values: `false` cannot stand for integer `0`,
nor integer `1` for floating-point `1.0`. An external checkpoint still binds
the original bank bytes. This repairs an offline evidence comparison; native
confirmation results, probability bounds and release authority are unchanged.

The existing [joint qualification contract](JOINT_CONSENSUS_QUALIFICATION_V1.md)
continues to require one justified model and native refinement for common
prefix, chain growth, both chain-quality notions and the installed confirmation
event. Its 18 unknown inputs, 13 open proof obligations and null confirmation
and lifetime bounds cannot be filled by either of these finite regressions.
