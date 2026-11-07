# Pure PoN quantum cost and difficulty research

Status: executable conditional arithmetic, **not a quantum attack, security proof,
production DAA change, or mainnet readiness claim**. The source baseline is
4b6b8a91b6dfe41fbd7f40f40b359d535c2c4251 (PR #498). This work adds only formal
research, fixtures, tests and receipts. Native node consensus remains unchanged.

## 2026-11-07: constructed costs and literal winners under a finite deadline

Continue the #755 research candidate at
`7a98f27f99abccc28da2f1f3cc60bdaa2eca4890`. The new
[bounded literal executor](w1_bounded_search.py) and
[construction binding](w1_constructed_search.py) connect the existing full and
prefix-restricted W1 circuits to the actual nonce-domain census. The existing
synthetic network simulator keeps its own declared probability premises; this
fixed-context experiment does not qualify a dynamic branch or a mining attack.
The [source and validation record](../../evidence/pon-quantum-bounded-search-20261107/README.md)
separates implementation, original failures and frozen observations.

### Exact successes, valid unmarked candidates and stopping

The shared ideal Grover kernel now handles zero iterations by the exact input
probability and marked fractions `1/4`, `1/2` and `3/4` by their exact integer
periods. Previously `p=3/4, q=1` returned
`1.4997597826618576e-32` even though its exact success probability is zero;
the exact dyadic sampler could consequently sample an impossible winner.
At `p=1/2, q=99,999,999`, floating argument reduction also drifted from `1/2`.
The special cases use an exact rational parallel failure product before one
binary64 conversion. Other interior probabilities retain their explicitly
approximate trigonometric evaluation. This is a numerical correctness repair,
not a new hardness result.

Let `S` be the oracle's marked subset and `F` the full legal winner set, with
`S` contained in `F`. Grover search amplifies `S`, but the unmarked measurement
outcomes can still contain valid W1 winners. For a noiseless symmetric Grover
state, writing `s=|S|`, `f=|F|`, and `N` for the domain size,

\[
p_S(q)=\sin^2\!\left((2q+1)\arcsin\sqrt{s/N}\right),\qquad
p_{\rm valid}(q)=p_S(q)+(1-p_S(q))\frac{f-s}{N-s}
\]

when `s<N`; if `s=N`, every candidate is valid. A fully paid **full W1**
candidate check therefore accepts legal unmarked candidates as well. At zero
iterations the valid probability reduces to `f/N`, independently of the chosen
phase subset. A retained reduced control has `N=2`, `f=2`, `s=0`: an empty
restricted marked set does not make its postmeasurement legal-candidate
probability zero. This is a reduced control, not a native attack receipt.

The executor takes a fixed domain/iteration schedule and an exact decimal
horizon. It re-enumerates the supplied censuses, then charges single-resident
template setup, fresh preparation, iterations, readout, every processor's
serial full-W1 check, one proof and separate propagation. Exact fractions of
the declared binary64 clocks preserve partial phases and equality at the
deadline. No measurement is sampled before readout ends; unfinished checks
expose no winner flag. Incomplete proof or propagation receives no delivered
result. Partial iteration time is a paid clock interval, not an assertion that
a corresponding number of quantum gates ran. A plan digest and internal fixed
schedule do not attest external precommitment or real execution.

### One provisioned schedule, explicit physical assumptions

The binding constructs each full/restricted oracle from its canonical header
and public matrices, then derives all stage budgets from those actual leaves.
Every planned preparation and Grover iteration contributes to one common code
distance, even if success or the horizon prevents a later trial from starting.
All processors pay their data patches and factories; the peak register width
is reserved across domains. Each iteration includes forward compute, phase
marking, complete uncompute and diffusion. The declared schedule serializes
stage execution and T-state service; its ideal-overlap lower bound is not used
as an achievable clock. Per-processor classical search setup is also paid.

The error estimate covers only coherent patch-cycles and the declared T-state
residual error. Initialization, reset/readout and the controller remain ideal
assumptions or outside this estimate. Simulated outcomes use the ideal Grover
law, not a noise-calibrated success distribution. Census/proof replay is offline
observer work, not free advice given to a miner. `proof_complete` records the
assumed proof-clock phase; `online_proofs_generated=0` and
`native_blocks_admitted=0` remain explicit.

The replayable [campaign](experiments/w1_bounded_search_campaign.py) retains
native 64x64/rank-8/32-bit PNH1, changed-target and PGH2 domains alongside
separately labeled reduced domains. Both predicates use the same predeclared
schedules, processor choices, hypothetical physical parameters and analysis
horizon. Changing target recomputes the entire challenged relation. The chosen
four-second **analysis** horizon and illustrative qubit cap are not the original
native service profile; no service gate is rerun, replaced or relaxed. A large
cost for this deliberately nonoptimal construction is not a lower bound on an
attacker, and zero completed iterations in that construction proves no quantum
safety threshold.

The campaign also retains predeclared `target=1` PNH1/PGH2 controls with zero
Grover iterations. Their actual censuses determine whether these fixed domains
are empty. The four-round retry/switch/revisit schedule exercises paid cache
reuse and eviction, failed candidate checks, and schedule exhaustion rather
than counting provisioned but unstarted transitions as executed.

Physical-model admission additionally rejects a declared Toffoli T-layer depth
larger than its declared T-gate count. This is consistency of one supplied
decomposition, not a universal lower bound on the cheapest Toffoli implementation.

Bailey and Sattath's [difficulty-increase analysis](https://arxiv.org/html/2403.08023v2)
motivates preserving branch-local DAA, timestamps and accumulated work in the
eventual attack model. Bounded retarget steps do not by themselves close the
problem. [Zalka's oracle-query optimality result](https://arxiv.org/abs/quant-ph/9711070)
does not prove that every legal W1 miner must use these arithmetic circuits.
Hardware calibration, best known alternative strategies, equal real-budget
accepted-work production, dynamic multi-miner fork security and production
qualification remain open. Native target, chainwork and fork choice are unchanged.

## 2026-11-06 followthrough: adaptive clocks, cost admission and reuse scopes

This continuation remains **Draft/HOLD**. Source-specific checks and preserved
failures belong to the [cost-closure evidence entry](../../evidence/pon-quantum-cost-closure-20261106/README.md);
this section does not transfer historical test results to the new source.

The executable adaptive private-release path now schedules and checks the same
upward-rounded deadline from the exact represented binary64 start and wait.
Previously, a wait starting at `0.5` with duration `0.1` could reach the rounded
`0.6` event yet fail the subtraction-based timeout check and lose its timer.
A horizon before the corrected deadline still leaves the private work
unpublished. The synthetic Grover path also shares the literal-domain success
kernel, keeping `p=0` exactly zero and `p=1` exactly one for supported iteration
and processor counts; interior trigonometric probabilities remain approximate.

Direct `physical_estimate()` calls now enforce the count/depth/subtotal
consistency already required of circuit inputs. Complete requests and normal
JSON admission also reject impossible gate-count/width/depth combinations,
including 100 gates on one wire in one layer or a Toffoli on two wires.
Counts and conservative depth bounds must describe the **same declared
schedule**; unrelated loose count ceilings and independently tight depth
ceilings are not this input contract. The necessary wire-capacity checks
preserve valid serial aggregation with peak live width and the larger derived
count range. They do not verify a netlist, register layout or physical machine.

[The preprocessing diagnostic](w1_preprocessing_reuse.py) compares canonical
framed bytes and checks actual SHA continuation against `hashlib`. Its eight
[byte-change controls](test_w1_preprocessing_reuse.py) cover nonce, parent,
target, timestamp, profile, growth witness, PNH1 task and PGH2 task changes.
It distinguishes `A B` inputs `(A, B, N, q)`, task-commitment input bytes,
matching fixed-prefix blocks and complete challenge input. A reusable
five-block SHA checkpoint does not make the complete challenge reusable;
identical challenge bytes alone do not establish later-intermediate reuse when
relation parameters differ. Input equality is a sufficient reuse condition,
not a lower bound excluding other caches or algorithms. No saved time, energy
or real amortization frequency is measured here.

Full and prefix-restricted fixed-context W1 constructions already exist, with
explicit loading, reverse operations and their distinct marked predicates.
The remaining gates are calibrated fault-tolerant hardware, measured work
production under equal real-time/resource budgets, an executable profitable
consensus attack or a mixed quantum/classical DAA and fork-choice security
proof. These repairs and reuse controls close none of those gates; native
consensus and production activation remain unchanged.

## 2026-11-06: measurement tails, declared depth and actual fork selection

Continue from integrated source `840522d0b65b4989f1a2a1d09c0ad51af1a1956d`.
The network and literal-domain measurement paths now draw an integer over the
exact dyadic denominator of the computed binary64 probability. The former
`random() < p` comparison gave its zero atom probability `2^-53`, inflating
smaller positive probabilities. The corrected sampler needs at most 1074 bits,
accepts true tail winners, and samples exactly the represented probability;
it does not make the preceding trigonometric calculation exact. Source-bound
network/adversarial campaigns and literal-domain measurements use fresh v2
namespaces. Historical traces and failures keep their original identities.

The event simulator also exposes `quantum_tip_policy="measure-at-next-iteration"`
for its one honest-tip quantum miner, alongside the default `restart` policy.
On an adopted competitor tip, a prepared old candidate completes the current
whole Grover iteration and pays readout, candidate verification and any proof
on its original parent/target. Repeated tips do not draw again or erase cost.
Unfinished preparation, shocks and horizon truncation keep their explicit paid
cancellation rules. Completion times round upward; the conditional whole-run
resource envelope still covers all permitted starts and planned iterations.
The paired campaign scenarios use identical declared budgets. This is a bounded
strategy model, not a multi-quantum-miner correlation model or profitability proof.

Physical models now reject a complete Toffoli decomposition depth below the
same model's T-layer depth. This self-consistency condition applies before
JSON request admission, logical/physical estimation or event-clock binding.
Equality is permitted; no hardware calibration or minimum-cost result follows.

The native DAA fixture now builds two full-work branches that separately reach
the lower and upper timestamp clamps. A height-48 harder branch must displace
a height-49 lower-work branch. A distinct equal-work sibling with smaller id
must not displace the selected tip, including after authenticated reopen.
All 67 packet records are retained under a separate fork-choice schema and
independently recomputed by the Python full PNW1 verifier. The existing bounds
fixture keeps its own namespace and all original negative/time controls.
The original full-workspace CI command exports both scopes into fresh separate
directories, then checks exact report digests and runs each reader's mutations.
These are native correctness controls with logical timestamps, not a measured
quantum attack or a same-resource economic comparison.

## Literal domains, a cheaper legal subset, and source-derived Fast DAA arithmetic

This continuation starts from integration source
`a9b8602706b66adba82655c3c2ce90bde88620a2`. It changes research implementations
and their reproduction checks. Native target, required work, branch selection,
confirmation and activation remain under the existing protocol owners.

### A legal attacker need not search every legal winner

[The prefix-restricted construction](w1_quantum_restricted_oracle.py) searches
an explicitly named subset of W1. For every noise label it requires the first
`N*R` raw words to be below `Q`. On that subset, the original rejection sampler
returns exactly those words, in the same order. The construction therefore keeps
the complete original challenge, low-rank factors, ordered tiled-prefix trace,
ticket and inclusive target comparison. Every retained marked candidate has
the original relation; some otherwise legal winners are deliberately discarded.

This distinction matters for attacker cost accounting. A winning miner needs
one valid winner, not an implementation that marks every possible valid nonce.
The old complete construction is one upper bound and cannot be treated as a
mandatory cost for all attackers.

The restricted phase predicate is:

\[
 g_{\mathrm{sub}}(x) =
 \left[\bigwedge_{\ell=0}^{3}\bigwedge_{j=0}^{NR-1}
       \mathrm{raw}_{\ell,j}(x)<Q\right]
 \land [\mathrm{ticket}_{\mathrm{W1}}(x)\le T].
\]

All validity flags, field operations, input copies and reverse operations are
charged. Invalid raw operands still have total reversible arithmetic and never
mark a state. There is no free data-dependent address or free rejection branch.
Preparation and diffusion retain the **original nonce register**. In particular,
the search denominator is `2**nonce_bits`, not the count of canonical-prefix
nonces; a filtered initial quantum state is not supplied.

For native `N=64`, `R=8`, `Q=2**32-5`, the restricted construction computes 64
noise hashes per label, instead of the full unrolled construction's 128, and
removes its 2,097,152 coherent selection calls. The native classical sampler
already stops after enough accepted words, normally near 64 counters. Thus
"half the hashes" compares these two coherent constructions, **not** a measured
factor-of-two improvement over the classical miner.

| 64-bit nonce construction | Full predicate | Prefix-restricted predicate |
| --- | ---: | ---: |
| PNH1 reserved logical qubits | 22,253,173 | 22,029,941 |
| PNH1 compute/mark/uncompute gates | 17,718,016,715 | 15,992,168,955 |
| PNH1 phase depth upper bound | 1,969,835,151 | 1,102,032,975 |
| PGH2 reserved logical qubits | 22,253,429 | 22,030,197 |
| PGH2 compute/mark/uncompute gates | 17,718,795,839 | 15,992,948,079 |
| PGH2 phase depth upper bound | 1,969,864,925 | 1,102,062,749 |

These are constructive census comparisons, with the same conservative retained
intermediate-register schedule. They do not measure physical QPU execution,
minimum work, a quantum/classical cost advantage or consensus attack viability.
The restricted strategy must use its own marked count `M_sub` in the success law;
substituting the full predicate's `M` is invalid.

Under the additional iid-uniform **raw-word** premise only, prefix retention is
`((2**32-5)/2**32)**2048`, approximately `0.9999976158170497`. This does not prove
independence from the ticket and cannot be multiplied by ticket probability to
obtain a W1 success theorem. The [differential campaign](experiments/w1_restricted_oracle_campaign.py)
retains actual discarded winners in reduced controls, replays literal native-size
domains, verifies their winning PNW1 proofs, and executes actual leaf gates for
one retained and one rejected reduced candidate. Native-sized circuit execution
remains hierarchical macro interpretation.

### Actual fixed-header marked sets

[Literal nonce censuses](w1_marked_domain.py) compute the exact W1 relation for
every nonce in a bounded declared low-nonce subspace. PNH1 and PGH2 use their
own challenge domains. Every native-shape winner is serialized from one public
`A B` precomputation and checked by the retained separate scalar full-proof
verifier. This is relation verification; native parent/task eligibility, clock,
required target and state application remain explicit preconditions.

The target itself is inside the challenged header. Changing difficulty requires
a new challenge/noise/trace/ticket census; merely rethresholding old tickets is
not a valid retarget experiment. Conversely, changing only the declared nonce
width does not make overlapping nonce values independent. Their identical
headers must have identical challenges and tickets.

The [literal-domain campaign](experiments/w1_marked_domain_campaign.py) records
zero-solution domains, prefix-restricted marked counts, overlap/covariance as
descriptive finite observations, and predeclared retry schedules. All processors
condition on the same actual marked set. Retrying `M=0` does not resample a
solution. Setup, fresh preparation, all measured-candidate checks and winning
proof construction have explicit cost scopes. Those clocks are caller premises,
not measurements of a quantum machine. This remains a bounded fixed-context
bridge; the evolving synthetic network is not silently relabeled a fully native
chain simulation.

### Interrupted domain preparation remains payable

The event model previously cached a domain when setup began and then returned
zero setup on reuse, including after participation changes interrupted setup.
A two-second setup paused at 0.5 seconds and resumed at one second could pay
only 0.5 seconds yet complete three candidate checks before a four-second
horizon. The regression now preserves exact rational remaining setup and
rounds resumed clocks upward. It pays two seconds and completes one check.
Repeated interruptions retain the same domain and marked count; a changed
parent pays for a fresh domain. This resumes classical preparation progress,
not a partially completed coherent search state.

### Fast DAA: inspected retarget component, incomplete protocol

The full revised ePrint PDF remained unavailable. A different primary source is
now available: Yu Shen's author-linked September 15, 2026 report,
[Parallel Blockchains and Applications](https://drive.google.com/file/d/11XmEh1BczmuDZhxzjvJW_K_unsCGugdD/view).
PDF pages 61--63, displayed slides 52--54, give the approximate-agreement
operation and difficulty formula. The [source manifest](vectors/fast-daa-author-slides-retarget-v1.json)
pins the PDF hash, author link, inspected pages, version distinction and
unresolved interpretations. The proceedings version, revised ePrint and author
slides are not treated as interchangeable algorithm versions.

[The arithmetic component](fast_daa_reference_component.py) implements those
displayed equations with exact rational arithmetic. Approximate agreement
removes extremes, selects the first representative of each retained chunk,
then averages representatives. It is **not** an ordinary trimmed mean.
For example, after trimming two extremes on each side of
`[1,2,3,4,10,16,100,200]`, the representatives are `3,10`, giving `13/2`;
the plain trimmed mean would be `33/4`.

The component explicitly declares ascending grouping and accepts only complete
chunks, unambiguous odd-length medians and present nonempty referenced histories.
It refuses unspecified cases. These are research API restrictions, not invented
production rules. It neither authenticates the input histories nor implements
the epoch, cross-chain reference, mining, target encoding, fork choice or ledger
protocol. `fast-daa-2026` therefore still refuses as a complete network backend.
Common-prefix/growth/quality/liveness and a mixed quantum-resource theorem remain
open, as do the mappings of security parameters and physical network clocks.

## Constructed oracle, adversarial strategies and complete bounded protocol model

The next continuation preserves integration source `03163dcb849a15cd267fcaf704a533a88cd54131`
and the concurrent Cell/model work through `d4816ca5d1375347d8ed341a434158e350c29bbc`.
The [construction reproduction record](../../evidence/pon-quantum-construction-20261104/README.md)
pins the later tested research source and lists retained failures and remaining
security gates. Native target, chainwork, fork choice and activation rules are
unchanged by this continuation. Earlier observations below retain their original
source scope; new research evidence does not qualify unrelated native changes.

### A concrete complete winner predicate for a fixed public context

[The hierarchical oracle](w1_quantum_oracle.py) now constructs the complete W1
winner predicate for a fixed canonical PNH1 or PGH2 header template and public
matrices. Its search variable is the header's actual nonce, with up to 64 bits.
The challenge is computed from the exact domain-framed header; it is not a free
256-bit search input. Task commitment and canonical matrix values are checked.
Native task eligibility, timestamp/target requirements, state execution and
other block-admission conditions remain checked classical preconditions.

The construction consists of actual clean-XOR
[X/CNOT/Toffoli leaf circuits](w1_quantum_primitives.py), static input-copy
wiring, persistent intermediate registers, phase marking and the complete
reverse schedule. Leaf outputs map directly to their external destination;
input/output aliases are rejected. Every leaf restores its input workspace.
The outer reverse restores all intermediate registers, including the failure
flags. H preparation, Z phase marking and a clean AND-ladder diffusion circuit
are accounted separately. This is one deliberately conservative construction,
not a proof of minimum work or an optimized quantum miner.

Noise sampling always covers all 128 counters for each of four labels, preserves
rejection order and selects the first 512 accepted field elements. Static scans
visit every destination, so no QRAM, dynamic addressing or coherent loading
oracle is hidden in a unit-cost operation. Insufficient accepted words yield an
unmarked candidate even when its ticket otherwise passes. Reduced-field controls
force rejections and exhaustion; the tiny probability of those branches at the
native field width is not used to omit them.

The five fixed initial SHA compression blocks of the header challenge can be
precomputed classically. The remaining calls and exact transcript order are
part of the coherent predicate:

| Component | PNH1 fixed template | PGH2 fixed template |
| --- | ---: | ---: |
| Complete framed header challenge input | 343 bytes | 407 bytes |
| Coherent header-challenge SHA compressions after fixed prefix | 1 | 2 |
| Noise SHA compressions, including every bounded rejection branch | 1,024 | 1,024 |
| Low-rank field multiplications | 65,536 | 65,536 |
| Ordered transcript field multiplications | 262,144 | 262,144 |
| Transcript SHA input / compressions | 131,120 bytes / 2,049 | 131,120 bytes / 2,049 |
| Ticket SHA compressions | 2 | 2 |

The PGH2 challenge tag is 37 bytes. A previous intermediate test expectation of
405 framed bytes was wrong; the actual native framing gives 407. The compression
count remains two coherent blocks after the five fixed blocks.

For the declared 64-bit nonce schedule, the resulting constructive census is:

| Resource | PNH1 | PGH2 |
| --- | ---: | ---: |
| Reserved logical qubits | 22,253,173 | 22,253,429 |
| Forward winner-compute gates | 8,859,008,357 | 8,859,397,919 |
| Compute–Z–uncompute gates | 17,718,016,715 | 17,718,795,839 |
| Compute–Z–uncompute depth upper bound | 1,969,835,151 | 1,969,864,925 |
| Additional diffusion gates / depth upper bound | 383 / 131 | 383 / 131 |

All intermediate outputs are retained until the global reverse, making the space
cost large. Better pebbling, recomputation, constant folding, alternative arithmetic,
data layouts or variable-time search may improve it. **A large upper bound cannot
establish that a quantum attacker must pay that cost.** The exact leaf netlist
hashes, call counts and wire schedule make this particular construction auditable.
They do not supply a physical QPU, a hardware compiler, or an adversarial lower bound.

The [oracle campaign](experiments/w1_quantum_oracle_campaign.py) distinguishes
three kinds of evidence: whole reduced-shape phase execution with actual leaf
gates; native-size hierarchical macro execution against a separate scalar W1
relation; and optional comparison to a historically admitted native PNW1 packet.
The native-size run does not execute billions of leaf gates. The historical packet
does not constitute a fresh native-node execution on the current integration tree.
Winning-candidate proof construction, public `A B` reuse and full PNW1 materialization
remain classical work after a winner, not an invented cost on every coherent query.

### Unknown marked counts, paid restarts and bounded attacker choices

[Adversarial search](quantum_adversarial_search.py) adds an explicit finite domain.
Its marked count is sampled once using exact integer inclusive ticket comparisons,
or supplied as a clearly conditional control. The evaluator keeps that count
hidden from the strategy. Failed retries and independent parallel processors share
the same domain; an `M=0` domain does not acquire a solution on the next attempt.
Changing a domain changes an explicit template salt and incurs setup cost. Actual
W1 realizability and independence of these modeled fresh domains are not proved.

For a known conditional fraction `M/N`, a batch of `P` independent processors
has success `1-(1-sin((2*q+1)*asin(sqrt(M/N)))**2)**P`. For an unknown count,
the expectation is taken **after** conditioning all processors on the shared
count. It is not obtained by inserting the mean fraction into Grover's formula
or by independently resampling a count for each processor. Exact binomial weights
are used only on a bounded small support; amplitudes and rates use float64.

The optional optimizer maximizes renewal throughput over a declared finite
iteration grid at one fixed target, using the same paid processors and clocks
for every candidate. All measurements pay preparation, readout and classical
candidate checks; winning batches additionally pay proof construction. Its finite
binomial mode requires a fresh domain after every measured batch. Persistent-domain
strategies do not obtain a fictitious independent geometric completion time.
This is not BBHT, an optimal posterior strategy, a global profit optimizer, or a
proof that the best real attacker was searched exhaustively.

The event model also adds MTP-minimum, future-bound and retarget-boundary timestamp
strategies, including valid regressions relative to a parent timestamp. Adaptive
private release reads the miner's separately delayed public view, never the global
observer's current tip. New finite experiments retain all prior default scenarios
and add source-bound adversarial campaign replay. Proof/candidate-check time,
cancelled work, future-parent delays and right-censored observations remain paid
and visible.

### Circuit-derived event clocks with a whole-campaign error envelope

[The resource-clock adapter](quantum_resource_clock.py) uses a single code distance
for the whole bounded campaign. The trial-start envelope is
`1 + max_events * max_blocks` per processor: a deferred delivery can adopt several
competing tips and restart more than once within one event. Each possible start
is charged a full preparation and the largest allowed iteration count, even if
interrupted. Error estimates include all processors and every allocated logical
patch/cycle plus the declared magic-state residual error. An unsatisfied error
budget or insufficient physical qubits refuses the binding.

Only the explicitly serialized stage/magic-delivery schedule becomes an event
clock. Ideal overlap is not promoted to an achievable speed. Quantum speed factors
must be on/off for a resource-bound run. Per-stage clocks, complete search deadlines
and quantum proof deadlines are rounded upward; exact binary-rational summation
avoids the downward rounding that can reappear after individually rounding clock
fields. Classical preprocessing and search setup are conservatively repeated on
every trial in this schedule. This overcharge is explicit; a negative attack result
cannot be interpreted as resistance to an attacker who optimizes reuse.

The [coupled campaign](experiments/quantum_resource_clock_campaign.py) accepts an
oracle specification and regenerates every circuit-stage budget from the construction.
Replay rederives those budgets, the whole-campaign distance, clocks and full event
trace digests. This binds a circuit cost shape, not the fixed header's actual marked
set to the evolving synthetic network targets. In particular, a reduced nonce
specification does not become a matching finite-domain mining experiment merely
by supplying its circuit budget. The physical parameters, factory model, routing factors, classical
times and uniform-ticket probability premise remain supplied assumptions. Source
hashes and reproducible arithmetic are not physical calibration or authenticated
hardware execution evidence.

The serialized per-T service premise includes production, delivery, immediate
injection and feedforward, with a live service/buffer patch paid inside the
factory footprint. It cannot silently mean production alone while assuming free
storage for a large batch of magic states. No fault-tolerant layout is verified.
The error union covers coherent stage cycles and the declared T-service errors;
initialization/reset/readout and the classical controller are assumed ideal or
outside its scope. Removing coherent idle time during classical waits does not
turn this conditional union into an end-to-end machine failure bound.

### A separately identified complete bounded parallel-chain candidate

[The OHIE text-profile model](parallel_variable_ohie.py) and its
[campaign](experiments/parallel_variable_ohie_campaign.py) use the complete
[Wang et al. arXiv v2 source](https://arxiv.org/html/2105.02927v2), including
Sections 4.2/6.3 and Appendix G. The model has actual common-parent commitments,
post-hash chain sortition, pivot references, branch-local target computation,
exact rational cumulative difficulty, delayed imports, private withholding,
cross-chain confirmation barriers and deterministic synthetic transaction-ledger
formation. It is a complete bounded state machine under its named profile, not
just a different target formula.

Several distinctions are part of that identity. The selected rank rule is the
body's `max(rank + difficulty, trailing.next_rank)`; Appendix G's conditional
increment differs on a concrete counterexample. The source also has inconsistent
environment-window notation. Targets use exclusive `ticket < T` and rational
`2**k/T` work, unlike native PoN's inclusive target and integer u512 chainwork.
The model transmits the entire committed parent vector, and its timestamp/finite
resource rules and confirmation lag are explicit experimental premises. The
literal same-hash low-bit sortition has finite-width bias; tiny target controls
show unreachable chains, which must not be presented as deployed-protocol attacks.

The candidate's classical random-oracle proofs are not inherited by these finite
parameters, the engineering encodings, or a quantum-resource overlay. The complete
Fast DAA 2026 PDF and the author-linked official slides remained unavailable during
the public-source retry. `fast-daa-2026` therefore still fails explicitly. This OHIE
profile is a separately identified candidate and does not close that fidelity gate.

### Remaining scientific exit conditions

Implemented constructions and passing replay close the specifically declared
engineering checks. They leave these distinct obligations open: adversarial W1
cost minimization or an appropriate lower bound; physically calibrated fault-tolerant
resource and data-access assumptions; a justified mapping from legal W1 search
domains to winning probabilities; full Fast DAA source-to-protocol reproduction;
and a mixed classical/quantum consensus argument for common prefix, growth, quality
and transaction liveness under a concrete deployed profile. Neither `sqrt(D)`
chainweight nor a new multi-resource score is activated by these experiments.

## Resource accounting and event scheduling continuation, 2026-11-04

The continuation starts from integration PR #688 at
`a4a0e2b561f057cfa3189979c5bf11f3a0eb2353`, with protected main at
`dd6e1c3cbeacbdc532b0679297835b3a0aac78f0`. These are source observations,
not an activation or a claim that unrelated native gates are complete. The
native validation was repeated after preserving concurrent integration commits
`d0737cf5434894ce47fad8082376fc417313c2cb` and
`bd2777f9cc74df10ba07ae8202584ed0fb90a519`. Research tests and the 30-run campaign
were repeated at checkpoint `9cecbf32ddbeb56c8556730d2d0102aff1e54310`, whose
native/configuration input bytes match the latest native validation. The older deterministic
model and its failed schedules below remain intact. The
[reproduction manifest](../../evidence/pon-quantum-event-resources-20261104/README.md)
records the tested source composition and the limits of each observation,
including the later preserved recovery/release-authority commit
`245146c7d2e6f7dfcda463f6a7dd342d4d7ca818`. Its unrelated source changes do not
inherit the earlier native validation merely by sharing an integration branch.

Two additional experiments address different missing parts:

- [Winner-predicate resource accounting](quantum_oracle_resources.py) separates
  task preprocessing, per-search setup, preparation, forward winner computation,
  phase marking, inverse computation, diffusion, interrupted work, classical
  checking after every complete measurement, and post-winner proof/propagation.
  Failed candidates and zero-iteration trials still pay their candidate check.
  A missing full W1 circuit produces an unknown
  cost, not a multiplication of isolated SHA component counts into a fabricated
  oracle. Caller-supplied circuit budgets enable explicitly conditional logical
  qubit/gate/depth and error-correction sensitivity calculations.
- [Event-based network experiment](quantum_network_sim.py) replaces the older
  expected honest clock with sampled classical arrivals and finite Grover
  trials. Proof completion and message delivery are separate events. Public-tip
  restart and private-fork continuation have distinct rules; participation
  changes, failed searches, discarded progress and unfinished trials remain
  visible. The [campaign entry point](experiments/quantum_network_campaign.py)
  produces bounded, seeded observations rather than a consensus security proof.

### The minimal legal winner predicate

For the current PNW1 relation, the ticket depends on the challenge and the exact
ordered tiled-prefix transcript. Canonical fixed task matrices, their task
identity and a useful `A B` product may be prepared classically. In contrast,
challenge-derived noise, challenge-modified matrices, ordered intermediate
prefixes, trace hashing and target comparison cannot be discarded merely because
the input task is public. The actual cheapest implementation of that predicate
remains an open adversarial optimization problem.

The native [relation](../../trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs)
already separates `TranscriptEvaluation` from corrected-product construction;
[legal attempts](../../trillionnium/crates/trnm-crypto-primitives/src/pon_work/legal_attempt.rs)
also expose public task reuse. This is why a cost model must not mechanically
charge the full verifier, corrected product, SQL, logging, network transport or
a separately generated succinct proof on every coherent query. A winning
candidate must still yield a complete valid proof before native acceptance.
Preprocessing is charged at its actual reuse scope; it does not confer current
task eligibility or authorization.

The resource calculator's circuit stages are supplied assertions. Even when
every stage has numerical values, it has not synthesized or verified a complete
W1 phase oracle, proved a minimum cost, calibrated a physical QPU, or established
the quantum security of the proof system. Its surface-code equation, gate
decomposition, factory throughput, residual magic-state error, routing factors
and clock period are explicit assumptions. Estimates that cannot satisfy their
declared error budget are reported as unavailable. The default W1 case remains
unknown; the fully populated demonstration is a small non-W1 arithmetic example.

### What the network experiment can and cannot establish

The periodic backend keeps the current branch-local target, integer required
work, median-time and future-time rules. Equal work retains the existing local
tip. Work from different profile identities is not comparable. The ASERT
backends reuse the earlier isolated exact-u256 arithmetic and remain research
policies; they are not alternative installed protocols.

For a specified marked fraction `p` and `q` Grover iterations, one ideal trial
has success probability `sin((2*q+1)*asin(sqrt(p)))**2`. Increasing `q` beyond
the peak can reduce success. Equating the marked fraction of a finite W1 search
space with the uniform ticket probability `(target+1)/2**256` is a separate
assumption. Unknown or zero marked counts, BBHT search, correlations, hardware
noise and the actual reversible predicate are not inferred from this formula.
The automatic iteration choice is near the first success-probability peak;
it is not claimed to maximize throughput or attacker profit. Explicit iteration
counts allow other bounded strategies to be tested.

A new public block can invalidate the parent of an honest-tip search; it does
not force an attacker mining a private branch to abandon that branch. The
experiment therefore records restart costs without building this incorrect
defence into its private-fork policy. A future-dated private parent does not stop
construction of its private descendants. Receiving miners separately enforce
the future-time rule for every ancestor; eligible prefixes can be adopted while
later descendants wait. Bounded phased timestamp strategies expose compression,
holding, relaxation and a configured tail as explicit inputs. Candidate checking,
post-winner proof and propagation costs must finish before a remote modeled receiver
can adopt that block. These are synthetic header events without W1 proofs,
task/effect execution or native networking.

Probe confirmation follows the native conjunction: six descendants and at least
six times the inclusion block's required work, with the inclusion block excluded
from both counts. Six easier descendants alone need not satisfy confirmation.
Trace readback independently checks integer credit, ancestry and admission-time
constraints and replays the seeded experiment. Source hashes and claims about
which files existed at the recorded Git commit are also checked. This is a
separate implementation check within this development task, not an external
cryptographic audit.

Reorganization, growth, quality, prefix and transaction-wait observations from
a finite run are empirical diagnostics under its declared assumptions. They
are not common-prefix, chain-growth, chain-quality or transaction-liveness
theorems, and they do not provide a mixed classical/quantum security threshold.
No bounded campaign, including a run without a reorganization, establishes that
the protocol is secure. No successful modeled private fork establishes a
physically realizable attack on Trillionnium.

### Candidate literature and implementation boundary

[Bailey and Sattath, arXiv:2403.08023v2](https://arxiv.org/html/2403.08023v2)
provide a variable-difficulty quantum attack construction and variants that
address timestamp lag and bounded adjustment factors. Their idealized mining
model does not supply a W1 oracle. The current exact 16-block clamp and integer
rules still have to be respected by any Trillionnium-specific schedule.

[Garay, Kiayias and Shen, Fast Difficulty Adjustment in Proof-of-Work Consensus](https://eprint.iacr.org/2026/1116)
is a CRYPTO 2026 paper, with a revised ePrint dated 2026-09-10. Its construction
uses parallel chains and approximate agreement over previous-epoch information.
The public abstract, [author-institution page](https://www.iog.io/papers/fast-difficulty-adjustment-in-proof-of-work-consensus)
and its two-page [explainer](https://www.iog.io/api/research/pdf/explainer/CMS48YZX)
were accessible for this continuation; the complete ePrint PDF was unavailable
through the research interface. There is no complete pseudocode-to-source
mapping here. Requesting its backend must fail explicitly. A trimmed mean,
median of targets, or faster single-chain adjustment is not a reproduction of
this construction. The paper's asymptotic adjustment result is not a seconds
guarantee for PoN or a quantum-mining theorem.

[Baig, Guenther and Pietrzak, Nakamoto Consensus from Multiple Resources](https://doi.org/10.4230/LIPIcs.AFT.2025.16)
classify weight functions in an ideal continuous-resource model against private
double spending. Monotonicity and joint degree-one homogeneity in timed resources
are central: `Gamma(S, alpha*V, alpha*W) = alpha*Gamma(S,V,W)`. The discrete model
needs additional resource-variation and majority assumptions. Replotting,
selfish-mining economics and implementation-specific network losses have their
own boundaries. This is a theoretical comparison, not a proposal to sum arbitrary
scores or replace current required work with `sqrt(D)`.

The original milestone left full W1 reversible synthesis open. The construction
above now supplies a specific upper bound. Adversarial cost minimization, a complete
Fast DAA reproduction and a proved mixed-resource PoN security model remain
separate research exit conditions. The native pure-PoN engineering line retains
its present consensus and original acceptance budgets.

## What this package establishes

[quantum_daa_model.py](quantum_daa_model.py) executes the current development
profile's periodic target/chainwork/time arithmetic and explicit alternative
cost hypotheses. It also evaluates isolated raw-timestamp and median11 ASERT
arithmetic, plus a **new, unproved fixed-probability/variable-work candidate**.
Every alternative is a counterfactual research policy. None has an activation
path here.

The model exposes a concrete distinction: a chain can award credit proportional
to difficulty while an assumed quantum search costs only its square root.
For selected schedules this permits a slower-at-baseline private miner to
accumulate more credited work and subsequently restore a recent tip timestamp.
It also records bounded schedules that fail either test. This shows which
cost premises a proposed mitigation needs; it does not establish those premises
for W1, real hardware, proof generation, state execution or a public network.

The existing [classical query bound](work_query_bound.py) is conditional on
classical first queries to an ideal uniform ticket oracle. Its expected-credit
bound does not become a bound on quantum queries, elapsed time, energy, or
arbitrary neural compute. The native
[work/DAA boundary](../../docs/protocol/pon-nakamoto-v1/details/WORK_COST_DAA_BOUNDARIES.md)
and the actual packet experiments remain separate evidence.

## Source ownership and integer semantics

At the frozen baseline, [consensus.rs](../../trillionnium/crates/trnm-pon-node/src/consensus.rs)
owns required work, retarget arithmetic and timestamp checks. The node's
expected_target path in
[store.rs](../../trillionnium/crates/trnm-pon-node/src/store.rs) evaluates the
candidate branch's actual ancestors. The formal model imports their existing
[arithmetic reference](reference.py), not the node, a proof generator, or a
network receiver.

The [development profile](../../config/pon/devnet-v1.json) supplies:

| Parameter | Modeled value |
| --- | --- |
| Periodic interval | 16 blocks |
| Target spacing | 10 seconds |
| Expected retarget span | 15 × 10 = 150 seconds |
| Observed span clamp | [38, 600] seconds |
| Median timestamp window | Previous 11 branch timestamps |
| Future allowance | 120 seconds |
| Maximum target | 2^255 − 1 |
| Required work | floor(2^256 / (target + 1)) |

The lower clamp uses **ceil(150/4) = 38**, not 37 or 37.5. Target inclusivity
is preserved: the ideal lottery probability is (target + 1)/2^256.
Time in this model is relative to zero; an additive genesis offset does not
change these arithmetic tests. The common prefix is synthetic arithmetic:
eight short retarget windows followed by an ordinary window produce a target
well below the maximum. No prefix header has a W1 proof or native admission.

The [#487 research candidate](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/84a0c697a3178eaee31ff9f60851a42c479b73f9/trillionnium/crates/trnm-pon-node/src/consensus.rs)
contains a separately scoped ASERT research interface. This package neither overwrites
that candidate nor treats its shadow/research paths as current native DAA.
The Python implementation uses exact raw u256 targets and the same absolute
anchor convention. It does not introduce Bitcoin compact-target rounding into
PoN.

The independently specified numerical checks are the 18 CalculateASERT
unit vectors from
[Bitcoin Cash Node, pinned commit 07576013](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/test/pow_tests.cpp#L649-L772).
The [immutable fixture](vectors/quantum-daa-asert-bchn-v1.json) records source,
blob and parameter hashes, exact targets and expected compact encodings.
It covers negative exponents, clamp boundaries, underflow and overflow.
This is **18 upstream unit vectors, not the full external ASERT vector corpus,
and not execution of #487's native implementation**.

The algorithm follows the pinned
[BCHN implementation](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/pow.cpp).
Signed fixed-point division truncates toward zero, as in Rust/C++; Python's
negative floor division would produce a different result. The vector adapter
adds 600 to the upstream table's time difference and one to its height
difference, exactly as the upstream test does. The raw and median11 branches
each have a steady 10-second honest control; they use consistent anchors.

## Cost model and exact limits of an attack observation

Write p = (T+1)/2^256. The current weight is approximately 1/p.
If one full challenge-bound PoN lottery evaluation has stable cost k_C,
classical expected search cost is k_C/p. Under an additional ideal quantum
search hypothesis, a full reversible winner oracle with stable cost k_Q
would instead cost proportionally to k_Q/sqrt(p).

Thus weight per modeled classical resource is approximately 1/k_C, while
weight per modeled quantum resource scales as 1/(k_Q sqrt(p)).
Increasing difficulty can increase the second quantity. This derivation
assumes the complete oracle, including required neural work and ticket
transcript, can be evaluated coherently. It is not an estimate obtained by
applying Grover search to the final SHA-256 alone.

In this package the attacker's baseline rate is **assumed** to be 0.25 times
the honest network rate: 40 modeled seconds per baseline block against the
honest control's 10. That is a relative rate, not a measured hardware share;
if the same rates were additive classical rates it would correspond to 20%
of their total. Quantum constant factors are absorbed into this unmeasured
baseline. The model does not infer the number or capability of real QPUs.

For each branch, mandatory cost is charged before its candidate timestamp can
become admissible. A proposed future timestamp incurs an explicit wait.
Targets/weights are exact integers; the hypothesized square-root costs use
70-digit decimal arithmetic, with 24-digit reporting. The honest competitor
receives floor(elapsed/10) baseline blocks at a constant target. This is a
deterministic expectation-based control, not a stochastic execution or
confidence bound for private-chain success.

The phase schedule compresses timestamp increments to 5 seconds, holds them
at 10, relaxes them to 20, then advances a catch-up tail at 10. All generated
timestamps exceed median11 and respect the future allowance at the modeled
completion time. A report marks a conditional reorganization schedule only
when its private chain both has greater modeled chainwork and has brought its
tip to within 10 seconds of modeled current time. This additional recent-tip
condition is a research challenge, not a newly introduced consensus rule.

The standard campaign contains the following distinct observations:

| Scenario | Purpose |
| --- | --- |
| Periodic/classical | Control: cost and credited difficulty grow together |
| Periodic/quantum-query hypothesis | Test the assumed square-root mismatch |
| ASERT160 raw and median11, 12,000 tail blocks | Retain bounded runs that have excess work but do not catch up in that budget |
| ASERT160 raw and median11, 16,000 tail blocks | Check an explicitly larger budget, retaining the earlier failures |
| ASERT7200 raw, short budget | A slower response with no successful path in this finite schedule |
| Fixed p, linear mandatory cost | Candidate premise under which work adjustment adds no scale-dependent advantage |
| Fixed p, square-root mandatory cost | Counterexample when that key premise fails |
| Periodic plus 5-second proof delay, original budget | Charge a hypothetical post-winner cost and retain the bounded failure |
| Same proof delay, longer tail | Test whether constant proof latency alone closes the modeled path |

No failure above proves a DAA secure, and no successful model run proves a
deployable attack. There is no actual nonce search, task-lease selection,
proof acceptance, fork admission, replay/state synchronization or networking.
The finite schedule is not an exhaustive adversarial search. Pooling,
interruption of quantum search, target-dependent oracle costs, fork-choice
resource bounds, stochastic variance and honest responses remain outside it.

### Relation to the quantum difficulty-increase paper

[Bailey and Sattath, v2](https://arxiv.org/html/2403.08023v2) analyze how a small
quantum miner can use difficulty changes to amplify credited work relative to
quantum search cost. Their constructions include raising/lowering difficulty
gradually and restoring recent tip time. Consequently, factor-four clamping
or rejecting an obviously stale final timestamp is not by itself a general
answer to that mechanism. The paper's setting is Bitcoin-style proof of work;
it does not supply a reversible W1 implementation or a theorem for this chain.

The raw/median11 ASERT experiments here are new conditional model observations,
not a claim that the paper proved these particular policies unsafe. No evidence
here supports replacing chainwork with its square root or choosing the longest
block count. Such changes alter classical incentives and security and would
require their own analyses. No BFT, PoS, TEE authority or hash-only work is used
to replace PoN in this candidate.

## Fixed probability and variable mandatory neural work

This branch is a research hypothesis, not an available security primitive.
Keep p0 fixed (or eventually prove a tightly bounded variation) and adjust
the amount u of mandatory challenge-bound neural work. The arithmetic model
inverts the periodic span:

    next_u = clamp(ceil(parent_u × desired / bounded_observed), 1, max_u)
    block_weight = u × floor(1/p0)

The unit budget is a declared integer count, **not measured FLOPs, energy,
model quality, useful outputs, or an existing W1 profile parameter**.
Its initial value is 1024 and the modeled maximum is 1,048,576.

Under full winner-oracle cost assumptions k_C(u)=a_C u and k_Q(u)=a_Q u,
expected costs scale as a_C u/p0 and a_Q u/sqrt(p0). Weight per resource is
then independent of u in either case. This removes this particular
work-size amplification in the model. A fixed quantum advantage proportional
to 1/sqrt(p0) remains; it must be included in the resource-adversary threshold.
The linear example therefore does not prove classical/quantum fairness.

If quantum winner-oracle cost is instead proportional to u^alpha, with
alpha < 1, weight per resource grows as u^(1-alpha). The included
alpha=1/2 counterexample restores the conditional attack while the lottery
probability stays fixed. The test is deliberately sensitive to the missing
lower bound; it cannot certify that lower bound by assuming it.

### Necessary statement and cost gates

All of the following remain required before this can become a PoN proposal:

1. **Challenge binding before ticket evaluation.** Bind the parent, chain and
   work-profile identity, miner/reward destination, nonce, unit count and ordered
   task input commitments into one domain-separated input context. Every unit
   seed must depend on that whole input context and its index. Derive outputs
   from those inputs; then bind their complete, canonically ordered commitment
   into the lottery. The output commitment must not be included in its own
   generating seed. This is a future bundle statement, not a change to the
   existing W1 transcript under its current profile.
   A miner must not keep u-1 old units while varying one cheap last unit,
   choose a cheaper subset, reorder units, split a winner into extra credited
   blocks, reuse old work, or change claimed work after seeing a ticket.
2. **Complete relation and unique lottery semantics.** All required outputs
   must be checked or proven. Proof randomness, padding, equivalent encodings,
   aggregation choices and noncanonical representations must not create free
   tickets for the same work. An all-unit relation must bind before the
   lottery even if a succinct proof is generated only after winning. Binding
   an invented output root does not show work: proof soundness must also
   survive grinding such roots and selecting those that meet the target.
   The main W1/W2 relation package owns these cryptographic statements.
3. **Lower bounds for the actual winner predicate.** Proving correct matrix
   products does not prove minimum physical cost. Require a stated classical
   and quantum cost model, representative and adversarial tasks, cross-unit,
   cross-nonce and cross-parent amortization experiments, and an analysis of
   reversible oracle construction, rather than a FLOP-count assertion.
4. **Distribution and structure.** Challenge-derived inputs may be correlated;
   useful neural tasks may be sparse, low-rank, repeated or algorithmically
   compressible. Query direct-product results such as
   [Lee and Roland](https://arxiv.org/abs/1104.4468) do not directly prove
   linear wall-clock, gate-count or energy cost for these distributions.
   [Ben-David and Ebtehaj](https://arxiv.org/abs/2610.06835) also distinguish
   distributional query bounds from worst-case formulations. Neither is a
   neural compute cost certificate.
5. **Liveness and hardware feasibility.** Bound per-block work, witness memory,
   verification and propagation; measure block latency and stale rates.
   Parallel execution can reduce latency without reducing gate count.
   Work-size changes can favor hardware with more memory/parallelism.
   At minimum/maximum unit caps, fixed probability may no longer maintain the
   desired rate. Task availability and continuation work are separate gates.
6. **Whole-chain security.** A post-quantum signature path alone does not
   qualify the work oracle, Fiat-Shamir soundness, transcript commitments,
   networking, state synchronization or economic threshold. No gate here
   authorizes a whole-chain post-quantum claim.

## Reproduction, receipts and costs

Run from the repository root using Python 3 with its standard library. The
output path must be new. The reader also requires the same source-file hashes;
source changes invalidate its replay rather than silently accepting old data.

~~~bash
bash scripts/project-preflight.sh --audit
python3 formal/pon-nakamoto-v1/test_quantum_daa_model.py
python3 formal/pon-nakamoto-v1/experiments/quantum_daa_campaign.py --out /tmp/new-pon-quantum-daa
python3 formal/pon-nakamoto-v1/experiments/quantum_daa_campaign.py --verify /tmp/new-pon-quantum-daa
~~~

The producer writes one deterministic gzip JSONL stream per scenario, a report
with parameters/assumptions and a SHA-256 inventory. It records source commit,
whether the model inputs match that commit, actual Python CPU/wall time and
whole-process peak RSS. Actual Python measurements are separate from every
field named modeled_*. No QPU, reversible oracle or native W1 cost was
measured; corresponding resource estimates remain **null**, not zero.

The reader checks exact file inventory/digests, source hashes and bounded JSON
decompression. It separately recomputes integer work and median/future checks,
then deterministically replays the shared model. Tests include mutated
chainwork/time, altered source/qualification claims, duplicate JSON keys,
unlisted files and output-overwrite refusal. This is a local single-operator
readback; neither SHA-256 manifests nor a repeated model execution
independently attest the recorded CPU time or the physical premises.

The retained receipt reports actual costs on its exact source. All cases keep
native_packets_generated=0, quantum_circuit_executed=false,
w1_cost_measured=false, security_theorem=false,
production_consensus_activation=false and release_ready=false.
The release gate remains **NO_GO** until the missing cost/soundness/native
and independent validation work is completed.
