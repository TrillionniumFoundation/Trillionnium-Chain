# W1 adaptive selection and joint execution research

Status: research contract, 2026-10-25. This refines PN1 in the
[sole development plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
It changes no production work relation, task authority, target, acceptance flag,
service envelope, or Hepta repository. The
[cost security game](W1_COST_SECURITY_GAME.md) defines the security obligation;
this document specifies two bounded native experiments within it.

## 1. What this increment can establish

The previous [campaign](../../../../evidence/pon-work-cost-research-v1/README.md)
retained complete accounting but independently replayed outcome-selected full
certificates. Its batch queue was sequential; its selector compared fixed
relation-only task families. The present experiments add actual four-challenge
SIMD arithmetic, original-Node task and advancing-parent selection, complete
research-proof retention including misses, and per-command peak RSS observations.
They are a new experiment, not a relabeling of the earlier qualification.

| Obligation | Concrete completion record | Limit |
| --- | --- | --- |
| Joint algorithm correctness | Every emitted certificate is byte-equivalent to the unchanged W1 relation; scalar Python replays every retained full proof | Correctness does not establish minimum cost |
| Joint execution benefit | Same family, task, seed, sample, target, width, budget and retention scope; actual joint versus sequential cost | One x64 host is not hardware independence or a direct-sum theorem |
| Paid task/header selection | Original signed development eligibility, paid screening, discarded candidates, original admissions, actual parent advances | Two controlled tasks and one frozen signal are not arbitrary adaptive optimization |
| Cache/authority separation | Actual renewal and revocation controls, exact current-parent checks and fee receipts | Arithmetic reuse alone supplies no lease, model quality or mining authority |
| Evidence integrity | Frozen source/tree/plan, fresh release build, external executable/manifest pins, full raw records, independent readers and mutation controls | Software receipts are not hardware attestation |
| Conditional probability model | Exact finite counterexamples and paid-policy optima, with stated query/output/bank assumptions | No resource-to-opportunity reduction for all W1 adversaries |

Publication must say which rows actually completed. A plan or compiled executable
alone does not close its measurement obligation.

## 2. Four-challenge arithmetic

The research [joint producer](../../../../trillionnium/crates/trnm-pon-node/examples/support/w1_joint_challenge.rs)
packs one canonical field word from each of four independent challenges into
four 64-bit AVX2 lanes. Noise products and every transcript dot product run in
those lanes together. Noise expansion and SHA-256 transcript state remain
challenge-specific. The shared `A*B` preparation is actually executed and timed.
No algebraic cancellation between the four random challenges is asserted.

The field is the unchanged `q = 2^32 - 5`. For a dot product of at most 64 terms,
each exact 32-by-32 product is split into low and high limbs. Accumulation keeps
the two limbs separate: summing full near-q products in a single u64 would
overflow. The first fold `low + 5*high` is below `2^41`; a second fold is below
`2q`. One conditional subtraction gives the canonical remainder. Private buffers,
runtime AVX2 dispatch and full-lane unaligned accesses delimit the unsafe code.

Widths one through four are allowed. Inactive lanes still execute real vector
arithmetic and supply no output credit. Partial tails, duplicate/reordered
challenges, mixed near-boundary words and cancellation are functional controls.
Cancellation returns no partial proof, including at the before-delivery boundary.
Non-x64 or x64 without AVX2 returns an explicit unsupported error; no scalar
fallback is labeled joint execution. Portable scalar controls still apply.

The near-q matrices are `-(J+I)` and `-(J+P)` for a cyclic permutation P. They
are full rank over this field but structurally special, with small signed
representations. Their only purpose here is canonical-word boundary checking;
full rank is not a hardness certificate.

The [joint CLI](../../../../trillionnium/crates/trnm-pon-node/examples/pon_w1_joint_research.rs)
compares `avx2-joint` and `prepared-sequential`. Producer, preparation mode and
batch width are excluded from challenge construction. Each complete diagnostic
header binds the task, target, seed/sample context and nonce. Diagnostic headers
have no claimed original-Node eligibility. A literal zero target rejects every
ticket; full relation replay uses the maximal target separately.

## 3. Original Node parent and selection experiment

The [parent CLI](../../../../trillionnium/crates/trnm-pon-node/examples/pon_w1_parent_reuse_research.rs)
uses the existing isolated `native-public-evaluation-dev-v1` and continuity
development profiles, original Node, ordinary packet admission and real native
SQLite state. The two material alternatives are immutable continuity maintenance
and one locally signed zero task. Development signers supply actual development
authority only; this does not claim that arbitrary zero tasks are publicly
eligible or that zero work improves a model.

All three strategies pay for the common input environment and acquire both
task alternatives. Consequently `maintenance-only` is the fixed choice inside
this shared-input comparison, not the cheapest possible whole policy that would
never register the other task. Actual signed fees and any escrow are recorded
separately from process CPU; token amounts are not converted into physical work.

At each active parent, the fixed strategies choose one task. `paid-task-screen`
constructs `2*screen_width` legal task/header candidates, expands all four noise
arrays, and chooses the smallest total popcount, then task index, then candidate
ordinal. This signal is frozen before performance collection. It is an exploratory
cost-related signal, not a proven predictor of low arithmetic cost. The selector
does not inspect ticket outcomes. Every discarded screen is charged. Production
expands noise again; no unrecorded preprocessing cache is lent to it.

Nonce is derived from the declared seed, round, attempt and candidate number;
the complete native header determines the challenge. Hot and cold runs under
one strategy share logical candidates. Different strategies can select different
first winning children and therefore follow different parent histories. Their
later proofs must not be presented as the same-challenge paired comparison.

The experiment pays for original bounded searches used for registration,
templates, fallback advancement, renewal and revocation. Every original winning
packet is retained. The original Node does not export bytes of its internal
misses; their number follows from the observed first winning nonce, and a separate
post-strategy reconstruction reproduces them. These reconstructions are checked
against the original winner and the independent relation, but are not called
original retention, given fresh credit, or fed back into strategy selection.

Actual current-parent eligibility is always obtained from the original owner.
Controls attempt wrong material, cached zero authority after revocation, duplicate
admission and continued maintenance. Signed renewal has a new lease revision.
Parent records retain active height and installed required work. Sibling tickets
are distinct candidates when their identities differ, never additive canonical
chain growth merely because they were all admitted.

## 4. Timing boundaries and budget credit

| Experiment | Charged primary interval | Budget credit | Exclusions |
| --- | --- | --- | --- |
| Joint | Process CPU from main clock, less measured mandatory full native observers; includes material, preparation, headers, generation, proof encoding, ordinary logging and cache/material teardown | Unique complete proof delivered by B, with subsequent independent confirmation | Startup before main clock; native observer intervals; final end-row construction and emission |
| Native parent | Whole strategy process CPU, including context, signatures, original searches, all full observers, logs, task/parent transitions and teardown | Unique original admission completed by B | Startup before clock; explicit post-strategy reconstruction; final report tail |
| GNU time | Whole measured executable through exit, user/system CPU, wall seconds and per-command maximum RSS | Observer only; no separate ticket numerator | Its printed precision is coarser than native clocks |

These are different accounting scopes. They must not share one pooled rate
denominator. Native nanosecond clocks and rounded GNU time values are not
substitutable. Stage charges partition some of each interval; unattributed
residual cost stays visible and nonnegative. Failed and over-budget work receives
no resource refund. Complete proof by B and complete admission by B remain
different events. No energy or network transfer is measured.

Joint `cold` prepares once per batch and destroys that cache within the charged
generation interval. `hot` prepares once per invocation; its final destructor
is included. Neither flushes processor caches. Native parent cold prepares each
selected proof, while hot task preparation may serve several paid parent states.

Native budget fences precede newly startable stages. A bounded original search
and its mandatory admission/readback, or a research proof and its full validation
tail, may finish after B. Their entire costs remain and late admissions have no
within-B credit. The native record identifies actual budget polls and atomic
tails. A zero-budget control does not grant free setup or an automatic winner.

## 5. Registration, collection and independent replay

The [registered plan](../../../../formal/pon-nakamoto-v1/experiments/w1_adaptive_joint_campaign_v1.json)
contains 42 joint jobs and 16 native-parent jobs. Main joint comparisons cover
three task families, both preparation modes, two short-budget seeds and one
long-budget seed. Short-job producer order is balanced. Controls cover zero
target, duplicate nonce, partial and narrow batches, near-q words and zero budget.
Native jobs compare three strategies and hot/cold caches under two seeds,
plus narrow/wide screening and zero/tight budgets. Caps remain censoring, not
proof that the full resource budget's maximum yield was found.

The [runner](../../../../scripts/run_w1_next_research.py) requires clean exact
source/tree and the original raw source guard, rejects hidden build overrides,
uses a nonexistent external target directory, and builds both Rust 1.95 release
executables with the locked offline dependency graph. It binds the actual GNU
time executable, pins one available CPU, runs jobs sequentially and preserves
raw stdout, stderr, step receipts, usage snapshots and failures. A partial or
unsupported command cannot become a successful zero-yield observation.

The [bundle reader](../../../../scripts/read_w1_next_research.py) requires trusted
external source/tree, plan, both executable and raw-manifest pins. Immutable Git
objects bind the plan, runner and reader components; Cargo artifacts bind the
fresh executable paths. Raw streams, command order, child resources and per-job
observer receipts must reconcile exactly. Every tracked file under `scripts`,
`formal` and `config`, including transitive helpers and runtime input data, is
also compared byte-for-byte with the measured Git tree before and after replay.
New helper files or drift in those scopes are rejected; later publication-only
documentation/evidence can coexist with the unchanged replay source. Relocating retained raw files changes
no recorded original command or source identity.

The [joint reader](../../../../scripts/w1_joint_challenge_reader.py) and
[parent reader](../../../../scripts/w1_parent_reuse_reader.py) independently replay
every retained full proof through the scalar Python oracle, including misses,
duplicates and explicitly labeled reconstructions. They separately check literal
target success, semantic identities, budget fences, charge sums and accounting
counts. Paid screening is re-expanded independently. Native admission remains a
source-bound original-Node observation, not Python execution attestation.

Posthoc readers may run in parallel; this changes no registered native strategy,
measurement interval or selected candidate. Final summaries retain all jobs,
zero yields, incomplete lifecycle controls and censoring. No observed finite
speed ratio is promoted to a universal kappa bound.

The frozen [analysis script](../../../../formal/pon-nakamoto-v1/experiments/analyze_w1_adaptive_joint.py)
constructs all 21 joint pairs from exact registered options and checks every
overlapping challenge/semantic identity. Its six main parent cache pairs require
matching complete original-acquisition and research identity sequences before
reporting a paired rate. It preserves rational numerator/denominator operands,
all 58 individual jobs, zero-yield cases, cap censoring and incomplete controls.
Different native policies may have different paid histories and remain separate
observations. Analysis input is an already verified readback, not a substitute
for bundle authentication and full relation replay.

Cross-observer CPU checks retain `whole waited command - native elapsed` for
joint jobs, and `whole waited command - strategy - explicit posthoc` for parent
jobs. Negative residuals are never clipped. The preregistered allowance is 2 us
for differencing microsecond waited-child counters; two GNU time printed CPU
components have a conservative combined 20-ms allowance. A larger contradiction
is an evidence failure, not a corrected zero cost. These consistency checks can
detect scope/unit mistakes but do not authenticate a physical clock.

## 6. Closure rules

Passing exact arithmetic and source/evidence controls closes those implementation
obligations for this source. A complete registered run closes this host's finite
measurement obligation. It cannot close an unlimited-adversary lower bound,
arbitrary multi-parent optimization, independent GPU/ARM/ASIC observations,
measured joules, private evaluation governance or actual Hepta training.

The [conditional models](../../../../formal/pon-nakamoto-v1/experiments/w1_adaptive_cost_models.py)
make query completion, paid preprocessing, reuse schedules and predictable
selection precise. Their tests are exact small models, not an oracle for native
cost. Protocol adoption still needs the resource-to-opportunity assumption and
an applicability argument for W1's actual trace digest. Output-size lower bounds
for an explicitly materialized transcript cannot be silently transferred to the
cost of producing only its hash.

## 7. Equal-budget native admission continuation

The [next registered campaign](../../../../formal/pon-nakamoto-v1/experiments/w1_native_budget_campaign_v1.json)
addresses a specific limitation of the completed 58-job cohort: all complete
native strategies stopped at 32 research attempts before spending their 1-second
CPU budget. Those consumed-CPU ratios do not measure different fixed-budget
outputs and remain unchanged historical observations.

The research-only `budget-final-parent-v2` namespace retains the original Node,
signed registration, paid dual-task acquisition, exact W1 bytes and renewal.
Three prefix rounds each attempt two complete research proofs and advance the
actual active parent. The fourth parent is fixed while the same strategy continues
until its full process-CPU budget expires. Its 4,096-attempt safety cap is explicit.
The final research parent remains active; admitted research candidates above it
are not activated as a new tip, including when a small registered control hits
its safety cap. This is a native sibling-admission experiment, not measured serial
chain growth, network TPS or a continuously changing difficulty campaign.

All signing, preparation, original template searches, screens, discarded
candidates, native full observers, raw retention, admission and context teardown
remain charged from the same process origin. An atomic tail may overshoot B;
its actual cost remains in the record and an admission completed after B earns
no within-B credit. Original hidden search misses are reconstructed only after
the strategy and contribute no new work credit. Arithmetic correctness, local
native eligibility and independent hardware execution keep separate verdicts.

The registered grid contains 24 main jobs (two seeds, three policies, both caches,
and two producer choices), six 500-ms hot jobs under a third seed, and eight
controls. Main jobs use 1 second. The producer comparison is general integer
pairing versus a fixed structure-specific mapping: `maintenance-limb` for the
maintenance task and `blocked-zero` for the signed development zero task. The map
is known before measurement and is not a claim of globally fastest algorithms.
All policies still pay for both tasks; avoiding zero registration entirely is an
untested different policy. Producer/cache execution order alternates in advance.

Each of the 30 main/short jobs closes its finite measurement obligation only if
it reaches the final parent, stops for the actual CPU budget and does not reach
the safety cap. Early stops, failures and caps remain visible; no parameter is
retuned after results. Budget jobs deliberately leave final revocation controls
incomplete. Two retained v1 lifecycle jobs separately exercise all four original
rejection controls. Other controls cover a small final cap, zero/tight budgets,
and exact joint/sequential proof generation after the architecture-scoping fix.

The [registered analysis](../../../../formal/pon-nakamoto-v1/experiments/analyze_w1_native_budget.py)
reports opportunities completed by B and distinct native admissions completed by
B separately, as well as actual charged CPU, overshoot and auxiliary work.
Its 15 producer pairs and 12 main cache pairs check identical paid acquisition
histories and matching research prefixes. Unequal lengths are the measured yield
outcome; divergent histories, unreached final parents or caps suppress a paired
yield claim. Ratios with a zero baseline remain undefined. Successful collection
alone cannot close the resource-to-opportunity hardness assumption or the external
hardware, genuine Hepta efficacy and production qualification blockers.
