# W1 finite-fork resource research contract

Status: research-only. This contract extends the
[phase-separated miner experiment](W1_MINER_RESOURCE_RESEARCH_V1.md) with actual
concurrent sibling branches, paid adaptive selection and finite preprocessing
reuse. It preserves the original W1 relation, Node admission, task authority,
target, chainwork and qualification rules. The
[cost game](W1_COST_SECURITY_GAME.md) remains the security specification; this
experiment does not discharge its arbitrary-strategy quantifiers.

## 1. Actual native topology and paid initial bank

The [executable](../../../../trillionnium/crates/trnm-pon-node/examples/pon_w1_fork_resource_research.rs)
and [implementation](../../../../trillionnium/crates/trnm-pon-node/examples/support/w1_fork_resource.rs)
use one isolated original Node and a common base `g`. If a zero task is acquired,
`g` is the genuinely admitted and activated registration block; otherwise it is
genesis. For each branch `b`, the harness constructs and admits

\[
g \longrightarrow v_{b,1} \longrightarrow \cdots
  \longrightarrow v_{b,d},\qquad b=0,\ldots,w-1.
\]

`w=1..4`, `d=1..4`. Branch blocks use `development_public(3+b)` as their actual
miner. Different branches therefore have different block identities and native
branch states. Each branch's first block has the same base parent; its later
blocks reference that branch's own predecessor. All leaf parents remain stored
simultaneously. The forest seal reads every leaf's stored packet, state root,
height, next required target and original Node exact-packet observation,
including stored chainwork and nonmembership in the active chain.

Templates are acquired through original native construction and admission on
each leaf, for every acquired task. Research headers preserve these exact
parent-relative fields and change only the registered nonce. Template and
research miners use `development_public(3)`. Branches, templates and research
candidates are never activated. Stored sibling work is not added together as
canonical chain growth, inclusion, confirmation depth or matured reward.

This is a finite common-root branch tree with a paid initial bank. It is not an
arbitrary fork forest, evolving publication race or global fork-choice proof.
The maximum candidate height is six, before the first native retarget; this
experiment does not exercise dynamic DAA. The separate
[native DAA contract](W1_NATIVE_DAA_RESOURCE_V2.md) owns that question.

## 2. Task authorization, fees and preprocessing

The alternatives are the original continuity maintenance material and an
explicitly signed zero-product development task. Registration uses the original
lease, statement, transaction signatures and branch-relative eligibility checks.
The disclosed development signers establish neither public demand nor model
quality. `selective` acquires the tasks selected for mining; `shared` acquires
both. Maintenance-only selective acquisition needs no zero registration. A
zero task still requires maintenance material for its registration block.

All context construction, signing, original search attempts, native admissions,
activation of the common registration base, forest observations, templates,
preparations and associated output are charged to setup `P`. Native registration
fee receipts retain their integer token units separately from CPU. If setup
stops after admitting a registration candidate but before activation, its
candidate receipt is retained while the active economy remains at the old tip.
It is not reported as an active-chain debit or matured payment.

The producer arm is fixed within a job. The cache is keyed by the original task
ID binding the canonical matrix operands; reuse requires the same material and
arm. Parent identity does not change those operands, so identical material can
legally share preparation across sibling parents. Unrelated materials are not
merged under a cache label.

| Reuse policy | Actual preparation and release |
| --- | --- |
| `lifetime` | Prepare each mining material during `P`; retain it across the finite forest and all online windows; release within the miner phase. |
| `window` | Start without arithmetic preparation; clear the cache at each online window, then prepare a selected missing material on demand within `B`. |
| `cold` | Prepare and release the selected producer for every proof within `B`; no cross-attempt arithmetic cache. |

These names do not imply hardware-cache flushing or perpetual availability.
Supported arms include the original generic and structure-specific producers
and the separately implemented
[zero Strassen producer](../../../../trillionnium/crates/trnm-pon-node/examples/support/w1_zero_strassen.rs).
Unsupported material is an error, with no silent fallback. Fewer scalar products
do not imply lower measured CPU, energy or minimum attacker cost.

## 3. One online budget, paid adaptation and output availability

Execution has exactly four consecutive phases: setup, miner, receiver, audit.
`P` and `B` are separate process-CPU limits. Setup must finish within `P` before
the miner may start. Windows are groups of attempts inside **one total `B`**;
they never restart its clock or grant another budget. Actual setup CPU, miner
CPU and their sum are reported separately. A rate including observed setup is
not an experiment with an interchangeable single `P+B` budget.

The miner receives templates, materials, prepared producers and its journal,
with no Node, verifier or receiver callback. Its policies are:

- `round-robin`: cycle the eligible task-by-branch templates deterministically.
- `paid-noise-screen`: expand every declared candidate's noise, retain every
  score and select the minimum with fixed tie breaks. The producer regenerates
  its noise. All screening work is charged; no ticket is inspected beforehand.
- `adaptive-cost`: first complete one paid exploration on each eligible
  template, then choose the smallest historical mean service CPU. For template
  `i`, retain `(samples_i, service_cpu_ns_i)` and compare means using exact integer
  cross multiplication, breaking ties by template index. History persists
  across windows; it contains completed prior work, never future samples.

Service CPU begins after selection and includes necessary preparation,
production, proof construction/encoding and complete proof-record flush.
Selection, window bookkeeping, remaining logging and cleanup also consume the
same `B`, even where they fall outside that service statistic. Locally computed
tickets are retained, but this adaptive policy does not select by ticket wins.
No receiver or audit result feeds back into any policy.

Every completed research proof, including misses, is retained in full. Its
availability stamp follows serialization and `stdout.flush()` of the complete
original proof record. A distinct semantic identity contributes to within-`B`
output only if this stamp is at or before `B`. Atomic operations can overshoot;
all excess CPU and late proofs remain recorded. **A late winning proof has zero
within-`B` credit**, even when the receiver subsequently admits it. A proof
available by `B` and later accepted is not called native admission completed by
`B`. A reached safety cap is explicitly censored, including when the terminal
poll also observes exhaustion of `B`.

Receiver admission follows the fixed recorded order after the miner seals.
Target misses take the original target rejection path; audit subsequently
checks their full relation too. Original setup searches do not expose losing
proof bytes while running: their paid search counts are retained, and audit
reconstructs every nonce through the original winner. Reconstructed misses and
repeated winners add no opportunities or credit. Known setup winning identities
remain separate from fresh research identities.

## 4. Registered comparisons and exact evidence binding

The [registered plan](../../../../formal/pon-nakamoto-v1/experiments/w1_fork_resource_campaign_v1.json)
contains 42 jobs, to be frozen with code, readers and
[analysis](../../../../scripts/analyze_w1_fork_resource.py) before formal collection:

| Cohort | Jobs | Fixed design |
| --- | ---: | --- |
| Main | 24 | Three topologies `(1,1)`, `(4,1)`, `(4,2)`; two seeds; round-robin/adaptive; general paired/structure-specialized; lifetime reuse. |
| Window | 4 | `(4,2)`, round-robin, two seeds and both reference arms; window reuse. |
| Screening | 4 | `(4,1)`, two seeds and both reference arms; two challenges per eligible template. |
| Strassen | 4 | `(4,1)`, two seeds, round-robin/adaptive; `structure-strassen`. |
| Controls | 6 | Zero/tight `P`, zero/tight `B`, attempt cap and cold cap. |

Main seeds are `5101/5102`; normal budgets are `P=1 s`, `B=128 ms`, with a
4,096-attempt safety cap and eight attempts per window. The plan fixes arm order,
controls and all exceptions. Small-cap functional fixtures are parser and native
correctness evidence, not formal performance observations or grounds to retune
this matrix. Failures and negative results remain retained.

Paired ratios require the same relevant options, complete identical paid forest
and acquisition/template history, matching overlapping semantic proof/challenge
prefixes, and complete uncensored budget observations. Different topology or
acquisition history is not forced into a matched instance. Adaptive choices can
diverge because their paid timing histories differ. Failed pairing yields
`null` ratios with the mismatch reason; zero denominators also remain `null`.
Per-job yields and costs remain visible. Counts summed across jobs are not
claims of globally distinct tickets.

The [collector](../../../../scripts/run_w1_fork_resource_research.py) binds clean
committed source, the committed plan, locked fresh release build, actual binary,
commands and GNU-time/waited-child observations. Only after a measured command
ends does [lossless compaction](../../../../scripts/w1_lossless_raw.py) create a
single-member gzip, verify its complete bounded round trip against the original
length and SHA256, then remove the redundant uncompressed stdout. Compression
receipts separately bind stored bytes and hashes; original step receipts stay
unchanged. A failure preserves the original and any partial archive.

The [bundle reader](../../../../scripts/read_w1_fork_resource_research.py) requires
external commit/tree/plan/binary/manifest pins, verifies transitive reader source
and data, preserves typed receipt equality and reconciles native process CPU
from its recorded origin to its explicit endpoint with the signed whole-command
residual. Final serialization and any remaining drops after that endpoint remain
in this residual; the endpoint is not claimed to include process exit or every
remaining cleanup operation. The
[raw reader](../../../../scripts/w1_fork_resource_reader.py) bounds decompression,
rejects extra gzip members/trailing bytes, validates all phase and selection
records and independently replays every retained full proof. Analysis separately
requires an external readback hash. Stage costs are contained in phase totals;
they are not added twice. Whole-command RSS, wall time and CPU remain separate.

## 5. Claims that remain open

The contract supports finite counterexamples and reproducible observations. It
does not prove an optimal arbitrary strategy, arbitrary task families or fork
forests, unbounded preprocessing/reuse, independent challenge hardness, a global
`kappa`, hardware-independent cost, honest network growth or Hepta efficacy.
Full diagnostic proof logging is a harness choice, not an enforceable physical
miner cost floor. Scalar replay does not reexecute Node state, authenticate
clocks/operators, or attest independent hardware. Local flush is not network
publication or remote durability. No energy, WAN throughput, canonical TPS,
finality, production adoption or training-quality claim follows.

The [resource reduction](W1_RESOURCE_REDUCTION_V1.md),
[multi-instance cost analysis](W1_MULTI_INSTANCE_COST_V2.md) and
[chain envelope](W1_CHAIN_SECURITY_ENVELOPE_V1.md) retain their separate assumptions
and outstanding proof obligations.
