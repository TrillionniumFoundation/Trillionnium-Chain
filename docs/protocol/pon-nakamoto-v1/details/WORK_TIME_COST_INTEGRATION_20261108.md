# Seven-package work, time and Hepta qualification continuation

## Source and acceptance boundary

This continuation starts from joint DAA audit PR #794, exact source
`b16bae2824e6c8236ef2011fc93a74df3ac7f039`, on that integration lineage.
The Chain main observed on 2026-11-08 remains
`dd6e1c3cbeacbdc532b0679297835b3a0aac78f0`; Hepta main remains
`732e934ba496d90fbe042b8d41d479ef901643e5`. These are distinct sources.

The executable additions are a frozen work contract, a versioned temporal
reference, a finite legal-optimization campaign and an exact cost-envelope
checker. The native `trillionnium/` tree and dependency lockfiles are unchanged.
Research JSON contracts live beside the formal components and are not loaded
as new native parameters. The current overall decision is **HOLD_NO_GO**.

## Delivery and exact remaining gates

| User work package | Implemented increment | Remaining acceptance requirement |
| --- | --- | --- |
| Freeze work profile and cost contract | Full baseline source roster, canonical W1 arithmetic and bytes, attacker freedoms, success criteria and lifecycle accounting | Actual build/load identity for a selected deployment; all-algorithm cost bounds; a specified variable-work successor |
| Refactor time and DAA interfaces | Committed schedule and temporal namespace; branch-derived anchor; integer ASERT; nondecreasing timestamps; cache validation; externally bound snapshot replay | Native profile, admission and database upgrade; independent recovery anchor and trusted clock; original resource qualification |
| Full-verifier legal optimization catalog | 24 profile/material/implementation cohorts; 96 complete attempts and 24 real partial cancellations; exact low-rank preparation, caching, batches and bank; full scalar replay | Native same-resource comparison; more legal strategies; reductions covering all allowed algorithms and initial states |
| Fixed p0, variable u | Exact interval, monotone-credit and joint-batch feasibility with fixed success target/deadline/round horizon | Actual mandatory variable-u relation; verified classical and quantum cost envelopes; no missing bounds |
| Hybrid consensus and lifetime budget | Explicit joint proof interface and exact conditional failure-budget arithmetic | Resource simulation, honest progress/network/availability model, joint variable-work consensus proof and complete lifetime bound |
| Same-version end-to-end engineering | Same-source controls and explicit cross-candidate inventory | One source/build pair through real admission, independent WAN, recovery, complete metering and positive provider payment |
| Real Hepta iteration | Original-owner adoption and complete NoUpdate boundaries preserved | Real task/training/evaluation/retention/payment/cold fetch/protected install/actual load/next-task use in the same independently operated iteration |

Component details:
[frozen contract](WORK_COST_CONTRACT_V1.md),
[time and DAA](BRANCH_TIME_DAA_V1.md),
[legal optimization catalog](LEGAL_OPTIMIZATION_CATALOG_V1.md),
[cost envelope](COST_ENVELOPE_CONTRACT_V1.md).

## Conclusions that affect the implementation

The old temporal rule admits negative endpoint spans. The predecessor audit
computed full W1 packets under PNH1 and PGH2 and observed spans `-42`, `-199`,
`-356`; its shorter branch had more credited work and survived cold recovery.
See the immutable
[joint audit evidence](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/b16bae2824e6c8236ef2011fc93a74df3ac7f039/evidence/pon-joint-consensus-daa-20261108/README.md).
The new component rejects a timestamp below its parent after the scheduled
upgrade. It retains a monotone compressed-time counterexample: eliminating
negative spans is not a whole-chain time-manipulation theorem. Its temporal
records carry no W1 or native admission authority. Cold replay is O(n squared)
in the worst case and has no original public-resource qualification.

Minimum cost ranges over every algorithm that passes the same full relation.
Cached AB, exact low-rank preparation and batches can be legal. Setup and failed
rank probes still consume resources. Winner-only reporting loses failed,
withheld and already launched work; the new complete roster rejects omissions.
A bank retrieval is untrusted bytes and grants no verification authority.

Fixing a threshold probability does not make classical and quantum cost curves
have the same shape. Normalize each class by one fixed explicit class scale.
Given valid bounds `L_j(u) <= C_j(u) <= U_j(u)` and distortion `k`, robust common
credit requires and, pointwise, is guaranteed by
`max_j U_j(u)/k <= min_j k L_j(u)`. This is a statement about the declared
bounds; it does not establish them. Monotone credit, discrete units and paid
joint-batch strategies add explicit constraints. The checker constructs the
least admissible credit vector and returns exact violated inequalities.

At `k=1`, positive normalized costs must agree at each work level. Curves
proportional to `u` and `sqrt(u)` therefore cannot both be repaired by a single
score depending on `u` over multiple work levels. Finite-range tolerances and
class scales must be stated. This algebra is not an impossibility theorem for
every hybrid consensus design. Cost per expected accepted output is not the
fixed-probability/deadline cost used in the main envelope contract.

## Required joint proof interface

1. Exact accepted work relation, task family and all header/task/branch freedoms;
   a resource-simulation reduction covering permitted initial states, helpers,
   failed, aborted and unreleased attempts.
2. Predictable fresh adversarial-work bounds under the actual branch schedule,
   with constants, preprocessing loss, bank reuse, batching and quantum state
   preparation, reversible computation and uncomputation costs.
3. An honest progress law after generation, independent verification, admission
   and transport. A timely ACK is not timely independent confirmation.
4. Stated delay, availability, partition and eclipse conditions, timestamp
   observations, branch-local DAA and weighted fork choice. CP, CQ and CG are
   separate required conclusions.
5. Actual signature, commitment, shared hash, transcript, compiler, AIR and
   recursion interfaces with their reductions and total lifetime query costs.
6. A complete event roster and non-rewinding allowance ledger. Sum valid
   conditional bounds without assuming independence; missing bounds stay null.

The existing finite-state and risk-ledger components retain their declared
finite-model/accounting scope. They are not physical resource simulations or
authenticated real-world failure probabilities.

The [2023 quantum backbone paper](https://quantum-journal.org/papers/q-2023-03-09-944/)
has an explicit query model with classical honest parties; its fixed-difficulty
analysis cannot simply be assigned to a variable-work schedule. The
[Bailey--Sattath attack](https://arxiv.org/html/2403.08023v2) illustrates why
branch timing, difficulty and cumulative credit need one analysis.
[Komargodski--Weinstein v4](https://arxiv.org/html/2504.09971v4), Remark 5.2,
already proposes fixed success probability with variable task size. Section 5
separates multi-instance and streaming requirements from the simpler definition.
This continuation does not claim that design choice itself as new.

## Current engineering and product evidence

The separately inspected
[runtime PR #782](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/782)
has source `4e007a87ceecbec8d265f6a70cfd71d512a514b5`. Its observations include
original-deadline timeout, cancellation, branch removal and cold reopen. It
still records consumed resources as null, unknown GPU billing and no positive
provider payment for that operation. These are not native observations of this
continuation and cannot fill its missing complete-cost or deployment gates.

[Hepta PR #5341](https://github.com/TrillionniumFoundation/hepta-private-ci/pull/5341)
is pinned at `f1785ca15e41e4e49509a5b211a659e3cbdbf60e`; its associated
[Chain reader PR #787](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/787)
is pinned at `e02126dabef04f13792dec45d96ac5d6916d0651`. The exports preserve
original task/manifest/permission and NoUpdate boundaries, but the examples
remain controlled actor fixtures. They do not establish actual training,
independent evaluation/control, positive settlement, protected installation
or neural loading. Readback does not export current adoption permission.

The real join must bind one operation, parent model, candidate, evaluation plan,
Chain/Hepta source/build pair, resource budget and original deadline through
all stages. It retains Unknown, timeout, cancellation, revocation, restart,
reorganization and legal NoUpdate. Payment does not grant adoption authority.

## Execution and publication

The dedicated workflow executes named controls and a complete fresh catalog on
the exact head and actual prospective merge. Existing full tracked-source
checks run before and after, including canonical merge reconstruction. Failed
steps and partial catalog output remain uploaded. These are research checks,
not deployment or native acceptance.

The local checkout contains the exact source trees but omits some large
historical evidence blobs. Its source-contract check is reported with that
scope. A whole-repository check requiring missing history must retain its
failure. Fresh hosted results require their own run and artifact readback.
