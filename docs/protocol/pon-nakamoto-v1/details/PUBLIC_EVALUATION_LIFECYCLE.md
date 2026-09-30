# Frozen public-evaluation lifecycle: bounded executable policy

[`public_evaluation_lifecycle.py`](../../../../formal/pon-nakamoto-v1/public_evaluation_lifecycle.py)
and [`test_public_evaluation_lifecycle.py`](../../../../formal/pon-nakamoto-v1/test_public_evaluation_lifecycle.py)
implement an off-chain policy on existing evaluation/artifact and operations owners.
Native revision4 remains unchanged. No ledger reward, consensus vote, chainwork,
transaction or monetary penalty is added.

## Freeze before candidates

`freeze_round` seals network/parameters, round number, parent artifact, family,
task-content root, model-contract root, externally supplied admission root, evaluator
keys with admitted source lineages, eligible author keys/lineages, score bound and four
confirmed-height boundaries. The owner retains the digest independently; reconstruction
rejects a changed downloaded plan. At most 16 evaluators and 16 authors, at least two
evaluator lineages and one candidate bound the experiment.

Known same-lineage evaluator aliases and evaluator/author lineage overlaps reject.
Distinct admitted strings/keys still do not prove independent administration. Actual
membership governance, Sybil resistance, independent measurement and rotation remain
external obligations; neither honest-majority rhetoric nor minimum scores supplies them.

## Strict signed phases

Messages use fresh domain `public-evaluation-message-sign-v1`; closed fields bind
schema, phase, frozen round digest, signer, candidate and payload. Existing strict
Ed25519 checks real signatures, not truth of the score/evaluation-result digest.

| Phase | Confirmed-height interval | Exact requirement |
|---|---|---|
| Candidate | start <= height <= candidate_end | Admitted author signs artifact/source/components; candidate identity recomputes. |
| Commit | candidate_end < height <= commit_end | Each fixed evaluator signs the commitment of its complete future reveal. |
| Reveal | commit_end < height <= reveal_end | Signed score, task/model roots, result root and 32-byte salt match frozen context and prior commitment. |
| Close | height > reveal_end | Complete roster required. Missing candidate/reveal or pre-close signature conflict explicitly aborts; no timeout vote. |
| Appeal | after result closure | Admitted participant signs closed-result, objection and evidence roots; current result is unchanged. |

Heights come from the existing admitting confirmation owner, never wall timestamps or
evaluator flags. Observations cannot rewind. Existing operations/outboxes must persist
and reconcile retirement/reorg; the policy object is not a second lifecycle database.
Replay, wrong identity/context, altered salt/score, Boolean aliases, early/late phases
and missing/mismatched commitments reject.

Complete reveal order does not alter the reported minimum. A zero remains zero.
Missing evidence closes as `aborted`, null score and no review eligibility/adoption/
reward authority. Positive complete scores permit only further external owner review.
Objective result replay, prospective independence and existing adoption/reward gates
remain required. Signed minimum aggregation is not objective ML truth or governance.

## Equivocation and immutable appeals

Conflict evidence retains two distinct strictly verified signed commit/reveal payloads
from the same phase/evaluator/round/candidate, canonically ordered. Forgery, cross-context
pairs or identical payloads cannot create evidence. Current frozen roster never shrinks:
a pre-close conflict invokes the frozen whole-round abort, not a smaller success quorum.
`next_round_disqualified_keys` exposes only verified-conflict keys for a later admission
owner's newly frozen roster. `freeze_successor_round` requires an actually closed prior
round, a newer round number and a fresh owner admission root; it rejects the proven key
and aliases sharing its previously admitted lineage in the immediate successor roster.
The successor's integer start height must be at least the predecessor's last confirmed
height observed and strictly after its reveal boundary. It may start at the same
confirmed height after the prior close and new freeze, but cannot replay a past phase
by constructing a new policy object. Later prior-round observations advance this bound.
Hidden fresh identities/common control remain an unsolved governance problem. There
is no automatic stake debit or current-round deletion.
Post-close evidence cannot rewrite the closed result. Consistently signed false scores
remain a separate risk that signature-conflict proof does not solve.

Appeals are bounded signed records, not implicit rescoring, replaced reveals, reopened
deadlines or retroactive result changes. Decision authority, review standard, consent,
objective replay and remedy require an explicit new authorized owner operation/context.
The observer cannot invent those actors. At most 16 appeals and two conflict phases per
frozen evaluator bound evidence retention.

```bash
python3 formal/pon-nakamoto-v1/test_public_evaluation_lifecycle.py
```

Tests execute real strict signatures, six reveal permutations, missing/zero results,
deadline boundaries, source aliases, changed commitments, proven conflicts, next-round
exclusion, immutable closed results and signed appeal binding. These are controlled
policy regressions, including rejection of successor height rewind after actual signed
intake/closure and later confirmed observation, not independently operated prospective
public rounds.
