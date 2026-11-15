# Closed-round successor and exact producer qualification

This package continues PR #204 and the existing module owners. It does not activate
production, alter revision3 defaults or introduce voting fork choice.

## Measured source

Implementation: `faf144086067f9b0a301a2b46760164d80fec04e`.
Tree: `cd3643aec9b12dab647f07b8c561e81eeae1493c`.
The measured checkout was committed and clean before and after qualification.
Original qualification bytes are unchanged. Later delivery checks are separate.

## Explicit successor

`--evaluation-policy closed-round-all-eligible-min-v1` selects a fresh revision4
network, parameter commitment and evaluation plan. Revision3 remains the default.
All frozen eligible genesis evaluators except the exact author must attest.
A missing evaluation expires without payout; it is not a timeout vote.

Nine `ClosedRoundTests` exercise signed Python/native execution, six 10/100/100
arrival orders at 1/2/4/8 workers, zero/missing evaluations, duplicate senders,
wrong contexts, budget publication/maturity/one-time claims, and ordinary native
CLI mining, disk reopen, heavier-fork removal and replay. Every complete order
returns score 10. Controlled positive scores are not new learned model gains.

Minimum aggregation does not prove evaluator honesty. Withholding can prevent
candidate adoption; equivocation, objective disputes, functional copies, split
attribution and public evaluator selection remain separate obligations.

## Faster producer, unchanged verifier

The producer caches the task product, transposes operands, batches canonical tile
bytes, and uses exact bounded reduction for q=2^32-5. The original full verifier
retains its separate remainder arithmetic. Boundary, deterministic and extreme
structured-input regressions compare the exact resulting certificates.

`prepared-cost.json` retains 64 samples: four structures, two targets (p=1/2 and
p=1/32 under the unqualified uniform-ticket assumption), eight samples per pair.
Setup is included. Ratios of within-case median baseline winning cost to prepared
total cost range from about 1.80 to 2.34 in this controlled CPU collection.
This is not a fastest-adversary lower bound, GPU benchmark or public TPS claim.

`work-cost/` is a separately executed clean-source half-range-target collection,
with build log, exact binary, raw samples and recomputed summaries. Ticket-passing
false transcripts still require expensive rejection. These ratios are not public
attack rates; current source identity cannot qualify the work primitive.

## Retained execution

The complete qualification has 48 successful command invocations, including 1,848
native tests and 15 documentation tests. Its 22 native-node integration cases are
included in the workspace total, not extra distinct tests. The research helper
ran separately; process-cut execution is not physical power-loss evidence.

Reference, explicit-native and session selections remain separate. Advancing-input
costs and the real work/receiver pipeline are unpaced logical-clock experiments.
No public throughput or tail percentile follows from their small sample sets.

Model-training and future-window experiments were NOT rerun for this package.
Older model outcomes, zero rewards and owned-host observations remain unchanged.
No new independent evaluator, consumer, public P2P or funded GPU service is claimed.

## Failure preservation and reproduction

`prequalification/` retains the initial assertion failure expecting CONTEXT where
the real native admission correctly returned NETWORK, plus the corrected rerun.
The rejection behavior was not weakened. The full clean-source suite ran after
the assertion correction; failed observations are not counted as passing tests.

Run the existing checks from the repository root:

```bash
python3 scripts/ci/prepare_evidence_sources.py
python3 scripts/ci/check_client_confirmation_evidence.py --native-node --evidence evidence/pon-closed-round-v1
python3 scripts/pon_work_cost_report.py --verify evidence/pon-closed-round-v1/work-cost
```

All prior evidence packages are unchanged and remain required under their
historical scopes. Every manifested publication input must be tracked by Git,
including raw logs. A local-only file is not a delivered observation.

The remaining six workstreams stay in the existing plan and module contracts.
Production activation, public-network acceptance and work qualification stay false.
