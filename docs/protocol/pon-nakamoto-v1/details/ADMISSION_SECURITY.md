# A2 — explicit attack budget, not an invented work-hardness proof

The exact matrix transcript relation is unchanged. It has measured cheap-forgery versus
full-recompute rejection asymmetry. No queue implementation resolves its cryptographic
cost hardness, input-instance fairness or permissionless Sybil problem.

## Implemented local capacity boundary

`trnm-transport::proof_admission` allocates three public permits and one recovery permit,
two permits per peer, with duplicate in-flight identities. The host receives a distinct
local RecoveryIngress capability; remote message fields cannot select it. Counts and
identity are updated under one mutex. Drop reclaims capacity on normal failure or unwind.
Stop changes generation; resumed service does not erase old live jobs or make their
permits current. Saturation returns Busy, not an invalid-block verdict.

This is an actual native component but not yet the production P2P host. A2000-identity
flood regression checks the local count and reserved capacity; it is not a measured
network attack nor proof an arbitrary public honest miner can always get a slot.

## Adversarial qualification matrix

| Attacker freedom | Required experiment | Current conclusion |
|---|---|---|
| invent trace that passes ticket | generation versus invalid verification cost at equal target | known amplification, unresolved |
| choose zero/low-rank/sparse task | compare fastest valid alternative transcript implementation | correctness can be checked; cost lower bound unqualified |
| reuse task or preprocessing | measure amortized cost over many challenges | no independence/hardness theorem inherited |
| change payout/body/parent | mutation and canonical transcript tests | binds context; not alone a work-cost proof |
| change proof representation | canonical output/block identity and malformed proof tests | no alternative serialization nonce accepted |
| vary peer identities | global cap and reserved recovery test | local resources bounded, public fairness unresolved |
| withhold bodies or old proof data | authenticated retrieval/cancel/timeout with bounded obligations | native network integration still missing |

A new succinct proof or admission mechanism requires its own exact statement, bytes,
security assumptions, verifier cost and invalid-input bounds. It cannot be substituted
silently, and normal hash tickets are not renamed useful work. Never alter chain validity
because one peer or receiver is overloaded. Busy and temporarily unavailable are local
observations; an actual cryptographically invalid proof is a separate fact.

## Executed work versus capacity, and cross-lane duplicates

Active duplicate keys include the local admission lane. A public sender holding a digest
cannot block the independently held recovery capability for that same digest. It still
cannot request recovery priority through a remote field. Each lane owns its own permit;
dropping a public permit cannot clear a recovery permit's identity or accounting.

`pon_admission_load` runs actual full verification during2048 local public attempts and
16 recovery verifications. It records before-work Busy decisions and expensive rejection
counts. This proves only the measured capacity/isolation behavior, not public honest-peer
fairness or a Sybil cost theorem. `pon_adversarial_cost` uses the actual half-range devnet
target with dense, zero, rank-one and sparse matrices, separating honest winning cost,
forgery hash trials, verification and rejection. Honest structured runs are not the
fastest adversarial implementation; measured cost does not supply a hardness theorem.

## Same-target resource model and public service obligations

A useful admission budget names the target, profile, task class, attacker preprocessing,
forged-ticket trials, honest work attempts, encoded bytes, verifier CPU time, queue delay,
cache state and actual hardware. Construction/rejection ratios use the same target and
units; ratios of process wall times must not be presented as cryptographic operation
lower bounds. Separately report cold and warm caches, invalid field/length/task checks,
failed ticket checks, ticket-passing false transcripts and duplicate valid retransmits.

For m public verifier slots, a measured isolated service approximation is
m / C_invalid requests per second when C_invalid is in seconds per request, not a safety theorem. Under an explicit
arrival model lambda_invalid*C_invalid + lambda_valid*C_valid must remain below the
usable public CPU budget for a stable queue; burst tails and honest waiting time still
need measurement. A recovery reservation protects only the locally authorized lane. It
does not prove that a new honest public miner can obtain service during identity churn.

The public qualification campaign must run the actual M04/M02 ordinary ingress path,
not acquire local permits by directly calling a library. Bind miner and attacker source,
identity churn policy, bounded queues, CPU scheduling, network loss/delay and independent
operator roles. Measure admitted, Busy, rejected-before-work, rejected-after-work, valid
accepted and honest wait-tail counters. Missing ordinary ingress is an integration gap,
not a passing fairness result. State whether the attack is controller-delivery withholding,
real network loss or genuine hostile peers; these observations are not interchangeable.

The controlled cost collector in `scripts/pon_work_cost_report.py` can re-run the existing
native cost binary and preserve raw output plus exact-source identities. It rejects
mixed targets, duplicate samples, Boolean counters and invented security flags, but
creates no public-admission qualification. It does not send traffic to any peer or host.

[The new controlled cost record](../../../../evidence/pon-contract-authority-v1/README.md)
binds actual execution, raw samples, target, binary and original source. Current-source
verification and the retained failed environment setup are separate from public admission
or work-hardness acceptance, which remain false.

## Early rejection before branch-state reconstruction

`work_oracle.precheck` is now reused by the existing Ledger admission path after bounded
header/transaction context checks and before potentially expensive `state_at(parent)`.
It checks certificate width/magic, field ranges, TaskId and ticket threshold. Malformed
fields, substituted task and bad ticket cannot force state replay or full transcript work.

A passing precheck is explicitly NOT `VerifiedWork`. A forged digest passing the ticket
still reaches the unchanged complete transcript verifier and rejects there. Parent-state
work eligibility, signatures, deterministic execution and roots remain mandatory before
persistence. This saves malformed-input replay cost; it does not solve a cheaply fabricated
passing ticket, structured-input shortcuts, fastest-adversary cost or public Sybil fairness.

## Current same-target measurements after native-session integration

[The new retained collection](../../../../evidence/pon-native-session-v1/work-cost/README.md)
binds the current native source inventory and exact binary to dense, zero, rank-one
and sparse tasks at one target. The old contract-authority collection is verified only
as historical observations. The current CI path still requires a matching current-cost
collection; it does not silence a stale-source failure by changing the old result.
These CPU timings do not bound the fastest adversary or guarantee honest public service.
