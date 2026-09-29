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
