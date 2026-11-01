# Whole-chain post-quantum acceptance target — 2026-11-01

**Target specification, not a current security attestation. All six existing gates remain UNQUALIFIED.**

The target is a property of the complete deployed configuration: every path that
can grant authority or change state must satisfy a declared quantum threat model,
while required legitimate operations remain available under the original budgets.
An algorithm implementation, a refused legacy request or a passing component test
does not establish that property. This document refines the existing
[development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and [six-gate claim boundary](WHOLE_CHAIN_PQ_CLAIM_GUARD_20261031.md);
it creates no new workflow, activation rule, security parameter or release gate.

## 1. Separate the security properties

| Property | Required question | Insufficient substitute |
| --- | --- | --- |
| Authorization and identity | Can only a current authorized identity cause the intended effect, under the selected PQ profile? | Finding ML-DSA in the repository or authenticating only one message. |
| Confidentiality | Can protected data remain secret against the declared collection and later quantum-decryption threat? | A signature, or key establishment without authenticated endpoints. |
| Work competition and chain selection | Do the actual work relation, difficulty adjustment and fork choice meet the declared adversarial cost and confirmation goals? | Replacing account signatures, using a STARK, or taking a square root of classical work. |

Proof-system soundness is a separate obligation within the existing proof gate.
Public ledger plaintext does not by itself invalidate authorization security;
private Cell and task data need an explicit confidentiality scope and construction.
The [application contract](PQ_APPLICATION_AUTHORIZATION_V6.md) keeps message
authentication, key establishment and endpoint identity distinct.

## 2. Threat model and trust assumptions to freeze

- State the adversary's quantum algorithms, classical resources, time horizon and
  security metric; distinguish forgery, preimage, collision, proof soundness,
  confidentiality and confirmation risk. Algorithm categories are not a system score.
- Include active peers that replay, reorder, delay, truncate and forge traffic;
  submit invalid or worst-cost inputs; withhold work; manipulate permitted
  timestamps; and combine those actions with partitions and restarts.
- Include restoration of a complete internally consistent old application directory,
  including database, WAL and journals, and rollback of separately stored configuration.
  Also consider copied instance credentials, concurrent writers and competing CAS calls.
- Specify key compromise, rotation and revocation timing, historical-signature use,
  clock assumptions and the boundary between local operator authority and remote requests.
- Identify which roots, configuration versions and external durable observations
  survive application rollback, who controls them and how their freshness is established.
  A witness filename or another process on the same rollback domain proves no independence.
- State excluded capabilities and residual risks explicitly. Protection cannot assume
  an independent anchor while allowing the attacker to reset that anchor unnoticed.
  Key protection and operational independence require evidence of their own.

## 3. Freeze the complete configuration before evaluating it

| Layer | Required immutable identification |
| --- | --- |
| Software | Chain and Hepta source commit/tree, modified-source inventory, executable digests, toolchain, Cargo graph/lockfile, build features and provider identities. |
| Cryptography | Exact algorithms, parameter sets, provider versions, canonical key/signature encoding, message API, domains, hash uses and their claimed security metrics. |
| Authority | Genesis/source checkpoint, profile and schema selection, role-specific trust roots, key generations, policy identity, revocation and upgrade/recovery authorities. |
| Protocol and work | Wire versions, context bindings, complete W1 relation, challenge/material families, cumulative-work arithmetic, timestamp and DAA rules. |
| Proofs | Actual relation and verifier, guest/compiler identities, commitments, Fiat–Shamir model, FRI settings, recursion/composition and complete security assumptions. |
| Persistence | Protected tables and other effect owners, checkpoint coverage, external binding, CAS/recovery semantics, configuration monotonicity and service durability. |
| Network and privacy | Endpoint names/roles/pins, handshake and resumption rules, encryption scope, private-data handling, retry/reconnect and downgrade policy. |
| Resources and evidence | Original hardware contract, fixtures, traffic, quotas, CPU owners, deadlines, workers, selectors, success conditions and independent acceptance requirements. |

Do not infer a frozen value from an algorithm name or silently choose a newer profile.
A new build or relevant configuration change needs evidence for that exact identity;
an earlier receipt must retain its original identity and cannot certify a pending rebuild.

## 4. Delivery status and the interrupted native candidate

This documentation branch is based on Chain commit
`0e9eac5d2a8cdb0a6f0cc7920f84e290e0d5d0d0`. It adds this acceptance target
and an [evidence recovery archive](../../evidence/pon-pq-native-witness-20261101/README.md).
It changes no runtime source, Cargo dependency, signed schema, resource budget,
source-corpus pin or activation setting. **It does not deliver a native rollback
witness or the interrupted PNQ2 admission changes.**

The earlier local candidate combined this baseline with research commit
`605af09da34ca72665f822200a2f3e75573e6052` and unpublished native changes.
An executor storage failure and subsequent environment loss occurred before those
changes were published. Exact logs and several historical receipts were recovered;
the full modified implementation, its executable and the complete final build-input
manifest were not. The archive retains 79 distinct selected native test successes
from an earlier candidate, followed by a last sealed rebuild that exited 101.
Those historical results do not qualify the runtime of this documentation branch,
and the two original large-state/History gates were not executed in this task.

The native witness experiment concerned only `pq_network_resource_v2`,
`pq_network_peer_v2` and `pq_network_request_v2`. Historical test and review text
about that experiment is neither a recoverable source delivery nor proof of whole-DB
rollback protection, an independent durable witness service, cold service reload or WAN.

Hepta changes were published separately before the environment loss:
[PR #4552](https://github.com/TrillionniumFoundation/hepta-private-ci/pull/4552),
commit `7ff91a4368bc110c35da789b16916e046f79b42c`. They add policy revision/digest
binding, close the reproduced policy rollback path and restore helper dispatch
before daemon-only environment loading. Their
[exact-source evidence](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/7ff91a4368bc110c35da789b16916e046f79b42c/qualification/pq-service-recovery-20261101/README.md)
records component phases, real PQ-authorized product requests against a local HTTP
model fixture, failures and unexecuted cases. That separate draft does not establish
ordinary Cell/installation/CURRENT/FinalUse/settlement composition or whole-chain PQ.
CI status must be read from the live PR; local evidence does not imply all CI passed.

The baseline [V6 application contract](PQ_APPLICATION_AUTHORIZATION_V6.md) and
[PNQ2 contract](PQ_NATIVE_NETWORK_OWNER_V2.md) continue to describe explicitly
selected development profiles. PNQ2 retains finite limits and signed loopback
plaintext. Provider availability does not select every authority owner.

## 5. Every authority-bearing effect needs a complete acceptance trace

Inventory real entrypoints and owners for account registration, transfer, rotation,
migration, task/lease start and renewal, quota, evaluation, publication and settlement.
Include public Submit and History, continuous operation, Cell discovery/publication,
Hepta CURRENT, installation, FinalUse, RunStart/ObjectiveStart and automation,
plus upgrade, administrative and recovery paths. Use the actual composed product
configuration; Chain evidence cannot substitute for a different Hepta executable.
The [Hepta handoff boundary](HEPTA_PQ_HANDOFF_V2_20261031.md) remains explicit.

For each effect, retain all of the following in one configuration:

1. **Normal success:** a legitimate PQ request enters the ordinary owner and completes
   its actual nonempty business effect, with independent readback of the resulting
   state, artifact, installation, balance or settlement as appropriate.
2. **Unauthorized refusal:** classical authorization in the PQ-only domain, cross-profile
   downgrade, wrong context, stale generation, revoked identity, replay and invalid
   recovery state cannot create that effect. Supported classical profiles remain separate.
3. **Recovery after refusal:** a subsequent authorized operation completes, retaining
   spent budget, sequence floors and revocations; a cached replay does not duplicate
   the effect. Refusing all requests is a failure of this acceptance trace.
4. **Failure boundaries:** retain observations before and after the real effect, external
   CAS, acknowledgement and local commit; exercise process loss and complete snapshot
   restoration. Success responses must agree with actual surviving effects.

Refusing RunStart V1 does not implement a successful PQ RunStart replacement.
Installation, CURRENT selection, FinalUse, publication, payment and recovery must
compose under the same trust and replay rules, including across process boundaries.

## 6. Migration, complete rollback and the external anchor

A fresh genesis is not migration of old ownership or liabilities. Require a fixed
source checkpoint, a trustworthy PQ ownership transition, preserved nonce floors,
source-side liabilities and prevention of claims on both source and destination.
Classical signatures alone cannot establish new ownership after the assumed quantum break.

Test old snapshots of the entire DB and all related effect stores, not only a changed
row. A locally consistent hash chain cannot establish that a complete old snapshot is
current. Independently protect configuration/policy generation as well as database state.
An equal PNQ2 checkpoint proves nothing about excluded account State, History,
CURRENT, Cell installation, FinalUse or other journals.

Specify independent anchor initialization, durable commit-before-ACK, cold restart and power loss,
lost replies, local commit failure, partitions, conflicting clients and disaster recovery.
Neither deleting the Node DB nor restoring an old policy may reset the external head.
Any proposed one-transition repair must not become arbitrary rollback recovery;
refused older states require an authorized recovery procedure that preserves effects.
A fresh Current response is not a distributed ownership lease. Deployment with cloned
credentials needs its own specified concurrency and ownership guarantees.
The [rollback research reference at its exact source](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/605af09da34ca72665f822200a2f3e75573e6052/docs/security/PQ_EXTERNAL_ROLLBACK_WITNESS_REFERENCE_20261031.md)
and the archived native-client experiment are distinct from an independently
deployed durable service.

## 7. Production network and private Cell acceptance

Verify full endpoint identity, role and name binding, trust-root rotation/revocation,
fresh reconnect/resumption and downgrade refusal on the selected production transport.
If ML-KEM establishes keys, separately verify PQ peer authentication; if ML-DSA signs
messages, separately verify confidentiality for the declared private data.
Include stored private artifacts, retention and recovery in that confidentiality scope.

Demonstrate sustained service with honest completion under hostile intake, bounded
allocation and amplification, persistent charging, original deadlines and recovery.
Exercise actual Cell publication, discovery, acquisition, installation and FinalUse.
Finite PNQ2 counters, a loopback listener and a Unix-socket witness exchange cannot
stand in for public service, private Cell protection or independent WAN operation.

## 8. Complete W1, proof soundness and quantum competition

Evaluate the actual complete native W1 verification path. Any compressed proof path
needs its own exact quantum-soundness argument and worst-invalid-input cost evidence;
neither the word STARK nor a different research verifier assigns a system security level.

Account for the cheapest legal classical and quantum producer, reusable setup,
material loading, challenge amortization, complete reversible oracle, work registers,
uncomputation and final release of a valid block. Report gates, depth, qubits,
error-correction and elapsed-time assumptions for the declared hardware model.
A constructed attack circuit supplies an upper bound for that strategy, not a
general lower bound on all attacks.

Use equal adversarial resource/time budgets with the real timestamp, DAA and fork
rules, withholding, propagation, reorganization and confirmation requirements.
The [quantum sensitivity model](PQ_QUANTUM_DAA_SENSITIVITY_20261031.md) is conditional
research; arithmetic scenarios are neither an executable W1 attack nor a hardness proof.

## 9. Original budgets, independent evidence and the six existing gates

Retain the [original acceptance selectors and budgets](../../evidence/pon-pq-native-witness-20261101/README.md#original-gates-not-executed),
including large-state honest completion, History, retained failures and required host resources.
Do not shrink fixtures, extend deadlines, refill spent counters or substitute a cheaper
supplement. Charge complete signature, state-readback, witness and Finish-tail cost;
record latency distributions, CPU/RSS, wire amplification and recovery under the original load.
Execute the development plan's unmodified independent WAN/operator and complete Hepta
requirements. Independent cryptographic, economic and operational review must assess
the exact deployed composition, reproduce failures and state unresolved assumptions.

| Existing gate | Status in this document |
| --- | --- |
| Authorization | UNQUALIFIED |
| Proof PQ-128 | UNQUALIFIED |
| Quantum mining and fork choice | UNQUALIFIED |
| Migration and rollback | UNQUALIFIED |
| Capacity and invalid input | UNQUALIFIED |
| Independent end-to-end | UNQUALIFIED |

Production networking spans authorization, capacity and independent end-to-end;
it cannot be closed by a local replay-witness experiment. Grep/source inventories,
authored-but-unrun tests, rejection-only paths, model tests, internal cross-review
and repeated runs of the same controls cannot replace end-to-end acceptance.
Only the existing reviewed acceptance process can close these obligations; this
document keeps HOLD / NO-GO and all production activation boundaries intact.
