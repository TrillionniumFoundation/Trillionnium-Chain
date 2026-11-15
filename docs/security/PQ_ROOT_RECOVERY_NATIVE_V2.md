# Real root signatures and durable research journal V2

Status: **HOLD / NO-GO**. This continuation of [#806](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/806)
connects real native OpenSSL cryptography to a bounded SQLite research owner.
It is Python component code, not the Rust M15 deployed release owner. It changes
no deployed root, key, service, account or production activation flag.

The prior [V1 policy model](PQ_ROOT_RECOVERY_POLICY_V1.md) remains a pure
approval-claim model. Its unchanged tests are not relabeled as native evidence.
The new [signature bridge](../../formal/pon-nakamoto-v1/pq_root_recovery_signatures_v2.py),
[journal](../../formal/pon-nakamoto-v1/pq_root_recovery_journal_v2.py), and
[provider readback verifier](../../formal/pon-nakamoto-v1/pq_root_effect_readback_v2.py)
form the component path described here. [Lifetime and independence obligations](PQ_ROOT_LIFETIME_GAPS_V2.md)
remain separate from those implementations.

## 1. Closed cryptographic policy

Every `normal`, `rotate`, `revoke`, `recover` and `policy-change` operation requires
**two distinct ML-DSA-87 keys AND two distinct SLH-DSA-SHA2-256s keys** from the
current three-plus-three roster. Every current and successor policy is checked
across all five paths, including inactive recovery alternatives.

Public key identities bind the exact suite and canonical DER bytes under
`TRNM/RootRecoveryNativeKey/v2`. The verifier checks exact SPKI OIDs, canonical
encoding and public-key/signature lengths before launching crypto work. The
same-size SLH-DSA-SHAKE-256s key cannot masquerade as the fixed SHA2 suite.
The complete domain-prefixed statement is signed, including payload, network,
genesis, authorizing generation/epoch, predecessor, sequence, nonce, validity
and the full successor policy. Approval and successor-possession roles use
separate V2 domains. No legacy verification fallback is available.

Rotation, recovery and policy changes require possession signatures from **all
six successor keys** over that exact transition and their individual roles.
These new-key signatures supplement the current root's four authorizations;
they cannot replace them. The operation ID excludes selected quorum members and
signature bytes. All nine combinations of valid pairs name the same operation.
Changing the semantic intent changes its operation ID, while the durable owner
also separately forbids reusing its nonce with any new intent.

A new algorithm or family is refused by this closed version. Actual algorithm
replacement needs a separately reviewed version, new signed domains and an
explicit old-authority/new-possession migration. This implementation does not
pretend to offer an already qualified arbitrary algorithm migration protocol.

## 2. Owner state and crash ordering

`RootJournal.create` creates a new file exclusively. Opening a missing file does
not initialize it or enroll it at an anchor. Reopening requires independently
supplied expected scope, anchor pins and writer pins. Scope cannot be selected
by a replaced database. Private signing keys are outside the journal. Enrollment and successor
transitions reject syntactic root/writer/anchor/provider role-key reuse; distinct
public keys still do not establish independent physical custody.

The complete committed state includes current policy and public keys, generation,
epoch and sequence, anchor/writer/provider trust pins, every retained nonce and
operation ID, monotone revoked signer IDs, exact effect intents, their approving
signers and validity, effect outcomes and reorganization observations. State and
event commitments use fresh SHA-512 domains. Opening or using the state replays
the bounded immutable enrollment and event chain and compares the full final
state with `current`; leaving its old root field beside substituted JSON fails.
This replay verifies commitments. It does not silently claim to re-run every
historical signature verification.

The original-operation transaction is:

1. Acquire SQLite `BEGIN IMMEDIATE`, replay the exact local state, and obtain an
   authenticated fresh anchor response for that scope and complete head.
2. Verify the complete root statement and actual current signatures against
   that exact owner state. Verify successor possession when required.
3. Construct and **durably commit the exact pending target** before any external
   compare-and-swap. The pending target includes consumed nonce/history and its
   complete post-operation state. New operations refuse while it exists.
4. Send an authenticated CAS over the original predecessor and exact target.
   Both request and response require the separately pinned dual-family quorums.
5. Finalize only that exact acknowledged target. Return the captured committed
   state, rather than reopening a potentially replaced local snapshot.

A lost reply or ambiguous write preserves the pending target and fences the
owner. `resume_pending` only completes when a newly authenticated current
response names that exact target. A response still naming the predecessor does
not justify clearing the reservation or claiming non-execution. This bounded
version has no automatic abandoned-pending retry/discard protocol; that is an
availability limitation, not an invitation to reset history.

Every cryptographic and adapter stage shares one original `OperationBudget`.
Known committed work is retained if returning it becomes late; the late caller
receives no successful dispatch. SQLite persistence assumes the trusted host,
filesystem and storage stack honor their documented synchronization semantics.
Power-loss behavior on every target storage device has not been established.

The journal intentionally refuses after 128 root-operation nonces, 128 retained
revocations, 2,048 events, or its explicit state-size limit. These are bounded
research refusal limits, not safe pruning rules, lifetime adversary caps, or
production scalability qualifications. No rotation, recovery or reorganization
resets them.

## 3. Fresh anchor and authenticated writers

Requests bind schema, scope, fresh challenge, action and (for CAS) the complete
expected and target heads under `TRNM/RootRecoveryJournal/AnchorWriter/v2`.
The receiver uses its independently enrolled writer public keys to validate
all four signatures before servicing the request. Response signatures use a
separate domain and bind the fresh challenge and complete request digest.
Changing a root, namespace, challenge, CAS target or signer family is refused.

The native fixture has real, separately generated root, writer, anchor and
provider keys and a separately durable anchor SQLite file. They all share the
same test machine and administrator. This demonstrates the component boundary,
**not independent operators, devices, entropy, recovery administrators, WAN
availability or production service isolation**. The callback interface is not
a deployed authenticated network service.

The [native journal tests](../../formal/pon-nakamoto-v1/test_pq_root_recovery_journal_native_v2.py)
retain both outcomes:

- Restoring the complete owner database and journal while the anchor survives
  produces an authenticated-head mismatch and refuses new operation authority.
- Restoring **both owner and anchor** to the same old state permits the restored
  valid operation again, even though the new challenge and response signature
  are fresh. The test deliberately keeps all independence and qualification
  flags false. It is an impossibility counterexample under those assumptions,
  not a passed full-rollback-resistance gate.

A production successor therefore needs a surviving independently administered
currentness source and a defined trust bootstrap. Adding more files or signed
copies under the same rollback administrator does not supply that source.

## 4. External effects, Unknown and reorganization

A normal operation authorizes a versioned complete effect intent, including
provider identity, request bytes and the chain block it references. Providers
must already be enrolled. Arbitrary generic payloads do not become effect
capabilities. `enter_effect` rechecks the signed validity interval, current root
generation/epoch/policy and revocation of the four approving signers before
persisting the one entered record and returning the stable operation ID and
exact request. A reserved operation cannot be entered after expiry, root
rotation, recovery, or revocation of a required approving signer.

No method here performs a payment, sends an application API request or starts a
resource-consuming application job. The caller must integrate the returned
stable ID with the real provider's idempotency/readback contract. An entered
operation cannot be dispatched again by this owner after a timeout, process
restart, generation change or reorganization. Losing the return after commit
can lose availability and requires provider readback; it cannot justify a new
nonce retry.

Provider readback requires a fresh challenge, exact operation and intent digest,
provider identity and separately pinned real dual-family signatures. A supplied
JSON success flag does not clear uncertainty. A reorganization appends an orphan
obligation while preserving executed/unknown outcomes, nonce history and
revocations. A fresh successful receipt alone does not settle that obligation:
the provider must explicitly acknowledge the exact orphan epoch and say that
liability is retained, terminal non-execution/cancellation is observed, or
compensation is observed. `not-applied` must mean terminal non-execution, not
merely absence from the provider at this instant.
The compensation observation is not itself a new payment authorization.

This authenticates a provider declaration. Its real-world truth, funds, payment
irreversibility, resource accounting and independent dispute resolution remain
outside a same-host fixture. The `actual_external_effects_verified` field stays
false. Recovery remains refused for entered/unknown effects or unresolved orphan
obligations.

## 5. Verification and retained limits

Structural checks and actual cryptography are separate suites:

| Suite | Scope |
| --- | --- |
| [Signature structure](../../formal/pon-nakamoto-v1/test_pq_root_recovery_signatures_v2.py) | Exact suites, shapes, domains and refusal before native processes |
| [Real signatures](../../formal/pon-nakamoto-v1/test_pq_root_recovery_signatures_native_v2.py) | Five operations, nine quorum pairs, current/successor corruption, role and suite confusion |
| [Provider structure](../../formal/pon-nakamoto-v1/test_pq_root_effect_readback_v2.py) | Closed receipt grammar and explicit orphan reconciliation |
| [Real provider receipts](../../formal/pon-nakamoto-v1/test_pq_root_effect_readback_native_v2.py) | Real signatures, challenges, pinned keys and cross-role refusal |
| [Durable native journal](../../formal/pon-nakamoto-v1/test_pq_root_recovery_journal_native_v2.py) | Actual SQLite persistence, replay, rollback, lost CAS, contention, effects and current use |

Native suites require explicit OpenSSL executable, digest, version and prefix
pins. They have no environment-driven successful skip. The default provider
contains the native algorithms, while that executable pin alone does not attest
every loaded library, provider, kernel or machine dependency. Private fixture
keys are temporary and never committed.

The existing M15 release, clock and witness owners retain their original
ML-DSA-65/SHA-256 contracts. This V2 does not relabel them as ML-DSA-87 AND
SLH-DSA-SHA2-256s. Full Rust owner/deployment/FinalUse integration, independent
custody and recovery ceremonies, real remote-service evidence, paid external
reconciliation, and concrete eight-domain lifetime reductions remain open.
All complete-qualification outputs preserve `status=HOLD`,
`actual_lifetime_failure_bound=null`, `whole_chain_pq_qualified=false` and
`composition_coverage_proved=false`.
