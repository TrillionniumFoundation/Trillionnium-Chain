# Seven-file review and exact effect-root coverage

Reviewed runtime source: `618d1bd225db4df8fb7c1d0fc53af991d7f7fdf7`, on parent
`6f458c4fbf07a0a44d7d7a6f451aa960c1b0a029`. This is an author verification report
with executable negative controls; it is not an independent third-party audit
or whole-system acceptance. The integration owner has separately reviewed the
main cold-open logic. Local derived source-integrity/selector updates are
identified in the [evidence README](README.md).

## Seven changed files

| File | Reviewed invariant and outcome | Residual limit |
| --- | --- | --- |
| [Witness service](../../../trillionnium/crates/trnm-pon-node/src/pq_rollback_witness.rs) | `Checkpoint::new` validates the caller's expected sequence/root before storage access. `known_head` is initialized to that expected value before `read_head`; the old read-and-adopt path is removed. Binding/key checks, storage identity checks and exclusive writer lock remain. No new signed domain, wire format or stored schema. | The API cannot establish that the caller retained a current checkpoint independently. That is an explicit trust premise. |
| [Witness tests](../../../trillionnium/crates/trnm-pon-node/src/pq_rollback_witness/tests.rs) | Real native Current/CAS receipts establish the retained head. A coherent old SQLite snapshot, stale expected head, future expected head and same-sequence conflicting root are refused. Exact head opens; second live owner remains busy. Invalid sequence/root is refused before a missing storage path is touched. Old-method controls fail and fixed controls pass. | Test fixture separation is not physical fault-domain independence. |
| [Admission owner](../../../trillionnium/crates/trnm-pon-node/src/store/pq_network.rs) | The #698 helper returns the same `Mutation` when there is no real expiry transition. The fresh Current observation, predecessor, permission reads and pending mutation therefore stay under the same IMMEDIATE transaction. Actual expiry retirement commits and publishes its epoch before a fresh guard is acquired. No deadline renewal or weakened policy lookup. | This removes one redundant guard acquisition in the common path; it does not establish whole-business performance. |
| [Store tests](../../../trillionnium/crates/trnm-pon-node/src/store/pq_rollback_witness/tests.rs) | Fixture `head()` obtains an authenticated Current response before service stop. Updated reopen calls explicitly pass the retained value. Imported native tests verify operation order `[1,2]`, pending replay `[1]`, and real expiry `[1,2,1,2]`, together with persisted rows, sequence advancement, epoch publication and cold Node reopen. | These orders cover PNQ2 state transitions, not arbitrary business effects. |
| [Combined process tests](../../../trillionnium/crates/trnm-pon-node/src/store/pq_rollback_witness/combined_tests.rs) | Parent passes explicit expected sequence/root to the child. For restart the Node is quiesced first, the parent obtains an authenticated Current receipt while the external service is live, then the service stops. Evidence collection and cleanup share one 10-second interval; original business assertions and 250 ms request cap are untouched. | Three original process controls are blocked by child Unix socket EPERM here. Their original assertions still require execution in CI. |
| [Witness contract](../../../docs/security/PQ_NETWORK_DURABLE_WITNESS_V1.md) | Documents exact external checkpoint provenance, stale/ahead/conflict refusal, uncertain receipt reconciliation, three-table scope and independent-authority premise. Removes the old auto-discovery recovery wording. | Does not promise automated repair, global effect coverage or a physical monotonic root. |
| [Sole plan](../../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md) | Records the narrow recovery and retained-admission changes in the existing candidate, while keeping all release and larger P0 qualifications open. | Integration must preserve one candidate and regenerate the final source inventory. |

The direct source comparison found no changed Cargo dependency, schema, signed
namespace, business budget, enrollment authority or release policy. Native
regressions for concurrent clients, exact/conflicting CAS, late known success,
unknown CAS, local commit failure and epoch invalidation passed in the retained
filter. The source-integrity test suite, strict Clippy and formatting also
passed; see the raw receipts in the README.

## What the current external root actually binds

[WitnessBinding](../../../trillionnium/crates/trnm-pon-node/src/pq_rollback_witness.rs)
uses a positive bounded generation, the full canonical PNQ2 policy and distinct
pinned ML-DSA-65 witness/writer SPKIs. Its identifier is a SHA-512 digest of that
binding. The service checkpoint is an exact `(sequence, 64-byte root)` value.

[protected_root](../../../trillionnium/crates/trnm-pon-node/src/store/pq_rollback_witness.rs)
uses domain `TRNM/PNQ2/protected-owner-tables/v1`, the binding identifier and an
ordered typed encoding of exactly these rows:

| Table | Committed columns |
| --- | --- |
| `pq_network_resource_v2` | `singleton`, `connections`, `input_bytes`, `inbound_verifications` |
| `pq_network_peer_v2` | `peer`, `highest_sequence`, `revoked` |
| `pq_network_request_v2` | `peer`, `sequence`, `operation`, `wire`, `response`, `response_digest`, `status` |

The local binding/policy metadata is checked against external configuration;
it is not an independent monotonic source. The same code bounds row counts,
storage classes and blob sizes before hashing. Neither account balances nor
business/settlement/task state, blocks, History, active-chain selection,
CURRENT, model installation or FinalUse is in the root's table enumeration.
The existing M03 whole-owner checkpoint contract is a different format; no
composition with this three-table root is introduced here.

[Mutation](../../../trillionnium/crates/trnm-pon-node/src/store/pq_rollback_witness.rs)
retains an IMMEDIATE transaction, compares fresh authenticated Current to the
local checkpoint, and recomputes the three-table root. It advances external
CAS before local commit. Missing/invalid/unknown CAS outcomes fence the client
and invalidate already-authorized network epochs; known successful late CAS
receipts align local commit before a live-use error is returned. This is
fail-closed behavior, not automatic distributed recovery.

[Node open/recover](../../../trillionnium/crates/trnm-pon-node/src/store.rs)
checks the witness before ordinary local recovery. Later account/History
validation and best-tip recovery do not thereby become externally committed
by the three-table root. A fresh Current is also not a distributed lease: two
cloned stores with valid writer authority can observe the same predecessor
and begin business work before protected-table CAS orders their changes.

## Remaining requirements for the sole plan

| Requirement still open | Concrete next acceptance evidence |
| --- | --- |
| Complete effect-state recovery | A versioned mapping from every real effect owner to an independently retained root: balances/settlement/obligations, task and History state, CURRENT and FinalUse journals/generation fences. Reject coherent rollback of each owner, including combinations whose three PNQ2 tables remain unchanged. |
| Uncertain CAS and multi-writer effect safety | Durable operation identity and idempotency/fencing at the actual effect owner; recovery rules for external success with local commit failure, lost receipts, conflicting writers and owner restarts. A guarded network ledger must not be treated as a lease or business-effect commit. |
| Independently current cold-recovery authority | Obtain the expected checkpoint outside the witness rollback/fault domain after all writers quiesce. Demonstrate durable retention and explicit conflict/unknown-outcome reconciliation. Refuse a stale checkpoint restored alongside SQLite. The new API checks equality; it does not provision this authority. |
| Current PQ authorization at every real entry | Establish one effective versioned profile and authoritative, rollback-resistant current trust roster; trace each ingress, retry, recovery, release/install and FinalUse action to it. Preserve closed failure on stale generations, revocation, mismatched owners and classic-profile downgrade. |
| Historical ownership and migration | Supply independently accepted evidence for precommitted PQ ownership timing, source finality and source retirement/locking, complete asset/liability conservation and current revocation/rotation semantics. The existing research import type cannot prove those historical premises. |
| Final composed native behavior | Run all 47 original required selectors and the additional combined process controls in the established CI environment with native ML-DSA and Unix sockets. Keep the current failed local observations and original limits. |

The PQ handoff implementation in
[hepta_handoff/pq.rs](../../../trillionnium/crates/trnm-research-protocol/src/hepta_handoff/pq.rs)
requires an externally supplied in-memory roster, one current generation per
DID, no duplicate PQ key aliases, validity/revocation checks, exact destination
chain and exact current owner admission snapshot before native ML-DSA-65
verification. It has no classic-signature OR fallback. It owns no durable
roster, nonce/journal or FinalUse token; the caller must supply current facts
and enforce the real effect. This Chain-side review is not an audit of every
Hepta deployed consumer.

The migration code in
[migration.rs](../../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/migration.rs)
and [task_migration_v1.rs](../../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/task_migration_v1.rs)
is explicitly for an independently selected new research genesis. It binds
the source header/state and enumerated obligations, requires precommitted PQ
keys and locked claims, and does not accept an anchor from ordinary request
bytes. Its contracts explicitly exclude proof of earlier registry timing,
source finality/retirement and retroactive recovery of already compromised
Ed25519 ownership. This change preserves those limits and does not declare
migration complete.
