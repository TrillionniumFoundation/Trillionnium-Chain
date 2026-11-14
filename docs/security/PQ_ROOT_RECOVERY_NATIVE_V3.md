# Native dual-family root and recovery candidate V3

Status: **HOLD / RESEARCH ONLY**. Production activation is false. The actual
lifetime failure bound is unknown; whole-chain PQ qualification and composition
coverage remain false. This extends the [V2 research owner](PQ_ROOT_RECOVERY_NATIVE_V2.md)
and [V1 policy model](PQ_ROOT_RECOVERY_POLICY_V1.md) with reusable Rust components.
It does not make those earlier observations native V3 evidence.

## Scope and source ownership

| Component | Source | Authority provided |
| --- | --- | --- |
| Fixed dual-family roster and real verification | [crypto V3](../../trillionnium/crates/trnm-crypto-primitives/src/pq_root_v3.rs) | Mathematical signature verification under a complete pinned roster |
| Canonical root statements and state transitions | [release kernel V3](../../trillionnium/crates/trnm-release-bundle/src/root_recovery_v3.rs) | In-memory root operation validation and monotone semantic history |
| Signed anchor requests and responses | [anchor V3](../../trillionnium/crates/trnm-pon-node/src/root_recovery_v3/anchor.rs) | Authentication under separately enrolled writer and anchor rosters |
| Durable journal and replay | [storage V3](../../trillionnium/crates/trnm-pon-node/src/root_recovery_v3/storage.rs) | Bounded retained bytes with complete replay and pending-state reconciliation |
| Native owner | [owner V3](../../trillionnium/crates/trnm-pon-node/src/root_recovery_v3.rs) | Current root state and an owner-borrowed intent observation |
| Dependency register | [register V3](PQ_ROOT_DEPENDENCY_REGISTER_V3.md) | A finite source/role/hash-use inventory with unknown concrete bounds |

The crypto codec is available without native verification. Real verification
requires `pq-native-openssl`. The kernel and Linux journal owner require
`pq-root-v3`. This opt-in does not select a production release profile or change
an existing deployed root.

## Exact policy and fresh signed domains

Every ordinary authorization, rotation, revocation, recovery and policy change
requires **ML-DSA-87 2-of-3 AND SLH-DSA-SHA2-256s 2-of-3**. The canonical roster
contains exactly three keys of each family. The quorum verifier requires exactly
four distinct approvals, two from each family; fifth or sixth approvals are
refused. All six public keys, including unused quorum members, are validated
and included in the policy commitment.

Canonical SPKI bytes bind each suite to its exact OID and key size. Same-size
SHAKE variants, weaker ML-DSA variants, unknown suites, ambiguous lengths and
noncanonical encodings are refused. ML-DSA-87 verification uses the existing
RustCrypto candidate backend. SLH-DSA-SHA2-256s verification uses in-process
OpenSSL EVP. Backend errors do not select another suite or relax the AND policy.

Key, roster, statement, semantic-operation, successor-possession, state,
journal, anchor-request and anchor-response domains are fresh V3 namespaces.
Key identities and commitments use SHA-512 with labeled, bounded inputs.
Approval signatures cover the complete canonical statement. A semantic operation
ID excludes quorum choices and signature bytes, so nine valid quorum pairs
cannot create nine different operations for one statement.

Rotation, recovery and policy change additionally require **all six successor
keys** to provide separate proofs of possession. Each proof binds its role,
signer identity, suite, complete successor roster and complete transition
statement. Four old approvals cannot substitute for these six proofs.

Algorithm substitution is not implemented. There is no OR policy, classical
fallback, suite alias or automatic algorithm migration. A future substitution
needs a new reviewed profile, explicit compatibility rules, current-authority
approval and new concrete security accounting.

## Native root kernel

The statement binds the enrolled scope, policy generation, next sequence,
complete predecessor-state commitment, 32-byte nonce, validity interval and
complete action. Validity uses **Unix seconds** with an exclusive upper endpoint;
V2 height semantics are not silently reused.

Only recovery can authorize a transition after the old policy expires. It still
requires both current family quorums, all six successor proofs, a currently valid
signed recovery statement and valid successor policy. Expiry never creates an
unsigned recovery mode. Rotation and ordinary operations after expiry fail.

Successful operations consume nonces and retain revoked key identities across
policy generations. Successors cannot reintroduce revoked keys. Private state
changes only after the complete operation succeeds; failed verification leaves
semantic state unchanged while actual cryptographic reservations remain charged.

Ordinary release intent binds the use kind, complete bundle and contract bytes,
complete artifact SHA-512 and observed size, and a fresh attempt identifier.
`matches_bytes` checks actual supplied material. Construction rejects oversized
material before copying or hashing it. Research bounds are 8 KiB per bundle or
contract, 64 MiB per artifact, 32 KiB per complete statement, 512 KiB per envelope
and 128 retained operations/revoked identities. The journal applies its own
stricter 256 KiB envelope, 2 MiB state and 32 MiB retained event-byte limits. Exhaustion refuses work; history
is not pruned and generations do not renew the lifetime allowance.

These implementation limits do not bound adversary offline queries, other
instances, unpublished work, failed attacks or the complete chain lifetime.
Current intent checking repeats generation, policy, signed expiry, time floor
and signer-revocation checks after fresh anchor observation and journal replay.
The Unix timestamp is a trusted caller input. This owner does not integrate the
existing M15 signed clock or independently establish wall-clock freshness.

## Durable owner and external currentness

Enrollment explicitly binds separate nonzero 32-byte **network**, **genesis**
and **owner** identifiers. A labeled SHA-512 scope derives from all three; both
raw identifiers and derived scope are retained. Opening an existing journal
requires the expected enrollment. These are domain labels, not proof that every
external chain identifier or existing chain hash has a PQ-128 collision bound.

Initial root, writer and anchor rosters are separately pinned and disjoint.
Successors cannot borrow writer or anchor keys. Cryptographic disjointness does
not establish independent human custody, hardware, administration or recovery.

The Linux owner uses a separate SQLite namespace, bounded decoding, filesystem
identity checks, exclusive owner locking and transactional updates. Foreign or
legacy SQLite namespaces are refused before writable database behavior. Existing
data is never silently enrolled or migrated. The mode-0700 directory must be
administered by a trusted owner UID: held-file and pathname checks detect
persistent replacement, but ordinary rusqlite reopening does not expose its
internal main-file descriptor. This is not proof against a same-UID actor
concurrently swapping and restoring pathnames during open. No custom VFS or
complete hostile-filesystem isolation is claimed.

The service must already be explicitly enrolled with the exact initial head.
Writer requests bind scope, action, fresh challenge and exact expected/target
heads. Responses bind the request and authenticate the observed head. Both use
separate fixed dual-family 2-of-3 AND 2-of-3 rosters. A signed but stale,
wrong-request or wrong-scope response is refused.

Each append follows this order:

1. Lock and replay the complete retained journal from immutable enrollment,
   including original root signatures and successor proofs.
2. Observe the retained anchor head with a fresh signed challenge.
3. Validate the new operation and persist the complete pending transition before
   calling the external compare-and-set service.
4. Require an authenticated exact pending-target response, then complete the
   local transition transactionally.

An uncertain CAS result fences the owner. Timeout, cancellation, exhausted budget
or invalid response cannot erase pending state, create a different operation or
declare success. Explicit resume accepts only an independently observed exact
pending target. If the anchor remains at the predecessor, V3 refuses retry or
discard; availability recovery for that case is unimplemented. Reopening also
refuses an unresolved predecessor.

Callbacks retain the original `OwnerBudgetV3` identity, cancellation and absolute
deadline. Replacement during writer/transport callbacks is detected. Explicit cancellation and observed external signals latch permanently;
clearing a retained external alias cannot restore permission. A transient signal
that is set and cleared entirely between observations is not detectable. Crypto
charges old approvals, six possession proofs and signed replay; nested calls do
not obtain a new allowance. The default crypto deadline is 60 seconds; the
explicit deadline constructor is caller-configurable. Neither establishes
independent real-world freshness or a universal timing guarantee.

The fixture uses actual signatures and a separately retained anchor object. It
tests this process boundary, not an independently administered durable WAN
anchor. Both outcomes remain explicit:

- Restoring only the owner database while the anchor remains advanced fails.
- Restoring the owner **and every retained anchor state together** can reproduce
  a valid old history and succeeds in the retained counterexample.

No local journal, local witness, timestamp or self-signed readback closes the
second case. An independently surviving, authenticated and sufficiently fresh
source of currentness is still required.

## Release and external-effect boundary

`CurrentIntentObservationV3` has private fields and borrows its owner; it is not
cloneable or deserializable. It is an observation, **not an effect-entry or
FinalUse capability**. V3 does not call existing M15 installation, launch-attempt,
held-object claim or final-use sinks. Existing ML-DSA-65 release paths remain
distinct and are not labeled V3 by this change.

Completing integration requires an explicitly selected protected profile to carry
these exact bytes, original budget, current authority and uncertain-result state
through the actual sink. It must also check the expected use kind and attempt
identifier; `matches_bytes` compares only its three material-byte arguments. The
profile must fail closed when any V3 component is unavailable. Feature enablement or a second check beside a legacy path does not
prove this refinement.

Provider readback, entered/Unknown outcomes and explicit orphan liability or
compensation remain in the separately tested Python V2 research owner. This
native owner does not claim to have paid a provider, reversed a payment, executed
an API, reconciled resources or compensated a reorganization. Native provider
schemas and production adapters remain open. Root-state rollback is never itself
proof that an external effect was undone.

## Mandatory tests and qualification

The explicit [recovery-floor continuation](PQ_ROOT_RECOVERY_FLOOR_V4.md)
adds an externally supplied, full-enrollment-bound minimum signed history to a
new open API; the original V3 open API retains its original behavior. The
[native V4 provider journal](PQ_ROOT_EFFECT_READBACK_NATIVE_V4.md) now supplies
authenticated historical readback and durable uncertainty without dispatching
effects. These are new V4 interfaces and signed domains, not an implicit change
to existing V3 persistent data or M15 authority.

The anchor writer and transport callbacks also check the original budget after
an error return, before propagating that error. This observes and latches
cancellation even when a callback reports failure. A signal set and cleared
entirely between checks remains outside that observation guarantee. The
[migration material review](PQ_ROOT_MIGRATION_REVIEW_V1.md) requires explicit
transition material and historical continuity; it supplies no algorithm switch
or migration authorization.

The [native runner](../../scripts/ci/run_pq_root_native_v3.py) executes five
explicit Cargo selectors for crypto structure, actual crypto integration, native
cached-key invariants, kernel and native owner integration tests. Every exact name and matching nonempty
summary is required, with zero failed, ignored or measured tests. Filtered
unrelated tests are recorded separately. Synthetic parser controls do not count
as native crypto execution.

The runner verifies exact committed source bytes before and after execution and
retains all attempted commands and raw output, including failures. Existing V2
native suites and original protocol/Host commands remain mandatory. A passing V3
component run is not a passing whole protocol lane or whole workspace.

The [dependency register](PQ_ROOT_DEPENDENCY_REGISTER_V3.md) binds a finite reviewed
snapshot and declares shared primitive budgets without filling unknown values.
Source/policy controls cannot establish independent custody, deployment,
freshness assumptions, complete event coverage, a reduction theorem or a concrete
lifetime probability bound. The [lifetime contract](PQ128_LIFETIME_BUDGET_V1.md)
continues to require all eight domains and shared hash-query accounting.

```text
status = HOLD
actual_lifetime_failure_bound = null
whole_chain_pq_qualified = false
composition_coverage_proved = false
production_activation = false
```

The [signature cost component](PQ_ROOT_SIGNATURE_COST_V1.md) retains immutable ML-DSA-87 expansion only. Signature acceptance and current authority are never cached. Its explicit observation example does not measure owner replay, Cell access or deployment performance.
