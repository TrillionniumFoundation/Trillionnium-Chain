# Root dependency and query obligation register V3

Status: **HOLD**. This is a reviewed inventory for the Python V2 root bridge,
native Rust V3 candidate and explicit V4 recovery-floor/provider-readback continuation.
It neither computes a cryptographic lifetime
failure bound nor activates a root, release, external effect or production
service.

The machine contract is
[pq-root-dependency-register-v3.json](../../config/pon/pq-root-dependency-register-v3.json),
checked by
[pq_root_dependency_register.py](../../scripts/ci/pq_root_dependency_register.py).
Its schema is `trnm-pq-root-dependency-register-v3`, separate from the
[existing lifetime budget](../../config/pon/pq128-lifetime-budget-v1.json).
The old fifteen-path register does not acquire coverage of these new modules
by continuing to pass. The
[V2 gap analysis](PQ_ROOT_LIFETIME_GAPS_V2.md) and
[lifetime contract](PQ128_LIFETIME_BUDGET_V1.md) retain their unresolved
independence, query-model and composition obligations.

## 1. Authority roles and implementation boundaries

The register requires all five roles, their actual implementations and their
entire key-epoch population. A roster has three keys per family. The number
of keys, rosters and epochs over the lifetime remains unknown.

| Role | Fixed authorization | Required uses | Candidate implementation |
| --- | --- | --- | --- |
| Root approval | ML-DSA-87 2-of-3 AND SLH-DSA-SHA2-256s 2-of-3 | Normal operation, rotation, revocation, recovery and policy change | Python V2 and native V3 |
| Successor possession | All three ML-DSA-87 keys AND all three SLH-DSA-SHA2-256s keys | Rotation, recovery and policy change, in addition to current-root approval | Python V2 and native V3 |
| Anchor writer | Both fixed 2-of-3 quorums under a separately pinned writer roster | Fresh read and compare-and-swap request authentication | Python V2 and native V3 |
| Anchor response | Both fixed 2-of-3 quorums under a separately pinned anchor roster | Fresh response bound to request, scope and complete retained head | Python V2 and native V3 |
| Effect provider | Both fixed 2-of-3 quorums under a separately pinned provider roster | Outcome readback for the complete intent and exact orphan epoch | Python V2 and native V4 declarations; actual effect entry remains unwired |

The [native cryptographic module](../../trillionnium/crates/trnm-crypto-primitives/src/pq_root_v3.rs)
uses the existing
[ML-DSA candidate verifier](../../trillionnium/crates/trnm-crypto-primitives/src/pq_candidate.rs)
for ML-DSA-87 and in-process OpenSSL for the exact SLH-DSA-SHA2-256s suite.
The adapter's direct
[protocol message-bound dependency](../../trillionnium/crates/trnm-protocol/src/crypto_profile.rs)
is also included in the reviewed source map.
Its codecs are exported independently of the `pq-native-openssl` feature;
real verification is feature gated. The
[root policy kernel](../../trillionnium/crates/trnm-release-bundle/src/root_recovery_v3.rs)
and Linux
[durable owner](../../trillionnium/crates/trnm-pon-node/src/root_recovery_v3.rs)
are selected by `pq-root-v3`. The declared source set also includes the
[anchor protocol](../../trillionnium/crates/trnm-pon-node/src/root_recovery_v3/anchor.rs),
[storage implementation](../../trillionnium/crates/trnm-pon-node/src/root_recovery_v3/storage.rs),
module exports, Cargo manifests, lockfile and new native tests.

These source and feature bindings do not establish production reachability.
The existing M15 release files are retained as boundary references. The
candidate's current-intent observation does not dispatch a payment or API
effect, establish native provider readback, or complete a production FinalUse
handoff.

Python V2 checks the original owner-height contract, including inclusive height
validity. Native V3 uses a distinct signed namespace and Unix seconds with
exclusive expiry. The register refuses a claim of wire equivalence or a
substitution of one validity contract for the other.

Each role includes initial, active, successor, retired and recovered keys.
Rotation, recovery, process restart and movement between roles do not reset
the lifetime. A retired key's remaining authority must be included when
determining the future security experiment. Different key bytes or different
role labels do not demonstrate independent operators, devices, backups or
recovery procedures.

## 2. Shared primitive accounting

The register contains sixteen declared hash-use groups and four canonical
primitive entries. The use groups identify source-level purposes. They do not
supply a reduction from scheme operations to primitive queries.

| Primitive | Recorded dependency |
| --- | --- |
| SHAKE128 | ML-DSA-87 internals across all five roles |
| SHAKE256 | ML-DSA-87 internals across all five roles |
| SHA-256 | SLH-DSA-SHA2-256s internals and the Python OpenSSL executable-integrity check |
| SHA-512 | SLH internals, HMAC-SHA-512 and MGF1-SHA-512; Python and native identities, commitments, state and request bindings |

ML-DSA's SHAKE128 and SHAKE256 dependencies follow
[FIPS 204, section 3.7](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf).
For SLH-DSA-SHA2-256s,
[FIPS 205, section 11.2.2](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf)
specifies SHA-256 and SHA-512, including HMAC-SHA-512 for the signing PRF and
MGF1-SHA-512 in the message-hash construction. The suite name does not remove
its SHA-512 dependency. These standard definitions alone do not instantiate
the deployment's concrete forgery or composition bounds.

The Python mapping includes the original policy/statement/operation model,
canonical public-key identities, complete verified messages, semantic operation
identities, the complete journal state chain, owner scope, effect intent,
anchor requests and provider requests. The native mapping additionally names:

| Source | SHA-512 bindings |
| --- | --- |
| `pq_root_v3.rs` | Exact suite and canonical public-key bytes; complete canonical roster; operation identity independent of selected witnesses |
| Release kernel `root_recovery_v3.rs` | Policy commitment; full state checkpoint; actual artifact bytes included in the complete release intent |
| Owner `root_recovery_v3.rs` | Network/genesis/owner scope; enrollment and full journal heads, including retained event and state bindings |
| Owner `anchor.rs` | Complete fresh writer request, carried into the signed anchor response |
| Owner `recovery_floor.rs` | Full enrollment bound to the externally supplied V4 history floor |
| Owner `effect_readback_v4.rs` | Complete provider enrollment and intent, fresh request, exact orphan epoch and retained evidence chain |

The native crypto domains include `TRNM/RootV3/Key/v3`,
`TRNM/RootV3/RosterCommitment/v3` and `TRNM/RootV3/Operation/v3`.
Kernel commitments use the `TRNM/RootRecovery/...` V3 namespaces. Owner
commitments and request digests use `TRNM/RootOwner/...` V3 namespaces.
The actual encodings and terminating null bytes are fixed by the bound source.
Signed approval, possession and receipt frames also consume the internal
hash primitives of the selected signature algorithms; a frame does not need
an additional explicit digest call to incur those dependencies.

Each primitive has one shared lifetime scope across listed roles, code
versions and key epochs. HMAC, MGF1, a new domain tag or a fresh roster cannot
be relabeled as an independent public SHA-512 function with a separate
resettable budget. The register also keeps the query expansion and quantum
reduction uninstantiated. It does not assert that counting source calls is
the right query unit or that all uses of two distinct SHAKE interfaces have
independent security events.

This root inventory does not close the whole chain's hash-query scope. Uses
outside these declared components still require accounting. The older lifetime
register and this register refer to shared public primitive identities; their
budgets cannot be treated as independent or reset at the register boundary.

All four maximum query budgets remain `null`. Their declared coverage
includes online and offline work, preprocessing, failed and cancelled
attempts, unpublished work, recursive and helper computations, shared roles,
all key epochs and authority surviving retirement. Initial advice is
unqualified. Converting elapsed time, resource limits, observed operations or
signed receipts into an adversary bound requires a separate justified model;
none is supplied here.

## 3. Local refusal limits are not adversary budgets

The register records selected refusal conditions with their original scope.
Examples include Python's 128 retained nonces and 2,048 journal events,
native root/journal capacity of 128, and the native shared verification
budget's reservation and byte ceilings. These are implementation limits on a
particular owner or operation. They do not limit an adversary's offline
queries, helper machines, rejected attempts or work before enrollment.

The 60-second `VerificationBudgetV3::new` duration is recorded separately as
a default. `with_deadline` accepts a caller-supplied monotonic deadline, so
the universal duration maximum remains `null`. Checks around an in-process
native verification call do not preempt that call once it is running.

Every listed cap carries `bounds_adversary_queries = false`.
It also grants no permission to prune one-use history or reset the lifetime.
The list describes selected refusal conditions; it does not claim to be the
complete resource policy. Even zero is rejected as a supplied numeric lifetime
budget in this inventory schema. Instantiating actual query bounds requires
a separately reviewed model, not a change of a cap's unit or scope label.

## 4. Reviewed source binding

The source map binds the declared regular files to exact SHA-256 digests.
The trusted checker also pins a digest of the canonical source map and the
recorded review-base revision. Changing both a source file and its manifest
digest therefore fails until the reviewed checker snapshot is deliberately
updated. There is no auto-regeneration or accept-current-bytes mode.

The review base `44330b91eb552fd20ef6f2e69bf5e6f1e8f5c0b0` is context for the
continuation. It is not a claim that the newly added files existed in that
revision. The inspector does not verify Git ancestry or the eventual commit,
and always returns `source_revision_bound = false`.

The [signature cost continuation](PQ_ROOT_SIGNATURE_COST_V1.md) reviews the
immutable ML-DSA-87 expansion cache and adds the native cost-observation example
to this declared source map. The cache changes no signed domains, authority
roles, operational charges, unknown lifetime populations or domain bounds.
The reviewed snapshot is deliberately updated after those code and test changes;
the runtime inspector still cannot regenerate its own approved snapshot.

The checker reuses the existing
[descriptor-bound source reader](../../scripts/ci/pq_source_reader.py).
It refuses missing, symlinked, nonregular, oversized and changing source
entries; parsing rejects duplicate JSON keys, ambiguous numbers and invalid
Unicode. Source and manifest reads are bounded. The checker performs no
filesystem mutation.

This establishes consistency of the declared file bytes with one reviewed
snapshot. It does not establish an atomic snapshot of the entire checkout,
a complete transitive dependency closure, executable provenance, a trusted
OpenSSL build/provider configuration, deployed custody or protection against
an actor who can also replace the trusted checker itself. Native libraries,
toolchain, operating system, entropy, storage semantics and runtime
configuration remain implementation/refinement obligations. SHA-256 source
fingerprints are local review metadata, not a new theorem about the root's
lifetime failure probability.

The native owner's Unix-time input is trusted caller time, not an attestation
from a production M15 clock. Its SQLite adapter assumes trusted administration
of the private directory during database opening. Held file and pathname
checks do not prove that SQLite's separate internal descriptor refers to the
same inode across a concurrent open race. This register supplies no custom
VFS proof and does not qualify protection against same-UID pathname changes.
These host assumptions remain explicit in the frozen profiles.

The [V4 recovery floor](PQ_ROOT_RECOVERY_FLOOR_V4.md) is an explicit trusted
caller input. Its constructor, separate namespace and signed-ancestry checks do
not authenticate an independent source or its age. The
[V4 provider journal](PQ_ROOT_EFFECT_READBACK_NATIVE_V4.md) verifies retained
provider declarations in a new namespace. Its `rust-v4-readback` entry is
separate from actual effect-entry/production-owner integration: the latter
remains in `native_unwired_roles`. A provider declaration cannot establish that
payment, API, resource or compensation actually occurred. Fixed provider keys,
provider-side request authentication/transport and their complete lifecycle
remain integration obligations. Neither continuation creates a new resettable
SHA-512 or signature query budget.

## 5. Result and regression contract

Run from the repository root:

~~~sh
python3 scripts/ci/pq_root_dependency_register.py --root .
python3 scripts/ci/test_pq_root_dependency_register.py
~~~

A matching reviewed inventory returns exit code zero and a result containing:

~~~json
{
  "status": "HOLD",
  "inventory_contract_satisfied": true,
  "source_files_checked": true,
  "source_revision_bound": false,
  "actual_lifetime_failure_bound": null,
  "whole_chain_pq_qualified": false,
  "composition_coverage_proved": false,
  "transitive_dependency_closure_proved": false,
  "whole_chain_hash_query_scope_closed": false,
  "native_m15_production_integration_complete": false,
  "production_activation": false
}
~~~

Malformed input, missing obligations, changed source bytes and attempted
promotion return `REFUSE` and exit code two. Exit zero means this inventory
contract matched; the status remains `HOLD`. The pure
`validate_manifest` API checks declarations only and leaves
`source_files_checked = false`; `inspect` additionally checks the declared
file bytes.

The [adversarial controls](../../scripts/ci/test_pq_root_dependency_register.py)
cover missing roles/actions, threshold and suite substitution, false native
provider coverage, missing SHA-512/HMAC/MGF/SHAKE dependencies, source and
source-map rewriting, role/epoch budget resets, hidden query channels,
numeric-cap laundering, default-duration promotion, malformed input and
source-path substitution. They verify frozen obligations and refusal behavior.
They are not cryptographic attack-cost estimates.

All eight domain bounds remain `null`: signature, commitment, proof, ledger,
transport, recovery, release and application. The open obligations retain
whole-chain event coverage, concrete quantum multi-user forgery, shared-oracle
instantiation, resource/query transformations, preprocessing and advice,
implementation refinement, independent custody, independently retained fresh
anchors, native provider/effect-owner integration and actual reconciliation.

Restoring every observer's state to the same coherent earlier history still
leaves no fresh independent evidence with which to distinguish that history
from a world where later actions never occurred. The complete-local-rollback
counterexample in the V2 gap analysis therefore remains applicable. A passing
same-host native fixture, a fresh request nonce or a differently named anchor
key does not establish an independently administered surviving authority.
