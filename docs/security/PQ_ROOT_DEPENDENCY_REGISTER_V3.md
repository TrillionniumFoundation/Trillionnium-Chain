# Root dependency and query obligation register V3

Status: **HOLD**. This is a reviewed inventory for the Python V2 root bridge,
native Rust V3 candidate, V4 recovery-floor/provider-readback continuation and
conditional V5 fresh-witness owner with a typed SQLite register component.
The V5 provider readback bridge retains the original V4 provider declaration
grammar while requiring live witnessed enrollment checks before and after the
provider callback. It adds no effect execution or production authority.
It neither computes a cryptographic lifetime
failure bound nor activates a root, release, external effect or production
service.

The machine contract is
[pq-root-dependency-register-v3.json](../../config/pon/pq-root-dependency-register-v3.json),
checked by
[pq_root_dependency_register.py](../../scripts/ci/pq_root_dependency_register.py).
Its schema is `trnm-pq-root-dependency-register-v3`, separate from the
[existing lifetime budget](../../config/pon/pq128-lifetime-budget-v1.json).
The historical fifteen-path register and its current twenty-one-path continuation
do not acquire coverage of these root modules by continuing to pass. The
[V2 gap analysis](PQ_ROOT_LIFETIME_GAPS_V2.md) and
[lifetime contract](PQ128_LIFETIME_BUDGET_V1.md) retain their unresolved
independence, query-model and composition obligations.

## 1. Authority roles and implementation boundaries

The register requires all six roles, their actual implementations and their
entire key-epoch population. A roster has three keys per family. The number
of keys, rosters and epochs over the lifetime remains unknown.

| Role | Fixed authorization | Required uses | Candidate implementation |
| --- | --- | --- | --- |
| Root approval | ML-DSA-87 2-of-3 AND SLH-DSA-SHA2-256s 2-of-3 | Normal operation, rotation, revocation, recovery and policy change | Python V2 and native V3 |
| Successor possession | All three ML-DSA-87 keys AND all three SLH-DSA-SHA2-256s keys | Rotation, recovery and policy change, in addition to current-root approval | Python V2 and native V3 |
| Anchor writer | Both fixed 2-of-3 quorums under a separately pinned writer roster | Fresh read and compare-and-swap request authentication, including the separate V5 witness request namespace | Python V2, native V3 and V5 |
| Anchor response | Both fixed 2-of-3 quorums under a separately pinned anchor roster | Fresh response bound to request, scope and complete retained head | Python V2 and native V3 |
| Effect provider | Both fixed 2-of-3 quorums under a separately pinned provider roster | Outcome readback for the complete intent and exact orphan epoch | Python V2 and native V4 declarations, plus V5 witnessed readback; actual effect entry remains unwired |
| Witness response | Both fixed 2-of-3 quorums under a separately pinned witness roster | Complete fresh request and exact journal-head acknowledgement in the V5 namespace | Native V5 client, request authenticator and typed SQLite durable register; independently operated service remains unverified |

The [V5 witness contract](ROOT_WITNESS_V5.md) adds the sixth role and uses the
existing writer keys in a separate request namespace. The witness roster must
be disjoint from root, writer and original anchor keys. Its independent custody,
policy provisioning, common-restore exclusion and deployed durable CAS-before-ACK
behavior remain explicit open obligations. The typed SQLite component implements
local transactional persistence and exact independent reopen checks; it supplies
no daemon, network framing, physical power-loss or custody evidence. It has no Python V2 or native
V3 witness implementation. V5 consumes the original shared operation budget and
does not create a new lifetime budget for its separate domain tags.

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

The register contains eighteen declared hash-use groups and four canonical
primitive entries. The use groups identify source-level purposes. They do not
supply a reduction from scheme operations to primitive queries.

| Primitive | Recorded dependency |
| --- | --- |
| SHAKE128 | ML-DSA-87 internals across all six roles |
| SHAKE256 | ML-DSA-87 internals across all six roles |
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
| Owner `witnessed_v5.rs` and its `durable.rs` component | Complete enrollment; declared restore domain, recovery epoch and witness roster; complete fresh read or exact CAS request; request digest carried into the witness receipt. The durable component checks exact provisioned policy bytes and uses the same request/receipt domains. |

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

The preceding review base was the frozen integration commit
`44e96b1a841a50613d0b93484c5e576caec9f81f`, tree
`c297ebb14fcbeeb5f8acf13b3143a66b8b3b6db8`. All 37 declared source blobs were
read from that Git object and compared with the current regular files before
the map was frozen. The preceding continuation used review base
`57e6c17ae2fa8a9cc547e271f34d90ef09115f04`; its 37 pinned file bytes were
independently recovered from retained delivery `44330b91eb552fd20ef6f2e69bf5e6f1e8f5c0b0`.
The inspector itself does not verify Git ancestry or the eventual commit,
and still always returns `source_revision_bound = false`.

That integration changed seven declared files:

| Source | Reviewed difference from the root continuation |
| --- | --- |
| `trillionnium/Cargo.lock` | Retains the release OpenSSL edge and adds the storage `getrandom 0.2.17` edge. The package/version set is unchanged. |
| `trnm-crypto-primitives/src/lib.rs` | Retains the current grouped-fresh-seal and PQ content-auth exports alongside the new root export. |
| `trnm-pon-node/src/lib.rs` | Preserves the current generation, observation, funded-service and storage interfaces, adding only the Linux/`pq-root-v3` gated root export to the #835/#836 composition. |
| `trnm-protocol/src/lib.rs` | Preserves funded-service and content-commitment module exports. |
| `trnm-release-bundle/Cargo.toml` | Retains `trnm-protocol` as a normal dependency together with the optional OpenSSL/root feature. |
| `trnm-release-bundle/src/lib.rs` | Preserves the content module beside the separately gated root module. |
| `trnm-release-bundle/src/pq_release.rs` | Preserves complete cheap signer-set preflight before mathematical quorum verification; every supplied signature still requires verification. |

That integration's canonical source-map digest was
`64973799af0ff75049e27990f805dfbf8c39e4411ad5e2079884c3a684240cbf`.
The pre-update guard's exit-2 lockfile mismatch remains retained. No source was
reverted to satisfy an old pin. This rebinding changes no role, suite, domain
budget, lifetime, operational limit, deadline, query obligation or false
qualification field. In particular, new exports do not expand the 37 declared
paths into a complete transitive closure or wire the production effect sink.

The M8 dependency-security review used commit
`189b9b5959d836ef6ae96e14fb285948e4920aa9`, tree
`35c9394cc41d4c8c5e555ba421311f0d5c1b1126`. All 37 source bytes were
independently read from that Git object and matched against the working files.
Relative to the preceding map, only `trillionnium/Cargo.lock` and
`trillionnium/crates/trnm-pon-node/Cargo.toml` change. They select the patched
bundled SQLite dependency pair `rusqlite 0.41.0` / `libsqlite3-sys 0.39.0` with
its required transitive graph, while preserving all node feature selections.
That canonical source-map digest was
`ce51663cec6b33474ce58f26897c0361e25567f8dba6e5cfeb7479d76d9149da`. The 37-path roster,
roles, suites, query obligations, null budgets and false qualification fields
are unchanged. This review does not relabel any M6 native observation as a run
of the new dependency graph, and the inspector still returns
`source_revision_bound = false`.

The preceding compatibility review used M11 commit
`be5f047771e4d714726fec41abfa68231a06260b`, tree
`1ed07f1e5fa04febddd4e33487062a04d22ce3cd`. All 37 declared files were read
from that exact Git snapshot and matched against the working bytes. Relative
to M8, only the selected `root_recovery_v3/storage.rs` source changes: the
private connection now has an exclusive `RefMut` owner while a progress guard
and transaction are live. The original callback interval, cancellation and
deadline, transaction checks and durable synchronization order remain.
That canonical source-map digest was
`54106449c9d83a4b2926429160c8fd340d8004a67502ddf7b1e932df655859f6`. The other 36 selected files, all declarations,
null budgets and false qualification values remain. M10
`b0c52dcae9c698e38b33a82d0200c0d8294f3ba1` failed its new native compilation;
that failure remains historical evidence. This source review does not qualify
the repaired candidate or expand the declared transitive dependency scope.

The initial 2026-11-11 successor review, published in commit
`32453783834aabf30141dc03248acb24874f01ca`, retained the historical review-base
field and bound a **41-file** snapshot. It added `witnessed_v5.rs`, its
`witnessed_v5/durable.rs` component and separate protocol/durable native test
targets, updated the parent owner for V5 and exact snapshot guards, and retained
the V4 common-restore contrast. The other 35 selected source hashes were
unchanged from the integration baseline. That initial source-map digest was
`1de0b7bac54253f9bfaf312a5930dc0283d6c2c980122eea0801f443043bb6cf`.

The follow-up keeps the same 41-source roster and closes a cold retry boundary:
a stored predecessor cannot itself authorize an Advanced retry receipt after
reopen. Only a CAS authenticated and durably committed by the live session may
establish its volatile retry pair. Fresh Current observations remain the cold
reconciliation path. The component and its same twelve native test functions
are rebound, including a same-head, altered-predecessor negative control. That
follow-up's canonical source-map digest was
`ac0cb401b9ef7111cd77085c3f817ecfe56bdc73fc5fd4206e2c3cc8f3767c52`.
The newly reviewed files are successor working bytes; neither the retained M11
review-base value nor the separate `e4abb172147e941b62483652b0ceabaae4317624`
integration baseline claims that those new files existed or were executed at
either earlier commit. The inspector continues to return
`source_revision_bound = false`; exact committed-source native observations are
recorded separately.

This review also explicitly extends the role and hash-use declarations for V5.
It does not expand any probability or query bound, change a quorum, create a
primitive alias, or promote a deployment claim. Both
`independent_common_restore_exclusion_proved` and
`native_witness_durable_service_verified` remain false. The source checker has
no accept-current-bytes mode; its reviewed digest and the manifest must agree.

### 2026-11-11 S3 source refresh

The current review uses commit
`454ae116159867ff6cddd91b964523df7f7e16f0`, tree
`3117250c4db0f2ae681d51ed6ee5e6a2fa7555a9`. All 41 declared files were read
from that published snapshot. Exactly three source digests change from the
preceding frozen map: `trillionnium/Cargo.lock`,
`trillionnium/crates/trnm-crypto-primitives/Cargo.toml`, and
`trillionnium/crates/trnm-pon-node/Cargo.toml`. Their reviewed differences
are the existing Rustix 1.1.4 to 1.1.6 remediation; the other 38 selected
source hashes and all existing feature selections are unchanged.

The prior frozen source-map digest
`76cf5db4ce841bc3763d6010d79f835a6a0018c8d12f40a4047f0455b8bde6a1`
and its retained M11 review-base value remain historical inputs. On S3, the
[original repository-truth job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43042229392/job/130613468571)
ran the unchanged 43 controls and recorded four failures plus one error,
starting with the stale workspace lockfile pin. That failed observation is
retained; no source is reverted and no guard is relaxed to make it pass.
The refreshed canonical source-map digest is
`0a6cb7dc497a9365e0538b0ab7de510c28068ef0f0b211d0f0971b460a7302d4`.

This source-only refresh preserves the 41-path roster, all six roles, both
signature families, hash-use declarations, operation limits, deadlines,
unknown budgets and false qualification fields. Existing historical reports
keep their original source identities. The inspector still returns
`source_revision_bound = false`; it supplies no native execution, custody,
cryptographic lifetime bound or production qualification.

### 2026-11-13 SQLite setup cleanup source continuation

The current 45-path source review uses implementation commit
`975af9eb4a7f15b405de602552fa05021a176c11`, tree
`0b48dffaadc6b6281f95d2aa0392aaf95b02874b`. Its canonical source-map digest is
`8cfc6a3d9a0347cb8bd7e6c41f5286523d85bba48b3b392922ad8aae8c8d2435`.
Only `formal/pon-nakamoto-v1/pq_root_recovery_journal_v2.py` changes within
this inventory: the same three setup PRAGMAs now run inside the existing
try/finally connection-close guard. Transaction ordering, authority checks,
limits, deadlines and the other 44 source hashes remain unchanged.

The exact historical 225ab source-map test retains its original journal digest
and original `844d27717babb9b3a286cd28915a06b0cd1152ffcf151ffdf6c30a01708bd9fe`
map digest. The typed weak-key mapping below remains a historical input.
This source binding supplies no native execution or new qualification;
all roles, query obligations, unknown bounds and false qualification fields remain.

### 2026-11-13 typed weak-key source continuation

The typed weak-key source review bound the same **45 declared files** at
`57b069ae1e7ed32ff95e4f2a18a74d5eadcda550`, tree
`887f402546a4d1449919915a82f122acf3d0d49d`. The canonical source-map digest is
`e877eae7f4c1f7df4874c49f0bf6e2fc5b27f15912d9a0532e6704bb8e112a95`.

Exactly one declared digest changes from the retained mapping below:
`trillionnium/crates/trnm-crypto-primitives/src/lib.rs` changes from
`4dc3fd4c60ee7548adb5b50f8658a8ff9529dcbbeae98bb590f03458a707f0a6` to
`83fe52804bfbc593e2768c3a88764b532539deb8c9e866ee7305286491e16115`.
The typed `WeakEd25519Key` cause preserves the established decode, canonical
point and weak-key checks and the existing error display. It permits the
reviewed operator consumer to distinguish `ACTOR_WEAK_KEY` from `ACTOR_KEY`
without changing the set of accepted keys. That consumer is outside this
45-path inventory; reviewing the shared export does not extend this roster.

The other 44 source hashes, six authority roles, 18 shared-hash use groups,
operation limits, deadlines and unknown lifetime bounds remain fixed.
All existing test methods remain, including the exact 225ab historical
map reconstruction. Their refusal cases now also retain the prior B review
label and pre-continuation crypto digest. No native execution result is
transferred by rebinding these source bytes. `source_revision_bound = false`,
`status = HOLD` and all existing false qualification fields remain unchanged.

### Retained initial 45-source mapping, 2026-11-13

That root source review bound all **45 declared files** to the exact
regular bytes in commit
`b683714cdd5ba241c16c335a81aebc12c1581902`, tree
`f11a77d95b665207206282f691efc9d1225f26ea`.
The prior 45-file map retained review context
`225ab38e1e5f7e0852a28372bd8dd769eec1084b` and canonical digest
`844d27717babb9b3a286cd28915a06b0cd1152ffcf151ffdf6c30a01708bd9fe`.
That context predates some retained V6 source files; it was not their Git
provenance. That source revision contains every declared file.

Exactly six declared digests change. The other 39 source hashes, the 45-path
roster, all six authority roles, 18 hash-use groups, shared primitive identities,
refusal caps, deadlines, null bounds and false qualification fields remain.

| Declared source | Reviewed difference |
| --- | --- |
| `trillionnium/Cargo.lock` | Records the current 188-package workspace graph, including Ed25519/curve25519 3.0.0/5.0.0, bundled `rusqlite 0.41.1` / `libsqlite3-sys 0.39.1`, current serde/borsh/clap selections, and the existing node development `getrandom 0.2.17` and checkpoint `socket2` edges. The root OpenSSL, ML-DSA and Rustix selections remain. This inventory does not attest the transitive implementation or a new native run. |
| `trnm-crypto-primitives/Cargo.toml` | Selects the existing Ed25519 major version 3; root feature selections remain. |
| `trnm-crypto-primitives/src/lib.rs` | Uses fixed-size hex/signature decoding while preserving malformed/width/case rejection order and canonical R checks; the explicit weak-key check tightens accepted Ed25519 keys. This is a real acceptance change, not a claim of unchanged behavior. |
| `trnm-pon-node/Cargo.toml` | Retains the exact SQLite 0.41.1 pin and existing feature flags, with a development-only `getrandom 0.2.17` edge for the sealed research owner. |
| `trnm-pon-node/src/lib.rs` | Adds Cell V2 paged and Linux V3 grouped-storage exports without changing the root exports. Reviewing an export does not qualify its implementation. |
| `trnm-protocol/src/lib.rs` | Deserializes through a private wire shape and validates the transaction afterwards, retaining unknown-field and decimal rules. Direct serde input is more strictly checked; it grants no root authority. |

The canonical source-map digest for this review is
`731549321b29739c499f99920eb15259f6df371d36590c3c3aba36898c5c8571`.
The original B repository-truth failure and the
independent pre-update run of all 47 controls, both with four failures and one
error starting at the stale Cargo lock pin, remain failed historical
observations. The original 47 controls remain; added controls reconstruct the
exact previous map and reject each superseded pin. No source is rolled back
and no reader rule is relaxed to satisfy a declaration.

The existing V6 retained-receipt component remains in the 45-file map and the
eighteenth shared-hash use group. It records retained witness evidence under
the existing unknown SHA-512 lifetime scope; it supplies no effect authority,
independent custody proof or new budget. This refresh does not transfer any
historical native observation to the current source. The source inspector
still returns `source_revision_bound = false`, `status = HOLD` and false
production and whole-chain qualification fields.

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
