# Root algorithm migration material review V1

Status: **HOLD / RESEARCH ONLY**. No algorithm replacement is implemented or
authorized. The configured packet contains `proposal: null`; the current native
V3 suite remains fixed. The actual lifetime failure bound is unknown.

The [read-only checker](../../scripts/ci/pq_root_migration_review_v1.py) makes the
continuity requirements for a future proposal explicit and checks actual input
file bytes. It never enters a root operation, alters a journal, changes a
cryptographic provider, executes supplied material, invokes a remote service,
or grants M15/FinalUse authority. Its
[default input](../../config/pon/pq-root-migration-review-v1.json) is deliberately
an absent proposal, not a synthetic approved migration.

This extends the review boundary described in
[native root V3](PQ_ROOT_RECOVERY_NATIVE_V3.md),
[the dependency register](PQ_ROOT_DEPENDENCY_REGISTER_V3.md), and
[the lifetime gaps](PQ_ROOT_LIFETIME_GAPS_V2.md). It does not close their open
conditions. NIST's [CSWP 39 update 1](https://csrc.nist.gov/pubs/cswp/39/upd1/considerations-for-achieving-crypto-agility/final),
updated June 29, 2026, treats algorithm replacement as a change across protocols,
applications and infrastructure that must preserve security and operations.
The invariants below are this candidate's specific review requirements; that
publication supplies no proof or concrete error estimate for this project.

## 1. Three different results

| Input/result | What is checked | What remains unverified |
| --- | --- | --- |
| No proposed migration | Exact schema and explicit absence of a proposal | Every migration prerequisite |
| Proposed packet, pure `evaluate` | Bounded schema, before/after declarations and complete proposal binding | Whether referenced files exist or match their hashes; every claim inside those files |
| Proposed packet, `inspect` | The same declarations plus exact length and SHA-512 of every required regular file | Signatures, embedded statements, new code semantics, actual currentness, proof applicability and independent provenance |

A complete byte readback sets `review_material_complete = true` and
`material_bytes_checked = true`. Here **complete means that every named input
material was present and matched its declared bytes**. It does not mean that a
valid migration certificate, a complete key population, or adequate security
evidence has been obtained. The tests deliberately use clearly labeled
synthetic, unverified bytes to check that this case still remains HOLD.

Every successful result keeps:

~~~text
migration_authorized = false
migration_implementation_verified = false
cryptographic_verification_performed = false
theorem_applicability_verified = false
complete_key_epoch_population_verified = false
independent_custody_verified = false
anchor_independence_verified = false
actual_external_effects_verified = false
observed_query_counts_bound_adversary = false
actual_lifetime_failure_bound = null
whole_chain_pq_qualified = false
composition_coverage_proved = false
production_activation = false
~~~

No input `verified`, `approved`, probability or activation field can override
these outputs. A source revision string, file hash or evidence label is not an
authentication of its producer or a proof that its assertion is true.

## 2. Bound before/after declarations

A proposed packet has an exact `scope` containing nonzero network, genesis and
owner identities. Both profiles name a full 40-hex source revision, policy and
roster commitments, a generation, both family descriptions, and their public
primitive identities. The current description requires ML-DSA-87 and
SLH-DSA-SHA2-256s; both require 2-of-3 approval and all three successor possession
records. Both profiles retain the AND combiner. Arbitrary successor algorithm
names are review declarations only and never select a runtime algorithm.

The successor must have a different profile ID, source revision, policy
commitment and roster commitment. Its generation advances exactly once.
The transition binds both complete profile digests, the scope digest, the
operation ID, predecessor/next heads, before/after sequence, a fresh 32-byte
nonce and the complete statement's SHA-512. The sequence advances once and the
head changes. The nonce must be absent before and present after. `inspect`
compares the statement digest against the actual supplied statement bytes.

The review digest uses the fresh namespace
`TRNM/RootMigrationReview/Binding/v1` followed by a zero byte and canonical
bounded JSON. It binds the full proposal, including every submitted history
record, before evidence references are attached. Every evidence reference
carries this exact digest. Changing an operation, profile, scope or liability
therefore invalidates the earlier reference binding unless that review packet
is explicitly rebuilt. This is an input-consistency property, not an
unforgeability statement: the review digest has no independent signer.

Actual source ancestry and complete build/dependency closure are not verified
by these revision strings. The checker does not decode a native signed
envelope and prove that its embedded statement equals these declarations.
The future migration implementation must make that check with the actual
current owner, complete native verifier and trusted currentness boundary.

## 3. Continuity checks that cannot be skipped

Each before/after snapshot carries the same explicit lifetime ID. The packet
retains every previously submitted key/role/generation record unchanged and
refuses future generations. A key identity has one suite label throughout the
submitted population. Root approval and successor possession may share their
intended keys; writer, anchor and provider roles cannot reuse another role's
retained key identity.

The current and successor root populations each contain exactly six distinct
keys, three for each declared family. Six separate successor-possession
records must name those exact six successor keys and suites. They are
**declarations about required possession material**, not successful possession
checks. The separate required material artifact must also exist; this reader
does not validate six signatures inside it.

Consumed nonces and revoked identities cannot disappear. A successor cannot
use a retained revoked key or an isolated writer/anchor/provider key. Every
submitted external-effect record retains its original operation, intent,
owner, orphan epoch, outcome and liability digest. In particular, an Unknown
outcome cannot become succeeded merely because a migration was proposed.
Actual reconciliation or compensation must be a separate authenticated owner
transition and must be captured in a subsequent, consistently frozen packet.
This review does not perform that transition.

The primitive inventory after migration is the exact union of the current
and successor profiles' primitive identities. Removing an algorithm does not
remove the prior primitive's history. Every existing public primitive keeps
its scope ID, its recorded observed query count cannot decrease, and duplicate
public identities cannot create separate scopes. Online, offline,
preprocessing, failed, cancelled, unpublished, recursive, helper, all-epoch
and surviving-retired-authority channels remain explicit.

Observed counts remain observations. Both adversary query and initial-advice
bounds must remain `null`; even a supplied zero is refused. No theorem turns
these local counts into adversary limits. The checker reports the roles for
which records were submitted and marks the inventory
`submitted-records-only-completeness-unverified`. It cannot discover omitted
keys, epochs, prior activity or missing role cohorts, and never labels this
declaration a complete lifetime population.

## 4. Required actual material inputs

A proposed packet must reference each of the following nonempty files:

| Material kind | Material to collect for a real proposal |
| --- | --- |
| `transition-statement` | Complete canonical statement bytes |
| `current-authority-envelope` | Actual complete old-authority authorization envelope, including both required families |
| `successor-possession-material` | Actual possession material for all six named successor keys |
| `transition-implementation` | Exact candidate source/build and explicit state/wire/profile migration description |
| `history-continuity` | Original owner records needed to verify nonce, revocation, key/epoch and liability continuity |
| `fresh-anchor` | Authenticated currentness evidence retained outside the relevant rollback domain |
| `effect-reconciliation` | Original provider/owner evidence for entered, Unknown and orphaned outcomes |
| `new-profile-security-reduction` | The proposed replacement's precise game, parameters, resource transformation and concrete security analysis |
| `shared-oracle-composition` | Full shared-primitive, preprocessing, lifetime and bad-event composition analysis |

Each record carries the exact evidence schema, kind, full proposal digest and
a material reference consisting of a safe relative path, nonzero SHA-512 and
bounded positive byte length. Missing kinds, detached bindings, empty material,
changed bytes, symlinks, unsafe paths and ambiguous JSON are refused. The reader
checks file bytes with the existing descriptor-bound source reader. This is
not an atomic snapshot of an external system and is not independent custody.

The checker requires material to be supplied; it cannot decide whether prose
contains a correct theorem or whether an envelope contains valid signatures.
Supplying arbitrary bytes can satisfy material presence, but cannot change the
unverified and unauthorized result. A future verified migration needs a
separate native protocol and review of its actual safety argument.

## 5. Commands and retained limits

Run from the repository root:

~~~sh
python3 scripts/ci/pq_root_migration_review_v1.py
python3 scripts/ci/test_pq_root_migration_review_v1.py
~~~

To review an explicitly prepared packet, use `--manifest path/to/packet.json`
under the selected `--root`. The tool never generates a proposal or repairs a
failing packet. The default no-proposal state and a matching complete material
packet both return zero with HOLD. A malformed or incomplete proposed packet
returns exit two with a structured `REFUSE` result. Neither exit zero nor
material completeness is permission to activate a replacement.

The [tests](../../scripts/ci/test_pq_root_migration_review_v1.py) check distinct
profiles, both family requirements, exact generations and sequences, six-key
population/possession declarations, retained history and effects, shared-query
continuity, material byte binding, malformed input and persistent non-promotion.
They do not execute an algorithm migration, authenticate an independent
operator, estimate the eight domain errors, or close the native M15 handoff.
