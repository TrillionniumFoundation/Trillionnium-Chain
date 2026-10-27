# Native ML-DSA-65 authorization increment

This increment continues the existing TPQ1 research wire on the current native
integration candidate. It adds actual cryptographic verification and an explicit
durable local operation owner. It does not activate a new chain or replace the
installed PNX1, transport, governance or Hepta authorization profiles.

## Exact source and algorithm

The TPQ1 syntax/SPKI preflight is imported from commit
`8d29130ecf5124d21449f0f1d549aacc27de99ad`, then formatted. Its wire remains
176 unsigned bytes, a two-byte signature length and 3,309 signature bytes. The
public key is the exact 1,974-byte ML-DSA-65 DER SPKI with no alternate algorithm,
optional DER parameters, appended bytes or permissive re-encoding.

The new M01 owner pins `ml-dsa = 0.1.1`, with default features disabled and `alloc`
enabled. `verify_ml_dsa_65` executes pure FIPS 204 verification with an explicit
context. `verify_tpq1` pins the empty FIPS context used by the independent TPQ1
OpenSSL oracle, checks all caller expectations, then verifies the real signature.
There is no external Boolean, subprocess result, Ed25519 fallback, or syntax-only
conversion to `SignatureCheckedPqFrame`.

The caller must independently pin the actual SPKI and authorization scope.
Signature validity under a key supplied by an attacker does not authorize that
attacker. The checked result grants no `VerifiedWork`, release, model-quality or
installation capability and consumes no nonce by itself.

## Durable local owner

`trnm-pon-node::pq_authority::PqAuthorizationOwner` is an explicit, separate local
owner. It commits a versioned policy digest covering purpose, network, owner
context, generation, maximum future lifetime and the complete pinned SPKI.
It refuses an unrelated existing SQLite database or a changed policy. Requests
are capped at one MiB of payload, the exact TPQ1 frame size and a policy lifetime
of at most one hour.

The owner obtains the next sequence from durable state and verifies the signature
before opening an immediate write transaction. The transaction compare-and-swaps
the old sequence and appends the exact signed statement and its SHA-384 digest.
Both writes commit together. Invalid signatures, wrong payloads, stale sequences,
expired messages and failed inserts cannot consume a new sequence. Two valid
randomized signatures for one statement remain the same operation. Local history
is not part of a reversible chain-state transition.

The returned record proves only that this local owner recorded a signature-checked
operation. It does not claim that an external effect executed, and is not a
replacement for the effect owner's atomic execution/recovery protocol. This
module is not installed by the ordinary legacy `Node` constructor or public
transport. The test uses real SQLite I/O but does not qualify the repository's
separate physical I/O boundary, power-loss recovery or physical rollback resistance.

## Independent verification material

The committed corpus is C2SP Wycheproof's complete ML-DSA-65 verification file at
commit `d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9`, containing 210 test cases.
The native test checks all results, including duplicate/noncanonical hints,
context handling, length and norm boundaries. The duplicate-hint regression is
particularly relevant to advisory GHSA-5x2r-hc65-25f9, which affected releases up
to 0.1.0-rc.3 and was patched starting with 0.1.0-rc.4.

Separate fixtures were signed and verified with Python cryptography 50.0.2's
OpenSSL-backed ML-DSA implementation. Fixture provenance records the actual
OpenSSL version, public test seed and SHA-256 of each committed input. These are
deliberately public test keys, never deployment or operator keys. Native tests
exercise exact-statement mutations, key substitution, signature corruption,
classical downgrade attempts and nonempty-context substitution.

The local-owner tests additionally cover three sequential signed operations,
reopening, randomized-signature replay, competing connections, changed scope,
unrelated databases and an injected insert failure inside the atomic transaction.
Three authorization operations are not three model-training rounds.

## Remaining whole-system work

The upstream RustCrypto crate explicitly states that it has not been independently
audited. Passing published vectors and an independent implementation's fixtures
does not replace a cryptographic implementation audit or side-channel analysis.

The active chain still needs a separately specified genesis/profile migration,
PQ-capable transaction and packet limits, ordinary transport and governance
authorization, key custody/revocation, and actual Hepta install/final-use integration.
The current native TPQ1 helper cannot be presented as completion of those paths.

The work-proof backend requires its own complete parameter/security analysis;
hash-based proving is not automatically a quantified post-quantum security claim.
Neural lottery hardness against quantum search is also independent of signature
security. No production or whole-chain post-quantum qualification flag changes.

## Actual authorization call boundaries reviewed on 2026-10-27

The following read-only trace distinguishes actual ordinary call paths from
library components used only in tests. It is not a completed whole-repository
security audit. No new concrete TPQ1 downgrade or authorization bypass was found
in these inspected paths; this does not qualify the remaining classical paths.

| Authorization boundary | Actual current implementation and caller | Required migration owner |
| --- | --- | --- |
| TPQ1 helper | `pq_auth::verify_tpq1` is called by `pq_authority::PqAuthorizationOwner::record_authorization`; that owner's current callers are its tests. It verifies ML-DSA-65 and returns errors without a classical fallback. | Each eventual effect owner must adopt the explicit new profile while retaining scope, generation, revocation, replay and atomic effect rules. |
| Ordinary PNX1 transactions | `trnm-protocol/src/pon_wire.rs::Envelope` retains a 32-byte sender and 64-byte signature. `trnm-pon-node/src/store/mempool.rs::SignedAdmissionHooks::verify_signature` reaches `pon_executor::validate_main_envelope`; `trnm-mvcc-fee/src/pon_executor.rs::prepare` executes Ed25519 `verify_hex_strict`. Secondary quota/use authorization also calls that primitive. | Wire/account identity, M05 admission, M06 execution and secondary consumer/service authorization. Migrating only the main envelope is incomplete. |
| Authenticated and public transport | `trnm-pon-node/src/ingress.rs` signs and verifies Ed25519 identities. The actual `trnm-pon-node/src/ingress/public_v3.rs` service loop verifies caller signatures; `validate_response_context` and `validate_challenge_context` verify the fixed server. Public bootstrap uses this same path. | Caller/server keys, request/cookie/response domains, generation/replay and frame limits. Removing extra hashcash does not change signatures; ML-DSA authentication is not ML-KEM encryption. |
| Task source and optional operator policy | `trnm-crypto-primitives/src/qualified_work_task/lifecycle_v2.rs::verify_lifecycle_statement` verifies an Ed25519 source signature and is called by M06 lifecycle and Node CLI. `trnm-pon-node/src/operator_task_policy.rs::authenticate` verifies registry/task signatures and is called by explicitly configured store open/refresh paths. | Source/lease and configured operator owners, preserving lease scope, withdrawal and high-water marks. A local operator policy remains distinct from permissionless PoN consensus. |
| Cell provider discovery | `trnm-data-availability/src/cell/discovery.rs::CellProviderRecordV1::verify_signature` verifies Ed25519; `trnm-data-availability/src/cell/discovery/transport.rs` actually decodes and verifies before `directory.accept_verified`. | Advertisement identity, sequence/equivocation history and discovery wire. Content hashes do not authenticate a provider or establish storage availability/model-use authority. |
| Governance and upgrade | `trnm-governance-guard/src/lib.rs::GovernanceGuard` compares an externally supplied caller with admin/role sets. The inspected instantiations are component tests; no ordinary Node authorization entry was found. | Establish the actual effect entry, independently fixed identity, profile/epoch, timelock and durable replay. A string parameter alone is not evidence of a reachable network spoofing vulnerability. |
| Hepta handoff | `trnm-research-protocol/src/hepta_handoff.rs::SignedHeptaAdmissionV1` verifies Ed25519, then independently fixed authority role and external context. Current uses found were definitions/exports and protocol tests, not ordinary Node final adoption. | Handoff trust pins and actual installer/CURRENT/runtime owners. A PQ signature still cannot substitute for product qualification, latest withdrawal checks or the final-use operation journal. |
| Release-finality component | `trnm-pon-node/src/release_finality.rs::verify_certificate` verifies classical signed votes under externally fixed context. No nondefinition Node caller was found. Its result explicitly grants no model-quality, availability, final-use or production capability. | Any legitimate consumer must retain those nonauthorizing boundaries. This component is not adopted as a committee replacement for pure PoN. |

All paths above are relative to `trillionnium/crates/`; function/module names
identify the actual source seam. The shared native `verify_hex_strict` in
`trnm-crypto-primitives/src/lib.rs` calls
`ed25519_dalek::VerifyingKey::verify_strict`. The inspected ordinary paths did
not establish an ECDSA/secp256k1 dependency, so they must not be described as one.
The complete-chain conclusion remains **not post-quantum qualified**.

## Separate the four quantum-security claims

The next profile needs four independently reviewable claims, with a declared
adversary budget and failure probability. No one claim substitutes for another.

| Claim | Exact obligation |
| --- | --- |
| Native authorization | Every reachable transaction, transport, task, provider, install and final-use owner authenticates its intended message under an independently fixed PQ key, preserves generation/revocation/replay, and rejects classical downgrade. FIPS 204 standardizes ML-DSA; it does not certify this entire application or its key custody. |
| Computation-proof soundness | Pin the concrete commitment/hash, field and challenge extensions, polynomial degrees, query counts, all segment/round composition and adaptive Fiat-Shamir/QROM assumptions. Use the actual receipt dimensions. The retained upstream conditional estimates are not quantum security bits. |
| Hash commitments | Inventory the exact domain, algorithm, output width, input choice and consumer. Distinguish an independently fixed content root from an adversary who chooses both committed messages. Include multi-target and lifetime composition rather than assuming every 256-bit digest has the same claim. |
| PoN mining and chain selection | Model the cost of a reversible oracle for the full challenge/noise/trace/ticket predicate, coherent query depth, memory, parent changes, parallelism and the adversarial fraction of effective successful work. PQ signatures and proof soundness do not rule out a mining advantage. |

For orientation only, ideal black-box search for a fraction p of marked items
has the familiar order `1/sqrt(p)` quantum-query scale rather than `1/p`
classical trials [5]. A W1 mining oracle would need to implement and uncompute
the complete W1 predicate; replacing it with a bare SHA call is not a cost
estimate. This observation neither supplies such an implementation nor measures
an attack on this chain. Difficulty adjustment does not by itself remove a
relative hardware/oracle advantage or prove an honest-work majority.

Likewise, the ideal quantum collision algorithm in [6] has a cube-root query
scale and an associated space/time tradeoff. An ideal n-bit hash gives the
usual generic screening exponents n/2 for targeted search and n/3 for collision
search; for n=256 those are 128 and about 85.3. These are oracle-model screens,
not practical attack costs, a full SHA-256 reduction, or a reason to call every
SHA-256 use a broken authorization path. In this source, TPQ1 payload and durable
policy/statement commitments use SHA-384, while its 32-byte key identifier uses
SHA-256. The verifier still requires the independently pinned complete SPKI;
an arbitrary colliding key identifier alone is not permission to replace that
key. TCM1 content checks and W1 trace/ticket bindings have different consumers
and must be analyzed on their own terms.

If the new commitment profile aims at a 128-bit generic quantum collision
screen, a 384-bit hash output is a candidate, with its complete construction,
composition and cost still subject to review. Replacing an existing 32-byte
field silently changes IDs, manifests, signed domains, Merkle roots and proof
parameters. Such a migration needs versioned encodings and exact cross-profile
refusal; this note changes none of them.

An actual authorization migration must bind new PQ ownership while the old
authorization is still trustworthy, or start from an independently authorized
new genesis/profile. After a classical signature scheme is assumed forgeable,
another signature in that scheme cannot establish which PQ replacement key is
the rightful owner's. Preserve the original effect owner and pending-operation
reconciliation; a new key registry or successful TPQ1 helper call does not grant
installation authority. The pure-PoN fork-choice rule stays unchanged.

## Primary references

- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
- [RustCrypto ML-DSA 0.1.1](https://docs.rs/ml-dsa/0.1.1/ml_dsa/)
- [Duplicate-hint advisory](https://github.com/RustCrypto/signatures/security/advisories/GHSA-5x2r-hc65-25f9)
- [Pinned Wycheproof corpus](https://github.com/C2SP/wycheproof/blob/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/mldsa_65_verify_test.json)
- [5: Tight bounds on quantum searching](https://arxiv.org/abs/quant-ph/9605034)
- [6: Quantum Algorithm for the Collision Problem](https://arxiv.org/abs/quant-ph/9705002)
