# V3 root signature cost and retained public-key expansion

Status: **HOLD / RESEARCH ONLY**. This continuation improves a reusable
cryptographic component and makes its cost scope explicit. It does not activate
a protected profile, migrate main, or establish whole-chain PQ security.

## Source and authority boundary

The [V3 crypto component](../../trillionnium/crates/trnm-crypto-primitives/src/pq_root_v3.rs)
requires **ML-DSA-87 2-of-3 AND SLH-DSA-SHA2-256s 2-of-3**. Every successful
quorum call still verifies four distinct signatures against the complete fixed
roster. The [native root owner](PQ_ROOT_RECOVERY_NATIVE_V3.md),
[recovery floor](PQ_ROOT_RECOVERY_FLOOR_V4.md) and
[provider readback](PQ_ROOT_EFFECT_READBACK_NATIVE_V4.md) retain their own
current-authority, history, original-budget and external-effect boundaries.

The observed main revision `dd6e1c3cbeacbdc532b0679297835b3a0aac78f0` still uses
[Ed25519 primitives](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/dd6e1c3cbeacbdc532b0679297835b3a0aac78f0/trillionnium/crates/trnm-crypto-primitives/src/lib.rs).
Candidate native PQ code is not evidence that production main has migrated.
Recheck that revision when making a later branch-status claim.

## What is retained

`DualFamilyRosterV3` owns a private, immutable, canonically ordered six-key
roster. With `pq-native-openssl`, it has exactly three lazy slots for successful
RustCrypto ML-DSA-87 public-key expansion, one for each member of that family.
Each slot is bound to its full canonical SPKI and position in this roster;
callers cannot supply an alternate key or mutate the slot's roster identity.

The slots are shared by `Arc` across clones of the same roster. A newly decoded
roster starts cold, including when its encoded bytes equal an earlier roster.
Encoding, semantic equality, roster commitments and signed domains depend on
the canonical public material, never on whether expansion has occurred.
No cache entry is serialized or restored as evidence of current authority.

Expansion remains lazy. Construction and decoding do not move its arithmetic
ahead of the caller's reservation or deadline checks. Retaining a successfully
expanded public key does not retain any prior signature result. Concurrent
first use may perform redundant temporary expansion before one slot is filled;
the three retained slots are not a single-flight or total-allocation guarantee.
SLH-DSA verification still imports and checks its native provider key on every
call. This change does not introduce a retained OpenSSL-provider key cache.

## Checks and costs that remain on every call

`verify_quorum` reserves four attempts and the original bounded input-byte
charge before native arithmetic. `verify_possessions` reserves six attempts;
a caller combining them must carry the same original budget through both.
Cancellation, the absolute deadline and cumulative charges remain observable
on cache hits. Rejected signatures do not refund those reservations.

Acceptance still requires message bounds, exact signature sizes, signer identity,
distinctness, the fixed family counts and every required mathematical signature.
Rejection may terminate early under the original unreduced reservation.
Deadline checks continue around each native call; an already running native
call is not made preemptible by public-key caching. The library/provider build
and configuration remain explicit trusted execution inputs.

The application owner still constructs the expected complete statement and
checks scope, current policy, generation, sequence, nonce, expiry, revocation
and fresh retained history. A cache hit does not authorize release, installation,
payment, an API call or FinalUse. It cannot certify independent custody or
make a restored old owner/anchor state current.

## Signature bytes are not a complete operation frame

[FIPS 204, Table 2](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
specifies ML-DSA sizes; [FIPS 205, Table 2](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf)
specifies SLH-DSA sizes. These are raw algorithm encodings, before this
protocol's key identities, DER SPKI, statement and envelope framing.

| Algorithm | Raw public key bytes | Raw signature bytes |
| --- | ---: | ---: |
| ML-DSA-65, existing Cell release profile | 1,952 | 3,309 |
| ML-DSA-87, root family | 2,592 | 4,627 |
| SLH-DSA-SHA2-256s, root family | 64 | 29,792 |

| V3 mathematical obligation | Signature count | Signature-only bytes |
| --- | ---: | ---: |
| Current root quorum: two signatures from each family | 4 | 68,838 |
| Successor possession: all three keys from each family | 6 | 103,257 |
| Current quorum plus all successor possessions | 10 | 172,095 |

The last row applies when the operation requires a successor roster; ordinary
approval alone does not acquire six additional possession signatures. The
four-signature figure must not be reported as a complete rotation-frame size.
Each ML-DSA-87 canonical SPKI is 2,614 bytes and each SLH-DSA canonical SPKI is
82 bytes. The complete six-key SPKI material therefore contributes 8,088 bytes,
before roster framing. Actual operation envelopes also carry statements,
signer identities and other protocol material. Their complete size must be
measured from their own canonical codec.

## Existing Cell path remains a separate workload

The [Cell PQ release path](../../trillionnium/crates/trnm-data-availability/src/cell/pq.rs)
already retains pinned `Arc<PqNativeVerifier>` ML-DSA-65 verifiers. It signs a
complete manifest once and verifies downloaded content through chunk digests;
current key lifetime, generation and revocation checks remain required.
The [ML-DSA-65 verifier](../../trillionnium/crates/trnm-crypto-primitives/src/pq_auth.rs)
already retains expanded mathematical key material.

This continuation therefore does not claim that each previous Cell hot read
paid the dual-family root quorum, or that it removes such a cost. Root authority,
release verification, content verification and actual loading have different
owners and must be measured through their real call paths.

## Bounded cost observation

The [native observation example](../../trillionnium/crates/trnm-crypto-primitives/examples/pq_root_v3_cost_observation.rs)
compares A, a fresh roster decode plus full quorum verification, with B, full
quorum verification using a retained roster. Both arms perform all four
signature checks and reserve the same four-attempt/input-byte budget.
After separately reported warmups, each measured block uses A-B-B-A order.
Fresh ephemeral key generation, signing, public fixtures and raw sample timings
are reported separately; no secret key or seed is emitted.

The example also observes four current approvals followed by six successor
possessions under one ten-attempt budget. Its complete statement is synthetic;
it does not execute a root-owner state transition or replay durable history.
The existing current roster has already been exercised by the earlier samples,
while the successor roster has not been verified by the V3 API before this step.

These are local component observations from one repeated public fixture.
They do not measure Cell reads, Node service, owner replay, complete transition
latency, network transport or system throughput. A small sample median does
not establish a population tail, acceptance threshold or deployment gain.
Retain the exact source, binary, locked graph, toolchain, provider, host load,
command and terminal exit alongside any later numbers. This document records
the measurement contract; it does not assert an unexecuted timing result.

## Qualification that remains open

The [dependency register](PQ_ROOT_DEPENDENCY_REGISTER_V3.md) retains
`whole_chain_pq_qualified=false`, `composition_coverage_proved=false` and
`production_activation=false`; all eight actual domain bounds remain `null`.
Standard algorithms and passing component tests cannot replace evidence for
independent custody, fresh state surviving common restoration, actual external
effects, explicit algorithm migration, complete lifetime populations or the
shared-adversary and QROM composition obligations. Those gates remain HOLD.
