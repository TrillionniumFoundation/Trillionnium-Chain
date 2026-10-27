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

## Primary references

- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
- [RustCrypto ML-DSA 0.1.1](https://docs.rs/ml-dsa/0.1.1/ml_dsa/)
- [Duplicate-hint advisory](https://github.com/RustCrypto/signatures/security/advisories/GHSA-5x2r-hc65-25f9)
- [Pinned Wycheproof corpus](https://github.com/C2SP/wycheproof/blob/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/mldsa_65_verify_test.json)
