# TRNM consensus remote-signer protocol v1

## PoN target and current-source scope

This crate remains existing implementation/reference source; this documentation does
not turn it into a PoN runtime. Selected development profile: `pon-nakamoto-v1`.
Source owner: M01. Target responsibility: Cryptography, neural-work verification and local identity.
See [M01 technical contract](../../../docs/modules/M01_CRYPTO_IDENTITY_TECHNICAL_SPEC_V1.md) and the
[PoN protocol](../../../docs/protocol/pon-nakamoto-v1/README.md).

Keep strict signatures, identity/role separation and legacy finality verifiers as history only.
Neither StrictFinalityProof nor an accept-all test verifier can authorize a PoN block.

## Retained implementation documentation

The source interfaces, stored formats, commands and tests below retain their actual
legacy/profile semantics. PoCO consensus is retired as the target. No old finality,
committee, vote, consumption weight or test pass is new neural-work/efficacy evidence.


This crate is an inert, data-only wire candidate. It carries owned canonical
vote and timeout-vote intents plus public role/profile, process-generation,
lease, whole-node-checkpoint, and request bindings. It contains no transport,
credential, journal, monotonic store, private key, producer, or runtime.

A successfully constructed or decoded request is only an untrusted,
well-formed request. `CanonicalSignIntentV0` is publicly constructible and a
vote intent does not carry enough locked-QC/justify state to evaluate the
HotStuff safe-vote rule. Neither an arbitrary positive SafetyState revision nor
a matching generation/lease/checkpoint witness makes the request Core or
SafetyRules authority.

No future service may pass this wire request to a signature producer or key
provider until the same protected trust domain has independently admitted it
through durable SafetyRules/SafetyState, signer-journal conflict checks,
external monotonic anti-rollback state, and process-generation fencing. Those
capabilities are outside this crate and remain false production truths.

The role/service/client references and Vote/Timeout-only purpose-profile digest
are protocol-local domains. They are not the same types or digest taxonomy as
the current Node `PocoNodeRemoteSignerRoleBindingsV1`, which also covers P2P,
Proposal/Handoff, and operator purposes. They must not be compared directly or
substituted for one another. Runtime integration requires a reviewed adapter
that explicitly binds the Node role-bindings checksum, or a later shared-type
migration; this crate deliberately has no Node dependency or adapter.

Response decoding is also inert: `UnverifiedRemoteSignerResponseV1` exposes
only shape-checked, cryptographically unverified signature wire bytes. Nonce
derivation is deterministic and does not provide freshness or uniqueness; a
future durable service journal must enforce both.
