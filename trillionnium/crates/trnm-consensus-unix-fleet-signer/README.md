# Unix fleet-root signer seam

## PoN target and current-source scope

This crate remains existing implementation/reference source; this documentation does
not turn it into a PoN runtime. Selected development profile: `pon-nakamoto-v1`.
Source owner: M03. Target responsibility: Mining-attempt ownership, identity custody and local fencing.
See [M03 technical contract](../../../docs/modules/M03_SAFETY_SIGNER_TECHNICAL_SPEC_V1.md) and the
[PoN protocol](../../../docs/protocol/pon-nakamoto-v1/README.md).

Reuse descriptor/nonce/fence/custody and bounded worker mechanisms where matching. Retire
SafetyRules vote locks and PoCO double-vote slashing as target requirements; retained signer
records stay historical.

## Retained implementation documentation

The source interfaces, stored formats, commands and tests below retain their actual
legacy/profile semantics. PoCO consensus is retired as the target. No old finality,
committee, vote, consumption weight or test pass is new neural-work/efficacy evidence.


`trnm-consensus-unix-fleet-signer` is a narrow, independently runnable
transport/client slice for fleet-root signatures. A request is an exact
bounded tuple:

`purpose + origin + validator-set id + signing root + caller nonce`

The purpose enum is closed and separates initial `Ready`/`Start` from
process-2 `RecoveryReady`/`RecoveryStart`; an exact signing root and nonce can
therefore never be replayed under the other lifecycle domain.

The client requires an absolute private Unix socket (socket and parent have no
group/world permissions), uses a four-byte big-endian length frame, checks the
response fingerprint/checksum, and strictly verifies the returned Ed25519
signature against the configured public key and signing root. The fixture
server returns the exact response for an exact replay and rejects a nonce
reused for a different request.

The `test-fixture` feature and `trnm-fleet-root-signer-test-fixture` binary are
test-only. The default build has no private-key API. This crate does not
provide nonce freshness, a durable watermark, lease/host admission,
Core/SafetyRules authorization, or consensus-runtime integration; all runtime
and production flags remain `false`.
