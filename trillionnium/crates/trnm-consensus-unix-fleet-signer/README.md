# Unix fleet-root signer seam

`trnm-consensus-unix-fleet-signer` is a narrow, independently runnable
transport/client slice for fleet-root signatures. A request is an exact
bounded tuple:

`purpose + origin + validator-set id + signing root + caller nonce`

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
