# TRNM Unix remote-signer client adapter (P0 slice)

This crate is a standalone, blocking Unix-domain client for the existing
`trnm-consensus-remote-signer-protocol` v1 envelope. It implements the
`trnm-consensus-signer-journal::SignatureProducerV0` seam without depending on
`trnm-poco-node`, so a host process can compose it with a journal without a
crate cycle.

The client performs the following checks before returning a signature:

* private Unix socket shape/permission preflight and bounded read/write
  timeouts;
* a four-byte big-endian length prefix with a strict request/response bound;
* exact protocol decoding, request-fingerprint/nonce/epoch/validator/purpose
  binding checks, and strict Ed25519 verification against the configured
  validator public key.

Malformed frames, cross-request response replays, binding mutations, invalid
signatures, timeouts, and transport failures are fail-closed. A deterministic
nonce is derived from the exact sign-intent fingerprint so a journal retry can
receive the same response from an idempotent service.

This is an adapter seam, not a complete signer authority. It does not own an
HSM/KMS, external monotonic watermark, SafetyRules/locked-QC admission,
process-generation fencing, host attestation, key rotation, or consensus
runtime activation. All production and activation metadata remain `false`.
The test-only subprocess server is available only with the `test-fixture`
feature; its deterministic private key must never be used as a deployment
credential.

The adapter has not been wired into the normal node runtime. A caller must
first compose it behind the signer journal and independently prove Core,
SafetyState, external watermark, and process-fence reconciliation.
