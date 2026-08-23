# D0 authenticated P2P admission helper (fixture boundary)

This branch contains an active, targeted helper around the existing signed
transport handshake.  The helper proves, in local Rust tests, both ends of a
TCP session authenticate with the configured P2P identity keys, the exact
epoch and validator-set ID are signed into the handshake context, the derived
challenge/hello nonce binding and session ID are replay-fenced, and a bounded
process-local peer lease rejects stale generations while allowing cleanup and
rebind after expiry.

The helper stops at admission.  It sends no consensus payload, does not drive
the validator event loop, does not persist consensus safety state, and does not
attest a host.  Therefore the following truth fields remain false:

```toml
consensus_transport = false
host_attestation = false
multihost_observed = false
validator_runtime_started = false
validator_run_completed = false
production_activation = false
```

The lease/replay window is process-local and non-persistent.  A production
implementation still needs an external monotonic lease/fencing authority,
append-only rollback-resistant state, host credential/attestation, and an
independent crash/restart campaign.  This document is not a seven-validator
or testnet claim.  Bind `source_commit`, Cargo.lock, binaries, and test output
in a later evidence manifest after this branch is reviewed.

