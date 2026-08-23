# `trnm-core-restart-v0`

This is the first runnable P0 checkpoint/restart/state-sync boundary for the
native application lane.

It does four concrete things:

1. verifies a real weighted `QuorumCertificate` (including every signature)
   against a caller-supplied validator set and verifier;
2. binds that certificate to an `ApplicationHeadV0` and an authenticated
   snapshot digest;
3. persists a successor checkpoint in an exclusive, append-only,
   SHA-256-linked log with predecessor CAS and directory/file `fsync`; and
4. replays the log on restart, returning `Ready` only when the exact snapshot
   is present. A missing snapshot returns `NeedsStateSync`; malformed,
   truncated, reordered, or modified records fail closed.

`StateSyncBundleV0` installs only the snapshot for an already admitted
checkpoint and checks checkpoint hash, state-root binding, and snapshot digest.
The caller remains responsible for the application/JMT proof that produced
the state-root attestation.

Normal checkpoint admission is deliberately same-epoch only. A caller cannot
advance the log into a new epoch until an authenticated epoch-anchor/joint-
handoff witness is added to the API; cross-epoch transition is therefore
fail-closed rather than inferred from a higher height or a changed validator
set.

This is intentionally not a complete node. It does not implement a three-chain
`FinalityProofV0`, Core/SafetyRules transitions, signer or HSM access, host
attestation, consensus transport, epoch activation, or validator runtime.
Those boundaries are explicit in the package metadata and all production and
activation flags remain `false`. A node integration must pass a strict
Ed25519 verifier, connect the retained checkpoint to live Core/SafetyStore
state, and add crash/power-loss and multi-node evidence before any network
signing gate can open.

Focused tests cover:

- signed weighted-QC admission, durable commit, restart readback, and QC
  re-verification;
- missing-state recovery and exact state-sync import; and
- stale CAS, truncated log, and checksum tampering fail-closed behavior; and
- a child-process abort immediately after a durable commit, followed by parent
  reopen and strict QC re-verification (`tests/process_crash_reopen.rs`).

The process-boundary test is evidence for this checkpoint store only. It does
not imply that `trnm-poco-node` has a live Core/SafetyRules restart owner,
external signer, or validator transport.
