# X230 authenticated P2P admission observation — 2026-08-23

This is a bounded, admission-only observation for the current canonical
candidate.  It proves that the P2P admission helper can be rebuilt and its
local Rust tests can run on the X230 self-hosted host.  It does **not** start a
validator, send consensus payloads, establish a consensus transport, or
provide Stage0 seven-validator evidence.

## Candidate and transport binding

```text
source_commit:       136117b454b6f442671025b6ed931fb41f575282
source_git_tree:     af24d044ef94d39b4af81f12d863f3b42ab003a7
trillionnium/Cargo.lock_sha256:
  72e254afa47d8b92fe8803b35869990bcfaa7f8106d9f0d4ecb45d127fbe150b
source_archive_sha256:
  3567c3d0259019f8eb40ac78efd1dc660b31c48d1a86c8c042bd2d4f1bdb5cb8
transport:             manual SSH via p4-x230
host:                  qian-ThinkPad-X230
toolchain:             rustc 1.95.0 (59807616e 2026-04-14)
                         cargo 1.95.0 (f2d3ce0bd 2026-03-21)
test_log_sha256:
  a85520b295aa205d7278b07cc8754c4f1516caf48018bac8832bc794442bd6e  
```

The source archive was made from a clean Git worktree with
`git archive --format=tar.gz --prefix=trillionnium-chain/ HEAD`.  The archive
hash was checked locally and again after transfer to X230.

## Command and result

The remote command used the prepared offline Cargo cache and did not copy a
validator binary, key, or deployment secret:

```text
timeout 300s cargo test --locked -p trnm-poco-lab-validator p2p_admission
```

Result: **3 passed, 0 failed**.  The passing tests covered exact epoch and
validator-set binding, nonce/session replay fencing, and bounded lease
generation cleanup/rebind.  The complete stdout is retained by the operator
under the content hash above.

## Truth boundary

The observation intentionally leaves these facts false:

```toml
consensus_transport = false
host_attestation = false
multihost_observed = false
validator_runtime_started = false
validator_run_completed = false
validator_run_7_completed = false
production_activation = false
```

The helper's lease and replay state is process-local and non-persistent.  An
external monotonic fencing authority, rollback-resistant signer journal,
host credential/attestation, validator-loop integration, and crash/restart
campaign are still required before any four- or seven-validator run is
admissible.

