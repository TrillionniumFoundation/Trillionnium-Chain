# External watermark authority — P0 timeout slice

This crate is the first executable cross-process boundary for the signer plan.
`trnm-external-watermark-v0` owns a private Unix socket and a separate
append-only, fixed-record SHA-256 hash-chain log.  A compare-and-advance request
must carry the exact prior `(scope, journal_id, sequence, chain_checksum)`;
the authority rejects stale generations, lower sequences, scope/journal forks,
replayed CAS requests, malformed frames, and any log checksum/predecessor/
truncation failure observed at restart.  Each accepted record is written,
`sync_data`'d, and followed by a directory sync before the process reports
success.

`UnixWatermarkClient` implements the existing
`ExternalMonotonicWatermarkV0` trait.  The local signer journal therefore
remains a separate SQLite/WAL namespace: its durable intent event must advance
the external head before an injected producer is called, and its signature
event must advance it again before the response is returned.

`TimeoutOnlySignerAdapter` is intentionally the only adapter exposed here. It
rejects vote intents and is suitable for a crash/replay test harness, not for a
validator. The crate has no consensus runtime, Core/SafetyRules admission,
host attestation, HSM/KMS implementation, validator loop, or production
activation. All such metadata remains `false`; the Ed25519 key in the
integration test is fixture-only.

Example (development only):

```text
trnm-external-watermark-v0 --socket /private/run/trnm/ew.sock \
  --log /private/run/trnm/ew.log
```

The black-box tests exercise two independent processes, restart, stale CAS,
partial-tail and byte-tamper fail-stop, local signer DB rollback while the
external head is ahead, producer ordering, and exact response replay.
