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

The timeout-only bridge uses the additional semantic CAS operation. It stores
`(epoch, view, Safety revision)` in a separately locked, fixed-record,
hash-chained sidecar and rejects lower rounds or non-increasing revisions even
after the authority process restarts. The main watermark log and semantic
sidecar must advance together; a crash between their durable writes leaves
unequal lengths and is a startup fail-stop, never an inferred repair.

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

`ReplayBoundTimeoutProducer` adds the missing producer-response boundary for
the narrow slice. It records `(intent fingerprint, signer profile, signing
root, signature)` in a second append-only hash-chain log with its own lock and
durable head anchor. After a producer response is returned, a restart can
replay that exact response without calling the producer again; a duplicate
fingerprint with a different binding, partial tail, or anchor-ahead rollback
fails closed. The response log is still test infrastructure: it is not a key
store, HSM, SafetyRules authorization, or Core admission path. It does not
claim whole-node clone/rollback detection; that remains an external watermark
and future host-fencing responsibility.

The executable refuses the legacy opaque mode unless the caller supplies the
explicit `--fixture-opaque` marker.  This keeps an old supervisor command from
silently starting an authority without the semantic scope/journal/capability
binding required by the timeout bridge.  A production-shaped invocation is:

```text
trnm-external-watermark-v0 semantic \
  --socket /private/run/trnm/ew.sock \
  --log /private/run/trnm/ew.log \
  --scope HEX32 --journal-id HEX32 --capability HEX32
```

The opaque path is test-only and must be explicit:

```text
trnm-external-watermark-v0 opaque --fixture-opaque \
  --socket /tmp/trnm-fixture.sock --log /tmp/trnm-fixture.log
```

The black-box tests exercise two independent processes, restart, stale CAS,
partial-tail and byte-tamper fail-stop, local signer DB rollback while the
external head is ahead, producer ordering, durable response replay after a
fresh adapter owner, and response-log rollback fail-stop.
