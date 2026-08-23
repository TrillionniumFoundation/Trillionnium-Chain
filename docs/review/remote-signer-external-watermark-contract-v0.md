# External signer watermark contract — review artifact

Status: **tests/docs-only; not production security evidence**.

The canonical signer journal already requires an
`ExternalMonotonicWatermarkV0`, but intentionally ships no filesystem-backed
implementation. Before a remote signer can be connected to Core/SafetyRules,
the external boundary must satisfy this minimum contract:

1. Store the exact `(scope, journal_id, sequence, chain_checksum)` head outside
   the local SQLite/WAL/sidecar namespace.
2. Accept `compare_and_advance(expected, target)` only for an exact expected
   head and the next sequence; never overwrite, decrement, fork, or repair a
   missing head from local bytes.
3. Validate an append-only/hash-linked event history and fail closed on event
   rewrite, tail truncation, ahead/foreign scope, or checksum mismatch.
4. Bind the private-key request and response to the canonical intent
   fingerprint and signing root. Exact replay must return the same persisted
   signature without a second producer call.
5. Treat any mismatch as a safety halt until Core/SafetyState, validator-set
   epoch, process generation, lease, and checkpoint witness are reconciled.

`trillionnium/crates/trnm-consensus-signer-journal/tests/external_watermark_contract_v0.rs`
implements a memory-only model of these rules. It has test-only fault
injectors that rewrite and truncate a local event log while leaving a separate
committed head unchanged. The tests prove that the model rejects both faults,
that a stale target cannot advance it, that exact journal replay does not call
the producer twice, and that an external-head mismatch stops before the next
producer call.

The model is deliberately not an HSM, KMS, TPM, host service, credential
loader, or deployable anti-rollback store. It must not be moved into runtime
code or counted as remote-signer/P0 closure. A production implementation still
needs independent ownership/attestation, durable compare-and-advance, key
rotation and fencing, crash/power-loss semantics, clone/whole-node rollback
detection, and an active Core/SafetyRules integration. Activation and
production flags remain closed.

## Failure matrix

| Fault | Required result | Local SQLite CAS alone |
| --- | --- | --- |
| stale sequence/round | reject; no producer call | detects only while row is intact |
| event rewrite | reject; safety halt | `integrity_check` is insufficient |
| tail truncation / old namespace restore | reject; safety halt | can reopen a self-consistent old DB |
| external head ahead/forked | reject; reconcile | no external comparison |
| exact request replay | persisted identical response | service-local duplicate checks only |
| crash after producer signs | deterministic retry or HSM idempotency | response event is not persisted |
