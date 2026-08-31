# Whole-node checkpoint types v1

This crate freezes an inert, `no_std`, data-only record for a future phased
whole-node checkpoint. It carries one cumulative cut across Chain, process and
lease fences, role bindings, Core Safety, Application, application attestor,
remote SafetyRules, signer journal, and the current vote/timeout operation.
The Application cut separately retains a validation-lineage watermark across
TimeoutVote cycles: store scope, last nonzero generation and validation ID,
record-chain checksum, and active-head checksum. A later Vote must advance the
same lineage and bind both exact predecessor heads.

The frozen phase tags are:

```text
0 Commissioned
1 AppValidated
2 SafetyPrepared
3 SignatureCommitted
4 EpochActivationPrepared
5 EpochActive
```

The full `WholeNodeCheckpointV1` schema remains signing-cycle-only: it carries
only phases 0 through 3, and its decoder rejects phase-4 or phase-5 payloads.
Its only successor edges remain
`Commissioned|SignatureCommitted -> AppValidated -> SafetyPrepared ->
SignatureCommitted`.

`WholeNodeCheckpointRefV1` is the single exported cross-crate taxonomy for
`{scope, generation, phase, predecessor checksum, checksum}`. Its fixed exact
codec is exactly 115 bytes under magic `TRNMWR01`. Every reference successor
advances the generation by exactly one and binds the predecessor checksum. Its
complete edge set is:

```text
Commissioned|SignatureCommitted|EpochActive -> AppValidated
AppValidated -> SafetyPrepared -> SignatureCommitted
Commissioned|SignatureCommitted|EpochActive -> EpochActivationPrepared
EpochActivationPrepared -> EpochActive
```

All other phase edges and every skipped phase are reserved and rejected. The
reference lets downstream data types reuse one taxonomy without inventing a
second domain. `EpochActive` is only a phase label and grants no epoch
activation authority. The reference remains data only.

`EpochActive -> AppValidated` is reference taxonomy only. Full record schema 1
cannot carry a phase-4/phase-5 predecessor or a new Chain cut, and
`post_epoch_signing_cycle_bridge` remains false. A future post-epoch signing
cycle requires a new schema and an explicit bridge; this crate does not close
that loop.

Exact full-record decoding validates bounded canonical bytes and the
domain-separated checksum, but it does not load or authenticate any referenced
store.

All values are public data. Construction, decoding, checksum agreement, and
successor shape do **not** prove application validity, SafetyRules admission,
lease ownership, durable persistence, external anti-rollback, CAS application,
or permission to use a private key. This crate intentionally contains no store,
CAS trait, producer, HSM adapter, runtime hook, or committed capability. It does
not modify or reinterpret the existing Node V0 checkpoint contract.
