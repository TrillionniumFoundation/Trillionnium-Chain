# Storage boundary follow-up

This continues the existing [sole plan](../../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and [model storage contract](../../../docs/development/specs/pon/CELL_MODEL_STORAGE_V1.md)
on integration source `a9b8602706b66adba82655c3c2ce90bde88620a2`, tree
`2f7e0eb7bf56d9bc4154177018764218ae3b3f31`. It preserves the preceding
[source-bound storage observations](../README.md), including the previously
unexecuted late Node composition checks and resource failures.

## Changes to verify

- Tensor entries require named JSON objects. Positional arrays cannot satisfy
  the exact safetensors metadata profile even when their complete payload hash
  and declared tensor values match. Field order remains free; duplicate, unknown,
  missing and incorrectly typed fields still reject.
- Persistent serving stops connection/frame admission after actual response
  bytes exhaust the original quota. Temporary reservations remain refundable;
  admitted workers keep their original deadlines and accounting. Availability
  manifest reads inherit the same original request deadline.
- New release intents reject permanent aligned-capacity, record-history and
  retired/funding-identity contradictions before leaving a pending root. Existing
  partial or impossible pending history remains readable and protects the complete
  closure. Real physical-writer contention still leaves a recoverable intent.
- Node paid storage rejects already expired requests before opening budgets and
  uses the original deadline for M09 physical writer acquisition and readback.
  Exact original claims/effects remain charged on uncertain outcomes and are
  reconciled without redispatch. M12's internal SQLite calls remain cooperative;
  this does not claim every journal wait has a hard wall-time bound.

## Counterexample source

The isolated test-only commit
[`8992e87ab14d6905303b9a813656a591621a49bd`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/8992e87ab14d6905303b9a813656a591621a49bd)
keeps the old parser and adds the exact complete-container regression
`cell::tensor_tests::tensor_entry_sequence_cannot_replace_required_named_object`.
Each hostile container is independently repinned to its actual bytes. The
F32/F16/BF16 examples are assertions within one test, not three separate tests.
This counterexample source is not an accepted implementation candidate.

The frozen-source command receipts and their actual execution verdicts are
recorded after the corresponding runs. Source review or successful compilation
alone is not a passing native test, independently funded retention, public-WAN
qualification, selected model installation or CURRENT/FinalUse acceptance.
