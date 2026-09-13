# TaskV1 archive admission contract v1

Primary module: M10. Consumers: archive exporters, proof producers and verifiers.
Status: candidate technical contract; no storage-deletion or activation authority.
The only execution plan remains
[Plan v2](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
The module entry remains the
[M10 technical reference](../modules/TRNM_MODULE_TECHNICAL_REFERENCE_V1.md).

## Owned decision and interface

`TaskArchiveBatchV1::validate(policy)` validates a complete candidate batch.
`TaskArchiveBatchV1::inclusion_proof(policy, task_id)` first performs the same
validation, then returns a proof for the unique task. The public
`verify_task_archive_batch_v1` wrapper independently retains its expiry check.
`verify_task_archive_inclusion_v1` proves one record against its supplied seal;
it does not establish full-batch uniqueness or accept an external hold registry.

The field encodings, hash domains, schema version and public signatures remain
unchanged. Validation has no durable write set. Rejected inputs cannot grant a
pruning permit, mutate a store, mint finality, or authorize deletion.

## Invariants and failure behavior

A prepaid retention height is inclusive. A record is admissible only when the
seal archive height is at least `retention_paid_through_height + 1`, computed
with checked arithmetic. Exact expiry is rejected with `InvalidState`. A paid
height of `u64::MAX` has no representable first-prunable height and is rejected
with `ArithmeticOverflow`; it never wraps to zero.

Task identity must be unique throughout the batch, not merely at each terminal
height. Two records with the same task ID are rejected with `NonCanonical` even
when their heights differ, their sort order is valid, and every root/range/charge
has been recomputed consistently. The uniqueness set is populated only after the
existing policy count limit, including the hard 4,096-record bound, passes.

Existing context, version, count, byte, minimum retention, prepaid charge,
canonical ordering, aggregate totals, Merkle root and seal range checks remain
mandatory. A valid root proves committed bytes, not their admissibility.
The planner additionally honors its explicit legal-hold set and live capacity
bounds; a supplied proof alone cannot establish those external obligations.

## Retained regression contract

`archive::tests::direct_batch_and_proof_admission_enforce_inclusive_retention`
uses a valid planner batch, holds its root fixed, rejects every early archive
height, and accepts the first height at which all records are eligible.

`archive::tests::duplicate_task_id_at_distinct_heights_is_rejected_with_a_matching_root`
rebinds the root and range after identity duplication. Direct admission, proof
production and public batch verification must all reject the mutant.

`archive::tests::maximum_prepaid_height_never_wraps_into_archive_eligibility`
accepts the maximum representable first-prunable height before rejecting a
one-height extension whose expiry cannot be represented.

The existing public-wrapper retention mutant retains its positive control and
now also requires direct validation and proof construction to reject early
archiving. Existing archive, market, wire and consumer regressions remain.

```bash
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-poco-agent-market-v1 --all-targets --locked
```

These tests establish only their exercised source-local invariants. Independent
review, exact-source consumer replay, real scale/retention campaigns, authoritative
hold ingestion and storage-deletion qualification remain separate acceptance.
