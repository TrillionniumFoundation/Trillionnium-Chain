# Authenticated epoch discovery: source-bound component evidence

This continuation starts from `0dc13a92cc49e9a751a2b6cf7cc96524f1244a2a`
(Cell capability PR #807). It adds an explicit authenticated PQ V3 discovery
profile and a fresh epoch directory. The original V1/V2 implementations and
their permanent high-water semantics remain historical, callable profiles.

The [protocol contract](../../docs/development/specs/pon/CELL_PROVIDER_DISCOVERY_AUTH_PQ_V3.md)
and [five-part storage acceptance register](../../docs/development/specs/pon/CELL_STORAGE_NETWORK_ACCEPTANCE_V1.md)
describe scope. The [sole development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
remains authoritative. Operational qualification is **HOLD_NO_GO**.

## Original-source observations

| Observation | Actual result | Source boundary |
| --- | --- | --- |
| Original discovery regression suite | 52 passed, 0 failed, 0 ignored, 376 filtered | Unmodified exact `0dc13a92...` source; default features; native library selector `cell::discovery::` |
| Desired expiry-recovery red controls | 0 passed, 2 failed, 0 ignored, 428 filtered; Cargo exit 101 | Same original implementation, augmented only with two explicitly failing test modules and their registrations |

The original baseline passed locked/offline workspace metadata and ran with
Rust/Cargo 1.95.0, two build jobs, one test thread and a separate target on shared
Linux x86_64. Full [baseline stdout](baseline/native.stdout.log),
[stderr](baseline/native.stderr.log) and [command summary](baseline/summary.json)
are retained. This selected baseline is not a new complete-crate or all-feature
runtime claim.

Both red controls perform 16 independently reopened durable operations for one
manifest, each using a real valid signature. All advertisements then expire;
the observed clock advances by 601 seconds and the directory reopens. A newly
signed seventeenth identity is still rejected with `discovery identity capacity`.
The directory's explicit test clock is advanced; this is not a 601-second
elapsed-time or WAN campaign. Signatures, SQLite commits and reopen operations
are native, actual executions.
The PQ control uses seventeen real, explicitly pinned ML-DSA-65 keys. There is
no fake verifier and no large single response whose scheduling explains the
failure. The [complete red output](red-controls/native.stdout.log),
[build output](red-controls/native.stderr.log) and
[source/command/log-digest summary](red-controls/summary.json) preserve the failures.

The test sources are retained as
[classic](red-controls/classic_prior_operations_expiry_red.rs) and
[PQ](red-controls/pq_prior_operations_expiry_red.rs). They are evidence files,
not registered tests in the final green suite. To reproduce, use a separate
worktree at exact `0dc13a92...`, copy them into the respective classic/PQ discovery
module directories, add `#[cfg(all(test, unix))] mod <file_stem>;` to each parent,
and run the exact command in the red summary. This is a test-only augmentation
of the old implementation, not execution of a new V3 candidate.

## Initial staged V3 observation

The first 27-file V3 snapshot passed 53 selected native PQ discovery tests:
37 new tests and 16 retained PQ controls, with zero failures, zero ignored and
412 filtered. Native execution took 204.16 seconds; the Cargo command, including
compilation, took 243.02 seconds. Formatting and both workspace/fuzz locked,
offline dependency graphs also passed. This was a staged, source-stable smoke
run, not a frozen-commit or complete-crate qualification.

The [command summary](staged-attempt01/summary.json),
[native stdout](staged-attempt01/discovery-native.stdout.log),
[native stderr](staged-attempt01/discovery-native.stderr.log),
[before](staged-attempt01/source-before.json) and
[after](staged-attempt01/source-after.json) source fingerprints are retained.
The before/after fingerprints match exactly. The complete input bundle's SHA256
is `82e2256d1228b1baf4a07a9962587213eab7c836a9dce24ee4245e99b08b2f78`.
The [provenance record](staged-attempt01/provenance.json) lists log digests and
also preserves the expected stale source-pin refusal before refreshing pins:
`check_pq_research_integration.py` exited 1 on the changed fuzz lockfile. That
refusal is not silently replaced by the later refreshed-source result.

## Review-discovered sequence-selection red controls

Review identified a separate operation-local regression: a higher valid sequence
could disappear from candidate selection when its short lease expired during
collection, or when a full source quota refused its withdrawal. A later lower
sequence from another source could then be selected. The correction retains
the highest actually verified sequence before current-expiry and quota filtering,
without granting durable admission to a refused record or widening any budget.

The first native attempt ran three new real-TCP tests against the unchanged
initial V3 implementation (`auth.rs` SHA256
`7214ea4e588a95cb0043d750123d7ad657ed7cba275ba54f1d4e62535ce7a30b`).
It recorded 0 passed / 3 failed / 465 filtered in 24.60 seconds. Both expiry
orderings reached the intended failure: the old implementation actually selected
the older endpoint. The third test failed at its preparation assertion before
reaching the quota regression; that unexplained setup failure is retained and
is not counted as a confirmed quota reproduction. See the complete
[first stdout](sequence-red-attempt01/native.stdout.log),
[stderr](sequence-red-attempt01/native.stderr.log) and
[source/command summary](sequence-red-attempt01/summary.json).

A diagnostic-only successor kept the same implementation, original deadlines,
records and operation structure. The isolated quota test's preparation actually
completed in 3.266 seconds with two connections, 35,476 received bytes, eight
provider plus two bootstrap validations, and no capacity rejection. The next
operation then reached the intended failure: a quota-refused newer withdrawal
allowed the old endpoint. This run recorded 0 passed / 1 failed / 467 filtered
in 7.75 seconds. See the complete
[diagnostic stdout](sequence-red-attempt02/native.stdout.log),
[stderr](sequence-red-attempt02/native.stderr.log) and
[source/command summary](sequence-red-attempt02/summary.json).
Both attempts retain the complete test and pre-fix implementation bytes.

## New profile and acceptance boundary

V3 changes the signed replay namespace explicitly: fixed epochs, active/history
quota separation, bounded source shares, immutable directory pins, native
bootstrap query/reply authentication and the original aggregate Cell reservation.
It cannot be presented as an automatic repair of existing V1/V2 databases.

New verification records must identify their own frozen source and retain
complete native stdout/stderr, locked graphs, formatting, strict Clippy,
negative source/CI controls and before/after source checks. Independent unsigned
byte vectors establish encoding agreement only. They do not establish an
independent cryptographic implementation or a production security level.

Actual independent operators, shard placement/repair, funded retention,
72-hour WAN cohorts, a persistent TCV1 retained-set owner and ordinary
restricted-loader/device/Hepta next-task execution remain unqualified. Safe
bounded refusal is not service success, and neither original deadline is widened.
