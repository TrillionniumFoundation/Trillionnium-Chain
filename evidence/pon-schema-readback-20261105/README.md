# Same-transaction schema SELECT preparation

Status: narrow local optimization, HOLD. This does not close #639, certify PQ,
change any deadline, or establish fixed-Host/public-network performance.

Starting source: `2ef9e2fa1985881721a1bff4d546a1b2bdc5ae47`.

`PostWriteReadback::current` continues to inspect the actual current database
schema on every call. Only preparation of the identical sqlite_master SELECT is
reused through the connection's existing bounded statement cache. No catalog
rows, successful validation, transaction ownership, complete-State comparison,
Host checks or authorization are cached or skipped. The writable_schema and
database_list PRAGMAs remain freshly prepared. SQLite invalidates the SELECT VM
on ordinary DDL and schema RESET; unversioned catalog edits are still read as
current rows.

Two added native tests cover repeated reads, ALTER/DROP/recreate, unversioned
rootpage changes, writable_schema refusal and RESET, temporary objects, and
ATTACH/DETACH after warming the SELECT. Existing transaction, graph, callback,
last-write and schema-tampering controls remain unchanged.

## Bounded cost observation

[schema-cost.rs](schema-cost.rs) retains both exact reader implementations.
[schema-cost.txt](schema-cost.txt) retains all eight alternating-order pairs.
[cost.json](cost.json) binds all observations and the linked rusqlite rlib.
Each batch performs 2,000 complete schema reads on a synthetic in-memory catalog
with 20 tables and 20 indexes (60 catalog rows including automatic indexes).
The median paired wall-time reduction is 12.875%; every pair is retained.

This is one local process, not a fixed-Host run or a Node throughput benchmark.
It includes the unchanged other schema checks and the returned catalog rows.
It does not measure RSS, p99, whole admission, Host cost, or a four-second
confirmation. A small SQL preparation saving cannot be extrapolated into
closing the original business gate.

Reproduce after the locked original-profile Node test build, selecting its exact
rusqlite rlib rather than an arbitrary version:

```
rustc --edition 2021 -O evidence/pon-schema-readback-20261105/schema-cost.rs \
  --extern rusqlite="$RUSQLITE_RLIB" -L dependency="$CARGO_TARGET_DIR/debug/deps" \
  -o /tmp/trnm-schema-cost
/tmp/trnm-schema-cost
```

## Original runtime observations remain failures

The independently downloaded historical fixed-Host artifact is run
41964910360, artifact 13387990434, source `47b4a62463d8e1371a175c74196d52d99c5fccb8`.
ZIP SHA256 is `5c6c65c0220b0f659bd246f0f9ef0faded4ef1a3719fc8ed4953a09f84f0542a`;
444 ZIP members passed CRC and all 443 manifested file lengths/digests matched.
Its baseline seven History imports total 24.286 seconds wall / 5.436 seconds
importer CPU. The nested 83,097 Host calls total 4.592 seconds invoking-thread
CPU; these intervals are not additive or exclusive. First confirmation is at
28.0866 seconds. This is historical source, not a result for this change.

The unchanged starting-source local original four-second/16-attacker attempt
also remains failed: independent imports returned PUBLIC_HOST_KERNEL_PARENT
because this executor exposes no fixed cgroup parent. Its safety/accounting
assertions passed, but neither phase confirmed a transaction. No cgroup check
was removed or mocked. Neither observation qualifies this optimization.

## Complete native-control counter-observation

[native-pairs.json](native-pairs.json) retains all eight alternating pairs of the
unchanged full admission/graph/reopen control, with both binary hashes and all
16 native returns (all pass). Whole-process timings on this concurrently used
cloud host are noisy and mixed: some candidate calls are slower, including two
above one second. They do not establish net Node improvement. No sample is
discarded and the standalone SQL result is not substituted for these outcomes.
Default cache capacity is unchanged; effects on other cached statements remain
part of the unqualified whole-operation cost question.

## Verification

[verification.json](verification.json) binds the changed implementation/test,
Cargo files and updated source pins. Actual native default-feature execution:
113 authenticated tests pass (2 existing ignored), including all 25 readback
controls; 202 public_v3 tests pass (1 existing ignored). These are 315 distinct
passes, not the full Node/workspace or PQ-feature runtime suite. The original
Growth parse-count failure exists on the base and belongs to a separate fix.

Strict workspace/all-target/all-feature Clippy, formatting, locked Cargo graph
(26 members / 180 packages), 43 source-negative controls, all 487 current source
pins and distributed inventory pass. Clippy used installed OpenSSL 3.5.7 and
is typechecking, not pinned-provider runtime evidence. Full fixed-Host and
prospective-merge acceptance are not claimed.
