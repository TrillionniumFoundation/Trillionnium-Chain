# Native SettlementEngine

This directory builds and qualifies the finite Service SettlementEngine public owner. The implementation is HIA. The hosted Python files orchestrate compilation and test execution; they do not execute Settlement business decisions for the public library.

The owned interface is declared in `engine_owned.h` and has 21 exact exports. Constructors and successful operations mint independent immutable owners. Borrowed views remain valid while their owner is alive. Callers must pass live handles created by this library and honor the C pointer, length, and ownership contract.

## Rebuild and qualify

Use the repository's pinned Hepta revision and native compiler. Set `HIA_TOOLCHAIN_ROOT`, `HIA_NATIVE_COMPILER`, and `HIA_NATIVE_COMPILER_SHA256` according to `hia/toolchain.lock.json` and the compiler binding. Rust qualification uses the unchanged locked original source with Rust 1.95.0, offline Cargo dependency resolution, and an empty target in the new output.

```sh
bash scripts/project-preflight.sh
python3 -B -m hia.platform.service_settlement.build --output /new/out/build
python3 -B -m hia.platform.service_settlement.qualify run --output /new/out/qualification --rust-bin /path/to/1.95.0-x86_64-unknown-linux-gnu/bin
python3 -B -m hia.platform.service_settlement.readback --input /new/out/qualification --output /new/out/independent-readback
```

Attached development checkouts run the normal project preflight before qualification. Detached read-only CI uses the existing audit mode and still binds the exact source, HEAD, tree, project boundary, and remote identity. The audit mode does not alter staged or push rules.

Every output must be new and outside the repository. The independent reader writes only its separate output. A complete gate requires both the fresh qualifier and independent reader to succeed.

The gate retains all eight native compiler inputs and outputs, the actual HIA ownership emitter buffers, exact public link, current source and tool identities, original Cargo events and feature graph, all process stdout and stderr, and complete observed response bytes. It preserves the original 30-second compiler limit and 128-function, 8192-operation budgets. The full qualification has a 1200-second deadline. Native observations and allocation controls retain their 240-second deadlines; the original generator retains 120 seconds. Owned commands use one independent three-second cleanup deadline.

The finite required roster is 137 original registered tests: 136 outer tests and the original child fixture explicitly exercised by its parent in both crash phases. The two original compile-fail documentation tests, formatting and strict Clippy are mandatory. Native comparison covers all 320 fixtures and 2636 operations, including 16066 native calls and 1754 independently recorded FFI height values. Allocation coverage requires 162 controls with 136 actual calloc refusals and eight concurrent readers producing 256 independent owners. The fixed 68 integrity controls are named in `qualification/integrity_roster.py`; a partial or failed result cannot become a successful report.

## Scope

This is the Engine owner qualification. It does not qualify a native SQLite Store, Node integration, the original service resource budget, other targets, production activation, a complete host dependency closure, package retirement, or whole-chain native completion. Original Rust remains the mandatory comparison implementation. The public runtime does not fall back to Rust or a Python interpreter. The allocator observer is test-only C and is linked only into the separate test image; the production library is not changed by those controls.

All failures and partial captures remain in their original output. Repeating qualification creates a new output and new execution identity.

For a native-stage timeout, inspect `native/fixture-progress.jsonl` in the original evidence. Its last complete line records the most recent phase reached; the fixture and operation ordinals are one-based positions in the frozen corpus. An `operation_start` row identifies an operation entered, not one completed. Rows include elapsed monotonic wall time, calling-thread CPU time, completed counts, and the next `calls.jsonl` ordinal. `public_dispatch_wall_ns` accumulates wall time inside the common public ABI dispatcher, excluding direct drops and private fee calls. It is a subset of stage wall time; neither it nor wall time minus CPU identifies scheduler wait by itself. The journal is best effort, bounded to 4096 rows (512 bytes each), retains complete lines without a final flush, contains no request or response bytes, and does not determine qualification status or change any deadline.

The hosted Settlement matrix additionally uploads `hia-settlement-compact-<head>-<run>-<attempt>` before packaging the complete archive. Its one bounded `summary.json` contains hashes of observed original source binds and phase receipts; it projects only fixed statuses, flags and counts. The last complete fixture-progress row, complete-row count and trailing-fragment byte count come from the existing journal. Missing, refused, changed and over-limit inputs are named without substituting successful values. The original receipt files, cursor history and full archive remain unchanged; raw requests, responses, command lines, exception text and environment records are not part of this companion. It neither qualifies a run nor changes a job outcome. A runner terminated before collection may have no companion.

The same compact summary reports the original integrity report's availability and hash separately from its 240-second process receipt. The report exposes only the fixed roster's recorded `PASS`/`REJECTED` values in order, plus the last recorded and first unrecorded control. An unrecorded control is not an observed failure or acceptance, and a producer `PASS` is not independent reader success. No exception strings, source inputs, arbitrary control labels or nested diagnostics are exported.

### Read-only Store schema gate (finite qualification)

`schema_read.hepta` is a separate qualification-only SQLite continuation. The
native URI encoder supplies the pathname URI; a disposable fixture transport
supplies the first 20 raw file bytes and relays the continuation's requests to
the exact checked native SQLite provider. HIA refuses a WAL header before any
SQLite open, selects the original read-only URI/NOFOLLOW/NOMUTEX flags, sets the
original two-second busy timeout, and executes `BEGIN DEFERRED`. HIA then checks
the exact three ordered names and SQLite definitions and the original zero
trigger count; nothing is published before the real statement and connection
close. An owned rollback-journal reader keeps an original writer from committing
between steps. The test uses the extracted exact original Rust Store open and
schema functions with its locked bundled SQLite, and checks extra/missing/
changed tables, forbidden triggers, and the original WAL refusal.

The fixture checks its private directory's currently resolved pathname and
refuses a final symlink before reading the header. SQLite also uses NOFOLLOW.
That is not a stable ancestor/descriptor identity, the original sidecar gate,
or the original post-open file check. None of those owner checks, metadata/state
decoding, journal replay, application state verification, or whole-Store or Node
integration is qualified here.

```sh
python3 -B -m unittest hia.tests.test_settlement_schema_read -v
```
