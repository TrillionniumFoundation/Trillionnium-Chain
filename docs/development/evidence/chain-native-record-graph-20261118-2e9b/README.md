# Native publication graph scope — 2026-11-18

Research-only continuation of the original Chain liveness work. This candidate addresses one measured redundant account-graph traversal. It does not claim F0 service acceptance, public-WAN/Sybil qualification, complete physical cost, native Hepta adoption, or production activation.

## Problem and measured scope

The previous exact candidate, `e6af21fd47347ba900ef87842447ed6fe227a6f0` (PR #960), failed the original fixed workload in run [44335832525](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/44335832525): **2/6 confirmations within the original 30-second phases, 0/6 within four seconds of their scheduled starts**. All six rounds and 42 business-packet exposures remain in the denominator. PR #961 retains the original ZIP, original reader, independent readback, and actual cost profile.

That retained database/profile shows 13 baseline receiver publications and 12 baseline client publications with no actual account SQL delta and exactly unchanged account Root. The account graph has 2,055 nodes. These are observed occurrences on the old candidate, not a measured saving or a forecast of this candidate's business result. Nested account-graph/Host CPU samples are not additive to their caller CPU.

## What changes

The private native publication owner captures an original transaction scope **before** its first complete parent graph read. The original verification still reads the actual parent graph, complete States, SQL deltas, resulting Root, cancellation/progress callbacks, record, and final fences.

After actual native apply, the private `save_publication_record` helper can reuse that exact verified account Root across **its own single literal metadata INSERT** only when:

- The same original `BEGIN IMMEDIATE`, connection/process/observer and schema remain current; no write occurred after the read-before-capture scope.
- The actual SQL deltas contain no account entry, and the actual child account Root equals the verified parent account Root.
- The metadata table has the exact original DDL; there is no trigger/view, temporary or attached schema, writable-schema condition, or metadata foreign key.
- The metadata table has only its original primary-key autoindex. Both the actual catalog and SQLite `index_list`/`index_xinfo` must show that exact ordinary `block`/BINARY key and rowid. Additional ordinary, expression, partial, or collation indexes on that table use the original full reader. Indexes on unrelated tables are not unnecessarily excluded.
- The original observer reports exactly one potentially writing statement after the old capture, including the creation of the new post-write scope, and the new scope is still current.

The helper owns the actual INSERT. It accepts no caller-supplied changed-set assertion, allowed-write count, graph receipt, or replacement scope. It transfers no subtree frontier or arbitrary record cache. The current child State, record, deltas, last progress callback and original final no-write fences still run before a graph hit.

Any additional/no-row/failed SQL, trigger/index program, graph or State damage, schema drift, connection mismatch, transaction/savepoint ABA, or cancellation follows the existing full verification or fails closed. The old scope is never re-stamped or re-enabled.

Five Rust files change. The only source-contract changes are their five current `pinned_blobs` entries; historical heads, required paths, qualification claims, the pressure workload, budgets, and all original assertions retain their original values.

## Actual native verification

The final index-restricted source was built with Rust 1.95.0, offline/locked release dependencies, two build jobs, one test thread, and incremental compilation disabled.

| Actual final suite | Result |
| --- | --- |
| SQLite original transaction-scope controls | 14 passed |
| Authenticated-store controls | 132 passed, 1 original ignored |
| Detached-admission controls | 23 passed, 1 original ignored |
| Legacy-admission controls | 8 passed |
| Task-output Root parity | 2 passed |
| Strict Clippy, node and SQLite-boundary libraries | exit 0 |
| Formatting and diff checks | passed |

The nine new metadata cases are a subset of the 132 authenticated cases, not nine additional passes. They include writes and graph damage before/after save and scope capture; the last parent callback; deliberately matching expected catalogs containing triggers or four kinds of extra index; unrelated indexes; foreign connection and transaction ABA; actual current State, cancellation, and the final child callback.

The first revision's seven new cases/130 authenticated passes are retained as a superseded source observation. Independent review identified the extra-index execution-program gap before publication; the final revision adds the explicit index checks and reruns the original suites. No first-revision result is represented as a final-source run.

For both revisions, all 1,702 tracked `trillionnium/` files present in the actual compilation checkout were SHA-256 checked before and after the tests. The final source is also checked after the final original suites. The compilation checkout's Git HEAD remained `7e3e454f9b18d5d135e72cc5ea373e04fc5a2ef8`, with the recorded prior #960 five-file native delta plus this five-file delta; it is not falsely described as a clean checkout of the later publication commit. The publication workspace is byte-matched to the final tested five files and to the previous published native source.

`native-originals.tar.xz` contains both revisions' full test stdout/stderr/exits, submitted/formatted patches, source manifests, the final five source files, actual toolchain identity and three final ELF identities. It does not contain the ELF bytes. The superseded initial ELF identity is explicitly UNKNOWN because that build target was later replaced.

- Native archive: 124,796 bytes; SHA-256 `283b5aeb8f66b6ee08cdcf88004754a835a17c844601bf5aad83518b504597cf`.
- Final five-file patch: 31,437 bytes; SHA-256 `c52916cae380877e42606940f5c2adb342159601bb879ad7381823fc10d84faa`.
- Full final source-contract file SHA-256: `3fa06624a27f3b1a2ddd9e3f56ca10c32f1607bfe1d3b88e09d58ea429225a13`.

## Original source gate

The original `scripts/ci/check_pq_research_integration.py` checked all **2,617** current pinned blobs and returned `HOLD_NO_GO`, `cryptographic_acceptance=false`, `node_activated=false` (exit 0). The unchanged `CorpusGateTests.test_native_ownership_boundaries_cannot_omit_or_mutate` passed (one test, 1.690 seconds). These are source-integrity results, not capability qualification.

The initial Mac materialization attempt failed when Git's promisor fetch could not connect to github.com:443. Its complete returned stdout/stderr and failure identity are retained. The same fixed provider head's original bytes were then retrieved from GitHub's official raw endpoint with every original Git blob hash checked before use: 1,494 downloaded files, 189,271,774 payload bytes, 2,618 selected paths including the additional original gate helper. The source contract and final native files remained byte-identical to the publication workspace. This acquisition traffic is an engineering observation, not F0 service traffic or a physical-cost estimate.

`source-gate-originals.tar.xz` retains the actual gate/control outputs and exits, the unchanged original checker/control/reader sources, the final full source-contract file, provider acquisition hash receipts, and the prior failed materialization observation. It does not duplicate all provider source files already bound by the immutable repository and original blob pins.

- Source-gate archive: 196,220 bytes; SHA-256 `a1d15f4f916793794e0fe0936ac3765d0c6eb87137a9c2f428c792387060e0fc`.

## Actual provider timing supplement

`provider-timing-44335832525.json` preserves the unmodified response from GitHub's official `GET /repos/TrillionniumFoundation/Trillionnium-Chain/actions/runs/44335832525/timing` endpoint:

- `billable.UBUNTU.total_ms = 0`, `jobs = 1`.
- `job_runs[0].job_id = 134912190949`, `duration_ms = 0`.
- `run_duration_ms = 2164000`.

These are provider-reported billing/timing fields. Zero reported billable milliseconds is **not** zero physical consumption or a zero monetary price. The run wall duration includes queue/wall time and is not CPU time. Energy, full physical resource cost, provider price, and complete cross-receiver attribution remain UNKNOWN; no missing quantity is imputed from nested CPU counters.

## Next original business test

The next measurement is one dispatch of the unchanged `pon-fixed-host-root-f0.yml` workflow on this frozen publication head. It keeps 1,024 seed transfers across four seed blocks, 21 business packets per phase, the baseline and valid-work ROOT phases, all six scheduled confirmations and 42 exposures, 24 external ROOT actors, the actual public 0.25-CPU/2-GiB parent, original controller ceilings, 30-second phase windows, and the four-second scheduled target.

At publication time this candidate's F0 business result is **PENDING**, not PASS. The previous 1/6, 0/6 and 2/6 original-window results, each with 0/6 scheduled-four-second confirmations, remain retained. Different GitHub runners and different completed work counts do not establish a paired causal speedup.
