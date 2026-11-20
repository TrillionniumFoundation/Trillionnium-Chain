# Native Payload metadata owner

This component implements the metadata portion of the original
`trnm-peer-lease::PayloadReplayStoreV1` in HIA v8. Its executable owns its private
state, journal and lock descriptors, namespace, published-head identity and four
complete replay indexes. It uses the canonical HIA SHA-256 implementation and a
HIA-emitted Linux x86-64 process entry. Python and the append-only Rust hooks are
qualification observers; they are not part of the production executable.

## Public method scope

| Original public method | Native process operation |
| --- | --- |
| `open` | 1: construct an owned store from the namespace and path |
| `path`, `head_path`, `namespace`, `last_hash`, `record_count`, `accepted_frame_count` | 5: return the cached getter values |
| `contains_session` | 6: cached session query |
| `latest_generation` | 7: cached generation query |
| `verify_bound_endpoint_identity` | 4: verify the bound filesystem identities |
| `admit` | 2: validate and append a frame, publish its head, update cached indexes |
| `lookup_exact_v1` | 3: validate live storage and perform exact replay lookup |

Operation 8 closes the store; operation 9 closes the process. Method requests are
length-prefixed little-endian words. The complete public transport mapping is
retained in `public_reference.rs`, and independent request reconstruction is in
`readback_observations.py`. Neither file supplies implementation logic to the
native executable. A successful getter reads cached state without adding a
filesystem refresh. The endpoint-identity method checks identities without
adding a journal parse. Admission and exact lookup preserve the original live
WAL/head checks, poisoning boundaries, write/commit ambiguity and final identity
fences. A failed final fence after a published commit does not pretend to undo
the already updated cached state.

The original constructor wire order is preserved: namespace where applicable,
direction enum conversion, scope construction, kind byte conversion, then frame
construction. The additional `pr_wire_frame_valid` helper wraps the unchanged
typed `pr_frame_valid` helper. This distinction matters when an invalid enum or
out-of-byte-range kind appears together with a zero scope or frame identifier.

The private `f0` objects and direct private-arena probes are test interfaces with
exclusive, nonoverlapping valid borrowed buffers. This component does not claim
a public foreign-pointer ownership ABI or concurrent access to one borrowed
arena. Concurrent allocation tests use distinct private owners. Public
filesystem locking is exercised by independent processes.

## Qualification

Use Rust 1.95.0, the pinned `f33d` Hepta checkout and the native compiler with
SHA-256 `87c247e4d1c3c9a449d2947fd4227fdc186d519bffd203a04cafce7861a4ed54`.
Set `HIA_TOOLCHAIN_ROOT`, `HIA_NATIVE_COMPILER` and
`HIA_NATIVE_COMPILER_SHA256` explicitly. Put the pinned Rust tools on `PATH` and
provide a Cargo cache for the unchanged locked workspace dependencies. The
qualification itself uses a fresh Cargo target, `--locked --offline`, the
complete original feature graph, all 121 original outer tests and their two
existing child reexecutions, workspace formatting and strict Clippy. Its Rust
observer sources also pass the pinned rustfmt check.

Run on a non-root Linux x86-64 account with real Unix filesystem permissions,
`strace`, permitted tracing of newly created owned children, and the required
compiler/linker tools:

```sh
python3 -B -m hia.platform.peer_payload.qualify run --output /absolute/fresh/output
python3 -B -m hia.platform.peer_payload.qualify readback --input /absolute/fresh/output
```

Output must be a fresh directory outside the repository. The source snapshot
contains the complete actual admitted HIA closure, every declared composition
key needed by the compiler, observer and reader modules, project boundary
inputs and the unchanged original Git blobs. The capture path rechecks the
complete member set and bytes before and after stages; admission and independent
readback also perform full Core composition. An old report cannot be relabeled
to a new Git/source graph. Compiler inputs, actual receipts, tool identities,
all stdout/stderr, emitted artifacts and observation files are retained.

| Fixed observation group | Required coverage |
| --- | --- |
| `primitives` | 4,472 original codec pairs, 8 added mixed-error wire pairs, 840 replay pairs |
| `runtime` | 10,640 paired direct/dispatch native calls, 21 boundaries, 48 read-only queries, 8 incremental/full-index replay comparisons |
| `allocations` | 857 shapes, 2,827 actual ABI calls, 840 actual allocation failures, 8 threads with 256 concurrent private-owner calls |
| `views` | 8 actual emitted loader view admissions/refusals |
| `public` | All original 47 histories plus constructor priority: 48 histories and 492 paired method calls |
| `syscalls` | 1 probe and 60 actual EIO/EINTR injections: 61 histories and 488 paired calls |
| `crash` | 14 paired durability boundaries: 28 SIGKILL cuts after real successful kernel syscalls, then actual reopen |
| `boundaries` | 32 namespace, path, 4,096-entry and concurrent-owner histories |
| `wal-small` | 11 fixtures, 18 native calls, 9 actual original parser comparisons |
| `wal-large` | 14 fixtures, 21 native calls, 12 actual original parser comparisons |
| `wal-maximum-replay` | 176,602 authenticated records: one actual native replay and one fresh original comparison |
| `wal-maximum-index` | One actual maximum-index call, all nodes of all four indexes checked against the identical same-round replay fixture and its actual Rust output |

The final three groups form the exact disjoint union of the original 15 large
fixtures, 23 `(case, mode)` native calls and 13 Rust comparisons. The index-only
group reports zero new Rust invocations and explicitly references the same
round's maximum replay; it cannot substitute an older result. Complete fixture
bytes, every AVL node/key/height/balance and unused index memory are checked.

Every native observation group retains the existing 240-second execution
deadline and one absolute three-second cleanup budget. The four original public
history groups remain intact. The whole fresh qualification must complete
within the unchanged 1,200-second job budget. Compilation/emission retains the
30-second plus single three-second bound and the pinned 128-function,
1,536-block, 8,192-operation profile. The 41 integrity controls include actual
normal and escaped child lifetimes, actual descendant and native-owner timeouts,
an exhausted public-observer cleanup window, a stopped ptrace child failure,
and reader/source/roster refusal cases. Deliberate observer injections are
labeled; they are not product failures or synthetic successful crash cuts.

The public Rust observer deliberately prints each error through
`public_reference.rs::error`, and prints constructor Scope errors in `frame`.
Readback reconstructs these exact ordered diagnostic lines from the actual
binary responses and requests, including the outer and inner
`CommitAmbiguous` lines. Native stderr must remain empty. Separate negative
controls remove, add and reorder diagnostic events, replace a response error
code, substitute `Replay` for an authenticated-WAL `Corrupt` rejection, and
replace the published-head read target with an unrelated temporary file.
The latter distinction follows the original `payload.rs::parse_log`
seen-session rejection and `preview_replayed_state` sequence checks; public
`admit` replay classification does not apply to corrupt serialized history.

## Preserved failures and limits

`qualification/wal-scope-history.json.xz` binds the original per-case/per-mode
240-second definition and the actual failed development aggregate. In that
failed round, maximum replay and index individually returned in approximately
104 and 101 seconds, while the new aggregate reached 240.175 seconds before
its original parser comparison. The failure remains a failure. Splitting the
observation work does not qualify the original four-second service budget.

This module covers metadata ownership. Payload bodies, external recovery,
whole-Peer replacement, whole-chain native completion and production activation
remain false in every accepted top-level report. A sibling published head is
not an independent freshness checkpoint. Real syscall completion followed by
SIGKILL is not a power-failure proof. The existing original package remains
required until its remaining body, recovery and service contracts are complete.
