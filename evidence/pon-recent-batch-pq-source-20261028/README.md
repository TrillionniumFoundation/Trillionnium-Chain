# Explicit reviewed NPQ3 source for the original recent-batch suite

The original [run 40615932188](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40615932188)
failed in all four lanes before any native test. The full repository source
checks passed for head `809b012a92e319f1932c2e15852e9ebfc12fdddc` and its actual
prospective merge; the first inline `store.rs` blob comparison then refused.
The always-run final source check passed again, after which hashing the absent
native logs failed. Neither that secondary error nor the original source pin
refusal is a native runtime result.

The [four-lane original receipt](original-four-lane-failure.json) contains
actual tested head/merge identities, ZIP hashes and per-member hashes. All four
original job logs and both source receipts per job are retained beside it.
The complete logs use gzip with recorded compressed and uncompressed hashes;
their timestamp-only lines contain original trailing spaces. The first staged
whitespace check refused those literal log files. That observation is retained
in the publication archive; no original bytes were normalized or discarded.
The four downloaded ZIPs passed their advertised SHA256 and every member CRC.
The historical failure remains a failure.

## Why an explicit new source profile is needed

The original workflow's source pins identify a reviewed implementation. They do
not make any future source implementing the same legacy behavior automatically
compatible. The sole development plan records earlier reviewed pin updates
alongside the original native suite. Here four of the sixteen pins differ,
including on the already-published NPQ predecessor; changing only `store.rs`
would still leave three mismatches and would not establish native compatibility.

| Changed original pin | Reviewed implementation effect | Required runtime check |
| --- | --- | --- |
| `store.rs` | Select explicit PQ schema, constructor, packet/header codec and state validation from Settings; carry header time into the existing executor. The explicit legacy selection continues through its existing branches. | All original error ordering, SQL corruption, fixed-BLOB, history, cache, recovery, pipeline and business cases. |
| `store/native_authenticated.rs` | Decode complete packets with the explicitly selected Settings profile; remove the now-unused fixed-codec import. | Original authenticated packet, ancestry and recovery cases. |
| `store/native_authenticated/arithmetic_cache.rs` | Validate selected native PQ account state before reusing arithmetic; the validator has its explicit legacy-profile exit. | Original cache mutation, cancellation, root and cold-read cases. |
| `store/native_fixed_blob_tests.rs` | Import the original `Node` and `Packet` fixture types explicitly after the parent import change; preserve the test bodies and assertions. | The same original fixed-BLOB tests. |

The [complete four-file diff](reviewed-source-diff.patch.gz) retains every changed
line. Gzip also preserves the unified diff's mandatory blank-context spaces;
its exact compressed and uncompressed hashes are in the review receipt. This review describes intent and the paths requiring execution; it does
not substitute for the original suite. The new source profile also pins fifteen
PQ Settings, packet, store, M05, wire and M06 owners, including the exact
saturating-deadline repair. Its review basis is
`b3f93a17e4eb424d26e516ca98340219ab554dfe`.

## Preserved old identity, explicit new identity

The [manifest](../../config/pon-recent-batch-source-profiles-v1.json) retains
`original-reviewed-v1` with all sixteen original pins unchanged. It adds
`native-pq-quota-v3-reviewed-v1` with thirty-one exact pins. The workflow selects
the new profile explicitly; the checker never tries an alternate profile and
never treats a source match as a native result. Selecting the original profile
on this source still refuses all four changed identities. Missing files,
symlinks, same-size changes, mixed old/new owners, unknown profiles, duplicate
JSON keys and noncanonical paths refuse.

The frozen original workflow fixture is byte-identical to Git blob
`59d1e66c6ea27d19dd5de0d43bc2a9d0d594b5c6`. A required control compares every
original named step except the replaced inline identity block byte for byte.
It separately preserves the original source-check/preflight lines and the
entire job matrix/resource/timeout block. Both architectures, both head and
actual merge lanes, the 25-minute job budget, original Rust version, release
profile, native selectors, expected counts, ignored observations, strict Clippy,
reader assertions and original retained source/binary artifacts remain intact.
The exact preserved-step hashes are in the [review receipt](source-review.json).

Ten source-profile controls passed, as recorded in the
[raw control log](source-profile-controls.log). They include the unchanged
runtime-command comparison and current source identities, but execute no native
Rust test. The full source guards and original four-lane native suite still
have to run on the actual committed successor. No native compatibility,
capacity, whole-chain PQ, full P1 or production qualification is inferred.
