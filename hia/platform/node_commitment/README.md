# Checked commitments and shared Snapshot ownership

The native runtime implements the finite commitment methods used by the held
Node owner. `owner.hepta` retains the original None ABI. `snapshot.hepta` and
`checked.hepta` add owned shared snapshots, Some binding, checked preparation and
check-and-bind. `tree.hepta` applies deltas to the real persistent compressed
tree. The Node dispatcher composes these functions into three additional native
images while preserving the original per-image compiler and size ceilings.

## Method and ownership contract

| Operation | Native request | Result and ownership |
| --- | --- | --- |
| Consume a Prepared snapshot | 17 | Consumes the Prepared only when a real Snapshot exists; fallback returns 73 without inventing one. |
| Inspect / clone / drop Snapshot | 18 / 19 / 20 | Full canonical map and shared tree; independently retained ownership and exact retirement. |
| Bind Some Parent | 21 | Validates the entire actual State, expected root and cache limits; retains both the actual map and predecessor snapshot. |
| Checked snapshot | 22 | Checks actual State against the supplied expected root, reuses an unchanged map, or performs real checked delta application. |
| Check and bind | 23 | Transfers the checked result into a Parent with the original preparation observation. |
| Prepare against Parent | 10 | Keeps the immutable original parent across every subsequent preparation. |
| Prepared inspect / clone / drop / get | 2 / 4 / 3 / 5 | Complete required changes and snapshot; clone owns its delta and shares immutable map/tree nodes. |

All handles belong to the same private State heap. Epoch, sequence, height,
object type and hidden-owner checks precede use. Exported bytes are observation
data and cannot initialize a capability. Internal Snapshot ownership is never
exposed as a caller-owned handle. A returned Prepared retains no borrow of the
parent map. Parent, source State, clone, Prepared and Snapshot can retire in the
tested independent orders; the final live-object and allocation counts must be
zero and the arena must be erased.

Some binding first validates `CacheLimits`, then completes canonical traversal
even after an earlier mismatch, then applies the wire limits, parent mismatch
and root mismatch checks in original order. `checked_snapshot` and
`check_and_bind` perform canonical validation before cache-limit validation.
Valid zero cache budgets still permit binding an existing Some snapshot.
Top-level State keys retain their original UTF-8 domain and byte limits;
canonical Value string/object-key and numeric rules remain unchanged.

The tree validates its expected root, every before value, duplicate keys, and
the final count before publishing a new root. This also applies to empty deltas.
Any internal tree-apply mismatch produces the original full-root fallback with
all required changes and no cached snapshot. Cache fallback priority remains
key, payload, workspace, then delta. The inclusive 65,536-change application and
65,537-change DeltaBudget fallback are exercised with actual inserted State rows,
not synthetic counts. No protocol, compiler, child-time or cleanup limit is
increased.

Node commitment currently has two local u32 SHA256 paths: the general arena
implementation in `sha256.hepta` and the two-block 94-byte fork specialization
in `sha256_fork.hepta`. The general path uses `work_sha_compress` with
`node_sha_first16` and `node_sha_next16`; the specialized path maintains its own
expanded rounds in `node_sha94_rounds_0` and `node_sha94_rounds_32`. The two paths
share the `node_sha_get32` and `node_sha_put32` memory helpers. Their compression
code also remains separate from the crypto arena and streaming implementations
in `hia/src/crypto`. Deduplication and a controlled comparison against the
canonical crypto core remain open.

Qualification compares actual native outputs to SHA256 across padding and fork
boundaries. The host hash observes the native output.

## Reproduce the finite qualification

First build the actual complete Node with the pinned HIA toolchain:

~~~sh
python -B -m hia.platform.mempool_node.build --output NODE
python -B -m hia.platform.node_commitment.qualify_hash --build NODE/build --output HASH
python -B -m hia.platform.node_commitment.qualify_snapshot --group some --build NODE/build --output SOME
python -B -m hia.platform.node_commitment.qualify_snapshot --group checked --build NODE/build --output CHECKED
python -B -m hia.platform.node_commitment.qualify_delta --changes 65536 --build NODE/build --sha-check HASH/report.json --method-check CHECKED/report.json --output DELTA65536
python -B -m hia.platform.node_commitment.qualify_delta --changes 65537 --build NODE/build --sha-check HASH/report.json --method-check CHECKED/report.json --output DELTA65537
python -B -m hia.platform.node_commitment.rust_oracle --build NODE/build --some SOME --checked CHECKED --delta65536 DELTA65536 --delta65537 DELTA65537 --cargo-target CARGO_TARGET --output ORIGINAL
~~~

Each output path must be fresh and outside the source tree. Native children use
the original 240-second deadline and 3-second cleanup contract. The direct method
groups contain 13 controls / 82 methods and 14 controls / 94 methods. The Rust
driver appends three private test children to an isolated copy of the unchanged
original module, rebuilds with exact Rust 1.95.0 and the locked graph, and compares
every complete observation. It also executes the retained original commitment
tests, preserving the six tests already ignored by the original source.

The direct method driver records all native calls and complete heap/frame bytes;
the large delta driver preserves the same bytes as hashed compressed blobs. Every
run binds the exact complete Node build and current source. These method tests
are separate from the five real Node/M05 lifecycle partitions, their mandatory
system-call traces, the two original Node comparisons, and source/build integrity
controls described in the [Node owner](../mempool_node/README.md).

This component does not certify successor admission, SQLite COMMIT, live service
confirmation, reorganizations or the 4-second / 16-request resource contract.
