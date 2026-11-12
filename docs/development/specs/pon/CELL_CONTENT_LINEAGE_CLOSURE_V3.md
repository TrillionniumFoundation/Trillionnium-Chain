# TCV3 full-content observation of declared model lineage

Status: **candidate / HOLD**. This format adds no migration, activation,
CURRENT selection, FinalUse grant, key authority, funded retention duty or
security probability. Historical provenance and undeclared semantic
dependencies remain unqualified. Native execution results must retain their
actual tested source; the test definitions below are not test-run evidence.

## Problem and retained components

The existing TCV2 object binds complete TCV1 metadata and SHA-512 commitments
to each model/environment payload and chunk. Its `verify_cached` path reads
the actual `CellStoreV1` bytes, and its sealed-loader bridge checks the exact
sealed model/environment objects. Those are real full-content mechanisms.

However, TMR1 stores direct parent model identifiers as 32-byte references.
TCV2 alone neither supplies every parent's complete version nor recursively
reads each ancestor's actual payload. A separately retained historical version
set also need not be an ancestry closure. Treating either object as proof of
expanded ancestry would overstate its contract.

[The TCV3 implementation](../../../../trillionnium/crates/trnm-data-availability/src/cell/version_content_closure_v3.rs)
reuses TCV2 and the existing retained-set owner. It adds one finite declared
ancestry graph whose entire actual content can be read back under a new,
independently selected commitment. TCV1, TCV2, TMR1, TCD1 and their existing
callers keep their formats and meanings.

## Exact content and graph contract

`CellVersionContentClosureV3` contains at most sixteen complete TCV2 nodes
and a nonempty list of selected roots. Nodes are ordered by their complete
64-byte TCV2 commitments; root indices are strictly increasing. Inputs are
never silently sorted or deduplicated by the public constructor.

For every node, all direct TMR1 lineage identifiers must resolve to exactly
one node in the same table. A missing parent is refused, even if its old
identifier is present. Two nodes with one legacy model identifier are refused,
including alternative strong-content declarations under identical old
metadata. Each parent must be in the same declared family and a strictly
earlier model generation. All nodes must be reachable from the selected roots;
cycles, out-of-range edges and paths deeper than sixteen are refused.

This version has no external frontier exception. An origin is a supplied
complete TCV2 node whose TMR1 lineage is explicitly empty. A missing,
retired or unavailable ancestor cannot be relabeled as an origin. Projects
that cannot supply the full declared ancestry receive an error and no complete
TCV3 observation.

Within each version, the original TCV1/TCD1 validators still require their
exact declared model and environment file sets and dependency graphs. TCV3
does not parse arbitrary payload programs to discover hidden dependencies.
The old base, parent, tokenizer and layout labels remain literal metadata;
the existing runtime/environment relationship retains its original rule.

## Fresh wire and commitment

The canonical encoding is:

| Field | Encoding |
| --- | --- |
| Namespace | Four bytes `TCV3` |
| Node count | Unsigned big-endian 16-bit integer, 1 through 16 |
| Selected-root count | Unsigned big-endian 16-bit integer, 1 through node count |
| Selected roots | That many unsigned big-endian 16-bit table indices |
| Each table node | Unsigned big-endian 32-bit byte length followed by the complete canonical TCV2 bytes |

The complete encoding is limited to 32 MiB. Each embedded node also retains
TCV2's own 24 MiB limit. Decoding rejects incomplete fields, oversized members,
different namespaces, noncanonical order and trailing bytes.

The new commitment is SHA-512 of the ASCII domain
`TRNM/Cell/ContentLineageClosure/v3` followed by a zero byte and the complete
TCV3 encoding. It does not hash an old root as a substitute for the table.
All 64 output bytes are retained. Existing signature and persistent-storage
namespaces are unchanged because this additive candidate neither signs nor
stores an authoritative migration transition.

The legacy model IDs serve only as unambiguous links within this independently
pinned full-content table. Changing an ancestor's TCV2 content changes the
new TCV3 root even when the old metadata is unchanged. This binds the newly
selected contents; it cannot establish which colliding old object an earlier
signature intended, repair old ancestry commitments, or authenticate lost
history.

## Actual retained-owner and cache entry

The additive method
`CellRetainedVersionSetV1::verify_content_lineage_cached` takes:

1. The TCV3 declaration and the actual `CellStoreV1`.
2. The existing independently supplied `CellRetainedSetOwnerV1`, including its
   exact set commitment, epoch, height, required retention horizon and complete
   ordered loader-owner roster.
3. A separate `CellContentLineagePinV3`, containing the independently expected
   TCV3 commitment and exact selected root TCV2 commitments.
4. One original caller-owned `CellContentReadSessionV2`.

Before scanning payloads, the method checks the existing owner's complete
roster and retention windows, validates the full graph and new pin, and matches
every node's complete TCV1 metadata to the exact retained entry. It never
constructs a trusted loader expectation from the fetched object.

Each member then goes through the existing TCV2 `verify_cached` implementation
with that member's original owner expectation. This reads actual cache
manifests, chunks and ordered payloads and checks the complete strong claims.
Every ancestor's model and environment are included. Missing content, changed
content or any member error prevents the aggregate observation from returning.

All members and caller retries share the same scan allowance, cumulative byte
and chunk reservations, and immutable original deadline. A failed scan is not
refunded. A shared ancestor is one table node, while payload bytes shared by
different versions are conservatively scanned and charged once per version.
These are declared read reservations, not measurements of CPU, disk, RAM,
network cost or adversary resources. Deadline checks are cooperative; they do
not preempt a hash or SQLite call already in progress.

## Result and qualification boundary

`CellContentLineageReadbackV3` has no public constructor or deserializer. It is
returned only after all actual reads succeed and records the exact content,
retained-set commitment, supplied epoch and height, cumulative session usage,
and observation interval. It is a sequential observation of the supplied
owner view, not simultaneous availability or independent freshness evidence.

The bridge is a concrete callable API on the existing retained-set owner. No
ordinary node, release, daemon or production loader is switched to it by this
change. Selecting a new root for real use still requires the original owner's
explicit authority, migration/retirement rules, currentness and FinalUse
checks. Recovery of an unavailable ancestor remains unavailable.

This candidate does not establish public/WAN availability, independent custody,
semantic compatibility, historical authenticity, whole-chain query coverage,
QROM composition, or an actual lifetime failure bound. All existing HOLD,
unknown/null and production-activation boundaries remain in force.

## Validation obligations

[The native controls](../../../../trillionnium/crates/trnm-data-availability/src/cell/version_content_closure_v3/tests.rs)
exercise real SQLite capture and cold readback, multiple generations with a
shared transitive ancestor, independent root and selected-root refusals,
missing parents, ambiguous old aliases, false ancestor content claims,
unreachable nodes, family/generation mismatches, cycle/depth rejection, exact
owner windows, missing actual bytes, cumulative failed-read accounting and
strict wire boundaries. A singleton-origin vector is independently framed
with Python `struct` and `hashlib` from the unchanged TCV2 fixture bytes.

Run the focused tests on the exact candidate before assigning any native
result. Retain the original TCV2/retained suites and the repository's locked
graphs, strict Clippy, formatting, source integrity and link gates. Source
presence or a passing graph check does not grant release qualification.
