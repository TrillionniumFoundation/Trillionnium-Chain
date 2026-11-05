# Finite source-publication evidence — 2026-10-27

## Exact scope

This directory is a finite publication snapshot through original integration
commit `86c2e3a68d28d6b4e583555f16c649d7d3c24cd3` and its mapped remote commit
`ecdaf1679e9c2e1ea725d4ebf355fd9bdaee82a9`, sharing tree
`9f57f975d74537af5032859a59f7fdb0e02a7b59`.

It retains 39 original commits across the selected integration and side
branches. The metadata commit that adds this directory and any later
reachability merge are outside this 39-commit snapshot and are not
self-included. Subsequent commits, observations, branch heads, CI runs and
publication actions require their own records.

The GitHub connector used for publication does not expose controls for
reproducing the original author/committer identities and timestamps. Its
commit-creation calls therefore produced new commit IDs. The original commit
payloads are retained byte-for-byte in [original-commits.json](original-commits.json).
Original SHAs in measured observations remain their measured source identities;
they are not replaced with API-created commit IDs. The separate
[original-to-remote mapping](original-to-remote-commit-map.jsonl) records the
translation.

## Verified content and ancestry

All 39 original commit payloads reproduce their original Git object SHA and
payload SHA-256. For all 39 mapped remote commits, actual Git Data GET responses
match the mapped commit SHA, original tree SHA and ordered mapped parent list.
Thirty-two responses were obtained in the first readback and seven in the
second. This scope covers source publication identity and ancestry; execution,
model quality and release conclusions remain those of the original observations.

The exact source summaries are retained unchanged as
[batch003 readback](readback-batch003-summary.json) and
[batch005 readback](readback-batch005-summary.json). Their original absolute
workspace references are historical provenance. The actual 39 response wrappers
are independently available inside [remote-commit-readbacks.tar.gz](remote-commit-readbacks.tar.gz),
with portable member paths, timestamps, checks and SHA-256 values in the
[readback index](remote-commit-readbacks-index.json).

The two remote prerequisite commits remain
`4b6b8a91b6dfe41fbd7f40f40b359d535c2c4251` and
`6f4b9cae0dafcb0e6bc171e2aa9b8f630e74eca6`; the retained
[boundary responses](verified-remote-boundaries.json) bind their trees and
ordered parents. [PR #323 readback](pr323-prepublication-readback.json) records
head `57c1ed545d067937cbd7aaa7570d5f22123265e6`, base
`9fedf7ecbbe07177069c030592b4e03dcffebb81`, at 2026-10-27
10:35:30.833 UTC. This is a dated observation rather than a live-head assertion.

## Integrated side identities

The [side-head evidence](integrated-side-heads.json) and
[exact delta comparison](side-head-delta-comparison.json) identify nine original
side commits whose changed path, mode, object type and resulting blob SHA sets
match integration-lineage commits exactly. These are the Cell, quantum/DAA and
History branches. The [compact list](integrated-side-heads-compact.json) maps
all four retained side heads, including the PQ head that is already a genuine
ancestor.

At this snapshot, the main mapped head reaches 29 of the 39 mapped original
commits. Retaining the three already-integrated side heads as additional
publication parents would make 38 reachable. A later publication merge must
retain exactly the tree of its primary metadata parent. This directory records
the verified side identities and intended ancestry scope; the future merge
itself is outside this snapshot.

## Blocked M06 remains separate

The blocked detached M06 prototype recorded here is original commit
`08d647017c38eb0213f8d60db938222df4f59195`, mapped to
`024f4806d3baf28cb48b876ea5e5f1a6cd302a5c`. It is excluded from the main
integration candidate's implementation and ancestor graph. All three suggested
integrated side-parent closures also exclude this M06 commit. Its original
parent `bb2d444…` is a shared earlier History change; retaining that ancestor
does not include its later M06 descendant.

The M06 mapping and raw commit payload are retained as independent provenance.
Its mapped source is separately recoverable through the isolated M06 candidate;
it is not a publication parent of the main implementation. This archive covers
only the `08d6470…` M06 snapshot. The later `dcdf…` candidate, its observations
and subsequent mappings are outside these 39 entries. No current full M06 head,
M06 qualification or successor outcome is asserted by this archive.

## Package integrity

[PACKAGE-MANIFEST.json](PACKAGE-MANIFEST.json) records the exact byte count and
SHA-256 of every retained file except the manifest itself. The compressed
readbacks preserve all 39 original response-wrapper bytes and were decompressed
and checked against their index before packaging. The original commit archive,
mapping, summaries and side-head comparisons are byte-exact copies of the
recorded publication artifacts. No large model payload or Git bundle is embedded.
