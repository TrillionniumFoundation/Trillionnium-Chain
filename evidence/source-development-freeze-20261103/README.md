# Frozen historical development pool: comparison blocked

419 complete Rust functions remain in 29 connected source families after AST
boundary validation and conservative source-family deduplication. The fixed split
is retained even though it fails the three-class comparison gate:

- dev_fit: M00 100, M04 8, M10 184; 20 families.
- dev_probe: M00 96, M04 0, M10 31; 9 families.
- M04 has only four source families overall. No model was trained, no evaluation
  outcome was optimized, and the hash split was not rerolled for class coverage.

This is historical development material from this same MIT-licensed repository.
It is not a future window, independent acceptance set, production model or reward
claim. Package-owner labels are declared static ownership, not independently
adjudicated task destinations.

## Collection and isolation

Fixed tree-sitter 0.25.2 / tree-sitter-rust 0.24.0 identify full function boundaries.
Nested overlapping functions and parser-error candidate files are excluded.
Candidates from baseline paths with parse errors are quarantined. Original path
exclusions remain; directly annotated inline tests are tagged, not silently removed.

Baseline fingerprints use the original 332 source files, not historical evaluation
task files. Exact AST-token copies and five-token-shingle near copies are removed.
The frozen thresholds are Jaccard >=0.85, or containment >=0.90 with size ratio
>=0.50. These are operational heuristics, not proof of statistical independence.

Families join paths across branches, version-stripped paths, every qualified
function identity, parent-file/subdirectory splits, exact copies and near copies.
Mixed-owner components are quarantined. Edge reasons and memberships are retained.
The independent review found that v1's sole M04 probe came from
unix/connection_service.rs while unix.rs was in fit; v2 joins that source family.
The original v1 plan and summary remain here. This stricter revision preceded any
model fitting and did not search for a favorable split.

## Verification and independent review

Verification passed 419 unique AST identities, 888 exact source-range proofs,
fixed features, all grouping and near-copy edges, parent/child isolation, parser
stress cases, and the expected no-M04-probe gate failure.

An independent reviewer checked 544 candidate heads, 13,881 source-change
occurrences, 23 candidate inventory versions and 161 source blobs. All 16 distinct
Cargo manifests were independently hash-checked and package-name checked, with
zero mismatches. The reviewer also confirmed all published function sources are
exact slices of those verified repository blobs. No private evaluation tasks or
private user records are included. Source attribution and the root MIT license
continue to apply.

## Frozen bytes and reproducibility

rows.json.gz is a deterministic gzip wrapper around the unchanged frozen rows.json.
Its decoded SHA256 is:

d27e63332cd6479181b7083c8d91414034fb4495a4f2d551ff8873e9747c00c3

The decoded file contains exact function source, fixed 257-coordinate features,
owner labels, source head/blob/byte ranges and group assignment. decoded-hashes.json
also binds the two compressed input metadata files. SHA256SUMS binds the package.

Basic package verification, with only the Python standard library:

    python evidence/source-development-freeze-20261103/verify_package.py

Full AST/source-range verification requires the pinned parser packages, this
repository's historical Git objects and a verified source cache. Install
parser-requirements.txt into an isolated environment. Set CHAIN_SOURCE_CACHE to a
local cache directory containing decompressed owner-discovery.json and
history-filter.json plus a blobs/ directory of the named original Git blobs.
Each cached blob is checked against its Git SHA before use. Baseline source blobs
must be readable from the Git object store. Missing objects are errors; lazy
network fetch is disabled, and no substitute source is silently accepted.

    CHAIN_SOURCE_CACHE=/path/to/verified-cache python evidence/source-development-freeze-20261103/verify_frozen.py

The published owner metadata keeps one verified representative head per source blob,
with the full discovery-file SHA256 retained for provenance; it is not the complete
544-head audit transcript. This projection preserves every collector-used input.
The source metadata provides exact Git object identities and representative head
references for retrieval from this repository. This package is honest about this
external historical-object/cache dependency: it is not a standalone full repository
archive. Standard-library verification does not replace full source-range checks.
CHAIN_REPOSITORY optionally selects another checkout for full reconstruction.
collect.py writes generated JSON beside itself, so run a copy in a separate output
folder with CHAIN_REPOSITORY and CHAIN_SOURCE_CACHE explicitly set. Do not overwrite
these frozen artifacts or load historical calibration/evaluation/consumer inputs.
The publication wrapper changes paths and compression only; full verification was
rerun against the packaged scripts and reproduced the retained verification.json.
A separate full reconstruction reproduced rows, groups, summary and exclusions
byte-for-byte. Edge-list array order is not deterministic because of set iteration;
the 32 near edges and 942 family edges match exactly as canonicalized sets.
rebuild-check.json preserves the initial byte-comparison failure and canonical
edge checks. Do not describe those edge files as byte-identical regenerated output.

Next required evidence is genuinely distinct M04 source families and checked labels,
then a newly frozen collection version. Existing families must not be split or
moved selectively to make training runnable. No release or efficacy decision follows
from merely finding historical code that differs from the initial source snapshot.
