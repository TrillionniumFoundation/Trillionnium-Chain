# Execution receipts stage v1

This is an intermediate preservation stage assembled from the exact reviewed postcommit receipt manifest. It contains 258 original payload files (21,635,495 bytes), plus the original manifest and README in provenance/. Every payload retains its original bytes, size and SHA256.

The original failure, UNKNOWN, completed review, historical hosted failure, and local source-gate statuses remain unchanged. The retained provenance describes its earlier preparation time; it has not been rewritten to describe this later copy.

No candidate files, Git objects, refs, remote state, protection or CI state were changed. No Git command, network request, scan, fsck or test was run by this staging operation. Active/future resume, dry-run, ROG, publication, merge or deletion results are excluded. Completed later results require a separately reviewed overlay.

Files were selected only from the 258 exact manifest rows, without globbing. All original files were checked for regular single-link identity, absence of symlinks, stable before/after fstat and final path identity, exact size and SHA256. All original source fingerprints were checked again after copying. This is a collection of independently verified files, not an atomic directory snapshot.

EVIDENCE_INDEX.json maps every source to its staged target and exact ZIP member. The ZIP has no extra outer directory: members begin with payloads/, provenance/, README.md or EVIDENCE_INDEX.json. Existing ZIP payloads are retained as opaque bytes; their nested members were not rescanned. The outer stage ZIP is checked member by member for size, CRC32 and SHA256.

The index cannot hash itself. Its hash, the outer ZIP hash and the complete ZIP member index are recorded in adjacent completion receipts. This stage and its new metadata are not claimed as inputs to any earlier audit, gate or archive verification. No execution tag has been created, and no new protocol or hosted qualification is granted.
