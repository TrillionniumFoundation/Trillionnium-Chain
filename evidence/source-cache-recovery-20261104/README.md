# Offline recovery of the frozen historical source cache

This additive tool restores the external source cache needed by the unchanged
[source-development freeze](../source-development-freeze-20261103/README.md).
It does not change its candidates, grouping, split, labels, parser, or failed
comparison gate. It neither trains a model nor reads historical evaluation,
calibration, or consumer task sets. Cache recovery is not an efficacy result.

## Pinned dependencies

`required-objects.json` is SHA256-pinned in `materialize.py`. It binds the original
compressed owner-discovery/history-filter bytes, decoded-hashes, collection plan,
collector, source-range verifier, and original SHA256SUMS. The decoded metadata is
checked against the original decoded hashes before use. It lists all 161 exact
candidate source blobs and the original baseline commit
`6cdbf9551aae1754e489773bac29bc0598e20a9b`, its inventory blob, scoped tree entries,
and 332 Rust source paths selected by that inventory's M00/M04/M10 packages.

There are 493 unique source blobs plus one inventory blob, 49 trees including
the root, and one baseline commit: 544 required objects. Representative candidate
heads are retrieval hints only; they are not traversed or required. No full
history or task-set traversal is performed.

## Usage

From the repository root (use an absolute cache path; `..` components are rejected):

    python evidence/source-cache-recovery-20261104/materialize.py \
      --repo . --cache /absolute/path/to/source-cache --check-only

`--check-only` verifies pinned metadata, repository identity, and every listed
local Git object's type/content hash. It reports exact missing/unreadable object
IDs as JSON, returns exit 2 if any are unavailable, and never writes a cache. It
does not inspect an existing cache or certify a full AST replay. Exit 1 denotes a
validation error; exit 0 denotes successful checking/materialization.

If objects are missing, an independently authorized operator can retrieve only
the reported IDs from the original repository. The separately tested acquisition
command is `git fetch --no-tags --filter=blob:none origin <exact missing SHAs>`.
There is no fetch, installation, network, or automatic dependency recovery in the
materializer. Git lazy fetching is disabled and all Git transport protocols are
denied even if inherited GIT_* environment variables try to override the policy.

After required objects are local, omit `--check-only`. The tool checks the original
origin URL, SHA1 object format, each required object, original inventory scope,
and exact baseline source-tree entries before writing decoded metadata and the
494 verified blobs. The inventory blob is included as a harmless cache dependency;
the original collector reads it directly from Git. Commit/tree dependencies remain
in the Git object store, as required by the unchanged original collector.

Writes use fsynced temporary files and atomic no-replace hard links. Existing exact
bytes are preserved; mismatched files fail without overwriting them. Every existing
destination is checked before adding files. Missing Git objects cause no cache
creation. Cache/file/ancestor symlinks, traversal paths, and non-regular files are
rejected with descriptor-relative, no-follow filesystem operations. Interrupted
runs can be rerun; a complete second run reports `new_files: 0`. Unexpected failures
may leave temporary files, but cannot publish a partly written destination file.
Use a dedicated cache directory, not an untrusted concurrently renamed filesystem.

Install the original pinned parser dependencies separately into an isolated Python
environment, then run the original source-range verifier with `CHAIN_SOURCE_CACHE`
and `CHAIN_REPOSITORY`. For full recollection, copy the original package to a new
output directory first: its collector writes beside itself. Never run collection
in the frozen package directory. Missing Git tree/commit dependencies remain errors;
this cache is not a standalone replacement for the historical repository.

## Tests and limits

    python evidence/source-cache-recovery-20261104/test_materialize.py

The 18 standard-library tests use synthetic Git repositories/tempdirs to exercise
successful recovery, idempotence, partial-cache resume, missing objects, wrong
origin/type, corrupt blob detection, cache conflicts, symlink files/directories/
ancestors, unsafe paths/IDs, pinned manifest/package tampering, missing metadata,
check-only no-write behavior, and inherited Git configuration isolation.

`object-precheck.json` records the real offline object availability check. These
tests do not replace full AST/source-range verification or a byte-for-byte/canonical
recollection check. Those must be recorded separately on the unchanged freeze.
The original failed three-class split gate remains unchanged, and training remains
blocked by that original gate.

## Actual clean-cache recovery and full replay

The host had lost all 161 candidate source blobs; baseline source objects remained.
Separate exact-ID Git acquisition restored those objects. The offline materializer
then verified 544 dependencies and created 496 files (494 blobs plus two decoded
metadata files). Its second run wrote zero files. The first attempt using a
`..` cache path was rejected; that observation is retained separately.

The unchanged full verifier passed 419 functions, 888 source-range proofs, 29
families and two parser stress cases, exactly matching its original report. A
separate collector copy rebuilt rows, groups, summary, parse audit, exclusions and
quarantine bytes identically. The 32 near edges differed only in array order; their
canonical multiset matched. The 942 family edges matched both bytes and multiset.
The preexisting nondeterministic edge ordering was not changed or hidden.

The new 648-head snapshot includes 22 heads added/updated relative to the earlier
630-head snapshot. Their M04 source blobs remain covered by the baseline and old
candidate pool. This does not resolve the original zero-M04-probe gate; no model
fit or split change was performed. Latest source-check metadata is retained.

All original frozen packages are unchanged. Native Rust/Clippy checks were not
run because cargo/rustc are unavailable; the added tool uses Python stdlib only.
