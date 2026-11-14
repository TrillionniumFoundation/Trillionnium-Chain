# Root-only import of the fixed external-evidence source capsule

This driver is prepared for review only. It has not been executed and has not accessed or changed the ROG source, object database, refs, shallow file, alternates, or configuration.

## Fixed input and mutable source context

The input pack must be source-objects-c58cdc5b6d8ceb69d2550e44e1e25f0154c91371.pack, exactly 2,487,542 bytes with SHA256 c0d9caf64494bec9d99f3b80a82fbcb0f36c1972aa0efd7da8741d3ba421865c. manifest.json must be exactly 1,439,371 bytes with SHA256 ac4f97386c73d337d3059df746ed1650bc75e0697aa7a12f28589e86817c02e7.

Both inputs must be direct fixed files in /home/qian-qi/chain-final-consolidation-20261114-root/external-evidence-object-capsule-input-v1. Their immutable content is checked through regular-file, no-symlink, single-link and before/after fstat guards. A verified private copy of the pack is used for indexing and the eventual import; the supplied files are not overwritten.

The caller must supply the actual full expected HEAD and tree. The driver does not fill a future candidate or a success state. The evidence directory must be a new direct child of the authorized root with prefix external-evidence-object-import-. No old evidence directory is resumed or overwritten.

## Source and Git state fences

Before importing, the driver checks HEAD/tree, full clean status, all refs, replacement refs, object format, shallow state, local configuration hashes, worktree configuration hash, alternates and graft metadata, partial-clone settings, and promisor markers. It runs the unchanged project-preflight.sh once and requires the same state afterward and immediately before the import.

A shallow state that already exists is recorded and must remain identical; this operation never adds or edits shallow boundaries. Active replacements, grafts, or promisor state are refused. Local configuration contents are hashed rather than copied into the receipt. Boolean fetch/transfer/receive fsck settings are recorded without rewriting them.

The original 2,972 existing objects are prerequisites, but the driver does not require the 940 capsule objects to remain absent. If some capsule objects are already present, exact type/size matches are accepted. New unrelated objects are harmless. A required object outside the capsule that has disappeared is reported as a missing environment prerequisite rather than an identity conflict.

## Why the import does not silently disable strict checking

Git documents --strict as checking broken objects and links, whereas --fsck-objects separates object validity from links. This source capsule intentionally excludes parent history outside the 14 declared source roots. A full-link check is therefore a different contract from the selected source snapshot closure.

Primary references:

- https://git-scm.com/docs/git-index-pack
- https://github.com/git/git/blob/v2.50.1/builtin/index-pack.c
- https://github.com/git/git/blob/v2.50.1/fetch-pack.c

The inspected upstream index-pack implementation enables its link walk through --strict. The fetch-pack implementation selects the effective fsck policy from fetch.fsckObjects first, then transfer.fsckObjects. The driver follows that precedence when checking existing settings. If the effective policy is enabled, it holds before any object import and asks for a separate parent-connectivity decision. It does not turn that policy off or substitute --fsck-objects.

When the applicable policy is absent or false, the reviewed path is ordinary git index-pack --stdin with an exact maximum input size. No --strict=ignore, skip list, --fix-thin, --promisor, shallow adjustment, or configuration mutation is used. Runtime Git version and every invoked argument are retained.

## Independent validation and the only mutation

Before the source object database is touched, Git rebuilds the index in the new evidence directory from the verified pack copy. A separate verify-pack command must produce exactly 940 matching OIDs, types and raw sizes. Delta entries, missing entries, foreign entries and duplicates are refused. The pack header, SHA1 trailer and fixed full SHA256 must also match.

The only intended source-object mutation is one invocation of git index-pack --stdin --max-input-size=2487542. The driver never fetches, creates a worktree, changes a source ref, edits configuration or retries an import. All normal stdout/stderr, exit codes and timeout outcomes are retained. A failed import remains HOLD even if later inspection finds some or all objects present.

## Exact readback after an attempted import

After the single attempted import, the driver reads the fixed 3,912-object closure through git cat-file --batch. It streams and hashes 509,417,482 raw object bytes without saving a second 509 MB content copy. Every object must match its Git SHA1, declared type and size; the 940 imported objects must additionally match the reviewed SHA256 values. The generated metadata receipt retains per-object hashes and the complete stream digest.

It then checks each of the 14 original commit-to-tree bindings and reads each recursive tree. Their union must be exactly the same 3,912 OIDs. No parent traversal, checkout, model execution or CI lane is selected.

The final source snapshot is always attempted after a source-bearing operation. Success requires import exit 0, the exact normal pack stdout identity, empty import stderr, complete raw-object readback, the 14-root closure proof, unchanged source/ref/config/shallow/alternate state, and no recorded error. Timeouts and partial outcomes have no automatic retry or rollback.

## Invocation after root review

Use the prepared Python 3.12 environment and the same explicit PATH as the root source/preflight workflow. Fill EXPECTED_HEAD and EXPECTED_TREE from the source that root actually intends to validate.

    /home/qian-qi/chain-final-consolidation-20261114-root/final-python312-env/bin/python -B \
      /home/qian-qi/chain-final-consolidation-20261114-root/import_external_evidence_source_capsule_v1.py \
      --expected-head EXPECTED_HEAD \
      --expected-tree EXPECTED_TREE \
      --pack-path /home/qian-qi/chain-final-consolidation-20261114-root/external-evidence-object-capsule-input-v1/source-objects-c58cdc5b6d8ceb69d2550e44e1e25f0154c91371.pack \
      --manifest-path /home/qian-qi/chain-final-consolidation-20261114-root/external-evidence-object-capsule-input-v1/manifest.json \
      --evidence-dir /home/qian-qi/chain-final-consolidation-20261114-root/external-evidence-object-import-FIXED_CONTEXT-v1

Import completion does not imply that external-evidence-contract passed. Root must still execute its original 30-command lane against the fixed final source, with the original materializer and all existing qualification boundaries.
