# Independent static review: fixed historical source-object importer

## Verdict

The reviewed fixed driver has no identified deterministic logic error that would reject otherwise complete normal reviewed inputs. Its selected readback does not traverse absent historical parents, it requests no ref/worktree/configuration mutation or network fetch, and it keeps a failed or timed-out import at HOLD even if later readback finds the objects.

One write-target precondition needs an explicit closure before execution: the actual `objects/pack` directory must be a canonical ordinary directory within the authorized root. Driver lines 201–205 check the object database itself, but lines 222–223 use `is_dir()/iterdir()` on the pack child without independently rejecting a symlink. The sole importing command writes that child. No actual ROG path anomaly has been observed by this reviewer; this is a static write-boundary gap, not an assertion that normal ROG import will fail. Root may close it with an already established current target-directory proof or a minimal explicit driver check. Directory device/inode can be recorded across snapshots; its contents and mtime legitimately change when a pack is added.

The readback child PID is retained in its final step rather than published to `active_owned_process` at launch. This does not fabricate success or add mutation, but immediate ownership publication would improve recovery if the reviewer process disappears during the read-only 509 MB stream. It is not the identified pre-execution write-boundary item.

## Exact reviewed inputs

- Driver: `/private/tmp/chain-consolidation-20261114-root/import_external_evidence_source_capsule_v1.py`, 28,580 bytes, SHA256 `36b3b01bcba2ee13e6a1a3ca3c933f354397d99a8ee192fa136da6e083d768f2`; 508 lines.
- Design README: `/private/tmp/chain-external-lane-readonly-review-20261114-v1/import-driver-review-v2/README.md`, 6,809 bytes, SHA256 `e8c0e0b73c76f4a45c82d5cd04efdf55634432e3ca91bf9b21560aeee9530852`.
- Manifest: `/private/tmp/chain-external-evidence-source-object-capsule-20261114-v2/manifest.json`, 1,439,371 bytes, SHA256 `ac4f97386c73d337d3059df746ed1650bc75e0697aa7a12f28589e86817c02e7`.
- Pack: 2,487,542 bytes, SHA256 `c0d9caf64494bec9d99f3b80a82fbcb0f36c1972aa0efd7da8741d3ba421865c`, trailer SHA1 `c58cdc5b6d8ceb69d2550e44e1e25f0154c91371`.

The independent static input receipt is `input-review.json`, 4,462 bytes, SHA256 `e3d69fceab5064a404c97bc937ede8b0a1181c95f98331f6a3a88494aad1a83c`. It confirms 940 capsule objects plus 2,972 prerequisites, exactly 3,912 unique OIDs: 14 commits, 521 trees and 3,377 blobs. Raw sizes are 9,204,616 capsule bytes and 509,417,482 total bytes. Both ordered OID digest constants, the fixed pack SHA256, version-2/940-object header and pack trailer match.

This review parsed the Python AST and JSON and hashed the fixed files. It did not execute the importer's main or helpers, run any Git command, access ROG, rebuild an index, decompress/revalidate each pack member, import objects or run a CI lane.

## Source, environment and mutation boundaries

Lines 90–118 require explicit actual expected HEAD/tree, canonical root/source/input directories and a create-only evidence directory. Listed Git repository/object/ref overrides are refused; replace objects and lazy fetching are disabled and protocol transport is disallowed in the selected Git commands.

The snapshot at lines 174–237 retains HEAD/tree, clean status, refs, Git/object database paths, object format, local configuration/worktree configuration, shallow file, alternates, grafts, promisor state and effective fsck Boolean values. It refuses replacement/promisor state and nonempty grafts. The unchanged project preflight and another snapshot occur before pack preparation; a further exact snapshot occurs immediately before the object mutation.

The independent index rebuild writes `validated.idx` outside the source object database. `verify-pack -v` must identify exactly the 940 selected non-delta members, including types and raw sizes. Fixed whole-pack content is checked again before the single ordinary `index-pack --stdin --max-input-size=2487542` invocation.

There is no import retry, fetch, checkout, source ref update, shallow-boundary creation, alternate rewrite or configuration write in the requested command list. The source snapshots do not assert that every byte of the entire working directory was independently rehashed; they enforce the stated HEAD/tree/status/metadata contract.

## Historical parents and fsck

The capsule intentionally supplies selected source commit/tree/blob closure, not full commit-parent history. The driver's 14 root checks read each selected commit's raw body and explicitly recurse its tree, then compare the union to the exact 3,912-object set. No parent walk is requested by this readback.

The driver implements the declared effective-policy choice as `fetch.fsckObjects` when specified, otherwise `transfer.fsckObjects`. If effective true, it stops before import with a parent-connectivity review requirement. It does not turn the policy off, use a skip list, change shallow metadata or replace the stricter policy with `--fsck-objects`. Receive policy is also recorded. The direct ordinary index-pack choice is therefore conditional on the recorded policy state; it is not a claim that source-snapshot closure proves full historical connectivity.

This review confirms the code's stated policy behavior and selected command boundaries. It does not claim a new execution of Git fsck or a full upstream implementation audit for the eventual ROG Git version; the driver retains that actual runtime version for subsequent execution evidence.

## Partial failures and readback

The 2,972 prerequisite objects must exist with exact metadata. Capsule objects may already be present, so harmless concurrent prior availability does not cause a false prerequisite failure. Foreign unrelated objects are outside this selected set.

The importing command is marked attempted before it starts. Its owned PID/process group, normal streams, timeout and actual exit are retained. Exit 0 alone is insufficient: the exact normal pack identity and empty stderr must also hold.

After any attempted import, the fixed `cat-file --batch` parser streams exact object headers and bodies, checks each Git SHA1, checks capsule SHA256 values, bounds the complete protocol stream, and rejects missing/trailing/partial data. It then checks 14 commit/tree bindings and their recursive union. Readback success cannot erase a prior command error.

The source-after snapshot is attempted in finally. Status becomes IMPORTED_AND_VERIFIED only with no error, import exit 0, unchanged fenced source state, complete raw object readback and complete 14-tree closure. A timeout or partial failure stays HOLD, with no automatic cleanup or rollback that could destroy evidence. This status would establish object availability only; it cannot stand in for external-evidence-contract acceptance.

## Execution disposition

No execution is performed or authorized by this review. The only outstanding item identified here is explicit closure of the pack child-directory write boundary. Parent-history completeness, native acceptance and hosted qualification remain outside this importer receipt.
