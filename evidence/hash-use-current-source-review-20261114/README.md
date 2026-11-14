# Hash-use current-source review, 2026-11-14 UTC

This packet records a manual review of the existing 19-use, 31-path hash
contract against the exact source blobs at
7d8d4c59fcd01480a12e1c64835b202079091800. All 31 input blobs also equal dc42;
six differ from the previous 57b069ae mapping and 25 remain identical. The new
map metadata belongs to the successor, not to the input checkpoint.

## Preserved boundaries

The semantic review base e4abb172147e941b62483652b0ceabaae4317624, the complete
19-use semantics commitment, strict regular-file reader, caps and all false/null
qualification fields are unchanged. Only six source pins and one independent
source-map commitment changed after review. New optional/exported APIs do not
acquire complete-callgraph coverage. No cryptographic bound or production
activation is granted. The previous complete manifest, reader and all 33
controls are preserved under historical-57b069ae/; the original document is
raw data named contract.md.original, so its old relative links are not treated
as current document links.

## Original failure

original-full-lane/ preserves all 39 original files (400,321 bytes) and the
original index from the failed 7d8 full Linux lane. Its summary SHA-256 is
79d37af0ecec1749098bdfd1cfc7127de2cf9aa928b7271ca4ef8de39cd4061b.
That run failed after 30.922 seconds: 33 hash-use methods, 31 passes,
one failure and one error. The 2,700-second limit was unchanged. Later commands
in that fail-fast lane did not execute. The source was acquired by an exact
local bundle; remote publication and hosted qualification were not verified.

## Executed necessary checks

On this isolated Mac working tree, the unmodified 33 hash-use methods passed
with no failure, error or skip. The existing one-method CI command guard also
passed, retaining its original mutation assertions for position, multiplicity
and failure policy. The actual hash-use CLI returned HOLD_NO_GO, with 19 uses,
31 source paths and qualification/activation false. The actual CI contract,
preflight and the three changed source/document paths' diff check passed.
The validation snapshot's 37 unique inputs were byte-identical before/after.

These observations do not replace a full Linux lane, the root's separate
122-command diagnostic or hosted CI. Corpus/sole-plan changes are deliberately
left to coordinated root integration. The original failure is not rewritten.

## Evidence layout

- reviewed-mapping.json: all 31 old/current OIDs, sizes, hashes, uses and
  per-path dispositions, including the selected change commits.
- source-deltas/: complete six-file source diffs, with no omitted hunks.
- consumer-and-scope-review.json and consumer-excerpts/: direct callers,
  independent-map enforcement, unchanged function spans and profile history.
- minimal-edit-proof.json: one reader AST literal changed, all original
  controls and semantic fields retained.
- validation-v1/: original command stdout/stderr, steps, summary and snapshots.
- diagnostics/: exact read-only diagnostic/validation scripts and the preserved
  initial diagnostic failure caused by a nonunique byte anchor. That diagnostic
  ran no project tests or source edits; the corrected version scopes the
  comparison to the named verifier function.
- consumer-pin-update-proposal.json: three exact Git blob OIDs for root
  integration, without writing the corpus.
- EVIDENCE_INDEX.json: exact retained payload sizes and SHA-256 values.

Absolute paths inside original receipts identify the original execution
locations; this index maps their retained copies. No raw receipt was rewritten.
