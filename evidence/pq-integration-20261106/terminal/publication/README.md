# Source-specific terminal evidence increment

Publication candidate: `ca4e2fb9160d3e388e131624f7b3350ae4f5d56b`  
Tree: `ba691b8b5f06a0cfeb062261d6a33f0c086f06b0`  
Recorded scope: `HOLD_NO_GO. Retained f85 broad terminal observations and ebd scoped native failures retain their exact sources. ca4 is the current composed source with only its twenty finite source/Python/locked-graph gates. No native or full hosted CI result is transferred to ca4, and no whole-chain PQ qualification is claimed.`

Every result retains its original tested source, command, profile and budget.
`collection-status.json` records explicit pending observations and per-source
owner classifications. A completed command is not a completed batch; a CI
snapshot with running jobs is not a final CI verdict. A matching tree or later
documentation commit never creates another native execution.

The earlier retained-history package remains immutable and separately indexed.
This increment keeps actual failed, timed-out and cancelled observations. New
candidate controls and an unexecuted red-baseline design are distinguished from
executed tests. Nested child summaries are not full-suite passes.

`selection-plan.json` and `file-manifest.json` bind exact original paths, bytes
and hashes. Full reports are retained through the explicit original gzip
indexes, not replaced by derived summaries. ZIP/ELF/database/cache copies are
excluded; their original identities remain in the owner indexes.

The optional transport uses deterministic regular-file tar headers and zstd
parts of at most1.5MiB. `verify_curated_evidence.py archive-index.json` checks
part/member hashes and coverage without extracting or executing the evidence.
Its success establishes archive integrity, not product qualification.
