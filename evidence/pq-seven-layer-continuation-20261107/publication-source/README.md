# Final composed-source checks

All observations here bind `276a1e26f1989aef4b3d75263ff5b55e073b46e9`, tree
`d2a3d83d2800c8e0829e3a951cb2f0f6aa233e56`. This is the committed composition
of the reviewed CI policy/evidence merge and concurrent `adebe0bd` analysis input.

The original thirteen source commands passed, including **270 Python cases**,
repository/inventory checks, the 713-blob corpus, HOLD guard, locked metadata and
formatting. The CodeQL suite now contributes twelve cases; the e36 source suite
had four, so its separate historical total remains 262. No overlapping counts
are added together.

Two supplementary commands passed: actual standalone locked/offline
metadata (12 packages), workspace all-features locked/offline metadata
(181 packages / 26 members). Strict workspace/all-target/all-feature Clippy
with `-D warnings` failed with Cargo exit 101: the compiler's Node library-test
process terminated with SIGKILL 9. No lint error, outer timeout or causal OOM/disk
diagnosis is established by that log. The original failed command is retained;
it was not retried. The earlier passing e36 Clippy observation remains scoped to
e36 and does not turn this later static attempt into success.
Default workspace metadata remains 176 packages / 26 members.
All sixteen receipts have identical before/after checked source identities:
11,064 tracked entries / 1,114,540,546 bytes.

The [receipt](receipt.json) binds original output hashes, command arguments and
the unchanged runtime/formal Git subtree objects. The separate
[independent readback](independent-readback.json) checks the actual records;
[raw archive and per-file index](source-static-observations-index.json) retain
the runners, logs, receipts, reader and cache-retirement observation.
Extract the adjacent `source-static-observations.tar.gz` in a fresh directory
and verify its per-file hashes before review.

The containing publication changes evidence and the sole plan only. These are
source/static checks, not a new native execution. Native and quantum results
retain their exact e36 identity; the failed full Node and recovery observations
remain failed. Identical Rust/formal trees do not create new execution evidence.
Whole-chain PQ-128, public WAN, quantum mining and production activation remain
HOLD / NO-GO.
