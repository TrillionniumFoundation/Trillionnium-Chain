# C2 cloud readiness observation

Exact source: `0e554f36ffdde3053a5eb1756eb5e526b1935032`, tree
`753cdbad6714f00d8ccb9ddbb47f0fd71280ee62`.

The unchanged 71-test readiness roster ran to completion and **failed with three
errors**. All three are actual `FileNotFoundError` exceptions while binding
`/usr/bin/time`; this environment did not provide that executable. There were 68
successful test completions and no assertion failures. This is not a successful
71-test observation and is not relabeled by a later run on another host. No tests,
observer, or time binary were skipped, replaced, or stubbed. The corpus suite ran
all 60 tests successfully, and all seven selected source-checker commands exited
zero. The four new guard-bypass mutations are subtests inside an existing test ID,
not four added top-level tests.

The archive retains every original regular output file, both complete materialized
source snapshots, and the exact runner. The snapshot covers the 5,135 materialized
tracked files of a sparse checkout, compared byte-for-byte to Git; it does not
claim the 22,777 sparse-absent paths were read from disk. Before and after snapshots
are identical. The original command summary stays unsuccessful.

Run `python3 verify_cloud.py` from this directory to verify the retained archive,
exact commands, source identity, stream hashes, and failed terminal result. This
only verifies recorded evidence; it does not rerun the original tests. Separate
desktop observations, if present in the parent directory, have their own source,
environment, logs, and result. Whole-chain PQ qualification remains false.
