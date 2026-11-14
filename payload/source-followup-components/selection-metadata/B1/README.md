# B1 completed execution receipts

This manifest selects completed local B1 evidence for a later execution archive.
It is a source-file manifest only; it does not create an archive or publish a Git
ref. Each entry has an exact source path, safe target path, size and SHA256.

B1 commit: 341a8b5f751342b51a4aaf9512534853c79d7b5b.
Tree: 234b37f6a0dfd8adf758d78d533b055499b295b8.
Parent: 7d8d4c59fcd01480a12e1c64835b202079091800.

The original 25 bridge methods retain their exact source and AST. The 31-method
suite (25 original plus six new) passed. The new source-roster control first
failed because the default Mac temporary path traversed /var, which the existing
regular-source reader rejects. Its original log is retained. The same source and
assertions passed with an explicitly canonical, owned temporary directory.
There was no native protocol execution, qualification change or complete-lane
success claim.

The five Python producers were originally invoked with -c. Their exact source
strings are now saved as non-executable text and identified alongside the actual
PTY sessions. Saved filenames are not represented as their original invocation.

Historical raw producer/Git objects already stored in B1, old artifact ZIPs,
full patches embedding those bytes, and future executions are excluded. The
manifest leaves source bytes in their existing locations for independently
verified staging; no payload directory is implied.
