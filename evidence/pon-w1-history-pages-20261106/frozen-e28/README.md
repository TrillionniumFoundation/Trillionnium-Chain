# Frozen e28 follow-up component execution

These observations belong to commit
`e28ac65b0727eb98fb2bb67291870c16587c59ad`, tree
`d8ff55d21d59a478f72cfedc9ce9a15cdbab4329`. They follow the first-publication
snapshot and do not rewrite its then-pending results.

The [execution summary](summary.json) records 76 selected library controls:
74 passed, zero failed and two retained ignored entries. The ignored cost
experiment was not executed; the ignored SIGKILL child is a subprocess entry,
and the actual parent crash/recovery control passed. All ten test processes
exited zero. Selection was checked against the actual binary's complete test
list, preventing a zero-test filter from being counted as a pass.

The library binary SHA-256 is
`875c7dabc2b7673087f49a1cfc9f7b480647ed88be4ab070b04c9f15e9fc540e`.
The source commit, tree, clean worktree and binary digest match before and
after execution. This binary uses explicitly recorded dev/test debug=0;
the results establish functional component behavior, not release timing or
the original fixed-Host four-second qualification.

Strict workspace/all-targets/all-features Clippy with `-D warnings` also
completed successfully using the original dev profile with debuginfo.
The exact invocation and log digest are in
[followup-observations.json](followup-observations.json). Its profile is
separate from the debug=0 library build. Original release library-build
SIGKILL observations and the local Host startup refusal remain in the parent
evidence directory.

The earlier applicability suite's six generated-table errors are retained
without relabelling them as successful executions. Corrected-table positive
controls subsequently passed: all six previously failing positive cases
executed with the corrected table, as retained in
`applicability-corrected-positive-controls.log`. No observation here qualifies
a later merged or modified source tree.
