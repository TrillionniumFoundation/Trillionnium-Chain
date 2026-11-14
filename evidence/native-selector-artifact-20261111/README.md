# Native selector artifact filename correction

The direct published parent is Chain `8c95a8d0a9199e9f72405835c8f0662c36af7c42`,
tree `20f27cc513247b8f3f8bbdff549e43144c90b724`. This correction preserves its
complete [HEPLCP03 source-pin evidence](../heplcp03-source-pins-20261111/README.md).

The original next-architecture workflow placed qualified Rust selectors directly
in artifact filenames. GitHub job 130240478504 on older `ced03a7` actually failed
its final upload because a generated `.exit` filename contained `:`. Its original
job log and normalized job observation are retained here. That upload did not
produce a usable artifact; this record does not invent the absent archive.
The workflow blob that caused the failure is unchanged in the direct parent.

## Naming and execution identity

The workflow now accepts the same ASCII Rust path grammar as the existing
required-test reader, uses a distinct `--` prefix boundary, and maps each `::`
separator to `-`. Rust identifier segments cannot contain hyphens and cannot be
empty, so the encoded path has no `--`; splitting the prefix and restoring each
single hyphen to `::` recovers the exact original identity. The two fixed prefixes
remain distinct, including the formerly ambiguous `component::a` / `a` case.
The helper uses exclusive creation for a `.selector.json` mapping and refuses
invalid selectors, unknown prefixes and a duplicate retained mapping.

The writer and reader use the same returned label. Cargo and the required-test
reader still receive the original selector. All 18 fixed selector names, complete
module runs, four matrix combinations, resource bounds, failure exits, source
fences and upload requirements remain intact. The existing capture script and
required-test reader are byte-for-byte unchanged. Mapping metadata proves only a
filename relationship; it does not prove that a test or native task executed.

## Validation and limits

[RESULT.json](RESULT.json) binds the changed files and exact source pins. The
retained storage CI controls plus six new filename regressions pass 25 tests;
five discovery controls and all 59 original corpus controls also pass. The new
regressions execute the actual generated helper and unchanged capture script on
explicit fixture bytes, preserve NUL, non-UTF-8 bytes, trailing whitespace and a
nonzero exit status, and require the original Rust identity when reading an
encoded filename. These parser and capture fixtures are not native executions.

Only the workflow and existing regression file need new corpus values. All 1,079
pins, all 987 required paths and their order, original observations and every
other manifest field remain present. The original inspector returns HOLD_NO_GO;
claim guard, CI contract and preflight pass without changing any acceptance gate.

There is no native rerun or post-correction hosted upload claimed here. The old
job's native results do not transfer to this successor tree. QROM input bounds,
CodeQL deadlines, Darwin process cleanup and native pressure thresholds are
unchanged. Model efficacy, independent custody, Hepta FinalUse and production
activation remain unqualified: **HOLD_NO_GO / DENY_ALL**.
