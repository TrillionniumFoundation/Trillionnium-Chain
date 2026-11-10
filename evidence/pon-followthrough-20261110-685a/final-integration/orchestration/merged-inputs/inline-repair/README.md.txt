# Repair of the actual C3 inline Store source pin failure

The observed failed C3 is `a715b2c8e89732ce356ebae67f978ef232156c04`.
Its actual checker, contract-test and repository-check errors identify one old
literal source guard in `.github/workflows/pon-recent-batch-acceptance.yml`.
The candidate changes only that guard's value:

```text
source: trillionnium/crates/trnm-pon-node/src/store.rs
old Git blob: a8bd7b9c8d9b02617060bea955b3bb21d905129f
new Git blob: 62f0a44f37d6258c32eee5f8977a99a51d89c284
```

The new value agrees independently with the original checker refusal and the
actual C3 corpus-refresh receipt. The actual C3 workflow was read through Hepta
and exactly equals the original da Git blob, `4f863aa86694735aceac19542c2cc825010e36f8`.
The resulting workflow blob is `89171c7274109594c3b5d82df8664d66eda710f8`.
The unformatted partial source-assembly Store blob is not used as the target.

## Complete workflow enumeration

All 31 da workflow files, totalling 539,165 bytes, were fetched or reused only
after exact Git-blob verification against the directory roster. The checker
function has no separate INLINE_SOURCE_PINS constant: it scans every `.yml`,
ignores comment lines, and requires a full match of the literal `git hash-object`
guard form. It finds 26 guards in two workflows: six in branch-encoding and
twenty in recent-batch. No unsupported guard form was found.

The four workflows modified in C3 were also read in full from the actual
worktree. None contains an active inline guard. The observed C3 status identifies
the same failed commit above. The source reads return independent versions and
are not claimed to be an atomic multi-file snapshot.

Only Store intersects the actual C3 changed-source pins. There are no inline
native_budget or native_generation_budget guards to update. Other Store-path
occurrences are path triggers or retained module-wiring assertions; this repair
does not alter them. None of the source paths named by the 26 guards is among
the 13 non-evidence paths changed by upstream df927.

## Outputs and boundaries

- `inline-store-source-pin.patch`: one-line incremental workflow repair.
- `candidate/.github/workflows/pon-recent-batch-acceptance.yml`: exact target.
- `repair-manifest.json`: frozen before/after/patch hashes.
- `final-review.json`: full literal census, actual C3 status attribution and
  per-workflow source hashes.
- `c3-read-files-receipt.json` and `c3-current-workflows-receipt.json`: actual
  bounded read identities; original SDK payloads are retained alongside them.

No checker, test, frozen C3 file, remote file or CI-union-v2 artifact was changed.
No test or native command was executed. The partial-baseline project preflight
was attempted and returned 128 because it is not a Git checkout; this is not a
passed project preflight. The actual M1 worktree must retain its own original
preflight, source bracket and complete validation results. Fixing this known
literal does not certify that the remaining full CI gates pass.
