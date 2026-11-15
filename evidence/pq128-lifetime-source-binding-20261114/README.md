# Reviewed current lifetime source mapping after the dc42 lane failure

This is a source-binding correction, with all security and production conclusions
remaining HOLD. The original full Linux repository-truth attempt failed; this
record does not claim that its unexecuted remainder or hosted acceptance passed.

## Original failure and source identity

- Runtime checkpoint: `dc42ce4df5cff79cc61c5addbaf01074b56b06ca`, tree `9fda17fed2542b2baccaa34585bb00afd699e12b`.
- Original full lane: 6.677 seconds, exit 1, unchanged 2700-second limit.
- Original budget controls: 58 run, 57 pass, one source-lock error at `pon_work.rs`.
- [Original summary](original-full-lane/summary.json), SHA-256
  `9a4bc9c021e80adff3d2c7d5500e1aed3f9eda519efb3942cbd42a2e34c5eab2`.
- [All 37 original files](original-full-lane/COPY_INDEX.json), 164,028 bytes;
  the original 17 steps are inside summary.json, with no fabricated steps.json.
- The original [register](historical/pq128-lifetime-budget-v1-0f9.json),
  [source lock](historical/pq128-source-lock-v1-0f9.json), and
  [composition manifest](historical/pq128-lifetime-composition-v2-before-dc42-review.json)
  retain their exact bytes.

## Reviewed repair scope

The [21-path source mapping](reviewed-source-mapping.json) records old/current
regular Git blobs, modes, byte lengths, SHA-256 values, complete changed-file
diffs and the previously selected implementation commits. Eight paths changed;
thirteen are byte-identical. Source correspondence alone is not a theorem,
full dependency closure, native replay or current-use authority.

The new default register changes only experiment.source_revision. The default
lock changes that revision and the eight reviewed SHA-256 entries. The original
budget reader, its 58 controls, exact probability arithmetic, event roster,
allocations, nine unmet assumptions, eight unknown terms, four unknown query
budgets, strict byte caps and false/null qualification values are unchanged.

The already correct 46-path root register remains unchanged at its independently
reviewed 5c04 source context. The current composition bridge freezes both exact
child identities and the exact 21/46/1/66 counts, retains the unique shared
pq_release.rs path and compares every shared digest. Its original sixty methods
remain; [AST comparison](composition-test-ast-adaptation.json) proves that only
two methods' fixed count expectations change. Its historical method name
containing 65 remains a stable control identifier. The baseline failures are
retained under [the original composition run](original-composition-baseline/).

The selected proof-profile reader continues to observe the native register as a
separate experiment. No historical proof identity, selected descriptor or
security eligibility is refreshed. The claim guard still invokes the unchanged
strict current lifetime inspector.

## Targeted validation results

The [original execution summary](validation-v1/summary.json) has SHA-256
`1fcda0f49c76a007bd7c1017651ce1d86032d13dd477b475a884a31920a2c94b`.
It records the repaired working source before its metadata commit, using Mac
Python 3.14.3 and an explicit canonical private temporary directory.

| Existing suite | Methods run | Result |
| --- | ---: | --- |
| Lifetime budget | 58 | PASS |
| Lifetime composition | 60 | PASS |
| Root dependency register | 51 | PASS |
| Whole-chain claim guard | 57 | PASS |
| Selected proof-profile binding | 39 | PASS |

These 265 method executions had zero failures, errors or skips. All five actual
inspectors, the actual current corpus and CI contract, and diff checking passed.
The 79 selected input files matched before and after. The selected proof-profile
descriptor remains
`8e95754db175bf8f2c4b3ffc0afe46f7b1eff476479d15fb2c005bf6d79dd0f1`.
All sixteen [stale-binding negative observations](validation-v1/reviewed-binding-refusals.json)
refused: eight individual old source digests, three old/current default pair
combinations, four superseded child identity fields and the old composition
review context. A final current positive check still succeeded without granting
any security or production qualification.

The original pre-edit Mac composition run is retained with **60 tests, five
failure records and three errors**. Its causes include the obsolete root
declaration and the unchanged reader's rejection of the platform's default
symlinked temporary path. The later run selects a canonical directory through
the environment; neither the reader nor its refusal assertion was weakened.
This local environment correction is separate from the original Linux
57-pass/one-error lifetime failure.

## Validation boundary

These targeted results do not replace the complete Linux lane on the final
successor commit or any exact-head/prospective hosted gate. No ROG source,
remote reference, PR metadata, protection, deadline or production flag was
changed by this correction. The [artifact index](EVIDENCE_INDEX.json) records the
exact preserved originals, reviewed mappings and current targeted observations.
