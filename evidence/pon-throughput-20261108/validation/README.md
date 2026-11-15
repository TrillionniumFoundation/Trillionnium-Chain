# Exact-source local validation

**440 Python tests passed on code commit
`f4c7137e63bdcc8a2a06f9c78789390ce0d87997`; throughput qualification remains HOLD.**
The following publication commit changes only retained evidence. The final
implementation, tests, workflow, non-evidence documentation and corpus pin are exactly the
tested code commit.

| Executed suite | Tests passed |
| --- | ---: |
| Original native full-path readers plus new transaction reader | 109 |
| Proof CPU accounting | 26 |
| Cell, loading and computation accounting | 32 |
| Reproducer output-path controls | 3 |
| Real subprocess/timeout receipts | 8 |
| Original raw source integrity controls | 43 |
| Original Host resource/confirmation controls | 79 |
| Original PQ source integration controls | 37 |
| Original CI contract controls | 103 |
| **Total** | **440** |

Of these, 126 test methods are newly added by this delivery. Native release
build, locked default/all-feature graphs, the corrected existing fuzz graph,
formatting, focused strict Clippy and four native regressions ran separately on
exact base `812589d9bb189b6abbf33b916a424121199dee75`; this delivery does not
change Rust implementation bytes. The original incorrect fuzz-manifest command
and exit 101 remain in the native archive beside the corrected exit-zero run.

Four source-pinned reports reproduced byte for byte. The reproducer executed
zero new native experiments: it reread three historical records and the one
new experiment separately retained under `../native-fresh/`. Native readers'
exit 1 denotes their original component-only HOLD, not a qualified throughput
pass. All qualified TPS fields remain null.

## Explicit local limits

Raw before/after checks cover all non-evidence tracked files plus all 166 code
publication paths, and their receipts are identical. The checkout omits some
historical evidence, so the original full-source validator correctly refuses
with exit 1: `index hides tracked worktree entries`. It was neither relaxed nor
reported as passed.

The original repository checker also fails locally with exit 2 at the absent
historical `evidence/pon-v1/README.md`. A separate diagnostic traced 233 missing
link occurrences to 165 exact-base historical targets and 19 to ten leftover
documents absent from the selected base. New throughput documents have zero
unresolved links, and both newly added plan links resolve. This scoped
diagnostic does not replace the failed original repository gate.

The dedicated GitHub workflow runs the unchanged full-source and repository
validators on a complete checkout. Its hosted result is an independent result,
pending when this evidence was published. A passing hosted result would not
change the original resource campaign from NOT_RUN, establish native depth-six
confirmation or qualify production TPS.

## Retained records

- [Machine summary](summary.json)
- [Exact command arguments, timing and exits](final-commands.json)
- [Four-report reproduction](final-reproduction.json)
- [Raw before-source receipt](final-source-before.json.gz) and
  [raw after-source receipt](final-source-after.json.gz)
- [Lossless logs and receipts](exact-source-validation.tar.gz) with
  [every archive-member digest](exact-source-validation-archive.json)
- [Original repository-check failure](repository-check.json) and
  [per-link base classification](repository-link-classification.json)

Initial failed fixture checks, parser hardening controls and output-path red
tests are preserved alongside their corrected green runs. No failure is
removed from the original denominators, and no absent measurement is encoded
as a zero rate.
