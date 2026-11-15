# b66 local complete-tree evidence

These preserved records apply to commit `b66e66d2465258d808c0f56ff851123306d4bdb4`, tree `11eee4a56ccab63394102a19204ab3922021d87c`. The complete original `native-complete-local-gates` directory was extracted without changing file bytes from the verified 144,444-byte archive, SHA256 `e1b6c209ef0901b8fc9673e1f2085f4c838fff4563a589d3bb5064f3f133c03a`. No check was rerun during this delivery step.

## Retained evidence

- [Original report and relative navigation](native-complete-local-gates/README.md)
- [Complete local repository gate summary](native-complete-local-gates/attempt-01/summary.json), [raw stdout](native-complete-local-gates/attempt-01/check-repository.stdout.log), and [exact command record](native-complete-local-gates/attempt-01/check-repository.command.json)
- [Tracked Markdown audit summary](native-complete-local-gates/markdown-tracked-attempt-01/summary.json) and [complete target mapping](native-complete-local-gates/markdown-tracked-attempt-01/local-link-targets.json)
- [Delivery summary](delivery-summary.json) and [physical-file SHA256 manifest](manifest.json)

The existing canonical `check_repository.py` actually returned PASS on the complete local b66 tree, with preflight PASS, clean HEAD/tree at both endpoints, and matching CI Python source hashes. The separate tracked-target audit read 565 physical Markdown files and checked 3,868 local link occurrences: 3,857 tracked file targets and 11 directories with tracked descendants. It reported no missing, escaping, or untracked targets. The original report preserves its parser and source-observation limitations.

This complete-tree local check complements the same-b66 Hepta sparse source, native, and publication evidence in the sibling `b66-remote` delivery. The remote sparse checkout did not itself provide a complete-tree repository check. Its original waiting-state records are retained alongside the later publication result that consumed these same-head local gates.

**These are b66 gate results. They are not a full `check_repository.py` PASS for merged commit `2d46d8682201bc0619f5b156af50e77fb399322e`.** The merged source and each of its actual validation results must retain their own exact commit binding. No runtime, physical execution, production, or global-work qualification is added here.

All 19 original files, including the original README and its relative links, are retained intact. The manifest covers all payload files; its own digest is included in the publisher's complete delivery receipt outside this directory. This delivery writes no repository source, commit, or remote ref.

## Physical inventory

This delivery contains **22 regular physical files**: 19 unchanged original evidence files, two new delivery descriptions (`README.md` and `delivery-summary.json`), and one new `manifest.json`. The manifest lists **21 payload files**, excluding only itself to avoid a self-referential digest. The publisher delivery receipt lists all 22 physical files, including the manifest and its SHA256. Original evidence-file counts and delivery-manifest payload counts are different measures.
