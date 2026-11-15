# b66 remote sparse-source and publication evidence

These original Hepta records apply to commit `b66e66d2465258d808c0f56ff851123306d4bdb4`, tree `11eee4a56ccab63394102a19204ab3922021d87c`. The designated `native-complete-source-gates` evidence directory is preserved in full: 82 original physical files with matching hashes before copying, in the copy, and after copying. Recorded source snapshots are part of that evidence; no live checkout, Git metadata, build cache, or other repository directory was copied. No original file was edited and no gate or publication command was replayed.

## Retained evidence

- [Original sparse scope](native-complete-source-gates/scope.json) and [core gate result](native-complete-source-gates/core-gates-result.json)
- [Complete stage arguments and return codes](native-complete-source-gates/stages.json), [environment](native-complete-source-gates/environment.json), and [source hashes](native-complete-source-gates/source-sha256.json)
- [Publication result](native-complete-source-gates/publication-result.json), [publication stages](native-complete-source-gates/publication-stages.json), [raw push output](native-complete-source-gates/git-push.log), and [exact GitHub branch readback](native-complete-source-gates/github-branch-readback.log)
- [Same-head complete-tree local gate summary retained by the publisher](native-complete-source-gates/full-tree-local-gates/attempt-01/summary.json) and [local Markdown audit summary](native-complete-source-gates/full-tree-local-gates/markdown-tracked-attempt-01/summary.json)
- [Delivery summary](delivery-summary.json) and [physical-file SHA256 manifest](manifest.json)

The remote checkout was sparse. Its core records cover the actual recorded Cargo graph, formatting, strict Clippy, owner/risk test targets, risk reader, CI contract/execution/source-integrity tests, inventory checks, source state, and terminal job result. The initial scope and core result say they were awaiting the same-head complete local tree gate. Those historical records remain unchanged. The later publication result records that the local complete-tree and tracked-Markdown gates had passed for the exact same b66 HEAD/tree, followed by a normal push and GitHub readback of b66.

The sibling `b66-local` delivery retains the complete original local gate directory, including the full link mapping and Markdown hash inventories. This local full-tree evidence complements the remote sparse core gates. The embedded local subset in the original remote evidence remains untouched.

The original remote scope explicitly says the standalone native example was **not** reexecuted in this b66 gate; it identifies the retained actual example separately. No fresh standalone run is invented here. **Neither this directory nor the complementary b66 local gate establishes a full `check_repository.py` PASS on merged commit `2d46d8682201bc0619f5b156af50e77fb399322e`.** Merged-source results must be bound and reported separately.

Original Markdown source snapshots already use `.source`; they retain that form. The manifest covers every payload file; its own digest is in the publisher's complete delivery receipt outside this directory. This delivery performs no source change, commit, push, activation, or new physical/global qualification.

## Physical inventory

This delivery contains **85 regular physical files**: 82 unchanged original evidence files, two new delivery descriptions (`README.md` and `delivery-summary.json`), and one new `manifest.json`. The manifest lists **84 payload files**, excluding only itself to avoid a self-referential digest. The publisher delivery receipt lists all 85 physical files, including the manifest and its SHA256. Original evidence-file counts and delivery-manifest payload counts are different measures.
