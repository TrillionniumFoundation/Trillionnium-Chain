# Reviewed source-binding follow-up integration

The original complete repository-truth lane on 7d8d4c59 failed; the subsequent
122-unit continuation diagnostic completed with 116 zero and six nonzero exits.
It is diagnostic evidence, not a passing original full lane.

- [Original diagnostic summary](diagnostics-original-summary.json)
- [Complete original diagnostic ZIP](diagnostics.zip)
- [Exact ZIP member index](diagnostics-index.json)
- [Cross-host copy verification](diagnostics-copy-verification.json)
- [Integration decisions and original carrier identities](integration-review.json)

The ZIP contains 266 original files plus its index. Original stdout, stderr,
command bodies, timing, source records and failure exits are preserved.
The four reviewed component commits are H1 e811c204, F1 2d9baf31, F2 6418023d
and B1 341a8b5f. Their local controls and explicit qualification boundaries
remain separate from any later exact-source complete lane or hosted result.

The current corpus changes only twelve existing reviewed blob pins and adds
one required raw historical collector dependency. The historical joint Markdown
document keeps its original bytes under a .md.original carrier; its original
index and file remain available at the F2 commit. No current Markdown checker
exception is added. No native runtime or original acceptance limit is changed.

The source commit which contains this integration cannot contain its own later
complete gate receipts. Those are collected separately with the actual head,
tree, original outputs and source readbacks before any publication decision.
