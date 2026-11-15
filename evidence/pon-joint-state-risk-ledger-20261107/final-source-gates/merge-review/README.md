# Merge review delivery for 2d46d868

This directory preserves the original independent merge and committed-tree Markdown audit for [the fixed candidate source](https://github.com/TrillionniumFoundation/Trillionnium-Chain/tree/2d46d8682201bc0619f5b156af50e77fb399322e). Its ordered parents are `b66e66d2465258d808c0f56ff851123306d4bdb4` and `cb314bb4656e5da4844325cd83994ab4764fe8e9`; tree is `5ae5317304588cca8295a19dd512c8e853f1ef5b`.

## Payload

- [Original audit archive](final-merge-audit-2d46.tar.gz): unchanged 6,269,719-byte artifact, SHA256 `824b243b25579796382dc9da5b1873cfe1b03ea0009ea76c31b61e695652539d`. It contains the original scripts, source hashes, full committed-tree input, actual Markdown input archive, all 12 verifier tests and their successful log, raw gate outputs, parent/path preservation evidence, the failed first promisor attempt, the cancelled full binary checkout, and the integration rehearsal.
- [Machine-readable summary](audit-summary.json): fixed commit and tree, observed results, retained archived evidence locations, and explicit scope flags.
- [Payload SHA256 manifest](manifest.json): every payload file's physical size and digest. The manifest's own digest and the complete four-file directory inventory are supplied in the publisher's delivery receipt outside this directory to avoid a self-referential checksum.

Source Markdown snapshots remain inside the original archives. They are not extracted here as current repository Markdown. The archive has not been rebuilt, trimmed, or rewritten, and the fixed audit inputs remain unchanged. No repository checkout, Git metadata, or historical 624 MB binary corpus is included.

## Observed result and scope

The independent verifier read all 18,289 entries in the tracked commit tree and the actual bytes of 605 Markdown files (6,365,746 bytes). It checked 4,133 local inline links with zero errors. All 12 verifier tests passed, including true missing/case-mismatched paths, escapes, symlink loops, non-UTF8 Markdown, independence from the working tree, and a parser-drift negative that retains old regex text in comments. The canonical checker source is restricted to the independently reviewed SHA256 `0d7040ac82a54a97a2db0a3d94db30822a047af5a8f4946ff4d4fc29ae9a190f`.

**This audit did not execute the canonical `check_repository.py`. It does not claim a full repository, JSON/TOML/raw-fixture, Cargo, or complete CI gate.** The retained result explicitly sets `canonical_check_repository_executed=false` and `full_repository_gate_pass_claimed=false`. Fragment anchors and reference-style links remain outside the canonical inline-link grammar checked here. Other actual gates must retain their own results.

The committed-tree preservation audit retained all 1,328 ours-only paths, 4,331 integration-only paths, and 10,644 paths on which both parent trees agreed, byte for byte and mode for mode. Ten overlapping paths were composed; the four actual conflicts were CI/source-pin conflicts. Separate CI contract negatives passed 108 tests. The remote integration ref was observed at `cb314bb4656e5da4844325cd83994ab4764fe8e9` on 2026-11-08 at 00:10:45 UTC. This historical observation is not a claim that the ref can never advance.

This delivery step only copies the already verified original audit archive and writes this description, summary, and manifest outside the repository. It makes no source edit, commit, push, activation, physical-clock qualification, or global-execution qualification.
