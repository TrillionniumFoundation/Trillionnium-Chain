# C2 publication: original CLI failure and REST correction

These are two separate, completed observations. The first operation pushed C2 normally through the existing project pre-push hook, then failed while updating the PR body through `gh pr edit`. The second operation updated only the reviewed PR body through REST and read it back. **The push ran once; the REST correction did not repeat it.**

| Observation | Original result |
| --- | --- |
| Original job `1a1c90b18dc-135c4-3a1` | Eight commands: seven exit zero, `gh pr edit` exit 1. The ordinary `git push` exited zero, the existing pre-push hook returned `PASS`, and remote readback advanced from C1 to C2. |
| CLI failure | `Projects (classic) is being deprecated`, at GraphQL field `repository.pullRequest.projectCards`. The original `failure.json` and raw stderr are retained. |
| Missing original tail | The original `summary.json` and `source-after.json` were never written. Their absence is recorded in the packaging index; neither file has been synthesized. |
| REST job `1a1c90f4721-135c4-3af` | Five commands, all exit zero. PATCH submitted only the reviewed body. Its response and a subsequent GET both contain the exact reviewed bytes. |
| PR readback | PR [#901](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/901), open and draft, actor `ProfHepta`, head `0e554f36ffdde3053a5eb1756eb5e526b1935032`. |

The original controller completed the push at `2026-11-11T05:19:06.839667+00:00` and retained its later CLI failure at `2026-11-11T05:19:26.735025+00:00`. The separate REST summary was finalized at `2026-11-11T05:23:28.168851+00:00`. Its SHA-256 is `3090779b55352e4608d651590ddf6a8189c6529b16a43bf5e07f6a5a0327b587`.

The reviewed body is 6,679 bytes, SHA-256 `859bd019bfad528e9269980eee5717d6f5d7de2a6ac8781b22a00ae070c7cb95`. The archived REST request contains exactly one property, `body`, whose bytes match that file. Before the REST correction, the PR body still matched the original pre-push observation. The retained PR responses keep base `31543fb6dde565b62b47436e0b1d399b6d0bd772` and the same base/head branch names throughout.

## Original-byte archive

`publication-originals-0e554f36ff.tar.xz` is **16,680 bytes**, SHA-256 **`2a1b7c7fd36c83add8a6a417a8c6019f3588b775648ea675455f62a000d86ceb`**. It preserves **62 original files / 151,064 bytes**, plus `archive-index.json` with every original absolute path, byte length, and SHA-256. Its sections are:

- `original-cli/`: the unchanged first operation's receipts, streams, failure, and observed source-before record.
- `rest-correction/`: the unchanged REST operation's receipts, streams, body request, summary, and its own source-before/source-after records.
- `controllers/`: the two exact original controllers requested for retention.
- `reviewed/`: the exact reviewed PR body.

The original archive path is `/data/pq-closure-publication-originals-0e554f36ff-d4d2.tar.xz`. Packaging job `1a1c915f4ea-135c4-3d3`, key `pq-closure-c2-publication-evidence-pack-0e554f36ff-d4d2`, read only the two finished output directories and three requested input files. It checked them again after archiving, including the missing original tail. No publisher/source checkout was read or changed by the packager, and neither original controller was executed again.

`h-packaging-observations.json` preserves the initial bounded file read, packaging launch, and packaging stdout/stderr; `h-transfer.json` preserves the archive's immutable-read version and the single complete binary-read chunk. The packet's verification uses original command receipts and retained API response bytes. It does not make a new GitHub query or depend on a newly queried H terminal status.

## Portable verification and scope

Run from this directory:

```sh
python3 -B verify_publication.py
```

The verifier checks the archive and all original member hashes, both exact command rosters, all 26 command stdout/stderr hashes, original failure and missing files, one normal push, the original hook result, remote C1-to-C2 readback, actor, REST request scope, precise PR source identity, and exact reviewed body readback. `publication-observation.json` records the actual offline verification command and result. `PUBLICATION_SHA256SUMS` covers all delivery files other than itself.

This packet preserves publication facts. It adds no test passes, does not turn the first failed controller run into success, and does not fill its missing source-after record using the separate REST observation. The earlier `cloud/` and `desktop/` packets remain unchanged. Publication to a draft PR does not establish whole-chain post-quantum qualification or production activation; both qualification fields remain false in the original REST summary.
