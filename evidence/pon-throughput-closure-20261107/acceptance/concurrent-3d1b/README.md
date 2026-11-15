# Concurrent head 3d1b650: read-only review

Observed 2026-11-07 at 11:17:27 UTC. Exact comparison:
[271a87f... → 3d1b650...](https://github.com/TrillionniumFoundation/Trillionnium-Chain/compare/271a87f831aa7e08f3c2024f738504c1422122dd...3d1b6507671ec694ce58e86d4063a125c8deeb66).

## Full delta and source identity

`3d1b6507671ec694ce58e86d4063a125c8deeb66` has sole parent
`271a87f831aa7e08f3c2024f738504c1422122dd` and tree
`88337d7d8e3c164f3367a1d4739b92f498943c32`. PR #688 remains draft/open/blocked,
base `dd6e1c3cbeacbdc532b0679297835b3a0aac78f0`; prospective merge is
`6afd57e4ac9aadc515a5f4bd2393cb85edad99f5`.

Exactly four paths changed:

| Path | Change |
| --- | --- |
| `.github/workflows/codeql-real-exact-source.yml` | Ten added lines: separate post-analysis diagnostic step; no deletion |
| `evidence/pon-current-inbound-history-e70-20261107/README.md` | New historical readback explanation, 145 lines |
| Same directory, `readback.json` | New retained historical results, 1,668 lines |
| Same directory, `reproduce.py` | New 200-line pinned-archive diagnostic reader |

No runtime, native test source, PQ corpus pin, resource budget or protocol change
is present. The added reader checks fixed original ZIP hashes, reads retained
records and queries copied SQLite main files read-only. It executes no native
binary; its successful exit means readback completion, not original acceptance.
The new History account distinguishes producer validator active height 4,105
from the independent confirmer's 2,362 retained imports and active genesis.
These are e70 historical facts, not results at 3d1b or the throughput candidate.

## CodeQL still fails, but the new diagnostics identify the path

The complete exact-head Actions query has 20/20 entries (18 PR, one dynamic,
one push): ten success, four failure, four in progress, two pending at the
snapshot. New CodeQL analysis export run `42366373961` succeeded. Local-SARIF PR
run `42366373938` and push run `42366364894` failed only their Rust source-after
checks; Python and actions lanes passed.

Downloaded head artifact `13572306286` and merge artifact `13572306317` match
their GitHub SHA256 digests. Their raw NUL-delimited status files are identical
(89 bytes), with exactly one entry:

```text
?? evidence/pon-w1-work-security-20261101/matching-direct-deps/harness/crypto/Cargo.lock
```

Both tracked `HEAD` diff-name and diff-stat files are zero bytes. This confirms
an untracked lock file on **these 3d1b runs**, not a tracked lock rewrite. It
does not retroactively prove the unrecorded changed path of the earlier 271a
runs. The exact raw files, archive identities and source-before receipts are in
`artifact-diagnostics.json`; no source-after success receipt is present.

The ten workflow lines are diagnostics, not a root-cause repair. They retain
`upload: never`, the original strict source guard and the before/after comparison.
The publication worktree's full staged/unstaged patches complement the new raw
NUL inventory; retaining both does not bypass validation.

## Recommended narrow repair, for the integration owner

Adding an independent `crypto/Cargo.lock` is appropriate as **new CodeQL scan
preparation**, subject to actual Cargo validation. The crypto manifest is a
standalone package with only `sha2 = "=0.10.9"` and `hex = "=0.4.3"` and no
workspace declaration. Its parent harness also has no workspace declaration.
The parent's retained historical lock does not establish the independent
package's lock file.

All five original `harness_before` / `harness_after` file hashes still match.
Keep those historical fields and bytes unchanged. The parent lock's dependency
closure for the crypto package contains 12 packages including its root; its
versions, checksums and original identity are provided in
`harness-lock-recommendation.json`. Prefer using that frozen closure when
generating the new standalone lock, then execute full `cargo metadata --locked`
twice and verify the resulting lock and all historical files remain unchanged.
The generated lock is a current scanning input; it is not a missing original
measurement artifact and confers no historical execution qualification.

The evidence package's `INDEX.json` explicitly enumerates packaged files and
requires later material to receive an additional entry. Give this lock a new
post-capture scan-preparation entry and explain it in the current throughput
evidence. Do not alter original manifests or relabel the old graph as matching
the production workspace. The historical wrapper intentionally references a
module whose old source symlinks were not archived; metadata preparation is not
a reason to recreate or substitute that missing measured source.

This review ran no Cargo command and changed no repository file. Actual lock
generation, two stable metadata checks and the next hosted full scan remain
the integration owner's work. Full source scanning and strict clean checks
remain required after the repair.
