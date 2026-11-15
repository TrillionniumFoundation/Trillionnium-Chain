# PR #688 concurrent-head and CodeQL readback

Snapshot interval: **2026-11-07 10:56:37–10:56:38 UTC**. This is a read-only
remote observation, not a rerun or acceptance of the throughput changes.

## Exact source identities

| Object | Commit | Tree / relationship |
| --- | --- | --- |
| Frozen local native-validation checkout | `a9efd4cba7546a8ef1e854ee0acdce9f5903ac2d` | `807e589d4cb8c2c0d2c2123e8e4ff0870d6a1eb7`; clean when rechecked |
| Unpublished remote throughput code commit | `b59610295776ea44694ecef97d9f0e1de40bba0c` | Same tree; parent `e70f13448aad715286fb8eb56fc802b09db643a3`; zero all-event Actions observed before publication |
| Concurrent PR #688 head | `271a87f831aa7e08f3c2024f738504c1422122dd` | `48f13f9cbc6cbaf62e5e6d08e934e593bf9b3c25`; same `e70f134...` parent |
| PR #688 base/main | `dd6e1c3cbeacbdc532b0679297835b3a0aac78f0` | Unchanged at this snapshot |
| PR #688 prospective merge | `3851387e5015a51f119bca9d24bf845aac05e870` | Belongs to concurrent head `271a87f...` |

[PR #688](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/688)
remains open, draft and merge-blocked. The concurrent head was committed at
10:36:20 UTC and changed exactly two files relative to `e70f134...`: the same
SQLite script-blob pin repair and the CodeQL workflow. It contains no native
runtime change. Its CodeQL workflow adds before/after exact-source receipts,
uses explicit `upload: never`, and retains artifacts even on failure. The
integration owner is reconciling these changes in a separate publication
worktree; this readback did not move either branch.

## Complete current-head workflow denominator

The exact-head Actions REST query had no event filter, requested 100 per page,
and returned **20 of total_count 20**. All matching pages were covered:
**18 pull_request + 1 dynamic + 1 push**; **11 success, 4 failure, 5 in progress**.
See `remote-head-snapshot.json` for every run ID, immutable source, event and
timestamp. Active runs are not successes and this is not a final CI result.

| Current-head observation | Exact run / job | Result |
| --- | --- | --- |
| Original native campaign | [42364678224](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42364678224), job `128380125651` | Failed original campaigns step |
| Fixed Host ROOT F0 | [42364678199](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42364678199), job `128380125519` | Execution and finalization failed |
| Local CodeQL SARIF, PR event | [42364678169](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42364678169) | Rust head and merge failed source-after identity; Python/actions four lanes passed |
| Local CodeQL SARIF, push event | [42364669362](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42364669362) | Rust failed source-after identity; Python/actions passed |
| CodeQL analysis exporter | [42364678188](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42364678188), job `128380125642` | **Success** at this new head; earlier `e70f134...` exporter timeout remains historical |
| Required baseline | [42364678236](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42364678236) | Still running; observed failed x64/ARM from-zero and head/merge protocol-contract jobs remain failures |
| Priority / History and PQ | [42364678301](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42364678301), [42364678201](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42364678201) | Still running; no completion qualification inferred |

## CodeQL failure is retained; the changed paths are unknown

Rust head job `128380125550` and merge job `128380125435` generated parseable
SARIF (`CODEQL_SARIF_FILES=1`) and then failed with
`ValueError: source is not clean`. The exact-source check includes all untracked
files, so this error alone cannot establish that a tracked `Cargo.lock` changed.

Downloaded and SHA256-verified Rust head artifact
[13571835350](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42364678169/artifacts/13571835350)
is a 124,960-byte ZIP with SHA256
`fc5222469c377fd1e589709d62153f74abfc5359516cb61683f0fe37c1c2238f`.
It contains only `rust.sarif` (4,128,200 bytes) and `source-before.json`
(423 bytes). There is no source-after receipt, porcelain inventory or tracked
diff. The SARIF invocation says extraction succeeded; this does not satisfy
the separate unchanged-source requirement. The logs identify CodeQL CLI 2.27.4.

The publication-worktree diagnostic addition writes the complete porcelain
status, the unstaged tracked diff and the staged tracked diff into the existing
identity artifact directory **before** the original strict source-after check.
It preserves `verify_ci_source.py` and the before/after `cmp`, restores or deletes
nothing, and grants no acceptance. A synthetic staged + unstaged + untracked
worktree confirmed the three receipts retain the changes while leaving the
source untouched. YAML parsing, shell syntax and `git diff --check` passed.
Actual hosted source-dirty attribution remains unresolved until those receipts
exist; no lock-file repair is justified from the present artifact alone.

## Correction to the earlier PR #760 characterization

At the exact pinned action commit
[`1fc58d04a4d4374f921bdac573c3811c240f9c26`](https://github.com/github/codeql-action/blob/1fc58d04a4d4374f921bdac573c3811c240f9c26/src/actions-util.ts#L175-L197),
`getUploadValue` maps the deprecated string `false` to **`failure-only`**.
It does **not** mean unconditional suppression of all SARIF uploads. The
concurrent `271a87f...` workflow uses **`never`**, the explicit no-upload mode.
The publication integration should describe PR #760 as a reviewed intermediate
correction superseded by the concurrently published workflow, not assert that
its `upload: false` unconditionally disabled uploads. Historical e70f upload
errors and the new source-after failures retain their distinct identities.

## Gates still open

The eventual combined publication source has not inherited any hosted result
from `271a87f...`, `e70f134...`, child PRs or the same-tree local commit. Its own
head and prospective-merge CI remain required. The original four-second,
16-worker service gate and complete 4,105-history durable activation gate have
no new passing observation here. Current active PQ/History jobs are incomplete,
and a successful analysis exporter does not qualify whole-chain PQ, production
activation, WAN finality, saturation TPS or proof replacement of native replay.

All changes by this acceptance pass are limited to the three diagnostic commands
in the publication worktree and these scratch drafts. The frozen main validation
checkout remains clean at `a9efd4c...` / tree `807e589...`.
