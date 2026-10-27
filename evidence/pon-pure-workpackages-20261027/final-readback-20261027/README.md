# Final readback snapshot: 2026-10-27

**Time-bound previous-source evidence. Hosted CI is not accepted.**

This metadata-only snapshot preserves the exact Chain and Hepta publication
identities and their actual observations. The source run/check lists are fixed
at **2026-10-27 10:51:11.474-10:51:11.842 UTC**. Selected job details were read
at 10:51:48 and completed-job logs at 10:52:42; each original timestamp remains
in its raw record. Later source fixes or CI conclusions do not replace this
snapshot. A queued or running check is never counted as success.

The proposed addition consists only of this README, [manifest.json](manifest.json)
and [readbacks.tar.gz](readbacks.tar.gz), on a separate documentation/evidence
branch based on the published Chain tree below. It does not change runtime
source, production/main heads, model adoption, or the fixed PR 506/4080 pins.

## Fixed publication identities

| Scope | Published head | Exact tree |
|---|---|---|
| Chain draft PR 506 | `0c804e9f5bcf6e972bbb4524c744d4b3c8801c34` | `ebd3545aac5815260ec1f94a2b9a2f383e8dd051` |
| Hepta draft PR 4080 | `2bfceaa3226611a72f43d24e67d13e30091c7449` | `c307ee700d9b1d8e8a7ec113c831d9e22fbed713` |
| Separate BLOCKED M06 evidence branch | `eb36361d4d412a369ff7909f91407a1fa2103ef8` | `82f6e9cf9e826758fd87c50f33a2f56dcd98a756` |

The Chain tuple remains source `0c804e9...`, base
`57c1ed545d067937cbd7aaa7570d5f22123265e6`, and GitHub's actual prospective
merge `e22045b22fcda846d826243210c998a97d4559a3`. The Hepta tuple remains source
`2bfceaa...`, base `3e9efb15faa261a4dc3ffc3205cd259aaee41a3f`, and actual merge
`66298edad48fe11253b6a311b2ca2749584d8e06`. The full ordered-parent and native
merge-tree checks are included byte-for-byte, including their scope limits.
A successful identity comparison does not certify runtime or CI acceptance.

The complete original c4a2 metadata and 3e222 pin commit archives are included
without changing any ID, parent, date or payload. Their raw Git commit payloads
are separately retained and SHA-1 checked. API-created remote commits and the
publication-only reachability merge have their own identities; original
measured IDs are not rewritten to impersonate them. M06 remains outside the
main candidate's implementation and ancestry.

## Actual source CI at this snapshot

| Source | Workflow runs | Check runs |
|---|---|---|
| Chain | 12 total: 5 queued, 3 running, **2 failed**, 2 successful | 64 total: 25 queued, 13 running, **7 failed**, 18 successful, 1 neutral |
| Hepta | 4 total: 3 queued, 1 running | 12 total: 10 queued, 2 running |

The lists retain endpoint, page size, pages fetched, total/returned counts,
source SHA and UTC. Selected later diagnostics do not retroactively change
these frozen counts. The original Hepta pair workflow really triggered as
run `40491440610`; its four Linux source-head/base-merge matrix jobs were still
queued at their job readback, with no model-step execution observed. Triggered
or wired native owners are not completed FinalUse/holdout evidence.

The completed-job diagnostics retain three concrete failure categories:

- The recent-batch workflow's exact-source fixed-blob guards disagree with two
  of sixteen pinned objects. Actual tracked-source verification succeeded;
  the native test stage was not reached in that run.
- One ARM release toolchain setup failed on the `cargo-clippy` installation
  conflict before Cargo build. This alone is not proof of a Rust compile
  regression.
- The from-zero native libtests passed, but report validation failed with
  `CONFIRMATION_TARGET`. Passing libtests does not establish the report's
  confirmation/service predicate; its precise failed flag still needs the
  actual report artifact.

Seven annotation endpoint attempts were refused by the connector's allowed
endpoint boundary and are preserved as error readbacks. Retrieved completed
job logs and the observation's stated limitations remain authoritative; no
missing annotation or incomplete job is converted into a pass.

## What the archive retains

The finite archive contains the three final publication receipts, both native
pair verification receipts, original local c4 validation logs, complete c4a2
and 3e222 original commit archives and raw payloads, all files of this frozen
CI observation and its collector manifest, and the final dcdf0503a M06 review.
Every member has a byte count and SHA-256 in the manifest; all archive members
were read back and checked after packing. Original files are copied as bytes,
not regenerated from a filtered or edited interpretation of their contents.

The review was performed read-only by another agent under the **same operator**.
Its historical filename contains `independent_review`; this means a separate
source review, not an external audit or independent security acceptance.
Its BLOCKED findings remain: honest large-State paid service failed, a caller
withholding the original frame leaves a different honest mutation at 0/1,
and the affected M06 suite retained 373 passes, 1 failure and 3 ignored tests.
The already sealed M06 evidence pack is not rewritten by this metadata bundle.

The c4 local logs retain 91 passing CI-contract controls and 34 passing source
integrity controls, including intentionally failing negative-control receipts.
Those local controls are not a hosted CI conclusion. This snapshot grants no
whole-chain post-quantum, independent WAN, all-honest saturated service, model
improvement, production self-upgrade or production-activation qualification.
Model adoption remains **NO_UPDATE**. If source successors are prepared later,
they need their own exact-source evidence rather than relabeling these results.
