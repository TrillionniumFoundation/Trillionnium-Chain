# Validation on the published implementation bytes

**Status: scoped local checks PASS; full business qualification HOLD_NO_GO.**

Code commit: `f0e702475e19f4ec456b11dce682f20cf59a81aa`.
Code tree: `93fbb686a983fa57e33791411fd3a18d6b2258ae`.
The later evidence delivery adds only files in this evidence directory and does
not relabel the delivered commit as a newly executed native implementation.

## Recovered workspace validation

After the temporary execution-environment outage, all 14 published files were
compared against their published Git blobs. They matched. Six actual commands
were then run in the selected-source projection, with separate raw stdout,
stderr and exit records; all published files matched again afterward.

| Suite | Distinct passing methods | Exit |
| --- | ---: | ---: |
| Original adoption reader | 26 | 0 |
| Original learning-iteration reader | 25 | 0 |
| Original completion reader | 13 | 0 |
| New native economic-readback controls | 29 | 0 |
| New business-join controls | 21 | 0 |
| Existing CI contract class with the new command group | 10 | 0 |
| Total | **124** | All zero |

There were no skips. Earlier runs and collector smoke checks are not added to
this count. This is a selected-source Python validation, not a full checkout,
Rust build, full native campaign or original-host performance qualification.

Two independent CLI invocations then replayed the original historical learning
materials. Their nested completion reports match the archived stdout bytes:

| Case | Outcome | Receipts | New business-report SHA-256 |
| --- | --- | ---: | --- |
| [adopt-v1](adopt-v1-review.json) | Selection, acknowledged next task | 7 | `2e6821f08b7cf76ceaf476d476609d562a4fcfabf291c09d4d12c6b448690645` |
| [no-update-v9](no-update-v9-review.json) | NoUpdate, acknowledged retained-model next task | 6 | `8a4b4861eab7c82296d9ef095584dcf7a54baef170b213839dc9606566d16d73` |

Both remain `DENY_ALL`, `NOT_EXPORTED`, `HOLD_NO_GO`, with no native funded
mapping, independent evaluator/consumer certification, real payment or FinalUse
acceptance. These commands did not train a model or execute a payment.

## Raw records and failures

The [archive](local-records.tar.gz) and its
[complete byte manifest](local-records-manifest.json) retain original command
logs, original-material inventory, pre-outage observations, exact-byte recovery,
post-recovery commands, two reader invocations and a hosted-workflow snapshot.
All archive members were decompressed and checked against their listed size and
SHA-256 before publication. [The structured summary](validation-summary.json)
records the scope and publication identities.

The archive keeps the first extra-terminal-LF materialization observation,
the later exact-source 64-method run, a real missing-import failure and its raw
log, and explicitly labelled tool-observation transcriptions for preparation
failures and environment interruption. The initial new diagnostic-name test
failure is a transcribed observation: it is not mislabeled a retained raw log.
No existing reader or historical refusal was changed to make these checks pass.

## Hosted validation remains a separate observation

The implementation-source push run is
[42628162579](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42628162579)
and the PR run is
[42628225393](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42628225393).
At the snapshot retained in this evidence, both scoped readback runs were
**queued**. No hosted PASS, full tracked-source execution result, whole native
workspace success or all-required-gates success is claimed here.

The source-bound workflow will retain its own before/after full tracked-source
checks and eight command outcomes. Its results cannot be inferred from the
local projection or from successful runs on another branch.
