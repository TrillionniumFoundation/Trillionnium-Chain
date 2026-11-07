# Exact original-source acceptance readback

This record reads existing GitHub Actions observations on
`e70f13448aad715286fb8eb56fc802b09db643a3`, tree
`1fc19c44ab2d4b35672b25d0f4e4039b769cadea`. It executes no new native service
campaign and does not qualify the changed throughput candidate.

## Current denominators and original failures

[All-event Actions metadata](actions-e70f134.json) retains all 20 runs returned
by the exact-head REST query: 18 `pull_request`, one `dynamic`, one `push`;
11 success, nine failure, zero nonterminal. The repository-truth head and
prospective-merge jobs both passed. Prior packaging-marker failures are not
relabelled as failures of this source. Workflow successes do not replace the
original business gates.

The three downloaded ZIPs match the GitHub SHA256 digests in the
[artifact index](artifact-index.json). The retained gzip members contain the
complete original text, including failed process receipts, service reports,
native test logs and Host observations. The omitted-member inventories describe
the large original database, executable and packet materials separately; no
missing material is represented by a successful replay.

| Exact original observation | Baseline independently confirmed | 16-worker pressure independently confirmed | Pressure client/receiver denominator |
| --- | --- | --- | --- |
| Retained-packet stream, artifact `13566551605` | 1/1; 3,098,539,910 ns from business start | 0/1 | 216 attack attempts, seven signed submits, two History calls, 22 Head calls; 246 retained receiver connections |
| Fresh-challenge stream, same artifact, separate test | 1/1; 3,085,988,757 ns from business start | 0/1 | 193 attack attempts, seven signed submits, one History call, 18 Head calls; 216 retained receiver connections |

The original native test returned exit zero while its business gate remained
`CONFIRMATION_TARGET`. The fresh-challenge test returned 101 with
`PUBLIC_REQUEST_DEADLINE` on its first independent import. Caller attempts and
receiver connections are separate populations: failure before connection,
shutdown and unreturned transport work prevent equating their counts. Both
receiver snapshots retained every observed connection, but global worker CPU,
physical network traffic, disk growth and per-request RSS remain unknown.

[Service observations](service-raw-observation.json) preserve both streams and
their nested Host/native costs. The retained-packet baseline's seven independent
imports performed 8,838 Host checkpoints: 480,424,395 ns of checkpoint-thread CPU
inside 536,801,692 ns of replay-thread CPU. These inclusive measurements identify
a substantial diagnostic cost; they must not be added to the enclosing replay
CPU or converted into a demonstrated optimization benefit. The original
four-second window and 0.25 CPU / 2 GiB / no swap / 256 PID Host limits remain.

| Current History artifact | Returning import calls | Non-genesis database rows | Published active state | Last retained outcome |
| --- | --- | --- | --- | --- |
| x64 `13568123690` | 2,362/4,105 | 2,362 | Genesis, generation 0; no reorg row | Server exited at its original 1,800-second lifetime; next History RPC returned connection refused |
| ARM64 `13568038035` | 4,104/4,105 | 4,105 | Genesis, generation 0 | Reorg cursor 3,404, `done=2`; lifecycle records `PUBLIC_REQUEST_DEADLINE` at cursor 3,404 |

The ARM final import expression lasted 30,001,567,869 ns. All packet rows being
present does not imply publication. [History readback](history-readback.json)
retains exact read-only SQL queries, database hashes, complete native exit
records and process failures. This is distinct from the previously quoted
3,322 x64 returns and ARM cursor 3,407; those earlier observations are preserved
under their original identities and are not results of these downloaded jobs.

[Backend and stage attribution](history-stage-attribution.json) independently
binds the original test, `Node::open` call path, native observation and both
read-only SQLite schemas to **Legacy**, not AuthenticatedV1. The independently
recomputed Legacy schema ID matches both databases; neither has the
AuthenticatedV1 commitment/archive tables. The final History page triggers
the long activation only after the preceding packets have been imported.

The new Legacy arithmetic path therefore targets the ARM record's final
activation staging, pre-COMMIT active-State and publication root checks. It
does not replace admission/W1 replay, full SQL reads, cursor transactions or
deadline checks. ARM recorded 3,406 staging validations (12.368103786 seconds
wall) and 3,406 active-tail validations (5.611721846 seconds wall); these are
whole-stage intervals, not isolated or wholly removable root-arithmetic costs.
The x64 record never entered reorganization and has zero such observations.
This root change cannot directly repair its earlier import/lifetime failure.

## Reader repair

The v2 failed-confirmation summary previously retained the hostile worker CPU
roster but omitted its attempt denominator. The new `attacker_attempts` section
records every available hostile caller row, repeated packet attempts, failed
and late returns, exhausted construction without submission, unknown statuses,
missing worker/call lists and original attempt-cap observations. It keeps call
CPU nested inside worker CPU and recorded body bytes separate from transmitted
or physical bytes. Display error text does not become a typed receiver cause.
Late booleans have independent known/missing counts even when another clock
field is absent. Unknown-status rows retain their observed CPU, bytes, clocks
and diagnostic text in a separate bucket without claiming a submission.

[Current retained-packet readback](original-service-readback.json) now shows all
216 attack attempts: 200 refused, 16 client errors, 16 after the original window,
16 distinct recorded packet indices and 200 repeated-index calls. Its strict
gate still returns `CONFIRMATION_TARGET`; successful baseline observations do
not promote the failed pressure phase. Explicit v1 readback is byte-stable.

Executed local reader checks:

- `python3 -m unittest discover -s scripts/ci -p test_run_from_zero_native.py -v`:
  149 passed, including nine new denominator/negative controls. The final two
  regressions cover missing-clock late flags and unknown-status resource retention.
- `python3 -m unittest discover -s scripts/ci -p test_run_w1_fresh_service_v1.py`:
  20 passed.
- `python3 scripts/ci/test_pq_research_integration.py`: 37 passed after the
  independently reviewed one-blob repair below. Later combined-source pin and
  native checks remain the integration owner's responsibility.

## Reviewed source corrections

The exact one-blob correction from
[PR #768](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/768)
at `0c084aba1fcbe56ea1661231df24d9a069bda921` is included. The actual
`scripts/ci/check_sqlite_build_requalification.py` Git blob is
`54440d8968cf5eee063605aabf81ea0f4438daf0`; its prior expected blob
`3790ce2b25faf674258b6cd9c4e1a16b4ec74817` made all four exact-head/prospective
PQ lanes stop before native execution. The source guard and negative mismatch
tests remain in place; successful integrity checking still reports
`HOLD_NO_GO` for the unqualified product.

The integration owner also reviewed the two source/test file differences in
[PR #772](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/772)
at `1e1cc50a0367fd29f48d00db20f35134900c656e`: the rendezvous test waits for
actual accept-loop readiness before beginning its unchanged client timeout.
This record imports no child-branch test qualification. Final corpus pins must
refer to the actual reviewed combined bytes.

The historical exact-source CodeQL jobs also failed because GitHub's default setup
rejected the advanced-configuration upload. Run `42352433630`, Rust head job
`128343245431`, retains that server error. It is separate from service
performance and is not counted as a successful analysis export. The historical
CodeQL exporter run `42352433650` separately exhausted its 1,200-second wait.

The integration owner initially reviewed the one-workflow correction from
[PR #760](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/760)
at `4906dbad8e97c2a252a395b7b581ebbe21a59204`. Its `upload: false` value maps
to `failure-only` in the
[exact pinned action](https://github.com/github/codeql-action/blob/1fc58d04a4d4374f921bdac573c3811c240f9c26/src/actions-util.ts),
so it is not a complete upload disable. This preliminary choice is superseded
by the concurrent PR #688 commit
[`271a87f831aa7e08f3c2024f738504c1422122dd`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/271a87f831aa7e08f3c2024f738504c1422122dd).
Its full workflow is preserved: explicit `upload: never`, exact before/after
source verification and always-retained local SARIF/identity artifacts, while
repository default setup owns server-side uploads. The merged workflow adds
source status and tracked-diff diagnostics before the unchanged after-verifier.
The new Rust jobs generated parseable SARIF but failed the strict clean-source
check; the available original artifacts do not identify which paths changed.
These are failures, not qualified hosted analyses. This correction does not
rewrite historical failures or turn local SARIF into a server-side export.

The [concurrent-head readback](concurrent-271a/README.md) retains all 20 matching
Actions rows at 10:56:37–10:56:38 UTC, the complete selected failure logs, the
hash-verified Rust SARIF ZIP and the diagnostic-capture controls. Its denominator
is 11 success, four failure and five still running; the new head's separate
CodeQL exporter passed. This timestamped snapshot belongs to `271a87f...`, not
the final combined throughput source.

No native deadline, pressure count, History length, CPU/memory budget, consensus
rule, production flag or original failed observation is relaxed by this record.
