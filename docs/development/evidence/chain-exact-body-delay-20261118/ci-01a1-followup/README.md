# Exact-head CI failures and report retention follow-up

This directory preserves the actual CI observations for candidate
`01a1db507b0ff39dee39f635855479be93dcd7bb` in Draft PR #955. It does not
declare the whole candidate passing. The original finite 4-second result remains
bound to native candidate `974049daa4b72825332b07b59084cb70f4b4c8b5` and run
44309944062 in the parent evidence directory. The native `trillionnium/` tree
has no changes between 974049d and 01a1db5; the exact-head workflow results are
still separate observations.

## Actual results at the retained readback

| Workflow run | Actual observation | Classification |
| --- | --- | --- |
| 44316662837, required baseline | Pending, no conclusion and no jobs at the readback | No baseline pass or failed step available |
| 44316662918, recent batch | All four x64/arm64 and head/prospective-merge cells failed the mixed-service assertion, with 130 attempts and `finite_target_met=false` | Actual business gate failure; per-attempt cause is missing from retained artifacts |
| 44316663108, W1 work security | Both fresh-service cells passed the original same-packet business case and failed the fresh-challenge business case | Actual new-challenge liveness counterexample under the original host limits |
| 44316663073, original budget controls | Three historical before-source cases rejected preparation with `IDENTICAL_GROUP_TESTS_LOCK_AND_PROFILE_REQUIRED`; zero native control processes started | Source/profile comparability guard, not an executed native business result |
| 44316662661, CodeQL export | Analyses/checks did not complete and stabilize before the export deadline | Evidence-export readiness timeout |
| 44316662872, owned process cleanup | Two macos-15 cells cancelled with no steps, `runner_id=0`; six other cells succeeded | No execution evidence for the cancelled cells; cancellation cause is not established |

The original results and all nine selected provider ZIPs are retained unchanged.
The detailed classifications, exact source IDs, job IDs, failed steps, before/after
source observations and costs are in [readout.json](readout.json).

## Mixed-service failure and missing detailed evidence

Each of the four recent-batch logs contains two actual executions:

- The public network business case passed, with 24 native confirmations, 52
  false calls and seven overlapping false calls in its own separate report.
- The mixed/reopen case failed at `public_v3_service_campaign.rs:399`, with
  130 total attempts and `finite_target_met=false`.

The two outcomes are not combined into one passing test. All four jobs exited
101 after `1 passed; 1 failed`.

The tested workflow set `TRNM_CI_RECEIPT_DIR`, which the network case consumes.
The mixed case instead consumes `TRNM_PUBLIC_V3_CAMPAIGN_DIR`. Without that
variable, the existing test writes its report into a `tempfile::TempDir`, which
is removed when the failed test unwinds. The complete uploaded ZIPs contain the
network report and the failing mixed log, but no mixed request/phase report.
Consequently the actual refusal, mutation, or gap predicate responsible for
these 130-attempt failures cannot be recovered from the retained originals.

A static possibility is that eight sequential repeated false bodies, delayed
by the new bounded 500-ms scheduling rule, outlive the fixed sequence of sixteen
honest probes and exceed the test's 2-second final gap rule. This is an inference
for the next retained run to resolve, not a measured cause or a reason to relax
the assertion.

The follow-up changes only the workflow environment to place the existing mixed
report under `recent-exact/mixed-service`, already covered by the unchanged
`if: always()` artifact upload. Its one changed workflow blob is rebound in the
existing corpus. The Rust tests, attempt counts, 500-ms call deadline, 2-second
gap, 4-second pressure window, verification rules and resource budgets remain
unchanged. [retention-change-provenance.json](retention-change-provenance.json)
records the original and resulting workflow/corpus hashes. No native rerun was
used to validate this retention change locally. Any naturally triggered future
CI belongs to the successor commit.

## Fresh-challenge result with complete original reports

Both cells used the actual original root-controlled host resource boundary:
0.25 CPU, 2 GiB memory, zero swap and 256 PIDs, with sixteen attack workers and
the original 4-second window. Source and original limits were checked before
and after execution. The original host receipts and all inner reports are in
the two fresh-service provider ZIPs.

| Cell | Same-packet pressure confirmation | Fresh-challenge pressure confirmation | Fresh pressure independent replay |
| --- | --- | --- | --- |
| x64 head 01a1db5 | 1/1, 3.700896235 s | 0/1 | First page accepted; second page rejected `PUBLIC_REQUEST_DEADLINE` |
| x64 prospective merge 684d0fe | 1/1, 3.500007489 s | 0/1 | First page accepted; second page rejected `PUBLIC_REQUEST_DEADLINE` |

Each fresh pressure run admitted all seven honest submissions. Both network
History fetches succeeded before the deadline. The failure occurred in the
independent client's native `history_import`, rather than in admission or a
reported socket error:

- Head: first page replay ran from 1.983241652 s to 3.678988879 s; its calling-thread CPU was
  75,309,069 ns (excluding scoped worker CPU), with an initial native CPU-wait
  interval of 489,937,008 ns
  wall time. The second replay started at 3.875566666 s and ended with the
  original deadline rejection at 4.075719131 s. The late return is a failure,
  with no post-window confirmation credited.
- Prospective merge: first replay ran from 1.896524116 s to 3.798330464 s. The
  second started at 3.995750029 s and was rejected at 4.000512713 s.

The head constructed and submitted 260 distinct challenges/packet indices;
the report records all context bindings and challenges as unique. The bounded
exact-body scheduling delay therefore does not establish protection for this
distinct-challenge workload. This is a retained limitation, not a production
qualification or a reason to change the deadline.

Whole fresh pressure process cost was 1,084,144,160 CPU ns / 4,540,971,297 wall ns
for head, and 1,074,258,916 CPU ns / 4,356,594,965 wall ns for prospective merge.
Those include failed calls, independent replay, joined workers, shutdown and
state readback. Separate preparation/build costs are retained in the original
host controller and preparation records. Nested actor/dispatch/Host intervals
are not added to whole-process totals. Energy, monetary cost and whole-research
cost remain unknown.

## Original evidence and reproducibility

The retention change passed the original three inline source-pin controls,
four recent-suite count controls, all 114 source-integrity negative controls,
the complete original corpus checker and the complete CI contract checker.
Validation used a separate complete checkout with 40,964 tracked paths at
01a1db5 plus only the two-file retention/binding patch. No native business
test was rerun locally. [source-validation.json](source-validation.json)
records the commands, wall times, original logs and changed-file SHA-256.

The first validation attempt on the deliberately sparse native publication
checkout could not open the test script and executed no assertion. The new
complete validation worktree also first hit the unchanged development-branch
preflight while detached; creating a task-owned development branch at the same
commit satisfied that original rule. Both preparation failures are retained in
[validation-preparation-failures.json](validation-preparation-failures.json).
The publication preserves the exact commit through a native Git bundle import
and the original checked-out-HEAD push rule, without widening the old sparse
checkout or overwriting its working files.

[artifact-inventory.json](artifact-inventory.json) records all nine original
ZIP IDs, 15,541,643 total ZIP bytes, provider and independently computed SHA-256,
and the name, byte length and SHA-256 of every member. The provider ZIPs are in
`artifacts/` without repacking. The two complete fresh reports can be read from:

- `artifacts/14435722444.zip`: `fresh-service/original/report.json` and
  `fresh-service/fresh/report.json` (head).
- `artifacts/14434382569.zip`: the same member paths (prospective merge).

`raw-results.tar.xz` retains the original read-only GitHub responses and job
logs, including unsuccessful log retrievals for cancelled jobs.
`source-01a1.tar.xz` retains the exact relevant workflow and Rust sources;
their Git blobs and SHA-256 values are also in the readout.

The original 974049d x64/arm64 finite-window success, the new 01a1db5 mixed/fresh
failures, and the retention-only successor's future CI remain three separate
evidence layers. General distinct-body/Sybil fairness, independent WAN service,
public-network readiness and production activation remain unqualified.
