# C5 GitHub business-job failure readback

This directory records four **completed failed jobs** for PR 782 after candidate
`034aa74358e0a5fa33f33e83cb63669e9738da4b` was pushed. It is a read-only investigation
of those executions. No job was rerun and no source, budget, deadline or workflow
was changed. Other jobs that were still running are outside this readback.

## Observed outcomes

| Job | Actual source exercised | Result supported by retained evidence |
| --- | --- | --- |
| Original native campaign, job 128636161917 | C5 head `034aa74358e0a5fa33f33e83cb63669e9738da4b` | Build succeeded. Three declared campaigns actually executed, each exited 101 and reported `finite_experiment_criteria_met=false`. All nine 30-second phases failed their full criteria. |
| Retained pressure failure, job 128636161686 | Workflow head is C5; historical payload was not obtained or executed | Retrieval of artifact 11531476198 from historical run 37730166589 found zero artifacts. The subsequent diagnostic step was skipped. This is missing historical evidence, not a new measured business failure. |
| W1 fresh service, job 128636161803 | C5 head `034aa74358e0a5fa33f33e83cb63669e9738da4b` | Original and fresh native controls both actually executed. Original exited 0 but failed the separately checked confirmation target; fresh exited 101 at the original four-second/six-depth business assertion. |
| W1 fresh service, job 128636161664 | Prospective merge `991168a783c3bf82e04f978091adbdc740998c47` | Same observed failure categories as the head lane. This is a distinct tested commit, with tree `8dd452c376452224602fb202940ae84fc1f84d2e`, equal to the C5 tree. |

All four job metadata records have C5 as their workflow `head_sha`. That field
must not be substituted for the prospective-merge lane's actual tested commit,
or treated as proof that the missing historical payload was exercised.

### Original native campaign

The three actual attempts retained the declared baseline/from-zero/late-product
order, 30 seconds per phase, and 0/24/24 attacker processes. Both pressure modes
reported all 24 actors ready. There were no reported phase startup errors or
report-validation failures. Report hashes and each attempt's stdout/stderr pins
match the downloaded bytes.

In each baseline, round 0 reached depth 6 inside the phase window; the next
recorded round did not. Each pressure phase had zero timely confirmations.
All nine phases record `PUBLIC_REQUEST_DEADLINE`, incomplete full signed-round
confirmation, and unequal final receiver/client state. The genuine paid-credit
depletion predicate also remained false. Thus this is an actual finite business
criteria failure, not a failure to build or launch the experiment. The outer
failure is `ORIGINAL_THREE_RUN_CAMPAIGN_FAILED`; the native assertion reports
`finite experiment criteria failed`.

### Original and fresh W1 service

Both lanes retained the original 4-second window, 16 pressure workers, and
observed public-parent limits `cpu.max=25000 100000` and
`memory.max=2147483648`. In both original and fresh controls, the attack-free
baseline confirmed one transaction within the original window (approximately
3.02–3.10 seconds), while the pressure phase confirmed zero. These pressure
phases retained `finite_business_target_met=false`,
`full_native_state_equal=false` and `overlap_demonstrated=false`.

The original control returned native exit 0 with protocol/accounting invariants
true, while the wrapper correctly retained `CONFIRMATION_TARGET`. Its last
pressure replay failed with `PUBLIC_REQUEST_DEADLINE`. Native exit zero is
therefore not evidence of passing the business target.

The fresh control actually constructed/submitted 213 unique challenges in the
head lane and 210 in the merge lane. Its last replay was accepted and
`verification_errors=[]`, but no timely six-depth business confirmation
followed. Its concrete panic is at `fresh_challenge.rs:244`:
“fresh challenges failed the original four-second/six-depth business target”.
The wrapper records `FRESH_NATIVE_PROCESS_REQUIRED` because this native process
exited 101. The fresh failure must not be described as the original control's
replay-deadline error.

These new records establish that the measured business gates still fail. They
do not, without a matched source comparison, establish that C5 introduced a new
regression. No cause is imported from C3, and missing artifacts are not assigned
a business verdict.

## Evidence and retrieval limits

- [summary.json](summary.json) gives exact run/job/source identities, failed and
  skipped steps, first/last concrete errors, inner outcomes, and claim limits.
- [manifest.json](manifest.json) hashes every retained file except itself.
- [fetch-manifest.json](fetch-manifest.json) retains all 11 job/run/log API GET
  attempts and their raw stdout/stderr hashes.
- [artifact-fetch-manifest.json](artifact-fetch-manifest.json) retains all three
  artifact metadata and ZIP fetches. Every downloaded ZIP SHA256 matches the
  digest printed by its own GitHub upload step.
- [extraction-manifest.json](extraction-manifest.json) maps 128 selected original
  artifact members to their retained bytes and hashes. Larger JSON reports are
  losslessly gzip-compressed; both original and compressed hashes are present.
  Full executable and SQLite payloads were not copied into this publication
  subset. The complete ZIP inventories and ZIP digests remain recorded.
- [inner-readback.json](inner-readback.json) preserves the detailed report
  readback, separately from the unchanged raw files.

Raw job logs are [native campaign](raw/original-native-campaign-log.log),
[retained pressure retrieval](raw/retained-pressure-failure-log.log),
[W1 head](raw/w1-fresh-head-log.log) and
[W1 prospective merge](raw/w1-fresh-prospective-merge-log.log).

All 17 GitHub GET requests completed successfully. The earlier Hepta preflight
launch response timed out at the transport boundary; same-idempotency readback
confirmed that the original preflight job had already succeeded without a
relaunch. That observation is preserved in
[preflight-fetch-history.json](preflight-fetch-history.json).
The historical artifact missing inside GitHub Actions remains a separate,
explicitly retained failed observation.

No production, WAN, hardness, payment, security, or original-business-budget
qualification follows from this archive. No new complete zkVM proof generation
was started by this investigation.
