# Independent current-source readback: Chain 362fbebe

DRAFT / SHADOW_ONLY / HOLD_NO_GO / DENY_ALL.

This is a readback of actual GitHub Actions logs at commit `362fbebe5027d731f16c88f710bfef7e922cd230`
and tree `5a7a2eadfcfb75b9fdf38fa0e8a05c6a503d776d`, retrieved on 2026-11-04.
No new native invocation, source implementation or performance acceptance is created.

## Existing fix supersedes the unpublished proposal

The owner branch progressed through c5dd7c, b4bdf14 and 362fbebe. Its evaluation
fixture now uses the existing metered Submit dispatcher with the same Node CPU
domain at both previously unmetered retained-fork activation sites. The source
checks exact retained packet bytes, stored-block count, generation, known charged
CPU, zero live owners and unchanged CPU identity. Its separate actual TCP control
keeps the original unmetered refusal and establishes readiness through pinned Head
responses before stopping and joining each listener. The independent unpublished
History-page proposal was not submitted; it is not counted as a delivered fix.

The owner's existing C1 hosted evidence reports all nine original Host selectors
successful in both lanes, including evaluation sync, followed by a distinct
public_submit_recovery failure. That earlier executed cohort is c5dd7c, not
362fbebe. The new owner's Submit correction requires its own complete runtime
terminal; both new runtime jobs were still in progress at this readback cutoff.

The owner's W1 history count is now 25/1 and its fresh source producer writes
the canonical source.json. This independently covers the two fixes in Draft #700;
the #700 branch and its historical failures are retained.

## Actual current failures

The current campaign job 126300603089 / run 41746463223 builds successfully and
executes all three exact original release selectors. Each returns native 101,
with elapsed times 109.728930527, 109.037178157 and 108.931509807 seconds. All
three keep their 600-second outer stage bound, original 30-second phases,
[0,24,24] attacker counts, 21 business blocks, 4 seed blocks and 1,024 seed transfers.
No phase startup, report-shape or source/binary-finalization failure was reported.
The original campaign business requirement remains failed. This readback does
not re-extract the large report ZIP, so it does not invent the latest per-phase
confirmation counts from an earlier cohort.

The current fresh-service head and actual-merge jobs 126300606020 and 126300605572
both compile and pass source/Host preparation. Their actual Host controller reports
no controller failure and no final Host errors, with original fixed parent limits.
The child command returns 1 and the controller correctly reports passed=false.
The exact inner fresh selector/report is in its original artifact, not this decoded
outer log; this record does not infer a new exact deadline error from an older run.

The 16 other current W1 jobs completed successfully. Individual W1 components do
not qualify fresh service or the original four-second/six-depth/16-hostile gate.
Issue #639 and parent #629 remain OPEN.

## Reproduction and byte boundaries

Run `python3 replay_decoded_logs.py` in this directory to verify every included
file against FILES.json and reproduce the narrow source/command/Host/failure
assertions. The verifier executes no repository source or native test and does not
download artifacts. Assertions use explicit exceptions, not Python assert.

The three .decoded.log files are the complete UTF-8 text returned by the GitHub
job-log connector and then encoded as UTF-8. Their hashes describe these retained
decoded bytes. Uploaded ZIP digests quoted in the logs are uploader-reported
metadata, not a newly performed independent ZIP or ELF rehash.

A pure JavaScript reader performed the same source, JSON, original-parameter and
failure checks in the active tool environment. Its SHA implementations were
checked against standard empty/abc vectors and an existing exact Git source blob.
The Python replay was authored but not executed because the execution environment
is unavailable. The repository shell preflight was likewise not runnable here.
This authorized evidence-only publication changes no production files, gates,
budgets, assertions or qualification flags. The original owner Actions and all
previous failures remain intact. The remote files are subsequently read back
byte-for-byte from this independent research branch.
