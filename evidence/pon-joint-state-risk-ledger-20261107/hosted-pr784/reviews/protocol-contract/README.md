# PR784 hosted protocol-contract failure review

This is a read-only diagnosis of run `42431209912` on candidate `b5c655ebe9611b3d62cf739e61e6867decc053e3`. It neither reruns nor cancels a CI job, changes source, posts a GitHub comment, commits, nor pushes.

## First confirmed failure

The [prospective-merge job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42431209912/job/128580281614) failed the original `confirmation_report` acceptance stage with the sole recorded failure `CONFIRMATION_TARGET`. All five named native invocations returned exit 0 and passed; formatting, source checks, service-report acceptance and sustained-report acceptance succeeded. The overall native driver still returned failure, and subsequent protocol CI commands were not observed. A passing test process does not establish the original business confirmation target.

- [Machine-readable diagnosis](diagnosis.json)
- [Verified merge manifest](merge-artifact/from-zero-native/manifest.json)
- [Actual raw confirmation report](merge-artifact/from-zero-native/confirmation/report.json) and [selected observed fields](merge-confirmation-observation.json)
- [Exact acceptance predicate source excerpt](confirmation-predicate-source.txt)
- [Original merge job log](merge-job-logs.log) and [original job metadata](merge-job.json)

The full merge artifact is [retained here](merge-artifact.zip): 5,892,591 bytes, SHA256 `b3c76968c20a93663304e958c2a1aa68e791aca204c7715908e7a203fe54dafa`, equal to the digest printed by the actual upload step. Its 78 files were extracted without executing any contents.

## Head job: precise remaining limit

The [head job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42431209912/job/128580281524) also has an actual outer-controller failure: native preparation compiled successfully and source/host lease checks succeeded, but the systemd child returned 1 and the controller reported `passed=false`. The [original head log](head-job-logs.log) does not expose the inner first failure.

The [downloaded head ZIP fragment](head-artifact.zip) is **partial and unverified**, only 2,177,980 bytes. Its SHA256 is `4e428d751d7d58c4f0d35cea775012c259b43a749363a0f645dcb23a48a86a4d`, which does not match the uploaded full artifact digest `965cacdc613d27a1243d8619ce397f1de3bfc35ca0c431ec8c0977bcb148674d` (expected size 6,105,364 bytes). The [transport error](head-artifact-download.stderr) records a TCP connection reset. No inner head manifest was obtained, no incomplete ZIP was treated as a validated artifact, and no new download was started after the existing job completed. Neither merge nor ARM attribution substitutes for head evidence.

## Existing blocker versus new regression

[Source comparison](source-comparison.json) shows that the from-zero native/host drivers, observation and parent-lease code, and original from-zero native test/support files are byte-identical between base `cb314bb4656e5da4844325cd83994ab4764fe8e9` and this candidate. The [CI command diff](ci-job-diff.txt) leaves the original first from-zero invocation unchanged; added certificate commands occur later, after the failing first command. The selected [native composition diff](native-composition-diff.txt) is retained separately rather than pretending every native library is unchanged.

The [base plan excerpts](base-existing-business-blocker.txt) already document successful named native invocations followed by `CONFIRMATION_TARGET` rejection, and pressure-window confirmation remaining blocked under the original limits. This supports classifying the confirmed merge observation as recurrence of an already open business acceptance gate. It does not prove an identical underlying performance cause, rule out every performance regression, or establish the head job's missing inner cause.

The actionable follow-up is to diagnose the real honest-client submission/adoption/confirmation path under the unchanged original budgets and deadlines, against the same no-attack baseline and pressure conditions. Preserve the failed observation and target; changing thresholds or treating the child test exit codes as overall success would conceal the unmet business condition.

## Retained provenance

[Retrieval records](retrieval.json), [artifact retrieval records](artifact-retrieval.json), [job summaries](job-summary.json), original metadata/logs, verified merge ZIP and extracted files, the explicit unverified head fragment, source comparisons, and [file hashes](artifact-sha256.json) are retained. This review does not reclassify the separate repository-truth results or infer overall workflow completion.
