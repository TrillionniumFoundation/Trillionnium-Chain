# N x64 cost failure: completed original-artifact review

## Result

The original x64 job 132415017426 in run 43582713392, attempt 1, failed its **business confirmation acceptance** with CONFIRMATION_TARGET. All five native test child processes returned exit 0 without timeout, and each original stdout reports one passed test. The confirmation test also reports finite_target_met=false; the original runner subsequently rejects its report. Test-method success and business-target success are separate observations.

The exact tested source is head 5a4b7fe8de1adce803184f262fd9f704ead1930c, tree 4bc5ade0813ba3172eeb0ad7425358469a1b1edd. The manifest's complete source-before and source-after records are equal and match the standalone source identity. This is the N head job, not a prospective merge or M8.

## Original conditions and observed boundary

Both original phases retain a 4,000,000,000 ns window and require one signed business transaction. The baseline uses zero attack workers; pressure uses 16, with all 16 worker records present.

| Original observation | Baseline | Pressure |
|---|---:|---:|
| Independently confirmed business transactions | 1 of 1 | 0 of 1 |
| Successful signed-submit ACKs | 7 of 7 | 7 of 7 |
| Successful History responses | 7 of 7 | 2 of 2 |
| Accepted independent replays | 7 of 7 | 1 of 2 |
| Verification errors | none | PUBLIC_REQUEST_DEADLINE |
| Finite business target | true | false |

Baseline business confirmation latency is 3.192652146 seconds. Pressure business begins 90.856880 ms after the original phase starts, leaving 3.909143120 seconds; it did not begin after the original window expired. The accepted pressure replay reports 1.690997151 seconds wall time. The failed or late replay reports 0.600477191 seconds wall time. The manifest does not supply the detailed per-call trace needed to attribute that delay to a lock, repeated computation, CPU scheduling, Host checks, or another micro-level cause.

The original service and sustained-report acceptance stages passed. The confirmation-report stage failed. Its retained bytes match the bytes examined by the original validator. The runner's terminal explicitly distinguishes completed child invocations from successful business acceptance; its legacy execution_finished=false is not evidence of a still-running child.

## Custody and limits

Artifact 14109658844 is exactly 9,884,207 bytes with SHA-256 10447497968910ffe69e51bd541f6dfe988293a86a2ab583120f3a25788c40b4, matching the official artifact metadata and original job upload record. Its 161 members passed the bounded safe-name, duplicate, symlink, size, CRC and SHA checks. The original ZIP is unchanged. Only the approved 17 manifest/source/process/stdout/stderr members were extracted and interpreted. Other members, including the large confirmation report and ELF, were hashed for custody but not executed or semantically analyzed.

The outer-log-only UNKNOWN findings remain byte-identical. This separate completion overlay adds the inner failure now directly evidenced by the approved artifact. No rerun, source edit, deadline change, worker change, dispatch, cancellation, or PR change was made. This N observation establishes no M8 failure, no general throughput/tail-latency qualification, and no production activation.
