# d873 History pages: original availability gates remain failed

The bounded History implementation and its native regressions are complete on
`d87357de197db5ff750d08c96d52432e5d22a0b4`. The original hosted four-second gate
and the separate original three-run native campaign both executed and failed
their business predicates. This record retains those failures and the exact
source, binary, Host and timing evidence. Successful ACKs and a complete History
response do not establish independent confirmation.

This is an evidence-only continuation of the tested candidate. Its additional
files do not change that candidate's source or inherit qualification for a new
code tree. PR #753 remains a draft stacked on the existing #688 integration
branch. No main qualification, activation, public throughput estimate or general
four-second confirmation-security claim is made.

## Exact source and binary identities

| Identity | Value |
| --- | --- |
| Tested head | `d87357de197db5ff750d08c96d52432e5d22a0b4` |
| Tested tree | `323d99df3155b2242aec70c1cc11215bbade2807` |
| Ordered head parents | `e28ac65b0727eb98fb2bb67291870c16587c59ad`, `a3e9002cd12ef90d62f8b252cad570e72dab6fa3` |
| #753 integration base | `a3e9002cd12ef90d62f8b252cad570e72dab6fa3` |
| Tested prospective merge | `6f03626963aa2145b53acce3f5f9254e7ff81410` |
| Ordered prospective parents | `a3e9002cd12ef90d62f8b252cad570e72dab6fa3`, `d87357de197db5ff750d08c96d52432e5d22a0b4` |
| Prospective tree | Same `323d99df3155b2242aec70c1cc11215bbade2807` |
| Four-second binary, both lanes | SHA-256 `f0eba36388fbe8ea212622f21b46adf1e966f637155d859efafe0b00c3511699` |
| Separate native binary | SHA-256 `4bb386830f6db35f51331dd10c5e14272f063f5556067b283e6d8e744c846521` |

Before/after source receipts and retained binary bytes agree. The prospective
merge is into #688's branch, **not main**. See the
[original gate summary](original-gates-summary.json),
[prospective identity](prospective-source-identity.json), and the exact receipts
inside [the Host/build archive](hosted-source-host-build-and-failure-receipts.tar.gz).

## What the candidate changes

V3 serves up to 16 consecutive History packets within 1,048,064 raw bytes
(2,096,128 hex bytes) and one cumulative 1,024-SQL allowance. It retains fixed-tip,
ancestry, parent, height, cursor, cancellation and corruption checks. Packet
formatting occurs after releasing the Node owner lock. These are same-owner
current reads, not a SQLite transaction snapshot. The original V2/local
single-packet API remains.

Actual signed submission recovery and peer polling now validate every returned
packet. Native admission remains per packet, with final-tip activation only at
the target. The generic importer rejects a page continuing beyond its fixed tip
before admitting any of its packets. Its new actual-chain regression covers
shared/exclusive access, an already-complete cursor, exact completion, durable
state, cold reopen and original CPU settlement.

Changed signed resource and arithmetic contracts use fresh r16 identities;
historical r10-r14 mappings remain exact. The concurrent a3e9002 rank research,
prepared SQL and SQLite build changes are preserved. The
[composition invariance receipt](../original-gate-invariance-after-composition.json)
records unchanged original four-second tests, Host checker, runner inputs,
fresh-service job block, native workflow and all 21 tracked lock/requirements
inputs. The fixed-tip importer is an intentional production change and is not
described as byte-identical to the baseline.

## Original four-second Host results

All lanes used the original one-quarter CPU, 2 GiB, no-swap, 256-PID Host and
16 pressure workers. A successful business result requires an independent
client to finish full replay and depth-six plus required-work confirmation
inside the original four-second window. Build and Host provisioning passed.

| Lane and scenario | No-attack confirmation | Pressure ACKs | Pressure History | Pressure confirmation | Actual stopping point |
| --- | --- | --- | --- | --- | --- |
| Head, original packet | 1 at 3.012580060 s | 7/7 | One response, 7 packets, complete | 0 | First packet W1, `PUBLIC_REQUEST_DEADLINE` |
| Head, fresh challenge | 1 at 3.007573084 s | 7/7 | One response, 7 packets, complete | 0 | First packet W1, `PUBLIC_REQUEST_DEADLINE` |
| Prospective, original packet | 1 at 1.897753394 s | 7/7 | One response, 7 packets, complete | 0 | First packet W1, `PUBLIC_REQUEST_DEADLINE` |
| Prospective, fresh challenge | 1 at 1.883493609 s | 7/7 | One response, 7 packets, complete | 0 | Page CPU wait, before packet decoding/work |

All four pressure phases report `no_attack_accepted=true` and
`accounting_closed=true`; all report `full_native_state_equal=false`.
Fresh challenge pressure constructed 198 distinct challenges and recorded 182
full transcript refusals on head; the prospective lane recorded 169 and 153.
Deadline cleanup after four seconds is retained as failure, not credited as an
extended confirmation window.

| Pressure phase | Last honest ACK | Complete History returned | Replay refusal returned |
| --- | --- | --- | --- |
| Head, original | 2.277124877 s | 2.673800618 s | 4.074280806 s |
| Head, fresh | 2.571323800 s | 3.064638535 s | 4.063169043 s |
| Prospective, original | 2.671357772 s | 3.075949755 s | 4.071989186 s |
| Prospective, fresh | 3.160444420 s | 3.653855217 s | 4.053762916 s |

The change demonstrably delivers the full seven-packet page under pressure.
It does not make the remaining independent replay fit the original deadline.
Raw reports are retained without reserialization:
[head/original](four-second-head-original-report.json.gz),
[head/fresh](four-second-head-fresh-report.json.gz),
[prospective/original](four-second-prospective-original-report.json.gz), and
[prospective/fresh](four-second-prospective-fresh-report.json.gz).

Original hosted sources:
[head job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42320841942/job/128244737579),
[head artifact](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42320841942/artifacts/13553258857),
[prospective job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42320841942/job/128244737639), and
[prospective artifact](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42320841942/artifacts/13553858028).

## Separate original three-run native campaign

This workload retains three 30-second phases per run, 0/24/24 attackers,
21 business blocks, four seed blocks and 1,024 seed transfers. It is distinct
from the four-second fixture. All three runs built, started all required actors,
passed the actual Host controllers and reached business execution. No startup
error or report-validation failure was recorded.

| Run | Baseline | From-zero pressure | Late-product pressure | Original campaign result |
| --- | --- | --- | --- | --- |
| 1 | 14/14 ACKs, 2 History responses; first round at 27.590810092 s | 7/7 ACKs, 1 History response, 0 confirmed rounds | 7/7 ACKs, 1 History response, 0 confirmed rounds | Fail, exit 101 |
| 2 | 14/14 ACKs, 2 History responses; first round at 27.597579755 s | 7/7 ACKs, 1 History response, 0 confirmed rounds | 7/7 ACKs, 1 History response, 0 confirmed rounds | Fail, exit 101 |
| 3 | 14/14 ACKs, 2 History responses; first round at 27.004876446 s | 7/7 ACKs, 1 History response, 0 confirmed rounds | 7/7 ACKs, 1 History response, 0 confirmed rounds | Fail, exit 101 |

All nine phase predicates are false with `PUBLIC_REQUEST_DEADLINE`.
Baseline's first confirmed round does not complete its original three-round
business target. `economics_complete=true` does not override failed business
criteria; `genuine_budget_depletion_observed=false` is retained.

Exact complete reports: [run 1](native-run-1-report.json.gz),
[run 2](native-run-2-report.json.gz), [run 3](native-run-3-report.json.gz).
Original [job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42320841936/job/128244736749)
and [artifact](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42320841936/artifacts/13552933660).

## Failure localization and its limits

The [retained phase analysis](retained-failure-latency.json.gz) covers the old
baseline, both current four-second lanes and all nine native phases. The
[server analysis](retained-server-latency.json.gz) independently reproduces the
canonical wire digest and uniquely matches 84 honest Submit requests and 27
History requests to server observations; it records no missing observations or
measurement failures.

On head's original/fresh pressure phases, the complete History response leaves
1.326/0.935 seconds. The client first waits approximately 0.400 seconds for its
cold page CPU budget, then reaches its deadline inside the first W1 verification.
M06 has not started. History RPC wall time is 396/493 ms, but the server's
body-decode-to-response-encoding interval is only 6.132/5.935 ms. The latter
includes owner acquisition, current reads and formatting; it is not an isolated
SQL measurement. Encoding and response writing have substantial wall time.
No actual History SQL-step count, separate owner-wait measurement or scheduler
trace exists in these reports.

The same exact four-second binary measures roughly 54 microseconds CPU per
Host checkpoint on the head runner and 25 microseconds on the prospective
runner. Normal controls perform approximately 8,800 checkpoints in both lanes.
The original 0ca272d controls also measure about 24 microseconds per checkpoint.
Host checker, ingress authority, scalar CPU accounting and History observation
source blobs are unchanged. These observations do not establish a code-caused
twofold regression. Raw old reports and their manifest are retained as
[original](original-0ca272d-original-report.json.gz),
[fresh](original-0ca272d-fresh-report.json.gz), and
[identity](original-0ca272d-manifest.json).

In native run 1 baseline, first-page replay takes 5.372 seconds CPU and 24.172
seconds wall. Host checkpoint observations account for 4.557 seconds CPU across
83,053 calls. Admission and activation take 3.463 and 1.448 seconds CPU;
account-graph observations total about 4.03 seconds CPU. These measurements are
nested and must not be added together. The actual SQLite commit API totals only
about 9 ms CPU for this page; this is not evidence that commit/fsync dominates.

The state-call audit closes 84 `verify_state` and 62 `account_graph` calls:
seven admissions contribute 56/36, nine activation write transactions contribute
27/25, and final confirmation contributes 1/1. Existing parent-epoch reuse,
post-write readback and bounded subtree reuse already eliminate some safe repeat
work. Crossing the remaining writes or transactions requires a new equivalence
proof, including foreign mutation, trigger corruption and transaction-ABA
controls. A successful cached decode is not such a proof.
The [M06 reuse audit](m06-reuse-options.json) distinguishes this source-and-root
call decomposition from a per-call runtime trace and names the existing
foreign-write, trigger-corruption, partial-frontier and transaction-ABA controls.

The [Host options audit](host-fresh-read-options.json) derives a normal-path
lower bound of 29 filesystem calls per checkpoint from source; it is not a
measured syscall trace. Rust 1.95 already uses a stack buffer for these short
paths. An absolute `CStr` experiment could remove short copies but no filesystem
calls; no speedup was measured. Retained directory FDs and mount-ID fences do
not yet preserve all current-path/ancestor-permission observations. No Host
authority cache, skipped checkpoint or speculative cross-transaction state
receipt is included in the candidate.

The [service scheduling audit](scheduling-options.json) also finds no evidenced
minimal scheduling change that preserves the original semantics and closes this
failure. Read queues and FIFO reservations already exist. The independent
verifier's cold CPU account and attack-side local work do not pass through the
service's paid queue. Actual honest/attack transport keys differ, but arbitrary
key generation and rotation do not establish a stable economic principal.
This audit does not claim that all possible fair scheduling designs are impossible.

## Exact local validation on d873

The [local native summary](local-native-validation-summary.json) binds all stages
to clean d873 source before and after execution:

- Strict workspace/all-targets/all-features Clippy with `-D warnings`: pass.
- Original release build of six affected integration targets: pass.
- Actual release integrations: 29 passed, zero failed; 26 signed/socket recovery,
  one pinned peer, one campaign-profile binding and one network-business test.
- Component library: 78 unique selected tests, 76 passed, zero failed, two original
  entries ignored. The fixed-tip test also ran separately, so execution totals
  are 79 selected / 77 passed / two ignored. The History suite itself has
  29 passed and one ignored subprocess entry; its actual crash/recovery parent
  control passed.
- The component profile has opt-level 3, debug info 0, debug assertions enabled
  and overflow checks enabled. It is not the original release library profile.
- Locked/offline workspace and fuzz graphs, both format checks, 43 source-integrity
  negative tests, 37 PQ negative tests, 102 CI contract checks, 20 fresh-runner
  controls, 560 exact source pins and repository/inventory checks: pass.

All commands, profiles, logs, binary identities and counts are retained in the
[local archive](local-validation-logs.tar.gz) and
[source-check summary](local-source-validation-summary.json). The earlier e28
release-library SIGKILL build failures and unavailable-local-Host refusal remain
in the [previous record](../README.md); no result here deletes or reclassifies them.

The local network regression confirms 24 distinct transactions after full native
consumer replay and cold reopen, with 780 false transcripts rejected. Its
six-second setting bounds attack-call initiation only. Confirmation occurs after
attack join and service shutdown; it has no whole-chain six-second confirmation
deadline and is not original Host qualification. The original report's r10 scope
prose is stale; its exact signed policy is r16. See the independently checked
[network audit](local-network-evidence-audit.json) and unchanged
[full raw report](local-network-business-report.json.gz).

## Retention and independent inspection

The independent [publication audit](publication-audit.json) performed 3,106
retained-evidence checks, including 106 file hashes, and found no core numeric or
hash discrepancy. It separately fetched the
[prospective Git commit object](prospective-git-commit.json) to confirm the tree
and ordered parents. Its [read-only script](publication-audit.py) is retained;
these checks are evidence checks, not new native executions.

[retention-manifest.json](retention-manifest.json) records original and stored
byte lengths and SHA-256 values. `.json.gz` files decompress to the exact
original JSON bytes, without parsing or reserialization. Archive members are
also hashed individually. [original-artifact-inventory.json](original-artifact-inventory.json)
records all 1,880 original artifact members, including retained binaries and
databases, and the three original ZIP hashes. Those full ZIPs remain at the
original GitHub Actions artifact URLs; this evidence commit preserves the
complete business reports plus selected source, Host, build and failure receipts.

The two original analysis scripts are retained as
[analyze_existing.py](analyze_existing.py) and [analyze_server.py](analyze_server.py).
They use the explicitly recorded collection paths; reconstruct that layout or
adapt those path constants before rerunning them. Their output is diagnostic
readback, not an executed native test or a qualification gate.

Use [verify_retained_evidence.py](verify_retained_evidence.py) to check the
retained byte hashes, compressed originals, archive members and core failed
business predicates. It reads existing files and never starts a service, invokes
a compiler or changes an acceptance threshold.

Availability remains open. Any further implementation must earn its own exact
source, binary and original fixed-Host results.

## Other CI, observed once at 2026-11-07 01:43:12 UTC

All four recent-batch jobs (head/prospective, x64/ARM64) passed. Required-baseline
at that observation had 11 successful, four failed and four still-running jobs.
The four failures are the two cross-architecture cost lanes and the two
protocol-contract lanes. Their retained logs reach the original Host runner's
`systemd_run_exit=1` child failure after successful build and source checks;
those wrapper logs do not contain the specific child assertion. They therefore
do not establish complete correctness or identify a new source regression.
The four running Rust runtime/quality shards are not claimed as passed.

The timestamped [secondary CI snapshot](secondary-ci-observation.json) and
complete failed-job logs in the Host/build archive preserve that distinction.
No rerun, cancellation or new diagnostic job was triggered by this readback.
