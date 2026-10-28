# History checkpoint consolidation — 2026-10-28

**The local component correction is implemented and its final controls pass.
WP2B remains open: this is not a repeat of the fixed-Host campaign or WAN
acceptance.** The original 131f observation still has 0/27 confirmations and
0/6 attack phases reaching paid depletion; those denominators are retained in
[the original readback](../pon-131f-native-and-pq-readback-20261028/README.md).

## Change and preserved boundaries

Three adjacent duplicate `Control::check()` calls were removed from History
admission and activation. Each original progress boundary still calls
`history_checkpoint(..., || control.check())`. Its `observe_with_control`
loop executes the original resource callback before sampling CPU and again
before every refill wait. The callback retains the original absolute deadline
and real production Host verification. It is neither cached nor sampled less
frequently across ledger work. Shared owners still refuse a paid deficit while
holding the writer; exclusive owners retain their existing checked refill path.

No SQL traversal, authenticated root, nonce, reorganization, epoch, finish,
profile, refill, deadline, input selection, W1 relation or chainweight changed.
The W1 helper remains. See the exact [Rust diff archive](../pon-r8-evidence-transport-20261028/original-records.zip).

The original fixed-Host campaign's repeated account-graph validation remains
an expensive operation. This small patch removes duplicate Host file reads
around it without trusting a previous graph verdict. Foreign SQLite writes
must remain visible at the original checks; the retained graph and parent
controls explicitly exercise that requirement.

## Exact source and measurements

The clean baseline is `189ba3adfd9a22c7cfc1537eab535e9eb7c442df`, tree
`ff572fb27e4fb5df9a80b3e2ec5096c697964200`. Candidate observations were taken on
that base plus recorded dirty source diffs. They are not relabeled as clean
committed-source builds. Every command retains its exact argv, start time,
return code, timeout, subprocess CPU, peak RSS, streams, source manifest and
diff. The final 1,075 native/config/toolchain input bytes were compared back
to the final build manifest before packaging. Python reader edits were present
in some recorded whole-tree diffs but did not alter the native build inputs.

[source-binding.json](source-binding.json), the three binary metadata files,
[commands.json](commands.json), and the complete
[raw-observations.tar.gz](raw-observations.tar.gz) bind these observations.
[raw-files.json](raw-files.json) records every archived byte stream and SHA-256.
No native binary is embedded in this evidence package.

All builds used Rust 1.95, one Cargo job, offline locked dependencies and default
features only. The inherited Node test profile uses optimization level 3,
debug assertions and overflow checks; Node debug symbols alone were disabled.
No PQ feature, crypto execution, deployment or CI run was requested here.

| Observation | Result | Actual outer elapsed |
| --- | --- | --- |
| Clean baseline build | PASS | 357.20 s |
| First candidate build | PASS | 293.98 s |
| Corrected fixture build | PASS | 293.09 s |
| Clean baseline History group | 9 pass, 1 child fixture ignored | 7.006 s |
| Final History group | 12 pass, 1 child fixture ignored | 11.114 s |
| Final eleven native control groups | 72 pass, 0 fail; 4 original ignored entries | See observations.json |
| Strict Node lib/tests Clippy | PASS, `-D warnings`, default features | 56.067 s |
| Changed Rust formatting, locked Cargo metadata, diff whitespace | PASS | Individual command receipts |

Compilation times are not import timings and do not demonstrate a speedup.
The four ignored harness entries are two subprocess-only fixtures, a
release-only graph microbenchmark, and the real W1 depletion control that was
also run separately with its original `--ignored` selector and passed. Parent
tests actually executed five History SIGKILL cuts and three reorg SIGKILL cuts.
These are process crashes, not physical power-loss tests.

The final groups retain graph mutation, typed-BLOB and cancellation ordering;
inactive-parent and changed-root checks; CPU unknown, poison and settlement;
same-account reorg cancellation and real W1 depletion; Host-parent parsing and
the requirement for an actual fixed parent on the public route. The 34 source
integrity negatives were also executed in the separate reader evidence package.
Global CI source pins and the full integrated all-feature gates remain owned
by the integration task.

## New controls and preserved failures

The first-resource-failure test rejects before work starts, spends no CPU
principal, leaves the active state unchanged, and reopens with zero credit.
Eight authenticated-transfer controls cover Shared/Exclusive owners at W1,
M06, admitted and activation-progress boundaries. Fault-injected Host rejection
preserves the appropriate precommit or committed-but-inactive state, settles
the original account exactly, and leaves nonce unchanged. A separate permitted
retry uses that same owner/account, advances nonce once, and retains active
state with cold zero-credit accounting after reopen. These callbacks explicitly
report `real_host_revocation: false`; they are not real cgroup revocation tests.

The held-writer control executes full native W1 until the original cold account
actually refuses a paid deficit. The final observation crossed 144,519 original
checkpoints, paid 133,826,368 ns, began at zero credit and retained -2,767 ns
after real settlement. The real epoch close then fenced the original domain;
both the same Node and reopened Node refused an unclean epoch. The test uses
observed settlement balance: only an actually nonnegative final balance may
close cleanly, and even then reopen starts at zero. There is no synthetic debit,
refill injection or replacement account.

The first candidate run has 71 passes and one failure: the initial test
incorrectly expected clean epoch closure despite remaining negative credit.
Production correctly refused. That failure and its full streams remain, as do
the initial missing-PATH/wrapper-argument mistakes and the first offline build
failure caused by using an unpopulated Cargo home. The cache retry reused an
existing populated directory; no dependency or lockfile changed.

## Honest input comparison and limits

All seven original inactive-history requests pass in the clean baseline, first
candidate and corrected candidate. Packet IDs, per-page active tips, the final
activation boundary, zero initial credit and accounting identities agree.
The exact rows are in [honest-page-comparison.json](honest-page-comparison.json).

| Build | Seven request wall times, sum | Final cumulative paid CPU |
| --- | --- | --- |
| Baseline | 2,101,095,565 ns | 501,564,184 ns |
| First candidate | 2,009,841,353 ns | 478,596,564 ns |
| Corrected fixture candidate | 1,730,309,621 ns | 408,623,700 ns |

These are single observations with the existing private no-op resource
callback, not actual fixed-Host measurements. Variation between candidate
builds cannot be attributed to an additional production change: only the test
fixture changed. No throughput or confirmation improvement is claimed.
The actual 131f input set, fixed Host, all honest requests, malicious load,
real depletion denominator and confirmation denominator must still be rerun
on the integrated source. Crash-debt recovery remains a conservative unclean
fence, not known debt reconstruction or restored service. Independent WAN,
multi-day and different-administrator acceptance remain unmeasured.
