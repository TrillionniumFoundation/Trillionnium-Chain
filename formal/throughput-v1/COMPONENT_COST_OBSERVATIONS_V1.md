# Complete-block and root-cost observation boundaries

Status: **component measurement / HOLD_NO_GO**. A decrease in state-application
count alone establishes no CPU or confirmed-business-throughput improvement.
The original fixed Host, confirmation rule and campaign deadlines remain
unchanged. These explicitly selected measurements create a separate development
profile, with their actual compiler, binary, source scope and resource
observations retained by the caller.

## Complete block

The existing native test
`pon_executor::repeated_sender_tests::repeated_sender_complete_block_cost_observation` calls
both complete M06 implementations on the same signed input and parent state.
The input has 256 transfers to a common recipient, with 2, 64 or 256 senders
and four workers. For each distribution it retains two warmup pairs and twelve
measurement pairs. Even pairs run reference then candidate; odd pairs reverse
that order. All 84 original rows, including warmups, are required.

Each timed region includes decode, every signature verification, canonical state
execution, final root and worker startup/join. After each timed call, native
assertions compare the full state, receipts and root against the serial
reference, retain 256 signature verifications and confirm the parent state is
unchanged. The comparison itself and fixture generation/signing are outside
the timed region. Node ingress, W1 proof, consensus confirmation, SQLite
commit/fsync, network delivery and recovery are outside this experiment.

The [reader](whole_block_cost_metrics.py) checks the fixed census, pair order,
warmup membership, complete original field set, execution counters, canonical
root and finite positive wall times. It retains all twelve pairs in each
cohort and reports the two wall medians, their ratio and the median of paired
ratios as different descriptive quantities. It does not select the fastest
sample, drop a failed run, pool distributions or extrapolate to sustained
public traffic. A supplied raw digest binds bytes; it does not authenticate a
host, resource enforcement, independent ownership or a physical clock.

The native v1 record did not measure per-arm CPU. Those fields and CPU change
remain null. A parent collector may retain the whole child process's kernel
`wait4` user/system CPU and peak RSS, but that process includes both arms,
warmups, fixture setup and assertions. Its total cannot be assigned to either
arm or used as their CPU ratio. Confirmed business TPS and independently useful
tasks per second remain null in every complete-block report.

## Complete root encoding

The existing explicitly ignored
`pon_executor::streaming_root_tests::complete_root_encoding_cost` uses 16,384 deterministic
keys and 4,096-byte encoded values. `TRNM_ROOT_ENCODING_IMPLEMENTATION` selects
`original` or `streamed`. Each selected implementation runs in a fresh process
so one arm's RSS high-water mark does not carry into the next arm.

A paired caller must preserve all planned arms and failures, compare the full
root across every completed process, and retain compiler/binary/profile identity.
The returned root-call wall duration is different from whole-process wall,
whole-process CPU and peak RSS. An ABBA sequence with two observations per arm
is a diagnostic illustration, not a tail, confidence interval or independent
host experiment. These are synthetic state values rather than ledger-admitted
accounts. Root encoding is not the complete incremental-root, cold-recovery
or business path.

## Original resource gate

The original four-second acceptance profile remains 0.25 CPU, 2 GiB, zero
swap, 256 PIDs, sixteen hostile inputs, and the installed depth-and-work rule.
The [unchanged prerequisite observer](host_prerequisites.py) must observe its
root-owned parent and exact unit before the corresponding owned campaign.
Missing kernel observations leave that campaign NOT_RUN and business metrics
unknown. The source checks and development observations above cannot replace
this gate, increase its deadline or reinterpret a historical failure.

## Reproduction

The original ignored tests are selected by their exact full names after
listing the built binary's tests. Use the repository's Rust 1.95.0 toolchain,
locked Cargo graph and a declared release profile. Retain the build command,
all stdout/stderr, actual exit status, source files and binary SHA-256. Do not
reuse a source or binary identity from a different run.

The reader's command-line help specifies the pinned stdout and process receipt
inputs. Its zero exit means a complete component readback, while the JSON
qualification remains `HOLD_NO_GO`; exit 2 denotes invalid/incomplete evidence.
The [regressions](test_whole_block_cost_metrics.py) cover incomplete and duplicate
samples, wrong order, changed workload, inconsistent roots, invalid timing,
failure/ignored-test summaries and claims that would promote this measurement
to CPU or business throughput.

The [component runner](run_component_observations.py) takes two already-built
libtest executables and a new output directory outside Git. It verifies each
actual test inventory, runs the fixed block/root plan, the complete request
observation unit module and the real TCP cancellation case. Every native test
process runs once. It keeps stdout/stderr and whole-process `wait4` records,
verifies binary file hashes before and after each invocation, and preserves
failed or unexecuted items. Endpoint file hashes are not an executed-image or
build-source attestation. A caller must retain the separate build receipts and
source guard. The dedicated native CI job supplies these on its exact head,
using a separately named development profile rather than the original Host
business acceptance profile.
