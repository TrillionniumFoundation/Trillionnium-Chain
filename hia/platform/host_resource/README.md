# Native aggregate Host resource owner

This candidate reads the original fixed cgroup parent through real Linux system
calls. Its input contains only a sample operation and qualification controls;
the caller cannot provide counters, paths, identity, quotas or a successful Host
verdict. The owner acquires and privately retains the original boot, device,
inode, UID and finite limits through the frozen Host acquisition implementation.

Each sample performs the complete fresh Host check, retains only that check's
local parent descriptor for `cpu.stat`, `memory.current` and `pids.current`,
closes it, and performs another complete fresh Host check. Every file is opened
with `O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK` and independently checked
as a regular file. Reads continue through short reads and `EINTR` to real EOF;
the CPU bound is 2048 bytes and each scalar bound is 64 bytes, with an additional
overflow probe byte. All three reads and UTF-8 validations complete before
semantic parsing. Duplicate unknown CPU keys are rejected as well as duplicate
required keys. Required counters and unsigned arithmetic follow the original
Rust field order, including zero, a leading plus, and the full `u64` range.

`sample` returns six actual values and stores a private baseline. `sample_delta`
requires that baseline, obtains another complete physical sample, and checks
the four CPU subtractions in their original order. Memory and PID values remain
point-in-time observations. A rewind refuses the operation; it never becomes
zero CPU, paid credit, a refund or a replay decision. Failed operations terminate
after cleanup and publish no qualified numeric sample. The private baseline is
updated only after successful complete sampling and any requested delta.

The composed program imports the complete, byte-identical frozen
[`host_checkpoint/owner_policy.hepta`](../host_checkpoint/owner_policy.hepta)
helper body and reuses its exact read-only Linux adapter. The resource owner
defers the pending close only after that helper's complete initial inode fence
and original-limit comparison succeed. The FD remains entirely inside the HIA
owner. The second check freshly opens the path again. No checkpoint source is
modified. The HIA source and HIA emitter are compiled by the pinned native HIA
compiler; Python only builds and qualifies the resulting static ELF.

The production image uses `/sys/fs/cgroup/trnmponpublic.slice`, requires its
parent directory to be owned by UID 0, and preserves the original at-most
0.25 CPU, 2 GiB memory, zero swap and 256 PID
limits. The explicitly separate fixture entry uses private test paths and the
actual test UID. Fixture success grants no production cgroup authority.

The original service's entry sample precedes listener operation. Its terminal
sample occurs after all owned service/miner/poller/Host workers join. The optional
request-observation output write must first succeed, then original service,
Host observer, miner and poller errors are propagated in that order before the
resource sample and checked delta. This component does not move those Node
boundaries. Per-thread paid
CPU accounting, external `wait4` child ownership, durable operation settlement,
the combined Node and the original four-second/16-request service acceptance
remain separate integration obligations. A whole-parent CPU delta is not any
one worker's CPU bill; memory is neither an RSS sum nor a historical peak.

The [development record](../../qualification/host-resource-development.json)
retains 183 actual native controls, 172 original-Rust case comparisons covering
180 operations, 44 original Host tests and independent actual syscall tracing.
Three source-integrity test groups and seven actual malformed bundle invocations
exercise complete source-set admission. Those results retain their development
source identities. Exact committed-source CI separately requires real tracing
and the same native corpus in actual original Rust. Fixed-parent production
resource sampling, the complete Node and original service budget remain open.
No Rust source or original service gate is retired by this component.

## Same-job production qualification

The production controller reuses only the sealed fixed parent created by this
same hosted job's successful exact-source Host qualification. It never creates
or repairs a parent and never substitutes a fixture, supplied counter or cached
Host verdict. Before acquiring its controller lock, it validates the complete
Host build and actual production report against the current source, executable,
run and attempt. The previous before/after records must have the same complete
eight-key binding; the original creator must equal the previous current service.
It compares the original lease and immutable parent identity again. Only the
newly owned current service may differ during fresh resource execution.

The controller creates only its uniquely named resource service inside that
already qualified parent. Native acquisition, one sample and two checked deltas
must emit four receipts with full-check counts 1, 3, 5 and 7. The per-sample
counter_reads field is 3 for every successful sample; it is not a cumulative
3/6/9 counter. An independent trace must observe the actual CPU, memory and PID
files through each captured parent FD, regular-file checks, exact bounded reads,
real EOF and close before the next complete Host check. All remaining Host
syscalls are audited with the existing complete Host trace verifier. Live TID,
membership and executable observations bind the actual process. The image owns
every read and decision; the controller only verifies its observations.

The source set now contains 52 exact inputs, including the complete Host build
closure, both production controllers and their tests, the three CI execution
helpers and the reviewed systemd unit. The source set is checked before and
after execution and in the finally path, including when native execution or
cleanup fails. The old 30-input development/CI records retain their identities.
Old valid reports cannot qualify changed current sources or a new kernel lease.

The native-host CI job runs all 18 production-controller refusal groups before
any parent provisioning. After actual Host production success it builds the
exact resource image and invokes:

```sh
python3 -B -m hia.platform.host_resource.qualify_production \\
  --build "$RUNNER_TEMP/hia-native-resource-production/build" \\
  --lease-receipts "$RUNNER_TEMP/hia-native-host-production" \\
  --output "$RUNNER_TEMP/hia-native-host-production/resource"
```

TRNM_CI_RECEIPT_DIR is the same Host production receipt root. Failure observations
and both builds are retained by always-run source checks and explicit artifact
collection. This extends the existing 20-minute Host job without weakening any
original limit or adding a fixture fallback.

The [production development record](../../qualification/host-resource-production-development.json)
preserves the first real fixture-trace failure, its corrected actual execution,
the final pre-lock lease guard and the complete controller sources. That fixture
is not a production parent. The [preceding committed Host successes](../../qualification/host-production-ci-success.json)
belong to exact head 34ecf1b; both its push and PR workflows completed all 14 HIA
jobs. Fresh fixed-parent resource production on this new source remains NOT_RUN
until its own exact-source hosted job completes. No full Node, paid-thread CPU,
original service budget or package retirement is accepted by this controller.
