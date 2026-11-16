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
