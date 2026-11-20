# Native finite PaidCPU account

This component owns a bounded native account epoch and executes its HIA work
inside the actual threads being measured. Its production executable reads one
192-byte work plan, creates one or two owner threads, creates at most eight
scoped workers per owner, joins every actual child, and writes one 1536-byte
diagnostic. The executable is a static Linux x86-64 ELF with no Rust, Python,
dynamic loader, or external meter in its runtime path.

This is a finite local profile. Persistent shared-domain handles, public intake,
authentication, deadlines, cancellation, termination continuations, the full
original block executor, Node State work, and the four-second / sixteen-attacker
service qualification remain open. Constructing this standalone epoch is not
permission to create a new serving account per request.

## Original contract

The source binding includes the complete original `scalar_cpu.rs`,
`request_observation.rs`, `pon_executor.rs`, the locked Cargo graph, and the
current shared qualification dependencies. The original production Rust prefix
is unchanged. The original comparison appends a private `cfg(test)` child only
to an isolated source copy and retains the resulting independently copied binary.

The native shared account keeps signed 128-bit credit, the original monotonic
watermark, outstanding reservations, unavailable state, and optional flow
diagnostics. It preserves the 2,000,000,000 ns burst, 250,000,000 ns/s refill,
100,000,000 ns start reserve, two-owner limit, and existing reserved fields.
No qualification changes those limits.

Refill compares signed 64-bit seconds and valid nanoseconds, computes the full
unsigned 128-bit elapsed amount, and updates a nonstale watermark before checked
refill arithmetic. Stale samples do not rewind the watermark. Known live CPU is
still debited after an unavailable latch. A missing reservation is not repaired.
Unknown settlement decreases an existing owner count without refunding its
principal; its booked flow principal remains outstanding. Flow arithmetic
failure may drop the optional diagnostic without fabricating a clean account.

Each operation pays the union of its actual owner interval and actual worker
intervals. Already paid live CPU is subtracted once from that union. Settlement
charges the unique residual; work is not counted a second time.

## Actual threads, clocks, and locks

The native adapter creates Linux threads with parent-set and child-clear TID
words, protected stacks, a real child-ready handshake, and private lifecycle
records. Only the creating owner joins a child. Shared `FUTEX_WAIT` uses the
actual clear-TID word; stacks and records remain live until the kernel clears it.
The finite roster does not reuse a lifecycle generation within one invocation.
It does not claim that an operating-system TID-reuse event was exercised.

`CLOCK_THREAD_CPUTIME_ID` executes in the actual working thread. The HIA work
body also executes there. The production ABI has no measured CPU, monotonic
timestamp, TID, generation, joined flag, or outcome input.

CPU sampling follows the locked rustix Linux raw backend used by the original
program: first `EINVAL` becomes unavailable without fallback; another first
error gets exactly one further actual raw call. A second error or invalid
successful timespec becomes unavailable. No third call is made. An unsuccessful
checkpoint does not advance its stored baseline. The request and worker owners,
rather than the primitive clock operation, apply the original Unknown latch.

Monotonic time uses `CLOCK_MONOTONIC` once. A failed call or invalid nanoseconds
causes managed panic. Any signed 64-bit seconds value is valid. The actual
account uses this clock while holding its own global mutex.

The mutex uses the original 0/1/2 acquire/release state. Contended waits use
`FUTEX_WAIT_BITSET_PRIVATE`, the full bitmask, and a null timeout. Wakeups do not
grant ownership without another atomic acquisition. When a clock panics while
request and global locks are held, the adapter poisons and releases global,
then request, preserving unwind order.

The HIA entry has three capability buffers: a read-only event, private
continuation memory, and the currently held mutable account view. Work mode has
a zero-length shared view. Switching from request to global retains the request
lock and private continuation identity. Collector state is serialized through
an internal native mutex; it does not introduce a new ordinary accounting error.

## Scoped work and outcomes

Both active and inactive plan profiles require worker count 1, 2, 4, or 8.
`min(workers, transactions) <= 1` runs in the owner thread and creates no worker
interval. Other profiles spawn in index order. Every successfully created
handle is joined, including after a later spawn failure or worker panic.

A partial start returns `WORKER_START` after all existing children retire.
After a complete start, worker panic wins over the first ordinary work error.
Canonical result validation follows those joins. Operation completion and final
settlement occur only after this real scoped lifetime ends.

Exit zero alone is not success. The output is a diagnostic that can report
Unknown, a poisoned account, a worker error, or an owner panic. Build and
qualification consumers inspect the complete framing and every relevant flag.
A panic during final settlement cannot be relabeled a returned original
settlement merely because some private prepared fields were already known.

## Private arithmetic and fault qualification

A separate 512-byte arithmetic fixture exercises full signed credit, wide
elapsed time, overflow, stale reads, reservation ownership, flow failures,
Unknown settlement, and exact residual attribution. It has a separate HIA entry,
separate emitter, distinct magic, and separate ELF. It accepts qualification
counter inputs only in that private image. The production ELF rejects its
frame. The private image rejects a production work plan.

The builder assembles all four checked HIA sources and requires all twenty
shared arithmetic/helper functions to have identical Core definitions between
production and the private fixture. It then invokes the pinned native compiler
and HIA emitters. No development Python author, assembler, or ISA generator
runs during build or qualification.

Native qualification retains complete real traces and raw input/output for six
work profiles, 67 arithmetic cases, thirteen actual fault histories, protocol
refusals, and altered-trace controls. The cold profile can legitimately earn the
original refill before its actual reserve if scheduling is delayed; it does
not assume that process startup itself guarantees a refusal.

The original negative oracle uses a separate controlled platform fixture:
before the new private process's unmodified loader executes, an owned ptrace
controller replaces only its initial-stack `AT_SYSINFO_EHDR` value with zero.
The original libc then takes its own raw clock path. Both the unchanged normal
vDSO baseline and the raw-fallback baseline are retained. These tests do not
claim ordinary vDSO error timing, retry behavior, or overhead.

Faults target actual syscall entry/exit in a traced descendant. Safe
`/proc/thread-self` observations correlate private oracle roles with the
kernel-reported writing TID; they contain no clock or CPU samples. Complete
original methods, actual Rust worker intervals, real joins, panic unwinding,
and settlement are then observed. The production HIA ABI is unchanged.

## Build and mandatory qualification

Use the repository's exact pinned HIA toolchain and native compiler settings.
Install the original reference toolchain with
`rustup toolchain install 1.95.0 --profile minimal --component rust-src`.
The oracle explicitly selects that toolchain, checks its exact compiler version,
fourteen standard-library source files, and both compiled standard libraries.
It binds the actual compiler and Cargo executable bytes before use, passes the
bound compiler path through `RUSTC`, and disables compiler wrappers. Unbound
compiler, wrapper, flags, target, and profile environment overrides are refused.
The host's actual libc and dynamic loader are recorded separately.

Generated outputs must be fresh directories outside `hia`. Cargo targets must
also be outside the original, component, and isolated source directories.

```sh
python -B -m hia.platform.paid_cpu.build --output "$RUNNER_TEMP/hia-paid-cpu-build"
python -B -m hia.platform.paid_cpu.qualify --output "$RUNNER_TEMP/hia-paid-cpu-native" --require-trace
python -B -m hia.platform.paid_cpu.rust_oracle --bundle "$RUNNER_TEMP/hia-paid-cpu-native" --output "$RUNNER_TEMP/hia-paid-cpu-original"
```

The original comparison requires the exact Rust compiler/std source contract,
the locked rustix archive and actual compiled backend, a complete current
source set, all retained original tests, and Linux positive clock tests that
cannot silently skip. A supplied bundle must match current top-level and build
source mappings exactly, and every native raw case is revalidated before Cargo.

Current-source checks run again after qualification, including failure paths.
A source check is not proof that a previous artifact came from a later commit.
The final integrated head must run its own mandatory CI job under the existing
twenty-minute budget.
