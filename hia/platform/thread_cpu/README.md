# Native thread CPU stamps and one worker lifetime

This component implements the original ThreadCpuStamp start, Clone, checkpoint
and consuming finish/value-drop primitives in HIA. The static Linux x86-64 image executes
CLOCK_THREAD_CPUTIME_ID inside the thread whose work is being measured. Input
commands cannot supply a measured duration, a TID, a thread generation, a path,
a clock identifier, an authority verdict or an arbitrary syscall argument.

The supported profile has the actual process main thread, one actual native
worker at a time, and 64 simultaneously live stamp capabilities. Only one lane
enters the HIA state machine at a time. Native private futex handoff transfers
execution between those two actual threads. The workload operation is bounded
native arithmetic used to verify this primitive; it is not the Node executor.

## Owned identity and consumption

The HIA owner reserves generation space before clone, then assigns the new
generation only after successful native clone and a child gettid/ready handshake.
The raw adapter uses the same aligned private u32 as CLONE_PARENT_SETTID and
CLONE_CHILD_CLEARTID. It joins with FUTEX_WAIT without the private flag, loops on
EAGAIN/EINTR, and reuses the guarded worker stack only after the join word is
zero. Ready and turn handoff use separate private futex words.

A stamp retains its owning native generation, actual TID and baseline. Linux
TID alone is insufficient because the operating system can reuse it. The
original Rust ThreadId is opaque and is not reused within a process lifetime;
these concepts must not be equated. The native generation is never input data.
A fresh child always has a different nonwrapping generation even if a future
kernel assigns an earlier numeric TID.

Each published stamp also has a private, nonreused object serial and 128 bits
read from kernel getrandom. The serial and capability are checked together.
Recycling a table slot cannot revive a consumed handle. A full table or exhausted
serial/generation space produces a separate finite-profile resource refusal,
without partially creating a stamp or turning the refusal into clock None.

Clone copies the original identity and baseline on either live execution lane;
it does not sample a clock. Copies advance independently. Checkpoint verifies
the actual thread before sampling and updates its baseline only after successful
clock conversion and checked subtraction. Failure retains the baseline.
Finish invalidates that copy before identity or clock checks, including on the
wrong thread; other copies remain usable. Explicit value drop consumes its copy on either lane
without clock sampling or an owning-thread requirement. This is the original
stamp value disposal, not the future paid operation's Unknown-on-drop policy.
Nested intervals are not additive.

The adapter fixes the clock ID to 3. Native HIA preserves the original signed
timespec conversions, nanosecond bound, checked multiplication/addition and
checked subtraction. It also preserves the locked rustix 1.1.6 linux_raw dynamic
clock backend's bounded fallback: EINVAL from the first call returns unavailable
immediately; any other first error makes exactly one further native call on the
same actual thread. A successful second call converts its own actual timespec;
a second error returns unavailable. A successful syscall with an invalid
timespec never triggers another call. The diagnostic clock counter includes
each actual attempt, while failed checkpoint leaves its baseline unchanged and
finish still consumes its copy before sampling. The stamp primitive itself
does not latch a global Unknown state.

This rule is an original dependency behavior, not an arbitrary retry policy.
The isolated original comparison verifies Cargo.lock's exact rustix package
checksum, the actual Cargo linux_raw/time compilation metadata, the backend
wrapper source, and every regular registry source file against that locked
crate before and after executing the retained original binary.

## Qualification and exact source binding

Build with the same pinned HIA compiler and Core toolchain as the platform:

    python3 -B -m hia.platform.thread_cpu.build --output /absolute/new-output

The build uses only the checked-in owner, fixture entry and literal HIA Linux
emitter. Development author scripts and GNU assembly are not build/runtime
dependencies. The emitter wraps the actual native policy in a static RX ELF
with an RW nonexecutable stack. The adapter's complete 1,900 instruction bytes
are checked against their reviewed SHA256.

The distinct fixture entry admits private baseline, generation/serial exhaustion
and same-numeric-TID alias controls; production rejects every such opcode.
The alias control preserves the old generation and copies only the actual current
TID inside the native fixture, to isolate generation ABA refusal. It does not
claim a kernel actually reused a TID. Separate explicitly labelled
ptrace fixtures alter a syscall's return/error or output timespec in both the
native and original Rust executable. Those fixtures prove conversion/failure
semantics and do not count as real kernel-clock positives. The mandatory
original Linux control requires a real successful start and positive finish;
it cannot inherit the original test's unavailable-clock early return.

The trace audit reconstructs complete unfinished/resumed syscalls per TID. It
checks fixed mappings and guarded stack boundaries, actual child birth and
exit, private handoff versus shared clear-tid waits, actual clock IDs/TIDs,
complete stdin/stdout bytes and receipts, and random capability bytes. It does
not pretend strace exposes the memory load that observes the zero join word;
that guard is also bound to the reviewed native instructions. Repeated real
births with different TIDs are not evidence of actual kernel TID reuse.

A real SIGUSR1 control interrupts the main thread's blocking read and the
worker's private turn futex, then requires successful CPU work, finish and join.
The trace auditor pairs the kernel ERESTARTSYS pseudo-result with actual signal
delivery and rt_sigreturn(-EINTR) on that same TID; dropping any event is refused.
This control does not claim a signal was observed inside the brief shared
clear-child-TID join wait. That wait's EINTR loop remains instruction-reviewed.

The native bundle and builder must contain exactly the complete current source
mapping, including comparison hooks and tests. Original comparison uses a
private cfg(test) child appended only in an isolated source copy. The original
production prefix is byte-identical, the original repository is unchanged, and
all original inputs and the actual Rust binary are rechecked before and after.
The complete binding includes the workspace manifest, lockfile and Node manifest.
The original 53 histories remain an exact ordered corpus prefix. Additional
persistent errno histories exercise failed fallback for start, checkpoint and
finish, alongside the retained first-EINVAL and successful-invalid-timespec
controls. Controlled syscall results remain separate from real-clock positives.

## Remaining integration boundaries

This finite component does not implement the shared signed i128 paid CPU
epoch, reservations, live debits, unique residual settlement, global Unknown
latch, Mutex poisoning policy, full scoped-worker spawn/join/panic semantics,
Node work embedding, wait4 child accounting or the original four-second service
gate with 16 attackers. An independent meter process is not a substitute for
embedding these primitives in the Node's actual executing worker. The old Rust
owner remains required until those independent boundaries close.

References: the checked original request_observation.rs, scalar_cpu.rs and
pon_executor.rs are complete source inputs. The platform contracts are documented
by [Rust ThreadId](https://doc.rust-lang.org/std/thread/struct.ThreadId.html),
[Linux clone](https://man7.org/linux/man-pages/man2/clone.2.html),
[set_tid_address](https://man7.org/linux/man-pages/man2/set_tid_address.2.html)
and [futex](https://man7.org/linux/man-pages/man2/futex.2.html).
