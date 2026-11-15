# Native Linux platform qualification fixture

This directory contains one finite operating-system fixture, authored entirely
as HIA runtime sources. The locked native compiler compiles the policy and the
ELF byte emitter. The resulting emitter constructs a static Linux x86-64
executable that performs real file, TCP, epoll, clock, randomness and signal
operations. No C, Rust, Python, assembler source, libc, dynamic loader or host
callback supplies the resulting runtime's behavior. Python remains the explicit
build, test and observation driver.

**This fixture does not close the full-node I/O or durable-owner gates.** Its
five-second elapsed check only runs after a syscall returns. An idle blocking
read remains blocked beyond that deadline without an external wakeup. The
qualifier preserves that actual failure and its bounded external cleanup in a
separate result. Finite control success must not be used as permission to remove
the existing node, storage or transport owner.

## Reproduce the exact native route

Use the compiler revision in [toolchain.lock.json](../toolchain.lock.json) and
the compiler identity in
[compiler-binding.json](../qualification/compiler-binding.json). Set
`HIA_TOOLCHAIN_ROOT` to a tracked-clean checkout of that revision,
`HIA_NATIVE_COMPILER` to the qualified standalone compiler, and
`HIA_NATIVE_COMPILER_SHA256` to its bound digest. The driver refuses missing or
different pins. It never fetches a compiler or falls back to a hosted emitter.

From the repository root, choose a fresh output directory outside `hia/`:

```sh
python -B hia/tools/qualify_platform.py --output /tmp/trnm-platform-qualification
```

To build without running the controls:

```sh
python -B hia/platform/build.py --output /tmp/trnm-platform-build
```

The source-to-execution chain is:

1. Native compiler consumes the exact captured `probe_policy.hepta` bytes and
   returns its flat native policy image.
2. The same compiler consumes `linux_adapter_emitter.hepta` and returns the
   standalone native emitter.
3. That emitter consumes the compiled policy image and writes the final ELF.
   HIA code writes the ISA/header constants, computes relative displacements,
   patches actual sizes and copies the policy bytes.
4. The hosted driver checks the exact ELF structure and runs sealed snapshots
   of the resulting bytes. The executable contains an RX load segment and a
   non-executable stack. Its private arena is mapped RW.

There is no invocation of `ld`, an assembler, a C/Rust compiler or a Python
machine-code generator in this route. The driver binds both HIA sources,
`build.py`, the qualifier, this document, the ABI, the toolchain lock and the
preserved compiler qualification artifacts. It records every native stage's
input, output, command, SHA256, exit status, stderr and time budget. The actual
HIA compiler payloads must match the captured manifest. Inputs and compiler
identity are checked again after the controls.

The native compiler's acceptance is the language check in this route; the
hosted Core assembler is not invoked. Neither that acceptance nor the ELF
structural check proves that ISA bytes written as HIA data obey Core's buffer
effect model. The flat policy image is a trusted build artifact, not a public
input or a verified executable capsule.

## ABI and trusted authority

[abi.json](abi.json) is the machine-readable contract. All numeric words are
little endian. The policy entry is
`f0(event:readbuf, command:mutbuf, state:mutbuf) -> u32`. The adapter supplies a
64-byte event, a 4096-byte command buffer and a 4096-byte state buffer. A return
of zero requests the command, one completes successfully, and any other value
fails the fixture.

The event carries the actual preceding syscall result, command phase and a
fresh monotonic timestamp. The command carries a syscall number, six arguments,
a pointer mask, a phase and an in-buffer data area starting at offset 128.
For its admitted pointer arguments the adapter checks the extent before adding
the command buffer address. `accept4` requires null address/length pointers and
`SOCK_CLOEXEC`. Unknown syscalls and mismatched masks/profiles exit with code 78.

These guards have a limited purpose: they qualify the fixed command profiles
used here. They do not provide directory capabilities, peer authorization or a
sandbox for a future untrusted policy. In particular, `openat` uses `AT_FDCWD`
and does not confine the path to a directory capability; socket/address policy
does not itself force loopback. The fixed embedded policy chooses the private
relative filename and loopback endpoint. It stores raw kernel file descriptors,
without generation counters or a rights table.

The emitted adapter also directly performs `mmap`, `umask`, `rt_sigaction`,
`rt_sigreturn`, internal `clock_gettime`, diagnostic `write` and `exit`. These
effects are outside the HIA policy's declared read/write/trap effects. In the
locked language there is no generic syscall opcode implied by this fixture.
The explicit technique is **HIA generating a Linux executable's bytes**.

## Actual fixed policy behavior

The policy reads exactly eight input bytes, `HIAprobe`, and obtains sixteen
bytes from `getrandom`. It exclusively creates `hia-platform-probe.bin` with
`O_NOFOLLOW | O_CLOEXEC`, mode `0600`, writes all eight payload bytes, fsyncs the
file, seeks, reads back and compares the bytes, then closes the file. The
adapter sets its own process umask to `0077`; a control starts it with inherited
umask `0777` and checks the resulting file is still `0600`.

The policy then creates a loopback TCP listener on an ephemeral port, creates
and connects a client, accepts a server socket, registers that socket with
epoll, sends the payload, observes readiness and verifies the received bytes.
It explicitly closes the client, server, listener and epoll descriptors before
writing a 96-byte observation. A separate control blocks this final write and
inspects the owned child's actual descriptor table: only stdin, stdout, stderr
and the inherited sealed executable descriptor may remain.

The successful observation includes the start/end monotonic timestamps, TCP
readback, random bytes, positive partial-result count, EINTR count, policy-call
count and independent file readback. The driver compares timestamps with its
own monotonic bracket and independently reads the created file. A random sample
does not certify entropy quality.

Positive partial reads/writes/randomness advance their pointer and remaining
count in the HIA policy. The qualifier **actually forces short stdin reads**;
it does not claim to have forced short socket/file/stdout writes or a partial
`getrandom`. EINTR retries are restricted to the operations listed in the ABI;
the policy does not blindly retry `close` or `connect`. An actual EAGAIN is a
reported failure, not readiness resumption.

Policy failure exits 70. Before exit the adapter attempts to write the 32-byte
event to stderr. It retries EINTR and positive partial writes for at most eight
attempts, stopping on other errors. Internal adapter failures first record the
actual negative syscall result and the `u64::MAX` phase sentinel. Diagnostic
delivery is not guaranteed: stderr can be closed, nonblocking or indefinitely
blocked. The attempt count is not a wall-time bound. Arena mapping failure
exits 79 without an event.

## Qualification scope and retained failures

The independent platform gate requires these finite controls:

- Ordinary file/TCP/epoll/clock/randomness success and private native umask.
- Actual short reads, exactly two actual EINTR returns, EOF, wrong input and
  EAGAIN refusal.
- Existing-file and symlink refusal without changing the existing bytes.
- Actual stdout EPIPE, stderr EPIPE and termination before file/network effects.
- Explicit descriptor closure before the final observation.
- The elapsed check after a deliberate external SIGUSR1 wakeup.
- Unknown syscall, pointer start/end, pointer mask, epoll-event count and three
  `accept4` profile rejections using separately compiled negative HIA policies.
- Empty/oversize pack input refusal and byte-exact native repacking.

The short-read driver observes an actual blocked `read(0, ..., remaining)`
before sending each of the 1-, 2- and 5-byte chunks. Signal controls observe the
installed handler, blocked read, pending-signal state and a later context switch
plus read re-entry. Signals target an owned pidfd. Polling intervals are only
sampling cadence; fixed sleeps never stand in for readiness. If `/proc` access
or a required observation fails, the control fails without fallback.

Every child has an external timeout and bounded termination/reaping. Native
build stages have a 30-second budget; finite case communication has a 10-second
budget; readiness waits have a 2-second budget; cleanup has a 3-second budget.
The idle limitation deliberately observes six seconds without input or signals,
then records the still-blocked read and terminates the owned child.

Two outcomes remain separate from the finite PASS count:

| Requirement or observation | Treatment |
| --- | --- |
| Native hard deadline without wakeup | Actual `FAIL`, full-node I/O gate `OPEN`; external cleanup is recorded |
| Independent syscall trace | Raw capture if available; `PTRACE_EPERM` or missing strace stays `UNKNOWN` |

The development report is a measured snapshot for its recorded source hashes.
CI writes a fresh report and raw artifacts to the requested external output
directory. A finite fixture PASS never turns either OPEN/UNKNOWN outcome into
a node qualification. Earlier prototype failures and observations remain in
the development record; this directory keeps only the final source version.

The separate [cleanup regressions](../tests/test_platform_cleanup.py) use real
short-lived hosted test children, then deterministically inject timeout/ESRCH
after those children have exited. They check that all three cleanup paths reap
and preserve the real result and raw output, while EPERM still propagates.
These six unittest cases are not native OS qualification controls and are not
included in the platform's 25-control count. The existing unittest discovery
runs them in CI; they can also be run alone with
`python -B -m unittest hia.tests.test_platform_cleanup -v`.

## Remaining owner boundary

There is no independent hard deadline, EAGAIN readiness scheduling, generic FD
capability table, directory/peer authority, authenticated transport, transaction
rollback or crash recovery here. Fsyncing one temporary file does not establish
a durable store: no directory fsync or commit/recovery protocol is present.
Failure-path descriptor reclamation relies on process exit. Blocking
`getrandom`, connect, reads and diagnostic writes can exceed the policy's elapsed
budget.

The current emitter copies a flat trusted image and resolves its own relative
ISA offsets. It does not consume ET_REL objects or exercise the upstream HIA
static linker. A future reusable platform must independently qualify its
policy-object linkage and authority/lifecycle semantics before adopting real
storage or network owners. Further work is tracked by the repository's sole
[development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
