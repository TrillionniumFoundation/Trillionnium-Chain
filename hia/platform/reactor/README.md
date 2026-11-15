# Native HIA stream reactor

This is a reusable, single-owner stream context. HIA owns descriptor admission,
capability slots, operation cursors, absolute deadlines, cancellation, epoll
resumption, terminal states and cleanup. A second HIA program emits the small
Linux x86-64 adapter and a static ELF image. The resulting process has no
Python, C, Rust, assembly-source runtime, interpreter or dynamic loader.

The scope is an already imported pipe/FIFO or connected stream socket. It does
not establish peer authentication, open a connection, run a complete node, or
give ordinary files and `fsync` a hard deadline. Those obligations remain open.

## Build and qualify

Use the repository's exact `hia/toolchain.lock.json`, qualified native compiler
and `hia/qualification/compiler-binding.json`. There is no fallback backend.

```sh
export HIA_TOOLCHAIN_ROOT=/absolute/path/to/pinned/Hepta
export HIA_NATIVE_COMPILER=/absolute/path/to/native-compiler
export HIA_NATIVE_COMPILER_SHA256=87c247e4d1c3c9a449d2947fd4227fdc186d519bffd203a04cafce7861a4ed54
python hia/tools/qualify_platform.py --reactor --output /absolute/fresh/reactor-qualification
```

The output directory must be new and outside `hia/`. The hosted driver captures
all source bytes and hashes, validates the upstream revision and tracked-clean
checkout, checks Core syntax/types, executes the pinned native compiler, and
executes the native HIA emitter. It saves the actual inputs, outputs, stderr,
return codes and budgets for every native stage. It checks the static ELF
structure and that the exact compiled policy is its final image region. These
checks do not prove the semantics of the emitted machine instructions.

The driver also compiles `context_fixture.hepta` with the exact, unchanged
`reactor_*` helper bytes from `policy.hepta`. The fixture replaces only the CLI
`f0`, exercising the reusable API. The composition and every resulting image
have separate source and executable hashes. No generated image, compiler,
authoring script or prototype source is checked into this directory.

`api_fixture.hepta` is a separate native HIA test entry for exceptional API
acknowledgements. It receives explicitly synthetic event/command/state frames
and returns the HIA API result plus resulting command/state bytes. Its thirteen
contract scenarios do not represent real kernel fault injection, time samples
or descriptor authority. The `contracts.py` driver only supplies frames,
executes the native image and checks returned bytes. Its evidence stays separate
from the forty-nine actual OS, caller and adapter/packer controls.

The shared build guard binds the existing finite OS fixture's inputs as build
dependencies. Those inputs are not code in the reactor image. The finite probe
in the parent directory has independent file, random and network controls; its
25 controls do not qualify this reactor or the storage owner.

## Caller and authority contract

`abi.json` is the normative field and operation inventory. All buffers belong
to one trusted native owner. Peer bytes may be copied into the data window;
they must never become an event, capability table, command descriptor or saved
state. This is an ownership contract within one process, not protection against
hostile writes to the same address space.

The event must come from the actual syscall/clock adapter. Each emitted command
has exactly one outstanding acknowledgement. The command phase must match the
event phase. The caller must not close/reuse imported descriptors, change their
open-file-description flags or socket linger configuration, or concurrently
call the context. `tick` and `submit` do not make concurrent aliases safe.

Admission initially borrows proposed descriptors. HIA checks actual `fstat`
type, device and inode, read/write access, and, for sockets, `SO_TYPE`, disabled
`SO_LINGER`, `getpeername` and the connected family. Only then does it mark a
data/cancel slot owned and issue `F_SETFL(O_NONBLOCK)`. State word at byte 432 is
the cumulative adopted-slot mask. A rejected, unadopted descriptor remains the
caller's responsibility and has not had its flags changed by that admission.
If a later admission or `F_SETFL` fails, previously adopted descriptors are
still owned and must be driven through `reactor_close`.

The diagnostic descriptor is borrowed. Its caller explicitly permits
`O_NONBLOCK` mutation; the reactor invalidates its logical capability at close
but never closes that descriptor. A diagnostic stream that fails admission is
disabled. This prevents a regular file or full blocking diagnostic channel
from becoming an unnoticed blocking path.

Input and output may be distinct descriptor numbers for the same connected
duplex socket. Cancellation and diagnostics must not alias the data objects:
HIA compares the actual device/inode identities and refuses those cases.
External aliases to an accepted open-file description share its nonblock flag
and remain outside the exclusive-owner contract. A private slot records raw
FD, generation, rights, type, registration, token, inode and device. Generation
and active state are invalidated before a close is issued. A close interrupted
by `EINTR` is never retried against a possibly reused raw FD.

## Operation lifecycle

The canonical functions are:

```text
reactor_start(event, command, state,
              mode, amount, absolute_deadline_ns,
              cancel_fd, input_fd, output_fd, diagnostic_fd) -> u32
reactor_tick(event, command, state) -> u32
reactor_submit(event, command, state, mode, amount, absolute_deadline_ns) -> u32
reactor_close(command, state) -> u32
```

All scalar parameters are `u64`; the buffers are `readbuf, mutbuf, mutbuf` as
shown in the HIA source. State must initially be zero. The library reserves its
first 1024 bytes; an embedding caller can use the suffix. A return of zero means
execute the command and call `tick` with its actual result. `256 + status` is an
operation terminal: descriptors and the epoll instance remain owned, and repeat
`tick` calls return the same terminal without changing state or issuing I/O.
`submit` starts the next operation on that context and never invents a new
deadline. `close` is allowed only while quiescent; drive its close commands with
`tick` until `128 + status`. Repeated closed `tick`/`close` calls have no effects.
Synchronous argument/phase refusals use **`512 + status`** and leave command,
state and ownership unchanged. In particular, a refused `submit` is never a
claim that the retained context has closed. The CLI maps that separate refusal
class to its process exit code.

Mode 0 copies up to 2 MiB in 64 KiB windows. Mode 1 reads/drains up to 2 MiB into
a reused window; to consume every byte in caller logic, submit reads no larger
than one window and inspect each result. Mode 2 writes a caller-prepared window
of at most 64 KiB. Larger writes use repeated submissions with an explicitly
shared deadline. The CLI's mode 2 alone fills a deterministic test pattern; the
reusable function never fabricates the caller's payload.

Every positive syscall result advances the cursor before deadline evaluation.
An interrupted operation keeps its cursor. `EAGAIN` registers a level-triggered
epoll event; readiness resumes the same cursor. Operation tokens include a
monotonic sequence and slot, and capabilities include their own generation.
Every wait recomputes the remaining absolute time and uses a 1–100 ms kernel
timeout. This is a scheduling-dependent elapsed-time bound, not a hard
real-time guarantee.

If the clock sample fails or regresses after a syscall, HIA first preserves
positive byte progress, successful descriptor creation and registration changes
from that acknowledgement. It then produces an error terminal and forbids new
submissions on that context. Cleanup remains possible. A clock-error terminal
retains the last valid timestamp rather than inventing a new time. Actual
kernel clock failure is not exercised by the OS controls; the independent
native policy-frame tests cover this state transition explicitly.

An optional accepted cancellation stream is checked before every data attempt,
including between successful progress steps, and is also registered with
epoll. One byte or EOF cancels the current operation. Timeout/cancellation
reports retain all actual read/write counts. They do not roll back external
effects. The terminal is selected once, after detaching the operation's data
registration; a detach error may become the single error terminal before it is
delivered. A later stop cannot turn a completed write into a rollback.

The final 192-byte diagnostic is best effort. It uses an admitted nonblocking
stream and at most eight immediate partial-write/`EINTR` attempts. `EAGAIN` or a
closed diagnostic reader cannot hold termination open. Cleanup attempts each
owned FD and epoll FD once. Its return retains the primary operation outcome;
the embedding caller must also inspect the close-error count at state byte 144,
last close errno bits at 440 and last close FD at 448. The diagnostic field
`closed_count` counts acknowledged close attempts, including failed closes; it
does not establish resource release after an error. Process-level failure
cleanup in the hosted qualifier is a
separate bounded control and never counts as a native deadline success.

## Native adapter boundary

`policy.hepta` is HIA semantics compiled by the qualified native compiler.
`linux_emitter.hepta` uses HIA buffer writes, integer operations and explicit
relative patches to emit the ELF header and Linux instructions as data. It
copies in the exact compiled policy image. This is not a new HIA syscall opcode
or a claim that Core verifies arbitrary ISA data.

The adapter permits only read, write, close, fstat, getpeername, restricted
getsockopt/fcntl, epoll_create1, epoll_ctl and epoll_wait command profiles. Pointer
offsets, lengths, masks and relevant operation constants are checked before the
syscall. These guards constrain this trusted policy interface; they are not a
general sandbox for an arbitrary policy image. Implicit adapter effects include
anonymous RW memory, `CLOCK_MONOTONIC`, ignored SIGPIPE, a non-restarting SIGUSR1
handler/restorer, and exit. The signal handler exists for real `EINTR`
qualification. Native deadline tests do not send it a signal.

The executable wrapper reads four bounded decimal arguments from the actual
kernel argv: mode, amount, budget in milliseconds, cancellation FD. It uses
stdin/stdout/stderr as the imported descriptors. Stdin has no special blocking
exemption: a regular file or device on FD 0 is refused before data reads.
Supported socket scope is an already connected AF_UNIX, AF_INET or AF_INET6
`SOCK_STREAM` with linger disabled. Creating/accepting/connecting a socket, and
checking `SO_ERROR` after `EINPROGRESS`, remain outside this component.

## Evidence and remaining boundaries

The qualifier uses real pipes and socket peers. Readiness for short reads and
signals is observed from the owned child's actual blocked epoll syscall,
registration tokens, signal state and context-switch count. It never assumes
handler installation from a fixed sleep. `/proc` observation failures are
explicit qualification failures. Tests force a 4096-byte output pipe to obtain
actual short writes, preserve partial effects on cancellation/deadline, and
exercise 2 MiB transfers across windows. The separate HIA fixture checks retained
FD/epoll state across two operations, terminal idempotence and actual `EBADF`
after owned descriptors close.

The previous blocking probe's no-wakeup deadline **FAIL** remains in its
source/ELF-bound report; it is not rewritten as a success. Reactor deadline
success applies only to the current stream image. A real strace attempt has its
own result; `PTRACE_EPERM` stays `UNKNOWN` and does not become trace coverage from
the non-trace OS controls.

Full node I/O remains **OPEN**. Regular-file/block-device operations, directory
transactions, fsync, connection establishment, multi-connection scheduling,
authenticated peer authority and integration with a durable owner require
their own implementations and evidence. The fixture also does not qualify the
upstream ET_REL static linker or arbitrary policy-image validation.
