# Native peer lease Unix transport

This module builds four Linux x86-64 executables from HIA: the daemon CLI,
the daemon API observer, a single-call client and a persistent client owner.
The daemon, client, framing, journal integration, errors and cleanup run in
native HIA images. Rust adapters observe the unchanged original implementation;
Python generates inputs, captures actual processes and independently reads the
evidence. Neither participates in the native business path.

`build.py` uses the repository's pinned self-hosted compiler and the HIA Linux
platform emitter. It retains every composed source, compiler input, raw compiler
result, native image and final executable. The private borrowed codec is a
separate shared object compiled by the same native compiler and linked by the
recorded system linker. Its sole entry is `f0`; it is not a public owned ABI.

## Qualified surface and remaining work

The finite transport contract includes private canonical Unix paths, same-user
peer credentials, acquire/renew/revalidate/release, one journal writer,
nonblocking bounded stream I/O, absolute request deadlines, typed errors,
fatal-before-deadline ordering and inode-guarded socket cleanup. The daemon keeps
64 connection slots and performs at most 16 progress steps per slot per turn.
The persistent client keeps explicit object identities, cloned paths, timeouts
and deadlines in a growable native arena. Drop invalidates the object identity,
clears its live bytes and permits logical arena reuse; it does not promise that
the process immediately returns the arena's high-water allocation to the OS.

The executable observer wire is documented in `abi.json`. It is a qualification
transport, not a claim of a stable general C ABI or a replacement for Rust
object layout. The original adapter converts an absolute monotonic deadline by
sampling `CLOCK_MONOTONIC` and `Instant`; it does not assume their layouts match.

The complete `trnm-peer-lease` package is not retired by this module. Payload
recovery owners, every external object/lifetime combination, concurrent access
to one arena, foreign allocator ownership, and the original whole-service
4-second/16-worker gate remain separate obligations. This module grants no
production activation or whole-chain completion.

## Reproducible qualification

Run on a non-root Linux x86-64 account with actual AF_UNIX, `SO_PEERCRED`,
`strace` fault injection, pidfds and child-subreaper support. The exact pinned
Hepta toolchain and cold-qualified native compiler must be available through
the standard `HIA_TOOLCHAIN_ROOT`, `HIA_NATIVE_COMPILER` and
`HIA_NATIVE_COMPILER_SHA256` variables. Rust 1.95.0, its fmt/Clippy components,
the original locked Cargo dependencies and a system ELF linker are required.
Cargo configuration files and compiler/test wrapper overrides are refused.

Use a fresh, short output directory outside the repository; case sockets must
still fit the original Unix path limit. Do not reuse or clean another run's
output directory.

```sh
bash scripts/project-preflight.sh --audit
python3 -B -m hia.platform.peer_lease_unix.qualify run --output /tmp/pu-unique
python3 -B -m hia.platform.peer_lease_unix.qualify readback --input /tmp/pu-unique
```

The run creates a fresh Cargo target and executes the unchanged package's full
unfiltered all-feature tests, whole-workspace formatting check and strict
all-target/all-feature Clippy check. The original suite has 121 outer tests and
two explicit nested child re-executions; those children do not increase the
outer count. Eleven actual test executable rosters and all four original public
observers are bound to their Cargo artifacts and complete debug profile.

The independent reader requires these complete finite observation rosters:

| Group | Required actual observations |
| --- | ---: |
| Private codec | 4,755 comparisons and 40 capacity refusals |
| Single-call client | 299 named comparisons |
| Persistent client owner | 1,782 commands per implementation |
| Daemon CLI | 37 named comparisons |
| Daemon API | All 18 original histories plus 6 idempotent capacity histories and 2 actual-target deadline observations |
| Filesystem faults | 9 paired histories |
| Syscall faults | 1 actual-target probe and 29 fault injections |
| Qualification integrity | 18 controls, including actual escaped-session cleanup, live rebinding identity, complete source rechecks and deadline evidence refusals |

The rebound-path fixture holds the previous socket inode with an actual
`O_PATH | O_NOFOLLOW | O_CLOEXEC` descriptor until the replacement is bound.
The old and replacement identities are checked while both remain live, avoiding
an incorrect assumption that an unreferenced inode cannot be reused. The reader
recomputes binding bytes from the observed pathname, device, inode and mode and
checks all six original/native old, zero and replacement responses. The added
control rejects seven altered identity/timestamp variants and tampered raw data.

Each observation group retains its native and original executables, complete
inputs and outputs, syscall traces, progress and process receipts. The reader
reconstructs compiler inputs from the admitted HIA, checks exact native image
composition, rechecks original Cargo commands and dependencies, and rejects
missing, repeated, replaced or failed case names. A matching count alone cannot
qualify a group. `contents.json` covers all retained regular files, directories,
symlink identities and socket entries without following links.

The first source capture and independent reader still admit every executable's
complete HIA composition through Core. Before and after each child stage, the
builder re-enumerates the complete declared source namespace and original Git
roster, reads every actual bound file, checks original Git blob identities,
and compares all bytes and members with that admitted snapshot. It also
rechecks the pinned toolchain and absence of external Cargo configuration.
Only the repeated semantic compilation of already identical source bytes is
omitted. A non-key transitive dependency remains in the admitted path set;
removing it, changing any bytes, adding a bound namespace member, replacing a
file with a symlink or changing the original Git member set still refuses.

The six original fresh-append capacity histories remain mandatory at 1, 16,
63, 64, 65 and 80 held peers, with their original 250 ms connection deadline,
195-byte successful response and 2-second caller bound. An additional six
histories seed a lease through the actual API, restart the daemon, and exercise
the same capacity limits with an exact idempotent token and unchanged durable
journal/head. They do not substitute for a failed fresh append.

The added deadline probe identifies each implementation's actual journal
`fsync` ordinal. A separate case uses `strace` to delay that successful syscall's
exit by 350 ms while retaining the 250 ms connection deadline. It requires an
empty late reply, a fully committed journal/head, and an exact successful
idempotent retry without a second mutation. The reader binds the configured
injection to the unmodified probe, the sole actual `(DELAYED)` trace line,
exchange duration, reply bytes and committed files. This is an explicit
scheduling injection, not a fabricated successful syscall or a production
timeout change. A spontaneous slow durable append in an original capacity
history still fails that history and retains its actual timing and trace.

Child stages retain their original 240-second maximum and one 3-second cleanup
deadline. Compiler stages retain 30 seconds plus 3 seconds; individual transport
observations retain their 4-second bound. The existing owned-process collector
uses subreaping, pidfd identities and actual wait records; terminal status of the
leader alone cannot qualify unfinished descendants. The compiler limits remain
128 functions, 8,192 operations, 1,536 blocks and 256 blocks per function. A
failure preserves its raw output and is never converted into a success report.

Controlled daemon shutdown verifies the actual tracee's parent, start identity
and executable, sends the stop through its pidfd, and keeps the tracer alive
until that tracer reaps its child. The independent reader checks this terminal
receipt and its one absolute deadline. Killing the tracer and daemon together
is not accepted merely because the outer observer exits successfully.

The qualification collector can retain 4,096 process observation rows across one
complete command; the same bound also limits its traversal and reap loops.
The single-call client group serially starts more than 1,000 children. This
qualifier does not separately enforce or qualify the original W1 limit of 256
simultaneous PIDs, and that original resource gate remains unchanged. An
actual 273-child serial control retains the previous 256-record refusal and
checks every child's actual PID/start-tick birth identity against the complete
collector history, with only one unwaited child at a time. Rediscovering a
completed zombie before its parent waits it can add an observation of the same
birth; it does not add a new child. The control requires exactly the 273 child
births plus their command root and retains both row and distinct-birth counts.
History exhaustion or truncated evidence still fails qualification; grouping
the tests does not renew their original absolute deadline.

These local finite checks do not substitute for committed CI, the original
whole-service acceptance or cross-platform qualification.
