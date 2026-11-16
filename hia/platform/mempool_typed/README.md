# HIA typed mempool admission owner

This component implements the queue, canonical metadata ownership and pending nonce
lease lifecycle of the original M05 typed admission API in checked HIA. Its present
trait implementations are explicit test adapters. The fixture-supplied signature,
replay and nonce callback outcomes are never production authentication authority.
Node PNX parsing, real signature verification, durable nonce ownership and the
SQLite-backed local pool must be integrated before this component can replace the
production mempool. This component does not retire trnm-mempool.

## Native ownership

The process owns its mutable arena, ready objects, copied transaction bodies and
pending leases. It has no command to import a context, pointer or restored object.
Ready handles are monotonically issued within an owner lifetime. Exhaustion refuses
before queue mutation; a consumed handle cannot acquire a later object by wrapping.

Normal and critical queues preserve the original capacity, reserve, spillover and
bounded fairness behavior. Canonical metadata includes the complete 32-byte digest
and signer, u64 nonce, u128 fee, both resource limits and every body byte. Exact
duplicate admission preserves the original callback order and bypass rules.
Reservation, handoff, commit, cancel, release and destruction invoke real HIA
callbacks; terminal release is attempted once, including error cleanup.

Explicit close destroys queued and ready objects and zeroes the complete private
arena before its final reply. EOF and I/O failures retain the primary failure and
perform the actual pending-lease cleanup. The Linux adapter validates distinct
blocking FIFO standard descriptors, seals each input read-only and handles actual
moving arena reallocations. It supports the original 1 MiB body default and larger
explicit custom limits without substituting a smaller fixture limit.

## Reproducible qualification

Set the three explicit toolchain variables required by hia/platform/build.py. The
revision and compiler digest are checked against the repository's preserved cold
compiler qualification. Run from the repository root with bytecode disabled:

    python3 -B -m hia.platform.mempool_typed.qualify --output /absolute/fresh/output --rustc /absolute/rustc

The qualification compiles typed_fixture.hepta and linux_emitter.hepta with the
pinned native compiler. The native HIA emitter constructs the executable containing
the exact native-compiled owner image. Python does not assemble instructions or
execute queue or lease semantics. The literal ISA in the Linux emitter is an
explicit platform boundary and is audited separately from HIA core semantics.

The declared semantic corpus has 323 histories and 9,332 commands. Each history
runs in a fresh sealed native process. The original comparison compiles the entire
unchanged Rust mempool library in an isolated directory with one appended test-only
child module. It runs all 153 retained library tests and the complete actual
original corpus. The complete M05 package and Rust toolchain/sysroot are bound
before and after execution. No shared Cargo target is used.

Only callback destruction order in operations 20, 21 and 22 is compared as a
multiset because the original uses an unordered HashMap. Both raw orders remain in
the evidence. Every other field, callback order, input, operation and history is
compared exactly. The private handle-exhaustion control is a declared test-only
memory intervention, outside the public command protocol.

The physical qualifier requires Linux strace and retains the complete actual
syscall traces, including moving mremap, injected ENOMEM/EINTR/EIO/EACCES, broken
output consumers and exactly-once pending cleanup. Injection of ENOMEM establishes
the kernel-error path, not real machine memory exhaustion. Native evidence,
original evidence and all failed attempts remain distinct.

The independent reader reconstructs the complete emitted ELF from its native
compiler outputs and requires every physical control, syscall trace and guarded
call. It validates all 26 private call transitions, the sole eight-byte test
intervention, nonwrapping handle exhaustion and complete close zeroization.
The integrity suite retains 18 source controls, five byte-tamper controls and
eight self-consistent witness mutations with 18 actual public CLI invocations.
The witness controls preserve each changed raw file and its rebound summary;
changing hashes alone cannot make an invalid observation admissible.

    python3 -B -m hia.platform.mempool_typed.test_integrity --output /absolute/fresh/source-controls
    python3 -B -m hia.platform.mempool_typed.test_integrity --bundle /absolute/complete/output --output /absolute/fresh/public-controls

## Boundaries

The original service resource budget, other targets, production Node transactions,
persistent pool recovery and whole-project migration gates remain separate. A
successful component qualification grants no production activation or package
retirement. Python build/test tools, the original Rust oracle and the test traits
remain migration infrastructure; they are not a completed HIA-only repository.
