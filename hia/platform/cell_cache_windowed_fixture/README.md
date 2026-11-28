# Sealed full-row window: private linked fixture

This test advances the physical evidence for the windowed history-cache
verification kernel without adding native syscall support. Its test-only
Rust carrier holds a fixed anonymous sealed fd 0 and an anonymous pipe
as fd 1, both created by the test launcher. No path, argv-selected
operation, extra input descriptor, system setting or real cache is used.
The previously qualified static 64 KiB native adapter is not used or
changed here. There is no executable install target.

The full input consists of the original fixed request and manifest (at
most 64 KiB combined), followed by up to one 4 MiB supplied synthetic row.
The fixed Rust test carrier checks the input extent and all four seals,
the zero starting position, and the FIFO stdout shape. It fills at most
64 KiB per input window, tolerates only bounded interrupted reads and
passes each window to the actual pinned Selfhost continuation. Only the
Rust test code performs native OS calls. It does not compute SHA-256,
select rows, compare expected row extent, or decide which bytes to copy.
The HIA entry is responsible for those decisions and holds its bounded
private scratch for the complete invocation.

The carrier checks real EOF, unchanged device/inode/length/seals, exact
cursor, and no early output. It checks close success before invoking the
HIA finish operation. It never publishes the output of a refused native
call. The parent independently re-reads the same sealed input with pread,
including full synthetic rows, and feeds those same bytes to the locked
original Rust held-reader comparator. This covers digest-before-width,
output capacity and exact bytes with no promise of physical pipe atomicity
on write failure. Logical EOF and zero-request fixtures carry no trailing
row bytes in this profile.

The build binds the stock compiler to the exact previously reviewed HIA
source closure and verifies the stock machine body at the unique f0 symbol
inside the final linked x86-64 executable, with its non-executable stack.
The test is not an OS-owner replacement. It does not establish Direct
physical execution, filesystem custody, real application data or production
dispatch. The earlier windowed memory fixture covers both stock backends.
