# Native default-genesis persistent owner

Acceptance is source-specific: native controls, complete original-source/corpus
admission and actual original Rust comparisons must all pass for the same
candidate. This finite owner does not establish complete Node migration.

The native HIA owner constructs Settings::development(None or Some(timestamp)),
the complete seven-row initial State, the genesis catalog row, active generation
zero and slot zero. It owns the real private directory description, its process
lock, the file being initialized and the published file. There is no external
State, Delta, context, expected-root or successful-admission input.

This is a fresh native stored schema. It does not read or rewrite SQLite, the
generic StoreOwner namespace, deployed data or any other backend. The complete
admitted namespace is ng1.owner.lock and exactly one internally named pending or
state file. That filename contains the full native-computed genesis identity.

The finite catalog has one block with absent parent and packet, height zero and
64 zero chainwork bytes, one active row, one initial snapshot referring to the
same complete State, and empty deltas, events, reorganization intent and steps,
reorganization lifecycle, ancestry jumps, local pool, replay, audit and outbox
collections. Other catalogs are refused even if they claim the genesis active
tip. This unit contains no successor-admission or arbitrary COMMIT operation.

Initialization synchronizes the complete pending file, rereads it and computes
M06 over its actual stored State, then publishes by RENAME_NOREPLACE and fsyncs
the directory. The same owner opens and fully validates the published file
before an opened receipt. Explicit recovery validates every existing byte of
the context-named pending prefix before writing only its missing suffix. After every diagnostic pause before a suffix write, the owner repeats the
complete existing-prefix read and validates its retained inode, size, pathname,
lock and private directory. After the prepublication pause it repeats complete
stored-byte and root validation. After rename, validation before directory
synchronization remains inside publication uncertainty. An
unbound lock-only namespace is not a recovery capability. Simultaneous pending
and final files, unknown entries and wrong-context filenames refuse unchanged.

A mode-1 cold open first completes the stored-byte, actual native root, pathname
and held-lock checks. It then sets publication uncertainty, fsyncs the retained
final-file descriptor, and only on success fsyncs the retained directory. Both
must succeed before uncertainty is cleared and NGOPEN01 is emitted. There is no
request callback between these steps. This explicitly settles a preceding
process death after rename but before its directory fsync; merely reading a
visible final file does not establish durability. The opened receipt denotes
this settled finite genesis owner. Synchronization does not rewrite file bytes.

Every READ repeats complete physical file reading, native root computation and
comparison with its actual stored catalog root. It checks the retained lock and
file inode against freshly opened names, along with exact directory/file
ownership, modes, regular type and one-link file ownership. Standard input, output and error must be three distinct real pipes with
read-only, write-only and write-only access respectively. They are admitted by
native HIA before bootstrap reading; an unadmitted stream fails silently without
writing a diagnostic. Both optional diagnostic FDs must also be distinct real
pipes with the correct access mode and must not alias any standard stream. They carry pause/resume observations, not service permission or commit
authority.

The renameat2 RENAME_NOREPLACE call is the namespace publication linearization
point. A successful syscall does not itself establish directory durability.
The finite profile assumes a private directory and cooperating owners using the
held flock. Pathname checks and a later rename are separate syscalls; repeated
checks do not establish safety against a continuously mutating same-UID process.
Controlled pause-boundary substitutions are tested separately from this limit.
A later missing receipt does not prove that a wrong file was never transiently
published, and no such claim is made for the original failing candidates.

The final rename attempt, or a mode-1 cold open's synchronization sequence,
starts the publication uncertainty interval. It ends only after successful
directory fsync. A missing opened receipt always requires
reopening; later response I/O failure does not establish rollback. The explicit
diagnostic gate can pause physical boundaries or encounter actual EOF. It does
not introduce a cancellable checkpoint after publication or implement the
original external PQ witness CAS contract.

Only native HIA code performs construction, state interpretation, expected-root
validation, filesystem state transitions and result decisions. The HIA-emitted
Linux x86-64 adapter remains a separately trusted literal-ISA boundary. Hosted
Python only authors, builds and qualifies source.

The original initialization relation is in store.rs 2183-2254. In this exact
closed genesis catalog, cold recover has no pending reorganization and its
best-work target equals the active genesis, so original recovery makes no
successor State write. Physical schema bytes differ because this is an explicit
new native format; the original full logical State and catalog facts must be
compared with a real original Rust Node.

Settings-dependent configuration, default task material, the 65,536 classic and
1,065,536 growth limits are unchanged. Seven rows are the result of this exact
default constructor, not a replacement maximum State size.

Still OPEN: complete M06 execution and its private admitted-output owner,
validated successor block/receipt/task output persistence, branch catalog,
reorganization/cancellation lifecycle, generic hot State changes, alternate
Settings and continuity/growth constructors, GSC2, authenticated and PQ backends,
replay/outbox mutation owners, external anti-rollback witness, physical power
loss, hostile continuous same-UID mutation, and original service budgets.
Neither this unit nor its future successful tests can retire the original Node.

## Qualification entry points

Each invocation builds and checks its complete current source closure before
running actual native processes. Output directories must be fresh. Every native
child keeps a 240-second deadline and a three-second termination budget.

```sh
python3 -B -m hia.platform.genesis_store.qualify --suite semantic --output /tmp/genesis-semantic
python3 -B -m hia.platform.genesis_store.qualify --suite crash --output /tmp/genesis-crash
python3 -B -m hia.platform.genesis_store.qualify --suite prefix --output /tmp/genesis-prefix
python3 -B -m hia.platform.genesis_store.qualify --suite namespace --output /tmp/genesis-namespace
python3 -B -m hia.platform.genesis_store.qualify --suite corruption --output /tmp/genesis-corruption
```

The semantic corpus contains all 30 fixed scalar cases: 16 successful
timestamp/worker combinations, six invalid timestamp combinations and eight
invalid worker combinations. Each successful case obtains the complete actual
opened receipt and READ bytes, tests a live competing owner, closes the first
process and reads the complete State again in a new process. The original Rust
observer calls the original Settings and Node implementations, then queries
their actual State, catalog, active rows, snapshots and all 18 logical table
counts. Its schema observations are retained separately from this native format.

The crash group preserves actual SIGKILL and diagnostic EOF/malformed-resume
outcomes, resolves the visible finite namespace with a new owner, and performs
a further complete cold read. It requires an actual syscall trace demonstrating
file fsync, directory fsync and then NGOPEN. Its two EIO controls use explicitly
reported kernel seccomp error injection on the actual retained descriptor;
they are not hardware disk failures. Prefix controls also use actual
RLIMIT_FSIZE-induced partial writes and EFBIG, then complete native recovery.
These controls do not flush the OS page cache or simulate physical power loss.

The native exit format differs from original Rust Error Display/code/kind.
For constructor and worker refusals, comparison preserves actual original
errors and checks the native failed operation, ordering, empty receipt and
unchanged namespace. It does not claim those Rust strings or typed error fields
are present in the native binary ABI. Out-of-profile native namespace refusals
are additional finite-profile controls, not a claim that original Node globally
rejects every unvisited catalog row. The directory authority is the supplied
retained descriptor; no external canonical pathname identity is promised.
