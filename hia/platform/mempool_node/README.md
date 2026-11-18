# One held-disk Node and production M05 method

The six files in hia/platform/node_owner own the disk/context source, canonical
State, View lease, Parent and Prefix lifecycle. Mempool node_methods.hepta extends
that producer with method 8. node_commitment/owner.hepta owns retained canonical
Parent and Prepared objects in the same State heap. Existing State, application,
mandatory, protocol, hashing and group helpers are composed from canonical files.

## Current closure and authority

A fresh isolated Genesis-format directory is initialized or cold-opened by the
actual native Genesis owner. Its held descriptors, namespace, complete bytes,
independently computed root and sync operations remain authoritative. Native
JSON-to-Value construction creates the State handle. Caller State, Config, nonce,
root, Prepared, signature results and lease tokens cannot initialize capabilities.

Default Settings accepts absent timestamp or valid positive signed-64-bit
timestamps. Qualification covers four Settings contexts. This differs from a
commitment predecessor snapshot: the current Parent/Prepared path uses None
predecessor. Native Some/CheckedApply is not claimed.

Method 8 holds a real View lease and runs actual PNX1 decoding, canonical sender
and metadata checks, exact-wire signature reuse, strict Ed25519 verification,
State nonce reads, typed admission and consuming Ready queue. Only successful
admission enters the same private Parent/Prefix methods as public Node methods.
Temporary Prepared is dropped before its Output State. Preview facts are
published only at the original success boundary. Error, cancellation and panic
preserve cache and base. Drop retires Prefix, Parent, checks real object counts,
releases View and clears its own buffers.

The real Prepared is built after BeforeCommitment and before
AfterCommitment/BeforeOutput. Its parent map is borrowed only during computation.
No external success flag grants persistence.

Original PendingPreview may internally choose a cached Some predecessor.
Differentials compare complete Ready/State/root/receipt, error, cancellation and
cache behavior; internal CheckedApply/cache-selection equivalence remains open.
The separate None-parent Node comparison covers all selected public Parent and
Prepared fields.

## Executable qualification

Each partition builds exact native machinecode independently:

~~~sh
python -B -m hia.platform.mempool_node.qualify --group smoke --output OUT
python -B -m hia.platform.mempool_node.qualify --group boundaries --output OUT
python -B -m hia.platform.mempool_node.qualify --group capacity --output OUT
python -B -m hia.platform.mempool_node.qualify --group node --output OUT
python -B -m hia.platform.mempool_node.qualify --group cross --output OUT
~~~

Explicit settings: HIA_TOOLCHAIN_ROOT, HIA_NATIVE_COMPILER and
HIA_NATIVE_COMPILER_SHA256. All 24 images, source inputs, literal emitter payload,
prefix and complete ELF are checked. Runtime child 240 seconds and cleanup
3 seconds remain unchanged.

~~~sh
python -B -m hia.platform.mempool_node.test_integrity --scope source --report REPORT
python -B -m hia.platform.mempool_node.test_integrity --scope build --build BUILD --report REPORT
python -B -m hia.platform.mempool_node.build --verify BUILD --report REPORT
~~~

Source scope executes six required groups; build scope executes nine. Skipped
groups never pass. The reader requires no compiler checkout.

The native evidence CLI uses --group node with --node, or --group m05 with
--smoke, --boundaries, --capacity and --cross, plus a fresh --report path.
It replays every pipe frame, the exact control record shapes and the fixed
outcome/signature/cache predicates from the bound qualification source.
Namespace snapshots are compared and all retained regular bytes are reopened.
Traces must contain a complete process start and retirement; this establishes
capture completeness, not an independent syscall-policy qualification.

Original CLI requires --cargo-target and --output. Group m05 requires --smoke,
--boundaries, --capacity and --cross artifacts; it runs 11 histories / 122 methods /
58 validations, six retained tests and the same-Node 24-method cross history.
Group node requires --node and runs four Settings / 96 methods / three retained
tests. Test-only child hooks observe unchanged production Rust.

Every original run rejects external tool overrides and binds actual compiler,
Cargo, locked registry archive, actual serde library, original SQLite build gate,
complete original include graph, independent binary and final source/raw/binary
fences. Evidence archives retain independent original binary bytes in full.

## Open domains

This finite owner does not open existing SQLite Node.db, admit successor blocks,
persist a local pool, publish mutable catalog generations or COMMIT a Node
transaction. Some/CheckedApply integration, live Paid/Host permit, block-derived
W1 capability and the 4-second / 16-request service qualification remain open.
The qualification callback ACK conveys cancellation only, never a permit.
Continuous hostile same-UID races and physical power loss are not claimed.

The joint Ed25519 entry reuses canonical field/group/SHA helpers. It does not
duplicate them or replace the previously qualified entry. Old 240-second failure,
32 CPU observations, 262 three-way crypto cases and all capacity runs retain
their separate source identities. Equal machinecode does not relabel an earlier
source graph as executed.
