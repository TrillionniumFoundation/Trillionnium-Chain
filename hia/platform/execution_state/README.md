# Native execution State, View and Patch ownership

This component owns the in-memory state relationship used by ordinary M06
execution. A sealed Linux x86-64 executable retains private State, Value, View
and Patch objects across a sequence of pipe commands. HIA constructs and
compares typed values, performs all map operations, retains complete prefix
snapshots, checks conflicts and consumes patches. The Linux adapter performs
pipe I/O, private memory allocation, protection and the internal call into the
existing canonical HIA state-root image.

## Original relationship

The source relation is `trnm-mvcc-fee/src/pon_executor.rs`: `State`,
`prefix_rows`, `View::new/get/put/scan`, `Patch::clone/current/apply`, and `root`.
The selected View methods do not invoke the optional account-access callback.
Application helpers, authenticated Prepared objects, mandatory block work,
fee/reward conservation, executor scheduling and Node persistence remain the
next integration boundary. A value handle or a Patch is never an
`AdmissionPersistence` capability.

A View borrows its base State immutably. The first read or write of each key
retains the original `Option<Value>`; later writes leave that observation
unchanged. The first scan of each prefix retains every matching original row.
Each scan returns an independently owned State made from that snapshot and the
current writes. Empty and nested prefixes use the same complete ordered range.
The original View has no remove operation; deletion belongs to State.

`Patch::current` compares point reads first, then all prefix snapshots using
actual typed Value equality. `Patch::apply` consumes its writes and extends the
destination State. It deliberately does not call `current`: the original
executor owns the decision to replay a stale patch. A cloned patch owns its own
maps and can be consumed independently. Fee and receipt bytes are retained
without granting execution or block admission authority.

## Values and allocation

The private allocator and AVL maps live inside an arena that grows through
actual `mremap`. References are arena-relative offsets and survive relocation.
Immutable Value storage is reference counted; map entries and object lifetimes
are independently owned. Released blocks are erased and coalesced. Orderly
close drops outstanding Views first, then all remaining objects, checks that
all allocations were reclaimed and that the entire arena is zero, and exits.

The constructor accepts the existing JVT1 typed transport: null, bool, u64,
i64, finite f64, UTF-8 string, array and object. Duplicate object keys retain
the last value. Positive i64 values normalize to serde's unsigned-number
representation. Floating minus zero compares equal to floating plus zero;
floating one differs from integer one. JSON bytes or hashes are not used as a
substitute for typed equality. JVT1's u32 node lengths are transport extents,
not M06 value limits.

Intermediate values, keys and States do not inherit the root function's
limits. Root first validates the complete State's values in key order; a float
returns RANGE and a non-ASCII string or nested object key returns
NONCANONICAL in the original traversal order. Only then does it check 65,536
rows and the per-row 160-byte key / 4,096-byte canonical-JSON value limits.
Top-level State keys may be empty or non-ASCII UTF-8. The owner constructs the
actual SRV1 bytes privately and calls the existing `state_root_compact.hepta`
image. A caller supplies no claimed digest, leaf, validation bit or root result.

Resource capacity is reserved before a semantic mutation. Allocation failure
is an explicit process resource failure, not an invented M06 LIMIT. The wire
ABI reports malformed frames, stale/wrong-kind handles and an attempted
mutable borrow separately from original semantic errors. These are local
ownership/precondition checks, not claimed Rust error strings.

## Process ABI

All three standard descriptors must be distinct blocking pipes with their
normal read/write access. The native adapter checks their actual type, access
and device/inode identity before reading input or emitting diagnostics. The
input mapping is read-only during each HIA call; output and heap mappings are
private and disjoint. The process handles one fully captured frame at a time.

A request is an eight-byte little-endian frame length followed by:

| Offset | Bytes | Meaning |
| --- | ---: | --- |
| 0 | 8 | `SVP00001` |
| 8 | 8 | Operation |
| 16 | 8 | First object handle, or zero |
| 24 | 8 | Second object handle, or zero |
| 32 | 8 | Fee for Patch take; otherwise zero |
| 40 | 8 | UTF-8 key or prefix byte length |
| 48 | 8 | JVT1 or receipt byte length |
| 56 | 8 | Reserved zero |
| 64 | variable | Exact key bytes followed by payload |

A response is length-prefixed in the same way. Its 64-byte header is
`SVPR0001`, operation, monotonic sequence, status, returned handle/boolean,
payload length, live object count and live allocation count (eight bytes each).
The last count describes only this native allocator and is not compared with
Rust's allocator. Handles are scoped to one process. Their serials never wrap;
consumed or dropped handles never become live again. They are value references,
not cross-process or consensus authorization tokens.

The operation map and exact field meanings are in `abi.json`. State export is
`u64 count`, then sorted rows `u64 key_bytes, u64 JVT1_bytes, key, JVT1`.
Read observations use a zero JVT1 length for absence; null is a present JVT1
value. Patch export is `u64 fee, u64 receipt_bytes, receipt`, writes, reads,
`u64 scan_count`, then each `u64 prefix_bytes, prefix, snapshot State`.

## Qualification

`python3 -B -m hia.platform.execution_state.qualify --output <fresh>` compiles
all three HIA images with the pinned native compiler, executes the real ELF
for every canonical history, retains complete pipes and receipts, and checks
source fences. Python only authors inputs, launches the sealed executable and
compares observations. It never implements a production State or root path.

The original verifier appends one private `cfg(test)` child to an isolated,
byte-identical `pon_executor.rs`, compiles the actual locked Rust crate, runs
its retained prefix tests, and executes the same corpus through original
methods. Its safe test registry retains actual `View<'static>` instances over
immutable cloned base values; those test-only backing clones are reclaimed
at process exit. This is an adapter for dynamic histories, not a claim that
Rust and HIA have identical allocator or object addresses. All comparisons
use complete values, snapshots, metadata and actual roots.

The original source manifest includes the complete original workspace, config
and formal trees, plus literal Rust data includes discovered through every
local Cargo path dependency of the tested crate. This includes the real growth
reference and protocol content vectors outside those trees. Unsupported include
expressions, missing fixtures and symbolic paths fail before Cargo; the isolated
test build receives the exact admitted bytes. The first development build that
omitted the growth vector remains a recorded compilation failure with no Rust
histories executed.

The original verifier rejects inherited compiler, wrapper, profile, target,
linker and loader overrides before copying original sources or discovering
tools. It binds the selected sysroot's actual rustc, Cargo and rustdoc files,
uses their absolute paths, and checks those identities after execution. The
serde comparison selects the actual library artifact explicitly. Guarded native
calls retain complete input, output and arena bytes in three separate journals;
the two private exhaustion counter writes are recorded as test fixtures.

Native development observations, original differential results and final
same-head CI are separate evidence. This component alone does not complete
M06, Node admission, SQL COMMIT, all migration gates or old-stack retirement.
