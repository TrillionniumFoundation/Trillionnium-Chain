# Native checkpoint authority and commit ledger

This component implements retained `trnm-checkpoint-store` behavior in HIA v8
for the pinned Linux x86-64 target. The production CLI retains all six original
commands and formats. A second executable exposes original methods through a
framed native API for callers and independent qualification.

The runtime executes HIA-compiled code and Linux syscalls. It does not call
Python, Rust, C, a dynamic loader, shell or host storage proxy to make checkpoint
decisions. Python only admits source, executes the pinned compiler, concatenates
opaque images and runs independent tests. The original Rust crate and tests
remain the oracle until the repository's complete replacement gate is satisfied.

This authority and separate commit ledger do not replace `Node.db`, implement a
consensus engine, recover deployed data by creating a fresh namespace, or grant
production activation. The original activation flags remain false.

## Build boundary

Run repository preflight and set `HIA_TOOLCHAIN_ROOT`, `HIA_NATIVE_COMPILER` and
`HIA_NATIVE_COMPILER_SHA256` to the exact clean pinned toolchain and qualified
compiler. Required compiler SHA-256:
`87c247e4d1c3c9a449d2947fd4227fdc186d519bffd203a04cafce7861a4ed54`.

```sh
bash scripts/project-preflight.sh
python -B -m hia.platform.checkpoint_store.build --output /absolute/new/build
python -B -m hia.platform.checkpoint_store.build --verify /absolute/new/build
```

The build emits `trnm-external-node-checkpoint-v2` and `checkpoint-store-api`.
Each uses 26 actual runtime images. No placeholder or fallback slot is linked.
Every image keeps the original limits: 128 functions, 1,536 blocks, 8,192
operations and 256 blocks per function.

`linux_emitter.hepta` produces the complete fixed ELF header and generic syscall
and image dispatcher. Its `HCSHD001` input contains image lengths and profile.
The build appends exact compiler outputs to the emitted 5,120-byte prefix; it
does not generate instructions or relocation bytes. The result is static ELF64
with one RX load segment and a nonexecutable RW stack declaration.

`build.json` binds actual composed source, canonical compiler input, compiler
execution receipts, images, HIA-emitted prefixes and complete executables.
Readback checks current canonical dependencies and every saved input/output.
Build success does not claim runtime qualification. Failed evidence stays in its
output directory.

The syscall adapter checks declared pointer extents against private mappings.
Mappings grow with `mremap`; continuations store offsets, not addresses. Paths,
journal length and scope count acquire no new fixed policy cap. The original
4,096-byte network frame and 1,000,000-record ledger bounds remain unchanged.
Actual address space, Linux path limits and OS failures still apply.

The target requires `/proc/self/fd`, `CLOCK_MONOTONIC`, Unix sockets, advisory
locks, private file and directory identities, and real file/directory sync.
Failed clock observations refuse admission. The runtime preserves caller umask
and ignores SIGPIPE like the original executable. Partial I/O and EINTR are
handled in HIA in the original operation-specific order.

## Production commands

```text
trnm-external-node-checkpoint-v2 register-new <socket-path> <log-path>
trnm-external-node-checkpoint-v2 reopen <socket-path> <log-path> <independently-retained-journal-checkpoint-bin>
trnm-external-node-checkpoint-v2 journal-checkpoint <live-socket-path> <new-export-bin>
trnm-external-node-checkpoint-v2 ledger-init <ledger-dir> <anchor-checkpoint-bin>
trnm-external-node-checkpoint-v2 ledger-advance <ledger-dir> <source-checkpoint-bin> <target-checkpoint-bin>
trnm-external-node-checkpoint-v2 ledger-resolve <ledger-dir> <source-checkpoint-bin> <target-checkpoint-bin>
```

Usage errors exit 64. Original operation errors exit 1 with the original Display
prefix and reason. Finite success exits 0. Daemons serve until terminated or an
integrity failure that the original considers fatal. Failure to write a result
or diagnostic refuses with 101; Rust panic formatting is outside this protocol.

## Recovery and ownership

New registration rejects existing journal, lock or sibling head, including an
empty interrupted enrollment. Structural `open` validates local files but grants
no runtime load, CAS, daemon or trusted export admission. Pinned reopen requires
both full-journal count and root to match an independently supplied value before
any local head repair. An unknown newer tail also fails. A sibling head remains
a crash-recovery record and never supplies independent freshness.

Authority reads, CAS and pin export revalidate retained FDs, named endpoints and
the complete live hash chain against the observed head. Length and metadata must
remain stable through verification. In-place truncation, coherent rollback and
replaced namespaces cannot return an old cache as current. CAS error priority
and file/directory sync order follow the original; failed mutations leave the
owner fenced where the original does.

The socket lease is separately locked. Stale recovery needs a matching lease
record (device, inode, UID, mode, links, ctime), explicit nonblocking connection
refusal and a repeated same-socket check. Live, saturated or ambiguous probes do
not authorize removal. Owner revalidation occurs after a complete frame, so a
connect-only liveness probe cannot fence an idle owner. One elapsed-time budget
covers header, body, retries and partial reads. Duration::MAX uses subtraction
and time_t saturation rather than overflowing an Instant deadline.

Ledger recovery validates complete history, published head, observed live
prefix and exact caller source/target before cleanup or repair. Supplied
source/target are operation context, not independent freshness. ThirdState
preserves journal-ahead and temporary evidence. A failed mutation fences the
owner; `head()` remains the original cached accessor. Repeated target append is
idempotent. Write, fsync, rename, directory sync, head publication and replay
keep their original order.

Failed constructors close all acquired descriptors. Explicit close releases
owner locks and makes its private arena reusable. A client owns its exact path
bytes, so later request-buffer reuse cannot mutate its path.

## Framed native method API

`checkpoint-store-api` processes stdin requests and stdout responses. One process
holds one explicit owner context: absent, authority, client or ledger. Separate
native processes provide independent contexts. The boundary exposes no private
memory offsets. EOF between requests exits cleanly; partial envelopes, reserved
bits or truncated bodies refuse with 64. Pipe/allocation failures cannot report
success. Request storage grows with actual length and is reused.

All envelope fields are little-endian u64; original payloads keep original byte
order. Request: `HCSAPI01` (8 bytes), method, exact body length, reserved zero,
then body. Response: `HCSAPO01`, status, error identifier, errno, payload length,
echoed method, then payload. Header sizes are 32 and 48 bytes. Status 0 is
success, 1 an original operation error, 2 an API shape/owner error. Error payloads
are original Display UTF-8. Typed values must be canonical at this language
boundary; invalid typed encodings are API failures rather than fabricated Rust
method calls.

A `cp` is a 672-byte canonical checkpoint; a `pin` is an 84-byte canonical
full-journal checkpoint. A `path` is the exact remaining raw Unix bytes, including
non-UTF-8 when allowed by the original. CAS body: `present:u64 || expected:cp ||
target:cp`, 1,352 bytes; expected bytes are unused when absent. Load result:
`present:u64` and optional cp. Ledger head: `sequence:u64 || cp || digest:32`.

| Method | Owner | Body | Original entry/result |
| --- | --- | --- | --- |
| 1 | any | bytes | Pin `decode_canonical_exact` → pin |
| 2 | any | pin | Pin `encode_canonical` → pin |
| 3 | any | pin | Pin `record_count`, `root` → u64 + 32 bytes |
| 4 | any | path | `read_external_journal_checkpoint_v1` → pin |
| 5 | any | pin + path | `write_new_external_journal_checkpoint_v1` |
| 10 | absent | path | Authority `open` |
| 11 | absent | path | Authority `register_new` |
| 12 | absent | pin + path | Authority `reopen_with_external_checkpoint` |
| 13 | authority | empty | `log_path` → bytes |
| 14 | authority | empty | `journal_checkpoint_v1` → pin |
| 15 | authority | empty | `revalidate_bound_endpoints_v2` |
| 16 | authority | scope:32 | `load_checked` → optional cp |
| 17 | authority | CAS body | `compare_and_advance_checked` |
| 18 | authority | path | `serve_unix`, consumes owner |
| 19 | authority | empty | Release authority |
| 30 | absent | path | Unix client `new` |
| 31 | client | seconds:u64 + nanos:u64 | `with_timeout` |
| 32 | client | empty | `socket_path` → bytes |
| 33 | client | empty | `journal_checkpoint_v1` → pin |
| 34 | client | scope:32 | `load_checked` |
| 35 | client | CAS body | `compare_and_advance_checked` |
| 36 | client | scope:32 | Store trait `load` |
| 37 | client | CAS body | Store trait `compare_and_advance` |
| 38 | client | empty | Release client |
| 40 | absent | cp + path | Ledger `initialize_new` |
| 41 | absent | source:cp + target:cp + path | `open_existing_expected` |
| 42 | ledger | empty | `head` → ledger head |
| 43 | ledger | source:cp + target:cp | `append_exact_successor` → head |
| 44 | ledger | source:cp + target:cp | `resolve_exact_source_or_target` → 0/1 |
| 45 | ledger | empty | Release ledger |
| 50 | any | path | Original `read_checkpoint_file_v1` → cp |

Diagnostics 60–62 provide produced error Display, fixed codec calls and original
capability flags. They cannot authorize recovery or activation. Method 60 takes
known error identifier and normalized errno. Method 61 takes codec number 0–17
plus the exact input documented in `abi.json`. Method 62 returns bits 0 (Unix
adapter), 8 (ledger implemented), 9 (exact source/target); activation is false.

Error IDs contain category in high u32 and the first four SHA-256 bytes of
`category-name:original-detail` in low u32; the finite set has a checked collision
invariant. Positive OS errno stays exact. Non-OS tags are `2^32 + tag`: 1 EOF,
2 WriteZero, 3 frame deadline, 4 filesystem NUL, 0x104 address NUL, 0x204 address
length, 0x305 live socket, 0x404 zero timeout. Trait methods preserve the original
three closed store errors.

## Qualification

Use unchanged Rust 1.95.0 and the complete retained original suite as the oracle.
Final runtime receipts must bind the exact HIA sources, native artifacts,
original sources and adapters. Source admission or this document does not stand
in for actual API, CLI, Unix socket, fsync, restart or failure-boundary evidence.
The original crate cannot be retired based on a successful build or a subset of
these comparisons.


The complete qualification entry point requires the same pinned compiler and
Rust 1.95.0 tools on `PATH`:

```sh
python -B -m hia.platform.checkpoint_store.qualify --output /absolute/new/qualification
python -B -m hia.platform.checkpoint_store.qualify --verify /absolute/new/qualification
```

This command builds both native executables, builds the locked original Cargo
graph in a separate target directory, runs all 77 retained original tests,
checks the standalone Rust adapter formatting, and requires strict Clippy and
original package formatting. It then executes six complete comparison groups:
208 public API, 151 history/recovery, 111 file/numeric/CAS, 23 finite CLI,
168 Unix observations and 131 durability observations. The 792 observations
contain 675 paired API calls and 31 paired CLI invocations. Eight additional
mixed-client mutations and two rollback probes are bound to their actual API
process streams, for 1,360 captured API request/response transactions.

The Unix group uses real sockets, production daemons, independent external
pins, live and saturated listener ownership, malformed peers and elapsed-time
budgets. The durability group runs 23 boundary scenarios in both executables:
15 real SIGKILL cuts after successful storage syscalls and eight explicitly
injected EIO failures. The controller traces only children it creates. These
are process-crash and syscall-failure observations, not power-loss testing.

Readback checks exact compiler inputs/outputs, frozen native image identities,
all original test names and invocation flags, each actual API/CLI process
stream, daemon termination, and the selected syscall entry/exit for all 46
traced children. Thirty-one negative controls modify private evidence copies:
missing or rewritten inputs, coherent compiler-output forgery, symlinks,
traversal, duplicate JSON fields, changed dependencies, omitted original tests,
relaxed Cargo/Clippy commands, filtered test invocations, false comparisons and
missing durability actions must all be refused. The production sources and
original observations remain unchanged during these controls.

Reports record failure rather than skip Unix, ptrace, fsync or original tests
when the host cannot provide them. A successful build alone remains distinct
from a complete `qualification.json` with successful independent readback.
