# Native durable peer lease store

This component implements the original `PeerLeaseStoreV1` with an actual private
Linux process owner. HIA opens and retains the journal, directory, and exclusive
lock file descriptions, replays the real on-disk records, keeps the current
leases and session history privately, and writes and synchronizes each original
record and head file. The host driver only starts the executable and transfers
original method arguments and observations. No host supplies accepted state,
record hashes, replay decisions, file descriptors for authority files, or
authorization decisions.

The implemented original public methods are `open`, `path`, `last_hash`,
`last_now_ms`, `active_lease`, and `latest_generation`, with owner destruction
and held-lock release. The original crate-private `apply(request, now_ms)` is
also implemented, including Acquire, Renew, Revalidate, and Release. Its clock
argument has exactly the original meaning: it is a clock sample supplied by
the owning service. This internal store boundary does not authenticate a
remote clock or turn a caller into the original daemon.

The Unix daemon, client, credential and Core authentication, payload metadata
and body stores, and recovery acknowledgement ledger remain outside this
component. The complete original package remains retained. This executable
has not been activated against deployed authority state.

## Private runtime

`owner_policy.hepta` contains the state machine and all store semantics.
`linux_emitter.hepta` emits the static Linux x86_64 executable prefix. The
locked native HIA compiler compiles both files; the resulting native emitter
produces the exact prefix, which is concatenated with the compiled policy.
There is no runtime interpreter, Rust fallback, assembler, dynamic linker,
or Python store implementation.

The literal machine instructions in the emitter are a separate trusted system
boundary. Structural ELF inspection and HIA checking do not constitute a proof
of those instructions. That boundary admits only the explicitly used syscall
numbers and pointer layouts, checks every buffer and path extent, executes the
actual syscall, and returns its actual result to the HIA state machine. The
process owns one anonymous private read/write mapping of 302,129,152 bytes.
Its event area, command area, journal copy, and scope/session indexes are never
exposed through the public transport. The journal area accommodates the
original 256 MiB read bound plus the extra byte used to detect an overrun.
The two private indexes each have 2^21 entries, compare complete original
keys after collisions, and point into immutable private journal records.

The maximum journal size remains exactly 268,435,456 bytes. There is no smaller
test-only journal bound in the implementation. Under the original held-lock
model, the journal bound also bounds both indexes. If a noncooperating writer
continually truncates the file while the same owner appends enough records to
exceed that private history extent, the native process refuses with resource
status 83; it does not discard history or silently claim original support for
unbounded hostile mutation.

The process admits three distinct FIFO descriptors for stdin, stdout, and
stderr with the required access directions. Optional diagnostic gate pipes
must also be distinct, have the required access directions, and not alias
stdio. The store itself opens every authority file. A transport failure stops
the process and lets the kernel release its retained file descriptions.
SIGPIPE is ignored so write errors are observed. Diagnostic error writes are
bounded. The executable contains one RX load segment and a non-executable RW
stack; it does not create an executable mapping at runtime.

## Original persisted bytes and order

The existing TPLR version 1 journal and TPLH version 1 head schemas are unchanged.
Each journal record is 236 bytes: a 42-byte header, a 162-byte payload, and a
32-byte SHA-256 digest of the preceding 204 bytes. The header contains the
outer operation tag, payload length, and previous-record digest. The payload
contains its original operation tag, scope, session, generation, expiry, and
observed clock. Each head is 80 bytes: magic/version/reserved fields, record
count, journal head digest, and the original domain-bound checksum.

Original replay behavior is preserved even where it is less restrictive than
a new design might be. Both encoded operation tags must be valid, but replay
does not require them to equal each other. A hash-valid replayed zero session
is not rejected merely because a new live Acquire would reject it. A head
behind the journal is reconciled using the original count-based rule; this
component does not add a check against that head's historical digest.
Hash, chain, scope, transition, expiry, generation, observed-clock, head-size,
head-count, and stale-temporary failures retain their original precedence.

Interrupted I/O follows the actual
[original standard-library wrappers](https://github.com/rust-lang/rust/blob/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/fs/unix.rs):
complete reads/writes, open, fsync, and chmod retry EINTR; metadata and seek
propagate it. Actual syscall-error controls check both retry and refusal,
selecting the relevant private-file metadata and final seek from an observed
baseline trace instead of assuming a libc-specific syscall ordinal.

A mutating request performs these operations in the original order:

1. Validate the request and private lease/history state, check the current
   physical journal extent, and append the complete 236-byte record.
2. Synchronize the journal, open and synchronize the current parent directory,
   then commit the record, clock, head hash, lease, generation, and session
   history in private memory.
3. Create a unique head temporary file with exclusive creation, check its
   private regular-file metadata, write the complete 80 bytes, synchronize it,
   and retain its identity.
4. Rename the temporary over the head, verify the published path still has
   that identity, then synchronize the directory descriptor held by the owner.
5. Return the token only after all preceding steps succeed.

A write or synchronization failure poisons the live owner. If the failure
occurs before the private commit, getters retain the previous committed state.
If temporary creation, head writing, head synchronization, rename, or final
directory synchronization fails after that commit, getters retain the new
committed state. In both cases a later `apply` returns AuthorityCorrupt. Failed
head temporaries are retained, including empty or partially written files.
Cold replay rejects matching stale temporary entries instead of removing them.
These properties are tested through actual file faults, kernel resource/error
controls, and explicitly labeled ptrace syscall-error injection.

The highest live observed clock includes read-only operations and business
rejections, as in the original. A rollback poisons the owner. Getters expose the
last persisted clock, not that higher live observation. Acquire retry, permanent
session reuse rejection, exact fencing, expiry, checked generation increments,
and the original TTL range of 1,000 through 120,000 milliseconds are preserved.

## Path and namespace behavior

Paths use raw POSIX bytes, including non-UTF-8 names. The input path must be
absolute. Parent preparation preserves the original private mode, effective
owner, ancestor ownership, writable-ancestor exception for root-owned sticky
directories, and canonical-alias checks. Regular authority files must have
mode 0600, one link, and the effective owner; no-follow opens reject symlink
files. Missing parents are created privately in the original order.

The original `Path` behavior is preserved for `parent`, `file_name`,
`with_extension("lease-lock")`, and `with_file_name`. Redundant separators and
dot components do not authorize a symlink alias. Crucially, sidecar derivation
retains the original raw prefix where Rust does, so an expanded lock pathname
can fail with actual ENAMETOOLONG even when the original journal string fits
the transport. Leading-dot, multiple-dot, trailing-dot, trailing `/.`, and
trailing `/..` cases are compared with the executed original implementation.
A non-UTF-8 basename uses the original `lease` fallback for the head name while
the lock name continues to use raw bytes. Stale-temp scanning ignores an entry
whose entire filename is not valid UTF-8, exactly as the original does.

The qualified Rust 1.95.0 path-library profile is reproduced from its
[exact compiler-commit source](https://github.com/rust-lang/rust/blob/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/path.rs).
Its `with_extension` first shortens the complete raw path by the original
extension length, then applies `set_extension` to that intermediate path.
Consequently `/a/..x` produces `/a/..`, while `/a/..x/.` produces
`/a/..lease-lock`. Both the two-stage byte operation and the resulting actual
store-open behavior are covered; the native code does not replace this with
a guessed suffix-normalization rule.

This preserves the original cooperating-lock ownership model. It does not
claim continuous safety against a hostile same-UID process replacing paths
between checks, physical power-loss qualification, or a new storage schema.

## Observation transport

All integer words below are unsigned little-endian `u64`, except for the
one-byte direction in an encoded scope. The entry bootstrap is `PLSTO001`,
path byte length, diagnostic write FD, diagnostic read FD, then the raw path.
Both diagnostic words are `u64::MAX` for ordinary operation. The explicit
transport path bound is 4,095 bytes; derived sidecars are still checked by the
actual kernel and are not shortened to make them pass.

Each subsequent command is `PLSC0001`, operation, then its exact payload.

| Operation | Original operation | Payload | Success body |
| --- | --- | --- | --- |
| 0 | Drop owner | Empty | Empty; process then exits |
| 1 | `last_now_ms`, `last_hash` | Empty | Clock word and 32-byte digest |
| 2 | `active_lease` | Scope, 105 bytes | Presence word and optional token |
| 3 | `latest_generation` | Scope, 105 bytes | Generation word |
| 4 | Crate-private `apply` | Request, 209 bytes | Token, 185 bytes |
| 5 | `path` | Empty | Exact original raw path bytes |

A scope is local digest, remote digest, direction byte, epoch word, peer-scope
digest. **Direction 1 is Outbound; direction 2 is Inbound.** A token adds session
digest, generation word, expiry word, and record digest. An apply request is
operation word, original `now_ms` word, scope, session digest, generation, expiry,
TTL, and record digest. Operation tags are 1 Acquire, 2 Renew, 3 Revalidate,
and 4 Release. Invalid scalar domains are transport errors and are not silently
truncated into valid Rust enums or scopes.

Each response is `PLSR0001`, command, category, code, payload length, payload.
The initial open response uses `u64::MAX` as command. Category 0 is success,
1 is an original InvalidRequest, 2 is original I/O, 4 is an original lease
rejection, and 100 is a malformed typed method payload. `abi.json` and the
transport-only `original.rs` define the complete error mapping. Actual original
Debug and Display error text is retained on stderr. An embedded NUL normalizes
the original non-errno I/O error to code 22; head metadata errors deliberately
wrapped into `io::Error::other` retain a distinct 8192-plus-errno code.

Diagnostic gates emit `PLSCUT01` and six words: sequence, phase tag, opened flag,
journal FD, directory FD, and temporary FD. One byte `01` resumes execution.
They only pause observation; they never set state or return a simulated syscall
result. Tags 1 through 12 are documented in `abi.json`. Qualification sends
actual SIGKILL at tags 2 through 10 and compares the physical resulting files
through fresh native and original recovery owners. SIGKILL is explicitly not
a power-loss experiment.

## Build and qualification

Run the repository preflight before editing or building. With the locked HIA
toolchain and native compiler configured, build into a fresh external directory:

```sh
bash scripts/project-preflight.sh
python3 -B -m hia.platform.peer_lease_store.build --output /private/work/build
python3 -B -m hia.platform.peer_lease_store.qualify --output /private/work/qualification
```

The qualification requires actual Cargo/Rust, Linux sockets, strace/ptrace,
and the original crate's complete dependency graph. It executes the full
unchanged original crate with all features, no test filter, and `--no-fail-fast`.
It also compiles the exact original store and protocol modules unchanged into
the observer and executes their retained unit tests. A failed original baseline
fails the qualification; unavailable sockets or ptrace are not skipped.

An earlier remote original baseline can only be admitted with
`HIA_PEER_STORE_ORIGINAL_BASELINE`, `HIA_PEER_STORE_ORIGINAL_ARCHIVE`, and
`HIA_PEER_STORE_SOURCE_ARCHIVE` all supplied. The actual archive members,
binaries, raw streams, complete original source, terminal process result, and
host provenance are reread and matched. The current complete original crate
is separately built for the observer. This reuse does not relabel a failed
local original test as a local pass. `HIA_PEER_STORE_CARGO_TARGET` may point to
an independent reusable Cargo cache; actual executed artifacts are separately
captured as evidence.

For another Linux host without the hosted Hepta authoring package,
`--native-build-input /private/captured-build` requires the exact earlier
Core-admitted source snapshot, full compiler proof, and actual compiler binary.
`replay_build.py` mechanically reconstructs the declared HIA composition,
checks every source byte, then actually runs the native compiler twice and
the emitted writer once on that host. All newly emitted bytes must match the
earlier executed build. The report distinguishes this actual native replay
from a fresh hosted Core admission.

The report requires every expected test to start and complete successfully,
all source bytes to remain unchanged, both original gates to pass, and every
recorded comparison to agree. Raw inputs, outputs, errors, gates, actual
syscall traces, compiler results, binary bytes, source snapshots, and physical
namespaces are retained. Sparse 256 MiB cap-control files retain their complete
bytes without forcing holes into allocated disk blocks. Actual partial-roster
and deliberate-failure controls are available through `--only` and
`--inject-failure`; these must report INCOMPLETE and FAIL respectively.

The result remains a source-bound durable-store qualification. Native daemon
integration, full-package retirement, deployment, and whole-chain completion
are separate unfulfilled obligations.
