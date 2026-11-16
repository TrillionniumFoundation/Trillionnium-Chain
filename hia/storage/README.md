# Native HIA transaction StoreOwner

This component owns a fresh private directory, a process lock, immutable
transaction payloads, an atomically published HEAD, and cold recovery. Both its
policy and its static ELF writer are HIA source. The runtime calls Linux directly;
it does not delegate persistence to Rust, SQLite, Python, libc, or a daemon.

It is a streaming generic transaction owner. Node branch/reorganization/replay/
outbox reducers are not integrated here, and an arbitrary payload is not an
authorized block, State root, request acknowledgement, or consensus fact.

## Implementation and build

`owner_policy.hepta` is the explicit state machine. `sha256_framing.hepta` frames
the bounded storage hash messages and uses the existing SHA-256 compression
functions from `src/protocol/state_root.hepta`. There is one canonical copy of
that compression algorithm. The builder uses the explicit component manifest,
independently checks every selected dependency through Core, and invokes the
locked native compiler on the complete HIA closure.
`linux_adapter_emitter.hepta` writes the ELF layout, literal Linux x86-64 adapter
instructions, relative fixups, and exact compiled policy image. This follows the
existing platform fixture's HIA writer pattern. The emitted adapter is a separate
trusted machine-code boundary; Core buffer checking does not prove its ISA or
filesystem semantics. The build driver emits no instructions.

Run from the repository with explicit `HIA_TOOLCHAIN_ROOT`,
`HIA_NATIVE_COMPILER`, and `HIA_NATIVE_COMPILER_SHA256` matching the checked-in
compiler binding:

```sh
python -B -m hia.tools.qualify_storage --output /absolute/fresh/output
```

The CI workflow runs this complete persistence qualification as a separate
required step. `test_storage_native.py` contains the small native buffer-shape
and open-command contract controls; it does not repeat the complete process and
filesystem suite inside the general native unit tests.

Build outputs and actual case transcripts stay outside the source tree. Source
and compiler identities are checked again after qualification. Hosted build and
test orchestration remain explicit; this is not a wholly native development tool
chain claim. SHA provenance and the absence of an inferred upstream license grant
remain documented in the parent HIA README.

## Capability and protocol

The exact wire and disk formats are in `abi.json`. The first 80 stdin bytes supply
the actual inherited directory descriptor, the fresh/existing mode, the expected
context, and an explicit optional observer/gate descriptor pair. The native
program opens its own directory description relative to that descriptor and
closes the transferred input descriptor. It neither accepts a filesystem path
from a peer nor uses the working directory as storage authority.

Directories must be owned by the effective UID and have mode 0700. Required
FORMAT, HEAD, owner.lock, and referenced transactions must have mode 0600, the
same UID, one hardlink, the exact required length, and the regular-file type.
The data files open with O_NOFOLLOW, O_CLOEXEC and O_NONBLOCK; fstat checks their
type before any data read. This prevents a referenced FIFO from blocking startup
or consuming queued pipe data. It does not impose a hard deadline on ordinary
file I/O. The process holds `owner.lock` exclusively until close or exit. It
rejects old SQLite filenames, unrelated names, symlinks in required file
positions, wrong contexts, and a nonempty fresh namespace. Allowed-name,
unreferenced remnants are ignored during recovery regardless of their type;
they are never read or promoted into committed state. A crashed incomplete fresh
initialization with no valid FORMAT is rejected; it is not silently initialized
over existing material.

After an opened receipt, requests compare both sequence and digest with the live
owner HEAD. Commit streams fixed 32 KiB chunks, with checked cumulative positions.
The artificial 16 MiB payload and 4,096-commit limits have been removed. A payload
must fit a signed Linux `off_t` together with its 128-byte header, and the next
sequence must fit `u64`. These are addressing bounds, not a claim that an entire
filesystem of that size has been qualified. The owner maps 270,336 bytes total,
including 196,608 bytes of private state, independently of payload and history
size. GET validates the current transaction before streaming its exact payload.
CLOSE releases the lock and directory. No raw descriptor or replaceable
transaction object is exported after bootstrap.

The complete classical State byte extent is now an actual physical qualification:
65,536 rows, each with a 160-byte key and a 4,096-byte canonical JSON value, form
one 279,445,512-byte SRV1 payload. One atomic commit, cold reopening and exact
streamed GET must all pass. Another control creates and synchronizes 4,105 actual
transactions, then reopens and verifies their complete chain. Both use a 2 GiB
native address-space limit and bounded test-controller buffers. Neither test
substitutes independent commits for the full-State atomic batch.

The disk and stdin formats are explicitly version 2, with new magic values and
hash domains. Old version-1 namespaces and bootstrap messages are refused
without rewriting them; SQLite import and implicit upgrade remain absent.
Recovery walks all retained transactions with constant working memory. Its time
and disk use still grow with history. Checkpointing, reference-aware compaction,
typed State/Node integration, and the original service budgets remain open.

Original `Node::open_selected_mode` uses its context-bound initialization marker
to recover interrupted creation. This owner currently refuses a nonempty partial
initialization when FORMAT has not become valid. The actual initialization-cut
controls preserve that refusal and verify that it does not overwrite old bytes;
they do not claim parity with the original automatic initialization recovery.

## Atomic publication and recovery

A commit writes its temporary transaction, synchronizes it, publishes it with
no replacement, and synchronizes the directory. It then writes and synchronizes
HEAD.tmp, atomically replaces HEAD, and synchronizes the directory again. Only
then does the owner return a durable receipt. Every positive partial read/write
advances the same cursor; retrying EINTR does not replay a completed prefix.

The HEAD replacement attempt starts an uncertainty interval. An error before its
successful directory sync ends the process with UNKNOWN_COMMIT. A caller must
reopen and compare actual committed identity; it cannot infer rollback or issue
an unconditional retry. A successful directory sync can also be followed by a
failed response write: I/O exit 70 describes a failure outside the publication
uncertainty interval and does not establish rollback. If a COMMIT response is
missing or incomplete, the caller must reopen and compare HEAD regardless of
the process exit code. Diagnostics report the owner's private committed
sequence, not a claim that the caller received an acknowledgement.

Corrupt, missing, truncated, extended, wrong-context, or
hash-inconsistent referenced transactions refuse recovery. Recovery walks every
predecessor back to the context-bound genesis. It does not adopt unreferenced
temporary or next-transaction objects as committed state.

The digest is a domain-separated SHA-256 chunk chain, specified exactly in the
ABI. It is not plain SHA256(payload), a protocol state root, or an external
anti-rollback anchor. SHA checks and an advisory lock do not defend against a
hostile same-UID writer or replacement of the whole namespace with an old backup.
The directory is exclusively delegated to the owner; privileged mount changes
and network filesystem guarantees are outside this component's qualification.

## Qualification scope

The external physical qualification driver uses Python assertions for independent
disk, crash-cut and process-result oracles. Running it with `python -O`,
`python -OO` or `PYTHONOPTIMIZE` would remove those assertions; its startup
now explicitly refuses all optimized interpreter modes before issuing native
operations. The non-optimized qualifier and the HIA runtime ABI are unchanged.
This is a fail-closed harness admission control, not new storage/recovery coverage.


The optional gate is activated only by the explicit bootstrap capability. At
documented physical stages the native policy reports a tag and waits for one
continuation byte. The qualifier can SIGKILL the real process at that point,
then reopen with the same normal runtime. Normal startup supplies neither gate
descriptor and never waits for a test controller. Closing the gate during the
HEAD uncertainty interval exercises a real I/O failure and UNKNOWN_COMMIT; it
does not pretend to be an injected filesystem EIO.

The standalone qualification runs the original 48 process/filesystem controls,
with their capacity expectation updated to the actual `off_t` bound. It also
requires old-format refusal, the complete State byte extent, and the history
beyond 4,096 actual commits. Native unit controls retain the 14 original shape/
open-command cases and add exact addressing/sequence and SHA framing boundaries.
The large streaming test controller has an explicit 180-second individual I/O
wait; this is development observation infrastructure, not a new Node deadline or
an increase of any original service CPU budget.

Actual controls cover exact large-payload readback, independent Python/hashlib
disk reconstruction, complete-chain corruption refusal, interrupted transaction
publication, lock contention, context/namespace/capacity/expected-head refusals,
short pipe reads, referenced FIFO refusal with and without a writer while
preserving queued bytes, a real file-size resource limit, and a committed transaction
whose response encounters actual EPIPE. Reports preserve each
process exit, stderr, executable/source digest, and bounded cleanup. Ptrace
availability is recorded separately; denial is UNKNOWN, never a successful
syscall trace.

Process termination controls do not model physical power loss. Ordinary file
I/O and fsync are cooperative and have no native hard deadline here. ENOSPC,
filesystem EIO, malicious filesystem behavior, cross-target execution, complete
Node semantics, original service budgets, and external witness CAS still need
their own qualification. No old runtime can be retired from this component's
success alone.
