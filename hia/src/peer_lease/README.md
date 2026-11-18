# Native peer-lease value owner

`values.hepta` implements the public immutable value operations of the original
`trnm-peer-lease` crate. HIA creates and retains private typed objects, executes
their constructors, getters, comparisons, copies, and destruction, hashes run
identifiers and payload bodies, and verifies and decodes complete recovery
status projections. The original complete Rust crate is the independently
executed comparison implementation.

This component does not yet implement the original durable lease journal,
payload metadata and body stores, recovery acknowledgement ledger, file locks,
Unix credential authentication, daemon, client, or recovery socket. The
projection's self-consistency is an integrity check, not evidence of Core
authentication or production authority. The original package remains required.

## Original behavior

The component implements `PeerLeaseScopeV1`, `PeerLeaseTokenV1`,
`PayloadReplayNamespaceV1`, `PayloadReplayFrameV1`,
`PayloadReplayRecoveryTargetV1`, `PayloadReplayCoreAcknowledgementV1`, all four
`PayloadReplayRecoveryStatusV1` variants, and
`PayloadReplayRecoveryStatusProjectionV1::from_canonical_bytes` and every
public getter. It includes the free run-ID and body digest functions and the
equivalent body-store digest helper. Original `Clone`, equality, and scope
ordering are preserved through public operations on private handles.

Constructors retain the original check order and complete typed integer
domains. An expiry, sequence, or namespace epoch of zero remains valid. The
scope's derived order compares local identity, remote identity, direction,
numeric epoch, then peer-scope digest; it does not compare the transport bytes
lexicographically. Recovery status enum fields retain the full original domain,
including zero counts or acknowledgement fields. Run identifiers accept every
valid UTF-8 string, including empty strings, NUL, and unnormalized Unicode.
Payload bodies are arbitrary bytes and retain the exact 8 MiB maximum.

The projection decoder preserves the original length, digest, header, target,
status, truth-boundary, and exact-end checks in their original order. It accepts
a zero namespace digest as the original public decoder does. Projection
integrity hashes cover the exact original canonical bytes, including the
three truth-boundary bytes. No host supplies an accepted decoded object or
an authorization decision.

## Private native boundary

The entry is `f0(input: readbuf, output: mutbuf, scratch: mutbuf) -> u32`.
All transport integer words are unsigned little-endian `u64`; every byte
extent must fit exactly. The outer input is eight bytes `PLV10001`, command
count, then commands consisting of operation, payload length, and payload.
The complete typed frame, including UTF-8 and exact end, is checked before
private object creation. Scalar transport values outside their original Rust
domain are malformed, not silently truncated.

Four actual HIA allocations own an immutable input copy, the typed object
arena, hash workspace, and staged output. The caller supplies no writable
state, object layout, allocator address, digest result, or authorization flag.
The foreign scratch buffer is unused and unchanged. Handles are native-issued,
monotonically increasing, session-local identifiers beginning at one. Failed
constructors do not consume a handle. Clone copies bytes into an independent
private slot, Drop invalidates and clears the selected slot, and handles are
never reused. All allocations are released before the foreign call returns.

| Operation | Public operation | Payload |
| --- | --- | --- |
| 0 | Scope constructor | Local, remote, peer-scope digests; direction; epoch |
| 1 | Token constructor | Scope handle; session digest; generation; expiry; record hash |
| 2 | Namespace constructor | Local, peer-scope, run, network digests; epoch |
| 3 | Namespace `scope_for` | Namespace handle; remote digest; direction |
| 4 | Frame constructor | Scope handle; run, network, session digests; generation, sequence, kind, body length; fingerprint |
| 5 | Recovery target constructor | Index; record hash; remote digest; direction; session digest; generation, sequence, kind, body length; fingerprint |
| 6 | Core acknowledgement constructor | Target handle; revision; digest |
| 7 | Recovery status enum value | Kind followed by its complete original fields |
| 8 | Projection decoder | Complete original canonical projection bytes |
| 9 | Run identifier digest | Complete valid UTF-8 bytes |
| 10 | Body digest | Complete arbitrary body bytes |
| 11 | Every public getter | Typed object handle |
| 12 | Clone | Typed object handle |
| 13 | Drop | Typed object handle |
| 14 | Equality | Two object handles of the same type |
| 15 | Scope order | Two scope handles |

Directions are 1 Inbound and 2 Outbound. Kinds 1 through 8 identify scope,
token, namespace, frame, recovery target, acknowledgement, recovery status,
and status projection. New and Clone return their handle as one word. Getter
responses begin with this type word, followed by all original public fields;
token, frame, and acknowledgement getters expand their nested value fields.
Equality returns one boolean word. Scope order returns 0 Less, 1 Equal, or
2 Greater. Drop returns an empty payload.

Status transport kind 1 has record count, head count, and `u32` temporary count;
kind 2 has record count and `u32` temporary count; kind 3 has record count and
head hash; kind 4 has record count, head hash, safety revision, Core ack digest,
and acknowledgement hash. Its getter appends recoverable and acknowledged
boolean words, then the length and bytes of the original status name.
Projection getters return canonical length and bytes, namespace and projection
digests, the complete recovery target, the status getter data, and the original
candidate-only, production-activation, atomic-Core-acknowledgement, and
self-consistency boolean words. The Rust adapter defines the exact field order
and compares every byte returned by the executed native artifact.

The result starts with `PLR10001`, command count, total result byte length,
and a reserved zero word. Each response contains operation, business status,
payload length, and payload. Business errors preserve the original display
bytes: 1–5 are the original protocol value errors, 10 is a payload invalid
request, 11 is the original body-bound error, and 20 is a recovery invalid
request. Transport-only object lookup errors are 64 absent or dropped handle
and 65 wrong object type. Business errors leave existing private objects
unchanged and do not prevent later commands from executing.

The native entry returns 0 only after publishing the complete transcript.
Status 100 rejects malformed frames or invalid UTF-8, 102 rejects insufficient
complete-result capacity, and 103 rejects failed private allocation or an
unrepresentable internal extent. Every nonzero entry result preserves the
entire external output. The output suffix beyond the published result is also
preserved. These complete-session lifetimes do not provide incremental daemon
handles or durable storage.

## Actual execution and retained gates

With the locked HIA toolchain and actual Rust and C compilers available, run:

```sh
python3 -B -m unittest hia.tests.test_peer_lease -v
```

Set `HIA_PEER_LEASE_OUTPUT` to a new directory to retain complete binaries,
raw requests and responses, compiler receipts, original test streams, native
worker streams, source identities, and a full-roster `report.json`. The native
child loads a sealed snapshot of the emitted HIA library and uses misaligned,
guarded buffers. It does not execute a Python peer-lease implementation.
Actual allocation-fault interposition rejects every private allocation and
checks cleanup and preservation of the external output.

The test driver bounds individual transports to 64 MiB and native workers to
512 MiB of address space. These are explicit test execution limits, not new
public value limits in the HIA component. The only business body bound is the
original 8 MiB limit.

Tests build the complete unchanged original crate with all features, execute
its unfiltered retained tests with `--no-fail-fast`, and compile the adapter
against the resulting real library. `HIA_PEER_LEASE_ORIGINAL_BASELINE` may
identify an already captured complete execution only when all original source
and manifest identities still match before, after, and at this run. Its result
and raw streams are copied without modification. External observations must
carry the exact unfiltered command, raw stream hashes, original binary
inventory, complete source report, retained manifest, terminal job result,
original process request, and explicit host provenance. Modified sources,
streams, target-selection flags, or test filters refuse the observation.
When this observation comes from another host, the suite separately builds
the full unchanged crate locally with `--no-run` for the real API adapter;
it never treats that local build as an executed retained test. Remote executed
binaries remain bound to their original host and complete evidence archive.
A failed original retained
suite remains a failed qualification even if every native value comparison
matches. In particular, unavailable Unix sockets are not skipped or replaced.
The report explicitly keeps whole-package retirement, durable journal owner,
Unix authority, native Core authentication, and production activation false.
