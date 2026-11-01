# Native PNQ2 external rollback witness, version 1

## Status and scope

This is an opt-in native component and a system acceptance input. It is not a
whole-chain post-quantum qualification, a production witness deployment, a WAN
service profile, or a claim that an independent operator has been audited.

This source was reconstructed after the unpublished candidate was lost. The
lost patch digest
`90a973df2f4c4a1d16272875e8bc330e82d2faa7a727889512fd056cb7248aa4` identifies
the lost artifact, not this reconstructed candidate. Its historical check or
test results cannot qualify this source. Current-source build and native test
receipts must be attached to the exact published candidate and prospective
merge source under the repository's source gates.

The protected state consists of exactly these PNQ2 owner tables:

- `pq_network_resource_v2`: connection, received-byte and signature-attempt
  consumption;
- `pq_network_peer_v2`: peer sequence high-water marks and revocation bits;
- `pq_network_request_v2`: retained requests, pending/completed/retired status,
  response bytes and response digests.

The local binding metadata and checkpoint are not independent trust anchors.
They can be rolled back together with the Node database. An independently
retained witness head supplies the necessary information outside that rollback.

Account state, blocks, History, chain selection, task state, CURRENT, model
installation, FinalUse, and financial effects outside these three tables are
not committed by this component's root. A guarded PNQ2 request can execute a
native PQ account transaction, but that composition does not extend the root's
coverage to account or whole-node rollback.

## Required trust boundary

The Node executable, configured policy/binding and writer signing credential
must remain trusted when the adversary restores or modifies the Node database.
The service executable, witness signing credential and independently retained
witness database must remain outside the same rollback domain. The witness
authenticates the configured writer; it does not re-execute or establish the
semantic validity of a proposed table root. A malicious holder of the writer
credential can request arbitrary successor roots.

The service checks an owner-only, single-link regular database file and a
same-euid parent directory that is not group/other writable. Registration creates
the file with mode `0600`. Existing-file validation rejects group/other file
permission bits; it does not claim that every accepted mode is exactly `0600`.
Descriptor/path device and inode identities are retained and checked, including
the immediate parent. SQLite is opened with NOFOLLOW and without CREATE for
ordinary open. These checks do not protect against a malicious same-uid/root
operator or rollback of the independent service itself. Ancestor namespace
protection remains an operator responsibility, as in the existing local native
owner/checkpoint-store assumptions.

The existing M03 `trnm-checkpoint-store` version-2 whole-owner checkpoint format
and this version-1 three-table witness are different contracts. Their roots,
serialized fields and authority scopes are not interchangeable. This component
does not replace an M03 whole-owner requirement with a smaller PNQ2 root.

## Explicit provisioning and open

`WitnessBinding::new` binds the exact canonical PNQ2 policy bytes, a positive
generation, a canonical ML-DSA-65 witness SPKI and a canonical ML-DSA-65 writer
SPKI. The witness and writer key identities must differ. No incoming packet can
enroll a key, change the policy, increment the binding generation, or reset the
external sequence.

`initial_network_checkpoint` computes the deterministic initial three-table
root from the selected policy and binding. `DurableWitness::register_new`
requires sequence 1, a nonzero 64-byte root, the pinned service signer and a new
file created exclusively. It is a distinct, explicitly privileged provisioning
operation. It refuses an existing file.

`DurableWitness::open_existing` requires existing state. Missing, malformed,
wrong-binding or replaced state is an error, never a request to enroll or reseed.
There is no network enrollment/reset operation.

`Node::create_with_pq_witness` requires a new Node database and an already
provisioned external head. `Node::open_with_pq_witness` requires an existing Node
database. Both select `StateBackend::PqWitnessV4`, with schema namespace
`native-pq-network-witness-schema-v4`. The ordinary PNQ2 and classical native
constructors cannot silently open this incompatible schema.

The Node verifies the local checkpoint against a fresh external observation
before ordinary active-state reads and recovery. Existing binding, policy and
fixed-context metadata are compared using SQL scalar type/length/value checks
before copying any corresponding BLOB into a Rust vector. This is a claim about
the new Rust read path, not a hard RSS or execution-time bound on SQLite itself.

## Signed wire contract

All integer fields in the witness protocol are unsigned big-endian values.
Checkpoints contain an 8-byte sequence followed by a 64-byte root. Sequences are
positive and no greater than `i64::MAX`; a root of all zero bytes is invalid.

The canonical binding starts with
`TRNM/PNQ2/external-owner-witness/binding/v1\0`, followed by generation (8 bytes),
canonical policy byte length (8 bytes), the policy bytes, witness SPKI and writer
SPKI. Its identifier is SHA-512 of those complete bytes. Canonical SPKI widths
are fixed and verified by the existing ML-DSA-65 implementation.

| Message | Unsigned body | Signature |
| --- | --- | --- |
| Request | 245 bytes: `PWR1` (4), operation (1), binding identifier (64), previous checkpoint (72), next checkpoint (72), challenge (32) | ML-DSA-65, 3309 bytes |
| Reply | 172 bytes: `PWS1` (4), binding identifier (64), observed checkpoint (72), echoed challenge (32) | ML-DSA-65, 3309 bytes |

Request signatures cover the exact body prefixed by
`TRNM/PNQ2/external-owner-witness/request/v1\0`. Reply signatures cover the exact
body prefixed by `TRNM/PNQ2/external-owner-witness/reply/v1\0`.

Operation 1 is Current and requires both checkpoint slots to be zero. Operation
2 is Advance and requires `next.sequence == previous.sequence + 1`. Every client
request uses a fresh 32-byte OS-random challenge; no deterministic counter or
stored database nonce substitutes for it. The client validates fixed wire
length, magic, binding, challenge, canonical signature and checkpoint fields.
A previously captured signed reply cannot satisfy a new challenge.

`ConnectedWitnessTransport` uses a caller-established Unix stream. The caller
owns connection establishment and its bound. Reads and writes recompute the
remaining time before every partial I/O operation and retry, using one absolute
deadline. A byte arriving periodically cannot renew that deadline. Each client
exchange is capped at 250 ms and, for live ingress operations, additionally at
the original request deadline. No confidentiality is provided by this protocol.

## External durability and compare-and-swap

The independent SQLite database has the exact `witness_v1` schema, containing
one binding, current checkpoint and immediately preceding checkpoint. Unknown
schema objects, including names that resemble SQLite prefixes, are refused.
Schema checks use bounded scalar comparisons before materializing names or SQL
text. Stored binding/root widths and storage classes are also checked before
BLOB reads.

Advance holds an IMMEDIATE transaction. A new transition requires exact
equality of the currently retained checkpoint and the proposed predecessor.
An exact retry is accepted only when the current checkpoint equals the proposed
successor and the retained preceding checkpoint equals the original predecessor.
Forks, skipped sequences and wraparound refuse. The service commits under
`synchronous=FULL` before creating a signed success reply.

The service cannot tell whether its own entire database was rolled back.
Independent retention of this database is therefore a security premise, not
something provided by its local previous-root field or SQLite checksum.

## Node transaction and failure ordering

Every protected mutation begins a local IMMEDIATE transaction, obtains a fresh
authenticated Current response, compares it to the local checkpoint, and
recomputes the protected root. Permission reads for revocation, sequence,
pending replay and cached responses use that same transaction. An earlier
unlocked permission read is never retained as authority.

The root is SHA-512 over an explicit versioned domain, binding identifier,
fixed ordered table names, ordered rows, row widths and typed canonical values.
Null, integer and BLOB values have separate encodings. Counts, cumulative wire
and response bytes, field storage classes and fixed-width BLOB lengths are
checked before the hashing scan. Existing PNQ2 row, byte and ingress limits
remain unchanged; DDL CHECK constraints alone are not trusted after an offline
restore.

When a protected root changes, the Node updates its local checkpoint within
the still-uncommitted transaction, sends external Advance for that exact
predecessor/successor, authenticates the receipt, and commits locally. This
ordering deliberately prefers detectable unavailability over replay of old
authority after an uncertain transition.

| Cut or failure | Local/external outcome | Required behavior |
| --- | --- | --- |
| Known cancellation before transport entry | No external request was sent; local transaction rolls back | Keep the client usable; a later legitimate operation may succeed on the same owner |
| Live cancellation after Current but before Advance | External head unchanged; local transaction rolls back | Refuse the operation before inserting or granting new pending authority |
| Authenticated successful Advance, then live deadline/callback expiry | External successor is known | Commit the corresponding local state first, then refuse late live use or ACK |
| Advance may have committed but response is missing, incomplete, invalid or unauthenticated | External outcome uncertain | Latch the client unavailable and refuse subsequent protected authority |
| External Advance succeeded but local commit failed | External head is ahead of local state | Latch unavailable; a fresh cold open must detect mismatch; no implicit rewind or repair |
| Complete old Node snapshot including its local checkpoint is restored | Retained external head differs | Refuse guarded open before ordinary recovery |

An authenticated matching CAS receipt remains usable for local reconciliation
when signature verification finishes after the original live deadline. A
freshness deadline still applies to Current. An unauthenticated or incomplete
reply cannot take this success path.

Latching the witness client also invalidates existing PNQ2 execution epochs.
Healthy owners issue nonzero epochs; zero is a terminal invalidation marker for
the unavailable owner. A worker that already obtained Execute cannot retain
its old epoch merely because a revoke CAS reply was lost. Known cancellation
before sending leaves the client and existing epoch usable. Expired-pending
retirement publishes its epoch invalidation even when a late live callback
refuses after the retirement was already committed.

Finish preserves the actual result after execution. Witness exchanges retain
their own cap. This does not establish an independently timed completion tail:
SQLite work, synchronous signature work and owner acquisition are not all hard
preemptible. The component makes no new public-load availability claim.

## Concurrency and recovery limits

A fresh Current observation is not a distributed lease. Two database clones
with the same trusted writer/binding may both observe the same pending
checkpoint and begin business work. External CAS orders protected table
transitions; it does not by itself prove exactly-once business execution or
exclusive authority over account state.

An unavailable client requires explicit owner replacement and a new fresh open.
If local and external state still agree, that open can resume service. If a CAS
outcome left them mismatched, the implementation does not infer, auto-enroll,
refund, reset a nonce, clear revocation, or repair from an older checkpoint.
Operational reconciliation for that mismatch remains a separate design task.

`pq_network_status` is local observation. It does not attest that the witness is
reachable or that the shown local head has just been externally confirmed.

## Required native controls

The reconstructed source includes exact native controls for whole SQLite plus
checkpoint rollback; external outage; lost successful CAS reply; actual local
commit failure after external CAS; signed reply replay; missing external state;
generation/policy/identity substitution; exact CAS retry and conflicting
successors; file replacement; fixed-width and metadata corruption; fresh
pending/cached permission checks; before-send cancellation and same-owner
recovery; authenticated late-success reconciliation; retirement epoch
publication; and invalidation of already-admitted work after uncertain revoke.

Socket controls exercise partial-read slow-drip behavior on both endpoints.
A composed control uses native PQ application v6, actual PNQ2 TCP Submit,
invalid-signature refusal followed by a legitimate transfer of 42 units and
cached replay, and a separate witness process that cold-reopens the retained
service database. It checks the resulting account balance and retained network
usage on a cold Node reopen. The child test harness is excluded from meaningful
control counts, and its libtest output is captured instead of being mixed into
the parent's exact-test receipt.

These controls must run against the current source with the pinned native
provider and required CI source identity. They do not replace original capacity,
large-state, History, WAN, quantum work/difficulty, migration or complete Hepta
acceptance gates, and they do not license a whole-chain PQ claim.
