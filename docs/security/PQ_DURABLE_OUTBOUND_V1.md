# Bounded durable PQ outbound owner V1

Status: explicit Linux loopback development component; no production activation.
This contract describes a client transport journal and sealed verified replies.
The [single development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
remains the planning authority.

Implementation provenance: local implementation
`6c2081437646203454b14a3150086e88f5d22bd2`, followed by cancellation correction
`8ba8aa97f9e9b8f288fc4d77ad046506d4cfc9b5`. API publication
`0482c7f4413c178b099188b4f4af64a6cbfb57a3` preserves the exact latter source tree
`4787f15ce291745842ffc92c7cf64f1b96130f41`, with parent
`5bb29d6ae39fa0c71f9151f3dce31fa1a3ab1800`. Publication has different Git commit
metadata; these commit IDs are not interchangeable. This provenance establishes
source identity, not native-test acceptance.

## Scope and implementation owners

The [outbound implementation](../../trillionnium/crates/trnm-pon-node/src/ingress/pq_network/outbound.rs)
owns one local SQLite journal, one signing client, one pinned destination and at
most one unresolved sequence. Its rows are separate from chain State, the Node
inbound replay ledger, account balances and migration inventories. Chain
reorganization must not restore or reset this client journal.

The [PQ client and server](../../trillionnium/crates/trnm-pon-node/src/ingress/pq_network.rs)
retain their original signed request/response grammar. The
[TLS client and server](../../trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls.rs)
retain their separately selected encrypted transport. Plaintext PNQ2/PNP2
authenticates messages without providing confidentiality. The TLS-required owner
uses its existing PQT1/PQS1 namespace and refuses the plaintext path. Request and
response bytes retained in the client journal are not encrypted at rest by this
component.

Creation is an explicit enrollment decision for a fresh peer/policy whose remote
sequence has not been spent. There is no remote enrollment handshake or discovery
that proves freshness. The operator must retain the intended context and give
this journal exclusive use of its peer credential. A separate process or journal
using the same key can strand pending operations; a local file lock does not
enforce exclusive custody of every copy of that key.

The live owner requires Linux `/proc/sys/kernel/random/boot_id` and
`CLOCK_BOOTTIME`. Other targets do not receive a substitute clock or a silent
fallback. The clock helper returns `PQ_OUTBOUND_BOOT_CLOCK_UNAVAILABLE` outside
Linux. This does not add a portable live-owner or public/WAN qualification.

## Public API

The owner is `ingress::pq_network::outbound::DurablePqOutbound`.

| API | Contract |
| --- | --- |
| `create_plaintext(path, address, client)` | Create a new journal for an explicitly selected `PqClient`; existing paths refuse. |
| `open_plaintext(path, address, client)` | Open and audit an existing journal; missing paths refuse without enrollment. |
| `create_tls(path, address, client)` | Create with an explicitly selected `PqTlsClient`; requires `pq-native-openssl`. |
| `open_tls(path, address, client)` | Reopen the same TLS context and journal; requires `pq-native-openssl`. |
| `prepare(request, expires_at, lifetime)` | Allocate the next sequence, sign once and durably retain the original wire and local operation deadline. Returns a `PendingPqOperation` observation. |
| `send_pending(attempt_deadline, cancel)` | Reserve a durable attempt, send only retained bytes, verify the signed reply and persist a terminal receipt before returning success. |
| `record_verified_reply(&VerifiedPqReply)` | Record an authenticated terminal for the exact owned wire. Duplicate identical retained receipts are idempotent. Public `PqResponse` values are not accepted. |
| `cancel_pending()` | Persist cancellation of the unresolved operation. It does not erase its record or infer the remote outcome. |
| `status()` | Return completed sequence, record count, reserved bytes and an optional pending observation. These fields do not grant authority. |
| `retained_response(sequence)` | Return an optional historically reverified `PqResponse`; it is not a fresh sealed reply or live send authorization. |

`PqClient::send_verified` and `PqTlsClient::send_verified` return
`VerifiedPqReply`. Its fields are private, with no public constructor or
deserializer. It retains the verified policy, peer, sequence, operation, an exact
request-wire digest, signed response bytes and decoded response. Immutable
accessors expose `response()`, `wire()`, `operation_id()` and `sequence()`;
`into_response()` discards the seal. The legacy `send(...) -> PqResponse` API
continues to return the original public response type.

Both verification paths retain the original absolute deadline and signed expiry.
The final completion fence follows full signature verification, canonical
decoding and materialization of the sealed reply, including bounded wire copying
and request-wire hashing. No constructor accepts a caller-provided `ok` or
terminal flag as proof of a consumed sequence.

## Fresh namespaces and complete context binding

The journal introduces these exact local namespaces:

| Namespace | Use |
| --- | --- |
| `pq_outbound_meta_v1` | One row: `singleton`, complete `binding`, `highest_sequence`. |
| `pq_outbound_request_v1` | `sequence`, `operation`, exact `wire`, `boot_id`, `started_ns`, `deadline_ns`, `attempts`, `cancelled`, optional signed `response`. |
| `TRNM/PQNetwork/durable-outbound/binding/v1\0` | Prefix of the exact stored client binding. |
| `TRNM/PQNetwork/durable-outbound/state/v1\0` | Domain of the in-memory SHA-256 journal-state observation. |
| `TRNM/PQNetwork/outbound-exact-request/v1\0` | Domain passed to the existing protocol hash for the complete request wire in a sealed reply. |

Here `\0` denotes one zero byte, not two printable characters. These are client
storage/observation namespaces; they do not replace the existing signed PNQ2 or
TLS owner domains.

The stored binding is the following byte concatenation, in this order:

1. Exact binding-domain bytes above.
2. Canonical policy-byte length as an eight-byte big-endian unsigned integer.
3. The complete canonical policy bytes.
4. The signing peer's 32-byte key ID.
5. The UTF-8 bytes of Rust `SocketAddr::to_string()` for the destination,
   including its port.

The full canonical policy includes its schema, network, parameters, genesis,
server SPKI, generation, ordered pinned peer roster, ledger limits, ingress
connection/byte/verification limits and transport-confidentiality selection.
The TLS variant also includes the exact CA-certificate SHA-256 pin and server
name, under its distinct policy schema and transport mode. The fixed crypto and
transport implementations remain selected by their existing constructors; an
incoming frame does not choose a weaker profile.

Changing the policy, peer, transport selection or destination refuses reopen.
Neither an alternative random signature for an otherwise identical operation
nor a newly extended expiry can replace the retained request. The operation ID
alone is insufficient: `record_verified_reply` also compares the complete
request-wire digest, then rechecks the signed retained response.

## Persistence and terminal semantics

Before preparation, the owner audits the existing journal and requires no
unresolved record. It obtains the next sequence from retained completed history,
signs the request once, reserves its maximum response space and commits the exact
wire with its original boot-clock deadline. The first request starts at sequence
1; callers cannot select a different starting cursor.

Before any socket exchange, `send_pending` revalidates the retained request
against current time, checks the original deadline/expiry and durably increments
its attempt counter. A failed or uncertain local mutation cannot release a new
send. Mutations use an immediate SQLite transaction, full synchronous writes and
file synchronization. Creation also synchronizes the parent directory. A failure
after mutation entry latches the live owner with `PQ_OUTBOUND_COMMIT_UNCERTAIN`.
Cold reopen examines the actual transactional state instead of assuming an
unsuccessful local return rolled back.

The terminal meaning depends on the existing fixed native server implementation,
not on signature authentication by itself. In `PqServer::handle_admitted`, a
signed reply reaches the transport only from a previously committed cached
receipt, or after `finish_pq_network_request` succeeds. The
[inbound store owner](../../trillionnium/crates/trnm-pon-node/src/store/pq_network.rs)
atomically stores the terminal response and advances the peer's highest sequence.
The TLS server uses this same admitted request path after transport validation.

An application dispatch refusal such as `UNKNOWN_PARENT` is therefore a terminal
receipt when emitted through that completed path. Authentication, ingress
resource, replay-conflict, revocation and other admission failures return an error
without that signed terminal receipt. They cannot advance the client sequence.
The client relies on the independently pinned server and its stated owner
semantics; this component adds no remote binary attestation or proof that an
arbitrary holder of the server key obeyed those semantics.

| Observation | Durable result and permitted next step |
| --- | --- |
| Prepared, no attempt reserved | Original request remains pending. There is no erase/replacement API. |
| Attempt committed, then connection/read/verification error | Exact request and spent attempt remain; remote outcome is unknown. Exact replay may be attempted only within all original bounds. |
| ACK lost after remote completion | Highest client sequence stays unchanged until an exact, verified terminal is recorded. A replay can recover the server's original cached signed bytes. |
| Verified successful or refused terminal | Store its original signed bytes and advance completed sequence in one transaction. A later explicit preparation may allocate the next sequence. |
| Duplicate identical verified terminal | No second sequence advance or repeated local completion. A conflicting signed receipt is refused. |
| Cancellation, expiry, exhausted attempts, local operation deadline or changed boot with no terminal | Keep the unresolved record. Do not skip its sequence, re-sign it, renew its expiry or use history membership as an ACK. |
| Uncertain local commit | Current instance refuses further operations. Reopen audits the actual retained state and retains all live authorization checks. |

Unknown outcome is an interpretation of the unresolved record, not a new
successful status or proof of non-execution. There is no automatic retirement,
server-ledger reconciliation, cursor reset or journal rollover API.

Cancellation is cooperative around one bounded exchange. The initially observed
true cancellation flag is persisted before returning; the initial check has one
atomic observation, with no second read that can exit without recording it.
Cancellation detected after attempt reservation also remains durable. Already
dispatched work may complete remotely. If a valid sealed terminal has been
received, it is retained even when cancellation or a local completion overrun
prevents a timely successful return. `record_verified_reply` can preserve a
previously verified terminal fact after cancellation or expiry; that fact does
not become a new live authorization or automatic dependent request.

## Independent storage and time bounds

| Bound | Exact scope |
| --- | --- |
| 64 records | Total retained request records in one journal, including completed and unresolved records. No pruning/refund occurs on reopen. |
| 16 MiB | Logical retained/reserved content: binding bytes plus, per record, request-wire length, actual response length or a full 2 MiB pending-response reservation, and 160 accounting bytes. This is not a process-memory or filesystem-total guarantee. |
| 32 MiB | SQLite main-file limit, with 4,096-byte pages and `max_page_count=8192`, plus file-size checks. It is not a bound on all rollback-journal, filesystem or process overhead. |
| 8 attempts | Durable reservations per pending request. An attempt is not refunded if cancellation, timeout or another failure follows its reservation, even if no socket operation ultimately occurs. |
| 60 seconds | Maximum local operation lifetime supplied to `prepare`, stored as an absolute boot-clock deadline before signing. Independently, the original signed request verifier permits at most a 60-second future expiry horizon. These are separate clocks and constraints. |
| 10 seconds | Existing client cap for a single exchange. Its deadline is additionally capped by the caller's attempt deadline and remaining original operation lifetime. TCP, TLS handshake where selected, framing, signature verification and completion share that one absolute deadline. |

`MAX_WIRE` remains 2,097,152 bytes. Reserving a full response before sending
prevents a locally exhausted logical ledger from accepting a remote operation
without room for its bounded terminal receipt. Incoming Node resource limits and
TLS ciphertext/handshake limits remain independent; these client limits do not
increase them or claim certificate-verification CPU qualification.
Deadline checks refuse late successful completion; they do not preempt a
synchronous signature-verification or storage call.

Reopening in the same boot retains the original boot ID, started/deadline
nanoseconds, signed expiry, request signature, bytes, attempts and cancellation.
An expired terminal can be audited at its original signed expiry as history. A
pending live resend must pass the original current-time verifier. Historical
verification does not convert `RetainedRequest` into live `VerifiedRequest` or
produce a new sealed reply. A different boot refuses continued dispatch while
leaving retained observations inspectable.

## Storage integrity and explicit exclusions

The file owner requires an owned, private regular journal file, one link, no
symlink following, a suitable owned parent directory and a nonblocking exclusive
file lock. It retains file and parent identity checks. Existing files must pass
the exact two-table schema, binding and complete record audit before persistent
journal-mode configuration. Misidentifying an unrelated SQLite file must not
change its journal mode before refusing it.

Audit rejects excess rows/bytes and incorrect SQL types or widths before loading
retained blobs. It then verifies every retained signature and the consistent
relationship between contiguous record sequences, terminal responses, the highest
completed sequence and at most one final pending record. An in-memory state
digest detects changes against the currently open instance's prior observation.

**A coherent whole-store rollback across process restart is not prevented.**
Cold open has no independent monotonic checkpoint and derives its initial
observation from the presented database. The digest, file lock and SQLite
transactions are not an external rollback witness. This contract also does not
qualify hostile same-UID storage, custody/rotation of all key copies, durable
external effects, source-chain retirement, fork-sensitive migration activation,
production operation or WAN fairness.

This component is a prerequisite for later explicitly owned PQ submission work.
It does not implement automatic verified-parent recovery, remove the classical
guard in `submit_with_verified_parent_recovery`, add writes to the read-only
PQHistory owner, infer block finality or substitute signatures for W1 work.
No CLI/default runtime or activation flag is enabled.

It does not close the [historical account migration contract](PQ_HISTORICAL_ACCOUNT_MIGRATION_V1.md).
Old account/state authority, full nonce and liability preservation, unsupported
historical rights, complete recovery proofs, independent source checkpoints and
source retirement retain their separate obligations. Unsupported source state
continues to require refusal; passing a fresh explicit PQ account or transport
case cannot establish complete account migration.

## Required control mapping and execution status

The [nine implementation controls](../../trillionnium/crates/trnm-pon-node/src/ingress/pq_network/outbound/tests.rs)
use the exact prefix `ingress::pq_network::outbound::tests::`. They are registered
under `test`, `pq-native-openssl` and Linux. The mapping describes what the code
exercises; it is not a claim that the controls have passed on the final candidate.

| Exact test suffix | Boundary exercised |
| --- | --- |
| `real_node_lost_ack_cold_reopen_replays_exact_signed_request_and_receipt` | Real plaintext Node and block submission; durable request/attempt visible at the receiving socket; lost ACK; client and Node cold reopen; identical request bytes, cached signed receipt and remote sequence. |
| `real_tls_unknown_parent_is_committed_terminal_then_explicit_new_sequences_work` | Real TLS Node; `UNKNOWN_PARENT` consumes the actual server sequence; explicit parent then child submissions consume new sequences; reopened Node state. No automatic recovery is invoked. |
| `admission_resource_refusal_has_no_terminal_seal_and_cannot_advance_client_sequence` | Actual Node ingress-resource refusal; no signed terminal, remote sequence remains zero, client remains unresolved across reopen. |
| `sealed_reply_rejects_other_policy_peer_and_randomized_wire_even_for_same_operation` | Real signatures under changed policy/peer and alternate exact request bytes; signature tampering; original completion deadline; duplicate exact terminal idempotence. Different-context signed fixtures are verifier controls, not execution receipts. |
| `cancellation_is_durable_and_late_received_terminal_is_retained_without_timely_success` | Pre-send durable cancellation with no connection; canceled reopen; actual remote completion followed by cancellation retains a terminal without timely success. |
| `expired_pending_stays_unknown_while_expired_terminal_cold_audit_is_historical_only` | Genuine signed expiry; pending request cannot renew or advance; expired completed signatures remain historical observations; no fresh socket. |
| `original_boot_deadline_attempt_limit_and_boot_change_cannot_be_renewed_by_reopen` | Genuine connection failures with persistent attempt count; eight-attempt cap; original boot-clock deadline; changed-boot refusal. |
| `failed_durable_attempt_latches_before_socket_and_reopen_recovers_actual_state` | Actual SQLite authorizer refusal of attempt mutation; no socket before durable authorization; instance latch and cold read of actual state. |
| `create_open_context_single_writer_schema_and_storage_identity_are_fail_closed` | Missing/create-existing paths, one writer, policy/peer/address, symlinks/hardlinks/permissions, schema/types/sequence/signature corruption, 20 MiB aggregate and 65-record refusal, in-process changes, and foreign WAL/data preservation. Oversized stores are malicious input controls, not genuine terminal histories. |

The `record_verified_reply` rustdoc control is `compile_fail,E0308` and must fail
for the intended type mismatch: expected `&VerifiedPqReply`, found `&PqResponse`.
A wrong import or another unrelated compile failure is not acceptable evidence
for this boundary.

Local preliminary library checks succeeded before the final small corrections;
native-test compilation, test metadata compilation and a later library Clippy
attempt were externally terminated by SIGKILL. No new runtime test executed in
that local attempt. Those failures remain observations, not replacement passes.
Acceptance requires the final integrated source, original provider/toolchain,
retained suites and original budgets. This document neither changes those gates
nor treats component source review as native execution or release qualification.

## 2026-11-14 compatibility preservation

The original contract and failed historical observations above remain intact.
This port is selected from `bbdb1af203674fec3923c522a49b3dcc6bbca6bc`
against current source `11bdc4cce16fc7d550d361f5cc863b061204f61b`.
It retains the two journal namespaces, original request bytes, cancellation,
attempt reservations, boot-clock deadline and all nine original controls.
The only owner-file adaptation calls the current TLS selected-client accessor;
the sealed reply adapter calls the current response verifier and checks the
same original completion deadline again after constructing the seal.

The current pinned-endpoint, TLS handshake, response-evidence and explicit parent
recovery paths retain their existing behavior. This independent API has no CLI
dispatch or default startup wiring. The current profile, signed domains,
historical source locks and all activation/qualification flags are unchanged.

Linux validation used Rust 1.95.0, the exact locked offline graph and the existing
pinned OpenSSL 3.5.9 provider. On the fixed source plus these four Rust files,
all nine original native tests passed (none ignored), the one
`record_verified_reply` compile-fail doctest passed, and Node library plus CLI
strict Clippy passed with `-D warnings`. Source hashes were equal before and
after every command. These results concern this component only; they do not
establish physical rollback resistance, a complete PQ migration or public use.
The initial sparse-source attempt stopped in preflight because
`PROJECT_BOUNDARY.json` was omitted. It performed no code application or build;
the corrected checkout retained the original fixed Git tree and passed preflight
before the reported validation.
