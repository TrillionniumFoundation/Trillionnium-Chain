# M14 RPC / Indexer / SDK / CLI technical specification v1

Status: **implementation contract; non-authoritative service**

## Authority

M14 owns client transport, request validation, projections, SDKs and CLI output.
M05 alone admits transactions; M06 simulates/executes; M08 supplies committed
records; M13 verifies proofs. Neither HTTP 200 nor an index row proves finality.
The API defined here is the **planned `dev-api-v1` profile**. Existing RPC
handlers are not automatically conformant, and no production availability is claimed.

### Source map

| Source | Existing surface | Required adapter |
|---|---|---|
| `trillionnium/crates/trnm-rpc/src/lib.rs` | Account/task/event DTOs, `RpcErrorResponse`, account validation | Unified versioned metadata and M05 submission/readback |
| `trillionnium/crates/trnm-rpc/src/persistence.rs` | Existing service persistence | Root-bound contiguous index publication |
| `trillionnium/crates/trnm-cli/src/main.rs` | Existing user CLI | Explicit candidate API negotiation and proof-aware output |
| `web4-frontend/docs/api-contract.md` | Existing frontend contract | Versioned translation; no fabricated finalized state |
| `trillionnium/crates/trnm-tx-lifecycle-v0/src/production.rs` | Admission/broadcast/readback ports | Network handler calls real coordinator, never fixture state |

## Interfaces

### Planned live native candidate socket profile

The first runtime-bound interface is `native-public-candidate-v1`, separate from
the M05-intent `dev-api-v1` below. It is a client protocol inside the isolated
candidate namespace, not an Internet-facing production service. A validator
owns one Unix-domain socket under its canonical data root; the directory is
0700, socket 0600 and stale socket replacement requires proving the previous
owner is absent. No request chooses an application database or filesystem path.
The client may use an independently authenticated tunnel to its host; a later
HTTP/TLS adapter must preserve this contract and is not implicit here.

Each connection carries one request and one response: u32 big-endian byte length
followed by UTF-8 JSON, then close. Reject zero/over-limit length before allocation,
truncation, trailing frames, duplicate/unknown fields and nesting over 64.
Requests are capped at 528,384 bytes; replies at 8 MiB + 16 KiB, allowing the
hex encoding of the complete 4 MiB native proof/evidence budget. Use lowercase
hex without `0x`, decimal strings for u64, no private keys. Suggested local
budgets are 16 connections, 2 seconds to receive a request, 5 seconds to complete
it and at most 8 queued submit requests handled per consensus event-loop turn.
Proof queries have a separate two-worker budget and cannot occupy proposal/vote
work. Timeout after persistence is an unknown result to the client, not rollback.

All requests have `schema`, opaque `request_id` (1..64 ASCII token bytes), `op`
and a closed `data` object. `request_id` correlates responses only; native hash
and nonce govern durable idempotency.

| Operation | Exact data | Successful data / authority |
|---|---|---|
| `capabilities` | `{}` | Candidate flag, chain/genesis/profile, socket and transaction limits, supported native proof classes |
| `submit` | `{ "signed_outer_hex": "..." }` | `native_tx_hash`, persistent `receive_sequence`, `status="admitted"` or current exact-retry status; only after M05 body+nonce transaction commits |
| `transaction` | `{ "native_tx_hash": "..." }` | Durable local status and optional block/index; explicitly `proof_verified:false` unless accompanied by verified inclusion |
| `proof` | `{ "native_tx_hash": "..." }` | Exact native package hex; proof class `ordinary-v0` or `epoch-first-v1`; the epoch class includes all eight named evidence preimages, collectively bounded with the package |
| `status` | `{}` | Readiness reasons, current view, finalized height, durable pending count/bytes; no secret paths or credentials |

Replies contain `schema`, `request_id`, `candidate_only:true`, chain/genesis/profile
identity, `ok` and exactly one of `data` or `{code,retryable}`. Errors include
`INVALID_REQUEST`, `UNSUPPORTED_PROFILE`, `BAD_SIGNATURE`, `SIGNER_UNAUTHORIZED`,
`WRONG_CHAIN`, `NONCE_CONFLICT`, `EXPIRED`, `BACKPRESSURE`, `TIME_UNREADY`,
`RECOVERY_REQUIRED`, `NOT_FOUND` and `PROOF_UNAVAILABLE`. Only transient capacity,
readiness and recovery conditions are retryable with the same exact bytes.
An unknown hash is not a failed transaction; no proof is not proof of absence.
Querying a retained rejected/expired transaction returns its local record.

The SDK preserves its signed bytes, retries submit verbatim after ambiguous I/O,
and verifies returned native hash by canonical decoding. Before labeling a
transaction `included-finalized`, it verifies the dual ordered branches and
strict finality against independently pinned M13 history, including complete
epoch evidence on that explicit route; returned set/preimages cannot self-select
trust. Derive native hash from the proven outer envelope, require the requested
hash, and expose only committed gas/fee/events. No M05 intent ID, outcome string
or intermediate post-state root is inferred from this profile. History reads
must use the proof for that exact block, not the latest Core tip's proof.

The endpoint must invoke the running validator's durable admission and proposal
owner, then read that owner's authenticated finalized history. A fake accepted
map, a separately executed G1 fixture or a background generated workload does not
satisfy this API. Tests use a real client-owned key, submit through this socket,
observe execution on the multi-validator chain and independently verify the
returned package, including after lost ACK, leader change and restart.

### Common encoding and metadata

Use HTTPS JSON with UTF-8, duplicate-key rejection, no unknown request fields,
no NaN/floats for monetary values, and explicit `schema="dev-api-v1"`.
Digests are exactly 64 lower-case hexadecimal characters without `0x`.
All `u64`/`u128` values are decimal strings without signs or leading zeros except
`"0"`; bytes are canonical padded base64. JSON is transport only: construct M00/M05
typed values and use their existing canonical signing/ID algorithms.

Every successful response has `{schema, request_id, data, context}`. `context`
contains `chain_id`, `genesis_digest`, `protocol_digest`, `profile_digest`,
`serving_node`, `candidate_only:true`, `consistency`, `observed_height`,
`finalized_height`, `state_root`, `proof_ref`, `indexer_height`, `index_lag`.
Unavailable roots/proofs are `null`, never all-zero placeholders. A response
may advertise `consistency="finalized"` only after M13 verification; admission
responses always use `local`. `observed_height` is not a timestamp.

Consistency is one of `local`, `committed`, `finalized`, `historical`.
`committed` binds a node commit record but carries no standalone proof claim.
`historical` additionally names the exact retained checkpoint. If the requested
class cannot be satisfied, return a typed error instead of silently downgrading.

### Methods and operations

| Method/path | Request | Output / authoritative source |
|---|---|---|
| `GET /dev/v1/capabilities` | No body | Supported schema/profile/methods, limits, candidate flag; M15 descriptor |
| `POST /dev/v1/transactions` | Exact signed intent below | M05 durable admission receipt; HTTP 202 |
| `GET /dev/v1/transactions/{tx_id}` | `consistency=local|finalized` | Local durable phase or M05 verified finalized readback |
| `GET /dev/v1/accounts/{account}` | `consistency`, optional checkpoint | M07 account/nonce plus M13 proof for finalized/historical |
| `POST /dev/v1/simulations` | Signed-intent shape, exact `at_root` | M06 result with `simulation:true`, no durable lifecycle or broadcast |
| `GET /dev/v1/events` | Root-bound filters, `limit`, optional cursor | Ordered verified projection with receipt/event proof reference |
| `GET /dev/v1/proofs/{digest}` | No body | Immutable bounded M13 proof bytes and format version |
| `GET /dev/v1/status` | No body | M15 readiness reasons and last observed authority height |

No HTTP endpoint signs for the user, rotates validator keys, sets nonce floors,
changes chain parameters, deletes a journal or activates a node. Those remain
separate authenticated operator/governance paths. REST method names are proposed;
unknown or unimplemented methods return `METHOD_UNAVAILABLE` explicitly.

The planned multi-transaction finalized response follows
[M05's exact V1 inclusion contract](M05_TX_LIFECYCLE_TECHNICAL_SPEC_V1.md#planned-v1-multi-transaction-proof-contract):
verified block state root and committed gas/fee/events are separate from local
intermediate-root or outcome observations. Report `included-finalized`; expose
an application result only when its committed semantics are actually proved.
Neither the browser nor an indexer may turn an extra JSON field into a proven fact.

### Transaction request and response

Submission request `data` has exactly these fields:

```json
{
  "chain_id": "<64 lower-case hex>",
  "sender": "<64 lower-case hex>",
  "nonce": "1",
  "fee_bid": "100",
  "valid_until_height": "1000",
  "resource_limits": {
    "max_compute": "10000", "max_state_reads": "32",
    "max_state_writes": "16", "max_event_bytes": "4096"
  },
  "payload_base64": "<canonical padded base64>",
  "authorization_base64": "<canonical padded base64>"
}
```

This is a shape example, not a valid signature vector. Resource fields map to
M05 `u64/u32/u32/u32`, and fee to `u128`; range validation occurs before conversion.
There is no caller-provided tx ID, lifecycle state or independent nonce lane.
The current v0 intent has one sender nonce domain; unsupported lane fields fail.
The SDK computes the ID with `TxIntentV0::tx_id`, including authorization.

HTTP 202 `data` contains `tx_id`, `phase`, `duplicate`, `wal_sequence`,
`record_digest`, `durable_receipt_digest`, and `finality:"unverified"`.
Initial phase is `wal_persisted`. Exact retry preserves tx ID and original WAL
sequence; phase and record/receipt digests describe the current durable snapshot,
which may have advanced. A collected record returns `TX_COLLECTED` instead.
If persistence outcome is uncertain, return HTTP 503 with `outcome:"unknown"`
and the computed `tx_id`; clients poll and retry the exact signed intent.
They must not generate a new nonce merely because the HTTP request timed out.

A V1 `included-finalized` response contains verified block/epoch/height/index,
block state_root, gas/fee/events and the exact proof reference/format. It may
label the M05 tx_id verified only if M13 establishes the full signed-intent
commitment described in M05; matching a lossy native payload is insufficient.
Other pre/post roots and execution-success fields stay in a separately labelled
`local_execution` observation or require an independent replay proof. Do not
present them as covered by receipt membership. A proved application event may
establish its particular outcome under that profile; inclusion alone does not.
Current v0 still requires execution post-root to equal finality state root;
unsupported intermediate-root/multi-transaction mappings return
`PROOF_UNAVAILABLE`. A transport receipt is not a finality proof.

### Errors and retry contract

Errors use `{schema, request_id, error:{code,message,retryable,outcome,
retry_after_ms,tx_id},context}`. `outcome` is `not_applied`, `unknown`, or
`already_recorded`. Do not return stack traces or namespace paths.

| Code | HTTP | Client behavior |
|---|---|---|
| `INVALID_ENCODING`, `INVALID_REQUEST`, `WRONG_CHAIN` | 400 | Fix request; no automatic retry |
| `INVALID_AUTHORIZATION` | 401 | Rebuild authorization; no implicit server signing |
| `NONCE_REPLAY`, `REPLACEMENT_REJECTED`, `ROOT_MISMATCH` | 409 | Read authoritative context before rebuilding |
| `TX_EXPIRED` | 422 | New signed intent required |
| `TX_UNKNOWN` | 404 | Absence in this local view only; not proof of global absence |
| `TX_COLLECTED`, `CHECKPOINT_PRUNED` | 410 | Use supplied retained checkpoint reference if available |
| `OVER_BUDGET` | 429 | Bounded retry delay; same signed bytes |
| `NOT_FINALIZED`, `INDEX_NOT_CAUGHT_UP`, `PROOF_UNAVAILABLE` | 503 | Poll within client deadline; do not lower proof class |
| `RECOVERY_REQUIRED`, `IO_UNCERTAIN`, `METHOD_UNAVAILABLE` | 503 | Preserve tx ID and explicit unknown/not-applied outcome |

## State machine

### Web4 auxiliary package: current read-only client and migration

`web4-frontend/lib/api-contract/{types,schemas,adapters,client}.ts` currently
implements `queryTask`, `queryEvents`, `queryCapabilityAudit` and optional
`queryNormalizedAuditEvents`. Their existing paths are `/query-task/:taskId`,
`/query-events/:taskId`, `/query-capability-audit/:subject` and
`/query-normalized-audit-events`; they are not the proposed `/dev/v1` methods.
The current exact DTOs and pagination fields remain in
`web4-frontend/docs/api-contract.md`. The deployment toolchain comes from
`.node-version` and `web4-frontend/package.json`/lockfile; an older guide's
Node 20/npm 10 minimum does not override the package's Node 24/npm 11 constraints.

The client normalizes/encodes path and filter tokens, fetches bounded pages,
validates strict Zod schemas, adapts into readonly DTOs and then renders a
snapshot through `lib/dashboard/source.ts`. Existing timeout defaults to 8 s;
GET retry defaults to two retries with 250 ms initial/2000 ms maximum backoff
and jitter. Retry only retryable network errors and HTTP 408/429/500/502/503/504.
`BAD_REQUEST`, `NOT_FOUND`, `INVALID_PAYLOAD` and user `ABORTED` terminate;
`TIMEOUT` remains distinct from user cancellation. A malformed response cannot
become an empty successful ledger view.

Normalized audit pagination currently defaults to 60 events/page and four pages.
`hasMore=true` requires a nonempty normalized cursor; repeated cursor terminates
the read to prevent a loop. This API exposes an optional diagnostic projection,
so absence may omit that panel; it cannot prove absence of canonical events.
The proposed adapter must display `partial/unavailable` when any required feed
fails, retain the last valid snapshot with its age, and label explicitly requested
`?mode=mock` data as mock. Runtime errors must not silently switch to mock.

There is no browser-authoritative ledger or durable acceptance receipt today.
For the planned `/dev/v1` adapter, key any optional cache by chain, API schema,
query and exact root; invalidate on profile/root mismatch and refetch after reload.
Store no private signing key, auth token or raw signed intent in that cache.
An external signer returns exact intent bytes; pending tx IDs may be restored
only as unverified hints and resolved through the M05 query operation.
Existing numeric `amount` DTOs cannot safely represent arbitrary u128 values:
new-profile adaptation requires decimal strings and rejects unsafe JS integers.

Verify current `test:unit`/`test:contract` plus planned adapter tests for schema
drift, unsafe amounts, 400/404 vs retryable failure, cancellation, repeated cursor,
partial optional audit, stale cache, wrong-root proof and explicit mock mode.
Only a verified M13 response may add a finalized badge; frontend build/release
scripts grant no chain-release authority.

Submission processing is `Parsed -> ContextBound -> M05Invoked -> Response`.
Cancellation before M05 invocation is `not_applied`. Cancellation after invocation
stops response work, not the durable transaction; readback resolves the outcome.
A request-scoped transport identity never grants consensus authority.

Indexer ingestion is `Absent -> Received -> RootVerified -> Applied -> Published`.
For height h, fetch the M08 committed block and M13 proof; verify chain, parent,
height, state/receipt/event roots; deduplicate by `(block_id,event_index)`; write
rows and the new watermark in one storage transaction. Publish the watermark
only after durability. Same key/different contents is corruption, not overwrite.
Unfinalized local projections are a separate namespace and cannot populate
finalized responses or caches.

SDK lifecycle is `Built -> UserSigned -> Submitted -> LocallyAdmitted ->
ProofVerifiedFinalized`. `UnknownOutcome` retains signed bytes and tx ID.
Wait-for-finality polls at 250 ms doubling to 2 s with jitter, honors `Retry-After`,
and has an explicit caller deadline. Deadline expiry returns a pending handle.

## Persistence and recovery

Index schema keys are `(chain,checkpoint,block_id,tx_index,event_index)` with
secondary account/topic keys. The durable index head stores schema version,
height, block ID and verified roots. Recovery compares this head with M08/M13,
replays only the next contiguous batch, and never rewrites canonical node state.
A conflicting finalized head freezes publication. Build a replacement index in
a new namespace from a verified checkpoint, replay to target, compare roots,
then atomically swap the service pointer; retain the old head for diagnosis.

Pagination tokens bind chain, root, filter digest, order, last returned key,
index schema and expiry. Planned tokens are base64url payload plus server HMAC;
use a service-only key with a rotation ID, not a validator key. Verify MAC before
querying. A new root requires a fresh query; pagination never silently moves it.
Restart may invalidate tokens by rotating the service key: return `CURSOR_EXPIRED`.

## Resource bounds

These are proposed private-devnet service defaults, validated at startup and
reported by capabilities. They are not consensus validity limits.

| Limit | Dev default / action |
|---|---|
| Submission body | 1,500,000 bytes; decoded payload <=1 MiB, authorization <=16 KiB |
| Other request body | 64 KiB, JSON nesting <=16; reject before unbounded allocation |
| Concurrency | 64 total, reserve 16 for status/submission, 8 proof workers |
| Request deadline | 5 s ordinary, 15 s proof; no unbounded server-side finality wait |
| Pagination | default 50, max 200 rows, response <=2 MiB |
| Proof response | <=4 MiB; larger bundles must use an explicitly versioned chunk API |
| Cursor | <=1024 bytes, lifetime 5 min, fixed query/root |
| Per-client admission rate | 20 requests/s, burst 40; global 200/s, burst 400 |
| Stream buffer if later enabled | 256 events or 1 MiB/client; terminate with resumable cursor on overflow |
| Index apply batch | <=1000 events or 8 MiB; commit one contiguous batch |

No stream endpoint is enabled until resume/gap tests pass. Rate-limit identity
is API principal plus source quota; it is separate from transaction sender auth.
Caches include chain/profile/root/consistency/filter in keys; finalized immutable
entries need no freshness guess. Local cache TTL is at most 1 s and reported.

## Security

Private-devnet TLS keys are service keys. Bind loopback by default; remote bind
requires explicit allowlist and TLS configuration. Disable cookies for write
APIs; if a browser deployment introduces cookies it must add CSRF defenses.
CORS origins are explicit, never credentialed wildcard. Body/response logging
excludes authorization bytes, API tokens and private payloads.

Clients independently verify proof chain and roots for finalized balances and
receipts. A compromised indexer can withhold data but cannot manufacture a
proof-valid state. Simulation cannot call external nondeterministic services or
commit writes; missing immutable state returns `ROOT_UNAVAILABLE`.

## Observability and SLO

Record per-method queue/service latency separately, status classes, overload,
index height/lag, proof failures, cursor expiry and cancellation outcome.
Use fixed method/code labels. `non-authoritative-service-v1` reports service
availability independently of chain finality; a healthy HTTP server on a stalled
chain must show finalized-height stagnation and return `NOT_FINALIZED` correctly.

## Verification and evidence

| Contract | Positive | Negative / fault |
|---|---|---|
| Submission | SDK and CLI build identical typed intent/ID; durable retry preserves WAL identity | Duplicate JSON key, u128 overflow, unknown lane, wrong chain, invalid auth |
| Status/proof | Executed then finalized readback verifies through M13 | Forged proof reference, receipt from another tx/root, finalized local fixture |
| Index | Crash after rows/before watermark converges to one atomic batch | Height gap, duplicate conflicting event, corrupt head, pruned checkpoint |
| Pagination | Stable page union equals root-bound full scan | Changed filter/root, MAC tamper, expiry, oversized cursor |
| Isolation | Slow proof queries leave submission/status capacity | Flood, cancelled request after durable ACK, cross-chain cache key collision |
| Frontend | Candidate banner and explicit pending/failed/finalized states | Mock response cannot enter a proof-verified production UI path |

Existing RPC tests are regression inputs; a conforming dev API additionally needs
an actual node end-to-end test: sign, submit, lose response, retry, finalize,
verify proof, rebuild index and reread the same receipt. M05/M07/M08/M13/M15 own
the corresponding producer contracts; M14 may not fill missing fields with guesses.

## Activation boundary

A labelled candidate API may expose only capabilities actually wired. Public
API readiness requires versioned schemas, independent client vectors, bounded
abuse tests, real-node proof readback and index-rebuild evidence. Deploying the
frontend or returning a status document does not activate the chain.

### Candidate clock binding

For `native-public-candidate-v1`, capabilities bind `wall_clock_epoch_ms` to the
manifest/profile digest. Envelope validity fields and block time are milliseconds
since that epoch, despite the frozen envelope's `unix_ms` field names. The node
computes time using checked subtraction from its own Unix clock; clients cannot
supply the server time. SDK signing derives the same chain-relative value and
rejects a future epoch. Genesis remains canonical timestamp 0. M15 defines the
parent-relative step, skew readiness, empty catch-up and drain rules. An exact
retry returns its durable prior status even after expiry; recovery of an already
executed body verifies its historical block time and must not re-admit it using
a backdated clock.

### Candidate client executable

The candidate validator executable exposes an explicit `native-client` command
before validator configuration or consensus keys are loaded. `sign` takes the
pinned public profile, selected campaign application key, explicit nonce/TTL and
command file; it writes one exact signed native body with create-new semantics.
TTL is bounded to five minutes and time comes from the committed profile epoch.
`request` sends one bounded length-prefixed request to an owner-private Unix
socket and checks response request/profile/genesis identity; receiving a response
does not count as proof verification. `verify` loads independently pinned
observer-public trust, binds the exact signed request bytes and native hash,
checks the canonical parent header against the finality-certified parent ID,
and runs the shared native payload/receipt/finality verifier. It ignores the
server's verification boolean as authority. Client keys stay outside validator
and observer-public bundles; no command implicitly generates load or keys.


### Candidate ordinary application replica command (M13 consumer)

`native-client sync <observer-public-root> <config> <manifest-sha256>
<private-socket> <replica-directory> <target-height> <profile-sha256>` loads only
independently pinned public context and signer policy. It requests exactly that
positive height using `sync_manifest {target_height}`, then `sync_chunk
{height,index,record_sha256}`. Responses retain request/chain/genesis/profile
context. Manifest/chunk response frames are bounded before JSON decoding; unknown
fields, noncanonical hashes, wrong coordinate, length or chunk hash reject.
Manifest hashes bind transfer bytes; every finalized proof and executed body is
still independently verified against the receiver's genesis and previous header.

A private destination lock permits at most two immutable manifest-digest stages
for resumable downloads, so an invalid first manifest can be retried with an honest
source without deleting verified state. A third distinct manifest reports capacity
exhaustion; completed replicas keep their selected stage.
Existing chunks are rehashed, and invalid incoming chunks are rejected before
persistence. The client reconstructs the actual schema-3 application database;
a missing tail retains verified commits but cannot create CURRENT. A retry opens
the same namespace, verifies the complete prefix against actual committed rows,
and publishes only after close/reopen confirms the exact target. CURRENT describes
an application replica, with `application_only=true` and `signing_authority=false`.
No private consensus key, signer journal or independent node watermark is loaded.
Epoch/seal targets and schema 4/5/6 are unsupported in this initial command.
The existing private Unix endpoint is the transport; this does not claim a public
Internet RPC, a complete validator join, or cross-epoch synchronization.
