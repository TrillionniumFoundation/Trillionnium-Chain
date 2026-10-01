# Public development intake v2

Status: implemented development candidate succeeding the authenticated transport
at `7d99848b6b5723b0f7b0779105db068dcc446042`. Existing authenticated,
protected-v1, and default listeners retain their existing behavior. This candidate
has no public-network, independent acceptance, consensus-hardness, SLA, or
production activation claim. Real physical-LAN qualification is still required.

The explicit transport profile is `public-protected-development-v2`.
A guest creates its own Ed25519 transport key and pays the configured resource
puzzle for each Submit, Head, or History operation. A valid guest signature
binds the submitted bytes to that transport caller. It does not grant task-source,
evaluator, model-adoption, mining-reward, account, or ledger-command permission.
Installed native task and ledger checks remain authoritative.

## API and outcome

`PublicPolicy::new(bits, lifetime)` accepts 8–20 leading zero bits and a
100–2000 ms solve-cookie lifetime. `PublicPolicy::development()` is 16 bits and
2000 ms. Clients pin the server key, chain network, parameters, genesis, and exact
policy digest. No legacy or allowlisted fallback exists.

`PublicServer::new(identity, policy)` obtains a fresh secret and epoch from OS
entropy. `serve_public_protected_v2(listener, node, lifetime, stop, server)` owns
the existing native Node with 2 proof workers and 1 read worker. Service lifetime
is 1 ms–3600 s. `call_public_protected_v2(address, request, settings,
pinned_server, caller, policy)` performs one connection and one attempt.

`PublicReply` exposes `ok`, `value`, `solve_trials`, `solve_elapsed_ns`, and
`body_bytes_sent`, with `identity_authority=false` and
`public_network_ready=false`. A verified signed business refusal is
`Ok(PublicReply { ok:false, value:{error:...}, ... })`. The caller must inspect
`ok`. Connection, timeout, canonical encoding, signature, and context errors
remain `Err`; no retry is performed inside the client. Response delivery is not
business confirmation or irreversible finality.

## Wire and state transitions

All integer fields in the fixed Hello and Solution are little-endian. Variable
server frames carry a 4-byte big-endian byte length checked before allocation.

Hello is exactly 108 bytes: `PPH2` (4), operation (1), reserved zeros (3),
body length (4), caller key (32), body digest (32), client random nonce (32).
Operations are Submit=1, Head=2, History=3; other operations are rejected.
Submit length is 1–2,097,216 bytes. Head/History length is 1–512 bytes.

The challenge is canonical JSON, at most 2048 bytes, with schema
`public-resource-cookie-v2`. Its HMAC-SHA256 and server signature bind the
profile digest, node network/parameters/genesis, server identity, random server
epoch and connection nonce, peer socket binding, caller key, client nonce,
operation, body length/digest, target bits, and monotonic issue/expiry ticks.
There is no wall-clock synchronization requirement for this ephemeral ticket.
A Solution is exactly 108 bytes: `PPS2`, cookie digest (32), puzzle nonce (8),
and guest signature (64). Its signature covers the cookie digest and nonce;
its puzzle hash domain is `public-ticket-v2`.

The challenge is cryptographically self-contained; there is no global issued-
challenge table or durable guest peer/nonce database. This fixed Solution codec
still references the current connection's one bounded cookie. It does not
implement portable/off-connection redemption. Each new connection has a fresh
cookie; replay from another connection, epoch, context, body, or operation fails.

The server validates expiry, puzzle, and strict guest signature, then atomically
reserves the spent-cookie identity in the reactor before body allocation or
expensive native work. Reservation remains consumed on queue Busy, malformed
body, business failure, or timeout. A full spent table refuses new tickets and
never evicts unexpired entries. Entries expire at their authenticated expiry;
expired cookies can no longer be accepted. There are at most 1024 entries, and
cleanup scans at most that many every 20 ms. The challenge issuance bucket is
128/s with a burst of 32. Both issuance and cache saturation can deny service;
they do not establish fairness among identities.

The stages are Hello → challenge output → Solution → Ready output → body →
bounded queue/native work → signed response output → close. Ready is at most
256 bytes. The server holds at most 64 connections and advances each by at most
64 KiB per reactor iteration. Partial prefaces, withheld bodies, and blocked
outputs never occupy proof/read workers. Raw body/canonical comparison uses a
streaming writer, and Submit rejects escaped/non-hex packet text before large
parser scratch allocation.

## Exact deadlines and byte budgets

Each deadline is absolute from phase entry and also limited by an absolute
30-second connection lifetime. Successful partial reads/writes never extend it.

| Phase | Maximum |
| --- | --- |
| Fixed 108-byte Hello | 2000 ms |
| Challenge output / Ready output | 2000 ms each |
| Solution receipt and validation | Authenticated issue tick + configured lifetime |
| Body, after accepted ticket and Ready | 5000 ms |
| Queue wait and native work | 10000 ms |
| Signed response output | 5000 ms |

The solve-cookie lifetime includes challenge transit. Cookie expiry is checked
at the atomic spent reservation. Once that reservation succeeds, the body has
its own grant and deadline; a body that completes after solve-cookie expiry is
permitted within its granted 5-second phase. A late Solution is rejected even
if otherwise correct. A lost response has an unknown client-observed outcome;
a retry is a new paid ticket for the same content-addressed block, not a durable
guest replay-nonce acknowledgement.

The hard native raw-packet cap is 1,048,576 bytes. Submit JSON is bounded by
`2 * raw_cap + 64`. A response is bounded by `2 * raw_cap + 4096`, including the
single-packet History Page and signed response context. These fixed additions
are checked by boundary tests. The current native transaction-count/envelope
limits make actually constructible packets smaller than this declared cap.
There are separate 8 MiB body and 32 MiB conservative output reservation pools.
The body reservation is three times the accepted body length and stays with
queued/running work. Output capacity is reserved before History materialization,
signing, and serialization at four times the response maximum, or 64 KiB for a
small Head/Submit result. It remains reserved through completed-output queues
and socket writes. Shutdown releases queued bodies and pending responses.
Fixed per-connection cookies/headers, bounded error responses, worker scratch,
SQLite caches, existing native state, and kernel socket buffers are additional
costs; these pools do not assert a whole-process RSS limit.

Every public bound and phase deadline is committed by `PublicPolicy::id()`, along
with bits and lifetime. Changing them requires a new pinned digest. This does not
change ledger validity by a local arbitrary allowlist.

## Bounded reads and actual validation

Head invokes `Node::public_head_metadata()` rather than `Node::stats()`. It reads
namespace/reorganization status, the active pointer, and one admitted block
metadata record. It returns context, tip, height, generation, chainwork, and the
admitted header's state-root commitment. It omits archive/event/state-key counts
and does not hash or audit the active key/value state. `commitment_scope` states
that distinction. `context_matches=true` records the native namespace check;
it is not independent consensus or data-availability attestation.

History returns at most one packet. A native derived binary-lifting index
locates the next admitted packet without repeatedly walking the full suffix.
Each History lookup/body load has a hard budget of 1024 indexed SQL reads, including the scalar
length check and final BLOB load; every indexed/body read checks work/deadline progress.
The fixed native namespace/reorganization checks precede the lookup. Before
loading a packet BLOB it checks the scalar stored length against the 1 MiB native
raw cap. Fixed-size header/hash projections are also length guarded. Unknown
cursors, non-ancestors, index inconsistencies and oversized corrupt stored BLOBs
fail explicitly. No unbounded ancestry spool or multi-packet JSON value is built.
The transport profile digest commits the derived-index version, 63 possible jump
levels and SQL budget; historical transport pins are distinct.

The index is created only by native admission in the same SQLite transaction as
the accepted block and its state deltas. The fresh DDL identity refuses existing
layouts; it does not silently migrate a live owner. Each used jump checks its
context hash, actual stored header parent/height and two visible half-jump links,
without recursively auditing the entire path. Reopen checks the active tip's
rows; untouched branch rows are checked lazily. The public hash detects local
inconsistency, not an owner who can rewrite and reseal the database. It is not an
independent proof of long ancestry. Every receiving Node still verifies every
returned PNW1/task/ledger packet and only activates after reaching the pinned tip.
See [derived-index details](NATIVE_ANCESTRY_INDEX.md).

The former 4096-suffix bootstrap limit is removed by this indexed path. This does
not renew a finite signed-task-v1 lease: continuing task qualification still needs
its own explicitly selected lifecycle profile and source-authorized transactions.

Submit calls the existing native context checks before full PNW1 replay, then
executes native task/ledger/state-root validation and branch activation. Two
proof workers bound simultaneous replay; they do not make PNW1 verification
cheap or preemptive. Native verification, state execution, persistence, and
activation are not forcibly interrupted inside an individual call. A queued
operation checks its deadline before work and again before admission; an already
entered native commit can finish after the connection expires. Its receipt may
be undelivered and the client must treat that outcome as unknown. The native
owner mutex also serializes ledger persistence and can delay reads while a
Submit executes. These are remaining public admission-budget/fair-service gates;
two proof workers alone do not prove a 10-second hard execution cutoff or read
fairness. Consensus state/execution cost, model efficacy, scientific
hardness, independent demand, and independent validator ownership are separate
gates. Global connection/puzzle/queue saturation can still reject honest users.

HMAC conformance uses [RFC 4231, section 4.2](https://www.rfc-editor.org/rfc/rfc4231.html#section-4.2)
with its key zero-extended to the fixed 32-byte interface, plus a full 32-byte
key vector cross-checked against Python's standard-library HMAC-SHA256.

## Retained measurements and attack matrix

Metrics distinguish issued tickets, failed puzzle/signature checks, replay/cache/
body/queue refusals, bounded phase error counts, native work starts/results/time,
ledger failures, completed operations, written responses, phase expiry, peak
connections/reservations, and post-shutdown reservation balances. Completed
operations can precede disconnect; they are not delivered acknowledgements.
Resource accounting is local observation, not hardware attestation or a
scientific PoN hardness result.

A source-pinned physical-LAN campaign must retain every honest/attacker attempt,
failures as well as success, before any public-readiness claim:

| Case | Required observations |
| --- | --- |
| Honest baseline | No automatic retry; correct Submit, bounded Head/History, independent full-sync and business confirmation |
| Unpaid false ticket / wrong guest signature | No body-ready grant, no native work; issuance CPU and bytes still counted |
| Paid false transcript | Exact solve trials/time and transmitted body; native verifier failure time |
| Paid valid PNW1, invalid ledger/task context | Context rejection vs full verifier vs ledger execution; no state/nonce side effects |
| 3 and then 64 rotating partial Hellos | Absolute 2 s closure, honest success/failure denominator, connection saturation |
| Paid withheld bodies | 5 s closure, pooled-memory peaks, no proof-worker ownership before body completion |
| Slow output readers | 5 s output closure, completed-but-undelivered outcomes, output permits released |
| Cache/queue/budget saturation and restart | No live eviction/replay, no durable guest table growth, old epoch refusal, eventual explicit bounded refusal |

Local regression proves 100/200/300 ms fragmented small frames and body delivery
without retry, 3 slow prefaces with concurrent paid Head service, canonical
limits/MAC binding/cache and permit lifecycle, actual signed-task PNW1 plus
invalid-ledger rejection, and independently verified one-packet partial sync.
It does not prove performance or fairness on a public network.
