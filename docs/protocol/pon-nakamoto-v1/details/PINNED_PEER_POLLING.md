# Bounded operator-pinned peer polling

## Native CLI composition

`serve --admission-profile public-protected-development-v3 --public-development-network
--pool-policy FILE --auth-secret FILE --peers FILE` runs the poller beside ingress
and, optionally, `--mine` under the same Node owner and stop signal. The opened
peers file must be bounded, regular, singly linked and not group/world writable;
symlinks and nonregular files refuse before store creation. Its JSON carries the
complete pinned configuration below. Bits/lifetime must match the service's
explicit `--admission-bits`/`--admission-ttl-ms`; `transport_profile` is the exact
V3 resource-policy **digest**, not the profile name.

The CLI caps file `runtime_ms` by service `--seconds` and optionally overrides
`poll_interval_ms` with `--peer-poll-ms` and `max_pages_per_cycle` with `--peer-pages`.
It validates and hashes these effective values. The startup record exposes that
context and `peer_polling_enabled`; the final report preserves the poller report.
Polling-only options without `--peers` and all polling options on V2 refuse.
Normal poll runtime/call limits leave ingress serving; structural polling failures
stop the shared runtime. Service completion stops and joins the miner and poller
before returning. Peer network calls and one native proof remain nonpreemptive;
service duration is not a hard shutdown deadline. A synchronous event/stdout sink
can also delay this local process.

`tests/public_pool_cli.rs` adds actual CLI source/receiver following, effective
configuration context, closed-store native packet equality and option/config
refusals. These finite local runs are separate from the retained fork/socket tests
and same-administrator Tailnet simulations; no public acceptance follows from them.

M15 `peer_polling::run_pinned_peer_polling` is a sibling of the public V3
reactor and miner. It receives their existing `Arc<Mutex<Node>>` and stop
signal; it creates no second database owner. Operator configuration pins
1–8 numeric socket addresses and Ed25519 server public keys. It never scans,
resolves DNS, follows peer advertisements or authorizes source/evaluator
identities. Transport uses only the existing paid and signed
`public-protected-development-v3` Head and one-packet History operations.
There is no new wire or consensus namespace and no public discovery or
eclipse-resistance claim.

## Exact local configuration

`PeerPollingConfig` has schema `pon-native-pinned-peer-poll-config-v1` and
rejects unknown fields, including unknown peer fields. All four context
strings are exact lowercase 64-hex: `network`, `parameters`, `genesis`,
and `transport_profile`. The first three must match `Settings` and the last
must equal the V3 `PublicPolicy::new(bits,lifetime_ms).id()` encoding.
`peers` is an array of `{ "address": "numeric-ip:port", "server_public":
"lowercase-64-hex" }`; IPv6 uses `[numeric-ip]:port`. Addresses must be
unique, have nonzero ports and not be unspecified or multicast. Public-key
pins must be nonzero and accepted by the strict Ed25519 key parser.

| Field | Bound |
| --- | --- |
| `bits` | 8–20, existing V3 puzzle policy |
| `lifetime_ms` | 100–2000, existing V3 puzzle policy |
| `peers` | 1–8 explicit pinned endpoints |
| `poll_interval_ms` | 10–60000 |
| `runtime_ms` | 1–259200000 |
| `max_calls` | 1–1000000 attempted RPCs over the whole runtime |
| `max_pages_per_cycle` | 1–64 History RPC attempts across all peers |

`PeerPollingConfig::from_file(path,&Settings)` opens without following a
symlink and with nonblocking open, requires a regular descriptor with one
hard link, rejects group/other write permission and accepts at most 16 KiB.
It does not claim to check the owner's UID. An embedding CLI may instead
perform its own stricter descriptor-owned file read, deserialize once,
apply explicit budget overrides and call `validate`. The report's context is
`H("native-pinned-peer-poll-context-v1",serde_json(config))` for the actual
validated configuration. Operator endpoint files and machine identities
belong in local run directories, not public evidence or repository examples.

## Target and cursor state

Each peer has one bounded in-memory record: fixed target, cursor, last
completed native tip, counters, whether its initial fallback was used and
one latest bounded failure. Peers are visited round robin, the first peer
rotates each cycle, and one failed peer retries only in the next cycle.
The global History attempt cap applies even to errors. Head calls and
History calls both consume the global RPC budget and pay V3 tickets.

1. With no unfinished target, paid Head supplies only a **tip locator**.
   Advertised height, chainwork, state root or evaluation score never authorize
   admission or activation. A tip already durably admitted locally may use
   that exact native admission fact and native clock/activation checks.
2. A new target stays fixed until complete. The initial cursor is that peer's
   last completed native tip, or genesis for a fresh runtime. New Head values
   cannot redirect an unfinished cursor.
3. History must have the exact nine `pon-native-history-v1` fields, exact
   network/parameters/genesis/target/after, at most one packet, at most 1 MiB
   raw packet represented by canonical lowercase even-length hex, and the
   packet's exact `parent == after`. `next` must equal the decoded packet ID;
   `complete` must equal `next == fixed_target`. An empty page is legal only
   at `after == fixed_target`, with that exact next and complete true.
   Collection and hex bounds are checked before serde string copying or
   packet-byte expansion.
4. Transport failures, malformed/cross-context pages, unknown blocks and
   native admission failures retain the target and cursor, retain a failure
   event and wait until the next bounded cycle. A signed business refusal
   `CURSOR` permits **one explicitly recorded restart at genesis** for the
   same newly fixed target, only while zero pages have advanced, only if the
   initial anchor was not genesis and only before that fallback was used.
   The original refusal remains in the event sequence. No other error
   triggers this restart; after progress, `CURSOR` also retains the cursor.
5. First, under the existing owner lock, current native task/source, parent
   and observed-clock context are checked. An already admitted exact packet
   reuses only that durable fact. A new immutable owned packet undergoes
   `WorkCheckedPacket::verify` **outside** the owner. After cancellation and
   clock checks, the owner rechecks context and atomically performs ledger
   admission through `admit_work_checked`. A valid PoN proof with a false
   state commitment still fails native M06 admission.
6. Only exact fixed-target completion requests `activate_observed` using the
   current local clock. Native accumulated work selects the active branch;
   lower/equal-work targets can complete synchronization without replacing
   the active heavier branch. Clock failures retain the unfinished target.

The poller does not silently rebuild or migrate storage. A fresh runtime
starts replay memory at genesis. It can reuse exact locally admitted packets,
or a locally admitted complete target, but stores no remote chainwork
certificate. Existing `Node::open/recover` may select a valid admitted prefix
on restart; that is not proof of completion of an unfinished pinned target.
If a server withdraws an unfinished target, failures and the cursor persist
until budgets expire or the operator explicitly starts a fresh runtime.

## Lifecycle and receipts

Normal runtime, shared-stop or call-budget completion returns a report and
does **not** stop the public service. A storage/owner structural failure or
observer failure returns an error and sets the shared stop signal. Runtime
and stop checks bound waiting and future calls. Existing V3 socket deadlines
bound each call; a currently running native proof, state reconstruction or
SQLite transaction is not preemptible and can finish after the requested
runtime. No hard native-stage latency guarantee is claimed.

Events contain a sequence, peer index, stage, current target/cursor,
measured elapsed nanoseconds, outcome and active tip when activated. A
successful signed reply includes client solve trials/time and completed
body-write bytes; a failed transport has `rpc_cost: null`, explicitly
preserving that partial solver/body costs are unknown. Error text is bounded
at 2048 UTF-8 bytes, with original length, completeness flag and a domain
hash of the whole original error. The module retains one such error per
peer. The embedding observer controls persistent logging; reports and local
signed receipts are not independent hardware/network measurements.

`public_network_ready`, `independent_accepted` and transport
`identity_authority` remain false. A 72-hour configuration ceiling is a
resource limit, not a successful 72-hour observation. Qualified V1 tasks
still have finite validity; continued task V3 production needs the explicit
native atomic-renew/source-signing controller. This module only synchronizes
already valid packets and cannot invent future demand or evaluator authority.

## Retained tests

Nine module tests cover exact configuration and file limits, bounded UTF-8
failure evidence, page shape/caps, global call/page budgets and rotation,
normal/fatal stop behavior, actual valid-work false-state rejection, fixed
native target under disconnect, initial fallback and lower-work activation.
The actual `pinned_peer_polling` TCP test runs paid pinned signed V3 replies
against a separate persisted native owner using
`signed-task-lifecycle-dev-v3`. After A3 completes, the real server creates a
heavier B4 fork; its actual History handler returns signed CURSOR for the
old anchor. The retained refusal is followed by one genesis restart, all
new packets receive native verification, a common admitted packet is reused
exactly, and the heavier branch's state/packets match. The test reopens the
local owner and checks guest session/outbox/audit rows remain zero and body/
output reservations return to zero after service shutdown.
This is a local TCP correctness regression; multi-host Tailnet/WAN service,
paid-Sybil load, public reachability and independent governance require their
own source-bound campaigns.
