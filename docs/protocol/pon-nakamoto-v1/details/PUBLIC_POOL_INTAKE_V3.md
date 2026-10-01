# Public development intake V3 and the native local pool

This is a fresh, explicitly selected development profile. It connects paid guest
transport requests to the Node's actual persistent pool. It does not certify public
readiness, independence, fair access under saturation, exact transaction inclusion,
confirmation, model efficacy, or economic work. V2 retains its separate signed domains
and one-hour service bound. Both modules bind the current derived ancestry index
with at most1024 SQL lookups in a fresh resource-policy digest; see
[NATIVE_ANCESTRY_INDEX](NATIVE_ANCESTRY_INDEX.md). V3's separate module currently duplicates the V2 reactor
so V2's contract is preserved; future security fixes must be reviewed for both.

## Exact boundary

`ingress::public_v3::serve_public_protected_v3` accepts the **existing**
`Arc<Mutex<Node>>` and `Arc<AtomicBool>`. The operator enables and fixes the local
pool before serving. The continuous miner and the public worker share that owner
and stop signal. The reactor does not create a second Node, a second database
owner, another mempool, or a miner. Shutdown requests stop and joins workers; it
cannot forcibly interrupt an already executing native stage.

The explicit finite service lifetime is greater than zero and at most 72 hours.
That is an operator-selected maximum, not evidence of a 72-hour run. Per-connection
phase deadlines, 64 active connections, the 8 MiB paid-body budget, 32 MiB output
budget, two native/proof workers with a two-entry queue, and one read worker with
a two-entry queue remain bounded. Scalar responses reserve 16 KiB capacity before
serialization; history retains its separate larger limit. Native stages are
nonpreemptive: the 10-second work deadline bounds admission/lock waiting and socket
phases; it is not a hard interruption guarantee for a running M06 preview. A
successful durable pool reservation can outlive the requesting socket or response.

V3 uses `PPH3` and `PPS3`, `public-protected-development-v3`, and fresh signed cookie,
caller, ticket, body, response, peer-binding and profile domains. There is no
version negotiation or fallback. V2/V3 cross-version requests are rejected before
paid request-body allocation. Every operation, including reads, must pay its own
connection-local resource ticket and sign the exact cookie/nonce. The random guest
transport identity confers no ledger key, source authorization, model ownership,
chain work, voting power, or reward claim. Guest identities/replay operations are
not stored durably; **valid signed transaction facts** are stored in the operator's
actual pool.

## Closed operations

| Op | Canonical request | Owner action |
| --- | --- | --- |
| 1 | `submit` with the existing block packet hex | Existing real work verification and native block admission |
| 2 | `head` | Existing bounded native head metadata |
| 3 | `history` with tip/after | Existing bounded native history page |
| 4 | `pool_submit_bundle` with `pool_context`, `transactions` | Exact signed PNX1 bytes through Node M05/M06 and durable reservation |
| 5 | `pool_status` | Read-only native pool snapshot, scalar public projection |

Op 4 requires an exact 64-character lowercase hex `pool_context` matching the
operator's stored pool policy under the same Node mutex. This pins existing
configuration; it does not let the guest select the miner or alter limits. The
canonical body scanner checks **before** serde vector allocation: 1–16 members,
each 159–2048 decoded bytes, no escapes or non-lowercase hex, at most 32,768 total
decoded bytes, and a raw JSON body of at most 66,048 bytes. All fields/cardinality,
wire op and canonical serialization must match. Operator limits can be stricter.

Actual Node admission verifies canonical encoding/network/selected profile,
strict main signature, expiry, fee/resource limits, nonce and full retained pending
prefix through the real M05 typed gate and M06 preview. The preview and admission
remain one bounded native stage under the existing Node owner. A malformed,
conflicting, unfunded or otherwise invalid bundle gets no partial new reservation.
The native receipt's typed-gate counts concern the **whole reconstructed pending
prefix**, not only the newly submitted members. `duplicate` means the same local
bundle facts were retained; it does not prove that the bundle was mined. Local
bundle grouping does not make unrelated signed transactions consensus-atomic;
atomic renewal uses the actual V3 renewal command.

Op 5 calls only `Node::pool_status_snapshot()`. It cannot call `pool_reconcile()`,
prune, reset, enable the pool, change configuration or select a miner. The native
snapshot validates bounded retained metadata/bytes but does not run a new M06
preview. The public response omits per-group digests/reasons/raw wires and returns
bounded counts, the actual active parent/generation, the last checked
parent/generation, `classification_current`, and four scalar native V2 cache-GC
observations. GC counters/hash describe local cache eviction, not exact inclusion,
finality or an operator deletion certificate; see
[LOCAL_MEMPOOL_CACHE_V2](LOCAL_MEMPOOL_CACHE_V2.md). It exposes stale classification
explicitly after an active-chain change until an **operator/miner** reconciles.
Counts for queued/blocked/expired/sequence-consumed groups refer to that last
classification. `SequenceConsumed` only says an active nonce is used; it does not
prove that these exact bytes were included. Receipt and status explicitly set
inclusion/adoption/reward/public-readiness authority to false. Normal chain
observation and confirmation remain separate.

## Cost, fairness and verification

Block PoN work counters and pool preview counters are separate. V3 reports actual
pool submit starts/finishes/failures and native elapsed time. Reads and transport
solution costs are recorded separately. Queued transaction fees are checked in
preview and charged by actual block execution; admission does not silently debit
ledger funds or invent a new economic payment. Duplicate submissions still incur
all transport and native verification costs.

The finite worker/row/body/output bounds do not prove honest service under a
saturated queue or a cheap adversarial hash farm. The shared mutex can delay reads
while a bounded native preview runs. Persisted pool growth, source renewal,
reorganization/finality recovery, cold restart and external WAN operation still
need actual integrated campaigns. A resource ticket is not a Sybil theorem.

## Ordinary CLI composition and executed acceptance

`serve --admission-profile public-protected-development-v3
--public-development-network --auth-secret FILE --pool-policy FILE` fixes the
operator's bounded local pool before listening. Add `--mine` and explicit
`--task-bootstrap` or model/input files to run the existing wall-clock miner on
the same owner and stop signal. Service completion or either failure stops and joins both. A successful finite
miner block limit leaves ingress serving the retained chain until the configured
service budget expires. Mining-only options without `--mine`
refuse; V2 refuses the pool/miner options. See
[CONTINUOUS_MINING_V1](CONTINUOUS_MINING_V1.md) for finite limits and failure facts.

`pool-push --transactions FILE --pool-context HEX --peer ADDRESS` and
`pool-status-remote --peer ADDRESS` require the exact V3 profile, server public-key
pin and caller identity file. They do not open a second local store. A signed
business denial remains structured stdout with `ok=false` and CLI exit status2.
Unknown profiles, private-session mixing and network logical clocks refuse without
fallback. Head/History/block push/full sync accept explicitly selected V3 alongside
their existing V2 contract.

`tests/public_pool_cli.rs` executes the actual CLI composition: an unknown guest
submits signed funding dependencies and a tag22 atomic renewal, a wall-clock miner
includes the exact three raws, and a different native receiver validates the chain
and new task statement. Its finite eight-block run and strict option refusals do
not certify public service. The first stale task-window fixture failures are retained
in work observations; task admission was not relaxed to make the run succeed.

Three native socket integration tests exercise actual guest signed transfer bundles,
funding/nonce dependency, same-bundle duplicates, wrong pool context and corrupted
signature rejection, no partial rows/no ledger nonce consumption, operator mining,
stale read-only snapshot, explicit operator reconcile and persistent reopen. Both
actual cross-version socket clients reject V2/V3 mixing and later honest requests
still succeed. Startup cannot enable an unconfigured pool; invalid lifetime bounds
are rejected. Eleven V3 unit tests exercise body guards, closed ops, profile/magic/
signature domains, cookie tampering/restart epochs, paid reservations, slow frames,
fragmented honest traffic, expired connections and cleanup.

These tests are local component evidence. The root integration must replay on the
final committed Cargo graph with the actual pool and continuous miner, complete
strict checks and resource campaigns, and preserve failures. No acceptance flag for
public readiness, source independence, task/model efficacy or production activation
is enabled by this document.

## Local request observations

`serve_public_protected_v3_with_metrics` accepts a trusted local shared metrics
mutex. It uses the same worker/queue/Node owner and returns a final snapshot after
shutdown; holding that observation mutex can delay this local process. These
counters neither authenticate a guest nor prove an economic cost bound.

`call_public_protected_v3_with_metrics` returns the ordinary result and separate
construction, challenge, solution-search, solution/body/response and total elapsed
nanoseconds. Failed calls retain their current stage, elapsed time and completed
ticket trials. A signed business refusal still completes transport; its failure
stage is null. Elapsed time includes scheduling/network waits and is not CPU time.
The ordinary API retains its wire and return behavior.

V3 client CLI commands can explicitly select `--client-observations` to emit this
unsigned local diagnostic as one stderr JSON line, also on a failed transport call.
The signed reply remains on stdout, and unsuccessful calls retain exit2. Parsing
or identity-file errors before constructing the observed call have no stage receipt.
V2 and other profiles refuse this option. Controller wall time includes process
startup too and must remain separate from the client's stage observations.
