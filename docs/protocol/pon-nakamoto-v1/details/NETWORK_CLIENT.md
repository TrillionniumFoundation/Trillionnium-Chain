# N1 — bounded network/client and deployment contract

M04 owns transport ingress, M14 user/client projections, M15 assembly. This describes an
exact executable-spec harness plus the remaining native contracts; it does not call a
localhost server a production peer network. No new consensus engine is introduced.

## N1.1 Implemented loopback envelope

`experiments/local_network.py` starts three separate processes, each with its own SQLite
ledger directory. It binds only127.0.0.1 on an ephemeral port. Socket timeout=10 seconds,
listen backlog16, server inactivity timeout30 seconds. Frame is BE32 byte length followed
by UTF8 JSON; 1<=length<=2,097,152. Length is checked before allocating the payload.
Duplicate JSON keys reject. This is test transport, not authenticated native P2P.

| Operation | Exact request | Response / failure |
|---|---|---|
| submit | op, header(hex), transactions(list hex), proof(strict base64) | verified block id, active tip, state root, generation and local validation duration; otherwise explicit error |
| head | op=head | complete active tip/root/generation |
| stop | op=stop | local test shutdown acknowledgement; never a remotely exposed product admin API |

Each process decodes and independently recomputes work, signatures, branch target, state
and receipts. Ack is produced only after admission/reorg completes and active state is
read back. Root agreement is checked by the parent harness. Honest localhost ACKs are
not a light-client proof; production clients must independently verify evidence.

The harness propagates64 signed transfers with disjoint versus hot recipients, six real
work confirmation-fill blocks, invalid transcript requests, oversize frames and a real
heavier competing branch. It does not sleep to achieve configured10-second spacing;
reported latency is implementation cost, not production TPS or a mainnet block-rate test.
Child processes are owned from creation and killed/reaped on timeout or parent failure.

## N1.2 Native peer protocol to implement at existing owners

Use the retained authentication/session frame library, with versioned message kinds:
Hello, HeaderAnnounce, HeaderRequest, BodyRequest, WorkRequest, ArtifactChunkRequest,
Response, Busy, Cancel. Request identity includes peer/session generation, request id,
chain/genesis/profile and expected content hash. A late response from a prior generation
cannot satisfy a new request. No Vote/QC/TC message or validator membership is restored.

Limits from devnet parameters: peer inflight4; global proof jobs4; pending headers4096;
hot forks64; max frame2MiB; body1MiB; model chunk1MiB; artifact64MiB. Block-control and
recovery queues have independent reserved capacity from model downloads and GPU work.
Per-peer rate limits are local service policy; they never make an otherwise valid block
consensus-invalid. Busy/timeout/missing data returns Unavailable, not forged bad-block proof.

Discovery, source diversity, Sybil/eclipse defense, authenticated artifact fetches,
proof-admission DoS and reconnect fairness remain native implementation/attack obligations.
The current loopback envelope provides no global-peer identity or independence guarantee.

## N1.3 Public client schemas

A production QueryConfirmation returns network, included_block, observed_tip, included_height,
observed_height, cumulative_work_delta, policy_id and active_generation. `confirmed` is
true only for the named depth+work policy; no `finalized=true` alias is permitted.
Any new active generation invalidates stale cached currentness, though historical facts
remain queryable. Header inclusion does not establish data availability or execution.

SubmitTransaction returns request_id, tx_id and admitted/submitted/rejected, not success
of physical execution. QueryTask returns immutable task/attempt scope, branch-relative
status, explicit uncertainty and original operation identity for reconciliation.
SubscribeEvents uses (generation,ordinal); reconnect resumes that cursor or requests a
fresh consistent snapshot. Missing history never silently starts at current tip.

DiscoverModel returns exact release, family, bundle hash, deployment profile and evidence
class. DownloadModel verifies bytes/shape before load; hot/cold expert selection and fewer
experts must be visible as different deployment profiles. No pickle or arbitrary scripts.
FreeInference requires an existing bounded quota, chosen model version, input commitment
and local authorization. Output binds the actual loaded model and immutable request.

## N1.4 Host assembly and shutdown

Startup order: validate configuration and fresh namespace → acquire owner locks → recover
unfinished reorg and effect journals → verify roots/parameter commitment → construct bounded
ports → admit connections. Private key custody, application budget and model authority
are distinct ports; no API returns a serialized bearer execution capability.

Shutdown: stop new admission, cancel bounded work/downloads, persist exact publication and
recovery position, drain acknowledgements, retain indeterminate effects, close stores and
release locks. Kill after a deadline never converts Unknown into NotExecuted. A GPU
failure cannot stop local revocation or chain recovery capacity.

Production services are not installed or run by these experiments. Generic release-bundle
checks do not establish this node lifecycle. The native adapter to ordinary Hepta requests,
independent operators, target-machine long runs and public RPC remain explicit missing
integrations, with component/reference evidence shown separately from deployment.

## Physical-host conformance without installing a service

`multihost_campaign.py` copies a closed source manifest into new private temporary roots
on explicitly selected SSH hosts. The test channel is framed authenticated SSH stdio,
not a public P2P protocol or independent network. No listener, firewall, router, key or
existing user service is changed. All child sessions are closed/reaped on completion.

A separately recorded temporary devnet configuration selects a distinct genesis whose
timestamp permits real UTC validation. Every peer verifies identical source/config
hashes and reports actual local UTC. Test headers use max(UTC,median+1); the configured
10-second target spacing is NOT enforced and the experiment does not report public TPS.

The campaign measures a deliberate controller delivery partition and catch-up, exit86
after block admission, startup selection, heavier fork detach/attach, retained local
effect facts, invalid proofs, independent physical artifact copies, author-copy removal,
integer inference parity, sponsored signed consumption, exhausted-quota rejection and
a six-depth/work confirmation. Actual observations include bytes, elapsed/CPU time,
peak RSS and database size. GPU work is absent, not a measured GPU performance claim.

Physical hosts controlled by the same person are not independent operators. Transport
routing attacks, hostile open peers, long-term DA, power loss and ordinary Hepta owner
execution remain different acceptance obligations.

## N2 — executed bounded history receiver and local confirmation

`formal/pon-nakamoto-v1/client_confirmation.py` adds the controlled M13/M14 caller,
not another consensus engine, chain store, native public node or succinct proof system.
The receiver uses its existing `Ledger.admit` (real work, signatures, expected target,
ordered state and roots), `Ledger.activate` and durable namespace. Optional explicitly
selected `TRNM_NATIVE_WORK` / `TRNM_NATIVE_EXECUTOR` retain their fail-without-fallback
semantics. Without those selections this is the existing Python reference backend.

### Page bytes and cursor

The versioned `pon-history-page-v1` object has exactly schema, network, parameters,
genesis, tip, after, blocks, next_after and complete. All five digest fields and the
genesis context are exact lowercase fixed digests. A block contains only canonical
base64 header, a list of canonical base64 transactions, and canonical base64 work proof.
Proof size comes from the installed work profile. Remote chainwork, confirmed, clock,
authority or snapshot fields reject; no peer total is used for chain selection.

At most16 blocks and2MiB occur in a page. Bytes are bounded before JSON, duplicate keys
reject, and decoded per-object limits apply before work. Parent links, the exact last
block identity and complete=(next_after==requested_tip) must agree. Empty pages are
valid only when the requested tip already equals the locally verified cursor.
These are transport budgets, not a permanent height or reorganization cutoff.

`history_pages` pins a stored branch and spools its ancestry once in an8KiB buffer,
then emits it forwards. Height must decrease strictly in ancestry; a cursor from another
fork rejects. The exporter does not export SQL snapshots or assert global currentness.
The iterator closes its spool on cancellation/close. Traversal and disk use can grow
with history; this does not claim constant-work synchronization or long-term DA.

### Admission, incomplete delivery and retry

`receive_page(receiver,bytes,expected_tip,after,observed_now)` uses the caller-pinned
expected tip, a cursor already present in the receiver's verified store, and the LOCAL
observation clock. Neither digest pinning nor the page's complete field proves that
this is the latest global chain. Full byte/context/order checks precede expensive work.
Each successful block is committed by the existing Ledger owner; failure or cancellation
may leave a fully verified prefix. It never persists the invalid block or returns a
successful completed-request receipt. Replaying the same page after a lost ACK uses
exact stored block/body/proof equality rather than repeating work or issuing rewards.

Requested-tip activation occurs after the complete target verifies and still uses
strictly greater locally derived cumulative work. A lower-work valid imported target
can complete without becoming active; both observations are returned separately.
A subsequent ordinary restart can correctly select a stored verified prefix as its
best observed chain. That fact is not completion of an interrupted longer request.
EOF before completion is INCOMPLETE_HISTORY; trailing data is not a successful request.
Already committed valid blocks are not rolled back to simulate page-level atomicity.

### Confirmation facts, not authority

`confirmation` reads the receiver's coherent active state, checks the included body's
transaction root and exact TxId membership, follows active ancestry, and computes depth
and cumulative-work delta against the installed depth+work policy. It returns included,
confirmed or reorged with exact observed tip and local generation. A replaced generation
fails STALE_VIEW. Any future-clock ancestor fails TIME_DEFERRED, including ancestors
below the included block: timestamps are median-constrained, not monotonically increasing.
A logical test clock is explicitly labelled and cannot become a wall-clock confirmation
merely by reopening its database or following a later, earlier-timestamped tip.
Orphaned inclusion has no current depth/work and cannot remain confirmed.

A retained confirmed response is only an observation at its returned generation/time.
It cannot authorize a physical call or guarantee global freshness, eclipse resistance,
zero rollback risk, data retention or independently administered validation. Finalized
and execution-authority fields remain false. The full client verifies history rather
than trusting a server's work counter; it is not advertised as a lightweight proof.

The controlled CLI supports export/receive/confirm with --store, caller-selected --tip,
--after, --transaction and --included-block. NDJSON transport bounds each line before
parsing. --logical-now is explicitly a test option; absence uses the local wall clock.
No public listener, firewall, running service, deployed key or Hepta permission is added.

Exact regression owners: `test_client_confirmation.py::VerifiedHistoryTests` covers
actual work/signature/state replay; disk reopen/resume and lost ACK; invalid and reordered
pages; body substitution; lower-work branches; heavy-fork removal of confirmation;
local-clock deferral; and real CLI subprocess receive/confirm. The same suite also runs
with both native component backends explicitly selected. This tests controlled client
behavior, not a full native node or independent public-network acceptance.

### Local-clock reobservation and cancellation

An immutable work result is reusable; a prior clock observation is not. `receive_page`
checks every incoming header against its caller's current clock even on exact stored
retransmission. Before completed-target activation (including an empty terminal page),
it checks all locally verified ancestry, so an old cursor cannot smuggle a future block
from an earlier logical-clock import. TIME_DEFERRED is a local retryable observation,
not a permanent invalid-block cache entry or a change to chainwork/consensus validity.

`confirmation(..., progress=...)` checks full ancestry through genesis in constant
auxiliary memory. It invokes the cancellation callback before walking and every256
ancestors. Cancellation returns no partial confirmation, changes no store and can be
retried. The generation is checked again before a result escapes; a reorg during the
walk yields STALE_VIEW. This is linear historical work, not a succinct proof or an
incremental native state index. Source-root reconstruction costs remain separate.

Actual counterexamples include a high-timestamp ancestor followed by a lower-timestamp
valid tip, an ancestor below inclusion, a duplicate page with a different local clock,
a terminal cursor referring to old future history, cancellation and a generation switch.
All work and state in those tests are actually verified; no accepted-history fixture
or remote clock field supplies their authority.

## Bounded coherent confirmation batches

`client_confirmation.confirmations` accepts 1..256 distinct (transaction, included-block)
pairs. It validates every required body commitment and membership, captures one active
tip/generation, and reobserves the COMPLETE verified ancestry against the caller's clock
once for that batch. A future timestamp spike below all requested inclusions still defers.
Any missing membership, invalid tuple, cancellation or generation change rejects the
response; there is no partial successful batch or persistent currentness cache.

The single `confirmation` API delegates to the same path. Included, confirmed and reorged
are computed per transaction under that one coherent view; no remote work sum is trusted.
A bounded batch avoids repeated identical scans inside one request without changing
probabilistic confirmation, returning deterministic finality, or granting execution rights.

The controlled session pipeline records submitted, source-included, receiver-verified
and locally policy-confirmed counts from actual signed transactions and work-verified
blocks. It is one controller passing bounded pages between separate stores with separate
native compute children, not authenticated public P2P, independent administration or WAN
capacity. The test uses an explicit logical clock and does not pace ten-second blocks.

## N3 — native development entry and its remaining public-host boundary

`trnm-pon-node` is the M15 native composition of the existing M00 codecs, M01 work
verifier and M06 twelve-command executor. Its `consensus` module implements M02
checked target/time/work arithmetic; `store::Node` is the M07/M08 single durable
owner for a NEW `native.sqlite` namespace. The Python Ledger remains a separate
conformance oracle, never a runtime fallback or writer of that namespace.

The ordinary binary exposes status/recover, make/mine, submit/export, confirm/confirm-batch,
push/sync and serve. It requires `--development`; the installed identities and units
are public test material, not wallet custody or a monetary deployment. Signed command
bytes are external inputs; this entry does not introduce a wallet or provider caller.
A packet is the existing 318-byte header, LE16 transaction count, repeated LE16 length
plus signed command bytes, and the exact 49,188-byte work certificate. Counts, total
bytes and each existing command codec are checked before accepted state is constructed.
Mining freezes native execution roots before varying nonce. Packet publication uses
create-new output, file/directory sync, then block admission/activation; an existing
output path cannot cause a newly mined block to be published silently.

`serve` binds loopback only, uses three fixed workers and the existing public proof
admission component. BE32-framed closed JSON has a 2 MiB bound and an absolute five-
second frame read/write deadline; incremental bytes cannot reset it. Remote messages
cannot stop the host, supply local time, select recovery priority or change genesis.
Full validation is serialized by the durable Node owner. This is real socket ingress,
not authenticated public discovery/gossip, parallel public verification or Sybil fairness.

The closed `pon-native-history-v1` page binds network, parameters, genesis, requested
branch/cursor, full packets and terminal identity. The receiver checks all cheap page
links before admission, recomputes work/execution itself and preserves only fully valid
prefixes on interruption. A completed lower-work branch is not necessarily active.
The native confirm path verifies exact transaction membership, active ancestry, all
ancestor timestamps and depth plus required work. Its identity includes transaction,
genesis, policy, observed generation/time and required work; it grants no finality or
physical-call authority. Cached immutable work does not cache a local clock verdict.

Build with `cargo build --locked --release --manifest-path trillionnium/Cargo.toml
-p trnm-pon-node --bins` (one command). Every store must use the same explicit context.
`--genesis-time` creates a distinct valueless development genesis for wall-clock socket
tests; it cannot reopen an existing store under new parameters. `--logical-now` is a
labelled local conformance option and is rejected for serve, sync and push.

Still missing: durable continuous mining and transaction-pool/reorg scheduling,
authenticated peer discovery/gossip, native incremental persistent state, bounded interruption of all
state reconstruction/admission/reorg work, ordinary Hepta admission/consent/effect owners and independent
public attack acceptance. Session cache and native Node own different namespaces; neither
may be substituted for the other without their own explicit invocation and evidence.

### Native coherent batches and cooperative read cancellation

`Node::confirmations` and `confirmations_with_progress` accept 1..256 distinct
(transaction, included-block) pairs. All requested memberships must validate; empty,
duplicate, oversized or partially invalid requests return no batch. One distinct body
is checked once, and the complete current ancestry is reobserved once for the batch.
Returned observations retain each transaction's depth/work/reorg result and share one
observed generation/time. `ancestry_checked` and `distinct_bodies_checked` count actual
checks; neither is a throughput estimate. Single confirmation delegates to this path.

The ordinary `confirm-batch --queries PATH` command reads at most 64 KiB of closed
transaction/block objects. Socket `confirm_many` uses the same owner and validation.
History export and confirmation call the cancellation hook before traversal, every
256 ancestors and before successful return. Cancellation or changed generation returns
no partial successful observation and stores no reusable currentness cache. Read-only
socket operations check local stop and a ten-second request deadline bounded by the
server lifetime. This is cooperative cancellation, not a preemptive deadline for one
SQLite call, root reconstruction, proof verification, admission or reorg execution.
Duplicate packet admission also rechecks its timestamp against the caller's clock;
immutable work equality never supplies that clock observation.

The actual socket regression runs ticket-passing false transcripts concurrently with
honest four-query confirmation batches through the normal native entry. It uses one
loopback host, bounded clients and the existing serialized owner, not public identities,
WAN load, independent operators or a Sybil-safe public-service result. Native generation
fault injection and actual heavier-fork tests are separately identified in the tests.
