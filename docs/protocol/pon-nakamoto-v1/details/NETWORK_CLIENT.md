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
