# Depleted public service: cooffered finite regression

## Entry and unchanged owner

The new `actual_depletion::depleted_domain_serves_honest_block_during_rotating_public_false_work`
regression is in the existing [native request-accounting tests](../../../../trillionnium/crates/trnm-pon-node/tests/public_v3_request_accounting.rs).
It adds no runtime queue, CPU domain, caller authority or persistent model owner.
The original two accounting tests and original three-round depletion/recovery test
remain unchanged. Work relations, packet meanings, budgets and production flags
are not modified.

## Actual experiment

The receiver starts with its existing policy: a 2-second CPU burst, 250ms CPU/s
refill, 100ms start reservation and two owners. Full reference W1 replays on the
actual local owner thread must produce a real live CPU-budget refusal before the
public traffic starts. A replay or time cap without that refusal is not a pass.
The same domain is then moved into the real protected TCP service.

Sixteen scoped local client threads offer a retained false W1 packet through the
ordinary paid public Submit protocol, rotating among 150 development identities.
Every negotiation, failed request and reply consumes one fixed four-second wall
window; each worker has an additional 1,024-attempt safety cap. A reached cap
fails this experiment rather than being called a saturation measurement. Calls
started within the window retain their original two-second deadline and are
joined before shutdown. The packet is constructed without acquiring a valid work
proof, but it is deliberately reused; this is not fresh-proof production cost.

A false call must actually complete before the honest operation starts. The
honest client submits a real newly mined packet and reads Head while the false
traffic continues. Both operations must succeed within two seconds and before
the shared traffic window closes. Measured false-call intervals must overlap the
honest interval; thread creation alone cannot establish cooffering.

The pass predicate also requires at least one real server work-verification
failure, no accepted false reply, complete bounded observation capture, closed
work accounting, zero outstanding CPU owners, and available clock/accounting
state. Full native active state must equal the independently advanced local
producer state. Node close/reopen must preserve the full active state and the
same retained CPU-domain epoch. Reports are written before the final assertion,
including failed outcomes; previous reports are never overwritten.

## Evidence and nonclaims

`depleted-public-overlap/report.json` records initial and final meters, actual
local depletion and settlement, every retained false-call outcome and transport
measurement, honest intervals, overlap count, receiver observations, full-state
comparison and reopen result. The current-source diagnostic workflow runs strict
Clippy and the complete accounting test target on x64/ARM64 and both source head
and the actual main-target merge. Source/tree/ordered-parent checks and the
original project preflight run before execution and source identity is rechecked
afterward. Original full baseline and state/history campaigns remain required;
this early gate does not replace them.

This closes a missing finite test boundary only when the exact-source execution
passes. Local trusted replay creates the depleted precondition. The experiment
does **not** show a remote attacker can induce depletion, establish the globally
cheapest work algorithm, or guarantee honest service against arbitrary sustained
Sybil traffic. The clients, producer and receiver share one controlling fixture.
They are not independent operators. Aggregate adversary CPU and WAN TPS remain
unmeasured; restart is a same-process Node reopen, not physical power loss. No
model installation, independent future learning, permanent DA or production
acceptance follows from this result. Those remain separate full-project exits.


## Network-only public business confirmation observation

The additive `public_v3_service_campaign` regression
`network_only_business::network_only_business_confirmations_survive_rotating_false_work`
uses the original public V3 r9 policy and one actual authenticated receiver. Four
public TCP clients rotate fixture keys while sending bounded false-trace traffic.
The receiver CPU domain is never charged through a local replay/debit hook. The
original acquisition and trace-search costs are retained; the supplied strategy is
not claimed to be the cheapest adversary. Each client attempt keeps its original
absolute deadline, success/refusal/error, transport counters and actual thread CPU.

Three prebuilt blocks carry eight signed hot-account transfers each; six ordinary
descendants provide the unchanged development confirmation depth and required work.
A distinct native consumer obtains the original packets through paid public History
requests and independently runs complete native admission and execution before
local confirmation. A remote ACK or Head value alone never increments the verified
confirmation count. Producer, receiver and consumer must have identical complete
active states; the receiver is then cold-reopened and compared again. Shutdown
joins the existing worker owner, with zero retained body/output/grant/CPU leases.
Every false attempt and all honest calls remain in the failure-preserving report.

The finite six-second offered-load window has four clients and at most512 calls
per client, with at most2176 observation records. Reaching a client cap is reported,
not silently represented as continuous saturation. Runtime tests require actual
overlap, complete measurements, no accepted false work and24 native-confirmed
business transactions. Full original service controls run alongside the new test
in the existing x64/ARM64 head/actual-main-merge lanes and unchanged25-minute budget.

These are same-process loopback clients and a same-implementation consumer with
separate stores, not independently operated parties. Logical prebuilt blocks,
reference-acquired false traces and finite attack load do not establish mining
throughput, cheapest physical/matrix cost, remotely sustained CPU exhaustion,
general Sybil fairness, future-task efficacy, physical power loss or WAN TPS. No
readiness or authority flag changes. Full65536-key/4105-block and two-repository
baselines retain their original independent execution requirements.
