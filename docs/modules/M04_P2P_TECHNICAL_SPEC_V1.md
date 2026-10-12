# M04 Bounded peer ingress and propagation

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Native admission components, the bounded loopback endpoint and an explicit allowlisted signed private-development profile. Separately selected [public V2](../protocol/pon-nakamoto-v1/details/PUBLIC_INTAKE_V2.md), [public V3 pool intake](../protocol/pon-nakamoto-v1/details/PUBLIC_POOL_INTAKE_V3.md) and [pinned peer following](../protocol/pon-nakamoto-v1/details/PINNED_PEER_POLLING.md) have their own resource and identity contracts; none grants independent public-network acceptance.

The claims below apply to their named component and tests, not to an independently accepted full native node.

## PoN State machine

### M04.ReadFrame

For the plain and allowlisted private profiles, use one absolute five-second frame deadline; require 1..2097152 before allocation and read exactly that many bytes. Plain service is loopback-only. The explicit authenticated development mode verifies canonical context-bound signatures before dispatch. The separately selected public profiles use their specified bounded phases and resource tickets; guest transport identity grants no source, evaluator or ledger permission. Submit payload still goes through full M02 validation, never through an accept flag.

**Atomic/commit boundary:** Transport has no chain authority. Authenticated replay reservation is durable before execution; M07/M08 remain the only block/state commit owner.

### M04.PropagateVerifiedBlock

Send one canonical packet through the normal native request path; each destination rechecks full work, state and local clock before acknowledgement. The authenticated client commits its exact signed wire before I/O and retries that wire after loss. Failed, retryable and terminal outcomes stay distinct.

**Atomic/commit boundary:** M07/M08 own block persistence. Inbound replay and outbound pending-wire records are separate atomic tables in the same private Node namespace; transport bytes cannot directly mutate chain state.

### M04.AuthenticateRequest

Derive one session from network, parameters, genesis, authentication profile, both peer identities and a positive generation. Verify strict Ed25519 over the canonical request and replay nonce. Reserve the exact nonce, payload digest and payload before execution; admit at most one active copy. A completed duplicate receives only the retained response after that response is reverified against the same request and server identity. A changed payload at the same nonce rejects.

**Atomic/commit boundary:** `peer_replay` and `peer_request_audit` reserve the request in one transaction. The signed terminal response and acknowledged nonce commit together. Expensive work runs outside the Node mutex, then destination context, state and clock are rechecked before a block commit.

## M04.RecoveryCapacity

**Invariant:** Public verification cannot consume or duplicate-pin a local recovery slot; stopped generations retain live accounting until every permit drops.

**Scope:** Native admission components, the bounded loopback endpoint and explicit private/public development profiles with separate resource contracts; none is an independently accepted public network service.

**Atomic boundary:** One mutex owns counts and per-lane duplicate identities; only the local recovery capability can select its lane; RAII releases each live permit.

**Failure schedule:** Fill public capacity with changing identities; Acquire recovery permit; Stop/resume while old jobs live; Panic unwind; Public caller holds the same certificate identity requested for local recovery.

**Expected result:** Public verification cannot consume or duplicate-pin a local recovery slot; stopped generations retain live accounting until every permit drops.

**Resource and retention rule:** Three public jobs, one recovery job, two jobs per peer; no unbounded queue.

## M04.AuthenticatedReplay

**Invariant:** One exact authenticated session nonce executes at most one active copy and replays only the same reverified signed terminal response; a different payload at that nonce rejects.

**Scope:** Allowlisted signed private development transport; no confidentiality, permissionless identity or public-network acceptance.

**Atomic boundary:** Reserve session, nonce, digest and payload before execution; terminal signed response and acknowledged nonce commit together. Work verification occurs outside the durable owner lock and context is rechecked before block commit.

**Failure schedule:** Restart with a pending request; Lose the first terminal response; Concurrent duplicate while pending; Changed payload at the same nonce; Replay a terminal error; Alter canonical session or request bytes.

**Expected result:** Restart and acknowledgement loss preserve exactly one request identity and one signed terminal result. A conflicting request never acquires authority, and a cached error remains an error rather than a completed success metric.

**Resource and retention rule:** At most64 peers, one pending nonce per session,16 retained response bodies,2MiB frames,three public workers and absolute deadlines.

## Concrete regression selectors

`trillionnium/crates/trnm-transport/src/proof_admission.rs::public_flood_cannot_consume_reserved_recovery_capacity`

`trillionnium/crates/trnm-transport/src/proof_admission.rs::stop_resume_does_not_erase_outstanding_work`

`trillionnium/crates/trnm-transport/src/proof_admission.rs::panic_unwind_releases_capacity`

`trillionnium/crates/trnm-transport/src/proof_admission.rs::public_duplicate_cannot_pin_a_locally_requested_recovery_digest`

`trillionnium/crates/trnm-pon-node/src/ingress.rs::test_authenticated_bytes_bind_session_signature_and_canonical_request`

`trillionnium/crates/trnm-pon-node/src/ingress.rs::test_durable_pending_request_recovers_and_completed_response_replays`

`trillionnium/crates/trnm-pon-node/src/ingress.rs::test_committed_submit_with_missing_auth_ack_recovers_without_work_replay`

`trillionnium/crates/trnm-pon-node/src/ingress.rs::test_authenticated_socket_replays_response_after_client_loses_first_ack`

`trillionnium/crates/trnm-pon-node/src/ingress.rs::test_cached_terminal_error_is_reverified_and_counted_as_rejected`

`trillionnium/crates/trnm-pon-node/tests/native_node.rs::test_authenticated_cli_push_and_sync_share_one_durable_outbox_owner`

These exact functions contain executable assertions. The registry only checks binding; actual outcomes and source/input identities belong to the separate qualification report.

## Module-specific threat and residual work

Sybil connection churn, eclipse, validation starvation and forged recovery priority.

The signed profile supplies identity, integrity and replay control for an explicit roster only. Confidentiality, trust distribution, open discovery/gossip, global public fairness and cheap-proof defense remain unresolved; local recovery capability is never selected by packet fields.

## Current source and verification

- [`trillionnium/crates/trnm-pon-node/src/ingress.rs`](../../trillionnium/crates/trnm-pon-node/src/ingress.rs).
- [`trillionnium/crates/trnm-transport/src/proof_admission.rs`](../../trillionnium/crates/trnm-transport/src/proof_admission.rs).

No test binding or local campaign grants independent acceptance, ordinary Hepta execution or production activation. Preserve the exact source, profile and environment of every outcome.

## Executed evidence and scope

[Responsibility-level evidence navigation](README.md#responsibility-and-evidence) reads
measured commits from immutable receipts. The module's entries in
[module-maturity-v1.json](../../config/pon/module-maturity-v1.json) identify actual callable
owners, controlled entrypoints, backends, persistence and exact observed test selectors.
Run `python3 scripts/ci/report_module_evidence.py --module M04` from the repository
root to see subject-byte and complete recorded-runtime matches separately, plus scenarios
not observed in each package. A byte match is not a new test run or product acceptance.
Historical v1/v3/v4 results are never repinned. The sole plan selects further work.

## Native development continuation and remaining scope

The native development server consumes actual bounded socket frames through the existing proof-admission component and Rust Node. Plain mode remains loopback-only. An explicit flag may instead enable the allowlisted signed private-development profile; key and roster files are inspected through no-follow opened descriptors, session generations are positive and request/response replay state is durable. This is not encrypted transport, open public P2P, Sybil fairness or a public recovery service.

The current callable mappings remain in `config/pon/module-maturity-v1.json`.
Exact native entry, storage and work behavior is specified by N3 in NETWORK_CLIENT,
the native continuation in STATE_RECOVERY and the prepared-producer section in WORK_PROFILE.
No historical receipt is relabelled as executing this source.

The native development Submit path releases the Node mutex for transcript replay,
then consumes an opaque exact-packet verification result through the same Node owner.
Context/clock/state checks are repeated before commit; lock waiting and post-work
cancellation are bounded. The exact remaining public-service limits and executed
counterexamples are in [A2](../protocol/pon-nakamoto-v1/details/ADMISSION_SECURITY.md).


## Owned CPU continuation past the purchased start quantum

The current public r9 receiver and local service operation share the existing
volatile scalar CPU owner. A start still deducts exactly 100,000,000ns and opens
one of at most two reservations. Burst, refill, deadlines, connection/lane caps,
work verification, source authority and final settlement remain unchanged.

Let `C` be stored free credit, `n` the active reservation count and `R` the fixed
start reserve. All live samples debit actual owner-plus-worker CPU immediately;
the complete start reserves are returned only at settlement. Thus the shared
balance before those returns is represented by `C + n*R`. The existing first
quantum rule still requires this balance to be nonnegative. After the request
crosses `R`, continuation now requires `C >= -R`, not `C >= 0`. It adds back only
that request's already purchased reserve; all other complete reserves remain
protected because `C + n*R >= (n-1)*R >= 0`. This eliminates a repeated own-reserve
constraint, not a second CPU charge or an increase in actual resource supply.

A request that exhausts its own quantum and all unreserved credit still refuses.
Known CPU from the refusing sample and final residual remains charged. Unknown
clocks, lost reservations, counter overflow, stopped requests and genuine shared
deficits retain their original refusal/fencing behavior. New starts cannot spend
negative stored credit. No accounting lock spans native work and no completed
native result is revoked by final metering. Final credit is still initial credit
plus bounded refill minus actual measured CPU, subject to the original ceiling.

The original four owned-quantum controls remain. Added native controls are:

- `ingress::public_v3::scalar_cpu::request_owned_reserve_tests::owned_quantum_remains_credited_when_request_crosses_its_first_quantum`
- `ingress::public_v3::scalar_cpu::request_owned_reserve_tests::extended_request_cannot_spend_the_other_owned_quantum`
- `ingress::public_v3::scalar_cpu::request_owned_reserve_tests::actual_cpu_extension_uses_its_own_reserve_and_settles_exact_total`

The Linux thread-CPU control actually crosses the first quantum with frozen
refill; exact balance checks retain one-nanosecond debt and the other owner's
reserve. These controls are required alongside the unchanged native public
service/hostile-business tests and complete baseline. A finite loopback pass
is not independent WAN operation, minimum physical attack cost, general Sybil
fairness or saturated confirmed TPS. No readiness flag is promoted.
