# M10 Agent, Task and Market technical specification v1

Status: candidate module contract; terminal-lifecycle extension below is planned.
Primary module: M10. No identity, market or economic activation is granted here.

## Authority

M10 owns delegated application authorization, per-lane nonce use, shared budgets,
task/lease/escrow state and their replay identities. It cannot authenticate an
Order-finality digest by assertion, mint money, select a consensus fork or
declare a verification result mature. M01 authenticates keys; M11 verifies
results; M12 settles; M08 supplies actual finalized application authority.

Normative design inputs are [identity specification 03](../protocol/poco-ai-native-v1/03-agent-identity-capabilities-and-nonce-lanes.md)
and [market specification 04](../protocol/poco-ai-native-v1/04-market-task-lease-escrow-and-lifecycle.md),
especially section 6.1's exact lifecycle bodies and sections 9-11's terminal
and migration predicates. Their global AI-v1 wire remains draft. Existing local
implementation is `trillionnium/crates/trnm-poco-agent-market-v1/src/`.
Its `types.rs`, `codec.rs`, `agent_transaction_wire_v1.rs`, and `store.rs`
define the selected candidate layouts; they do not amend frozen bft-v0 bytes.

## Interfaces

`PocoAgentMarketStoreV1::execute_order_finalized(context, command)` accepts
an exact `OrderFinalizedExecutionContextV1` and `KernelCommandV1`.
The context is a monotonic predecessor/target CAS input, not a proof verifier.
`preview_before_vote_v1` returns `AgentMarketPreVotePreviewV1` without durable
logical mutation. `confirm_receipt` returns `ConfirmedKernelReceiptV1` only
after source-bound fresh readback. M15 must supply the authenticated caller.

Current command variants and selected operation kinds are closed:

| Command | Kind | Inputs / effect |
|---|---:|---|
| `CapabilityGrant` | 2 | Exact grant body and controller authorization; create scoped capability/budget |
| `SessionGrant` | 3 | Exact session body and authorization; create bounded delegated session/lane |
| `TaskCreate` | 4 | Task+escrow operation, declared resource charge, authorization; atomic funding/reservation |
| `Bid` | 5 | Bid body, charge, authorization; bind provider offer to current task |
| `LeaseAccept` | 6 | Lease body and expected bid/escrow/bond versions; atomic lease/resource reservation |
| `ProviderAccept` | 7 | Provider acceptance body and expected lease revision; Offered→Active |

`KernelAuthorizationStatementV1` binds schema/context, kind and operation digest,
sender/key, optional capability/session IDs, live generations, nonce lane/nonce,
expected lane version and validity heights. `KernelAuthorizationV1` adds signer
key ID and signature. Controller lane is 0; the all-zero controller sentinel
is a defined internal key identifier, not a generally acceptable public key.

Capability bodies specify operation/resource scopes, spend limits per asset,
fee/gas/DA/retention caps, allowed lanes, height interval, rate window and count,
total operations, delegation depth and revocation generation. Session grants
must be no broader than the selected capability. IDs are derived from exact
candidate bodies using `codec.rs`; provided IDs and operation digests must match.

### Owned chain-external worker: `trnm-worker-agent`

This binary is an operator tool, not an implementation of the six AI commands.
Its current `SubmissionRecord` binds numeric task ID, worker, optional nonce,
commit/result hashes, 32-byte salt representation and commit/reveal command
specifications. `MessageIngressRecord` additionally retains request/session/
idempotency identity, input, assignment, output/provenance, adapter outcome and
acknowledged transaction hashes. These JSON/JSONL records are local workflow
state, not CEV1 objects or proof of finalized task state. Their task IDs require
an explicit commissioned mapping before any AI-v1 integration.

The workflow parses configured commands into argv, rejects shell-program entry,
invokes the operator-selected adapter with a timeout, classifies its status and
persists acknowledgement hashes for restart. Current transaction defaults are
3 retries and 200 ms backoff; LLM defaults are 2 retries, 200 ms backoff and
10,000 ms timeout. These are process defaults, not task-consensus deadlines.
Return codes 0/9/10/11 mean success/duplicate/nonce rejection/SLO violation.
Deterministic rejection terminates retries; an uncertain result must retain
the same task/commit/result identity and consult persisted acknowledgement state.
An acknowledgement hash is an input to M13 proof lookup, not finality by itself.

The operator, never task text or provider output, selects executable and signing
custody. Production adapters must authenticate the worker and submit through
M05's nonce/funding checks; a `worker` string in a local record grants no chain
authority. Do not reissue a commit under a new nonce merely because its response
was lost. Preserve the exact salt until reveal and redact it, credentials and
private prompt/output from ordinary logs. JSONL replay must reject an incomplete
or conflicting record instead of silently advancing `last_task_id`.

Planned **WORKER-DEV-1** host admission caps UTF-8 prompt/output at 64 KiB/1 MiB,
one active task and 128 queued submissions, 1 MiB/record and 128 MiB live outbox;
retry caps are 3 transaction/2 LLM retries, each process at most 10 seconds.
Reject oversize before spawn/append; full outbox pauses new work while preserving
accepted records. Bound captured stdout/stderr to 1 MiB each and terminate an
overproducer. These aggregate/output limits need implementation; the current
timeout/retry code alone does not supply them. Planned durable outbox records
bind schema, task identity, command digest and commit/reveal ACK state; fsync the
record before advancing the cursor, and reconcile ambiguous writes after reopen.

Required vectors include loss after commit ACK followed by resume (reuse the
same persisted hash, no duplicate commit), malformed ACK on a duplicate response
(do not claim accepted), deterministic nonce rejection after one transient error
(stop), and oversized output (terminate, no reveal). Existing regression anchors
are `tests_adapter_path_flush_persist.rs`, `tests_adapter_path_flush_result.rs`
and `tests_adapter_path_classification_retry.rs`, including
`flush_submissions_requires_tx_hash_receipts_for_terminal_acceptance` and
`run_adapter_with_retry_stops_after_retriable_failure_followed_by_deterministic_rejection`.
M11 proof-adapter outcomes and local provenance remain observations until their
exact evidence is accepted by the commissioned verification profile.

## State machine

### Authentication and shared reservation algorithm

1. Bound/decode the exact selected command; derive its operation ID and body digest.
2. Match installed chain/genesis/profile and authenticated current height.
3. Resolve signer from committed controller/session state; strictly verify
   the statement. Never use a public key carried by an untrusted command as authority.
4. Verify live capability/session generations, height interval, scope/price
   constraints and allowed lane. Compare nonce and expected lane version exactly.
5. Check shared capability budgets across all its sessions/lanes, not only this
   lane. Check asset, fee, gas, DA, retention, rate and total-operation counters.
6. Resolve all referenced objects and exact expected versions. Compute every
   debit/reservation/successor and checked arithmetic before applying any.
7. In one transaction consume nonce, shared budgets, rate count and object
   changes; append exact operation receipt and state/journal roots.
8. Commit, close and fresh-read exact target before returning confirmation.
   Rejected commands change none of nonce, funds, budgets or authoritative roots.

Two different operations cannot both reserve the same final shared budget.
Exact operation replay returns the original receipt, not another nonce use.
The planned controller revocation operation increments generation atomically;
all older session/capability authorizations reject thereafter. This is an
explicit future command, not already present among the six variants above.

### Current market prefix

`TaskCreate` moves funds from the requester account into the specified escrow
and creates both objects atomically. A bid binds task/profile/price/deadline
and provider identity. `LeaseAccept` consumes expected task/bid/escrow/bond
versions and creates the lease plus reservations as one transition.
`ProviderAccept` requires the named provider, offered lease revision and valid
acceptance deadline. It advances to Active without selecting a new task/profile.

### Planned complete lifecycle, using the existing draft bodies

No new wire kind is allocated by this table. Before enabling each operation,
implement the exact body and tags from specification 04 section 6.1 and add
it to the closed candidate codec with explicit version compatibility.

| Operation | Required predecessor and authorization | Atomic successor |
|---|---|---|
| Start | Leased/accepted exact lease, provider, current attempt, start deadline | Running; start identity recorded once |
| Progress/checkpoint | Running, same attempt/provider, increasing checkpoint sequence, authenticated artifact retention | New checkpoint reference; no payment or result-finality authority |
| Pause | Profile-permitted phase and authorized requester/provider rule | Paused with preserved escrow, latest verified checkpoint and deadline |
| Resume/migrate | Paused or eligible migration phase, exact checkpoint and successor lease accepted | Increment attempt; switch lease; previous attempt cannot submit current result |
| Submit result | Running, current attempt/provider, exact receipt/output/profile, before result deadline | ResultSubmitted; retain result/evidence obligations |
| Begin verification | Exact M11-admitted result and pinned profile | Verifying; no release of escrow |
| Settle | M11 mature challenge-closed result and M12 exact settlement receipt | Settled, consume settlement identity once, retain remaining DA/archive liabilities |
| Cancel/expire/fail | Enumerated draft branch, current revision, height predicate and actor authorization | Terminal status plus authenticated refund/slash intent; no guessed compensation |
| Refund confirmation | Exact M12 receipt for prior terminal intent | Refunded accounting; cannot double-credit or resurrect task |

Every transition consumes current revision and increments it with checked
arithmetic. A missing result is not an invalid result; `Unavailable` keeps the
task retryable or follows the explicitly selected deadline/refund branch.
Cancellation is not permitted merely because an RPC caller requests it.

## Persistence and recovery

The current store records schema/config identity, object bodies and mutable
versions, operation command/receipt history, and finalized-block markers.
`advance_empty_order_finalized_v1` records empty ordered blocks so deadline/rate
progress cannot depend on new user transactions. Recover by checking all roots,
contiguous operation/marker predecessors, exact command replay and schema.

Before commit failure resolves to the complete predecessor. Lost response after
commit resolves to the exact recorded successor. `CommitUncertain` requires
fresh reopen; `ThirdStateFenced` is permanent for that owner. Never replay a
subset of task/escrow/bond/nonce rows. Local checks do not prove whole-store
freshness after coherent rollback; M08 must reconcile externally retained state.

Planned terminal service selects due items by `(due_height, task_id, attempt,
revision)` and processes a bounded prefix before new admissions. Persist the
service cursor with the same state update; restart repeats only the exact item.
Resource release requires settlement/refund and retention obligations resolved.
Archive proofs retain retired task IDs, nonces and terminal receipts; deleting
active rows cannot reopen an old task or permit ID reuse.

## Resource bounds

For planned **MARKET-DEV-1**, use at most 1,024 active tasks, 16 active leases
per provider, 16 nonce lanes per agent, 64 scopes/grant, delegation depth at
most 4, 64 terminal-service items/block and 64 retained checkpoints/task.
These are selected development admission limits, not existing source constants.
Wire command bytes must also satisfy `MAX_AGENT_TRANSACTION_COMMAND_BYTES_V1`.
When either limit is exceeded, reject new admission before reservation;
continuing service/refund work must retain separately reserved capacity.

The planned development profile caps each grant at 1,000,000 fee units,
10,000,000 gas units, 8,192 DA bytes, 20,000 retention-block units and
1,000,000 total operations. `rate_window_blocks` is 1..10,000 and
`rate_max_operations` is 1..1,024; total operations must be at least that cap.
The exact requested budget may be smaller and is committed in the grant.
Expiry must exceed valid_from and be at most 100,000 blocks after it.
Allowed lanes are sorted and fit the host bound; per-asset spend is at most
1,000,000 units and cannot exceed authenticated funding. Overflow rejects.
Identity/key/profile commitments and policy version are mandatory nonzero
values from the signed commissioning input; they have no local fallback.
Changing application-visible limits requires an authenticated profile change.

## Security

Use actual `AgentMarketErrorCodeV1`: `InvalidSignature`/`Unauthorized` reject
the actor; `InvalidCapability`/`InvalidSession`/`InvalidNonceLane` reject scope;
`NonceReplay`/`NonceGap` reject sequencing; `BudgetExceeded`/`RateExceeded`
refuse admission; `StaleVersion`/`Expired`/`Conflict` preserve predecessor.
`ConservationViolation`/`ArithmeticOverflow` reject atomically. `StoreFailure`
is local availability/uncertainty; schema/tamper/third-state errors fence.
Do not report storage exhaustion as a malicious user's invalid signature.

Capability revocation, task cancellation and final settlement are distinct
authorities. Revoking a session stops future actions, not an authorized refund.
Private prompts/model data stay outside chain state; only committed references
and bounded public verification metadata belong here.

## Observability and SLO

Report admitted/rejected operations by code, active reservations per resource,
terminal queue age, nonce contention, receipt latency, preview/commit latency,
archive size and replay time. Publish shared-budget and conservation violations
as zero-tolerance invariants; do not log signatures, bearer material or prompts.
MARKET-DEV-1 service acceptance requires every due item progresses within
ceil(due_items/64) successful blocks absent a blocking proof dependency.

## Verification and evidence

| Case | Input and exact expected property |
|---|---|
| M10-SHARED | Budget 100, existing reserve 60, two lanes each request 50: neither may raise reserve above 100; rejected reservation leaves 60 |
| M10-NONCE | Expected nonce 8; signed nonce 7→`NonceReplay`, 9→`NonceGap`; neither consumes balance or nonce |
| M10-STALE | LeaseAccept expected escrow version 3, stored 4: `StaleVersion`; no lease/bond partial write |
| M10-LOSS | Lose TaskCreate response after commit; exact retry returns original task/escrow/receipt, one debit |
| M10-ATTEMPT, planned | Migrate attempt 2→3; old provider submits attempt 2 result: reject, retain attempt 3 state |
| M10-SERVICE, planned | 65 due refunds, no user submissions: 64 then 1 processed over two successful blocks |
| M10-REVOKE, planned | Increment generation 4→5, then use signed generation 4 session: reject before nonce/budget use |

Existing `src/tests.rs` anchors are `task_funded_escrow_bid_lease_and_provider_accept_are_atomic`,
`authorization_signature_context_nonce_scope_and_budget_fail_closed`,
`order_finalized_height_advances_monotonically_and_resets_rate_window`,
and `crash_outcomes_are_exact_and_third_state_is_permanently_fenced`.
Planned terminal/revocation cases need independent encoded vectors and real
M11/M12 consumers; the existing prefix regression does not cover them.
The [agent-market case inventory](../protocol/poco-ai-native-v1/vectors/cev1-agent-market-kernel-v1.json)
maps candidate names to the executable source. It does not replace independently
derived bytes, expected parser errors or terminal-lifecycle vectors.

## Activation boundary

Commission only the six implemented candidate commands until planned codecs,
state transitions, service/archive bounds and producer/consumer replay pass.
Public lifecycle support requires the exact finalized-order authority and real
M09/M11/M12 joins. Candidate constructors, source tests and this design never
enable AI-v1, production consensus or independent acceptance.
