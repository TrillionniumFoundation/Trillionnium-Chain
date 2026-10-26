# P1: original-domain CPU ownership for pinned peer W1 history replay

**Candidate only, not accepted/public qualification.** Parent commit
'db0dad68f0909460e8b1cf0c248d8bab4b59c129'. No W1 byte, ticket, fork
selection, chainwork, task selection or V3 signed-resource revision changes.

## Original bypass

Before this fix, 'peer_polling.rs::admit_page' accepted a signed, pinned
remote history page, ran ordinary 'WorkCheckedPacket::verify(packet)' outside
the existing Node lock, and then called 'Node::admit_work_checked'. Peer
signatures authenticated a sender but **did not pay** the receiving host's W1
CPU budget. The owner cgroup could cap aggregate host CPU, but the public V3
shared mutation account could be drained indirectly by concurrent uncharged
pinned-peer work, allowing reader/submit starvation. The finite configured
pages/rate cannot establish per-W1 CPU conservation.

## Implemented source boundary

- The receiving Node must **already** expose its one original
  'public_service_cpu_domain()'. No per-peer/connection/identity bucket can
  be created. An unbound Node returns 'OWNER_PUBLIC_SERVICE_DOMAIN_UNBOUND'
  before calling the complete verifier.
- In the combined CLI service, the pinned poller and public V3 listener
  start concurrently. The poller waits no more than the original 10-second
  startup cap for the same Node's original domain to be bound; a genuinely
  unavailable owner fails closed.
- A new history packet starts an original 'ServiceMutationCpuOperation',
  then replays W1 with 'WorkCheckedPacket::verify_with_progress'. The same
  live CPU handle checks stop, deadline and budget at the original W1
  noise/row/tile/product callbacks.
- The identical operation covers 'admit_work_checked_with_control', including
  any real M06 workers registered through its scoped worker accounting.
  Native success and rejection are separate from the subsequent CPU
  settlement; unknown accounting fences new paid work instead of rewriting
  a completed ledger fact or inventing a refund.
- An exact previously admitted packet keeps its existing admission-context
  short-circuit; it does not acquire or reissue a full-work CPU reservation.
  Parent/task/clock and durable adoption checks remain with the only Node.
- The original typed 'PUBLIC_MUTATION_CPU_BUDGET' is a local finite-capacity
  refusal, not an invalid W1 statement or negative chainwork. The poller
  continues next finite cycle only as permitted by its typed error policy.
  Missing/unbound CPU authority is never treated as a ticket failure.

## New native controls

'peer_polling.rs' adds:
- 'pinned_peer_requires_the_existing_service_domain_before_full_work':
  create an otherwise-valid new block but refuse the replay on an unbound
  receiver; compare stats/active head unchanged.
- 'pinned_peer_false_product_spends_the_same_real_cpu_bucket_without_chainwork':
  corrupt just the claimed product of a correct signed-header-compatible
  W1 proof; the trace and winning ticket remain valid. The late Product
  rejection must leave the exact original CPU account settled without
  unknown child clocks and preserve all chain state.
- Existing pinned polling fixtures bind a single trusted local test domain
  once; this test-only helper is not called by the real network poller.
  The ordinary polling function cannot mint it.

## Outstanding blockers and evidence boundary

This is an auditable source mitigation, **not** a measured production proof:
- Compile, format and execute the exact Rust change on a complete checkout.
  The current assistant environment has no Rust toolchain or mounted
  checkout; no CI result is substituted for test execution.
- Physically verify that inbound V3 and outgoing pinned polling consume the
  same Host cgroup and local domain while adversarial unsigned/expired
  packets and a signed malicious pinned peer compete with honestly confirmed
  blocks and control reads. Include multi-process service restart and
  revocation of a pinned peer.
- The plain native CLI 'sync' and legacy authenticated paths need separate
  reachability and resource-owner examination; this patch only closes one
  unmetered callback in 'peer_polling.rs'.
- P2 actual client/GPU economic costs, P3 key/peer churn, full A03 P4,
  cryptographically complete W2 P5 and independent P6 remain OPEN.
- A pinned peer may still consume budget through **valid** W1 + bad
  application roots and may starve honest operations. Equal shared
  accounting does not by itself guarantee fair scheduling under arbitrary
  attack. No automatic admission/consensus rule or permissionless network
  activation follows.

Source status: SHADOW_ONLY / HOLD_NO_GO.


## Fail-closed original CPU settlement (follow-up)

The original pinned-peer W1/M06 operation no longer discards the typed
ServiceMutationCpuSettlement. When 'accounting_unavailable' is true, the
outbound poller returns local 'PUBLIC_MUTATION_CPU_UNAVAILABLE' instead of
reporting a successfully verified/caught-up History page. A previously
durably admitted native block remains factual; nothing is rolled back,
reverified as invalid W1 or silently charged zero. A bounded poller must
reconcile the original owner before claiming a completed sync.

This is NOT a signed public V3 outcome modification. The exact current
source requires native Rust execution and physical CPU-owner evidence before
P1 is accepted; code inspection alone is not a receipt.


## Fatality of lost original accounting (2026-10-26 addendum)

The existing `peer_polling::Engine::reject` derives whether to stop
from `Error::requires_owner_stop`. Although unknown CPU accounting
previously returned `PUBLIC_MUTATION_CPU_UNAVAILABLE`, this variant was
classified `DependencyUnavailable` and was not itself an owner-stop
condition. Subsequent peer cycles could therefore continue after an
untrusted accounting state, obscuring the initial local resource fault
and consuming network/queue resources. The source now stops pinned
polling for **local typed** `PublicMutationCpuUnavailable`,
`OwnerPublicServiceCpuDomain`,
`OwnerPublicServiceDomainUnbound` and
`OwnerPublicServiceUncleanEpoch`. An ordinary
`PublicMutationCpuBudget` (finite paid capacity) remains retryable
under the original deadline/fairness policy. A peer-supplied signed
error *string* resembling `PUBLIC_MUTATION_CPU_UNAVAILABLE`
retains `RemoteRefusal` origin and **cannot kill the owner**.

Exact Rust selectors added:
`error::tests::unavailable_original_cpu_owner_is_fatal_but_budget_and_remote_refusals_are_not`
and `peer_polling::tests::pinned_polling_stops_on_local_cpu_account_failure_but_not_remote_error_text`.
This is a **source-level fix pending exact native compilation and
physical resource failure injection**, not a new P1 pass.

## P3 pinned-source repeated false-transcript retry containment (2026-10-26)

This additional **local** peer-polling schedule control targets a separate
resource-amplification mechanism not closed by merely accounting the CPU:
a deliberately malicious *operator-pinned* remote sender can deliver different,
properly encoded false W1 transcripts at each poll cycle. The current pinned
poller accepts 10ms minimum intervals; each false Work claim is finally
rejected only after its costly complete replay. Host cgroup + original V3
bucket bound aggregate resource loss but do not prevent a single bad pinned
peer from continuously competing with other pinned peers for scarce CPU.

The new state is limited to the **existing fixed peer roster slot** (1–8
configured peers, no new authenticated identity, allocation or protocol data):
`invalid_w1_streak: u8` and `invalid_w1_retry_after: Option<Instant>`.
Only *locally produced* full-W1 `WORK:Transcript` and `WORK:Product`
errors during `native_admission` start a retry delay, with monotonic delays
250, 500, 1000, 2000, 4000 and at most 8000 milliseconds. The streak
saturates at 6, and the delay never exceeds 8 seconds for this exact peer.
A new *actually verified and admitted* W1 block clears this peer's
delay. Already admitted exact packets cannot manufacture a new valid-work
observation to wash the streak.

The scheduler skips the penalized peer before any new Head/History RPC
while other pinned peers continue under their existing finite queues,
work budgets and original rotation. It does not refund previously
charged CPU or create a new host/lane budget. Local CPU budget exhaustion
(`PUBLIC_MUTATION_CPU_BUDGET`), remote error text, disconnect, bad
StateRoot after **valid** W1, `TIME_DEFERRED`, and local account failure
have their **existing** retry/owner-stop classifications; none is
reclassified into Work invalidity or a false mathematical verdict.
The existing `PUBLIC_MUTATION_CPU_UNAVAILABLE` owner-stop rule is preserved.

Exact new Rust selectors on this branch:

- `invalid_w1_backoff_is_bounded_monotone_and_clears_only_on_new_valid_work`
  verifies 250ms first delay, 8s upper bound, saturation and clear.
- `invalid_w1_penalty_is_per_pinned_peer_and_never_triggered_by_remote_text_or_cpu_busy`
  verifies malicious native Work errors delay only that configured peer,
  while other peers continue, and spoofed remote text, real CPU shortage
  and bad StateRoot do not cause quarantine.

Additional end-to-end native negative selector:
`actual_ticket_passing_false_trace_quarantines_only_its_pinned_source`
mines one **separate legal fixture** to obtain valid header/task context,
then substitutes a freshly chosen bogus trace whose cheap W1 ticket
passes the original target. It confirms a real `WORK:Transcript` result
from the Node, unchanged active history/stats/cursor, one peer request,
and no second RPC while the original 250ms invalid-work cooldown is
active. This uses a valid fixture to construct the negative input and
is NOT misrepresented as the original four-from-zero attack producer.

This is **not** a Sybil-safe public network admission algorithm: one
honest pinned peer wrongly serving invalid material is temporarily
deprioritized, and a malicious operator controlling many independent
pinned keys/servers can distribute the attack. Reopening a polling
process resets this *scheduler-local* cooldown but cannot authorize
a fresh V3 CPU budget (original Node and physical owner rules continue
to apply). The delay also cannot stop expensive W1 work already running.

No documented target/lottery/proof validity/fork rule, request schema,
signed domain, persisted Node state, score, model or FinalUse capability
is modified. P0 source vectors, P1 physical limits and all P2–P6
independent criteria **remain unqualified** until full exact-source Rust
compilation, same-host hostile campaigns, original A03 3×3×3 and
external cryptographic review. Status: SHADOW_ONLY / HOLD_NO_GO.
