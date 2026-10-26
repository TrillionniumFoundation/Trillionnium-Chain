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

## P1 follow-up: parent-context CPU must be reserved first

Additional child branch starting from parent #340 head
`563a8c982106dc38880f4a8cbaf37f4f89fa9cb4`.
This patch moves the **one existing** `ServiceMutationCpuOperation::begin`
ahead of `check_admission_context_with_progress` in
`peer_polling.rs::admit_page`. The original code selected the correct
shared domain first but reconstructed parent context before reservation.
The new operation covers parent State materialization, task/ancestry checks,
an exact stored duplicate, full W1 replay, and eventual M06 admission
execution, with its original progress/deadline/live CPU checkpoints.

A new Linux test first admits a genuine native block locally, then binds
a **zero-credit original cold service domain** and attempts both the exact
stored duplicate and a distinct invalid-header packet. Each must refuse
`PUBLIC_MUTATION_CPU_BUDGET` *before* parent State or proof replay; active
tip, stats and CPU inflight stay unchanged. Old late Product rejection and
unbound-domain cases remain in the parent PR. This is a source-level
security regression; exact Rust compilation, formatting and real host
resource evidence have not been performed in this assistant container.

This tradeoff deliberately charges an exact duplicate's bounded context
lookup too. Verified/active historical state is not declared invalid on
local CPU starvation. It can be retried when the **same** original CPU domain
has genuine available credit. No new token bucket, epoch, Work relation,
Chainwork or consensus-invalid error is created.

P1 still requires physical process/cgroup proof, hostile real-page and
honest mixed-traffic experiments. P2–P6 retain their separate gates.
