# P1: Remote History sync must enter original fixed Host resource parent

**Draft security mitigation only.** Source baseline:
'db0dad68f0909460e8b1cf0c248d8bab4b59c129'.
No W1 byte change, no consensus target adjustment, no chainwork, Genesis,
Cookie, Final-use, Node authority or production flag change.

## Exploit and former gap

Remote source can send complete 49,188-byte W1 proof bytes inside History
pages. Native 'ingress::receive_page' checks bounded JSON/page structure,
then calls 'node.admit(packet, clock)' for up to 16 packets per page.
Three source functions 'sync_from', 'sync_from_authenticated', and
'sync_from_authenticated_durable' can request up to 4096 pages. The CLI 'sync'
public-V3 branch calls 'receive_page' directly. All are **operator-initiated
outbound** retrieval paths; authentication only identifies the remote peer.
Before this candidate they did **not** require an original host kernel
budget before repeated expensive W1 validation. Bounded page counts do not
establish a host-wide CPU budget or honest-service fairness.

## Implemented original ownership

- All three native sync variants call the existing
  'host_kernel_parent::require_for_listener(address)' **before connecting**.
  The same administrator-provisioned fixed 'trnmponpublic.slice' parent as
  public V3 is required for nonloopback destination addresses; loopback-only
  development retains the original unprivileged path.
- Before each remote page and after all native verification/admission of that
  page, check the same root-owned cgroup identity, current *calling-thread*
  membership, CPU/memory/PID caps, boot marker, limits and context through
  the original 'KernelBudget::verify'. No new account is minted per peer,
  client identity, process or sync invocation.
- The CLI 'sync' calls the same checker at branch entry; its public V3 page
  loop also performs before/after checks. The ordinary direct and authenticated
  branches are covered by their above native sync function checks.
- The already accepted native block is a durable fact. If a post-page cgroup
  verification fails, the sync returns an operational error with no claim of
  successful complete sync, **not** a chain-invalid or automatic rollback.
  Authentication/cookie/status remains separate from mathematical work.
- Negative Rust selector
  'ingress::tests::remote_sync_without_original_host_cgroup_rejects_before_any_network_or_w1'
  covers raw, authenticated and durable sync using a documentation-network
  destination. On a host without the admin-installed parent, all three fail
  with the same original typed host-policy error and no Node mutation. On an
  actual eligible parent the host checker itself verifies membership; real
  native paid WAN load must be run separately.

## Important limits / remaining P0–P6 blockers

1. This is a **kernel aggregate cap**, not per-remote-source admission price,
   not full honest-fair scheduling and not a substitute for V3 actual request
   CPU accounting. Repeated real W1 validation can still starve other work
   within a finite cgroup.
2. A local process can relay a remote hostile source over loopback; the
   destination-address check alone cannot detect that proxy. Untrusted
   loopback relays must share the same physical host owner and guarded sync
   mode by explicit deployment contract. Direct public use of addressless
   'receive_page' by another embedding application also needs an enforced
   caller-owner contract; this candidate does not change its public API.
3. Exact committed Rust toolchain build, original preflight, native failure
   tests, physical cgroup readback, multiple processes, crash-restarts,
   cancellation, mixed honest requests, source SHA capture and independent
   operators have not been produced by this candidate in the current tool
   environment. It is not accepted or merge-ready.
4. P2 signed Cookie CPU/GPU price, P3 rotating identities+wrong StateRoot+
   sustained mixed service, original A03 3 modes × 3 runs × 3 timely honest
   confirmations, mathematically sound/efficient W2 proof and independent P6
   cryptographic third-party review are all separate **OPEN** gates.

Status: SHADOW_ONLY / HOLD_NO_GO. Production activation stays disabled.


## Subsequent API-boundary remediation

A second P1 pass found that guarding the three sync callers was insufficient:
the previously public five-argument 'ingress::receive_page' had **no peer
locator or kernel-owner parameter**, allowing an embedding application to
bypass the native sync entrypoint checks.

The previous addressless page parser is now **module private**, and its
only public history-page import replacement is:

    ingress::receive_page_from(node, configured_source_address, page,
                                tip, after, observed_clock)

The new exported function checks the **same fixed Host kernel parent**
through 'require_for_listener(configured_source_address)' immediately
before and after invoking the private exact native import. The ordinary,
authenticated and durable sync variants and the CLI V3 public-sync branch
all call this checked function. The negative remote-sync test also passes
an invalid Page into the exported guarded API and requires the Host
policy refusal **before any Page parsing or expensive proof check**.
No decoded Page, signed Peer response or missing local clock is a
'VerifiedWork' authority.

The explicit 'configured_source_address' is a **caller-supplied routing
context**, not cryptographic proof of the true historical origin. A
loopback proxy/tunnel can still relay hostile WAN bytes without changing
the configured address. Only an administrator-approved deployment
policy with the real physical host and transport boundary can close
this residual; neither the new wrapper nor 'ip.is_loopback()' prove
peer location. A malicious host operator can always submit local bytes
to Node, so the resource containment and public-network threat model
must be tested separately.

The new unexported parser remains useful for unit coverage and does
not expose a second public unchecked history-import symbol.
This is an API-path reduction, **not** a production/security gate PASS.


## P1 continuation: meter each History W1/M06 inside one original CPU owner

The prior cgroup and exported API guard bounded the **host aggregate**, but
the private receive_page still called Node::admit without its per-request
CPU account for each remotely supplied proof. Cgroup enforcement alone could
leave another trusted operation starved by a malicious remote source.

New candidate scope (child of the last committed #342 head):

1. ServiceMutationCpuDomain::cold_remote_sync_epoch uses the same original
   PaidMutationCpuBudget::cold_start(): **zero initial credit**, no synthetic
   warm two-second grant. The only refill and reservation are the unchanged
   250M CPU-ns/wall-second shared budget, 100M CPU-ns start quantum and at
   most two in-flight workers. This factory is crate-private and the Node
   owner binds its result once, only after original source-dependent Host
   kernel eligibility/membership checks. Existing V3 or continuous owners
   take precedence: **no per-page/peer/caller reset**.
2. Every decoded History packet begins one bounded, budgeted original
   ServiceMutationCpuOperation before potentially expensive parent/State
   inspection. It repeats Node::admit's exact progression:
   current context/exact-block → owner permit → complete W1 proof with
   cooperative live CPU checkpoints → verified packet rebind → native
   M06 execution with the same operation's scoped-worker accounting.
   The signed remote page does not provide proof authority.
3. The operation always settles after the native result, including incorrect
   transcripts/products, cancellation and bad execution roots. An unknown
   clock or failed settlement makes the sync result unqualified and fences
   later CPU operations, but **cannot undo an already durable block**.
4. A cold start may wait at most five seconds to acquire an original start
   quantum through original refill; there is no new grant or altered consensus
   TTL. Insufficient credit remains local PUBLIC_MUTATION_CPU_BUDGET, not an
   invalid W1 verdict. Individual deep stages remain cooperative rather than
   hard-preemptible.
5. A source claiming loopback still pays this original Node-local account.
   A local TCP tunnel can lie about true origin and bypass the nonloopback
   cgroup requirement; it cannot thereby skip this local CPU charge.
6. A native Rust test imports **two distinct canonical wrong-C claims** under
   one valid transcript/header/target and expects late WORK:Product refusal
   and no State/chainwork change. It checks the same cold initial credit zero,
   positive measured total CPU, zero outstanding reservations and balance
   conservation. A subsequent valid packet must still be accepted through
   the exact same CPU owner.

**Qualification still OPEN:** exact-head Rust compilation and project preflight
are unavailable in the current assistant environment; no physical cgroup
throttle/readback or signed independent WAN A03 campaign was run. The existing
source locator is not cryptographic proof of remote identity. Cross-process
and loopback-proxy policy require physical deployment evidence. A03 three
modes × three runs × three timely confirmations, fair queue service, calibrated
attacker CPU/GPU costs, actual mathematically sound and efficient W2 proof,
and independent cryptography review remain mandatory. HOLD_NO_GO.
