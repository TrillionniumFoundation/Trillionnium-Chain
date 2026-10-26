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


## Follow-up: each imported History packet charges the original CPU domain

**Draft engineering follow-up, not accepted or production-ready.** The prior
host-cgroup-only guard bounds aggregate CPU but does not consume the V3 shared
per-Node CPU account. This new candidate changes that source behavior while
leaving the original W1 consensus and admission semantics unchanged.

- 'ingress::prepare_history_cpu_domain(node, source)' verifies the original
  fixed physical host parent and binds a SINGLE existing Node service domain.
  A new **nonloopback** Node starts through the original 'cold_start' with
  zero CPU credit. Loopback developer sync uses only the historical bounded
  warm standalone developer epoch. No additional budget per remote peer,
  page, protocol request or rotated signing identity is allowed.
- 'receive_page_from' now requires the Node to be prepared even on
  loopback. An unprepared call returns
  'OWNER_PUBLIC_SERVICE_DOMAIN_UNBOUND' before page data is parsed or
  full W1 begins. The original addressless reader remains private.
  The public CLI and all three native sync_from variants prepare once before
  requesting any History pages.
- 'admit_history_packet_with_cpu' preserves the exact original Node::admit
  authority sequence: check_admission_context, begin_owner_work,
  WorkCheckedPacket::verify_with_progress, attach_owner_work and
  admit_work_checked_with_control. ONE original CPU operation covers context,
  full W1 arithmetic and real M06 scoped workers, with original cooperative
  progress checkpoints. Complete invalid W1 earns zero Chainwork.
- Operations reserve before parent State reconstruction. If the original
  cold domain lacks its existing 100ms start reserve, wait at most 1500ms for
  the ordinary 250ms CPU per second refill; return the original typed local
  PUBLIC_MUTATION_CPU_BUDGET if it cannot acquire. No new credit, queue,
  per-peer priority, signed profile or difficulty change.
- History tip activation receives a separate original-domain CPU operation.
  Unknown accounting returns local PUBLIC_MUTATION_CPU_UNAVAILABLE. Native
  commits already performed are never reclassified as unexecuted work and
  cannot be silently rolled back on a late resource fault.

The new source has two Rust test selectors:
'history_receive_requires_one_existing_cpu_owner_and_charges_late_false_product'
and 'history_remote_cold_budget_starts_at_zero_and_cannot_be_reissued_per_peer'.
The Product counterexample retains legal challenge, target, A/B and trace,
changes only the claimed C, and requires a complete mathematical refusal,
zero live permits and unchanged Node stats/active head.

**OPEN blockers:** The full exact-source Rust checkout, Cargo, fmt,
preflight, strict Clippy, real fixed parent cgroup and original A03 3x3x3
hostile network experiment have NOT been executed in the current tool
environment. Per-packet W1 cost accounting does not prove that hostile
read/JSON/authentication traffic is fairly scheduled; deep nonpreemptible
State/SQLite operations and loopback proxies are still resource surfaces.
If a process forwards untrusted WAN pages over loopback, caller-supplied
source addresses cannot attest remote origin, despite in-process W1 CPU
metering. Process restarts still need the original aggregate kernel cgroup
and continuous owner reconciliation for durable debt.

P2 GPU/ASIC attacker prices, P3 mixed hostile traffic, P4 3x3x3 timely
honest confirmation, P5 sound/efficient W2 and P6 independent external
cryptography review all remain HOLD_NO_GO. Do not activate consensus.
