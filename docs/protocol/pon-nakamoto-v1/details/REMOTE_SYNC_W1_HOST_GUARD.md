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

## Public loopback-proxy hardening and per-proof host checkpoints (P1 continuation)

The previous public `receive_page_from` was source-address-bound but still
allowed an **unmetered loopback exemption**, since `require_for_listener`
returns no required cgroup for a `127.0.0.1` endpoint. An operator or
untrusted local proxy can redirect externally supplied W1 certificates onto
that loopback endpoint without changing their mathematical contents.
The public destination string is **not** origin authentication.

The new public `ingress::receive_page_from` always requires the **same**
`FIXED_PUBLIC_KERNEL_PARENT` via
`require_host_kernel_budget(source, Some(FIXED_PUBLIC_KERNEL_PARENT))`,
including for loopback. If the original administrator-owned parent is
unavailable, public History pages are rejected **before** Page parsing or
full W1 replay. This is an explicit compatibility/security tightening:
a public V3 CLI syncing from a loopback address now also needs the fixed
cgroup. It cannot silently fall back to an unpriced public admission path.

Three pre-existing native `sync_from*` routines instead use the separate
**module-private** `receive_page_from_local_development`. Its local-loopback
historical test/development behavior remains unchanged; a nonloopback native
destination still must join the fixed parent. This private path is neither a
public imported-verification API nor evidence that an untrusted loopback
relay is economically safe. The caller and local deployment remain
explicitly trusted for that limited development profile.

The previous page-level budget guard also had a coarse granularity:
a legal History page may hold **16 separate full W1 proof replays**. An
administrator changing the cgroup context after the page starts might leave
additional expensive replays unchecked until the entire page completed.
The original `receive_page` parsing/admission logic is now performed by a
single private `receive_page_with_checkpoint` loop. Hardened public pages
check the **same actual Host owner before and after every W1 replay**, and
before/after final activation. The private developer path applies the
same per-W1 checks whenever its destination already required the fixed
parent; its unprivileged, deliberately trusted loopback use keeps the
original no-cgroup behavior. The source does **not** create a new owner,
rewrite W1 work or change the target/fork choice.

New native counterexamples in `ingress.rs`:

- `untrusted_public_history_rejects_loopback_proxies_without_original_host_owner`:
  public loopback cannot skip the same original fixed parent even when the
  legacy private test caller can parse and refuse an invalid Page normally.
  No Node state or chainwork changes on refusal.
- `history_multi_packet_budget_checkpoint_is_per_w1_and_preserves_retryable_native_facts`:
  two valid W1 blocks in one History page; simulated original Host-owner
  failure **after** first durable admission rejects the sync without
  inventing a bad W1 verdict or rewinding the existing block. Cold-reopen
  replay must complete with two per-work before/after checks plus two
  activation checks, and select the actual second block.

These are **source-level negative regression definitions, not completed
native runs** in this tool environment. There is no independent physical
Host cgroup readback, Rust compile, original A03 mixed valid/false-TRACE/
false-StateRoot WAN qualification, GPU/ASIC pricing, mathematical W2 proof,
or P6 independent external cryptanalysis. All these remain OPEN.
The only permitted status is HOLD_NO_GO; production activation stays off.
