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


## P1 integrated original-owner checkpoint refinement (2026-10-26)

The unified source child PR includes both:
- pinned-peer original V3 mutation CPU accounting (from #340);
- all remote History sync root-cgroup containment (from #342).

The retained native 'receive_page_from' now forwards a local physical-owner
checkpoint into the **original Node::admit sequence** through
'Node::admit_with_work_progress'. This helper preserves ordinary
'check_admission_context', 'begin_owner_work', the private verified packet
construction, 'attach_owner_work' and 'admit_work_checked'. It does **not**
create an alternate verifier, allow unchecked work or invent Chainwork.

All up to 16 W1 statements on a received page require a physical-owner
check before and after their native admission, and the W1 verifier supports
additional checks at deterministic points during expensive arithmetic.
The parent cgroup is enforced continuously by the kernel. The userspace
resource identity check additionally observes task/host membership at
'BeforeReplay', 'BeforeProduct', 'BeforeVerifiedWork', every 32 noise
hash counters, every 32 output matrix rows, and each of the eight outer
transcript tile rows. Within the 512-tile transcript, no more than 64
tile updates can pass without checking the original resource owner's
membership/limits. Checking on all 512 callbacks would itself impose a
large attacker-driven cgroup syscall cost; the 64-tile source bound is
tested explicitly, not a claim of a measured p99 or physical preemption.

The native negative controls deliberately inject:
- a failed physical ownership check before any W1 replay;
- a failure at the first selected transcript tile, distinct from the
  arithmetic Transcript error, with unchanged Node stats and chainwork;
- a failed check after genuine W1 validation and durable native admission,
  which withholds complete sync status but does not roll back the accepted
  immutable block.

The last control reflects a fundamental operational distinction:
**local CPU/cgroup failure is not mathematical consensus invalidity**.
Indivisible state/root/SQLite and OS schedule boundaries still require
dedicated physical fault campaigns. The original exact-head preflight,
build, Rust native test execution, actual cgroup capture, WAN independent
operators, A03 3x3x3 campaign, GPU/ASIC calibration, succinct W2 proof and
independent cryptanalysis remain unqualified; the tests are source-defined,
not asserted to have passed in this assistant's runtime.

## P1 integrated API visibility hardening: public loopback proxy cannot select weak import

The unified candidate had already added strict
`ingress::receive_public_page_from` with the same mandatory fixed Host parent
for all sources, including `127.0.0.1`, and changed the public V3 CLI to use
that hardened function. It also retained a **second externally callable**
`pub fn ingress::receive_page_from`, however, whose trusted-local
`require_for_listener(source)` path waives the cgroup check on loopback.
An embedding library could choose that weaker symbol and submit adversarial
WAN certificates through a local relay, bypassing the strict public path.

The code now changes that legacy symbol to **`pub(crate)` only**, retaining
its three original module-local native sync call sites and their explicit
development loopback compatibility. The *only* exported History page import
symbol intended for arbitrary caller-supplied untrusted public bytes is
`receive_public_page_from`, which forces
`FIXED_PUBLIC_KERNEL_PARENT` even when the supplied address is loopback.
A rustdoc `compile_fail` vector asserts an independent crate cannot import
the old weak entry. The genuine W1 native validation and per-W1 original
kernel checkpoint logic remain unchanged.

This fixes a public API reachability ambiguity, **not** the fundamental
actor-cost lower bound, malicious local operator issue, synthetic loopback
relay via an explicitly trusted native development CLI, or independent
physical-host resource/fairness qualification. Rustdoc and actual native
compilation are still outstanding in the current source-only environment;
retain the failed/unknown status if either check is missing.

## P1 two-work replay/recovery negative (integrated candidate)

A new `ingress::tests::two_history_w1s_preserve_original_first_commit_across_owner_fault_and_cold_retry`
asserts the original Host's physical-ownership checkpoint remains effective
across two separate valid W1 proofs in a **single** History page. The test
does not use a fabricated W1 result or a new consensus transition:
it mines two legal packets against the exact parent chain, counts the
original verifier's selected Host rechecks, and injects one local cgroup
failure immediately **after** durable admission of the first block.
That failure must withhold page completion, keep the first block durably
available, prevent running the second W1, and leave the active head at
Genesis. An actual cold reopen then retries identical bytes using the
same original native admission rules: the already stored first packet
is not new work, the second W1 remains mandatory, and only after the
full successful page does the active head reach its real second block.
The after-commit fault is **not** a consensus-Invalid or automatic
rollback. Exact Rust and physical ownership execution still must be
recorded separately; this source-level test cannot close P1/P4 alone.
