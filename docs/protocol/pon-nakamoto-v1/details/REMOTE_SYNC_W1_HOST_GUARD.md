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


## Per-packet Host owner fence (2026-10-26 candidate)

An additional source pass identified that the already protected exported
'receive_page_from' checked the physical cgroup before and after a **whole
History page**. The exact page grammar permits up to sixteen individual W1
proofs. A source-bound but untrustworthy peer could thus demand sixteen
expensive proofs between physical-owner/membership checks. The Host's own
kernel cgroup still throttles aggregate CPU, but relocation or quota
violations noticed only at page boundaries are too coarse.

The private 'receive_page' now has a mandatory in-process progress callback.
Its sole externally reachable caller, 'receive_page_from', supplies a
closure that rechecks the existing administrator-provisioned HostKernelBudget.
Each admitted packet is bracketed by this callback:
'check -> node.admit(packet, clock) -> check'. The callback does not
replace the original native verifier or change consensus validity, and it
does not mint CPU credit. The existing early public API guard still runs
before decoding an untrusted page. No additional public no-callback import
endpoint was introduced.

The native regression
'ingress::tests::history_page_checks_original_owner_between_valid_w1_packets'
constructs two real legitimate W1 packets on one frozen development chain,
then injects an owner-lost error at the **third** checkpoint (before the
second packet). It checks that the first packet remains exactly admitted,
the second is absent, the active head remains unchanged and cold-reopen
retains that fact. A subsequent full retry permits both originals to be
checked and activates the original intended tip; four packet-level checks
must have been executed, not one check for the whole batch.

This is local deterministic failure-injection coverage, not evidence of
actual Linux cgroup migration, W1 GPU adversaries, real timeouts or
cross-process budget fairness. A single deeply nonpreemptible W1/SQLite
stage can still run between two checks; the fixed kernel continues to be
the host resource owner. The loopback-relay issue remains an explicit
open operator-deployment P1 threat. All P2–P6 qualification requirements
and production HOLD_NO_GO flags remain unchanged.


## Bounded cooperative Host checks inside real W1 replay

The next source-only P1 candidate extends the existing per-packet guard without
adding any new CPU allowance or changing the immutable W1 relation. An
untrusted History packet is now sent through the Node's private
'admit_with_verification_progress' (not through a second work verifier).
This uses the existing owner-context check, original task-operation permit,
'WorkCheckedPacket::verify_with_progress', exact native attachment and
'admit_work_checked' to preserve the original admission/ledger semantics.

The original external 'receive_page_from' remains the only exported source-bound
History import. It still checks the fixed root-owned HostKernelBudget before
parsing and after importing a page. Its private page implementation also checks
before and after each packet. Inside W1 it additionally asks the **same** budget
for checks at a fixed, bounded subset of existing progress events:

- BeforeReplay, BeforeProduct and BeforeVerifiedWork;
- the first noise hash of each of the four challenge labels;
- matrix rows 0, 16, 32, 48, where those rows exist;
- **8 of 512** transcript tiles: exactly column 0, inner 0 in each of the
  eight distinct block-row groups.

This avoids the avoidable per-tile Linux cgroup read amplification of
checking all 512 transcript tiles. The actual complete W1 arithmetic still
runs and authenticates its entire transcript and product; an early
resource-cancellation is a **local operational error**, not an invalid
consensus proof or a false 'VerifiedWork' capability.

Added exact Rust negative selectors:
- 'history_page_checks_original_owner_between_valid_w1_packets': real two
  W1 block History page; force a checkpoint failure just before the second
  packet; first stored block stays intact while second is absent, active head
  is still old, cold reopen retains correct partial state, then full
  resumption yields the original intended tip;
- 'hostile_host_owner_loss_during_w1_replay_leaves_no_verified_block':
  cancel a genuine W1 replay on its first selected transcript tile.
  The original block must remain unadmitted with unchanged state;
- 'w1_history_kernel_checkpoints_are_bounded_and_cover_each_tile_row_group':
  deterministic check counts: 4/512 noise-epoch labels, 8/512 transcript
  tiles and only named matrix rows, plus all three authority boundaries.

These are source-level *tests to be executed* on the exact committed Rust
checkout, not attestations of native test success in this chat. Every
high-cost nonpreemptible parent-State/SQLite stage still needs separate
physical duration/resource measurement and a full Host cgroup envelope.
The selected checkpoints must be calibrated with actual sysfs overhead
and worst-case cancellation latency; no economic-hardness, honest-fairness,
WAN or A03 P4 result is claimed. Loopback forwarding, all native/sync
caller budgets, P2 GPU/ASIC cost, P3 mixed traffic, P5 sound succinct work
and independent P6 review remain HOLD_NO_GO.


## Native M06 / precommit Host ownership continuation

The W1 cooperative checkpoint is not enough if the verified History block
then enters M06 State execution while its original physical CPU owner has
become unavailable. The guarded-only crate-local Node method
'admit_with_verification_progress' now requires a SECOND, independent
'ExecutionProgress' callback with the existing 'Fn + Sync' executor contract.
Its final stage calls 'admit_work_checked_with_progress' instead of the
no-checkpoint 'admit_work_checked'. The earlier W1 path remains the same
full verifier; consensus acceptance, task, header, work ticket, historical
state, durable database ownership and rollback semantics are unchanged.

The sole exported 'receive_page_from' wires both callbacks to the
**same fixed HostKernelBudget**:
- sparse, bounded 'VerificationProgress' cgroup checks inside W1;
- complete M06 ExecutionProgress checkpoints on the existing native
  execution path, including its pre-parent/precommit fences;
- already preserved pre/post packet checks and the outer page checks.

The native test
'history_import_loses_host_owner_after_valid_w1_before_m06_commit'
creates an actual fully valid W1 packet, observes
'VerificationProgress::BeforeVerifiedWork', then has the Host
ExecutionProgress callback fail. It requires no accepted block, no active
head movement, no metadata/stat change and identical cold-reopen state.
This is not simulated acceptance: the native verifier runs normally and
the injected failure is at the subsequent operational resource boundary.

Uninterruptible filesystem, SQLite or long single-stage State work still
needs target machine measurements and the root-owned kernel aggregate
limits; this cooperative callback is not a hard CPU/time preemption or a
general fairness guarantee. Unknown accounting cannot be relabelled as
WORK:Transcript, Product, or consensus-invalid chainwork. A previously
committed native result is not undone if its later physical resource
observation fails. No deployment or P0–P6 gate is promoted by these
source-only tests until exact source/binary and physical acceptance.
