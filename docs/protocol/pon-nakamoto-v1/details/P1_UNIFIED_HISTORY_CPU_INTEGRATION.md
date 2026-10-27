# P1 unified W1 History CPU ownership: source integration, NOT production acceptance

Status: **DRAFT / SHADOW_ONLY / HOLD_NO_GO**. This integration joins two
concurrent security candidates without merging either into protected main,
widening the root Host budget, bypassing W1, changing block validation or
claiming a demonstrated permissionless cost floor.

## Exact parents and resolution

- Target source: Chain #456 head '6bc67d79e7bcc6a5a161e40e728377ae80265806',
  which already contains original #335 four-false-transcript tests and
  #339/#340/#342 W2-C research, pinned-peer W1 actual CPU charging,
  server/source-aware History guards, and low-priority peer scheduling.
- Donor source: Chain #454 head '30951e0b6976b58005d9d9cb05f45d65f7365f9f',
  built on #437 paid cold History import and strict public-V3 loopback
  Host enforcement.
- Before transplant, target blobs for 'ingress.rs', 'main.rs',
  'host_kernel_parent.rs', 'store/operator_continuous_owner.rs',
  'scripts/ci/ci_job.sh' and 'REMOTE_SYNC_W1_HOST_GUARD.md' equal exactly
  #454's source ancestor 'e55107450eb1a1f051a6c98101f3f88b7afa8f91'.
  The remaining History docs and source regression are add-only.
  These source files therefore have no edit overlap with #456's peer
  scheduling work and can retain exact donor blobs.
- Sole overlap: 'ingress/public_v3/scalar_cpu.rs' had the #456 peer
  low-priority reservation. The donor adds one
  'cold_remote_history_epoch()' method; removing its exact 478-byte
  addition from the donor file yields the exact common-ancestor bytes.
  The resulting merge preserves #456's 'begin_with_priority(true)' as well
  as the single cold original Node-scoped History constructor.

This is a source-level integration with a fresh commit/tree identity.
It is not a performed production deployment, CI qualification, completed
security audit or independent cryptographic endorsement.

## Actual change in the combined candidate

1. A standalone remote History importer obtains the existing Node-bound
   original domain, initializing exactly one zero-credit CPU epoch only when
   no live/unclean V3 or continuous owner has already claimed it. The durable
   active V3 marker blocks an unclean-restart reset. There is never a
   per-source, per-signature, per-page or per-proof CPU bucket.
2. All remote History work is charged: canonical bytes/packet header parsing,
   complete W1 replay with cooperative cancellation, M06 and real scoped
   worker execution, and final tip activation. The original Node and the
   original Host cgroup remain the only authorities.
3. Explicit public V3 History import always requires the fixed,
   administrator-provisioned cgroup **even when the peer address is loopback**.
   A 127.0.0.1 relay is not proof of local trust.
4. The already-existing peer low-priority CPU start rule now applies to
   *all* remote History import operations as well. The beginning of a remote
   import must leave the original two ordinary start quanta available, and
   no second background History operation can start concurrently within the
   same CPU domain. Real CPU remains charged even if the operation overshoots
   its start reservation; this is a bounded scheduling preference, NOT
   immunity to infinite attack or a new budget.
5. W1 and M06 check original Host membership and finite limits before,
   during and after expensive work at bounded checkpoints. If a Host fault
   occurs after a durable native outcome, it makes the sync incomplete
   without rewriting that outcome as invalid chainwork.
6. An inherited source-integrity test was stale after #454's changed Rust
   signatures. The candidate replaces that test with exact combined-source
   ownership checks for private History parser, low-priority domain, cold
   Node startup, bounded Host/W1/M06 callbacks, public loopback and native
   negative fixtures. Deliberately reverting one guard now fails the test.

## Remaining acceptance blockers

- This source was assembled through GitHub connector reads/writes and checked
  with twelve-plus exact-source string/byte invariants. The current sandbox
  has no Rust compiler and cannot fetch the complete repository over GitHub
  DNS, so 'project-preflight.sh', rustfmt, cargo, real native tests and
  clean-room replay on the exact resulting tree were **NOT RUN**.
- A real administrator must place all participating processes and spawned
  worker threads in one fixed CPU/memory/PID-capped cgroup. Capture kernel
  counters and prove inheritance through process restart, source relay,
  overload, cancel/crash and original durable state.
- A request can still exceed a start reservation between checkpoints, and
  shared-CPU accounting cannot prove that malicious sources fund every
  verifier cycle. Honest Node lock/contention fairness under a valid-work
  bad-StateRoot flood is not qualified.
- V3 Cookie CPU/GPU/ASIC pricing, P3 mixed real attacks, P4's preregistered
  original A03 three modes x three runs x 3/3 on-time confirmations,
  a sound/efficient W2 proof and independent P6 cryptanalysis remain OPEN.
- Cryptographic, authorization, public readiness and production activation
  flags must stay false. None of these mitigations changes 'PNW1', ticket,
  required target, cumulative work or old historical consensus validity.

This is additive **candidate hardening**; do not mark ready, merge protected
main or count a shaped internal report as independent physical evidence.
