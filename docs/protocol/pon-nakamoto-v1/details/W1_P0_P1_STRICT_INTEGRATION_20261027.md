# P0–P1 exact integration preview: W1 negatives and Host-bound history
Status: **draft / shadow-only / HOLD_NO_GO**. No PNW1 byte, target, ticket, fork-weight,
FinalUse, model installation, V3 Cookie, genesis, or production flag modification.

## Frozen input owners and retained failures
- Source parent: Chain PR #484, commit `288e6a7f12770aec44f6449b0330c917b1d382bd`. This already incorporates
  #340 (pinned-peer shared CPU), #342 (nonloopback History guard), and #483
  (durable single-host W2-C spent tickets with a copied-DB double-spend counterexample).
- P0: transplant the exact corrected four-false-transcript Python test blob
  `534854e1341c9613e30b965123710891295a9de8` from PR #461.
  The parent #484 had a literal unterminated `assertRaisesRegex` string.
  The original negative vectors, nonce/trial counts, W1 relation and timing scope
  are unchanged. This repair **enables** the test; it is not evidence that
  a native Rust campaign ran.
- P1: preserve #479 strict paid public/authenticated History request context
  and #480 explicit fixed Host parent for V3 loopback listeners with remote
  pinned-peer polling. Plain loopback-only local developer serving without
  external history remains distinct.
- P1 external API: `ingress::receive_page_from` is now crate-private.
  It deliberately retains the old loopback-only developer compatibility.
  The sole public History page import is `receive_public_page_from`,
  requiring the original admin-provisioned
  `/sys/fs/cgroup/trnmponpublic.slice` even if the caller's socket address
  is loopback (a TCP proxy is not source provenance).
  A compile-fail rustdoc rejects importing the weak symbol from an external crate.
- P1 full W1 replay: the existing Native Node remains sole authority.
  `admit_with_work_progress` preserves `Node::admit`'s task,
  owner, parent, and durable checks while allowing a *local* resource callback;
  no new work primitive or arithmetic-cache acceptance is created.
  Import checks actual Host membership/limits before and after each of up to
  16 received packets, before and after activation, and during W1 at
  BeforeReplay, BeforeProduct, BeforeVerifiedWork, bounded noise/row and
  every 64 transcript tiles. Raw cgroup `cpu.max` remains enforced by the
  kernel between reads. An already committed native block is not turned
  into invalid W1 after a local post-admission resource fault.

## Focused source/test selectors (not yet qualified in this session)
- `python3 formal/pon-nakamoto-v1/test_work_precheck.py -v`
- `cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node
  kernel_progress_rechecks_original_host_at_most_every_64_tiles -- --exact`
- `cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node
  public_loopback_history_requires_real_fixed_host_parent`
- `cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --doc`
- Existing remote History / pinned-peer CPU integration tests and actual
  host-owned A03 work all remain mandatory. First run project preflight
  in a real checkout as required by repository AGENTS.md.

## Invariants and remaining blockers
The preview has never minted `VerifiedWork` from a ticket or local cache:
P0 four forged transcripts must continue to fail `TRANSCRIPT`, adding
zero state/chainwork. P1 Host/calling-thread guards do **not** replace
per-caller economics, cross-process CPU accounting, isolation of durable
external effects, or honest fairness under an unbounded identity flood.

P0 still needs exact-head native source/binary/CPU and historical raw evidence;
P1 needs physically independent cgroup and proxy attack runs;
P2 needs measured signed-cookie honest CPU/GPU/ASIC and attacker costs;
P3 needs mixed identity/key churn, false-StateRoot, recovery and honest clients;
P4 needs A03's 3 hostile modes × 3 repetitions × 3/3 timely confirmed honest
rounds **per repetition**, retaining every Busy/timeout/negative sample;
P5 needs a computationally sound, economical full W2 proof (not W2-A sampling,
W2-B full replay or unpriced W2-C); P6 requires actual independent
cryptographic authorship, verification and signed source-bound review.
The sender cannot certify independent reviewers or run physical WAN
experiments merely by adding source tests. No protocol activation is authorized.

## Follow-up: valid W1 still needs Host checks through M06 and SQLite

At #488 original source `7d7fd9f242830f718b9c4ff81d2796b360a0d2e3`,
History page import checked the physical Host at W1 entry, every 64
transcript tiles and after each native packet. But
`Node::admit_with_work_progress` switched to the original **no-progress**
`admit_work_checked` once W1 succeeded. A *valid* W1 packet carrying
costly application work could cross a Host membership/quota change during
M06, state-root generation or SQLite admission without intermediate checks.

The candidate keeps exactly the same `KernelBudget::verify` callback through
both the original W1 `VerificationProgress` and the existing
`admit_work_checked_with_progress` / `ExecutionProgress`. This includes
BeforeParentBinding, M06 prepare/apply, BeforePersistence, SQLite deltas
and BeforeDurableCommit. A precommit local Host failure must roll back
the native transaction; after-commit Host failures make the overall import
unqualified but **never** turn durable success into invalid W1.

New Rust regression
`history_valid_w1_cannot_commit_after_m06_host_owner_rejection` uses a
full legitimate W1 proof (512 tiles), injects Host-limits failure at actual
BeforeDurableCommit, asserts no retained block/active change and accepts
an independent subsequent legitimate retry. The parallel regression
`host_owner_failure_during_w1_tile_does_not_commit_or_poison_retry`
from #488 is retained and adapted to the new two-callback API rather
than being overwritten.

Source is draft/unqualified until real `scripts/project-preflight.sh`,
exact Rust build/fmt/clippy, native negative selector, physical host resource
ownership and A03 service campaigns execute successfully. The unchanged
W1 proof/target/ticket/Chainwork, signed Cookie and production activation
grant no new authority. All P1–P6 remaining independent gates remain OPEN.
