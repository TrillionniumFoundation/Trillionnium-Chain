# W1 exact negative singleflight: bounded concurrent-replay research

**Status: DRAFT, optional/off by default, not production qualification.**
Starts from pinned Chain #335 source
'db0dad68f0909460e8b1cf0c248d8bab4b59c129'. No W1 proof wire,
task, ticket, target, chainwork, fork choice, V3 policy digest, new scheduler
or consensus authority is changed.

## Previously exploitable resource duplication

The existing optional 'pon_work::rejection_cache::RejectionCache' memoized
an exact complete \`TRANSCRIPT\` or \`PRODUCT\` failure for a bounded period,
but it checked the cache and then released its lock **before full replay**.
Twelve distinct connections could therefore submit the **same** false W1
packet concurrently while the entry was empty and all twelve could enter
a 512-tile replay before the first failure inserted an invalid fact.
The final cache entry was correct, but simultaneous CPU amplification
remained. Key rotation could bypass per-peer client controls.

## One mathematical leader, no shared verdict authority

The updated implementation retains original optional activation and
1..256 direct-mapped slots, 1..30-second invalid fact lifetime, complete
context+proof hash key and the untouched full W1 verifier. It replaces
the cache-wide lock with a small independent Mutex+Condvar per slot:

- On the first new exact statement a leader marks 'Computing(key)' under
  the slot lock, releases the lock and runs the original full verifier.
- Concurrent **identical** statements wait in 5ms cancellable polls,
  using each caller's original callback/deadline. Only a fully completed,
  deterministic mathematical 'Transcript' or 'Product' refusal may publish
  a short-lived negative fact. Waiting callers receive only that same
  invalid relation; no VerifiedWork is constructed.
- Leader cancellation, cheap errors, successful W1 verification or panic
  cannot publish a negative verdict. RAII drop frees the computing marker
  and wakes waiters; a waiter then independently retries full work.
- **Different** statements that happen to hash into one finite slot
  bypass the cache and run the original verifier without waiting for
  an attacker's computation. This intentionally sacrifices caching for
  unrelated proofs to preserve their progress.
- A poisoned *optional* cache lock fails open to **complete mathematical
  validation**, not to successful block or work authority. Public V3
  already owns the actual CPU reservation for every submitted request,
  including a waiter or a full-cache bypass.
- Four **different** from-zero traces each still require initial full
  replay. Exact retransmission coalescing is not neural-work hardness,
  anonymous fairness or an anti-Sybil admission price.

The optional cache adds local, bounded counters
'started_replays', 'exact_hits', 'wait_polls' and
'collision_bypasses'. Counters are research telemetry only, not chainwork.
A single local service account and bounded ingress pool still own CPU,
connections, cancellation and throughput. This cache owns none of them.

## Exact negative regressions

The existing original tests remain unchanged. Additional tests in
'trillionnium/crates/trnm-crypto-primitives/src/pon_work/rejection_cache.rs':

1. 'twelve_concurrent_exact_false_traces_require_only_one_full_w1_replay':
   an actual leader blocks at its first tile; 12 independent concurrent
   callers enter cache waits, then complete only after the leader publishes
   the real 'Transcript' error. Require exactly one started full replay,
   all 12 exact hits and zero minted VerifiedWork.
2. 'leader_cancellation_does_not_publish_invalidity_or_strand_next_waiter':
   a cancelled leader publishes no false negative; a subsequent independent
   caller must replay all 512 tiles and return 'Transcript'.
3. 'unrelated_hash_slot_collision_does_not_block_behind_false_leader':
   force one slot, block the first false statement and submit another false
   trace. It must finish 512 tiles before the first leader is released.

Manual native controls (not run by this tool session, which has no Rust
toolchain / checked-out candidate and cannot run project preflight):

    bash scripts/project-preflight.sh
    cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
    cargo test --locked --manifest-path trillionnium/Cargo.toml \
      -p trnm-crypto-primitives rejection_cache -- --test-threads=1

A real physical V3 service campaign must compare identical vs distinct
false-trace mixes, honest producer/client p95/p99 including queue waiting,
true process/cgroup CPU, signed task consistency and source identity.

## Nonclosure and safety limitations

This patch is still opt-in, does not change V3's signed r13 Cookie or
introduce an unaudited budget. It cannot detect forged transcript digests
without the first complete replay. Cross-process/cross-host duplicate
proofs do not share a cache. For valid exact proofs the negative-only
cache intentionally does not retain acceptance authority: followers may
serially rerun valid W1, so service performance and fair-access metrics
must be compared before any default activation. Host/process memory
beyond the bounded cache and threads is not measured here.

The user's original four false transcripts and current four separate new
ones remain valid red-team cases. P1 real host-wide ownership and physical
experiment, P2 native/GPU attack price, P3 honest/invalid mixed sustained
traffic, original A03 P4 3x3x3 timely confirmations, fully secure W2 P5 and
independent external cryptanalysis P6 are all still **OPEN**.

No main merge, no activation, no claim of public readiness: HOLD_NO_GO.
