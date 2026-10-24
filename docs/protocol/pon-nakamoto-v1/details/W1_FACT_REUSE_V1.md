# Explicit native W1 mathematical-fact reuse

Status: local development implementation and finite native regressions. No public
listener, CLI profile, consensus parameter, readiness flag, Hepta pin or deployed
owner is changed. This continues the original W1 relation and M05/M06 owner path.

## Exact authority boundary

`pon_work::facts::WorkFactCache` is a fixed-profile volatile cache. Its key binds
W1, the complete header-derived challenge, the canonical actual task, and the
claimed transcript. A cached product is published only after the unchanged full
native verifier succeeds, including exact C and the final cancellation checkpoint.
Every request repeats the original length/version/field/task/current-target checks.
A hit compares C byte for byte before constructing a fresh private `VerifiedWork`.
Target, source leases, revocations, branch state, membership, confirmations and
local execution authority are never cached. SHA-256 collision resistance remains
an explicit assumption of content-addressed task and challenge identity.

There is no negative cache. A false C with the same block/transcript identity
cannot blacklist a later valid packet. A false transcript does not publish a fact.
At cold start, a false C arriving before its valid counterpart still costs one full
failed verification. Repeated distinct false transcripts still require admission
protection; the cache is not a solution to public work economics or Sybil flooding.

The original Node already checks exact packet content for an existing block ID
before W1 replay. Do not report this cache as newly fixing that durable duplicate
path. Its incremental benefit is pre-persistence and concurrent mathematical
verification, including work-valid statements that do not become admitted blocks.

## Bounded concurrency and cancellation

The caller selects 1..256 direct-mapped slots. Each completed slot owns 4096 u32
product words (16 KiB), plus bounded metadata. This is not a whole-process memory
bound; request buffers, verification scratch and caller threads are separate.
At most one computation owns each slot. Identical requests share that work; a
colliding key waits, and a completed different key can be evicted. This policy
bounds internal state but does not prove adversarial cache-hit rates or fairness.

Slot locks never cover W1 arithmetic or caller callbacks. A waiting call polls its
original cancellation callback after a Condvar timeout of at most five milliseconds;
this is not a wall-time/preemption guarantee. Callers bound threads and provide
an absolute deadline. Leader cancellation, native rejection or unwind releases its
computing slot and wakes waiters. Each waiter rechecks its own cancellation and
acquires its own verification attempt if necessary. A poisoned local lock returns
Unavailable, not consensus-invalid work and not an uncached silent fallback.

`full_replays` counts started full-verifier calls, including rejected/cancelled
ones; `hits` includes fast rejected C variants. Counters saturate and never grant
acceptance. A fresh cache has no retained verdicts. Returned products are independent
owned copies, not mutable aliases of cached facts.

## Existing native M05 integration

The current exported entry is `ingress::dispatch_shared_with_metered_work_facts`.
The first unmetered embedding wrapper is now crate-private and cfg(test) only;
it retains the original seven owner controls, not an alternate production path.
The current Submit-only entry requires the existing ServiceMutationCpuDomain.
It never constructs a new budget, reserves before W1/M06 work, and checks an
installed continuous owner's domain before dispatch. The caller's deadline and
cancellation are checked alongside that same live CPU operation at native and
W1 checkpoints. Actual M06 scoped workers register with the same operation and
are joined before settlement. A callback alone is insufficient: the original
unmetered wrapper plus an external CPU checkpoint was reproduced rejecting a
valid parallel M06 execution with unknown/unregistered worker accounting.

The complete native success/rejection/cancellation result is retained separately
from the CPU settlement. Known CPU, including failed request tails, remains paid.
Unknown accounting fences subsequent shared-domain starts, but cannot rewrite
an already committed native success as an unexecuted operation. Panic uses the
existing operation Drop rule: unknown accounting, no fabricated refund. Pool
and read requests are not routed through this mutation-only entry. The trusted
caller must not nest it inside an already reserved V3 request (which would buy a
second reservation); V3's existing dispatcher continues owning its own permit.

Current context and owner permits are checked before verification, the expensive
verification runs outside the only durable writer mutex, and the original owner,
state/root/nonce/current-clock and commit checks still run afterward. Public
V2/V3 listeners and CLI still use their original verifier and pinned resource
policies. No automatic public-cache profile selection is added.

No additional Node, database, operation journal, trainer or authority owner exists.
The original scalar/transposed/limb verifiers and original callback ordering remain
available unchanged. The new API has its own cache-hit/wait callback schedule.

## Finite observations and reproduction

The original Rust source plus a negative regression reproduced four complete
replays for one valid proof and three canonical false C variants; zero invalid
proofs were accepted. The one-replay assertion failed (exit101), as expected.
The failure log and exact additive test are retained outside the working tree.

The native primitive controls cover the 4-to-1 replay case, invalid-first ordering,
current target/task/field checks, 64 scalar differential cases over four structures
and two challenges, restart/eviction/capacity, independent returned bytes, eight
concurrent callers, waiter cancellation, leader cancellation, unwind, final-hit
cancellation and explicit poisoned-lock failure.

Native M05 fixtures contain real signed development transfers. They exercise
false-product rejection with no mutation, exact original state equality and cold
reopen; eight concurrent requests with one full replay and one durable block;
unchanged context failures; lock release and cancelled-hit/no-commit retry; and
one cache slot with a full 256-transfer block whose duplicate does not consume
another nonce. Development fixture signatures are not independent real operators.

Run the normal project preflight, then the existing package tests:

```sh
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-crypto-primitives --lib
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib ingress::work_fact_tests -- --nocapture
```

These tests establish finite implementation behavior, not elapsed-time speedup,
independent public qualification, compact-proof soundness, physical durability,
future learning quality or production activation. Hosted results must refer to the
actual new source, not the predecessor's Chain/Hepta paired green.

## Shared CPU continuation observations

Nine additional Linux tests exercise actual metered signed native admission,
owner-plus-scoped CPU accounting, exact paid-tail conservation with refill frozen
only in test controls, cold/warm refusal before replay under exhaustion, positive
facts after failed C, cancellation/retry, two real occupied reservations, eight
server reconstructions sharing one retained debt, and unwind fencing.
A separate test within those nine opens two actual framed V3 TCP listeners sharing
the same CPU domain. While one deliberately held invalid cached request remains
in flight outside the writer lock, a valid public submission and six additional
native blocks complete. An independent local Node obtains seven real History
pages over the other listener, fully verifies them, confirms all eight signed
transfers under the installed depth/work policy, and cold-reopens equal state.
The held invalid request is then rejected and charged; no resource remains live.

This is one bounded controlled overlap, not a saturation/flooding campaign or a
WAN throughput estimate. Holding a request is test scheduling, not measured
attacker CPU. Eight reconstructed PublicServer objects do not simulate an OS
process or host reboot. Same-domain pointers do not enforce a host-global cap
across independent processes, unrelated Nodes or deliberately created standalone
budgets. Cross-process kernel enforcement, unclean-restart debt qualification,
pre-cookie connection costs and public-cache profile integration remain open.
Mining generation and independent client work in the test are outside the
receiver mutation accounting. Signed wire and consensus bytes are unchanged.

## Optional kernel execution envelope

`formal/pon-nakamoto-v1/kernel_process.py` adds an explicit administrator-only
Linux/cgroup-v2/systemd adapter around the retained `bounded_process.run_bounded`.
The trusted operator provisions one parent slice and supplies its original boot,
device and inode identity plus exact CPU, memory, swap and task ceilings. The
adapter never creates, refills or silently replaces that parent. A reconnect must
present the same retained identity; missing/replaced parents and changed limits
are unavailable. This identity is not a new ledger or a disk rollback proof.

Every native process is assigned a distinct transient child unit under that SAME
parent. Child units do not have independent CPU quotas which could add another
allowance per identity or restart. The existing systemd manager applies cgroup
membership before exec; native code runs as a dynamic unprivileged user with no
capabilities, no privilege escalation, a private network, protected home/control
files, bounded private temporary filesystems, and no cgroup delegation. The
runtime ceiling and whole-cgroup stop are configured before exec. Ordinary POSIX
process-group cleanup remains responsible only for the local pipe broker; it is
not misrepresented as covering a descendant which changes sessions.

Input/output retain the original bounded pipe exchange. Executable bytes and all
ancestors must be root-owned/non-writable by other users; the original executable
hash is checked before launch. No guest can choose an executable, argv, slice,
properties, UID or environment through this adapter. This module is not exposed
as a privileged request service. It requires an authorized existing supervisor;
a normal unprivileged Node cannot invoke administrator operations by itself.

An observed native result and kernel cleanup are distinct. If cleanup fails, the
error retains any already observed native outcome, never converts it to an
unexecuted operation, and fences that handle. A short successful unit may already
be collected: this is resolved using actual manager `not-found` AND absent cgroup,
not by ignoring arbitrary stop/permission errors. A pipe-broker failure can lose a
manager launch acknowledgement; a momentarily absent unit then does not prove
no delayed launch exists. The adapter preserves that bounded exchange failure,
returns `KERNEL_EXCHANGE_UNCERTAIN` and fences the handle instead of declaring a
clean failure or authorizing blind retry. It does not mint a
`VerifiedWork`, state admission or succinct proof from its process receipt. The
existing operation owner still owns exactly-once reconciliation after lost replies.

The optional smoke runner `scripts/run_kernel_native_smoke.py` uses one temporary
parent with `cpu.max=25000 100000` (25% of one fair-scheduled CPU), 256 MiB memory,
zero swap and 24 tasks. It stages exact native executable copies under a temporary
root-owned `/opt` directory (not `/run`, which may be noexec), uses only new test
units, and removes its test units/assets afterward. Those local conservative test
limits are not PoN consensus parameters and are not a proven production sizing.
They are not the existing 2-second-burst scalar credit formula either: the kernel
ceiling is a separate, stricter aggregate protection, with kernel granularity.

The ordinary runner exercises four original W1 byte cases (valid, false product,
wrong task, zero target), two concurrent correct native verifier processes, a
same-identity handle reattach, and the retained real two-listener M05/M06 test
with eight signed transfers and seven independently verified History pages inside
the kernel envelope. All outcomes must equal the original native path. Twelve
portable logic controls cover caller bounds, identity/limit failures, bounded
outputs and native-result preservation; mock controls are not kernel measurements.

This optional supervisor path does not replace the public V2/V3/CLI default or
wire the external verifier into `WorkCheckedPacket`. Host-wide coverage requires
all relevant entry processes to be assigned to the approved parent. Manager,
launch-broker and out-of-envelope client CPU are not in that parent's accounting.
Root compromise, administrator-created alternate parents, physical host reboot,
unclean persistent CPU-debt migration, kernel OOM/task-exhaustion behavior under
attack, supervisor-death cleanup, saturation fairness and WAN confirmed goodput
remain separate unqualified cases. A full pressure/fault-injection script was
blocked by the execution tool safety check during this increment and did not run;
its unexecuted cases must not be replaced by ordinary smoke success.

Relevant mechanism reference: the Linux kernel's cgroup-v2 documentation describes
hierarchical enforcement, `cpu.max`, `memory.max`, `pids.max` and `cgroup.events`.
The parent CPU counter is aggregate usage across child units, not per-request cost;
its throttle time is not a wall-time latency estimate.

Observed in this increment: the earlier ordinary native run matched all four W1
cases and passed the retained two-listener/eight-transfer Node fixture under the
25%-CPU/256-MiB/24-task parent. The parent counter was continuous, the kernel
reported throttling, and no tasks remained afterward. A later final native rerun
was itself blocked before execution. Consequently the final adapter's tightened
unknown-broker handling has portable logic coverage but NOT final-source real-
process qualification. The added two-request concurrent smoke step was not run. The earlier raw
results remain historical within this increment, not silently reassigned to the
final source. No actual kernel OOM, task-exhaustion, forced controller death or
physical reboot result is reported. The public receiver still uses its original
implementation and the previous Hepta pair remains pinned to its unchanged Rust.

Final child launches request systemd `--collect`, so failed native input should
not leave one retained manager unit per rejection. The original raw stderr/exit
and generated unit identity remain available to the owner. This final collection
option has command-construction coverage only; it is included in the outstanding
final-source kernel run, not claimed tested by the earlier smoke observation.

## Exact Node owner binding for local metered W1 facts

The existing metered W1 path now checks/binds the original Node's exact
public-service domain BEFORE acquiring CPU reservation or starting M05/M06.
A first trusted local caller can bind an ordinary Node; later callers must
reuse it. Continuous owner identity remains mandatory. A foreign domain
cannot pay from a fresh allowance, enter a W1 replay, start M06 workers
or mutate native state. Native business result and CPU settlement remain
separate. This does not activate the cache in default public V3 and does not
establish host-wide enforcement across independent processes.
