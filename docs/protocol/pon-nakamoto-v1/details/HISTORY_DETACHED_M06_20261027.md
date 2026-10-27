# Native History private prepare, execute and commit

**Blocked isolated prototype. Do not integrate or activate this continuation.**
Request cancellation during a durable multi-step activation can leave the
original global reorg intent unfinished. Exact authenticated retry is covered
below, but an independent bounded reconciler under every original service/CPU
owner is still missing. An attacker need not send that retry. The explicit
withheld-frame socket experiment must retain its actual failing honest-service
result; targeted component success cannot close this availability blocker.

This implementation continues `bb2d444a3f5fe24b0077c1f01ed1d0953c2b6ff1`
under the existing sole development plan. It changes ordinary shared-owner
execution scheduling. It does not change PoN eligibility, PNW1, target,
chainwork, signed domains, stored schemas or production activation.

## Actual owner boundary

`store/detached_admission.rs` owns the private preparation and execution
artifact. `ingress::admit_shared_checked` is the common shared Submit/History
dispatcher. Both use the existing request's execution control and worker CPU
accounting; the dispatcher does not begin another CPU reservation.

Preparation holds the original Node mutex. It validates current namespace,
storage context, header, target, clock, complete parent State, task/material
eligibility and original SQLite epoch. A single non-cloneable lease captures
that Node incarnation. The immutable State, selected checked arithmetic,
configuration and full W1-checked packet move into a private owned preparation.
The Node mutex is released while the actual original M06 executor binds the
complete State, runs its scoped workers, derives eligible task output and
compares the final State and receipt roots.

Only that execution can construct the single-use result. Neither a public
`StagedOutput`, a claimed root, a cached verdict nor an arbitrary copied State
can be supplied to commit. The private artifact is not serializable and has
no public fields or unchecked-result constructor.

On reacquisition, the original Node rechecks incarnation, directory/DB/owner
identity, network/parameters/genesis/backend, owner availability, observed clock,
target, parent record and original connection epoch. A legal append or reorg
through the same owner triggers a complete fresh parent/task/material check;
a valid competing branch is not invalid merely because the active tip moved.
Any foreign SQLite write, including a write subsequently restored to identical
bytes, refuses the old artifact. Reopening a Node cannot reuse its predecessor's
artifact.

Submit obtains a fresh local clock at reacquisition. History preserves the
page's original caller-supplied observed clock and rechecks against that same
observation; it does not claim to resample wall time or extend the original
absolute business deadline.

The final epoch and context check occurs again **inside the original
`BEGIN IMMEDIATE` transaction**, before the first insert. This closes the gap
between the last preparation check and acquisition of the database writer.
All original block/delta/snapshot/authenticated publication, packet/delta
readback, full parent and successor State checks, ancestry validation and
active-tip checks remain in one common persistence function used by both
held-owner and detached admission. A failed final check rolls back the same
original transaction. No cancellation is added after a successful commit.

## Deliberately bounded scope

There is one retained detached State slot per Node. Contending callers release
the writer and wait at most two seconds while checking their original CPU and
absolute deadline controls. There is no per-peer credit, new CPU domain,
restart allowance, hashcash, stake, bond or consensus committee.

The retained canonical key/value payload is capped at the existing 8 MiB
commitment material ceiling. The counted payload is the sum of each key's
UTF-8 byte length and its value's canonical serialized length; it excludes
map/allocator overhead. Exceeding it produces a private `HeldRequired` scheduling
result before any M06. The dispatcher still holds the same Node and passes the
same actual `WorkCheckedPacket` into the original checked held M06 path under
the original CPU/deadline controls. The temporary State and detached lease are
dropped. No W1, CPU account or execution output is fabricated. Only the private
counter's actual size result can select this schedule; callback/encoding errors
propagate even if their text/code resembles a capacity hint. A large valid
parent is therefore not permanently refused by this representation limit.
This is **not an RSS bound**: the original complete
State is materialized before measuring that payload, the executor clones
State for its output, checked arithmetic and allocator overhead remain, and
final SQL readback constructs complete State again. The slot limits retained
concurrency, not the peak cost of the original State reader. The held schedule
retains the original writer cost and currently repeats the parent validation
already done during preparation. Early overflow observations are scanned byte
lower bounds, not measurements of the entire State. The true >8 MiB parity
fixture uses an explicit separate preallocated genesis, the original complete
validator, a genuinely admitted signed seed block and subsequent native W1/
signed transitions; it does not claim default-genesis historical growth.

Restricted task, mining, continuous, permanent/reference growth and explicitly
enabled ROOT-rejection-cache owners keep their existing held-owner path. They
cannot construct this ordinary-owner artifact. If such an owner replaces the
ordinary context during execution, the detached artifact is refused. The
#498 continuous History gate remains before paid work:
`OWNER_CONTINUOUS_HISTORY_DURABLE_REQUIRED`.

History activation and shared Submit activation now use the existing progress
aware activation API with the original CPU/deadline control. This includes
the previously admitted exact-packet recovery path. SQL/root/fsync primitives
remain indivisible; cooperative cancellation is not hard realtime preemption.

The legacy authenticated listener keeps its ordinary `ready()` gate. Only an
already verified signed Submit with the same original pending frame, session,
nonce, digest, length, canonical payload and exact stored intent target may
enter the original controlled activation recovery. The original replay owner
is fully recovered and rechecked; this exception writes no new nonce or audit
row. Cancellation returns a nonterminal signed response and preserves that
pending scope. A new explicit signed attempt can finish and ACK it once; a
changed frame, target, payload, session or current time still refuses. This
does not provide autonomous recovery when the original sender disappears.

The unused legacy `RecoveryIngress` capability is only a concurrency reservation,
not CPU credit or a durable recovery authority. The ordinary V3 original CPU
domain/service lifetime could support a separately designed bounded supervisor,
but its native recovery currently loops all steps. Continuous owners require
their original durable operation purposes and allowances. None of these gaps
is filled by a temporary standalone account, an extra worker or renewal of the
cancelled guest's deadline in this prototype.

## Controls and measurement

The native tests exercise both legacy and authenticated backends, actual
signed transactions, native W1, actual M06, same-Node mutex access during M06,
wrong roots, original cancellation, owner reopen/revocation, valid competing
forks, foreign write-and-restore, the final transaction window and real SQL
trigger corruption. Linux History tests include actual SIGKILL while M06 is
in progress in addition to durable-epoch/W1/committed-admission/activation
cuts. The crash marker remains conservative fail-closed accounting, not exact
crash-time CPU-debt reconciliation or a physical power-failure certificate.

The explicit ignored cost test creates actual native history with 1024 signed
transfers to distinct recipients, then reports actual full-State key/value
bytes, prepare/execute/commit wall and whole-process CPU intervals and RSS
snapshots. Those CPU intervals include joined executor workers. RSS snapshots
include allocator retention and cannot be attributed to one allocation.
Raw results and failed attempts belong to the evidence record for the exact
tested source; command examples alone are not successful observations.
A separate deep clone of the actual native parent is measured after the primary
pipeline, without warming that pipeline's earlier clone allocation.

```sh
bash scripts/project-preflight.sh
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib detached_admission -- --test-threads=1
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib history_import -- --test-threads=1
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib detached_full_state_cost_uses_real_signed_history_and_reports_scope -- --ignored --nocapture --test-threads=1
```

Full parent extraction, final SQL publication/readback and activation still
hold the writer. This change therefore cannot establish high throughput or
fair service under saturation by itself. Original A03 Host requirements,
real budget depletion, complete hostile modes with every honest-request
denominator, independent WAN acceptance, large-State capacity and continuous
durable History reconciliation remain separate acceptance gates. Finite local
controls must not be relabeled as any of those qualifications.
