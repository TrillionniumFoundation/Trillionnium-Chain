# Authorized History increment: actual operation, cancellation and known-prefix crash recovery

This is a V5-compatible increment on genuine parent
`081c04e893850a42b539d98d6ccfa659496e99ee` (PR503), with the original **25-package**
Cargo graph. It adds an enabled, separately authorized single-successor History
operation and an opaque recovery handle. It also fixes an independently
reproduced nonce-delegation omission in the original protected packet receiver.

**Whole History P0 remains OPEN.** The actual SIGKILL test covers a known-settled
validation plus a known-settled, internally cancelled activation. It does not
cover a process killed during validation, admission committed before CPU
settlement, activation committed before CPU settlement, or a partially committed
arbitrary reorg. Those cases require a distinct effect/recovery authorization
namespace. The old V5 pending/unknown refusals are preserved, not counted as a
completed recovery mechanism.

The [protocol and API description](../../docs/protocol/pon-nakamoto-v1/details/CONTINUOUS_HISTORY_OPERATION_V1.md)
and [sole development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
state the intended boundary. There is no new consensus authority, validator
voting, automatic activation, production grant, or completed model-product claim.

## Actual final native result

The unique executable SHA256 is
`76aeb191a35b1d13702346cab6b077b392266ba3e83c477e692944ddae8d86d7`.
Its [build/execution receipt](native-attempt-07-nonce-and-pidfd/attempt.json)
records the exact command and environment. The code was copied to a unique
snapshot immediately after Cargo emitted its executable path, listed, executed,
and hashed again. All present non-evidence source files were hashed before the
build, after the build, and after execution. The byte maps and exact patch on
parent 081 are retained in that directory as compressed reconstruction inputs.

- **Seven new native tests passed**, with no failed tests. One helper is ignored
  in an ordinary sweep; its mandatory owning test explicitly starts it twice in
  separate processes and requires the actual resume process to pass.
- The [nine retained native regressions](native-attempt-07-nonce-and-pidfd/retained/retained-summary.json)
  passed on the same executable: six original durable CPU/child tests and three
  exact original History tests. This is **16 distinct main tests**, not a full
  workspace suite. The child helper executions are not counted as extra distinct
  regressions.
- [Strict Clippy](clippy-final/receipt.json) passed for M01 and Node, all targets
  and all features, with `-D warnings`; source bytes stayed unchanged.
- The source-integrity suite passed **34 tests** and the CI-contract suite passed
  **91 tests**. Their intentionally failing fixtures remain visible in the logs;
  they are negative assertions, not failed suite results.

The standard whole-repository checker was also executed and **failed locally**
because this genuine sparse checkout does not materialize historical evidence,
starting with `docs/README.md -> ../evidence/pon-v1/README.md`. Its original log is
retained as `repository-check-final.log.gz`; no original check was skipped or
weakened. A separate audit of all 162 present Markdown files found 1,064 local
link references: 1,011 resolve on disk and the other 53 point to preserved Git
index entries. No target is absent from the index. The 13 local links in the new
protocol/evidence documents resolve on disk. `final-static-verification.json`
records this supplemental scope; it does not claim a complete-checkout gate PASS.

Rust is the restored actual 1.95 toolchain. Cargo used `--offline --locked`,
`CARGO_BUILD_JOBS=1`, the original vendor/Cargo home, and
`CARGO_PROFILE_TEST_DEBUG=0`. No `RUSTFLAGS`, package optimization override, lock
update, dependency substitution or 26-package PQ graph was introduced.
`trillionnium/Cargo.lock` SHA256 remains
`6efe75ea2f9293e3f0d003d6896e89e795c1ef021b9e15179db4d2e37317b864`.

The native fixtures execute original checkpoint-task bootstrap, signed
allocations/views, actual nonce search, full scalar W1 reference verification,
M06 with two actual scoped workers, original admission/activation and durable
journal calls. The checkpoint/activation material and authority declaration are
synthetic, with disclosed deterministic test keys. They do **not** prove actual
LLM training/forward quality, external Registry2 admission, public Host campaign
acceptance, independent governance or a secure PoN cost assumption. The fixture
identity declares parent 081 as its local test source identity; the actual
modified executable is identified by the frozen byte maps, patch and binary hash.

## Preserved sequence of failures and repairs

| Attempt | Actual native result | Interpretation and retained evidence |
| --- | --- | --- |
| 01 | 0 passed, 5 failed | Fixture supplied the wrong mandatory activation-profile literal; initialization failure, not a History logic result |
| 02 | 0 passed, 6 failed | Fixture omitted the protected journal directory; original journal policy correctly refused |
| 03 | 0 passed, 6 failed | Fixture used the manifest identifier instead of its matrix-task identifier; a separate destructive duplicate-settlement test then incorrectly expected a clean reopen of a faulted journal |
| 04 | 4 passed, 2 failed | Actual causal RED: the first unpublished History adapter omitted the upper nonce fence; a separate actual known-settled admission/cancelled activation cold reopen reached the original advance HOLD |
| 05 | 6 passed, 1 failed, 1 helper ignored | New History nonce fence and opaque cold recovery passed. The real-process guardian could not resolve an inner PID through outer-mounted `/proc`; cleanup SIGKILL is retained but does not qualify recovery |
| 06 | 0 passed, 1 failed | Independent causal RED: after fresh real signatures and a fresh operation, the pre-existing protected receiver admitted packet nonce 8 under a delegation allowing only nonce 9, executing full W1 and two children |
| 07 | 7 passed, 0 failed, 1 helper ignored | Both nonce gates reject before Work/children; actual two-worker success, worker cancellation, worker panic, known-prefix SIGKILL and fresh-process resume pass |

Each attempt retains original build output, execution log, source hashes and
reconstructable source patch. The actual nonce RED sources are
[attempt 04](native-attempt-04/source-changes.patch.gz) and
[attempt 06](native-attempt-06-original-receiver-red/source.patch.gz).
The first is a bug in this increment's initial unpublished adapter. The second
is the independently exercised pre-existing receiver omission. They must not be
conflated or attributed to an untested upstream variant.

The final code puts the original `check_nonce_window` inside the original paid
`continuous_validate` closure, before any State restoration/full W1/M06, and
retains the same permit, task binding, CPU checkpoint and settlement. A signed
packet is not a substitute for the upper signed nonce delegation.

## What the actual process-crash experiment proves

The complete raw process material, SQLite files, journal, signed test inputs,
child stdout and guardian observation are in the
[actual process fixture archive](native-attempt-07-nonce-and-pidfd/actual-process-fixture.tar.gz).
The first native process completes and journals full two-worker validation, then
cancels activation from an internal progress callback and persists that known
settlement. It parks after an fsynced barrier without CleanClose or Node Drop.

The guardian holds a pidfd opened from its own `Popen` child PID, cross-checks
PPid, NSpid, namespace inode, executable digest and process start time, verifies
the parked process has no descendants, and sends SIGKILL to its original owned
namespace PID. It obtains actual `wait4`; it never signals an inferred outer PID.
The initial failed `/proc` mapping and the separate pidfd positive/real-grandchild
negative probes are retained. Any unreadable or ambiguous process observation
fails; a missing `children` kernel interface is not treated as an empty set.

The retained observation reports approximately 0.797347 seconds of process CPU,
of which 0.731976560 seconds belongs to the known original scopes. Original
floating-point timeval representations and their integer-nanosecond conversions
are both preserved. These units do not establish nanosecond accuracy or a general
physical CPU bound.

The disclosed local test authority signs that exact observed prefix and residual.
The test invokes the original protected `prepare_known_unclean_restart`, rejects
the same residual a second time without another debit, then launches a **second
actual native process**. That process starts with **zero initial CPU credit**,
opens the opaque recovery handle, spends fresh selected claims, verifies the
already-admitted exact packet and actually activates it at generation 1. It
retains the old receipts and spent history, has eight claims/eight started
operations/zero pending scopes, then performs a genuine clean checkpoint. The
parent reopens and reads the retained journal after the second process exits.

The public entry retains the original concrete-source fixed Host permit,
including loopback sources. Native fixtures call the crate-private adapter and
therefore do not claim a public Host or WAN admission campaign. The protected
one-shot recovery CLI exposes only the opaque handle until the actual selected
activation, known settlements, empty scope and clean close succeed.

## PR503 CI failure and retained sixteen source pins

The actual recent-batch acceptance run was
[40486763243](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40486763243).
Both raw head/merge job logs are retained here. The complete source verifier
passed, then the hardcoded blob gate failed **before** the Rust/native stage.
The later missing `*.log` artifact hash command is secondary; native tests had
not started. This observation is not a native regression result.

The Store pin was already stale at #498, and PR503 also changed Store. PR503
introduced two further byte changes in `native_authenticated_tests.rs` and
`tests/public_v3_multiprocess.rs`. Their reviewed changes concern retained test
fixtures/formatting and the concrete fixed Host test source. This increment
retains **all 16 assertions**, explicitly rebinds those three reviewed blobs,
and adds the seven new exact test names. The other 13 pins stay unchanged. See
[the diagnosis](ci503-pinned-blob-diagnosis.json) and
[the sixteen reviewed pin rows](followup-sixteen-pins.json).

The selected native tests and explicitly enumerated component gates passed;
the sparse-checkout whole-repository limitation above remains separate. No
remote run of this unpublished follow-up is represented as having passed.

## Integrity and scope

[SHA256_MANIFEST.json](SHA256_MANIFEST.json) records every archived observation
and reconstruction input except itself and this explanatory README; the Git tree
binds both. Compressed files preserve exact original bytes on decompression.
Raw CI/libtest logs retain their original trailing spaces and terminal blank
lines inside gzip, rather than editing observations to satisfy source-whitespace
checks. The initial raw-log whitespace observation is retained separately.
Large native executables are omitted from Git; their independent local snapshots
and hashes are retained, and the original V4 `ce6e82f3…` executable was backed up
before the shared target was reused. Historical evidence blobs absent from the
local sparse checkout were never replaced, synthesized or deleted.

The new private recovery selector changes no V5 signed field or stored event.
It cannot recover a pending/unknown scope. A separate V6 research protocol is
required for explicit effect intent/atomic SQLite commit markers, nonrollback
spent anchors, independent closed-process evidence and conservative crash-debt
discharge. Validation-in-progress and activation-commit-before-settlement are
still mandatory OPEN cut points for that subsequent work; retaining their V5
HOLD is not counted as complete History acceptance.
