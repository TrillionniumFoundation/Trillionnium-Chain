# Joint-candidate component repairs: retained observations

This directory retains component observations used to prepare the next joint
candidate. It is **not** a complete-checkout qualification receipt, a native
model run, a public-service acceptance result or release authorization.

The reviewed source was Chain `7ae0d1b227853fc75e02334b497f69dd52d50235`.
The later `f9977c5d6d1b57880967ef36dcd1570010cbbe4f` and
`c7dd1ec73a22f5643581a19dece46f418a230909` commits added independent historical
evidence; they did not change these repaired source files. The exact changed
files and component logs are hash-bound in [manifest.json](manifest.json).

## Supervisor cancellation

[The original real-child observation](runtime-stop-original-red.json) records
SIGINT after a child was spawned but before `_Wait4Child` was assigned to the
caller. The original supervisor unwound with `KeyboardInterrupt`, left the
child live and had no completed reap. The observation fixture subsequently
cleaned up its own child. The post-adoption control completed the original
cleanup. The retained 43 RSS-owner tests passed even on the original source;
they did not cover that constructor handoff.

The repair installs a scoped, sticky SIGINT/SIGTERM request before the ordinary
neural reader invokes the original supervisor. The handler does not unwind
the constructor or perform cleanup. The original pidfd/wait4 owner retains
the five-second TERM and one-second KILL/reap windows. Cancellation remains a
failed result, including when the child exits zero. Unknown cleanup retains
the exact handle and failure receipt. Main-thread admission, partial handler
installation rollback, repeated SIGTERM during cleanup and handler restoration
are covered. SIGKILL, arbitrary asynchronous exceptions and a child that the
kernel never terminates are outside this component's claim.

[The combined log](runtime-stop-green59.log) contains 12 new stop controls,
43 retained RSS-owner controls and four retained neural-worker framing controls:
59 passed. These tests ran against the assembled selected-file fixture, which
is not a complete upstream checkout. They executed real Linux child processes,
not a model. The new suite is included in the original protocol-contract CI
lane with its existing command-presence and ordering controls.

## Rejection-cost observation

The current ordinary verifier uses FullLimb. The v2 observation includes that
implementation alongside the three retained kernels and uses it as the
production comparison denominator. The [reader-control log](rejection-reader92.log)
records 92 passing Python controls. Those controls do not execute Rust or
measure the proposed 96 cohorts, 1,152 timed verifications and 96 scalar replays.

The [v2 plan](../../docs/research/PON_WORK_REJECTION_COST_V2_PLAN.md) defines the
new record separately. It compares verifiers with a fixed honest producer;
its honest acquisition cost is not an attacker-cost floor. The existing
from-zero forged-trace and legal-strategy experiments remain separate inputs
to an independent cheapest-known-strategy review. No global cheapest-work,
worst-case rejection, CPU/energy, economic or public-service claim is granted.

## Qualification boundary

All eight gates remain HOLD in the
[sole development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
Native commands must execute on a complete, committed, clean source with the
original toolchain, dependency graph, configuration and budgets. Old successes
and these selected-file controls do not transfer qualification to a new head.
The original learning trial remains spent 1/1 and aborted; it is neither reset
nor relabelled as a valid no-update. Independent operators and fault domains
must supply the required WAN and long-run evidence.
