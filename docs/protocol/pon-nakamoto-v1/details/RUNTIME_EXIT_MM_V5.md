# Explicit V5 exit-memory observation

Status: **HOLD, local process accounting only**. This is the retained
`linux-owned-exit-mm-detached-v5` research profile from
[`e34a60bf63`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/e34a60bf63).
It remains separate from strict V1 and the existing V2–V4 profiles. No model
qualification, process release, installation or public-network authority is
granted by selecting it.

The [V5 observer](../../../../scripts/llm_runtime_exit_mm_observation.py)
retains the original owned pidfd and directory descriptors. It reads a complete
task stat frontier before the original status read that may lack `VmRSS`.
Only the same-sample capability can create the typed observation. A later
diagnostic, a substituted owner, a changed task set or an incomplete prior
frontier cannot retrospectively supply that authority.

Detachment of a process memory map is not a zero-RSS observation or proof of
released memory. The [runtime supervisor](../../../../scripts/llm_runtime_pilot.py)
retains the original reservation and wall/RSS budgets, the bounded drain
window and the exact terminal `wait4` receipt requirement. Current registered
plan bindings and stop-request propagation remain in force. V5 cannot use a
later ordinary terminal read to repair a missing original frontier.

The original tiny-process probe is preserved as an explicit local diagnostic.
It creates its own output directory and records fixed budgets, source hashes,
failures and inconclusive observations. It is not run automatically by this
consolidation and is not a model benchmark or release gate. Old observations
remain evidence of their old source and host only.

The existing protocol-contract lane now runs the V2, V3, V4 and V5 observer
controls alongside the original RSS owner controls. New V5 controls also check
the current registered-plan wrapper and reject mismatched profile bindings.
These tests use explicit fixtures; passing them does not attest to a kernel,
real deployment or independent model efficacy.
