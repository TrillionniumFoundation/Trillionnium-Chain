# Unknown-marked-count search policy and solver evidence readback

Base source is `a99ef8e333b6f1b7486b33e820464cf824fec273` from the existing
finite-stop research candidate. This continuation adds one explicit M-blind
randomized stopping policy and its conditional cost evaluator. It changes no
native W1, account, target, chainwork, DAA, activation or original model source.
The [contract](../../docs/security/PON_UNKNOWN_MARKED_POLICY_COST_V1.md) specifies
the policy, costs, numerical limits and open qualification requirements.

## Retained development outcomes

The first eleven-method run had one test-harness failure: two equivalent
binary64 decompositions returned 97.25 and 97.25000000000003. The direct
equality assertion was replaced by a stated 2e-15 relative tolerance. The
initial [failure log](unknown-first.log) is retained rather than counted as a
passing execution.

Review of the actual first report then found a real rare-failure accounting
defect. For N=2^64 and M=N-1, rounding the success probability to one erased
all later work. A new regression actually failed on that source; the
[RED log](unknown-rare-failure-red.log),
[original source bytes](original-model.py.txt) and
[uncorrected report](original-uncorrected-report.json) are retained. The
reconstructed original bytes match the report's original model SHA-256.
The uncorrected report is not valid cost evidence.

The correction carries success and failure probabilities separately from the
80-digit recurrence, then selects the stable tail when composing the policy.
The nearly full-domain control now preserves expected additional Grover work
of 2^-65 at cap two. All twelve new methods pass in the
[final regression log](unknown-rare-failure-green.log). They contain 8,576
dense state-vector comparisons and 120 independent terminal-path enumerations,
with endpoint, interruption, complete-cost reconciliation and numerical-limit
controls. These counts describe individual comparisons within twelve methods.

The unchanged original methods also executed: [21 finite-stop controls](baseline-stopping.log),
[11 gate-template controls](blueprint-controls.log), and
[7 native DAA controls](native-daa.log). The DAA controls compiled the actual
pinned consensus source with Rust 1.95.0 and `-D warnings`; they did not skip.
These 51 methods do not constitute a Cargo workspace, physical quantum,
global-minimum oracle or complete-chain security qualification.

## Independently replayed original native solver evidence

The original reader at source `c59b5ddc4c37a56a0b7f814eabb5805afbab4a5b` executed
again in a separate full checkout. Its [actual log](solver-readback.log) and
[derived identity/cost summary](solver-independent-readback.json) record:

- the complete original ARM ZIP is 10,226,619 bytes with SHA-256
  `fd92550ad8efb9271dd4bc1e2de3e470200fcefeb7f75396f087974fa2d64cc7`;
- all 4,032 non-timing cohort records agree with x64, including inputs, full
  proof streams, tickets, unsupported outcomes, misses and admission calls;
- there are 509 distinct native maintenance winning headers, not 10,464 new
  blocks; the larger number includes repeated admission of known packets;
- the original ARM executable is retained; the original x64 executable is not.

This was an artifact readback, not a fresh mining experiment. With retained
preparation at horizon 256, maintenance-split-limb costs 0.903603 ms per winning
call versus 0.930592 ms for Prepared on x64, and 1.260630 versus 1.305780 ms on
ARM64. Preparation plus every failed attempt/exhausted search remains in the
numerator. Without preparation reuse the ratios differ substantially; the
retained-preparation comparison must not be replaced by that cheaper baseline
assumption. Verification, admission and IO remain outside this producer metric.

The full existing evidence and reproducer remain in
[solver PR #515](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/515).
Two shared CPU hosts do not establish a globally cheapest solver or physical
hardware comparison. GPU, energy, independent hardware, further registered
useful-task structures and end-to-end costs remain open.

## Execution boundaries

The original project preflight passed in the complete checkout. The
[native inventory](inventory.log) and an initial
[whole-repository readback](repository.log) passed; the latter explicitly
records a dirty candidate and is not a committed-source receipt. Fresh final
source identity and workflow observations must be kept separate from these
development logs. The existing dedicated hosted workflow retains all original
methods and adds the new controls and report at the actual PR head. Its
timeout, source guard and readonly permissions remain unchanged.

The numerical examples assume all physical timings. The 2,748,849,130 Toffoli
per-Grover-iteration figure is the original complete W1 retained-history
construction plus its diffusion, not a lower bound or calibrated rate.
Unknown-M policy costs are now explicit; actual W1 marked distribution,
lowest-cost oracle, unknown-policy optimality, physical fault tolerance,
strategic measurement, DAA chain quality and production/security qualification
remain open. Every authority and activation flag remains false.
