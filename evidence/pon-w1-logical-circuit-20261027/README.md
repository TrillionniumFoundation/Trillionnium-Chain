# Complete W1 logical circuit observations

This archive belongs to the [logical circuit research contract](../../docs/security/PON_W1_LOGICAL_CIRCUIT_BLUEPRINT_V1.md).
The local run started on parent `829c5d28ec9a0fc13de2bd098b477cbacacdb4b7` with an
explicitly dirty research worktree. The twelve named source files in
`source-before.json` and `source-after.json` remained byte-identical. A later
published commit does not retroactively become the starting HEAD of this run.

All eight commands in `observations.json` returned zero: the development boundary,
11 actual circuit controls, the full logical report, the existing conditional
DAA report, 95 CI-contract controls, 34 source-integrity negatives, 16 project
boundary negatives and the source inventory. Raw stdout, stderr, exit code and
process CPU/wall observations are retained for each command. Test execution time
is never reported as quantum computation time. The original branch-name refusal
and its correction, without changing the boundary policy, remain in observations.

The separate full repository checker **failed** because this local checkout does
not materialize historical evidence: `docs/README.md` links to the preserved but
absent local `evidence/pon-v1/README.md`. `repository.*` retain that actual failure.
No link was removed, no checker disabled, and no full local repository/source
guard is claimed. The dedicated exact-head CI must perform a full checkout and
independent before/after source checks.

`logical-circuit-upper-bound.json` includes both actual gate-template identities
and the complete fixed-control-flow schedule, with all coherent rejection
branches, intermediate transcript values, input-port loads and uncomputation.
Its two logical upper-bound constructions are conditional on the specified
hierarchical wiring. The full billion-gate list is not expanded; the complete
quantum circuit is not simulated or formally verified. Classical full-W1
differentials and logical template simulation are separate observations.

`conditional-daa.json` reruns the existing source-bound integer/model report;
this local archive does not re-execute its native Rust parity test. The assumed
relative mining rate remains uncalibrated. The gate ledger is not a least-cost
oracle, practical attack, security lower bound, fault-tolerant resource estimate,
PQ128 qualification, native PQ transaction integration or production activation.

The source and command records contain no signing keys, deployment credentials,
model checkpoints or account secrets. `artifact-hashes.json` binds the retained
observation files. Native authority and all existing release gates remain open.
