# Complete default Node library observation

The unfiltered default library command on source commit
`a5b5127883393da33c8619cc5f2b8e333a2dcf1b` completed with **1,114 passed,
4 failed and 31 ignored**, in 1,761.15 seconds. Its exit code was 101.
This is a failed complete command, not a passing full-library qualification.

`observation.json` records the exact source tree, binary digest, command,
profile overrides and uncompressed log hashes. The gzip logs preserve all
original bytes. The existing repository package optimization settings were
retained; debug symbols were disabled and incremental compilation was disabled
to avoid deleting other work in the low-disk environment. This is not an
original-resource or original-profile performance acceptance.

## Four failures and their boundaries

- The actual-kernel CPU sample test could not read
  `/sys/fs/cgroup/cpu.stat` because that file was absent. Read-only observation
  also returned `0::/` from `/proc/self/cgroup`. A permitted separate read-only
  check did not expose the missing file. No counters or quota were invented.
- Three combined guarded NPQ6 tests failed before their independent witness
  became ready. Each child reached `UnixListener::bind` in
  `store/pq_rollback_witness/combined_tests.rs` and received `EPERM`.
  These tests therefore do not establish their required replay, recovery or
  independent-process restart outcomes in this environment.
- A tool-reviewed rerun of those same three unchanged tests also failed at
  that same bind. Its separate log is retained. No TCP substitution, in-process
  witness, ignored assertion, network-setting change or further route around
  the restriction was attempted.

The remaining observed default tests passed, including the actual 65,536-key
continuity and capacity-reclamation/reorganization cases. This must not be
confused with the separately ignored signed Growth transition across 65,536
accounts or any other explicit release campaign. All 31 original ignores
remain visible in the complete log; none is counted as a pass.

No production code or test requirements changed for this observation.
The [development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
retains its original eight HOLD gates. A suitable authorized execution context
must run the unchanged kernel sample and independent witness requirements;
this local evidence does not satisfy them or replace the pending CI results.
