# G1-R2 stacked development note

`TRNM_G1_REPLAY_TO_CORE_DURABLE_ACK_EXECUTION_PACKAGE_V1.md` is developed on
`dev/g1-replay-to-core-durable-ack-owner-v1`, stacked on the unverified G1-R1
branch `dev/g1-payload-replay-recovery-owner-v1`.

The stack is intentional and does not promote either package. Review and merge
order is strictly:

```text
G1-R1 authorized clean-clone verification
 -> G1-R1 review/merge decision
 -> rebase G1-R2 on the accepted parent
 -> G1-R2A authorized clean-clone verification
 -> G1-R2B real Core adapter/process evidence
```

The R2-B contract is documented separately:

- [`TRNM_G1_R2B_REAL_CORE_ADAPTER_EXECUTION_PACKAGE_V1.md`](TRNM_G1_R2B_REAL_CORE_ADAPTER_EXECUTION_PACKAGE_V1.md)
- [`trnm-g1-r2b-manifest-v1.toml`](trnm-g1-r2b-manifest-v1.toml)
- [`check_replay_to_core_r2b_contract_v1.sh`](../../../scripts/ci/check_replay_to_core_r2b_contract_v1.sh)

The current worktree carries a candidate `CandidateCoreIngressV1` probe. That
probe is not source-bound evidence. R2-B remains a candidate-only
contract until the real Core/SafetyState owner, process fault cuts and clean
clone review are accepted.

R2-A retains these false facts:

```text
live_core_adapter=false
core_ack_generated_by_core=false
core_ack_atomic_with_core=false
node_process_integration=false
production_activation=false
```
