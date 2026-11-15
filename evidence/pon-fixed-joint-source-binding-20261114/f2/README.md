# F2 joint-contract source binding

The 23 listed inputs are reviewed against actual F1 source commit `2d9baf313e54e49a4507c5057578e89ddbe7a1b6`.
Four inputs differ from the historical 2bb56596 source, including the committed
F1 fixed-probability JSON; nineteen are unchanged. The reader's independent
revision and map constants change with this reviewed mapping. No probability,
cost, native runtime, configuration parameter, limit or qualification changes.

The original 35 test methods remain. Exactly one method adapts its required
current revision and adds the old 2bb56596 revision to the rejection cases.
The other 34 methods are AST-identical. The old contract, reader, tests and
document are preserved under `../historical/`; original Linux source-mismatch
failures are preserved under `../original-diagnostics/`.

`source-review/all-23-inputs-review.json` records every old and current Git OID,
length and SHA-256. `reviewed-source-deltas.zip` preserves all four complete
patches. `minimal-change-proof.json` records the exact adaptation boundary.
Focused validation results are recorded separately; none grants production or
hosted qualification.

## Targeted validation

All 35 retained methods passed with the recorded macOS Python command. The
actual production CLI returned contract_validation=PASS and HOLD_NO_GO;
--require-qualified exited 3 with REFUSED_UNPROVED_JOINT_CONSENSUS. Direct calls
to the same production reader rejected both the original historical revision
and the old map paired with the current revision. All 35 explicitly named
inputs matched before and after validation. Exact commands, raw streams and
scope are recorded in validation/summary.json. This is not a full Linux lane
or hosted qualification.
