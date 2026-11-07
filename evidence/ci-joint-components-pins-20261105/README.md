# Preserve joint-component source identity

Candidate `9ecdbebc897d35f07b998d084b015db8474be84b` changes five already registered CI/runtime Python and shell files without updating their required source pins. [Original guard failure](original-failure.txt) and [all five mismatches](stale-pins.json) are retained.

This repair updates only those pin values to the exact committed source. It changes no runtime implementation, test expectation, trust policy, workload, profile, deadline or guard logic. The current native-apply experiment is untouched. Verification of these source identities is not execution or qualification of every joint component, and cannot promote pending hosted runs or business/security gates.

Validation: [100 CI contract tests](ci-contract.txt), [37 PQ source negative tests](pq-source-controls.txt), [43 source-integrity controls](source-integrity.txt), [521 exact pins](source-guard.json) and generated inventory pass. These are source/control checks, not new native, model, work-security or business acceptance executions.
