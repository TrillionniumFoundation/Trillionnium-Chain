# Python integration diagnostics

These commands ran on the explicit integration working tree based on
`e4abb172147e941b62483652b0ceabaae4317624`. They are not a clean-source hosted
run, a native test run, or a business-throughput result.

## Before source-pin repair

`before-repin-results.json` retains all ten command outcomes, before/after HEAD,
and the observed changed tracked-file digests. `before-repin.tar.xz` retains
the original stdout/stderr and result file; member digests are in
`before-repin-members.json`. Other agents were editing the integration tree;
the eighth diagnostic records a changed tracked diff during its execution.

| Command | Exit | Observed result |
| --- | ---: | --- |
| `scripts/ci/test_pq_lifetime_budget.py` | 1 | Original consensus source-lock mismatch; 58 methods, one error |
| `scripts/ci/pq_lifetime_budget.py` | 2 | Same consensus mismatch |
| `scripts/ci/test_pq_authority_effect_register.py` | 1 | Current integration ingress bytes do not match the retained authority lock |
| `scripts/ci/pq_authority_effect_register.py` | 2 | Same current ingress mismatch |
| `scripts/ci/pq_chain_claim_guard.py` | 2 | Stops at lifetime lock mismatch |
| `scripts/w1_qrom_current_implementation_audit.py` | 0 | Existing audit returned success for its own source scope |
| `scripts/ci/check_ci_contract.py` | 1 | Current store blob differs from the inline recent-batch workflow pin |
| `scripts/ci/test_w1_factorial_native_gate.py` | 0 | Existing gate mutation tests passed before the roster update |
| `scripts/refresh_distributed_source_inventory.py --check` | 1 | New native test sources are absent from the existing inventory |
| `scripts/ci/check_repository.py` | 2 | Stops at the same inline store pin mismatch |

The consensus mismatch also exists in the original hosted e4abb run. The
ingress/store/inventory discrepancies here concern the new integration edits;
they must not be presented as additional original hosted e4abb failures.

## Minimal History roster update

`roster-result.json`, `roster-stdout.log`, and `roster-stderr.log` record the
existing `scripts/ci/test_w1_factorial_native_gate.py` after adding the three
shared-detached-History test names to the existing workflow and fixture.
All **nine test methods passed** in 30.812 seconds. The workflow and fixture
digests agree before and after this invocation.

The fixture expects 36 passing History tests and the existing one ignored
child, replacing the former 33 plus one. The three new exact names are required
once; the existing missing/duplicate named-control cases cover them. All prior
negative cases remain. This Python result proves the gate's behavior under
those fixtures. Native compilation/listing and real execution must establish
the actual 36-plus-one roster separately.
