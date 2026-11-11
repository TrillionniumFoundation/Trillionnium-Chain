# SP27-02/06 measurement handoff for the current run

The current SP27-02 owner accepted the strict `< T` plus original native final
gate semantics and the new-CI scope in an explicit agent message. The measurement
subagent read the original 06 contract and code, verified their exact upstream
Git blob identities, and executed that retained consumer on the two original CI
phases. This is a concrete local interface-consumption result.

The freeze is [CONTRACT_FREEZE.json](CONTRACT_FREEZE.json). The minimum actual
sample and consumer output are under
[results/ci_pair_43052900246](results/ci_pair_43052900246/CONSUMER_RECEIPT.json).
Root should rerun `consume_native_v2.py ci-pair` into a distinct directory,
compare contract/schedule/event and result digests, and retain a separate ACK
naming the freeze SHA-256. A matching execution confirms byte/field consumption,
not a new native experiment or an attack mechanism.

The earlier Agent 06 author and portfolio coordinator have not supplied a
verified reply within this measurement handoff. Do not rename the current
subagent as that earlier author or mark coordinator acceptance complete. Keep
their pending acknowledgment explicit. Shared catalog and portfolio files are
left to the coordinator; this work modifies only the SP27-02 private directory.

The manuscript should report the original CI pair as a separate, fixed-order
observation. The raw boundary recheck may establish whether the old reader's
inclusive endpoint affected retained counts; it does not rescue a failed health
control or justify running pressure against an unhealthy environment.
