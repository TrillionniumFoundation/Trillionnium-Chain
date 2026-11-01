# PQ system continuation: native network admission and external witness

Status: **HOLD / whole-chain UNQUALIFIED**. This record refines the existing
[whole-chain claim guard](WHOLE_CHAIN_PQ_CLAIM_GUARD_20261031.md) and the sole
[development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
It does not activate a profile or change release authority.

## Source and evidence boundary

The original Chain input is [#678 at 5606a971](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/5606a97104f9cd3243befc2921ccace3fae2c369).
The current composition also retains the concurrent [64cb26b5 upstream](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/64cb26b53ed82be14049000387040ba119f00e1e), including its bounded full-root arithmetic work,
original controls and separate workspace CPU workflow. Both Node constructor
fields and all upstream changes are retained; source pins identify the actual
combined bytes. The first local build on the earlier source received SIGKILL
and executed no native tests. Its full failure record remains in the evidence.
The paired Hepta policy fix is [#4558](https://github.com/TrillionniumFoundation/hepta-private-ci/pull/4558),
initially based on #4552 at `0f7c63418a7eec6cff5e4348e8cdc733850f8386`.
Neither input is the default main branch. Separate candidate passes cannot be
added together to certify a combined Chain/Hepta installation.

A scratch cleanup removed the earlier unpublished Chain working files and raw
records. The native work was reconstructed from retained edits and is a new
candidate. Earlier compilation, Clippy and partial test observations are not
current acceptance evidence. The preserved Hepta publication payload was saved
without alteration; subsequent Hepta checkpoint corrections and native Rust
1.96 execution are separately bound to their own exact source.

Current command records belong in the
[continuation evidence](../../evidence/pon-pq-system-continuation-20261101/README.md).
The [command recorder](../../scripts/ci/record_pq_native_command.py) verifies raw
tracked source bytes before and after each command, retains failed exit codes,
and hashes complete logs. It records command success only. The original
[named-test reader](../../scripts/ci/check_required_native_test.py) separately
requires each real execution; empty filters, ignored tests, absent receipts and
child-process harness entry points cannot supply a missing control.

## Native admission correction

PNQ2 admission preserves the original absolute request deadline while waiting
for the native owner lock. It checks liveness before and after durable resource
charging, after signature verification, before request admission and cached
replay, and before a successful response. A signature failure still consumes
its durable verification charge. It does not consume the unused request sequence
needed by a later valid request.

The positive control submits a real PQ transfer and checks the resulting balance
and cold-reopened budget state. The negative controls exercise elapsed deadlines,
lock contention, signature expiry and cancelled intake. Synchronous cryptography
and an in-flight SQLite operation are not advertised as immediately preemptible.
If a business effect has completed, its real result must still be persisted;
withholding a late success response does not undo the effect.

## External witness correction and limits

The explicit `PqWitnessV4` namespace adds a native service/client and SQLite CAS
integration for the three PNQ2 state tables. The
[witness contract](PQ_NETWORK_DURABLE_WITNESS_V1.md) specifies the signed domains,
binding, explicit provisioning, crash order, file-owner assumptions, independent
state and original request deadline propagation.

The external service persists its own state and authenticates fresh client
challenges. A local mutation checks the current predecessor, updates its SQL
state, advances the external checkpoint and then commits locally. A lost reply
or failed local commit cannot be converted into invented success or silently
re-enrolled state. An authenticated, matching CAS success received late is a
known external effect: local completion must retain consistency before the
request is refused as late. The result is fail-closed when recovery is uncertain;
it is not a complete automatic recovery protocol.

This does **not** authenticate all account balances, History, CURRENT, FinalUse,
installed artifacts, settlement or governance state. A snapshot whose protected
PNQ2 state has not changed is outside this rollback detector's guarantee. The
writer and witness service are trusted to follow the protocol, the writer key
must remain protected, and the witness's independent database must not be rolled
back with the Node. A fresh current-state check is not a distributed lease and
does not establish safety for cloned concurrent business writers. The Unix
adapter is not authenticated encrypted WAN transport or an operationally
independent deployed quorum.

## Hepta authorization correction and remaining composition

The PQ dispatcher now binds lease renewal to the exact persisted owner-policy
revision and digest inside its SQLite renewal transaction. Same-key policy
revocation cannot be bypassed by a stale snapshot or the unbound renewal API once
the owner-policy floor exists. The transaction is the policy linearization point;
revocation after commit and before a remote effect remains a separate problem.

The final Hepta follow-up also serializes ordinary replay-checkpoint sync with
trust refresh under the existing owner mutex. A real ARM product failure exposed
two callers reading the same external predecessor before one advanced it. The
new deterministic concurrency control requires both valid callers to complete,
rejects a genuinely old witness and then restores signed service after exact
witness repair. It does not weaken rollback checks or extend test timeouts.

Normal Cell V2 startup from #4497 and PQ profile validation from #4552 still need
one combined source tree and real qualification-to-CURRENT-to-load/read/unload
tests. RunStart and ObjectiveStart require versioned producers, authenticators,
both normal and conflict journal encodings, decoders, revocation and an external
freshness owner. Rejecting the current classical format is necessary but is not
the successful PQ business path. The precise pinned dependencies are recorded in
[Hepta's migration analysis](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/cd3c1b860f2b0f05c24bfb8d4b5da6ba7f99704a/qualification/pq-policy-renewal-20261101/MIGRATION_DEPENDENCIES.md).

## All six qualification gates remain open

| Gate | This continuation supplies | Still required for a whole-system claim |
| --- | --- | --- |
| Complete authorization | Live PNQ2 admission and policy-bound Hepta renewal controls | Every normal effect path, composed Cell/FinalUse, RunStart/ObjectiveStart, upgrade, revocation and recovery under the same protected PQ profile |
| Proof PQ-128 | No change to proof acceptance or claimed security level | Exact full relation and verifier parameters, quantum soundness, recursive composition and independent cryptographic review |
| Quantum work and fork choice | No change to W1, difficulty or chainwork | Complete reversible W1 cost, amortization and cheapest valid work, quantum search, DAA/timestamps, forks and propagation under original budgets |
| Migration and rollback | Explicit native witness for three PNQ2 tables | Historical assets and liabilities, all effect-bearing state, independently administered monotonic trust, conflict recovery and actual deployed cold-restoration acceptance |
| Capacity and invalid input | Original ingress budgets and real invalid/valid controls retained | Original full-state/History/work/service budgets, adversarial load, memory and latency, sustained authenticated confidential network service where private data requires it |
| Independent end-to-end | Exact-source local/CI records, x64/ARM and head/merge lanes | One reproducible Chain/Hepta configuration, independent reviewers and operators, sustained WAN/fault tests, then the existing activation process |

The new CI workflow is additional component evidence. Existing original-budget
and retained full-workspace lanes remain in force. No budget is raised to obtain
a pass. No `physical_rollback_resistant`, `public_wan_accepted`,
`hepta_final_use_integrated`, `quantum_pon_hardness_qualified` or production flag is
promoted by these changes.

ML-DSA is a signature scheme ([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final));
ML-KEM establishes shared key material ([FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)).
Neither algorithm name alone proves authenticated confidential transport,
quantum-resistant proof soundness or quantum work/fork-choice safety.
