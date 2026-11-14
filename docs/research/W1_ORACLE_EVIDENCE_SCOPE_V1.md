# W1 reversible construction, submitted proof and native admission

Status: **HOLD / NO-GO for quantum mining security and production qualification.**

The fixed-context W1 reversible winner predicate has been constructed. It binds
the nonce, all bounded noise branches, arithmetic and ordered transcript,
ticket/target comparison, phase and inverse. The retained
[construction record](../../evidence/pon-quantum-construction-20261104/README.md)
contains 17 construction controls and five cases: three native-sized macro
executions and two reduced-shape leaf-gate executions. These are software
observations with their original source identities, not quantum hardware runs.

This continuation separates four questions which a single Boolean cannot answer:

| Question | Evidence and scope |
| --- | --- |
| Is a fixed-context circuit constructed? | Rebuild the selected full or restricted program and its census from exact source. |
| Was that circuit executed here? | Record this invocation's execution mode, selected input and clean inverse separately from construction. |
| Is the submitted native proof valid and admitted? | Replay the complete proof and compare the original native process observations for the same packet and source. |
| Is quantum mining secure? | Remains unqualified: construction and finite differential checks supply neither an optimal attacker nor a work lower bound. |

## Preserve the historical accounting interface

The V1 generic resource accountant accepts caller-supplied circuit budgets. Its
`full_W1_oracle_constructed=false` is a report-local limitation: that invocation
does not construct or authenticate a complete W1 circuit. The same field in the
V1 adversarial assumptions describes that model's assumed successful predicates.
Neither is a repository-wide statement that no construction exists.

Do not change those V1 payloads or relabel their historical receipts. Their
exact dictionaries and source digests participate in deterministic replay.
The new [scope reader](../../formal/pon-nakamoto-v1/w1_quantum_evidence_scope.py)
uses a separate schema and rebuilds program structure before describing it.
Caller strings, including `constructed-w1/` provenance, cannot upgrade an
unverified budget into a constructed program.

The new reader distinguishes the complete fixed-context predicate, a legal
restricted search predicate, reduced-shape controls and caller-only budgets.
The restricted program's use of the full program's resource code does not make
its accepted nonce set the full predicate. A census is not a record of the
historical five executions or of this invocation executing a quantum search.

## Cost interpretation

The existing full PNH1 construction uses 22,253,173 logical qubits and
17,718,016,715 compute-Z-uncompute gates, with a serial depth upper bound of
1,969,835,151. Its PGH2 counterpart has separate framing and a distinct census.
The retained legal restricted construction already reduces the PNH1 phase gate
count to 15,992,168,955 and the depth upper bound to 1,102,032,975.
See the [research note](../../formal/pon-nakamoto-v1/QUANTUM_DAA_RESEARCH.md)
for the actual schedules, data access and probability assumptions.

These are constructive logical resource upper bounds for particular circuits.
They are not lower bounds on the cheapest legal attacker, and are not calibrated
physical qubits, elapsed time or attack economics. An attacker may use a different
algorithm, preprocessing, a restricted nonce set, task reuse or parallelism.
Fewer gates per restricted oracle do not establish a cheaper mining campaign
at the same success probability; the restricted marked mass and all attempts
must be accounted for separately.
The abstract event model's success law is not established merely by connecting
it to a circuit-derived clock. No square-root chainweight or protocol activation
follows from these records.

## A current-source packet bridge

The [native bridge](../../formal/pon-nakamoto-v1/w1_quantum_native_bridge.py)
reads an externally pinned archive, validates its original source guards and
native process readback, and evaluates the same PGH2/PNP2 packet through the
independent scalar W1 relation and the native-sized reversible macro program.
It compares challenge, transcript, ticket, winner, phase, nonce preservation and
clean uncomputation. The input archive, source, tree, original preregistration
and binary identities remain distinct from the new reader's source and results.

The frozen input cohort is the original native-fullpath artifact from source
`e4abb172147e941b62483652b0ceabaae4317624`, GitHub Actions run `42830743579`,
job `129927393431`, artifact `13785762485`. The
[evidence record](../../evidence/pon-w1-oracle-scope-20261110/README.md) retains
the original ZIP and its externally read digest. The new bridge does not rerun
the original native binary or transfer its observations to a different source.
Archive consistency is not an independent execution attestation.

The original late-product packet is a required counterexample. Its header,
nonce, A/B matrices and transcript match the valid packet while its submitted
C matrix is corrupt. The winner predicate can still mark this nonce, because
it computes its own mathematical product. The complete submitted-proof replay
must reject `PRODUCT`, and the original native receiver must reject
`WORK:Product`. A winning nonce cannot authorize a corrupt submitted proof.

The original duplicate and cancelled attempts remain distinct: neither supplies
another newly admitted block or another complete native verification. The
recorded local block has depth zero and zero timely accepted progress under the
original service contract. The native test's 16 newly sealed wrong-context cases
also remain one native test method, not 16 independent safety proofs.

### Retained collector identity after current-source improvements

The retained cohort names source
`e4abb172147e941b62483652b0ceabaae4317624` and tree
`016ebf3deeac88d6d7a782edf563f2291ebe17f5`. Its context commits to
collector SHA256
`f40c5d621454d0532141920724a3cfd57e240f4a3b061536162313daa676c254`.
The current collector has since acquired exact-source verification. Replacing
that historical context digest with the current collector would change the
meaning of the retained observation.

For this one source, the reader requires the exact historical tree and context
digest, then reads the original 23,639-byte
[collector as data](../../formal/pon-nakamoto-v1/fixtures/native-collector-e4abb172.py.raw)
through the existing bounded regular-file reader. It verifies the independent
SHA256, byte count and Git blob identity. Missing data, a changed tree, a different
producer, symlinks and nonregular files are refused; the historical source does
not fall back to the current collector. Other sources retain the existing
current-collector comparison. The raw historical producer is included in the
reader's source commitment and is never imported, compiled or executed.

The [fixed Git provenance](../../evidence/branch-consolidation-followup-20261114/native-collector-history-v1/README.md)
retains the original commit and three tree objects linking that source to the
collector blob. Their content addresses were checked independently during this
correction. This is a source-content binding, not an independent authentication
of the external pins or proof that a native binary was built or executed from
that source. The original ZIP, context and saved reports keep their original
bytes; no new native execution, service acceptance or qualification is claimed.

## Acceptance boundary and remaining work

The engineering exit for this continuation is a reproducible separation of
construction scope and exact-packet observations, with rejection of substituted
sources, altered packets, missing evidence and unsupported qualification flags.
Both new control suites are required in the existing repository-truth lane;
their omission, duplication, reordering and suppressed failures are rejected.

The following remain open regardless of this reader's success:

1. Physically calibrated fault-tolerant execution, routing, data access, reset,
   measurement and whole-campaign reliability.
2. An attacker-minimal cost argument or suitable lower bound over the actual
   legal strategy space, including reuse and amortization.
3. The actual legal-domain success law, correlations, freshness and quantum
   search strategies for the deployed relation.
4. Joint classical/quantum DAA, timestamps, fork choice, network scheduling,
   common-prefix/growth/quality and transaction-liveness analysis.
5. Full current native/public-network service and recovery qualification.

`quantum_hardware_executed`, quantum mining/security qualification and production
activation remain false. Unknown physical costs and security bounds remain
unknown. A passing source, replay or finite control suite cannot close them.
