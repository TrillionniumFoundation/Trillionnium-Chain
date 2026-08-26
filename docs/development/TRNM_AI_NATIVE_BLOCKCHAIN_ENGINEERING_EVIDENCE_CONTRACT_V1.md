# TRNM AI-native Blockchain Engineering Evidence Contract v1

Status: supporting execution contract for the sole canonical development plan

Canonical plan: `TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`

This document defines the minimum shape of evidence that may advance a gate. It
is not a second roadmap and it cannot change `config/consensus-mainline.json`
or any protocol status flag. A result without the fields below is an
observation, not promotion evidence.

## 1. Authority and reproducibility

Every evidence bundle is produced from one clean, committed tree and contains:

```text
evidence_id
gate_id                 # G0, G1, G1.5, G2A..G2F, G3, G4, G5
plan_id
plan_sha256
source_commit
source_tree_hash
protocol_manifest_sha256
machine_truth_before
machine_truth_after
toolchain_lock
artifact_sha256          # binary/image/SBOM/provenance roots
exact_commands
topology_manifest
workload_manifest
fault_schedule
raw_artifact_index
negative_controls
known_gaps
reviewers
signature_set
scope                    # crate, fixture, process, host, network, production
authority                # candidate, simulation, normative, production
classification           # candidate-non-normative, reproducible, accepted, ...
```

`scope`, `authority`, and `classification` are mandatory. Candidate-local
evidence is represented by its explicit scope/authority and must never use an
unqualified production-looking flag. A promotion record changes only the
flags listed in `machine_truth_after`, and the change is rejected if the source
tree, plan digest, or protocol manifest differs from the signed bundle.

The evidence index must be replayable in a clean clone with no private workspace,
mutable service, or network dependency unless that dependency is declared in
the topology manifest and captured as an immutable fixture. Raw traces,
negative mutants, failed runs, and superseded bundles are retained; a later
success does not erase a failed safety result.

## 2. Canonical vertical trace

An enabled operation kind is not complete until one trace row binds the same
bytes and digests across every plane:

```text
CEV1 schema/domain
  -> AgentTransactionV1 admission
  -> TransactionBatch and content root
  -> DA certificate / BatchRef / ArtifactEvidence
  -> proposal and vote predicate
  -> deterministic execution receipt
  -> application JMT and post_state_root
  -> result/challenge/settlement proof
  -> RPC/WS, SDK, indexer, vectors, and status flag
```

The row records object type, version, domain separator, size/depth limits,
content digest, parser implementation, verifier, retention/expiry policy, and
the exact vector or replay command. A local kernel or SQLite readback may fill a
candidate row but cannot fill an integrated-alpha or production row without a
Node-owned authority, authenticated transport, durable CAS, and independent
replay.

## 3. Wire and transaction conformance

The conformance bundle freezes three separately versioned surfaces:

1. logical CEV1 transaction/object codec;
2. authenticated P2P proposal/vote/DA transport; and
3. RPC/WS and proof response codecs.

For each enabled object, two independent parsers must agree on canonical bytes,
roots, and error classes. The corpus must include unknown fields, trailing
bytes, duplicate signers, cross-version domains, nested length/depth overflow,
oversized artifacts, invalid signatures, replayed nonces, and resource-budget
exhaustion. Fuzz and mutation results are signed and retained, including every
counterexample.

## 4. AI verification and settlement profiles

The launch profile registry is versioned. Each profile has independent fields
for `implemented`, `enabled`, `activation_gate`, `order_authority`,
`result_authority`, and `settlement_authority`. A disabled or unknown profile is
rejected during admission; it cannot silently fall back to a weaker profile.

For deterministic re-execution, reproducible ML, ZK, TEE, stake-quorum,
optimistic, and subjective profiles, record the statement, evidence backend,
trust root, model/runtime/data provenance, expiry and revocation, challenge and
appeal path, bond/fee rule, and negative vectors. Subjective verification can
produce an explicitly subjective result only; it cannot create objective
settlement or PoCO weight without a separately authorized rule.

Settlement evidence must bind `SettlementIntent` and `SettlementReceipt` to the
admitted transaction, DA/Order roots, execution/JMT root, result finality,
challenge maturity, and exactly-once crash/retry semantics. Conservation covers
all assets and every escrow, bond, reward, slash, refund, fee, treasury, dust,
and rounding path.

## 5. Benchmark contract

Every comparison uses a signed `benchmark-manifest-v1` containing workload
grammar and exact bytes, operation mix, batch/block/resource caps, AI profile,
hardware/OS/toolchain/container, process/host/operator/region topology, RTT and
fault schedule, seed, warm-up, run count, percentile denominator, confidence
interval method, raw trace index, cost normalization, and comparator commit or
container digest. “Committed goodput” and “finality” definitions are explicit;
submitted/ingress TPS is never substituted. Release floors and shadow targets
are separate fields and cannot be silently compared.

## 6. Gate invalidation and recovery

A failed invariant, source/protocol digest change, Order replacement, migration
parameter change, or reopened Critical/High finding invalidates the affected
gate and every downstream evidence bundle. The owner records the invalidation
edge, rerun set, retained negative mutant, and new source/plan digests. A
post-finality rollback never copies a PoCO database or WAL back to Comet; recovery
after activation is only through the authorized PoCO governance migration path.
