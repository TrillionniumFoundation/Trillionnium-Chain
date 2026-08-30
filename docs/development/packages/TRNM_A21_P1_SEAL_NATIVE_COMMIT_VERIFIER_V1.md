# A21 / P1 seal native commit-receipt verifier v1

Status: **candidate implementation generated; exact-head verification required; no production activation**

## Security defect

`NativeCommitReceiptEvidenceV0::verify_with` returns the private
`VerifiedNativeCommitReceiptV0` capability consumed by the durable handed-off
commit transition. Before this package, any downstream crate could implement
`NativeCommitReceiptVerifierV0` as an always-accept verifier and mint that
capability from shape-valid caller assertions.

## Candidate repair

- make `NativeCommitReceiptVerifierV0` extend a private sealed supertrait;
- implement the seal only for the real `DurableNativeCommitReceiptVerifierV0`
  and explicitly named in-module test verifiers;
- retain the public read-only verifier contract and private token fields;
- add a downstream `compile_fail` proof that an external always-accept verifier
  cannot implement the authority;
- expose a machine truth constant and Cargo metadata bit for the sealed boundary;
- leave native readback production activation, CheckTx, signing, broadcast,
  production candidacy and consensus activation false.

## Required exact-head evidence

```text
workspace all-targets compile
trnm-poco-node tx-admission-wal Clippy -D warnings
downstream verifier-forgery compile-fail doctest
new sealed-authority regression
all retained transaction-admission WAL regressions
canonical Plan and Native PoCO pre-cutover truth
clean source tree with no write-capable one-shot workflow or transform script
```

## Non-claims

```text
tx_admission_native_commit_verifier_sealed = true
tx_admission_boundary_native_readback = true
tx_admission_boundary_native_readback_production = false
tx_admission_handoff_readback = false
tx_admission_boundary_production_activation = false
tx_admission_boundary_signing = false
tx_admission_boundary_broadcast = false
independent_review_closed = false
g1_exit = false
production_candidate = false
production_consensus_activation = false
release_ready = false
```

The repair prevents downstream capability forgery. It does not prove that the
real durable verifier is production-owned, does not create a production
application/finality lifetime owner, and does not resolve external review,
HSM/anchor, physical power-loss, multi-host, audit or soak blockers.
