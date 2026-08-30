# A21 / P1 seal native commit-receipt verifier v1

Status: **module-closed candidate / exact-source verified / no production activation**

## Exact boundary

```text
repository = TrillionniumFoundation/Trillionnium-Chain
base_ref = feature/chain-a20-p2-tx-tombstone-gc-v1-20260830
base_commit = 0aeb5a797b3726c6657b003b44f7ec0040d7d423
verified_source_commit = c05364e7324fe3ff2c4a8b22322698a0cddd5dc1
verified_source_tree = a8626c41ea26bfb808d5a4aba07082849077954e
verification_workflow = trnm-a21-seal-native-commit-verifier
verification_run = 33315018262
verification_conclusion = completed/success
consensus_mainline = native-poco-bft
protocol_target = poco-bft-v0
production_candidate = false
```

The verified source is unsigned and is not release-signature evidence. This
documentation descendant binds the tested source; it does not replace or
silently promote it.

## Security defect

`NativeCommitReceiptEvidenceV0::verify_with` returns the private
`VerifiedNativeCommitReceiptV0` capability consumed by both the live candidate
commit path and restart handoff recovery. Before this package, any downstream
crate could implement `NativeCommitReceiptVerifierV0` as an always-accept
verifier and mint that durable commit capability from shape-valid caller
assertions.

## Candidate repair

- make `NativeCommitReceiptVerifierV0` extend a private sealed supertrait;
- implement the seal only for the real `DurableNativeCommitReceiptVerifierV0`
  and explicitly named in-module test verifiers;
- retain the public read-only verifier contract and private token fields;
- add a downstream `compile_fail` proof that an external always-accept verifier
  cannot implement the authority;
- add a focused sealed-authority regression;
- expose a machine truth constant and Cargo metadata bit for the sealed boundary;
- leave native readback production activation, CheckTx, signing, broadcast,
  production candidacy and consensus activation false;
- remove the write-capable one-shot workflow and transform script from the exact
  tested source tree before publication.

## Exact-source evidence

```text
workflow = trnm-a21-seal-native-commit-verifier
run = 33315018262 completed/success
immutable hardening source = success
Rust 1.95.0 = success
workspace all-targets compile = success
trnm-poco-node tx-admission-wal Clippy -D warnings = success
downstream commit-verifier forgery compile-fail = success
sealed-authority regression = success
A20 tombstone regressions = success
retained transaction-admission WAL regressions = success
canonical Plan = success
Native PoCO pre-cutover truth = success
clean source tree = success
exact tested source push = success
```

The executed source checks included:

```text
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
cargo check --manifest-path trillionnium/Cargo.toml --workspace --all-targets --locked
cargo clippy --manifest-path trillionnium/Cargo.toml \
  -p trnm-poco-node --features tx-admission-wal --lib --locked -- -D warnings
cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-poco-node --features tx-admission-wal --doc --locked
cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-poco-node --features tx-admission-wal --lib \
  tx_admission_wal::tests::native_commit_verifier_authority_is_sealed_v1 \
  -- --exact --nocapture
cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-poco-node --features tx-admission-wal --lib \
  tx_admission_wal::tombstone_gc_tests_v1 -- --nocapture
cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-poco-node --features tx-admission-wal --lib \
  tx_admission_wal::tests -- --nocapture
```

## Authority boundary after repair

The only non-test implementation is the concrete
`DurableNativeCommitReceiptVerifierV0`, which joins the admitted exact builder
carrier to durable native application readback and a carried native PoCO
finality proof. Downstream callers can request verification and consume the
resulting opaque token, but cannot substitute a verifier implementation.

This closes the repository-owned capability-forgery seam. It does not establish
production ownership of the application/proof lifetimes, independently accept
the finality interface, or make the candidate node production-ready.

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
multi_host_campaign_closed = false
external_anchor_hsm_closed = false
physical_power_loss_closed = false
independent_audit_closed = false
wall_clock_soak_closed = false
g1_exit = false
production_candidate = false
production_consensus_activation = false
release_ready = false
```

The repair prevents downstream capability forgery. It does not create a
production application/finality lifetime owner and does not resolve independent
review, HSM/anchor, physical power-loss, multi-host, audit or soak blockers.
