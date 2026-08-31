# A23 / P2 native finalized replay floor v1

Status: **candidate-implemented / exact-head qualification in progress / no Gate promotion**

## Exact source and patch boundary

```text
repository = TrillionniumFoundation/Trillionnium-Chain
base_ref = integration/native-poco-a04-a19-a23-v1-20260831
base_commit = 50e05d9eff6d12050bf792d8d1ea0ad74314a481
base_tree = 2d351c0082580976fcceda527eb198ba2939848f
target_ref = integration/native-poco-a04-a19-a23-qualified-v1-20260831
patch_sha256 = 3978ee7a03650c8e4add0d3818d5ed3913d171a55b22404563fc173bdef20e85
generator_commit = ca172504a975565ac329757c0e0fb3568f7b7985
generator_blob = a1af430ec06a6cbb826a8d5d31d1dd60c10314a4
consensus_mainline = native-poco-bft
protocol_target = poco-bft-v0
production_candidate = false
production_consensus_activation = false
```

The exact seven-file patch was frozen before this run. The qualifier
reconstructs it from two content-addressed carrier blobs, verifies its
SHA-256, applies it only to the exact A04+A19 source tree, formats it with
Rust 1.95.0, and accepts no unexpected path or Cargo.lock change.

## Implemented repository-owned boundary

The candidate derives a signer-local replay floor only from strictly
verified native finality and durable application history. The verified
floor is bound to application owner affinity, durable store identity,
canonical signer resolution, WAL namespace and the frozen retention
policy. Tombstone deletion requires the non-cloneable verified floor;
an unverified height, local cache value or caller-supplied signer cannot
authorize reclamation.

This slice does not start a production validator, mint signing authority,
establish cross-store atomicity, supply an external anti-rollback anchor,
prove physical power-loss durability, or promote any production flag.

## Required exact-head verification

```text
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
cargo check/clippy/test: trnm-native-execution-v0
cargo check/clippy/test: trnm-poco-node --features tx-admission-wal
cargo test: trnm-native-application and trnm-native-application-sqlite
capability-authority audit and compile-fail proofs
CI runner/offline policy
repository/blocker/canonical-plan/pre-cutover/project truth
Cargo offline inputs unchanged
```

## Remaining fail-closed boundary

Live default-node integration, process-2 recovery/state sync,
descriptor-anchored whole-node storage, production remote signing,
external monotonic anti-rollback, authenticated cross-platform P2P,
production transaction ingress/broadcast, real multi-host campaigns,
physical power-loss, independent audit and soak remain separate evidence
predicates. No absent evidence is inferred from this repository slice.
