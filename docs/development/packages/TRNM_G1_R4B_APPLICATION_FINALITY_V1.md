# G1-R4B application finality v1

Status: **candidate-implemented / canonical qualification pending / no Gate promotion**

## Exact source and provenance boundary

```text
repository = TrillionniumFoundation/Trillionnium-Chain
base_ref = feature/chain-p2-node-candidate-devnet-cli-v1-20260831
base_commit = eb0f1de90d2baa5d0f8a7ef1975d7914bd9d4af9
branch = feature/chain-a04-g1-r4-application-finality-canonical-v1-20260831
reviewed_import_commit = f38df4ec81cb76f92c709d8cd45311e164fa5753
reviewed_import_tree = bf7bbf43b8a783ffc443b1105f8f53aa406efff1
reviewed_original_base = 6e0189e351015ef3230f217ca7ff86149baedcf0
consensus_mainline = native-poco-bft
protocol_target = poco-bft-v0
production_candidate = false
production_consensus_activation = false
```

All three modified Rust destination blobs were proven identical between the
current canonical base and the reviewed original base before the reviewed head
blobs were transplanted. The obsolete historical branch ancestry is not merged.

## Implemented candidate boundary

The application-owned finalization slice provides:

- host-neutral `NativeFinalizationIntentV0`;
- exact structural `NativeFinalizationApplyReadbackV0`;
- bounded `NativeFinalizationQueueV0` and retry dispositions;
- contiguous ascending enqueue and front-only acknowledgement;
- exact replay idempotence and conflicting replay rejection;
- target, proof, overlay and state-root identity checks;
- retained-fork records and bounded reclamation rules;
- multi-successor, response-loss, duplicate, reorder, skip and fork vectors.

A local `AppCommitted` result is not Core-ack eligible by itself. This slice does
not mint Core, Safety, signer or checkpoint authority and does not activate a
production node.

## Required canonical verification

The exact candidate must pass on the dedicated X230 runner with Rust 1.95.0 and
the frozen offline Cargo cache:

```text
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
cargo check --manifest-path trillionnium/Cargo.toml --workspace --all-targets --locked --offline
cargo clippy --manifest-path trillionnium/Cargo.toml \
  -p trnm-native-application --all-targets --locked --offline -- -D warnings
cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-native-application --all-targets --locked --offline
```

## Remaining fail-closed boundaries

This candidate does not establish:

- an accepted permit-bound body/header/overlay/JMT carrier for arbitrary live
  proposals;
- cross-store application/Core/Safety/checkpoint atomicity;
- a cryptographically bound external receipt or anti-rollback floor;
- authenticated live-reference inventory and production fork reclamation;
- live process/effect-driver ownership;
- physical power-loss or independent multi-host evidence;
- production, public-testnet, release, normative-freeze or activation status.

The queue/readback API is therefore a prerequisite candidate for A19 durable
history and later cross-store integration, not a claim that `P1-EXEC-001` or G1
has exited.
