# G1-R4B application finality v1

Status: **candidate-implemented / exact-head restack qualification pending / no Gate promotion**

## Exact source and provenance boundary

```text
repository = TrillionniumFoundation/Trillionnium-Chain
base_ref = feature/chain-p2-node-candidate-devnet-cli-v1-20260831
base_commit = fddc8e919a77f3be42b72ad4b8a7f8ff91d7abdc
base_tree = 6eee331a3baea8c91ad33328602580b9ef6dc271
restack_branch = integration/native-poco-a04-a19-stack-v1-20260901
reviewed_source_commit = 1fa71c942e129ce88937a030c3054c8f72649aaf
reviewed_source_tree = b2c9301d53d05c21b6835ae5ffb7aab4ae52c6f4
reviewed_import_commit = f38df4ec81cb76f92c709d8cd45311e164fa5753
reviewed_original_base = 6e0189e351015ef3230f217ca7ff86149baedcf0
application_blob_before = 730b0c0233fe260d70c4cbeef165cb7051585fd1
application_blob_after = 9e448b80d4ebc912d9eb2fd346ad60ff55738332
lib_blob_before = e952aa8dd3b5fad21fa96242cd824a745b76e263
lib_blob_after = 536eb1c198e1127a766eb11f0cee9ae7fd5bae3d
tests_blob_before = 0cb02b4f68cf0941320fcb9616b26b187f60e651
tests_blob_after = 2ad5cc7ddd1910f0e62e0b42cdbc46b2d0d8e476
consensus_mainline = native-poco-bft
protocol_target = poco-bft-v0
production_candidate = false
production_consensus_activation = false
```

The three Rust destination blobs on the exact qualified Node head were proven
byte-identical to the reviewed A04 predecessor blobs before transplantation.
Only the reviewed post-A04 blobs are imported; obsolete branch ancestry and
one-shot publisher files are excluded.

## Implemented candidate boundary

The application-owned finalization slice provides:

- host-neutral `NativeFinalizationIntentV0`;
- exact structural `NativeFinalizationApplyReadbackV0`;
- bounded `NativeFinalizationQueueV0` and retry dispositions;
- contiguous ascending enqueue and front-only acknowledgement;
- exact replay idempotence and conflicting replay rejection;
- target, proof, overlay, body, JMT-plan and state-root identity checks;
- retained-fork records and bounded reclamation rules;
- multi-successor, response-loss, duplicate, reorder, skip and fork vectors.

A local `AppCommitted` result is not Core-ack eligible by itself. This slice does
not mint Core, Safety, signer, checkpoint or production-node authority.

## Required exact-head verification

```text
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
cargo check --manifest-path trillionnium/Cargo.toml --workspace --all-targets --locked --offline
cargo clippy --manifest-path trillionnium/Cargo.toml \
  -p trnm-native-application --all-targets --locked --offline -- -D warnings
cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-native-application --all-targets --locked --offline
```

The same exact head must also preserve capability-authority, repository-truth,
blocker-ledger, canonical-plan, Native PoCO pre-cutover, project-boundary and
offline-input invariants.

## Remaining fail-closed boundaries

This candidate does not by itself establish permit-bound live proposal
execution, cross-store application/Core/Safety/checkpoint atomicity, an external
anti-rollback floor, authenticated live-reference inventory, live process
effect ownership, physical power-loss evidence, independent review, multi-host
campaign evidence, production readiness or activation. It is the prerequisite
carrier for A19 terminal history and A23 finalized replay-floor enforcement.
