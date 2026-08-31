# G1-R4B application finality v1

Status: **candidate-implemented / exact-head qualification pending / no Gate promotion**

## Exact source and provenance boundary

```text
repository = TrillionniumFoundation/Trillionnium-Chain
base_ref = feature/chain-p2-node-candidate-devnet-cli-v1-20260831
base_commit = fddc8e919a77f3be42b72ad4b8a7f8ff91d7abdc
base_tree = 6eee331a3baea8c91ad33328602580b9ef6dc271
branch = integration/native-poco-a04-a19-a23-v1-20260831
reviewed_import_commit = f38df4ec81cb76f92c709d8cd45311e164fa5753
reviewed_import_tree = bf7bbf43b8a783ffc443b1105f8f53aa406efff1
reviewed_original_base = 6e0189e351015ef3230f217ca7ff86149baedcf0
canonical_a04_commit = 1fa71c942e129ce88937a030c3054c8f72649aaf
base_application_blob = 730b0c0233fe260d70c4cbeef165cb7051585fd1
base_lib_blob = e952aa8dd3b5fad21fa96242cd824a745b76e263
base_tests_blob = 0cb02b4f68cf0941320fcb9616b26b187f60e651
imported_application_blob = 9e448b80d4ebc912d9eb2fd346ad60ff55738332
imported_lib_blob = 536eb1c198e1127a766eb11f0cee9ae7fd5bae3d
imported_tests_blob = 2ad5cc7ddd1910f0e62e0b42cdbc46b2d0d8e476
consensus_mainline = native-poco-bft
protocol_target = poco-bft-v0
production_candidate = false
production_consensus_activation = false
```

The three Rust destination blobs on the exact qualified Node head were proven
byte-identical to the reviewed A04 transplant base before the reviewed head
blobs were reused. No historical merge ancestry, publisher workflow, generated
artifact, or diagnostic path is imported.

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
not mint Core, Safety, signer, checkpoint, migration, production-node, or
activation authority.

## Required exact-head verification

The exact unchanged candidate must pass on the dedicated X230 runner with Rust
1.95.0 and the frozen offline Cargo cache:

```text
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
cargo check --manifest-path trillionnium/Cargo.toml --workspace --all-targets --locked --offline
cargo clippy --manifest-path trillionnium/Cargo.toml \
  -p trnm-native-application --all-targets --locked --offline -- -D warnings
cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-native-application --all-targets --locked --offline
```

Repository truth, capability-authority audit, canonical-plan truth, Native PoCO
pre-cutover truth, project boundary and Cargo-input immutability must remain
valid on the same source commit.

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

The queue/readback API is therefore the exact prerequisite for A19 durable
history and A23 replay-floor integration, not a claim that `P1-EXEC-001`, G1,
or P2 has exited.
