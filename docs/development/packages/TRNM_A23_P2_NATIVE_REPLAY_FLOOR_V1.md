# TRNM A23 P2 native replay-floor v1

## Scope

This package closes the repository-owned native replay-floor adapter left open by A20. It does not activate production transaction admission or alter any Gate/release flag.

## Authority chain

1. `DurableNativeApplicationV0` freshly validates a committed durable-P row.
2. The exact `FinalityProofV0` is strictly verified with the store's validator set, parameters, parent timestamp, and `StrictEd25519Verifier`.
3. The private committed signer-nonce set must contain every nonce in the exact signer-local prefix `1..=floor`; one gap rejects the claim.
4. A non-Clone, private-field `VerifiedNativeSignerReplayFloorV1` carries only signer, floor, height, root, proof digest, store identity, and owner affinity.
5. The sealed Node verifier binds that application signer to the installed canonical signer resolver, exact WAL namespace, and one frozen retention-policy digest.
6. Only the resulting private `VerifiedTxAdmissionReplayFloorV1` can delete compact tombstones, and it is consumed inside the Node boundary.

## Negative properties

- caller-supplied height, state root, finality digest, and policy digest are not accepted;
- a missing nonce in the claimed prefix fails closed;
- a foreign signer cannot inherit another signer's prefix;
- an unauthenticated three-chain fails before WAL mutation;
- neither verified fact is Clone, serializable, or constructible outside its owner module;
- no Core, Safety, signer, storage-ack, network, broadcast, or activation authority is returned.

## Non-claims

Independent review, branch protection, hardware anchor/HSM evidence, physical power-loss tests, multi-host campaign evidence, external audit, and wall-clock soak remain external acceptance requirements.

## Exact restacked source binding

```text
base_ref = feature/chain-a19-p1-exec-terminal-history-v2-20260830
base_commit = fa7aa82a5fa8fe1910b26845caae99784211746b
base_tree = 18fea587635d41675b8a654e6e49787bc2ac2629
generator_commit = ca172504a975565ac329757c0e0fb3568f7b7985
generator_blob = a1af430ec06a6cbb826a8d5d31d1dd60c10314a4
production_candidate = false
production_consensus_activation = false
```

## Exact A04/A19 restacked qualification binding

```text
source_ref = integration/native-poco-a04-a19-stack-v1-20260901
source_commit = 8eda2af07b0a61f0b0846926e912354fdde95b20
source_tree = 762a0329c084d6518c7123f16a77fb408df4bb61
a04_commit = d8e68c0dc5d9b8950331c2e060be11ed904cf732
pr55_head = fddc8e919a77f3be42b72ad4b8a7f8ff91d7abdc
patch_sha256 = 3978ee7a03650c8e4add0d3818d5ed3913d171a55b22404563fc173bdef20e85
production_candidate = false
production_consensus_activation = false
release_ready = false
```
