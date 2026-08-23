# External node-checkpoint CAS v0

This crate supplies one explicit Unix client/daemon adapter for the canonical
`trnm-poco-node::ExternalNodeCheckpointStoreV0` contract. The daemon owns a
private append-only hash-chain journal and durable head anchor. Successful
records bind the exact scope, expected checkpoint, target checkpoint, global
record sequence, and predecessor hash. Startup rejects malformed canonical
values, byte edits, partial tails, reordered/replayed transitions, a journal
shorter than its head anchor, and an anchor/hash mismatch.

The Unix client opens a fresh connection for each load or CAS and implements
the canonical trait. A lost acknowledgement remains an uncertain result: the
caller must perform a fresh exact-scope `load`, as required by the trait.

This slice deliberately does **not** provide:

- a private key, signer, HSM/KMS, or arbitrary signing operation;
- host or peer attestation;
- SafetyRules/Core admission, restart policy, or state-sync policy;
- automatic node/runtime wiring;
- protection when an administrator rolls back both the journal and its head
  anchor together (that requires an independently monotonic device/service);
- production/testnet activation.

Accordingly, `EXTERNAL_NODE_CHECKPOINT_OPERATIONAL_INTEGRATION_V0` in
`trnm-poco-node` remains `false`, and every runtime/production flag in this
crate remains `false`. This crate proves a process boundary and exact durable
CAS behavior only.
