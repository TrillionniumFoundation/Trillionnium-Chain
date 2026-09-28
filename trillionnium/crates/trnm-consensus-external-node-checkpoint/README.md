# External node-checkpoint CAS v0

## PoN target and current-source scope

This crate remains existing implementation/reference source; this documentation does
not turn it into a PoN runtime. Selected development profile: `pon-nakamoto-v1`.
Source owner: M03. Target responsibility: Mining-attempt ownership, identity custody and local fencing.
See [M03 technical contract](../../../docs/modules/M03_SAFETY_SIGNER_TECHNICAL_SPEC_V1.md) and the
[PoN protocol](../../../docs/protocol/pon-nakamoto-v1/README.md).

Reuse descriptor/nonce/fence/custody and bounded worker mechanisms where matching. Retire
SafetyRules vote locks and PoCO double-vote slashing as target requirements; retained signer
records stay historical.

## Retained implementation documentation

The source interfaces, stored formats, commands and tests below retain their actual
legacy/profile semantics. PoCO consensus is retired as the target. No old finality,
committee, vote, consumption weight or test pass is new neural-work/efficacy evidence.


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

The open authority also retains descriptor/path identity for its private
journal, lock, head anchor, and parent directory. Each request and durable
head publication revalidates device/inode, owner, mode, link count, type, and
canonical pathname; a same-UID rename, replacement, hard-link, or symlink race
fails closed. This is a candidate process-boundary fence, not an independent
monotonic anti-rollback service.

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

The V0 record and CAS port are shared through the existing M03 signer-journal
package; this daemon has no normal dependency on the Node implementation.
Node retains its old public re-exports. The independent checkpoint CAS never
delegates to the signer watermark, and decoding a record grants no authority.
