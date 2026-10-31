# trnm-data-availability

Owner: M09. Reusable candidate component; no consensus activation.

Signed storage responsibility, chunk retrieval, repair and retention; no block consensus.

Domains and data schemas use a fresh portability namespace. Never open a deployed
historical database as an upgrade shortcut. Retained tests cover local behavior only.

Storage attestation thresholds are storage contracts, not ledger consensus votes.
The current transaction-batch namespace does not yet implement public model artifacts.

```bash
cargo test --locked -p trnm-data-availability --all-targets --all-features
```

Run from `trillionnium`. See [modules](../../../docs/modules/README.md) and
[ownership](../../../config/portability-inventory-v1.json).

## Opt-in Cell Swarm local byte boundary (V0)

`cell_swarm` adds a bounded, **non-networked**, content-addressed Cell
reassembly primitive. A caller must independently pin the manifest identifier
from the existing Hepta artifact/withdrawal owner. The manifest commits to
network, release root, Cell identity, exact byte length, chunk size, complete
content digest and ordered Merkle-rooted chunk hashes. Input bounds are 64 MiB
per Cell, 1 MiB per chunk and 1,024 chunks per Cell. Whole-content identity
is checked again on completion.

Chunks can arrive out of order from separate, untrusted transport sources.
Corrupt, missing, conflicting, wrong-sized or swapped bytes cannot produce a
`VerifiedCellSwarmBytesV0`. The result is **bytes only**, not an installation,
signature, source-independence, custody, lease, export or `FinalUse` authority.
A host must separately verify the actual PQ provider authorization, persistent
availability, compatible model family/shape, present withdrawal frontier and
local Hepta runtime admission. Merkle/SHA-256 content checks by themselves do
not qualify a whole-chain PQ-128 claim.

No ordinary P2P server, DHT, erasure coding, operator-independent replication,
model weight loading, reward logic or consensus path is changed. These remain
P1 acceptance obligations. No existing transaction-batch DA schema is reused
for model authority. The in-crate tests exercise ordered and out-of-order
assembly, changed pinned context, forged chunk rejection, duplicates, incomplete
content and descriptor bounds.

Focused verification (from the repository root):

```sh
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-data-availability cell_swarm -- --nocapture
```
