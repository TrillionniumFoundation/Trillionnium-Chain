# trnm-data-availability

Owner: M09. Reusable candidate component; no consensus activation.

Signed storage responsibility, chunk retrieval, repair and retention; no block consensus.

Domains and data schemas use a fresh portability namespace. Never open a deployed
historical database as an upgrade shortcut. Retained tests cover local behavior only.

Storage attestation thresholds are storage contracts, not ledger consensus votes.
The current transaction-batch namespace does not yet implement public model artifacts.

The candidate `cell` module and `trnm-cell` binary add a separate, local-only
content-addressed model-cell cache. A caller must provide an authority-pinned
manifest digest; the cache verifies the full payload and ordered chunk hashes,
supports bounded multi-peer repair, and publishes files with create-only semantics.
`CellReleaseManifestV1` additionally binds the release owner's declared
required-cell set and lets a local cache verify that every listed member is
present and context-compatible. It cannot infer omitted dependencies or model
executability. All context and member digests must be nonzero; an initial release
must name an explicit owner-defined parent/genesis digest. Unrelated cached cells
never establish a complete release.
Whole-release verification requires caller-supplied total payload-byte, total
chunk-reference and absolute deadline limits. It checks every manifest and the
aggregate limits before reading payloads, then verifies against the same deadline.
Shared chunks count for each full-payload read. Blocking filesystem calls are
cooperative; these limits do not reserve disk bandwidth or grant installation.
It does not discover peers, authenticate a public network, issue storage proofs,
change `CURRENT`, bypass withdrawal, or grant model execution. Those boundaries
remain explicit until a later public DA qualification.

```bash
cargo test --locked -p trnm-data-availability --all-targets --all-features
```

Run from `trillionnium`. See [modules](../../../docs/modules/README.md) and
[ownership](../../../config/portability-inventory-v1.json).
