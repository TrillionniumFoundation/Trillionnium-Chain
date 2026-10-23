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
`fetch-release` takes the release owner's local TCR1 file plus its independently
pinned digest. It fetches every declared member through the existing configured
peers under one shared connection, actual response-byte and absolute time budget.
All member manifests must fit the declared aggregate payload/chunk limits and
match the release context before any missing payload is downloaded. Only a
complete freshly verified cache permits create-only publication of the exact
TCR1 completion marker. Partial verified chunks may remain cached on failure;
there is no partial marker, automatic retry, discovery or refreshed member budget.
As with single-Cell materialization, a failure after the no-replace link may
leave a complete marker. Reconcile its pinned identity and current cache with
`verify-release`; an uncertain acknowledgement does not permit overwriting it.
The marker is not a weights bundle, storage lease or model-use token; consumers
must recheck cache integrity and their normal owners before use. `verify-release`
performs that bounded local cache check without publication. Release roots are
not discovered over TCP; TCM1, TCQ1, TCS1 and TCR1 stay unchanged.
The supplied local release file and destination directory are caller-controlled.
This path does not defend against a hostile process with the same local
filesystem authority. Filesystem operations remain cooperative and can return
after the deadline; the operation is not a hard real-time guarantee.
It does not discover peers, authenticate a public network, issue storage proofs,
change `CURRENT`, bypass withdrawal, or grant model execution. Those boundaries
remain explicit until a later public DA qualification.

The disposable cache now requires fresh TCL2/schema2 and explicit immutable
`CellCacheConfigV2` limits on every writable open. Live payload, manifest wire
and each 32-byte key share one logical byte quota; chunk/manifest rows have
separate finite bounds. Ordinary writer commands require `--cache-max-bytes N
--cache-max-chunks N --cache-max-manifests N`; exact retries reuse these same
persisted caps. `serve`/`manifest` read existing caches only. Old TCL1 caches are
refused, never automatically reset. Atomic dedup/batch/deletion accounting and
cold schema/counter checks do not reserve physical DB/WAL/SHM/temp/output bytes.
Cache deletion changes no acknowledged retention obligation or native funding.

```bash
cargo test --locked -p trnm-data-availability --all-targets --all-features
```

Run from `trillionnium`. See [modules](../../../docs/modules/README.md) and
[ownership](../../../config/portability-inventory-v1.json).
