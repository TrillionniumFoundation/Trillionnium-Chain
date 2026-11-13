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
Release-marker publication finishes directory synchronization and owned cleanup,
then checks the original deadline again. A late completion is an error with the
exact marker retained; no timeout can erase an already completed publication.
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

The disposable cache now requires fresh TCL4/schema4 and explicit immutable
`CellCacheConfigV4` limits on every writable open. Live payload, manifest wire
and each 32-byte key share one logical byte quota; chunk/manifest rows have
separate finite bounds. Ordinary writer commands require `--cache-max-bytes N
--cache-max-chunks N --cache-max-manifests N --cache-max-db-bytes N`; exact retries reuse these same
persisted caps. `serve`/`manifest` read existing caches only. Old TCL1/TCL2/TCL3 caches are
refused, never automatically reset. Atomic dedup/batch/deletion accounting and
cold schema/counter checks preserve the original logical quota. The added immutable
main-DB image/file-length cap uses 4096-byte pages and is reapplied on every writer
connection; read-only opens audit it. Supported writes share a cross-process gate
that requires a complete zero-length WAL before each spill-free FULL transaction.
A held reader refuses before mutation and can be retried after release. WAL/SHM
file-length caps are derived from the main cap, including FULL padding; this does
not reserve allocated blocks or close new-cache journal/memory/temp/output peaks.
Oversized main files, tails and sidecars are refused. See the existing
[Cell contract](../../../docs/protocol/pon-nakamoto-v1/details/CELL_P2P_V1.md) for
formulas, the shared five-second contention allowance and namespace assumptions.
Cache deletion changes no acknowledged retention obligation or native funding.

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


### Cross-release chunk reuse (research-only)

Chunk digests now commit to bytes alone using a dedicated content domain.
The same Base/Cell piece reused in two releases can have one content ID.
The separately pinned manifest still commits to the **ordered** chunk list,
network, release root, Cell ID, exact length, chunk width and whole-content
digest. Identical chunk IDs do not confer a different model-release authority.

This refines the unactivated experimental V0 identity: old expected manifest
IDs must not be reinterpreted or silently migrated. Prior pins fail closed.
The new tests compare distinct-release manifests and reject incorrect chunk
positions even when other positions reuse identical bytes.

No DHT, live networking, erasure repair, custody, independent operator,
ML-DSA channel, FinalUse, PQ128 qualification or activation is implemented.


### Bounded XOR missing-chunk repair (research-only V0)

The opt-in `cell_swarm_xor_repair` module adds a **separate owner-pinned
parity plan**. A verified complete Cell may be split into stripes of 2–16
chunks, with one XOR parity shard per stripe. Its typed plan binds the
original immutable Cell Swarm manifest ID, stripe width, and each
position-specific parity digest. A consumer must independently pin both
the original manifest and the parity-plan ID. A parity hint from a peer is
not automatically trusted, even when its bytes hash correctly.

The local reconstructor verifies every supplied original chunk against
the immutable manifest, validates every supplied parity shard against
its pinned plan, and reconstructs **at most one** absent chunk per stripe.
Recovered bytes must independently satisfy the original chunk digest
and final whole-Cell digest before `VerifiedCellSwarmBytesV0` is returned.
Two missing chunks in one stripe, corrupted parity, altered manifest,
incorrect owner pin or source-byte poisoning fail closed. The last
stripe supports a shortened final chunk. Width and input arrays remain
bounded by the existing 64 MiB / 1 MiB / 1,024-chunk limits.

This is elementary XOR redundancy, **not** general Reed–Solomon repair,
a live P2P service, an independent custody receipt or proof of provider
diversity. It does not prove long-term availability, permission to
redistribute any model, active ML-DSA authority or Hepta FinalUse. It
does not change consensus, work, rewards, existing DA records or production
activation. Repair plan IDs are experimental V0 identities and require
new independent pins after any future encoding change.

Run the candidate unit tests on an exact committed Rust toolchain source:

```sh
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-data-availability cell_swarm_xor_repair -- --nocapture
```

Full original required jobs and independent tests remain separate gates.
